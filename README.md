# Lazurio for GitHub broker

Open-source, publicly auditable source for the small credential boundary used
by Lazurio Team Workspaces. The broker exchanges an authenticated Workspace
request for a short-lived GitHub App installation token restricted to one
immutable repository id. The Workspace's live GitHub Team grant on that
repository selects one of two exact permission sets:

- write tier (`push`, `maintain` or `admin` grant): `actions: write`,
  `checks: read`, `contents: write`, `members: read` plus
  `pull_requests: write`, and
  `workflows: write` and `issues: write` where the Organization's policy
  declares them;
- read tier (`pull` or `triage` grant): `actions: read`, `checks: read`,
  `contents: read`, `members: read` plus `pull_requests: read`, and
  `issues: write` where the Organization's policy declares it.

GitHub adds `metadata: read` to every token. Both tiers read Organization
membership (`members: read`, which the installation already holds for the Team
gate) so an Environment can find the Organization Owners to mention in an
issue; without it GitHub answers the Owner and collaborator lists with an empty
list instead of an error.

Lazurio for GitHub is an independent project. It is not affiliated with,
sponsored by, or endorsed by GitHub, Inc. GitHub and GitHub CLI are trademarks
of GitHub, Inc.; their names are used only to identify compatibility and
provenance.

The source is public so customers can review what handles the App private key.
Public source alone is not deployment proof: an operator must also record the
exact source commit, immutable runtime image and deployment attestation.

The same immutable image also carries the small `brokered-gh` adapter used by
Hosted Team Workspaces. The adapter keeps the official GitHub CLI as the only
GitHub API implementation while replacing persistent human CLI credentials
with a fresh, one-repository installation token for each operation.

## Trust boundary

The broker makes one machine authorization decision:

```text
Workspace id + Workspace credential + repository (name or id)
    -> exact deployment policy (Organization, App, installation, Workspace -> Team)
    -> repository owner is the policy's Organization
    -> live GitHub App installation identity and permissions
    -> live grant of the Workspace's immutable GitHub Team on that repository
       (push/maintain/admin -> write tier, pull/triage -> read tier, none -> refused)
    -> one-repository installation token of that tier for the repository id GitHub returned
```

- It never asks which human last used the Workspace.
- It never receives a browser session or OAuth token.
- The GitHub App private key exists only in the broker workload.
- Every Workspace is bound to exactly one immutable GitHub Team id. The live
  GitHub Team grant is the scope: a Workspace can obtain a token for exactly
  the repositories of the policy's Organization on which its Team holds any
  repository grant at the moment of the request, and the grant decides the
  tier. A `push`, `maintain` or `admin` grant mints the write tier; a `pull` or
  `triage` grant mints the read tier. The policy holds no repository list and
  no tier, so it never grants anything GitHub has not granted and never
  narrows or widens what GitHub has granted. An Organization Admin who grants
  a Team access to a new repository, or raises or lowers a grant, changes what
  that Team's Environment can do on the next request, without a broker policy
  change or redeploy.
- A write-tier token can read checks, rerun workflows, change repository
  contents and create or update pull requests only for that one repository,
  and, with `issues: write` declared, open and manage issues there. GitHub has
  no rerun-only installation permission, so `actions: write` also permits
  other Actions mutations in that repository; the token still receives no
  Checks write, administration, membership change or cross-repository
  authority. Its `members: read` reads the Organization's members and Teams,
  as any member of the Organization can.
- A read-tier token can clone, fetch and read the contents of that one
  repository and list and view its pull requests, check runs and GitHub
  Actions workflow runs. `actions: read` also lets it read that repository's
  workflow run logs and artifacts, as a person with read access can. It
  receives no contents, pull request, Checks, Actions or workflow write. With
  `issues: write` declared it can also open issues, which is how an Agent
  without write access proposes a change. GitHub has no create-only
  issue permission: `issues: write` also lets the token edit, label, close,
  reopen and comment on existing issues in that repository, which is closer to
  the `triage` role for issues than to a person with read access.
- Immutable ids are the authorization keys: the Workspace id, the Team id, the
  Organization id and the repository id GitHub returns from the live Team
  grant. Repository names are resolved live on every request and never cached.
- Installation tokens are neither logged nor written to disk by this service.
- The client credential helper must also avoid disk persistence.

Human entry to T3 Code, Launchpad and module applications is a separate
GitHub-backed gateway decision. See [ARCHITECTURE.md](./ARCHITECTURE.md).

## Runtime

One platform-neutral authorization and GitHub policy core is exposed through
two runtime adapters:

- `src/broker.mjs` is the Node.js/OCI adapter for a custody-mounted service;
- `src/worker.mjs` is the Cloudflare Workers adapter for a separately deployed
  remote broker.

The adapters do not own different policy schemas or authorization rules. A
deployment chooses one adapter and supplies the same customer-neutral source
with deployment-owned policy and secrets.

### Node.js / OCI

Requirements: Node.js 24 or newer.

```sh
npm test
npm run check
```

Run with custody-mounted files:

```sh
GITHUB_APP_ID=1234 \
GITHUB_APP_PRIVATE_KEY_FILE=/run/secrets/github-app.pem \
BROKER_POLICY_FILE=/run/config/policy.json \
node src/broker.mjs
```

The policy schema is demonstrated in
[`examples/policy.example.json`](./examples/policy.example.json). Secret files
contain one high-entropy value and are referenced by path; their values never
belong in the policy or Git.

### Policy schema `lazurio.github_app_broker.policy.v3`

Schema v3 binds each Workspace to its GitHub Team and names no repositories:

- `github_app {id, slug}`, `github_owner {id, login}`, `installation_id` and
  `installation_repository_selection` (`selected` or `all`; omitted means
  `selected`) assert the exact App installation.
- `installation_permissions` is the exact accepted permission set. It must
  include `actions: write`, `checks: read`, `contents: write`,
  `members: read` and `pull_requests: write`; the App reads Teams and Team
  repository grants through `members: read`.
- `installation_permissions.workflows: write` is optional. When the
  Organization accepted it and the policy declares it, every write-tier token
  also asks for `workflows: write`, so a Workspace can push commits that add
  or change `.github/workflows/` files in its repository, exactly like a Team
  member with a write grant. Without it the token keeps the base set. Because
  the installation gate compares permissions exactly, accept the permission
  and deploy the policy that declares it in one short window.
- `installation_permissions.issues: write` is optional in the same way. When
  the Organization accepted it and the policy declares it, every token of
  both tiers also asks for `issues: write`, so a Team Environment can open
  issues whatever its grant: a read-only Environment proposes a change, a
  write-capable one files an escalation. Without it neither tier asks for
  `issues`, and the write tier keeps exactly its previous set. See
  [Read-only Team grants](#read-only-team-grants) for the App permission this
  needs.
- `workspaces[]` has `id`, `github_team_id`, optional `github_team_slug` and
  `credential_file`. Workspace ids, Team ids and credential files must each be
  unique, so exactly one broker Workspace exists per Team. The optional slug
  is a human-readback assertion: when present, the live Team slug must match;
  a renamed Team fails closed until the policy is reviewed, and the slug never
  selects a different Team.

`repositories` and `workspaces[].repository_ids` no longer exist. A v3 policy
that still contains either key is rejected, so a half-migrated policy fails
closed instead of silently ignoring a list someone believes is enforced.

#### Migration from v2

Schema v2 (and the already retired v1) is rejected with a migration message.
Migrate by setting `schema_version` to `lazurio.github_app_broker.policy.v3`
and deleting `repositories` and every `workspaces[].repository_ids`; the live
Team grant is the scope. Run `policy check --live` against the converted
policy and compare the listed repositories of each Team with what that Team's
Environment should reach. A Team that holds more write grants
than its v2 allowlist gains those repositories; narrow such a Team on GitHub
before switching. Only then deploy broker `0.10.0` with the v3 policy.

Roll out the broker before the client adapter: broker `0.10.0` accepts both
the new `{"repository": ...}` body and the `{"repository_id": ...}` body that
already deployed `0.9.0` adapters send. The `0.10.0` adapter sends only the
name form and therefore needs a `0.10.0` broker.

#### Read-only Team grants

Since `0.11.0` a Team's `pull` or `triage` grant mints the read tier instead
of being refused as `403 team_grant_missing`. An Organization can therefore
give a Team only read access to some repositories (for example a knowledge
base, planning data or the Organization root): the Team's Environment can
still clone, pull and read them and propose changes as issues, while the
people who hold write access change them from their own Environments under
their own GitHub accounts. Before `0.11.0` lowering such a grant to read cut
the Team's Environment off the repository completely.

The read tier reads contents, pull requests, check runs and GitHub Actions
workflow runs, so people in a read-only Environment see pull requests and CI
results, but it writes nothing except, where declared, issues.

`triage` maps to the same read tier as `pull`. The installation permission
that would add pull request triage is `pull_requests: write`, which also lets a
token open and edit pull requests; an Environment without write access
proposes through issues, so the read tier stays minimal. Issue triage comes
with `issues: write` anyway, because GitHub has no create-only issue
permission.

The policy stays schema v3 and names no tier: the tier comes from the live
grant on every request.

**App permission prerequisite for issues.** Opening an issue needs the App to
request the repository permission `Issues: Read and write`. The public Lazurio
for GitHub App requested no `issues` permission when `0.11.0` was prepared, so
issue creation, from either tier, needs, per Organization:

1. once, an owner of the App adds `Issues: Read and write` in the App's
   permission settings. GitHub then asks every installation to accept; an
   installation that has not accepted keeps its previous permissions, so
   nothing changes for that Organization yet;
2. an Organization owner reviews and accepts the request in the Organization's
   GitHub App settings. Accepting also accepts any other permission the App
   requests at that moment, so read the whole request; and
3. because the installation gate compares permissions exactly, the policy
   then declares the whole newly accepted set, including
   `installation_permissions.issues: write`, in the same short window.
   Between acceptance and the policy deploy the Worker refuses every token
   request of that Organization with `502 token_unavailable`, and the Node
   adapter refuses to start and fails `--verify-only`, exactly as with
   `workflows: write`.

Without these steps the read tier still clones, fetches and reads, the write
tier mints exactly what it minted before, and GitHub only refuses issue
creation. Once the policy declares `issues: write`, write-tier tokens of that
Organization also carry it.

**Rollout order.** The order matters, because a grant lowered before step 2
cuts the Environment off the repository:

1. Release `0.11.0`.
2. Deploy broker `0.11.0` for each Organization. No policy change is needed
   and write grants mint exactly what they minted before.
3. Optionally pin the `0.11.0` adapter in the Workspaces, which explains a
   refused write instead of leaving only GitHub's error. The `0.10.0` adapter
   already works with read-tier tokens because it ignores `access`.
4. Where the Organization wants its Environments to open issues (proposals
   from read-only ones, escalations from write-capable ones), follow the App
   permission prerequisite above.
5. Run `policy check --live` to see every Team's current grants and tiers, then
   lower the Team grants on GitHub. A lowered repository mints the read tier on
   the next request; a write-tier token minted earlier stays valid until it
   expires on GitHub's installation-token schedule (at most one hour).

Rolling the broker back to `0.10.0` refuses read-only Teams again with
`team_grant_missing`; it never widens access.

### API

`POST /v1/token` accepts exactly one of two bodies:

```http
Authorization: Bearer <workspace credential>
X-Lazurio-Workspace-ID: customer-team
Content-Type: application/json

{"repository": "example-organization/example-repository"}
```

```http
{"repository_id": 2345}
```

The name form is what the adapter sends. The id form keeps already deployed
`0.9.0` adapters working during rollout and costs one extra GitHub read. A
body with both keys, neither, any other key, a non-positive or non-integer id,
or a name that is not exactly `Owner/name` is refused with `400`.

The response contains the installation token, GitHub's expiry timestamp, the
immutable `repository_id`, the canonical `repository` full name GitHub
returned and the `access` tier that was minted (`write` or `read`), with
`Cache-Control: no-store`:

```json
{"token": "<installation token>", "expires_at": "2030-01-01T00:00:00Z", "repository_id": 2345, "repository": "example-organization/example-repository", "access": "write"}
```

`access` is additive: clients that ignore it keep working, and brokers before
`0.11.0` never send it because they mint only the write tier.

`POST /v1/workspace` is the repository-independent connection proof the
adapter uses for host-level discovery outside a repository checkout. It takes
the same headers (its body is not read), runs the same credential gate, then
the installation gate and a read of the Workspace's Team through the same
revoked `members: read` plus `metadata: read` probe. It mints no repository
token and returns, with `Cache-Control: no-store`:

```json
{"workspace_id": "customer-team", "organization": "example-organization", "github_team_id": 4001, "github_team_slug": "customer-team"}
```

`GET /health` returns `204` only after startup policy verification has
succeeded.

Every `POST /v1/token` passes these gates in order; a failed gate never issues
a scoped repository token. The Team gate itself first mints a short-lived
`members: read` plus `metadata: read` probe token, performs its reads and
revokes the probe, so a Team or grant refusal has already cost that probe mint
and revocation; it only guarantees that no final repository token exists:

1. credential: unknown Workspace or wrong credential, no GitHub traffic;
2. body shape and, for the name form, owner: the owner must equal
   `github_owner.login` case-insensitively, no GitHub traffic;
3. installation gate: exact App identity, Organization target, selection mode
   and permissions (the Node adapter at startup, the Worker on every request);
4. Team gate: the Workspace's Team exists with the asserted identity and holds
   a grant on the repository, whose role selects the tier; then the
   one-repository mint of that tier.

| Status | `error` | Meaning |
| --- | --- | --- |
| `401` | `workspace_unauthorized` | Unknown Workspace id or wrong credential. No GitHub traffic. |
| `400` | `invalid_request` | Body is not exactly one of the two forms. No GitHub traffic. |
| `403` | `repository_denied` | The repository belongs to another owner than the policy's Organization. The name form is refused without GitHub traffic; the id form after the live readback. |
| `403` | `team_grant_missing` | Live GitHub readback shows the Workspace's Team is gone, has a different identity than the policy asserts, or holds no grant (none of pull, triage, push, maintain or admin) on the repository; or the repository id is not visible to the installation. |
| `502` | `token_unavailable` | GitHub was unreachable, rate-limited or over quota, returned an unexpected shape, the mint left the requested scope, or the body exceeded the size limit. |
| `415` | `unsupported_media_type` | Body is not JSON. |

`POST /v1/workspace` uses the same codes: `401 workspace_unauthorized` with no
GitHub traffic, `403 team_grant_missing` when the Workspace's Team is gone or
its identity differs from the policy, `502 token_unavailable` on any GitHub
failure and `415` for a non-JSON media type. It never returns `400` or
`repository_denied` because it names no repository.

The Team gate runs live on every mint with a short-lived `members: read` plus
`metadata: read` probe token that is revoked immediately afterwards. Its read
requests are:

1. `GET /organizations/{org_id}/team/{team_id}` proves the Team still exists in
   the installation's Organization and matches the asserted identity
   (Organization `members: read`).
2. Id form only: `GET /repositories/{id}` learns the repository's current
   `full_name` and `owner.id`; an owner other than `github_owner.id` is
   `repository_denied`, and a repository the installation cannot see is
   `team_grant_missing`.
3. `GET /organizations/{org_id}/team/{team_id}/repos/{owner}/{repo}` with
   `Accept: application/vnd.github.v3.repository+json` returns the repository
   with the Team's `permissions`. The broker requires the returned
   `owner.id` to equal `github_owner.id`, at least one of `pull`, `triage`,
   `push`, `maintain` or `admin` to be `true` and, for the id form, the
   returned id to equal the requested id. `admin`, `maintain` or `push`
   selects the write tier; otherwise `triage` or `pull` selects the read tier.
   A `404` or a payload without any of these is `team_grant_missing`
   (Organization `members: read`; GitHub also lists this endpoint under
   repository `administration: read`, which is not required). GitHub answers
   `404` here for a Team without a grant even on a public repository, so a
   public repository is not readable through the broker unless the Team was
   granted it. The probe also needs repository `metadata: read`: without it
   GitHub answers `404` for every private repository the probe cannot see,
   which would look like a missing grant.

The token is minted for the repository id GitHub returned in step 3, with the
permission set of the tier that step selected. Archived repositories are not
special-cased: GitHub itself refuses writes to them.
Nothing from these readbacks is cached: revoking a Team grant on GitHub
refuses the next token without a restart, granting one makes the next request
succeed, and a token already issued expires on GitHub's installation-token
schedule.

In `selected` installation mode a repository must also be added to the App
installation on GitHub before a token can be minted for it; until then the
probe cannot see it and the request is refused. In `all` mode every
Organization repository is installed, so the Team grant alone decides. Both
are GitHub-side actions an Organization Admin performs without the broker
operator.

#### GitHub request budget

The installation gate is one request. A successful Team gate costs four GitHub
requests for the name form (probe mint, Team read, grant read, probe
revocation) and five for the id form (plus the repository read). A missing
Team refuses early after three (probe mint, Team read, probe revocation).
Including the final scoped mint, one accepted token request costs:

| Path | GitHub requests |
| --- | --- |
| Node adapter, accepted name form | 5 (Team gate 4 + scoped mint 1) |
| Node adapter, accepted id form | 6 (Team gate 5 + scoped mint 1) |
| Worker adapter, accepted name form | 6 (installation gate 1 + Team gate 4 + scoped mint 1) |
| Worker adapter, accepted id form | 7 (installation gate 1 + Team gate 5 + scoped mint 1) |
| Node adapter, accepted `POST /v1/workspace` | 3 (probe mint, Team read, probe revocation) |
| Worker adapter, accepted `POST /v1/workspace` | 4 (installation gate 1 + the same 3) |
| `policy check --live` | 1 + per Workspace: probe mint, Team read, one Team repository list page per 100 repositories, probe revocation (a missing Team skips the list) |

Denied credentials, invalid bodies and foreign owners in the name form cost
zero GitHub requests.

All of these requests draw on the installation's GitHub rate limit. A
rate-limit or quota response, like any other GitHub failure, fails closed as
`502 token_unavailable` (or a non-zero `policy check --live` exit) and issues
no scoped repository token; the Team gate's probe token may already have been
minted and revoked by then. There is no readback cache to fall back on.

Both runtime adapters reject an invalid route, media type or Workspace
credential before consuming the request body. An authenticated token body is
read with a hard `1024`-byte streaming limit before JSON parsing.

The Node broker parses the policy and Workspace credentials once, verifies the
exact live GitHub installation and only then starts listening. Policy or
credential changes become active only through a verified service restart;
deployment automation must recreate the workload whenever either mounted input
changes. A repository newly granted to a Team needs neither.

`installation_repository_selection` is an explicit assertion with the values
`selected` or `all`. The installation gate compares the mode, not a
repository set. An `all` installation lets the Team grant alone decide and
increases the private key's provider-side blast radius to every Organization
repository; it should be a reviewed deployment decision, not an implicit
fallback.

Operators can revalidate the same live contract without starting another
listener:

```sh
node src/broker.mjs --verify-only
```

The command reads the same mounted policy, App key and Workspace credentials,
performs the exact live installation readback, emits no secret or token, and
exits non-zero on drift. Deployment automation should run it on every
desired-state apply in addition to the startup gate.

### Policy check and migration gate

`policy check` is the operator-side readback that gates a policy before it is
deployed to either adapter. It runs on the operator's machine, so
`BROKER_POLICY_FILE` and `GITHUB_APP_PRIVATE_KEY_FILE` may point at any custody
path; only the serving commands require the runtime mounts.

```sh
BROKER_POLICY_FILE=./policy.json \
node src/broker.mjs policy check

GITHUB_APP_ID=1234 \
GITHUB_APP_PRIVATE_KEY_FILE=/path/in/operator/custody/github-app.pem \
BROKER_POLICY_FILE=./policy.json \
node src/broker.mjs policy check --live
```

Without `--live` the command only parses the policy and prints the exact
permission set each tier asks for under this policy, then the Workspace to
Team binding; it needs no key and makes no GitHub call:

```text
lazurio.github_app_broker.policy.v3 owner=example-org installation=2001
write tier (push/maintain/admin grant) asks for: actions=write checks=read contents=write issues=write pull_requests=write
read tier (pull/triage grant) asks for: actions=read checks=read contents=read issues=write pull_requests=read
WORKSPACE   TEAM_ID  TEAM_SLUG
alpha-team  4001     alpha-team
```

With `--live` it first performs the same installation verification as
`--verify-only`, then, with one `members: read` plus `metadata: read` probe
token per Workspace, verifies the Team identity and lists the Team's live
repository grants of the policy's Organization with the tier each one mints:

```text
WORKSPACE   TEAM_ID  TEAM_SLUG   REPOSITORY_ID  REPOSITORY            ROLE   ACCESS  STATUS   DETAIL
alpha-team  4001     alpha-team  3001           example-org/alpha     write  write   ok
alpha-team  4001     alpha-team  3003           example-org/gamma     admin  write   ok
alpha-team  4001     alpha-team  3004           example-org/handbook  read   read    ok
beta-team   4002     ?           -              -                     -      -       refused  Workspace beta-team GitHub Team 4002 no longer exists in the Organization
2 Workspaces checked, 1 Teams ok, 1 refused; 3 repository grants (2 write, 1 read)
```

The repository rows are information: they show the Team's live grants as the
probe sees them and the tier a token for each would have. In `selected`
installation mode a listed repository is mintable only while it is also
installed for the App; the check does not prove that per repository. A Team
with no grant prints one `ok` row saying so. The output contains no token or
credential. The command exits non-zero only when a Team is missing or its
identity differs from the policy, or when the installation differs from the
policy. The check never edits
GitHub; a refused row is fixed by restoring the Team on GitHub or reviewing
the policy, never by the broker.

### Cloudflare Workers

The Worker is a separate broker service. It is not deployed on a Conglomerate
Host or Organization Host and it receives neither their SSH credentials nor
their filesystems. Concrete Worker names, accounts, routes, customer ids,
policy and secrets belong to the restricted deployment owner, not this public
repository.

The Worker reads these deployment bindings:

- `GITHUB_APP_ID`: the decimal App id asserted by the policy;
- `GITHUB_APP_PRIVATE_KEY`: the App private key as unencrypted PKCS#8 PEM;
- `BROKER_POLICY_JSON`: the same complete policy document used by the Node
  adapter; and
- one independent secret per Workspace, named
  `WORKSPACE_CREDENTIAL_<WORKSPACE_ID>`, where the lowercase Workspace id is
  uppercased and `-` becomes `_` (for example `blue-team` becomes
  `WORKSPACE_CREDENTIAL_BLUE_TEAM`).

All four classes are deployment bindings and none belongs in Git or Wrangler
configuration. Workspace ids make the secret-binding mapping injective because
policy ids allow only lowercase letters, digits and hyphens. Credential values
must remain unique. A missing, malformed or duplicated binding makes the
Worker return `503 configuration_unavailable` without disclosing which secret
failed.

Unlike the always-on Node process, a Worker has no trustworthy startup phase.
It therefore parses the policy and credential snapshot on each request and,
after a valid Workspace credential, a valid body and (for the name form) the
owner check, verifies the exact live GitHub installation and then the live
Team grant immediately before every token mint. Bad credentials, invalid
bodies and foreign-owner names never trigger GitHub traffic. `GET
/health` proves only that the current Worker bindings form a valid local
configuration, including an importable RSA PKCS#8 App key; a successful token
request is the live installation proof.

Prepare and validate the customer-neutral bundle locally:

```sh
npm ci
npm test
npm run check
```

`npm run check` includes a pinned Wrangler `--dry-run`. A real deployment must
use the deployment-owned Cloudflare account and explicit Worker name, load all
secrets through Cloudflare secret custody, then record the exact public source
commit and resulting immutable Worker version id. This repository deliberately
does not declare an account id, customer route or shared production Worker.

## Container build

The Dockerfile deliberately has no floating base-image default:

```sh
docker build \
  --build-arg NODE_RUNTIME_IMAGE='node:24.19.0-bookworm@sha256:<digest>' \
  -t lazurio-github-app-broker:<source-commit> .
```

Operators must pin the complete image reference and attest the resulting image
id. No customer policy, secret or App credential is baked into the image.
The committed `.dockerignore` sends only the broker `src/`, reusable `adapter/`
and the required license bundle as build-context payload.

## Brokered GitHub CLI adapter

The reusable adapter is shipped in the image at
`/opt/lazurio/github-app/adapter`. A Workspace image copies the two JavaScript
files from an exact OCI digest, installs the official `gh` binary separately
as `/usr/local/libexec/lazurio/gh-real`, creates the root-owned read-only
directory `/usr/local/share/lazurio/gh-config`, and exposes
`adapter/brokered-gh.mjs` as `gh`.

The adapter has four command classes:

1. local help/version invokes real `gh` without any token;
2. exactly `gh auth status --json hosts` and `gh api user --jq .login`
   perform an uncached live broker proof and report the truthful machine actor
   `lazurio-for-github[bot]`;
3. all other `auth`, `config`, `alias`, `extension`, host override and
   cross-repository `search` surfaces fail closed; and
4. repository commands resolve one exact repository from `--repo`/`-R`,
   `GH_REPO` or the current checkout's brokered HTTPS origin, mint a fresh
   scoped token, and invoke real `gh` with the token only in the child process
   environment. Without a target the command fails closed and asks to run
   inside a Team repository or pass `--repo OWNER/REPO`; there is no default
   repository.

`gh run rerun <run-id> --repo OWNER/REPO` follows the fourth class. It uses the
same one-repository token as other repository commands and does not require a
human `gh auth` login or a synthetic source commit. The adapter does not claim
to narrow GitHub's `actions: write` permission to that single verb.

The adapter refuses no repository command by access tier. It sends the
repository, receives whichever tier the broker minted and runs official `gh`
with that token; GitHub decides. With a read-tier token, a Git credential
helper built on `requestGitHubAppToken` serves `git clone`, `fetch` and `pull`,
and `gh repo view`, `gh api` reads, `gh pr list`, `gh pr view`, `gh pr checks`
and `gh run view` and, where the policy declares `issues: write`,
`gh issue create` work. A `git push` fails
with GitHub's own `403` permission error. A `gh` command GitHub refuses, such
as `gh pr create`, keeps official `gh`'s error and exit code. After any failed
command under the read tier the adapter adds one conditional stderr line: if
GitHub refused a change, the read access is the reason; any other error is
GitHub's own; an issue can propose the change once the Organization accepted
the Issues permission. A refusal therefore does not look like a broker outage,
and an unrelated failure is not misdiagnosed as one.

`gh pr checks` and `--json statusCheckRollup`, which T3's pull request list
uses, also ask GitHub for the workflow run behind each GitHub Actions check.
That is Actions data, which is why the read tier asks for `actions: read`; the
write tier's `actions: write` already includes it.

`requestGitHubAppToken` returns the minted `access`. It accepts `read` or
`write`, treats a missing value as `write` (brokers before `0.11.0` mint only
that tier) and refuses any other value as an invalid broker response.

Current T3 PR operations explicitly pass `--hostname github.com` to official
`gh`. The adapter accepts only that exact host on repository commands; the
discovery/viewer envelopes remain exact, a missing value or any other host is
denied, and the argument is forwarded unchanged rather than interpreted as a
second authority.

The host-level authenticated indicator means only that the broker accepted a
fresh proof. Inside a repository checkout (or with `GH_REPO`) the proof mints
and discards a token for that repository. Anywhere else, such as the Folder
root from which Launchpad and T3 run discovery, it calls `POST /v1/workspace`,
which proves the live installation and the Workspace's Team without minting a
repository token. A failure of whichever proof applies reports the
unauthenticated host shape; a failed repository proof does not fall back to the
Workspace proof. The indicator is not an Organization-wide capability claim.
Every actual command resolves and authorizes its own repository again.

The adapter holds no repository list. It sends the repository name, and it
accepts only a broker response whose `repository` names the same repository
(case-insensitively) and whose `repository_id` is a positive integer. A
leftover `GITHUB_REPOSITORY_POLICY_JSON` from a `0.9.0` Workspace is ignored.

Required Workspace environment:

- `GITHUB_TOKEN_BROKER_URL`: the exact deployment-owned broker origin;
- `GITHUB_BROKER_WORKSPACE_ID`: immutable lowercase Workspace id; and
- `GITHUB_BROKER_CLIENT_CREDENTIAL_FILE=/run/secrets/github_broker_client_token`.

The Iotor-compatible local lane keeps the fixed
`http://github-token-broker:8787` origin only while the fixed remote config is
absent. A remote Organization Host mounts the root-owned read-only
`/run/config/github_broker_client.json` file with exactly this closed contract:

```json
{
  "schema_version": "lazurio.github_broker_client.v1",
  "origin": "https://github-broker.example.com"
}
```

When this file exists, the adapter accepts only a canonical HTTPS origin
without credentials, a path, query, fragment or non-default port. It discovers
the fixed path independently of environment variables, reads it before the
Workspace credential and requires the environment origin to match. Removing or
changing an environment variable therefore cannot bypass or redirect the pin;
plaintext local transport remains available only to the legacy lane with no
mounted remote config.

The adapter does not persist `hosts.yml`, a PAT or an installation token. It
forces `GH_PAGER=cat`, removes browser/editor/pager overrides, uses an isolated
read-only `GH_CONFIG_DIR`, denies multi-repository search, and never rewrites a
REST or GraphQL request.

### Compatibility matrix

| Component | Validated version |
| --- | --- |
| Lazurio T3 Code | `lazurio-pilot-prestable-20260817.1` |
| GitHub CLI | `2.97.0` |
| Node.js | `24.19.0` |
| Adapter | `0.11.0` |
| Cloudflare Wrangler | `4.127.1` |

Upstream T3 or `gh` command-envelope drift must pass the exact contract tests
before deployment. A proven user-only GraphQL query is a separate minimal T3
review gate; the adapter must not disguise it.

## Immutable releases

The manual `Lazurio for GitHub Release` workflow accepts only an existing
semantic-version tag and its exact source SHA. It refuses an existing Release
or OCI tag, publishes only `ghcr.io/lazurio/github-app:<version>` (never
`latest`), attaches SBOM/provenance/attestation evidence, and creates the
matching public GitHub Release. Consumers pin the resulting OCI digest, not
the mutable tag.

## License and third-party software

Lazurio for GitHub is licensed under the
[Apache License 2.0](./LICENSE). The OCI image carries this license and the
[third-party notices](./THIRD_PARTY_NOTICES.md), including the unmodified MIT
License for the pinned official GitHub CLI 2.97.0 distribution. Release assets
repeat the same license bundle alongside checksums, SBOM, provenance and the
GitHub attestation.

## Security

Read [SECURITY.md](./SECURITY.md) before reporting a vulnerability. Do not put
tokens, private keys, customer policy or live infrastructure identifiers in a
public issue.
