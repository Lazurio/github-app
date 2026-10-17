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

A Workspace whose policy entry declares `permission_ceiling: "read"` mints only
the read tier, for every grant, with each permission lowered to `read` (an
accepted `issues: write` becomes `issues: read`): its tokens carry no write
permission. See [Read-only Workspaces](#read-only-workspaces-permission_ceiling).

Since `0.13.0` the Cloudflare Worker adapter also serves short-lived GitHub
Actions runners: a job of an allowlisted Deployment Repo exchanges its GitHub
Actions OIDC token for one installation token of a configured purpose, limited
to one repository and to that purpose's exact permission set, with no secret
stored in GitHub. See
[CI runners: GitHub Actions OIDC purposes](#ci-runners-github-actions-oidc-purposes).

**Provider limitation.** For an installation that accepted the Issues
permission, GitHub let every installation token tested open an issue in a
public repository, whatever permissions it asked for and whatever repository it
was limited to, including a public repository outside the installation. No
tier, ceiling or permission set the broker can request refused it there; see
[Opening issues in public repositories](#opening-issues-in-public-repositories).

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
    -> the Workspace's optional permission ceiling (read: every grant -> read-only set)
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
  widens what GitHub has granted. Its only narrowing is the optional
  per-Workspace read ceiling, which lowers permissions and never changes which
  repositories a Workspace reaches. An Organization Admin who grants
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
- A token of a Workspace with `permission_ceiling: "read"` is the read tier
  with every permission at `read`, whatever the Team's grant: it reads the
  repository, its pull requests, check runs, workflow runs and, where the
  Organization accepted Issues, its issues. It carries no write permission.
  In the live check GitHub refused its attempts to edit, comment on, close and
  reopen issues, to create refs and pull requests and to push, but let it
  open an issue in a public repository (see
  [Opening issues in public repositories](#opening-issues-in-public-repositories)).
- Immutable ids are the authorization keys: the Workspace id, the Team id, the
  Organization id and the repository id GitHub returns from the live Team
  grant. Repository names are resolved live on every request and never cached.
- Installation tokens are neither logged nor written to disk by this service.
- The client credential helper must also avoid disk persistence.

A GitHub Actions job takes the second decision the broker makes, through the
Worker adapter only:

```text
GitHub Actions OIDC token + {"purpose": name}
    -> GitHub's signature, issuer, this broker's exact audience and expiry
    -> listed Deployment Repo (immutable repository id and owner id)
    -> configured purpose: repository, workflow file on one exact branch, event,
       GitHub Environment and runner environment
    -> each OIDC token once, at most N tokens of the purpose per workflow run attempt
    -> live GitHub App installation identity and permissions
    -> one-repository installation token with exactly the purpose's permission set
```

It never involves a Workspace, a Team grant or a browser user, and a caller
never chooses the repository or the permissions: the purpose does.

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
with deployment-owned policy and secrets. Only the Worker adapter serves the
GitHub Actions OIDC route: a GitHub-hosted runner reaches a broker only over
the public internet, which is where the Worker runs. The Node adapter parses
the same policy, prints its OIDC purposes in `policy check` and answers
`404` on that route.

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
- `workspaces[]` has `id`, `github_team_id`, optional `github_team_slug`,
  `credential_file` and optional `permission_ceiling`. Workspace ids, Team ids
  and credential files must each be unique, so exactly one broker Workspace
  exists per Team. The optional slug is a human-readback assertion: when
  present, the live Team slug must match; a renamed Team fails closed until
  the policy is reviewed, and the slug never selects a different Team.
- `workspaces[].permission_ceiling` is optional and its only value is
  `"read"`. Absent, the Workspace mints exactly what its live grant selects,
  as before `0.12.0`. With `"read"` every token of that Workspace is
  read-only; see [Read-only Workspaces](#read-only-workspaces-permission_ceiling).
  Any other value, including `null`, is rejected.
- `oidc` is optional (since `0.13.0`). It declares the purposes for which
  GitHub Actions jobs of listed Deployment Repos may obtain a token; see
  [The `oidc` purpose table](#the-oidc-purpose-table). Absent, the broker has
  no OIDC route. A policy that declares `oidc` may list no Workspace
  (`"workspaces": []`), for a broker that serves only CI runners; every other
  policy still needs at least one Workspace.

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
results, but it carries no write permission except, where declared,
`issues: write`. Where the installation accepted the Issues permission, it could
also open issues in public repositories without `issues: write` (see
[Opening issues in public repositories](#opening-issues-in-public-repositories)).

`triage` maps to the same read tier as `pull`. The installation permission
that would add pull request triage is `pull_requests: write`, which also lets a
token open and edit pull requests; an Environment without write access
proposes through issues, so the read tier stays minimal. Issue triage comes
with `issues: write` anyway, because GitHub has no create-only issue
permission.

The policy stays schema v3 and names no tier: the tier comes from the live
grant on every request.

**App permission prerequisite for issues.** For the broker to ask for
`issues: write`, the App must request the repository permission
`Issues: Read and write`. The public Lazurio for GitHub App requested no
`issues` permission when `0.11.0` was prepared, so a token with
`issues: write`, from either tier, needs, per Organization:

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
tier mints exactly what it minted before, and no token carries
`issues: write`. What GitHub then allows for opening issues, in public
repositories in particular, was not tested ([#23](https://github.com/Lazurio/github-app/issues/23)). Once the policy declares
`issues: write`, write-tier tokens of that Organization also carry it.

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

#### Read-only Workspaces (`permission_ceiling`)

Since `0.12.0` a Workspace's tokens can carry no write permission while the
Organization keeps `issues: write` and the write tier for its other
Workspaces. The installation's accepted Issues permission is
Organization-wide and the installation gate compares permissions exactly, so
the policy cannot leave `issues` out for one Workspace; instead that Workspace
declares a ceiling:

```json
{
  "id": "example-visitors",
  "github_team_id": 4003,
  "github_team_slug": "visitors",
  "credential_file": "/run/secrets/workspace-example-visitors",
  "permission_ceiling": "read"
}
```

For such a Workspace:

- every usable grant (`pull`, `triage`, `push`, `maintain` or `admin`) mints
  the read tier, so a Team that is later given more than read still gets
  only read permissions; `policy check --live` shows the live `ROLE` next to
  the capped `ACCESS`;
- the read tier's permissions are each lowered to `read`. With the Organization
  having accepted Issues the token asks for `actions: read`, `checks: read`,
  `contents: read`, `issues: read`, `members: read` and `pull_requests: read`
  (plus GitHub's automatic `metadata: read`); without it, the plain read tier.
  In the live check GitHub answered `403` to editing, commenting on, closing
  and reopening issues and to ref and pull request creation, and refused a
  push. Opening a new issue in a public repository is the exception below;
- no grant, a missing or drifted Team and a foreign owner are refused exactly
  as without a ceiling. The ceiling never creates access and never changes
  which repositories the Workspace reaches; the live Team grant still decides.

The ceiling fails closed on every path: a mint of the write tier for such a
Workspace is refused before GitHub is asked, a mint without a Workspace of the
policy is refused, and any token permission set (with or without a ceiling)
that asks for a permission or level the installation has not accepted is
refused before the request instead of relying on GitHub to narrow it. The
installation gate itself is unchanged.

#### Opening issues in public repositories

For an installation that accepted the Issues permission, GitHub authorized
opening an issue in a public repository for every installation token tested,
whatever permissions the token asked for and whatever repository it was limited
to ([#23](https://github.com/Lazurio/github-app/issues/23)). Observed on 2026-10-17 with tokens limited to one public repository
of that installation:

- tokens with only `metadata: read`, only `contents: read`, the read tier
  without `issues` and the read tier with `issues: read` (the read ceiling)
  each passed authorization for `POST /repos/{owner}/{repo}/issues` with an
  empty body (`422`, nothing created). The `metadata: read` token did so in its
  repository, in another public repository of the installation and in a public
  repository of an unrelated owner;
- a read-ceiling token minted by the broker opened an issue with a title
  (`201`) in its repository;
- GitHub sent `X-Accepted-GitHub-Permissions: issues=write` on these responses
  but did not enforce it;
- commenting was refused (`403`) for every one of these tokens, and editing,
  closing and reopening were refused (`403`) for the read-ceiling token.

An installation that has not accepted the Issues permission was not tested.

A read ceiling therefore removes every write permission, not this capability.
Where the installation accepted the Issues permission, a Workspace used by
untrusted people cannot be made unable to open issues through the broker's
tokens; decide that at the Workspace (for example, do not give a Workspace that
only reads public repositories any token, since public repositories need none),
not by policy.

Offline `policy check` adds the ceiling's set and a `CEILING` column only when
a Workspace declares one, so the output of every other policy is unchanged:

```text
lazurio.github_app_broker.policy.v3 owner=example-org installation=2001
write tier (push/maintain/admin grant) asks for: actions=write checks=read contents=write issues=write members=read pull_requests=write
read tier (pull/triage grant) asks for: actions=read checks=read contents=read issues=write members=read pull_requests=read
read ceiling (any grant of a CEILING read Workspace) asks for: actions=read checks=read contents=read issues=read members=read pull_requests=read
WORKSPACE         TEAM_ID  TEAM_SLUG   CEILING
alpha-team        4001     alpha-team  -
example-visitors  4003     visitors    read
```

**Rollout.** Deploy broker `0.12.0` with the unchanged policy first: without a
`permission_ceiling` every Workspace mints exactly what it minted under
`0.11.0`. Then add the ceiling to the Workspaces that must be read-only, run
`policy check` and deploy the policy. A broker before `0.12.0` does not know
the key: it accepts such a policy and mints the uncapped tiers. Never deploy a
policy with a ceiling to an older broker, and never roll a read-only
Workspace's broker back below `0.12.0` while its credential is in use; rotate
that Workspace's credential first. A read-only Workspace's adapter needs no
change.

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
| `502` | `token_unavailable` | GitHub was unreachable, rate-limited or over quota, returned an unexpected shape, the mint left the requested scope (since `0.13.0` the broker revokes such a token with its own credential before refusing), or the body exceeded the size limit. |
| `415` | `unsupported_media_type` | Body is not JSON. |

`POST /v1/workspace` uses the same codes: `401 workspace_unauthorized` with no
GitHub traffic, `403 team_grant_missing` when the Workspace's Team is gone or
its identity differs from the policy, `502 token_unavailable` on any GitHub
failure and `415` for a non-JSON media type. It never returns `400` or
`repository_denied` because it names no repository.

`POST /v1/oidc/token` takes a GitHub Actions OIDC token instead of a Workspace
credential and has its own codes; see
[CI runners: GitHub Actions OIDC purposes](#ci-runners-github-actions-oidc-purposes).

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
write tier (push/maintain/admin grant) asks for: actions=write checks=read contents=write issues=write members=read pull_requests=write
read tier (pull/triage grant) asks for: actions=read checks=read contents=read issues=write members=read pull_requests=read
WORKSPACE   TEAM_ID  TEAM_SLUG
alpha-team  4001     alpha-team
```

A policy with a [read permission ceiling](#read-only-workspaces-permission_ceiling)
adds that set and a `CEILING` column. A policy with
[OIDC purposes](#the-oidc-purpose-table) adds them after the table, one line
per rule with the exact set it asks for (a policy without Workspaces prints
`no Workspaces` instead of the table):

```text
oidc audience=https://github-broker.example.com runners=github-hosted deployment_repositories=3101/1001,7101/7001
purpose deployment-apply repository=caller workflow=.github/workflows/lazurio-rollout.yml per_run=2
  push,workflow_dispatch refs/heads/main environment=production asks for: administration=read checks=read contents=write issues=read members=read organization_administration=read pull_requests=read
  pull_request_target refs/heads/main environment=- read-only asks for: administration=read checks=read contents=read issues=read members=read organization_administration=read pull_requests=read
```

`--live` adds nothing for OIDC purposes beyond the installation gate, which
already compares the permissions they rely on.

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
  `WORKSPACE_CREDENTIAL_BLUE_TEAM`); and
- when the policy declares `oidc`, the Durable Object binding
  `OIDC_RUN_GUARD` of the class `OidcRunGuard`, which holds each workflow
  run's used OIDC token ids and grant counts.

The first four classes are secrets or policy and none belongs in Git or
Wrangler configuration. Workspace ids make the secret-binding mapping injective because
policy ids allow only lowercase letters, digits and hyphens. Credential values
must remain unique. A missing, malformed or duplicated binding makes the
Worker return `503 configuration_unavailable` without disclosing which secret
failed; so does a policy with `oidc` on a Worker without `OIDC_RUN_GUARD`.
The public `wrangler.jsonc` declares the Durable Object binding and the
migration that creates its class (`new_sqlite_classes`, which needs no paid
plan); a deployment that uses its own Wrangler configuration adds both.

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

## CI runners: GitHub Actions OIDC purposes

Since `0.13.0` the Worker adapter serves short-lived GitHub Actions runners,
such as the runner mode of Lazurio Machines rollouts, which plans and applies
on a GitHub-hosted runner instead of an operator's computer. A job of an
allowlisted Deployment Repo presents its GitHub Actions OIDC token and names a
purpose; the broker mints one installation token for that purpose's one
repository with that purpose's exact permission set. No repository,
Environment or Organization secret holds a broker credential, and the job
never sees the App private key.

```http
POST /v1/oidc/token
Authorization: Bearer <GitHub Actions OIDC token, audience = this broker's public origin>
Content-Type: application/json

{"purpose": "deployment-apply"}
```

The body is exactly one purpose name. The response has the shape of
`/v1/token` plus the exact permission set, with `Cache-Control: no-store`;
`access` is `write` when any permission of the set is `write`, else `read`:

```json
{"token": "<installation token>", "expires_at": "2030-01-01T00:00:00Z", "repository_id": 3101, "repository": "example-organization/deployment", "access": "write", "permissions": {"contents": "write", "pull_requests": "read"}}
```

### The `oidc` purpose table

Purposes are reviewed policy, not code. A complete example with synthetic ids
is [`examples/policy.oidc.example.json`](./examples/policy.oidc.example.json):

```json
"oidc": {
  "audience": "https://github-broker.example.com",
  "runner_environments": ["github-hosted"],
  "deployment_repositories": [
    { "repository_id": 3101, "repository_owner_id": 1001 },
    { "repository_id": 7101, "repository_owner_id": 7001 }
  ],
  "purposes": [
    {
      "purpose": "deployment-apply",
      "repository": "caller",
      "workflow": ".github/workflows/lazurio-rollout.yml",
      "rules": [
        { "events": ["push", "workflow_dispatch"], "ref": "refs/heads/main", "environment": "production" },
        { "events": ["pull_request_target"], "ref": "refs/heads/main", "environment": null, "read_only": true }
      ],
      "permissions": { "administration": "read", "checks": "read", "contents": "write", "issues": "read", "members": "read", "organization_administration": "read", "pull_requests": "read" },
      "max_grants_per_run": 2
    }
  ]
}
```

- `audience` is this broker's exact public origin (`https`, no path, port or
  trailing slash). A token GitHub issued for any other audience, such as the
  rollout gateway's, is refused.
- `deployment_repositories` lists the callers by immutable repository id and
  the owner id that repository must still have. A transferred repository keeps
  its id, so the owner id is checked too.
- `runner_environments` is optional and defaults to `["github-hosted"]`; add
  `"self-hosted"` only for a domain that accepts self-hosted runners.
- `purposes[]` names, per purpose:
  - `purpose`: the name a caller sends;
  - `repository`: `"caller"`, the calling Deployment Repo itself, which must
    belong to the policy's Organization, or `{"repository_id": N}`, one fixed
    repository of the policy's Organization that any listed Deployment Repo
    may read;
  - `workflow`: the one workflow file the job must be defined in;
  - `rules`: each with `events`, one exact branch `ref`, `environment` (a GitHub
    Environment name, or `null` for a job without one) and optional
    `read_only`, which lowers every permission of the set to `read`;
  - `permissions`: the exact set, within the installation's accepted
    permissions (GitHub adds `metadata: read`);
  - `max_grants_per_run`: how many tokens of this purpose one workflow run
    attempt may receive (1 to 100).

Unknown keys are refused at every level, so a misspelled rule fails closed.
Two rules are code: a rule whose purpose asks for any `write` and that admits
an event other than `push` or `workflow_dispatch`, the only events whose
initiator needs write access to the repository, must be `read_only`; and `ref`
is one exact branch, so a `pull_request` run, whose ref is
`refs/pull/<n>/merge` and whose workflow file comes from the pull request,
never matches.

A later purpose is one more entry. For example, if the rollout gateway's
Permit-ledger probe ran as a workflow of the Deployment Repo, its read would be:

```json
{ "purpose": "gateway-ledger-read", "repository": "caller", "workflow": ".github/workflows/lazurio-ledger-probe.yml", "rules": [{ "events": ["schedule", "workflow_dispatch"], "ref": "refs/heads/main", "environment": null }], "permissions": { "contents": "read" }, "max_grants_per_run": 1 }
```

No deployment enables it with this release.

### Admission and refusals

Every request passes these gates in order; the first failure is the answer,
with one concrete code. Nothing before step 10 costs a GitHub API request
(verifying the token may fetch GitHub's published signing keys, see
[Token verification](#token-verification)):

1. media type `application/json` (`415 unsupported_media_type`);
2. a bearer OIDC token that verifies (`401`, see
   [Token verification](#token-verification));
3. the body is exactly `{"purpose": "<name>"}` (`400 invalid_request`);
4. `repository_id` is a listed Deployment Repo (`403 repository_not_admitted`).
   Any GitHub workflow anywhere can request a token for this audience, so a
   caller that is not listed learns nothing else;
5. `repository_owner_id` is the listed owner (`403 repository_owner_mismatch`);
6. the purpose is configured (`403 purpose_unknown`);
7. for `repository: "caller"`, the caller belongs to the policy's Organization
   (`403 repository_denied`);
8. `runner_environment` is admitted (`403 runner_not_allowed`), and one rule
   admits the job: its `event_name` (`403 event_not_allowed`), its `ref`
   (`403 ref_not_allowed`), `workflow_ref` equal to
   `<repository>/<workflow>@<ref>` (`403 workflow_not_allowed`),
   `job_workflow_ref` equal to `workflow_ref`, so the job is defined in that
   file and not in a reusable workflow it calls
   (`403 job_workflow_not_allowed`), and its GitHub Environment
   (`403 environment_mismatch`). With several rules, the refusal names the
   check of the rule that came closest;
9. the run guard: each OIDC token once (`401 token_replayed`) and each purpose
   at most `max_grants_per_run` times per workflow run attempt
   (`429 rate_limited`);
10. the live installation gate, exactly as for Workspaces, and the
    one-repository mint (`502 token_unavailable` on any GitHub failure or a
    response outside the requested scope, which the broker revokes first).

| Status | `error` | Meaning |
| --- | --- | --- |
| `400` | `invalid_request` | The body is not exactly one purpose name. |
| `401` | `token_missing`, `token_malformed`, `token_algorithm_refused`, `token_key_unknown`, `token_signature_invalid`, `token_issuer_mismatch`, `token_audience_mismatch`, `token_expired`, `token_not_yet_valid`, `token_claims_invalid` | The OIDC token does not verify as a GitHub Actions token for this broker. |
| `401` | `token_replayed` | This OIDC token was already used. |
| `403` | `repository_not_admitted`, `repository_owner_mismatch`, `purpose_unknown`, `repository_denied`, `runner_not_allowed`, `event_not_allowed`, `ref_not_allowed`, `workflow_not_allowed`, `job_workflow_not_allowed`, `environment_mismatch` | The verified caller is not admitted for this purpose. |
| `404` | `not_found` | This broker's policy declares no `oidc` purposes, or the adapter is the Node adapter. |
| `415` | `unsupported_media_type` | The body is not JSON. |
| `429` | `rate_limited` | The workflow run attempt already received its tokens of this purpose. A rerun is a new attempt. |
| `502` | `token_unavailable` | GitHub or the run guard failed, the installation drifted from the policy, the mint left its scope, or the body exceeded the size limit. |
| `503` | `jwks_unavailable` | GitHub's signing keys could not be fetched. |

### Token verification

The Worker verifies the token with [jose](https://github.com/panva/jose): the
issuer `https://token.actions.githubusercontent.com`, the exact `audience`,
`RS256` only, a required key id (a token without one would otherwise verify
against a key set that holds a single key), required `exp` and `iat`, `60`
seconds of clock tolerance and no `iat` in the future. GitHub's key set comes
from its JWKS endpoint, cached by jose per Worker isolate for at most ten
minutes, refetched for an unknown key id at most once per 30-second cooldown,
each fetch bounded by five seconds. A key set that cannot be fetched is
`503 jwks_unavailable`, never a refusal of the token. Admission reads only the
verified claims: ids such as `repository_id` stay GitHub's decimal strings and
a job without a GitHub Environment has `environment: null`.

### Run guard

One Durable Object per workflow run attempt, named
`<repository_id>/<run_id>/<run_attempt>` from verified claims, records the
run's used OIDC token ids (`jti`) and its grant count per purpose. It is
consulted after admission and before GitHub, and it only refuses: a repeated
token id, or a purpose that reached `max_grants_per_run`. A rerun of failed
jobs is a new attempt with its own budget. A token id is kept until it can no
longer verify; the whole record deletes itself seven days after its first
grant. If the Durable Object cannot answer, the request fails closed as
`502 token_unavailable`.

### The rollout purposes and their permissions

Lazurio's rollout runner uses two purposes:

| Purpose | Served by | Repository | Rules | Permission set | Per run |
| --- | --- | --- | --- | --- | --- |
| `deployment-apply` | each Organization's own broker | `caller`: the Organization's Deployment Repo | `push` or `workflow_dispatch` on `refs/heads/main` in Environment `production`; `pull_request_target` on `refs/heads/main` without an Environment, `read_only` | `administration: read`, `checks: read`, `contents: write`, `issues: read`, `members: read`, `organization_administration: read`, `pull_requests: read` | 2 |
| `machines-release` | the broker of the Organization that publishes Machines releases | `{"repository_id": <the Machines repository>}` | the same events, refs and Environments, none `read_only` (the set has no write) | `contents: read` | 4 |

A `pull_request_target` Plan run of `deployment-apply` receives the same set
with every permission at `read`. The current runner does not ask for it: its
Plan job asks only for `machines-release`.

Each permission of `deployment-apply` serves the runner's live Permit evidence
and the Permit consumption push, and the set is the runner's contract:

- `pull_requests: read` reads the merged pull request, its files and reviews;
- `issues: read` reads the pull request's issue events. GitHub lists that
  endpoint under both the Issues and the Pull requests permission, and which of
  them an installation token needs has not been probed yet;
- `checks: read` reads the check runs of the reviewed head;
- `administration: read` reads the repository rulesets with their bypass
  actors. GitHub documents that it returns `bypass_actors` only to a caller
  with write access to the ruleset; whether `administration: read` is enough
  must be proven by the live probe before the first apply;
- `members: read` reads the Organization's Owners;
- `organization_administration: read` is what the runner contract names for
  the Organization's plan. GitHub documents the narrower Organization `Plan`
  permission (`organization_plan: read`) for that field; if the live probe
  confirms it, the deployment replaces the one with the other in its policy,
  without a broker change;
- `contents: write` is the push that consumes the Permit in that one
  repository (and reads its `CODEOWNERS`). GitHub has no narrower installation
  permission for pushing a ref.

Repository collaborators, rulesets as such and repository metadata are read
with GitHub's automatic `metadata: read`.

### Revocation

The token is an ordinary installation token that expires on GitHub's schedule
(at most one hour). Its holder revokes it earlier with GitHub's
`DELETE /installation/token`, authenticated with the token itself, as runner
mode does at the end of every run. The broker keeps no copy and therefore has
no revocation route. It revokes a token itself only when GitHub returns one
outside the requested repository or permission set, before refusing the
request; since `0.13.0` this also applies to Workspace tokens.

### Audit lines

The Worker writes one JSON line per decision of this route to its log stream:

```json
{"schema_version": "lazurio.github_app_broker.audit.v1", "at": "2026-10-17T12:00:00.000Z", "event": "oidc_token", "decision": "granted", "status": 200, "code": "granted", "purpose": "deployment-apply", "caller": {"repository_id": "3101", "repository_owner_id": "1001", "repository": "example-organization/deployment", "event_name": "push", "ref": "refs/heads/main", "environment": "production", "workflow_ref": "...", "job_workflow_ref": "...", "runner_environment": "github-hosted", "run_id": "9001", "run_attempt": "1", "actor_id": "5001", "actor": "example-user", "sha": "...", "jti": "..."}, "grant": {"repository_id": 3101, "repository": "example-organization/deployment", "access": "write", "permissions": {"...": "..."}, "expires_at": "..."}}
```

A refusal carries its code, `grant: null` and, for a token that did not
verify, `caller: null`. A line never contains an installation token, the OIDC
token or a request header. It does contain the GitHub login of the workflow's
actor, so the log is the deployment owner's private record; retaining it
(Workers Logs, Logpush or a tail) is a deployment setting. The Workspace routes
write no audit lines.

### GitHub request budget

An accepted request costs two GitHub requests (the installation gate and the
scoped mint) and one Durable Object request; GitHub's key set adds one fetch at
most every ten minutes per isolate, or on an unknown key id at most once per
30 seconds. Refusals before the run guard cost no GitHub request.

### Deploying OIDC purposes

Each Organization's private deployment configuration adds, by name (values
stay in the deployment owner's custody):

1. **App permissions.** `deployment-apply` needs the installation to hold
   repository `Administration: Read`, `Issues: Read` (an accepted
   `Read and write` also serves) and Organization `Administration: Read`, or
   Organization `Plan: Read` once the probe confirms it. The App owner adds the
   missing ones to the App once; each Organization owner then accepts them.
   Because the installation gate compares permissions exactly, the policy's
   `installation_permissions` must declare the whole newly accepted set in the
   same short window; in between every token request of that Organization,
   Workspaces included, is `502 token_unavailable`, exactly as with
   `workflows: write`. `machines-release` needs only `contents: read`, which
   every installation already holds.
2. **Policy.** `oidc.audience` (the broker's public origin, exactly as the
   runner's repository variable names it), `oidc.deployment_repositories`
   (the Organization's Deployment Repo ids with their owner id; on the broker
   that serves `machines-release`, every admitted Organization's Deployment
   Repo) and `oidc.purposes` (`deployment-apply`; on that broker also
   `machines-release` with the Machines repository id). Run `policy check`
   before deploying it.
3. **Worker.** The Durable Object binding `OIDC_RUN_GUARD` to the class
   `OidcRunGuard` and its migration, from the public `wrangler.jsonc` or added
   to a deployment-owned one, and retention of the Worker's log stream for the
   audit lines.
4. **Installation repositories.** In `selected` mode the Deployment Repo, and
   on the `machines-release` broker the Machines repository, are installed for
   the App.

Rollout order:

1. Release `0.13.0` and deploy it unchanged to every broker. A policy without
   `oidc` keeps exactly its previous behavior and has no new route, so this
   step needs no Organization's approval of new behavior.
2. **Ring 0, the reference Organization's broker**, first: accept the App
   permissions, deploy the policy with `deployment-apply` for its Deployment
   Repo and prove the refusal matrix and one grant there. Its runs also need
   `machines-release` from the next step before a Plan or apply can run end to
   end.
3. **The broker of the Organization that publishes Machines releases**, which
   also serves real users: only with its Organization Admin's go, add
   `machines-release` (allowlisting Ring 0's Deployment Repo first) and its own
   `deployment-apply`.
4. **Every other Organization's broker**, each after its owner accepted the
   App permissions; then add its Deployment Repo to the `machines-release`
   allowlist.

Rolling a broker back below `0.13.0` removes the route (an older broker ignores
the `oidc` key), so runners fail closed; a policy with `"workspaces": []` is
refused by an older broker, so keep a Workspace or do not roll that broker
back.

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
| Adapter | `0.13.0` |
| Cloudflare Wrangler | `4.127.1` |
| jose (Worker bundle) | `6.2.12` |

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
GitHub attestation. The Worker bundle includes jose 6.2.12, the broker's only
runtime dependency, under its MIT License
([`third_party/jose/LICENSE.md`](./third_party/jose/LICENSE.md)); the OCI image
does not contain it.

## Security

Read [SECURITY.md](./SECURITY.md) before reporting a vulnerability. Do not put
tokens, private keys, customer policy or live infrastructure identifiers in a
public issue.
