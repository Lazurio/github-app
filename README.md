# Lazurio for GitHub broker

Open-source, publicly auditable source for the small credential boundary used
by Lazurio Team Workspaces. The broker exchanges an authenticated Workspace
request for a short-lived GitHub App installation token restricted to one
immutable repository id and exactly `actions: write`, `checks: read`,
`contents: write` plus `pull_requests: write`.

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
Workspace id + Workspace credential + repository id
    -> exact deployment policy
    -> immutable GitHub App id and slug
    -> live GitHub App installation grant
    -> one-repository installation token
```

- It never asks which human last used the Workspace.
- It never receives a browser session or OAuth token.
- The GitHub App private key exists only in the broker workload.
- A Workspace credential authorizes only that Workspace's configured
  repository ids.
- A minted token can read checks, rerun workflows, change repository contents
  and create or update pull requests only for that one repository. GitHub has
  no rerun-only installation permission, so `actions: write` also permits
  other Actions mutations in that repository; the token still receives no
  Checks write, administration, membership or cross-repository authority.
- Repository names are assertions for human readback; immutable GitHub ids are
  the authorization keys.
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

### API

`POST /v1/token`

```http
Authorization: Bearer <workspace credential>
X-Lazurio-Workspace-ID: customer-team
Content-Type: application/json

{"repository_id": 2345}
```

The response contains the installation token and GitHub expiry timestamp with
`Cache-Control: no-store`. `GET /health` returns `204` only after startup
policy verification has succeeded.

The broker parses the policy and Workspace credentials once, verifies the exact
live GitHub installation and only then starts listening. Runtime requests never
trigger installation-wide GitHub verification. Policy or credential changes
become active only through a verified service restart; deployment automation
must recreate the workload whenever either mounted input changes.

`installation_repository_selection` is an explicit policy assertion with the
values `selected` or `all`; an omitted value remains backward-compatible with
`selected`. In `selected` mode, the live installation repository set must equal
the policy exactly. In `all` mode, verification still requires every immutable
repository id and asserted full name in the policy to exist, while additional
installation repositories are expected and do not become broker-authorized.
Every token request remains constrained to one policy repository id and one
Workspace allowlist. An `all` installation nevertheless increases the private
key's provider-side blast radius and should be a reviewed deployment decision,
not an implicit fallback.

Operators can revalidate the same live contract without starting another
listener:

```sh
node src/broker.mjs --verify-only
```

The command reads the same mounted policy, App key and Workspace credentials,
performs the exact live GitHub readback, emits no secret or token, and exits
non-zero on drift. Deployment automation should run it on every desired-state
apply in addition to the startup gate.

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
after a valid Workspace credential and repository allowlist match, verifies
the exact live GitHub installation immediately before every token mint. Bad
credentials and denied repositories never trigger GitHub traffic. `GET
/health` proves only that the current Worker bindings form a valid local
configuration; a successful token request is the live installation proof.

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
4. repository commands resolve one exact approved repository, mint a fresh
   scoped token, and invoke real `gh` with the token only in the child process
   environment.

`gh run rerun <run-id> --repo OWNER/REPO` follows the fourth class. It uses the
same one-repository token as other repository commands and does not require a
human `gh auth` login or a synthetic source commit. The adapter does not claim
to narrow GitHub's `actions: write` permission to that single verb.

Current T3 PR operations explicitly pass `--hostname github.com` to official
`gh`. The adapter accepts only that exact host on repository commands; the
discovery/viewer envelopes remain exact, a missing value or any other host is
denied, and the argument is forwarded unchanged rather than interpreted as a
second authority.

The host-level authenticated indicator means only that the broker accepted a
fresh proof for the first deterministic repository in the validated Team
policy. It is not an Organization-wide capability claim. Every actual command
resolves and authorizes its own repository again.

Required Workspace environment:

- `GITHUB_REPOSITORY_POLICY_JSON`: exact `OWNER/REPO` to immutable repository
  id mapping;
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
| Adapter | `0.8.0` |
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
