# Architecture

## What this service does

The broker holds one GitHub App private key and mints installation tokens for
predeclared Team Workspaces. Its deployment-owned policy binds:

- one immutable GitHub Organization id and asserted login;
- one installation id and the exact accepted permission set;
- the exact selected repository ids and asserted full names; and
- each immutable Workspace id to a separate deployment credential reference
  and repository-id allowlist.

Credential references and credential values must be unique across all
Workspaces. The Node adapter proves file-path uniqueness and snapshots all
values before listening; the Worker adapter reconstructs one complete binding
snapshot per request. Authentication never mixes values from two snapshots.
A duplicated or aliased secret fails the whole issuance path closed instead of
enabling cross-Workspace impersonation.

Before minting a token, the active runtime verifies the live installation
owner, target type, selected-repository mode, exact permissions and exact
repository set. The Node adapter performs this gate before listening; the
Worker performs it after local authorization on every valid token request.
Every token request then asks GitHub to mint a new one-repository token with
exactly `actions: write`,
`checks: read`, `contents: write` and `pull_requests: write`; removal of a live
repository grant therefore fails the next issuance without waiting for a local
cache.
Read-only Checks access and Actions write access let the standard GitHub CLI
render check runs and their workflow-run context and explicitly rerun a failed
workflow without a synthetic commit or human credential. GitHub exposes no
rerun-only installation permission: `actions: write` also authorizes other
Actions mutations in the same repository. The remaining boundaries therefore
stay material: one immutable repository per short-lived token, an exact
Workspace repository allowlist and no Checks write access.

## What this service does not do

- It is not a human login service or membership database.
- It does not decide whether a browser may enter a Team Workspace.
- It does not attribute a shared Workspace push to the last connected person.
- It does not store OpenAI credentials, GitHub OAuth tokens or Git data.
- It does not expose the App private key or a general GitHub API proxy.

Human ingress is implemented separately with a standard OAuth gateway. The
gateway checks the live GitHub Team for every new session/reconnect; removing a
person blocks their later entry but does not terminate an already-running
server-side Agent job. The broker remains independent because an Agent job can
continue after the browser disconnects.

## Rotation and recovery

- Replace one Workspace credential file or Worker secret to revoke only that
  Workspace, then replace the client-side copy in its custody boundary.
- Remove a repository id from a Workspace policy to stop its next issuance.
  Removing a repository from the global policy also requires removing the
  matching live App installation grant because the global set is exact.
- Rotate the App private key in deployment custody and restart the Node broker
  or publish a new Worker secret version.
- Keep the prior immutable image or Worker version available for source
  rollback, but never roll back a revoked credential or repository grant.

## Runtime adapters

The policy parser, GitHub installation verification, one-repository token
validation and Workspace authorization handler form one platform-neutral
core. Node.js/OCI and Cloudflare Workers are transport and custody adapters
around that core; neither adapter may fork the policy schema, permission set or
authorization decisions.

The Node.js adapter resolves distinct custody-mounted credential files,
verifies the exact live GitHub installation before opening its listener and
keeps that immutable snapshot for the process lifetime. Configuration changes
require a verified restart.

The Cloudflare adapter has no filesystem or reliable startup phase. It maps
each immutable Workspace id to one independently rotatable Worker secret,
validates the complete binding snapshot on each request and performs exact live
installation verification immediately before every authorized token mint.
Unknown credentials and denied repositories fail before this provider call.
This deliberately trades extra GitHub readback latency for convergence without
module-state caches. Missing or duplicated secrets fail the whole Worker
configuration closed; neither errors nor observability contain secret values.

A Cloudflare deployment is a separate service boundary. It is not a third
workload on a Conglomerate Host or Organization Host, and it does not turn the
Cloudflare account, DNS or Worker name into a GitHub access authority. GitHub
installation grants remain the only repository authority; Cloudflare holds
only the runtime secret custody needed to exercise that bounded App identity.
Concrete account ids, routes, customer policy, secret values and deployment
version evidence live in the restricted deployment owner.

Runtime evidence must identify the public source commit and active policy
digest. Node deployments also identify the pinned base image and built image
id; Worker deployments identify the immutable Cloudflare version id. Evidence
contains no secret values.

## Brokered `gh` compatibility boundary

Hosted Team Workspaces consume the adapter from the same immutable public
release but do not receive the App private key. Their only secret is the
separate credential for their exact Workspace broker identity.

The adapter is a deny-first launcher around the official GitHub CLI, not a
GitHub API proxy. A repository command must resolve one HTTPS GitHub checkout
or one matching `--repo` selector, obtain a fresh token through `/v1/token`,
and then run the real CLI. Installation tokens exist only in the child
environment and are never cached, rendered or written to GitHub CLI config.
The official CLI remains responsible for pull requests, REST and GraphQL.

T3 Code performs two host-level discovery calls that are not repository API
operations. The adapter recognizes only their exact argument envelopes:

- `gh auth status --json hosts` performs a live token proof for the first
  deterministic repository in the validated Team policy, discards the token,
  and emits the official JSON host shape for `lazurio-for-github[bot]`;
- `gh api user --jq .login` performs the same proof and emits that machine
  actor without calling GitHub's user endpoint.

A failed proof returns the official unauthenticated host shape and a non-zero
exit. The result is deliberately not cached, so repository or installation
revocation affects the next discovery and operation without restarting the
Workspace. This host signal never substitutes for per-repository
authorization.

Credential management, `gh config`, aliases, extensions, host overrides and
multi-repository search remain unavailable. The isolated config directory is
root-owned and read-only; pager, browser and editor inheritance is removed.
If a future pinned T3 release requires a user-only GraphQL field unsupported
by an installation token, the adapter fails visibly. Such evidence may justify
a separate bounded T3 compatibility change, never request rewriting here.

The adapter deliberately remains a compatibility launcher for the official
CLI rather than claiming a false command-level security boundary. A Workspace
that can receive this token can use the full repository-scoped Actions write
permission GitHub defines; operator policy and review must accept that exact
provider capability before rollout.
