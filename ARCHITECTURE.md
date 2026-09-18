# Architecture

## What this service does

The broker holds one GitHub App private key and mints installation tokens for
predeclared Team Workspaces. Its deployment-owned policy binds:

- one immutable GitHub Organization id and asserted login;
- one installation id and the exact accepted permission set;
- the exact selected repository ids and asserted full names; and
- each immutable Workspace id to exactly one immutable GitHub Team id, a
  separate deployment credential reference and a repository-id allowlist.

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
Between the installation gate and the mint, the runtime performs the Team gate
described below; it is the step that turns a live GitHub Team grant into the
authority for the token.
Read-only Checks access and Actions write access let the standard GitHub CLI
render check runs and their workflow-run context and explicitly rerun a failed
workflow without a synthetic commit or human credential. GitHub exposes no
rerun-only installation permission: `actions: write` also authorizes other
Actions mutations in the same repository. The remaining boundaries therefore
stay material: one immutable repository per short-lived token, an exact
Workspace repository allowlist and no Checks write access.

## Team binding and live grant verification

A Hosted Team Workspace has no human GitHub identity; its GitHub identity is
the App, reached through this broker, acting for exactly one GitHub Team. The
policy therefore binds each Workspace to one immutable numeric
`github_team_id`, and the parser refuses a policy where a Workspace has no
Team or two Workspaces claim the same Team. Team ids are immutable on GitHub;
a Team deleted and recreated under the same name has a new id and is a
different Team for the broker.

The live GitHub Team membership and Team-to-repository grants are the only
grant authority: the policy never grants anything GitHub has not granted and
never replaces GitHub's ACL. The policy's `workspace.repository_ids` allowlist
is nevertheless a separate, deny-only admission gate that decides which live
grants the broker will use at all: a repository outside the allowlist is
refused before the Team grant is read, even when the Team holds a write grant
on it. On every token request, after the credential and allowlist
checks, the runtime mints a `members: read` probe token, reads the Team by
`/organizations/{org_id}/team/{team_id}`, checks the Team's grant on the exact
repository with `/organizations/{org_id}/team/{team_id}/repos/{owner}/{repo}`
and the repository-permissions media type, revokes the probe, and only then
mints the one-repository token. A missing Team, an identity that differs from
the policy assertions, a missing grant, a `pull`/`triage`-only grant or a
repository id mismatch is refused with `403 team_grant_missing`; a GitHub
outage, rate-limit or quota response is `502 token_unavailable`. Neither
refusal issues a repository token — the only token minted before the decision
is the short-lived probe, already revoked — and nothing from the readback is
retained between requests, so
the only window in which a revoked grant can still act is the lifetime of a
token already issued.

This convergence is paid in GitHub requests, deliberately without a cache: a
successful Team gate is four requests (probe mint, two reads, probe
revocation), so an accepted Node request costs five GitHub requests and an
accepted Worker request nine, because the Worker also repeats the installation
gate. A missing Team refuses early after three requests (probe mint, Team read,
probe revocation) and never reads the repository grant. Rate
limiting therefore degrades issuance to fail-closed refusals rather than to
stale allows; the README documents the per-path budget.

The Node adapter still performs the installation gate once before listening;
the Team gate is per request in both adapters because it is the revocation
path. A Workspace whose Team temporarily lacks a grant does not stop the
service for other Workspaces; it is refused per request.

`policy check --live` is the same verification run over every Workspace and
every allowlisted repository at once. It is the migration and readback gate an
operator runs before deploying a policy and exits non-zero on any refused
row; the rows never contain a token or credential.

The Lazurio Dashboard is a read-only lens over this contract. It may show the
desired Team-to-repository mapping and derive a reviewed policy input, but
that input is reviewed and published in the owner Deployment Repository and
grants nothing by itself. Neither the Dashboard nor the policy is a second
ACL: the broker's live check against GitHub is the authority for every token.

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
- Remove the GitHub Team's grant on a repository, or delete the Team, to
  refuse that Workspace's next token for the repository without touching the
  policy or restarting the broker; the reviewed policy then converges by
  removing the stale repository id or Workspace.
- Remove a repository id from a Workspace policy to stop its next issuance.
  Removing a repository from the global policy also requires removing the
  matching live App installation grant because the global set is exact.
- Rotate the App private key in deployment custody and restart the Node broker
  or publish a new Worker secret version.
- Keep the prior immutable image or Worker version available for source
  rollback, but never roll back a revoked credential or repository grant.

## Runtime adapters

The policy parser, GitHub installation verification, live Team grant
verification, one-repository token validation and Workspace authorization
handler form one platform-neutral core. Node.js/OCI and Cloudflare Workers are transport and custody adapters
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
