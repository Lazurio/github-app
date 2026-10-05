# Architecture

## What this service does

The broker holds one GitHub App private key and mints installation tokens for
predeclared Team Workspaces. Its deployment-owned policy binds:

- one immutable GitHub Organization id and asserted login;
- one installation id, its repository selection mode and the exact accepted
  permission set; and
- each immutable Workspace id to exactly one immutable GitHub Team id and a
  separate deployment credential reference.

The policy names no repositories and no access tiers. The scope of a
Workspace is the live GitHub Team grant: the repositories of the policy's
Organization on which the Workspace's Team holds any repository grant at the
moment of a request, and the grant's role selects the tier. A `push`,
`maintain` or `admin` grant mints the write tier; a `pull` or `triage` grant
mints the read tier. The policy no longer narrows below GitHub. An
Organization that wants a narrower scope for a Team Environment does it with
GitHub Team grants: it grants that Team only the repositories the Environment
should reach, at the role it should have, or binds the Environment to a
dedicated, narrower Team. GitHub stays the one place where access is granted,
read and revoked, and an Organization Admin can make a new repository
available to a Team Environment, or lower it to read, herself, without a
broker policy change or redeploy.

Credential references and credential values must be unique across all
Workspaces. The Node adapter proves file-path uniqueness and snapshots all
values before listening; the Worker adapter reconstructs one complete binding
snapshot per request. Authentication never mixes values from two snapshots.
A duplicated or aliased secret fails the whole issuance path closed instead of
enabling cross-Workspace impersonation.

Before minting a token, the active runtime verifies the live installation
owner, target type, repository selection mode and exact permissions. It does
not compare a repository set; there is none in the policy. The Node adapter
performs this gate before listening; the Worker performs it after local
authorization on every valid token request. Every token request then asks
GitHub to mint a new one-repository token with exactly the permission set of
its tier, and refuses a response with any other scope or any other repository:

- write tier: `actions: write`, `checks: read`, `contents: write` and
  `pull_requests: write`, plus `workflows: write` and `issues: write` each
  when the policy declares that the installation accepted it;
- read tier: `actions: read`, `checks: read`, `contents: read` and
  `pull_requests: read`, plus `issues: write` when the policy declares that
  the installation accepted it.

GitHub adds `metadata: read` to both. There is no default tier: a mint without
an explicit tier fails before reaching GitHub, so a lost tier can never become
the write set. Between the installation gate and the mint, the runtime
performs the Team gate described below; it is the step that turns a live
GitHub Team grant into the authority and the tier for the token.
Read-only Checks access and Actions write access let the standard GitHub CLI
render check runs and their workflow-run context and explicitly rerun a failed
workflow without a synthetic commit or human credential. GitHub exposes no
rerun-only installation permission: `actions: write` also authorizes other
Actions mutations in the same repository. The remaining boundaries therefore
stay material: one immutable repository per short-lived token, a live Team
grant on exactly that repository and no Checks write access.

The read tier exists so an Organization can keep some repositories read-only
for a Team without cutting that Team's Environment off them. A read-tier token
clones, fetches and reads one repository and lists and views its pull requests,
check runs and GitHub Actions workflow runs, so people in a read-only
Environment see pull requests and CI. `actions: read` is there because GitHub
CLI check views and the `statusCheckRollup` behind T3's pull request list read
the workflow run of each Actions check; it also lets the token read that
repository's workflow run logs and artifacts, as a person with read access
can. The token receives no contents, pull request, Checks, Actions or workflow
write. `issues: write` is the
only write it can carry, so that an Agent without write access can propose a
change as an issue the way a person with read access does. GitHub has no
create-only issue permission: the same permission lets the token edit, label,
close, reopen and comment on existing issues of that repository, which is
closer to the `triage` role for issues than to read access. `triage` maps to
the same read tier as `pull`, because the permission that would add pull
request triage, `pull_requests: write`, also opens and edits pull requests.

`issues: write` is one opt-in for both tiers. An Organization opts in by
accepting the App permission and declaring it in its reviewed policy; then a
write-tier token also carries it, so a write-capable Environment can file the
escalation issues its work asks for. Without the declaration neither tier asks
for `issues` and the write tier is exactly its previous set.

`workflows: write` lets a Workspace push commits that change
`.github/workflows/`. Editing a workflow does not by itself run it or hand it
secrets, but a workflow it writes can, in an eligible run, reference and
exfiltrate the repository and Organization Actions secrets available to that
run, subject to environment protections (fork-pull-request and Dependabot
events withhold ordinary secrets, and protected environment secrets need
approval). That is the same capability a Team member with a write grant
already has from GitHub, and an Organization opts into it by accepting the
App permission and declaring it in its reviewed policy. A policy without it
mints the base set, so the release can roll out before any Organization
accepts. The same holds for `issues: write` in both tiers.

## Team binding and live grant verification

A Hosted Team Workspace has no human GitHub identity; its GitHub identity is
the App, reached through this broker, acting for exactly one GitHub Team. The
policy therefore binds each Workspace to one immutable numeric
`github_team_id`, and the parser refuses a policy where a Workspace has no
Team or two Workspaces claim the same Team. Team ids are immutable on GitHub;
a Team deleted and recreated under the same name has a new id and is a
different Team for the broker.

The live GitHub Team-to-repository grants are the only grant authority and the
whole scope: the policy never grants anything GitHub has not granted and never
narrows what GitHub has granted. A request names its repository either as
`Owner/name` or, for adapters released before `0.10.0`, as an immutable id. A
name whose owner is not the policy's Organization login is refused with
`403 repository_denied` before any GitHub traffic. Otherwise, after the
installation gate, the runtime mints a `members: read` plus `metadata: read`
probe token, reads the Team by `/organizations/{org_id}/team/{team_id}`, for
the id form resolves the repository's current name and owner by
`/repositories/{id}` (another owner is `repository_denied`), checks the Team's
grant with `/organizations/{org_id}/team/{team_id}/repos/{owner}/{repo}` and
the repository-permissions media type, revokes the probe, and only then mints
the one-repository token of the grant's tier for the repository id GitHub
returned. The returned `owner.id` must equal the policy's Organization id.
`admin`, `maintain` or `push` selects the write tier, `triage` or `pull` the
read tier. A missing Team, an identity that differs from the policy
assertions, a missing grant or one without any of these roles, a repository
the installation cannot see or, for the id form, a returned id that differs
from the requested id is refused with `403 team_grant_missing`; a GitHub
outage, rate-limit or quota response is `502 token_unavailable`. No refusal
issues a repository token — the only token minted before the decision is the
short-lived probe, already revoked — and nothing from the readback is
retained between requests, so a revoked or
lowered grant can still act only through a token already issued, and a new or
raised grant works on the next request. The token response names the minted
tier as `access`, so the adapter and operators see which one was issued.

Names are inputs, never keys. The authorization keys are the immutable
Workspace id, Team id, Organization id and the repository id GitHub returns
from the live grant; a renamed repository is resolved by GitHub on the next
request, and the response tells the client the canonical name GitHub returned.

This convergence is paid in GitHub requests, deliberately without a cache: a
successful Team gate is four requests for the name form (probe mint, Team
read, grant read, probe revocation) and five for the id form, so an accepted
Node request costs five or six GitHub requests and an accepted Worker request
six or seven, because the Worker also repeats the one-request installation
gate. A missing Team refuses early after three requests. Rate limiting
therefore degrades issuance to fail-closed refusals rather than to stale
allows; the README documents the per-path budget.

The Node adapter still performs the installation gate once before listening;
the Team gate is per request in both adapters because it is the revocation
path. A Workspace whose Team temporarily lacks a grant does not stop the
service for other Workspaces; it is refused per request.

`policy check --live` runs the installation gate and then, per Workspace,
verifies the Team identity and lists the Team's live repository grants with
the tier each one mints. Without `--live` it prints the exact permission set
each tier asks for under the policy. It is the migration and readback gate an
operator runs before deploying a policy or lowering Team grants. The
repository rows are information; the command exits non-zero only on a missing
or drifted Team or installation drift, and its rows never contain a token or
credential.

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
  policy or restarting the broker. Lower the grant to `pull` or `triage` to
  make the next token read-tier. Granting or raising a Team's grant likewise
  takes effect on the next request.
- Remove a Workspace from the policy, or rotate its credential, to stop all of
  its issuance.
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
Unknown credentials, invalid bodies and foreign-owner names fail before this
provider call.
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
and then run the real CLI. The adapter holds no repository list: it sends the
repository name and accepts only a response for that same repository; the
broker's live Team gate decides. It also refuses nothing by tier: with a
read-tier token official `gh` runs and GitHub refuses what the token cannot
do, with GitHub's own error and exit code. After such a refusal the adapter
adds one stderr line naming the read access, so a permission refusal is not
mistaken for a broker outage. Installation tokens exist only in the child
environment and are never cached, rendered or written to GitHub CLI config.
The official CLI remains responsible for pull requests, REST and GraphQL.

T3 Code performs two host-level discovery calls that are not repository API
operations. The adapter recognizes only their exact argument envelopes:

- `gh auth status --json hosts` performs a live proof and emits the official
  JSON host shape for `lazurio-for-github[bot]`. Inside a repository checkout
  (or with `GH_REPO`) the proof mints and discards a token for that
  repository; anywhere else, such as the Folder root, it calls
  `POST /v1/workspace`, which runs the credential gate, the installation gate
  and the Team identity read through the revoked probe and mints no
  repository token;
- `gh api user --jq .login` performs the same proof and emits that machine
  actor without calling GitHub's user endpoint.

A failed proof returns the official unauthenticated host shape and a non-zero
exit; a failed repository proof never falls back to the Workspace proof. The result is deliberately not cached, so repository or installation
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
