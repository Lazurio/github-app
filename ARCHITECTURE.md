# Architecture

## What this service does

The broker holds one GitHub App private key and mints installation tokens for
predeclared Team Workspaces and, since `0.13.0`, for GitHub Actions jobs of
listed Deployment Repos (see
[GitHub Actions OIDC purposes](#github-actions-oidc-purposes)). Its
deployment-owned policy binds:

- one immutable GitHub Organization id and asserted login;
- one installation id, its repository selection mode and the exact accepted
  permission set;
- each immutable Workspace id to exactly one immutable GitHub Team id, a
  separate deployment credential reference and an optional read permission
  ceiling; and
- optionally, the OIDC purposes: this broker's audience, the Deployment Repos
  by immutable repository and owner id, and per purpose its one repository,
  optional callers among those Deployment Repos, workflow file, admission
  rules, exact permission set and per-run budget.

The policy names no repositories and no access tiers. The scope of a
Workspace is the live GitHub Team grant: the repositories of the policy's
Organization on which the Workspace's Team holds any repository grant at the
moment of a request, and the grant's role selects the tier. A `push`,
`maintain` or `admin` grant mints the write tier; a `pull` or `triage` grant
mints the read tier. The policy never narrows the scope below GitHub. Its
only narrowing is the optional per-Workspace `permission_ceiling: "read"`,
described below, which lowers the permissions of that Workspace's tokens and
never changes which repositories it reaches. An
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

- write tier: `actions: write`, `checks: read`, `contents: write`,
  `members: read` and `pull_requests: write`, plus `workflows: write` and `issues: write` each
  when the policy declares that the installation accepted it;
- read tier: `actions: read`, `checks: read`, `contents: read`,
  `members: read` and `pull_requests: read`, plus `issues: write` when the
  policy declares that the installation accepted it;
- read tier of a Workspace with `permission_ceiling: "read"`: the read tier
  with every permission lowered to `read`, so an accepted `issues: write`
  becomes `issues: read`.

Before asking GitHub, the runtime refuses any set that asks for a permission
or level the installation has not accepted, and any write tier for a
Workspace with a read ceiling; the installation gate itself stays an exact
comparison.

GitHub adds `metadata: read` to both. `members: read` lets an Environment
list the Organization Owners it mentions in an issue; GitHub answers that list
with an empty list, not an error, to a token without it. There is no default tier: a mint without
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

Because the accepted Issues permission is Organization-wide and the
installation gate compares it exactly, a Workspace whose tokens must carry no
write permission (for example a shared visitor Environment) cannot get there by
leaving `issues` out of the policy. It declares `permission_ceiling: "read"`
instead. Its Team gate then selects the read tier for every usable grant,
including `push`, `maintain` and `admin`, so a grant raised later on GitHub
still mints only reads, and its read tier asks for each permission at `read`.
A missing grant is refused as without a ceiling: the ceiling never creates
access. A Workspace without the key mints exactly what it minted before the
ceiling existed. A broker that predates the key would accept such a policy
and mint the uncapped tiers, so a policy with a ceiling must only be deployed
to a broker that understands it.

The ceiling removes write permissions; it cannot remove one capability GitHub
did not tie to them in the live check ([#23](https://github.com/Lazurio/github-app/issues/23)). For an installation that accepted
the Issues permission, GitHub authorized opening an issue in a public
repository for every installation token tested, whatever permissions it asked
for and whatever repository it was limited to, including a public repository
outside the installation. Commenting was refused for all of them, and editing,
closing and reopening for the read-ceiling token. An installation without the
Issues permission was not tested. No tier or ceiling the broker can request
refused issue creation in public repositories there, so a Workspace used by
untrusted people must decide at the Workspace whether it receives a token at
all.

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
narrows which repositories GitHub has granted; a read ceiling only lowers the
tier. A request names its repository either as
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
read tier, and a Workspace's read ceiling turns every one of them into the
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
the tier each one mints, after any read ceiling, next to the live role.
Without `--live` it prints the exact permission set each tier asks for under
the policy and, when a Workspace declares a read ceiling, that set and a
`CEILING` column. It is the migration and readback gate an
operator runs before deploying a policy or lowering Team grants. The
repository rows are information; the command exits non-zero only on a missing
or drifted Team or installation drift, and its rows never contain a token or
credential.

The Lazurio Dashboard is a read-only lens over this contract. It may show the
desired Team-to-repository mapping and derive a reviewed policy input, but
that input is reviewed and published in the owner Deployment Repository and
grants nothing by itself. Neither the Dashboard nor the policy is a second
ACL: the broker's live check against GitHub is the authority for every token.

## GitHub Actions OIDC purposes

Rollouts move from an operator's computer to short-lived GitHub-hosted
runners. Such a runner needs GitHub tokens the workflow's own `GITHUB_TOKEN`
cannot provide: Organization-scoped facts for the Permit evidence of the
Deployment Repo, and a read of a private release repository of another
Organization. It must not hold a stored secret, and it must never hold the App
private key. `POST /v1/oidc/token` gives it exactly one installation token per
request, for one configured purpose.

The credential is the job's GitHub Actions OIDC token, which GitHub signs per
job for the audience the job asks for. The broker accepts only its own exact
public origin as the token's only audience, verifies the signature against
GitHub's published keys with jose and then decides from signed claims alone,
in this order:

1. the caller's immutable `repository_id` is a listed Deployment Repo and its
   `repository_owner_id` is the owner listed with it;
2. the purpose is configured; a purpose that names `callers` admits only
   those of the listed Deployment Repos, and a purpose for the caller's own
   repository serves only repositories of the policy's Organization;
3. the runner environment is admitted (`github-hosted` unless the policy also
   admits `self-hosted`);
4. one rule of the purpose admits the job's event, its exact branch ref, the
   reviewed workflow file at that ref (`workflow_ref`, which GitHub sends on
   every token) and its GitHub Environment; a `job_workflow_ref`, which GitHub
   documents for jobs that run a reusable workflow, must be absent or name that
   same file, so no reusable workflow is admitted unless a later policy names
   one;
5. the run guard has not seen this OIDC token and the purpose has budget left
   in this workflow run attempt;
6. the live installation gate, unchanged.

The purpose then fixes everything the token can do: its one repository (the
caller's own Deployment Repo, or one fixed repository of the Organization) and
its exact permission set, which the parser has checked against the
installation's accepted permissions. A rule may lower the set to `read`; a rule
that admits an event a person without write access can start must do so
whenever the set contains a write. The token response is the `/v1/token` shape
plus the permission set. A token outside the requested scope is revoked before
the refusal.

Purposes are configuration so that the next one (for example a read of the
Permit ledger) is a reviewed policy entry rather than a broker change. The
code keeps the invariants that make any entry safe: immutable ids, one exact
branch per rule, the reviewed workflow file, read-only rules for events others
can start, one repository per token, the installation's accepted permissions
as the ceiling, one use per OIDC token and a per-run budget.

`oidc.deployment_repositories` is one allowlist for the whole broker, so a
fixed-repository purpose without `callers` is open to every Deployment Repo on
it. That is right for a release repository every admitted Organization reads,
and too wide for a repository only some of them may read, such as the
Deployment Repo that holds the broker Organization's Conglomerate Host Record,
read by the guest Organizations whose lanes run on that host. Since `0.14.0` a
purpose can name its `callers`: Deployment Repos written exactly as the
allowlist lists them, by immutable repository id and owner id. The list only
narrows the allowlist; the parser refuses a caller the allowlist does not hold
with that owner id, and admission refuses a listed Deployment Repo the purpose
does not name with `caller_not_admitted` before any state or GitHub request.
Who may read stays a reviewed policy decision of the broker's Organization,
revocable by removing the caller.

Rollout order: release and deploy broker `0.14.0` before any policy names
`callers`. A `0.13.0` broker does not know the key and refuses the whole
policy (the Worker answers every request, Workspaces included, with
`503 configuration_unavailable`; the Node broker does not start), so it fails
closed and never serves such a purpose to every listed Deployment Repo. For
the same reason, remove every purpose that names `callers` before rolling a
broker back below `0.14.0`: deleting only the key would open the purpose to
every listed Deployment Repo.

The run guard is the broker's only state. It is one Durable Object per
workflow run attempt, named from verified claims, holding used token ids and
grant counts, and it can only refuse; it never allows a request admission
refused, and it caches nothing GitHub decides. Without it, an OIDC token could
be replayed until it expires and a buggy or compromised run could mint
without bound. Workspace authorization does not use it.

Every decision of the route writes one audit line to the Worker's log stream:
the decision and its code, the purpose, the verified caller claims and, for a
grant, the repository, access, permission set and expiry, never a token.

Only the Worker adapter serves the route. A GitHub-hosted runner can reach only
a public broker, which is where the Worker runs; the Node adapter runs inside
an Organization's private network. The Node adapter parses the same policy,
lists its purposes in `policy check` and answers `404` on the route, so jose
and the run guard never enter the OCI image.

## Threat model

The broker is a small boundary around a powerful secret: the App private key
can mint any installation token of every installation the App has, within the
permissions each Organization accepted. Everything the broker does is to hand
out narrower, short-lived tokens for decisions it can verify.

**Trusted.** GitHub (identity, Team grants, installation permissions, Actions
OIDC tokens and the GitHub-hosted runners), the deployment owner's Cloudflare
account and secret custody, and the reviewed policy. A deployment owner who
can change the policy or the Worker can grant anything the installation holds;
review of the owner Deployment Repository is that boundary.

**Workspace route.** A caller must present one Workspace's credential. The
live Team grant on the exact repository decides; the policy can only lower
access. A stolen Workspace credential acts as that Workspace until the
credential is rotated.

**OIDC route: a broker that holds the App private key is now reachable by CI
runners.** The route is public: anyone can send a request, and any GitHub
Actions workflow anywhere can obtain a validly signed OIDC token for this
broker's audience. The rules above bound what that reach can achieve:

- Without a token GitHub signed for this broker as its only audience, a
  request fails before any state or GitHub request. Forged, expired,
  foreign-audience, multi-audience and key-less tokens are refused; GitHub's
  key set is fetched at most once per cooldown, so invalid tokens cannot drive
  traffic to GitHub's JWKS endpoint.
- A validly signed token from a repository that is not listed, or whose owner
  changed, is refused first, so strangers learn nothing about the purposes.
- A listed repository obtains a token only from the reviewed workflow file on
  its default branch, never through a reusable workflow that file calls, for
  the admitted events and GitHub Environment. Code that runs with the token therefore passed the
  Deployment Repo's own review and branch rules, and an apply additionally
  waited for the Environment's required reviewers before the job started. A
  pull request cannot change which workflow runs: `pull_request` runs never
  match, and `pull_request_target` runs, which execute the default branch's
  workflow, receive only read permissions.
- Only GitHub-hosted runners are admitted by default: an ephemeral virtual
  machine per job, with no persistent foreign host that could keep the token.
- One OIDC token yields at most one installation token; a run attempt yields
  at most the purpose's budget.
- The installation token reaches one repository with the purpose's exact
  permission set, never more than the installation accepted, for at most an
  hour, and the runner revokes it when it finishes. It never reaches another
  Organization: an installation token is bound to its installation, and a
  fixed-repository purpose names one repository of the broker's own
  Organization.
- The App private key, the App JWT and the Workspace credentials never leave
  the Worker and are not used to answer anything but GitHub itself.

What remains:

- Whoever can merge to a Deployment Repo's default branch can change the
  workflow and so control a job that receives that repository's
  `deployment-apply` token; for an apply, the Environment's reviewers still
  have to approve the run. This is the same trust the Permit gate already
  places in the Deployment Repo's review rules.
- A compromised step inside an admitted job, for example a compromised action
  the workflow uses, can use the token within its repository, set and expiry.
  Pinning actions by commit and keeping the job small are the workflow's part.
- The installation grows by the permissions `deployment-apply` needs
  (repository administration read, Organization administration or plan read,
  issues read). Workspace tokens never request them, but a leaked App private
  key could; key custody stays the main control.
- A key GitHub withdraws can verify tokens until the cached key set expires,
  at most ten minutes.
- An allowlisted Deployment Repo of another Organization can read the one
  fixed release repository on every run, which is the purpose of
  `machines-release`; removing it from the allowlist stops it at the next
  request. A fixed-repository purpose that names `callers` is open only to
  them, but a named caller holds the purpose's whole permission set on the
  whole fixed repository for up to an hour, so whoever can merge to the
  caller's default branch can read all of it, not only the file its runner
  needs. Removing the caller, or the purpose, stops it at the next request.
- Audit lines name the workflow's actor and are kept by the deployment owner.

## What this service does not do

- It is not a human login service or membership database.
- It does not decide whether a browser may enter a Team Workspace.
- It does not attribute a shared Workspace push to the last connected person.
- It does not store OpenAI credentials, GitHub OAuth tokens or Git data.
- It does not expose the App private key or a general GitHub API proxy.
- It does not let a CI runner choose a repository or a permission set, keep
  the OIDC tokens it verifies, or offer a revocation route for tokens it no
  longer holds.

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
- Remove a Deployment Repo from `oidc.deployment_repositories`, a caller from
  a purpose's `callers`, or a purpose from `oidc.purposes`, and deploy the
  policy to refuse its next OIDC request. A Deployment Repo that a purpose
  still names as a caller must leave that `callers` list too, or the policy
  fails to load. The last caller leaves with its purpose, never by deleting
  the `callers` key, which would open the purpose to every listed Deployment
  Repo. A token already issued stays valid until it expires or its holder
  revokes it; for an emergency, an Organization owner can suspend the App
  installation on GitHub, which blocks the App's access to that
  Organization's resources while it stays suspended.
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
Two exceptions hold no authorization: GitHub's OIDC signing keys, which jose
caches per isolate for at most ten minutes, and the deny-only OIDC run guard in
a Durable Object. A policy with OIDC purposes and no run guard binding is an
incomplete configuration and fails closed like a missing secret.

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
do, with GitHub's own error and exit code. After any failed read-tier command
the adapter adds one conditional stderr line: it names the read access as the
reason if GitHub refused a change, leaves every other error as GitHub's own and
says that proposing through an issue needs the accepted Issues permission. The
adapter cannot tell a refusal from a bad argument or an outage, so it never
claims which one happened. Installation tokens exist only in the child
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
