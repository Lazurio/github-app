# Architecture

## What this service does

The broker holds one GitHub App private key and mints installation tokens for
predeclared Team Workspaces. Its deployment-owned policy binds:

- one immutable GitHub Organization id and asserted login;
- one installation id and the exact accepted permission set;
- the exact selected repository ids and asserted full names; and
- each immutable Workspace id to a separate credential file and repository-id
  allowlist.

Credential file paths and credential-value digests must be unique across all
Workspaces. The broker checks both on every request without logging or storing
the values. Authentication then uses that exact per-request credential
snapshot rather than rereading one file, so secret rotation cannot race the
uniqueness check. A duplicated or aliased secret fails the whole issuance path
closed instead of enabling cross-Workspace impersonation.

At startup the broker verifies the live installation owner, target type,
selected-repository mode, exact permissions and exact repository set. It does
not listen if any assertion differs. The mounted policy is read at every token
request; a changed file is parsed and live-verified before it replaces the
last accepted policy, so a Workspace allowlist removal applies on the next
request without restarting the process. Every token request still asks GitHub
to mint a new one-repository token with exactly `actions: read`,
`checks: read`, `contents: write` and `pull_requests: write`; removal of a live
repository grant therefore fails the next issuance without waiting for a local
cache.
Read-only Checks and Actions access lets the standard GitHub CLI render check
runs and their workflow-run context in a pull-request view. Neither permission
grants authority to create, update, rerun or cancel a check or workflow run.

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

- Replace one Workspace credential file to revoke only that Workspace, then
  replace the client-side copy in its custody boundary.
- Remove a repository id from a Workspace policy to stop its next issuance.
  Removing a repository from the global policy also requires removing the
  matching live App installation grant because the global set is exact.
- Rotate the App private key in deployment custody and restart only the broker.
- Keep the prior immutable image available for rollback, but never roll back a
  revoked credential or repository grant.

Runtime evidence must identify the public source commit, the pinned base image,
the built image id and the active policy digest. Evidence contains no secret
values.
