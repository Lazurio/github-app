# Agent rules

This repository is the public source for a security boundary. Keep it small,
dependency-light and customer-neutral.

## Invariants

1. GitHub is the only authority for installation repositories, Team
   repository grants and permissions.
2. Authorization uses immutable keys: the Workspace id, the GitHub Team id,
   the GitHub Organization id and the repository id GitHub returns from the
   live Team grant. Repository and Team names are resolved live on every
   request and never cached; a name never selects a different object than the
   id GitHub returns for it.
3. The App private key never leaves the broker workload.
4. A token is limited to one repository and to exactly one of two permission
   sets (plus GitHub's automatic `metadata: read`), and expires on GitHub's
   installation-token schedule. The write tier is `actions: write`,
   `checks: read`, `contents: write` and `pull_requests: write`. The read tier
   is `actions: read`, `checks: read`, `contents: read` and
   `pull_requests: read`. Each tier
   adds `issues: write`, and the write tier `workflows: write`, only when the
   reviewed policy declares that the installation accepted that permission. A
   mint without an explicit tier fails.
5. Workspace credentials and installation tokens are never logged, committed,
   stored in Git configuration or persisted by this service.
6. The broker authorizes a Workspace and repository, never a browser user.
7. No customer-specific policy, ids or credentials belong in this public repo.
8. Every behavior change requires focused tests for the positive path and
   cross-Workspace, cross-repository and foreign-owner denial.
9. Every Workspace is bound to exactly one immutable GitHub Team id, and every
   token issuance verifies live that the Team exists and holds a grant on the
   exact repository, failing closed with `team_grant_missing`. The grant's
   role selects the tier: `push`, `maintain` or `admin` mints the write tier,
   `pull` or `triage` the read tier. The live Team grant is the scope: the
   policy holds no repository list or tier and never narrows or widens it.
   Nothing from that readback is cached; the policy, the Dashboard and any
   derived mapping are reviewed inputs, never a second ACL.

`actions: write` is GitHub's smallest installation-token permission that can
rerun a workflow. GitHub does not provide a rerun-only token capability, so
this permission also authorizes other Actions mutations inside the same exact
repository. Keep that provider limitation explicit in architecture and
operator documentation; never describe the token as rerun-only.

`issues: write` is likewise GitHub's smallest installation-token permission
that can open an issue. It also authorizes editing, labelling, closing,
reopening and commenting on existing issues of the same repository. Never
describe a read-tier token with `issues: write` as read-only or as able only
to create issues. The read tier's `actions: read` likewise reads more than
check status: it also reads the repository's workflow run logs and artifacts.

Use an isolated worktree and pull request for every change. Code, comments,
commits and pull-request descriptions are English. Run `npm test` and
`npm run check` before handoff.
