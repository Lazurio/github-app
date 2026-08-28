# Agent rules

This repository is the public source for a security boundary. Keep it small,
dependency-light and customer-neutral.

## Invariants

1. GitHub is the only authority for installation repositories and permissions.
2. Authorization uses immutable Workspace and GitHub repository ids. Provider
   names may be asserted but never select a different object after a rename.
3. The App private key never leaves the broker workload.
4. A token is limited to one repository and exactly `actions: write`,
   `checks: read`, `contents: write` and `pull_requests: write` (plus GitHub's
   automatic `metadata: read`), and expires on GitHub's installation-token
   schedule.
5. Workspace credentials and installation tokens are never logged, committed,
   stored in Git configuration or persisted by this service.
6. The broker authorizes a Workspace and repository, never a browser user.
7. No customer-specific policy, ids or credentials belong in this public repo.
8. Every behavior change requires focused tests for the positive path and
   cross-Workspace / cross-repository denial.

`actions: write` is GitHub's smallest installation-token permission that can
rerun a workflow. GitHub does not provide a rerun-only token capability, so
this permission also authorizes other Actions mutations inside the same exact
repository. Keep that provider limitation explicit in architecture and
operator documentation; never describe the token as rerun-only.

Use an isolated worktree and pull request for every change. Code, comments,
commits and pull-request descriptions are English. Run `npm test` and
`npm run check` before handoff.
