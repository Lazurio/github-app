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
4. A token is limited to one repository and to the exact permission set of
   one of two tiers (plus GitHub's automatic `metadata: read`), and expires on GitHub's
   installation-token schedule. The write tier is `actions: write`,
   `checks: read`, `contents: write`, `members: read` and
   `pull_requests: write`. The read tier is `actions: read`, `checks: read`,
   `contents: read`, `members: read` and `pull_requests: read`. Each tier
   adds `issues: write`, and the write tier `workflows: write`, only when the
   reviewed policy declares that the installation accepted that permission. A
   Workspace whose policy declares `permission_ceiling: "read"` mints only the
   read tier with every permission lowered to `read`, so its tokens carry no
   write permission. A mint without an explicit tier or a Workspace of the
   policy fails, and so does any set that asks for a permission or level the
   installation has not accepted. A token of a GitHub Actions OIDC purpose is
   limited to the purpose's one repository and its exact reviewed permission
   set (plus `metadata: read`), which the parser checks against the
   installation's accepted permissions; a rule that admits an event other than
   `push` or `workflow_dispatch` must be `read_only` when the set holds a write.
5. Workspace credentials, GitHub Actions OIDC tokens and installation tokens
   are never logged, committed, stored in Git configuration or persisted by
   this service. Audit lines carry decisions and verified claims, never a
   token or a request header.
6. The broker authorizes a Workspace and repository, or an admitted GitHub
   Actions job for one configured purpose, never a browser user. A caller never
   chooses the repository or the permissions of a purpose token.
7. No customer-specific policy, ids or credentials belong in this public repo.
   Deployment Repo ids, purpose callers, fixed purpose repositories and
   audiences live in each Organization's private deployment policy.
8. Every behavior change requires focused tests for the positive path and
   cross-Workspace, cross-repository and foreign-owner denial; for the OIDC
   route also an unlisted repository, a changed owner, another Organization's
   Deployment Repo, a listed Deployment Repo that a purpose's `callers` do not
   name, every event, ref, workflow, job workflow and Environment outside the
   rules, a replayed token and an exhausted run budget.
9. Every Workspace is bound to exactly one immutable GitHub Team id, and every
   token issuance verifies live that the Team exists and holds a grant on the
   exact repository, failing closed with `team_grant_missing`. The grant's
   role selects the tier: `push`, `maintain` or `admin` mints the write tier,
   `pull` or `triage` the read tier; a Workspace's read ceiling turns every
   usable grant into the read tier and never creates access. The live Team
   grant is the scope: the policy holds no repository list or tier and never
   narrows or widens which repositories it reaches.
   Nothing from that readback is cached; the policy, the Dashboard and any
   derived mapping are reviewed inputs, never a second ACL.
10. `POST /v1/oidc/token` admits a GitHub Actions job only from signed claims:
    this broker's origin as the token's only audience, a listed immutable
    repository id with its listed owner id, one of the purpose's `callers`
    when it names them (a list that only narrows the allowlist, never widens
    it), the purpose's workflow file on one exact branch as `workflow_ref`
    (sent on every token; admission keys on it),
    a `job_workflow_ref` that is absent or names that same file (GitHub
    documents it only for reusable workflows, so never require it), an
    admitted event, GitHub Environment and runner environment
    (`github-hosted` unless configured). Each OIDC token is used
    once and each purpose has a per-run budget, kept in a deny-only Durable
    Object that never allows anything admission refused; it is the broker's
    only state. Purposes are configuration; a new purpose is a reviewed policy
    entry, never a code path for one Organization. Only the Worker adapter
    serves the route.
11. jose, pinned exactly, is the only runtime dependency. Only `src/oidc.mjs`
    imports it, and only the Worker entry imports that module, so the core and
    the Node adapter in the OCI image stay dependency-free. The Worker entry
    module exports only functions and classes: workerd refuses to start a
    Worker whose entry module exports a plain value.

`actions: write` is GitHub's smallest installation-token permission that can
rerun a workflow. GitHub does not provide a rerun-only token capability, so
this permission also authorizes other Actions mutations inside the same exact
repository. Keep that provider limitation explicit in architecture and
operator documentation; never describe the token as rerun-only.

`issues: write` is likewise the installation-token permission GitHub documents
for opening an issue. It also authorizes editing, labelling, closing, reopening
and commenting on existing issues of the same repository. Never describe a
read-tier token with `issues: write` as read-only or as able only to create
issues. For an installation that accepted the Issues permission, GitHub also
let every token tested, whatever its permissions and repository, open issues in
public repositories ([#23](https://github.com/Lazurio/github-app/issues/23)): never describe a token of such an installation,
including a read-ceiling token, as unable to open issues or as writing nothing
on GitHub. The read tier's `actions: read` likewise reads more than
check status: it also reads the repository's workflow run logs and artifacts.

Describe an OIDC purpose's permissions exactly as GitHub defines them, and say
which of them a live probe has not proven yet. `contents: write` on a
Deployment Repo pushes any ref there, not only the Permit consumption, and
`administration: read` reads every repository setting GitHub ties to it.

Use an isolated worktree and pull request for every change. Code, comments,
commits and pull-request descriptions are English. Run `npm test` and
`npm run check` before handoff.
