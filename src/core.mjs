// SPDX-License-Identifier: Apache-2.0

export const MAX_BODY_BYTES = 1024;

const POLICY_SCHEMA = "lazurio.github_app_broker.policy.v3";
const RETIRED_POLICY_SCHEMA_V1 = "lazurio.github_app_broker.policy.v1";
const RETIRED_POLICY_SCHEMA_V2 = "lazurio.github_app_broker.policy.v2";
const V3_MIGRATION =
  "migrate to lazurio.github_app_broker.policy.v3 by deleting `repositories` and every `workspaces[].repository_ids`; the live Team grant is the scope";
const GITHUB_API_VERSION = "2026-03-10";
const USER_AGENT = "lazurio-github-app-broker/0.13.0";
/** Upper bound for `policy check --live` Team repository pages (100 repositories per page). */
const MAX_TEAM_REPOSITORY_PAGES = 100;
const DUMMY_WORKSPACE_CREDENTIAL = "0".repeat(64);

/**
 * Access tiers. The live Team grant selects the tier at mint time: a `push`, `maintain` or `admin`
 * grant mints the write tier, a `pull` or `triage` grant the read tier. The policy holds no tier.
 */
export const WRITE_ACCESS = "write";
export const READ_ACCESS = "read";

/**
 * Both tiers read Organization membership (`members: read`, which the installation already
 * requires for the Team gate), so an Environment can find the Organization Owners to mention in an
 * issue: without it GitHub answers the Owner and collaborator lists with an empty list, not an error.
 */
const WRITE_TOKEN_PERMISSIONS = Object.freeze({
  actions: "write",
  checks: "read",
  contents: "write",
  members: "read",
  pull_requests: "write",
});
/**
 * A read-tier token can clone, fetch and read the repository and see its pull requests, check runs
 * and the workflow runs behind them (plus GitHub's automatic `metadata: read`). GitHub CLI check
 * views and `statusCheckRollup` read the workflow run of each Actions check, which needs
 * `actions: read`. The read tier never asks for any contents, pull request, Checks, Actions or
 * workflow write.
 */
const READ_TOKEN_PERMISSIONS = Object.freeze({
  actions: "read",
  checks: "read",
  contents: "read",
  members: "read",
  pull_requests: "read",
});

/** The only `workspaces[].permission_ceiling` value: every token of the Workspace is read-only. */
export const READ_CEILING = "read";

const PERMISSION_LEVELS = Object.freeze({ read: 1, write: 2 });

/**
 * The exact permission set a token of `access` asks GitHub for under `policy` for `workspace`, which
 * must be a Workspace of that policy. Two opt-ins follow the permissions the Organization accepted
 * and the reviewed policy declares, so a deployment whose installation has not accepted them keeps
 * minting the base sets:
 * - `workflows: write` (write tier only) lets a push touch `.github/workflows/`;
 * - `issues: write` (both tiers) is GitHub's smallest installation permission that can open an
 *   issue, so an Environment can propose a change or escalate through an issue.
 *
 * A Workspace with `permission_ceiling: "read"` mints only the read tier, with every permission
 * lowered to `read`: an accepted `issues: write` becomes `issues: read`, so its tokens carry no
 * write of any kind. A write tier for such a Workspace is refused, never silently lowered here; the
 * Team gate already selects the read tier for it. Any set that asks for a permission or level the
 * installation has not accepted is refused before GitHub is asked.
 */
export function tokenPermissions(policy, access, workspace) {
  if (!policy.workspaces.includes(workspace)) fail("token permissions need a Workspace of the policy");
  const accepted = policy.installation_permissions;
  const issues = accepted.issues === "write" ? { issues: "write" } : {};
  let permissions;
  if (access === WRITE_ACCESS) {
    if (workspace.permission_ceiling === READ_CEILING) {
      fail(`Workspace ${workspace.id} permission ceiling is read; it never mints the write tier`);
    }
    const workflows = accepted.workflows === "write" ? { workflows: "write" } : {};
    permissions = { ...WRITE_TOKEN_PERMISSIONS, ...workflows, ...issues };
  } else if (access === READ_ACCESS) {
    permissions = { ...READ_TOKEN_PERMISSIONS, ...issues };
    // The read tier holds no write-only permission, so lowering each write to read keeps every key.
    if (workspace.permission_ceiling === READ_CEILING) {
      permissions = Object.fromEntries(Object.keys(permissions).map((permission) => [permission, "read"]));
    }
  } else {
    fail("token access tier must be read or write");
  }
  for (const [permission, level] of Object.entries(permissions)) {
    if (!(PERMISSION_LEVELS[accepted[permission]] >= PERMISSION_LEVELS[level])) {
      fail(`token asks for ${permission}: ${level}, which the installation has not accepted`);
    }
  }
  return Object.freeze(permissions);
}

/**
 * Maps a live Team grant role to the access tier it mints for `workspace`; undefined means no usable
 * grant. A Workspace with a read permission ceiling gets the read tier for every usable grant, so a
 * Team that is later given push still mints nothing but reads.
 */
function grantAccess(role, workspace) {
  const ceiling = workspace.permission_ceiling === READ_CEILING;
  if (role === "admin" || role === "maintain" || role === "write") return ceiling ? READ_ACCESS : WRITE_ACCESS;
  if (role === "triage" || role === "read") return READ_ACCESS;
  return undefined;
}
/**
 * Organization `members: read` reads Teams and Team repository grants. GitHub answers the Team
 * repository check with 404 unless the token can also see the repository, which takes
 * `metadata: read`; a `members: read`-only probe therefore refuses every private repository.
 */
const TEAM_PROBE_PERMISSIONS = Object.freeze({ members: "read", metadata: "read" });
/** Custom media type that makes the Team repository check return the repository with its `permissions`. */
const REPOSITORY_PERMISSIONS_MEDIA_TYPE = "application/vnd.github.v3.repository+json";

export const TEAM_GRANT_MISSING = "team_grant_missing";
export const REPOSITORY_DENIED = "repository_denied";
export const INVALID_REQUEST = "invalid_request";

/** A live GitHub Team binding or repository grant diverged from the policy; the broker mints nothing. */
export class TeamGrantError extends Error {
  constructor(message) {
    super(message);
    this.name = "TeamGrantError";
    this.code = TEAM_GRANT_MISSING;
  }
}

/** The requested repository belongs to another owner than the policy's Organization. */
export class RepositoryDeniedError extends Error {
  constructor(message) {
    super(message);
    this.name = "RepositoryDeniedError";
    this.code = REPOSITORY_DENIED;
  }
}

/**
 * Every refusal of `POST /v1/oidc/token`: one concrete code and its HTTP status. The body is
 * `{"error": "<code>"}` like every other refusal of the broker; it never echoes claims or policy.
 */
export const OIDC_REFUSALS = Object.freeze({
  token_missing: 401,
  token_malformed: 401,
  token_algorithm_refused: 401,
  token_key_unknown: 401,
  token_signature_invalid: 401,
  token_issuer_mismatch: 401,
  token_audience_mismatch: 401,
  token_expired: 401,
  token_not_yet_valid: 401,
  token_claims_invalid: 401,
  token_replayed: 401,
  invalid_request: 400,
  repository_not_admitted: 403,
  repository_owner_mismatch: 403,
  purpose_unknown: 403,
  repository_denied: 403,
  runner_not_allowed: 403,
  event_not_allowed: 403,
  ref_not_allowed: 403,
  workflow_not_allowed: 403,
  job_workflow_not_allowed: 403,
  environment_mismatch: 403,
  unsupported_media_type: 415,
  rate_limited: 429,
  token_unavailable: 502,
  jwks_unavailable: 503,
});

/** A refused GitHub Actions OIDC request; `code` is a key of OIDC_REFUSALS. */
export class OidcRefusal extends Error {
  constructor(code) {
    if (!Object.hasOwn(OIDC_REFUSALS, code)) throw new Error(`unknown OIDC refusal ${code}`);
    super(`OIDC request refused: ${code}`);
    this.name = "OidcRefusal";
    this.code = code;
    this.status = OIDC_REFUSALS[code];
  }
}

/** Seconds of clock tolerance for GitHub Actions OIDC token times (exp, nbf, iat). */
export const OIDC_CLOCK_TOLERANCE_SECONDS = 60;
/** How long a run's replay and grant record lives after its first grant. */
export const RUN_GUARD_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
export const AUDIT_SCHEMA = "lazurio.github_app_broker.audit.v1";

function fail(message) {
  throw new Error(message);
}

function refuse(message) {
  throw new TeamGrantError(message);
}

function deny(message) {
  throw new RepositoryDeniedError(message);
}

function refuseOidc(code) {
  throw new OidcRefusal(code);
}

const OWNER_LOGIN_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPOSITORY_NAME_PATTERN = /^[A-Za-z0-9_.-]{1,100}$/;

/**
 * Parses an exact `Owner/name` coordinate. `.` and `..` are refused because they would change the
 * meaning of the GitHub API path the name is placed into.
 */
export function parseRepositoryCoordinate(value) {
  if (typeof value !== "string") return undefined;
  const parts = value.split("/");
  if (
    parts.length !== 2 ||
    !OWNER_LOGIN_PATTERN.test(parts[0]) ||
    !REPOSITORY_NAME_PATTERN.test(parts[1]) ||
    parts[1] === "." ||
    parts[1] === ".."
  ) {
    return undefined;
  }
  return Object.freeze({ owner: parts[0], name: parts[1], full_name: `${parts[0]}/${parts[1]}` });
}

/**
 * Parses the `POST /v1/token` body: exactly one of `{"repository": "Owner/name"}` or
 * `{"repository_id": <positive integer>}`. Returns undefined for anything else.
 */
export function parseTokenRequest(bodyText) {
  let body;
  try {
    body = JSON.parse(bodyText);
  } catch {
    return undefined;
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) return undefined;
  const keys = Object.keys(body);
  if (keys.length !== 1) return undefined;
  if (keys[0] === "repository") {
    const coordinate = parseRepositoryCoordinate(body.repository);
    return coordinate ? Object.freeze({ repository: coordinate.full_name }) : undefined;
  }
  if (keys[0] === "repository_id") {
    const id = body.repository_id;
    return Number.isSafeInteger(id) && id > 0 ? Object.freeze({ repository_id: id }) : undefined;
  }
  return undefined;
}

const PURPOSE_NAME_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;
const WORKFLOW_PATH_PATTERN = /^\.github\/workflows\/[A-Za-z0-9._-]{1,200}\.ya?ml$/;
const BRANCH_REF_PATTERN = /^refs\/heads\/[A-Za-z0-9._/-]{1,200}$/;
const EVENT_NAME_PATTERN = /^[a-z][a-z_]{0,63}$/;
const RUNNER_ENVIRONMENTS = Object.freeze(["github-hosted", "self-hosted"]);
const MAX_GRANTS_PER_RUN = 100;
/**
 * The only events whose initiator needs write access to the repository: a push to the branch or a
 * manual dispatch. A rule that admits any other event (for example the `pull_request_target` of a
 * Plan) must be read-only, so a run another person can start never receives a write permission.
 */
const WRITE_EVENTS = Object.freeze(["push", "workflow_dispatch"]);

/**
 * Parses the `POST /v1/oidc/token` body: exactly `{"purpose": "<name>"}`. Returns the purpose name
 * or undefined for anything else.
 */
export function parseOidcTokenRequest(bodyText) {
  let body;
  try {
    body = JSON.parse(bodyText);
  } catch {
    return undefined;
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) return undefined;
  const keys = Object.keys(body);
  if (keys.length !== 1 || keys[0] !== "purpose") return undefined;
  return typeof body.purpose === "string" && PURPOSE_NAME_PATTERN.test(body.purpose) ? body.purpose : undefined;
}

function plainObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
  return value;
}

/** Refuses unknown keys, so a misspelled admission rule fails closed instead of being ignored. */
function exactKeys(value, allowed, required, label) {
  plainObject(value, label);
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) fail(`${label}.${key} is not a known key`);
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) fail(`${label}.${key} is required`);
  }
  return value;
}

function canonicalHttpsOrigin(value, label) {
  let url;
  try {
    url = new URL(value);
  } catch {
    fail(`${label} must be a canonical HTTPS origin`);
  }
  if (
    typeof value !== "string" ||
    url.protocol !== "https:" ||
    url.origin !== value ||
    url.port !== "" ||
    url.username ||
    url.password
  ) {
    fail(`${label} must be a canonical HTTPS origin without a path, port or trailing slash`);
  }
  return value;
}

function lowerToRead(permissions) {
  return Object.freeze(Object.fromEntries(Object.keys(permissions).map((permission) => [permission, "read"])));
}

/** Fails when `permissions` asks for a permission or level the installation has not accepted. */
function assertAccepted(accepted, permissions, label) {
  for (const [permission, level] of Object.entries(permissions)) {
    if (!(PERMISSION_LEVELS[accepted[permission]] >= PERMISSION_LEVELS[level])) {
      fail(`${label} asks for ${permission}: ${level}, which the installation has not accepted`);
    }
  }
}

function parseOidcRule(rule, label, purposePermissions) {
  exactKeys(rule, ["events", "ref", "environment", "read_only"], ["events", "ref", "environment"], label);
  const events = rule.events;
  if (
    !Array.isArray(events) ||
    events.length === 0 ||
    events.some((event) => typeof event !== "string" || !EVENT_NAME_PATTERN.test(event)) ||
    new Set(events).size !== events.length
  ) {
    fail(`${label}.events must be a non-empty list of distinct GitHub event names`);
  }
  const ref = rule.ref;
  if (
    typeof ref !== "string" ||
    !BRANCH_REF_PATTERN.test(ref) ||
    ref.includes("..") ||
    ref.includes("//") ||
    ref.endsWith("/") ||
    ref.endsWith(".lock")
  ) {
    fail(`${label}.ref must be one exact branch ref such as refs/heads/main`);
  }
  const environment = rule.environment;
  if (
    environment !== null &&
    (typeof environment !== "string" || environment.length === 0 || environment.length > 255 || /[\u0000-\u001f\u007f]/.test(environment))
  ) {
    fail(`${label}.environment must be a GitHub Environment name or null for a job without one`);
  }
  const readOnly = rule.read_only ?? false;
  if (typeof readOnly !== "boolean") fail(`${label}.read_only must be true or false`);
  const writes = Object.values(purposePermissions).includes("write");
  if (writes && !readOnly && events.some((event) => !WRITE_EVENTS.includes(event))) {
    fail(`${label} admits an event that a person without write access can start; set read_only: true`);
  }
  return Object.freeze({
    events: Object.freeze([...events]),
    ref,
    environment,
    read_only: readOnly,
  });
}

function parseOidcPurpose(purpose, index, installationPermissions) {
  const label = `oidc.purposes[${index}]`;
  exactKeys(
    purpose,
    ["purpose", "repository", "workflow", "rules", "permissions", "max_grants_per_run"],
    ["purpose", "repository", "workflow", "rules", "permissions", "max_grants_per_run"],
    label,
  );
  if (typeof purpose.purpose !== "string" || !PURPOSE_NAME_PATTERN.test(purpose.purpose)) {
    fail(`${label}.purpose must be a lowercase name`);
  }
  let repository;
  if (purpose.repository === "caller") {
    repository = "caller";
  } else {
    exactKeys(purpose.repository, ["repository_id"], ["repository_id"], `${label}.repository`);
    repository = Object.freeze({
      repository_id: positiveInteger(purpose.repository.repository_id, `${label}.repository.repository_id`),
    });
  }
  if (typeof purpose.workflow !== "string" || !WORKFLOW_PATH_PATTERN.test(purpose.workflow)) {
    fail(`${label}.workflow must be a workflow file below .github/workflows/`);
  }
  const permissions = plainObject(purpose.permissions, `${label}.permissions`);
  if (
    Object.keys(permissions).length === 0 ||
    Object.entries(permissions).some(
      ([key, value]) => !/^[a-z][a-z0-9_]*$/.test(key) || key === "metadata" || !["read", "write"].includes(value),
    )
  ) {
    fail(`${label}.permissions must name at least one permission as read or write (GitHub adds metadata: read)`);
  }
  assertAccepted(installationPermissions, permissions, label);
  if (!Array.isArray(purpose.rules) || purpose.rules.length === 0) fail(`${label}.rules must be a non-empty list`);
  const rules = purpose.rules.map((rule, ruleIndex) => parseOidcRule(rule, `${label}.rules[${ruleIndex}]`, permissions));
  const maxGrants = purpose.max_grants_per_run;
  if (!Number.isSafeInteger(maxGrants) || maxGrants < 1 || maxGrants > MAX_GRANTS_PER_RUN) {
    fail(`${label}.max_grants_per_run must be an integer from 1 to ${MAX_GRANTS_PER_RUN}`);
  }
  return Object.freeze({
    purpose: purpose.purpose,
    repository,
    workflow: purpose.workflow,
    rules: Object.freeze(rules),
    permissions: Object.freeze({ ...permissions }),
    max_grants_per_run: maxGrants,
  });
}

/**
 * The optional `oidc` section: the purposes for which GitHub Actions workflows of the listed
 * Deployment Repos may exchange an OIDC token for one installation token. Absent, the broker has no
 * OIDC route. Every purpose is configuration: a new purpose is one more reviewed entry.
 */
function parseOidc(input, installationPermissions, ownerId) {
  exactKeys(
    input,
    ["audience", "runner_environments", "deployment_repositories", "purposes"],
    ["audience", "deployment_repositories", "purposes"],
    "oidc",
  );
  const audience = canonicalHttpsOrigin(input.audience, "oidc.audience");
  const runnerEnvironments = input.runner_environments ?? ["github-hosted"];
  if (
    !Array.isArray(runnerEnvironments) ||
    runnerEnvironments.length === 0 ||
    runnerEnvironments.some((value) => !RUNNER_ENVIRONMENTS.includes(value)) ||
    new Set(runnerEnvironments).size !== runnerEnvironments.length
  ) {
    fail("oidc.runner_environments must list github-hosted and optionally self-hosted");
  }
  if (!Array.isArray(input.deployment_repositories) || input.deployment_repositories.length === 0) {
    fail("oidc.deployment_repositories must be a non-empty list");
  }
  const deploymentRepositories = input.deployment_repositories.map((entry, index) => {
    const label = `oidc.deployment_repositories[${index}]`;
    exactKeys(entry, ["repository_id", "repository_owner_id"], ["repository_id", "repository_owner_id"], label);
    return Object.freeze({
      repository_id: positiveInteger(entry.repository_id, `${label}.repository_id`),
      repository_owner_id: positiveInteger(entry.repository_owner_id, `${label}.repository_owner_id`),
    });
  });
  if (new Set(deploymentRepositories.map(({ repository_id }) => repository_id)).size !== deploymentRepositories.length) {
    fail("oidc.deployment_repositories must list each repository id once");
  }
  if (!Array.isArray(input.purposes) || input.purposes.length === 0) fail("oidc.purposes must be a non-empty list");
  const purposes = input.purposes.map((purpose, index) => parseOidcPurpose(purpose, index, installationPermissions));
  if (new Set(purposes.map(({ purpose }) => purpose)).size !== purposes.length) {
    fail("oidc.purposes must name each purpose once");
  }
  // A purpose for the caller's own repository can only ever serve this Organization's repositories.
  if (
    purposes.some(({ repository }) => repository === "caller") &&
    !deploymentRepositories.some(({ repository_owner_id }) => repository_owner_id === ownerId)
  ) {
    fail("a purpose for the caller's repository needs a Deployment Repo of the policy's Organization");
  }
  return Object.freeze({
    audience,
    runner_environments: Object.freeze([...runnerEnvironments]),
    deployment_repositories: Object.freeze(deploymentRepositories),
    purposes: Object.freeze(purposes),
  });
}

function positiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) fail(`${label} must be a positive integer`);
  return value;
}

function canonicalObject(value) {
  return JSON.stringify(
    Object.fromEntries(Object.entries(value ?? {}).sort(([left], [right]) => left.localeCompare(right))),
  );
}

export function parsePolicy(raw) {
  const input = typeof raw === "string" ? JSON.parse(raw) : structuredClone(raw);
  if (!input || typeof input !== "object" || Array.isArray(input)) fail("policy must be an object");
  if (input.schema_version === RETIRED_POLICY_SCHEMA_V1) {
    fail(
      `policy schema ${RETIRED_POLICY_SCHEMA_V1} is retired; add one immutable workspaces[].github_team_id per Workspace and ${V3_MIGRATION}`,
    );
  }
  if (input.schema_version === RETIRED_POLICY_SCHEMA_V2) {
    fail(`policy schema ${RETIRED_POLICY_SCHEMA_V2} is retired; ${V3_MIGRATION}`);
  }
  if (input.schema_version !== POLICY_SCHEMA) fail("unsupported policy schema");
  if (Object.hasOwn(input, "repositories")) {
    fail(`policy v3 must not contain \`repositories\`; ${V3_MIGRATION}`);
  }

  const appId = positiveInteger(input.github_app?.id, "github_app.id");
  const appSlug = input.github_app?.slug;
  if (typeof appSlug !== "string" || !/^[a-z0-9](?:[a-z0-9-]{0,99})$/.test(appSlug)) {
    fail("github_app.slug is invalid");
  }
  const ownerId = positiveInteger(input.github_owner?.id, "github_owner.id");
  const ownerLogin = input.github_owner?.login;
  if (typeof ownerLogin !== "string" || !OWNER_LOGIN_PATTERN.test(ownerLogin)) {
    fail("github_owner.login is invalid");
  }
  const installationId = positiveInteger(input.installation_id, "installation_id");
  const installationRepositorySelection = input.installation_repository_selection ?? "selected";
  if (!new Set(["selected", "all"]).has(installationRepositorySelection)) {
    fail("installation_repository_selection must be selected or all");
  }

  const installationPermissions = input.installation_permissions;
  if (
    !installationPermissions ||
    typeof installationPermissions !== "object" ||
    Array.isArray(installationPermissions) ||
    installationPermissions.actions !== "write" ||
    installationPermissions.checks !== "read" ||
    installationPermissions.contents !== "write" ||
    installationPermissions.pull_requests !== "write" ||
    installationPermissions.members !== "read" ||
    Object.entries(installationPermissions).some(
      ([key, value]) => !/^[a-z][a-z0-9_]*$/.test(key) || !["read", "write"].includes(value),
    )
  ) {
    fail(
      "installation_permissions must be exact and include actions: write, checks: read, contents: write, members: read and pull_requests: write",
    );
  }

  // Optional and absent by default: without it the broker serves Workspaces only and has no OIDC route.
  const oidc = input.oidc === undefined ? undefined : parseOidc(input.oidc, installationPermissions, ownerId);

  // A broker that only serves OIDC purposes may hold no Workspace; otherwise at least one is required.
  if (!Array.isArray(input.workspaces) || (input.workspaces.length === 0 && oidc === undefined)) {
    fail("workspaces must be a non-empty array (or an empty array when the policy declares oidc purposes)");
  }
  const workspaces = input.workspaces.map((workspace, index) => {
    if (workspace && typeof workspace === "object" && Object.hasOwn(workspace, "repository_ids")) {
      fail(`policy v3 must not contain \`workspaces[${index}].repository_ids\`; ${V3_MIGRATION}`);
    }
    const id = workspace?.id;
    if (typeof id !== "string" || !/^[a-z0-9][a-z0-9-]{1,62}$/.test(id)) {
      fail(`workspaces[${index}].id is invalid`);
    }
    const teamId = positiveInteger(workspace?.github_team_id, `workspaces[${index}].github_team_id`);
    const teamSlug = workspace?.github_team_slug;
    if (teamSlug !== undefined && (typeof teamSlug !== "string" || !/^[a-z0-9][a-z0-9-]{0,254}$/.test(teamSlug))) {
      fail(`workspaces[${index}].github_team_slug is invalid`);
    }
    const credentialFile = workspace?.credential_file;
    if (
      typeof credentialFile !== "string" ||
      !/^\/run\/secrets\/[A-Za-z0-9._-]+$/.test(credentialFile)
    ) {
      fail(`workspaces[${index}].credential_file must be a canonical file below /run/secrets`);
    }
    // Optional and absent by default: a Workspace without it mints exactly what its live grant selects.
    const ceiling = workspace?.permission_ceiling;
    if (ceiling !== undefined && ceiling !== READ_CEILING) {
      fail(`workspaces[${index}].permission_ceiling must be "${READ_CEILING}" when present`);
    }
    return Object.freeze({
      id,
      github_team_id: teamId,
      ...(teamSlug === undefined ? {} : { github_team_slug: teamSlug }),
      credential_file: credentialFile,
      ...(ceiling === undefined ? {} : { permission_ceiling: ceiling }),
    });
  });
  if (new Set(workspaces.map(({ id }) => id)).size !== workspaces.length) {
    fail("workspace ids must be unique");
  }
  if (new Set(workspaces.map(({ github_team_id }) => github_team_id)).size !== workspaces.length) {
    fail("GitHub Team ids must be unique: exactly one broker Workspace per immutable GitHub Team");
  }
  if (new Set(workspaces.map(({ credential_file }) => credential_file)).size !== workspaces.length) {
    fail("Workspace credential files must be unique");
  }

  return Object.freeze({
    schema_version: POLICY_SCHEMA,
    github_app: Object.freeze({ id: appId, slug: appSlug }),
    github_owner: Object.freeze({ id: ownerId, login: ownerLogin }),
    installation_id: installationId,
    installation_repository_selection: installationRepositorySelection,
    installation_permissions: Object.freeze({ ...installationPermissions }),
    workspaces: Object.freeze(workspaces),
    ...(oidc === undefined ? {} : { oidc }),
  });
}

/** The GitHub Actions OIDC claims the broker reads, as the verifier normalized them. */
function decimalClaim(value) {
  return typeof value === "string" && /^[1-9][0-9]{0,19}$/.test(value) && Number.isSafeInteger(Number(value))
    ? Number(value)
    : undefined;
}

/** The checks of one rule, in order; a refusal names the check of the rule that came closest. */
const OIDC_RULE_CHECKS = Object.freeze([
  "event_not_allowed",
  "ref_not_allowed",
  "workflow_not_allowed",
  "job_workflow_not_allowed",
  "environment_mismatch",
]);

function oidcRuleRefusal(purpose, rule, claims) {
  if (!rule.events.includes(claims.event_name)) return "event_not_allowed";
  if (claims.ref !== rule.ref) return "ref_not_allowed";
  // The reviewed workflow file of the caller's repository, at the admitted branch.
  if (claims.workflow_ref !== `${claims.repository}/${purpose.workflow}@${rule.ref}`) return "workflow_not_allowed";
  // The job itself is defined in that file, not in a reusable workflow it calls.
  if (claims.job_workflow_ref !== claims.workflow_ref) return "job_workflow_not_allowed";
  if (claims.environment !== rule.environment) return "environment_mismatch";
  return undefined;
}

/**
 * Pure admission of one verified GitHub Actions OIDC caller for one purpose. Throws OidcRefusal with
 * the first failed check. The order reveals as little as possible to a caller that is not admitted:
 * any GitHub workflow can obtain a token for this audience, so the Deployment Repo allowlist comes
 * first. Returns the one repository to mint for, the exact permission set and the access it implies.
 */
export function admitOidcRequest(policy, claims, purposeName) {
  const oidc = policy?.oidc;
  if (!oidc) fail("the policy declares no OIDC purposes");
  const repositoryId = decimalClaim(claims?.repository_id);
  const ownerId = decimalClaim(claims?.repository_owner_id);
  if (repositoryId === undefined || ownerId === undefined) refuseOidc("token_claims_invalid");
  const listed = oidc.deployment_repositories.find((entry) => entry.repository_id === repositoryId);
  if (!listed) refuseOidc("repository_not_admitted");
  // Repository ids survive a transfer; the owner id binds the entry to the Organization it names.
  if (listed.repository_owner_id !== ownerId) refuseOidc("repository_owner_mismatch");
  const purpose = oidc.purposes.find((entry) => entry.purpose === purposeName);
  if (!purpose) refuseOidc("purpose_unknown");
  if (purpose.repository === "caller" && ownerId !== policy.github_owner.id) refuseOidc("repository_denied");
  if (!oidc.runner_environments.includes(claims.runner_environment)) refuseOidc("runner_not_allowed");

  let refusal;
  for (const rule of purpose.rules) {
    const ruleRefused = oidcRuleRefusal(purpose, rule, claims);
    if (ruleRefused === undefined) {
      const permissions = rule.read_only ? lowerToRead(purpose.permissions) : purpose.permissions;
      return Object.freeze({
        purpose: purpose.purpose,
        repository_id: purpose.repository === "caller" ? repositoryId : purpose.repository.repository_id,
        permissions,
        access: Object.values(permissions).includes("write") ? WRITE_ACCESS : READ_ACCESS,
        max_grants_per_run: purpose.max_grants_per_run,
      });
    }
    if (refusal === undefined || OIDC_RULE_CHECKS.indexOf(ruleRefused) > OIDC_RULE_CHECKS.indexOf(refusal)) {
      refusal = ruleRefused;
    }
  }
  refuseOidc(refusal);
}

const JTI_PATTERN = /^[\x21-\x7e]{1,256}$/;

/**
 * Deny-only per-run state behind the OIDC route: each OIDC token (`jti`) is accepted once, and each
 * purpose at most `limit` times per workflow run attempt. `storage` is one run's Durable Object
 * storage (or an equivalent with get, put, getAlarm and setAlarm). It never allows anything the
 * admission refused; it only refuses. Returns "admitted", "replayed" or "rate_limited".
 */
export async function admitRunGrant(storage, request, now) {
  const { jti, expires_at: expiresAt, purpose, limit } = request ?? {};
  if (
    typeof jti !== "string" ||
    !JTI_PATTERN.test(jti) ||
    !Number.isSafeInteger(expiresAt) ||
    expiresAt <= 0 ||
    typeof purpose !== "string" ||
    !PURPOSE_NAME_PATTERN.test(purpose) ||
    !Number.isSafeInteger(limit) ||
    limit < 1 ||
    limit > MAX_GRANTS_PER_RUN
  ) {
    fail("run guard request is invalid");
  }
  const stored = await storage.get("run");
  const nowSeconds = Math.floor(now / 1000);
  // A token past its expiry and the verifier's tolerance can no longer be presented at all.
  const jtis = (Array.isArray(stored?.jtis) ? stored.jtis : []).filter(
    ([, expiry]) => expiry + 2 * OIDC_CLOCK_TOLERANCE_SECONDS >= nowSeconds,
  );
  const grants = Array.isArray(stored?.grants) ? stored.grants : [];
  if (jtis.some(([seen]) => seen === jti)) return "replayed";
  const used = grants.find(([name]) => name === purpose)?.[1] ?? 0;
  if (used >= limit) return "rate_limited";
  await storage.put("run", {
    jtis: [...jtis, [jti, expiresAt]],
    grants: [...grants.filter(([name]) => name !== purpose), [purpose, used + 1]],
  });
  if ((await storage.getAlarm()) === null) await storage.setAlarm(now + RUN_GUARD_RETENTION_MS);
  return "admitted";
}

function base64urlJson(value) {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function createGithubClient({ appId, signJwt, fetchImpl = fetch, now = () => Date.now() }) {
  if (!/^\d+$/.test(String(appId))) fail("GITHUB_APP_ID must be numeric");
  if (typeof signJwt !== "function") fail("GitHub App JWT signer is missing");

  let cachedJwt;
  async function appJwt() {
    const timestamp = Math.floor(now() / 1000);
    if (cachedJwt && timestamp < cachedJwt.refreshAt) return cachedJwt.value;
    const unsigned = `${base64urlJson({ alg: "RS256", typ: "JWT" })}.${base64urlJson({
      iat: timestamp - 60,
      exp: timestamp + 540,
      iss: String(appId),
    })}`;
    const signature = await signJwt(unsigned);
    if (typeof signature !== "string" || !/^[A-Za-z0-9_-]+$/.test(signature)) {
      fail("GitHub App JWT signer returned an invalid signature");
    }
    cachedJwt = Object.freeze({ value: `${unsigned}.${signature}`, refreshAt: timestamp + 480 });
    return cachedJwt.value;
  }

  async function request(
    path,
    {
      method = "GET",
      authorization,
      body,
      accept = "application/vnd.github+json",
      tolerateNotFound = false,
    } = {},
  ) {
    const response = await fetchImpl(`https://api.github.com${path}`, {
      method,
      headers: {
        Accept: accept,
        Authorization: authorization ?? `Bearer ${await appJwt()}`,
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
        "User-Agent": USER_AGENT,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (tolerateNotFound && response.status === 404) return undefined;
    if (!response.ok) throw new Error(`GitHub request failed with HTTP ${response.status}`);
    if (response.status === 204) return null;
    return response.json();
  }

  async function withProbeToken(policy, permissions, run) {
    const probe = await request(`/app/installations/${policy.installation_id}/access_tokens`, {
      method: "POST",
      body: { permissions },
    });
    if (!probe?.token) fail("GitHub installation probe returned no token");
    const authorization = `Bearer ${probe.token}`;
    let result;
    try {
      result = await run(authorization);
    } catch (error) {
      // The refusal is the primary outcome; a failed revocation must not disguise it.
      await request("/installation/token", { method: "DELETE", authorization }).catch(() => {});
      throw error;
    }
    await request("/installation/token", { method: "DELETE", authorization });
    return result;
  }

  /**
   * Installation gate: exact App identity, Organization target, repository selection mode and
   * permission set. The policy names no repositories, so the gate enumerates none; the live Team
   * grant decides which repository a Workspace may use.
   */
  async function verifyPolicy(policy) {
    if (String(policy.github_app.id) !== String(appId)) {
      fail("configured GitHub App id differs from policy");
    }
    const installation = await request(`/app/installations/${policy.installation_id}`);
    if (
      installation?.app_id !== policy.github_app.id ||
      installation?.app_slug !== policy.github_app.slug ||
      installation?.account?.id !== policy.github_owner.id ||
      installation?.account?.login !== policy.github_owner.login ||
      installation?.target_type !== "Organization" ||
      installation?.repository_selection !== policy.installation_repository_selection ||
      canonicalObject(installation?.permissions) !== canonicalObject(policy.installation_permissions)
    ) {
      fail("live GitHub installation identity, selection or permissions differ from policy");
    }
  }

  function grantRole(permissions) {
    if (permissions?.admin === true) return "admin";
    if (permissions?.maintain === true) return "maintain";
    if (permissions?.push === true) return "write";
    if (permissions?.triage === true) return "triage";
    if (permissions?.pull === true) return "read";
    return "none";
  }

  async function readTeam(policy, workspace, authorization) {
    const team = await request(`/organizations/${policy.github_owner.id}/team/${workspace.github_team_id}`, {
      authorization,
      tolerateNotFound: true,
    });
    if (team === undefined) {
      refuse(`Workspace ${workspace.id} GitHub Team ${workspace.github_team_id} no longer exists in the Organization`);
    }
    if (
      team?.id !== workspace.github_team_id ||
      team?.organization?.id !== policy.github_owner.id ||
      team?.organization?.login !== policy.github_owner.login ||
      typeof team?.slug !== "string" ||
      (workspace.github_team_slug !== undefined && team.slug !== workspace.github_team_slug)
    ) {
      refuse(`Workspace ${workspace.id} live GitHub Team identity differs from policy`);
    }
    return Object.freeze({ id: team.id, slug: team.slug });
  }

  /** Resolves an immutable repository id to its live coordinate inside the policy's Organization. */
  async function resolveRepositoryId(policy, workspace, repositoryId, authorization) {
    const repository = await request(`/repositories/${repositoryId}`, { authorization, tolerateNotFound: true });
    if (repository === undefined) {
      refuse(`Workspace ${workspace.id} cannot see repository ${repositoryId}`);
    }
    if (repository?.owner?.id !== policy.github_owner.id) {
      deny(`repository ${repositoryId} belongs to another owner than the policy's Organization`);
    }
    const coordinate = parseRepositoryCoordinate(repository?.full_name);
    if (repository?.id !== repositoryId || !coordinate) {
      fail("GitHub returned an invalid repository identity");
    }
    return coordinate;
  }

  async function readTeamGrant(policy, workspace, target, authorization) {
    let coordinate;
    if (target?.repository_id !== undefined) {
      coordinate = await resolveRepositoryId(policy, workspace, target.repository_id, authorization);
    } else {
      coordinate = parseRepositoryCoordinate(target?.repository);
      if (!coordinate) fail("repository coordinate is invalid");
      if (coordinate.owner.toLowerCase() !== policy.github_owner.login.toLowerCase()) {
        deny(`repository ${coordinate.full_name} belongs to another owner than the policy's Organization`);
      }
    }
    const grant = await request(
      `/organizations/${policy.github_owner.id}/team/${workspace.github_team_id}/repos/${encodeURIComponent(coordinate.owner)}/${encodeURIComponent(coordinate.name)}`,
      { authorization, accept: REPOSITORY_PERMISSIONS_MEDIA_TYPE, tolerateNotFound: true },
    );
    if (grant === undefined) {
      refuse(`Workspace ${workspace.id} GitHub Team has no live grant on repository ${coordinate.full_name}`);
    }
    if (grant?.owner && grant.owner.id !== policy.github_owner.id) {
      deny(`repository ${coordinate.full_name} belongs to another owner than the policy's Organization`);
    }
    const role = grantRole(grant?.permissions);
    const access = grantAccess(role, workspace);
    const returned = parseRepositoryCoordinate(grant?.full_name);
    if (
      grant?.owner?.id !== policy.github_owner.id ||
      !Number.isSafeInteger(grant?.id) ||
      grant.id <= 0 ||
      !returned ||
      (target?.repository_id !== undefined && grant.id !== target.repository_id) ||
      access === undefined
    ) {
      refuse(`Workspace ${workspace.id} GitHub Team holds no verifiable grant on repository ${coordinate.full_name}`);
    }
    return Object.freeze({
      workspace_id: workspace.id,
      github_team_id: workspace.github_team_id,
      repository_id: grant.id,
      full_name: returned.full_name,
      role,
      access,
    });
  }

  /**
   * Live per-mint Team gate. `target` is `{ repository: "Owner/name" }` or `{ repository_id }`.
   * Throws RepositoryDeniedError when the repository belongs to another owner, and TeamGrantError
   * when the Workspace's immutable GitHub Team is gone, has a different identity than the policy
   * asserts, or holds no grant on the repository. A `pull`/`triage` grant resolves to the read
   * tier, a `push`/`maintain`/`admin` grant to the write tier. Nothing is cached across calls.
   */
  async function verifyTeamGrant(policy, workspace, target) {
    return withProbeToken(policy, TEAM_PROBE_PERMISSIONS, async (authorization) => {
      const team = await readTeam(policy, workspace, authorization);
      const grant = await readTeamGrant(policy, workspace, target, authorization);
      return Object.freeze({ ...grant, github_team_slug: team.slug });
    });
  }

  /**
   * Live Workspace identity proof: the Workspace's immutable Team exists in the Organization with
   * the asserted identity. Reads through the revoked probe and mints no repository token.
   */
  async function verifyWorkspaceTeam(policy, workspace) {
    return withProbeToken(policy, TEAM_PROBE_PERMISSIONS, (authorization) => readTeam(policy, workspace, authorization));
  }

  /**
   * Readback of one Workspace: its Team identity and the Team's live repository grants with the
   * access tier each one mints, with a single probe token. A missing or drifted Team becomes one
   * refused row; it never throws for that case.
   */
  async function readWorkspaceTeamGrants(policy, workspace) {
    return withProbeToken(policy, TEAM_PROBE_PERMISSIONS, async (authorization) => {
      let team;
      try {
        team = await readTeam(policy, workspace, authorization);
      } catch (error) {
        if (error?.code !== TEAM_GRANT_MISSING) throw error;
        return Object.freeze([
          Object.freeze({
            workspace_id: workspace.id,
            github_team_id: workspace.github_team_id,
            github_team_slug: workspace.github_team_slug ?? "?",
            repository_id: "-",
            full_name: "-",
            role: "-",
            access: "-",
            status: "refused",
            detail: error.message,
          }),
        ]);
      }
      const rows = [];
      for (let page = 1; ; page += 1) {
        if (page > MAX_TEAM_REPOSITORY_PAGES) fail("GitHub Team repository list exceeds the readback bound");
        const repositories = await request(
          `/organizations/${policy.github_owner.id}/team/${workspace.github_team_id}/repos?per_page=100&page=${page}`,
          { authorization },
        );
        if (!Array.isArray(repositories)) fail("GitHub returned an invalid Team repository list");
        for (const repository of repositories) {
          const role = grantRole(repository?.permissions);
          const access = grantAccess(role, workspace);
          const coordinate = parseRepositoryCoordinate(repository?.full_name);
          if (
            repository?.owner?.id !== policy.github_owner.id ||
            !Number.isSafeInteger(repository?.id) ||
            !coordinate ||
            access === undefined
          ) {
            continue;
          }
          rows.push(
            Object.freeze({
              workspace_id: workspace.id,
              github_team_id: workspace.github_team_id,
              github_team_slug: team.slug,
              repository_id: repository.id,
              full_name: coordinate.full_name,
              role,
              access,
              status: "ok",
              detail: "",
            }),
          );
        }
        if (repositories.length < 100) break;
      }
      if (rows.length === 0) {
        rows.push(
          Object.freeze({
            workspace_id: workspace.id,
            github_team_id: workspace.github_team_id,
            github_team_slug: team.slug,
            repository_id: "-",
            full_name: "-",
            role: "-",
            access: "-",
            status: "ok",
            detail: "Team holds no repository grant",
          }),
        );
      }
      return Object.freeze(rows);
    });
  }

  /**
   * Mints the one-repository token of the `access` tier the live Team gate resolved for `workspace`.
   * The tier and the Workspace are required: there is no default, so a caller that lost either can
   * never mint the write set or skip the Workspace's permission ceiling.
   */
  /**
   * Mints one installation token for exactly `repositoryId` with exactly `requested` (plus GitHub's
   * automatic `metadata: read`). A response outside that scope is revoked at once with its own token
   * and refused, so a token nobody may hold never outlives the request. `sameIdentity` adds checks of
   * the returned repository object.
   */
  async function mintScopedToken(policy, repositoryId, requested, sameIdentity = () => true) {
    const result = await request(`/app/installations/${policy.installation_id}/access_tokens`, {
      method: "POST",
      body: {
        repository_ids: [repositoryId],
        permissions: requested,
      },
    });
    const expiresAt = Date.parse(result?.expires_at ?? "");
    const returnedRepositories = result?.repositories ?? [];
    const returnedPermissions = result?.permissions ?? {};
    if (
      typeof result?.token !== "string" ||
      result.token.length < 20 ||
      !Number.isFinite(expiresAt) ||
      expiresAt <= now() ||
      expiresAt > now() + 65 * 60 * 1000 ||
      returnedRepositories.length !== 1 ||
      returnedRepositories[0]?.id !== repositoryId ||
      Object.entries(requested).some(([permission, level]) => returnedPermissions[permission] !== level) ||
      Object.entries(returnedPermissions).some(
        ([permission, level]) =>
          requested[permission] !== level && !(permission === "metadata" && level === "read"),
      ) ||
      !sameIdentity(returnedRepositories[0])
    ) {
      if (typeof result?.token === "string" && /^[!-~]{1,255}$/.test(result.token)) {
        // The refusal is the outcome; a failed revocation must not disguise it.
        await request("/installation/token", { method: "DELETE", authorization: `Bearer ${result.token}` }).catch(
          () => {},
        );
      }
      fail("GitHub returned a token outside the requested repository or permission scope");
    }
    return result;
  }

  async function mintToken(policy, workspace, repositoryId, access) {
    const requested = tokenPermissions(policy, access, workspace);
    const result = await mintScopedToken(policy, repositoryId, requested);
    return { token: result.token, expires_at: result.expires_at, repository_id: repositoryId, access };
  }

  /**
   * Mints the token of an admitted OIDC purpose: one repository of the policy's Organization and
   * exactly the purpose's permission set, which must lie within the accepted installation
   * permissions. Returns the canonical repository name GitHub reports for that id.
   */
  async function mintPurposeToken(policy, repositoryId, permissions) {
    if (!Number.isSafeInteger(repositoryId) || repositoryId <= 0) fail("purpose token needs a repository id");
    const requested = Object.freeze({ ...plainObject(permissions, "purpose permissions") });
    if (Object.keys(requested).length === 0 || Object.values(requested).some((level) => !PERMISSION_LEVELS[level])) {
      fail("purpose token needs an exact permission set");
    }
    assertAccepted(policy.installation_permissions, requested, "purpose token");
    const result = await mintScopedToken(
      policy,
      repositoryId,
      requested,
      (repository) => repository?.owner?.id === policy.github_owner.id && parseRepositoryCoordinate(repository?.full_name) !== undefined,
    );
    return {
      token: result.token,
      expires_at: result.expires_at,
      repository_id: repositoryId,
      repository: parseRepositoryCoordinate(result.repositories[0].full_name).full_name,
      permissions: requested,
    };
  }

  return Object.freeze({
    verifyPolicy,
    verifyTeamGrant,
    verifyWorkspaceTeam,
    readWorkspaceTeamGrants,
    mintToken,
    mintPurposeToken,
  });
}

/**
 * Migration and readback gate: verifies the live installation, then every Workspace's Team
 * binding, and lists each Team's live repository grants with the access tier each one mints as
 * information. Only a missing or drifted Team (or installation drift, which throws) makes the
 * result not ok. Emits no secret.
 */
export async function checkPolicyLive({ policy, github }) {
  if (typeof github?.verifyPolicy !== "function" || typeof github?.readWorkspaceTeamGrants !== "function") {
    fail("GitHub client is invalid");
  }
  await github.verifyPolicy(policy);
  const rows = [];
  for (const workspace of policy.workspaces) {
    rows.push(...(await github.readWorkspaceTeamGrants(policy, workspace)));
  }
  return Object.freeze({ ok: rows.every(({ status }) => status === "ok"), rows: Object.freeze(rows) });
}

const POLICY_CHECK_COLUMNS = Object.freeze([
  ["workspace_id", "WORKSPACE"],
  ["github_team_id", "TEAM_ID"],
  ["github_team_slug", "TEAM_SLUG"],
  ["repository_id", "REPOSITORY_ID"],
  ["full_name", "REPOSITORY"],
  ["role", "ROLE"],
  ["access", "ACCESS"],
  ["status", "STATUS"],
  ["detail", "DETAIL"],
]);

export function formatPolicyCheckTable(rows) {
  const cells = rows.map((row) => POLICY_CHECK_COLUMNS.map(([key]) => String(row[key] ?? "")));
  const widths = POLICY_CHECK_COLUMNS.map(([, header], column) =>
    Math.max(header.length, ...cells.map((line) => line[column].length)),
  );
  const line = (values) => values.map((value, column) => value.padEnd(widths[column])).join("  ").trimEnd();
  const workspaces = new Map();
  for (const row of rows) {
    const refused = workspaces.get(row.workspace_id) === "refused" || row.status !== "ok";
    workspaces.set(row.workspace_id, refused ? "refused" : "ok");
  }
  const refusedTeams = [...workspaces.values()].filter((status) => status === "refused").length;
  const grants = rows.filter(({ status, repository_id }) => status === "ok" && repository_id !== "-");
  const writeGrants = grants.filter(({ access }) => access === WRITE_ACCESS).length;
  const readGrants = grants.filter(({ access }) => access === READ_ACCESS).length;
  return [
    line(POLICY_CHECK_COLUMNS.map(([, header]) => header)),
    ...cells.map(line),
    `${workspaces.size} Workspaces checked, ${workspaces.size - refusedTeams} Teams ok, ${refusedTeams} refused; ${grants.length} repository grants (${writeGrants} write, ${readGrants} read)`,
  ].join("\n") + "\n";
}

function result(status, body) {
  return Object.freeze({ status, body });
}

/** The verified claims of an OIDC caller that an audit line keeps; never the token itself. */
function auditedCaller(claims) {
  return Object.freeze({
    repository_id: claims.repository_id ?? null,
    repository_owner_id: claims.repository_owner_id ?? null,
    repository: claims.repository ?? null,
    event_name: claims.event_name ?? null,
    ref: claims.ref ?? null,
    environment: claims.environment ?? null,
    workflow_ref: claims.workflow_ref ?? null,
    job_workflow_ref: claims.job_workflow_ref ?? null,
    runner_environment: claims.runner_environment ?? null,
    run_id: claims.run_id ?? null,
    run_attempt: claims.run_attempt ?? null,
    actor_id: claims.actor_id ?? null,
    actor: claims.actor ?? null,
    sha: claims.sha ?? null,
    jti: claims.jti ?? null,
  });
}

/**
 * One audit line per OIDC decision (`lazurio.github_app_broker.audit.v1`). It carries the decision,
 * its code, the purpose, the verified caller claims (none for a token that did not verify) and, for
 * a grant, the repository, access, permissions and expiry. It never carries a token, the OIDC token
 * or a request header.
 */
function oidcAuditRecord({ at, status, code, purpose, claims, grant }) {
  return Object.freeze({
    schema_version: AUDIT_SCHEMA,
    at,
    event: "oidc_token",
    decision: status === 200 ? "granted" : "refused",
    status,
    code,
    purpose: purpose ?? null,
    caller: claims ? auditedCaller(claims) : null,
    grant: grant ?? null,
  });
}

/**
 * `oidc` holds the adapter's OIDC capabilities: `verify(token)` returns verified claims or throws
 * OidcRefusal, `guard.admit(...)` is the per-run replay and grant budget, `audit(record)` receives
 * one line per decision and `now()` is the clock. Without them, or without an `oidc` policy section,
 * `POST /v1/oidc/token` does not exist (404).
 */
export function createBrokerHandler({ policy, github, credentials, secretMatches, oidc }) {
  if (!(credentials instanceof Map)) fail("Workspace credentials must be a Map");
  if (typeof secretMatches !== "function") fail("secret matcher is missing");
  if (
    typeof github?.verifyTeamGrant !== "function" ||
    typeof github?.verifyWorkspaceTeam !== "function" ||
    typeof github?.mintToken !== "function"
  ) {
    fail("GitHub client must verify the Team grant and Workspace Team and mint tokens");
  }
  const oidcEnabled = policy.oidc !== undefined && oidc !== undefined;
  if (
    oidcEnabled &&
    (typeof oidc.verify !== "function" ||
      typeof oidc.guard?.admit !== "function" ||
      typeof oidc.audit !== "function" ||
      typeof oidc.now !== "function" ||
      typeof github.mintPurposeToken !== "function")
  ) {
    fail("OIDC purposes need a verifier, a run guard, an audit sink, a clock and a purpose mint");
  }
  const workspaces = new Map(policy.workspaces.map((workspace) => [workspace.id, workspace]));
  const ownerKey = policy.github_owner.login.toLowerCase();

  async function authenticate(workspaceId, authorization) {
    const presentedCredential = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
    const workspace = typeof workspaceId === "string" ? workspaces.get(workspaceId) : undefined;
    const credentialMatches = await secretMatches(
      presentedCredential,
      (typeof workspaceId === "string" ? credentials.get(workspaceId) : undefined) ??
        DUMMY_WORKSPACE_CREDENTIAL,
    );
    return workspace && presentedCredential && credentialMatches ? workspace : undefined;
  }

  /** Maps a live-gate refusal to its 403; any other failure stays a 502. */
  function refusal(error) {
    if (error?.code === TEAM_GRANT_MISSING || error?.code === REPOSITORY_DENIED) {
      return result(403, { error: error.code });
    }
    throw error;
  }

  async function token(workspace, readBody) {
    if (typeof readBody !== "function") fail("request body reader is missing");
    const bodyText = await readBody();
    if (typeof bodyText !== "string") fail("request body reader returned an invalid value");
    if (new TextEncoder().encode(bodyText).byteLength > MAX_BODY_BYTES) {
      fail("request body is too large");
    }
    const target = parseTokenRequest(bodyText);
    if (!target) return result(400, { error: INVALID_REQUEST });
    // A name outside the policy's Organization is refused before any GitHub traffic.
    if (target.repository !== undefined && target.repository.split("/", 1)[0].toLowerCase() !== ownerKey) {
      return result(403, { error: REPOSITORY_DENIED });
    }

    let grant;
    try {
      grant = await github.verifyTeamGrant(policy, workspace, target);
    } catch (error) {
      return refusal(error);
    }
    const repositoryId = grant?.repository_id;
    const repository = parseRepositoryCoordinate(grant?.full_name);
    const access = grant?.access;
    if (!Number.isSafeInteger(repositoryId) || repositoryId <= 0 || !repository) {
      fail("Team gate returned an invalid repository");
    }
    if (access !== WRITE_ACCESS && access !== READ_ACCESS) fail("Team gate returned an invalid access tier");
    const minted = await github.mintToken(policy, workspace, repositoryId, access);
    if (minted?.repository_id !== repositoryId) fail("minted token is outside the verified repository");
    if (minted?.access !== access) fail("minted token is outside the verified access tier");
    return result(200, {
      token: minted.token,
      expires_at: minted.expires_at,
      repository_id: repositoryId,
      repository: repository.full_name,
      access,
    });
  }

  /** Repository-independent connection proof; the body is never read and no token is minted. */
  async function workspaceProof(workspace) {
    let team;
    try {
      team = await github.verifyWorkspaceTeam(policy, workspace);
    } catch (error) {
      return refusal(error);
    }
    if (team?.id !== workspace.github_team_id || typeof team?.slug !== "string") {
      fail("Workspace Team proof returned an invalid Team");
    }
    return result(200, {
      workspace_id: workspace.id,
      organization: policy.github_owner.login,
      github_team_id: team.id,
      github_team_slug: team.slug,
    });
  }

  /**
   * `POST /v1/oidc/token`: a GitHub Actions OIDC token and `{"purpose": "<name>"}` in, one
   * installation token for the purpose's one repository out. Gates, in order: token verification,
   * body, admission by the purpose table, the per-run replay and grant budget, then (in the adapter)
   * the live installation gate and the scoped mint. Every outcome writes one audit line.
   */
  async function oidcToken({ contentType, authorization, readBody }) {
    let claims;
    let purposeName;
    const audit = (status, code, grant) => {
      try {
        oidc.audit(
          oidcAuditRecord({ at: new Date(oidc.now()).toISOString(), status, code, purpose: purposeName, claims, grant }),
        );
      } catch {
        // An audit sink failure never changes the decision.
      }
    };
    const refused = (code) => {
      const status = OIDC_REFUSALS[code];
      audit(status, code);
      return result(status, { error: code });
    };
    if (!contentType.toLowerCase().startsWith("application/json")) return refused("unsupported_media_type");
    try {
      const bearer = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
      if (bearer === "") return refused("token_missing");
      claims = await oidc.verify(bearer);

      if (typeof readBody !== "function") fail("request body reader is missing");
      const bodyText = await readBody();
      if (typeof bodyText !== "string") fail("request body reader returned an invalid value");
      if (new TextEncoder().encode(bodyText).byteLength > MAX_BODY_BYTES) fail("request body is too large");
      purposeName = parseOidcTokenRequest(bodyText);
      if (purposeName === undefined) return refused(INVALID_REQUEST);

      const admitted = admitOidcRequest(policy, claims, purposeName);
      if (
        decimalClaim(claims.run_id) === undefined ||
        decimalClaim(claims.run_attempt) === undefined ||
        typeof claims.jti !== "string" ||
        !Number.isSafeInteger(claims.exp)
      ) {
        return refused("token_claims_invalid");
      }
      const decision = await oidc.guard.admit({
        key: `${claims.repository_id}/${claims.run_id}/${claims.run_attempt}`,
        jti: claims.jti,
        expires_at: claims.exp,
        purpose: admitted.purpose,
        limit: admitted.max_grants_per_run,
      });
      if (decision === "replayed") return refused("token_replayed");
      if (decision === "rate_limited") return refused("rate_limited");
      if (decision !== "admitted") fail("run guard returned an invalid decision");

      const minted = await github.mintPurposeToken(policy, admitted.repository_id, admitted.permissions);
      const repository = parseRepositoryCoordinate(minted?.repository);
      if (
        typeof minted?.token !== "string" ||
        minted.repository_id !== admitted.repository_id ||
        !repository ||
        canonicalObject(minted.permissions) !== canonicalObject(admitted.permissions)
      ) {
        fail("minted purpose token is outside the admitted repository or permission set");
      }
      const grant = Object.freeze({
        repository_id: admitted.repository_id,
        repository: repository.full_name,
        access: admitted.access,
        permissions: admitted.permissions,
        expires_at: minted.expires_at,
      });
      audit(200, "granted", grant);
      return result(200, {
        token: minted.token,
        expires_at: minted.expires_at,
        repository_id: admitted.repository_id,
        repository: repository.full_name,
        access: admitted.access,
        permissions: admitted.permissions,
      });
    } catch (error) {
      if (error instanceof OidcRefusal) return refused(error.code);
      return refused("token_unavailable");
    }
  }

  return async ({
    method,
    path,
    contentType = "",
    workspaceId,
    authorization = "",
    readBody = async () => "",
  }) => {
    if (method === "GET" && path === "/health") {
      return result(204, null);
    }
    if (method === "POST" && path === "/v1/oidc/token" && oidcEnabled) {
      return oidcToken({ contentType, authorization, readBody });
    }
    if (method !== "POST" || (path !== "/v1/token" && path !== "/v1/workspace")) {
      return result(404, { error: "not_found" });
    }
    if (!contentType.toLowerCase().startsWith("application/json")) {
      return result(415, { error: "unsupported_media_type" });
    }

    try {
      const workspace = await authenticate(workspaceId, authorization);
      if (!workspace) return result(401, { error: "workspace_unauthorized" });
      return path === "/v1/token" ? await token(workspace, readBody) : await workspaceProof(workspace);
    } catch {
      return result(502, { error: "token_unavailable" });
    }
  };
}
