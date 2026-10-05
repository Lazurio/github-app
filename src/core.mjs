// SPDX-License-Identifier: Apache-2.0

export const MAX_BODY_BYTES = 1024;

const POLICY_SCHEMA = "lazurio.github_app_broker.policy.v3";
const RETIRED_POLICY_SCHEMA_V1 = "lazurio.github_app_broker.policy.v1";
const RETIRED_POLICY_SCHEMA_V2 = "lazurio.github_app_broker.policy.v2";
const V3_MIGRATION =
  "migrate to lazurio.github_app_broker.policy.v3 by deleting `repositories` and every `workspaces[].repository_ids`; the live Team grant is the scope";
const GITHUB_API_VERSION = "2026-03-10";
const USER_AGENT = "lazurio-github-app-broker/0.11.0";
/** Upper bound for `policy check --live` Team repository pages (100 repositories per page). */
const MAX_TEAM_REPOSITORY_PAGES = 100;
const DUMMY_WORKSPACE_CREDENTIAL = "0".repeat(64);

/**
 * Access tiers. The live Team grant selects the tier at mint time: a `push`, `maintain` or `admin`
 * grant mints the write tier, a `pull` or `triage` grant the read tier. The policy holds no tier.
 */
export const WRITE_ACCESS = "write";
export const READ_ACCESS = "read";

const WRITE_TOKEN_PERMISSIONS = Object.freeze({
  actions: "write",
  checks: "read",
  contents: "write",
  pull_requests: "write",
});
/**
 * A read-tier token can clone, fetch and read the repository and see its pull requests and check
 * runs (plus GitHub's automatic `metadata: read`). It never asks for any contents, pull request,
 * Actions or workflow write, nor for Actions read.
 */
const READ_TOKEN_PERMISSIONS = Object.freeze({
  checks: "read",
  contents: "read",
  pull_requests: "read",
});

/**
 * The exact permission set a token of `access` asks GitHub for under `policy`. Two opt-ins follow
 * the permissions the Organization accepted and the reviewed policy declares, so a deployment
 * whose installation has not accepted them keeps minting the base sets:
 * - `workflows: write` (write tier only) lets a push touch `.github/workflows/`;
 * - `issues: write` (both tiers) is GitHub's smallest installation permission that can open an
 *   issue, so an Environment can propose a change or escalate through an issue.
 */
export function tokenPermissions(policy, access) {
  const accepted = policy.installation_permissions;
  const issues = accepted.issues === "write" ? { issues: "write" } : {};
  if (access === WRITE_ACCESS) {
    const workflows = accepted.workflows === "write" ? { workflows: "write" } : {};
    return Object.freeze({ ...WRITE_TOKEN_PERMISSIONS, ...workflows, ...issues });
  }
  if (access === READ_ACCESS) return Object.freeze({ ...READ_TOKEN_PERMISSIONS, ...issues });
  fail("token access tier must be read or write");
}

/** Maps a live Team grant role to its access tier; undefined means no usable grant. */
function grantAccess(role) {
  if (role === "admin" || role === "maintain" || role === "write") return WRITE_ACCESS;
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

function fail(message) {
  throw new Error(message);
}

function refuse(message) {
  throw new TeamGrantError(message);
}

function deny(message) {
  throw new RepositoryDeniedError(message);
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

  if (!Array.isArray(input.workspaces) || input.workspaces.length === 0) {
    fail("workspaces must be a non-empty array");
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
    return Object.freeze({
      id,
      github_team_id: teamId,
      ...(teamSlug === undefined ? {} : { github_team_slug: teamSlug }),
      credential_file: credentialFile,
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
  });
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
    const access = grantAccess(role);
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
          const access = grantAccess(role);
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
   * Mints the one-repository token of the `access` tier the live Team gate resolved. The tier is
   * required: there is no default, so a caller that lost the tier can never mint the write set.
   */
  async function mintToken(policy, repositoryId, access) {
    const requested = tokenPermissions(policy, access);
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
      )
    ) {
      fail("GitHub returned a token outside the requested repository or permission scope");
    }
    return { token: result.token, expires_at: result.expires_at, repository_id: repositoryId, access };
  }

  return Object.freeze({ verifyPolicy, verifyTeamGrant, verifyWorkspaceTeam, readWorkspaceTeamGrants, mintToken });
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

export function createBrokerHandler({ policy, github, credentials, secretMatches }) {
  if (!(credentials instanceof Map)) fail("Workspace credentials must be a Map");
  if (typeof secretMatches !== "function") fail("secret matcher is missing");
  if (
    typeof github?.verifyTeamGrant !== "function" ||
    typeof github?.verifyWorkspaceTeam !== "function" ||
    typeof github?.mintToken !== "function"
  ) {
    fail("GitHub client must verify the Team grant and Workspace Team and mint tokens");
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
    const minted = await github.mintToken(policy, repositoryId, access);
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
