// SPDX-License-Identifier: Apache-2.0

export const MAX_BODY_BYTES = 1024;

const POLICY_SCHEMA = "lazurio.github_app_broker.policy.v2";
const RETIRED_POLICY_SCHEMA = "lazurio.github_app_broker.policy.v1";
const GITHUB_API_VERSION = "2026-03-10";
const USER_AGENT = "lazurio-github-app-broker/0.9.0";
const DUMMY_WORKSPACE_CREDENTIAL = "0".repeat(64);
const TOKEN_PERMISSIONS = Object.freeze({
  actions: "write",
  checks: "read",
  contents: "write",
  pull_requests: "write",
});
/** Organization `members: read` is the GitHub App permission that reads Teams and Team repository grants. */
const TEAM_PROBE_PERMISSIONS = Object.freeze({ members: "read" });
/** Custom media type that makes the Team repository check return the repository with its `permissions`. */
const REPOSITORY_PERMISSIONS_MEDIA_TYPE = "application/vnd.github.v3.repository+json";

export const TEAM_GRANT_MISSING = "team_grant_missing";

/** A live GitHub Team binding or repository grant diverged from the policy; the broker mints nothing. */
export class TeamGrantError extends Error {
  constructor(message) {
    super(message);
    this.name = "TeamGrantError";
    this.code = TEAM_GRANT_MISSING;
  }
}

function fail(message) {
  throw new Error(message);
}

function refuse(message) {
  throw new TeamGrantError(message);
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
  if (input.schema_version === RETIRED_POLICY_SCHEMA) {
    fail(
      `policy schema ${RETIRED_POLICY_SCHEMA} is retired; migrate to ${POLICY_SCHEMA} with one immutable workspaces[].github_team_id per Workspace`,
    );
  }
  if (input.schema_version !== POLICY_SCHEMA) fail("unsupported policy schema");

  const appId = positiveInteger(input.github_app?.id, "github_app.id");
  const appSlug = input.github_app?.slug;
  if (typeof appSlug !== "string" || !/^[a-z0-9](?:[a-z0-9-]{0,99})$/.test(appSlug)) {
    fail("github_app.slug is invalid");
  }
  const ownerId = positiveInteger(input.github_owner?.id, "github_owner.id");
  const ownerLogin = input.github_owner?.login;
  if (typeof ownerLogin !== "string" || !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(ownerLogin)) {
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

  if (!Array.isArray(input.repositories) || input.repositories.length === 0) {
    fail("repositories must be a non-empty array");
  }
  const repositories = input.repositories.map((repository, index) => {
    const id = positiveInteger(repository?.id, `repositories[${index}].id`);
    const fullName = repository?.full_name;
    if (
      typeof fullName !== "string" ||
      !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(fullName) ||
      fullName.split("/", 1)[0].toLowerCase() !== ownerLogin.toLowerCase()
    ) {
      fail(`repositories[${index}].full_name is invalid for the asserted owner`);
    }
    return Object.freeze({ id, full_name: fullName });
  });
  if (new Set(repositories.map(({ id }) => id)).size !== repositories.length) {
    fail("repository ids must be unique");
  }
  if (new Set(repositories.map(({ full_name }) => full_name.toLowerCase())).size !== repositories.length) {
    fail("repository full names must be unique");
  }
  const repositoryIds = new Set(repositories.map(({ id }) => id));

  if (!Array.isArray(input.workspaces) || input.workspaces.length === 0) {
    fail("workspaces must be a non-empty array");
  }
  const workspaces = input.workspaces.map((workspace, index) => {
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
    if (!Array.isArray(workspace.repository_ids) || workspace.repository_ids.length === 0) {
      fail(`workspaces[${index}].repository_ids must be non-empty`);
    }
    const ids = workspace.repository_ids.map((repositoryId, repositoryIndex) => {
      const result = positiveInteger(
        repositoryId,
        `workspaces[${index}].repository_ids[${repositoryIndex}]`,
      );
      if (!repositoryIds.has(result)) fail(`workspace ${id} references an unknown repository id`);
      return result;
    });
    if (new Set(ids).size !== ids.length) fail(`workspace ${id} repeats a repository id`);
    return Object.freeze({
      id,
      github_team_id: teamId,
      ...(teamSlug === undefined ? {} : { github_team_slug: teamSlug }),
      credential_file: credentialFile,
      repository_ids: Object.freeze(ids),
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
    repositories: Object.freeze(repositories),
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

    await withProbeToken(policy, { contents: "read" }, async (authorization) => {
      const actual = new Map();
      let page = 1;
      let total = Number.POSITIVE_INFINITY;
      while (actual.size < total && page <= 100) {
        const response = await request(`/installation/repositories?per_page=100&page=${page}`, {
          authorization,
        });
        total = response?.total_count;
        if (!Number.isSafeInteger(total) || total < 0) fail("GitHub returned an invalid repository total");
        for (const repository of response.repositories ?? []) {
          actual.set(repository.id, repository.full_name);
        }
        page += 1;
      }
      const expected = new Map(policy.repositories.map(({ id, full_name }) => [id, full_name]));
      const configuredRepositoryMissing = [...expected].some(
        ([id, fullName]) => actual.get(id) !== fullName,
      );
      const selectedInstallationHasDrift =
        policy.installation_repository_selection === "selected" && actual.size !== expected.size;
      if (actual.size !== total || configuredRepositoryMissing || selectedInstallationHasDrift) {
        fail("live GitHub installation repository grants differ from policy");
      }
    });
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

  async function readTeamGrant(policy, workspace, repositoryId, authorization) {
    const repository = policy.repositories.find(({ id }) => id === repositoryId);
    if (!repository || !workspace.repository_ids.includes(repositoryId)) {
      fail(`repository ${repositoryId} is outside the Workspace ${workspace.id} policy`);
    }
    const grant = await request(
      `/organizations/${policy.github_owner.id}/team/${workspace.github_team_id}/repos/${repository.full_name}`,
      { authorization, accept: REPOSITORY_PERMISSIONS_MEDIA_TYPE, tolerateNotFound: true },
    );
    if (grant === undefined) {
      refuse(`Workspace ${workspace.id} GitHub Team has no live grant on repository ${repository.full_name}`);
    }
    const role = grantRole(grant?.permissions);
    if (grant?.id !== repositoryId || !["admin", "maintain", "write"].includes(role)) {
      refuse(
        `Workspace ${workspace.id} GitHub Team grant on repository ${repository.full_name} is not write-capable`,
      );
    }
    return Object.freeze({
      workspace_id: workspace.id,
      github_team_id: workspace.github_team_id,
      repository_id: repositoryId,
      full_name: repository.full_name,
      role,
    });
  }

  /**
   * Live per-mint Team binding check. Throws TeamGrantError when the Workspace's immutable
   * GitHub Team is gone, has a different identity than the policy asserts, or lacks a
   * write-capable grant on the exact repository. Nothing is cached across calls.
   */
  async function verifyTeamGrant(policy, workspace, repositoryId) {
    return withProbeToken(policy, TEAM_PROBE_PERMISSIONS, async (authorization) => {
      const team = await readTeam(policy, workspace, authorization);
      const grant = await readTeamGrant(policy, workspace, repositoryId, authorization);
      return Object.freeze({ ...grant, github_team_slug: team.slug });
    });
  }

  /** Readback of every repository grant of one Workspace with a single probe token; never throws per row. */
  async function readWorkspaceTeamGrants(policy, workspace) {
    return withProbeToken(policy, TEAM_PROBE_PERMISSIONS, async (authorization) => {
      const rows = [];
      let team;
      try {
        team = await readTeam(policy, workspace, authorization);
      } catch (error) {
        if (error?.code !== TEAM_GRANT_MISSING) throw error;
        return policy.repositories
          .filter(({ id }) => workspace.repository_ids.includes(id))
          .map(({ id, full_name }) =>
            Object.freeze({
              workspace_id: workspace.id,
              github_team_id: workspace.github_team_id,
              github_team_slug: workspace.github_team_slug ?? "?",
              repository_id: id,
              full_name,
              role: "none",
              status: "refused",
              detail: error.message,
            }),
          );
      }
      for (const repositoryId of workspace.repository_ids) {
        try {
          const grant = await readTeamGrant(policy, workspace, repositoryId, authorization);
          rows.push(Object.freeze({ ...grant, github_team_slug: team.slug, status: "ok", detail: "" }));
        } catch (error) {
          if (error?.code !== TEAM_GRANT_MISSING) throw error;
          const repository = policy.repositories.find(({ id }) => id === repositoryId);
          rows.push(
            Object.freeze({
              workspace_id: workspace.id,
              github_team_id: workspace.github_team_id,
              github_team_slug: team.slug,
              repository_id: repositoryId,
              full_name: repository.full_name,
              role: "none",
              status: "refused",
              detail: error.message,
            }),
          );
        }
      }
      return Object.freeze(rows);
    });
  }

  async function mintToken(policy, repositoryId) {
    const result = await request(`/app/installations/${policy.installation_id}/access_tokens`, {
      method: "POST",
      body: {
        repository_ids: [repositoryId],
        permissions: TOKEN_PERMISSIONS,
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
      returnedPermissions.actions !== "write" ||
      returnedPermissions.checks !== "read" ||
      returnedPermissions.contents !== "write" ||
      returnedPermissions.pull_requests !== "write" ||
      Object.entries(returnedPermissions).some(
        ([permission, level]) =>
          !(
            (permission === "actions" && level === "write") ||
            (permission === "checks" && level === "read") ||
            (permission === "contents" && level === "write") ||
            (permission === "pull_requests" && level === "write") ||
            (permission === "metadata" && level === "read")
          ),
      )
    ) {
      fail("GitHub returned a token outside the requested repository or permission scope");
    }
    return { token: result.token, expires_at: result.expires_at, repository_id: repositoryId };
  }

  return Object.freeze({ verifyPolicy, verifyTeamGrant, readWorkspaceTeamGrants, mintToken });
}

/**
 * Migration and readback gate: verifies the live installation, then every Workspace's Team
 * binding and every `repository_ids` grant. Returns rows for a human table; emits no secret.
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
  ["status", "STATUS"],
  ["detail", "DETAIL"],
]);

export function formatPolicyCheckTable(rows) {
  const cells = rows.map((row) => POLICY_CHECK_COLUMNS.map(([key]) => String(row[key] ?? "")));
  const widths = POLICY_CHECK_COLUMNS.map(([, header], column) =>
    Math.max(header.length, ...cells.map((line) => line[column].length)),
  );
  const line = (values) => values.map((value, column) => value.padEnd(widths[column])).join("  ").trimEnd();
  const refused = rows.filter(({ status }) => status !== "ok").length;
  return [
    line(POLICY_CHECK_COLUMNS.map(([, header]) => header)),
    ...cells.map(line),
    `${rows.length} grants checked, ${rows.length - refused} ok, ${refused} refused`,
  ].join("\n") + "\n";
}

export function createBrokerHandler({ policy, github, credentials, secretMatches }) {
  if (!(credentials instanceof Map)) fail("Workspace credentials must be a Map");
  if (typeof secretMatches !== "function") fail("secret matcher is missing");
  if (typeof github?.verifyTeamGrant !== "function" || typeof github?.mintToken !== "function") {
    fail("GitHub client must verify the Team grant and mint tokens");
  }
  const workspaces = new Map(policy.workspaces.map((workspace) => [workspace.id, workspace]));

  return async ({
    method,
    path,
    contentType = "",
    workspaceId,
    authorization = "",
    readBody = async () => "",
  }) => {
    if (method === "GET" && path === "/health") {
      return Object.freeze({ status: 204, body: null });
    }
    if (method !== "POST" || path !== "/v1/token") {
      return Object.freeze({ status: 404, body: { error: "not_found" } });
    }
    if (!contentType.toLowerCase().startsWith("application/json")) {
      return Object.freeze({ status: 415, body: { error: "unsupported_media_type" } });
    }

    const presentedCredential = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
    try {
      const workspace = typeof workspaceId === "string" ? workspaces.get(workspaceId) : undefined;
      const credentialMatches = await secretMatches(
        presentedCredential,
        (typeof workspaceId === "string" ? credentials.get(workspaceId) : undefined) ??
          DUMMY_WORKSPACE_CREDENTIAL,
      );
      if (!workspace || !presentedCredential || !credentialMatches) {
        return Object.freeze({ status: 401, body: { error: "workspace_unauthorized" } });
      }

      if (typeof readBody !== "function") fail("request body reader is missing");
      const bodyText = await readBody();
      if (typeof bodyText !== "string") fail("request body reader returned an invalid value");
      if (new TextEncoder().encode(bodyText).byteLength > MAX_BODY_BYTES) {
        fail("request body is too large");
      }
      const body = JSON.parse(bodyText);
      const repositoryId = body?.repository_id;
      if (!Number.isSafeInteger(repositoryId) || !workspace.repository_ids.includes(repositoryId)) {
        return Object.freeze({ status: 403, body: { error: "repository_denied" } });
      }
      try {
        await github.verifyTeamGrant(policy, workspace, repositoryId);
      } catch (error) {
        if (error?.code === TEAM_GRANT_MISSING) {
          return Object.freeze({ status: 403, body: { error: TEAM_GRANT_MISSING } });
        }
        throw error;
      }
      return Object.freeze({ status: 200, body: await github.mintToken(policy, repositoryId) });
    } catch {
      return Object.freeze({ status: 502, body: { error: "token_unavailable" } });
    }
  };
}
