// SPDX-License-Identifier: Apache-2.0

export const MAX_BODY_BYTES = 1024;

const POLICY_SCHEMA = "lazurio.github_app_broker.policy.v1";
const GITHUB_API_VERSION = "2026-03-10";
const USER_AGENT = "lazurio-github-app-broker/0.8.0";
const DUMMY_WORKSPACE_CREDENTIAL = "0".repeat(64);
const TOKEN_PERMISSIONS = Object.freeze({
  actions: "write",
  checks: "read",
  contents: "write",
  pull_requests: "write",
});

function fail(message) {
  throw new Error(message);
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
    Object.entries(installationPermissions).some(
      ([key, value]) => !/^[a-z][a-z0-9_]*$/.test(key) || !["read", "write"].includes(value),
    )
  ) {
    fail(
      "installation_permissions must be exact and include actions: write, checks: read, contents: write and pull_requests: write",
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
    return Object.freeze({ id, credential_file: credentialFile, repository_ids: Object.freeze(ids) });
  });
  if (new Set(workspaces.map(({ id }) => id)).size !== workspaces.length) {
    fail("workspace ids must be unique");
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

  async function request(path, { method = "GET", authorization, body } = {}) {
    const response = await fetchImpl(`https://api.github.com${path}`, {
      method,
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: authorization ?? `Bearer ${await appJwt()}`,
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
        "User-Agent": USER_AGENT,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) throw new Error(`GitHub request failed with HTTP ${response.status}`);
    if (response.status === 204) return null;
    return response.json();
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

    const probe = await request(`/app/installations/${policy.installation_id}/access_tokens`, {
      method: "POST",
      body: { permissions: { contents: "read" } },
    });
    if (!probe?.token) fail("GitHub installation repository probe returned no token");

    try {
      const actual = new Map();
      let page = 1;
      let total = Number.POSITIVE_INFINITY;
      while (actual.size < total && page <= 100) {
        const response = await request(`/installation/repositories?per_page=100&page=${page}`, {
          authorization: `Bearer ${probe.token}`,
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
    } finally {
      await request("/installation/token", {
        method: "DELETE",
        authorization: `Bearer ${probe.token}`,
      });
    }
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

  return Object.freeze({ verifyPolicy, mintToken });
}

export function createBrokerHandler({ policy, github, credentials, secretMatches }) {
  if (!(credentials instanceof Map)) fail("Workspace credentials must be a Map");
  if (typeof secretMatches !== "function") fail("secret matcher is missing");
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
      return Object.freeze({ status: 200, body: await github.mintToken(policy, repositoryId) });
    } catch {
      return Object.freeze({ status: 502, body: { error: "token_unavailable" } });
    }
  };
}
