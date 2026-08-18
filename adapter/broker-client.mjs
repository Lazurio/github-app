import fs from "node:fs";

const BROKER_ORIGIN = "http://github-token-broker:8787";
const CREDENTIAL_FILE = "/run/secrets/github_broker_client_token";
const MAX_TOKEN_LIFETIME_MS = 65 * 60 * 1000;

function fail(message) {
  throw new Error(message);
}

export function normalizeRepository(value) {
  const candidate = String(value ?? "").trim();
  const coordinate = candidate
    .replace(/^https:\/\/github\.com\//, "")
    .replace(/^git@github\.com:/, "")
    .replace(/^github\.com\//, "")
    .replace(/\.git$/, "");
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(coordinate)) {
    fail("GitHub repository identity is invalid");
  }
  return coordinate;
}

export function requireHttpsGitHubOrigin(value) {
  const candidate = String(value ?? "").trim();
  if (!/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\.git$/.test(candidate)) {
    fail("Hosted Team Workspace origin must use brokered HTTPS");
  }
  return normalizeRepository(candidate);
}

export function parseRepositoryPolicy(environment = process.env) {
  let input;
  try {
    input = JSON.parse(environment.GITHUB_REPOSITORY_POLICY_JSON ?? "null");
  } catch {
    fail("Team repository policy is invalid");
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    fail("Team repository policy is invalid");
  }

  const entries = Object.entries(input).map(([repository, repositoryId]) => {
    const coordinate = normalizeRepository(repository);
    if (
      coordinate !== repository ||
      !Number.isSafeInteger(repositoryId) ||
      repositoryId <= 0
    ) {
      fail("Team repository policy is invalid");
    }
    return Object.freeze({ repository: coordinate, repositoryId });
  });
  if (entries.length === 0) fail("Team repository policy is invalid");
  if (
    new Set(entries.map(({ repository }) => repository.toLowerCase())).size !== entries.length ||
    new Set(entries.map(({ repositoryId }) => repositoryId)).size !== entries.length
  ) {
    fail("Team repository policy is invalid");
  }
  entries.sort(({ repository: left }, { repository: right }) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
  return Object.freeze(entries);
}

export function firstPolicyRepository(environment = process.env) {
  return parseRepositoryPolicy(environment)[0].repository;
}

function requireBrokerRuntime(environment) {
  if (environment.GITHUB_TOKEN_BROKER_URL !== BROKER_ORIGIN) {
    fail("GitHub token broker endpoint is invalid");
  }
  const workspaceId = environment.GITHUB_BROKER_WORKSPACE_ID ?? "";
  if (!/^[a-z0-9][a-z0-9-]{1,62}$/.test(workspaceId)) {
    fail("Team Workspace broker identity is invalid");
  }
  if (environment.GITHUB_BROKER_CLIENT_CREDENTIAL_FILE !== CREDENTIAL_FILE) {
    fail("Workspace broker credential path is invalid");
  }
  return workspaceId;
}

export async function requestGitHubAppToken({
  repository,
  environment = process.env,
  readFile = fs.readFileSync,
  fetchImpl = fetch,
  now = () => Date.now(),
  timeoutMs = 5_000,
}) {
  const coordinate = normalizeRepository(repository);
  const policy = parseRepositoryPolicy(environment);
  const policyEntry = policy.find((entry) => entry.repository === coordinate);
  if (!policyEntry) fail("repository is outside the Team Workspace policy");
  const workspaceId = requireBrokerRuntime(environment);

  const clientCredential = readFile(CREDENTIAL_FILE, "utf8").trim();
  if (clientCredential.length < 32 || /\s/.test(clientCredential)) {
    fail("Workspace broker credential is invalid");
  }

  let response;
  try {
    response = await fetchImpl(`${BROKER_ORIGIN}/v1/token`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${clientCredential}`,
        "Content-Type": "application/json",
        "X-Lazurio-Workspace-ID": workspaceId,
      },
      body: JSON.stringify({ repository_id: policyEntry.repositoryId }),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    fail("GitHub token broker is unavailable");
  }
  if (!response.ok) fail("GitHub token broker refused the request");

  let result;
  try {
    result = await response.json();
  } catch {
    fail("GitHub token broker returned an invalid scoped response");
  }
  const expiresAt = Date.parse(result?.expires_at ?? "");
  if (
    typeof result?.token !== "string" ||
    result.token.length < 20 ||
    result.repository_id !== policyEntry.repositoryId ||
    !Number.isFinite(expiresAt) ||
    expiresAt <= now() ||
    expiresAt > now() + MAX_TOKEN_LIFETIME_MS
  ) {
    fail("GitHub token broker returned an invalid scoped response");
  }
  return Object.freeze({
    token: result.token,
    repository: coordinate,
    repositoryId: policyEntry.repositoryId,
    expiresAt: result.expires_at,
  });
}
