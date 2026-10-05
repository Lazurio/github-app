// SPDX-License-Identifier: Apache-2.0
import fs from "node:fs";
import { isIP } from "node:net";

const LOCAL_BROKER_ORIGIN = "http://github-token-broker:8787";
const BROKER_CONFIG_FILE = "/run/config/github_broker_client.json";
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

/** GitHub owner and repository names identify the same resource regardless of letter case. */
export function repositoryIdentityKey(value) {
  return normalizeRepository(value).toLowerCase();
}

export function requireHttpsGitHubOrigin(value) {
  const candidate = String(value ?? "").trim();
  if (!/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\.git$/.test(candidate)) {
    fail("Hosted Team Workspace origin must use brokered HTTPS");
  }
  return normalizeRepository(candidate);
}

export function parseBrokerClientConfig(raw) {
  let input;
  try {
    input = JSON.parse(raw);
  } catch {
    fail("GitHub token broker client config is invalid");
  }
  if (
    !input ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    Object.keys(input).sort().join(",") !== "origin,schema_version" ||
    input.schema_version !== "lazurio.github_broker_client.v1" ||
    typeof input.origin !== "string"
  ) {
    fail("GitHub token broker client config is invalid");
  }
  let url;
  try {
    url = new URL(input.origin);
  } catch {
    fail("GitHub token broker client config is invalid");
  }
  const remoteHttps =
    url.protocol === "https:" &&
    (url.port === "" || url.port === "443") &&
    /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(url.hostname) &&
    isIP(url.hostname) === 0 &&
    !/^(?:localhost|127(?:\.[0-9]+){3}|0\.0\.0\.0|\[?::1\]?)$/.test(url.hostname) &&
    url.username === "" &&
    url.password === "" &&
    url.pathname === "/" &&
    url.search === "" &&
    url.hash === "" &&
    url.origin === input.origin;
  if (!remoteHttps) {
    fail("GitHub token broker client config is invalid");
  }
  return Object.freeze({ origin: input.origin });
}

function requireBrokerRuntime(environment, readFile, exists) {
  let brokerOrigin = LOCAL_BROKER_ORIGIN;
  if (exists(BROKER_CONFIG_FILE)) {
    let raw;
    try {
      raw = readFile(BROKER_CONFIG_FILE, "utf8");
    } catch {
      fail("GitHub token broker client config is unavailable");
    }
    brokerOrigin = parseBrokerClientConfig(raw).origin;
  }
  if (environment.GITHUB_TOKEN_BROKER_URL !== brokerOrigin) {
    fail("GitHub token broker endpoint is invalid");
  }
  const workspaceId = environment.GITHUB_BROKER_WORKSPACE_ID ?? "";
  if (!/^[a-z0-9][a-z0-9-]{1,62}$/.test(workspaceId)) {
    fail("Team Workspace broker identity is invalid");
  }
  if (environment.GITHUB_BROKER_CLIENT_CREDENTIAL_FILE !== CREDENTIAL_FILE) {
    fail("Workspace broker credential path is invalid");
  }
  return Object.freeze({ workspaceId, brokerOrigin });
}

/** Authenticated POST to one broker route with the pinned origin, Workspace id and credential. */
async function postToBroker(path, body, { environment, readFile, exists, fetchImpl, timeoutMs }) {
  const { workspaceId, brokerOrigin } = requireBrokerRuntime(environment, readFile, exists);

  const clientCredential = readFile(CREDENTIAL_FILE, "utf8").trim();
  if (clientCredential.length < 32 || /\s/.test(clientCredential)) {
    fail("Workspace broker credential is invalid");
  }

  let response;
  try {
    response = await fetchImpl(`${brokerOrigin}${path}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${clientCredential}`,
        "Content-Type": "application/json",
        "X-Lazurio-Workspace-ID": workspaceId,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    fail("GitHub token broker is unavailable");
  }
  if (!response.ok) fail("GitHub token broker refused the request");

  try {
    return { workspaceId, result: await response.json() };
  } catch {
    return { workspaceId, result: undefined };
  }
}

export async function requestGitHubAppToken({
  repository,
  environment = process.env,
  readFile = fs.readFileSync,
  exists = fs.existsSync,
  fetchImpl = fetch,
  now = () => Date.now(),
  timeoutMs = 5_000,
}) {
  // The broker decides the scope from the live GitHub Team grant; the client holds no allowlist.
  const coordinate = normalizeRepository(repository);
  const { result } = await postToBroker(
    "/v1/token",
    { repository: coordinate },
    { environment, readFile, exists, fetchImpl, timeoutMs },
  );
  const expiresAt = Date.parse(result?.expires_at ?? "");
  let returnedRepository;
  try {
    returnedRepository = normalizeRepository(result?.repository);
  } catch {
    returnedRepository = undefined;
  }
  // Brokers before 0.11.0 send no `access`; they mint only for push/maintain/admin grants.
  const access = result?.access === undefined ? "write" : result.access;
  if (
    (access !== "read" && access !== "write") ||
    typeof result?.token !== "string" ||
    result.token.length < 20 ||
    returnedRepository === undefined ||
    returnedRepository !== result.repository ||
    repositoryIdentityKey(returnedRepository) !== repositoryIdentityKey(coordinate) ||
    !Number.isSafeInteger(result?.repository_id) ||
    result.repository_id <= 0 ||
    !Number.isFinite(expiresAt) ||
    expiresAt <= now() ||
    expiresAt > now() + MAX_TOKEN_LIFETIME_MS
  ) {
    fail("GitHub token broker returned an invalid scoped response");
  }
  return Object.freeze({
    token: result.token,
    repository: returnedRepository,
    repositoryId: result.repository_id,
    expiresAt: result.expires_at,
    access,
  });
}

/**
 * Repository-independent connection proof: the broker verifies the live installation and the
 * Workspace's GitHub Team and mints no repository token.
 */
export async function requestWorkspaceProof({
  environment = process.env,
  readFile = fs.readFileSync,
  exists = fs.existsSync,
  fetchImpl = fetch,
  timeoutMs = 5_000,
} = {}) {
  const { workspaceId, result } = await postToBroker(
    "/v1/workspace",
    {},
    { environment, readFile, exists, fetchImpl, timeoutMs },
  );
  if (
    result?.workspace_id !== workspaceId ||
    typeof result?.organization !== "string" ||
    !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(result.organization) ||
    !Number.isSafeInteger(result?.github_team_id) ||
    result.github_team_id <= 0 ||
    typeof result?.github_team_slug !== "string" ||
    result.github_team_slug.length === 0 ||
    "token" in result
  ) {
    fail("GitHub token broker returned an invalid Workspace proof");
  }
  return Object.freeze({
    workspaceId,
    organization: result.organization,
    githubTeamId: result.github_team_id,
    githubTeamSlug: result.github_team_slug,
  });
}
