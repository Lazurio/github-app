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
    new Set(entries.map(({ repository }) => repositoryIdentityKey(repository))).size !==
      entries.length ||
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

export async function requestGitHubAppToken({
  repository,
  environment = process.env,
  readFile = fs.readFileSync,
  exists = fs.existsSync,
  fetchImpl = fetch,
  now = () => Date.now(),
  timeoutMs = 5_000,
}) {
  const coordinate = normalizeRepository(repository);
  const policy = parseRepositoryPolicy(environment);
  const coordinateKey = repositoryIdentityKey(coordinate);
  const policyEntry = policy.find(
    (entry) => repositoryIdentityKey(entry.repository) === coordinateKey,
  );
  if (!policyEntry) fail("repository is outside the Team Workspace policy");
  const { workspaceId, brokerOrigin } = requireBrokerRuntime(environment, readFile, exists);

  const clientCredential = readFile(CREDENTIAL_FILE, "utf8").trim();
  if (clientCredential.length < 32 || /\s/.test(clientCredential)) {
    fail("Workspace broker credential is invalid");
  }

  let response;
  try {
    response = await fetchImpl(`${brokerOrigin}/v1/token`, {
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
