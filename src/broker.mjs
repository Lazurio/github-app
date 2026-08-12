#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";

const POLICY_SCHEMA = "lazurio.github_app_broker.policy.v1";
const GITHUB_API_VERSION = "2026-03-10";
const USER_AGENT = "lazurio-github-app-broker/0.1";
const MAX_BODY_BYTES = 1024;

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

  const installationPermissions = input.installation_permissions;
  if (
    !installationPermissions ||
    typeof installationPermissions !== "object" ||
    Array.isArray(installationPermissions) ||
    installationPermissions.contents !== "write" ||
    Object.entries(installationPermissions).some(
      ([key, value]) => !/^[a-z][a-z0-9_]*$/.test(key) || !["read", "write"].includes(value),
    )
  ) {
    fail("installation_permissions must be exact and include contents: write");
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
      !/^\/run\/secrets\/[A-Za-z0-9._-]+$/.test(credentialFile) ||
      path.posix.normalize(credentialFile) !== credentialFile
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
    installation_permissions: Object.freeze({ ...installationPermissions }),
    repositories: Object.freeze(repositories),
    workspaces: Object.freeze(workspaces),
  });
}

function base64url(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

export function createGithubClient({ appId, privateKey, fetchImpl = fetch, now = () => Date.now() }) {
  if (!/^\d+$/.test(String(appId))) fail("GITHUB_APP_ID must be numeric");
  if (!privateKey) fail("GitHub App private key is missing");

  function appJwt() {
    const timestamp = Math.floor(now() / 1000);
    const unsigned = `${base64url({ alg: "RS256", typ: "JWT" })}.${base64url({
      iat: timestamp - 60,
      exp: timestamp + 540,
      iss: String(appId),
    })}`;
    const signature = crypto.sign("RSA-SHA256", Buffer.from(unsigned), privateKey);
    return `${unsigned}.${signature.toString("base64url")}`;
  }

  async function request(path, { method = "GET", authorization = `Bearer ${appJwt()}`, body } = {}) {
    const response = await fetchImpl(`https://api.github.com${path}`, {
      method,
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: authorization,
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
      installation?.repository_selection !== "selected" ||
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
      if (
        actual.size !== total ||
        actual.size !== expected.size ||
        [...actual].some(([id, fullName]) => expected.get(id) !== fullName)
      ) {
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
        permissions: { contents: "write" },
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
      returnedPermissions.contents !== "write" ||
      Object.entries(returnedPermissions).some(
        ([permission, level]) =>
          !(
            (permission === "contents" && level === "write") ||
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

export function createReloadingPolicy({
  policyFile,
  github,
  readFile = fs.readFileSync,
  realpath = fs.realpathSync,
}) {
  let acceptedRaw;
  let acceptedPolicy;
  let pending;

  return async function getPolicy() {
    const raw = readFile(policyFile, "utf8");
    if (acceptedRaw === raw && acceptedPolicy) {
      return {
        policy: acceptedPolicy,
        credentials: snapshotWorkspaceCredentials(acceptedPolicy, { readFile, realpath }),
      };
    }
    if (pending?.raw === raw) {
      const policy = await pending.promise;
      return {
        policy,
        credentials: snapshotWorkspaceCredentials(policy, { readFile, realpath }),
      };
    }

    const promise = (async () => {
      const candidate = parsePolicy(raw);
      await github.verifyPolicy(candidate);
      acceptedRaw = raw;
      acceptedPolicy = candidate;
      return candidate;
    })();
    pending = { raw, promise };
    try {
      const policy = await promise;
      return {
        policy,
        credentials: snapshotWorkspaceCredentials(policy, { readFile, realpath }),
      };
    } finally {
      if (pending?.promise === promise) pending = undefined;
    }
  };
}

function readWorkspaceCredential(file, readFile = fs.readFileSync) {
  const credential = readFile(file, "utf8").trim();
  if (credential.length < 32 || /\s/.test(credential)) fail("Workspace credential is invalid");
  return credential;
}

function snapshotWorkspaceCredentials(policy, { readFile, realpath }) {
  const realPaths = new Set();
  const digests = new Set();
  const credentials = new Map();
  for (const workspace of policy.workspaces) {
    const resolved = realpath(workspace.credential_file);
    if (!/^\/run\/secrets\/[A-Za-z0-9._-]+$/.test(resolved) || realPaths.has(resolved)) {
      fail("Workspace credential files must resolve to unique /run/secrets files");
    }
    realPaths.add(resolved);
    const credential = readWorkspaceCredential(workspace.credential_file, readFile);
    const digest = crypto.createHash("sha256").update(credential).digest("hex");
    if (digests.has(digest)) fail("Workspace credential values must be unique");
    digests.add(digest);
    credentials.set(workspace.id, credential);
  }
  return credentials;
}

function secretMatches(actual, expected) {
  const actualDigest = crypto.createHash("sha256").update(actual).digest();
  const expectedDigest = crypto.createHash("sha256").update(expected).digest();
  return crypto.timingSafeEqual(actualDigest, expectedDigest);
}

function json(response, status, body) {
  const payload = JSON.stringify(body);
  response.writeHead(status, {
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(payload),
    "Content-Type": "application/json",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
  });
  response.end(payload);
}

async function readJsonBody(request) {
  let body = "";
  request.setEncoding("utf8");
  for await (const chunk of request) {
    body += chunk;
    if (Buffer.byteLength(body) > MAX_BODY_BYTES) fail("request body is too large");
  }
  return JSON.parse(body);
}

export function createBrokerServer({
  policy,
  getPolicy,
  github,
  readFile = fs.readFileSync,
  realpath = fs.realpathSync,
}) {
  const policySource =
    getPolicy ??
    (async () => {
      return {
        policy,
        credentials: snapshotWorkspaceCredentials(policy, { readFile, realpath }),
      };
    });

  const server = http.createServer(async (request, response) => {
    if (request.method === "GET" && request.url === "/health") {
      response.writeHead(204, { "Cache-Control": "no-store" });
      response.end();
      return;
    }
    if (request.method !== "POST" || request.url !== "/v1/token") {
      json(response, 404, { error: "not_found" });
      return;
    }
    if (!request.headers["content-type"]?.toLowerCase().startsWith("application/json")) {
      json(response, 415, { error: "unsupported_media_type" });
      return;
    }

    const workspaceId = request.headers["x-lazurio-workspace-id"];
    const authorization = request.headers.authorization ?? "";
    const presentedCredential = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
    try {
      const { policy: activePolicy, credentials } = await policySource();
      const workspace =
        typeof workspaceId === "string"
          ? activePolicy.workspaces.find(({ id }) => id === workspaceId)
          : undefined;
      if (
        !workspace ||
        !presentedCredential ||
        !secretMatches(presentedCredential, credentials.get(workspace.id) ?? "")
      ) {
        json(response, 401, { error: "workspace_unauthorized" });
        return;
      }

      const body = await readJsonBody(request);
      const repositoryId = body?.repository_id;
      if (!Number.isSafeInteger(repositoryId) || !workspace.repository_ids.includes(repositoryId)) {
        json(response, 403, { error: "repository_denied" });
        return;
      }
      json(response, 200, await github.mintToken(activePolicy, repositoryId));
    } catch {
      if (!response.headersSent) json(response, 502, { error: "token_unavailable" });
    }
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 5_000;
  server.keepAliveTimeout = 5_000;
  return server;
}

export async function startBroker({
  policy,
  getPolicy,
  github,
  readFile = fs.readFileSync,
  realpath = fs.realpathSync,
  port = 8787,
  host = "0.0.0.0",
}) {
  const policySource =
    getPolicy ??
    (async () => {
      return {
        policy,
        credentials: snapshotWorkspaceCredentials(policy, { readFile, realpath }),
      };
    });
  const initial = await policySource();
  if (!getPolicy) await github.verifyPolicy(initial.policy);
  const server = createBrokerServer({ getPolicy: policySource, github, readFile, realpath });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, resolve);
  });
  return server;
}

export function parseCommand(arguments_) {
  if (arguments_.length === 0) return Object.freeze({ verifyOnly: false });
  if (arguments_.length === 1 && arguments_[0] === "--verify-only") {
    return Object.freeze({ verifyOnly: true });
  }
  fail("usage: broker.mjs [--verify-only]");
}

async function main() {
  const command = parseCommand(process.argv.slice(2));
  const appId = process.env.GITHUB_APP_ID ?? "";
  const privateKeyFile = process.env.GITHUB_APP_PRIVATE_KEY_FILE ?? "";
  const policyFile = process.env.BROKER_POLICY_FILE ?? "";
  const port = Number(process.env.PORT ?? "8787");
  if (!privateKeyFile.startsWith("/run/secrets/") || !policyFile.startsWith("/run/config/")) {
    fail("private key and policy must be custody-mounted files");
  }
  if (!Number.isSafeInteger(port) || port !== 8787) fail("broker port must remain 8787");

  const github = createGithubClient({
    appId,
    privateKey: fs.readFileSync(privateKeyFile),
  });
  const getPolicy = createReloadingPolicy({ policyFile, github });
  if (command.verifyOnly) {
    await getPolicy();
    return;
  }
  await startBroker({ getPolicy, github, port });
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  await main();
}
