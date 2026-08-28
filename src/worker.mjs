// SPDX-License-Identifier: Apache-2.0
import {
  createBrokerHandler,
  createGithubClient,
  parsePolicy,
} from "./core.mjs";

function fail(message) {
  throw new Error(message);
}

function requiredBinding(env, name) {
  const value = env?.[name];
  if (typeof value !== "string" || value.length === 0) fail(`${name} binding is missing`);
  return value;
}

export function workspaceCredentialBindingName(workspaceId) {
  if (typeof workspaceId !== "string" || !/^[a-z0-9][a-z0-9-]{1,62}$/.test(workspaceId)) {
    fail("Workspace id cannot be mapped to a Worker secret binding");
  }
  return `WORKSPACE_CREDENTIAL_${workspaceId.toUpperCase().replaceAll("-", "_")}`;
}

function workerCredentials(policy, env) {
  const values = new Set();
  const credentials = new Map();
  for (const workspace of policy.workspaces) {
    const credential = requiredBinding(env, workspaceCredentialBindingName(workspace.id));
    if (credential.length < 32 || /\s/.test(credential)) fail("Workspace credential is invalid");
    if (values.has(credential)) fail("Workspace credential values must be unique");
    values.add(credential);
    credentials.set(workspace.id, credential);
  }
  return credentials;
}

function pemBytes(privateKey) {
  const match = privateKey.trim().match(
    /^-----BEGIN PRIVATE KEY-----\s+([A-Za-z0-9+/=\s]+)\s+-----END PRIVATE KEY-----$/,
  );
  if (!match) fail("GitHub App private key must be PKCS#8 PEM");
  const binary = atob(match[1].replaceAll(/\s/g, ""));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function bytesToBase64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function createWorkerJwtSigner(privateKey, subtle = crypto.subtle) {
  const keyBytes = pemBytes(privateKey);
  let importedKey;
  return async (unsigned) => {
    importedKey ??= subtle.importKey(
      "pkcs8",
      keyBytes,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const signature = await subtle.sign(
      "RSASSA-PKCS1-v1_5",
      await importedKey,
      new TextEncoder().encode(unsigned),
    );
    return bytesToBase64url(new Uint8Array(signature));
  };
}

async function workerSecretMatches(actual, expected, subtle = crypto.subtle) {
  const encoder = new TextEncoder();
  const [actualDigest, expectedDigest] = await Promise.all([
    subtle.digest("SHA-256", encoder.encode(actual)),
    subtle.digest("SHA-256", encoder.encode(expected)),
  ]);
  const actualBytes = new Uint8Array(actualDigest);
  const expectedBytes = new Uint8Array(expectedDigest);
  let difference = actualBytes.length ^ expectedBytes.length;
  for (let index = 0; index < actualBytes.length; index += 1) {
    difference |= actualBytes[index] ^ expectedBytes[index];
  }
  return difference === 0;
}

function responseHeaders() {
  return {
    "Cache-Control": "no-store",
    "Content-Type": "application/json",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
  };
}

function workerResponse({ status, body }) {
  if (status === 204) return new Response(null, { status, headers: { "Cache-Control": "no-store" } });
  return Response.json(body, { status, headers: responseHeaders() });
}

function configurationUnavailable() {
  return workerResponse({ status: 503, body: { error: "configuration_unavailable" } });
}

function defaultGithub({ appId, privateKey, fetchImpl }) {
  return createGithubClient({
    appId,
    signJwt: createWorkerJwtSigner(privateKey),
    fetchImpl,
  });
}

export function createWorkerEntrypoint({ createGithub = defaultGithub, fetchImpl = fetch } = {}) {
  return Object.freeze({
    async fetch(request, env) {
      let policy;
      let credentials;
      let github;
      try {
        policy = parsePolicy(requiredBinding(env, "BROKER_POLICY_JSON"));
        const appId = requiredBinding(env, "GITHUB_APP_ID");
        if (String(policy.github_app.id) !== appId) fail("configured GitHub App id differs from policy");
        credentials = workerCredentials(policy, env);
        github = createGithub({
          appId,
          privateKey: requiredBinding(env, "GITHUB_APP_PRIVATE_KEY"),
          fetchImpl,
        });
        if (!github || typeof github.verifyPolicy !== "function" || typeof github.mintToken !== "function") {
          fail("GitHub client is invalid");
        }
      } catch {
        return configurationUnavailable();
      }

      const verifiedGithub = Object.freeze({
        async mintToken(activePolicy, repositoryId) {
          await github.verifyPolicy(activePolicy);
          return github.mintToken(activePolicy, repositoryId);
        },
      });
      const handle = createBrokerHandler({
        policy,
        credentials,
        github: verifiedGithub,
        secretMatches: workerSecretMatches,
      });
      const url = new URL(request.url);
      const isTokenRequest = request.method === "POST" && url.pathname === "/v1/token" && !url.search;
      let bodyText = "";
      try {
        if (isTokenRequest) bodyText = await request.text();
      } catch {
        return workerResponse({ status: 502, body: { error: "token_unavailable" } });
      }
      return workerResponse(await handle({
        method: request.method,
        path: `${url.pathname}${url.search}`,
        contentType: request.headers.get("content-type") ?? "",
        workspaceId: request.headers.get("x-lazurio-workspace-id") ?? undefined,
        authorization: request.headers.get("authorization") ?? "",
        bodyText,
      }));
    },
  });
}

export default createWorkerEntrypoint();
