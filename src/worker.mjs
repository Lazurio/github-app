// SPDX-License-Identifier: Apache-2.0
import {
  MAX_BODY_BYTES,
  admitRunGrant,
  createBrokerHandler,
  createGithubClient,
  parsePolicy,
} from "./core.mjs";
import { createGithubActionsKeySet, createOidcVerifier } from "./oidc.mjs";

/**
 * The Durable Object binding that holds the per-run OIDC replay and grant record. Not exported:
 * workerd treats every named export of the entry module as an entrypoint and refuses to start a
 * Worker that exports a plain value.
 */
const OIDC_RUN_GUARD_BINDING = "OIDC_RUN_GUARD";

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

export async function createWorkerJwtSigner(privateKey, subtle = crypto.subtle) {
  const keyBytes = pemBytes(privateKey);
  const importedKey = await subtle.importKey(
    "pkcs8",
    keyBytes,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return async (unsigned) => {
    const signature = await subtle.sign(
      "RSASSA-PKCS1-v1_5",
      importedKey,
      new TextEncoder().encode(unsigned),
    );
    return bytesToBase64url(new Uint8Array(signature));
  };
}

async function readWorkerBody(request) {
  const declaredLength = request.headers.get("content-length");
  if (/^\d+$/.test(declaredLength ?? "") && Number(declaredLength) > MAX_BODY_BYTES) {
    fail("request body is too large");
  }
  if (!request.body) return "";

  const reader = request.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let body = "";
  let byteLength = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      byteLength += value.byteLength;
      if (byteLength > MAX_BODY_BYTES) {
        await reader.cancel("request body is too large");
        fail("request body is too large");
      }
      body += decoder.decode(value, { stream: true });
    }
    return body + decoder.decode();
  } finally {
    reader.releaseLock();
  }
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

async function defaultGithub({ appId, privateKey, fetchImpl }) {
  return createGithubClient({
    appId,
    signJwt: await createWorkerJwtSigner(privateKey),
    fetchImpl,
  });
}

/**
 * One Durable Object per workflow run attempt (named `<repository_id>/<run_id>/<run_attempt>` from
 * verified claims) holds that run's used OIDC token ids and grant counts per purpose. It only ever
 * refuses: a repeated token id or a purpose over its per-run budget. Its storage deletes itself
 * after the retention period.
 */
export class OidcRunGuard {
  constructor(state) {
    this.storage = state.storage;
  }

  async fetch(request) {
    let input;
    try {
      input = await request.json();
    } catch {
      return Response.json({ error: "invalid_request" }, { status: 400 });
    }
    try {
      return Response.json({ decision: await admitRunGrant(this.storage, input, Date.now()) });
    } catch {
      return Response.json({ error: "invalid_request" }, { status: 400 });
    }
  }

  async alarm() {
    await this.storage.deleteAll();
  }
}

function durableObjectRunGuard(namespace) {
  if (typeof namespace?.idFromName !== "function" || typeof namespace?.get !== "function") {
    fail(`${OIDC_RUN_GUARD_BINDING} Durable Object binding is missing`);
  }
  return Object.freeze({
    async admit({ key, ...grant }) {
      const stub = namespace.get(namespace.idFromName(key));
      const response = await stub.fetch("https://oidc-run-guard.invalid/admit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(grant),
      });
      if (!response.ok) fail("OIDC run guard refused the request shape");
      return (await response.json())?.decision;
    },
  });
}

let isolateKeySet;
/** GitHub's key set, cached per Worker isolate by jose (at most ten minutes, see oidc.mjs). */
function defaultOidcKeySet() {
  isolateKeySet ??= createGithubActionsKeySet();
  return isolateKeySet;
}

/** One JSON line per OIDC decision on the Worker's log stream; it never contains a token. */
function defaultAudit(record) {
  console.log(JSON.stringify(record));
}

export function createWorkerEntrypoint({
  createGithub = defaultGithub,
  fetchImpl = fetch,
  oidcKeySet = defaultOidcKeySet,
  audit = defaultAudit,
  now = () => Date.now(),
} = {}) {
  return Object.freeze({
    async fetch(request, env) {
      let policy;
      let credentials;
      let github;
      let oidc;
      try {
        policy = parsePolicy(requiredBinding(env, "BROKER_POLICY_JSON"));
        const appId = requiredBinding(env, "GITHUB_APP_ID");
        if (String(policy.github_app.id) !== appId) fail("configured GitHub App id differs from policy");
        credentials = workerCredentials(policy, env);
        github = await createGithub({
          appId,
          privateKey: requiredBinding(env, "GITHUB_APP_PRIVATE_KEY"),
          fetchImpl,
        });
        if (
          !github ||
          typeof github.verifyPolicy !== "function" ||
          typeof github.verifyTeamGrant !== "function" ||
          typeof github.verifyWorkspaceTeam !== "function" ||
          typeof github.mintToken !== "function" ||
          (policy.oidc !== undefined && typeof github.mintPurposeToken !== "function")
        ) {
          fail("GitHub client is invalid");
        }
        // A policy with OIDC purposes is complete only together with its run guard binding.
        if (policy.oidc !== undefined) {
          oidc = Object.freeze({
            verify: createOidcVerifier({ audience: policy.oidc.audience, keySet: oidcKeySet(), now }),
            guard: durableObjectRunGuard(env?.[OIDC_RUN_GUARD_BINDING]),
            audit,
            now,
          });
        }
      } catch {
        return configurationUnavailable();
      }

      // No trustworthy startup phase: the exact live installation is verified before the
      // Team gate (or the Workspace Team proof, or an admitted OIDC purpose's mint) on every
      // authorized request, and it precedes the one-repository mint.
      const verifiedGithub = Object.freeze({
        async verifyTeamGrant(activePolicy, workspace, target) {
          await github.verifyPolicy(activePolicy);
          return github.verifyTeamGrant(activePolicy, workspace, target);
        },
        async verifyWorkspaceTeam(activePolicy, workspace) {
          await github.verifyPolicy(activePolicy);
          return github.verifyWorkspaceTeam(activePolicy, workspace);
        },
        mintToken(activePolicy, workspace, repositoryId, access) {
          return github.mintToken(activePolicy, workspace, repositoryId, access);
        },
        async mintPurposeToken(activePolicy, repositoryId, permissions) {
          await github.verifyPolicy(activePolicy);
          return github.mintPurposeToken(activePolicy, repositoryId, permissions);
        },
      });
      const handle = createBrokerHandler({
        policy,
        credentials,
        github: verifiedGithub,
        secretMatches: workerSecretMatches,
        oidc,
      });
      const url = new URL(request.url);
      return workerResponse(await handle({
        method: request.method,
        path: `${url.pathname}${url.search}`,
        contentType: request.headers.get("content-type") ?? "",
        workspaceId: request.headers.get("x-lazurio-workspace-id") ?? undefined,
        authorization: request.headers.get("authorization") ?? "",
        readBody: () => readWorkerBody(request),
      }));
    },
  });
}

export default createWorkerEntrypoint();
