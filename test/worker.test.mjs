// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  createWorkerEntrypoint,
  createWorkerJwtSigner,
  workspaceCredentialBindingName,
} from "../src/worker.mjs";

const ALPHA_CREDENTIAL = "alpha-secret-value-with-at-least-32-bytes";
const BETA_CREDENTIAL = "beta-secret-value-with-at-least-32-bytes";

function policyFixture() {
  return {
    schema_version: "lazurio.github_app_broker.policy.v1",
    github_app: { id: 42, slug: "example-app" },
    github_owner: { id: 1001, login: "example-org" },
    installation_id: 2001,
    installation_repository_selection: "selected",
    installation_permissions: {
      actions: "write",
      checks: "read",
      contents: "write",
      members: "read",
      metadata: "read",
      pull_requests: "write",
    },
    repositories: [
      { id: 3001, full_name: "example-org/alpha" },
      { id: 3002, full_name: "example-org/beta" },
    ],
    workspaces: [
      {
        id: "alpha-team",
        credential_file: "/run/secrets/workspace-alpha",
        repository_ids: [3001],
      },
      {
        id: "beta-team",
        credential_file: "/run/secrets/workspace-beta",
        repository_ids: [3002],
      },
    ],
  };
}

function environment(overrides = {}) {
  return {
    BROKER_POLICY_JSON: JSON.stringify(policyFixture()),
    GITHUB_APP_ID: "42",
    GITHUB_APP_PRIVATE_KEY: "synthetic-test-key",
    WORKSPACE_CREDENTIAL_ALPHA_TEAM: ALPHA_CREDENTIAL,
    WORKSPACE_CREDENTIAL_BETA_TEAM: BETA_CREDENTIAL,
    ...overrides,
  };
}

function workerFixture() {
  const calls = { verify: 0, mint: 0 };
  const worker = createWorkerEntrypoint({
    createGithub: () => ({
      async verifyPolicy() {
        calls.verify += 1;
      },
      async mintToken(_policy, repositoryId) {
        calls.mint += 1;
        return {
          token: `ghs_synthetic_${repositoryId}`,
          expires_at: "2030-01-01T00:00:00Z",
          repository_id: repositoryId,
        };
      },
    }),
  });
  return { worker, calls };
}

function tokenRequest({
  origin = "https://broker.example.test",
  workspace = "alpha-team",
  credential = ALPHA_CREDENTIAL,
  repositoryId = 3001,
} = {}) {
  return new Request(`${origin}/v1/token`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${credential}`,
      "Content-Type": "application/json",
      "X-Lazurio-Workspace-ID": workspace,
    },
    body: JSON.stringify({ repository_id: repositoryId }),
  });
}

test("maps immutable Workspace ids to independent Worker secret bindings", () => {
  assert.equal(workspaceCredentialBindingName("blue-team"), "WORKSPACE_CREDENTIAL_BLUE_TEAM");
  assert.throws(() => workspaceCredentialBindingName("Blue_Team"), /cannot be mapped/);
});

test("Worker health validates deployment bindings without calling GitHub", async () => {
  const { worker, calls } = workerFixture();
  const response = await worker.fetch(new Request("https://broker.example.test/health"), environment());
  assert.equal(response.status, 204);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual(calls, { verify: 0, mint: 0 });
});

test("Worker fails closed when policy, key or unique Workspace secrets are unavailable", async () => {
  const { worker, calls } = workerFixture();
  for (const env of [
    environment({ BROKER_POLICY_JSON: "" }),
    environment({ GITHUB_APP_PRIVATE_KEY: "" }),
    environment({ WORKSPACE_CREDENTIAL_BETA_TEAM: ALPHA_CREDENTIAL }),
  ]) {
    const response = await worker.fetch(new Request("https://broker.example.test/health"), env);
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: "configuration_unavailable" });
  }
  assert.deepEqual(calls, { verify: 0, mint: 0 });
});

test("default Worker runtime rejects a non-PKCS#8 App key before reporting healthy", async () => {
  const worker = createWorkerEntrypoint();
  const response = await worker.fetch(
    new Request("https://broker.example.test/health"),
    environment(),
  );
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: "configuration_unavailable" });
});

test("Worker denies invalid credentials and repositories before live GitHub verification", async () => {
  const { worker, calls } = workerFixture();
  const unauthorized = await worker.fetch(tokenRequest({ credential: "wrong-secret-with-at-least-thirty-two-bytes" }), environment());
  assert.equal(unauthorized.status, 401);
  assert.deepEqual(await unauthorized.json(), { error: "workspace_unauthorized" });

  const denied = await worker.fetch(tokenRequest({ repositoryId: 3002 }), environment());
  assert.equal(denied.status, 403);
  assert.deepEqual(await denied.json(), { error: "repository_denied" });
  assert.deepEqual(calls, { verify: 0, mint: 0 });
});

test("Worker verifies live policy before every fresh one-repository token", async () => {
  const { worker, calls } = workerFixture();
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const response = await worker.fetch(tokenRequest(), environment());
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.deepEqual(await response.json(), {
      token: "ghs_synthetic_3001",
      expires_at: "2030-01-01T00:00:00Z",
      repository_id: 3001,
    });
  }
  assert.deepEqual(calls, { verify: 2, mint: 2 });
});

test("Worker rejects query substitution and oversized token bodies", async () => {
  const { worker, calls } = workerFixture();
  const query = await worker.fetch(new Request("https://broker.example.test/v1/token?redirect=elsewhere", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${ALPHA_CREDENTIAL}`,
      "Content-Type": "application/json",
      "X-Lazurio-Workspace-ID": "alpha-team",
    },
    body: JSON.stringify({ repository_id: 3001 }),
  }), environment());
  assert.equal(query.status, 404);

  const oversized = new Request("https://broker.example.test/v1/token", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${ALPHA_CREDENTIAL}`,
      "Content-Type": "application/json",
      "X-Lazurio-Workspace-ID": "alpha-team",
    },
    body: JSON.stringify({ repository_id: 3001, padding: "x".repeat(1024) }),
  });
  const response = await worker.fetch(oversized, environment());
  assert.equal(response.status, 502);
  assert.deepEqual(await response.json(), { error: "token_unavailable" });
  assert.deepEqual(calls, { verify: 0, mint: 0 });
});

test("Worker PKCS#8 signer produces a valid RS256 signature", async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pem = privateKey.export({ type: "pkcs8", format: "pem" });
  const signer = createWorkerJwtSigner(pem, crypto.webcrypto.subtle);
  const unsigned = "header.payload";
  const signature = await signer(unsigned);
  assert.equal(
    crypto.verify("RSA-SHA256", Buffer.from(unsigned), publicKey, Buffer.from(signature, "base64url")),
    true,
  );
});
