// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { RepositoryDeniedError, TeamGrantError } from "../src/core.mjs";
import {
  createWorkerEntrypoint,
  createWorkerJwtSigner,
  workspaceCredentialBindingName,
} from "../src/worker.mjs";

const ALPHA_CREDENTIAL = "alpha-secret-value-with-at-least-32-bytes";
const BETA_CREDENTIAL = "beta-secret-value-with-at-least-32-bytes";

function policyFixture() {
  return {
    schema_version: "lazurio.github_app_broker.policy.v3",
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
    workspaces: [
      {
        id: "alpha-team",
        github_team_id: 4001,
        credential_file: "/run/secrets/workspace-alpha",
      },
      {
        id: "beta-team",
        github_team_id: 4002,
        credential_file: "/run/secrets/workspace-beta",
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

const grantedAlpha = async (_policy, _workspace, target) => {
  if (target.repository_id !== undefined && target.repository_id !== 3001) {
    throw new TeamGrantError("no grant");
  }
  if (target.repository !== undefined && target.repository.toLowerCase() !== "example-org/alpha") {
    throw new TeamGrantError("no grant");
  }
  return { repository_id: 3001, full_name: "example-org/alpha", role: "write", access: "write" };
};

const provenTeam = async (_policy, workspace) => ({ id: workspace.github_team_id, slug: workspace.id });

function workerFixture({ teamGrant = grantedAlpha, workspaceTeam = provenTeam } = {}) {
  const calls = { verify: 0, teamGrant: 0, workspaceTeam: 0, mint: 0, order: [], tiers: [] };
  const worker = createWorkerEntrypoint({
    createGithub: () => ({
      async verifyPolicy() {
        calls.verify += 1;
        calls.order.push("installation");
      },
      async verifyTeamGrant(policy, workspace, target) {
        calls.teamGrant += 1;
        calls.order.push("team");
        return teamGrant(policy, workspace, target);
      },
      async verifyWorkspaceTeam(policy, workspace) {
        calls.workspaceTeam += 1;
        calls.order.push("workspace-team");
        return workspaceTeam(policy, workspace);
      },
      async mintToken(_policy, repositoryId, access) {
        calls.mint += 1;
        calls.order.push("mint");
        calls.tiers.push(access);
        return {
          token: `ghs_synthetic_${repositoryId}`,
          expires_at: "2030-01-01T00:00:00Z",
          repository_id: repositoryId,
          access,
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
  body = { repository: "example-org/alpha" },
} = {}) {
  return new Request(`${origin}/v1/token`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${credential}`,
      "Content-Type": "application/json",
      "X-Lazurio-Workspace-ID": workspace,
    },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

function countsOf(calls) {
  return { verify: calls.verify, teamGrant: calls.teamGrant, mint: calls.mint };
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
  assert.deepEqual(countsOf(calls), { verify: 0, teamGrant: 0, mint: 0 });
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
  assert.deepEqual(countsOf(calls), { verify: 0, teamGrant: 0, mint: 0 });
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

test("Worker health imports the PKCS#8 key and rejects invalid DER or a non-RSA key", async () => {
  const worker = createWorkerEntrypoint();
  const ecPrivateKey = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({
    type: "pkcs8",
    format: "pem",
  });
  for (const privateKey of [
    "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
    ecPrivateKey,
  ]) {
    const response = await worker.fetch(
      new Request("https://broker.example.test/health"),
      environment({ GITHUB_APP_PRIVATE_KEY: privateKey }),
    );
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: "configuration_unavailable" });
  }

  const rsaPrivateKey = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({
    type: "pkcs8",
    format: "pem",
  });
  const healthy = await worker.fetch(
    new Request("https://broker.example.test/health"),
    environment({ GITHUB_APP_PRIVATE_KEY: rsaPrivateKey }),
  );
  assert.equal(healthy.status, 204);
});

test("Worker rejects request metadata without consuming the body stream", async () => {
  const { worker, calls } = workerFixture();
  for (const { contentType, credential, expectedStatus, expectedError } of [
    {
      contentType: "text/plain",
      credential: ALPHA_CREDENTIAL,
      expectedStatus: 415,
      expectedError: "unsupported_media_type",
    },
    {
      contentType: "application/json",
      credential: "wrong-secret-with-at-least-thirty-two-bytes",
      expectedStatus: 401,
      expectedError: "workspace_unauthorized",
    },
  ]) {
    let reads = 0;
    const body = new ReadableStream({
      pull() {
        reads += 1;
        throw new Error("body must not be read");
      },
    }, { highWaterMark: 0 });
    const request = new Request("https://broker.example.test/v1/token", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${credential}`,
        "Content-Type": contentType,
        "X-Lazurio-Workspace-ID": "alpha-team",
      },
      body,
      duplex: "half",
    });
    const response = await worker.fetch(request, environment());
    assert.equal(response.status, expectedStatus);
    assert.deepEqual(await response.json(), { error: expectedError });
    assert.equal(reads, 0);
  }
  assert.deepEqual(countsOf(calls), { verify: 0, teamGrant: 0, mint: 0 });
});

test("Worker denies invalid credentials, invalid bodies and foreign owners before live GitHub verification", async () => {
  const { worker, calls } = workerFixture();
  const unauthorized = await worker.fetch(tokenRequest({ credential: "wrong-secret-with-at-least-thirty-two-bytes" }), environment());
  assert.equal(unauthorized.status, 401);
  assert.deepEqual(await unauthorized.json(), { error: "workspace_unauthorized" });

  for (const repository of ["other-org/alpha", "OTHER-ORG/beta"]) {
    const denied = await worker.fetch(tokenRequest({ body: { repository } }), environment());
    assert.equal(denied.status, 403);
    assert.deepEqual(await denied.json(), { error: "repository_denied" });
  }

  for (const body of [
    "{",
    {},
    { repository: "example-org/alpha", repository_id: 3001 },
    { repository_id: "3001" },
    { repository: "example-org/.." },
  ]) {
    const invalid = await worker.fetch(tokenRequest({ body }), environment());
    assert.equal(invalid.status, 400, JSON.stringify(body));
    assert.deepEqual(await invalid.json(), { error: "invalid_request" });
  }
  assert.deepEqual(countsOf(calls), { verify: 0, teamGrant: 0, mint: 0 });
});

test("Worker verifies the live installation, then the Team grant, before every fresh token in both forms", async () => {
  const { worker, calls } = workerFixture();
  for (const body of [{ repository: "example-org/alpha" }, { repository_id: 3001 }]) {
    const response = await worker.fetch(tokenRequest({ body }), environment());
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.deepEqual(await response.json(), {
      token: "ghs_synthetic_3001",
      expires_at: "2030-01-01T00:00:00Z",
      repository_id: 3001,
      repository: "example-org/alpha",
      access: "write",
    });
  }
  assert.deepEqual(countsOf(calls), { verify: 2, teamGrant: 2, mint: 2 });
  assert.deepEqual(calls.order, ["installation", "team", "mint", "installation", "team", "mint"]);
  assert.deepEqual(calls.tiers, ["write", "write"]);
});

test("Worker passes the read tier of a pull or triage grant to the mint and reports it", async () => {
  const { worker, calls } = workerFixture({
    teamGrant: async (policy, workspace, target) => ({
      ...(await grantedAlpha(policy, workspace, target)),
      role: "triage",
      access: "read",
    }),
  });
  const response = await worker.fetch(tokenRequest(), environment());
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    token: "ghs_synthetic_3001",
    expires_at: "2030-01-01T00:00:00Z",
    repository_id: 3001,
    repository: "example-org/alpha",
    access: "read",
  });
  assert.deepEqual(calls.order, ["installation", "team", "mint"]);
  assert.deepEqual(calls.tiers, ["read"]);
});

test("Worker refuses cross-repository and foreign-owner ids from the Team gate and mints nothing", async () => {
  const { worker, calls } = workerFixture({
    teamGrant: async (policy, workspace, target) => {
      if (target.repository_id === 9001) throw new RepositoryDeniedError("another owner");
      return grantedAlpha(policy, workspace, target);
    },
  });
  const crossRepository = await worker.fetch(tokenRequest({ body: { repository: "example-org/beta" } }), environment());
  assert.equal(crossRepository.status, 403);
  assert.deepEqual(await crossRepository.json(), { error: "team_grant_missing" });

  const foreignId = await worker.fetch(tokenRequest({ body: { repository_id: 9001 } }), environment());
  assert.equal(foreignId.status, 403);
  assert.deepEqual(await foreignId.json(), { error: "repository_denied" });
  assert.deepEqual(countsOf(calls), { verify: 2, teamGrant: 2, mint: 0 });
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
    body: JSON.stringify({ repository: "example-org/alpha" }),
  }), environment());
  assert.equal(query.status, 404);

  const oversized = new Request("https://broker.example.test/v1/token", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${ALPHA_CREDENTIAL}`,
      "Content-Type": "application/json",
      "X-Lazurio-Workspace-ID": "alpha-team",
    },
    body: JSON.stringify({ repository: "example-org/alpha", padding: "x".repeat(1024) }),
  });
  const response = await worker.fetch(oversized, environment());
  assert.equal(response.status, 502);
  assert.deepEqual(await response.json(), { error: "token_unavailable" });
  assert.deepEqual(countsOf(calls), { verify: 0, teamGrant: 0, mint: 0 });
});

test("Worker PKCS#8 signer produces a valid RS256 signature", async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pem = privateKey.export({ type: "pkcs8", format: "pem" });
  const signer = await createWorkerJwtSigner(pem, crypto.webcrypto.subtle);
  const unsigned = "header.payload";
  const signature = await signer(unsigned);
  assert.equal(
    crypto.verify("RSA-SHA256", Buffer.from(unsigned), publicKey, Buffer.from(signature, "base64url")),
    true,
  );
});

test("Worker refuses with team_grant_missing after live verification and mints nothing", async () => {
  let attempts = 0;
  const { worker, calls } = workerFixture({
    teamGrant: async (policy, workspace, target) => {
      attempts += 1;
      if (attempts > 1) throw new TeamGrantError("grant revoked between mints");
      return grantedAlpha(policy, workspace, target);
    },
  });
  const granted = await worker.fetch(tokenRequest(), environment());
  assert.equal(granted.status, 200);

  const refused = await worker.fetch(tokenRequest(), environment());
  assert.equal(refused.status, 403);
  assert.equal(refused.headers.get("cache-control"), "no-store");
  assert.deepEqual(await refused.json(), { error: "team_grant_missing" });
  assert.deepEqual(countsOf(calls), { verify: 2, teamGrant: 2, mint: 1 });
});

test("Worker treats a GitHub client without Team or Workspace verification as unavailable configuration", async () => {
  const worker = createWorkerEntrypoint({
    createGithub: () => ({ verifyPolicy: async () => {}, mintToken: async () => ({}) }),
  });
  const response = await worker.fetch(tokenRequest(), environment());
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: "configuration_unavailable" });

  const withoutWorkspaceProof = createWorkerEntrypoint({
    createGithub: () => ({ verifyPolicy: async () => {}, verifyTeamGrant: async () => ({}), mintToken: async () => ({}) }),
  });
  const missingProof = await withoutWorkspaceProof.fetch(workspaceRequest(), environment());
  assert.equal(missingProof.status, 503);
  assert.deepEqual(await missingProof.json(), { error: "configuration_unavailable" });
});

function workspaceRequest({ workspace = "alpha-team", credential = ALPHA_CREDENTIAL } = {}) {
  return new Request("https://broker.example.test/v1/workspace", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${credential}`,
      "Content-Type": "application/json",
      "X-Lazurio-Workspace-ID": workspace,
    },
    body: "{}",
  });
}

test("Worker /v1/workspace verifies the installation, then the Team, and mints nothing", async () => {
  const { worker, calls } = workerFixture();
  const response = await worker.fetch(workspaceRequest(), environment());
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual(await response.json(), {
    workspace_id: "alpha-team",
    organization: "example-org",
    github_team_id: 4001,
    github_team_slug: "alpha-team",
  });
  assert.deepEqual(calls.order, ["installation", "workspace-team"]);
  assert.equal(calls.mint, 0);
  assert.equal(calls.teamGrant, 0);
});

test("Worker /v1/workspace refuses bad credentials without GitHub, drift with 403 and outages with 502", async () => {
  const unauthorized = workerFixture();
  const denied = await unauthorized.worker.fetch(
    workspaceRequest({ credential: "wrong-secret-with-at-least-thirty-two-bytes" }),
    environment(),
  );
  assert.equal(denied.status, 401);
  assert.deepEqual(await denied.json(), { error: "workspace_unauthorized" });
  assert.deepEqual(unauthorized.calls.order, []);

  const drifted = workerFixture({
    workspaceTeam: async () => {
      throw new TeamGrantError("Team gone");
    },
  });
  const refused = await drifted.worker.fetch(workspaceRequest(), environment());
  assert.equal(refused.status, 403);
  assert.deepEqual(await refused.json(), { error: "team_grant_missing" });
  assert.equal(drifted.calls.mint, 0);

  const outage = workerFixture({
    workspaceTeam: async () => {
      throw new Error("GitHub request failed with HTTP 503");
    },
  });
  const unavailable = await outage.worker.fetch(workspaceRequest(), environment());
  assert.equal(unavailable.status, 502);
  assert.deepEqual(await unavailable.json(), { error: "token_unavailable" });
  assert.equal(outage.calls.mint, 0);

  const wrongTeam = workerFixture({ workspaceTeam: async () => ({ id: 4999, slug: "other" }) });
  const mismatch = await wrongTeam.worker.fetch(workspaceRequest(), environment());
  assert.equal(mismatch.status, 502);
});
