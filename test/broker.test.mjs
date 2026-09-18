// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { once } from "node:events";
import http from "node:http";
import test from "node:test";

import {
  checkPolicyLive,
  createBrokerServer,
  createGithubClient,
  formatPolicyCheckTable,
  formatPolicySummary,
  parseCommand,
  parsePolicy,
  startBroker,
} from "../src/broker.mjs";

const secretByPath = new Map([
  ["/run/secrets/workspace-alpha", "alpha-secret-value-with-at-least-32-bytes"],
  ["/run/secrets/workspace-beta", "beta-secret-value-with-at-least-32-bytes"],
]);

function policyFixture() {
  return {
    schema_version: "lazurio.github_app_broker.policy.v2",
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
        github_team_id: 4001,
        github_team_slug: "alpha-team",
        credential_file: "/run/secrets/workspace-alpha",
        repository_ids: [3001],
      },
      {
        id: "beta-team",
        github_team_id: 4002,
        credential_file: "/run/secrets/workspace-beta",
        repository_ids: [3002],
      },
    ],
  };
}

const grantedTeam = async (_policy, workspace, repositoryId) => ({
  workspace_id: workspace.id,
  github_team_id: workspace.github_team_id,
  github_team_slug: workspace.github_team_slug ?? workspace.id,
  repository_id: repositoryId,
  role: "write",
});

async function withServer(run, mintToken = async (_policy, repositoryId) => ({
  token: `ghs_synthetic_${repositoryId}`,
  expires_at: "2030-01-01T00:00:00Z",
  repository_id: repositoryId,
}), verifyTeamGrant = grantedTeam) {
  const server = createBrokerServer({
    policy: parsePolicy(policyFixture()),
    github: { verifyTeamGrant, mintToken },
    readFile: (file) => secretByPath.get(file) ?? "",
    realpath: (file) => file,
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const address = server.address();
    await run(`http://127.0.0.1:${address.port}`);
  } finally {
    server.close();
    await once(server, "close");
  }
}

function request(origin, { workspace = "alpha-team", secret = secretByPath.get("/run/secrets/workspace-alpha"), repositoryId = 3001 } = {}) {
  return fetch(`${origin}/v1/token`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${secret}`,
      "Content-Type": "application/json",
      "X-Lazurio-Workspace-ID": workspace,
    },
    body: JSON.stringify({ repository_id: repositoryId }),
  });
}

function requestHeadersWithoutBody(origin, { contentType, secret }) {
  return new Promise((resolve, reject) => {
    const client = http.request(`${origin}/v1/token`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${secret}`,
        "Content-Length": "1048576",
        "Content-Type": contentType,
        "X-Lazurio-Workspace-ID": "alpha-team",
      },
    }, (response) => {
      response.setEncoding("utf8");
      let body = "";
      response.on("data", (chunk) => {
        body += chunk;
      });
      response.on("end", () => {
        client.destroy();
        resolve({ status: response.statusCode, body: JSON.parse(body) });
      });
    });
    client.on("error", reject);
    client.flushHeaders();
  });
}

test("mints a non-cacheable token only for the Workspace repository id", async () => {
  await withServer(async (origin) => {
    const response = await request(origin);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.deepEqual(await response.json(), {
      token: "ghs_synthetic_3001",
      expires_at: "2030-01-01T00:00:00Z",
      repository_id: 3001,
    });
  });
});

test("rejects an invalid Workspace credential without calling GitHub", async () => {
  let calls = 0;
  await withServer(
    async (origin) => {
      const response = await request(origin, { secret: "wrong-secret-value-with-at-least-32-bytes" });
      assert.equal(response.status, 401);
      assert.deepEqual(await response.json(), { error: "workspace_unauthorized" });
      assert.equal(calls, 0);
    },
    async () => {
      calls += 1;
      throw new Error("must not be called");
    },
  );
});

test("rejects media type and credentials before reading a token body", async () => {
  await withServer(async (origin) => {
    const unsupported = await requestHeadersWithoutBody(origin, {
      contentType: "text/plain",
      secret: secretByPath.get("/run/secrets/workspace-alpha"),
    });
    assert.deepEqual(unsupported, { status: 415, body: { error: "unsupported_media_type" } });

    const unauthorized = await requestHeadersWithoutBody(origin, {
      contentType: "application/json",
      secret: "wrong-secret-value-with-at-least-32-bytes",
    });
    assert.deepEqual(unauthorized, { status: 401, body: { error: "workspace_unauthorized" } });
  });
});

test("rejects cross-Workspace repository access before calling GitHub", async () => {
  let calls = 0;
  await withServer(
    async (origin) => {
      const response = await request(origin, { repositoryId: 3002 });
      assert.equal(response.status, 403);
      assert.deepEqual(await response.json(), { error: "repository_denied" });
      assert.equal(calls, 0);
    },
    async () => {
      calls += 1;
      throw new Error("must not be called");
    },
  );
});

test("does not cache installation tokens between requests", async () => {
  let calls = 0;
  await withServer(
    async (origin) => {
      assert.equal((await request(origin)).status, 200);
      assert.equal((await request(origin)).status, 200);
      assert.equal(calls, 2);
    },
    async (_policy, repositoryId) => {
      calls += 1;
      return {
        token: `ghs_synthetic_${repositoryId}_${calls}`,
        expires_at: "2030-01-01T00:00:00Z",
        repository_id: repositoryId,
      };
    },
  );
});

test("fails closed when GitHub stops issuing a repository token", async () => {
  await withServer(
    async (origin) => {
      const response = await request(origin);
      assert.equal(response.status, 502);
      assert.deepEqual(await response.json(), { error: "token_unavailable" });
    },
    async () => {
      throw new Error("repository was removed from the installation");
    },
  );
});

test("policy rejects mutable-name drift and ambiguous Workspace credentials", () => {
  const wrongOwner = policyFixture();
  wrongOwner.repositories[0].full_name = "other-org/alpha";
  assert.throws(() => parsePolicy(wrongOwner), /asserted owner/);

  const duplicateSecret = policyFixture();
  duplicateSecret.workspaces[1].credential_file = duplicateSecret.workspaces[0].credential_file;
  assert.throws(() => parsePolicy(duplicateSecret), /credential files must be unique/);

  const missingPullRequests = policyFixture();
  delete missingPullRequests.installation_permissions.pull_requests;
  assert.throws(() => parsePolicy(missingPullRequests), /pull_requests: write/);

  const missingActions = policyFixture();
  delete missingActions.installation_permissions.actions;
  assert.throws(() => parsePolicy(missingActions), /actions: write/);

  const missingChecks = policyFixture();
  delete missingChecks.installation_permissions.checks;
  assert.throws(() => parsePolicy(missingChecks), /checks: read/);

  const invalidSelection = policyFixture();
  invalidSelection.installation_repository_selection = "unexpected";
  assert.throws(
    () => parsePolicy(invalidSelection),
    /installation_repository_selection must be selected or all/,
  );
});

test("defaults legacy policy to selected and accepts explicit all selection", () => {
  const legacy = policyFixture();
  delete legacy.installation_repository_selection;
  assert.equal(parsePolicy(legacy).installation_repository_selection, "selected");

  const all = policyFixture();
  all.installation_repository_selection = "all";
  assert.equal(parsePolicy(all).installation_repository_selection, "all");
});

function jsonResponse(body, status = 200) {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: status === 204 ? undefined : { "Content-Type": "application/json" },
  });
}

function testPrivateKey() {
  return crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({
    type: "pkcs8",
    format: "pem",
  });
}

test("verifies the exact live installation and immutable repository set", async () => {
  const calls = [];
  const policy = parsePolicy(policyFixture());
  const fetchImpl = async (url, init) => {
    const path = new URL(url).pathname + new URL(url).search;
    calls.push({ path, method: init.method, body: init.body && JSON.parse(init.body) });
    if (path === "/app/installations/2001" && init.method === "GET") {
      return jsonResponse({
        app_id: 42,
        app_slug: "example-app",
        account: { id: 1001, login: "example-org" },
        target_type: "Organization",
        repository_selection: "selected",
        permissions: {
          actions: "write",
          checks: "read",
          contents: "write",
          members: "read",
          metadata: "read",
          pull_requests: "write",
        },
      });
    }
    if (path === "/app/installations/2001/access_tokens" && init.method === "POST") {
      assert.deepEqual(JSON.parse(init.body), { permissions: { contents: "read" } });
      return jsonResponse({ token: "ghs_repository_probe" });
    }
    if (path === "/installation/repositories?per_page=100&page=1" && init.method === "GET") {
      assert.equal(init.headers.Authorization, "Bearer ghs_repository_probe");
      return jsonResponse({
        total_count: 2,
        repositories: [
          { id: 3001, full_name: "example-org/alpha" },
          { id: 3002, full_name: "example-org/beta" },
        ],
      });
    }
    if (path === "/installation/token" && init.method === "DELETE") {
      return jsonResponse(null, 204);
    }
    throw new Error(`unexpected request ${init.method} ${path}`);
  };
  const github = createGithubClient({ appId: "42", privateKey: testPrivateKey(), fetchImpl });
  await github.verifyPolicy(policy);
  assert.equal(calls.at(-1).path, "/installation/token");
});

test("accepts an all-repository installation without authorizing unlisted repositories", async () => {
  const fixture = policyFixture();
  fixture.installation_repository_selection = "all";
  const policy = parsePolicy(fixture);
  const fetchImpl = async (url, init) => {
    const path = new URL(url).pathname + new URL(url).search;
    if (path === "/app/installations/2001" && init.method === "GET") {
      return jsonResponse({
        app_id: 42,
        app_slug: "example-app",
        account: { id: 1001, login: "example-org" },
        target_type: "Organization",
        repository_selection: "all",
        permissions: policy.installation_permissions,
      });
    }
    if (path === "/app/installations/2001/access_tokens" && init.method === "POST") {
      assert.deepEqual(JSON.parse(init.body), { permissions: { contents: "read" } });
      return jsonResponse({ token: "ghs_repository_probe" });
    }
    if (path === "/installation/repositories?per_page=100&page=1" && init.method === "GET") {
      return jsonResponse({
        total_count: 3,
        repositories: [
          { id: 3001, full_name: "example-org/alpha" },
          { id: 3002, full_name: "example-org/beta" },
          { id: 3999, full_name: "example-org/not-broker-authorized" },
        ],
      });
    }
    if (path === "/installation/token" && init.method === "DELETE") {
      return jsonResponse(null, 204);
    }
    throw new Error(`unexpected request ${init.method} ${path}`);
  };
  const github = createGithubClient({ appId: "42", privateKey: testPrivateKey(), fetchImpl });
  await github.verifyPolicy(policy);

  const server = createBrokerServer({
    policy,
    github: {
      verifyTeamGrant: grantedTeam,
      mintToken: async () => {
        throw new Error("must not mint an unlisted repository token");
      },
    },
    readFile: (file) => secretByPath.get(file) ?? "",
    realpath: (file) => file,
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const address = server.address();
    const response = await request(`http://127.0.0.1:${address.port}`, {
      repositoryId: 3999,
    });
    assert.equal(response.status, 403);
    assert.deepEqual(await response.json(), { error: "repository_denied" });
  } finally {
    server.close();
    await once(server, "close");
  }
});

test("rejects selection drift and repository-set drift in either installation mode", async () => {
  const privateKey = testPrivateKey();
  const installation = (selection) => ({
    app_id: 42,
    app_slug: "example-app",
    account: { id: 1001, login: "example-org" },
    target_type: "Organization",
    repository_selection: selection,
    permissions: parsePolicy(policyFixture()).installation_permissions,
  });

  const allFixture = policyFixture();
  allFixture.installation_repository_selection = "all";
  const allPolicy = parsePolicy(allFixture);
  const selectionDrift = createGithubClient({
    appId: "42",
    privateKey,
    fetchImpl: async () => jsonResponse(installation("selected")),
  });
  await assert.rejects(
    () => selectionDrift.verifyPolicy(allPolicy),
    /identity, selection or permissions differ from policy/,
  );

  async function verifyRepositorySet(policy, repositories) {
    const fetchImpl = async (url, init) => {
      const path = new URL(url).pathname + new URL(url).search;
      if (path === "/app/installations/2001") {
        return jsonResponse(installation(policy.installation_repository_selection));
      }
      if (path === "/app/installations/2001/access_tokens") {
        return jsonResponse({ token: "ghs_repository_probe" });
      }
      if (path === "/installation/repositories?per_page=100&page=1") {
        return jsonResponse({ total_count: repositories.length, repositories });
      }
      if (path === "/installation/token" && init.method === "DELETE") {
        return jsonResponse(null, 204);
      }
      throw new Error(`unexpected request ${init.method} ${path}`);
    };
    const github = createGithubClient({ appId: "42", privateKey, fetchImpl });
    return github.verifyPolicy(policy);
  }

  await assert.rejects(
    () =>
      verifyRepositorySet(parsePolicy(policyFixture()), [
        { id: 3001, full_name: "example-org/alpha" },
        { id: 3002, full_name: "example-org/beta" },
        { id: 3999, full_name: "example-org/extra" },
      ]),
    /repository grants differ from policy/,
  );
  await assert.rejects(
    () =>
      verifyRepositorySet(allPolicy, [
        { id: 3001, full_name: "example-org/alpha" },
        { id: 3999, full_name: "example-org/extra" },
      ]),
    /repository grants differ from policy/,
  );
});

test("rejects live permission expansion even when required contents access remains", async () => {
  const policy = parsePolicy(policyFixture());
  const fetchImpl = async () =>
    jsonResponse({
      account: { id: 1001, login: "example-org" },
      app_id: 42,
      app_slug: "example-app",
      target_type: "Organization",
      repository_selection: "selected",
      permissions: {
        administration: "write",
        actions: "write",
        checks: "read",
        contents: "write",
        members: "read",
        metadata: "read",
        pull_requests: "write",
      },
    });
  const github = createGithubClient({ appId: "42", privateKey: testPrivateKey(), fetchImpl });
  await assert.rejects(() => github.verifyPolicy(policy), /permissions differ from policy/);
});

test("rejects a different configured or live GitHub App identity", async () => {
  const policy = parsePolicy(policyFixture());
  const privateKey = testPrivateKey();
  const wrongConfiguredApp = createGithubClient({
    appId: "43",
    privateKey,
    fetchImpl: async () => {
      throw new Error("must not call GitHub for a mismatched configured App");
    },
  });
  await assert.rejects(
    () => wrongConfiguredApp.verifyPolicy(policy),
    /configured GitHub App id differs/,
  );

  const wrongLiveApp = createGithubClient({
    appId: "42",
    privateKey,
    fetchImpl: async () =>
      jsonResponse({
        app_id: 42,
        app_slug: "other-app",
        account: { id: 1001, login: "example-org" },
        target_type: "Organization",
        repository_selection: "selected",
        permissions: {
          actions: "write",
          checks: "read",
          contents: "write",
          members: "read",
          metadata: "read",
          pull_requests: "write",
        },
      }),
  });
  await assert.rejects(() => wrongLiveApp.verifyPolicy(policy), /identity, selection or permissions/);
});

test("mints through repository_ids and rejects under- or over-scoped responses", async () => {
  const policy = parsePolicy(policyFixture());
  const now = 1_700_000_000_000;
  let responsePermissions = {
    actions: "write",
    checks: "read",
    contents: "write",
    metadata: "read",
    pull_requests: "write",
  };
  const fetchImpl = async (_url, init) => {
    assert.deepEqual(JSON.parse(init.body), {
      repository_ids: [3001],
      permissions: {
        actions: "write",
        checks: "read",
        contents: "write",
        pull_requests: "write",
      },
    });
    return jsonResponse({
      token: "ghs_scoped_synthetic_token",
      expires_at: new Date(now + 60 * 60 * 1000).toISOString(),
      repositories: [{ id: 3001 }],
      permissions: responsePermissions,
    });
  };
  const github = createGithubClient({
    appId: "42",
    privateKey: testPrivateKey(),
    fetchImpl,
    now: () => now,
  });
  assert.deepEqual(await github.mintToken(policy, 3001), {
    token: "ghs_scoped_synthetic_token",
    expires_at: new Date(now + 60 * 60 * 1000).toISOString(),
    repository_id: 3001,
  });

  responsePermissions = {
    checks: "read",
    contents: "write",
    metadata: "read",
    pull_requests: "write",
  };
  await assert.rejects(
    () => github.mintToken(policy, 3001),
    /outside the requested repository or permission scope/,
  );

  responsePermissions = {
    actions: "write",
    contents: "write",
    metadata: "read",
    pull_requests: "write",
  };
  await assert.rejects(
    () => github.mintToken(policy, 3001),
    /outside the requested repository or permission scope/,
  );

  responsePermissions = {
    actions: "write",
    checks: "read",
    contents: "write",
    metadata: "read",
  };
  await assert.rejects(
    () => github.mintToken(policy, 3001),
    /outside the requested repository or permission scope/,
  );

  responsePermissions = {
    administration: "write",
    actions: "write",
    checks: "read",
    contents: "write",
    metadata: "read",
    pull_requests: "write",
  };
  await assert.rejects(
    () => github.mintToken(policy, 3001),
    /outside the requested repository or permission scope/,
  );
});

test("rejects duplicated Workspace credential values and aliased paths before listening", async () => {
  const policy = parsePolicy(policyFixture());
  const github = { verifyPolicy: async () => {} };
  await assert.rejects(
    () =>
      startBroker({
        policy,
        github,
        readFile: () => "same-secret-value-with-at-least-32-bytes",
        realpath: (file) => file,
        port: 0,
        host: "127.0.0.1",
      }),
    /credential values must be unique/,
  );
  await assert.rejects(
    () =>
      startBroker({
        policy,
        github,
        readFile: (file) => secretByPath.get(file) ?? "",
        realpath: () => "/run/secrets/same-file",
        port: 0,
        host: "127.0.0.1",
      }),
    /resolve to unique/,
  );
});

test("policy rejects a non-canonical secret path", () => {
  const policy = policyFixture();
  policy.workspaces[0].credential_file = "/run/secrets//workspace-alpha";
  assert.throws(() => parsePolicy(policy), /canonical file/);
});

test("accepts only the server, one-shot verification and policy check commands", () => {
  assert.deepEqual(parseCommand([]), { mode: "serve" });
  assert.deepEqual(parseCommand(["--verify-only"]), { mode: "verify" });
  assert.deepEqual(parseCommand(["policy", "check"]), { mode: "policy-check", live: false });
  assert.deepEqual(parseCommand(["policy", "check", "--live"]), { mode: "policy-check", live: true });
  assert.throws(() => parseCommand(["--unknown"]), /usage/);
  assert.throws(() => parseCommand(["--verify-only", "extra"]), /usage/);
  assert.throws(() => parseCommand(["policy", "check", "--offline"]), /usage/);
  assert.throws(() => parseCommand(["policy"]), /usage/);
});

test("keeps one verified credential snapshot for the complete server lifetime", async () => {
  const reads = new Map();
  const server = createBrokerServer({
    policy: parsePolicy(policyFixture()),
    github: {
      verifyTeamGrant: grantedTeam,
      mintToken: async (_policy, repositoryId) => ({
        token: `ghs_synthetic_${repositoryId}`,
        expires_at: "2030-01-01T00:00:00Z",
        repository_id: repositoryId,
      }),
    },
    readFile: (file) => {
      const count = (reads.get(file) ?? 0) + 1;
      reads.set(file, count);
      if (count > 1) return secretByPath.get("/run/secrets/workspace-beta");
      return secretByPath.get(file) ?? "";
    },
    realpath: (file) => file,
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const address = server.address();
    assert.equal((await request(`http://127.0.0.1:${address.port}`)).status, 200);
    assert.equal((await request(`http://127.0.0.1:${address.port}`)).status, 200);
    assert.equal(reads.get("/run/secrets/workspace-alpha"), 1);
    assert.equal(reads.get("/run/secrets/workspace-beta"), 1);
  } finally {
    server.close();
    await once(server, "close");
  }
});

test("verifies live policy exactly once before serving runtime requests", async () => {
  let verifies = 0;
  const server = await startBroker({
    policy: parsePolicy(policyFixture()),
    github: {
      verifyPolicy: async () => {
        verifies += 1;
      },
      verifyTeamGrant: grantedTeam,
      mintToken: async (_policy, repositoryId) => ({
        token: `ghs_synthetic_${repositoryId}`,
        expires_at: "2030-01-01T00:00:00Z",
        repository_id: repositoryId,
      }),
    },
    readFile: (file) => secretByPath.get(file) ?? "",
    realpath: (file) => file,
    port: 0,
    host: "127.0.0.1",
  });
  try {
    const address = server.address();
    assert.equal(verifies, 1);
    assert.equal((await request(`http://127.0.0.1:${address.port}`)).status, 200);
    assert.equal((await request(`http://127.0.0.1:${address.port}`)).status, 200);
    assert.equal(verifies, 1);
  } finally {
    server.close();
    await once(server, "close");
  }
});

test("unknown Workspace credentials are denied before any GitHub token call", async () => {
  let calls = 0;
  await withServer(
    async (origin) => {
      const response = await request(origin, {
        workspace: "unknown-team",
        secret: "unknown-secret-value-with-at-least-32-bytes",
      });
      assert.equal(response.status, 401);
      assert.deepEqual(await response.json(), { error: "workspace_unauthorized" });
      assert.equal(calls, 0);
    },
    async () => {
      calls += 1;
      throw new Error("must not be called");
    },
  );
});

test("policy requires exactly one broker Workspace per immutable GitHub Team", () => {
  const missingTeam = policyFixture();
  delete missingTeam.workspaces[0].github_team_id;
  assert.throws(() => parsePolicy(missingTeam), /workspaces\[0\]\.github_team_id must be a positive integer/);

  const stringTeam = policyFixture();
  stringTeam.workspaces[0].github_team_id = "4001";
  assert.throws(() => parsePolicy(stringTeam), /github_team_id must be a positive integer/);

  const duplicateTeam = policyFixture();
  duplicateTeam.workspaces[1].github_team_id = duplicateTeam.workspaces[0].github_team_id;
  assert.throws(() => parsePolicy(duplicateTeam), /exactly one broker Workspace per immutable GitHub Team/);

  const invalidSlug = policyFixture();
  invalidSlug.workspaces[0].github_team_slug = "Alpha Team";
  assert.throws(() => parsePolicy(invalidSlug), /github_team_slug is invalid/);

  const missingMembers = policyFixture();
  delete missingMembers.installation_permissions.members;
  assert.throws(() => parsePolicy(missingMembers), /members: read/);

  const parsed = parsePolicy(policyFixture());
  assert.equal(parsed.workspaces[0].github_team_id, 4001);
  assert.equal(parsed.workspaces[0].github_team_slug, "alpha-team");
  assert.equal(parsed.workspaces[1].github_team_id, 4002);
  assert.equal("github_team_slug" in parsed.workspaces[1], false);
});

test("policy retires schema v1 with an explicit migration message", () => {
  const legacy = policyFixture();
  legacy.schema_version = "lazurio.github_app_broker.policy.v1";
  assert.throws(() => parsePolicy(legacy), /policy\.v1 is retired; migrate to lazurio\.github_app_broker\.policy\.v2/);

  const unknown = policyFixture();
  unknown.schema_version = "lazurio.github_app_broker.policy.v3";
  assert.throws(() => parsePolicy(unknown), /unsupported policy schema/);
});

function teamGrantFetch({
  team = { id: 4001, slug: "alpha-team", organization: { id: 1001, login: "example-org" } },
  grant = { id: 3001, full_name: "example-org/alpha", permissions: { admin: false, maintain: false, pull: true, push: true, triage: true } },
  calls = [],
} = {}) {
  return async (url, init) => {
    const path = new URL(url).pathname + new URL(url).search;
    calls.push({ path, method: init.method, accept: init.headers.Accept, authorization: init.headers.Authorization, body: init.body && JSON.parse(init.body) });
    if (path === "/app/installations/2001/access_tokens" && init.method === "POST") {
      return jsonResponse({ token: "ghs_team_probe" });
    }
    if (path === "/organizations/1001/team/4001" && init.method === "GET") {
      return team === null ? jsonResponse({ message: "Not Found" }, 404) : jsonResponse(team);
    }
    if (path === "/organizations/1001/team/4001/repos/example-org/alpha" && init.method === "GET") {
      return grant === null ? jsonResponse({ message: "Not Found" }, 404) : jsonResponse(grant);
    }
    if (path === "/installation/token" && init.method === "DELETE") {
      return jsonResponse(null, 204);
    }
    throw new Error(`unexpected request ${init.method} ${path}`);
  };
}

test("verifies the live Team binding and write-capable grant with a revoked members-only probe", async () => {
  const policy = parsePolicy(policyFixture());
  const calls = [];
  const github = createGithubClient({
    appId: "42",
    privateKey: testPrivateKey(),
    fetchImpl: teamGrantFetch({ calls }),
  });
  const grant = await github.verifyTeamGrant(policy, policy.workspaces[0], 3001);
  assert.deepEqual(grant, {
    workspace_id: "alpha-team",
    github_team_id: 4001,
    github_team_slug: "alpha-team",
    repository_id: 3001,
    full_name: "example-org/alpha",
    role: "write",
  });
  assert.deepEqual(calls.map(({ method, path }) => `${method} ${path}`), [
    "POST /app/installations/2001/access_tokens",
    "GET /organizations/1001/team/4001",
    "GET /organizations/1001/team/4001/repos/example-org/alpha",
    "DELETE /installation/token",
  ]);
  assert.deepEqual(calls[0].body, { permissions: { members: "read" } });
  assert.equal(calls[1].authorization, "Bearer ghs_team_probe");
  assert.equal(calls[2].accept, "application/vnd.github.v3.repository+json");
  assert.equal(calls[3].authorization, "Bearer ghs_team_probe");
});

test("refuses with team_grant_missing when the Team is absent, renamed under a new id, or lacks write", async () => {
  const policy = parsePolicy(policyFixture());
  const workspace = policy.workspaces[0];
  const privateKey = testPrivateKey();
  const cases = [
    { name: "team absent", fetch: teamGrantFetch({ team: null }), message: /no longer exists/ },
    {
      name: "team id differs",
      fetch: teamGrantFetch({ team: { id: 4999, slug: "alpha-team", organization: { id: 1001, login: "example-org" } } }),
      message: /identity differs from policy/,
    },
    {
      name: "team belongs to another organization",
      fetch: teamGrantFetch({ team: { id: 4001, slug: "alpha-team", organization: { id: 1002, login: "other-org" } } }),
      message: /identity differs from policy/,
    },
    {
      name: "asserted slug drifted",
      fetch: teamGrantFetch({ team: { id: 4001, slug: "renamed-team", organization: { id: 1001, login: "example-org" } } }),
      message: /identity differs from policy/,
    },
    { name: "no grant", fetch: teamGrantFetch({ grant: null }), message: /no live grant on repository example-org\/alpha/ },
    {
      name: "read-only grant",
      fetch: teamGrantFetch({ grant: { id: 3001, full_name: "example-org/alpha", permissions: { admin: false, maintain: false, pull: true, push: false, triage: true } } }),
      message: /not write-capable/,
    },
    {
      name: "grant on a different repository id",
      fetch: teamGrantFetch({ grant: { id: 3999, full_name: "example-org/alpha", permissions: { admin: true, maintain: true, pull: true, push: true, triage: true } } }),
      message: /not write-capable/,
    },
    {
      name: "204 without permissions payload",
      fetch: teamGrantFetch({ grant: undefined }),
      message: /not write-capable/,
    },
  ];
  for (const { name, fetch: fetchImpl, message } of cases) {
    const calls = [];
    const wrapped = async (url, init) => {
      calls.push(`${init.method} ${new URL(url).pathname}`);
      if (name === "204 without permissions payload" && new URL(url).pathname.endsWith("/repos/example-org/alpha")) {
        return jsonResponse(null, 204);
      }
      return fetchImpl(url, init);
    };
    const github = createGithubClient({ appId: "42", privateKey, fetchImpl: wrapped });
    await assert.rejects(
      () => github.verifyTeamGrant(policy, workspace, 3001),
      (error) => {
        assert.equal(error.code, "team_grant_missing", name);
        assert.match(error.message, message, name);
        return true;
      },
    );
    assert.equal(calls.at(-1), "DELETE /installation/token", `${name} must revoke the probe`);
    assert.equal(calls.filter((call) => call.startsWith("POST /app/installations/2001/access_tokens")).length, 1, name);
  }
});

test("accepts maintain and admin grants and distinguishes outages from refusals", async () => {
  const policy = parsePolicy(policyFixture());
  const privateKey = testPrivateKey();
  for (const [permissions, role] of [
    [{ admin: false, maintain: true, pull: true, push: true, triage: true }, "maintain"],
    [{ admin: true, maintain: true, pull: true, push: true, triage: true }, "admin"],
  ]) {
    const github = createGithubClient({
      appId: "42",
      privateKey,
      fetchImpl: teamGrantFetch({ grant: { id: 3001, full_name: "example-org/alpha", permissions } }),
    });
    assert.equal((await github.verifyTeamGrant(policy, policy.workspaces[0], 3001)).role, role);
  }

  const outage = createGithubClient({
    appId: "42",
    privateKey,
    fetchImpl: async (url, init) => {
      if (new URL(url).pathname === "/organizations/1001/team/4001") return jsonResponse({ message: "boom" }, 503);
      return teamGrantFetch()(url, init);
    },
  });
  await assert.rejects(
    () => outage.verifyTeamGrant(policy, policy.workspaces[0], 3001),
    (error) => error.code === undefined && /HTTP 503/.test(error.message),
  );

  const outsidePolicy = createGithubClient({ appId: "42", privateKey, fetchImpl: teamGrantFetch() });
  await assert.rejects(
    () => outsidePolicy.verifyTeamGrant(policy, policy.workspaces[0], 3002),
    (error) => error.code === undefined && /outside the Workspace alpha-team policy/.test(error.message),
  );
});

test("mints only after a live Team grant and refuses with team_grant_missing otherwise", async () => {
  let mints = 0;
  let checks = 0;
  const server = createBrokerServer({
    policy: parsePolicy(policyFixture()),
    github: {
      verifyTeamGrant: async (_policy, workspace, repositoryId) => {
        checks += 1;
        assert.equal(workspace.github_team_id, 4001);
        assert.equal(repositoryId, 3001);
        if (workspace.id === "alpha-team" && checks > 1) {
          const error = new Error("grant revoked");
          error.code = "team_grant_missing";
          throw error;
        }
        return { role: "write" };
      },
      mintToken: async (_policy, repositoryId) => {
        mints += 1;
        assert.equal(checks, mints, "the Team grant must be verified before every mint");
        return {
          token: `ghs_synthetic_${repositoryId}_${mints}`,
          expires_at: "2030-01-01T00:00:00Z",
          repository_id: repositoryId,
        };
      },
    },
    readFile: (file) => secretByPath.get(file) ?? "",
    realpath: (file) => file,
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const origin = `http://127.0.0.1:${server.address().port}`;
    const first = await request(origin);
    assert.equal(first.status, 200);
    assert.equal((await first.json()).token, "ghs_synthetic_3001_1");

    const second = await request(origin);
    assert.equal(second.status, 403);
    assert.equal(second.headers.get("cache-control"), "no-store");
    assert.deepEqual(await second.json(), { error: "team_grant_missing" });
    assert.equal(checks, 2);
    assert.equal(mints, 1);
  } finally {
    server.close();
    await once(server, "close");
  }
});

test("Team grant outages fail closed as token_unavailable and cross-Workspace checks never run", async () => {
  let checks = 0;
  await withServer(
    async (origin) => {
      const outage = await request(origin);
      assert.equal(outage.status, 502);
      assert.deepEqual(await outage.json(), { error: "token_unavailable" });
      assert.equal(checks, 1);

      const denied = await request(origin, { repositoryId: 3002 });
      assert.equal(denied.status, 403);
      assert.deepEqual(await denied.json(), { error: "repository_denied" });
      assert.equal(checks, 1);
    },
    async () => {
      throw new Error("must not mint without a verified Team grant");
    },
    async () => {
      checks += 1;
      throw new Error("GitHub request failed with HTTP 503");
    },
  );
});

test("policy check --live reads back every Team grant and prints a secret-free table", async () => {
  const policy = parsePolicy(policyFixture());
  assert.equal(
    formatPolicySummary(policy),
    [
      "lazurio.github_app_broker.policy.v2 owner=example-org installation=2001",
      "WORKSPACE   TEAM_ID  TEAM_SLUG   REPOSITORIES",
      "alpha-team  4001     alpha-team  1",
      "beta-team   4002     -           1",
      "",
    ].join("\n"),
  );

  const probes = [];
  const github = {
    verifyPolicy: async () => probes.push("verify"),
    readWorkspaceTeamGrants: async (_policy, workspace) => {
      probes.push(`grants:${workspace.id}`);
      return workspace.repository_ids.map((repositoryId) => ({
        workspace_id: workspace.id,
        github_team_id: workspace.github_team_id,
        github_team_slug: workspace.github_team_slug ?? "beta",
        repository_id: repositoryId,
        full_name: policy.repositories.find(({ id }) => id === repositoryId).full_name,
        role: workspace.id === "alpha-team" ? "write" : "none",
        status: workspace.id === "alpha-team" ? "ok" : "refused",
        detail: workspace.id === "alpha-team" ? "" : "Workspace beta-team GitHub Team has no live grant on repository example-org/beta",
      }));
    },
  };
  const result = await checkPolicyLive({ policy, github });
  assert.deepEqual(probes, ["verify", "grants:alpha-team", "grants:beta-team"]);
  assert.equal(result.ok, false);
  const table = formatPolicyCheckTable(result.rows);
  assert.equal(
    table,
    [
      "WORKSPACE   TEAM_ID  TEAM_SLUG   REPOSITORY_ID  REPOSITORY         ROLE   STATUS   DETAIL",
      "alpha-team  4001     alpha-team  3001           example-org/alpha  write  ok",
      "beta-team   4002     beta        3002           example-org/beta   none   refused  Workspace beta-team GitHub Team has no live grant on repository example-org/beta",
      "2 grants checked, 1 ok, 1 refused",
      "",
    ].join("\n"),
  );
  assert.doesNotMatch(table, /ghs_|secret/i);

  const failedInstallation = { ...github, verifyPolicy: async () => { throw new Error("live GitHub installation identity, selection or permissions differ from policy"); } };
  await assert.rejects(() => checkPolicyLive({ policy, github: failedInstallation }), /differ from policy/);
});

test("readWorkspaceTeamGrants uses one probe per Workspace and reports each repository", async () => {
  const fixture = policyFixture();
  fixture.workspaces[0].repository_ids = [3001, 3002];
  const policy = parsePolicy(fixture);
  const calls = [];
  const fetchImpl = async (url, init) => {
    const path = new URL(url).pathname;
    calls.push(`${init.method} ${path}`);
    if (path === "/app/installations/2001/access_tokens") return jsonResponse({ token: "ghs_team_probe" });
    if (path === "/organizations/1001/team/4001") {
      return jsonResponse({ id: 4001, slug: "alpha-team", organization: { id: 1001, login: "example-org" } });
    }
    if (path === "/organizations/1001/team/4001/repos/example-org/alpha") {
      return jsonResponse({ id: 3001, full_name: "example-org/alpha", permissions: { admin: false, maintain: true, pull: true, push: true, triage: true } });
    }
    if (path === "/organizations/1001/team/4001/repos/example-org/beta") return jsonResponse({ message: "Not Found" }, 404);
    if (path === "/organizations/1001/team/4002") return jsonResponse({ message: "Not Found" }, 404);
    if (path === "/installation/token") return jsonResponse(null, 204);
    throw new Error(`unexpected request ${init.method} ${path}`);
  };
  const github = createGithubClient({ appId: "42", privateKey: testPrivateKey(), fetchImpl });

  const alpha = await github.readWorkspaceTeamGrants(policy, policy.workspaces[0]);
  assert.deepEqual(alpha.map(({ repository_id, role, status }) => [repository_id, role, status]), [
    [3001, "maintain", "ok"],
    [3002, "none", "refused"],
  ]);
  assert.match(alpha[1].detail, /no live grant on repository example-org\/beta/);
  assert.equal(calls.filter((call) => call === "POST /app/installations/2001/access_tokens").length, 1);
  assert.equal(calls.at(-1), "DELETE /installation/token");

  const beta = await github.readWorkspaceTeamGrants(policy, policy.workspaces[1]);
  assert.deepEqual(beta.map(({ repository_id, github_team_slug, status }) => [repository_id, github_team_slug, status]), [
    [3002, "?", "refused"],
  ]);
  assert.match(beta[0].detail, /Team 4002 no longer exists/);
});
