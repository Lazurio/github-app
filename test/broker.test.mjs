import assert from "node:assert/strict";
import crypto from "node:crypto";
import { once } from "node:events";
import test from "node:test";

import {
  createBrokerServer,
  createGithubClient,
  createReloadingPolicy,
  parseCommand,
  parsePolicy,
} from "../src/broker.mjs";

const secretByPath = new Map([
  ["/run/secrets/workspace-alpha", "alpha-secret-value-with-at-least-32-bytes"],
  ["/run/secrets/workspace-beta", "beta-secret-value-with-at-least-32-bytes"],
]);

function policyFixture() {
  return {
    schema_version: "lazurio.github_app_broker.policy.v1",
    github_app: { id: 42, slug: "example-app" },
    github_owner: { id: 1001, login: "example-org" },
    installation_id: 2001,
    installation_permissions: { contents: "write", members: "read", metadata: "read" },
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

async function withServer(run, mintToken = async (_policy, repositoryId) => ({
  token: `ghs_synthetic_${repositoryId}`,
  expires_at: "2030-01-01T00:00:00Z",
  repository_id: repositoryId,
})) {
  const server = createBrokerServer({
    policy: parsePolicy(policyFixture()),
    github: { mintToken },
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
        permissions: { contents: "write", members: "read", metadata: "read" },
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
        contents: "write",
        members: "read",
        metadata: "read",
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
        permissions: { contents: "write", members: "read", metadata: "read" },
      }),
  });
  await assert.rejects(() => wrongLiveApp.verifyPolicy(policy), /identity, selection or permissions/);
});

test("mints through repository_ids and rejects an over-scoped token response", async () => {
  const policy = parsePolicy(policyFixture());
  const now = 1_700_000_000_000;
  let responsePermissions = { contents: "write", metadata: "read" };
  const fetchImpl = async (_url, init) => {
    assert.deepEqual(JSON.parse(init.body), {
      repository_ids: [3001],
      permissions: { contents: "write" },
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

  responsePermissions = { administration: "write", contents: "write", metadata: "read" };
  await assert.rejects(
    () => github.mintToken(policy, 3001),
    /outside the requested repository or permission scope/,
  );
});

test("reloads and verifies a changed Workspace repository policy without restart", async () => {
  let current = JSON.stringify(policyFixture());
  let verifies = 0;
  const getPolicy = createReloadingPolicy({
    policyFile: "/run/config/policy.json",
    github: {
      verifyPolicy: async () => {
        verifies += 1;
      },
    },
    readFile: (file) =>
      file === "/run/config/policy.json" ? current : (secretByPath.get(file) ?? ""),
    realpath: (file) => file,
  });

  assert.deepEqual((await getPolicy()).policy.workspaces[0].repository_ids, [3001]);
  assert.equal(verifies, 1);
  assert.deepEqual((await getPolicy()).policy.workspaces[0].repository_ids, [3001]);
  assert.equal(verifies, 1);

  const changed = policyFixture();
  changed.workspaces[0].repository_ids = [3002];
  current = JSON.stringify(changed);
  assert.deepEqual((await getPolicy()).policy.workspaces[0].repository_ids, [3002]);
  assert.equal(verifies, 2);
});

test("does not fall back to the previously accepted policy when a replacement is invalid", async () => {
  let current = JSON.stringify(policyFixture());
  const getPolicy = createReloadingPolicy({
    policyFile: "/run/config/policy.json",
    github: { verifyPolicy: async () => {} },
    readFile: (file) =>
      file === "/run/config/policy.json" ? current : (secretByPath.get(file) ?? ""),
    realpath: (file) => file,
  });
  await getPolicy();
  current = "{not-json";
  await assert.rejects(() => getPolicy(), SyntaxError);
});

test("rejects duplicated Workspace credential values and aliased paths", async () => {
  const current = JSON.stringify(policyFixture());
  const duplicateValue = createReloadingPolicy({
    policyFile: "/run/config/policy.json",
    github: { verifyPolicy: async () => {} },
    readFile: (file) =>
      file === "/run/config/policy.json" ? current : "same-secret-value-with-at-least-32-bytes",
    realpath: (file) => file,
  });
  await assert.rejects(() => duplicateValue(), /credential values must be unique/);

  const aliasedPath = createReloadingPolicy({
    policyFile: "/run/config/policy.json",
    github: { verifyPolicy: async () => {} },
    readFile: (file) =>
      file === "/run/config/policy.json" ? current : (secretByPath.get(file) ?? ""),
    realpath: () => "/run/secrets/same-file",
  });
  await assert.rejects(() => aliasedPath(), /resolve to unique/);
});

test("policy rejects a non-canonical secret path", () => {
  const policy = policyFixture();
  policy.workspaces[0].credential_file = "/run/secrets//workspace-alpha";
  assert.throws(() => parsePolicy(policy), /canonical file/);
});

test("accepts only the server and one-shot verification commands", () => {
  assert.deepEqual(parseCommand([]), { verifyOnly: false });
  assert.deepEqual(parseCommand(["--verify-only"]), { verifyOnly: true });
  assert.throws(() => parseCommand(["--unknown"]), /usage/);
  assert.throws(() => parseCommand(["--verify-only", "extra"]), /usage/);
});

test("authenticates against the same credential snapshot that passed uniqueness", async () => {
  const reads = new Map();
  const server = createBrokerServer({
    policy: parsePolicy(policyFixture()),
    github: {
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
    const response = await request(`http://127.0.0.1:${address.port}`);
    assert.equal(response.status, 200);
    assert.equal(reads.get("/run/secrets/workspace-alpha"), 1);
    assert.equal(reads.get("/run/secrets/workspace-beta"), 1);
  } finally {
    server.close();
    await once(server, "close");
  }
});

test("concurrent policy verification never shares a stale credential snapshot", async () => {
  const values = new Map(secretByPath);
  let releaseVerification;
  let verificationStarted;
  const started = new Promise((resolve) => {
    verificationStarted = resolve;
  });
  const blocked = new Promise((resolve) => {
    releaseVerification = resolve;
  });
  const getPolicy = createReloadingPolicy({
    policyFile: "/run/config/policy.json",
    github: {
      verifyPolicy: async () => {
        verificationStarted();
        await blocked;
      },
    },
    readFile: (file) =>
      file === "/run/config/policy.json"
        ? JSON.stringify(policyFixture())
        : (values.get(file) ?? ""),
    realpath: (file) => file,
  });

  const first = getPolicy();
  await started;
  values.set("/run/secrets/workspace-alpha", "rotated-alpha-secret-with-at-least-32-bytes");
  const second = getPolicy();
  releaseVerification();

  assert.equal(
    (await first).credentials.get("alpha-team"),
    "rotated-alpha-secret-with-at-least-32-bytes",
  );
  assert.equal(
    (await second).credentials.get("alpha-team"),
    "rotated-alpha-secret-with-at-least-32-bytes",
  );
});
