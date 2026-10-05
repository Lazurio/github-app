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
        github_team_slug: "alpha-team",
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

/** Synthetic live grants of alpha's Team: name -> [repository id, access tier the grant mints]. */
const SYNTHETIC_REPOSITORIES = new Map([
  ["example-org/alpha", [3001, "write"]],
  ["example-org/beta", [3002, "write"]],
  ["example-org/handbook", [3004, "read"]],
]);

/** Synthetic Workspace Team proof: the bound Team exists with its asserted identity. */
const provenTeam = async (_policy, workspace) => ({
  id: workspace.github_team_id,
  slug: workspace.github_team_slug ?? workspace.id,
});

/** Synthetic Team gate: resolves both body forms to the canonical repository id, name and tier. */
const grantedTeam = async (_policy, workspace, target) => {
  const entry = target.repository_id === undefined
    ? [...SYNTHETIC_REPOSITORIES].find(([name]) => name === target.repository.toLowerCase())
    : [...SYNTHETIC_REPOSITORIES].find(([, [id]]) => id === target.repository_id);
  if (!entry) throw Object.assign(new Error("no grant"), { code: "team_grant_missing" });
  const [fullName, [repositoryId, access]] = entry;
  return {
    workspace_id: workspace.id,
    github_team_id: workspace.github_team_id,
    github_team_slug: workspace.github_team_slug ?? workspace.id,
    repository_id: repositoryId,
    full_name: fullName,
    role: access === "write" ? "write" : "read",
    access,
  };
};

/** Synthetic mint that honours the requested repository and access tier. */
const syntheticMint = async (_policy, repositoryId, access) => ({
  token: `ghs_synthetic_${repositoryId}`,
  expires_at: "2030-01-01T00:00:00Z",
  repository_id: repositoryId,
  access,
});

async function withServer(run, mintToken = syntheticMint, verifyTeamGrant = grantedTeam, verifyWorkspaceTeam = provenTeam) {
  const server = createBrokerServer({
    policy: parsePolicy(policyFixture()),
    github: { verifyTeamGrant, verifyWorkspaceTeam, mintToken },
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

function request(origin, {
  workspace = "alpha-team",
  secret = secretByPath.get("/run/secrets/workspace-alpha"),
  body = { repository: "example-org/alpha" },
  rawBody,
} = {}) {
  return fetch(`${origin}/v1/token`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${secret}`,
      "Content-Type": "application/json",
      "X-Lazurio-Workspace-ID": workspace,
    },
    body: rawBody ?? JSON.stringify(body),
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

test("mints a non-cacheable token for the Team-granted repository in both body forms", async () => {
  await withServer(async (origin) => {
    for (const body of [{ repository: "example-org/alpha" }, { repository: "Example-Org/Alpha" }, { repository_id: 3001 }]) {
      const response = await request(origin, { body });
      assert.equal(response.status, 200, JSON.stringify(body));
      assert.equal(response.headers.get("cache-control"), "no-store");
      assert.deepEqual(await response.json(), {
        token: "ghs_synthetic_3001",
        expires_at: "2030-01-01T00:00:00Z",
        repository_id: 3001,
        repository: "example-org/alpha",
        access: "write",
      });
    }
  });
});

test("mints the read tier for a read-granted repository and says so in the response", async () => {
  const mints = [];
  await withServer(
    async (origin) => {
      for (const body of [{ repository: "example-org/handbook" }, { repository_id: 3004 }]) {
        const response = await request(origin, { body });
        assert.equal(response.status, 200, JSON.stringify(body));
        assert.equal(response.headers.get("cache-control"), "no-store");
        assert.deepEqual(await response.json(), {
          token: "ghs_synthetic_3004",
          expires_at: "2030-01-01T00:00:00Z",
          repository_id: 3004,
          repository: "example-org/handbook",
          access: "read",
        });
      }
      assert.deepEqual(mints, [[3004, "read"], [3004, "read"]]);
    },
    async (policy, repositoryId, access) => {
      mints.push([repositoryId, access]);
      return syntheticMint(policy, repositoryId, access);
    },
  );
});

test("fails closed when the Team gate or the mint loses the access tier", async () => {
  for (const [name, mintToken, verifyTeamGrant] of [
    [
      "gate without a tier",
      async () => {
        throw new Error("must not mint without a verified tier");
      },
      async (...args) => ({ ...(await grantedTeam(...args)), access: undefined }),
    ],
    [
      "gate with an unknown tier",
      async () => {
        throw new Error("must not mint without a verified tier");
      },
      async (...args) => ({ ...(await grantedTeam(...args)), access: "admin" }),
    ],
    [
      "mint of another tier",
      async (policy, repositoryId) => syntheticMint(policy, repositoryId, "write"),
      async (...args) => ({ ...(await grantedTeam(...args)), access: "read" }),
    ],
  ]) {
    await withServer(
      async (origin) => {
        const response = await request(origin);
        assert.equal(response.status, 502, name);
        assert.deepEqual(await response.json(), { error: "token_unavailable" }, name);
      },
      mintToken,
      verifyTeamGrant,
    );
  }
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

test("rejects a repository of another owner by name before any GitHub traffic", async () => {
  let calls = 0;
  const count = async () => {
    calls += 1;
    throw new Error("must not be called");
  };
  await withServer(
    async (origin) => {
      for (const repository of ["other-org/alpha", "example-org-two/alpha", "Other-Org/beta"]) {
        const response = await request(origin, { body: { repository } });
        assert.equal(response.status, 403, repository);
        assert.deepEqual(await response.json(), { error: "repository_denied" });
      }
      assert.equal(calls, 0);
    },
    count,
    count,
  );
});

test("rejects every body other than exactly one repository form with 400 and no GitHub traffic", async () => {
  let calls = 0;
  const count = async () => {
    calls += 1;
    throw new Error("must not be called");
  };
  await withServer(
    async (origin) => {
      for (const rawBody of [
        "{",
        "[]",
        "null",
        "\"example-org/alpha\"",
        "{}",
        JSON.stringify({ repository: "example-org/alpha", repository_id: 3001 }),
        JSON.stringify({ repository_id: 3001, padding: "x" }),
        JSON.stringify({ repository_id: "3001" }),
        JSON.stringify({ repository_id: 0 }),
        JSON.stringify({ repository_id: -1 }),
        JSON.stringify({ repository_id: 1.5 }),
        JSON.stringify({ repository_id: 2 ** 53 }),
        JSON.stringify({ repository: "example-org" }),
        JSON.stringify({ repository: "example-org/alpha/extra" }),
        JSON.stringify({ repository: "example-org/.." }),
        JSON.stringify({ repository: "example-org/." }),
        JSON.stringify({ repository: "example-org/al%2Fpha" }),
        JSON.stringify({ repository: "https://github.com/example-org/alpha" }),
        JSON.stringify({ repository: " example-org/alpha" }),
        JSON.stringify({ repository: 3001 }),
        JSON.stringify({ full_name: "example-org/alpha" }),
      ]) {
        const response = await request(origin, { rawBody });
        assert.equal(response.status, 400, rawBody);
        assert.deepEqual(await response.json(), { error: "invalid_request" });
      }
      assert.equal(calls, 0);
    },
    count,
    count,
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
    async (_policy, repositoryId, access) => {
      calls += 1;
      return {
        token: `ghs_synthetic_${repositoryId}_${calls}`,
        expires_at: "2030-01-01T00:00:00Z",
        repository_id: repositoryId,
        access,
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

test("policy rejects ambiguous Workspace credentials and incomplete permissions", () => {
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

function liveInstallation(selection = "selected", overrides = {}) {
  return {
    app_id: 42,
    app_slug: "example-app",
    account: { id: 1001, login: "example-org" },
    target_type: "Organization",
    repository_selection: selection,
    permissions: {
      actions: "write",
      checks: "read",
      contents: "write",
      members: "read",
      metadata: "read",
      pull_requests: "write",
    },
    ...overrides,
  };
}

test("verifies the exact live installation with one read and no repository enumeration", async () => {
  for (const selection of ["selected", "all"]) {
    const fixture = policyFixture();
    fixture.installation_repository_selection = selection;
    const policy = parsePolicy(fixture);
    const calls = [];
    const fetchImpl = async (url, init) => {
      const path = new URL(url).pathname + new URL(url).search;
      calls.push(`${init.method} ${path}`);
      if (path === "/app/installations/2001" && init.method === "GET") return jsonResponse(liveInstallation(selection));
      throw new Error(`unexpected request ${init.method} ${path}`);
    };
    const github = createGithubClient({ appId: "42", privateKey: testPrivateKey(), fetchImpl });
    await github.verifyPolicy(policy);
    assert.deepEqual(calls, ["GET /app/installations/2001"], selection);
  }
});

test("rejects selection, owner and target drift of the live installation", async () => {
  const privateKey = testPrivateKey();
  const allFixture = policyFixture();
  allFixture.installation_repository_selection = "all";
  for (const [policy, installation] of [
    [parsePolicy(allFixture), liveInstallation("selected")],
    [parsePolicy(policyFixture()), liveInstallation("all")],
    [parsePolicy(policyFixture()), liveInstallation("selected", { account: { id: 1002, login: "example-org" } })],
    [parsePolicy(policyFixture()), liveInstallation("selected", { account: { id: 1001, login: "other-org" } })],
    [parsePolicy(policyFixture()), liveInstallation("selected", { target_type: "User" })],
  ]) {
    const github = createGithubClient({ appId: "42", privateKey, fetchImpl: async () => jsonResponse(installation) });
    await assert.rejects(() => github.verifyPolicy(policy), /identity, selection or permissions differ from policy/);
  }
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
    members: "read",
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
        members: "read",
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
  assert.deepEqual(await github.mintToken(policy, 3001, "write"), {
    token: "ghs_scoped_synthetic_token",
    expires_at: new Date(now + 60 * 60 * 1000).toISOString(),
    repository_id: 3001,
    access: "write",
  });

  responsePermissions = {
    checks: "read",
    contents: "write",
    members: "read",
    metadata: "read",
    pull_requests: "write",
  };
  await assert.rejects(
    () => github.mintToken(policy, 3001, "write"),
    /outside the requested repository or permission scope/,
  );

  responsePermissions = {
    actions: "write",
    contents: "write",
    members: "read",
    metadata: "read",
    pull_requests: "write",
  };
  await assert.rejects(
    () => github.mintToken(policy, 3001, "write"),
    /outside the requested repository or permission scope/,
  );

  responsePermissions = {
    actions: "write",
    checks: "read",
    contents: "write",
    members: "read",
    metadata: "read",
  };
  await assert.rejects(
    () => github.mintToken(policy, 3001, "write"),
    /outside the requested repository or permission scope/,
  );

  responsePermissions = {
    actions: "write",
    checks: "read",
    contents: "write",
    metadata: "read",
    pull_requests: "write",
  };
  await assert.rejects(
    () => github.mintToken(policy, 3001, "write"),
    /outside the requested repository or permission scope/,
  );

  responsePermissions = {
    administration: "write",
    actions: "write",
    checks: "read",
    contents: "write",
    members: "read",
    metadata: "read",
    pull_requests: "write",
  };
  await assert.rejects(
    () => github.mintToken(policy, 3001, "write"),
    /outside the requested repository or permission scope/,
  );
});

test("asks for workflows: write only when the policy declares the accepted permission", async () => {
  const now = 1_700_000_000_000;
  const base = { actions: "write", checks: "read", contents: "write", members: "read", pull_requests: "write" };
  let requested;
  let responsePermissions;
  const github = createGithubClient({
    appId: "42",
    privateKey: testPrivateKey(),
    fetchImpl: async (_url, init) => {
      requested = JSON.parse(init.body).permissions;
      return jsonResponse({
        token: "ghs_scoped_synthetic_token",
        expires_at: new Date(now + 60 * 60 * 1000).toISOString(),
        repositories: [{ id: 3001 }],
        permissions: responsePermissions,
      });
    },
    now: () => now,
  });

  const withoutWorkflows = parsePolicy(policyFixture());
  responsePermissions = { ...base, metadata: "read", workflows: "write" };
  await assert.rejects(
    () => github.mintToken(withoutWorkflows, 3001, "write"),
    /outside the requested repository or permission scope/,
  );
  assert.deepEqual(requested, base);

  const fixture = policyFixture();
  fixture.installation_permissions = { ...fixture.installation_permissions, emails: "read", workflows: "write" };
  const withWorkflows = parsePolicy(fixture);
  assert.equal((await github.mintToken(withWorkflows, 3001, "write")).repository_id, 3001);
  assert.deepEqual(requested, { ...base, workflows: "write" });

  responsePermissions = { ...base, metadata: "read" };
  await assert.rejects(
    () => github.mintToken(withWorkflows, 3001, "write"),
    /outside the requested repository or permission scope/,
  );

  responsePermissions = { ...base, metadata: "read", workflows: "write", emails: "read" };
  await assert.rejects(
    () => github.mintToken(withWorkflows, 3001, "write"),
    /outside the requested repository or permission scope/,
  );

});

test("the write tier adds issues: write only when the policy declares the accepted permission", async () => {
  const now = 1_700_000_000_000;
  const base = { actions: "write", checks: "read", contents: "write", members: "read", pull_requests: "write" };
  let requested;
  let responsePermissions;
  const github = createGithubClient({
    appId: "42",
    privateKey: testPrivateKey(),
    fetchImpl: async (_url, init) => {
      requested = JSON.parse(init.body).permissions;
      return jsonResponse({
        token: "ghs_scoped_synthetic_token",
        expires_at: new Date(now + 60 * 60 * 1000).toISOString(),
        repositories: [{ id: 3001 }],
        permissions: responsePermissions,
      });
    },
    now: () => now,
  });

  // Not declared: the write tier stays the base set and refuses an issues grant it did not ask for.
  responsePermissions = { ...base, issues: "write", metadata: "read" };
  await assert.rejects(
    () => github.mintToken(parsePolicy(policyFixture()), 3001, "write"),
    /outside the requested repository or permission scope/,
  );
  assert.deepEqual(requested, base);

  // Declared alone, and together with workflows.
  const fixture = policyFixture();
  fixture.installation_permissions.issues = "write";
  responsePermissions = { ...base, issues: "write", metadata: "read" };
  assert.equal((await github.mintToken(parsePolicy(fixture), 3001, "write")).access, "write");
  assert.deepEqual(requested, { ...base, issues: "write" });

  fixture.installation_permissions.workflows = "write";
  responsePermissions = { ...base, issues: "write", metadata: "read", workflows: "write" };
  assert.equal((await github.mintToken(parsePolicy(fixture), 3001, "write")).access, "write");
  assert.deepEqual(requested, { ...base, issues: "write", workflows: "write" });

  // Declared but missing from GitHub's answer is refused.
  responsePermissions = { ...base, metadata: "read", workflows: "write" };
  await assert.rejects(
    () => github.mintToken(parsePolicy(fixture), 3001, "write"),
    /outside the requested repository or permission scope/,
  );

  // An issues permission declared only as read is not the accepted write permission.
  fixture.installation_permissions.issues = "read";
  responsePermissions = { ...base, metadata: "read", workflows: "write" };
  await github.mintToken(parsePolicy(fixture), 3001, "write");
  assert.deepEqual(requested, { ...base, workflows: "write" });
});

test("the read tier asks for contents, pull request, check and Actions reads, adds issues: write only when declared, and nothing else", async () => {
  const now = 1_700_000_000_000;
  let requests = 0;
  let requested;
  let responsePermissions;
  const github = createGithubClient({
    appId: "42",
    privateKey: testPrivateKey(),
    fetchImpl: async (_url, init) => {
      requests += 1;
      const body = JSON.parse(init.body);
      assert.deepEqual(body.repository_ids, [3004]);
      requested = body.permissions;
      return jsonResponse({
        token: "ghs_scoped_synthetic_token",
        expires_at: new Date(now + 60 * 60 * 1000).toISOString(),
        repositories: [{ id: 3004 }],
        permissions: responsePermissions,
      });
    },
    now: () => now,
  });

  const readBase = { actions: "read", checks: "read", contents: "read", members: "read", pull_requests: "read" };

  // Base policy: no issues accepted. A workflows acceptance never leaks into the read tier.
  const fixture = policyFixture();
  fixture.installation_permissions.workflows = "write";
  const withoutIssues = parsePolicy(fixture);
  responsePermissions = { ...readBase, metadata: "read" };
  assert.deepEqual(await github.mintToken(withoutIssues, 3004, "read"), {
    token: "ghs_scoped_synthetic_token",
    expires_at: new Date(now + 60 * 60 * 1000).toISOString(),
    repository_id: 3004,
    access: "read",
  });
  assert.deepEqual(requested, readBase);

  fixture.installation_permissions.issues = "write";
  const withIssues = parsePolicy(fixture);
  responsePermissions = { ...readBase, issues: "write", metadata: "read" };
  assert.equal((await github.mintToken(withIssues, 3004, "read")).access, "read");
  assert.deepEqual(requested, { ...readBase, issues: "write" });

  // An issues permission declared only as read is not the accepted write permission.
  fixture.installation_permissions.issues = "read";
  responsePermissions = { ...readBase, metadata: "read" };
  await github.mintToken(parsePolicy(fixture), 3004, "read");
  assert.deepEqual(requested, readBase);

  // Any write or read beyond the requested set, a missing read, or an undeclared issues grant is refused.
  for (const permissions of [
    { ...readBase, contents: "write", metadata: "read" },
    { ...readBase, pull_requests: "write", metadata: "read" },
    { ...readBase, checks: "write", metadata: "read" },
    { ...readBase, actions: "write", metadata: "read" },
    { ...readBase, workflows: "write", metadata: "read" },
    { ...readBase, issues: "write", metadata: "read" },
    { ...readBase, members: "write", metadata: "read" },
    { actions: "read", contents: "read", members: "read", pull_requests: "read", metadata: "read" },
    { actions: "read", checks: "read", contents: "read", members: "read", metadata: "read" },
    { checks: "read", contents: "read", members: "read", pull_requests: "read", metadata: "read" },
    { actions: "read", checks: "read", contents: "read", pull_requests: "read", metadata: "read" },
  ]) {
    responsePermissions = permissions;
    await assert.rejects(
      () => github.mintToken(withoutIssues, 3004, "read"),
      /outside the requested repository or permission scope/,
      JSON.stringify(permissions),
    );
  }
  responsePermissions = { ...readBase, metadata: "read" };
  await assert.rejects(
    () => github.mintToken(withIssues, 3004, "read"),
    /outside the requested repository or permission scope/,
  );

  // There is no default tier: a missing or unknown tier never reaches GitHub.
  const before = requests;
  for (const access of [undefined, "", "admin", "WRITE"]) {
    await assert.rejects(() => github.mintToken(withIssues, 3004, access), /access tier must be read or write/);
  }
  assert.equal(requests, before);
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
      verifyWorkspaceTeam: provenTeam,
      mintToken: syntheticMint,
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
      verifyWorkspaceTeam: provenTeam,
      mintToken: syntheticMint,
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

test("policy retires schemas v1 and v2 with an explicit v3 migration message", () => {
  const v1 = policyFixture();
  v1.schema_version = "lazurio.github_app_broker.policy.v1";
  assert.throws(
    () => parsePolicy(v1),
    /policy\.v1 is retired; .*migrate to lazurio\.github_app_broker\.policy\.v3 by deleting `repositories` and every `workspaces\[\]\.repository_ids`; the live Team grant is the scope/,
  );

  const v2 = policyFixture();
  v2.schema_version = "lazurio.github_app_broker.policy.v2";
  v2.repositories = [{ id: 3001, full_name: "example-org/alpha" }];
  v2.workspaces[0].repository_ids = [3001];
  assert.throws(
    () => parsePolicy(v2),
    /policy\.v2 is retired; migrate to lazurio\.github_app_broker\.policy\.v3 by deleting `repositories` and every `workspaces\[\]\.repository_ids`; the live Team grant is the scope/,
  );

  const unknown = policyFixture();
  unknown.schema_version = "lazurio.github_app_broker.policy.v4";
  assert.throws(() => parsePolicy(unknown), /unsupported policy schema/);
});

test("a half-migrated v3 policy with repositories or repository_ids fails closed", () => {
  const withRepositories = policyFixture();
  withRepositories.repositories = [{ id: 3001, full_name: "example-org/alpha" }];
  assert.throws(() => parsePolicy(withRepositories), /v3 must not contain `repositories`; migrate/);

  const emptyRepositories = policyFixture();
  emptyRepositories.repositories = [];
  assert.throws(() => parsePolicy(emptyRepositories), /v3 must not contain `repositories`/);

  const withRepositoryIds = policyFixture();
  withRepositoryIds.workspaces[1].repository_ids = [3002];
  assert.throws(() => parsePolicy(withRepositoryIds), /v3 must not contain `workspaces\[1\]\.repository_ids`; migrate/);

  const parsed = parsePolicy(policyFixture());
  assert.equal("repositories" in parsed, false);
  assert.equal("repository_ids" in parsed.workspaces[0], false);
});

const PROBE_PERMISSIONS = { members: "read", metadata: "read" };

function teamGrantFetch({
  team = { id: 4001, slug: "alpha-team", organization: { id: 1001, login: "example-org" } },
  grant = {
    id: 3001,
    full_name: "example-org/alpha",
    owner: { id: 1001, login: "example-org" },
    permissions: { admin: false, maintain: false, pull: true, push: true, triage: true },
  },
  repositories = {
    3001: { id: 3001, full_name: "example-org/alpha", owner: { id: 1001, login: "example-org" } },
  },
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
    // The second Team exists and holds no repository grant.
    if (path === "/organizations/1001/team/4002" && init.method === "GET") {
      return jsonResponse({ id: 4002, slug: "beta", organization: { id: 1001, login: "example-org" } });
    }
    if (path.startsWith("/organizations/1001/team/4002/repos/") && init.method === "GET") {
      return jsonResponse({ message: "Not Found" }, 404);
    }
    const repositoryMatch = path.match(/^\/repositories\/(\d+)$/);
    if (repositoryMatch && init.method === "GET") {
      const repository = repositories[repositoryMatch[1]];
      return repository ? jsonResponse(repository) : jsonResponse({ message: "Not Found" }, 404);
    }
    if (path === "/organizations/1001/team/4001/repos/example-org/alpha" && init.method === "GET") {
      return grant === null ? jsonResponse({ message: "Not Found" }, 404) : jsonResponse(grant);
    }
    if (path.startsWith("/organizations/1001/team/4001/repos/") && init.method === "GET") {
      return jsonResponse({ message: "Not Found" }, 404);
    }
    if (path === "/installation/token" && init.method === "DELETE") {
      return jsonResponse(null, 204);
    }
    throw new Error(`unexpected request ${init.method} ${path}`);
  };
}

test("verifies the live Team binding and a write grant by name with a revoked probe", async () => {
  const policy = parsePolicy(policyFixture());
  const calls = [];
  const github = createGithubClient({
    appId: "42",
    privateKey: testPrivateKey(),
    fetchImpl: teamGrantFetch({ calls }),
  });
  const grant = await github.verifyTeamGrant(policy, policy.workspaces[0], { repository: "example-org/alpha" });
  assert.deepEqual(grant, {
    workspace_id: "alpha-team",
    github_team_id: 4001,
    github_team_slug: "alpha-team",
    repository_id: 3001,
    full_name: "example-org/alpha",
    role: "write",
    access: "write",
  });
  assert.deepEqual(calls.map(({ method, path }) => `${method} ${path}`), [
    "POST /app/installations/2001/access_tokens",
    "GET /organizations/1001/team/4001",
    "GET /organizations/1001/team/4001/repos/example-org/alpha",
    "DELETE /installation/token",
  ]);
  assert.deepEqual(calls[0].body, { permissions: PROBE_PERMISSIONS });
  assert.equal(calls[1].authorization, "Bearer ghs_team_probe");
  assert.equal(calls[2].accept, "application/vnd.github.v3.repository+json");
  assert.equal(calls[3].authorization, "Bearer ghs_team_probe");
});

test("the id form resolves the live coordinate first and costs one extra read", async () => {
  const policy = parsePolicy(policyFixture());
  const calls = [];
  const github = createGithubClient({
    appId: "42",
    privateKey: testPrivateKey(),
    fetchImpl: teamGrantFetch({ calls }),
  });
  const grant = await github.verifyTeamGrant(policy, policy.workspaces[0], { repository_id: 3001 });
  assert.equal(grant.repository_id, 3001);
  assert.equal(grant.full_name, "example-org/alpha");
  assert.deepEqual(calls.map(({ method, path }) => `${method} ${path}`), [
    "POST /app/installations/2001/access_tokens",
    "GET /organizations/1001/team/4001",
    "GET /repositories/3001",
    "GET /organizations/1001/team/4001/repos/example-org/alpha",
    "DELETE /installation/token",
  ]);
  assert.equal(calls[2].authorization, "Bearer ghs_team_probe");
});

test("returns the canonical repository name and id GitHub reports for a differently cased name", async () => {
  const policy = parsePolicy(policyFixture());
  const calls = [];
  const fetchImpl = async (url, init) => {
    const path = new URL(url).pathname;
    calls.push(path);
    if (path === "/organizations/1001/team/4001/repos/Example-Org/ALPHA") {
      return jsonResponse({
        id: 3001,
        full_name: "example-org/alpha",
        owner: { id: 1001, login: "example-org" },
        permissions: { admin: false, maintain: false, pull: true, push: true, triage: true },
      });
    }
    return teamGrantFetch()(url, init);
  };
  const github = createGithubClient({ appId: "42", privateKey: testPrivateKey(), fetchImpl });
  const grant = await github.verifyTeamGrant(policy, policy.workspaces[0], { repository: "Example-Org/ALPHA" });
  assert.equal(grant.full_name, "example-org/alpha");
  assert.equal(grant.repository_id, 3001);
  assert.ok(calls.includes("/organizations/1001/team/4001/repos/Example-Org/ALPHA"));
});

test("refuses with team_grant_missing when the Team is absent, drifted, or holds no grant", async () => {
  const policy = parsePolicy(policyFixture());
  const workspace = policy.workspaces[0];
  const privateKey = testPrivateKey();
  const writeGrant = (overrides) => ({
    id: 3001,
    full_name: "example-org/alpha",
    owner: { id: 1001, login: "example-org" },
    permissions: { admin: false, maintain: false, pull: true, push: true, triage: true },
    ...overrides,
  });
  const byName = { repository: "example-org/alpha" };
  const byId = { repository_id: 3001 };
  const cases = [
    { name: "team absent", fetch: teamGrantFetch({ team: null }), target: byName, message: /no longer exists/ },
    {
      name: "team id differs",
      fetch: teamGrantFetch({ team: { id: 4999, slug: "alpha-team", organization: { id: 1001, login: "example-org" } } }),
      target: byName,
      message: /identity differs from policy/,
    },
    {
      name: "team belongs to another organization",
      fetch: teamGrantFetch({ team: { id: 4001, slug: "alpha-team", organization: { id: 1002, login: "other-org" } } }),
      target: byName,
      message: /identity differs from policy/,
    },
    {
      name: "asserted slug drifted",
      fetch: teamGrantFetch({ team: { id: 4001, slug: "renamed-team", organization: { id: 1001, login: "example-org" } } }),
      target: byName,
      message: /identity differs from policy/,
    },
    { name: "no grant by name", fetch: teamGrantFetch({ grant: null }), target: byName, message: /no live grant on repository example-org\/alpha/ },
    { name: "no grant by id", fetch: teamGrantFetch({ grant: null }), target: byId, message: /no live grant on repository example-org\/alpha/ },
    {
      name: "repository not in the Team (cross-repository)",
      fetch: teamGrantFetch(),
      target: { repository: "example-org/beta" },
      message: /no live grant on repository example-org\/beta/,
    },
    { name: "id not visible", fetch: teamGrantFetch(), target: { repository_id: 3999 }, message: /cannot see repository 3999/ },
    {
      name: "grant payload without any permission",
      fetch: teamGrantFetch({ grant: writeGrant({ permissions: { admin: false, maintain: false, pull: false, push: false, triage: false } }) }),
      target: byName,
      message: /holds no verifiable grant on repository example-org\/alpha/,
    },
    {
      name: "grant payload without a permissions object",
      fetch: teamGrantFetch({ grant: writeGrant({ permissions: undefined }) }),
      target: byId,
      message: /holds no verifiable grant/,
    },
    {
      name: "id form grant returns a different repository id",
      fetch: teamGrantFetch({ grant: writeGrant({ id: 3999 }) }),
      target: byId,
      message: /holds no verifiable grant/,
    },
    {
      name: "read grant returns a different repository id",
      fetch: teamGrantFetch({ grant: writeGrant({ id: 3999, permissions: { admin: false, maintain: false, pull: true, push: false, triage: false } }) }),
      target: byId,
      message: /holds no verifiable grant/,
    },
    {
      name: "grant without a canonical full name",
      fetch: teamGrantFetch({ grant: writeGrant({ full_name: undefined }) }),
      target: byName,
      message: /holds no verifiable grant/,
    },
    {
      name: "204 without permissions payload",
      fetch: teamGrantFetch(),
      target: byName,
      message: /holds no verifiable grant/,
    },
  ];
  for (const { name, fetch: fetchImpl, target, message } of cases) {
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
      () => github.verifyTeamGrant(policy, workspace, target),
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

test("refuses a repository of another owner with repository_denied in both forms", async () => {
  const policy = parsePolicy(policyFixture());
  const workspace = policy.workspaces[0];
  const privateKey = testPrivateKey();
  const foreign = { id: 9001, full_name: "other-org/alpha", owner: { id: 1002, login: "other-org" } };
  const cases = [
    {
      name: "id form resolves to a public repository of another owner",
      fetch: teamGrantFetch({ repositories: { 9001: foreign } }),
      target: { repository_id: 9001 },
      reads: ["GET /repositories/9001"],
    },
    {
      name: "grant readback reports another owner",
      fetch: teamGrantFetch({
        grant: {
          id: 3001,
          full_name: "example-org/alpha",
          owner: { id: 1002, login: "example-org" },
          permissions: { admin: true, maintain: true, pull: true, push: true, triage: true },
        },
      }),
      target: { repository: "example-org/alpha" },
      reads: ["GET /organizations/1001/team/4001/repos/example-org/alpha"],
    },
    {
      name: "direct client call with a name of another owner",
      fetch: teamGrantFetch(),
      target: { repository: "other-org/alpha" },
      reads: [],
    },
  ];
  for (const { name, fetch: fetchImpl, target, reads } of cases) {
    const calls = [];
    const github = createGithubClient({
      appId: "42",
      privateKey,
      fetchImpl: async (url, init) => {
        calls.push(`${init.method} ${new URL(url).pathname}`);
        return fetchImpl(url, init);
      },
    });
    await assert.rejects(
      () => github.verifyTeamGrant(policy, workspace, target),
      (error) => {
        assert.equal(error.code, "repository_denied", name);
        return true;
      },
    );
    for (const read of reads) assert.ok(calls.includes(read), `${name} reads ${read}`);
    assert.equal(calls.some((call) => call.includes("/repos/other-org/")), false, name);
    assert.equal(calls.at(-1), "DELETE /installation/token", `${name} must revoke the probe`);
  }
});

test("maps every live grant role to its access tier in both body forms", async () => {
  const policy = parsePolicy(policyFixture());
  const privateKey = testPrivateKey();
  for (const [permissions, role, access] of [
    [{ admin: false, maintain: false, pull: true, push: false, triage: false }, "read", "read"],
    [{ admin: false, maintain: false, pull: true, push: false, triage: true }, "triage", "read"],
    [{ admin: false, maintain: false, pull: true, push: true, triage: true }, "write", "write"],
    [{ admin: false, maintain: true, pull: true, push: true, triage: true }, "maintain", "write"],
    [{ admin: true, maintain: true, pull: true, push: true, triage: true }, "admin", "write"],
  ]) {
    for (const target of [{ repository: "example-org/alpha" }, { repository_id: 3001 }]) {
      const calls = [];
      const github = createGithubClient({
        appId: "42",
        privateKey,
        fetchImpl: teamGrantFetch({
          calls,
          grant: { id: 3001, full_name: "example-org/alpha", owner: { id: 1001, login: "example-org" }, permissions },
        }),
      });
      const grant = await github.verifyTeamGrant(policy, policy.workspaces[0], target);
      assert.deepEqual([grant.role, grant.access, grant.repository_id, grant.full_name], [role, access, 3001, "example-org/alpha"], role);
      // The tier comes from the same single grant read through the revoked probe; nothing else is read.
      assert.deepEqual(calls[0].body, { permissions: PROBE_PERMISSIONS });
      assert.equal(calls.at(-1).method, "DELETE");
      assert.equal(calls.filter(({ path }) => path.includes("/team/4001/repos/")).length, 1);
    }
  }
});

test("distinguishes Team grant outages from refusals", async () => {
  const policy = parsePolicy(policyFixture());
  const privateKey = testPrivateKey();

  const outage = createGithubClient({
    appId: "42",
    privateKey,
    fetchImpl: async (url, init) => {
      if (new URL(url).pathname === "/organizations/1001/team/4001") return jsonResponse({ message: "boom" }, 503);
      return teamGrantFetch()(url, init);
    },
  });
  await assert.rejects(
    () => outage.verifyTeamGrant(policy, policy.workspaces[0], { repository: "example-org/alpha" }),
    (error) => error.code === undefined && /HTTP 503/.test(error.message),
  );
});

test("mints only after a live Team grant and refuses with team_grant_missing otherwise", async () => {
  let mints = 0;
  let checks = 0;
  const server = createBrokerServer({
    policy: parsePolicy(policyFixture()),
    github: {
      verifyWorkspaceTeam: provenTeam,
      verifyTeamGrant: async (policy, workspace, target) => {
        checks += 1;
        assert.equal(workspace.github_team_id, 4001);
        assert.deepEqual(target, { repository: "example-org/alpha" });
        if (checks > 1) {
          const error = new Error("grant revoked");
          error.code = "team_grant_missing";
          throw error;
        }
        return grantedTeam(policy, workspace, target);
      },
      mintToken: async (_policy, repositoryId, access) => {
        mints += 1;
        assert.equal(checks, mints, "the Team grant must be verified before every mint");
        return {
          token: `ghs_synthetic_${repositoryId}_${mints}`,
          expires_at: "2030-01-01T00:00:00Z",
          repository_id: repositoryId,
          access,
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

/** Runs the real core client behind the Node server with a synthetic GitHub. */
async function withLiveCoreServer(fetchImpl, run) {
  const github = createGithubClient({ appId: "42", privateKey: testPrivateKey(), fetchImpl });
  const server = createBrokerServer({
    policy: parsePolicy(policyFixture()),
    github,
    readFile: (file) => secretByPath.get(file) ?? "",
    realpath: (file) => file,
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    await run(`http://127.0.0.1:${server.address().port}`);
  } finally {
    server.close();
    await once(server, "close");
  }
}

/** Synthetic GitHub that grants exactly the requested scoped permissions plus metadata: read. */
function mintingFetch(calls, teamFetch = teamGrantFetch(), scopedMints = []) {
  return async (url, init) => {
    const path = new URL(url).pathname;
    calls.push(`${init.method} ${path}`);
    if (path === "/app/installations/2001/access_tokens" && JSON.parse(init.body).repository_ids) {
      const { repository_ids: [repositoryId], permissions } = JSON.parse(init.body);
      scopedMints.push(permissions);
      return jsonResponse({
        token: `ghs_scoped_synthetic_${repositoryId}`,
        expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
        repositories: [{ id: repositoryId }],
        permissions: { ...permissions, metadata: "read" },
      });
    }
    return teamFetch(url, init);
  };
}

test("end to end: a Team-granted repository mints for its id; other Teams, repositories and owners mint nothing", async () => {
  const calls = [];
  await withLiveCoreServer(mintingFetch(calls), async (origin) => {
    for (const body of [{ repository: "example-org/alpha" }, { repository_id: 3001 }]) {
      const response = await request(origin, { body });
      assert.equal(response.status, 200);
      const json = await response.json();
      assert.equal(json.repository_id, 3001);
      assert.equal(json.repository, "example-org/alpha");
    }
    const mints = () => calls.filter((call) => call === "POST /app/installations/2001/access_tokens").length;
    const before = mints();

    // Cross-repository: alpha's Team holds no grant on beta.
    const crossRepository = await request(origin, { body: { repository: "example-org/beta" } });
    assert.equal(crossRepository.status, 403);
    assert.deepEqual(await crossRepository.json(), { error: "team_grant_missing" });

    // Cross-Workspace: beta's Team (4002) holds no grant on alpha, whatever alpha's Team holds.
    const crossWorkspace = await request(origin, {
      workspace: "beta-team",
      secret: secretByPath.get("/run/secrets/workspace-beta"),
    });
    assert.equal(crossWorkspace.status, 403);
    assert.deepEqual(await crossWorkspace.json(), { error: "team_grant_missing" });
    assert.ok(calls.includes("GET /organizations/1001/team/4002/repos/example-org/alpha"));

    // Foreign owner by id: GitHub resolves a public repository of another owner.
    const trafficBefore = calls.length;
    const foreignName = await request(origin, { body: { repository: "other-org/alpha" } });
    assert.equal(foreignName.status, 403);
    assert.equal(calls.length, trafficBefore, "a foreign owner name never reaches GitHub");

    // Every refusal minted only its revoked probe, never a scoped repository token.
    assert.equal(
      calls.filter((call) => call === "DELETE /installation/token").length,
      mints() - 2,
      "each probe is revoked; only the two accepted requests minted a scoped token",
    );
    assert.equal(before, 4);
  });
});

test("end to end: a pull or triage grant mints a read-tier token; push mints write; no grant mints nothing", async () => {
  const readGrant = (triage) => teamGrantFetch({
    grant: {
      id: 3001,
      full_name: "example-org/alpha",
      owner: { id: 1001, login: "example-org" },
      permissions: { admin: false, maintain: false, pull: true, push: false, triage },
    },
  });
  for (const triage of [false, true]) {
    const calls = [];
    const scopedMints = [];
    await withLiveCoreServer(mintingFetch(calls, readGrant(triage), scopedMints), async (origin) => {
      for (const body of [{ repository: "example-org/alpha" }, { repository_id: 3001 }]) {
        const response = await request(origin, { body });
        assert.equal(response.status, 200);
        const json = await response.json();
        assert.equal(json.access, "read");
        assert.equal(json.repository_id, 3001);
        assert.equal(json.repository, "example-org/alpha");
      }
      // The installation has not accepted issues: write, so the read tier asks for reads only.
      const readSet = { actions: "read", checks: "read", contents: "read", members: "read", pull_requests: "read" };
      assert.deepEqual(scopedMints, [readSet, readSet]);

      // Cross-Workspace: beta's Team holds nothing on alpha, whatever alpha's Team holds.
      const crossWorkspace = await request(origin, {
        workspace: "beta-team",
        secret: secretByPath.get("/run/secrets/workspace-beta"),
      });
      assert.equal(crossWorkspace.status, 403);
      assert.deepEqual(await crossWorkspace.json(), { error: "team_grant_missing" });
      assert.equal(scopedMints.length, 2);
    });
  }

  const writeMints = [];
  await withLiveCoreServer(mintingFetch([], teamGrantFetch(), writeMints), async (origin) => {
    const response = await request(origin);
    assert.equal((await response.json()).access, "write");
    assert.deepEqual(writeMints, [{ actions: "write", checks: "read", contents: "write", members: "read", pull_requests: "write" }]);
  });

  const noneMints = [];
  await withLiveCoreServer(mintingFetch([], teamGrantFetch({ grant: null }), noneMints), async (origin) => {
    const response = await request(origin);
    assert.equal(response.status, 403);
    assert.deepEqual(await response.json(), { error: "team_grant_missing" });
    assert.deepEqual(noneMints, []);
  });
});

test("end to end: an id of another owner is refused with repository_denied and mints nothing", async () => {
  const calls = [];
  const foreign = teamGrantFetch({
    repositories: { 9001: { id: 9001, full_name: "other-org/public", owner: { id: 1002, login: "other-org" } } },
  });
  await withLiveCoreServer(mintingFetch(calls, foreign), async (origin) => {
    const response = await request(origin, { body: { repository_id: 9001 } });
    assert.equal(response.status, 403);
    assert.deepEqual(await response.json(), { error: "repository_denied" });
    assert.equal(calls.filter((call) => call.startsWith("GET /organizations/1001/team/4001/repos/")).length, 0);
    assert.equal(calls.filter((call) => call === "POST /app/installations/2001/access_tokens").length, 1);
    assert.equal(calls.at(-1), "DELETE /installation/token");
  });
});

test("Team grant outages fail closed as token_unavailable and foreign owners never reach the gate", async () => {
  let checks = 0;
  await withServer(
    async (origin) => {
      const outage = await request(origin);
      assert.equal(outage.status, 502);
      assert.deepEqual(await outage.json(), { error: "token_unavailable" });
      assert.equal(checks, 1);

      const denied = await request(origin, { body: { repository: "other-org/alpha" } });
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

test("refuses a mint whose result names another repository than the Team gate verified", async () => {
  await withServer(
    async (origin) => {
      const response = await request(origin);
      assert.equal(response.status, 502);
      assert.deepEqual(await response.json(), { error: "token_unavailable" });
    },
    async () => ({ token: "ghs_synthetic_other", expires_at: "2030-01-01T00:00:00Z", repository_id: 3002 }),
  );
});

test("policy check --live lists live Team grants as information and fails only on Team drift", async () => {
  const policy = parsePolicy(policyFixture());
  assert.equal(
    formatPolicySummary(policy),
    [
      "lazurio.github_app_broker.policy.v3 owner=example-org installation=2001",
      "write tier (push/maintain/admin grant) asks for: actions=write checks=read contents=write members=read pull_requests=write",
      "read tier (pull/triage grant) asks for: actions=read checks=read contents=read members=read pull_requests=read",
      "WORKSPACE   TEAM_ID  TEAM_SLUG",
      "alpha-team  4001     alpha-team",
      "beta-team   4002     -",
      "",
    ].join("\n"),
  );

  const probes = [];
  const rowsFor = {
    "alpha-team": [
      { workspace_id: "alpha-team", github_team_id: 4001, github_team_slug: "alpha-team", repository_id: 3001, full_name: "example-org/alpha", role: "write", access: "write", status: "ok", detail: "" },
      { workspace_id: "alpha-team", github_team_id: 4001, github_team_slug: "alpha-team", repository_id: 3003, full_name: "example-org/gamma", role: "admin", access: "write", status: "ok", detail: "" },
      { workspace_id: "alpha-team", github_team_id: 4001, github_team_slug: "alpha-team", repository_id: 3004, full_name: "example-org/handbook", role: "read", access: "read", status: "ok", detail: "" },
    ],
    "beta-team": [
      { workspace_id: "beta-team", github_team_id: 4002, github_team_slug: "?", repository_id: "-", full_name: "-", role: "-", access: "-", status: "refused", detail: "Workspace beta-team GitHub Team 4002 no longer exists in the Organization" },
    ],
  };
  const github = {
    verifyPolicy: async () => probes.push("verify"),
    readWorkspaceTeamGrants: async (_policy, workspace) => {
      probes.push(`grants:${workspace.id}`);
      return rowsFor[workspace.id];
    },
  };
  const result = await checkPolicyLive({ policy, github });
  assert.deepEqual(probes, ["verify", "grants:alpha-team", "grants:beta-team"]);
  assert.equal(result.ok, false);
  const table = formatPolicyCheckTable(result.rows);
  assert.equal(
    table,
    [
      "WORKSPACE   TEAM_ID  TEAM_SLUG   REPOSITORY_ID  REPOSITORY            ROLE   ACCESS  STATUS   DETAIL",
      "alpha-team  4001     alpha-team  3001           example-org/alpha     write  write   ok",
      "alpha-team  4001     alpha-team  3003           example-org/gamma     admin  write   ok",
      "alpha-team  4001     alpha-team  3004           example-org/handbook  read   read    ok",
      "beta-team   4002     ?           -              -                     -      -       refused  Workspace beta-team GitHub Team 4002 no longer exists in the Organization",
      "2 Workspaces checked, 1 Teams ok, 1 refused; 3 repository grants (2 write, 1 read)",
      "",
    ].join("\n"),
  );
  assert.doesNotMatch(table, /ghs_|secret/i);

  rowsFor["beta-team"] = [
    { workspace_id: "beta-team", github_team_id: 4002, github_team_slug: "beta", repository_id: "-", full_name: "-", role: "-", access: "-", status: "ok", detail: "Team holds no repository grant" },
  ];
  const healthy = await checkPolicyLive({ policy, github });
  assert.equal(healthy.ok, true, "a Team without grants is information, not drift");
  assert.match(formatPolicyCheckTable(healthy.rows), /2 Workspaces checked, 2 Teams ok, 0 refused; 3 repository grants \(2 write, 1 read\)/);

  const failedInstallation = { ...github, verifyPolicy: async () => { throw new Error("live GitHub installation identity, selection or permissions differ from policy"); } };
  await assert.rejects(() => checkPolicyLive({ policy, github: failedInstallation }), /differ from policy/);
});

test("readWorkspaceTeamGrants paginates the Team's repository grants with their tier and one probe", async () => {
  const policy = parsePolicy(policyFixture());
  const calls = [];
  const writable = { admin: false, maintain: false, pull: true, push: true, triage: true };
  const firstPage = Array.from({ length: 100 }, (_, index) => ({
    id: 5000 + index,
    full_name: `example-org/repo-${index}`,
    owner: { id: 1001, login: "example-org" },
    permissions: index === 0 ? { admin: false, maintain: false, pull: true, push: false, triage: true } : writable,
  }));
  const secondPage = [
    { id: 3001, full_name: "example-org/alpha", owner: { id: 1001, login: "example-org" }, permissions: { ...writable, maintain: true } },
    { id: 9001, full_name: "other-org/foreign", owner: { id: 1002, login: "other-org" }, permissions: writable },
    { id: 3002, full_name: "example-org/beta", owner: { id: 1001, login: "example-org" }, permissions: { pull: true } },
    { id: 3005, full_name: "example-org/none", owner: { id: 1001, login: "example-org" }, permissions: { pull: false } },
  ];
  const fetchImpl = async (url, init) => {
    const path = new URL(url).pathname + new URL(url).search;
    calls.push(`${init.method} ${path}`);
    if (path === "/app/installations/2001/access_tokens") {
      assert.deepEqual(JSON.parse(init.body), { permissions: PROBE_PERMISSIONS });
      return jsonResponse({ token: "ghs_team_probe" });
    }
    if (path === "/organizations/1001/team/4001") {
      return jsonResponse({ id: 4001, slug: "alpha-team", organization: { id: 1001, login: "example-org" } });
    }
    if (path === "/organizations/1001/team/4001/repos?per_page=100&page=1") return jsonResponse(firstPage);
    if (path === "/organizations/1001/team/4001/repos?per_page=100&page=2") return jsonResponse(secondPage);
    if (path === "/organizations/1001/team/4002") return jsonResponse({ id: 4002, slug: "beta", organization: { id: 1001, login: "example-org" } });
    if (path === "/organizations/1001/team/4002/repos?per_page=100&page=1") return jsonResponse([]);
    if (path === "/installation/token") return jsonResponse(null, 204);
    throw new Error(`unexpected request ${init.method} ${path}`);
  };
  const github = createGithubClient({ appId: "42", privateKey: testPrivateKey(), fetchImpl });

  const alpha = await github.readWorkspaceTeamGrants(policy, policy.workspaces[0]);
  assert.equal(alpha.length, 102, "100 grants from page one plus alpha and beta; foreign and grant-less rows are skipped");
  assert.deepEqual(alpha.at(-2), {
    workspace_id: "alpha-team",
    github_team_id: 4001,
    github_team_slug: "alpha-team",
    repository_id: 3001,
    full_name: "example-org/alpha",
    role: "maintain",
    access: "write",
    status: "ok",
    detail: "",
  });
  assert.deepEqual(
    alpha.filter(({ access }) => access === "read").map(({ repository_id, role }) => [repository_id, role]),
    [[5000, "triage"], [3002, "read"]],
  );
  assert.equal(alpha.filter(({ access }) => access === "write").length, 100);
  assert.equal(alpha.some(({ repository_id }) => repository_id === 9001 || repository_id === 3005), false);
  assert.equal(calls.filter((call) => call === "POST /app/installations/2001/access_tokens").length, 1);
  assert.equal(calls.at(-1), "DELETE /installation/token");

  const beta = await github.readWorkspaceTeamGrants(policy, policy.workspaces[1]);
  assert.deepEqual(beta.map(({ repository_id, status, detail }) => [repository_id, status, detail]), [
    ["-", "ok", "Team holds no repository grant"],
  ]);
});

test("readWorkspaceTeamGrants reports a missing Team as one refused row without listing repositories", async () => {
  const policy = parsePolicy(policyFixture());
  const calls = [];
  const fetchImpl = async (url, init) => {
    const path = new URL(url).pathname + new URL(url).search;
    calls.push(`${init.method} ${path}`);
    if (path === "/app/installations/2001/access_tokens") return jsonResponse({ token: "ghs_team_probe" });
    if (path === "/organizations/1001/team/4002") return jsonResponse({ message: "Not Found" }, 404);
    if (path === "/installation/token") return jsonResponse(null, 204);
    throw new Error(`unexpected request ${init.method} ${path}`);
  };
  const github = createGithubClient({ appId: "42", privateKey: testPrivateKey(), fetchImpl });
  const rows = await github.readWorkspaceTeamGrants(policy, policy.workspaces[1]);
  assert.deepEqual(rows.map(({ github_team_slug, status }) => [github_team_slug, status]), [["?", "refused"]]);
  assert.match(rows[0].detail, /Team 4002 no longer exists/);
  assert.deepEqual(calls, [
    "POST /app/installations/2001/access_tokens",
    "GET /organizations/1001/team/4002",
    "DELETE /installation/token",
  ]);
});

function workspaceRequest(origin, {
  workspace = "alpha-team",
  secret = secretByPath.get("/run/secrets/workspace-alpha"),
} = {}) {
  return fetch(`${origin}/v1/workspace`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${secret}`,
      "Content-Type": "application/json",
      "X-Lazurio-Workspace-ID": workspace,
    },
    body: "{}",
  });
}

test("POST /v1/workspace proves the live Workspace Team through a revoked probe and mints no token", async () => {
  const calls = [];
  await withLiveCoreServer(mintingFetch(calls), async (origin) => {
    const response = await workspaceRequest(origin);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.deepEqual(await response.json(), {
      workspace_id: "alpha-team",
      organization: "example-org",
      github_team_id: 4001,
      github_team_slug: "alpha-team",
    });
    assert.deepEqual(calls, [
      "POST /app/installations/2001/access_tokens",
      "GET /organizations/1001/team/4001",
      "DELETE /installation/token",
    ]);
  });
});

test("POST /v1/workspace refuses bad credentials without GitHub traffic and a drifted Team with 403", async () => {
  const calls = [];
  const drifted = teamGrantFetch({ team: { id: 4001, slug: "renamed-team", organization: { id: 1001, login: "example-org" } } });
  await withLiveCoreServer(mintingFetch(calls, drifted), async (origin) => {
    for (const options of [
      { secret: "wrong-secret-value-with-at-least-32-bytes" },
      { workspace: "unknown-team", secret: "unknown-secret-value-with-at-least-32-bytes" },
      { workspace: "beta-team", secret: secretByPath.get("/run/secrets/workspace-alpha") },
    ]) {
      const response = await workspaceRequest(origin, options);
      assert.equal(response.status, 401);
      assert.deepEqual(await response.json(), { error: "workspace_unauthorized" });
    }
    assert.equal(calls.length, 0);

    const refused = await workspaceRequest(origin);
    assert.equal(refused.status, 403);
    assert.deepEqual(await refused.json(), { error: "team_grant_missing" });
    assert.deepEqual(calls, [
      "POST /app/installations/2001/access_tokens",
      "GET /organizations/1001/team/4001",
      "DELETE /installation/token",
    ]);
  });

  const missing = [];
  await withLiveCoreServer(mintingFetch(missing, teamGrantFetch({ team: null })), async (origin) => {
    const response = await workspaceRequest(origin);
    assert.equal(response.status, 403);
    assert.deepEqual(await response.json(), { error: "team_grant_missing" });
    assert.equal(missing.at(-1), "DELETE /installation/token");
  });
});

test("POST /v1/workspace fails closed as token_unavailable on a GitHub outage and never reads repositories", async () => {
  const calls = [];
  const outage = async (url, init) => {
    if (new URL(url).pathname === "/organizations/1001/team/4001") return jsonResponse({ message: "boom" }, 503);
    return teamGrantFetch()(url, init);
  };
  await withLiveCoreServer(mintingFetch(calls, outage), async (origin) => {
    const response = await workspaceRequest(origin);
    assert.equal(response.status, 502);
    assert.deepEqual(await response.json(), { error: "token_unavailable" });
    assert.equal(calls.some((call) => call.includes("/repos") || call.startsWith("GET /repositories")), false);
    assert.equal(calls.filter((call) => call === "POST /app/installations/2001/access_tokens").length, 1);
    assert.equal(calls.at(-1), "DELETE /installation/token");
  });
});

test("POST /v1/workspace is not a token route: it rejects other methods, media types and paths", async () => {
  await withServer(async (origin) => {
    assert.equal((await fetch(`${origin}/v1/workspace`)).status, 404);
    assert.equal((await fetch(`${origin}/v1/workspace/extra`, { method: "POST" })).status, 404);
    const unsupported = await fetch(`${origin}/v1/workspace`, {
      method: "POST",
      headers: { "Content-Type": "text/plain", "X-Lazurio-Workspace-ID": "alpha-team" },
      body: "{}",
    });
    assert.equal(unsupported.status, 415);
    const proof = await (await workspaceRequest(origin)).json();
    assert.equal("token" in proof, false);
  });
});
