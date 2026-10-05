// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";

import * as brokerClient from "../adapter/broker-client.mjs";
import {
  normalizeRepository,
  parseBrokerClientConfig,
  repositoryIdentityKey,
  requestGitHubAppToken,
  requestWorkspaceProof,
  requireHttpsGitHubOrigin,
} from "../adapter/broker-client.mjs";
import {
  assertReadOnlyGhConfigDirectory,
  brokeredGhEnvironment,
  classifyGhCommand,
  HOSTED_GITHUB_ACTOR,
  READ_ONLY_GH_CONFIG_DIR,
  readAccessNotice,
  resolveGhRepository,
  runBrokeredGh,
  uncredentialedGhEnvironment,
} from "../adapter/brokered-gh.mjs";

const TOKEN = "ghs_secret_token_that_must_never_be_rendered";
const NOW = Date.parse("2026-08-18T12:00:00Z");
const environment = {
  GITHUB_TOKEN_BROKER_URL: "http://github-token-broker:8787",
  GITHUB_BROKER_WORKSPACE_ID: "example-management",
  GITHUB_BROKER_CLIENT_CREDENTIAL_FILE: "/run/secrets/github_broker_client_token",
};

function response(body, { ok = true } = {}) {
  return { ok, json: async () => body };
}

function validToken(repositoryId = 101, repository = "Example/Alpha") {
  return {
    token: TOKEN,
    repository_id: repositoryId,
    repository,
    expires_at: "2026-08-18T13:00:00Z",
  };
}

test("normalizes repository coordinates and holds no client-side repository policy", () => {
  assert.equal(normalizeRepository("https://github.com/Example/Alpha.git"), "Example/Alpha");
  assert.equal(repositoryIdentityKey("github.com/Example/Alpha"), "example/alpha");
  assert.equal(requireHttpsGitHubOrigin("https://github.com/Example/Alpha.git"), "Example/Alpha");
  assert.throws(() => requireHttpsGitHubOrigin("git@github.com:Example/Alpha.git"), /brokered HTTPS/);
  assert.equal("parseRepositoryPolicy" in brokerClient, false);
  assert.equal("firstPolicyRepository" in brokerClient, false);
});

test("accepts only the exact T3 discovery and viewer envelopes", () => {
  assert.equal(classifyGhCommand(["auth", "status", "--json", "hosts"], environment), "auth-status");
  assert.equal(classifyGhCommand(["api", "user", "--jq", ".login"], environment), "viewer-login");
  for (const args of [
    ["auth", "status", "hosts", "--json"],
    ["auth", "status", "--json", "hosts", "--active"],
    ["auth", "status", "--json", "hosts", "--show-token"],
    ["auth", "status", "--hostname", "github.com", "--json", "hosts"],
    ["auth", "status", "-t"],
    ["auth", "token"],
    ["config", "get", "git_protocol"],
    ["alias", "set", "leak", "!env"],
    ["extension", "install", "owner/repo"],
    ["search", "prs", "example"],
  ]) {
    assert.equal(classifyGhCommand(args, environment), "denied", args.join(" "));
  }
  assert.equal(classifyGhCommand(["pr", "list", "--help"], environment), "local");
  assert.equal(classifyGhCommand(["pr", "list"], environment), "repository");
  assert.equal(
    classifyGhCommand(
      ["run", "rerun", "33188102618", "--repo", "Example/Alpha"],
      environment,
    ),
    "repository",
  );
  assert.equal(
    classifyGhCommand(["api", "graphql", "--hostname", "github.com", "--input", "-"], environment),
    "repository",
  );
  assert.equal(
    classifyGhCommand(["pr", "view", "1", "--hostname=github.com"], environment),
    "repository",
  );
  for (const args of [
    ["api", "graphql", "--hostname"],
    ["api", "graphql", "--hostname", "github.example"],
    ["api", "graphql", "--hostname=github.example"],
  ]) {
    assert.equal(classifyGhCommand(args, environment), "denied", args.join(" "));
  }
  assert.equal(
    classifyGhCommand(["pr", "view", "https://github.example/Example/Alpha/pull/1"], environment),
    "denied",
  );
});

test("requests one fresh repo-scoped token by name without exposing the Workspace credential", async () => {
  let captured;
  const result = await requestGitHubAppToken({
    repository: "example/alpha",
    // A leftover v0.9.0 client policy is ignored: it neither widens nor narrows the request.
    environment: { ...environment, GITHUB_REPOSITORY_POLICY_JSON: JSON.stringify({ "Example/Bravo": 202 }) },
    readFile: () => "workspace-credential-with-at-least-32-bytes",
    fetchImpl: async (url, options) => {
      captured = { url, options };
      return response(validToken());
    },
    now: () => NOW,
  });
  assert.deepEqual({ ...result }, {
    token: TOKEN,
    repository: "Example/Alpha",
    repositoryId: 101,
    expiresAt: "2026-08-18T13:00:00Z",
    // A broker before 0.11.0 sends no tier; it minted only for write-capable grants.
    access: "write",
  });
  assert.equal(captured.url, "http://github-token-broker:8787/v1/token");
  assert.deepEqual(JSON.parse(captured.options.body), { repository: "example/alpha" });
  assert.equal(captured.options.headers["X-Lazurio-Workspace-ID"], "example-management");
  assert.equal(captured.options.headers.Authorization.startsWith("Bearer "), true);
});

test("uses only a controller-pinned HTTPS broker origin for remote Workspaces", async () => {
  const remoteOrigin = "https://github-broker.lazurio.example";
  const remoteEnvironment = {
    ...environment,
    GITHUB_TOKEN_BROKER_URL: remoteOrigin,
  };
  const reads = [];
  let requestedUrl;
  const result = await requestGitHubAppToken({
    repository: "Example/Alpha",
    environment: remoteEnvironment,
    readFile: (path) => {
      reads.push(path);
      if (path === "/run/config/github_broker_client.json") {
        return JSON.stringify({
          schema_version: "lazurio.github_broker_client.v1",
          origin: remoteOrigin,
        });
      }
      if (path === "/run/secrets/github_broker_client_token") {
        return "workspace-credential-with-at-least-32-bytes";
      }
      throw new Error("unexpected path");
    },
    exists: (path) => path === "/run/config/github_broker_client.json",
    fetchImpl: async (url) => {
      requestedUrl = url;
      return response(validToken());
    },
    now: () => NOW,
  });
  assert.equal(result.repositoryId, 101);
  assert.equal(requestedUrl, `${remoteOrigin}/v1/token`);
  assert.deepEqual(reads, [
    "/run/config/github_broker_client.json",
    "/run/secrets/github_broker_client_token",
  ]);
});

test("remote broker config rejects endpoint substitution and unsafe origins", async () => {
  const remoteEnvironment = {
    ...environment,
    GITHUB_TOKEN_BROKER_URL: "https://attacker.invalid",
  };
  await assert.rejects(
    () => requestGitHubAppToken({
      repository: "Example/Alpha",
      environment: remoteEnvironment,
      readFile: (path) => path.endsWith(".json")
        ? JSON.stringify({
            schema_version: "lazurio.github_broker_client.v1",
            origin: "https://github-broker.lazurio.example",
          })
        : "workspace-credential-with-at-least-32-bytes",
      exists: (path) => path === "/run/config/github_broker_client.json",
      fetchImpl: async () => response(validToken()),
      now: () => NOW,
    }),
    /endpoint is invalid/,
  );
  for (const origin of [
    "http://broker.example",
    "https://localhost",
    "https://127.0.0.1",
    "https://10.0.0.1",
    "https://169.254.169.254",
    "https://192.168.1.1",
    "https://user@broker.example",
    "https://broker.example/path",
    "https://broker.example/",
    "http://github-token-broker:8787",
  ]) {
    assert.throws(
      () => parseBrokerClientConfig(JSON.stringify({
        schema_version: "lazurio.github_broker_client.v1",
        origin,
      })),
      /config is invalid/,
      origin,
    );
  }
});

test("a mounted remote config cannot be bypassed by removing environment fields", async () => {
  await assert.rejects(
    () => requestGitHubAppToken({
      repository: "Example/Alpha",
      environment,
      exists: (path) => path === "/run/config/github_broker_client.json",
      readFile: (path) => path.endsWith(".json")
        ? JSON.stringify({
            schema_version: "lazurio.github_broker_client.v1",
            origin: "https://github-broker.lazurio.example",
          })
        : "workspace-credential-with-at-least-32-bytes",
      fetchImpl: async () => response(validToken()),
      now: () => NOW,
    }),
    /endpoint is invalid/,
  );
});

test("rejects a broker response for another repository or without a canonical identity", async () => {
  const shared = {
    repository: "Example/Alpha",
    environment,
    readFile: () => "workspace-credential-with-at-least-32-bytes",
    now: () => NOW,
  };
  for (const body of [
    validToken(202, "Example/Bravo"),
    validToken(101, "Other/Alpha"),
    validToken(101, "https://github.com/Example/Alpha"),
    validToken(101, "Example/Alpha.git"),
    { ...validToken(), repository: undefined },
    validToken(0),
    validToken(-1),
    validToken("101"),
    { ...validToken(), repository_id: undefined },
    { ...validToken(), expires_at: "2026-08-18T14:30:00Z" },
  ]) {
    await assert.rejects(
      () => requestGitHubAppToken({ ...shared, fetchImpl: async () => response(body) }),
      /invalid scoped response/,
      JSON.stringify(body),
    );
  }
});

test("reports the access tier the broker minted and rejects an unknown tier", async () => {
  const shared = {
    repository: "Example/Alpha",
    environment,
    readFile: () => "workspace-credential-with-at-least-32-bytes",
    now: () => NOW,
  };
  for (const access of ["read", "write"]) {
    const result = await requestGitHubAppToken({
      ...shared,
      fetchImpl: async () => response({ ...validToken(), access }),
    });
    assert.equal(result.access, access);
    assert.equal(result.token, TOKEN);
  }
  for (const access of [null, "", "admin", "READ", 1]) {
    await assert.rejects(
      () => requestGitHubAppToken({ ...shared, fetchImpl: async () => response({ ...validToken(), access }) }),
      /invalid scoped response/,
      JSON.stringify(access),
    );
  }
});

test("broker refusal, timeout and malformed response fail closed", async () => {
  const shared = {
    repository: "Example/Alpha",
    environment,
    readFile: () => "workspace-credential-with-at-least-32-bytes",
    now: () => NOW,
  };
  await assert.rejects(
    () => requestGitHubAppToken({ ...shared, fetchImpl: async () => response({}, { ok: false }) }),
    /refused/,
  );
  await assert.rejects(
    () => requestGitHubAppToken({ ...shared, fetchImpl: async () => { throw new Error(TOKEN); } }),
    /unavailable/,
  );
  await assert.rejects(
    () => requestGitHubAppToken({ ...shared, fetchImpl: async () => response({ token: TOKEN }) }),
    /invalid scoped response/,
  );
});

test("auth status performs an uncached live proof and emits the official host schema", async () => {
  const stdout = [];
  const stderr = [];
  let proofs = 0;
  const input = {
    args: ["auth", "status", "--json", "hosts"],
    environment,
    readOrigin: () => "https://github.com/Example/Alpha.git",
    requestToken: async ({ repository }) => {
      proofs += 1;
      assert.equal(repository, "Example/Alpha");
      if (proofs === 2) throw new Error(TOKEN);
      return { token: TOKEN };
    },
    writeStdout: (value) => stdout.push(value),
    writeStderr: (value) => stderr.push(value),
  };
  assert.equal(await runBrokeredGh(input), 0);
  const status = JSON.parse(stdout.at(-1));
  assert.equal(status.hosts["github.com"][0].state, "success");
  assert.equal(status.hosts["github.com"][0].active, true);
  assert.equal(status.hosts["github.com"][0].login, HOSTED_GITHUB_ACTOR);
  assert.equal(JSON.stringify(status).includes(TOKEN), false);

  assert.equal(await runBrokeredGh(input), 1);
  assert.deepEqual(JSON.parse(stdout.at(-1)), { hosts: {} });
  assert.equal(stderr.at(-1), "Brokered gh authentication proof failed.\n");
  assert.equal(`${stdout.join("")} ${stderr.join("")}`.includes(TOKEN), false);
});

test("the exact viewer probe reports the machine actor only after a live proof", async () => {
  const stdout = [];
  let calls = 0;
  assert.equal(
    await runBrokeredGh({
      args: ["api", "user", "--jq", ".login"],
      environment: { ...environment, GH_REPO: "Example/Bravo" },
      readOrigin: () => null,
      requestToken: async ({ repository }) => {
        calls += 1;
        assert.equal(repository, "Example/Bravo");
        return { token: TOKEN };
      },
      writeStdout: (value) => stdout.push(value),
    }),
    0,
  );
  assert.equal(calls, 1);
  assert.deepEqual(stdout, [`${HOSTED_GITHUB_ACTOR}\n`]);
});

const WORKSPACE_PROOF = {
  workspace_id: "example-management",
  organization: "Example",
  github_team_id: 4001,
  github_team_slug: "management",
};

function brokerStub(status, body) {
  const requests = [];
  return {
    requests,
    fetchImpl: async (url, options) => {
      requests.push({ url, options });
      return { ok: status >= 200 && status < 300, status, json: async () => body };
    },
  };
}

test("requestWorkspaceProof posts to /v1/workspace with the pinned identity and returns the Team", async () => {
  const stub = brokerStub(200, WORKSPACE_PROOF);
  const proof = await requestWorkspaceProof({
    environment,
    readFile: () => "workspace-credential-with-at-least-32-bytes",
    fetchImpl: stub.fetchImpl,
  });
  assert.deepEqual({ ...proof }, {
    workspaceId: "example-management",
    organization: "Example",
    githubTeamId: 4001,
    githubTeamSlug: "management",
  });
  assert.equal(stub.requests.length, 1);
  assert.equal(stub.requests[0].url, "http://github-token-broker:8787/v1/workspace");
  assert.equal(stub.requests[0].options.method, "POST");
  assert.deepEqual(JSON.parse(stub.requests[0].options.body), {});
  assert.equal(stub.requests[0].options.headers["X-Lazurio-Workspace-ID"], "example-management");
  assert.ok(stub.requests[0].options.signal);

  // The same pinned remote-origin and credential-path validation as the token request.
  await assert.rejects(
    () => requestWorkspaceProof({
      environment: { ...environment, GITHUB_TOKEN_BROKER_URL: "https://attacker.invalid" },
      readFile: () => "workspace-credential-with-at-least-32-bytes",
      fetchImpl: stub.fetchImpl,
    }),
    /endpoint is invalid/,
  );
  await assert.rejects(
    () => requestWorkspaceProof({
      environment: { ...environment, GITHUB_BROKER_CLIENT_CREDENTIAL_FILE: "/tmp/credential" },
      readFile: () => "workspace-credential-with-at-least-32-bytes",
      fetchImpl: stub.fetchImpl,
    }),
    /credential path is invalid/,
  );
  assert.equal(stub.requests.length, 1);
});

test("requestWorkspaceProof fails closed on refusals, outages and foreign or token-bearing answers", async () => {
  const shared = { environment, readFile: () => "workspace-credential-with-at-least-32-bytes" };
  for (const [status, body] of [
    [401, { error: "workspace_unauthorized" }],
    [403, { error: "team_grant_missing" }],
    [502, { error: "token_unavailable" }],
  ]) {
    await assert.rejects(
      () => requestWorkspaceProof({ ...shared, fetchImpl: brokerStub(status, body).fetchImpl }),
      /refused/,
      String(status),
    );
  }
  await assert.rejects(
    () => requestWorkspaceProof({ ...shared, fetchImpl: async () => { throw new Error(TOKEN); } }),
    /unavailable/,
  );
  for (const body of [
    { ...WORKSPACE_PROOF, workspace_id: "other-workspace" },
    { ...WORKSPACE_PROOF, github_team_id: 0 },
    { ...WORKSPACE_PROOF, github_team_slug: "" },
    { ...WORKSPACE_PROOF, organization: "not an org" },
    { ...WORKSPACE_PROOF, token: TOKEN },
    null,
  ]) {
    await assert.rejects(
      () => requestWorkspaceProof({ ...shared, fetchImpl: brokerStub(200, body).fetchImpl }),
      /invalid Workspace proof/,
      JSON.stringify(body),
    );
  }
});

test("from the Folder root the discovery proofs use /v1/workspace and mint no repository token", async () => {
  const stdout = [];
  let tokenRequests = 0;
  let workspaceProofs = 0;
  const shared = {
    environment,
    readOrigin: () => null,
    requestToken: async () => {
      tokenRequests += 1;
      return { token: TOKEN };
    },
    requestWorkspace: async ({ environment: proofEnvironment }) => {
      workspaceProofs += 1;
      assert.equal(proofEnvironment, environment);
      return WORKSPACE_PROOF;
    },
    writeStdout: (value) => stdout.push(value),
    writeStderr: () => {},
  };
  assert.equal(await runBrokeredGh({ ...shared, args: ["auth", "status", "--json", "hosts"] }), 0);
  const status = JSON.parse(stdout.at(-1));
  assert.equal(status.hosts["github.com"][0].state, "success");
  assert.equal(status.hosts["github.com"][0].login, HOSTED_GITHUB_ACTOR);
  assert.equal(await runBrokeredGh({ ...shared, args: ["api", "user", "--jq", ".login"] }), 0);
  assert.equal(stdout.at(-1), `${HOSTED_GITHUB_ACTOR}\n`);
  assert.equal(workspaceProofs, 2);
  assert.equal(tokenRequests, 0);
});

test("from the Folder root a refused or unavailable Workspace proof fails closed", async () => {
  for (const [status, body] of [
    [401, { error: "workspace_unauthorized" }],
    [403, { error: "team_grant_missing" }],
    [502, { error: "token_unavailable" }],
  ]) {
    const stub = brokerStub(status, body);
    const stdout = [];
    const stderr = [];
    const shared = {
      environment,
      readOrigin: () => null,
      requestToken: async () => {
        throw new Error("must not mint a repository token from the Folder root");
      },
      requestWorkspace: (options) => requestWorkspaceProof({
        ...options,
        readFile: () => "workspace-credential-with-at-least-32-bytes",
        exists: () => false,
        fetchImpl: stub.fetchImpl,
      }),
      writeStdout: (value) => stdout.push(value),
      writeStderr: (value) => stderr.push(value),
    };
    assert.equal(await runBrokeredGh({ ...shared, args: ["auth", "status", "--json", "hosts"] }), 1, String(status));
    assert.deepEqual(JSON.parse(stdout.at(-1)), { hosts: {} });
    assert.equal(stderr.at(-1), "Brokered gh authentication proof failed.\n");
    await assert.rejects(
      () => runBrokeredGh({ ...shared, args: ["api", "user", "--jq", ".login"] }),
      /identity proof failed/,
    );
    assert.deepEqual(stub.requests.map(({ url }) => url), [
      "http://github-token-broker:8787/v1/workspace",
      "http://github-token-broker:8787/v1/workspace",
    ]);
  }
});

test("inside a checkout the discovery proof stays the repository mint and never falls back", async () => {
  let workspaceProofs = 0;
  const stdout = [];
  const exitCode = await runBrokeredGh({
    args: ["auth", "status", "--json", "hosts"],
    environment,
    readOrigin: () => "https://github.com/Example/Alpha.git",
    requestToken: async () => {
      throw new Error("team_grant_missing");
    },
    requestWorkspace: async () => {
      workspaceProofs += 1;
      return WORKSPACE_PROOF;
    },
    writeStdout: (value) => stdout.push(value),
    writeStderr: () => {},
  });
  assert.equal(exitCode, 1);
  assert.deepEqual(JSON.parse(stdout.at(-1)), { hosts: {} });
  assert.equal(workspaceProofs, 0);
});

test("repository operations accept T3 lowercase identity and pass only an env-local token", async () => {
  let child;
  const exitCode = await runBrokeredGh({
    args: ["pr", "list", "--repo", "github.com/example/alpha", "--hostname", "github.com"],
    environment: {
      ...environment,
      GITHUB_TOKEN: "ambient-personal-token",
      GH_TOKEN: "ambient-stale-token",
      PAGER: "secret-pager",
      GH_BROWSER: "secret-browser",
      BROWSER: "secret-browser",
      GH_EDITOR: "secret-editor",
      EDITOR: "secret-editor",
      GH_FORCE_TTY: "100%",
      GH_HTTP_UNIX_SOCKET: "/tmp/untrusted.sock",
      HTTPS_PROXY: "http://untrusted.invalid:8080",
      https_proxy: "http://untrusted.invalid:8080",
    },
    readOrigin: () => "https://github.com/Example/Alpha.git",
    requestToken: async ({ repository }) => {
      assert.equal(repository, "Example/Alpha");
      return { token: TOKEN };
    },
    assertConfigDirectory: () => {},
    runRealGh: (args, childEnvironment) => {
      child = { args, environment: childEnvironment };
      return 0;
    },
  });
  assert.equal(exitCode, 0);
  assert.deepEqual(child.args, [
    "pr",
    "list",
    "--repo",
    "github.com/example/alpha",
    "--hostname",
    "github.com",
  ]);
  assert.equal(child.args.includes(TOKEN), false);
  assert.equal(child.environment.GH_TOKEN, TOKEN);
  assert.equal(child.environment.GITHUB_TOKEN, undefined);
  assert.equal(child.environment.GH_PAGER, "cat");
  assert.equal(child.environment.PAGER, undefined);
  assert.equal(child.environment.GH_BROWSER, undefined);
  assert.equal(child.environment.BROWSER, undefined);
  assert.equal(child.environment.GH_EDITOR, undefined);
  assert.equal(child.environment.EDITOR, undefined);
  assert.equal(child.environment.GH_FORCE_TTY, undefined);
  assert.equal(child.environment.GH_HTTP_UNIX_SOCKET, undefined);
  assert.equal(child.environment.HTTPS_PROXY, undefined);
  assert.equal(child.environment.https_proxy, undefined);
  assert.equal(child.environment.GH_CONFIG_DIR, READ_ONLY_GH_CONFIG_DIR);
});

test("the gh allow-list refuses no repository command by access tier", () => {
  for (const args of [
    ["pr", "create", "--title", "t", "--body", "b"],
    ["pr", "merge", "1"],
    ["pr", "comment", "1", "--body", "b"],
    ["issue", "create", "--title", "t", "--body", "b"],
    ["issue", "list"],
    ["run", "rerun", "1"],
    ["repo", "view"],
    ["api", "repos/Example/Alpha/contents/README.md"],
    ["api", "-X", "POST", "repos/Example/Alpha/issues", "-f", "title=t"],
  ]) {
    assert.equal(classifyGhCommand(args, environment), "repository", args.join(" "));
  }
});

/** A requestToken that runs the real broker client against a stub broker answering `body`. */
function brokerClientAnswering(body, requests = []) {
  return (options) => requestGitHubAppToken({
    ...options,
    readFile: () => "workspace-credential-with-at-least-32-bytes",
    exists: () => false,
    fetchImpl: async (url, init) => {
      requests.push({ url, body: JSON.parse(init.body) });
      return response(body);
    },
    now: () => NOW,
  });
}

test("a read-tier token runs official gh; reads succeed silently and a refused write is explained", async () => {
  const readToken = { ...validToken(101, "Example/Alpha"), access: "read" };
  const children = [];
  const stderr = [];
  const run = (args, exitCode, body = readToken) => runBrokeredGh({
    args,
    environment,
    readOrigin: () => "https://github.com/Example/Alpha.git",
    requestToken: brokerClientAnswering(body),
    assertConfigDirectory: () => {},
    runRealGh: (childArgs, childEnvironment) => {
      children.push({ args: childArgs, token: childEnvironment.GH_TOKEN });
      return exitCode;
    },
    writeStderr: (value) => stderr.push(value),
  });

  // Reads and issue creation go to official gh with the read-tier token and add no output.
  assert.equal(await run(["issue", "create", "--title", "t", "--body", "b"], 0), 0);
  assert.equal(await run(["api", "repos/Example/Alpha", "--jq", ".full_name"], 0), 0);
  assert.deepEqual(stderr, []);

  // A pull request is not refused up front: official gh runs, GitHub refuses, the exit code
  // passes through and the adapter says why instead of looking like a broker outage.
  assert.equal(await run(["pr", "create", "--title", "t", "--body", "b"], 1), 1);
  assert.deepEqual(children.map(({ args }) => args[0]), ["issue", "api", "pr"]);
  assert.ok(children.every(({ token }) => token === TOKEN));
  assert.deepEqual(stderr, [readAccessNotice("Example/Alpha")]);
  assert.match(stderr[0], /read access to Example\/Alpha/);
  assert.match(stderr[0], /gh issue create/);
  assert.equal(stderr.join("").includes(TOKEN), false);

  // A write-tier failure, or one from a broker that reports no tier, stays official gh's own output.
  assert.equal(await run(["pr", "create"], 1, { ...validToken(), access: "write" }), 1);
  assert.equal(await run(["pr", "create"], 1, validToken()), 1);
  assert.equal(stderr.length, 1);
});

test("discovery inside a checkout succeeds with a read-tier repository proof", async () => {
  const stdout = [];
  const requests = [];
  assert.equal(
    await runBrokeredGh({
      args: ["auth", "status", "--json", "hosts"],
      environment,
      readOrigin: () => "https://github.com/Example/Alpha.git",
      requestToken: brokerClientAnswering({ ...validToken(), access: "read" }, requests),
      requestWorkspace: async () => {
        throw new Error("a checkout proof never falls back to the Workspace proof");
      },
      writeStdout: (value) => stdout.push(value),
      writeStderr: () => {},
    }),
    0,
  );
  assert.equal(JSON.parse(stdout.at(-1)).hosts["github.com"][0].state, "success");
  assert.deepEqual(requests.map(({ url, body }) => [url, body]), [
    ["http://github-token-broker:8787/v1/token", { repository: "Example/Alpha" }],
  ]);
});

test("denied commands cannot reach the broker or official gh", async () => {
  let brokerCalls = 0;
  let childCalls = 0;
  await assert.rejects(
    () =>
      runBrokeredGh({
        args: ["auth", "status", "--show-token"],
        environment,
        requestToken: async () => {
          brokerCalls += 1;
          return { token: TOKEN };
        },
        runRealGh: () => {
          childCalls += 1;
          return 0;
        },
      }),
    /disabled/,
  );
  assert.equal(brokerCalls, 0);
  assert.equal(childCalls, 0);
});

test("local help and version invoke real gh without any ambient credential", async () => {
  let childEnvironment;
  assert.equal(
    await runBrokeredGh({
      args: ["--version"],
      environment: { ...environment, GH_TOKEN: TOKEN, GITHUB_TOKEN: TOKEN },
      assertConfigDirectory: () => {},
      runRealGh: (_args, child) => {
        childEnvironment = child;
        return 0;
      },
    }),
    0,
  );
  assert.equal(childEnvironment.GH_TOKEN, undefined);
  assert.equal(childEnvironment.GITHUB_TOKEN, undefined);
});

test("repo selection and origin disagreements fail closed; no target means no default", () => {
  assert.equal(
    resolveGhRepository({
      args: ["pr", "list", "--repo=Example/Alpha"],
      environment: {},
      readOrigin: () => "https://github.com/Example/Alpha.git",
    }),
    "Example/Alpha",
  );
  assert.equal(
    resolveGhRepository({
      args: ["pr", "view", "26", "--repo=github.com/example/alpha"],
      environment: {},
      readOrigin: () => "https://github.com/Example/Alpha.git",
    }),
    "Example/Alpha",
  );
  assert.throws(
    () =>
      resolveGhRepository({
        args: ["pr", "list", "--repo", "Example/Bravo"],
        environment: {},
        readOrigin: () => "https://github.com/Example/Alpha.git",
      }),
    /does not match/,
  );
  assert.equal(
    resolveGhRepository({ args: ["pr", "list", "-R", "Example/Bravo"], environment: {}, readOrigin: () => null }),
    "Example/Bravo",
  );
  assert.throws(
    () => resolveGhRepository({ args: ["pr", "list"], environment: {}, readOrigin: () => null }),
    /run gh inside a Team repository checkout or pass --repo OWNER\/REPO/,
  );
});

test("the gh config boundary is read-only and environment sanitation is stable", () => {
  assert.doesNotThrow(() =>
    assertReadOnlyGhConfigDirectory(() => ({ isDirectory: () => true, mode: 0o40555 })),
  );
  assert.throws(
    () => assertReadOnlyGhConfigDirectory(() => ({ isDirectory: () => true, mode: 0o40755 })),
    /read-only directory/,
  );
  const clean = uncredentialedGhEnvironment({ GH_TOKEN: TOKEN, GH_REPO: "Example/Alpha" });
  assert.equal(clean.GH_TOKEN, undefined);
  assert.equal(clean.GH_REPO, undefined);
  assert.equal(clean.GH_PAGER, "cat");
  const brokered = brokeredGhEnvironment({ GH_TOKEN: "stale" }, TOKEN, "Example/Alpha");
  assert.equal(brokered.GH_TOKEN, TOKEN);
  assert.equal(brokered.GH_REPO, "Example/Alpha");
});
