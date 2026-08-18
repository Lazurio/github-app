import assert from "node:assert/strict";
import test from "node:test";

import {
  firstPolicyRepository,
  normalizeRepository,
  parseRepositoryPolicy,
  requestGitHubAppToken,
  requireHttpsGitHubOrigin,
} from "../adapter/broker-client.mjs";
import {
  assertReadOnlyGhConfigDirectory,
  brokeredGhEnvironment,
  classifyGhCommand,
  HOSTED_GITHUB_ACTOR,
  READ_ONLY_GH_CONFIG_DIR,
  resolveGhRepository,
  runBrokeredGh,
  uncredentialedGhEnvironment,
} from "../adapter/brokered-gh.mjs";

const TOKEN = "ghs_secret_token_that_must_never_be_rendered";
const NOW = Date.parse("2026-08-18T12:00:00Z");
const environment = {
  GITHUB_REPOSITORY_POLICY_JSON: JSON.stringify({
    "Example/Bravo": 202,
    "Example/Alpha": 101,
  }),
  GITHUB_TOKEN_BROKER_URL: "http://github-token-broker:8787",
  GITHUB_BROKER_WORKSPACE_ID: "example-management",
  GITHUB_BROKER_CLIENT_CREDENTIAL_FILE: "/run/secrets/github_broker_client_token",
};

function response(body, { ok = true } = {}) {
  return { ok, json: async () => body };
}

function validToken(repositoryId = 101) {
  return {
    token: TOKEN,
    repository_id: repositoryId,
    expires_at: "2026-08-18T13:00:00Z",
  };
}

test("validates and deterministically sorts the Team repository policy", () => {
  assert.deepEqual(parseRepositoryPolicy(environment), [
    { repository: "Example/Alpha", repositoryId: 101 },
    { repository: "Example/Bravo", repositoryId: 202 },
  ]);
  assert.equal(firstPolicyRepository(environment), "Example/Alpha");
  assert.equal(normalizeRepository("https://github.com/Example/Alpha.git"), "Example/Alpha");
  assert.equal(requireHttpsGitHubOrigin("https://github.com/Example/Alpha.git"), "Example/Alpha");
  assert.throws(() => requireHttpsGitHubOrigin("git@github.com:Example/Alpha.git"), /brokered HTTPS/);
  assert.throws(
    () => parseRepositoryPolicy({ GITHUB_REPOSITORY_POLICY_JSON: '{"Example/Alpha":101,"example/alpha":202}' }),
    /policy is invalid/,
  );
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

test("requests one fresh repo-scoped token without exposing the Workspace credential", async () => {
  let captured;
  const result = await requestGitHubAppToken({
    repository: "Example/Alpha",
    environment,
    readFile: () => "workspace-credential-with-at-least-32-bytes",
    fetchImpl: async (url, options) => {
      captured = { url, options };
      return response(validToken());
    },
    now: () => NOW,
  });
  assert.equal(result.repositoryId, 101);
  assert.equal(captured.url, "http://github-token-broker:8787/v1/token");
  assert.deepEqual(JSON.parse(captured.options.body), { repository_id: 101 });
  assert.equal(captured.options.headers["X-Lazurio-Workspace-ID"], "example-management");
  assert.equal(captured.options.headers.Authorization.startsWith("Bearer "), true);
});

test("broker refusal, timeout, malformed policy and malformed response fail closed", async () => {
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
  await assert.rejects(
    () => requestGitHubAppToken({ ...shared, environment: { ...environment, GITHUB_REPOSITORY_POLICY_JSON: "{" } }),
    /policy is invalid/,
  );
});

test("auth status performs an uncached live proof and emits the official host schema", async () => {
  const stdout = [];
  const stderr = [];
  let proofs = 0;
  const input = {
    args: ["auth", "status", "--json", "hosts"],
    environment,
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
      environment,
      requestToken: async () => {
        calls += 1;
        return { token: TOKEN };
      },
      writeStdout: (value) => stdout.push(value),
    }),
    0,
  );
  assert.equal(calls, 1);
  assert.deepEqual(stdout, [`${HOSTED_GITHUB_ACTOR}\n`]);
});

test("repository operations resolve one exact HTTPS checkout and pass only env-local token", async () => {
  let child;
  const exitCode = await runBrokeredGh({
    args: ["pr", "list", "--repo", "github.com/Example/Alpha", "--hostname", "github.com"],
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
    "github.com/Example/Alpha",
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

test("repo selection, policy and origin disagreements fail closed", () => {
  assert.equal(
    resolveGhRepository({
      args: ["pr", "list", "--repo=Example/Alpha"],
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
