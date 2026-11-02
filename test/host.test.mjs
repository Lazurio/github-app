// SPDX-License-Identifier: Apache-2.0
//
// Conglomerate Host callers (0.15.0, Lazurio/github-app#30): a host proves itself with its own
// Ed25519 key, whose public part the broker reads live from its own Organization's Deployment Repo,
// and receives one token with exactly contents: read and members: read on that repository.
//
// Synthetic identities only: the broker's Organization 1001 with its Deployment Repo 3101; another
// Organization 7001; hosts "example-conglomerate-host" and "other-host".

import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import test from "node:test";

import { formatPolicySummary } from "../src/broker.mjs";
import { admitRunGrant, createBrokerHandler, createGithubClient, parsePolicy } from "../src/core.mjs";
import {
  HOST_GRANTS_PER_HOUR,
  HOST_KEY_DOCUMENT_SCHEMA,
  HOST_READS_PER_HOUR,
  HOST_REFUSALS,
  HOST_TOKEN_PERMISSIONS,
  HostRefusal,
  base64urlBytes,
  decodeHostAssertion,
  parseHostKeyDocument,
  verifyEd25519,
} from "../src/host.mjs";
import { OidcRunGuard, createWorkerEntrypoint } from "../src/worker.mjs";

const AUDIENCE = "https://github-broker.example.com";
const HOST = "example-conglomerate-host";
const NOW = Date.parse("2026-11-02T12:00:00Z");
const NOW_S = Math.floor(NOW / 1000);
const DIRECTORY = "access/conglomerate-hosts";
const REF = "machines-evidence-v1";

function hostsPolicyFixture(overrides = {}) {
  return {
    schema_version: "lazurio.github_app_broker.policy.v3",
    github_app: { id: 42, slug: "example-app" },
    github_owner: { id: 1001, login: "example-org" },
    installation_id: 2001,
    installation_repository_selection: "all",
    installation_permissions: {
      actions: "write",
      checks: "read",
      contents: "write",
      members: "read",
      metadata: "read",
      pull_requests: "write",
    },
    workspaces: [],
    conglomerate_hosts: { audience: AUDIENCE, repository_id: 3101, ref: REF, directory: DIRECTORY, ...overrides },
  };
}

function b64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function keyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const x = publicKey.export({ format: "jwk" }).x;
  return { privateKey, brokerKey: `ed25519:${x}` };
}

const HOST_KEY = keyPair();
const OTHER_KEY = keyPair();

/** A compact EdDSA JWS as the host's access service builds it. */
function assertion({
  key = HOST_KEY,
  header = { alg: "EdDSA", kid: HOST },
  claims = {},
  signature,
} = {}) {
  const payload = {
    aud: AUDIENCE,
    iss: header.kid,
    iat: NOW_S,
    exp: NOW_S + 60,
    jti: b64url(randomBytes(18)),
    ...claims,
  };
  const input = `${b64url(Buffer.from(JSON.stringify(header)))}.${b64url(Buffer.from(JSON.stringify(payload)))}`;
  const signed = signature ?? b64url(sign(null, Buffer.from(input), key.privateKey));
  return `${input}.${signed}`;
}

function keyDocument(overrides = {}) {
  return JSON.stringify({
    schema_version: HOST_KEY_DOCUMENT_SCHEMA,
    host: HOST,
    organization_id: 1001,
    broker_key: HOST_KEY.brokerKey,
    source: {
      repository_id: 3102,
      evidence_commit: "a".repeat(40),
      evidence_path: "evidence/example-conglomerate-host/20261102T110000Z-apply.json",
    },
    written_at: "2026-11-02T11:00:00Z",
    ...overrides,
  });
}

function memoryStorage() {
  const data = new Map();
  let alarm = null;
  return {
    async get(key) {
      return structuredClone(data.get(key));
    },
    async put(key, value) {
      data.set(key, structuredClone(value));
    },
    async getAlarm() {
      return alarm;
    },
    async setAlarm(at) {
      alarm = at;
    },
    async deleteAll() {
      data.clear();
      alarm = null;
    },
  };
}

/** The deny-only guard as the Worker's Durable Object answers it, one storage per key. */
function memoryGuard(now = () => NOW) {
  const objects = new Map();
  const calls = [];
  return {
    calls,
    async admit({ key, ...grant }) {
      calls.push({ key, ...grant });
      if (!objects.has(key)) objects.set(key, memoryStorage());
      return admitRunGrant(objects.get(key), grant, now());
    },
  };
}

/** A GitHub client double: the key documents by path, and a record of every read and mint. */
function syntheticGithub({ documents = { [`${DIRECTORY}/${HOST}.json`]: keyDocument() }, mint, read } = {}) {
  const reads = [];
  const mints = [];
  return {
    reads,
    mints,
    client: {
      async verifyPolicy() {},
      async verifyTeamGrant() {
        throw new Error("no Workspace in this test");
      },
      async verifyWorkspaceTeam() {
        throw new Error("no Workspace in this test");
      },
      async mintToken() {
        throw new Error("no Workspace in this test");
      },
      async readHostKeyDocument(_policy, path) {
        reads.push(path);
        if (read) return read(path);
        return documents[path];
      },
      async mintPurposeToken(_policy, repositoryId, permissions) {
        mints.push({ repositoryId, permissions });
        if (mint) return mint(repositoryId, permissions);
        return {
          token: "ghs_synthetic_host_token_value",
          expires_at: "2026-11-02T13:00:00Z",
          repository_id: repositoryId,
          repository: "example-org/deployment",
          permissions: { ...permissions },
        };
      },
    },
  };
}

function hostHandler({ policy = hostsPolicyFixture(), github = syntheticGithub(), guard = memoryGuard(), now = () => NOW } = {}) {
  const records = [];
  const handle = createBrokerHandler({
    policy: parsePolicy(policy),
    github: github.client,
    credentials: new Map(),
    secretMatches: async () => false,
    hosts: { verify: verifyEd25519, guard, audit: (record) => records.push(record), now },
  });
  return { handle, github, guard, records };
}

function hostCall(handle, token, { body = "{}", contentType = "application/json" } = {}) {
  return handle({
    method: "POST",
    path: "/v1/host/token",
    contentType,
    authorization: token === undefined ? "" : `Bearer ${token}`,
    readBody: async () => body,
  });
}

// ------------------------------------------------------------------------------- the policy ---

test("conglomerate_hosts is optional; with it a policy may hold no Workspace, and its permission set is fixed", () => {
  const policy = parsePolicy(hostsPolicyFixture());
  assert.deepEqual(policy.conglomerate_hosts, {
    audience: AUDIENCE,
    repository_id: 3101,
    ref: REF,
    directory: DIRECTORY,
    permissions: HOST_TOKEN_PERMISSIONS,
  });
  assert.deepEqual(HOST_TOKEN_PERMISSIONS, { contents: "read", members: "read" });
  const { conglomerate_hosts: _hosts, ...without } = hostsPolicyFixture();
  assert.throws(() => parsePolicy(without), /workspaces must be a non-empty array/);
  assert.match(formatPolicySummary(policy), /conglomerate_hosts audience=https:\/\/github-broker\.example\.com repository=3101 ref=machines-evidence-v1 directory=access\/conglomerate-hosts asks for: contents=read members=read/);
});

test("conglomerate_hosts refuses anything but exact keys, a canonical origin, one branch and a plain relative directory", () => {
  const invalid = [
    { permissions: { contents: "write" } },
    { audience: "http://github-broker.example.com" },
    { audience: "https://github-broker.example.com/" },
    { audience: "https://user@github-broker.example.com" },
    { repository_id: 0 },
    { repository_id: "3101" },
    { ref: "refs/heads/machines-evidence-v1" },
    { ref: "a/../b" },
    { ref: "branch.lock" },
    { ref: "" },
    { directory: "/access/conglomerate-hosts" },
    { directory: "access/../secrets" },
    { directory: "access//hosts" },
    { directory: "Access/Hosts" },
    { directory: "." },
  ];
  for (const overrides of invalid) {
    assert.throws(() => parsePolicy(hostsPolicyFixture(overrides)), Error, JSON.stringify(overrides));
  }
  const missing = hostsPolicyFixture();
  delete missing.conglomerate_hosts.ref;
  assert.throws(() => parsePolicy(missing), /exactly audience, repository_id, ref and directory/);
});

// ---------------------------------------------------------------------------- the assertion ---

test("an assertion is refused by its header, claims, audience, lifetime and time before any key is read", () => {
  const decode = (token, now = NOW) => {
    try {
      decodeHostAssertion(token, { audience: AUDIENCE, now });
      return "accepted";
    } catch (error) {
      assert.ok(error instanceof HostRefusal);
      return error.code;
    }
  };
  assert.equal(decode(assertion()), "accepted");
  assert.equal(decode(""), "assertion_missing");
  assert.equal(decode("a.b"), "assertion_malformed");
  assert.equal(decode(`${assertion()}=`), "assertion_malformed");
  assert.equal(decode(assertion({ header: { alg: "RS256", kid: HOST } })), "assertion_algorithm_refused");
  assert.equal(decode(assertion({ header: { alg: "none", kid: HOST } })), "assertion_algorithm_refused");
  assert.equal(decode(assertion({ header: { alg: "EdDSA", kid: HOST, jku: "https://x" } })), "assertion_malformed");
  assert.equal(decode(assertion({ header: { alg: "EdDSA", kid: HOST, typ: "at+jwt" } })), "assertion_malformed");
  assert.equal(decode(assertion({ header: { alg: "EdDSA", kid: "../secrets" } })), "assertion_claims_invalid");
  assert.equal(decode(assertion({ header: { alg: "EdDSA", kid: "Example-Host" } })), "assertion_claims_invalid");
  assert.equal(decode(assertion({ claims: { aud: "https://other-broker.example.com" } })), "assertion_audience_mismatch");
  assert.equal(decode(assertion({ claims: { aud: [AUDIENCE] } })), "assertion_audience_mismatch");
  assert.equal(decode(assertion({ claims: { iss: "other-host" } })), "assertion_claims_invalid");
  assert.equal(decode(assertion({ claims: { jti: "short" } })), "assertion_claims_invalid");
  assert.equal(decode(assertion({ claims: { exp: NOW_S } })), "assertion_claims_invalid");
  assert.equal(decode(assertion({ claims: { exp: NOW_S + 61 } })), "assertion_lifetime_too_long");
  assert.equal(decode(assertion({ claims: { nbf: NOW_S } })), "assertion_claims_invalid");
  assert.equal(decode(assertion({ claims: { iat: NOW_S + 31, exp: NOW_S + 60 } })), "assertion_not_yet_valid");
  assert.equal(decode(assertion({ claims: { iat: NOW_S - 120, exp: NOW_S - 61 } })), "assertion_expired");
  // Tolerated: 30 s of clock skew either way.
  assert.equal(decode(assertion({ claims: { iat: NOW_S + 30, exp: NOW_S + 60 } })), "accepted");
  assert.equal(decode(assertion({ claims: { iat: NOW_S - 90, exp: NOW_S - 30 } })), "accepted");
  // A signature that is not 64 bytes.
  assert.equal(decode(assertion({ signature: b64url(randomBytes(63)) })), "assertion_malformed");
});

test("base64url is accepted only in its one canonical unpadded form", () => {
  assert.deepEqual([...base64urlBytes("AQID")], [1, 2, 3]);
  assert.equal(base64urlBytes("AQID="), undefined);
  assert.equal(base64urlBytes("AQ+D"), undefined);
  // "AR" and "AQ" both decode to 0x01 with lax decoders; only "AQ" is canonical.
  assert.deepEqual([...base64urlBytes("AQ")], [1]);
  assert.equal(base64urlBytes("AR"), undefined);
});

// -------------------------------------------------------------------------- the key document ---

test("a key document must name exactly this host and this broker's Organization, with one Ed25519 key", () => {
  const parse = (text) => {
    try {
      return parseHostKeyDocument(text, { host: HOST, organizationId: 1001 }).length;
    } catch (error) {
      assert.ok(error instanceof HostRefusal);
      return error.code;
    }
  };
  assert.equal(parse(keyDocument()), 32);
  assert.equal(parse(keyDocument({ organization_id: 7001 })), "organization_mismatch");
  assert.equal(parse(keyDocument({ host: "other-host" })), "host_key_invalid");
  assert.equal(parse(keyDocument({ schema_version: "machines.conglomerate-host-broker-key.v2" })), "host_key_invalid");
  assert.equal(parse(keyDocument({ broker_key: HOST_KEY.brokerKey.replace("ed25519:", "ssh-ed25519 ") })), "host_key_invalid");
  assert.equal(parse(keyDocument({ broker_key: `ed25519:${b64url(randomBytes(31))}` })), "host_key_invalid");
  assert.equal(parse(keyDocument({ extra: true })), "host_key_invalid");
  assert.equal(parse(keyDocument({ source: { repository_id: 3102 } })), "host_key_invalid");
  assert.equal(parse(keyDocument({ written_at: "yesterday" })), "host_key_invalid");
  assert.equal(parse("not json"), "host_key_invalid");
  assert.equal(parse(`${keyDocument()}${" ".repeat(5000)}`), "host_key_invalid");
});

// --------------------------------------------------------------------------- the route ---

test("a host with its key document and a valid signature gets one token: its Deployment Repo, contents and members read, audited without the token", async () => {
  const { handle, github, records } = hostHandler();
  const { status, body } = await hostCall(handle, assertion());
  assert.equal(status, 200);
  assert.deepEqual(body, {
    token: "ghs_synthetic_host_token_value",
    expires_at: "2026-11-02T13:00:00Z",
    repository_id: 3101,
    repository: "example-org/deployment",
    access: "read",
    permissions: { contents: "read", members: "read" },
  });
  assert.deepEqual(github.reads, [`${DIRECTORY}/${HOST}.json`]);
  assert.deepEqual(github.mints, [{ repositoryId: 3101, permissions: HOST_TOKEN_PERMISSIONS }]);
  assert.equal(records.length, 1);
  assert.deepEqual(records[0], {
    schema_version: "lazurio.github_app_broker.audit.v1",
    at: "2026-11-02T12:00:00.000Z",
    route: "host",
    status: 200,
    decision: "granted",
    host: HOST,
    organization_id: 1001,
    grant: {
      repository_id: 3101,
      repository: "example-org/deployment",
      access: "read",
      permissions: { contents: "read", members: "read" },
      expires_at: "2026-11-02T13:00:00Z",
    },
  });
  assert.doesNotMatch(JSON.stringify(records), /ghs_synthetic|eyJ/);
});

test("an unknown host, another key, another Organization's document or an invalid document mint nothing", async () => {
  const cases = [
    [{}, assertion({ header: { alg: "EdDSA", kid: "other-host" } }), "host_unknown"],
    [{}, assertion({ key: OTHER_KEY }), "assertion_signature_invalid"],
    [{ [`${DIRECTORY}/${HOST}.json`]: keyDocument({ organization_id: 7001 }) }, assertion(), "organization_mismatch"],
    [{ [`${DIRECTORY}/${HOST}.json`]: keyDocument({ broker_key: OTHER_KEY.brokerKey }) }, assertion(), "assertion_signature_invalid"],
    [{ [`${DIRECTORY}/${HOST}.json`]: "{}" }, assertion(), "host_key_invalid"],
  ];
  for (const [documents, token, code] of cases) {
    const github = syntheticGithub(Object.keys(documents).length ? { documents } : undefined);
    const { handle, records } = hostHandler({ github });
    const { status, body } = await hostCall(handle, token);
    assert.equal(status, HOST_REFUSALS[code], code);
    assert.deepEqual(body, { error: code });
    assert.equal(github.mints.length, 0, code);
    assert.equal(records.at(-1).decision, code);
    assert.equal(records.at(-1).grant, undefined);
  }
});

test("a signature over other claims than those presented is refused: the signing input is the presented header and claims", async () => {
  const genuine = assertion();
  const [header, , signature] = genuine.split(".");
  const altered = `${header}.${b64url(Buffer.from(JSON.stringify({ aud: AUDIENCE, iss: HOST, iat: NOW_S, exp: NOW_S + 60, jti: b64url(randomBytes(18)) })))}.${signature}`;
  const { handle, github } = hostHandler();
  const { status, body } = await hostCall(handle, altered);
  assert.equal(status, 401);
  assert.deepEqual(body, { error: "assertion_signature_invalid" });
  assert.equal(github.mints.length, 0);
});

test("refusals that need no key happen before any GitHub request: media type, body, audience, time", async () => {
  const github = syntheticGithub();
  const { handle } = hostHandler({ github });
  const results = [
    await hostCall(handle, assertion(), { contentType: "text/plain" }),
    await hostCall(handle, assertion(), { body: '{"repository":"example-org/other"}' }),
    await hostCall(handle, assertion(), { body: "[]" }),
    await hostCall(handle, assertion(), { body: "not json" }),
    await hostCall(handle, undefined),
    await hostCall(handle, assertion({ claims: { aud: "https://other-broker.example.com" } })),
    await hostCall(handle, assertion({ claims: { iat: NOW_S - 300, exp: NOW_S - 240 } })),
  ];
  assert.deepEqual(
    results.map(({ status, body }) => [status, body.error]),
    [
      [415, "unsupported_media_type"],
      [400, "invalid_request"],
      [400, "invalid_request"],
      [400, "invalid_request"],
      [401, "assertion_missing"],
      [401, "assertion_audience_mismatch"],
      [401, "assertion_expired"],
    ],
  );
  assert.equal(github.reads.length, 0);
  assert.equal(github.mints.length, 0);
});

test("a replayed assertion is refused before the key document is read again, and never mints twice", async () => {
  const { handle, github } = hostHandler();
  const token = assertion();
  assert.equal((await hostCall(handle, token)).status, 200);
  const again = await hostCall(handle, token);
  assert.equal(again.status, 401);
  assert.deepEqual(again.body, { error: "assertion_replayed" });
  assert.equal(github.reads.length, 1);
  assert.equal(github.mints.length, 1);
});

test("the broker's hourly read budget refuses before GitHub, and a host's hourly grant budget before the mint", async () => {
  // Reads: unauthenticated callers can only spend this deny-only budget, never the installation's.
  {
    const github = syntheticGithub({ documents: {} });
    const { handle } = hostHandler({ github });
    for (let index = 0; index < HOST_READS_PER_HOUR; index += 1) {
      assert.equal((await hostCall(handle, assertion())).body.error, "host_unknown");
    }
    const limited = await hostCall(handle, assertion());
    assert.deepEqual([limited.status, limited.body.error], [429, "rate_limited"]);
    assert.equal(github.reads.length, HOST_READS_PER_HOUR);
  }
  // Grants: one host mints at most HOST_GRANTS_PER_HOUR tokens per hour of its assertions' iat.
  {
    const { handle, github } = hostHandler();
    for (let index = 0; index < HOST_GRANTS_PER_HOUR; index += 1) {
      assert.equal((await hostCall(handle, assertion())).status, 200);
    }
    const limited = await hostCall(handle, assertion());
    assert.deepEqual([limited.status, limited.body.error], [429, "rate_limited"]);
    assert.equal(github.mints.length, HOST_GRANTS_PER_HOUR);
  }
});

test("a mint outside the configured repository or permission set, or a failing GitHub read, is token_unavailable", async () => {
  const outside = [
    (repositoryId, permissions) => ({
      token: "ghs_x_token_value_long_enough",
      expires_at: "2026-11-02T13:00:00Z",
      repository_id: 3999,
      repository: "example-org/other",
      permissions,
    }),
    (repositoryId) => ({
      token: "ghs_x_token_value_long_enough",
      expires_at: "2026-11-02T13:00:00Z",
      repository_id: repositoryId,
      repository: "example-org/deployment",
      permissions: { contents: "write", members: "read" },
    }),
  ];
  for (const mint of outside) {
    const { handle } = hostHandler({ github: syntheticGithub({ mint }) });
    const { status, body } = await hostCall(handle, assertion());
    assert.deepEqual([status, body], [502, { error: "token_unavailable" }]);
  }
  const failing = syntheticGithub({
    read: () => {
      throw new Error("GitHub request failed with HTTP 500");
    },
  });
  const { handle } = hostHandler({ github: failing });
  assert.deepEqual((await hostCall(handle, assertion())).body, { error: "token_unavailable" });
  assert.equal(failing.mints.length, 0);
});

test("without conglomerate_hosts, or without the host dependencies (the Node adapter), the route does not exist", async () => {
  const { conglomerate_hosts: _hosts, ...plain } = hostsPolicyFixture();
  plain.workspaces = [{ id: "alpha-team", github_team_id: 4001, credential_file: "/run/secrets/workspace-alpha" }];
  for (const [policy, hosts] of [
    [plain, { verify: verifyEd25519, guard: memoryGuard(), audit: () => {}, now: () => NOW }],
    [hostsPolicyFixture(), undefined],
  ]) {
    const github = syntheticGithub();
    const handle = createBrokerHandler({
      policy: parsePolicy(policy),
      github: github.client,
      credentials: new Map(),
      secretMatches: async () => false,
      hosts,
    });
    const { status, body } = await hostCall(handle, assertion());
    assert.deepEqual([status, body], [404, { error: "not_found" }]);
    assert.equal(github.reads.length, 0);
  }
});

// ------------------------------------------------------------------- the real GitHub client ---

function fakeGithubApi({ document = keyDocument(), status = 200, owner = 1001 } = {}) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    const { pathname, search } = new URL(url);
    calls.push({ method: init.method ?? "GET", path: `${pathname}${search}`, accept: init.headers?.Accept, authorization: init.headers?.Authorization, body: init.body });
    if (pathname === "/app/installations/2001/access_tokens") {
      const requested = JSON.parse(init.body);
      return Response.json(
        {
          token: "ghs_internal_read_token_value",
          expires_at: new Date(Date.now() + 3_600_000).toISOString(),
          permissions: requested.permissions,
          repositories: [{ id: requested.repository_ids[0], full_name: "example-org/deployment", owner: { id: owner, login: "example-org" } }],
        },
        { status: 201 },
      );
    }
    if (pathname.startsWith("/repositories/3101/contents/")) {
      return status === 200 ? new Response(document, { status: 200 }) : new Response("", { status });
    }
    if (pathname === "/installation/token") return new Response(null, { status: 204 });
    return new Response("{}", { status: 404 });
  };
  return { calls, client: createGithubClient({ appId: 42, signJwt: async () => "c2lnbmF0dXJl", fetchImpl }) };
}

test("the GitHub client reads a key document raw at the policy's ref with a contents-read token for exactly that repository, and revokes it", async () => {
  const policy = parsePolicy(hostsPolicyFixture());
  const api = fakeGithubApi();
  assert.equal(await api.client.readHostKeyDocument(policy, `${DIRECTORY}/${HOST}.json`), keyDocument());
  const [mint, read, revoke] = api.calls;
  assert.deepEqual(JSON.parse(mint.body), { repository_ids: [3101], permissions: { contents: "read" } });
  assert.equal(read.path, `/repositories/3101/contents/access/conglomerate-hosts/${HOST}.json?ref=machines-evidence-v1`);
  assert.equal(read.accept, "application/vnd.github.raw+json");
  assert.equal(read.authorization, "Bearer ghs_internal_read_token_value");
  assert.deepEqual([revoke.method, revoke.path, revoke.authorization], ["DELETE", "/installation/token", "Bearer ghs_internal_read_token_value"]);
});

test("the GitHub client answers a missing document as unknown, refuses another owner and paths outside the directory, and always revokes", async () => {
  const policy = parsePolicy(hostsPolicyFixture());
  const missing = fakeGithubApi({ status: 404 });
  assert.equal(await missing.client.readHostKeyDocument(policy, `${DIRECTORY}/${HOST}.json`), undefined);
  assert.equal(missing.calls.at(-1).method, "DELETE");
  const failing = fakeGithubApi({ status: 500 });
  await assert.rejects(failing.client.readHostKeyDocument(policy, `${DIRECTORY}/${HOST}.json`), /HTTP 500/);
  assert.equal(failing.calls.at(-1).method, "DELETE");
  const foreign = fakeGithubApi({ owner: 7001 });
  await assert.rejects(foreign.client.readHostKeyDocument(policy, `${DIRECTORY}/${HOST}.json`), /outside the requested repository/);
  assert.equal(foreign.calls.some((call) => call.path.startsWith("/repositories/")), false);
  const api = fakeGithubApi();
  await assert.rejects(api.client.readHostKeyDocument(policy, "secrets/key.json"), /outside the policy's directory/);
  await assert.rejects(api.client.readHostKeyDocument(policy, `${DIRECTORY}/../x.json`), /outside the policy's directory/);
  assert.equal(api.calls.length, 0);
});

// ------------------------------------------------------------------------------- the Worker ---

function durableObjectNamespace() {
  const objects = new Map();
  return {
    objects,
    idFromName: (name) => ({ name }),
    get(id) {
      if (!objects.has(id.name)) objects.set(id.name, new OidcRunGuard({ storage: memoryStorage() }));
      const guard = objects.get(id.name);
      return { fetch: (url, init) => guard.fetch(new Request(url, init)) };
    },
  };
}

function hostRequest(token) {
  return new Request(`${AUDIENCE}/v1/host/token`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: "{}",
  });
}

test("Worker end to end: WebCrypto Ed25519, the Durable Object guard and the live installation gate before the key read and the mint", async () => {
  const github = syntheticGithub();
  const order = [];
  const client = {
    ...github.client,
    async verifyPolicy() {
      order.push("verifyPolicy");
    },
    async readHostKeyDocument(policy, path) {
      order.push("read");
      return github.client.readHostKeyDocument(policy, path);
    },
    async mintPurposeToken(policy, repositoryId, permissions) {
      order.push("mint");
      return github.client.mintPurposeToken(policy, repositoryId, permissions);
    },
  };
  const records = [];
  const namespace = durableObjectNamespace();
  const worker = createWorkerEntrypoint({ createGithub: () => client, audit: (record) => records.push(record), now: () => Date.now() });
  const env = {
    BROKER_POLICY_JSON: JSON.stringify(hostsPolicyFixture()),
    GITHUB_APP_ID: "42",
    GITHUB_APP_PRIVATE_KEY: "synthetic-test-key",
    OIDC_RUN_GUARD: namespace,
  };
  const now = Math.floor(Date.now() / 1000);
  const token = assertion({ claims: { iat: now, exp: now + 60 } });
  const response = await worker.fetch(hostRequest(token), env);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual((await response.json()).permissions, { contents: "read", members: "read" });
  assert.deepEqual(order, ["verifyPolicy", "read", "verifyPolicy", "mint"]);
  assert.ok([...namespace.objects.keys()].some((name) => name.startsWith(`host/${HOST}/`)));
  assert.equal(records.at(-1).decision, "granted");
  // The same assertion again: refused by the Durable Object, no further GitHub request.
  const replay = await worker.fetch(hostRequest(token), env);
  assert.equal(replay.status, 401);
  assert.deepEqual(await replay.json(), { error: "assertion_replayed" });
  assert.equal(order.length, 4);
});

test("Worker: a policy naming conglomerate_hosts without the guard binding, or a client without a key reader, is unavailable configuration", async () => {
  const github = syntheticGithub();
  const { readHostKeyDocument: _read, ...withoutReader } = github.client;
  for (const [client, withGuard] of [
    [github.client, false],
    [withoutReader, true],
  ]) {
    const worker = createWorkerEntrypoint({ createGithub: () => client, audit: () => {} });
    const env = {
      BROKER_POLICY_JSON: JSON.stringify(hostsPolicyFixture()),
      GITHUB_APP_ID: "42",
      GITHUB_APP_PRIVATE_KEY: "synthetic-test-key",
      ...(withGuard ? { OIDC_RUN_GUARD: durableObjectNamespace() } : {}),
    };
    const response = await worker.fetch(hostRequest(assertion()), env);
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: "configuration_unavailable" });
  }
});
