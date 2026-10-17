// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { once } from "node:events";
import { readFileSync } from "node:fs";
import test from "node:test";

import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from "jose";

import { createBrokerServer, formatPolicySummary } from "../src/broker.mjs";
import {
  OIDC_REFUSALS,
  OidcRefusal,
  RUN_GUARD_RETENTION_MS,
  admitOidcRequest,
  admitRunGrant,
  createBrokerHandler,
  createGithubClient,
  parseOidcTokenRequest,
  parsePolicy,
} from "../src/core.mjs";
import { GITHUB_ACTIONS_ISSUER, createGithubActionsKeySet, createOidcVerifier } from "../src/oidc.mjs";
import { OidcRunGuard, createWorkerEntrypoint } from "../src/worker.mjs";

// Synthetic identities only: the broker's Organization 1001 with its Deployment Repo 3101 and a
// fixed release repository 3201; another Organization 7001 with its Deployment Repo 7101.
const AUDIENCE = "https://github-broker.example.com";
const WORKFLOW = ".github/workflows/lazurio-rollout.yml";
const ALPHA_CREDENTIAL = "alpha-secret-value-with-at-least-32-bytes";

const DEPLOYMENT_APPLY = Object.freeze({
  administration: "read",
  checks: "read",
  contents: "write",
  issues: "read",
  members: "read",
  organization_administration: "read",
  pull_requests: "read",
});
const DEPLOYMENT_PLAN = Object.freeze(
  Object.fromEntries(Object.keys(DEPLOYMENT_APPLY).map((permission) => [permission, "read"])),
);
const RELEASE_READ = Object.freeze({ contents: "read" });

const REPOSITORIES = new Map([
  [3101, { full_name: "example-org/deployment", owner: { id: 1001, login: "example-org" } }],
  [3201, { full_name: "example-org/releases", owner: { id: 1001, login: "example-org" } }],
]);

function oidcPolicyFixture() {
  return {
    schema_version: "lazurio.github_app_broker.policy.v3",
    github_app: { id: 42, slug: "example-app" },
    github_owner: { id: 1001, login: "example-org" },
    installation_id: 2001,
    installation_repository_selection: "selected",
    installation_permissions: {
      actions: "write",
      administration: "read",
      checks: "read",
      contents: "write",
      issues: "read",
      members: "read",
      metadata: "read",
      organization_administration: "read",
      pull_requests: "write",
    },
    workspaces: [
      { id: "alpha-team", github_team_id: 4001, credential_file: "/run/secrets/workspace-alpha" },
    ],
    oidc: {
      audience: AUDIENCE,
      deployment_repositories: [
        { repository_id: 3101, repository_owner_id: 1001 },
        { repository_id: 7101, repository_owner_id: 7001 },
      ],
      purposes: [
        {
          purpose: "deployment-apply",
          repository: "caller",
          workflow: WORKFLOW,
          rules: [
            { events: ["push", "workflow_dispatch"], ref: "refs/heads/main", environment: "production" },
            { events: ["pull_request_target"], ref: "refs/heads/main", environment: null, read_only: true },
          ],
          permissions: { ...DEPLOYMENT_APPLY },
          max_grants_per_run: 2,
        },
        {
          purpose: "machines-release",
          repository: { repository_id: 3201 },
          workflow: WORKFLOW,
          rules: [
            { events: ["push", "workflow_dispatch"], ref: "refs/heads/main", environment: "production" },
            { events: ["pull_request_target"], ref: "refs/heads/main", environment: null },
          ],
          permissions: { ...RELEASE_READ },
          max_grants_per_run: 4,
        },
      ],
    },
  };
}

/** Verified claims as the verifier returns them: a push to main of the Deployment Repo, in production. */
function claimsFixture(overrides = {}) {
  const repository = overrides.repository ?? "example-org/deployment";
  const ref = overrides.ref ?? "refs/heads/main";
  const workflowRef = `${repository}/${WORKFLOW}@${ref}`;
  return {
    jti: "6c0f6a6e-1f62-4e36-9f0e-2d8c1e8a0b51",
    exp: Math.floor(Date.now() / 1000) + 300,
    iat: Math.floor(Date.now() / 1000),
    repository,
    repository_id: "3101",
    repository_owner: repository.split("/")[0],
    repository_owner_id: "1001",
    ref,
    event_name: "push",
    environment: "production",
    workflow_ref: workflowRef,
    job_workflow_ref: workflowRef,
    runner_environment: "github-hosted",
    run_id: "9001",
    run_attempt: "1",
    actor: "example-user",
    actor_id: "5001",
    sha: "a".repeat(40),
    ...overrides,
  };
}

const OTHER_ORG = Object.freeze({ repository: "other-org/deployment", repository_id: "7101", repository_owner_id: "7001" });
const PLAN_RUN = Object.freeze({ event_name: "pull_request_target", environment: null });

function admit(overrides, purpose = "deployment-apply", policy = parsePolicy(oidcPolicyFixture())) {
  return admitOidcRequest(policy, claimsFixture(overrides), purpose);
}

function refusalOf(run) {
  try {
    run();
  } catch (error) {
    assert.ok(error instanceof OidcRefusal, `expected an OIDC refusal, got ${error}`);
    return error.code;
  }
  assert.fail("expected a refusal");
}

// ---------------------------------------------------------------------------------------------
// Policy: the `oidc` section
// ---------------------------------------------------------------------------------------------

test("policy parses the oidc purpose table; without it the policy has no oidc key", () => {
  const policy = parsePolicy(oidcPolicyFixture());
  assert.equal(policy.oidc.audience, AUDIENCE);
  assert.deepEqual(policy.oidc.runner_environments, ["github-hosted"]);
  assert.deepEqual(policy.oidc.deployment_repositories, [
    { repository_id: 3101, repository_owner_id: 1001 },
    { repository_id: 7101, repository_owner_id: 7001 },
  ]);
  assert.deepEqual(
    policy.oidc.purposes.map(({ purpose, repository, max_grants_per_run }) => [purpose, repository, max_grants_per_run]),
    [
      ["deployment-apply", "caller", 2],
      ["machines-release", { repository_id: 3201 }, 4],
    ],
  );
  assert.equal(policy.oidc.purposes[0].rules[0].read_only, false);
  assert.equal(policy.oidc.purposes[0].rules[1].read_only, true);
  assert.ok(Object.isFrozen(policy.oidc.purposes[0].permissions));

  const withoutOidc = oidcPolicyFixture();
  delete withoutOidc.oidc;
  assert.equal("oidc" in parsePolicy(withoutOidc), false);
});

test("policy rejects every malformed or widening oidc entry", () => {
  const cases = [
    ["http audience", (p) => { p.oidc.audience = "http://github-broker.example.com"; }, /canonical HTTPS origin/],
    ["audience with a trailing slash", (p) => { p.oidc.audience = `${AUDIENCE}/`; }, /canonical HTTPS origin/],
    ["audience with a path", (p) => { p.oidc.audience = `${AUDIENCE}/v1`; }, /canonical HTTPS origin/],
    ["audience with a port", (p) => { p.oidc.audience = "https://github-broker.example.com:8443"; }, /canonical HTTPS origin/],
    ["upper-case audience host", (p) => { p.oidc.audience = "https://GitHub-Broker.example.com"; }, /canonical HTTPS origin/],
    ["unknown oidc key", (p) => { p.oidc.allow_everything = true; }, /oidc\.allow_everything is not a known key/],
    ["missing audience", (p) => { delete p.oidc.audience; }, /oidc\.audience is required/],
    ["self-hosted only as a typo", (p) => { p.oidc.runner_environments = ["selfhosted"]; }, /runner_environments/],
    ["empty runner list", (p) => { p.oidc.runner_environments = []; }, /runner_environments/],
    ["no Deployment Repo", (p) => { p.oidc.deployment_repositories = []; }, /deployment_repositories must be a non-empty list/],
    ["Deployment Repo without owner", (p) => { delete p.oidc.deployment_repositories[0].repository_owner_id; }, /repository_owner_id is required/],
    ["duplicate Deployment Repo", (p) => { p.oidc.deployment_repositories[1] = { repository_id: 3101, repository_owner_id: 1001 }; }, /each repository id once/],
    ["string repository id", (p) => { p.oidc.deployment_repositories[0].repository_id = "3101"; }, /positive integer/],
    ["no purposes", (p) => { p.oidc.purposes = []; }, /purposes must be a non-empty list/],
    ["duplicate purpose", (p) => { p.oidc.purposes[1].purpose = "deployment-apply"; }, /each purpose once/],
    ["upper-case purpose", (p) => { p.oidc.purposes[0].purpose = "Deployment"; }, /lowercase name/],
    ["unknown purpose key", (p) => { p.oidc.purposes[0].scope = "all"; }, /purposes\[0\]\.scope is not a known key/],
    ["repository by name", (p) => { p.oidc.purposes[1].repository = "example-org/releases"; }, /repository must be an object/],
    ["workflow outside .github/workflows", (p) => { p.oidc.purposes[0].workflow = "lazurio-rollout.yml"; }, /workflow file below/],
    ["empty permission set", (p) => { p.oidc.purposes[1].permissions = {}; }, /at least one permission/],
    ["metadata named explicitly", (p) => { p.oidc.purposes[1].permissions = { contents: "read", metadata: "read" }; }, /at least one permission/],
    ["admin level", (p) => { p.oidc.purposes[1].permissions = { contents: "admin" }; }, /at least one permission/],
    ["permission above the accepted level", (p) => { p.oidc.purposes[0].permissions.administration = "write"; }, /administration: write, which the installation has not accepted/],
    ["permission the installation lacks", (p) => { p.oidc.purposes[1].permissions = { organization_plan: "read" }; }, /organization_plan: read, which the installation has not accepted/],
    ["no rules", (p) => { p.oidc.purposes[0].rules = []; }, /rules must be a non-empty list/],
    ["unknown rule key", (p) => { p.oidc.purposes[0].rules[0].refs = ["refs/heads/*"]; }, /rules\[0\]\.refs is not a known key/],
    ["rule without environment", (p) => { delete p.oidc.purposes[0].rules[0].environment; }, /environment is required/],
    ["empty environment", (p) => { p.oidc.purposes[0].rules[0].environment = ""; }, /GitHub Environment name or null/],
    ["no events", (p) => { p.oidc.purposes[0].rules[0].events = []; }, /distinct GitHub event names/],
    ["duplicate events", (p) => { p.oidc.purposes[0].rules[0].events = ["push", "push"]; }, /distinct GitHub event names/],
    ["wildcard ref", (p) => { p.oidc.purposes[0].rules[0].ref = "refs/heads/*"; }, /one exact branch ref/],
    ["tag ref", (p) => { p.oidc.purposes[0].rules[0].ref = "refs/tags/v1"; }, /one exact branch ref/],
    ["pull request ref", (p) => { p.oidc.purposes[0].rules[0].ref = "refs/pull/1/merge"; }, /one exact branch ref/],
    ["dot-dot ref", (p) => { p.oidc.purposes[0].rules[0].ref = "refs/heads/main/../x"; }, /one exact branch ref/],
    ["read_only as a string", (p) => { p.oidc.purposes[0].rules[1].read_only = "yes"; }, /read_only must be true or false/],
    [
      "write for a Plan run",
      (p) => { delete p.oidc.purposes[0].rules[1].read_only; },
      /admits an event that a person without write access can start; set read_only: true/,
    ],
    [
      "write for a comment",
      (p) => { p.oidc.purposes[0].rules[0].events = ["push", "issue_comment"]; },
      /admits an event that a person without write access can start/,
    ],
    ["zero grants per run", (p) => { p.oidc.purposes[0].max_grants_per_run = 0; }, /from 1 to 100/],
    ["unbounded grants per run", (p) => { p.oidc.purposes[0].max_grants_per_run = 101; }, /from 1 to 100/],
    ["fractional grants per run", (p) => { p.oidc.purposes[0].max_grants_per_run = 1.5; }, /from 1 to 100/],
    [
      "caller purpose without a Deployment Repo of this Organization",
      (p) => { p.oidc.deployment_repositories = [{ repository_id: 7101, repository_owner_id: 7001 }]; },
      /needs a Deployment Repo of the policy's Organization/,
    ],
  ];
  for (const [label, mutate, expected] of cases) {
    const policy = oidcPolicyFixture();
    mutate(policy);
    assert.throws(() => parsePolicy(policy), expected, label);
  }
});

test("both published example policies parse", () => {
  const examples = new URL("../examples/", import.meta.url);
  assert.equal(parsePolicy(readFileSync(new URL("policy.example.json", examples), "utf8")).oidc, undefined);
  const oidc = parsePolicy(readFileSync(new URL("policy.oidc.example.json", examples), "utf8")).oidc;
  assert.deepEqual(oidc.purposes.map(({ purpose }) => purpose), ["deployment-apply", "machines-release"]);
});

test("a broker with oidc purposes may hold no Workspace; without them a Workspace stays required", () => {
  const oidcOnly = oidcPolicyFixture();
  oidcOnly.workspaces = [];
  assert.deepEqual(parsePolicy(oidcOnly).workspaces, []);

  delete oidcOnly.oidc;
  assert.throws(() => parsePolicy(oidcOnly), /workspaces must be a non-empty array/);
});

test("the token body is exactly one purpose name", () => {
  assert.equal(parseOidcTokenRequest('{"purpose":"deployment-apply"}'), "deployment-apply");
  for (const body of [
    "",
    "{",
    "[]",
    "{}",
    '{"purpose":1}',
    '{"purpose":"Deployment"}',
    '{"purpose":"deployment-apply","repository":"example-org/other"}',
    '{"purpose":"deployment-apply","repository_id":3201}',
    '{"repository":"example-org/deployment"}',
  ]) {
    assert.equal(parseOidcTokenRequest(body), undefined, body);
  }
});

// ---------------------------------------------------------------------------------------------
// Admission matrix: every refusal first, then the grants
// ---------------------------------------------------------------------------------------------

test("admission refuses a repository that is not an allowlisted Deployment Repo before anything else", () => {
  // Any GitHub workflow can obtain a token for this audience; a stranger learns only this code.
  for (const purpose of ["deployment-apply", "machines-release", "no-such-purpose"]) {
    assert.equal(refusalOf(() => admit({ repository_id: "3999", repository: "example-org/scratch" }, purpose)), "repository_not_admitted");
  }
  assert.equal(refusalOf(() => admit({ repository_id: "3999", runner_environment: "self-hosted" })), "repository_not_admitted");
});

test("admission binds each Deployment Repo to its owner id, so a transferred repository is refused", () => {
  assert.equal(refusalOf(() => admit({ repository_owner_id: "7001" })), "repository_owner_mismatch");
  assert.equal(refusalOf(() => admit({ repository_owner_id: "7001" }, "machines-release")), "repository_owner_mismatch");
});

test("admission refuses a purpose this broker does not configure", () => {
  assert.equal(refusalOf(() => admit({}, "gateway-ledger-read")), "purpose_unknown");
});

test("deployment-apply refuses an allowlisted Deployment Repo of another Organization", () => {
  assert.equal(refusalOf(() => admit(OTHER_ORG)), "repository_denied");
  assert.equal(refusalOf(() => admit({ ...OTHER_ORG, ...PLAN_RUN })), "repository_denied");
});

test("admission refuses self-hosted runners unless the policy admits them", () => {
  assert.equal(refusalOf(() => admit({ runner_environment: "self-hosted" })), "runner_not_allowed");
  assert.equal(refusalOf(() => admit({ runner_environment: "custom" }, "machines-release")), "runner_not_allowed");

  const allowing = oidcPolicyFixture();
  allowing.oidc.runner_environments = ["github-hosted", "self-hosted"];
  assert.equal(admit({ runner_environment: "self-hosted" }, "deployment-apply", parsePolicy(allowing)).access, "write");
});

test("admission refuses every event, ref, workflow, job workflow and environment outside the rules", () => {
  const deploymentWorkflow = (suffix) => `example-org/deployment/${suffix}`;
  const cases = [
    [{ event_name: "pull_request" }, "event_not_allowed"],
    [{ event_name: "schedule", environment: null }, "event_not_allowed"],
    [{ event_name: "workflow_run" }, "event_not_allowed"],
    [{ ref: "refs/heads/feature" }, "ref_not_allowed"],
    [{ event_name: "pull_request_target", environment: null, ref: "refs/pull/7/merge" }, "ref_not_allowed"],
    [{ ref: "refs/tags/v1.0.0" }, "ref_not_allowed"],
    [
      { workflow_ref: deploymentWorkflow(".github/workflows/other.yml@refs/heads/main") },
      "workflow_not_allowed",
    ],
    [
      { workflow_ref: deploymentWorkflow(`${WORKFLOW}@refs/heads/feature`) },
      "workflow_not_allowed",
    ],
    [
      { workflow_ref: `example-org/elsewhere/${WORKFLOW}@refs/heads/main` },
      "workflow_not_allowed",
    ],
    [
      { job_workflow_ref: `other-org/shared/.github/workflows/apply.yml@refs/heads/main` },
      "job_workflow_not_allowed",
    ],
    [{ environment: null }, "environment_mismatch"],
    [{ environment: "staging" }, "environment_mismatch"],
    [{ event_name: "workflow_dispatch", environment: "Production" }, "environment_mismatch"],
    [{ event_name: "pull_request_target", environment: "production" }, "environment_mismatch"],
  ];
  for (const [overrides, code] of cases) {
    assert.equal(refusalOf(() => admit(overrides)), code, JSON.stringify(overrides));
  }
  assert.equal(refusalOf(() => admit({ ...OTHER_ORG, event_name: "pull_request" }, "machines-release")), "event_not_allowed");
  assert.equal(refusalOf(() => admit({ ...OTHER_ORG, environment: "staging" }, "machines-release")), "environment_mismatch");
});

test("admission keys on workflow_ref; job_workflow_ref may be absent, may equal it, and is refused when it differs", () => {
  const reusable = "other-org/shared/.github/workflows/apply.yml@refs/heads/main";
  const ownReusable = `example-org/deployment/.github/workflows/apply-reusable.yml@refs/heads/main`;
  for (const [purpose, job] of [
    ["deployment-apply", {}],
    ["deployment-apply", PLAN_RUN],
    ["machines-release", {}],
    ["machines-release", PLAN_RUN],
    ["machines-release", OTHER_ORG],
  ]) {
    const label = `${purpose} ${JSON.stringify(job)}`;
    // A job defined directly in the admitted workflow file: GitHub need not send the claim.
    assert.equal(admit({ ...job, job_workflow_ref: null }, purpose).purpose, purpose, `absent: ${label}`);
    assert.equal(admit({ ...job, job_workflow_ref: undefined }, purpose).purpose, purpose, `undefined: ${label}`);
    // The same job when GitHub does send it: it names the admitted file itself.
    assert.equal(admit(job, purpose).purpose, purpose, `equal: ${label}`);
    // A job that runs a reusable workflow, of another repository or of the caller's own: refused.
    for (const job_workflow_ref of [reusable, ownReusable]) {
      assert.equal(refusalOf(() => admit({ ...job, job_workflow_ref }, purpose)), "job_workflow_not_allowed", `different: ${label}`);
    }
  }
  // Absence never stands in for the workflow itself: workflow_ref still decides.
  assert.equal(
    refusalOf(() => admit({ job_workflow_ref: null, workflow_ref: `example-org/deployment/.github/workflows/other.yml@refs/heads/main` })),
    "workflow_not_allowed",
  );
});

test("admission names the check of the rule that came closest to admitting the run", () => {
  // The push rule fails only at its environment; the Plan rule already fails at its event.
  assert.equal(refusalOf(() => admit({ environment: "staging" })), "environment_mismatch");
  // Both rules fail at the ref: the refusal is the furthest check any rule reached.
  assert.equal(refusalOf(() => admit({ event_name: "pull_request_target", environment: null, ref: "refs/heads/dev" })), "ref_not_allowed");
});

test("admission refuses claims that are not GitHub's decimal ids", () => {
  assert.equal(refusalOf(() => admit({ repository_id: "03101" })), "token_claims_invalid");
  assert.equal(refusalOf(() => admit({ repository_owner_id: 1001 })), "token_claims_invalid");
});

test("deployment-apply admits a push or dispatch on main in production with exactly its permission set", () => {
  for (const event_name of ["push", "workflow_dispatch"]) {
    assert.deepEqual(admit({ event_name }), {
      purpose: "deployment-apply",
      repository_id: 3101,
      permissions: DEPLOYMENT_APPLY,
      access: "write",
      max_grants_per_run: 2,
    });
  }
});

test("a Plan run of deployment-apply gets the same permissions lowered to read", () => {
  assert.deepEqual(admit(PLAN_RUN), {
    purpose: "deployment-apply",
    repository_id: 3101,
    permissions: DEPLOYMENT_PLAN,
    access: "read",
    max_grants_per_run: 2,
  });
});

test("machines-release admits any allowlisted Deployment Repo for the fixed repository and contents: read only", () => {
  for (const overrides of [{}, PLAN_RUN, OTHER_ORG, { ...OTHER_ORG, ...PLAN_RUN }, { ...OTHER_ORG, event_name: "workflow_dispatch" }]) {
    assert.deepEqual(admit(overrides, "machines-release"), {
      purpose: "machines-release",
      repository_id: 3201,
      permissions: RELEASE_READ,
      access: "read",
      max_grants_per_run: 4,
    }, JSON.stringify(overrides));
  }
});

test("a later purpose is one more policy entry, not code", () => {
  const policy = oidcPolicyFixture();
  policy.oidc.purposes.push({
    purpose: "gateway-ledger-read",
    repository: "caller",
    workflow: ".github/workflows/lazurio-ledger-probe.yml",
    rules: [{ events: ["schedule", "workflow_dispatch"], ref: "refs/heads/main", environment: null }],
    permissions: { contents: "read" },
    max_grants_per_run: 1,
  });
  const ledgerRef = `example-org/deployment/.github/workflows/lazurio-ledger-probe.yml@refs/heads/main`;
  const admitted = admitOidcRequest(
    parsePolicy(policy),
    claimsFixture({ event_name: "schedule", environment: null, workflow_ref: ledgerRef, job_workflow_ref: ledgerRef }),
    "gateway-ledger-read",
  );
  assert.deepEqual(admitted.permissions, { contents: "read" });
  assert.equal(admitted.repository_id, 3101);
});

// ---------------------------------------------------------------------------------------------
// OIDC token verification with jose
// ---------------------------------------------------------------------------------------------

const NOW_SECONDS = Math.floor(Date.now() / 1000);
const keyPair = await generateKeyPair("RS256", { extractable: true });
const otherKeyPair = await generateKeyPair("RS256", { extractable: true });
const publicJwk = { ...(await exportJWK(keyPair.publicKey)), kid: "github-key-1", alg: "RS256", use: "sig" };
const otherPublicJwk = { ...(await exportJWK(otherKeyPair.publicKey)), kid: "github-key-2", alg: "RS256", use: "sig" };
const localKeySet = createLocalJWKSet({ keys: [publicJwk] });

/** A GitHub-shaped OIDC token for `claimsFixture`, signed like GitHub signs it. */
async function signedToken(
  overrides = {},
  { privateKey = keyPair.privateKey, header = { alg: "RS256", kid: "github-key-1", typ: "JWT" }, omit = [] } = {},
) {
  const { exp: _exp, iat: _iat, ...claims } = claimsFixture();
  const payload = {
    iss: GITHUB_ACTIONS_ISSUER,
    aud: AUDIENCE,
    sub: "repo:example-org/deployment:environment:production",
    nbf: NOW_SECONDS - 600,
    iat: NOW_SECONDS,
    exp: NOW_SECONDS + 300,
    ...claims,
    jti: `jti-${Math.random().toString(36).slice(2)}-${Date.now()}`,
    ...overrides,
  };
  for (const name of omit) delete payload[name];
  if (payload.environment === null) delete payload.environment;
  return new SignJWT(payload).setProtectedHeader(header).sign(privateKey);
}

/**
 * The claim set GitHub documents for a job defined directly in its workflow file, as runner mode's
 * `plan` and `apply` jobs are: no reusable-workflow claim `job_workflow_ref`, plus the claims the
 * broker does not read (`sub`, `workflow`, `ref_type`, `x5t`, ...). `plan` makes it the
 * `pull_request_target` Plan job, which runs without a GitHub Environment.
 */
async function plainJobToken({ plan = false, ...overrides } = {}) {
  const repository = "example-org/deployment";
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    jti: crypto.randomUUID(),
    sub: plan ? `repo:${repository}:pull_request` : `repo:${repository}:environment:production`,
    ...(plan ? {} : { environment: "production" }),
    aud: AUDIENCE,
    ref: "refs/heads/main",
    sha: "b".repeat(40),
    repository,
    repository_owner: "example-org",
    actor_id: "5001",
    repository_visibility: "private",
    repository_id: "3101",
    repository_owner_id: "1001",
    run_id: plan ? "9201" : "9202",
    run_number: "12",
    run_attempt: "1",
    runner_environment: "github-hosted",
    actor: "example-user",
    workflow: "Lazurio rollout",
    head_ref: plan ? "lane-change" : "",
    base_ref: plan ? "main" : "",
    event_name: plan ? "pull_request_target" : "push",
    ref_type: "branch",
    workflow_ref: `${repository}/${WORKFLOW}@refs/heads/main`,
    workflow_sha: "b".repeat(40),
    iss: GITHUB_ACTIONS_ISSUER,
    nbf: now - 300,
    exp: now + 300,
    iat: now,
    ...overrides,
  };
  return new SignJWT(payload)
    .setProtectedHeader({ typ: "JWT", alg: "RS256", x5t: "example-thumbprint", kid: "github-key-1" })
    .sign(keyPair.privateKey);
}

function verifier(keySet = localKeySet, now = () => NOW_SECONDS * 1000) {
  return createOidcVerifier({ audience: AUDIENCE, keySet, now });
}

async function verifyRefusal(verify, token) {
  try {
    await verify(token);
  } catch (error) {
    assert.ok(error instanceof OidcRefusal, `expected an OIDC refusal, got ${error}`);
    return error.code;
  }
  assert.fail("expected a refusal");
}

test("the verifier returns GitHub's signed claims, with a job without an Environment as null", async () => {
  const claims = await verifier()(await signedToken());
  assert.equal(claims.repository_id, "3101");
  assert.equal(claims.repository_owner_id, "1001");
  assert.equal(claims.environment, "production");
  assert.equal(claims.workflow_ref, `example-org/deployment/${WORKFLOW}@refs/heads/main`);
  assert.equal(claims.exp, NOW_SECONDS + 300);

  const plan = await verifier()(await signedToken({ event_name: "pull_request_target", environment: null }));
  assert.equal(plan.environment, null);
  assert.equal(plan.event_name, "pull_request_target");
});

test("the verifier accepts a job without job_workflow_ref, keeps one GitHub sent and refuses an invalid one", async () => {
  const verify = verifier(localKeySet, () => Date.now());
  // A job defined directly in its workflow file need not carry the reusable-workflow claim.
  for (const plan of [false, true]) {
    const claims = await verify(await plainJobToken({ plan }));
    assert.equal(claims.job_workflow_ref, null);
    assert.equal(claims.workflow_ref, `example-org/deployment/${WORKFLOW}@refs/heads/main`);
    assert.equal(claims.environment, plan ? null : "production");
  }
  // When GitHub sends it, the verifier passes it on unchanged for admission to compare.
  const sent = `example-org/deployment/${WORKFLOW}@refs/heads/main`;
  assert.equal((await verify(await plainJobToken({ job_workflow_ref: sent }))).job_workflow_ref, sent);
  const reusable = "other-org/shared/.github/workflows/apply.yml@refs/heads/main";
  assert.equal((await verify(await plainJobToken({ job_workflow_ref: reusable }))).job_workflow_ref, reusable);
  // Present but not a claim GitHub could have sent.
  for (const job_workflow_ref of ["", 42, null, ["x"], "x".repeat(513)]) {
    assert.equal(await verifyRefusal(verify, await plainJobToken({ job_workflow_ref })), "token_claims_invalid", JSON.stringify(job_workflow_ref));
  }
  // workflow_ref, which GitHub sends on every token, stays required.
  assert.equal(await verifyRefusal(verify, await plainJobToken({ workflow_ref: undefined })), "token_claims_invalid");
});

test("the verifier refuses missing, malformed, key-less and oversized tokens", async () => {
  const verify = verifier();
  assert.equal(await verifyRefusal(verify, ""), "token_missing");
  const good = await signedToken();
  const [header, payload] = good.split(".");
  const unsignedHeader = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  for (const token of [
    "not-a-token",
    `${header}.${payload}`,
    `${header}.${payload}.`,
    `${unsignedHeader({ alg: "none", kid: "github-key-1" })}.${payload}.`,
    `${Buffer.from("{not json").toString("base64url")}.${payload}.c2ln`,
    `${header}.${payload}.${"A".repeat(9000)}`,
    await signedToken({}, { header: { alg: "RS256", typ: "JWT" } }),
  ]) {
    assert.equal(await verifyRefusal(verify, token), "token_malformed", token.slice(0, 40));
  }
});

test("the verifier refuses other algorithms, unknown keys and broken signatures", async () => {
  const verify = verifier();
  const hmac = await new SignJWT({ iss: GITHUB_ACTIONS_ISSUER, aud: AUDIENCE, iat: NOW_SECONDS, exp: NOW_SECONDS + 300 })
    .setProtectedHeader({ alg: "HS256", kid: "github-key-1" })
    .sign(new TextEncoder().encode("a-shared-secret-of-at-least-32-bytes!!"));
  assert.equal(await verifyRefusal(verify, hmac), "token_algorithm_refused");

  const foreignKey = await signedToken({}, { privateKey: otherKeyPair.privateKey, header: { alg: "RS256", kid: "github-key-2" } });
  assert.equal(await verifyRefusal(verify, foreignKey), "token_key_unknown");

  // A real GitHub key id, but signed by another key.
  const forged = await signedToken({}, { privateKey: otherKeyPair.privateKey });
  assert.equal(await verifyRefusal(verify, forged), "token_signature_invalid");

  // A signature moved onto other claims.
  const [header, , signature] = (await signedToken()).split(".");
  const [, otherPayload] = (await signedToken({ repository_id: "3201" })).split(".");
  assert.equal(await verifyRefusal(verify, `${header}.${otherPayload}.${signature}`), "token_signature_invalid");
});

test("the verifier refuses another issuer or audience, expired, future and incomplete tokens", async () => {
  const verify = verifier();
  assert.equal(await verifyRefusal(verify, await signedToken({ iss: "https://token.actions.example.com" })), "token_issuer_mismatch");
  for (const aud of ["https://gateway.example.com", `${AUDIENCE}/`, [`${AUDIENCE}/v1`]]) {
    assert.equal(await verifyRefusal(verify, await signedToken({ aud })), "token_audience_mismatch", JSON.stringify(aud));
  }
  // jose accepts an audience array that merely contains the broker's origin; the broker does not.
  for (const aud of [
    [AUDIENCE, "https://gateway.example.com"],
    ["https://gateway.example.com", AUDIENCE],
    [AUDIENCE, AUDIENCE],
  ]) {
    assert.equal(await verifyRefusal(verify, await signedToken({ aud })), "token_audience_mismatch", JSON.stringify(aud));
  }
  // The origin as the only audience, as a string or a one-element array, is the same audience.
  assert.equal((await verify(await signedToken({ aud: [AUDIENCE] }))).repository_id, "3101");
  assert.equal(await verifyRefusal(verify, await signedToken({ iat: NOW_SECONDS - 400, exp: NOW_SECONDS - 61 })), "token_expired");
  assert.equal((await verify(await signedToken({ iat: NOW_SECONDS - 400, exp: NOW_SECONDS - 59 }))).repository_id, "3101");
  assert.equal(await verifyRefusal(verify, await signedToken({ nbf: NOW_SECONDS + 120 })), "token_not_yet_valid");
  assert.equal(await verifyRefusal(verify, await signedToken({ iat: NOW_SECONDS + 120, exp: NOW_SECONDS + 420 })), "token_not_yet_valid");
  for (const name of ["exp", "iat", "repository_id", "repository_owner_id", "workflow_ref", "run_id", "runner_environment", "jti"]) {
    assert.equal(await verifyRefusal(verify, await signedToken({}, { omit: [name] })), "token_claims_invalid", name);
  }
  for (const overrides of [{ repository_id: 3101 }, { run_id: "12a" }, { run_attempt: "0" }, { environment: "" }, { repository: "example-org" }]) {
    assert.equal(await verifyRefusal(verify, await signedToken(overrides)), "token_claims_invalid", JSON.stringify(overrides));
  }
});

test("GitHub's remote key set: unavailability is 503, a rotated key is refetched once per cooldown", async () => {
  const unavailable = [
    async () => { throw new TypeError("fetch failed"); },
    async () => new Response("busy", { status: 503 }),
    async () => new Response("not json", { status: 200 }),
    async (_url, init) => new Promise((_resolve, reject) => init.signal.addEventListener("abort", () => reject(init.signal.reason))),
  ];
  // AbortSignal.timeout does not keep the event loop alive on its own.
  const keepAlive = setInterval(() => {}, 10);
  try {
    for (const fetchImpl of unavailable) {
      const verify = verifier(createGithubActionsKeySet({ fetchImpl, timeoutMs: 20 }));
      assert.equal(await verifyRefusal(verify, await signedToken()), "jwks_unavailable");
    }
  } finally {
    clearInterval(keepAlive);
  }

  let fetches = 0;
  let keys = [publicJwk];
  const rotating = createGithubActionsKeySet({
    fetchImpl: async (url, init) => {
      fetches += 1;
      assert.equal(String(url), "https://token.actions.githubusercontent.com/.well-known/jwks");
      assert.equal(init.redirect, "manual");
      return Response.json({ keys });
    },
    cooldownMs: 60_000,
  });
  const verify = verifier(rotating);
  await verify(await signedToken());
  assert.equal(fetches, 1);
  await verify(await signedToken());
  assert.equal(fetches, 1, "the key set is cached");

  keys = [publicJwk, otherPublicJwk];
  const rotated = await signedToken({}, { privateKey: otherKeyPair.privateKey, header: { alg: "RS256", kid: "github-key-2" } });
  // The first fetch is younger than the cooldown, so an unknown key id is not refetched yet.
  assert.equal(await verifyRefusal(verify, rotated), "token_key_unknown");
  assert.equal(fetches, 1);

  const eager = createGithubActionsKeySet({ fetchImpl: async () => { fetches += 1; return Response.json({ keys }); }, cooldownMs: 0 });
  keys = [publicJwk];
  const eagerVerify = verifier(eager);
  await eagerVerify(await signedToken());
  keys = [publicJwk, otherPublicJwk];
  const before = fetches;
  assert.equal((await eagerVerify(rotated)).repository_id, "3101");
  assert.equal(fetches, before + 1, "an unknown key id triggers exactly one refetch");
});

// ---------------------------------------------------------------------------------------------
// Per-run guard: one use per token id, a grant budget per purpose and run
// ---------------------------------------------------------------------------------------------

function memoryStorage() {
  const data = new Map();
  let alarm = null;
  return {
    data,
    get alarm() {
      return alarm;
    },
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

test("the run guard accepts each token id once and each purpose up to its per-run budget", async () => {
  const storage = memoryStorage();
  const now = 1_800_000_000_000;
  const exp = now / 1000 + 300;
  const grant = (jti, purpose = "deployment-apply", limit = 2) => admitRunGrant(storage, { jti, expires_at: exp, purpose, limit }, now);

  assert.equal(await grant("jti-1"), "admitted");
  assert.equal(storage.alarm, now + RUN_GUARD_RETENTION_MS);
  assert.equal(await grant("jti-1"), "replayed");
  assert.equal(await grant("jti-1", "machines-release", 4), "replayed", "a token id is spent for every purpose");
  assert.equal(await grant("jti-2"), "admitted");
  assert.equal(await grant("jti-3"), "rate_limited");
  assert.equal(await grant("jti-3"), "rate_limited", "a refused token id is not recorded");
  assert.equal(await grant("jti-3", "machines-release", 4), "admitted", "each purpose has its own budget");
  assert.equal(storage.alarm, now + RUN_GUARD_RETENTION_MS, "the retention alarm is set once");

  for (const invalid of [
    { jti: "", expires_at: exp, purpose: "deployment-apply", limit: 2 },
    { jti: "has space", expires_at: exp, purpose: "deployment-apply", limit: 2 },
    { jti: "jti-9", expires_at: "1", purpose: "deployment-apply", limit: 2 },
    { jti: "jti-9", expires_at: exp, purpose: "__proto__", limit: 2 },
    { jti: "jti-9", expires_at: exp, purpose: "deployment-apply", limit: 0 },
  ]) {
    await assert.rejects(() => admitRunGrant(storage, invalid, now), /run guard request is invalid/);
  }
});

test("the run guard forgets token ids only after they can no longer verify", async () => {
  const storage = memoryStorage();
  const now = 1_800_000_000_000;
  const exp = now / 1000 + 300;
  await admitRunGrant(storage, { jti: "jti-1", expires_at: exp, purpose: "machines-release", limit: 4 }, now);
  // Within the verifier's tolerance the token could still be presented: still a replay.
  assert.equal(await admitRunGrant(storage, { jti: "jti-1", expires_at: exp, purpose: "machines-release", limit: 4 }, (exp + 60) * 1000), "replayed");
  // Long after expiry the id is pruned, but the grant count of the run is kept.
  assert.equal(await admitRunGrant(storage, { jti: "jti-2", expires_at: exp, purpose: "machines-release", limit: 4 }, (exp + 600) * 1000), "admitted");
  assert.deepEqual(storage.data.get("run").jtis.map(([jti]) => jti), ["jti-2"]);
  assert.deepEqual(storage.data.get("run").grants, [["machines-release", 2]]);
});

test("the Durable Object answers decisions, refuses bad input and deletes the run on its alarm", async () => {
  const storage = memoryStorage();
  const guard = new OidcRunGuard({ storage });
  const ask = (body) => guard.fetch(new Request("https://oidc-run-guard.invalid/admit", { method: "POST", body }));
  const exp = Math.floor(Date.now() / 1000) + 300;
  const body = JSON.stringify({ jti: "jti-1", expires_at: exp, purpose: "deployment-apply", limit: 1 });
  assert.deepEqual(await (await ask(body)).json(), { decision: "admitted" });
  assert.deepEqual(await (await ask(body)).json(), { decision: "replayed" });
  assert.equal((await ask("{")).status, 400);
  assert.equal((await ask(JSON.stringify({ jti: "jti-2" }))).status, 400);
  await guard.alarm();
  assert.equal(storage.data.size, 0);
  assert.equal(storage.alarm, null);
});

// ---------------------------------------------------------------------------------------------
// Handler: the route, its order of gates and the audit lines
// ---------------------------------------------------------------------------------------------

function fakeGuard(decisions = []) {
  const calls = [];
  return {
    calls,
    async admit(request) {
      calls.push(request);
      const next = decisions.shift() ?? "admitted";
      if (next instanceof Error) throw next;
      return next;
    },
  };
}

function purposeMint(calls) {
  return async (_policy, repositoryId, permissions) => {
    calls.push({ repositoryId, permissions });
    return {
      token: `ghs_${"p".repeat(36)}`,
      expires_at: "2030-01-01T00:00:00Z",
      repository_id: repositoryId,
      repository: REPOSITORIES.get(repositoryId).full_name,
      permissions,
    };
  };
}

function oidcHandler({
  claims = claimsFixture(),
  verify = async (token) => {
    if (token !== "verified-oidc-token") throw new OidcRefusal("token_signature_invalid");
    return claims;
  },
  guard = fakeGuard(),
  mintPurposeToken,
  policy = parsePolicy(oidcPolicyFixture()),
} = {}) {
  const mints = [];
  const records = [];
  const handle = createBrokerHandler({
    policy,
    credentials: new Map([["alpha-team", ALPHA_CREDENTIAL]]),
    secretMatches: async (actual, expected) => actual === expected,
    github: {
      verifyTeamGrant: async () => assert.fail("the Team gate is not part of the OIDC route"),
      verifyWorkspaceTeam: async () => assert.fail("the Workspace proof is not part of the OIDC route"),
      mintToken: async () => assert.fail("the Workspace mint is not part of the OIDC route"),
      mintPurposeToken: mintPurposeToken ?? purposeMint(mints),
    },
    oidc: { verify, guard, audit: (record) => records.push(record), now: () => Date.parse("2026-10-17T12:00:00Z") },
  });
  return { handle, mints, records, guard };
}

function oidcCall(handle, { token = "verified-oidc-token", body = { purpose: "deployment-apply" }, contentType = "application/json", reads } = {}) {
  return handle({
    method: "POST",
    path: "/v1/oidc/token",
    contentType,
    authorization: token === null ? "" : `Bearer ${token}`,
    readBody: async () => {
      if (reads) reads.count += 1;
      return typeof body === "string" ? body : JSON.stringify(body);
    },
  });
}

test("the OIDC route does not exist without an oidc policy or without the adapter's OIDC capabilities", async () => {
  const withoutPolicy = oidcPolicyFixture();
  delete withoutPolicy.oidc;
  const { handle } = oidcHandler({ policy: parsePolicy(withoutPolicy) });
  assert.deepEqual(await oidcCall(handle), { status: 404, body: { error: "not_found" } });

  // The Node adapter passes no OIDC capabilities: the same policy serves Workspaces only there.
  const server = createBrokerServer({
    policy: parsePolicy(oidcPolicyFixture()),
    github: { verifyTeamGrant: async () => {}, verifyWorkspaceTeam: async () => {}, mintToken: async () => {} },
    readFile: () => ALPHA_CREDENTIAL,
    realpath: (file) => file,
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/v1/oidc/token`, {
      method: "POST",
      headers: { Authorization: "Bearer verified-oidc-token", "Content-Type": "application/json" },
      body: '{"purpose":"deployment-apply"}',
    });
    assert.equal(response.status, 404);
  } finally {
    server.close();
    await once(server, "close");
  }
});

test("refusals before admission read no body or GitHub and each writes one audit line", async () => {
  const { handle, mints, records, guard } = oidcHandler();
  const reads = { count: 0 };
  assert.deepEqual(await oidcCall(handle, { contentType: "text/plain", reads }), { status: 415, body: { error: "unsupported_media_type" } });
  assert.deepEqual(await oidcCall(handle, { token: null, reads }), { status: 401, body: { error: "token_missing" } });
  assert.deepEqual(await oidcCall(handle, { token: "forged-oidc-token", reads }), { status: 401, body: { error: "token_signature_invalid" } });
  assert.equal(reads.count, 0);

  for (const body of ["{", {}, { purpose: "Deployment" }, { purpose: "deployment-apply", repository_id: 3201 }]) {
    assert.deepEqual(await oidcCall(handle, { body }), { status: 400, body: { error: "invalid_request" } });
  }
  assert.equal(mints.length, 0);
  assert.equal(guard.calls.length, 0);
  assert.equal(records.length, 7);
  assert.deepEqual(records.map(({ code }) => code), [
    "unsupported_media_type",
    "token_missing",
    "token_signature_invalid",
    "invalid_request",
    "invalid_request",
    "invalid_request",
    "invalid_request",
  ]);
  assert.ok(records.every(({ decision, grant }) => decision === "refused" && grant === null));
  assert.deepEqual(records.slice(0, 3).map(({ caller }) => caller), [null, null, null], "no claims before verification");
  assert.equal(records[3].caller.repository_id, "3101");
});

test("verifier outcomes keep their status: 401 for a bad token, 503 when GitHub's keys are unavailable", async () => {
  for (const code of ["token_expired", "token_audience_mismatch", "token_key_unknown", "jwks_unavailable"]) {
    const { handle, records } = oidcHandler({ verify: async () => { throw new OidcRefusal(code); } });
    assert.deepEqual(await oidcCall(handle), { status: OIDC_REFUSALS[code], body: { error: code } });
    assert.equal(records[0].code, code);
  }
  assert.equal(OIDC_REFUSALS.jwks_unavailable, 503);
  const { handle } = oidcHandler({ verify: async () => { throw new Error("verifier defect"); } });
  assert.deepEqual(await oidcCall(handle), { status: 502, body: { error: "token_unavailable" } });
});

test("admission refusals reach neither the run guard nor GitHub", async () => {
  for (const [claims, purpose, code] of [
    [claimsFixture({ repository_id: "3999" }), "deployment-apply", "repository_not_admitted"],
    [claimsFixture(OTHER_ORG), "deployment-apply", "repository_denied"],
    [claimsFixture({ ref: "refs/heads/feature" }), "deployment-apply", "ref_not_allowed"],
    [claimsFixture(), "gateway-ledger-read", "purpose_unknown"],
  ]) {
    const { handle, mints, records, guard } = oidcHandler({ claims });
    assert.deepEqual(await oidcCall(handle, { body: { purpose } }), { status: 403, body: { error: code } });
    assert.equal(guard.calls.length, 0);
    assert.equal(mints.length, 0);
    assert.equal(records[0].purpose, purpose);
    assert.equal(records[0].caller.repository_id, claims.repository_id);
  }
});

test("the run guard decides before GitHub: a replay is 401, an exhausted budget 429, a guard outage 502", async () => {
  for (const [decision, status, code] of [
    ["replayed", 401, "token_replayed"],
    ["rate_limited", 429, "rate_limited"],
    ["maybe", 502, "token_unavailable"],
    [new Error("Durable Object unavailable"), 502, "token_unavailable"],
  ]) {
    const { handle, mints, records, guard } = oidcHandler({ guard: fakeGuard([decision]) });
    assert.deepEqual(await oidcCall(handle), { status, body: { error: code } });
    assert.equal(mints.length, 0);
    assert.deepEqual(guard.calls, [
      { key: "3101/9001/1", jti: claimsFixture().jti, expires_at: claimsFixture().exp, purpose: "deployment-apply", limit: 2 },
    ]);
    assert.equal(records[0].code, code);
  }
});

test("a grant returns one repository, the exact permissions and the access; the audit line holds no token", async () => {
  const { handle, mints, records } = oidcHandler();
  const response = await oidcCall(handle);
  assert.deepEqual(response, {
    status: 200,
    body: {
      token: `ghs_${"p".repeat(36)}`,
      expires_at: "2030-01-01T00:00:00Z",
      repository_id: 3101,
      repository: "example-org/deployment",
      access: "write",
      permissions: DEPLOYMENT_APPLY,
    },
  });
  assert.deepEqual(mints, [{ repositoryId: 3101, permissions: DEPLOYMENT_APPLY }]);
  assert.equal(records.length, 1);
  const [record] = records;
  assert.deepEqual(
    { ...record, caller: undefined },
    {
      schema_version: "lazurio.github_app_broker.audit.v1",
      at: "2026-10-17T12:00:00.000Z",
      event: "oidc_token",
      decision: "granted",
      status: 200,
      code: "granted",
      purpose: "deployment-apply",
      caller: undefined,
      grant: {
        repository_id: 3101,
        repository: "example-org/deployment",
        access: "write",
        permissions: DEPLOYMENT_APPLY,
        expires_at: "2030-01-01T00:00:00Z",
      },
    },
  );
  assert.equal(record.caller.run_id, "9001");
  assert.equal(record.caller.workflow_ref, `example-org/deployment/${WORKFLOW}@refs/heads/main`);
  assert.equal(JSON.stringify(records).includes("ghs_"), false);
  assert.equal(JSON.stringify(records).includes("verified-oidc-token"), false);
});

test("a mint outside the admitted repository or set, or a GitHub failure, is 502 and audited", async () => {
  for (const mintPurposeToken of [
    async () => { throw new Error("GitHub request failed with HTTP 422"); },
    async (_policy, repositoryId, permissions) => ({ token: "ghs_x", expires_at: "2030", repository_id: repositoryId + 1, repository: "example-org/x", permissions }),
    async (_policy, repositoryId) => ({ token: "ghs_x", expires_at: "2030", repository_id: repositoryId, repository: "example-org/x", permissions: { contents: "write" } }),
  ]) {
    const { handle, records } = oidcHandler({ mintPurposeToken });
    assert.deepEqual(await oidcCall(handle), { status: 502, body: { error: "token_unavailable" } });
    assert.equal(records[0].code, "token_unavailable");
    assert.equal(records[0].grant, null);
  }
});

test("Workspace credentials and OIDC tokens never cross routes", async () => {
  const { handle } = oidcHandler();
  // An OIDC token is not a Workspace credential.
  const workspaceRoute = await handle({
    method: "POST",
    path: "/v1/token",
    contentType: "application/json",
    workspaceId: "alpha-team",
    authorization: "Bearer verified-oidc-token",
    readBody: async () => '{"repository":"example-org/deployment"}',
  });
  assert.deepEqual(workspaceRoute, { status: 401, body: { error: "workspace_unauthorized" } });
  // A Workspace credential is not an OIDC token (here through the real verifier).
  const real = oidcHandler({ verify: verifier() });
  assert.deepEqual(await oidcCall(real.handle, { token: ALPHA_CREDENTIAL }), { status: 401, body: { error: "token_malformed" } });
});

// ---------------------------------------------------------------------------------------------
// Token scoping and revocation against a synthetic GitHub
// ---------------------------------------------------------------------------------------------

function syntheticGithub({ installationPermissions = oidcPolicyFixture().installation_permissions, mint } = {}) {
  const calls = [];
  const revoked = new Set();
  let serial = 0;
  const fetchImpl = async (url, init) => {
    const path = new URL(url).pathname;
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ method: init.method, path, authorization: init.headers.Authorization, body });
    if (path === "/app/installations/2001" && init.method === "GET") {
      return Response.json({
        app_id: 42,
        app_slug: "example-app",
        account: { id: 1001, login: "example-org" },
        target_type: "Organization",
        repository_selection: "selected",
        permissions: installationPermissions,
      });
    }
    if (path === "/app/installations/2001/access_tokens" && init.method === "POST") {
      serial += 1;
      const [repositoryId] = body.repository_ids;
      const standard = {
        token: `ghs_synthetic_scoped_token_${serial}`,
        expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
        repositories: [{ id: repositoryId, ...REPOSITORIES.get(repositoryId) }],
        permissions: { ...body.permissions, metadata: "read" },
      };
      return Response.json(mint ? mint(standard, body) : standard);
    }
    if (path === "/installation/token" && init.method === "DELETE") {
      revoked.add(init.headers.Authorization.slice("Bearer ".length));
      return new Response(null, { status: 204 });
    }
    throw new Error(`unexpected request ${init.method} ${path}`);
  };
  const client = createGithubClient({ appId: "42", signJwt: async () => "c2lnbmF0dXJl", fetchImpl });
  return { client, calls, revoked, fetchImpl };
}

test("a purpose token is minted for exactly one repository id and exactly the purpose's permissions", async () => {
  const policy = parsePolicy(oidcPolicyFixture());
  const github = syntheticGithub();
  const minted = await github.client.mintPurposeToken(policy, 3101, DEPLOYMENT_APPLY);
  assert.deepEqual(github.calls.map(({ method, path, body }) => ({ method, path, body })), [
    { method: "POST", path: "/app/installations/2001/access_tokens", body: { repository_ids: [3101], permissions: DEPLOYMENT_APPLY } },
  ]);
  assert.equal(minted.repository_id, 3101);
  assert.equal(minted.repository, "example-org/deployment");
  assert.deepEqual(minted.permissions, DEPLOYMENT_APPLY);
  assert.equal(github.revoked.size, 0, "the broker never revokes the token it delivers");

  // A set beyond what the installation accepted never reaches GitHub.
  const unaccepted = syntheticGithub();
  await assert.rejects(
    () => unaccepted.client.mintPurposeToken(policy, 3201, { contents: "read", secrets: "read" }),
    /secrets: read, which the installation has not accepted/,
  );
  await assert.rejects(() => unaccepted.client.mintPurposeToken(policy, 3201, {}), /exact permission set/);
  assert.equal(unaccepted.calls.length, 0);
});

test("a purpose token outside the requested scope is revoked at once and refused", async () => {
  const policy = parsePolicy(oidcPolicyFixture());
  const cases = [
    ["another repository", (standard) => ({ ...standard, repositories: [{ id: 3201, ...REPOSITORIES.get(3201) }] })],
    ["two repositories", (standard) => ({ ...standard, repositories: [...standard.repositories, { id: 3201, ...REPOSITORIES.get(3201) }] })],
    ["another owner", (standard) => ({ ...standard, repositories: [{ ...standard.repositories[0], owner: { id: 7001, login: "other-org" } }] })],
    ["no repository name", (standard) => ({ ...standard, repositories: [{ id: 3101, owner: { id: 1001 } }] })],
    ["an added permission", (standard) => ({ ...standard, permissions: { ...standard.permissions, administration: "write" } })],
    ["a missing permission", (standard) => ({ ...standard, permissions: { contents: "write", metadata: "read" } })],
    ["a long expiry", (standard) => ({ ...standard, expires_at: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString() })],
  ];
  for (const [label, mint] of cases) {
    const github = syntheticGithub({ mint });
    await assert.rejects(
      () => github.client.mintPurposeToken(policy, 3101, DEPLOYMENT_APPLY),
      /outside the requested repository or permission scope/,
      label,
    );
    assert.deepEqual([...github.revoked], ["ghs_synthetic_scoped_token_1"], label);
  }
});

test("revocation: the runner revokes its delivered token through GitHub; the broker keeps no copy", async () => {
  const github = syntheticGithub();
  const handle = createBrokerHandler({
    policy: parsePolicy(oidcPolicyFixture()),
    credentials: new Map(),
    secretMatches: async () => false,
    github: { verifyTeamGrant: async () => {}, verifyWorkspaceTeam: async () => {}, mintToken: async () => {}, mintPurposeToken: github.client.mintPurposeToken },
    oidc: { verify: async () => claimsFixture(), guard: fakeGuard(), audit: () => {}, now: () => Date.now() },
  });
  const { status, body } = await oidcCall(handle);
  assert.equal(status, 200);
  assert.equal(github.revoked.size, 0);

  // GitHub's revocation endpoint, called with the token itself, as runner mode does at the end.
  const response = await github.fetchImpl("https://api.github.com/installation/token", {
    method: "DELETE",
    headers: { Authorization: `Bearer ${body.token}` },
  });
  assert.equal(response.status, 204);
  assert.deepEqual([...github.revoked], [body.token]);
});

// ---------------------------------------------------------------------------------------------
// Worker end to end: jose, the Durable Object run guard and the core GitHub client
// ---------------------------------------------------------------------------------------------

function durableObjectNamespace() {
  const objects = new Map();
  return {
    objects,
    idFromName: (name) => ({ name }),
    get(id) {
      if (!objects.has(id.name)) {
        const storage = memoryStorage();
        objects.set(id.name, { storage, guard: new OidcRunGuard({ storage }) });
      }
      const { guard } = objects.get(id.name);
      return { fetch: (url, init) => guard.fetch(new Request(url, init)) };
    },
  };
}

function workerFixture({ installationPermissions, keySet = localKeySet, mint, policy = oidcPolicyFixture() } = {}) {
  const github = syntheticGithub({ installationPermissions, mint });
  const records = [];
  const namespace = durableObjectNamespace();
  const worker = createWorkerEntrypoint({
    createGithub: () => github.client,
    oidcKeySet: () => keySet,
    audit: (record) => records.push(record),
  });
  const env = {
    BROKER_POLICY_JSON: JSON.stringify(policy),
    GITHUB_APP_ID: "42",
    GITHUB_APP_PRIVATE_KEY: "synthetic-test-key",
    WORKSPACE_CREDENTIAL_ALPHA_TEAM: ALPHA_CREDENTIAL,
    OIDC_RUN_GUARD: namespace,
  };
  return { worker, env, github, records, namespace };
}

function oidcRequest(token, purpose = "deployment-apply") {
  return new Request("https://github-broker.example.com/v1/oidc/token", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ purpose }),
  });
}

test("Worker end to end: a push apply mints one scoped token after the installation gate; a replay is refused", async () => {
  const { worker, env, github, records, namespace } = workerFixture();
  const token = await signedToken({ iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300 });
  const response = await worker.fetch(oidcRequest(token), env);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const body = await response.json();
  assert.equal(body.repository, "example-org/deployment");
  assert.equal(body.access, "write");
  assert.deepEqual(body.permissions, DEPLOYMENT_APPLY);
  assert.deepEqual(github.calls.map(({ method, path }) => `${method} ${path}`), [
    "GET /app/installations/2001",
    "POST /app/installations/2001/access_tokens",
  ]);
  assert.deepEqual([...namespace.objects.keys()], ["3101/9001/1"]);

  const replay = await worker.fetch(oidcRequest(token), env);
  assert.equal(replay.status, 401);
  assert.deepEqual(await replay.json(), { error: "token_replayed" });
  assert.equal(github.calls.length, 2, "a replay costs no GitHub request");
  assert.deepEqual(records.map(({ code }) => code), ["granted", "token_replayed"]);
  assert.equal(JSON.stringify(records).includes(body.token), false);
  assert.equal(JSON.stringify(records).includes(token), false);
});

test("Worker end to end: plain Plan and apply jobs without job_workflow_ref get their tokens; a reusable workflow does not", async () => {
  const { worker, env, github, records } = workerFixture();
  const apply = await worker.fetch(oidcRequest(await plainJobToken()), env);
  assert.equal(apply.status, 200);
  const applyBody = await apply.json();
  assert.equal(applyBody.access, "write");
  assert.deepEqual(applyBody.permissions, DEPLOYMENT_APPLY);

  const planRelease = await worker.fetch(oidcRequest(await plainJobToken({ plan: true }), "machines-release"), env);
  assert.equal(planRelease.status, 200);
  assert.deepEqual((await planRelease.json()).permissions, RELEASE_READ);
  const planDeployment = await worker.fetch(oidcRequest(await plainJobToken({ plan: true })), env);
  assert.equal(planDeployment.status, 200);
  assert.deepEqual((await planDeployment.json()).permissions, DEPLOYMENT_PLAN);

  const before = github.calls.length;
  for (const purpose of ["deployment-apply", "machines-release"]) {
    const delegated = await worker.fetch(
      oidcRequest(await plainJobToken({ job_workflow_ref: "other-org/shared/.github/workflows/apply.yml@refs/heads/main" }), purpose),
      env,
    );
    assert.equal(delegated.status, 403);
    assert.deepEqual(await delegated.json(), { error: "job_workflow_not_allowed" });
  }
  assert.equal(github.calls.length, before, "a refused reusable workflow costs no GitHub request");
  assert.deepEqual(records.map(({ code }) => code), ["granted", "granted", "granted", "job_workflow_not_allowed", "job_workflow_not_allowed"]);
  assert.equal(records[0].caller.job_workflow_ref, null);
});

test("Worker end to end: the per-run budget refuses a third deployment token of the same run", async () => {
  const { worker, env, github } = workerFixture();
  const fresh = () => signedToken({ iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300 });
  assert.equal((await worker.fetch(oidcRequest(await fresh()), env)).status, 200);
  assert.equal((await worker.fetch(oidcRequest(await fresh()), env)).status, 200);
  const third = await worker.fetch(oidcRequest(await fresh()), env);
  assert.equal(third.status, 429);
  assert.deepEqual(await third.json(), { error: "rate_limited" });
  // A rerun is a new run attempt with its own budget.
  const rerun = await worker.fetch(oidcRequest(await signedToken({ run_attempt: "2" })), env);
  assert.equal(rerun.status, 200);
  assert.equal(github.calls.filter(({ method }) => method === "POST").length, 3);
});

test("Worker end to end: a Plan run reads, and a Deployment Repo of another Organization reads the release repository", async () => {
  const { worker, env, github } = workerFixture();
  const plan = await worker.fetch(oidcRequest(await signedToken({ event_name: "pull_request_target", environment: null })), env);
  assert.equal(plan.status, 200);
  assert.deepEqual((await plan.json()).permissions, DEPLOYMENT_PLAN);

  const otherOrgToken = await signedToken({
    ...OTHER_ORG,
    repository_owner: "other-org",
    workflow_ref: `other-org/deployment/${WORKFLOW}@refs/heads/main`,
    job_workflow_ref: `other-org/deployment/${WORKFLOW}@refs/heads/main`,
  });
  const release = await worker.fetch(oidcRequest(otherOrgToken, "machines-release"), env);
  assert.equal(release.status, 200);
  const body = await release.json();
  assert.equal(body.repository_id, 3201);
  assert.equal(body.repository, "example-org/releases");
  assert.equal(body.access, "read");
  assert.deepEqual(body.permissions, RELEASE_READ);

  const otherOrgApply = await worker.fetch(oidcRequest(otherOrgToken, "deployment-apply"), env);
  assert.equal(otherOrgApply.status, 403);
  assert.deepEqual(await otherOrgApply.json(), { error: "repository_denied" });
  assert.deepEqual(
    github.calls.filter(({ method }) => method === "POST").map(({ body: request }) => request),
    [
      { repository_ids: [3101], permissions: DEPLOYMENT_PLAN },
      { repository_ids: [3201], permissions: RELEASE_READ },
    ],
  );
});

test("Worker end to end: installation drift and GitHub's key set outages fail closed and mint nothing", async () => {
  const drifted = workerFixture({ installationPermissions: { ...oidcPolicyFixture().installation_permissions, administration: "write" } });
  const response = await drifted.worker.fetch(oidcRequest(await signedToken()), drifted.env);
  assert.equal(response.status, 502);
  assert.deepEqual(await response.json(), { error: "token_unavailable" });
  assert.deepEqual(drifted.github.calls.map(({ method, path }) => `${method} ${path}`), ["GET /app/installations/2001"]);

  const offline = workerFixture({ keySet: createGithubActionsKeySet({ fetchImpl: async () => { throw new TypeError("fetch failed"); } }) });
  const unavailable = await offline.worker.fetch(oidcRequest(await signedToken()), offline.env);
  assert.equal(unavailable.status, 503);
  assert.deepEqual(await unavailable.json(), { error: "jwks_unavailable" });
  assert.equal(offline.github.calls.length, 0);
});

test("Worker: a policy with oidc purposes needs its run guard binding; without oidc the route is absent", async () => {
  const { worker, env } = workerFixture();
  const { OIDC_RUN_GUARD: _guard, ...withoutGuard } = env;
  for (const request of [new Request("https://github-broker.example.com/health"), oidcRequest(await signedToken())]) {
    const response = await worker.fetch(request, withoutGuard);
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: "configuration_unavailable" });
  }

  const policy = oidcPolicyFixture();
  delete policy.oidc;
  const plain = workerFixture({ policy });
  const { OIDC_RUN_GUARD: _unused, ...plainEnv } = plain.env;
  assert.equal((await plain.worker.fetch(new Request("https://github-broker.example.com/health"), plainEnv)).status, 204);
  const absent = await plain.worker.fetch(oidcRequest(await signedToken()), plainEnv);
  assert.equal(absent.status, 404);
  assert.equal(plain.github.calls.length, 0);
  assert.equal(plain.records.length, 0);
});

test("Worker: a GitHub client without the purpose mint is unavailable configuration once oidc is declared", async () => {
  const { env } = workerFixture();
  const worker = createWorkerEntrypoint({
    createGithub: () => ({ verifyPolicy: async () => {}, verifyTeamGrant: async () => {}, verifyWorkspaceTeam: async () => {}, mintToken: async () => {} }),
    oidcKeySet: () => localKeySet,
  });
  const response = await worker.fetch(new Request("https://github-broker.example.com/health"), env);
  assert.equal(response.status, 503);
});

// ---------------------------------------------------------------------------------------------
// policy check
// ---------------------------------------------------------------------------------------------

test("policy check prints each purpose with the exact permission set every rule asks for", () => {
  const policy = oidcPolicyFixture();
  policy.workspaces = [];
  assert.equal(
    formatPolicySummary(parsePolicy(policy)),
    [
      "lazurio.github_app_broker.policy.v3 owner=example-org installation=2001",
      "no Workspaces",
      `oidc audience=${AUDIENCE} runners=github-hosted deployment_repositories=3101/1001,7101/7001`,
      `purpose deployment-apply repository=caller workflow=${WORKFLOW} per_run=2`,
      "  push,workflow_dispatch refs/heads/main environment=production asks for: administration=read checks=read contents=write issues=read members=read organization_administration=read pull_requests=read",
      "  pull_request_target refs/heads/main environment=- read-only asks for: administration=read checks=read contents=read issues=read members=read organization_administration=read pull_requests=read",
      `purpose machines-release repository=3201 workflow=${WORKFLOW} per_run=4`,
      "  push,workflow_dispatch refs/heads/main environment=production asks for: contents=read",
      "  pull_request_target refs/heads/main environment=- asks for: contents=read",
      "",
    ].join("\n"),
  );
});
