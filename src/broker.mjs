#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";

import {
  MAX_BODY_BYTES,
  checkPolicyLive,
  createBrokerHandler,
  createGithubClient as createSharedGithubClient,
  formatPolicyCheckTable,
  parsePolicy,
} from "./core.mjs";

export { checkPolicyLive, formatPolicyCheckTable, parsePolicy } from "./core.mjs";

function fail(message) {
  throw new Error(message);
}

function nodeJwtSigner(privateKey) {
  if (!privateKey) fail("GitHub App private key is missing");
  return async (unsigned) =>
    crypto.sign("RSA-SHA256", Buffer.from(unsigned), privateKey).toString("base64url");
}

export function createGithubClient({ appId, privateKey, fetchImpl = fetch, now = () => Date.now() }) {
  return createSharedGithubClient({
    appId,
    signJwt: nodeJwtSigner(privateKey),
    fetchImpl,
    now,
  });
}

function readWorkspaceCredential(file, readFile = fs.readFileSync) {
  const credential = readFile(file, "utf8").trim();
  if (credential.length < 32 || /\s/.test(credential)) fail("Workspace credential is invalid");
  return credential;
}

function snapshotWorkspaceCredentials(policy, { readFile, realpath }) {
  const realPaths = new Set();
  const digests = new Set();
  const credentials = new Map();
  for (const workspace of policy.workspaces) {
    const resolved = realpath(workspace.credential_file);
    if (!/^\/run\/secrets\/[A-Za-z0-9._-]+$/.test(resolved) || realPaths.has(resolved)) {
      fail("Workspace credential files must resolve to unique /run/secrets files");
    }
    realPaths.add(resolved);
    const credential = readWorkspaceCredential(workspace.credential_file, readFile);
    const digest = crypto.createHash("sha256").update(credential).digest("hex");
    if (digests.has(digest)) fail("Workspace credential values must be unique");
    digests.add(digest);
    credentials.set(workspace.id, credential);
  }
  return credentials;
}

function secretMatches(actual, expected) {
  const actualDigest = crypto.createHash("sha256").update(actual).digest();
  const expectedDigest = crypto.createHash("sha256").update(expected).digest();
  return crypto.timingSafeEqual(actualDigest, expectedDigest);
}

function writeResult(response, { status, body }) {
  if (status === 204) {
    response.writeHead(status, { "Cache-Control": "no-store" });
    response.end();
    return;
  }
  const payload = JSON.stringify(body);
  response.writeHead(status, {
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(payload),
    "Content-Type": "application/json",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
  });
  response.end(payload);
}

async function readBody(request) {
  let body = "";
  request.setEncoding("utf8");
  for await (const chunk of request) {
    body += chunk;
    if (Buffer.byteLength(body) > MAX_BODY_BYTES) throw new Error("request body is too large");
  }
  return body;
}

export function createBrokerServer({
  policy,
  github,
  readFile = fs.readFileSync,
  realpath = fs.realpathSync,
  credentials = snapshotWorkspaceCredentials(policy, { readFile, realpath }),
}) {
  const handle = createBrokerHandler({ policy, github, credentials, secretMatches });
  const server = http.createServer(async (request, response) => {
    try {
      writeResult(response, await handle({
        method: request.method,
        path: request.url,
        contentType: request.headers["content-type"] ?? "",
        workspaceId: request.headers["x-lazurio-workspace-id"],
        authorization: request.headers.authorization ?? "",
        readBody: () => readBody(request),
      }));
    } catch {
      if (!response.headersSent) writeResult(response, { status: 502, body: { error: "token_unavailable" } });
    }
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 5_000;
  server.keepAliveTimeout = 5_000;
  return server;
}

export async function startBroker({
  policy,
  github,
  readFile = fs.readFileSync,
  realpath = fs.realpathSync,
  port = 8787,
  host = "0.0.0.0",
}) {
  const credentials = snapshotWorkspaceCredentials(policy, { readFile, realpath });
  await github.verifyPolicy(policy);
  const server = createBrokerServer({ policy, credentials, github, readFile, realpath });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, resolve);
  });
  return server;
}

const USAGE = "usage: broker.mjs [--verify-only | policy check [--live]]";

export function parseCommand(arguments_) {
  const joined = arguments_.join(" ");
  if (joined === "") return Object.freeze({ mode: "serve" });
  if (joined === "--verify-only") return Object.freeze({ mode: "verify" });
  if (joined === "policy check") return Object.freeze({ mode: "policy-check", live: false });
  if (joined === "policy check --live") return Object.freeze({ mode: "policy-check", live: true });
  fail(USAGE);
}

/** Offline summary of the parsed Team binding; no GitHub traffic and no secret. */
export function formatPolicySummary(policy) {
  const header = ["WORKSPACE", "TEAM_ID", "TEAM_SLUG", "REPOSITORIES"];
  const rows = policy.workspaces.map((workspace) => [
    workspace.id,
    String(workspace.github_team_id),
    workspace.github_team_slug ?? "-",
    String(workspace.repository_ids.length),
  ]);
  const widths = header.map((title, column) => Math.max(title.length, ...rows.map((row) => row[column].length)));
  const line = (values) => values.map((value, column) => value.padEnd(widths[column])).join("  ").trimEnd();
  return [
    `${policy.schema_version} owner=${policy.github_owner.login} installation=${policy.installation_id}`,
    line(header),
    ...rows.map(line),
  ].join("\n") + "\n";
}

/**
 * `policy check [--live]` is the migration and readback gate an operator runs before a
 * policy is deployed. It runs on the operator's machine, so the policy and App key may
 * be read from any custody path; only the serving commands require the runtime mounts.
 */
async function runPolicyCheck({ live, env, write }) {
  const policyFile = env.BROKER_POLICY_FILE ?? "";
  if (policyFile === "") fail("BROKER_POLICY_FILE must name the policy to check");
  const policy = parsePolicy(fs.readFileSync(policyFile, "utf8"));
  write(formatPolicySummary(policy));
  if (!live) return true;

  const privateKeyFile = env.GITHUB_APP_PRIVATE_KEY_FILE ?? "";
  if (privateKeyFile === "") fail("GITHUB_APP_PRIVATE_KEY_FILE must name the App private key for a live check");
  const github = createGithubClient({
    appId: env.GITHUB_APP_ID ?? "",
    privateKey: fs.readFileSync(privateKeyFile),
  });
  const result = await checkPolicyLive({ policy, github });
  write(formatPolicyCheckTable(result.rows));
  return result.ok;
}

async function main() {
  const command = parseCommand(process.argv.slice(2));
  if (command.mode === "policy-check") {
    const ok = await runPolicyCheck({
      live: command.live,
      env: process.env,
      write: (text) => process.stdout.write(text),
    });
    if (!ok) process.exitCode = 1;
    return;
  }

  const appId = process.env.GITHUB_APP_ID ?? "";
  const privateKeyFile = process.env.GITHUB_APP_PRIVATE_KEY_FILE ?? "";
  const policyFile = process.env.BROKER_POLICY_FILE ?? "";
  const port = Number(process.env.PORT ?? "8787");
  if (!privateKeyFile.startsWith("/run/secrets/") || !policyFile.startsWith("/run/config/")) {
    fail("private key and policy must be custody-mounted files");
  }
  if (!Number.isSafeInteger(port) || port !== 8787) fail("broker port must remain 8787");

  const github = createGithubClient({
    appId,
    privateKey: fs.readFileSync(privateKeyFile),
  });
  const policy = parsePolicy(fs.readFileSync(policyFile, "utf8"));
  if (command.mode === "verify") {
    snapshotWorkspaceCredentials(policy, { readFile: fs.readFileSync, realpath: fs.realpathSync });
    await github.verifyPolicy(policy);
    return;
  }
  await startBroker({ policy, github, port });
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  await main();
}
