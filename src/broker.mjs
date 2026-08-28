#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";

import {
  MAX_BODY_BYTES,
  createBrokerHandler,
  createGithubClient as createSharedGithubClient,
  parsePolicy,
} from "./core.mjs";

export { parsePolicy } from "./core.mjs";

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
      const isTokenRequest = request.method === "POST" && request.url === "/v1/token";
      writeResult(response, await handle({
        method: request.method,
        path: request.url,
        contentType: request.headers["content-type"] ?? "",
        workspaceId: request.headers["x-lazurio-workspace-id"],
        authorization: request.headers.authorization ?? "",
        bodyText: isTokenRequest ? await readBody(request) : "",
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

export function parseCommand(arguments_) {
  if (arguments_.length === 0) return Object.freeze({ verifyOnly: false });
  if (arguments_.length === 1 && arguments_[0] === "--verify-only") {
    return Object.freeze({ verifyOnly: true });
  }
  fail("usage: broker.mjs [--verify-only]");
}

async function main() {
  const command = parseCommand(process.argv.slice(2));
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
  if (command.verifyOnly) {
    snapshotWorkspaceCredentials(policy, { readFile: fs.readFileSync, realpath: fs.realpathSync });
    await github.verifyPolicy(policy);
    return;
  }
  await startBroker({ policy, github, port });
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  await main();
}
