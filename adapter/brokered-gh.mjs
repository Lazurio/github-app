#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import fs from "node:fs";
import { spawnSync } from "node:child_process";

import {
  firstPolicyRepository,
  normalizeRepository,
  repositoryIdentityKey,
  requestGitHubAppToken,
  requireHttpsGitHubOrigin,
} from "./broker-client.mjs";

export const HOSTED_GITHUB_ACTOR = "lazurio-for-github[bot]";
export const REAL_GH = "/usr/local/libexec/lazurio/gh-real";
export const READ_ONLY_GH_CONFIG_DIR = "/usr/local/share/lazurio/gh-config";

const AUTH_STATUS_ARGS = Object.freeze(["auth", "status", "--json", "hosts"]);
const VIEWER_LOGIN_ARGS = Object.freeze(["api", "user", "--jq", ".login"]);
const DENIED_COMMANDS = new Set(["auth", "alias", "config", "extension", "search"]);
const STRIPPED_ENVIRONMENT = Object.freeze([
  "ALL_PROXY",
  "BROWSER",
  "DEBUG",
  "EDITOR",
  "GH_BROWSER",
  "GH_DEBUG",
  "GH_EDITOR",
  "GH_ENTERPRISE_TOKEN",
  "GH_FORCE_TTY",
  "GH_HTTP_UNIX_SOCKET",
  "GH_TOKEN",
  "GITHUB_ENTERPRISE_TOKEN",
  "GITHUB_TOKEN",
  "HTTPS_PROXY",
  "HTTP_PROXY",
  "PAGER",
  "all_proxy",
  "https_proxy",
  "http_proxy",
]);

function fail(message) {
  throw new Error(message);
}

function exactArgs(actual, expected) {
  return actual.length === expected.length && actual.every((value, index) => value === expected[index]);
}

function hasForbiddenHostOverride(args, environment) {
  if (environment.GH_HOST && environment.GH_HOST !== "github.com") return true;
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--hostname") {
      if (args[index + 1] !== "github.com") return true;
      index += 1;
      continue;
    }
    if (argument.startsWith("--hostname=")) {
      if (argument.slice("--hostname=".length) !== "github.com") return true;
      continue;
    }
    if (/^https?:\/\//.test(argument) && !/^https:\/\/github\.com(?:\/|$)/.test(argument)) {
      return true;
    }
  }
  return false;
}

export function classifyGhCommand(args, environment = process.env) {
  if (exactArgs(args, AUTH_STATUS_ARGS)) return "auth-status";
  if (exactArgs(args, VIEWER_LOGIN_ARGS)) return "viewer-login";
  if (
    DENIED_COMMANDS.has(args[0]) ||
    args.includes("--show-token") ||
    hasForbiddenHostOverride(args, environment)
  ) {
    return "denied";
  }
  if (
    args.length === 0 ||
    exactArgs(args, ["--version"]) ||
    exactArgs(args, ["version"]) ||
    args[0] === "help" ||
    args.includes("--help") ||
    args.includes("-h")
  ) {
    return "local";
  }
  return "repository";
}

function explicitRepository(args, environment) {
  let result = environment.GH_REPO ? normalizeRepository(environment.GH_REPO) : null;
  for (let index = 0; index < args.length; index += 1) {
    let value;
    if (args[index] === "--repo" || args[index] === "-R") {
      value = args[index + 1];
      if (!value) fail("gh repository selector lacks a value");
      index += 1;
    } else if (args[index].startsWith("--repo=")) {
      value = args[index].slice("--repo=".length);
    } else {
      continue;
    }
    const parsed = normalizeRepository(value);
    if (result && repositoryIdentityKey(result) !== repositoryIdentityKey(parsed)) {
      fail("gh repository selectors disagree");
    }
    result = parsed;
  }
  return result;
}

export function resolveGhRepository({
  args,
  environment = process.env,
  readOrigin = () => {
    const result = spawnSync("git", ["remote", "get-url", "origin"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    return result.status === 0 ? result.stdout.trim() : null;
  },
}) {
  const selected = explicitRepository(args, environment);
  const origin = readOrigin();
  const originRepository = origin ? requireHttpsGitHubOrigin(origin) : null;
  if (
    selected &&
    originRepository &&
    repositoryIdentityKey(selected) !== repositoryIdentityKey(originRepository)
  ) {
    fail("gh repository selector does not match the current brokered checkout");
  }
  // Prefer the checkout's canonical spelling when gh/T3 supplied the same GitHub identity in a
  // different case. The original gh arguments remain untouched and official gh still executes.
  const repository = originRepository ?? selected;
  if (!repository) fail("run gh inside an approved Team repository or pass --repo OWNER/REPO");
  return repository;
}

function sanitizedEnvironment(environment) {
  const result = { ...environment };
  for (const name of STRIPPED_ENVIRONMENT) delete result[name];
  result.GH_CONFIG_DIR = READ_ONLY_GH_CONFIG_DIR;
  result.GH_HOST = "github.com";
  result.GH_NO_EXTENSION_UPDATE_NOTIFIER = "1";
  result.GH_NO_UPDATE_NOTIFIER = "1";
  result.GH_PAGER = "cat";
  result.GH_PROMPT_DISABLED = "1";
  return result;
}

export function uncredentialedGhEnvironment(environment = process.env) {
  const result = sanitizedEnvironment(environment);
  delete result.GH_REPO;
  return result;
}

export function brokeredGhEnvironment(environment, token, repository) {
  const result = sanitizedEnvironment(environment);
  result.GH_TOKEN = token;
  result.GH_REPO = repository;
  return result;
}

export function assertReadOnlyGhConfigDirectory(stat = fs.statSync) {
  const metadata = stat(READ_ONLY_GH_CONFIG_DIR);
  if (!metadata.isDirectory() || (metadata.mode & 0o222) !== 0) {
    fail("GitHub CLI config boundary must be a read-only directory");
  }
}

function defaultRunRealGh(args, environment) {
  const child = spawnSync(REAL_GH, args, { env: environment, stdio: "inherit" });
  if (child.error) throw child.error;
  return child.status ?? 1;
}

function authenticatedStatus() {
  return {
    hosts: {
      "github.com": [
        {
          state: "success",
          active: true,
          host: "github.com",
          login: HOSTED_GITHUB_ACTOR,
          tokenSource: "lazurio-broker-live-proof",
          scopes: "",
          gitProtocol: "https",
        },
      ],
    },
  };
}

export async function runBrokeredGh({
  args,
  environment = process.env,
  readOrigin,
  requestToken = requestGitHubAppToken,
  runRealGh = defaultRunRealGh,
  assertConfigDirectory = assertReadOnlyGhConfigDirectory,
  writeStdout = (value) => process.stdout.write(value),
  writeStderr = (value) => process.stderr.write(value),
}) {
  const classification = classifyGhCommand(args, environment);
  if (classification === "denied") {
    fail("this gh command is disabled in a hosted Team Workspace");
  }
  if (classification === "local") {
    assertConfigDirectory();
    return runRealGh(args, uncredentialedGhEnvironment(environment));
  }
  if (classification === "auth-status" || classification === "viewer-login") {
    try {
      const repository = firstPolicyRepository(environment);
      await requestToken({ repository, environment });
    } catch {
      if (classification === "auth-status") {
        writeStdout(`${JSON.stringify({ hosts: {} })}\n`);
        writeStderr("Brokered gh authentication proof failed.\n");
        return 1;
      }
      fail("GitHub broker identity proof failed");
    }
    if (classification === "auth-status") {
      writeStdout(`${JSON.stringify(authenticatedStatus())}\n`);
    } else {
      writeStdout(`${HOSTED_GITHUB_ACTOR}\n`);
    }
    return 0;
  }

  assertConfigDirectory();
  const repository = resolveGhRepository({ args, environment, readOrigin });
  const credential = await requestToken({ repository, environment });
  return runRealGh(args, brokeredGhEnvironment(environment, credential.token, repository));
}

async function main() {
  const exitCode = await runBrokeredGh({ args: process.argv.slice(2) });
  process.exitCode = exitCode;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  main().catch((error) => {
    process.stderr.write(`Brokered gh failed closed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
