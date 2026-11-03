// SPDX-License-Identifier: Apache-2.0
//
// Conglomerate Host callers (since 0.15.0, Lazurio/github-app#30).
//
// A Conglomerate Host runs the Headscale of one or more Organizations and an access service that
// reads, about once a minute, each served Organization's membership and its Deployment Repo. It
// asks that Organization's broker for one read-only token, proving itself with a key it generated
// and never lets go. The broker does not hold that key in its policy: it reads the host's public
// key live from its own Organization's Deployment Repo, where the Organization's own tooling
// projects it next to the reviewed fact that the Organization runs on that host. Joining a host and
// rebuilding it therefore need no broker change.
//
// This module holds only pure parts: the policy section, the assertion, the key document and the
// Ed25519 check through WebCrypto. It imports nothing, so the core and the Node adapter stay
// dependency-free; only the Worker adapter serves the route.

export const HOST_ROUTE = "/v1/host/token";
export const HOST_KEY_DOCUMENT_SCHEMA = "machines.conglomerate-host-broker-key.v1";
/** The one permission set a host token carries (GitHub adds `metadata: read`). */
export const HOST_TOKEN_PERMISSIONS = Object.freeze({ contents: "read", members: "read" });
/** An assertion lives at most this long between `iat` and `exp`. */
export const HOST_ASSERTION_MAX_LIFETIME_SECONDS = 60;
/** Clock tolerance for `iat` and `exp`. */
export const HOST_CLOCK_TOLERANCE_SECONDS = 30;
/** Key document reads per broker and hour, before any assertion is verified (deny-only). */
export const HOST_READS_PER_HOUR = 60;
/** Tokens per host and hour of its assertions' `iat` (deny-only). */
export const HOST_GRANTS_PER_HOUR = 12;
export const HOST_MAX_ASSERTION_BYTES = 2048;
export const HOST_MAX_DOCUMENT_BYTES = 4096;

/**
 * Every refusal of `POST /v1/host/token`: one code and its HTTP status. The body is
 * `{"error": "<code>"}`; it never echoes the assertion, the key document or the policy.
 */
export const HOST_REFUSALS = Object.freeze({
  assertion_missing: 401,
  assertion_malformed: 401,
  assertion_algorithm_refused: 401,
  assertion_audience_mismatch: 401,
  assertion_claims_invalid: 401,
  assertion_lifetime_too_long: 401,
  assertion_not_yet_valid: 401,
  assertion_expired: 401,
  assertion_signature_invalid: 401,
  assertion_replayed: 401,
  invalid_request: 400,
  host_unknown: 403,
  host_key_invalid: 403,
  organization_mismatch: 403,
  deployment_repository_writer_not_approved: 403,
  deployment_repository_write_key: 403,
  unsupported_media_type: 415,
  rate_limited: 429,
  token_unavailable: 502,
});

/** A refused host request; `code` is a key of HOST_REFUSALS. */
export class HostRefusal extends Error {
  constructor(code) {
    if (!Object.hasOwn(HOST_REFUSALS, code)) throw new Error(`unknown host refusal ${code}`);
    super(`host request refused: ${code}`);
    this.name = "HostRefusal";
    this.code = code;
    this.status = HOST_REFUSALS[code];
  }
}

function refuse(code) {
  throw new HostRefusal(code);
}

function fail(message) {
  throw new Error(message);
}

// A Machines machine id: lowercase DNS label.
const LOGIN_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const HOST_ID_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const JTI_PATTERN = /^[A-Za-z0-9_-]{22,128}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const REF_SEGMENT_PATTERN = /^[A-Za-z0-9_-][A-Za-z0-9._-]{0,99}$/;
const DIRECTORY_SEGMENT_PATTERN = /^[a-z0-9_-][a-z0-9._-]{0,99}$/;
const BROKER_KEY_PATTERN = /^ed25519:([A-Za-z0-9_-]{43})$/;
const COMMIT_PATTERN = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const TIME_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

function plainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value, required, optional = []) {
  if (!plainObject(value)) return false;
  const keys = Object.keys(value);
  return (
    required.every((key) => Object.hasOwn(value, key)) &&
    keys.every((key) => required.includes(key) || optional.includes(key))
  );
}

function positiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function canonicalHttpsOrigin(value) {
  if (typeof value !== "string") return undefined;
  let url;
  try {
    url = new URL(value);
  } catch {
    return undefined;
  }
  return url.protocol === "https:" && !url.username && !url.password && value === url.origin ? value : undefined;
}

/** `ref` names one branch by its short name, segment by segment, never `..` or a leading `refs/`. */
function validRef(value) {
  return (
    typeof value === "string" &&
    value.length <= 200 &&
    !value.startsWith("refs/") &&
    value.split("/").every((segment) => REF_SEGMENT_PATTERN.test(segment) && !segment.endsWith(".lock") && !segment.includes(".."))
  );
}

/** `directory` is a relative path of plain lowercase segments, never `.` or `..`. */
function validDirectory(value) {
  return (
    typeof value === "string" &&
    value.length <= 200 &&
    value.split("/").every((segment) => DIRECTORY_SEGMENT_PATTERN.test(segment) && segment !== "." && segment !== "..")
  );
}

/**
 * Parses the optional policy key `conglomerate_hosts`:
 *
 *   {"audience": "<this broker's origin>", "repository_id": <own Deployment Repo id>,
 *    "ref": "<branch>", "directory": "<relative path>"}
 *
 * The repository must belong to the policy's Organization; the mint checks that live. The token's
 * permission set is fixed, never configured, and must lie within the accepted installation.
 */
export function parseConglomerateHosts(input, installationPermissions) {
  if (!exactKeys(input, ["audience", "repository_id", "ref", "directory", "approved_writers"])) {
    fail("conglomerate_hosts must have exactly audience, repository_id, ref, directory and approved_writers");
  }
  const audience = canonicalHttpsOrigin(input.audience);
  if (audience === undefined) fail("conglomerate_hosts.audience must be the broker's canonical https origin");
  if (!positiveInteger(input.repository_id)) fail("conglomerate_hosts.repository_id must be a positive integer");
  if (!validRef(input.ref)) fail("conglomerate_hosts.ref must name one branch");
  if (!validDirectory(input.directory)) fail("conglomerate_hosts.directory must be a relative path of plain segments");
  // Besides the Organization's Owners, the only accounts that may write the Deployment Repo: an
  // explicit, possibly empty list, by immutable id (the login is for review only).
  if (!Array.isArray(input.approved_writers) || input.approved_writers.length > 20) {
    fail("conglomerate_hosts.approved_writers must be a list of at most 20 accounts");
  }
  const approvedWriters = input.approved_writers.map((writer, index) => {
    if (
      !exactKeys(writer, ["id", "login"]) ||
      !positiveInteger(writer.id) ||
      typeof writer.login !== "string" ||
      !LOGIN_PATTERN.test(writer.login)
    ) {
      fail(`conglomerate_hosts.approved_writers[${index}] must have exactly a positive id and a login`);
    }
    return Object.freeze({ id: writer.id, login: writer.login });
  });
  if (new Set(approvedWriters.map(({ id }) => id)).size !== approvedWriters.length) {
    fail("conglomerate_hosts.approved_writers must list each account once");
  }
  // The token's permissions, and administration: read for the live deploy key check.
  for (const [permission, level] of Object.entries({ ...HOST_TOKEN_PERMISSIONS, administration: "read" })) {
    if (installationPermissions?.[permission] !== "read" && installationPermissions?.[permission] !== "write") {
      fail(`conglomerate_hosts needs the installation to accept ${permission}: ${level}`);
    }
  }
  return Object.freeze({
    audience,
    repository_id: input.repository_id,
    ref: input.ref,
    directory: input.directory,
    approved_writers: Object.freeze(approvedWriters),
    permissions: HOST_TOKEN_PERMISSIONS,
  });
}

/** Unpadded base64url to bytes; undefined for anything else. */
export function base64urlBytes(text) {
  if (typeof text !== "string" || !BASE64URL_PATTERN.test(text) || text.length % 4 === 1) return undefined;
  const padded = text.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (text.length % 4)) % 4);
  let binary;
  try {
    binary = atob(padded);
  } catch {
    return undefined;
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  // Canonical encoding only: no other string decodes to the same bytes.
  let reencoded = "";
  for (const byte of bytes) reencoded += String.fromCharCode(byte);
  return btoa(reencoded).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "") === text ? bytes : undefined;
}

function jsonPart(text) {
  const bytes = base64urlBytes(text);
  if (bytes === undefined) return undefined;
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return undefined;
  }
}

/**
 * Decodes a compact JWS a host presents and checks everything that needs no key: the header
 * (exactly `alg: EdDSA`, `kid` a host id, optional `typ: JWT`), the claims (exactly `aud` this
 * broker's origin, `iss` equal to `kid`, `iat`, `exp` at most 60 s after `iat`, a random `jti`) and
 * the time. The signature is checked later against the host's key document.
 */
export function decodeHostAssertion(compact, { audience, now }) {
  if (typeof compact !== "string" || compact.length === 0) refuse("assertion_missing");
  if (compact.length > HOST_MAX_ASSERTION_BYTES) refuse("assertion_malformed");
  const parts = compact.split(".");
  if (parts.length !== 3 || parts.some((part) => !BASE64URL_PATTERN.test(part))) refuse("assertion_malformed");
  const header = jsonPart(parts[0]);
  const claims = jsonPart(parts[1]);
  const signature = base64urlBytes(parts[2]);
  if (!plainObject(header) || !plainObject(claims) || signature === undefined) refuse("assertion_malformed");
  if (!exactKeys(header, ["alg", "kid"], ["typ"]) || (header.typ !== undefined && header.typ !== "JWT")) {
    refuse("assertion_malformed");
  }
  if (header.alg !== "EdDSA") refuse("assertion_algorithm_refused");
  if (signature.length !== 64) refuse("assertion_malformed");
  if (typeof header.kid !== "string" || !HOST_ID_PATTERN.test(header.kid)) refuse("assertion_claims_invalid");
  if (!exactKeys(claims, ["aud", "iss", "iat", "exp", "jti"])) refuse("assertion_claims_invalid");
  if (claims.aud !== audience) refuse("assertion_audience_mismatch");
  if (
    claims.iss !== header.kid ||
    !positiveInteger(claims.iat) ||
    !positiveInteger(claims.exp) ||
    claims.exp <= claims.iat ||
    typeof claims.jti !== "string" ||
    !JTI_PATTERN.test(claims.jti)
  ) {
    refuse("assertion_claims_invalid");
  }
  if (claims.exp - claims.iat > HOST_ASSERTION_MAX_LIFETIME_SECONDS) refuse("assertion_lifetime_too_long");
  const nowSeconds = Math.floor(now / 1000);
  if (claims.iat > nowSeconds + HOST_CLOCK_TOLERANCE_SECONDS) refuse("assertion_not_yet_valid");
  if (hostAssertionExpired(claims, now)) refuse("assertion_expired");
  return Object.freeze({
    host: header.kid,
    jti: claims.jti,
    iat: claims.iat,
    exp: claims.exp,
    signing_input: `${parts[0]}.${parts[1]}`,
    signature,
  });
}

/** Whether a decoded assertion has expired by `now`, with the same tolerance as decoding. */
export function hostAssertionExpired(assertion, now) {
  return assertion.exp + HOST_CLOCK_TOLERANCE_SECONDS < Math.floor(now / 1000);
}

/** The repository path of a host's key document. */
export function hostKeyDocumentPath(hosts, host) {
  if (!HOST_ID_PATTERN.test(host)) fail("host id is invalid");
  return `${hosts.directory}/${host}.json`;
}

/**
 * Validates the key document a host's served Organization projected into its Deployment Repo and
 * returns the 32 bytes of the host's Ed25519 public key. It must name exactly this host and this
 * broker's Organization.
 */
export function parseHostKeyDocument(text, { host, organizationId }) {
  if (typeof text !== "string" || new TextEncoder().encode(text).byteLength > HOST_MAX_DOCUMENT_BYTES) {
    refuse("host_key_invalid");
  }
  let document;
  try {
    document = JSON.parse(text);
  } catch {
    refuse("host_key_invalid");
  }
  if (
    !exactKeys(document, ["schema_version", "host", "organization_id", "broker_key", "source", "written_at"]) ||
    document.schema_version !== HOST_KEY_DOCUMENT_SCHEMA ||
    document.host !== host ||
    !positiveInteger(document.organization_id) ||
    !exactKeys(document.source, ["repository_id", "evidence_commit", "evidence_path"]) ||
    !positiveInteger(document.source.repository_id) ||
    typeof document.source.evidence_commit !== "string" ||
    !COMMIT_PATTERN.test(document.source.evidence_commit) ||
    typeof document.source.evidence_path !== "string" ||
    document.source.evidence_path.length === 0 ||
    document.source.evidence_path.length > 512 ||
    typeof document.written_at !== "string" ||
    !TIME_PATTERN.test(document.written_at)
  ) {
    refuse("host_key_invalid");
  }
  if (document.organization_id !== organizationId) refuse("organization_mismatch");
  const encoded = BROKER_KEY_PATTERN.exec(typeof document.broker_key === "string" ? document.broker_key : "")?.[1];
  const key = encoded === undefined ? undefined : base64urlBytes(encoded);
  if (key === undefined || key.length !== 32) refuse("host_key_invalid");
  return key;
}

/** Ed25519 through WebCrypto, which both Workers and Node provide; false for any failure. */
export async function verifyEd25519(publicKey, signingInput, signature, subtle = globalThis.crypto?.subtle) {
  try {
    const key = await subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    return (await subtle.verify({ name: "Ed25519" }, key, signature, new TextEncoder().encode(signingInput))) === true;
  } catch {
    return false;
  }
}
