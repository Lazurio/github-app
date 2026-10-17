// SPDX-License-Identifier: Apache-2.0
//
// GitHub Actions OIDC token verification with jose: RS256 only, GitHub's key set from its JWKS
// (cached by jose, refetched for an unknown key id at most once per cooldown, every fetch bounded
// by a timeout), the exact issuer, the broker's origin as the token's only audience, required exp
// and iat and 60 seconds of clock tolerance. The broker's admission (core.mjs) reads only claims
// returned from here, so nothing it decides on is a claim GitHub did not sign. Only the Worker
// adapter imports this module.
import { createRemoteJWKSet, customFetch, decodeProtectedHeader, errors, jwtVerify } from "jose";

import { OIDC_CLOCK_TOLERANCE_SECONDS, OidcRefusal } from "./core.mjs";

export const GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com";
export const GITHUB_ACTIONS_JWKS_URL = `${GITHUB_ACTIONS_ISSUER}/.well-known/jwks`;

const MAX_TOKEN_LENGTH = 8192;
const COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const DECIMAL = /^[1-9][0-9]{0,19}$/;
const JTI = /^[\x21-\x7e]{1,256}$/;
const COMMIT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const REPOSITORY = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9_.-]{1,100}$/;

/**
 * GitHub's Actions signing keys through jose's remote key set: cached for at most ten minutes, so
 * a key GitHub withdraws stops verifying within that time, refetched for an unknown key id at most
 * once per cooldown and every fetch bounded by a timeout. `fetchImpl` replaces the network in tests.
 */
export function createGithubActionsKeySet({
  fetchImpl,
  timeoutMs = 5_000,
  cooldownMs = 30_000,
  cacheMaxAgeMs = 600_000,
} = {}) {
  return createRemoteJWKSet(new URL(GITHUB_ACTIONS_JWKS_URL), {
    timeoutDuration: timeoutMs,
    cooldownDuration: cooldownMs,
    cacheMaxAge: cacheMaxAgeMs,
    ...(fetchImpl ? { [customFetch]: fetchImpl } : {}),
  });
}

/**
 * A token that does not verify is refused with a concrete 401 code; a key set that cannot be
 * fetched (timeout, network, a non-200 or unparsable answer) leaves the broker unavailable (503).
 */
function refusalFor(error) {
  if (error instanceof errors.JWTExpired) return new OidcRefusal("token_expired");
  if (error instanceof errors.JWTClaimValidationFailed) {
    if (error.claim === "iss") return new OidcRefusal("token_issuer_mismatch");
    if (error.claim === "aud") return new OidcRefusal("token_audience_mismatch");
    if (error.claim === "nbf" && error.reason === "check_failed") return new OidcRefusal("token_not_yet_valid");
    return new OidcRefusal("token_claims_invalid");
  }
  if (error instanceof errors.JOSEAlgNotAllowed) return new OidcRefusal("token_algorithm_refused");
  if (error instanceof errors.JWKSNoMatchingKey || error instanceof errors.JWKSMultipleMatchingKeys) {
    return new OidcRefusal("token_key_unknown");
  }
  if (error instanceof errors.JWSSignatureVerificationFailed) return new OidcRefusal("token_signature_invalid");
  if (
    error instanceof errors.JWKSTimeout ||
    error instanceof errors.JWKSInvalid ||
    (error instanceof errors.JOSEError && error.code === "ERR_JOSE_GENERIC")
  ) {
    return new OidcRefusal("jwks_unavailable");
  }
  if (error instanceof errors.JOSEError) return new OidcRefusal("token_malformed");
  // Anything else comes from fetching the key set (a network error is not a JOSE error).
  return new OidcRefusal("jwks_unavailable");
}

function stringClaim(payload, name, pattern) {
  const value = payload[name];
  if (typeof value !== "string" || value.length === 0 || value.length > 512 || (pattern && !pattern.test(value))) {
    throw new OidcRefusal("token_claims_invalid");
  }
  return value;
}

function decimalClaim(payload, name) {
  const value = stringClaim(payload, name, DECIMAL);
  if (!Number.isSafeInteger(Number(value))) throw new OidcRefusal("token_claims_invalid");
  return value;
}

/** An optional string claim: null when GitHub did not send it, refused when it is present but invalid. */
function optionalStringClaim(payload, name, maxLength = 512) {
  if (payload[name] === undefined) return null;
  const value = payload[name];
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength) {
    throw new OidcRefusal("token_claims_invalid");
  }
  return value;
}

/**
 * The claims admission reads, normalized: ids stay GitHub's decimal strings; a missing `environment`
 * is null, and so is a missing `job_workflow_ref`, which GitHub documents for jobs that use a
 * reusable workflow and need not send for a job defined directly in the workflow file.
 */
function claimsOf(payload) {
  const environment = optionalStringClaim(payload, "environment", 255);
  const sha = typeof payload.sha === "string" && COMMIT.test(payload.sha) ? payload.sha : null;
  return Object.freeze({
    jti: stringClaim(payload, "jti", JTI),
    exp: payload.exp,
    iat: payload.iat,
    repository: stringClaim(payload, "repository", REPOSITORY),
    repository_id: decimalClaim(payload, "repository_id"),
    repository_owner: stringClaim(payload, "repository_owner"),
    repository_owner_id: decimalClaim(payload, "repository_owner_id"),
    ref: stringClaim(payload, "ref"),
    event_name: stringClaim(payload, "event_name"),
    environment,
    workflow_ref: stringClaim(payload, "workflow_ref"),
    job_workflow_ref: optionalStringClaim(payload, "job_workflow_ref"),
    runner_environment: stringClaim(payload, "runner_environment"),
    run_id: decimalClaim(payload, "run_id"),
    run_attempt: decimalClaim(payload, "run_attempt"),
    actor: stringClaim(payload, "actor"),
    actor_id: decimalClaim(payload, "actor_id"),
    sha,
  });
}

/**
 * jose accepts an `aud` array that merely contains the expected audience. The broker requires its
 * origin to be the token's only audience: the string itself, or an array of exactly that string.
 */
function audienceIsExactly(aud, audience) {
  return aud === audience || (Array.isArray(aud) && aud.length === 1 && aud[0] === audience);
}

/**
 * Returns `verify(token)`, which resolves to the verified claims of one GitHub Actions OIDC token
 * whose only audience is `audience` (this broker's public origin) or throws OidcRefusal. A token
 * without a key id is malformed: it would otherwise verify against any single key of the set.
 */
export function createOidcVerifier({ audience, keySet, now = () => Date.now() }) {
  if (typeof audience !== "string" || audience.length === 0) throw new Error("OIDC audience is missing");
  if (typeof keySet !== "function") throw new Error("OIDC key set is missing");
  return async function verify(token) {
    if (typeof token !== "string" || token.length === 0) throw new OidcRefusal("token_missing");
    if (token.length > MAX_TOKEN_LENGTH || !COMPACT_JWS.test(token)) throw new OidcRefusal("token_malformed");
    let header;
    try {
      header = decodeProtectedHeader(token);
    } catch {
      throw new OidcRefusal("token_malformed");
    }
    if (typeof header.kid !== "string" || header.kid.length === 0) throw new OidcRefusal("token_malformed");
    if (header.alg !== "RS256") throw new OidcRefusal("token_algorithm_refused");
    const current = now();
    let payload;
    try {
      ({ payload } = await jwtVerify(token, keySet, {
        issuer: GITHUB_ACTIONS_ISSUER,
        audience,
        algorithms: ["RS256"],
        clockTolerance: OIDC_CLOCK_TOLERANCE_SECONDS,
        requiredClaims: ["exp", "iat"],
        currentDate: new Date(current),
      }));
    } catch (error) {
      throw refusalFor(error);
    }
    // jose has checked exp, nbf, iss, that aud contains the audience and that exp and iat exist; a
    // token for several audiences and a token issued in the future are refused here.
    if (!audienceIsExactly(payload.aud, audience)) throw new OidcRefusal("token_audience_mismatch");
    if (payload.iat > Math.floor(current / 1000) + OIDC_CLOCK_TOLERANCE_SECONDS) {
      throw new OidcRefusal("token_not_yet_valid");
    }
    return claimsOf(payload);
  };
}
