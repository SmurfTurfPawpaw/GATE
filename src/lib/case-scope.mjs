import crypto from "node:crypto";

const CASE_ID = /^[a-z][a-z0-9-]{1,62}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const DISPLAY_NAME = /^[A-Za-z][A-Za-z0-9 .'-]{0,59}$/u;

export const CASE_SCOPE_SCHEMA = "https://gate.local/schemas/case.schema.json";
export const CASE_SCOPE_API_VERSION = "gate.dev/case/v1";
export const CASE_SCOPE_KIND = "Case";
export const CASE_SCOPE_ISOLATION = Object.freeze({
  stateNamespace: "isolated-directory",
  processBoundary: "shared-user",
  networkBoundary: "adapter-dependent"
});

function exactObject(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} must contain exactly ${expected.join(", ")}`);
  }
  return value;
}

function assertCaseId(value, label) {
  if (typeof value !== "string" || !CASE_ID.test(value)) {
    throw new Error(`${label} is invalid`);
  }
}

function assertSha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
}

export function canonicalCaseScopeText(value) {
  return `${JSON.stringify(stableValue(value), null, 2)}\n`;
}

export function caseScopeDigest(value) {
  const envelope = structuredClone(value);
  delete envelope.scopeSha256;
  return crypto.createHash("sha256").update(canonicalCaseScopeText(envelope), "utf8").digest("hex");
}

function assertBinding(value, digestKey, label) {
  exactObject(value, ["id", digestKey], label);
  assertCaseId(value.id, `${label} id`);
  assertSha256(value[digestKey], `${label} ${digestKey}`);
}

function assertCanonicalInstant(value) {
  if (typeof value !== "string") throw new Error("case metadata createdAt must be a canonical UTC instant");
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    throw new Error("case metadata createdAt must be a canonical UTC instant");
  }
}

/**
 * Validate the complete immutable case-scope envelope and its content digest.
 * This verifier deliberately has no filesystem imports so path validation and
 * case storage can share it without introducing an import cycle.
 */
export function assertCaseScope(value, options = {}) {
  exactObject(value, [
    "$schema",
    "apiVersion",
    "kind",
    "metadata",
    "program",
    "project",
    "isolation",
    "scopeSha256"
  ], "case scope");
  if (value.$schema !== CASE_SCOPE_SCHEMA) throw new Error("case scope schema is invalid");
  if (value.apiVersion !== CASE_SCOPE_API_VERSION) throw new Error("case scope API version is invalid");
  if (value.kind !== CASE_SCOPE_KIND) throw new Error("case scope kind is invalid");

  exactObject(value.metadata, ["id", "displayName", "createdAt"], "case metadata");
  assertCaseId(value.metadata.id, "case metadata id");
  if (options.expectedId !== undefined && value.metadata.id !== options.expectedId) {
    throw new Error("case scope id does not match its directory");
  }
  if (typeof value.metadata.displayName !== "string" || !DISPLAY_NAME.test(value.metadata.displayName)) {
    throw new Error("case metadata displayName is invalid");
  }
  assertCanonicalInstant(value.metadata.createdAt);

  assertBinding(value.program, "profileSha256", "case program binding");
  if (value.project !== null) assertBinding(value.project, "contractSha256", "case project binding");

  exactObject(
    value.isolation,
    ["stateNamespace", "processBoundary", "networkBoundary"],
    "case isolation"
  );
  for (const [key, expected] of Object.entries(CASE_SCOPE_ISOLATION)) {
    if (value.isolation[key] !== expected) throw new Error(`case isolation ${key} is invalid`);
  }

  assertSha256(value.scopeSha256, "case scope scopeSha256");
  if (value.scopeSha256 !== caseScopeDigest(value)) throw new Error("case scope digest changed");
  return value;
}

export function assertCaseStateBinding(marker, scope, options = {}) {
  assertCaseScope(scope, options);
  exactObject(marker, ["caseId", "scopeSha256"], "case state-root binding");
  assertCaseId(marker.caseId, "case state-root binding caseId");
  assertSha256(marker.scopeSha256, "case state-root binding scopeSha256");
  if (marker.caseId !== scope.metadata.id || marker.scopeSha256 !== scope.scopeSha256) {
    throw new Error(`case state-root binding does not match its immutable scope: ${scope.metadata.id}`);
  }
  return marker;
}
