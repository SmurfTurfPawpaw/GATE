import crypto from "node:crypto";

export const RUNNER_AUTH_VERSION = "gate.runner-request/v1";
export const DEFAULT_RUNNER_CLOCK_SKEW_MS = 60_000;

export const RUNNER_AUTH_HEADERS = Object.freeze({
  runner: "X-GATE-Runner",
  timestamp: "X-GATE-Timestamp",
  nonce: "X-GATE-Nonce",
  bodySha256: "X-GATE-Body-SHA256",
  signature: "X-GATE-Signature"
});

const MAX_CLOCK_SKEW_MS = 5 * 60_000;
const MAX_BODY_BYTES = 128 * 1024;
const MAX_PATH_BYTES = 4_096;
const MAX_PUBLIC_KEY_PEM_BYTES = 8_192;
const MAX_PRIVATE_KEY_PEM_BYTES = 16_384;
const RUNNER_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/u;
const METHOD = /^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}$/u;
const ORIGIN_FORM = /^\/[\x21-\x7e]*$/u;
const TIMESTAMP = /^(?:0|[1-9][0-9]{0,15})$/u;
const NONCE = /^[A-Za-z0-9_-]{32,64}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;
const PUBLIC_KEY_PEM = /^-----BEGIN PUBLIC KEY-----[\s\S]+-----END PUBLIC KEY-----\s*$/u;
const PRIVATE_KEY_PEM = /^-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----[\s\S]+-----END (?:ENCRYPTED )?PRIVATE KEY-----\s*$/u;
const REQUIRED_HEADER_NAMES = new Map(
  Object.values(RUNNER_AUTH_HEADERS).map((name) => [name.toLowerCase(), name])
);

export class RunnerAuthError extends Error {
  constructor(status, code, publicMessage) {
    super(publicMessage);
    this.name = "RunnerAuthError";
    this.status = status;
    this.code = code;
    this.publicMessage = publicMessage;
  }
}

function invalidRequest() {
  return new RunnerAuthError(400, "runner-auth-invalid", "The runner authentication request is invalid.");
}

function rejectedRequest() {
  return new RunnerAuthError(401, "runner-auth-rejected", "The runner authentication request was rejected.");
}

function replayedRequest() {
  return new RunnerAuthError(409, "runner-auth-replayed", "The runner authentication request was already used.");
}

function unavailableRequest() {
  return new RunnerAuthError(503, "runner-auth-unavailable", "Runner authentication is unavailable.");
}

function normalizeRunnerId(value) {
  if (typeof value !== "string" || !RUNNER_ID.test(value)) throw invalidRequest();
  return value;
}

function normalizeMethod(value) {
  if (typeof value !== "string" || !METHOD.test(value)) throw invalidRequest();
  return value;
}

function normalizePath(value) {
  if (typeof value !== "string" || !ORIGIN_FORM.test(value) || value.startsWith("//")
      || value.includes("#") || Buffer.byteLength(value, "utf8") > MAX_PATH_BYTES) {
    throw invalidRequest();
  }
  return value;
}

function normalizeTimestamp(value) {
  const raw = typeof value === "number" ? String(value) : value;
  if (typeof raw !== "string" || !TIMESTAMP.test(raw)) throw invalidRequest();
  const timestamp = Number(raw);
  if (!Number.isSafeInteger(timestamp) || timestamp < 1 || String(timestamp) !== raw) throw invalidRequest();
  return Object.freeze({ raw, timestamp });
}

function normalizeNonce(value) {
  if (typeof value !== "string" || !NONCE.test(value)) throw invalidRequest();
  return value;
}

function normalizeBody(value) {
  let body;
  if (value === undefined || value === null) body = Buffer.alloc(0);
  else if (Buffer.isBuffer(value)) body = value;
  else if (typeof value === "string") body = Buffer.from(value, "utf8");
  else if (ArrayBuffer.isView(value)) body = Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  else if (value instanceof ArrayBuffer) body = Buffer.from(value);
  else throw invalidRequest();
  if (body.byteLength > MAX_BODY_BYTES) throw invalidRequest();
  return body;
}

function normalizeBodySha256(value) {
  if (typeof value !== "string" || !SHA256.test(value)) throw invalidRequest();
  return value;
}

function normalizeSignature(value) {
  if (typeof value !== "string" || !SIGNATURE.test(value)) throw invalidRequest();
  let decoded;
  try {
    decoded = Buffer.from(value, "base64url");
  } catch {
    throw invalidRequest();
  }
  if (decoded.byteLength !== 64 || decoded.toString("base64url") !== value) throw invalidRequest();
  return decoded;
}

function normalizeNow(value) {
  const now = typeof value === "function" ? value() : value;
  if (!Number.isSafeInteger(now) || now < 1) throw new TypeError("runner authentication clock must return epoch milliseconds");
  return now;
}

function normalizeMaxSkew(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_CLOCK_SKEW_MS) {
    throw new TypeError("runner authentication clock skew must be between 1 and 300000 milliseconds");
  }
  return value;
}

function loadPrivateKey(value) {
  if (typeof value === "string") {
    if (Buffer.byteLength(value, "utf8") > MAX_PRIVATE_KEY_PEM_BYTES || !PRIVATE_KEY_PEM.test(value)) {
      throw new TypeError("runner private key must be an Ed25519 private KeyObject or PEM value");
    }
  } else if (!(value instanceof crypto.KeyObject) || value.type !== "private") {
    throw new TypeError("runner private key must be an Ed25519 private KeyObject or PEM value");
  }
  let key;
  try {
    key = value instanceof crypto.KeyObject ? value : crypto.createPrivateKey(value);
  } catch {
    throw new TypeError("runner private key must be an Ed25519 private KeyObject or PEM value");
  }
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
    throw new TypeError("runner private key must be an Ed25519 private KeyObject or PEM value");
  }
  return key;
}

function loadPublicKey(value) {
  if (typeof value === "string") {
    if (Buffer.byteLength(value, "utf8") > MAX_PUBLIC_KEY_PEM_BYTES || !PUBLIC_KEY_PEM.test(value)) {
      throw rejectedRequest();
    }
  } else if (!(value instanceof crypto.KeyObject) || value.type !== "public") {
    throw rejectedRequest();
  }
  let key;
  try {
    key = value instanceof crypto.KeyObject ? value : crypto.createPublicKey(value);
  } catch {
    throw rejectedRequest();
  }
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") throw rejectedRequest();
  return key;
}

function configuredPublicKey(publicKeys, runnerId) {
  let value;
  if (publicKeys instanceof Map) {
    value = publicKeys.get(runnerId);
  } else if (publicKeys !== null && typeof publicKeys === "object" && !Array.isArray(publicKeys)) {
    value = Object.hasOwn(publicKeys, runnerId) ? publicKeys[runnerId] : undefined;
  } else {
    throw new TypeError("runner public keys must be a Map or record");
  }
  if (value === undefined) throw rejectedRequest();
  return loadPublicKey(value);
}

function headerEntries(headers) {
  if (Array.isArray(headers)) {
    if (headers.length > 0 && headers.every((entry) => Array.isArray(entry))) {
      return headers.map((entry) => {
        if (entry.length !== 2) throw invalidRequest();
        return entry;
      });
    }
    if (headers.length % 2 !== 0) throw invalidRequest();
    const entries = [];
    for (let index = 0; index < headers.length; index += 2) entries.push([headers[index], headers[index + 1]]);
    return entries;
  }
  if (typeof Headers === "function" && headers instanceof Headers) return [...headers.entries()];
  if (headers !== null && typeof headers === "object") return Object.entries(headers);
  throw invalidRequest();
}

function runnerHeaders(headers) {
  const selected = new Map();
  for (const [rawName, rawValue] of headerEntries(headers)) {
    if (typeof rawName !== "string") throw invalidRequest();
    const lowerName = rawName.toLowerCase();
    if (!lowerName.startsWith("x-gate-")) continue;
    if (!REQUIRED_HEADER_NAMES.has(lowerName) || selected.has(lowerName)
        || typeof rawValue !== "string") {
      throw invalidRequest();
    }
    selected.set(lowerName, rawValue);
  }
  if (selected.size !== REQUIRED_HEADER_NAMES.size) throw invalidRequest();
  const result = {};
  for (const [lowerName, exactName] of REQUIRED_HEADER_NAMES) result[exactName] = selected.get(lowerName);
  return result;
}

function lengthPrefixed(value) {
  return `${Buffer.byteLength(value, "utf8")}:${value}`;
}

export function canonicalRunnerRequest({ runnerId, method, path, timestamp, nonce, bodySha256 }) {
  const normalizedTimestamp = normalizeTimestamp(timestamp).raw;
  const fields = [
    ["version", RUNNER_AUTH_VERSION],
    ["runner-id", normalizeRunnerId(runnerId)],
    ["method", normalizeMethod(method)],
    ["path", normalizePath(path)],
    ["timestamp", normalizedTimestamp],
    ["nonce", normalizeNonce(nonce)],
    ["body-sha256", normalizeBodySha256(bodySha256)]
  ];
  return fields.map(([name, value]) => `${lengthPrefixed(name)}${lengthPrefixed(value)}`).join("");
}

function createSignedHeaders({ runnerId, method, path, body, timestamp, nonce, privateKey }) {
  const normalizedBody = normalizeBody(body);
  const bodySha256 = crypto.createHash("sha256").update(normalizedBody).digest("hex");
  const normalizedTimestamp = normalizeTimestamp(timestamp).raw;
  const canonical = canonicalRunnerRequest({
    runnerId,
    method,
    path,
    timestamp: normalizedTimestamp,
    nonce,
    bodySha256
  });
  const signature = crypto.sign(null, Buffer.from(canonical, "utf8"), privateKey).toString("base64url");
  return Object.freeze({
    [RUNNER_AUTH_HEADERS.runner]: runnerId,
    [RUNNER_AUTH_HEADERS.timestamp]: normalizedTimestamp,
    [RUNNER_AUTH_HEADERS.nonce]: nonce,
    [RUNNER_AUTH_HEADERS.bodySha256]: bodySha256,
    [RUNNER_AUTH_HEADERS.signature]: signature
  });
}

export function signRunnerRequest({
  runnerId,
  privateKey,
  method,
  path,
  body,
  timestamp = Date.now(),
  nonce = crypto.randomBytes(24).toString("base64url")
}) {
  return createSignedHeaders({
    runnerId: normalizeRunnerId(runnerId),
    privateKey: loadPrivateKey(privateKey),
    method,
    path,
    body,
    timestamp,
    nonce
  });
}

export function createRunnerRequestSigner({ runnerId, privateKey, now = Date.now, nonceFactory } = {}) {
  const normalizedRunnerId = normalizeRunnerId(runnerId);
  const signingKey = loadPrivateKey(privateKey);
  if (typeof now !== "function") throw new TypeError("runner authentication clock must be a function");
  if (nonceFactory !== undefined && typeof nonceFactory !== "function") {
    throw new TypeError("runner authentication nonce factory must be a function");
  }
  const nextNonce = nonceFactory || (() => crypto.randomBytes(24).toString("base64url"));
  return Object.freeze({
    sign({ method, path, body, timestamp = normalizeNow(now), nonce = nextNonce() }) {
      return createSignedHeaders({
        runnerId: normalizedRunnerId,
        privateKey: signingKey,
        method,
        path,
        body,
        timestamp,
        nonce
      });
    }
  });
}

// This authenticates an already-buffered HTTP request. The server owns the
// transport boundary: it must require HTTPS and pass the untouched request
// target (path plus query), raw header representation, and exact body bytes.
export async function verifyRunnerRequest({
  headers,
  publicKeys,
  nonceStore,
  method,
  path,
  body,
  now = Date.now(),
  maxSkewMs = DEFAULT_RUNNER_CLOCK_SKEW_MS
}) {
  const skew = normalizeMaxSkew(maxSkewMs);
  const currentTime = normalizeNow(now);
  if (!nonceStore || typeof nonceStore.consume !== "function") {
    throw new TypeError("runner nonce store must provide consume(runnerId, nonce, expiresAt)");
  }
  const selected = runnerHeaders(headers);
  const runnerId = normalizeRunnerId(selected[RUNNER_AUTH_HEADERS.runner]);
  const { raw: timestampText, timestamp } = normalizeTimestamp(selected[RUNNER_AUTH_HEADERS.timestamp]);
  const nonce = normalizeNonce(selected[RUNNER_AUTH_HEADERS.nonce]);
  const claimedDigest = normalizeBodySha256(selected[RUNNER_AUTH_HEADERS.bodySha256]);
  const signature = normalizeSignature(selected[RUNNER_AUTH_HEADERS.signature]);
  const normalizedMethod = normalizeMethod(method);
  const normalizedPath = normalizePath(path);
  const normalizedBody = normalizeBody(body);

  // Keep the accepted timestamp interval open at both ends. Nonces expire at
  // timestamp + skew, so accepting that exact instant would let cleanup remove
  // the first nonce before an otherwise identical replay is verified.
  if (Math.abs(currentTime - timestamp) >= skew) throw rejectedRequest();

  const actualDigest = crypto.createHash("sha256").update(normalizedBody).digest();
  const claimedDigestBytes = Buffer.from(claimedDigest, "hex");
  if (actualDigest.byteLength !== claimedDigestBytes.byteLength
      || !crypto.timingSafeEqual(actualDigest, claimedDigestBytes)) {
    throw rejectedRequest();
  }

  const canonical = canonicalRunnerRequest({
    runnerId,
    method: normalizedMethod,
    path: normalizedPath,
    timestamp: timestampText,
    nonce,
    bodySha256: claimedDigest
  });
  const publicKey = configuredPublicKey(publicKeys, runnerId);
  if (!crypto.verify(null, Buffer.from(canonical, "utf8"), publicKey, signature)) throw rejectedRequest();

  const expiresAt = Math.max(currentTime + 1, timestamp + skew);
  let consumed;
  try {
    consumed = await nonceStore.consume(runnerId, nonce, expiresAt);
  } catch {
    throw unavailableRequest();
  }
  if (consumed !== true) throw replayedRequest();
  return Object.freeze({ runnerId });
}

export class MemoryRunnerNonceStore {
  #entries = new Map();
  #maxEntries;
  #now;

  constructor({ maxEntries = 10_000, now = Date.now } = {}) {
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1 || maxEntries > 1_000_000) {
      throw new TypeError("runner nonce store limit must be between 1 and 1000000");
    }
    if (typeof now !== "function") throw new TypeError("runner nonce store clock must be a function");
    this.#maxEntries = maxEntries;
    this.#now = now;
  }

  consume(runnerId, nonce, expiresAt) {
    const currentTime = normalizeNow(this.#now);
    normalizeRunnerId(runnerId);
    normalizeNonce(nonce);
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= currentTime) throw new TypeError("runner nonce expiry is invalid");
    for (const [key, expiry] of this.#entries) {
      if (expiry <= currentTime) this.#entries.delete(key);
    }
    const key = `${runnerId}\u0000${nonce}`;
    if (this.#entries.has(key)) return false;
    if (this.#entries.size >= this.#maxEntries) throw new Error("runner nonce store is full");
    this.#entries.set(key, expiresAt);
    return true;
  }
}

export const runnerAuthInternals = Object.freeze({
  MAX_BODY_BYTES,
  MAX_PATH_BYTES,
  normalizePath,
  runnerHeaders
});
