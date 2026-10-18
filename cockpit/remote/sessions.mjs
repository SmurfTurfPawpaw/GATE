import { createHash, randomBytes as nodeRandomBytes, timingSafeEqual } from "node:crypto";

export const SESSION_COOKIE_NAME = "__Host-gate-session";

const OPAQUE_BYTES = 32;
const OPAQUE_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const COOKIE_NAME_PATTERN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;
const COOKIE_VALUE_PATTERN = /^[\x21-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$/u;
const ZERO_TOKEN = Buffer.alloc(OPAQUE_BYTES);

const DEFAULTS = Object.freeze({
  idleTtlMs: 30 * 60 * 1_000,
  absoluteTtlMs: 12 * 60 * 60 * 1_000,
  rotationIntervalMs: 10 * 60 * 1_000,
  rotationGraceMs: 5 * 1_000,
  maxSessions: 32,
  maxCookieHeaderBytes: 4_096,
  maxCookieCount: 64
});

export class SessionStoreError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "SessionStoreError";
    this.code = code;
  }
}

/**
 * A bounded, in-memory browser-session store.
 *
 * Cookie credentials and CSRF values remain private to this module. Public
 * methods return frozen snapshots; the only representation of a cookie
 * credential that leaves the store is a complete Set-Cookie header value.
 */
export class SessionStore {
  #absoluteTtlMs;
  #byId = new Map();
  #clock;
  #closed = false;
  #idleTtlMs;
  #lastNow = Number.NEGATIVE_INFINITY;
  #maxCookieCount;
  #maxCookieHeaderBytes;
  #maxSessions;
  #randomBytes;
  #rotationIntervalMs;
  #rotationGraceMs;
  #tokenIndex = new Map();

  constructor(options = {}) {
    if (!isPlainObject(options)) {
      throw new TypeError("SessionStore options must be a plain object.");
    }

    this.#idleTtlMs = positiveSafeInteger(options.idleTtlMs ?? DEFAULTS.idleTtlMs, "idleTtlMs");
    this.#absoluteTtlMs = positiveSafeInteger(
      options.absoluteTtlMs ?? DEFAULTS.absoluteTtlMs,
      "absoluteTtlMs"
    );
    this.#rotationIntervalMs = nonNegativeSafeInteger(
      options.rotationIntervalMs ?? DEFAULTS.rotationIntervalMs,
      "rotationIntervalMs"
    );
    this.#rotationGraceMs = nonNegativeSafeInteger(
      options.rotationGraceMs ?? DEFAULTS.rotationGraceMs,
      "rotationGraceMs"
    );
    this.#maxSessions = positiveSafeInteger(options.maxSessions ?? DEFAULTS.maxSessions, "maxSessions");
    this.#maxCookieHeaderBytes = positiveSafeInteger(
      options.maxCookieHeaderBytes ?? DEFAULTS.maxCookieHeaderBytes,
      "maxCookieHeaderBytes"
    );
    this.#maxCookieCount = positiveSafeInteger(
      options.maxCookieCount ?? DEFAULTS.maxCookieCount,
      "maxCookieCount"
    );

    const clock = options.clock ?? Date.now;
    if (typeof clock === "function") {
      this.#clock = clock;
    } else if (clock && typeof clock.now === "function") {
      this.#clock = () => clock.now();
    } else {
      throw new TypeError("clock must be a function or an object with now().");
    }

    this.#randomBytes = options.randomBytes ?? nodeRandomBytes;
    if (typeof this.#randomBytes !== "function") {
      throw new TypeError("randomBytes must be a function.");
    }
  }

  get size() {
    return this.#byId.size;
  }

  create(identity) {
    this.#assertOpen();
    const immutableIdentity = immutableIdentityCopy(identity);
    const now = this.#now();
    this.#pruneAt(now);
    this.#makeRoom();

    const id = this.#newPublicId();
    const token = this.#newCookieToken();
    const csrf = this.#newDistinctToken(token);
    const absoluteExpiresAt = safeAdd(now, this.#absoluteTtlMs);
    const idleExpiresAt = Math.min(safeAdd(now, this.#idleTtlMs), absoluteExpiresAt);
    const record = {
      id,
      identity: immutableIdentity,
      token,
      tokenDigest: digestKey(token),
      previousToken: null,
      previousTokenDigest: null,
      previousTokenExpiresAt: null,
      csrf,
      createdAt: now,
      lastSeenAt: now,
      rotatedAt: now,
      idleExpiresAt,
      absoluteExpiresAt,
      revision: 1,
      epoch: 1
    };

    this.#byId.set(record.id, record);
    this.#tokenIndex.set(record.tokenDigest, record.id);

    return Object.freeze({
      session: snapshot(record),
      csrf: encodeOpaque(csrf),
      setCookie: serializeCookie(token, idleExpiresAt, now)
    });
  }

  /**
   * Authenticate a Cookie header. A successful result always contains a
   * Set-Cookie value so the browser's idle lifetime follows the server. When
   * the rotation interval has elapsed, that header carries a fresh credential.
   * One previous credential remains valid until the replacement is first
   * observed, then for a short fixed grace period. This keeps response loss
   * from stranding the browser while bounding overlap after acknowledgement.
   */
  authenticateCookie(cookieHeader) {
    this.#assertOpen();
    const cookies = parseCookieHeader(cookieHeader, {
      maxBytes: this.#maxCookieHeaderBytes,
      maxCount: this.#maxCookieCount
    });
    const encoded = cookies.get(SESSION_COOKIE_NAME);
    if (encoded === undefined) {
      return null;
    }

    const candidate = decodeOpaque(encoded);
    if (candidate === null) {
      return null;
    }

    const now = this.#now();
    this.#pruneAt(now);
    const id = this.#tokenIndex.get(digestKey(candidate));
    const record = id === undefined ? undefined : this.#byId.get(id);
    const current = record !== undefined && timingSafeEqual(candidate, record.token);
    const previous = record !== undefined && record.previousToken !== null
      && (record.previousTokenExpiresAt === null || now < record.previousTokenExpiresAt)
      && timingSafeEqual(candidate, record.previousToken);
    if (record === undefined || !current && !previous) {
      candidate.fill(0);
      return null;
    }

    candidate.fill(0);
    if (current && record.previousToken !== null && record.previousTokenExpiresAt === null) {
      record.previousTokenExpiresAt = safeAdd(now, this.#rotationGraceMs);
    }
    if (current && now - record.rotatedAt >= this.#rotationIntervalMs) {
      this.#rotate(record, now);
    }

    record.lastSeenAt = now;
    record.idleExpiresAt = Math.min(safeAdd(now, this.#idleTtlMs), record.absoluteExpiresAt);
    record.revision += 1;

    return Object.freeze({
      session: snapshot(record),
      setCookie: serializeCookie(record.token, record.idleExpiresAt, now)
    });
  }

  /**
   * Check whether a previously authenticated session snapshot still names the
   * current live epoch. This deliberately does not extend the idle lifetime:
   * long-lived transports must expire unless the browser authenticates again.
   */
  isActive(session) {
    this.#assertOpen();
    const now = this.#now();
    this.#pruneAt(now);

    const supplied = unwrapSession(session);
    if (supplied === null) {
      return false;
    }
    const record = this.#byId.get(supplied.id);
    return record !== undefined && supplied.epoch === record.epoch;
  }

  /**
   * Validate the write-side browser proof. `header` must be a request-header
   * object containing X-GATE-CSRF and Sec-Fetch-Site. Sec-Fetch-Site is
   * required and may be only `same-origin` or `same-site`; the separate exact
   * Origin equality check still prevents a sibling site from writing.
   */
  requireCsrf(session, origin, configuredOrigin, header) {
    this.#assertOpen();
    const now = this.#now();
    this.#pruneAt(now);

    const supplied = unwrapSession(session);
    if (supplied === null) {
      throw rejected("session-rejected", "The browser session is not active.");
    }
    const record = this.#byId.get(supplied.id);
    if (record === undefined || supplied.epoch !== record.epoch) {
      throw rejected("session-rejected", "The browser session is not active.");
    }

    if (
      typeof origin !== "string" ||
      typeof configuredOrigin !== "string" ||
      origin.length === 0 ||
      origin !== configuredOrigin ||
      !isSerializedOrigin(configuredOrigin)
    ) {
      throw rejected("origin-rejected", "The request origin was rejected.");
    }

    const { csrf, secFetchSite } = extractWriteHeaders(header);
    if (secFetchSite !== "same-origin" && secFetchSite !== "same-site") {
      throw rejected("fetch-site-rejected", "The browser request context was rejected.");
    }

    const decoded = decodeOpaque(csrf);
    const compared = decoded ?? ZERO_TOKEN;
    const matches = timingSafeEqual(compared, record.csrf);
    if (decoded === null || !matches) {
      throw rejected("csrf-rejected", "The browser write proof was rejected.");
    }

    return snapshot(record);
  }

  revoke(sessionId) {
    this.#assertOpen();
    if (typeof sessionId !== "string") {
      return false;
    }
    const record = this.#byId.get(sessionId);
    if (record === undefined) {
      return false;
    }
    this.#delete(record);
    return true;
  }

  prune() {
    this.#assertOpen();
    return this.#pruneAt(this.#now());
  }

  clear() {
    const count = this.#byId.size;
    for (const record of this.#byId.values()) {
      record.token.fill(0);
      record.previousToken?.fill(0);
      record.csrf.fill(0);
    }
    this.#byId.clear();
    this.#tokenIndex.clear();
    return count;
  }

  close() {
    if (this.#closed) {
      return 0;
    }
    const count = this.clear();
    this.#closed = true;
    return count;
  }

  #assertOpen() {
    if (this.#closed) {
      throw new SessionStoreError("store-closed", "The session store is closed.");
    }
  }

  #delete(record) {
    this.#byId.delete(record.id);
    this.#tokenIndex.delete(record.tokenDigest);
    if (record.previousTokenDigest !== null) this.#tokenIndex.delete(record.previousTokenDigest);
    record.token.fill(0);
    record.previousToken?.fill(0);
    record.csrf.fill(0);
  }

  #makeRoom() {
    while (this.#byId.size >= this.#maxSessions) {
      let oldest;
      for (const record of this.#byId.values()) {
        if (oldest === undefined || compareEviction(record, oldest) < 0) {
          oldest = record;
        }
      }
      this.#delete(oldest);
    }
  }

  #newCookieToken() {
    for (let attempt = 0; attempt < 16; attempt += 1) {
      const candidate = this.#randomOpaque();
      if (!this.#tokenIndex.has(digestKey(candidate))) {
        return candidate;
      }
      candidate.fill(0);
    }
    throw new SessionStoreError("token-generation-failed", "Could not generate a unique session credential.");
  }

  #newDistinctToken(other) {
    for (let attempt = 0; attempt < 16; attempt += 1) {
      const candidate = this.#randomOpaque();
      if (!timingSafeEqual(candidate, other)) {
        return candidate;
      }
      candidate.fill(0);
    }
    throw new SessionStoreError("token-generation-failed", "Could not generate a distinct browser proof.");
  }

  #newPublicId() {
    for (let attempt = 0; attempt < 16; attempt += 1) {
      const bytes = this.#randomOpaque();
      // Opaque base64url can begin with "-" or "_", while durable command
      // bindings deliberately require an alphanumeric first character.
      const candidate = `session_${encodeOpaque(bytes)}`;
      bytes.fill(0);
      if (!this.#byId.has(candidate)) {
        return candidate;
      }
    }
    throw new SessionStoreError("token-generation-failed", "Could not generate a unique session identifier.");
  }

  #now() {
    const observed = this.#clock();
    if (!Number.isSafeInteger(observed) || observed < 0) {
      throw new SessionStoreError("clock-invalid", "The session clock must return non-negative integer milliseconds.");
    }
    this.#lastNow = Math.max(this.#lastNow, observed);
    return this.#lastNow;
  }

  #pruneAt(now) {
    let removed = 0;
    for (const record of [...this.#byId.values()]) {
      if (now >= record.idleExpiresAt || now >= record.absoluteExpiresAt) {
        this.#delete(record);
        removed += 1;
      } else {
        this.#expirePrevious(record, now);
      }
    }
    return removed;
  }

  #randomOpaque() {
    const value = this.#randomBytes(OPAQUE_BYTES);
    if (!(value instanceof Uint8Array) || value.byteLength !== OPAQUE_BYTES) {
      throw new SessionStoreError("random-source-invalid", `randomBytes must return exactly ${OPAQUE_BYTES} bytes.`);
    }
    return Buffer.from(value);
  }

  #rotate(record, now) {
    const replacement = this.#newCookieToken();
    this.#discardPrevious(record);
    record.previousToken = record.token;
    record.previousTokenDigest = record.tokenDigest;
    record.previousTokenExpiresAt = null;
    record.token = replacement;
    record.tokenDigest = digestKey(replacement);
    record.rotatedAt = now;
    record.epoch += 1;
    this.#tokenIndex.set(record.tokenDigest, record.id);
  }

  #expirePrevious(record, now) {
    if (record.previousToken === null || record.previousTokenExpiresAt === null
        || now < record.previousTokenExpiresAt) return;
    this.#discardPrevious(record);
  }

  #discardPrevious(record) {
    if (record.previousToken === null) return;
    this.#tokenIndex.delete(record.previousTokenDigest);
    record.previousToken.fill(0);
    record.previousToken = null;
    record.previousTokenDigest = null;
    record.previousTokenExpiresAt = null;
  }
}

function compareEviction(left, right) {
  return (
    left.lastSeenAt - right.lastSeenAt ||
    left.createdAt - right.createdAt ||
    left.id.localeCompare(right.id)
  );
}

function decodeOpaque(value) {
  if (typeof value !== "string" || !OPAQUE_PATTERN.test(value)) {
    return null;
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.byteLength !== OPAQUE_BYTES || encodeOpaque(decoded) !== value) {
    decoded.fill(0);
    return null;
  }
  return decoded;
}

function digestKey(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function encodeOpaque(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function extractWriteHeaders(header) {
  if (!header || typeof header !== "object" || Array.isArray(header)) {
    return { csrf: undefined, secFetchSite: undefined };
  }
  return {
    csrf: singleHeader(header, "x-gate-csrf", "csrf"),
    secFetchSite: singleHeader(header, "sec-fetch-site", "secFetchSite")
  };
}

function singleHeader(headers, canonicalName, alias) {
  const matches = [];
  for (const [name, value] of Object.entries(headers)) {
    if (name.toLowerCase() === canonicalName || name === alias) {
      matches.push(value);
    }
  }
  if (matches.length !== 1 || typeof matches[0] !== "string") {
    return undefined;
  }
  return matches[0];
}

function immutableIdentityCopy(identity) {
  if (
    (typeof identity !== "string" && !isPlainObject(identity)) ||
    (isPlainObject(identity) && Object.keys(identity).length === 0)
  ) {
    throw new SessionStoreError(
      "identity-invalid",
      "The operator identity must be a non-empty string or non-empty plain object."
    );
  }
  const seen = new Set();
  const normalized = normalizeJson(identity, seen);
  const serialized = JSON.stringify(normalized);
  if (serialized === undefined || Buffer.byteLength(serialized, "utf8") > 4_096) {
    throw new SessionStoreError("identity-invalid", "The operator identity is empty or too large.");
  }
  return deepFreeze(normalized);
}

function normalizeJson(value, seen) {
  if (value === null || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "string") {
    if (value.length === 0) {
      throw new SessionStoreError("identity-invalid", "Identity strings must not be empty.");
    }
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new SessionStoreError("identity-invalid", "Identity numbers must be finite.");
    }
    return value;
  }
  if (typeof value !== "object" || value === undefined || seen.has(value)) {
    throw new SessionStoreError("identity-invalid", "The operator identity must be acyclic JSON data.");
  }

  seen.add(value);
  let result;
  if (Array.isArray(value)) {
    result = value.map((entry) => normalizeJson(entry, seen));
  } else {
    if (!isPlainObject(value)) {
      throw new SessionStoreError("identity-invalid", "The operator identity must contain only plain objects.");
    }
    result = Object.create(null);
    for (const key of Object.keys(value).sort()) {
      if (key === "__proto__" || key === "constructor" || key === "prototype") {
        throw new SessionStoreError("identity-invalid", "The operator identity contains a reserved key.");
      }
      result[key] = normalizeJson(value[key], seen);
    }
  }
  seen.delete(value);
  return result;
}

function deepFreeze(value) {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) {
      deepFreeze(child);
    }
    Object.freeze(value);
  }
  return value;
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isSerializedOrigin(value) {
  try {
    const parsed = new URL(value);
    return parsed.origin === value && parsed.username === "" && parsed.password === "";
  } catch {
    return false;
  }
}

function nonNegativeSafeInteger(value, name) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${name} must be a non-negative safe integer.`);
  }
  return value;
}

function parseCookieHeader(cookieHeader, { maxBytes, maxCount }) {
  const result = new Map();
  if (cookieHeader === undefined || cookieHeader === null || cookieHeader === "") {
    return result;
  }
  if (typeof cookieHeader !== "string") {
    throw new SessionStoreError("cookie-header-malformed", "Cookie must be a single header string.");
  }
  if (Buffer.byteLength(cookieHeader, "utf8") > maxBytes) {
    throw new SessionStoreError("cookie-header-oversized", "Cookie header exceeds the configured limit.");
  }
  if (/[^\x20-\x7E]/u.test(cookieHeader)) {
    throw new SessionStoreError("cookie-header-malformed", "Cookie header contains invalid characters.");
  }

  const pairs = cookieHeader.split(";");
  if (pairs.length > maxCount) {
    throw new SessionStoreError("cookie-header-oversized", "Cookie header contains too many values.");
  }
  for (const rawPair of pairs) {
    const pair = rawPair.trim();
    const separator = pair.indexOf("=");
    if (pair.length === 0 || separator <= 0) {
      throw new SessionStoreError("cookie-header-malformed", "Cookie header contains a malformed pair.");
    }
    const name = pair.slice(0, separator);
    const value = pair.slice(separator + 1);
    if (!COOKIE_NAME_PATTERN.test(name) || !COOKIE_VALUE_PATTERN.test(value)) {
      throw new SessionStoreError("cookie-header-malformed", "Cookie header contains a malformed pair.");
    }
    if (result.has(name)) {
      throw new SessionStoreError("cookie-header-duplicate", "Cookie header contains a duplicate name.");
    }
    result.set(name, value);
  }
  return result;
}

function positiveSafeInteger(value, name) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${name} must be a positive safe integer.`);
  }
  return value;
}

function rejected(code, message) {
  return new SessionStoreError(code, message);
}

function safeAdd(left, right) {
  const sum = left + right;
  if (!Number.isSafeInteger(sum)) {
    throw new SessionStoreError("clock-overflow", "Session expiry exceeds safe integer time.");
  }
  return sum;
}

function serializeCookie(token, expiresAt, now) {
  const maxAge = Math.max(1, Math.ceil((expiresAt - now) / 1_000));
  return `${SESSION_COOKIE_NAME}=${encodeOpaque(token)}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${maxAge}`;
}

function snapshot(record) {
  return Object.freeze({
    id: record.id,
    identity: record.identity,
    revision: record.revision,
    epoch: record.epoch,
    createdAt: record.createdAt,
    lastSeenAt: record.lastSeenAt,
    idleExpiresAt: record.idleExpiresAt,
    absoluteExpiresAt: record.absoluteExpiresAt,
    expiresAt: Math.min(record.idleExpiresAt, record.absoluteExpiresAt)
  });
}

function unwrapSession(value) {
  const candidate = value && isPlainObject(value.session) ? value.session : value;
  if (
    !candidate ||
    typeof candidate !== "object" ||
    typeof candidate.id !== "string" ||
    !Number.isSafeInteger(candidate.epoch)
  ) {
    return null;
  }
  return candidate;
}

