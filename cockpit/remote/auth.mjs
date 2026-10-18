import { createPublicKey, verify as verifySignature } from "node:crypto";
import { lookup as dnsLookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";

const MAX_TOKEN_BYTES = 24 * 1024;
const MAX_HEADER_SEGMENT_BYTES = 2 * 1024;
const MAX_PAYLOAD_SEGMENT_BYTES = 16 * 1024;
const MAX_SIGNATURE_SEGMENT_BYTES = 2 * 1024;
const MAX_JSON_DEPTH = 16;
const MAX_JWKS_BYTES = 64 * 1024;
const MAX_JWKS_KEYS = 32;
const ALLOWED_ALGORITHMS = new Set(["RS256", "ES256"]);
const ALLOWED_HEADER_MEMBERS = new Set(["alg", "kid", "typ"]);
const CONFIGURATION_MEMBERS = new Set([
  "issuer",
  "audience",
  "operatorSubject",
  "jwksUrl",
  "clockSkewSeconds",
  "maxTokenLifetimeSeconds",
  "jwksCacheMs",
  "jwksTimeoutMs"
]);
const OPTION_MEMBERS = new Set(["fetch", "clock", "lookup"]);

export class OidcVerificationError extends Error {
  constructor(code = "invalid-identity-assertion") {
    super("Identity assertion verification failed");
    this.name = "OidcVerificationError";
    this.code = code;
  }
}

function fail(code) {
  throw new OidcVerificationError(code);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function requireBoundedString(value, name, maximum = 2_048) {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new TypeError(`${name} must be a non-empty bounded string`);
  }
  return value;
}

function requireInteger(value, name, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${name} is outside its supported range`);
  }
  return value;
}

function parseIpv4(address) {
  if (isIP(address) !== 4) return null;
  return address.split(".").map((part) => Number(part));
}

function isPublicIpv4(address) {
  const octets = parseIpv4(address);
  if (!octets) return false;
  const [a, b] = octets;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && (b === 0 || b === 168)) return false;
  if (a === 198 && (b === 18 || b === 19 || b === 51)) return false;
  if (a === 203 && b === 0) return false;
  return true;
}

function parseIpv6(address) {
  let source = address.toLowerCase();
  const zoneIndex = source.indexOf("%");
  if (zoneIndex !== -1) source = source.slice(0, zoneIndex);

  let ipv4Tail = null;
  if (source.includes(".")) {
    const lastColon = source.lastIndexOf(":");
    if (lastColon === -1) return null;
    const octets = parseIpv4(source.slice(lastColon + 1));
    if (!octets) return null;
    ipv4Tail = [(octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]];
    source = `${source.slice(0, lastColon)}:${ipv4Tail[0].toString(16)}:${ipv4Tail[1].toString(16)}`;
  }

  const halves = source.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  if (halves.length === 1 && left.length !== 8) return null;
  const missing = 8 - left.length - right.length;
  if (missing < 0 || (halves.length === 2 && missing < 1)) return null;
  const pieces = [...left, ...Array(missing).fill("0"), ...right];
  if (pieces.length !== 8 || pieces.some((piece) => !/^[0-9a-f]{1,4}$/u.test(piece))) return null;
  return pieces.map((piece) => Number.parseInt(piece, 16));
}

function isPublicIpv6(address) {
  const pieces = parseIpv6(address);
  if (!pieces) return false;
  // Public unicast space is currently inside 2000::/3. Keeping the verifier
  // inside that range fails closed for local, link-local, ULA and multicast.
  if (pieces[0] < 0x2000 || pieces[0] > 0x3fff) return false;
  // Documentation range 2001:db8::/32 is not a network destination.
  if (pieces[0] === 0x2001 && pieces[1] === 0x0db8) return false;
  return true;
}

function isPublicAddress(address) {
  const family = isIP(address);
  if (family === 4) return isPublicIpv4(address);
  if (family === 6) return isPublicIpv6(address);
  return false;
}

function validateJwksUrl(value, allowTestTransport) {
  const raw = requireBoundedString(value, "jwksUrl", 2_048);
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new TypeError("jwksUrl must be an absolute URL");
  }
  if (url.username || url.password || url.hash) {
    throw new TypeError("jwksUrl must not contain credentials or a fragment");
  }
  if (!allowTestTransport && url.protocol !== "https:") {
    throw new TypeError("jwksUrl must use HTTPS");
  }
  if (!allowTestTransport && (!url.hostname || url.hostname === "localhost" || url.hostname.endsWith(".localhost") || url.hostname.endsWith(".local"))) {
    throw new TypeError("jwksUrl must not use a local host");
  }
  const literalHost = url.hostname.replace(/^\[|\]$/gu, "");
  if (!allowTestTransport && isIP(literalHost) && !isPublicAddress(literalHost)) {
    throw new TypeError("jwksUrl must not use a private address");
  }
  return Object.freeze({ raw: url.href, url, literalHost });
}

function validateConfiguration(config, allowTestTransport) {
  if (!isPlainObject(config)) throw new TypeError("OIDC configuration must be an object");
  if (Object.keys(config).some((member) => !CONFIGURATION_MEMBERS.has(member))) {
    throw new TypeError("OIDC configuration contains an unknown member");
  }
  const issuer = requireBoundedString(config.issuer, "issuer");
  const audience = requireBoundedString(config.audience, "audience");
  const operatorSubject = requireBoundedString(config.operatorSubject, "operatorSubject");
  const jwks = validateJwksUrl(config.jwksUrl, allowTestTransport);
  const clockSkewSeconds = requireInteger(config.clockSkewSeconds ?? 30, "clockSkewSeconds", 0, 120);
  const maxTokenLifetimeSeconds = requireInteger(
    config.maxTokenLifetimeSeconds ?? 3_600,
    "maxTokenLifetimeSeconds",
    1,
    86_400
  );
  const jwksCacheMs = requireInteger(config.jwksCacheMs ?? 300_000, "jwksCacheMs", 0, 3_600_000);
  const jwksTimeoutMs = requireInteger(config.jwksTimeoutMs ?? 3_000, "jwksTimeoutMs", 10, 10_000);
  return Object.freeze({
    issuer,
    audience,
    operatorSubject,
    jwks,
    clockSkewSeconds,
    maxTokenLifetimeSeconds,
    jwksCacheMs,
    jwksTimeoutMs
  });
}

function decodeBase64url(segment, maximumBytes, code) {
  if (typeof segment !== "string" || segment.length === 0 || segment.length > Math.ceil((maximumBytes * 4) / 3)) fail(code);
  if (!/^[A-Za-z0-9_-]+$/u.test(segment)) fail(code);
  let decoded;
  try {
    decoded = Buffer.from(segment, "base64url");
  } catch {
    fail(code);
  }
  if (decoded.length === 0 || decoded.length > maximumBytes || decoded.toString("base64url") !== segment) fail(code);
  return decoded;
}

function scanJson(text) {
  let index = 0;
  const skipSpace = () => {
    while (index < text.length && /[\u0009\u000a\u000d\u0020]/u.test(text[index])) index += 1;
  };
  const scanString = () => {
    const start = index;
    if (text[index] !== '"') fail("malformed-json");
    index += 1;
    while (index < text.length) {
      const character = text[index];
      if (character === '"') {
        index += 1;
        try {
          return JSON.parse(text.slice(start, index));
        } catch {
          fail("malformed-json");
        }
      }
      if (character === "\\") {
        index += 1;
        if (index >= text.length || !/["\\/bfnrtu]/u.test(text[index])) fail("malformed-json");
        if (text[index] === "u") {
          if (!/^[0-9a-fA-F]{4}$/u.test(text.slice(index + 1, index + 5))) fail("malformed-json");
          index += 4;
        }
      } else if (character.charCodeAt(0) < 0x20) {
        fail("malformed-json");
      }
      index += 1;
    }
    fail("malformed-json");
  };
  const scanValue = (depth) => {
    if (depth > MAX_JSON_DEPTH) fail("malformed-json");
    skipSpace();
    if (text[index] === '"') {
      scanString();
      return;
    }
    if (text[index] === "{") {
      index += 1;
      skipSpace();
      const members = new Set();
      if (text[index] === "}") {
        index += 1;
        return;
      }
      while (index < text.length) {
        skipSpace();
        const member = scanString();
        if (members.has(member)) fail("duplicate-json-member");
        members.add(member);
        skipSpace();
        if (text[index] !== ":") fail("malformed-json");
        index += 1;
        scanValue(depth + 1);
        skipSpace();
        if (text[index] === "}") {
          index += 1;
          return;
        }
        if (text[index] !== ",") fail("malformed-json");
        index += 1;
      }
      fail("malformed-json");
    }
    if (text[index] === "[") {
      index += 1;
      skipSpace();
      if (text[index] === "]") {
        index += 1;
        return;
      }
      while (index < text.length) {
        scanValue(depth + 1);
        skipSpace();
        if (text[index] === "]") {
          index += 1;
          return;
        }
        if (text[index] !== ",") fail("malformed-json");
        index += 1;
      }
      fail("malformed-json");
    }
    const remainder = text.slice(index);
    const primitive = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/u.exec(remainder);
    if (!primitive) fail("malformed-json");
    index += primitive[0].length;
  };

  scanValue(0);
  skipSpace();
  if (index !== text.length) fail("malformed-json");
}

function parseJson(buffer, code) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  } catch {
    fail(code);
  }
  try {
    scanJson(text);
    return JSON.parse(text);
  } catch (error) {
    if (error instanceof OidcVerificationError) throw error;
    fail(code);
  }
}

function parseCompactJws(value) {
  if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value, "utf8") > MAX_TOKEN_BYTES) {
    fail("malformed-assertion");
  }
  // The server chooses and extracts the assertion header. This verifier accepts
  // only that value and never reads a request or a different header itself.
  if (value.trim() !== value || /\s/u.test(value)) fail("malformed-assertion");
  const segments = value.split(".");
  if (segments.length !== 3) fail("malformed-assertion");
  const headerBytes = decodeBase64url(segments[0], MAX_HEADER_SEGMENT_BYTES, "malformed-header");
  const payloadBytes = decodeBase64url(segments[1], MAX_PAYLOAD_SEGMENT_BYTES, "malformed-claims");
  const signature = decodeBase64url(segments[2], MAX_SIGNATURE_SEGMENT_BYTES, "malformed-signature");
  const header = parseJson(headerBytes, "malformed-header");
  const claims = parseJson(payloadBytes, "malformed-claims");
  if (!isPlainObject(header) || !isPlainObject(claims)) fail("malformed-assertion");
  const headerMembers = Object.keys(header);
  if (headerMembers.some((member) => !ALLOWED_HEADER_MEMBERS.has(member))) fail("unsafe-header");
  if (!ALLOWED_ALGORITHMS.has(header.alg)) fail("unsupported-algorithm");
  if (typeof header.kid !== "string" || header.kid.length === 0 || header.kid.length > 128 || !/^[A-Za-z0-9._:-]+$/u.test(header.kid)) {
    fail("invalid-key-id");
  }
  if (Object.hasOwn(header, "typ") && header.typ !== "JWT") fail("unsafe-header");
  return Object.freeze({
    header: Object.freeze({ alg: header.alg, kid: header.kid, ...(header.typ ? { typ: header.typ } : {}) }),
    claims,
    signature,
    signingInput: Buffer.from(`${segments[0]}.${segments[1]}`, "ascii")
  });
}

async function resolvePublicJwksDestination(config, lookup) {
  if (config.jwks.literalHost && isIP(config.jwks.literalHost)) {
    if (!isPublicAddress(config.jwks.literalHost)) fail("private-jwks-destination");
    return Object.freeze({ address: config.jwks.literalHost, family: isIP(config.jwks.literalHost) });
  }
  let addresses;
  try {
    addresses = await lookup(config.jwks.url.hostname, { all: true, verbatim: true });
  } catch {
    fail("jwks-dns-failed");
  }
  if (!Array.isArray(addresses) || addresses.length === 0 || addresses.some((item) => !item || !isPublicAddress(item.address))) {
    fail("private-jwks-destination");
  }
  return Object.freeze({ address: addresses[0].address, family: isIP(addresses[0].address) });
}

function fetchPinnedHttps(url, destination, signal) {
  return new Promise((resolve, reject) => {
    const request = httpsRequest(
      url,
      {
        method: "GET",
        agent: false,
        signal,
        headers: { Accept: "application/jwk-set+json, application/json" },
        lookup(_hostname, _options, callback) {
          callback(null, destination.address, destination.family);
        }
      },
      (response) => {
        resolve({
          status: response.statusCode,
          redirected: false,
          url: url.href,
          headers: {
            get(name) {
              const value = response.headers[String(name).toLowerCase()];
              return Array.isArray(value) ? value.join(",") : (value ?? null);
            }
          },
          body: response
        });
      }
    );
    request.once("error", reject);
    request.end();
  });
}

async function readBoundedResponse(response) {
  const declaredLength = response.headers?.get?.("content-length");
  if (declaredLength !== null && declaredLength !== undefined) {
    const parsed = Number(declaredLength);
    if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > MAX_JWKS_BYTES) fail("jwks-too-large");
  }
  const chunks = [];
  let length = 0;
  if (response.body && typeof response.body.getReader === "function") {
    const reader = response.body.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!(value instanceof Uint8Array)) fail("invalid-jwks-body");
        length += value.byteLength;
        if (length > MAX_JWKS_BYTES) {
          await reader.cancel().catch(() => {});
          fail("jwks-too-large");
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock?.();
    }
  } else if (response.body && typeof response.body[Symbol.asyncIterator] === "function") {
    for await (const value of response.body) {
      if (!(value instanceof Uint8Array)) fail("invalid-jwks-body");
      length += value.byteLength;
      if (length > MAX_JWKS_BYTES) {
        response.body.destroy?.();
        fail("jwks-too-large");
      }
      chunks.push(value);
    }
  } else {
    fail("jwks-body-unavailable");
  }
  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)), length);
}

function discardResponse(response) {
  try {
    if (typeof response?.body?.destroy === "function") response.body.destroy();
    else response?.body?.cancel?.().catch(() => {});
  } catch {
    // The response is already being rejected; disposal is best effort.
  }
}

function validateJwksDocument(document) {
  if (!isPlainObject(document) || !Array.isArray(document.keys) || document.keys.length === 0 || document.keys.length > MAX_JWKS_KEYS) {
    fail("invalid-jwks");
  }
  const kids = new Set();
  for (const key of document.keys) {
    if (!isPlainObject(key) || typeof key.kid !== "string" || key.kid.length === 0 || key.kid.length > 128) fail("invalid-jwks");
    if (kids.has(key.kid)) fail("duplicate-jwks-key-id");
    kids.add(key.kid);
  }
  return document.keys;
}

function selectVerificationKey(keys, header) {
  const jwk = keys.find((candidate) => candidate.kid === header.kid);
  if (!jwk) return null;
  if (["d", "p", "q", "dp", "dq", "qi", "oth"].some((member) => Object.hasOwn(jwk, member))) {
    fail("invalid-verification-key");
  }
  if (jwk.use !== undefined && jwk.use !== "sig") fail("invalid-verification-key");
  if (
    jwk.key_ops !== undefined &&
    (!Array.isArray(jwk.key_ops) ||
      jwk.key_ops.length === 0 ||
      jwk.key_ops.some((operation) => typeof operation !== "string") ||
      new Set(jwk.key_ops).size !== jwk.key_ops.length ||
      !jwk.key_ops.includes("verify"))
  ) {
    fail("invalid-verification-key");
  }
  if (jwk.alg !== undefined && jwk.alg !== header.alg) fail("invalid-verification-key");
  if (header.alg === "RS256" && jwk.kty !== "RSA") fail("invalid-verification-key");
  if (header.alg === "ES256" && (jwk.kty !== "EC" || jwk.crv !== "P-256")) fail("invalid-verification-key");
  let key;
  try {
    key = createPublicKey({ key: jwk, format: "jwk" });
  } catch {
    fail("invalid-verification-key");
  }
  if (key.type !== "public") fail("invalid-verification-key");
  if (header.alg === "RS256") {
    if (key.asymmetricKeyType !== "rsa" || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2_048) fail("invalid-verification-key");
  } else if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
    fail("invalid-verification-key");
  }
  return key;
}

function validateNumericDate(value, name, required = true) {
  if (value === undefined && !required) return undefined;
  if (!Number.isSafeInteger(value) || value < 0) fail(`invalid-${name}`);
  return value;
}

function validateClaims(claims, config, nowMs) {
  const exactAudience =
    claims.aud === config.audience ||
    (Array.isArray(claims.aud) && claims.aud.length === 1 && claims.aud[0] === config.audience);
  if (claims.iss !== config.issuer || claims.sub !== config.operatorSubject || !exactAudience) {
    fail("identity-mismatch");
  }
  const issuedAt = validateNumericDate(claims.iat, "issued-at");
  const expiresAt = validateNumericDate(claims.exp, "expiration");
  const notBefore = validateNumericDate(claims.nbf, "not-before", false);
  const now = Math.floor(nowMs / 1_000);
  const skew = config.clockSkewSeconds;
  if (expiresAt <= issuedAt || expiresAt - issuedAt > config.maxTokenLifetimeSeconds) fail("invalid-token-lifetime");
  if (expiresAt <= now - skew) fail("expired-assertion");
  if (issuedAt > now + skew) fail("future-issued-at");
  if (notBefore !== undefined && notBefore > now + skew) fail("assertion-not-active");
  if (notBefore !== undefined && notBefore > expiresAt) fail("invalid-token-lifetime");
  return Object.freeze({ issuedAt, expiresAt, ...(notBefore === undefined ? {} : { notBefore }) });
}

function sanitizeIdentity(parsed, config, dates) {
  return Object.freeze({
    issuer: config.issuer,
    subject: config.operatorSubject,
    audience: config.audience,
    algorithm: parsed.header.alg,
    keyId: parsed.header.kid,
    issuedAt: dates.issuedAt,
    expiresAt: dates.expiresAt,
    ...(dates.notBefore === undefined ? {} : { notBefore: dates.notBefore })
  });
}

export function createOidcVerifier(configuration, options = {}) {
  if (!isPlainObject(options)) throw new TypeError("OIDC verifier options must be an object");
  if (Object.keys(options).some((member) => !OPTION_MEMBERS.has(member))) {
    throw new TypeError("OIDC verifier options contain an unknown member");
  }
  const injectedFetch = Object.hasOwn(options, "fetch");
  if (injectedFetch && typeof options.fetch !== "function") throw new TypeError("fetch must be a function");
  if (options.clock !== undefined && typeof options.clock !== "function") throw new TypeError("clock must be a function");
  if (options.lookup !== undefined && typeof options.lookup !== "function") throw new TypeError("lookup must be a function");
  const fetchImpl = options.fetch;
  const clock = options.clock ?? Date.now;
  const lookup = options.lookup ?? dnsLookup;
  const config = validateConfiguration(configuration, injectedFetch);
  let cache = null;
  let inFlight = null;

  const now = () => {
    const value = clock();
    if (!Number.isFinite(value) || value < 0) fail("invalid-clock");
    return value;
  };

  const fetchJwks = async () => {
    const controller = new AbortController();
    let rejectTimeout;
    const timeout = new Promise((_, reject) => {
      rejectTimeout = reject;
    });
    const timer = setTimeout(() => {
      controller.abort();
      rejectTimeout(new Error("JWKS request timed out"));
    }, config.jwksTimeoutMs);
    const operation = async () => {
      const response = injectedFetch
        ? await fetchImpl(config.jwks.raw, {
            method: "GET",
            redirect: "manual",
            signal: controller.signal,
            headers: Object.freeze({ Accept: "application/jwk-set+json, application/json" })
          })
        : await fetchPinnedHttps(config.jwks.url, await resolvePublicJwksDestination(config, lookup), controller.signal);
      if (!response || response.redirected === true || !Number.isInteger(response.status) || response.status < 200 || response.status > 299) {
        discardResponse(response);
        fail("jwks-http-rejected");
      }
      if (!injectedFetch && response.url !== config.jwks.raw) {
        discardResponse(response);
        fail("jwks-redirect-rejected");
      }
      const contentType = response.headers?.get?.("content-type")?.split(";", 1)[0]?.trim()?.toLowerCase();
      if (contentType !== "application/json" && contentType !== "application/jwk-set+json") {
        discardResponse(response);
        fail("jwks-content-type-rejected");
      }
      const document = parseJson(await readBoundedResponse(response), "invalid-jwks");
      const keys = validateJwksDocument(document);
      return Object.freeze({ keys, expiresAt: now() + config.jwksCacheMs });
    };
    try {
      return await Promise.race([operation(), timeout]);
    } catch (error) {
      if (error instanceof OidcVerificationError) throw error;
      fail("jwks-fetch-failed");
    } finally {
      clearTimeout(timer);
    }
  };

  const getJwks = async (forceRefresh = false) => {
    const currentTime = now();
    if (!forceRefresh && cache && currentTime < cache.expiresAt) return cache.keys;
    if (!inFlight) {
      inFlight = fetchJwks()
        .then((next) => {
          cache = next;
          return next.keys;
        })
        .finally(() => {
          inFlight = null;
        });
    }
    return inFlight;
  };

  const verify = async (headerValue) => {
    try {
      const parsed = parseCompactJws(headerValue);
      let keys = await getJwks(false);
      let key = selectVerificationKey(keys, parsed.header);
      if (!key) {
        keys = await getJwks(true);
        key = selectVerificationKey(keys, parsed.header);
      }
      if (!key) fail("unknown-key-id");
      if (parsed.header.alg === "ES256" && parsed.signature.length !== 64) fail("malformed-signature");
      if (parsed.header.alg === "RS256" && parsed.signature.length * 8 !== key.asymmetricKeyDetails.modulusLength) {
        fail("malformed-signature");
      }
      let valid = false;
      try {
        valid = verifySignature(
          "sha256",
          parsed.signingInput,
          parsed.header.alg === "ES256" ? { key, dsaEncoding: "ieee-p1363" } : key,
          parsed.signature
        );
      } catch {
        fail("invalid-signature");
      }
      if (!valid) fail("invalid-signature");
      const dates = validateClaims(parsed.claims, config, now());
      return sanitizeIdentity(parsed, config, dates);
    } catch (error) {
      if (error instanceof OidcVerificationError) throw error;
      throw new OidcVerificationError();
    }
  };

  return Object.freeze({ verify });
}
