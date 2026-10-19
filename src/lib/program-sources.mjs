import crypto from "node:crypto";
import dns from "node:dns";
import fs from "node:fs";
import https from "node:https";
import net from "node:net";
import path from "node:path";
import { ensureRuntime } from "./paths.mjs";
import {
  openPrivateFileExclusive,
  readPrivateFileBounded,
  securePrivateDirectory,
  securePrivateFile,
  syncPrivateDirectory,
  writePrivateFileAtomic,
  writePrivateFileExclusive
} from "./private-fs.mjs";
import { assertValidDocument } from "./schema.mjs";
import { assertNoLikelySecret, assertNoUnsafeText, oneLine } from "./text.mjs";

export const PROGRAM_SOURCE_MAXIMUM_BYTES = 2 * 1024 * 1024;
export const PROGRAM_SOURCE_MAXIMUM_REDIRECTS = 3;
export const PROGRAM_SOURCE_REQUEST_TIMEOUT_MS = 15_000;
export const PROGRAM_SOURCE_MAXIMUM_MANIFEST_BYTES = 512 * 1024;
export const PROGRAM_SOURCE_MAXIMUM_HISTORY_BYTES = 16 * 1024 * 1024;
export const PROGRAM_SOURCE_MAXIMUM_BODY_HISTORY_BYTES = 64 * 1024 * 1024;
export const PROGRAM_SOURCE_MAXIMUM_REVISIONS = 999_999;

const ID = /^[a-z][a-z0-9-]{1,62}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const MEDIA_TYPE = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/u;
const MANIFEST_FILE = /^r([0-9]{6})-([a-f0-9]{16})\.json$/u;
const BODY_FILE = /^([a-f0-9]{64})\.bin$/u;
const SOURCE_TYPES = new Set([
  "operator-statement", "program-rules", "safe-harbor", "scope-list", "contract",
  "platform-page", "architecture", "account-instructions", "other"
]);
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const SNAPSHOT_SCHEMA = "https://gate.local/schemas/program-source-snapshot.schema.json";

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
  }
  return value;
}

function canonicalBytes(value) {
  return Buffer.from(JSON.stringify(canonicalValue(value)), "utf8");
}

function canonicalDigest(value, domain) {
  return sha256(Buffer.concat([Buffer.from(`${domain}\0`, "utf8"), canonicalBytes(value)]));
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const observed = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(observed) !== JSON.stringify(wanted)) {
    throw new Error(`${label} must contain exactly: ${wanted.join(", ")}`);
  }
}

function assertId(value, label) {
  if (typeof value !== "string" || !ID.test(value)) {
    throw new Error(`${label} must start with a letter and contain only lowercase letters, numbers, or dashes`);
  }
  return value;
}

function normalizeMediaType(value, fallback = "application/octet-stream") {
  const candidate = String(value || fallback).split(";", 1)[0].trim().toLowerCase();
  if (!MEDIA_TYPE.test(candidate) || candidate.length > 200) {
    throw new Error("program source media type is invalid");
  }
  return candidate;
}

function normalizeTimestamp(value) {
  const candidate = value instanceof Date ? value : new Date(value ?? Date.now());
  if (!Number.isFinite(candidate.getTime())) throw new Error("program source capture time is invalid");
  return candidate.toISOString();
}

function assertReference(value, label = "program source reference") {
  if (typeof value !== "string" || value.length > 2000 || /\s/u.test(value)) {
    throw new Error(`${label} must be a bounded URL without whitespace`);
  }
  assertNoUnsafeText(value, label);
  assertNoLikelySecret(value, label);
  if (!value.startsWith("https://") && !value.startsWith("private://")) {
    throw new Error(`${label} must use https:// or private://`);
  }
  return value;
}

function assertSafeProjectionText(value, label) {
  if (typeof value === "string") {
    assertNoUnsafeText(value, label);
    assertNoLikelySecret(value, label);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertSafeProjectionText(entry, `${label}[${index}]`));
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, entry] of Object.entries(value)) assertSafeProjectionText(entry, `${label}.${key}`);
  }
}

function normalizeProjection(value = {}) {
  const candidate = value === undefined ? {} : value;
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
    throw new Error("program source projection must be an object");
  }
  if (Object.keys(candidate).some((key) => !new Set(["scope", "rules"]).has(key))) {
    throw new Error("program source projection contains an unknown field");
  }
  const projection = {
    scope: candidate.scope === undefined ? [] : structuredClone(candidate.scope),
    rules: candidate.rules === undefined ? [] : structuredClone(candidate.rules)
  };
  for (const [label, entries] of Object.entries(projection)) {
    if (!Array.isArray(entries)) throw new Error(`program source projection ${label} must be an array`);
    const ids = entries.map((entry) => entry?.id);
    if (new Set(ids).size !== ids.length) throw new Error(`program source projection ${label} ids must be unique`);
    for (const entry of entries) {
      if (entry?.disposition === "conditional" && (!Array.isArray(entry.conditions) || entry.conditions.length === 0)) {
        throw new Error(`conditional program source projection ${label} claims require conditions`);
      }
      if (entry?.disposition === "unknown" && entry?.claimState !== "unverified") {
        throw new Error(`unknown program source projection ${label} claims must be unverified`);
      }
    }
  }
  assertSafeProjectionText(projection, "program source projection");
  return canonicalValue(projection);
}

function normalizeSource(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("program source identity must be an object");
  }
  exactKeys(value, ["id", "type", "title", "reference", ...(Object.hasOwn(value, "notes") ? ["notes"] : [])], "program source identity");
  const id = assertId(value.id, "program source id");
  if (!SOURCE_TYPES.has(value.type)) throw new Error("program source type is invalid");
  const title = oneLine(value.title, { name: "program source title", max: 500 });
  assertNoLikelySecret(title, "program source title");
  const reference = assertReference(value.reference);
  let notes = null;
  if (value.notes !== undefined && value.notes !== null) {
    if (typeof value.notes !== "string" || value.notes.length > 10_000 || !value.notes.trim()) {
      throw new Error("program source notes must be non-empty text of at most 10000 characters");
    }
    assertNoUnsafeText(value.notes, "program source notes");
    assertNoLikelySecret(value.notes, "program source notes");
    notes = value.notes.trim();
  }
  return { id, type: value.type, title, reference, notes };
}

function snapshotEnvelope(snapshot) {
  const { snapshotSha256: ignored, ...metadata } = snapshot.metadata;
  return { ...snapshot, metadata };
}

function snapshotDigest(snapshot) {
  return canonicalDigest(snapshotEnvelope(snapshot), "gate.program-source-snapshot.v1");
}

export function programSourceProjectionDigest(projection) {
  return canonicalDigest(normalizeProjection(projection), "gate.program-source-projection.v1");
}

function sameOrDescendant(parent, candidate) {
  const relative = path.relative(path.resolve(parent), path.resolve(candidate));
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

function sourceRoot(paths) {
  if (!paths?.home || !paths?.repo) throw new Error("program source storage requires an exact GATE runtime path table");
  if (paths.caseId) throw new Error("program source snapshots use the shared registry and reject a selected case runtime");
  return path.join(path.resolve(paths.home), "program-sources");
}

export function programSourcePaths(paths, programId, sourceId) {
  const cleanProgramId = assertId(programId, "program id");
  const cleanSourceId = assertId(sourceId, "program source id");
  const root = sourceRoot(paths);
  const program = path.join(root, cleanProgramId);
  const source = path.join(program, cleanSourceId);
  return {
    root,
    program,
    source,
    revisions: path.join(source, "revisions"),
    bodies: path.join(source, "bodies"),
    current: path.join(source, "current.json"),
    lock: path.join(source, ".mutation.lock")
  };
}

function ensureStorage(paths, programId, sourceId) {
  ensureRuntime(paths);
  const locations = programSourcePaths(paths, programId, sourceId);
  for (const [directory, label] of [
    [locations.root, "private program source root"],
    [locations.program, `private program source program ${programId}`],
    [locations.source, `private program source ${sourceId}`],
    [locations.revisions, `private program source revisions ${sourceId}`],
    [locations.bodies, `private program source bodies ${sourceId}`]
  ]) securePrivateDirectory(directory, { label });
  return locations;
}

function existingStorage(paths, programId, sourceId) {
  ensureRuntime(paths);
  const locations = programSourcePaths(paths, programId, sourceId);
  try {
    securePrivateDirectory(locations.root, { create: false, label: "private program source root" });
    securePrivateDirectory(locations.program, { create: false, label: `private program source program ${programId}` });
    securePrivateDirectory(locations.source, { create: false, label: `private program source ${sourceId}` });
    securePrivateDirectory(locations.revisions, { create: false, label: `private program source revisions ${sourceId}` });
    securePrivateDirectory(locations.bodies, { create: false, label: `private program source bodies ${sourceId}` });
  } catch (error) {
    if (error.code === "ENOENT") {
      throw Object.assign(new Error(`program source does not exist: ${programId}/${sourceId}`), { code: "ENOENT", cause: error });
    }
    throw error;
  }
  return locations;
}

function readJsonBounded(file, maximumBytes, label) {
  let value;
  try {
    value = JSON.parse(readPrivateFileBounded(file, maximumBytes, "utf8", { label }));
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error(`${label} is not valid JSON`, { cause: error });
    throw error;
  }
  return value;
}

function stableExternalFileRead(file, paths, maximumBytes) {
  const resolved = path.resolve(file);
  const before = fs.lstatSync(resolved);
  if (before.isSymbolicLink() || !before.isFile() || before.nlink !== 1) {
    throw new Error("program source input must be one regular, non-linked file");
  }
  if (process.platform !== "win32" && typeof process.geteuid === "function" && before.uid !== process.geteuid()) {
    throw new Error("program source input must be owned by the current user");
  }
  const real = fs.realpathSync.native ? fs.realpathSync.native(resolved) : fs.realpathSync(resolved);
  const realRepo = fs.realpathSync.native ? fs.realpathSync.native(paths.repo) : fs.realpathSync(paths.repo);
  if (sameOrDescendant(realRepo, real)) {
    throw new Error("program source input must stay outside the GATE repository");
  }
  if (before.size > maximumBytes) throw new Error(`program source input exceeds the ${maximumBytes}-byte limit`);
  const descriptor = fs.openSync(resolved, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const opened = fs.fstatSync(descriptor);
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) {
      throw new Error("program source input changed while it was being opened");
    }
    const chunks = [];
    let total = 0;
    while (total <= maximumBytes) {
      const buffer = Buffer.allocUnsafe(Math.min(64 * 1024, maximumBytes + 1 - total));
      const count = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      chunks.push(buffer.subarray(0, count));
      total += count;
    }
    if (total > maximumBytes) throw new Error(`program source input exceeds the ${maximumBytes}-byte limit`);
    const after = fs.fstatSync(descriptor);
    const named = fs.lstatSync(resolved);
    if (
      after.dev !== opened.dev || after.ino !== opened.ino || named.dev !== opened.dev || named.ino !== opened.ino ||
      after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs ||
      total !== after.size
    ) throw new Error("program source input changed while it was being read");
    return Buffer.concat(chunks, total);
  } finally {
    fs.closeSync(descriptor);
  }
}

export function readProgramSourceProjection(file, options = {}) {
  const paths = options.paths;
  if (!paths) throw new Error("program source projection requires an exact GATE runtime path table");
  let value;
  try {
    value = JSON.parse(
      stableExternalFileRead(file, paths, PROGRAM_SOURCE_MAXIMUM_MANIFEST_BYTES).toString("utf8")
    );
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error("program source projection is not valid JSON", { cause: error });
    throw error;
  }
  return normalizeProjection(value);
}

function ipv4Number(address) {
  if (net.isIP(address) !== 4) return null;
  const parts = address.split(".").map(Number);
  return (((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3]) >>> 0;
}

function ipv4In(address, base, bits) {
  const value = ipv4Number(address);
  const reference = ipv4Number(base);
  if (value === null || reference === null) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (value & mask) === (reference & mask);
}

function ipv6Number(address) {
  let value = address.toLowerCase().split("%", 1)[0];
  if (value.startsWith("[") && value.endsWith("]")) value = value.slice(1, -1);
  const ipv4Tail = value.match(/(?:^|:)(\d+\.\d+\.\d+\.\d+)$/u)?.[1];
  if (ipv4Tail) {
    const ipv4 = ipv4Number(ipv4Tail);
    if (ipv4 === null) return null;
    value = value.slice(0, -ipv4Tail.length) + `${(ipv4 >>> 16).toString(16)}:${(ipv4 & 0xffff).toString(16)}`;
  }
  if (net.isIP(address.replace(/^\[|\]$/gu, "")) !== 6 && !value.includes(":")) return null;
  const halves = value.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves[1] ? halves[1].split(":") : [];
  const fill = halves.length === 2 ? 8 - left.length - right.length : 0;
  const groups = [...left, ...Array(fill).fill("0"), ...right];
  if (groups.length !== 8 || groups.some((item) => !/^[a-f0-9]{1,4}$/u.test(item))) return null;
  return groups.reduce((total, item) => (total << 16n) | BigInt(`0x${item}`), 0n);
}

function ipv6In(address, base, bits) {
  const value = ipv6Number(address);
  const reference = ipv6Number(base);
  if (value === null || reference === null) return false;
  const shift = BigInt(128 - bits);
  return (value >> shift) === (reference >> shift);
}

export function isPublicProgramSourceAddress(address) {
  if (net.isIP(address) === 4) {
    return ![
      ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
      ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
      ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
      ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4]
    ].some(([base, bits]) => ipv4In(address, base, bits));
  }
  if (net.isIP(address.replace(/^\[|\]$/gu, "")) !== 6) return false;
  const clean = address.replace(/^\[|\]$/gu, "").split("%", 1)[0];
  if (ipv6In(clean, "::ffff:0:0", 96)) {
    const value = ipv6Number(clean);
    const embedded = Number(value & 0xffffffffn) >>> 0;
    return isPublicProgramSourceAddress([
      embedded >>> 24, (embedded >>> 16) & 255, (embedded >>> 8) & 255, embedded & 255
    ].join("."));
  }
  return ipv6In(clean, "2000::", 3) && ![
    ["2001::", 32], ["2001:2::", 48], ["2001:10::", 28], ["2001:db8::", 32], ["2002::", 16]
  ].some(([base, bits]) => ipv6In(clean, base, bits));
}

function normalizePublicUrl(value) {
  let parsed;
  try {
    parsed = new URL(String(value));
  } catch (error) {
    throw new Error("public program source URL is invalid", { cause: error });
  }
  if (parsed.protocol !== "https:") throw new Error("public program source URL must use HTTPS");
  if (parsed.username || parsed.password) throw new Error("public program source URL must not contain user information");
  if (parsed.port && parsed.port !== "443") throw new Error("public program source URL must use the default HTTPS port");
  if (parsed.href.length > 2000) throw new Error("public program source URL exceeds the 2000-character limit");
  parsed.hash = "";
  assertNoLikelySecret(parsed.href, "public program source URL");
  const hostname = parsed.hostname.replace(/^\[|\]$/gu, "").toLowerCase();
  if (
    hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local") ||
    hostname.endsWith(".internal") || hostname.endsWith(".home.arpa") || hostname.endsWith(".invalid") ||
    hostname.endsWith(".test")
  ) throw new Error("public program source URL hostname is not public");
  return parsed;
}

function awaitWithSignal(promise, signal, message) {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(new Error(message));
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (action, value) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", abort);
      action(value);
    };
    const abort = () => finish(reject, new Error(message));
    signal.addEventListener("abort", abort, { once: true });
    Promise.resolve(promise).then(
      (value) => finish(resolve, value),
      (error) => finish(reject, error)
    );
  });
}

export async function resolvePublicProgramSourceUrl(value, options = {}) {
  const parsed = normalizePublicUrl(value);
  const hostname = parsed.hostname.replace(/^\[|\]$/gu, "");
  let addresses;
  if (net.isIP(hostname)) {
    addresses = [{ address: hostname, family: net.isIP(hostname) }];
  } else {
    const resolver = options.lookup || dns.promises.lookup;
    addresses = await awaitWithSignal(
      resolver(hostname, { all: true, verbatim: true }),
      options.signal,
      "public program source request timed out during DNS resolution"
    );
  }
  if (!Array.isArray(addresses) || addresses.length === 0) {
    throw new Error("public program source URL did not resolve to an address");
  }
  const normalized = addresses.map((entry) => ({ address: String(entry.address), family: Number(entry.family) }));
  if (normalized.some((entry) => ![4, 6].includes(entry.family) || !isPublicProgramSourceAddress(entry.address))) {
    throw new Error("public program source URL resolved to a non-public or unsupported address");
  }
  return { url: parsed.href, hostname, addresses: normalized };
}

function addressesEquivalent(left, right) {
  if (left === right) return true;
  const left4 = ipv4Number(left);
  const right4 = ipv4Number(right);
  if (left4 !== null && right4 !== null) return left4 === right4;
  const left6 = ipv6Number(left);
  const right6 = ipv6Number(right);
  if (left6 !== null && ipv6In(left, "::ffff:0:0", 96) && right4 !== null) {
    return (Number(left6 & 0xffffffffn) >>> 0) === right4;
  }
  if (right6 !== null && ipv6In(right, "::ffff:0:0", 96) && left4 !== null) {
    return (Number(right6 & 0xffffffffn) >>> 0) === left4;
  }
  return left6 !== null && right6 !== null && left6 === right6;
}

function defaultHttpsTransport({ url, address, family, maximumBytes, timeoutMs, signal }) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const request = https.request({
      protocol: "https:",
      hostname: address,
      family,
      port: 443,
      path: `${parsed.pathname}${parsed.search}`,
      method: "GET",
      servername: net.isIP(parsed.hostname.replace(/^\[|\]$/gu, "")) ? undefined : parsed.hostname,
      rejectUnauthorized: true,
      headers: {
        Host: parsed.host,
        Accept: "text/html, application/json;q=0.9, text/plain;q=0.8, application/xml;q=0.7, */*;q=0.1",
        "Accept-Encoding": "identity",
        "User-Agent": "GATE-program-source-snapshot/1"
      }
    }, (response) => {
      const chunks = [];
      let total = 0;
      response.on("error", reject);
      const declared = Number(response.headers["content-length"]);
      if (Number.isFinite(declared) && declared > maximumBytes) {
        response.destroy(new Error(`public program source exceeds the ${maximumBytes}-byte limit`));
        return;
      }
      response.on("data", (chunk) => {
        total += chunk.length;
        if (total > maximumBytes) {
          response.destroy(new Error(`public program source exceeds the ${maximumBytes}-byte limit`));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => resolve({
        status: Number(response.statusCode),
        headers: response.headers,
        body: Buffer.concat(chunks, total)
      }));
    });
    request.setTimeout(timeoutMs, () => request.destroy(new Error("public program source request timed out")));
    const abort = () => request.destroy(new Error("public program source request timed out"));
    request.on("close", () => signal?.removeEventListener("abort", abort));
    request.on("error", reject);
    if (signal?.aborted) abort();
    else signal?.addEventListener("abort", abort, { once: true });
    request.on("socket", (socket) => {
      socket.once("secureConnect", () => {
        if (!addressesEquivalent(socket.remoteAddress || "", address)) {
          request.destroy(new Error("public program source peer address changed before TLS completion"));
        }
      });
    });
    request.end();
  });
}

function headerValue(headers, name) {
  if (!headers || typeof headers !== "object") return null;
  const value = headers[name] ?? headers[name.toLowerCase()] ?? null;
  if (Array.isArray(value)) return value[0] ?? null;
  return value === undefined || value === null ? null : String(value);
}

export async function fetchPublicProgramSource(value, options = {}) {
  const maximumBytes = options.maximumBytes ?? PROGRAM_SOURCE_MAXIMUM_BYTES;
  const timeoutMs = options.timeoutMs ?? PROGRAM_SOURCE_REQUEST_TIMEOUT_MS;
  const maximumRedirects = options.maximumRedirects ?? PROGRAM_SOURCE_MAXIMUM_REDIRECTS;
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > PROGRAM_SOURCE_MAXIMUM_BYTES) {
    throw new Error(`public program source byte limit must be between 1 and ${PROGRAM_SOURCE_MAXIMUM_BYTES}`);
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60_000) {
    throw new Error("public program source timeout must be between 100 and 60000 milliseconds");
  }
  if (!Number.isSafeInteger(maximumRedirects) || maximumRedirects < 0 || maximumRedirects > PROGRAM_SOURCE_MAXIMUM_REDIRECTS) {
    throw new Error(`public program source redirects must be between 0 and ${PROGRAM_SOURCE_MAXIMUM_REDIRECTS}`);
  }
  const transport = options.transport || defaultHttpsTransport;
  const requested = normalizePublicUrl(value).href;
  let current = requested;
  let remainingBytes = maximumBytes;
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(), timeoutMs);
  try {
    for (let redirects = 0; redirects <= maximumRedirects; redirects += 1) {
      const resolved = await resolvePublicProgramSourceUrl(current, {
        lookup: options.lookup,
        signal: controller.signal
      });
      const selected = resolved.addresses[0];
      const response = await awaitWithSignal(transport({
        url: resolved.url,
        address: selected.address,
        family: selected.family,
        maximumBytes: remainingBytes,
        timeoutMs,
        signal: controller.signal
      }), controller.signal, "public program source request timed out");
      if (!response || !Number.isSafeInteger(response.status) || !Buffer.isBuffer(response.body)) {
        throw new Error("public program source transport returned an invalid response");
      }
      if (response.body.length > remainingBytes) {
        throw new Error(`public program source exceeds the cumulative ${maximumBytes}-byte limit`);
      }
      remainingBytes -= response.body.length;
      if (REDIRECT_STATUSES.has(response.status)) {
        const location = headerValue(response.headers, "location");
        if (!location) throw new Error("public program source redirect omitted a location");
        if (redirects === maximumRedirects) throw new Error("public program source exceeded the redirect limit");
        current = normalizePublicUrl(new URL(location, resolved.url).href).href;
        continue;
      }
      if (response.status < 200 || response.status > 299) {
        throw new Error(`public program source returned HTTP ${response.status}`);
      }
      const contentEncodingValue = headerValue(response.headers, "content-encoding");
      const contentEncoding = contentEncodingValue
        ? oneLine(contentEncodingValue, { name: "public program source content encoding", max: 500 })
        : null;
      return {
        body: response.body,
        requestedUrl: requested,
        finalUrl: resolved.url,
        redirects,
        httpStatus: response.status,
        mediaType: normalizeMediaType(headerValue(response.headers, "content-type")),
        contentEncoding
      };
    }
  } finally {
    clearTimeout(deadline);
  }
  throw new Error("public program source retrieval ended without a response");
}

function bodyRef(programId, sourceId, digest) {
  return `private://program-sources/${programId}/${sourceId}/bodies/${digest}.bin`;
}

function manifestFilename(revision, digest) {
  return `r${String(revision).padStart(6, "0")}-${digest.slice(0, 16)}.json`;
}

function readPointer(locations) {
  if (!securePrivateFile(locations.current, { label: "current program source pointer" })) return null;
  const pointer = readJsonBounded(locations.current, 4096, "current program source pointer");
  exactKeys(pointer, ["apiVersion", "revision", "manifest", "snapshotSha256"], "current program source pointer");
  if (pointer.apiVersion !== "gate.dev/program-source-pointer/v1") throw new Error("current program source pointer version is invalid");
  if (!Number.isSafeInteger(pointer.revision) || pointer.revision < 1 || pointer.revision > PROGRAM_SOURCE_MAXIMUM_REVISIONS) {
    throw new Error("current program source pointer revision is invalid");
  }
  if (!MANIFEST_FILE.test(pointer.manifest) || !SHA256.test(pointer.snapshotSha256 || "")) {
    throw new Error("current program source pointer identity is invalid");
  }
  return pointer;
}

function resolveBodyPath(snapshot, paths, locations) {
  const expected = bodyRef(snapshot.metadata.programId, snapshot.metadata.sourceId, snapshot.metadata.contentSha256);
  if (snapshot.storage.bodyRef !== expected) throw new Error("program source body reference does not match its content digest");
  const file = path.join(locations.bodies, `${snapshot.metadata.contentSha256}.bin`);
  if (!sameOrDescendant(sourceRoot(paths), file)) throw new Error("program source body reference escapes private storage");
  return file;
}

function verifySnapshot(snapshot, paths, locations, options = {}) {
  assertValidDocument(snapshot, "program-source-snapshot.schema.json", { paths });
  if (snapshot.metadata.programId !== path.basename(locations.program) || snapshot.metadata.sourceId !== path.basename(locations.source)) {
    throw new Error("program source snapshot storage identity does not match its metadata");
  }
  if (snapshot.source.id !== snapshot.metadata.sourceId || snapshot.source.contentSha256 !== snapshot.metadata.contentSha256 ||
      snapshot.source.observedAt !== snapshot.metadata.capturedAt) {
    throw new Error("program source snapshot source projection does not match its metadata");
  }
  if (programSourceProjectionDigest(snapshot.projection) !== snapshot.metadata.projectionSha256) {
    throw new Error("program source projection digest changed");
  }
  if (snapshotDigest(snapshot) !== snapshot.metadata.snapshotSha256) throw new Error("program source snapshot digest changed");
  const bodyFile = resolveBodyPath(snapshot, paths, locations);
  if (options.verifyBody === false) return snapshot;
  const body = readPrivateFileBounded(bodyFile, PROGRAM_SOURCE_MAXIMUM_BYTES, null, { label: "private program source body" });
  if (body.length !== snapshot.metadata.bodyBytes || sha256(body) !== snapshot.metadata.contentSha256) {
    throw new Error("private program source body changed after snapshot publication");
  }
  return snapshot;
}

function manifestRevision(name) {
  const match = MANIFEST_FILE.exec(name);
  return match ? Number(match[1]) : null;
}

function assertPredecessor(snapshot, previous) {
  const expected = previous ? {
    revision: previous.metadata.revision,
    snapshotSha256: previous.metadata.snapshotSha256,
    contentSha256: previous.metadata.contentSha256,
    projectionSha256: previous.metadata.projectionSha256
  } : null;
  if (JSON.stringify(canonicalValue(snapshot.predecessor)) !== JSON.stringify(canonicalValue(expected))) {
    throw new Error(`program source revision ${snapshot.metadata.revision} predecessor chain changed`);
  }
}

function readCurrentUnlocked(paths, locations, manifestNames = null) {
  const manifests = manifestNames || fs.readdirSync(locations.revisions);
  const pointer = readPointer(locations);
  if (!pointer) {
    if (manifests.length > 0) throw new Error("program source revision history exists without a current pointer");
    return null;
  }
  if (manifests.length !== pointer.revision) {
    throw new Error("program source revision history and current pointer diverged");
  }
  const ordered = [...manifests].sort((left, right) => manifestRevision(left) - manifestRevision(right));
  if (ordered.at(-1) !== pointer.manifest) {
    throw new Error("current program source pointer does not name the latest contiguous revision");
  }
  let totalBytes = 0;
  let previous = null;
  const verifiedBodyDigests = new Set();
  for (let index = 0; index < ordered.length; index += 1) {
    const revision = index + 1;
    const name = ordered[index];
    if (manifestRevision(name) !== revision) throw new Error("program source revision history is not contiguous");
    const file = path.join(locations.revisions, name);
    const stat = fs.statSync(file);
    totalBytes += stat.size;
    if (stat.size > PROGRAM_SOURCE_MAXIMUM_MANIFEST_BYTES || totalBytes > PROGRAM_SOURCE_MAXIMUM_HISTORY_BYTES) {
      throw new Error("program source revision history exceeds its private read bound");
    }
    const snapshot = readJsonBounded(
      file,
      PROGRAM_SOURCE_MAXIMUM_MANIFEST_BYTES,
      `program source revision ${revision}`
    );
    const verifyBody = !verifiedBodyDigests.has(snapshot.metadata.contentSha256);
    verifySnapshot(snapshot, paths, locations, { verifyBody });
    if (verifyBody) verifiedBodyDigests.add(snapshot.metadata.contentSha256);
    if (
      snapshot.metadata.revision !== revision ||
      name !== manifestFilename(revision, snapshot.metadata.snapshotSha256)
    ) throw new Error(`program source revision ${revision} filename does not match its snapshot`);
    assertPredecessor(snapshot, previous);
    previous = snapshot;
  }
  if (!previous || previous.metadata.snapshotSha256 !== pointer.snapshotSha256) {
    throw new Error("current program source pointer does not match its revision manifest");
  }
  return verifySnapshot(previous, paths, locations);
}

function auditStorage(locations, options = {}) {
  const sourceEntries = fs.readdirSync(locations.source);
  if (sourceEntries.length > 4) throw new Error("program source storage contains too many control entries");
  const allowed = new Set(["revisions", "bodies", "current.json", ".mutation.lock"]);
  for (const entry of sourceEntries) {
    if (!allowed.has(entry)) throw new Error(`program source storage contains an unexpected entry: ${entry}`);
    const file = path.join(locations.source, entry);
    if (entry === "revisions" || entry === "bodies") securePrivateDirectory(file, { create: false, label: `program source ${entry}` });
    else if (entry === ".mutation.lock" && options.ownLock) continue;
    else securePrivateFile(file, { allowMissing: false, label: `program source ${entry}` });
  }
  const manifests = fs.readdirSync(locations.revisions);
  if (manifests.length > PROGRAM_SOURCE_MAXIMUM_REVISIONS) throw new Error("program source revision limit reached");
  for (const entry of manifests) {
    if (!MANIFEST_FILE.test(entry)) throw new Error(`program source revisions contain an unexpected entry: ${entry}`);
    securePrivateFile(path.join(locations.revisions, entry), { allowMissing: false, label: `program source revision ${entry}` });
  }
  const bodies = fs.readdirSync(locations.bodies);
  if (bodies.length > 1_000_000) throw new Error("program source body limit reached");
  let bodyBytes = 0;
  for (const entry of bodies) {
    if (!BODY_FILE.test(entry)) throw new Error(`program source bodies contain an unexpected entry: ${entry}`);
    const file = path.join(locations.bodies, entry);
    securePrivateFile(file, { allowMissing: false, label: `program source body ${entry}` });
    bodyBytes += fs.statSync(file).size;
    if (bodyBytes > PROGRAM_SOURCE_MAXIMUM_BODY_HISTORY_BYTES) {
      throw new Error("program source retained body history exceeds its private read bound");
    }
  }
  return { manifests, bodyBytes };
}

async function withMutationLock(locations, action) {
  let descriptor;
  try {
    descriptor = openPrivateFileExclusive(locations.lock, { label: "program source mutation lock" });
  } catch (error) {
    if (error.code === "EEXIST") throw new Error("program source is locked or has an interrupted mutation requiring review", { cause: error });
    throw error;
  }
  const identity = fs.fstatSync(descriptor);
  let retainOnFailure = false;
  let succeeded = false;
  try {
    fs.writeFileSync(descriptor, `${JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() })}\n`, "utf8");
    fs.fsyncSync(descriptor);
    const result = await action({
      beginDurableMutation() {
        retainOnFailure = true;
      }
    });
    succeeded = true;
    return result;
  } finally {
    fs.closeSync(descriptor);
    const named = fs.lstatSync(locations.lock);
    if (named.dev !== identity.dev || named.ino !== identity.ino || !named.isFile() || named.isSymbolicLink()) {
      throw new Error("program source mutation lock changed while held");
    }
    if (succeeded || !retainOnFailure) fs.unlinkSync(locations.lock);
    syncPrivateDirectory(locations.source, { label: "private program source directory" });
  }
}

function compareIdCollections(previous = [], current = []) {
  const before = new Map(previous.map((item) => [item.id, canonicalDigest(item, "gate.program-source-claim.v1")]));
  const after = new Map(current.map((item) => [item.id, canonicalDigest(item, "gate.program-source-claim.v1")]));
  let added = 0;
  let removed = 0;
  let changed = 0;
  let unchanged = 0;
  for (const [id, digest] of after) {
    if (!before.has(id)) added += 1;
    else if (before.get(id) === digest) unchanged += 1;
    else changed += 1;
  }
  for (const id of before.keys()) if (!after.has(id)) removed += 1;
  return { added, removed, changed, unchanged };
}

export function diffProgramSourceSnapshots(previous, current) {
  if (!current) throw new Error("current program source snapshot is required");
  const first = previous === null || previous === undefined;
  if (!first && (previous.metadata.programId !== current.metadata.programId || previous.metadata.sourceId !== current.metadata.sourceId)) {
    throw new Error("program source diff requires snapshots from the same source");
  }
  const contentChanged = first || previous.metadata.contentSha256 !== current.metadata.contentSha256;
  const projectionChanged = first || previous.metadata.projectionSha256 !== current.metadata.projectionSha256;
  const sourceMetadataChanged = first || canonicalDigest({
    type: previous.source.type,
    title: previous.source.title,
    reference: previous.source.reference,
    notes: previous.source.notes
  }, "gate.program-source-identity.v1") !== canonicalDigest({
    type: current.source.type,
    title: current.source.title,
    reference: current.source.reference,
    notes: current.source.notes
  }, "gate.program-source-identity.v1");
  return {
    firstRevision: first,
    previousRevision: first ? null : previous.metadata.revision,
    currentRevision: current.metadata.revision,
    changed: contentChanged || projectionChanged || sourceMetadataChanged,
    contentChanged,
    projectionChanged,
    sourceMetadataChanged,
    scope: compareIdCollections(first ? [] : previous.projection.scope, current.projection.scope),
    rules: compareIdCollections(first ? [] : previous.projection.rules, current.projection.rules)
  };
}

export function programProfileSourceFromSnapshot(snapshot) {
  return structuredClone(snapshot.source);
}

export function programSourceSnapshotSummary(snapshot) {
  if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) {
    throw new Error("program source snapshot is required");
  }
  return {
    programId: snapshot.metadata.programId,
    sourceId: snapshot.metadata.sourceId,
    revision: snapshot.metadata.revision,
    capturedAt: snapshot.metadata.capturedAt,
    identities: {
      contentSha256: snapshot.metadata.contentSha256,
      projectionSha256: snapshot.metadata.projectionSha256,
      snapshotSha256: snapshot.metadata.snapshotSha256
    },
    body: {
      bytes: snapshot.metadata.bodyBytes,
      mediaType: snapshot.acquisition.mediaType,
      contentEncoding: snapshot.acquisition.contentEncoding
    },
    source: {
      type: snapshot.source.type,
      title: snapshot.source.title,
      reference: snapshot.source.reference,
      observedAt: snapshot.source.observedAt,
      claimState: snapshot.source.claimState
    },
    acquisition: {
      method: snapshot.acquisition.method,
      redirects: snapshot.acquisition.redirects,
      httpStatus: snapshot.acquisition.httpStatus
    },
    projection: {
      scopeClaims: snapshot.projection.scope.length,
      ruleClaims: snapshot.projection.rules.length
    },
    predecessor: snapshot.predecessor ? structuredClone(snapshot.predecessor) : null
  };
}

export function readCurrentProgramSource(programId, sourceId, options = {}) {
  const paths = options.paths;
  const locations = existingStorage(paths, programId, sourceId);
  if (fs.existsSync(locations.lock)) throw new Error("program source is locked or has an interrupted mutation requiring review");
  const { manifests } = auditStorage(locations);
  const snapshot = readCurrentUnlocked(paths, locations, manifests);
  if (!snapshot) throw Object.assign(new Error(`program source does not exist: ${programId}/${sourceId}`), { code: "ENOENT" });
  return snapshot;
}

export function readProgramSourceRevision(programId, sourceId, revision, options = {}) {
  if (!Number.isSafeInteger(revision) || revision < 1 || revision > PROGRAM_SOURCE_MAXIMUM_REVISIONS) {
    throw new Error("program source revision must be a positive integer within the revision limit");
  }
  const paths = options.paths;
  const locations = existingStorage(paths, programId, sourceId);
  if (fs.existsSync(locations.lock)) throw new Error("program source is locked or has an interrupted mutation requiring review");
  const { manifests } = auditStorage(locations);
  const current = readCurrentUnlocked(paths, locations, manifests);
  if (!current || revision > current.metadata.revision) {
    throw Object.assign(
      new Error(`program source revision does not exist: ${programId}/${sourceId}@${revision}`),
      { code: "ENOENT" }
    );
  }
  const matching = manifests.filter((name) => manifestRevision(name) === revision);
  if (matching.length !== 1) throw new Error(`program source revision ${revision} is not uniquely retained`);
  const snapshot = readJsonBounded(
    path.join(locations.revisions, matching[0]),
    PROGRAM_SOURCE_MAXIMUM_MANIFEST_BYTES,
    `program source revision ${revision}`
  );
  verifySnapshot(snapshot, paths, locations);
  if (
    snapshot.metadata.revision !== revision ||
    matching[0] !== manifestFilename(revision, snapshot.metadata.snapshotSha256)
  ) throw new Error(`program source revision ${revision} filename does not match its snapshot`);
  return snapshot;
}

export async function importProgramSource(options = {}) {
  const paths = options.paths;
  const programId = assertId(options.programId, "program id");
  let source = normalizeSource(options.source);
  const projection = normalizeProjection(options.projection);
  const acquisition = options.acquisition;
  if (!acquisition || typeof acquisition !== "object" || Array.isArray(acquisition)) {
    throw new Error("program source acquisition is required");
  }
  let acquired;
  if (acquisition.kind === "local-file") {
    exactKeys(acquisition, ["kind", "path", ...(Object.hasOwn(acquisition, "mediaType") ? ["mediaType"] : [])], "local program source acquisition");
    const body = stableExternalFileRead(acquisition.path, paths, PROGRAM_SOURCE_MAXIMUM_BYTES);
    acquired = {
      body,
      requestedUrl: null,
      finalUrl: null,
      redirects: 0,
      httpStatus: null,
      mediaType: normalizeMediaType(acquisition.mediaType),
      contentEncoding: null
    };
  } else if (acquisition.kind === "public-url") {
    exactKeys(acquisition, ["kind", "url"], "public URL program source acquisition");
    if (options.allowNetwork !== true) {
      throw new Error("public program source retrieval requires explicit allowNetwork: true");
    }
    const requestedInput = normalizePublicUrl(acquisition.url).href;
    if (!source.reference.startsWith("https://") || normalizePublicUrl(source.reference).href !== requestedInput) {
      throw new Error("public program source reference must match the exact requested URL");
    }
    source = { ...source, reference: requestedInput };
    const retriever = options.fetchPublicSource || fetchPublicProgramSource;
    acquired = await retriever(requestedInput, options.fetchOptions || {});
    if (!acquired || !Buffer.isBuffer(acquired.body)) throw new Error("public program source retriever returned invalid body bytes");
    if (acquired.body.length > PROGRAM_SOURCE_MAXIMUM_BYTES) {
      throw new Error(`public program source exceeds the ${PROGRAM_SOURCE_MAXIMUM_BYTES}-byte limit`);
    }
    acquired = {
      ...acquired,
      requestedUrl: normalizePublicUrl(acquired.requestedUrl).href,
      finalUrl: normalizePublicUrl(acquired.finalUrl).href,
      mediaType: normalizeMediaType(acquired.mediaType),
      contentEncoding: acquired.contentEncoding === null || acquired.contentEncoding === undefined
        ? null
        : oneLine(acquired.contentEncoding, { name: "public program source content encoding", max: 500 })
    };
    if (acquired.requestedUrl !== requestedInput) {
      throw new Error("public program source retriever changed the requested URL identity");
    }
  } else {
    throw new Error("program source acquisition kind must be local-file or public-url");
  }
  const capturedAt = normalizeTimestamp(options.now);
  const contentSha256 = sha256(acquired.body);
  const projectionSha256 = programSourceProjectionDigest(projection);
  const locations = ensureStorage(paths, programId, source.id);
  auditStorage(locations);

  return withMutationLock(locations, async ({ beginDurableMutation }) => {
    const { manifests, bodyBytes: retainedBodyBytes } = auditStorage(locations, { ownLock: true });
    const previous = readCurrentUnlocked(paths, locations, manifests);
    const revision = (previous?.metadata.revision || 0) + 1;
    if (revision > PROGRAM_SOURCE_MAXIMUM_REVISIONS) throw new Error("program source revision limit reached");
    const snapshot = {
      $schema: SNAPSHOT_SCHEMA,
      apiVersion: "gate.dev/program-source-snapshot/v1",
      kind: "ProgramSourceSnapshot",
      metadata: {
        programId,
        sourceId: source.id,
        revision,
        capturedAt,
        contentSha256,
        projectionSha256,
        snapshotSha256: "0".repeat(64),
        bodyBytes: acquired.body.length
      },
      source: {
        ...source,
        contentSha256,
        observedAt: capturedAt,
        claimState: "observed"
      },
      acquisition: {
        method: acquisition.kind,
        requestedUrl: acquired.requestedUrl,
        finalUrl: acquired.finalUrl,
        redirects: acquired.redirects,
        httpStatus: acquired.httpStatus,
        mediaType: acquired.mediaType,
        contentEncoding: acquired.contentEncoding
      },
      projection,
      storage: { bodyRef: bodyRef(programId, source.id, contentSha256) },
      predecessor: previous ? {
        revision: previous.metadata.revision,
        snapshotSha256: previous.metadata.snapshotSha256,
        contentSha256: previous.metadata.contentSha256,
        projectionSha256: previous.metadata.projectionSha256
      } : null
    };
    snapshot.metadata.snapshotSha256 = snapshotDigest(snapshot);
    assertValidDocument(snapshot, "program-source-snapshot.schema.json", { paths });
    const manifestBytes = Buffer.from(`${JSON.stringify(snapshot, null, 2)}\n`, "utf8");
    if (manifestBytes.length > PROGRAM_SOURCE_MAXIMUM_MANIFEST_BYTES) {
      throw new Error(`program source revision exceeds the ${PROGRAM_SOURCE_MAXIMUM_MANIFEST_BYTES}-byte manifest limit`);
    }
    const retainedHistoryBytes = manifests.reduce((total, name) =>
      total + fs.statSync(path.join(locations.revisions, name)).size, 0);
    if (retainedHistoryBytes + manifestBytes.length > PROGRAM_SOURCE_MAXIMUM_HISTORY_BYTES) {
      throw new Error(`program source history exceeds the ${PROGRAM_SOURCE_MAXIMUM_HISTORY_BYTES}-byte limit`);
    }

    const bodyFile = path.join(locations.bodies, `${contentSha256}.bin`);
    if (!fs.existsSync(bodyFile) && retainedBodyBytes + acquired.body.length > PROGRAM_SOURCE_MAXIMUM_BODY_HISTORY_BYTES) {
      throw new Error(`program source retained body history exceeds the ${PROGRAM_SOURCE_MAXIMUM_BODY_HISTORY_BYTES}-byte limit`);
    }
    beginDurableMutation();
    if (fs.existsSync(bodyFile)) {
      const retained = readPrivateFileBounded(bodyFile, PROGRAM_SOURCE_MAXIMUM_BYTES, null, { label: "retained private program source body" });
      if (retained.length !== acquired.body.length || sha256(retained) !== contentSha256 || !retained.equals(acquired.body)) {
        throw new Error("retained program source body conflicts with its content digest");
      }
    } else {
      writePrivateFileExclusive(bodyFile, acquired.body, { label: "private program source body" });
    }

    const filename = manifestFilename(revision, snapshot.metadata.snapshotSha256);
    writePrivateFileExclusive(
      path.join(locations.revisions, filename),
      manifestBytes,
      { label: `program source revision ${revision}` }
    );
    const pointer = {
      apiVersion: "gate.dev/program-source-pointer/v1",
      revision,
      manifest: filename,
      snapshotSha256: snapshot.metadata.snapshotSha256
    };
    writePrivateFileAtomic(
      locations.current,
      `${JSON.stringify(pointer, null, 2)}\n`,
      { encoding: "utf8", label: "current program source pointer" }
    );
    syncPrivateDirectory(locations.revisions, { label: "private program source revisions" });
    syncPrivateDirectory(locations.bodies, { label: "private program source bodies" });
    const published = readCurrentUnlocked(paths, locations, [...manifests, filename]);
    return {
      snapshot: published,
      profileSource: programProfileSourceFromSnapshot(published),
      diff: diffProgramSourceSnapshots(previous, published)
    };
  });
}
