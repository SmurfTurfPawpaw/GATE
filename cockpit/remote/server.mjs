import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { parsePublicSnapshot } from "../assets/model.js";
import {
  MAX_REMOTE_PROJECTION_BYTES,
  RemoteContractError,
  normalizeRemoteCaseBinding,
  normalizeRemoteCommandStatusRequest,
  normalizeRemoteFleetProjection,
  normalizeRemoteMessageRequest,
  normalizeRemoteQuestionResponse,
  normalizeRemoteStateProjection,
  remoteCommandStatusResponse
} from "./contracts.mjs";
import { OidcVerificationError } from "./auth.mjs";
import { RunnerAuthError, verifyRunnerRequest } from "./runner-auth.mjs";
import { SESSION_COOKIE_NAME, SessionStore, SessionStoreError } from "./sessions.mjs";

const COCKPIT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SESSION_API_VERSION = "gate.remote-cockpit-session/v1";
const RUNNER_HEARTBEAT_VERSION = "gate.remote-runner-heartbeat/v1";
const RUNNER_LEASE_REQUEST_VERSION = "gate.remote-runner-lease-request/v1";
const RUNNER_LEASE_VERSION = "gate.remote-runner-lease/v1";
const RUNNER_TRANSITION_VERSION = "gate.remote-runner-transition/v1";
const RUNNER_ACTIVITY_VERSION = "gate.remote-runner-activity/v1";
const RUNNER_ACK_VERSION = "gate.remote-runner-ack/v1";
const EVENTS_READY_VERSION = "gate.remote-events-ready/v1";
const RESYNC_VERSION = "gate.remote-resync/v1";

const DEFAULTS = Object.freeze({
  maxRequestsPerWindow: 10_000,
  requestWindowMs: 60_000,
  maxBrowserBodyBytes: 16 * 1024,
  maxRunnerBodyBytes: MAX_REMOTE_PROJECTION_BYTES,
  requestTimeoutMs: 10_000,
  operationTimeoutMs: 5_000,
  maxSseStreams: 32,
  maxSseStreamsPerSession: 2,
  sseKeepAliveMs: 15_000,
  ssePollMs: 750,
  sseMaxDurationMs: 10 * 60_000,
  eventPageLimit: 128,
  commandTtlMs: 5 * 60_000,
  runnerLeaseMs: 30_000,
  expirySweepMs: 1_000,
  runnerClockSkewMs: 60_000,
  maxHeaderBytes: 64 * 1024
});

const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "connect-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "worker-src 'none'",
  "manifest-src 'self'",
  "upgrade-insecure-requests"
].join("; ");

const STATIC_ROUTES = new Map([
  ["/assets/app.js", ["assets/app.js", "text/javascript; charset=utf-8"]],
  ["/assets/model.js", ["assets/model.js", "text/javascript; charset=utf-8"]],
  ["/assets/styles.css", ["assets/styles.css", "text/css; charset=utf-8"]],
  ["/assets/favicon.svg", ["assets/favicon.svg", "image/svg+xml"]],
  ["/remote/client.js", ["remote/client.js", "text/javascript; charset=utf-8"]],
  ["/robots.txt", ["robots.txt", "text/plain; charset=utf-8"]],
  ["/.nojekyll", [".nojekyll", "application/octet-stream"]]
]);

const BROWSER_ROUTES = new Set([
  "/api/cockpit/v1/session",
  "/api/cockpit/v1/state",
  "/api/cockpit/v1/fleet",
  "/api/cockpit/v1/events",
  "/api/cockpit/v1/commands/status",
  "/api/cockpit/v1/messages",
  "/api/cockpit/v1/questions"
]);

const RUNNER_ROUTES = new Set([
  "/api/runner/v1/heartbeat",
  "/api/runner/v1/lease",
  "/api/runner/v1/transition",
  "/api/runner/v1/state",
  "/api/runner/v1/fleet",
  "/api/runner/v1/activity"
]);

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, expected) {
  if (!record(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function boundedInteger(value, name, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${name} is outside its supported range`);
  }
  return value;
}

function configuredOrigin(value) {
  if (typeof value !== "string" || value.length > 2_048) throw new TypeError("origin is required");
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError("origin must be an absolute HTTPS origin");
  }
  if (parsed.protocol !== "https:" || parsed.origin !== value || parsed.username || parsed.password
      || parsed.pathname !== "/" || parsed.search || parsed.hash) {
    throw new TypeError("origin must be an exact HTTPS origin without a path");
  }
  return Object.freeze({ value, host: parsed.host });
}

function configuredHost(value) {
  if (value !== "127.0.0.1" && value !== "::1") {
    throw new TypeError("host must be an explicit loopback bind address behind the HTTPS identity gateway");
  }
  return value;
}

export function configuredHeaderName(value) {
  const normalized = value ?? "x-gate-oidc-assertion";
  if (typeof normalized !== "string" || normalized !== normalized.toLowerCase()
      || !/^[a-z][a-z0-9-]{1,62}$/u.test(normalized)
      || new Set(["authorization", "cookie", "host", "origin", "sec-fetch-site"]).has(normalized)) {
    throw new TypeError("identityAssertionHeader must be a lowercase private request header");
  }
  return normalized;
}

function clockMilliseconds(clock) {
  const value = clock();
  const milliseconds = value instanceof Date ? value.getTime() : value;
  if (!Number.isSafeInteger(milliseconds) || milliseconds < 0) throw new Error("clock unavailable");
  return milliseconds;
}

function isoNow(clock) {
  return new Date(clockMilliseconds(clock)).toISOString();
}

function commonHeaders(contentType) {
  return {
    "Cache-Control": "no-store, max-age=0",
    "Content-Security-Policy": CSP,
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Origin-Agent-Cluster": "?1",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()",
    "Referrer-Policy": "no-referrer",
    "Strict-Transport-Security": "max-age=31536000",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Type": contentType
  };
}

function send(response, status, body, contentType = "application/json; charset=utf-8", method = "GET", extra = {}) {
  if (response.headersSent || response.writableEnded) return;
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(body, "utf8");
  response.writeHead(status, { ...commonHeaders(contentType), ...extra, "Content-Length": bytes.length });
  if (method === "HEAD") response.end();
  else response.end(bytes);
}

function json(response, status, value, method = "GET", extra = {}) {
  send(response, status, `${JSON.stringify(value)}\n`, "application/json; charset=utf-8", method, extra);
}

function errorBody(code, message) {
  return { ok: false, error: { code, message } };
}

function publicFailure(error) {
  if (error instanceof RemoteContractError || error instanceof RunnerAuthError || error instanceof SessionStoreError
      || (record(error) && Number.isInteger(error.status) && typeof error.code === "string"
        && typeof error.publicMessage === "string")) {
    const status = Number.isInteger(error.status) ? error.status
      : error.code.startsWith("origin-") || error.code.startsWith("csrf-") || error.code.startsWith("fetch-site-") ? 403
        : error.code.startsWith("session-") ? 401 : 400;
    const message = error.publicMessage || error.message || "The request was rejected.";
    return { status: status >= 400 && status <= 599 ? status : 503, code: error.code, message };
  }
  if (error instanceof OidcVerificationError) {
    return { status: 401, code: "identity-rejected", message: "The operator identity assertion was rejected." };
  }
  return { status: 503, code: "bridge-unavailable", message: "The remote cockpit is temporarily unavailable." };
}

function fail(status, code, publicMessage) {
  throw Object.assign(new Error(publicMessage), { status, code, publicMessage });
}

function singleRawHeader(request, name, { required = false, maximumBytes = 32 * 1024 } = {}) {
  const values = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index].toLowerCase() === name) values.push(request.rawHeaders[index + 1]);
  }
  if (values.length > 1) fail(400, "header-rejected", "The request contains a repeated security header.");
  if (values.length === 0) {
    if (required) fail(400, "header-required", "A required request header is missing.");
    return undefined;
  }
  const value = values[0];
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > maximumBytes || /[\r\n\0]/u.test(value)) {
    fail(400, "header-rejected", "A request header is invalid.");
  }
  return value;
}

function assertExternalRequest(request, config) {
  const host = singleRawHeader(request, "host", { required: true, maximumBytes: 512 });
  if (host !== config.origin.host) fail(421, "host-rejected", "The remote cockpit rejected this host.");
  if (request.socket.encrypted !== true) {
    const forwarded = singleRawHeader(request, "x-forwarded-proto", { maximumBytes: 16 });
    if (forwarded !== "https") fail(421, "transport-rejected", "The remote cockpit requires HTTPS.");
  }
  if (singleRawHeader(request, "authorization") !== undefined) {
    fail(400, "authorization-rejected", "Use the configured identity gateway to open the remote cockpit.");
  }
}

function assertNoRequestBody(request) {
  const length = singleRawHeader(request, "content-length");
  const transfer = singleRawHeader(request, "transfer-encoding");
  if ((length !== undefined && length !== "0") || transfer !== undefined) {
    fail(400, "body-rejected", "This request does not accept a body.");
  }
}

async function readJson(request, maximumBytes) {
  const contentType = singleRawHeader(request, "content-type", { required: true, maximumBytes: 128 });
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(contentType)) {
    fail(415, "json-required", "This endpoint accepts JSON only.");
  }
  const declared = singleRawHeader(request, "content-length", { maximumBytes: 32 });
  if (declared !== undefined) {
    if (!/^(?:0|[1-9][0-9]*)$/u.test(declared) || Number(declared) > maximumBytes) {
      fail(413, "request-too-large", "The request body is too large.");
    }
  }
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > maximumBytes) {
      request.destroy();
      fail(413, "request-too-large", "The request body is too large.");
    }
    chunks.push(chunk);
  }
  if (length === 0) fail(400, "json-invalid", "The request body is invalid.");
  const bytes = Buffer.concat(chunks, length);
  try {
    const value = JSON.parse(bytes.toString("utf8"));
    if (!record(value)) throw new Error("object required");
    return Object.freeze({ value, bytes });
  } catch {
    fail(400, "json-invalid", "The request body is invalid.");
  }
}

function withDeadline(action, milliseconds) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(Object.assign(new Error("operation timed out"), {
      status: 503,
      code: "operation-timeout",
      publicMessage: "The remote cockpit operation timed out."
    })), milliseconds);
    timer.unref?.();
  });
  return Promise.race([Promise.resolve().then(action), timeout]).finally(() => clearTimeout(timer));
}

class RollingWindowLimiter {
  #limit;
  #timestamps = [];
  #windowMs;
  #lastNow = null;

  constructor(limit, windowMs) {
    this.#limit = boundedInteger(limit, "maxRequestsPerWindow", 1, 1_000_000);
    this.#windowMs = boundedInteger(windowMs, "requestWindowMs", 1_000, 60 * 60_000);
  }

  take(now) {
    if (!Number.isSafeInteger(now) || now < 0) throw new Error("request limiter clock unavailable");
    if (this.#lastNow !== null && now < this.#lastNow) this.#timestamps = [];
    this.#lastNow = now;
    const earliest = now - this.#windowMs;
    let remove = 0;
    while (remove < this.#timestamps.length && this.#timestamps[remove] <= earliest) remove += 1;
    if (remove > 0) this.#timestamps.splice(0, remove);
    if (this.#timestamps.length >= this.#limit) return false;
    this.#timestamps.push(now);
    return true;
  }
}

function secureRead(root, relative, maximumBytes = 1024 * 1024) {
  const absolute = path.resolve(root, relative);
  if (absolute !== root && !absolute.startsWith(`${root}${path.sep}`)) throw new Error("asset escaped cockpit root");
  const before = fs.lstatSync(absolute, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.size > BigInt(maximumBytes)) throw new Error("invalid cockpit asset");
  const bytes = fs.readFileSync(absolute);
  const after = fs.lstatSync(absolute, { bigint: true });
  if (!after.isFile() || after.isSymbolicLink() || before.dev !== after.dev || before.ino !== after.ino
      || after.size !== BigInt(bytes.length) || before.mtimeNs !== after.mtimeNs) {
    throw new Error("cockpit asset changed while loading");
  }
  return bytes;
}

function preloadStatic(root) {
  const assets = new Map();
  for (const [route, [relative, contentType]] of STATIC_ROUTES) {
    assets.set(route, Object.freeze({ bytes: secureRead(root, relative), contentType }));
  }
  const snapshot = secureRead(root, "data/status.json", 64 * 1024);
  if (parsePublicSnapshot(JSON.parse(snapshot.toString("utf8"))).kind !== "available") {
    throw new Error("cockpit snapshot is invalid");
  }
  assets.set("/data/status.json", Object.freeze({ bytes: snapshot, contentType: "application/json; charset=utf-8" }));
  const original = secureRead(root, "index.html").toString("utf8");
  const appTag = '<script type="module" src="./assets/app.js"></script>';
  if (!original.includes(appTag)) throw new Error("cockpit index is missing its application module");
  const injected = original.replace(appTag,
    `<script type="module" src="./remote/client.js"></script>\n    ${appTag}`);
  assets.set("/", Object.freeze({ bytes: Buffer.from(injected), contentType: "text/html; charset=utf-8" }));
  assets.set("/index.html", assets.get("/"));
  return assets;
}

function methodRejected(response, method, allowed, extra = {}) {
  return json(response, 405, errorBody("method-rejected", "That remote cockpit method is unavailable."), method,
    { ...extra, Allow: allowed.join(", ") });
}

function requestLimitRejected(response, method, config, extra = {}) {
  return json(response, 429, errorBody("request-limit", "The remote cockpit request window is full."), method,
    {
      ...extra,
      "Retry-After": String(Math.max(1, Math.ceil(config.requestWindowMs / 1_000)))
    });
}

function requireExactObject(value, expected, apiVersion, label) {
  if (!exactKeys(value, expected) || value.apiVersion !== apiVersion) {
    fail(400, `${label}-invalid`, `The remote ${label} request is invalid.`);
  }
}

function requireConfiguredBinding(value, config) {
  if (value.caseId !== config.caseBinding.caseId || value.sessionRevision !== config.caseBinding.sessionRevision) {
    fail(409, "session-changed", "The remote cockpit session changed. Reload the runner.");
  }
}

function requireIsoNearNow(value, config, label) {
  if (typeof value !== "string") fail(400, `${label}-invalid`, `The remote ${label} timestamp is invalid.`);
  const parsed = new Date(value);
  const milliseconds = parsed.getTime();
  if (!Number.isFinite(milliseconds) || parsed.toISOString() !== value
      || Math.abs(clockMilliseconds(config.clock) - milliseconds) > config.runnerClockSkewMs) {
    fail(400, `${label}-invalid`, `The remote ${label} timestamp is outside the accepted window.`);
  }
  return value;
}

function browserBinding(config, session) {
  return Object.freeze({
    operatorId: config.caseBinding.operatorId,
    browserSessionId: session.id,
    caseId: config.caseBinding.caseId,
    sessionRevision: config.caseBinding.sessionRevision
  });
}

function caseBinding(config) {
  return config.caseBinding;
}

function runnerBinding(config, runnerId, value) {
  return Object.freeze({
    commandId: value.commandId,
    operatorId: config.caseBinding.operatorId,
    caseId: config.caseBinding.caseId,
    sessionRevision: config.caseBinding.sessionRevision,
    runnerId,
    leaseId: value.leaseId
  });
}

function publicLease(command) {
  if (command === null) return null;
  if (!command.lease) fail(503, "lease-invalid", "The remote command lease is unavailable.");
  return Object.freeze({
    commandId: command.commandId,
    kind: command.kind,
    payloadSha256: command.payloadSha256,
    payload: command.payload,
    issuedAt: command.issuedAt,
    expiresAt: command.expiresAt,
    lease: Object.freeze({ leaseId: command.lease.leaseId, expiresAt: command.lease.expiresAt })
  });
}

function sseChunk({ id, event, data }) {
  const serialized = JSON.stringify(data);
  if (Buffer.byteLength(serialized, "utf8") > MAX_REMOTE_PROJECTION_BYTES + 1024 || /[\r\n]/u.test(event)) {
    throw new Error("invalid SSE event");
  }
  return `${id === undefined ? "" : `id: ${id}\n`}event: ${event}\ndata: ${serialized}\n\n`;
}

function parseCursor(url, request) {
  const entries = [...url.searchParams.entries()];
  if (entries.some(([key]) => key !== "cursor") || url.searchParams.getAll("cursor").length > 1) {
    fail(400, "cursor-invalid", "The remote event cursor is invalid.");
  }
  const query = url.searchParams.get("cursor");
  const header = singleRawHeader(request, "last-event-id", { maximumBytes: 32 });
  const parse = (value) => {
    if (value === undefined || value === null || value === "") return null;
    if (!/^(?:0|[1-9][0-9]*)$/u.test(value)) fail(400, "cursor-invalid", "The remote event cursor is invalid.");
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed)) fail(400, "cursor-invalid", "The remote event cursor is invalid.");
    return parsed;
  };
  const fromQuery = parse(query);
  const fromHeader = parse(header);
  if (fromQuery !== null && fromHeader !== null && fromQuery !== fromHeader) {
    fail(409, "cursor-conflict", "The remote event cursors do not match.");
  }
  return fromHeader ?? fromQuery ?? 0;
}

function sessionResponse(config, session, csrf) {
  return Object.freeze({
    apiVersion: SESSION_API_VERSION,
    sessionRevision: config.caseBinding.sessionRevision,
    csrf,
    expiresAt: new Date(session.expiresAt).toISOString(),
    caseId: config.caseBinding.caseId
  });
}

function validateStore(store) {
  const methods = [
    "configuration", "isOpen", "claimCaseBinding", "expireDue", "enqueue", "leaseNext", "renewLease", "acceptCommand", "startCommand",
    "completeCommand", "failCommand", "getCommandStatuses", "putStateProjection", "putFleetProjection", "getStateProjection",
    "getFleetProjection", "appendActivity", "eventsSince"
  ];
  if (!store || methods.some((method) => typeof store[method] !== "function")) {
    throw new TypeError("store must implement the remote bridge store contract");
  }
  return store;
}

function validateSessionStore(store) {
  if (!store || ["create", "authenticateCookie", "isActive", "requireCsrf", "revoke", "close"]
    .some((method) => typeof store[method] !== "function")) {
    throw new TypeError("sessionStore must implement the remote session contract");
  }
  return store;
}

function storeReady(store) {
  try {
    if (!store.isOpen()) return false;
    const value = store.configuration();
    return record(value) && value.journalMode === "wal" && value.foreignKeys === true && value.synchronous === "full";
  } catch {
    return false;
  }
}

export async function startRemoteCockpitServer(options = {}) {
  if (!record(options)) throw new TypeError("remote server options must be an object");
  const allowedOptions = new Set([
    "origin", "host", "port", "operatorId", "caseId", "sessionRevision", "root", "store", "sessionStore",
    "oidcVerifier", "identityAssertionHeader", "runnerVerifier", "runnerNonceStore", "runnerPublicKeys", "clock",
    "maxRequestsPerWindow", "requestWindowMs", "maxBrowserBodyBytes", "maxRunnerBodyBytes", "requestTimeoutMs",
    "operationTimeoutMs", "maxSseStreams", "maxSseStreamsPerSession", "sseKeepAliveMs", "ssePollMs",
    "sseMaxDurationMs", "eventPageLimit", "commandTtlMs", "runnerLeaseMs", "expirySweepMs", "runnerClockSkewMs", "closeStore",
    "closeSessionStore", "closeRunnerNonceStore"
  ]);
  if (Object.keys(options).some((key) => !allowedOptions.has(key))) {
    throw new TypeError("remote server options contain an unknown member");
  }
  if (!Object.hasOwn(options, "host") || !Object.hasOwn(options, "port")) {
    throw new TypeError("host and port must be configured explicitly");
  }
  const origin = configuredOrigin(options.origin);
  const host = configuredHost(options.host);
  const requestedPort = boundedInteger(options.port, "port", 0, 65_535);
  const caseBindingValue = normalizeRemoteCaseBinding({
    operatorId: options.operatorId,
    caseId: options.caseId,
    sessionRevision: options.sessionRevision
  });
  const root = path.resolve(options.root ?? COCKPIT_ROOT);
  const staticAssets = preloadStatic(root);
  const store = validateStore(options.store);
  const ownsSessions = options.sessionStore === undefined;
  const sessionStore = validateSessionStore(options.sessionStore ?? new SessionStore());
  if (!options.oidcVerifier || typeof options.oidcVerifier.verify !== "function") {
    throw new TypeError("oidcVerifier.verify is required");
  }
  const runnerVerifier = options.runnerVerifier ?? verifyRunnerRequest;
  if (typeof runnerVerifier !== "function") throw new TypeError("runnerVerifier must be a function");
  const runnerNonceStore = options.runnerNonceStore
    ?? (typeof store.runnerNonceStore === "function" ? store.runnerNonceStore() : null);
  if (!runnerNonceStore || typeof runnerNonceStore.consume !== "function") {
    throw new TypeError("a durable runnerNonceStore.consume implementation is required");
  }
  if (!options.runnerPublicKeys && options.runnerVerifier === undefined) {
    throw new TypeError("runnerPublicKeys are required");
  }
  const clock = options.clock ?? Date.now;
  if (typeof clock !== "function") throw new TypeError("clock must be a function");
  const config = Object.freeze({
    origin,
    caseBinding: caseBindingValue,
    identityAssertionHeader: configuredHeaderName(options.identityAssertionHeader),
    clock,
    maxRequestsPerWindow: boundedInteger(options.maxRequestsPerWindow ?? DEFAULTS.maxRequestsPerWindow,
      "maxRequestsPerWindow", 1, 1_000_000),
    requestWindowMs: boundedInteger(options.requestWindowMs ?? DEFAULTS.requestWindowMs,
      "requestWindowMs", 1_000, 60 * 60_000),
    maxBrowserBodyBytes: boundedInteger(options.maxBrowserBodyBytes ?? DEFAULTS.maxBrowserBodyBytes,
      "maxBrowserBodyBytes", 1_024, 64 * 1024),
    maxRunnerBodyBytes: boundedInteger(options.maxRunnerBodyBytes ?? DEFAULTS.maxRunnerBodyBytes,
      "maxRunnerBodyBytes", 1_024, MAX_REMOTE_PROJECTION_BYTES),
    requestTimeoutMs: boundedInteger(options.requestTimeoutMs ?? DEFAULTS.requestTimeoutMs,
      "requestTimeoutMs", 100, 60_000),
    operationTimeoutMs: boundedInteger(options.operationTimeoutMs ?? DEFAULTS.operationTimeoutMs,
      "operationTimeoutMs", 100, 60_000),
    maxSseStreams: boundedInteger(options.maxSseStreams ?? DEFAULTS.maxSseStreams, "maxSseStreams", 1, 256),
    maxSseStreamsPerSession: boundedInteger(options.maxSseStreamsPerSession ?? DEFAULTS.maxSseStreamsPerSession,
      "maxSseStreamsPerSession", 1, 8),
    sseKeepAliveMs: boundedInteger(options.sseKeepAliveMs ?? DEFAULTS.sseKeepAliveMs, "sseKeepAliveMs", 1_000, 60_000),
    ssePollMs: boundedInteger(options.ssePollMs ?? DEFAULTS.ssePollMs, "ssePollMs", 100, 10_000),
    sseMaxDurationMs: boundedInteger(options.sseMaxDurationMs ?? DEFAULTS.sseMaxDurationMs,
      "sseMaxDurationMs", 1_000, 60 * 60_000),
    eventPageLimit: boundedInteger(options.eventPageLimit ?? DEFAULTS.eventPageLimit, "eventPageLimit", 1, 256),
    commandTtlMs: boundedInteger(options.commandTtlMs ?? DEFAULTS.commandTtlMs, "commandTtlMs", 1_000, 15 * 60_000),
    runnerLeaseMs: boundedInteger(options.runnerLeaseMs ?? DEFAULTS.runnerLeaseMs, "runnerLeaseMs", 1_000, 5 * 60_000),
    expirySweepMs: boundedInteger(options.expirySweepMs ?? DEFAULTS.expirySweepMs, "expirySweepMs", 100, 10_000),
    runnerClockSkewMs: boundedInteger(options.runnerClockSkewMs ?? DEFAULTS.runnerClockSkewMs,
      "runnerClockSkewMs", 1_000, 5 * 60_000)
  });
  const streams = new Set();
  const sessionStreamCounts = new Map();
  // Keep unauthenticated/static traffic, authenticated browser traffic, and
  // verified runner traffic in independent windows. In particular, unsigned
  // requests to the public runner route must never spend the lease-renewal
  // budget of an enrolled runner. The gateway remains responsible for
  // pre-authentication and volumetric abuse controls.
  const publicRequestLimiter = new RollingWindowLimiter(config.maxRequestsPerWindow, config.requestWindowMs);
  const browserRequestLimiter = new RollingWindowLimiter(config.maxRequestsPerWindow, config.requestWindowMs);
  const runnerRequestLimiter = new RollingWindowLimiter(config.maxRequestsPerWindow, config.requestWindowMs);
  await withDeadline(() => store.claimCaseBinding(config.caseBinding), config.operationTimeoutMs);
  await withDeadline(() => store.expireDue(), config.operationTimeoutMs);
  let expirySweepHealthy = true;
  let expirySweepRunning = false;
  let expirySweepTimer;

  const sweepExpiredCommands = async () => {
    if (expirySweepRunning) return;
    expirySweepRunning = true;
    try {
      await withDeadline(() => store.expireDue(), config.operationTimeoutMs);
      expirySweepHealthy = true;
    } catch {
      expirySweepHealthy = false;
    } finally {
      expirySweepRunning = false;
    }
  };

  const authenticateBrowser = (request) => {
    const cookie = singleRawHeader(request, "cookie", { maximumBytes: 4_096 });
    const authenticated = sessionStore.authenticateCookie(cookie);
    if (!authenticated || authenticated.session.identity?.subject !== config.caseBinding.operatorId) {
      if (authenticated) sessionStore.revoke(authenticated.session.id);
      fail(401, "session-required", "Open the remote cockpit through the configured identity gateway.");
    }
    return authenticated;
  };

  const handleSession = async (request, response, method) => {
    if (method !== "GET") return methodRejected(response, method, ["GET"]);
    assertNoRequestBody(request);
    if (singleRawHeader(request, "sec-fetch-site", { required: true, maximumBytes: 32 }) !== "same-origin") {
      fail(403, "fetch-site-rejected", "The remote cockpit rejected this browser context.");
    }
    const assertion = singleRawHeader(request, config.identityAssertionHeader, { required: true, maximumBytes: 24 * 1024 });
    const identity = await withDeadline(() => options.oidcVerifier.verify(assertion), config.operationTimeoutMs);
    if (!identity || identity.subject !== config.caseBinding.operatorId) {
      fail(401, "identity-rejected", "The operator identity assertion was rejected.");
    }
    if (!browserRequestLimiter.take(clockMilliseconds(config.clock))) {
      return requestLimitRejected(response, method, config);
    }
    let authenticated = sessionStore.authenticateCookie(singleRawHeader(request, "cookie", { maximumBytes: 4_096 }));
    let csrf = null;
    if (authenticated && authenticated.session.identity?.subject !== config.caseBinding.operatorId) {
      sessionStore.revoke(authenticated.session.id);
      authenticated = null;
    }
    if (authenticated && typeof authenticated.csrf === "string") {
      csrf = authenticated.csrf;
    } else if (!authenticated) {
      const created = sessionStore.create(identity);
      authenticated = { session: created.session, setCookie: created.setCookie };
      csrf = created.csrf;
    }
    // Older injected session stores may not return CSRF on authentication. A
    // verified gateway assertion then creates a fresh page session rather than
    // disclosing or guessing the existing proof.
    if (csrf === null) {
      sessionStore.revoke(authenticated.session.id);
      const created = sessionStore.create(identity);
      authenticated = { session: created.session, setCookie: created.setCookie };
      csrf = created.csrf;
    }
    return json(response, 200, sessionResponse(config, authenticated.session, csrf), method,
      { "Set-Cookie": authenticated.setCookie });
  };

  const handleEventStream = async (request, response, authenticated, url) => {
    const cursorAtOpen = parseCursor(url, request);
    const binding = browserBinding(config, authenticated.session);
    const preflight = await withDeadline(
      () => store.eventsSince(binding, cursorAtOpen, { limit: config.eventPageLimit }),
      config.operationTimeoutMs
    );
    const currentForSession = sessionStreamCounts.get(authenticated.session.id) ?? 0;
    if (streams.size >= config.maxSseStreams || currentForSession >= config.maxSseStreamsPerSession) {
      return json(response, 429, errorBody("stream-limit", "The remote event stream limit was reached."), "GET",
        { "Retry-After": "5", "Set-Cookie": authenticated.setCookie });
    }
    request.setTimeout(0);
    response.writeHead(200, {
      ...commonHeaders("text/event-stream; charset=utf-8"),
      "Set-Cookie": authenticated.setCookie,
      Connection: "keep-alive",
      "X-Accel-Buffering": "no"
    });
    let cursor = cursorAtOpen;
    let polling = false;
    let closed = false;
    let paused = false;
    let pollTimer;
    let keepAliveTimer;
    let sessionTimer;
    let durationTimer;

    const sessionIsActive = () => {
      try {
        return sessionStore.isActive(authenticated.session);
      } catch {
        return false;
      }
    };

    const write = (chunk) => {
      if (closed || response.writableEnded) return false;
      const accepted = response.write(chunk);
      if (!accepted) {
        paused = true;
        response.once("drain", () => {
          paused = false;
          void poll();
        });
      }
      return accepted;
    };
    const close = () => {
      if (closed) return;
      closed = true;
      clearInterval(pollTimer);
      clearInterval(keepAliveTimer);
      clearInterval(sessionTimer);
      clearTimeout(durationTimer);
      streams.delete(stream);
      const remaining = (sessionStreamCounts.get(authenticated.session.id) ?? 1) - 1;
      if (remaining > 0) sessionStreamCounts.set(authenticated.session.id, remaining);
      else sessionStreamCounts.delete(authenticated.session.id);
      if (!response.writableEnded) response.end();
    };
    const poll = async () => {
      if (closed) return;
      if (!sessionIsActive()) {
        close();
        return;
      }
      if (paused || polling) return;
      polling = true;
      try {
        do {
          const page = await withDeadline(() => store.eventsSince(binding, cursor, { limit: config.eventPageLimit }),
            config.operationTimeoutMs);
          if (!sessionIsActive()) {
            close();
            return;
          }
          if (page.resyncRequired === true) {
            cursor = page.headCursor;
            if (!write(sseChunk({ id: cursor, event: "resync", data: { apiVersion: RESYNC_VERSION, cursor } }))) break;
          } else {
            for (const event of page.events) {
              if (!new Set(["activity", "command", "state", "fleet"]).has(event.kind)) throw new Error("invalid event kind");
              cursor = event.sequence;
              if (!write(sseChunk({ id: event.sequence, event: event.kind, data: event.payload }))) break;
            }
            if (!paused) cursor = page.nextCursor;
          }
          if (paused || page.hasMore !== true) break;
        } while (!closed);
      } catch {
        close();
      } finally {
        polling = false;
      }
    };
    const stream = Object.freeze({ response, close });
    streams.add(stream);
    sessionStreamCounts.set(authenticated.session.id, currentForSession + 1);
    if (!sessionIsActive()) {
      close();
      return;
    }
    write("retry: 2000\n\n");
    if (preflight.resyncRequired === true) {
      cursor = preflight.headCursor;
      write(sseChunk({ id: cursor, event: "resync", data: { apiVersion: RESYNC_VERSION, cursor } }));
    }
    write(sseChunk({ event: "ready", data: { apiVersion: EVENTS_READY_VERSION, cursor } }));
    pollTimer = setInterval(() => void poll(), config.ssePollMs);
    pollTimer.unref?.();
    keepAliveTimer = setInterval(() => {
      if (!sessionIsActive()) close();
      else write(": keepalive\n\n");
    }, config.sseKeepAliveMs);
    keepAliveTimer.unref?.();
    sessionTimer = setInterval(() => {
      if (!sessionIsActive()) close();
    }, Math.min(config.ssePollMs, 1_000));
    sessionTimer.unref?.();
    durationTimer = setTimeout(close, config.sseMaxDurationMs);
    durationTimer.unref?.();
    request.once("close", close);
    void poll();
  };

  const handleBrowser = async (request, response, method, pathname, url) => {
    if (pathname === "/api/cockpit/v1/session") return handleSession(request, response, method);
    let authenticated;
    try {
      authenticated = authenticateBrowser(request);
      const setCookie = { "Set-Cookie": authenticated.setCookie };
      if (!browserRequestLimiter.take(clockMilliseconds(config.clock))) {
        return requestLimitRejected(response, method, config, setCookie);
      }
      if (pathname === "/api/cockpit/v1/events") {
        if (method !== "GET") return methodRejected(response, method, ["GET"], setCookie);
        assertNoRequestBody(request);
        return await handleEventStream(request, response, authenticated, url);
      }
      if (url.search) fail(400, "query-rejected", "This remote cockpit endpoint does not accept query parameters.");
      if (pathname === "/api/cockpit/v1/state" || pathname === "/api/cockpit/v1/fleet") {
        if (method !== "GET") return methodRejected(response, method, ["GET"], setCookie);
        assertNoRequestBody(request);
        const storedProjection = await withDeadline(() => pathname.endsWith("/state")
          ? store.getStateProjection(config.caseBinding)
          : store.getFleetProjection(config.caseBinding),
        config.operationTimeoutMs);
        let projection = null;
        try {
          projection = storedProjection === null ? null : pathname.endsWith("/state")
            ? normalizeRemoteStateProjection(storedProjection)
            : normalizeRemoteFleetProjection(storedProjection);
        } catch {
          projection = null;
        }
        if (!projection || projection.sessionRevision !== config.caseBinding.sessionRevision) {
          return json(response, 503, errorBody("projection-unavailable", "The remote cockpit projection is unavailable."), method,
            setCookie);
        }
        if (Date.parse(projection.validUntil) <= clockMilliseconds(config.clock)) {
          return json(response, 503, errorBody("projection-expired", "The remote cockpit projection has expired."), method,
            setCookie);
        }
        return json(response, 200, projection, method, setCookie);
      }
      if (!["/api/cockpit/v1/commands/status", "/api/cockpit/v1/messages", "/api/cockpit/v1/questions"].includes(pathname)) {
        return json(response, 404, errorBody("not-found", "That remote cockpit resource does not exist."), method, setCookie);
      }
      if (method !== "POST") return methodRejected(response, method, ["POST"], setCookie);
      if (singleRawHeader(request, "origin", { required: true, maximumBytes: 2_048 }) !== config.origin.value
          || singleRawHeader(request, "sec-fetch-site", { required: true, maximumBytes: 32 }) !== "same-origin") {
        fail(403, "origin-rejected", "The remote cockpit rejected this request origin.");
      }
      sessionStore.requireCsrf(authenticated.session, request.headers.origin, config.origin.value, request.headers);
      const { value } = await readJson(request, config.maxBrowserBodyBytes);
      if (pathname === "/api/cockpit/v1/commands/status") {
        const normalized = normalizeRemoteCommandStatusRequest(value);
        if (normalized.caseId !== config.caseBinding.caseId
            || normalized.sessionRevision !== config.caseBinding.sessionRevision) {
          fail(409, "session-changed", "The remote cockpit session changed. Reload the cockpit.");
        }
        const commands = await withDeadline(
          () => store.getCommandStatuses(browserBinding(config, authenticated.session), normalized),
          config.operationTimeoutMs
        );
        return json(response, 200, remoteCommandStatusResponse({
          caseId: config.caseBinding.caseId,
          sessionRevision: config.caseBinding.sessionRevision,
          commands
        }), method, setCookie);
      }
      const normalized = pathname.endsWith("/messages")
        ? normalizeRemoteMessageRequest(value)
        : normalizeRemoteQuestionResponse(value);
      if (normalized.sessionRevision !== config.caseBinding.sessionRevision) {
        fail(409, "session-changed", "The remote cockpit session changed. Reload the cockpit.");
      }
      const result = await withDeadline(() => store.enqueue(browserBinding(config, authenticated.session), normalized,
        { ttlMs: config.commandTtlMs }), config.operationTimeoutMs);
      return json(response, 202, result.receipt, method, setCookie);
    } catch (error) {
      if (!authenticated || response.headersSent) throw error;
      const failure = publicFailure(error);
      return json(response, failure.status, errorBody(failure.code, failure.message), method,
        { "Set-Cookie": authenticated.setCookie });
    }
  };

  const handleRunner = async (request, response, method, pathname, url) => {
    if (method !== "POST") return methodRejected(response, method, ["POST"]);
    if (url.search) fail(400, "query-rejected", "Runner endpoints do not accept query parameters.");
    const { value, bytes } = await readJson(request, config.maxRunnerBodyBytes);
    const verified = await withDeadline(() => runnerVerifier({
      headers: request.rawHeaders,
      publicKeys: options.runnerPublicKeys,
      nonceStore: runnerNonceStore,
      method,
      path: request.url,
      body: bytes,
      now: config.clock,
      maxSkewMs: config.runnerClockSkewMs
    }), config.operationTimeoutMs);
    if (!verified || typeof verified.runnerId !== "string") fail(401, "runner-auth-rejected", "Runner authentication failed.");
    if (!runnerRequestLimiter.take(clockMilliseconds(config.clock))) {
      return requestLimitRejected(response, method, config);
    }

    if (pathname === "/api/runner/v1/heartbeat") {
      requireExactObject(value, ["apiVersion", "caseId", "sessionRevision", "observedAt"],
        RUNNER_HEARTBEAT_VERSION, "runner-heartbeat");
      requireConfiguredBinding(value, config);
      requireIsoNearNow(value.observedAt, config, "runner-heartbeat");
      return json(response, 200, { apiVersion: RUNNER_ACK_VERSION, acceptedAt: isoNow(config.clock) }, method);
    }
    if (pathname === "/api/runner/v1/lease") {
      requireExactObject(value, ["apiVersion", "caseId", "sessionRevision"],
        RUNNER_LEASE_REQUEST_VERSION, "runner-lease");
      requireConfiguredBinding(value, config);
      const command = await withDeadline(() => store.leaseNext({
        operatorId: config.caseBinding.operatorId,
        caseId: config.caseBinding.caseId,
        sessionRevision: config.caseBinding.sessionRevision,
        runnerId: verified.runnerId,
        leaseMs: config.runnerLeaseMs
      }), config.operationTimeoutMs);
      return json(response, 200, { apiVersion: RUNNER_LEASE_VERSION, command: publicLease(command) }, method);
    }
    if (pathname === "/api/runner/v1/transition") {
      requireExactObject(value, ["apiVersion", "caseId", "sessionRevision", "commandId", "leaseId", "state"],
        RUNNER_TRANSITION_VERSION, "runner-transition");
      requireConfiguredBinding(value, config);
      const binding = runnerBinding(config, verified.runnerId, value);
      const actions = new Map([
        ["renewed", () => store.renewLease(binding, { leaseMs: config.runnerLeaseMs })],
        ["accepted", () => store.acceptCommand(binding)],
        ["running", () => store.startCommand(binding)],
        ["completed", () => store.completeCommand(binding)],
        ["failed", () => store.failCommand(binding)]
      ]);
      const action = actions.get(value.state);
      if (!action) fail(400, "runner-transition-invalid", "The remote runner transition is invalid.");
      await withDeadline(action, config.operationTimeoutMs);
      return json(response, 200, { apiVersion: RUNNER_ACK_VERSION, acceptedAt: isoNow(config.clock) }, method);
    }
    if (pathname === "/api/runner/v1/state") {
      const projection = normalizeRemoteStateProjection(value);
      if (projection.sessionRevision !== config.caseBinding.sessionRevision) {
        fail(409, "session-changed", "The remote cockpit session changed. Reload the runner.");
      }
      requireIsoNearNow(projection.observedAt, config, "state-projection");
      if (Date.parse(projection.validUntil) <= clockMilliseconds(config.clock)) {
        fail(409, "projection-expired", "The remote state projection is already expired.");
      }
      await withDeadline(() => store.putStateProjection(caseBinding(config), projection), config.operationTimeoutMs);
      return json(response, 200, { apiVersion: RUNNER_ACK_VERSION, acceptedAt: isoNow(config.clock) }, method);
    }
    if (pathname === "/api/runner/v1/fleet") {
      const projection = normalizeRemoteFleetProjection(value);
      if (projection.sessionRevision !== config.caseBinding.sessionRevision) {
        fail(409, "session-changed", "The remote cockpit session changed. Reload the runner.");
      }
      requireIsoNearNow(projection.receivedAt, config, "fleet-projection");
      if (Date.parse(projection.validUntil) <= clockMilliseconds(config.clock)) {
        fail(409, "projection-expired", "The remote fleet projection is already expired.");
      }
      await withDeadline(() => store.putFleetProjection(caseBinding(config), projection), config.operationTimeoutMs);
      return json(response, 200, { apiVersion: RUNNER_ACK_VERSION, acceptedAt: isoNow(config.clock) }, method);
    }
    if (pathname === "/api/runner/v1/activity") {
      requireExactObject(value, ["apiVersion", "caseId", "sessionRevision", "event"],
        RUNNER_ACTIVITY_VERSION, "runner-activity");
      requireConfiguredBinding(value, config);
      await withDeadline(() => store.appendActivity(caseBinding(config), value.event), config.operationTimeoutMs);
      return json(response, 200, { apiVersion: RUNNER_ACK_VERSION, acceptedAt: isoNow(config.clock) }, method);
    }
    return json(response, 404, errorBody("not-found", "That runner resource does not exist."), method);
  };

  const server = http.createServer({ maxHeaderSize: DEFAULTS.maxHeaderBytes }, (request, response) => {
    const run = async () => {
      const method = request.method || "GET";
      request.setTimeout(config.requestTimeoutMs, () => request.destroy());
      let url;
      try {
        url = new URL(request.url || "/", config.origin.value);
      } catch {
        if (!publicRequestLimiter.take(clockMilliseconds(config.clock))) {
          return requestLimitRejected(response, method, config);
        }
        return json(response, 400, errorBody("request-invalid", "The remote cockpit rejected this request."), method);
      }
      const pathname = url.pathname;
      if (["/healthz", "/readyz"].includes(pathname)) {
        if (!publicRequestLimiter.take(clockMilliseconds(config.clock))) {
          return requestLimitRejected(response, method, config);
        }
        if (url.search) return json(response, 400, errorBody("query-rejected", "Health endpoints do not accept queries."), method);
        if (method !== "GET" && method !== "HEAD") return methodRejected(response, method, ["GET", "HEAD"]);
        assertNoRequestBody(request);
        const ready = pathname === "/healthz" || expirySweepHealthy && storeReady(store);
        return json(response, ready ? 200 : 503, {
          ok: ready,
          service: pathname === "/healthz" ? "gate-remote-cockpit" : "gate-remote-cockpit-ready"
        }, method);
      }
      assertExternalRequest(request, config);
      if (url.origin !== config.origin.value || !request.url?.startsWith("/")) {
        fail(400, "request-target-rejected", "The remote cockpit rejected this request target.");
      }
      const originHeader = singleRawHeader(request, "origin", { maximumBytes: 2_048 });
      if (originHeader !== undefined && originHeader !== config.origin.value) {
        fail(403, "origin-rejected", "The remote cockpit rejected this request origin.");
      }
      const staticAsset = staticAssets.get(pathname);
      if (staticAsset) {
        if (!publicRequestLimiter.take(clockMilliseconds(config.clock))) {
          return requestLimitRejected(response, method, config);
        }
        if (url.search) return json(response, 400, errorBody("query-rejected", "Static resources do not accept queries."), method);
        if (method !== "GET" && method !== "HEAD") return methodRejected(response, method, ["GET", "HEAD"]);
        assertNoRequestBody(request);
        return send(response, 200, staticAsset.bytes, staticAsset.contentType, method);
      }
      if (BROWSER_ROUTES.has(pathname)) return handleBrowser(request, response, method, pathname, url);
      if (RUNNER_ROUTES.has(pathname)) return handleRunner(request, response, method, pathname, url);
      if (!publicRequestLimiter.take(clockMilliseconds(config.clock))) {
        return requestLimitRejected(response, method, config);
      }
      if (pathname.startsWith("/api/")) {
        return json(response, 404, errorBody("not-found", "That remote cockpit resource does not exist."), method);
      }
      return json(response, 404, errorBody("not-found", "That remote cockpit resource does not exist."), method);
    };
    void run().catch((error) => {
      const failure = publicFailure(error);
      if (!response.headersSent) json(response, failure.status, errorBody(failure.code, failure.message), request.method || "GET");
      else if (!response.writableEnded) response.end();
    });
  });
  server.headersTimeout = config.requestTimeoutMs;
  server.requestTimeout = config.requestTimeoutMs;
  server.keepAliveTimeout = Math.min(5_000, config.requestTimeoutMs);
  server.maxRequestsPerSocket = Math.min(config.maxRequestsPerWindow, 1_000);
  server.on("clientError", (_error, socket) => {
    if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
  });

  await new Promise((resolve, reject) => {
    const onError = (error) => reject(error);
    server.once("error", onError);
    server.listen(requestedPort, host, () => {
      server.off("error", onError);
      resolve();
    });
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : requestedPort;
  expirySweepTimer = setInterval(() => void sweepExpiredCommands(), config.expirySweepMs);
  expirySweepTimer.unref?.();
  let closePromise = null;
  return Object.freeze({
    host,
    port,
    origin: config.origin.value,
    close: async () => {
      if (!closePromise) {
        closePromise = (async () => {
          clearInterval(expirySweepTimer);
          for (const stream of [...streams]) stream.close();
          await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
          if (options.closeStore === true) store.close();
          if (ownsSessions || options.closeSessionStore === true) sessionStore.close();
          if (options.closeRunnerNonceStore === true && typeof runnerNonceStore.close === "function") runnerNonceStore.close();
        })();
      }
      return closePromise;
    }
  });
}

export const remoteServerInternals = Object.freeze({
  CSP,
  DEFAULTS,
  RUNNER_ACK_VERSION,
  RUNNER_ACTIVITY_VERSION,
  RUNNER_HEARTBEAT_VERSION,
  RUNNER_LEASE_REQUEST_VERSION,
  RUNNER_LEASE_VERSION,
  RUNNER_TRANSITION_VERSION,
  RollingWindowLimiter,
  SESSION_API_VERSION,
  SESSION_COOKIE_NAME,
  STATIC_ROUTES,
  preloadStatic,
  publicFailure,
  sseChunk,
  storeReady
});
