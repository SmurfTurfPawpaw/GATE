import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  CompanionContractError,
  MAX_BODY_BYTES,
  acceptedReceipt,
  normalizeDecisionRequest,
  normalizeMessageRequest,
  normalizeQuestionResponse
} from "./contracts.mjs";
import { createUnavailableFleetProvider } from "./gate-fleet.mjs";

const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_MAX_REQUESTS = 20_000;
const DEFAULT_SNAPSHOT_MAX_AGE_MS = 5 * 60_000;
const MAX_STATIC_ASSET_BYTES = 1024 * 1024;
const MAX_SNAPSHOT_BYTES = 64 * 1024;
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
  "frame-ancestors 'none'"
].join("; ");

const STATIC_ROUTES = new Map([
  ["/assets/app.js", ["assets/app.js", "text/javascript; charset=utf-8"]],
  ["/assets/model.js", ["assets/model.js", "text/javascript; charset=utf-8"]],
  ["/assets/styles.css", ["assets/styles.css", "text/css; charset=utf-8"]],
  ["/assets/favicon.svg", ["assets/favicon.svg", "image/svg+xml"]],
  ["/robots.txt", ["robots.txt", "text/plain; charset=utf-8"]],
  ["/.nojekyll", [".nojekyll", "application/octet-stream"]]
]);

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function randomToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function sameToken(actual, expected) {
  if (typeof actual !== "string") return false;
  const left = Buffer.from(actual);
  const right = Buffer.from(expected);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function isLoopbackHost(host) {
  return host === "127.0.0.1" || host === "::1";
}

function isLoopbackAddress(address) {
  return address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1";
}

function hostHeader(host, port) {
  return `${host === "::1" ? `[${host}]` : host}:${port}`;
}

function commonHeaders(contentType) {
  return {
    "Cache-Control": "no-store, max-age=0",
    "Content-Security-Policy": CSP,
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Type": contentType
  };
}

function send(response, status, body, contentType = "application/json; charset=utf-8", method = "GET", extra = {}) {
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(body, "utf8");
  response.writeHead(status, {
    ...commonHeaders(contentType),
    ...extra,
    "Content-Length": bytes.length
  });
  if (method === "HEAD") response.end();
  else response.end(bytes);
}

function json(response, status, value, method = "GET", extra = {}) {
  send(response, status, `${JSON.stringify(value)}\n`, "application/json; charset=utf-8", method, extra);
}

function publicError(error) {
  if (error instanceof CompanionContractError) {
    return { status: error.status, code: error.code, message: error.publicMessage };
  }
  return { status: 503, code: "companion-unavailable", message: "The local companion could not accept that request." };
}

async function readJson(request) {
  if (!String(request.headers["content-type"] || "").toLowerCase().startsWith("application/json")) {
    throw new CompanionContractError(415, "json-required", "The local companion accepts JSON requests only.");
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) {
      throw new CompanionContractError(413, "request-too-large", "The local cockpit request is too large.");
    }
    chunks.push(chunk);
  }
  try {
    const value = JSON.parse(Buffer.concat(chunks, total).toString("utf8"));
    if (!record(value)) throw new Error("object required");
    return value;
  } catch (error) {
    if (error instanceof CompanionContractError) throw error;
    throw new CompanionContractError(400, "json-invalid", "The local cockpit request is invalid.");
  }
}

function secureRead(root, relative, maximum = MAX_STATIC_ASSET_BYTES) {
  const absolute = path.resolve(root, relative);
  if (absolute !== root && !absolute.startsWith(`${root}${path.sep}`)) throw new Error("static asset escaped repository root");
  const before = fs.lstatSync(absolute, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.size > BigInt(maximum)) throw new Error("invalid static asset");
  const bytes = fs.readFileSync(absolute);
  const after = fs.lstatSync(absolute, { bigint: true });
  if (!after.isFile() || after.isSymbolicLink() || before.dev !== after.dev || before.ino !== after.ino
      || after.size !== BigInt(bytes.length)) throw new Error("static asset changed while loading");
  return bytes;
}

function preloadStatic(root) {
  const assets = new Map();
  for (const [route, [relative, contentType]] of STATIC_ROUTES) {
    assets.set(route, { bytes: secureRead(root, relative), contentType });
  }
  const originalIndex = secureRead(root, "index.html").toString("utf8");
  const appTag = '<script type="module" src="./assets/app.js"></script>';
  if (!originalIndex.includes(appTag)) throw new Error("cockpit index is missing its application module");
  const injected = originalIndex.replace(
    appTag,
    `<script type="module" src="./companion/client.js"></script>\n    ${appTag}`
  );
  assets.set("/", { bytes: Buffer.from(injected), contentType: "text/html; charset=utf-8" });
  assets.set("/index.html", assets.get("/"));
  assets.set("/companion/client.js", {
    bytes: secureRead(root, "companion/client.js"),
    contentType: "text/javascript; charset=utf-8"
  });
  return assets;
}

export function createFileSnapshotProvider(snapshotPath) {
  const absolute = path.resolve(snapshotPath);
  return async () => {
    const bytes = secureRead(path.dirname(absolute), path.basename(absolute), MAX_SNAPSHOT_BYTES);
    let value;
    try {
      value = JSON.parse(bytes.toString("utf8"));
    } catch {
      throw new Error("cockpit snapshot is invalid");
    }
    if (!record(value)) throw new Error("cockpit snapshot is invalid");
    return value;
  };
}

function validateObservedSnapshot(snapshot, generatedAt, now = Date.now()) {
  if (!record(snapshot) || snapshot.schema !== "gate.public-cockpit/v1" || snapshot.mode !== "observed"
      || snapshot.snapshot?.generatedAt !== generatedAt) {
    throw new CompanionContractError(409, "snapshot-changed", "The cockpit changed. Reload it before continuing.");
  }
  const produced = Date.parse(snapshot.snapshot.generatedAt);
  const expires = Date.parse(snapshot.snapshot.validUntil);
  if (!Number.isFinite(produced) || !Number.isFinite(expires) || produced > now + 300_000 || expires < now
      || produced >= expires || expires - produced > 900_000) {
    throw new CompanionContractError(409, "snapshot-expired", "The cockpit snapshot expired. Reload it before continuing.");
  }
  return snapshot;
}

function validateLocalSession(adapter, revision) {
  const state = adapter.privateState();
  if (state?.apiVersion !== "gate.local-companion-state/v1" || state.connected !== true
      || state.sessionRevision !== revision) {
    throw new CompanionContractError(409, "session-changed", "The local companion session changed. Reload the cockpit.");
  }
  return state;
}

function validateDecision(snapshot, request, now = Date.now()) {
  const decision = snapshot.decision;
  if (!record(decision) || decision.state !== "waiting" || decision.id !== request.decisionId
      || decision.revision !== request.decisionRevision || !Array.isArray(decision.choices)
      || !decision.choices.includes(request.choice)) {
    throw new CompanionContractError(409, "decision-changed", "That decision changed. Reload the cockpit before choosing.");
  }
  const expiresAt = Date.parse(decision.expiresAt);
  if (!Number.isFinite(expiresAt) || expiresAt < now) {
    throw new CompanionContractError(409, "decision-expired", "That decision expired. Reload the cockpit.");
  }
}

class SubmissionLedger {
  #entries = new Map();
  #limit;

  constructor(limit = 256) {
    this.#limit = limit;
  }

  run(id, value, action) {
    const digest = crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
    const previous = this.#entries.get(id);
    if (previous) {
      if (previous.digest !== digest) {
        throw new CompanionContractError(409, "request-id-reused", "Reload the cockpit before retrying that request.");
      }
      return previous.promise;
    }
    const promise = Promise.resolve().then(action).then(() => acceptedReceipt(id));
    this.#entries.set(id, { digest, promise });
    promise.catch(() => this.#entries.delete(id));
    while (this.#entries.size > this.#limit) this.#entries.delete(this.#entries.keys().next().value);
    return promise;
  }
}

class DecisionLedger {
  #entries = new Map();

  run(key, action) {
    if (this.#entries.has(key)) {
      throw new CompanionContractError(409, "decision-consumed", "That decision was already answered. Reload the cockpit.");
    }
    const promise = Promise.resolve().then(action);
    this.#entries.set(key, promise);
    promise.catch(() => this.#entries.delete(key));
    return promise;
  }
}

export async function startCompanionServer(options = {}) {
  const host = options.host || "127.0.0.1";
  if (!isLoopbackHost(host)) throw new Error("cockpit companion must bind to an explicit loopback address");
  const requestedPort = options.port === undefined ? 0 : Number(options.port);
  if (!Number.isSafeInteger(requestedPort) || requestedPort < 0 || requestedPort > 65535) {
    throw new Error("cockpit companion port must be an integer from 0 through 65535");
  }
  const maxRequests = options.maxRequests ?? DEFAULT_MAX_REQUESTS;
  if (!Number.isSafeInteger(maxRequests) || maxRequests < 1 || maxRequests > 100_000) {
    throw new Error("cockpit companion request limit must be between 1 and 100000");
  }
  const requestTimeoutMs = options.requestTimeoutMs ?? 10_000;
  if (!Number.isSafeInteger(requestTimeoutMs) || requestTimeoutMs < 10 || requestTimeoutMs > 60_000) {
    throw new Error("cockpit companion request timeout must be between 10 and 60000 milliseconds");
  }
  const root = path.resolve(options.root || REPOSITORY_ROOT);
  const staticAssets = preloadStatic(root);
  const snapshotProvider = options.snapshotProvider || createFileSnapshotProvider(path.join(root, "data/status.json"));
  const fleetProvider = options.fleetProvider || createUnavailableFleetProvider();
  if (typeof fleetProvider !== "function") throw new Error("cockpit fleet provider must be a function");
  const adapter = options.adapter;
  if (!adapter || typeof adapter.sendMessage !== "function" || typeof adapter.sendDecision !== "function"
      || typeof adapter.answerQuestion !== "function" || typeof adapter.privateState !== "function"
      || !adapter.activityStore) throw new Error("cockpit companion adapter is required");
  const sessionToken = randomToken();
  const csrfToken = randomToken();
  const ledger = new SubmissionLedger(options.ledgerLimit);
  const decisionLedger = new DecisionLedger();
  const streams = new Set();
  let expectedHost;
  let origin;
  let requestCount = 0;

  const server = http.createServer(async (request, response) => {
    requestCount += 1;
    request.setTimeout(requestTimeoutMs, () => request.destroy());
    const method = request.method || "GET";
    if (requestCount > maxRequests) return json(response, 429, { ok: false, error: { code: "request-limit", message: "Restart the local companion to continue." } }, method);
    if (!isLoopbackAddress(request.socket.remoteAddress) || request.headers.host !== expectedHost) {
      return json(response, 421, { ok: false, error: { code: "host-rejected", message: "The local companion rejected this host." } }, method);
    }
    if (request.headers.origin && request.headers.origin !== origin) {
      return json(response, 403, { ok: false, error: { code: "origin-rejected", message: "The local companion rejected this origin." } }, method);
    }
    const fetchSite = String(request.headers["sec-fetch-site"] || "").toLowerCase();
    if (fetchSite === "cross-site") {
      return json(response, 403, { ok: false, error: { code: "site-rejected", message: "The local companion rejected a cross-site request." } }, method);
    }
    let pathname;
    try {
      pathname = new URL(request.url || "/", origin).pathname;
    } catch {
      return json(response, 400, { ok: false, error: { code: "request-invalid", message: "The local companion rejected this request." } }, method);
    }

    if ((method === "GET" || method === "HEAD") && pathname === "/healthz") {
      return json(response, 200, { ok: true, service: "gate-cockpit-companion" }, method);
    }
    if ((method === "GET" || method === "HEAD") && pathname === "/data/status.json") {
      try {
        return json(response, 200, await snapshotProvider(), method);
      } catch {
        return json(response, 503, { error: "snapshot unavailable" }, method);
      }
    }
    const staticAsset = staticAssets.get(pathname);
    if ((method === "GET" || method === "HEAD") && staticAsset) {
      return send(response, 200, staticAsset.bytes, staticAsset.contentType, method);
    }

    if (!pathname.startsWith("/api/")) {
      return json(response, 404, { ok: false, error: { code: "not-found", message: "That local cockpit resource does not exist." } }, method);
    }
    if (!sameToken(request.headers["x-gate-session"], sessionToken)) {
      return json(response, 401, { ok: false, error: { code: "session-required", message: "Open the cockpit from the companion URL." } }, method);
    }
    if (method === "GET" && pathname === "/api/private-state") {
      return json(response, 200, { ok: true, state: adapter.privateState() }, method);
    }
    if (method === "GET" && pathname === "/api/fleet") {
      try {
        return json(response, 200, { ok: true, fleet: await fleetProvider() }, method);
      } catch {
        return json(response, 503, { ok: false, error: { code: "fleet-unavailable", message: "GATE fleet status is unavailable." } }, method);
      }
    }
    if (method === "GET" && pathname === "/api/events") {
      request.setTimeout(0);
      const lastSequence = Number(request.headers["last-event-id"] || 0);
      response.writeHead(200, {
        ...commonHeaders("text/event-stream; charset=utf-8"),
        Connection: "keep-alive",
        "X-Accel-Buffering": "no"
      });
      response.write("retry: 2000\n\n");
      const writeEvent = (event) => {
        if (response.writableEnded) return;
        response.write(`id: ${event.sequence}\nevent: activity\ndata: ${JSON.stringify(event)}\n\n`);
      };
      for (const event of adapter.activityStore.since(Number.isSafeInteger(lastSequence) ? lastSequence : 0)) writeEvent(event);
      const onEvent = (event) => writeEvent(event);
      adapter.activityStore.on("event", onEvent);
      const onState = () => {
        if (!response.writableEnded) {
          response.write('event: state\ndata: {"apiVersion":"gate.local-companion-state-signal/v1"}\n\n');
        }
      };
      if (typeof adapter.on === "function") adapter.on("state", onState);
      const keepAlive = setInterval(() => {
        if (!response.writableEnded) response.write(": keepalive\n\n");
      }, 15_000);
      keepAlive.unref?.();
      const stream = { response, close: () => {
        clearInterval(keepAlive);
        adapter.activityStore.off("event", onEvent);
        if (typeof adapter.off === "function") adapter.off("state", onState);
        if (!response.writableEnded) response.end();
      } };
      streams.add(stream);
      request.once("close", () => { stream.close(); streams.delete(stream); });
      return;
    }
    if (method !== "POST" || !["/api/message", "/api/decision", "/api/question"].includes(pathname)) {
      return json(response, 405, { ok: false, error: { code: "method-rejected", message: "That local cockpit action is unavailable." } }, method, { Allow: "GET, HEAD, POST" });
    }
    if (request.headers.origin !== origin || !sameToken(request.headers["x-gate-csrf"], csrfToken)) {
      return json(response, 403, { ok: false, error: { code: "csrf-rejected", message: "Reload the local cockpit before continuing." } }, method);
    }
    try {
      const body = await readJson(request);
      let normalized;
      let receipt;
      if (pathname === "/api/message") {
        normalized = normalizeMessageRequest(body);
        validateLocalSession(adapter, normalized.sessionRevision);
        receipt = await ledger.run(normalized.requestId, normalized, () => adapter.sendMessage(normalized));
      } else if (pathname === "/api/decision") {
        normalized = normalizeDecisionRequest(body);
        const snapshot = validateObservedSnapshot(await snapshotProvider(), normalized.snapshotGeneratedAt);
        validateDecision(snapshot, normalized);
        const internalDecision = Object.freeze({
          ...normalized,
          campaign: snapshot.decision.campaign,
          prompt: snapshot.decision.prompt
        });
        const decisionKey = `${normalized.decisionId}:${normalized.decisionRevision}`;
        receipt = await ledger.run(normalized.requestId, normalized, () => (
          decisionLedger.run(decisionKey, () => adapter.sendDecision(internalDecision))
        ));
      } else {
        normalized = normalizeQuestionResponse(body);
        validateLocalSession(adapter, normalized.sessionRevision);
        receipt = await ledger.run(normalized.requestId, normalized, () => adapter.answerQuestion(normalized));
      }
      return json(response, 202, receipt, method);
    } catch (error) {
      const failure = publicError(error);
      return json(response, failure.status, { ok: false, error: { code: failure.code, message: failure.message } }, method);
    }
  });
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
  expectedHost = hostHeader(host, port);
  origin = `http://${expectedHost}`;
  const fragment = new URLSearchParams({ session: sessionToken, csrf: csrfToken }).toString();
  const url = `${origin}/#${fragment}`;

  return Object.freeze({
    host,
    port,
    origin,
    url,
    close: async () => {
      for (const stream of streams) stream.close();
      streams.clear();
      await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
      if (options.closeAdapter !== false && typeof adapter.close === "function") await adapter.close();
    }
  });
}

export const companionServerInternals = Object.freeze({
  CSP,
  DEFAULT_MAX_REQUESTS,
  DEFAULT_SNAPSHOT_MAX_AGE_MS,
  MAX_SNAPSHOT_BYTES,
  STATIC_ROUTES,
  DecisionLedger,
  SubmissionLedger,
  hostHeader,
  isLoopbackAddress,
  isLoopbackHost,
  preloadStatic,
  publicError,
  sameToken,
  validateDecision,
  validateLocalSession,
  validateObservedSnapshot
});
