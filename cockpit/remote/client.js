import {
  parseRemoteSseFrame,
  readRemoteJsonResponse,
  remoteStateIsFresh,
  validateRemoteOperatorMessage,
  validateRemoteActivityEvent,
  validateRemoteCommandEvent,
  validateRemoteCommandStatusRequest,
  validateRemoteCommandStatusResponse,
  validateRemoteCompanionState,
  validateRemoteFleet,
  validateRemoteQueuedReceipt,
  validateRemoteRevocation,
  validateRemoteSession
} from "../assets/model.js";
import "../assets/app.js";

const API = "/api/cockpit/v1";
const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/u;
const QUESTION_TOKEN = /^q_[A-Za-z0-9_-]{43}$/u;
const QUESTION_ID = /^[a-z][a-z0-9_-]{0,63}$/u;
const MAX_SESSION_BYTES = 4 * 1024;
const MAX_RECEIPT_BYTES = 8 * 1024;
const MAX_COMMAND_STATUS_BYTES = 8 * 1024;
const MAX_STATE_BYTES = 136 * 1024;
const MAX_FLEET_BYTES = 136 * 1024;
const MAX_EVENT_FRAME_BYTES = 136 * 1024;
const MAX_EVENT_BUFFER_BYTES = 160 * 1024;

let session = null;
let bridge = null;
let streamAbort = null;
let pollTimer = null;
let stateDeadlineTimer = null;
let lastCursor = 0;
let latestStateRevision = -1;
let latestFleetRevision = -1;
let latestState = null;
let latestFleet = null;
let streamReady = false;
let stopped = false;
const commandReceipts = new Map();

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, keys) {
  if (!record(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function canonicalProjection(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalProjection).join(",")}]`;
  if (record(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalProjection(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sameProjection(left, right) {
  try {
    return canonicalProjection(left) === canonicalProjection(right);
  } catch {
    return false;
  }
}

function canonicalNow() {
  return new Date().toISOString();
}

function connection(state) {
  globalThis.dispatchEvent(new CustomEvent("gate:remote-connection", {
    detail: Object.freeze({ apiVersion: "gate.remote-cockpit-connection/v1", state, at: canonicalNow() })
  }));
}

function clearTimers() {
  if (pollTimer !== null) globalThis.clearInterval(pollTimer);
  if (stateDeadlineTimer !== null) globalThis.clearTimeout(stateDeadlineTimer);
  pollTimer = null;
  stateDeadlineTimer = null;
}

function projectionUnavailable(projection) {
  const stateUnavailable = projection === "state";
  const changed = stateUnavailable
    ? latestState !== null || latestFleet !== null
    : latestFleet !== null;
  if (stateUnavailable) {
    if (stateDeadlineTimer !== null) globalThis.clearTimeout(stateDeadlineTimer);
    stateDeadlineTimer = null;
    latestState = null;
    latestFleet = null;
  } else {
    latestFleet = null;
  }
  if (!changed) return;
  globalThis.dispatchEvent(new CustomEvent("gate:remote-projection-unavailable", {
    detail: Object.freeze({
      apiVersion: "gate.remote-projection-unavailable/v1",
      projection
    })
  }));
}

function scheduleStateDeadline(value) {
  if (stateDeadlineTimer !== null) globalThis.clearTimeout(stateDeadlineTimer);
  const delay = Math.max(0, Date.parse(value.validUntil) - Date.now());
  stateDeadlineTimer = globalThis.setTimeout(() => {
    stateDeadlineTimer = null;
    if (latestState !== value) return;
    if (remoteStateIsFresh(value)) scheduleStateDeadline(value);
    else projectionUnavailable("state");
  }, delay);
}

function clearBridge() {
  streamReady = false;
  if (globalThis.GATE_REMOTE_COCKPIT_BRIDGE === bridge) {
    try { delete globalThis.GATE_REMOTE_COCKPIT_BRIDGE; } catch { /* app still fails closed from connection state */ }
  }
  bridge = null;
}

function revoke() {
  if (stopped) return;
  stopped = true;
  streamAbort?.abort();
  streamAbort = null;
  clearTimers();
  clearBridge();
  session = null;
  commandReceipts.clear();
  latestStateRevision = -1;
  latestFleetRevision = -1;
  latestState = null;
  latestFleet = null;
  lastCursor = 0;
  globalThis.dispatchEvent(new Event("gate:remote-revoked"));
  connection("revoked");
}

function requestHeaders(accept) {
  return Object.freeze({ Accept: accept });
}

async function fetchResponse(path, init = {}) {
  const response = await fetch(`${API}${path}`, {
    cache: "no-store",
    credentials: "same-origin",
    redirect: "error",
    ...init
  });
  if (response.status === 401 || response.status === 403) {
    revoke();
    return null;
  }
  if (response.redirected) return null;
  return response;
}

async function readSession() {
  const response = await fetchResponse("/session", { headers: requestHeaders("application/json") });
  if (!response) return null;
  return validateRemoteSession(await readRemoteJsonResponse(response, MAX_SESSION_BYTES));
}

async function readState() {
  if (!session || stopped) return false;
  try {
    const response = await fetchResponse("/state", { headers: requestHeaders("application/json") });
    if (!response) {
      if (!stopped) projectionUnavailable("state");
      return false;
    }
    const accepted = acceptState(await readRemoteJsonResponse(response, MAX_STATE_BYTES));
    const available = accepted && latestState !== null;
    if (!available && !stopped) projectionUnavailable("state");
    return available;
  } catch {
    if (!stopped) projectionUnavailable("state");
    return false;
  }
}

function acceptState(input) {
  const value = validateRemoteCompanionState(input, {
    sessionRevision: session.sessionRevision
  });
  if (!value) return false;
  if (value.stateRevision < latestStateRevision) return true;
  if (value.stateRevision === latestStateRevision && latestState !== null) {
    return sameProjection(value, latestState);
  }
  latestStateRevision = value.stateRevision;
  if (!remoteStateIsFresh(value)) {
    projectionUnavailable("state");
    return true;
  }
  latestState = value;
  scheduleStateDeadline(value);
  globalThis.dispatchEvent(new CustomEvent("gate:remote-private-state", { detail: value }));
  return true;
}

async function readFleet() {
  if (!session || stopped) return false;
  try {
    const response = await fetchResponse("/fleet", { headers: requestHeaders("application/json") });
    if (!response) {
      if (!stopped) projectionUnavailable("fleet");
      return false;
    }
    const accepted = acceptFleet(await readRemoteJsonResponse(response, MAX_FLEET_BYTES));
    if (!accepted && !stopped) projectionUnavailable("fleet");
    return accepted;
  } catch {
    if (!stopped) projectionUnavailable("fleet");
    return false;
  }
}

function acceptFleet(input) {
  const value = validateRemoteFleet(input, {
    sessionRevision: session.sessionRevision
  });
  if (!value) return false;
  if (!latestState || !remoteStateIsFresh(latestState)) {
    projectionUnavailable("state");
    return true;
  }
  if (value.revision < latestFleetRevision) return true;
  if (value.revision === latestFleetRevision && latestFleet !== null) {
    return sameProjection(value, latestFleet);
  }
  latestFleetRevision = value.revision;
  latestFleet = value;
  globalThis.dispatchEvent(new CustomEvent("gate:remote-fleet", { detail: value }));
  return true;
}

function validMessageRequest(value) {
  if (!exactKeys(value, ["apiVersion", "requestId", "sessionRevision", "message"])
      || value.apiVersion !== "gate.remote-message-request/v1"
      || !REQUEST_ID.test(value.requestId)
      || value.sessionRevision !== session?.sessionRevision) return false;
  const message = validateRemoteOperatorMessage(value.message);
  return message.valid && message.message === value.message;
}

function remoteWritable() {
  return streamReady && globalThis.GATE_PUBLIC_COCKPIT_BRIDGE === undefined && session !== null
    && latestState?.sessionRevision === session.sessionRevision
    && latestState.runner.state === "connected"
    && latestState.codex.state !== "offline"
    && remoteStateIsFresh(latestState);
}

function validQuestionRequest(value) {
  if (!exactKeys(value, ["apiVersion", "requestId", "sessionRevision", "questionToken", "answers"])
      || value.apiVersion !== "gate.remote-question-response/v1"
      || !REQUEST_ID.test(value.requestId)
      || value.sessionRevision !== session?.sessionRevision
      || !QUESTION_TOKEN.test(value.questionToken) || !record(value.answers)) return false;
  const entries = Object.entries(value.answers);
  return entries.length >= 1 && entries.length <= 3 && entries.every(([id, answer]) => {
    const normalized = validateRemoteOperatorMessage(answer);
    return QUESTION_ID.test(id) && normalized.valid && normalized.message === answer
      && [...answer].length <= 100 && new TextEncoder().encode(answer).byteLength <= 400;
  });
}

async function post(path, request, validateRequest) {
  if (!session || stopped || !remoteWritable() || !validateRequest(request)) throw new Error("remote request rejected");
  const body = JSON.stringify(request);
  if (new TextEncoder().encode(body).byteLength > 16 * 1024) throw new Error("remote request rejected");
  const expectedSessionRevision = session.sessionRevision;
  const response = await fetchResponse(path, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-GATE-CSRF": session.csrf
    },
    body
  });
  if (!response || response.status !== 202) throw new Error("remote request rejected");
  const receipt = validateRemoteQueuedReceipt(
    await readRemoteJsonResponse(response, MAX_RECEIPT_BYTES),
    request.requestId,
    expectedSessionRevision
  );
  if (!receipt || session?.sessionRevision !== expectedSessionRevision) throw new Error("remote request rejected");
  commandReceipts.set(receipt.commandId, receipt);
  while (commandReceipts.size > 256) commandReceipts.delete(commandReceipts.keys().next().value);
  return receipt;
}

async function reconcileCommands(request) {
  if (!session || stopped || !remoteWritable()) throw new Error("remote request rejected");
  const normalized = validateRemoteCommandStatusRequest(request, {
    caseId: session.caseId,
    sessionRevision: session.sessionRevision
  });
  if (!normalized) throw new Error("remote request rejected");
  const body = JSON.stringify(normalized);
  if (new TextEncoder().encode(body).byteLength > 16 * 1024) throw new Error("remote request rejected");
  const expectedSession = session;
  const response = await fetchResponse("/commands/status", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-GATE-CSRF": expectedSession.csrf
    },
    body
  });
  if (!response || response.status !== 200) throw new Error("remote request rejected");
  const result = validateRemoteCommandStatusResponse(
    await readRemoteJsonResponse(response, MAX_COMMAND_STATUS_BYTES),
    normalized
  );
  if (!result || session !== expectedSession || !remoteWritable()) throw new Error("remote request rejected");
  return result;
}

function installBridge() {
  bridge = Object.freeze({
    apiVersion: "gate.remote-cockpit-bridge/v1",
    caseId: session.caseId,
    sessionRevision: session.sessionRevision,
    reconcileCommands,
    submitMessage: (request) => post("/messages", request, validMessageRequest),
    submitQuestion: (request) => post("/questions", request, validQuestionRequest)
  });
  Object.defineProperty(globalThis, "GATE_REMOTE_COCKPIT_BRIDGE", {
    configurable: true,
    enumerable: false,
    writable: false,
    value: bridge
  });
  streamReady = true;
}

function splitFrame(buffer) {
  const lf = buffer.indexOf("\n\n");
  const crlf = buffer.indexOf("\r\n\r\n");
  if (lf < 0 && crlf < 0) return null;
  if (crlf >= 0 && (lf < 0 || crlf < lf)) return [buffer.slice(0, crlf), buffer.slice(crlf + 4)];
  return [buffer.slice(0, lf), buffer.slice(lf + 2)];
}

async function resync() {
  if (!await readState()) return false;
  return readFleet();
}

async function dispatchFrame(decoded, options = {}) {
  if (decoded.name === "ready") {
    if (!exactKeys(decoded.value, ["apiVersion", "cursor"])
        || decoded.value.apiVersion !== "gate.remote-events-ready/v1"
        || !Number.isSafeInteger(decoded.value.cursor) || decoded.value.cursor < 0
        || options.expectedReadyCursor === undefined || decoded.value.cursor !== options.expectedReadyCursor
        || decoded.value.cursor !== lastCursor) return false;
    return true;
  }
  if (decoded.name === "resync") {
    if (!exactKeys(decoded.value, ["apiVersion", "cursor"])
        || decoded.value.apiVersion !== "gate.remote-resync/v1"
        || !Number.isSafeInteger(decoded.value.cursor) || decoded.value.cursor < 0
        || decoded.id !== decoded.value.cursor) return false;
    clearBridge();
    connection("connecting");
    if (!await resync()) return false;
    lastCursor = decoded.value.cursor;
    if (options.beforeReady !== true) {
      installBridge();
      connection("connected");
    }
    return true;
  }
  if (decoded.id <= lastCursor) return true;
  let value;
  if (decoded.name === "activity") {
    value = validateRemoteActivityEvent(decoded.value);
    if (!value || value.sequence !== decoded.id) return false;
    globalThis.dispatchEvent(new CustomEvent("gate:remote-activity", { detail: value }));
  } else if (decoded.name === "command") {
    const receipt = record(decoded.value) ? commandReceipts.get(decoded.value.commandId) : null;
    value = validateRemoteCommandEvent(decoded.value, receipt ? { acceptedAt: receipt.acceptedAt } : {});
    if (!value || value.sequence !== decoded.id) return false;
    globalThis.dispatchEvent(new CustomEvent("gate:remote-command", { detail: value }));
  } else if (decoded.name === "state") {
    if (!acceptState(decoded.value)) return false;
  } else if (decoded.name === "fleet") {
    if (!acceptFleet(decoded.value)) return false;
  } else {
    value = validateRemoteRevocation(decoded.value);
    if (!value) return false;
    lastCursor = decoded.id;
    revoke();
    return false;
  }
  lastCursor = decoded.id;
  return true;
}

async function consumeEvents(response, requestedCursor) {
  if (!response || !response.ok || response.redirected || !response.body) return false;
  const contentType = response.headers.get("content-type") || "";
  if (!/^text\/event-stream(?:\s*;|$)/iu.test(contentType)) return false;
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > MAX_EVENT_BUFFER_BYTES)) return false;
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let buffer = "";
  let ready = false;
  let initialResync = false;
  try {
    while (!stopped) {
      const { value, done } = await reader.read();
      if (done) {
        buffer += decoder.decode();
        return buffer.trim() === "";
      }
      buffer += decoder.decode(value, { stream: true });
      while (true) {
        const split = splitFrame(buffer);
        if (!split) break;
        buffer = split[1];
        const decoded = parseRemoteSseFrame(split[0], MAX_EVENT_FRAME_BYTES);
        const meaningful = split[0].replace(/\r\n/gu, "\n").split("\n")
          .some((line) => line !== "" && !line.startsWith(":") && !line.startsWith("retry:"));
        if (!decoded && meaningful) return false;
        if (decoded) {
          if (!ready && !new Set(["ready", "resync"]).has(decoded.name)) return false;
          if (ready && decoded.name === "ready") return false;
          if (!ready && decoded.name === "resync") {
            if (initialResync || !await dispatchFrame(decoded, { beforeReady: true })) return false;
            initialResync = true;
            continue;
          }
          if (!await dispatchFrame(decoded, ready ? {} : { expectedReadyCursor: lastCursor })) return false;
          if (!ready && decoded.name === "ready") {
            ready = true;
            installBridge();
            connection("connected");
          }
        }
      }
      if (new TextEncoder().encode(buffer).byteLength > MAX_EVENT_BUFFER_BYTES) return false;
    }
  } catch {
    return false;
  } finally {
    try { await reader.cancel(); } catch { /* stream already closed */ }
  }
  return false;
}

async function openEventStream() {
  streamAbort = new AbortController();
  const requestedCursor = lastCursor;
  const response = await fetchResponse(`/events?cursor=${requestedCursor}`, {
    signal: streamAbort.signal,
    headers: {
      Accept: "text/event-stream",
      "Last-Event-ID": String(requestedCursor)
    }
  });
  if (!response) return false;
  return consumeEvents(response, requestedCursor);
}

function beginPolling() {
  pollTimer = globalThis.setInterval(() => {
    if (!stopped) void resync();
  }, 5_000);
}

async function start() {
  try {
    let bootstrapDelay = 1_000;
    while (!session && !stopped) {
      connection("connecting");
      try { session = await readSession(); } catch { session = null; }
      if (session || stopped) break;
      connection("offline");
      await new Promise((resolve) => globalThis.setTimeout(resolve, bootstrapDelay));
      bootstrapDelay = Math.min(bootstrapDelay * 2, 30_000);
    }
    if (!session || stopped) return;
    await resync();
    if (stopped) return;
    beginPolling();
    let delay = 1_000;
    while (!stopped) {
      clearBridge();
      connection("connecting");
      let opened = false;
      try {
        opened = await openEventStream();
      } catch {
        opened = false;
      }
      if (stopped) return;
      clearBridge();
      connection("offline");
      await new Promise((resolve) => globalThis.setTimeout(resolve, delay));
      delay = opened ? 1_000 : Math.min(delay * 2, 30_000);
    }
  } catch {
    if (!stopped) connection("offline");
  }
}

globalThis.addEventListener("pagehide", () => {
  stopped = true;
  streamAbort?.abort();
  clearTimers();
  clearBridge();
});

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start, { once: true });
else globalThis.queueMicrotask(start);
