import crypto from "node:crypto";
import { unavailablePilotProjection, validatePilotProjection } from "../assets/model.js";
import { validateExecutionMirror } from "../execution-mirror.mjs";

export const REMOTE_BRIDGE_VERSION = "gate.remote-cockpit-bridge/v1";
export const REMOTE_MESSAGE_VERSION = "gate.remote-message-request/v1";
export const REMOTE_QUESTION_VERSION = "gate.remote-question-response/v1";
export const REMOTE_RECEIPT_VERSION = "gate.remote-cockpit-receipt/v1";
export const REMOTE_COMMAND_VERSION = "gate.remote-command/v1";
export const REMOTE_COMMAND_EVENT_VERSION = "gate.remote-command-event/v1";
export const REMOTE_COMMAND_STATUS_REQUEST_VERSION = "gate.remote-command-status-request/v1";
export const REMOTE_COMMAND_STATUS_RESPONSE_VERSION = "gate.remote-command-status-response/v1";
export const REMOTE_ACTIVITY_EVENT_VERSION = "gate.remote-cockpit-event/v1";
export const REMOTE_STATE_VERSION = "gate.remote-cockpit-state/v1";
export const REMOTE_FLEET_VERSION = "gate.remote-fleet/v4";
export const REMOTE_EVENTS_PAGE_VERSION = "gate.remote-events-page/v1";

export const MAX_REMOTE_MESSAGE_CHARACTERS = 1_000;
export const MAX_REMOTE_PROJECTION_BYTES = 128 * 1024;
export const MAX_REMOTE_COMMAND_STATUS_REFERENCES = 16;
export const REMOTE_COMMAND_STATES = Object.freeze([
  "queued",
  "leased",
  "accepted",
  "running",
  "completed",
  "failed",
  "expired",
  "cancelled"
]);

const COMMAND_STATES = new Set(REMOTE_COMMAND_STATES);
const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/u;
const COMMAND_ID = /^cmd_[A-Za-z0-9_-]{16,128}$/u;
const QUESTION_TOKEN = /^q_[A-Za-z0-9_-]{32,128}$/u;
const DISPLAY_QUESTION_TOKEN = /^q_[A-Za-z0-9_-]{43}$/u;
const PRINCIPAL_ID = /^[A-Za-z0-9][A-Za-z0-9._:@|+-]{2,127}$/u;
const SESSION_OR_RUNNER_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/u;
const CASE_ID = /^[a-z][a-z0-9-]{1,62}$/u;
const CONTROL_CHARACTERS = /[\u0000-\u0009\u000B\u000C\u000E-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/u;
const SECRET_ASSIGNMENT = /["']?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|private[_-]?key|session[_-]?(?:id|key|token)|aws[_-]?(?:access[_-]?key[_-]?id|secret[_-]?access[_-]?key)|authorization|cookie|secret)["']?\s*[:=]\s*(?:"[^"\r\n]+"|'[^'\r\n]+'|\S+)/iu;
const AUTHORIZATION_TOKEN = /\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{12,}={0,2}\b/iu;
const PRIVATE_KEY = /-----BEGIN (?:(?:[A-Z0-9][A-Z0-9 -]* )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----/u;
const CREDENTIAL_URL = /\b[a-z][a-z0-9+.-]{1,31}:\/\/[^\s/:@]{1,128}:[^\s/@]{1,256}@/iu;
const SENSITIVE_HEADER = /(?:^|\n)\s*(?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\r\n]+/iu;
const STANDALONE_CREDENTIAL = /(?:\b(?:github_pat_[A-Za-z0-9_]{20,255}|gh[pousr]_[A-Za-z0-9]{20,255}|glpat-[A-Za-z0-9_-]{20,255}|sk-(?:proj-|ant-api\d{2}-)?[A-Za-z0-9_-]{16,255}|(?:sk|rk)_live_[A-Za-z0-9]{16,255}|xox[baprs]-[A-Za-z0-9-]{10,255}|npm_[A-Za-z0-9]{30,255}|pypi-[A-Za-z0-9_-]{30,255}|hf_[A-Za-z0-9]{20,255}|ya29\.[A-Za-z0-9_-]{20,255}|AIza[A-Za-z0-9_-]{35}|(?:AKIA|ASIA)[A-Z0-9]{16})\b|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b)/u;
const ACTIVITY_CATEGORIES = new Set([
  "thinking",
  "testing",
  "build",
  "repository",
  "research",
  "file-change",
  "tool",
  "agent",
  "waiting"
]);
const ACTIVITY_STATES = new Set(["started", "progress", "completed", "failed", "blocked"]);
const RUNNER_STATES = new Set(["connected", "stale", "offline"]);
const CODEX_STATES = new Set(["idle", "working", "waiting", "offline"]);
const CONVERSATION_ROLES = new Set(["operator", "codex"]);
const FLEET_PRECISION = new Set(["exact", "lower-bound", "unavailable"]);
const FLEET_CONNECTION = new Set(["connected", "unavailable"]);
const FLEET_SOURCE_FRESHNESS = new Set(["current", "delayed", "unavailable"]);
const FLEET_KINDS = new Set(["case", "profile"]);
const FLEET_STAGES = new Set([
  "governance", "offline-static", "offline-dynamic", "passive-research", "active-observation",
  "active-testing", "high-impact-controlled", "closure", "multiple", "idle", "unknown",
  "profile-questionnaire", "profile-operator-review", "profile-ready", "profile-superseded"
]);
const FLEET_STATES = new Set(["queued", "running", "waiting", "blocked", "succeeded", "failed", "cancelled", "unknown", "idle"]);
const FLEET_ATTENTION = new Set(["steady", "watch", "response-needed"]);
const FLEET_FRESHNESS = new Set(["current", "delayed", "unknown"]);
const FLEET_PROFILE_SECTIONS = new Set([
  "identity-objectives", "authority-sources", "actions-techniques", "limits-schedule", "scope-assets",
  "accounts-identities", "architecture-data-flows", "workflow-coverage", "data-evidence",
  "stops-escalation-cleanup", "reporting-disclosure", "ambiguities-attestation", "conditional-modules"
]);
const FLEET_CONTEXT_LABEL = /^[A-Za-z0-9][A-Za-z0-9 &().,'+_-]{0,79}$/u;
const FLEET_CONTEXT_URL = /(?:\b(?:https?|file|ftp):\/\/|\bwww\.)/iu;
const FLEET_CONTEXT_HOSTNAME = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/iu;
const FLEET_CONTEXT_IPV4 = /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/u;
const FLEET_CONTEXT_PATH = /(?:^|\s)(?:~?[\\/]|[A-Za-z]:[\\/]|\\\\)/u;
const FLEET_EVENT_CATEGORIES = new Set(["campaign", "workflow", "execution", "test", "evidence", "learning", "analysis", "tool", "operator", "system", "other"]);
const FLEET_EVENT_STATUSES = new Set(["queued", "running", "waiting", "blocked", "succeeded", "failed", "cancelled", "unknown"]);
const FLEET_TOKEN_AVAILABILITY = new Set(["exact", "estimated", "partial", "unavailable"]);
const TOKEN_PROVENANCE = new Set(["exact", "estimated", "unavailable"]);
const MAX_SAFE_SEQUENCE = Number.MAX_SAFE_INTEGER;

export class RemoteContractError extends Error {
  constructor(status, code, publicMessage) {
    super(publicMessage);
    this.name = "RemoteContractError";
    this.status = status;
    this.code = code;
    this.publicMessage = publicMessage;
  }
}

function fail(status, code, message) {
  throw new RemoteContractError(status, code, message);
}

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, expected) {
  if (!record(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function normalizeFleetContext(value, kind, stage) {
  const invalid = () => fail(400, "fleet-projection-invalid", "The remote fleet projection is invalid.");
  if (!exactKeys(value, ["label", "nextSection"])) invalid();
  let label = null;
  if (value.label !== null) {
    if (typeof value.label !== "string") invalid();
    label = value.label.normalize("NFC").trim();
    if (label !== value.label || !FLEET_CONTEXT_LABEL.test(label) || FLEET_CONTEXT_URL.test(label)
        || FLEET_CONTEXT_HOSTNAME.test(label) || FLEET_CONTEXT_IPV4.test(label)
        || FLEET_CONTEXT_PATH.test(label) || containsLikelyRemoteCredential(label)) invalid();
  }
  const nextSection = value.nextSection === null ? null
    : typeof value.nextSection === "string" && FLEET_PROFILE_SECTIONS.has(value.nextSection) ? value.nextSection : undefined;
  if (nextSection === undefined || kind === "case" && nextSection !== null
      || kind === "profile" && stage === "profile-questionnaire" && nextSection === null
      || kind === "profile" && stage !== "profile-questionnaire" && nextSection !== null) invalid();
  return Object.freeze({ label, nextSection });
}

function boundedInteger(value, minimum, maximum) {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}

function normalizeIdentifier(value, pattern, code, label) {
  if (typeof value !== "string" || !pattern.test(value)) {
    fail(400, code, `The ${label} is invalid.`);
  }
  return value;
}

function requestId(value) {
  return normalizeIdentifier(value, REQUEST_ID, "request-invalid", "request");
}

function commandId(value) {
  return normalizeIdentifier(value, COMMAND_ID, "command-invalid", "command");
}

function sessionRevision(value) {
  if (!boundedInteger(value, 1, 2_147_483_647)) {
    fail(409, "session-changed", "The remote cockpit session changed. Reload the cockpit.");
  }
  return value;
}

function normalizeTimestamp(value, code = "timestamp-invalid", label = "timestamp") {
  if (typeof value !== "string") fail(400, code, `The ${label} is invalid.`);
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    fail(400, code, `The ${label} is invalid.`);
  }
  return value;
}

function normalizeText(value, maximum, label, maximumBytes = 4_096, maximumLines = 12) {
  if (typeof value !== "string") fail(400, `${label}-invalid`, `The ${label} is invalid.`);
  const normalized = value.normalize("NFC").replace(/\r\n?/gu, "\n").trim();
  const length = [...normalized].length;
  if (length < 1 || length > maximum || Buffer.byteLength(normalized, "utf8") > maximumBytes
      || normalized.split("\n").length > maximumLines || CONTROL_CHARACTERS.test(normalized)) {
    fail(400, `${label}-invalid`, `The ${label} must be between 1 and ${maximum} characters.`);
  }
  return normalized;
}

export function containsLikelyRemoteCredential(value) {
  return typeof value === "string"
    && (SECRET_ASSIGNMENT.test(value) || AUTHORIZATION_TOKEN.test(value) || PRIVATE_KEY.test(value)
      || CREDENTIAL_URL.test(value) || SENSITIVE_HEADER.test(value) || STANDALONE_CREDENTIAL.test(value));
}

function rejectCredential(value) {
  if (containsLikelyRemoteCredential(value)) {
    fail(400, "credential-rejected", "Remove credentials or secrets before sending this value.");
  }
}

export function normalizeRemoteMessageRequest(value) {
  if (!exactKeys(value, ["apiVersion", "requestId", "sessionRevision", "message"])
      || value.apiVersion !== REMOTE_MESSAGE_VERSION) {
    fail(400, "message-request-invalid", "Reload the cockpit before sending that message.");
  }
  const message = normalizeText(value.message, MAX_REMOTE_MESSAGE_CHARACTERS, "message");
  rejectCredential(message);
  return Object.freeze({
    apiVersion: REMOTE_MESSAGE_VERSION,
    requestId: requestId(value.requestId),
    sessionRevision: sessionRevision(value.sessionRevision),
    message
  });
}

export function normalizeRemoteQuestionResponse(value) {
  if (!exactKeys(value, ["apiVersion", "requestId", "sessionRevision", "questionToken", "answers"])
      || value.apiVersion !== REMOTE_QUESTION_VERSION
      || typeof value.questionToken !== "string" || !QUESTION_TOKEN.test(value.questionToken)
      || !record(value.answers)) {
    fail(400, "question-response-invalid", "Reload the cockpit before answering that question.");
  }
  const entries = Object.entries(value.answers);
  if (entries.length < 1 || entries.length > 3) {
    fail(400, "question-response-invalid", "The remote question response is invalid.");
  }
  const answers = Object.create(null);
  for (const [id, selected] of entries) {
    if (!/^[a-z][a-z0-9_-]{0,63}$/u.test(id) || typeof selected !== "string") {
      fail(400, "question-response-invalid", "The remote question response is invalid.");
    }
    answers[id] = normalizeText(selected, 100, "answer");
    rejectCredential(answers[id]);
  }
  return Object.freeze({
    apiVersion: REMOTE_QUESTION_VERSION,
    requestId: requestId(value.requestId),
    sessionRevision: sessionRevision(value.sessionRevision),
    questionToken: value.questionToken,
    answers: Object.freeze(answers)
  });
}

export function normalizeRemoteCommandStatusRequest(value) {
  if (!exactKeys(value, ["apiVersion", "caseId", "sessionRevision", "commands"])
      || value.apiVersion !== REMOTE_COMMAND_STATUS_REQUEST_VERSION
      || !Array.isArray(value.commands) || value.commands.length < 1
      || value.commands.length > MAX_REMOTE_COMMAND_STATUS_REFERENCES) {
    fail(400, "command-status-request-invalid", "The remote command status request is invalid.");
  }
  const seenRequestIds = new Set();
  const seenCommandIds = new Set();
  const commands = value.commands.map((reference) => {
    if (!exactKeys(reference, ["requestId", "commandId"])) {
      fail(400, "command-status-request-invalid", "The remote command status request is invalid.");
    }
    const normalized = Object.freeze({
      requestId: requestId(reference.requestId),
      commandId: commandId(reference.commandId)
    });
    if (seenRequestIds.has(normalized.requestId) || seenCommandIds.has(normalized.commandId)) {
      fail(400, "command-status-request-invalid", "The remote command status request is invalid.");
    }
    seenRequestIds.add(normalized.requestId);
    seenCommandIds.add(normalized.commandId);
    return normalized;
  });
  return Object.freeze({
    apiVersion: REMOTE_COMMAND_STATUS_REQUEST_VERSION,
    caseId: normalizeIdentifier(value.caseId, CASE_ID, "case-invalid", "case"),
    sessionRevision: sessionRevision(value.sessionRevision),
    commands: Object.freeze(commands)
  });
}

export function remoteCommandStatusResponse(value) {
  if (!exactKeys(value, ["caseId", "sessionRevision", "commands"])
      || !Array.isArray(value.commands) || value.commands.length > MAX_REMOTE_COMMAND_STATUS_REFERENCES) {
    fail(500, "command-status-response-invalid", "The remote command status response is invalid.");
  }
  const commands = value.commands.map((status) => {
    if (!exactKeys(status, ["requestId", "commandId", "state"]) || !COMMAND_STATES.has(status.state)) {
      fail(500, "command-status-response-invalid", "The remote command status response is invalid.");
    }
    return Object.freeze({
      requestId: requestId(status.requestId),
      commandId: commandId(status.commandId),
      state: status.state
    });
  });
  return Object.freeze({
    apiVersion: REMOTE_COMMAND_STATUS_RESPONSE_VERSION,
    caseId: normalizeIdentifier(value.caseId, CASE_ID, "case-invalid", "case"),
    sessionRevision: sessionRevision(value.sessionRevision),
    commands: Object.freeze(commands)
  });
}

export function normalizeRemoteCommandBinding(value) {
  if (!exactKeys(value, ["operatorId", "browserSessionId", "caseId", "sessionRevision"])) {
    fail(400, "command-binding-invalid", "The remote command binding is invalid.");
  }
  return Object.freeze({
    operatorId: normalizeIdentifier(value.operatorId, PRINCIPAL_ID, "operator-invalid", "operator"),
    browserSessionId: normalizeIdentifier(value.browserSessionId, SESSION_OR_RUNNER_ID,
      "browser-session-invalid", "browser session"),
    caseId: normalizeIdentifier(value.caseId, CASE_ID, "case-invalid", "case"),
    sessionRevision: sessionRevision(value.sessionRevision)
  });
}

export function normalizeRemoteCaseBinding(value) {
  if (!exactKeys(value, ["operatorId", "caseId", "sessionRevision"])) {
    fail(400, "case-binding-invalid", "The remote case binding is invalid.");
  }
  return Object.freeze({
    operatorId: normalizeIdentifier(value.operatorId, PRINCIPAL_ID, "operator-invalid", "operator"),
    caseId: normalizeIdentifier(value.caseId, CASE_ID, "case-invalid", "case"),
    sessionRevision: sessionRevision(value.sessionRevision)
  });
}

function canonicalize(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!record(value)) fail(400, "payload-invalid", "The remote payload is invalid.");
  const result = Object.create(null);
  for (const key of Object.keys(value).sort()) result[key] = canonicalize(value[key]);
  return result;
}

export function digestRemotePayload(value) {
  const canonical = JSON.stringify(canonicalize(value));
  return crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}

export function remoteQueuedReceipt(value) {
  if (!exactKeys(value, ["requestId", "sessionRevision", "commandId", "sequence", "acceptedAt"])) {
    fail(500, "receipt-invalid", "The remote command receipt is invalid.");
  }
  if (!boundedInteger(value.sequence, 1, MAX_SAFE_SEQUENCE)) {
    fail(500, "receipt-invalid", "The remote command receipt is invalid.");
  }
  return Object.freeze({
    apiVersion: REMOTE_RECEIPT_VERSION,
    requestId: requestId(value.requestId),
    sessionRevision: sessionRevision(value.sessionRevision),
    commandId: commandId(value.commandId),
    sequence: value.sequence,
    status: "queued",
    acceptedAt: normalizeTimestamp(value.acceptedAt, "receipt-invalid", "receipt timestamp")
  });
}

export function normalizeRemoteCommandEvent(value) {
  if (!exactKeys(value, ["apiVersion", "sequence", "at", "requestId", "commandId", "state"])
      || value.apiVersion !== REMOTE_COMMAND_EVENT_VERSION
      || !boundedInteger(value.sequence, 1, MAX_SAFE_SEQUENCE)
      || !COMMAND_STATES.has(value.state)) {
    fail(500, "event-invalid", "The remote command event is invalid.");
  }
  return Object.freeze({
    apiVersion: REMOTE_COMMAND_EVENT_VERSION,
    sequence: value.sequence,
    at: normalizeTimestamp(value.at, "event-invalid", "event timestamp"),
    requestId: requestId(value.requestId),
    commandId: commandId(value.commandId),
    state: value.state
  });
}

function normalizeTokenCost(value) {
  if (!exactKeys(value, ["availability", "amountMicros", "unit"])
      || !new Set(["estimated", "unavailable"]).has(value.availability)) {
    fail(400, "state-projection-invalid", "The remote state projection is invalid.");
  }
  if (value.availability === "unavailable") {
    if (value.amountMicros !== null || value.unit !== null) {
      fail(400, "state-projection-invalid", "The remote state projection is invalid.");
    }
  } else if (!boundedInteger(value.amountMicros, 0, MAX_SAFE_SEQUENCE)
      || !new Set(["USD", "credits"]).has(value.unit)) {
    fail(400, "state-projection-invalid", "The remote state projection is invalid.");
  }
  return Object.freeze({ ...value });
}

function normalizeTokens(value) {
  if (value === null) return null;
  if (!exactKeys(value, [
    "availability", "source", "input", "cachedInput", "output", "reasoningOutput", "total", "contextWindow", "cost"
  ]) || value.availability !== "exact" || value.source !== "codex-notification") {
    fail(400, "state-projection-invalid", "The remote state projection is invalid.");
  }
  for (const key of ["input", "cachedInput", "output", "reasoningOutput", "total"]) {
    if (!boundedInteger(value[key], 0, MAX_SAFE_SEQUENCE)) {
      fail(400, "state-projection-invalid", "The remote state projection is invalid.");
    }
  }
  if (!(value.contextWindow === null || boundedInteger(value.contextWindow, 1, MAX_SAFE_SEQUENCE))) {
    fail(400, "state-projection-invalid", "The remote state projection is invalid.");
  }
  return Object.freeze({ ...value, cost: normalizeTokenCost(value.cost) });
}

function safeProjectionJson(value, label) {
  let nodes = 0;
  const inspect = (item, depth) => {
    nodes += 1;
    if (nodes > 5_000 || depth > 12) fail(400, `${label}-invalid`, `The ${label} is invalid.`);
    if (item === null || typeof item === "boolean") return;
    if (typeof item === "number") {
      if (!Number.isFinite(item) || !Number.isSafeInteger(item)) {
        fail(400, `${label}-invalid`, `The ${label} is invalid.`);
      }
      return;
    }
    if (typeof item === "string") {
      if ([...item].length > 4_000 || Buffer.byteLength(item, "utf8") > 16_000 || CONTROL_CHARACTERS.test(item)) {
        fail(400, `${label}-invalid`, `The ${label} is invalid.`);
      }
      return;
    }
    if (Array.isArray(item)) {
      if (item.length > 512) fail(400, `${label}-invalid`, `The ${label} is invalid.`);
      for (const nested of item) inspect(nested, depth + 1);
      return;
    }
    if (!record(item)) fail(400, `${label}-invalid`, `The ${label} is invalid.`);
    const keys = Object.keys(item);
    if (keys.length > 128) fail(400, `${label}-invalid`, `The ${label} is invalid.`);
    for (const key of keys) {
      if (!/^[A-Za-z][A-Za-z0-9_-]{0,63}$/u.test(key)) {
        fail(400, `${label}-invalid`, `The ${label} is invalid.`);
      }
      inspect(item[key], depth + 1);
    }
  };
  inspect(value, 0);
  let serialized;
  try {
    serialized = JSON.stringify(value);
  } catch {
    fail(400, `${label}-invalid`, `The ${label} is invalid.`);
  }
  if (Buffer.byteLength(serialized, "utf8") > MAX_REMOTE_PROJECTION_BYTES) {
    fail(413, `${label}-too-large`, `The ${label} is too large.`);
  }
  return JSON.parse(serialized);
}

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.freeze(value);
}

function normalizeConversation(value, observedAt) {
  if (!Array.isArray(value) || value.length > 48) {
    fail(400, "state-projection-invalid", "The remote state projection is invalid.");
  }
  let previous = -Infinity;
  return Object.freeze(value.map((entry) => {
    if (!exactKeys(entry, ["role", "text", "at"]) || !CONVERSATION_ROLES.has(entry.role)) {
      fail(400, "state-projection-invalid", "The remote state projection is invalid.");
    }
    const text = normalizeText(entry.text, 4_000, "conversation", 16_000, 24);
    rejectCredential(text);
    const at = normalizeTimestamp(entry.at, "state-projection-invalid", "conversation timestamp");
    const millis = Date.parse(at);
    if (millis < previous || millis > Date.parse(observedAt)) {
      fail(400, "state-projection-invalid", "The remote state projection is invalid.");
    }
    previous = millis;
    return Object.freeze({ role: entry.role, text, at });
  }));
}

function normalizePendingQuestions(value) {
  if (!Array.isArray(value) || value.length > 8) {
    fail(400, "state-projection-invalid", "The remote state projection is invalid.");
  }
  const tokens = new Set();
  return Object.freeze(value.map((pending) => {
    if (!exactKeys(pending, ["token", "questions"]) || typeof pending.token !== "string"
        || !DISPLAY_QUESTION_TOKEN.test(pending.token) || tokens.has(pending.token)
        || !Array.isArray(pending.questions) || pending.questions.length < 1 || pending.questions.length > 3) {
      fail(400, "state-projection-invalid", "The remote state projection is invalid.");
    }
    tokens.add(pending.token);
    const ids = new Set();
    const questions = pending.questions.map((question) => {
      if (!exactKeys(question, ["id", "header", "question", "options"])
          || typeof question.id !== "string" || !/^[a-z][a-z0-9_-]{0,63}$/u.test(question.id)
          || ids.has(question.id) || !Array.isArray(question.options)
          || question.options.length < 2 || question.options.length > 3) {
        fail(400, "state-projection-invalid", "The remote state projection is invalid.");
      }
      ids.add(question.id);
      const header = normalizeText(question.header, 24, "question header", 96, 1);
      const prompt = normalizeText(question.question, 500, "question", 2_000, 12);
      rejectCredential(header);
      rejectCredential(prompt);
      const labels = new Set();
      const options = question.options.map((option, index) => {
        if (!exactKeys(option, ["label", "description", "recommended"]) || typeof option.recommended !== "boolean"
            || option.recommended !== (index === 0)) {
          fail(400, "state-projection-invalid", "The remote state projection is invalid.");
        }
        const label = normalizeText(option.label, 100, "option label", 400, 2);
        const description = normalizeText(option.description, 300, "option description", 1_200, 6);
        if (labels.has(label)) fail(400, "state-projection-invalid", "The remote state projection is invalid.");
        labels.add(label);
        rejectCredential(label);
        rejectCredential(description);
        return Object.freeze({ label, description, recommended: option.recommended });
      });
      return Object.freeze({ id: question.id, header, question: prompt, options: Object.freeze(options) });
    });
    return Object.freeze({ token: pending.token, questions: Object.freeze(questions) });
  }));
}

export function normalizeRemoteStateProjection(value) {
  if (!exactKeys(value, [
    "apiVersion", "sessionRevision", "stateRevision", "observedAt", "validUntil", "runner", "codex",
    "tokens", "conversation", "pendingQuestions"
  ]) || value.apiVersion !== REMOTE_STATE_VERSION
      || !boundedInteger(value.stateRevision, 0, 2_147_483_647)
      || !exactKeys(value.runner, ["state", "observedAt"]) || !RUNNER_STATES.has(value.runner.state)
      || !exactKeys(value.codex, ["state"]) || !CODEX_STATES.has(value.codex.state)) {
    fail(400, "state-projection-invalid", "The remote state projection is invalid.");
  }
  const observedAt = normalizeTimestamp(value.observedAt, "state-projection-invalid", "state timestamp");
  const validUntil = normalizeTimestamp(value.validUntil, "state-projection-invalid", "state expiry");
  const runnerObservedAt = normalizeTimestamp(value.runner.observedAt,
    "state-projection-invalid", "runner timestamp");
  const observedMillis = Date.parse(observedAt);
  if (Date.parse(validUntil) <= observedMillis || Date.parse(validUntil) - observedMillis > 300_000
      || Date.parse(runnerObservedAt) > observedMillis) {
    fail(400, "state-projection-invalid", "The remote state projection is invalid.");
  }
  const normalized = Object.freeze({
    apiVersion: REMOTE_STATE_VERSION,
    sessionRevision: sessionRevision(value.sessionRevision),
    stateRevision: value.stateRevision,
    observedAt,
    validUntil,
    runner: Object.freeze({ state: value.runner.state, observedAt: runnerObservedAt }),
    codex: Object.freeze({ state: value.codex.state }),
    tokens: normalizeTokens(value.tokens),
    conversation: normalizeConversation(value.conversation, observedAt),
    pendingQuestions: normalizePendingQuestions(value.pendingQuestions)
  });
  safeProjectionJson(normalized, "state-projection");
  return normalized;
}

export function normalizeRemoteFleetProjection(value) {
  if (!exactKeys(value, [
    "apiVersion", "sessionRevision", "revision", "selectionEpoch", "observedAt", "receivedAt", "validUntil", "connection", "sourceFreshness",
    "coverage", "summary", "campaigns"
  ]) || value.apiVersion !== REMOTE_FLEET_VERSION
      || !boundedInteger(value.revision, 1, 2_147_483_647)
      || typeof value.selectionEpoch !== "string" || !/^[a-f0-9]{32}$/u.test(value.selectionEpoch)
      || !FLEET_CONNECTION.has(value.connection) || !FLEET_SOURCE_FRESHNESS.has(value.sourceFreshness)) {
    fail(400, "fleet-projection-invalid", "The remote fleet projection is invalid.");
  }
  const observedAt = value.observedAt === null
    ? null
    : normalizeTimestamp(value.observedAt, "fleet-projection-invalid", "fleet observation timestamp");
  const receivedAt = normalizeTimestamp(value.receivedAt, "fleet-projection-invalid", "fleet receipt timestamp");
  const validUntil = normalizeTimestamp(value.validUntil, "fleet-projection-invalid", "fleet expiry timestamp");
  if ((value.connection === "unavailable") !== (observedAt === null)
      || (observedAt !== null && Date.parse(observedAt) > Date.parse(receivedAt))
      || Date.parse(validUntil) <= Date.parse(receivedAt)
      || Date.parse(validUntil) - Date.parse(receivedAt) > 15_000) {
    fail(400, "fleet-projection-invalid", "The remote fleet projection is invalid.");
  }

  const invalid = () => fail(400, "fleet-projection-invalid", "The remote fleet projection is invalid.");
  const metric = (item) => {
    if (!exactKeys(item, ["value", "precision"]) || !FLEET_PRECISION.has(item.precision)) invalid();
    if (item.precision === "unavailable") {
      if (item.value !== null) invalid();
    } else if (!boundedInteger(item.value, 0, 1_000_000_000)) invalid();
    return Object.freeze({ ...item });
  };
  const scan = (item, profile = false) => {
    const keys = ["availability", "discovered", "scanned", "omitted", "invalid", "discoveredAtLeast",
      "omittedAtLeast", "complete", "truncated", ...(profile ? ["visible", "representedByCases"] : [])];
    if (!exactKeys(item, keys) || !new Set(["available", "unavailable"]).has(item.availability)
        || typeof item.discoveredAtLeast !== "boolean" || typeof item.omittedAtLeast !== "boolean"
        || typeof item.complete !== "boolean" || typeof item.truncated !== "boolean") invalid();
    const numeric = ["discovered", "scanned", "omitted", "invalid", ...(profile ? ["visible", "representedByCases"] : [])];
    if (item.availability === "unavailable") {
      if (numeric.some((key) => item[key] !== null) || item.discoveredAtLeast !== false
          || item.omittedAtLeast !== false || item.complete !== false || item.truncated !== true) invalid();
    } else if (numeric.some((key) => !boundedInteger(item[key], 0, 1_000_000_000))) invalid();
    return Object.freeze({ ...item });
  };
  const fleetTokens = (item, allowPartial = false) => {
    const allowed = allowPartial ? FLEET_TOKEN_AVAILABILITY : new Set(["exact", "estimated", "unavailable"]);
    if (!exactKeys(item, ["availability", "total"]) || !allowed.has(item.availability)) invalid();
    if (item.availability === "unavailable") {
      if (item.total !== null) invalid();
    } else if (!boundedInteger(item.total, 0, MAX_SAFE_SEQUENCE)) invalid();
    return Object.freeze({ ...item });
  };
  const tokenCost = (item) => {
    if (!exactKeys(item, ["availability", "amountMicros", "unit"])
        || !new Set(["estimated", "unavailable"]).has(item.availability)) invalid();
    if (item.availability === "unavailable") {
      if (item.amountMicros !== null || item.unit !== null) invalid();
    } else if (!boundedInteger(item.amountMicros, 0, MAX_SAFE_SEQUENCE)
        || !new Set(["USD", "credits"]).has(item.unit)) invalid();
    return Object.freeze({ ...item });
  };
  const hostTokens = (item) => {
    if (!exactKeys(item, ["availability", "input", "cachedInput", "output", "total", "cost"])
        || !TOKEN_PROVENANCE.has(item.availability)) invalid();
    const counters = ["input", "cachedInput", "output", "total"];
    if (item.availability === "unavailable") {
      if (counters.some((key) => item[key] !== null)) invalid();
    } else if (counters.some((key) => !(item[key] === null || boundedInteger(item[key], 0, MAX_SAFE_SEQUENCE)))
        || counters.every((key) => item[key] === null)) invalid();
    return Object.freeze({ ...item, cost: tokenCost(item.cost) });
  };

  if (!exactKeys(value.coverage, ["state", "cases", "profiles"]) || !FLEET_PRECISION.has(value.coverage.state)) invalid();
  const cases = scan(value.coverage.cases);
  const profiles = scan(value.coverage.profiles, true);

  const metricKeys = ["campaigns", "active", "waiting", "attention", "runningExecutions", "activeWorkflows",
    "runningAnalyses", "setupBlockers", "blockers"];
  if (!exactKeys(value.summary, [
    "campaigns", "active", "waiting", "attention", "profileAnswers", "runningExecutions", "activeWorkflows",
    "runningAnalyses", "setupBlockers", "blockers", "campaignTokens", "hostTokens"
  ])) invalid();
  const summary = Object.create(null);
  for (const key of metricKeys) summary[key] = metric(value.summary[key]);
  if (!exactKeys(value.summary.profileAnswers, ["answered", "total", "precision"])
      || !FLEET_PRECISION.has(value.summary.profileAnswers.precision)) invalid();
  if (value.summary.profileAnswers.precision === "unavailable") {
    if (value.summary.profileAnswers.answered !== null || value.summary.profileAnswers.total !== null) invalid();
  } else if (!boundedInteger(value.summary.profileAnswers.answered, 0, 1_000_000_000)
      || !boundedInteger(value.summary.profileAnswers.total, 0, 1_000_000_000)
      || value.summary.profileAnswers.answered > value.summary.profileAnswers.total) invalid();
  summary.profileAnswers = Object.freeze({ ...value.summary.profileAnswers });
  summary.campaignTokens = fleetTokens(value.summary.campaignTokens, true);
  summary.hostTokens = hostTokens(value.summary.hostTokens);

  if (!Array.isArray(value.campaigns) || value.campaigns.length > 64) invalid();
  const aliases = new Set();
  const campaigns = value.campaigns.map((item) => {
    const campaignKeys = ["alias", "context", "kind", "stage", "state", "progress", "attention", "freshness", "work", "tokens", "mirror", "pilot", "latestEvent"];
    if (!(exactKeys(item, campaignKeys) || exactKeys(item, campaignKeys.filter((key) => key !== "pilot")))
        || typeof item.alias !== "string" || !/^Campaign [1-9]\d{0,2}$/u.test(item.alias) || aliases.has(item.alias)
        || !FLEET_KINDS.has(item.kind) || !FLEET_STAGES.has(item.stage) || !FLEET_STATES.has(item.state)
        || !FLEET_ATTENTION.has(item.attention) || !FLEET_FRESHNESS.has(item.freshness)) invalid();
    aliases.add(item.alias);
    const context = normalizeFleetContext(item.context, item.kind, item.stage);
    let progress = null;
    if (item.kind === "case") {
      if (item.progress !== null || item.stage.startsWith("profile-")) invalid();
    } else {
      if (!item.stage.startsWith("profile-") || !exactKeys(item.progress, ["completed", "total", "percent"])
          || !boundedInteger(item.progress.completed, 0, 1_000_000_000)
          || !boundedInteger(item.progress.total, 0, 1_000_000_000)
          || item.progress.completed > item.progress.total
          || !(item.progress.percent === null || boundedInteger(item.progress.percent, 0, 100))) invalid();
      progress = Object.freeze({ ...item.progress });
    }
    if (!exactKeys(item.work, ["runningExecutions", "activeWorkflows", "runningAnalyses", "setupBlockers"])) invalid();
    const work = Object.create(null);
    for (const key of ["runningExecutions", "activeWorkflows", "runningAnalyses", "setupBlockers"]) {
      work[key] = metric(item.work[key]);
    }
    const mirror = validateExecutionMirror(item.mirror, { isUnsafeText: containsLikelyRemoteCredential });
    const pilot = item.pilot === undefined ? unavailablePilotProjection("missing") : validatePilotProjection(item.pilot);
    if (!mirror || !pilot || !exactKeys(item.latestEvent, ["availability", "category", "status", "at"])) invalid();
    const latestEvent = item.latestEvent.availability === "unavailable"
      && item.latestEvent.category === null && item.latestEvent.status === null && item.latestEvent.at === null
      ? Object.freeze({ ...item.latestEvent })
      : item.latestEvent.availability === "available" && FLEET_EVENT_CATEGORIES.has(item.latestEvent.category)
        && FLEET_EVENT_STATUSES.has(item.latestEvent.status) && normalizeTimestamp(
          item.latestEvent.at, "fleet-projection-invalid", "fleet event timestamp"
        ) ? Object.freeze({ ...item.latestEvent }) : null;
    if (!latestEvent || latestEvent.availability === "available" && observedAt !== null
        && Date.parse(latestEvent.at) > Date.parse(observedAt)) invalid();
    if (observedAt !== null && mirror.attempts.some((attempt) => Date.parse(attempt.updatedAt) > Date.parse(observedAt))) invalid();
    return Object.freeze({
      ...item,
      context,
      progress,
      work: Object.freeze(work),
      tokens: fleetTokens(item.tokens),
      mirror,
      pilot,
      latestEvent
    });
  });
  const setupBlockerTotal = campaigns
    .filter((item) => item.kind === "profile" && item.work.setupBlockers.precision !== "unavailable")
    .reduce((total, item) => total + item.work.setupBlockers.value, 0);
  if (campaigns.some((item) => item.kind === "case" && item.work.setupBlockers.precision !== "unavailable"
      && item.work.setupBlockers.value !== 0)
      || campaigns.some((item) => item.kind === "profile" && item.stage !== "profile-operator-review"
        && item.work.setupBlockers.precision !== "unavailable" && item.work.setupBlockers.value !== 0)
      || campaigns.some((item) => item.kind === "profile" && item.stage === "profile-operator-review"
        && (item.work.setupBlockers.precision === "unavailable" || item.work.setupBlockers.value < 1))
      || summary.setupBlockers.precision !== "unavailable" && summary.setupBlockers.value !== setupBlockerTotal
      || summary.blockers.precision !== "unavailable" && summary.blockers.value !== setupBlockerTotal
        + campaigns.filter((item) => item.kind === "case" && item.state === "blocked").length) invalid();
  if (value.connection === "connected" && campaigns.some((item) => item.pilot.availability === "available"
      && (Date.parse(item.pilot.observedAt) > Date.parse(observedAt)
        || Date.parse(validUntil) > Date.parse(item.pilot.validUntil)))) invalid();
  if (value.connection === "unavailable" && (value.coverage.state !== "unavailable" || campaigns.length !== 0
      || Object.values(summary).some((item) => item?.precision && item.precision !== "unavailable"))) invalid();

  const copy = safeProjectionJson({
    apiVersion: REMOTE_FLEET_VERSION,
    sessionRevision: sessionRevision(value.sessionRevision),
    revision: value.revision,
    selectionEpoch: value.selectionEpoch,
    observedAt,
    receivedAt,
    validUntil,
    connection: value.connection,
    sourceFreshness: value.sourceFreshness,
    coverage: Object.freeze({ state: value.coverage.state, cases, profiles }),
    summary: Object.freeze(summary),
    campaigns: Object.freeze(campaigns)
  }, "fleet-projection");
  return deepFreeze(copy);
}

export function sanitizeRemoteActivityEvent(value, sequence, at = new Date()) {
  if (!exactKeys(value, ["category", "state", "completed", "total", "tokens"])
      || !ACTIVITY_CATEGORIES.has(value.category) || !ACTIVITY_STATES.has(value.state)
      || !boundedInteger(sequence, 1, MAX_SAFE_SEQUENCE) || !(at instanceof Date) || !Number.isFinite(at.getTime())) {
    return null;
  }
  const indeterminate = value.completed === null && value.total === null;
  const determinate = boundedInteger(value.completed, 0, 999_999)
    && boundedInteger(value.total, 1, 999_999) && value.completed <= value.total;
  if (!indeterminate && !determinate) return null;
  let tokens = null;
  if (value.tokens !== null) {
    if (!exactKeys(value.tokens, ["total", "contextWindow"])
        || !boundedInteger(value.tokens.total, 0, 1_000_000_000)
        || !(value.tokens.contextWindow === null
          || boundedInteger(value.tokens.contextWindow, 1, 1_000_000_000))) return null;
    tokens = Object.freeze({ total: value.tokens.total, contextWindow: value.tokens.contextWindow });
  }
  return Object.freeze({
    apiVersion: REMOTE_ACTIVITY_EVENT_VERSION,
    sequence,
    at: at.toISOString(),
    category: value.category,
    state: value.state,
    completed: determinate ? value.completed : null,
    total: determinate ? value.total : null,
    tokens
  });
}

export const remoteContractInternals = Object.freeze({
  ACTIVITY_CATEGORIES: Object.freeze([...ACTIVITY_CATEGORIES]),
  ACTIVITY_STATES: Object.freeze([...ACTIVITY_STATES]),
  CASE_ID,
  COMMAND_ID,
  PRINCIPAL_ID,
  REQUEST_ID,
  SESSION_OR_RUNNER_ID,
  exactKeys,
  normalizeTimestamp,
  safeProjectionJson
});
