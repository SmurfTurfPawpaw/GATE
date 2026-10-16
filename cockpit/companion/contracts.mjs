import crypto from "node:crypto";

export const LOCAL_BRIDGE_VERSION = "gate.local-cockpit-bridge/v1";
export const LOCAL_MESSAGE_VERSION = "gate.local-message-request/v1";
export const LOCAL_QUESTION_VERSION = "gate.local-question-response/v1";
export const LOCAL_RECEIPT_VERSION = "gate.local-cockpit-receipt/v1";
export const LOCAL_EVENT_VERSION = "gate.local-cockpit-event/v1";

export const MAX_MESSAGE_CHARACTERS = 1_000;
export const MAX_BODY_BYTES = 16 * 1024;

const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/u;
const QUESTION_TOKEN = /^q_[A-Za-z0-9_-]{32,128}$/u;
const CONTROL_CHARACTERS = /[\u0000-\u0009\u000B\u000C\u000E-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/u;
const SECRET_ASSIGNMENT = /(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|private[_-]?key|session[_-]?(?:id|key|token))\s*[:=]\s*\S+/iu;
const BEARER_TOKEN = /\bbearer\s+[A-Za-z0-9._~+/-]{16,}={0,2}\b/iu;
const PRIVATE_KEY = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u;

const EVENT_CATEGORIES = new Set([
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
const EVENT_STATES = new Set(["started", "progress", "completed", "failed", "blocked"]);

export class CompanionContractError extends Error {
  constructor(status, code, publicMessage) {
    super(publicMessage);
    this.name = "CompanionContractError";
    this.status = status;
    this.code = code;
    this.publicMessage = publicMessage;
  }
}

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, expected) {
  if (!record(value)) return false;
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return actual.length === sortedExpected.length
    && actual.every((key, index) => key === sortedExpected[index]);
}

function requestId(value) {
  if (typeof value !== "string" || !REQUEST_ID.test(value)) {
    throw new CompanionContractError(400, "request-invalid", "The local companion rejected an invalid request.");
  }
  return value;
}

function sessionRevision(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2_147_483_647) {
    throw new CompanionContractError(409, "session-changed", "The local companion session changed. Reload the cockpit.");
  }
  return value;
}

function normalizeText(value, maximum, label) {
  if (typeof value !== "string") {
    throw new CompanionContractError(400, `${label}-invalid`, `The ${label} is invalid.`);
  }
  const normalized = value.normalize("NFC").replace(/\r\n?/gu, "\n").trim();
  const length = [...normalized].length;
  if (length < 1 || length > maximum || Buffer.byteLength(normalized, "utf8") > 4_096
      || normalized.split("\n").length > 12 || CONTROL_CHARACTERS.test(normalized)) {
    throw new CompanionContractError(400, `${label}-invalid`, `The ${label} must be between 1 and ${maximum} characters.`);
  }
  return normalized;
}

export function containsLikelyCredential(value) {
  return typeof value === "string"
    && (SECRET_ASSIGNMENT.test(value) || BEARER_TOKEN.test(value) || PRIVATE_KEY.test(value));
}

export function normalizeMessageRequest(value) {
  if (!exactKeys(value, ["apiVersion", "requestId", "sessionRevision", "message"])
      || value.apiVersion !== LOCAL_MESSAGE_VERSION) {
    throw new CompanionContractError(400, "message-request-invalid", "Reload the cockpit before sending that message.");
  }
  const message = normalizeText(value.message, MAX_MESSAGE_CHARACTERS, "message");
  if (containsLikelyCredential(message)) {
    throw new CompanionContractError(400, "credential-rejected", "Remove credentials or secrets before sending this message.");
  }
  return Object.freeze({
    apiVersion: LOCAL_MESSAGE_VERSION,
    requestId: requestId(value.requestId),
    sessionRevision: sessionRevision(value.sessionRevision),
    message
  });
}

export function normalizeQuestionResponse(value) {
  if (!exactKeys(value, ["apiVersion", "requestId", "sessionRevision", "questionToken", "answers"])
      || value.apiVersion !== LOCAL_QUESTION_VERSION
      || typeof value.questionToken !== "string" || !QUESTION_TOKEN.test(value.questionToken)
      || !record(value.answers)) {
    throw new CompanionContractError(400, "question-response-invalid", "Reload the cockpit before answering that question.");
  }
  const answers = {};
  const entries = Object.entries(value.answers);
  if (entries.length < 1 || entries.length > 3) {
    throw new CompanionContractError(400, "question-response-invalid", "The local question response is invalid.");
  }
  for (const [id, selected] of entries) {
    if (!/^[a-z][a-z0-9_-]{0,63}$/u.test(id) || typeof selected !== "string") {
      throw new CompanionContractError(400, "question-response-invalid", "The local question response is invalid.");
    }
    answers[id] = normalizeText(selected, 100, "answer");
  }
  return Object.freeze({
    apiVersion: LOCAL_QUESTION_VERSION,
    requestId: requestId(value.requestId),
    sessionRevision: sessionRevision(value.sessionRevision),
    questionToken: value.questionToken,
    answers: Object.freeze(answers)
  });
}

export function acceptedReceipt(id) {
  return Object.freeze({
    apiVersion: LOCAL_RECEIPT_VERSION,
    requestId: requestId(id),
    status: "accepted"
  });
}

export function questionToken() {
  return `q_${crypto.randomBytes(32).toString("base64url")}`;
}

export function sanitizeActivityEvent(value, sequence, at = new Date()) {
  if (!record(value) || !EVENT_CATEGORIES.has(value.category) || !EVENT_STATES.has(value.state)) return null;
  const determinate = Number.isSafeInteger(value.completed) && value.completed >= 0
    && Number.isSafeInteger(value.total) && value.total > 0 && value.completed <= value.total;
  const tokens = record(value.tokens)
    && Number.isSafeInteger(value.tokens.total) && value.tokens.total >= 0
    && (value.tokens.contextWindow === null
      || (Number.isSafeInteger(value.tokens.contextWindow) && value.tokens.contextWindow > 0))
    ? Object.freeze({ total: value.tokens.total, contextWindow: value.tokens.contextWindow })
    : null;
  return Object.freeze({
    apiVersion: LOCAL_EVENT_VERSION,
    sequence,
    at: at.toISOString(),
    category: value.category,
    state: value.state,
    completed: determinate ? value.completed : null,
    total: determinate ? value.total : null,
    tokens
  });
}

export const companionContractInternals = Object.freeze({
  EVENT_CATEGORIES: Object.freeze([...EVENT_CATEGORIES]),
  EVENT_STATES: Object.freeze([...EVENT_STATES]),
  exactKeys
});
