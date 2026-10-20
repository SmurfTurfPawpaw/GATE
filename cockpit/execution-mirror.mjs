import { assertNoLikelySecret } from "../src/lib/text.mjs";

const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F-\u009F\u061C\u200B\u200E\u200F\u2028-\u202E\u2060-\u206F\uFEFF\u{E0000}-\u{E007F}]/u;
const PRIVATE_REFERENCE = /\b(?:event|evidence|private|commit|file):\/\/\S+/iu;
const PRIVATE_IDENTIFIER = /\b(?:xmf|xrun|amf|arun|wreq|wpa|wtest|wxr|wle|lcap)_[a-f0-9]{32}\b/u;
const POSIX_ABSOLUTE_PATH = /(?:^|[^A-Za-z0-9_./\\-])\/(?!\/)[^\s"'`<>\])},;]*/u;
const WINDOWS_DRIVE_PATH = /(?:^|[^A-Za-z0-9_./\\-])[A-Za-z]:[\\/][^\s"'`<>\])},;]*/u;
const WINDOWS_UNC_PATH = /(?:^|[^A-Za-z0-9_./\\-])\\\\[^\s\\"'<>]+\\[^\s"'`<>\])},;]*/u;
const PROTOCOL_RELATIVE_PATH = /(?:^|[^A-Za-z0-9_+.:/\\-])\/\/[^\s"'`<>\])},;]*/u;
const LOW_ENTROPY_CREDENTIAL = /(?:["'](?:api[_-]?key|access[_-]?token|auth(?:entication|orization)?|bearer|client[_-]?secret|credential|key|password|passwd|secret|session[_-]?(?:id|key|token)|token)["']\s*:\s*(?!["']?\[secret withheld\]["']?(?:$|[\s,}\]]))(?:(?:"[^"]*"|'[^']*'|[^,\s}\]]+))|\b(?:auth(?:entication|orization)?|bearer|credential|key|secret|token)\b\s*[:=]\s*(?!["']?\[secret withheld\]["']?(?:$|[\s,}\]]))(?:(?:"[^"]*"|'[^']*'|\S+))|(?:^|\s)--?(?:api[_-]?key|access[_-]?token|auth(?:entication|orization)?|bearer|client[_-]?secret|credential|key|password|passwd|secret|session[_-]?(?:id|key|token)|token)(?:\s+|=)(?!["']?\[secret withheld\]["']?(?:$|[\s,}\]]))(?:(?:"[^"]*"|'[^']*'|\S+))|\bcurl\b[^\n]*?\s(?:-u|--user)(?:\s+|=)(?!["']?\[secret withheld\]["']?(?:$|[\s,}\]]))(?:(?:"[^"]*"|'[^']*'|\S+)))/iu;

const MIRROR_REASONS = new Set([
  "disabled",
  "not-applicable",
  "no-attempts",
  "source-unavailable"
]);
const ATTEMPT_STATES = new Set([
  "queued",
  "running",
  "stopping",
  "succeeded",
  "failed",
  "cancelled",
  "blocked",
  "unknown"
]);
const ENTRY_STATES = new Set([
  "queued",
  "running",
  "waiting",
  "blocked",
  "succeeded",
  "failed",
  "cancelled",
  "unknown"
]);
const ENTRY_CHANNELS = new Set([
  "work-order",
  "command",
  "stdout",
  "stderr",
  "browser",
  "tool",
  "file",
  "test",
  "agent",
  "system",
  "result"
]);
const ENTRY_FIDELITY = new Set(["exact", "redacted", "summarized", "unavailable"]);
const TOKEN_AVAILABILITY = new Set(["exact", "estimated", "partial", "unavailable"]);
const COUNT_AVAILABILITY = new Set(["exact", "estimated", "unavailable"]);
const MAX_ATTEMPTS = 8;
const MAX_ENTRIES = 8;
const MAX_ENTRY_TEXT = 240;
const MAX_PHASE_TEXT = 80;
const MAX_TOOL_TEXT = 64;
const MAX_ACTION_TEXT = 64;

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, expected) {
  if (!record(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function timestamp(value) {
  if (typeof value !== "string") return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? value : null;
}

function integer(value, minimum = 0) {
  return Number.isSafeInteger(value) && value >= minimum ? value : null;
}

function attemptAlias(value) {
  const match = typeof value === "string" ? /^Attempt ([1-9][0-9]{0,15})$/u.exec(value) : null;
  return match && Number.isSafeInteger(Number(match[1])) ? value : null;
}

function containsLikelySecret(value) {
  try {
    assertNoLikelySecret(value, "execution mirror text");
    return false;
  } catch {
    return true;
  }
}

function boundedText(value, maximum, isUnsafeText) {
  if (typeof value !== "string" || value.length === 0 || value !== value.normalize("NFC")
      || [...value].length > maximum || Buffer.byteLength(value, "utf8") > maximum * 4
      || CONTROL_CHARACTERS.test(value) || PRIVATE_REFERENCE.test(value) || PRIVATE_IDENTIFIER.test(value)
      || POSIX_ABSOLUTE_PATH.test(value) || WINDOWS_DRIVE_PATH.test(value) || WINDOWS_UNC_PATH.test(value)
      || PROTOCOL_RELATIVE_PATH.test(value)
      || LOW_ENTROPY_CREDENTIAL.test(value) || containsLikelySecret(value) || isUnsafeText(value)) return null;
  return value;
}

function nullableText(value, maximum, isUnsafeText) {
  return value === null ? null : boundedText(value, maximum, isUnsafeText);
}

function unavailableCounter() {
  return Object.freeze({ availability: "unavailable", value: null });
}

function normalizeCounter(value) {
  if (!exactKeys(value, ["availability", "value"]) || !COUNT_AVAILABILITY.has(value.availability)) return null;
  if (value.availability === "unavailable") return value.value === null ? unavailableCounter() : null;
  return integer(value.value) === null ? null : Object.freeze({ availability: value.availability, value: value.value });
}

function normalizeTokens(value) {
  if (!exactKeys(value, ["availability", "total"]) || !TOKEN_AVAILABILITY.has(value.availability)) return null;
  if (value.availability === "unavailable") {
    return value.total === null ? Object.freeze({ availability: "unavailable", total: null }) : null;
  }
  return integer(value.total) === null ? null : Object.freeze({ availability: value.availability, total: value.total });
}

function normalizeCost(value) {
  if (!exactKeys(value, ["availability", "amountMicros", "unit"])
      || !new Set(["estimated", "unavailable"]).has(value.availability)) return null;
  if (value.availability === "unavailable") {
    return value.amountMicros === null && value.unit === null
      ? Object.freeze({ availability: "unavailable", amountMicros: null, unit: null })
      : null;
  }
  return integer(value.amountMicros) === null || !new Set(["USD", "credits"]).has(value.unit)
    ? null
    : Object.freeze({ availability: "estimated", amountMicros: value.amountMicros, unit: value.unit });
}

function normalizeProgress(value) {
  if (!exactKeys(value, ["availability", "completed", "total", "percent"])
      || !new Set(["exact", "unavailable"]).has(value.availability)) return null;
  if (value.availability === "unavailable") {
    return value.completed === null && value.total === null && value.percent === null
      ? Object.freeze({ availability: "unavailable", completed: null, total: null, percent: null })
      : null;
  }
  if (integer(value.completed) === null || integer(value.total, 1) === null || value.completed > value.total
      || integer(value.percent) === null || value.percent > 100
      || value.percent !== Math.round(value.completed / value.total * 100)) return null;
  return Object.freeze({ availability: "exact", completed: value.completed, total: value.total, percent: value.percent });
}

function normalizeUsage(value) {
  if (!exactKeys(value, ["tokens", "cost", "requests", "retries", "toolRuns"])) return null;
  const tokens = normalizeTokens(value.tokens);
  const cost = normalizeCost(value.cost);
  const requests = normalizeCounter(value.requests);
  const retries = normalizeCounter(value.retries);
  const toolRuns = normalizeCounter(value.toolRuns);
  if (!tokens || !cost || !requests || !retries || !toolRuns
      || toolRuns.availability !== "exact" || toolRuns.value !== 1) return null;
  return Object.freeze({ tokens, cost, requests, retries, toolRuns });
}

function normalizeEntries(value, updatedAt, isUnsafeText) {
  if (!Array.isArray(value) || value.length > MAX_ENTRIES) return null;
  let previousSequence = 0;
  let previousAt = -Infinity;
  const maximumAt = Date.parse(updatedAt);
  const entries = [];
  for (const entry of value) {
    if (!exactKeys(entry, ["sequence", "at", "channel", "state", "fidelity", "truncated", "text"])
        || integer(entry.sequence, 1) === null || entry.sequence <= previousSequence
        || !ENTRY_CHANNELS.has(entry.channel) || !ENTRY_STATES.has(entry.state)
        || !ENTRY_FIDELITY.has(entry.fidelity) || typeof entry.truncated !== "boolean") return null;
    const at = timestamp(entry.at);
    const text = boundedText(entry.text, MAX_ENTRY_TEXT, isUnsafeText);
    const atMs = at === null ? NaN : Date.parse(at);
    if (at === null || text === null || atMs < previousAt || atMs > maximumAt) return null;
    previousSequence = entry.sequence;
    previousAt = atMs;
    entries.push(Object.freeze({
      sequence: entry.sequence,
      at,
      channel: entry.channel,
      state: entry.state,
      fidelity: entry.fidelity,
      truncated: entry.truncated,
      text
    }));
  }
  return Object.freeze(entries);
}

function normalizeAttempt(value, isUnsafeText) {
  if (!exactKeys(value, [
    "alias", "kind", "state", "phase", "tool", "action", "startedAt", "finishedAt", "updatedAt",
    "elapsedMs", "progress", "usage", "entries"
  ]) || attemptAlias(value.alias) === null
      || value.kind !== "supervised-execution" || !ATTEMPT_STATES.has(value.state)) return null;
  const phase = nullableText(value.phase, MAX_PHASE_TEXT, isUnsafeText);
  const tool = nullableText(value.tool, MAX_TOOL_TEXT, isUnsafeText);
  const action = nullableText(value.action, MAX_ACTION_TEXT, isUnsafeText);
  const startedAt = value.startedAt === null ? null : timestamp(value.startedAt);
  const finishedAt = value.finishedAt === null ? null : timestamp(value.finishedAt);
  const updatedAt = timestamp(value.updatedAt);
  const elapsedMs = value.elapsedMs === null ? null : integer(value.elapsedMs);
  if (value.phase !== null && phase === null || value.tool !== null && tool === null
      || value.action !== null && action === null || value.startedAt !== null && startedAt === null
      || value.finishedAt !== null && finishedAt === null || updatedAt === null
      || value.elapsedMs !== null && elapsedMs === null
      || startedAt !== null && Date.parse(startedAt) > Date.parse(updatedAt)
      || finishedAt !== null && (Date.parse(finishedAt) > Date.parse(updatedAt)
        || startedAt !== null && Date.parse(finishedAt) < Date.parse(startedAt))) return null;
  const progress = normalizeProgress(value.progress);
  const usage = normalizeUsage(value.usage);
  const entries = normalizeEntries(value.entries, updatedAt, isUnsafeText);
  return !progress || !usage || !entries ? null : Object.freeze({
    alias: value.alias,
    kind: "supervised-execution",
    state: value.state,
    phase,
    tool,
    action,
    startedAt,
    finishedAt,
    updatedAt,
    elapsedMs,
    progress,
    usage,
    entries
  });
}

export function unavailableExecutionMirror(reason = "disabled") {
  if (!MIRROR_REASONS.has(reason)) throw new Error("invalid execution mirror reason");
  return Object.freeze({ availability: "unavailable", reason, attempts: Object.freeze([]) });
}

export function validateExecutionMirror(value, options = {}) {
  const isUnsafeText = options.isUnsafeText ?? (() => false);
  if (typeof isUnsafeText !== "function" || !exactKeys(value, ["availability", "reason", "attempts"])
      || !new Set(["available", "unavailable"]).has(value.availability)
      || !Array.isArray(value.attempts) || value.attempts.length > MAX_ATTEMPTS) return null;
  if (value.availability === "unavailable") {
    return MIRROR_REASONS.has(value.reason) && value.attempts.length === 0
      ? unavailableExecutionMirror(value.reason)
      : null;
  }
  if (value.reason !== null || value.attempts.length === 0) return null;
  const aliases = new Set();
  const attempts = [];
  for (const item of value.attempts) {
    const attempt = normalizeAttempt(item, isUnsafeText);
    if (!attempt || aliases.has(attempt.alias)) return null;
    aliases.add(attempt.alias);
    attempts.push(attempt);
  }
  return Object.freeze({ availability: "available", reason: null, attempts: Object.freeze(attempts) });
}

export const executionMirrorInternals = Object.freeze({
  MAX_ACTION_TEXT,
  MAX_ATTEMPTS,
  MAX_ENTRIES,
  MAX_ENTRY_TEXT,
  MAX_PHASE_TEXT,
  MAX_TOOL_TEXT
});

