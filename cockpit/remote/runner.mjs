import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { unavailableExecutionMirror, validateExecutionMirror } from "../execution-mirror.mjs";

import {
  REMOTE_COMMAND_VERSION,
  REMOTE_FLEET_VERSION,
  REMOTE_MESSAGE_VERSION,
  REMOTE_QUESTION_VERSION,
  REMOTE_STATE_VERSION,
  MAX_REMOTE_PROJECTION_BYTES,
  containsLikelyRemoteCredential,
  digestRemotePayload,
  normalizeRemoteFleetProjection,
  normalizeRemoteMessageRequest,
  normalizeRemoteQuestionResponse,
  normalizeRemoteStateProjection,
  remoteContractInternals,
  sanitizeRemoteActivityEvent
} from "./contracts.mjs";
import { createRunnerRequestSigner } from "./runner-auth.mjs";

const JOURNAL_VERSION = "gate.remote-runner-journal/v1";
const HEARTBEAT_VERSION = "gate.remote-runner-heartbeat/v1";
const LEASE_REQUEST_VERSION = "gate.remote-runner-lease-request/v1";
const LEASE_RESPONSE_VERSION = "gate.remote-runner-lease/v1";
const TRANSITION_VERSION = "gate.remote-runner-transition/v1";
const ACTIVITY_UPLOAD_VERSION = "gate.remote-runner-activity/v1";
const ACK_VERSION = "gate.remote-runner-ack/v1";
const LOCAL_FLEET_VERSION = "gate.local-fleet/v3";

const RUNNER_API_PREFIX = "/api/runner/v1";
const JSON_CONTENT_TYPE = "application/json";
const JSON_RESPONSE_CONTENT_TYPE = "application/json; charset=utf-8";
const MAX_RESPONSE_BYTES = 128 * 1024;
const MAX_JOURNAL_BYTES = 2 * 1024 * 1024;
const MAX_JOURNAL_ENTRIES = 2_048;
const MAX_PROJECTION_NODES = 5_000;
const MAX_FOOTPRINT_NODES = 100_000;
const PROJECTION_REVISION_RESERVATION = 64;
const MAX_ACTIVITY_PER_CYCLE = 16;
const TERMINAL_STATES = new Set(["completed", "failed"]);
const COMMAND_ID = remoteContractInternals.COMMAND_ID;
const SESSION_OR_RUNNER_ID = remoteContractInternals.SESSION_OR_RUNNER_ID;
const CASE_ID = remoteContractInternals.CASE_ID;
const LEASE_ID = /^lease_[A-Za-z0-9_-]{16,128}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const WITHHELD_REMOTE_CONTENT = "[Content withheld from remote cockpit]";
const TRUNCATED_REMOTE_CONTENT = "\n[Remote cockpit truncated this message]";
const MAX_PROJECTED_CONVERSATION_ENTRIES = 12;
const MAX_PROJECTED_PENDING_QUESTIONS = 1;
const LEASE_RECOVERY_SKEW_MS = 5 * 60_000;

const DEFAULTS = Object.freeze({
  requestTimeoutMs: 15_000,
  pollIntervalMs: 1_000,
  heartbeatIntervalMs: 10_000,
  projectionIntervalMs: 2_000,
  fleetIntervalMs: 5_000,
  stateTtlMs: 30_000,
  adapterConnectTimeoutMs: 15_000,
  backoffBaseMs: 500,
  backoffMaxMs: 30_000
});

export class RemoteRunnerError extends Error {
  constructor(code, publicMessage, status = null) {
    super(publicMessage);
    this.name = "RemoteRunnerError";
    this.code = code;
    this.publicMessage = publicMessage;
    this.status = status;
  }
}

function fail(code, message, status = null) {
  throw new RemoteRunnerError(code, message, status);
}

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, expected) {
  return remoteContractInternals.exactKeys(value, expected);
}

function integer(value, minimum, maximum, label) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function identifier(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) throw new TypeError(`${label} is invalid`);
  return value;
}

function timestamp(value, label) {
  if (typeof value !== "string") fail("response-invalid", `The remote ${label} is invalid.`);
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    fail("response-invalid", `The remote ${label} is invalid.`);
  }
  return value;
}

function nowMilliseconds(clock) {
  const value = clock();
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError("runner clock must return epoch milliseconds");
  return value;
}

function normalizeOrigin(value) {
  let parsed;
  try {
    parsed = value instanceof URL ? new URL(value.href) : new URL(value);
  } catch {
    throw new TypeError("control-plane URL must be an HTTPS origin");
  }
  if (parsed.protocol !== "https:" || !parsed.hostname || parsed.username || parsed.password
      || parsed.search || parsed.hash || parsed.pathname !== "/") {
    throw new TypeError("control-plane URL must be an HTTPS origin");
  }
  return parsed.origin;
}

function assertOwnerOnly(stat, label) {
  if ((stat.mode & 0o077) !== 0) throw new TypeError(`${label} must be owner-only`);
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
    throw new TypeError(`${label} must be owned by the current operator`);
  }
}

function prepareJournalDirectory(value) {
  if (typeof value !== "string" || !path.isAbsolute(value) || path.normalize(value) !== value
      || value.includes("\0")) {
    throw new TypeError("runner journal directory must be an absolute normalized path");
  }
  let stat;
  try {
    stat = fs.lstatSync(value);
  } catch {
    throw new TypeError("runner journal directory is unavailable");
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new TypeError("runner journal directory must be a real directory");
  }
  let real;
  try {
    real = fs.realpathSync.native(value);
  } catch {
    throw new TypeError("runner journal directory is unavailable");
  }
  if (real !== value) throw new TypeError("runner journal directory must not traverse symbolic links");
  assertOwnerOnly(stat, "runner journal directory");
  return value;
}

function journalEntry(value) {
  if (!exactKeys(value, ["commandId", "payloadSha256", "acceptedAt", "terminalState"])
      || typeof value.commandId !== "string" || !COMMAND_ID.test(value.commandId)
      || typeof value.payloadSha256 !== "string" || !SHA256.test(value.payloadSha256)
      || !(value.terminalState === null || TERMINAL_STATES.has(value.terminalState))) {
    fail("journal-invalid", "The remote runner journal is invalid.");
  }
  timestamp(value.acceptedAt, "runner journal timestamp");
  return Object.freeze({ ...value });
}

class RunnerJournal {
  #caseId;
  #entries = new Map();
  #file;
  #directory;
  #runnerId;
  #sessionRevision;
  #projectionCurrent = { state: 0, fleet: 0 };
  #projectionHighWater = { state: 0, fleet: 0 };
  #writeCounter = 0;

  constructor({ directory, runnerId, caseId, sessionRevision }) {
    this.#directory = prepareJournalDirectory(directory);
    this.#file = path.join(this.#directory, "remote-runner-journal.json");
    this.#runnerId = runnerId;
    this.#caseId = caseId;
    this.#sessionRevision = sessionRevision;
    this.#load();
  }

  get(commandId) {
    return this.#entries.get(commandId) ?? null;
  }

  get hasUnresolvedCommand() {
    return [...this.#entries.values()].some((entry) => entry.terminalState === null);
  }

  accept(commandId, payloadSha256, at) {
    const current = this.#entries.get(commandId);
    if (current) {
      if (current.payloadSha256 !== payloadSha256) {
        fail("journal-conflict", "The remote runner journal conflicts with the leased command.");
      }
      return Object.freeze({ entry: current, replayed: true });
    }
    const previousEntries = new Map(this.#entries);
    while (this.#entries.size >= MAX_JOURNAL_ENTRIES) {
      const oldestTerminal = [...this.#entries].find(([, entry]) => entry.terminalState !== null);
      if (!oldestTerminal) fail("journal-full", "The remote runner journal is full.");
      this.#entries.delete(oldestTerminal[0]);
    }
    const entry = Object.freeze({ commandId, payloadSha256, acceptedAt: at, terminalState: null });
    this.#entries.set(commandId, entry);
    try {
      this.#write();
    } catch (error) {
      this.#entries = previousEntries;
      throw error;
    }
    return Object.freeze({ entry, replayed: false });
  }

  terminal(commandId, state) {
    const current = this.#entries.get(commandId);
    if (!current || !TERMINAL_STATES.has(state)) {
      fail("journal-invalid", "The remote runner journal transition is invalid.");
    }
    if (current.terminalState === state) return current;
    if (current.terminalState !== null) {
      fail("journal-conflict", "The remote runner journal transition conflicts with its terminal state.");
    }
    const next = Object.freeze({ ...current, terminalState: state });
    this.#entries.set(commandId, next);
    try {
      this.#write();
    } catch (error) {
      this.#entries.set(commandId, current);
      throw error;
    }
    return next;
  }

  nextProjectionRevision(kind) {
    if (!new Set(["state", "fleet"]).has(kind)) {
      fail("journal-invalid", "The remote runner projection counter is invalid.");
    }
    if (this.#projectionCurrent[kind] >= this.#projectionHighWater[kind]) {
      const previous = this.#projectionHighWater[kind];
      if (previous >= 2_147_483_647) {
        fail("journal-full", "The remote runner projection counter is exhausted.");
      }
      this.#projectionHighWater[kind] = Math.min(2_147_483_647,
        previous + PROJECTION_REVISION_RESERVATION);
      try {
        this.#write();
      } catch (error) {
        this.#projectionHighWater[kind] = previous;
        throw error;
      }
    }
    this.#projectionCurrent[kind] += 1;
    return this.#projectionCurrent[kind];
  }

  #document() {
    return {
      apiVersion: JOURNAL_VERSION,
      runnerId: this.#runnerId,
      caseId: this.#caseId,
      sessionRevision: this.#sessionRevision,
      projectionRevisions: {
        state: this.#projectionHighWater.state,
        fleet: this.#projectionHighWater.fleet
      },
      accepted: [...this.#entries.values()]
    };
  }

  #load() {
    let stat;
    try {
      stat = fs.lstatSync(this.#file);
    } catch (error) {
      if (error?.code === "ENOENT") {
        this.#write();
        return;
      }
      fail("journal-unavailable", "The remote runner journal is unavailable.");
    }
    if (!stat.isFile() || stat.isSymbolicLink()) fail("journal-invalid", "The remote runner journal is invalid.");
    assertOwnerOnly(stat, "remote runner journal");
    if (stat.size > MAX_JOURNAL_BYTES) fail("journal-too-large", "The remote runner journal is too large.");
    let parsed;
    try {
      parsed = JSON.parse(fs.readFileSync(this.#file, "utf8"));
    } catch {
      fail("journal-invalid", "The remote runner journal is invalid.");
    }
    if (!exactKeys(parsed, [
      "apiVersion", "runnerId", "caseId", "sessionRevision", "projectionRevisions", "accepted"
    ])
        || parsed.apiVersion !== JOURNAL_VERSION || parsed.runnerId !== this.#runnerId
        || parsed.caseId !== this.#caseId || parsed.sessionRevision !== this.#sessionRevision
        || !exactKeys(parsed.projectionRevisions, ["state", "fleet"])
        || !Number.isSafeInteger(parsed.projectionRevisions.state) || parsed.projectionRevisions.state < 0
        || parsed.projectionRevisions.state > 2_147_483_647
        || !Number.isSafeInteger(parsed.projectionRevisions.fleet) || parsed.projectionRevisions.fleet < 0
        || parsed.projectionRevisions.fleet > 2_147_483_647
        || !Array.isArray(parsed.accepted) || parsed.accepted.length > MAX_JOURNAL_ENTRIES) {
      fail("journal-binding-invalid", "The remote runner journal does not match this runner.");
    }
    this.#projectionHighWater = { ...parsed.projectionRevisions };
    this.#projectionCurrent = { ...parsed.projectionRevisions };
    for (const raw of parsed.accepted) {
      const entry = journalEntry(raw);
      if (this.#entries.has(entry.commandId)) fail("journal-invalid", "The remote runner journal is invalid.");
      this.#entries.set(entry.commandId, entry);
    }
  }

  #write() {
    const body = `${JSON.stringify(this.#document())}\n`;
    if (Buffer.byteLength(body, "utf8") > MAX_JOURNAL_BYTES) {
      fail("journal-too-large", "The remote runner journal is too large.");
    }
    const suffix = `${process.pid}.${++this.#writeCounter}.${crypto.randomBytes(8).toString("hex")}`;
    const temporary = path.join(this.#directory, `.remote-runner-journal.${suffix}.tmp`);
    let descriptor;
    try {
      descriptor = fs.openSync(temporary,
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0), 0o600);
      fs.writeFileSync(descriptor, body, "utf8");
      fs.fsyncSync(descriptor);
      fs.closeSync(descriptor);
      descriptor = undefined;
      fs.renameSync(temporary, this.#file);
      const directoryDescriptor = fs.openSync(this.#directory, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0));
      try { fs.fsyncSync(directoryDescriptor); } finally { fs.closeSync(directoryDescriptor); }
    } catch {
      if (descriptor !== undefined) {
        try { fs.closeSync(descriptor); } catch {}
      }
      try { fs.rmSync(temporary, { force: true }); } catch {}
      fail("journal-write-failed", "The remote runner journal could not be saved.");
    }
  }
}

function boundedRemoteText(value, maximumCharacters, maximumBytes, truncatedSuffix, maximumLines) {
  if (typeof value !== "string") return value;
  const normalized = value.normalize("NFC");
  if ([...normalized].length <= maximumCharacters && Buffer.byteLength(normalized, "utf8") <= maximumBytes
      && normalized.split("\n").length <= maximumLines) {
    return normalized;
  }
  const suffixCharacters = [...truncatedSuffix].length;
  const suffixBytes = Buffer.byteLength(truncatedSuffix, "utf8");
  const prefixCharacterLimit = Math.max(0, maximumCharacters - suffixCharacters);
  const prefixByteLimit = Math.max(0, maximumBytes - suffixBytes);
  let result = "";
  let characters = 0;
  let bytes = 0;
  let lines = truncatedSuffix.split("\n").length;
  for (const character of normalized) {
    const nextBytes = Buffer.byteLength(character, "utf8");
    if (characters >= prefixCharacterLimit || bytes + nextBytes > prefixByteLimit
        || (character === "\n" && lines >= maximumLines)) break;
    if (character === "\n") lines += 1;
    result += character;
    characters += 1;
    bytes += nextBytes;
  }
  return `${result}${truncatedSuffix}`;
}

function cloneConversation(value) {
  if (!Array.isArray(value)) return [];
  const omitted = Math.max(0, value.length - (MAX_PROJECTED_CONVERSATION_ENTRIES - 1));
  const selected = omitted > 0 ? value.slice(-(MAX_PROJECTED_CONVERSATION_ENTRIES - 1)) : value;
  const projected = selected.map((entry) => ({
    role: entry?.role,
    text: containsLikelyRemoteCredential(entry?.text)
      ? WITHHELD_REMOTE_CONTENT
      : boundedRemoteText(entry?.text, 1_000, 2_000, TRUNCATED_REMOTE_CONTENT, 24),
    at: entry?.at
  }));
  if (omitted > 0) {
    projected.unshift({
      role: "codex",
      text: `[${omitted} earlier conversation ${omitted === 1 ? "entry was" : "entries were"} omitted from the remote cockpit]`,
      at: selected[0]?.at
    });
  }
  return projected;
}

function questionFitsRemoteText(pending) {
  const fits = (value, characters, bytes, lines) => typeof value === "string"
    && [...value.normalize("NFC")].length <= characters
    && Buffer.byteLength(value.normalize("NFC"), "utf8") <= bytes
    && value.split("\n").length <= lines;
  return Array.isArray(pending?.questions) && pending.questions.every((question) =>
    fits(question?.header, 24, 96, 1) && fits(question?.question, 500, 2_000, 12)
    && Array.isArray(question?.options) && question.options.every((option) =>
      fits(option?.label, 100, 400, 2) && fits(option?.description, 300, 1_200, 6)));
}

function clonePendingQuestions(value) {
  if (!Array.isArray(value)) return [];
  return value.filter(questionFitsRemoteText).filter((pending) => {
    return !pending.questions.some((question) => containsLikelyRemoteCredential(question?.header)
      || containsLikelyRemoteCredential(question?.question)
      || (Array.isArray(question?.options) && question.options.some((option) =>
        containsLikelyRemoteCredential(option?.label) || containsLikelyRemoteCredential(option?.description))));
  }).slice(0, MAX_PROJECTED_PENDING_QUESTIONS).map((pending) => ({
    token: pending?.token,
    questions: pending.questions.map((question) => ({
      id: question?.id,
      header: question?.header,
      question: question?.question,
      options: question.options.map((option) => ({
        label: option?.label,
        description: option?.description,
        recommended: option?.recommended
      }))
    }))
  }));
}

export function projectRemoteState(privateState, {
  sessionRevision,
  stateRevision = privateState?.stateRevision,
  now,
  ttlMs = DEFAULTS.stateTtlMs
} = {}) {
  if (!record(privateState)) fail("state-invalid", "The local companion state is unavailable.");
  const observedMs = now instanceof Date ? now.getTime() : now;
  if (!Number.isSafeInteger(observedMs) || observedMs < 1) throw new TypeError("state projection clock is invalid");
  integer(ttlMs, 1_000, 300_000, "state projection lifetime");
  const observedAt = new Date(observedMs).toISOString();
  const connected = privateState.connected === true;
  const turn = privateState.turn;
  const codexState = !connected ? "offline" : turn === "working" ? "working" : turn === "waiting" ? "waiting" : "idle";
  return normalizeRemoteStateProjection({
    apiVersion: REMOTE_STATE_VERSION,
    sessionRevision,
    stateRevision,
    observedAt,
    validUntil: new Date(observedMs + ttlMs).toISOString(),
    runner: { state: "connected", observedAt },
    codex: { state: codexState },
    tokens: privateState.tokens ?? null,
    conversation: cloneConversation([
      ...(Array.isArray(privateState.conversation) ? privateState.conversation : []),
      ...(Array.isArray(privateState.pendingQuestions)
        && privateState.pendingQuestions.some((pending) => !questionFitsRemoteText(pending))
        ? [{ role: "codex", text: "[Oversized questions omitted from remote cockpit; answer locally]", at: observedAt }]
        : [])
    ]),
    pendingQuestions: clonePendingQuestions(privateState.pendingQuestions)
  });
}

function projectionFootprint(value) {
  let nodes = 0;
  const seen = new WeakSet();
  const visit = (item, depth) => {
    nodes += 1;
    if (nodes > MAX_FOOTPRINT_NODES || depth > 12) {
      fail("fleet-projection-invalid", "The local fleet projection is invalid.");
    }
    if (item === null || typeof item !== "object") return;
    if (seen.has(item)) fail("fleet-projection-invalid", "The local fleet projection is invalid.");
    seen.add(item);
    for (const nested of Array.isArray(item) ? item : Object.values(item)) visit(nested, depth + 1);
  };
  visit(value, 0);
  return Object.freeze({ bytes: Buffer.byteLength(JSON.stringify(value), "utf8"), nodes });
}

function attemptPriority(left, right) {
  const active = (attempt) => new Set(["running", "stopping"]).has(attempt.state) ? 0 : 1;
  return active(left.attempt) - active(right.attempt)
    || Date.parse(right.attempt.updatedAt) - Date.parse(left.attempt.updatedAt)
    || left.attempt.alias.localeCompare(right.attempt.alias)
    || left.campaignIndex - right.campaignIndex;
}

function projectedAttemptState(value) {
  return value === "stopping" ? "running" : value;
}

function trimmedMirror(state) {
  if (state.source.availability === "unavailable") return state.source;
  const selected = state.source.attempts
    .filter((attempt) => state.selected.has(attempt.alias))
    .map((attempt) => ({ attempt, campaignIndex: state.campaignIndex }))
    .sort(attemptPriority)
    .map(({ attempt }) => attempt);
  if (selected.length === 0) return unavailableExecutionMirror("source-unavailable");
  const allAttemptsSelected = selected.length === state.source.attempts.length;
  const allEntriesSelected = selected.every((attempt) => (state.entryCounts.get(attempt.alias) || 0) >= attempt.entries.length);
  if (allAttemptsSelected && allEntriesSelected) return state.source;

  const markerHolder = selected[0];
  const attempts = selected.map((attempt) => {
    const requested = Math.min(state.entryCounts.get(attempt.alias) || 0, attempt.entries.length);
    const keep = attempt === markerHolder ? Math.min(requested, 7) : requested;
    const entries = keep === 0 ? [] : attempt.entries.slice(-keep);
    return { ...attempt, entries };
  });
  const omittedAttempts = state.source.attempts.length - attempts.length;
  const retainedEntries = attempts.reduce((total, attempt) => total + attempt.entries.length, 0);
  const sourceEntries = state.source.attempts.reduce((total, attempt) => total + attempt.entries.length, 0);
  const omittedEntries = sourceEntries - retainedEntries;
  const holder = attempts[0];
  const retained = holder.entries.map((entry, index) => ({ ...entry, sequence: index + 1 }));
  retained.push({
    sequence: retained.length + 1,
    at: holder.updatedAt,
    channel: "system",
    state: projectedAttemptState(holder.state),
    fidelity: "summarized",
    truncated: true,
    text: `Remote mirror omitted ${omittedAttempts} attempt${omittedAttempts === 1 ? "" : "s"} and ${omittedEntries} entr${omittedEntries === 1 ? "y" : "ies"} to stay within 128 KiB.`
  });
  attempts[0] = { ...holder, entries: retained };
  return { availability: "available", reason: null, attempts };
}

function projectionWithMirrorBudget(candidate) {
  if (!Array.isArray(candidate.campaigns)) return normalizeRemoteFleetProjection(candidate);
  const observedMs = candidate.observedAt === null ? null : Date.parse(candidate.observedAt);
  const states = candidate.campaigns.map((campaign, campaignIndex) => {
    const source = validateExecutionMirror(campaign?.mirror, { isUnsafeText: containsLikelyRemoteCredential });
    if (!source || observedMs !== null && source.attempts.some((attempt) => Date.parse(attempt.updatedAt) > observedMs)) {
      fail("fleet-invalid", "The local fleet projection is unavailable.");
    }
    return { campaignIndex, source, selected: new Set(), entryCounts: new Map() };
  });
  const base = {
    ...candidate,
    campaigns: candidate.campaigns.map((campaign, index) => ({
      ...campaign,
      mirror: states[index].source.availability === "available"
        ? unavailableExecutionMirror("source-unavailable")
        : states[index].source
    }))
  };
  const normalizedBase = normalizeRemoteFleetProjection(base);
  const validatedCandidate = {
    ...normalizedBase,
    campaigns: normalizedBase.campaigns.map((campaign, index) => ({
      ...campaign,
      mirror: states[index].source
    }))
  };
  const fullFootprint = projectionFootprint(validatedCandidate);
  if (fullFootprint.bytes <= MAX_REMOTE_PROJECTION_BYTES && fullFootprint.nodes <= MAX_PROJECTION_NODES) {
    return normalizeRemoteFleetProjection(validatedCandidate);
  }
  const baseFootprint = projectionFootprint(normalizedBase);
  const mirrorFootprints = normalizedBase.campaigns.map((campaign) => projectionFootprint(campaign.mirror));
  let totalBytes = baseFootprint.bytes;
  let totalNodes = baseFootprint.nodes;
  const consider = (state, nextMirror) => {
    const next = projectionFootprint(nextMirror);
    const previous = mirrorFootprints[state.campaignIndex];
    const nextBytes = totalBytes - previous.bytes + next.bytes;
    const nextNodes = totalNodes - previous.nodes + next.nodes;
    if (nextBytes > MAX_REMOTE_PROJECTION_BYTES || nextNodes > MAX_PROJECTION_NODES) return false;
    totalBytes = nextBytes;
    totalNodes = nextNodes;
    mirrorFootprints[state.campaignIndex] = next;
    return true;
  };

  const attempts = states.flatMap((state) => state.source.availability === "available"
    ? state.source.attempts.map((attempt) => ({ state, attempt, campaignIndex: state.campaignIndex }))
    : []).sort(attemptPriority);
  for (const { state, attempt } of attempts) {
    if (state.selected.size > 0) continue;
    state.selected.add(attempt.alias);
    if (!consider(state, trimmedMirror(state))) state.selected.delete(attempt.alias);
  }
  for (const { state, attempt } of attempts) {
    if (state.selected.has(attempt.alias)) continue;
    state.selected.add(attempt.alias);
    if (!consider(state, trimmedMirror(state))) state.selected.delete(attempt.alias);
  }
  for (const { state, attempt } of attempts) {
    if (!state.selected.has(attempt.alias)) continue;
    for (let retained = 1; retained <= attempt.entries.length; retained += 1) {
      state.entryCounts.set(attempt.alias, retained);
      if (!consider(state, trimmedMirror(state))) {
        state.entryCounts.set(attempt.alias, retained - 1);
        break;
      }
    }
  }
  const projected = {
    ...normalizedBase,
    campaigns: normalizedBase.campaigns.map((campaign, index) => ({ ...campaign, mirror: trimmedMirror(states[index]) }))
  };
  const footprint = projectionFootprint(projected);
  if (footprint.bytes > MAX_REMOTE_PROJECTION_BYTES || footprint.nodes > MAX_PROJECTION_NODES) {
    fail("fleet-projection-too-large", "The remote fleet projection is too large.", 413);
  }
  return normalizeRemoteFleetProjection(projected);
}

export function projectRemoteFleet(localFleet, { sessionRevision, revision = localFleet?.revision } = {}) {
  if (!record(localFleet) || localFleet.apiVersion !== LOCAL_FLEET_VERSION) {
    fail("fleet-invalid", "The local fleet projection is unavailable.");
  }
  const candidate = {
    apiVersion: REMOTE_FLEET_VERSION,
    sessionRevision,
    revision,
    selectionEpoch: localFleet.selectionEpoch,
    observedAt: localFleet.observedAt,
    receivedAt: localFleet.receivedAt,
    validUntil: localFleet.validUntil,
    connection: localFleet.connection,
    sourceFreshness: localFleet.sourceFreshness,
    coverage: localFleet.coverage,
    summary: localFleet.summary,
    campaigns: localFleet.campaigns
  };
  return projectionWithMirrorBudget(candidate);
}

function normalizeLeaseResponse(value, configuration) {
  if (!exactKeys(value, ["apiVersion", "command"]) || value.apiVersion !== LEASE_RESPONSE_VERSION) {
    fail("lease-response-invalid", "The remote lease response is invalid.");
  }
  if (value.command === null) return null;
  const command = value.command;
  if (!exactKeys(command, [
    "commandId", "kind", "payloadSha256", "payload", "issuedAt", "expiresAt", "lease"
  ]) || typeof command.commandId !== "string" || !COMMAND_ID.test(command.commandId)
      || !new Set(["message", "question"]).has(command.kind)
      || typeof command.payloadSha256 !== "string" || !SHA256.test(command.payloadSha256)
      || !exactKeys(command.lease, ["leaseId", "expiresAt"])
      || typeof command.lease.leaseId !== "string" || !LEASE_ID.test(command.lease.leaseId)) {
    fail("lease-response-invalid", "The remote lease response is invalid.");
  }
  const issuedAt = timestamp(command.issuedAt, "command issue timestamp");
  const expiresAt = timestamp(command.expiresAt, "command expiry");
  const leaseExpiresAt = timestamp(command.lease.expiresAt, "command lease expiry");
  if (Date.parse(expiresAt) <= Date.parse(issuedAt) || Date.parse(leaseExpiresAt) > Date.parse(expiresAt)) {
    fail("lease-response-invalid", "The remote lease response is invalid.");
  }
  const payload = command.kind === "message"
    ? normalizeRemoteMessageRequest(command.payload)
    : normalizeRemoteQuestionResponse(command.payload);
  if (payload.apiVersion !== (command.kind === "message" ? REMOTE_MESSAGE_VERSION : REMOTE_QUESTION_VERSION)
      || payload.sessionRevision !== configuration.sessionRevision
      || digestRemotePayload(payload) !== command.payloadSha256) {
    fail("lease-response-invalid", "The remote lease response is invalid.");
  }
  return Object.freeze({
    apiVersion: REMOTE_COMMAND_VERSION,
    commandId: command.commandId,
    kind: command.kind,
    payloadSha256: command.payloadSha256,
    payload,
    issuedAt,
    expiresAt,
    lease: Object.freeze({ leaseId: command.lease.leaseId, expiresAt: leaseExpiresAt })
  });
}

function validateAck(value) {
  if (!exactKeys(value, ["apiVersion", "acceptedAt"]) || value.apiVersion !== ACK_VERSION) {
    fail("ack-invalid", "The remote runner acknowledgement is invalid.");
  }
  timestamp(value.acceptedAt, "runner acknowledgement timestamp");
  return value;
}

async function defaultDelay(milliseconds, signal) {
  if (signal?.aborted) return;
  await new Promise((resolve) => {
    const finish = () => {
      signal?.removeEventListener("abort", abort);
      resolve();
    };
    const timer = setTimeout(finish, milliseconds);
    const abort = () => {
      clearTimeout(timer);
      finish();
    };
    signal?.addEventListener("abort", abort, { once: true });
  });
}

function cancelReader(reader) {
  try {
    const cancelled = reader.cancel();
    cancelled?.catch?.(() => {});
  } catch {}
}

async function boundedResponseBody(response, signal) {
  const length = response.headers?.get?.("content-length");
  if (length !== null && length !== undefined && (!/^(?:0|[1-9][0-9]*)$/u.test(length)
      || Number(length) > MAX_RESPONSE_BYTES)) {
    fail("response-too-large", "The remote runner response is too large.");
  }
  const aborted = Symbol("response-aborted");
  let onAbort;
  const abortPromise = signal
    ? new Promise((resolve) => {
        onAbort = () => resolve(aborted);
        if (signal.aborted) resolve(aborted);
        else signal.addEventListener("abort", onAbort, { once: true });
      })
    : null;
  const wait = async (operation) => {
    const value = abortPromise ? await Promise.race([operation, abortPromise]) : await operation;
    if (value === aborted) fail("request-failed", "The remote control plane is unavailable.");
    return value;
  };
  if (response.body?.getReader) {
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    try {
      while (true) {
        const item = await wait(reader.read());
        if (item.done) break;
        if (!(item.value instanceof Uint8Array)) fail("response-invalid", "The remote runner response is invalid.");
        size += item.value.byteLength;
        if (size > MAX_RESPONSE_BYTES) {
          cancelReader(reader);
          fail("response-too-large", "The remote runner response is too large.");
        }
        chunks.push(Buffer.from(item.value));
      }
      return Buffer.concat(chunks, size).toString("utf8");
    } finally {
      if (signal && onAbort) signal.removeEventListener("abort", onAbort);
      if (signal?.aborted) cancelReader(reader);
    }
  }
  try {
    const bytes = Buffer.from(await wait(response.arrayBuffer()));
    if (bytes.byteLength > MAX_RESPONSE_BYTES) fail("response-too-large", "The remote runner response is too large.");
    return bytes.toString("utf8");
  } finally {
    if (signal && onAbort) signal.removeEventListener("abort", onAbort);
  }
}

function retryableCycleError(error) {
  if (!(error instanceof RemoteRunnerError)) return false;
  if (error.code === "request-rejected") return error.status === 429 || (error.status ?? 0) >= 500;
  return new Set([
    "request-failed", "content-type-invalid", "response-too-large", "response-invalid", "ack-invalid",
    "lease-response-invalid"
  ]).has(error.code);
}

function compatibleAdapter(value) {
  return value && typeof value.privateState === "function" && typeof value.sendMessage === "function"
    && typeof value.answerQuestion === "function" && value.activityStore
    && typeof value.activityStore.since === "function";
}

function offlineAdapterState(previous = null) {
  return Object.freeze({
    apiVersion: "gate.local-companion-state/v1",
    sessionRevision: Number.isSafeInteger(previous?.sessionRevision) ? previous.sessionRevision : 1,
    stateRevision: Number.isSafeInteger(previous?.stateRevision) ? previous.stateRevision : 0,
    observedAt: typeof previous?.observedAt === "string" ? previous.observedAt : new Date(0).toISOString(),
    connected: false,
    turn: "idle",
    tokens: null,
    conversation: Array.isArray(previous?.conversation) ? previous.conversation : [],
    pendingQuestions: []
  });
}

export class RemoteCockpitRunner {
  #active = false;
  #activityCursor = 0;
  #adapter;
  #adapterClosedListener = null;
  #adapterConnectGeneration = 0;
  #adapterFactory;
  #adapterLastState = null;
  #adapterLastConnectedState = null;
  #adapterNextAttemptAt = Number.NEGATIVE_INFINITY;
  #adapterConnecting = null;
  #adapterRecoveryCandidate = null;
  #adapterRecoveryFailure = null;
  #adapterRecoveryFailures = 0;
  #adapterRecoveryPromise = null;
  #adapterUnavailable = false;
  #clock;
  #closeAdapter;
  #configuration;
  #conversationDispatchBlocked = false;
  #currentFetchController = null;
  #delay;
  #executing = false;
  #failureCount = 0;
  #fetch;
  #fleetProvider;
  #journal;
  #lastFleetAt = Number.NEGATIVE_INFINITY;
  #lastHeartbeatAt = Number.NEGATIVE_INFINITY;
  #lastStateAt = Number.NEGATIVE_INFINITY;
  #leaseSuppressedUntil = Number.NEGATIVE_INFINITY;
  #projectionLifecycleRevision = 0;
  #random;
  #runPromise = null;
  #signer;
  #stopController = new AbortController();
  #stopRequested = false;

  constructor(options = {}) {
    if (!record(options)) throw new TypeError("runner options must be an object");
    const runnerId = identifier(options.runnerId, SESSION_OR_RUNNER_ID, "runner identifier");
    const caseId = identifier(options.caseId, CASE_ID, "case identifier");
    const sessionRevision = integer(options.sessionRevision, 1, 2_147_483_647, "session revision");
    const adapter = options.adapter;
    if (!compatibleAdapter(adapter)) {
      throw new TypeError("runner adapter is incompatible");
    }
    this.#clock = options.clock ?? Date.now;
    this.#random = options.random ?? Math.random;
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#delay = options.delay ?? defaultDelay;
    this.#fleetProvider = options.fleetProvider ?? null;
    this.#adapterFactory = options.adapterFactory ?? null;
    this.#closeAdapter = options.closeAdapter !== false;
    if (typeof this.#clock !== "function" || typeof this.#random !== "function"
        || typeof this.#fetch !== "function" || typeof this.#delay !== "function"
        || !(this.#fleetProvider === null || typeof this.#fleetProvider === "function")
        || !(this.#adapterFactory === null || typeof this.#adapterFactory === "function")) {
      throw new TypeError("runner dependency is invalid");
    }
    const controlPlaneOrigin = normalizeOrigin(options.controlPlaneUrl);
    const configuration = {
      controlPlaneOrigin,
      runnerId,
      caseId,
      sessionRevision,
      requestTimeoutMs: integer(options.requestTimeoutMs ?? DEFAULTS.requestTimeoutMs, 250, 120_000,
        "request timeout"),
      pollIntervalMs: integer(options.pollIntervalMs ?? DEFAULTS.pollIntervalMs, 10, 60_000, "poll interval"),
      heartbeatIntervalMs: integer(options.heartbeatIntervalMs ?? DEFAULTS.heartbeatIntervalMs,
        100, 300_000, "heartbeat interval"),
      projectionIntervalMs: integer(options.projectionIntervalMs ?? DEFAULTS.projectionIntervalMs,
        100, 300_000, "projection interval"),
      fleetIntervalMs: integer(options.fleetIntervalMs ?? DEFAULTS.fleetIntervalMs,
        100, 300_000, "fleet interval"),
      stateTtlMs: integer(options.stateTtlMs ?? DEFAULTS.stateTtlMs, 1_000, 300_000,
        "state projection lifetime"),
      adapterConnectTimeoutMs: integer(options.adapterConnectTimeoutMs ?? DEFAULTS.adapterConnectTimeoutMs,
        250, 120_000, "adapter connect timeout"),
      backoffBaseMs: integer(options.backoffBaseMs ?? DEFAULTS.backoffBaseMs, 10, 60_000, "backoff base"),
      backoffMaxMs: integer(options.backoffMaxMs ?? DEFAULTS.backoffMaxMs, 10, 300_000, "backoff maximum")
    };
    if (configuration.backoffMaxMs < configuration.backoffBaseMs) {
      throw new TypeError("backoff maximum must not be less than its base");
    }
    this.#configuration = Object.freeze(configuration);
    this.#adapter = adapter;
    this.#signer = createRunnerRequestSigner({
      runnerId,
      privateKey: options.privateKey,
      now: this.#clock,
      nonceFactory: options.nonceFactory
    });
    this.#journal = new RunnerJournal({
      directory: options.journalDirectory,
      runnerId,
      caseId,
      sessionRevision
    });
    this.#conversationDispatchBlocked = this.#journal.hasUnresolvedCommand;
    this.#attachAdapterClosedListener(adapter);
  }

  get running() {
    return this.#active;
  }

  start() {
    if (this.#runPromise) return this.#runPromise;
    if (this.#stopRequested) throw new Error("remote runner is stopped");
    this.#active = true;
    this.#runPromise = this.#loop().finally(() => { this.#active = false; });
    return this.#runPromise;
  }

  async stop() {
    if (this.#stopRequested) return this.#runPromise;
    this.#stopRequested = true;
    this.#adapterConnectGeneration += 1;
    this.#stopController.abort();
    if (!this.#executing) this.#currentFetchController?.abort();
    if (this.#adapterConnecting && typeof this.#adapterConnecting.close === "function") {
      void Promise.resolve(this.#adapterConnecting.close()).catch(() => {});
    }
    if (this.#adapterRecoveryCandidate && typeof this.#adapterRecoveryCandidate.close === "function") {
      void Promise.resolve(this.#adapterRecoveryCandidate.close()).catch(() => {});
    }
    if (this.#runPromise) await this.#runPromise;
  }

  async #loop() {
    try {
      try {
        if (typeof this.#adapter.connect === "function") {
          await this.#adapter.connect();
        }
        const initialState = this.#readAdapterState();
        if (!record(initialState) || initialState.connected !== true
            || this.#adapterLastConnectedState !== initialState) {
          this.#markAdapterUnavailable(this.#adapter, true);
        } else {
          this.#adapterUnavailable = false;
          this.#adapterLastState = initialState;
        }
      } catch {
        // A local conversation adapter may be unavailable at process start.
        // Keep the signed observer/fleet channel alive, but do not attempt an
        // automatic replacement without a trusted connected-idle snapshot.
        this.#markAdapterUnavailable(this.#adapter, true);
      }
      while (!this.#stopRequested) {
        try {
          await this.#adoptRecoveredAdapter();
          await this.#cycle();
          this.#failureCount = 0;
          if (!this.#stopRequested) {
            await this.#delay(this.#configuration.pollIntervalMs, this.#stopController.signal);
          }
        } catch (error) {
          if (this.#stopRequested) break;
          if (error instanceof RemoteRunnerError && error.code === "adapter-unavailable") {
            this.#markAdapterUnavailable();
            this.#failureCount = 0;
            await this.#delay(this.#configuration.pollIntervalMs, this.#stopController.signal);
            continue;
          }
          if (!retryableCycleError(error)) throw error;
          this.#failureCount += 1;
          const exponent = Math.min(30, this.#failureCount - 1);
          const ceiling = Math.min(this.#configuration.backoffMaxMs,
            this.#configuration.backoffBaseMs * (2 ** exponent));
          const random = this.#random();
          if (typeof random !== "number" || !Number.isFinite(random) || random < 0 || random >= 1) {
            throw new TypeError("runner random source must return a number from zero up to one");
          }
          const wait = Math.max(1, Math.min(this.#configuration.backoffMaxMs,
            Math.round(ceiling * (0.75 + random * 0.5))));
          await this.#delay(wait, this.#stopController.signal);
        }
      }
    } finally {
      this.#adapterConnectGeneration += 1;
      this.#detachAdapterClosedListener(this.#adapter);
      if (this.#adapterConnecting && typeof this.#adapterConnecting.close === "function") {
        try { await Promise.resolve(this.#adapterConnecting.close()); } catch {}
      }
      this.#adapterConnecting = null;
      if (this.#adapterRecoveryCandidate && typeof this.#adapterRecoveryCandidate.close === "function") {
        try { await Promise.resolve(this.#adapterRecoveryCandidate.close()); } catch {}
      }
      this.#adapterRecoveryCandidate = null;
      if (this.#closeAdapter && typeof this.#adapter.close === "function") {
        try { await this.#adapter.close(); } catch {}
      }
    }
  }

  async #cycle() {
    const current = nowMilliseconds(this.#clock);
    if (current - this.#lastHeartbeatAt >= this.#configuration.heartbeatIntervalMs) {
      await this.#postAck("/heartbeat", {
        apiVersion: HEARTBEAT_VERSION,
        caseId: this.#configuration.caseId,
        sessionRevision: this.#configuration.sessionRevision,
        observedAt: new Date(current).toISOString()
      });
      this.#lastHeartbeatAt = current;
    }
    if (current - this.#lastStateAt >= this.#configuration.projectionIntervalMs) {
      const projection = projectRemoteState(this.#stateForProjection(), {
        sessionRevision: this.#configuration.sessionRevision,
        stateRevision: this.#journal.nextProjectionRevision("state"),
        now: current,
        ttlMs: this.#configuration.stateTtlMs
      });
      const lifecycleRevision = this.#projectionLifecycleRevision;
      await this.#postAck("/state", projection);
      if (lifecycleRevision === this.#projectionLifecycleRevision) this.#lastStateAt = current;
    }
    if (this.#fleetProvider && current - this.#lastFleetAt >= this.#configuration.fleetIntervalMs) {
      const projection = projectRemoteFleet(await this.#fleetProvider(), {
        sessionRevision: this.#configuration.sessionRevision,
        revision: this.#journal.nextProjectionRevision("fleet")
      });
      await this.#postAck("/fleet", projection);
      this.#lastFleetAt = current;
    }
    await this.#uploadActivity();
    this.#scheduleAdapterRecovery(current);
    if (!this.#conversationAvailable() || current < this.#leaseSuppressedUntil) return;
    const command = await this.#lease();
    if (command && this.#conversationAvailable()) await this.#execute(command);
    else if (command) this.#holdLeasedCommand(command);
  }

  async #uploadActivity() {
    const selectedAdapter = this.#adapter;
    const events = selectedAdapter.activityStore.since(this.#activityCursor).slice(0, MAX_ACTIVITY_PER_CYCLE);
    for (const local of events) {
      const at = new Date(local.at);
      const event = sanitizeRemoteActivityEvent({
        category: local.category,
        state: local.state,
        completed: local.completed,
        total: local.total,
        tokens: local.tokens
      }, local.sequence, at);
      if (!event) fail("activity-invalid", "The local activity projection is invalid.");
      await this.#postAck("/activity", {
        apiVersion: ACTIVITY_UPLOAD_VERSION,
        caseId: this.#configuration.caseId,
        sessionRevision: this.#configuration.sessionRevision,
        event: {
          category: event.category,
          state: event.state,
          completed: event.completed,
          total: event.total,
          tokens: event.tokens
        }
      });
      this.#activityCursor = event.sequence;
    }
  }

  async #lease() {
    const result = await this.#post("/lease", {
      apiVersion: LEASE_REQUEST_VERSION,
      caseId: this.#configuration.caseId,
      sessionRevision: this.#configuration.sessionRevision
    });
    return normalizeLeaseResponse(result, this.#configuration);
  }

  async #execute(command) {
    if (!this.#conversationAvailable()) return;
    this.#executing = true;
    const acceptedAt = new Date(nowMilliseconds(this.#clock)).toISOString();
    let acceptedDurably = false;
    let terminalRecorded = false;
    try {
      const accepted = this.#journal.accept(command.commandId, command.payloadSha256, acceptedAt);
      acceptedDurably = true;
      await this.#transition(command, "accepted");
      if (accepted.replayed) {
        await this.#transition(command, "failed");
        if (accepted.entry.terminalState === null) this.#journal.terminal(command.commandId, "failed");
        terminalRecorded = true;
        return;
      }
      const running = await this.#transition(command, "running");
      let terminal = "completed";
      const renewalController = new AbortController();
      const renewal = this.#renewLease(command, running, renewalController.signal);
      try {
        try {
          // CodexCompanionAdapter resolves after the local app-server accepts a
          // turn start/steer or question response. This terminal state confirms
          // delivery to that adapter; later state/activity projections report
          // the Codex turn's own progress and completion.
          const delivery = command.kind === "message"
            ? this.#adapter.sendMessage(command.payload)
            : this.#adapter.answerQuestion(command.payload);
          await Promise.race([delivery, renewal]);
          this.#readAdapterState();
        } catch (error) {
          if (error instanceof RemoteRunnerError
              && new Set(["adapter-unavailable", "lease-renewal-failed"]).has(error.code)) throw error;
          if (!this.#adapterStateAvailable()) {
            fail("adapter-unavailable", "The local Codex companion is unavailable.");
          }
          terminal = "failed";
        }
        // Renewal remains active while the terminal transition is in flight.
        // Once finalization starts, its acknowledgement is authoritative: a
        // concurrent renewal may receive 409 after the coordinator has already
        // committed this terminal state.
        await this.#transition(command, terminal);
        this.#journal.terminal(command.commandId, terminal);
        terminalRecorded = true;
      } finally {
        renewalController.abort();
        await Promise.allSettled([renewal]);
      }
    } catch (error) {
      if (acceptedDurably && !terminalRecorded) {
        if (!this.#conversationDispatchBlocked) this.#projectionLifecycleRevision += 1;
        this.#conversationDispatchBlocked = true;
        this.#lastStateAt = Number.NEGATIVE_INFINITY;
      }
      throw error;
    } finally {
      this.#executing = false;
    }
  }

  #adapterStateAvailable() {
    if (this.#adapterUnavailable || this.#conversationDispatchBlocked) return false;
    try {
      return this.#adapter.privateState()?.connected === true;
    } catch {
      return false;
    }
  }

  #readAdapterState() {
    let state;
    try { state = this.#adapter.privateState(); } catch {}
    if (record(state)) {
      this.#adapterLastState = state;
      this.#rememberConnectedState(state);
    }
    return state;
  }

  #rememberConnectedState(state) {
    if (!record(state) || state.connected !== true) return;
    try {
      projectRemoteState(state, {
        sessionRevision: this.#configuration.sessionRevision,
        stateRevision: 1,
        now: nowMilliseconds(this.#clock),
        ttlMs: this.#configuration.stateTtlMs
      });
      this.#adapterLastConnectedState = state;
    } catch {
      // An unprojectable state cannot establish a safe recovery point.
    }
  }

  #stateForProjection() {
    const state = this.#readAdapterState();
    if (!this.#adapterUnavailable && !this.#conversationDispatchBlocked
        && record(state) && state.connected === true) {
      return state;
    }
    if (!record(state) || state.connected !== true) this.#markAdapterUnavailable();
    return offlineAdapterState(this.#adapterLastState);
  }

  #conversationAvailable() {
    if (this.#adapterUnavailable || this.#conversationDispatchBlocked) return false;
    const state = this.#readAdapterState();
    if (!record(state) || state.connected !== true) {
      this.#markAdapterUnavailable();
      return false;
    }
    return true;
  }

  #markAdapterUnavailable(adapter = this.#adapter, forceDispatchBlock = false) {
    if (adapter !== this.#adapter) return;
    const wasUnavailable = this.#adapterUnavailable;
    const wasDispatchBlocked = this.#conversationDispatchBlocked;
    const state = this.#readAdapterState();
    if (record(state)) this.#adapterLastState = state;
    this.#adapterUnavailable = true;
    this.#lastStateAt = Number.NEGATIVE_INFINITY;
    const currentPending = record(state) && Array.isArray(state.pendingQuestions) ? state.pendingQuestions : null;
    const trustedPending = Array.isArray(this.#adapterLastConnectedState?.pendingQuestions)
      ? this.#adapterLastConnectedState.pendingQuestions : null;
    if (forceDispatchBlock || this.#executing || !record(state) || state.turn !== "idle"
        || !Array.isArray(currentPending) || currentPending.length !== 0
        || this.#adapterLastConnectedState?.turn !== "idle"
        || !Array.isArray(trustedPending) || trustedPending.length !== 0) {
      this.#conversationDispatchBlocked = true;
    }
    if (!wasUnavailable || wasDispatchBlocked !== this.#conversationDispatchBlocked) {
      this.#projectionLifecycleRevision += 1;
    }
  }

  #holdLeasedCommand(command) {
    const leaseExpiry = Date.parse(command?.lease?.expiresAt);
    if (Number.isFinite(leaseExpiry)) {
      this.#leaseSuppressedUntil = Math.max(this.#leaseSuppressedUntil,
        leaseExpiry + LEASE_RECOVERY_SKEW_MS);
    }
  }

  #attachAdapterClosedListener(adapter) {
    if (typeof adapter.on !== "function") return;
    this.#adapterClosedListener = () => this.#markAdapterUnavailable(adapter);
    adapter.on("closed", this.#adapterClosedListener);
  }

  #detachAdapterClosedListener(adapter) {
    if (!this.#adapterClosedListener) return;
    if (typeof adapter.off === "function") adapter.off("closed", this.#adapterClosedListener);
    else if (typeof adapter.removeListener === "function") {
      adapter.removeListener("closed", this.#adapterClosedListener);
    }
    this.#adapterClosedListener = null;
  }

  #recoveryWait() {
    const exponent = Math.min(30, Math.max(0, this.#adapterRecoveryFailures - 1));
    const ceiling = Math.min(this.#configuration.backoffMaxMs,
      this.#configuration.backoffBaseMs * (2 ** exponent));
    const random = this.#random();
    if (typeof random !== "number" || !Number.isFinite(random) || random < 0 || random >= 1) {
      throw new TypeError("runner random source must return a number from zero up to one");
    }
    return Math.max(1, Math.min(this.#configuration.backoffMaxMs,
      Math.round(ceiling * (0.75 + random * 0.5))));
  }

  #recordAdapterRecoveryFailure() {
    this.#adapterRecoveryFailures += 1;
    this.#adapterNextAttemptAt = nowMilliseconds(this.#clock) + this.#recoveryWait();
  }

  #scheduleAdapterRecovery(current) {
    if (!this.#adapterUnavailable || this.#conversationDispatchBlocked || this.#adapterFactory === null
        || this.#adapterRecoveryPromise || this.#adapterRecoveryCandidate
        || current < this.#adapterNextAttemptAt || this.#stopRequested) return;
    const generation = ++this.#adapterConnectGeneration;
    this.#adapterRecoveryPromise = this.#recoverAdapter(generation)
      .catch((error) => { this.#adapterRecoveryFailure = error; })
      .finally(() => { this.#adapterRecoveryPromise = null; });
  }

  async #recoverAdapter(generation) {
    let candidate;
    let expired = false;
    let timer;
    const closeCandidate = async () => {
      if (candidate && candidate !== this.#adapter && typeof candidate.close === "function") {
        try { await Promise.resolve(candidate.close()); } catch {}
      }
    };
    try {
      const attempt = (async () => {
        candidate = await this.#adapterFactory();
        if (!compatibleAdapter(candidate) || candidate === this.#adapter) {
          throw new TypeError("replacement runner adapter is incompatible");
        }
        if (expired || this.#stopRequested || generation !== this.#adapterConnectGeneration) {
          await closeCandidate();
          return null;
        }
        this.#adapterConnecting = candidate;
        if (typeof candidate.connect === "function") await candidate.connect();
        if (expired || this.#stopRequested || generation !== this.#adapterConnectGeneration) {
          await closeCandidate();
          return null;
        }
        const state = candidate.privateState();
        if (!record(state) || state.connected !== true) {
          throw new Error("replacement runner adapter is unavailable");
        }
        projectRemoteState(state, {
          sessionRevision: this.#configuration.sessionRevision,
          stateRevision: 1,
          now: nowMilliseconds(this.#clock),
          ttlMs: this.#configuration.stateTtlMs
        });
        return candidate;
      })();
      const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => {
          expired = true;
          reject(new Error("replacement runner adapter connection timed out"));
        }, this.#configuration.adapterConnectTimeoutMs);
        timer.unref?.();
      });
      const connectedCandidate = await Promise.race([attempt, timeout]);
      clearTimeout(timer);
      if (connectedCandidate === null) return;
      if (this.#stopRequested || generation !== this.#adapterConnectGeneration || expired) {
        await closeCandidate();
        return;
      }
      this.#adapterRecoveryCandidate = connectedCandidate;
      this.#adapterRecoveryFailure = null;
    } catch {
      expired = true;
      clearTimeout(timer);
      await closeCandidate();
      if (!this.#stopRequested && generation === this.#adapterConnectGeneration) {
        this.#recordAdapterRecoveryFailure();
      }
    } finally {
      if (this.#adapterConnecting === candidate) this.#adapterConnecting = null;
    }
  }

  async #adoptRecoveredAdapter() {
    if (this.#adapterRecoveryFailure) {
      const error = this.#adapterRecoveryFailure;
      this.#adapterRecoveryFailure = null;
      if (error instanceof TypeError && /random source/u.test(error.message)) throw error;
    }
    const candidate = this.#adapterRecoveryCandidate;
    if (!candidate) return;
    let state;
    try { state = candidate.privateState(); } catch {}
    if (this.#stopRequested || this.#conversationDispatchBlocked || !record(state) || state.connected !== true) {
      if (typeof candidate.close === "function") {
        try { await Promise.resolve(candidate.close()); } catch {}
      }
      if (!this.#stopRequested && !this.#conversationDispatchBlocked) this.#recordAdapterRecoveryFailure();
      this.#adapterRecoveryCandidate = null;
      return;
    }
    const previous = this.#adapter;
    if (candidate.activityStore !== previous.activityStore
        && previous.activityStore.since(this.#activityCursor).length > 0) {
      return;
    }
    this.#adapterRecoveryCandidate = null;
    this.#detachAdapterClosedListener(previous);
    this.#adapter = candidate;
    this.#attachAdapterClosedListener(candidate);
    this.#adapterLastState = state;
    this.#rememberConnectedState(state);
    this.#adapterUnavailable = false;
    this.#projectionLifecycleRevision += 1;
    this.#adapterRecoveryFailures = 0;
    this.#adapterNextAttemptAt = Number.NEGATIVE_INFINITY;
    if (candidate.activityStore !== previous.activityStore) this.#activityCursor = 0;
    this.#lastStateAt = Number.NEGATIVE_INFINITY;
    if (this.#closeAdapter && typeof previous.close === "function") {
      void Promise.resolve(previous.close()).catch(() => {});
    }
  }

  async #renewLease(command, running, signal) {
    const serverNow = Date.parse(running.acceptedAt);
    const leaseExpiresAt = Date.parse(command.lease.expiresAt);
    const remaining = leaseExpiresAt - serverNow;
    if (!Number.isSafeInteger(remaining) || remaining <= 0) {
      fail("lease-renewal-failed", "The remote command lease could not be renewed.");
    }
    const interval = Math.max(25, Math.min(5_000, Math.floor(remaining / 3)));
    while (!signal.aborted) {
      await defaultDelay(interval, signal);
      if (signal.aborted) return;
      if (!this.#adapterStateAvailable()) {
        fail("adapter-unavailable", "The local Codex companion is unavailable.");
      }
      try {
        await this.#transition(command, "renewed", signal);
      } catch {
        if (signal.aborted) return;
        fail("lease-renewal-failed", "The remote command lease could not be renewed.");
      }
    }
  }

  async #transition(command, state, signal) {
    const request = {
      apiVersion: TRANSITION_VERSION,
      caseId: this.#configuration.caseId,
      sessionRevision: this.#configuration.sessionRevision,
      commandId: command.commandId,
      leaseId: command.lease.leaseId,
      state
    };
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        return await this.#postAck("/transition", request, signal);
      } catch (error) {
        if (signal?.aborted) throw error;
        const terminalAttempt = attempt === 2;
        const clientRejection = error instanceof RemoteRunnerError
          && error.status !== null && error.status >= 400 && error.status < 500;
        if (terminalAttempt || clientRejection) throw error;
        const wait = Math.min(1_000, this.#configuration.backoffBaseMs * (2 ** attempt));
        await this.#delay(wait);
      }
    }
    throw new Error("unreachable remote runner transition retry");
  }

  async #postAck(route, value, signal) {
    return validateAck(await this.#post(route, value, signal));
  }

  async #post(route, value, signal) {
    const body = JSON.stringify(value);
    if (Buffer.byteLength(body, "utf8") > MAX_RESPONSE_BYTES) {
      fail("request-too-large", "The remote runner request is too large.");
    }
    const requestPath = `${RUNNER_API_PREFIX}${route}`;
    const headers = this.#signer.sign({ method: "POST", path: requestPath, body });
    const controller = new AbortController();
    const abort = () => controller.abort();
    if (signal?.aborted) controller.abort();
    else signal?.addEventListener("abort", abort, { once: true });
    this.#currentFetchController = controller;
    const timer = setTimeout(() => controller.abort(), this.#configuration.requestTimeoutMs);
    try {
      let response;
      try {
        response = await this.#fetch(`${this.#configuration.controlPlaneOrigin}${requestPath}`, {
          method: "POST",
          headers: { ...headers, Accept: JSON_CONTENT_TYPE, "Content-Type": JSON_CONTENT_TYPE },
          body,
          redirect: "error",
          cache: "no-store",
          signal: controller.signal
        });
      } catch {
        fail("request-failed", "The remote control plane is unavailable.");
      }
      if (!response || response.redirected === true || response.status !== 200) {
        fail("request-rejected", "The remote control plane rejected the runner request.", response?.status ?? null);
      }
      if (response.headers?.get?.("content-type") !== JSON_RESPONSE_CONTENT_TYPE) {
        fail("content-type-invalid", "The remote control plane returned an invalid content type.");
      }
      const raw = await boundedResponseBody(response, controller.signal);
      let parsed;
      try {
        parsed = JSON.parse(raw);
      } catch {
        fail("response-invalid", "The remote control plane returned invalid JSON.");
      }
      if (!record(parsed)) fail("response-invalid", "The remote control plane returned an invalid response.");
      return parsed;
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      if (this.#currentFetchController === controller) this.#currentFetchController = null;
    }
  }
}

export const remoteRunnerInternals = Object.freeze({
  ACK_VERSION,
  ACTIVITY_UPLOAD_VERSION,
  HEARTBEAT_VERSION,
  JOURNAL_VERSION,
  LEASE_REQUEST_VERSION,
  LEASE_RESPONSE_VERSION,
  LEASE_RECOVERY_SKEW_MS,
  MAX_RESPONSE_BYTES,
  MAX_JOURNAL_ENTRIES,
  MAX_PROJECTED_CONVERSATION_ENTRIES,
  MAX_PROJECTED_PENDING_QUESTIONS,
  MAX_REMOTE_PROJECTION_BYTES,
  PROJECTION_REVISION_RESERVATION,
  WITHHELD_REMOTE_CONTENT,
  TRANSITION_VERSION,
  normalizeLeaseResponse
});
