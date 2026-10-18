import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import {
  REMOTE_COMMAND_EVENT_VERSION,
  REMOTE_COMMAND_VERSION,
  REMOTE_EVENTS_PAGE_VERSION,
  RemoteContractError,
  digestRemotePayload,
  normalizeRemoteCaseBinding,
  normalizeRemoteCommandBinding,
  normalizeRemoteCommandEvent,
  normalizeRemoteCommandStatusRequest,
  normalizeRemoteFleetProjection,
  normalizeRemoteMessageRequest,
  normalizeRemoteQuestionResponse,
  normalizeRemoteStateProjection,
  remoteContractInternals,
  remoteQueuedReceipt,
  sanitizeRemoteActivityEvent
} from "./contracts.mjs";

const SCHEMA_VERSION = 1;
const DEFAULT_BUSY_TIMEOUT_MS = 5_000;
const DEFAULT_COMMAND_TTL_MS = 5 * 60_000;
const MAX_COMMAND_TTL_MS = 15 * 60_000;
const DEFAULT_LEASE_MS = 30_000;
const MAX_LEASE_MS = 5 * 60_000;
const DEFAULT_EVENT_LIMIT = 100;
const MAX_EVENT_LIMIT = 256;
const DEFAULT_MAX_RUNNER_NONCES = 10_000;
const MAX_RUNNER_NONCES = 1_000_000;
const MAX_RUNNER_NONCE_TTL_MS = 10 * 60_000;
const DEFAULT_MAX_EVENTS = 20_000;
const MAX_EVENTS = 1_000_000;
const DEFAULT_MAX_COMMANDS = 50_000;
const MAX_COMMANDS = 1_000_000;
const COMMAND_ID = remoteContractInternals.COMMAND_ID;
const PRINCIPAL_ID = remoteContractInternals.PRINCIPAL_ID;
const SESSION_OR_RUNNER_ID = remoteContractInternals.SESSION_OR_RUNNER_ID;
const CASE_ID = remoteContractInternals.CASE_ID;
const LEASE_ID = /^lease_[A-Za-z0-9_-]{16,128}$/u;
const RUNNER_NONCE = /^[A-Za-z0-9_-]{32,64}$/u;
const TERMINAL_STATES = new Set(["completed", "failed", "expired", "cancelled"]);

export class RemoteStoreError extends Error {
  constructor(status, code, publicMessage) {
    super(publicMessage);
    this.name = "RemoteStoreError";
    this.status = status;
    this.code = code;
    this.publicMessage = publicMessage;
  }
}

function storeFail(status, code, message) {
  throw new RemoteStoreError(status, code, message);
}

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, expected) {
  return remoteContractInternals.exactKeys(value, expected);
}

function requireInteger(value, minimum, maximum, code, label) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    storeFail(400, code, `The ${label} is invalid.`);
  }
  return value;
}

function requireIdentifier(value, pattern, code, label) {
  if (typeof value !== "string" || !pattern.test(value)) {
    storeFail(400, code, `The ${label} is invalid.`);
  }
  return value;
}

function requireDuration(value, fallback, maximum, label) {
  const duration = value ?? fallback;
  return requireInteger(duration, 1_000, maximum, `${label}-invalid`, label);
}

function dateFromClock(clock) {
  const value = clock();
  const date = value instanceof Date ? new Date(value.getTime()) : null;
  if (!date || !Number.isFinite(date.getTime())) {
    storeFail(500, "clock-invalid", "The remote command clock is unavailable.");
  }
  return date;
}

function timestamp(milliseconds) {
  return new Date(milliseconds).toISOString();
}

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.freeze(value);
}

function parseStoredJson(value, label) {
  try {
    return deepFreeze(JSON.parse(value));
  } catch {
    storeFail(500, "store-corrupt", `The remote ${label} record is corrupt.`);
  }
}

function assertOwnerOnly(stat, label) {
  if ((stat.mode & 0o077) !== 0) {
    storeFail(500, "store-permissions-invalid", `The remote ${label} must be owner-only.`);
  }
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
    storeFail(500, "store-owner-invalid", `The remote ${label} must be owned by the current operator.`);
  }
}

function prepareDatabasePath(databasePath) {
  if (typeof databasePath !== "string" || databasePath.length < 1 || databasePath.includes("\0")
      || !path.isAbsolute(databasePath) || path.normalize(databasePath) !== databasePath) {
    storeFail(500, "store-path-invalid", "The remote database path must be an absolute normalized path.");
  }
  const parent = path.dirname(databasePath);
  let parentStat;
  try {
    parentStat = fs.lstatSync(parent);
  } catch {
    storeFail(500, "store-parent-missing", "The remote database parent directory is unavailable.");
  }
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink()) {
    storeFail(500, "store-parent-invalid", "The remote database parent must be a real directory.");
  }
  let realParent;
  try {
    realParent = fs.realpathSync.native(parent);
  } catch {
    storeFail(500, "store-parent-invalid", "The remote database parent directory is unavailable.");
  }
  if (realParent !== parent) {
    storeFail(500, "store-parent-invalid", "The remote database parent must not traverse symbolic links.");
  }
  assertOwnerOnly(parentStat, "database parent directory");

  let created = false;
  try {
    const flags = fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_RDWR
      | (fs.constants.O_NOFOLLOW ?? 0);
    const descriptor = fs.openSync(databasePath, flags, 0o600);
    fs.closeSync(descriptor);
    created = true;
  } catch (error) {
    if (error?.code !== "EEXIST") {
      storeFail(500, "store-create-failed", "The remote database could not be created.");
    }
  }

  let databaseStat;
  try {
    databaseStat = fs.lstatSync(databasePath);
  } catch {
    storeFail(500, "store-file-invalid", "The remote database file is unavailable.");
  }
  if (!databaseStat.isFile() || databaseStat.isSymbolicLink()) {
    storeFail(500, "store-file-invalid", "The remote database must be a regular file.");
  }
  assertOwnerOnly(databaseStat, "database file");
  return { created };
}

function normalizeRequest(request) {
  if (request?.apiVersion === "gate.remote-message-request/v1") {
    return { kind: "message", request: normalizeRemoteMessageRequest(request) };
  }
  if (request?.apiVersion === "gate.remote-question-response/v1") {
    return { kind: "question", request: normalizeRemoteQuestionResponse(request) };
  }
  throw new RemoteContractError(400, "request-invalid", "The remote request is invalid.");
}

function normalizeRunnerClaim(value) {
  if (!exactKeys(value, ["operatorId", "caseId", "sessionRevision", "runnerId", "leaseMs"])) {
    storeFail(400, "runner-claim-invalid", "The remote runner claim is invalid.");
  }
  return Object.freeze({
    operatorId: requireIdentifier(value.operatorId, PRINCIPAL_ID, "operator-invalid", "operator"),
    caseId: requireIdentifier(value.caseId, CASE_ID, "case-invalid", "case"),
    sessionRevision: requireInteger(value.sessionRevision, 1, 2_147_483_647,
      "session-changed", "session revision"),
    runnerId: requireIdentifier(value.runnerId, SESSION_OR_RUNNER_ID, "runner-invalid", "runner"),
    leaseMs: requireDuration(value.leaseMs, DEFAULT_LEASE_MS, MAX_LEASE_MS, "lease duration")
  });
}

function normalizeRunnerBinding(value) {
  if (!exactKeys(value, ["commandId", "operatorId", "caseId", "sessionRevision", "runnerId", "leaseId"])) {
    storeFail(400, "runner-binding-invalid", "The remote runner binding is invalid.");
  }
  return Object.freeze({
    commandId: requireIdentifier(value.commandId, COMMAND_ID, "command-invalid", "command"),
    operatorId: requireIdentifier(value.operatorId, PRINCIPAL_ID, "operator-invalid", "operator"),
    caseId: requireIdentifier(value.caseId, CASE_ID, "case-invalid", "case"),
    sessionRevision: requireInteger(value.sessionRevision, 1, 2_147_483_647,
      "session-changed", "session revision"),
    runnerId: requireIdentifier(value.runnerId, SESSION_OR_RUNNER_ID, "runner-invalid", "runner"),
    leaseId: requireIdentifier(value.leaseId, LEASE_ID, "lease-invalid", "lease")
  });
}

function normalizeBrowserCommandBinding(value) {
  if (!exactKeys(value, ["commandId", "operatorId", "browserSessionId", "caseId", "sessionRevision"])) {
    storeFail(400, "browser-command-binding-invalid", "The remote browser command binding is invalid.");
  }
  const binding = normalizeRemoteCommandBinding({
    operatorId: value.operatorId,
    browserSessionId: value.browserSessionId,
    caseId: value.caseId,
    sessionRevision: value.sessionRevision
  });
  return Object.freeze({
    commandId: requireIdentifier(value.commandId, COMMAND_ID, "command-invalid", "command"),
    ...binding
  });
}

function normalizeCommandLookup(value) {
  return normalizeBrowserCommandBinding(value);
}

function rowMatchesBrowserScope(row, binding) {
  return row.operator_id === binding.operatorId
    && row.case_id === binding.caseId
    && row.session_revision === binding.sessionRevision;
}

function rowMatchesRunner(row, binding) {
  return row.operator_id === binding.operatorId
    && row.case_id === binding.caseId
    && row.session_revision === binding.sessionRevision
    && row.runner_id === binding.runnerId
    && row.lease_id === binding.leaseId;
}

export class RemoteBridgeStore {
  #database;
  #databasePath;
  #now;
  #idGenerator;
  #busyTimeoutMs;
  #maxRunnerNonces;
  #maxEvents;
  #maxCommands;
  #runnerNonceAdapter;
  #closed = false;

  constructor(options = {}) {
    if (!record(options) || !exactKeys(options, [
      "databasePath", "now", "idGenerator", "busyTimeoutMs", "maxRunnerNonces", "maxEvents", "maxCommands"
    ]
      .filter((key) => options[key] !== undefined))) {
      storeFail(500, "store-options-invalid", "The remote store options are invalid.");
    }
    this.#databasePath = options.databasePath;
    this.#now = options.now ?? (() => new Date());
    this.#idGenerator = options.idGenerator ?? ((kind) => `${kind}_${crypto.randomUUID()}`);
    this.#busyTimeoutMs = requireInteger(options.busyTimeoutMs ?? DEFAULT_BUSY_TIMEOUT_MS,
      1, 60_000, "busy-timeout-invalid", "database busy timeout");
    this.#maxRunnerNonces = requireInteger(options.maxRunnerNonces ?? DEFAULT_MAX_RUNNER_NONCES,
      1, MAX_RUNNER_NONCES, "runner-nonce-limit-invalid", "runner nonce limit");
    this.#maxEvents = requireInteger(options.maxEvents ?? DEFAULT_MAX_EVENTS,
      1, MAX_EVENTS, "event-retention-limit-invalid", "event retention limit");
    this.#maxCommands = requireInteger(options.maxCommands ?? DEFAULT_MAX_COMMANDS,
      1, MAX_COMMANDS, "command-retention-limit-invalid", "command retention limit");
    if (typeof this.#now !== "function" || typeof this.#idGenerator !== "function") {
      storeFail(500, "store-options-invalid", "The remote store options are invalid.");
    }
    const prepared = prepareDatabasePath(this.#databasePath);
    try {
      this.#database = new DatabaseSync(this.#databasePath, { allowExtension: false });
      this.#configure();
      this.#initializeSchema();
      this.#verifyConfiguration();
    } catch (error) {
      try { this.#database?.close(); } catch {}
      if (prepared.created) {
        try { fs.rmSync(this.#databasePath, { force: true }); } catch {}
      }
      if (error instanceof RemoteStoreError || error instanceof RemoteContractError) throw error;
      storeFail(500, "store-open-failed", "The remote command store could not be opened.");
    }
  }

  #assertOpen() {
    if (this.#closed) storeFail(503, "store-closed", "The remote command store is closed.");
  }

  #configure() {
    this.#database.exec(`
      PRAGMA foreign_keys = ON;
      PRAGMA synchronous = FULL;
      PRAGMA busy_timeout = ${this.#busyTimeoutMs};
      PRAGMA trusted_schema = OFF;
      PRAGMA journal_mode = WAL;
    `);
  }

  #initializeSchema() {
    const version = this.#database.prepare("PRAGMA user_version").get().user_version;
    if (version !== 0 && version !== SCHEMA_VERSION) {
      storeFail(500, "store-schema-unsupported", "The remote database schema is unsupported.");
    }
    this.#database.exec(`
      CREATE TABLE IF NOT EXISTS commands (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        command_id TEXT NOT NULL UNIQUE,
        request_id TEXT NOT NULL,
        operator_id TEXT NOT NULL,
        browser_session_id TEXT NOT NULL,
        case_id TEXT NOT NULL,
        session_revision INTEGER NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('message', 'question')),
        request_json TEXT NOT NULL,
        payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
        state TEXT NOT NULL CHECK (state IN (
          'queued', 'leased', 'accepted', 'running', 'completed', 'failed', 'expired', 'cancelled'
        )),
        issued_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL,
        receipt_json TEXT,
        runner_id TEXT,
        lease_id TEXT,
        lease_expires_at_ms INTEGER,
        updated_at_ms INTEGER NOT NULL,
        CHECK (expires_at_ms > issued_at_ms),
        CHECK (
          (runner_id IS NULL AND lease_id IS NULL AND lease_expires_at_ms IS NULL)
          OR (runner_id IS NOT NULL AND lease_id IS NOT NULL AND lease_expires_at_ms IS NOT NULL)
        )
      );

      CREATE INDEX IF NOT EXISTS commands_dispatch_idx
        ON commands (operator_id, case_id, state, sequence);

      CREATE UNIQUE INDEX IF NOT EXISTS commands_request_scope_idx
        ON commands (operator_id, case_id, session_revision, request_id);

      CREATE INDEX IF NOT EXISTS commands_retention_idx
        ON commands (state, expires_at_ms, sequence);

      CREATE TABLE IF NOT EXISTS case_bindings (
        operator_id TEXT NOT NULL,
        case_id TEXT NOT NULL,
        session_revision INTEGER NOT NULL,
        updated_at_ms INTEGER NOT NULL,
        PRIMARY KEY (operator_id, case_id)
      ) WITHOUT ROWID;

      CREATE TABLE IF NOT EXISTS events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        operator_id TEXT NOT NULL,
        browser_session_id TEXT,
        case_id TEXT NOT NULL,
        session_revision INTEGER NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('command', 'activity', 'state', 'fleet')),
        command_id TEXT,
        at_ms INTEGER NOT NULL,
        payload_json TEXT NOT NULL,
        FOREIGN KEY (command_id) REFERENCES commands(command_id) ON DELETE RESTRICT
      );

      CREATE INDEX IF NOT EXISTS events_scope_idx
        ON events (operator_id, case_id, session_revision, sequence);

      CREATE INDEX IF NOT EXISTS events_command_idx ON events (command_id);

      CREATE TABLE IF NOT EXISTS event_retention (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        pruned_through INTEGER NOT NULL CHECK (pruned_through >= 0)
      );

      INSERT OR IGNORE INTO event_retention (singleton, pruned_through) VALUES (1, 0);

      CREATE TABLE IF NOT EXISTS state_projections (
        operator_id TEXT NOT NULL,
        case_id TEXT NOT NULL,
        session_revision INTEGER NOT NULL,
        revision INTEGER NOT NULL,
        digest TEXT NOT NULL CHECK (length(digest) = 64),
        projection_json TEXT NOT NULL,
        updated_at_ms INTEGER NOT NULL,
        PRIMARY KEY (operator_id, case_id)
      );

      CREATE TABLE IF NOT EXISTS fleet_projections (
        operator_id TEXT NOT NULL,
        case_id TEXT NOT NULL,
        session_revision INTEGER NOT NULL,
        revision INTEGER NOT NULL,
        digest TEXT NOT NULL CHECK (length(digest) = 64),
        projection_json TEXT NOT NULL,
        updated_at_ms INTEGER NOT NULL,
        PRIMARY KEY (operator_id, case_id)
      );

      CREATE TABLE IF NOT EXISTS runner_nonces (
        runner_id TEXT NOT NULL,
        nonce TEXT NOT NULL,
        expires_at_ms INTEGER NOT NULL,
        PRIMARY KEY (runner_id, nonce)
      ) WITHOUT ROWID;

      CREATE INDEX IF NOT EXISTS runner_nonces_expiry_idx ON runner_nonces (expires_at_ms);

      PRAGMA user_version = ${SCHEMA_VERSION};
    `);
  }

  #verifyConfiguration() {
    const journalMode = this.#database.prepare("PRAGMA journal_mode").get().journal_mode;
    const foreignKeys = this.#database.prepare("PRAGMA foreign_keys").get().foreign_keys;
    const synchronous = this.#database.prepare("PRAGMA synchronous").get().synchronous;
    const busyTimeout = this.#database.prepare("PRAGMA busy_timeout").get().timeout;
    if (String(journalMode).toLowerCase() !== "wal" || foreignKeys !== 1 || synchronous !== 2
        || busyTimeout !== this.#busyTimeoutMs) {
      storeFail(500, "store-configuration-invalid", "The remote database safety configuration is unavailable.");
    }
    const databaseStat = fs.lstatSync(this.#databasePath);
    assertOwnerOnly(databaseStat, "database file");
  }

  #transaction(operation) {
    this.#assertOpen();
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const result = operation();
      this.#database.exec("COMMIT");
      return result;
    } catch (error) {
      try { this.#database.exec("ROLLBACK"); } catch {}
      throw error;
    }
  }

  #readTransaction(operation) {
    this.#assertOpen();
    this.#database.exec("BEGIN");
    try {
      const result = operation();
      this.#database.exec("COMMIT");
      return result;
    } catch (error) {
      try { this.#database.exec("ROLLBACK"); } catch {}
      throw error;
    }
  }

  #newId(kind, pattern) {
    const value = this.#idGenerator(kind);
    if (typeof value !== "string" || !pattern.test(value)) {
      storeFail(500, "id-generator-invalid", "The remote identifier generator returned an invalid value.");
    }
    return value;
  }

  #commandRow(commandIdValue) {
    return this.#database.prepare("SELECT * FROM commands WHERE command_id = ?").get(commandIdValue) ?? null;
  }

  #requireCurrentCaseBinding(binding) {
    const current = this.#database.prepare(`
      SELECT session_revision FROM case_bindings WHERE operator_id = ? AND case_id = ?
    `).get(binding.operatorId, binding.caseId);
    if (!current || current.session_revision !== binding.sessionRevision) {
      storeFail(409, "session-changed", "The remote cockpit session changed. Reload the cockpit.");
    }
  }

  #commandFromRow(row) {
    if (!row) return null;
    const payload = parseStoredJson(row.request_json, "command payload");
    const lease = row.lease_id === null ? null : Object.freeze({
      leaseId: row.lease_id,
      runnerId: row.runner_id,
      expiresAt: timestamp(row.lease_expires_at_ms)
    });
    return Object.freeze({
      apiVersion: REMOTE_COMMAND_VERSION,
      sequence: row.sequence,
      commandId: row.command_id,
      kind: row.kind,
      requestId: row.request_id,
      operatorId: row.operator_id,
      browserSessionId: row.browser_session_id,
      caseId: row.case_id,
      sessionRevision: row.session_revision,
      issuedAt: timestamp(row.issued_at_ms),
      expiresAt: timestamp(row.expires_at_ms),
      payloadSha256: row.payload_sha256,
      payload,
      state: row.state,
      lease
    });
  }

  #appendEvent({ operatorId, browserSessionId = null, caseId, sessionRevision, kind, commandIdValue = null,
    atMilliseconds, buildPayload }) {
    const inserted = this.#database.prepare(`
      INSERT INTO events (
        operator_id, browser_session_id, case_id, session_revision, kind, command_id, at_ms, payload_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, '{}')
    `).run(operatorId, browserSessionId, caseId, sessionRevision, kind, commandIdValue, atMilliseconds);
    const sequence = Number(inserted.lastInsertRowid);
    const payload = buildPayload(sequence);
    const serialized = JSON.stringify(payload);
    if (Buffer.byteLength(serialized, "utf8") > 128 * 1024) {
      storeFail(413, "event-too-large", "The remote event is too large.");
    }
    this.#database.prepare("UPDATE events SET payload_json = ? WHERE sequence = ?").run(serialized, sequence);
    this.#compactEvents();
    return Object.freeze({
      kind,
      sequence,
      at: timestamp(atMilliseconds),
      payload: deepFreeze(JSON.parse(serialized))
    });
  }

  #compactEvents() {
    const cutoff = this.#database.prepare(`
      SELECT sequence FROM events ORDER BY sequence DESC LIMIT 1 OFFSET ?
    `).get(this.#maxEvents);
    if (!cutoff) return;
    this.#database.prepare("DELETE FROM events WHERE sequence <= ?").run(cutoff.sequence);
    this.#database.prepare(`
      UPDATE event_retention
      SET pruned_through = CASE WHEN pruned_through < ? THEN ? ELSE pruned_through END
      WHERE singleton = 1
    `).run(cutoff.sequence, cutoff.sequence);
  }

  #appendCommandEvent(row, state, atMilliseconds) {
    return this.#appendEvent({
      operatorId: row.operator_id,
      browserSessionId: row.browser_session_id,
      caseId: row.case_id,
      sessionRevision: row.session_revision,
      kind: "command",
      commandIdValue: row.command_id,
      atMilliseconds,
      buildPayload: (sequence) => normalizeRemoteCommandEvent({
        apiVersion: REMOTE_COMMAND_EVENT_VERSION,
        sequence,
        at: timestamp(atMilliseconds),
        requestId: row.request_id,
        commandId: row.command_id,
        state
      })
    });
  }

  #expireDueInTransaction(nowMilliseconds) {
    const rows = this.#database.prepare(`
      SELECT * FROM commands
      WHERE (state IN ('queued', 'leased', 'accepted') AND expires_at_ms <= ?)
        OR (state = 'running' AND lease_expires_at_ms <= ?)
      ORDER BY sequence
    `).all(nowMilliseconds, nowMilliseconds);
    let expired = 0;
    for (const row of rows) {
      // A running delivery may already have reached the local adapter, so it
      // must never be re-leased after its runner disappears. Mark the
      // coordinator-side outcome failed once its lease is abandoned; the
      // delivery result is conservatively unknown rather than replayable.
      const terminalState = row.state === "running" ? "failed" : "expired";
      const changed = this.#database.prepare(`
        UPDATE commands SET state = ?, updated_at_ms = ?
        WHERE command_id = ? AND state = ?
      `).run(terminalState, nowMilliseconds, row.command_id, row.state);
      if (changed.changes === 1) {
        expired += 1;
        this.#appendCommandEvent(row, terminalState, nowMilliseconds);
      }
    }
    return expired;
  }

  #reserveCommandCapacity(nowMilliseconds) {
    const count = this.#database.prepare("SELECT COUNT(*) AS count FROM commands").get().count;
    if (count < this.#maxCommands) return;
    const required = count - this.#maxCommands + 1;
    const candidates = this.#database.prepare(`
      SELECT command_id
      FROM commands
      WHERE state IN ('completed', 'failed', 'expired', 'cancelled')
        AND expires_at_ms <= ?
        AND NOT EXISTS (
          SELECT 1 FROM events WHERE events.command_id = commands.command_id
        )
      ORDER BY sequence
      LIMIT ?
    `).all(nowMilliseconds, required);
    for (const candidate of candidates) {
      this.#database.prepare(`
        DELETE FROM commands
        WHERE command_id = ?
          AND state IN ('completed', 'failed', 'expired', 'cancelled')
          AND expires_at_ms <= ?
          AND NOT EXISTS (SELECT 1 FROM events WHERE events.command_id = commands.command_id)
      `).run(candidate.command_id, nowMilliseconds);
    }
    const retained = this.#database.prepare("SELECT COUNT(*) AS count FROM commands").get().count;
    if (retained >= this.#maxCommands) {
      storeFail(503, "command-store-full", "The remote command store is full.");
    }
  }

  configuration() {
    this.#assertOpen();
    const retention = this.#database.prepare(`
      SELECT
        (SELECT COUNT(*) FROM events) AS retained_events,
        (SELECT COUNT(*) FROM commands) AS retained_commands,
        (SELECT pruned_through FROM event_retention WHERE singleton = 1) AS pruned_through,
        COALESCE((SELECT MAX(sequence) FROM events),
          (SELECT pruned_through FROM event_retention WHERE singleton = 1)) AS head_cursor
    `).get();
    return Object.freeze({
      schemaVersion: SCHEMA_VERSION,
      journalMode: String(this.#database.prepare("PRAGMA journal_mode").get().journal_mode).toLowerCase(),
      foreignKeys: this.#database.prepare("PRAGMA foreign_keys").get().foreign_keys === 1,
      synchronous: this.#database.prepare("PRAGMA synchronous").get().synchronous === 2 ? "full" : "unknown",
      busyTimeoutMs: this.#database.prepare("PRAGMA busy_timeout").get().timeout,
      maxEvents: this.#maxEvents,
      maxCommands: this.#maxCommands,
      retainedEvents: retention.retained_events,
      retainedCommands: retention.retained_commands,
      eventPrunedThrough: retention.pruned_through,
      eventHeadCursor: retention.head_cursor
    });
  }

  isOpen() {
    return !this.#closed;
  }

  close() {
    if (this.#closed) return;
    this.#database.close();
    this.#closed = true;
  }

  consumeRunnerNonce(runnerIdValue, nonceValue, expiresAt) {
    this.#assertOpen();
    const runnerId = requireIdentifier(runnerIdValue, SESSION_OR_RUNNER_ID, "runner-invalid", "runner");
    const nonce = requireIdentifier(nonceValue, RUNNER_NONCE, "runner-nonce-invalid", "runner nonce");
    const now = dateFromClock(this.#now).getTime();
    requireInteger(expiresAt, now + 1, now + MAX_RUNNER_NONCE_TTL_MS,
      "runner-nonce-expiry-invalid", "runner nonce expiry");
    return this.#transaction(() => {
      this.#database.prepare("DELETE FROM runner_nonces WHERE expires_at_ms <= ?").run(now);
      const prior = this.#database.prepare(`
        SELECT 1 AS present FROM runner_nonces WHERE runner_id = ? AND nonce = ?
      `).get(runnerId, nonce);
      if (prior) return false;
      const count = this.#database.prepare("SELECT COUNT(*) AS count FROM runner_nonces").get().count;
      if (count >= this.#maxRunnerNonces) {
        storeFail(503, "runner-nonce-store-full", "The remote runner replay store is full.");
      }
      this.#database.prepare(`
        INSERT INTO runner_nonces (runner_id, nonce, expires_at_ms) VALUES (?, ?, ?)
      `).run(runnerId, nonce, expiresAt);
      return true;
    });
  }

  runnerNonceStore() {
    this.#assertOpen();
    if (!this.#runnerNonceAdapter) {
      this.#runnerNonceAdapter = Object.freeze({
        consume: (runnerId, nonce, expiresAt) => this.consumeRunnerNonce(runnerId, nonce, expiresAt)
      });
    }
    return this.#runnerNonceAdapter;
  }

  claimCaseBinding(bindingValue) {
    this.#assertOpen();
    const binding = normalizeRemoteCaseBinding(bindingValue);
    const now = dateFromClock(this.#now).getTime();
    return this.#transaction(() => {
      const current = this.#database.prepare(`
        SELECT session_revision FROM case_bindings WHERE operator_id = ? AND case_id = ?
      `).get(binding.operatorId, binding.caseId);
      if (current && binding.sessionRevision < current.session_revision) {
        storeFail(409, "session-changed", "The remote cockpit session revision is stale.");
      }
      if (!current) {
        this.#database.prepare(`
          INSERT INTO case_bindings (operator_id, case_id, session_revision, updated_at_ms)
          VALUES (?, ?, ?, ?)
        `).run(binding.operatorId, binding.caseId, binding.sessionRevision, now);
        return Object.freeze({ sessionRevision: binding.sessionRevision, advanced: false });
      }
      if (binding.sessionRevision === current.session_revision) {
        return Object.freeze({ sessionRevision: binding.sessionRevision, advanced: false });
      }

      const obsolete = this.#database.prepare(`
        SELECT * FROM commands
        WHERE operator_id = ? AND case_id = ? AND session_revision < ?
          AND state IN ('queued', 'leased', 'accepted', 'running')
        ORDER BY sequence
      `).all(binding.operatorId, binding.caseId, binding.sessionRevision);
      for (const row of obsolete) {
        const terminalState = row.state === "running" ? "failed" : "cancelled";
        this.#database.prepare(`
          UPDATE commands SET state = ?, updated_at_ms = ? WHERE command_id = ?
        `).run(terminalState, now, row.command_id);
        this.#appendCommandEvent(row, terminalState, now);
      }
      this.#database.prepare(`
        UPDATE case_bindings SET session_revision = ?, updated_at_ms = ?
        WHERE operator_id = ? AND case_id = ?
      `).run(binding.sessionRevision, now, binding.operatorId, binding.caseId);
      return Object.freeze({ sessionRevision: binding.sessionRevision, advanced: true });
    });
  }

  enqueue(bindingValue, requestValue, options = {}) {
    this.#assertOpen();
    const binding = normalizeRemoteCommandBinding(bindingValue);
    const { kind, request } = normalizeRequest(requestValue);
    if (request.sessionRevision !== binding.sessionRevision) {
      storeFail(409, "session-changed", "The remote cockpit session changed. Reload the cockpit.");
    }
    if (!record(options) || !exactKeys(options, ["ttlMs"].filter((key) => options[key] !== undefined))) {
      storeFail(400, "enqueue-options-invalid", "The remote enqueue options are invalid.");
    }
    const ttlMs = requireDuration(options.ttlMs, DEFAULT_COMMAND_TTL_MS, MAX_COMMAND_TTL_MS, "command lifetime");
    const now = dateFromClock(this.#now).getTime();
    const payloadSha256 = digestRemotePayload(request);
    const requestJson = JSON.stringify(request);

    return this.#transaction(() => {
      this.#requireCurrentCaseBinding(binding);
      this.#expireDueInTransaction(now);
      const prior = this.#database.prepare(`
        SELECT * FROM commands
        WHERE operator_id = ? AND case_id = ? AND session_revision = ? AND request_id = ?
      `).get(binding.operatorId, binding.caseId, binding.sessionRevision, request.requestId);
      if (prior) {
        if (prior.kind !== kind || prior.payload_sha256 !== payloadSha256) {
          storeFail(409, "request-replay-conflict", "That request identifier was already used for different input.");
        }
        this.#appendCommandEvent(prior, prior.state, now);
        return Object.freeze({
          receipt: parseStoredJson(prior.receipt_json, "command receipt"),
          replayed: true,
          command: this.#commandFromRow(prior)
        });
      }

      this.#reserveCommandCapacity(now);

      const commandIdValue = this.#newId("cmd", COMMAND_ID);
      let inserted;
      try {
        inserted = this.#database.prepare(`
          INSERT INTO commands (
            command_id, request_id, operator_id, browser_session_id, case_id, session_revision, kind,
            request_json, payload_sha256, state, issued_at_ms, expires_at_ms, updated_at_ms
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?)
        `).run(commandIdValue, request.requestId, binding.operatorId, binding.browserSessionId, binding.caseId,
          binding.sessionRevision, kind, requestJson, payloadSha256, now, now + ttlMs, now);
      } catch {
        storeFail(503, "id-collision", "The remote command identifier could not be allocated.");
      }
      const commandSequence = Number(inserted.lastInsertRowid);
      const receipt = remoteQueuedReceipt({
        requestId: request.requestId,
        sessionRevision: binding.sessionRevision,
        commandId: commandIdValue,
        sequence: commandSequence,
        acceptedAt: timestamp(now)
      });
      this.#database.prepare("UPDATE commands SET receipt_json = ? WHERE command_id = ?")
        .run(JSON.stringify(receipt), commandIdValue);
      const row = this.#commandRow(commandIdValue);
      this.#appendCommandEvent(row, "queued", now);
      return Object.freeze({ receipt, replayed: false, command: this.#commandFromRow(row) });
    });
  }

  getCommand(bindingValue) {
    this.#assertOpen();
    const binding = normalizeCommandLookup(bindingValue);
    return this.#readTransaction(() => {
      this.#requireCurrentCaseBinding(binding);
      const row = this.#commandRow(binding.commandId);
      if (!row || !rowMatchesBrowserScope(row, binding)) return null;
      return this.#commandFromRow(row);
    });
  }

  getCommandStatuses(bindingValue, requestValue) {
    this.#assertOpen();
    const binding = normalizeRemoteCommandBinding(bindingValue);
    const request = normalizeRemoteCommandStatusRequest(requestValue);
    if (request.caseId !== binding.caseId || request.sessionRevision !== binding.sessionRevision) {
      storeFail(409, "session-changed", "The remote cockpit session changed. Reload the cockpit.");
    }
    const now = dateFromClock(this.#now).getTime();
    return this.#transaction(() => {
      this.#requireCurrentCaseBinding(binding);
      this.#expireDueInTransaction(now);
      const statuses = [];
      for (const reference of request.commands) {
        const row = this.#commandRow(reference.commandId);
        if (!row || !rowMatchesBrowserScope(row, binding) || row.request_id !== reference.requestId) continue;
        statuses.push(Object.freeze({
          requestId: row.request_id,
          commandId: row.command_id,
          state: row.state
        }));
      }
      return Object.freeze(statuses);
    });
  }

  leaseNext(claimValue) {
    this.#assertOpen();
    const claim = normalizeRunnerClaim(claimValue);
    const now = dateFromClock(this.#now).getTime();
    return this.#transaction(() => {
      this.#requireCurrentCaseBinding(claim);
      this.#expireDueInTransaction(now);
      const row = this.#database.prepare(`
        SELECT * FROM commands
        WHERE operator_id = ? AND case_id = ? AND session_revision = ? AND expires_at_ms > ?
          AND (state = 'queued' OR (state = 'leased' AND lease_expires_at_ms <= ?))
        ORDER BY sequence
        LIMIT 1
      `).get(claim.operatorId, claim.caseId, claim.sessionRevision, now, now);
      if (!row) return null;
      const leaseId = this.#newId("lease", LEASE_ID);
      const leaseExpiresAt = Math.min(now + claim.leaseMs, row.expires_at_ms);
      const changed = this.#database.prepare(`
        UPDATE commands
        SET state = 'leased', runner_id = ?, lease_id = ?, lease_expires_at_ms = ?, updated_at_ms = ?
        WHERE command_id = ? AND (state = 'queued' OR (state = 'leased' AND lease_expires_at_ms <= ?))
      `).run(claim.runnerId, leaseId, leaseExpiresAt, now, row.command_id, now);
      if (changed.changes !== 1) return null;
      const leased = this.#commandRow(row.command_id);
      this.#appendCommandEvent(leased, "leased", now);
      return this.#commandFromRow(leased);
    });
  }

  renewLease(bindingValue, options = {}) {
    this.#assertOpen();
    const binding = normalizeRunnerBinding(bindingValue);
    if (!record(options) || !exactKeys(options, ["leaseMs"].filter((key) => options[key] !== undefined))) {
      storeFail(400, "lease-options-invalid", "The remote lease options are invalid.");
    }
    const leaseMs = requireDuration(options.leaseMs, DEFAULT_LEASE_MS, MAX_LEASE_MS, "lease duration");
    const now = dateFromClock(this.#now).getTime();
    return this.#transaction(() => {
      this.#requireCurrentCaseBinding(binding);
      const row = this.#commandRow(binding.commandId);
      if (!row || !rowMatchesRunner(row, binding)) {
        storeFail(404, "command-not-found", "The bound remote command was not found.");
      }
      if (!new Set(["leased", "accepted", "running"]).has(row.state) || row.lease_expires_at_ms <= now) {
        storeFail(409, "lease-inactive", "The remote command lease is no longer active.");
      }
      const requestedExpiry = now + leaseMs;
      const leaseExpiresAt = row.state === "running" ? requestedExpiry : Math.min(requestedExpiry, row.expires_at_ms);
      if (leaseExpiresAt <= now) storeFail(409, "command-expired", "The remote command has expired.");
      this.#database.prepare(`
        UPDATE commands SET lease_expires_at_ms = ?, updated_at_ms = ? WHERE command_id = ?
      `).run(leaseExpiresAt, now, row.command_id);
      return this.#commandFromRow(this.#commandRow(row.command_id));
    });
  }

  #transitionRunner(bindingValue, allowedStates, targetState) {
    this.#assertOpen();
    const binding = normalizeRunnerBinding(bindingValue);
    const now = dateFromClock(this.#now).getTime();
    return this.#transaction(() => {
      this.#requireCurrentCaseBinding(binding);
      const row = this.#commandRow(binding.commandId);
      if (!row || !rowMatchesRunner(row, binding)) {
        storeFail(404, "command-not-found", "The bound remote command was not found.");
      }
      if (row.state === targetState) return this.#commandFromRow(row);
      if (!allowedStates.has(row.state)) {
        storeFail(409, "command-transition-invalid", "The remote command cannot make that transition.");
      }
      if (row.lease_expires_at_ms <= now) {
        storeFail(409, "lease-inactive", "The remote command lease is no longer active.");
      }
      if (new Set(["accepted", "running"]).has(targetState) && row.expires_at_ms <= now) {
        storeFail(409, "command-expired", "The remote command has expired.");
      }
      this.#database.prepare("UPDATE commands SET state = ?, updated_at_ms = ? WHERE command_id = ?")
        .run(targetState, now, row.command_id);
      const changed = this.#commandRow(row.command_id);
      this.#appendCommandEvent(changed, targetState, now);
      return this.#commandFromRow(changed);
    });
  }

  acceptCommand(bindingValue) {
    return this.#transitionRunner(bindingValue, new Set(["leased"]), "accepted");
  }

  startCommand(bindingValue) {
    return this.#transitionRunner(bindingValue, new Set(["accepted"]), "running");
  }

  completeCommand(bindingValue) {
    return this.#transitionRunner(bindingValue, new Set(["running"]), "completed");
  }

  failCommand(bindingValue) {
    return this.#transitionRunner(bindingValue, new Set(["accepted", "running"]), "failed");
  }

  cancelCommand(bindingValue) {
    this.#assertOpen();
    const binding = normalizeBrowserCommandBinding(bindingValue);
    const now = dateFromClock(this.#now).getTime();
    return this.#transaction(() => {
      this.#requireCurrentCaseBinding(binding);
      const row = this.#commandRow(binding.commandId);
      if (!row || !rowMatchesBrowserScope(row, binding)) {
        storeFail(404, "command-not-found", "The bound remote command was not found.");
      }
      if (row.state === "cancelled") return this.#commandFromRow(row);
      if (TERMINAL_STATES.has(row.state)) {
        storeFail(409, "command-terminal", "The remote command is already terminal.");
      }
      this.#database.prepare("UPDATE commands SET state = 'cancelled', updated_at_ms = ? WHERE command_id = ?")
        .run(now, row.command_id);
      const changed = this.#commandRow(row.command_id);
      this.#appendCommandEvent(changed, "cancelled", now);
      return this.#commandFromRow(changed);
    });
  }

  expireDue() {
    this.#assertOpen();
    const now = dateFromClock(this.#now).getTime();
    return this.#transaction(() => this.#expireDueInTransaction(now));
  }

  #putProjection(type, bindingValue, projectionValue) {
    this.#assertOpen();
    const binding = normalizeRemoteCaseBinding(bindingValue);
    const state = type === "state";
    const projection = state
      ? normalizeRemoteStateProjection(projectionValue)
      : normalizeRemoteFleetProjection(projectionValue);
    if (projection.sessionRevision !== binding.sessionRevision) {
      storeFail(409, "session-changed", "The remote cockpit session changed. Reload the cockpit.");
    }
    const revision = state ? projection.stateRevision : projection.revision;
    const serialized = JSON.stringify(projection);
    const digest = crypto.createHash("sha256").update(serialized, "utf8").digest("hex");
    const table = state ? "state_projections" : "fleet_projections";
    const now = dateFromClock(this.#now).getTime();
    return this.#transaction(() => {
      this.#requireCurrentCaseBinding(binding);
      const current = this.#database.prepare(`
        SELECT * FROM ${table} WHERE operator_id = ? AND case_id = ?
      `).get(binding.operatorId, binding.caseId);
      if (current) {
        if (binding.sessionRevision < current.session_revision
            || (binding.sessionRevision === current.session_revision && revision < current.revision)) {
          storeFail(409, "projection-stale", "The remote projection revision is stale.");
        }
        if (binding.sessionRevision === current.session_revision && revision === current.revision) {
          if (digest !== current.digest) {
            storeFail(409, "projection-replay-conflict", "That remote projection revision already has different content.");
          }
          return Object.freeze({ projection: parseStoredJson(current.projection_json, `${type} projection`), replayed: true,
            event: null });
        }
        this.#database.prepare(`
          UPDATE ${table}
          SET session_revision = ?, revision = ?, digest = ?, projection_json = ?, updated_at_ms = ?
          WHERE operator_id = ? AND case_id = ?
        `).run(binding.sessionRevision, revision, digest, serialized, now, binding.operatorId, binding.caseId);
      } else {
        this.#database.prepare(`
          INSERT INTO ${table} (
            operator_id, case_id, session_revision, revision, digest, projection_json, updated_at_ms
          ) VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(binding.operatorId, binding.caseId, binding.sessionRevision, revision, digest, serialized, now);
      }
      const event = this.#appendEvent({
        operatorId: binding.operatorId,
        caseId: binding.caseId,
        sessionRevision: binding.sessionRevision,
        kind: type,
        atMilliseconds: now,
        buildPayload: () => projection
      });
      return Object.freeze({ projection, replayed: false, event });
    });
  }

  putStateProjection(bindingValue, projectionValue) {
    return this.#putProjection("state", bindingValue, projectionValue);
  }

  putFleetProjection(bindingValue, projectionValue) {
    return this.#putProjection("fleet", bindingValue, projectionValue);
  }

  #getProjection(type, lookupValue) {
    this.#assertOpen();
    const lookup = normalizeRemoteCaseBinding(lookupValue);
    const table = type === "state" ? "state_projections" : "fleet_projections";
    return this.#readTransaction(() => {
      this.#requireCurrentCaseBinding(lookup);
      const row = this.#database.prepare(`
        SELECT projection_json FROM ${table}
        WHERE operator_id = ? AND case_id = ? AND session_revision = ?
      `).get(lookup.operatorId, lookup.caseId, lookup.sessionRevision);
      return row ? parseStoredJson(row.projection_json, `${type} projection`) : null;
    });
  }

  getStateProjection(lookupValue) {
    return this.#getProjection("state", lookupValue);
  }

  getFleetProjection(lookupValue) {
    return this.#getProjection("fleet", lookupValue);
  }

  appendActivity(bindingValue, value) {
    this.#assertOpen();
    const binding = normalizeRemoteCaseBinding(bindingValue);
    const nowDate = dateFromClock(this.#now);
    return this.#transaction(() => {
      this.#requireCurrentCaseBinding(binding);
      return this.#appendEvent({
        operatorId: binding.operatorId,
        caseId: binding.caseId,
        sessionRevision: binding.sessionRevision,
        kind: "activity",
        atMilliseconds: nowDate.getTime(),
        buildPayload: (sequence) => {
          const event = sanitizeRemoteActivityEvent(value, sequence, nowDate);
          if (!event) storeFail(400, "activity-invalid", "The remote activity event is invalid.");
          return event;
        }
      });
    });
  }

  eventsSince(bindingValue, cursor = 0, options = {}) {
    this.#assertOpen();
    const binding = normalizeRemoteCommandBinding(bindingValue);
    requireInteger(cursor, 0, Number.MAX_SAFE_INTEGER, "event-cursor-invalid", "event cursor");
    if (!record(options) || !exactKeys(options, ["limit"].filter((key) => options[key] !== undefined))) {
      storeFail(400, "event-options-invalid", "The remote event options are invalid.");
    }
    const limit = requireInteger(options.limit ?? DEFAULT_EVENT_LIMIT, 1, MAX_EVENT_LIMIT,
      "event-limit-invalid", "event limit");
    return this.#readTransaction(() => {
      this.#requireCurrentCaseBinding(binding);
      const visibilitySql = `
        operator_id = ? AND case_id = ? AND session_revision = ?
      `;
      const retention = this.#database.prepare(`
        SELECT
          pruned_through,
          COALESCE((SELECT MAX(sequence) FROM events), pruned_through) AS head
        FROM event_retention WHERE singleton = 1
      `).get();
      const resyncRequired = (retention.pruned_through > 0 && cursor <= retention.pruned_through)
        || cursor > retention.head;
      if (resyncRequired) {
        return Object.freeze({
          apiVersion: REMOTE_EVENTS_PAGE_VERSION,
          after: cursor,
          nextCursor: retention.head,
          headCursor: retention.head,
          resyncRequired: true,
          hasMore: false,
          events: Object.freeze([])
        });
      }
      const rows = this.#database.prepare(`
        SELECT sequence, kind, at_ms, payload_json
        FROM events
        WHERE ${visibilitySql} AND sequence > ?
        ORDER BY sequence
        LIMIT ?
      `).all(binding.operatorId, binding.caseId, binding.sessionRevision, cursor, limit + 1);
      const selected = rows.slice(0, limit);
      const events = selected.map((row) => Object.freeze({
        kind: row.kind,
        sequence: row.sequence,
        at: timestamp(row.at_ms),
        payload: parseStoredJson(row.payload_json, "event payload")
      }));
      return Object.freeze({
        apiVersion: REMOTE_EVENTS_PAGE_VERSION,
        after: cursor,
        nextCursor: events.length > 0 ? events.at(-1).sequence : retention.head,
        headCursor: retention.head,
        resyncRequired: false,
        hasMore: rows.length > limit,
        events: Object.freeze(events)
      });
    });
  }
}

export const remoteStoreInternals = Object.freeze({
  DEFAULT_BUSY_TIMEOUT_MS,
  DEFAULT_COMMAND_TTL_MS,
  DEFAULT_EVENT_LIMIT,
  DEFAULT_LEASE_MS,
  DEFAULT_MAX_EVENTS,
  DEFAULT_MAX_COMMANDS,
  DEFAULT_MAX_RUNNER_NONCES,
  LEASE_ID,
  MAX_COMMAND_TTL_MS,
  MAX_EVENTS,
  MAX_COMMANDS,
  MAX_EVENT_LIMIT,
  MAX_LEASE_MS,
  MAX_RUNNER_NONCES,
  MAX_RUNNER_NONCE_TTL_MS,
  RUNNER_NONCE,
  SCHEMA_VERSION,
  prepareDatabasePath
});
