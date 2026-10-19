import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import {
  readPrivateFileBounded,
  securePrivateDirectory,
  syncPrivateDirectory,
  writePrivateFileAtomic,
  writePrivateFileExclusive
} from "./private-fs.mjs";
import { validateDocument } from "./schema.mjs";

const MAX_STATE_BYTES = 64 * 1024;
const MAX_TRANSFER_RECEIPT_BYTES = 16 * 1024;
const MAX_TRANSFER_TRANSACTION_BYTES = 8 * 1024;
const MAX_TRANSFER_RECEIPTS = 10_000;
const CASE_ID = /^[a-z][a-z0-9-]{1,62}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const RECEIPT_FILE = /^([a-f0-9]{64})\.json$/u;
const MAX_STATE_VALIDITY_MS = 180_000;
const TRANSFER_TRANSACTION_FILE = ".transfer.transaction.json";
const TRANSFER_TRANSACTION_STAGE = ".transfer.transaction.pending";
const TRANSFER_RECEIPT_STAGE = ".transfer.receipt.pending";
const UNAVAILABLE_REASONS = new Set([
  "not-case-scoped", "missing", "invalid", "expired", "worker-unavailable"
]);

function pilotPaths(paths) {
  if (!paths?.caseId) throw new Error("CTF pilot state requires a case-scoped runtime");
  const root = path.join(paths.stateHome, "ctf-pilot");
  const state = path.join(root, "state.json");
  const transfers = path.join(root, "transfers");
  if (path.resolve(paths.ctfPilotRoot) !== path.resolve(root) ||
      path.resolve(paths.ctfPilotState) !== path.resolve(state) ||
      path.resolve(paths.ctfPilotTransfers) !== path.resolve(transfers)) {
    throw new Error("CTF pilot paths do not match their case-local locations");
  }
  return { root, state, transfers };
}

function trustedFlock() {
  for (const candidate of ["/usr/bin/flock", "/bin/flock"]) {
    try {
      if (fs.realpathSync(candidate) !== candidate) continue;
      const stat = fs.lstatSync(candidate);
      if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o111) === 0 || (stat.mode & 0o022) !== 0) continue;
      if (typeof process.geteuid === "function" && stat.uid === process.geteuid()) continue;
      try { fs.accessSync(candidate, fs.constants.W_OK); continue; }
      catch (error) { if (!new Set(["EACCES", "EPERM", "EROFS"]).has(error.code)) throw error; }
      return candidate;
    } catch {
      // Try the next protected fixed path.
    }
  }
  throw new Error("CTF pilot serialization requires flock from a protected system path");
}

/**
 * Hold one kernel flock on a retained owner-only descriptor for the complete
 * read/compare/write operation. `flock` and this process share the inherited
 * open-file description, so the lock remains held after the helper exits and
 * is released by the kernel when this process closes or dies.
 */
function withPilotWriteLock(paths, action) {
  const locations = pilotPaths(paths);
  securePrivateDirectory(locations.root, { create: false, label: "private CTF pilot directory" });
  const file = path.join(locations.root, ".state.serialization");
  const descriptor = fs.openSync(
    file,
    fs.constants.O_CREAT | fs.constants.O_RDWR | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0),
    0o600
  );
  const identity = fs.fstatSync(descriptor);
  try {
    if (!identity.isFile() || identity.nlink !== 1 ||
        (process.platform !== "win32" && (identity.mode & 0o7777) !== 0o600) ||
        (typeof process.geteuid === "function" && identity.uid !== process.geteuid())) {
      throw new Error("CTF pilot serialization file is not owner-only");
    }
    const locked = spawnSync(trustedFlock(), ["--exclusive", "--timeout", "2", "3"], {
      stdio: ["ignore", "pipe", "pipe", descriptor],
      env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
      shell: false,
      timeout: 5_000,
      maxBuffer: 16 * 1024
    });
    if (locked.error || locked.status !== 0) {
      throw new Error("CTF pilot state is already being updated or its lock is indeterminate", { cause: locked.error });
    }
    const current = fs.lstatSync(file);
    if (!current.isFile() || current.isSymbolicLink() || current.nlink !== 1 ||
        current.dev !== identity.dev || current.ino !== identity.ino) {
      throw new Error("CTF pilot serialization identity changed while acquiring the lock");
    }
    recoverTransferTransaction({ paths, locations });
    return action();
  } finally {
    fs.closeSync(descriptor);
  }
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function digestValue(value) {
  return crypto.createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

function digestBytes(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function readOptionalPrivateFile(file, maximumBytes, label) {
  try {
    return readPrivateFileBounded(file, maximumBytes, null, { label });
  } catch (error) {
    if (error?.code === "ENOENT" || error?.cause?.code === "ENOENT") return null;
    throw error;
  }
}

function transferTransactionPath(locations) {
  return path.join(locations.root, TRANSFER_TRANSACTION_FILE);
}

function removeTransferTransaction(file, locations) {
  fs.unlinkSync(file);
  syncPrivateDirectory(locations.root, { label: "private CTF pilot directory" });
}

function discardPrivateStage(file, maximumBytes, parent, label) {
  const bytes = readOptionalPrivateFile(file, maximumBytes, label);
  if (bytes === null) return false;
  fs.unlinkSync(file);
  syncPrivateDirectory(parent, { label: `parent directory for ${label}` });
  return true;
}

function publishStagedPrivateFile(stage, destination, content, { label }) {
  writePrivateFileExclusive(stage, content, { encoding: "utf8", label: `${label} staging file` });
  fs.renameSync(stage, destination);
  syncPrivateDirectory(path.dirname(destination), { label: `parent directory for ${label}` });
  if (path.dirname(stage) !== path.dirname(destination)) {
    syncPrivateDirectory(path.dirname(stage), { label: `staging directory for ${label}` });
  }
}

/**
 * Resolve the only two crash-safe transaction outcomes while holding the
 * pilot flock: roll an orphan receipt back to the prior state, or retain a
 * receipt already reflected by the atomically published next state.
 */
function recoverTransferTransaction({ paths, locations = pilotPaths(paths) }) {
  const transactionPath = transferTransactionPath(locations);
  const transactionStage = path.join(locations.root, TRANSFER_TRANSACTION_STAGE);
  const receiptStage = path.join(locations.root, TRANSFER_RECEIPT_STAGE);
  const transactionBytes = readOptionalPrivateFile(
    transactionPath,
    MAX_TRANSFER_TRANSACTION_BYTES,
    "private CTF pilot transfer transaction"
  );
  if (transactionBytes === null) {
    discardPrivateStage(
      transactionStage,
      MAX_TRANSFER_TRANSACTION_BYTES,
      locations.root,
      "private CTF pilot transfer transaction staging file"
    );
    discardPrivateStage(
      receiptStage,
      MAX_TRANSFER_RECEIPT_BYTES,
      locations.root,
      "private CTF pilot transfer receipt staging file"
    );
    return "none";
  }
  let transaction;
  try {
    transaction = JSON.parse(transactionBytes.toString("utf8"));
  } catch (error) {
    throw new Error("CTF pilot transfer transaction is malformed", { cause: error });
  }
  const validation = validateDocument(transaction, "ctf-pilot-transfer-transaction.schema.json", { paths });
  if (!validation.ok || transaction.caseId !== paths.caseId) {
    throw new Error("CTF pilot transfer transaction is invalid");
  }
  discardPrivateStage(
    transactionStage,
    MAX_TRANSFER_TRANSACTION_BYTES,
    locations.root,
    "private CTF pilot transfer transaction staging file"
  );

  const stateBytes = readOptionalPrivateFile(
    locations.state,
    MAX_STATE_BYTES,
    "private CTF pilot state during transfer recovery"
  );
  if (stateBytes === null) throw new Error("CTF pilot transfer transaction has no bound state");
  const stateDigest = digestBytes(stateBytes);
  const receiptPath = path.join(locations.transfers, `${transaction.receiptFileDigest}.json`);
  const receiptBytes = readOptionalPrivateFile(
    receiptPath,
    MAX_TRANSFER_RECEIPT_BYTES,
    "private CTF pilot transfer receipt during recovery"
  );
  if (receiptBytes !== null) {
    if (digestBytes(receiptBytes) !== transaction.receiptSha256) {
      throw new Error("CTF pilot transfer receipt changed during recovery");
    }
    let receipt;
    try { receipt = JSON.parse(receiptBytes.toString("utf8")); }
    catch (error) { throw new Error("CTF pilot transfer receipt is malformed during recovery", { cause: error }); }
    if (!receiptIsConsistent(receipt, paths) ||
        transferBindingDigest(receipt) !== transaction.receiptFileDigest) {
      throw new Error("CTF pilot transfer receipt binding changed during recovery");
    }
  }

  if (stateDigest === transaction.priorStateSha256) {
    if (receiptBytes !== null) {
      fs.unlinkSync(receiptPath);
      syncPrivateDirectory(locations.transfers, { label: "private CTF pilot transfer directory" });
    }
    discardPrivateStage(
      receiptStage,
      MAX_TRANSFER_RECEIPT_BYTES,
      locations.root,
      "private CTF pilot transfer receipt staging file"
    );
    removeTransferTransaction(transactionPath, locations);
    return "rolled-back";
  }
  if (stateDigest === transaction.nextStateSha256 && receiptBytes !== null) {
    discardPrivateStage(
      receiptStage,
      MAX_TRANSFER_RECEIPT_BYTES,
      locations.root,
      "private CTF pilot transfer receipt staging file"
    );
    removeTransferTransaction(transactionPath, locations);
    return "committed";
  }
  throw new Error("CTF pilot transfer transaction state is indeterminate");
}

function transferBinding(receipt) {
  return {
    apiVersion: receipt.apiVersion,
    caseId: receipt.metadata.caseId,
    learningDigest: receipt.learningDigest,
    sourceTask: receipt.sourceTask,
    distinctTask: receipt.distinctTask,
    appliedChangeDigest: receipt.appliedChangeDigest,
    validationEvidenceDigest: receipt.validationEvidenceDigest
  };
}

function transferBindingDigest(receipt) {
  return digestValue(transferBinding(receipt));
}

function transferDedupeDigest(receipt) {
  return digestValue({
    caseId: receipt.metadata.caseId,
    learningDigest: receipt.learningDigest,
    sourceTaskDigest: receipt.sourceTask.digest,
    distinctTaskDigest: receipt.distinctTask.digest
  });
}

function expectedTransferId(receipt) {
  return `transfer-${transferBindingDigest(receipt).slice(0, 32)}`;
}

function receiptIsConsistent(receipt, paths) {
  const validation = validateDocument(receipt, "ctf-pilot-transfer-receipt.schema.json", { paths });
  if (!validation.ok || receipt.metadata.caseId !== paths.caseId) return false;
  if (receipt.sourceTask.pseudonym === receipt.distinctTask.pseudonym ||
      receipt.sourceTask.digest === receipt.distinctTask.digest) return false;
  return receipt.metadata.id === expectedTransferId(receipt);
}

function unavailable(reason) {
  if (!UNAVAILABLE_REASONS.has(reason)) throw new TypeError("invalid CTF pilot availability reason");
  return Object.freeze({ availability: "unavailable", reason, state: null });
}

function unavailableTransferSummary(reason) {
  if (!UNAVAILABLE_REASONS.has(reason)) throw new TypeError("invalid CTF transfer availability reason");
  return Object.freeze({ availability: "unavailable", reason, count: null });
}

function availableMetric(metric) {
  return metric?.availability === "available" ? metric.value : null;
}

function unavailableMetrics(values) {
  return values.every((value) => value?.availability === "unavailable" && value.value === null);
}

function axisMetricsAreUnavailable(state) {
  const solving = state.solving;
  const learning = state.learning;
  const cockpit = state.cockpit;
  const integrity = state.integrity;
  if (solving.availability === "unavailable" && (
    solving.completion.state !== null || solving.completion.reproduction !== null ||
    solving.completion.externalAcceptance !== null ||
    solving.objectives.availability !== "unavailable" || solving.depth.level !== "unavailable" ||
    !unavailableMetrics([
      solving.depth.branchesExplored,
      solving.depth.techniquesAttempted,
      solving.depth.deadEndsRetired,
      ...Object.values(solving.efficiency)
    ])
  )) return false;
  if (learning.availability === "unavailable" && !unavailableMetrics(Object.values(learning.stages))) return false;
  if (cockpit.availability === "unavailable" && (
    cockpit.signals.availability !== "unavailable" ||
    !unavailableMetrics([cockpit.updatesPublished, cockpit.updatesMissed])
  )) return false;
  return integrity.availability !== "unavailable" || (
    integrity.checks.availability === "unavailable" &&
    unavailableMetrics([integrity.issues])
  );
}

function atOrBefore(candidate, ceiling) {
  const left = Date.parse(candidate);
  const right = Date.parse(ceiling);
  return Number.isFinite(left) && Number.isFinite(right) && left <= right;
}

function metadataIsConsistent(metadata) {
  const updatedAt = Date.parse(metadata.updatedAt);
  const validUntil = Date.parse(metadata.validUntil);
  return Number.isFinite(updatedAt) && Number.isFinite(validUntil) &&
    updatedAt < validUntil && validUntil - updatedAt <= MAX_STATE_VALIDITY_MS;
}

function requestedNow(now) {
  const value = now === undefined ? Date.now() : now instanceof Date ? now.getTime() : Date.parse(now);
  if (!Number.isFinite(value)) throw new TypeError("CTF pilot observation time is invalid");
  return value;
}

/** Return an ISO timestamp that is strictly later than the prior publication. */
export function nextCtfPilotTimestamp(previous, proposed = new Date()) {
  const prior = previous instanceof Date ? previous.getTime() : Date.parse(previous);
  const candidate = proposed instanceof Date ? proposed.getTime() : Date.parse(proposed);
  if (!Number.isFinite(prior) || !Number.isFinite(candidate)) {
    throw new TypeError("CTF pilot timestamp input is invalid");
  }
  return new Date(Math.max(candidate, prior + 1)).toISOString();
}

function passVerdictsAreSupported(state) {
  if (state.solving.verdict === "pass") {
    const completion = state.solving.completion;
    const objectives = state.solving.objectives;
    if (state.solving.now !== "complete" || state.solving.actionNeeded !== "none" ||
        completion.state !== "complete" ||
        !new Set(["confirmed", "not-applicable"]).has(completion.reproduction) ||
        !new Set(["accepted", "not-applicable"]).has(completion.externalAcceptance) ||
        objectives.availability !== "available" || objectives.completed !== objectives.total) return false;
  }
  if (state.learning.verdict === "pass") {
    if (state.learning.actionNeeded !== "none" || availableMetric(state.learning.stages.transferred) < 1) return false;
  }
  if (state.cockpit.verdict === "pass") {
    const signals = state.cockpit.signals;
    if (state.cockpit.now !== "current" || state.cockpit.actionNeeded !== "none" ||
        signals.availability !== "available" || signals.available !== signals.total ||
        availableMetric(state.cockpit.updatesMissed) !== 0) return false;
  }
  return true;
}

function stateIsConsistent(state, options = {}) {
  if (!metadataIsConsistent(state.metadata)) return false;
  if (!axisMetricsAreUnavailable(state)) return false;
  const completed = state.solving.objectives.completed;
  const total = state.solving.objectives.total;
  if (state.solving.objectives.availability === "available" && completed > total) return false;
  const elapsed = availableMetric(state.solving.efficiency.elapsedSeconds);
  const active = availableMetric(state.solving.efficiency.activeSeconds);
  if (elapsed !== null && active !== null && active > elapsed) return false;

  const stages = Object.fromEntries(Object.entries(state.learning.stages)
    .map(([key, value]) => [key, availableMetric(value)]));
  const exceeds = (value, ceiling) => value !== null && ceiling !== null && value > ceiling;
  if (exceeds(stages.candidates, stages.observations) || exceeds(stages.validated, stages.candidates) ||
      exceeds(stages.applied, stages.validated) || exceeds(stages.transferred, stages.applied) ||
      exceeds(stages.regressed, stages.applied)) return false;
  if (options.transferCount !== undefined) {
    if (!Number.isSafeInteger(options.transferCount) || options.transferCount < 0) return false;
    if (state.learning.availability === "available" && stages.transferred !== options.transferCount) return false;
    if (state.learning.availability === "unavailable" && options.transferCount !== 0) return false;
  }

  for (const coverage of [state.cockpit.signals, state.integrity.checks]) {
    if (coverage.availability === "available" && coverage.available > coverage.total) return false;
  }
  if (state.integrity.availability === "available") {
    const issues = availableMetric(state.integrity.issues);
    if (issues === null || state.integrity.checks.availability !== "available") return false;
    const complete = state.integrity.checks.available === state.integrity.checks.total;
    if (state.integrity.status === "consistent" && (issues !== 0 || !complete)) return false;
    if (state.integrity.status === "degraded" && issues === 0 && complete) return false;
  }

  const updatedAt = state.metadata.updatedAt;
  for (const axis of [state.solving, state.learning, state.cockpit]) {
    if (axis.availability === "available" && !atOrBefore(axis.updatedAt, updatedAt)) return false;
  }
  if (state.integrity.availability === "available" && !atOrBefore(state.integrity.checkedAt, updatedAt)) return false;
  return passVerdictsAreSupported(state);
}

function readTransferLedger({ paths }) {
  const locations = pilotPaths(paths);
  securePrivateDirectory(locations.transfers, { create: false, label: "private CTF pilot transfer directory" });
  const names = [];
  const handle = fs.opendirSync(locations.transfers);
  try {
    while (true) {
      const entry = handle.readSync();
      if (entry === null) break;
      if (!RECEIPT_FILE.test(entry.name)) throw new Error("private CTF pilot transfer directory has an unexpected entry");
      names.push(entry.name);
      if (names.length > MAX_TRANSFER_RECEIPTS) throw new Error("private CTF pilot transfer receipt limit exceeded");
    }
  } finally {
    handle.closeSync();
  }

  const receipts = new Map();
  const deduplicated = new Map();
  const appliedChanges = new Map();
  for (const name of names.sort()) {
    const fileDigest = RECEIPT_FILE.exec(name)[1];
    let receipt;
    try {
      receipt = JSON.parse(readPrivateFileBounded(
        path.join(locations.transfers, name),
        MAX_TRANSFER_RECEIPT_BYTES,
        "utf8",
        { label: "private CTF pilot transfer receipt" }
      ));
    } catch (error) {
      throw new Error("private CTF pilot transfer receipt is invalid", { cause: error });
    }
    if (!receiptIsConsistent(receipt, paths) || transferBindingDigest(receipt) !== fileDigest) {
      throw new Error("private CTF pilot transfer receipt binding is invalid");
    }
    const dedupeDigest = transferDedupeDigest(receipt);
    if (deduplicated.has(dedupeDigest)) {
      throw new Error("private CTF pilot transfer ledger contains a duplicate task transfer");
    }
    if (appliedChanges.has(receipt.appliedChangeDigest)) {
      throw new Error("private CTF pilot transfer ledger contains a duplicate applied learning");
    }
    receipts.set(fileDigest, receipt);
    deduplicated.set(dedupeDigest, fileDigest);
    appliedChanges.set(receipt.appliedChangeDigest, fileDigest);
  }
  return { count: appliedChanges.size, receipts, deduplicated, appliedChanges };
}

/** Hash the transferable learning snapshot without its receipt-derived count. */
export function ctfPilotLearningDigest(learning) {
  if (!learning || typeof learning !== "object" || !learning.stages || typeof learning.stages !== "object") {
    throw new TypeError("CTF pilot learning state is required");
  }
  const { transferred: _receiptDerived, ...stages } = learning.stages;
  const { updatedAt: _publicationTime, ...semanticLearning } = learning;
  return digestValue({ ...semanticLearning, stages });
}

/** Build a validated-by-recording, deterministic private transfer receipt. */
export function createCtfPilotTransferReceipt(input) {
  if (!input || typeof input !== "object" || !CASE_ID.test(input.caseId || "") ||
      !Number.isFinite(Date.parse(input.recordedAt)) || !SHA256.test(input.learningDigest || "") ||
      !SHA256.test(input.appliedChangeDigest || "") || !SHA256.test(input.validationEvidenceDigest || "")) {
    throw new TypeError("CTF pilot transfer receipt input is invalid");
  }
  for (const task of [input.sourceTask, input.distinctTask]) {
    if (!task || !CASE_ID.test(task.pseudonym || "") || !SHA256.test(task.digest || "")) {
      throw new TypeError("CTF pilot transfer task binding is invalid");
    }
  }
  if (input.sourceTask.pseudonym === input.distinctTask.pseudonym ||
      input.sourceTask.digest === input.distinctTask.digest) {
    throw new Error("CTF pilot transfer requires a distinct destination task");
  }
  const receipt = {
    $schema: "https://gate.local/schemas/ctf-pilot-transfer-receipt.schema.json",
    apiVersion: "gate.dev/ctf-pilot-transfer-receipt/v1",
    kind: "CtfPilotTransferReceipt",
    metadata: { id: "transfer-placeholder", caseId: input.caseId, recordedAt: input.recordedAt },
    learningDigest: input.learningDigest,
    sourceTask: { pseudonym: input.sourceTask.pseudonym, digest: input.sourceTask.digest },
    distinctTask: { pseudonym: input.distinctTask.pseudonym, digest: input.distinctTask.digest },
    appliedChangeDigest: input.appliedChangeDigest,
    validationEvidenceDigest: input.validationEvidenceDigest
  };
  receipt.metadata.id = expectedTransferId(receipt);
  return Object.freeze(receipt);
}

/** Return only the availability and evidence-derived deduplicated count. */
export function readCtfPilotTransferSummary({ paths }) {
  if (!paths?.caseId) return unavailableTransferSummary("not-case-scoped");
  try {
    const ledger = readTransferLedger({ paths });
    return Object.freeze({ availability: "available", reason: null, count: ledger.count });
  } catch (error) {
    const missing = error?.code === "ENOENT" || error?.cause?.code === "ENOENT";
    return unavailableTransferSummary(missing ? "missing" : "invalid");
  }
}

/**
 * Read the one case-local CTF pilot scorecard. Exact challenge identity,
 * flags, evidence, commands, receipts, and narrative remain outside this
 * bounded contract.
 */
function readCtfPilotStatusInternal({ paths, now, checkExpiry }) {
  if (!paths?.caseId) return unavailable("not-case-scoped");
  const locations = pilotPaths(paths);
  let state;
  try {
    state = JSON.parse(readPrivateFileBounded(
      locations.state,
      MAX_STATE_BYTES,
      "utf8",
      { label: "private CTF pilot state" }
    ));
  } catch (error) {
    return unavailable(error?.code === "ENOENT" || error?.cause?.code === "ENOENT" ? "missing" : "invalid");
  }
  const validation = validateDocument(state, "ctf-pilot-state.schema.json", { paths });
  if (!validation.ok || state.metadata.caseId !== paths.caseId) return unavailable("invalid");

  let ledger;
  try {
    ledger = readTransferLedger({ paths });
  } catch {
    return unavailable("invalid");
  }
  const claimed = state.learning.stages.transferred;
  if ((state.learning.availability === "available" &&
       (claimed.availability !== "available" || claimed.value !== ledger.count)) ||
      (state.learning.availability === "unavailable" &&
       (claimed.availability !== "unavailable" || ledger.count !== 0))) {
    return unavailable("invalid");
  }

  const derived = state.learning.availability === "available"
    ? {
        ...state,
        learning: {
          ...state.learning,
          stages: { ...state.learning.stages, transferred: { availability: "available", value: ledger.count } }
        }
      }
    : state;
  if (!stateIsConsistent(derived, { transferCount: ledger.count })) return unavailable("invalid");
  if (checkExpiry && requestedNow(now) >= Date.parse(derived.metadata.validUntil)) return unavailable("expired");
  return Object.freeze({ availability: "available", reason: null, state: derived });
}

export function readCtfPilotStatus({ paths, now } = {}) {
  return readCtfPilotStatusInternal({ paths, now, checkExpiry: true });
}

function writeCtfPilotStateUnlocked(
  state,
  { paths },
  current = readCtfPilotStatusInternal({ paths, checkExpiry: false })
) {
  const locations = pilotPaths(paths);
  const validation = validateDocument(state, "ctf-pilot-state.schema.json", { paths });
  let ledger;
  try {
    ledger = readTransferLedger({ paths });
  } catch (error) {
    throw new Error("CTF pilot transfer ledger is invalid", { cause: error });
  }
  if (!validation.ok || state.metadata.caseId !== paths.caseId ||
      !stateIsConsistent(state, { transferCount: ledger.count })) {
    throw new Error("CTF pilot state is invalid");
  }
  if (current.reason === "invalid") throw new Error("existing CTF pilot state is invalid");
  if (current.availability === "available") {
    if (state.metadata.id !== current.state.metadata.id ||
        state.metadata.revision !== current.state.metadata.revision + 1 ||
        Date.parse(state.metadata.updatedAt) <= Date.parse(current.state.metadata.updatedAt)) {
      throw new Error("CTF pilot state must use the exact next revision and a strictly later time");
    }
  } else if (current.reason !== "missing" || state.metadata.revision !== 1) {
    throw new Error("initial CTF pilot state must start at revision 1");
  }
  const bytes = serializePilotState(state);
  if (Buffer.byteLength(bytes) > MAX_STATE_BYTES) throw new Error("CTF pilot state exceeds the size limit");
  securePrivateDirectory(locations.root, { create: false, label: "private CTF pilot directory" });
  writePrivateFileAtomic(locations.state, bytes, { encoding: "utf8", label: "private CTF pilot state" });
  return Object.freeze(state);
}

function serializePilotState(state) {
  return `${JSON.stringify(state, null, 2)}\n`;
}

/** Validate and atomically publish the exact next case-worker scorecard. */
export function writeCtfPilotState(state, { paths }) {
  return withPilotWriteLock(paths, () => writeCtfPilotStateUnlocked(state, { paths }));
}

/**
 * Serialize a read/merge/write cycle so independent local producers cannot
 * silently replace the same revision. The callback receives the fully
 * validated current status and must return the complete next state.
 */
export function updateCtfPilotState(update, { paths }) {
  if (typeof update !== "function") throw new TypeError("CTF pilot updater must be a function");
  return withPilotWriteLock(paths, () => {
    const current = readCtfPilotStatusInternal({ paths, checkExpiry: false });
    const next = update(current);
    return writeCtfPilotStateUnlocked(next, { paths }, current);
  });
}

/**
 * Deduplicate and record one audited cross-task transfer, then advance the
 * stored receipt-derived count under the same per-case mutation lock.
 */
export function recordCtfPilotTransferReceipt(receipt, { paths, afterReceiptDurable } = {}) {
  if (afterReceiptDurable !== undefined && typeof afterReceiptDurable !== "function") {
    throw new TypeError("CTF pilot transfer receipt hook must be a function");
  }
  return withPilotWriteLock(paths, () => {
    if (!receiptIsConsistent(receipt, paths)) throw new Error("CTF pilot transfer receipt is invalid");
    const current = readCtfPilotStatusInternal({
      paths,
      now: receipt?.metadata?.recordedAt,
      checkExpiry: true
    });
    if (current.availability !== "available") throw new Error("current CTF pilot state is unavailable");
    const ledger = readTransferLedger({ paths });
    const bindingDigest = transferBindingDigest(receipt);
    if (ledger.receipts.has(bindingDigest)) {
      return Object.freeze({ created: false, count: ledger.count, state: current.state });
    }
    if (ledger.deduplicated.has(transferDedupeDigest(receipt))) {
      throw new Error("CTF pilot transfer conflicts with an existing deduplicated task transfer");
    }
    if (ledger.appliedChanges.has(receipt.appliedChangeDigest)) {
      throw new Error("CTF pilot transfer conflicts with an already transferred applied learning");
    }
    if (receipt.learningDigest !== ctfPilotLearningDigest(current.state.learning)) {
      throw new Error("CTF pilot transfer receipt does not bind the current learning state");
    }
    const applied = availableMetric(current.state.learning.stages.applied);
    if (current.state.learning.availability !== "available" || applied === null || ledger.count + 1 > applied) {
      throw new Error("CTF pilot transfer receipt exceeds audited applied learning");
    }
    if (Date.parse(receipt.metadata.recordedAt) <= Date.parse(current.state.metadata.updatedAt)) {
      throw new Error("CTF pilot transfer receipt time must be strictly later than current state");
    }

    const next = {
      ...current.state,
      metadata: {
        ...current.state.metadata,
        revision: current.state.metadata.revision + 1,
        updatedAt: receipt.metadata.recordedAt
      },
      learning: {
        ...current.state.learning,
        updatedAt: receipt.metadata.recordedAt,
        stages: {
          ...current.state.learning.stages,
          transferred: { availability: "available", value: ledger.count + 1 }
        }
      }
    };
    const locations = pilotPaths(paths);
    const receiptPath = path.join(locations.transfers, `${bindingDigest}.json`);
    const bytes = `${JSON.stringify(receipt, null, 2)}\n`;
    if (Buffer.byteLength(bytes) > MAX_TRANSFER_RECEIPT_BYTES) {
      throw new Error("CTF pilot transfer receipt exceeds the size limit");
    }
    const priorStateBytes = readPrivateFileBounded(
      locations.state,
      MAX_STATE_BYTES,
      null,
      { label: "private CTF pilot state before transfer" }
    );
    const nextStateBytes = serializePilotState(next);
    const transactionPath = transferTransactionPath(locations);
    const transactionStage = path.join(locations.root, TRANSFER_TRANSACTION_STAGE);
    const receiptStage = path.join(locations.root, TRANSFER_RECEIPT_STAGE);
    const transaction = {
      $schema: "https://gate.local/schemas/ctf-pilot-transfer-transaction.schema.json",
      apiVersion: "gate.dev/ctf-pilot-transfer-transaction/v1",
      kind: "CtfPilotTransferTransaction",
      caseId: paths.caseId,
      createdAt: receipt.metadata.recordedAt,
      receiptFileDigest: bindingDigest,
      receiptSha256: digestBytes(bytes),
      priorStateSha256: digestBytes(priorStateBytes),
      nextStateSha256: digestBytes(nextStateBytes)
    };
    const transactionBytes = `${JSON.stringify(transaction, null, 2)}\n`;
    if (Buffer.byteLength(transactionBytes) > MAX_TRANSFER_TRANSACTION_BYTES) {
      throw new Error("CTF pilot transfer transaction exceeds the size limit");
    }
    const transactionValidation = validateDocument(
      transaction,
      "ctf-pilot-transfer-transaction.schema.json",
      { paths }
    );
    if (!transactionValidation.ok) throw new Error("CTF pilot transfer transaction is invalid");
    publishStagedPrivateFile(transactionStage, transactionPath, transactionBytes, {
      label: "private CTF pilot transfer transaction"
    });
    try {
      publishStagedPrivateFile(receiptStage, receiptPath, bytes, {
        label: "private CTF pilot transfer receipt"
      });
      afterReceiptDurable?.();
      const state = writeCtfPilotStateUnlocked(next, { paths }, current);
      removeTransferTransaction(transactionPath, locations);
      return Object.freeze({ created: true, count: ledger.count + 1, state });
    } catch (error) {
      try {
        const outcome = recoverTransferTransaction({ paths, locations });
        if (outcome === "committed") {
          const recovered = readCtfPilotStatusInternal({ paths, checkExpiry: false });
          if (recovered.availability === "available") {
            return Object.freeze({
              created: true,
              count: availableMetric(recovered.state.learning.stages.transferred),
              state: recovered.state
            });
          }
        }
      } catch (recoveryError) {
        throw new Error("CTF pilot transfer state failed and recovery is indeterminate", {
          cause: new AggregateError([error, recoveryError])
        });
      }
      throw error;
    }
  });
}

/** Return the identifier-free local CLI view used by case workers and tests. */
export function ctfPilotStatusProjection(status) {
  if (status?.availability !== "available") {
    return Object.freeze({
      availability: "unavailable",
      reason: UNAVAILABLE_REASONS.has(status?.reason) ? status.reason : "invalid",
      revision: null,
      observedAt: null,
      solving: null,
      learning: null,
      cockpit: null,
      integrity: null
    });
  }
  const state = status.state;
  return Object.freeze({
    availability: "available",
    reason: null,
    revision: state.metadata.revision,
    observedAt: state.metadata.updatedAt,
    solving: state.solving,
    learning: state.learning,
    cockpit: state.cockpit,
    integrity: state.integrity
  });
}

export const ctfPilotInternals = Object.freeze({
  MAX_STATE_BYTES,
  MAX_TRANSFER_RECEIPT_BYTES,
  MAX_TRANSFER_RECEIPTS,
  MAX_STATE_VALIDITY_MS,
  stateIsConsistent,
  transferBindingDigest,
  transferDedupeDigest,
  expectedTransferId,
  trustedFlock
});
