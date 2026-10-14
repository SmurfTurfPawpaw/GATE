import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

import { checkEngagement } from "./engagements.mjs";
import { ensureRuntime, runtimePaths } from "./paths.mjs";
import { PENTEST_COVERAGE_DOMAINS, pentestWorkflowSemanticErrors } from "./pentest-workflow.mjs";
import {
  appendPrivateFile,
  readPrivateFileBounded,
  securePrivateDirectory,
  syncPrivateDirectory,
  writePrivateFileAtomic,
  writePrivateFileExclusive
} from "./private-fs.mjs";
import { assertValidDocument } from "./schema.mjs";

const ID_PATTERN = /^[a-z][a-z0-9-]{1,62}$/u;
const PHASE_ID_PATTERN = /^[a-z][a-z0-9-]{1,79}$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const REQUEST_PATTERN = /^wreq_[a-f0-9]{32}$/u;
const ATTEMPT_PATTERN = /^wpa_[a-f0-9]{32}$/u;
const RESERVATION_PATTERN = /^wxr_[a-f0-9]{32}$/u;
const LEDGER_PATTERN = /^wle_[a-f0-9]{32}$/u;
const TERMINAL_DISPOSITIONS = new Set(["tested", "not-applicable", "blocked", "untested"]);
const CLEAN_LEDGER_STATES = new Set(["empty", "verified-clean"]);
const TEARDOWN_PHASES = new Set([
  "offline-lab-reset-verification",
  "cleanup-and-restoration",
  "retest-cleanup-verification",
  "recovery-hold"
]);

const MAX_JOURNAL_BYTES = 16 * 1024 * 1024;
const MAX_PROJECTION_BYTES = 4 * 1024 * 1024;
const MAX_EXTERNAL_BYTES = 256 * 1024 * 1024;
const MAX_EVENTS = 100_000;
const MAX_COMPACT_STATUS_BYTES = 16 * 1024;
const MAX_COMPACT_STOPS = 32;
const MAX_FLEET_DISCOVERY = 4096;
const MAX_FLEET_SCAN = 64;
const MAX_FLEET_PROJECTION_BYTES = 128 * 1024;
const MAX_FLEET_JOURNAL_BYTES = 256 * 1024;

function stableObject(value) {
  if (Array.isArray(value)) return value.map(stableObject);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableObject(value[key])]));
}

function canonicalBytes(value) {
  return Buffer.from(JSON.stringify(stableObject(value)));
}

function sha256(value) {
  return crypto.createHash("sha256").update(Buffer.isBuffer(value) ? value : Buffer.from(value)).digest("hex");
}

function canonicalDigest(value, domain = "gate.workflow.canonical.v1") {
  return sha256(Buffer.concat([Buffer.from(`${domain}\0`), canonicalBytes(value)]));
}

function newId(prefix) {
  return `${prefix}_${crypto.randomBytes(16).toString("hex")}`;
}

function intentOptions(options, operation, input) {
  return {
    ...options,
    requestSha256: canonicalDigest({ operation, input }, "gate.workflow.request.v1")
  };
}

function requireId(value, label = "workflow instance id") {
  const result = String(value || "");
  if (!ID_PATTERN.test(result)) throw new Error(`${label} must use 2-63 lowercase letters, digits, and hyphens and start with a letter`);
  return result;
}

function requireEvidenceId(value, label) {
  const result = String(value || "");
  if (!PHASE_ID_PATTERN.test(result)) throw new Error(`${label} is invalid`);
  return result;
}

function oneLine(value, label, maximum) {
  const result = String(value ?? "").trim();
  if (!result || result.length > maximum || /[\u0000\r\n]/u.test(result)) {
    throw new Error(`${label} must be a nonempty single-line value of at most ${maximum} characters`);
  }
  return result;
}

function normalizePaths(input = {}) {
  const supplied = input?.home ? input : runtimePaths(input);
  const base = runtimePaths({ home: supplied.home, repo: supplied.repo, env: supplied.env });
  return { ...base, ...supplied, workflows: supplied.workflows || base.workflows || path.join(base.home, "workflows") };
}

function workflowPaths(input = {}, id = null) {
  const base = normalizePaths(input);
  if (id === null || id === undefined) return base;
  const instanceId = requireId(id);
  const workflowDirectory = path.join(base.workflows, instanceId);
  return {
    ...base,
    workflowDirectory,
    workflowProjection: path.join(workflowDirectory, "instance.json"),
    workflowJournal: path.join(workflowDirectory, "journal.jsonl"),
    workflowLock: path.join(workflowDirectory, ".lock"),
    workflowAdmissions: path.join(workflowDirectory, "admissions"),
    workflowHandoffs: path.join(workflowDirectory, "handoffs"),
    workflowEvidence: path.join(workflowDirectory, "evidence"),
    workflowReports: path.join(workflowDirectory, "reports")
  };
}

function ensureWorkflowRoot(paths, options = {}) {
  const normalized = normalizePaths(paths);
  if (!options.runtimeEnsured) ensureRuntime(normalized);
  securePrivateDirectory(normalized.workflows, { label: "private workflow root" });
  return normalized;
}

function ensureInstanceDirectories(paths, create) {
  securePrivateDirectory(paths.workflowDirectory, {
    create,
    label: `private workflow instance ${path.basename(paths.workflowDirectory)}`
  });
  for (const [directory, label] of [
    [paths.workflowAdmissions, "workflow admissions"],
    [paths.workflowHandoffs, "workflow handoffs"],
    [paths.workflowEvidence, "workflow evidence"],
    [paths.workflowReports, "workflow reports"]
  ]) securePrivateDirectory(directory, { create, label });
}

function stableFileBytes(file, maximumBytes, label) {
  const resolved = path.resolve(String(file || ""));
  let before;
  try {
    before = fs.lstatSync(resolved, { bigint: true });
  } catch (error) {
    throw new Error(`${label} is unavailable: ${error.message}`, { cause: error });
  }
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) {
    throw new Error(`${label} must be a regular single-link non-symlink file`);
  }
  if (before.size > BigInt(maximumBytes)) throw new Error(`${label} exceeds the ${maximumBytes}-byte limit`);
  if (process.platform !== "win32" && !fs.constants.O_NOFOLLOW) {
    throw new Error(`${label} cannot be opened without following links on this platform`);
  }
  const descriptor = fs.openSync(
    resolved,
    fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK || 0) |
      (process.platform === "win32" ? 0 : fs.constants.O_NOFOLLOW)
  );
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    const unchanged = (left, right) => left.dev === right.dev && left.ino === right.ino &&
      left.size === right.size && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
    if (!opened.isFile() || opened.nlink !== 1n || !unchanged(before, opened)) {
      throw new Error(`${label} changed while it was being opened`);
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
    if (total > maximumBytes) throw new Error(`${label} exceeds the ${maximumBytes}-byte limit`);
    const afterRead = fs.fstatSync(descriptor, { bigint: true });
    const afterPath = fs.lstatSync(resolved, { bigint: true });
    if (!afterPath.isFile() || afterPath.isSymbolicLink() || afterPath.nlink !== 1n ||
      !unchanged(opened, afterRead) || !unchanged(afterRead, afterPath) || BigInt(total) !== afterRead.size) {
      throw new Error(`${label} changed while it was being read`);
    }
    return Buffer.concat(chunks, total);
  } finally {
    fs.closeSync(descriptor);
  }
}

function readTrackedJson(file, schema, paths, maximumBytes = 16 * 1024 * 1024) {
  const bytes = stableFileBytes(file, maximumBytes, `tracked ${path.basename(file)}`);
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); }
  catch { throw new Error(`${path.basename(file)} is malformed JSON`); }
  assertValidDocument(value, schema, { paths });
  return { value, bytes, sha256: sha256(bytes) };
}

function loadDefinition(paths) {
  const id = "pentest-e2e";
  const workflow = readTrackedJson(
    path.join(paths.repo, "config", "workflows", `${id}.json`),
    "pentest-workflow.schema.json",
    paths
  );
  if (workflow.value.metadata.id !== id) throw new Error("workflow definition id does not match its filename");
  const catalog = readTrackedJson(path.join(paths.repo, "catalog", "security-tools.json"), "tool-catalog.schema.json", paths);
  const policy = readTrackedJson(path.join(paths.repo, "policies", "engagements.json"), "engagement-policy.schema.json", paths);
  const errors = pentestWorkflowSemanticErrors(workflow.value, {
    catalog: catalog.value,
    engagementPolicy: policy.value
  });
  if (errors.length) throw new Error(`workflow semantic validation failed: ${errors.join("; ")}`);
  if (JSON.stringify(workflow.value.coverageDomains) !== JSON.stringify(PENTEST_COVERAGE_DOMAINS)) {
    throw new Error("workflow coverage domains differ from the exact 18-domain contract");
  }
  const mandatoryStops = [...new Set([
    ...workflow.value.defaultStopConditions,
    ...workflow.value.phases.flatMap((phase) => phase.stopPolicy?.additional || [])
  ])].sort();
  const definedStops = workflow.value.stopConditions.map((stop) => stop.id).sort();
  if (JSON.stringify(mandatoryStops) !== JSON.stringify(definedStops)) {
    throw new Error("workflow mandatory-stop union differs from the defined stop conditions");
  }
  const contractSha256 = canonicalDigest({
    workflowSha256: workflow.sha256,
    catalogSha256: catalog.sha256,
    engagementPolicySha256: policy.sha256
  }, "gate.workflow.contract.v1");
  return {
    value: workflow.value,
    catalog: catalog.value,
    engagementPolicy: policy.value,
    workflowSha256: workflow.sha256,
    catalogSha256: catalog.sha256,
    engagementPolicySha256: policy.sha256,
    contractSha256,
    mandatoryStops
  };
}

function phaseById(definition, id) {
  const phase = definition.value.phases.find((candidate) => candidate.id === id);
  if (!phase) throw new Error(`unknown workflow phase: ${id}`);
  return phase;
}

function effectiveStops(definition, phase) {
  return [...new Set([
    ...(phase.stopPolicy?.inheritDefaultEngagementStops ? definition.mandatoryStops : []),
    ...(phase.stopPolicy?.additional || [])
  ])].sort();
}

function entryEnvelope(entry) {
  const copy = structuredClone(entry);
  delete copy.entrySha256;
  return copy;
}

function entryDigest(entry) {
  return canonicalDigest(entryEnvelope(entry), "gate.workflow.journal-entry.v1");
}

function projectionEnvelope(projection) {
  const copy = structuredClone(projection);
  delete copy.projectionSha256;
  return copy;
}

function sealProjection(projection, paths) {
  projection.projectionSha256 = canonicalDigest(projectionEnvelope(projection), "gate.workflow.projection.v1");
  assertValidDocument(projection, "workflow-instance.schema.json", { paths });
  return projection;
}

function processStartTicks(text) {
  const close = text.lastIndexOf(")");
  if (close === -1) return null;
  const fields = text.slice(close + 2).trim().split(/\s+/u);
  return fields.length > 19 && /^\d+$/u.test(fields[19]) ? fields[19] : null;
}

function currentLockIdentity() {
  if (process.platform !== "linux") throw new Error("workflow mutation locks require Linux process identity support");
  const bootId = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim().toLowerCase();
  const startTimeTicks = processStartTicks(fs.readFileSync(`/proc/${process.pid}/stat`, "utf8"));
  if (!/^[a-f0-9-]{36}$/u.test(bootId) || !startTimeTicks) throw new Error("workflow lock process identity is unavailable");
  return { pid: process.pid, bootId, startTimeTicks };
}

function validLockOwner(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([
    "apiVersion", "bootId", "createdAt", "nonce", "pid", "startTimeTicks"
  ])) return false;
  return value.apiVersion === "gate.workflow-lock/v1" && Number.isSafeInteger(value.pid) && value.pid > 0 &&
    /^[a-f0-9-]{36}$/u.test(value.bootId) && /^\d+$/u.test(value.startTimeTicks) &&
    /^[a-f0-9]{32}$/u.test(value.nonce) && Number.isFinite(Date.parse(value.createdAt));
}

function ownerProvablyDead(owner) {
  if (!validLockOwner(owner)) return false;
  let bootId;
  try { bootId = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim().toLowerCase(); }
  catch { return false; }
  if (owner.bootId !== bootId) return true;
  let stat;
  try { stat = fs.readFileSync(`/proc/${owner.pid}/stat`, "utf8"); }
  catch (error) { return error.code === "ENOENT"; }
  const start = processStartTicks(stat);
  return Boolean(start && start !== owner.startTimeTicks);
}

function retireDeadLock(paths, expectedBytes, owner) {
  if (!ownerProvablyDead(owner)) throw new Error("workflow mutation lock owner is live or cannot be proven dead");
  const script = String.raw`
const fs=require('node:fs');
const file=process.argv[1], expected=Buffer.from(process.argv[2],'base64');
function ticks(s){const c=s.lastIndexOf(')');if(c<0)return null;const f=s.slice(c+2).trim().split(/\s+/u);return f.length>19&&/^\d+$/.test(f[19])?f[19]:null}
let current;try{current=fs.readFileSync(file)}catch(e){process.exit(e.code==='ENOENT'?0:20)}
if(!current.equals(expected))process.exit(21);
let owner;try{owner=JSON.parse(current)}catch{process.exit(22)}
let boot;try{boot=fs.readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim().toLowerCase()}catch{process.exit(23)}
let dead=owner.bootId!==boot;
if(!dead){try{const now=ticks(fs.readFileSync('/proc/'+owner.pid+'/stat','utf8'));dead=Boolean(now&&now!==owner.startTimeTicks)}catch(e){dead=e.code==='ENOENT'}}
if(!dead)process.exit(24);
try{fs.unlinkSync(file)}catch(e){if(e.code!=='ENOENT')process.exit(25)}
`;
  const result = spawnSync("flock", ["--exclusive", "--timeout", "0", paths.workflowLock,
    process.execPath, "-e", script, paths.workflowLock, expectedBytes.toString("base64")], {
    encoding: "utf8",
    timeout: 10_000
  });
  if (result.error || result.status !== 0) {
    throw new Error(`stale workflow lock could not be retired safely${result.status === null ? "" : ` (status ${result.status})`}`);
  }
  syncPrivateDirectory(paths.workflowDirectory, { label: "workflow instance directory" });
}

function acquireLock(paths) {
  const identity = currentLockIdentity();
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const owner = {
      apiVersion: "gate.workflow-lock/v1",
      ...identity,
      nonce: crypto.randomBytes(16).toString("hex"),
      createdAt: new Date().toISOString()
    };
    const bytes = Buffer.from(`${JSON.stringify(owner)}\n`);
    try {
      writePrivateFileExclusive(paths.workflowLock, bytes, { label: "workflow mutation lock" });
      return { owner, bytes };
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      let observed;
      try { observed = readPrivateFileBounded(paths.workflowLock, 4096, null, { label: "workflow mutation lock" }); }
      catch (readError) {
        if (readError.code === "ENOENT") continue;
        throw readError;
      }
      let existing;
      try { existing = JSON.parse(observed.toString("utf8")); }
      catch { throw new Error("workflow mutation lock identity is malformed"); }
      if (!validLockOwner(existing)) throw new Error("workflow mutation lock identity is malformed");
      if (!ownerProvablyDead(existing)) throw new Error("workflow mutation lock is held by a live or indeterminate owner");
      retireDeadLock(paths, observed, existing);
    }
  }
  throw new Error("workflow mutation lock could not be acquired");
}

function releaseLock(paths, lease) {
  const observed = readPrivateFileBounded(paths.workflowLock, 4096, null, { label: "workflow mutation lock" });
  if (!observed.equals(lease.bytes)) throw new Error("workflow mutation lock ownership changed before release");
  fs.unlinkSync(paths.workflowLock);
  syncPrivateDirectory(paths.workflowDirectory, { label: "workflow instance directory" });
}

function ledgerState(projection) {
  const values = Object.values(projection.ledger);
  if (!values.length) return "empty";
  if (values.some((entry) => entry.status === "residual-hold")) return "residual-hold";
  if (values.every((entry) => entry.status === "verified-clean")) return "verified-clean";
  if (values.some((entry) => entry.status === "cleanup-pending")) return "cleanup-pending";
  return "open";
}

function pendingReservations(projection) {
  return Object.values(projection.executionReservations).filter((reservation) =>
    ["reserved", "claimed", "unknown"].includes(reservation.status)
  );
}

function applyEntry(previous, entry, paths) {
  let projection;
  if (entry.type === "workflow.created") {
    if (previous) throw new Error("workflow genesis entry is not first");
    projection = {
      apiVersion: "gate.workflow-instance/v1",
      kind: "WorkflowInstanceProjection",
      instanceId: entry.instanceId,
      createdAt: entry.at,
      definition: structuredClone(entry.payload.definition),
      engagementId: entry.payload.engagementId,
      status: "open",
      appliedSequence: entry.sequence,
      journalHeadSha256: entry.entrySha256,
      activePhase: null,
      phases: {},
      evidence: [],
      coverage: {},
      ledger: {},
      stops: [],
      executionReservations: {},
      budget: null,
      joined: null,
      report: null,
      closedAt: null,
      projectionSha256: "0".repeat(64)
    };
    return sealProjection(projection, paths);
  }
  if (!previous) throw new Error("workflow journal does not begin with genesis");
  projection = structuredClone(previous);
  const payload = entry.payload;
  switch (entry.type) {
    case "phase.started": {
      const record = { ...structuredClone(payload), status: "running", startedAt: entry.at, finishedAt: null };
      if (payload.budget) projection.budget = structuredClone(payload.budget);
      projection.activePhase = structuredClone(record);
      projection.phases[payload.phaseId] = record;
      break;
    }
    case "phase.finished": {
      const prior = projection.phases[payload.phaseId] || {};
      projection.phases[payload.phaseId] = {
        ...prior,
        phaseId: payload.phaseId,
        attemptId: payload.attemptId,
        status: payload.disposition,
        direct: payload.direct,
        rationale: payload.rationale,
        evidenceSha256: [...payload.evidenceSha256],
        finishedAt: entry.at
      };
      if (projection.activePhase?.attemptId === payload.attemptId) projection.activePhase = null;
      break;
    }
    case "evidence.added":
      projection.evidence.push({ ...structuredClone(payload), recordedAt: entry.at, journalEntrySha256: entry.entrySha256 });
      break;
    case "coverage.set":
      projection.coverage[payload.domain] = { ...structuredClone(payload), recordedAt: entry.at };
      break;
    case "ledger.opened":
      if (payload.budget) projection.budget = structuredClone(payload.budget);
      projection.ledger[payload.entryId] = {
        ...structuredClone(payload), status: "open", openedAt: entry.at, openedEntrySha256: entry.entrySha256
      };
      break;
    case "ledger.cleanup-recorded":
      projection.ledger[payload.entryId] = {
        ...projection.ledger[payload.entryId], status: "cleanup-pending",
        cleanupEvidenceSha256: payload.cleanupEvidenceSha256, cleanupAt: entry.at,
        cleanupEntrySha256: entry.entrySha256
      };
      break;
    case "ledger.verified":
      projection.ledger[payload.entryId] = {
        ...projection.ledger[payload.entryId], status: "verified-clean",
        verificationEvidenceSha256: payload.verificationEvidenceSha256, verifiedAt: entry.at,
        verificationEntrySha256: entry.entrySha256
      };
      break;
    case "ledger.held":
      projection.ledger[payload.entryId] = {
        ...projection.ledger[payload.entryId], status: "residual-hold", holdReason: payload.reason, heldAt: entry.at
      };
      projection.status = "recovery-hold";
      projection.activePhase = null;
      break;
    case "stop.triggered":
      projection.stops.push({ ...structuredClone(payload), firedAt: entry.at, journalEntrySha256: entry.entrySha256 });
      projection.status = payload.ledgerState === "empty" || payload.ledgerState === "verified-clean"
        ? "stopped" : "recovery-hold";
      projection.activePhase = null;
      break;
    case "execution.reserved":
      projection.executionReservations[payload.reservationId] = {
        ...structuredClone(payload), status: "reserved", reservedAt: entry.at
      };
      break;
    case "execution.claimed":
      projection.executionReservations[payload.reservationId] = {
        ...projection.executionReservations[payload.reservationId],
        manifestId: payload.manifestId,
        manifestSha256: payload.manifestSha256,
        runId: payload.runId,
        status: "claimed",
        claimedAt: entry.at
      };
      break;
    case "execution.completed": {
      const status = payload.status === "succeeded" ? "completed" : payload.status;
      projection.executionReservations[payload.reservationId] = {
        ...projection.executionReservations[payload.reservationId],
        status,
        runSha256: payload.runSha256,
        resultSha256: payload.resultSha256 || null,
        terminationReason: payload.terminationReason || null,
        completedAt: entry.at
      };
      if (status === "unknown") {
        projection.status = "recovery-hold";
        projection.activePhase = null;
      }
      break;
    }
    case "execution.cancelled":
      projection.executionReservations[payload.reservationId] = {
        ...projection.executionReservations[payload.reservationId], status: "cancelled",
        cancellationReason: payload.reason, cancelledAt: entry.at
      };
      break;
    case "coverage.joined": {
      projection.joined = { ...structuredClone(payload), joinedAt: entry.at };
      const attemptId = `wpa_${entry.entrySha256.slice(0, 32)}`;
      projection.phases["coverage-join"] = {
        phaseId: "coverage-join", attemptId, status: "tested", direct: false,
        rationale: null, evidenceSha256: [payload.coverageSha256, payload.ledgerSha256],
        startedAt: entry.at, finishedAt: entry.at, authority: null
      };
      projection.evidence.push(
        { phaseId: "coverage-join", attemptId, evidenceId: "coverage-disposition-join", claimState: "observed", sensitivity: "private", sha256: payload.coverageSha256, bytes: 0, ref: "journal://coverage", recordedAt: entry.at },
        { phaseId: "coverage-join", attemptId, evidenceId: "state-ledger-reconciliation", claimState: "observed", sensitivity: "restricted", sha256: payload.ledgerSha256, bytes: 0, ref: "journal://ledger", recordedAt: entry.at }
      );
      break;
    }
    case "report.attached": {
      projection.report = { ...structuredClone(payload), attachedAt: entry.at };
      projection.status = "reported";
      const attemptId = `wpa_${entry.entrySha256.slice(0, 32)}`;
      projection.phases["reporting-and-closeout"] = {
        phaseId: "reporting-and-closeout", attemptId, status: "tested", direct: false,
        rationale: null, evidenceSha256: [payload.sha256], startedAt: entry.at, finishedAt: entry.at, authority: null
      };
      break;
    }
    case "workflow.closed":
      projection.status = "closed";
      projection.closedAt = entry.at;
      break;
    default:
      throw new Error(`unsupported workflow journal event: ${entry.type}`);
  }
  projection.appliedSequence = entry.sequence;
  projection.journalHeadSha256 = entry.entrySha256;
  return sealProjection(projection, paths);
}

function parseJournal(paths, maximumBytes = MAX_JOURNAL_BYTES) {
  let bytes;
  try {
    bytes = readPrivateFileBounded(paths.workflowJournal, maximumBytes, null, { label: "authoritative workflow journal" });
  } catch (error) {
    if (error.code === "ENOENT") throw new Error("authoritative workflow journal is missing");
    throw error;
  }
  if (!bytes.length || bytes.at(-1) !== 0x0a) throw new Error("workflow journal is empty or has a truncated tail");
  const lines = bytes.toString("utf8").split("\n");
  lines.pop();
  if (lines.length > MAX_EVENTS) throw new Error(`workflow journal exceeds ${MAX_EVENTS} events`);
  const entries = [];
  let previous = null;
  for (let index = 0; index < lines.length; index += 1) {
    let entry;
    try { entry = JSON.parse(lines[index]); }
    catch { throw new Error(`workflow journal line ${index + 1} is malformed`); }
    assertValidDocument(entry, "workflow-journal-entry.schema.json", { paths });
    if (entry.instanceId !== path.basename(paths.workflowDirectory)) throw new Error(`workflow journal line ${index + 1} has the wrong instance id`);
    if (entry.sequence !== index) throw new Error(`workflow journal sequence is not contiguous at ${index}`);
    if (entry.previousEntrySha256 !== (previous?.entrySha256 || null)) throw new Error(`workflow journal chain is broken at ${index}`);
    if (entry.entrySha256 !== entryDigest(entry)) throw new Error(`workflow journal entry digest is invalid at ${index}`);
    if (previous && entry.definitionSha256 !== previous.definitionSha256) throw new Error("workflow definition digest changes inside the journal");
    entries.push(entry);
    previous = entry;
  }
  if (!entries.length) throw new Error("workflow journal has no genesis entry");
  return entries;
}

function replay(entries, paths) {
  let projection = null;
  for (const entry of entries) {
    projection = applyEntry(projection, entry, paths);
  }
  return { projection };
}

function sameProjection(left, right) {
  return canonicalDigest(left, "gate.workflow.projection-compare.v1") ===
    canonicalDigest(right, "gate.workflow.projection-compare.v1");
}

function persistProjection(paths, projection) {
  writePrivateFileAtomic(paths.workflowProjection, `${JSON.stringify(projection, null, 2)}\n`, {
    label: "workflow instance projection"
  });
  syncPrivateDirectory(paths.workflowDirectory, { label: "workflow instance directory" });
}

function loadProjection(paths, {
  repair = true,
  requireCurrentContract = true,
  journalMaximumBytes = MAX_JOURNAL_BYTES,
  projectionMaximumBytes = MAX_PROJECTION_BYTES
} = {}) {
  const entries = parseJournal(paths, journalMaximumBytes);
  const played = replay(entries, paths);
  let observed;
  try {
    observed = JSON.parse(readPrivateFileBounded(
      paths.workflowProjection, projectionMaximumBytes, "utf8", { label: "workflow instance projection" }
    ));
  } catch (error) {
    if (!repair) throw error;
    if (error instanceof SyntaxError) throw new Error("workflow instance projection is malformed");
    if (error.code === "ENOENT") {
      writePrivateFileExclusive(paths.workflowProjection, `${JSON.stringify(played.projection, null, 2)}\n`, {
        label: "workflow instance projection"
      });
      return { ...played, entries, repaired: true };
    }
    throw error;
  }
  assertValidDocument(observed, "workflow-instance.schema.json", { paths });
  if (observed.instanceId !== path.basename(paths.workflowDirectory)) throw new Error("workflow projection has the wrong instance id");
  const observedDigest = canonicalDigest(projectionEnvelope(observed), "gate.workflow.projection.v1");
  if (observed.projectionSha256 !== observedDigest) throw new Error("workflow projection digest is invalid");
  if (observed.appliedSequence > played.projection.appliedSequence) throw new Error("workflow projection is ahead of its authoritative journal");
  const expectedPrefix = replay(entries.slice(0, observed.appliedSequence + 1), paths).projection;
  if (!expectedPrefix || observed.journalHeadSha256 !== expectedPrefix.journalHeadSha256) {
    throw new Error("workflow projection does not name an exact authoritative journal prefix");
  }
  if (!sameProjection(observed, expectedPrefix)) {
    if (observed.appliedSequence === played.projection.appliedSequence) {
      throw new Error("workflow projection differs from the journal at the same head");
    }
    throw new Error("workflow projection is not an exact authoritative journal prefix");
  }
  let repaired = false;
  if (observed.appliedSequence < played.projection.appliedSequence) {
    if (!repair) throw new Error("workflow projection is behind the authoritative journal");
    persistProjection(paths, played.projection);
    repaired = true;
  }
  if (requireCurrentContract) {
    const definition = loadDefinition(paths);
    if (played.projection.definition.sha256 !== definition.contractSha256 ||
      played.projection.definition.workflowSha256 !== definition.workflowSha256 ||
      played.projection.definition.catalogSha256 !== definition.catalogSha256 ||
      played.projection.definition.engagementPolicySha256 !== definition.engagementPolicySha256 ||
      JSON.stringify(played.projection.definition.coverageDomains) !== JSON.stringify(PENTEST_COVERAGE_DOMAINS) ||
      JSON.stringify([...played.projection.definition.mandatoryStops].sort()) !== JSON.stringify(definition.mandatoryStops)) {
      throw new Error("workflow instance definition no longer matches the installed contract");
    }
  }
  return { ...played, entries, repaired };
}

function appendEntry(paths, definitionSha256, previous, type, payload, options = {}) {
  const requestId = options.requestId || newId("wreq");
  if (!REQUEST_PATTERN.test(requestId)) throw new Error("workflow request id is invalid");
  const requestSha256 = options.requestSha256 || canonicalDigest({ type, payload }, "gate.workflow.request.v1");
  const repeated = options.entries?.find((entry) => entry.requestId === requestId);
  if (repeated) {
    if (repeated.requestSha256 !== requestSha256) throw new Error("workflow request id was reused with different content");
    return { entry: repeated, replayed: true };
  }
  if (options.expectedSequence !== undefined && Number(options.expectedSequence) !== previous.sequence) {
    throw new Error(`workflow sequence changed: expected ${options.expectedSequence}, observed ${previous.sequence}`);
  }
  if (options.expectedHead !== undefined && String(options.expectedHead) !== previous.entrySha256) {
    throw new Error("workflow journal head changed before mutation");
  }
  if (previous.sequence + 1 >= MAX_EVENTS) throw new Error(`workflow journal exceeds ${MAX_EVENTS} events`);
  const entry = {
    apiVersion: "gate.workflow-journal/v1",
    kind: "WorkflowJournalEntry",
    instanceId: path.basename(paths.workflowDirectory),
    sequence: previous.sequence + 1,
    at: options.at
      ? new Date(typeof options.at === "function" ? options.at() : options.at).toISOString()
      : options.now
        ? new Date(options.now()).toISOString()
        : new Date().toISOString(),
    requestId,
    requestSha256,
    type,
    definitionSha256,
    previousEntrySha256: previous.entrySha256,
    payload,
    entrySha256: "0".repeat(64)
  };
  entry.entrySha256 = entryDigest(entry);
  assertValidDocument(entry, "workflow-journal-entry.schema.json", { paths });
  const line = `${JSON.stringify(entry)}\n`;
  const journalSize = fs.statSync(paths.workflowJournal).size;
  if (journalSize + Buffer.byteLength(line) > MAX_JOURNAL_BYTES) throw new Error("workflow journal would exceed its byte limit");
  const preview = options.projection ? applyEntry(options.projection, entry, paths) : null;
  if (preview && Buffer.byteLength(`${JSON.stringify(preview, null, 2)}\n`) > MAX_PROJECTION_BYTES) {
    throw new Error("workflow projection would exceed its byte limit");
  }
  appendPrivateFile(paths.workflowJournal, line, {
    encoding: "utf8", sync: true, label: "authoritative workflow journal"
  });
  syncPrivateDirectory(paths.workflowDirectory, { label: "workflow instance directory" });
  return { entry, replayed: false, preview };
}

function mutate(id, options, planner) {
  const paths = workflowPaths(options?.paths || options, id);
  ensureWorkflowRoot(paths);
  ensureInstanceDirectories(paths, false);
  const owner = acquireLock(paths);
  let primaryError = null;
  try {
    const loaded = loadProjection(paths);
    if (options.requestId) {
      const repeated = loaded.entries.find((entry) => entry.requestId === options.requestId);
      if (repeated) {
        if (!options.requestSha256 || repeated.requestSha256 !== options.requestSha256) {
          throw new Error("workflow request id was reused with different content");
        }
        return { projection: loaded.projection, entry: repeated, replayed: true, paths };
      }
    }
    if (options.expectedSequence !== undefined && Number(options.expectedSequence) !== loaded.projection.appliedSequence) {
      throw new Error(`workflow sequence changed: expected ${options.expectedSequence}, observed ${loaded.projection.appliedSequence}`);
    }
    if (options.expectedHead !== undefined && String(options.expectedHead) !== loaded.projection.journalHeadSha256) {
      throw new Error("workflow journal head changed before mutation");
    }
    const planned = planner(loaded.projection, loaded.entries, paths);
    if (planned.noop) {
      return { projection: loaded.projection, entry: planned.entry, replayed: true, paths };
    }
    const appended = appendEntry(paths, loaded.projection.definition.sha256, loaded.entries.at(-1),
      planned.type, planned.payload, { ...options, entries: loaded.entries, projection: loaded.projection });
    if (appended.replayed) return { projection: loaded.projection, entry: appended.entry, replayed: true, paths };
    const projection = appended.preview || applyEntry(loaded.projection, appended.entry, paths);
    persistProjection(paths, projection);
    return { projection, entry: appended.entry, replayed: false, paths };
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    try { releaseLock(paths, owner); }
    catch (error) { if (!primaryError) throw error; }
  }
}

function allocationStatus(projection, active) {
  if (!active?.envelope) return null;
  const additive = ["maxMinutes", "maxRequests", "maxTotalTokens", "maxEvidenceBytes"];
  const reservations = Object.values(projection.executionReservations).filter((reservation) =>
    reservation.phaseAttemptId === active.attemptId && reservation.status !== "cancelled"
  );
  const conservativelyReserved = Object.fromEntries(additive.map((field) => [
    field, reservations.reduce((total, reservation) => total + Number(reservation.envelope?.[field] || 0), 0)
  ]));
  return {
    admitted: Object.fromEntries([
      "maxMinutes", "maxRequests", "maxRatePerSecond", "maxParallel", "maxInputTokens",
      "maxOutputTokens", "maxTotalTokens", "maxEvidenceBytes", "maxSpend"
    ].map((field) => [field, active.envelope[field]])),
    conservativelyReserved,
    remaining: Object.fromEntries(additive.map((field) => [
      field, Math.max(0, Number(active.envelope[field] || 0) - conservativelyReserved[field])
    ])),
    controls: { ...active.envelope.controls }
  };
}

function compactStatus(projection, definition, extra = {}) {
  const active = projection.activePhase;
  const { updatedAt = null, ...journalExtra } = extra;
  const phaseCounts = { running: 0, tested: 0, "not-applicable": 0, blocked: 0, untested: 0, pending: 0 };
  for (const phase of definition.value.phases) {
    const status = projection.phases[phase.id]?.status || "pending";
    phaseCounts[status] = (phaseCounts[status] || 0) + 1;
  }
  const allStops = projection.stops;
  const visibleStops = allStops.slice(-MAX_COMPACT_STOPS).map((stop) => ({
    condition: stop.condition, phaseId: stop.phaseId, firedAt: stop.firedAt
  }));
  const result = {
    ok: true,
    instanceId: projection.instanceId,
    status: projection.status,
    updatedAt,
    journal: { sequence: projection.appliedSequence, headSha256: projection.journalHeadSha256, ...journalExtra },
    contract: {
      id: projection.definition.id,
      version: projection.definition.version,
      sha256: projection.definition.sha256,
      coverageDomainCount: projection.definition.coverageDomains.length,
      mandatoryStopCount: projection.definition.mandatoryStops.length
    },
    activePhase: active ? {
      id: active.phaseId,
      attemptId: active.attemptId,
      lane: active.lane,
      effectClass: active.effectClass,
      toolId: active.toolId,
      admissionSha256: active.admissionSha256,
      handoffSha256: active.handoffSha256,
      authorityReceiptSha256: active.authority?.receiptSha256 || null,
      envelope: active.envelope,
      allocation: allocationStatus(projection, active),
      stopConditions: active.effectiveStops
    } : null,
    phaseCounts,
    coverage: { recorded: Object.keys(projection.coverage).length, required: PENTEST_COVERAGE_DOMAINS.length },
    ledger: { state: ledgerState(projection), entries: Object.keys(projection.ledger).length },
    executionReservations: pendingReservations(projection).map((reservation) => ({
      id: reservation.reservationId, status: reservation.status, phaseId: reservation.phaseId
    })),
    stopCount: allStops.length,
    omittedStopCount: allStops.length - visibleStops.length,
    stops: visibleStops,
    unresolvedClaims: projection.evidence.filter((record) => record.claimState === "unverified").length,
    evidenceCount: projection.evidence.length,
    joined: Boolean(projection.joined),
    reportSha256: projection.report?.sha256 || null
  };
  while (Buffer.byteLength(`${JSON.stringify(result, null, 2)}\n`) >= MAX_COMPACT_STATUS_BYTES && result.stops.length) {
    result.stops.shift();
    result.omittedStopCount += 1;
  }
  if (Buffer.byteLength(`${JSON.stringify(result, null, 2)}\n`) >= MAX_COMPACT_STATUS_BYTES) {
    throw new Error(`compact workflow status exceeds ${MAX_COMPACT_STATUS_BYTES} bytes`);
  }
  return result;
}

function fileIdentity(file) {
  const stat = fs.lstatSync(file, { bigint: true });
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n) throw new Error("workflow file identity is unsafe");
  return `${stat.dev}:${stat.ino}:${stat.size}:${stat.mtimeNs}:${stat.ctimeNs}`;
}

function lockExists(file) {
  try { fs.lstatSync(file); return true; }
  catch (error) { if (error.code === "ENOENT") return false; throw error; }
}

function degradedFleetInstance(instanceId) {
  return { instanceId, status: "unknown", activePhase: null, journalSequence: null, reservations: null, stops: null, health: "degraded" };
}

function fastFleetInstance(paths, instanceId) {
  const instancePaths = workflowPaths(paths, instanceId);
  try {
    securePrivateDirectory(instancePaths.workflowDirectory, { create: false, label: `private workflow instance ${instanceId}` });
    if (lockExists(instancePaths.workflowLock)) return degradedFleetInstance(instanceId);
    const projectionIdentity = fileIdentity(instancePaths.workflowProjection);
    const journalIdentity = fileIdentity(instancePaths.workflowJournal);
    const loaded = loadProjection(instancePaths, {
      repair: false, requireCurrentContract: false,
      journalMaximumBytes: MAX_FLEET_JOURNAL_BYTES,
      projectionMaximumBytes: MAX_FLEET_PROJECTION_BYTES
    });
    const projection = loaded.projection;
    if (lockExists(instancePaths.workflowLock) || fileIdentity(instancePaths.workflowProjection) !== projectionIdentity ||
      fileIdentity(instancePaths.workflowJournal) !== journalIdentity) throw new Error("workflow state changed during fast status");
    const active = projection.activePhase;
    return {
      instanceId,
      status: projection.status,
      activePhase: active ? {
        id: active.phaseId, lane: active.lane, effectClass: active.effectClass, toolId: active.toolId,
        envelopeControls: active.envelope ? { ...active.envelope.controls } : null
      } : null,
      journalSequence: projection.appliedSequence,
      reservations: pendingReservations(projection).length,
      stops: projection.stops.length,
      health: "bounded-replay-verified"
    };
  } catch {
    return degradedFleetInstance(instanceId);
  }
}

export function workflowFleetStatus(options = {}) {
  const paths = workflowPaths(options.paths || options);
  if (options.runtimeEnsured) securePrivateDirectory(paths.workflows, { label: "private workflow root" });
  else ensureWorkflowRoot(paths);
  const discoveredNames = [];
  let discoveryTruncated = false;
  const directory = fs.opendirSync(paths.workflows);
  try {
    while (discoveredNames.length <= MAX_FLEET_DISCOVERY) {
      const entry = directory.readSync();
      if (!entry) break;
      discoveredNames.push(entry.name);
    }
    discoveryTruncated = discoveredNames.length > MAX_FLEET_DISCOVERY;
  } finally { directory.closeSync(); }
  const names = discoveredNames.slice(0, MAX_FLEET_DISCOVERY).sort();
  const selected = names.slice(0, MAX_FLEET_SCAN);
  const instances = [];
  let invalidNames = 0;
  for (const name of selected) {
    if (!ID_PATTERN.test(name)) { invalidNames += 1; continue; }
    instances.push(fastFleetInstance(paths, name));
  }
  const scanned = selected.length;
  const discovered = discoveryTruncated ? MAX_FLEET_DISCOVERY + 1 : names.length;
  const omitted = Math.max(0, discovered - scanned);
  const counts = {
    total: discovered,
    active: instances.filter((instance) => instance.activePhase).length,
    open: instances.filter((instance) => instance.status === "open").length,
    stopped: instances.filter((instance) => instance.status === "stopped").length,
    "recovery-hold": instances.filter((instance) => instance.status === "recovery-hold").length,
    reported: instances.filter((instance) => instance.status === "reported").length,
    closed: instances.filter((instance) => instance.status === "closed").length,
    degraded: instances.filter((instance) => instance.health === "degraded").length + invalidNames,
    unknown: instances.filter((instance) => instance.status === "unknown").length + invalidNames + omitted
  };
  return {
    counts, instances,
    scan: { discovered, scanned, omitted, complete: !discoveryTruncated && omitted === 0 && counts.degraded === 0, truncated: discoveryTruncated || omitted > 0 }
  };
}

function phaseTerminal(projection, phaseId) {
  return TERMINAL_DISPOSITIONS.has(projection.phases[phaseId]?.status);
}

function phaseSatisfied(projection, phaseId) {
  return projection.phases[phaseId]?.status === "tested";
}

function assertDependencies(projection, phase, definition) {
  const all = phase.dependsOn?.allOf || [];
  const any = phase.dependsOn?.anyOf || [];
  const missingAll = all.filter((id) => !phaseSatisfied(projection, id));
  if (missingAll.length) throw new Error(`phase dependencies are incomplete: ${missingAll.join(", ")}`);
  if (any.length && !any.some((id) => phaseSatisfied(projection, id))) {
    throw new Error(`phase requires one completed dependency: ${any.join(", ")}`);
  }
  if (phase.id === definition.value.coverageJoin.phaseId) throw new Error("use gate workflow join for the coverage barrier");
}

function ledgerGuardMatches(guard, projection) {
  const state = ledgerState(projection);
  if (guard === "any") return true;
  if (guard === "nonempty") return !CLEAN_LEDGER_STATES.has(state);
  return guard === state;
}

function transitionKind(projection, sourcePhase) {
  const source = projection.phases[sourcePhase];
  const stopped = [...projection.stops].reverse().find((record) =>
    record.phaseId === sourcePhase && (!source?.attemptId || record.attemptId === source.attemptId)
  );
  if (stopped) return "stop";
  const failed = Object.values(projection.executionReservations).some((reservation) =>
    reservation.phaseId === sourcePhase && (!source?.attemptId || reservation.phaseAttemptId === source.attemptId) &&
    ["failed", "unknown"].includes(reservation.status)
  );
  return failed || (source && !source.direct && ["blocked", "untested"].includes(source.status)) ? "failure" : "normal";
}

function applicabilityMatches(guard, projection, sourcePhase) {
  if (guard === "any" || guard === "all-required-dispositioned") return true;
  const status = projection.phases[sourcePhase]?.status;
  if (guard === "applicable") return status === "tested" || status === "running" || transitionKind(projection, sourcePhase) === "failure";
  return status === guard;
}

function transitionFor(projection, definition, sourcePhase, phase, handoffId) {
  if (!sourcePhase) {
    if (phase.id !== "authorization-and-roe") throw new Error("a non-root phase requires an exact source phase");
    return null;
  }
  const source = phaseById(definition, sourcePhase);
  const kind = transitionKind(projection, sourcePhase);
  const candidates = source.transitions.filter((transition) => transition.to === phase.id && transition.kind === kind &&
    (!handoffId || transition.handoffId === handoffId) && applicabilityMatches(transition.guard.applicability, projection, sourcePhase) &&
    ledgerGuardMatches(transition.guard.ledger, projection));
  if (candidates.length !== 1) {
    throw new Error(`workflow transition from ${sourcePhase} to ${phase.id} is missing or ambiguous for ${kind}`);
  }
  if (handoffId && candidates[0].handoffId !== handoffId) throw new Error("workflow handoff id does not match the transition");
  if (kind === "normal" && !phaseTerminal(projection, sourcePhase)) throw new Error(`source phase is not complete: ${sourcePhase}`);
  return candidates[0];
}

function parseExternalJson(bytes, schema, paths, label) {
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); }
  catch { throw new Error(`${label} is malformed JSON`); }
  assertValidDocument(value, schema, { paths });
  return value;
}

function saveContentAddressed(directory, digest, bytes, label) {
  const file = path.join(directory, `${digest}.json`);
  try { writePrivateFileExclusive(file, bytes, { label }); }
  catch (error) {
    if (error.code !== "EEXIST") throw error;
    const observed = readPrivateFileBounded(file, Math.max(bytes.length, 1), null, { label });
    if (!observed.equals(bytes)) throw new Error(`${label} digest collision or replacement detected`);
  }
  return file;
}

function validateEnvelope(envelope) {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) throw new Error("workflow admission envelope is missing");
  for (const field of ["maxMinutes", "maxRequests", "maxRatePerSecond", "maxParallel", "maxInputTokens", "maxOutputTokens", "maxTotalTokens", "maxEvidenceBytes"]) {
    if (!Number.isFinite(Number(envelope[field])) || Number(envelope[field]) < 0) throw new Error(`workflow admission envelope ${field} is invalid`);
  }
  if (Number(envelope.maxMinutes) <= 0 || Number(envelope.maxRequests) <= 0 || Number(envelope.maxParallel) <= 0 ||
    Number(envelope.maxRatePerSecond) <= 0 || Number(envelope.maxTotalTokens) <= 0 || Number(envelope.maxEvidenceBytes) <= 0) {
    throw new Error("workflow admission envelope active limits must be positive");
  }
  if (Number(envelope.maxInputTokens) + Number(envelope.maxOutputTokens) > Number(envelope.maxTotalTokens)) {
    throw new Error("workflow admission token allocations exceed the total token envelope");
  }
  const controlValues = new Set(["enforced", "measured-only", "unavailable"]);
  for (const control of ["wallTime", "requests", "rate", "parallel", "tokens", "evidenceBytes", "spend"]) {
    if (!controlValues.has(envelope.controls?.[control])) throw new Error(`workflow admission envelope control ${control} is invalid`);
  }
}

function admissionAction(value) {
  return value.action || value.actionClass;
}

function validateAdmission(paths, projection, definition, phase, bytesOrFile, options = {}) {
  const bytes = Buffer.isBuffer(bytesOrFile)
    ? bytesOrFile
    : stableFileBytes(bytesOrFile, 2 * 1024 * 1024, "workflow admission file");
  const value = parseExternalJson(bytes, "workflow-admission.schema.json", paths, "workflow admission file");
  const digest = sha256(bytes);
  if (value.instanceId !== projection.instanceId || value.workflowDefinitionSha256 !== projection.definition.sha256 ||
    value.phaseId !== phase.id) throw new Error("workflow admission does not bind the active workflow contract and phase");
  if (Date.now() < Date.parse(value.issuedAt) ||
    (Date.now() >= Date.parse(value.expiresAt) && !options.allowExpiredTeardown)) {
    throw new Error("workflow admission is not currently valid");
  }
  const mapping = phase.toolMappings.find((candidate) => candidate.toolId === value.toolId);
  if (!mapping) throw new Error("workflow admission tool is not mapped to the phase");
  const mappingSha256 = canonicalDigest(mapping, "gate.workflow.tool-mapping.v1");
  if (value.toolMappingSha256 !== mappingSha256) throw new Error("workflow admission tool mapping digest is invalid");
  if (value.adapterConstraint !== mapping.adapterConstraint) throw new Error("workflow admission adapter constraint differs from the mapped adapter");
  if (mapping.mode !== "offline-only" && phase.targetContact && !String(mapping.adapterConstraint || "").trim()) {
    throw new Error("target-contact admission requires a reviewed adapter constraint");
  }
  validateEnvelope(value.envelope);
  const action = admissionAction(value);
  const check = checkEngagement(value.authority.engagementId, {
    target: value.target,
    action,
    maxMinutes: value.envelope.maxMinutes,
    estimatedRequests: value.envelope.maxRequests,
    maxParallel: value.envelope.maxParallel,
    maxRatePerSecond: value.envelope.maxRatePerSecond,
    maxTokens: value.envelope.maxTotalTokens
  }, { paths });
  let binding = check.executionBinding;
  if (!check.allowed) {
    const teardownReasons = new Set([
      "authorization expired",
      "declared duration extends beyond the authorization window"
    ]);
    if (!options.allowExpiredTeardown || check.reasons.some((reason) => !teardownReasons.has(reason))) {
      throw new Error(`workflow admission authority failed: ${check.reasons.join("; ")}`);
    }
    const sourceAuthority = options.sourceAuthority;
    if (!sourceAuthority || canonicalDigest(sourceAuthority) !== canonicalDigest(value.authority)) {
      throw new Error("expired teardown admission does not retain the source authority binding");
    }
    const receiptFile = path.join(paths.authorizations, `${value.authority.engagementId}.receipt.json`);
    const receiptBytes = readPrivateFileBounded(receiptFile, 64 * 1024, null, { label: "operator authorization receipt" });
    if (sha256(receiptBytes) !== value.authority.receiptSha256) {
      throw new Error("expired teardown authority receipt byte identity changed");
    }
    binding = {
      ...value.authority,
      target: { value: value.target },
      action,
      permittedTools: [...check.engagement.scope.permittedTools]
    };
  } else {
    for (const [field, expected] of [
      ["engagementId", value.authority.engagementId],
      ["planSha256", value.authority.planSha256],
      ["envelopeSha256", value.authority.envelopeSha256],
      ["receiptSha256", value.authority.receiptSha256],
      ["authorizationValidUntil", value.authority.authorizationValidUntil]
    ]) if (binding[field] !== expected) throw new Error(`workflow admission authority binding changed: ${field}`);
  }
  if (projection.engagementId && projection.engagementId !== value.authority.engagementId) {
    throw new Error("workflow admission belongs to a different engagement");
  }
  if (binding.target.value !== value.target || binding.action !== action || !binding.permittedTools.includes(value.toolId)) {
    throw new Error("workflow admission target, action, or tool is outside current authority");
  }
  const limits = check.engagement.limits;
  const budget = structuredClone(projection.budget || {
    total: { maxMinutes: limits.maxMinutes, maxRequests: limits.maxRequests, maxTotalTokens: limits.maxTokens },
    used: { maxMinutes: 0, maxRequests: 0, maxTotalTokens: 0 },
    cleanup: { maxMinutes: Math.ceil(limits.maxMinutes / 10), maxRequests: Math.ceil(limits.maxRequests / 10), maxTotalTokens: Math.ceil(limits.maxTokens / 10) },
    reporting: { maxMinutes: Math.ceil(limits.maxMinutes / 10), maxRequests: Math.ceil(limits.maxRequests / 10), maxTotalTokens: Math.ceil(limits.maxTokens / 10) }
  });
  for (const field of Object.keys(budget.total)) {
    const protectedAmount = budget.reporting[field] + (TEARDOWN_PHASES.has(phase.id) ? 0 : budget.cleanup[field]);
    if (budget.used[field] + value.envelope[field] > budget.total[field] - protectedAmount) {
      throw new Error(`workflow ${field} exceeds remaining capacity with protected closeout reserves`);
    }
    budget.used[field] += value.envelope[field];
  }
  return {
    value,
    digest,
    mappingSha256,
    budget,
    action,
    authority: {
      engagementId: binding.engagementId,
      planSha256: binding.planSha256,
      envelopeSha256: binding.envelopeSha256,
      receiptSha256: binding.receiptSha256,
      authorizationValidUntil: binding.authorizationValidUntil,
      checkedAt: value.authority.checkedAt
    }
  };
}

function validateHandoff(paths, projection, definition, phase, transition, admission, bytesOrFile, options = {}) {
  const bytes = Buffer.isBuffer(bytesOrFile)
    ? bytesOrFile
    : stableFileBytes(bytesOrFile, 2 * 1024 * 1024, "workflow handoff file");
  const value = parseExternalJson(bytes, "workflow-handoff.schema.json", paths, "workflow handoff file");
  const digest = sha256(bytes);
  const source = projection.phases[transition.__fromPhase];
  const expected = [
    ["instanceId", projection.instanceId],
    ["workflowDefinitionSha256", projection.definition.sha256],
    ["handoffId", transition.handoffId],
    ["fromPhase", transition.__fromPhase],
    ["toPhase", phase.id],
    ["sourceAttemptId", source?.attemptId],
    ["admissionSha256", admission.digest],
    ["toolId", admission.value.toolId],
    ["toolMappingSha256", admission.mappingSha256],
    ["target", admission.value.target],
    ["action", admission.action],
    ["adapterConstraint", admission.value.adapterConstraint],
    ["policyId", definition.value.handoffs.find((item) => item.id === transition.handoffId)?.policyId],
    ["type", definition.value.handoffs.find((item) => item.id === transition.handoffId)?.type]
  ];
  for (const [field, wanted] of expected) {
    if (value[field] !== wanted) throw new Error(`workflow handoff binding differs: ${field}`);
  }
  if (canonicalDigest(value.authority) !== canonicalDigest(admission.authority)) {
    throw new Error("workflow handoff authority differs from admission");
  }
  if (canonicalDigest(value.envelope) !== canonicalDigest(admission.value.envelope)) {
    throw new Error("workflow handoff envelope differs from admission");
  }
  if (JSON.stringify([...value.mandatoryStopConditions].sort()) !==
    JSON.stringify([...projection.definition.mandatoryStops].sort())) {
    throw new Error("workflow handoff mandatory stop set is incomplete");
  }
  const knownEvidence = new Map(projection.evidence.filter((record) => record.phaseId === transition.__fromPhase)
    .map((record) => [record.sha256, record]));
  if (!value.priorEvidence.every((record) => knownEvidence.get(record.sha256)?.evidenceId === record.evidenceId &&
    knownEvidence.get(record.sha256)?.claimState === record.claimState)) {
    throw new Error("workflow handoff references unknown or mismatched source evidence");
  }
  if (Date.now() < Date.parse(value.issuedAt) ||
    (Date.now() >= Date.parse(value.expiresAt) && !options.allowExpiredTeardown)) {
    throw new Error("workflow handoff is not currently valid");
  }
  return { value, digest };
}

function recheckAdmission(paths, phaseRecord, { completion = false } = {}) {
  if (!phaseRecord?.admissionSha256 || !phaseRecord.authority || !phaseRecord.envelope) {
    throw new Error("target-contact phase has no durable admission binding");
  }
  const file = path.join(paths.workflowAdmissions, `${phaseRecord.admissionSha256}.json`);
  const bytes = readPrivateFileBounded(file, 2 * 1024 * 1024, null, { label: "workflow admission" });
  if (sha256(bytes) !== phaseRecord.admissionSha256) throw new Error("workflow admission digest changed");
  const admission = parseExternalJson(bytes, "workflow-admission.schema.json", paths, "workflow admission");
  if (Date.now() < Date.parse(admission.issuedAt) ||
    (Date.now() >= Date.parse(admission.expiresAt) && !(completion && phaseRecord.preauthorizedTeardown))) {
    throw new Error("workflow admission is not currently valid");
  }
  const check = checkEngagement(phaseRecord.authority.engagementId, {
    target: phaseRecord.target,
    action: phaseRecord.action,
    maxMinutes: completion ? undefined : phaseRecord.envelope.maxMinutes,
    estimatedRequests: phaseRecord.envelope.maxRequests,
    maxParallel: phaseRecord.envelope.maxParallel,
    maxRatePerSecond: phaseRecord.envelope.maxRatePerSecond,
    maxTokens: phaseRecord.envelope.maxTotalTokens
  }, { paths });
  if (!check.allowed) {
    if (!completion || !phaseRecord.preauthorizedTeardown || check.reasons.some((reason) => !["authorization expired", "declared duration extends beyond the authorization window"].includes(reason))) {
      throw new Error(`workflow phase authority failed: ${check.reasons.join("; ")}`);
    }
    const receipt = readPrivateFileBounded(path.join(paths.authorizations, `${phaseRecord.authority.engagementId}.receipt.json`), 64 * 1024, null, { label: "operator authorization receipt" });
    if (sha256(receipt) !== phaseRecord.authority.receiptSha256) throw new Error("workflow phase authority receipt byte identity changed");
    return phaseRecord.authority;
  }
  if (check.executionBinding.receiptSha256 !== phaseRecord.authority.receiptSha256) {
    throw new Error("workflow phase authority receipt byte identity changed");
  }
  return check.executionBinding;
}

function assertDirectMutationAllowed(projection, operation) {
  if (projection.status !== "open") throw new Error(`workflow status ${projection.status} cannot ${operation}`);
}

export function createWorkflowInstance(id, input = {}, options = {}) {
  if (input.definitionId !== undefined) throw new Error("alternate workflow definitions are unsupported");
  const instanceId = requireId(id);
  const requestId = options.requestId || newId("wreq");
  if (!REQUEST_PATTERN.test(requestId)) throw new Error("workflow request id is invalid");
  const paths = workflowPaths(options.paths || options, instanceId);
  ensureWorkflowRoot(paths);
  let createdDirectory = false;
  try {
    fs.mkdirSync(paths.workflowDirectory, { mode: 0o700 });
    createdDirectory = true;
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
  }
  ensureInstanceDirectories(paths, true);
  const definition = loadDefinition(paths);
  const engagementId = input.engagementId === undefined || input.engagementId === null
    ? null : requireId(input.engagementId, "engagement id");
  const requestSha256 = options.requestSha256 || canonicalDigest({
    operation: "workflow.new",
    input: { instanceId, definitionId: definition.value.metadata.id, engagementId }
  }, "gate.workflow.request.v1");
  const owner = acquireLock(paths);
  let primaryError = null;
  try {
    if (!createdDirectory && fs.existsSync(paths.workflowJournal)) {
      const loaded = loadProjection(paths);
      const genesis = loaded.entries[0];
      if (genesis.requestId !== requestId || genesis.requestSha256 !== requestSha256) {
        throw new Error(`workflow instance already exists: ${instanceId}`);
      }
      return compactStatus(loaded.projection, definition, {
        repaired: loaded.repaired, updatedAt: loaded.entries.at(-1)?.at || null
      });
    }
    if (fs.existsSync(paths.workflowProjection)) throw new Error("incomplete workflow scaffold contains a projection without a journal");
    const unexpected = fs.readdirSync(paths.workflowDirectory).filter((name) =>
      !new Set([".lock", "admissions", "handoffs", "evidence", "reports"]).has(name)
    );
    if (unexpected.length) throw new Error("incomplete workflow scaffold contains unexpected entries");
    const now = options.now ? new Date(options.now()).toISOString() : new Date().toISOString();
    const entry = {
      apiVersion: "gate.workflow-journal/v1",
      kind: "WorkflowJournalEntry",
      instanceId,
      sequence: 0,
      at: now,
      requestId,
      requestSha256,
      type: "workflow.created",
      definitionSha256: definition.contractSha256,
      previousEntrySha256: null,
      payload: {
        engagementId,
        definition: {
          id: definition.value.metadata.id,
          version: definition.value.metadata.version,
          sha256: definition.contractSha256,
          workflowSha256: definition.workflowSha256,
          catalogSha256: definition.catalogSha256,
          engagementPolicySha256: definition.engagementPolicySha256,
          coverageDomains: [...definition.value.coverageDomains],
          mandatoryStops: [...definition.mandatoryStops]
        }
      },
      entrySha256: "0".repeat(64)
    };
    entry.entrySha256 = entryDigest(entry);
    assertValidDocument(entry, "workflow-journal-entry.schema.json", { paths });
    writePrivateFileExclusive(paths.workflowJournal, `${JSON.stringify(entry)}\n`, { label: "authoritative workflow journal" });
    const projection = applyEntry(null, entry, paths);
    writePrivateFileExclusive(paths.workflowProjection, `${JSON.stringify(projection, null, 2)}\n`, { label: "workflow instance projection" });
    syncPrivateDirectory(paths.workflowDirectory, { label: "workflow instance directory" });
    return compactStatus(projection, definition, { repaired: false, updatedAt: now });
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    try { releaseLock(paths, owner); } catch (error) { if (!primaryError) throw error; }
  }
}

export function workflowStatus(id, options = {}) {
  let paths;
  let owner = null;
  let result;
  try {
    paths = workflowPaths(options.paths || options, id);
    ensureWorkflowRoot(paths);
    ensureInstanceDirectories(paths, false);
    owner = acquireLock(paths);
    const loaded = loadProjection(paths, { repair: true, requireCurrentContract: true });
    const definition = loadDefinition(paths);
    result = compactStatus(loaded.projection, definition, {
      repaired: loaded.repaired, updatedAt: loaded.entries.at(-1)?.at || null
    });
  } catch (error) {
    const blocker = String(error?.message || "workflow status is unavailable").replace(/[\u0000\r\n]+/gu, " ").slice(0, 500);
    result = { ok: false, instanceId: String(id || ""), status: "blocked", blocker };
  } finally {
    if (owner) {
      try { releaseLock(paths, owner); }
      catch (error) {
        const blocker = String(error?.message || "workflow lock release failed").replace(/[\u0000\r\n]+/gu, " ").slice(0, 500);
        result = { ok: false, instanceId: String(id || ""), status: "blocked", blocker };
      }
    }
  }
  return result;
}

function requireConfirmationPreconditions(projection, options, label) {
  if (options.expectedSequence === undefined || options.expectedHead === undefined) {
    throw new Error(`${label} requires the exact --expected-sequence and --expected-head returned by preflight`);
  }
  if (Number(options.expectedSequence) !== projection.appliedSequence) {
    throw new Error(`workflow sequence changed: expected ${options.expectedSequence}, observed ${projection.appliedSequence}`);
  }
  if (String(options.expectedHead) !== projection.journalHeadSha256) {
    throw new Error("workflow journal head changed before mutation");
  }
}

function validatePhaseStart(projection, paths, input, admissionBytes, handoffBytes, options = {}) {
  const phaseId = requireEvidenceId(input.phaseId, "phase id");
  if (["closed", "reported"].includes(projection.status)) throw new Error(`workflow status ${projection.status} cannot start a phase`);
  if (projection.activePhase) throw new Error(`phase ${projection.activePhase.phaseId} is already active`);
  if (projection.phases[phaseId]) throw new Error(`phase ${phaseId} already has an attempt`);
  const definition = loadDefinition(paths);
  const phase = phaseById(definition, phaseId);
  if (projection.joined && !new Set(["retest-and-regression", "retest-cleanup-verification"]).has(phaseId)) {
    throw new Error("joined coverage permits only the defined retest branch before reporting");
  }
  const sourcePhase = input.sourcePhase ? requireEvidenceId(input.sourcePhase, "source phase") : null;
  const handoffId = input.handoffId ? requireEvidenceId(input.handoffId, "handoff id") : null;
  let transition = transitionFor(projection, definition, sourcePhase, phase, handoffId);
  if (transition) transition = { ...transition, __fromPhase: sourcePhase };
  const teardown = transition?.guard.authorization === "preauthorized-teardown" && TEARDOWN_PHASES.has(phase.id);
  if (["stopped", "recovery-hold"].includes(projection.status) && !teardown) {
    throw new Error("a fired stop blocks normal phase progress");
  }
  if (!teardown) assertDependencies(projection, phase, definition);
  let admission = null;
  let handoff = null;
  let authorizationSha256 = null;
  let confirmationRequired = null;
  if (phase.targetContact) {
    if (!admissionBytes) throw new Error("target-contact phase requires a reviewed admission file");
    admission = validateAdmission(paths, projection, definition, phase, admissionBytes, {
      allowExpiredTeardown: teardown,
      sourceAuthority: projection.phases[sourcePhase]?.authority || null
    });
    if (transition?.guard.authorization === "new-engagement") {
      const sourceAuthority = projection.phases[sourcePhase]?.authority;
      if (sourceAuthority?.receiptSha256 === admission.authority.receiptSha256) {
        throw new Error("transition requires a fresh engagement receipt");
      }
    } else if (transition?.guard.authorization === "current-engagement") {
      const sourceAuthority = projection.phases[sourcePhase]?.authority;
      if (!sourceAuthority || sourceAuthority.receiptSha256 !== admission.authority.receiptSha256) {
        throw new Error("transition requires the current engagement receipt");
      }
    } else if (transition?.guard.authorization === "preauthorized-teardown") {
      const sourceAuthority = projection.phases[sourcePhase]?.authority;
      if (!sourceAuthority || sourceAuthority.receiptSha256 !== admission.authority.receiptSha256 ||
        sourceAuthority.engagementId !== admission.authority.engagementId) {
        throw new Error("preauthorized teardown must retain the source phase authority receipt");
      }
    }
    if (phase.effectClass === "A3") {
      if (!transition?.handoffId) throw new Error("A3 phase entry requires a structured handoff id");
      if (handoffBytes) {
        handoff = validateHandoff(paths, projection, definition, phase, transition, admission, handoffBytes, {
          allowExpiredTeardown: teardown
        });
      } else if (!options.preflight) {
        throw new Error("A3 phase entry requires a structured handoff file");
      }
    }
  } else if (admissionBytes || handoffBytes || input.confirm) {
    throw new Error("non-contact phase does not accept active admission or high-impact confirmation");
  }
  const transitionSha256 = transition
    ? canonicalDigest({ sourcePhase, transition: Object.fromEntries(Object.entries(transition).filter(([key]) => key !== "__fromPhase")), handoffId: transition.handoffId || handoffId }, "gate.workflow.transition.v1")
    : canonicalDigest({ root: phase.id }, "gate.workflow.transition.v1");
  if (handoff) {
    authorizationSha256 = canonicalDigest({
      instanceId: projection.instanceId,
      workflowDefinitionSha256: projection.definition.sha256,
      journalSequence: projection.appliedSequence,
      journalHeadSha256: projection.journalHeadSha256,
      phaseId: phase.id,
      sourcePhase,
      transitionSha256,
      admissionSha256: admission.digest,
      handoffSha256: handoff.digest
    }, "gate.workflow.phase-authorization.v1");
    confirmationRequired = `AUTHORIZE A3 ${projection.instanceId} ${phase.id} ${handoff.digest} ${authorizationSha256}`;
    if (!options.preflight) {
      requireConfirmationPreconditions(projection, options, "A3 phase start");
      if (input.confirm !== confirmationRequired) {
        throw new Error(`high-impact confirmation must be exactly: ${confirmationRequired}`);
      }
    }
  }
  return {
    admission,
    authorizationSha256,
    confirmationRequired,
    definition,
    handoff,
    handoffId,
    handoffRequired: phase.effectClass === "A3",
    phase,
    sourcePhase,
    teardown,
    transition,
    transitionSha256
  };
}

export function preflightWorkflowPhase(id, input, options = {}) {
  const phaseId = requireEvidenceId(input.phaseId, "phase id");
  const admissionBytes = input.admissionFile ? stableFileBytes(input.admissionFile, 2 * 1024 * 1024, "workflow admission file") : null;
  const handoffBytes = input.handoffFile ? stableFileBytes(input.handoffFile, 2 * 1024 * 1024, "workflow handoff file") : null;
  const paths = workflowPaths(options.paths || options, id);
  ensureWorkflowRoot(paths);
  ensureInstanceDirectories(paths, false);
  const owner = acquireLock(paths);
  let primaryError = null;
  try {
    const loaded = loadProjection(paths, { repair: false, requireCurrentContract: true });
    const validated = validatePhaseStart(loaded.projection, paths, { ...input, phaseId }, admissionBytes, handoffBytes, {
      preflight: true
    });
    if (!validated.phase.targetContact) throw new Error("workflow phase preflight is only available for target-contact phases");
    return {
      ok: true,
      readOnly: true,
      operation: "workflow.phase.start",
      instanceId: loaded.projection.instanceId,
      phaseId,
      sourcePhase: validated.sourcePhase,
      journal: {
        sequence: loaded.projection.appliedSequence,
        headSha256: loaded.projection.journalHeadSha256
      },
      transitionSha256: validated.transitionSha256,
      admissionSha256: validated.admission.digest,
      authorizationSha256: validated.authorizationSha256,
      handoffRequired: validated.handoffRequired,
      handoffSha256: validated.handoff?.digest || null,
      confirmationRequired: validated.confirmationRequired,
      readyForMutation: !validated.handoffRequired || Boolean(validated.handoff),
      persisted: false
    };
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    try { releaseLock(paths, owner); } catch (error) { if (!primaryError) throw error; }
  }
}

export function startWorkflowPhase(id, input, options = {}) {
  const phaseId = requireEvidenceId(input.phaseId, "phase id");
  const admissionBytes = input.admissionFile ? stableFileBytes(input.admissionFile, 2 * 1024 * 1024, "workflow admission file") : null;
  const handoffBytes = input.handoffFile ? stableFileBytes(input.handoffFile, 2 * 1024 * 1024, "workflow handoff file") : null;
  const startIntent = {
    ...input,
    admissionFile: input.admissionFile ? path.basename(input.admissionFile) : null,
    handoffFile: input.handoffFile ? path.basename(input.handoffFile) : null,
    admissionFileSha256: admissionBytes ? sha256(admissionBytes) : null,
    handoffFileSha256: handoffBytes ? sha256(handoffBytes) : null
  };
  return mutate(id, intentOptions(options, "phase.start", startIntent), (projection, entries, paths) => {
    const validated = validatePhaseStart(projection, paths, { ...input, phaseId }, admissionBytes, handoffBytes, {
      expectedSequence: options.expectedSequence,
      expectedHead: options.expectedHead
    });
    const { admission, definition, handoff, handoffId, phase, sourcePhase, transition, transitionSha256 } = validated;
    if (admission) saveContentAddressed(paths.workflowAdmissions, admission.digest, admissionBytes, `workflow admission ${admission.digest}`);
    if (handoff) saveContentAddressed(paths.workflowHandoffs, handoff.digest, handoffBytes, `workflow handoff ${handoff.digest}`);
    const attemptId = newId("wpa");
    const executionEpochSha256 = canonicalDigest({
      instanceId: projection.instanceId,
      definitionSha256: projection.definition.sha256,
      phaseId,
      attemptId,
      transitionSha256,
      admissionSha256: admission?.digest || null,
      handoffSha256: handoff?.digest || null,
      previousJournalHeadSha256: projection.journalHeadSha256
    }, "gate.workflow.execution-epoch.v1");
    return {
      type: "phase.started",
      payload: {
        phaseId,
        attemptId,
        sourcePhase,
        transitionSha256,
        handoffId: transition?.handoffId || handoffId || null,
        lane: phase.lane,
        effectClass: phase.effectClass,
        targetContact: phase.targetContact,
        target: admission?.value.target || null,
        targetSha256: admission ? sha256(Buffer.from(admission.value.target)) : null,
        action: admission?.action || null,
        toolId: admission?.value.toolId || null,
        toolMappingSha256: admission?.mappingSha256 || null,
        admissionSha256: admission?.digest || null,
        handoffSha256: handoff?.digest || null,
        authority: admission?.authority || null,
        envelope: admission?.value.envelope || null,
        preauthorizedTeardown: transition?.guard.authorization === "preauthorized-teardown" && TEARDOWN_PHASES.has(phaseId),
        budget: admission?.budget || null,
        effectiveStops: effectiveStops(definition, phase),
        executionEpochSha256
      }
    };
  });
}

export function addWorkflowEvidence(id, input, options = {}) {
  const phaseId = requireEvidenceId(input.phaseId, "phase id");
  const evidenceId = requireEvidenceId(input.evidenceId, "evidence id");
  const claimState = String(input.claimState || "observed");
  if (!["observed", "inferred", "unverified"].includes(claimState)) throw new Error("evidence claim state is invalid");
  const bytes = stableFileBytes(input.file, MAX_EXTERNAL_BYTES, "workflow evidence file");
  const digest = sha256(bytes);
  return mutate(id, intentOptions(options, "evidence.add", {
    phaseId, evidenceId, claimState, fileSha256: digest
  }), (projection, entries, paths) => {
    const definition = loadDefinition(paths);
    const phase = phaseById(definition, phaseId);
    if (projection.activePhase?.phaseId !== phaseId) throw new Error("evidence can be added only to the active phase");
    if (projection.status !== "open" && !TEARDOWN_PHASES.has(phaseId)) {
      throw new Error(`workflow status ${projection.status} cannot add evidence outside teardown`);
    }
    const expected = phase.evidence.find((record) => record.id === evidenceId);
    if (!expected) throw new Error(`evidence id ${evidenceId} is not declared by phase ${phaseId}`);
    if (claimState !== expected.claimState) throw new Error(`evidence ${evidenceId} claim state must be ${expected.claimState}`);
    const file = path.join(paths.workflowEvidence, `${digest}.bin`);
    try { writePrivateFileExclusive(file, bytes, { label: `workflow evidence ${digest}` }); }
    catch (error) {
      if (error.code !== "EEXIST") throw error;
      const observed = readPrivateFileBounded(file, MAX_EXTERNAL_BYTES, null, { label: `workflow evidence ${digest}` });
      if (!observed.equals(bytes)) throw new Error("workflow evidence digest collision or replacement detected");
    }
    return {
      type: "evidence.added",
      payload: {
        phaseId,
        attemptId: projection.activePhase.attemptId,
        evidenceId,
        claimState,
        sensitivity: expected.sensitivity,
        sha256: digest,
        bytes: bytes.length,
        ref: `private://workflows/${projection.instanceId}/evidence/${digest}.bin`
      }
    };
  });
}

export function finishWorkflowPhase(id, input, options = {}) {
  const phaseId = requireEvidenceId(input.phaseId, "phase id");
  const disposition = String(input.disposition || "");
  if (!TERMINAL_DISPOSITIONS.has(disposition)) throw new Error("phase disposition must be tested, not-applicable, blocked, or untested");
  const explicitEvidence = [...new Set(input.evidenceSha256 || [])].sort();
  if (explicitEvidence.some((digest) => !SHA256_PATTERN.test(digest))) throw new Error("phase disposition evidence digest is invalid");
  return mutate(id, intentOptions(options, "phase.finish", input), (projection, entries, paths) => {
    const definition = loadDefinition(paths);
    const phase = phaseById(definition, phaseId);
    const running = projection.activePhase?.phaseId === phaseId;
    if (projection.joined && !running) throw new Error("joined coverage rejects direct phase dispositions");
    if (projection.status !== "open" && !(running && TEARDOWN_PHASES.has(phaseId))) {
      throw new Error(`workflow status ${projection.status} cannot finish this phase`);
    }
    if (projection.phases[phaseId] && !running) throw new Error(`phase ${phaseId} is already terminal`);
    if (disposition === "tested" && !running) throw new Error("tested disposition requires an active phase attempt");
    let attemptId = projection.phases[phaseId]?.attemptId || null;
    if (!running) {
      if (phase.applicability.mode !== "conditional") throw new Error("an always phase must be started and tested");
      if (projection.activePhase) throw new Error("another phase is active");
      if (!input.rationale) throw new Error("direct conditional disposition requires a rationale");
      attemptId = newId("wpa");
    }
    const record = projection.phases[phaseId] || { attemptId, authority: null };
    const phaseEvidence = projection.evidence.filter((evidence) => evidence.phaseId === phaseId && evidence.attemptId === record.attemptId);
    if (disposition === "tested") {
      const missing = phase.evidence.filter((expected) => expected.required &&
        !phaseEvidence.some((actual) => actual.evidenceId === expected.id && actual.claimState === expected.claimState));
      if (missing.length) throw new Error(`phase required evidence is missing: ${missing.map((item) => item.id).join(", ")}`);
      if (pendingReservations(projection).some((reservation) => reservation.phaseAttemptId === record.attemptId)) {
        throw new Error("phase cannot finish while an execution reservation is pending");
      }
      if (phase.targetContact) recheckAdmission(paths, record, { completion: true });
      if (explicitEvidence.length) throw new Error("tested disposition evidence is derived from the active phase and must not be supplied directly");
    } else {
      if (!input.rationale) throw new Error(`${disposition} disposition requires a rationale`);
      const known = new Set(projection.evidence.map((item) => item.sha256));
      if (explicitEvidence.some((digest) => !known.has(digest))) throw new Error("phase disposition references unknown evidence");
      if (disposition === "not-applicable" && !explicitEvidence.length) {
        throw new Error("not-applicable disposition requires explicit supporting evidence");
      }
      if (disposition !== "not-applicable" && explicitEvidence.length) {
        throw new Error(`${disposition} direct disposition does not accept evidence digests`);
      }
    }
    return {
      type: "phase.finished",
      payload: {
        phaseId,
        attemptId: record.attemptId,
        direct: !running,
        disposition,
        rationale: input.rationale ? oneLine(input.rationale, "phase rationale", 1000) : null,
        evidenceSha256: disposition === "tested" ? phaseEvidence.map((item) => item.sha256).sort() : explicitEvidence
      }
    };
  });
}

export function setWorkflowCoverage(id, input, options = {}) {
  const domain = requireEvidenceId(input.domain, "coverage domain");
  const disposition = String(input.disposition || "");
  if (!TERMINAL_DISPOSITIONS.has(disposition)) throw new Error("coverage disposition is invalid");
  const evidenceSha256 = [...new Set(input.evidenceSha256 || [])].sort();
  if (evidenceSha256.some((digest) => !SHA256_PATTERN.test(digest))) throw new Error("coverage evidence digest is invalid");
  return mutate(id, intentOptions(options, "coverage.set", input), (projection, entries, paths) => {
    assertDirectMutationAllowed(projection, "set coverage");
    if (!PENTEST_COVERAGE_DOMAINS.includes(domain)) throw new Error(`unknown coverage domain: ${domain}`);
    if (projection.coverage[domain]) throw new Error(`coverage domain already has a disposition: ${domain}`);
    const known = new Set(projection.evidence.map((record) => record.sha256));
    if (evidenceSha256.some((digest) => !known.has(digest))) throw new Error("coverage references unknown evidence");
    if (disposition === "tested" && !evidenceSha256.length) throw new Error("tested coverage requires evidence");
    if (disposition === "tested") {
      const definition = loadDefinition(paths);
      const supportsDomain = evidenceSha256.some((digest) => projection.evidence.some((record) => {
        const evidencePhase = phaseById(definition, record.phaseId);
        return record.sha256 === digest && record.claimState !== "unverified" &&
          projection.phases[record.phaseId]?.status === "tested" && evidencePhase.coverageDomains.includes(domain);
      }));
      if (!supportsDomain) throw new Error("tested coverage requires verified evidence from a tested phase that declares the domain");
    }
    const rationale = input.rationale ? oneLine(input.rationale, "coverage rationale", 1000) : null;
    if (disposition !== "tested" && !rationale) throw new Error(`${disposition} coverage requires a rationale or limitation`);
    return { type: "coverage.set", payload: { domain, disposition, evidenceSha256, rationale } };
  });
}

function validateLedgerOpen(projection, paths, input, pivotAdmissionBytes, options = {}) {
  if (!projection.activePhase) throw new Error("a ledger change requires an active phase");
  if (projection.status !== "open") throw new Error(`workflow status ${projection.status} cannot open new target state`);
  if (!projection.evidence.some((record) => record.sha256 === input.beforeEvidenceSha256 &&
    record.phaseId === projection.activePhase.phaseId && record.attemptId === projection.activePhase.attemptId)) {
    throw new Error("ledger before-evidence digest is not bound to the active phase attempt");
  }
  const definition = loadDefinition(paths);
  const phase = phaseById(definition, projection.activePhase.phaseId);
  if (!phase.stateChangeHandling?.mayChangeState) throw new Error("active phase does not permit target-side state change");
  const pivotEntries = Object.values(projection.ledger).filter((entry) => entry.changeType === "pivot");
  if (input.changeType === "pivot" && pivotEntries.length >= 3) throw new Error("pivot depth is capped at three workflow ledger entries");
  let admission = null;
  let confirmationRequired = null;
  let pivot = null;
  if (input.changeType === "pivot") {
    if (!pivotAdmissionBytes) throw new Error("pivot subiteration requires a fresh reviewed admission file");
    if (pendingReservations(projection).length) throw new Error("pivot cannot begin while an execution reservation is pending");
    admission = validateAdmission(paths, projection, definition, phase, pivotAdmissionBytes);
    const priorReceipts = new Set([
      ...Object.values(projection.phases).map((record) => record.authority?.receiptSha256),
      ...pivotEntries.map((record) => record.pivot?.authority?.receiptSha256)
    ].filter(Boolean));
    if (priorReceipts.has(admission.authority.receiptSha256)) throw new Error("pivot subiteration requires a fresh engagement receipt");
    const targetSha256 = sha256(Buffer.from(admission.value.target));
    if (targetSha256 !== input.targetSelectorSha256) throw new Error("pivot target selector digest differs from its fresh admission target");
    const depth = pivotEntries.length + 1;
    const authorizationSha256 = canonicalDigest({
      instanceId: projection.instanceId,
      workflowDefinitionSha256: projection.definition.sha256,
      journalSequence: projection.appliedSequence,
      journalHeadSha256: projection.journalHeadSha256,
      phaseId: phase.id,
      phaseAttemptId: projection.activePhase.attemptId,
      depth,
      admissionSha256: admission.digest,
      targetSelectorSha256: input.targetSelectorSha256,
      beforeEvidenceSha256: input.beforeEvidenceSha256,
      cleanupAction: input.cleanupAction
    }, "gate.workflow.pivot-authorization.v1");
    confirmationRequired = `AUTHORIZE PIVOT ${projection.instanceId} ${phase.id} ${admission.digest} ${authorizationSha256}`;
    if (!options.preflight) {
      requireConfirmationPreconditions(projection, options, "pivot ledger open");
      if (input.pivotConfirm !== confirmationRequired) {
        throw new Error(`pivot confirmation must be exactly: ${confirmationRequired}`);
      }
    }
    pivot = {
      depth,
      toolId: admission.value.toolId,
      toolMappingSha256: admission.mappingSha256,
      admissionSha256: admission.digest,
      authorizationSha256,
      authority: admission.authority,
      envelope: admission.value.envelope,
      targetSha256,
      executionEpochSha256: canonicalDigest({
        instanceId: projection.instanceId,
        phaseId: phase.id,
        attemptId: projection.activePhase.attemptId,
        depth,
        admissionSha256: admission.digest,
        previousJournalHeadSha256: projection.journalHeadSha256
      }, "gate.workflow.pivot-epoch.v1")
    };
  } else if (pivotAdmissionBytes || input.pivotConfirm) {
    throw new Error("non-pivot ledger entries do not accept pivot authority");
  }
  return { admission, confirmationRequired, phase, pivot };
}

function normalizeLedgerOpenInput(input) {
  const normalized = {
    ...input,
    changeType: oneLine(input.changeType, "state change type", 80),
    targetSelectorSha256: String(input.targetSelectorSha256 || ""),
    beforeEvidenceSha256: String(input.beforeEvidenceSha256 || ""),
    cleanupAction: oneLine(input.cleanupAction, "cleanup action", 1000)
  };
  if (!SHA256_PATTERN.test(normalized.targetSelectorSha256) || !SHA256_PATTERN.test(normalized.beforeEvidenceSha256)) {
    throw new Error("ledger target and before-evidence digests must be SHA-256 values");
  }
  return normalized;
}

export function preflightWorkflowPivot(id, input, options = {}) {
  const normalized = normalizeLedgerOpenInput(input);
  if (normalized.changeType !== "pivot") throw new Error("workflow ledger preflight is only available for pivot entries");
  const pivotAdmissionBytes = normalized.pivotAdmissionFile
    ? stableFileBytes(normalized.pivotAdmissionFile, 2 * 1024 * 1024, "pivot admission file") : null;
  const paths = workflowPaths(options.paths || options, id);
  ensureWorkflowRoot(paths);
  ensureInstanceDirectories(paths, false);
  const owner = acquireLock(paths);
  let primaryError = null;
  try {
    const loaded = loadProjection(paths, { repair: false, requireCurrentContract: true });
    const validated = validateLedgerOpen(loaded.projection, paths, normalized, pivotAdmissionBytes, { preflight: true });
    return {
      ok: true,
      readOnly: true,
      operation: "workflow.ledger.open",
      instanceId: loaded.projection.instanceId,
      phaseId: validated.phase.id,
      phaseAttemptId: loaded.projection.activePhase.attemptId,
      journal: {
        sequence: loaded.projection.appliedSequence,
        headSha256: loaded.projection.journalHeadSha256
      },
      admissionSha256: validated.admission.digest,
      authorizationSha256: validated.pivot.authorizationSha256,
      targetSelectorSha256: normalized.targetSelectorSha256,
      beforeEvidenceSha256: normalized.beforeEvidenceSha256,
      cleanupActionSha256: sha256(Buffer.from(normalized.cleanupAction)),
      confirmationRequired: validated.confirmationRequired,
      readyForMutation: true,
      persisted: false
    };
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    try { releaseLock(paths, owner); } catch (error) { if (!primaryError) throw error; }
  }
}

export function openWorkflowLedger(id, input, options = {}) {
  const normalized = normalizeLedgerOpenInput(input);
  const pivotAdmissionBytes = normalized.pivotAdmissionFile
    ? stableFileBytes(normalized.pivotAdmissionFile, 2 * 1024 * 1024, "pivot admission file") : null;
  const intent = {
    ...normalized,
    pivotAdmissionFile: normalized.pivotAdmissionFile ? path.basename(normalized.pivotAdmissionFile) : null,
    pivotAdmissionFileSha256: pivotAdmissionBytes ? sha256(pivotAdmissionBytes) : null
  };
  return mutate(id, intentOptions(options, "ledger.open", intent), (projection, entries, paths) => {
    const validated = validateLedgerOpen(projection, paths, normalized, pivotAdmissionBytes, {
      expectedSequence: options.expectedSequence,
      expectedHead: options.expectedHead
    });
    if (validated.admission) {
      saveContentAddressed(paths.workflowAdmissions, validated.admission.digest, pivotAdmissionBytes,
        `workflow admission ${validated.admission.digest}`);
    }
    return {
      type: "ledger.opened",
      payload: {
        entryId: newId("wle"),
        phaseId: validated.phase.id,
        attemptId: projection.activePhase.attemptId,
        changeType: normalized.changeType,
        targetSelectorSha256: normalized.targetSelectorSha256,
        beforeEvidenceSha256: normalized.beforeEvidenceSha256,
        cleanupAction: normalized.cleanupAction,
        pivot: validated.pivot,
        budget: validated.admission?.budget || null
      }
    };
  });
}

export function recordWorkflowLedgerCleanup(id, input, options = {}) {
  const entryId = String(input.entryId || "");
  const digest = String(input.cleanupEvidenceSha256 || "");
  if (!LEDGER_PATTERN.test(entryId) || !SHA256_PATTERN.test(digest)) throw new Error("ledger cleanup binding is invalid");
  return mutate(id, intentOptions(options, "ledger.cleanup", input), (projection, entries) => {
    const record = projection.ledger[entryId];
    if (!record || record.status !== "open") throw new Error("ledger entry is not open");
    const cleanupPhases = new Set(["offline-lab-reset-verification", "cleanup-and-restoration", "retest-cleanup-verification"]);
    if (!projection.activePhase || !cleanupPhases.has(projection.activePhase.phaseId)) {
      throw new Error("ledger cleanup evidence requires an active workflow cleanup phase");
    }
    const evidence = projection.evidence.find((candidate) => candidate.sha256 === digest &&
      candidate.phaseId === projection.activePhase.phaseId && candidate.attemptId === projection.activePhase.attemptId);
    if (!evidence) throw new Error("ledger cleanup evidence is not bound to the active cleanup phase attempt");
    const openedSequence = entries.find((entry) => entry.entrySha256 === record.openedEntrySha256)?.sequence;
    const evidenceSequence = entries.find((entry) => entry.entrySha256 === evidence.journalEntrySha256)?.sequence;
    if (!Number.isInteger(openedSequence) || !Number.isInteger(evidenceSequence) || evidenceSequence <= openedSequence) {
      throw new Error("ledger cleanup evidence must be recorded after the state change");
    }
    const outstanding = Object.values(projection.ledger).filter((entry) => entry.status !== "verified-clean");
    if (outstanding.at(-1)?.entryId !== entryId) throw new Error("cleanup must proceed in LIFO order");
    return { type: "ledger.cleanup-recorded", payload: { entryId, cleanupEvidenceSha256: digest } };
  });
}

export function verifyWorkflowLedger(id, input, options = {}) {
  const entryId = String(input.entryId || "");
  const digest = String(input.verificationEvidenceSha256 || "");
  if (!LEDGER_PATTERN.test(entryId) || !SHA256_PATTERN.test(digest)) throw new Error("ledger verification binding is invalid");
  return mutate(id, intentOptions(options, "ledger.verify", input), (projection, entries) => {
    const record = projection.ledger[entryId];
    if (!record || record.status !== "cleanup-pending") throw new Error("ledger entry has no cleanup evidence to verify");
    const cleanupPhases = new Set(["offline-lab-reset-verification", "cleanup-and-restoration", "retest-cleanup-verification"]);
    if (!projection.activePhase || !cleanupPhases.has(projection.activePhase.phaseId)) {
      throw new Error("ledger verification evidence requires an active workflow cleanup phase");
    }
    const evidence = projection.evidence.find((candidate) => candidate.sha256 === digest &&
      candidate.phaseId === projection.activePhase.phaseId && candidate.attemptId === projection.activePhase.attemptId);
    if (!evidence) throw new Error("ledger verification evidence is not bound to the active cleanup phase attempt");
    const cleanupSequence = entries.find((entry) => entry.entrySha256 === record.cleanupEntrySha256)?.sequence;
    const evidenceSequence = entries.find((entry) => entry.entrySha256 === evidence.journalEntrySha256)?.sequence;
    if (!Number.isInteger(cleanupSequence) || !Number.isInteger(evidenceSequence) || evidenceSequence <= cleanupSequence) {
      throw new Error("ledger verification evidence must be recorded after cleanup");
    }
    if (record.cleanupEvidenceSha256 === digest) throw new Error("ledger verification requires independent evidence");
    const outstanding = Object.values(projection.ledger).filter((entry) => entry.status !== "verified-clean");
    if (outstanding.at(-1)?.entryId !== entryId) throw new Error("verification must proceed in LIFO order");
    return { type: "ledger.verified", payload: { entryId, verificationEvidenceSha256: digest } };
  });
}

export function holdWorkflowLedger(id, input, options = {}) {
  const entryId = String(input.entryId || "");
  if (!LEDGER_PATTERN.test(entryId)) throw new Error("ledger entry id is invalid");
  return mutate(id, intentOptions(options, "ledger.hold", input), (projection) => {
    const record = projection.ledger[entryId];
    if (!record || record.status === "verified-clean") throw new Error("ledger entry cannot enter recovery hold");
    return { type: "ledger.held", payload: { entryId, reason: oneLine(input.reason, "recovery hold reason", 1000) } };
  });
}

export function stopWorkflow(id, input, options = {}) {
  const condition = requireEvidenceId(input.condition, "stop condition");
  const evidenceSha256 = input.evidenceSha256 ? String(input.evidenceSha256) : null;
  if (evidenceSha256 && !SHA256_PATTERN.test(evidenceSha256)) throw new Error("stop evidence digest is invalid");
  return mutate(id, intentOptions(options, "workflow.stop", input), (projection) => {
    if (!projection.definition.mandatoryStops.includes(condition)) throw new Error(`unknown mandatory stop condition: ${condition}`);
    if (["closed", "reported"].includes(projection.status)) throw new Error(`${projection.status} workflow cannot be stopped`);
    return {
      type: "stop.triggered",
      payload: {
        condition,
        phaseId: projection.activePhase?.phaseId || null,
        attemptId: projection.activePhase?.attemptId || null,
        ledgerState: ledgerState(projection),
        reason: oneLine(input.reason, "stop reason", 1000),
        evidenceSha256
      }
    };
  });
}

export function joinWorkflowCoverage(id, input = {}, options = {}) {
  return mutate(id, intentOptions(options, "coverage.join", input), (projection, entries, paths) => {
    assertDirectMutationAllowed(projection, "join coverage");
    const definition = loadDefinition(paths);
    if (projection.activePhase) throw new Error("coverage cannot join while a phase is active");
    if (pendingReservations(projection).length) throw new Error("coverage cannot join while an execution reservation is pending");
    if (projection.joined) throw new Error("coverage is already joined");
    const missingDomains = PENTEST_COVERAGE_DOMAINS.filter((domain) => !projection.coverage[domain]);
    const extraDomains = Object.keys(projection.coverage).filter((domain) => !PENTEST_COVERAGE_DOMAINS.includes(domain));
    if (missingDomains.length || extraDomains.length || Object.keys(projection.coverage).length !== 18) {
      throw new Error(`coverage join requires exact 18-domain equality; missing=${missingDomains.join(",") || "none"} extra=${extraDomains.join(",") || "none"}`);
    }
    const requiredAlways = definition.value.phases.filter((phase) => phase.applicability.mode === "always" &&
      phase.id !== definition.value.coverageJoin.phaseId && phase.id !== "reporting-and-closeout");
    const missingAlways = requiredAlways.filter((phase) => !phaseSatisfied(projection, phase.id));
    if (missingAlways.length) throw new Error(`always phases are incomplete: ${missingAlways.map((phase) => phase.id).join(", ")}`);
    const postJoinPhases = new Set(["retest-and-regression", "retest-cleanup-verification", "recovery-hold"]);
    const conditional = definition.value.phases.filter((phase) =>
      phase.applicability.mode === "conditional" && !postJoinPhases.has(phase.id)
    );
    const missingPhases = conditional.filter((phase) => !phaseTerminal(projection, phase.id));
    if (missingPhases.length) throw new Error(`conditional phase dispositions are missing: ${missingPhases.map((phase) => phase.id).join(", ")}`);
    const state = ledgerState(projection);
    if (!CLEAN_LEDGER_STATES.has(state)) throw new Error(`coverage join requires an empty or verified-clean ledger, observed ${state}`);
    return {
      type: "coverage.joined",
      payload: {
        coverageSha256: canonicalDigest(projection.coverage, "gate.workflow.coverage.v1"),
        phaseDispositionSha256: canonicalDigest(projection.phases, "gate.workflow.phase-dispositions.v1"),
        ledgerState: state,
        ledgerSha256: canonicalDigest(projection.ledger, "gate.workflow.ledger.v1")
      }
    };
  });
}

function assertCloseout(projection) {
  if (projection.activePhase) throw new Error("reporting requires no active phase");
  if (projection.phases["retest-and-regression"]?.status !== "tested") throw new Error("reporting requires completed retest");
  if (Object.values(projection.ledger).some((entry) => entry.phaseId === "retest-and-regression") &&
    projection.phases["retest-cleanup-verification"]?.status !== "tested") throw new Error("reporting requires completed retest cleanup verification");
}

export function attachWorkflowReport(id, input, options = {}) {
  const bytes = stableFileBytes(input.file, MAX_EXTERNAL_BYTES, "workflow report file");
  const digest = sha256(bytes);
  return mutate(id, intentOptions(options, "report.attach", { fileSha256: digest }), (projection, entries, paths) => {
    assertDirectMutationAllowed(projection, "attach a report");
    assertCloseout(projection);
    if (!projection.joined) throw new Error("reporting requires a successful coverage join");
    if (!CLEAN_LEDGER_STATES.has(ledgerState(projection))) throw new Error("reporting requires an empty or verified-clean ledger");
    if (pendingReservations(projection).length) throw new Error("reporting cannot proceed while an execution reservation is pending");
    if (projection.report) throw new Error("a workflow report is already attached");
    const file = path.join(paths.workflowReports, `${digest}.bin`);
    try { writePrivateFileExclusive(file, bytes, { label: `workflow report ${digest}` }); }
    catch (error) {
      if (error.code !== "EEXIST") throw error;
      const observed = readPrivateFileBounded(file, MAX_EXTERNAL_BYTES, null, { label: `workflow report ${digest}` });
      if (!observed.equals(bytes)) throw new Error("workflow report digest collision or replacement detected");
    }
    return {
      type: "report.attached",
      payload: {
        sha256: digest,
        bytes: bytes.length,
        coverageSha256: projection.joined.coverageSha256,
        ref: `private://workflows/${projection.instanceId}/reports/${digest}.bin`
      }
    };
  });
}

export function closeWorkflow(id, input, options = {}) {
  return mutate(id, intentOptions(options, "workflow.close", input), (projection) => {
    assertCloseout(projection);
    if (projection.status !== "reported" || !projection.report || !projection.joined) {
      throw new Error("workflow can close only after joined reporting");
    }
    if (!CLEAN_LEDGER_STATES.has(ledgerState(projection))) throw new Error("workflow cannot close with unresolved target state");
    if (pendingReservations(projection).length) throw new Error("workflow cannot close while an execution reservation is pending");
    const confirmation = `CLOSE ${projection.instanceId} ${projection.report.sha256}`;
    if (input.confirm !== confirmation) throw new Error(`workflow close confirmation must be exactly: ${confirmation}`);
    return { type: "workflow.closed", payload: { reportSha256: projection.report.sha256 } };
  });
}

function executionEnvelope(input, active) {
  const source = input.envelope || input;
  const value = {
    maxMinutes: Number(source.maxMinutes),
    maxRequests: Number(source.maxRequests),
    maxRatePerSecond: Number(source.maxRatePerSecond),
    maxParallel: Number(source.maxParallel),
    maxInputTokens: Number(source.maxInputTokens || 0),
    maxOutputTokens: Number(source.maxOutputTokens || 0),
    maxTotalTokens: Number(source.maxTotalTokens),
    maxEvidenceBytes: Number(source.maxEvidenceBytes),
    maxSpend: Number(source.maxSpend || 0),
    controls: { ...active.envelope.controls }
  };
  validateEnvelope(value);
  return value;
}

function assertReservationBinding(reservation, input) {
  if (!reservation) throw new Error("workflow execution reservation does not exist");
  const comparisons = [
    ["phaseAttemptId", input.phaseAttemptId],
    ["executionEpochSha256", input.executionEpochSha256],
    ["manifestId", input.manifestId],
    ["manifestSha256", input.manifestSha256],
    ["runId", input.runId]
  ].filter(([, value]) => value !== undefined && value !== null);
  for (const [field, expected] of comparisons) {
    if (field === "manifestSha256" && reservation.manifestSha256 === null) continue;
    if (reservation[field] !== expected) throw new Error(`workflow execution reservation binding changed: ${field}`);
  }
}

export function reserveWorkflowExecution(id, input, options = {}) {
  const phaseAttemptId = String(input.phaseAttemptId || "");
  if (!ATTEMPT_PATTERN.test(phaseAttemptId)) throw new Error("workflow phase attempt id is invalid");
  const manifestId = String(input.manifestId || "");
  const runId = String(input.runId || "");
  if (!/^xmf_[a-f0-9]{32}$/u.test(manifestId) || !/^xrun_[a-f0-9]{32}$/u.test(runId)) {
    throw new Error("workflow execution manifest and run identifiers are invalid");
  }
  const target = oneLine(input.target, "workflow execution target", 1000);
  const action = oneLine(input.action, "workflow execution action", 80);
  const toolId = requireEvidenceId(input.toolId, "workflow execution tool id");
  const intent = { ...input, target, action, toolId, phaseAttemptId, manifestId, runId };
  const result = mutate(id, intentOptions(options, "execution.reserve", intent), (projection, entries, paths) => {
    assertDirectMutationAllowed(projection, "reserve execution");
    const active = projection.activePhase;
    if (!active || active.attemptId !== phaseAttemptId) throw new Error("workflow execution does not bind the active phase attempt");
    if (!active.targetContact || !active.admissionSha256 || !active.authority) throw new Error("active phase has no target-contact admission");
    if (active.effectClass === "A3") throw new Error("the supervised generic execution lane cannot execute an A3 phase");
    if (target !== active.target || action !== active.action || toolId !== active.toolId) {
      throw new Error("workflow execution target, action, or tool differs from the active admission");
    }
    if (input.engagementId && input.engagementId !== active.authority.engagementId) {
      throw new Error("workflow execution engagement differs from the active admission");
    }
    if (pendingReservations(projection).some((reservation) => reservation.phaseAttemptId === phaseAttemptId)) {
      throw new Error("the active phase attempt already has a pending execution reservation");
    }
    recheckAdmission(paths, active);
    const envelope = executionEnvelope(input, active);
    for (const field of ["maxMinutes", "maxRequests", "maxRatePerSecond", "maxParallel", "maxInputTokens", "maxOutputTokens", "maxTotalTokens", "maxEvidenceBytes", "maxSpend"]) {
      if (envelope[field] > Number(active.envelope[field])) throw new Error(`workflow execution ${field} exceeds the active admission`);
    }
    const used = Object.values(projection.executionReservations).filter((reservation) =>
      reservation.phaseAttemptId === phaseAttemptId && reservation.status !== "cancelled"
    );
    for (const field of ["maxMinutes", "maxRequests", "maxTotalTokens", "maxEvidenceBytes", "maxSpend"]) {
      const reserved = used.reduce((sum, reservation) => sum + Number(reservation.envelope?.[field] || 0), 0);
      if (reserved + envelope[field] > Number(active.envelope[field])) {
        throw new Error(`workflow execution ${field} exceeds the remaining phase allocation`);
      }
    }
    const reservationId = newId("wxr");
    return {
      type: "execution.reserved",
      payload: {
        reservationId,
        instanceId: projection.instanceId,
        phaseId: active.phaseId,
        phaseAttemptId,
        engagementId: active.authority.engagementId,
        manifestId,
        manifestSha256: null,
        runId,
        targetSha256: sha256(Buffer.from(target)),
        action,
        toolId,
        toolMappingSha256: active.toolMappingSha256,
        admissionSha256: active.admissionSha256,
        authorityReceiptSha256: active.authority.receiptSha256,
        journalHeadAtReservationSha256: projection.journalHeadSha256,
        executionEpochSha256: active.executionEpochSha256,
        envelope
      }
    };
  });
  return { ...result.entry.payload, replayed: result.replayed };
}

export function claimWorkflowExecution(id, input, options = {}) {
  const reservationId = String(input.reservationId || "");
  if (!RESERVATION_PATTERN.test(reservationId)) throw new Error("workflow execution reservation id is invalid");
  if (!SHA256_PATTERN.test(String(input.manifestSha256 || ""))) throw new Error("workflow execution manifest digest is invalid");
  return mutate(id, intentOptions(options, "execution.claim", input), (projection, entries, paths) => {
    assertDirectMutationAllowed(projection, "claim execution");
    if (input.expectedJournalHeadSha256 !== undefined) {
      if (!SHA256_PATTERN.test(String(input.expectedJournalHeadSha256))) {
        throw new Error("expected workflow journal head digest is invalid");
      }
      if (projection.journalHeadSha256 !== input.expectedJournalHeadSha256) {
        throw new Error("workflow journal head changed after manifest creation");
      }
    }
    const reservation = projection.executionReservations[reservationId];
    if (!reservation || reservation.status !== "reserved") throw new Error("workflow execution reservation is not available to claim");
    assertReservationBinding(reservation, input);
    const active = projection.activePhase;
    if (!active || active.attemptId !== reservation.phaseAttemptId || active.executionEpochSha256 !== reservation.executionEpochSha256) {
      throw new Error("workflow execution reservation no longer binds the active phase epoch");
    }
    recheckAdmission(paths, active);
    return {
      type: "execution.claimed",
      payload: {
        reservationId,
        phaseAttemptId: reservation.phaseAttemptId,
        executionEpochSha256: reservation.executionEpochSha256,
        manifestId: reservation.manifestId,
        manifestSha256: input.manifestSha256,
        runId: reservation.runId
      }
    };
  });
}

export function checkWorkflowExecution(id, input, options = {}) {
  const paths = workflowPaths(options.paths || options, id);
  ensureWorkflowRoot(paths);
  ensureInstanceDirectories(paths, false);
  const owner = acquireLock(paths);
  let primaryError = null;
  try {
    const loaded = loadProjection(paths);
    if (loaded.projection.status !== "open") {
      throw new Error(`workflow status ${loaded.projection.status} cannot authorize execution`);
    }
    if (input.expectedJournalHeadSha256 !== undefined) {
      if (!SHA256_PATTERN.test(String(input.expectedJournalHeadSha256))) {
        throw new Error("expected workflow journal head digest is invalid");
      }
      if (loaded.projection.journalHeadSha256 !== input.expectedJournalHeadSha256) {
        throw new Error("workflow journal head changed after manifest creation or claim");
      }
    }
    const reservation = loaded.projection.executionReservations[String(input.reservationId || "")];
    if (reservation && ["completed", "failed", "cancelled", "blocked", "unknown"].includes(reservation.status)) {
      assertReservationBinding(reservation, input);
      throw new Error(`execution manifest was already consumed: ${reservation.manifestId}`);
    }
    if (!reservation || !["reserved", "claimed"].includes(reservation.status)) {
      throw new Error("workflow execution reservation is not active");
    }
    assertReservationBinding(reservation, input);
    const active = loaded.projection.activePhase;
    if (!active || active.attemptId !== reservation.phaseAttemptId || active.executionEpochSha256 !== reservation.executionEpochSha256) {
      throw new Error("workflow execution reservation no longer binds the active phase epoch");
    }
    if (input.target && sha256(Buffer.from(input.target)) !== reservation.targetSha256) throw new Error("workflow execution target changed");
    if (input.action && input.action !== reservation.action) throw new Error("workflow execution action changed");
    if (input.toolId && input.toolId !== reservation.toolId) throw new Error("workflow execution tool changed");
    for (const [field, actual] of [
      ["definitionSha256", loaded.projection.definition.sha256],
      ["admissionSha256", reservation.admissionSha256],
      ["toolMappingSha256", reservation.toolMappingSha256],
      ["authorityReceiptSha256", reservation.authorityReceiptSha256]
    ]) {
      if (input[field] !== undefined && input[field] !== actual) {
        throw new Error(`workflow execution ${field} binding changed`);
      }
    }
    const effectiveStopsSha256 = canonicalDigest(active.effectiveStops, "gate.workflow.effective-stops.v1");
    if (input.effectiveStopsSha256 !== undefined && input.effectiveStopsSha256 !== effectiveStopsSha256) {
      throw new Error("workflow execution effective stop binding changed");
    }
    recheckAdmission(paths, active);
    return {
      ok: true,
      instanceId: loaded.projection.instanceId,
      phaseId: reservation.phaseId,
      phaseAttemptId: reservation.phaseAttemptId,
      reservationId: reservation.reservationId,
      executionEpochSha256: reservation.executionEpochSha256,
      journalHeadSha256: loaded.projection.journalHeadSha256,
      definitionSha256: loaded.projection.definition.sha256,
      admissionSha256: reservation.admissionSha256,
      toolMappingSha256: reservation.toolMappingSha256,
      authorityReceiptSha256: reservation.authorityReceiptSha256,
      effectiveStops: [...active.effectiveStops],
      effectiveStopsSha256,
      effectClass: active.effectClass,
      envelope: structuredClone(reservation.envelope)
    };
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    try { releaseLock(paths, owner); } catch (error) { if (!primaryError) throw error; }
  }
}

export function completeWorkflowExecution(id, input, options = {}) {
  const reservationId = String(input.reservationId || "");
  if (!RESERVATION_PATTERN.test(reservationId)) throw new Error("workflow execution reservation id is invalid");
  const status = String(input.status || "");
  if (!["succeeded", "failed", "cancelled", "blocked", "unknown"].includes(status)) throw new Error("workflow execution terminal status is invalid");
  if (!SHA256_PATTERN.test(String(input.runSha256 || ""))) throw new Error("workflow execution run digest is invalid");
  if (input.resultSha256 && !SHA256_PATTERN.test(String(input.resultSha256))) throw new Error("workflow execution result digest is invalid");
  return mutate(id, intentOptions(options, "execution.complete", input), (projection, entries) => {
    const reservation = projection.executionReservations[reservationId];
    if (!reservation) throw new Error("workflow execution reservation does not exist");
    assertReservationBinding(reservation, input);
    if (["completed", "failed", "cancelled", "blocked", "unknown"].includes(reservation.status)) {
      const existing = {
        status: reservation.status === "completed" ? "succeeded" : reservation.status,
        runSha256: reservation.runSha256,
        resultSha256: reservation.resultSha256 || null,
        terminationReason: reservation.terminationReason || null
      };
      const proposed = {
        status,
        runSha256: input.runSha256,
        resultSha256: input.resultSha256 || null,
        terminationReason: input.terminationReason || null
      };
      if (canonicalDigest(existing) !== canonicalDigest(proposed)) throw new Error("workflow execution terminal result conflicts with the recorded result");
      const existingEntry = [...entries].reverse().find((entry) =>
        entry.type === "execution.completed" && entry.payload.reservationId === reservationId
      );
      if (!existingEntry) throw new Error("workflow execution terminal journal entry is missing");
      return { noop: true, entry: existingEntry };
    }
    if (reservation.status !== "claimed") throw new Error("workflow execution must be claimed before completion");
    return {
      type: "execution.completed",
      payload: {
        reservationId,
        manifestId: reservation.manifestId,
        manifestSha256: reservation.manifestSha256,
        runId: reservation.runId,
        status,
        runSha256: input.runSha256,
        resultSha256: input.resultSha256 || null,
        terminationReason: input.terminationReason ? oneLine(input.terminationReason, "execution termination reason", 200) : null
      }
    };
  });
}

export function cancelWorkflowExecution(id, input, options = {}) {
  const reservationId = String(input.reservationId || "");
  if (!RESERVATION_PATTERN.test(reservationId)) throw new Error("workflow execution reservation id is invalid");
  return mutate(id, intentOptions(options, "execution.cancel", input), (projection) => {
    const reservation = projection.executionReservations[reservationId];
    if (!reservation || reservation.status !== "reserved") throw new Error("only an unused workflow execution reservation can be cancelled");
    return {
      type: "execution.cancelled",
      payload: { reservationId, reason: oneLine(input.reason, "execution reservation cancellation reason", 500) }
    };
  });
}

export const workflowRuntimeInternals = Object.freeze({
  canonicalDigest,
  entryDigest,
  projectionEnvelope,
  ledgerState,
  loadDefinition,
  workflowPaths
});
