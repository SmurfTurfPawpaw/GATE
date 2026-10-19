import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";

import {
  blockManagedCampaignJob,
  campaignInternals,
  campaignStatus,
  completeManagedCampaignJob,
  recoverCampaign,
  runNextCampaignJob,
  startNextManagedCampaignJob
} from "./campaigns.mjs";
import {
  dispatchAuthorizedLabCampaignJob,
  labCampaignAuthorityStatus
} from "./lab-campaign-authority.mjs";
import { nextCtfPilotTimestamp, updateCtfPilotState } from "./ctf-pilot.mjs";
import { runtimePaths } from "./paths.mjs";
import {
  readPrivateFileBounded,
  securePrivateFile,
  syncPrivateDirectory,
  writePrivateFileAtomic
} from "./private-fs.mjs";
import { assertValidDocument } from "./schema.mjs";

const WORKER_SCHEMA = "https://gate.local/schemas/campaign-worker-state.schema.json";
const MAX_HEARTBEAT_BYTES = 64 * 1024;
const DEFAULT_POLL_MS = 2_000;
const DEFAULT_HEARTBEAT_MS = 5_000;
const MIN_POLL_MS = 250;
const MAX_POLL_MS = 60_000;
const MIN_HEARTBEAT_MS = 1_000;
const MAX_HEARTBEAT_MS = 60_000;
const CURRENT_AFTER_MS = 15_000;
const DELAYED_AFTER_MS = 60_000;

function instant(value = Date.now()) {
  const parsed = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(parsed.getTime())) throw new Error("campaign worker time is invalid");
  return parsed.toISOString();
}

function nowValue(options = {}) {
  const value = typeof options.now === "function" ? options.now() : options.now ?? Date.now();
  return instant(value);
}

function boundedInteger(value, fallback, minimum, maximum, label) {
  const candidate = value === undefined ? fallback : Number(value);
  if (!Number.isSafeInteger(candidate) || candidate < minimum || candidate > maximum) {
    throw new Error(`${label} must be an integer between ${minimum} and ${maximum}`);
  }
  return candidate;
}

function processIdentity() {
  if (process.platform !== "linux") throw new Error("campaign workers require Linux/WSL2");
  const stat = fs.readFileSync(`/proc/${process.pid}/stat`, "utf8");
  const close = stat.lastIndexOf(")");
  const fields = close === -1 ? [] : stat.slice(close + 2).trim().split(/\s+/u);
  const startTimeTicks = fields[19];
  const bootId = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim().toLowerCase();
  if (!/^\d+$/u.test(startTimeTicks || "") || !/^[a-f0-9-]{36}$/u.test(bootId)) {
    throw new Error("campaign worker process identity is unavailable");
  }
  return { pid: process.pid, bootId, startTimeTicks };
}

function acquireWorkerLease(resolved, startedAt, worker = {}) {
  if (process.platform !== "linux") throw new Error("campaign worker serialization requires Linux/WSL2");
  const controller = worker.controller || processIdentity();
  const generation = worker.generation ?? null;
  if (generation !== null && !/^[a-f0-9]{32}$/u.test(generation)) {
    throw new Error("campaign worker generation is invalid");
  }
  const descriptor = fs.openSync(
    resolved.workerLease,
    fs.constants.O_CREAT | fs.constants.O_RDWR | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
    0o600
  );
  let retained = false;
  try {
    const fileIdentity = fs.fstatSync(descriptor);
    if (!fileIdentity.isFile() || fileIdentity.nlink !== 1 ||
        (typeof process.geteuid === "function" && fileIdentity.uid !== process.geteuid()) ||
        (fileIdentity.mode & 0o7777) !== 0o600) {
      throw new Error("campaign worker lease file is not owner-only");
    }
    const locked = spawnSync(
      campaignInternals.trustedCampaignFlock(),
      ["--exclusive", "--nonblock", "3"],
      {
        stdio: ["ignore", "pipe", "pipe", descriptor],
        env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
        shell: false,
        timeout: 5_000,
        maxBuffer: 16 * 1024
      }
    );
    if (locked.error || locked.status !== 0) {
      throw new Error("campaign worker is already active or its lease is indeterminate", { cause: locked.error });
    }
    const current = fs.lstatSync(resolved.workerLease);
    if (current.dev !== fileIdentity.dev || current.ino !== fileIdentity.ino) {
      throw new Error("campaign worker lease identity changed");
    }
    const owner = `${JSON.stringify({ ...controller, generation, acquiredAt: startedAt })}\n`;
    fs.ftruncateSync(descriptor, 0);
    fs.writeSync(descriptor, owner, 0, "utf8");
    fs.fsyncSync(descriptor);
    syncPrivateDirectory(resolved.directory, { label: "private campaign after worker lease acquisition" });
    retained = true;
    return Object.freeze({
      release() {
        fs.closeSync(descriptor);
      }
    });
  } finally {
    if (!retained) fs.closeSync(descriptor);
  }
}

function campaignProjection(status) {
  return {
    status: status.state.status,
    journal: structuredClone(status.state.journal),
    queue: structuredClone(status.state.queue)
  };
}

function campaignStatusForWorker(id, options, counters = null) {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    try { return campaignStatus(id, options); }
    catch (error) {
      const transient = /^private campaign journal changed while it was being (?:read|opened|verified)$/u
        .test(String(error?.message || ""));
      if (!transient || attempt === 3) throw error;
      if (counters) counters.snapshotRetries += 1;
    }
  }
  throw new Error("campaign worker snapshot retry exhausted");
}

function heartbeatEnvelope(context, serviceState, status, heartbeatAt, failureCategory = null) {
  const validUntil = new Date(
    Date.parse(heartbeatAt) + Math.max(CURRENT_AFTER_MS, context.heartbeatMs * 3)
  ).toISOString();
  return {
    $schema: WORKER_SCHEMA,
    apiVersion: "gate.dev/campaign-worker-state/v1",
    kind: "CampaignWorkerState",
    caseId: context.paths.caseId,
    campaignId: context.campaignId,
    generation: context.generation,
    controller: context.controller,
    serviceState,
    startedAt: context.startedAt,
    heartbeatAt,
    validUntil,
    campaign: campaignProjection(status),
    counters: structuredClone(context.counters),
    failureCategory
  };
}

function writeHeartbeat(context, serviceState, status, options = {}) {
  const at = nowValue(options);
  const heartbeat = heartbeatEnvelope(
    context,
    serviceState,
    status,
    at,
    options.failureCategory || null
  );
  assertValidDocument(heartbeat, "campaign-worker-state.schema.json", { paths: context.paths });
  const bytes = `${JSON.stringify(heartbeat, null, 2)}\n`;
  if (Buffer.byteLength(bytes, "utf8") > MAX_HEARTBEAT_BYTES) {
    throw new Error("campaign worker heartbeat exceeds its byte limit");
  }
  writePrivateFileAtomic(context.resolved.worker, bytes, {
    encoding: "utf8",
    label: "private campaign worker heartbeat"
  });
  context.lastHeartbeatMs = Date.parse(at);
  return heartbeat;
}

function wait(milliseconds, signal) {
  if (signal?.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(done, milliseconds);
    function done() {
      clearTimeout(timer);
      signal?.removeEventListener("abort", done);
      resolve();
    }
    signal?.addEventListener("abort", done, { once: true });
  });
}

function unavailableMetric() {
  return { availability: "unavailable", value: null };
}

function availableMetric(value) {
  return { availability: "available", value };
}

function unavailableCoverage() {
  return { availability: "unavailable", available: null, total: null };
}

function unavailableObjectives() {
  return { availability: "unavailable", completed: null, total: null };
}

function unavailableLearning() {
  return {
    availability: "unavailable",
    verdict: null,
    now: null,
    actionNeeded: null,
    updatedAt: null,
    stages: {
      observations: unavailableMetric(),
      candidates: unavailableMetric(),
      validated: unavailableMetric(),
      applied: unavailableMetric(),
      transferred: unavailableMetric(),
      regressed: unavailableMetric()
    }
  };
}

function unavailableIntegrity() {
  return {
    availability: "unavailable",
    status: null,
    checks: unavailableCoverage(),
    issues: unavailableMetric(),
    checkedAt: null
  };
}

function mergeCount(previous, observed) {
  const oldValue = previous?.availability === "available" ? previous.value : null;
  if (!Number.isSafeInteger(observed) || observed < 0) return oldValue === null ? unavailableMetric() : availableMetric(oldValue);
  return availableMetric(oldValue === null ? observed : Math.max(oldValue, observed));
}

function metricInteger(measurement) {
  return measurement?.availability === "available" &&
    Number.isSafeInteger(measurement.value) && measurement.value >= 0
    ? measurement.value
    : 0;
}

function observedInteger(measurement) {
  return measurement?.availability === "exact" && Number.isSafeInteger(measurement.value) && measurement.value >= 0
    ? measurement.value
    : null;
}

function campaignStage(state) {
  if (state.status === "running") return { now: "enumerating", actionNeeded: "solver" };
  if (state.status === "paused") return { now: "idle", actionNeeded: "operator" };
  if (state.status === "blocked") return { now: "blocked", actionNeeded: "review" };
  if (state.status === "completed") return { now: "complete", actionNeeded: "none" };
  return { now: "idle", actionNeeded: "none" };
}

function pilotStateFromCampaign(current, context, status, at, publication = {}) {
  const previous = current?.availability === "available" ? current.state : null;
  const semantic = publication.semantic !== false;
  const updatedAt = previous ? nextCtfPilotTimestamp(previous.metadata.updatedAt, at) : at;
  const validUntil = new Date(
    Date.parse(updatedAt) + Math.max(CURRENT_AFTER_MS, context.heartbeatMs * 3)
  ).toISOString();
  const sameProducer = previous?.metadata?.producer?.kind === "campaign-worker" &&
    previous.metadata.producer.campaignId === context.campaignId &&
    previous.metadata.producer.generation === context.generation;
  const preserveAssessment = sameProducer && !semantic;
  const stage = campaignStage(status.state);
  const previousSolving = previous?.solving?.availability === "available" ? previous.solving : null;
  const requests = observedInteger(status.state.usage.observed.requests);
  const tokens = observedInteger(status.state.usage.observed.totalTokens);
  const solving = {
    availability: "available",
    verdict: preserveAssessment && previousSolving ? previousSolving.verdict : status.state.status === "blocked" ? "blocked" : "unknown",
    now: preserveAssessment && previousSolving ? previousSolving.now : stage.now,
    actionNeeded: preserveAssessment && previousSolving ? previousSolving.actionNeeded : stage.actionNeeded,
    updatedAt: semantic ? updatedAt : previousSolving?.updatedAt || updatedAt,
    completion: sameProducer && previousSolving?.completion || {
      state: "unknown",
      reproduction: "unknown",
      externalAcceptance: "unknown"
    },
    objectives: previousSolving?.objectives || unavailableObjectives(),
    depth: previousSolving?.depth || {
      level: "unavailable",
      branchesExplored: unavailableMetric(),
      techniquesAttempted: unavailableMetric(),
      deadEndsRetired: unavailableMetric()
    },
    efficiency: {
      elapsedSeconds: previousSolving?.efficiency?.elapsedSeconds || unavailableMetric(),
      activeSeconds: previousSolving?.efficiency?.activeSeconds || unavailableMetric(),
      tokens: mergeCount(previousSolving?.efficiency?.tokens, tokens),
      // A campaign attempt is not necessarily a tool execution. Dry-run jobs
      // launch no tool and managed jobs may block before the broker. Preserve
      // a receipt-backed solver value, otherwise report this as unavailable.
      toolRuns: previousSolving?.efficiency?.toolRuns || unavailableMetric(),
      requests: requests === null ? unavailableMetric() : mergeCount(previousSolving?.efficiency?.requests, requests),
      retries: previousSolving?.efficiency?.retries || unavailableMetric()
    }
  };
  const previousCockpit = previous?.cockpit?.availability === "available" ? previous.cockpit : null;
  // The callback runs under the case pilot's mutation lock. Merge the latest
  // durable totals on every publication so another authorized producer cannot
  // be overwritten by a baseline captured earlier in this worker generation.
  // Keep a local floor for defense in depth and add only failures not already
  // represented by this worker's last successful publication.
  const projectedSemanticUpdates = Math.max(
    metricInteger(previousCockpit?.updatesPublished),
    context.lastPilotCounts?.published || 0
  ) + (semantic ? 1 : 0);
  const pendingFailures = Math.max(
    0,
    context.counters.pilotUpdateFailures - context.accountedPilotFailures
  );
  const projectedMissedUpdates = Math.max(
    metricInteger(previousCockpit?.updatesMissed),
    context.lastPilotCounts?.missed || 0
  ) + pendingFailures;
  context.pendingPilotCounts = {
    published: projectedSemanticUpdates,
    missed: projectedMissedUpdates
  };
  const cockpit = {
    availability: "available",
    verdict: preserveAssessment && previousCockpit ? previousCockpit.verdict : "unknown",
    now: preserveAssessment && previousCockpit ? previousCockpit.now : "current",
    actionNeeded: preserveAssessment && previousCockpit ? previousCockpit.actionNeeded : "none",
    updatedAt: semantic ? updatedAt : previousCockpit?.updatedAt || updatedAt,
    signals: previousCockpit?.signals || unavailableCoverage(),
    updatesPublished: availableMetric(projectedSemanticUpdates),
    updatesMissed: availableMetric(projectedMissedUpdates)
  };
  if (cockpit.verdict === "pass" && projectedMissedUpdates > 0) cockpit.verdict = "provisional";
  if (pendingFailures > 0) cockpit.updatedAt = updatedAt;
  return {
    $schema: "https://gate.local/schemas/ctf-pilot-state.schema.json",
    apiVersion: "gate.dev/ctf-pilot-state/v1",
    kind: "CtfPilotState",
    metadata: {
      id: previous?.metadata?.id || "campaign-pilot",
      caseId: context.paths.caseId,
      revision: (previous?.metadata?.revision || 0) + 1,
      updatedAt,
      validUntil,
      producer: {
        kind: "campaign-worker",
        campaignId: context.campaignId,
        generation: context.generation
      }
    },
    solving,
    learning: previous?.learning || unavailableLearning(),
    cockpit,
    // A new process generation has not re-established the prior producer's
    // integrity verdict. Keep receipt-backed learning, but make integrity
    // unavailable until a producer with current evidence writes it.
    integrity: sameProducer ? previous?.integrity || unavailableIntegrity() : unavailableIntegrity()
  };
}

function publishPilot(context, status, options = {}) {
  const at = nowValue(options);
  const semantic = options.semantic !== false;
  try {
    updateCtfPilotState(
      (current) => pilotStateFromCampaign(current, context, status, at, { semantic }),
      { paths: context.paths }
    );
    context.lastPilotCounts = context.pendingPilotCounts;
    context.pendingPilotCounts = null;
    context.accountedPilotFailures = context.counters.pilotUpdateFailures;
    context.counters.pilotUpdates += 1;
    if (semantic) context.counters.pilotSemanticUpdates += 1;
    context.lastPublishedJournalSequence = status.state.journal.sequence;
    return true;
  } catch (error) {
    context.pendingPilotCounts = null;
    context.counters.pilotUpdateFailures += 1;
    if (typeof options.onPilotError === "function") options.onPilotError(error);
    return false;
  }
}

function readHeartbeat(file, paths) {
  securePrivateFile(file, { allowMissing: false, label: "private campaign worker heartbeat" });
  let value;
  try {
    value = JSON.parse(readPrivateFileBounded(file, MAX_HEARTBEAT_BYTES, "utf8", {
      label: "private campaign worker heartbeat"
    }));
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error("campaign worker heartbeat is malformed", { cause: error });
    throw error;
  }
  assertValidDocument(value, "campaign-worker-state.schema.json", { paths });
  return value;
}

function unavailableProjection(campaignId, reason) {
  return {
    availability: "unavailable",
    freshness: "unavailable",
    campaignId,
    workerState: null,
    observedAt: null,
    validUntil: null,
    campaign: null,
    counters: null,
    reason
  };
}

function workerLiveness(controller) {
  if (process.platform !== "linux") return "unknown";
  let bootId;
  try { bootId = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim().toLowerCase(); }
  catch { return "unknown"; }
  if (bootId !== controller.bootId) return "dead";
  let stat;
  try { stat = fs.readFileSync(`/proc/${controller.pid}/stat`, "utf8"); }
  catch (error) { return new Set(["ENOENT", "ESRCH"]).has(error.code) ? "dead" : "unknown"; }
  const close = stat.lastIndexOf(")");
  const fields = close === -1 ? [] : stat.slice(close + 2).trim().split(/\s+/u);
  if (!/^[A-Z]$/u.test(fields[0] || "") || !/^\d+$/u.test(fields[19] || "")) return "unknown";
  if (fields[0] === "Z" || fields[19] !== controller.startTimeTicks) return "dead";
  return "live";
}

function validLeaseOwner(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value).sort();
  if (keys.join("\0") !== ["acquiredAt", "bootId", "generation", "pid", "startTimeTicks"].sort().join("\0")) {
    return false;
  }
  return Number.isSafeInteger(value.pid) && value.pid > 0 &&
    /^[a-f0-9-]{36}$/u.test(value.bootId || "") && /^\d+$/u.test(value.startTimeTicks || "") &&
    (value.generation === null || /^[a-f0-9]{32}$/u.test(value.generation || "")) &&
    Number.isFinite(Date.parse(value.acquiredAt || ""));
}

function workerLeaseObservation(file) {
  let descriptor;
  try {
    descriptor = fs.openSync(file, fs.constants.O_RDWR | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const identity = fs.fstatSync(descriptor);
    if (!identity.isFile() || identity.nlink !== 1 ||
        (typeof process.geteuid === "function" && identity.uid !== process.geteuid()) ||
        (identity.mode & 0o7777) !== 0o600 || identity.size < 2 || identity.size > 4096) {
      return { status: "unknown", owner: null };
    }
    const buffer = Buffer.alloc(Number(identity.size));
    const bytesRead = fs.readSync(descriptor, buffer, 0, buffer.length, 0);
    let owner = null;
    try { owner = JSON.parse(buffer.subarray(0, bytesRead).toString("utf8")); }
    catch { return { status: "unknown", owner: null }; }
    if (!validLeaseOwner(owner)) return { status: "unknown", owner: null };
    const probe = spawnSync(campaignInternals.trustedCampaignFlock(), ["--exclusive", "--nonblock", "3"], {
      stdio: ["ignore", "pipe", "pipe", descriptor],
      env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
      shell: false,
      timeout: 5_000,
      maxBuffer: 16 * 1024
    });
    if (probe.error) return { status: "unknown", owner: null };
    const status = probe.status === 0 ? "inactive" : probe.status === 1 ? "active" : "unknown";
    return { status, owner: status === "unknown" ? null : owner };
  } catch {
    return { status: "unknown", owner: null };
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

export function campaignWorkerProjection(id, options = {}) {
  const paths = options.paths || runtimePaths(options);
  const resolved = campaignInternals.campaignPaths(paths, id);
  let heartbeat;
  try {
    heartbeat = readHeartbeat(resolved.worker, paths);
  } catch (error) {
    const reason = error?.code === "ENOENT" ? "heartbeat-missing" : "heartbeat-invalid";
    return unavailableProjection(id, reason);
  }
  if (heartbeat.caseId !== paths.caseId || heartbeat.campaignId !== id) {
    return unavailableProjection(id, "heartbeat-binding-mismatch");
  }
  const at = Date.parse(nowValue(options));
  const observed = Date.parse(heartbeat.heartbeatAt);
  const validUntil = Date.parse(heartbeat.validUntil);
  if (Date.parse(heartbeat.startedAt) > observed || observed >= validUntil || at < observed) {
    return unavailableProjection(id, "heartbeat-invalid");
  }
  const ageMs = Math.max(0, at - observed);
  const liveness = workerLiveness(heartbeat.controller);
  const leaseObservation = workerLeaseObservation(resolved.workerLease);
  const lease = leaseObservation.status;
  const leaseOwner = leaseObservation.owner;
  const leaseBindingCurrent = lease !== "active" || leaseOwner &&
    leaseOwner.generation === heartbeat.generation &&
    leaseOwner.pid === heartbeat.controller.pid &&
    leaseOwner.bootId === heartbeat.controller.bootId &&
    leaseOwner.startTimeTicks === heartbeat.controller.startTimeTicks;
  const expired = at >= validUntil;
  const freshness = liveness !== "live" || lease !== "active" || !leaseBindingCurrent || expired
    ? "stale"
    : ageMs <= CURRENT_AFTER_MS
    ? "current"
    : ageMs <= DELAYED_AFTER_MS ? "delayed" : "stale";
  return {
    availability: "available",
    freshness,
    reason: lease === "inactive"
      ? "worker-inactive"
      : !leaseBindingCurrent
      ? "worker-generation-mismatch"
      : liveness === "dead"
      ? "worker-dead"
      : liveness === "unknown" || lease === "unknown"
        ? "worker-liveness-unavailable"
        : expired ? "heartbeat-expired" : null,
    campaignId: id,
    workerState: heartbeat.serviceState,
    observedAt: heartbeat.heartbeatAt,
    validUntil: heartbeat.validUntil,
    campaign: {
      status: heartbeat.campaign.status,
      journalSequence: heartbeat.campaign.journal.sequence,
      queue: structuredClone(heartbeat.campaign.queue)
    },
    counters: structuredClone(heartbeat.counters)
  };
}

/**
 * Verify that a private pilot producer still names the exact live worker
 * generation holding the campaign lease. The returned projection contains no
 * process identity, generation, selector, target, or command material.
 */
export function campaignWorkerProducerStatus(producer, options = {}) {
  const keys = producer && typeof producer === "object" && !Array.isArray(producer)
    ? Object.keys(producer).sort().join("\0")
    : "";
  if (keys !== ["campaignId", "generation", "kind"].sort().join("\0") ||
      producer.kind !== "campaign-worker" ||
      !/^[a-z][a-z0-9-]{1,62}$/u.test(producer.campaignId || "") ||
      !/^[a-f0-9]{32}$/u.test(producer.generation || "")) {
    return Object.freeze({ availability: "unavailable", reason: "producer-invalid", observedAt: null, validUntil: null });
  }
  const paths = options.paths || runtimePaths(options);
  const projection = campaignWorkerProjection(producer.campaignId, { ...options, paths });
  if (projection.availability !== "available" || projection.freshness === "stale" || projection.reason !== null) {
    return Object.freeze({
      availability: "unavailable",
      reason: projection.reason || "worker-unavailable",
      observedAt: projection.observedAt,
      validUntil: projection.validUntil
    });
  }
  const resolved = campaignInternals.campaignPaths(paths, producer.campaignId);
  let heartbeat;
  try { heartbeat = readHeartbeat(resolved.worker, paths); }
  catch {
    return Object.freeze({ availability: "unavailable", reason: "heartbeat-invalid", observedAt: null, validUntil: null });
  }
  if (heartbeat.generation !== producer.generation) {
    return Object.freeze({
      availability: "unavailable",
      reason: "worker-generation-mismatch",
      observedAt: heartbeat.heartbeatAt,
      validUntil: heartbeat.validUntil
    });
  }
  return Object.freeze({
    availability: "available",
    reason: null,
    observedAt: projection.observedAt,
    validUntil: projection.validUntil,
    freshness: projection.freshness,
    workerState: projection.workerState,
    journalSequence: projection.campaign.journalSequence
  });
}

function deferredManagedJob(state, reason) {
  return {
    ok: false,
    deferred: true,
    contactAttempted: false,
    state,
    job: state.jobs.find((job) => job.status === "queued")?.id || null,
    reason
  };
}

/**
 * Run one controller job, crossing into target contact only when the queue head
 * is a managed HTTP job and one exact, confirmed LabCampaignAuthority is
 * supplied (or was durably bound by adaptive enqueue). The controller start is
 * committed before dispatch; the terminal result is committed afterwards.
 */
export async function runNextCampaignWorkerJob(id, options = {}) {
  const paths = options.paths || runtimePaths(options);
  const observed = campaignStatus(id, { ...options, paths });
  const queued = observed.state.jobs.find((job) => job.status === "queued");
  if (!queued || queued.kind !== "managed-adapter") {
    return runNextCampaignJob(id, { ...options, paths });
  }

  const configuredAuthority = options.labAuthorityId === undefined || options.labAuthorityId === null ||
    options.labAuthorityId === ""
    ? null
    : String(options.labAuthorityId);
  if (queued.authority && configuredAuthority && queued.authority.id !== configuredAuthority) {
    return deferredManagedJob(observed.state, "The configured lab authority differs from the queue head's durable enqueue permit.");
  }
  const authorityId = queued.authority?.id || configuredAuthority;
  if (!authorityId) {
    return deferredManagedJob(observed.state, "A confirmed dedicated-lab authority must be selected before managed dispatch.");
  }

  const loadCampaignContext = options.loadCampaignContext || campaignInternals.loadCampaignContext;
  const readAuthorityStatus = options.labCampaignAuthorityStatus || labCampaignAuthorityStatus;
  let authority;
  try {
    authority = readAuthorityStatus(authorityId, { ...options, paths, loadCampaignContext });
  } catch (error) {
    return deferredManagedJob(observed.state, `Lab authority is unavailable: ${String(error?.message || error)}`);
  }
  if (authority && typeof authority.then === "function") {
    throw new Error("lab campaign authority status must be read synchronously before controller mutation");
  }
  if (authority?.authorityId !== authorityId || authority?.campaignId !== id ||
      authority?.confirmed !== true || authority?.status !== "authorized") {
    return deferredManagedJob(observed.state, "The selected lab authority is not confirmed, current, and bound to this campaign.");
  }

  const controllerOptions = { ...options, paths };
  const started = startNextManagedCampaignJob(id, authorityId, controllerOptions);
  if (!started.ok || !started.envelope) return started;
  const dispatch = options.dispatchAuthorizedLabCampaignJob || dispatchAuthorizedLabCampaignJob;
  let dispatchResult;
  try {
    dispatchResult = await dispatch(authorityId, structuredClone(started.envelope), {
      ...options,
      paths,
      loadCampaignContext
    });
  } catch (error) {
    try {
      return blockManagedCampaignJob(id, authorityId, started.envelope, error, controllerOptions);
    } catch (controllerError) {
      throw new AggregateError(
        [error, controllerError],
        "lab dispatch failed and its campaign ambiguity record could not be committed"
      );
    }
  }
  return completeManagedCampaignJob(id, authorityId, started.envelope, dispatchResult, controllerOptions);
}

export async function runCampaignWorker(id, options = {}) {
  const paths = options.paths || runtimePaths(options);
  const pollMs = boundedInteger(options.pollMs, DEFAULT_POLL_MS, MIN_POLL_MS, MAX_POLL_MS, "campaign worker poll interval");
  const heartbeatMs = boundedInteger(
    options.heartbeatMs,
    DEFAULT_HEARTBEAT_MS,
    MIN_HEARTBEAT_MS,
    MAX_HEARTBEAT_MS,
    "campaign worker heartbeat interval"
  );
  const resolved = campaignInternals.campaignPaths(paths, id);
  const startedAt = nowValue(options);
  const generation = crypto.randomBytes(16).toString("hex");
  const processController = processIdentity();
  const lease = acquireWorkerLease(resolved, startedAt, {
    generation,
    controller: processController
  });
  const controller = new AbortController();
  const externalSignal = options.signal;
  const abortFromExternal = () => controller.abort();
  externalSignal?.addEventListener("abort", abortFromExternal, { once: true });
  if (externalSignal?.aborted) controller.abort();
  const processSignals = options.processSignals !== false;
  const stopFromSignal = () => controller.abort();
  if (processSignals) {
    process.once("SIGINT", stopFromSignal);
    process.once("SIGTERM", stopFromSignal);
  }
  const context = {
    paths,
    resolved,
    campaignId: id,
    generation,
    controller: processController,
    startedAt,
    counters: {
      cycles: 0,
      runNextCalls: 0,
      recoveries: 0,
      snapshotRetries: 0,
      heartbeatWriteFailures: 0,
      pilotUpdates: 0,
      pilotSemanticUpdates: 0,
      pilotUpdateFailures: 0
    },
    heartbeatMs,
    lastHeartbeatMs: 0,
    lastPublishedJournalSequence: null,
    lastPilotCounts: null,
    pendingPilotCounts: null,
    accountedPilotFailures: 0
  };
  let latest = null;
  try {
    const recovered = recoverCampaign(id, { ...options, paths });
    if (recovered.retiredLock || recovered.repairedJournalTail || recovered.recoveredJobs.length > 0) {
      context.counters.recoveries += 1;
    }
    latest = campaignStatusForWorker(id, { ...options, paths }, context.counters);
    writeHeartbeat(context, "starting", latest, options);
    publishPilot(context, latest, options);
    while (!controller.signal.aborted) {
      context.counters.cycles += 1;
      latest = campaignStatusForWorker(id, { ...options, paths }, context.counters);
      if (latest.state.journal.sequence !== context.lastPublishedJournalSequence) {
        publishPilot(context, latest, options);
      }
      if (latest.state.status === "stopped") {
        const heartbeat = writeHeartbeat(context, "stopping", latest, options);
        return {
          ok: true,
          campaignId: id,
          reason: latest.state.status,
          heartbeatAt: heartbeat.heartbeatAt,
          counters: structuredClone(context.counters)
        };
      }
      if (latest.state.status === "running") {
        writeHeartbeat(context, "running", latest, options);
        context.counters.runNextCalls += 1;
        const cycle = await runNextCampaignWorkerJob(id, {
          ...options,
          paths,
          onTransition(transition) {
            latest = { ...latest, state: transition.state };
            const serviceState = transition.state.status === "stopped"
              ? "stopping"
              : transition.state.status === "running" ? "running" : "waiting";
            try { writeHeartbeat(context, serviceState, latest, options); }
            catch { context.counters.heartbeatWriteFailures += 1; }
            publishPilot(context, latest, options);
          }
        });
        if (cycle?.deferred) {
          latest = campaignStatusForWorker(id, { ...options, paths }, context.counters);
          writeHeartbeat(context, "waiting", latest, options);
          publishPilot(context, latest, { ...options, semantic: false });
          await (options.wait || wait)(Math.min(pollMs, heartbeatMs), controller.signal);
        }
        continue;
      }
      const currentMs = Date.parse(nowValue(options));
      if (currentMs - context.lastHeartbeatMs >= heartbeatMs) {
        writeHeartbeat(context, "waiting", latest, options);
        publishPilot(context, latest, { ...options, semantic: false });
      }
      const untilHeartbeat = Math.max(1, heartbeatMs - (currentMs - context.lastHeartbeatMs));
      await (options.wait || wait)(Math.min(pollMs, untilHeartbeat), controller.signal);
    }
    latest = campaignStatusForWorker(id, { ...options, paths }, context.counters);
    const heartbeat = writeHeartbeat(context, "stopping", latest, options);
    return {
      ok: true,
      campaignId: id,
      reason: "signal",
      heartbeatAt: heartbeat.heartbeatAt,
      counters: structuredClone(context.counters)
    };
  } catch (error) {
    try {
      writeHeartbeat(context, "failed", latest, { ...options, failureCategory: "controller-error" });
    } catch {
      // Preserve the primary controller failure. A stale/missing heartbeat is
      // itself visible to the bounded projector.
    }
    throw error;
  } finally {
    if (processSignals) {
      process.removeListener("SIGINT", stopFromSignal);
      process.removeListener("SIGTERM", stopFromSignal);
    }
    externalSignal?.removeEventListener("abort", abortFromExternal);
    lease.release();
  }
}

export const campaignWorkerInternals = Object.freeze({
  acquireWorkerLease,
  deferredManagedJob,
  heartbeatEnvelope,
  readHeartbeat,
  workerLeaseObservation,
  writeHeartbeat
});
