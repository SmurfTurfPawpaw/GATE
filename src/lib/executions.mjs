import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

import { checkEngagement } from "./engagements.mjs";
import { recordEvent } from "./events.mjs";
import {
  assertManagedAdapterManifest,
  prepareManagedAdapterInvocation,
  reverifyManagedAdapterManifest,
  validateManagedAdapterOutput
} from "./managed-adapters.mjs";
import { ensureRuntime, runtimePaths } from "./paths.mjs";
import {
  openPrivateFileExclusive,
  readPrivateFileBounded,
  securePrivateDirectory,
  writePrivateFileAtomic,
  writePrivateFileExclusive
} from "./private-fs.mjs";
import { assertValidDocument } from "./schema.mjs";
import { toolPlan } from "./tools.mjs";
import {
  cancelWorkflowExecution,
  checkWorkflowExecution,
  claimWorkflowExecution,
  completeWorkflowExecution,
  reserveWorkflowExecution,
  workflowRuntimeInternals,
  workflowStatus
} from "./workflow-runtime.mjs";

const TARGET_PLACEHOLDER = "{{GATE_TARGET}}";
const DEFAULT_MANIFEST_TTL_MS = 15 * 60_000;
const DEFAULT_POLL_INTERVAL_MS = 250;
const DEFAULT_TERMINATION_GRACE_MS = 3_000;
const DEFAULT_MAX_EVIDENCE_BYTES = 256 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 2 * 1024 * 1024;
const MAX_RUN_BYTES = 512 * 1024;
const MAX_EXECUTABLE_BYTES = 4 * 1024 * 1024 * 1024;

export const EXECUTION_ENFORCED = Object.freeze([
  "engagement-binding",
  "workflow-phase-binding",
  "workflow-reservation",
  "target-argument-binding",
  "declared-action-label-binding",
  "tool-allowlist",
  "exact-argv",
  "shell-disabled",
  "executable-descriptor-observed-sha256",
  "minimal-environment",
  "private-stdout-stderr",
  "one-shot-claim",
  "declared-bounds-within-receipt"
]);

export const EXECUTION_BEST_EFFORT = Object.freeze([
  "authorization-revocation-polling",
  "wall-duration",
  "process-group-termination"
]);

export const EXECUTION_UNAVAILABLE = Object.freeze([
  "egress-target-restriction",
  "request-count-measurement",
  "request-rate-measurement",
  "tool-concurrency-measurement",
  "token-measurement",
  "daemon-escape-containment",
  "filesystem-isolation",
  "credential-broker",
  "tool-artifact-inventory",
  "known-good-executable-provenance",
  "argv-action-semantics-validation",
  "supervisor-crash-containment",
  "immutable-executable-snapshot"
]);

export const MANAGED_EXECUTION_ENFORCED = Object.freeze([
  "engagement-binding",
  "workflow-phase-binding",
  "workflow-reservation",
  "target-argument-binding",
  "declared-action-label-binding",
  "tool-allowlist",
  "exact-argv",
  "shell-disabled",
  "executable-descriptor-observed-sha256",
  "minimal-environment",
  "private-stdout-stderr",
  "one-shot-claim",
  "declared-bounds-within-receipt",
  "reviewed-adapter-registry",
  "adapter-operation-schema",
  "argv-action-semantics-validation",
  "managed-runtime-lock",
  "current-managed-executable",
  "zero-egress-smoke-before-launch",
  "discovered-target-expansion-disabled",
  "current-workflow-journal-head"
]);

export const MANAGED_EXECUTION_BEST_EFFORT = Object.freeze([
  "authorization-revocation-polling",
  "wall-duration",
  "process-group-termination",
  "tool-request-bound",
  "tool-rate-limit",
  "tool-concurrency-limit",
  "workflow-stop-polling"
]);

export const MANAGED_EXECUTION_UNAVAILABLE = Object.freeze([
  "egress-target-restriction",
  "request-count-measurement",
  "request-rate-measurement",
  "tool-concurrency-measurement",
  "token-measurement",
  "daemon-escape-containment",
  "filesystem-isolation",
  "credential-broker",
  "supervisor-crash-containment",
  "immutable-executable-snapshot"
]);

function executionPaths(input) {
  const paths = input || runtimePaths();
  const executions = paths.executions || path.join(paths.home, "executions");
  return {
    ...paths,
    executions,
    executionManifests: paths.executionManifests || path.join(executions, "manifests"),
    executionClaims: paths.executionClaims || path.join(executions, "claims"),
    executionRuns: paths.executionRuns || path.join(executions, "runs"),
    executionStops: paths.executionStops || path.join(executions, "stops"),
    executionSandboxes: paths.executionSandboxes || path.join(executions, "sandboxes")
  };
}

function stableObject(value) {
  if (Array.isArray(value)) return value.map(stableObject);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableObject(value[key])]));
}

function sha256(content) {
  return crypto.createHash("sha256").update(content).digest("hex");
}

function canonicalDigest(value) {
  return sha256(Buffer.from(JSON.stringify(stableObject(value))));
}

function manifestEnvelope(value) {
  const copy = structuredClone(value);
  delete copy.manifestSha256;
  return copy;
}

function manifestDigest(value) {
  return canonicalDigest(manifestEnvelope(value));
}

function randomId(prefix) {
  return `${prefix}_${crypto.randomBytes(16).toString("hex")}`;
}

function currentIds() {
  if (typeof process.geteuid !== "function" || typeof process.getegid !== "function") {
    throw new Error("the supervised execution lane requires POSIX user identity support");
  }
  return { uid: process.geteuid(), gid: process.getegid() };
}

function procStartTime(statText) {
  const close = statText.lastIndexOf(")");
  if (close === -1) return null;
  const fields = statText.slice(close + 2).trim().split(/\s+/u);
  return fields.length > 19 && /^\d+$/u.test(fields[19]) ? fields[19] : null;
}

function processSnapshot(pid, knownBootId = null) {
  const statText = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
  const close = statText.lastIndexOf(")");
  if (close === -1) throw new Error("process stat is malformed");
  const fields = statText.slice(close + 2).trim().split(/\s+/u);
  const state = fields[0];
  const pgid = Number(fields[2]);
  const sessionId = Number(fields[3]);
  const startTimeTicks = procStartTime(statText);
  const bootId = knownBootId || fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim().toLowerCase();
  if (
    !Number.isSafeInteger(pgid) || pgid < 1 || !Number.isSafeInteger(sessionId) || sessionId < 1 ||
    !startTimeTicks || !/^[a-f0-9-]{36}$/u.test(bootId)
  ) {
    throw new Error("process identity is unavailable");
  }
  return { identity: { pid, pgid, sessionId, bootId, startTimeTicks }, state };
}

function processIdentity(pid) {
  return processSnapshot(pid).identity;
}

function sameProcessIdentity(left, right) {
  return Boolean(left && right) && left.pid === right.pid && left.pgid === right.pgid &&
    left.sessionId === right.sessionId && left.bootId === right.bootId && left.startTimeTicks === right.startTimeTicks;
}

function liveProcessIdentity(expected) {
  if (!expected) return false;
  try {
    const snapshot = processSnapshot(expected.pid);
    return snapshot.state !== "Z" && sameProcessIdentity(snapshot.identity, expected);
  } catch {
    return false;
  }
}

export function executionCapability() {
  let reason = null;
  if (process.platform !== "linux") reason = "unsupported-platform";
  else {
    try {
      const stat = fs.statSync("/proc/self/fd");
      if (!stat.isDirectory()) reason = "proc-descriptor-unavailable";
    } catch {
      reason = "proc-descriptor-unavailable";
    }
    if (!reason) {
      try {
        processIdentity(process.pid);
      } catch {
        reason = "proc-process-identity-unavailable";
      }
    }
  }
  return {
    configured: true,
    laneAvailable: reason === null,
    mode: "supervised-generic",
    reason,
    enforced: [...EXECUTION_ENFORCED],
    bestEffort: [...EXECUTION_BEST_EFFORT],
    unavailable: [...EXECUTION_UNAVAILABLE]
  };
}

function requireCapability() {
  const capability = executionCapability();
  if (!capability.laneAvailable) throw new Error(`supervised execution is unavailable: ${capability.reason}`);
  return capability;
}

function positiveInteger(value, name, minimum = 1) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < minimum) throw new Error(`${name} must be an integer of at least ${minimum}`);
  return number;
}

function positiveNumber(value, name) {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) throw new Error(`${name} must be positive`);
  return number;
}

function normalizeManifestInput(input) {
  const workflowId = String(input.workflowId || "");
  if (!/^[a-z][a-z0-9-]{1,62}$/u.test(workflowId)) {
    throw new Error("workflowId must be a valid workflow instance identifier");
  }
  const phaseAttemptId = String(input.phaseAttemptId || "");
  if (!/^wpa_[a-f0-9]{32}$/u.test(phaseAttemptId)) {
    throw new Error("phaseAttemptId must be a valid workflow phase-attempt identifier");
  }
  const target = String(input.target || "");
  if (!target || target.length > 1000 || /[\u0000\r\n]/u.test(target)) {
    throw new Error("execution target must be a nonempty single-line value of at most 1000 characters");
  }
  const toolId = String(input.toolId || "");
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(toolId) || toolId.length < 2 || toolId.length > 64) {
    throw new Error("toolId must be a catalog-style tool identifier");
  }
  if (!Array.isArray(input.argv) || input.argv.length < 1 || input.argv.length > 256) {
    throw new Error("argv must contain from 1 to 256 exact arguments");
  }
  let totalBytes = 0;
  const argvTemplate = input.argv.map((argument) => {
    if (typeof argument !== "string" || argument.length > 8192 || argument.includes("\u0000")) {
      throw new Error("every argument must be a NUL-free string of at most 8192 characters");
    }
    totalBytes += Buffer.byteLength(argument);
    return argument;
  });
  if (totalBytes > 131_072) throw new Error("the argument array exceeds the 131072-byte limit");
  const targetSlots = argvTemplate.flatMap((value, index) => value === TARGET_PLACEHOLDER ? [index] : []);
  if (targetSlots.length !== 1) {
    throw new Error(`argv must contain exactly one whole-argument ${TARGET_PLACEHOLDER} placeholder`);
  }
  const argv = [...argvTemplate];
  argv[targetSlots[0]] = target;
  const maxEvidenceBytes = positiveInteger(
    input.maxEvidenceBytes || DEFAULT_MAX_EVIDENCE_BYTES * 2,
    "maxEvidenceBytes",
    2 * 1024 * 1024
  );
  if (maxEvidenceBytes > 2 * 1024 * 1024 * 1024) throw new Error("maxEvidenceBytes exceeds 2 GiB");
  return {
    workflowId,
    phaseAttemptId,
    target,
    action: String(input.action || ""),
    toolId,
    argv,
    targetArgIndex: targetSlots[0],
    declaredBounds: {
      maxMinutes: positiveInteger(input.maxMinutes, "maxMinutes"),
      estimatedRequests: positiveInteger(input.estimatedRequests, "estimatedRequests"),
      maxParallel: positiveInteger(input.maxParallel, "maxParallel"),
      maxRatePerSecond: positiveNumber(input.maxRatePerSecond, "maxRatePerSecond"),
      maxTokens: positiveInteger(input.maxTokens, "maxTokens", 1000),
      maxEvidenceBytes
    }
  };
}

function statIdentity(stat) {
  return {
    size: Number(stat.size),
    device: String(stat.dev),
    inode: String(stat.ino),
    mtimeNs: String(stat.mtimeNs),
    ctimeNs: String(stat.ctimeNs)
  };
}

function sameStat(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function openExecutable(requestedPath, expected = null) {
  if (typeof requestedPath !== "string" || !path.isAbsolute(requestedPath) || /[\u0000\r\n]/u.test(requestedPath)) {
    throw new Error("the discovered executable path must be an absolute single-line path");
  }
  const resolvedPath = expected?.resolvedPath || fs.realpathSync.native(requestedPath);
  if (!path.isAbsolute(resolvedPath) || /[\u0000\r\n]/u.test(resolvedPath)) {
    throw new Error("the physical executable path is invalid");
  }
  const beforePath = fs.lstatSync(resolvedPath, { bigint: true });
  if (!beforePath.isFile() || beforePath.isSymbolicLink()) throw new Error("the physical executable must be a regular non-symlink file");
  if (beforePath.size < 1n || beforePath.size > BigInt(MAX_EXECUTABLE_BYTES)) {
    throw new Error(`the executable must be from 1 to ${MAX_EXECUTABLE_BYTES} bytes`);
  }
  fs.accessSync(resolvedPath, fs.constants.X_OK);
  if (!fs.constants.O_NOFOLLOW) throw new Error("the platform cannot open an executable without following links");
  const descriptor = fs.openSync(resolvedPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!opened.isFile() || !sameStat(beforePath, opened)) throw new Error("the executable changed while it was opened");
    const hash = crypto.createHash("sha256");
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let total = 0;
    while (true) {
      const bytesRead = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      hash.update(buffer.subarray(0, bytesRead));
    }
    const afterRead = fs.fstatSync(descriptor, { bigint: true });
    const afterPath = fs.lstatSync(resolvedPath, { bigint: true });
    if (!sameStat(opened, afterRead) || !sameStat(afterRead, afterPath) || total !== Number(afterRead.size)) {
      throw new Error("the executable changed while it was hashed");
    }
    const value = {
      requestedPath,
      resolvedPath,
      sha256: hash.digest("hex"),
      ...statIdentity(afterRead)
    };
    if (expected) {
      for (const key of ["resolvedPath", "sha256", "size", "device", "inode", "mtimeNs", "ctimeNs"]) {
        if (value[key] !== expected[key]) throw new Error(`the executable ${key} changed after manifest creation`);
      }
    }
    return { descriptor, value };
  } catch (error) {
    fs.closeSync(descriptor);
    throw error;
  }
}

function assertExecutableDescriptorStable(descriptor, expected) {
  const current = fs.fstatSync(descriptor, { bigint: true });
  if (!current.isFile()) throw new Error("the verified executable descriptor is no longer a regular file");
  const value = statIdentity(current);
  for (const key of ["size", "device", "inode", "mtimeNs", "ctimeNs"]) {
    if (value[key] !== expected[key]) throw new Error(`the executable ${key} changed before launch`);
  }
}

function closeDescriptor(descriptor) {
  if (descriptor === null || descriptor === undefined) return;
  try {
    fs.closeSync(descriptor);
  } catch {
    // The primary execution result owns the diagnostic.
  }
}

function checkInput(operation, bounds) {
  return {
    target: operation.targetArgument,
    action: operation.action,
    maxMinutes: bounds.maxMinutes,
    estimatedRequests: bounds.estimatedRequests,
    maxParallel: bounds.maxParallel,
    maxRatePerSecond: bounds.maxRatePerSecond,
    maxTokens: bounds.maxTokens
  };
}

function workflowReservationEnvelope(bounds) {
  return {
    maxMinutes: bounds.maxMinutes,
    maxRequests: bounds.estimatedRequests,
    maxRatePerSecond: bounds.maxRatePerSecond,
    maxParallel: bounds.maxParallel,
    maxTotalTokens: bounds.maxTokens,
    maxEvidenceBytes: bounds.maxEvidenceBytes
  };
}

function requireExecutionBinding(check, expected = null, toolId = null) {
  if (!check?.allowed) throw new Error(`engagement preflight failed: ${(check?.reasons || ["unknown reason"]).join("; ")}`);
  const binding = check.executionBinding;
  if (!binding || typeof binding !== "object") throw new Error("engagement preflight did not produce an execution binding");
  if (toolId && (!Array.isArray(binding.permittedTools) || !binding.permittedTools.includes(toolId))) {
    throw new Error(`tool is outside the approved engagement scope: ${toolId}`);
  }
  if (binding.environment !== "host") {
    throw new Error(`the supervised generic lane requires an approved host environment (received ${binding.environment || "unknown"})`);
  }
  if (!Array.isArray(binding.allowedDestinations) || !binding.allowedDestinations.includes("gate-home")) {
    throw new Error("the supervised generic lane requires gate-home as an approved evidence destination");
  }
  if (expected) {
    const comparisons = [
      ["engagementId", expected.engagement.id],
      ["planSha256", expected.engagement.planSha256],
      ["envelopeSha256", expected.engagement.envelopeSha256],
      ["receiptSha256", expected.engagement.receiptSha256],
      ["authorizationValidUntil", expected.engagement.authorizationValidUntil],
      ["environment", expected.engagement.environment],
      ["action", expected.operation.action]
    ];
    for (const [key, value] of comparisons) {
      if (binding[key] !== value) throw new Error(`engagement execution binding changed: ${key}`);
    }
    if (canonicalDigest(binding.allowedDestinations) !== canonicalDigest(expected.engagement.allowedDestinations)) {
      throw new Error("engagement execution binding changed: allowedDestinations");
    }
    if (canonicalDigest(binding.target) !== canonicalDigest(expected.operation.targetSelector)) {
      throw new Error("engagement execution binding changed: target");
    }
  }
  return binding;
}

function executionFile(directory, id, prefix) {
  if (!new RegExp(`^${prefix}_[a-f0-9]{32}$`, "u").test(id)) throw new Error(`invalid ${prefix} identifier`);
  return path.join(directory, `${id}.json`);
}

function manifestFile(paths, id) {
  return executionFile(paths.executionManifests, id, "xmf");
}

function runFile(paths, id) {
  return executionFile(paths.executionRuns, id, "xrun");
}

function stopFile(paths, id) {
  return executionFile(paths.executionStops, id, "xrun");
}

function claimFile(paths, id) {
  return executionFile(paths.executionClaims, id, "xmf");
}

function exactArray(value, expected) {
  return Array.isArray(value) && value.length === expected.length && value.every((item, index) => item === expected[index]);
}

function assertManifestInvariants(manifest, paths) {
  const runId = manifest.metadata.runId;
  const managed = manifest.operation.adapter !== null;
  if (
    workflowRuntimeInternals.canonicalDigest(
      manifest.workflow.effectiveStops,
      "gate.workflow.effective-stops.v1"
    ) !== manifest.workflow.effectiveStopsSha256
  ) {
    throw new Error("execution manifest effective stop binding is invalid");
  }
  if (!managed && manifest.operation.argv[manifest.operation.targetArgIndex] !== manifest.operation.targetArgument) {
    throw new Error("execution manifest target argument binding is invalid");
  }
  if (manifest.operation.targetSelector.value !== manifest.operation.targetArgument) {
    throw new Error("execution manifest canonical target binding is invalid");
  }
  if (
    manifest.operation.argv0 !== path.basename(manifest.operation.executable.requestedPath) ||
    manifest.operation.tool.catalogCommand !== manifest.operation.argv0
  ) {
    throw new Error("execution manifest catalog executable binding is invalid");
  }
  const expectedEvidence = evidenceRefs(runId);
  for (const key of ["stdoutRef", "stderrRef", "resultRef"]) {
    if (manifest.runtime.evidence[key] !== expectedEvidence[key]) {
      throw new Error(`execution manifest evidence binding is invalid: ${key}`);
    }
  }
  if (manifest.runtime.sandboxRef !== `private://executions/sandboxes/${runId}`) {
    throw new Error("execution manifest sandbox binding is invalid");
  }
  if (manifest.runtime.maxEvidenceBytesPerStream !== Math.floor(manifest.declaredBounds.maxEvidenceBytes / 2)) {
    throw new Error("execution manifest evidence allocation binding is invalid");
  }
  const expectedEnvironment = minimalExecutionEnvironment(paths, runId, manifest.operation.executable.resolvedPath);
  if (canonicalDigest(manifest.runtime.environment) !== canonicalDigest(expectedEnvironment)) {
    throw new Error("execution manifest minimal environment binding is invalid");
  }
  if (manifest.runtime.mode !== (managed ? "reviewed-managed-adapter" : "supervised-generic")) {
    throw new Error("execution manifest runtime lane binding is invalid");
  }
  if (manifest.operation.tool.readiness !== (managed ? "verified-managed" : "discovered") ||
      manifest.operation.tool.knownGoodProvenance !== managed) {
    throw new Error("execution manifest tool provenance claim is invalid");
  }
  const expectedEnforced = managed ? MANAGED_EXECUTION_ENFORCED : EXECUTION_ENFORCED;
  const expectedBestEffort = managed ? MANAGED_EXECUTION_BEST_EFFORT : EXECUTION_BEST_EFFORT;
  const expectedUnavailable = managed ? MANAGED_EXECUTION_UNAVAILABLE : EXECUTION_UNAVAILABLE;
  if (!exactArray(manifest.enforcement.enforced, expectedEnforced)) {
    throw new Error("execution manifest enforced capability claims are invalid");
  }
  if (!exactArray(manifest.enforcement.bestEffort, expectedBestEffort)) {
    throw new Error("execution manifest best-effort capability claims are invalid");
  }
  if (!exactArray(manifest.enforcement.unavailable, expectedUnavailable)) {
    throw new Error("execution manifest unavailable capability claims are invalid");
  }
  if (managed) assertManagedAdapterManifest(manifest, { paths });
  const createdAt = Date.parse(manifest.metadata.createdAt);
  const expiresAt = Date.parse(manifest.metadata.expiresAt);
  const authorizationEnd = Date.parse(manifest.engagement.authorizationValidUntil);
  if (!(createdAt < expiresAt && expiresAt <= authorizationEnd)) {
    throw new Error("execution manifest validity window is invalid");
  }
}

function assertRunInvariants(run) {
  const expected = evidenceRefs(run.runId);
  if (
    run.evidence.stdout.ref !== expected.stdoutRef ||
    run.evidence.stderr.ref !== expected.stderrRef ||
    run.evidence.resultRef !== expected.resultRef ||
    run.evidence.sandboxRef !== `private://executions/sandboxes/${run.runId}`
  ) {
    throw new Error("execution run evidence binding is invalid");
  }
  if (run.status === "queued" && (run.startedAt || run.finishedAt || run.process || run.terminationReason)) {
    throw new Error("queued execution run lifecycle is invalid");
  }
  if (new Set(["running", "stopping"]).has(run.status) && (!run.startedAt || run.finishedAt || !run.process)) {
    throw new Error(`${run.status} execution run lifecycle is invalid`);
  }
  if (run.status === "running" && run.terminationReason) throw new Error("running execution cannot have a termination reason");
  if (run.status === "stopping" && !run.terminationReason) throw new Error("stopping execution must have a termination reason");
  if (new Set(["succeeded", "failed", "cancelled", "blocked"]).has(run.status) && !run.finishedAt) {
    throw new Error("terminal execution run must have a finish time");
  }
  if (
    run.status === "succeeded" &&
    (run.terminationReason !== "completed" || run.result.exitCode !== 0 || run.result.signal !== null)
  ) {
    throw new Error("succeeded execution run result is invalid");
  }
  if (run.status === "cancelled" && (!run.terminationReason || run.terminationReason === "completed")) {
    throw new Error("cancelled execution run reason is invalid");
  }
  if (run.status === "blocked" && (
    run.startedAt || run.process || !new Set([
      null,
      "workflow-claim-failed",
      "managed-runtime-invalidated"
    ]).has(run.terminationReason)
  )) {
    throw new Error("blocked execution run lifecycle is invalid");
  }
  if (run.status === "unknown" && (!run.finishedAt || run.terminationReason !== "supervision-lost")) {
    throw new Error("unknown execution run must record supervision loss");
  }
  for (const stream of [run.evidence.stdout, run.evidence.stderr]) {
    if (stream.available !== (stream.sha256 !== null)) {
      throw new Error("execution stream availability does not match its digest");
    }
    if (!stream.available && stream.bytes !== 0) {
      throw new Error("unavailable execution stream cannot claim captured bytes");
    }
  }
}

function readManifest(paths, id) {
  const value = JSON.parse(readPrivateFileBounded(
    manifestFile(paths, id),
    MAX_MANIFEST_BYTES,
    "utf8",
    { label: `private execution manifest ${id}` }
  ));
  assertValidDocument(value, "execution-manifest.schema.json", { paths });
  if (manifestDigest(value) !== value.manifestSha256) throw new Error("execution manifest digest changed");
  assertManifestInvariants(value, paths);
  return value;
}

function readRun(paths, id) {
  const value = JSON.parse(readPrivateFileBounded(
    runFile(paths, id),
    MAX_RUN_BYTES,
    "utf8",
    { label: `private execution run ${id}` }
  ));
  assertValidDocument(value, "execution-run.schema.json", { paths });
  assertRunInvariants(value);
  return value;
}

function readClaim(paths, manifestId) {
  const claim = JSON.parse(readPrivateFileBounded(
    claimFile(paths, manifestId),
    64 * 1024,
    "utf8",
    { label: `one-shot execution claim ${manifestId}` }
  ));
  const identity = claim.supervisor;
  const workflow = claim.workflow;
  if (
    claim.apiVersion !== "gate.execution-claim/v1" || claim.manifestId !== manifestId ||
    !/^xrun_[a-f0-9]{32}$/u.test(claim.runId) ||
    !/^[a-z][a-z0-9-]{1,62}$/u.test(claim.engagementId) ||
    !/^[a-f0-9]{64}$/u.test(claim.manifestSha256) ||
    !workflow || !/^[a-z][a-z0-9-]{1,62}$/u.test(workflow.instanceId) ||
    !/^[a-z][a-z0-9-]{1,79}$/u.test(workflow.phaseId) ||
    !/^wpa_[a-f0-9]{32}$/u.test(workflow.phaseAttemptId) ||
    !/^wxr_[a-f0-9]{32}$/u.test(workflow.reservationId) ||
    !/^[a-f0-9]{64}$/u.test(workflow.executionEpochSha256) ||
    !Number.isFinite(Date.parse(claim.claimedAt)) || !Number.isFinite(Date.parse(claim.createdAt)) ||
    !identity || !Number.isSafeInteger(identity.pid) || identity.pid < 1 ||
    !Number.isSafeInteger(identity.pgid) || identity.pgid < 1 ||
    !Number.isSafeInteger(identity.sessionId) || identity.sessionId < 1 ||
    !/^[a-f0-9-]{36}$/u.test(identity.bootId) || !/^\d+$/u.test(identity.startTimeTicks)
  ) {
    throw new Error("one-shot execution claim metadata is invalid");
  }
  return claim;
}

function readClaimMetadata(paths, manifestId) {
  const claim = readClaim(paths, manifestId);
  const identity = claim.supervisor;
  return {
    runId: claim.runId,
    manifestId: claim.manifestId,
    engagementId: claim.engagementId,
    workflow: {
      instanceId: claim.workflow.instanceId,
      phaseId: claim.workflow.phaseId,
      phaseAttemptId: claim.workflow.phaseAttemptId,
      reservationId: claim.workflow.reservationId
    },
    status: liveProcessIdentity(identity) ? "queued" : "unknown",
    createdAt: claim.createdAt,
    startedAt: null,
    finishedAt: null,
    terminationReason: null,
    exitCode: null,
    signal: null
  };
}

function writeRun(paths, value) {
  assertValidDocument(value, "execution-run.schema.json", { paths });
  assertRunInvariants(value);
  writePrivateFileAtomic(runFile(paths, value.runId), `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf8",
    label: `private execution run ${value.runId}`
  });
}

function minimalExecutionEnvironment(paths, runId, executablePath) {
  const sandbox = path.join(paths.executionSandboxes, runId);
  const executableDirectory = path.dirname(executablePath);
  if (executableDirectory.includes(":")) throw new Error("executable directories containing ':' cannot be represented safely in PATH");
  const search = [...new Set([
    executableDirectory,
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin"
  ])].join(":");
  return {
    HOME: path.join(sandbox, "home"),
    TMPDIR: path.join(sandbox, "tmp"),
    PATH: search,
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    TERM: "dumb",
    NO_COLOR: "1"
  };
}

function executionEnvironment(paths, runId, executablePath) {
  const sandbox = path.join(paths.executionSandboxes, runId);
  const environment = minimalExecutionEnvironment(paths, runId, executablePath);
  securePrivateDirectory(sandbox, { label: `execution sandbox ${runId}` });
  securePrivateDirectory(environment.HOME, { label: `execution home ${runId}` });
  securePrivateDirectory(environment.TMPDIR, { label: `execution temporary directory ${runId}` });
  return { sandbox, environment };
}

function evidenceRefs(runId) {
  const base = `execution-${runId}`;
  return {
    stdoutRef: `private://evidence/${base}-stdout.bin`,
    stderrRef: `private://evidence/${base}-stderr.bin`,
    resultRef: `private://evidence/${base}-result.json`
  };
}

function evidencePath(paths, reference) {
  const prefix = "private://evidence/";
  if (!reference.startsWith(prefix)) throw new Error("execution evidence reference is invalid");
  const filename = reference.slice(prefix.length);
  if (path.basename(filename) !== filename) throw new Error("execution evidence reference escapes the evidence directory");
  return path.join(paths.evidence, filename);
}

export function createExecutionManifest(engagementId, input, options = {}) {
  const paths = executionPaths(options.paths || runtimePaths(options));
  ensureRuntime(paths);
  return createPreparedExecutionManifest(
    engagementId,
    normalizeManifestInput(input),
    { ...options, paths },
    null
  );
}

export function createManagedExecutionManifest(engagementId, input, options = {}) {
  const paths = executionPaths(options.paths || runtimePaths(options));
  ensureRuntime(paths);
  const prepared = prepareManagedAdapterInvocation(input, { ...options, paths });
  return createPreparedExecutionManifest(engagementId, prepared.normalized, { ...options, paths }, prepared);
}

function createPreparedExecutionManifest(engagementId, normalized, options, managedContext) {
  const paths = options.paths;
  const capability = requireCapability();
  const managed = Boolean(managedContext);
  const check = checkEngagement(engagementId, {
    target: normalized.target,
    action: normalized.action,
    ...normalized.declaredBounds
  }, { paths });
  const binding = requireExecutionBinding(check, null, normalized.toolId);
  if (normalized.target !== binding.target.value) {
    throw new Error(`execution target must use its canonical approved form exactly: ${binding.target.value}`);
  }
  if (managed && binding.target.type !== managedContext.adapter.selectorType) {
    throw new Error(`managed adapter requires an exact ${managedContext.adapter.selectorType} engagement selector`);
  }
  const plannedTool = managed
    ? {
        id: managedContext.adapter.tool.id,
        installed: true,
        compatible: true,
        executionAvailable: true,
        executable: managedContext.verifiedRuntime.verified.executable,
        host: managedContext.verifiedRuntime.platform.host,
        riskClass: managedContext.adapter.tool.riskClass
      }
    : (options.resolveTool || ((id) => toolPlan(id, { paths })))(normalized.toolId);
  const eligible = plannedTool && plannedTool.id === normalized.toolId && plannedTool.installed === true &&
    plannedTool.compatible === true && plannedTool.executionAvailable === true &&
    typeof plannedTool.executable === "string" &&
    new Set(["P0", "P1", "A1", "A2", "A3"]).has(plannedTool.riskClass) &&
    (managed || plannedTool.genericLaneEligible === true);
  if (!eligible) {
    throw new Error(`tool is not eligible for ${managed ? "managed-adapter" : "supervised"} execution on this host: ${normalized.toolId}`);
  }
  const opened = openExecutable(plannedTool.executable);
  const executable = opened.value;
  closeDescriptor(opened.descriptor);
  if (managed && executable.sha256 !== managedContext.binding.runtime.executableSha256) {
    throw new Error("managed adapter executable bytes differ from the reviewed runtime lock");
  }
  if (!managed && normalized.targetArgIndex !== 0) {
    const firstArgument = normalized.argv[0];
    const executableTokens = new Set([
      plannedTool.executable,
      path.basename(plannedTool.executable),
      executable.resolvedPath,
      path.basename(executable.resolvedPath)
    ]);
    if (executableTokens.has(firstArgument)) {
      throw new Error("argv contains the selected executable as its first argument; pass tool arguments only after --");
    }
  }

  // Hashing a large executable can take time. Re-check authority after that
  // work and bind only the second, current preflight result.
  const currentCheck = checkEngagement(engagementId, {
    target: normalized.target,
    action: normalized.action,
    ...normalized.declaredBounds
  }, { paths });
  const currentBinding = requireExecutionBinding(currentCheck, null, normalized.toolId);
  if (canonicalDigest(binding) !== canonicalDigest(currentBinding)) {
    throw new Error("engagement execution binding changed while the executable was hashed");
  }

  const now = options.now ? new Date(options.now()) : new Date();
  const authorizationEnd = Date.parse(currentBinding.authorizationValidUntil);
  const expiresAt = new Date(Math.min(now.getTime() + (options.manifestTtlMs || DEFAULT_MANIFEST_TTL_MS), authorizationEnd));
  if (!Number.isFinite(authorizationEnd) || expiresAt <= now) throw new Error("authorization expires before the manifest can be used");
  const manifestId = randomId("xmf");
  const runId = randomId("xrun");
  const workflow = reserveWorkflowExecution(normalized.workflowId, {
    phaseAttemptId: normalized.phaseAttemptId,
    engagementId: currentBinding.engagementId,
    target: normalized.target,
    action: normalized.action,
    toolId: normalized.toolId,
    envelope: workflowReservationEnvelope(normalized.declaredBounds),
    manifestId,
    runId
  }, { paths });
  let manifestPersisted = false;
  try {
    const workflowCheck = checkWorkflowExecution(workflow.instanceId, {
      reservationId: workflow.reservationId,
      phaseAttemptId: workflow.phaseAttemptId,
      executionEpochSha256: workflow.executionEpochSha256,
      manifestId,
      target: normalized.target,
      action: normalized.action,
      toolId: normalized.toolId
    }, { paths });
    if (workflowCheck?.effectClass === "A3") {
      throw new Error(`the ${managed ? "managed adapter" : "supervised generic"} execution lane does not admit A3 workflow phases`);
    }
    if (managed && !managedContext.adapter.allowedPhases.includes(workflowCheck.phaseId)) {
      throw new Error(`managed adapter does not admit workflow phase ${workflowCheck.phaseId}`);
    }
    const { uid, gid } = currentIds();
    const { environment } = executionEnvironment(paths, runId, executable.resolvedPath);
    const evidence = evidenceRefs(runId);
    const maxEvidenceBytesPerStream = Math.floor(normalized.declaredBounds.maxEvidenceBytes / 2);
    const argv0 = path.basename(plannedTool.executable);
    const manifest = {
      $schema: "../../schemas/execution-manifest.schema.json",
      apiVersion: "gate.execution/v2",
      kind: "ExecutionManifest",
      metadata: { id: manifestId, runId, createdAt: now.toISOString(), expiresAt: expiresAt.toISOString() },
      engagement: {
        id: currentBinding.engagementId,
        planSha256: currentBinding.planSha256,
        envelopeSha256: currentBinding.envelopeSha256,
        receiptSha256: currentBinding.receiptSha256,
        authorizationValidUntil: currentBinding.authorizationValidUntil,
        environment: currentBinding.environment,
        allowedDestinations: [...currentBinding.allowedDestinations]
      },
      workflow: {
        instanceId: workflow.instanceId,
        phaseId: workflow.phaseId,
        phaseAttemptId: workflow.phaseAttemptId,
        reservationId: workflow.reservationId,
        executionEpochSha256: workflow.executionEpochSha256,
        journalHeadSha256: workflowCheck.journalHeadSha256,
        definitionSha256: workflowCheck.definitionSha256,
        admissionSha256: workflowCheck.admissionSha256,
        toolMappingSha256: workflowCheck.toolMappingSha256,
        authorityReceiptSha256: workflowCheck.authorityReceiptSha256,
        effectiveStops: [...workflowCheck.effectiveStops],
        effectiveStopsSha256: workflowCheck.effectiveStopsSha256
      },
      operation: {
        targetArgument: normalized.target,
        targetSelector: currentBinding.target,
        targetArgIndex: normalized.targetArgIndex,
        action: normalized.action,
        tool: {
          id: normalized.toolId,
          catalogCommand: argv0,
          host: plannedTool.host,
          riskClass: plannedTool.riskClass,
          readiness: managed ? "verified-managed" : "discovered",
          knownGoodProvenance: managed
        },
        executable,
        argv0,
        argv: normalized.argv,
        adapter: managed ? structuredClone(managedContext.binding) : null
      },
      declaredBounds: normalized.declaredBounds,
      runtime: {
        mode: managed ? "reviewed-managed-adapter" : "supervised-generic",
        platform: "linux",
        uid,
        gid,
        environment,
        sandboxRef: `private://executions/sandboxes/${runId}`,
        evidence,
        maxEvidenceBytesPerStream
      },
      enforcement: {
        enforced: [...(managed ? MANAGED_EXECUTION_ENFORCED : capability.enforced)],
        bestEffort: [...(managed ? MANAGED_EXECUTION_BEST_EFFORT : capability.bestEffort)],
        unavailable: [...(managed ? MANAGED_EXECUTION_UNAVAILABLE : EXECUTION_UNAVAILABLE)]
      },
      manifestSha256: "0".repeat(64)
    };
    manifest.manifestSha256 = manifestDigest(manifest);
    checkWorkflowExecution(workflow.instanceId, {
      reservationId: workflow.reservationId,
      phaseAttemptId: workflow.phaseAttemptId,
      executionEpochSha256: workflow.executionEpochSha256,
      manifestId,
      expectedJournalHeadSha256: manifest.workflow.journalHeadSha256,
      target: normalized.target,
      action: normalized.action,
      toolId: normalized.toolId
    }, { paths });
    assertValidDocument(manifest, "execution-manifest.schema.json", { paths });
    assertManifestInvariants(manifest, paths);
    writePrivateFileExclusive(manifestFile(paths, manifestId), `${JSON.stringify(manifest, null, 2)}\n`, {
      encoding: "utf8",
      label: `private execution manifest ${manifestId}`
    });
    manifestPersisted = true;
    return {
      ok: true,
      manifestId,
      runId,
      manifestSha256: manifest.manifestSha256,
      expiresAt: manifest.metadata.expiresAt,
      workflow: { ...manifest.workflow },
      operation: manifest.operation,
      declaredBounds: manifest.declaredBounds,
      enforcement: manifest.enforcement,
      confirmationRequired: `EXECUTE ${manifestId} ${manifest.manifestSha256} UNMETERED`,
      manifestRef: `private://executions/manifests/${manifestId}.json`
    };
  } catch (error) {
    if (!manifestPersisted) {
      try {
        cancelWorkflowExecution(workflow.instanceId, {
          reservationId: workflow.reservationId,
          reason: "Execution manifest persistence did not complete."
        }, { paths });
      } catch {
        // The original failure remains authoritative; the reservation stays
        // visible for explicit operator recovery if compensation also fails.
      }
    }
    throw error;
  }
}

function effectClass(manifest) {
  const classes = ["local-read", "network-observe", "network-probe", "target-mutate", "high-impact"];
  const action = manifest.operation.action;
  const declared = action === "observe"
    ? "network-observe"
    : new Set(["scan", "fuzz"]).has(action)
      ? "network-probe"
      : new Set(["intercept", "authenticate", "exploit-safe", "data-access"]).has(action)
        ? "target-mutate"
        : "high-impact";
  const networkTarget = new Set(["domain", "ip", "cidr", "url"]).has(manifest.operation.targetSelector.type);
  const riskFloor = {
    P0: networkTarget ? "network-observe" : "local-read",
    P1: "network-observe",
    A1: "network-probe",
    A2: "target-mutate",
    A3: "high-impact"
  }[manifest.operation.tool.riskClass];
  return classes[Math.max(classes.indexOf(declared), classes.indexOf(riskFloor))];
}

function executionEvent(manifest, kind, status, summary, options = {}) {
  return recordEvent({
    kind,
    status,
    runId: manifest.metadata.runId,
    taskId: manifest.metadata.id,
    component: "gate-execution",
    agent: "gate-execution",
    summary,
    effect: {
      class: effectClass(manifest),
      targetRef: `private://executions/manifests/${manifest.metadata.id}.json#target`,
      engagementId: manifest.engagement.id,
      planDigest: manifest.engagement.planSha256
    },
    evidenceRefs: options.evidenceRefs || []
  }, { paths: options.paths });
}

function emptyStream(ref) {
  return { ref, available: false, sha256: null, bytes: 0 };
}

function newRun(manifest) {
  return {
    $schema: "../../schemas/execution-run.schema.json",
    apiVersion: "gate.execution-run/v1",
    kind: "ExecutionRun",
    runId: manifest.metadata.runId,
    manifestId: manifest.metadata.id,
    manifestSha256: manifest.manifestSha256,
    engagementId: manifest.engagement.id,
    workflow: executionRunWorkflowBinding(manifest),
    status: "queued",
    createdAt: new Date().toISOString(),
    startedAt: null,
    finishedAt: null,
    supervisor: processIdentity(process.pid),
    process: null,
    terminationReason: null,
    result: { exitCode: null, signal: null, durationMs: null },
    evidence: {
      stdout: emptyStream(manifest.runtime.evidence.stdoutRef),
      stderr: emptyStream(manifest.runtime.evidence.stderrRef),
      resultRef: manifest.runtime.evidence.resultRef,
      resultAvailable: false,
      sandboxRef: manifest.runtime.sandboxRef
    }
  };
}

function executionRunWorkflowBinding(manifest) {
  return {
    instanceId: manifest.workflow.instanceId,
    phaseId: manifest.workflow.phaseId,
    phaseAttemptId: manifest.workflow.phaseAttemptId,
    reservationId: manifest.workflow.reservationId,
    executionEpochSha256: manifest.workflow.executionEpochSha256
  };
}

function exactConfirmation(manifest) {
  return `EXECUTE ${manifest.metadata.id} ${manifest.manifestSha256} UNMETERED`;
}

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(String(left));
  const rightBuffer = Buffer.from(String(right));
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function durableClaim(paths, manifest, run) {
  const claim = {
    apiVersion: "gate.execution-claim/v1",
    manifestId: manifest.metadata.id,
    runId: manifest.metadata.runId,
    manifestSha256: manifest.manifestSha256,
    engagementId: manifest.engagement.id,
    workflow: { ...manifest.workflow },
    claimedAt: new Date().toISOString(),
    createdAt: run.createdAt,
    supervisor: run.supervisor
  };
  try {
    writePrivateFileExclusive(claimFile(paths, manifest.metadata.id), `${JSON.stringify(claim)}\n`, {
      encoding: "utf8",
      label: `one-shot execution claim ${manifest.metadata.id}`
    });
  } catch (error) {
    if (error.code === "EEXIST") throw new Error(`execution manifest was already consumed: ${manifest.metadata.id}`);
    throw error;
  }
}

function completeWorkflowRun(manifest, run, resultSha256, paths) {
  return completeWorkflowExecution(manifest.workflow.instanceId, {
    reservationId: manifest.workflow.reservationId,
    manifestId: manifest.metadata.id,
    manifestSha256: manifest.manifestSha256,
    runId: run.runId,
    status: run.status,
    terminationReason: run.terminationReason,
    runSha256: canonicalDigest(run),
    resultSha256: run.evidence.resultAvailable ? resultSha256 : null
  }, { paths });
}

function workflowClaimInput(manifest, expectedJournalHeadSha256 = undefined) {
  return {
    reservationId: manifest.workflow.reservationId,
    phaseAttemptId: manifest.workflow.phaseAttemptId,
    executionEpochSha256: manifest.workflow.executionEpochSha256,
    manifestId: manifest.metadata.id,
    manifestSha256: manifest.manifestSha256,
    runId: manifest.metadata.runId,
    ...(expectedJournalHeadSha256 ? { expectedJournalHeadSha256 } : {})
  };
}

function claimWorkflowRun(manifest, paths, expectedJournalHeadSha256 = undefined) {
  return claimWorkflowExecution(
    manifest.workflow.instanceId,
    workflowClaimInput(manifest, expectedJournalHeadSha256),
    { paths }
  );
}

function workflowReservationStatus(manifest, paths) {
  const status = workflowStatus(manifest.workflow.instanceId, { paths });
  if (!status.ok) throw new Error(`workflow status is blocked: ${status.blocker || status.status}`);
  return status.executionReservations.find(({ id }) => id === manifest.workflow.reservationId)?.status || null;
}

function ensureWorkflowRunClaimed(manifest, paths) {
  const confirmClaim = () => checkWorkflowExecution(manifest.workflow.instanceId, {
    ...workflowClaimInput(manifest),
    target: manifest.operation.targetArgument,
    action: manifest.operation.action,
    toolId: manifest.operation.tool.id
  }, { paths });

  const before = workflowReservationStatus(manifest, paths);
  if (before === "claimed") return confirmClaim();
  if (before !== "reserved") throw new Error("workflow execution reservation is not available for reconciliation");
  try {
    return claimWorkflowRun(manifest, paths);
  } catch (error) {
    // A concurrent recovery may have claimed the reservation after the status
    // read. Accept only the exact durable binding in that case.
    if (workflowReservationStatus(manifest, paths) === "claimed") return confirmClaim();
    throw error;
  }
}

function bindingStillMatches(manifest, paths, options = {}) {
  const input = options.includeBounds === false
    ? { target: manifest.operation.targetArgument, action: manifest.operation.action }
    : checkInput(manifest.operation, manifest.declaredBounds);
  const check = checkEngagement(manifest.engagement.id, input, { paths });
  requireExecutionBinding(check, manifest, manifest.operation.tool.id);
  const workflowInput = {
    reservationId: manifest.workflow.reservationId,
    phaseAttemptId: manifest.workflow.phaseAttemptId,
    executionEpochSha256: manifest.workflow.executionEpochSha256,
    manifestId: manifest.metadata.id,
    definitionSha256: manifest.workflow.definitionSha256,
    admissionSha256: manifest.workflow.admissionSha256,
    toolMappingSha256: manifest.workflow.toolMappingSha256,
    authorityReceiptSha256: manifest.workflow.authorityReceiptSha256,
    effectiveStopsSha256: manifest.workflow.effectiveStopsSha256,
    target: manifest.operation.targetArgument,
    action: manifest.operation.action,
    toolId: manifest.operation.tool.id
  };
  if (options.expectedWorkflowJournalHeadSha256) {
    workflowInput.expectedJournalHeadSha256 = options.expectedWorkflowJournalHeadSha256;
  }
  if (options.includeManifestDigest !== false) workflowInput.manifestSha256 = manifest.manifestSha256;
  const workflow = checkWorkflowExecution(manifest.workflow.instanceId, workflowInput, { paths });
  if (workflow?.effectClass === "A3") {
    throw new Error("the supervised generic execution lane does not admit A3 workflow phases");
  }
  if (manifest.operation.adapter) assertManagedAdapterManifest(manifest, { paths });
  return workflow;
}

function launchAuthorityError(message, terminationReason) {
  return Object.assign(new Error(message), { terminationReason });
}

function assertLaunchAuthority(manifest, paths, deadline = null, expectedWorkflowJournalHeadSha256 = undefined) {
  if (deadline !== null && Date.now() >= deadline) {
    throw launchAuthorityError("execution duration limit elapsed before launch", "duration-limit");
  }
  if (Date.now() >= Date.parse(manifest.metadata.expiresAt)) {
    throw launchAuthorityError("execution manifest expired before launch", "authorization-expired");
  }
  if (Date.now() >= Date.parse(manifest.engagement.authorizationValidUntil)) {
    throw launchAuthorityError("engagement authorization expired before launch", "authorization-expired");
  }
  if (fs.existsSync(stopFile(paths, manifest.metadata.runId))) {
    throw launchAuthorityError("execution was stopped before launch", "operator-stop");
  }
  try {
    bindingStillMatches(manifest, paths, { expectedWorkflowJournalHeadSha256 });
  } catch (error) {
    throw launchAuthorityError(error.message, "engagement-invalidated");
  }
}

function authenticatedGroupMembers(identity) {
  if (!identity) return { trusted: false, members: [] };
  let bootId;
  try {
    bootId = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim().toLowerCase();
  } catch {
    return { trusted: false, members: [] };
  }
  if (bootId !== identity.bootId) return { trusted: false, members: [] };
  const members = [];
  for (const entry of fs.readdirSync("/proc")) {
    if (!/^\d+$/u.test(entry)) continue;
    try {
      const snapshot = processSnapshot(Number(entry), bootId);
      if (
        snapshot.identity.pgid === identity.pgid &&
        snapshot.identity.sessionId === identity.sessionId
      ) {
        members.push({ ...snapshot.identity, state: snapshot.state });
      }
    } catch {
      // Processes can exit while /proc is scanned.
    }
  }
  const leader = members.find((member) => member.pid === identity.pid);
  if (leader && !sameProcessIdentity(leader, identity)) return { trusted: false, members: [] };
  if (!leader) {
    try {
      if (!sameProcessIdentity(processIdentity(identity.pid), identity)) return { trusted: false, members: [] };
    } catch {
      // A departed session leader is expected while descendants remain. Linux
      // retains its session/process-group identifiers until the final member.
    }
  }
  return { trusted: true, members };
}

function signalProcessGroup(identity, signal) {
  if (!identity) return false;
  const observed = authenticatedGroupMembers(identity);
  if (!observed.trusted || !observed.members.some((member) => member.state !== "Z")) return false;
  try {
    process.kill(-identity.pgid, signal);
    return true;
  } catch (error) {
    if (error.code === "ESRCH") return false;
    throw error;
  }
}

async function waitForTerminatedGroup(identity, forceKillAt, pollIntervalMs) {
  if (!identity) return false;
  while (true) {
    let observed;
    try {
      observed = authenticatedGroupMembers(identity);
    } catch {
      return false;
    }
    if (!observed.trusted) return false;
    if (!observed.members.some((member) => member.state !== "Z")) return true;
    if (Date.now() >= forceKillAt) {
      try {
        signalProcessGroup(identity, "SIGKILL");
      } catch {
        return false;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, Math.min(250, Math.max(10, pollIntervalMs))));
  }
}

function terminalStatus(reason, exitCode, signal) {
  if (new Set([
    "evidence-limit", "evidence-write-failure", "spawn-failure", "managed-runtime-invalidated",
    "indeterminate-output", "output-validation-failed"
  ]).has(reason)) return "failed";
  if (reason && reason !== "completed") return "cancelled";
  return exitCode === 0 && signal === null ? "succeeded" : "failed";
}

function streamCapture(stream, descriptor, maximumBytes, onFailure) {
  const hash = crypto.createHash("sha256");
  let bytes = 0;
  let failed = false;
  stream.on("data", (chunk) => {
    if (failed) return;
    try {
      if (bytes + chunk.length > maximumBytes) {
        failed = true;
        onFailure("evidence-limit");
        return;
      }
      let offset = 0;
      while (offset < chunk.length) {
        const written = fs.writeSync(descriptor, chunk, offset, chunk.length - offset);
        if (!Number.isInteger(written) || written < 1) throw new Error("evidence write made no progress");
        hash.update(chunk.subarray(offset, offset + written));
        bytes += written;
        offset += written;
      }
    } catch {
      failed = true;
      onFailure("evidence-write-failure");
    }
  });
  stream.on("error", () => {
    if (!failed) {
      failed = true;
      onFailure("evidence-write-failure");
    }
  });
  return {
    finish() {
      // A limit or stream-write failure can still leave a valid captured
      // prefix. Flush that prefix before advertising its digest. If fsync
      // itself fails, propagate the failure so the caller leaves this stream
      // unavailable in durable metadata.
      try {
        fs.fsyncSync(descriptor);
      } catch (error) {
        onFailure("evidence-write-failure");
        throw error;
      }
      return { available: true, bytes, sha256: hash.digest("hex") };
    }
  };
}

function childLifecycle(child) {
  let spawnError = null;
  const closed = new Promise((resolve) => {
    child.once("error", (error) => { spawnError = error; });
    child.once("close", (code, signal) => resolve({ code, signal, spawnError }));
  });
  const spawned = new Promise((resolve) => {
    child.once("spawn", () => {
      try {
        // Capture PID identity inside the spawn event callback. A very short
        // lived executable may be reaped before an awaiting continuation runs.
        resolve({ ok: true, process: processIdentity(child.pid), error: null });
      } catch (error) {
        resolve({ ok: true, process: null, error });
      }
    });
    child.once("error", (error) => resolve({ ok: false, process: null, error }));
  });
  return { spawned, closed };
}

export async function executeExecutionManifest(engagementId, input, options = {}) {
  const paths = executionPaths(options.paths || runtimePaths(options));
  ensureRuntime(paths);
  requireCapability();
  const manifest = readManifest(paths, String(input.manifestId || ""));
  if (manifest.engagement.id !== engagementId) throw new Error("execution manifest belongs to a different engagement");
  if (Date.now() >= Date.parse(manifest.metadata.expiresAt)) throw new Error("execution manifest expired");
  if (!safeEqual(input.confirm, exactConfirmation(manifest))) {
    throw new Error(`execution confirmation must be exactly: ${exactConfirmation(manifest)}`);
  }
  const { uid, gid } = currentIds();
  if (uid !== manifest.runtime.uid || gid !== manifest.runtime.gid) throw new Error("execution user changed after manifest creation");
  if (fs.existsSync(claimFile(paths, manifest.metadata.id))) {
    readClaim(paths, manifest.metadata.id);
    throw new Error(`execution manifest was already consumed: ${manifest.metadata.id}`);
  }
  bindingStillMatches(manifest, paths, {
    includeManifestDigest: false,
    expectedWorkflowJournalHeadSha256: manifest.workflow.journalHeadSha256
  });
  let run = newRun(manifest);
  durableClaim(paths, manifest, run);
  let claimedWorkflowJournalHeadSha256;
  try {
    const claimed = claimWorkflowRun(manifest, paths, manifest.workflow.journalHeadSha256);
    claimedWorkflowJournalHeadSha256 = claimed.projection.journalHeadSha256;
  } catch (error) {
    // The generic one-shot claim is already durable. Persist a terminal local
    // record before releasing or completing its workflow reservation so this
    // failure cannot become an invisible, permanently blocking allocation.
    run.status = "blocked";
    run.finishedAt = new Date().toISOString();
    run.terminationReason = "workflow-claim-failed";
    run.result.durationMs = 0;
    let persisted = false;
    try {
      writeRun(paths, run);
      persisted = true;
    } catch {
      // Preserve the workflow-claim failure. Reconciliation can reconstruct
      // the missing run from the durable generic claim after this process dies.
    }
    if (persisted) {
      try {
        cancelWorkflowExecution(manifest.workflow.instanceId, {
          reservationId: manifest.workflow.reservationId,
          reason: "The durable generic claim could not be bound to the workflow reservation."
        }, { paths });
      } catch {
        // If the workflow claim committed before surfacing an error, complete
        // the exact blocked run instead of leaving the reservation pending.
        try {
          ensureWorkflowRunClaimed(manifest, paths);
          completeWorkflowRun(manifest, run, null, paths);
        } catch {
          // The durable run and generic claim remain available to reconcile.
        }
      }
      try {
        executionEvent(
          manifest,
          "execution.completed",
          run.status,
          "A supervised execution was blocked while binding its workflow reservation.",
          { paths }
        );
      } catch {
        // Preserve the workflow-claim failure.
      }
    }
    throw error;
  }

  let executableDescriptor = null;
  let stdoutDescriptor = null;
  let stderrDescriptor = null;
  let child = null;
  let launchAttempted = false;
  let childSpawned = false;
  let childClosed = null;
  let childResult = null;
  let processRecord = null;
  let groupSignalAllowed = true;
  let terminationReason = null;
  let terminationSignalled = false;
  let killTimer = null;
  let forceKillAt = null;
  let pollTimer = null;
  let finalStatePersisted = false;
  let supervisionLost = false;
  const startedClock = Date.now();
  const deadline = startedClock + manifest.declaredBounds.maxMinutes * 60_000;
  const stdoutPath = evidencePath(paths, manifest.runtime.evidence.stdoutRef);
  const stderrPath = evidencePath(paths, manifest.runtime.evidence.stderrRef);
  const resultPath = evidencePath(paths, manifest.runtime.evidence.resultRef);
  const pollIntervalMs = options.pollIntervalMs || DEFAULT_POLL_INTERVAL_MS;
  const terminationGraceMs = options.terminationGraceMs || DEFAULT_TERMINATION_GRACE_MS;

  const startStopping = (reason) => {
    terminationReason ||= reason;
    if (terminationSignalled || !childSpawned) return;
    terminationSignalled = true;
    if (run.status === "running") {
      run.status = "stopping";
      run.terminationReason = terminationReason;
      try { writeRun(paths, run); } catch { /* The final record retries. */ }
    }
    if (processRecord) {
      try { signalProcessGroup(processRecord, "SIGTERM"); } catch { /* Retry with SIGKILL below. */ }
      forceKillAt = Date.now() + terminationGraceMs;
      killTimer ||= setTimeout(() => {
        try {
          if (!signalProcessGroup(processRecord, "SIGKILL")) child?.kill("SIGKILL");
        } catch {
          try { child?.kill("SIGKILL"); } catch { /* Await close; do not abandon a possibly-live child. */ }
        }
      }, terminationGraceMs);
      killTimer.unref?.();
    } else if (childSpawned && child?.pid) {
      // A successful detached spawn establishes PGID == PID. If /proc identity
      // capture itself failed, terminate immediately because the supervisor can
      // no longer safely authenticate this process on a later retry.
      try {
        if (groupSignalAllowed) process.kill(-child.pid, "SIGKILL");
        else child.kill("SIGKILL");
      } catch {
        try { child.kill("SIGKILL"); } catch { /* Await close below. */ }
      }
    }
  };

  const signalHandler = () => startStopping("supervisor-signal");
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(signal, signalHandler);

  let stdoutCapture;
  let stderrCapture;
  let stdoutEvidence = null;
  let stderrEvidence = null;
  let resultSha256 = null;
  const finishCaptures = () => {
    if (stdoutCapture && !stdoutEvidence) stdoutEvidence = stdoutCapture.finish();
    if (stderrCapture && !stderrEvidence) stderrEvidence = stderrCapture.finish();
    return { stdout: stdoutEvidence, stderr: stderrEvidence };
  };
  try {
    // The run record follows the durable one-shot claim before any expensive
    // hashing or launch work. The claim itself carries enough metadata for
    // status reconciliation if the supervisor crashes between these writes.
    writeRun(paths, run);
    executionEvent(manifest, "execution.queued", "queued", "A supervised execution was claimed for bound pre-launch checks.", { paths });
    try { assertLaunchAuthority(manifest, paths, deadline, claimedWorkflowJournalHeadSha256); } catch (error) {
      terminationReason = error.terminationReason || "engagement-invalidated";
      throw error;
    }
    if (manifest.operation.adapter) {
      try {
        reverifyManagedAdapterManifest(manifest, {
          paths,
          verifyManagedTool: options.verifyManagedTool,
          runManagedSmoke: options.runManagedSmoke
        });
      } catch (error) {
        terminationReason = "managed-runtime-invalidated";
        throw launchAuthorityError(error.message, "managed-runtime-invalidated");
      }
    }
    const opened = openExecutable(manifest.operation.executable.resolvedPath, manifest.operation.executable);
    executableDescriptor = opened.descriptor;
    try { assertLaunchAuthority(manifest, paths, deadline, claimedWorkflowJournalHeadSha256); } catch (error) {
      terminationReason = error.terminationReason || "engagement-invalidated";
      throw error;
    }
    stdoutDescriptor = openPrivateFileExclusive(stdoutPath, { label: `execution stdout ${manifest.metadata.runId}` });
    stderrDescriptor = openPrivateFileExclusive(stderrPath, { label: `execution stderr ${manifest.metadata.runId}` });

    try { assertLaunchAuthority(manifest, paths, deadline, claimedWorkflowJournalHeadSha256); } catch (error) {
      terminationReason = error.terminationReason || "engagement-invalidated";
      throw error;
    }
    if (terminationReason) throw launchAuthorityError("execution was cancelled before launch", terminationReason);
    assertExecutableDescriptorStable(executableDescriptor, manifest.operation.executable);

    const previousUmask = process.umask(0o077);
    try {
      launchAttempted = true;
      child = spawn("/proc/self/fd/3", manifest.operation.argv, {
        argv0: manifest.operation.argv0,
        cwd: path.join(paths.executionSandboxes, manifest.metadata.runId),
        env: { ...manifest.runtime.environment },
        detached: true,
        shell: false,
        stdio: ["ignore", "pipe", "pipe", executableDescriptor]
      });
    } finally {
      process.umask(previousUmask);
    }
    // Register both terminal listeners before awaiting anything. A trivial tool
    // can exit between the spawn event and the first metadata write.
    const lifecycle = childLifecycle(child);
    childClosed = lifecycle.closed;
    stdoutCapture = streamCapture(child.stdout, stdoutDescriptor, manifest.runtime.maxEvidenceBytesPerStream, startStopping);
    stderrCapture = streamCapture(child.stderr, stderrDescriptor, manifest.runtime.maxEvidenceBytesPerStream, startStopping);
    const spawnResult = await lifecycle.spawned;
    childSpawned = spawnResult.ok;
    closeDescriptor(executableDescriptor);
    executableDescriptor = null;
    if (!childSpawned) {
      terminationReason = "spawn-failure";
      throw new Error("verified executable could not be spawned");
    }
    if (spawnResult.error) {
      supervisionLost = true;
      terminationReason = "supervision-lost";
      throw spawnResult.error;
    }
    processRecord = spawnResult.process;
    if (processRecord.pgid !== child.pid || processRecord.sessionId !== child.pid) {
      groupSignalAllowed = false;
      processRecord = null;
      supervisionLost = true;
      terminationReason = "supervision-lost";
      try { child.kill("SIGKILL"); } catch { /* The lifecycle wait below remains authoritative. */ }
      throw new Error("supervised child did not start in its own process group");
    }
    if (terminationReason) {
      startStopping(terminationReason);
      throw new Error("execution was cancelled while the child process started");
    }
    run.status = "running";
    run.startedAt = new Date().toISOString();
    run.process = processRecord;
    writeRun(paths, run);
    if (options.afterSpawn) await options.afterSpawn({ runId: run.runId, pid: child.pid, process: { ...processRecord } });
    if (terminationReason) {
      startStopping(terminationReason);
      throw new Error("execution was cancelled during post-launch supervision setup");
    }
    executionEvent(manifest, "execution.started", "running", "A supervised execution started with private evidence capture.", { paths });

    pollTimer = setInterval(() => {
      try {
        if (fs.existsSync(stopFile(paths, manifest.metadata.runId))) startStopping("operator-stop");
        else if (Date.now() >= Date.parse(manifest.engagement.authorizationValidUntil)) startStopping("authorization-expired");
        else if (Date.now() >= deadline) startStopping("duration-limit");
        else bindingStillMatches(manifest, paths, {
          includeBounds: false,
          expectedWorkflowJournalHeadSha256: claimedWorkflowJournalHeadSha256
        });
      } catch {
        startStopping("engagement-invalidated");
      }
    }, pollIntervalMs);
    pollTimer.unref?.();

    const closed = await childClosed;
    childResult = closed;
    if (closed.spawnError && !terminationReason) terminationReason = "spawn-failure";
    if (!terminationReason) {
      const remaining = authenticatedGroupMembers(processRecord);
      if (!remaining.trusted) terminationReason = "spawn-failure";
      else if (remaining.members.some((member) => member.state !== "Z")) startStopping("process-group-remained");
      else terminationReason = "completed";
    }
    if (pollTimer) clearInterval(pollTimer);
    if (terminationReason !== "completed" && processRecord) {
      const terminated = await waitForTerminatedGroup(processRecord, forceKillAt || Date.now(), pollIntervalMs);
      if (!terminated) {
        supervisionLost = true;
        terminationReason = "supervision-lost";
        throw new Error("the supervised process group could no longer be authenticated during termination");
      }
    }
    if (killTimer) clearTimeout(killTimer);
    const { stdout, stderr } = finishCaptures();
    closeDescriptor(stdoutDescriptor);
    closeDescriptor(stderrDescriptor);
    stdoutDescriptor = null;
    stderrDescriptor = null;
    let adapterOutput = null;
    if (manifest.operation.adapter && terminationReason === "completed" && closed.code === 0 && closed.signal === null) {
      try {
        const stdoutBytes = readPrivateFileBounded(
          stdoutPath,
          manifest.runtime.maxEvidenceBytesPerStream,
          null,
          { label: `managed execution stdout ${manifest.metadata.runId}` }
        );
        adapterOutput = validateManagedAdapterOutput(manifest, stdoutBytes, { paths });
      } catch {
        adapterOutput = { ok: false, status: "invalid", reason: "output-validation-failed", records: 0 };
      }
      if (!adapterOutput.ok) terminationReason = adapterOutput.reason;
    }
    const finishedAt = new Date();
    run.status = terminalStatus(terminationReason, closed.code, closed.signal);
    run.finishedAt = finishedAt.toISOString();
    run.terminationReason = terminationReason;
    run.result = {
      exitCode: Number.isInteger(closed.code) ? closed.code : null,
      signal: closed.signal || null,
      durationMs: Math.max(0, finishedAt.getTime() - startedClock)
    };
    run.evidence.stdout = { ...run.evidence.stdout, ...stdout };
    run.evidence.stderr = { ...run.evidence.stderr, ...stderr };
    const resultEvidence = {
      apiVersion: "gate.execution-result/v1",
      runId: run.runId,
      manifestId: run.manifestId,
      manifestSha256: run.manifestSha256,
      engagementId: run.engagementId,
      workflow: { ...run.workflow },
      status: run.status,
      startedAt: run.startedAt,
      finishedAt: run.finishedAt,
      terminationReason: run.terminationReason,
      result: run.result,
      stdout: run.evidence.stdout,
      stderr: run.evidence.stderr,
      enforcement: manifest.enforcement,
      ...(adapterOutput ? { adapterOutput } : {})
    };
    try {
      const serializedResult = `${JSON.stringify(resultEvidence, null, 2)}\n`;
      writePrivateFileExclusive(resultPath, serializedResult, {
        encoding: "utf8",
        label: `execution result ${manifest.metadata.runId}`
      });
      resultSha256 = sha256(Buffer.from(serializedResult));
    } catch (error) {
      terminationReason = "evidence-write-failure";
      throw error;
    }
    run.evidence.resultAvailable = true;
    writeRun(paths, run);
    finalStatePersisted = true;
    completeWorkflowRun(manifest, run, resultSha256, paths);
    executionEvent(
      manifest,
      "execution.completed",
      run.status,
      `A supervised execution finished with status ${run.status}.`,
      { paths, evidenceRefs: [run.evidence.stdout.ref, run.evidence.stderr.ref, run.evidence.resultRef] }
    );
    return {
      ok: run.status === "succeeded",
      status: run.status,
      runId: run.runId,
      manifestId: run.manifestId,
      workflow: {
        instanceId: run.workflow.instanceId,
        phaseId: run.workflow.phaseId,
        phaseAttemptId: run.workflow.phaseAttemptId,
        reservationId: run.workflow.reservationId
      },
      startedAt: run.startedAt,
      finishedAt: run.finishedAt,
      durationMs: run.result.durationMs,
      exitCode: run.result.exitCode,
      signal: run.result.signal,
      terminationReason: run.terminationReason,
      evidence: run.evidence,
      ...(adapterOutput ? { adapterOutput } : {})
    };
  } catch (error) {
    if (pollTimer) clearInterval(pollTimer);
    if (childSpawned && !childResult) {
      startStopping(terminationReason || "spawn-failure");
      // Never return control while a launched tool may still be contacting its
      // target. The grace timer remains armed until close is observed.
      childResult = await childClosed;
    }
    if (childSpawned && processRecord && terminationReason !== "completed" && !supervisionLost) {
      try {
        const terminated = await waitForTerminatedGroup(processRecord, forceKillAt || Date.now(), pollIntervalMs);
        if (!terminated) {
          supervisionLost = true;
          terminationReason = "supervision-lost";
        }
      } catch {
        supervisionLost = true;
        terminationReason = "supervision-lost";
      }
    }
    if (killTimer) clearTimeout(killTimer);
    try {
      const captured = finishCaptures();
      if (captured.stdout) run.evidence.stdout = { ...run.evidence.stdout, ...captured.stdout };
      if (captured.stderr) run.evidence.stderr = { ...run.evidence.stderr, ...captured.stderr };
    } catch {
      terminationReason = "evidence-write-failure";
    }
    closeDescriptor(stdoutDescriptor);
    closeDescriptor(stderrDescriptor);
    stdoutDescriptor = null;
    stderrDescriptor = null;
    if (!finalStatePersisted) {
      const prelaunchCancellation = !launchAttempted && new Set([
        "operator-stop",
        "engagement-invalidated",
        "authorization-expired",
        "duration-limit",
        "supervisor-signal"
      ]).has(terminationReason);
      const launchWasBlocked = !launchAttempted && !prelaunchCancellation;
      run.status = supervisionLost
        ? "unknown"
        : prelaunchCancellation
          ? "cancelled"
          : launchWasBlocked
            ? "blocked"
            : terminalStatus(
                terminationReason || "spawn-failure",
                Number.isInteger(childResult?.code) ? childResult.code : null,
                childResult?.signal || null
              );
      run.finishedAt = new Date().toISOString();
      run.terminationReason = supervisionLost
        ? "supervision-lost"
        : launchWasBlocked
          ? (terminationReason === "managed-runtime-invalidated" ? terminationReason : null)
          : terminationReason || "spawn-failure";
      if (childResult) {
        run.result.exitCode = Number.isInteger(childResult.code) ? childResult.code : null;
        run.result.signal = childResult.signal || null;
      }
      run.result.durationMs = Math.max(0, Date.now() - startedClock);
      let persisted = false;
      try {
        writeRun(paths, run);
        persisted = true;
        finalStatePersisted = true;
      } catch {
        // Preserve the original launch or supervision error.
      }
      if (persisted) {
        try {
          completeWorkflowRun(manifest, run, resultSha256, paths);
        } catch {
          // The durable run remains the reconciliation source of truth.
        }
        const evidenceRefs = [run.evidence.stdout, run.evidence.stderr]
          .filter((stream) => stream.available)
          .map((stream) => stream.ref);
        try {
          executionEvent(
            manifest,
            "execution.completed",
            run.status,
            `A supervised execution finished with status ${run.status}.`,
            { paths, evidenceRefs }
          );
        } catch {
          // The original execution error remains authoritative.
        }
      }
    }
    throw error;
  } finally {
    for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.off(signal, signalHandler);
    closeDescriptor(executableDescriptor);
    closeDescriptor(stdoutDescriptor);
    closeDescriptor(stderrDescriptor);
  }
}

function reconcileConfirmation(manifest) {
  return `RECONCILE EXECUTION ${manifest.metadata.id} ${manifest.manifestSha256}`;
}

function assertRunManifestBinding(run, manifest) {
  if (
    run.runId !== manifest.metadata.runId || run.manifestId !== manifest.metadata.id ||
    run.manifestSha256 !== manifest.manifestSha256 || run.engagementId !== manifest.engagement.id ||
    canonicalDigest(run.workflow) !== canonicalDigest(executionRunWorkflowBinding(manifest))
  ) {
    throw new Error("execution run does not match its manifest binding");
  }
}

function assertClaimManifestBinding(claim, manifest) {
  if (
    claim.runId !== manifest.metadata.runId || claim.manifestId !== manifest.metadata.id ||
    claim.manifestSha256 !== manifest.manifestSha256 || claim.engagementId !== manifest.engagement.id ||
    canonicalDigest(claim.workflow) !== canonicalDigest(manifest.workflow)
  ) {
    throw new Error("one-shot execution claim does not match its manifest binding");
  }
}

function persistedResultSha256(paths, run) {
  if (!run.evidence.resultAvailable) return null;
  const bytes = readPrivateFileBounded(
    evidencePath(paths, run.evidence.resultRef),
    MAX_RUN_BYTES,
    null,
    { label: `execution result ${run.runId}` }
  );
  return sha256(bytes);
}

export function reconcileExecution(engagementId, input, options = {}) {
  const paths = executionPaths(options.paths || runtimePaths(options));
  ensureRuntime(paths);
  requireCapability();
  const manifest = readManifest(paths, String(input.manifestId || ""));
  if (manifest.engagement.id !== engagementId) throw new Error("execution manifest belongs to a different engagement");
  if (!safeEqual(input.confirm, reconcileConfirmation(manifest))) {
    throw new Error(`execution reconciliation confirmation must be exactly: ${reconcileConfirmation(manifest)}`);
  }
  let run;
  let workflowReservationCancelled = false;
  try {
    run = readRun(paths, manifest.metadata.runId);
    assertRunManifestBinding(run, manifest);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    const claim = readClaim(paths, manifest.metadata.id);
    assertClaimManifestBinding(claim, manifest);
    if (liveProcessIdentity(claim.supervisor)) {
      throw new Error("execution reconciliation refused because its supervisor may still be alive");
    }
    try {
      ensureWorkflowRunClaimed(manifest, paths);
    } catch (error) {
      try {
        cancelWorkflowExecution(manifest.workflow.instanceId, {
          reservationId: manifest.workflow.reservationId,
          reason: "The original supervisor ended before the workflow reservation was claimed."
        }, { paths });
        workflowReservationCancelled = true;
      } catch {
        throw error;
      }
    }
    run = newRun(manifest);
    run.createdAt = claim.createdAt;
    run.supervisor = claim.supervisor;
    run.status = "unknown";
    run.finishedAt = new Date().toISOString();
    run.terminationReason = "supervision-lost";
    run.result.durationMs = Math.max(0, Date.parse(run.finishedAt) - Date.parse(run.createdAt));
    writeRun(paths, run);
  }

  const terminal = new Set(["succeeded", "failed", "cancelled", "blocked", "unknown"]);
  if (!terminal.has(run.status)) {
    if (liveProcessIdentity(run.supervisor)) {
      throw new Error("execution reconciliation refused because its supervisor may still be alive");
    }
    if (run.process) {
      const group = authenticatedGroupMembers(run.process);
      if (!group.trusted) {
        throw new Error("execution reconciliation cannot authenticate the recorded process group");
      }
      if (group.members.some((member) => member.state !== "Z")) {
        throw new Error("execution reconciliation refused because the recorded process group may still be alive");
      }
    }
    run.status = "unknown";
    run.finishedAt = new Date().toISOString();
    run.terminationReason = "supervision-lost";
    run.result.durationMs = Math.max(0, Date.parse(run.finishedAt) - Date.parse(run.startedAt || run.createdAt));
    writeRun(paths, run);
  }

  const resultSha256 = persistedResultSha256(paths, run);
  if (run.terminationReason === "workflow-claim-failed") {
    const reservationStatus = workflowReservationStatus(manifest, paths);
    if (reservationStatus === "claimed") {
      completeWorkflowRun(manifest, run, resultSha256, paths);
    } else if (reservationStatus === "reserved") {
      cancelWorkflowExecution(manifest.workflow.instanceId, {
        reservationId: manifest.workflow.reservationId,
        reason: "The durable generic claim could not be bound to the workflow reservation."
      }, { paths });
    }
  } else if (!workflowReservationCancelled) {
    completeWorkflowRun(manifest, run, resultSha256, paths);
  }
  executionEvent(
    manifest,
    "execution.reconciled",
    run.status,
    `A durable execution run was reconciled with status ${run.status}.`,
    { paths, evidenceRefs: resultSha256 ? [run.evidence.resultRef] : [] }
  );
  return {
    ok: run.status === "succeeded",
    status: run.status,
    runId: run.runId,
    manifestId: run.manifestId,
    workflow: {
      instanceId: run.workflow.instanceId,
      phaseId: run.workflow.phaseId,
      phaseAttemptId: run.workflow.phaseAttemptId,
      reservationId: run.workflow.reservationId
    },
    terminationReason: run.terminationReason,
    confirmationRequired: reconcileConfirmation(manifest)
  };
}

export function requestExecutionStop(engagementId, input, options = {}) {
  const paths = executionPaths(options.paths || runtimePaths(options));
  ensureRuntime(paths);
  const run = readRun(paths, String(input.runId || ""));
  if (run.engagementId !== engagementId) throw new Error("execution run belongs to a different engagement");
  if (new Set(["succeeded", "failed", "cancelled", "blocked"]).has(run.status)) {
    return { ok: true, engagementId, runId: run.runId, status: run.status, requestedAt: null };
  }
  const requestedAt = new Date().toISOString();
  try {
    writePrivateFileExclusive(stopFile(paths, run.runId), `${JSON.stringify({
      apiVersion: "gate.execution-stop/v1",
      engagementId,
      runId: run.runId,
      requestedAt
    })}\n`, { encoding: "utf8", label: `execution stop request ${run.runId}` });
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
  }
  recordEvent({
    kind: "execution.stop-requested",
    status: "waiting",
    runId: run.runId,
    taskId: run.manifestId,
    component: "gate-execution",
    agent: "gate-execution",
    summary: "A stop was requested for a supervised execution.",
    effect: { class: "none", targetRef: null, engagementId: null, planDigest: null },
    evidenceRefs: []
  }, { paths });
  return { ok: true, engagementId, runId: run.runId, status: "stop-requested", requestedAt };
}

export function requestEngagementStops(engagementId, options = {}) {
  const paths = executionPaths(options.paths || runtimePaths(options));
  ensureRuntime(paths);
  const requested = [];
  for (const entry of fs.readdirSync(paths.executionRuns).filter((name) => /^xrun_[a-f0-9]{32}\.json$/u.test(name))) {
    try {
      const run = readRun(paths, entry.slice(0, -5));
      if (run.engagementId === engagementId && new Set(["queued", "running", "stopping"]).has(run.status)) {
        requested.push(requestExecutionStop(engagementId, { runId: run.runId }, { paths }));
      }
    } catch {
      // Invalid private state cannot be safely associated with this engagement.
    }
  }
  return requested;
}

function publicRunMetadata(run) {
  let status = run.status;
  const supervised = liveProcessIdentity(run.supervisor);
  if (status === "queued" && !supervised) status = "unknown";
  if (new Set(["running", "stopping"]).has(status) && (!supervised || !liveProcessIdentity(run.process))) {
    status = "unknown";
  }
  return {
    runId: run.runId,
    manifestId: run.manifestId,
    engagementId: run.engagementId,
    workflow: {
      instanceId: run.workflow.instanceId,
      phaseId: run.workflow.phaseId,
      phaseAttemptId: run.workflow.phaseAttemptId,
      reservationId: run.workflow.reservationId
    },
    status,
    createdAt: run.createdAt,
    startedAt: run.startedAt,
    finishedAt: run.finishedAt,
    terminationReason: run.terminationReason,
    exitCode: run.result.exitCode,
    signal: run.result.signal
  };
}

export function executionStatus(options = {}) {
  const paths = executionPaths(options.paths || runtimePaths(options));
  ensureRuntime(paths);
  const recent = [];
  const seenRuns = new Set();
  let invalid = 0;
  for (const entry of fs.readdirSync(paths.executionRuns).filter((name) => name.endsWith(".json"))) {
    const id = entry.slice(0, -5);
    if (/^xrun_[a-f0-9]{32}$/u.test(id)) seenRuns.add(id);
    try {
      const metadata = publicRunMetadata(readRun(paths, id));
      recent.push(metadata);
    } catch {
      invalid += 1;
    }
  }
  for (const entry of fs.readdirSync(paths.executionClaims).filter((name) => /^xmf_[a-f0-9]{32}\.json$/u.test(name))) {
    try {
      const metadata = readClaimMetadata(paths, entry.slice(0, -5));
      if (!seenRuns.has(metadata.runId)) recent.push(metadata);
    } catch {
      invalid += 1;
    }
  }
  recent.sort((left, right) => Date.parse(right.createdAt) - Date.parse(left.createdAt));
  const count = (status) => recent.filter((run) => run.status === status).length;
  return {
    capability: executionCapability(),
    counts: {
      queued: count("queued"),
      running: count("running"),
      stopping: count("stopping"),
      succeeded: count("succeeded"),
      failed: count("failed"),
      cancelled: count("cancelled"),
      blocked: count("blocked"),
      unknown: count("unknown") + invalid
    },
    recent: recent.slice(0, 100)
  };
}

export const executionInternals = Object.freeze({
  manifestDigest,
  processIdentity,
  sameProcessIdentity,
  TARGET_PLACEHOLDER
});
