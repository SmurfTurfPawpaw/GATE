import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";

import { checkEngagement, targetMatches } from "./engagements.mjs";
import { appendJsonLine } from "./jsonl.mjs";
import { prepareManagedAdapterInvocation } from "./managed-adapters.mjs";
import { ensureRuntime, runtimePaths } from "./paths.mjs";
import {
  readPrivateFileBounded,
  securePrivateDirectory,
  syncPrivateDirectory,
  writePrivateFileAtomic,
  writePrivateFileExclusive
} from "./private-fs.mjs";
import { assertValidDocument } from "./schema.mjs";
import { cancelWorkflowExecution, workflowStatus } from "./workflow-runtime.mjs";

const AUTHORITY_SCHEMA = "https://gate.local/schemas/lab-campaign-authority.schema.json";
const RECEIPT_SCHEMA = "https://gate.local/schemas/lab-campaign-authorization-receipt.schema.json";
const CAPABILITY_SCHEMA = "https://gate.local/schemas/lab-campaign-job-capability.schema.json";
const ID = /^[a-z][a-z0-9-]{1,62}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const MAX_DOCUMENT_BYTES = 2 * 1024 * 1024;
const MAX_JOURNAL_BYTES = 64 * 1024 * 1024;
const MAX_JOURNAL_ENTRIES = 100_000;
const ZERO_SHA256 = "0".repeat(64);
const JOURNAL_EVENT_TYPES = Object.freeze(new Set([
  "authority-created",
  "authority-confirmed",
  "authority-stopped",
  "dynamic-job-authorized",
  "dynamic-job-enqueued",
  "capability-issued",
  "request-started",
  "manifest-bound",
  "request-completed",
  "request-failed"
]));

const LAB_STOPS = Object.freeze([
  "authority-expiry",
  "campaign-binding-change",
  "engagement-invalid",
  "workflow-binding-change",
  "destination-binding-change",
  "adapter-contract-change",
  "budget-exhausted",
  "rate-backoff-stop",
  "redirect-observed",
  "target-instability",
  "evidence-integrity-failure",
  "execution-ambiguity",
  "execution-blocked",
  "operator-stop"
]);

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
}

function canonicalText(value) {
  return `${JSON.stringify(stableValue(value), null, 2)}\n`;
}

function canonicalSha256(value, domain = "gate.canonical.v1") {
  return crypto.createHash("sha256").update(`${domain}\0`, "utf8").update(canonicalText(value), "utf8").digest("hex");
}

function bytesSha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function digestWithout(value, field, domain) {
  const envelope = structuredClone(value);
  delete envelope[field];
  return canonicalSha256(envelope, domain);
}

function sameValue(left, right) {
  return canonicalSha256(left) === canonicalSha256(right);
}

function hasExactKeys(value, expected) {
  return value && typeof value === "object" && !Array.isArray(value) &&
    sameValue(Object.keys(value).sort(), [...expected].sort());
}

function nowInstant(options = {}) {
  const raw = typeof options.now === "function" ? options.now() : options.now || Date.now();
  const date = new Date(raw);
  if (!Number.isFinite(date.getTime())) throw new Error("lab campaign time must be a valid instant");
  return date.toISOString();
}

function nowMilliseconds(options = {}) {
  return Date.parse(nowInstant(options));
}

function exactId(value, label) {
  const id = String(value || "");
  if (!ID.test(id)) throw new Error(`${label} must start with a letter and contain lowercase letters, numbers, or dashes`);
  return id;
}

function exactSha(value, label) {
  const digest = String(value || "");
  if (!SHA256.test(digest)) throw new Error(`${label} must be a SHA-256 digest`);
  return digest;
}

function canonicalIp(value) {
  const raw = String(value || "");
  const version = net.isIP(raw);
  if (!version) throw new Error("each frozen destination must be one literal IP address");
  if (version === 4) return raw;
  const normalized = new URL(`http://[${raw}]/`).hostname.slice(1, -1);
  if (normalized !== raw.toLowerCase()) throw new Error(`frozen IPv6 addresses must be canonical: ${normalized}`);
  return normalized;
}

function canonicalOrigin(value) {
  let parsed;
  try { parsed = new URL(String(value || "")); }
  catch { throw new Error("challenge origin must be a valid HTTP or HTTPS origin"); }
  if (!new Set(["http:", "https:"]).has(parsed.protocol) || parsed.username || parsed.password ||
      parsed.pathname !== "/" || parsed.search || parsed.hash || String(value) !== parsed.origin) {
    throw new Error(`challenge origin must use its exact canonical origin form: ${parsed.origin}`);
  }
  return parsed.origin;
}

function canonicalUrl(value) {
  let parsed;
  try { parsed = new URL(String(value || "")); }
  catch { throw new Error("lab campaign target must be a valid HTTP or HTTPS URL"); }
  if (!new Set(["http:", "https:"]).has(parsed.protocol) || parsed.username || parsed.password || parsed.hash ||
      String(value) !== parsed.href) throw new Error(`lab campaign target must use its canonical URL form exactly: ${parsed.href}`);
  return parsed.href;
}

function authorityPaths(paths, authorityId = null) {
  if (!paths?.caseId || !paths?.stateHome) throw new Error("lab campaign authority requires a case-scoped runtime");
  const root = path.join(paths.stateHome, "lab-campaign-authorities");
  if (authorityId === null) return { root };
  const id = exactId(authorityId, "lab campaign authority id");
  const directory = path.join(root, id);
  return {
    root,
    directory,
    authority: path.join(directory, "authority.json"),
    admission: path.join(directory, "workflow-admission.json"),
    destinationObservation: path.join(directory, "destination-observation.json"),
    receipt: path.join(directory, "authorization-receipt.json"),
    journal: path.join(directory, "journal.jsonl"),
    lock: path.join(directory, ".authority.lock"),
    serialization: path.join(directory, ".authority.serialization"),
    capabilities: path.join(directory, "capabilities"),
    claims: path.join(directory, "claims")
  };
}

function ensureRoot(paths) {
  ensureRuntime(paths);
  const resolved = authorityPaths(paths);
  securePrivateDirectory(resolved.root, { label: "private lab campaign authority root" });
  return resolved.root;
}

function readJson(file, schema, paths, label) {
  const bytes = readPrivateFileBounded(file, MAX_DOCUMENT_BYTES, null, { label });
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); }
  catch { throw new Error(`${label} is not valid JSON`); }
  assertValidDocument(value, schema, { paths });
  return { value, bytes };
}

function readExternalDocument(file, schema, paths, label) {
  const resolved = path.resolve(String(file || ""));
  const stat = fs.lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_DOCUMENT_BYTES) {
    throw new Error(`${label} must be one regular file no larger than ${MAX_DOCUMENT_BYTES} bytes`);
  }
  const bytes = fs.readFileSync(resolved);
  const after = fs.lstatSync(resolved);
  if (after.dev !== stat.dev || after.ino !== stat.ino || after.size !== stat.size || after.mtimeMs !== stat.mtimeMs) {
    throw new Error(`${label} changed while it was read`);
  }
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); }
  catch { throw new Error(`${label} is not valid JSON`); }
  assertValidDocument(value, schema, { paths });
  return { value, bytes, sha256: bytesSha256(bytes) };
}

function grantDigest(grant) {
  return digestWithout(grant, "grantSha256", "gate.campaign-grant.v1");
}

function jobDigest(job) {
  return digestWithout(job, "jobSha256", "gate.campaign-job.v1");
}

function authorityDigest(authority) {
  return digestWithout(authority, "authoritySha256", "gate.lab-campaign-authority.v1");
}

function receiptDigest(receipt) {
  return digestWithout(receipt, "receiptSha256", "gate.lab-campaign-authorization-receipt.v1");
}

function capabilityDigest(capability) {
  return digestWithout(capability, "capabilitySha256", "gate.lab-campaign-job-capability.v1");
}

function enqueuePermitDigest(permit) {
  return digestWithout(permit, "permitSha256", "gate.lab-campaign-enqueue-permit.v1");
}

function exactConfirmation(authority) {
  return `AUTHORIZE LAB CAMPAIGN ${authority.metadata.id} ${authority.authoritySha256}`;
}

function exactStopConfirmation(authority) {
  return `STOP LAB CAMPAIGN ${authority.metadata.id} ${authority.authoritySha256}`;
}

function exactRecoveryConfirmation(authority) {
  return `RECOVER LAB CAMPAIGN ${authority.metadata.id} ${authority.authoritySha256}`;
}

function assertContext(context, paths, { expectedCampaignId, allowedState, requireSchedulingReady = true }) {
  if (!context || typeof context !== "object") throw new Error("campaign authority context is unavailable");
  const { grant, jobs, state, bindingHealth, labPermits = [], activeStart = null } = context;
  assertValidDocument(grant, "campaign-grant.schema.json", { paths });
  if (grant.grantSha256 !== grantDigest(grant)) throw new Error("campaign grant digest changed");
  if (grant.metadata.id !== expectedCampaignId || state?.campaignId !== expectedCampaignId ||
      state?.grantSha256 !== grant.grantSha256) throw new Error("campaign authority context binding changed");
  if (requireSchedulingReady && bindingHealth?.schedulingReady !== true && bindingHealth?.ready !== true) {
    throw new Error(`campaign scheduling bindings are not current: ${(bindingHealth?.reasons || ["unavailable"]).join("; ")}`);
  }
  if (!allowedState.has(state.status)) throw new Error(`campaign must be ${[...allowedState].join(" or ")}, observed ${state.status}`);
  if (!Array.isArray(jobs) || jobs.length < 1 || jobs.length > 10_000) throw new Error("lab campaign needs at least one immutable job");
  const seen = new Set();
  for (const job of jobs) {
    assertValidDocument(job, "campaign-job.schema.json", { paths });
    if (job.campaignId !== expectedCampaignId || job.grantSha256 !== grant.grantSha256 || job.jobSha256 !== jobDigest(job)) {
      throw new Error(`campaign job binding changed: ${job.metadata?.id || "unknown"}`);
    }
    if (seen.has(job.metadata.id)) throw new Error(`campaign job id is duplicated: ${job.metadata.id}`);
    seen.add(job.metadata.id);
    const projected = state.jobs?.find((candidate) => candidate.id === job.metadata.id);
    if (!projected || projected.jobSha256 !== job.jobSha256) throw new Error(`campaign projection job binding changed: ${job.metadata.id}`);
  }
  if (seen.size !== state.jobs?.length) throw new Error("campaign projection job set changed");
  if (!Array.isArray(labPermits)) throw new Error("campaign lab permit projection is invalid");
  return {
    grant,
    jobs: [...jobs].sort((a, b) => a.metadata.id.localeCompare(b.metadata.id)),
    state,
    bindingHealth,
    activeStart: structuredClone(activeStart),
    labPermits: structuredClone(labPermits)
  };
}

function assertExactControllerStart(context, authorityId, job) {
  const start = context.activeStart;
  if (!start || typeof start !== "object" || Array.isArray(start)) {
    throw new Error("lab dispatch requires the controller's hash-validated active start binding");
  }
  if (!hasExactKeys(start, ["jobId", "jobSha256", "authorityId"])) {
    throw new Error("campaign active start binding has unexpected fields");
  }
  if (start.authorityId !== authorityId || start.jobId !== job.metadata.id ||
      start.jobSha256 !== job.jobSha256) {
    throw new Error("campaign active start binding differs from the exact lab authority and job");
  }
  return start;
}

function noCommandSurface(value, label = "campaign job") {
  if (!value || typeof value !== "object") return;
  for (const [key, nested] of Object.entries(value)) {
    if (new Set(["argv", "command", "shell", "executable"]).has(key.toLowerCase())) {
      throw new Error(`${label} must not contain a command, argv, shell, or executable surface`);
    }
    noCommandSurface(nested, label);
  }
}

function jobAdapterInput(job) {
  if (job.job.type !== "managed-adapter") throw new Error(`lab authority admits managed-adapter jobs only: ${job.metadata.id}`);
  noCommandSurface(job.job);
  return {
    adapterId: job.job.adapter.id,
    workflowId: job.job.workflow.instanceId,
    phaseAttemptId: job.job.workflow.phaseAttemptId,
    target: job.job.selector.value,
    operation: structuredClone(job.job.operation),
    ...job.job.bounds
  };
}

function adapterIdentity(prepared) {
  return {
    id: prepared.binding.id,
    action: prepared.binding.action,
    toolId: prepared.adapter.tool.id,
    registrySha256: prepared.binding.registrySha256,
    entrySha256: prepared.binding.entrySha256,
    compilerId: prepared.binding.compiler.id,
    compilerSourceSha256: prepared.binding.compiler.sourceSha256,
    runtime: structuredClone(prepared.binding.runtime)
  };
}

function assertPrepared(prepared, job, origin, frozenIps, workflow) {
  if (job.job.adapter.id !== "httpx-url-fetch" || job.job.adapter.action !== "observe" || job.job.adapter.toolId !== "httpx") {
    throw new Error(`lab authority admits httpx-url-fetch observe jobs only: ${job.metadata.id}`);
  }
  if (job.job.selector.type !== "url") throw new Error(`lab authority requires an exact URL selector: ${job.metadata.id}`);
  const url = canonicalUrl(job.job.selector.value);
  if (new URL(url).origin !== origin) throw new Error(`campaign job leaves the exact challenge origin: ${job.metadata.id}`);
  if (!targetMatches({ type: "url", value: workflow.target }, { type: "url", value: url })) {
    throw new Error(`campaign job leaves the active workflow admission path prefix: ${job.metadata.id}`);
  }
  if (!frozenIps.includes(prepared.binding.operation.allowedIp)) {
    throw new Error(`campaign job destination is outside the frozen IP set: ${job.metadata.id}`);
  }
  const controls = prepared.binding.controls;
  if (prepared.binding.operation.kind !== "http-fetch" || !new Set(["GET", "HEAD"]).has(prepared.binding.operation.method) ||
      controls.redirects !== false || controls.redirectsFollowed !== 0 || controls.requestBody !== false ||
      controls.operatorCustomHeaders !== false || controls.authentication !== false || controls.socketDestinationPinned !== true ||
      controls.exactApprovedUrl !== true || controls.exactDialUrl !== true || controls.retries !== 0 || controls.concurrency !== 1) {
    throw new Error(`campaign job does not retain the reviewed no-redirect exact-destination contract: ${job.metadata.id}`);
  }
  return url;
}

function assertAdaptiveJobWithinAuthority(authority, job) {
  noCommandSurface(job.job);
  const value = job.job;
  if (value.type !== "managed-adapter" || value.engagementId !== authority.binding.engagement.id ||
      value.workflow.instanceId !== authority.binding.workflow.instanceId ||
      value.workflow.phaseAttemptId !== authority.binding.workflow.phaseAttemptId ||
      value.adapter.id !== "httpx-url-fetch" || value.adapter.action !== "observe" || value.adapter.toolId !== "httpx" ||
      value.selector.type !== "url") {
    throw new Error(`dynamic campaign job leaves the confirmed engagement, workflow, or adapter: ${job.metadata.id}`);
  }
  const url = canonicalUrl(value.selector.value);
  if (new URL(url).origin !== authority.binding.challenge.origin ||
      !targetMatches(
        { type: "url", value: authority.binding.challenge.pathPrefix },
        { type: "url", value: url }
      )) {
    throw new Error(`dynamic campaign job leaves the confirmed origin or path prefix: ${job.metadata.id}`);
  }
  const operation = value.operation;
  if (operation?.kind !== "http-fetch" || !authority.adaptive.allowedMethods.includes(operation.method) ||
      !authority.binding.challenge.frozenIps.includes(canonicalIp(operation.allowedIp)) ||
      !Number.isSafeInteger(operation.timeoutSeconds) || operation.timeoutSeconds < 1 ||
      operation.timeoutSeconds > authority.adaptive.maxTimeoutSeconds ||
      !Number.isSafeInteger(operation.maxResponseBytes) || operation.maxResponseBytes < 1024 ||
      operation.maxResponseBytes > authority.adaptive.maxResponseBytes ||
      !sameValue(value.bounds, authority.adaptive.jobBounds)) {
    throw new Error(`dynamic campaign job exceeds the confirmed HTTP or resource bounds: ${job.metadata.id}`);
  }
}

function executionBinding(check) {
  if (!check?.allowed || !check.executionBinding) {
    throw new Error(`dedicated-lab engagement preflight failed: ${(check?.reasons || ["unavailable"]).join("; ")}`);
  }
  if (check.engagement?.authorization?.basis !== "dedicated-lab") {
    throw new Error("lab campaign authority requires authorization.basis=dedicated-lab");
  }
  if (check.executionBinding.environment !== "host") throw new Error("lab campaign execution requires the approved host environment");
  if (!check.executionBinding.permittedTools?.includes("httpx")) throw new Error("httpx is outside the dedicated-lab engagement");
  if (!check.executionBinding.allowedDestinations?.includes("gate-home")) throw new Error("dedicated-lab evidence must remain under GATE_HOME");
  return check.executionBinding;
}

function sameEngagementBinding(left, right) {
  for (const field of ["engagementId", "planSha256", "envelopeSha256", "receiptSha256", "authorizationValidUntil", "environment"]) {
    if (left[field] !== right[field]) return false;
  }
  return true;
}

function assertWorkflow(status, admission, admissionSha256, jobs, engagement, options = {}) {
  if (!status?.ok || !status.activePhase) throw new Error("lab campaign requires one active reviewed workflow phase");
  const active = status.activePhase;
  const first = jobs[0].job;
  if (active.id !== "active-surface-validation" || active.effectClass !== "A1" || active.toolId !== "httpx" ||
      active.attemptId !== first.workflow.phaseAttemptId || status.instanceId !== first.workflow.instanceId) {
    throw new Error("lab campaign workflow must be the exact active-surface-validation A1/httpx phase attempt");
  }
  if (jobs.some((job) => job.job.workflow.instanceId !== status.instanceId || job.job.workflow.phaseAttemptId !== active.attemptId)) {
    throw new Error("all lab campaign jobs must bind the same active workflow phase attempt");
  }
  if (active.admissionSha256 !== admissionSha256 || admission.instanceId !== status.instanceId ||
      admission.phaseId !== active.id || admission.toolId !== "httpx" || admission.action !== "observe" ||
      admission.workflowDefinitionSha256 !== status.contract.sha256 && admission.workflowDefinitionSha256 !== status.contract.workflowSha256) {
    // Older compact status exposes only its contract digest. The admission
    // remains independently byte-bound and the broker rechecks definition SHA.
    if (active.admissionSha256 !== admissionSha256 || admission.instanceId !== status.instanceId ||
        admission.phaseId !== active.id || admission.toolId !== "httpx" || admission.action !== "observe") {
      throw new Error("workflow admission differs from the active phase");
    }
  }
  if (active.authorityReceiptSha256 !== engagement.receiptSha256 || admission.authority.receiptSha256 !== engagement.receiptSha256 ||
      admission.authority.engagementId !== engagement.engagementId || admission.authority.planSha256 !== engagement.planSha256 ||
      admission.authority.envelopeSha256 !== engagement.envelopeSha256 ||
      admission.authority.authorizationValidUntil !== engagement.authorizationValidUntil) {
    throw new Error("workflow admission authority differs from the current dedicated-lab engagement");
  }
  if (!sameValue(active.envelope, admission.envelope)) throw new Error("active workflow envelope differs from the reviewed admission");
  for (const field of ["wallTime", "requests", "rate", "parallel", "tokens", "evidenceBytes", "spend"]) {
    if (admission.envelope.controls[field] !== "enforced") throw new Error(`workflow admission control must be enforced: ${field}`);
  }
  if (nowMilliseconds(options) >= Date.parse(admission.expiresAt)) throw new Error("workflow admission expired");
  return {
    instanceId: status.instanceId,
    contractSha256: exactSha(status.contract.sha256, "workflow contract digest"),
    definitionSha256: exactSha(admission.workflowDefinitionSha256, "workflow definition digest"),
    phaseId: active.id,
    phaseAttemptId: active.attemptId,
    admissionSha256,
    admissionExpiresAt: admission.expiresAt,
    authorityReceiptSha256: active.authorityReceiptSha256,
    toolId: active.toolId,
    action: admission.action,
    envelopeSha256: canonicalSha256(admission.envelope, "gate.workflow-admission-envelope.v1"),
    target: canonicalUrl(admission.target),
    envelope: structuredClone(admission.envelope),
    stopConditions: [...active.stopConditions]
  };
}

function minimum(...values) {
  const numbers = values.map(Number);
  if (numbers.some((value) => !Number.isFinite(value))) throw new Error("authority ceiling source is invalid");
  return Math.min(...numbers);
}

function authorityCeilings(grant, engagement, workflow) {
  const engagementLimits = engagement.engagement.limits;
  const envelope = workflow.envelope;
  return {
    maxWallMinutes: minimum(grant.ceilings.maxWallMinutes, engagementLimits.maxMinutes, envelope.maxMinutes),
    maxRequests: minimum(grant.ceilings.maxRequests, engagementLimits.maxRequests, envelope.maxRequests),
    maxRatePerSecond: minimum(grant.ceilings.maxRatePerSecond, engagementLimits.maxRatePerSecond, envelope.maxRatePerSecond, 2),
    // One unresolved request must stop the next request until its terminal
    // outcome is durable. Without a separately durable execution-liveness
    // protocol, a value above one would make a crashed request
    // indistinguishable from an intentionally concurrent live request.
    maxConcurrency: minimum(grant.ceilings.maxConcurrency, engagementLimits.maxParallel, envelope.maxParallel, 1),
    maxInputTokens: minimum(grant.ceilings.maxInputTokens, envelope.maxInputTokens),
    maxOutputTokens: minimum(grant.ceilings.maxOutputTokens, envelope.maxOutputTokens),
    maxTotalTokens: minimum(grant.ceilings.maxTotalTokens, engagementLimits.maxTokens, envelope.maxTotalTokens),
    maxSpend: minimum(grant.ceilings.maxSpend, envelope.maxSpend),
    maxEvidenceBytes: minimum(grant.ceilings.maxEvidenceBytes, envelope.maxEvidenceBytes)
  };
}

function aggregateJobBounds(jobs) {
  return jobs.reduce((total, job) => ({
    maxWallMinutes: total.maxWallMinutes + job.job.bounds.maxMinutes,
    maxRequests: total.maxRequests + job.job.bounds.estimatedRequests,
    maxTotalTokens: total.maxTotalTokens + job.job.bounds.maxTokens,
    maxSpend: total.maxSpend + job.job.bounds.maxSpend,
    maxEvidenceBytes: total.maxEvidenceBytes + job.job.bounds.maxEvidenceBytes,
    maxRatePerSecond: Math.max(total.maxRatePerSecond, job.job.bounds.maxRatePerSecond),
    maxConcurrency: Math.max(total.maxConcurrency, job.job.bounds.maxParallel)
  }), {
    maxWallMinutes: 0, maxRequests: 0, maxTotalTokens: 0, maxSpend: 0,
    maxEvidenceBytes: 0, maxRatePerSecond: 0, maxConcurrency: 0
  });
}

function assertAggregateFits(jobs, ceilings) {
  const aggregate = aggregateJobBounds(jobs);
  for (const field of ["maxWallMinutes", "maxRequests", "maxTotalTokens", "maxSpend", "maxEvidenceBytes"]) {
    if (aggregate[field] > ceilings[field]) throw new Error(`lab campaign jobs exceed cumulative authority ceiling: ${field}`);
  }
  for (const field of ["maxRatePerSecond", "maxConcurrency"]) {
    if (aggregate[field] > ceilings[field]) throw new Error(`lab campaign jobs exceed instantaneous authority ceiling: ${field}`);
  }
}

function requireLoader(options) {
  if (typeof options.loadCampaignContext !== "function") {
    throw new Error("lab campaign authority requires the campaign controller's immutable context loader");
  }
  return options.loadCampaignContext;
}

function adapterPrepare(job, paths, options) {
  const prepare = options.prepareManagedAdapterInvocation || prepareManagedAdapterInvocation;
  return prepare(jobAdapterInput(job), { ...options, paths });
}

function engagementCheck(job, paths, options) {
  const check = options.checkEngagement || checkEngagement;
  return check(job.job.engagementId, {
    target: job.job.selector,
    action: job.job.adapter.action,
    ...job.job.bounds
  }, { paths });
}

function workflowCheck(job, paths, options) {
  const status = options.workflowStatus || workflowStatus;
  return status(job.job.workflow.instanceId, { paths });
}

function journalEntry(authorityId, sequence, previousEntrySha256, type, payload, at) {
  const entry = {
    apiVersion: "gate.lab-campaign-journal/v1",
    authorityId,
    sequence,
    at,
    type,
    previousEntrySha256,
    payload,
    entrySha256: ZERO_SHA256
  };
  entry.entrySha256 = digestWithout(entry, "entrySha256", "gate.lab-campaign-journal-entry.v1");
  return entry;
}

function parseJournalBytes(resolved, bytes) {
  if (bytes.length === 0) return [];
  const text = bytes.toString("utf8");
  const lines = text.endsWith("\n") ? text.slice(0, -1).split("\n") : text.split("\n");
  if (lines.some((line) => line.length === 0)) throw new Error("lab campaign journal contains an empty record");
  if (lines.length > MAX_JOURNAL_ENTRIES) throw new Error("lab campaign journal exceeds its entry limit");
  let previous = ZERO_SHA256;
  let previousAt = null;
  return lines.map((line, index) => {
    let entry;
    try { entry = JSON.parse(line); } catch { throw new Error("lab campaign journal contains invalid JSON"); }
    if (!hasExactKeys(entry, [
      "apiVersion", "authorityId", "sequence", "at", "type", "previousEntrySha256", "payload", "entrySha256"
    ]) || entry.apiVersion !== "gate.lab-campaign-journal/v1" ||
        entry.authorityId !== path.basename(resolved.directory) || entry.sequence !== index + 1 ||
        !JOURNAL_EVENT_TYPES.has(entry.type) || !entry.payload || typeof entry.payload !== "object" ||
        Array.isArray(entry.payload) ||
        entry.previousEntrySha256 !== previous || entry.entrySha256 !== digestWithout(entry, "entrySha256", "gate.lab-campaign-journal-entry.v1")) {
      throw new Error("lab campaign journal hash chain is invalid");
    }
    const at = new Date(entry.at);
    if (!Number.isFinite(at.getTime()) || at.toISOString() !== entry.at ||
        (previousAt !== null && at.getTime() < previousAt)) {
      throw new Error("lab campaign journal time is invalid");
    }
    previousAt = at.getTime();
    previous = entry.entrySha256;
    return entry;
  });
}

function readJournal(resolved, { allowUninitialized = false } = {}) {
  let bytes;
  try { bytes = readPrivateFileBounded(resolved.journal, MAX_JOURNAL_BYTES, null, { label: "private lab campaign journal" }); }
  catch (error) {
    if (error.code === "ENOENT" && allowUninitialized) return [];
    if (error.code === "ENOENT") throw new Error("lab campaign journal is missing and authority state is indeterminate", { cause: error });
    throw error;
  }
  if (bytes.length === 0) {
    if (allowUninitialized) return [];
    throw new Error("lab campaign journal is empty and authority state is indeterminate");
  }
  if (bytes.length > 0 && bytes.at(-1) !== 0x0a) {
    throw new Error("lab campaign journal has an incomplete final record; use exact reviewed recovery");
  }
  return parseJournalBytes(resolved, bytes);
}

function assertAuthorityJournalPrefix(entries, authority, receipt, { allowPendingConfirmation = false } = {}) {
  const created = entries[0];
  const expectedCreated = {
    authoritySha256: authority.authoritySha256,
    campaignId: authority.campaign.id,
    grantSha256: authority.campaign.grantSha256,
    jobSetSha256: authority.campaign.jobSetSha256
  };
  if (!created || created.type !== "authority-created" || !sameValue(created.payload, expectedCreated)) {
    throw new Error("lab campaign journal does not begin with the exact bound authority-created record");
  }
  const confirmations = entries.filter((entry) => entry.type === "authority-confirmed");
  if (!receipt) {
    if (confirmations.length !== 0) {
      throw new Error("lab campaign journal has a confirmation without its bound receipt");
    }
    return entries;
  }
  const expectedConfirmation = {
    authoritySha256: authority.authoritySha256,
    receiptSha256: receipt.receiptSha256
  };
  if (allowPendingConfirmation && entries.length === 1 && confirmations.length === 0) return entries;
  if (entries[1]?.type !== "authority-confirmed" || confirmations.length !== 1 ||
      !sameValue(entries[1].payload, expectedConfirmation)) {
    throw new Error("lab campaign journal is missing its exact bound authority-confirmed prefix");
  }
  return entries;
}

function readBoundJournal(loaded, options = {}) {
  return assertAuthorityJournalPrefix(
    readJournal(loaded.resolved),
    loaded.authority,
    loaded.receipt,
    options
  );
}

function repairIncompleteJournalTail(loaded, options) {
  const resolved = loaded.resolved;
  const bytes = readPrivateFileBounded(resolved.journal, MAX_JOURNAL_BYTES, null, {
    label: "private lab campaign journal"
  });
  if (bytes.length === 0 || bytes.at(-1) === 0x0a) return { repaired: false, mode: null };
  const boundary = bytes.lastIndexOf(0x0a);
  const prefix = boundary < 0 ? Buffer.alloc(0) : bytes.subarray(0, boundary + 1);
  const tail = boundary < 0 ? bytes : bytes.subarray(boundary + 1);
  const entries = parseJournalBytes(resolved, prefix);

  // A complete hash-valid final record that merely lost its newline is still
  // committed. Restore the delimiter rather than rolling that record back.
  let candidate;
  let completeJson = false;
  try {
    candidate = JSON.parse(tail.toString("utf8"));
    completeJson = true;
  } catch { /* A nonparseable final fragment is quarantined below. */ }
  if (completeJson) {
    const previous = entries.at(-1)?.entrySha256 || ZERO_SHA256;
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate) ||
        candidate.authorityId !== path.basename(resolved.directory) ||
        candidate.sequence !== entries.length + 1 || candidate.previousEntrySha256 !== previous ||
        candidate.entrySha256 !== digestWithout(candidate, "entrySha256", "gate.lab-campaign-journal-entry.v1")) {
      throw new Error("lab campaign journal final record is complete but invalid and was preserved for review");
    }
    assertAuthorityJournalPrefix([...entries, candidate], loaded.authority, loaded.receipt);
    writePrivateFileAtomic(resolved.journal, Buffer.concat([bytes, Buffer.from("\n")]), {
      label: "repaired private lab campaign journal delimiter"
    });
    syncPrivateDirectory(resolved.directory, { label: "private lab campaign authority after journal repair" });
    return { repaired: true, mode: "delimiter-restored" };
  }

  if (entries.length === 0) throw new Error("lab campaign journal has no complete record to recover");
  assertAuthorityJournalPrefix(entries, loaded.authority, loaded.receipt);
  const quarantine = `${resolved.journal}.torn.${crypto.randomBytes(8).toString("hex")}.bin`;
  writePrivateFileExclusive(quarantine, tail, { label: "quarantined private lab campaign journal tail" });
  const stopped = entries.some((entry) => entry.type === "authority-stopped");
  const stop = stopped ? Buffer.alloc(0) : Buffer.from(`${JSON.stringify(journalEntry(
    path.basename(resolved.directory), entries.length + 1, entries.at(-1).entrySha256,
    "authority-stopped", { condition: "execution-ambiguity", jobId: null, runId: null }, nowInstant(options)
  ))}\n`);
  writePrivateFileAtomic(resolved.journal, Buffer.concat([prefix, stop]), { label: "repaired private lab campaign journal" });
  syncPrivateDirectory(resolved.directory, { label: "private lab campaign authority after journal repair" });
  return { repaired: true, mode: "incomplete-tail-quarantined" };
}

function appendEntry(resolved, type, payload, options = {}, loaded = null) {
  const creating = type === "authority-created";
  const entries = creating
    ? readJournal(resolved, { allowUninitialized: true })
    : readBoundJournal(loaded, { allowPendingConfirmation: type === "authority-confirmed" });
  if (creating && entries.length !== 0) throw new Error("lab campaign authority creation journal is already initialized");
  const entry = journalEntry(
    path.basename(resolved.directory),
    entries.length + 1,
    entries.at(-1)?.entrySha256 || ZERO_SHA256,
    type,
    payload,
    nowInstant(options)
  );
  appendJsonLine(resolved.journal, entry, 0o600, { sync: true });
  if (creating) {
    assertAuthorityJournalPrefix([entry], loaded.authority, null);
  } else {
    assertAuthorityJournalPrefix([...entries, entry], loaded.authority, loaded.receipt);
  }
  return entry;
}

function processStartTicks(text) {
  const close = text.lastIndexOf(")");
  const fields = close === -1 ? [] : text.slice(close + 2).trim().split(/\s+/u);
  return fields.length > 19 && /^\d+$/u.test(fields[19]) ? fields[19] : null;
}

function currentLockOwner() {
  if (process.platform !== "linux") throw new Error("lab campaign locks require Linux process identity support");
  const bootId = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim().toLowerCase();
  const startTimeTicks = processStartTicks(fs.readFileSync(`/proc/${process.pid}/stat`, "utf8"));
  if (!/^[a-f0-9-]{36}$/u.test(bootId) || !startTimeTicks) throw new Error("lab campaign lock process identity is unavailable");
  return {
    apiVersion: "gate.lab-campaign-lock/v1",
    pid: process.pid,
    bootId,
    startTimeTicks,
    nonce: crypto.randomBytes(16).toString("hex"),
    createdAt: new Date().toISOString()
  };
}

function validLockOwner(owner) {
  return owner?.apiVersion === "gate.lab-campaign-lock/v1" && Number.isSafeInteger(owner.pid) && owner.pid > 0 &&
    /^[a-f0-9-]{36}$/u.test(owner.bootId) && /^\d+$/u.test(owner.startTimeTicks) &&
    /^[a-f0-9]{32}$/u.test(owner.nonce) && Number.isFinite(Date.parse(owner.createdAt));
}

function ownerProvablyDead(owner) {
  if (!validLockOwner(owner)) return false;
  let bootId;
  try { bootId = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim().toLowerCase(); }
  catch { return false; }
  if (bootId !== owner.bootId) return true;
  try {
    const observed = processStartTicks(fs.readFileSync(`/proc/${owner.pid}/stat`, "utf8"));
    return Boolean(observed && observed !== owner.startTimeTicks);
  } catch (error) {
    return error.code === "ENOENT";
  }
}

function readLockOwner(resolved) {
  try {
    const value = JSON.parse(readPrivateFileBounded(resolved.lock, 4096, "utf8", {
      label: "lab campaign authority mutation lock"
    }));
    return validLockOwner(value) ? value : null;
  } catch { return null; }
}

function trustedAuthorityFlock() {
  for (const candidate of ["/usr/bin/flock", "/bin/flock"]) {
    try {
      if (fs.realpathSync(candidate) !== candidate) continue;
      const stat = fs.lstatSync(candidate);
      if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o111) === 0 || (stat.mode & 0o022) !== 0) continue;
      if (typeof process.geteuid === "function" && stat.uid === process.geteuid()) continue;
      try {
        fs.accessSync(candidate, fs.constants.W_OK);
        continue;
      } catch (error) {
        if (!new Set(["EACCES", "EPERM", "EROFS"]).has(error.code)) throw error;
      }
      return candidate;
    } catch { /* Try the next fixed system path. */ }
  }
  throw new Error("lab campaign authority serialization requires flock from a protected system path");
}

function withAuthoritySerialization(resolved, callback) {
  if (process.platform !== "linux") throw new Error("lab campaign authority serialization requires Linux/WSL2");
  const descriptor = fs.openSync(
    resolved.serialization,
    fs.constants.O_CREAT | fs.constants.O_RDWR | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
    0o600
  );
  try {
    const identity = fs.fstatSync(descriptor);
    if (!identity.isFile() || identity.nlink !== 1 ||
        (typeof process.geteuid === "function" && identity.uid !== process.geteuid()) ||
        (identity.mode & 0o7777) !== 0o600) {
      throw new Error("lab campaign authority serialization file is not owner-only");
    }
    const locked = spawnSync(
      trustedAuthorityFlock(),
      ["--exclusive", "--timeout", "2", "3"],
      {
        stdio: ["ignore", "pipe", "pipe", descriptor],
        env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
        shell: false,
        timeout: 5_000,
        maxBuffer: 16 * 1024
      }
    );
    if (locked.error || locked.status !== 0) {
      throw new Error("lab campaign authority serialization is active or indeterminate", { cause: locked.error });
    }
    const current = fs.lstatSync(resolved.serialization);
    if (current.dev !== identity.dev || current.ino !== identity.ino) {
      throw new Error("lab campaign authority serialization identity changed");
    }
    return callback();
  } finally {
    fs.closeSync(descriptor);
  }
}

function retireProvablyDeadLock(resolved) {
  const identity = fs.lstatSync(resolved.lock);
  const bytes = readPrivateFileBounded(resolved.lock, 4096, null, {
    label: "lab campaign authority mutation lock"
  });
  let owner;
  try { owner = JSON.parse(bytes.toString("utf8")); }
  catch { throw new Error("lab campaign authority lock is malformed and requires reviewed recovery"); }
  if (!validLockOwner(owner)) throw new Error("lab campaign authority lock is malformed and requires reviewed recovery");
  if (!ownerProvablyDead(owner)) return false;
  const currentIdentity = fs.lstatSync(resolved.lock);
  const currentBytes = readPrivateFileBounded(resolved.lock, 4096, null, {
    label: "lab campaign authority mutation lock"
  });
  if (currentIdentity.dev !== identity.dev || currentIdentity.ino !== identity.ino || !currentBytes.equals(bytes)) {
    throw new Error("lab campaign authority lock changed during dead-owner proof");
  }
  const retired = `${resolved.lock}.retired.${crypto.randomBytes(8).toString("hex")}`;
  fs.renameSync(resolved.lock, retired);
  syncPrivateDirectory(resolved.directory, { label: "private lab campaign authority after lock retirement" });
  return true;
}

function acquireLock(resolved) {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const owner = currentLockOwner();
    try {
      writePrivateFileExclusive(resolved.lock, `${JSON.stringify(owner)}\n`, {
        encoding: "utf8", label: "lab campaign authority mutation lock"
      });
      return owner;
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      const prior = readLockOwner(resolved);
      if (attempt === 0 && prior && retireProvablyDeadLock(resolved)) {
        continue;
      }
      throw new Error(prior
        ? "lab campaign authority is already being mutated"
        : "lab campaign authority lock is malformed and requires reviewed recovery");
    }
  }
  throw new Error("lab campaign authority lock recovery did not converge");
}

function releaseLock(resolved, owner) {
  const current = readLockOwner(resolved);
  if (!current || !sameValue(current, owner)) throw new Error("lab campaign authority lock ownership changed");
  fs.rmSync(resolved.lock);
  syncPrivateDirectory(resolved.directory, { label: "private lab campaign authority directory" });
}

function withLock(resolved, callback) {
  return withAuthoritySerialization(resolved, () => {
    const owner = acquireLock(resolved);
    try { return callback(); }
    finally { releaseLock(resolved, owner); }
  });
}

function loadAuthority(paths, authorityId, { journalRecovery = false } = {}) {
  const resolved = authorityPaths(paths, authorityId);
  const { value: authority } = readJson(resolved.authority, "lab-campaign-authority.schema.json", paths, "private lab campaign authority");
  if (authority.metadata.id !== authorityId || authority.authoritySha256 !== authorityDigest(authority)) {
    throw new Error("lab campaign authority digest changed");
  }
  let receipt = null;
  try {
    receipt = readJson(resolved.receipt, "lab-campaign-authorization-receipt.schema.json", paths, "private lab campaign authorization receipt").value;
    if (receipt.authorityId !== authorityId || receipt.authoritySha256 !== authority.authoritySha256 ||
        receipt.confirmation !== exactConfirmation(authority) || receipt.receiptSha256 !== receiptDigest(receipt)) {
      throw new Error("lab campaign authorization receipt binding changed");
    }
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const loaded = { resolved, authority, receipt };
  if (!journalRecovery) loaded.entries = readBoundJournal(loaded);
  return loaded;
}

function assertBoundDestinationObservation(loaded, paths) {
  const observed = readJson(
    loaded.resolved.destinationObservation,
    "lab-destination-observation.schema.json",
    paths,
    "bound lab destination observation"
  );
  const value = observed.value;
  const ips = [...new Set(value.ips.map(canonicalIp))].sort();
  if (bytesSha256(observed.bytes) !== loaded.authority.binding.challenge.destinationObservationSha256 ||
      canonicalOrigin(value.origin) !== loaded.authority.binding.challenge.origin ||
      value.hostname !== new URL(loaded.authority.binding.challenge.origin).hostname ||
      value.observedAt !== loaded.authority.binding.challenge.destinationObservedAt ||
      value.source.sha256 !== loaded.authority.binding.challenge.destinationSourceSha256 ||
      !sameValue(ips, loaded.authority.binding.challenge.frozenIps)) {
    throw new Error("bound lab destination observation changed");
  }
  return value;
}

function assertAuthorityCampaignSnapshot(authority, checked) {
  if (checked.grant.grantSha256 !== authority.campaign.grantSha256 ||
      !sameValue(checked.grant.binding.case, authority.binding.case) ||
      !sameValue(checked.grant.binding.program, authority.binding.program) ||
      !sameValue(checked.grant.binding.source, authority.binding.source)) {
    throw new Error("campaign binding changed after lab authority review");
  }
  const initial = new Map(authority.campaign.jobs.map((job) => [job.id, job.jobSha256]));
  const initialListed = checked.jobs.filter((job) => initial.has(job.metadata.id))
    .map((job) => ({ id: job.metadata.id, jobSha256: job.jobSha256 }));
  if (canonicalSha256(initialListed, "gate.lab-campaign-job-set.v1") !== authority.campaign.jobSetSha256 ||
      !sameValue(initialListed, authority.campaign.jobs)) throw new Error("initial campaign job set changed after lab authority review");
}

function currentContext(loaded, options, allowedState, { requireSchedulingReady = true } = {}) {
  const authority = loaded.authority;
  const context = requireLoader(options)(authority.campaign.id, { ...options, paths: options.paths });
  const checked = assertContext(context, options.paths, {
    expectedCampaignId: authority.campaign.id,
    allowedState,
    requireSchedulingReady
  });
  assertAuthorityCampaignSnapshot(authority, checked);
  const initial = new Map(authority.campaign.jobs.map((job) => [job.id, job.jobSha256]));
  const entries = readBoundJournal(loaded);
  const authorized = new Map(entries.filter((entry) => entry.type === "dynamic-job-authorized")
    .map((entry) => [entry.payload.jobId, entry.payload]));
  const dynamic = checked.jobs.filter((job) => !initial.has(job.metadata.id));
  for (const job of dynamic) {
    const intent = authorized.get(job.metadata.id);
    if (!intent || intent.jobSha256 !== job.jobSha256) {
      throw new Error(`campaign contains a dynamic job without this authority's exact append-only intent: ${job.metadata.id}`);
    }
    assertAdaptiveJobWithinAuthority(authority, job);
  }
  if (checked.jobs.length > authority.adaptive.maxJobs) throw new Error("campaign exceeds the authorized adaptive job count");
  assertAggregateFits(checked.jobs, authority.ceilings);
  return checked;
}

function enqueuePermitFor(loaded, candidateJob) {
  const permit = {
    authorityId: loaded.authority.metadata.id,
    authoritySha256: loaded.authority.authoritySha256,
    receiptSha256: loaded.receipt.receiptSha256,
    campaignId: loaded.authority.campaign.id,
    grantSha256: loaded.authority.campaign.grantSha256,
    jobId: candidateJob.metadata.id,
    jobSha256: candidateJob.jobSha256,
    origin: loaded.authority.binding.challenge.origin,
    // The controller persists an origin plus a canonical absolute pathname.
    // The authority itself retains the full reviewed URL so query-sensitive
    // targetMatches checks remain part of every live authority verification.
    pathPrefix: new URL(loaded.authority.binding.challenge.pathPrefix).pathname,
    frozenIps: [...loaded.authority.binding.challenge.frozenIps],
    adapter: {
      id: loaded.authority.binding.adapter.id,
      action: loaded.authority.binding.adapter.action,
      toolId: loaded.authority.binding.adapter.toolId,
      registrySha256: loaded.authority.binding.adapter.registrySha256,
      entrySha256: loaded.authority.binding.adapter.entrySha256,
      compilerSourceSha256: loaded.authority.binding.adapter.compilerSourceSha256,
      runtimeSha256: canonicalSha256(loaded.authority.binding.adapter.runtime, "gate.lab-runtime-binding.v1")
    },
    workflow: {
      instanceId: loaded.authority.binding.workflow.instanceId,
      phaseId: loaded.authority.binding.workflow.phaseId,
      phaseAttemptId: loaded.authority.binding.workflow.phaseAttemptId,
      admissionSha256: loaded.authority.binding.workflow.admissionSha256,
      authorityReceiptSha256: loaded.authority.binding.workflow.authorityReceiptSha256
    },
    ceilings: structuredClone(loaded.authority.ceilings),
    dynamic: {
      maxJobs: loaded.authority.adaptive.maxJobs,
      allowedMethods: [...loaded.authority.adaptive.allowedMethods],
      maxResponseBytes: loaded.authority.adaptive.maxResponseBytes,
      maxTimeoutSeconds: loaded.authority.adaptive.maxTimeoutSeconds
    },
    permitSha256: ZERO_SHA256
  };
  permit.permitSha256 = enqueuePermitDigest(permit);
  return permit;
}

function committedControllerEnqueue(loaded, candidateJob, options) {
  const context = assertContext(
    requireLoader(options)(loaded.authority.campaign.id, { ...options, paths: options.paths }),
    options.paths,
    {
      expectedCampaignId: loaded.authority.campaign.id,
      allowedState: new Set(["paused", "running", "blocked", "stopped", "completed"]),
      requireSchedulingReady: false
    }
  );
  assertAuthorityCampaignSnapshot(loaded.authority, context);
  const records = context.labPermits.filter((record) => record.jobId === candidateJob.metadata.id);
  if (records.length === 0) return null;
  if (records.length !== 1) throw new Error("campaign contains duplicate durable permits for the adaptive job");

  const expectedPermit = enqueuePermitFor(loaded, candidateJob);
  const record = records[0];
  const committedJob = context.jobs.find((job) => job.metadata.id === candidateJob.metadata.id);
  const projected = context.state.jobs.find((job) => job.id === candidateJob.metadata.id);
  if (!committedJob || !sameValue(committedJob, candidateJob) || committedJob.jobSha256 !== candidateJob.jobSha256 ||
      record.jobSha256 !== candidateJob.jobSha256 || record.authorityId !== loaded.authority.metadata.id ||
      !sameValue(record.permit, expectedPermit) || projected?.jobSha256 !== candidateJob.jobSha256 ||
      projected?.authority?.id !== loaded.authority.metadata.id ||
      projected?.authority?.authoritySha256 !== loaded.authority.authoritySha256 ||
      projected?.authority?.receiptSha256 !== loaded.receipt.receiptSha256 ||
      projected?.authority?.permitSha256 !== expectedPermit.permitSha256) {
    throw new Error("committed adaptive campaign job differs from the exact authority intent");
  }

  const payload = {
    jobId: candidateJob.metadata.id,
    jobSha256: candidateJob.jobSha256,
    permitSha256: expectedPermit.permitSha256
  };
  const entries = readBoundJournal(loaded);
  const intents = entries.filter((entry) => entry.type === "dynamic-job-authorized" &&
    entry.payload.jobId === candidateJob.metadata.id);
  if (intents.length !== 1 || !sameValue(intents[0].payload, payload)) {
    throw new Error("committed adaptive campaign job lacks its exact durable authority intent");
  }
  const completions = entries.filter((entry) => entry.type === "dynamic-job-enqueued" &&
    entry.payload.jobId === candidateJob.metadata.id);
  if (completions.length > 1 || (completions.length === 1 && !sameValue(completions[0].payload, payload))) {
    throw new Error("adaptive campaign enqueue completion differs from its exact authority intent");
  }
  return { context, permit: expectedPermit, payload, completed: completions.length === 1 };
}

function assertCurrentBindings(authority, context, admission, paths, options, requestedJob = null) {
  const jobs = requestedJob ? [requestedJob] : context.jobs;
  const firstCheck = engagementCheck(jobs[0], paths, options);
  const firstBinding = executionBinding(firstCheck);
  const expectedEngagement = authority.binding.engagement;
  if (!sameEngagementBinding(firstBinding, {
    engagementId: expectedEngagement.id,
    ...expectedEngagement
  }) || firstCheck.engagement.authorization.basis !== expectedEngagement.basis) {
    throw new Error("dedicated-lab engagement binding changed after review");
  }
  const status = workflowCheck(jobs[0], paths, options);
  const workflow = assertWorkflow(status, admission, authority.binding.workflow.admissionSha256, jobs, firstBinding, options);
  const currentWorkflow = { ...workflow };
  delete currentWorkflow.target;
  delete currentWorkflow.envelope;
  delete currentWorkflow.stopConditions;
  if (!sameValue(currentWorkflow, authority.binding.workflow)) throw new Error("workflow binding changed after lab authority review");
  for (const job of jobs) {
    const binding = executionBinding(engagementCheck(job, paths, options));
    if (!sameEngagementBinding(binding, firstBinding)) throw new Error("campaign jobs no longer share one engagement binding");
    const prepared = adapterPrepare(job, paths, options);
    assertPrepared(prepared, job, authority.binding.challenge.origin, authority.binding.challenge.frozenIps, workflow);
    if (!sameValue(adapterIdentity(prepared), authority.binding.adapter)) throw new Error("managed adapter identity changed after lab authority review");
  }
  return { firstBinding, workflow };
}

export function createLabCampaignAuthority(input, options = {}) {
  const paths = options.paths || runtimePaths(options);
  options = { ...options, paths };
  const authorityId = exactId(input.authorityId, "lab campaign authority id");
  const campaignId = exactId(input.campaignId, "campaign id");
  const context = assertContext(requireLoader(options)(campaignId, options), paths, {
    expectedCampaignId: campaignId,
    allowedState: new Set(["paused"])
  });
  if (context.state.jobs.some((job) => job.status !== "queued")) throw new Error("lab authority review requires every campaign job to remain queued");
  if (!context.grant.binding.engagement) throw new Error("lab authority requires a campaign-bound engagement");
  if (context.grant.allow.environment !== "host") throw new Error("lab authority requires a host campaign environment");
  const origin = canonicalOrigin(input.challengeOrigin);
  const frozenIps = [...new Set((input.frozenIps || []).map(canonicalIp))].sort();
  if (frozenIps.length < 1 || frozenIps.length > 32) throw new Error("lab authority requires one to 32 frozen destination IPs");
  const destinationObservation = readExternalDocument(
    input.destinationObservationFile,
    "lab-destination-observation.schema.json",
    paths,
    "reviewed lab destination observation"
  );
  const observedOrigin = canonicalOrigin(destinationObservation.value.origin);
  const observedIps = [...new Set(destinationObservation.value.ips.map(canonicalIp))].sort();
  if (observedOrigin !== origin || destinationObservation.value.hostname !== new URL(origin).hostname ||
      !sameValue(observedIps, frozenIps)) {
    throw new Error("frozen destinations differ from the cited destination observation");
  }
  if (Date.parse(destinationObservation.value.observedAt) > nowMilliseconds(options)) {
    throw new Error("destination observation cannot be from the future");
  }
  const admission = readExternalDocument(input.admissionFile, "workflow-admission.schema.json", paths, "reviewed workflow admission");
  const firstCheck = engagementCheck(context.jobs[0], paths, options);
  const firstBinding = executionBinding(firstCheck);
  if (firstBinding.engagementId !== context.grant.binding.engagement.id) throw new Error("campaign engagement binding changed");
  const status = workflowCheck(context.jobs[0], paths, options);
  const workflow = assertWorkflow(status, admission.value, admission.sha256, context.jobs, firstBinding, options);
  const prepared = [];
  for (const job of context.jobs) {
    if (!context.grant.allow.operations.some((operation) => operation.adapterId === job.job.adapter.id &&
        operation.action === job.job.adapter.action && operation.toolId === job.job.adapter.toolId)) {
      throw new Error(`campaign grant does not allow job adapter tuple: ${job.metadata.id}`);
    }
    if (!context.grant.allow.selectors.some((selector) => targetMatches(selector, job.job.selector))) {
      throw new Error(`campaign grant does not allow job selector: ${job.metadata.id}`);
    }
    const binding = executionBinding(engagementCheck(job, paths, options));
    if (!sameEngagementBinding(binding, firstBinding)) throw new Error("campaign jobs do not share one dedicated-lab engagement binding");
    const compiled = adapterPrepare(job, paths, options);
    assertPrepared(compiled, job, origin, frozenIps, workflow);
    prepared.push(compiled);
  }
  const identity = adapterIdentity(prepared[0]);
  if (prepared.some((item) => !sameValue(adapterIdentity(item), identity))) throw new Error("campaign jobs do not share one adapter/runtime identity");
  if (context.grant.allow.adapterRegistrySha256 !== identity.registrySha256) throw new Error("campaign grant adapter registry digest changed");
  const ceilings = authorityCeilings(context.grant, firstCheck, workflow);
  assertAggregateFits(context.jobs, ceilings);
  const dynamicBounds = structuredClone(input.dynamicJobBounds || context.jobs[0].job.bounds);
  const maxJobs = Number(input.maxJobs ?? Math.min(32, ceilings.maxRequests));
  if (!Number.isSafeInteger(maxJobs) || maxJobs < context.jobs.length || maxJobs > 10_000) {
    throw new Error("adaptive lab maxJobs must cover the initial jobs and remain at most 10000");
  }
  const adaptive = {
    maxJobs,
    allowedMethods: ["GET", "HEAD"],
    maxResponseBytes: Number(input.maxResponseBytes ?? Math.max(...context.jobs.map((job) => job.job.operation.maxResponseBytes))),
    maxTimeoutSeconds: Number(input.maxTimeoutSeconds ?? Math.max(...context.jobs.map((job) => job.job.operation.timeoutSeconds))),
    jobBounds: dynamicBounds
  };
  const createdAt = nowInstant(options);
  const requestedExpiry = new Date(input.expiresAt);
  if (!Number.isFinite(requestedExpiry.getTime())) throw new Error("lab authority expiry must be a valid instant");
  const latestExpiry = Math.min(
    Date.parse(context.grant.metadata.expiresAt),
    Date.parse(firstBinding.authorizationValidUntil),
    Date.parse(admission.value.expiresAt),
    Date.parse(createdAt) + ceilings.maxWallMinutes * 60_000
  );
  if (requestedExpiry.getTime() > latestExpiry) throw new Error("lab authority expiry exceeds a bound campaign, engagement, workflow, or wall-time window");
  if (requestedExpiry.getTime() <= Date.parse(createdAt)) throw new Error("lab authority must expire in the future");
  const listedJobs = context.jobs.map((job) => ({ id: job.metadata.id, jobSha256: job.jobSha256 }));
  const workflowBinding = { ...workflow };
  delete workflowBinding.target;
  delete workflowBinding.envelope;
  delete workflowBinding.stopConditions;
  const authority = {
    $schema: AUTHORITY_SCHEMA,
    apiVersion: "gate.lab-campaign-authority/v1",
    kind: "LabCampaignAuthority",
    metadata: { id: authorityId, createdAt, expiresAt: requestedExpiry.toISOString() },
    campaign: {
      id: campaignId,
      grantSha256: context.grant.grantSha256,
      jobSetSha256: canonicalSha256(listedJobs, "gate.lab-campaign-job-set.v1"),
      jobs: listedJobs
    },
    binding: {
      case: structuredClone(context.grant.binding.case),
      program: structuredClone(context.grant.binding.program),
      source: structuredClone(context.grant.binding.source),
      engagement: {
        id: firstBinding.engagementId,
        basis: "dedicated-lab",
        planSha256: firstBinding.planSha256,
        envelopeSha256: firstBinding.envelopeSha256,
        receiptSha256: firstBinding.receiptSha256,
        authorizationValidUntil: firstBinding.authorizationValidUntil,
        environment: firstBinding.environment
      },
      workflow: workflowBinding,
      challenge: {
        origin,
        exactUrl: workflow.target,
        pathPrefix: workflow.target,
        frozenIps,
        destinationObservationSha256: destinationObservation.sha256,
        destinationObservedAt: destinationObservation.value.observedAt,
        destinationSourceSha256: destinationObservation.value.source.sha256
      },
      adapter: identity
    },
    ceilings,
    adaptive,
    stopConditions: [...new Set([...context.grant.stopConditions, ...workflow.stopConditions, ...LAB_STOPS])].sort(),
    authoritySha256: ZERO_SHA256
  };
  authority.authoritySha256 = authorityDigest(authority);
  assertValidDocument(authority, "lab-campaign-authority.schema.json", { paths });
  const root = ensureRoot(paths);
  const resolved = authorityPaths(paths, authorityId);
  try {
    fs.mkdirSync(resolved.directory, { mode: 0o700 });
  } catch (error) {
    if (error.code === "EEXIST") throw new Error(`lab campaign authority already exists: ${authorityId}`);
    throw error;
  }
  try {
    securePrivateDirectory(resolved.capabilities, { label: "private lab campaign capabilities" });
    securePrivateDirectory(resolved.claims, { label: "private lab campaign capability claims" });
    writePrivateFileExclusive(resolved.authority, canonicalText(authority), { encoding: "utf8", label: "private lab campaign authority" });
    writePrivateFileExclusive(resolved.admission, admission.bytes, { label: "bound workflow admission" });
    writePrivateFileExclusive(resolved.destinationObservation, destinationObservation.bytes, {
      label: "bound lab destination observation"
    });
    appendEntry(resolved, "authority-created", {
      authoritySha256: authority.authoritySha256,
      campaignId,
      grantSha256: authority.campaign.grantSha256,
      jobSetSha256: authority.campaign.jobSetSha256
    }, options, { resolved, authority, receipt: null });
    syncPrivateDirectory(resolved.directory, { label: "private lab campaign authority directory" });
  } catch (error) {
    fs.rmSync(resolved.directory, { recursive: true, force: true });
    throw error;
  }
  syncPrivateDirectory(root, { label: "private lab campaign authority root" });
  return {
    authority,
    confirmationRequired: exactConfirmation(authority),
    authorityRef: `private://lab-campaign-authorities/${authorityId}/authority.json`
  };
}

export function confirmLabCampaignAuthority(authorityId, input, options = {}) {
  const paths = options.paths || runtimePaths(options);
  options = { ...options, paths };
  const loaded = loadAuthority(paths, exactId(authorityId, "lab campaign authority id"));
  if (loaded.receipt) throw new Error(`lab campaign authority is already confirmed: ${authorityId}`);
  const required = exactConfirmation(loaded.authority);
  const supplied = Buffer.from(String(input?.confirm || ""));
  const expected = Buffer.from(required);
  if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
    throw new Error(`lab campaign confirmation must be exactly: ${required}`);
  }
  if (nowMilliseconds(options) >= Date.parse(loaded.authority.metadata.expiresAt)) throw new Error("lab campaign authority expired before confirmation");
  const admission = readJson(loaded.resolved.admission, "workflow-admission.schema.json", paths, "bound workflow admission");
  if (bytesSha256(admission.bytes) !== loaded.authority.binding.workflow.admissionSha256) {
    throw new Error("bound workflow admission bytes changed");
  }
  assertBoundDestinationObservation(loaded, paths);
  const context = currentContext(loaded, options, new Set(["paused"]));
  if (context.state.jobs.some((job) => job.status !== "queued")) throw new Error("lab authority confirmation requires every job to remain queued");
  assertCurrentBindings(loaded.authority, context, admission.value, paths, options);
  const confirmedAt = nowInstant(options);
  const receipt = {
    $schema: RECEIPT_SCHEMA,
    apiVersion: "gate.lab-campaign-authorization/v1",
    kind: "LabCampaignAuthorizationReceipt",
    authorityId: loaded.authority.metadata.id,
    authoritySha256: loaded.authority.authoritySha256,
    confirmation: required,
    confirmedAt,
    receiptSha256: ZERO_SHA256
  };
  receipt.receiptSha256 = receiptDigest(receipt);
  assertValidDocument(receipt, "lab-campaign-authorization-receipt.schema.json", { paths });
  return withLock(loaded.resolved, () => {
    // Validate the complete delimiter-terminated journal before publishing the
    // receipt so a torn creation record cannot leave a receipt without its
    // matching confirmation entry.
    const entries = readBoundJournal(loaded);
    if (entries.some((entry) => entry.type === "authority-stopped")) {
      throw new Error("lab campaign authority is stopped");
    }
    writePrivateFileExclusive(loaded.resolved.receipt, canonicalText(receipt), {
      encoding: "utf8", label: "private lab campaign authorization receipt"
    });
    appendEntry(loaded.resolved, "authority-confirmed", {
      authoritySha256: loaded.authority.authoritySha256,
      receiptSha256: receipt.receiptSha256
    }, options, { ...loaded, receipt });
    return {
      confirmed: true,
      authorityId: loaded.authority.metadata.id,
      authoritySha256: loaded.authority.authoritySha256,
      receiptSha256: receipt.receiptSha256,
      expiresAt: loaded.authority.metadata.expiresAt
    };
  });
}

export function stopLabCampaignAuthority(authorityId, input, options = {}) {
  const paths = options.paths || runtimePaths(options);
  const loaded = loadAuthority(paths, exactId(authorityId, "lab campaign authority id"));
  if (!loaded.receipt) throw new Error("lab campaign authority has not been confirmed");
  const confirmation = exactStopConfirmation(loaded.authority);
  if (String(input?.confirm || "") !== confirmation) {
    throw new Error(`lab campaign stop confirmation must be exactly: ${confirmation}`);
  }
  return withLock(loaded.resolved, () => {
    const entries = readBoundJournal(loaded);
    const stopped = entries.find((entry) => entry.type === "authority-stopped");
    if (stopped) return { stopped: true, replayed: true, authorityId, stop: stopped.payload };
    const entry = appendEntry(loaded.resolved, "authority-stopped", {
      condition: "operator-stop",
      jobId: null,
      runId: null
    }, options, loaded);
    return { stopped: true, replayed: false, authorityId, stop: entry.payload };
  });
}

/**
 * Retire only capabilities that were durably claimed before the pre-contact
 * request intent could be journaled. A started request remains ambiguous and
 * requires execution reconciliation; this command never guesses its outcome.
 */
export function recoverLabCampaignAuthority(authorityId, input, options = {}) {
  const paths = options.paths || runtimePaths(options);
  const loaded = loadAuthority(paths, exactId(authorityId, "lab campaign authority id"), { journalRecovery: true });
  const confirmation = exactRecoveryConfirmation(loaded.authority);
  if (String(input?.confirm || "") !== confirmation) {
    throw new Error(`lab campaign recovery confirmation must be exactly: ${confirmation}`);
  }
  return withLock(loaded.resolved, () => {
    const journalRepair = repairIncompleteJournalTail(loaded, options);
    const entries = readBoundJournal(loaded);
    const claims = readClaims(loaded.resolved, paths);
    const started = new Set(entries.filter((entry) => entry.type === "request-started")
      .map((entry) => entry.payload.capabilityId));
    const terminal = new Set(entries.filter((entry) =>
      new Set(["request-completed", "request-failed"]).has(entry.type)
    ).map((entry) => entry.payload.capabilityId));
    const unresolvedStarted = unresolvedStartedClaims(entries, claims);
    if (unresolvedStarted.length) {
      throw new Error(`lab campaign has a started request that requires execution reconciliation: ${unresolvedStarted[0].metadata.id}`);
    }
    const unjournaled = claims.filter((claim) =>
      !started.has(claim.metadata.id) && !terminal.has(claim.metadata.id));
    const ambiguousTail = journalRepair.mode === "incomplete-tail-quarantined";
    if ((unjournaled.length || ambiguousTail) && !entries.some((entry) => entry.type === "authority-stopped")) {
      appendEntry(loaded.resolved, "authority-stopped", {
        condition: "execution-ambiguity",
        jobId: unjournaled[0]?.campaign.jobId || null,
        runId: null
      }, options, loaded);
    }
    for (const claim of unjournaled) {
      appendEntry(loaded.resolved, "request-failed", {
        capabilityId: claim.metadata.id,
        jobId: claim.campaign.jobId,
        manifestId: null,
        reason: "Reviewed recovery retired a claimed capability before any request intent was journaled."
      }, options, loaded);
    }
    return {
      recovered: true,
      authorityId,
      journalRepair,
      retiredCapabilities: unjournaled.map((claim) => claim.metadata.id),
      stopped: unjournaled.length > 0 || ambiguousTail
    };
  });
}

function capabilityFor(authority, receipt, job, prepared) {
  const seed = canonicalSha256({ authority: authority.authoritySha256, receipt: receipt.receiptSha256, job: job.jobSha256 }, "gate.lab-capability-id.v1");
  const capability = {
    $schema: CAPABILITY_SCHEMA,
    apiVersion: "gate.lab-campaign-job-capability/v1",
    kind: "LabCampaignJobCapability",
    metadata: { id: `lcap_${seed.slice(0, 32)}`, issuedAt: receipt.confirmedAt, expiresAt: authority.metadata.expiresAt },
    authority: { id: authority.metadata.id, sha256: authority.authoritySha256, receiptSha256: receipt.receiptSha256 },
    campaign: { id: authority.campaign.id, grantSha256: authority.campaign.grantSha256, jobId: job.metadata.id, jobSha256: job.jobSha256 },
    workflow: {
      instanceId: authority.binding.workflow.instanceId,
      phaseId: authority.binding.workflow.phaseId,
      phaseAttemptId: authority.binding.workflow.phaseAttemptId,
      admissionSha256: authority.binding.workflow.admissionSha256,
      authorityReceiptSha256: authority.binding.workflow.authorityReceiptSha256
    },
    request: {
      url: job.job.selector.value,
      origin: authority.binding.challenge.origin,
      method: prepared.binding.operation.method,
      allowedIp: prepared.binding.operation.allowedIp,
      operationSha256: prepared.binding.operationSha256,
      argvSha256: prepared.binding.argvSha256
    },
    adapter: {
      id: prepared.binding.id,
      registrySha256: prepared.binding.registrySha256,
      entrySha256: prepared.binding.entrySha256,
      compilerSourceSha256: prepared.binding.compiler.sourceSha256,
      runtimeSha256: canonicalSha256(prepared.binding.runtime, "gate.lab-runtime-binding.v1")
    },
    bounds: structuredClone(job.job.bounds),
    capabilitySha256: ZERO_SHA256
  };
  capability.capabilitySha256 = capabilityDigest(capability);
  return capability;
}

function writeOrVerifyCapability(resolved, capability, paths) {
  const file = path.join(resolved.capabilities, `${capability.metadata.id}.json`);
  try {
    writePrivateFileExclusive(file, canonicalText(capability), { encoding: "utf8", label: "private lab job capability" });
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    const current = readJson(file, "lab-campaign-job-capability.schema.json", paths, "private lab job capability").value;
    if (!sameValue(current, capability) || current.capabilitySha256 !== capabilityDigest(current)) {
      throw new Error("existing lab job capability differs from the reviewed job");
    }
  }
  return file;
}

function readClaims(resolved, paths) {
  return fs.readdirSync(resolved.claims, { withFileTypes: true }).filter((entry) => entry.isFile() && entry.name.endsWith(".json")).map((entry) => {
    const file = path.join(resolved.claims, entry.name);
    const { value } = readJson(file, "lab-campaign-job-capability.schema.json", paths, "claimed lab job capability");
    if (value.capabilitySha256 !== capabilityDigest(value) || `${value.metadata.id}.json` !== entry.name) {
      throw new Error("lab campaign capability claim binding changed");
    }
    return value;
  });
}

function claimedReservations(claims) {
  return claims.reduce((total, capability) => ({
    maxWallMinutes: total.maxWallMinutes + capability.bounds.maxMinutes,
    maxRequests: total.maxRequests + capability.bounds.estimatedRequests,
    maxTotalTokens: total.maxTotalTokens + capability.bounds.maxTokens,
    maxSpend: total.maxSpend + capability.bounds.maxSpend,
    maxEvidenceBytes: total.maxEvidenceBytes + capability.bounds.maxEvidenceBytes
  }), { maxWallMinutes: 0, maxRequests: 0, maxTotalTokens: 0, maxSpend: 0, maxEvidenceBytes: 0 });
}

function assertClaimBudget(authority, claims, next) {
  const reservations = claimedReservations([...claims, next]);
  for (const field of ["maxWallMinutes", "maxRequests", "maxTotalTokens", "maxSpend", "maxEvidenceBytes"]) {
    if (reservations[field] > authority.ceilings[field]) throw new Error(`lab campaign cumulative budget exhausted: ${field}`);
  }
  const entries = claims.length;
  if (entries >= authority.adaptive.maxJobs) throw new Error("lab campaign has no unclaimed jobs");
}

function claimCapability(resolved, capability) {
  const file = path.join(resolved.claims, `${capability.metadata.id}.json`);
  try {
    writePrivateFileExclusive(file, canonicalText(capability), { encoding: "utf8", label: "single-use lab job capability claim" });
  } catch (error) {
    if (error.code === "EEXIST") throw new Error(`lab campaign job capability was already consumed: ${capability.campaign.jobId}`);
    throw error;
  }
  return file;
}

function activeRequestCount(entries) {
  const active = new Set();
  for (const entry of entries) {
    if (entry.type === "request-started") active.add(entry.payload.capabilityId);
    if (new Set(["request-completed", "request-failed"]).has(entry.type)) active.delete(entry.payload.capabilityId);
  }
  return active.size;
}

function unresolvedStartedClaims(entries, claims) {
  const started = new Set(entries.filter((entry) => entry.type === "request-started")
    .map((entry) => entry.payload.capabilityId));
  const terminal = new Set(entries.filter((entry) =>
    new Set(["request-completed", "request-failed"]).has(entry.type)
  ).map((entry) => entry.payload.capabilityId));
  return claims.filter((claim) => started.has(claim.metadata.id) && !terminal.has(claim.metadata.id));
}

function lastRequestAt(entries) {
  return entries.filter((entry) => entry.type === "request-started").at(-1)?.at || null;
}

function manifestMatchesCapability(manifest, authority, capability, prepared, options = {}) {
  const manifestExpiry = Date.parse(manifest?.expiresAt);
  const expectedLabCampaign = capabilityReferenceContext({ authority }, capability, null);
  return manifest?.ok === true && manifest.manifestId && manifest.manifestSha256 &&
    Number.isFinite(manifestExpiry) && manifestExpiry <= Date.parse(authority.metadata.expiresAt) &&
    manifestExpiry > nowMilliseconds(options) &&
    manifest.operation?.targetArgument === capability.request.url &&
    sameValue(manifest.operation?.adapter, prepared.binding) &&
    sameValue(manifest.operation?.argv, prepared.compiled.argv) &&
    sameValue(manifest.declaredBounds, prepared.normalized.declaredBounds) &&
    manifest.workflow?.instanceId === capability.workflow.instanceId &&
    manifest.workflow?.phaseId === capability.workflow.phaseId &&
    manifest.workflow?.phaseAttemptId === capability.workflow.phaseAttemptId &&
    manifest.workflow?.admissionSha256 === capability.workflow.admissionSha256 &&
    manifest.workflow?.authorityReceiptSha256 === capability.workflow.authorityReceiptSha256 &&
    manifest.workflow?.definitionSha256 === authority.binding.workflow.definitionSha256 &&
    sameValue(manifest.labCampaign, expectedLabCampaign) &&
    manifest.confirmationRequired === `EXECUTE ${manifest.manifestId} ${manifest.manifestSha256} UNMETERED`;
}

function safeError(error) {
  return String(error?.message || error || "execution failed").replace(/[\u0000\r\n]+/gu, " ").slice(0, 500);
}

function resultEvidenceBytes(result, paths, maximum) {
  const streams = Number(result?.evidence?.stdout?.bytes || 0) + Number(result?.evidence?.stderr?.bytes || 0);
  if (!result?.evidence?.resultAvailable) return streams;
  const prefix = "private://evidence/";
  const ref = String(result.evidence.resultRef || "");
  if (!ref.startsWith(prefix) || path.basename(ref.slice(prefix.length)) !== ref.slice(prefix.length)) {
    throw new Error("execution result evidence reference is invalid");
  }
  const bytes = readPrivateFileBounded(path.join(paths.evidence, ref.slice(prefix.length)), maximum, null, {
    label: "private lab execution result evidence"
  });
  return streams + bytes.length;
}

function stopForResult(result) {
  if (result?.status !== "succeeded" || result?.ok !== true) return "execution-blocked";
  const status = result.adapterOutput?.metrics?.statusCode;
  if (status === 429) return "rate-backoff-stop";
  if (Number.isInteger(status) && status >= 300 && status < 400) return "redirect-observed";
  if (Number.isInteger(status) && status >= 500) return "target-instability";
  return null;
}

function checkedAdapterMetrics(result, prepared) {
  const output = result?.adapterOutput;
  const metrics = output?.metrics;
  const operation = prepared.binding.operation;
  const controls = prepared.binding.controls;
  const valid = output?.ok === true && output.status === "observed" && metrics?.requestCount === 1 &&
    metrics.method === operation.method && Number.isSafeInteger(metrics.statusCode) &&
    metrics.statusCode >= 100 && metrics.statusCode <= 599 &&
    Number.isSafeInteger(metrics.responseBodyBytes) && metrics.responseBodyBytes >= 0 &&
    metrics.responseBodyBytes <= operation.maxResponseBytes &&
    Number.isSafeInteger(metrics.responseContentLength) && metrics.responseContentLength >= 0 &&
    metrics.rateLimitPerSecond === controls.ratePerSecond && metrics.redirectsFollowed === 0 &&
    metrics.redirectStatus === "not-followed" && metrics.retries === 0 &&
    metrics.backoffStatus === "disabled-no-retries";
  if (!valid) {
    const error = new Error("managed adapter result metrics failed the lab capability integrity check");
    error.labStopCondition = "evidence-integrity-failure";
    throw error;
  }
  return metrics;
}

/**
 * Revalidate a claimed one-shot capability for the execution broker. This is
 * the only input that may select the dedicated-lab path-prefix reservation.
 */
export function verifyLabCampaignExecutionCapability(capability, expected, options = {}) {
  const paths = options.paths || runtimePaths(options);
  options = { ...options, paths };
  if (capability?.kind !== "LabCampaignJobCapability") {
    const reference = capability;
    const authorityId = exactId(reference?.authorityId, "lab campaign authority id");
    const capabilityId = String(reference?.capabilityId || "");
    if (!/^lcap_[a-f0-9]{32}$/u.test(capabilityId)) throw new Error("lab campaign capability reference is invalid");
    const resolved = authorityPaths(paths, authorityId);
    capability = readJson(
      path.join(resolved.capabilities, `${capabilityId}.json`),
      "lab-campaign-job-capability.schema.json",
      paths,
      "private lab job capability"
    ).value;
    if (reference.authoritySha256 !== capability.authority.sha256 ||
        reference.receiptSha256 !== capability.authority.receiptSha256 ||
        reference.capabilitySha256 !== capability.capabilitySha256 ||
        reference.expiresAt !== capability.metadata.expiresAt) {
      throw new Error("lab campaign capability reference binding changed");
    }
  }
  assertValidDocument(capability, "lab-campaign-job-capability.schema.json", { paths });
  if (capability.capabilitySha256 !== capabilityDigest(capability)) throw new Error("lab campaign capability digest changed");
  const loaded = loadAuthority(paths, capability.authority.id);
  if (!loaded.receipt || loaded.authority.authoritySha256 !== capability.authority.sha256 ||
      loaded.receipt.receiptSha256 !== capability.authority.receiptSha256) {
    throw new Error("lab campaign capability authority receipt changed");
  }
  if (nowMilliseconds(options) >= Date.parse(loaded.authority.metadata.expiresAt) ||
      nowMilliseconds(options) >= Date.parse(capability.metadata.expiresAt)) throw new Error("lab campaign execution capability expired");
  const entries = readBoundJournal(loaded);
  if (entries.some((entry) => entry.type === "authority-stopped")) throw new Error("lab campaign authority is stopped");
  assertBoundDestinationObservation(loaded, paths);
  const capabilityFile = path.join(loaded.resolved.capabilities, `${capability.metadata.id}.json`);
  const claimFile = path.join(loaded.resolved.claims, `${capability.metadata.id}.json`);
  const persisted = readJson(capabilityFile, "lab-campaign-job-capability.schema.json", paths, "private lab job capability").value;
  const claimed = readJson(claimFile, "lab-campaign-job-capability.schema.json", paths, "claimed lab job capability").value;
  if (!sameValue(persisted, capability) || !sameValue(claimed, capability)) {
    throw new Error("lab campaign capability or claim differs from the broker input");
  }
  if (!entries.some((entry) => entry.type === "request-started" &&
      entry.payload.capabilityId === capability.metadata.id &&
      entry.payload.capabilitySha256 === capability.capabilitySha256)) {
    throw new Error("lab campaign request intent is not durably journaled");
  }
  if (entries.some((entry) => new Set(["request-completed", "request-failed"]).has(entry.type) &&
      entry.payload.capabilityId === capability.metadata.id)) {
    throw new Error("lab campaign capability already has a terminal request record");
  }
  const manifestBindings = entries.filter((entry) => entry.type === "manifest-bound" &&
    entry.payload.capabilityId === capability.metadata.id);
  if (expected?.manifestId) {
    if (manifestBindings.length !== 1 || manifestBindings[0].payload.manifestId !== expected.manifestId ||
        manifestBindings[0].payload.manifestSha256 !== expected.manifestSha256) {
      throw new Error("lab campaign capability is not bound to this exact execution manifest");
    }
  } else if (manifestBindings.length) {
    throw new Error("lab campaign capability already has an execution manifest");
  }
  const context = currentContext(loaded, options, new Set(["running"]));
  const job = context.jobs.find((candidate) => candidate.metadata.id === capability.campaign.jobId);
  const projected = context.state.jobs.find((candidate) => candidate.id === capability.campaign.jobId);
  if (!job || projected?.status !== "running" || job.jobSha256 !== capability.campaign.jobSha256 ||
      job.grantSha256 !== capability.campaign.grantSha256) {
    throw new Error("lab campaign capability job is no longer the running controller job");
  }
  assertExactControllerStart(context, loaded.authority.metadata.id, job);
  const admission = readJson(loaded.resolved.admission, "workflow-admission.schema.json", paths, "bound workflow admission");
  assertCurrentBindings(loaded.authority, context, admission.value, paths, options, job);
  const prepared = adapterPrepare(job, paths, options);
  const comparisons = {
    engagementId: loaded.authority.binding.engagement.id,
    target: capability.request.url,
    action: "observe",
    toolId: "httpx",
    adapterId: "httpx-url-fetch",
    operationSha256: capability.request.operationSha256,
    argvSha256: capability.request.argvSha256,
    workflowId: capability.workflow.instanceId,
    phaseAttemptId: capability.workflow.phaseAttemptId
  };
  for (const [field, wanted] of Object.entries(comparisons)) {
    if (expected?.[field] !== wanted) throw new Error(`execution request differs from lab capability: ${field}`);
  }
  const expectedBounds = {
    maxMinutes: capability.bounds.maxMinutes,
    estimatedRequests: capability.bounds.estimatedRequests,
    maxParallel: capability.bounds.maxParallel,
    maxRatePerSecond: capability.bounds.maxRatePerSecond,
    maxTokens: capability.bounds.maxTokens,
    maxEvidenceBytes: capability.bounds.maxEvidenceBytes
  };
  if (!sameValue(expected?.declaredBounds, expectedBounds) ||
      !sameValue(prepared.normalized.declaredBounds, expectedBounds) ||
      !sameValue(expected?.adapterBinding, prepared.binding)) {
    throw new Error("execution bounds or reviewed adapter binding differs from the lab capability");
  }
  if (prepared.binding.operation.allowedIp !== capability.request.allowedIp ||
      new URL(capability.request.url).origin !== loaded.authority.binding.challenge.origin ||
      !targetMatches({ type: "url", value: loaded.authority.binding.challenge.pathPrefix },
        { type: "url", value: capability.request.url }) ||
      !loaded.authority.binding.challenge.frozenIps.includes(capability.request.allowedIp)) {
    throw new Error("lab capability leaves its origin, path prefix, or frozen destination set");
  }
  return capabilityReferenceContext(loaded, capability, expectedBounds);
}

function capabilityReferenceContext(loaded, capability, expectedBounds = null) {
  const authority = loaded.authority;
  const receiptSha256 = loaded.receipt?.receiptSha256 || capability.authority.receiptSha256;
  const bounds = expectedBounds || {
    maxMinutes: capability.bounds.maxMinutes,
    estimatedRequests: capability.bounds.estimatedRequests,
    maxParallel: capability.bounds.maxParallel,
    maxRatePerSecond: capability.bounds.maxRatePerSecond,
    maxTokens: capability.bounds.maxTokens,
    maxEvidenceBytes: capability.bounds.maxEvidenceBytes
  };
  return {
    authorityId: authority.metadata.id,
    authoritySha256: authority.authoritySha256,
    receiptSha256,
    capabilityId: capability.metadata.id,
    capabilitySha256: capability.capabilitySha256,
    campaignId: authority.campaign.id,
    grantSha256: authority.campaign.grantSha256,
    engagementId: authority.binding.engagement.id,
    workflowInstanceId: capability.workflow.instanceId,
    phaseId: capability.workflow.phaseId,
    phaseAttemptId: capability.workflow.phaseAttemptId,
    admissionSha256: capability.workflow.admissionSha256,
    authorityReceiptSha256: capability.workflow.authorityReceiptSha256,
    origin: authority.binding.challenge.origin,
    pathPrefix: authority.binding.challenge.pathPrefix,
    requestUrl: capability.request.url,
    requestUrlSha256: bytesSha256(Buffer.from(capability.request.url)),
    allowedIp: capability.request.allowedIp,
    operationSha256: capability.request.operationSha256,
    argvSha256: capability.request.argvSha256,
    boundsSha256: canonicalSha256(bounds, "gate.lab-execution-bounds.v1"),
    expiresAt: authority.metadata.expiresAt
  };
}

/**
 * Verify the persisted single-use capability against a workflow projection
 * that is already locked by workflow-runtime. This deliberately avoids
 * workflowStatus/current campaign loading so it cannot recursively acquire the
 * workflow lock and historical replay never depends on live external state.
 */
export function verifyLabCampaignWorkflowReservation(reference, expected, options = {}) {
  const paths = options.paths || runtimePaths(options);
  const authorityId = exactId(reference?.authorityId, "lab campaign authority id");
  const capabilityId = String(reference?.capabilityId || "");
  if (!/^lcap_[a-f0-9]{32}$/u.test(capabilityId)) throw new Error("lab campaign capability reference is invalid");
  const loaded = loadAuthority(paths, authorityId);
  if (!loaded.receipt) throw new Error("lab campaign authority has not been confirmed");
  if (nowMilliseconds(options) >= Date.parse(loaded.authority.metadata.expiresAt)) throw new Error("lab campaign authority expired");
  const capability = readJson(
    path.join(loaded.resolved.capabilities, `${capabilityId}.json`),
    "lab-campaign-job-capability.schema.json",
    paths,
    "private lab job capability"
  ).value;
  if (capability.capabilitySha256 !== capabilityDigest(capability)) throw new Error("lab campaign capability digest changed");
  const claimed = readJson(
    path.join(loaded.resolved.claims, `${capabilityId}.json`),
    "lab-campaign-job-capability.schema.json",
    paths,
    "claimed lab job capability"
  ).value;
  if (!sameValue(claimed, capability)) throw new Error("lab campaign capability claim changed");
  const entries = readBoundJournal(loaded);
  if (entries.some((entry) => entry.type === "authority-stopped")) throw new Error("lab campaign authority is stopped");
  if (!entries.some((entry) => entry.type === "request-started" &&
      entry.payload.capabilityId === capabilityId && entry.payload.capabilitySha256 === capability.capabilitySha256)) {
    throw new Error("lab campaign request intent is not durably journaled");
  }
  if (entries.some((entry) => new Set(["request-completed", "request-failed"]).has(entry.type) &&
      entry.payload.capabilityId === capabilityId)) {
    throw new Error("lab campaign capability was already consumed");
  }
  const manifestBindings = entries.filter((entry) => entry.type === "manifest-bound" &&
    entry.payload.capabilityId === capabilityId);
  if (expected?.requireUnbound === true && manifestBindings.length) {
    throw new Error("lab campaign capability already has an execution manifest");
  }
  if (manifestBindings.length && (manifestBindings.length !== 1 ||
      manifestBindings[0].payload.manifestId !== expected?.manifestId ||
      (expected?.manifestSha256 && manifestBindings[0].payload.manifestSha256 !== expected.manifestSha256))) {
    throw new Error("lab campaign capability is bound to a different execution manifest");
  }
  assertBoundDestinationObservation(loaded, paths);
  const context = capabilityReferenceContext(loaded, capability);
  if (!sameValue(reference, context)) throw new Error("lab campaign workflow reservation reference changed");
  const comparisons = {
    engagementId: context.engagementId,
    workflowInstanceId: context.workflowInstanceId,
    phaseId: context.phaseId,
    phaseAttemptId: context.phaseAttemptId,
    admissionSha256: context.admissionSha256,
    authorityReceiptSha256: context.authorityReceiptSha256,
    targetSha256: context.requestUrlSha256,
    action: "observe",
    toolId: "httpx"
  };
  for (const [field, wanted] of Object.entries(comparisons)) {
    if (expected?.[field] !== wanted) throw new Error(`workflow reservation differs from lab capability: ${field}`);
  }
  const envelope = expected?.envelope;
  if (!envelope || envelope.maxMinutes !== capability.bounds.maxMinutes ||
      envelope.maxRequests !== capability.bounds.estimatedRequests ||
      envelope.maxRatePerSecond !== capability.bounds.maxRatePerSecond ||
      envelope.maxParallel !== capability.bounds.maxParallel ||
      envelope.maxInputTokens !== 0 || envelope.maxOutputTokens !== 0 ||
      envelope.maxTotalTokens !== capability.bounds.maxTokens ||
      envelope.maxEvidenceBytes !== capability.bounds.maxEvidenceBytes ||
      !Number.isFinite(envelope.maxSpend) || envelope.maxSpend < 0 ||
      envelope.maxSpend > capability.bounds.maxSpend) {
    throw new Error("workflow reservation envelope differs from the lab capability bounds");
  }
  if (expected.target !== context.requestUrl || new URL(expected.target).origin !== context.origin ||
      !targetMatches({ type: "url", value: context.pathPrefix }, { type: "url", value: expected.target }) ||
      capability.request.allowedIp !== context.allowedIp ||
      !loaded.authority.binding.challenge.frozenIps.includes(context.allowedIp)) {
    throw new Error("workflow reservation leaves the lab origin, path prefix, or frozen destination set");
  }
  return context;
}

/** Verify one exact adaptive job against an already-confirmed lab authority. */
export function verifyLabCampaignEnqueuePermit(authorityId, candidateJob, options = {}) {
  const paths = options.paths || runtimePaths(options);
  options = { ...options, paths };
  const loaded = loadAuthority(paths, exactId(authorityId, "lab campaign authority id"));
  if (!loaded.receipt) throw new Error("lab campaign authority has not been confirmed");
  if (nowMilliseconds(options) >= Date.parse(loaded.authority.metadata.expiresAt)) throw new Error("lab campaign authority expired");
  const entries = readBoundJournal(loaded);
  if (entries.some((entry) => entry.type === "authority-stopped")) throw new Error("lab campaign authority is stopped");
  assertBoundDestinationObservation(loaded, paths);
  assertValidDocument(candidateJob, "campaign-job.schema.json", { paths });
  if (candidateJob.jobSha256 !== jobDigest(candidateJob)) throw new Error("adaptive campaign job digest changed");
  const context = currentContext(loaded, options, new Set(["paused", "running", "completed"]));
  if (candidateJob.campaignId !== loaded.authority.campaign.id ||
      candidateJob.grantSha256 !== loaded.authority.campaign.grantSha256) {
    throw new Error("adaptive job belongs to a different campaign or grant");
  }
  const existing = context.jobs.find((job) => job.metadata.id === candidateJob.metadata.id);
  if (existing && !sameValue(existing, candidateJob)) throw new Error("adaptive job id already names a different immutable job");
  const allJobs = existing ? context.jobs : [...context.jobs, candidateJob];
  if (allJobs.length > loaded.authority.adaptive.maxJobs) throw new Error("adaptive lab job count exceeds the confirmed authority");
  assertAggregateFits(allJobs, loaded.authority.ceilings);
  if (!loaded.authority.adaptive.allowedMethods.includes(candidateJob.job.operation?.method) ||
      candidateJob.job.operation?.maxResponseBytes > loaded.authority.adaptive.maxResponseBytes ||
      candidateJob.job.operation?.timeoutSeconds > loaded.authority.adaptive.maxTimeoutSeconds ||
      !sameValue(candidateJob.job.bounds, loaded.authority.adaptive.jobBounds)) {
    throw new Error("adaptive job exceeds the confirmed per-job operation or resource envelope");
  }
  if (!context.grant.allow.operations.some((operation) => operation.adapterId === candidateJob.job.adapter.id &&
      operation.action === candidateJob.job.adapter.action && operation.toolId === candidateJob.job.adapter.toolId) ||
      !context.grant.allow.selectors.some((selector) => targetMatches(selector, candidateJob.job.selector))) {
    throw new Error("adaptive job is outside the immutable campaign grant");
  }
  const admission = readJson(loaded.resolved.admission, "workflow-admission.schema.json", paths, "bound workflow admission");
  if (bytesSha256(admission.bytes) !== loaded.authority.binding.workflow.admissionSha256) {
    throw new Error("bound workflow admission bytes changed");
  }
  const binding = executionBinding(engagementCheck(candidateJob, paths, options));
  const status = workflowCheck(candidateJob, paths, options);
  const workflow = assertWorkflow(
    status,
    admission.value,
    loaded.authority.binding.workflow.admissionSha256,
    [candidateJob],
    binding,
    options
  );
  const prepared = adapterPrepare(candidateJob, paths, options);
  assertPrepared(
    prepared,
    candidateJob,
    loaded.authority.binding.challenge.origin,
    loaded.authority.binding.challenge.frozenIps,
    workflow
  );
  if (!sameValue(adapterIdentity(prepared), loaded.authority.binding.adapter)) {
    throw new Error("adaptive job adapter identity differs from the confirmed authority");
  }
  return enqueuePermitFor(loaded, candidateJob);
}

/**
 * Build and durably authorize one same-origin adaptive HTTP job before asking
 * the campaign controller to append it to its own hash-chained queue.
 */
export async function enqueueAuthorizedLabCampaignFetch(authorityId, input, options = {}) {
  const paths = options.paths || runtimePaths(options);
  options = { ...options, paths };
  const loaded = loadAuthority(paths, exactId(authorityId, "lab campaign authority id"));
  if (!loaded.receipt) throw new Error("lab campaign authority has not been confirmed");
  const method = String(input.method || "GET").toUpperCase();
  const target = canonicalUrl(input.target);
  const allowedIp = canonicalIp(input.allowedIp);
  const timeoutSeconds = Number(input.timeoutSeconds ?? loaded.authority.adaptive.maxTimeoutSeconds);
  const maxResponseBytes = Number(input.maxResponseBytes ?? loaded.authority.adaptive.maxResponseBytes);
  const job = {
    $schema: "https://gate.local/schemas/campaign-job.schema.json",
    apiVersion: "gate.dev/campaign-job/v1",
    kind: "CampaignJob",
    metadata: {
      id: exactId(input.jobId, "adaptive campaign job id"),
      createdAt: loaded.receipt.confirmedAt
    },
    campaignId: loaded.authority.campaign.id,
    grantSha256: loaded.authority.campaign.grantSha256,
    job: {
      type: "managed-adapter",
      engagementId: loaded.authority.binding.engagement.id,
      workflow: {
        instanceId: loaded.authority.binding.workflow.instanceId,
        phaseAttemptId: loaded.authority.binding.workflow.phaseAttemptId
      },
      adapter: { id: "httpx-url-fetch", action: "observe", toolId: "httpx" },
      selector: { type: "url", value: target },
      operation: { kind: "http-fetch", method, allowedIp, timeoutSeconds, maxResponseBytes },
      bounds: structuredClone(loaded.authority.adaptive.jobBounds)
    },
    jobSha256: ZERO_SHA256
  };
  job.jobSha256 = jobDigest(job);
  const campaignModule = options.enqueueLabCampaignJob ? null : await import("./campaigns.mjs");
  const enqueue = options.enqueueLabCampaignJob || campaignModule.enqueueLabCampaignJob;
  if (typeof enqueue !== "function") throw new Error("campaign controller does not expose adaptive lab job enqueue");
  const committed = withLock(loaded.resolved, () => {
    // A controller append is the commit point. If the process died before the
    // authority completion entry, reconcile only that exact persisted
    // job/permit before applying current expiry or stop checks. This path
    // cannot authorize, enqueue, or contact anything new.
    const reconciled = committedControllerEnqueue(loaded, job, options);
    if (reconciled) {
      if (!reconciled.completed) {
        appendEntry(loaded.resolved, "dynamic-job-enqueued", reconciled.payload, options, loaded);
      }
      return {
        permit: reconciled.permit,
        controller: {
          ok: true,
          reconciled: true,
          campaignId: loaded.authority.campaign.id,
          job: { id: job.metadata.id, jobSha256: job.jobSha256 },
          authority: {
            id: loaded.authority.metadata.id,
            permitSha256: reconciled.permit.permitSha256
          },
          state: reconciled.context.state
        }
      };
    }

    const entries = readBoundJournal(loaded);
    if (entries.some((entry) => entry.type === "authority-stopped")) {
      throw new Error("lab campaign authority is stopped");
    }
    if (nowMilliseconds(options) >= Date.parse(loaded.authority.metadata.expiresAt)) {
      throw new Error("lab campaign authority expired");
    }
    const permit = verifyLabCampaignEnqueuePermit(authorityId, job, options);
    const prior = entries.find((entry) => entry.type === "dynamic-job-authorized" && entry.payload.jobId === job.metadata.id);
    const payload = {
      jobId: job.metadata.id,
      jobSha256: job.jobSha256,
      permitSha256: permit.permitSha256
    };
    if (prior && !sameValue(prior.payload, payload)) throw new Error("adaptive job authorization intent changed");
    if (!prior) appendEntry(loaded.resolved, "dynamic-job-authorized", payload, options, loaded);
    const controllerResult = enqueue(loaded.authority.campaign.id, {
      authorityId: loaded.authority.metadata.id,
      job
    }, {
      ...options,
      paths,
      verifyLabEnqueue: (_authorityId, candidate) => {
        const exactCandidate = candidate?.kind === "CampaignJob" ? candidate : candidate?.job || candidate;
        if (!sameValue(exactCandidate, job)) throw new Error("campaign controller requested a substituted adaptive job permit");
        const verified = verifyLabCampaignEnqueuePermit(authorityId, job, options);
        if (!sameValue(verified, permit)) throw new Error("adaptive lab enqueue permit changed inside controller lock");
        return verified;
      }
    });
    if (controllerResult && typeof controllerResult.then === "function") {
      throw new Error("campaign controller lab enqueue must be synchronous for authority atomicity");
    }
    const currentEntries = readBoundJournal(loaded);
    if (!currentEntries.some((entry) => entry.type === "dynamic-job-enqueued" && entry.payload.jobId === job.metadata.id)) {
      appendEntry(loaded.resolved, "dynamic-job-enqueued", payload, options, loaded);
    }
    return { permit, controller: controllerResult };
  });
  return {
    ok: true,
    authorityId,
    campaignId: loaded.authority.campaign.id,
    job,
    permit: committed.permit,
    controller: committed.controller
  };
}

/**
 * Consume one already-running campaign job through the unchanged execution
 * broker. The campaign controller remains responsible for its own job journal.
 */
export async function dispatchAuthorizedLabCampaignJob(authorityId, jobEnvelope, options = {}) {
  const paths = options.paths || runtimePaths(options);
  options = { ...options, paths };
  const loaded = loadAuthority(paths, exactId(authorityId, "lab campaign authority id"));
  if (!loaded.receipt) throw new Error("lab campaign authority has not been confirmed");
  if (nowMilliseconds(options) >= Date.parse(loaded.authority.metadata.expiresAt)) throw new Error("lab campaign authority expired");
  const context = currentContext(loaded, options, new Set(["running"]));
  const jobId = exactId(jobEnvelope?.metadata?.id, "campaign job id");
  const job = context.jobs.find((candidate) => candidate.metadata.id === jobId);
  if (!job || !sameValue(job, jobEnvelope) || job.jobSha256 !== jobEnvelope.jobSha256) {
    throw new Error("campaign controller supplied a different immutable job envelope");
  }
  const projected = context.state.jobs.find((candidate) => candidate.id === jobId);
  if (projected?.status !== "running") throw new Error("lab dispatch requires the controller to durably start the exact job first");
  assertExactControllerStart(context, loaded.authority.metadata.id, job);
  const admission = readJson(loaded.resolved.admission, "workflow-admission.schema.json", paths, "bound workflow admission");
  if (bytesSha256(admission.bytes) !== loaded.authority.binding.workflow.admissionSha256) throw new Error("bound workflow admission bytes changed");
  assertBoundDestinationObservation(loaded, paths);
  assertCurrentBindings(loaded.authority, context, admission.value, paths, options, job);
  const prepared = adapterPrepare(job, paths, options);
  const capability = capabilityFor(loaded.authority, loaded.receipt, job, prepared);
  assertValidDocument(capability, "lab-campaign-job-capability.schema.json", { paths });
  // Rate, concurrency, durable single use, and the pre-contact request intent
  // become one serialized transition. Recheck after any bounded rate wait so
  // two dispatchers cannot both pass a stale observation.
  while (true) {
    if (nowMilliseconds(options) >= Date.parse(loaded.authority.metadata.expiresAt)) throw new Error("lab campaign authority expired");
    const refreshed = currentContext(loaded, options, new Set(["running"]));
    const refreshedJob = refreshed.jobs.find((candidate) => candidate.metadata.id === jobId);
    const refreshedProjection = refreshed.state.jobs.find((candidate) => candidate.id === jobId);
    if (!refreshedJob || !sameValue(refreshedJob, job) || refreshedProjection?.status !== "running") {
      throw new Error("campaign job or controller state changed before lab dispatch");
    }
    assertExactControllerStart(refreshed, loaded.authority.metadata.id, refreshedJob);
    assertBoundDestinationObservation(loaded, paths);
    assertCurrentBindings(loaded.authority, refreshed, admission.value, paths, options, job);
    let waitMilliseconds = 0;
    withLock(loaded.resolved, () => {
      const entries = readBoundJournal(loaded);
      if (entries.some((entry) => entry.type === "authority-stopped")) throw new Error("lab campaign authority is stopped");
      const claims = readClaims(loaded.resolved, paths);
      const startedCapabilities = new Set(entries.filter((entry) => entry.type === "request-started")
        .map((entry) => entry.payload.capabilityId));
      const terminalCapabilities = new Set(entries.filter((entry) =>
        new Set(["request-completed", "request-failed"]).has(entry.type)
      ).map((entry) => entry.payload.capabilityId));
      const unjournaledClaim = claims.find((claim) =>
        !startedCapabilities.has(claim.metadata.id) && !terminalCapabilities.has(claim.metadata.id)
      );
      if (unjournaledClaim) {
        throw new Error(`lab campaign recovery is required for capability: ${unjournaledClaim.metadata.id}`);
      }
      const unresolvedStarted = unresolvedStartedClaims(entries, claims);
      if (unresolvedStarted.length > 0) {
        throw new Error(
          `lab campaign has an unresolved started request that requires execution reconciliation: ${unresolvedStarted[0].metadata.id}`
        );
      }
      if (activeRequestCount(entries) >= loaded.authority.ceilings.maxConcurrency) {
        throw new Error("lab campaign concurrency ceiling is exhausted");
      }
      if (claims.some((claim) => claim.metadata.id === capability.metadata.id)) {
        throw new Error(`lab campaign job capability was already consumed: ${capability.campaign.jobId}`);
      }
      const last = lastRequestAt(entries);
      if (last) {
        waitMilliseconds = Math.max(
          0,
          Math.ceil(1000 / loaded.authority.ceilings.maxRatePerSecond) - (nowMilliseconds(options) - Date.parse(last))
        );
      }
      if (waitMilliseconds > 0) return;
      writeOrVerifyCapability(loaded.resolved, capability, paths);
      assertClaimBudget(loaded.authority, claims, capability);
      claimCapability(loaded.resolved, capability);
      appendEntry(loaded.resolved, "capability-issued", {
        capabilityId: capability.metadata.id,
        capabilitySha256: capability.capabilitySha256,
        jobId,
        jobSha256: job.jobSha256
      }, options, loaded);
      appendEntry(loaded.resolved, "request-started", {
        capabilityId: capability.metadata.id,
        capabilitySha256: capability.capabilitySha256,
        jobId,
        method: capability.request.method,
        urlSha256: bytesSha256(Buffer.from(capability.request.url)),
        destinationIpSha256: bytesSha256(Buffer.from(capability.request.allowedIp))
      }, options, loaded);
    });
    if (waitMilliseconds === 0) break;
    if (typeof options.wait === "function") await options.wait(waitMilliseconds);
    else await new Promise((resolve) => setTimeout(resolve, waitMilliseconds));
  }
  const defaultBroker = !options.createManagedExecutionManifest || !options.executeExecutionManifest
    ? await import("./executions.mjs")
    : null;
  const createManifest = options.createManagedExecutionManifest || defaultBroker.createManagedExecutionManifest;
  const executeManifest = options.executeExecutionManifest || defaultBroker.executeExecutionManifest;
  let manifest = null;
  try {
    manifest = createManifest(job.job.engagementId, {
      ...jobAdapterInput(job),
      labCampaignCapability: structuredClone(capability)
    }, { ...options, paths });
    if (!manifestMatchesCapability(manifest, loaded.authority, capability, prepared, options)) {
      try {
        if (manifest?.workflow?.reservationId) {
          (options.cancelWorkflowExecution || cancelWorkflowExecution)(manifest.workflow.instanceId, {
            reservationId: manifest.workflow.reservationId,
            reason: "Lab campaign manifest differed from its single-use job capability."
          }, { paths });
        }
      } catch { /* The mismatch remains authoritative and visible. */ }
      throw new Error("execution broker manifest differs from the single-use lab job capability");
    }
    if (nowMilliseconds(options) >= Date.parse(loaded.authority.metadata.expiresAt)) {
      try {
        (options.cancelWorkflowExecution || cancelWorkflowExecution)(manifest.workflow.instanceId, {
          reservationId: manifest.workflow.reservationId,
          reason: "Lab campaign authority expired before execution."
        }, { paths });
      } catch { /* The expired authority remains authoritative. */ }
      throw new Error("lab campaign authority expired before execution");
    }
    withLock(loaded.resolved, () => {
      appendEntry(loaded.resolved, "manifest-bound", {
        capabilityId: capability.metadata.id,
        manifestId: manifest.manifestId,
        manifestSha256: manifest.manifestSha256,
        confirmationSha256: bytesSha256(Buffer.from(manifest.confirmationRequired))
      }, options, loaded);
    });
    const result = await executeManifest(job.job.engagementId, {
      manifestId: manifest.manifestId,
      confirm: manifest.confirmationRequired
    }, { ...options, paths });
    const adapterMetrics = checkedAdapterMetrics(result, prepared);
    const evidenceBytes = resultEvidenceBytes(result, paths, capability.bounds.maxEvidenceBytes);
    if (evidenceBytes > capability.bounds.maxEvidenceBytes) throw new Error("execution evidence exceeded the single-use capability bound");
    const metrics = {
      wallMilliseconds: Number.isSafeInteger(result.durationMs) ? result.durationMs : 0,
      requests: 1,
      inputTokens: 0,
      outputTokens: 0,
      totalTokens: 0,
      spend: 0,
      evidenceBytes,
      method: adapterMetrics.method,
      statusCode: adapterMetrics.statusCode,
      responseBodyBytes: adapterMetrics.responseBodyBytes,
      responseContentLength: adapterMetrics.responseContentLength,
      rateLimitPerSecond: adapterMetrics.rateLimitPerSecond,
      redirectsFollowed: adapterMetrics.redirectsFollowed,
      redirectStatus: adapterMetrics.redirectStatus,
      retries: adapterMetrics.retries,
      backoffStatus: adapterMetrics.backoffStatus,
      evidenceIntegrity: "verified",
      recoveryStatus: "not-required"
    };
    const stop = stopForResult(result);
    withLock(loaded.resolved, () => {
      // Persist a required stop before the terminal result. A crash between
      // these records may require reconciliation, but cannot allow a later
      // request to continue after a redirect, backoff, or instability stop.
      if (stop) appendEntry(loaded.resolved, "authority-stopped", { condition: stop, jobId, runId: result.runId }, options, loaded);
      appendEntry(loaded.resolved, "request-completed", {
        capabilityId: capability.metadata.id,
        jobId,
        manifestId: manifest.manifestId,
        runId: result.runId,
        status: result.status,
        metrics
      }, options, loaded);
    });
    return {
      ok: result.ok === true && !stop,
      status: stop ? "blocked" : result.status,
      authorityId: loaded.authority.metadata.id,
      capabilityId: capability.metadata.id,
      campaignId: loaded.authority.campaign.id,
      jobId,
      manifestId: manifest.manifestId,
      runId: result.runId,
      metrics,
      stopCondition: stop
    };
  } catch (error) {
    withLock(loaded.resolved, () => {
      const entries = readBoundJournal(loaded);
      if (!entries.some((entry) => entry.type === "authority-stopped")) {
        appendEntry(loaded.resolved, "authority-stopped", {
          condition: error.labStopCondition || "execution-ambiguity",
          jobId,
          runId: null
        }, options, loaded);
      }
      if (!entries.some((entry) => new Set(["request-completed", "request-failed"]).has(entry.type) &&
          entry.payload.capabilityId === capability.metadata.id)) {
        appendEntry(loaded.resolved, "request-failed", {
          capabilityId: capability.metadata.id,
          jobId,
          manifestId: manifest?.manifestId || null,
          reason: safeError(error)
        }, options, loaded);
      }
    });
    throw error;
  }
}

export function labCampaignAuthorityStatus(authorityId, options = {}) {
  const paths = options.paths || runtimePaths(options);
  const loaded = loadAuthority(paths, exactId(authorityId, "lab campaign authority id"));
  const entries = readBoundJournal(loaded);
  const claims = readClaims(loaded.resolved, paths);
  const completed = entries.filter((entry) => entry.type === "request-completed");
  const authorizedJobs = new Map();
  const enqueuedJobs = new Map();
  for (const entry of entries) {
    if (!new Set(["dynamic-job-authorized", "dynamic-job-enqueued"]).has(entry.type)) continue;
    const target = entry.type === "dynamic-job-authorized" ? authorizedJobs : enqueuedJobs;
    const prior = target.get(entry.payload.jobId);
    if (prior) throw new Error(`lab campaign journal repeats ${entry.type}: ${entry.payload.jobId}`);
    target.set(entry.payload.jobId, entry.payload);
  }
  for (const [jobId, payload] of enqueuedJobs) {
    const intent = authorizedJobs.get(jobId);
    if (!intent || !sameValue(intent, payload)) {
      throw new Error(`lab campaign committed dynamic job differs from its durable authority intent: ${jobId}`);
    }
  }
  const pendingJobs = [...authorizedJobs.keys()].filter((jobId) => !enqueuedJobs.has(jobId));
  const stopped = entries.filter((entry) => entry.type === "authority-stopped").at(-1) || null;
  const ambiguous = claims.filter((claim) => !entries.some((entry) =>
    new Set(["request-completed", "request-failed"]).has(entry.type) && entry.payload.capabilityId === claim.metadata.id
  ));
  const expired = nowMilliseconds(options) >= Date.parse(loaded.authority.metadata.expiresAt);
  const incompleteMetrics = entries.some((entry) => entry.type === "request-started" &&
    !completed.some((completion) => completion.payload.capabilityId === entry.payload.capabilityId));
  return {
    authorityId: loaded.authority.metadata.id,
    campaignId: loaded.authority.campaign.id,
    status: stopped ? "stopped" : ambiguous.length ? "recovery-required" : expired ? "expired" : loaded.receipt ? "authorized" : "proposed",
    confirmed: Boolean(loaded.receipt),
    expiresAt: loaded.authority.metadata.expiresAt,
    stopConfirmationRequired: loaded.receipt ? exactStopConfirmation(loaded.authority) : null,
    recoveryConfirmationRequired: ambiguous.length ? exactRecoveryConfirmation(loaded.authority) : null,
    journal: { sequence: entries.length, headSha256: entries.at(-1)?.entrySha256 || ZERO_SHA256 },
    jobs: {
      total: loaded.authority.campaign.jobs.length + enqueuedJobs.size,
      initial: loaded.authority.campaign.jobs.length,
      dynamic: enqueuedJobs.size,
      pending: pendingJobs.length,
      claimed: claims.length,
      completed: completed.length,
      ambiguous: ambiguous.length
    },
    usage: completed.reduce((total, entry) => ({
      precision: total.precision,
      requests: total.requests + entry.payload.metrics.requests,
      wallMilliseconds: total.wallMilliseconds + entry.payload.metrics.wallMilliseconds,
      evidenceBytes: total.evidenceBytes + entry.payload.metrics.evidenceBytes,
      totalTokens: total.totalTokens + entry.payload.metrics.totalTokens,
      spend: total.spend + entry.payload.metrics.spend
    }), { precision: incompleteMetrics ? "lower-bound" : "exact", requests: 0, wallMilliseconds: 0, evidenceBytes: 0, totalTokens: 0, spend: 0 }),
    stop: stopped?.payload || null
  };
}

export const labCampaignAuthorityInternals = Object.freeze({
  LAB_STOPS,
  authorityDigest,
  authorityPaths,
  canonicalSha256,
  capabilityDigest,
  enqueuePermitDigest,
  exactConfirmation,
  exactRecoveryConfirmation,
  exactStopConfirmation,
  grantDigest,
  jobDigest,
  receiptDigest
});
