import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";

import {
  bountyProfileInternals,
  showProgramProfile,
  verifyProgramProfile
} from "./bounty-profiles.mjs";
import { assertCaseScope } from "./case-scope.mjs";
import { recordEvent } from "./events.mjs";
import { appendJsonLine } from "./jsonl.mjs";
import { loadManagedAdapterRegistry } from "./managed-adapters.mjs";
import { ensureRuntime, runtimePaths } from "./paths.mjs";
import { readCurrentProgramSource } from "./program-sources.mjs";
import {
  readPrivateFileBounded,
  securePrivateDirectory,
  securePrivateFile,
  syncPrivateDirectory,
  writePrivateFileAtomic,
  writePrivateFileExclusive
} from "./private-fs.mjs";
import { assertValidDocument } from "./schema.mjs";
import { oneLine } from "./text.mjs";

const CAMPAIGN_ID = /^[a-z][a-z0-9-]{1,62}$/u;
const SOURCE_ID = CAMPAIGN_ID;
const SHA256 = /^[a-f0-9]{64}$/u;
const MAX_GRANT_BYTES = 2 * 1024 * 1024;
const MAX_JOB_BYTES = 2 * 1024 * 1024;
const MAX_STATE_BYTES = 32 * 1024 * 1024;
const MAX_JOURNAL_BYTES = 64 * 1024 * 1024;
const MAX_JOURNAL_ENTRIES = 100_000;
const MAX_JOBS = 10_000;
const ZERO_SHA256 = "0".repeat(64);

const GRANT_SCHEMA = "https://gate.local/schemas/campaign-grant.schema.json";
const JOB_SCHEMA = "https://gate.local/schemas/campaign-job.schema.json";
const STATE_SCHEMA = "https://gate.local/schemas/campaign-state.schema.json";

const STOP_CONDITIONS = Object.freeze([
  "operator-stop",
  "campaign-expiry",
  "case-binding-change",
  "program-profile-change",
  "source-binding-change",
  "engagement-invalid",
  "scope-mismatch",
  "adapter-contract-change",
  "budget-exhausted",
  "evidence-integrity-failure",
  "unexpected-sensitive-data",
  "target-instability",
  "execution-ambiguity",
  "execution-blocked",
  "controller-recovery-required"
]);

const CAPABILITY_REASON =
  "Managed adapter dispatch is available only through the campaign worker or run-next integration with an exact confirmed dedicated-lab authority. The generic controller path never dispatches target contact.";
const RECOVERY_REQUEUE_REASON = "Recovery safely requeued an interrupted non-contact dry-run.";
const RECOVERY_BLOCK_REASON = "Recovery cannot infer the result of a target-contact operation.";
const RECOVERY_TAIL_STOP_REASON =
  "Recovery quarantined an ambiguous final journal fragment; scheduling remains stopped.";
const RECOVERABLE_BINDING_BLOCKS = Object.freeze(new Set([
  "case-binding-change",
  "program-profile-change",
  "source-binding-change",
  "adapter-contract-change",
  "controller-recovery-required"
]));

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
}

function canonicalText(value) {
  return `${JSON.stringify(stableValue(value), null, 2)}\n`;
}

function canonicalSha256(value, domain) {
  return crypto.createHash("sha256").update(`${domain}\0`, "utf8").update(canonicalText(value), "utf8").digest("hex");
}

function digestWithout(value, field, domain) {
  const envelope = structuredClone(value);
  delete envelope[field];
  return canonicalSha256(envelope, domain);
}

function campaignId(value) {
  const id = String(value || "");
  if (!CAMPAIGN_ID.test(id)) {
    throw new Error("campaign id must start with a letter and contain only lowercase letters, numbers, or dashes");
  }
  return id;
}

function exactInstant(value, label) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new Error(`${label} must be a valid instant`);
  return date.toISOString();
}

function nowInstant(options = {}) {
  const raw = typeof options.now === "function" ? options.now() : options.now || Date.now();
  return exactInstant(raw, "campaign time");
}

function currentTimeMilliseconds(options = {}) {
  return Date.parse(nowInstant(options));
}

function campaignPaths(paths, id = null) {
  if (!paths.caseId || !paths.caseScope || !paths.caseBinding) {
    throw new Error("campaigns require an explicitly selected case runtime");
  }
  const root = path.join(paths.stateHome, "campaigns");
  if (id === null) return { root };
  const cleanId = campaignId(id);
  const directory = path.join(root, cleanId);
  return {
    root,
    directory,
    grant: path.join(directory, "grant.json"),
    jobs: path.join(directory, "jobs"),
    journal: path.join(directory, "journal.jsonl"),
    state: path.join(directory, "state.json"),
    lock: path.join(directory, ".campaign.lock"),
    worker: path.join(directory, "worker.json"),
    workerLease: path.join(directory, ".worker.serialization")
  };
}

function ensureCampaignRoot(paths) {
  ensureRuntime(paths);
  const resolved = campaignPaths(paths);
  securePrivateDirectory(resolved.root, { label: "private campaign root" });
  return resolved.root;
}

function parsePrivateJson(file, maximumBytes, label) {
  let value;
  try {
    value = JSON.parse(readPrivateFileBounded(file, maximumBytes, "utf8", { label }));
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error(`${label} is not valid JSON`, { cause: error });
    throw error;
  }
  return value;
}

function entryExists(file) {
  try {
    fs.lstatSync(file);
    return true;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

function readCurrentCase(paths) {
  securePrivateFile(paths.caseScope, { allowMissing: false, label: `private case scope ${paths.caseId}` });
  const value = parsePrivateJson(paths.caseScope, MAX_GRANT_BYTES, `private case scope ${paths.caseId}`);
  assertValidDocument(value, "case.schema.json", { paths });
  assertCaseScope(value, { expectedId: paths.caseId });
  return value;
}

function currentProfileContext(paths, caseRecord, options = {}) {
  if (typeof options.readCurrentProgramProfileBinding === "function") {
    const binding = options.readCurrentProgramProfileBinding(caseRecord.program.id, { paths });
    if (!binding || binding.id !== caseRecord.program.id || !SHA256.test(binding.profileSha256 || "") ||
        !Array.isArray(binding.sources)) {
      throw new Error("current program-profile binding reader returned an invalid binding");
    }
    return {
      binding: { id: binding.id, profileSha256: binding.profileSha256 },
      sources: structuredClone(binding.sources)
    };
  }
  const verification = verifyProgramProfile(caseRecord.program.id, {
    paths,
    now: nowInstant(options)
  });
  if (!verification.ok || !verification.structuralValid || !verification.ready || !SHA256.test(verification.profileSha256 || "")) {
    throw new Error("current program profile is not ready");
  }
  const profile = showProgramProfile(caseRecord.program.id, { paths, format: "json" });
  if (profile?.metadata?.id !== caseRecord.program.id || !Array.isArray(profile.sources) ||
      bountyProfileInternals.canonicalSha256(profile) !== verification.profileSha256) {
    throw new Error("current program profile changed during verification");
  }
  return {
    binding: { id: caseRecord.program.id, profileSha256: verification.profileSha256 },
    sources: structuredClone(profile.sources)
  };
}

export function campaignSourceBinding(snapshot, expectedProgramId = null, expectedSourceId = null) {
  if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) {
    throw new Error("campaign source snapshot must be an object");
  }
  const metadata = snapshot.metadata;
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    throw new Error("campaign source snapshot metadata is unavailable");
  }
  const programId = String(metadata.programId || "");
  const id = String(metadata.sourceId || "");
  if (!CAMPAIGN_ID.test(programId)) throw new Error("campaign source program id is invalid");
  if (!SOURCE_ID.test(id)) throw new Error("campaign source id is invalid");
  if (expectedProgramId !== null && programId !== expectedProgramId) {
    throw new Error("campaign source belongs to a different program profile");
  }
  if (expectedSourceId !== null && id !== expectedSourceId) {
    throw new Error("campaign source id changed during resolution");
  }
  for (const field of ["contentSha256", "projectionSha256", "snapshotSha256"]) {
    if (!SHA256.test(metadata[field] || "")) throw new Error(`campaign source ${field} is invalid`);
  }
  return {
    id,
    contentSha256: metadata.contentSha256,
    projectionSha256: metadata.projectionSha256,
    snapshotSha256: metadata.snapshotSha256
  };
}

function expectedSourceBinding(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("campaign creation requires an exact expected source binding");
  }
  exactKeys(
    value,
    ["id", "contentSha256", "projectionSha256", "snapshotSha256"],
    "campaign expected source binding"
  );
  const result = {
    id: String(value.id || ""),
    contentSha256: String(value.contentSha256 || ""),
    projectionSha256: String(value.projectionSha256 || ""),
    snapshotSha256: String(value.snapshotSha256 || "")
  };
  if (!SOURCE_ID.test(result.id)) throw new Error("campaign source id is invalid");
  for (const field of ["contentSha256", "projectionSha256", "snapshotSha256"]) {
    if (!SHA256.test(result[field])) throw new Error(`campaign expected source ${field} is invalid`);
  }
  return result;
}

function resolveSourceBinding(paths, programId, expected, options = {}) {
  const wanted = expectedSourceBinding(expected);
  const readCurrent = options.readCurrentProgramSource || readCurrentProgramSource;
  const registryPaths = runtimePaths({ home: paths.home, repo: paths.repo });
  const snapshot = readCurrent(programId, wanted.id, { paths: registryPaths });
  assertValidDocument(snapshot, "program-source-snapshot.schema.json", { paths: registryPaths });
  const observed = campaignSourceBinding(snapshot, programId, wanted.id);
  if (!sameValue(observed, wanted)) {
    const error = new Error("current program source does not match the exact expected source binding");
    error.code = "SOURCE_BINDING_CHANGED";
    throw error;
  }
  return observed;
}

function sameValue(left, right) {
  return canonicalText(left) === canonicalText(right);
}

function operationTuple(value) {
  return `${value.adapterId}\0${value.action}\0${value.toolId}`;
}

function normalizeAllowedOperations(value, paths) {
  if (!Array.isArray(value)) throw new Error("campaign operations must be an array");
  if (value.length > 64) throw new Error("campaign operations must contain 64 entries or fewer");
  const registry = value.length > 0 ? loadManagedAdapterRegistry({ paths }) : null;
  const result = value.map((item) => ({
    adapterId: String(item?.adapterId || ""),
    action: String(item?.action || ""),
    toolId: String(item?.toolId || "")
  }));
  for (const operation of result) {
    const adapter = registry.adapters.get(operation.adapterId);
    if (!adapter || adapter.action !== operation.action || adapter.tool.id !== operation.toolId) {
      throw new Error(`campaign operation is not one exact current managed adapter tuple: ${operation.adapterId}`);
    }
  }
  if (new Set(result.map(operationTuple)).size !== result.length) {
    throw new Error("campaign operations must be unique");
  }
  return {
    operations: result.sort((left, right) => operationTuple(left).localeCompare(operationTuple(right))),
    adapterRegistrySha256: registry?.registrySha256 || null
  };
}

function normalizeSelectors(value) {
  if (!Array.isArray(value)) throw new Error("campaign selectors must be an array");
  if (value.length > 256) throw new Error("campaign selectors must contain 256 entries or fewer");
  const selectors = value.map((item) => ({ type: String(item?.type || ""), value: String(item?.value || "") }));
  const keys = selectors.map((selector) => canonicalText(selector));
  if (new Set(keys).size !== keys.length) throw new Error("campaign selectors must be unique");
  return selectors;
}

function normalizeCeilings(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("campaign ceilings must be an object");
  }
  return {
    maxWallMinutes: Number(value.maxWallMinutes),
    maxRequests: Number(value.maxRequests),
    maxRatePerSecond: Number(value.maxRatePerSecond),
    maxConcurrency: Number(value.maxConcurrency),
    maxInputTokens: Number(value.maxInputTokens),
    maxOutputTokens: Number(value.maxOutputTokens),
    maxTotalTokens: Number(value.maxTotalTokens),
    maxSpend: Number(value.maxSpend),
    maxEvidenceBytes: Number(value.maxEvidenceBytes)
  };
}

function exactSha256(value, label) {
  const digest = String(value || "");
  if (!SHA256.test(digest)) throw new Error(`${label} must be a SHA-256 digest`);
  return digest;
}

function canonicalIp(value) {
  const raw = String(value || "");
  const version = net.isIP(raw);
  if (!version) throw new Error("lab enqueue frozenIps must contain literal IP addresses");
  if (version === 4) return raw;
  const canonical = new URL(`http://[${raw}]/`).hostname.slice(1, -1);
  if (canonical !== raw.toLowerCase()) throw new Error(`lab enqueue IPv6 address must be canonical: ${canonical}`);
  return canonical;
}

function canonicalOrigin(value) {
  let parsed;
  try { parsed = new URL(String(value || "")); }
  catch { throw new Error("lab enqueue origin must be a valid HTTP or HTTPS origin"); }
  if (!new Set(["http:", "https:"]).has(parsed.protocol) || parsed.username || parsed.password ||
      parsed.pathname !== "/" || parsed.search || parsed.hash || String(value) !== parsed.origin) {
    throw new Error(`lab enqueue origin must use its canonical form: ${parsed.origin}`);
  }
  return parsed.origin;
}

function canonicalPathPrefix(value, origin) {
  const raw = String(value || "");
  let parsed;
  try { parsed = new URL(raw, origin); }
  catch { throw new Error("lab enqueue pathPrefix is invalid"); }
  if (!raw.startsWith("/") || parsed.origin !== origin || parsed.search || parsed.hash || parsed.pathname !== raw) {
    throw new Error("lab enqueue pathPrefix must be one canonical absolute URL pathname");
  }
  return parsed.pathname;
}

function pathWithinPrefix(pathname, prefix) {
  if (prefix === "/") return true;
  const base = prefix.endsWith("/") ? prefix : `${prefix}/`;
  return pathname === prefix || pathname.startsWith(base);
}

function normalizePermitCeilings(value) {
  exactKeys(value, [
    "maxWallMinutes", "maxRequests", "maxRatePerSecond", "maxConcurrency",
    "maxInputTokens", "maxOutputTokens", "maxTotalTokens", "maxSpend", "maxEvidenceBytes"
  ], "lab enqueue permit ceilings");
  const ceilings = normalizeCeilings(value);
  for (const field of [
    "maxWallMinutes", "maxRequests", "maxConcurrency", "maxInputTokens", "maxOutputTokens",
    "maxTotalTokens", "maxEvidenceBytes"
  ]) {
    if (!Number.isSafeInteger(ceilings[field]) || ceilings[field] < (field === "maxWallMinutes" || field === "maxConcurrency" ? 1 : 0)) {
      throw new Error(`lab enqueue permit ceiling is invalid: ${field}`);
    }
  }
  for (const field of ["maxRatePerSecond", "maxSpend"]) {
    if (!Number.isFinite(ceilings[field]) || ceilings[field] < 0) {
      throw new Error(`lab enqueue permit ceiling is invalid: ${field}`);
    }
  }
  return ceilings;
}

function normalizeLabEnqueuePermit(value, grant, authorityId, at) {
  exactKeys(value, [
    "authorityId", "authoritySha256", "receiptSha256", "campaignId", "grantSha256", "origin",
    "pathPrefix", "frozenIps", "adapter", "workflow", "ceilings", "dynamic", "jobId", "jobSha256", "permitSha256"
  ], "verified lab enqueue permit");
  exactKeys(value.adapter, [
    "id", "action", "toolId", "registrySha256", "entrySha256", "compilerSourceSha256", "runtimeSha256"
  ], "lab enqueue permit adapter");
  exactKeys(value.workflow, [
    "instanceId", "phaseId", "phaseAttemptId", "admissionSha256", "authorityReceiptSha256"
  ], "lab enqueue permit workflow");
  exactKeys(value.dynamic, ["maxJobs", "allowedMethods", "maxResponseBytes", "maxTimeoutSeconds"], "lab enqueue permit dynamic bounds");
  const permit = structuredClone(value);
  if (permit.authorityId !== campaignId(authorityId) || permit.campaignId !== grant.metadata.id ||
      permit.grantSha256 !== grant.grantSha256) {
    throw new Error("lab enqueue permit campaign or authority binding changed");
  }
  for (const [field, digest] of [
    ["authoritySha256", permit.authoritySha256], ["receiptSha256", permit.receiptSha256],
    ["jobSha256", permit.jobSha256],
    ["adapter.registrySha256", permit.adapter.registrySha256], ["adapter.entrySha256", permit.adapter.entrySha256],
    ["adapter.compilerSourceSha256", permit.adapter.compilerSourceSha256], ["adapter.runtimeSha256", permit.adapter.runtimeSha256],
    ["workflow.admissionSha256", permit.workflow.admissionSha256],
    ["workflow.authorityReceiptSha256", permit.workflow.authorityReceiptSha256]
  ]) exactSha256(digest, `lab enqueue permit ${field}`);
  if (permit.adapter.id !== "httpx-url-fetch" || permit.adapter.action !== "observe" || permit.adapter.toolId !== "httpx" ||
      permit.adapter.registrySha256 !== grant.allow.adapterRegistrySha256) {
    throw new Error("lab enqueue permit does not retain the exact campaign httpx adapter tuple");
  }
  permit.origin = canonicalOrigin(permit.origin);
  permit.pathPrefix = canonicalPathPrefix(permit.pathPrefix, permit.origin);
  if (!Array.isArray(permit.frozenIps) || permit.frozenIps.length < 1 || permit.frozenIps.length > 32) {
    throw new Error("lab enqueue permit needs one to 32 frozen IP addresses");
  }
  permit.frozenIps = permit.frozenIps.map(canonicalIp);
  if (new Set(permit.frozenIps).size !== permit.frozenIps.length) throw new Error("lab enqueue permit frozen IPs must be unique");
  if (!CAMPAIGN_ID.test(permit.workflow.instanceId || "") || permit.workflow.phaseId !== "active-surface-validation" ||
      !/^wpa_[a-f0-9]{32}$/u.test(permit.workflow.phaseAttemptId || "")) {
    throw new Error("lab enqueue permit workflow binding is invalid");
  }
  permit.ceilings = normalizePermitCeilings(permit.ceilings);
  for (const field of Object.keys(permit.ceilings)) {
    if (permit.ceilings[field] > grant.ceilings[field]) {
      throw new Error(`lab enqueue permit exceeds the campaign grant ceiling: ${field}`);
    }
  }
  if (!Number.isSafeInteger(permit.dynamic.maxJobs) || permit.dynamic.maxJobs < 1 || permit.dynamic.maxJobs > MAX_JOBS ||
      !Number.isSafeInteger(permit.dynamic.maxResponseBytes) || permit.dynamic.maxResponseBytes < 1024 || permit.dynamic.maxResponseBytes > 131_072 ||
      !Number.isSafeInteger(permit.dynamic.maxTimeoutSeconds) || permit.dynamic.maxTimeoutSeconds < 1 || permit.dynamic.maxTimeoutSeconds > 15 ||
      !Array.isArray(permit.dynamic.allowedMethods) || permit.dynamic.allowedMethods.length < 1 ||
      permit.dynamic.allowedMethods.some((method) => !new Set(["GET", "HEAD"]).has(method)) ||
      new Set(permit.dynamic.allowedMethods).size !== permit.dynamic.allowedMethods.length) {
    throw new Error("lab enqueue permit dynamic bounds are invalid");
  }
  const expectedPermitSha256 = digestWithout(permit, "permitSha256", "gate.lab-campaign-enqueue-permit.v1");
  if (permit.permitSha256 !== expectedPermitSha256) throw new Error("lab enqueue permit digest changed");
  if (Date.parse(at) >= Date.parse(grant.metadata.expiresAt)) throw new Error("campaign grant expired before lab enqueue");
  return permit;
}

function assertLabJobMatchesPermit(job, permit, grant) {
  const value = job.job;
  if (permit.jobId !== job.metadata.id || permit.jobSha256 !== job.jobSha256) {
    throw new Error("lab enqueue permit names a different immutable job");
  }
  if (value.type !== "managed-adapter" || value.adapter.id !== permit.adapter.id ||
      value.adapter.action !== permit.adapter.action || value.adapter.toolId !== permit.adapter.toolId) {
    throw new Error("lab enqueue job must use the permitted httpx adapter tuple");
  }
  if (value.workflow.instanceId !== permit.workflow.instanceId || value.workflow.phaseAttemptId !== permit.workflow.phaseAttemptId) {
    throw new Error("lab enqueue job workflow binding changed");
  }
  if (value.selector.type !== "url") throw new Error("lab enqueue job requires one exact URL selector");
  let url;
  try { url = new URL(value.selector.value); }
  catch { throw new Error("lab enqueue job URL is invalid"); }
  if (url.href !== value.selector.value || url.origin !== permit.origin || url.username || url.password || url.hash ||
      !pathWithinPrefix(url.pathname, permit.pathPrefix)) {
    throw new Error("lab enqueue job leaves the exact origin or path prefix");
  }
  exactKeys(value.operation, ["kind", "method", "allowedIp", "timeoutSeconds", "maxResponseBytes"], "lab enqueue HTTP operation");
  if (value.operation.kind !== "http-fetch" || !permit.dynamic.allowedMethods.includes(value.operation.method) ||
      canonicalIp(value.operation.allowedIp) !== value.operation.allowedIp || !permit.frozenIps.includes(value.operation.allowedIp) ||
      !Number.isSafeInteger(value.operation.timeoutSeconds) || value.operation.timeoutSeconds < 1 ||
      value.operation.timeoutSeconds > permit.dynamic.maxTimeoutSeconds ||
      !Number.isSafeInteger(value.operation.maxResponseBytes) || value.operation.maxResponseBytes < 1024 ||
      value.operation.maxResponseBytes > permit.dynamic.maxResponseBytes) {
    throw new Error("lab enqueue job HTTP operation exceeds its verified permit");
  }
  if (value.bounds.estimatedRequests !== 1 || value.bounds.maxParallel !== 1 || value.bounds.maxMinutes > 5 ||
      value.bounds.maxRatePerSecond > 2 || value.operation.timeoutSeconds > value.bounds.maxMinutes * 60) {
    throw new Error("lab enqueue job bounds exceed the fixed exact-URL adapter contract");
  }
  managedJobWithinGrant(value, grant, { allowVerifiedLabSelector: true });
}

function labPermitContract(permit) {
  const contract = structuredClone(permit);
  delete contract.jobId;
  delete contract.jobSha256;
  delete contract.permitSha256;
  return contract;
}

function normalizeStopConditions(value = STOP_CONDITIONS) {
  if (!Array.isArray(value)) throw new Error("campaign stopConditions must be an array");
  const result = [...new Set(value.map(String))].sort();
  const missing = STOP_CONDITIONS.filter((condition) => !result.includes(condition));
  if (missing.length > 0) throw new Error(`campaign grant is missing mandatory stop conditions: ${missing.join(", ")}`);
  return result;
}

function grantDigest(grant) {
  return digestWithout(grant, "grantSha256", "gate.campaign-grant.v1");
}

function jobDigest(job) {
  return digestWithout(job, "jobSha256", "gate.campaign-job.v1");
}

function assertGrant(grant, paths) {
  if (Buffer.byteLength(canonicalText(grant), "utf8") > MAX_GRANT_BYTES) {
    throw new Error("campaign grant exceeds its byte limit");
  }
  assertValidDocument(grant, "campaign-grant.schema.json", { paths });
  if (grant.grantSha256 !== grantDigest(grant)) throw new Error("campaign grant digest changed");
  normalizeStopConditions(grant.stopConditions);
  return grant;
}

function assertJob(job, grant, paths) {
  if (Buffer.byteLength(canonicalText(job), "utf8") > MAX_JOB_BYTES) {
    throw new Error(`campaign job exceeds its byte limit: ${job?.metadata?.id || "unknown"}`);
  }
  assertValidDocument(job, "campaign-job.schema.json", { paths });
  if (job.campaignId !== grant.metadata.id || job.grantSha256 !== grant.grantSha256) {
    throw new Error(`campaign job ${job.metadata.id} belongs to a different grant`);
  }
  if (job.jobSha256 !== jobDigest(job)) throw new Error(`campaign job digest changed: ${job.metadata.id}`);
  return job;
}

function containsExecutionTextSurface(value, key = "operation") {
  if (!value || typeof value !== "object") return false;
  if (Array.isArray(value)) return value.some((item) => containsExecutionTextSurface(item, key));
  const forbidden = new Set(["argv", "args", "command", "cmd", "executable", "script", "shell", "stdin"]);
  return Object.entries(value).some(([name, child]) =>
    forbidden.has(name.toLowerCase()) || containsExecutionTextSurface(child, `${key}.${name}`)
  );
}

function selectorAllowed(grant, selector) {
  return grant.allow.selectors.some((allowed) => sameValue(allowed, selector));
}

function managedJobWithinGrant(job, grant, options = {}) {
  if (!grant.binding.engagement || job.engagementId !== grant.binding.engagement.id) {
    throw new Error("managed campaign job does not match the grant engagement");
  }
  const tuple = { adapterId: job.adapter.id, action: job.adapter.action, toolId: job.adapter.toolId };
  if (!grant.allow.operations.some((allowed) => operationTuple(allowed) === operationTuple(tuple))) {
    throw new Error("managed campaign job is outside the exact adapter/action/tool grant");
  }
  if (!selectorAllowed(grant, job.selector) && options.allowVerifiedLabSelector !== true) {
    throw new Error("managed campaign job selector is not an exact allowed selector");
  }
  if (containsExecutionTextSurface(job.operation)) {
    throw new Error("managed campaign job operation contains a command, argv, shell, script, or executable surface");
  }
  const limits = grant.ceilings;
  const bounds = job.bounds;
  for (const [field, ceiling] of [
    ["maxMinutes", limits.maxWallMinutes],
    ["estimatedRequests", limits.maxRequests],
    ["maxParallel", limits.maxConcurrency],
    ["maxRatePerSecond", limits.maxRatePerSecond],
    ["maxTokens", limits.maxTotalTokens],
    ["maxSpend", limits.maxSpend],
    ["maxEvidenceBytes", limits.maxEvidenceBytes]
  ]) {
    if (bounds[field] > ceiling) throw new Error(`managed campaign job ${field} exceeds the campaign ceiling`);
  }
}

function normalizeJob(input, grant, at, paths, options = {}) {
  const id = campaignId(input?.id);
  let job;
  if (input?.type === "non-contact-dry-run") {
    job = {
      type: "non-contact-dry-run",
      summary: oneLine(input.summary, { name: `campaign job ${id} summary`, max: 500 })
    };
  } else if (input?.type === "managed-adapter") {
    job = {
      type: "managed-adapter",
      engagementId: String(input.engagementId || ""),
      workflow: structuredClone(input.workflow),
      adapter: structuredClone(input.adapter),
      selector: structuredClone(input.selector),
      operation: structuredClone(input.operation),
      bounds: structuredClone(input.bounds)
    };
    managedJobWithinGrant(job, grant, options);
  } else {
    throw new Error(`unsupported campaign job type: ${String(input?.type || "")}`);
  }
  const envelope = {
    $schema: JOB_SCHEMA,
    apiVersion: "gate.dev/campaign-job/v1",
    kind: "CampaignJob",
    metadata: { id, createdAt: at },
    campaignId: grant.metadata.id,
    grantSha256: grant.grantSha256,
    job,
    jobSha256: ZERO_SHA256
  };
  envelope.jobSha256 = jobDigest(envelope);
  assertJob(envelope, grant, paths);
  return envelope;
}

function assertAggregateJobCeilings(jobs, grant) {
  assertJobsFitCeilings(jobs, grant.ceilings, "campaign queued jobs");
}

function aggregateJobReservations(jobs) {
  const aggregate = {
    maxWallMinutes: 0,
    maxRequests: 0,
    maxTotalTokens: 0,
    maxSpend: 0,
    maxEvidenceBytes: 0
  };
  for (const envelope of jobs) {
    if (envelope.job.type !== "managed-adapter") continue;
    aggregate.maxWallMinutes += envelope.job.bounds.maxMinutes;
    aggregate.maxRequests += envelope.job.bounds.estimatedRequests;
    aggregate.maxTotalTokens += envelope.job.bounds.maxTokens;
    aggregate.maxSpend += envelope.job.bounds.maxSpend;
    aggregate.maxEvidenceBytes += envelope.job.bounds.maxEvidenceBytes;
  }
  return aggregate;
}

function assertJobsFitCeilings(jobs, ceilings, label) {
  const aggregate = aggregateJobReservations(jobs);
  for (const [field, used] of Object.entries(aggregate)) {
    if (used > ceilings[field]) {
      throw new Error(`${label} reserve ${used} ${field}, exceeding the ceiling of ${ceilings[field]}`);
    }
  }
}

function journalEntry(previous, type, payload, at) {
  const entry = {
    sequence: previous ? previous.sequence + 1 : 1,
    at,
    type,
    payload,
    previousEntrySha256: previous ? previous.entrySha256 : ZERO_SHA256,
    entrySha256: ZERO_SHA256
  };
  entry.entrySha256 = digestWithout(entry, "entrySha256", "gate.campaign-journal-entry.v1");
  return entry;
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (!sameValue(actual, wanted)) throw new Error(`${label} fields changed`);
}

function assertJournalEntry(entry, previous) {
  exactKeys(entry, ["sequence", "at", "type", "payload", "previousEntrySha256", "entrySha256"], "campaign journal entry");
  if (!Number.isSafeInteger(entry.sequence) || entry.sequence !== (previous ? previous.sequence + 1 : 1)) {
    throw new Error("campaign journal sequence changed");
  }
  const at = exactInstant(entry.at, "campaign journal time");
  if (previous && Date.parse(at) < Date.parse(previous.at)) {
    throw new Error("campaign journal time moved backwards");
  }
  if (typeof entry.type !== "string" || !/^[a-z]+(?:-[a-z]+)*$/u.test(entry.type)) {
    throw new Error("campaign journal event type is invalid");
  }
  if (!entry.payload || typeof entry.payload !== "object" || Array.isArray(entry.payload)) {
    throw new Error("campaign journal payload is invalid");
  }
  if (entry.previousEntrySha256 !== (previous ? previous.entrySha256 : ZERO_SHA256)) {
    throw new Error("campaign journal hash chain changed");
  }
  if (entry.entrySha256 !== digestWithout(entry, "entrySha256", "gate.campaign-journal-entry.v1")) {
    throw new Error("campaign journal entry digest changed");
  }
}

function parseJournalText(text) {
  if (!text.endsWith("\n")) throw new Error("campaign journal has an incomplete trailing record");
  const lines = text.split(/\r?\n/u).filter(Boolean);
  if (lines.length < 1) throw new Error("campaign journal is empty");
  if (lines.length > MAX_JOURNAL_ENTRIES) throw new Error("campaign journal exceeds its entry limit");
  const entries = [];
  for (const [index, line] of lines.entries()) {
    let entry;
    try { entry = JSON.parse(line); }
    catch (error) { throw new Error(`campaign journal entry ${index + 1} is not valid JSON`, { cause: error }); }
    assertJournalEntry(entry, entries.at(-1) || null);
    entries.push(entry);
  }
  return entries;
}

function readJournal(file) {
  const text = readPrivateFileBounded(file, MAX_JOURNAL_BYTES, "utf8", { label: "private campaign journal" });
  return parseJournalText(text);
}

function measurement(availability, value) {
  return { availability, value };
}

function emptyUsage() {
  return {
    reserved: {
      wallMinutes: 0,
      requests: 0,
      inputTokens: 0,
      outputTokens: 0,
      totalTokens: 0,
      spend: 0,
      evidenceBytes: 0
    },
    observed: {
      wallMinutes: measurement("exact", 0),
      requests: measurement("exact", 0),
      inputTokens: measurement("exact", 0),
      outputTokens: measurement("exact", 0),
      totalTokens: measurement("exact", 0),
      spend: measurement("exact", 0),
      evidenceBytes: measurement("exact", 0)
    }
  };
}

function invalidateContactUsage(state) {
  for (const key of ["requests", "wallMinutes", "evidenceBytes"]) {
    state.usage.observed[key] = measurement("unavailable", null);
  }
}

function initialUsage(jobs) {
  const usage = emptyUsage();
  for (const envelope of jobs) {
    if (envelope.job.type !== "managed-adapter") continue;
    usage.reserved.wallMinutes += envelope.job.bounds.maxMinutes;
    usage.reserved.requests += envelope.job.bounds.estimatedRequests;
    usage.reserved.totalTokens += envelope.job.bounds.maxTokens;
    usage.reserved.spend += envelope.job.bounds.maxSpend;
    usage.reserved.evidenceBytes += envelope.job.bounds.maxEvidenceBytes;
  }
  return usage;
}

function reserveJob(usage, envelope) {
  if (envelope.job.type !== "managed-adapter") return;
  usage.reserved.wallMinutes += envelope.job.bounds.maxMinutes;
  usage.reserved.requests += envelope.job.bounds.estimatedRequests;
  usage.reserved.totalTokens += envelope.job.bounds.maxTokens;
  usage.reserved.spend += envelope.job.bounds.maxSpend;
  usage.reserved.evidenceBytes += envelope.job.bounds.maxEvidenceBytes;
}

function queueCounts(jobs) {
  const counts = { total: jobs.length, queued: 0, running: 0, completed: 0, blocked: 0, failed: 0 };
  for (const job of jobs) counts[job.status] += 1;
  return counts;
}

function campaignKpis(jobs, recoveries = 0) {
  return {
    jobsAttempted: measurement("exact", jobs.reduce((total, job) => total + job.attempts, 0)),
    jobsCompleted: measurement("exact", jobs.filter((job) => job.status === "completed").length),
    hypotheses: measurement("unavailable", null),
    recoveries: measurement("exact", recoveries)
  };
}

function replay(entries, grant, jobs, paths) {
  let state = null;
  const definitions = new Map(jobs.map((job) => [job.metadata.id, job]));
  const labAuthorities = new Map();
  for (const entry of entries) {
    if (entry.type === "campaign-created") {
      if (state !== null || entry.sequence !== 1) throw new Error("campaign-created must be the first journal entry");
      exactKeys(entry.payload, ["grantSha256", "jobs"], "campaign-created payload");
      if (entry.payload.grantSha256 !== grant.grantSha256 || !Array.isArray(entry.payload.jobs)) {
        throw new Error("campaign-created binding changed");
      }
      const listed = entry.payload.jobs.map((item) => {
        exactKeys(item, ["id", "kind", "jobSha256"], "campaign-created job");
        const definition = definitions.get(item.id);
        if (!definition || definition.jobSha256 !== item.jobSha256 || definition.job.type !== item.kind) {
          throw new Error(`campaign-created job binding changed: ${item.id}`);
        }
        return {
          id: item.id,
          kind: item.kind,
          jobSha256: item.jobSha256,
          authority: null,
          status: "queued",
          attempts: 0,
          updatedAt: entry.at,
          reason: null
        };
      });
      if (new Set(listed.map((item) => item.id)).size !== listed.length) {
        throw new Error("campaign-created job set changed");
      }
      const initialDefinitions = listed.map((item) => definitions.get(item.id));
      state = {
        $schema: STATE_SCHEMA,
        apiVersion: "gate.dev/campaign-state/v1",
        kind: "CampaignState",
        campaignId: grant.metadata.id,
        grantSha256: grant.grantSha256,
        status: "paused",
        createdAt: entry.at,
        updatedAt: entry.at,
        journal: { sequence: entry.sequence, headSha256: entry.entrySha256 },
        jobs: listed,
        queue: queueCounts(listed),
        kpis: campaignKpis(listed),
        usage: initialUsage(initialDefinitions),
        stop: null,
        capability: {
          nonContactDryRun: "available",
          managedAdapterDispatch: "confirmed-dedicated-lab-only",
          reason: CAPABILITY_REASON
        }
      };
      continue;
    }
    if (!state) throw new Error("campaign journal does not begin with campaign-created");
    if (entry.type === "job-enqueued") {
      exactKeys(entry.payload, [
        "jobId", "jobSha256", "kind", "authorityId", "authoritySha256", "receiptSha256", "permitSha256", "permit"
      ], "job-enqueued payload");
      if (!new Set(["paused", "running", "completed"]).has(state.status)) {
        throw new Error(`campaign cannot enqueue a lab job from ${state.status}`);
      }
      const definition = definitions.get(entry.payload.jobId);
      if (!definition || definition.jobSha256 !== entry.payload.jobSha256 ||
          definition.job.type !== entry.payload.kind || definition.job.type !== "managed-adapter" ||
          definition.job.adapter.id !== "httpx-url-fetch" || definition.job.adapter.action !== "observe" ||
          definition.job.adapter.toolId !== "httpx" || state.jobs.some((job) => job.id === entry.payload.jobId)) {
        throw new Error(`campaign lab enqueue binding changed: ${entry.payload.jobId}`);
      }
      campaignId(entry.payload.authorityId);
      for (const field of ["authoritySha256", "receiptSha256", "permitSha256"]) {
        exactSha256(entry.payload[field], `campaign lab enqueue ${field}`);
      }
      const permit = normalizeLabEnqueuePermit(entry.payload.permit, grant, entry.payload.authorityId, entry.at);
      if (permit.jobId !== entry.payload.jobId || permit.jobSha256 !== entry.payload.jobSha256 ||
          permit.authoritySha256 !== entry.payload.authoritySha256 ||
          permit.receiptSha256 !== entry.payload.receiptSha256 ||
          permit.permitSha256 !== entry.payload.permitSha256) {
        throw new Error(`campaign lab enqueue permit binding changed: ${entry.payload.jobId}`);
      }
      assertLabJobMatchesPermit(definition, permit, grant);
      const contract = labPermitContract(permit);
      const existingAuthority = labAuthorities.get(permit.authorityId);
      if (existingAuthority && !sameValue(existingAuthority.contract, contract)) {
        throw new Error(`campaign lab authority contract changed: ${permit.authorityId}`);
      }
      const authorityJobs = existingAuthority?.jobs || [];
      const replayedJobs = [...state.jobs.map((job) => definitions.get(job.id)), definition];
      if (replayedJobs.length > permit.dynamic.maxJobs) {
        throw new Error("campaign lab enqueue exceeds its durable job-count ceiling");
      }
      assertJobsFitCeilings(replayedJobs, permit.ceilings, "durable lab campaign jobs");
      labAuthorities.set(permit.authorityId, { contract, jobs: [...authorityJobs, definition.metadata.id] });
      state.jobs.push({
        id: definition.metadata.id,
        kind: definition.job.type,
        jobSha256: definition.jobSha256,
        authority: {
          id: permit.authorityId,
          authoritySha256: permit.authoritySha256,
          receiptSha256: permit.receiptSha256,
          permitSha256: permit.permitSha256
        },
        status: "queued",
        attempts: 0,
        updatedAt: entry.at,
        reason: null
      });
      reserveJob(state.usage, definition);
      for (const [used, ceiling] of [
        [state.usage.reserved.wallMinutes, grant.ceilings.maxWallMinutes],
        [state.usage.reserved.requests, grant.ceilings.maxRequests],
        [state.usage.reserved.totalTokens, grant.ceilings.maxTotalTokens],
        [state.usage.reserved.spend, grant.ceilings.maxSpend],
        [state.usage.reserved.evidenceBytes, grant.ceilings.maxEvidenceBytes]
      ]) {
        if (used > ceiling) throw new Error("campaign enqueued reservations exceed the immutable grant ceiling");
      }
      if (state.status === "completed") state.status = "running";
      state.updatedAt = entry.at;
      state.journal = { sequence: entry.sequence, headSha256: entry.entrySha256 };
      state.queue = queueCounts(state.jobs);
      state.kpis = campaignKpis(state.jobs, state.kpis.recoveries.value);
      continue;
    }
    const completedRecoveryStop = state.status === "completed" &&
      entry.type === "campaign-stopped" &&
      entry.payload?.condition === "controller-recovery-required" &&
      entry.payload?.reason === RECOVERY_TAIL_STOP_REASON;
    if (new Set(["stopped", "completed"]).has(state.status) && !completedRecoveryStop) {
      throw new Error(`campaign journal cannot mutate terminal state ${state.status}`);
    }
    const mutableJob = (id) => {
      const job = state.jobs.find((candidate) => candidate.id === id);
      if (!job) throw new Error(`campaign journal names an unknown job: ${id}`);
      return job;
    };
    if (entry.type === "campaign-resumed") {
      exactKeys(entry.payload, [], "campaign-resumed payload");
      const recoverableBlock = state.status === "blocked" && state.queue.queued > 0 &&
        RECOVERABLE_BINDING_BLOCKS.has(state.stop?.condition);
      if (state.status !== "paused" && !recoverableBlock) throw new Error("campaign resume transition is invalid");
      state.status = "running";
      state.stop = null;
    } else if (entry.type === "campaign-paused") {
      exactKeys(entry.payload, [], "campaign-paused payload");
      if (state.status !== "running" || state.jobs.some((job) => job.status === "running")) {
        throw new Error("campaign pause transition is invalid");
      }
      state.status = "paused";
    } else if (entry.type === "campaign-blocked") {
      exactKeys(entry.payload, ["condition", "reason"], "campaign-blocked payload");
      if (state.status !== "running" || state.jobs.some((job) => job.status === "running") ||
          !grant.stopConditions.includes(entry.payload.condition)) {
        throw new Error("campaign block transition is invalid");
      }
      state.status = "blocked";
      state.stop = { ...entry.payload, at: entry.at };
    } else if (entry.type === "campaign-stopped") {
      exactKeys(entry.payload, ["condition", "reason"], "campaign-stopped payload");
      if ((!new Set(["paused", "running", "blocked"]).has(state.status) && !completedRecoveryStop) ||
          state.jobs.some((job) => job.status === "running") ||
          !grant.stopConditions.includes(entry.payload.condition)) {
        throw new Error("campaign stop transition is invalid");
      }
      state.status = "stopped";
      state.stop = { ...entry.payload, at: entry.at };
    } else if (entry.type === "campaign-completed") {
      exactKeys(entry.payload, [], "campaign-completed payload");
      if (state.status !== "running" || state.jobs.some((job) => new Set(["queued", "running"]).has(job.status))) {
        throw new Error("campaign cannot complete with unfinished jobs");
      }
      state.status = state.jobs.some((job) => new Set(["blocked", "failed"]).has(job.status)) ? "blocked" : "completed";
    } else if (entry.type === "campaign-recovered") {
      exactKeys(entry.payload, ["jobs"], "campaign-recovered payload");
      if (state.status !== "running" || !Array.isArray(entry.payload.jobs) || entry.payload.jobs.length === 0) {
        throw new Error("campaign recovery transition is invalid");
      }
      const recoveredIds = [];
      let blocked = false;
      for (const recovery of entry.payload.jobs) {
        exactKeys(recovery, ["jobId", "jobSha256", "disposition", "reason"], "campaign recovered job");
        const job = mutableJob(recovery.jobId);
        const definition = definitions.get(job.id);
        if (job.status !== "running" || job.jobSha256 !== recovery.jobSha256) {
          throw new Error(`campaign recovered job transition is invalid: ${job.id}`);
        }
        const expectedDisposition = definition.job.type === "non-contact-dry-run" ? "requeued" : "blocked";
        const expectedReason = expectedDisposition === "requeued" ? RECOVERY_REQUEUE_REASON : RECOVERY_BLOCK_REASON;
        if (recovery.disposition !== expectedDisposition || recovery.reason !== expectedReason) {
          throw new Error(`campaign recovered job disposition is invalid: ${job.id}`);
        }
        job.status = expectedDisposition === "requeued" ? "queued" : "blocked";
        job.updatedAt = entry.at;
        job.reason = recovery.reason;
        blocked ||= expectedDisposition === "blocked";
        recoveredIds.push(job.id);
      }
      if (new Set(recoveredIds).size !== recoveredIds.length ||
          state.jobs.some((job) => job.status === "running")) {
        throw new Error("campaign-recovered job set is incomplete or duplicated");
      }
      if (blocked) {
        invalidateContactUsage(state);
        state.status = "blocked";
        state.stop = {
          condition: "execution-ambiguity",
          reason: "A target-contact job had ambiguous state during recovery.",
          at: entry.at
        };
      }
      state.kpis.recoveries.value += 1;
    } else if (entry.type === "job-started") {
      exactKeys(entry.payload, ["jobId", "jobSha256", "authorityId"], "job-started payload");
      const job = mutableJob(entry.payload.jobId);
      if (job.jobSha256 !== entry.payload.jobSha256 || job.status !== "queued" || state.status !== "running") {
        throw new Error(`campaign job start transition is invalid: ${job.id}`);
      }
      if (entry.payload.authorityId !== null) campaignId(entry.payload.authorityId);
      if (definitions.get(job.id).job.type === "non-contact-dry-run" && entry.payload.authorityId !== null) {
        throw new Error(`non-contact campaign job cannot name execution authority: ${job.id}`);
      }
      if (job.authority && entry.payload.authorityId !== job.authority.id) {
        throw new Error(`campaign job start authority differs from its enqueue permit: ${job.id}`);
      }
      job.status = "running";
      job.attempts += 1;
      job.updatedAt = entry.at;
      job.reason = null;
    } else if (entry.type === "job-completed") {
      exactKeys(entry.payload, ["jobId", "jobSha256", "metrics"], "job-completed payload");
      const job = mutableJob(entry.payload.jobId);
      if (job.jobSha256 !== entry.payload.jobSha256 || job.status !== "running" || state.status !== "running") {
        throw new Error(`campaign job completion transition is invalid: ${job.id}`);
      }
      const metrics = entry.payload.metrics;
      exactKeys(metrics, ["wallMilliseconds", "requests", "inputTokens", "outputTokens", "totalTokens", "spend", "evidenceBytes"], "campaign job metrics");
      for (const [key, value] of Object.entries(metrics)) {
        if (typeof value !== "number" || !Number.isFinite(value) || value < 0) throw new Error(`campaign job metric is invalid: ${key}`);
      }
      for (const key of ["wallMilliseconds", "requests", "inputTokens", "outputTokens", "totalTokens", "evidenceBytes"]) {
        if (!Number.isSafeInteger(metrics[key])) throw new Error(`campaign job metric must be a safe integer: ${key}`);
      }
      if (metrics.totalTokens !== metrics.inputTokens + metrics.outputTokens) {
        throw new Error("campaign total-token metric does not equal input plus output tokens");
      }
      job.status = "completed";
      job.updatedAt = entry.at;
      if (state.usage.observed.wallMinutes.availability === "exact") state.usage.observed.wallMinutes.value += metrics.wallMilliseconds / 60_000;
      if (state.usage.observed.requests.availability === "exact") state.usage.observed.requests.value += metrics.requests;
      state.usage.observed.inputTokens.value += metrics.inputTokens;
      state.usage.observed.outputTokens.value += metrics.outputTokens;
      state.usage.observed.totalTokens.value += metrics.totalTokens;
      state.usage.observed.spend.value += metrics.spend;
      if (state.usage.observed.evidenceBytes.availability === "exact") state.usage.observed.evidenceBytes.value += metrics.evidenceBytes;
      for (const [used, ceiling] of [
        [state.usage.observed.wallMinutes.value, grant.ceilings.maxWallMinutes],
        [state.usage.observed.requests.value, grant.ceilings.maxRequests],
        [state.usage.observed.inputTokens.value, grant.ceilings.maxInputTokens],
        [state.usage.observed.outputTokens.value, grant.ceilings.maxOutputTokens],
        [state.usage.observed.totalTokens.value, grant.ceilings.maxTotalTokens],
        [state.usage.observed.spend.value, grant.ceilings.maxSpend],
        [state.usage.observed.evidenceBytes.value, grant.ceilings.maxEvidenceBytes]
      ]) {
        if (used > ceiling) throw new Error("campaign observed usage exceeds its immutable grant ceiling");
      }
    } else if (entry.type === "job-blocked" || entry.type === "job-failed") {
      exactKeys(entry.payload, ["jobId", "jobSha256", "reason"], `${entry.type} payload`);
      const job = mutableJob(entry.payload.jobId);
      if (job.jobSha256 !== entry.payload.jobSha256 || job.status !== "running" || state.status !== "running") {
        throw new Error(`campaign job terminal transition is invalid: ${job.id}`);
      }
      if (definitions.get(job.id).job.type === "managed-adapter") invalidateContactUsage(state);
      job.status = entry.type === "job-blocked" ? "blocked" : "failed";
      job.updatedAt = entry.at;
      job.reason = oneLine(entry.payload.reason, { name: `${entry.type} reason`, max: 500 });
    } else {
      throw new Error(`unsupported campaign journal event: ${entry.type}`);
    }
    state.updatedAt = entry.at;
    state.journal = { sequence: entry.sequence, headSha256: entry.entrySha256 };
    state.queue = queueCounts(state.jobs);
    state.kpis = campaignKpis(state.jobs, state.kpis.recoveries.value);
  }
  if (state.jobs.length !== definitions.size || state.jobs.some((job) => !definitions.has(job.id))) {
    throw new Error("campaign immutable job definitions do not match the journaled job set");
  }
  assertValidDocument(state, "campaign-state.schema.json", { paths });
  return state;
}

function jobFile(resolved, id) {
  return path.join(resolved.jobs, `${campaignId(id)}.json`);
}

function loadCampaignRecords(paths, id, resolved, entries) {
  const grant = assertGrant(parsePrivateJson(resolved.grant, MAX_GRANT_BYTES, `private campaign grant ${id}`), paths);
  if (grant.metadata.id !== campaignId(id)) throw new Error("campaign grant id does not match its directory");
  const created = entries[0];
  if (created.type !== "campaign-created" || !Array.isArray(created.payload?.jobs) || created.payload.jobs.length > MAX_JOBS) {
    throw new Error("campaign-created job index is invalid");
  }
  const indexedJobs = [
    ...created.payload.jobs,
    ...entries.filter((entry) => entry.type === "job-enqueued").map((entry) => ({
      id: entry.payload?.jobId,
      jobSha256: entry.payload?.jobSha256
    }))
  ];
  if (indexedJobs.length > MAX_JOBS || new Set(indexedJobs.map((item) => item.id)).size !== indexedJobs.length) {
    throw new Error("campaign journal job index is invalid or duplicated");
  }
  const jobs = indexedJobs.map((item) =>
    assertJob(parsePrivateJson(jobFile(resolved, item.id), MAX_JOB_BYTES, `private campaign job ${item.id}`), grant, paths)
  );
  const state = replay(entries, grant, jobs, paths);
  return { resolved, grant, jobs, entries, state };
}

function loadCampaign(paths, id) {
  ensureCampaignRoot(paths);
  const resolved = campaignPaths(paths, id);
  securePrivateDirectory(resolved.directory, { create: false, label: `private campaign ${resolved.directory}` });
  securePrivateDirectory(resolved.jobs, { create: false, label: `private campaign jobs ${resolved.directory}` });
  return loadCampaignRecords(paths, id, resolved, readJournal(resolved.journal));
}

function activeCampaignStart(bundle) {
  const running = bundle.state.jobs.filter((job) => job.status === "running");
  if (running.length === 0) return null;
  if (running.length !== 1) throw new Error("campaign projection contains more than one running job");
  const projected = running[0];
  const started = [...bundle.entries].reverse().find((entry) =>
    entry.type === "job-started" &&
    entry.payload.jobId === projected.id &&
    entry.payload.jobSha256 === projected.jobSha256
  );
  if (!started) throw new Error("running campaign job lacks its hash-validated start record");
  return {
    jobId: started.payload.jobId,
    jobSha256: started.payload.jobSha256,
    authorityId: started.payload.authorityId
  };
}

function interruptedJobRecoveries(bundle) {
  return bundle.state.jobs.filter((candidate) => candidate.status === "running").map((job) => {
    const definition = bundle.jobs.find((candidate) => candidate.metadata.id === job.id);
    const requeue = definition.job.type === "non-contact-dry-run";
    return {
      jobId: job.id,
      jobSha256: job.jobSha256,
      disposition: requeue ? "requeued" : "blocked",
      reason: requeue ? RECOVERY_REQUEUE_REASON : RECOVERY_BLOCK_REASON
    };
  });
}

function repairIncompleteJournalTail(paths, id, resolved, options = {}) {
  const bytes = readPrivateFileBounded(resolved.journal, MAX_JOURNAL_BYTES, null, {
    label: "private campaign journal"
  });
  if (bytes.length > 0 && bytes.at(-1) === 0x0a) {
    return { repaired: false, mode: null, recoveredJobs: [] };
  }
  const boundary = bytes.lastIndexOf(0x0a);
  const prefix = boundary < 0 ? Buffer.alloc(0) : bytes.subarray(0, boundary + 1);
  const tail = boundary < 0 ? bytes : bytes.subarray(boundary + 1);
  const entries = prefix.length === 0 ? [] : parseJournalText(prefix.toString("utf8"));

  // A complete, valid final record remains authoritative if only its line
  // delimiter was lost. Restore that delimiter rather than rolling it back.
  let candidate;
  let completeJson = false;
  try {
    candidate = JSON.parse(tail.toString("utf8"));
    completeJson = true;
  } catch { /* An unparseable final fragment is quarantined below. */ }
  if (completeJson) {
    try {
      assertJournalEntry(candidate, entries.at(-1) || null);
      const completeEntries = [...entries, candidate];
      if (completeEntries.length > MAX_JOURNAL_ENTRIES || bytes.length + 1 > MAX_JOURNAL_BYTES) {
        throw new Error("campaign journal final record exceeds its recovery limits");
      }
      loadCampaignRecords(paths, id, resolved, completeEntries);
    } catch (error) {
      throw new Error("campaign journal final record is complete but invalid and was preserved for review", {
        cause: error
      });
    }
    writePrivateFileAtomic(resolved.journal, Buffer.concat([bytes, Buffer.from("\n")]), {
      label: "repaired private campaign journal delimiter"
    });
    syncPrivateDirectory(resolved.directory, { label: "private campaign after journal delimiter repair" });
    return { repaired: true, mode: "delimiter-restored", recoveredJobs: [] };
  }

  if (entries.length === 0) throw new Error("campaign journal has no complete record to recover");
  let bundle = loadCampaignRecords(paths, id, resolved, entries);
  const recoveries = interruptedJobRecoveries(bundle);
  const repairedEntries = [...entries];
  if (recoveries.length > 0) {
    const recovered = journalEntry(
      repairedEntries.at(-1),
      "campaign-recovered",
      { jobs: recoveries },
      nowInstant(options)
    );
    assertJournalEntry(recovered, repairedEntries.at(-1));
    repairedEntries.push(recovered);
    bundle = loadCampaignRecords(paths, id, resolved, repairedEntries);
  }
  if (bundle.state.status !== "stopped") {
    const stopped = journalEntry(
      repairedEntries.at(-1),
      "campaign-stopped",
      {
        condition: "controller-recovery-required",
        reason: RECOVERY_TAIL_STOP_REASON
      },
      nowInstant(options)
    );
    assertJournalEntry(stopped, repairedEntries.at(-1));
    repairedEntries.push(stopped);
    bundle = loadCampaignRecords(paths, id, resolved, repairedEntries);
  }
  if (repairedEntries.length > MAX_JOURNAL_ENTRIES) {
    throw new Error("campaign journal reached its entry limit during recovery");
  }
  const recoveryBytes = Buffer.from(
    repairedEntries.slice(entries.length).map((entry) => `${JSON.stringify(entry)}\n`).join(""),
    "utf8"
  );
  const repairedBytes = Buffer.concat([prefix, recoveryBytes]);
  if (repairedBytes.length > MAX_JOURNAL_BYTES) {
    throw new Error("campaign journal reached its byte limit during recovery");
  }

  const quarantine = `${resolved.journal}.torn.${crypto.randomBytes(8).toString("hex")}.bin`;
  writePrivateFileExclusive(quarantine, tail, { label: "quarantined private campaign journal tail" });
  writePrivateFileAtomic(resolved.journal, repairedBytes, { label: "fail-closed private campaign journal repair" });
  syncPrivateDirectory(resolved.directory, { label: "private campaign after journal tail repair" });
  return {
    repaired: true,
    mode: "incomplete-tail-quarantined",
    recoveredJobs: recoveries.map((item) => item.jobId)
  };
}

function writeProjection(file, state, paths) {
  assertValidDocument(state, "campaign-state.schema.json", { paths });
  const bytes = canonicalText(state);
  if (Buffer.byteLength(bytes, "utf8") > MAX_STATE_BYTES) {
    throw new Error("campaign state projection exceeds its byte limit");
  }
  writePrivateFileAtomic(file, bytes, { encoding: "utf8", label: "private campaign state projection" });
}

function appendCampaignEntry(bundle, type, payload, options = {}) {
  if (bundle.entries.length >= MAX_JOURNAL_ENTRIES) {
    throw new Error("campaign journal reached its entry limit");
  }
  const entry = journalEntry(bundle.entries.at(-1) || null, type, payload, nowInstant(options));
  assertJournalEntry(entry, bundle.entries.at(-1) || null);
  const nextEntries = [...bundle.entries, entry];
  const nextState = replay(nextEntries, bundle.grant, bundle.jobs, options.paths);
  const encoded = `${JSON.stringify(entry)}\n`;
  const currentBytes = fs.statSync(bundle.resolved.journal, { bigint: true }).size;
  if (currentBytes + BigInt(Buffer.byteLength(encoded, "utf8")) > BigInt(MAX_JOURNAL_BYTES)) {
    throw new Error("campaign journal reached its byte limit");
  }
  appendJsonLine(bundle.resolved.journal, entry, 0o600, { sync: true });
  bundle.entries = nextEntries;
  bundle.state = nextState;
  writeProjection(bundle.resolved.state, bundle.state, options.paths);
  return entry;
}

function observeCampaignTransition(bundle, type, options = {}) {
  if (typeof options.onTransition !== "function") return;
  // This hook only observes an already-durable, schema-validated projection.
  // It has no influence over job selection, authorization, or dispatch. A
  // telemetry failure must not turn a committed journal transition into an
  // apparent controller failure, so observers own their own failure counter.
  try {
    options.onTransition(Object.freeze({
      type,
      state: structuredClone(bundle.state)
    }));
  } catch {
    // The append and projection are already durable. The worker's heartbeat
    // and pilot counters surface publication failures on its next cycle.
  }
}

function processIdentity() {
  if (process.platform !== "linux") throw new Error("campaign controller locking currently requires Linux");
  const stat = fs.readFileSync(`/proc/${process.pid}/stat`, "utf8");
  const close = stat.lastIndexOf(")");
  const fields = close === -1 ? [] : stat.slice(close + 2).trim().split(/\s+/u);
  const startTimeTicks = fields[19];
  const bootId = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim().toLowerCase();
  if (!/^\d+$/u.test(startTimeTicks || "") || !/^[a-f0-9-]{36}$/u.test(bootId)) {
    throw new Error("campaign controller process identity is unavailable");
  }
  return { pid: process.pid, startTimeTicks, bootId };
}

function validLockOwner(owner) {
  if (!owner || typeof owner !== "object" || Array.isArray(owner)) return false;
  try {
    exactKeys(owner, ["pid", "startTimeTicks", "bootId", "acquiredAt"], "campaign lock owner");
  } catch {
    return false;
  }
  return Number.isSafeInteger(owner.pid) && owner.pid > 0 && /^\d+$/u.test(owner.startTimeTicks || "") &&
    /^[a-f0-9-]{36}$/u.test(owner.bootId || "") &&
    Number.isFinite(Date.parse(owner.acquiredAt || "")) && exactInstant(owner.acquiredAt, "campaign lock acquisition") === owner.acquiredAt;
}

function lockOwnerStatus(owner) {
  if (!validLockOwner(owner) || process.platform !== "linux") return "unknown";
  let bootId;
  try {
    bootId = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim().toLowerCase();
  } catch {
    return "unknown";
  }
  if (!/^[a-f0-9-]{36}$/u.test(bootId)) return "unknown";
  if (bootId !== owner.bootId) return "dead";
  let stat;
  try {
    stat = fs.readFileSync(`/proc/${owner.pid}/stat`, "utf8");
  } catch (error) {
    return new Set(["ENOENT", "ESRCH"]).has(error.code) ? "dead" : "unknown";
  }
  const close = stat.lastIndexOf(")");
  const fields = close === -1 ? [] : stat.slice(close + 2).trim().split(/\s+/u);
  if (!/^[A-Z]$/u.test(fields[0] || "") || !/^\d+$/u.test(fields[19] || "")) return "unknown";
  if (fields[0] === "Z" || fields[19] !== owner.startTimeTicks) return "dead";
  return "live";
}

function trustedCampaignFlock() {
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
      let current = path.dirname(candidate);
      let protectedPath = true;
      while (true) {
        const currentStat = fs.statSync(current);
        if ((currentStat.mode & 0o022) !== 0 ||
            (typeof process.geteuid === "function" && currentStat.uid === process.geteuid())) {
          protectedPath = false;
          break;
        }
        try {
          fs.accessSync(current, fs.constants.W_OK);
          protectedPath = false;
          break;
        } catch (error) {
          if (!new Set(["EACCES", "EPERM", "EROFS"]).has(error.code)) throw error;
        }
        const parent = path.dirname(current);
        if (parent === current) break;
        current = parent;
      }
      if (protectedPath) return candidate;
    } catch {
      // Try the next fixed protected system path.
    }
  }
  throw new Error("campaign controller serialization requires flock from a protected system path");
}

function withCampaignSerialization(resolved, action) {
  if (process.platform !== "linux") throw new Error("campaign controller serialization requires Linux/WSL2");
  const file = `${resolved.lock}.serialization`;
  const descriptor = fs.openSync(
    file,
    fs.constants.O_CREAT | fs.constants.O_RDWR | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
    0o600
  );
  try {
    const identity = fs.fstatSync(descriptor);
    if (!identity.isFile() || identity.nlink !== 1 ||
        (typeof process.geteuid === "function" && identity.uid !== process.geteuid()) ||
        (identity.mode & 0o7777) !== 0o600) {
      throw new Error("campaign controller serialization file is not owner-only");
    }
    const locked = spawnSync(
      trustedCampaignFlock(),
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
      throw new Error("campaign controller lock acquisition is active or indeterminate", { cause: locked.error });
    }
    const current = fs.lstatSync(file);
    if (current.dev !== identity.dev || current.ino !== identity.ino) {
      throw new Error("campaign controller serialization identity changed");
    }
    return action();
  } finally {
    fs.closeSync(descriptor);
  }
}

function acquireLock(resolved, options = {}) {
  const owner = { ...processIdentity(), acquiredAt: nowInstant(options) };
  const bytes = canonicalText(owner);
  try {
    writePrivateFileExclusive(resolved.lock, bytes, { encoding: "utf8", label: "private campaign controller lock" });
  } catch (error) {
    if (error.code === "EEXIST") throw new Error("campaign is locked; use campaign recover only after the owning process exits");
    throw error;
  }
  return { owner, bytes };
}

function releaseLock(resolved, lease) {
  try {
    const current = readPrivateFileBounded(resolved.lock, 4096, "utf8", { label: "private campaign controller lock" });
    if (current !== lease.bytes) throw new Error("campaign controller lock ownership changed");
    fs.unlinkSync(resolved.lock);
    syncPrivateDirectory(resolved.directory, { label: "private campaign after lock release" });
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

function retireDeadLock(resolved) {
  let identity;
  let bytes;
  try {
    securePrivateFile(resolved.lock, { allowMissing: false, label: "private campaign controller lock" });
    identity = fs.lstatSync(resolved.lock);
    bytes = readPrivateFileBounded(resolved.lock, 4096, null, { label: "private campaign controller lock" });
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
  let owner;
  try {
    owner = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    throw new Error("campaign controller lock owner is malformed and was preserved for manual review", { cause: error });
  }
  if (!validLockOwner(owner)) {
    throw new Error("campaign controller lock owner is invalid and was preserved for manual review");
  }
  const ownerStatus = lockOwnerStatus(owner);
  if (ownerStatus !== "dead") {
    throw new Error(`campaign controller lock owner is ${ownerStatus} and cannot be retired`);
  }
  const currentIdentity = fs.lstatSync(resolved.lock);
  const currentBytes = readPrivateFileBounded(resolved.lock, 4096, null, { label: "private campaign controller lock" });
  if (currentIdentity.dev !== identity.dev || currentIdentity.ino !== identity.ino || !currentBytes.equals(bytes)) {
    throw new Error("campaign controller lock changed during dead-owner proof");
  }
  const retired = `${resolved.lock}.retired.${crypto.randomBytes(8).toString("hex")}`;
  fs.renameSync(resolved.lock, retired);
  securePrivateFile(retired, { allowMissing: false, label: "retired private campaign controller lock" });
  syncPrivateDirectory(resolved.directory, { label: "private campaign after lock retirement" });
  return true;
}

function withLock(paths, id, options, callback) {
  const resolved = campaignPaths(paths, id);
  const lease = withCampaignSerialization(resolved, () => acquireLock(resolved, options));
  try { return callback(); }
  finally { releaseLock(resolved, lease); }
}

function sourceHealth(paths, grant, options) {
  try {
    const current = resolveSourceBinding(paths, grant.binding.program.id, grant.binding.source, options);
    return { current: true, observed: current, reason: null };
  } catch (error) {
    return {
      current: false,
      observed: null,
      reason: error.code === "SOURCE_BINDING_CHANGED" ? "source-binding-changed" : "source-binding-unavailable"
    };
  }
}

function adapterRegistryHealth(paths, grant) {
  if (grant.allow.operations.length === 0) {
    return { current: grant.allow.adapterRegistrySha256 === null, reason: null };
  }
  try {
    const loaded = loadManagedAdapterRegistry({ paths });
    const tuplesCurrent = grant.allow.operations.every((operation) => {
      const adapter = loaded.adapters.get(operation.adapterId);
      return adapter?.action === operation.action && adapter?.tool?.id === operation.toolId;
    });
    return {
      current: tuplesCurrent && loaded.registrySha256 === grant.allow.adapterRegistrySha256,
      reason: tuplesCurrent && loaded.registrySha256 === grant.allow.adapterRegistrySha256
        ? null
        : "adapter-registry-binding-changed"
    };
  } catch {
    return { current: false, reason: "adapter-registry-unavailable" };
  }
}

function bindingHealth(paths, grant, options = {}) {
  let currentCase;
  let currentProfileContextValue;
  const reasons = [];
  try {
    currentCase = readCurrentCase(paths);
  } catch {
    reasons.push("case-binding-unavailable");
  }
  const caseCurrent = Boolean(currentCase) && currentCase.metadata.id === grant.binding.case.id &&
    currentCase.scopeSha256 === grant.binding.case.scopeSha256;
  if (!caseCurrent && currentCase) reasons.push("case-binding-changed");
  try {
    if (currentCase) currentProfileContextValue = currentProfileContext(paths, currentCase, options);
  } catch {
    reasons.push("program-profile-unavailable-or-not-ready");
  }
  const profileCurrent = Boolean(currentProfileContextValue) &&
    sameValue(currentProfileContextValue.binding, grant.binding.program);
  if (!profileCurrent && currentProfileContextValue) reasons.push("program-profile-binding-changed");
  const source = sourceHealth(paths, grant, options);
  if (!source.current && source.reason) reasons.push(source.reason);
  const adapterRegistry = adapterRegistryHealth(paths, grant);
  if (!adapterRegistry.current && adapterRegistry.reason) reasons.push(adapterRegistry.reason);
  const grantCurrent = currentTimeMilliseconds(options) < Date.parse(grant.metadata.expiresAt);
  if (!grantCurrent) reasons.push("campaign-grant-expired");
  const engagement = grant.binding.engagement === null
    ? { availability: "not-required", current: true }
    : {
        availability: "unavailable",
        current: null,
        reason: "The scheduling grant does not duplicate engagement-broker authority checks."
      };
  return {
    schedulingReady: caseCurrent && profileCurrent && source.current && adapterRegistry.current && grantCurrent,
    caseCurrent,
    profileCurrent,
    sourceCurrent: source.current,
    adapterRegistryCurrent: adapterRegistry.current,
    grantCurrent,
    engagement,
    executionAuthorityReady: false,
    reasons: [...new Set(reasons)]
  };
}

function assertBindingHealth(paths, grant, options = {}) {
  const health = bindingHealth(paths, grant, options);
  if (!health.schedulingReady) {
    const error = new Error(`campaign binding is not current: ${health.reasons.join("; ")}`);
    error.bindingHealth = health;
    throw error;
  }
  return health;
}

function bindingFailureCondition(health) {
  if (!health?.grantCurrent) return "campaign-expiry";
  if (health.reasons?.includes("case-binding-changed")) return "case-binding-change";
  if (health.reasons?.includes("program-profile-binding-changed")) return "program-profile-change";
  if (health.reasons?.includes("source-binding-changed")) return "source-binding-change";
  if (health.reasons?.includes("adapter-registry-binding-changed")) return "adapter-contract-change";
  return "controller-recovery-required";
}

function campaignEvent(bundle, kind, status, summary, paths) {
  return recordEvent({
    kind,
    status,
    taskId: bundle.grant.metadata.id,
    component: "gate-campaign",
    agent: "gate-campaign",
    summary,
    effect: {
      class: "host-write",
      targetRef: `private://campaigns/${bundle.grant.metadata.id}/state.json`,
      engagementId: bundle.grant.binding.engagement?.id || null,
      planDigest: bundle.grant.grantSha256
    },
    evidenceRefs: []
  }, { paths });
}

export function createCampaign(input = {}, options = {}) {
  const paths = options.paths || runtimePaths(options);
  const root = ensureCampaignRoot(paths);
  const id = campaignId(input.id);
  const at = nowInstant(options);
  const created = new Date(at);
  const expiresAt = exactInstant(input.expiresAt, "campaign expiry");
  if (Date.parse(expiresAt) <= created.getTime()) throw new Error("campaign expiry must be after creation");
  const caseRecord = readCurrentCase(paths);
  const profile = currentProfileContext(paths, caseRecord, options);
  const program = profile.binding;
  if (!sameValue(program, caseRecord.program)) throw new Error("case program-profile binding is stale");
  const expectedSource = expectedSourceBinding(input.source);
  const profileSource = profile.sources.find((item) => item?.id === expectedSource.id);
  if (!profileSource || profileSource.contentSha256 !== expectedSource.contentSha256) {
    throw new Error("campaign source is not the exact content-bound source in the reviewed program profile ledger");
  }
  const source = resolveSourceBinding(paths, program.id, expectedSource, options);
  const allowedOperations = normalizeAllowedOperations(input.operations || [], paths);
  const operations = allowedOperations.operations;
  const selectors = normalizeSelectors(input.selectors || []);
  if (operations.length > 0 && selectors.length === 0) throw new Error("a target-contact campaign grant requires at least one exact selector");
  const engagementId = input.engagementId === undefined || input.engagementId === null
    ? null
    : campaignId(input.engagementId);
  if (operations.length > 0 && engagementId === null) {
    throw new Error("a target-contact campaign grant requires an engagement binding");
  }
  const grant = {
    $schema: GRANT_SCHEMA,
    apiVersion: "gate.dev/campaign-grant/v1",
    kind: "CampaignGrant",
    metadata: { id, createdAt: at, expiresAt },
    binding: {
      case: { id: caseRecord.metadata.id, scopeSha256: caseRecord.scopeSha256 },
      program,
      source,
      engagement: engagementId === null ? null : { id: engagementId }
    },
    allow: {
      operations,
      adapterRegistrySha256: allowedOperations.adapterRegistrySha256,
      selectors,
      environment: String(input.environment || "host")
    },
    ceilings: normalizeCeilings(input.ceilings),
    stopConditions: normalizeStopConditions(input.stopConditions),
    grantSha256: ZERO_SHA256
  };
  grant.grantSha256 = grantDigest(grant);
  assertGrant(grant, paths);
  const inputs = Array.isArray(input.jobs) ? input.jobs : [];
  if (inputs.length > MAX_JOBS) throw new Error(`campaign jobs must contain ${MAX_JOBS} entries or fewer`);
  const jobs = inputs.map((job) => normalizeJob(job, grant, at, paths));
  if (new Set(jobs.map((job) => job.metadata.id)).size !== jobs.length) {
    throw new Error("campaign job ids must be unique");
  }
  assertAggregateJobCeilings(jobs, grant);

  const resolved = campaignPaths(paths, id);
  if (entryExists(resolved.directory)) throw new Error(`campaign already exists: ${id}`);
  const stagingDirectory = path.join(root, `.${id}.creating.${process.pid}.${crypto.randomBytes(8).toString("hex")}`);
  const staged = {
    ...resolved,
    directory: stagingDirectory,
    grant: path.join(stagingDirectory, "grant.json"),
    jobs: path.join(stagingDirectory, "jobs"),
    journal: path.join(stagingDirectory, "journal.jsonl"),
    state: path.join(stagingDirectory, "state.json"),
    lock: path.join(stagingDirectory, ".campaign.lock")
  };
  try {
    fs.mkdirSync(staged.directory, { mode: 0o700 });
  } catch (error) {
    if (error.code === "EEXIST") throw new Error("campaign staging identity collided; retry creation");
    throw error;
  }
  try {
    securePrivateDirectory(staged.directory, { create: false, label: `private staged campaign ${id}` });
    securePrivateDirectory(staged.jobs, { label: `private staged campaign jobs ${id}` });
    writePrivateFileExclusive(staged.grant, canonicalText(grant), { encoding: "utf8", label: `private staged campaign grant ${id}` });
    for (const job of jobs) {
      writePrivateFileExclusive(jobFile(staged, job.metadata.id), canonicalText(job), {
        encoding: "utf8",
        label: `private staged campaign job ${job.metadata.id}`
      });
    }
    const first = journalEntry(null, "campaign-created", {
      grantSha256: grant.grantSha256,
      jobs: jobs.map((job) => ({ id: job.metadata.id, kind: job.job.type, jobSha256: job.jobSha256 }))
    }, at);
    assertJournalEntry(first, null);
    appendJsonLine(staged.journal, first, 0o600, { sync: true });
    const state = replay([first], grant, jobs, paths);
    writeProjection(staged.state, state, paths);
    syncPrivateDirectory(staged.jobs, { label: `private staged campaign jobs ${id}` });
    syncPrivateDirectory(staged.directory, { label: `private staged campaign ${id}` });
    assertBindingHealth(paths, grant, options);
    if (entryExists(resolved.directory)) throw new Error(`campaign already exists: ${id}`);
    try {
      fs.renameSync(staged.directory, resolved.directory);
    } catch (error) {
      if (new Set(["EEXIST", "ENOTEMPTY"]).has(error.code)) throw new Error(`campaign already exists: ${id}`);
      throw error;
    }
    syncPrivateDirectory(root, { label: "private campaign root after publication" });
    securePrivateDirectory(resolved.directory, { create: false, label: `private campaign ${id}` });
    const bundle = { resolved, grant, jobs, entries: [first], state };
    campaignEvent(bundle, "campaign.created", "waiting", `Campaign ${id} was created paused with ${jobs.length} immutable jobs.`, paths);
    return { created: true, grant, state, bindingHealth: bindingHealth(paths, grant, options) };
  } finally {
    fs.rmSync(staged.directory, { recursive: true, force: true });
    securePrivateDirectory(root, { create: false, label: "private campaign root" });
  }
}

export function enqueueLabCampaignJob(id, input = {}, options = {}) {
  const paths = options.paths || runtimePaths(options);
  if (typeof options.verifyLabEnqueue !== "function") {
    throw new Error("lab campaign enqueue requires the persisted authority verifier");
  }
  exactKeys(input, ["authorityId", "job"], "lab campaign enqueue input");
  return withLock(paths, id, options, () => {
    const bundle = loadCampaign(paths, id);
    if (!new Set(["paused", "running", "completed"]).has(bundle.state.status)) {
      throw new Error(`campaign cannot enqueue a lab job from ${bundle.state.status}`);
    }
    assertBindingHealth(paths, bundle.grant, options);
    const at = nowInstant(options);
    const job = input.job?.kind === "CampaignJob"
      ? assertJob(structuredClone(input.job), bundle.grant, paths)
      : normalizeJob(input.job, bundle.grant, at, paths, { allowVerifiedLabSelector: true });
    if (job.job.type !== "managed-adapter") throw new Error("lab campaign enqueue accepts managed-adapter jobs only");
    const verified = options.verifyLabEnqueue(input.authorityId, structuredClone(job), {
      paths,
      campaignId: bundle.grant.metadata.id,
      grantSha256: bundle.grant.grantSha256
    });
    if (verified && typeof verified.then === "function") {
      throw new Error("lab campaign enqueue verifier must complete synchronously before the journal mutation");
    }
    const permit = normalizeLabEnqueuePermit(verified, bundle.grant, input.authorityId, at);
    assertLabJobMatchesPermit(job, permit, bundle.grant);
    const existingJob = bundle.state.jobs.find((candidate) => candidate.id === job.metadata.id);
    if (existingJob) {
      const existingEntry = bundle.entries.find((entry) => entry.type === "job-enqueued" &&
        entry.payload.jobId === job.metadata.id);
      if (!existingEntry || existingJob.jobSha256 !== job.jobSha256 ||
          existingEntry.payload.authorityId !== permit.authorityId ||
          existingEntry.payload.authoritySha256 !== permit.authoritySha256 ||
          existingEntry.payload.receiptSha256 !== permit.receiptSha256 ||
          existingEntry.payload.permitSha256 !== permit.permitSha256 ||
          !sameValue(existingEntry.payload.permit, permit)) {
        throw new Error(`campaign job already exists with a different authority binding: ${job.metadata.id}`);
      }
      return {
        ok: true,
        reconciled: true,
        campaignId: bundle.grant.metadata.id,
        job: { id: job.metadata.id, jobSha256: job.jobSha256 },
        authority: { id: permit.authorityId, permitSha256: permit.permitSha256 },
        state: bundle.state
      };
    }
    const nextJobs = [...bundle.jobs, job];
    if (nextJobs.length > MAX_JOBS || nextJobs.length > permit.dynamic.maxJobs) {
      throw new Error("lab campaign enqueue exceeds its verified job-count ceiling");
    }
    assertAggregateJobCeilings(nextJobs, bundle.grant);
    assertJobsFitCeilings(nextJobs, permit.ceilings, "lab campaign jobs");

    const file = jobFile(bundle.resolved, job.metadata.id);
    try {
      writePrivateFileExclusive(file, canonicalText(job), {
        encoding: "utf8",
        label: `private campaign job ${job.metadata.id}`
      });
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      const orphan = assertJob(
        parsePrivateJson(file, MAX_JOB_BYTES, `private orphaned campaign job ${job.metadata.id}`),
        bundle.grant,
        paths
      );
      if (!sameValue(orphan, job)) throw new Error(`orphaned campaign job differs from the verified enqueue: ${job.metadata.id}`);
    }

    bundle.jobs.push(job);
    try {
      appendCampaignEntry(bundle, "job-enqueued", {
        jobId: job.metadata.id,
        jobSha256: job.jobSha256,
        kind: job.job.type,
        authorityId: permit.authorityId,
        authoritySha256: permit.authoritySha256,
        receiptSha256: permit.receiptSha256,
        permitSha256: permit.permitSha256,
        permit: structuredClone(permit)
      }, { ...options, paths });
    } catch (error) {
      bundle.jobs.pop();
      // The durable journal append may have completed before a later cache
      // write failed. Preserve the immutable job file so replay can resolve
      // either a committed entry or a safe orphan on the next exact retry.
      throw error;
    }
    campaignEvent(
      bundle,
      "campaign.job-enqueued",
      "waiting",
      `Campaign ${bundle.grant.metadata.id} durably enqueued one verified dedicated-lab job.`,
      paths
    );
    return {
      ok: true,
      reconciled: false,
      campaignId: bundle.grant.metadata.id,
      job: { id: job.metadata.id, jobSha256: job.jobSha256 },
      authority: { id: permit.authorityId, permitSha256: permit.permitSha256 },
      state: bundle.state
    };
  });
}

export function campaignStatus(id, options = {}) {
  const paths = options.paths || runtimePaths(options);
  const bundle = loadCampaign(paths, id);
  let projection = { available: false, current: false };
  try {
    const cached = parsePrivateJson(bundle.resolved.state, MAX_STATE_BYTES, `private campaign state ${id}`);
    assertValidDocument(cached, "campaign-state.schema.json", { paths });
    projection = { available: true, current: sameValue(cached, bundle.state) };
  } catch (error) {
    projection = { available: false, current: false, reason: String(error.message || error) };
  }
  return {
    state: bundle.state,
    bindingHealth: bindingHealth(paths, bundle.grant, options),
    projection,
    grant: {
      expiresAt: bundle.grant.metadata.expiresAt,
      operations: bundle.grant.allow.operations.length,
      selectors: bundle.grant.allow.selectors.length,
      environment: bundle.grant.allow.environment,
      ceilings: bundle.grant.ceilings
    }
  };
}

export function resumeCampaign(id, options = {}) {
  const paths = options.paths || runtimePaths(options);
  return withLock(paths, id, options, () => {
    const bundle = loadCampaign(paths, id);
    assertBindingHealth(paths, bundle.grant, options);
    const recoverableBlock = bundle.state.status === "blocked" && bundle.state.queue.queued > 0 &&
      RECOVERABLE_BINDING_BLOCKS.has(bundle.state.stop?.condition);
    if (bundle.state.status !== "paused" && !recoverableBlock) {
      throw new Error(`campaign cannot resume from ${bundle.state.status}`);
    }
    appendCampaignEntry(bundle, "campaign-resumed", {}, { ...options, paths });
    campaignEvent(bundle, "campaign.resumed", "running", `Campaign ${bundle.grant.metadata.id} resumed.`, paths);
    return { ok: true, state: bundle.state };
  });
}

export function pauseCampaign(id, options = {}) {
  const paths = options.paths || runtimePaths(options);
  return withLock(paths, id, options, () => {
    const bundle = loadCampaign(paths, id);
    if (bundle.state.status !== "running") throw new Error(`campaign cannot pause from ${bundle.state.status}`);
    appendCampaignEntry(bundle, "campaign-paused", {}, { ...options, paths });
    campaignEvent(bundle, "campaign.paused", "waiting", `Campaign ${bundle.grant.metadata.id} paused.`, paths);
    return { ok: true, state: bundle.state };
  });
}

export function stopCampaign(id, input = {}, options = {}) {
  const paths = options.paths || runtimePaths(options);
  return withLock(paths, id, options, () => {
    const bundle = loadCampaign(paths, id);
    if (new Set(["stopped", "completed"]).has(bundle.state.status)) {
      throw new Error(`campaign is already ${bundle.state.status}`);
    }
    const reason = oneLine(input.reason || "The operator stopped the campaign.", { name: "campaign stop reason", max: 500 });
    appendCampaignEntry(bundle, "campaign-stopped", { condition: "operator-stop", reason }, { ...options, paths });
    campaignEvent(bundle, "campaign.stopped", "cancelled", `Campaign ${bundle.grant.metadata.id} stopped.`, paths);
    return { ok: true, state: bundle.state };
  });
}

export function runNextCampaignJob(id, inputOptions = {}) {
  const paths = inputOptions.paths || runtimePaths(inputOptions);
  const transitionObserver = inputOptions.onTransition;
  const transitions = [];
  const options = {
    ...inputOptions,
    onTransition(transition) { transitions.push(transition); }
  };
  const result = withLock(paths, id, options, () => {
    const bundle = loadCampaign(paths, id);
    if (bundle.state.status !== "running") throw new Error(`campaign run-next requires running state, observed ${bundle.state.status}`);
    try {
      assertBindingHealth(paths, bundle.grant, options);
    } catch (error) {
      const condition = bindingFailureCondition(error.bindingHealth || bindingHealth(paths, bundle.grant, options));
      const expired = condition === "campaign-expiry";
      appendCampaignEntry(bundle, expired ? "campaign-stopped" : "campaign-blocked", {
        condition,
        reason: oneLine(String(error.message || error), { name: "campaign binding failure", max: 500 })
      }, { ...options, paths });
      observeCampaignTransition(bundle, expired ? "campaign-stopped" : "campaign-blocked", options);
      campaignEvent(bundle, "campaign.blocked", "blocked", `Campaign ${bundle.grant.metadata.id} stopped before dispatch because a binding check failed.`, paths);
      return { ok: false, contactAttempted: false, state: bundle.state, reason: String(error.message || error) };
    }
    const queued = bundle.state.jobs.find((job) => job.status === "queued");
    if (!queued) {
      appendCampaignEntry(bundle, "campaign-completed", {}, { ...options, paths });
      observeCampaignTransition(bundle, "campaign-completed", options);
      campaignEvent(bundle, "campaign.completed", "succeeded", `Campaign ${bundle.grant.metadata.id} has no queued jobs.`, paths);
      return { ok: bundle.state.status === "completed", contactAttempted: false, state: bundle.state, job: null };
    }
    const definition = bundle.jobs.find((job) => job.metadata.id === queued.id);
    if (definition.job.type === "managed-adapter") {
      const reason = CAPABILITY_REASON;
      appendCampaignEntry(bundle, "job-started", {
        jobId: definition.metadata.id,
        jobSha256: definition.jobSha256,
        authorityId: null
      }, { ...options, paths });
      observeCampaignTransition(bundle, "job-started", options);
      appendCampaignEntry(bundle, "job-blocked", {
        jobId: definition.metadata.id,
        jobSha256: definition.jobSha256,
        reason
      }, { ...options, paths });
      observeCampaignTransition(bundle, "job-blocked", options);
      appendCampaignEntry(bundle, "campaign-blocked", { condition: "execution-blocked", reason }, { ...options, paths });
      observeCampaignTransition(bundle, "campaign-blocked", options);
      campaignEvent(bundle, "campaign.job-blocked", "blocked", `Campaign ${bundle.grant.metadata.id} preserved a managed adapter job without target contact.`, paths);
      return { ok: false, contactAttempted: false, state: bundle.state, job: definition.metadata.id, reason };
    }

    appendCampaignEntry(bundle, "job-started", {
      jobId: definition.metadata.id,
      jobSha256: definition.jobSha256,
      authorityId: null
    }, { ...options, paths });
    observeCampaignTransition(bundle, "job-started", options);
    const started = Date.now();
    // The dry-run deliberately performs no interpretation, command expansion,
    // process launch, network access, evidence write, or model invocation.
    assertJob(definition, bundle.grant, paths);
    const wallMilliseconds = Math.max(0, Date.now() - started);
    appendCampaignEntry(bundle, "job-completed", {
      jobId: definition.metadata.id,
      jobSha256: definition.jobSha256,
      metrics: {
        wallMilliseconds,
        requests: 0,
        inputTokens: 0,
        outputTokens: 0,
        totalTokens: 0,
        spend: 0,
        evidenceBytes: 0
      }
    }, { ...options, paths });
    observeCampaignTransition(bundle, "job-completed", options);
    if (!bundle.state.jobs.some((job) => new Set(["queued", "running"]).has(job.status))) {
      appendCampaignEntry(bundle, "campaign-completed", {}, { ...options, paths });
      observeCampaignTransition(bundle, "campaign-completed", options);
    }
    campaignEvent(bundle, "campaign.job-completed", "succeeded", `Campaign ${bundle.grant.metadata.id} completed one non-contact dry-run job.`, paths);
    return {
      ok: true,
      contactAttempted: false,
      state: bundle.state,
      job: definition.metadata.id,
      result: { type: "non-contact-dry-run", wallMilliseconds }
    };
  });
  if (typeof transitionObserver === "function") {
    for (const transition of transitions) {
      try { transitionObserver(transition); }
      catch { /* Durable controller state must not depend on telemetry. */ }
    }
  }
  return result;
}

function deliverCampaignTransitions(transitions, observer) {
  if (typeof observer !== "function") return;
  for (const transition of transitions) {
    try { observer(transition); }
    catch { /* Durable controller state must not depend on telemetry. */ }
  }
}

function managedStartBinding(bundle, jobId, jobSha256, authorityId) {
  const projected = bundle.state.jobs.find((candidate) => candidate.id === jobId);
  const definition = bundle.jobs.find((candidate) => candidate.metadata.id === jobId);
  if (!projected || !definition || definition.job.type !== "managed-adapter" ||
      projected.jobSha256 !== jobSha256 || definition.jobSha256 !== jobSha256) {
    throw new Error("managed campaign job binding changed");
  }
  if (projected.authority && projected.authority.id !== authorityId) {
    throw new Error("managed campaign job authority differs from its durable enqueue permit");
  }
  const started = [...bundle.entries].reverse().find((entry) => entry.type === "job-started" &&
    entry.payload.jobId === jobId);
  if (!started || started.payload.jobSha256 !== jobSha256 || started.payload.authorityId !== authorityId) {
    throw new Error("managed campaign job start authority binding changed");
  }
  return { projected, definition };
}

/**
 * Durably claim the next exact managed job for one named dedicated-lab
 * authority. This transition performs no target contact and releases the
 * controller lock before the authority invokes the execution broker.
 */
export function startNextManagedCampaignJob(id, authorityId, inputOptions = {}) {
  const paths = inputOptions.paths || runtimePaths(inputOptions);
  const exactAuthorityId = campaignId(authorityId);
  const transitionObserver = inputOptions.onTransition;
  const transitions = [];
  const options = {
    ...inputOptions,
    paths,
    onTransition(transition) { transitions.push(transition); }
  };
  const result = withLock(paths, id, options, () => {
    const bundle = loadCampaign(paths, id);
    if (bundle.state.status !== "running") {
      throw new Error(`campaign managed start requires running state, observed ${bundle.state.status}`);
    }
    if (bundle.state.jobs.some((job) => job.status === "running")) {
      throw new Error("campaign already has a running job");
    }
    try {
      assertBindingHealth(paths, bundle.grant, options);
    } catch (error) {
      const condition = bindingFailureCondition(error.bindingHealth || bindingHealth(paths, bundle.grant, options));
      const expired = condition === "campaign-expiry";
      appendCampaignEntry(bundle, expired ? "campaign-stopped" : "campaign-blocked", {
        condition,
        reason: oneLine(String(error.message || error), { name: "campaign binding failure", max: 500 })
      }, options);
      observeCampaignTransition(bundle, expired ? "campaign-stopped" : "campaign-blocked", options);
      return {
        ok: false,
        contactAttempted: false,
        state: bundle.state,
        job: null,
        reason: String(error.message || error)
      };
    }
    const queued = bundle.state.jobs.find((job) => job.status === "queued");
    if (!queued) {
      appendCampaignEntry(bundle, "campaign-completed", {}, options);
      observeCampaignTransition(bundle, "campaign-completed", options);
      return { ok: true, contactAttempted: false, state: bundle.state, job: null, envelope: null };
    }
    const definition = bundle.jobs.find((job) => job.metadata.id === queued.id);
    if (!definition || definition.job.type !== "managed-adapter") {
      throw new Error("the next campaign job is not a managed adapter job");
    }
    if (queued.authority && queued.authority.id !== exactAuthorityId) {
      throw new Error("the next campaign job is bound to a different lab authority");
    }
    appendCampaignEntry(bundle, "job-started", {
      jobId: definition.metadata.id,
      jobSha256: definition.jobSha256,
      authorityId: exactAuthorityId
    }, options);
    observeCampaignTransition(bundle, "job-started", options);
    campaignEvent(
      bundle,
      "campaign.job-started",
      "running",
      `Campaign ${bundle.grant.metadata.id} durably started one authorized dedicated-lab job.`,
      paths
    );
    return {
      ok: true,
      contactAttempted: false,
      state: bundle.state,
      job: definition.metadata.id,
      envelope: structuredClone(definition),
      authorityId: exactAuthorityId
    };
  });
  deliverCampaignTransitions(transitions, transitionObserver);
  return result;
}

function managedResultMetrics(result, definition) {
  if (!result || typeof result !== "object" || Array.isArray(result) || typeof result.ok !== "boolean" ||
      typeof result.status !== "string" || !result.metrics || typeof result.metrics !== "object" ||
      Array.isArray(result.metrics)) {
    throw new Error("lab campaign dispatch returned an invalid terminal result");
  }
  const metrics = Object.fromEntries([
    "wallMilliseconds", "requests", "inputTokens", "outputTokens", "totalTokens", "spend", "evidenceBytes"
  ].map((field) => [field, result.metrics[field]]));
  for (const [field, value] of Object.entries(metrics)) {
    if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
      throw new Error(`lab campaign dispatch metric is invalid: ${field}`);
    }
  }
  for (const field of ["wallMilliseconds", "requests", "inputTokens", "outputTokens", "totalTokens", "evidenceBytes"]) {
    if (!Number.isSafeInteger(metrics[field])) throw new Error(`lab campaign dispatch metric must be a safe integer: ${field}`);
  }
  if (metrics.totalTokens !== metrics.inputTokens + metrics.outputTokens) {
    throw new Error("lab campaign dispatch total-token metric is inconsistent");
  }
  const bounds = definition.job.bounds;
  if (metrics.wallMilliseconds > bounds.maxMinutes * 60_000 || metrics.requests > bounds.estimatedRequests ||
      metrics.totalTokens > bounds.maxTokens || metrics.spend > bounds.maxSpend ||
      metrics.evidenceBytes > bounds.maxEvidenceBytes) {
    throw new Error("lab campaign dispatch metrics exceed the immutable job bounds");
  }
  return metrics;
}

/** Commit one authority-bound broker result into the campaign journal. */
export function completeManagedCampaignJob(id, authorityId, jobEnvelope, dispatchResult, inputOptions = {}) {
  const paths = inputOptions.paths || runtimePaths(inputOptions);
  const exactAuthorityId = campaignId(authorityId);
  const transitionObserver = inputOptions.onTransition;
  const transitions = [];
  const options = {
    ...inputOptions,
    paths,
    onTransition(transition) { transitions.push(transition); }
  };
  const jobId = campaignId(jobEnvelope?.metadata?.id);
  const jobSha256 = exactSha256(jobEnvelope?.jobSha256, "managed campaign job digest");
  const result = withLock(paths, id, options, () => {
    const bundle = loadCampaign(paths, id);
    if (bundle.state.status !== "running") {
      throw new Error(`campaign managed completion requires running state, observed ${bundle.state.status}`);
    }
    const { projected, definition } = managedStartBinding(bundle, jobId, jobSha256, exactAuthorityId);
    if (projected.status !== "running" || !sameValue(definition, jobEnvelope)) {
      throw new Error("managed campaign job changed before completion");
    }
    if (dispatchResult.authorityId !== exactAuthorityId || dispatchResult.campaignId !== bundle.grant.metadata.id ||
        dispatchResult.jobId !== jobId || !/^lcap_[a-f0-9]{32}$/u.test(dispatchResult.capabilityId || "") ||
        !/^xmf_[a-f0-9]{32}$/u.test(dispatchResult.manifestId || "") ||
        !/^xrun_[a-f0-9]{32}$/u.test(dispatchResult.runId || "")) {
      throw new Error("lab campaign dispatch result provenance differs from the running job");
    }
    const metrics = managedResultMetrics(dispatchResult, definition);
    appendCampaignEntry(bundle, "job-completed", { jobId, jobSha256, metrics }, options);
    observeCampaignTransition(bundle, "job-completed", options);
    if (dispatchResult.ok !== true) {
      const stop = String(dispatchResult.stopCondition || "execution-blocked");
      const reason = oneLine(`Dedicated-lab execution stopped: ${stop}.`, {
        name: "managed campaign block reason",
        max: 500
      });
      appendCampaignEntry(bundle, "campaign-blocked", {
        condition: stop === "execution-ambiguity" ? "execution-ambiguity" : "execution-blocked",
        reason
      }, options);
      observeCampaignTransition(bundle, "campaign-blocked", options);
    } else if (!bundle.state.jobs.some((job) => new Set(["queued", "running"]).has(job.status))) {
      appendCampaignEntry(bundle, "campaign-completed", {}, options);
      observeCampaignTransition(bundle, "campaign-completed", options);
    }
    campaignEvent(
      bundle,
      dispatchResult.ok === true ? "campaign.job-completed" : "campaign.job-blocked",
      dispatchResult.ok === true ? "succeeded" : "blocked",
      dispatchResult.ok === true
        ? `Campaign ${bundle.grant.metadata.id} completed one authorized dedicated-lab job.`
        : `Campaign ${bundle.grant.metadata.id} stopped after one authorized dedicated-lab result.`,
      paths
    );
    return {
      ok: dispatchResult.ok === true,
      contactAttempted: true,
      state: bundle.state,
      job: jobId,
      result: {
        type: "managed-adapter",
        status: dispatchResult.status,
        stopCondition: dispatchResult.stopCondition || null,
        metrics
      }
    };
  });
  deliverCampaignTransitions(transitions, transitionObserver);
  return result;
}

/** Fail closed when authority/broker dispatch has no trustworthy terminal result. */
export function blockManagedCampaignJob(id, authorityId, jobEnvelope, failure, inputOptions = {}) {
  const paths = inputOptions.paths || runtimePaths(inputOptions);
  const exactAuthorityId = campaignId(authorityId);
  const transitionObserver = inputOptions.onTransition;
  const transitions = [];
  const options = {
    ...inputOptions,
    paths,
    onTransition(transition) { transitions.push(transition); }
  };
  const jobId = campaignId(jobEnvelope?.metadata?.id);
  const jobSha256 = exactSha256(jobEnvelope?.jobSha256, "managed campaign job digest");
  const reason = oneLine(String(failure?.message || failure || "Authorized lab dispatch did not return a terminal result."), {
    name: "managed campaign failure",
    max: 500
  });
  const result = withLock(paths, id, options, () => {
    const bundle = loadCampaign(paths, id);
    if (bundle.state.status !== "running") {
      throw new Error(`campaign managed failure requires running state, observed ${bundle.state.status}`);
    }
    const { projected, definition } = managedStartBinding(bundle, jobId, jobSha256, exactAuthorityId);
    if (projected.status !== "running" || !sameValue(definition, jobEnvelope) ||
        bundle.state.jobs.some((job) => job.id !== jobId && job.status === "running")) {
      throw new Error("managed campaign job changed before failure was recorded");
    }
    appendCampaignEntry(bundle, "job-blocked", { jobId, jobSha256, reason }, options);
    observeCampaignTransition(bundle, "job-blocked", options);
    appendCampaignEntry(bundle, "campaign-blocked", {
      condition: "execution-ambiguity",
      reason: "The authorized target-contact dispatch has no trustworthy terminal result."
    }, options);
    observeCampaignTransition(bundle, "campaign-blocked", options);
    campaignEvent(
      bundle,
      "campaign.job-blocked",
      "blocked",
      `Campaign ${bundle.grant.metadata.id} preserved an ambiguous dedicated-lab dispatch for review.`,
      paths
    );
    return {
      ok: false,
      contactAttempted: null,
      contactStatus: "indeterminate",
      state: bundle.state,
      job: jobId,
      reason
    };
  });
  deliverCampaignTransitions(transitions, transitionObserver);
  return result;
}

export function recoverCampaign(id, options = {}) {
  const paths = options.paths || runtimePaths(options);
  ensureCampaignRoot(paths);
  const resolved = campaignPaths(paths, id);
  const retiredLock = entryExists(resolved.lock)
    ? withCampaignSerialization(resolved, () => entryExists(resolved.lock) ? retireDeadLock(resolved) : false)
    : false;
  return withLock(paths, id, options, () => {
    const journalRepair = repairIncompleteJournalTail(paths, id, resolved, options);
    const bundle = loadCampaign(paths, id);
    const recoveries = interruptedJobRecoveries(bundle);
    if (recoveries.length > 0) {
      appendCampaignEntry(bundle, "campaign-recovered", { jobs: recoveries }, { ...options, paths });
    } else {
      writeProjection(bundle.resolved.state, bundle.state, paths);
    }
    campaignEvent(bundle, "campaign.recovered", "succeeded", `Campaign ${bundle.grant.metadata.id} replayed its durable journal.`, paths);
    return {
      ok: true,
      retiredLock,
      repairedJournalTail: journalRepair.repaired,
      journalRepair: { repaired: journalRepair.repaired, mode: journalRepair.mode },
      recoveredJobs: [...journalRepair.recoveredJobs, ...recoveries.map((item) => item.jobId)],
      state: bundle.state,
      bindingHealth: bindingHealth(paths, bundle.grant, options)
    };
  });
}

export const campaignInternals = Object.freeze({
  CAPABILITY_REASON,
  STOP_CONDITIONS,
  canonicalSha256,
  campaignPaths,
  grantDigest,
  jobDigest,
  journalEntry,
  loadCampaignContext(id, options = {}) {
    const paths = options.paths || runtimePaths(options);
    const bundle = loadCampaign(paths, id);
    return structuredClone({
      grant: bundle.grant,
      jobs: bundle.jobs,
      state: bundle.state,
      activeStart: activeCampaignStart(bundle),
      labPermits: bundle.entries
        .filter((entry) => entry.type === "job-enqueued")
        .map((entry) => ({
          jobId: entry.payload.jobId,
          jobSha256: entry.payload.jobSha256,
          authorityId: entry.payload.authorityId,
          permit: entry.payload.permit
        })),
      bindingHealth: bindingHealth(paths, bundle.grant, options)
    });
  },
  replay,
  trustedCampaignFlock
});
