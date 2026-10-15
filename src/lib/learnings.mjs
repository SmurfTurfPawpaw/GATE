import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { appendJsonLine } from "./jsonl.mjs";
import { newId, recordEvent } from "./events.mjs";
import { ensureRuntime, runtimePaths } from "./paths.mjs";
import { readPrivateFileBounded } from "./private-fs.mjs";
import { assertValidDocument } from "./schema.mjs";
import { assertNoLikelySecret, oneLine } from "./text.mjs";

const LEDGER_PREAMBLE = `# GATE learnings

This reviewed public ledger contains sanitized repository-wide lessons. The machine-readable append log is \`memory/learnings.jsonl\`; promotion updates this ledger with the same cause and change. Target identifiers, credentials, private paths, captures, client material, and unpublished findings belong in the private learning record under \`GATE_HOME\`.

Format:

\`\`\`text
YYYY-MM-DD | Cause: what happened | Change: the durable behavior or configuration change | Evidence: public reference | Status: proposed|active|superseded|reverted
\`\`\`
`;

const waitBuffer = new Int32Array(new SharedArrayBuffer(4));
const LEARNING_DOMAINS = new Set(["active-testing", "software-testing", "orchestration", "tooling", "general"]);
const OUTCOME_DISPOSITIONS = new Set(["confirmed", "contradicted", "inconclusive", "blocked", "error"]);
const APPLICABILITY_KINDS = new Set(["component", "workflow", "phase", "tool", "adapter", "test", "environment"]);
const LEARNING_ID_PATTERN = /^lrn_[A-Za-z0-9][A-Za-z0-9_-]{5,127}$/u;
const TOKEN_PATTERN = /^[a-z][a-z0-9-]{1,127}$/u;
const APPLICABILITY_ID_PATTERN = /^[a-z][a-z0-9._-]{1,127}$/u;
const VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const GIT_SHA_PATTERN = /^[a-f0-9]{40}$/u;
const EVIDENCE_REF_PATTERN = /^(?:event|evidence|private|commit):\/\/\S+$/u;
const CHANGE_REF_PATTERN = /^(?:evidence|commit):\/\/\S+$/u;
const REVIEW_REF_PATTERN = /^evidence:\/\/no-mistakes\/\S+$/u;
const PUBLIC_LEARNING_ID_PATTERN = /^lrn_[0-9]{14}_[a-f0-9]{8}$/u;
const MAX_LOG_BYTES = 64 * 1024 * 1024;
const MAX_LOG_RECORDS = 10000;
const DEFAULT_CONSULT_LIMIT = 8;
const DEFAULT_CONSULT_BYTES = 4096;
const PROMOTION_INPUT_FIELDS = new Set([
  "at",
  "changeRefs",
  "conflictsWith",
  "evidence",
  "id",
  "review",
  "scope",
  "sensitivity",
  "validationRefs"
]);

function sleep(milliseconds) {
  Atomics.wait(waitBuffer, 0, 0, milliseconds);
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
}

function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function digest(value, domain) {
  return crypto.createHash("sha256").update(`${domain}\0`).update(canonicalJson(value)).digest("hex");
}

function learningDigest(learning) {
  return digest(learning, "gate.learning.record.v1");
}

export function learningCandidateSha256(candidate) {
  if (
    !candidate ||
    candidate.apiVersion !== "gate.learning/v2" ||
    candidate.status !== "proposed" ||
    candidate.promotion?.state !== "candidate"
  ) throw new Error("candidate digest requires a proposed gate.learning/v2 candidate");
  return learningDigest(candidate);
}

function normalizeEvidenceRefs(value, name, { minimum = 0, change = false } = {}) {
  if (!Array.isArray(value)) throw new Error(`${name} must be an array`);
  const refs = [...new Set(value.map((item) => String(item)))].sort();
  const pattern = change ? CHANGE_REF_PATTERN : EVIDENCE_REF_PATTERN;
  if (refs.length < minimum) throw new Error(`${name} must contain at least ${minimum} reference`);
  if (refs.length > 64) throw new Error(`${name} must contain 64 references or fewer`);
  for (const ref of refs) if (!pattern.test(ref)) throw new Error(`${name} contains an invalid reference: ${ref}`);
  return refs;
}

function normalizeConfigurationRefs(value = []) {
  if (!Array.isArray(value)) throw new Error("configurationRefs must be an array");
  const refs = [...new Set(value.map((item) => String(item)))].sort();
  if (refs.length > 64) throw new Error("configurationRefs must contain 64 references or fewer");
  return refs;
}

function normalizeReviewAttestation(value, candidateSha256) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("review must be a No Mistakes attestation object");
  }
  if (Object.keys(value).some((key) => ![
    "owner",
    "attestationRef",
    "attestationSha256",
    "candidateSha256",
    "headSha"
  ].includes(key))) {
    throw new Error("review contains an unknown field");
  }
  if (value.owner !== "no-mistakes") throw new Error("review.owner must be no-mistakes");
  const attestationRef = String(value.attestationRef || "");
  if (!REVIEW_REF_PATTERN.test(attestationRef)) {
    throw new Error("review.attestationRef must use evidence://no-mistakes/<id>");
  }
  const attestationSha256 = String(value.attestationSha256 || "");
  if (!SHA256_PATTERN.test(attestationSha256)) {
    throw new Error("review.attestationSha256 must be a lowercase SHA-256 digest");
  }
  const reviewedCandidateSha256 = String(value.candidateSha256 || "");
  if (!SHA256_PATTERN.test(reviewedCandidateSha256)) {
    throw new Error("review.candidateSha256 must be a lowercase SHA-256 digest");
  }
  if (reviewedCandidateSha256 !== candidateSha256) {
    throw new Error("review.candidateSha256 does not match the exact learning candidate");
  }
  const headSha = String(value.headSha || "");
  if (!GIT_SHA_PATTERN.test(headSha)) {
    throw new Error("review.headSha must be a full 40-character lowercase Git commit SHA");
  }
  return {
    owner: "no-mistakes",
    attestationRef,
    attestationSha256,
    candidateSha256: reviewedCandidateSha256,
    headSha
  };
}

function normalizeConflictIds(value = []) {
  return normalizeLearningIds(value, "conflictsWith");
}

function normalizeReplacementIds(value = []) {
  return normalizeLearningIds(value, "replaces");
}

function normalizeLearningIds(value, name, { sort = true } = {}) {
  if (!Array.isArray(value)) throw new Error(`${name} must be an array`);
  const ids = value.map((item) => String(item));
  if (ids.length > 64) throw new Error(`${name} must contain 64 learning ids or fewer`);
  if (new Set(ids).size !== ids.length) throw new Error(`${name} learning ids must be unique`);
  for (const id of ids) if (!LEARNING_ID_PATTERN.test(id)) throw new Error(`${name} contains an invalid learning id: ${id}`);
  return sort ? ids.sort() : ids;
}

function assertPromotionInput(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("promotion input must be an object");
  }
  const unsupported = Object.keys(input).filter((key) => !PROMOTION_INPUT_FIELDS.has(key)).sort();
  if (unsupported.length) {
    throw new Error(`promotion cannot replace candidate content or set unknown fields: ${unsupported.join(", ")}`);
  }
}

function normalizeApplicability(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 16) {
    throw new Error("applicability must contain between 1 and 16 references");
  }
  const normalized = value.map((item, index) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new Error(`applicability[${index}] must be an object`);
    }
    if (Object.keys(item).some((key) => !["kind", "id", "version", "digest"].includes(key))) {
      throw new Error(`applicability[${index}] contains an unknown field`);
    }
    const kind = String(item.kind || "");
    const id = String(item.id || "");
    if (!APPLICABILITY_KINDS.has(kind)) throw new Error(`applicability[${index}].kind is invalid`);
    if (!APPLICABILITY_ID_PATTERN.test(id)) throw new Error(`applicability[${index}].id is invalid`);
    const result = { kind, id };
    if (item.version !== undefined) {
      const version = String(item.version);
      if (!VERSION_PATTERN.test(version)) throw new Error(`applicability[${index}].version is invalid`);
      result.version = version;
    }
    if (item.digest !== undefined) {
      const digestValue = String(item.digest);
      if (!SHA256_PATTERN.test(digestValue)) throw new Error(`applicability[${index}].digest is invalid`);
      result.digest = digestValue;
    }
    return result;
  }).sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
  if (new Set(normalized.map(canonicalJson)).size !== normalized.length) {
    throw new Error("applicability references must be unique");
  }
  return normalized;
}

function normalizeCycle(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("cycle must be an object");
  if (!value.outcome || typeof value.outcome !== "object" || Array.isArray(value.outcome)) {
    throw new Error("cycle.outcome must be an object");
  }
  const disposition = String(value.outcome.disposition || "");
  if (!OUTCOME_DISPOSITIONS.has(disposition)) throw new Error("cycle.outcome.disposition is invalid");
  const cycle = {
    hypothesis: oneLine(value.hypothesis, { name: "cycle.hypothesis", max: 500 }),
    method: oneLine(value.method, { name: "cycle.method", max: 500 }),
    outcome: {
      disposition,
      summary: oneLine(value.outcome.summary, { name: "cycle.outcome.summary", max: 500 })
    },
    lesson: oneLine(value.lesson, { name: "cycle.lesson", max: 500 }),
    nextAdjustment: oneLine(value.nextAdjustment, { name: "cycle.nextAdjustment", max: 500 })
  };
  for (const [name, narrative] of [
    ["cycle.hypothesis", cycle.hypothesis],
    ["cycle.method", cycle.method],
    ["cycle.outcome.summary", cycle.outcome.summary],
    ["cycle.lesson", cycle.lesson],
    ["cycle.nextAdjustment", cycle.nextAdjustment]
  ]) assertNoLikelySecret(narrative, name);
  return cycle;
}

function normalizeSensitivity(value, fallback) {
  const sensitivity = value || fallback;
  if (!["public", "private"].includes(sensitivity)) throw new Error("sensitivity must be public or private");
  return sensitivity;
}

function normalizeScope(value, sensitivity) {
  const scope = value || (sensitivity === "private" ? "session" : "repository");
  if (!["session", "project", "repository"].includes(scope)) {
    throw new Error("scope must be session, project, or repository");
  }
  if (scope === "project" && sensitivity === "public") {
    throw new Error("public project learning has no configured promotion destination; use --private --scope project");
  }
  return scope;
}

function publicMaterialReason(value) {
  if (/private:\/\//iu.test(value)) return "a private reference";
  if (/\b(?:https?|wss?|ftp):\/\//iu.test(value)) return "a target or source URL";
  if (/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/u.test(value)) return "an email address";
  if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/u.test(value)) return "an IP address";
  const colonCandidates = value.match(/\[?[A-Fa-f0-9:]{2,}\]?/gu) || [];
  if (colonCandidates.some((candidate) => net.isIP(candidate.replace(/^\[|\]$/gu, "")) === 6)) {
    return "an IP address";
  }
  if (/(?:^|[\s("'])\/[^\s,;)"']+/u.test(value) ||
      /(?:^|[\s("'])[A-Za-z]:[\\/][^\s]+/u.test(value) ||
      /(?:^|[\s("'])~[\\/][^\s]+/u.test(value)) return "an absolute or private path";
  if (/(?<![A-Za-z0-9_.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/iu.test(value)) {
    return "a likely target hostname or dotted identifier";
  }
  if (/\b[A-Za-z0-9][A-Za-z0-9_-]*[-_.](?:prod(?:uction)?|stag(?:e|ing)?|dev(?:elopment)?|qa|uat)\b/iu.test(value)) {
    return "a likely target environment identifier";
  }
  return null;
}

function publicApplicabilityReason(value) {
  const general = publicMaterialReason(value);
  if (general) return general;
  if (/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/iu.test(value)) {
    return "a likely target hostname";
  }
  if (/(?:^|[._-])(?:client|customer|target|private|secret)s?(?:$|[._-])/iu.test(value)) {
    return "a likely client or private identifier";
  }
  return null;
}

function publicConfigurationReason(value) {
  if (/private:\/\//iu.test(value)) return "a private reference";
  if (/\b(?:https?|wss?|ftp):\/\//iu.test(value)) return "a target or source URL";
  if (/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/u.test(value)) return "an email address";
  if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/u.test(value)) return "an IP address";
  const colonCandidates = value.match(/\[?[A-Fa-f0-9:]{2,}\]?/gu) || [];
  if (colonCandidates.some((candidate) => net.isIP(candidate.replace(/^\[|\]$/gu, "")) === 6)) {
    return "an IP address";
  }
  if (path.isAbsolute(value) || /^[A-Za-z]:[\\/]/u.test(value) || /^~[\\/]/u.test(value)) {
    return "an absolute or private path";
  }
  if (/(?:^|[\\/._-])(?:client|customer|target|private|secret)s?(?:$|[\\/._-])/iu.test(value)) {
    return "a likely client or private path";
  }
  return null;
}

function sameOrDescendant(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return relative === "" ||
    (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

function assertPublicConfigurationRefsSafe(learning, paths) {
  const realRepository = fs.realpathSync(path.resolve(paths.repo));
  for (const ref of learning.configurationRefs || []) {
    assertNoLikelySecret(ref, "public learning configurationRef");
    const reason = publicConfigurationReason(ref);
    if (reason) throw new Error(`public learning configurationRefs contains ${reason}`);
    if (ref.includes("\\")) {
      throw new Error("public learning configurationRef must use a repository-relative POSIX path");
    }
    const segments = ref.split("/");
    if (!segments.length || segments.some((segment) => !segment || segment === "." || segment === ".." || segment === ".git")) {
      throw new Error("public learning configurationRef must use a canonical repository path");
    }
    let candidate = realRepository;
    for (const segment of segments) {
      candidate = path.join(candidate, segment);
      let stat;
      try {
        stat = fs.lstatSync(candidate);
      } catch (error) {
        if (error.code === "ENOENT") {
          throw new Error("public learning configurationRef must identify an existing repository file");
        }
        throw error;
      }
      if (stat.isSymbolicLink()) {
        throw new Error("public learning configurationRef must not traverse a symbolic link");
      }
    }
    if (!sameOrDescendant(realRepository, candidate)) {
      throw new Error("public learning configurationRef resolves outside the repository");
    }
    if (!fs.lstatSync(candidate).isFile()) {
      throw new Error("public learning configurationRef must identify a regular non-symlink file");
    }
  }
}

function assertPublicNarrativesSafe(learning) {
  for (const [name, value] of [
    ["cause", learning.cause],
    ["change", learning.change],
    ["cycle.hypothesis", learning.cycle?.hypothesis],
    ["cycle.method", learning.cycle?.method],
    ["cycle.outcome.summary", learning.cycle?.outcome?.summary],
    ["cycle.lesson", learning.cycle?.lesson],
    ["cycle.nextAdjustment", learning.cycle?.nextAdjustment]
  ]) {
    if (!value) continue;
    assertNoLikelySecret(value, name);
    const reason = publicMaterialReason(value);
    if (reason) throw new Error(`public learning ${name} contains ${reason}; keep target and private-path material private`);
  }
  for (const ref of [
    ...(learning.evidence || []),
    ...(learning.promotion?.validationRefs || []),
    ...(learning.promotion?.changeRefs || []),
    learning.promotion?.review?.attestationRef
  ].filter(Boolean)) {
    assertNoLikelySecret(ref, "public learning reference");
    if (ref.startsWith("private://")) throw new Error("public learning must not contain private:// evidence");
    const reason = publicMaterialReason(ref);
    if (reason) throw new Error(`public learning reference contains ${reason}; keep target and private-path material private`);
  }
}

function assertPublicLearningSafe(learning, paths) {
  assertPublicNarrativesSafe(learning);
  if (!PUBLIC_LEARNING_ID_PATTERN.test(learning.id) ||
    learning.supersedes !== null && !PUBLIC_LEARNING_ID_PATTERN.test(learning.supersedes)) {
    throw new Error("public learning ids must be opaque GATE-generated ids");
  }
  if (learning.apiVersion === "gate.learning/v2") {
    if (learning.promotion?.state === "validated" &&
      !PUBLIC_LEARNING_ID_PATTERN.test(learning.promotion.candidateId || "")) {
      throw new Error("public structured learning ids must be opaque GATE-generated ids");
    }
    if ([
      ...(learning.promotion?.conflictsWith || []),
      ...(learning.promotion?.replaces || [])
    ].some((id) => !PUBLIC_LEARNING_ID_PATTERN.test(id))) {
      throw new Error("public structured learning references must use opaque GATE-generated ids");
    }
    assertNoLikelySecret(learning.trigger, "public learning trigger");
    const triggerReason = publicApplicabilityReason(learning.trigger);
    if (triggerReason) throw new Error(`public learning trigger contains ${triggerReason}`);
  }
  for (const applicability of learning.applicability || []) {
    assertNoLikelySecret(applicability.id, "public learning applicability.id");
    const reason = publicApplicabilityReason(applicability.id);
    if (reason) {
      throw new Error(`public learning applicability id contains ${reason}`);
    }
    if (applicability.version !== undefined) {
      assertNoLikelySecret(applicability.version, "public learning applicability.version");
      const versionReason = publicMaterialReason(applicability.version);
      if (versionReason) throw new Error(`public learning applicability version contains ${versionReason}`);
    }
  }
  assertPublicConfigurationRefsSafe(learning, paths);
}

function publicLearningIsSafe(learning, paths) {
  try {
    assertPublicLearningSafe(learning, paths);
    return true;
  } catch {
    return false;
  }
}

function assertV2Lifecycle(learning) {
  if (learning.promotion.state === "candidate") {
    if (learning.status !== "proposed" || learning.supersedes !== null) {
      throw new Error("a learning candidate must be proposed and must not supersede another record");
    }
    return;
  }
  if (
    learning.promotion.state !== "validated" ||
    learning.status !== "active" ||
    learning.supersedes !== learning.promotion.candidateId ||
    learning.promotion.review?.candidateSha256 !== learning.promotion.candidateSha256
  ) throw new Error("a promoted learning must be active and supersede its bound candidate");
}

function processRecord(text) {
  const close = text.lastIndexOf(")");
  if (close === -1) return null;
  const fields = text.slice(close + 2).trim().split(/\s+/u);
  return fields.length > 19 && /^[A-Z]$/u.test(fields[0]) && /^\d+$/u.test(fields[19])
    ? { state: fields[0], startTimeTicks: fields[19] }
    : null;
}

function linuxLockIdentity(pid = process.pid) {
  if (process.platform !== "linux") return null;
  try {
    const bootId = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim().toLowerCase();
    const record = processRecord(fs.readFileSync(`/proc/${pid}/stat`, "utf8"));
    if (!/^[a-f0-9-]{36}$/u.test(bootId) || !record || ["Z", "X"].includes(record.state)) return null;
    return { bootId, startTimeTicks: record.startTimeTicks };
  } catch {
    return null;
  }
}

function lockOwner() {
  const identity = linuxLockIdentity();
  if (process.platform === "linux" && !identity) {
    throw new Error("learning ledger lock process identity is unavailable");
  }
  return {
    apiVersion: "gate.learning-lock/v1",
    pid: process.pid,
    platform: process.platform,
    bootId: identity?.bootId || null,
    startTimeTicks: identity?.startTimeTicks || null,
    nonce: crypto.randomBytes(16).toString("hex"),
    createdAt: new Date().toISOString()
  };
}

function validLockOwner(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (canonicalJson(Object.keys(value).sort()) !== canonicalJson([
    "apiVersion", "bootId", "createdAt", "nonce", "pid", "platform", "startTimeTicks"
  ])) return false;
  if (value.apiVersion !== "gate.learning-lock/v1" || !Number.isSafeInteger(value.pid) || value.pid <= 0 ||
    typeof value.platform !== "string" || !value.platform || !/^[a-f0-9]{32}$/u.test(value.nonce) ||
    !Number.isFinite(Date.parse(value.createdAt))) return false;
  if (value.platform === "linux") {
    return /^[a-f0-9-]{36}$/u.test(value.bootId || "") && /^\d+$/u.test(value.startTimeTicks || "");
  }
  return value.bootId === null && value.startTimeTicks === null;
}

function ownerProvablyDead(owner) {
  if (!validLockOwner(owner) || owner.platform !== process.platform) return false;
  if (process.platform === "linux") {
    let bootId;
    try { bootId = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim().toLowerCase(); }
    catch { return false; }
    if (owner.bootId !== bootId) return true;
    let stat;
    try { stat = fs.readFileSync(`/proc/${owner.pid}/stat`, "utf8"); }
    catch (error) { return error.code === "ENOENT" || error.code === "ESRCH"; }
    const record = processRecord(stat);
    return Boolean(record && (["Z", "X"].includes(record.state) || record.startTimeTicks !== owner.startTimeTicks));
  }
  try {
    process.kill(owner.pid, 0);
    return false;
  } catch (error) {
    return error.code === "ESRCH";
  }
}

function lockBytes(owner) {
  return Buffer.from(`${canonicalJson(owner)}\n`);
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function lockAuxiliaryDirectory(file) {
  const directory = path.join(path.dirname(file), ".gate-learning-locks");
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700 ||
    typeof process.geteuid === "function" && stat.uid !== process.geteuid()) {
    throw new Error("learning ledger auxiliary lock directory is not trusted and owner-only");
  }
  return directory;
}

function lockResourceKey(file) {
  return crypto.createHash("sha256").update(path.resolve(file)).digest("hex");
}

function readLock(file) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 4096) {
    throw new Error("learning ledger lock identity is malformed");
  }
  const bytes = fs.readFileSync(file);
  let owner;
  try { owner = JSON.parse(bytes.toString("utf8")); }
  catch { throw new Error("learning ledger lock identity is malformed"); }
  if (!validLockOwner(owner)) throw new Error("learning ledger lock identity is malformed");
  return { bytes, owner };
}

function trustedLearningFlock() {
  for (const candidate of ["/usr/bin/flock", "/bin/flock"]) {
    try {
      if (fs.realpathSync(candidate) !== candidate) continue;
      const stat = fs.lstatSync(candidate);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== 0 ||
        (stat.mode & 0o111) === 0 || (stat.mode & 0o022) !== 0) continue;
      let current = path.dirname(candidate);
      let protectedPath = true;
      while (true) {
        const currentStat = fs.statSync(current);
        if (currentStat.uid !== 0 || (currentStat.mode & 0o022) !== 0) {
          protectedPath = false;
          break;
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
  throw new Error("dead learning lock recovery requires flock from a protected system path");
}

function recoveryDescriptor(file) {
  const serializationFile = path.join(lockAuxiliaryDirectory(file), `${lockResourceKey(file)}.recovery`);
  const flags = fs.constants.O_CREAT | fs.constants.O_RDWR |
    (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_CLOEXEC || 0);
  const descriptor = fs.openSync(serializationFile, flags, 0o600);
  try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o600 ||
      typeof process.geteuid === "function" && stat.uid !== process.geteuid()) {
      throw new Error("learning ledger recovery lock is not a trusted owner-only file");
    }
    return descriptor;
  } catch (error) {
    fs.closeSync(descriptor);
    throw error;
  }
}

function recoverDeadLock(file) {
  if (process.platform !== "linux") return false;
  const descriptor = recoveryDescriptor(file);
  const script = String.raw`
const fs=require('node:fs');
const file=process.argv[1];
function proc(s){const c=s.lastIndexOf(')');if(c<0)return null;const f=s.slice(c+2).trim().split(/\s+/u);return f.length>19&&/^[A-Z]$/.test(f[0])&&/^\d+$/.test(f[19])?{state:f[0],start:f[19]}:null}
let stat;try{stat=fs.lstatSync(file)}catch(e){process.exit(e.code==='ENOENT'?0:20)}
if(!stat.isFile()||stat.isSymbolicLink()||stat.size>4096)process.exit(22);
let bytes,owner;try{bytes=fs.readFileSync(file);owner=JSON.parse(bytes.toString('utf8'))}catch{process.exit(22)}
const keys=['apiVersion','bootId','createdAt','nonce','pid','platform','startTimeTicks'];
const valid=owner&&typeof owner==='object'&&!Array.isArray(owner)&&JSON.stringify(Object.keys(owner).sort())===JSON.stringify(keys)&&
 owner.apiVersion==='gate.learning-lock/v1'&&Number.isSafeInteger(owner.pid)&&owner.pid>0&&owner.platform==='linux'&&
 /^[a-f0-9-]{36}$/.test(owner.bootId||'')&&/^\d+$/.test(owner.startTimeTicks||'')&&/^[a-f0-9]{32}$/.test(owner.nonce||'')&&
 Number.isFinite(Date.parse(owner.createdAt));
if(!valid)process.exit(22);
let boot;try{boot=fs.readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim().toLowerCase()}catch{process.exit(24)}
let dead=owner.bootId!==boot;
if(!dead){try{const now=proc(fs.readFileSync('/proc/'+owner.pid+'/stat','utf8'));dead=Boolean(now&&((now.state==='Z'||now.state==='X')||now.start!==owner.startTimeTicks))}catch(e){dead=e.code==='ENOENT'||e.code==='ESRCH'}}
if(!dead)process.exit(24);
let current;try{current=fs.readFileSync(file)}catch(e){process.exit(e.code==='ENOENT'?0:20)}
if(!current.equals(bytes))process.exit(24);
try{fs.unlinkSync(file)}catch(e){if(e.code!=='ENOENT')process.exit(20)}
`;
  let result;
  try {
    result = spawnSync(
      trustedLearningFlock(),
      ["--exclusive", "--timeout", "1", "/proc/self/fd/3", process.execPath, "-e", script, file],
      {
        stdio: ["ignore", "pipe", "pipe", descriptor],
        env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
        shell: false,
        windowsHide: true,
        timeout: 5_000,
        maxBuffer: 16 * 1024
      }
    );
  } finally {
    fs.closeSync(descriptor);
  }
  if (result.error) throw new Error(`learning ledger lock recovery failed: ${result.error.message}`);
  if (result.status === 0) return true;
  if (result.status === 24) return false;
  if (result.status === 22) throw new Error("learning ledger lock identity is malformed");
  throw new Error(`learning ledger lock recovery failed${result.status === null ? "" : ` (status ${result.status})`}`);
}

function publishLock(file, owner, bytes, options) {
  const pending = path.join(
    lockAuxiliaryDirectory(file),
    `${lockResourceKey(file)}.pending-${owner.nonce}`
  );
  let descriptor;
  let published = false;
  let acquired = false;
  try {
    descriptor = fs.openSync(pending, "wx", 0o600);
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
    if (options.beforePublish !== undefined) {
      if (typeof options.beforePublish !== "function") throw new Error("learning lock beforePublish hook must be a function");
      options.beforePublish(pending);
    }
    try {
      fs.linkSync(pending, file);
    } catch (error) {
      if (error.code === "EEXIST") return null;
      throw error;
    }
    published = true;
    const source = fs.fstatSync(descriptor);
    const target = fs.lstatSync(file);
    if (!target.isFile() || target.isSymbolicLink() || !sameFileIdentity(source, target)) {
      throw new Error("learning ledger lock publication identity changed");
    }
    acquired = true;
    return descriptor;
  } catch (error) {
    if (published && !acquired) {
      try {
        const source = descriptor === undefined ? null : fs.fstatSync(descriptor);
        const target = fs.lstatSync(file);
        if (source && sameFileIdentity(source, target)) fs.unlinkSync(file);
      } catch {
        // Preserve the publication failure; ownership checks fail closed later.
      }
    }
    throw error;
  } finally {
    try {
      fs.unlinkSync(pending);
    } catch (cleanupError) {
      if (cleanupError.code !== "ENOENT" && published) {
        try { fs.unlinkSync(file); } catch { /* Report the pending-file cleanup failure. */ }
        published = false;
        acquired = false;
      }
      if (cleanupError.code !== "ENOENT") throw cleanupError;
    } finally {
      if (!acquired && descriptor !== undefined) fs.closeSync(descriptor);
    }
  }
}

function releaseLock(file, descriptor, bytes) {
  try {
    let current;
    try { current = fs.lstatSync(file); }
    catch (error) {
      if (error.code === "ENOENT") throw new Error("learning ledger lock disappeared before release");
      throw error;
    }
    if (!sameFileIdentity(fs.fstatSync(descriptor), current)) {
      throw new Error("learning ledger lock ownership changed before release");
    }
    const observed = fs.readFileSync(file);
    if (!observed.equals(bytes)) throw new Error("learning ledger lock ownership changed before release");
    fs.unlinkSync(file);
  } finally {
    fs.closeSync(descriptor);
  }
}

function withFileLock(file, action, options = {}) {
  const timeoutMs = options.timeoutMs ?? 5_000;
  const retryMs = options.retryMs ?? 10;
  const lockFile = `${file}.lock`;
  const owner = lockOwner();
  const bytes = lockBytes(owner);
  const deadline = Date.now() + timeoutMs;
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });

  while (true) {
    const descriptor = publishLock(lockFile, owner, bytes, options);
    if (descriptor !== null) {
      try {
        return action();
      } finally {
        releaseLock(lockFile, descriptor, bytes);
      }
    }

    let observed;
    try {
      observed = readLock(lockFile);
    } catch (error) {
      if (error.code === "ENOENT") continue;
      throw error;
    }
    if (ownerProvablyDead(observed.owner) && recoverDeadLock(lockFile)) continue;

    if (Date.now() >= deadline) {
      throw new Error(`timed out waiting for learning ledger lock: ${lockFile}`);
    }
    sleep(Math.min(retryMs, Math.max(1, deadline - Date.now())));
  }
}

export function withLearningLedgerSnapshot(options = {}, action) {
  if (typeof action !== "function") throw new Error("learning ledger snapshot action must be a function");
  const paths = options.paths || runtimePaths(options);
  ensureRuntime(paths);
  return withFileLock(path.resolve(paths.publicLearningRecords), action, options.lock);
}

function withLearningLedgerLocks(paths, action, options = {}) {
  const ledgers = [...new Set([
    path.resolve(paths.privateLearnings),
    path.resolve(paths.publicLearningRecords)
  ])].sort();
  const acquire = (index) => index === ledgers.length
    ? action()
    : withFileLock(ledgers[index], () => acquire(index + 1), options);
  return acquire(0);
}

function learningLine(learning, status = learning.status) {
  const evidence = learning.evidence.join(", ");
  return `- ${learning.at.slice(0, 10)} | Cause: ${learning.cause} | Change: ${learning.change} | Evidence: ${evidence} | Status: ${status}`;
}

function readPublicRecords(file, paths) {
  if (!fs.existsSync(file)) return [];
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("public learning log must be a regular file");
  if (stat.size > MAX_LOG_BYTES) throw new Error(`public learning log exceeds the ${MAX_LOG_BYTES}-byte limit`);
  const lines = fs.readFileSync(file, "utf8")
    .split(/\r?\n/)
    .filter((line) => line.trim());
  if (lines.length > MAX_LOG_RECORDS) throw new Error(`public learning log exceeds the ${MAX_LOG_RECORDS}-record limit`);
  return lines.map((line, index) => {
      let learning;
      try {
        learning = JSON.parse(line);
      } catch {
        throw new Error(`public learning record ${index + 1} is not valid JSON`);
      }
      assertValidDocument(learning, "learning.schema.json", { paths });
      if (learning.sensitivity !== "public") {
        throw new Error(`public learning record ${index + 1} is not public`);
      }
      return learning;
    });
}

function readPrivateRecords(file, paths) {
  let text;
  try {
    text = readPrivateFileBounded(file, MAX_LOG_BYTES, "utf8", { label: "private learning log" });
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
  const lines = text.split(/\r?\n/u).filter((line) => line.trim());
  if (lines.length > MAX_LOG_RECORDS) throw new Error(`private learning log exceeds the ${MAX_LOG_RECORDS}-record limit`);
  return lines.map((line, index) => {
    let learning;
    try {
      learning = JSON.parse(line);
    } catch {
      throw new Error(`private learning record ${index + 1} is not valid JSON`);
    }
    assertValidDocument(learning, "learning.schema.json", { paths });
    if (learning.sensitivity !== "private") throw new Error(`private learning record ${index + 1} is not private`);
    return learning;
  });
}

function allRecords(paths) {
  return [...readPublicRecords(paths.publicLearningRecords, paths), ...readPrivateRecords(paths.privateLearnings, paths)];
}

function uniqueRecordIndex(records) {
  const byId = new Map();
  for (const record of records) {
    if (byId.has(record.id)) throw new Error(`learning id is duplicated: ${record.id}`);
    byId.set(record.id, record);
  }
  return byId;
}

function validateReplacementTargets(replaces, { records, byId, domain, applicability, sensitivity }) {
  const alreadyReplaced = new Set(records.flatMap((record) =>
    record.apiVersion === "gate.learning/v2" && record.promotion?.state === "validated"
      ? record.promotion.replaces || []
      : []
  ));
  for (const replacementId of replaces) {
    const replacement = byId.get(replacementId);
    if (
      !replacement ||
      replacement.apiVersion !== "gate.learning/v2" ||
      replacement.status !== "active" ||
      replacement.promotion?.state !== "validated" ||
      replacement.promotion.review?.candidateSha256 !== replacement.promotion.candidateSha256
    ) throw new Error(`replaces must reference an active validated learning: ${replacementId}`);
    if (
      replacement.domain !== domain ||
      canonicalJson(replacement.applicability) !== canonicalJson(applicability) ||
      sensitivity !== undefined && replacement.sensitivity !== sensitivity
    ) {
      const qualifier = sensitivity === undefined ? "domain and applicability" : "sensitivity, domain, and applicability";
      throw new Error(`replaces must reference a learning with the same ${qualifier}: ${replacementId}`);
    }
    if (alreadyReplaced.has(replacementId)) {
      throw new Error(`replaces must reference currently effective guidance: ${replacementId}`);
    }
  }
}

function renderLedger(learnings) {
  const replacedIds = new Set(learnings.flatMap((learning) =>
    learning.apiVersion === "gate.learning/v2" && learning.promotion?.state === "validated"
      ? learning.promotion.replaces || []
      : []
  ));
  const active = learnings
    .filter((learning) => learning.status === "active" && !replacedIds.has(learning.id))
    .map((learning) => learningLine(learning));
  const proposed = learnings.filter((learning) => learning.status === "proposed").map((learning) => learningLine(learning));
  const historical = learnings
    .filter((learning) => ["superseded", "reverted"].includes(learning.status) || replacedIds.has(learning.id))
    .map((learning) => learningLine(learning, replacedIds.has(learning.id) ? "superseded" : learning.status));
  return `${LEDGER_PREAMBLE}
## Active

${active.join("\n")}

## Proposed

Add proposed lessons here only after removing sensitive context. Promotion must include the behavior, policy, configuration, test, or documentation change that makes the lesson real.
${proposed.join("\n")}

## Superseded or reverted

Move old entries here with the new evidence and replacement learning. Do not erase history.
${historical.join("\n")}
`;
}

function writeAtomically(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temporary = path.join(
    path.dirname(file),
    `.${path.basename(file)}.${process.pid}.${Math.random().toString(16).slice(2)}.tmp`
  );
  try {
    fs.writeFileSync(temporary, content, { encoding: "utf8", mode: 0o644, flag: "wx" });
    fs.renameSync(temporary, file);
  } finally {
    fs.rmSync(temporary, { force: true });
  }
}

function appendPublicLearningUnlocked(paths, learning) {
  const current = readPublicRecords(paths.publicLearningRecords, paths);
  if (current.some((record) => record.id === learning.id)) throw new Error(`learning id already exists: ${learning.id}`);
  const learnings = [...current, learning];
  appendJsonLine(paths.publicLearningRecords, learning, 0o644);
  writeAtomically(paths.publicLearnings, renderLedger(learnings));
}

function appendPrivateLearningUnlocked(paths, learning) {
  const current = readPrivateRecords(paths.privateLearnings, paths);
  if (current.some((record) => record.id === learning.id)) throw new Error(`learning id already exists: ${learning.id}`);
  appendJsonLine(paths.privateLearnings, learning);
}

function auditSummary(learning, action) {
  if (learning.sensitivity === "private") return `Private learning ${action}.`;
  const text = `${learning.cause} → ${learning.change}`;
  return text.length <= 500 ? text : `${learning.cause.slice(0, 240)} → ${learning.change.slice(0, 240)}`;
}

function persistValidatedLearning(learning, options, evidenceEventId) {
  const { paths } = options;
  const persist = () => {
    const records = allRecords(paths);
    const byId = uniqueRecordIndex(records);
    if (byId.has(learning.id)) {
      throw new Error("learning id already exists across the learning ledgers");
    }
    if (options.validateRecords) options.validateRecords(records, byId);
    recordEvent({
      id: evidenceEventId,
      kind: "learning.observed",
      summary: auditSummary(learning, "observed")
    }, { paths });
    if (learning.sensitivity === "private") appendPrivateLearningUnlocked(paths, learning);
    else appendPublicLearningUnlocked(paths, learning);
    recordEvent({
      kind: "learning.recorded",
      summary: auditSummary(learning, "recorded"),
      evidenceRefs: [`event://${evidenceEventId}`]
    }, { paths });
    return learning;
  };
  if (options.ledgersLocked) return persist();
  return withLearningLedgerLocks(paths, persist, options.lock);
}

export function addLearning(input, options = {}) {
  const paths = options.paths || runtimePaths(options);
  ensureRuntime(paths);
  const cause = oneLine(input.cause, { name: "cause", max: 500 });
  const change = oneLine(input.change, { name: "change", max: 500 });
  assertNoLikelySecret(cause, "cause");
  assertNoLikelySecret(change, "change");
  const sensitivity = normalizeSensitivity(input.sensitivity, "public");
  const scope = normalizeScope(input.scope, sensitivity);
  const status = input.status || (sensitivity === "private" ? "active" : "proposed");
  if (!["proposed", "active", "superseded", "reverted"].includes(status)) {
    throw new Error("status must be proposed, active, superseded, or reverted");
  }
  const evidenceEventId = newId("evt");
  const evidence = Array.isArray(input.evidence) && input.evidence.length
    ? input.evidence
    : [`event://${evidenceEventId}`];
  const learning = {
    apiVersion: "gate.learning/v1",
    id: input.id || newId("lrn"),
    at: input.at || new Date().toISOString(),
    scope,
    cause,
    change,
    evidence,
    status,
    sensitivity,
    supersedes: input.supersedes || null,
    configurationRefs: Array.isArray(input.configurationRefs) ? input.configurationRefs : []
  };
  // Validate the complete record before emitting its observed audit event.
  assertValidDocument(learning, "learning.schema.json", { paths });
  if (sensitivity === "public") assertPublicLearningSafe(learning, paths);
  return persistValidatedLearning(learning, { ...options, paths }, evidenceEventId);
}

export function addLearningCycle(input, options = {}) {
  const paths = options.paths || runtimePaths(options);
  ensureRuntime(paths);
  if (input.status !== undefined && input.status !== "proposed") {
    throw new Error("structured learning cycles are proposed candidates; promote after validation");
  }
  if (input.supersedes !== undefined && input.supersedes !== null) {
    throw new Error("structured learning candidates cannot supersede another record");
  }
  if (input.promotion !== undefined) throw new Error("promotion metadata is controlled by GATE");
  if (input.sensitivity !== undefined && input.sensitivity !== "private") {
    throw new Error("structured learning candidates must remain private until promotion");
  }
  const cycle = normalizeCycle(input.cycle);
  const trigger = String(input.trigger || "");
  if (!TOKEN_PATTERN.test(trigger)) throw new Error("trigger must be a lowercase kebab token");
  const domain = String(input.domain || "");
  if (!LEARNING_DOMAINS.has(domain)) throw new Error("domain is invalid");
  const applicability = normalizeApplicability(input.applicability);
  const replaces = normalizeReplacementIds(input.replaces);
  const sensitivity = "private";
  const scope = normalizeScope(input.scope, sensitivity);
  const cause = input.cause === undefined
    ? cycle.outcome.summary : oneLine(input.cause, { name: "cause", max: 500 });
  const change = input.change === undefined
    ? cycle.nextAdjustment : oneLine(input.change, { name: "change", max: 500 });
  assertNoLikelySecret(cause, "cause");
  assertNoLikelySecret(change, "change");
  const evidenceEventId = newId("evt");
  const evidence = Array.isArray(input.evidence) && input.evidence.length
    ? normalizeEvidenceRefs(input.evidence, "evidence", { minimum: 1 })
    : [`event://${evidenceEventId}`];
  const learning = {
    apiVersion: "gate.learning/v2",
    id: input.id || newId("lrn"),
    at: input.at || new Date().toISOString(),
    scope,
    cause,
    change,
    evidence,
    status: "proposed",
    sensitivity,
    supersedes: null,
    configurationRefs: normalizeConfigurationRefs(input.configurationRefs),
    trigger,
    domain,
    cycle,
    applicability,
    promotion: {
      state: "candidate",
      candidateId: null,
      candidateSha256: null,
      validatedAt: null,
      validationRefs: [],
      changeRefs: [],
      review: null,
      conflictsWith: [],
      replaces
    }
  };
  assertV2Lifecycle(learning);
  assertValidDocument(learning, "learning.schema.json", { paths });
  return persistValidatedLearning(learning, {
    ...options,
    paths,
    validateRecords(records, byId) {
      validateReplacementTargets(replaces, { records, byId, domain, applicability });
    }
  }, evidenceEventId);
}

export function promoteLearning(candidateId, input = {}, options = {}) {
  const paths = options.paths || runtimePaths(options);
  ensureRuntime(paths);
  if (!LEARNING_ID_PATTERN.test(String(candidateId || ""))) throw new Error("candidate learning id is invalid");
  assertPromotionInput(input);
  return withLearningLedgerLocks(paths, () => {
    // Promotion decisions use a single cross-ledger snapshot held through the
    // append, so concurrent writers cannot validate the same candidate twice.
    const records = allRecords(paths);
    const byId = uniqueRecordIndex(records);
    const candidate = byId.get(candidateId);
    if (!candidate) throw new Error(`learning candidate does not exist: ${candidateId}`);
    if (
      candidate.apiVersion !== "gate.learning/v2" ||
      candidate.status !== "proposed" ||
      candidate.promotion?.state !== "candidate"
    ) throw new Error("only a proposed gate.learning/v2 candidate can be promoted");
    const existing = records.find((record) =>
      record.apiVersion === "gate.learning/v2" &&
      record.promotion?.state === "validated" &&
      record.promotion.candidateId === candidateId
    );
    if (existing) throw new Error(`learning candidate is already promoted by ${existing.id}`);

    const candidateSha256 = learningCandidateSha256(candidate);
    const validationRefs = normalizeEvidenceRefs(input.validationRefs, "validationRefs", { minimum: 1 });
    const changeRefs = normalizeEvidenceRefs(input.changeRefs, "changeRefs", { minimum: 1, change: true });
    const review = normalizeReviewAttestation(input.review, candidateSha256);
    const conflictsWith = normalizeConflictIds(input.conflictsWith);
    const replaces = structuredClone(candidate.promotion.replaces);
    const sensitivity = normalizeSensitivity(input.sensitivity, candidate.sensitivity);
    const scope = normalizeScope(
      input.scope || (sensitivity === "public" ? "repository" : candidate.scope),
      sensitivity
    );
    if (sensitivity === "public" && scope !== "repository") {
      throw new Error("public promoted learning must use repository scope");
    }
    if (sensitivity === "public") assertPublicLearningSafe(candidate, paths);

    const replacementTargets = new Set(replaces);
    if (conflictsWith.some((id) => replacementTargets.has(id))) {
      throw new Error("a learning cannot both conflict with and replace the same active learning");
    }

    validateReplacementTargets(replaces, {
      records,
      byId,
      domain: candidate.domain,
      applicability: candidate.applicability,
      sensitivity
    });

    for (const conflictId of conflictsWith) {
      const conflicting = byId.get(conflictId);
      if (
        !conflicting ||
        conflicting.apiVersion !== "gate.learning/v2" ||
        conflicting.status !== "active" ||
        conflicting.promotion?.state !== "validated" ||
        conflicting.promotion.review?.candidateSha256 !== conflicting.promotion.candidateSha256
      ) throw new Error(`conflictsWith must reference an active validated learning: ${conflictId}`);
      if (
        conflicting.sensitivity !== sensitivity ||
        conflicting.domain !== candidate.domain ||
        canonicalJson(conflicting.applicability) !== canonicalJson(candidate.applicability)
      ) throw new Error(`conflictsWith must reference a learning with the same sensitivity, domain, and applicability: ${conflictId}`);
    }
    const evidence = input.evidence === undefined
      ? validationRefs : normalizeEvidenceRefs(input.evidence, "evidence", { minimum: 1 });
    const at = input.at || new Date().toISOString();
    const promotionId = input.id || newId("lrn");
    if (byId.has(promotionId)) {
      throw new Error("promotion learning id already exists across the learning ledgers");
    }
    const learning = {
      apiVersion: "gate.learning/v2",
      id: promotionId,
      at,
      scope,
      cause: candidate.cause,
      change: candidate.change,
      evidence,
      status: "active",
      sensitivity,
      supersedes: candidate.id,
      configurationRefs: structuredClone(candidate.configurationRefs),
      trigger: candidate.trigger,
      domain: candidate.domain,
      cycle: structuredClone(candidate.cycle),
      applicability: structuredClone(candidate.applicability),
      promotion: {
        state: "validated",
        candidateId: candidate.id,
        candidateSha256,
        validatedAt: at,
        validationRefs,
        changeRefs,
        review,
        conflictsWith,
        replaces
      }
    };
    assertV2Lifecycle(learning);
    assertValidDocument(learning, "learning.schema.json", { paths });
    if (sensitivity === "public") assertPublicLearningSafe(learning, paths);
    return persistValidatedLearning(
      learning,
      { ...options, paths, ledgersLocked: true },
      newId("evt")
    );
  }, options.lock);
}

function applicabilitySha256(applicability) {
  return digest(applicability, "gate.learning.applicability.v1");
}

function v2Projection(record) {
  return {
    id: record.id,
    apiVersion: record.apiVersion,
    domain: record.domain,
    trigger: record.trigger,
    lesson: record.cycle.lesson,
    nextAdjustment: record.cycle.nextAdjustment,
    applicabilitySha256: applicabilitySha256(record.applicability),
    validatedAt: record.promotion.validatedAt
  };
}

function sealConsultation(envelope) {
  return {
    ...envelope,
    projectionSha256: digest(envelope, "gate.learning.consultation.v1")
  };
}

function consultationBytes(envelope) {
  return Buffer.byteLength(JSON.stringify(sealConsultation(envelope)));
}

function consultLearningsWithRecords(input = {}, options = {}, suppliedRecords = null) {
  const paths = options.paths || runtimePaths(options);
  ensureRuntime(paths);
  const applicability = normalizeApplicability(input.applicability);
  const limit = input.limit === undefined ? DEFAULT_CONSULT_LIMIT : Number(input.limit);
  const maxBytes = input.maxBytes === undefined ? DEFAULT_CONSULT_BYTES : Number(input.maxBytes);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > DEFAULT_CONSULT_LIMIT) {
    throw new Error(`consult limit must be between 1 and ${DEFAULT_CONSULT_LIMIT}`);
  }
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 512 || maxBytes > DEFAULT_CONSULT_BYTES) {
    throw new Error(`consult maxBytes must be between 512 and ${DEFAULT_CONSULT_BYTES}`);
  }

  const records = suppliedRecords === null
    ? readPublicRecords(paths.publicLearningRecords, paths)
    : suppliedRecords;
  uniqueRecordIndex(records);
  const matchingV2 = records.filter((record) =>
    record.apiVersion === "gate.learning/v2" &&
    record.sensitivity === "public" &&
    record.scope === "repository" &&
    record.status === "active" &&
    record.promotion?.state === "validated" &&
    record.supersedes === record.promotion.candidateId &&
    record.promotion.review?.candidateSha256 === record.promotion.candidateSha256 &&
    canonicalJson(record.applicability) === canonicalJson(applicability) &&
    publicLearningIsSafe(record, paths)
  );

  // Replacement edges are immutable. Following all reviewed edges keeps the
  // full history while excluding every ancestor in a replacement chain.
  const replacedIds = new Set(matchingV2.flatMap((record) => record.promotion.replaces || []));
  const effectiveV2 = matchingV2.filter((record) => !replacedIds.has(record.id));
  const matchingById = new Map(effectiveV2.map((record) => [record.id, record]));
  const conflictEdges = new Map(effectiveV2.map((record) => [record.id, new Set()]));
  for (const record of effectiveV2) {
    for (const conflictId of record.promotion.conflictsWith || []) {
      const conflicting = matchingById.get(conflictId);
      if (!conflicting || conflicting.domain !== record.domain) continue;
      conflictEdges.get(record.id).add(conflictId);
      conflictEdges.get(conflictId).add(record.id);
    }
  }
  const visited = new Set();
  const conflictGroups = [];
  for (const record of effectiveV2) {
    if (visited.has(record.id) || conflictEdges.get(record.id).size === 0) continue;
    const pending = [record.id];
    const learningIds = [];
    while (pending.length) {
      const id = pending.pop();
      if (visited.has(id)) continue;
      visited.add(id);
      learningIds.push(id);
      pending.push(...conflictEdges.get(id));
    }
    conflictGroups.push({ record, learningIds: learningIds.sort() });
  }
  const conflicts = conflictGroups.map(({ record, learningIds }) => ({
    domain: record.domain,
    applicabilitySha256: applicabilitySha256(record.applicability),
    learningIds
  })).sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
  const conflictedIds = new Set(conflicts.flatMap((conflict) => conflict.learningIds));
  const candidates = effectiveV2.filter((record) => !conflictedIds.has(record.id)).map(v2Projection);

  candidates.sort((left, right) =>
    right.validatedAt.localeCompare(left.validatedAt) ||
    left.domain.localeCompare(right.domain) ||
    left.id.localeCompare(right.id)
  );

  let envelope = {
    apiVersion: "gate.learning-consultation/v1",
    applicabilitySha256: applicabilitySha256(applicability),
    ledgerHeadSha256: digest(records, "gate.learning.public-ledger.v1"),
    selected: [],
    conflicts: conflicts.slice(0, 8),
    truncation: {
      truncated: candidates.length > 0 || conflicts.length > 8,
      omittedLearnings: candidates.length,
      omittedConflicts: Math.max(0, conflicts.length - 8)
    }
  };
  while (consultationBytes(envelope) > maxBytes && envelope.conflicts.length) {
    envelope.conflicts.pop();
    envelope.truncation.omittedConflicts += 1;
    envelope.truncation.truncated = true;
  }
  for (const candidate of candidates.slice(0, limit)) {
    const next = {
      ...envelope,
      selected: [...envelope.selected, candidate],
      truncation: {
        ...envelope.truncation,
        omittedLearnings: candidates.length - envelope.selected.length - 1,
        truncated: candidates.length - envelope.selected.length - 1 > 0 ||
          envelope.truncation.omittedConflicts > 0
      }
    };
    if (consultationBytes(next) > maxBytes) break;
    envelope = next;
  }
  envelope = {
    ...envelope,
    truncation: {
      ...envelope.truncation,
      omittedLearnings: candidates.length - envelope.selected.length,
      truncated: candidates.length > envelope.selected.length || envelope.truncation.omittedConflicts > 0
    }
  };
  const result = sealConsultation(envelope);
  if (Buffer.byteLength(JSON.stringify(result)) > maxBytes) {
    throw new Error("learning consultation metadata exceeds the requested byte limit");
  }
  return result;
}

export function consultLearnings(input = {}, options = {}) {
  return consultLearningsWithRecords(input, options);
}

function publicLedgerPrefix(records, ledgerHeadSha256) {
  const hash = crypto.createHash("sha256").update("gate.learning.public-ledger.v1\0[");
  if (hash.copy().update("]").digest("hex") === ledgerHeadSha256) return [];
  for (let index = 0; index < records.length; index += 1) {
    if (index > 0) hash.update(",");
    hash.update(canonicalJson(records[index]));
    if (hash.copy().update("]").digest("hex") === ledgerHeadSha256) {
      return records.slice(0, index + 1);
    }
  }
  return null;
}

export function verifyLearningConsultationSnapshot(snapshot, options = {}) {
  if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) {
    throw new Error("learning consultation snapshot must be an object");
  }
  if (Object.keys(snapshot).some((key) => ![
    "applicability", "learningIds", "ledgerHeadSha256", "projectionSha256"
  ].includes(key))) {
    throw new Error("learning consultation snapshot contains an unknown field");
  }
  const paths = options.paths || runtimePaths(options);
  ensureRuntime(paths);
  const applicability = normalizeApplicability(snapshot.applicability);
  const learningIds = normalizeLearningIds(snapshot.learningIds, "learningIds", { sort: false });
  if (learningIds.length > DEFAULT_CONSULT_LIMIT) {
    throw new Error(`learningIds must contain ${DEFAULT_CONSULT_LIMIT} learning ids or fewer`);
  }
  const ledgerHeadSha256 = String(snapshot.ledgerHeadSha256 || "");
  const projectionSha256 = String(snapshot.projectionSha256 || "");
  if (!SHA256_PATTERN.test(ledgerHeadSha256)) {
    throw new Error("learning consultation ledger head must be a lowercase SHA-256 digest");
  }
  if (!SHA256_PATTERN.test(projectionSha256)) {
    throw new Error("learning consultation projection must be a lowercase SHA-256 digest");
  }
  const currentRecords = readPublicRecords(paths.publicLearningRecords, paths);
  const records = publicLedgerPrefix(currentRecords, ledgerHeadSha256);
  if (records === null) throw new Error("learning consultation ledger head does not name a retained public-ledger prefix");
  const consultation = consultLearningsWithRecords({ applicability }, { paths }, records);
  if (consultation.conflicts.length || consultation.truncation.omittedConflicts > 0) {
    throw new Error("learning consultation snapshot contains unresolved conflicts");
  }
  if (consultation.truncation.omittedLearnings > 0) {
    throw new Error("learning consultation snapshot omits applicable guidance");
  }
  if (canonicalJson(consultation.selected.map((learning) => learning.id)) !== canonicalJson(learningIds)) {
    throw new Error("learning consultation snapshot learning ids do not match the historical projection");
  }
  if (consultation.ledgerHeadSha256 !== ledgerHeadSha256 || consultation.projectionSha256 !== projectionSha256) {
    throw new Error("learning consultation snapshot digest does not match the historical projection");
  }
  return consultation;
}

export const learningInternals = Object.freeze({
  applicabilitySha256,
  canonicalJson,
  learningDigest
});
