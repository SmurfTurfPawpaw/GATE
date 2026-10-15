import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { verifyProgramProfile } from "./bounty-profiles.mjs";
import { ensureRuntime, runtimePaths } from "./paths.mjs";
import {
  readPrivateFileBounded,
  securePrivateDirectory,
  securePrivateFile,
  syncPrivateDirectory,
  writePrivateFileExclusive
} from "./private-fs.mjs";
import { projectContractBinding } from "./projects.mjs";
import { assertValidDocument } from "./schema.mjs";

const CASE_ID = /^[a-z][a-z0-9-]{1,62}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const DISPLAY_NAME = /^[A-Za-z][A-Za-z0-9 .'-]{0,59}$/u;
const MAX_CASE_BYTES = 64 * 1024;
const MAX_CASE_SCAN = 32;
const MAX_CASE_DISCOVERY = 1024;
const MAX_CASE_BINDING_BYTES = 1024;
const CASE_SCHEMA = "https://gate.local/schemas/case.schema.json";
const ISOLATION = Object.freeze({
  stateNamespace: "isolated-directory",
  processBoundary: "shared-user",
  networkBoundary: "adapter-dependent"
});

function caseId(value) {
  if (typeof value !== "string" || !CASE_ID.test(value)) {
    throw new Error("case id must start with a letter and contain only lowercase letters, numbers, or dashes");
  }
  return value;
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
}

function canonicalText(value) {
  return `${JSON.stringify(stableValue(value), null, 2)}\n`;
}

function digest(value) {
  return crypto.createHash("sha256").update(canonicalText(value), "utf8").digest("hex");
}

function scopeEnvelope(value) {
  const copy = structuredClone(value);
  delete copy.scopeSha256;
  return copy;
}

function scopeDigest(value) {
  return digest(scopeEnvelope(value));
}

function baseRuntimePaths(options = {}) {
  const supplied = options.paths || runtimePaths(options);
  if (!supplied?.home || !supplied?.repo) throw new Error("case storage requires GATE_HOME and the GATE repository");
  return runtimePaths({ home: supplied.home, repo: supplied.repo });
}

function ensureCaseRoot(paths) {
  ensureRuntime(paths);
  securePrivateDirectory(paths.cases, { label: "private case registry" });
}

function caseDirectory(paths, id) {
  return path.join(paths.cases, caseId(id));
}

function caseScopeFile(paths, id) {
  return path.join(caseDirectory(paths, id), "scope.json");
}

function caseStateDirectory(paths, id) {
  return path.join(caseDirectory(paths, id), "state");
}

function exactObject(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} must contain exactly ${expected.join(" and ")}`);
  }
  return value;
}

function binding(value, digestKey, label) {
  const normalized = exactObject(value, ["id", digestKey], label);
  const id = caseId(normalized.id);
  const sha256 = normalized[digestKey];
  if (typeof sha256 !== "string" || !SHA256.test(sha256)) {
    throw new Error(`${label} ${digestKey} must be a lowercase SHA-256 digest`);
  }
  return { id, [digestKey]: sha256 };
}

function currentProgramBinding(program, paths, options = {}) {
  try {
    const verification = verifyProgramProfile(program.id, { paths, now: options.now });
    return verification.ok === true && verification.structuralValid === true && verification.ready === true &&
      verification.profileSha256 === program.profileSha256;
  } catch {
    return false;
  }
}

function currentProjectBinding(project, paths) {
  if (project === null) return true;
  try {
    const current = projectContractBinding(project.id, { paths });
    return current.contractSha256 === project.contractSha256;
  } catch {
    return false;
  }
}

function assertCurrentBindings(record, paths, options = {}) {
  if (!currentProgramBinding(record.program, paths, options)) {
    throw new Error("case program-profile binding is stale or not ready");
  }
  if (!currentProjectBinding(record.project, paths)) {
    throw new Error("case managed-project binding is stale or invalid");
  }
}

function bindingHealth(record, paths, options = {}) {
  const programCurrent = currentProgramBinding(record.program, paths, options);
  const projectCurrent = currentProjectBinding(record.project, paths);
  return {
    status: programCurrent && projectCurrent ? "ready" : "stale",
    programCurrent,
    projectCurrent
  };
}

function stateBinding(record) {
  return { caseId: record.metadata.id, scopeSha256: record.scopeSha256 };
}

function assertStateBinding(paths, record) {
  const file = path.join(caseStateDirectory(paths, record.metadata.id), ".case-binding.json");
  securePrivateFile(file, { allowMissing: false, label: `private case state binding ${record.metadata.id}` });
  let marker;
  try {
    marker = JSON.parse(readPrivateFileBounded(
      file,
      MAX_CASE_BINDING_BYTES,
      "utf8",
      { label: `private case state binding ${record.metadata.id}` }
    ));
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error(`case state-root binding is not valid JSON: ${record.metadata.id}`, { cause: error });
    throw error;
  }
  if (
    !marker || typeof marker !== "object" || Array.isArray(marker) ||
    Object.keys(marker).sort().join(",") !== "caseId,scopeSha256" ||
    marker.caseId !== record.metadata.id || marker.scopeSha256 !== record.scopeSha256
  ) throw new Error(`case state-root binding does not match its immutable scope: ${record.metadata.id}`);
}

function readCaseRecord(paths, id) {
  const cleanId = caseId(id);
  const directory = caseDirectory(paths, cleanId);
  securePrivateDirectory(directory, { create: false, label: `private case ${cleanId}` });
  securePrivateDirectory(caseStateDirectory(paths, cleanId), {
    create: false,
    label: `private case state ${cleanId}`
  });
  const file = caseScopeFile(paths, cleanId);
  securePrivateFile(file, { allowMissing: false, label: `private case scope ${cleanId}` });
  let value;
  try {
    value = JSON.parse(readPrivateFileBounded(
      file,
      MAX_CASE_BYTES,
      "utf8",
      { label: `private case scope ${cleanId}` }
    ));
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error(`case scope is not valid JSON: ${cleanId}`, { cause: error });
    throw error;
  }
  assertValidDocument(value, "case.schema.json", { paths });
  if (value.metadata.id !== cleanId) throw new Error("case scope id does not match its directory");
  if (value.scopeSha256 !== scopeDigest(value)) throw new Error("case scope digest changed");
  assertStateBinding(paths, value);
  return value;
}

function scanCaseNames(paths) {
  const names = [];
  const directory = fs.opendirSync(paths.cases);
  try {
    while (names.length <= MAX_CASE_DISCOVERY) {
      const entry = directory.readSync();
      if (!entry) break;
      names.push(entry.name);
    }
  } finally {
    directory.closeSync();
  }
  const discoveryTruncated = names.length > MAX_CASE_DISCOVERY;
  const discoveredNames = names.slice(0, MAX_CASE_DISCOVERY).sort();
  const selected = discoveredNames.slice(0, MAX_CASE_SCAN);
  const discovered = discoveryTruncated ? MAX_CASE_DISCOVERY + 1 : discoveredNames.length;
  const omitted = Math.max(0, discovered - selected.length);
  return {
    names: selected,
    scan: {
      limit: MAX_CASE_SCAN,
      discoveryLimit: MAX_CASE_DISCOVERY,
      discovered,
      scanned: selected.length,
      omitted,
      discoveredAtLeast: discoveryTruncated,
      omittedAtLeast: discoveryTruncated,
      complete: !discoveryTruncated && omitted === 0,
      truncated: discoveryTruncated || omitted > 0,
      invalid: 0
    }
  };
}

function invalidCase(name) {
  return {
    id: CASE_ID.test(name) ? name : null,
    displayName: null,
    status: "invalid",
    binding: null,
    isolation: null,
    scopeSha256: null
  };
}

function fleetRecord(record, paths, options = {}) {
  const health = bindingHealth(record, paths, options);
  return {
    id: record.metadata.id,
    displayName: record.metadata.displayName,
    status: health.status,
    binding: {
      program: { ...record.program, current: health.programCurrent },
      project: record.project === null ? null : { ...record.project, current: health.projectCurrent }
    },
    isolation: { ...record.isolation },
    scopeSha256: record.scopeSha256
  };
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function rollbackCreatedCaseDirectory(paths, directory, createdIdentity) {
  let current;
  try {
    current = fs.lstatSync(directory);
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
  if (!current.isDirectory() || current.isSymbolicLink() || !sameIdentity(current, createdIdentity)) return false;
  const quarantine = path.join(paths.cases, `.rollback-${crypto.randomUUID()}`);
  fs.renameSync(directory, quarantine);
  const moved = fs.lstatSync(quarantine);
  if (!moved.isDirectory() || moved.isSymbolicLink() || !sameIdentity(moved, createdIdentity)) return false;
  fs.rmSync(quarantine, { recursive: true, force: true });
  syncPrivateDirectory(paths.cases, { label: "private case registry" });
  return true;
}

export function createCase(id, input, options = {}) {
  const cleanId = caseId(id);
  const paths = baseRuntimePaths(options);
  ensureCaseRoot(paths);
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("case input must be an object");
  if (typeof input.displayName !== "string" || !DISPLAY_NAME.test(input.displayName)) {
    throw new Error("case display name must be 1-60 characters, start with a letter, and contain only letters, numbers, spaces, dot, apostrophe, or dash");
  }
  const displayName = input.displayName;
  const program = binding(input.program, "profileSha256", "case program binding");
  const project = input.project === undefined || input.project === null
    ? null
    : binding(input.project, "contractSha256", "case project binding");
  if (!currentProgramBinding(program, paths, options)) {
    throw new Error("case program-profile binding must name the exact current ready profile");
  }
  if (!currentProjectBinding(project, paths)) {
    throw new Error("case project binding must name the exact current managed project");
  }

  const at = options.now instanceof Date
    ? options.now
    : new Date(typeof options.now === "function" ? options.now() : options.now || Date.now());
  if (!Number.isFinite(at.getTime())) throw new Error("case creation time must be valid");
  const record = {
    $schema: CASE_SCHEMA,
    apiVersion: "gate.dev/case/v1",
    kind: "Case",
    metadata: { id: cleanId, displayName, createdAt: at.toISOString() },
    program,
    project,
    isolation: { ...ISOLATION },
    scopeSha256: "0".repeat(64)
  };
  record.scopeSha256 = scopeDigest(record);
  assertValidDocument(record, "case.schema.json", { paths });
  const serialized = canonicalText(record);
  if (Buffer.byteLength(serialized, "utf8") > MAX_CASE_BYTES) throw new Error("case scope exceeds its byte limit");

  const directory = caseDirectory(paths, cleanId);
  try {
    fs.mkdirSync(directory, { mode: 0o700 });
  } catch (error) {
    if (error.code === "EEXIST") throw new Error(`case already exists: ${cleanId}`);
    throw error;
  }
  const createdIdentity = fs.lstatSync(directory);
  let createdComplete = false;
  try {
    securePrivateDirectory(directory, { create: false, label: `private case ${cleanId}` });
    const stateDirectory = caseStateDirectory(paths, cleanId);
    securePrivateDirectory(stateDirectory, { label: `private case state ${cleanId}` });
    writePrivateFileExclusive(
      path.join(stateDirectory, ".case-binding.json"),
      canonicalText(stateBinding(record)),
      { label: `private case state binding ${cleanId}` }
    );
    syncPrivateDirectory(stateDirectory, { label: `private case state ${cleanId}` });
    // The first check protects record construction; this final check is
    // intentionally adjacent to publication so a changed source binding can
    // never be silently admitted into a newly immutable case scope.
    assertCurrentBindings(record, paths, options);
    writePrivateFileExclusive(caseScopeFile(paths, cleanId), serialized, { label: `private case scope ${cleanId}` });
    const scopedPaths = runtimePaths({ home: paths.home, repo: paths.repo, caseId: cleanId });
    ensureRuntime(scopedPaths);
    syncPrivateDirectory(directory, { label: `private case ${cleanId}` });
    syncPrivateDirectory(paths.cases, { label: "private case registry" });
    createdComplete = true;
  } finally {
    if (!createdComplete) rollbackCreatedCaseDirectory(paths, directory, createdIdentity);
  }
  return { created: true, case: record };
}

export function showCase(id, options = {}) {
  const paths = baseRuntimePaths(options);
  ensureCaseRoot(paths);
  return readCaseRecord(paths, id);
}

export function listCases(options = {}) {
  const paths = baseRuntimePaths(options);
  ensureCaseRoot(paths);
  const result = scanCaseNames(paths);
  let invalid = 0;
  const cases = result.names.map((name) => {
    if (!CASE_ID.test(name)) {
      invalid += 1;
      return invalidCase(name);
    }
    try {
      return readCaseRecord(paths, name);
    } catch {
      invalid += 1;
      return invalidCase(name);
    }
  });
  return {
    cases,
    scan: { ...result.scan, invalid, complete: result.scan.complete && invalid === 0 }
  };
}

export function openCaseRuntime(id, options = {}) {
  const paths = baseRuntimePaths(options);
  ensureCaseRoot(paths);
  const record = readCaseRecord(paths, id);
  const scopedPaths = runtimePaths({ home: paths.home, repo: paths.repo, caseId: record.metadata.id });
  ensureRuntime(scopedPaths);
  const currentRecord = readCaseRecord(paths, record.metadata.id);
  if (currentRecord.scopeSha256 !== record.scopeSha256) throw new Error("case scope changed during selection");
  const health = bindingHealth(currentRecord, paths, options);
  return {
    case: currentRecord,
    paths: scopedPaths,
    caseRef: { id: currentRecord.metadata.id, scopeSha256: currentRecord.scopeSha256 },
    bindingHealth: health
  };
}

export function selectCaseRuntime(id, options = {}) {
  const opened = openCaseRuntime(id, options);
  if (!opened.bindingHealth.programCurrent) {
    throw new Error("case program-profile binding is stale or not ready");
  }
  if (!opened.bindingHealth.projectCurrent) {
    throw new Error("case managed-project binding is stale or invalid");
  }
  return { case: opened.case, paths: opened.paths };
}

export function caseFleetStatus(options = {}) {
  const paths = baseRuntimePaths(options);
  ensureCaseRoot(paths);
  const result = scanCaseNames(paths);
  let invalid = 0;
  const cases = result.names.map((name) => {
    if (!CASE_ID.test(name)) {
      invalid += 1;
      return invalidCase(name);
    }
    try {
      return fleetRecord(readCaseRecord(paths, name), paths, options);
    } catch {
      invalid += 1;
      return invalidCase(name);
    }
  });
  return {
    cases,
    scan: { ...result.scan, invalid, complete: result.scan.complete && invalid === 0 }
  };
}
