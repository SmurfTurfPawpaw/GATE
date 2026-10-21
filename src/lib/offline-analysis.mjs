import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";

import { recordEvent } from "./events.mjs";
import { ensureRuntime, runtimePaths } from "./paths.mjs";
import {
  openPrivateFile,
  openPrivateFileExclusive,
  readPrivateFileBounded,
  securePrivateDirectory,
  syncPrivateDirectory,
  writePrivateFileAtomic,
  writePrivateFileExclusive
} from "./private-fs.mjs";
import { projectContractBinding } from "./projects.mjs";
import { assertValidDocument } from "./schema.mjs";
import { readUpstreamLock, resolveUpstreamBinary } from "./upstreams.mjs";

const MAX_ARTIFACT_BYTES = 512 * 1024 * 1024;
const MAX_EVIDENCE_BYTES = 64 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 2 * 1024 * 1024;
const MAX_CREATION_PUBLICATION_BYTES = Math.ceil(MAX_MANIFEST_BYTES * 4 / 3) + 64 * 1024;
const MAX_RUN_BYTES = 512 * 1024;
const MAX_CLAIM_BYTES = 64 * 1024;
const MAX_PURGE_BYTES = 128 * 1024;
const MAX_RETAINED_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_RETAINED_ARTIFACTS = 64;
const MAX_RECENT_OFFLINE_ANALYSES = 25;
const MANIFEST_TTL_MS = 15 * 60_000;
const TERMINATION_GRACE_MS = 1_000;
const RETENTION_LOCK_TIMEOUT_MS = 5_000;
const ADAPTER_ID = "rea-inspect-pe-resources-v1";
const ADAPTER_MAX_ENTRIES = 16_384;
const isolationProbeCache = new Map();
const retentionWaitBuffer = new Int32Array(new SharedArrayBuffer(4));

export const OFFLINE_ANALYSIS_ENFORCED = Object.freeze([
  "project-contract-binding",
  "typed-path-binding",
  "artifact-snapshot-sha256",
  "pinned-upstream-integrity",
  "fixed-adapter-argv",
  "bubblewrap-network-namespace",
  "read-only-runtime-mounts",
  "ephemeral-sandbox-writes",
  "shell-disabled",
  "cleared-environment",
  "private-bounded-evidence",
  "one-shot-claim",
  "wall-duration"
]);

export const OFFLINE_ANALYSIS_UNAVAILABLE = Object.freeze([
  "cpu-limit",
  "memory-limit",
  "immutable-managed-upstream-snapshot",
  "same-uid-gate-home-tamper-resistance",
  "unix-socket-system-call-denial"
]);

const SANDBOX_ENVIRONMENT = Object.freeze({
  HOME: "/home/gate",
  TMPDIR: "/tmp",
  PATH: "/opt/gate/node:/usr/bin:/bin",
  LANG: "C.UTF-8",
  LC_ALL: "C.UTF-8",
  TZ: "UTC",
  TERM: "dumb",
  NO_COLOR: "1"
});

const LOGICAL_MOUNTS = Object.freeze([
  { source: "host-usr", destination: "/usr", mode: "read-only" },
  { source: "artifact-snapshot-fd", destination: "/input/artifact", mode: "read-only" },
  { source: "node-directory-fd", destination: "/opt/gate/node", mode: "read-only" },
  { source: "rea-directory-fd", destination: "/opt/gate/rea", mode: "read-only" },
  { source: "adapter-file-fd", destination: "/opt/gate/adapter.mjs", mode: "read-only" }
]);

function analysisPaths(input) {
  const paths = input || runtimePaths();
  const root = paths.offlineAnalyses || path.join(paths.home, "offline-analysis");
  return {
    ...paths,
    offlineAnalyses: root,
    offlineAnalysisTransactions: paths.offlineAnalysisTransactions || path.join(root, "transactions"),
    offlineAnalysisManifests: paths.offlineAnalysisManifests || path.join(root, "manifests"),
    offlineAnalysisCreations: paths.offlineAnalysisCreations || path.join(root, "creations"),
    offlineAnalysisClaims: paths.offlineAnalysisClaims || path.join(root, "claims"),
    offlineAnalysisPurges: paths.offlineAnalysisPurges || path.join(root, "purges"),
    offlineAnalysisRuns: paths.offlineAnalysisRuns || path.join(root, "runs"),
    offlineAnalysisInputs: paths.offlineAnalysisInputs || path.join(root, "inputs"),
    offlineAnalysisSandboxes: paths.offlineAnalysisSandboxes || path.join(root, "sandboxes")
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

function manifestEnvelope(manifest) {
  const value = structuredClone(manifest);
  delete value.manifestSha256;
  return value;
}

function manifestDigest(manifest) {
  return canonicalDigest(manifestEnvelope(manifest));
}

function randomId(prefix) {
  return `${prefix}_${crypto.randomBytes(16).toString("hex")}`;
}

function sameStat(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
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

function fileHash(descriptor, maximumBytes) {
  const hash = crypto.createHash("sha256");
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  let bytes = 0;
  while (true) {
    const read = fs.readSync(descriptor, buffer, 0, buffer.length, null);
    if (read === 0) break;
    bytes += read;
    if (bytes > maximumBytes) throw new Error(`file exceeds the ${maximumBytes}-byte limit`);
    hash.update(buffer.subarray(0, read));
  }
  return { sha256: hash.digest("hex"), bytes };
}

function openObservedFile(file, options = {}) {
  const requested = path.resolve(file);
  const resolved = fs.realpathSync.native(requested);
  const before = fs.lstatSync(resolved, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) throw new Error(`${options.label || "file"} must be a regular non-symlink file`);
  const maximumBytes = options.maximumBytes || 4 * 1024 * 1024 * 1024;
  if (before.size < 1n || before.size > BigInt(maximumBytes)) throw new Error(`${options.label || "file"} has an invalid size`);
  if (options.executable) fs.accessSync(resolved, fs.constants.X_OK);
  if (!fs.constants.O_NOFOLLOW) throw new Error("the platform cannot open files without following links");
  const descriptor = fs.openSync(resolved, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!opened.isFile() || !sameStat(before, opened)) throw new Error(`${options.label || "file"} changed while it was opened`);
    const digest = fileHash(descriptor, maximumBytes);
    const afterRead = fs.fstatSync(descriptor, { bigint: true });
    const afterPath = fs.lstatSync(resolved, { bigint: true });
    if (!sameStat(opened, afterRead) || !sameStat(afterRead, afterPath) || BigInt(digest.bytes) !== afterRead.size) {
      throw new Error(`${options.label || "file"} changed while it was hashed`);
    }
    return { descriptor, value: { path: resolved, sha256: digest.sha256, ...statIdentity(afterRead) } };
  } catch (error) {
    fs.closeSync(descriptor);
    throw error;
  }
}

function closeDescriptor(descriptor) {
  if (descriptor === null || descriptor === undefined) return;
  try { fs.closeSync(descriptor); } catch { /* The primary result owns the diagnostic. */ }
}

function privateFileObservation(file, maximumBytes, label, options = {}) {
  if (!fs.constants.O_NOFOLLOW) throw new Error("the platform cannot inspect private state without following links");
  const before = fs.lstatSync(file, { bigint: true });
  const allowedLinks = options.allowedLinks || new Set([1n]);
  if (
    !before.isFile() || before.isSymbolicLink() || !allowedLinks.has(before.nlink) ||
    (typeof process.geteuid === "function" && before.uid !== BigInt(process.geteuid())) ||
    (before.mode & 0o7777n) !== 0o600n || before.size > BigInt(maximumBytes)
  ) throw new Error(`${label} is not a bounded owner-only regular file`);
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!sameStat(before, opened) || opened.nlink !== before.nlink) throw new Error(`${label} changed while it was opened`);
    const content = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    const named = fs.lstatSync(file, { bigint: true });
    if (
      content.length !== Number(after.size) || !sameStat(opened, after) || opened.nlink !== after.nlink ||
      !sameStat(after, named) || after.nlink !== named.nlink
    ) throw new Error(`${label} changed while it was read`);
    return { content, stat: after };
  } finally {
    closeDescriptor(descriptor);
  }
}

function unlinkObservedPrivateFile(file, observed, directory, label) {
  const named = fs.lstatSync(file, { bigint: true });
  if (!sameStat(observed, named) || observed.nlink !== named.nlink) throw new Error(`${label} changed before recovery`);
  fs.unlinkSync(file);
  syncPrivateDirectory(directory, { label: `parent directory for ${label}` });
}

function transactionOwnerSuffix(owner) {
  const boot = owner.processIdentity.bootId.replaceAll("-", "");
  return `${owner.pid}-${boot}-${owner.processIdentity.startTimeTicks}-${owner.nonce}`;
}

function recordTransactionFile(paths, kind, id, owner) {
  if (!new Set(["creation", "publication", "manifest", "claim", "purge"]).has(kind)) {
    throw new Error("offline transaction kind is invalid");
  }
  if (!/^(?:amf|arun)_[a-f0-9]{32}$/u.test(id)) throw new Error("offline transaction identifier is invalid");
  return path.join(paths.offlineAnalysisTransactions, `.record-${kind}-${id}-${transactionOwnerSuffix(owner)}.pending`);
}

function atomicExclusiveRecord(paths, file, content, options = {}) {
  const owner = retentionLockOwner();
  const kind = options.kind;
  const id = options.id;
  const label = options.label || `offline ${kind} record ${id}`;
  const maximumBytes = options.maximumBytes || MAX_MANIFEST_BYTES;
  if (Buffer.byteLength(content, options.encoding || "utf8") > maximumBytes) {
    throw new Error(`${label} exceeds the ${maximumBytes}-byte publication limit`);
  }
  securePrivateDirectory(paths.offlineAnalysisTransactions, { label: "offline analysis transaction directory" });
  const temporary = recordTransactionFile(paths, kind, id, owner);
  let descriptor;
  let published = false;
  try {
    descriptor = openPrivateFileExclusive(temporary, { label: `${label} transaction` });
    fs.writeFileSync(descriptor, content, options.encoding || "utf8");
    fs.fsyncSync(descriptor);
    closeDescriptor(descriptor);
    descriptor = undefined;
    syncPrivateDirectory(paths.offlineAnalysisTransactions, { label: "offline analysis transaction directory" });
    try {
      fs.lstatSync(file);
      throw Object.assign(new Error(`${label} already exists`), { code: "EEXIST" });
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    // Every caller holds the retention lock, so the destination-absent check
    // and rename form a no-replace publication within the trusted writer set.
    fs.renameSync(temporary, file);
    published = true;
    syncPrivateDirectory(path.dirname(file), { label: `parent directory for ${label}` });
    syncPrivateDirectory(paths.offlineAnalysisTransactions, { label: "offline analysis transaction directory" });
  } catch (error) {
    closeDescriptor(descriptor);
    if (!published) {
      try {
        const observed = privateFileObservation(temporary, maximumBytes, `${label} transaction`);
        unlinkObservedPrivateFile(
          temporary,
          observed.stat,
          paths.offlineAnalysisTransactions,
          `${label} transaction`
        );
      } catch (cleanupError) {
        if (cleanupError.code !== "ENOENT") error.transactionCleanupError = cleanupError.message;
      }
    }
    error.recordPublished = published;
    throw error;
  }
}

function retentionLockFile(paths) {
  return path.join(paths.offlineAnalyses, ".retention.lock");
}

function retentionLockOwner() {
  return {
    apiVersion: "gate.offline-analysis-retention-lock/v1",
    pid: process.pid,
    processIdentity: linuxProcessIdentity(process.pid),
    nonce: crypto.randomBytes(16).toString("hex"),
    createdAt: new Date().toISOString()
  };
}

function retentionLockStagingFile(paths, owner) {
  return path.join(paths.offlineAnalysisTransactions, `.retention-lock-${transactionOwnerSuffix(owner)}.pending`);
}

function readRetentionLock(file) {
  const observed = privateFileObservation(
    file,
    MAX_CLAIM_BYTES,
    "offline artifact retention lock",
    { allowedLinks: new Set([1n, 2n]) }
  );
  const owner = JSON.parse(observed.content.toString("utf8"));
  const keys = Object.keys(owner || {}).sort();
  if (
    owner?.apiVersion !== "gate.offline-analysis-retention-lock/v1" ||
    !Number.isSafeInteger(owner.pid) || owner.pid < 1 ||
    !/^[a-f0-9]{32}$/u.test(owner.nonce || "") ||
    !Number.isFinite(Date.parse(owner.createdAt)) ||
    !owner.processIdentity ||
    !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u.test(owner.processIdentity.bootId || "") ||
    !/^[0-9]{1,32}$/u.test(owner.processIdentity.startTimeTicks || "") ||
    keys.join(",") !== "apiVersion,createdAt,nonce,pid,processIdentity" ||
    Object.keys(owner.processIdentity).sort().join(",") !== "bootId,startTimeTicks"
  ) throw new Error("offline artifact retention lock metadata is invalid");
  return { owner, observed };
}

function processIdentityIsAlive(pid, identity) {
  if (process.platform !== "linux" || !Number.isSafeInteger(pid) || pid < 1) {
    throw new Error("Linux retention-lock process identity is unavailable");
  }
  const bootId = linuxBootIdentity();
  if (bootId !== identity.bootId) return false;
  let startTimeTicks;
  try {
    startTimeTicks = linuxProcessStartTimeTicks(pid);
  } catch (error) {
    if (new Set(["ENOENT", "ESRCH"]).has(error.code)) return false;
    throw new Error(`could not determine whether retention-lock process ${pid} is alive: ${error.message}`, { cause: error });
  }
  return startTimeTicks === identity.startTimeTicks;
}

function removeStaleRetentionLock(paths) {
  const file = retentionLockFile(paths);
  const { owner, observed } = readRetentionLock(file);
  let staging = null;
  if (observed.stat.nlink === 2n) {
    staging = retentionLockStagingFile(paths, owner);
    const staged = fs.lstatSync(staging, { bigint: true });
    if (!sameStat(observed.stat, staged) || staged.nlink !== 2n) {
      throw new Error("offline artifact retention lock has an unrecognized hard link");
    }
  }
  if (processIdentityIsAlive(owner.pid, owner.processIdentity)) return false;
  if (staging) {
    const beforeStageUnlink = fs.lstatSync(staging, { bigint: true });
    if (!sameStat(observed.stat, beforeStageUnlink) || beforeStageUnlink.nlink !== 2n) {
      throw new Error("offline artifact retention-lock transaction changed before stale recovery");
    }
    fs.unlinkSync(staging);
    syncPrivateDirectory(paths.offlineAnalysisTransactions, { label: "offline analysis transaction directory" });
  }
  const beforeUnlink = fs.lstatSync(file, { bigint: true });
  if (!sameStat(observed.stat, beforeUnlink) || beforeUnlink.nlink !== 1n) {
    throw new Error("offline artifact retention lock changed before stale recovery");
  }
  fs.unlinkSync(file);
  syncPrivateDirectory(paths.offlineAnalyses, { label: "offline analysis root" });
  return true;
}

function recoverInterruptedRecordTransactions(paths) {
  const pattern = /^\.record-(creation|publication|manifest|claim|purge)-((?:amf|arun)_[a-f0-9]{32})-([1-9][0-9]*)-([a-f0-9]{32})-([0-9]{1,32})-([a-f0-9]{32})\.pending$/u;
  const lockPattern = /^\.retention-lock-([1-9][0-9]*)-([a-f0-9]{32})-([0-9]{1,32})-([a-f0-9]{32})\.pending$/u;
  for (const name of fs.readdirSync(paths.offlineAnalysisTransactions)) {
    const recordMatch = pattern.exec(name);
    const lockMatch = lockPattern.exec(name);
    const match = recordMatch || lockMatch;
    if (!match) throw new Error(`offline analysis transaction entry is invalid: ${name}`);
    const [pidText, bootHex, startTimeTicks] = recordMatch ? match.slice(3, 6) : match.slice(1, 4);
    const bootId = `${bootHex.slice(0, 8)}-${bootHex.slice(8, 12)}-${bootHex.slice(12, 16)}-${bootHex.slice(16, 20)}-${bootHex.slice(20)}`;
    const pid = Number(pidText);
    if (!Number.isSafeInteger(pid) || pid < 1) throw new Error(`offline analysis transaction owner is invalid: ${name}`);
    const file = path.join(paths.offlineAnalysisTransactions, name);
    if (processIdentityIsAlive(pid, { bootId, startTimeTicks })) {
      if (lockMatch) continue;
      throw new Error(`offline analysis transaction still has a live owner: ${name}`);
    }
    const observed = privateFileObservation(file, MAX_CREATION_PUBLICATION_BYTES, `offline analysis transaction ${name}`);
    unlinkObservedPrivateFile(file, observed.stat, paths.offlineAnalysisTransactions, `offline analysis transaction ${name}`);
  }
}

function withRetentionLock(paths, action, options = {}) {
  paths = analysisPaths(paths);
  securePrivateDirectory(paths.offlineAnalyses, { create: false, label: "offline analysis root" });
  securePrivateDirectory(paths.offlineAnalysisTransactions, { label: "offline analysis transaction directory" });
  const file = retentionLockFile(paths);
  const owner = retentionLockOwner();
  const timeoutMs = options.timeoutMs ?? RETENTION_LOCK_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new Error("offline retention lock timeout must be positive");
  const deadline = Date.now() + timeoutMs;
  const serialization = openDirectory(paths.offlineAnalyses, "offline analysis root");
  try {
    if (process.platform !== "linux") throw new Error("offline retention serialization requires Linux/WSL2");
    const locked = spawnSync("flock", ["--exclusive", "--timeout", String(timeoutMs / 1000), "3"], {
      stdio: ["ignore", "pipe", "pipe", serialization],
      env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
      shell: false,
      timeout: timeoutMs + 1000,
      maxBuffer: 16 * 1024
    });
    if (locked.error || locked.status !== 0) throw new Error("timed out waiting for offline retention serialization", { cause: locked.error });
    let acquired = false;
    let lockStat;
    while (!acquired) {
      const staging = retentionLockStagingFile(paths, owner);
      let descriptor;
      let stagingStat;
      let linked = false;
      try {
        descriptor = openPrivateFileExclusive(staging, { label: "offline artifact retention-lock transaction" });
        stagingStat = fs.fstatSync(descriptor);
        fs.writeFileSync(descriptor, `${JSON.stringify(owner)}\n`, "utf8");
        fs.fsyncSync(descriptor);
        closeDescriptor(descriptor);
        descriptor = undefined;
        syncPrivateDirectory(paths.offlineAnalysisTransactions, { label: "offline analysis transaction directory" });
        fs.linkSync(staging, file);
        linked = true;
        lockStat = fs.lstatSync(file);
        if (lockStat.dev !== stagingStat.dev || lockStat.ino !== stagingStat.ino) {
          throw new Error("offline artifact retention lock changed while it was published");
        }
        fs.unlinkSync(staging);
        syncPrivateDirectory(paths.offlineAnalysisTransactions, { label: "offline analysis transaction directory" });
        syncPrivateDirectory(paths.offlineAnalyses, { label: "offline analysis root" });
        acquired = true;
      } catch (error) {
        closeDescriptor(descriptor);
        if (linked) try {
          const named = fs.lstatSync(file);
          if (stagingStat && named.dev === stagingStat.dev && named.ino === stagingStat.ino) {
            fs.unlinkSync(file);
            syncPrivateDirectory(paths.offlineAnalyses, { label: "offline analysis root" });
          }
        } catch { /* Preserve the lock publication error. */ }
        try {
          const named = fs.lstatSync(staging);
          if (stagingStat && named.dev === stagingStat.dev && named.ino === stagingStat.ino) {
            fs.unlinkSync(staging);
            syncPrivateDirectory(paths.offlineAnalysisTransactions, { label: "offline analysis transaction directory" });
          }
        } catch { /* Preserve the lock publication error. */ }
        if (error.code !== "EEXIST") throw error;
        try {
          if (removeStaleRetentionLock(paths)) continue;
        } catch (lockError) {
          if (Date.now() >= deadline) {
            throw new Error(`offline artifact retention lock could not be recovered safely: ${lockError.message}`, { cause: lockError });
          }
        }
        if (Date.now() >= deadline) throw new Error("timed out waiting for the offline artifact retention lock");
        Atomics.wait(retentionWaitBuffer, 0, 0, Math.min(20, Math.max(1, deadline - Date.now())));
      }
    }
    try {
      recoverInterruptedRecordTransactions(paths);
      recoverInterruptedManifestCreations(paths);
      const retained = scanRetainedArtifacts(paths, { strict: true });
      return action(retained);
    } finally {
      try {
        const finalStat = fs.lstatSync(file);
        if (lockStat && finalStat.dev === lockStat.dev && finalStat.ino === lockStat.ino) {
          fs.unlinkSync(file);
          syncPrivateDirectory(paths.offlineAnalyses, { label: "offline analysis root" });
        }
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
    }
  } finally {
    closeDescriptor(serialization);
  }
}

function scanRetainedArtifacts(paths, options = {}) {
  const artifacts = new Map();
  let bytes = 0n;
  let invalidEntries = 0;
  for (const name of fs.readdirSync(paths.offlineAnalysisInputs)) {
    const file = path.join(paths.offlineAnalysisInputs, name);
    let observedBytes = 0n;
    let valid = /^arun_[a-f0-9]{32}\.bin$/u.test(name);
    try {
      const leaf = fs.lstatSync(file, { bigint: true });
      if (leaf.isFile() && !leaf.isSymbolicLink() && leaf.size > 0n) observedBytes = leaf.size;
      else valid = false;
      if (valid) {
        const descriptor = openPrivateFile(file, { operation: "read", label: `offline artifact snapshot ${name}` });
        try {
          const opened = fs.fstatSync(descriptor, { bigint: true });
          if (!opened.isFile() || opened.nlink !== 1n || opened.size < 1n || opened.size > BigInt(MAX_ARTIFACT_BYTES)) {
            valid = false;
          } else {
            observedBytes = opened.size;
          }
        } finally {
          closeDescriptor(descriptor);
        }
      }
    } catch {
      valid = false;
    }
    bytes += observedBytes;
    if (valid) artifacts.set(name.slice(0, -4), { file, bytes: Number(observedBytes) });
    else invalidEntries += 1;
  }
  if (options.strict && invalidEntries > 0) {
    throw new Error("offline artifact storage contains invalid entries; refusing quota-sensitive mutation");
  }
  return { artifacts, bytes, invalidEntries };
}

function assertIdentity(actual, expected, label) {
  for (const key of ["path", "sha256", "size", "device", "inode", "mtimeNs", "ctimeNs"]) {
    if (actual[key] !== expected[key]) throw new Error(`${label} ${key} changed after manifest creation`);
  }
}

function canonicalSourcePath(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 4096 || /[\u0000\r\n]/u.test(value)) {
    throw new Error("analysis path must be a nonempty NUL-free single-line string of at most 4096 characters");
  }
  if (!path.isAbsolute(value)) throw new Error("analysis path must be absolute");
  return path.resolve(value);
}

function snapshotRef(runId) {
  return `private://offline-analysis/inputs/${runId}.bin`;
}

function snapshotPath(paths, reference) {
  const prefix = "private://offline-analysis/inputs/";
  if (typeof reference !== "string" || !reference.startsWith(prefix)) throw new Error("offline artifact snapshot reference is invalid");
  const filename = reference.slice(prefix.length);
  if (!/^arun_[a-f0-9]{32}\.bin$/u.test(filename) || path.basename(filename) !== filename) {
    throw new Error("offline artifact snapshot reference escapes its private directory");
  }
  return path.join(paths.offlineAnalysisInputs, filename);
}

function snapshotArtifact(sourceInput, runId, paths, retained) {
  const source = canonicalSourcePath(sourceInput);
  const before = fs.lstatSync(source, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) throw new Error("analysis path must name a regular non-symlink file");
  if (before.size < 1n || before.size > BigInt(MAX_ARTIFACT_BYTES)) {
    throw new Error(`analysis artifact must be from 1 to ${MAX_ARTIFACT_BYTES} bytes`);
  }
  if (retained.artifacts.size + 1 > MAX_RETAINED_ARTIFACTS) {
    throw new Error(
      `offline artifact retention count quota exceeded: ${retained.artifacts.size} retained artifacts plus 1 requested artifact exceeds ${MAX_RETAINED_ARTIFACTS}`
    );
  }
  if (retained.bytes + before.size > BigInt(MAX_RETAINED_ARTIFACT_BYTES)) {
    throw new Error(
      `offline artifact retention quota exceeded: ${retained.bytes} retained bytes plus ${before.size} requested bytes exceeds ${MAX_RETAINED_ARTIFACT_BYTES}`
    );
  }
  if (!fs.constants.O_NOFOLLOW) throw new Error("the platform cannot open an artifact without following links");
  const sourceDescriptor = fs.openSync(source, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | (fs.constants.O_NONBLOCK || 0));
  const reference = snapshotRef(runId);
  const destination = snapshotPath(paths, reference);
  let destinationDescriptor;
  try {
    const opened = fs.fstatSync(sourceDescriptor, { bigint: true });
    if (!opened.isFile() || !sameStat(before, opened)) throw new Error("analysis artifact changed while it was opened");
    destinationDescriptor = openPrivateFileExclusive(destination, { label: `offline artifact snapshot ${runId}` });
    const hash = crypto.createHash("sha256");
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let bytes = 0;
    while (true) {
      const read = fs.readSync(sourceDescriptor, buffer, 0, buffer.length, null);
      if (read === 0) break;
      bytes += read;
      if (bytes > MAX_ARTIFACT_BYTES) throw new Error(`analysis artifact exceeds the ${MAX_ARTIFACT_BYTES}-byte limit`);
      let offset = 0;
      while (offset < read) {
        const written = fs.writeSync(destinationDescriptor, buffer, offset, read - offset);
        if (!Number.isInteger(written) || written < 1) throw new Error("artifact snapshot write made no progress");
        hash.update(buffer.subarray(offset, offset + written));
        offset += written;
      }
    }
    fs.fsyncSync(destinationDescriptor);
    syncPrivateDirectory(paths.offlineAnalysisInputs, { label: "offline artifact input directory" });
    const afterRead = fs.fstatSync(sourceDescriptor, { bigint: true });
    const afterPath = fs.lstatSync(source, { bigint: true });
    if (!sameStat(opened, afterRead) || !sameStat(afterRead, afterPath) || BigInt(bytes) !== afterRead.size) {
      throw new Error("analysis artifact changed while it was copied");
    }
    return {
      source,
      snapshot: {
        snapshotRef: reference,
        sha256: hash.digest("hex"),
        bytes,
        sourceIdentity: statIdentity(afterRead)
      }
    };
  } catch (error) {
    closeDescriptor(destinationDescriptor);
    destinationDescriptor = null;
    try {
      fs.rmSync(destination, { force: true });
      syncPrivateDirectory(paths.offlineAnalysisInputs, { label: "offline artifact input directory" });
    } catch { /* Preserve the source error. */ }
    throw error;
  } finally {
    closeDescriptor(sourceDescriptor);
    closeDescriptor(destinationDescriptor);
  }
}

function defaultRuntimeResolver(paths) {
  if (process.platform !== "linux") throw new Error("offline Bubblewrap analysis requires Linux");
  const bwrapPath = ["/usr/bin/bwrap", "/bin/bwrap"].find((candidate) => fs.existsSync(candidate));
  if (!bwrapPath) throw new Error("Bubblewrap is unavailable; install bwrap before creating an offline manifest");
  const nodePath = fs.realpathSync.native(process.execPath);
  const adapterPath = path.join(paths.repo, "src", "adapters", "rea-pe-resources.mjs");
  const { lock } = readUpstreamLock({ paths });
  const entry = lock.upstreams.find((candidate) => candidate.id === "rea-stable");
  if (!entry?.install || entry.install.lane !== "npm") throw new Error("the reviewed rea-stable npm lock is unavailable");
  const resolved = resolveUpstreamBinary("rea-stable", "rea", { paths });
  const reaEntryPath = fs.realpathSync.native(resolved.executable);
  const expectedRoot = `${fs.realpathSync.native(resolved.directory)}${path.sep}`;
  if (!reaEntryPath.startsWith(expectedRoot) || path.relative(expectedRoot, reaEntryPath) !== "node_modules/rea-agents/scripts/rea.mjs") {
    throw new Error("the rea-stable executable does not resolve to its reviewed package entrypoint");
  }
  return {
    bwrapPath,
    nodePath,
    nodeDirectory: path.dirname(nodePath),
    adapterPath,
    reaEntryPath,
    reaDirectory: fs.realpathSync.native(resolved.directory),
    upstream: {
      id: "rea-stable",
      version: entry.version,
      commit: entry.commit,
      packageIntegrity: entry.install.integrity,
      lockSha256: entry.install.lockSha256
    }
  };
}

function resolveRuntime(paths) {
  return defaultRuntimeResolver(paths);
}

function defaultCapabilityRuntime(paths) {
  if (process.platform !== "linux") throw new Error("offline Bubblewrap analysis requires Linux");
  const bwrapPath = ["/usr/bin/bwrap", "/bin/bwrap"].find((candidate) => fs.existsSync(candidate));
  if (!bwrapPath) throw new Error("Bubblewrap is unavailable; install bwrap before creating an offline manifest");
  const { lock } = readUpstreamLock({ paths });
  const entry = lock.upstreams.find((candidate) => candidate.id === "rea-stable");
  if (!entry?.install || entry.install.lane !== "npm") throw new Error("the reviewed rea-stable npm lock is unavailable");
  const expected = [
    ["node", fs.realpathSync.native(process.execPath)],
    ["adapter", path.join(paths.repo, "src", "adapters", "rea-pe-resources.mjs")],
    ["rea-stable-receipt", path.join(paths.upstreamTools, "rea-stable", "install.json")],
    ["rea-stable", path.join(paths.upstreamTools, "rea-stable", "node_modules", "rea-agents", "scripts", "rea.mjs")]
  ];
  for (const [label, candidate] of expected) {
    try {
      const stat = fs.lstatSync(candidate);
      if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("unexpected file type");
    } catch {
      throw new Error(`offline runtime prerequisite is unavailable: ${label}`);
    }
  }
  let receipt;
  try {
    receipt = JSON.parse(readPrivateFileBounded(
      path.join(paths.upstreamTools, "rea-stable", "install.json"),
      MAX_CLAIM_BYTES,
      "utf8",
      { label: "rea-stable install receipt" }
    ));
  } catch {
    throw new Error("offline runtime prerequisite is unavailable: rea-stable-receipt");
  }
  if (
    receipt?.apiVersion !== "gate.upstream-install/v2" || receipt.id !== "rea-stable" || receipt.lane !== "npm" ||
    receipt.package !== entry.install.package || receipt.version !== entry.version ||
    receipt.integrity !== entry.install.integrity || receipt.lockSha256 !== entry.install.lockSha256
  ) throw new Error("offline runtime prerequisite is unavailable: rea-stable-receipt");
  return { bwrapPath };
}

function probeIsolationRuntime(runtime) {
  const observed = fs.statSync(runtime.bwrapPath, { bigint: true });
  const key = [runtime.bwrapPath, observed.dev, observed.ino, observed.size, observed.mtimeNs, observed.ctimeNs].join(":");
  if (isolationProbeCache.has(key)) return isolationProbeCache.get(key);
  const probe = spawnSync(runtime.bwrapPath, [
    "--unshare-user",
    "--unshare-pid",
    "--unshare-net",
    "--unshare-ipc",
    "--unshare-uts",
    "--unshare-cgroup-try",
    "--disable-userns",
    "--die-with-parent",
    "--new-session",
    "--cap-drop", "ALL",
    "--clearenv",
    "--ro-bind", "/usr", "/usr",
    "--symlink", "usr/bin", "/bin",
    "--symlink", "usr/lib", "/lib",
    "--symlink", "usr/lib64", "/lib64",
    "--proc", "/proc",
    "--dev", "/dev",
    "--", "/usr/bin/true"
  ], {
    cwd: "/",
    env: {},
    encoding: "utf8",
    shell: false,
    timeout: 5_000,
    windowsHide: true
  });
  const outcome = probe.status === 0
    ? { ok: true, reason: null }
    : {
        ok: false,
        reason: `Bubblewrap namespace probe failed: ${String(probe.error?.message || probe.stderr || probe.status || "unknown failure").trim().slice(0, 500)}`
      };
  isolationProbeCache.set(key, outcome);
  return outcome;
}

function observeRuntime(runtime) {
  const opened = {};
  try {
    opened.bwrap = openObservedFile(runtime.bwrapPath, { label: "Bubblewrap executable", executable: true });
    opened.node = openObservedFile(runtime.nodePath, { label: "Node executable", executable: true });
    opened.adapter = openObservedFile(runtime.adapterPath, { label: "offline adapter" });
    opened.reaEntry = openObservedFile(runtime.reaEntryPath, { label: "REA entrypoint" });
    return Object.fromEntries(Object.entries(opened).map(([key, value]) => [key, value.value]));
  } finally {
    for (const value of Object.values(opened)) closeDescriptor(value.descriptor);
  }
}

function evidenceRefs(runId) {
  const base = `offline-analysis-${runId}`;
  return {
    stdoutRef: `private://evidence/${base}-stdout.json`,
    stderrRef: `private://evidence/${base}-stderr.bin`,
    resultRef: `private://evidence/${base}-result.json`
  };
}

function exactArray(value, expected) {
  return Array.isArray(value) && value.length === expected.length && value.every((item, index) => item === expected[index]);
}

function expectedSandboxRef(runId) {
  return `private://offline-analysis/sandboxes/${runId}`;
}

function assertManifestInvariants(manifest) {
  const { id, runId } = manifest.metadata;
  if (manifest.operation.targetSelector.type !== "path" || !path.isAbsolute(manifest.operation.targetSelector.value)) {
    throw new Error("offline manifest typed path binding is invalid");
  }
  if (manifest.operation.artifact.snapshotRef !== snapshotRef(runId)) throw new Error("offline manifest snapshot binding is invalid");
  if (manifest.operation.action !== "local-static-analysis" || manifest.networkPolicy !== "none") {
    throw new Error("offline manifest action or network policy is invalid");
  }
  if (manifest.operation.adapter.id !== ADAPTER_ID || manifest.operation.adapter.toolId !== "rea") {
    throw new Error("offline manifest adapter binding is invalid");
  }
  const argumentsValue = manifest.operation.adapter.arguments;
  if (
    argumentsValue.maxFileBytes !== MAX_ARTIFACT_BYTES || argumentsValue.maxEntries !== ADAPTER_MAX_ENTRIES ||
    argumentsValue.format !== "json" || argumentsValue.fullOutput !== true
  ) throw new Error("offline manifest fixed adapter arguments are invalid");
  if (
    manifest.limits.maxRequests !== 0 || manifest.limits.maxRatePerSecond !== 0 ||
    manifest.limits.maxParallel !== 1 || manifest.limits.maxTokens !== 0
  ) throw new Error("offline manifest zero-contact bounds are invalid");
  if (canonicalDigest(manifest.runtime.environment) !== canonicalDigest(SANDBOX_ENVIRONMENT)) {
    throw new Error("offline manifest environment binding is invalid");
  }
  if (canonicalDigest(manifest.runtime.logicalMounts) !== canonicalDigest(LOGICAL_MOUNTS)) {
    throw new Error("offline manifest mount binding is invalid");
  }
  if (manifest.runtime.sandboxRef !== expectedSandboxRef(runId)) throw new Error("offline manifest sandbox binding is invalid");
  const refs = evidenceRefs(runId);
  for (const key of ["stdoutRef", "stderrRef", "resultRef"]) {
    if (manifest.runtime.evidence[key] !== refs[key]) throw new Error(`offline manifest evidence binding is invalid: ${key}`);
  }
  if (manifest.runtime.maxEvidenceBytesPerStream !== MAX_EVIDENCE_BYTES) throw new Error("offline manifest evidence limit is invalid");
  if (!exactArray(manifest.enforcement.enforced, OFFLINE_ANALYSIS_ENFORCED)) throw new Error("offline enforced-control claims are invalid");
  if (!exactArray(manifest.enforcement.unavailable, OFFLINE_ANALYSIS_UNAVAILABLE)) throw new Error("offline unavailable-control claims are invalid");
  const createdAt = Date.parse(manifest.metadata.createdAt);
  const expiresAt = Date.parse(manifest.metadata.expiresAt);
  if (!(createdAt < expiresAt && expiresAt - createdAt <= MANIFEST_TTL_MS)) throw new Error("offline manifest validity window is invalid");
  if (!/^amf_[a-f0-9]{32}$/u.test(id) || !/^arun_[a-f0-9]{32}$/u.test(runId)) {
    throw new Error("offline manifest identity is invalid");
  }
}

function manifestFile(paths, id) {
  if (!/^amf_[a-f0-9]{32}$/u.test(id)) throw new Error("invalid offline analysis manifest identifier");
  return path.join(paths.offlineAnalysisManifests, `${id}.json`);
}

function runFile(paths, id) {
  if (!/^arun_[a-f0-9]{32}$/u.test(id)) throw new Error("invalid offline analysis run identifier");
  return path.join(paths.offlineAnalysisRuns, `${id}.json`);
}

function claimFile(paths, id) {
  if (!/^amf_[a-f0-9]{32}$/u.test(id)) throw new Error("invalid offline analysis manifest identifier");
  return path.join(paths.offlineAnalysisClaims, `${id}.json`);
}

function purgeFile(paths, id) {
  if (!/^amf_[a-f0-9]{32}$/u.test(id)) throw new Error("invalid offline analysis manifest identifier");
  return path.join(paths.offlineAnalysisPurges, `${id}.json`);
}

function creationFile(paths, id) {
  if (!/^amf_[a-f0-9]{32}$/u.test(id)) throw new Error("invalid offline analysis creation identifier");
  return path.join(paths.offlineAnalysisCreations, `${id}.json`);
}

function creationPublicationFile(paths, id) {
  if (!/^amf_[a-f0-9]{32}$/u.test(id)) throw new Error("invalid offline analysis publication identifier");
  return path.join(paths.offlineAnalysisCreations, `${id}.publication.json`);
}

function newCreationIntent(manifestId, runId, projectId) {
  return {
    apiVersion: "gate.offline-analysis-creation/v1",
    manifestId,
    runId,
    projectId,
    createdAt: new Date().toISOString()
  };
}

function readCreationIntent(paths, id) {
  const intent = JSON.parse(readPrivateFileBounded(
    creationFile(paths, id),
    MAX_CLAIM_BYTES,
    "utf8",
    { label: `offline analysis creation intent ${id}` }
  ));
  if (
    intent?.apiVersion !== "gate.offline-analysis-creation/v1" || intent.manifestId !== id ||
    !/^arun_[a-f0-9]{32}$/u.test(intent.runId || "") ||
    !/^[a-z][a-z0-9-]{1,62}$/u.test(intent.projectId || "") ||
    !Number.isFinite(Date.parse(intent.createdAt)) ||
    Object.keys(intent).sort().join(",") !== "apiVersion,createdAt,manifestId,projectId,runId"
  ) throw new Error("offline analysis creation intent metadata is invalid");
  return intent;
}

function newCreationPublication(intent, manifest, content) {
  const bytes = Buffer.from(content, "utf8");
  return {
    apiVersion: "gate.offline-analysis-creation-publication/v1",
    manifestId: intent.manifestId,
    runId: intent.runId,
    projectId: intent.projectId,
    manifestSha256: manifest.manifestSha256,
    contentSha256: sha256(bytes),
    contentBytes: bytes.length,
    contentBase64: bytes.toString("base64"),
    createdAt: new Date().toISOString()
  };
}

function readCreationPublication(paths, id) {
  const publication = JSON.parse(readPrivateFileBounded(
    creationPublicationFile(paths, id),
    MAX_CREATION_PUBLICATION_BYTES,
    "utf8",
    { label: `offline analysis creation publication ${id}` }
  ));
  if (
    publication?.apiVersion !== "gate.offline-analysis-creation-publication/v1" || publication.manifestId !== id ||
    !/^arun_[a-f0-9]{32}$/u.test(publication.runId || "") ||
    !/^[a-z][a-z0-9-]{1,62}$/u.test(publication.projectId || "") ||
    !/^[a-f0-9]{64}$/u.test(publication.manifestSha256 || "") ||
    !/^[a-f0-9]{64}$/u.test(publication.contentSha256 || "") ||
    typeof publication.contentBase64 !== "string" ||
    !Number.isSafeInteger(publication.contentBytes) || publication.contentBytes < 1 || publication.contentBytes > MAX_MANIFEST_BYTES ||
    !Number.isFinite(Date.parse(publication.createdAt)) ||
    Object.keys(publication).sort().join(",") !== "apiVersion,contentBase64,contentBytes,contentSha256,createdAt,manifestId,manifestSha256,projectId,runId"
  ) throw new Error("offline analysis creation publication metadata is invalid");
  const expected = Buffer.from(publication.contentBase64, "base64");
  if (
    expected.length !== publication.contentBytes || expected.toString("base64") !== publication.contentBase64 ||
    sha256(expected) !== publication.contentSha256
  ) throw new Error("offline analysis creation publication content binding is invalid");
  return publication;
}

function removeCreationIntent(paths, id) {
  for (const file of [creationPublicationFile(paths, id), creationFile(paths, id)]) {
    try {
      const observed = privateFileObservation(file, MAX_CREATION_PUBLICATION_BYTES, `offline analysis creation control ${id}`);
      unlinkObservedPrivateFile(
        file,
        observed.stat,
        paths.offlineAnalysisCreations,
        `offline analysis creation control ${id}`
      );
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
}

function removeIncompleteSnapshot(paths, runId) {
  const file = snapshotPath(paths, snapshotRef(runId));
  let descriptor = null;
  try {
    const before = fs.lstatSync(file, { bigint: true });
    descriptor = openPrivateFile(file, { operation: "read", label: `incomplete offline artifact snapshot ${runId}` });
    const opened = fs.fstatSync(descriptor, { bigint: true });
    const named = fs.lstatSync(file, { bigint: true });
    if (!sameStat(before, opened) || !sameStat(opened, named)) {
      throw new Error("incomplete offline artifact snapshot changed during recovery");
    }
    fs.unlinkSync(file);
    syncPrivateDirectory(paths.offlineAnalysisInputs, { label: "offline artifact input directory" });
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    syncPrivateDirectory(paths.offlineAnalysisInputs, { label: "offline artifact input directory" });
  } finally {
    closeDescriptor(descriptor);
  }
}

function recoverInterruptedManifestCreations(paths) {
  const names = fs.readdirSync(paths.offlineAnalysisCreations);
  const intentIds = new Set(names
    .filter((entry) => /^amf_[a-f0-9]{32}\.json$/u.test(entry))
    .map((entry) => entry.slice(0, -5)));
  for (const name of names.filter((entry) => /^amf_[a-f0-9]{32}\.publication\.json$/u.test(entry))) {
    const id = name.slice(0, -".publication.json".length);
    if (!intentIds.has(id)) throw new Error(`offline analysis creation publication has no matching intent: ${name}`);
  }
  for (const name of names) {
    if (/^amf_[a-f0-9]{32}\.publication\.json$/u.test(name)) continue;
    if (!/^amf_[a-f0-9]{32}\.json$/u.test(name)) {
      throw new Error(`offline analysis creation-intent entry is invalid: ${name}`);
    }
    const intent = readCreationIntent(paths, name.slice(0, -5));
    let publication = null;
    try {
      publication = readCreationPublication(paths, intent.manifestId);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    if (publication && (
      publication.runId !== intent.runId || publication.projectId !== intent.projectId
    )) throw new Error("offline analysis creation publication does not match its intent");
    let manifest = null;
    try {
      manifest = readManifest(paths, intent.manifestId);
    } catch (error) {
      if (error.code !== "ENOENT") {
        if (!publication) throw error;
        const expected = Buffer.from(publication.contentBase64, "base64");
        const observed = privateFileObservation(
          manifestFile(paths, intent.manifestId),
          MAX_MANIFEST_BYTES,
          `interrupted offline analysis manifest ${intent.manifestId}`
        );
        if (
          observed.content.length >= publication.contentBytes ||
          !expected.subarray(0, observed.content.length).equals(observed.content)
        ) {
          throw new Error("offline analysis manifest publication is malformed or does not match its transaction", { cause: error });
        }
        unlinkObservedPrivateFile(
          manifestFile(paths, intent.manifestId),
          observed.stat,
          paths.offlineAnalysisManifests,
          `interrupted offline analysis manifest ${intent.manifestId}`
        );
      }
    }
    if (manifest) {
      if (manifest.metadata.runId !== intent.runId || manifest.project.id !== intent.projectId) {
        throw new Error("offline analysis creation intent does not match its published manifest");
      }
      if (publication) {
        const content = readPrivateFileBounded(
          manifestFile(paths, intent.manifestId),
          MAX_MANIFEST_BYTES,
          null,
          { label: `published offline analysis manifest ${intent.manifestId}` }
        );
        if (
          content.length !== publication.contentBytes || sha256(content) !== publication.contentSha256 ||
          manifest.manifestSha256 !== publication.manifestSha256
        ) throw new Error("offline analysis manifest does not match its publication transaction");
      }
      const descriptor = openSnapshot(manifest, paths);
      closeDescriptor(descriptor);
      securePrivateDirectory(
        path.join(paths.offlineAnalysisSandboxes, intent.runId),
        { create: false, label: `offline analysis sandbox ${intent.runId}` }
      );
    } else {
      removeIncompleteSnapshot(paths, intent.runId);
      removeEmptyAnalysisSandboxByRunId(intent.runId, paths);
    }
    removeCreationIntent(paths, intent.manifestId);
  }
}

function evidencePath(paths, reference) {
  const prefix = "private://evidence/";
  if (typeof reference !== "string" || !reference.startsWith(prefix)) throw new Error("offline evidence reference is invalid");
  const filename = reference.slice(prefix.length);
  if (!/^offline-analysis-arun_[a-f0-9]{32}-(?:stdout\.json|stderr\.bin|result\.json)$/u.test(filename)) {
    throw new Error("offline evidence reference escapes the evidence directory");
  }
  return path.join(paths.evidence, filename);
}

function readManifest(paths, id) {
  const manifest = JSON.parse(readPrivateFileBounded(
    manifestFile(paths, id),
    MAX_MANIFEST_BYTES,
    "utf8",
    { label: `private offline analysis manifest ${id}` }
  ));
  assertValidDocument(manifest, "offline-analysis-manifest.schema.json", { paths });
  if (manifest.metadata.id !== id) throw new Error("offline analysis manifest identifier does not match its filename");
  if (manifestDigest(manifest) !== manifest.manifestSha256) throw new Error("offline analysis manifest digest changed");
  assertManifestInvariants(manifest);
  return manifest;
}

function bindingStillMatches(manifest, paths) {
  const current = projectContractBinding(manifest.project.id, { paths });
  if (canonicalDigest(current) !== canonicalDigest(manifest.project)) {
    throw new Error("registered project contract changed after offline manifest creation");
  }
}

function runtimeStillMatches(manifest, paths) {
  const runtime = resolveRuntime(paths);
  if (canonicalDigest(runtime.upstream) !== canonicalDigest(manifest.operation.adapter.upstream)) {
    throw new Error("reviewed REA upstream binding changed after offline manifest creation");
  }
  const observed = observeRuntime(runtime);
  for (const key of ["bwrap", "node", "adapter", "reaEntry"]) {
    assertIdentity(observed[key], manifest.runtime[key], key);
  }
  return runtime;
}

function positiveInteger(value, fallback, name, maximum) {
  const number = Number(value ?? fallback);
  if (!Number.isSafeInteger(number) || number < 1 || number > maximum) {
    throw new Error(`${name} must be an integer from 1 to ${maximum}`);
  }
  return number;
}

function assertInputKeys(value, allowed, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const unexpected = Object.keys(value).filter((key) => !allowed.has(key));
  if (unexpected.length) throw new Error(`${label} contains unsupported fields: ${unexpected.join(", ")}`);
}

function publicPaths(options, label, extraOptionKeys = []) {
  assertInputKeys(options, new Set(["paths", ...extraOptionKeys]), `${label} options`);
  const paths = analysisPaths(options.paths || runtimePaths());
  const trustedRepo = fs.realpathSync.native(runtimePaths().repo);
  let selectedRepo;
  try {
    selectedRepo = fs.realpathSync.native(paths.repo);
  } catch {
    throw new Error(`${label} repository path is unavailable`);
  }
  if (selectedRepo !== trustedRepo) {
    throw new Error(`${label} repository path must be the installed GATE repository`);
  }
  return paths;
}

function offlineEvent(manifest, kind, status, summary, options = {}) {
  return recordEvent({
    kind,
    status,
    runId: manifest.metadata.runId,
    taskId: manifest.metadata.id,
    component: "gate-offline-analysis",
    agent: "gate-offline-analysis",
    summary,
    effect: {
      class: options.effectClass || "local-read",
      targetRef: manifest.operation.artifact.snapshotRef,
      engagementId: null,
      planDigest: null
    },
    evidenceRefs: options.evidenceRefs || []
  }, { paths: options.paths });
}

export function offlineAnalysisCapability(options = {}) {
  let reason = null;
  let paths;
  try {
    paths = publicPaths(options, "offline analysis capability");
    ensureRuntime(paths);
    if (process.platform !== "linux") throw new Error("unsupported-platform");
    if (typeof process.geteuid !== "function" || typeof process.getegid !== "function") throw new Error("posix-identity-unavailable");
    // Status and the observer use a presence/namespace probe only. The full
    // reviewed-lock reconstruction remains mandatory in manifest creation and
    // immediately before execution through resolveRuntime().
    const runtime = defaultCapabilityRuntime(paths);
    const probe = probeIsolationRuntime(runtime);
    if (!probe.ok) throw new Error(probe.reason);
  } catch (error) {
    reason = error.message;
  }
  return {
    configured: true,
    laneAvailable: reason === null,
    mode: "bubblewrap-offline",
    reason,
    enforced: [...OFFLINE_ANALYSIS_ENFORCED],
    unavailable: [...OFFLINE_ANALYSIS_UNAVAILABLE]
  };
}

export function createOfflineAnalysisManifest(projectId, input, options = {}) {
  assertInputKeys(input, new Set(["path", "maxMinutes"]), "offline analysis manifest input");
  const paths = publicPaths(options, "offline analysis manifest", ["expectedProjectContractSha256"]);
  const expectedProjectContractSha256 = options.expectedProjectContractSha256;
  if (
    expectedProjectContractSha256 !== undefined &&
    !/^[a-f0-9]{64}$/u.test(expectedProjectContractSha256)
  ) throw new Error("expected managed-project contract digest must be a lowercase SHA-256 digest");
  ensureRuntime(paths);
  const capability = offlineAnalysisCapability({ paths });
  if (!capability.laneAvailable) throw new Error(`offline analysis is unavailable: ${capability.reason}`);
  const project = projectContractBinding(projectId, { paths });
  if (
    expectedProjectContractSha256 !== undefined &&
    project.contractSha256 !== expectedProjectContractSha256
  ) {
    throw new Error(
      `managed-project contract digest changed: expected ${expectedProjectContractSha256}, observed ${project.contractSha256}`
    );
  }
  const manifestId = randomId("amf");
  const runId = randomId("arun");
  const sandbox = path.join(paths.offlineAnalysisSandboxes, runId);
  const transaction = withRetentionLock(paths, (retained) => {
    const intent = newCreationIntent(manifestId, runId, projectId);
    atomicExclusiveRecord(paths, creationFile(paths, manifestId), `${JSON.stringify(intent)}\n`, {
      encoding: "utf8",
      kind: "creation",
      id: manifestId,
      label: `offline analysis creation intent ${manifestId}`
    });
    let copied = null;
    let manifestWritten = false;
    try {
      copied = snapshotArtifact(input.path, runId, paths, retained);
      securePrivateDirectory(sandbox, { label: `offline analysis sandbox ${runId}` });
      const runtime = resolveRuntime(paths);
      const observed = observeRuntime(runtime);
      const currentProject = projectContractBinding(projectId, { paths });
      if (canonicalDigest(project) !== canonicalDigest(currentProject)) {
        throw new Error("registered project changed while the artifact snapshot was created");
      }
      if (
        expectedProjectContractSha256 !== undefined &&
        currentProject.contractSha256 !== expectedProjectContractSha256
      ) {
        throw new Error(
          `managed-project contract digest changed: expected ${expectedProjectContractSha256}, observed ${currentProject.contractSha256}`
        );
      }
      const now = new Date();
      const expiresAt = new Date(now.getTime() + MANIFEST_TTL_MS);
      const maxMinutes = positiveInteger(input.maxMinutes, 15, "maxMinutes", 60);
      const manifest = {
        $schema: "../../schemas/offline-analysis-manifest.schema.json",
        apiVersion: "gate.offline-analysis/v1",
        kind: "OfflineAnalysisManifest",
        metadata: { id: manifestId, runId, createdAt: now.toISOString(), expiresAt: expiresAt.toISOString() },
        project,
        operation: {
          action: "local-static-analysis",
          targetSelector: { type: "path", value: copied.source },
          artifact: copied.snapshot,
          adapter: {
            id: ADAPTER_ID,
            toolId: "rea",
            upstream: runtime.upstream,
            arguments: {
              maxFileBytes: MAX_ARTIFACT_BYTES,
              maxEntries: ADAPTER_MAX_ENTRIES,
              format: "json",
              fullOutput: true
            }
          }
        },
        networkPolicy: "none",
        limits: { maxMinutes, maxRequests: 0, maxRatePerSecond: 0, maxParallel: 1, maxTokens: 0 },
        runtime: {
          mode: "bubblewrap-offline",
          platform: "linux",
          uid: process.geteuid(),
          gid: process.getegid(),
          environment: { ...SANDBOX_ENVIRONMENT },
          sandboxRef: expectedSandboxRef(runId),
          evidence: evidenceRefs(runId),
          maxEvidenceBytesPerStream: MAX_EVIDENCE_BYTES,
          ...observed,
          logicalMounts: LOGICAL_MOUNTS.map((entry) => ({ ...entry }))
        },
        enforcement: {
          enforced: [...OFFLINE_ANALYSIS_ENFORCED],
          unavailable: [...OFFLINE_ANALYSIS_UNAVAILABLE]
        },
        manifestSha256: "0".repeat(64)
      };
      manifest.manifestSha256 = manifestDigest(manifest);
      assertValidDocument(manifest, "offline-analysis-manifest.schema.json", { paths });
      assertManifestInvariants(manifest);
      const manifestContent = `${JSON.stringify(manifest, null, 2)}\n`;
      const publicationProject = projectContractBinding(projectId, { paths });
      if (canonicalDigest(project) !== canonicalDigest(publicationProject)) {
        throw new Error("registered project changed before offline manifest publication");
      }
      if (
        expectedProjectContractSha256 !== undefined &&
        publicationProject.contractSha256 !== expectedProjectContractSha256
      ) {
        throw new Error(
          `managed-project contract digest changed: expected ${expectedProjectContractSha256}, observed ${publicationProject.contractSha256}`
        );
      }
      const publication = newCreationPublication(intent, manifest, manifestContent);
      atomicExclusiveRecord(paths, creationPublicationFile(paths, manifestId), `${JSON.stringify(publication)}\n`, {
        encoding: "utf8",
        kind: "publication",
        id: manifestId,
        maximumBytes: MAX_CREATION_PUBLICATION_BYTES,
        label: `offline analysis creation publication ${manifestId}`
      });
      atomicExclusiveRecord(paths, manifestFile(paths, manifestId), manifestContent, {
        encoding: "utf8",
        kind: "manifest",
        id: manifestId,
        label: `private offline analysis manifest ${manifestId}`
      });
      manifestWritten = true;
      removeCreationIntent(paths, manifestId);
      return { manifest, copied };
    } catch (error) {
      if (!manifestWritten) {
        try {
          const publication = readCreationPublication(paths, manifestId);
          const published = readManifest(paths, manifestId);
          const content = readPrivateFileBounded(
            manifestFile(paths, manifestId),
            MAX_MANIFEST_BYTES,
            null,
            { label: `published offline analysis manifest ${manifestId}` }
          );
          if (
            published.metadata.runId === runId && published.project.id === projectId &&
            published.manifestSha256 === publication.manifestSha256 &&
            content.length === publication.contentBytes && sha256(content) === publication.contentSha256
          ) manifestWritten = true;
        } catch { /* A later locked recovery will distinguish absent, partial, and ambiguous state. */ }
      }
      if (!manifestWritten) {
        let cleanupComplete = true;
        let manifestAbsent = false;
        try {
          fs.lstatSync(manifestFile(paths, manifestId));
        } catch (manifestError) {
          if (manifestError.code === "ENOENT") manifestAbsent = true;
          else cleanupComplete = false;
        }
        // If a destination manifest exists but is not exact, retain every
        // transaction-bound input. Recovery may remove only a safely short
        // partial publication; an equal-size mismatch fails closed.
        if (manifestAbsent) {
          try { removeIncompleteSnapshot(paths, runId); } catch { cleanupComplete = false; }
          try { removeEmptyAnalysisSandboxByRunId(runId, paths); } catch { cleanupComplete = false; }
        } else {
          cleanupComplete = false;
        }
        if (cleanupComplete) {
          try { removeCreationIntent(paths, manifestId); } catch { /* Recovery will retry under the next lock. */ }
        }
      }
      throw error;
    }
  });
  const { manifest, copied } = transaction;
  offlineEvent(manifest, "offline-analysis.manifest-created", "waiting", "Created a project-bound offline static-analysis manifest.", {
    paths,
    effectClass: "host-write",
    evidenceRefs: [copied.snapshot.snapshotRef]
  });
  return {
    ok: true,
    manifestId,
    runId,
    manifestSha256: manifest.manifestSha256,
    expiresAt: manifest.metadata.expiresAt,
    project: manifest.project,
    artifact: { sha256: copied.snapshot.sha256, bytes: copied.snapshot.bytes },
    adapter: manifest.operation.adapter,
    networkPolicy: "none",
    limits: manifest.limits,
    enforcement: manifest.enforcement,
    confirmationRequired: `ANALYZE ${manifestId} ${manifest.manifestSha256} OFFLINE`,
    purgeConfirmationRequired: `PURGE ${manifestId} ${manifest.manifestSha256} OFFLINE ARTIFACT`,
    manifestRef: `private://offline-analysis/manifests/${manifestId}.json`
  };
}

function emptyStream(reference) {
  return { ref: reference, available: false, sha256: null, bytes: 0 };
}

function newRun(manifest) {
  return {
    $schema: "../../schemas/offline-analysis-run.schema.json",
    apiVersion: "gate.offline-analysis-run/v1",
    kind: "OfflineAnalysisRun",
    runId: manifest.metadata.runId,
    manifestId: manifest.metadata.id,
    manifestSha256: manifest.manifestSha256,
    projectId: manifest.project.id,
    status: "queued",
    createdAt: new Date().toISOString(),
    startedAt: null,
    finishedAt: null,
    terminationReason: null,
    result: { exitCode: null, signal: null, durationMs: null },
    evidence: {
      stdout: emptyStream(manifest.runtime.evidence.stdoutRef),
      stderr: emptyStream(manifest.runtime.evidence.stderrRef),
      resultRef: manifest.runtime.evidence.resultRef,
      resultAvailable: false,
      sandboxRef: manifest.runtime.sandboxRef
    },
    isolationVerified: null
  };
}

function assertRunInvariants(run) {
  const refs = evidenceRefs(run.runId);
  if (
    run.evidence.stdout.ref !== refs.stdoutRef || run.evidence.stderr.ref !== refs.stderrRef ||
    run.evidence.resultRef !== refs.resultRef || run.evidence.sandboxRef !== expectedSandboxRef(run.runId)
  ) throw new Error("offline analysis run evidence binding is invalid");
  if (run.status === "queued" && (run.startedAt || run.finishedAt || run.terminationReason)) {
    throw new Error("queued offline analysis lifecycle is invalid");
  }
  if (run.status === "running" && (!run.startedAt || run.finishedAt || run.terminationReason)) {
    throw new Error("running offline analysis lifecycle is invalid");
  }
  if (new Set(["succeeded", "failed", "cancelled", "blocked", "unknown"]).has(run.status) && !run.finishedAt) {
    throw new Error("terminal offline analysis must have a finish time");
  }
  if (run.status === "succeeded" && (run.terminationReason !== "completed" || run.result.exitCode !== 0 || run.isolationVerified !== true)) {
    throw new Error("successful offline analysis result is invalid");
  }
  for (const stream of [run.evidence.stdout, run.evidence.stderr]) {
    if (stream.available !== (stream.sha256 !== null)) throw new Error("offline evidence availability does not match its digest");
    if (!stream.available && stream.bytes !== 0) throw new Error("unavailable offline evidence cannot claim bytes");
  }
}

function writeRun(paths, run) {
  assertValidDocument(run, "offline-analysis-run.schema.json", { paths });
  assertRunInvariants(run);
  writePrivateFileAtomic(runFile(paths, run.runId), `${JSON.stringify(run, null, 2)}\n`, {
    encoding: "utf8",
    label: `private offline analysis run ${run.runId}`
  });
  syncPrivateDirectory(paths.offlineAnalysisRuns, {
    label: "private offline analysis runs directory"
  });
}

function exactConfirmation(manifest) {
  return `ANALYZE ${manifest.metadata.id} ${manifest.manifestSha256} OFFLINE`;
}

function exactPurgeConfirmation(manifest) {
  return `PURGE ${manifest.metadata.id} ${manifest.manifestSha256} OFFLINE ARTIFACT`;
}

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(String(left));
  const rightBuffer = Buffer.from(String(right));
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function newPurgeRecord(manifest, transition) {
  return {
    $schema: "../../schemas/offline-analysis-purge.schema.json",
    apiVersion: "gate.offline-analysis-purge/v1",
    kind: "OfflineAnalysisArtifactPurge",
    manifestId: manifest.metadata.id,
    runId: manifest.metadata.runId,
    manifestSha256: manifest.manifestSha256,
    projectId: manifest.project.id,
    transition,
    status: "claimed",
    requestedAt: new Date().toISOString(),
    completedAt: null,
    artifact: {
      snapshotRef: manifest.operation.artifact.snapshotRef,
      sha256: manifest.operation.artifact.sha256,
      bytes: manifest.operation.artifact.bytes
    },
    bytesFreed: 0
  };
}

function assertPurgeInvariants(purge, manifest) {
  if (
    purge.manifestId !== manifest.metadata.id || purge.runId !== manifest.metadata.runId ||
    purge.manifestSha256 !== manifest.manifestSha256 || purge.projectId !== manifest.project.id ||
    purge.artifact?.snapshotRef !== manifest.operation.artifact.snapshotRef ||
    purge.artifact?.sha256 !== manifest.operation.artifact.sha256 ||
    purge.artifact?.bytes !== manifest.operation.artifact.bytes
  ) throw new Error("offline artifact purge binding is invalid");
  if (purge.status === "claimed" && (purge.completedAt !== null || purge.bytesFreed !== 0)) {
    throw new Error("claimed offline artifact purge lifecycle is invalid");
  }
  if (
    purge.status === "purged" &&
    (!Number.isFinite(Date.parse(purge.completedAt)) || purge.bytesFreed !== manifest.operation.artifact.bytes)
  ) throw new Error("completed offline artifact purge lifecycle is invalid");
}

function readPurge(paths, manifest) {
  const purge = JSON.parse(readPrivateFileBounded(
    purgeFile(paths, manifest.metadata.id),
    MAX_PURGE_BYTES,
    "utf8",
    { label: `offline artifact purge ${manifest.metadata.id}` }
  ));
  assertValidDocument(purge, "offline-analysis-purge.schema.json", { paths });
  assertPurgeInvariants(purge, manifest);
  return purge;
}

function readPurgeIfPresent(paths, manifest) {
  try {
    return readPurge(paths, manifest);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

function writePurge(paths, purge, manifest, options = {}) {
  assertValidDocument(purge, "offline-analysis-purge.schema.json", { paths });
  assertPurgeInvariants(purge, manifest);
  const content = `${JSON.stringify(purge, null, 2)}\n`;
  if (options.exclusive) {
    atomicExclusiveRecord(paths, purgeFile(paths, purge.manifestId), content, {
      encoding: "utf8",
      kind: "purge",
      id: purge.manifestId,
      label: `offline artifact purge ${purge.manifestId}`
    });
  } else {
    writePrivateFileAtomic(purgeFile(paths, purge.manifestId), content, {
      encoding: "utf8",
      label: `offline artifact purge ${purge.manifestId}`
    });
    syncPrivateDirectory(paths.offlineAnalysisPurges, { label: "offline artifact purge directory" });
  }
}

function purgeClaim(manifest) {
  return {
    apiVersion: "gate.offline-analysis-purge-claim/v1",
    manifestId: manifest.metadata.id,
    runId: manifest.metadata.runId,
    manifestSha256: manifest.manifestSha256,
    projectId: manifest.project.id,
    claimedAt: new Date().toISOString()
  };
}

function claimPurgeIfUnconsumed(paths, manifest) {
  let claim;
  try {
    claim = readClaimMetadata(paths, manifest.metadata.id);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (!claim) {
    try {
      fs.lstatSync(runFile(paths, manifest.metadata.runId));
      throw new Error("offline analysis run exists without its durable execution claim");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    try {
      atomicExclusiveRecord(
        paths,
        claimFile(paths, manifest.metadata.id),
        `${JSON.stringify(purgeClaim(manifest))}\n`,
        {
          encoding: "utf8",
          kind: "claim",
          id: manifest.metadata.id,
          label: `offline artifact purge claim ${manifest.metadata.id}`
        }
      );
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
    }
    claim = readClaimMetadata(paths, manifest.metadata.id);
  }
  if (
    claim.runId !== manifest.metadata.runId || claim.manifestSha256 !== manifest.manifestSha256 ||
    claim.projectId !== manifest.project.id
  ) throw new Error("offline analysis claim does not match the purge manifest");
  return claim;
}

function purgeTransition(paths, manifest, claim) {
  if (claim.claimKind === "purge") {
    return Date.now() >= Date.parse(manifest.metadata.expiresAt) ? "expired" : "abandoned";
  }
  const run = readRun(paths, manifest.metadata.runId);
  if (
    run.manifestId !== manifest.metadata.id || run.manifestSha256 !== manifest.manifestSha256 ||
    run.projectId !== manifest.project.id
  ) throw new Error("offline analysis run does not match the purge manifest");
  if (!new Set(["succeeded", "failed", "cancelled", "blocked"]).has(run.status)) {
    throw new Error(`offline artifact cannot be purged while its run is ${run.status}`);
  }
  return "terminal";
}

function openSnapshotForPurge(manifest, paths) {
  const file = snapshotPath(paths, manifest.operation.artifact.snapshotRef);
  const descriptor = openSnapshot(manifest, paths);
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    const named = fs.lstatSync(file, { bigint: true });
    if (!sameStat(opened, named)) throw new Error("offline artifact snapshot changed before purge");
    return { descriptor, file, opened };
  } catch (error) {
    closeDescriptor(descriptor);
    throw error;
  }
}

function unlinkSnapshotForPurge(opened, paths) {
  try {
    const named = fs.lstatSync(opened.file, { bigint: true });
    if (!sameStat(opened.opened, named)) throw new Error("offline artifact snapshot changed during purge");
    fs.unlinkSync(opened.file);
    syncPrivateDirectory(paths.offlineAnalysisInputs, { label: "offline artifact input directory" });
  } finally {
    closeDescriptor(opened.descriptor);
  }
}

function readProcIdentityFile(file, maximumBytes = 4096) {
  if (!fs.constants.O_NOFOLLOW) throw new Error("the platform cannot read process identity without following links");
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const chunks = [];
    let bytes = 0;
    const buffer = Buffer.allocUnsafe(1024);
    while (true) {
      const read = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (read === 0) break;
      bytes += read;
      if (bytes > maximumBytes) throw new Error("process identity record exceeds its byte limit");
      chunks.push(Buffer.from(buffer.subarray(0, read)));
    }
    return Buffer.concat(chunks).toString("utf8").trim();
  } finally {
    closeDescriptor(descriptor);
  }
}

function linuxBootIdentity() {
  const bootId = readProcIdentityFile("/proc/sys/kernel/random/boot_id", 128);
  if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u.test(bootId)) {
    throw new Error("Linux boot identity is malformed");
  }
  return bootId;
}

function linuxProcessStartTimeTicks(pid) {
  const stat = readProcIdentityFile(`/proc/${pid}/stat`, 4096);
  const commandEnd = stat.lastIndexOf(")");
  if (commandEnd < 2 || stat[commandEnd + 1] !== " ") throw new Error("Linux process identity is malformed");
  const fields = stat.slice(commandEnd + 2).split(" ");
  // The suffix starts at proc(5) field 3; starttime is field 22.
  const startTimeTicks = fields[19];
  if (!/^[0-9]{1,32}$/u.test(startTimeTicks || "")) throw new Error("Linux process start time is malformed");
  return startTimeTicks;
}

function linuxProcessIdentity(pid) {
  if (process.platform !== "linux" || !Number.isSafeInteger(pid) || pid < 1) {
    throw new Error("Linux supervisor process identity is unavailable");
  }
  const bootId = linuxBootIdentity();
  const startTimeTicks = linuxProcessStartTimeTicks(pid);
  return { bootId, startTimeTicks };
}

function durableClaim(paths, manifest, run) {
  const supervisorIdentity = linuxProcessIdentity(process.pid);
  try {
    atomicExclusiveRecord(paths, claimFile(paths, manifest.metadata.id), `${JSON.stringify({
      apiVersion: "gate.offline-analysis-claim/v1",
      manifestId: manifest.metadata.id,
      runId: manifest.metadata.runId,
      manifestSha256: manifest.manifestSha256,
      projectId: manifest.project.id,
      claimedAt: new Date().toISOString(),
      supervisorPid: process.pid,
      supervisorIdentity
    })}\n`, {
      encoding: "utf8",
      kind: "claim",
      id: manifest.metadata.id,
      label: `offline analysis one-shot claim ${manifest.metadata.id}`
    });
  } catch (error) {
    if (error.code === "EEXIST") throw new Error(`offline analysis manifest was already consumed: ${manifest.metadata.id}`);
    throw error;
  }
}

function openDirectory(directory, label) {
  const resolved = fs.realpathSync.native(directory);
  const before = fs.lstatSync(resolved, { bigint: true });
  if (!before.isDirectory() || before.isSymbolicLink()) throw new Error(`${label} must be a regular directory`);
  const descriptor = fs.openSync(resolved, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0) | (fs.constants.O_NOFOLLOW || 0));
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!opened.isDirectory() ||
      before.dev !== opened.dev || before.ino !== opened.ino ||
      before.uid !== opened.uid || before.gid !== opened.gid || before.mode !== opened.mode) {
      throw new Error(`${label} changed while it was opened`);
    }
    return descriptor;
  } catch (error) {
    closeDescriptor(descriptor);
    throw error;
  }
}

function openIdentityBoundFile(file, options, expected, identityLabel) {
  const opened = openObservedFile(file, options);
  try {
    assertIdentity(opened.value, expected, identityLabel);
    return opened.descriptor;
  } catch (error) {
    closeDescriptor(opened.descriptor);
    throw error;
  }
}

function openSnapshot(manifest, paths) {
  const file = snapshotPath(paths, manifest.operation.artifact.snapshotRef);
  const descriptor = openPrivateFile(file, { operation: "read", label: `offline artifact snapshot ${manifest.metadata.runId}` });
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    const digest = fileHash(descriptor, MAX_ARTIFACT_BYTES);
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (!sameStat(before, after) || digest.bytes !== manifest.operation.artifact.bytes || digest.sha256 !== manifest.operation.artifact.sha256) {
      throw new Error("offline artifact snapshot changed after manifest creation");
    }
    return descriptor;
  } catch (error) {
    closeDescriptor(descriptor);
    throw error;
  }
}

function prepareLaunch(manifest, paths) {
  const runtime = runtimeStillMatches(manifest, paths);
  const resources = {
    bwrap: null,
    artifact: null,
    nodeDirectory: null,
    reaDirectory: null,
    adapter: null
  };
  try {
    resources.bwrap = openIdentityBoundFile(
      runtime.bwrapPath,
      { label: "Bubblewrap executable", executable: true },
      manifest.runtime.bwrap,
      "bwrap"
    );
    closeDescriptor(openIdentityBoundFile(
      runtime.nodePath,
      { label: "Node executable", executable: true },
      manifest.runtime.node,
      "node"
    ));
    resources.adapter = openIdentityBoundFile(
      runtime.adapterPath,
      { label: "offline adapter" },
      manifest.runtime.adapter,
      "adapter"
    );
    closeDescriptor(openIdentityBoundFile(
      runtime.reaEntryPath,
      { label: "REA entrypoint" },
      manifest.runtime.reaEntry,
      "reaEntry"
    ));
    resources.artifact = openSnapshot(manifest, paths);
    resources.nodeDirectory = openDirectory(runtime.nodeDirectory, "Node runtime directory");
    resources.reaDirectory = openDirectory(runtime.reaDirectory, "REA installation directory");
    return { runtime, resources };
  } catch (error) {
    for (const descriptor of Object.values(resources)) closeDescriptor(descriptor);
    throw error;
  }
}

function bwrapArguments(manifest, runtime) {
  const nodeName = path.basename(runtime.nodePath);
  const reaRelative = path.relative(runtime.reaDirectory, runtime.reaEntryPath).split(path.sep).join("/");
  if (!/^[A-Za-z0-9._+-]+$/u.test(nodeName) || reaRelative !== "node_modules/rea-agents/scripts/rea.mjs") {
    throw new Error("offline runtime command paths are outside the fixed adapter contract");
  }
  const args = [
    "--unshare-user",
    "--unshare-pid",
    "--unshare-net",
    "--unshare-ipc",
    "--unshare-uts",
    "--unshare-cgroup-try",
    "--disable-userns",
    "--die-with-parent",
    "--new-session",
    "--cap-drop", "ALL",
    "--hostname", "gate-offline",
    "--clearenv",
    "--ro-bind", "/usr", "/usr",
    "--symlink", "usr/bin", "/bin",
    "--symlink", "usr/lib", "/lib",
    "--symlink", "usr/lib64", "/lib64",
    "--proc", "/proc",
    "--dev", "/dev",
    "--tmpfs", "/tmp",
    "--dir", "/input",
    "--dir", "/opt",
    "--dir", "/opt/gate",
    "--dir", "/home",
    "--dir", "/home/gate",
    "--ro-bind-fd", "4", "/input/artifact",
    "--ro-bind-fd", "5", "/opt/gate/node",
    "--ro-bind-fd", "6", "/opt/gate/rea",
    "--ro-bind-fd", "7", "/opt/gate/adapter.mjs",
    "--chdir", "/tmp"
  ];
  for (const [name, value] of Object.entries(SANDBOX_ENVIRONMENT)) args.push("--setenv", name, value);
  args.push(
    "--",
    `/opt/gate/node/${nodeName}`,
    "/opt/gate/adapter.mjs",
    `/opt/gate/rea/${reaRelative}`,
    "/input/artifact",
    String(MAX_ARTIFACT_BYTES),
    String(ADAPTER_MAX_ENTRIES)
  );
  return args;
}

function streamCapture(stream, descriptor, maximumBytes, onLimit) {
  const hash = crypto.createHash("sha256");
  let bytes = 0;
  let failed = false;
  stream.on("data", (chunk) => {
    if (failed) return;
    try {
      const remaining = maximumBytes - bytes;
      const accepted = chunk.subarray(0, Math.max(0, remaining));
      let offset = 0;
      while (offset < accepted.length) {
        const written = fs.writeSync(descriptor, accepted, offset, accepted.length - offset);
        if (!Number.isInteger(written) || written < 1) throw new Error("offline evidence write made no progress");
        hash.update(accepted.subarray(offset, offset + written));
        bytes += written;
        offset += written;
      }
      if (accepted.length !== chunk.length) {
        failed = true;
        onLimit();
      }
    } catch {
      failed = true;
      onLimit("evidence-write-failure");
    }
  });
  stream.on("error", () => {
    failed = true;
    onLimit("evidence-write-failure");
  });
  return {
    finish() {
      fs.fsyncSync(descriptor);
      return { available: true, sha256: hash.digest("hex"), bytes };
    }
  };
}

function validatedAdapterResult(bytes, manifest) {
  let result;
  try { result = JSON.parse(bytes.toString("utf8")); } catch { throw new Error("offline adapter returned invalid JSON"); }
  if (
    result?.apiVersion !== "gate.offline-adapter-result/v1" || result.adapterId !== ADAPTER_ID ||
    result.action !== "local-static-analysis" || result.networkPolicy !== "none"
  ) throw new Error("offline adapter result binding is invalid");
  if (
    result.artifact?.sha256 !== manifest.operation.artifact.sha256 ||
    result.artifact?.bytes !== manifest.operation.artifact.bytes
  ) throw new Error("offline adapter analyzed a different artifact");
  const zeroCapabilities = ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]
    .every((key) => result.isolation?.capabilities?.[key] === "0000000000000000");
  if (
    canonicalDigest(result.isolation?.interfaces) !== canonicalDigest(["lo"]) ||
    canonicalDigest(result.isolation?.ipv4Routes) !== canonicalDigest([]) ||
    result.isolation?.noNewPrivileges !== true || !zeroCapabilities
  ) throw new Error("offline adapter isolation evidence is invalid");
  return result;
}

function signalGroup(child, signal) {
  if (!child?.pid) return;
  try { process.kill(-child.pid, signal); } catch {
    try { child.kill(signal); } catch { /* Child may already have exited. */ }
  }
}

export async function executeOfflineAnalysisManifest(projectId, input, options = {}) {
  assertInputKeys(input, new Set(["manifestId", "confirm"]), "offline analysis execution input");
  const paths = publicPaths(options, "offline analysis execution");
  ensureRuntime(paths);
  const manifest = readManifest(paths, String(input.manifestId || ""));
  if (manifest.project.id !== projectId) throw new Error("offline analysis manifest belongs to a different project");
  if (Date.now() >= Date.parse(manifest.metadata.expiresAt)) throw new Error("offline analysis manifest expired");
  if (!safeEqual(input.confirm, exactConfirmation(manifest))) {
    throw new Error(`offline analysis confirmation must be exactly: ${exactConfirmation(manifest)}`);
  }
  if (process.geteuid() !== manifest.runtime.uid || process.getegid() !== manifest.runtime.gid) {
    throw new Error("offline analysis user changed after manifest creation");
  }
  bindingStillMatches(manifest, paths);
  let run = newRun(manifest);
  withRetentionLock(paths, () => durableClaim(paths, manifest, run));
  writeRun(paths, run);

  let launch = null;
  let stdoutDescriptor = null;
  let stderrDescriptor = null;
  let child = null;
  let childClosed = false;
  let closedPromise = null;
  let launchAttempted = false;
  let terminationReason = null;
  let killTimer = null;
  let deadlineTimer = null;
  let resultEvidencePersisted = false;
  let terminalPersisted = false;
  const startedClock = Date.now();
  const stop = (reason = "duration-limit") => {
    terminationReason ||= reason;
    if (!child?.pid) return;
    signalGroup(child, "SIGTERM");
    killTimer ||= setTimeout(() => signalGroup(child, "SIGKILL"), TERMINATION_GRACE_MS);
    killTimer.unref?.();
  };
  const signalHandler = () => stop("supervisor-signal");
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(signal, signalHandler);

  try {
    offlineEvent(manifest, "offline-analysis.queued", "queued", "Claimed a one-shot offline static-analysis manifest.", { paths });
    bindingStillMatches(manifest, paths);
    launch = prepareLaunch(manifest, paths);
    bindingStillMatches(manifest, paths);
    const stdoutPath = evidencePath(paths, manifest.runtime.evidence.stdoutRef);
    const stderrPath = evidencePath(paths, manifest.runtime.evidence.stderrRef);
    stdoutDescriptor = openPrivateFileExclusive(stdoutPath, { label: `offline stdout ${manifest.metadata.runId}` });
    stderrDescriptor = openPrivateFileExclusive(stderrPath, { label: `offline stderr ${manifest.metadata.runId}` });
    const args = bwrapArguments(manifest, launch.runtime);
    // Yield once after the potentially long integrity preflight so a signal
    // delivered while synchronous verification was running is observed before
    // launch. Recheck the short-lived authority at the last possible point.
    await new Promise((resolve) => setImmediate(resolve));
    if (terminationReason === "supervisor-signal") {
      throw new Error("offline analysis was cancelled before launch by a supervisor signal");
    }
    if (Date.now() >= Date.parse(manifest.metadata.expiresAt)) {
      terminationReason = "manifest-expired";
      throw new Error("offline analysis manifest expired during preflight");
    }
    launchAttempted = true;
    child = spawn("/proc/self/fd/3", args, {
      argv0: "bwrap",
      cwd: "/",
      env: {},
      detached: true,
      shell: false,
      stdio: [
        "ignore",
        "pipe",
        "pipe",
        launch.resources.bwrap,
        launch.resources.artifact,
        launch.resources.nodeDirectory,
        launch.resources.reaDirectory,
        launch.resources.adapter
      ]
    });
    closedPromise = new Promise((resolve) => {
      let spawnError = null;
      child.once("error", (error) => { spawnError = error; });
      child.once("close", (code, signal) => {
        childClosed = true;
        resolve({ code, signal, spawnError });
      });
    });
    const onCaptureFailure = (reason = "evidence-limit") => stop(reason);
    const stdoutCapture = streamCapture(child.stdout, stdoutDescriptor, MAX_EVIDENCE_BYTES, onCaptureFailure);
    const stderrCapture = streamCapture(child.stderr, stderrDescriptor, MAX_EVIDENCE_BYTES, onCaptureFailure);
    await new Promise((resolve, reject) => {
      child.once("spawn", resolve);
      child.once("error", reject);
    });
    run.status = "running";
    run.startedAt = new Date().toISOString();
    writeRun(paths, run);
    offlineEvent(manifest, "offline-analysis.started", "running", "Started REA inside a zero-network Bubblewrap namespace.", { paths });
    deadlineTimer = setTimeout(() => stop("duration-limit"), manifest.limits.maxMinutes * 60_000);
    deadlineTimer.unref?.();
    const outcome = await closedPromise;
    if (deadlineTimer) clearTimeout(deadlineTimer);
    if (killTimer) clearTimeout(killTimer);
    const stdoutEvidence = stdoutCapture.finish();
    const stderrEvidence = stderrCapture.finish();
    closeDescriptor(stdoutDescriptor);
    closeDescriptor(stderrDescriptor);
    stdoutDescriptor = null;
    stderrDescriptor = null;
    run.evidence.stdout = { ...run.evidence.stdout, ...stdoutEvidence };
    run.evidence.stderr = { ...run.evidence.stderr, ...stderrEvidence };
    if (outcome.spawnError && !terminationReason) terminationReason = "spawn-failure";
    if (!terminationReason && (outcome.code !== 0 || outcome.signal)) terminationReason = "tool-failed";
    let adapterResult = null;
    if (!terminationReason) {
      adapterResult = validatedAdapterResult(readPrivateFileBounded(
        stdoutPath,
        MAX_EVIDENCE_BYTES,
        null,
        { label: `offline stdout ${manifest.metadata.runId}` }
      ), manifest);
      terminationReason = "completed";
    }
    const finishedAt = new Date();
    run.status = terminationReason === "completed"
      ? "succeeded"
      : new Set(["duration-limit", "supervisor-signal"]).has(terminationReason)
        ? "cancelled"
        : "failed";
    run.finishedAt = finishedAt.toISOString();
    run.terminationReason = terminationReason;
    run.result = {
      exitCode: Number.isInteger(outcome.code) ? outcome.code : null,
      signal: outcome.signal || null,
      durationMs: Math.max(0, finishedAt.getTime() - startedClock)
    };
    run.isolationVerified = adapterResult ? true : false;
    const resultEvidence = {
      apiVersion: "gate.offline-analysis-result/v1",
      runId: run.runId,
      manifestId: run.manifestId,
      manifestSha256: run.manifestSha256,
      project: manifest.project,
      artifact: { sha256: manifest.operation.artifact.sha256, bytes: manifest.operation.artifact.bytes },
      status: run.status,
      terminationReason: run.terminationReason,
      result: run.result,
      isolationVerified: run.isolationVerified,
      stdout: run.evidence.stdout,
      stderr: run.evidence.stderr,
      enforcement: manifest.enforcement
    };
    writePrivateFileExclusive(evidencePath(paths, run.evidence.resultRef), `${JSON.stringify(resultEvidence, null, 2)}\n`, {
      encoding: "utf8",
      label: `offline analysis result ${run.runId}`
    });
    resultEvidencePersisted = true;
    run.evidence.resultAvailable = true;
    writeRun(paths, run);
    terminalPersisted = true;
    offlineEvent(
      manifest,
      "offline-analysis.completed",
      run.status,
      `Offline static analysis finished with status ${run.status}.`,
      { paths, evidenceRefs: [run.evidence.stdout.ref, run.evidence.stderr.ref, run.evidence.resultRef] }
    );
    return {
      ok: run.status === "succeeded",
      status: run.status,
      runId: run.runId,
      manifestId: run.manifestId,
      terminationReason: run.terminationReason,
      result: run.result,
      isolationVerified: run.isolationVerified,
      evidence: run.evidence
    };
  } catch (error) {
    if (child?.pid && !childClosed) {
      stop(terminationReason || "spawn-failure");
      if (closedPromise) await closedPromise;
      else await new Promise((resolve) => child.once("close", resolve));
    }
    if (deadlineTimer) clearTimeout(deadlineTimer);
    if (killTimer) clearTimeout(killTimer);
    if (!terminalPersisted) {
      const finishedAt = new Date();
      const alreadyTerminal = new Set(["succeeded", "failed", "cancelled", "blocked", "unknown"]).has(run.status);
      if (alreadyTerminal && !resultEvidencePersisted) {
        run.status = "failed";
        run.terminationReason = "evidence-write-failure";
        run.evidence.resultAvailable = false;
      } else if (!alreadyTerminal) {
        const cancelledBeforeLaunch = !launchAttempted && terminationReason === "supervisor-signal";
        run.status = cancelledBeforeLaunch ? "cancelled" : launchAttempted ? "failed" : "blocked";
        run.terminationReason = cancelledBeforeLaunch
          ? "supervisor-signal"
          : launchAttempted
            ? (terminationReason || "result-validation-failed")
            : (terminationReason || "preflight-failed");
      }
      run.finishedAt ||= finishedAt.toISOString();
      run.result.durationMs = Math.max(0, finishedAt.getTime() - startedClock);
      run.isolationVerified ??= false;
      try {
        writeRun(paths, run);
        terminalPersisted = true;
      } catch { /* Preserve the primary error; status will surface the stale active record as unknown. */ }
      try {
        offlineEvent(manifest, "offline-analysis.completed", run.status, `Offline static analysis finished with status ${run.status}.`, { paths });
      } catch { /* Preserve the primary error. */ }
    }
    throw error;
  } finally {
    for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.off(signal, signalHandler);
    closeDescriptor(stdoutDescriptor);
    closeDescriptor(stderrDescriptor);
    if (launch) for (const descriptor of Object.values(launch.resources)) closeDescriptor(descriptor);
  }
}

function snapshotExists(manifest, paths) {
  try {
    fs.lstatSync(snapshotPath(paths, manifest.operation.artifact.snapshotRef));
    return true;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

function removeEmptyAnalysisSandboxByRunId(runId, paths) {
  if (!/^arun_[a-f0-9]{32}$/u.test(runId)) throw new Error("invalid offline analysis sandbox identifier");
  const directory = path.join(paths.offlineAnalysisSandboxes, runId);
  try {
    fs.lstatSync(directory);
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  try {
    securePrivateDirectory(directory, { create: false, label: `offline analysis sandbox ${runId}` });
    fs.rmdirSync(directory);
    syncPrivateDirectory(paths.offlineAnalysisSandboxes, { label: "offline analysis sandbox directory" });
  } catch (error) {
    if (!new Set(["ENOENT", "ENOTEMPTY", "EEXIST"]).has(error.code)) throw error;
  }
}

function removeEmptyAnalysisSandbox(manifest, paths) {
  removeEmptyAnalysisSandboxByRunId(manifest.metadata.runId, paths);
}

export function purgeOfflineAnalysisArtifact(projectId, input, options = {}) {
  assertInputKeys(input, new Set(["manifestId", "confirm"]), "offline artifact purge input");
  const paths = publicPaths(options, "offline artifact purge");
  ensureRuntime(paths);
  const manifest = readManifest(paths, String(input.manifestId || ""));
  if (manifest.project.id !== projectId) throw new Error("offline analysis manifest belongs to a different project");
  if (!safeEqual(input.confirm, exactPurgeConfirmation(manifest))) {
    throw new Error(`offline artifact purge confirmation must be exactly: ${exactPurgeConfirmation(manifest)}`);
  }

  const outcome = withRetentionLock(paths, () => {
    const current = readManifest(paths, manifest.metadata.id);
    if (current.manifestSha256 !== manifest.manifestSha256) {
      throw new Error("offline analysis manifest changed before artifact purge");
    }
    let purge = readPurgeIfPresent(paths, current);
    if (purge?.status === "purged") {
      if (snapshotExists(current, paths)) {
        throw new Error("purged offline artifact unexpectedly remains in private storage");
      }
      removeEmptyAnalysisSandbox(current, paths);
      return { purge, alreadyPurged: true };
    }

    const claim = claimPurgeIfUnconsumed(paths, current);
    const transition = purge?.transition || purgeTransition(paths, current, claim);
    if (purge && purge.transition !== transition) throw new Error("offline artifact purge transition changed");

    let opened = null;
    try {
      try {
        opened = openSnapshotForPurge(current, paths);
      } catch (error) {
        if (!(purge?.status === "claimed" && error.code === "ENOENT")) throw error;
      }
      if (!purge) {
        if (!opened) throw new Error("offline artifact snapshot is missing before purge intent was recorded");
        purge = newPurgeRecord(current, transition);
        writePurge(paths, purge, current, { exclusive: true });
      }
      if (opened) {
        const selected = opened;
        opened = null;
        unlinkSnapshotForPurge(selected, paths);
      }
      const completed = {
        ...purge,
        status: "purged",
        completedAt: new Date().toISOString(),
        bytesFreed: current.operation.artifact.bytes
      };
      writePurge(paths, completed, current);
      removeEmptyAnalysisSandbox(current, paths);
      return { purge: completed, alreadyPurged: false };
    } finally {
      closeDescriptor(opened?.descriptor);
    }
  });

  if (!outcome.alreadyPurged) {
    offlineEvent(manifest, "offline-analysis.artifact-purged", "succeeded", "Purged a digest-bound offline artifact snapshot.", {
      paths,
      effectClass: "host-write",
      evidenceRefs: [`private://offline-analysis/purges/${manifest.metadata.id}.json`]
    });
  }
  return {
    ok: true,
    manifestId: manifest.metadata.id,
    runId: manifest.metadata.runId,
    manifestSha256: manifest.manifestSha256,
    project: manifest.project,
    transition: outcome.purge.transition,
    status: outcome.purge.status,
    bytesFreed: outcome.purge.bytesFreed,
    completedAt: outcome.purge.completedAt,
    alreadyPurged: outcome.alreadyPurged,
    purgeRef: `private://offline-analysis/purges/${manifest.metadata.id}.json`
  };
}

function readRun(paths, id) {
  const run = JSON.parse(readPrivateFileBounded(
    runFile(paths, id),
    MAX_RUN_BYTES,
    "utf8",
    { label: `private offline analysis run ${id}` }
  ));
  assertValidDocument(run, "offline-analysis-run.schema.json", { paths });
  if (run.runId !== id) throw new Error("offline analysis run identifier does not match its filename");
  assertRunInvariants(run);
  return run;
}

function readClaimMetadata(paths, id) {
  const claim = JSON.parse(readPrivateFileBounded(
    claimFile(paths, id),
    MAX_CLAIM_BYTES,
    "utf8",
    { label: `private offline analysis claim ${id}` }
  ));
  const commonValid = claim?.manifestId === id && /^arun_[a-f0-9]{32}$/u.test(claim.runId || "") &&
    /^[a-f0-9]{64}$/u.test(claim.manifestSha256 || "") &&
    /^[a-z][a-z0-9-]{1,62}$/u.test(claim.projectId || "") && Number.isFinite(Date.parse(claim.claimedAt));
  if (claim?.apiVersion === "gate.offline-analysis-purge-claim/v1") {
    if (
      !commonValid ||
      Object.keys(claim).sort().join(",") !== "apiVersion,claimedAt,manifestId,manifestSha256,projectId,runId"
    ) throw new Error("offline artifact purge claim metadata is invalid");
    return {
      claimKind: "purge",
      runId: claim.runId,
      manifestId: claim.manifestId,
      manifestSha256: claim.manifestSha256,
      projectId: claim.projectId,
      claimedAt: claim.claimedAt
    };
  }
  if (
    claim?.apiVersion !== "gate.offline-analysis-claim/v1" || !commonValid ||
    !Number.isSafeInteger(claim.supervisorPid) || claim.supervisorPid < 1 ||
    !claim.supervisorIdentity ||
    !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u.test(claim.supervisorIdentity.bootId || "") ||
    !/^[0-9]{1,32}$/u.test(claim.supervisorIdentity.startTimeTicks || "") ||
    Object.keys(claim.supervisorIdentity).some((key) => !new Set(["bootId", "startTimeTicks"]).has(key))
  ) throw new Error("offline analysis claim metadata is invalid");
  return {
    claimKind: "execute",
    runId: claim.runId,
    manifestId: claim.manifestId,
    manifestSha256: claim.manifestSha256,
    projectId: claim.projectId,
    status: "unknown",
    createdAt: claim.claimedAt,
    startedAt: null,
    finishedAt: null,
    terminationReason: "supervision-lost",
    isolationVerified: null,
    supervisorPid: claim.supervisorPid,
    supervisorIdentity: claim.supervisorIdentity
  };
}

function supervisorIsAlive(claim) {
  try {
    const current = linuxProcessIdentity(claim.supervisorPid);
    return current.bootId === claim.supervisorIdentity.bootId &&
      current.startTimeTicks === claim.supervisorIdentity.startTimeTicks;
  } catch {
    return false;
  }
}

function boundedByteCount(value) {
  return Number(value > BigInt(Number.MAX_SAFE_INTEGER) ? BigInt(Number.MAX_SAFE_INTEGER) : value);
}

function creationIntentStatus(paths) {
  const names = fs.readdirSync(paths.offlineAnalysisCreations);
  const baseNames = names.filter((name) => /^amf_[a-f0-9]{32}\.json$/u.test(name));
  const publicationNames = names.filter((name) => /^amf_[a-f0-9]{32}\.publication\.json$/u.test(name));
  const recognized = new Set([...baseNames, ...publicationNames]);
  let invalidCreationIntents = names.length - recognized.size;
  const runIds = new Set();
  const intentIds = new Set();
  for (const name of baseNames) {
    const id = name.slice(0, -5);
    try {
      const intent = readCreationIntent(paths, id);
      intentIds.add(id);
      runIds.add(intent.runId);
      try {
        const publication = readCreationPublication(paths, id);
        if (publication.runId !== intent.runId || publication.projectId !== intent.projectId) {
          invalidCreationIntents += 1;
        }
      } catch (error) {
        if (error.code !== "ENOENT") invalidCreationIntents += 1;
      }
    } catch {
      invalidCreationIntents += 1;
    }
  }
  for (const name of publicationNames) {
    const id = name.slice(0, -".publication.json".length);
    if (!intentIds.has(id)) invalidCreationIntents += 1;
  }
  return {
    creatingManifests: baseNames.length,
    invalidCreationIntents,
    mutationBlocked: invalidCreationIntents > 0,
    runIds
  };
}

function retentionControlStatus(paths) {
  let lockState = "absent";
  let invalidControlRecords = 0;
  try {
    const { owner } = readRetentionLock(retentionLockFile(paths));
    try {
      lockState = processIdentityIsAlive(owner.pid, owner.processIdentity) ? "active" : "stale";
    } catch {
      lockState = "indeterminate";
      invalidControlRecords += 1;
    }
  } catch (error) {
    if (error.code !== "ENOENT") {
      lockState = "invalid";
      invalidControlRecords += 1;
    }
  }
  let pendingTransactions = 0;
  let invalidTransactionRecords = 0;
  let blockingTransactions = 0;
  const recordPattern = /^\.record-(?:creation|publication|manifest|claim|purge)-(?:amf|arun)_[a-f0-9]{32}-([1-9][0-9]*)-([a-f0-9]{32})-([0-9]{1,32})-[a-f0-9]{32}\.pending$/u;
  const lockPattern = /^\.retention-lock-([1-9][0-9]*)-([a-f0-9]{32})-([0-9]{1,32})-[a-f0-9]{32}\.pending$/u;
  for (const name of fs.readdirSync(paths.offlineAnalysisTransactions)) {
    const recordMatch = recordPattern.exec(name);
    const lockMatch = lockPattern.exec(name);
    const match = recordMatch || lockMatch;
    if (!match) {
      invalidTransactionRecords += 1;
      continue;
    }
    pendingTransactions += 1;
    const [, pidText, bootHex, startTimeTicks] = match;
    const bootId = `${bootHex.slice(0, 8)}-${bootHex.slice(8, 12)}-${bootHex.slice(12, 16)}-${bootHex.slice(16, 20)}-${bootHex.slice(20)}`;
    try {
      const live = processIdentityIsAlive(Number(pidText), { bootId, startTimeTicks });
      if (recordMatch && live) {
        blockingTransactions += 1;
      }
      if (!live) {
        privateFileObservation(
          path.join(paths.offlineAnalysisTransactions, name),
          MAX_CREATION_PUBLICATION_BYTES,
          `offline analysis transaction ${name}`
        );
      }
    } catch {
      invalidTransactionRecords += 1;
    }
  }
  invalidControlRecords += invalidTransactionRecords;
  return {
    lockState,
    pendingTransactions,
    blockingTransactions,
    invalidTransactionRecords,
    invalidControlRecords,
    mutationBlocked: new Set(["invalid", "indeterminate"]).has(lockState) ||
      invalidTransactionRecords > 0 || blockingTransactions > 0
  };
}

function offlineArtifactRetentionStatus(
  paths,
  manifests,
  executionClaims,
  purgeClaims,
  runsByRun,
  activeRunIds,
  invalidClaimIds,
  invalidClaimRecords,
  invalidRunIds,
  invalidRunRecordCount,
  controls
) {
  const scanned = scanRetainedArtifacts(paths);
  const unmatched = new Map(scanned.artifacts);
  const creations = creationIntentStatus(paths);
  // Count independently unusable on-disk records and controls, rather than
  // attempting to collapse related observations into one inferred root cause.
  let invalidEntries = scanned.invalidEntries + creations.invalidCreationIntents + controls.invalidControlRecords +
    invalidClaimRecords + invalidRunRecordCount;
  let effectiveInvalidClaimRecords = invalidClaimRecords;
  let invalidRunRecords = invalidRunRecordCount;
  let pendingManifests = 0;
  let expiredManifests = 0;
  let activeManifests = 0;
  let terminalManifests = 0;
  let unknownManifests = 0;
  let purgePendingManifests = 0;
  let purgedManifests = 0;
  let missingArtifacts = 0;
  let blockedManifests = 0;
  let invalidPurgeRecords = 0;
  const purgeRecordIds = new Set();
  for (const entry of directoryEntries(paths.offlineAnalysisPurges)) {
    const name = entry.name;
    if (/^amf_[a-f0-9]{32}\.json$/u.test(name)) purgeRecordIds.add(name.slice(0, -5));
    else {
      invalidEntries += 1;
      invalidPurgeRecords += 1;
    }
  }

  for (const { id, manifest } of manifests.records) {
    if (!manifest) {
      invalidEntries += 1;
      if (/^amf_[a-f0-9]{32}$/u.test(id)) {
        blockedManifests += 1;
        unknownManifests += 1;
      }
      continue;
    }
    const runId = manifest.metadata.runId;
    const artifact = unmatched.get(runId) || null;
    if (artifact) unmatched.delete(runId);
    if (invalidClaimIds.has(manifest.metadata.id)) {
      blockedManifests += 1;
      unknownManifests += 1;
      continue;
    }
    let purge = null;
    try {
      purge = readPurgeIfPresent(paths, manifest);
    } catch {
      invalidEntries += 1;
      invalidPurgeRecords += 1;
      blockedManifests += 1;
      unknownManifests += 1;
      purgeRecordIds.delete(manifest.metadata.id);
      continue;
    }
    purgeRecordIds.delete(manifest.metadata.id);
    if (purge?.status === "purged") {
      purgedManifests += 1;
      if (artifact) {
        purgePendingManifests += 1;
        invalidEntries += 1;
      }
      continue;
    }
    if (purge?.status === "claimed") {
      purgePendingManifests += 1;
      continue;
    }
    const artifactMissing = !artifact;
    if (artifactMissing) {
      missingArtifacts += 1;
      invalidEntries += 1;
    }
    const purgeClaimValue = purgeClaims.get(manifest.metadata.id);
    if (purgeClaimValue) {
      if (
        purgeClaimValue.runId !== runId || purgeClaimValue.manifestSha256 !== manifest.manifestSha256 ||
        purgeClaimValue.projectId !== manifest.project.id
      ) {
        invalidEntries += 1;
        effectiveInvalidClaimRecords += 1;
        blockedManifests += 1;
        unknownManifests += 1;
        continue;
      }
    }
    const claim = executionClaims.get(manifest.metadata.id);
    if (claim && (
      claim.runId !== runId || claim.manifestSha256 !== manifest.manifestSha256 ||
      claim.projectId !== manifest.project.id
    )) {
      invalidEntries += 1;
      effectiveInvalidClaimRecords += 1;
      blockedManifests += 1;
      unknownManifests += 1;
      continue;
    }
    if (invalidRunIds.has(runId)) {
      blockedManifests += 1;
      unknownManifests += 1;
      continue;
    }
    if (artifactMissing) continue;
    if (purgeClaimValue) {
      purgePendingManifests += 1;
      continue;
    }
    if (!claim) {
      if (Date.now() >= Date.parse(manifest.metadata.expiresAt)) expiredManifests += 1;
      else pendingManifests += 1;
      continue;
    }
    const run = runsByRun.get(runId);
    if (!run) {
      unknownManifests += 1;
    } else if (
      run.manifestId !== manifest.metadata.id || run.manifestSha256 !== manifest.manifestSha256 ||
      run.projectId !== manifest.project.id
    ) {
      invalidEntries += 1;
      invalidRunRecords += 1;
      blockedManifests += 1;
      unknownManifests += 1;
    } else if (new Set(["succeeded", "failed", "cancelled", "blocked"]).has(run.status)) {
      terminalManifests += 1;
    } else if (activeRunIds.has(runId)) {
      activeManifests += 1;
    } else {
      unknownManifests += 1;
    }
  }

  invalidEntries += purgeRecordIds.size;
  invalidPurgeRecords += purgeRecordIds.size;

  for (const runId of creations.runIds) unmatched.delete(runId);

  let orphanedBytes = 0n;
  for (const artifact of unmatched.values()) orphanedBytes += BigInt(artifact.bytes);
  const retainedBytes = boundedByteCount(scanned.bytes);
  return {
    quotaBytes: MAX_RETAINED_ARTIFACT_BYTES,
    quotaArtifacts: MAX_RETAINED_ARTIFACTS,
    retainedBytes,
    availableBytes: Math.max(0, MAX_RETAINED_ARTIFACT_BYTES - retainedBytes),
    availableArtifacts: Math.max(0, MAX_RETAINED_ARTIFACTS - scanned.artifacts.size),
    overQuota: scanned.bytes > BigInt(MAX_RETAINED_ARTIFACT_BYTES) || scanned.artifacts.size > MAX_RETAINED_ARTIFACTS,
    retainedArtifacts: scanned.artifacts.size,
    retentionLockState: controls.lockState,
    pendingTransactions: controls.pendingTransactions,
    blockingTransactions: controls.blockingTransactions,
    invalidTransactionRecords: controls.invalidTransactionRecords,
    creatingManifests: creations.creatingManifests,
    invalidCreationIntents: creations.invalidCreationIntents,
    invalidClaimRecords: effectiveInvalidClaimRecords,
    invalidPurgeRecords,
    invalidRunRecords,
    blockedManifests,
    mutationBlocked: scanned.invalidEntries > 0 || creations.mutationBlocked || controls.mutationBlocked,
    pendingManifests,
    expiredManifests,
    activeManifests,
    terminalManifests,
    unknownManifests,
    purgePendingManifests,
    purgedManifests,
    orphanedArtifacts: unmatched.size,
    orphanedBytes: boundedByteCount(orphanedBytes),
    missingArtifacts,
    invalidEntries
  };
}

function compactStatusManifest(manifest) {
  return {
    metadata: {
      id: manifest.metadata.id,
      runId: manifest.metadata.runId,
      expiresAt: manifest.metadata.expiresAt
    },
    manifestSha256: manifest.manifestSha256,
    project: { id: manifest.project.id },
    operation: {
      artifact: {
        snapshotRef: manifest.operation.artifact.snapshotRef,
        sha256: manifest.operation.artifact.sha256,
        bytes: manifest.operation.artifact.bytes
      }
    }
  };
}

function* directoryEntries(directory) {
  const handle = fs.opendirSync(directory);
  try {
    let entry;
    while ((entry = handle.readSync()) !== null) yield entry;
  } finally {
    handle.closeSync();
  }
}

function collectStatusManifests(paths) {
  const records = [];
  const byId = new Map();
  for (const entry of directoryEntries(paths.offlineAnalysisManifests)) {
    if (!entry.name.endsWith(".json")) continue;
    const id = entry.name.slice(0, -5);
    try {
      const manifest = compactStatusManifest(readManifest(paths, id));
      records.push({ id, manifest });
      byId.set(id, manifest);
    } catch {
      records.push({ id, manifest: null });
    }
  }
  return { records, byId };
}

function compareRecentOfflineAnalyses(left, right) {
  const created = String(right.createdAt).localeCompare(String(left.createdAt));
  if (created !== 0) return created;
  const run = left.runId.localeCompare(right.runId);
  if (run !== 0) return run;
  return left.manifestId.localeCompare(right.manifestId);
}

function retainRecentOfflineAnalysis(recent, metadata) {
  let lower = 0;
  let upper = recent.length;
  while (lower < upper) {
    const middle = Math.floor((lower + upper) / 2);
    if (compareRecentOfflineAnalyses(metadata, recent[middle]) < 0) upper = middle;
    else lower = middle + 1;
  }
  recent.splice(lower, 0, metadata);
  if (recent.length > MAX_RECENT_OFFLINE_ANALYSES) recent.pop();
}

function offlineStatusGeneration(paths) {
  const identities = {};
  for (const [key, directory] of [
    ["root", paths.offlineAnalyses],
    ["transactions", paths.offlineAnalysisTransactions],
    ["manifests", paths.offlineAnalysisManifests],
    ["creations", paths.offlineAnalysisCreations],
    ["claims", paths.offlineAnalysisClaims],
    ["purges", paths.offlineAnalysisPurges],
    ["runs", paths.offlineAnalysisRuns],
    ["inputs", paths.offlineAnalysisInputs],
    ["sandboxes", paths.offlineAnalysisSandboxes]
  ]) {
    const observed = fs.lstatSync(directory, { bigint: true });
    if (!observed.isDirectory() || observed.isSymbolicLink()) {
      throw new Error("offline analysis status directory identity is invalid");
    }
    identities[key] = {
      device: String(observed.dev),
      inode: String(observed.ino),
      size: String(observed.size),
      mtimeNs: String(observed.mtimeNs),
      ctimeNs: String(observed.ctimeNs)
    };
  }
  try {
    const observed = fs.lstatSync(retentionLockFile(paths), { bigint: true });
    identities.retentionLock = {
      device: String(observed.dev),
      inode: String(observed.ino),
      size: String(observed.size),
      mtimeNs: String(observed.mtimeNs),
      ctimeNs: String(observed.ctimeNs),
      type: observed.isFile() && !observed.isSymbolicLink() ? "file" : "invalid"
    };
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    identities.retentionLock = null;
  }
  return canonicalDigest(identities);
}

function collectOfflineAnalysisStatus(paths) {
  const recent = [];
  const counts = {
    queued: 0,
    running: 0,
    succeeded: 0,
    failed: 0,
    cancelled: 0,
    blocked: 0,
    unknown: 0
  };
  const recordProjection = (metadata) => {
    counts[metadata.status] += 1;
    retainRecentOfflineAnalysis(recent, metadata);
  };
  const claimsByManifest = new Map();
  const purgeClaimsByManifest = new Map();
  const runsByRun = new Map();
  const activeRunIds = new Set();
  const invalidClaimIds = new Set();
  const invalidRunIds = new Set();
  let invalidClaimRecords = 0;
  let invalidRunRecordCount = 0;
  let invalid = 0;
  const manifests = collectStatusManifests(paths);
  for (const entry of directoryEntries(paths.offlineAnalysisClaims)) {
    const name = entry.name;
    const id = name.endsWith(".json") ? name.slice(0, -5) : name;
    try {
      const metadata = readClaimMetadata(paths, id);
      if (metadata.claimKind === "purge") purgeClaimsByManifest.set(metadata.manifestId, metadata);
      else claimsByManifest.set(metadata.manifestId, metadata);
    } catch {
      invalid += 1;
      invalidClaimRecords += 1;
      if (/^amf_[a-f0-9]{32}$/u.test(id)) invalidClaimIds.add(id);
    }
  }
  for (const entry of directoryEntries(paths.offlineAnalysisRuns)) {
    const name = entry.name;
    const validName = /^arun_[a-f0-9]{32}\.json$/u.test(name);
    const id = name.endsWith(".json") ? name.slice(0, -5) : name;
    try {
      if (!validName) throw new Error("offline analysis run filename is invalid");
      const run = readRun(paths, id);
      runsByRun.set(run.runId, run);
      const claim = claimsByManifest.get(run.manifestId);
      const manifest = manifests.byId.get(run.manifestId);
      const manifestBindingInvalid = !manifest || manifest.metadata.runId !== run.runId ||
        manifest.manifestSha256 !== run.manifestSha256 || manifest.project.id !== run.projectId;
      const claimRecordInvalid = invalidClaimIds.has(run.manifestId);
      const claimMissing = !claim && !claimRecordInvalid;
      const claimBindingInvalid = Boolean(claim) && (
        claim.runId !== run.runId || claim.manifestId !== run.manifestId ||
        claim.projectId !== run.projectId || claim.manifestSha256 !== run.manifestSha256
      );
      const runRecordInvalid = manifestBindingInvalid || claimMissing;
      const projectionBindingInvalid = runRecordInvalid || claimRecordInvalid || claimBindingInvalid;
      if (runRecordInvalid) {
        invalidRunIds.add(run.runId);
        invalidRunRecordCount += 1;
      }
      const activeStatus = run.status === "queued" || run.status === "running";
      const activeSupervisor = activeStatus && !projectionBindingInvalid && supervisorIsAlive(claim);
      const staleActive = activeStatus && !activeSupervisor;
      if (activeSupervisor) activeRunIds.add(run.runId);
      recordProjection({
        runId: run.runId,
        manifestId: run.manifestId,
        projectId: run.projectId,
        status: staleActive || projectionBindingInvalid ? "unknown" : run.status,
        createdAt: run.createdAt,
        startedAt: run.startedAt,
        finishedAt: run.finishedAt,
        terminationReason: manifestBindingInvalid
          ? "manifest-binding-invalid"
          : claimRecordInvalid || claimMissing || claimBindingInvalid
            ? "claim-binding-invalid"
            : staleActive ? "supervision-lost" : run.terminationReason,
        isolationVerified: staleActive || projectionBindingInvalid ? null : run.isolationVerified
      });
    } catch {
      invalid += 1;
      invalidRunRecordCount += 1;
      if (/^arun_[a-f0-9]{32}$/u.test(id)) invalidRunIds.add(id);
    }
  }
  for (const metadata of claimsByManifest.values()) {
    if (!runsByRun.has(metadata.runId)) {
      const {
        supervisorPid: _supervisorPid,
        supervisorIdentity: _supervisorIdentity,
        manifestSha256: _manifestSha256,
        claimKind: _claimKind,
        ...projection
      } = metadata;
      recordProjection(projection);
    }
  }
  counts.unknown += invalid;
  const controls = retentionControlStatus(paths);
  return {
    retention: offlineArtifactRetentionStatus(
      paths,
      manifests,
      claimsByManifest,
      purgeClaimsByManifest,
      runsByRun,
      activeRunIds,
      invalidClaimIds,
      invalidClaimRecords,
      invalidRunIds,
      invalidRunRecordCount,
      controls
    ),
    counts,
    recent
  };
}

export function offlineAnalysisStatus(options = {}) {
  const paths = publicPaths(options, "offline analysis status");
  ensureRuntime(paths);
  let snapshot = null;
  let stable = false;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const before = offlineStatusGeneration(paths);
    snapshot = collectOfflineAnalysisStatus(paths);
    const after = offlineStatusGeneration(paths);
    if (before === after) {
      stable = true;
      break;
    }
  }
  if (!snapshot) throw new Error("offline analysis status snapshot is unavailable");
  const activeMutation = snapshot.retention.retentionLockState === "active";
  snapshot.retention.snapshotState = stable
    ? (activeMutation ? "mutation-active" : "consistent")
    : "indeterminate";
  if (!stable || activeMutation) snapshot.retention.mutationBlocked = true;
  return {
    capability: offlineAnalysisCapability({ paths }),
    ...snapshot
  };
}

export const offlineAnalysisInternals = Object.freeze({
  analysisPaths,
  bwrapArguments,
  canonicalSourcePath,
  exactPurgeConfirmation,
  manifestDigest,
  openDirectory,
  openIdentityBoundFile,
  scanRetainedArtifacts,
  validatedAdapterResult,
  withRetentionLock
});
