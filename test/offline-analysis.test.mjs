import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  createOfflineAnalysisManifest,
  executeOfflineAnalysisManifest,
  offlineAnalysisCapability,
  offlineAnalysisInternals,
  offlineAnalysisStatus,
  purgeOfflineAnalysisArtifact
} from "../src/lib/offline-analysis.mjs";
import { gateHome, runtimePaths } from "../src/lib/paths.mjs";
import { registerProject } from "../src/lib/projects.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const template = JSON.parse(fs.readFileSync(path.join(repo, "templates", "project.json"), "utf8"));
const upstreamLock = JSON.parse(fs.readFileSync(path.join(repo, "locks", "upstreams.lock.json"), "utf8"));
const reaLock = upstreamLock.upstreams.find(({ id }) => id === "rea-stable");
const realBwrap = ["/usr/bin/bwrap", "/bin/bwrap"].find((candidate) => fs.existsSync(candidate));
const realNode = fs.realpathSync.native(process.execPath);
const sourceManagedHome = gateHome();
const sourceReaDirectory = path.join(sourceManagedHome, "upstream-tools", "rea-stable");
const sourceReaEntry = path.join(sourceReaDirectory, "node_modules", "rea-agents", "scripts", "rea.mjs");
const productionAdapter = path.join(repo, "src", "adapters", "rea-pe-resources.mjs");
const MAX_EVIDENCE_BYTES = 64 * 1024 * 1024;

function upstreamBinding() {
  return {
    id: "rea-stable",
    version: reaLock.version,
    commit: reaLock.commit,
    packageIntegrity: reaLock.install.integrity,
    lockSha256: reaLock.install.lockSha256
  };
}

function project(id = "offline-project") {
  const value = structuredClone(template);
  value.metadata = { id, displayName: "Offline Analysis Fixture" };
  value.repository.url = `https://github.com/example/${id}`;
  return value;
}

function writeProjectSource(root, value = project()) {
  const source = path.join(root, "project.json");
  fs.writeFileSync(source, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  return source;
}

function writeMinimalPe(file) {
  const bytes = Buffer.alloc(512);
  bytes.writeUInt16LE(0x5a4d, 0);
  bytes.writeUInt32LE(0x80, 0x3c);
  bytes.writeUInt32LE(0x00004550, 0x80);
  bytes.writeUInt16LE(0x014c, 0x84);
  bytes.writeUInt16LE(0, 0x86);
  bytes.writeUInt16LE(96, 0x94);
  bytes.writeUInt16LE(0x010b, 0x98);
  bytes.writeUInt32LE(bytes.length, 0x98 + 60);
  bytes.writeUInt32LE(0, 0x98 + 92);
  fs.writeFileSync(file, bytes, { mode: 0o600 });
  return bytes;
}

let managedFixtureRoot = null;
let managedHome = null;
let managedSetupFailure = null;

function copyTree(source, destination) {
  fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
  const cp = ["/bin/cp", "/usr/bin/cp"].find((candidate) => fs.existsSync(candidate));
  if (cp) {
    const copied = spawnSync(cp, ["-a", "--reflink=auto", source, destination], {
      encoding: "utf8",
      timeout: 120_000
    });
    if (copied.status === 0) return;
  }
  fs.cpSync(source, destination, { recursive: true, preserveTimestamps: true });
}

function prepareManagedFixture() {
  if (integrationSkipReason()) return;
  try {
    managedFixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "gate-offline-managed-"));
    managedHome = path.join(managedFixtureRoot, "home");
    fs.mkdirSync(path.join(managedHome, "upstream-tools"), { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.join(managedHome, "cache"), { recursive: true, mode: 0o700 });
    copyTree(sourceReaDirectory, path.join(managedHome, "upstream-tools", "rea-stable"));
    copyTree(path.join(sourceManagedHome, "cache", "npm"), path.join(managedHome, "cache", "npm"));
    process.once("exit", () => fs.rmSync(managedFixtureRoot, { recursive: true, force: true }));
  } catch (error) {
    managedSetupFailure = error.message;
    if (managedFixtureRoot) fs.rmSync(managedFixtureRoot, { recursive: true, force: true });
    managedFixtureRoot = null;
    managedHome = null;
  }
}

function fixture(t) {
  if (!managedHome) throw new Error(`managed offline runtime fixture is unavailable: ${managedSetupFailure || integrationSkipReason()}`);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-offline-analysis-"));
  const caseRoot = path.join(managedHome, "test-cases", crypto.randomBytes(12).toString("hex"));
  const base = runtimePaths({ home: managedHome, repo });
  const offlineAnalyses = path.join(caseRoot, "offline-analysis");
  const paths = {
    ...base,
    events: path.join(caseRoot, "events.jsonl"),
    tokens: path.join(caseRoot, "tokens.jsonl"),
    evidence: path.join(caseRoot, "evidence"),
    projects: path.join(caseRoot, "projects"),
    offlineAnalyses,
    offlineAnalysisTransactions: path.join(offlineAnalyses, "transactions"),
    offlineAnalysisManifests: path.join(offlineAnalyses, "manifests"),
    offlineAnalysisCreations: path.join(offlineAnalyses, "creations"),
    offlineAnalysisClaims: path.join(offlineAnalyses, "claims"),
    offlineAnalysisPurges: path.join(offlineAnalyses, "purges"),
    offlineAnalysisRuns: path.join(offlineAnalyses, "runs"),
    offlineAnalysisInputs: path.join(offlineAnalyses, "inputs"),
    offlineAnalysisSandboxes: path.join(offlineAnalyses, "sandboxes")
  };
  registerProject(writeProjectSource(root), { paths });
  t.after(() => {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(caseRoot, { recursive: true, force: true });
  });
  return { root, paths, runtime: actualRuntime() };
}

function manifestPath(paths, id) {
  return path.join(paths.offlineAnalysisManifests, `${id}.json`);
}

function creationPath(paths, id) {
  return path.join(paths.offlineAnalysisCreations, `${id}.json`);
}

function claimPath(paths, id) {
  return path.join(paths.offlineAnalysisClaims, `${id}.json`);
}

function runPath(paths, id) {
  return path.join(paths.offlineAnalysisRuns, `${id}.json`);
}

function purgePath(paths, id) {
  return path.join(paths.offlineAnalysisPurges, `${id}.json`);
}

function snapshotPath(paths, runId) {
  return path.join(paths.offlineAnalysisInputs, `${runId}.bin`);
}

function readManifest(paths, id) {
  return JSON.parse(fs.readFileSync(manifestPath(paths, id), "utf8"));
}

function evidencePath(paths, reference) {
  assert.match(reference, /^private:\/\/evidence\/[^/]+$/u);
  return path.join(paths.evidence, reference.slice("private://evidence/".length));
}

function mode(file) {
  return fs.statSync(file).mode & 0o777;
}

function testProcessIdentity(pid = process.pid) {
  const bootId = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
  const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8").trim();
  const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
  return { bootId, startTimeTicks: fields[19] };
}

function actualRuntime(adapterPath = productionAdapter) {
  const reaDirectory = path.join(managedHome, "upstream-tools", "rea-stable");
  return {
    bwrapPath: realBwrap,
    nodePath: realNode,
    nodeDirectory: path.dirname(realNode),
    adapterPath,
    reaEntryPath: path.join(reaDirectory, "node_modules", "rea-agents", "scripts", "rea.mjs"),
    reaDirectory,
    upstream: upstreamBinding()
  };
}

function integrationSkipReason() {
  if (process.platform !== "linux") return "real Bubblewrap integration requires Linux";
  for (const candidate of [realBwrap, realNode, sourceReaEntry, productionAdapter, path.join(sourceManagedHome, "cache", "npm")]) {
    if (!candidate || !fs.existsSync(candidate)) return "the pinned local Bubblewrap/REA runtime is unavailable";
  }
  const probe = spawnSync(realBwrap, [
    "--unshare-user", "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts",
    "--unshare-cgroup-try", "--disable-userns", "--die-with-parent", "--new-session",
    "--cap-drop", "ALL", "--clearenv", "--ro-bind", "/usr", "/usr", "--proc", "/proc",
    "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
    "--symlink", "usr/lib64", "/lib64", "--dev", "/dev", "--", "/usr/bin/true"
  ], { encoding: "utf8", timeout: 10_000 });
  return probe.status === 0
    ? false
    : `Bubblewrap namespace probe failed: ${String(probe.stderr || probe.error?.message || probe.status).trim()}`;
}

const realIntegrationSkip = integrationSkipReason();
prepareManagedFixture();
const managedRuntimeSkip = realIntegrationSkip || managedSetupFailure;
if (process.env.GATE_REQUIRE_OFFLINE_INTEGRATION === "1" && managedRuntimeSkip) {
  throw new Error(`required offline-analysis integration runtime is unavailable: ${managedRuntimeSkip}`);
}

function managedTest(name, options, fn) {
  if (typeof options === "function") {
    return test(name, { skip: managedRuntimeSkip || false }, options);
  }
  return test(name, { ...options, skip: managedRuntimeSkip || options.skip || false }, fn);
}

test("public APIs reject runtime and capability injection options before side effects", async () => {
  const markerRoot = fs.mkdtempSync(path.join(os.tmpdir(), "gate-offline-injection-"));
  const marker = path.join(markerRoot, "resolver-ran");
  const runtimeResolver = () => {
    fs.writeFileSync(marker, "bypassed\n");
    return {};
  };
  try {
    const capability = offlineAnalysisCapability({ runtimeResolver });
    assert.equal(capability.laneAvailable, false);
    assert.match(capability.reason, /unsupported fields: runtimeResolver/u);
    const capabilityBypass = offlineAnalysisCapability({ capabilityRuntime: runtimeResolver });
    assert.equal(capabilityBypass.laneAvailable, false);
    assert.match(capabilityBypass.reason, /unsupported fields: capabilityRuntime/u);
    assert.throws(
      () => createOfflineAnalysisManifest("offline-project", { path: "/tmp/never-read.exe" }, { runtimeResolver }),
      /unsupported fields: runtimeResolver/u
    );
    await assert.rejects(
      executeOfflineAnalysisManifest("offline-project", { manifestId: "amf_00000000000000000000000000000000", confirm: "x" }, { runtimeResolver }),
      /unsupported fields: runtimeResolver/u
    );
    await assert.rejects(
      executeOfflineAnalysisManifest("offline-project", { manifestId: "amf_00000000000000000000000000000000", confirm: "x" }, {
        afterSpawn: runtimeResolver
      }),
      /unsupported fields: afterSpawn/u
    );
    assert.throws(() => offlineAnalysisStatus({ capabilityRuntime: {} }), /unsupported fields: capabilityRuntime/u);
    assert.equal(fs.existsSync(marker), false);
  } finally {
    fs.rmSync(markerRoot, { recursive: true, force: true });
  }
});

test("prelaunch validation closes descriptors on identity and directory errors", { skip: process.platform !== "linux" }, () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-offline-descriptors-"));
  const observedFile = path.join(root, "observed.bin");
  const observedDirectory = path.join(root, "observed-directory");
  fs.writeFileSync(observedFile, "descriptor fixture\n", { mode: 0o600 });
  fs.mkdirSync(observedDirectory, { mode: 0o700 });
  try {
    const originalOpenSync = fs.openSync;
    let fileDescriptor;
    fs.openSync = (...args) => {
      const descriptor = originalOpenSync(...args);
      if (args[0] === observedFile) fileDescriptor = descriptor;
      return descriptor;
    };
    try {
      assert.throws(
        () => offlineAnalysisInternals.openIdentityBoundFile(
          observedFile,
          { label: "descriptor fixture" },
          { path: "/identity-mismatch" },
          "fixture"
        ),
        /fixture path changed/u
      );
    } finally {
      fs.openSync = originalOpenSync;
    }
    assert.ok(Number.isSafeInteger(fileDescriptor));
    assert.throws(() => fs.fstatSync(fileDescriptor), (error) => error?.code === "EBADF");

    const originalFstatSync = fs.fstatSync;
    let directoryDescriptor;
    fs.openSync = (...args) => {
      const descriptor = originalOpenSync(...args);
      if (args[0] === observedDirectory) directoryDescriptor = descriptor;
      return descriptor;
    };
    fs.fstatSync = (descriptor, ...args) => {
      if (descriptor === directoryDescriptor) throw new Error("injected directory validation failure");
      return originalFstatSync(descriptor, ...args);
    };
    try {
      assert.throws(
        () => offlineAnalysisInternals.openDirectory(observedDirectory, "descriptor fixture directory"),
        /injected directory validation failure/u
      );
    } finally {
      fs.openSync = originalOpenSync;
      fs.fstatSync = originalFstatSync;
    }
    assert.ok(Number.isSafeInteger(directoryDescriptor));
    assert.throws(() => fs.fstatSync(directoryDescriptor), (error) => error?.code === "EBADF");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

managedTest("retention locks recover only a definitively stale owner and fail closed otherwise", (t) => {
  const { paths } = fixture(t);
  const lock = path.join(paths.offlineAnalyses, ".retention.lock");
  const identity = testProcessIdentity();
  const writeLock = (pid, processIdentity, extra = {}) => fs.writeFileSync(lock, `${JSON.stringify({
    apiVersion: "gate.offline-analysis-retention-lock/v1",
    pid,
    processIdentity,
    nonce: "a".repeat(32),
    createdAt: new Date().toISOString(),
    ...extra
  })}\n`, { mode: 0o600 });

  writeLock(2_147_483_647, { bootId: identity.bootId, startTimeTicks: "1" });
  assert.equal(offlineAnalysisInternals.withRetentionLock(paths, () => "recovered", { timeoutMs: 100 }), "recovered");
  assert.equal(fs.existsSync(lock), false);

  const linkedOwner = {
    apiVersion: "gate.offline-analysis-retention-lock/v1",
    pid: 2_147_483_647,
    processIdentity: { bootId: identity.bootId, startTimeTicks: "1" },
    nonce: "b".repeat(32),
    createdAt: new Date().toISOString()
  };
  const linkedStaging = path.join(
    paths.offlineAnalysisTransactions,
    `.retention-lock-${linkedOwner.pid}-${identity.bootId.replaceAll("-", "")}-1-${linkedOwner.nonce}.pending`
  );
  fs.writeFileSync(linkedStaging, `${JSON.stringify(linkedOwner)}\n`, { mode: 0o600 });
  fs.linkSync(linkedStaging, lock);
  assert.equal(offlineAnalysisInternals.withRetentionLock(paths, () => "linked-recovered", { timeoutMs: 100 }), "linked-recovered");
  assert.equal(fs.existsSync(linkedStaging), false);
  assert.equal(fs.existsSync(lock), false);

  writeLock(process.pid, identity);
  assert.throws(
    () => offlineAnalysisInternals.withRetentionLock(paths, () => "stolen", { timeoutMs: 30 }),
    /timed out waiting/u
  );
  assert.equal(fs.existsSync(lock), true);
  fs.rmSync(lock);

  fs.writeFileSync(lock, "{}\n", { mode: 0o600 });
  const malformedLockStatus = offlineAnalysisStatus({ paths });
  assert.equal(malformedLockStatus.retention.retentionLockState, "invalid");
  assert.equal(malformedLockStatus.retention.mutationBlocked, true);
  assert.ok(malformedLockStatus.retention.invalidEntries >= 1);
  assert.throws(
    () => offlineAnalysisInternals.withRetentionLock(paths, () => "unsafe", { timeoutMs: 30 }),
    /could not be recovered safely/u
  );
  assert.equal(fs.existsSync(lock), true);
  fs.rmSync(lock);
});

managedTest("a partial retention-lock owner write never publishes a malformed stable lock", (t) => {
  const { paths } = fixture(t);
  const lock = path.join(paths.offlineAnalyses, ".retention.lock");
  const originalOpenSync = fs.openSync;
  const originalWriteFileSync = fs.writeFileSync;
  let lockDescriptor = null;
  fs.openSync = (file, ...args) => {
    const descriptor = originalOpenSync(file, ...args);
    if (typeof file === "string" && path.basename(file).startsWith(".retention-lock-")) lockDescriptor = descriptor;
    return descriptor;
  };
  fs.writeFileSync = (file, content, ...args) => {
    if (file === lockDescriptor) {
      const bytes = Buffer.from(String(content));
      fs.writeSync(file, bytes.subarray(0, 17));
      throw new Error("injected partial retention-lock write");
    }
    return originalWriteFileSync(file, content, ...args);
  };
  try {
    assert.throws(
      () => offlineAnalysisInternals.withRetentionLock(paths, () => "unreachable"),
      /injected partial retention-lock write/u
    );
  } finally {
    fs.openSync = originalOpenSync;
    fs.writeFileSync = originalWriteFileSync;
  }
  assert.equal(fs.existsSync(lock), false);
  assert.equal(offlineAnalysisInternals.withRetentionLock(paths, () => "recovered"), "recovered");
  assert.equal(fs.existsSync(lock), false);
});

managedTest("dead retention-lock stages are reclaimed while live contenders are preserved", (t) => {
  const { paths } = fixture(t);
  offlineAnalysisInternals.withRetentionLock(paths, () => null);
  const identity = testProcessIdentity();
  const deadStage = path.join(
    paths.offlineAnalysisTransactions,
    `.retention-lock-2147483647-${identity.bootId.replaceAll("-", "")}-1-${"d".repeat(32)}.pending`
  );
  fs.writeFileSync(deadStage, "partial owner record", { mode: 0o600 });
  let status = offlineAnalysisStatus({ paths });
  assert.equal(status.retention.pendingTransactions, 1);
  assert.equal(offlineAnalysisInternals.withRetentionLock(paths, () => "recovered"), "recovered");
  assert.equal(fs.existsSync(deadStage), false);

  const liveStage = path.join(
    paths.offlineAnalysisTransactions,
    `.retention-lock-${process.pid}-${identity.bootId.replaceAll("-", "")}-${identity.startTimeTicks}-${"e".repeat(32)}.pending`
  );
  fs.writeFileSync(liveStage, "live contender", { mode: 0o600 });
  fs.chmodSync(liveStage, 0o644);
  status = offlineAnalysisStatus({ paths });
  assert.equal(status.retention.invalidTransactionRecords, 0);
  assert.equal(status.retention.mutationBlocked, false);
  assert.equal(offlineAnalysisInternals.withRetentionLock(paths, () => "tolerated"), "tolerated");
  assert.equal(fs.existsSync(liveStage), true);
  fs.rmSync(liveStage);

  const malformedStage = path.join(paths.offlineAnalysisTransactions, ".retention-lock-malformed.pending");
  fs.writeFileSync(malformedStage, "ambiguous", { mode: 0o600 });
  status = offlineAnalysisStatus({ paths });
  assert.equal(status.retention.invalidTransactionRecords, 1);
  assert.equal(status.retention.mutationBlocked, true);
  assert.throws(
    () => offlineAnalysisInternals.withRetentionLock(paths, () => "unsafe"),
    /transaction entry is invalid/u
  );
  assert.equal(fs.existsSync(malformedStage), true);
  fs.rmSync(malformedStage);

  const unsafeDeadRecord = path.join(
    paths.offlineAnalysisTransactions,
    `.record-claim-amf_${"f".repeat(32)}-2147483647-${identity.bootId.replaceAll("-", "")}-1-${"a".repeat(32)}.pending`
  );
  fs.writeFileSync(unsafeDeadRecord, "unsafe", { mode: 0o600 });
  fs.chmodSync(unsafeDeadRecord, 0o644);
  status = offlineAnalysisStatus({ paths });
  assert.equal(status.retention.invalidTransactionRecords, 1);
  assert.equal(status.retention.mutationBlocked, true);
  assert.throws(
    () => offlineAnalysisInternals.withRetentionLock(paths, () => "unsafe"),
    /bounded owner-only regular file/u
  );
  assert.equal(fs.existsSync(unsafeDeadRecord), true);
});

managedTest("a partial creation-intent write remains an isolated transaction", (t) => {
  const { root, paths } = fixture(t);
  const artifact = path.join(root, "partial-creation-intent.exe");
  writeMinimalPe(artifact);
  const originalOpenSync = fs.openSync;
  const originalWriteFileSync = fs.writeFileSync;
  let creationDescriptor = null;
  fs.openSync = (file, ...args) => {
    const descriptor = originalOpenSync(file, ...args);
    if (typeof file === "string" && path.basename(file).startsWith(".record-creation-")) creationDescriptor = descriptor;
    return descriptor;
  };
  fs.writeFileSync = (file, content, ...args) => {
    if (file === creationDescriptor) {
      const bytes = Buffer.from(String(content));
      fs.writeSync(file, bytes.subarray(0, 13));
      throw new Error("injected partial creation-intent write");
    }
    return originalWriteFileSync(file, content, ...args);
  };
  try {
    assert.throws(
      () => createOfflineAnalysisManifest("offline-project", { path: artifact, maxMinutes: 1 }, { paths }),
      /injected partial creation-intent write/u
    );
  } finally {
    fs.openSync = originalOpenSync;
    fs.writeFileSync = originalWriteFileSync;
  }
  assert.deepEqual(fs.readdirSync(paths.offlineAnalysisCreations), []);
  assert.deepEqual(fs.readdirSync(paths.offlineAnalysisManifests), []);
  assert.deepEqual(fs.readdirSync(paths.offlineAnalysisInputs), []);
  const created = createOfflineAnalysisManifest("offline-project", { path: artifact, maxMinutes: 1 }, { paths });
  assert.equal(fs.existsSync(manifestPath(paths, created.manifestId)), true);
});

managedTest("manifest parent-fsync ambiguity preserves the exact manifest and its artifact", (t) => {
  const { root, paths } = fixture(t);
  const firstArtifact = path.join(root, "parent-fsync.exe");
  const secondArtifact = path.join(root, "after-parent-fsync.exe");
  writeMinimalPe(firstArtifact);
  writeMinimalPe(secondArtifact);
  const originalFsyncSync = fs.fsyncSync;
  let injected = false;
  fs.fsyncSync = (descriptor) => {
    let openedPath = null;
    try { openedPath = fs.readlinkSync(`/proc/self/fd/${descriptor}`); } catch { /* Descriptor diagnostics are best effort. */ }
    if (!injected && openedPath === paths.offlineAnalysisManifests) {
      injected = true;
      throw new Error("injected manifest parent fsync failure");
    }
    return originalFsyncSync(descriptor);
  };
  try {
    assert.throws(
      () => createOfflineAnalysisManifest("offline-project", { path: firstArtifact, maxMinutes: 1 }, { paths }),
      /injected manifest parent fsync failure/u
    );
  } finally {
    fs.fsyncSync = originalFsyncSync;
  }
  const [manifestName] = fs.readdirSync(paths.offlineAnalysisManifests);
  assert.match(manifestName, /^amf_[a-f0-9]{32}\.json$/u);
  const manifestId = manifestName.slice(0, -5);
  const manifest = readManifest(paths, manifestId);
  assert.equal(fs.existsSync(snapshotPath(paths, manifest.metadata.runId)), true);
  assert.equal(fs.existsSync(path.join(paths.offlineAnalysisSandboxes, manifest.metadata.runId)), true);
  assert.equal(fs.existsSync(creationPath(paths, manifestId)), true);
  assert.equal(fs.existsSync(path.join(paths.offlineAnalysisCreations, `${manifestId}.publication.json`)), true);
  let status = offlineAnalysisStatus({ paths });
  assert.equal(status.retention.creatingManifests, 1);
  assert.equal(status.retention.invalidCreationIntents, 0);
  assert.equal(status.retention.pendingManifests, 1);
  createOfflineAnalysisManifest("offline-project", { path: secondArtifact, maxMinutes: 1 }, { paths });
  assert.equal(fs.existsSync(creationPath(paths, manifestId)), false);
  assert.equal(fs.existsSync(snapshotPath(paths, manifest.metadata.runId)), true);
  status = offlineAnalysisStatus({ paths });
  assert.equal(status.retention.creatingManifests, 0);
  assert.equal(status.retention.pendingManifests, 2);
});

managedTest("a transaction-bound partial manifest is reclaimed without deleting ambiguous records", (t) => {
  const { root, paths } = fixture(t);
  const firstArtifact = path.join(root, "partial-manifest.exe");
  const secondArtifact = path.join(root, "after-partial-manifest.exe");
  writeMinimalPe(firstArtifact);
  writeMinimalPe(secondArtifact);
  const originalRenameSync = fs.renameSync;
  let interrupted = false;
  fs.renameSync = (source, destination) => {
    if (!interrupted && typeof source === "string" && path.basename(source).startsWith(".record-manifest-")) {
      interrupted = true;
      const content = fs.readFileSync(source);
      fs.writeFileSync(destination, content.subarray(0, Math.max(1, Math.floor(content.length / 2))), { mode: 0o600 });
      throw new Error("injected partial manifest publication");
    }
    return originalRenameSync(source, destination);
  };
  try {
    assert.throws(
      () => createOfflineAnalysisManifest("offline-project", { path: firstArtifact, maxMinutes: 1 }, { paths }),
      /injected partial manifest publication/u
    );
  } finally {
    fs.renameSync = originalRenameSync;
  }
  const [intentName] = fs.readdirSync(paths.offlineAnalysisCreations)
    .filter((name) => /^amf_[a-f0-9]{32}\.json$/u);
  const manifestId = intentName.slice(0, -5);
  const intent = JSON.parse(fs.readFileSync(creationPath(paths, manifestId), "utf8"));
  assert.equal(fs.existsSync(snapshotPath(paths, intent.runId)), true);
  assert.throws(() => JSON.parse(fs.readFileSync(manifestPath(paths, manifestId), "utf8")));
  createOfflineAnalysisManifest("offline-project", { path: secondArtifact, maxMinutes: 1 }, { paths });
  assert.equal(fs.existsSync(manifestPath(paths, manifestId)), false);
  assert.equal(fs.existsSync(snapshotPath(paths, intent.runId)), false);
  assert.equal(fs.existsSync(creationPath(paths, manifestId)), false);
});

managedTest("malformed creation controls are visible and block mutation fail closed", (t) => {
  const { root, paths } = fixture(t);
  const artifact = path.join(root, "malformed-creation.exe");
  writeMinimalPe(artifact);
  const id = `amf_${"c".repeat(32)}`;
  fs.writeFileSync(creationPath(paths, id), "{\"apiVersion\":", { mode: 0o600 });
  const status = offlineAnalysisStatus({ paths });
  assert.equal(status.retention.creatingManifests, 1);
  assert.equal(status.retention.invalidCreationIntents, 1);
  assert.equal(status.retention.mutationBlocked, true);
  assert.ok(status.retention.invalidEntries >= 1);
  assert.throws(
    () => createOfflineAnalysisManifest("offline-project", { path: artifact, maxMinutes: 1 }, { paths }),
    /Unexpected end of JSON input|creation intent/u
  );
  assert.equal(fs.existsSync(creationPath(paths, id)), true);
});

managedTest("transaction storage is contained within GATE_HOME", (t) => {
  const { root, paths } = fixture(t);
  const escaped = path.join(root, "escaped-transactions");
  assert.throws(
    () => offlineAnalysisStatus({ paths: { ...paths, offlineAnalysisTransactions: escaped } }),
    /escapes GATE_HOME/u
  );
  assert.equal(fs.existsSync(escaped), false);
});

managedTest("partial claim and purge records block only their bound manifests", async (t) => {
  const { root, paths } = fixture(t);
  const firstArtifact = path.join(root, "partial-claim.exe");
  const secondArtifact = path.join(root, "partial-purge.exe");
  const thirdArtifact = path.join(root, "after-partial-controls.exe");
  writeMinimalPe(firstArtifact);
  writeMinimalPe(secondArtifact);
  writeMinimalPe(thirdArtifact);
  const first = createOfflineAnalysisManifest("offline-project", { path: firstArtifact, maxMinutes: 1 }, { paths });
  const originalRenameSync = fs.renameSync;
  let partialClaimWritten = false;
  fs.renameSync = (source, destination) => {
    if (!partialClaimWritten && path.dirname(destination) === paths.offlineAnalysisClaims) {
      partialClaimWritten = true;
      const content = fs.readFileSync(source);
      fs.writeFileSync(destination, content.subarray(0, Math.max(1, Math.floor(content.length / 2))), { mode: 0o600 });
      throw new Error("injected partial claim publication");
    }
    return originalRenameSync(source, destination);
  };
  try {
    await assert.rejects(
      executeOfflineAnalysisManifest("offline-project", {
        manifestId: first.manifestId,
        confirm: first.confirmationRequired
      }, { paths }),
      /injected partial claim publication/u
    );
  } finally {
    fs.renameSync = originalRenameSync;
  }
  let status = offlineAnalysisStatus({ paths });
  assert.equal(status.retention.invalidClaimRecords, 1);
  assert.equal(status.retention.blockedManifests, 1);
  assert.equal(status.retention.pendingManifests, 0);
  assert.equal(status.retention.unknownManifests, 1);

  const second = createOfflineAnalysisManifest("offline-project", { path: secondArtifact, maxMinutes: 1 }, { paths });
  let partialPurgeWritten = false;
  fs.renameSync = (source, destination) => {
    if (!partialPurgeWritten && path.dirname(destination) === paths.offlineAnalysisPurges) {
      partialPurgeWritten = true;
      const content = fs.readFileSync(source);
      fs.writeFileSync(destination, content.subarray(0, Math.max(1, Math.floor(content.length / 2))), { mode: 0o600 });
      throw new Error("injected partial purge publication");
    }
    return originalRenameSync(source, destination);
  };
  try {
    assert.throws(
      () => purgeOfflineAnalysisArtifact("offline-project", {
        manifestId: second.manifestId,
        confirm: second.purgeConfirmationRequired
      }, { paths }),
      /injected partial purge publication/u
    );
  } finally {
    fs.renameSync = originalRenameSync;
  }
  assert.equal(fs.existsSync(snapshotPath(paths, second.runId)), true);
  status = offlineAnalysisStatus({ paths });
  assert.equal(status.retention.invalidClaimRecords, 1);
  assert.equal(status.retention.invalidPurgeRecords, 1);
  assert.equal(status.retention.blockedManifests, 2);
  assert.equal(status.retention.pendingManifests, 0);
  assert.throws(
    () => purgeOfflineAnalysisArtifact("offline-project", {
      manifestId: second.manifestId,
      confirm: second.purgeConfirmationRequired
    }, { paths }),
    /JSON|purge|Unterminated/u
  );
  const third = createOfflineAnalysisManifest("offline-project", { path: thirdArtifact, maxMinutes: 1 }, { paths });
  assert.equal(fs.existsSync(manifestPath(paths, third.manifestId)), true);
});

managedTest("status marks cross-bound claims and runs blocked instead of pending or terminal", (t) => {
  const { root, paths } = fixture(t);
  const firstArtifact = path.join(root, "cross-claim.exe");
  const secondArtifact = path.join(root, "cross-run.exe");
  writeMinimalPe(firstArtifact);
  writeMinimalPe(secondArtifact);
  const first = createOfflineAnalysisManifest("offline-project", { path: firstArtifact, maxMinutes: 1 }, { paths });
  const firstManifest = readManifest(paths, first.manifestId);
  const identity = testProcessIdentity();
  fs.writeFileSync(claimPath(paths, first.manifestId), `${JSON.stringify({
    apiVersion: "gate.offline-analysis-claim/v1",
    manifestId: first.manifestId,
    runId: `arun_${"1".repeat(32)}`,
    manifestSha256: first.manifestSha256,
    projectId: "offline-project",
    claimedAt: new Date().toISOString(),
    supervisorPid: process.pid,
    supervisorIdentity: identity
  })}\n`, { mode: 0o600 });

  const second = createOfflineAnalysisManifest("offline-project", { path: secondArtifact, maxMinutes: 1 }, { paths });
  const secondManifest = readManifest(paths, second.manifestId);
  fs.writeFileSync(claimPath(paths, second.manifestId), `${JSON.stringify({
    apiVersion: "gate.offline-analysis-claim/v1",
    manifestId: second.manifestId,
    runId: second.runId,
    manifestSha256: second.manifestSha256,
    projectId: "offline-project",
    claimedAt: new Date().toISOString(),
    supervisorPid: process.pid,
    supervisorIdentity: identity
  })}\n`, { mode: 0o600 });
  fs.writeFileSync(runPath(paths, second.runId), `${JSON.stringify({
    $schema: "../../schemas/offline-analysis-run.schema.json",
    apiVersion: "gate.offline-analysis-run/v1",
    kind: "OfflineAnalysisRun",
    runId: second.runId,
    manifestId: first.manifestId,
    manifestSha256: second.manifestSha256,
    projectId: "offline-project",
    status: "blocked",
    createdAt: new Date().toISOString(),
    startedAt: null,
    finishedAt: new Date().toISOString(),
    terminationReason: "preflight-failed",
    result: { exitCode: null, signal: null, durationMs: 0 },
    evidence: {
      stdout: { ref: secondManifest.runtime.evidence.stdoutRef, available: false, sha256: null, bytes: 0 },
      stderr: { ref: secondManifest.runtime.evidence.stderrRef, available: false, sha256: null, bytes: 0 },
      resultRef: secondManifest.runtime.evidence.resultRef,
      resultAvailable: false,
      sandboxRef: secondManifest.runtime.sandboxRef
    },
    isolationVerified: false
  }, null, 2)}\n`, { mode: 0o600 });

  const status = offlineAnalysisStatus({ paths });
  assert.equal(status.retention.pendingManifests, 0);
  assert.equal(status.retention.terminalManifests, 0);
  assert.equal(status.retention.unknownManifests, 2);
  assert.equal(status.retention.blockedManifests, 2);
  assert.equal(status.retention.invalidClaimRecords, 1);
  assert.equal(status.retention.invalidRunRecords, 1);
  assert.ok(status.retention.invalidEntries >= 2);
  assert.equal(status.recent.find((run) => run.runId === second.runId)?.status, "unknown");
  assert.equal(status.recent.find((run) => run.runId === second.runId)?.terminationReason, "manifest-binding-invalid");
  assert.equal(firstManifest.metadata.runId, first.runId);
});

managedTest("status state matrix never presents rejected manifest, claim, and run combinations as ready", (t) => {
  const { root, paths } = fixture(t);
  const artifact = path.join(root, "status-state-matrix.exe");
  writeMinimalPe(artifact);
  const created = createOfflineAnalysisManifest("offline-project", { path: artifact, maxMinutes: 1 }, { paths });
  const manifest = readManifest(paths, created.manifestId);
  const identity = testProcessIdentity();
  const validClaim = {
    apiVersion: "gate.offline-analysis-claim/v1",
    manifestId: created.manifestId,
    runId: created.runId,
    manifestSha256: created.manifestSha256,
    projectId: "offline-project",
    claimedAt: new Date().toISOString(),
    supervisorPid: process.pid,
    supervisorIdentity: identity
  };
  const validRun = {
    $schema: "../../schemas/offline-analysis-run.schema.json",
    apiVersion: "gate.offline-analysis-run/v1",
    kind: "OfflineAnalysisRun",
    runId: created.runId,
    manifestId: created.manifestId,
    manifestSha256: created.manifestSha256,
    projectId: "offline-project",
    status: "blocked",
    createdAt: new Date().toISOString(),
    startedAt: null,
    finishedAt: new Date().toISOString(),
    terminationReason: "preflight-failed",
    result: { exitCode: null, signal: null, durationMs: 0 },
    evidence: {
      stdout: { ref: manifest.runtime.evidence.stdoutRef, available: false, sha256: null, bytes: 0 },
      stderr: { ref: manifest.runtime.evidence.stderrRef, available: false, sha256: null, bytes: 0 },
      resultRef: manifest.runtime.evidence.resultRef,
      resultAvailable: false,
      sandboxRef: manifest.runtime.sandboxRef
    },
    isolationVerified: false
  };
  const files = {
    manifest: manifestPath(paths, created.manifestId),
    claim: claimPath(paths, created.manifestId),
    run: runPath(paths, created.runId)
  };
  const retainedArtifactFile = snapshotPath(paths, created.runId);
  const retainedArtifact = fs.readFileSync(retainedArtifactFile);
  const states = {
    validManifest: `${JSON.stringify(manifest, null, 2)}\n`,
    validClaim: `${JSON.stringify(validClaim)}\n`,
    purgeClaim: `${JSON.stringify({
      apiVersion: "gate.offline-analysis-purge-claim/v1",
      manifestId: created.manifestId,
      runId: created.runId,
      manifestSha256: created.manifestSha256,
      projectId: "offline-project",
      claimedAt: new Date().toISOString()
    })}\n`,
    crossBoundClaim: `${JSON.stringify({ ...validClaim, runId: `arun_${"1".repeat(32)}` })}\n`,
    validRun: `${JSON.stringify(validRun, null, 2)}\n`,
    crossBoundRun: `${JSON.stringify({ ...validRun, manifestId: `amf_${"2".repeat(32)}` }, null, 2)}\n`,
    corrupt: "{}\n"
  };
  const cases = [
    {
      name: "unclaimed manifest",
      manifest: "validManifest",
      claim: null,
      run: null,
      expected: { pending: 1, terminal: 0, unknown: 0, blocked: 0, invalidClaims: 0, invalidRuns: 0, invalidEntries: 0 }
    },
    {
      name: "durable claim before run publication",
      manifest: "validManifest",
      claim: "validClaim",
      run: null,
      expected: { pending: 0, terminal: 0, unknown: 1, blocked: 0, invalidClaims: 0, invalidRuns: 0, invalidEntries: 0 }
    },
    {
      name: "run without durable claim",
      manifest: "validManifest",
      claim: null,
      run: "validRun",
      expected: { pending: 0, terminal: 0, unknown: 1, blocked: 1, invalidClaims: 0, invalidRuns: 1, invalidEntries: 1 },
      recentReason: "claim-binding-invalid"
    },
    {
      name: "run without durable claim or retained artifact",
      manifest: "validManifest",
      claim: null,
      run: "validRun",
      artifact: false,
      expected: {
        pending: 0,
        terminal: 0,
        unknown: 1,
        blocked: 1,
        invalidClaims: 0,
        invalidRuns: 1,
        invalidEntries: 2,
        missingArtifacts: 1
      },
      recentReason: "claim-binding-invalid"
    },
    {
      name: "run with corrupt claim",
      manifest: "validManifest",
      claim: "corrupt",
      run: "validRun",
      expected: { pending: 0, terminal: 0, unknown: 1, blocked: 1, invalidClaims: 1, invalidRuns: 0, invalidEntries: 1 },
      recentReason: "claim-binding-invalid"
    },
    {
      name: "run with cross-bound claim",
      manifest: "validManifest",
      claim: "crossBoundClaim",
      run: "validRun",
      expected: { pending: 0, terminal: 0, unknown: 1, blocked: 1, invalidClaims: 1, invalidRuns: 0, invalidEntries: 1 },
      recentReason: "claim-binding-invalid"
    },
    {
      name: "purge claim without run",
      manifest: "validManifest",
      claim: "purgeClaim",
      run: null,
      expected: {
        pending: 0,
        terminal: 0,
        unknown: 0,
        blocked: 0,
        invalidClaims: 0,
        invalidRuns: 0,
        invalidEntries: 0,
        purgePending: 1
      }
    },
    {
      name: "run with purge claim instead of execution claim",
      manifest: "validManifest",
      claim: "purgeClaim",
      run: "validRun",
      expected: { pending: 0, terminal: 0, unknown: 1, blocked: 1, invalidClaims: 0, invalidRuns: 1, invalidEntries: 1 },
      recentReason: "claim-binding-invalid"
    },
    {
      name: "malformed bound run",
      manifest: "validManifest",
      claim: "validClaim",
      run: "corrupt",
      expected: { pending: 0, terminal: 0, unknown: 1, blocked: 1, invalidClaims: 0, invalidRuns: 1, invalidEntries: 1 }
    },
    {
      name: "cross-bound run",
      manifest: "validManifest",
      claim: "validClaim",
      run: "crossBoundRun",
      expected: { pending: 0, terminal: 0, unknown: 1, blocked: 1, invalidClaims: 0, invalidRuns: 1, invalidEntries: 1 },
      recentReason: "manifest-binding-invalid"
    },
    {
      name: "complete terminal record set",
      manifest: "validManifest",
      claim: "validClaim",
      run: "validRun",
      expected: { pending: 0, terminal: 1, unknown: 0, blocked: 0, invalidClaims: 0, invalidRuns: 0, invalidEntries: 0 }
    },
    {
      name: "run whose manifest is missing",
      manifest: null,
      claim: "validClaim",
      run: "validRun",
      expected: { pending: 0, terminal: 0, unknown: 0, blocked: 0, invalidClaims: 0, invalidRuns: 1, invalidEntries: 1 },
      recentReason: "manifest-binding-invalid"
    },
    {
      name: "run whose manifest is corrupt",
      manifest: "corrupt",
      claim: "validClaim",
      run: "validRun",
      expected: { pending: 0, terminal: 0, unknown: 1, blocked: 1, invalidClaims: 0, invalidRuns: 1, invalidEntries: 2 },
      recentReason: "manifest-binding-invalid"
    }
  ];

  for (const state of cases) {
    for (const file of Object.values(files)) fs.rmSync(file, { force: true });
    fs.writeFileSync(retainedArtifactFile, retainedArtifact, { mode: 0o600 });
    if (state.artifact === false) fs.rmSync(retainedArtifactFile);
    for (const key of ["manifest", "claim", "run"]) {
      if (state[key]) fs.writeFileSync(files[key], states[state[key]], { mode: 0o600 });
    }
    const status = offlineAnalysisStatus({ paths });
    const retention = status.retention;
    assert.equal(retention.pendingManifests, state.expected.pending, `${state.name}: pending`);
    assert.equal(retention.expiredManifests, 0, `${state.name}: expired`);
    assert.equal(retention.activeManifests, 0, `${state.name}: active`);
    assert.equal(retention.terminalManifests, state.expected.terminal, `${state.name}: terminal`);
    assert.equal(retention.unknownManifests, state.expected.unknown, `${state.name}: unknown`);
    assert.equal(retention.blockedManifests, state.expected.blocked, `${state.name}: blocked`);
    assert.equal(retention.invalidClaimRecords, state.expected.invalidClaims, `${state.name}: invalid claims`);
    assert.equal(retention.invalidRunRecords, state.expected.invalidRuns, `${state.name}: invalid runs`);
    assert.equal(retention.invalidEntries, state.expected.invalidEntries, `${state.name}: invalid entries`);
    assert.equal(retention.missingArtifacts, state.expected.missingArtifacts || 0, `${state.name}: missing artifacts`);
    assert.equal(retention.purgePendingManifests, state.expected.purgePending || 0, `${state.name}: purge pending`);
    assert.equal(retention.purgedManifests, 0, `${state.name}: purged`);
    if (state.recentReason) {
      assert.equal(status.recent.find(({ runId }) => runId === created.runId)?.status, "unknown", `${state.name}: recent status`);
      assert.equal(
        status.recent.find(({ runId }) => runId === created.runId)?.terminationReason,
        state.recentReason,
        `${state.name}: recent reason`
      );
    }
    if (state.name === "run without durable claim") {
      assert.throws(
        () => purgeOfflineAnalysisArtifact("offline-project", {
          manifestId: created.manifestId,
          confirm: created.purgeConfirmationRequired
        }, { paths }),
        /run exists without its durable execution claim/u
      );
    }
  }
});

managedTest("status reports an indeterminate snapshot when state mutates through every retry", (t) => {
  const { paths } = fixture(t);
  const marker = path.join(paths.offlineAnalysisInputs, "status-generation-marker");
  const originalReaddirSync = fs.readdirSync;
  fs.readdirSync = (directory, ...args) => {
    if (directory === paths.offlineAnalysisClaims) {
      fs.writeFileSync(marker, "x", { mode: 0o600 });
      fs.rmSync(marker);
    }
    return originalReaddirSync(directory, ...args);
  };
  let status;
  try {
    status = offlineAnalysisStatus({ paths });
  } finally {
    fs.readdirSync = originalReaddirSync;
  }
  assert.equal(status.retention.snapshotState, "indeterminate");
  assert.equal(status.retention.mutationBlocked, true);
  assert.equal(status.retention.invalidEntries, 0);
});

managedTest("manifest preserves an exact comma-and-space path and exposes no arbitrary argv", (t) => {
  const { root, paths, runtime } = fixture(t);
  const artifact = path.join(root, "fixture, with  two spaces.exe");
  const bytes = writeMinimalPe(artifact);
  assert.throws(() => createOfflineAnalysisManifest("offline-project", {
    path: artifact,
    argv: ["--user-controlled", "contact.example"]
  }, { paths }), /unsupported fields: argv/u);
  const created = createOfflineAnalysisManifest("offline-project", {
    path: artifact,
    maxMinutes: 2
  }, { paths });
  const manifest = readManifest(paths, created.manifestId);

  assert.equal(manifest.operation.targetSelector.value, artifact);
  assert.equal(manifest.operation.artifact.bytes, bytes.length);
  assert.equal(manifest.operation.artifact.sha256, crypto.createHash("sha256").update(bytes).digest("hex"));
  assert.equal(manifest.networkPolicy, "none");
  assert.deepEqual(manifest.limits, {
    maxMinutes: 2,
    maxRequests: 0,
    maxRatePerSecond: 0,
    maxParallel: 1,
    maxTokens: 0
  });
  assert.deepEqual(manifest.operation.adapter.arguments, {
    maxFileBytes: 512 * 1024 * 1024,
    maxEntries: 16_384,
    format: "json",
    fullOutput: true
  });

  const argv = offlineAnalysisInternals.bwrapArguments(manifest, runtime);
  const commandBoundary = argv.indexOf("--");
  assert.ok(commandBoundary > 0);
  assert.deepEqual(argv.slice(commandBoundary + 1), [
    `/opt/gate/node/${path.basename(realNode)}`,
    "/opt/gate/adapter.mjs",
    "/opt/gate/rea/node_modules/rea-agents/scripts/rea.mjs",
    "/input/artifact",
    String(512 * 1024 * 1024),
    String(16_384)
  ]);
  assert.equal(argv.includes(artifact), false);
  assert.equal(argv.includes("--user-controlled"), false);
  assert.equal(argv.includes("contact.example"), false);
  assert.equal(argv.some((argument) => argument.includes("touch should-never-run")), false);
});

managedTest("manifest rejects relative paths, symlinks, FIFOs, and directories", {
  skip: process.platform === "win32" && "POSIX FIFO and symlink semantics are required"
}, (t) => {
  const { root, paths } = fixture(t);
  const regular = path.join(root, "regular.exe");
  writeMinimalPe(regular);
  const linked = path.join(root, "linked.exe");
  const directory = path.join(root, "directory.exe");
  const fifo = path.join(root, "artifact.fifo");
  fs.symlinkSync(regular, linked);
  fs.mkdirSync(directory);
  const mkfifo = spawnSync("mkfifo", [fifo], { encoding: "utf8" });
  assert.equal(mkfifo.status, 0, mkfifo.stderr);

  assert.throws(
    () => createOfflineAnalysisManifest("offline-project", { path: "relative.exe" }, { paths }),
    /analysis path must be absolute/u
  );
  for (const rejected of [linked, fifo, directory]) {
    assert.throws(
      () => createOfflineAnalysisManifest("offline-project", { path: rejected }, { paths }),
      /regular non-symlink file/u
    );
  }
  assert.deepEqual(fs.readdirSync(paths.offlineAnalysisInputs), []);
  assert.deepEqual(fs.readdirSync(paths.offlineAnalysisManifests), []);
});

managedTest("execution rejects project-contract mutation before consuming the manifest", async (t) => {
  const { root, paths } = fixture(t);
  const artifact = path.join(root, "project-bound.exe");
  writeMinimalPe(artifact);
  const created = createOfflineAnalysisManifest(
    "offline-project",
    { path: artifact, maxMinutes: 1 },
    { paths }
  );
  const storedProject = path.join(paths.projects, "offline-project.json");
  const changed = JSON.parse(fs.readFileSync(storedProject, "utf8"));
  changed.metadata.displayName = "Mutated After Manifest";
  fs.writeFileSync(storedProject, `${JSON.stringify(changed, null, 2)}\n`, { mode: 0o600 });

  await assert.rejects(
    executeOfflineAnalysisManifest("offline-project", {
      manifestId: created.manifestId,
      confirm: created.confirmationRequired
    }, { paths }),
    /registered project contract changed/u
  );
  assert.equal(fs.existsSync(claimPath(paths, created.manifestId)), false);
});

managedTest("execution rejects a manifest whose bytes changed without its digest", async (t) => {
  const { root, paths } = fixture(t);
  const artifact = path.join(root, "manifest-bound.exe");
  writeMinimalPe(artifact);
  const created = createOfflineAnalysisManifest(
    "offline-project",
    { path: artifact, maxMinutes: 1 },
    { paths }
  );
  const file = manifestPath(paths, created.manifestId);
  const manifest = JSON.parse(fs.readFileSync(file, "utf8"));
  manifest.limits.maxMinutes = 2;
  fs.writeFileSync(file, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });

  await assert.rejects(
    executeOfflineAnalysisManifest("offline-project", {
      manifestId: created.manifestId,
      confirm: created.confirmationRequired
    }, { paths }),
    /manifest digest changed/u
  );
  assert.equal(fs.existsSync(claimPath(paths, created.manifestId)), false);
});

managedTest("execution requires the byte-exact confirmation before creating a claim", async (t) => {
  const { root, paths } = fixture(t);
  const artifact = path.join(root, "confirmation.exe");
  writeMinimalPe(artifact);
  const created = createOfflineAnalysisManifest(
    "offline-project",
    { path: artifact, maxMinutes: 1 },
    { paths }
  );
  for (const confirm of [
    created.confirmationRequired.toLowerCase(),
    `${created.confirmationRequired} `,
    created.confirmationRequired.replace(/ [a-f0-9]{64} /u, ` ${"0".repeat(64)} `)
  ]) {
    await assert.rejects(
      executeOfflineAnalysisManifest("offline-project", { manifestId: created.manifestId, confirm }, { paths }),
      /confirmation must be exactly/u
    );
    assert.equal(fs.existsSync(claimPath(paths, created.manifestId)), false);
  }
});

managedTest("one-shot claim blocks concurrent and later replay", async (t) => {
  const { root, paths } = fixture(t);
  const artifact = path.join(root, "one-shot.exe");
  writeMinimalPe(artifact);
  const created = createOfflineAnalysisManifest(
    "offline-project",
    { path: artifact, maxMinutes: 1 },
    { paths }
  );
  const first = executeOfflineAnalysisManifest("offline-project", {
    manifestId: created.manifestId,
    confirm: created.confirmationRequired
  }, { paths });

  await assert.rejects(
    executeOfflineAnalysisManifest("offline-project", {
      manifestId: created.manifestId,
      confirm: created.confirmationRequired
    }, { paths }),
    /already consumed/u
  );
  const result = await first;
  assert.equal(result.ok, true);
  assert.equal(result.status, "succeeded");
  assert.equal(result.terminationReason, "completed");
  await assert.rejects(
    executeOfflineAnalysisManifest("offline-project", {
      manifestId: created.manifestId,
      confirm: created.confirmationRequired
    }, { paths }),
    /already consumed/u
  );

  const run = JSON.parse(fs.readFileSync(runPath(paths, created.runId), "utf8"));
  assert.equal(run.status, "succeeded");
  assert.equal(run.isolationVerified, true);
  assert.equal(mode(claimPath(paths, created.manifestId)), 0o600);
  assert.equal(mode(runPath(paths, created.runId)), 0o600);
  for (const stream of [result.evidence.stdout, result.evidence.stderr]) {
    assert.ok(stream.bytes <= MAX_EVIDENCE_BYTES);
    assert.equal(mode(evidencePath(paths, stream.ref)), 0o600);
  }
  assert.equal(mode(evidencePath(paths, result.evidence.resultRef)), 0o600);
});

managedTest("runtime file identity changes block launch and produce a terminal private run", async (t) => {
  const { root, paths } = fixture(t);
  const artifact = path.join(root, "runtime-bound.exe");
  writeMinimalPe(artifact);
  const created = createOfflineAnalysisManifest(
    "offline-project",
    { path: artifact, maxMinutes: 1 },
    { paths }
  );
  const manifest = readManifest(paths, created.manifestId);
  manifest.runtime.adapter.sha256 = "0".repeat(64);
  manifest.manifestSha256 = offlineAnalysisInternals.manifestDigest(manifest);
  fs.writeFileSync(manifestPath(paths, created.manifestId), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
  const confirmation = `ANALYZE ${created.manifestId} ${manifest.manifestSha256} OFFLINE`;

  await assert.rejects(
    executeOfflineAnalysisManifest("offline-project", {
      manifestId: created.manifestId,
      confirm: confirmation
    }, { paths }),
    /adapter (?:sha256|size|mtimeNs|ctimeNs) changed after manifest creation/u
  );
  const run = JSON.parse(fs.readFileSync(runPath(paths, created.runId), "utf8"));
  assert.equal(run.status, "blocked");
  assert.equal(run.terminationReason, "preflight-failed");
  assert.equal(run.isolationVerified, false);
  assert.equal(mode(runPath(paths, created.runId)), 0o600);
});

managedTest("artifact snapshot mutation is detected before launch", async (t) => {
  const { root, paths } = fixture(t);
  const artifact = path.join(root, "snapshot-bound.exe");
  writeMinimalPe(artifact);
  const created = createOfflineAnalysisManifest(
    "offline-project",
    { path: artifact, maxMinutes: 1 },
    { paths }
  );
  const manifest = readManifest(paths, created.manifestId);
  const snapshot = path.join(paths.offlineAnalysisInputs, `${created.runId}.bin`);
  assert.equal(manifest.operation.artifact.snapshotRef, `private://offline-analysis/inputs/${created.runId}.bin`);
  fs.appendFileSync(snapshot, Buffer.from([0xff]));

  await assert.rejects(
    executeOfflineAnalysisManifest("offline-project", {
      manifestId: created.manifestId,
      confirm: created.confirmationRequired
    }, { paths }),
    /artifact snapshot changed after manifest creation/u
  );
  assert.equal(JSON.parse(fs.readFileSync(runPath(paths, created.runId), "utf8")).status, "blocked");
});

managedTest("creation intents recover pre-publication snapshots and preserve published manifests", (t) => {
  const { root, paths } = fixture(t);
  const firstArtifact = path.join(root, "published.exe");
  const secondArtifact = path.join(root, "after-recovery.exe");
  writeMinimalPe(firstArtifact);
  writeMinimalPe(secondArtifact);
  const published = createOfflineAnalysisManifest("offline-project", { path: firstArtifact, maxMinutes: 1 }, { paths });
  fs.writeFileSync(creationPath(paths, published.manifestId), `${JSON.stringify({
    apiVersion: "gate.offline-analysis-creation/v1",
    manifestId: published.manifestId,
    runId: published.runId,
    projectId: "offline-project",
    createdAt: new Date().toISOString()
  })}\n`, { mode: 0o600 });

  const orphanManifestId = `amf_${"a".repeat(32)}`;
  const orphanRunId = `arun_${"b".repeat(32)}`;
  fs.writeFileSync(creationPath(paths, orphanManifestId), `${JSON.stringify({
    apiVersion: "gate.offline-analysis-creation/v1",
    manifestId: orphanManifestId,
    runId: orphanRunId,
    projectId: "offline-project",
    createdAt: new Date().toISOString()
  })}\n`, { mode: 0o600 });
  fs.writeFileSync(snapshotPath(paths, orphanRunId), Buffer.alloc(512, 0x41), { mode: 0o600 });
  const orphanSandbox = path.join(paths.offlineAnalysisSandboxes, orphanRunId);
  fs.mkdirSync(orphanSandbox, { mode: 0o700 });

  const afterRecovery = createOfflineAnalysisManifest("offline-project", { path: secondArtifact, maxMinutes: 1 }, { paths });
  assert.equal(fs.existsSync(creationPath(paths, published.manifestId)), false);
  assert.equal(fs.existsSync(creationPath(paths, orphanManifestId)), false);
  assert.equal(fs.existsSync(snapshotPath(paths, published.runId)), true);
  assert.equal(fs.existsSync(snapshotPath(paths, afterRecovery.runId)), true);
  assert.equal(fs.existsSync(snapshotPath(paths, orphanRunId)), false);
  assert.equal(fs.existsSync(orphanSandbox), false);
  const status = offlineAnalysisStatus({ paths });
  assert.equal(status.retention.retainedArtifacts, 2);
  assert.equal(status.retention.pendingManifests, 2);
  assert.equal(status.retention.orphanedArtifacts, 0);
  assert.equal(status.retention.invalidEntries, 0);
});

managedTest("retention status accounts for pending artifacts and enforces the fixed aggregate quota", (t) => {
  const { root, paths } = fixture(t);
  const artifact = path.join(root, "pending.exe");
  const bytes = writeMinimalPe(artifact);
  const created = createOfflineAnalysisManifest("offline-project", { path: artifact, maxMinutes: 1 }, { paths });
  let status = offlineAnalysisStatus({ paths });
  assert.equal(status.retention.quotaBytes, 2 * 1024 * 1024 * 1024);
  assert.equal(status.retention.quotaArtifacts, 64);
  assert.equal(status.retention.retainedBytes, bytes.length);
  assert.equal(status.retention.availableBytes, status.retention.quotaBytes - bytes.length);
  assert.equal(status.retention.retainedArtifacts, 1);
  assert.equal(status.retention.availableArtifacts, 63);
  assert.equal(status.retention.pendingManifests, 1);
  assert.equal(status.retention.expiredManifests, 0);
  assert.equal(status.retention.invalidEntries, 0);
  assert.equal(fs.existsSync(snapshotPath(paths, created.runId)), true);

  const malformed = path.join(paths.offlineAnalysisInputs, "malformed-name.bin");
  fs.writeFileSync(malformed, Buffer.from([0xff]), { mode: 0o600 });
  status = offlineAnalysisStatus({ paths });
  assert.equal(status.retention.invalidEntries, 1);
  assert.equal(status.retention.retainedBytes, bytes.length + 1);
  assert.throws(
    () => createOfflineAnalysisManifest("offline-project", { path: artifact, maxMinutes: 1 }, { paths }),
    /storage contains invalid entries/u
  );
  fs.rmSync(malformed);

  fs.rmSync(snapshotPath(paths, created.runId));
  for (let index = 0; index < 4; index += 1) {
    const runId = `arun_${String(index).padStart(32, "0")}`;
    const retained = snapshotPath(paths, runId);
    fs.writeFileSync(retained, Buffer.from([0]), { mode: 0o600 });
    fs.truncateSync(retained, 512 * 1024 * 1024);
  }
  assert.throws(
    () => createOfflineAnalysisManifest("offline-project", { path: artifact, maxMinutes: 1 }, { paths }),
    /retention quota exceeded/u
  );
  status = offlineAnalysisStatus({ paths });
  assert.equal(status.retention.retainedBytes, status.retention.quotaBytes);
  assert.equal(status.retention.availableBytes, 0);
  assert.equal(status.retention.overQuota, false);
  assert.equal(status.retention.orphanedArtifacts, 4);

  for (const name of fs.readdirSync(paths.offlineAnalysisInputs)) fs.rmSync(path.join(paths.offlineAnalysisInputs, name));
  for (let index = 0; index < 64; index += 1) {
    const runId = `arun_${index.toString(16).padStart(32, "0")}`;
    fs.writeFileSync(snapshotPath(paths, runId), Buffer.from([index]), { mode: 0o600 });
  }
  assert.throws(
    () => createOfflineAnalysisManifest("offline-project", { path: artifact, maxMinutes: 1 }, { paths }),
    /retention count quota exceeded/u
  );
  status = offlineAnalysisStatus({ paths });
  assert.equal(status.retention.retainedArtifacts, status.retention.quotaArtifacts);
  assert.equal(status.retention.availableArtifacts, 0);
  assert.equal(status.retention.overQuota, false);
  fs.writeFileSync(snapshotPath(paths, `arun_${"f".repeat(32)}`), Buffer.from([0xff]), { mode: 0o600 });
  status = offlineAnalysisStatus({ paths });
  assert.equal(status.retention.retainedArtifacts, 65);
  assert.equal(status.retention.availableArtifacts, 0);
  assert.equal(status.retention.overQuota, true);
});

managedTest("digest-bound purge retires an abandoned artifact and is idempotent", async (t) => {
  const { root, paths } = fixture(t);
  const artifact = path.join(root, "abandoned.exe");
  const bytes = writeMinimalPe(artifact);
  const created = createOfflineAnalysisManifest("offline-project", { path: artifact, maxMinutes: 1 }, { paths });
  const snapshot = snapshotPath(paths, created.runId);

  assert.throws(
    () => purgeOfflineAnalysisArtifact("offline-project", {
      manifestId: created.manifestId,
      confirm: `${created.purgeConfirmationRequired} `
    }, { paths }),
    /confirmation must be exactly/u
  );
  assert.equal(fs.existsSync(snapshot), true);
  assert.equal(fs.existsSync(claimPath(paths, created.manifestId)), false);

  const purged = purgeOfflineAnalysisArtifact("offline-project", {
    manifestId: created.manifestId,
    confirm: created.purgeConfirmationRequired
  }, { paths });
  assert.equal(purged.transition, "abandoned");
  assert.equal(purged.status, "purged");
  assert.equal(purged.bytesFreed, bytes.length);
  assert.equal(purged.alreadyPurged, false);
  assert.equal(fs.existsSync(snapshot), false);
  assert.equal(fs.existsSync(manifestPath(paths, created.manifestId)), true);
  assert.equal(fs.existsSync(claimPath(paths, created.manifestId)), true);
  assert.equal(fs.existsSync(purgePath(paths, created.manifestId)), true);
  assert.equal(mode(purgePath(paths, created.manifestId)), 0o600);
  assert.equal(mode(paths.offlineAnalysisPurges), 0o700);

  const interruptedReceipt = JSON.parse(fs.readFileSync(purgePath(paths, created.manifestId), "utf8"));
  interruptedReceipt.status = "claimed";
  interruptedReceipt.completedAt = null;
  interruptedReceipt.bytesFreed = 0;
  fs.writeFileSync(purgePath(paths, created.manifestId), `${JSON.stringify(interruptedReceipt, null, 2)}\n`, { mode: 0o600 });
  const interruptedStatus = offlineAnalysisStatus({ paths });
  assert.equal(interruptedStatus.retention.purgePendingManifests, 1);
  assert.equal(interruptedStatus.retention.missingArtifacts, 0);
  assert.equal(interruptedStatus.retention.invalidEntries, 0);
  const recovered = purgeOfflineAnalysisArtifact("offline-project", {
    manifestId: created.manifestId,
    confirm: created.purgeConfirmationRequired
  }, { paths });
  assert.equal(recovered.alreadyPurged, false);
  assert.equal(recovered.status, "purged");

  const repeated = purgeOfflineAnalysisArtifact("offline-project", {
    manifestId: created.manifestId,
    confirm: created.purgeConfirmationRequired
  }, { paths });
  assert.equal(repeated.alreadyPurged, true);
  assert.equal(repeated.completedAt, recovered.completedAt);
  const status = offlineAnalysisStatus({ paths });
  assert.equal(status.retention.retainedBytes, 0);
  assert.equal(status.retention.pendingManifests, 0);
  assert.equal(status.retention.purgedManifests, 1);
  await assert.rejects(
    executeOfflineAnalysisManifest("offline-project", {
      manifestId: created.manifestId,
      confirm: created.confirmationRequired
    }, { paths }),
    /already consumed/u
  );
});

managedTest("purge records an expired manifest transition", (t) => {
  const { root, paths } = fixture(t);
  const artifact = path.join(root, "expired.exe");
  writeMinimalPe(artifact);
  const created = createOfflineAnalysisManifest("offline-project", { path: artifact, maxMinutes: 1 }, { paths });
  const manifest = readManifest(paths, created.manifestId);
  manifest.metadata.createdAt = new Date(Date.now() - 20 * 60_000).toISOString();
  manifest.metadata.expiresAt = new Date(Date.now() - 5 * 60_000).toISOString();
  manifest.manifestSha256 = offlineAnalysisInternals.manifestDigest(manifest);
  fs.writeFileSync(manifestPath(paths, created.manifestId), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });

  const before = offlineAnalysisStatus({ paths });
  assert.equal(before.retention.pendingManifests, 0);
  assert.equal(before.retention.expiredManifests, 1);
  const purged = purgeOfflineAnalysisArtifact("offline-project", {
    manifestId: created.manifestId,
    confirm: offlineAnalysisInternals.exactPurgeConfirmation(manifest)
  }, { paths });
  assert.equal(purged.transition, "expired");
  assert.equal(fs.existsSync(snapshotPath(paths, created.runId)), false);
  assert.equal(offlineAnalysisStatus({ paths }).retention.purgedManifests, 1);
});

managedTest("purge removes only the snapshot after a completed run", { timeout: 60_000 }, async (t) => {
  const { root, paths } = fixture(t);
  const artifact = path.join(root, "completed.exe");
  writeMinimalPe(artifact);
  const created = createOfflineAnalysisManifest("offline-project", { path: artifact, maxMinutes: 1 }, { paths });
  const result = await executeOfflineAnalysisManifest("offline-project", {
    manifestId: created.manifestId,
    confirm: created.confirmationRequired
  }, { paths });
  assert.equal(result.status, "succeeded");
  const preserved = [
    manifestPath(paths, created.manifestId),
    claimPath(paths, created.manifestId),
    runPath(paths, created.runId),
    evidencePath(paths, result.evidence.stdout.ref),
    evidencePath(paths, result.evidence.stderr.ref),
    evidencePath(paths, result.evidence.resultRef)
  ];
  assert.equal(offlineAnalysisStatus({ paths }).retention.terminalManifests, 1);

  const purged = purgeOfflineAnalysisArtifact("offline-project", {
    manifestId: created.manifestId,
    confirm: created.purgeConfirmationRequired
  }, { paths });
  assert.equal(purged.transition, "terminal");
  assert.equal(fs.existsSync(snapshotPath(paths, created.runId)), false);
  for (const file of preserved) assert.equal(fs.existsSync(file), true);
  const status = offlineAnalysisStatus({ paths });
  assert.equal(status.counts.succeeded, 1);
  assert.equal(status.retention.terminalManifests, 0);
  assert.equal(status.retention.purgedManifests, 1);
});

managedTest("status converts a PID-reuse identity mismatch and malformed private state to unknown", (t) => {
  const { root, paths } = fixture(t);
  const artifact = path.join(root, "orphaned-claim.exe");
  writeMinimalPe(artifact);
  const created = createOfflineAnalysisManifest(
    "offline-project",
    { path: artifact, maxMinutes: 1 },
    { paths }
  );
  const manifest = readManifest(paths, created.manifestId);
  const identity = testProcessIdentity();
  fs.writeFileSync(claimPath(paths, created.manifestId), `${JSON.stringify({
    apiVersion: "gate.offline-analysis-claim/v1",
    manifestId: created.manifestId,
    runId: created.runId,
    manifestSha256: created.manifestSha256,
    projectId: "offline-project",
    claimedAt: new Date().toISOString(),
    supervisorPid: process.pid,
    supervisorIdentity: {
      bootId: identity.bootId,
      startTimeTicks: String(BigInt(identity.startTimeTicks) + 1n)
    }
  })}\n`, { mode: 0o600 });
  fs.writeFileSync(runPath(paths, created.runId), `${JSON.stringify({
    $schema: "../../schemas/offline-analysis-run.schema.json",
    apiVersion: "gate.offline-analysis-run/v1",
    kind: "OfflineAnalysisRun",
    runId: created.runId,
    manifestId: created.manifestId,
    manifestSha256: created.manifestSha256,
    projectId: "offline-project",
    status: "queued",
    createdAt: new Date().toISOString(),
    startedAt: null,
    finishedAt: null,
    terminationReason: null,
    result: { exitCode: null, signal: null, durationMs: null },
    evidence: {
      stdout: { ref: manifest.runtime.evidence.stdoutRef, available: false, sha256: null, bytes: 0 },
      stderr: { ref: manifest.runtime.evidence.stderrRef, available: false, sha256: null, bytes: 0 },
      resultRef: manifest.runtime.evidence.resultRef,
      resultAvailable: false,
      sandboxRef: manifest.runtime.sandboxRef
    },
    isolationVerified: null
  }, null, 2)}\n`, { mode: 0o600 });

  let status = offlineAnalysisStatus({ paths });
  assert.equal(status.counts.unknown, 1);
  assert.equal(status.recent[0].runId, created.runId);
  assert.equal(status.recent[0].status, "unknown");
  assert.equal(status.recent[0].terminationReason, "supervision-lost");
  assert.throws(
    () => purgeOfflineAnalysisArtifact("offline-project", {
      manifestId: created.manifestId,
      confirm: created.purgeConfirmationRequired
    }, { paths }),
    /cannot be purged while its run is queued/u
  );
  assert.equal(fs.existsSync(snapshotPath(paths, created.runId)), true);
  assert.equal(fs.existsSync(purgePath(paths, created.manifestId)), false);

  fs.writeFileSync(runPath(paths, created.runId), "{}\n", { mode: 0o600 });
  status = offlineAnalysisStatus({ paths });
  assert.equal(status.counts.unknown, 2);
  assert.equal(status.retention.invalidRunRecords, 1);
  assert.equal(status.retention.invalidEntries, 1);
  assert.equal(status.retention.blockedManifests, 1);
  assert.equal(status.retention.unknownManifests, 1);
  assert.equal(status.retention.pendingManifests, 0);
  assert.equal(status.retention.activeManifests, 0);
  assert.equal(status.retention.terminalManifests, 0);
  assert.equal(status.retention.mutationBlocked, false);
  assert.equal(status.retention.snapshotState, "consistent");
  assert.throws(
    () => purgeOfflineAnalysisArtifact("offline-project", {
      manifestId: created.manifestId,
      confirm: created.purgeConfirmationRequired
    }, { paths }),
    /offline(?:-| )analysis(?:-| )run/u
  );
});

managedTest("execution rechecks manifest expiry after integrity preflight and before spawn", {
  timeout: 60_000
}, async (t) => {
  const { root, paths } = fixture(t);
  const artifact = path.join(root, "expires-during-preflight.exe");
  writeMinimalPe(artifact);
  const created = createOfflineAnalysisManifest("offline-project", { path: artifact, maxMinutes: 1 }, { paths });
  const manifest = readManifest(paths, created.manifestId);
  manifest.metadata.expiresAt = new Date(Date.now() + 750).toISOString();
  manifest.manifestSha256 = offlineAnalysisInternals.manifestDigest(manifest);
  fs.writeFileSync(manifestPath(paths, created.manifestId), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
  assert.ok(Date.now() < Date.parse(manifest.metadata.expiresAt));

  await assert.rejects(
    executeOfflineAnalysisManifest("offline-project", {
      manifestId: created.manifestId,
      confirm: `ANALYZE ${created.manifestId} ${manifest.manifestSha256} OFFLINE`
    }, { paths }),
    /expired during preflight/u
  );
  const run = JSON.parse(fs.readFileSync(runPath(paths, created.runId), "utf8"));
  assert.equal(run.status, "blocked");
  assert.equal(run.startedAt, null);
  assert.equal(run.terminationReason, "manifest-expired");
});

managedTest("a supervisor signal observed after preflight prevents spawn", {
  timeout: 60_000
}, async (t) => {
  const { root, paths } = fixture(t);
  const artifact = path.join(root, "signal-during-preflight.exe");
  writeMinimalPe(artifact);
  const created = createOfflineAnalysisManifest("offline-project", { path: artifact, maxMinutes: 1 }, { paths });
  const execution = executeOfflineAnalysisManifest("offline-project", {
    manifestId: created.manifestId,
    confirm: created.confirmationRequired
  }, { paths });
  process.emit("SIGTERM");
  await assert.rejects(execution, /cancelled before launch/u);
  const run = JSON.parse(fs.readFileSync(runPath(paths, created.runId), "utf8"));
  assert.equal(run.status, "cancelled");
  assert.equal(run.startedAt, null);
  assert.equal(run.terminationReason, "supervisor-signal");
});

managedTest("a failure after terminal computation still persists a terminal run", {
  timeout: 60_000
}, async (t) => {
  const { root, paths } = fixture(t);
  const artifact = path.join(root, "terminal-persistence.exe");
  writeMinimalPe(artifact);
  const created = createOfflineAnalysisManifest("offline-project", { path: artifact, maxMinutes: 1 }, { paths });
  const manifest = readManifest(paths, created.manifestId);
  fs.writeFileSync(evidencePath(paths, manifest.runtime.evidence.resultRef), "occupied\n", { mode: 0o600 });

  await assert.rejects(
    executeOfflineAnalysisManifest("offline-project", {
      manifestId: created.manifestId,
      confirm: created.confirmationRequired
    }, { paths }),
    /exist/u
  );
  const run = JSON.parse(fs.readFileSync(runPath(paths, created.runId), "utf8"));
  assert.equal(run.status, "failed");
  assert.equal(run.finishedAt !== null, true);
  assert.equal(run.terminationReason, "evidence-write-failure");
  assert.equal(run.evidence.resultAvailable, false);
});

managedTest("real Bubblewrap and pinned REA analyze a harmless minimal PE with private bounded evidence", {
  skip: realIntegrationSkip,
  timeout: 60_000
}, async (t) => {
  const runtime = actualRuntime();
  const { root, paths } = fixture(t);
  assert.equal(offlineAnalysisCapability({ paths }).laneAvailable, true);
  const artifact = path.join(root, "minimal, PE  fixture.exe");
  writeMinimalPe(artifact);
  const created = createOfflineAnalysisManifest(
    "offline-project",
    { path: artifact, maxMinutes: 1 },
    { paths }
  );
  const manifest = readManifest(paths, created.manifestId);
  assert.equal(manifest.operation.targetSelector.value, artifact);
  assert.equal(manifest.runtime.maxEvidenceBytesPerStream, MAX_EVIDENCE_BYTES);
  assert.match(manifest.runtime.evidence.stdoutRef, /^private:\/\/evidence\//u);
  assert.match(manifest.runtime.evidence.stderrRef, /^private:\/\/evidence\//u);
  assert.match(manifest.runtime.evidence.resultRef, /^private:\/\/evidence\//u);

  const result = await executeOfflineAnalysisManifest("offline-project", {
    manifestId: created.manifestId,
    confirm: created.confirmationRequired
  }, { paths });
  assert.equal(result.ok, true);
  assert.equal(result.status, "succeeded");
  assert.equal(result.terminationReason, "completed");
  assert.equal(result.isolationVerified, true);
  const stdoutFile = evidencePath(paths, result.evidence.stdout.ref);
  const stderrFile = evidencePath(paths, result.evidence.stderr.ref);
  const resultFile = evidencePath(paths, result.evidence.resultRef);
  const adapterResult = JSON.parse(fs.readFileSync(stdoutFile, "utf8"));
  assert.deepEqual(adapterResult.isolation.interfaces, ["lo"]);
  assert.deepEqual(adapterResult.isolation.ipv4Routes, []);
  assert.equal(adapterResult.isolation.noNewPrivileges, true);
  assert.ok(Object.values(adapterResult.isolation.capabilities).every((value) => value === "0000000000000000"));
  assert.equal(adapterResult.artifact.sha256, created.artifact.sha256);
  assert.equal(adapterResult.artifact.bytes, created.artifact.bytes);
  assert.equal(adapterResult.result.ok, true);
  assert.equal(adapterResult.result.data.normalized_result.format, "pe32");
  assert.equal(adapterResult.result.data.normalized_result.coverage.status, "complete");
  assert.equal(fs.readFileSync(stdoutFile, "utf8").includes(artifact), false);
  assert.equal(fs.readFileSync(resultFile, "utf8").includes(artifact), false);
  assert.equal(fs.statSync(stdoutFile).size, result.evidence.stdout.bytes);
  assert.equal(fs.statSync(stderrFile).size, result.evidence.stderr.bytes);
  assert.ok(result.evidence.stdout.bytes <= MAX_EVIDENCE_BYTES);
  assert.ok(result.evidence.stderr.bytes <= MAX_EVIDENCE_BYTES);
  for (const file of [
    manifestPath(paths, created.manifestId),
    claimPath(paths, created.manifestId),
    runPath(paths, created.runId),
    path.join(paths.offlineAnalysisInputs, `${created.runId}.bin`),
    stdoutFile,
    stderrFile,
    resultFile
  ]) assert.equal(mode(file), 0o600);
  for (const directory of [
    paths.home,
    paths.offlineAnalyses,
    paths.offlineAnalysisTransactions,
    paths.offlineAnalysisManifests,
    paths.offlineAnalysisCreations,
    paths.offlineAnalysisClaims,
    paths.offlineAnalysisPurges,
    paths.offlineAnalysisRuns,
    paths.offlineAnalysisInputs,
    paths.offlineAnalysisSandboxes,
    paths.evidence
  ]) assert.equal(mode(directory), 0o700);

  const status = offlineAnalysisStatus({ paths });
  assert.equal(status.counts.succeeded, 1);
  assert.equal(status.recent[0].runId, created.runId);
  assert.equal(status.recent[0].isolationVerified, true);
});

managedTest("a Bubblewrap network namespace cannot reach a host-loopback listener", {
  timeout: 60_000
}, async (t) => {
  let hostConnections = 0;
  const server = net.createServer((socket) => {
    hostConnections += 1;
    socket.destroy();
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(() => server.close());
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const script = [
    "import socket",
    "sock = socket.socket()",
    "sock.settimeout(0.5)",
    `print(str(sock.connect_ex((\"127.0.0.1\", ${address.port})) == 0).lower(), end=\"\")`
  ].join("; ");
  const probe = spawnSync(realBwrap, [
    "--unshare-user", "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts",
    "--unshare-cgroup-try", "--disable-userns", "--die-with-parent", "--new-session",
    "--cap-drop", "ALL", "--clearenv", "--ro-bind", "/usr", "/usr", "--proc", "/proc",
    "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
    "--symlink", "usr/lib64", "/lib64", "--dev", "/dev",
    "--", "/usr/bin/python3", "-c", script
  ], { cwd: "/", env: {}, encoding: "utf8", timeout: 10_000 });
  assert.equal(probe.status, 0, probe.stderr);
  assert.equal(probe.stdout, "false");
  await delay(25);
  assert.equal(hostConnections, 0);
});
