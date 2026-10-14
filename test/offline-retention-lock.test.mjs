import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";

import { offlineAnalysisInternals } from "../src/lib/offline-analysis.mjs";

const runtimeModule = new URL("../src/lib/offline-analysis.mjs", import.meta.url).href;

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-retention-serialization-"));
  const paths = offlineAnalysisInternals.analysisPaths({ home: root });
  for (const [key, directory] of Object.entries(paths)) {
    if (key.startsWith("offline")) fs.mkdirSync(directory, { mode: 0o700, recursive: true });
  }
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, paths };
}

function staleLock(paths) {
  const file = path.join(paths.offlineAnalyses, ".retention.lock");
  fs.writeFileSync(file, `${JSON.stringify({
    apiVersion: "gate.offline-analysis-retention-lock/v1",
    pid: 2_147_483_647,
    processIdentity: { bootId: fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim(), startTimeTicks: "1" },
    nonce: "a".repeat(32),
    createdAt: new Date().toISOString()
  })}\n`, { mode: 0o600 });
  return file;
}

async function waitFor(file) {
  const deadline = Date.now() + 4000;
  while (!fs.existsSync(file)) {
    if (Date.now() >= deadline) throw new Error(`worker did not publish ${path.basename(file)}`);
    await delay(10);
  }
}

const workerSource = `
import fs from "node:fs";
import path from "node:path";
import { offlineAnalysisInternals } from ${JSON.stringify(runtimeModule)};
const [root, role] = process.argv.slice(1);
const paths = offlineAnalysisInternals.analysisPaths({ home: root });
const signal = (name) => fs.writeFileSync(path.join(root, name), "ready", { mode: 0o600 });
const wait = (name) => {
  const deadline = Date.now() + 4000;
  while (!fs.existsSync(path.join(root, name))) {
    if (Date.now() >= deadline) throw new Error("worker signal timed out: " + name);
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
  }
};
if (role === "recoverer") {
  const unlink = fs.unlinkSync;
  let paused = false;
  fs.unlinkSync = function(file) {
    if (!paused && file === path.join(paths.offlineAnalyses, ".retention.lock")) {
      paused = true;
      signal("recovery-paused");
      wait("resume-recovery");
    }
    return unlink.call(fs, file);
  };
}
signal(role + "-started");
offlineAnalysisInternals.withRetentionLock(paths, (retained) => {
  signal(role + "-entered");
  if (role === "recoverer") wait("release-recoverer");
  if (retained.artifacts.size < 64) {
    fs.writeFileSync(path.join(paths.offlineAnalysisInputs, "arun_" + (role === "recoverer" ? "e" : "f").repeat(32) + ".bin"), "x", { mode: 0o600 });
  }
  signal(role + "-finished");
});
`;

function worker(t, root, role) {
  const child = spawn(process.execPath, ["--input-type=module", "-e", workerSource, root, role], {
    stdio: ["ignore", "pipe", "pipe"]
  });
  let stderr = "";
  child.stderr.on("data", (bytes) => { stderr += bytes; });
  t.after(() => { if (child.exitCode === null) child.kill("SIGKILL"); });
  const finished = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => resolve({ code, stderr }));
  });
  return finished;
}

test("stale recovery excludes a concurrent successor through mutation and release", { skip: process.platform !== "linux" }, async (t) => {
  const { root, paths } = fixture(t);
  const lock = staleLock(paths);
  for (let index = 0; index < 63; index += 1) {
    fs.writeFileSync(path.join(paths.offlineAnalysisInputs, `arun_${index.toString(16).padStart(32, "0")}.bin`), "x", { mode: 0o600 });
  }
  const recovering = worker(t, root, "recoverer");
  await waitFor(path.join(root, "recovery-paused"));
  const contender = worker(t, root, "contender");
  await waitFor(path.join(root, "contender-started"));
  const descriptor = fs.openSync(paths.offlineAnalyses, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try {
    const probe = spawnSync("flock", ["--exclusive", "--nonblock", "3"], {
      stdio: ["ignore", "pipe", "pipe", descriptor], env: { PATH: "/usr/bin:/bin" }
    });
    assert.equal(probe.status, 1, "recovery must retain kernel ownership while paused before unlink");
  } finally {
    fs.closeSync(descriptor);
  }
  assert.equal(fs.existsSync(path.join(root, "contender-entered")), false);
  fs.writeFileSync(path.join(root, "resume-recovery"), "go", { mode: 0o600 });
  await waitFor(path.join(root, "recoverer-entered"));
  assert.equal(fs.existsSync(path.join(root, "contender-entered")), false);
  fs.writeFileSync(path.join(root, "release-recoverer"), "go", { mode: 0o600 });
  assert.deepEqual(await recovering, { code: 0, stderr: "" });
  assert.deepEqual(await contender, { code: 0, stderr: "" });
  assert.equal(fs.readdirSync(paths.offlineAnalysisInputs).length, 64);
  assert.equal(fs.existsSync(lock), false);
  assert.deepEqual(fs.readdirSync(paths.offlineAnalysisTransactions), []);
});

test("retention serialization releases after failure and preserves malformed metadata", { skip: process.platform !== "linux" }, (t) => {
  const { paths } = fixture(t);
  const lock = staleLock(paths);
  assert.throws(() => offlineAnalysisInternals.withRetentionLock(paths, () => {
    throw new Error("fixture action failed");
  }), /fixture action failed/u);
  assert.equal(fs.existsSync(lock), false);
  assert.equal(offlineAnalysisInternals.withRetentionLock(paths, () => "success"), "success");
  fs.writeFileSync(lock, "{}\n", { mode: 0o600 });
  assert.throws(() => offlineAnalysisInternals.withRetentionLock(paths, () => "unsafe", { timeoutMs: 30 }), /could not be recovered safely/u);
  assert.equal(fs.readFileSync(lock, "utf8"), "{}\n");
});
