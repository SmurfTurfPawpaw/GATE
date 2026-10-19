#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import {
  CodexCompanionAdapter,
  REMOTE_CODEX_APP_SERVER_VERSION,
  REMOTE_READ_ONLY_EXECUTION_POSTURE
} from "../companion/app-server.mjs";
import { ActivityStore } from "../companion/activity.mjs";
import { createGateFleetProvider, gateFleetInternals } from "../companion/gate-fleet.mjs";
import { RemoteCockpitRunner } from "./runner.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_CWD = path.resolve(HERE, "../..");
const THREAD_RECORD_VERSION = "gate.remote-runner-thread/v3";
const REMOTE_TOOL_BOUNDARY_REVISION = "gate.remote-tool-boundary/v2";
const LOCK_VERSION = "gate.remote-runner-lock/v1";
const THREAD_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/u;
const RUNNER_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/u;
const CASE_ID = /^[a-z][a-z0-9-]{1,62}$/u;
const MAX_PRIVATE_KEY_BYTES = 16 * 1024;
const MAX_THREAD_RECORD_BYTES = 4 * 1024;
const REMOTE_CODEX_ENVIRONMENT_KEYS = new Set([
  "COMSPEC",
  "LANG",
  "LANGUAGE",
  "LC_ALL",
  "PATH",
  "PATHEXT",
  "SYSTEMROOT",
  "TEMP",
  "TMP",
  "TMPDIR",
  "WINDIR"
]);

function remoteCodexEnvironment(source, codexHome) {
  if (typeof codexHome !== "string" || !path.isAbsolute(codexHome)) {
    throw new Error("remote Codex home must be absolute");
  }
  const result = {};
  for (const [key, value] of Object.entries(source)) {
    const canonicalKey = key.toUpperCase();
    if (!REMOTE_CODEX_ENVIRONMENT_KEYS.has(canonicalKey)
        || typeof value !== "string" || value.includes("\0")) continue;
    if (Object.hasOwn(result, canonicalKey) && result[canonicalKey] !== value) {
      throw new Error("remote Codex environment contains conflicting case aliases");
    }
    result[canonicalKey] = value;
  }
  result.CODEX_HOME = codexHome;
  result.HOME = codexHome;
  result.USERPROFILE = codexHome;
  result.APPDATA = path.join(codexHome, "appdata");
  result.LOCALAPPDATA = path.join(codexHome, "local-appdata");
  result.XDG_CACHE_HOME = path.join(codexHome, "xdg-cache");
  result.XDG_CONFIG_HOME = path.join(codexHome, "xdg-config");
  result.XDG_DATA_HOME = path.join(codexHome, "xdg-data");
  return Object.freeze(result);
}

function usage() {
  return `Usage: node cockpit/remote/runner-cli.mjs [options]

Required options (or matching environment variables):
  --control-plane URL       HTTPS coordinator origin (GATE_REMOTE_CONTROL_PLANE)
  --case-id ID              One configured GATE case (GATE_REMOTE_CASE_ID)
  --session-revision N      Coordinator session revision (GATE_REMOTE_SESSION_REVISION)
  --runner-id ID            Registered Ed25519 runner identity (GATE_REMOTE_RUNNER_ID)
  --private-key-file PATH   Owner-only Ed25519 private PEM (GATE_REMOTE_PRIVATE_KEY_FILE)
  --journal-dir PATH        Existing owner-only state directory (GATE_REMOTE_JOURNAL_DIR)
  --codex-home PATH         Dedicated owner-only Codex home directly under journal-dir
                            (GATE_REMOTE_CODEX_HOME)
  --thread-id-file PATH     Thread record directly under journal-dir
                            (GATE_REMOTE_THREAD_ID_FILE)

Optional:
  --cwd PATH                Dedicated Codex thread working directory (GATE_REPO)
  --gate-observer URL       Exact loopback /api/status endpoint (GATE_OBSERVER_URL)
  --help                    Show this help
`;
}

function nonempty(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function resolved(value) {
  return value === null ? null : path.resolve(value);
}

function parseRevision(value) {
  if (value === null || !/^[1-9][0-9]{0,9}$/u.test(value)) throw new Error("session revision is required");
  const revision = Number(value);
  if (!Number.isSafeInteger(revision) || revision > 2_147_483_647) {
    throw new Error("session revision is invalid");
  }
  return revision;
}

function parseArguments(argv, env = process.env) {
  const values = {
    controlPlaneUrl: nonempty(env.GATE_REMOTE_CONTROL_PLANE),
    caseId: nonempty(env.GATE_REMOTE_CASE_ID),
    sessionRevision: nonempty(env.GATE_REMOTE_SESSION_REVISION),
    runnerId: nonempty(env.GATE_REMOTE_RUNNER_ID),
    privateKeyFile: resolved(nonempty(env.GATE_REMOTE_PRIVATE_KEY_FILE)),
    journalDirectory: resolved(nonempty(env.GATE_REMOTE_JOURNAL_DIR)),
    codexHome: resolved(nonempty(env.GATE_REMOTE_CODEX_HOME)),
    threadIdFile: resolved(nonempty(env.GATE_REMOTE_THREAD_ID_FILE)),
    cwd: resolved(nonempty(env.GATE_REPO)) ?? DEFAULT_CWD,
    gateObserver: nonempty(env.GATE_OBSERVER_URL) ?? gateFleetInternals.DEFAULT_OBSERVER_URL
  };
  const optionNames = new Map([
    ["--control-plane", "controlPlaneUrl"],
    ["--case-id", "caseId"],
    ["--session-revision", "sessionRevision"],
    ["--runner-id", "runnerId"],
    ["--private-key-file", "privateKeyFile"],
    ["--journal-dir", "journalDirectory"],
    ["--codex-home", "codexHome"],
    ["--thread-id-file", "threadIdFile"],
    ["--cwd", "cwd"],
    ["--gate-observer", "gateObserver"]
  ]);
  const seen = new Set();
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help") return Object.freeze({ help: true });
    const key = optionNames.get(argument);
    if (!key) throw new Error("unknown runner option");
    if (seen.has(key)) throw new Error("runner option was repeated");
    seen.add(key);
    const value = nonempty(argv[++index]);
    if (!value) throw new Error("runner option requires a value");
    values[key] = new Set(["privateKeyFile", "journalDirectory", "codexHome", "threadIdFile", "cwd"]).has(key)
      ? path.resolve(value)
      : value;
  }
  for (const [key, label] of [
    ["controlPlaneUrl", "control-plane URL"],
    ["caseId", "case identifier"],
    ["runnerId", "runner identifier"],
    ["privateKeyFile", "private-key file"],
    ["journalDirectory", "journal directory"],
    ["codexHome", "remote Codex home"],
    ["threadIdFile", "thread-id file"]
  ]) {
    if (!values[key]) throw new Error(`${label} is required`);
  }
  values.sessionRevision = parseRevision(values.sessionRevision);
  let coordinator;
  try { coordinator = new URL(values.controlPlaneUrl); } catch { throw new Error("control-plane URL is invalid"); }
  if (coordinator.protocol !== "https:" || !coordinator.hostname || coordinator.origin !== values.controlPlaneUrl
      || coordinator.pathname !== "/" || coordinator.search || coordinator.hash
      || coordinator.username || coordinator.password) {
    throw new Error("control-plane URL must be an exact HTTPS origin");
  }
  if (!CASE_ID.test(values.caseId)) throw new Error("case identifier is invalid");
  if (!RUNNER_ID.test(values.runnerId)) throw new Error("runner identifier is invalid");
  if (path.dirname(values.threadIdFile) !== values.journalDirectory) {
    throw new Error("thread-id file must be directly under the journal directory");
  }
  if (path.dirname(values.codexHome) !== values.journalDirectory) {
    throw new Error("remote Codex home must be directly under the journal directory");
  }
  if (new Set(["remote-runner-journal.json", ".remote-runner.lock"]).has(path.basename(values.threadIdFile))) {
    throw new Error("thread-id file conflicts with reserved runner state");
  }
  if (values.threadIdFile === values.privateKeyFile) throw new Error("thread-id file conflicts with the private key");
  return Object.freeze(values);
}

function assertOwnerOnly(stat, label) {
  if ((stat.mode & 0o077) !== 0) throw new Error(`${label} must be owner-only`);
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
    throw new Error(`${label} must be owned by the current operator`);
  }
}

function ownerDirectory(value) {
  let stat;
  try { stat = fs.lstatSync(value); } catch { throw new Error("runner state directory is unavailable"); }
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("runner state directory is invalid");
  assertOwnerOnly(stat, "runner state directory");
  let real;
  try { real = fs.realpathSync.native(value); } catch { throw new Error("runner state directory is unavailable"); }
  if (real !== value) throw new Error("runner state directory must not traverse symbolic links");
  return value;
}

function pathsOverlap(left, right) {
  const normalized = (value) => {
    const absolute = path.resolve(value);
    return process.platform === "win32" ? absolute.toLowerCase() : absolute;
  };
  const first = normalized(left);
  const second = normalized(right);
  const contains = (parent, candidate) => {
    const relative = path.relative(parent, candidate);
    return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`)
      && !path.isAbsolute(relative));
  };
  return contains(first, second) || contains(second, first);
}

function assertProtectedRuntimePath(value) {
  let current = value;
  while (true) {
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) throw new Error("remote Codex runtime path must not contain symbolic links");
    let writable = false;
    try { fs.accessSync(current, fs.constants.W_OK); writable = true; } catch {}
    const unsafePosixMetadata = process.platform !== "win32" && ((stat.mode & 0o022) !== 0 || stat.uid !== 0);
    if (writable || unsafePosixMetadata) {
      throw new Error("remote Codex runtime path must be administrator-owned and not writable by local accounts");
    }
    const parent = path.dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

function remoteExecutableNames(environment) {
  if (process.platform !== "win32") return ["codex"];
  const extensions = String(environment.PATHEXT || ".COM;.EXE;.CMD;.BAT")
    .split(";")
    .map((value) => value.trim())
    .filter((value) => /^\.[A-Za-z0-9]{1,12}$/u.test(value));
  return extensions.map((extension) => `codex${extension}`);
}

function prepareRemoteCodexLaunch(source, codexHome, forbiddenRoots = []) {
  const baseEnvironment = remoteCodexEnvironment(source, codexHome);
  if (!Array.isArray(forbiddenRoots)
      || forbiddenRoots.some((value) => typeof value !== "string" || !path.isAbsolute(value))) {
    throw new Error("remote Codex forbidden roots must be absolute");
  }
  const roots = forbiddenRoots.map((value) => path.resolve(value));
  const directories = [];
  for (const rawEntry of String(baseEnvironment.PATH || "").split(path.delimiter)) {
    const entry = rawEntry.trim().replace(/^"(.*)"$/u, "$1");
    if (!entry || !path.isAbsolute(entry) || entry.includes("\0")) continue;
    let directory;
    try {
      directory = fs.realpathSync.native(entry);
      if (!fs.statSync(directory).isDirectory() || roots.some((root) => pathsOverlap(root, directory))) continue;
      assertProtectedRuntimePath(directory);
    } catch {
      continue;
    }
    const key = process.platform === "win32" ? directory.toLowerCase() : directory;
    if (!directories.some((item) => item.key === key)) directories.push({ key, path: directory });
  }
  let command = null;
  for (const directory of directories) {
    for (const name of remoteExecutableNames(baseEnvironment)) {
      const candidate = path.join(directory.path, name);
      try {
        const real = fs.realpathSync.native(candidate);
        const stat = fs.statSync(real);
        if (!stat.isFile() || roots.some((root) => pathsOverlap(root, real))) continue;
        fs.accessSync(real, process.platform === "win32" ? fs.constants.F_OK : fs.constants.X_OK);
        assertProtectedRuntimePath(real);
        command = real;
        break;
      } catch {
        // Continue through the sanitized, protected absolute search path.
      }
    }
    if (command) break;
  }
  if (!command) throw new Error("a protected absolute Codex executable is unavailable outside private runner state");
  return Object.freeze({
    command,
    environment: Object.freeze({
      ...baseEnvironment,
      PATH: directories.map((item) => item.path).join(path.delimiter)
    })
  });
}

function stableOwnerFile(value, maximumBytes, label) {
  let before;
  try { before = fs.lstatSync(value, { bigint: true }); } catch { throw new Error(`${label} is unavailable`); }
  if (!before.isFile() || before.isSymbolicLink() || before.size < 1n || before.size > BigInt(maximumBytes)) {
    throw new Error(`${label} is invalid`);
  }
  assertOwnerOnly({ mode: Number(before.mode), uid: Number(before.uid) }, label);
  let real;
  try { real = fs.realpathSync.native(value); } catch { throw new Error(`${label} is unavailable`); }
  if (real !== value) throw new Error(`${label} must not traverse symbolic links`);
  let descriptor;
  try {
    descriptor = fs.openSync(value, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (!after.isFile() || before.dev !== after.dev || before.ino !== after.ino || after.size !== BigInt(bytes.length)
        || before.mtimeNs !== after.mtimeNs) throw new Error("changed");
    return bytes;
  } catch {
    throw new Error(`${label} could not be read safely`);
  } finally {
    if (descriptor !== undefined) try { fs.closeSync(descriptor); } catch {}
  }
}

function readPrivateKey(value) {
  const bytes = stableOwnerFile(value, MAX_PRIVATE_KEY_BYTES, "runner private-key file");
  try {
    const key = crypto.createPrivateKey(bytes);
    if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
      throw new Error("wrong key type");
    }
    return key;
  } catch {
    throw new Error("runner private-key file does not contain an Ed25519 private key");
  } finally {
    bytes.fill(0);
  }
}

function fsyncDirectory(directory) {
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0));
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}

function atomicOwnerWrite(file, value) {
  const directory = path.dirname(file);
  const temporary = path.join(directory, `.remote-runner-state.${process.pid}.${Date.now()}.tmp`);
  let descriptor;
  try {
    descriptor = fs.openSync(temporary,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0), 0o600);
    fs.writeFileSync(descriptor, value, "utf8");
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.renameSync(temporary, file);
    fsyncDirectory(directory);
  } catch {
    if (descriptor !== undefined) try { fs.closeSync(descriptor); } catch {}
    try { fs.rmSync(temporary, { force: true }); } catch {}
    throw new Error("runner private state could not be saved");
  }
}

function exactKeys(value, expected) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

class ThreadRecord {
  #beganHere = false;
  #caseId;
  #codexHome;
  #cwd;
  #file;
  #runnerId;
  #state;
  #provisionedHere = false;
  #poisoned = false;

  constructor({ file, runnerId, caseId, cwd, codexHome }) {
    if (typeof codexHome !== "string" || !path.isAbsolute(codexHome)) {
      throw new Error("runner thread record requires an absolute remote Codex home");
    }
    this.#file = file;
    this.#runnerId = runnerId;
    this.#caseId = caseId;
    this.#cwd = cwd;
    this.#codexHome = codexHome;
    this.#state = this.#load();
  }

  get threadId() {
    this.#assertUsable();
    if (this.#state.state === "used") return this.#state.threadId;
    if (this.#state.state === "absent") return null;
    throw new Error("a prior Codex thread creation is unresolved; reconcile it before restarting the runner");
  }

  begin() {
    this.#assertUsable();
    if (this.#state.state !== "absent") throw new Error("Codex thread creation is already recorded");
    this.#persist(this.#document("creating", null));
    this.#beganHere = true;
  }

  provisional(threadId) {
    this.#assertUsable();
    if (!this.#beganHere || this.#state.state !== "creating"
        || typeof threadId !== "string" || !THREAD_ID.test(threadId)) {
      throw new Error("Codex returned an invalid dedicated thread identifier");
    }
    this.#persist(this.#document("provisional", threadId));
    this.#provisionedHere = true;
  }

  markUsed(threadId) {
    this.#assertUsable();
    if (this.#state.state === "used" && this.#state.threadId === threadId) return false;
    if (!this.#provisionedHere || this.#state.state !== "provisional" || this.#state.threadId !== threadId
        || typeof threadId !== "string" || !THREAD_ID.test(threadId)) {
      throw new Error("Codex thread use does not match the provisional record");
    }
    this.#persist(this.#document("used", threadId));
    return true;
  }

  discardCleanProvisional(threadId) {
    this.#assertUsable();
    if (this.#state.state === "used") {
      if (this.#state.threadId !== threadId) throw new Error("clean shutdown thread does not match its record");
      return false;
    }
    if (this.#state.state === "absent") return false;
    if (!this.#provisionedHere || this.#state.state !== "provisional" || this.#state.threadId !== threadId
        || typeof threadId !== "string" || !THREAD_ID.test(threadId)) {
      throw new Error("only the matching clean provisional thread can be discarded");
    }
    const expected = `${JSON.stringify(this.#state)}\n`;
    try {
      const bytes = stableOwnerFile(this.#file, MAX_THREAD_RECORD_BYTES, "runner thread-id file");
      if (!bytes.equals(Buffer.from(expected, "utf8"))) throw new Error("changed");
      fs.unlinkSync(this.#file);
      fsyncDirectory(path.dirname(this.#file));
    } catch {
      this.#poisoned = true;
      throw new Error("runner provisional thread record could not be discarded");
    }
    this.#state = Object.freeze({ state: "absent", threadId: null });
    this.#beganHere = false;
    this.#provisionedHere = false;
    return true;
  }

  #document(state, threadId) {
    return Object.freeze({
      apiVersion: THREAD_RECORD_VERSION,
      toolBoundaryRevision: REMOTE_TOOL_BOUNDARY_REVISION,
      codexAppServerVersion: REMOTE_CODEX_APP_SERVER_VERSION,
      executionPosture: REMOTE_READ_ONLY_EXECUTION_POSTURE,
      runnerId: this.#runnerId,
      caseId: this.#caseId,
      cwd: this.#cwd,
      codexHome: this.#codexHome,
      state,
      threadId
    });
  }

  #load() {
    if (!fs.existsSync(this.#file)) return Object.freeze({ state: "absent", threadId: null });
    const bytes = stableOwnerFile(this.#file, MAX_THREAD_RECORD_BYTES, "runner thread-id file");
    let value;
    try { value = JSON.parse(bytes.toString("utf8")); } catch { throw new Error("runner thread-id file is invalid"); }
    if (!exactKeys(value, [
      "apiVersion",
      "toolBoundaryRevision",
      "codexAppServerVersion",
      "executionPosture",
      "runnerId",
      "caseId",
      "cwd",
      "codexHome",
      "state",
      "threadId"
    ])
        || value.apiVersion !== THREAD_RECORD_VERSION
        || value.toolBoundaryRevision !== REMOTE_TOOL_BOUNDARY_REVISION
        || value.codexAppServerVersion !== REMOTE_CODEX_APP_SERVER_VERSION
        || value.executionPosture !== REMOTE_READ_ONLY_EXECUTION_POSTURE
        || value.runnerId !== this.#runnerId
        || value.caseId !== this.#caseId || value.cwd !== this.#cwd || value.codexHome !== this.#codexHome
        || !new Set(["creating", "provisional", "used"]).has(value.state)
        || (value.state === "creating" ? value.threadId !== null
          : typeof value.threadId !== "string" || !THREAD_ID.test(value.threadId))) {
      throw new Error("runner thread-id file does not match this runner");
    }
    return Object.freeze(value);
  }

  #assertUsable() {
    if (this.#poisoned) throw new Error("runner thread record has an ambiguous write and requires reconciliation");
  }

  #persist(document) {
    try {
      atomicOwnerWrite(this.#file, `${JSON.stringify(document)}\n`);
    } catch (error) {
      this.#poisoned = true;
      throw error;
    }
    this.#state = document;
  }
}

function acquireInstanceLock(directory) {
  const file = path.join(directory, ".remote-runner.lock");
  let descriptor;
  let identity = null;
  let created = false;
  const removeOwnedPath = () => {
    if (!created || identity === null) return false;
    let current;
    try { current = fs.lstatSync(file, { bigint: true }); } catch { return false; }
    if (!current.isFile() || current.isSymbolicLink()
        || current.dev !== identity.dev || current.ino !== identity.ino) return false;
    try { fs.rmSync(file); fsyncDirectory(directory); return true; } catch { return false; }
  };
  try {
    descriptor = fs.openSync(file,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0), 0o600);
    created = true;
    identity = fs.fstatSync(descriptor, { bigint: true });
    fs.writeFileSync(descriptor, `${JSON.stringify({ apiVersion: LOCK_VERSION, pid: process.pid })}\n`, "utf8");
    fs.fsyncSync(descriptor);
    fsyncDirectory(directory);
  } catch {
    if (descriptor !== undefined) try { fs.closeSync(descriptor); } catch {}
    removeOwnedPath();
    throw new Error("another runner may already own this state directory");
  }
  let released = false;
  return () => {
    if (released) return;
    released = true;
    try { fs.closeSync(descriptor); } catch {}
    removeOwnedPath();
  };
}

function validateCwd(value) {
  let stat;
  try { stat = fs.lstatSync(value); } catch { throw new Error("Codex working directory is unavailable"); }
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("Codex working directory is invalid");
  let real;
  try { real = fs.realpathSync.native(value); } catch { throw new Error("Codex working directory is unavailable"); }
  const expected = path.resolve(value);
  const comparableReal = process.platform === "win32" ? real.toLowerCase() : real;
  const comparableExpected = process.platform === "win32" ? expected.toLowerCase() : expected;
  if (comparableReal !== comparableExpected) throw new Error("Codex working directory must not traverse symbolic links");
  return real;
}

function assertWorkingDirectoryBoundary(cwd, values) {
  const boundaries = [
    [values.journalDirectory, "runner journal"],
    [values.codexHome, "remote Codex home"],
    [path.dirname(values.privateKeyFile), "runner private-key state"],
    [values.threadIdFile, "runner thread state"]
  ];
  for (const [candidate, label] of boundaries) {
    if (pathsOverlap(cwd, candidate)) {
      throw new Error(`Codex working directory must not overlap ${label}`);
    }
  }
}

async function run(options) {
  const journalDirectory = ownerDirectory(options.journalDirectory);
  const cwd = validateCwd(options.cwd);
  const codexHome = ownerDirectory(options.codexHome);
  const privateKey = readPrivateKey(options.privateKeyFile);
  assertWorkingDirectoryBoundary(cwd, {
    ...options,
    journalDirectory,
    codexHome
  });
  const codexLaunch = prepareRemoteCodexLaunch(process.env, codexHome, [
    cwd,
    journalDirectory,
    path.dirname(options.privateKeyFile)
  ]);
  const releaseLock = acquireInstanceLock(journalDirectory);
  let adapter;
  let runner;
  let runnerStarted = false;
  try {
    const fleetProvider = createGateFleetProvider({ observerUrl: options.gateObserver });
    const threadRecord = new ThreadRecord({
      file: options.threadIdFile,
      runnerId: options.runnerId,
      caseId: options.caseId,
      cwd,
      codexHome
    });
    const activityStore = new ActivityStore();
    const createAdapter = () => new CodexCompanionAdapter({
      cwd,
      ephemeral: false,
      threadId: threadRecord.threadId,
      executionPosture: REMOTE_READ_ONLY_EXECUTION_POSTURE,
      codexHome,
      command: codexLaunch.command,
      environment: codexLaunch.environment,
      activityStore,
      beforeThreadCreate: () => threadRecord.begin(),
      afterThreadCreate: (threadId) => threadRecord.provisional(threadId),
      beforeFirstTurn: (threadId) => threadRecord.markUsed(threadId)
    });
    adapter = createAdapter();
    runner = new RemoteCockpitRunner({
      controlPlaneUrl: options.controlPlaneUrl,
      runnerId: options.runnerId,
      caseId: options.caseId,
      sessionRevision: options.sessionRevision,
      privateKey,
      journalDirectory,
      adapter,
      adapterFactory: createAdapter,
      fleetProvider
    });
    await adapter.connect();
    process.stdout.write("Remote cockpit runner connected to its dedicated Codex thread.\n");
    process.stdout.write("Keep this terminal open. Press Ctrl+C to stop cleanly.\n");

    let stopping = false;
    const stop = () => {
      if (stopping) return;
      stopping = true;
      void runner.stop();
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
    try {
      const running = runner.start();
      runnerStarted = true;
      await running;
      threadRecord.discardCleanProvisional(adapter.threadId);
    } finally {
      process.off("SIGINT", stop);
      process.off("SIGTERM", stop);
    }
  } finally {
    if (!runnerStarted && adapter) await adapter.close().catch(() => {});
    releaseLock();
  }
}

async function main() {
  let options;
  try {
    options = parseArguments(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.message}\n\n${usage()}`);
    process.exitCode = 2;
    return;
  }
  if (options.help) {
    process.stdout.write(usage());
    return;
  }
  process.stdout.write("GATE // Welcome, Giovanni.\n");
  try {
    await run(options);
  } catch {
    process.stderr.write("The remote cockpit runner stopped before it was ready. Check its private configuration and coordinator.\n");
    process.exitCode = 1;
  }
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) await main();

export const runnerCliInternals = Object.freeze({
  THREAD_RECORD_VERSION,
  REMOTE_TOOL_BOUNDARY_REVISION,
  ThreadRecord,
  acquireInstanceLock,
  assertWorkingDirectoryBoundary,
  parseArguments,
  pathsOverlap,
  prepareRemoteCodexLaunch,
  readPrivateKey,
  remoteCodexEnvironment,
  run,
  usage
});
