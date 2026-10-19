import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { REMOTE_CODEX_APP_SERVER_VERSION } from "../../cockpit/companion/app-server.mjs";
import { createOidcVerifier } from "../../cockpit/remote/auth.mjs";
import { runnerCliInternals } from "../../cockpit/remote/runner-cli.mjs";
import { serverCliInternals } from "../../cockpit/remote/server-cli.mjs";
import { ensureRuntime } from "./paths.mjs";
import {
  securePrivateDirectory,
  syncPrivateDirectory,
  writePrivateFileExclusive
} from "./private-fs.mjs";

const REMOTE_CASE_VERSION = "gate.remote-case/v1";
const CASE_ID = /^[a-z][a-z0-9-]{1,62}$/u;
const RUNNER_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/u;
const HEADER_NAME = /^[a-z0-9][a-z0-9-]{0,126}$/u;
const MAX_MANIFEST_BYTES = 32 * 1024;
const EXPECTED_CODEX_VERSION = `codex-cli ${REMOTE_CODEX_APP_SERVER_VERSION}`;
const usesPosixPermissions = process.platform !== "win32";
const noFollow = fs.constants.O_NOFOLLOW || 0;
const nonBlocking = fs.constants.O_NONBLOCK || 0;

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, keys) {
  if (!record(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function boundedText(value, label, maximum = 2_048) {
  if (typeof value !== "string" || !value || value.length > maximum || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error(`${label} must be a non-empty bounded value without control characters`);
  }
  return value;
}

function exactHttpsOrigin(value, label = "remote origin") {
  const raw = boundedText(value, label);
  let parsed;
  try { parsed = new URL(raw); } catch { throw new Error(`${label} must be an exact HTTPS origin`); }
  if (parsed.protocol !== "https:" || parsed.origin !== raw || parsed.pathname !== "/" || parsed.search || parsed.hash
      || parsed.username || parsed.password || !parsed.hostname) {
    throw new Error(`${label} must be an exact HTTPS origin`);
  }
  return raw;
}

function httpsUrl(value, label, options = {}) {
  const raw = boundedText(value, label);
  let parsed;
  try { parsed = new URL(raw); } catch { throw new Error(`${label} must be an HTTPS URL`); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash || !parsed.hostname
      || (!options.allowQuery && parsed.search)) {
    throw new Error(`${label} must be an HTTPS URL without credentials${options.allowQuery ? "" : ", query, or fragment"}`);
  }
  return raw;
}

function positiveInteger(value, label, maximum) {
  const text = String(value);
  if (!/^[1-9][0-9]*$/u.test(text)) throw new Error(`${label} must be a positive integer`);
  const number = Number(text);
  if (!Number.isSafeInteger(number) || number > maximum) throw new Error(`${label} is outside its supported range`);
  return number;
}

function validateDirectory(value, label) {
  const resolved = path.resolve(boundedText(value, label, 8_192));
  let stat;
  try { stat = fs.lstatSync(resolved); } catch { throw new Error(`${label} is unavailable`); }
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`${label} must be a real directory`);
  let real;
  try { real = fs.realpathSync.native(resolved); } catch { throw new Error(`${label} is unavailable`); }
  const comparable = (candidate) => process.platform === "win32" ? candidate.toLowerCase() : candidate;
  if (comparable(real) !== comparable(resolved)) throw new Error(`${label} must not traverse symbolic links`);
  return resolved;
}

function validateObserverUrl(value) {
  const raw = boundedText(value, "observer URL");
  let parsed;
  try { parsed = new URL(raw); } catch { throw new Error("observer URL must be an exact loopback status URL"); }
  if (parsed.protocol !== "http:" || !new Set(["127.0.0.1", "[::1]"]).has(parsed.hostname)
      || parsed.pathname !== "/api/status" || parsed.search || parsed.hash || parsed.username || parsed.password) {
    throw new Error("observer URL must be an exact loopback /api/status URL");
  }
  return raw;
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", `'"'"'`)}'`;
}

function layout(paths, caseId) {
  const root = path.join(paths.home, "remote", caseId);
  const runner = path.join(root, "runner");
  const coordinator = path.join(root, "coordinator");
  return Object.freeze({
    root,
    manifest: path.join(root, "case.json"),
    runner,
    runnerPrivateKey: path.join(runner, "runner-private.pem"),
    runnerPublicKey: path.join(runner, "runner-public.pem"),
    runnerEnvironment: path.join(runner, "runner.env"),
    runnerCodexHome: path.join(runner, "codex-home"),
    runnerThreadRecord: path.join(runner, "codex-thread.json"),
    coordinator,
    coordinatorConfig: path.join(coordinator, "server.json"),
    coordinatorPublicKey: path.join(coordinator, "runner-public.pem")
  });
}

function runnerValues(manifest, locations) {
  return Object.freeze({
    controlPlaneUrl: manifest.origin,
    caseId: manifest.caseId,
    sessionRevision: manifest.sessionRevision,
    runnerId: manifest.runnerId,
    privateKeyFile: locations.runnerPrivateKey,
    journalDirectory: locations.runner,
    codexHome: locations.runnerCodexHome,
    threadIdFile: locations.runnerThreadRecord,
    cwd: manifest.repository,
    gateObserver: manifest.observerUrl
  });
}

function runnerEnvironment(values) {
  return Object.freeze({
    GATE_REMOTE_CONTROL_PLANE: values.controlPlaneUrl,
    GATE_REMOTE_CASE_ID: values.caseId,
    GATE_REMOTE_SESSION_REVISION: String(values.sessionRevision),
    GATE_REMOTE_RUNNER_ID: values.runnerId,
    GATE_REMOTE_PRIVATE_KEY_FILE: values.privateKeyFile,
    GATE_REMOTE_JOURNAL_DIR: values.journalDirectory,
    GATE_REMOTE_CODEX_HOME: values.codexHome,
    GATE_REMOTE_THREAD_ID_FILE: values.threadIdFile,
    GATE_REPO: values.cwd,
    GATE_OBSERVER_URL: values.gateObserver
  });
}

function renderRunnerEnvironment(values) {
  const environment = runnerEnvironment(values);
  return `${Object.entries(environment).map(([key, value]) => `${key}=${shellQuote(value)}`).join("\n")}\n`;
}

function coordinatorConfiguration(manifest, input) {
  return {
    apiVersion: serverCliInternals.CONFIG_VERSION,
    origin: manifest.origin,
    host: "127.0.0.1",
    port: input.port,
    operatorId: input.subject,
    caseId: manifest.caseId,
    sessionRevision: manifest.sessionRevision,
    databasePath: path.join(manifest.coordinatorStateRoot, "bridge.sqlite"),
    identityAssertionHeader: input.identityHeader,
    oidc: {
      issuer: input.issuer,
      audience: input.audience,
      operatorSubject: input.subject,
      jwksUrl: input.jwksUrl,
      clockSkewSeconds: 30,
      maxTokenLifetimeSeconds: 3_600,
      jwksCacheMs: 300_000,
      jwksTimeoutMs: 3_000
    },
    runner: {
      id: manifest.runnerId,
      publicKeyPath: path.join(manifest.coordinatorConfigRoot, "runner-public.pem")
    }
  };
}

function normalizeInput(input) {
  if (!record(input) || !CASE_ID.test(input.caseId || "")) {
    throw new Error("remote case id must start with a letter and contain only lowercase letters, numbers, or dashes");
  }
  const runnerId = input.runnerId === undefined ? `runner-${input.caseId}` : boundedText(input.runnerId, "runner id", 128);
  if (!RUNNER_ID.test(runnerId)) throw new Error("runner id is invalid");
  const identityHeader = input.identityHeader === undefined
    ? "x-gate-oidc-assertion"
    : boundedText(input.identityHeader, "identity assertion header", 127);
  if (!HEADER_NAME.test(identityHeader)) throw new Error("identity assertion header must be lowercase HTTP header syntax");
  const coordinatorConfigRoot = boundedText(input.coordinatorConfigRoot, "coordinator config root", 8_192);
  const coordinatorStateRoot = boundedText(input.coordinatorStateRoot, "coordinator state root", 8_192);
  for (const [value, label] of [
    [coordinatorConfigRoot, "coordinator config root"],
    [coordinatorStateRoot, "coordinator state root"]
  ]) {
    if (!path.isAbsolute(value) || path.normalize(value) !== value || value === path.parse(value).root) {
      throw new Error(`${label} must be an absolute normalized non-root path on the coordinator host`);
    }
  }
  if (pathsOverlap(coordinatorConfigRoot, coordinatorStateRoot)) {
    throw new Error("coordinator config root and state root must not overlap");
  }
  return Object.freeze({
    caseId: input.caseId,
    origin: exactHttpsOrigin(input.origin),
    issuer: httpsUrl(input.issuer, "OIDC issuer"),
    audience: boundedText(input.audience, "OIDC audience"),
    subject: boundedText(input.subject, "OIDC operator subject"),
    jwksUrl: httpsUrl(input.jwksUrl, "OIDC JWKS URL", { allowQuery: true }),
    repository: validateDirectory(input.repository, "case working directory"),
    observerUrl: validateObserverUrl(input.observerUrl || "http://127.0.0.1:4173/api/status"),
    coordinatorConfigRoot,
    coordinatorStateRoot,
    runnerId,
    sessionRevision: positiveInteger(input.sessionRevision ?? 1, "session revision", 2_147_483_647),
    port: positiveInteger(input.port ?? 43_180, "coordinator port", 65_535),
    identityHeader
  });
}

function writePrivateJson(file, value) {
  writePrivateFileExclusive(file, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8" });
}

function checkOwner(stat, label, type) {
  if (stat.isSymbolicLink() || (type === "file" ? !stat.isFile() : !stat.isDirectory())) {
    throw new Error(`${label} has the wrong filesystem type`);
  }
  if (type === "file" && stat.nlink !== 1) throw new Error(`${label} must not have multiple hard links`);
  if (usesPosixPermissions && typeof process.geteuid === "function" && stat.uid !== process.geteuid()) {
    throw new Error(`${label} is not owned by the current user`);
  }
  const expected = type === "file" ? 0o600 : 0o700;
  if (usesPosixPermissions && (stat.mode & 0o7777) !== expected) {
    throw new Error(`${label} permissions are not owner-only`);
  }
}

function inspectDirectory(directory, label) {
  let before;
  try { before = fs.lstatSync(directory); } catch { throw new Error(`${label} is unavailable`); }
  checkOwner(before, label, "directory");
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0) | noFollow);
  try {
    const opened = fs.fstatSync(descriptor);
    checkOwner(opened, label, "directory");
    if (before.dev !== opened.dev || before.ino !== opened.ino) throw new Error(`${label} changed while it was inspected`);
    const after = fs.lstatSync(directory);
    if (after.dev !== opened.dev || after.ino !== opened.ino) throw new Error(`${label} changed while it was inspected`);
  } finally {
    fs.closeSync(descriptor);
  }
}

function inspectFile(file, label) {
  let before;
  try { before = fs.lstatSync(file); } catch { throw new Error(`${label} is unavailable`); }
  checkOwner(before, label, "file");
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | nonBlocking | noFollow);
  try {
    const opened = fs.fstatSync(descriptor);
    checkOwner(opened, label, "file");
    if (before.dev !== opened.dev || before.ino !== opened.ino || before.size !== opened.size) {
      throw new Error(`${label} changed while it was inspected`);
    }
    const after = fs.lstatSync(file);
    if (after.dev !== opened.dev || after.ino !== opened.ino) throw new Error(`${label} changed while it was inspected`);
  } finally {
    fs.closeSync(descriptor);
  }
}

function readOwnerFile(file, maximumBytes, label) {
  let before;
  try { before = fs.lstatSync(file); } catch { throw new Error(`${label} is unavailable`); }
  checkOwner(before, label, "file");
  if (before.size < 1 || before.size > maximumBytes) throw new Error(`${label} has an invalid size`);
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | nonBlocking | noFollow);
  try {
    const opened = fs.fstatSync(descriptor);
    checkOwner(opened, label, "file");
    if (before.dev !== opened.dev || before.ino !== opened.ino || before.size !== opened.size) {
      throw new Error(`${label} changed while it was opened`);
    }
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== bytes.length
        || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) {
      throw new Error(`${label} changed while it was read`);
    }
    const final = fs.lstatSync(file);
    if (final.dev !== after.dev || final.ino !== after.ino) throw new Error(`${label} changed while it was verified`);
    return bytes;
  } finally {
    fs.closeSync(descriptor);
  }
}

function readManifest(file) {
  let value;
  try { value = JSON.parse(readOwnerFile(file, MAX_MANIFEST_BYTES, "remote case manifest").toString("utf8")); }
  catch (error) {
    if (error instanceof SyntaxError) throw new Error("remote case manifest is malformed");
    throw error;
  }
  if (!exactKeys(value, [
    "apiVersion", "caseId", "coordinatorConfigRoot", "coordinatorStateRoot", "createdAt", "observerUrl", "origin", "repository", "runnerId",
    "sessionRevision"
  ]) || value.apiVersion !== REMOTE_CASE_VERSION || !CASE_ID.test(value.caseId || "")
      || !RUNNER_ID.test(value.runnerId || "") || !Number.isFinite(Date.parse(value.createdAt))) {
    throw new Error("remote case manifest does not match the reviewed shape");
  }
  exactHttpsOrigin(value.origin);
  validateObserverUrl(value.observerUrl);
  positiveInteger(value.sessionRevision, "session revision", 2_147_483_647);
  for (const [candidate, label] of [
    [value.coordinatorConfigRoot, "config"],
    [value.coordinatorStateRoot, "state"]
  ]) {
    if (!path.isAbsolute(candidate) || path.normalize(candidate) !== candidate
        || candidate === path.parse(candidate).root) {
      throw new Error(`remote case manifest coordinator ${label} root is invalid`);
    }
  }
  if (pathsOverlap(value.coordinatorConfigRoot, value.coordinatorStateRoot)) {
    throw new Error("remote case manifest coordinator roots overlap");
  }
  if (!path.isAbsolute(value.repository) || path.normalize(value.repository) !== value.repository) {
    throw new Error("remote case manifest working directory is invalid");
  }
  return Object.freeze(value);
}

function removeNewTree(directory) {
  try { fs.rmSync(directory, { recursive: true, force: true }); } catch {}
}

function pathsOverlap(left, right) {
  const normalize = (value) => {
    const absolute = path.resolve(value);
    return process.platform === "win32" ? absolute.toLowerCase() : absolute;
  };
  const contains = (parent, candidate) => {
    const relative = path.relative(parent, candidate);
    return relative === "" || (!path.isAbsolute(relative) && relative !== ".."
      && !relative.startsWith(`..${path.sep}`));
  };
  const first = normalize(left);
  const second = normalize(right);
  return contains(first, second) || contains(second, first);
}

function assertWorkingDirectoryBoundary(repository, home, label = "case working directory") {
  const canonicalRepository = fs.realpathSync.native(repository);
  const canonicalHome = fs.realpathSync.native(home);
  if (pathsOverlap(canonicalRepository, canonicalHome)) {
    throw new Error(`${label} must not overlap GATE_HOME or private remote runner state`);
  }
  return canonicalRepository;
}

export function initializeRemoteCase(input, options = {}) {
  const values = normalizeInput(input);
  const paths = options.paths;
  ensureRuntime(paths);
  assertWorkingDirectoryBoundary(values.repository, paths.home);
  const remoteRoot = path.join(paths.home, "remote");
  securePrivateDirectory(remoteRoot);
  const locations = layout(paths, values.caseId);
  try {
    fs.lstatSync(locations.root);
    throw new Error(`remote case already exists: ${values.caseId}; run ./bin/gate.mjs remote doctor ${values.caseId}`);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }

  const staging = path.join(remoteRoot, `.init-${values.caseId}-${process.pid}-${crypto.randomBytes(8).toString("hex")}`);
  fs.mkdirSync(staging, { mode: 0o700 });
  securePrivateDirectory(staging, { create: false });
  const staged = Object.fromEntries(Object.entries(locations).map(([key, value]) => [
    key,
    key === "root" ? staging : path.join(staging, path.relative(locations.root, value))
  ]));
  let privatePem;
  try {
    for (const directory of [staged.runner, staged.runnerCodexHome, staged.coordinator]) {
      securePrivateDirectory(directory);
    }
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
    privatePem = Buffer.from(privateKey.export({ type: "pkcs8", format: "pem" }));
    const publicPem = Buffer.from(publicKey.export({ type: "spki", format: "pem" }));
    writePrivateFileExclusive(staged.runnerPrivateKey, privatePem);
    writePrivateFileExclusive(staged.runnerPublicKey, publicPem);
    writePrivateFileExclusive(staged.coordinatorPublicKey, publicPem);

    const manifest = {
      apiVersion: REMOTE_CASE_VERSION,
      caseId: values.caseId,
      createdAt: (options.now || (() => new Date().toISOString()))(),
      origin: values.origin,
      runnerId: values.runnerId,
      sessionRevision: values.sessionRevision,
      coordinatorConfigRoot: values.coordinatorConfigRoot,
      coordinatorStateRoot: values.coordinatorStateRoot,
      repository: values.repository,
      observerUrl: values.observerUrl
    };
    const remoteRunner = runnerValues(manifest, locations);
    writePrivateFileExclusive(staged.runnerEnvironment, renderRunnerEnvironment(remoteRunner), { encoding: "utf8" });
    writePrivateJson(staged.coordinatorConfig, coordinatorConfiguration(manifest, values));
    writePrivateJson(staged.manifest, manifest);
    syncPrivateDirectory(staged.runner);
    syncPrivateDirectory(staged.coordinator);
    syncPrivateDirectory(staging);
    try {
      (options.rename || fs.renameSync)(staging, locations.root);
    } catch (error) {
      if (new Set(["EEXIST", "ENOTEMPTY"]).has(error?.code)) {
        throw new Error(`remote case already exists: ${values.caseId}; run ./bin/gate.mjs remote doctor ${values.caseId}`, {
          cause: error
        });
      }
      throw error;
    }
    syncPrivateDirectory(remoteRoot);

    const fingerprint = crypto.createHash("sha256")
      .update(publicKey.export({ type: "spki", format: "der" }))
      .digest("hex");
    return Object.freeze({
      ok: true,
      caseId: values.caseId,
      stateDirectory: locations.root,
      runnerEnvironment: locations.runnerEnvironment,
      coordinatorConfig: locations.coordinatorConfig,
      coordinatorConfigRoot: values.coordinatorConfigRoot,
      coordinatorStateRoot: values.coordinatorStateRoot,
      coordinatorPublicKey: locations.coordinatorPublicKey,
      publicKeyFingerprint: `sha256:${fingerprint}`,
      next: `./bin/gate.mjs remote doctor ${values.caseId}`
    });
  } catch (error) {
    removeNewTree(staging);
    throw error;
  } finally {
    privatePem?.fill(0);
  }
}

function checkResult(id, description, inspect, options = {}) {
  try {
    inspect();
    return Object.freeze({ id, status: "passed", required: options.required !== false, description });
  } catch (error) {
    return Object.freeze({
      id,
      status: "failed",
      required: options.required !== false,
      description,
      problem: typeof options.failure === "string" ? options.failure : error.message
    });
  }
}

function unverifiedResult(id, description) {
  return Object.freeze({ id, status: "unverified", required: false, description });
}

function versionAtLeast(actual, required) {
  const left = String(actual).split(".").map(Number);
  const right = String(required).split(".").map(Number);
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    const difference = (left[index] || 0) - (right[index] || 0);
    if (difference !== 0) return difference > 0;
  }
  return true;
}

function runProbe(commandRunner, command, args, options) {
  try {
    return commandRunner(command, args, {
      cwd: options.cwd,
      env: options.env,
      encoding: "utf8",
      timeout: 5_000,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"]
    });
  } catch {
    return { status: null, error: { code: "probe-failed" }, stdout: "", stderr: "" };
  }
}

export function inspectRemoteCase(caseId, options = {}) {
  if (!CASE_ID.test(caseId || "")) throw new Error("remote case id is invalid");
  const paths = options.paths;
  const locations = layout(paths, caseId);
  const checks = [];
  let manifest;
  let configuration;
  let remoteRunner;
  let codexProbeLaunch;

  checks.push(checkResult("state-boundary", "Remote private state is outside the GATE repository.", () => {
    const home = fs.realpathSync.native(paths.home);
    const repo = fs.realpathSync.native(paths.repo);
    if (pathsOverlap(home, repo)) throw new Error("GATE_HOME and the repository overlap");
  }));
  checks.push(checkResult("private-layout", "Remote state directories are real, owner-only directories.", () => {
    for (const [directory, label] of [
      [paths.home, "GATE_HOME"],
      [path.dirname(locations.root), "remote state directory"],
      [locations.root, "remote case directory"],
      [locations.runner, "runner directory"],
      [locations.runnerCodexHome, "dedicated Codex home"],
      [locations.coordinator, "coordinator bundle directory"]
    ]) inspectDirectory(directory, label);
  }));
  checks.push(checkResult("case-manifest", "The private case manifest is valid and bound to this case.", () => {
    manifest = readManifest(locations.manifest);
    if (manifest.caseId !== caseId) throw new Error("remote case manifest case binding does not match");
  }));
  checks.push(checkResult("private-files", "Generated configuration and key files are owner-only regular files.", () => {
    for (const [file, maximum, label] of [
      [locations.manifest, MAX_MANIFEST_BYTES, "remote case manifest"],
      [locations.runnerPrivateKey, 16 * 1024, "runner private key"],
      [locations.runnerPublicKey, 16 * 1024, "runner public key"],
      [locations.runnerEnvironment, 32 * 1024, "runner environment"],
      [locations.coordinatorConfig, 32 * 1024, "coordinator configuration"],
      [locations.coordinatorPublicKey, 16 * 1024, "coordinator runner public key"]
    ]) {
      inspectFile(file, label);
      const stat = fs.statSync(file);
      if (stat.size < 1 || stat.size > maximum) throw new Error(`${label} has an invalid size`);
    }
  }));
  checks.push(checkResult("coordinator-config", "Coordinator configuration matches the reviewed server contract.", () => {
    if (!manifest) manifest = readManifest(locations.manifest);
    configuration = serverCliInternals.readConfiguration(locations.coordinatorConfig);
    if (configuration.caseId !== manifest.caseId || configuration.origin !== manifest.origin
        || configuration.runner.id !== manifest.runnerId || configuration.sessionRevision !== manifest.sessionRevision
        || configuration.databasePath !== path.join(manifest.coordinatorStateRoot, "bridge.sqlite")
        || configuration.runner.publicKeyPath !== path.join(manifest.coordinatorConfigRoot, "runner-public.pem")) {
      throw new Error("coordinator configuration no longer matches the case manifest");
    }
    exactHttpsOrigin(configuration.origin);
    httpsUrl(configuration.oidc.issuer, "OIDC issuer");
    httpsUrl(configuration.oidc.jwksUrl, "OIDC JWKS URL", { allowQuery: true });
    boundedText(configuration.oidc.audience, "OIDC audience");
    boundedText(configuration.oidc.operatorSubject, "OIDC operator subject");
    if (!HEADER_NAME.test(configuration.identityAssertionHeader || "")) {
      throw new Error("identity assertion header is invalid");
    }
    createOidcVerifier(configuration.oidc);
  }));
  checks.push(checkResult("runner-config", "Runner environment matches the reviewed case-bound configuration.", () => {
    if (!manifest) manifest = readManifest(locations.manifest);
    remoteRunner = runnerValues(manifest, locations);
    const actual = readOwnerFile(locations.runnerEnvironment, 32 * 1024, "runner environment");
    const expected = Buffer.from(renderRunnerEnvironment(remoteRunner));
    if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
      throw new Error("runner environment no longer matches the case manifest");
    }
    runnerCliInternals.parseArguments([], runnerEnvironment(remoteRunner));
  }));
  checks.push(checkResult("runner-keypair", "The laptop private key matches both enrolled Ed25519 public keys.", () => {
    const privateKey = runnerCliInternals.readPrivateKey(locations.runnerPrivateKey);
    const laptopPublic = crypto.createPublicKey(readOwnerFile(locations.runnerPublicKey, 16 * 1024, "runner public key"));
    const coordinatorPublic = serverCliInternals.loadRunnerPublicKey(locations.coordinatorPublicKey);
    const derived = crypto.createPublicKey(privateKey).export({ type: "spki", format: "der" });
    for (const publicKey of [laptopPublic, coordinatorPublic]) {
      const encoded = publicKey.export({ type: "spki", format: "der" });
      if (encoded.length !== derived.length || !crypto.timingSafeEqual(encoded, derived)) {
        throw new Error("runner public enrollment does not match the private key");
      }
    }
  }));
  checks.push(checkResult("case-working-directory", "The dedicated case working directory is available and unchanged.", () => {
    if (!manifest) manifest = readManifest(locations.manifest);
    const repository = validateDirectory(manifest.repository, "case working directory");
    if (repository !== manifest.repository) {
      throw new Error("case working directory changed after initialization");
    }
    assertWorkingDirectoryBoundary(repository, paths.home);
  }));
  checks.push(checkResult("node-runtime", "Node.js 22.20 or newer is available.", () => {
    const version = options.nodeVersion || process.versions.node;
    if (!versionAtLeast(version, "22.20.0")) throw new Error("Node.js 22.20 or newer is required");
  }));
  checks.push(checkResult("node-sqlite", "The coordinator runtime provides node:sqlite.", () => {
    const available = options.sqliteAvailable ?? Boolean(process.getBuiltinModule?.("node:sqlite")?.DatabaseSync);
    if (!available) throw new Error("node:sqlite is unavailable");
  }));

  const commandRunner = options.commandRunner || spawnSync;
  const resolveCodexLaunch = options.prepareCodexLaunch || runnerCliInternals.prepareRemoteCodexLaunch;
  const prepareCodexProbe = () => {
    if (!codexProbeLaunch) {
      codexProbeLaunch = resolveCodexLaunch(
        process.env,
        locations.runnerCodexHome,
        [paths.home, paths.repo]
      );
    }
    return codexProbeLaunch;
  };
  checks.push(checkResult("codex-version", `Codex CLI ${REMOTE_CODEX_APP_SERVER_VERSION} is installed for the runner.`, () => {
    if (!manifest) manifest = readManifest(locations.manifest);
    const launch = prepareCodexProbe();
    const result = runProbe(commandRunner, launch.command, ["--version"], {
      cwd: locations.runnerCodexHome,
      env: launch.environment
    });
    const firstLine = `${result.stdout || ""}\n${result.stderr || ""}`.trim().split(/\r?\n/u)[0];
    if (result.error || result.status !== 0 || firstLine !== EXPECTED_CODEX_VERSION) {
      throw new Error(`expected ${EXPECTED_CODEX_VERSION}`);
    }
  }, { failure: `Codex CLI must report exactly ${EXPECTED_CODEX_VERSION}` }));
  checks.push(checkResult("codex-login", "The dedicated remote Codex home has a working login.", () => {
    if (!manifest) manifest = readManifest(locations.manifest);
    const launch = prepareCodexProbe();
    const result = runProbe(commandRunner, launch.command, ["login", "status"], {
      cwd: locations.runnerCodexHome,
      env: launch.environment
    });
    if (result.error || result.status !== 0) throw new Error("dedicated Codex login is unavailable");
  }, { failure: "Run codex login with CODEX_HOME set to this case's dedicated Codex home" }));

  checks.push(
    unverifiedResult("identity-gateway", "External TLS, OIDC assertion injection, route splitting, and edge limits require host verification."),
    unverifiedResult("live-round-trip", "Queue durability, runner delivery, and cockpit event flow require an end-to-end deployment test.")
  );
  const failed = checks.filter((check) => check.required && check.status === "failed");
  return Object.freeze({
    ok: failed.length === 0,
    liveReady: false,
    caseId,
    checks,
    counts: {
      passed: checks.filter((check) => check.status === "passed").length,
      failed: checks.filter((check) => check.status === "failed").length,
      unverified: checks.filter((check) => check.status === "unverified").length
    },
    next: failed.length
      ? "Resolve failed local checks and rerun doctor."
      : "Install only coordinator/server.json and coordinator/runner-public.pem under the recorded coordinator root, then verify host permissions, the identity gateway, and a live round trip."
  });
}

export const remoteSetupInternals = Object.freeze({
  CASE_ID,
  EXPECTED_CODEX_VERSION,
  REMOTE_CASE_VERSION,
  exactHttpsOrigin,
  layout,
  normalizeInput,
  pathsOverlap,
  readManifest,
  renderRunnerEnvironment,
  runnerEnvironment,
  runnerValues,
  versionAtLeast
});
