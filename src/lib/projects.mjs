import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { readJson, writeJsonAtomic } from "./config.mjs";
import { recordEvent } from "./events.mjs";
import { ensureRuntime, runtimePaths } from "./paths.mjs";
import { readPrivateFileBounded, securePrivateFile } from "./private-fs.mjs";
import { validateDocument } from "./schema.mjs";

const PROJECT_ID = /^[a-z][a-z0-9-]{1,62}$/u;
const MAX_PROJECT_BYTES = 128 * 1024;
const REMOTE_PROVIDERS = new Set(["github", "gitlab", "forgejo", "gitea"]);
const REGISTRY_LOCK = ".registry.lock";
const REGISTRY_PENDING = ".registry.pending";
const PROJECT_TEMPLATE_SENTINELS = Object.freeze({
  id: "replace-project",
  displayName: "Replace Project",
  repositoryIdentity: "remote:github.com/replace-owner/replace-project"
});
const waitBuffer = new Int32Array(new SharedArrayBuffer(4));

function registryPaths(options = {}) {
  const paths = options.paths || runtimePaths(options);
  if (paths.projects) return paths;
  if (!paths.home) throw new Error("project registry requires GATE_HOME");
  return { ...paths, projects: path.join(paths.home, "projects") };
}

function sleep(milliseconds) {
  Atomics.wait(waitBuffer, 0, 0, milliseconds);
}

function check(name, ok, detail) {
  return { name, ok: Boolean(ok), detail };
}

function projectId(value) {
  if (typeof value !== "string" || !PROJECT_ID.test(value)) {
    throw new Error("project id must start with a letter and contain only lowercase letters, numbers, or dashes");
  }
  return value;
}

function projectFile(paths, id) {
  return path.join(paths.projects, `${projectId(id)}.json`);
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function writeProjectAtomic(paths, id, value) {
  const destination = projectFile(paths, id);
  const staging = path.join(
    paths.home,
    `.project-${id}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.staging.json`
  );
  let renamed = false;
  let stagedStat;
  try {
    writeJsonAtomic(staging, stableValue(value), 0o600);
    securePrivateFile(staging, { allowMissing: false, label: `staged private project ${id}` });
    stagedStat = fs.lstatSync(staging);
    fs.renameSync(staging, destination);
    renamed = true;
    securePrivateFile(destination, { allowMissing: false, label: `private project ${id}` });
    const destinationStat = fs.lstatSync(destination);
    if (!sameIdentity(stagedStat, destinationStat)) {
      throw new Error(`private project ${id} changed during publication`);
    }
    fs.rmSync(staging, { force: true });
    return { file: destination, stat: destinationStat };
  } catch (error) {
    if (renamed) {
      try {
        rollbackProject(destination, stagedStat);
        renamed = false;
      } catch (rollbackError) {
        const failure = new Error(
          `project publication failed and exact destination rollback was blocked: ${rollbackError.message}`,
          { cause: error }
        );
        failure.preserveRegistryPending = true;
        throw failure;
      }
    }
    try {
      fs.rmSync(staging, { force: true });
    } catch (cleanupError) {
      throw new Error(`project publication failed and staging cleanup was blocked: ${cleanupError.message}`, { cause: error });
    }
    throw error;
  }
}

function rollbackProject(file, expected) {
  let current;
  try {
    current = fs.lstatSync(file);
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  if (!current.isFile() || current.isSymbolicLink() || current.nlink !== 1 || !sameIdentity(current, expected)) {
    throw new Error("new project changed before failed-audit rollback");
  }
  fs.unlinkSync(file);
}

function writePendingMarker(paths, transaction) {
  const file = path.join(paths.projects, REGISTRY_PENDING);
  let descriptor;
  try {
    descriptor = fs.openSync(file, "wx", 0o600);
    fs.writeFileSync(descriptor, `${JSON.stringify(transaction)}\n`, "utf8");
    fs.fsyncSync(descriptor);
    const stat = fs.fstatSync(descriptor);
    securePrivateFile(file, { allowMissing: false, label: "project registry pending marker" });
    const current = fs.lstatSync(file);
    if (!sameIdentity(stat, current)) throw new Error("project registry pending marker changed while it was created");
    return { file, stat: current };
  } catch (error) {
    if (error.code === "EEXIST") {
      throw new Error("project registry contains an incomplete transaction that requires operator reconciliation");
    }
    throw error;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function removePendingMarker(marker) {
  rollbackProject(marker.file, marker.stat);
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
}

function canonicalText(value) {
  return `${JSON.stringify(stableValue(value), null, 2)}\n`;
}

function canonicalDigest(canonical) {
  return crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}

function normalizedForStorage(value, identity) {
  const normalized = stableValue(value);
  if (normalized.repository.provider === "local") {
    const prefix = "local:";
    if (typeof identity !== "string" || !identity.startsWith(prefix)) {
      throw new Error("local repository identity could not be established");
    }
    normalized.repository.url = pathToFileURL(identity.slice(prefix.length)).href;
  }
  return normalized;
}

function unchangedFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function readBounded(descriptor, maximumBytes) {
  const chunks = [];
  let total = 0;
  while (total <= maximumBytes) {
    const buffer = Buffer.allocUnsafe(Math.min(64 * 1024, maximumBytes + 1 - total));
    const bytesRead = fs.readSync(descriptor, buffer, 0, buffer.length, null);
    if (bytesRead === 0) break;
    chunks.push(buffer.subarray(0, bytesRead));
    total += bytesRead;
  }
  if (total > maximumBytes) return null;
  return Buffer.concat(chunks, total);
}

function readBoundedSource(file) {
  const source = path.resolve(file);
  const before = fs.lstatSync(source, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new Error("project source must be a regular non-symlink file");
  }
  if (before.size > BigInt(MAX_PROJECT_BYTES)) {
    throw new Error(`project source exceeds the ${MAX_PROJECT_BYTES}-byte limit`);
  }
  if (process.platform !== "win32" && !fs.constants.O_NOFOLLOW) {
    throw new Error("project source cannot be opened without following links on this platform");
  }
  const flags = fs.constants.O_RDONLY |
    (fs.constants.O_NONBLOCK || 0) |
    (process.platform === "win32" ? 0 : fs.constants.O_NOFOLLOW);
  let descriptor;
  try {
    descriptor = fs.openSync(source, flags);
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!opened.isFile() || !unchangedFile(before, opened)) {
      throw new Error("project source changed while it was being opened");
    }
    const content = readBounded(descriptor, MAX_PROJECT_BYTES);
    if (!content) {
      throw new Error(`project source exceeds the ${MAX_PROJECT_BYTES}-byte limit`);
    }
    const afterRead = fs.fstatSync(descriptor, { bigint: true });
    const afterPath = fs.lstatSync(source, { bigint: true });
    if (
      !afterPath.isFile() || afterPath.isSymbolicLink() ||
      !unchangedFile(opened, afterRead) || !unchangedFile(afterRead, afterPath) ||
      BigInt(content.length) !== afterRead.size
    ) {
      throw new Error("project source changed while it was being read");
    }
    return content.toString("utf8");
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function parseProjectSource(file) {
  let value;
  try {
    value = JSON.parse(readBoundedSource(file));
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error(`project source is not valid JSON: ${error.message}`);
    throw error;
  }
  return value;
}

function normalizedRemoteRepository(repository) {
  const raw = repository.url;
  if (/[\\\u0000\r\n]/u.test(raw) || raw.includes("?") || raw.includes("#")) {
    throw new Error("remote repository URL must not contain backslashes, control characters, a query, or a fragment");
  }
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error("remote repository URL must be a valid HTTPS URL");
  }
  if (parsed.protocol !== "https:") throw new Error("remote repository URL must use HTTPS");
  if (parsed.username || parsed.password) throw new Error("remote repository URL must not contain credentials");
  if (!parsed.hostname) throw new Error("remote repository URL must include a hostname");
  const hostname = parsed.hostname.toLowerCase();
  const hostedProvider = new Map([["github.com", "github"], ["gitlab.com", "gitlab"]]).get(hostname);
  if (hostedProvider && repository.provider !== hostedProvider) {
    throw new Error(`${hostname} projects must use the ${hostedProvider} provider`);
  }
  if (repository.provider === "github" && hostname !== "github.com") {
    throw new Error("GitHub projects must use a github.com repository URL");
  }
  let segments;
  try {
    segments = parsed.pathname.split("/").filter(Boolean).map((segment) => decodeURIComponent(segment));
  } catch {
    throw new Error("remote repository URL contains invalid path encoding");
  }
  if (segments.length < 2) throw new Error("remote repository URL must identify an owner and repository");
  if (repository.provider === "github" && segments.length !== 2) {
    throw new Error("GitHub repository URL must contain exactly an owner and repository path");
  }
  if (new Set(["gitea", "forgejo"]).has(repository.provider) && segments.length !== 2) {
    throw new Error(`${repository.provider} repository URL must contain exactly an owner and repository path`);
  }
  if (repository.provider === "gitlab" && segments.includes("-")) {
    throw new Error("GitLab repository URL must not contain a web-view route");
  }
  if (segments.some((segment) => !segment || segment === "." || segment === ".." || /[\/\\\u0000\r\n]/u.test(segment))) {
    throw new Error("remote repository URL contains an unsafe path segment");
  }
  const last = segments.at(-1).replace(/\.git$/iu, "");
  if (!last) throw new Error("remote repository URL must identify a repository");
  segments[segments.length - 1] = last;
  // Supported hosted forges treat repository paths case-insensitively for
  // identity and redirects. Normalize all of them so provider and path casing
  // cannot register the same physical repository twice.
  segments = segments.map((segment) => segment.toLowerCase());
  return `remote:${hostname}${parsed.port ? `:${parsed.port}` : ""}/${segments.join("/")}`;
}

function normalizedLocalRepository(repository) {
  const raw = repository.url;
  if (/[\u0000\r\n]/u.test(raw) || raw.includes("?") || raw.includes("#")) {
    throw new Error("local repository URL must not contain control characters, a query, or a fragment");
  }
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error("local repository URL must be an absolute file URL");
  }
  if (parsed.protocol !== "file:" || parsed.username || parsed.password) {
    throw new Error("local repository URL must be an absolute file URL without credentials");
  }
  if (parsed.hostname) throw new Error("local repository URL must not use a remote file host");
  let localPath;
  try {
    localPath = path.resolve(fileURLToPath(parsed));
  } catch {
    throw new Error("local repository URL contains an invalid path");
  }
  if (localPath === path.parse(localPath).root) throw new Error("local repository URL must identify a repository directory");
  let localStat;
  try {
    localPath = fs.realpathSync.native ? fs.realpathSync.native(localPath) : fs.realpathSync(localPath);
    localStat = fs.statSync(localPath);
  } catch (error) {
    if (error.code === "ENOENT") throw new Error("local repository path must exist before registration");
    throw new Error("local repository path could not be canonicalized");
  }
  if (!localStat.isDirectory()) throw new Error("local repository path must be a directory");
  if (process.platform === "win32") localPath = localPath.toLowerCase();
  return `local:${localPath}`;
}

function repositoryIdentity(project) {
  const repository = project.repository;
  if (repository.provider === "local") return normalizedLocalRepository(repository);
  if (!REMOTE_PROVIDERS.has(repository.provider)) throw new Error(`unsupported repository provider: ${repository.provider}`);
  return normalizedRemoteRepository(repository);
}

function validBranchName(value) {
  if (typeof value !== "string" || !value || value === "@" || value.startsWith("/") || value.endsWith("/") || value.endsWith(".")) {
    return false;
  }
  if (value.includes("//") || value.includes("..") || value.includes("@{")) return false;
  return value.split("/").every((component) => component && !component.startsWith(".") && !component.endsWith(".lock"));
}

function profileCheck(paths, id, label) {
  const file = path.join(paths.repo, "config", "profiles", `${id}.json`);
  if (!fs.existsSync(file)) return check(label, false, `unknown profile: ${id}`);
  try {
    const profile = readJson(file);
    return check(label, profile?.id === id, profile?.id === id ? id : `profile identity mismatch: ${id}`);
  } catch {
    return check(label, false, `profile is unreadable: ${id}`);
  }
}

function verifyValue(value, paths, expectedId = null) {
  const schema = validateDocument(value, "project.schema.json", { paths });
  const checks = [check("schema", schema.ok, schema.ok ? "project.schema.json" : schema.errors.join("; "))];
  let identity = null;
  if (schema.ok) {
    checks.push(check(
      "template-metadata-id",
      value.metadata.id !== PROJECT_TEMPLATE_SENTINELS.id,
      value.metadata.id === PROJECT_TEMPLATE_SENTINELS.id
        ? "replace the project template metadata.id before registration"
        : "project id differs from the template sentinel"
    ));
    checks.push(check(
      "template-display-name",
      value.metadata.displayName !== PROJECT_TEMPLATE_SENTINELS.displayName,
      value.metadata.displayName === PROJECT_TEMPLATE_SENTINELS.displayName
        ? "replace the project template metadata.displayName before registration"
        : "project display name differs from the template sentinel"
    ));
    checks.push(check(
      "identity",
      expectedId === null || value.metadata.id === expectedId,
      expectedId === null || value.metadata.id === expectedId
        ? value.metadata.id
        : `project id ${value.metadata.id} does not match registry entry ${expectedId}`
    ));
    try {
      identity = repositoryIdentity(value);
      checks.push(check("repository", true, "canonical repository identity established"));
      checks.push(check(
        "template-repository-url",
        identity !== PROJECT_TEMPLATE_SENTINELS.repositoryIdentity,
        identity === PROJECT_TEMPLATE_SENTINELS.repositoryIdentity
          ? "replace the project template repository.url before registration"
          : "project repository differs from the template sentinel"
      ));
    } catch (error) {
      checks.push(check("repository", false, error.message));
    }
    checks.push(check(
      "default-branch",
      validBranchName(value.repository.defaultBranch),
      validBranchName(value.repository.defaultBranch) ? value.repository.defaultBranch : "default branch is not a valid Git branch name"
    ));
    checks.push(profileCheck(paths, value.execution.profile, "execution-profile"));
    checks.push(profileCheck(paths, value.security.profile, "security-profile"));
  }
  return { ok: checks.every((item) => item.ok), checks, identity };
}

function projectSummary(value, verification) {
  return {
    id: value.metadata.id,
    displayName: value.metadata.displayName,
    status: verification.ok ? "ready" : "invalid",
    repository: {
      provider: value.repository.provider,
      defaultBranch: value.repository.defaultBranch
    },
    execution: {
      profile: value.execution.profile,
      environment: value.execution.environment,
      workspaceProvider: value.execution.workspaceProvider,
      primaryHarness: value.execution.primaryHarness
    },
    delivery: {
      mode: value.delivery.mode,
      autoMerge: value.delivery.autoMerge,
      deploymentEnabled: value.delivery.deployment.enabled
    },
    security: {
      profile: value.security.profile,
      activeTestingEnabled: value.security.activeTestingEnabled,
      requireEngagementReceipt: value.security.requireEngagementReceipt
    }
  };
}

function loadEntry(paths, id) {
  const cleanId = projectId(id);
  const file = projectFile(paths, cleanId);
  const value = JSON.parse(readPrivateFileBounded(file, MAX_PROJECT_BYTES, "utf8", { label: `private project ${cleanId}` }));
  const verification = verifyValue(value, paths, cleanId);
  if (verification.ok && value.repository.provider === "local") {
    const stableLocator = canonicalText(normalizedForStorage(value, verification.identity)) === canonicalText(value);
    verification.checks.push(check(
      "repository-locator",
      stableLocator,
      stableLocator
        ? "local repository locator resolves to its registered physical path"
        : "local repository locator no longer resolves to its registered physical path"
    ));
    verification.ok = verification.ok && stableLocator;
  }
  return { file, value, verification };
}

function projectEntries(paths) {
  return fs.readdirSync(paths.projects)
    .filter((name) => name !== REGISTRY_LOCK && name !== REGISTRY_PENDING)
    .sort((left, right) => left.localeCompare(right));
}

function registryControlPresent(paths, name) {
  const file = path.join(paths.projects, name);
  try {
    return securePrivateFile(file, { label: `project registry control file ${name}` });
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

function registryUnavailable(paths) {
  return registryControlPresent(paths, REGISTRY_LOCK) || registryControlPresent(paths, REGISTRY_PENDING);
}

function unavailableVerification(id) {
  return {
    ok: false,
    id,
    status: "invalid",
    project: null,
    checks: [check("registry-transaction", false, "project registry has an active or incomplete transaction")]
  };
}

function lockOwner() {
  return {
    pid: process.pid,
    nonce: crypto.randomBytes(16).toString("hex"),
    createdAt: new Date().toISOString()
  };
}

function registrationTransaction(id, owner, contractSha256) {
  return {
    apiVersion: "gate.project-registration/v1",
    kind: "ProjectRegistrationPending",
    projectId: id,
    transactionNonce: owner.nonce,
    contractSha256,
    eventId: `evt_project_${owner.nonce}`,
    pid: owner.pid,
    createdAt: owner.createdAt
  };
}

function transactionEvidenceRef(transaction) {
  return `evidence://project-registration/${transaction.transactionNonce}/${transaction.contractSha256}`;
}

function auditMatchesTransaction(event, transaction) {
  const targetRef = `private://projects/${transaction.projectId}.json`;
  return event?.id === transaction.eventId &&
    event.kind === "project.registered" &&
    event.effect?.targetRef === targetRef &&
    Array.isArray(event.evidenceRefs) &&
    event.evidenceRefs.includes(targetRef) &&
    event.evidenceRefs.includes(transactionEvidenceRef(transaction));
}

function withRegistryLock(paths, action, options = {}) {
  const lockFile = path.join(paths.projects, REGISTRY_LOCK);
  const owner = lockOwner();
  const timeoutMs = options.timeoutMs ?? 5_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
    throw new Error("project registry lock timeout must be a positive safe integer");
  }
  const deadline = Date.now() + timeoutMs;
  let descriptor;
  let descriptorStat;
  while (descriptor === undefined) {
    try {
      descriptor = fs.openSync(lockFile, "wx", 0o600);
      fs.writeFileSync(descriptor, `${JSON.stringify(owner)}\n`, "utf8");
      fs.fsyncSync(descriptor);
      descriptorStat = fs.fstatSync(descriptor);
    } catch (error) {
      if (descriptor !== undefined) {
        fs.closeSync(descriptor);
        descriptor = undefined;
        fs.rmSync(lockFile, { force: true });
      }
      if (error.code !== "EEXIST") throw error;
      try {
        const present = fs.lstatSync(lockFile);
        if (!present.isFile() || present.isSymbolicLink()) throw new Error("project registry lock must be a regular file");
      } catch (lockError) {
        if (lockError.code !== "ENOENT") throw lockError;
        continue;
      }
      if (Date.now() >= deadline) {
        throw new Error("timed out waiting for the project registry lock; verify no registration process is active before removing the lock");
      }
      sleep(Math.min(20, Math.max(1, deadline - Date.now())));
    }
  }
  try {
    return action(owner);
  } finally {
    fs.closeSync(descriptor);
    try {
      const finalStat = fs.lstatSync(lockFile);
      if (descriptorStat && finalStat.dev === descriptorStat.dev && finalStat.ino === descriptorStat.ino) fs.unlinkSync(lockFile);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
}

export function registerProject(sourceFile, options = {}) {
  const paths = registryPaths(options);
  ensureRuntime(paths);
  const value = parseProjectSource(sourceFile);
  const verification = verifyValue(value, paths);
  if (!verification.ok) {
    throw new Error(`project validation failed: ${verification.checks.filter((item) => !item.ok).map((item) => item.detail).join("; ")}`);
  }
  const storedValue = normalizedForStorage(value, verification.identity);
  const storedVerification = verifyValue(storedValue, paths);
  if (!storedVerification.ok) throw new Error("normalized project contract failed verification");
  const id = projectId(storedValue.metadata.id);
  const canonical = canonicalText(storedValue);
  const canonicalBytes = Buffer.byteLength(canonical, "utf8");
  if (canonicalBytes > MAX_PROJECT_BYTES) {
    throw new Error(`canonical project contract exceeds the ${MAX_PROJECT_BYTES}-byte limit`);
  }
  const contractSha256 = canonicalDigest(canonical);
  const eventRecorder = options.eventRecorder || recordEvent;
  if (typeof eventRecorder !== "function") throw new Error("project event recorder must be a function");
  const outcome = withRegistryLock(paths, (owner) => {
    if (registryControlPresent(paths, REGISTRY_PENDING)) {
      throw new Error(
        "project registry contains an incomplete transaction; reconcile its project and project.registered event before removing the pending marker"
      );
    }
    for (const entry of projectEntries(paths)) {
      if (!entry.endsWith(".json")) throw new Error(`project registry contains an unexpected entry: ${entry}`);
      const entryId = entry.slice(0, -".json".length);
      if (!PROJECT_ID.test(entryId)) throw new Error(`project registry contains an invalid entry name: ${entry}`);
      let current;
      try {
        current = loadEntry(paths, entryId);
      } catch {
        throw new Error(`project registry contains an unreadable entry: ${entryId}`);
      }
      if (!current.verification.ok) throw new Error(`project registry contains an invalid entry: ${entryId}`);
      if (entryId === id) {
        if (canonicalText(current.value) !== canonical) {
          throw new Error(`project already exists with different content: ${id}`);
        }
        return { created: false, project: current.value, verification: current.verification };
      }
      if (current.verification.identity === storedVerification.identity) {
        throw new Error(`repository is already registered as project ${entryId}`);
      }
    }
    const transaction = registrationTransaction(id, owner, contractSha256);
    const marker = writePendingMarker(paths, transaction);
    let stored;
    try {
      stored = writeProjectAtomic(paths, id, storedValue);
    } catch (error) {
      if (error.preserveRegistryPending === true) throw error;
      try {
        removePendingMarker(marker);
      } catch (cleanupError) {
        throw new Error(`project write failed and pending-marker cleanup was blocked: ${cleanupError.message}`, { cause: error });
      }
      throw error;
    }
    try {
      const event = eventRecorder({
        id: transaction.eventId,
        kind: "project.registered",
        component: "gate-projects",
        summary: `Project ${id} registered.`,
        effect: { class: "host-write", targetRef: `private://projects/${id}.json` },
        evidenceRefs: [
          `private://projects/${id}.json`,
          transactionEvidenceRef(transaction)
        ]
      }, { paths });
      if (!auditMatchesTransaction(event, transaction)) {
        throw new Error("event recorder did not return the transaction-bound project registration event");
      }
    } catch (error) {
      // An append error is ambiguous: the complete event may already have
      // reached the file before fsync/close reported failure. Keep both the
      // exact contract and transaction-bound marker so recovery can prove
      // whether the expected event exists without risking an orphaned event.
      throw new Error(
        `project registration audit outcome is uncertain; the contract and pending marker were preserved: ${error.message}`,
        { cause: error }
      );
    }
    try {
      removePendingMarker(marker);
    } catch (error) {
      throw new Error(`project was registered and audited but its pending marker could not be cleared: ${error.message}`, { cause: error });
    }
    return { created: true, project: storedValue, verification: verifyValue(storedValue, paths, id) };
  }, options.lock);
  return {
    created: outcome.created,
    project: projectSummary(outcome.project, outcome.verification),
    checks: outcome.verification.checks
  };
}

export function showProject(id, options = {}) {
  const paths = registryPaths(options);
  ensureRuntime(paths);
  if (registryUnavailable(paths)) throw new Error("project registry has an active or incomplete transaction");
  const { value, verification } = loadEntry(paths, id);
  if (registryUnavailable(paths)) throw new Error("project registry has an active or incomplete transaction");
  if (!verification.ok) {
    throw new Error(`project validation failed: ${verification.checks.filter((item) => !item.ok).map((item) => item.detail).join("; ")}`);
  }
  return value;
}

export function projectContractBinding(id, options = {}) {
  const paths = registryPaths(options);
  ensureRuntime(paths);
  const cleanId = projectId(id);
  if (registryUnavailable(paths)) throw new Error("project registry has an active or incomplete transaction");
  const { value, verification } = loadEntry(paths, cleanId);
  if (registryUnavailable(paths)) throw new Error("project registry has an active or incomplete transaction");
  if (!verification.ok) {
    throw new Error(`project validation failed: ${verification.checks.filter((item) => !item.ok).map((item) => item.detail).join("; ")}`);
  }
  return {
    id: cleanId,
    contractSha256: canonicalDigest(canonicalText(value))
  };
}

export function verifyProject(id, options = {}) {
  const paths = registryPaths(options);
  ensureRuntime(paths);
  const cleanId = projectId(id);
  if (registryUnavailable(paths)) return unavailableVerification(cleanId);
  const result = verifyRegisteredEntry(paths, cleanId);
  return registryUnavailable(paths) ? unavailableVerification(cleanId) : result;
}

function verifyRegisteredEntry(paths, id) {
  const cleanId = projectId(id);
  try {
    const { value, verification } = loadEntry(paths, cleanId);
    return {
      ok: verification.ok,
      id: cleanId,
      status: verification.ok ? "ready" : "invalid",
      project: verification.ok ? projectSummary(value, verification) : null,
      checks: verification.checks
    };
  } catch (error) {
    return {
      ok: false,
      id: cleanId,
      status: "invalid",
      project: null,
      checks: [check("registry-entry", false, error.code === "ENOENT" ? "project is not registered" : error.message)]
    };
  }
}

export function listProjects(options = {}) {
  const paths = registryPaths(options);
  ensureRuntime(paths);
  const unavailableBefore = registryUnavailable(paths);
  const entries = projectEntries(paths).map((entry) => {
    if (!entry.endsWith(".json")) {
      return { id: null, entry, status: "invalid", project: null, checks: [check("entry-name", false, "unexpected project registry entry")] };
    }
    const entryId = entry.slice(0, -".json".length);
    if (!PROJECT_ID.test(entryId)) {
      return { id: null, entry, status: "invalid", project: null, checks: [check("entry-name", false, "invalid project registry entry name")] };
    }
    return verifyRegisteredEntry(paths, entryId);
  });
  if (!unavailableBefore && !registryUnavailable(paths)) return entries;
  if (!entries.length) {
    return [{ id: null, entry: "registry-transaction", ...unavailableVerification(null) }];
  }
  return entries.map((entry) => ({
    ...unavailableVerification(entry.id),
    entry: entry.entry || entry.id || "registry-transaction"
  }));
}

/** A contract-only status view. Repository URLs and deployment destinations never enter general status. */
export function projectRegistryStatus(options = {}) {
  return listProjects(options).map((entry) => {
    if (!entry.ok || !entry.project) {
      return { id: entry.id, registryEntry: entry.entry || entry.id, status: "invalid" };
    }
    return {
      id: entry.project.id,
      status: "ready",
      provider: entry.project.repository.provider,
      executionProfile: entry.project.execution.profile,
      environment: entry.project.execution.environment,
      deliveryMode: entry.project.delivery.mode,
      deploymentEnabled: entry.project.delivery.deploymentEnabled,
      securityProfile: entry.project.security.profile,
      activeTestingEnabled: entry.project.security.activeTestingEnabled
    };
  });
}
