import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const MAX_PACKAGE_BYTES = 64 * 1024;
const MAX_GIT_OUTPUT_BYTES = 128 * 1024;
const GIT_TIMEOUT_MS = 2_000;
const SEMVER_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u;
const COMMIT_PATTERN = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u;
const SOURCE_STATES = new Set(["clean", "modified", "unavailable"]);
const TRUSTED_GIT_CANDIDATES = process.platform === "win32" ? [] : ["/usr/bin/git", "/bin/git"];
const GIT_CONFIG_PROTECTIONS = [
  ["core.hooksPath", os.devNull],
  ["core.fsmonitor", "false"],
  ["core.useReplaceRefs", "false"],
  ["core.commitGraph", "false"],
  ["core.trustctime", "true"],
  ["core.checkStat", "default"],
  ["core.ignoreStat", "false"],
  ...(process.platform === "win32" ? [] : [
    ["core.fileMode", "true"],
    ["core.symlinks", "true"]
  ]),
  ["protocol.allow", "never"]
];

function boundedPackageJson(file) {
  let descriptor;
  try {
    const before = fs.lstatSync(file, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink() || before.size > BigInt(MAX_PACKAGE_BYTES)) return null;
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (
      !opened.isFile() || opened.size > BigInt(MAX_PACKAGE_BYTES) ||
      opened.dev !== before.dev || opened.ino !== before.ino
    ) return null;
    const body = Buffer.alloc(Number(opened.size));
    let offset = 0;
    while (offset < body.byteLength) {
      const read = fs.readSync(descriptor, body, offset, body.byteLength - offset, offset);
      if (read === 0) return null;
      offset += read;
    }
    if (fs.readSync(descriptor, Buffer.alloc(1), 0, 1, offset) !== 0) return null;
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (
      after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size ||
      after.mtimeNs !== opened.mtimeNs || after.ctimeNs !== opened.ctimeNs
    ) return null;
    const value = JSON.parse(body.toString("utf8"));
    return value && typeof value === "object" && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mode === right.mode && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function assertProtectedPath(file) {
  let current = file;
  while (true) {
    const stat = fs.lstatSync(current, { bigint: true });
    if (stat.isSymbolicLink()) throw new Error("trusted Git path contains a symbolic link");
    if (typeof process.geteuid === "function") {
      const effectiveUser = process.geteuid();
      if (effectiveUser === 0 || stat.uid === BigInt(effectiveUser)) {
        throw new Error("trusted Git path is controlled by the current process identity");
      }
    }
    try {
      fs.accessSync(current, fs.constants.W_OK);
    } catch (error) {
      if (!new Set(["EACCES", "EPERM", "EROFS"]).has(error.code)) throw error;
      const parent = path.dirname(current);
      if (parent === current) return;
      current = parent;
      continue;
    }
    throw new Error("trusted Git path is writable by the current process identity");
  }
}

function observeTrustedGit(file) {
  const resolved = fs.realpathSync.native ? fs.realpathSync.native(file) : fs.realpathSync(file);
  const before = fs.lstatSync(resolved, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || (before.mode & 0o111n) === 0n) {
    throw new Error("trusted Git is not a regular executable");
  }
  assertProtectedPath(resolved);
  if (!fs.constants.O_NOFOLLOW) throw new Error("trusted Git cannot be opened without following links");
  const descriptor = fs.openSync(resolved, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    const after = fs.lstatSync(resolved, { bigint: true });
    if (!opened.isFile() || !sameFileIdentity(before, opened) || !sameFileIdentity(opened, after)) {
      throw new Error("trusted Git changed while it was inspected");
    }
    return Object.freeze({ path: resolved, identity: opened });
  } finally {
    fs.closeSync(descriptor);
  }
}

function resolveTrustedGit() {
  for (const candidate of TRUSTED_GIT_CANDIDATES) {
    try {
      return observeTrustedGit(candidate);
    } catch {
      // Try the next fixed system path and otherwise leave identity unavailable.
    }
  }
  return null;
}

function gitEnvironment(executable) {
  const safePath = [...new Set([path.dirname(executable), "/usr/bin", "/bin"])].join(path.delimiter);
  return {
    GIT_ALLOW_PROTOCOL: "",
    GCM_INTERACTIVE: "never",
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: os.devNull,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_NO_LAZY_FETCH: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0",
    HOME: "/",
    LANG: "C",
    LC_ALL: "C",
    NO_COLOR: "1",
    PATH: safePath,
    XDG_CONFIG_HOME: "/nonexistent"
  };
}

function runGit(repo, arguments_) {
  const runtime = resolveTrustedGit();
  if (!runtime) return null;
  const result = spawnSync(runtime.path, [
    "--no-replace-objects",
    "--no-optional-locks",
    ...GIT_CONFIG_PROTECTIONS.flatMap(([key, value]) => ["-c", `${key}=${value}`]),
    ...arguments_
  ], {
    cwd: repo,
    encoding: "utf8",
    env: gitEnvironment(runtime.path),
    maxBuffer: MAX_GIT_OUTPUT_BYTES,
    timeout: GIT_TIMEOUT_MS,
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true
  });
  let current;
  try {
    current = observeTrustedGit(runtime.path);
  } catch {
    return null;
  }
  if (current.path !== runtime.path || !sameFileIdentity(runtime.identity, current.identity)) return null;
  if (result.error || result.signal || result.status !== 0 || typeof result.stdout !== "string") return null;
  return result.stdout;
}

function hiddenIndexState(output) {
  return output.split("\0").filter(Boolean).some((entry) => !entry.startsWith("H "))
    ? "modified"
    : "clean";
}

function packageVersion(value) {
  return typeof value === "string" && value.length <= 128 && SEMVER_PATTERN.test(value) ? value : null;
}

function commitIdentity(value) {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  return COMMIT_PATTERN.test(normalized) ? normalized : null;
}

export function normalizeBuildIdentity(value) {
  const input = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const version = packageVersion(input.version);
  const commit = commitIdentity(input.commit);
  const state = commit && SOURCE_STATES.has(input.state) ? input.state : "unavailable";
  return Object.freeze({
    version,
    commit,
    commitShort: commit ? commit.slice(0, 12) : null,
    state
  });
}

export function observeBuildIdentity(repo, options = {}) {
  const readPackage = options.readPackage || boundedPackageJson;
  const git = options.runGit || runGit;
  let manifest = null;
  try {
    manifest = readPackage(path.join(repo, "package.json"));
  } catch {
    manifest = null;
  }

  let version = null;
  try {
    version = manifest?.version;
  } catch {
    version = null;
  }

  let commit = null;
  try {
    commit = commitIdentity(git(repo, ["rev-parse", "--verify", "HEAD^{commit}"]));
  } catch {
    commit = null;
  }
  let state = "unavailable";
  if (commit) {
    try {
      const status = git(repo, [
        "status", "--porcelain=v1", "--untracked-files=normal", "--ignore-submodules=none"
      ]);
      const index = git(repo, ["ls-files", "-v", "-z"]);
      if (typeof status === "string" && typeof index === "string") {
        state = status.length === 0 && hiddenIndexState(index) === "clean" ? "clean" : "modified";
      }
    } catch {
      state = "unavailable";
    }
  }

  return normalizeBuildIdentity({ version, commit, state });
}
