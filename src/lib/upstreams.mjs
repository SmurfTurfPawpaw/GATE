import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { readJson, writeJsonAtomic } from "./config.mjs";
import { recordEvent } from "./events.mjs";
import { ensureRuntime, runtimePaths } from "./paths.mjs";
import { assertValidDocument } from "./schema.mjs";

function childDirectory(root, name) {
  const resolvedRoot = path.resolve(root);
  const directory = path.resolve(resolvedRoot, name);
  if (!directory.startsWith(`${resolvedRoot}${path.sep}`)) throw new Error(`upstream path escapes its private root: ${name}`);
  return directory;
}

export function readUpstreamLock(options = {}) {
  const paths = options.paths || runtimePaths(options);
  const lock = readJson(path.join(paths.repo, "locks", "upstreams.lock.json"));
  assertValidDocument(lock, "upstream-lock.schema.json", { paths });
  const ids = lock.upstreams.map((entry) => entry.id);
  if (new Set(ids).size !== ids.length) throw new Error("upstream lock contains duplicate ids");
  return { paths, lock };
}

function realPath(file) {
  return fs.realpathSync.native ? fs.realpathSync.native(file) : fs.realpathSync(file);
}

function sameOrDescendant(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mode === right.mode && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function assertNotControlledByCurrentProcess(file, stat, label) {
  if (process.platform !== "win32" && typeof process.geteuid === "function") {
    const euid = process.geteuid();
    if (euid === 0 || stat.uid === BigInt(euid)) {
      throw new Error(`${label} is owned by the current process identity: ${file}`);
    }
  }
  try {
    fs.accessSync(file, fs.constants.W_OK);
  } catch (error) {
    if (new Set(["EACCES", "EPERM", "EROFS"]).has(error.code)) return;
    throw error;
  }
  throw new Error(`${label} is writable by the current process: ${file}`);
}

function assertProtectedPathChain(file, label) {
  let current = realPath(file);
  while (true) {
    const stat = fs.lstatSync(current, { bigint: true });
    if (stat.isSymbolicLink()) throw new Error(`${label} path chain contains a symbolic link: ${current}`);
    assertNotControlledByCurrentProcess(current, stat, label);
    const parent = path.dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

function assertProtectedRuntimePlatform() {
  if (process.platform === "win32") {
    throw new Error("protected upstream execution is unavailable on native Windows; run GATE inside WSL");
  }
}

function observeTrustedRegularFile(file, label, options = {}) {
  const resolved = realPath(file);
  const before = fs.lstatSync(resolved, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) throw new Error(`${label} is not a regular file`);
  if (options.executable && process.platform !== "win32" && (before.mode & 0o111n) === 0n) {
    throw new Error(`${label} is not executable`);
  }
  if (!hasLockedSystemPath(resolved)) throw new Error(`${label} is reachable through a group- or other-writable path`);
  if (options.protectedFromCurrentProcess) assertProtectedPathChain(resolved, label);
  if (process.platform !== "win32" && !fs.constants.O_NOFOLLOW) {
    throw new Error(`${label} cannot be opened without following links on this platform`);
  }
  const descriptor = fs.openSync(resolved, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    const after = fs.lstatSync(resolved, { bigint: true });
    if (!opened.isFile() || !sameFileIdentity(before, opened) || !sameFileIdentity(opened, after)) {
      throw new Error(`${label} changed while its identity was checked`);
    }
    return { path: resolved, identity: opened };
  } finally {
    fs.closeSync(descriptor);
  }
}

const MAX_NPM_IMPLEMENTATION_ENTRIES = 20_000;
const MAX_NPM_IMPLEMENTATION_BYTES = 512 * 1024 * 1024;

function observeProtectedTree(root, label) {
  const resolvedRoot = realPath(root);
  const rootStat = fs.lstatSync(resolvedRoot, { bigint: true });
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw new Error(`${label} is not a regular directory tree`);
  assertProtectedPathChain(resolvedRoot, label);
  const hash = crypto.createHash("sha256");
  let entries = 0;
  let bytes = 0;
  const visit = (directory, relativeDirectory = "") => {
    const children = fs.readdirSync(directory, { withFileTypes: true })
      .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
    for (const child of children) {
      entries += 1;
      if (entries > MAX_NPM_IMPLEMENTATION_ENTRIES) throw new Error(`${label} has too many entries`);
      const absolute = path.join(directory, child.name);
      const relative = relativeDirectory ? `${relativeDirectory}/${child.name}` : child.name;
      const before = fs.lstatSync(absolute, { bigint: true });
      if (before.isSymbolicLink()) throw new Error(`${label} contains a symbolic link: ${relative}`);
      assertNotControlledByCurrentProcess(absolute, before, label);
      if (before.isDirectory()) {
        hash.update(`dir\0${relative}\0${before.mode}\0`);
        visit(absolute, relative);
        const after = fs.lstatSync(absolute, { bigint: true });
        if (!sameFileIdentity(before, after)) throw new Error(`${label} changed while it was hashed: ${relative}`);
        continue;
      }
      if (!before.isFile()) throw new Error(`${label} contains an unsupported file type: ${relative}`);
      bytes += Number(before.size);
      if (!Number.isSafeInteger(bytes) || bytes > MAX_NPM_IMPLEMENTATION_BYTES) {
        throw new Error(`${label} exceeds its byte limit`);
      }
      if (process.platform !== "win32" && !fs.constants.O_NOFOLLOW) {
        throw new Error(`${label} cannot be opened without following links on this platform`);
      }
      const descriptor = fs.openSync(absolute, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
      try {
        const opened = fs.fstatSync(descriptor, { bigint: true });
        if (!opened.isFile() || !sameFileIdentity(before, opened)) {
          throw new Error(`${label} changed while it was opened: ${relative}`);
        }
        hash.update(`file\0${relative}\0${opened.mode}\0${opened.size}\0`);
        const buffer = Buffer.allocUnsafe(1024 * 1024);
        while (true) {
          const read = fs.readSync(descriptor, buffer, 0, buffer.length, null);
          if (read === 0) break;
          hash.update(buffer.subarray(0, read));
        }
        hash.update("\0");
        const afterRead = fs.fstatSync(descriptor, { bigint: true });
        const afterPath = fs.lstatSync(absolute, { bigint: true });
        if (!sameFileIdentity(opened, afterRead) || !sameFileIdentity(afterRead, afterPath)) {
          throw new Error(`${label} changed while it was hashed: ${relative}`);
        }
      } finally {
        fs.closeSync(descriptor);
      }
    }
  };
  visit(resolvedRoot);
  return { path: resolvedRoot, sha256: hash.digest("hex"), entries, bytes };
}

function assertObservedFileStillMatches(observed, label, options = {}) {
  const current = observeTrustedRegularFile(observed.path, label, options);
  if (current.path !== observed.path || !sameFileIdentity(current.identity, observed.identity)) {
    throw new Error(`${label} changed while it was used`);
  }
}

let trustedGitPath;

function resolveTrustedGit() {
  assertProtectedRuntimePlatform();
  const options = { executable: true, protectedFromCurrentProcess: true };
  if (trustedGitPath) return observeTrustedRegularFile(trustedGitPath, "trusted system Git", options);
  const candidates = process.platform === "win32"
    ? ["C:\\Program Files\\Git\\cmd\\git.exe", "C:\\Program Files\\Git\\bin\\git.exe"]
    : ["/usr/bin/git", "/bin/git"];
  const allowed = new Set(candidates.map((candidate) => process.platform === "win32" ? candidate.toLowerCase() : candidate));
  for (const candidate of candidates) {
    try {
      const observed = observeTrustedRegularFile(candidate, "trusted system Git", options);
      const normalized = process.platform === "win32" ? observed.path.toLowerCase() : observed.path;
      if (!allowed.has(normalized)) continue;
      trustedGitPath = observed.path;
      return observed;
    } catch {
      // Try the next fixed system location, then fail closed.
    }
  }
  throw new Error(`no trusted system Git is available for ${process.platform}`);
}

function controlledGitEnvironment(executable) {
  const safePath = [...new Set([
    path.dirname(executable),
    ...(process.platform === "win32" ? [] : ["/usr/bin", "/bin"])
  ])].join(path.delimiter);
  const environment = {
    HOME: process.platform === "win32" ? "C:\\Windows" : "/",
    LANG: "C",
    LC_ALL: "C",
    NO_COLOR: "1",
    PATH: safePath,
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0"
  };
  if (process.platform === "win32") {
    environment.SystemRoot = /^[A-Za-z]:\\Windows$/iu.test(process.env.SystemRoot || "")
      ? process.env.SystemRoot
      : "C:\\Windows";
    environment.USERPROFILE = environment.HOME;
  }
  return environment;
}

function controlledGitArguments(args) {
  const nullDevice = process.platform === "win32" ? "NUL" : "/dev/null";
  return [
    "--no-replace-objects",
    "--no-optional-locks",
    "-c", "core.fsmonitor=false",
    "-c", `core.hooksPath=${nullDevice}`,
    "-c", "core.useReplaceRefs=false",
    ...args
  ];
}

function git(args, cwd) {
  const runtime = resolveTrustedGit();
  const result = spawnSync(runtime.path, controlledGitArguments(args), {
    cwd,
    env: controlledGitEnvironment(runtime.path),
    encoding: "utf8",
    timeout: 120_000,
    windowsHide: true,
    shell: false,
    maxBuffer: 32 * 1024 * 1024
  });
  assertObservedFileStillMatches(runtime, "trusted system Git", {
    executable: true,
    protectedFromCurrentProcess: true
  });
  if (result.error || result.status !== 0) {
    throw new Error((result.stderr || result.error?.message || "git command failed").trim());
  }
  return result.stdout.trim();
}

function gitWithInput(args, cwd, input) {
  const runtime = resolveTrustedGit();
  const result = spawnSync(runtime.path, controlledGitArguments(args), {
    cwd,
    env: controlledGitEnvironment(runtime.path),
    input,
    encoding: "utf8",
    timeout: 120_000,
    windowsHide: true,
    shell: false,
    maxBuffer: 32 * 1024 * 1024
  });
  assertObservedFileStillMatches(runtime, "trusted system Git", {
    executable: true,
    protectedFromCurrentProcess: true
  });
  if (result.error || result.status !== 0) {
    throw new Error((result.stderr || result.error?.message || "git command failed").trim());
  }
  return result.stdout.trim();
}

function lstatExists(file) {
  try {
    return fs.lstatSync(file);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

function parseIndexEntries(output) {
  return output.split("\0").filter(Boolean).map((record) => {
    const match = record.match(/^([0-7]{6}) ([a-f0-9]+) ([0-3])\t([\s\S]+)$/u);
    return match && { mode: match[1], object: match[2], stage: match[3], name: match[4] };
  });
}

function parseCommitTree(output) {
  return output.split("\0").filter(Boolean).map((record) => {
    const match = record.match(/^([0-7]{6}) (blob|commit) ([a-f0-9]+)\t([\s\S]+)$/u);
    return match && { mode: match[1], type: match[2], object: match[3], name: match[4] };
  });
}

function worktreeContainsOnlyExpectedPaths(directory, treeEntries) {
  const files = new Set(treeEntries.map((entry) => entry.name));
  const directories = new Set([""]);
  for (const entry of treeEntries) {
    const parts = entry.name.split("/");
    for (let index = 1; index < parts.length; index += 1) {
      directories.add(parts.slice(0, index).join("/"));
    }
  }
  const visit = (relativeDirectory) => {
    const absoluteDirectory = relativeDirectory
      ? path.join(directory, ...relativeDirectory.split("/"))
      : directory;
    for (const item of fs.readdirSync(absoluteDirectory, { withFileTypes: true })) {
      const relative = relativeDirectory ? `${relativeDirectory}/${item.name}` : item.name;
      if (!relativeDirectory && item.name === ".git") continue;
      if (item.isDirectory()) {
        if (!directories.has(relative) || !visit(relative)) return false;
      } else if (!files.has(relative)) {
        return false;
      }
    }
    return true;
  };
  return visit("");
}

function sourceCheckoutClean(directory, expectedHead = null) {
  if (!expectedHead || git(["rev-parse", "HEAD"], directory) !== expectedHead) return false;
  const root = fs.realpathSync(directory);
  if (fs.realpathSync(git(["rev-parse", "--show-toplevel"], directory)) !== root) return false;
  const dotGit = path.join(root, ".git");
  const dotGitStat = lstatExists(dotGit);
  if (!dotGitStat?.isDirectory() || dotGitStat.isSymbolicLink()) return false;
  const gitDirectory = fs.realpathSync(git(["rev-parse", "--absolute-git-dir"], directory));
  const commonDirectory = fs.realpathSync(path.resolve(directory, git(["rev-parse", "--git-common-dir"], directory)));
  if (gitDirectory !== fs.realpathSync(dotGit) || commonDirectory !== gitDirectory) return false;
  for (const relative of ["info/grafts", "objects/info/alternates", "objects/info/http-alternates"]) {
    if (lstatExists(path.join(commonDirectory, ...relative.split("/")))) return false;
  }
  const objects = fs.lstatSync(path.join(commonDirectory, "objects"));
  if (!objects.isDirectory() || objects.isSymbolicLink()) return false;
  if (git(["for-each-ref", "--format=%(refname)", "refs/replace"], directory)) return false;

  const expectedTree = parseCommitTree(git(["ls-tree", "-r", "-z", "--full-tree", expectedHead], directory));
  const indexEntries = parseIndexEntries(git(["ls-files", "-s", "-z"], directory));
  if (
    expectedTree.some((entry) => !entry || /[\r\n]/u.test(entry.name)) ||
    indexEntries.some((entry) => !entry || entry.stage !== "0" || /[\r\n]/u.test(entry.name)) ||
    expectedTree.length !== indexEntries.length
  ) return false;
  for (let index = 0; index < expectedTree.length; index += 1) {
    const expected = expectedTree[index];
    const actual = indexEntries[index];
    if (
      expected.mode !== actual.mode || expected.object !== actual.object || expected.name !== actual.name ||
      (expected.mode === "160000" ? expected.type !== "commit" : expected.type !== "blob")
    ) return false;
  }

  // `git status` trusts these index flags. A pinned source checkout must not
  // use them to hide working-tree bytes from the admission decision.
  const tracked = git(["ls-files", "-v", "-z"], directory)
    .split("\0")
    .filter(Boolean);
  if (tracked.length !== expectedTree.length || tracked.some((record) => !record.startsWith("H "))) return false;

  const regular = [];
  for (const entry of expectedTree) {
    const absolute = path.resolve(root, ...entry.name.split("/"));
    if (!absolute.startsWith(`${root}${path.sep}`)) return false;
    let stat;
    try {
      stat = fs.lstatSync(absolute);
    } catch {
      return false;
    }
    if (entry.mode === "100644" || entry.mode === "100755") {
      if (!stat.isFile() || stat.isSymbolicLink()) return false;
      if (process.platform !== "win32" && Boolean(stat.mode & 0o111) !== (entry.mode === "100755")) return false;
      regular.push(entry);
    } else if (entry.mode === "120000") {
      if (!stat.isSymbolicLink()) return false;
      const actual = gitWithInput(["hash-object", "--no-filters", "--stdin"], directory, fs.readlinkSync(absolute));
      if (actual !== entry.object) return false;
    } else if (entry.mode === "160000") {
      // Managed source sync does not initialize submodules. Treat an
      // incomplete or independently configured gitlink as unavailable.
      return false;
    } else {
      return false;
    }
  }
  if (regular.length) {
    const input = `${regular.map((entry) => entry.name).join("\n")}\n`;
    const actual = gitWithInput(["hash-object", "--no-filters", "--stdin-paths"], directory, input).split(/\r?\n/u);
    if (actual.length !== regular.length || actual.some((hash, index) => hash !== regular[index].object)) return false;
  }
  return worktreeContainsOnlyExpectedPaths(root, expectedTree);
}

function digestTree(root) {
  const hash = crypto.createHash("sha256");
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name))) {
      const absolute = path.join(directory, entry.name);
      const relative = path.relative(root, absolute).split(path.sep).join("/");
      const stat = fs.lstatSync(absolute);
      if (stat.isSymbolicLink()) {
        hash.update(`link\0${relative}\0${fs.readlinkSync(absolute)}\0`);
      } else if (stat.isDirectory()) {
        hash.update(`dir\0${relative}\0`);
        visit(absolute);
      } else if (stat.isFile()) {
        hash.update(`file\0${relative}\0${stat.size}\0`);
        hash.update(fs.readFileSync(absolute));
        hash.update("\0");
      } else {
        throw new Error(`unsupported installed file type: ${relative}`);
      }
    }
  };
  visit(root);
  return hash.digest("hex");
}

function trackedNpmLock(entry, paths) {
  const repositoryRoot = path.resolve(paths.repo);
  const lockFile = path.resolve(repositoryRoot, entry.install.lockfile);
  if (!lockFile.startsWith(`${repositoryRoot}${path.sep}`)) throw new Error(`npm lock escapes repository: ${entry.id}`);
  if (digestFile(lockFile) !== entry.install.lockSha256) throw new Error(`tracked npm lock digest changed: ${entry.id}`);
  const lock = readJson(lockFile);
  const direct = lock.packages?.[`node_modules/${entry.install.package}`];
  if (
    lock.packages?.[""]?.dependencies?.[entry.install.package] !== entry.version ||
    direct?.version !== entry.version ||
    direct?.integrity !== entry.install.integrity
  ) throw new Error(`tracked npm lock does not match ${entry.install.package}@${entry.version}`);
  const packageFile = path.join(path.dirname(lockFile), "package.json");
  if (!fs.existsSync(packageFile)) throw new Error(`tracked npm package manifest is missing: ${entry.id}`);
  return { lockFile, packageFile, lock };
}

function npmCache(paths) {
  return path.join(paths.home, "cache", "npm");
}

function resolveBundledNpmRuntime() {
  assertProtectedRuntimePlatform();
  const protectedOptions = { executable: true, protectedFromCurrentProcess: true };
  const node = observeTrustedRegularFile(process.execPath, "current Node executable", protectedOptions);
  const nodeDirectory = path.dirname(node.path);
  const installationRoot = realPath(process.platform === "win32" ? nodeDirectory : path.resolve(nodeDirectory, ".."));
  if (!hasLockedSystemPath(installationRoot)) {
    throw new Error("the current Node installation is reachable through a group- or other-writable path");
  }
  const candidates = process.platform === "win32"
    ? [path.join(nodeDirectory, "node_modules", "npm", "bin", "npm-cli.js")]
    : [
        path.join(installationRoot, "lib", "node_modules", "npm", "bin", "npm-cli.js"),
        path.join(installationRoot, "share", "nodejs", "npm", "bin", "npm-cli.js"),
        path.join(installationRoot, "node_modules", "npm", "bin", "npm-cli.js")
      ];
  let rejection = null;
  for (const candidate of [...new Set(candidates)]) {
    try {
      const npmCli = observeTrustedRegularFile(candidate, "bundled npm CLI", { protectedFromCurrentProcess: true });
      if (!sameOrDescendant(installationRoot, npmCli.path)) continue;
      if (path.basename(npmCli.path) !== "npm-cli.js" || path.basename(path.dirname(npmCli.path)) !== "bin") continue;
      const npmRoot = realPath(path.resolve(path.dirname(npmCli.path), ".."));
      if (!sameOrDescendant(installationRoot, npmRoot)) continue;
      const npmTree = observeProtectedTree(npmRoot, "bundled npm implementation");
      return { node, npmCli, npmTree, installationRoot };
    } catch (error) {
      if (!new Set(["ENOENT", "ENOTDIR"]).has(error.code)) rejection = error;
      // Try each layout supported by the current Node installation.
    }
  }
  if (rejection) throw rejection;
  throw new Error("the current Node installation does not contain a trusted bundled npm CLI");
}

function controlledNpmEnvironment(cache, runtimeHome, runtimeTemporary, userConfig, globalConfig, offline) {
  const environment = {
    HOME: runtimeHome,
    USERPROFILE: runtimeHome,
    TMPDIR: runtimeTemporary,
    TMP: runtimeTemporary,
    TEMP: runtimeTemporary,
    LANG: "C",
    LC_ALL: "C",
    TZ: "UTC",
    NO_COLOR: "1",
    NPM_CONFIG_AUDIT: "false",
    NPM_CONFIG_CACHE: cache,
    NPM_CONFIG_COLOR: "false",
    NPM_CONFIG_FUND: "false",
    NPM_CONFIG_GLOBALCONFIG: globalConfig,
    NPM_CONFIG_IGNORE_SCRIPTS: "true",
    NPM_CONFIG_OFFLINE: offline ? "true" : "false",
    NPM_CONFIG_PROGRESS: "false",
    NPM_CONFIG_UPDATE_NOTIFIER: "false",
    NPM_CONFIG_USERCONFIG: userConfig
  };
  if (process.platform === "win32") {
    environment.SystemRoot = /^[A-Za-z]:\\Windows$/iu.test(process.env.SystemRoot || "")
      ? process.env.SystemRoot
      : "C:\\Windows";
  }
  return environment;
}

function materializeNpmTree(entry, paths, staging, options = {}) {
  const { lockFile, packageFile } = trackedNpmLock(entry, paths);
  fs.mkdirSync(staging, { recursive: true, mode: 0o700 });
  fs.copyFileSync(packageFile, path.join(staging, "package.json"));
  fs.copyFileSync(lockFile, path.join(staging, "package-lock.json"));
  const cache = npmCache(paths);
  fs.mkdirSync(cache, { recursive: true, mode: 0o700 });
  const runtimeDirectory = path.join(staging, ".gate-npm-runtime");
  const runtimeHome = path.join(runtimeDirectory, "home");
  const runtimeTemporary = path.join(runtimeDirectory, "tmp");
  const userConfig = path.join(runtimeDirectory, "user.npmrc");
  const globalConfig = path.join(runtimeDirectory, "global.npmrc");
  fs.mkdirSync(runtimeHome, { recursive: true, mode: 0o700 });
  fs.mkdirSync(runtimeTemporary, { recursive: true, mode: 0o700 });
  fs.writeFileSync(userConfig, "", { mode: 0o600 });
  fs.writeFileSync(globalConfig, "", { mode: 0o600 });
  const args = [
    "ci",
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    "--update-notifier=false",
    "--color=false",
    "--progress=false",
    `--cache=${cache}`,
    `--userconfig=${userConfig}`,
    `--globalconfig=${globalConfig}`
  ];
  if (options.offline) args.push("--offline");
  let result;
  try {
    const runtime = resolveBundledNpmRuntime();
    result = spawnSync(runtime.node.path, [runtime.npmCli.path, ...args], {
      cwd: staging,
      encoding: "utf8",
      timeout: 180_000,
      windowsHide: true,
      shell: false,
      maxBuffer: 32 * 1024 * 1024,
      env: controlledNpmEnvironment(
        cache,
        runtimeHome,
        runtimeTemporary,
        userConfig,
        globalConfig,
        options.offline === true
      )
    });
    assertObservedFileStillMatches(runtime.node, "current Node executable", {
      executable: true,
      protectedFromCurrentProcess: true
    });
    assertObservedFileStillMatches(runtime.npmCli, "bundled npm CLI", { protectedFromCurrentProcess: true });
    const npmTree = observeProtectedTree(runtime.npmTree.path, "bundled npm implementation");
    if (
      npmTree.path !== runtime.npmTree.path || npmTree.sha256 !== runtime.npmTree.sha256 ||
      npmTree.entries !== runtime.npmTree.entries || npmTree.bytes !== runtime.npmTree.bytes
    ) throw new Error("bundled npm implementation changed while it was used");
  } finally {
    fs.rmSync(runtimeDirectory, { recursive: true, force: true });
  }
  if (result.error || result.status !== 0) {
    const reason = (result.stderr || result.error?.message || `npm exited ${result.status}`).trim();
    const prefix = options.offline
      ? "could not reconstruct the npm tree from the reviewed lock and local integrity cache"
      : "npm install failed";
    throw new Error(`${prefix}: ${reason}`);
  }
  if (digestFile(lockFile) !== digestFile(path.join(staging, "package-lock.json"))) {
    throw new Error(`npm changed the reviewed lock while installing: ${entry.id}`);
  }
  const installed = readJson(path.join(staging, "package-lock.json"));
  const direct = installed.packages?.[`node_modules/${entry.install.package}`];
  if (direct?.version !== entry.version || direct?.integrity !== entry.install.integrity) {
    throw new Error(`integrity verification failed for ${entry.install.package}@${entry.version}`);
  }
  return digestTree(path.join(staging, "node_modules"));
}

function reconstructedNpmTreeDigest(entry, paths) {
  fs.mkdirSync(paths.upstreamTools, { recursive: true, mode: 0o700 });
  const staging = fs.mkdtempSync(path.join(paths.upstreamTools, `.${entry.id}-verify-`));
  try {
    return materializeNpmTree(entry, paths, staging, { offline: true });
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
  }
}

function promoteDirectory(staging, destination) {
  const backup = `${destination}.previous-${process.pid}-${crypto.randomBytes(4).toString("hex")}`;
  let movedExisting = false;
  try {
    if (fs.existsSync(destination)) {
      fs.renameSync(destination, backup);
      movedExisting = true;
    }
    fs.renameSync(staging, destination);
    if (movedExisting) fs.rmSync(backup, { recursive: true, force: true });
  } catch (error) {
    if (!fs.existsSync(destination) && movedExisting && fs.existsSync(backup)) fs.renameSync(backup, destination);
    throw error;
  }
}

function verifyNpmReceipt(entry, directory) {
  const receiptFile = path.join(directory, "install.json");
  const receipt = readJson(receiptFile);
  const expected = {
    apiVersion: "gate.upstream-install/v2",
    id: entry.id,
    lane: "npm",
    package: entry.install.package,
    version: entry.version,
    integrity: entry.install.integrity,
    lockSha256: entry.install.lockSha256
  };
  for (const [key, value] of Object.entries(expected)) {
    if (receipt[key] !== value) throw new Error(`npm install receipt ${key} mismatch: ${entry.id}`);
  }
  if (!Number.isFinite(Date.parse(receipt.verifiedAt))) {
    throw new Error(`npm install receipt evidence is malformed: ${entry.id}`);
  }
  return receipt;
}

function verifyNpmInstallation(entry, paths, directory) {
  const { lockFile } = trackedNpmLock(entry, paths);
  const installedLock = path.join(directory, "package-lock.json");
  const modules = path.join(directory, "node_modules");
  const receipt = verifyNpmReceipt(entry, directory);
  if (digestFile(lockFile) !== digestFile(installedLock)) throw new Error(`installed npm lock changed: ${entry.id}`);
  // install.json is evidence, not an integrity anchor: it is writable beside
  // node_modules. Recreate the expected bytes offline from the reviewed lock
  // and its integrity-addressed npm cache before admitting an executable.
  if (digestTree(modules) !== reconstructedNpmTreeDigest(entry, paths)) {
    throw new Error(`installed npm tree changed: ${entry.id}`);
  }
  return receipt;
}

function verifyReleaseReceipt(entry, directory) {
  const install = entry.install;
  const platformKey = `${process.platform}-${process.arch}`;
  const artifact = install.artifacts?.[platformKey];
  if (!artifact?.executableSha256) throw new Error(`${entry.id} has no reviewed executable digest for ${platformKey}`);
  const receipt = readJson(path.join(directory, "install.json"));
  if (
    receipt.apiVersion !== "gate.upstream-install/v2" || receipt.id !== entry.id || receipt.lane !== "github-release" ||
    receipt.version !== entry.version || receipt.platform !== platformKey || receipt.sha256 !== artifact?.sha256 ||
    receipt.tag !== install.tag || receipt.artifact !== artifact?.name ||
    receipt.executable !== `bin/${install.binary}${process.platform === "win32" ? ".exe" : ""}` ||
    receipt.executableSha256 !== artifact.executableSha256 || receipt.versionSource !== "reviewed-lock" ||
    receipt.executedDuringInstall !== false || !Number.isFinite(Date.parse(receipt.verifiedAt))
  ) throw new Error(`installed release verification failed: ${entry.id}`);
  return receipt;
}

function verifyReleaseInstallation(entry, directory) {
  const install = entry.install;
  const receipt = verifyReleaseReceipt(entry, directory);
  const executable = path.join(directory, "bin", `${install.binary}${process.platform === "win32" ? ".exe" : ""}`);
  const stat = fs.lstatSync(executable);
  const artifact = install.artifacts[`${process.platform}-${process.arch}`];
  if (!stat.isFile() || stat.isSymbolicLink() || digestFile(executable) !== artifact.executableSha256) {
    throw new Error(`installed release executable is unsafe or changed: ${entry.id}`);
  }
  return { receipt, executable };
}

export function upstreamStatus(options = {}) {
  const { paths, lock } = readUpstreamLock(options);
  const verifyIntegrity = options.verifyIntegrity !== false;
  return lock.upstreams.map((entry) => {
    const directory = childDirectory(paths.upstreams, entry.id);
    const toolDirectory = childDirectory(paths.upstreamTools, entry.id);
    let installedCommit = null;
    let installedVersion = null;
    let sourceClean = null;
    let integrityState = "not-installed";
    if (fs.existsSync(path.join(directory, ".git"))) {
      try {
        installedCommit = git(["rev-parse", "HEAD"], directory);
        if (verifyIntegrity) sourceClean = sourceCheckoutClean(directory, entry.commit);
        integrityState = verifyIntegrity ? (sourceClean ? "verified" : "invalid") : "commit-only";
      } catch {
        installedCommit = "invalid";
        integrityState = "invalid";
      }
    }
    if (entry.install?.lane === "npm" && fs.existsSync(toolDirectory)) {
      try {
        const receipt = verifyIntegrity
          ? verifyNpmInstallation(entry, paths, toolDirectory)
          : verifyNpmReceipt(entry, toolDirectory);
        installedVersion = receipt.version;
        integrityState = verifyIntegrity ? "verified" : "receipt-only";
      } catch {
        installedVersion = null;
        integrityState = "invalid";
      }
    }
    if (entry.install?.lane === "github-release" && fs.existsSync(toolDirectory)) {
      try {
        const receipt = verifyIntegrity
          ? verifyReleaseInstallation(entry, toolDirectory).receipt
          : verifyReleaseReceipt(entry, toolDirectory);
        installedVersion = receipt.version;
        integrityState = verifyIntegrity ? "verified" : "receipt-only";
      } catch {
        installedVersion = null;
        integrityState = "invalid";
      }
    }
    const sourceInstalled = installedCommit === entry.commit;
    const packageInstalled = ["npm", "github-release"].includes(entry.install?.lane) && installedVersion === entry.version;
    const integrityVerified = integrityState === "verified";
    const sourceReady = sourceInstalled && sourceClean === true && integrityVerified;
    const packageReady = packageInstalled && integrityVerified;
    return {
      ...entry,
      directory,
      toolDirectory,
      installedCommit,
      installedVersion,
      sourceClean,
      integrityState,
      installed: sourceInstalled || packageInstalled,
      sourceReady,
      packageReady,
      ready: packageReady || sourceReady
    };
  });
}

export function syncUpstream(id, options = {}) {
  const { paths, lock } = readUpstreamLock(options);
  ensureRuntime(paths);
  const entry = lock.upstreams.find((candidate) => candidate.id === id);
  if (!entry) throw new Error(`unknown upstream: ${id}`);
  const directory = childDirectory(paths.upstreams, entry.id);
  fs.mkdirSync(paths.upstreams, { recursive: true, mode: 0o700 });
  const staging = fs.mkdtempSync(path.join(paths.upstreams, `.${id}-sync-`));
  const template = fs.mkdtempSync(path.join(paths.upstreams, ".git-template-"));
  try {
    git(
      ["clone", "--filter=blob:none", "--no-checkout", "--no-recurse-submodules", `--template=${template}`, entry.repository, staging],
      paths.home
    );
    const remote = git(["remote", "get-url", "origin"], staging).replace(/\.git$/, "");
    if (remote !== entry.repository.replace(/\.git$/, "")) throw new Error(`remote mismatch for ${id}`);
    git(["fetch", "--depth=1", "origin", entry.commit], staging);
    git(["checkout", "--detach", entry.commit], staging);
    const actual = git(["rev-parse", "HEAD"], staging);
    if (actual !== entry.commit) throw new Error(`commit verification failed for ${id}`);
    if (!sourceCheckoutClean(staging, entry.commit)) {
      throw new Error(`source checkout differs from the locked commit or contains extra paths: ${id}`);
    }
    promoteDirectory(staging, directory);
    recordEvent(
      { kind: "upstream.synced", summary: `Pinned ${id} at ${entry.commit}.`, details: { upstream: id, commit: entry.commit } },
      { paths }
    );
    return { id, directory, commit: actual };
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
    fs.rmSync(template, { recursive: true, force: true });
  }
}

function installNpmUpstream(entry, paths) {
  const id = entry.id;
  if (!entry.version || !entry.install.package || !entry.install.integrity) {
    throw new Error(`${id} is missing an exact npm version or integrity value`);
  }
  const directory = childDirectory(paths.upstreamTools, id);
  trackedNpmLock(entry, paths);
  fs.mkdirSync(paths.upstreamTools, { recursive: true, mode: 0o700 });
  const staging = fs.mkdtempSync(path.join(paths.upstreamTools, `.${id}-install-`));
  try {
    materializeNpmTree(entry, paths, staging);
    const installedManifest = path.join(staging, "node_modules", ...entry.install.package.split("/"), "package.json");
    const manifest = readJson(installedManifest);
    const bin = typeof manifest.bin === "string" ? { [entry.install.package]: manifest.bin } : manifest.bin || {};
    const receipt = {
      apiVersion: "gate.upstream-install/v2",
      id,
      lane: "npm",
      package: entry.install.package,
      version: entry.version,
      integrity: entry.install.integrity,
      lockSha256: entry.install.lockSha256,
      verifiedAt: new Date().toISOString()
    };
    writeJsonAtomic(path.join(staging, "install.json"), receipt, 0o600);
    promoteDirectory(staging, directory);
    verifyNpmInstallation(entry, paths, directory);
    recordEvent(
      {
        kind: "upstream.installed",
        summary: `Installed ${entry.install.package}@${entry.version} from its reviewed complete npm lock.`,
        effect: { class: "host-write", targetRef: directory, engagementId: null, planDigest: null },
        evidenceRefs: [`file://${path.join(directory, "install.json")}`]
      },
      { paths }
    );
    return { ...receipt, directory, bin };
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
  }
}

function runChecked(command, args, options = {}) {
  const encoding = Object.hasOwn(options, "encoding") ? options.encoding : "utf8";
  const result = spawnSync(command, args, {
    encoding,
    env: options.env || process.env,
    input: options.input,
    maxBuffer: options.maxBuffer || 32 * 1024 * 1024,
    timeout: options.timeout || 180_000,
    windowsHide: true,
    cwd: options.cwd,
    shell: false,
    stdio: [options.input === undefined ? "ignore" : "pipe", "pipe", "pipe"]
  });
  if (result.error || result.status !== 0) {
    const stderr = Buffer.isBuffer(result.stderr) ? result.stderr.toString("utf8") : result.stderr;
    throw new Error((stderr || result.error?.message || `${command} exited ${result.status}`).trim());
  }
  return Buffer.isBuffer(result.stdout) ? result.stdout : result.stdout.trim();
}

let trustedGitHubCliPath;

function allowedGitHubCliLocation(file) {
  const normalized = process.platform === "win32" ? file.toLowerCase() : file;
  if (process.platform === "win32") return normalized === "c:\\program files\\github cli\\gh.exe";
  if (new Set(["/usr/bin/gh", "/bin/gh", "/usr/local/bin/gh"]).has(normalized)) return true;
  if (process.platform !== "darwin") return false;
  return /^\/(?:opt\/homebrew|usr\/local)\/Cellar\/gh\/[^/]+\/bin\/gh$/u.test(normalized);
}

function resolveTrustedGitHubCli() {
  assertProtectedRuntimePlatform();
  const options = { executable: true, protectedFromCurrentProcess: true };
  if (trustedGitHubCliPath) {
    return observeTrustedRegularFile(trustedGitHubCliPath, "trusted system GitHub CLI", options);
  }
  const candidates = process.platform === "win32"
    ? ["C:\\Program Files\\GitHub CLI\\gh.exe"]
    : process.platform === "darwin"
      ? ["/opt/homebrew/bin/gh", "/usr/local/bin/gh", "/usr/bin/gh"]
      : ["/usr/bin/gh", "/bin/gh", "/usr/local/bin/gh"];
  for (const candidate of candidates) {
    try {
      const observed = observeTrustedRegularFile(candidate, "trusted system GitHub CLI", options);
      if (!allowedGitHubCliLocation(observed.path)) continue;
      trustedGitHubCliPath = observed.path;
      return observed;
    } catch {
      // Try the next fixed system location, then fail closed.
    }
  }
  throw new Error(`no trusted system GitHub CLI is available for ${process.platform}`);
}

function controlledGitHubEnvironment(runtimeHome, runtimeTemporary, configDirectory) {
  const environment = {
    HOME: runtimeHome,
    USERPROFILE: runtimeHome,
    XDG_CONFIG_HOME: path.join(runtimeHome, ".config"),
    GH_CONFIG_DIR: configDirectory,
    GH_PROMPT_DISABLED: "1",
    GH_NO_UPDATE_NOTIFIER: "1",
    LANG: "C",
    LC_ALL: "C",
    NO_COLOR: "1",
    TMPDIR: runtimeTemporary,
    TMP: runtimeTemporary,
    TEMP: runtimeTemporary
  };
  for (const name of [
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy"
  ]) {
    if (typeof process.env[name] === "string") environment[name] = process.env[name];
  }
  if (process.platform === "win32") {
    environment.SystemRoot = /^[A-Za-z]:\\Windows$/iu.test(process.env.SystemRoot || "")
      ? process.env.SystemRoot
      : "C:\\Windows";
  }
  return environment;
}

function runGitHubCli(args, staging) {
  if (![process.env.GH_TOKEN, process.env.GITHUB_TOKEN].some((value) => typeof value === "string" && value.length)) {
    throw new Error("GitHub release installation requires GH_TOKEN or GITHUB_TOKEN in the environment");
  }
  const runtime = resolveTrustedGitHubCli();
  const runtimeDirectory = path.join(staging, ".gate-gh-runtime");
  const runtimeHome = path.join(runtimeDirectory, "home");
  const runtimeTemporary = path.join(runtimeDirectory, "tmp");
  const configDirectory = path.join(runtimeDirectory, "config");
  fs.mkdirSync(runtimeHome, { recursive: true, mode: 0o700 });
  fs.mkdirSync(runtimeTemporary, { recursive: true, mode: 0o700 });
  fs.mkdirSync(configDirectory, { recursive: true, mode: 0o700 });
  let output;
  let failure = null;
  try {
    try {
      output = runChecked(runtime.path, args, {
        env: controlledGitHubEnvironment(runtimeHome, runtimeTemporary, configDirectory)
      });
    } catch (error) {
      failure = error;
    }
    assertObservedFileStillMatches(runtime, "trusted system GitHub CLI", {
      executable: true,
      protectedFromCurrentProcess: true
    });
    if (failure) throw failure;
    return output;
  } finally {
    fs.rmSync(runtimeDirectory, { recursive: true, force: true });
  }
}

let trustedTarPath;

function hasLockedSystemPath(file) {
  if (process.platform === "win32") return true;
  let current = file;
  while (true) {
    const stat = fs.statSync(current);
    if ((stat.mode & 0o022) !== 0) return false;
    const parent = path.dirname(current);
    if (parent === current) return true;
    current = parent;
  }
}

function resolveTrustedTar() {
  assertProtectedRuntimePlatform();
  const options = { executable: true, protectedFromCurrentProcess: true };
  if (trustedTarPath) return observeTrustedRegularFile(trustedTarPath, "trusted system tar", options);
  const candidates = process.platform === "win32"
    ? ["C:\\Windows\\System32\\tar.exe"]
    : process.platform === "darwin"
      ? ["/usr/bin/tar"]
      : ["/usr/bin/tar", "/bin/tar"];
  for (const candidate of candidates) {
    try {
      const observed = observeTrustedRegularFile(candidate, "trusted system tar", options);
      const trustedLocation = process.platform === "win32"
        ? observed.path.toLowerCase() === "c:\\windows\\system32\\tar.exe"
        : observed.path === "/usr/bin/tar" || observed.path === "/bin/tar";
      if (trustedLocation) {
        trustedTarPath = observed.path;
        return observed;
      }
    } catch {
      // Try the next fixed system location, then fail closed.
    }
  }
  throw new Error(`no trusted system tar is available for ${process.platform}`);
}

function controlledArchiveEnvironment() {
  if (process.platform === "win32") {
    return { PATH: "C:\\Windows\\System32", SystemRoot: "C:\\Windows" };
  }
  return { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" };
}

function runTar(args, options = {}) {
  const runtime = resolveTrustedTar();
  let output;
  let failure = null;
  try {
    output = runChecked(runtime.path, args, { ...options, env: controlledArchiveEnvironment() });
  } catch (error) {
    failure = error;
  }
  assertObservedFileStillMatches(runtime, "trusted system tar", {
    executable: true,
    protectedFromCurrentProcess: true
  });
  if (failure) throw failure;
  return output;
}

function repositoryName(url) {
  const match = String(url).match(/^https:\/\/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?$/i);
  if (!match) throw new Error(`unsupported release repository: ${url}`);
  return `${match[1]}/${match[2]}`;
}

function digestFile(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

const MAX_RELEASE_ARCHIVE_BYTES = 256 * 1024 * 1024;
const MAX_RELEASE_EXECUTABLE_BYTES = 256 * 1024 * 1024;

function readBoundedRegularFile(file, label, maximumBytes) {
  const before = fs.lstatSync(file, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) throw new Error(`${label} is not a regular file`);
  if (before.size > BigInt(maximumBytes)) throw new Error(`${label} exceeds its byte limit`);
  if (process.platform !== "win32" && !fs.constants.O_NOFOLLOW) {
    throw new Error(`${label} cannot be opened without following links on this platform`);
  }
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!opened.isFile() || !sameFileIdentity(before, opened)) throw new Error(`${label} changed while it was opened`);
    const bytes = Buffer.allocUnsafe(Number(opened.size));
    let offset = 0;
    while (offset < bytes.length) {
      const read = fs.readSync(descriptor, bytes, offset, bytes.length - offset, null);
      if (read === 0) throw new Error(`${label} changed while it was read`);
      offset += read;
    }
    const afterRead = fs.fstatSync(descriptor, { bigint: true });
    const afterPath = fs.lstatSync(file, { bigint: true });
    if (
      !sameFileIdentity(opened, afterRead) || !sameFileIdentity(afterRead, afterPath)
    ) throw new Error(`${label} changed while it was read`);
    return bytes;
  } finally {
    fs.closeSync(descriptor);
  }
}

function inspectReleaseArchiveBytes(bytes, label) {
  const gzip = bytes[0] === 0x1f && bytes[1] === 0x8b;
  const entries = runTar([gzip ? "-tzf" : "-tf", "-"], { input: bytes }).split(/\r?\n/).filter(Boolean);
  const details = runTar([gzip ? "-tzvf" : "-tvf", "-"], { input: bytes }).split(/\r?\n/).filter(Boolean);
  const unsafeName = (name) => (
    path.isAbsolute(name) || /^[A-Za-z]:[\\/]/u.test(name) || name.split(/[\\/]/).includes("..")
  );
  if (
    !entries.length || entries.some(unsafeName) || details.length !== entries.length ||
    details.some((line) => line[0] !== "-" && line[0] !== "d")
  ) {
    throw new Error(`release archive has unsafe paths or entry types: ${label}`);
  }
  return entries;
}

export function inspectReleaseArchive(archive) {
  const bytes = readBoundedRegularFile(archive, "release archive", MAX_RELEASE_ARCHIVE_BYTES);
  return inspectReleaseArchiveBytes(bytes, path.basename(archive));
}

export function readVerifiedReleaseExecutable(archive, artifact, binaryName) {
  if (
    !artifact?.name || !/^[a-f0-9]{64}$/u.test(artifact.sha256 || "") ||
    !/^[a-f0-9]{64}$/u.test(artifact.executableSha256 || "") ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(binaryName || "")
  ) throw new Error("release executable verification requires reviewed artifact metadata");
  const bytes = readBoundedRegularFile(archive, "release archive", MAX_RELEASE_ARCHIVE_BYTES);
  const actualDigest = crypto.createHash("sha256").update(bytes).digest("hex");
  if (actualDigest !== artifact.sha256) throw new Error(`SHA-256 verification failed for ${artifact.name}`);
  const entries = inspectReleaseArchiveBytes(bytes, artifact.name);
  const candidates = entries.filter((name) => path.basename(name) === binaryName);
  if (candidates.length !== 1) throw new Error(`release archive must contain exactly one ${binaryName}`);
  const gzip = bytes[0] === 0x1f && bytes[1] === 0x8b;
  const executable = runTar([gzip ? "-xzOf" : "-xOf", "-", "--", candidates[0]], {
    input: bytes,
    encoding: null,
    maxBuffer: MAX_RELEASE_EXECUTABLE_BYTES
  });
  const executableDigest = crypto.createHash("sha256").update(executable).digest("hex");
  if (executableDigest !== artifact.executableSha256) {
    throw new Error(`executable SHA-256 verification failed for ${binaryName}`);
  }
  return { archiveSha256: actualDigest, executableSha256: executableDigest, executable };
}

function installReleaseUpstream(entry, paths) {
  const install = entry.install || {};
  const platformKey = `${process.platform}-${process.arch}`;
  const artifact = install.artifacts?.[platformKey];
  if (
    !entry.version || !install.tag || !install.binary || !artifact?.name ||
    !/^[a-f0-9]{64}$/.test(artifact.sha256 || "") ||
    !/^[a-f0-9]{64}$/.test(artifact.executableSha256 || "")
  ) {
    throw new Error(`${entry.id} has no verified release artifact for ${platformKey}`);
  }
  const directory = childDirectory(paths.upstreamTools, entry.id);
  fs.mkdirSync(paths.upstreamTools, { recursive: true, mode: 0o700 });
  const staging = fs.mkdtempSync(path.join(paths.upstreamTools, `.${entry.id}-install-`));
  try {
    runGitHubCli(
      ["release", "download", install.tag, "--repo", repositoryName(entry.repository), "--pattern", artifact.name, "--dir", staging, "--clobber"],
      staging
    );
    const archive = path.join(staging, artifact.name);
    const binaryName = `${install.binary}${process.platform === "win32" ? ".exe" : ""}`;
    const archiveResult = readVerifiedReleaseExecutable(archive, artifact, binaryName);
    const binDirectory = path.join(staging, "bin");
    fs.mkdirSync(binDirectory, { recursive: true, mode: 0o700 });
    const destination = path.join(binDirectory, binaryName);
    fs.writeFileSync(destination, archiveResult.executable, { flag: "wx", mode: 0o700 });
    if (process.platform !== "win32") fs.chmodSync(destination, 0o700);
    const receipt = {
      apiVersion: "gate.upstream-install/v2",
      id: entry.id,
      lane: "github-release",
      version: entry.version,
      tag: install.tag,
      platform: platformKey,
      artifact: artifact.name,
      sha256: archiveResult.archiveSha256,
      executableSha256: artifact.executableSha256,
      executable: `bin/${binaryName}`,
      versionSource: "reviewed-lock",
      executedDuringInstall: false,
      verifiedAt: new Date().toISOString()
    };
    writeJsonAtomic(path.join(staging, "install.json"), receipt, 0o600);
    promoteDirectory(staging, directory);
    const verified = verifyReleaseInstallation(entry, directory);
    recordEvent(
      {
        kind: "upstream.installed",
        summary: `Installed ${entry.id} ${entry.version} from a verified GitHub release.`,
        effect: { class: "host-write", targetRef: directory, engagementId: null, planDigest: null },
        evidenceRefs: [`file://${path.join(directory, "install.json")}`]
      },
      { paths }
    );
    return { ...receipt, directory, executable: verified.executable };
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
  }
}

export function installUpstream(id, options = {}) {
  const { paths, lock } = readUpstreamLock(options);
  ensureRuntime(paths);
  const entry = lock.upstreams.find((candidate) => candidate.id === id);
  if (!entry) throw new Error(`unknown upstream: ${id}`);
  if (entry.install?.lane === "npm") return installNpmUpstream(entry, paths);
  if (entry.install?.lane === "github-release") return installReleaseUpstream(entry, paths);
  throw new Error(`${id} uses the ${entry.install?.lane || "unknown"} lane; use upstream sync for its pinned source`);
}

export function resolveUpstreamBinary(id, name, options = {}) {
  const { paths, lock } = readUpstreamLock(options);
  const entry = lock.upstreams.find((candidate) => candidate.id === id);
  if (!entry) throw new Error(`unknown upstream: ${id}`);
  if (entry.install?.lane === "github-release") {
    const selected = name || entry.install.binary;
    if (selected !== entry.install.binary) throw new Error(`unknown ${id} executable: ${selected}; available: ${entry.install.binary}`);
    const directory = childDirectory(paths.upstreamTools, id);
    let executable;
    try {
      ({ executable } = verifyReleaseInstallation(entry, directory));
    } catch {
      throw new Error(`${id} is absent or failed integrity verification; run: gate upstream install ${id}`);
    }
    return { id, name: selected, executable, directory: childDirectory(paths.upstreamTools, id) };
  }
  if (entry.install?.lane !== "npm") throw new Error(`${id} has no GATE-managed executable; use its pinned source directory`);
  const directory = childDirectory(paths.upstreamTools, id);
  try {
    verifyNpmInstallation(entry, paths, directory);
  } catch {
    throw new Error(`${id} is absent or failed integrity verification; run: gate upstream install ${id}`);
  }
  const manifestFile = path.join(directory, "node_modules", ...entry.install.package.split("/"), "package.json");
  if (!fs.existsSync(manifestFile)) throw new Error(`${id} is not installed; run: gate upstream install ${id}`);
  const manifest = readJson(manifestFile);
  const bins = typeof manifest.bin === "string" ? { [entry.install.package]: manifest.bin } : manifest.bin || {};
  const selected = name || Object.keys(bins)[0];
  if (!selected || !Object.hasOwn(bins, selected)) {
    throw new Error(`unknown ${id} executable: ${selected || "none"}; available: ${Object.keys(bins).join(", ") || "none"}`);
  }
  const executable = path.join(directory, "node_modules", ".bin", `${selected}${process.platform === "win32" ? ".cmd" : ""}`);
  if (!fs.existsSync(executable)) throw new Error(`installed executable is missing: ${selected}`);
  return { id, name: selected, executable, directory };
}
