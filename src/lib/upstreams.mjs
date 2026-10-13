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

function controlledGitEnvironment() {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.toUpperCase().startsWith("GIT_")) env[key] = value;
  }
  return {
    ...env,
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0"
  };
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
  const result = spawnSync("git", controlledGitArguments(args), {
    cwd,
    env: controlledGitEnvironment(),
    encoding: "utf8",
    timeout: 120_000,
    windowsHide: true,
    maxBuffer: 32 * 1024 * 1024
  });
  if (result.error || result.status !== 0) {
    throw new Error((result.stderr || result.error?.message || "git command failed").trim());
  }
  return result.stdout.trim();
}

function gitWithInput(args, cwd, input) {
  const result = spawnSync("git", controlledGitArguments(args), {
    cwd,
    env: controlledGitEnvironment(),
    input,
    encoding: "utf8",
    timeout: 120_000,
    windowsHide: true,
    maxBuffer: 32 * 1024 * 1024
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

function materializeNpmTree(entry, paths, staging, options = {}) {
  const { lockFile, packageFile } = trackedNpmLock(entry, paths);
  fs.mkdirSync(staging, { recursive: true, mode: 0o700 });
  fs.copyFileSync(packageFile, path.join(staging, "package.json"));
  fs.copyFileSync(lockFile, path.join(staging, "package-lock.json"));
  const cache = npmCache(paths);
  fs.mkdirSync(cache, { recursive: true, mode: 0o700 });
  const args = ["ci", "--ignore-scripts", "--no-audit", "--no-fund"];
  if (options.offline) args.push("--offline");
  const result = spawnSync(npmCommand(), args, {
    cwd: staging,
    encoding: "utf8",
    timeout: 180_000,
    windowsHide: true,
    env: {
      ...process.env,
      NPM_CONFIG_CACHE: cache,
      NPM_CONFIG_IGNORE_SCRIPTS: "true"
    }
  });
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

function npmCommand() {
  return process.platform === "win32" ? "npm.cmd" : "npm";
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
  const result = spawnSync(command, args, {
    encoding: "utf8",
    env: options.env || process.env,
    timeout: options.timeout || 180_000,
    windowsHide: true,
    cwd: options.cwd,
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (result.error || result.status !== 0) {
    throw new Error((result.stderr || result.error?.message || `${command} exited ${result.status}`).trim());
  }
  return result.stdout.trim();
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
  if (trustedTarPath) return trustedTarPath;
  const candidates = process.platform === "win32"
    ? ["C:\\Windows\\System32\\tar.exe"]
    : process.platform === "darwin"
      ? ["/usr/bin/tar"]
      : ["/usr/bin/tar", "/bin/tar"];
  for (const candidate of candidates) {
    try {
      const resolved = fs.realpathSync(candidate);
      const stat = fs.statSync(resolved);
      const trustedLocation = process.platform === "win32"
        ? resolved.toLowerCase() === "c:\\windows\\system32\\tar.exe"
        : resolved === "/usr/bin/tar" || resolved === "/bin/tar";
      if (stat.isFile() && trustedLocation && hasLockedSystemPath(resolved)) {
        trustedTarPath = resolved;
        return trustedTarPath;
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
  return runChecked(resolveTrustedTar(), args, { ...options, env: controlledArchiveEnvironment() });
}

function repositoryName(url) {
  const match = String(url).match(/^https:\/\/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?$/i);
  if (!match) throw new Error(`unsupported release repository: ${url}`);
  return `${match[1]}/${match[2]}`;
}

function digestFile(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

export function inspectReleaseArchive(archive) {
  const entries = runTar(["-tf", archive]).split(/\r?\n/).filter(Boolean);
  const details = runTar(["-tvf", archive]).split(/\r?\n/).filter(Boolean);
  const unsafeName = (name) => (
    path.isAbsolute(name) || /^[A-Za-z]:[\\/]/u.test(name) || name.split(/[\\/]/).includes("..")
  );
  if (
    !entries.length || entries.some(unsafeName) || details.length !== entries.length ||
    details.some((line) => line[0] !== "-" && line[0] !== "d")
  ) {
    throw new Error(`release archive has unsafe paths or entry types: ${path.basename(archive)}`);
  }
  return entries;
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
    runChecked(
      "gh",
      ["release", "download", install.tag, "--repo", repositoryName(entry.repository), "--pattern", artifact.name, "--dir", staging, "--clobber"]
    );
    const archive = path.join(staging, artifact.name);
    const actualDigest = digestFile(archive);
    if (actualDigest !== artifact.sha256) throw new Error(`SHA-256 verification failed for ${artifact.name}`);
    const entries = inspectReleaseArchive(archive);
    const extracted = path.join(staging, "extracted");
    fs.mkdirSync(extracted, { mode: 0o700 });
    runTar(["-xf", archive, "-C", extracted]);
    const binaryName = `${install.binary}${process.platform === "win32" ? ".exe" : ""}`;
    const candidates = entries.filter((name) => path.basename(name) === binaryName);
    if (candidates.length !== 1) throw new Error(`release archive must contain exactly one ${binaryName}`);
    const source = path.resolve(extracted, candidates[0]);
    const extractedPrefix = `${path.resolve(extracted)}${path.sep}`;
    const stat = fs.lstatSync(source);
    if (!source.startsWith(extractedPrefix) || !stat.isFile() || stat.isSymbolicLink()) {
      throw new Error(`release executable is not a regular file: ${binaryName}`);
    }
    const binDirectory = path.join(staging, "bin");
    fs.mkdirSync(binDirectory, { recursive: true, mode: 0o700 });
    const destination = path.join(binDirectory, binaryName);
    fs.copyFileSync(source, destination);
    if (process.platform !== "win32") fs.chmodSync(destination, 0o700);
    const executableDigest = digestFile(destination);
    if (executableDigest !== artifact.executableSha256) {
      throw new Error(`executable SHA-256 verification failed for ${binaryName}`);
    }
    const receipt = {
      apiVersion: "gate.upstream-install/v2",
      id: entry.id,
      lane: "github-release",
      version: entry.version,
      tag: install.tag,
      platform: platformKey,
      artifact: artifact.name,
      sha256: actualDigest,
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
