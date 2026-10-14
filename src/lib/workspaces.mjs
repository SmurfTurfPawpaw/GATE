import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { newId, recordEvent } from "./events.mjs";
import { ensureRuntime, runtimePaths } from "./paths.mjs";
import { securePrivateDirectory } from "./private-fs.mjs";
import { resolveUpstreamBinary, upstreamStatus as readUpstreamStatus } from "./upstreams.mjs";

const TREEHOUSE_ID = "treehouse";
const TREEHOUSE_HOLDER_PREFIX = "gate:";
const LEASE_ID = /^[a-f0-9]{32}$/u;
const TASK_ID = /^[A-Za-z0-9][A-Za-z0-9_.-]{1,119}$/u;
const MAX_JSON_BYTES = 4 * 1024 * 1024;
const MAX_TREE_BYTES = 64 * 1024 * 1024;
const MAX_STATUS_ENTRIES = 512;
const MAX_TASK_ROOTS = MAX_STATUS_ENTRIES - 1;
const MAX_WORKTREE_FILES = 250_000;
const MAX_WORKTREE_BYTES = 4 * 1024 * 1024 * 1024;
const RAW_VERIFICATION_TIMEOUT_MS = 300_000;
const TREEHOUSE_STATE_VERSION = 4;
const LEASE_BINDING_FILE = ".gate-lease-binding.json";
const OPERATION_LOCKED_CODE = "GATE_WORKSPACE_OPERATION_LOCKED";
const NULL_DEVICE = process.platform === "win32" ? "NUL" : "/dev/null";
const GIT_CONFIG_PROTECTIONS = [
  ["core.hooksPath", NULL_DEVICE],
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
function boundedString(value, label, { minimum = 1, maximum = 240, allowEmpty = false } = {}) {
  if (typeof value !== "string") throw new Error(`${label} must be a string`);
  if ((!allowEmpty && value.length < minimum) || value.length > maximum || /[\0\r\n]/u.test(value)) {
    throw new Error(`${label} is malformed`);
  }
  return value;
}

function taskIdentifier(value) {
  const taskId = boundedString(value, "task id", { maximum: 120 });
  if (!TASK_ID.test(taskId)) throw new Error("task id must contain only letters, numbers, dots, underscores, and hyphens");
  return taskId;
}

function gitRef(value, label) {
  const ref = boundedString(value, label, { maximum: 240 });
  if (
    ref.startsWith("-") || ref.startsWith("/") || ref.endsWith("/") || ref.endsWith(".") || ref.endsWith(".lock") ||
    ref.includes("..") || ref.includes("@{") || ref.includes("//") || ref.includes("\\") ||
    !/^[A-Za-z0-9][A-Za-z0-9._/-]*$/u.test(ref)
  ) throw new Error(`${label} is not a supported Git ref`);
  return ref;
}

function commitPattern(objectFormat) {
  if (objectFormat === "sha1") return /^[a-f0-9]{40}$/u;
  if (objectFormat === "sha256") return /^[a-f0-9]{64}$/u;
  throw new Error(`Git returned an unsupported object format: ${objectFormat}`);
}

function existingDirectory(value, label) {
  const supplied = boundedString(value, label, { maximum: 4096 });
  const resolved = path.resolve(supplied);
  let stat;
  try {
    stat = fs.statSync(resolved);
  } catch (error) {
    throw new Error(`${label} is unavailable: ${error.message}`);
  }
  if (!stat.isDirectory()) throw new Error(`${label} must be a directory`);
  return fs.realpathSync(resolved);
}

function samePath(left, right) {
  const first = path.resolve(left);
  const second = path.resolve(right);
  return process.platform === "win32" ? first.toLowerCase() === second.toLowerCase() : first === second;
}

function normalizedPathKey(value) {
  const resolved = path.resolve(value);
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

function sameOrDescendant(parent, candidate) {
  const relative = path.relative(path.resolve(parent), path.resolve(candidate));
  return relative === "" ||
    (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

function safeErrorText(value) {
  const text = String(value || "").replace(/[\0\r]+/gu, " ").trim();
  return text.slice(0, 4_000) || "command failed without diagnostics";
}

function assertTrustedPath(candidate, protectedRoots, expectedType) {
  const resolved = fs.realpathSync(candidate);
  const stat = fs.statSync(resolved);
  if (expectedType === "file" && !stat.isFile()) throw new Error(`${candidate} is not a regular file`);
  if (expectedType === "directory" && !stat.isDirectory()) throw new Error(`${candidate} is not a directory`);
  if (expectedType === "file" && process.platform !== "win32" && (stat.mode & 0o111) === 0) {
    throw new Error(`${candidate} is not executable`);
  }
  if (protectedRoots.some((root) => sameOrDescendant(root, resolved))) {
    throw new Error(`${candidate} is inside a protected workspace or GATE state directory`);
  }
  if (process.platform !== "win32") {
    let current = resolved;
    while (true) {
      const currentStat = fs.statSync(current);
      if ((currentStat.mode & 0o022) !== 0) {
        throw new Error(`${candidate} is reachable through a group- or other-writable path`);
      }
      const parent = path.dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }
  return resolved;
}

function resolveGitExecution(protectedRoots, injectedExecutable = null) {
  if (process.platform === "win32" && !injectedExecutable) {
    throw new Error("Windows workspace operations require an explicitly configured trusted Git executable");
  }
  const candidates = injectedExecutable ? [injectedExecutable] : ["/usr/bin/git", "/bin/git"];
  let executable = null;
  for (const candidate of candidates) {
    if (!path.isAbsolute(candidate)) {
      if (injectedExecutable) throw new Error("the injected Git executable must be an absolute path");
      continue;
    }
    try {
      executable = assertTrustedPath(candidate, protectedRoots, "file");
      break;
    } catch {
      // PATH is an ordered set of candidates. Unsafe or absent entries are
      // ignored so a later system installation can still be selected.
    }
  }
  if (!executable) throw new Error("no trusted absolute Git executable was found on PATH");

  const fixedDirectories = process.platform === "win32"
    ? [path.dirname(executable)]
    : [path.dirname(executable), "/usr/bin", "/bin"];
  const safeDirectories = [];
  for (const directory of fixedDirectories) {
    try {
      const resolved = assertTrustedPath(directory, protectedRoots, "directory");
      if (!safeDirectories.some((entry) => samePath(entry, resolved))) safeDirectories.push(resolved);
    } catch {
      // Treehouse receives only fixed trusted system directories (plus an
      // explicitly injected internal/test Git directory on Windows).
    }
  }
  return { executable, path: safeDirectories.join(path.delimiter) };
}

function minimalChildEnvironment(childHome, temporary, safePath) {
  if (process.platform === "win32") {
    const systemRoot = "C:\\Windows";
    return {
      GIT_ALLOW_PROTOCOL: "",
      GIT_NO_LAZY_FETCH: "1",
      HOME: childHome,
      NO_COLOR: "1",
      PATH: safePath,
      PATHEXT: ".COM;.EXE",
      SystemRoot: systemRoot,
      TEMP: temporary,
      TMP: temporary,
      USERPROFILE: childHome,
      WINDIR: systemRoot,
      XDG_CONFIG_HOME: path.join(childHome, ".config")
    };
  }
  return {
    GIT_ALLOW_PROTOCOL: "",
    GIT_NO_LAZY_FETCH: "1",
    HOME: childHome,
    LANG: "C",
    LC_ALL: "C",
    NO_COLOR: "1",
    PATH: safePath,
    TMPDIR: temporary,
    XDG_CONFIG_HOME: path.join(childHome, ".config")
  };
}

function treehouseEnvironment(treehouseRoot, childHome, temporary, safePath) {
  const config = {};
  GIT_CONFIG_PROTECTIONS.forEach(([key, value], index) => {
    config[`GIT_CONFIG_KEY_${index}`] = key;
    config[`GIT_CONFIG_VALUE_${index}`] = value;
  });
  return {
    ...minimalChildEnvironment(childHome, temporary, safePath),
    GCM_INTERACTIVE: "Never",
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CONFIG_COUNT: String(GIT_CONFIG_PROTECTIONS.length),
    GIT_CONFIG_GLOBAL: NULL_DEVICE,
    GIT_CONFIG_NOSYSTEM: "1",
    ...config,
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0",
    TREEHOUSE_NO_UPDATE_CHECK: "1",
    TREEHOUSE_ROOT: treehouseRoot,
    TREEHOUSE_WORKTREE_PATH: "{pool}/{slot}/{repo}",
    TREEHOUSE_VCS: "git",
    TREEHOUSE_APFS_SHARING: "off"
  };
}

function controlledGitEnvironment(childHome, temporary, safePath) {
  return {
    ...minimalChildEnvironment(childHome, temporary, safePath),
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: NULL_DEVICE,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0"
  };
}

function controlledGitArguments(args) {
  return [
    "--no-replace-objects",
    "--no-optional-locks",
    ...GIT_CONFIG_PROTECTIONS.flatMap(([key, value]) => ["-c", `${key}=${value}`]),
    ...args
  ];
}

function execute(command, args, invocation, options = {}) {
  const runner = options.runner || spawnSync;
  let result;
  try {
    const encoding = Object.hasOwn(invocation, "encoding") ? invocation.encoding : "utf8";
    result = runner(command, args, {
      cwd: invocation.cwd,
      env: invocation.env,
      encoding,
      timeout: invocation.timeout,
      maxBuffer: invocation.maxBuffer || MAX_JSON_BYTES,
      windowsHide: true,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"]
    });
  } catch (error) {
    throw new Error(`${invocation.label} could not start: ${safeErrorText(error.message)}`);
  }
  if (!result || typeof result !== "object") throw new Error(`${invocation.label} returned no process result`);
  if (result.error) throw new Error(`${invocation.label} failed: ${safeErrorText(result.error.message)}`);
  return {
    status: result.status,
    signal: result.signal || null,
    stdout: Buffer.isBuffer(result.stdout)
      ? result.stdout
      : typeof result.stdout === "string" ? result.stdout : String(result.stdout || ""),
    stderr: Buffer.isBuffer(result.stderr)
      ? result.stderr
      : typeof result.stderr === "string" ? result.stderr : String(result.stderr || "")
  };
}

function checkedTreehouseGet(tool, args, repository, options, timeout = 180_000) {
  if (args[0] !== "get") throw new Error("the workspace bridge only permits the reviewed Treehouse get operation");
  assertSafeWorktreeConfigs(repository, tool, options);
  assertNoCommonGitTransactionLocks(repository, tool, options);
  assertNoWorktreeTransactionLocks(repository, "main Git worktree", tool, options);
  const result = execute(tool.executable, args, {
    cwd: repository,
    env: tool.environment,
    timeout,
    label: `Treehouse ${args[0] || "command"}`
  }, options);
  if (result.status !== 0) {
    throw new Error(`Treehouse ${args[0] || "command"} failed: ${safeErrorText(result.stderr || result.stdout)}`);
  }
  assertSafeWorktreeConfigs(repository, tool, options);
  assertNoCommonGitTransactionLocks(repository, tool, options);
  assertNoWorktreeTransactionLocks(repository, "main Git worktree", tool, options);
  return result.stdout;
}

function runGit(
  args,
  cwd,
  tool,
  options,
  acceptedStatuses = new Set([0]),
  timeout = 30_000,
  environmentOverrides = {},
  encoding = "utf8",
  maxBuffer = MAX_JSON_BYTES
) {
  const result = execute(tool.gitExecutable, controlledGitArguments(args), {
    cwd,
    env: { ...tool.gitEnvironment, ...environmentOverrides },
    timeout,
    encoding,
    maxBuffer,
    label: `Git ${args[0] || "command"}`
  }, options);
  if (!acceptedStatuses.has(result.status)) {
    throw new Error(`Git ${args[0] || "command"} failed: ${safeErrorText(result.stderr || result.stdout)}`);
  }
  return result;
}

const COMMAND_CAPABLE_GIT_CONFIG = [
  /^alias\./u,
  /^branch\..+\.mergeoptions$/u,
  /^browser\..+\.(?:cmd|path)$/u,
  /^include(?:if\..+)?\.path$/u,
  /^filter\./u,
  /^diff\..+\.(?:command|textconv)$/u,
  /^diff\.external$/u,
  /^(?:diff|merge)\.(?:gui)?tool$/u,
  /^difftool\..+\.(?:cmd|path)$/u,
  /^merge\..+\.driver$/u,
  /^mergetool\..+\.(?:cmd|layout|path)$/u,
  /^(?:core|sequence)\.editor$/u,
  /^core\.(?:askpass|gitproxy|sshcommand)$/u,
  /^credential(?:\..+)?\.helper$/u,
  /^gpg(?:\..+)?\.program$/u,
  /^gpg\.ssh\.defaultkeycommand$/u,
  /^gc\.recentobjectshook$/u,
  /^guitool\..+\.cmd$/u,
  /^man\..+\.(?:cmd|path)$/u,
  /^pager\./u,
  /^core\.pager$/u,
  /^interactive\.difffilter$/u,
  /^imap\.tunnel$/u,
  /^instaweb\./u,
  /^rebase\.instructionformat$/u,
  /^submodule\..+\.update$/u,
  /^remote\..+\.(?:uploadpack|receivepack|vcs)$/u,
  /^sendemail(?:\..+)?\.smtpserver$/u,
  /^sendemail(?:\..+)?\.(?:cccmd|headercmd|sendmailcmd|tocmd)$/u,
  /^svn\.authorsprog$/u,
  /^tar\..+\.command$/u,
  /^trailer\..+\.(?:cmd|command)$/u,
  /^protocol(?:\..+)?\.allow$/u,
  /^pull\.(?:octopus|twohead)$/u
];

const REPOSITORY_REDIRECTING_GIT_CONFIG = [
  // core.worktree can make a command launched in the main checkout inspect a
  // linked worktree instead. The other keys either redirect repository input
  // files/commands or change whether Git treats the repository as a worktree.
  /^core\.(?:alternaterefscommand|attributesfile|checkstat|commitgraph|excludesfile|fsmonitor(?:hookversion)?|gitdir|hookspath|ignorestat|trustctime|worktree)$/u,
  /^fsck\./u
];

// Local and per-worktree config lives in a task-writable common Git directory.
// Treat only the small set needed for ordinary clone identity and branch
// tracking as compatible. Unknown keys fail closed because Git repeatedly adds
// new command and strategy selectors that cannot be made safe by inheritance
// controls alone.
const REVIEWED_LOCAL_GIT_CONFIG = [
  /^core\.(?:bare|filemode|ignorecase|logallrefupdates|precomposeunicode|protecthfs|protectntfs|repositoryformatversion|sharedrepository|symlinks)$/u,
  /^extensions\.(?:compatobjectformat|objectformat|refstorage|worktreeconfig)$/u,
  /^user\.(?:email|name|signingkey|useconfigonly)$/u,
  /^remote\..+\.(?:fetch|mirror|partialclonefilter|promisor|push|pushurl|tagopt|url)$/u,
  /^branch\..+\.(?:description|merge|pushremote|rebase|remote)$/u,
  /^submodule\..+\.(?:active|branch|fetchrecursesubmodules|ignore|shallow|url)$/u,
  /^init\.defaultbranch$/u,
  /^push\.(?:autosetupremote|default|followtags)$/u,
  /^pull\.(?:ff|rebase)$/u
];

function assertExpectedWorktree(cwd, label, tool, options) {
  const output = runGit(["rev-parse", "--show-toplevel"], cwd, tool, options).stdout.trim();
  if (!output || /[\0\r\n]/u.test(output)) throw new Error(`Git returned an invalid ${label} top-level path`);
  const topLevel = existingDirectory(output, `${label} top-level path`);
  const intended = fs.realpathSync(cwd);
  if (!samePath(topLevel, intended)) {
    throw new Error(`${label} is redirected to a different Git worktree (${topLevel})`);
  }
}

function assertNoSubmodules(cwd, tool, options) {
  const staged = runGit(["ls-files", "--stage", "-z"], cwd, tool, options).stdout
    .split("\0")
    .filter(Boolean);
  const committed = runGit(["ls-tree", "-r", "-z", "HEAD"], cwd, tool, options).stdout
    .split("\0")
    .filter(Boolean);
  if (staged.some((entry) => entry.startsWith("160000 ")) || committed.some((entry) => entry.startsWith("160000 "))) {
    throw new Error("Git submodules are incompatible with workspace operations because nested worktree integrity cannot be established");
  }
}

function assertPrivateWorkspacePath(workspacePath, tool) {
  if (!tool.treehouseRoot) throw new Error("workspace operation has no task-specific Treehouse root");
  if (samePath(workspacePath, tool.treehouseRoot) || !sameOrDescendant(tool.treehouseRoot, workspacePath)) {
    throw new Error("Treehouse workspace path must be a strict descendant of the private GATE-owned Treehouse root");
  }
}

function privateWorkspaceContainer(workspacePath, tool) {
  const container = path.dirname(fs.realpathSync(workspacePath));
  if (samePath(container, tool.treehouseRoot) || !sameOrDescendant(tool.treehouseRoot, container)) {
    throw new Error("Treehouse workspace container must be a strict descendant of the private clone-specific root");
  }
  return container;
}

function parseGitConfigEntries(output) {
  return output.split("\0").filter(Boolean).map((record) => {
    const separator = record.indexOf("\n");
    if (separator < 1) throw new Error("repository-local Git configuration is malformed");
    return {
      name: record.slice(0, separator).toLowerCase(),
      value: record.slice(separator + 1)
    };
  });
}

function unsafeBooleanConfig(entries) {
  const falseValues = new Set(["0", "false", "no", "off"]);
  const trueValues = new Set(["1", "true", "yes", "on"]);
  for (const entry of entries) {
    const value = entry.value.trim().toLowerCase();
    if (entry.name === "core.bare" && !falseValues.has(value)) return entry.name;
    if (
      process.platform !== "win32" &&
      new Set(["core.filemode", "core.symlinks"]).has(entry.name) &&
      !trueValues.has(value)
    ) return entry.name;
  }
  return null;
}

function assertSafeRepositoryConfig(cwd, tool, options) {
  const localEntries = parseGitConfigEntries(runGit(
    ["config", "--local", "--no-includes", "--null", "--list"],
    cwd,
    tool,
    options
  ).stdout);
  const worktreeConfigOutput = runGit(
    ["rev-parse", "--git-path", "config.worktree"],
    cwd,
    tool,
    options
  ).stdout.trim();
  if (!worktreeConfigOutput || /[\0\r\n]/u.test(worktreeConfigOutput)) {
    throw new Error("Git returned an invalid per-worktree configuration path");
  }
  const worktreeConfig = path.isAbsolute(worktreeConfigOutput)
    ? worktreeConfigOutput
    : path.resolve(cwd, worktreeConfigOutput);
  let before = null;
  try {
    before = fs.lstatSync(worktreeConfig);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  let worktreeEntries = [];
  if (before) {
    if (!before.isFile() || before.isSymbolicLink() || before.size > MAX_JSON_BYTES) {
      throw new Error("per-worktree Git configuration must be a bounded regular non-symlink file");
    }
    worktreeEntries = parseGitConfigEntries(runGit(
      ["config", "--file", worktreeConfig, "--no-includes", "--null", "--list"],
      cwd,
      tool,
      options
    ).stdout);
    const after = fs.lstatSync(worktreeConfig);
    if (
      before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs
    ) throw new Error("per-worktree Git configuration changed while it was inspected");
  }
  const entries = [...localEntries, ...worktreeEntries];
  const names = [...new Set(entries.map((entry) => entry.name))];
  if (names.length > 10_000 || names.some((name) => name.length > 1_024 || /[\r\n]/u.test(name))) {
    throw new Error("repository-local Git configuration is malformed or unbounded");
  }
  const unsafe = names.map((name) => name.toLowerCase()).find((name) => {
    return COMMAND_CAPABLE_GIT_CONFIG.some((pattern) => pattern.test(name));
  });
  if (unsafe) {
    throw new Error(`repository-local Git configuration can execute a command (${unsafe}); workspace operations are blocked`);
  }
  const redirecting = names.map((name) => name.toLowerCase()).find((name) => {
    return REPOSITORY_REDIRECTING_GIT_CONFIG.some((pattern) => pattern.test(name));
  });
  if (redirecting) {
    throw new Error(`repository-local Git configuration can redirect repository behavior (${redirecting}); workspace operations are blocked`);
  }
  const unsafeBoolean = unsafeBooleanConfig(entries);
  if (unsafeBoolean) {
    throw new Error(`repository-local Git configuration weakens worktree integrity (${unsafeBoolean}); workspace operations are blocked`);
  }
  const unsupportedRefStorage = entries.find((entry) => {
    return entry.name === "extensions.refstorage" && entry.value.trim().toLowerCase() !== "files";
  });
  if (unsupportedRefStorage) {
    throw new Error("repository-local Git configuration selects unsupported reference storage; workspace operations require the files ref backend");
  }
  const unreviewed = names.map((name) => name.toLowerCase()).find((name) => {
    return !REVIEWED_LOCAL_GIT_CONFIG.some((pattern) => pattern.test(name));
  });
  if (unreviewed) {
    throw new Error(`repository-local Git configuration is outside the reviewed workspace allowlist (${unreviewed})`);
  }
  assertExpectedWorktree(cwd, "Git worktree", tool, options);
  assertNoSubmodules(cwd, tool, options);
}

function assertSafeWorktreeConfigs(repository, tool, options) {
  const output = runGit(
    ["worktree", "list", "--porcelain", "-z"],
    repository,
    tool,
    options
  ).stdout;
  const candidates = output.split("\0")
    .filter((field) => field.startsWith("worktree "))
    .map((field) => field.slice("worktree ".length));
  if (candidates.length < 1 || candidates.length > MAX_STATUS_ENTRIES) {
    throw new Error("Git returned an invalid or unbounded worktree list");
  }
  const primary = existingDirectory(candidates[0], "primary Git worktree path");
  if (!samePath(primary, repository)) {
    throw new Error("repository path must be the registered primary Git worktree");
  }
  const primaryCommonDirectory = commonGitDirectory(repository, tool, options);
  const primaryMarker = fs.lstatSync(path.join(repository, ".git"));
  if (!primaryMarker.isDirectory() || primaryMarker.isSymbolicLink() || !samePath(primaryCommonDirectory, fs.realpathSync(path.join(repository, ".git")))) {
    throw new Error("repository path must have a physical primary .git directory");
  }
  assertNoExecutableCommonHooks(primaryCommonDirectory);
  const adminRegistry = candidates.length > 1
    ? registeredLinkedWorktreeAdmins(primaryCommonDirectory)
    : null;
  const seen = new Set();
  for (const candidate of candidates) {
    const worktree = existingDirectory(candidate, "Git worktree path");
    const key = normalizedPathKey(worktree);
    if (seen.has(key)) throw new Error("Git returned a duplicate worktree path");
    seen.add(key);
    if (!samePath(worktree, repository)) {
      assertWorkspaceUnderRegisteredTaskRoot(worktree, repository, tool);
      assertRegisteredLinkedWorktree(worktree, adminRegistry, tool, options);
    }
    assertSafeRepositoryConfig(worktree, tool, options);
  }
}

function assertWorkspaceUnderRegisteredTaskRoot(worktree, repository, tool) {
  const relative = path.relative(tool.tasksRoot, worktree);
  const components = relative.split(path.sep);
  if (
    relative === "" || relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative) ||
    components.length < 2 || !/^[a-f0-9]{64}$/u.test(components[0])
  ) {
    throw new Error("Git worktree path escaped the private registered task-specific Treehouse roots");
  }
  const taskRoot = securePrivateDirectory(path.join(tool.tasksRoot, components[0]), {
    create: false,
    label: "registered task-specific Treehouse root"
  });
  readTaskBinding(taskRoot, repository);
  if (samePath(taskRoot, worktree) || !sameOrDescendant(taskRoot, worktree)) {
    throw new Error("Git worktree path escaped its registered task-specific Treehouse root");
  }
}

function assertNoExecutableCommonHooks(commonDirectory) {
  const hooks = path.join(commonDirectory, "hooks");
  let entries;
  try {
    entries = fs.readdirSync(hooks, { withFileTypes: true });
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  if (entries.length > 512) throw new Error("shared Git hooks directory is unbounded");
  for (const entry of entries) {
    const candidate = path.join(hooks, entry.name);
    const stat = fs.lstatSync(candidate);
    if (entry.name.endsWith(".sample") && stat.isFile() && !stat.isSymbolicLink()) continue;
    if (stat.isSymbolicLink() || !stat.isFile() || (process.platform !== "win32" && (stat.mode & 0o111) !== 0)) {
      throw new Error(`shared Git hook surface is unsafe (${entry.name}); workspace operations are blocked`);
    }
  }
}

function assertVisibleIndex(cwd, label, tool, options) {
  const hidden = runGit(["ls-files", "-v", "-z"], cwd, tool, options).stdout
    .split("\0")
    .filter(Boolean)
    .filter((record) => /^[a-zS] /u.test(record));
  if (hidden.length > 0) {
    throw new Error(`${label} has assume-unchanged or skip-worktree index flags`);
  }
}

function assertRealIndexMatchesHead(cwd, label, tool, options) {
  const result = runGit(
    ["diff-index", "--cached", "--quiet", "--no-ext-diff", "HEAD", "--"],
    cwd,
    tool,
    options,
    new Set([0, 1])
  );
  if (result.status === 1) throw new Error(`${label} has staged changes and will remain leased`);
}

function assertNoNestedGitMetadata(workspacePath) {
  const root = fs.realpathSync(workspacePath);
  const stack = [root];
  const visited = new Set([process.platform === "win32" ? root.toLowerCase() : root]);
  let entries = 0;
  while (stack.length > 0) {
    const directory = stack.pop();
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      entries += 1;
      if (entries > MAX_WORKTREE_FILES) {
        throw new Error(`Treehouse workspace filesystem exceeds the ${MAX_WORKTREE_FILES}-entry metadata inspection limit`);
      }
      const candidate = path.join(directory, entry.name);
      const relative = path.relative(root, candidate);
      if (relative !== ".git" && entry.name === ".git") {
        throw new Error("Treehouse workspace contains nested Git metadata; remove it before lease reuse or return");
      }
      const stat = fs.lstatSync(candidate);
      if (!stat.isDirectory() || stat.isSymbolicLink()) continue;
      const resolved = fs.realpathSync(candidate);
      if (!sameOrDescendant(root, resolved)) continue;
      const key = process.platform === "win32" ? resolved.toLowerCase() : resolved;
      if (visited.has(key)) continue;
      visited.add(key);
      stack.push(resolved);
    }
  }
}

function sameFilesystemObject(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function rawStateError(label, detail) {
  return new Error(`${label} raw filesystem state does not exactly match HEAD (${detail})`);
}

function compareRegularFiles(actualFile, canonicalFile, expectedMode, label, deadline) {
  const before = fs.lstatSync(actualFile, { bigint: true });
  const canonicalBefore = fs.lstatSync(canonicalFile, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || !canonicalBefore.isFile() || canonicalBefore.isSymbolicLink()) {
    throw rawStateError(label, "tracked file type changed");
  }
  if (before.nlink !== 1n) throw rawStateError(label, "tracked file has multiple hard links");
  if (process.platform !== "win32") {
    const executable = (before.mode & 0o111n) !== 0n;
    const canonicalExecutable = (canonicalBefore.mode & 0o111n) !== 0n;
    if (executable !== canonicalExecutable || executable !== (expectedMode === "100755")) {
      throw rawStateError(label, "tracked executable mode changed");
    }
  }
  if (before.size !== canonicalBefore.size) throw rawStateError(label, "tracked bytes changed");
  const descriptor = fs.openSync(actualFile, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  const canonicalDescriptor = fs.openSync(canonicalFile, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    const canonicalOpened = fs.fstatSync(canonicalDescriptor, { bigint: true });
    if (
      !opened.isFile() || !canonicalOpened.isFile() || !sameFilesystemObject(before, opened) ||
      !sameFilesystemObject(canonicalBefore, canonicalOpened)
    ) {
      throw rawStateError(label, "tracked file changed while it was opened");
    }
    const chunk = Buffer.allocUnsafe(128 * 1024);
    const canonicalChunk = Buffer.allocUnsafe(128 * 1024);
    let total = 0n;
    while (true) {
      if (Date.now() > deadline) throw rawStateError(label, "verification time limit exceeded");
      const count = fs.readSync(descriptor, chunk, 0, chunk.length, null);
      const canonicalCount = fs.readSync(canonicalDescriptor, canonicalChunk, 0, canonicalChunk.length, null);
      if (count !== canonicalCount || !chunk.subarray(0, count).equals(canonicalChunk.subarray(0, canonicalCount))) {
        throw rawStateError(label, "tracked bytes changed");
      }
      if (count === 0) break;
      total += BigInt(count);
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    const canonicalAfter = fs.fstatSync(canonicalDescriptor, { bigint: true });
    if (
      !sameFilesystemObject(opened, after) || opened.size !== after.size || total !== after.size ||
      opened.mtimeNs !== after.mtimeNs || opened.ctimeNs !== after.ctimeNs ||
      !sameFilesystemObject(canonicalOpened, canonicalAfter) || canonicalOpened.size !== canonicalAfter.size ||
      canonicalOpened.mtimeNs !== canonicalAfter.mtimeNs || canonicalOpened.ctimeNs !== canonicalAfter.ctimeNs
    ) throw rawStateError(label, "tracked file changed while it was read");
    const final = fs.lstatSync(actualFile, { bigint: true });
    if (!sameFilesystemObject(after, final)) throw rawStateError(label, "tracked file path changed while it was read");
    return after.size;
  } finally {
    fs.closeSync(descriptor);
    fs.closeSync(canonicalDescriptor);
  }
}

function compareSymlinks(actualFile, canonicalFile, label) {
  const before = fs.lstatSync(actualFile, { bigint: true });
  const canonicalBefore = fs.lstatSync(canonicalFile, { bigint: true });
  if (!before.isSymbolicLink() || !canonicalBefore.isSymbolicLink()) {
    throw rawStateError(label, "tracked symbolic-link type changed");
  }
  const target = fs.readlinkSync(actualFile, { encoding: "buffer" });
  const canonicalTarget = fs.readlinkSync(canonicalFile, { encoding: "buffer" });
  const after = fs.lstatSync(actualFile, { bigint: true });
  const canonicalAfter = fs.lstatSync(canonicalFile, { bigint: true });
  if (
    !target.equals(canonicalTarget) || !sameFilesystemObject(before, after) ||
    before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs ||
    !sameFilesystemObject(canonicalBefore, canonicalAfter) ||
    canonicalBefore.mtimeNs !== canonicalAfter.mtimeNs || canonicalBefore.ctimeNs !== canonicalAfter.ctimeNs
  ) {
    throw rawStateError(label, "tracked symbolic link changed while it was read");
  }
  return BigInt(target.length);
}

function parseHeadTree(cwd, tool, options, objectFormat, label) {
  const output = runGit(
    ["ls-tree", "-r", "-z", "--full-tree", "HEAD"],
    cwd,
    tool,
    options,
    new Set([0]),
    120_000,
    {},
    null,
    MAX_TREE_BYTES
  ).stdout;
  if (!Buffer.isBuffer(output)) throw rawStateError(label, "Git tree output was not binary-safe");
  const objectId = commitPattern(objectFormat);
  const files = new Map();
  const directories = new Set();
  let offset = 0;
  while (offset < output.length) {
    const end = output.indexOf(0, offset);
    if (end < 0) throw rawStateError(label, "Git tree output was malformed");
    const record = output.subarray(offset, end);
    offset = end + 1;
    const tab = record.indexOf(0x09);
    if (tab < 1) throw rawStateError(label, "Git tree output was malformed");
    const header = record.subarray(0, tab).toString("ascii");
    const match = /^(100644|100755|120000|160000) (blob|commit) ([a-f0-9]+)$/u.exec(header);
    if (!match || !objectId.test(match[3])) throw rawStateError(label, "Git tree entry was malformed");
    if (match[1] === "160000" || match[2] === "commit") {
      throw new Error("Git submodules are incompatible with workspace operations because nested worktree integrity cannot be established");
    }
    const relative = record.subarray(tab + 1);
    if (relative.length < 1 || relative[0] === 0x2f || relative.at(-1) === 0x2f) {
      throw rawStateError(label, "Git tree path was malformed");
    }
    const components = [];
    let componentStart = 0;
    for (let index = 0; index <= relative.length; index += 1) {
      if (index !== relative.length && relative[index] !== 0x2f) continue;
      const component = relative.subarray(componentStart, index);
      if (
        component.length < 1 || component.equals(Buffer.from(".")) || component.equals(Buffer.from("..")) ||
        component.equals(Buffer.from(".git"))
      ) throw rawStateError(label, "Git tree path was unsafe");
      components.push(component);
      componentStart = index + 1;
    }
    const key = relative.toString("hex");
    if (files.has(key)) throw rawStateError(label, "Git tree contained a duplicate path");
    files.set(key, { mode: match[1], objectId: match[3], relative: Buffer.from(relative) });
    for (let count = 1; count < components.length; count += 1) {
      directories.add(Buffer.concat(components.slice(0, count).flatMap((part, index) => {
        return index === 0 ? [part] : [Buffer.from("/"), part];
      })).toString("hex"));
    }
    if (files.size > MAX_WORKTREE_FILES) {
      throw rawStateError(label, `Git tree exceeds the ${MAX_WORKTREE_FILES}-entry limit`);
    }
  }
  return { files, directories };
}

function nativeTreePath(root, relative) {
  const nativeRelative = path.sep === "/"
    ? relative
    : Buffer.from(relative).map((byte) => byte === 0x2f ? path.sep.charCodeAt(0) : byte);
  return Buffer.concat([Buffer.from(root), Buffer.from(path.sep), nativeRelative]);
}

function ignoredWorktreePaths(cwd, tool, options, label) {
  const output = runGit(
    ["ls-files", "--others", "--ignored", "--exclude-standard", "-z"],
    cwd,
    tool,
    options,
    new Set([0]),
    120_000,
    {},
    null,
    MAX_TREE_BYTES
  ).stdout;
  if (!Buffer.isBuffer(output)) throw rawStateError(label, "ignored-path output was not binary-safe");
  const files = new Set();
  const directories = new Set();
  let offset = 0;
  while (offset < output.length) {
    const end = output.indexOf(0, offset);
    if (end < 0) throw rawStateError(label, "ignored-path output was malformed");
    const relative = output.subarray(offset, end);
    offset = end + 1;
    if (relative.length < 1 || relative[0] === 0x2f || relative.at(-1) === 0x2f) {
      throw rawStateError(label, "ignored path was malformed");
    }
    const components = [];
    let componentStart = 0;
    for (let index = 0; index <= relative.length; index += 1) {
      if (index !== relative.length && relative[index] !== 0x2f) continue;
      const component = relative.subarray(componentStart, index);
      if (
        component.length < 1 || component.equals(Buffer.from(".")) || component.equals(Buffer.from("..")) ||
        component.equals(Buffer.from(".git"))
      ) throw rawStateError(label, "ignored path was unsafe");
      components.push(component);
      componentStart = index + 1;
    }
    files.add(relative.toString("hex"));
    for (let count = 1; count < components.length; count += 1) {
      directories.add(Buffer.concat(components.slice(0, count).flatMap((part, index) => {
        return index === 0 ? [part] : [Buffer.from("/"), part];
      })).toString("hex"));
    }
    if (files.size > MAX_WORKTREE_FILES) throw rawStateError(label, "ignored-path output was unbounded");
  }
  return { files, directories };
}

function assertCanonicalHeadState(cwd, label, tool, options, { allowIgnoredExtras = false } = {}) {
  const root = fs.realpathSync(cwd);
  const objectFormat = runGit(["rev-parse", "--show-object-format"], cwd, tool, options).stdout.trim();
  const { files, directories } = parseHeadTree(cwd, tool, options, objectFormat, label);
  const ignored = allowIgnoredExtras
    ? ignoredWorktreePaths(cwd, tool, options, label)
    : { files: new Set(), directories: new Set() };
  const verificationRoot = fs.mkdtempSync(path.join(tool.sessionRoot, "checkout-"));
  if (process.platform !== "win32") fs.chmodSync(verificationRoot, 0o700);
  try {
    const canonicalRoot = path.join(verificationRoot, "tree");
    fs.mkdirSync(canonicalRoot, { mode: 0o700 });
    const verificationEnvironment = {
      GIT_INDEX_FILE: path.join(verificationRoot, "index"),
      GIT_WORK_TREE: canonicalRoot
    };
    runGit(["read-tree", "HEAD"], cwd, tool, options, new Set([0]), 30_000, verificationEnvironment);
    runGit(
      ["checkout-index", "--all", "--force", `--prefix=${canonicalRoot}${path.sep}`],
      cwd,
      tool,
      options,
      new Set([0]),
      300_000,
      verificationEnvironment
    );
    const unseenFiles = new Set(files.keys());
    const unseenDirectories = new Set(directories);
    const rootBytes = Buffer.from(root);
    const filesystemSeparator = Buffer.from(path.sep);
    const treeSeparator = Buffer.from("/");
    const stack = [{ filesystem: rootBytes, relative: Buffer.alloc(0) }];
    const deadline = Date.now() + RAW_VERIFICATION_TIMEOUT_MS;
    let entries = 0;
    let bytes = 0n;
    while (stack.length > 0) {
      if (Date.now() > deadline) throw rawStateError(label, "verification time limit exceeded");
      const directory = stack.pop();
      for (const entry of fs.readdirSync(directory.filesystem, { withFileTypes: true, encoding: "buffer" })) {
        entries += 1;
        if (entries > MAX_WORKTREE_FILES) {
          throw rawStateError(label, `filesystem exceeds the ${MAX_WORKTREE_FILES}-entry limit`);
        }
        const relative = directory.relative.length === 0
          ? entry.name
          : Buffer.concat([directory.relative, treeSeparator, entry.name]);
        const fullPath = Buffer.concat([directory.filesystem, filesystemSeparator, entry.name]);
        if (directory.relative.length === 0 && entry.name.equals(Buffer.from(".git"))) {
          const administrative = fs.lstatSync(fullPath, { bigint: true });
          if (administrative.isSymbolicLink() || (!administrative.isFile() && !administrative.isDirectory())) {
            throw rawStateError(label, "root Git administrative entry was unsafe");
          }
          if (administrative.isFile() && administrative.nlink !== 1n) {
            throw rawStateError(label, "root Git administrative file has multiple hard links");
          }
          continue;
        }
        const key = relative.toString("hex");
        const stat = fs.lstatSync(fullPath);
        if (stat.isDirectory() && !stat.isSymbolicLink()) {
          const trackedDirectory = unseenDirectories.delete(key);
          if (!trackedDirectory && !ignored.directories.has(key)) {
            throw rawStateError(label, "filesystem contained an extra directory");
          }
          stack.push({ filesystem: fullPath, relative });
          continue;
        }
        const expected = files.get(key);
        if (!expected || !unseenFiles.delete(key)) {
          if (ignored.files.has(key)) continue;
          throw rawStateError(label, "filesystem contained an extra path");
        }
        const canonicalPath = nativeTreePath(canonicalRoot, expected.relative);
        const canonicalStat = fs.lstatSync(canonicalPath);
        let size;
        if (canonicalStat.isSymbolicLink()) size = compareSymlinks(fullPath, canonicalPath, label);
        else size = compareRegularFiles(fullPath, canonicalPath, expected.mode, label, deadline);
        bytes += size;
        if (bytes > BigInt(MAX_WORKTREE_BYTES)) {
          throw rawStateError(label, `tracked content exceeds the ${MAX_WORKTREE_BYTES}-byte limit`);
        }
      }
    }
    if (unseenFiles.size > 0 || unseenDirectories.size > 0) {
      throw rawStateError(label, "tracked paths were missing");
    }
  } finally {
    assertNoWorkspaceMounts(verificationRoot, options);
    fs.rmSync(verificationRoot, { recursive: true, force: true });
  }
}

function commonGitDirectory(cwd, tool, options) {
  const raw = runGit(["rev-parse", "--git-common-dir"], cwd, tool, options).stdout.trim();
  if (!raw || /[\0\r\n]/u.test(raw)) throw new Error("Git returned an invalid common directory");
  return existingDirectory(path.isAbsolute(raw) ? raw : path.resolve(cwd, raw), "Git common directory");
}

function assertOwnedPhysicalDirectory(directory, label) {
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || !samePath(fs.realpathSync(directory), directory)) {
    throw new Error(`${label} must be a physical directory`);
  }
  if (process.platform !== "win32") {
    if (typeof process.geteuid === "function" && stat.uid !== process.geteuid()) {
      throw new Error(`${label} is not owned by the current user`);
    }
    if ((stat.mode & 0o022) !== 0) throw new Error(`${label} is group- or other-writable`);
  }
  return fs.realpathSync(directory);
}

function readStableOwnedFile(file, label, {
  maximum = MAX_JSON_BYTES,
  exactSize = null,
  ownerOnly = false,
  encoding = null
} = {}) {
  const before = fs.lstatSync(file);
  if (
    !before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size < 1 ||
    before.size > maximum || (exactSize !== null && before.size !== exactSize)
  ) throw new Error(`${label} must be a bounded regular single-link file`);
  if (process.platform !== "win32") {
    if (typeof process.geteuid === "function" && before.uid !== process.geteuid()) {
      throw new Error(`${label} is not owned by the current user`);
    }
    if ((before.mode & 0o022) !== 0 || (ownerOnly && (before.mode & 0o7777) !== 0o600)) {
      throw new Error(`${label} has unsafe permissions`);
    }
  }
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const opened = fs.fstatSync(descriptor);
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) {
      throw new Error(`${label} changed while it was opened`);
    }
    const content = fs.readFileSync(descriptor, encoding === null ? undefined : { encoding });
    const after = fs.fstatSync(descriptor);
    const final = fs.lstatSync(file);
    if (
      after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size ||
      after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs ||
      final.dev !== after.dev || final.ino !== after.ino || final.size !== after.size ||
      final.mtimeMs !== after.mtimeMs || final.ctimeMs !== after.ctimeMs
    ) throw new Error(`${label} changed while it was read`);
    return content;
  } finally {
    fs.closeSync(descriptor);
  }
}

function readStableAdminPointer(file, label) {
  const before = fs.lstatSync(file);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size < 1 || before.size > 16_384) {
    throw new Error(`${label} must be a bounded regular single-link file`);
  }
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const opened = fs.fstatSync(descriptor);
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) {
      throw new Error(`${label} changed while it was opened`);
    }
    const content = fs.readFileSync(descriptor, "utf8");
    const after = fs.fstatSync(descriptor);
    const final = fs.lstatSync(file);
    if (
      after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size ||
      after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs ||
      final.dev !== after.dev || final.ino !== after.ino || final.size !== after.size
    ) throw new Error(`${label} changed while it was read`);
    if (!content || /[\0\r]/u.test(content)) {
      throw new Error(`${label} is malformed`);
    }
    const normalized = content.endsWith("\n") ? content.slice(0, -1) : content;
    if (!normalized || normalized.includes("\n")) throw new Error(`${label} is malformed`);
    return normalized;
  } finally {
    fs.closeSync(descriptor);
  }
}

function absolutePointer(value, prefix, base, label) {
  if (!value.startsWith(prefix)) throw new Error(`${label} is malformed`);
  const raw = value.slice(prefix.length);
  if (!raw || /[\0\r\n]/u.test(raw)) throw new Error(`${label} is malformed`);
  const resolved = path.resolve(base, raw);
  if (!path.isAbsolute(raw)) throw new Error(`${label} must use an absolute path`);
  return resolved;
}

function registeredLinkedWorktreeAdmins(commonDirectory) {
  const worktreesRoot = path.join(commonDirectory, "worktrees");
  const worktreesStat = fs.lstatSync(worktreesRoot);
  if (!worktreesStat.isDirectory() || worktreesStat.isSymbolicLink()) {
    throw new Error("Git linked-worktree registry must be a physical directory");
  }
  const registeredRoot = fs.realpathSync(worktreesRoot);
  const entries = fs.readdirSync(registeredRoot, { withFileTypes: true });
  if (entries.length < 1 || entries.length > MAX_TASK_ROOTS) {
    throw new Error("Git linked-worktree registry is empty or unbounded");
  }
  const byMarker = new Map();
  for (const entry of entries) {
    if (!entry.isDirectory() || entry.isSymbolicLink()) {
      throw new Error("Git linked-worktree registry contains an unsafe entry");
    }
    const candidate = path.join(registeredRoot, entry.name);
    const candidateStat = fs.lstatSync(candidate);
    if (!candidateStat.isDirectory() || candidateStat.isSymbolicLink()) {
      throw new Error("Git linked-worktree registry entry is unsafe");
    }
    const administrative = fs.realpathSync(candidate);
    if (!samePath(path.dirname(administrative), registeredRoot)) {
      throw new Error("Git linked-worktree registry entry escaped its physical registry");
    }
    const pointer = absolutePointer(
      readStableAdminPointer(path.join(administrative, "gitdir"), "registered linked-worktree reverse pointer"),
      "",
      administrative,
      "registered linked-worktree reverse pointer"
    );
    const key = normalizedPathKey(pointer);
    const matches = byMarker.get(key) || [];
    matches.push(administrative);
    byMarker.set(key, matches);
  }
  return { registeredRoot, byMarker };
}

function assertRegisteredLinkedWorktree(worktree, adminRegistry, tool, options) {
  if (!adminRegistry) throw new Error("Git linked-worktree registry was not inspected");
  const marker = path.join(fs.realpathSync(worktree), ".git");
  const markerTarget = absolutePointer(
    readStableAdminPointer(marker, "linked-worktree .git marker"),
    "gitdir: ",
    worktree,
    "linked-worktree .git marker"
  );
  const targetStat = fs.lstatSync(markerTarget);
  if (!targetStat.isDirectory() || targetStat.isSymbolicLink()) {
    throw new Error("linked-worktree .git marker must target a physical administrative directory");
  }
  const activeOutput = runGit(
    ["rev-parse", "--path-format=absolute", "--absolute-git-dir"],
    worktree,
    tool,
    options
  ).stdout.trim();
  if (!activeOutput || /[\0\r\n]/u.test(activeOutput) || !path.isAbsolute(activeOutput)) {
    throw new Error("Git returned an invalid linked-worktree administrative directory");
  }
  const active = fs.realpathSync(activeOutput);
  if (!samePath(active, fs.realpathSync(markerTarget))) {
    throw new Error("linked-worktree .git marker redirects away from its active administrative directory");
  }
  if (!samePath(path.dirname(active), adminRegistry.registeredRoot)) {
    throw new Error("linked-worktree administrative directory is not a direct registered entry");
  }
  const reverse = absolutePointer(
    readStableAdminPointer(path.join(active, "gitdir"), "linked-worktree reverse pointer"),
    "",
    active,
    "linked-worktree reverse pointer"
  );
  if (!samePath(reverse, marker)) throw new Error("linked-worktree reverse pointer does not name the workspace .git marker");
  const matches = adminRegistry.byMarker.get(normalizedPathKey(marker)) || [];
  if (matches.length !== 1 || !samePath(matches[0], active)) {
    throw new Error("workspace .git marker does not have one unique registered administrative directory");
  }
}

function assertNoInProgressGitOperation(cwd, label, tool, options) {
  const raw = runGit(["rev-parse", "--absolute-git-dir"], cwd, tool, options).stdout.trim();
  if (!raw || /[\0\r\n]/u.test(raw)) throw new Error(`Git returned an invalid ${label} administrative directory`);
  const gitDirectory = existingDirectory(raw, `${label} administrative directory`);
  const sentinels = [
    "AUTO_MERGE",
    "BISECT_ANCESTORS_OK",
    "BISECT_EXPECTED_REV",
    "BISECT_LOG",
    "BISECT_NAMES",
    "BISECT_START",
    "BISECT_TERMS",
    "CHERRY_PICK_HEAD",
    "MERGE_HEAD",
    "MERGE_MODE",
    "MERGE_MSG",
    "MERGE_RR",
    "REBASE_HEAD",
    "REVERT_HEAD",
    "SQUASH_MSG",
    "rebase-apply",
    "rebase-merge",
    "sequencer"
  ];
  for (const sentinel of sentinels) {
    try {
      fs.lstatSync(path.join(gitDirectory, sentinel));
      throw new Error(`${label} has an in-progress Git operation (${sentinel}) and will remain leased`);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
}

function assertAbsentGitLock(candidate, label) {
  try {
    fs.lstatSync(candidate);
    throw new Error(`${label} exists; workspace state is not quiescent`);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

function assertNoRefLocks(commonDirectory, label) {
  const refsRoot = path.join(commonDirectory, "refs");
  let rootStat;
  try {
    rootStat = fs.lstatSync(refsRoot);
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new Error(`${label} refs registry must be a physical directory`);
  }

  const stack = [{ directory: refsRoot, depth: 0 }];
  let entries = 0;
  let pathBytes = Buffer.byteLength(refsRoot);
  while (stack.length > 0) {
    const current = stack.pop();
    if (current.depth > 256) throw new Error(`${label} refs registry exceeds the supported depth`);
    const handle = fs.opendirSync(current.directory);
    try {
      let entry;
      while ((entry = handle.readSync()) !== null) {
        entries += 1;
        pathBytes += Buffer.byteLength(entry.name) + 1;
        if (entries > MAX_WORKTREE_FILES || pathBytes > MAX_TREE_BYTES) {
          throw new Error(`${label} refs registry is unbounded`);
        }
        const candidate = path.join(current.directory, entry.name);
        const stat = fs.lstatSync(candidate);
        if (entry.name.endsWith(".lock")) {
          throw new Error(`${label} has an active or stale Git ref lock (${path.relative(commonDirectory, candidate)})`);
        }
        if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile())) {
          throw new Error(`${label} refs registry contains a non-physical entry`);
        }
        if (stat.isDirectory()) stack.push({ directory: candidate, depth: current.depth + 1 });
      }
    } finally {
      try {
        handle.closeSync();
      } catch (error) {
        if (error.code !== "ERR_DIR_CLOSED") throw error;
      }
    }
  }
}

function gitAdministrativeDirectory(cwd, label, tool, options) {
  const raw = runGit(
    ["rev-parse", "--path-format=absolute", "--absolute-git-dir"],
    cwd,
    tool,
    options
  ).stdout.trim();
  if (!raw || /[\0\r\n]/u.test(raw) || !path.isAbsolute(raw)) {
    throw new Error(`Git returned an invalid ${label} administrative directory`);
  }
  return assertOwnedPhysicalDirectory(raw, `${label} administrative directory`);
}

function assertNoWorktreeTransactionLocks(cwd, label, tool, options) {
  const administrative = gitAdministrativeDirectory(cwd, label, tool, options);
  for (const name of ["index.lock", "HEAD.lock", "config.worktree.lock"]) {
    assertAbsentGitLock(path.join(administrative, name), `${label} ${name}`);
  }
  assertNoRefLocks(administrative, `${label} private Git repository`);
}

function assertNoCommonGitTransactionLocks(cwd, tool, options) {
  const commonDirectory = assertOwnedPhysicalDirectory(
    commonGitDirectory(cwd, tool, options),
    "shared common Git directory"
  );
  for (const name of ["config.lock", "shallow.lock", "packed-refs.lock"]) {
    assertAbsentGitLock(path.join(commonDirectory, name), `shared Git ${name}`);
  }
  assertNoRefLocks(commonDirectory, "shared Git repository");
}

function assertUnmodifiedObjectGraph(commonDirectory, cwd, tool, options) {
  const forbidden = [
    [path.join(commonDirectory, "info", "grafts"), "Git grafts"],
    [path.join(commonDirectory, "objects", "info", "alternates"), "Git object alternates"],
    [path.join(commonDirectory, "objects", "info", "http-alternates"), "Git HTTP object alternates"]
  ];
  for (const [candidate, label] of forbidden) {
    try {
      fs.lstatSync(candidate);
      throw new Error(`${label} are incompatible with workspace landing verification`);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
  const replacements = runGit(
    ["for-each-ref", "--format=%(refname)", "refs/replace"],
    cwd,
    tool,
    options
  ).stdout.trim();
  if (replacements) throw new Error("Git replacement refs are incompatible with workspace landing verification");
}

function assertObjectIntegrity(cwd, tool, options) {
  runGit(
    ["fsck", "--full", "--strict", "--no-reflogs", "--no-dangling", "--no-progress"],
    cwd,
    tool,
    options,
    new Set([0]),
    300_000
  );
}

function parseJson(stdout, label) {
  if (Buffer.byteLength(stdout, "utf8") > MAX_JSON_BYTES) throw new Error(`${label} output exceeded ${MAX_JSON_BYTES} bytes`);
  try {
    return JSON.parse(stdout);
  } catch {
    throw new Error(`${label} did not return valid JSON`);
  }
}

function normalizeLease(value, expectedHolder = null) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Treehouse lease output must be an object");
  const workspacePath = existingDirectory(value.path, "Treehouse workspace path");
  const leaseId = boundedString(value.lease_id, "Treehouse lease id", { maximum: 32 });
  if (!LEASE_ID.test(leaseId)) throw new Error("Treehouse lease id must be a 128-bit lowercase hexadecimal value");
  const leaseHolder = boundedString(value.lease_holder, "Treehouse lease holder", { maximum: 160 });
  if (expectedHolder && leaseHolder !== expectedHolder) throw new Error("Treehouse returned a different lease holder");
  const leasedAt = boundedString(value.leased_at, "Treehouse lease timestamp", { maximum: 80 });
  if (!Number.isFinite(Date.parse(leasedAt))) throw new Error("Treehouse lease timestamp is invalid");
  const baseBranch = boundedString(value.base_branch, "Treehouse base branch", { allowEmpty: true, minimum: 0, maximum: 240 });
  if (baseBranch) gitRef(baseBranch, "Treehouse base branch");
  return { path: workspacePath, leaseId, leaseHolder, leasedAt, baseBranch };
}

function trustedTreehouse(paths, options) {
  const statusReader = options.readUpstreamStatus || readUpstreamStatus;
  const resolver = options.resolveUpstreamBinary || resolveUpstreamBinary;
  const entries = statusReader({ paths, verifyIntegrity: true });
  const entry = Array.isArray(entries) ? entries.find((candidate) => candidate.id === TREEHOUSE_ID) : null;
  if (!entry || entry.ready !== true || entry.integrityState !== "verified") {
    throw new Error("Treehouse is absent or not integrity-verified; run: gate upstream install treehouse");
  }
  const tool = resolver(TREEHOUSE_ID, null, { paths });
  if (!tool || tool.id !== TREEHOUSE_ID || typeof tool.executable !== "string" || !path.isAbsolute(tool.executable)) {
    throw new Error("Treehouse executable resolution did not return the reviewed executable");
  }
  return { entry, executable: tool.executable };
}

function cloneBindingValue(repository) {
  const repositoryStat = fs.lstatSync(repository, { bigint: true });
  const gitMarker = path.join(repository, ".git");
  const gitStat = fs.lstatSync(gitMarker, { bigint: true });
  if (!repositoryStat.isDirectory() || repositoryStat.isSymbolicLink()) {
    throw new Error("repository binding requires a physical main worktree directory");
  }
  if (!gitStat.isDirectory() || gitStat.isSymbolicLink()) {
    throw new Error("repository binding requires a physical main .git directory");
  }
  return {
    version: 1,
    repository,
    repositoryDevice: repositoryStat.dev.toString(),
    repositoryInode: repositoryStat.ino.toString(),
    gitDirectory: fs.realpathSync(gitMarker),
    gitDevice: gitStat.dev.toString(),
    gitInode: gitStat.ino.toString()
  };
}

function assertCloneBinding(treehouseRoot, repository) {
  const bindingPath = path.join(treehouseRoot, ".gate-clone-binding.json");
  const expected = cloneBindingValue(repository);
  let present = false;
  try {
    present = fs.lstatSync(bindingPath);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (!present) {
    if (fs.readdirSync(treehouseRoot).length !== 0) {
      throw new Error("clone-specific Treehouse root has no durable binding and is not empty; reconcile it manually");
    }
    let descriptor;
    try {
      descriptor = fs.openSync(
        bindingPath,
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0),
        0o600
      );
      fs.writeFileSync(descriptor, `${JSON.stringify(expected)}\n`, "utf8");
      fs.fsyncSync(descriptor);
    } finally {
      if (descriptor !== undefined) fs.closeSync(descriptor);
    }
  }
  const before = fs.lstatSync(bindingPath);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > 16_384) {
    throw new Error("clone-specific Treehouse binding must be a bounded regular single-link file");
  }
  if (process.platform !== "win32") {
    if (typeof process.geteuid === "function" && before.uid !== process.geteuid()) {
      throw new Error("clone-specific Treehouse binding is not owned by the current user");
    }
    if ((before.mode & 0o7777) !== 0o600) throw new Error("clone-specific Treehouse binding must be owner-only");
  }
  const actual = JSON.parse(fs.readFileSync(bindingPath, "utf8"));
  const after = fs.lstatSync(bindingPath);
  if (
    before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
    before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs
  ) throw new Error("clone-specific Treehouse binding changed while it was read");
  if (
    !actual || typeof actual !== "object" || Array.isArray(actual) ||
    Object.keys(actual).length !== Object.keys(expected).length ||
    Object.entries(expected).some(([key, value]) => actual[key] !== value)
  ) {
    throw new Error("clone-specific Treehouse root is bound to a different physical repository; reconcile it manually");
  }
}

function taskRootIdentity(taskId) {
  return crypto.createHash("sha256").update(taskId).digest("hex");
}

function taskBindingValue(repository, taskId) {
  return {
    ...cloneBindingValue(repository),
    taskId,
    taskHash: taskRootIdentity(taskId)
  };
}

function writeTaskBinding(taskRoot, repository, taskId) {
  const bindingPath = path.join(taskRoot, ".gate-task-binding.json");
  const expected = taskBindingValue(repository, taskId);
  const descriptor = fs.openSync(
    bindingPath,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0),
    0o600
  );
  try {
    fs.writeFileSync(descriptor, `${JSON.stringify(expected)}\n`, "utf8");
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function fsyncDirectory(directory) {
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0));
  try {
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function readTaskBinding(taskRoot, repository) {
  const bindingPath = path.join(taskRoot, ".gate-task-binding.json");
  const before = fs.lstatSync(bindingPath);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > 16_384) {
    throw new Error("task-specific Treehouse binding must be a bounded regular single-link file");
  }
  if (process.platform !== "win32") {
    if (typeof process.geteuid === "function" && before.uid !== process.geteuid()) {
      throw new Error("task-specific Treehouse binding is not owned by the current user");
    }
    if ((before.mode & 0o7777) !== 0o600) throw new Error("task-specific Treehouse binding must be owner-only");
  }
  const actual = JSON.parse(fs.readFileSync(bindingPath, "utf8"));
  const taskId = taskIdentifier(actual?.taskId);
  const expected = taskBindingValue(repository, taskId);
  const after = fs.lstatSync(bindingPath);
  if (
    before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
    before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs
  ) throw new Error("task-specific Treehouse binding changed while it was read");
  if (
    !actual || typeof actual !== "object" || Array.isArray(actual) ||
    Object.keys(actual).length !== Object.keys(expected).length ||
    Object.entries(expected).some(([key, value]) => actual[key] !== value) ||
    path.basename(taskRoot) !== expected.taskHash
  ) {
    throw new Error("task-specific Treehouse root binding is invalid or belongs to another repository");
  }
  return { taskId, taskHash: expected.taskHash };
}

function activateTaskRoot(tool, repository, taskId, { create = false, options = {} } = {}) {
  const taskHash = taskRootIdentity(taskId);
  const taskRoot = path.join(tool.tasksRoot, taskHash);
  if (create) {
    try {
      fs.lstatSync(taskRoot);
      throw new Error("task id already has a burned or active Treehouse root; choose a new task id");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    if (listTaskRoots(tool, repository).length >= MAX_TASK_ROOTS) {
      throw new Error(`task-specific Treehouse root capacity (${MAX_TASK_ROOTS}) is exhausted before creating a new lease`);
    }
    const preparedRoot = fs.mkdtempSync(path.join(tool.sessionRoot, "task-root-"));
    if (process.platform !== "win32") fs.chmodSync(preparedRoot, 0o700);
    try {
      writeTaskBinding(preparedRoot, repository, taskId);
      fsyncDirectory(preparedRoot);
      if (options.runner && typeof options.beforeTaskRootPublish === "function") {
        options.beforeTaskRootPublish({ preparedRoot, taskRoot });
      }
      fs.renameSync(preparedRoot, taskRoot);
      fsyncDirectory(tool.tasksRoot);
    } catch (error) {
      if (error.code === "EEXIST") {
        throw new Error("task id already has a burned or active Treehouse root; choose a new task id");
      }
      throw error;
    }
  } else {
    securePrivateDirectory(taskRoot, { create: false, label: "GATE-owned task-specific Treehouse root" });
  }
  const binding = readTaskBinding(taskRoot, repository);
  if (binding.taskId !== taskId) throw new Error("task-specific Treehouse root belongs to a different task id");
  return {
    ...tool,
    environment: treehouseEnvironment(taskRoot, tool.childHome, tool.childTemporary, tool.safePath),
    treehouseRoot: taskRoot,
    taskId
  };
}

function listTaskRoots(tool, repository) {
  const entries = fs.readdirSync(tool.tasksRoot, { withFileTypes: true });
  if (entries.length > MAX_TASK_ROOTS) throw new Error("task-specific Treehouse root registry is unbounded");
  return entries.map((entry) => {
    if (!entry.isDirectory() || entry.isSymbolicLink() || !/^[a-f0-9]{64}$/u.test(entry.name)) {
      throw new Error("task-specific Treehouse root registry contains an invalid entry");
    }
    const taskRoot = securePrivateDirectory(path.join(tool.tasksRoot, entry.name), {
      create: false,
      label: "GATE-owned task-specific Treehouse root"
    });
    const binding = readTaskBinding(taskRoot, repository);
    return { taskRoot, ...binding };
  });
}

function assertExactDirectoryEntries(directory, expected, label) {
  const actual = fs.readdirSync(directory, { withFileTypes: true });
  const names = actual.map((entry) => entry.name).sort();
  const wanted = [...expected].sort();
  if (names.length !== wanted.length || names.some((name, index) => name !== wanted[index])) {
    throw new Error(`${label} contains unexpected or missing entries`);
  }
  return new Map(actual.map((entry) => [entry.name, entry]));
}

function assertOwnedRegularFileMetadata(file, label, { allowEmpty = true, ownerOnly = false } = {}) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (!allowEmpty && stat.size < 1)) {
    throw new Error(`${label} must be a regular single-link file`);
  }
  if (process.platform !== "win32") {
    if (typeof process.geteuid === "function" && stat.uid !== process.geteuid()) {
      throw new Error(`${label} is not owned by the current user`);
    }
    if ((stat.mode & 0o022) !== 0 || (ownerOnly && (stat.mode & 0o7777) !== 0o600)) {
      throw new Error(`${label} has unsafe permissions`);
    }
  }
}

function treehouseLayout(taskRoot, workspacePath, { leaseBinding = "required" } = {}) {
  const root = assertOwnedPhysicalDirectory(taskRoot, "task-specific Treehouse root");
  const workspace = assertOwnedPhysicalDirectory(workspacePath, "Treehouse workspace path");
  const relative = path.relative(root, workspace);
  const components = relative.split(path.sep);
  if (
    relative === "" || relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative) ||
    components.length !== 4 || components[0] !== ".treehouse" ||
    components.some((component) => !component || component === "." || component === "..")
  ) {
    throw new Error("Treehouse workspace does not have the forced {pool}/{slot}/{repo} layout");
  }
  const [, poolName, slotName, repositoryName] = components;
  if (slotName !== "1") throw new Error("one-shot Treehouse root did not allocate the expected first slot");
  const poolRoot = assertOwnedPhysicalDirectory(path.join(root, ".treehouse"), "Treehouse pool root");
  const poolDirectory = assertOwnedPhysicalDirectory(path.join(poolRoot, poolName), "Treehouse pool directory");
  const slotDirectory = assertOwnedPhysicalDirectory(path.join(poolDirectory, slotName), "Treehouse slot directory");
  if (!samePath(path.join(slotDirectory, repositoryName), workspace)) {
    throw new Error("Treehouse workspace escaped its forced pool layout");
  }

  const taskEntries = new Set([".gate-task-binding.json", ".treehouse"]);
  if (leaseBinding === "required") taskEntries.add(LEASE_BINDING_FILE);
  if (leaseBinding === "optional" && fs.existsSync(path.join(root, LEASE_BINDING_FILE))) {
    taskEntries.add(LEASE_BINDING_FILE);
  }
  assertExactDirectoryEntries(root, taskEntries, "task-specific Treehouse root");
  assertExactDirectoryEntries(poolRoot, new Set([".gitignore", poolName]), "Treehouse pool root");
  const ignore = readStableOwnedFile(path.join(poolRoot, ".gitignore"), "Treehouse root ignore file", {
    maximum: 16,
    encoding: "utf8"
  });
  if (ignore !== "*\n") throw new Error("Treehouse root ignore file is not the reviewed self-ignore rule");

  const stateFile = path.join(poolDirectory, "treehouse-state.json");
  const keyFile = path.join(poolDirectory, "treehouse-state.key");
  const lockFile = path.join(poolDirectory, "treehouse-state.lock");
  assertExactDirectoryEntries(
    poolDirectory,
    new Set(["treehouse-state.json", "treehouse-state.key", "treehouse-state.lock", slotName]),
    "Treehouse pool directory"
  );
  assertOwnedRegularFileMetadata(lockFile, "Treehouse state lock file");
  assertExactDirectoryEntries(slotDirectory, new Set([repositoryName]), "Treehouse slot directory");
  return { root, workspace, poolRoot, poolDirectory, slotDirectory, slotName, stateFile, keyFile, lockFile };
}

function plainJsonObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error(`${label} must be a JSON object`);
  }
  return value;
}

function exactObjectKeys(value, allowed, label) {
  const unexpected = Object.keys(value).find((key) => !allowed.has(key));
  if (unexpected) throw new Error(`${label} contains an unsupported field (${unexpected})`);
}

function stateString(value, label, { maximum = 4096, allowEmpty = false } = {}) {
  if (typeof value !== "string" || (!allowEmpty && value.length < 1) || value.length > maximum || value.includes("\0")) {
    throw new Error(`${label} is malformed`);
  }
  return value;
}

function goJsonMarshal(value) {
  return JSON.stringify(value).replace(/[<>&\u2028\u2029]/gu, (character) => {
    return `\\u${character.codePointAt(0).toString(16).padStart(4, "0")}`;
  });
}

function validateSeedInventory(entry, key) {
  const rawSeededPaths = entry.seeded_paths === undefined ? [] : entry.seeded_paths;
  if (entry.seed_inventory_known !== true || !Array.isArray(rawSeededPaths) || rawSeededPaths.length > 100_000) {
    throw new Error("Treehouse state has an unknown or unbounded seeded-path inventory");
  }
  let total = 0;
  const seededPaths = rawSeededPaths.map((value) => {
    const seededPath = stateString(value, "Treehouse seeded path", { maximum: 4096 });
    total += Buffer.byteLength(seededPath);
    if (
      total > MAX_TREE_BYTES || path.posix.isAbsolute(seededPath) || path.posix.normalize(seededPath) !== seededPath ||
      seededPath.includes("\\") || [".git", ".jj"].includes(seededPath.split("/", 1)[0].toLowerCase())
    ) throw new Error("Treehouse state contains an unsafe seeded path");
    return seededPath;
  });
  const seedBackend = stateString(entry.seed_backend ?? "", "Treehouse seed backend", {
    maximum: 40,
    allowEmpty: true
  });
  const seedAuthIdentity = stateString(entry.seed_auth_identity ?? "", "Treehouse seed authentication identity", {
    maximum: 4096,
    allowEmpty: true
  });
  if ((seededPaths.length === 0 && (seedBackend || seedAuthIdentity)) ||
      (seededPaths.length > 0 && (seedBackend !== "git" || seedAuthIdentity))) {
    throw new Error("Treehouse state contains invalid seeded-path authentication metadata");
  }
  const supplied = stateString(entry.seed_inventory_digest, "Treehouse seed inventory digest", { maximum: 64 });
  if (!/^[a-f0-9]{64}$/u.test(supplied)) throw new Error("Treehouse seed inventory digest is malformed");
  const payload = goJsonMarshal({
    name: entry.name,
    path: path.normalize(entry.path),
    seeded_paths: seededPaths,
    seed_backend: seedBackend,
    seed_auth_identity: seedAuthIdentity
  });
  const expected = crypto.createHmac("sha256", key).update(payload).digest();
  const actual = Buffer.from(supplied, "hex");
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
    throw new Error("Treehouse state seeded-path inventory authentication failed");
  }
  return seededPaths;
}

const TREEHOUSE_STATE_ENTRY_FIELDS = new Set([
  "name", "path", "created_at", "destroying", "owner_pid", "owner_started_at", "leased", "lease_id",
  "lease_holder", "leased_at", "base_branch", "seeded_paths", "seed_inventory_known", "seed_inventory_digest",
  "seed_backend", "seed_auth_identity", "recovery_error", "recovery_reason"
]);

function readTreehouseState(taskRoot, workspacePath, expected = {}, { leaseBinding = "required" } = {}) {
  const layout = treehouseLayout(taskRoot, workspacePath, { leaseBinding });
  const stateBytes = readStableOwnedFile(layout.stateFile, "Treehouse state file", { maximum: MAX_JSON_BYTES });
  const key = readStableOwnedFile(layout.keyFile, "Treehouse state key", {
    maximum: 32,
    exactSize: 32,
    ownerOnly: true
  });
  let state;
  try {
    state = JSON.parse(stateBytes.toString("utf8"));
  } catch {
    throw new Error("Treehouse state file is not valid JSON");
  }
  plainJsonObject(state, "Treehouse state");
  exactObjectKeys(state, new Set(["version", "worktrees"]), "Treehouse state");
  if (state.version !== TREEHOUSE_STATE_VERSION || !Array.isArray(state.worktrees) || state.worktrees.length !== 1) {
    throw new Error("Treehouse state must be version 4 with exactly one one-shot worktree entry");
  }
  const entry = plainJsonObject(state.worktrees[0], "Treehouse state worktree entry");
  exactObjectKeys(entry, TREEHOUSE_STATE_ENTRY_FIELDS, "Treehouse state worktree entry");
  const name = stateString(entry.name, "Treehouse state worktree name", { maximum: 160 });
  const entryPath = stateString(entry.path, "Treehouse state worktree path", { maximum: 4096 });
  if (name !== layout.slotName || !path.isAbsolute(entryPath) || entryPath !== path.resolve(entryPath) ||
      !samePath(entryPath, layout.workspace) || !samePath(fs.realpathSync(entryPath), layout.workspace)) {
    throw new Error("Treehouse state worktree identity does not match the forced pool layout");
  }
  const createdAt = stateString(entry.created_at, "Treehouse state creation timestamp", { maximum: 80 });
  const leasedAt = stateString(entry.leased_at, "Treehouse state lease timestamp", { maximum: 80 });
  if (!Number.isFinite(Date.parse(createdAt)) || !Number.isFinite(Date.parse(leasedAt))) {
    throw new Error("Treehouse state contains an invalid timestamp");
  }
  const leaseId = stateString(entry.lease_id, "Treehouse state lease id", { maximum: 32 });
  const leaseHolder = stateString(entry.lease_holder, "Treehouse state lease holder", { maximum: 160 });
  const baseBranch = stateString(entry.base_branch ?? "", "Treehouse state base branch", {
    maximum: 240,
    allowEmpty: true
  });
  if (baseBranch) gitRef(baseBranch, "Treehouse state base branch");
  if (
    entry.leased !== true || !LEASE_ID.test(leaseId) || entry.destroying === true ||
    (entry.owner_pid ?? 0) !== 0 || (entry.owner_started_at ?? 0) !== 0 ||
    (entry.recovery_error ?? "") !== "" || (entry.recovery_reason ?? "") !== ""
  ) throw new Error("Treehouse state entry is not one healthy durable lease");
  if (entry.destroying !== undefined && entry.destroying !== false) throw new Error("Treehouse state destroying flag is malformed");
  if (!Number.isSafeInteger(entry.owner_pid ?? 0) || !Number.isSafeInteger(entry.owner_started_at ?? 0)) {
    throw new Error("Treehouse state owner fields are malformed");
  }
  const seededPaths = validateSeedInventory(entry, key);
  if (expected.leaseId && leaseId !== expected.leaseId) throw new Error("Treehouse state lease identity does not match the trusted acquisition receipt");
  if (expected.leaseHolder && leaseHolder !== expected.leaseHolder) throw new Error("Treehouse state lease holder does not match the trusted acquisition receipt");
  if (expected.leasedAt && leasedAt !== expected.leasedAt) throw new Error("Treehouse state lease timestamp does not match the trusted acquisition receipt");
  if (Object.hasOwn(expected, "baseBranch") && baseBranch !== (expected.baseBranch || "")) {
    throw new Error("Treehouse state base branch does not match the trusted acquisition receipt");
  }
  const finalLayout = treehouseLayout(taskRoot, workspacePath, { leaseBinding });
  if (!samePath(finalLayout.poolDirectory, layout.poolDirectory)) {
    throw new Error("Treehouse pool layout changed while state was inspected");
  }
  return {
    layout,
    entry: { name, path: layout.workspace, leaseId, leaseHolder, leasedAt, baseBranch, seededPaths },
    stateSha256: crypto.createHash("sha256").update(stateBytes).digest("hex"),
    keySha256: crypto.createHash("sha256").update(key).digest("hex")
  };
}

function providerLeaseBindingValue(repository, taskId, branch, lease, snapshot) {
  return {
    ...taskBindingValue(repository, taskId),
    workspacePath: snapshot.layout.workspace,
    poolDirectory: snapshot.layout.poolDirectory,
    branch,
    leaseId: lease.leaseId,
    leaseHolder: lease.leaseHolder,
    leasedAt: lease.leasedAt,
    baseBranch: lease.baseBranch,
    stateSha256: snapshot.stateSha256,
    keySha256: snapshot.keySha256
  };
}

function leaseBindingValue(repository, taskId, branch, lease, snapshot, event) {
  if (!event || typeof event !== "object" || Array.isArray(event)) {
    throw new Error("workspace lease event receipt is unavailable");
  }
  const eventId = boundedString(event.id, "workspace lease event id", { maximum: 160 });
  if (event.kind !== "workspace.leased" || event.taskId !== taskId ||
      event.effect?.targetRef !== `private://workspaces/${lease.leaseId}`) {
    throw new Error("workspace lease event receipt does not match the acquired lease");
  }
  return {
    ...providerLeaseBindingValue(repository, taskId, branch, lease, snapshot),
    phase: "complete",
    eventId,
    eventSha256: crypto.createHash("sha256").update(JSON.stringify(event)).digest("hex")
  };
}

function pendingLeaseBindingValue(repository, taskId, branch, leaseHolder, baseBranch) {
  return {
    ...taskBindingValue(repository, taskId),
    phase: "pending",
    branch,
    leaseHolder,
    requestedBaseBranch: baseBranch || ""
  };
}

function writePendingLeaseBinding(repository, tool, branch, leaseHolder, baseBranch) {
  const bindingPath = path.join(tool.treehouseRoot, LEASE_BINDING_FILE);
  const value = pendingLeaseBindingValue(repository, tool.taskId, branch, leaseHolder, baseBranch);
  let descriptor;
  try {
    descriptor = fs.openSync(
      bindingPath,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0),
      0o600
    );
    fs.writeFileSync(descriptor, `${JSON.stringify(value)}\n`, "utf8");
    fs.fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  fsyncDirectory(tool.treehouseRoot);
  return value;
}

function readPendingLeaseBinding(repository, tool) {
  const bindingPath = path.join(tool.treehouseRoot, LEASE_BINDING_FILE);
  const raw = readStableOwnedFile(bindingPath, "pending GATE Treehouse lease binding", {
    maximum: 32_768,
    ownerOnly: true,
    encoding: "utf8"
  });
  let value;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error("pending GATE Treehouse lease binding is not valid JSON");
  }
  plainJsonObject(value, "pending GATE Treehouse lease binding");
  const fields = new Set([
    "version", "repository", "repositoryDevice", "repositoryInode", "gitDirectory", "gitDevice", "gitInode",
    "taskId", "taskHash", "phase", "branch", "leaseHolder", "requestedBaseBranch"
  ]);
  exactObjectKeys(value, fields, "pending GATE Treehouse lease binding");
  if (Object.keys(value).length !== fields.size || value.phase !== "pending") {
    throw new Error("pending GATE Treehouse lease binding is incomplete");
  }
  const taskId = taskIdentifier(value.taskId);
  const expectedTask = taskBindingValue(repository, taskId);
  if (Object.entries(expectedTask).some(([key, expected]) => value[key] !== expected) ||
      taskId !== tool.taskId || path.basename(tool.treehouseRoot) !== value.taskHash) {
    throw new Error("pending GATE Treehouse lease binding belongs to another physical repository or task");
  }
  const branch = gitRef(value.branch, "pending workspace branch");
  const leaseHolder = stateString(value.leaseHolder, "pending Treehouse lease holder", { maximum: 160 });
  const requestedBaseBranch = stateString(value.requestedBaseBranch, "pending Treehouse base branch", {
    maximum: 240,
    allowEmpty: true
  });
  if (leaseHolder !== `${TREEHOUSE_HOLDER_PREFIX}${taskId}`) {
    throw new Error("pending GATE Treehouse lease holder is invalid");
  }
  if (requestedBaseBranch) gitRef(requestedBaseBranch, "pending Treehouse base branch");
  return { ...value, taskId, branch, leaseHolder, requestedBaseBranch };
}

function writeLeaseBinding(repository, tool, branch, lease, snapshot, event, options = {}) {
  const pending = readPendingLeaseBinding(repository, tool);
  if (pending.branch !== branch || pending.leaseHolder !== lease.leaseHolder ||
      (pending.requestedBaseBranch && pending.requestedBaseBranch !== snapshot.entry.baseBranch)) {
    throw new Error("pending GATE Treehouse lease binding does not match the acquisition receipt");
  }
  const bindingPath = path.join(tool.treehouseRoot, LEASE_BINDING_FILE);
  const preparedPath = path.join(tool.sessionRoot, `lease-binding-${crypto.randomBytes(12).toString("hex")}`);
  const value = leaseBindingValue(repository, tool.taskId, branch, lease, snapshot, event);
  let descriptor;
  try {
    descriptor = fs.openSync(
      preparedPath,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0),
      0o600
    );
    fs.writeFileSync(descriptor, `${JSON.stringify(value)}\n`, "utf8");
    fs.fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  if (options.runner && typeof options.beforeLeaseReadyPublish === "function") {
    options.beforeLeaseReadyPublish({ preparedPath, bindingPath });
  }
  fs.renameSync(preparedPath, bindingPath);
  fsyncDirectory(tool.treehouseRoot);
  return value;
}

const LEASE_BINDING_FIELDS = new Set([
  "version", "repository", "repositoryDevice", "repositoryInode", "gitDirectory", "gitDevice", "gitInode",
  "taskId", "taskHash", "phase", "workspacePath", "poolDirectory", "branch", "leaseId", "leaseHolder", "leasedAt",
  "baseBranch", "stateSha256", "keySha256", "eventId", "eventSha256"
]);

function readLeaseBinding(repository, tool) {
  const bindingPath = path.join(tool.treehouseRoot, LEASE_BINDING_FILE);
  const raw = readStableOwnedFile(bindingPath, "GATE Treehouse lease binding", {
    maximum: 32_768,
    ownerOnly: true,
    encoding: "utf8"
  });
  let value;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error("GATE Treehouse lease binding is not valid JSON");
  }
  plainJsonObject(value, "GATE Treehouse lease binding");
  exactObjectKeys(value, LEASE_BINDING_FIELDS, "GATE Treehouse lease binding");
  if (Object.keys(value).length !== LEASE_BINDING_FIELDS.size || value.phase !== "complete") {
    throw new Error("GATE Treehouse lease binding is incomplete");
  }
  const taskId = taskIdentifier(value.taskId);
  const expectedTask = taskBindingValue(repository, taskId);
  if (Object.entries(expectedTask).some(([key, expected]) => value[key] !== expected) ||
      taskId !== tool.taskId || path.basename(tool.treehouseRoot) !== value.taskHash) {
    throw new Error("GATE Treehouse lease binding belongs to another physical repository or task");
  }
  const workspacePath = existingDirectory(value.workspacePath, "bound Treehouse workspace path");
  const poolDirectory = existingDirectory(value.poolDirectory, "bound Treehouse pool directory");
  const branch = gitRef(value.branch, "bound workspace branch");
  const leaseId = stateString(value.leaseId, "bound Treehouse lease id", { maximum: 32 });
  const leaseHolder = stateString(value.leaseHolder, "bound Treehouse lease holder", { maximum: 160 });
  const leasedAt = stateString(value.leasedAt, "bound Treehouse lease timestamp", { maximum: 80 });
  const baseBranch = stateString(value.baseBranch ?? "", "bound Treehouse base branch", {
    maximum: 240,
    allowEmpty: true
  });
  if (!LEASE_ID.test(leaseId) || leaseHolder !== `${TREEHOUSE_HOLDER_PREFIX}${taskId}` || !Number.isFinite(Date.parse(leasedAt))) {
    throw new Error("GATE Treehouse lease binding contains an invalid lease identity");
  }
  if (baseBranch) gitRef(baseBranch, "bound Treehouse base branch");
  if (!/^[a-f0-9]{64}$/u.test(value.stateSha256) || !/^[a-f0-9]{64}$/u.test(value.keySha256)) {
    throw new Error("GATE Treehouse lease binding contains an invalid state digest");
  }
  const eventId = boundedString(value.eventId, "bound workspace lease event id", { maximum: 160 });
  if (!/^[a-f0-9]{64}$/u.test(value.eventSha256)) {
    throw new Error("GATE Treehouse lease binding contains an invalid event digest");
  }
  return {
    ...value,
    taskId,
    workspacePath,
    poolDirectory,
    branch,
    leaseId,
    leaseHolder,
    leasedAt,
    baseBranch,
    eventId
  };
}

function assertStateMatchesLeaseBinding(snapshot, binding) {
  if (
    !samePath(snapshot.layout.workspace, binding.workspacePath) ||
    !samePath(snapshot.layout.poolDirectory, binding.poolDirectory) ||
    snapshot.entry.leaseId !== binding.leaseId || snapshot.entry.leaseHolder !== binding.leaseHolder ||
    snapshot.entry.leasedAt !== binding.leasedAt || snapshot.stateSha256 !== binding.stateSha256 ||
    snapshot.keySha256 !== binding.keySha256
  ) throw new Error("Treehouse state no longer matches the immutable GATE lease binding; reconcile it manually");
}

function prepareTreehouse(paths, repository, workspacePath, options) {
  if (process.platform !== "linux") {
    throw new Error("workspace operations currently require Linux or WSL2 mount-boundary verification");
  }
  const reviewed = trustedTreehouse(paths, options);
  ensureRuntime(paths);
  const home = fs.realpathSync(paths.home);
  if (home.includes("$")) {
    throw new Error("GATE_HOME cannot contain '$' because Treehouse expands environment variables in TREEHOUSE_ROOT");
  }
  if (sameOrDescendant(repository, home) || sameOrDescendant(home, repository)) {
    throw new Error("GATE_HOME and the target repository must not overlap");
  }
  const treehouseBase = securePrivateDirectory(path.join(home, "treehouse"), {
    label: "GATE-owned Treehouse base directory"
  });
  const repositoryRoots = securePrivateDirectory(path.join(treehouseBase, "repos"), {
    label: "GATE-owned Treehouse repository roots directory"
  });
  const repositoryIdentity = crypto.createHash("sha256").update(repository).digest("hex");
  const repositoryRoot = securePrivateDirectory(path.join(repositoryRoots, repositoryIdentity), {
    label: "GATE-owned clone-specific Treehouse root"
  });
  assertCloneBinding(repositoryRoot, repository);
  const tasksRoot = securePrivateDirectory(path.join(repositoryRoot, "tasks"), {
    label: "GATE-owned task-specific Treehouse roots directory"
  });
  const temporaryRoot = securePrivateDirectory(path.join(repositoryRoot, "tmp"), {
    label: "GATE-owned Treehouse temporary directory"
  });
  const sessionRoot = fs.mkdtempSync(path.join(temporaryRoot, "operation-"));
  if (process.platform !== "win32") fs.chmodSync(sessionRoot, 0o700);
  const childHome = securePrivateDirectory(path.join(sessionRoot, "home"), {
    label: "GATE workspace operation home"
  });
  securePrivateDirectory(path.join(childHome, ".config"), {
    label: "GATE workspace operation config home"
  });
  const childTemporary = securePrivateDirectory(path.join(sessionRoot, "tmp"), {
    label: "GATE workspace operation temporary directory"
  });
  const protectedRoots = [home, repository];
  if (workspacePath) protectedRoots.push(workspacePath);
  const git = resolveGitExecution(protectedRoots, options.gitExecutable || null);
  return {
    ...reviewed,
    gitExecutable: git.executable,
    safePath: git.path,
    environment: null,
    gitEnvironment: controlledGitEnvironment(childHome, childTemporary, git.path),
    childHome,
    childTemporary,
    repositoryRoot,
    sessionRoot,
    tasksRoot,
    treehouseRoot: null
  };
}

function cleanupTreehouseSession(tool, options) {
  if (!sameOrDescendant(tool.repositoryRoot, tool.sessionRoot) || samePath(tool.repositoryRoot, tool.sessionRoot)) {
    throw new Error("GATE workspace operation session escaped the private Treehouse root");
  }
  assertNoWorkspaceMounts(tool.sessionRoot, options);
  fs.rmSync(tool.sessionRoot, { recursive: true, force: true });
}

function withWorkspaceOperationLock(tool, operation) {
  const lockPath = path.join(tool.repositoryRoot, ".gate-workspace-operation.lock");
  let descriptor;
  try {
    descriptor = fs.openSync(
      lockPath,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0),
      0o600
    );
  } catch (error) {
    if (error.code === "EEXIST") {
      const locked = new Error("another or stale GATE workspace operation lock exists; reconcile it manually before retrying");
      locked.code = OPERATION_LOCKED_CODE;
      throw locked;
    }
    throw new Error(`GATE workspace operation lock could not be acquired: ${safeErrorText(error.message)}`);
  }
  const locked = fs.fstatSync(descriptor);
  try {
    fs.writeFileSync(descriptor, `${process.pid} ${new Date().toISOString()}\n`, { encoding: "utf8" });
    fs.fsyncSync(descriptor);
    return operation();
  } finally {
    fs.closeSync(descriptor);
    const current = fs.lstatSync(lockPath);
    if (current.dev !== locked.dev || current.ino !== locked.ino || !current.isFile() || current.isSymbolicLink()) {
      throw new Error("GATE workspace operation lock changed while the operation was running");
    }
    fs.unlinkSync(lockPath);
  }
}

function operationLockWorkspaceStatus(tool) {
  const lockPath = path.join(tool.repositoryRoot, ".gate-workspace-operation.lock");
  let evidence = "owner metadata could not be verified";
  let verifiedEvidence = false;
  try {
    const raw = readStableOwnedFile(lockPath, "GATE workspace operation lock", {
      maximum: 4_096,
      ownerOnly: true,
      encoding: "utf8"
    });
    const match = /^([1-9][0-9]*) ([^\s]+)\n?$/u.exec(raw);
    const pid = match ? Number(match[1]) : Number.NaN;
    const timestamp = match?.[2] || "";
    const parsedTimestamp = Date.parse(timestamp);
    const canonicalTimestamp = Number.isFinite(parsedTimestamp)
      && new Date(parsedTimestamp).toISOString() === timestamp;
    if (Number.isSafeInteger(pid) && pid > 0 && canonicalTimestamp) {
      evidence = `recorded owner PID ${pid}, acquired ${timestamp}`;
      verifiedEvidence = true;
    }
  } catch (error) {
    evidence = `owner metadata is unavailable (${safeErrorText(error.message)})`;
  }
  const recoveryReason = verifiedEvidence
    ? `GATE workspace operation lock is present (${evidence}); follow the ordered operation-lock recovery procedure, leave it in place while that PID or any related process may be active, and only remove the exact unchanged lock after the procedure proves it stale before retrying status`
    : `GATE workspace operation lock is present (${evidence}); leave it in place because its owner evidence is not trustworthy, follow the ordered operation-lock recovery procedure, and do not inspect or mutate task state`;
  return {
    name: "operation-lock",
    path: null,
    status: "unverified",
    branch: "",
    detached: false,
    flavor: "git",
    branchError: null,
    recoveryReason,
    recoveryBackup: null,
    leaseId: "",
    leaseHolder: "",
    leasedAt: null,
    processes: [],
    dirty: null,
    phase: "operation-lock-present",
    taskId: null
  };
}

function recordWorkspaceEvent(kind, taskId, leaseId, summary, paths, options) {
  const recorder = options.recordEvent || recordEvent;
  const targetRef = `private://workspaces/${leaseId}`;
  const id = newId("evt");
  const event = recorder({
    id,
    kind,
    component: "gate-workspaces",
    taskId,
    summary,
    effect: {
      class: "host-write",
      targetRef,
      engagementId: null,
      planDigest: null
    },
    evidenceRefs: [targetRef]
  }, { paths });
  if (!event || typeof event !== "object" || event.id !== id || event.kind !== kind ||
      event.taskId !== taskId || event.effect?.targetRef !== targetRef) {
    throw new Error("workspace event recorder returned an invalid durable receipt");
  }
  return event;
}

function normalizeWorkspaceProcesses(processes) {
  if (!Array.isArray(processes) || processes.length > 1_024) {
    throw new Error("workspace process inventory is malformed or unbounded");
  }
  const seen = new Set();
  return processes.map((process) => {
    if (!process || typeof process !== "object" || !Number.isSafeInteger(process.pid) || process.pid < 1 || seen.has(process.pid)) {
      throw new Error("workspace process inventory contains an invalid process");
    }
    seen.add(process.pid);
    return { pid: process.pid, name: boundedString(process.name, "workspace process name", { maximum: 240 }) };
  });
}

function processParent(pid) {
  const status = fs.readFileSync(`/proc/${pid}/status`, "utf8");
  if (Buffer.byteLength(status) > 1024 * 1024 || status.includes("\0")) throw new Error("Linux process metadata is malformed");
  const match = /^PPid:\s+(\d+)$/mu.exec(status);
  if (!match) throw new Error("Linux process metadata has no parent identity");
  return Number(match[1]);
}

function protectedProcessIds() {
  const protectedIds = new Set();
  let pid = process.pid;
  for (let depth = 0; pid > 0 && depth < 1_024; depth += 1) {
    if (protectedIds.has(pid)) throw new Error("Linux process ancestry contains a cycle");
    protectedIds.add(pid);
    try {
      pid = processParent(pid);
    } catch (error) {
      if (error.code === "ENOENT") break;
      throw error;
    }
  }
  return protectedIds;
}

function workspaceProcesses(workspacePath, options) {
  if (options.runner && typeof options.workspaceProcesses === "function") {
    return normalizeWorkspaceProcesses(options.workspaceProcesses(workspacePath));
  }
  if (process.platform !== "linux") throw new Error("workspace process inspection currently requires Linux or WSL2");
  const root = fs.realpathSync(workspacePath);
  const protectedIds = protectedProcessIds();
  const entries = fs.readdirSync("/proc", { withFileTypes: true });
  if (entries.length > 1_000_000) throw new Error("Linux process inventory is unbounded");
  const processes = [];
  for (const entry of entries) {
    if (!entry.isDirectory() || !/^[1-9][0-9]*$/u.test(entry.name)) continue;
    const pid = Number(entry.name);
    if (!Number.isSafeInteger(pid) || protectedIds.has(pid)) continue;
    let processStat;
    try {
      processStat = fs.lstatSync(`/proc/${pid}`);
    } catch (error) {
      if (error.code === "ENOENT") continue;
      throw error;
    }
    if (typeof process.geteuid === "function" && processStat.uid !== process.geteuid()) continue;
    let cwd;
    try {
      cwd = fs.realpathSync(`/proc/${pid}/cwd`);
    } catch (error) {
      if (error.code === "ENOENT") continue;
      if (["EACCES", "EPERM"].includes(error.code)) {
        throw new Error(`workspace process inventory is unverified for same-user process ${pid}`);
      }
      throw error;
    }
    if (!sameOrDescendant(root, cwd)) continue;
    let name = "process";
    try {
      name = fs.readFileSync(`/proc/${pid}/comm`, "utf8").replace(/[\0\r\n]/gu, " ").trim().slice(0, 240) || name;
    } catch (error) {
      if (error.code === "ENOENT") continue;
      throw error;
    }
    processes.push({ pid, name });
    if (processes.length > 1_024) throw new Error("workspace process inventory is unbounded");
  }
  return normalizeWorkspaceProcesses(processes);
}

function readBoundLease(repository, tool, options) {
  const binding = readLeaseBinding(repository, tool);
  assertPrivateWorkspacePath(binding.workspacePath, tool);
  assertNoWorkspaceMounts(privateWorkspaceContainer(binding.workspacePath, tool), options);
  const snapshot = readTreehouseState(tool.treehouseRoot, binding.workspacePath, {
    leaseId: binding.leaseId,
    leaseHolder: binding.leaseHolder,
    leasedAt: binding.leasedAt
  });
  assertStateMatchesLeaseBinding(snapshot, binding);
  return { binding, snapshot };
}

function statusWithTool(repository, tool, options) {
  const { binding, snapshot } = readBoundLease(repository, tool, options);
  const workspaceContainer = privateWorkspaceContainer(binding.workspacePath, tool);
  assertNoWorkspaceMounts(workspaceContainer, options);
  assertNoWorktreeTransactionLocks(binding.workspacePath, "Treehouse workspace", tool, options);
  const branchResult = runGit(
    ["symbolic-ref", "--quiet", "--short", "HEAD"],
    binding.workspacePath,
    tool,
    options,
    new Set([0, 1])
  );
  const branch = branchResult.status === 0
    ? boundedString(branchResult.stdout.trim(), "workspace branch", { maximum: 240 })
    : "";
  const dirty = runGit(
    ["status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching", "-z"],
    binding.workspacePath,
    tool,
    options,
    new Set([0]),
    120_000
  ).stdout.length > 0;
  const processes = workspaceProcesses(binding.workspacePath, options);
  const finalSnapshot = readTreehouseState(tool.treehouseRoot, binding.workspacePath, {
    leaseId: binding.leaseId,
    leaseHolder: binding.leaseHolder,
    leasedAt: binding.leasedAt
  });
  assertStateMatchesLeaseBinding(finalSnapshot, binding);
  assertNoWorkspaceMounts(workspaceContainer, options);
  assertNoWorktreeTransactionLocks(binding.workspacePath, "Treehouse workspace", tool, options);
  if (snapshot.stateSha256 !== finalSnapshot.stateSha256 || snapshot.keySha256 !== finalSnapshot.keySha256) {
    throw new Error("Treehouse state changed while workspace status was inspected");
  }
  return [{
    name: snapshot.entry.name,
    path: binding.workspacePath,
    status: "leased",
    branch,
    detached: branchResult.status === 1,
    flavor: "git",
    branchError: branch === binding.branch ? null : `expected bound branch ${binding.branch}`,
    recoveryReason: null,
    recoveryBackup: null,
    leaseId: binding.leaseId,
    leaseHolder: binding.leaseHolder,
    leasedAt: binding.leasedAt,
    processes,
    dirty
  }];
}

function unverifiedWorkspaceStatus(taskId, reason, details = {}) {
  return {
    name: details.name || "pending",
    path: details.path || null,
    status: "unverified",
    branch: "",
    detached: false,
    flavor: "git",
    branchError: details.expectedBranch
      ? `expected branch ${details.expectedBranch}; the actual branch was not verified`
      : null,
    recoveryReason: safeErrorText(reason),
    recoveryBackup: null,
    leaseId: details.leaseId || "",
    leaseHolder: details.leaseHolder || `${TREEHOUSE_HOLDER_PREFIX}${taskId}`,
    leasedAt: details.leasedAt || null,
    processes: [],
    dirty: null,
    phase: details.phase || "reconciliation"
  };
}

function discoverPendingWorkspace(repository, tool, options, originalError) {
  let pending;
  try {
    pending = readPendingLeaseBinding(repository, tool);
  } catch {
    return unverifiedWorkspaceStatus(
      tool.taskId,
      `task-specific Treehouse state requires manual reconciliation: ${safeErrorText(originalError.message)}`
    );
  }
  const rootEntries = fs.readdirSync(tool.treehouseRoot, { withFileTypes: true });
  if (rootEntries.length === 2 && rootEntries.every((entry) => {
    return [".gate-task-binding.json", LEASE_BINDING_FILE].includes(entry.name) && entry.isFile() && !entry.isSymbolicLink();
  })) {
    return unverifiedWorkspaceStatus(
      tool.taskId,
      "Treehouse acquisition is pending or stopped before provider state was created; the task id remains burned",
      { expectedBranch: pending.branch, leaseHolder: pending.leaseHolder, phase: "pending" }
    );
  }
  try {
    const poolRoot = assertOwnedPhysicalDirectory(path.join(tool.treehouseRoot, ".treehouse"), "pending Treehouse pool root");
    const poolRootEntries = fs.readdirSync(poolRoot, { withFileTypes: true });
    const poolEntries = poolRootEntries.filter((entry) => entry.name !== ".gitignore");
    if (poolEntries.length !== 1 || !poolEntries[0].isDirectory() || poolEntries[0].isSymbolicLink()) {
      throw new Error("pending Treehouse pool does not contain one physical repository pool");
    }
    const poolDirectory = assertOwnedPhysicalDirectory(path.join(poolRoot, poolEntries[0].name), "pending Treehouse pool directory");
    const candidates = fs.readdirSync(poolDirectory, { withFileTypes: true })
      .filter((entry) => !["treehouse-state.json", "treehouse-state.key", "treehouse-state.lock"].includes(entry.name));
    if (candidates.length !== 1 || !candidates[0].isDirectory() || candidates[0].isSymbolicLink()) {
      throw new Error("pending Treehouse pool does not contain one physical slot");
    }
    const slot = assertOwnedPhysicalDirectory(path.join(poolDirectory, candidates[0].name), "pending Treehouse slot");
    const workspaces = fs.readdirSync(slot, { withFileTypes: true });
    if (workspaces.length !== 1 || !workspaces[0].isDirectory() || workspaces[0].isSymbolicLink()) {
      throw new Error("pending Treehouse slot does not contain one physical workspace");
    }
    const workspacePath = assertOwnedPhysicalDirectory(path.join(slot, workspaces[0].name), "pending Treehouse workspace");
    assertNoWorkspaceMounts(slot, options);
    const snapshot = readTreehouseState(tool.treehouseRoot, workspacePath, {
      leaseHolder: pending.leaseHolder,
      ...(pending.requestedBaseBranch ? { baseBranch: pending.requestedBaseBranch } : {})
    });
    return unverifiedWorkspaceStatus(
      tool.taskId,
      "Treehouse acquisition created a durable lease without a complete immutable GATE receipt; it remains held for manual reconciliation",
      {
        name: snapshot.entry.name,
        path: workspacePath,
        expectedBranch: pending.branch,
        leaseId: snapshot.entry.leaseId,
        leaseHolder: snapshot.entry.leaseHolder,
        leasedAt: snapshot.entry.leasedAt,
        phase: "unbound"
      }
    );
  } catch (error) {
    return unverifiedWorkspaceStatus(
      tool.taskId,
      `pending Treehouse acquisition could not be inspected safely: ${safeErrorText(error.message)}`,
      { expectedBranch: pending.branch, leaseHolder: pending.leaseHolder, phase: "reconciliation" }
    );
  }
}

function assertNoUnreachableObjects(cwd, tool, options) {
  const result = runGit(
    ["fsck", "--full", "--strict", "--unreachable", "--no-reflogs", "--no-progress"],
    cwd,
    tool,
    options,
    new Set([0]),
    300_000
  );
  if (result.stdout.trim() || result.stderr.trim()) {
    throw new Error("Git contains unreachable objects; preserve them with a ref or reconcile them before workspace lifecycle mutation");
  }
}

function decodeMountInfoPath(value) {
  return value.replace(/\\(040|011|012|134)/gu, (_, digits) => {
    return String.fromCharCode(Number.parseInt(digits, 8));
  });
}

function assertNoWorkspaceMounts(workspacePath, options) {
  if (process.platform !== "linux") {
    throw new Error("workspace mount-boundary verification requires Linux or WSL2");
  }
  let mountInfo;
  try {
    mountInfo = options.runner && typeof options.readMountInfo === "function"
      ? options.readMountInfo()
      : fs.readFileSync("/proc/self/mountinfo", "utf8");
  } catch (error) {
    throw new Error(`workspace mount-boundary information is unavailable: ${safeErrorText(error.message)}`);
  }
  if (typeof mountInfo !== "string" || Buffer.byteLength(mountInfo) > MAX_JSON_BYTES || mountInfo.includes("\0")) {
    throw new Error("workspace mount-boundary information is malformed or unbounded");
  }
  const root = fs.realpathSync(workspacePath);
  for (const line of mountInfo.split("\n")) {
    if (!line) continue;
    const fields = line.split(" ");
    if (fields.length < 10 || !fields.includes("-")) {
      throw new Error("workspace mount-boundary information is malformed");
    }
    const mountPoint = path.resolve(decodeMountInfoPath(fields[4]));
    if (samePath(root, mountPoint) || sameOrDescendant(root, mountPoint)) {
      throw new Error("Treehouse workspace contains a nested mount; unmount it before workspace verification");
    }
  }
}

export function leaseWorkspace(input, options = {}) {
  const paths = options.paths || runtimePaths(options);
  const repository = existingDirectory(input?.repository, "repository path");
  const taskId = taskIdentifier(input?.taskId);
  const branch = gitRef(input?.branch, "workspace branch");
  const baseBranch = input?.baseBranch === undefined || input?.baseBranch === null
    ? null
    : gitRef(input.baseBranch, "workspace base branch");
  const holder = `${TREEHOUSE_HOLDER_PREFIX}${taskId}`;
  const tool = prepareTreehouse(paths, repository, null, options);
  try {
    return withWorkspaceOperationLock(tool, () => {
      assertSafeWorktreeConfigs(repository, tool, options);
      assertNoCommonGitTransactionLocks(repository, tool, options);
      assertNoWorktreeTransactionLocks(repository, "main Git worktree", tool, options);
      Object.assign(tool, activateTaskRoot(tool, repository, taskId, { create: true, options }));
      writePendingLeaseBinding(repository, tool, branch, holder, baseBranch);
      assertNoUnreachableObjects(repository, tool, options);
      const args = ["get", "--lease", "--json", "--no-fetch", "--branch", branch, "--lease-holder", holder];
      if (baseBranch) args.push("--base", baseBranch);
      const lease = normalizeLease(parseJson(checkedTreehouseGet(tool, args, repository, options), "Treehouse lease"), holder);
      assertPrivateWorkspacePath(lease.path, tool);
      if (baseBranch && lease.baseBranch !== baseBranch) {
        throw new Error("Treehouse returned a different workspace base branch");
      }
      const leaseContainer = privateWorkspaceContainer(lease.path, tool);
      assertNoWorkspaceMounts(leaseContainer, options);
      const initialState = readTreehouseState(tool.treehouseRoot, lease.path, {
        leaseId: lease.leaseId,
        leaseHolder: lease.leaseHolder,
        leasedAt: lease.leasedAt,
        baseBranch: lease.baseBranch
      });
      const binding = providerLeaseBindingValue(repository, tool.taskId, branch, lease, initialState);
      if (initialState.entry.seededPaths.length > 0) {
        throw new Error("newly leased Treehouse workspace contains seeded paths and remains held for reconciliation");
      }
      const actualBranch = runGit(["symbolic-ref", "--quiet", "--short", "HEAD"], lease.path, tool, options).stdout.trim();
      if (actualBranch !== branch) throw new Error("newly leased Treehouse workspace is on a different branch and remains held for reconciliation");
      assertNoNestedGitMetadata(lease.path);
      assertNoInProgressGitOperation(lease.path, "newly leased Treehouse workspace", tool, options);
      assertNoWorktreeTransactionLocks(lease.path, "newly leased Treehouse workspace", tool, options);
      assertVisibleIndex(lease.path, "newly leased Treehouse workspace", tool, options);
      assertRealIndexMatchesHead(lease.path, "newly leased Treehouse workspace", tool, options);
      assertObjectIntegrity(lease.path, tool, options);
      assertNoUnreachableObjects(lease.path, tool, options);
      try {
        assertCanonicalHeadState(lease.path, "newly leased Treehouse workspace", tool, options);
      } catch (error) {
        throw new Error(`newly leased Treehouse workspace is not a raw HEAD match; the lease remains held for status reconciliation: ${safeErrorText(error.message)}`);
      }
      assertSafeWorktreeConfigs(repository, tool, options);
      assertNoCommonGitTransactionLocks(repository, tool, options);
      assertNoWorktreeTransactionLocks(repository, "main Git worktree", tool, options);
      assertNoWorktreeTransactionLocks(lease.path, "newly leased Treehouse workspace", tool, options);
      assertNoWorkspaceMounts(leaseContainer, options);
      const finalState = readTreehouseState(tool.treehouseRoot, lease.path, {
        leaseId: lease.leaseId,
        leaseHolder: lease.leaseHolder,
        leasedAt: lease.leasedAt,
        baseBranch: lease.baseBranch
      });
      assertStateMatchesLeaseBinding(finalState, binding);
      const result = {
        provider: TREEHOUSE_ID,
        version: tool.entry.version,
        integrityState: tool.entry.integrityState,
        repository,
        taskId,
        branch,
        ...lease
      };
      const event = recordWorkspaceEvent(
        "workspace.leased",
        taskId,
        lease.leaseId,
        "Treehouse workspace lease was acquired.",
        paths,
        options
      );
      const committedBinding = writeLeaseBinding(repository, tool, branch, lease, finalState, event, options);
      const committedState = readTreehouseState(tool.treehouseRoot, lease.path, {
        leaseId: lease.leaseId,
        leaseHolder: lease.leaseHolder,
        leasedAt: lease.leasedAt,
        baseBranch: lease.baseBranch
      });
      assertStateMatchesLeaseBinding(committedState, committedBinding);
      return result;
    });
  } finally {
    cleanupTreehouseSession(tool, options);
  }
}

export function workspaceStatus(input, options = {}) {
  const paths = options.paths || runtimePaths(options);
  const repository = existingDirectory(input?.repository, "repository path");
  const tool = prepareTreehouse(paths, repository, null, options);
  try {
    try {
      return withWorkspaceOperationLock(tool, () => {
        assertSafeWorktreeConfigs(repository, tool, options);
        assertNoCommonGitTransactionLocks(repository, tool, options);
        assertNoWorktreeTransactionLocks(repository, "main Git worktree", tool, options);
        const workspaces = [];
        try {
          for (const task of listTaskRoots(tool, repository)) {
            Object.assign(tool, activateTaskRoot(tool, repository, task.taskId));
            let taskWorkspaces;
            try {
              taskWorkspaces = statusWithTool(repository, tool, options);
            } catch (error) {
              taskWorkspaces = [discoverPendingWorkspace(repository, tool, options, error)];
            }
            for (const workspace of taskWorkspaces) {
              workspaces.push({ ...workspace, taskId: task.taskId });
              if (workspaces.length > MAX_STATUS_ENTRIES) throw new Error("aggregated Treehouse status is unbounded");
            }
          }
        } finally {
          assertSafeWorktreeConfigs(repository, tool, options);
          assertNoCommonGitTransactionLocks(repository, tool, options);
          assertNoWorktreeTransactionLocks(repository, "main Git worktree", tool, options);
        }
        return {
          provider: TREEHOUSE_ID,
          version: tool.entry.version,
          integrityState: tool.entry.integrityState,
          repository,
          workspaces
        };
      });
    } catch (error) {
      if (error.code !== OPERATION_LOCKED_CODE) throw error;
      return {
        provider: TREEHOUSE_ID,
        version: tool.entry.version,
        integrityState: tool.entry.integrityState,
        repository,
        workspaces: [operationLockWorkspaceStatus(tool)]
      };
    }
  } finally {
    cleanupTreehouseSession(tool, options);
  }
}

export function verifyWorkspace(input, options = {}) {
  const paths = options.paths || runtimePaths(options);
  const repository = existingDirectory(input?.repository, "repository path");
  const workspacePath = existingDirectory(input?.path, "workspace path");
  const taskId = taskIdentifier(input?.taskId);
  const leaseId = boundedString(input?.leaseId, "lease id", { maximum: 32 });
  if (!LEASE_ID.test(leaseId)) throw new Error("lease id must be a 128-bit lowercase hexadecimal value");
  const suppliedLandedRef = gitRef(input?.landedRef, "landed ref");
  const holder = `${TREEHOUSE_HOLDER_PREFIX}${taskId}`;
  const tool = prepareTreehouse(paths, repository, workspacePath, options);
  try {
    return withWorkspaceOperationLock(tool, () => {
  Object.assign(tool, activateTaskRoot(tool, repository, taskId));
  assertPrivateWorkspacePath(workspacePath, tool);
  assertSafeWorktreeConfigs(repository, tool, options);
  assertNoCommonGitTransactionLocks(repository, tool, options);
  assertNoWorktreeTransactionLocks(repository, "main Git worktree", tool, options);
  assertNoWorktreeTransactionLocks(workspacePath, "Treehouse workspace", tool, options);
  const workspaceContainer = privateWorkspaceContainer(workspacePath, tool);
  assertNoWorkspaceMounts(workspaceContainer, options);
  const { binding, snapshot: initialState } = readBoundLease(repository, tool, options);
  if (!samePath(binding.workspacePath, workspacePath) || binding.leaseId !== leaseId || binding.leaseHolder !== holder) {
    throw new Error("supplied workspace lease does not match the immutable GATE lease binding");
  }
  const processes = workspaceProcesses(workspacePath, options);
  if (processes.length > 0) throw new Error("Treehouse workspace still has running processes; stop them before verification");
  assertNoNestedGitMetadata(workspacePath);
  assertNoInProgressGitOperation(workspacePath, "Treehouse workspace", tool, options);

  let gitMarker;
  try {
    gitMarker = fs.lstatSync(path.join(repository, ".git"));
  } catch {
    throw new Error("repository path must be the main Git worktree before landing verification can run");
  }
  if (!gitMarker.isDirectory() || gitMarker.isSymbolicLink()) {
    throw new Error("repository path must be the main Git worktree before landing verification can run");
  }
  const repositoryCommonDirectory = commonGitDirectory(repository, tool, options);
  const repositoryGitDirectory = fs.realpathSync(path.join(repository, ".git"));
  if (!samePath(repositoryGitDirectory, repositoryCommonDirectory)) {
    throw new Error("repository .git directory must be the shared common Git directory");
  }
  const workspaceCommonDirectory = commonGitDirectory(workspacePath, tool, options);
  if (!samePath(repositoryCommonDirectory, workspaceCommonDirectory)) {
    throw new Error("repository and Treehouse workspace do not share one Git common directory");
  }
  assertExpectedWorktree(repository, "main Git worktree", tool, options);
  assertExpectedWorktree(workspacePath, "Treehouse workspace", tool, options);
  const workspaceBranch = runGit(["symbolic-ref", "--quiet", "--short", "HEAD"], workspacePath, tool, options).stdout.trim();
  if (workspaceBranch !== binding.branch) {
    throw new Error(`Treehouse workspace is no longer on its bound branch (${binding.branch})`);
  }
  assertUnmodifiedObjectGraph(repositoryCommonDirectory, repository, tool, options);
  const landedBranch = runGit(["symbolic-ref", "--quiet", "--short", "HEAD"], repository, tool, options).stdout.trim();
  if (!landedBranch || suppliedLandedRef !== landedBranch) {
    throw new Error(`landed ref must match the main worktree's checked-out branch (${landedBranch || "detached"})`);
  }
  const landedRef = `refs/heads/${landedBranch}`;

  assertVisibleIndex(repository, "main Git worktree", tool, options);
  assertRealIndexMatchesHead(repository, "main Git worktree", tool, options);
  assertVisibleIndex(workspacePath, "Treehouse workspace", tool, options);
  assertRealIndexMatchesHead(workspacePath, "Treehouse workspace", tool, options);
  assertObjectIntegrity(repository, tool, options);
  assertNoUnreachableObjects(repository, tool, options);
  try {
    assertCanonicalHeadState(repository, "main Git worktree", tool, options, { allowIgnoredExtras: true });
  } catch (error) {
    throw new Error(`main Git worktree has raw changes; landing cannot be established: ${safeErrorText(error.message)}`);
  }
  try {
    assertCanonicalHeadState(workspacePath, "Treehouse workspace", tool, options);
  } catch (error) {
    throw new Error(`Treehouse workspace has raw, ignored, nested, or uncommitted changes and will remain leased: ${safeErrorText(error.message)}`);
  }
  const objectFormat = runGit(["rev-parse", "--show-object-format"], repository, tool, options).stdout.trim();
  const commitId = commitPattern(objectFormat);
  const head = runGit(["rev-parse", "--verify", "HEAD^{commit}"], workspacePath, tool, options).stdout.trim();
  const landedCommit = runGit(["rev-parse", "--verify", `${landedRef}^{commit}`], repository, tool, options).stdout.trim();
  if (!commitId.test(head) || !commitId.test(landedCommit)) throw new Error("Git returned an invalid commit identity");
  const ancestry = runGit(
    ["merge-base", "--is-ancestor", head, landedCommit],
    repository,
    tool,
    options,
    new Set([0, 1])
  );
  assertObjectIntegrity(repository, tool, options);
  assertNoUnreachableObjects(repository, tool, options);
  if (ancestry.status !== 0) {
    throw new Error(`Treehouse workspace HEAD ${head} has not landed in ${landedRef}; the lease will remain held`);
  }
  assertUnmodifiedObjectGraph(repositoryCommonDirectory, repository, tool, options);
  assertNoWorkspaceMounts(workspaceContainer, options);
  assertSafeWorktreeConfigs(repository, tool, options);
  assertNoCommonGitTransactionLocks(repository, tool, options);
  assertNoWorktreeTransactionLocks(repository, "main Git worktree", tool, options);
  assertNoWorktreeTransactionLocks(workspacePath, "Treehouse workspace", tool, options);
  const finalState = readTreehouseState(tool.treehouseRoot, workspacePath, {
    leaseId: binding.leaseId,
    leaseHolder: binding.leaseHolder,
    leasedAt: binding.leasedAt
  });
  assertStateMatchesLeaseBinding(finalState, binding);
  if (initialState.stateSha256 !== finalState.stateSha256 || initialState.keySha256 !== finalState.keySha256) {
    throw new Error("Treehouse state changed while landing verification was running");
  }

  const result = {
    provider: TREEHOUSE_ID,
    version: tool.entry.version,
    integrityState: tool.entry.integrityState,
    repository,
    taskId,
    path: workspacePath,
    leaseId,
    leaseHolder: holder,
    head,
    landedRef,
    landedCommit,
    verified: true,
    returned: false,
    retained: true
  };
  recordWorkspaceEvent(
    "workspace.verified",
    taskId,
    leaseId,
    "Treehouse workspace landing was verified; its durable lease remains held.",
    paths,
    options
  );
  return result;
    });
  } finally {
    cleanupTreehouseSession(tool, options);
  }
}

export function returnWorkspace() {
  throw new Error("workspace return is disabled because Treehouse 3.1.3 resets worktrees destructively; use workspace verify");
}
