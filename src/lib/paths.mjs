import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertCaseStateBinding } from "./case-scope.mjs";
import {
  readPrivateFileBounded,
  securePrivateDirectory,
  securePrivateFile
} from "./private-fs.mjs";

function auditPresentEntry(file, audit, options) {
  try {
    audit(file, options);
  } catch (error) {
    if ((error.code || error.cause?.code) === "ENOENT") {
      try {
        fs.lstatSync(file);
      } catch (confirmation) {
        if (confirmation.code === "ENOENT") return;
        throw confirmation;
      }
    }
    throw error;
  }
}

function* directoryEntries(directory) {
  const handle = fs.opendirSync(directory);
  try {
    while (true) {
      const entry = handle.readSync();
      if (entry === null) return;
      yield entry.name;
    }
  } finally {
    handle.closeSync();
  }
}

const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const CASE_ID = /^[a-z][a-z0-9-]{1,62}$/u;
const MAX_CASE_BINDING_BYTES = 1024;
const MAX_CASE_SCOPE_BYTES = 64 * 1024;
const RUNTIME_PATH_KEYS = Object.freeze([
  "stateHome", "cases", "caseRoot", "caseScope", "caseBinding",
  "events", "tokens", "engagements", "authorizations", "plans", "evidence", "programs", "workflows",
  "ctfPilotRoot", "ctfPilotState", "ctfPilotTransfers",
  "executions", "executionManifests", "executionClaims", "executionRuns", "executionStops", "executionSandboxes",
  "offlineAnalyses", "offlineAnalysisTransactions", "offlineAnalysisManifests", "offlineAnalysisCreations",
  "offlineAnalysisClaims", "offlineAnalysisPurges", "offlineAnalysisRuns", "offlineAnalysisInputs",
  "offlineAnalysisSandboxes", "projects", "upstreams", "upstreamTools", "toolRuntimes", "toolRuntimeStaging",
  "toolCache", "toolArtifactCache", "privateLearnings", "publicLearningRecords", "publicLearnings"
]);

export function findRepoRoot() {
  // Executable assets, policies, schemas, and locks are always loaded from the
  // installed GATE package. Registered destination projects remain explicit
  // inputs; cwd must never replace same-origin dashboard code or authority
  // contracts.
  return sourceRoot;
}

export function gateHome(env = process.env) {
  if (env.GATE_HOME) return path.resolve(env.GATE_HOME);
  if (process.platform === "win32") {
    const base = env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local");
    return path.join(base, "GATE");
  }
  return path.join(env.XDG_DATA_HOME || path.join(os.homedir(), ".local", "share"), "gate");
}

export function gateConfigHome(env = process.env) {
  if (env.GATE_CONFIG_HOME) return path.resolve(env.GATE_CONFIG_HOME);
  if (process.platform === "win32") {
    const base = env.APPDATA || path.join(os.homedir(), "AppData", "Roaming");
    return path.join(base, "GATE");
  }
  return path.join(env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config"), "gate");
}

export function runtimePaths(options = {}) {
  for (const key of RUNTIME_PATH_KEYS) {
    if (Object.hasOwn(options, key) && key !== "stateHome") {
      throw new Error(`runtime path override is not allowed: ${key}`);
    }
  }
  const home = path.resolve(options.home || gateHome(options.env));
  const repo = path.resolve(options.repo || findRepoRoot(options.cwd));
  const cases = path.join(home, "cases");
  let caseId = null;
  if (options.caseId !== undefined && options.caseId !== null) {
    if (typeof options.caseId !== "string" || !CASE_ID.test(options.caseId)) {
      throw new Error("case id must start with a letter and contain only lowercase letters, numbers, or dashes");
    }
    caseId = options.caseId;
  }
  const expectedCaseStateHome = caseId ? path.join(cases, caseId, "state") : null;
  const stateHome = path.resolve(options.stateHome || expectedCaseStateHome || home);
  const expectedStateHome = path.resolve(expectedCaseStateHome || home);
  if (stateHome !== expectedStateHome) {
    throw new Error(caseId
      ? "case stateHome must match GATE_HOME/cases/CASE_ID/state"
      : "base stateHome must match GATE_HOME");
  }
  const executions = path.join(stateHome, "executions");
  const offlineAnalyses = path.join(stateHome, "offline-analysis");
  const toolRuntimes = path.join(home, "tool-runtimes");
  const toolCache = path.join(home, "tool-cache");
  const programs = path.join(home, "programs");
  const ctfPilotRoot = path.join(stateHome, "ctf-pilot");
  return {
    repo,
    home,
    stateHome,
    caseId,
    cases,
    caseRoot: caseId ? path.join(cases, caseId) : null,
    caseScope: caseId ? path.join(cases, caseId, "scope.json") : null,
    caseBinding: caseId ? path.join(stateHome, ".case-binding.json") : null,
    configHome: gateConfigHome(options.env),
    events: path.join(stateHome, "events.jsonl"),
    tokens: path.join(stateHome, "tokens.jsonl"),
    engagements: path.join(stateHome, "engagements"),
    authorizations: path.join(stateHome, "authorizations"),
    plans: path.join(stateHome, "plans"),
    evidence: path.join(stateHome, "evidence"),
    programs,
    workflows: path.join(stateHome, "workflows"),
    ctfPilotRoot,
    ctfPilotState: path.join(ctfPilotRoot, "state.json"),
    ctfPilotTransfers: path.join(ctfPilotRoot, "transfers"),
    executions,
    executionManifests: path.join(executions, "manifests"),
    executionClaims: path.join(executions, "claims"),
    executionRuns: path.join(executions, "runs"),
    executionStops: path.join(executions, "stops"),
    executionSandboxes: path.join(executions, "sandboxes"),
    offlineAnalyses,
    offlineAnalysisTransactions: path.join(offlineAnalyses, "transactions"),
    offlineAnalysisManifests: path.join(offlineAnalyses, "manifests"),
    offlineAnalysisCreations: path.join(offlineAnalyses, "creations"),
    offlineAnalysisClaims: path.join(offlineAnalyses, "claims"),
    offlineAnalysisPurges: path.join(offlineAnalyses, "purges"),
    offlineAnalysisRuns: path.join(offlineAnalyses, "runs"),
    offlineAnalysisInputs: path.join(offlineAnalyses, "inputs"),
    offlineAnalysisSandboxes: path.join(offlineAnalyses, "sandboxes"),
    projects: path.join(home, "projects"),
    upstreams: path.join(home, "upstreams"),
    upstreamTools: path.join(home, "upstream-tools"),
    toolRuntimes,
    toolRuntimeStaging: path.join(toolRuntimes, ".staging"),
    toolCache,
    toolArtifactCache: path.join(toolCache, "sha256"),
    privateLearnings: path.join(stateHome, "memory", "private", "learnings.jsonl"),
    publicLearningRecords: path.join(repo, "memory", "learnings.jsonl"),
    publicLearnings: path.join(repo, "memory", "LEARNINGS.md")
  };
}

function sameResolvedPath(left, right) {
  return typeof left === "string" && typeof right === "string" && path.resolve(left) === path.resolve(right);
}

function exactRuntimePaths(supplied) {
  if (!supplied?.home) throw new Error("GATE_HOME is required");
  const suppliedHome = path.resolve(supplied.home);
  if (suppliedHome === path.parse(suppliedHome).root) throw new Error("GATE_HOME cannot be a filesystem root");
  if (!supplied.repo) throw new Error("the GATE repository path is required");
  const expected = runtimePaths({
    home: supplied.home,
    repo: supplied.repo,
    caseId: supplied.caseId,
    stateHome: supplied.stateHome
  });
  if (supplied.caseId !== undefined && supplied.caseId !== null && supplied.caseId !== expected.caseId) {
    throw new Error("runtime case id does not match its derived path table");
  }
  for (const key of RUNTIME_PATH_KEYS) {
    if (!Object.hasOwn(supplied, key)) continue;
    const actual = supplied[key];
    const derived = expected[key];
    const matches = actual === null || derived === null
      ? actual === derived
      : sameResolvedPath(actual, derived);
    if (!matches) {
      throw new Error(`runtime path does not match its derived location: ${key} (override escapes GATE_HOME or another case)`);
    }
  }
  return expected;
}

function readJsonBounded(file, maximumBytes, label) {
  let value;
  try {
    value = JSON.parse(readPrivateFileBounded(file, maximumBytes, "utf8", { label }));
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error(`${label} is not valid JSON`, { cause: error });
    throw error;
  }
  return value;
}

function assertScopedStateBinding(paths) {
  if (!paths.caseId) return;
  securePrivateDirectory(paths.caseRoot, { create: false, label: `private case ${paths.caseId}` });
  securePrivateDirectory(paths.stateHome, { create: false, label: `private case state ${paths.caseId}` });
  securePrivateFile(paths.caseScope, { allowMissing: false, label: `private case scope ${paths.caseId}` });
  securePrivateFile(paths.caseBinding, { allowMissing: false, label: `private case state binding ${paths.caseId}` });
  const scope = readJsonBounded(paths.caseScope, MAX_CASE_SCOPE_BYTES, `private case scope ${paths.caseId}`);
  const marker = readJsonBounded(paths.caseBinding, MAX_CASE_BINDING_BYTES, `private case state binding ${paths.caseId}`);
  assertCaseStateBinding(marker, scope, { expectedId: paths.caseId });
}

function lstatIfPresent(file) {
  try {
    return fs.lstatSync(file);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

function sameOrDescendant(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return relative === "" ||
    (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

function pathsOverlap(left, right) {
  return sameOrDescendant(left, right) || sameOrDescendant(right, left);
}

function prospectiveRealPath(candidate) {
  let current = path.resolve(candidate);
  const missing = [];
  while (true) {
    try {
      const real = fs.realpathSync.native ? fs.realpathSync.native(current) : fs.realpathSync(current);
      return path.resolve(real, ...missing.reverse());
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      const parent = path.dirname(current);
      if (parent === current) throw error;
      missing.push(path.basename(current));
      current = parent;
    }
  }
}

function assertUnscopedHomeOutsideCaseState(home, canonicalHome) {
  const visited = new Set();
  for (const candidate of [path.resolve(home), path.resolve(canonicalHome)]) {
    let current = candidate;
    while (!visited.has(current)) {
      visited.add(current);
      const marker = path.join(current, ".case-binding.json");
      if (lstatIfPresent(marker)) {
        throw new Error("unassigned GATE_HOME must not be a case state root or its descendant");
      }
      const parent = path.dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }
}

export function ensureRuntime(paths) {
  paths = exactRuntimePaths(paths);
  const home = path.resolve(paths.home);
  if (home === path.parse(home).root) throw new Error("GATE_HOME cannot be a filesystem root");

  const homeStat = lstatIfPresent(home);
  if (homeStat?.isSymbolicLink()) throw new Error("GATE_HOME must not be a symbolic link");
  if (homeStat && !homeStat.isDirectory()) throw new Error("GATE_HOME must be a directory");
  if (!paths.repo) throw new Error("the GATE repository path is required");
  const repo = path.resolve(paths.repo);
  if (pathsOverlap(home, repo)) {
    throw new Error("GATE_HOME and the GATE repository must not overlap");
  }
  const canonicalHome = prospectiveRealPath(home);
  const canonicalRepo = prospectiveRealPath(repo);
  if (pathsOverlap(canonicalHome, canonicalRepo)) {
    throw new Error("GATE_HOME and the GATE repository must not overlap after resolving parent links");
  }
  if (!paths.caseId) assertUnscopedHomeOutsideCaseState(home, canonicalHome);

  const stateHome = path.resolve(paths.stateHome || home);
  if (!sameOrDescendant(home, stateHome)) {
    throw new Error("runtime stateHome must remain inside GATE_HOME");
  }
  const canonicalStateHome = prospectiveRealPath(stateHome);
  if (!sameOrDescendant(canonicalHome, canonicalStateHome)) {
    throw new Error("runtime stateHome must remain inside GATE_HOME after resolving parent links");
  }

  // Only create private state after both the lexical and physical locations
  // are proven separate from the repository's Git-managed tree.
  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  securePrivateDirectory(home, { create: false, label: "GATE_HOME" });
  if (paths.caseId) assertScopedStateBinding(paths);

  // Derive the workflow root for older callers that pass a partial paths
  // object. Workflow operations validate individual instance directories;
  // generic runtime bootstrap deliberately does not enumerate retained
  // workflow history, so its cost stays bounded as that history grows.
  const workflows = paths.workflows || path.join(home, "workflows");

  const directoryPaths = [
    paths.cases || path.join(home, "cases"),
    stateHome,
    paths.engagements,
    paths.authorizations,
    paths.plans,
    paths.evidence,
    paths.programs,
    workflows,
    paths.caseId ? paths.ctfPilotRoot : null,
    paths.caseId ? paths.ctfPilotTransfers : null,
    paths.executions,
    paths.executionManifests,
    paths.executionClaims,
    paths.executionRuns,
    paths.executionStops,
    paths.executionSandboxes,
    paths.offlineAnalyses,
    paths.offlineAnalysisTransactions,
    paths.offlineAnalysisManifests,
    paths.offlineAnalysisCreations,
    paths.offlineAnalysisClaims,
    paths.offlineAnalysisPurges,
    paths.offlineAnalysisRuns,
    paths.offlineAnalysisInputs,
    paths.offlineAnalysisSandboxes,
    paths.projects,
    paths.upstreams,
    paths.upstreamTools,
    paths.toolRuntimes,
    paths.toolRuntimeStaging,
    paths.toolCache,
    paths.toolArtifactCache,
    path.join(home, "cache"),
    path.join(home, "cache", "npm"),
    paths.privateLearnings ? path.dirname(paths.privateLearnings) : null
  ].filter(Boolean).map((directory) => path.resolve(directory));

  const ensureContained = (candidate, label) => {
    const relative = path.relative(home, candidate);
    if (relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative))) return;
    throw new Error(`${label} escapes GATE_HOME: ${candidate}`);
  };

  for (const directory of directoryPaths) {
    ensureContained(directory, "private directory");
    const relative = path.relative(home, directory);
    let current = home;
    for (const component of relative.split(path.sep).filter(Boolean)) {
      current = path.join(current, component);
      securePrivateDirectory(current, { label: `private runtime directory ${current}` });
    }
  }

  const knownFiles = [
    paths.events,
    paths.tokens,
    paths.privateLearnings,
    paths.caseId ? paths.ctfPilotState : null
  ].filter(Boolean).map((file) => path.resolve(file));
  for (const file of knownFiles) {
    ensureContained(file, "private file");
    securePrivateFile(file, { label: `private runtime file ${file}` });
  }

  // These roots contain only GATE state files. Auditing their existing direct
  // children makes bootstrap fail before a planted link can be read or
  // appended, and remediates legacy 0644/0666 state to 0600.
  for (const directory of [
    paths.engagements,
    paths.authorizations,
    paths.plans,
    paths.caseId ? paths.ctfPilotTransfers : null,
    paths.projects,
    paths.executionManifests,
    paths.executionClaims,
    paths.executionStops,
    paths.offlineAnalysisManifests,
    paths.offlineAnalysisCreations,
    paths.offlineAnalysisClaims,
    paths.offlineAnalysisPurges
  ].filter(Boolean)) {
    for (const entry of directoryEntries(directory)) {
      // The project writer owns these short-lived control files and project
      // readers validate them without following links. Skipping them here
      // prevents status/bootstrap calls from racing their unlink after readdir.
      if (directory === paths.projects && new Set([".registry.lock", ".registry.pending"]).has(entry)) continue;
      try {
        securePrivateFile(path.join(directory, entry), { allowMissing: false, label: `private runtime entry ${entry}` });
      } catch (error) {
        // Atomic writers rename a private temporary file after readdir. A file
        // that is now absent is safe to ignore; every path still present must
        // pass the full no-follow, owner, type, link-count, and mode checks.
        if (error.code !== "ENOENT") throw error;
      }
    }
  }

  // Active-tool sandboxes contain arbitrary tool-created trees. Only their
  // direct roots are part of GATE's control plane; their contents are opaque
  // private evidence and are never traversed during bootstrap.
  if (paths.executionSandboxes) {
    for (const entry of directoryEntries(paths.executionSandboxes)) {
      securePrivateDirectory(path.join(paths.executionSandboxes, entry), {
        create: false,
        label: `private execution sandbox ${entry}`
      });
    }
  }

  // Program profiles are directory-scoped private records with their own
  // bounded file audit. Runtime bootstrap validates only the direct profile
  // roots so it stays independent of retained compilation history.
  if (paths.programs) {
    for (const entry of directoryEntries(paths.programs)) {
      auditPresentEntry(path.join(paths.programs, entry), securePrivateDirectory, {
        create: false,
        label: `private program profile ${entry}`
      });
    }
  }

  if (paths.offlineAnalysisSandboxes) {
    for (const entry of directoryEntries(paths.offlineAnalysisSandboxes)) {
      auditPresentEntry(path.join(paths.offlineAnalysisSandboxes, entry), securePrivateDirectory, {
        create: false,
        label: `private offline-analysis sandbox ${entry}`
      });
    }
  }

  // Managed upstream roots may contain complex trees, including reviewed
  // source symlinks, but each top-level installation must itself be a real
  // owner-only directory.
  for (const directory of [paths.upstreams, paths.upstreamTools].filter(Boolean)) {
    for (const entry of directoryEntries(directory)) {
      securePrivateDirectory(path.join(directory, entry), {
        create: false,
        label: `managed upstream directory ${entry}`
      });
    }
  }

  // Runtime installations are private, content-verified trees. The staging
  // directory is internal bookkeeping rather than an installed tool.
  if (paths.toolRuntimes) {
    for (const entry of directoryEntries(paths.toolRuntimes)) {
      if (entry === ".staging") continue;
      auditPresentEntry(path.join(paths.toolRuntimes, entry), securePrivateDirectory, {
        create: false,
        label: `managed tool runtime ${entry}`
      });
    }
  }

  if (paths.toolArtifactCache) {
    for (const entry of directoryEntries(paths.toolArtifactCache)) {
      auditPresentEntry(path.join(paths.toolArtifactCache, entry), securePrivateFile, {
        allowMissing: false,
        label: `managed tool artifact ${entry}`
      });
    }
  }
  if (paths.caseId) assertScopedStateBinding(paths);
}
