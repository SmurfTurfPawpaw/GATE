import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { securePrivateDirectory, securePrivateFile } from "./private-fs.mjs";

const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

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
  const home = path.resolve(options.home || gateHome(options.env));
  const repo = path.resolve(options.repo || findRepoRoot(options.cwd));
  const executions = path.join(home, "executions");
  const offlineAnalyses = path.join(home, "offline-analysis");
  return {
    repo,
    home,
    configHome: gateConfigHome(options.env),
    events: path.join(home, "events.jsonl"),
    tokens: path.join(home, "tokens.jsonl"),
    engagements: path.join(home, "engagements"),
    authorizations: path.join(home, "authorizations"),
    plans: path.join(home, "plans"),
    evidence: path.join(home, "evidence"),
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
    privateLearnings: path.join(home, "memory", "private", "learnings.jsonl"),
    publicLearningRecords: path.join(repo, "memory", "learnings.jsonl"),
    publicLearnings: path.join(repo, "memory", "LEARNINGS.md")
  };
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

export function ensureRuntime(paths) {
  if (!paths?.home) throw new Error("GATE_HOME is required");
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

  // Only create private state after both the lexical and physical locations
  // are proven separate from the repository's Git-managed tree.
  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  securePrivateDirectory(home, { create: false, label: "GATE_HOME" });

  const directoryPaths = [
    paths.engagements,
    paths.authorizations,
    paths.plans,
    paths.evidence,
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

  const knownFiles = [paths.events, paths.tokens, paths.privateLearnings].filter(Boolean).map((file) => path.resolve(file));
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
    paths.projects,
    paths.executionManifests,
    paths.executionClaims,
    paths.executionStops,
    paths.offlineAnalysisManifests,
    paths.offlineAnalysisCreations,
    paths.offlineAnalysisClaims,
    paths.offlineAnalysisPurges
  ].filter(Boolean)) {
    for (const entry of fs.readdirSync(directory)) {
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
    for (const entry of fs.readdirSync(paths.executionSandboxes)) {
      securePrivateDirectory(path.join(paths.executionSandboxes, entry), {
        create: false,
        label: `private execution sandbox ${entry}`
      });
    }
  }

  if (paths.offlineAnalysisSandboxes) {
    for (const entry of fs.readdirSync(paths.offlineAnalysisSandboxes)) {
      securePrivateDirectory(path.join(paths.offlineAnalysisSandboxes, entry), {
        create: false,
        label: `private offline-analysis sandbox ${entry}`
      });
    }
  }

  // Managed upstream roots may contain complex trees, including reviewed
  // source symlinks, but each top-level installation must itself be a real
  // owner-only directory.
  for (const directory of [paths.upstreams, paths.upstreamTools].filter(Boolean)) {
    for (const entry of fs.readdirSync(directory)) {
      securePrivateDirectory(path.join(directory, entry), {
        create: false,
        label: `managed upstream directory ${entry}`
      });
    }
  }
}
