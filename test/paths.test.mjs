import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  canonicalCaseScopeText,
  caseScopeDigest
} from "../src/lib/case-scope.mjs";
import { writeJsonAtomic } from "../src/lib/config.mjs";
import { ensureRuntime, runtimePaths } from "../src/lib/paths.mjs";
import { readPrivateFileBounded } from "../src/lib/private-fs.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const gate = path.join(repo, "bin", "gate.mjs");

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-runtime-"));
  const home = path.join(root, "home");
  const paths = runtimePaths({ home, repo: path.resolve(".") });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, home, paths };
}

function permissions(file) {
  return fs.statSync(file).mode & 0o777;
}

function seedCaseBinding(paths) {
  const scope = {
    $schema: "https://gate.local/schemas/case.schema.json",
    apiVersion: "gate.dev/case/v1",
    kind: "Case",
    metadata: {
      id: paths.caseId,
      displayName: paths.caseId === "alpha-case" ? "Alpha case" : "Beta case",
      createdAt: "2026-10-15T12:00:00.000Z"
    },
    program: { id: "fixture-program", profileSha256: "a".repeat(64) },
    project: null,
    isolation: {
      stateNamespace: "isolated-directory",
      processBoundary: "shared-user",
      networkBoundary: "adapter-dependent"
    },
    scopeSha256: "0".repeat(64)
  };
  scope.scopeSha256 = caseScopeDigest(scope);
  fs.mkdirSync(paths.stateHome, { recursive: true, mode: 0o700 });
  fs.writeFileSync(paths.caseScope, canonicalCaseScopeText(scope), { mode: 0o600 });
  fs.writeFileSync(
    paths.caseBinding,
    `${JSON.stringify({ caseId: paths.caseId, scopeSha256: scope.scopeSha256 })}\n`,
    { mode: 0o600 }
  );
  return scope;
}

const derivedRuntimePathKeys = [
  "stateHome", "cases", "caseRoot", "caseScope", "caseBinding",
  "events", "tokens", "engagements", "authorizations", "plans", "evidence", "programs", "workflows",
  "executions", "executionManifests", "executionClaims", "executionRuns", "executionStops", "executionSandboxes",
  "offlineAnalyses", "offlineAnalysisTransactions", "offlineAnalysisManifests", "offlineAnalysisCreations",
  "offlineAnalysisClaims", "offlineAnalysisPurges", "offlineAnalysisRuns", "offlineAnalysisInputs",
  "offlineAnalysisSandboxes", "projects", "upstreams", "upstreamTools", "toolRuntimes", "toolRuntimeStaging",
  "toolCache", "toolArtifactCache", "privateLearnings", "publicLearningRecords", "publicLearnings"
];

test("runtime setup remediates private directories to 0700 and state files to 0600", {
  skip: process.platform === "win32" && "Windows uses profile ACLs instead of POSIX mode bits"
}, (t) => {
  const { home, paths } = fixture(t);
  fs.mkdirSync(paths.engagements, { recursive: true });
  fs.chmodSync(home, 0o777);
  fs.chmodSync(paths.engagements, 0o777);
  fs.writeFileSync(paths.events, "{\"kind\":\"fixture\"}\n");
  fs.chmodSync(paths.events, 0o666);
  const engagement = path.join(paths.engagements, "fixture.json");
  fs.writeFileSync(engagement, "{}\n");
  fs.chmodSync(engagement, 0o644);

  ensureRuntime(paths);

  for (const directory of [
    paths.home,
    paths.engagements,
    paths.authorizations,
    paths.plans,
    paths.evidence,
    paths.workflows,
    paths.projects,
    paths.upstreams,
    paths.upstreamTools,
    path.dirname(paths.privateLearnings),
    path.join(paths.home, "cache"),
    path.join(paths.home, "cache", "npm")
  ]) {
    assert.equal(permissions(directory), 0o700, directory);
  }
  assert.equal(permissions(paths.events), 0o600);
  assert.equal(permissions(engagement), 0o600);
});

test("case runtime paths isolate mutable state while retaining shared registries and tool roots", (t) => {
  const { home, paths } = fixture(t);
  const first = runtimePaths({ home, repo: paths.repo, caseId: "alpha-case" });
  const second = runtimePaths({ home, repo: paths.repo, caseId: "beta-case" });

  assert.equal(first.stateHome, path.join(home, "cases", "alpha-case", "state"));
  assert.equal(second.stateHome, path.join(home, "cases", "beta-case", "state"));
  for (const key of [
    "events", "tokens", "engagements", "authorizations", "plans", "evidence", "workflows",
    "executions", "offlineAnalyses", "privateLearnings"
  ]) {
    assert.notEqual(first[key], second[key], key);
    assert.equal(first[key].startsWith(`${first.stateHome}${path.sep}`), true, key);
    assert.equal(second[key].startsWith(`${second.stateHome}${path.sep}`), true, key);
  }
  for (const key of [
    "projects", "programs", "upstreams", "upstreamTools", "toolRuntimes", "toolCache", "toolArtifactCache"
  ]) {
    assert.equal(first[key], second[key], key);
    assert.equal(first[key], paths[key], key);
  }

  seedCaseBinding(first);
  seedCaseBinding(second);
  ensureRuntime(first);
  ensureRuntime(second);
  if (process.platform !== "win32") {
    assert.equal(permissions(first.stateHome), 0o700);
    assert.equal(permissions(second.stateHome), 0o700);
  }
});

test("case selection rejects mismatched and escaping state roots", (t) => {
  const { root, home, paths } = fixture(t);
  assert.throws(
    () => runtimePaths({
      home,
      repo: paths.repo,
      caseId: "alpha-case",
      stateHome: path.join(home, "cases", "beta-case", "state")
    }),
    /case stateHome must match/u
  );

  assert.throws(
    () => runtimePaths({ home, repo: paths.repo, stateHome: path.join(root, "escaped") }),
    /base stateHome must match GATE_HOME/u
  );
  assert.equal(fs.existsSync(path.join(root, "escaped")), false);
});

test("runtime path tables reject every mutable and shared path override", (t) => {
  const { home, paths } = fixture(t);
  ensureRuntime(paths);
  for (const key of derivedRuntimePathKeys) {
    const redirected = path.join(home, "redirected", key);
    assert.throws(
      () => runtimePaths({ home, repo: paths.repo, [key]: redirected }),
      /runtime path override is not allowed|base stateHome must match/u,
      `runtimePaths must reject ${key}`
    );
    assert.throws(
      () => ensureRuntime({ ...paths, [key]: redirected }),
      /runtime path does not match its derived location|base stateHome must match/u,
      `ensureRuntime must reject ${key}`
    );
  }
});

test("scoped runtime setup requires the exact immutable state-root binding", (t) => {
  const { home, paths } = fixture(t);
  const scoped = runtimePaths({ home, repo: paths.repo, caseId: "alpha-case" });
  assert.throws(() => ensureRuntime(scoped), /private case alpha-case does not exist/u);

  const scope = seedCaseBinding(scoped);
  assert.doesNotThrow(() => ensureRuntime(scoped));
  fs.writeFileSync(scoped.caseBinding, `${JSON.stringify({
    caseId: "other-case",
    scopeSha256: scope.scopeSha256
  })}\n`, { mode: 0o600 });
  assert.throws(() => ensureRuntime(scoped), /state-root binding does not match/u);
});

test("scoped runtime setup verifies the complete immutable scope and recomputes its digest", (t) => {
  const { home, paths } = fixture(t);
  const scoped = runtimePaths({ home, repo: paths.repo, caseId: "alpha-case" });
  const scope = seedCaseBinding(scoped);

  fs.writeFileSync(scoped.caseScope, `${JSON.stringify({
    metadata: { id: scoped.caseId },
    scopeSha256: scope.scopeSha256
  })}\n`, { mode: 0o600 });
  assert.throws(() => ensureRuntime(scoped), /case scope must contain exactly/u);

  fs.writeFileSync(scoped.caseScope, canonicalCaseScopeText({
    ...scope,
    metadata: { ...scope.metadata, displayName: "Changed without a new digest" }
  }), { mode: 0o600 });
  assert.throws(() => ensureRuntime(scoped), /case scope digest changed/u);
});

test("unassigned runtime rejects a case state root before writing into it", (t) => {
  const { home, paths } = fixture(t);
  const scoped = runtimePaths({ home, repo: paths.repo, caseId: "alpha-case" });
  seedCaseBinding(scoped);
  const before = fs.readdirSync(scoped.stateHome).sort();

  const result = spawnSync(process.execPath, [
    gate,
    "--unassigned",
    "engagement",
    "new",
    "aliased-case",
    "--targets",
    "app.example.test",
    "--actions",
    "scan",
    "--tools",
    "nmap",
    "--json"
  ], {
    cwd: repo,
    env: { ...process.env, GATE_HOME: scoped.stateHome, GATE_CASE: "" },
    encoding: "utf8",
    timeout: 10_000
  });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /must not be a case state root or its descendant/u);
  assert.deepEqual(fs.readdirSync(scoped.stateHome).sort(), before);
  assert.equal(fs.existsSync(path.join(scoped.stateHome, "cases")), false);
  assert.equal(fs.existsSync(path.join(scoped.stateHome, "engagements", "aliased-case.json")), false);
});

test("unassigned runtime rejects a symlink-parent alias below a case state root before writing", {
  skip: process.platform === "win32" && "creating symlinks can require elevated Windows privileges"
}, (t) => {
  const { root, home, paths } = fixture(t);
  const scoped = runtimePaths({ home, repo: paths.repo, caseId: "alpha-case" });
  seedCaseBinding(scoped);
  const alias = path.join(root, "case-state-alias");
  fs.symlinkSync(scoped.stateHome, alias, "dir");
  const nestedHome = path.join(alias, "nested-unassigned");

  assert.throws(
    () => ensureRuntime(runtimePaths({ home: nestedHome, repo: paths.repo })),
    /must not be a case state root or its descendant/u
  );
  assert.equal(fs.existsSync(path.join(scoped.stateHome, "nested-unassigned")), false);
});

test("runtime setup creates the workflow root without scanning retained instances", {
  skip: process.platform === "win32" && "creating symlinks can require elevated Windows privileges"
}, (t) => {
  const { root, home, paths } = fixture(t);
  ensureRuntime({ home, repo: paths.repo });
  const workflows = path.join(home, "workflows");
  assert.equal(permissions(workflows), 0o700);

  const outside = path.join(root, "outside-workflow");
  fs.mkdirSync(outside);
  fs.symlinkSync(outside, path.join(workflows, "retained-entry"), "dir");

  assert.doesNotThrow(() => ensureRuntime(paths));
});

test("runtime setup rejects a filesystem-root GATE_HOME before changing it", () => {
  const root = path.parse(path.resolve(".")).root;
  assert.throws(() => ensureRuntime({ home: root }), /cannot be a filesystem root/);
});

test("runtime setup rejects lexical repository overlap in either direction before creating state", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-runtime-overlap-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const repo = path.join(root, "repo");
  fs.mkdirSync(repo);

  const nestedHome = path.join(repo, "private-state");
  assert.throws(
    () => ensureRuntime(runtimePaths({ home: nestedHome, repo })),
    /repository must not overlap/
  );
  assert.equal(fs.existsSync(nestedHome), false);

  const home = path.join(root, "home");
  const nestedRepo = path.join(home, "gate");
  fs.mkdirSync(nestedRepo, { recursive: true });
  assert.throws(
    () => ensureRuntime(runtimePaths({ home, repo: nestedRepo })),
    /repository must not overlap/
  );
  assert.equal(fs.existsSync(path.join(home, "engagements")), false);

  assert.throws(
    () => ensureRuntime(runtimePaths({ home: repo, repo })),
    /repository must not overlap/
  );
});

test("runtime setup rejects canonical overlap through a parent symlink without creating state", {
  skip: process.platform === "win32" && "creating symlinks can require elevated Windows privileges"
}, (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-runtime-canonical-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const repo = path.join(root, "repo");
  const alias = path.join(root, "repo-alias");
  fs.mkdirSync(repo);
  fs.symlinkSync(repo, alias, "dir");
  const home = path.join(alias, "private-state");

  assert.throws(
    () => ensureRuntime(runtimePaths({ home, repo })),
    /must not overlap after resolving parent links/
  );
  assert.equal(fs.existsSync(path.join(repo, "private-state")), false);

  const inverseHome = path.join(root, "inverse-home");
  const physicalRepo = path.join(inverseHome, "gate");
  const repoAlias = path.join(root, "nested-repo-alias");
  fs.mkdirSync(physicalRepo, { recursive: true });
  fs.symlinkSync(physicalRepo, repoAlias, "dir");
  assert.throws(
    () => ensureRuntime(runtimePaths({ home: inverseHome, repo: repoAlias })),
    /must not overlap after resolving parent links/
  );
  assert.equal(fs.existsSync(path.join(inverseHome, "engagements")), false);
});

test("runtime setup rejects a symlinked GATE_HOME", {
  skip: process.platform === "win32" && "creating symlinks can require elevated Windows privileges"
}, (t) => {
  const { root } = fixture(t);
  const target = path.join(root, "target");
  const home = path.join(root, "linked-home");
  fs.mkdirSync(target);
  fs.symlinkSync(target, home, "dir");
  const paths = runtimePaths({ home, repo: path.resolve(".") });
  assert.throws(() => ensureRuntime(paths), /GATE_HOME must not be a symbolic link/);
});

test("runtime setup rejects symlinked private directories and files", {
  skip: process.platform === "win32" && "creating symlinks can require elevated Windows privileges"
}, (t) => {
  const { root, home, paths } = fixture(t);
  const outsideDirectory = path.join(root, "outside");
  fs.mkdirSync(home);
  fs.mkdirSync(outsideDirectory);
  fs.symlinkSync(outsideDirectory, paths.engagements, "dir");
  assert.throws(() => ensureRuntime(paths), /must not be a symbolic link/);
  fs.unlinkSync(paths.engagements);

  ensureRuntime(paths);
  const outsideFile = path.join(root, "outside.jsonl");
  fs.writeFileSync(outsideFile, "outside\n");
  fs.symlinkSync(outsideFile, paths.events);
  assert.throws(() => ensureRuntime(paths), /private runtime file .* must not be a symbolic link/);
  assert.equal(fs.readFileSync(outsideFile, "utf8"), "outside\n");
});

test("runtime setup rejects planted engagement entries and paths outside GATE_HOME", {
  skip: process.platform === "win32" && "creating symlinks can require elevated Windows privileges"
}, (t) => {
  const { root, paths } = fixture(t);
  ensureRuntime(paths);
  const outsideFile = path.join(root, "outside.json");
  fs.writeFileSync(outsideFile, "{}\n");
  fs.symlinkSync(outsideFile, path.join(paths.engagements, "planted.json"));
  assert.throws(() => ensureRuntime(paths), /private runtime entry planted\.json must not be a symbolic link/);

  fs.unlinkSync(path.join(paths.engagements, "planted.json"));
  const escaped = { ...paths, plans: path.join(root, "escaped-plans") };
  assert.throws(() => ensureRuntime(escaped), /runtime path does not match its derived location: plans/u);
});

test("runtime setup streams retained state beyond 4096 direct entries", (t) => {
  const { paths } = fixture(t);
  ensureRuntime(paths);
  for (let index = 0; index < 4097; index += 1) {
    fs.writeFileSync(
      path.join(paths.engagements, `entry-${String(index).padStart(4, "0")}.json`),
      "{}\n",
      { mode: 0o600 }
    );
  }

  assert.doesNotThrow(() => ensureRuntime(paths));
});

test("runtime setup rejects linked project registry entries", {
  skip: process.platform === "win32" && "creating links can require elevated Windows privileges"
}, (t) => {
  const { root, paths } = fixture(t);
  ensureRuntime(paths);
  const outsideFile = path.join(root, "outside-project.json");
  fs.writeFileSync(outsideFile, "{}\n", { mode: 0o600 });
  fs.symlinkSync(outsideFile, path.join(paths.projects, "linked-project.json"));
  assert.throws(() => ensureRuntime(paths), /private runtime entry linked-project\.json must not be a symbolic link/);
  assert.equal(fs.readFileSync(outsideFile, "utf8"), "{}\n");
});

test("private atomic JSON writes reject a pre-positioned destination symlink", {
  skip: process.platform === "win32" && "creating symlinks can require elevated Windows privileges"
}, (t) => {
  const { root, paths } = fixture(t);
  ensureRuntime(paths);
  const outsideFile = path.join(root, "outside.json");
  const destination = path.join(paths.evidence, "publication.json");
  fs.writeFileSync(outsideFile, "unchanged\n");
  fs.symlinkSync(outsideFile, destination);

  assert.throws(() => writeJsonAtomic(destination, { changed: true }), /must not be a symbolic link/);
  assert.equal(fs.readFileSync(outsideFile, "utf8"), "unchanged\n");
});

test("bounded private reads reject oversized state without returning partial content", (t) => {
  const { paths } = fixture(t);
  ensureRuntime(paths);
  const file = path.join(paths.projects, "large-project.json");
  fs.writeFileSync(file, "x".repeat(1025), { mode: 0o600 });
  assert.throws(() => readPrivateFileBounded(file, 1024, "utf8"), /exceeds the 1024-byte limit/);
});

test("runtime setup rejects hard-linked private state", {
  skip: process.platform === "win32" && "hard-link creation may require additional Windows privileges"
}, (t) => {
  const { root, paths } = fixture(t);
  ensureRuntime(paths);
  const outsideFile = path.join(root, "outside.jsonl");
  fs.writeFileSync(outsideFile, "outside\n");
  fs.linkSync(outsideFile, paths.events);

  assert.throws(() => ensureRuntime(paths), /must not have multiple hard links/);
  assert.equal(fs.readFileSync(outsideFile, "utf8"), "outside\n");
});

test("runtime setup rejects private state owned by another account", {
  skip: process.platform === "win32" || typeof process.geteuid !== "function" || process.geteuid() !== 0
}, (t) => {
  const { paths } = fixture(t);
  ensureRuntime(paths);
  fs.writeFileSync(paths.events, "{}\n", { mode: 0o600 });
  fs.chownSync(paths.events, 65534, 65534);
  try {
    assert.throws(() => ensureRuntime(paths), /not owned by the current user/);
  } finally {
    fs.chownSync(paths.events, process.geteuid(), process.getegid());
  }
});

for (const kind of ["runtime", "artifact"]) {
  test(`${kind} audit tolerates a listed entry removed by concurrent mutation`, (t) => {
    const { paths } = fixture(t);
    ensureRuntime(paths);
    const directory = kind === "runtime" ? paths.toolRuntimes : paths.toolArtifactCache;
    const entry = path.join(directory, "retiring-entry");
    if (kind === "runtime") fs.mkdirSync(entry, { mode: 0o700 });
    else fs.writeFileSync(entry, "fixture", { mode: 0o600 });
    const opendir = fs.opendirSync;
    fs.opendirSync = (file, ...args) => {
      const handle = opendir(file, ...args);
      if (file !== directory) return handle;
      return {
        readSync(...readArgs) {
          const directoryEntry = handle.readSync(...readArgs);
          if (directoryEntry?.name === path.basename(entry) && fs.existsSync(entry)) {
            fs.rmSync(entry, { recursive: true });
          }
          return directoryEntry;
        },
        closeSync(...closeArgs) {
          return handle.closeSync(...closeArgs);
        }
      };
    };
    try {
      assert.doesNotThrow(() => ensureRuntime(paths));
      assert.equal(fs.existsSync(entry), false);
    } finally {
      fs.opendirSync = opendir;
    }
  });

  test(`${kind} audit rejects ENOENT when the listed entry remains present`, (t) => {
    const { paths } = fixture(t);
    ensureRuntime(paths);
    const directory = kind === "runtime" ? paths.toolRuntimes : paths.toolArtifactCache;
    const entry = path.join(directory, "present-entry");
    if (kind === "runtime") fs.mkdirSync(entry, { mode: 0o700 });
    else fs.writeFileSync(entry, "fixture", { mode: 0o600 });
    const open = fs.openSync;
    fs.openSync = (file, ...args) => {
      if (file === entry) throw Object.assign(new Error("transient open failure"), { code: "ENOENT" });
      return open(file, ...args);
    };
    try {
      assert.throws(() => ensureRuntime(paths), /transient open failure/);
      assert.equal(fs.existsSync(entry), true);
    } finally {
      fs.openSync = open;
    }
  });

  test(`${kind} audit still rejects a present symlink`, { skip: process.platform === "win32" }, (t) => {
    const { root, paths } = fixture(t);
    ensureRuntime(paths);
    const directory = kind === "runtime" ? paths.toolRuntimes : paths.toolArtifactCache;
    fs.symlinkSync(root, path.join(directory, "invalid-entry"));
    assert.throws(() => ensureRuntime(paths), /symbolic link/);
  });
}

test("offline sandbox audit tolerates a listed root removed by concurrent purge", (t) => {
  const { paths } = fixture(t);
  ensureRuntime(paths);
  const entry = path.join(paths.offlineAnalysisSandboxes, "retiring-sandbox");
  fs.mkdirSync(entry, { mode: 0o700 });
  const opendir = fs.opendirSync;
  fs.opendirSync = (file, ...args) => {
    const handle = opendir(file, ...args);
    if (file !== paths.offlineAnalysisSandboxes) return handle;
    return {
      readSync(...readArgs) {
        const directoryEntry = handle.readSync(...readArgs);
        if (directoryEntry?.name === path.basename(entry) && fs.existsSync(entry)) {
          fs.rmSync(entry, { recursive: true });
        }
        return directoryEntry;
      },
      closeSync(...closeArgs) {
        return handle.closeSync(...closeArgs);
      }
    };
  };
  try {
    assert.doesNotThrow(() => ensureRuntime(paths));
    assert.equal(fs.existsSync(entry), false);
  } finally {
    fs.opendirSync = opendir;
  }
});

for (const kind of ["runtime", "artifact"]) {
  for (const stage of ["open", "final identity check"]) {
    test(`${kind} audit tolerates confirmed disappearance during ${stage}`, {
      skip: process.platform === "win32" && "directory descriptor audit requires POSIX"
    }, (t) => {
      const { paths } = fixture(t);
      ensureRuntime(paths);
      const directory = kind === "runtime" ? paths.toolRuntimes : paths.toolArtifactCache;
      const entry = path.join(directory, "retiring-entry");
      if (kind === "runtime") fs.mkdirSync(entry, { mode: 0o700 });
      else fs.writeFileSync(entry, "fixture", { mode: 0o600 });
      const open = fs.openSync;
      const lstat = fs.lstatSync;
      let opened = false;
      let retired = false;
      fs.openSync = (file, ...args) => {
        if (file === entry && stage === "open") {
          fs.rmSync(entry, { recursive: true });
          retired = true;
        }
        const descriptor = open(file, ...args);
        if (file === entry) opened = true;
        return descriptor;
      };
      fs.lstatSync = (file, ...args) => {
        if (file === entry && stage === "final identity check" && opened && !retired) {
          retired = true;
          fs.rmSync(entry, { recursive: true });
        }
        return lstat(file, ...args);
      };
      try {
        assert.doesNotThrow(() => ensureRuntime(paths));
        assert.equal(retired, true, "the audit must reach the raced boundary");
        assert.equal(fs.existsSync(entry), false);
      } finally {
        fs.openSync = open;
        fs.lstatSync = lstat;
      }
    });
  }
}
