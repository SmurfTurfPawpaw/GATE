import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { writeJsonAtomic } from "../src/lib/config.mjs";
import { ensureRuntime, runtimePaths } from "../src/lib/paths.mjs";
import { readPrivateFileBounded } from "../src/lib/private-fs.mjs";

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
  assert.throws(() => ensureRuntime(escaped), /private directory escapes GATE_HOME/);
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
    const readdir = fs.readdirSync;
    fs.readdirSync = (file, ...args) => {
      const entries = readdir(file, ...args);
      if (file === directory && fs.existsSync(entry)) fs.rmSync(entry, { recursive: true });
      return entries;
    };
    try {
      assert.doesNotThrow(() => ensureRuntime(paths));
      assert.equal(fs.existsSync(entry), false);
    } finally {
      fs.readdirSync = readdir;
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
