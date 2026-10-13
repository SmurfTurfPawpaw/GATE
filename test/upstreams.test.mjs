import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { runtimePaths } from "../src/lib/paths.mjs";
import { inspectReleaseArchive, installUpstream, resolveUpstreamBinary, upstreamStatus } from "../src/lib/upstreams.mjs";

const sourceRepo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const npm = process.platform === "win32" ? "npm.cmd" : "npm";

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-upstreams-"));
  const repo = path.join(root, "gate");
  const home = path.join(root, "home");
  fs.mkdirSync(path.join(repo, "schemas"), { recursive: true });
  fs.copyFileSync(
    path.join(sourceRepo, "schemas", "upstream-lock.schema.json"),
    path.join(repo, "schemas", "upstream-lock.schema.json")
  );
  fs.copyFileSync(
    path.join(sourceRepo, "schemas", "event.schema.json"),
    path.join(repo, "schemas", "event.schema.json")
  );
  fs.mkdirSync(path.join(repo, "locks"), { recursive: true });
  const paths = runtimePaths({ repo, home, env: { ...process.env, GATE_HOME: home } });
  fs.mkdirSync(paths.upstreams, { recursive: true });
  fs.mkdirSync(paths.upstreamTools, { recursive: true });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, repo, home, paths };
}

function writeLock(repo, upstreams) {
  fs.writeFileSync(path.join(repo, "locks", "upstreams.lock.json"), `${JSON.stringify({
    schemaVersion: 1,
    generatedAt: "2026-10-13T00:00:00.000Z",
    updatePolicy: "reviewed-pull-request",
    upstreams
  }, null, 2)}\n`);
}

function git(cwd, ...args) {
  return execFileSync("git", args, { cwd, encoding: "utf8" }).trim();
}

test("release execution is anchored to the reviewed executable digest, not its writable receipt", (t) => {
  const { repo, paths } = fixture(t);
  const platform = `${process.platform}-${process.arch}`;
  const binaryName = `fixture-release${process.platform === "win32" ? ".exe" : ""}`;
  const trustedBytes = Buffer.from("reviewed release bytes\n");
  const trustedDigest = sha256(trustedBytes);
  const archiveDigest = "a".repeat(64);
  writeLock(repo, [{
    id: "fixture-release",
    repository: "https://github.com/example/fixture-release.git",
    commit: "b".repeat(40),
    version: "1.0.0",
    install: {
      lane: "github-release",
      tag: "v1.0.0",
      binary: "fixture-release",
      artifacts: {
        [platform]: { name: "fixture-release.tar.gz", sha256: archiveDigest, executableSha256: trustedDigest }
      }
    }
  }]);

  const directory = path.join(paths.upstreamTools, "fixture-release");
  const executable = path.join(directory, "bin", binaryName);
  fs.mkdirSync(path.dirname(executable), { recursive: true });
  fs.writeFileSync(executable, trustedBytes);
  const receiptFile = path.join(directory, "install.json");
  const receipt = {
    apiVersion: "gate.upstream-install/v2",
    id: "fixture-release",
    lane: "github-release",
    version: "1.0.0",
    tag: "v1.0.0",
    platform,
    artifact: "fixture-release.tar.gz",
    sha256: archiveDigest,
    executableSha256: trustedDigest,
    executable: `bin/${binaryName}`,
    versionSource: "reviewed-lock",
    executedDuringInstall: false,
    verifiedAt: "2026-10-13T00:00:00.000Z"
  };
  fs.writeFileSync(receiptFile, `${JSON.stringify(receipt)}\n`);

  assert.equal(resolveUpstreamBinary("fixture-release", null, { paths }).executable, executable);

  const changedBytes = Buffer.from("modified release bytes\n");
  fs.writeFileSync(executable, changedBytes);
  fs.writeFileSync(receiptFile, `${JSON.stringify({ ...receipt, executableSha256: sha256(changedBytes) })}\n`);
  assert.throws(
    () => resolveUpstreamBinary("fixture-release", null, { paths }),
    /failed integrity verification/
  );
  assert.equal(upstreamStatus({ paths })[0].integrityState, "invalid");
});

test("release archive inspection rejects links before extraction", { skip: process.platform === "win32" }, (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-release-archive-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const content = path.join(root, "content");
  fs.mkdirSync(content);
  fs.writeFileSync(path.join(content, "fixture-release"), "reviewed bytes\n");
  fs.symlinkSync("/tmp/outside-gate-release", path.join(content, "escape"));
  const archive = path.join(root, "fixture-release.tar.gz");
  execFileSync("tar", ["-czf", archive, "-C", content, "fixture-release", "escape"]);
  assert.throws(() => inspectReleaseArchive(archive), /unsafe paths or entry types/);
});

test("release admission verifies bytes without executing the fresh binary", { skip: process.platform === "win32" }, (t) => {
  const { root, repo, paths } = fixture(t);
  const content = path.join(root, "release-content");
  const fakeBin = path.join(root, "fake-bin");
  const sentinel = path.join(root, "fresh-binary-ran");
  const tarOptionsSentinel = path.join(root, "tar-options-ran");
  const pathTarSentinel = path.join(root, "path-tar-ran");
  const tarOptionsCanary = path.join(root, "tar-options-canary");
  fs.mkdirSync(content);
  fs.mkdirSync(fakeBin);
  const binary = path.join(content, "fixture-release");
  fs.writeFileSync(binary, `#!/bin/sh\nprintf ran > '${sentinel}'\nexit 99\n`);
  fs.chmodSync(binary, 0o700);
  const archive = path.join(root, "fixture-release.tar.gz");
  execFileSync("tar", ["-czf", archive, "-C", content, "fixture-release"]);
  const archiveDigest = sha256(fs.readFileSync(archive));
  const executableDigest = sha256(fs.readFileSync(binary));
  writeLock(repo, [{
    id: "fixture-release",
    repository: "https://github.com/example/fixture-release.git",
    commit: "d".repeat(40),
    version: "1.0.0",
    install: {
      lane: "github-release",
      tag: "v1.0.0",
      binary: "fixture-release",
      artifacts: {
        [`${process.platform}-${process.arch}`]: {
          name: "fixture-release.tar.gz",
          sha256: archiveDigest,
          executableSha256: executableDigest
        }
      }
    }
  }]);
  const fakeGh = path.join(fakeBin, "gh");
  fs.writeFileSync(fakeGh, `#!/bin/sh
destination=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--dir" ]; then
    shift
    destination="$1"
  fi
  shift
done
cp "$GATE_TEST_RELEASE_ARCHIVE" "$destination/fixture-release.tar.gz"
`);
  fs.chmodSync(fakeGh, 0o700);
  fs.writeFileSync(tarOptionsCanary, "#!/bin/sh\nprintf ran > \"${0%/*}/tar-options-ran\"\n");
  fs.chmodSync(tarOptionsCanary, 0o700);
  const fakeTar = path.join(fakeBin, "tar");
  fs.writeFileSync(fakeTar, "#!/bin/sh\nprintf ran > \"${0%/*}/../path-tar-ran\"\nexit 99\n");
  fs.chmodSync(fakeTar, 0o700);
  const maliciousTarOptions = `--checkpoint=1 --checkpoint-action=exec=${tarOptionsCanary}`;

  if (process.platform === "linux" && fs.existsSync("/usr/bin/tar")) {
    execFileSync("/usr/bin/tar", ["-tf", archive], {
      env: {
        ...process.env,
        TAR_OPTIONS: maliciousTarOptions
      }
    });
    assert.equal(fs.existsSync(tarOptionsSentinel), true, "the GNU tar exploit fixture must execute without hardening");
    fs.rmSync(tarOptionsSentinel);
  }

  const previousPath = process.env.PATH;
  const previousArchive = process.env.GATE_TEST_RELEASE_ARCHIVE;
  const previousTarOptions = process.env.TAR_OPTIONS;
  process.env.PATH = `${fakeBin}${path.delimiter}${previousPath}`;
  process.env.GATE_TEST_RELEASE_ARCHIVE = archive;
  process.env.TAR_OPTIONS = maliciousTarOptions;
  try {
    const result = installUpstream("fixture-release", { paths });
    assert.equal(result.version, "1.0.0");
    assert.equal(result.versionSource, "reviewed-lock");
    assert.equal(result.executedDuringInstall, false);
  } finally {
    process.env.PATH = previousPath;
    if (previousArchive === undefined) delete process.env.GATE_TEST_RELEASE_ARCHIVE;
    else process.env.GATE_TEST_RELEASE_ARCHIVE = previousArchive;
    if (previousTarOptions === undefined) delete process.env.TAR_OPTIONS;
    else process.env.TAR_OPTIONS = previousTarOptions;
  }
  assert.equal(fs.existsSync(sentinel), false);
  assert.equal(fs.existsSync(tarOptionsSentinel), false);
  assert.equal(fs.existsSync(pathTarSentinel), false);
});

test("npm execution reconstructs reviewed lock bytes and rejects a forged tree receipt", (t) => {
  const { root, repo, home, paths } = fixture(t);
  const packageRoot = path.join(root, "fixture-package");
  const cache = path.join(home, "cache", "npm");
  fs.mkdirSync(packageRoot, { recursive: true });
  fs.mkdirSync(cache, { recursive: true });
  fs.writeFileSync(path.join(packageRoot, "package.json"), JSON.stringify({
    name: "fixture-tool",
    version: "1.0.0",
    bin: { "fixture-tool": "cli.js" }
  }));
  fs.writeFileSync(path.join(packageRoot, "cli.js"), "#!/usr/bin/env node\nconsole.log('trusted');\n");
  const tarballName = execFileSync(
    npm,
    ["pack", "--ignore-scripts", "--silent", "--cache", cache],
    { cwd: packageRoot, encoding: "utf8" }
  ).trim();
  const tarball = path.join(packageRoot, tarballName);
  const integrity = `sha512-${crypto.createHash("sha512").update(fs.readFileSync(tarball)).digest("base64")}`;
  execFileSync(npm, ["cache", "add", tarball, "--ignore-scripts", "--silent", "--cache", cache]);

  const lockDirectory = path.join(repo, "locks", "npm", "fixture-tool");
  fs.mkdirSync(lockDirectory, { recursive: true });
  const packageManifest = {
    name: "gate-upstream-fixture-tool",
    private: true,
    version: "0.0.0",
    dependencies: { "fixture-tool": "1.0.0" }
  };
  const packageLock = {
    name: "gate-upstream-fixture-tool",
    lockfileVersion: 3,
    requires: true,
    packages: {
      "": { dependencies: { "fixture-tool": "1.0.0" } },
      "node_modules/fixture-tool": {
        version: "1.0.0",
        resolved: "https://registry.npmjs.org/fixture-tool/-/fixture-tool-1.0.0.tgz",
        integrity,
        bin: { "fixture-tool": "cli.js" }
      }
    }
  };
  const packageFile = path.join(lockDirectory, "package.json");
  const lockFile = path.join(lockDirectory, "package-lock.json");
  fs.writeFileSync(packageFile, `${JSON.stringify(packageManifest, null, 2)}\n`);
  fs.writeFileSync(lockFile, `${JSON.stringify(packageLock, null, 2)}\n`);
  const lockSha256 = sha256(fs.readFileSync(lockFile));
  writeLock(repo, [{
    id: "fixture-tool",
    repository: "https://github.com/example/fixture-tool.git",
    commit: "c".repeat(40),
    version: "1.0.0",
    install: {
      lane: "npm",
      package: "fixture-tool",
      integrity,
      lockfile: "locks/npm/fixture-tool/package-lock.json",
      lockSha256
    }
  }]);

  const directory = path.join(paths.upstreamTools, "fixture-tool");
  fs.mkdirSync(directory, { recursive: true });
  fs.copyFileSync(packageFile, path.join(directory, "package.json"));
  fs.copyFileSync(lockFile, path.join(directory, "package-lock.json"));
  execFileSync(
    npm,
    ["ci", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", "--cache", cache],
    { cwd: directory }
  );
  const receiptFile = path.join(directory, "install.json");
  const receipt = {
    apiVersion: "gate.upstream-install/v2",
    id: "fixture-tool",
    lane: "npm",
    package: "fixture-tool",
    version: "1.0.0",
    integrity,
    lockSha256,
    verifiedAt: "2026-10-13T00:00:00.000Z"
  };
  fs.writeFileSync(receiptFile, `${JSON.stringify(receipt)}\n`);

  assert.match(resolveUpstreamBinary("fixture-tool", null, { paths }).executable, /fixture-tool/);

  const installedCli = path.join(directory, "node_modules", "fixture-tool", "cli.js");
  fs.writeFileSync(installedCli, "#!/usr/bin/env node\nconsole.log('modified');\n");
  fs.writeFileSync(receiptFile, `${JSON.stringify({ ...receipt, treeSha256: sha256(fs.readFileSync(installedCli)) })}\n`);
  assert.throws(
    () => resolveUpstreamBinary("fixture-tool", null, { paths }),
    /failed integrity verification/
  );
});

test("source readiness rejects replacement refs, hidden index flags, and every extra path", (t) => {
  const { repo, paths } = fixture(t);
  const directory = path.join(paths.upstreams, "fixture-source");
  fs.mkdirSync(directory, { recursive: true });
  git(directory, "init");
  git(directory, "config", "user.name", "GATE Test");
  git(directory, "config", "user.email", "gate-test@example.invalid");
  fs.writeFileSync(path.join(directory, ".gitignore"), "ignored.cfg\n");
  fs.writeFileSync(path.join(directory, "tracked.txt"), "reviewed\n");
  git(directory, "add", ".gitignore", "tracked.txt");
  git(directory, "commit", "-m", "fixture");
  const commit = git(directory, "rev-parse", "HEAD");
  writeLock(repo, [{
    id: "fixture-source",
    repository: "https://github.com/example/fixture-source.git",
    commit,
    version: null,
    install: { lane: "source", reason: "test source verification" }
  }]);

  assert.equal(upstreamStatus({ paths })[0].ready, true);

  fs.writeFileSync(path.join(directory, "tracked.txt"), "tampered\n");
  git(directory, "add", "tracked.txt");
  git(directory, "commit", "-m", "tampered replacement tree");
  const replacement = git(directory, "rev-parse", "HEAD");
  git(directory, "replace", commit, replacement);
  git(directory, "reset", "--hard", commit);
  assert.equal(git(directory, "rev-parse", "HEAD"), commit);
  assert.equal(git(directory, "status", "--porcelain"), "");
  assert.equal(upstreamStatus({ paths })[0].ready, false);
  git(directory, "replace", "-d", commit);
  git(directory, "reset", "--hard", commit);
  assert.equal(upstreamStatus({ paths })[0].ready, true);

  git(directory, "update-index", "--assume-unchanged", "tracked.txt");
  fs.writeFileSync(path.join(directory, "tracked.txt"), "hidden with assume-unchanged\n");
  assert.equal(upstreamStatus({ paths })[0].ready, false);
  git(directory, "update-index", "--no-assume-unchanged", "tracked.txt");
  git(directory, "checkout", "--", "tracked.txt");

  git(directory, "update-index", "--skip-worktree", "tracked.txt");
  fs.writeFileSync(path.join(directory, "tracked.txt"), "hidden with skip-worktree\n");
  assert.equal(upstreamStatus({ paths })[0].ready, false);
  git(directory, "update-index", "--no-skip-worktree", "tracked.txt");
  git(directory, "checkout", "--", "tracked.txt");

  fs.writeFileSync(path.join(directory, "ignored.cfg"), "unreviewed behavior\n");
  assert.equal(upstreamStatus({ paths })[0].ready, false);
  fs.rmSync(path.join(directory, "ignored.cfg"));

  fs.mkdirSync(path.join(directory, "feature-enabled"));
  assert.equal(git(directory, "status", "--porcelain", "--untracked-files=all"), "");
  assert.equal(upstreamStatus({ paths })[0].ready, false);
});

test("source verification does not invoke repository-configured filters or fsmonitor", (t) => {
  const { root, repo, paths } = fixture(t);
  const directory = path.join(paths.upstreams, "filtered-source");
  const sentinel = path.join(root, "filter-ran");
  const fsmonitorSentinel = path.join(root, "fsmonitor-ran");
  const filter = path.join(root, "filter.sh");
  const fsmonitor = path.join(root, "fsmonitor.sh");
  fs.mkdirSync(directory, { recursive: true });
  git(directory, "init");
  git(directory, "config", "user.name", "GATE Test");
  git(directory, "config", "user.email", "gate-test@example.invalid");
  fs.writeFileSync(path.join(directory, ".gitattributes"), "tracked.txt filter=gate-test-filter\n");
  fs.writeFileSync(path.join(directory, "tracked.txt"), "reviewed\n");
  git(directory, "add", ".gitattributes", "tracked.txt");
  git(directory, "commit", "-m", "filtered fixture");
  const commit = git(directory, "rev-parse", "HEAD");
  writeLock(repo, [{
    id: "filtered-source",
    repository: "https://github.com/example/filtered-source.git",
    commit,
    version: null,
    install: { lane: "source", reason: "test filter isolation" }
  }]);
  fs.writeFileSync(filter, `#!/bin/sh\nprintf ran > '${sentinel}'\ncat\n`);
  fs.chmodSync(filter, 0o700);
  fs.writeFileSync(fsmonitor, `#!/bin/sh\nprintf ran > '${fsmonitorSentinel}'\nexit 0\n`);
  fs.chmodSync(fsmonitor, 0o700);
  git(directory, "config", "filter.gate-test-filter.clean", filter);
  git(directory, "config", "filter.gate-test-filter.smudge", filter);
  git(directory, "config", "filter.gate-test-filter.required", "true");
  git(directory, "config", "core.fsmonitor", fsmonitor);

  git(directory, "ls-files", "-s");
  assert.equal(fs.existsSync(fsmonitorSentinel), true, "the fixture must reproduce Git's local fsmonitor execution");
  fs.rmSync(fsmonitorSentinel);

  assert.equal(upstreamStatus({ paths })[0].ready, true);
  assert.equal(fs.existsSync(sentinel), false);
  assert.equal(fs.existsSync(fsmonitorSentinel), false);
});
