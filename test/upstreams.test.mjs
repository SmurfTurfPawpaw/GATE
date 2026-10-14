import assert from "node:assert/strict";
import childProcess, { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { runtimePaths } from "../src/lib/paths.mjs";
import {
  inspectReleaseArchive,
  installUpstream,
  readVerifiedReleaseExecutable,
  resolveUpstreamBinary,
  upstreamStatus
} from "../src/lib/upstreams.mjs";

const sourceRepo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const fixedGitHubCli = process.platform === "win32"
  ? "C:\\Program Files\\GitHub CLI\\gh.exe"
  : ["/usr/bin/gh", "/bin/gh", "/usr/local/bin/gh"].find((candidate) => fs.existsSync(candidate));

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

test("native Windows protected upstream execution fails closed in favor of WSL", {
  skip: process.platform !== "win32"
}, (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-native-windows-upstream-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const archive = path.join(root, "fixture.tar");
  fs.writeFileSync(archive, "not an archive");
  assert.throws(
    () => inspectReleaseArchive(archive),
    /protected upstream execution is unavailable on native Windows; run GATE inside WSL/u
  );
});

test("release verification binds hash, inspection, and executable extraction to one archive snapshot", {
  skip: process.platform === "win32"
}, (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-release-snapshot-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const content = path.join(root, "content");
  fs.mkdirSync(content);
  const executableBytes = Buffer.from("reviewed executable bytes\n");
  fs.writeFileSync(path.join(content, "fixture-release"), executableBytes);
  fs.writeFileSync(path.join(content, "unrelated.txt"), "must not be extracted\n");
  const archive = path.join(root, "fixture-release.tar.gz");
  execFileSync("tar", ["-czf", archive, "-C", content, "fixture-release", "unrelated.txt"]);
  const artifact = {
    name: path.basename(archive),
    sha256: sha256(fs.readFileSync(archive)),
    executableSha256: sha256(executableBytes)
  };
  const before = fs.readdirSync(root).sort();
  const verified = readVerifiedReleaseExecutable(archive, artifact, "fixture-release");
  assert.deepEqual(verified.executable, executableBytes);
  assert.deepEqual(fs.readdirSync(root).sort(), before, "verification must not unpack archive entries");

  const originalSpawnSync = childProcess.spawnSync;
  childProcess.spawnSync = function failBinaryTarExtraction(command, args, options) {
    if (/^-x/u.test(args?.[0] || "") && options?.encoding === null) {
      return { status: 2, signal: null, error: undefined, stdout: Buffer.alloc(0), stderr: Buffer.from("binary tar failure\n") };
    }
    return originalSpawnSync.call(childProcess, command, args, options);
  };
  syncBuiltinESMExports();
  try {
    assert.throws(
      () => readVerifiedReleaseExecutable(archive, artifact, "fixture-release"),
      /binary tar failure/u
    );
  } finally {
    childProcess.spawnSync = originalSpawnSync;
    syncBuiltinESMExports();
  }

  const raceArchive = path.join(root, "race.tar.gz");
  fs.copyFileSync(archive, raceArchive);
  const replacementContent = path.join(root, "replacement-content");
  fs.mkdirSync(replacementContent);
  fs.writeFileSync(path.join(replacementContent, "fixture-release"), "unreviewed replacement\n");
  const replacementArchive = path.join(root, "replacement.tar.gz");
  execFileSync("tar", ["-czf", replacementArchive, "-C", replacementContent, "fixture-release"]);
  const raceIdentity = fs.statSync(raceArchive, { bigint: true });
  const originalReadSync = fs.readSync;
  let swapped = false;
  fs.readSync = function readAndSwap(file, buffer, offset, length, position) {
    const bytesRead = originalReadSync.call(fs, file, buffer, offset, length, position);
    if (!swapped && typeof file === "number" && BigInt(offset + bytesRead) === raceIdentity.size) {
      const identity = fs.fstatSync(file, { bigint: true });
      if (identity.dev === raceIdentity.dev && identity.ino === raceIdentity.ino) {
        fs.renameSync(replacementArchive, raceArchive);
        swapped = true;
      }
    }
    return bytesRead;
  };
  try {
    assert.throws(
      () => readVerifiedReleaseExecutable(raceArchive, artifact, "fixture-release"),
      /release archive changed while it was read/u
    );
  } finally {
    fs.readSync = originalReadSync;
  }
  assert.equal(swapped, true, "the regression must replace the archive after its descriptor is read");
});

test("release archive and download tooling reject ambient command and configuration injection", {
  skip: process.platform === "win32" || !fixedGitHubCli
}, (t) => {
  const { root, repo, paths } = fixture(t);
  const content = path.join(root, "release-content");
  const fakeBin = path.join(root, "fake-bin");
  const sentinel = path.join(root, "fresh-binary-ran");
  const tarOptionsSentinel = path.join(root, "tar-options-ran");
  const pathTarSentinel = path.join(root, "path-tar-ran");
  const pathGitHubCliSentinel = path.join(root, "path-gh-ran");
  const tarOptionsCanary = path.join(root, "tar-options-canary");
  const hostileGitHubConfig = path.join(root, "ambient-gh-config-file");
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
printf ran > '${pathGitHubCliSentinel}'
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
  fs.writeFileSync(hostileGitHubConfig, "ambient config must not be read\n", { mode: 0o600 });
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
  const protectedEnvironment = new Map([
    ["GH_CONFIG_DIR", process.env.GH_CONFIG_DIR],
    ["GH_HOST", process.env.GH_HOST],
    ["GH_TOKEN", process.env.GH_TOKEN],
    ["GITHUB_TOKEN", process.env.GITHUB_TOKEN],
    ["HTTP_PROXY", process.env.HTTP_PROXY],
    ["HTTPS_PROXY", process.env.HTTPS_PROXY],
    ["NO_PROXY", process.env.NO_PROXY],
    ["http_proxy", process.env.http_proxy],
    ["https_proxy", process.env.https_proxy],
    ["no_proxy", process.env.no_proxy],
    ["LD_PRELOAD", process.env.LD_PRELOAD]
  ]);
  process.env.PATH = `${fakeBin}${path.delimiter}${previousPath}`;
  process.env.GATE_TEST_RELEASE_ARCHIVE = archive;
  process.env.TAR_OPTIONS = maliciousTarOptions;
  process.env.GH_CONFIG_DIR = hostileGitHubConfig;
  process.env.GH_HOST = "attacker.invalid";
  delete process.env.GH_TOKEN;
  delete process.env.GITHUB_TOKEN;
  assert.throws(
    () => installUpstream("fixture-release", { paths }),
    /requires GH_TOKEN or GITHUB_TOKEN/u
  );
  process.env.GH_TOKEN = "gate-test-token";
  process.env.HTTP_PROXY = "http://127.0.0.1:1";
  process.env.HTTPS_PROXY = "http://127.0.0.1:1";
  process.env.NO_PROXY = "";
  process.env.http_proxy = "http://127.0.0.1:1";
  process.env.https_proxy = "http://127.0.0.1:1";
  process.env.no_proxy = "";
  process.env.LD_PRELOAD = path.join(root, "ambient-loader-must-not-load.so");
  try {
    assert.deepEqual(inspectReleaseArchive(archive), ["fixture-release"]);
    assert.throws(
      () => installUpstream("fixture-release", { paths }),
      (error) => {
        assert.match(error.message, /(?:proxy|connect|127\.0\.0\.1)/iu);
        assert.doesNotMatch(error.message, /(?:LD_PRELOAD|ld\.so|ambient-gh-config-file|attacker\.invalid)/iu);
        return true;
      }
    );
  } finally {
    process.env.PATH = previousPath;
    if (previousArchive === undefined) delete process.env.GATE_TEST_RELEASE_ARCHIVE;
    else process.env.GATE_TEST_RELEASE_ARCHIVE = previousArchive;
    if (previousTarOptions === undefined) delete process.env.TAR_OPTIONS;
    else process.env.TAR_OPTIONS = previousTarOptions;
    for (const [name, value] of protectedEnvironment) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
  assert.equal(fs.existsSync(sentinel), false);
  assert.equal(fs.existsSync(tarOptionsSentinel), false);
  assert.equal(fs.existsSync(pathTarSentinel), false);
  assert.equal(fs.existsSync(pathGitHubCliSentinel), false);
});

test("offline REA resolution uses bundled npm with a clean environment and rejects a forged tree receipt", {
  skip: process.platform === "win32"
}, (t) => {
  const { root, repo, home, paths } = fixture(t);
  const packageRoot = path.join(root, "fixture-package");
  const cache = path.join(home, "cache", "npm");
  fs.mkdirSync(packageRoot, { recursive: true });
  fs.mkdirSync(cache, { recursive: true });
  fs.writeFileSync(path.join(packageRoot, "package.json"), JSON.stringify({
    name: "rea-agents",
    version: "1.0.0",
    bin: { rea: "cli.js" }
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

  const lockDirectory = path.join(repo, "locks", "npm", "rea-stable");
  fs.mkdirSync(lockDirectory, { recursive: true });
  const packageManifest = {
    name: "gate-upstream-rea-stable",
    private: true,
    version: "0.0.0",
    dependencies: { "rea-agents": "1.0.0" }
  };
  const packageLock = {
    name: "gate-upstream-rea-stable",
    lockfileVersion: 3,
    requires: true,
    packages: {
      "": { dependencies: { "rea-agents": "1.0.0" } },
      "node_modules/rea-agents": {
        version: "1.0.0",
        resolved: "https://registry.npmjs.org/rea-agents/-/rea-agents-1.0.0.tgz",
        integrity,
        bin: { rea: "cli.js" }
      }
    }
  };
  const packageFile = path.join(lockDirectory, "package.json");
  const lockFile = path.join(lockDirectory, "package-lock.json");
  fs.writeFileSync(packageFile, `${JSON.stringify(packageManifest, null, 2)}\n`);
  fs.writeFileSync(lockFile, `${JSON.stringify(packageLock, null, 2)}\n`);
  const lockSha256 = sha256(fs.readFileSync(lockFile));
  writeLock(repo, [{
    id: "rea-stable",
    repository: "https://github.com/example/rea.git",
    commit: "c".repeat(40),
    version: "1.0.0",
    install: {
      lane: "npm",
      package: "rea-agents",
      integrity,
      lockfile: "locks/npm/rea-stable/package-lock.json",
      lockSha256
    }
  }]);

  const directory = path.join(paths.upstreamTools, "rea-stable");
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
    id: "rea-stable",
    lane: "npm",
    package: "rea-agents",
    version: "1.0.0",
    integrity,
    lockSha256,
    verifiedAt: "2026-10-13T00:00:00.000Z"
  };
  fs.writeFileSync(receiptFile, `${JSON.stringify(receipt)}\n`);

  assert.match(resolveUpstreamBinary("rea-stable", "rea", { paths }).executable, /rea/u);

  const fakeBin = path.join(root, "fake-npm-bin");
  const pathSentinel = path.join(root, "ambient-path-npm-ran");
  const nodeOptionsSentinel = path.join(root, "ambient-node-options-ran");
  const nodeOptionsHook = path.join(root, "ambient-node-options.cjs");
  fs.mkdirSync(fakeBin);
  fs.writeFileSync(
    path.join(fakeBin, process.platform === "win32" ? "npm.cmd" : "npm"),
    process.platform === "win32"
      ? `@echo ran>"${pathSentinel}"\r\n@exit /b 99\r\n`
      : `#!/bin/sh\nprintf ran > '${pathSentinel}'\nexit 99\n`,
    { mode: 0o700 }
  );
  fs.writeFileSync(
    nodeOptionsHook,
    `require("node:fs").writeFileSync(${JSON.stringify(nodeOptionsSentinel)}, "ran");\n`,
    { mode: 0o600 }
  );
  const previousPath = process.env.PATH;
  const previousNodeOptions = process.env.NODE_OPTIONS;
  try {
    process.env.PATH = `${fakeBin}${path.delimiter}${previousPath || ""}`;
    delete process.env.NODE_OPTIONS;
    assert.match(resolveUpstreamBinary("rea-stable", "rea", { paths }).executable, /rea/u);
    assert.equal(fs.existsSync(pathSentinel), false, "ambient PATH npm must not execute");

    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
    process.env.NODE_OPTIONS = `--require=${nodeOptionsHook}`;
    execFileSync(process.execPath, ["-e", ""], { env: { ...process.env } });
    assert.equal(fs.existsSync(nodeOptionsSentinel), true, "the NODE_OPTIONS fixture must execute without hardening");
    fs.rmSync(nodeOptionsSentinel);
    assert.match(resolveUpstreamBinary("rea-stable", "rea", { paths }).executable, /rea/u);
    assert.equal(fs.existsSync(nodeOptionsSentinel), false, "ambient NODE_OPTIONS must not reach bundled npm");
  } finally {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
    if (previousNodeOptions === undefined) delete process.env.NODE_OPTIONS;
    else process.env.NODE_OPTIONS = previousNodeOptions;
  }

  if (process.platform === "linux") {
    assert.equal(fs.existsSync("/usr/bin/bwrap"), true, "Linux npm closure coverage requires Bubblewrap");
    const realNode = fs.realpathSync.native(process.execPath);
    const realInstallationRoot = path.resolve(path.dirname(realNode), "..");
    const npmCli = [
      path.join(realInstallationRoot, "lib", "node_modules", "npm", "bin", "npm-cli.js"),
      path.join(realInstallationRoot, "share", "nodejs", "npm", "bin", "npm-cli.js"),
      path.join(realInstallationRoot, "node_modules", "npm", "bin", "npm-cli.js")
    ].find((candidate) => fs.existsSync(candidate));
    assert.ok(npmCli, "the current Node installation must expose its bundled npm CLI for this regression");
    const npmRoot = path.resolve(path.dirname(npmCli), "..");
    const mutableLib = path.join(root, "mutable-npm-lib");
    const mutableMarker = path.join(root, "mutable-npm-implementation-ran");
    fs.cpSync(path.join(npmRoot, "lib"), mutableLib, {
      recursive: true,
      preserveTimestamps: true
    });
    const mutableCliImplementation = path.join(mutableLib, "cli.js");
    fs.writeFileSync(
      mutableCliImplementation,
      `require("node:fs").writeFileSync(${JSON.stringify(mutableMarker)}, "ran");\n${fs.readFileSync(mutableCliImplementation, "utf8")}`
    );
    const childScript = path.join(root, "mutable-runtime-check.mjs");
    fs.writeFileSync(childScript, `
import { installUpstream } from ${JSON.stringify(pathToFileURL(path.join(sourceRepo, "src", "lib", "upstreams.mjs")).href)};
const paths = ${JSON.stringify(paths)};
try {
  installUpstream("rea-stable", { paths });
  process.exitCode = 91;
} catch (error) {
  process.stdout.write(String(error.message));
}
`);
    const rejection = execFileSync("/usr/bin/bwrap", [
      "--die-with-parent",
      "--ro-bind", "/", "/",
      "--bind", root, root,
      "--bind", mutableLib, path.join(npmRoot, "lib"),
      "--proc", "/proc",
      "--dev", "/dev",
      "--",
      realNode,
      childScript
    ], {
      encoding: "utf8",
      env: {},
      timeout: 120_000
    });
    assert.match(rejection, /bundled npm implementation is owned by the current process identity/u);
    assert.equal(fs.existsSync(mutableMarker), false, "a mutable npm implementation must be rejected before execution");
  }

  const installedCli = path.join(directory, "node_modules", "rea-agents", "cli.js");
  fs.writeFileSync(installedCli, "#!/usr/bin/env node\nconsole.log('modified');\n");
  fs.writeFileSync(receiptFile, `${JSON.stringify({ ...receipt, treeSha256: sha256(fs.readFileSync(installedCli)) })}\n`);
  assert.throws(
    () => resolveUpstreamBinary("rea-stable", "rea", { paths }),
    /failed integrity verification/
  );
});

test("source readiness rejects replacement refs, hidden index flags, and every extra path", {
  skip: process.platform === "win32"
}, (t) => {
  const { root, repo, paths } = fixture(t);
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

  const fakeBin = path.join(root, "fake-git-bin");
  const pathGitSentinel = path.join(root, "ambient-path-git-ran");
  fs.mkdirSync(fakeBin);
  fs.writeFileSync(
    path.join(fakeBin, process.platform === "win32" ? "git.exe" : "git"),
    process.platform === "win32"
      ? "This fixture is intentionally not a valid executable.\n"
      : `#!/bin/sh\nprintf ran > '${pathGitSentinel}'\nexit 99\n`,
    { mode: 0o700 }
  );
  const previousPath = process.env.PATH;
  try {
    process.env.PATH = `${fakeBin}${path.delimiter}${previousPath || ""}`;
    assert.equal(upstreamStatus({ paths })[0].ready, true);
  } finally {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
  }
  assert.equal(fs.existsSync(pathGitSentinel), false, "ambient PATH Git must not execute");

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

test("source verification does not invoke repository-configured filters or fsmonitor", {
  skip: process.platform === "win32"
}, (t) => {
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
