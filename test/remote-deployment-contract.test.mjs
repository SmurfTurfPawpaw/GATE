import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const installerPath = path.join(repo, "deploy", "remote", "scripts", "gate-remote-install-release");

function installerSource() {
  return fs.readFileSync(installerPath, "utf8");
}

test("release installer is valid Bash and rejects malformed identities before privilege use", () => {
  const syntax = spawnSync("bash", ["-n", installerPath], { encoding: "utf8" });
  assert.equal(syntax.status, 0, syntax.stderr);

  const hostileDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "gate-installer-hostile-path-"));
  const hostileMarker = path.join(hostileDirectory, "ambient-cat-ran");
  fs.writeFileSync(path.join(hostileDirectory, "cat"), [
    "#!/bin/sh",
    `: > ${JSON.stringify(hostileMarker)}`,
    "exit 77"
  ].join("\n"), { mode: 0o755 });
  const help = spawnSync(installerPath, ["--help"], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: hostileDirectory,
      TAR_OPTIONS: `--checkpoint=1 --checkpoint-action=exec=${path.join(hostileDirectory, "cat")}`
    }
  });
  const hostileCatRan = fs.existsSync(hostileMarker);
  fs.rmSync(hostileDirectory, { recursive: true, force: true });
  assert.equal(help.status, 0, help.stderr);
  assert.equal(hostileCatRan, false, "help must not execute an ambient cat");
  assert.match(help.stdout, /immutable remote-cockpit\s+release/u);
  assert.match(help.stdout, /--stage-only/u);

  const invalid = spawnSync(installerPath, [
    "--deployment", "../other-service",
    "--archive", "/tmp/release.tar.gz",
    "--archive-sha256", "0".repeat(64),
    "--commit", "0".repeat(40),
    "--installer-sha256", "0".repeat(64),
    "--stage-only"
  ], { encoding: "utf8" });
  assert.notEqual(invalid.status, 0);
  assert.match(invalid.stderr, /deployment ID is invalid/u);

  if (typeof process.getuid !== "function" || process.getuid() !== 0) {
    const validUnprivileged = spawnSync(installerPath, [
      "--deployment", "example-case",
      "--archive", "/tmp/release.tar.gz",
      "--archive-sha256", "0".repeat(64),
      "--commit", "0".repeat(40),
      "--installer-sha256", "0".repeat(64)
    ], { encoding: "utf8" });
    assert.notEqual(validUnprivileged.status, 0);
    assert.match(validUnprivileged.stderr, /installer must run as root/u);
  }
});

test("release installer preserves the no-follow archive and bootstrap contracts", () => {
  const source = installerSource();
  assert.match(source, /^#!\/bin\/bash\n/u);
  assert.doesNotMatch(source, /^#!\/usr\/bin\/env bash/mu);
  const environmentReset = source.indexOf("export PATH=/usr/sbin:/usr/bin:/sbin:/bin");
  const argumentParser = source.indexOf("while (($#))");
  assert.ok(environmentReset > 0 && environmentReset < argumentParser);
  assert.ok(source.indexOf("unset TAR_OPTIONS", environmentReset) < argumentParser);
  assert.ok(source.indexOf("unset BASH_ENV", environmentReset) < argumentParser);
  assert.match(source, /curl --disable --noproxy/u);
  assert.match(source, /for helper_directory in \/usr\/local \/usr\/local\/sbin/u);

  const copy = source.indexOf('dd if="$archive" of="$snapshot"');
  const snapshotIdentity = source.indexOf("snapshot_stat=$(stat", copy);
  const snapshotBound = source.indexOf("snapshot_size <= MAX_ARCHIVE_BYTES", snapshotIdentity);
  const digest = source.indexOf("actual_archive_sha256=$(sha256sum", snapshotBound);
  const expandedBound = source.indexOf('bounded_command_output "$expanded_snapshot"', digest);
  const archiveListing = source.indexOf('tar --restrict --quoting-style=escape -tf "$expanded_snapshot"', expandedBound);
  assert.ok(copy > 0);
  assert.ok(copy < snapshotIdentity && snapshotIdentity < snapshotBound);
  assert.ok(snapshotBound < digest && digest < expandedBound && expandedBound < archiveListing);
  assert.match(source, /iflag=nofollow,nonblock,count_bytes,fullblock/u);
  assert.match(source, /oflag=nofollow/u);
  assert.match(source, /conv=excl,fsync/u);
  assert.match(source, /count=\$\(\(MAX_ARCHIVE_BYTES \+ 1\)\)/u);
  assert.doesNotMatch(source, /install[^\n]*"\$archive"[^\n]*"\$snapshot"/u);
  assert.match(source, /MAX_EXPANDED_ARCHIVE_BYTES=.*320 \* 1024 \* 1024/u);
  assert.match(source, /MAX_TAR_LISTING_BYTES=.*16 \* 1024 \* 1024/u);
  assert.match(source, /"expanded archive" gzip --decompress --stdout/u);
  assert.match(source, /"archive member listing" tar[^\n]*--restrict/u);
  assert.match(source, /"archive detail listing" tar[^\n]*--restrict/u);
  assert.doesNotMatch(source, /tar[^\n]*> "\$member_(?:list|details)"/u);

  const stagedRelease = source.indexOf('mv -- "$candidate" "$release"');
  const stageOnly = source.indexOf('if [[ "$stage_only" == true ]]');
  const inspectCurrent = source.indexOf("previous=", stageOnly);
  const firstSystemctl = source.indexOf("systemctl restart", stageOnly);
  assert.ok(stagedRelease > 0 && stagedRelease < stageOnly);
  assert.ok(stageOnly < inspectCurrent && inspectCurrent < firstSystemctl);
  assert.doesNotMatch(source.slice(stageOnly, inspectCurrent), /systemctl|\$current/u);
});

test("installer sanitization prevents inherited TAR_OPTIONS execution", (t) => {
  if (process.platform !== "linux") return t.skip("the production installer targets Linux");
  const source = installerSource();
  const preludeStart = source.indexOf("export PATH=/usr/sbin:/usr/bin:/sbin:/bin");
  const preludeEnd = source.indexOf("readonly DEPLOY_BASE=", preludeStart);
  assert.ok(preludeStart > 0 && preludeEnd > preludeStart);
  const prelude = source.slice(preludeStart, preludeEnd);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "gate-installer-tar-env-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const input = path.join(directory, "input");
  const archive = path.join(directory, "archive.tar");
  const marker = path.join(directory, "tar-options-ran");
  const payload = path.join(directory, "payload");
  fs.writeFileSync(input, "bounded\n");
  fs.writeFileSync(payload, `#!/bin/sh\n: > ${JSON.stringify(marker)}\n`, { mode: 0o755 });
  const packed = spawnSync("/usr/bin/tar", ["-cf", archive, "-C", directory, "input"], { encoding: "utf8" });
  assert.equal(packed.status, 0, packed.stderr);

  const probe = `${prelude}\n/usr/bin/tar --restrict -tf "$1" >/dev/null`;
  const result = spawnSync("/bin/bash", ["-c", probe, "bash", archive], {
    encoding: "utf8",
    env: {
      ...process.env,
      TAR_OPTIONS: `--checkpoint=1 --checkpoint-action=exec=${payload}`
    }
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(fs.existsSync(marker), false, "sanitized tar must not run the inherited checkpoint action");
});

test("activation interruption restores the previous link and restarts its service", (t) => {
  if (process.platform !== "linux") return t.skip("the production installer targets Linux");
  const source = installerSource();
  const extract = (startText, endText) => {
    const start = source.indexOf(startText);
    const end = source.indexOf(endText, start);
    assert.ok(start > 0 && end > start, startText);
    return source.slice(start, end);
  };
  const cleanup = extract("cleanup() {", "\ntrap cleanup EXIT");
  const activate = extract("activate_release() {", "\n\nservice_main_pid()");
  const restore = extract("restore_after_interruption() {", "\n\nactivation_in_progress=true");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "gate-installer-signal-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const oldCommit = "a".repeat(40);
  const newCommit = "b".repeat(40);
  fs.mkdirSync(path.join(directory, "releases", oldCommit), { recursive: true });
  fs.mkdirSync(path.join(directory, "releases", newCommit), { recursive: true });
  fs.symlinkSync(`releases/${oldCommit}`, path.join(directory, "current"));
  const probe = [
    "set -euo pipefail",
    "deploy_root=$1",
    'current="$deploy_root/current"',
    `previous=releases/${oldCommit}`,
    `release="$deploy_root/releases/${newCommit}"`,
    'service="gate-remote@test.service"',
    'work_directory="$deploy_root/work"',
    'mkdir -p "$work_directory"',
    'created_release=false',
    'activation_in_progress=false',
    'systemctl() { printf "%s\\n" "$*" >> "$deploy_root/systemctl.log"; }',
    cleanup,
    "trap cleanup EXIT",
    "trap 'exit 130' HUP INT TERM",
    activate,
    restore,
    "activation_in_progress=true",
    `activate_release releases/${newCommit}`,
    "kill -TERM $$",
    "exit 99"
  ].join("\n");
  const interrupted = spawnSync("/bin/bash", ["-c", probe, "bash", directory], { encoding: "utf8" });
  assert.equal(interrupted.status, 130, interrupted.stderr);
  assert.equal(fs.readlinkSync(path.join(directory, "current")), `releases/${oldCommit}`);
  assert.match(fs.readFileSync(path.join(directory, "systemctl.log"), "utf8"),
    /restart gate-remote@test\.service/u);
});

test("signals inside failed-activation recovery cannot bypass restart or stop", (t) => {
  if (process.platform !== "linux") return t.skip("the production installer targets Linux");
  const source = installerSource();
  const extract = (startText, endText) => {
    const start = source.indexOf(startText);
    const end = source.indexOf(endText, start);
    assert.ok(start > 0 && end > start, startText);
    return source.slice(start, end);
  };
  const cleanup = extract("cleanup() {", "\ntrap cleanup EXIT");
  const activate = extract("activate_release() {", "\n\nservice_main_pid()");
  const restore = extract("restore_after_interruption() {", "\n\nactivation_in_progress=true");
  const rollbackStart = source.indexOf("printf 'gate remote deploy: activation failed; starting rollback");
  assert.ok(rollbackStart > 0);
  const rollback = source.slice(rollbackStart);

  for (const hasPrevious of [true, false]) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "gate-installer-recovery-signal-"));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    const oldCommit = "c".repeat(40);
    const newCommit = "d".repeat(40);
    fs.mkdirSync(path.join(directory, "releases", oldCommit), { recursive: true });
    fs.mkdirSync(path.join(directory, "releases", newCommit), { recursive: true });
    fs.symlinkSync(`releases/${newCommit}`, path.join(directory, "current"));
    const probe = [
      "set -euo pipefail",
      "deploy_root=$1",
      'current="$deploy_root/current"',
      hasPrevious ? `previous=releases/${oldCommit}` : "previous=",
      `release="$deploy_root/releases/${newCommit}"`,
      'service="gate-remote@test.service"',
      'work_directory="$deploy_root/work"',
      'mkdir -p "$work_directory"',
      'created_release=false',
      'activation_in_progress=true',
      'systemctl_calls=0',
      'systemctl() { systemctl_calls=$((systemctl_calls + 1)); if [[ $systemctl_calls == 1 ]]; then kill -TERM $$; fi; printf "%s\\n" "$*" >> "$deploy_root/systemctl.log"; }',
      'wait_until_ready() { return 0; }',
      'fail() { printf "%s\\n" "$*" >&2; exit 1; }',
      cleanup,
      "trap cleanup EXIT",
      "trap 'exit 130' HUP INT TERM",
      activate,
      restore,
      rollback
    ].join("\n");
    const interrupted = spawnSync("/bin/bash", ["-c", probe, "bash", directory], { encoding: "utf8" });
    assert.equal(interrupted.status, 130, interrupted.stderr);
    if (hasPrevious) {
      assert.equal(fs.readlinkSync(path.join(directory, "current")), `releases/${oldCommit}`);
      assert.match(fs.readFileSync(path.join(directory, "systemctl.log"), "utf8"),
        /restart gate-remote@test\.service/u);
    } else {
      assert.equal(fs.existsSync(path.join(directory, "current")), false);
      assert.match(fs.readFileSync(path.join(directory, "systemctl.log"), "utf8"),
        /stop gate-remote@test\.service/u);
    }
  }
});

test("sudo delegation binds environment, helper path, and exact helper digest", () => {
  const sudoers = fs.readFileSync(path.join(repo, "deploy", "remote", "gate-remote-deployer.sudoers.example"), "utf8");
  assert.match(sudoers, /env_reset/u);
  assert.match(sudoers, /secure_path="\/usr\/sbin:\/usr\/bin:\/sbin:\/bin"/u);
  assert.match(sudoers, /NOPASSWD:NOSETENV:/u);
  assert.match(sudoers, /sha256:REPLACE_WITH_64_CHARACTER_LOWERCASE_INSTALLER_SHA256/u);
  assert.match(sudoers, /\/usr\/local\/sbin\/gate-remote-install-release/u);
});

test("expanded archive and tar metadata output stop at a hard byte sentinel", (t) => {
  if (process.platform !== "linux") return t.skip("the production installer targets Linux");
  const source = installerSource();
  const functionStart = source.indexOf("bounded_command_output() {");
  const functionEnd = source.indexOf("\n}\n\n# Bound the complete decompressed", functionStart);
  assert.ok(functionStart > 0 && functionEnd > functionStart);
  const boundedFunction = source.slice(functionStart, functionEnd + 2)
    .replace('"$output_uid" == 0', '"$output_uid" == "$EUID"');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "gate-installer-expanded-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const compressed = path.join(directory, "metadata-bomb.gz");
  fs.writeFileSync(compressed, gzipSync(Buffer.alloc(64 * 1024, 0x41), { level: 9 }));
  const output = path.join(directory, "expanded.tar");
  const probe = [
    "set -euo pipefail",
    'fail() { printf "%s\\n" "$*" >&2; exit 1; }',
    boundedFunction,
    'bounded_command_output "$2" "$1" "expanded archive" gzip --decompress --stdout -- "$3"'
  ].join("\n");
  const bounded = spawnSync("/bin/bash", ["-c", probe, "bash", "4096", output, compressed], {
    encoding: "utf8"
  });
  assert.notEqual(bounded.status, 0);
  assert.match(bounded.stderr, /exceeds its reviewed byte bound/u);
  assert.equal(fs.statSync(output).size, 4097);
});

test("GNU dd primitives used by the installer reject symlinks and preserve the over-limit sentinel", (t) => {
  if (process.platform !== "linux") return t.skip("the production installer targets Linux");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "gate-installer-dd-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const source = path.join(directory, "source.tar.gz");
  const link = path.join(directory, "source-link.tar.gz");
  fs.writeFileSync(source, Buffer.alloc(32, 0x41));
  fs.symlinkSync(source, link);

  const flags = [
    "bs=1M", "iflag=nofollow,nonblock,count_bytes,fullblock", "oflag=nofollow",
    "count=9", "conv=excl,fsync", "status=none"
  ];
  const linked = spawnSync("dd", [`if=${link}`, `of=${path.join(directory, "linked-copy")}`, ...flags], {
    encoding: "utf8"
  });
  assert.notEqual(linked.status, 0);

  const boundedPath = path.join(directory, "bounded-copy");
  const bounded = spawnSync("dd", [`if=${source}`, `of=${boundedPath}`, ...flags], { encoding: "utf8" });
  assert.equal(bounded.status, 0, bounded.stderr);
  assert.equal(fs.statSync(boundedPath).size, 9);
});

test("readiness binds the exact response to the active systemd MainPID listener", async (t) => {
  if (process.platform !== "linux") return t.skip("the production readiness proof uses Linux procfs");
  const source = installerSource();
  const functionStart = source.indexOf("pid_owns_health_listener() {");
  const functionEnd = source.indexOf("\n}\n\nready_for_pid()", functionStart);
  assert.ok(functionStart > 0 && functionEnd > functionStart);
  const listenerFunction = source.slice(functionStart, functionEnd + 2);

  assert.match(source, /systemctl is-active --quiet "\$service"/u);
  assert.match(source, /systemctl show --property=MainPID --value "\$service"/u);
  assert.match(source, /\/proc\/\$expected_pid\/fd/u);
  assert.match(source, /\/proc\/net\/tcp \/proc\/net\/tcp6/u);
  assert.match(source, /"\$response" == '\{"ok":true,"service":"gate-remote-cockpit-ready"\}'/u);
  assert.doesNotMatch(source, /"\$response" == \*'"ok":true'/u);

  const server = net.createServer();
  t.after(() => server.close());
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.equal(typeof address, "object");
  const probe = [
    "set -euo pipefail",
    "health_port=$1",
    "health_port_decimal=$1",
    listenerFunction,
    'pid_owns_health_listener "$2"'
  ].join("\n");
  const owner = spawnSync("/bin/bash", ["-c", probe, "bash", String(address.port), String(process.pid)], {
    encoding: "utf8"
  });
  assert.equal(owner.status, 0, owner.stderr);
  const unrelated = spawnSync("/bin/bash", ["-c", probe, "bash", String(address.port), "99999999"], {
    encoding: "utf8"
  });
  assert.notEqual(unrelated.status, 0);
});
