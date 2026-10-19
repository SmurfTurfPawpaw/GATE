import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  initializeRemoteCase,
  inspectRemoteCase,
  remoteSetupInternals
} from "../src/lib/remote-setup.mjs";
import { runtimePaths } from "../src/lib/paths.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const gate = path.join(repo, "bin", "gate.mjs");

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-remote-setup-"));
  const home = path.join(root, "home");
  const working = path.join(root, "case-work");
  fs.mkdirSync(working, { mode: 0o700 });
  const paths = runtimePaths({ home });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, home, working, paths };
}

function input(working, overrides = {}) {
  return {
    caseId: "demo-case",
    origin: "https://gate.example.test",
    issuer: "https://identity.example.test/oidc",
    audience: "gate.example.test",
    subject: "operator-subject-001",
    jwksUrl: "https://identity.example.test/.well-known/jwks.json",
    repository: working,
    coordinatorConfigRoot: "/etc/gate-remote/demo-case",
    coordinatorStateRoot: "/var/lib/gate-remote/demo-case",
    runnerId: "runner-demo-001",
    sessionRevision: 3,
    port: 43_180,
    identityHeader: "x-gate-oidc-assertion",
    observerUrl: "http://127.0.0.1:4173/api/status",
    ...overrides
  };
}

function fakeCodexProbe(secret = "PROBE_SECRET_CANARY") {
  const invocations = [];
  const run = (command, args, options) => {
    invocations.push({ command, args, options });
    if (args.length === 1 && args[0] === "--version") {
      return { status: 0, stdout: `${remoteSetupInternals.EXPECTED_CODEX_VERSION}\n${secret}\n`, stderr: "" };
    }
    if (args[0] === "login" && args[1] === "status") {
      return { status: 0, stdout: `Logged in ${secret}\n`, stderr: "" };
    }
    return { status: 1, stdout: "", stderr: secret };
  };
  return { invocations, run };
}

function fakeCodexLaunch(codexHome) {
  const command = path.join(path.parse(codexHome).root, "protected", process.platform === "win32" ? "codex.EXE" : "codex");
  return {
    command,
    environment: { PATH: path.dirname(command), HOME: codexHome, CODEX_HOME: codexHome }
  };
}

test("remote init creates one owner-only case bundle outside Git with matching Ed25519 enrollment", (t) => {
  if (process.platform === "win32") return t.skip("POSIX owner-only modes are asserted on the WSL/Linux control plane");
  const { home, working, paths } = fixture(t);
  const result = initializeRemoteCase(input(working), {
    paths,
    now: () => "2026-10-19T12:00:00.000Z"
  });
  const locations = remoteSetupInternals.layout(paths, "demo-case");

  assert.equal(result.ok, true);
  assert.equal(result.stateDirectory, locations.root);
  assert.equal(path.relative(paths.repo, locations.root).startsWith(".."), true);
  assert.equal(locations.root.startsWith(path.join(home, "remote")), true);
  for (const directory of [
    locations.root,
    locations.runner,
    locations.runnerCodexHome,
    locations.coordinator
  ]) assert.equal(fs.statSync(directory).mode & 0o777, 0o700, directory);
  for (const file of [
    locations.manifest,
    locations.runnerPrivateKey,
    locations.runnerPublicKey,
    locations.runnerEnvironment,
    locations.coordinatorConfig,
    locations.coordinatorPublicKey
  ]) assert.equal(fs.statSync(file).mode & 0o777, 0o600, file);

  const privateKey = crypto.createPrivateKey(fs.readFileSync(locations.runnerPrivateKey));
  const derived = crypto.createPublicKey(privateKey).export({ type: "spki", format: "der" });
  for (const file of [locations.runnerPublicKey, locations.coordinatorPublicKey]) {
    const actual = crypto.createPublicKey(fs.readFileSync(file)).export({ type: "spki", format: "der" });
    assert.deepEqual(actual, derived);
  }
  const config = JSON.parse(fs.readFileSync(locations.coordinatorConfig, "utf8"));
  const manifest = JSON.parse(fs.readFileSync(locations.manifest, "utf8"));
  assert.equal(manifest.coordinatorConfigRoot, "/etc/gate-remote/demo-case");
  assert.equal(manifest.coordinatorStateRoot, "/var/lib/gate-remote/demo-case");
  assert.equal(config.databasePath, "/var/lib/gate-remote/demo-case/bridge.sqlite");
  assert.equal(config.runner.publicKeyPath, "/etc/gate-remote/demo-case/runner-public.pem");
  assert.equal(config.oidc.operatorSubject, config.operatorId);
  assert.doesNotMatch(JSON.stringify(config), /runner-private|\/runner\//u);
  const environment = fs.readFileSync(locations.runnerEnvironment, "utf8");
  assert.match(environment, new RegExp(`GATE_REMOTE_PRIVATE_KEY_FILE=.*${path.basename(locations.runnerPrivateKey)}`, "u"));
  assert.doesNotMatch(environment, /BEGIN PRIVATE KEY/u);
  assert.equal(fs.existsSync(locations.runnerThreadRecord), false);
  assert.match(result.publicKeyFingerprint, /^sha256:[a-f0-9]{64}$/u);
  assert.doesNotMatch(JSON.stringify(result), /BEGIN PRIVATE KEY/u);
});

test("public runner environment reference mirrors the generated runner subdirectory", (t) => {
  const { working, paths } = fixture(t);
  initializeRemoteCase(input(working), { paths });
  const locations = remoteSetupInternals.layout(paths, "demo-case");
  const decodeShellLiteral = (raw) => raw.startsWith("'") && raw.endsWith("'")
    ? raw.slice(1, -1).replaceAll(`'"'"'`, "'")
    : raw;
  const parseAssignments = (value) => Object.fromEntries(value
    .split(/\r?\n/u)
    .filter((line) => /^[A-Z][A-Z0-9_]*=/u.test(line))
    .map((line) => {
      const delimiter = line.indexOf("=");
      return [line.slice(0, delimiter), decodeShellLiteral(line.slice(delimiter + 1))];
    }));
  const generated = parseAssignments(fs.readFileSync(locations.runnerEnvironment, "utf8"));
  const example = parseAssignments(fs.readFileSync(path.join(repo, "deploy", "remote", "runner.env.example"), "utf8"));
  const exampleRoot = "/home/operator/.local/share/gate/remote/example-case";
  for (const [variable, location] of [
    ["GATE_REMOTE_PRIVATE_KEY_FILE", locations.runnerPrivateKey],
    ["GATE_REMOTE_JOURNAL_DIR", locations.runner],
    ["GATE_REMOTE_CODEX_HOME", locations.runnerCodexHome],
    ["GATE_REMOTE_THREAD_ID_FILE", locations.runnerThreadRecord]
  ]) {
    assert.equal(
      path.posix.relative(exampleRoot, example[variable]),
      path.relative(locations.root, generated[variable]).split(path.sep).join("/"),
      variable
    );
    assert.match(example[variable], /\/runner(?:\/|$)/u, variable);
  }
});

test("repository-local remote init exposes a bounded summary and dispatches into private GATE_HOME state", (t) => {
  if (process.platform === "win32") return t.skip("CLI fixture targets the WSL/Linux control plane");
  const { root, home, working } = fixture(t);
  const fakeBin = path.join(root, "bin");
  fs.mkdirSync(fakeBin, { mode: 0o700 });
  fs.writeFileSync(path.join(fakeBin, "codex"), [
    "#!/usr/bin/env node",
    "if (process.argv[2] === '--version') console.log('codex-cli 0.159.2');",
    "else if (process.argv[2] === 'login' && process.argv[3] === 'status') console.log('Logged in');",
    "else process.exitCode = 2;",
    ""
  ].join("\n"), { mode: 0o700 });
  const environment = { ...process.env, PATH: fakeBin, GATE_HOME: home, GATE_CASE: "" };
  const result = spawnSync(process.execPath, [
    gate, "remote", "init", "cli-case",
    "--origin", "https://gate.example.test",
    "--issuer", "https://identity.example.test/oidc",
    "--audience", "gate.example.test",
    "--subject", "operator-subject-001",
    "--jwks-url", "https://identity.example.test/.well-known/jwks.json",
    "--repo", working,
    "--coordinator-config-root", "/etc/gate-remote/cli-case",
    "--coordinator-state-root", "/var/lib/gate-remote/cli-case",
    "--json"
  ], {
    cwd: repo,
    env: environment,
    encoding: "utf8",
    timeout: 10_000
  });
  assert.equal(result.status, 0, result.stderr);
  const summary = JSON.parse(result.stdout);
  assert.equal(summary.caseId, "cli-case");
  assert.equal(summary.next, "./bin/gate.mjs remote doctor cli-case");
  assert.match(summary.publicKeyFingerprint, /^sha256:[a-f0-9]{64}$/u);
  assert.equal(summary.coordinatorConfigRoot, "/etc/gate-remote/cli-case");
  assert.equal(summary.coordinatorStateRoot, "/var/lib/gate-remote/cli-case");
  assert.doesNotMatch(result.stdout, /BEGIN PRIVATE KEY/u);
  assert.equal(fs.existsSync(path.join(home, "remote", "cli-case", "runner", "runner-private.pem")), true);

  const doctor = spawnSync(process.execPath, [gate, "remote", "doctor", "cli-case", "--json"], {
    cwd: repo,
    env: environment,
    encoding: "utf8",
    timeout: 10_000
  });
  assert.equal(doctor.status, 1, doctor.stderr);
  const report = JSON.parse(doctor.stdout);
  assert.equal(report.ok, false);
  assert.equal(report.liveReady, false);
  assert.equal(report.counts.unverified, 2);
  assert.equal(report.checks.find((check) => check.id === "codex-version").status, "failed");
});

test("generated runner environment shell-quotes a hostile but valid working-directory name", (t) => {
  if (process.platform === "win32") return t.skip("runner environment is sourced by the WSL/Linux shell");
  const fixtureRoot = fixture(t);
  const working = path.join(fixtureRoot.root, "work-'$(touch PWNED_CANARY)'");
  fs.mkdirSync(working, { mode: 0o700 });
  initializeRemoteCase(input(working), { paths: fixtureRoot.paths });
  const environmentFile = remoteSetupInternals.layout(fixtureRoot.paths, "demo-case").runnerEnvironment;
  const sourced = spawnSync("bash", ["-c", 'set -a; . "$1"; printf "%s" "$GATE_REPO"', "bash", environmentFile], {
    cwd: fixtureRoot.root,
    env: { PATH: process.env.PATH || "" },
    encoding: "utf8",
    timeout: 5_000
  });
  assert.equal(sourced.status, 0, sourced.stderr);
  assert.equal(sourced.stdout, working);
  assert.equal(fs.existsSync(path.join(fixtureRoot.root, "PWNED_CANARY")), false);
});

test("remote doctor validates local prerequisites without returning probe output or ambient credentials", (t) => {
  const { working, paths } = fixture(t);
  initializeRemoteCase(input(working), { paths });
  const probe = fakeCodexProbe();
  const launchRequests = [];
  const oldToken = process.env.GH_TOKEN;
  process.env.GH_TOKEN = "AMBIENT_GITHUB_SECRET_CANARY";
  t.after(() => {
    if (oldToken === undefined) delete process.env.GH_TOKEN;
    else process.env.GH_TOKEN = oldToken;
  });

  const report = inspectRemoteCase("demo-case", {
    paths,
    commandRunner: probe.run,
    prepareCodexLaunch: (source, codexHome, forbiddenRoots) => {
      launchRequests.push({ source, codexHome, forbiddenRoots });
      return fakeCodexLaunch(codexHome);
    },
    nodeVersion: "22.20.0",
    sqliteAvailable: true
  });
  assert.equal(report.ok, true);
  assert.equal(report.liveReady, false);
  assert.equal(report.counts.failed, 0);
  assert.equal(report.counts.unverified, 2);
  assert.equal(report.checks.find((check) => check.id === "runner-keypair").status, "passed");
  assert.equal(report.checks.find((check) => check.id === "codex-login").status, "passed");
  assert.equal(launchRequests.length, 1);
  assert.equal(launchRequests[0].source, process.env);
  assert.deepEqual(launchRequests[0].forbiddenRoots, [paths.home, paths.repo]);
  assert.equal(probe.invocations.length, 2);
  for (const invocation of probe.invocations) {
    assert.equal(path.isAbsolute(invocation.command), true);
    assert.match(path.basename(invocation.command), /^codex(?:\.[A-Za-z0-9]+)?$/u);
    assert.equal(invocation.options.env.GH_TOKEN, undefined);
    assert.equal(invocation.options.env.HOME, remoteSetupInternals.layout(paths, "demo-case").runnerCodexHome);
  }
  const serialized = JSON.stringify(report);
  assert.doesNotMatch(serialized, /PROBE_SECRET_CANARY/u);
  assert.doesNotMatch(serialized, /AMBIENT_GITHUB_SECRET_CANARY/u);
});

test("remote init fails closed on unsafe inputs and never replaces an existing case", (t) => {
  const { working, paths } = fixture(t);
  assert.throws(
    () => initializeRemoteCase(input(working, { origin: "http://gate.example.test" }), { paths }),
    /exact HTTPS origin/u
  );
  assert.throws(
    () => initializeRemoteCase(input(working, { subject: "operator\nsubject" }), { paths }),
    /without control characters/u
  );
  assert.throws(
    () => initializeRemoteCase(input(working, { coordinatorConfigRoot: "relative/coordinator" }), { paths }),
    /absolute normalized non-root path/u
  );
  assert.throws(
    () => initializeRemoteCase(input(working, { coordinatorStateRoot: "/etc/gate-remote/demo-case/state" }), { paths }),
    /must not overlap/u
  );
  assert.equal(fs.existsSync(path.join(paths.home, "remote", "demo-case")), false);

  initializeRemoteCase(input(working), { paths });
  const locations = remoteSetupInternals.layout(paths, "demo-case");
  const before = crypto.createHash("sha256").update(fs.readFileSync(locations.runnerPrivateKey)).digest("hex");
  assert.throws(
    () => initializeRemoteCase(input(working), { paths }),
    /remote case already exists: demo-case; run \.\/bin\/gate\.mjs remote doctor demo-case/u
  );
  const after = crypto.createHash("sha256").update(fs.readFileSync(locations.runnerPrivateKey)).digest("hex");
  assert.equal(after, before);
});

test("remote init rejects a case working directory that contains GATE_HOME", (t) => {
  const fixtureRoot = fixture(t);
  assert.throws(
    () => initializeRemoteCase(input(fixtureRoot.root), { paths: fixtureRoot.paths }),
    /must not overlap GATE_HOME or private remote runner state/u
  );
  const privateWorking = path.join(fixtureRoot.home, "case-work");
  fs.mkdirSync(privateWorking, { mode: 0o700 });
  assert.throws(
    () => initializeRemoteCase(input(privateWorking), { paths: fixtureRoot.paths }),
    /must not overlap GATE_HOME or private remote runner state/u
  );
  assert.equal(fs.existsSync(path.join(fixtureRoot.home, "remote", "demo-case")), false);
});

test("a losing concurrent remote init removes only its own staging tree", (t) => {
  const { working, paths } = fixture(t);
  const locations = remoteSetupInternals.layout(paths, "demo-case");
  const winner = path.join(locations.root, "winner-canary");
  assert.throws(() => initializeRemoteCase(input(working), {
    paths,
    rename: (_source, destination) => {
      fs.mkdirSync(destination, { mode: 0o700 });
      fs.writeFileSync(winner, "winner remains\n", { mode: 0o600 });
      throw Object.assign(new Error("concurrent destination won"), { code: "EEXIST" });
    }
  }), /remote case already exists: demo-case; run \.\/bin\/gate\.mjs remote doctor demo-case/u);
  assert.equal(fs.readFileSync(winner, "utf8"), "winner remains\n");
  assert.deepEqual(
    fs.readdirSync(path.dirname(locations.root)).filter((entry) => entry.startsWith(".init-demo-case-")),
    []
  );
});

test("remote doctor detects drift without repairing permissions or revealing changed content", (t) => {
  if (process.platform === "win32") return t.skip("POSIX permission drift is asserted on the WSL/Linux control plane");
  const { working, paths } = fixture(t);
  initializeRemoteCase(input(working), { paths });
  const locations = remoteSetupInternals.layout(paths, "demo-case");
  fs.appendFileSync(locations.runnerEnvironment, "# PRIVATE_ENV_CANARY\n");
  fs.chmodSync(locations.runnerEnvironment, 0o644);

  const report = inspectRemoteCase("demo-case", {
    paths,
    commandRunner: fakeCodexProbe().run,
    prepareCodexLaunch: (_source, codexHome) => fakeCodexLaunch(codexHome),
    nodeVersion: "24.0.0",
    sqliteAvailable: true
  });
  assert.equal(report.ok, false);
  assert.equal(report.checks.find((check) => check.id === "private-files").status, "failed");
  assert.equal(report.checks.find((check) => check.id === "runner-config").status, "failed");
  assert.equal(fs.statSync(locations.runnerEnvironment).mode & 0o777, 0o644);
  assert.doesNotMatch(JSON.stringify(report), /PRIVATE_ENV_CANARY/u);
});

test("remote doctor rejects a manifest working directory inside private runner state", (t) => {
  const { working, paths } = fixture(t);
  initializeRemoteCase(input(working), { paths });
  const locations = remoteSetupInternals.layout(paths, "demo-case");
  const manifest = JSON.parse(fs.readFileSync(locations.manifest, "utf8"));
  manifest.repository = locations.runner;
  fs.writeFileSync(locations.manifest, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });

  const report = inspectRemoteCase("demo-case", {
    paths,
    commandRunner: fakeCodexProbe().run,
    prepareCodexLaunch: (_source, codexHome) => fakeCodexLaunch(codexHome),
    nodeVersion: "24.0.0",
    sqliteAvailable: true
  });
  const workingDirectory = report.checks.find((check) => check.id === "case-working-directory");
  assert.equal(workingDirectory.status, "failed");
  assert.match(workingDirectory.problem, /must not overlap GATE_HOME or private remote runner state/u);
});

test("remote doctor reports a mismatched key and pinned Codex version as local failures", (t) => {
  const { working, paths } = fixture(t);
  initializeRemoteCase(input(working), { paths });
  const locations = remoteSetupInternals.layout(paths, "demo-case");
  const replacement = crypto.generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" });
  fs.writeFileSync(locations.coordinatorPublicKey, replacement, { mode: 0o600 });
  const report = inspectRemoteCase("demo-case", {
    paths,
    commandRunner: () => ({ status: 0, stdout: "codex-cli 999.0.0\nSECRET_VERSION_CANARY", stderr: "" }),
    prepareCodexLaunch: (_source, codexHome) => fakeCodexLaunch(codexHome),
    nodeVersion: "22.19.0",
    sqliteAvailable: false
  });
  for (const id of ["runner-keypair", "node-runtime", "node-sqlite", "codex-version"]) {
    assert.equal(report.checks.find((check) => check.id === id).status, "failed", id);
  }
  assert.equal(report.ok, false);
  assert.doesNotMatch(JSON.stringify(report), /SECRET_VERSION_CANARY/u);
});

const invalidIdentityHeaders = [
  "x", "cookie", "authorization", "host", "origin", "sec-fetch-site",
  "1x-private", "X-Private", "x".repeat(64)
];

test("remote init rejects headers forbidden by the coordinator before creating a case", (t) => {
  const { working, paths } = fixture(t);
  for (const identityHeader of invalidIdentityHeaders) {
    assert.throws(() => initializeRemoteCase(input(working, { identityHeader }), { paths }),
      /identityAssertionHeader must be a lowercase private request header/u);
    assert.equal(fs.existsSync(remoteSetupInternals.layout(paths, "demo-case").root), false);
  }
});

test("remote doctor applies the coordinator header contract to persisted configuration", (t) => {
  const { working, paths } = fixture(t);
  initializeRemoteCase(input(working), { paths });
  const locations = remoteSetupInternals.layout(paths, "demo-case");
  const config = JSON.parse(fs.readFileSync(locations.coordinatorConfig, "utf8"));
  for (const identityAssertionHeader of [...invalidIdentityHeaders, "xy", "x".repeat(63)]) {
    fs.writeFileSync(locations.coordinatorConfig, JSON.stringify({ ...config, identityAssertionHeader }));
    const report = inspectRemoteCase("demo-case", {
      paths,
      commandRunner: fakeCodexProbe().run,
      prepareCodexLaunch: (_source, codexHome) => fakeCodexLaunch(codexHome),
      nodeVersion: "24.0.0",
      sqliteAvailable: true
    });
    const check = report.checks.find((entry) => entry.id === "coordinator-config");
    assert.equal(check.status, invalidIdentityHeaders.includes(identityAssertionHeader) ? "failed" : "passed",
      identityAssertionHeader);
  }
});
