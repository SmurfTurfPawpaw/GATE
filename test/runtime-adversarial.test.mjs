import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  approveEngagement,
  attachPlan,
  createEngagement,
  recordTechnicalReview
} from "../src/lib/engagements.mjs";
import { createExecutionManifest, executionCapability } from "../src/lib/executions.mjs";
import { runtimePaths } from "../src/lib/paths.mjs";
import { catalogEntrySha256, installManagedTool } from "../src/lib/tool-runtimes.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const gate = path.join(repo, "bin", "gate.mjs");

function fixture(t, prefix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const home = path.join(root, "home");
  const paths = runtimePaths({ home, repo });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, home, paths };
}

function invoke(args, home) {
  return spawnSync(process.execPath, [gate, ...args], {
    cwd: repo,
    env: { ...process.env, GATE_HOME: home },
    encoding: "utf8",
    timeout: 10_000
  });
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function noNetworkInstallFixture(t, port) {
  const { root, home } = fixture(t, "gate-runtime-zero-egress-");
  const fixtureRepo = path.join(root, "repo");
  for (const directory of ["schemas", "catalog", "locks"]) {
    fs.mkdirSync(path.join(fixtureRepo, directory), { recursive: true });
  }
  for (const name of ["tool-runtime-lock.schema.json", "tool-install-receipt.schema.json", "event.schema.json"]) {
    fs.copyFileSync(path.join(repo, "schemas", name), path.join(fixtureRepo, "schemas", name));
  }

  const tool = {
    id: "netprobe",
    name: "Network isolation fixture",
    category: "osint",
    riskClass: "P1",
    approval: "declared-source",
    license: "MIT",
    openSource: true,
    upstream: "https://github.com/example/netprobe",
    command: "netprobe",
    installLanes: ["pinned-release"],
    supportedHosts: ["linux", "wsl2"],
    privileges: ["user"],
    notes: "A local fixture that fails if its smoke process can reach the host loopback listener."
  };
  const catalog = {
    $schema: "../schemas/tool-catalog.schema.json",
    apiVersion: "gate.dev/catalog/v1",
    kind: "SecurityToolCatalog",
    policy: {},
    tools: [tool]
  };
  fs.writeFileSync(path.join(fixtureRepo, "catalog", "security-tools.json"), `${JSON.stringify(catalog, null, 2)}\n`);

  const executableBytes = Buffer.from(
    `#!/usr/bin/python3\nimport socket, sys\ns = socket.socket()\ns.settimeout(0.5)\ntry:\n    s.connect(("127.0.0.1", ${port}))\nexcept OSError:\n    print("network denied fixture")\n    sys.exit(0)\nprint("host network was reachable")\nsys.exit(9)\n`
  );
  const content = path.join(root, "content");
  fs.mkdirSync(content);
  fs.writeFileSync(path.join(content, "netprobe"), executableBytes, { mode: 0o700 });
  const archiveName = "netprobe_1.2.3_linux_amd64.tar.gz";
  const archive = path.join(root, archiveName);
  const packed = spawnSync("/usr/bin/tar", ["-czf", archive, "netprobe"], {
    cwd: content,
    encoding: "utf8",
    shell: false
  });
  assert.equal(packed.status, 0, packed.stderr);
  const archiveBytes = fs.readFileSync(archive);
  const entry = {
    id: tool.id,
    toolId: tool.id,
    catalogEntrySha256: catalogEntrySha256(tool),
    version: "1.2.3",
    source: {
      repository: tool.upstream,
      commit: "1".repeat(40),
      tag: "v1.2.3"
    },
    releaseEvidence: {
      provider: "github",
      releaseId: 123,
      releaseApiUrl: "https://api.github.com/repos/example/netprobe/releases/123",
      immutableObserved: false,
      sourceCommitVerification: "unverified",
      checksumManifest: {
        assetId: 124,
        assetApiUrl: "https://api.github.com/repos/example/netprobe/releases/assets/124",
        url: "https://github.com/example/netprobe/releases/download/v1.2.3/checksums.txt",
        size: 64,
        sha256: "2".repeat(64)
      }
    },
    provider: "verified-release",
    executable: { name: tool.command, relativePath: "bin/netprobe" },
    artifacts: [{
      platform: process.arch === "arm64" ? "linux-arm64" : "linux-x64",
      assetId: 125,
      assetApiUrl: "https://api.github.com/repos/example/netprobe/releases/assets/125",
      url: `https://github.com/example/netprobe/releases/download/v1.2.3/${archiveName}`,
      size: archiveBytes.length,
      sha256: sha256(archiveBytes),
      archiveType: "tar.gz",
      entries: ["netprobe"],
      executablePath: "netprobe",
      executableSha256: sha256(executableBytes)
    }],
    smoke: {
      argv: ["--version"],
      expectedOutputContains: "network denied fixture",
      timeoutMs: 3000,
      maxOutputBytes: 4096,
      maxProcesses: 32,
      network: "none",
      sandbox: "bubblewrap-prlimit-v1"
    },
    effects: {
      networkDuringInstall: true,
      hostWrites: false,
      adminRequired: false,
      services: false,
      devices: false
    }
  };
  fs.writeFileSync(path.join(fixtureRepo, "locks", "tool-runtimes.lock.json"), `${JSON.stringify({
    $schema: "../schemas/tool-runtime-lock.schema.json",
    apiVersion: "gate.dev/tool-runtime-lock/v1",
    kind: "ToolRuntimeLock",
    updatePolicy: "reviewed-pull-request",
    runtimes: [entry]
  }, null, 2)}\n`);

  return {
    paths: runtimePaths({ home, repo: fixtureRepo }),
    downloadArtifact: async (_artifact, destination) => fs.copyFileSync(archive, destination, fs.constants.COPYFILE_EXCL)
  };
}

function approveFixtureEngagement(paths, root) {
  const id = "runtime-digest-swap";
  const target = "swap.example.test";
  const action = "scan";
  const toolId = "fixture-swap";
  const planFile = path.join(root, "plan.md");
  fs.writeFileSync(planFile, "# Plan\nExercise the managed executable digest boundary.\n");
  createEngagement({
    id,
    targets: [target],
    actions: [action],
    tools: [toolId],
    environment: "host",
    maxMinutes: 5,
    maxRequests: 5,
    maxParallel: 1,
    maxRate: 1,
    maxTokens: 5_000,
    allowedDestinations: ["gate-home"]
  }, { paths });
  const planned = attachPlan(id, planFile, { paths });
  recordTechnicalReview(id, {
    run: `no-mistakes/${id}`,
    headSha: "a".repeat(40),
    status: "passed"
  }, { paths });
  approveEngagement(id, { sha256: planned.plan.sha256, confirm: `APPROVE ${id}` }, { paths });
  return { id, target, action, toolId };
}

test("managed tool CLI rejects ambiguous selectors and passthrough arguments before mutation", (t) => {
  const { home } = fixture(t, "gate-runtime-cli-boundary-");
  const attempts = [
    {
      args: ["tool", "install", "ffuf", "--profile", "core", "--json"],
      message: /requires exactly one tool id or --profile ID/
    },
    {
      args: ["tool", "verify", "--profile", "core", "--profile", "core", "--json"],
      message: /tool option must not be repeated: --profile/
    },
    {
      args: ["tool", "verify", "--profile", "core", "--", "unexpected"],
      message: /tool commands do not accept -- passthrough arguments/
    }
  ];

  for (const attempt of attempts) {
    const result = invoke(attempt.args, home);
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, attempt.message);
  }
  assert.equal(fs.existsSync(path.join(home, "tool-runtimes")), false);
});

test("profile verification reports every absent runtime as structured partial failure", (t) => {
  const { home } = fixture(t, "gate-runtime-cli-partial-");
  const expected = JSON.parse(fs.readFileSync(path.join(repo, "config", "profiles", "core.json"), "utf8"));
  const result = invoke(["tool", "verify", "--profile", "core", "--json"], home);

  assert.equal(result.status, 2, result.stderr);
  const body = JSON.parse(result.stdout);
  assert.equal(body.ok, false);
  assert.equal(body.complete, false);
  assert.equal(body.selector.type, "profile");
  assert.equal(body.selector.id, "core");
  assert.equal(body.counts.selected, expected.toolIds.length);
  assert.equal(body.counts.succeeded, 0);
  assert.equal(body.counts.unresolved, expected.toolIds.length);
  assert.equal(body.targetAuthority, "engagement-receipt-required");
  assert.equal(body.installationGrantsAuthority, false);
  assert.deepEqual(body.results.map((item) => item.id), expected.toolIds);
  assert.ok(body.results.every((item) => (
    item.ok === false && item.state === "absent" && item.installed === false &&
    item.verified === false && item.executable === null &&
    item.installationGrantsAuthority === false
  )));
});

test("the default smoke supervisor cannot reach a host loopback listener", async (t) => {
  if (process.platform !== "linux") return t.skip("Bubblewrap smoke supervision is Linux-only");
  if (!new Set(["x64", "arm64"]).has(process.arch)) return t.skip(`unsupported fixture architecture: ${process.arch}`);
  if (!fs.existsSync("/usr/bin/bwrap") || !fs.existsSync("/usr/bin/prlimit") || !fs.existsSync("/usr/bin/python3")) {
    return t.skip("the protected Bubblewrap, prlimit, and Python fixture runtime are unavailable");
  }

  let hostConnections = 0;
  const server = net.createServer((socket) => {
    hostConnections += 1;
    socket.destroy();
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const address = server.address();
  assert.equal(typeof address, "object");
  const fixture = noNetworkInstallFixture(t, address.port);

  let installed;
  try {
    installed = await installManagedTool("netprobe", {
      paths: fixture.paths,
      downloadArtifact: fixture.downloadArtifact
    });
  } catch (error) {
    if (/Bubblewrap|namespace|Operation not permitted|Permission denied/iu.test(String(error.message || error))) {
      return t.skip(`zero-egress namespace unavailable: ${error.message}`);
    }
    throw error;
  }
  assert.equal(installed.ok, true);
  assert.equal(installed.verified, true);
  assert.equal(hostConnections, 0);
  assert.equal(fs.readdirSync(fixture.paths.engagements).length, 0);
});

test("manifest creation rejects an executable swapped after managed verification", (t) => {
  const capability = executionCapability();
  if (!capability.laneAvailable) return t.skip(`supervised execution unavailable: ${capability.reason}`);
  if (!new Set(["x64", "arm64"]).has(process.arch)) return t.skip(`unsupported fixture architecture: ${process.arch}`);

  const { root, paths } = fixture(t, "gate-runtime-digest-swap-");
  const scope = approveFixtureEngagement(paths, root);
  const executable = path.join(root, "fixture-swap");
  const reviewedBytes = Buffer.from("#!/bin/sh\nexit 0\n");
  fs.writeFileSync(executable, reviewedBytes, { mode: 0o700 });
  const provenance = {
    provider: "verified-release",
    version: "1.2.3",
    platform: process.arch === "arm64" ? "linux-arm64" : "linux-x64",
    lockEntrySha256: "1".repeat(64),
    catalogEntrySha256: "2".repeat(64),
    artifactSha256: "3".repeat(64),
    executableSha256: crypto.createHash("sha256").update(reviewedBytes).digest("hex")
  };

  const resolveTool = (id) => {
    const replacement = `${executable}.replacement`;
    fs.writeFileSync(replacement, "#!/bin/sh\nexit 1\n", { mode: 0o700 });
    fs.renameSync(replacement, executable);
    return {
      id,
      installed: true,
      executable,
      compatible: true,
      genericLaneEligible: true,
      executionAvailable: true,
      host: process.env.WSL_DISTRO_NAME ? "wsl2" : "linux",
      riskClass: "A1",
      managedRuntimeVerified: true,
      managedRuntime: {
        verified: true,
        state: "verified",
        executable,
        version: provenance.version,
        provenance
      }
    };
  };

  assert.throws(
    () => createExecutionManifest(scope.id, {
      target: scope.target,
      action: scope.action,
      toolId: scope.toolId,
      argv: ["{{GATE_TARGET}}"],
      maxMinutes: 1,
      estimatedRequests: 1,
      maxParallel: 1,
      maxRatePerSecond: 1,
      maxTokens: 1_000
    }, { paths, resolveTool }),
    /managed executable bytes do not match their reviewed provenance/
  );
  assert.equal(fs.readdirSync(paths.executionManifests).length, 0);
});
