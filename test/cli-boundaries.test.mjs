import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const gate = path.join(repo, "bin", "gate.mjs");

function invoke(args, home) {
  return spawnSync(process.execPath, [gate, ...args], {
    cwd: repo,
    env: { ...process.env, GATE_HOME: home },
    encoding: "utf8",
    timeout: 10_000
  });
}

test("raw command surfaces fail closed before spawning passthrough commands", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-cli-boundary-"));
  const home = path.join(root, "home");
  const marker = path.join(root, "spawned");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const payload = `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'bad')`;

  const attempts = [
    {
      args: ["run", "--label", "unsafe", "--", process.execPath, "-e", payload],
      message: /raw command execution is disabled/
    },
    {
      args: ["upstream", "exec", "gnhf", "--", "--help"],
      message: /raw upstream execution is disabled/
    },
    {
      args: [
        "engagement", "exec", "demo", "--manifest", "missing-manifest",
        "--confirm", `EXECUTE missing-manifest ${"0".repeat(64)} UNMETERED`,
        "--", process.execPath, "-e", payload
      ],
      message: /engagement exec does not accept command arguments/
    },
    {
      args: [
        "engagement", "manifest", "demo", "--target", "example.test", "--action", "scan",
        "--tool", "nmap", "--requests", "1", "--parallel", "1", "--rate", "1",
        "--minutes", "1", "--tokens", "1000", "--", "{{GATE_TARGET}}", "-e", payload
      ],
      message: /engagement does not exist/
    }
  ];

  for (const attempt of attempts) {
    const result = invoke(attempt.args, home);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, attempt.message);
    assert.equal(fs.existsSync(marker), false);
  }
});

test("engagement creation rejects caller-supplied authorization evidence references", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-cli-evidence-boundary-"));
  const home = path.join(root, "home");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const result = invoke([
    "engagement", "new", "cli-client",
    "--basis", "client-written-authorization",
    "--evidence-ref", "private://authorizations/cli-client.evidence",
    "--targets", "app.example.test",
    "--actions", "scan"
  ], home);

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unsupported option: --evidence-ref/);
  assert.equal(fs.existsSync(path.join(home, "engagements", "cli-client.json")), false);
});

test("offline analysis CLI rejects passthrough and ambiguous options before any run", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-cli-analysis-boundary-"));
  const home = path.join(root, "home");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const attempts = [
    {
      args: ["analysis", "capability", "--"],
      message: /analysis commands do not accept -- passthrough arguments/
    },
    {
      args: ["analysis", "status", "--", "unexpected"],
      message: /analysis commands do not accept -- passthrough arguments/
    },
    {
      args: ["analysis", "manifest", "--project=alpha", "--project", "beta", "--path", "/tmp/file.exe"],
      message: /analysis option must not be repeated: --project/
    },
    {
      args: ["analysis", "manifest", "--project", "alpha", "--path=/tmp/a,  b.exe", "--path", "/tmp/c.exe"],
      message: /analysis option must not be repeated: --path/
    },
    {
      args: ["analysis", "run", "--project", "alpha", "--manifest", `amf_${"a".repeat(32)}`, "--confirm", "first", "--confirm=second"],
      message: /analysis option must not be repeated: --confirm/
    },
    {
      args: ["analysis", "purge", "--project", "alpha", "--project=beta", "--manifest", `amf_${"a".repeat(32)}`, "--confirm", "x"],
      message: /analysis option must not be repeated: --project/
    },
    {
      args: ["analysis", "purge", "--project", "alpha", "--manifest", `amf_${"a".repeat(32)}`, "--confirm", "x", "--contact-target"],
      message: /unsupported option: --contact-target/
    },
    {
      args: ["analysis", "purge", "--json"],
      message: /--project is required/
    },
    {
      args: ["analysis", "status", "--json=true"],
      message: /--json does not accept a value/
    },
    {
      args: ["analysis", "manifest", "--project", "alpha", "--path", "/tmp/file.exe", "--minutes", "--json"],
      message: /--minutes needs a value/
    },
    {
      args: ["analysis", "manifest", "--project", "alpha", "--path", "/tmp/file.exe", "--arguments", "--contact-target"],
      message: /unsupported option: --arguments/
    }
  ];

  for (const attempt of attempts) {
    const result = invoke(attempt.args, home);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, attempt.message);
  }
  assert.equal(fs.existsSync(path.join(home, "offline-analysis", "claims")), false);
});

test("offline analysis status commands expose metadata without requiring an installed lane", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-cli-analysis-status-"));
  const home = path.join(root, "home");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const statusResult = invoke(["analysis", "status", "--json"], home);
  assert.equal(statusResult.status, 0, statusResult.stderr);
  const status = JSON.parse(statusResult.stdout);
  assert.equal(status.capability.configured, true);
  assert.equal(status.capability.mode, "bubblewrap-offline");
  assert.equal(typeof status.capability.laneAvailable, "boolean");
  assert.deepEqual(status.recent, []);
  assert.equal(status.counts.running, 0);
  assert.equal(status.retention.quotaBytes, 2 * 1024 * 1024 * 1024);
  assert.equal(status.retention.quotaArtifacts, 64);
  assert.equal(status.retention.retainedBytes, 0);
  assert.equal(status.retention.availableArtifacts, 64);
  assert.equal(status.retention.pendingManifests, 0);
  assert.equal(status.retention.expiredManifests, 0);

  const overallResult = invoke(["status", "--json"], home);
  assert.equal(overallResult.status, 0, overallResult.stderr);
  const overall = JSON.parse(overallResult.stdout);
  assert.deepEqual(overall.offlineAnalysis.counts, status.counts);
  assert.equal(overall.offlineAnalysis.capability.mode, "bubblewrap-offline");
});
