import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { cliInternals } from "../src/cli.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const gate = path.join(repo, "bin", "gate.mjs");

function invoke(args, home, extraEnvironment = {}) {
  return spawnSync(process.execPath, [gate, ...args], {
    cwd: repo,
    env: { ...process.env, GATE_HOME: home, GATE_CASE: "", ...extraEnvironment },
    encoding: "utf8",
    timeout: 10_000
  });
}

test("case routing keeps closeout paths stale-safe and new admission strict", () => {
  const mode = (command, positional) => cliInternals.caseSelectionMode(command, { positional, flags: {} });
  const required = (command, positional) => cliInternals.caseSelectorRequired(command, { positional, flags: {} });
  for (const positional of [
    ["status", "case-workflow"],
    ["stop", "case-workflow"],
    ["phase", "finish", "case-workflow"],
    ["test", "review", "case-workflow"],
    ["evidence", "add", "case-workflow"],
    ["coverage", "set", "case-workflow"],
    ["ledger", "cleanup", "case-workflow"],
    ["ledger", "verify", "case-workflow"],
    ["ledger", "hold", "case-workflow"],
    ["execution", "cancel", "case-workflow"],
    ["join", "case-workflow"],
    ["report", "case-workflow"],
    ["close", "case-workflow"]
  ]) {
    assert.equal(mode("workflow", positional), "stale-safe", positional.join(" "));
  }
  for (const positional of [
    ["new", "case-workflow"],
    ["phase", "preflight", "case-workflow"],
    ["phase", "start", "case-workflow"],
    ["test", "plan", "case-workflow"],
    ["ledger", "preflight", "case-workflow"],
    ["ledger", "open", "case-workflow"]
  ]) {
    assert.equal(mode("workflow", positional), "strict", positional.join(" "));
  }
  assert.equal(mode("analysis", ["capability"]), "global");
  assert.equal(mode("analysis", ["status"]), "stale-safe");
  assert.equal(required("engagement", ["status", "engagement-id"]), true);
  assert.equal(required("workflow", ["status", "workflow-id"]), true);
  assert.equal(required("bounty", ["profile", "compile", "profile-id"]), true);
  for (const action of ["manifest", "run", "purge", "status"]) {
    assert.equal(required("analysis", [action]), true);
  }
  assert.equal(required("analysis", ["capability"]), false);
  assert.equal(required("status", []), false);
  assert.equal(required("event", ["operator.note"]), false);
  assert.equal(required("learn", []), false);
});

test("shared commands reject explicit and ambient case selectors before creating state", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-cli-global-case-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const commands = [
    ["bootstrap", "--json"],
    ["validate", "--json"],
    ["doctor", "--json"],
    ["up"],
    ["case", "list", "--json"],
    ["project", "list", "--json"],
    ["workspace", "status", "--json"],
    ["upstream", "list", "--json"],
    ["publication", "check", "--json"],
    ["remote", "doctor", "selector-canary", "--json"],
    ["analysis", "capability", "--json"],
    ...["create", "resume", "status", "show", "verify"].map((action) => [
      "bounty", "profile", action, "selector-canary", "--json"
    ]),
    ...["list", "show", "plan", "prefetch", "install", "verify", "remove"].map((action) => [
      "tool", action, "selector-canary", "--json"
    ])
  ];

  commands.forEach((command, index) => {
    const home = path.join(root, `explicit-${index}`);
    const result = invoke(["--case", "phantom-case", ...command], home);
    assert.notEqual(result.status, 0, command.join(" "));
    assert.match(result.stderr, /uses shared state and does not accept --case, GATE_CASE, or --unassigned/u);
    assert.equal(fs.existsSync(home), false, command.join(" "));
  });

  const ambientHome = path.join(root, "ambient");
  const ambient = invoke(["project", "list", "--json"], ambientHome, { GATE_CASE: "phantom-case" });
  assert.notEqual(ambient.status, 0);
  assert.match(ambient.stderr, /uses shared state and does not accept --case, GATE_CASE, or --unassigned/u);
  assert.equal(fs.existsSync(ambientHome), false);

  const unassignedHome = path.join(root, "unassigned");
  const unassigned = invoke(["--unassigned", "bootstrap", "--json"], unassignedHome);
  assert.notEqual(unassigned.status, 0);
  assert.match(unassigned.stderr, /uses shared state and does not accept --case, GATE_CASE, or --unassigned/u);
  assert.equal(fs.existsSync(unassignedHome), false);

  const conflictingHome = path.join(root, "conflicting");
  const conflicting = invoke(
    ["--unassigned", "analysis", "status", "--json"],
    conflictingHome,
    { GATE_CASE: "phantom-case" }
  );
  assert.notEqual(conflicting.status, 0);
  assert.match(conflicting.stderr, /--unassigned and GATE_CASE are mutually exclusive/u);
  assert.equal(fs.existsSync(conflictingHome), false);

  const doubleSelectorHome = path.join(root, "double-selector");
  const doubleSelector = invoke([
    "--case", "phantom-case", "--unassigned", "analysis", "status", "--json"
  ], doubleSelectorHome);
  assert.notEqual(doubleSelector.status, 0);
  assert.match(doubleSelector.stderr, /--unassigned and --case are mutually exclusive/u);
  assert.equal(fs.existsSync(doubleSelectorHome), false);
});

test("case-owned commands require an explicit case or explicit unassigned lane before mutation", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-cli-required-case-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const attempts = [
    ["engagement", "new", "selector-canary", "--targets", "app.example.test", "--actions", "scan", "--tools", "nmap"],
    ["workflow", "new", "selector-canary"],
    ["bounty", "profile", "compile", "selector-canary"],
    ["analysis", "manifest", "--project", "selector-canary", "--path", "/tmp/input"],
    ["analysis", "run", "--project", "selector-canary", "--manifest", `amf_${"a".repeat(32)}`, "--confirm", "x"],
    ["analysis", "purge", "--project", "selector-canary", "--manifest", `amf_${"a".repeat(32)}`, "--confirm", "x"],
    ["analysis", "status", "--json"]
  ];

  attempts.forEach((args, index) => {
    const home = path.join(root, String(index));
    const result = invoke(args, home);
    assert.notEqual(result.status, 0, args.join(" "));
    assert.match(result.stderr, /requires --case ID \(or GATE_CASE\) or explicit --unassigned/u);
    assert.equal(fs.existsSync(home), false, args.join(" "));
  });

  const compatibilityHome = path.join(root, "compatibility");
  const compatibility = invoke(["--unassigned", "analysis", "status", "--json"], compatibilityHome);
  assert.equal(compatibility.status, 0, compatibility.stderr);
  assert.equal(JSON.parse(compatibility.stdout).counts.running, 0);
});

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
        "--unassigned", "engagement", "exec", "demo", "--manifest", "missing-manifest",
        "--confirm", `EXECUTE missing-manifest ${"0".repeat(64)} UNMETERED`,
        "--", process.execPath, "-e", payload
      ],
      message: /engagement exec does not accept command arguments/
    },
    {
      args: [
        "--unassigned", "engagement", "adapter-manifest", "demo", "--adapter", "dnsx-domain-observe",
        "--workflow", "demo-workflow", "--phase-attempt", `wpa_${"a".repeat(32)}`,
        "--target", "fixture.example", "--minutes", "1", "--requests", "1",
        "--parallel", "1", "--rate", "1", "--tokens", "1000", "--timeout-seconds", "5",
        "--record-type", "A", "--resolver", "127.0.0.1:5353", "--", "-unsafe"
      ],
      message: /adapter-manifest does not accept raw command arguments/
    },
    {
      args: [
        "--unassigned", "engagement", "manifest", "demo", "--target", "example.test", "--action", "scan",
        "--workflow", "demo-workflow", "--phase-attempt", `wpa_${"a".repeat(32)}`,
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

test("managed adapter manifest dispatch is reachable at the engagement command level", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-cli-adapter-dispatch-"));
  const home = path.join(root, "home");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const result = invoke([
    "--unassigned", "engagement", "adapter-manifest", "demo", "--adapter", "unsupported-adapter"
  ], home);

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unknown managed target-contact adapter: unsupported-adapter/u);
  assert.doesNotMatch(result.stderr, /id is not defined|unknown engagement action/u);
});

test("engagement creation rejects caller-supplied authorization evidence references", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-cli-evidence-boundary-"));
  const home = path.join(root, "home");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const result = invoke([
    "--unassigned", "engagement", "new", "cli-client",
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
      args: ["--unassigned", "analysis", "status", "--", "unexpected"],
      message: /analysis commands do not accept -- passthrough arguments/
    },
    {
      args: ["--unassigned", "analysis", "manifest", "--project=alpha", "--project", "beta", "--path", "/tmp/file.exe"],
      message: /analysis option must not be repeated: --project/
    },
    {
      args: ["--unassigned", "analysis", "manifest", "--project", "alpha", "--path=/tmp/a,  b.exe", "--path", "/tmp/c.exe"],
      message: /analysis option must not be repeated: --path/
    },
    {
      args: ["--unassigned", "analysis", "run", "--project", "alpha", "--manifest", `amf_${"a".repeat(32)}`, "--confirm", "first", "--confirm=second"],
      message: /analysis option must not be repeated: --confirm/
    },
    {
      args: ["--unassigned", "analysis", "purge", "--project", "alpha", "--project=beta", "--manifest", `amf_${"a".repeat(32)}`, "--confirm", "x"],
      message: /analysis option must not be repeated: --project/
    },
    {
      args: ["--unassigned", "analysis", "purge", "--project", "alpha", "--manifest", `amf_${"a".repeat(32)}`, "--confirm", "x", "--contact-target"],
      message: /unsupported option: --contact-target/
    },
    {
      args: ["--unassigned", "analysis", "purge", "--json"],
      message: /--project is required/
    },
    {
      args: ["--unassigned", "analysis", "status", "--json=true"],
      message: /--json does not accept a value/
    },
    {
      args: ["--unassigned", "analysis", "manifest", "--project", "alpha", "--path", "/tmp/file.exe", "--minutes", "--json"],
      message: /--minutes needs a value/
    },
    {
      args: ["--unassigned", "analysis", "manifest", "--project", "alpha", "--path", "/tmp/file.exe", "--arguments", "--contact-target"],
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

  const statusResult = invoke(["--unassigned", "analysis", "status", "--json"], home);
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

test("workflow CLI creates a journaled instance and rejects ambiguous command surfaces", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-cli-workflow-boundary-"));
  const home = path.join(root, "home");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const instanceId = "cli-map-first";
  const requestId = `wreq_${"a".repeat(32)}`;
  const createdResult = invoke([
    "--unassigned", "workflow", "new", instanceId, "--request", requestId, "--json"
  ], home);
  assert.equal(createdResult.status, 0, createdResult.stderr);
  const created = JSON.parse(createdResult.stdout);
  assert.equal(created.ok, true);
  assert.equal(created.instanceId, instanceId);
  assert.equal(created.status, "open");
  assert.equal(created.journal.sequence, 0);
  assert.equal(created.contract.coverageDomainCount, 18);

  const directory = path.join(home, "workflows", instanceId);
  assert.equal(fs.statSync(directory).mode & 0o777, 0o700);
  assert.equal(fs.statSync(path.join(directory, "journal.jsonl")).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.join(directory, "instance.json")).mode & 0o777, 0o600);

  const statusResult = invoke(["--unassigned", "workflow", "status", instanceId, "--json"], home);
  assert.equal(statusResult.status, 0, statusResult.stderr);
  const status = JSON.parse(statusResult.stdout);
  assert.equal(status.ok, true);
  assert.equal(status.instanceId, instanceId);
  assert.equal(status.status, "open");

  const attempts = [
    {
      args: ["--unassigned", "workflow", "new", "duplicate-request", "--request", requestId, "--request", `wreq_${"b".repeat(32)}`],
      message: /workflow option must not be repeated: --request/
    },
    {
      args: ["--unassigned", "workflow", "status", instanceId, "--", "unexpected"],
      message: /workflow commands do not accept passthrough arguments/
    },
    {
      args: ["--unassigned", "workflow", "status", instanceId, "--json=true"],
      message: /--json does not accept a value/
    },
    {
      args: ["--unassigned", "workflow", "status", instanceId, "--contact-target"],
      message: /unsupported option: --contact-target/
    }
  ];
  for (const attempt of attempts) {
    const result = invoke(attempt.args, home);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, attempt.message);
  }
  assert.equal(fs.existsSync(path.join(home, "workflows", "duplicate-request")), false);
});

test("blocked workflow status uses the operational-block exit code", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-cli-workflow-status-"));
  const home = path.join(root, "home");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const instanceId = "cli-blocked-status";
  const created = invoke(["--unassigned", "workflow", "new", instanceId, "--json"], home);
  assert.equal(created.status, 0, created.stderr);

  const journal = path.join(home, "workflows", instanceId, "journal.jsonl");
  const bytes = fs.readFileSync(journal);
  fs.writeFileSync(journal, bytes.subarray(0, bytes.length - 1), { mode: 0o600 });

  const blockedResult = invoke(["--unassigned", "workflow", "status", instanceId, "--json"], home);
  assert.equal(blockedResult.status, 2, blockedResult.stderr);
  const blocked = JSON.parse(blockedResult.stdout);
  assert.equal(blocked.ok, false);
  assert.equal(blocked.status, "blocked");
  assert.match(blocked.blocker, /truncated tail/);
});
