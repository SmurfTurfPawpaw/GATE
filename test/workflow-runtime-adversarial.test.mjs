import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { PENTEST_COVERAGE_DOMAINS } from "../src/lib/pentest-workflow.mjs";
import { runtimePaths } from "../src/lib/paths.mjs";
import {
  addWorkflowEvidence,
  attachWorkflowReport,
  createWorkflowInstance,
  finishWorkflowPhase,
  joinWorkflowCoverage,
  openWorkflowLedger,
  setWorkflowCoverage,
  startWorkflowPhase,
  stopWorkflow,
  workflowStatus
} from "../src/lib/workflow-runtime.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const definition = JSON.parse(fs.readFileSync(path.join(repo, "config", "workflows", "pentest-e2e.json"), "utf8"));

function fixture(t, prefix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const paths = runtimePaths({ home: path.join(root, "home"), repo });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, paths };
}

function instanceFiles(paths, id) {
  const directory = path.join(paths.workflows, id);
  return {
    directory,
    journal: path.join(directory, "journal.jsonl"),
    lock: path.join(directory, ".lock")
  };
}

function inputFile(root, name, contents = `${name}\n`) {
  const file = path.join(root, name);
  fs.writeFileSync(file, contents, { mode: 0o600 });
  return file;
}

function addRequiredEvidence(id, phaseId, root, paths) {
  const phase = definition.phases.find((candidate) => candidate.id === phaseId);
  const digests = [];
  for (const record of phase.evidence.filter((candidate) => candidate.required)) {
    const bytes = Buffer.from(`${phaseId}:${record.id}:adversarial-fixture\n`);
    const file = inputFile(root, `${phaseId}-${record.id}.txt`, bytes);
    addWorkflowEvidence(id, {
      phaseId,
      evidenceId: record.id,
      claimState: record.claimState,
      file
    }, { paths });
    digests.push(crypto.createHash("sha256").update(bytes).digest("hex"));
  }
  return digests;
}

function completeFoundation(id, root, paths) {
  startWorkflowPhase(id, { phaseId: "authorization-and-roe" }, { paths });
  addRequiredEvidence(id, "authorization-and-roe", root, paths);
  finishWorkflowPhase(id, { phaseId: "authorization-and-roe", disposition: "tested" }, { paths });

  startWorkflowPhase(id, {
    phaseId: "target-and-architecture-map",
    sourcePhase: "authorization-and-roe"
  }, { paths });
  addRequiredEvidence(id, "target-and-architecture-map", root, paths);
  finishWorkflowPhase(id, { phaseId: "target-and-architecture-map", disposition: "tested" }, { paths });
}

test("malformed non-null workflow lock identity is preserved and blocks reads and mutations", (t) => {
  const { paths } = fixture(t, "gate-workflow-malformed-lock-");
  const id = "malformed-lock";
  createWorkflowInstance(id, {}, { paths });
  const { lock } = instanceFiles(paths, id);
  const lockBytes = Buffer.from(`${JSON.stringify({
    apiVersion: "gate.workflow-lock/v1",
    pid: process.pid,
    bootId: "malformed-non-null-boot-id",
    startTimeTicks: "malformed-non-null-start-ticks",
    nonce: "a".repeat(32),
    createdAt: new Date().toISOString()
  })}\n`);
  fs.writeFileSync(lock, lockBytes, { flag: "wx", mode: 0o600 });

  const status = workflowStatus(id, { paths });
  assert.equal(status.ok, false);
  assert.equal(status.status, "blocked");
  assert.match(status.blocker, /lock identity is malformed/u);
  assert.deepEqual(fs.readFileSync(lock), lockBytes);

  assert.throws(
    () => stopWorkflow(id, {
      condition: "operator-stop",
      reason: "The malformed lock must block mutation without being retired."
    }, { paths }),
    /lock identity is malformed/u
  );
  assert.deepEqual(fs.readFileSync(lock), lockBytes);
});

test("dead workflow lock recovery ignores PATH flock and ambient Node preload", (t) => {
  if (process.platform !== "linux") return t.skip("workflow mutation locks require Linux/WSL2");
  const { root, paths } = fixture(t, "gate-workflow-lock-path-");
  const id = "protected-lock-recovery";
  createWorkflowInstance(id, {}, { paths });
  const { lock } = instanceFiles(paths, id);
  const fakeBin = path.join(root, "fake-bin");
  const flockMarker = path.join(root, "fake-flock-ran.txt");
  const preloadMarker = path.join(root, "node-preload-ran.txt");
  const preload = path.join(root, "preload.cjs");
  fs.mkdirSync(fakeBin, { mode: 0o700 });
  fs.writeFileSync(path.join(fakeBin, "flock"),
    `#!/bin/sh\nprintf '%s' "$GATE_WORKFLOW_TOKEN" > '${flockMarker}'\nexec /usr/bin/flock "$@"\n`,
    { mode: 0o700 });
  fs.writeFileSync(preload, `require('node:fs').writeFileSync(${JSON.stringify(preloadMarker)}, 'loaded');\n`, { mode: 0o600 });
  fs.writeFileSync(lock, `${JSON.stringify({
    apiVersion: "gate.workflow-lock/v1",
    pid: process.pid,
    bootId: "00000000-0000-0000-0000-000000000000",
    startTimeTicks: "1",
    nonce: "b".repeat(32),
    createdAt: new Date().toISOString()
  })}\n`, { flag: "wx", mode: 0o600 });

  const names = ["PATH", "NODE_OPTIONS", "GATE_WORKFLOW_TOKEN"];
  const previous = Object.fromEntries(names.map((name) => [name, process.env[name]]));
  t.after(() => {
    for (const name of names) {
      if (previous[name] === undefined) delete process.env[name];
      else process.env[name] = previous[name];
    }
  });
  process.env.PATH = `${fakeBin}${path.delimiter}${previous.PATH || ""}`;
  process.env.NODE_OPTIONS = `--require=${preload}`;
  process.env.GATE_WORKFLOW_TOKEN = "WORKFLOW_TOKEN_CANARY";

  const stopped = stopWorkflow(id, {
    condition: "operator-stop",
    reason: "Exercise protected stale-lock recovery."
  }, { paths });
  assert.equal(stopped.projection.status, "stopped");
  assert.equal(fs.existsSync(flockMarker), false, "PATH-first flock must not execute");
  assert.equal(fs.existsSync(preloadMarker), false, "NODE_OPTIONS must not reach the lock-recovery Node child");
  assert.equal(fs.existsSync(lock), false, "the protected flock path must still complete lock recovery");
});

test("a stopped workflow rejects direct progress mutations and ordinary phase starts", (t) => {
  const { root, paths } = fixture(t, "gate-workflow-stopped-guard-");
  const id = "stopped-guard";
  createWorkflowInstance(id, {}, { paths });
  stopWorkflow(id, {
    condition: "operator-stop",
    reason: "Stop before any branch begins."
  }, { paths });

  assert.throws(
    () => finishWorkflowPhase(id, {
      phaseId: "local-artifact-analysis",
      disposition: "blocked",
      rationale: "A stop cannot be converted into a direct phase disposition."
    }, { paths }),
    /workflow status stopped cannot finish this phase/u
  );
  assert.throws(
    () => setWorkflowCoverage(id, {
      domain: PENTEST_COVERAGE_DOMAINS[0],
      disposition: "blocked",
      rationale: "A stop cannot be converted into coverage."
    }, { paths }),
    /workflow status stopped cannot set coverage/u
  );
  assert.throws(
    () => joinWorkflowCoverage(id, {}, { paths }),
    /workflow status stopped cannot join coverage/u
  );
  assert.throws(
    () => attachWorkflowReport(id, { file: inputFile(root, "blocked-report.md", "# blocked\n") }, { paths }),
    /workflow status stopped cannot attach a report/u
  );
  assert.throws(
    () => startWorkflowPhase(id, { phaseId: "authorization-and-roe" }, { paths }),
    /fired stop blocks normal phase progress/u
  );

  const status = workflowStatus(id, { paths });
  assert.equal(status.ok, true);
  assert.equal(status.status, "stopped");
  assert.equal(status.journal.sequence, 1);
  assert.equal(status.coverage.recorded, 0);
  assert.equal(status.joined, false);
  assert.equal(status.reportSha256, null);
});

test("recovery hold permits only its exact preauthorized teardown route", (t) => {
  const { root, paths } = fixture(t, "gate-workflow-teardown-route-");
  const id = "teardown-route";
  createWorkflowInstance(id, {}, { paths });
  completeFoundation(id, root, paths);

  startWorkflowPhase(id, {
    phaseId: "local-artifact-analysis",
    sourcePhase: "target-and-architecture-map"
  }, { paths });
  addRequiredEvidence(id, "local-artifact-analysis", root, paths);
  finishWorkflowPhase(id, { phaseId: "local-artifact-analysis", disposition: "tested" }, { paths });

  startWorkflowPhase(id, {
    phaseId: "desktop-client-dynamic-analysis",
    sourcePhase: "local-artifact-analysis"
  }, { paths });
  const [beforeEvidenceSha256] = addRequiredEvidence(id, "desktop-client-dynamic-analysis", root, paths);
  openWorkflowLedger(id, {
    changeType: "offline-lab-change",
    targetSelectorSha256: "b".repeat(64),
    beforeEvidenceSha256,
    cleanupAction: "Restore the isolated lab snapshot and independently verify its baseline."
  }, { paths });
  stopWorkflow(id, {
    condition: "operator-stop",
    reason: "Stop the dynamic fixture after a recorded lab change."
  }, { paths });
  assert.equal(workflowStatus(id, { paths }).status, "recovery-hold");

  assert.throws(
    () => startWorkflowPhase(id, {
      phaseId: "source-and-supply-chain-review",
      sourcePhase: "target-and-architecture-map"
    }, { paths }),
    /fired stop blocks normal phase progress/u
  );

  const teardown = startWorkflowPhase(id, {
    phaseId: "offline-lab-reset-verification",
    sourcePhase: "desktop-client-dynamic-analysis"
  }, { paths });
  assert.equal(teardown.entry.type, "phase.started");
  assert.equal(teardown.projection.activePhase.phaseId, "offline-lab-reset-verification");
  assert.equal(teardown.projection.status, "recovery-hold");
});

test("repeated stops remain journal-complete while compact status stays below 16 KiB", (t) => {
  const { paths } = fixture(t, "gate-workflow-stop-bound-");
  const id = "bounded-stops";
  createWorkflowInstance(id, {}, { paths });
  const stopTotal = 144;
  for (let index = 0; index < stopTotal; index += 1) {
    stopWorkflow(id, {
      condition: index === stopTotal - 1 ? "operator-stop" : "scope-mismatch",
      reason: `Stop ${index}: ${"bounded-adversarial-reason ".repeat(30)}`
    }, { paths });
  }

  const status = workflowStatus(id, { paths });
  assert.equal(status.ok, true);
  assert.equal(status.status, "stopped");
  assert.equal(status.stopCount, stopTotal);
  assert.equal(status.stops.length, 32);
  assert.equal(status.omittedStopCount, stopTotal - status.stops.length);
  assert.equal(status.stops.at(-1).condition, "operator-stop");
  assert.ok(Buffer.byteLength(`${JSON.stringify(status, null, 2)}\n`) < 16 * 1024);

  const journalLines = fs.readFileSync(instanceFiles(paths, id).journal, "utf8").trimEnd().split("\n");
  assert.equal(journalLines.length, stopTotal + 1);
  assert.equal(status.journal.sequence, stopTotal);
});
