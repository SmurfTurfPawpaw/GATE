import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { runtimePaths } from "../src/lib/paths.mjs";
import { buildStatus } from "../src/lib/status.mjs";
import { AGENT_SUMMARY_MAX_BYTES, statusSummary } from "../src/lib/summaries.mjs";
import {
  addWorkflowEvidence,
  createWorkflowInstance,
  finishWorkflowPhase,
  holdWorkflowLedger,
  openWorkflowLedger,
  startWorkflowPhase,
  stopWorkflow
} from "../src/lib/workflow-runtime.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const definition = JSON.parse(fs.readFileSync(path.join(repo, "config", "workflows", "pentest-e2e.json"), "utf8"));
const MAX_PROJECTION_BYTES = 4 * 1024 * 1024;

function fixture(t, prefix = "gate-workflow-visibility-") {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const paths = runtimePaths({ home: path.join(root, "home"), repo });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, paths };
}

function outputBytes(value) {
  return Buffer.byteLength(`${JSON.stringify(value, null, 2)}\n`);
}

function inputFile(root, name, contents = `${name}\n`) {
  const file = path.join(root, name);
  fs.writeFileSync(file, contents, { mode: 0o600 });
  return file;
}

function addRequiredEvidence(instanceId, phaseId, root, paths) {
  const phase = definition.phases.find((candidate) => candidate.id === phaseId);
  const results = [];
  for (const record of phase.evidence.filter((candidate) => candidate.required)) {
    results.push(addWorkflowEvidence(instanceId, {
      phaseId,
      evidenceId: record.id,
      claimState: record.claimState,
      file: inputFile(root, `${instanceId}-${phaseId}-${record.id}.txt`, `${record.id}: bounded fixture evidence\n`)
    }, { paths }));
  }
  return results;
}

function finishTestedPhase(instanceId, phaseId, root, paths, sourcePhase = null) {
  startWorkflowPhase(instanceId, { phaseId, ...(sourcePhase ? { sourcePhase } : {}) }, { paths });
  const evidence = addRequiredEvidence(instanceId, phaseId, root, paths);
  finishWorkflowPhase(instanceId, { phaseId, disposition: "tested" }, { paths });
  return evidence;
}

function completeFoundation(instanceId, root, paths) {
  finishTestedPhase(instanceId, "authorization-and-roe", root, paths);
  finishTestedPhase(instanceId, "target-and-architecture-map", root, paths, "authorization-and-roe");
}

function enterRecoveryHold(instanceId, root, paths) {
  completeFoundation(instanceId, root, paths);
  finishTestedPhase(instanceId, "local-artifact-analysis", root, paths, "target-and-architecture-map");
  startWorkflowPhase(instanceId, {
    phaseId: "desktop-client-dynamic-analysis",
    sourcePhase: "local-artifact-analysis"
  }, { paths });
  const [before] = addRequiredEvidence(instanceId, "desktop-client-dynamic-analysis", root, paths);
  const opened = openWorkflowLedger(instanceId, {
    changeType: "fixture-change",
    targetSelectorSha256: "1".repeat(64),
    beforeEvidenceSha256: before.entry.payload.sha256,
    cleanupAction: "Restore the exact offline visibility fixture."
  }, { paths });
  holdWorkflowLedger(instanceId, {
    entryId: opened.entry.payload.entryId,
    reason: "Independent cleanup verification is unavailable in the offline fixture."
  }, { paths });
}

function workflowDirectory(paths, instanceId) {
  return path.join(paths.workflows, instanceId);
}

function workflowMetadata(workflows, instanceId) {
  return workflows.instances.find((candidate) => candidate.instanceId === instanceId);
}

async function observedStatus(paths) {
  return buildStatus({
    paths,
    now: new Date("2026-10-14T16:00:00.000Z"),
    tokens: { roots: [path.join(paths.home, "no-codex-sessions")] }
  });
}

test("fresh workflows are visible in full and bounded status projections", async (t) => {
  const { paths } = fixture(t, "gate-workflow-visible-fresh-");
  createWorkflowInstance("fresh-workflow", {}, { paths });

  const status = await observedStatus(paths);
  assert.equal(status.workflows.counts.total, 1);
  assert.equal(status.workflows.counts.open, 1);
  assert.equal(status.workflows.counts.active, 0);
  assert.equal(status.workflows.counts.degraded, 0);
  assert.deepEqual(status.workflows.scan, {
    discovered: 1,
    scanned: 1,
    omitted: 0,
    complete: true,
    truncated: false
  });
  assert.deepEqual(workflowMetadata(status.workflows, "fresh-workflow"), {
    instanceId: "fresh-workflow",
    status: "open",
    activePhase: null,
    journalSequence: 0,
    reservations: 0,
    stops: 0,
    health: "bounded-replay-verified"
  });

  const summary = statusSummary(status);
  assert.equal(summary.workflows.counts.total, 1);
  assert.equal(summary.workflows.counts.open, 1);
  assert.deepEqual(workflowMetadata(summary.workflows, "fresh-workflow"),
    workflowMetadata(status.workflows, "fresh-workflow"));
  assert.deepEqual(summary.workflows.scan, status.workflows.scan);
  assert.ok(outputBytes(summary) < AGENT_SUMMARY_MAX_BYTES);
});

test("workflow status aggregates active, stopped, and recovery-hold state with safe metadata", async (t) => {
  const { root, paths } = fixture(t, "gate-workflow-visible-states-");

  createWorkflowInstance("active-workflow", {}, { paths });
  startWorkflowPhase("active-workflow", { phaseId: "authorization-and-roe" }, { paths });

  createWorkflowInstance("stopped-workflow", {}, { paths });
  stopWorkflow("stopped-workflow", {
    condition: "operator-stop",
    reason: "Stop the bounded visibility fixture."
  }, { paths });

  createWorkflowInstance("held-workflow", {}, { paths });
  enterRecoveryHold("held-workflow", root, paths);

  const status = await observedStatus(paths);
  assert.equal(status.workflows.counts.total, 3);
  assert.equal(status.workflows.counts.active, 1);
  assert.equal(status.workflows.counts.open, 1);
  assert.equal(status.workflows.counts.stopped, 1);
  assert.equal(status.workflows.counts["recovery-hold"], 1);
  assert.equal(status.workflows.counts.degraded, 0);

  const active = workflowMetadata(status.workflows, "active-workflow");
  assert.deepEqual(active, {
    instanceId: "active-workflow",
    status: "open",
    activePhase: {
      id: "authorization-and-roe",
      lane: "governance",
      effectClass: "P0",
      toolId: null,
      envelopeControls: null
    },
    journalSequence: 1,
    reservations: 0,
    stops: 0,
    health: "bounded-replay-verified"
  });
  assert.equal(workflowMetadata(status.workflows, "stopped-workflow").stops, 1);
  assert.equal(workflowMetadata(status.workflows, "held-workflow").status, "recovery-hold");

  const serialized = JSON.stringify(status.workflows);
  for (const forbidden of [
    paths.home,
    "journalHeadSha256",
    "admissionSha256",
    "authorityReceiptSha256",
    "targetSha256",
    "stopConditions",
    "evidenceCount",
    "unresolvedClaims"
  ]) assert.equal(serialized.includes(forbidden), false, `workflow visibility leaked ${forbidden}`);

  const summary = statusSummary(status);
  assert.equal(summary.workflows.counts.active, 1);
  assert.equal(summary.workflows.counts.stopped, 1);
  assert.equal(summary.workflows.counts["recovery-hold"], 1);
  assert.deepEqual(workflowMetadata(summary.workflows, "active-workflow"), active);
  assert.ok(outputBytes(summary) < AGENT_SUMMARY_MAX_BYTES);
});

test("malformed, locked, oversized, and truncated workflow state is degraded rather than omitted", async (t) => {
  const { paths } = fixture(t, "gate-workflow-visible-degraded-");
  const ids = ["malformed-workflow", "locked-workflow", "oversized-workflow", "truncated-workflow"];
  for (const id of ids) createWorkflowInstance(id, {}, { paths });

  fs.writeFileSync(
    path.join(workflowDirectory(paths, "malformed-workflow"), "instance.json"),
    "{\"private-marker\":\"must-not-be-reflected\"",
    { mode: 0o600 }
  );

  let bootId = null;
  let startTimeTicks = null;
  if (process.platform === "linux") {
    bootId = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim().toLowerCase();
    const stat = fs.readFileSync(`/proc/${process.pid}/stat`, "utf8");
    const close = stat.lastIndexOf(")");
    startTimeTicks = stat.slice(close + 2).trim().split(/\s+/u)[19];
  }
  fs.writeFileSync(path.join(workflowDirectory(paths, "locked-workflow"), ".lock"), `${JSON.stringify({
    apiVersion: "gate.workflow-lock/v1",
    pid: process.pid,
    bootId,
    startTimeTicks,
    nonce: "a".repeat(32),
    createdAt: new Date().toISOString()
  })}\n`, { mode: 0o600, flag: "wx" });

  fs.writeFileSync(
    path.join(workflowDirectory(paths, "oversized-workflow"), "instance.json"),
    Buffer.alloc(MAX_PROJECTION_BYTES + 1, 0x78),
    { mode: 0o600 }
  );

  const truncatedJournal = path.join(workflowDirectory(paths, "truncated-workflow"), "journal.jsonl");
  const journalBytes = fs.readFileSync(truncatedJournal);
  fs.writeFileSync(truncatedJournal, journalBytes.subarray(0, journalBytes.length - 1), { mode: 0o600 });

  const status = await observedStatus(paths);
  assert.equal(status.workflows.counts.total, ids.length);
  assert.equal(status.workflows.counts.degraded, ids.length);
  assert.equal(status.workflows.scan.discovered, ids.length);
  assert.equal(status.workflows.scan.scanned, ids.length);
  assert.equal(status.workflows.scan.omitted, 0);
  assert.equal(status.workflows.scan.complete, false);
  assert.equal(status.workflows.scan.truncated, false);
  assert.deepEqual(status.workflows.instances.map((entry) => entry.instanceId).sort(), ids.sort());
  for (const id of ids) {
    assert.deepEqual(workflowMetadata(status.workflows, id), {
      instanceId: id,
      status: "unknown",
      activePhase: null,
      journalSequence: null,
      reservations: null,
      stops: null,
      health: "degraded"
    });
  }

  const serialized = JSON.stringify(status.workflows);
  assert.equal(serialized.includes(paths.home), false);
  assert.equal(serialized.includes("must-not-be-reflected"), false);
  assert.equal(serialized.includes("blocker"), false);

  const summary = statusSummary(status);
  assert.equal(summary.workflows.counts.degraded, ids.length);
  assert.equal(summary.workflows.scan.complete, false);
  assert.deepEqual(summary.workflows.instances.map((entry) => entry.instanceId).sort(), ids.sort());
});

test("bounded workflow scans report omitted unknown state when discovery is truncated", async (t) => {
  const { paths } = fixture(t, "gate-workflow-visible-truncated-scan-");
  const discovered = 513;
  fs.mkdirSync(paths.workflows, { recursive: true, mode: 0o700 });
  for (let index = 0; index < discovered; index += 1) {
    fs.mkdirSync(path.join(paths.workflows, `scan-${String(index).padStart(4, "0")}`), { mode: 0o700 });
  }

  const status = await observedStatus(paths);
  assert.equal(status.workflows.counts.total, discovered);
  assert.equal(status.workflows.scan.discovered, discovered);
  assert.ok(status.workflows.scan.scanned > 0);
  assert.ok(status.workflows.scan.scanned < discovered);
  assert.equal(status.workflows.scan.omitted, discovered - status.workflows.scan.scanned);
  assert.equal(status.workflows.instances.length, status.workflows.scan.scanned);
  assert.equal(status.workflows.scan.complete, false);
  assert.equal(status.workflows.scan.truncated, true);
  assert.ok(status.workflows.counts.unknown >= status.workflows.scan.omitted);

  const summary = statusSummary(status);
  assert.equal(summary.workflows.counts.total, discovered);
  assert.equal(summary.workflows.scan.discovered, discovered);
  assert.equal(summary.workflows.scan.omitted, status.workflows.scan.omitted);
  assert.equal(summary.workflows.scan.complete, false);
  assert.equal(summary.workflows.scan.truncated, true);
  assert.ok(summary.workflows.instances.length < status.workflows.instances.length);
  assert.equal(
    summary.workflows.omittedInstances,
    status.workflows.instances.length - summary.workflows.instances.length + status.workflows.scan.omitted
  );
  assert.ok(outputBytes(summary) < AGENT_SUMMARY_MAX_BYTES);
});

test("worst-case workflow metadata keeps the agent status summary below 8 KiB", () => {
  const instances = Array.from({ length: 256 }, (_, index) => ({
    instanceId: `workflow-${String(index).padStart(3, "0")}-${"x".repeat(48)}`,
    status: index % 4 === 0 ? "open" : index % 4 === 1 ? "stopped" : index % 4 === 2 ? "recovery-hold" : "unknown",
    activePhase: index % 4 === 0 ? {
      id: `phase-${index}-${"x".repeat(80)}`,
      lane: `lane-${index}-${"x".repeat(80)}`,
      effectClass: "A3",
      toolId: `tool-${index}-${"x".repeat(80)}`,
      envelopeControls: {
        wallTime: "unavailable",
        requests: "unavailable",
        rate: "unavailable",
        parallel: "unavailable",
        tokens: "unavailable",
        evidenceBytes: "unavailable",
        spend: "unavailable"
      }
    } : null,
    journalSequence: index,
    reservations: index,
    stops: index,
    health: index % 4 === 3 ? "degraded" : "bounded-replay-verified",
    privateBody: "private".repeat(1_000)
  }));
  const status = {
    at: "2026-10-14T16:00:00.000Z",
    events: [], learnings: [], engagements: [], projects: [],
    execution: { counts: {} }, offlineAnalysis: { counts: {}, retention: {} },
    tokens: [], upstreams: [], toolRuntimes: { tools: [] },
    workflows: {
      counts: { total: 1_000_000, active: 64, open: 64, stopped: 64,
        "recovery-hold": 64, degraded: 64, unknown: 999_744 },
      instances,
      scan: { discovered: 1_000_000, scanned: 256, omitted: 999_744, complete: false, truncated: true }
    }
  };

  const summary = statusSummary(status);
  assert.ok(outputBytes(summary) < AGENT_SUMMARY_MAX_BYTES);
  assert.equal(summary.workflows.counts.total, 1_000_000);
  assert.equal(summary.workflows.scan.truncated, true);
  assert.ok(summary.workflows.instances.length > 0);
  assert.ok(summary.workflows.instances.length < instances.length);
  assert.equal(summary.workflows.omittedInstances, 1_000_000 - summary.workflows.instances.length);
  assert.equal(JSON.stringify(summary.workflows).includes("privateBody"), false);
});
