import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { buildStatus } from "../src/lib/status.mjs";
import {
  AGENT_SUMMARY_MAX_BYTES,
  statusSummary,
  toolInventorySummary
} from "../src/lib/summaries.mjs";
import { runtimePaths } from "../src/lib/paths.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const gate = path.join(repo, "bin", "gate.mjs");

function bytes(value) {
  return Buffer.byteLength(JSON.stringify(value, null, 2));
}

function outputBytes(value) {
  return bytes(value) + 1;
}

test("observer status requests receipt evidence without executable hashing", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-fast-status-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const paths = runtimePaths({ repo, home: path.join(root, "home") });
  const status = await buildStatus({
    paths,
    now: new Date("2026-10-14T16:00:00.000Z"),
    tokens: { roots: [path.join(root, "no-sessions")] }
  });
  assert.equal(status.at, "2026-10-14T16:00:00.000Z");
  assert.equal(status.toolRuntimes.verificationMode, "receipt-only");
  assert.equal(status.toolRuntimes.currentBytesChecked, false);
  assert.equal(status.toolRuntimes.executableHashReads, 0);
});

test("status bounds engagement discovery, projection, and individual record reads", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-bounded-engagement-status-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const paths = runtimePaths({ repo, home: path.join(root, "home") });
  fs.mkdirSync(paths.engagements, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(paths.engagements, "000-oversized.json"), "x".repeat(2 * 1024 * 1024 + 1), {
    mode: 0o600
  });
  for (let index = 0; index < 70; index += 1) {
    const name = `eng-${String(index).padStart(3, "0")}.json`;
    fs.writeFileSync(path.join(paths.engagements, name), `${JSON.stringify({ marker: name })}\n`, { mode: 0o600 });
  }

  const status = await buildStatus({
    paths,
    tokens: { roots: [path.join(root, "no-sessions")] }
  });

  assert.equal(status.engagements.length, 64);
  assert.deepEqual(status.engagements[0], { id: "000-oversized.json", status: "invalid" });
  assert.equal(status.engagements[1].marker, "eng-000.json");
  assert.deepEqual(status.engagementScan, {
    limit: 64,
    discoveryLimit: 4096,
    entriesInspected: 71,
    discoveredAtLeast: 71,
    scanned: 64,
    omittedAtLeast: 7,
    invalid: 1,
    complete: false,
    truncated: true,
    discoveryTruncated: false
  });
});

test("agent status summary stays below 8 KiB under adversarial bounded fields", () => {
  const manyCounts = Object.fromEntries(Array.from({ length: 30 }, (_, index) => [
    `count-${index}-${"x".repeat(100)}`,
    index
  ]));
  const raw = {
    at: "2026-10-14T16:00:00.000Z",
    repository: "/private/repository",
    gate_home: "/private/home",
    events: Array.from({ length: 30 }, (_, index) => ({ kind: `event.${index}`, summary: "x".repeat(2_000) })),
    learnings: Array.from({ length: 30 }, (_, index) => ({
      status: `learning-${index}-${"x".repeat(100)}`,
      cause: "x".repeat(2_000)
    })),
    engagements: Array.from({ length: 30 }, (_, index) => ({
      metadata: { status: `engagement-${index}-${"x".repeat(100)}` },
      privateBody: "x".repeat(2_000)
    })),
    projects: Array.from({ length: 30 }, (_, index) => ({
      status: `project-${index}-${"x".repeat(100)}`,
      privateBody: "x".repeat(2_000)
    })),
    execution: { capability: { laneAvailable: true, mode: "supervised-generic" }, counts: manyCounts },
    offlineAnalysis: {
      capability: { laneAvailable: true, mode: "bubblewrap-offline" },
      counts: manyCounts,
      retention: { retainedArtifacts: 0, retainedBytes: 0, mutationBlocked: false }
    },
    tokens: {
      availability: "unavailable",
      source: "codex-session-jsonl:host-session-roots",
      discoveredFiles: 0,
      scannedFiles: 0,
      matchedFiles: 0,
      bytesRead: 0,
      cacheHits: 0,
      filesRead: 0,
      partial: false,
      truncated: false,
      totals: {
        inputTokens: null,
        cachedInputTokens: null,
        outputTokens: null,
        reasoningTokens: null,
        totalTokens: null
      }
    },
    upstreams: Array.from({ length: 30 }, (_, index) => ({
      integrityState: `integrity-${index}-${"x".repeat(100)}`,
      privateBody: "x".repeat(2_000)
    })),
    toolRuntimes: {
      verificationMode: "receipt-only",
      currentBytesChecked: false,
      executableHashReads: 0,
      catalog: 126,
      locked: 7,
      installed: 12,
      verified: 0,
      executable: 0,
      unresolved: 126,
      tools: Array.from({ length: 126 }, (_, index) => ({
        id: `tool-${index}-${"x".repeat(200)}`,
        state: `state-${index}-${"x".repeat(200)}`,
        installed: index < 12,
        verificationEvidence: index < 12 ? {
          kind: "installation-receipt",
          lastVerifiedAt: "2026-10-14T00:00:00.000Z",
          ageSeconds: 99_999,
          current: false,
          currentBytesChecked: false,
          liveSmokeExecutedNow: false
        } : null
      }))
    }
  };
  const summary = statusSummary(raw);
  assert.ok(outputBytes(summary) < AGENT_SUMMARY_MAX_BYTES);
  assert.equal(summary.tokens.availability, "unavailable");
  assert.deepEqual(Object.values(summary.tokens.totals), [null, null, null, null, null]);
  assert.equal(summary.toolRuntimes.currentBytesChecked, false);
  assert.equal(summary.toolRuntimes.executableHashReads, 0);
  assert.equal(summary.toolRuntimes.installedRuntimes.length, 5);
  assert.equal(summary.toolRuntimes.omittedInstalledRuntimes, 7);
  assert.equal(summary.execution.omittedCountKinds, 24);
  assert.equal(summary.omitted.runtimeBodies, 126);
  assert.match(summary.source.sha256, /^[a-f0-9]{64}$/u);
  assert.ok(summary.source.bytes > bytes(summary));
});

test("status summary retains runtime selection and bounded actionable case lanes", () => {
  const executionCounts = (running = 0) => ({
    queued: 0, running, stopping: 0, succeeded: 0, failed: 0, cancelled: 0, blocked: 0, unknown: 0
  });
  const offlineCounts = (queued = 0) => ({
    queued, running: 0, succeeded: 0, failed: 0, cancelled: 0, blocked: 0, unknown: 0
  });
  const workflowCounts = (active = 0) => ({
    total: active, active, open: active, stopped: 0, "recovery-hold": 0,
    reported: 0, closed: 0, degraded: 0, unknown: 0
  });
  const cases = Array.from({ length: 32 }, (_, index) => ({
    id: `case-${String(index).padStart(2, "0")}`,
    displayName: `Case ${index} ${"x".repeat(200)}`,
    status: index === 0 ? "stale" : "ready",
    binding: {
      program: { id: `program-${index}`, current: index !== 0 },
      project: null
    },
    rawTarget: `PRIVATE_TARGET_${index}`,
    runtime: {
      engagements: [{
        metadata: { status: "active" },
        evidence: `PRIVATE_EVIDENCE_${index}`,
        argv: [`PRIVATE_ARGV_${index}`]
      }],
      engagementScan: { complete: true, omittedAtLeast: 0, invalid: 0 },
      execution: { counts: executionCounts(index === 31 ? 2 : 0) },
      workflows: { counts: workflowCounts(index === 30 ? 1 : 0) },
      offlineAnalysis: { counts: offlineCounts(index === 29 ? 3 : 0) },
      tokens: []
    }
  }));
  const aggregate = statusSummary({
    at: "2026-10-15T12:00:00.000Z",
    selection: { mode: "aggregate", caseId: null },
    cases,
    caseScan: {
      attempted: true,
      limit: 32,
      discoveryLimit: 1024,
      discovered: 40,
      scanned: 32,
      omitted: 8,
      invalid: 0,
      discoveredAtLeast: false,
      omittedAtLeast: false,
      complete: false,
      truncated: true
    },
    events: [], learnings: [], engagements: [], projects: [], upstreams: [],
    toolRuntimes: { tools: [] }
  });
  assert.ok(outputBytes(aggregate) < AGENT_SUMMARY_MAX_BYTES);
  assert.deepEqual(aggregate.selection, { mode: "aggregate", caseId: null, bindingHealth: null });
  assert.equal(aggregate.caseFleet.scan.discovered, 40);
  assert.equal(aggregate.caseFleet.scan.omitted, 8);
  assert.equal(aggregate.caseFleet.observedCases, 32);
  assert.ok(aggregate.caseFleet.items.length > 0 && aggregate.caseFleet.items.length <= 8);
  assert.equal(
    aggregate.caseFleet.omittedObservedCases,
    aggregate.caseFleet.observedCases - aggregate.caseFleet.items.length
  );
  const projectedCaseIds = new Set(aggregate.caseFleet.items.map((item) => item.id));
  for (const id of ["case-29", "case-30", "case-31"]) {
    assert.equal(projectedCaseIds.has(id), true, `${id} should be retained in the actionable projection`);
  }
  assert.equal(aggregate.caseFleet.statuses.stale, 1);
  assert.equal(aggregate.caseFleet.observedLaneCounts.execution.nonzero.running, 2);
  assert.equal(aggregate.caseFleet.observedLaneCounts.workflows.nonzero.active, 1);
  assert.equal(aggregate.caseFleet.observedLaneCounts.offlineAnalysis.nonzero.queued, 3);
  assert.equal(aggregate.caseFleet.observedLaneCounts.coverageComplete, false);
  assert.equal(aggregate.caseFleet.retrieval.caseStatus, "gate --case ID status --summary --json");
  const serialized = JSON.stringify(aggregate);
  for (const forbidden of ["PRIVATE_TARGET", "PRIVATE_EVIDENCE", "PRIVATE_ARGV", "rawTarget", "evidence", "argv"]) {
    assert.equal(serialized.includes(forbidden), false, `status summary leaked ${forbidden}`);
  }

  const selected = statusSummary({
    selection: {
      mode: "case",
      caseId: "selected-case",
      bindingHealth: { status: "stale", programCurrent: false, projectCurrent: true }
    },
    selectedCaseId: "selected-case",
    cases: [],
    caseScan: { attempted: false, discovered: 0, scanned: 0, omitted: 0, invalid: 0, complete: false, truncated: false },
    events: [], learnings: [], engagements: [], projects: [], upstreams: [], toolRuntimes: { tools: [] }
  });
  assert.deepEqual(selected.selection, {
    mode: "case",
    caseId: "selected-case",
    bindingHealth: { status: "stale", programCurrent: false, projectCurrent: true }
  });
  assert.equal(selected.caseFleet.scan.attempted, false);
  assert.equal(selected.retrieval.fullStatus, "gate --case ID status --json");
  assert.equal(selected.retrieval.workflowDetail, "gate --case ID workflow status ID --json");

  const unassigned = statusSummary({
    selection: { mode: "unassigned", caseId: null },
    cases: [],
    caseScan: { attempted: false, discovered: 0, scanned: 0, omitted: 0, invalid: 0, complete: false, truncated: false },
    events: [], learnings: [], engagements: [], projects: [], upstreams: [], toolRuntimes: { tools: [] }
  });
  assert.deepEqual(unassigned.selection, { mode: "unassigned", caseId: null, bindingHealth: null });
  assert.equal(unassigned.caseFleet.observedCases, 0);
  assert.equal(unassigned.retrieval.fullStatus, "gate --unassigned status --json");
  assert.equal(unassigned.retrieval.workflowDetail, "gate --unassigned workflow status ID --json");
});

test("agent status summary selects the latest cumulative usage per logical session", () => {
  const record = (id, at, totalTokens) => ({
    id,
    at,
    runId: "run.same",
    taskId: null,
    agent: "codex",
    provider: "openai",
    model: "gpt",
    availability: "exact",
    measure: "cumulative",
    inputTokens: null,
    cachedInputTokens: null,
    outputTokens: null,
    reasoningTokens: null,
    totalTokens
  });
  const summary = statusSummary({
    tokens: [
      record("use_first", "2026-10-14T16:00:00.000Z", 10),
      record("use_second", "2026-10-14T16:01:00.000Z", 15)
    ],
    events: [],
    learnings: [],
    engagements: [],
    projects: [],
    upstreams: [],
    toolRuntimes: { tools: [] }
  });
  assert.equal(summary.tokens.availability, "exact");
  assert.equal(summary.tokens.totals.totalTokens, 15);
  assert.equal(summary.tokens.sessions, 1);
});

test("agent status summary preserves last occurrence order for duplicate usage IDs", async (t) => {
  const at = "2026-10-14T16:00:00.000Z";
  const record = (id, totalTokens) => ({
    apiVersion: "gate.usage/v1",
    id,
    at,
    runId: "run.same",
    taskId: null,
    agent: "codex",
    provider: "openai",
    model: "gpt",
    availability: "exact",
    measure: "cumulative",
    inputTokens: null,
    cachedInputTokens: null,
    outputTokens: null,
    reasoningTokens: null,
    totalTokens,
    source: "gate-token-log"
  });
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-usage-order-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const paths = runtimePaths({ repo, home: path.join(root, "home") });
  fs.mkdirSync(paths.home, { recursive: true, mode: 0o700 });
  const records = [record("use_first01", 10), record("use_second", 20), record("use_first01", 30)];
  fs.writeFileSync(paths.tokens, `${records.map((value) => JSON.stringify(value)).join("\n")}\n`, { mode: 0o600 });
  const status = await buildStatus({ paths });
  assert.equal(statusSummary({ tokens: records.slice(0, 2) }).tokens.totals.totalTokens, 20);
  assert.deepEqual(status.tokens.map((value) => value.id), ["use_second", "use_first01"]);
  assert.equal(status.tokens.length, 2);
  const summary = statusSummary(status);
  assert.equal(summary.tokens.totals.totalTokens, 30);
  assert.equal(summary.tokens.sessions, 1);
});

test("tool summary is digest-bound, paged, and below 8 KiB", () => {
  const inventory = {
    host: "linux",
    count: 126,
    locked: 7,
    installed: 7,
    receiptOnly: 7,
    verified: 0,
    executable: 0,
    unresolved: 126,
    verificationMode: "receipt-only",
    tools: Array.from({ length: 126 }, (_, index) => ({
      id: `tool-${String(index).padStart(3, "0")}`,
      name: `Tool ${index} ${"x".repeat(200)}`,
      category: "network",
      riskClass: "A2",
      readiness: "candidate",
      compatible: true,
      managedRuntimeLocked: index < 7,
      installed: index < 7,
      integrityVerified: false,
      adapterReady: false,
      executionAvailable: false,
      privateBody: "x".repeat(4_000)
    }))
  };
  const first = toolInventorySummary(inventory, { limit: 12, cursor: 0 });
  const second = toolInventorySummary(inventory, { limit: 12, cursor: first.page.nextCursor });
  assert.ok(outputBytes(first) < AGENT_SUMMARY_MAX_BYTES);
  assert.equal(first.page.shown, 12);
  assert.equal(first.page.omittedCount, 114);
  assert.equal(first.page.nextCursor, 12);
  assert.equal(second.page.cursor, 12);
  assert.equal(second.tools[0].id, "tool-012");
  assert.match(first.source.sha256, /^[a-f0-9]{64}$/u);
  assert.ok(first.source.bytes > bytes(first));
  assert.throws(() => toolInventorySummary(inventory, { limit: 13 }), /integer from 0 to 12/);
});

test("tool summary dynamically fits multibyte catalog fields below the wire limit", () => {
  const inventory = {
    host: "linux",
    profile: { id: `p${"x".repeat(78)}`, maxRiskClass: "A3" },
    count: 12,
    locked: 0,
    installed: 0,
    receiptOnly: 0,
    verified: 0,
    executable: 0,
    unresolved: 12,
    verificationMode: "receipt-only",
    tools: Array.from({ length: 12 }, (_, index) => ({
      id: `wide-tool-${index}`,
      name: "界".repeat(100),
      category: "network",
      riskClass: "A2",
      readiness: "candidate",
      compatible: true,
      managedRuntimeLocked: false,
      installed: false,
      integrityVerified: false,
      adapterReady: false,
      executionAvailable: false
    }))
  };
  const summary = toolInventorySummary(inventory, { limit: 12, cursor: 0, profile: inventory.profile.id });
  assert.ok(outputBytes(summary) < AGENT_SUMMARY_MAX_BYTES);
  assert.ok(summary.page.shown > 0 && summary.page.shown < 12);
  assert.equal(summary.page.nextCursor, summary.page.shown);
  assert.equal(summary.page.omittedCount, 12 - summary.page.shown);
});

test("summary CLI projections stay bounded and paginate without inventing token usage", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-summary-cli-"));
  const home = path.join(root, "gate-home");
  const userHome = path.join(root, "user-home");
  fs.mkdirSync(userHome, { recursive: true });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const environment = { ...process.env, HOME: userHome, CODEX_HOME: path.join(root, "codex"), GATE_HOME: home };
  const invoke = (args) => spawnSync(process.execPath, [gate, ...args], {
    cwd: repo,
    env: environment,
    encoding: "utf8",
    timeout: 20_000,
    maxBuffer: 2 * 1024 * 1024
  });

  const status = invoke(["status", "--summary", "--json"]);
  assert.equal(status.status, 0, status.stderr);
  assert.ok(Buffer.byteLength(status.stdout) < AGENT_SUMMARY_MAX_BYTES);
  const statusValue = JSON.parse(status.stdout);
  assert.deepEqual(statusValue.selection, { mode: "aggregate", caseId: null, bindingHealth: null });
  assert.equal(statusValue.tokens.availability, "unavailable");
  assert.equal(statusValue.tokens.totals.totalTokens, null);

  const unassignedStatus = invoke(["--unassigned", "status", "--summary", "--json"]);
  assert.equal(unassignedStatus.status, 0, unassignedStatus.stderr);
  assert.ok(Buffer.byteLength(unassignedStatus.stdout) < AGENT_SUMMARY_MAX_BYTES);
  const unassignedStatusValue = JSON.parse(unassignedStatus.stdout);
  assert.deepEqual(unassignedStatusValue.selection, { mode: "unassigned", caseId: null, bindingHealth: null });
  assert.equal(unassignedStatusValue.caseFleet.scan.attempted, false);

  const list = invoke(["tool", "list", "--summary", "--limit", "10", "--cursor", "0", "--json"]);
  assert.equal(list.status, 0, list.stderr);
  assert.ok(Buffer.byteLength(list.stdout) < AGENT_SUMMARY_MAX_BYTES);
  const listValue = JSON.parse(list.stdout);
  assert.equal(listValue.page.shown, 10);
  assert.ok(listValue.page.omittedCount > 0);

  const detail = invoke(["tool", "show", listValue.tools[0].id, "--json"]);
  assert.equal(detail.status, 0, detail.stderr);
  assert.ok(Buffer.byteLength(detail.stdout) < AGENT_SUMMARY_MAX_BYTES);
  assert.equal(JSON.parse(detail.stdout).tool.id, listValue.tools[0].id);

  for (const flag of ["profile", "category"]) {
    const missing = invoke(["tool", "list", `--${flag}`, "--summary", "--json"]);
    assert.notEqual(missing.status, 0);
    assert.match(missing.stderr, new RegExp(`--${flag} needs a value`, "u"));
  }
});
