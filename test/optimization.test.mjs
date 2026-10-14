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

test("agent status summary breaks equal usage timestamps by original log order", () => {
  const at = "2026-10-14T16:00:00.000Z";
  const record = (id, totalTokens) => ({
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
    tokens: [record("use_first", 10), record("use_second", 20)],
    events: [],
    learnings: [],
    engagements: [],
    projects: [],
    upstreams: [],
    toolRuntimes: { tools: [] }
  });
  assert.equal(summary.tokens.totals.totalTokens, 20);
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
  assert.equal(statusValue.tokens.availability, "unavailable");
  assert.equal(statusValue.tokens.totals.totalTokens, null);

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
