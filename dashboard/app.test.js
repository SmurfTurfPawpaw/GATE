import assert from "node:assert/strict";
import test from "node:test";

import { executionPresentation, executionRunPresentation, reconcileRefreshResults } from "./app.js";

const at = "2026-10-13T12:00:00.000Z";

function fulfilled(value) {
  return { status: "fulfilled", value };
}

function rejected() {
  return { status: "rejected", reason: new Error("endpoint unavailable") };
}

function currentState() {
  return {
    status: { observedAt: "2026-10-13T11:59:00.000Z" },
    events: [{ id: "evt_previous" }],
    learnings: [{ id: "lrn_previous" }],
    failedEndpoints: new Set(),
    lastNetworkSuccess: 100
  };
}

test("partial endpoint failures preserve the last valid event and learning projections", () => {
  const current = currentState();
  const next = reconcileRefreshResults(current, {
    status: fulfilled({ apiVersion: "gate.observer/v1", at, state: "running" }),
    events: rejected(),
    learnings: rejected()
  }, 200);

  assert.strictEqual(next.events, current.events);
  assert.strictEqual(next.learnings, current.learnings);
  assert.deepEqual([...next.failedEndpoints], ["/api/events", "/api/learnings"]);
  assert.equal(next.lastNetworkSuccess, 200);
});

test("valid empty collections replace old data while malformed responses preserve it", () => {
  const current = currentState();
  const next = reconcileRefreshResults(current, {
    status: rejected(),
    events: fulfilled({ apiVersion: "gate.observer/v1", at, events: [] }),
    learnings: fulfilled({ apiVersion: "gate.observer/v1", at, records: [] })
  }, 300);

  assert.deepEqual(next.events, []);
  assert.strictEqual(next.learnings, current.learnings);
  assert.deepEqual([...next.failedEndpoints], ["/api/status", "/api/learnings"]);
  assert.equal(next.lastNetworkSuccess, 300);
});

test("a total refresh failure keeps the previous network-success timestamp", () => {
  const current = currentState();
  const next = reconcileRefreshResults(current, {
    status: rejected(),
    events: rejected(),
    learnings: rejected()
  }, 400);

  assert.strictEqual(next.status, current.status);
  assert.strictEqual(next.events, current.events);
  assert.strictEqual(next.learnings, current.learnings);
  assert.equal(next.lastNetworkSuccess, 100);
});

test("execution presentation separates configuration, lane availability, and durable run counts", () => {
  assert.deepEqual(executionPresentation({
    configured: true,
    laneAvailable: false,
    mode: "supervised-generic",
    reason: "proc-descriptor-unavailable",
    runningCount: 3,
    stoppingCount: 1
  }), {
    laneState: "unavailable",
    laneLabel: "Unavailable",
    configuredLabel: "Configured",
    modeLabel: "Supervised generic",
    reasonLabel: "Proc descriptor unavailable",
    runningLabel: "3",
    stoppingLabel: "1"
  });

  const unknown = executionPresentation({ configured: null, laneAvailable: true });
  assert.equal(unknown.laneState, "unknown");
  assert.equal(unknown.runningLabel, "—");
  assert.equal(unknown.modeLabel, "Unknown");
});

test("execution run presentation uses lifecycle metadata only", () => {
  assert.deepEqual(executionRunPresentation({
    runId: "run_1111111111111111",
    manifestId: "manifest_2222222222222222",
    engagementId: "engagement_3333333333333333",
    status: "failed",
    createdAt: "2026-10-13T12:00:00.000Z",
    startedAt: "2026-10-13T12:00:01.000Z",
    finishedAt: "2026-10-13T12:00:02.000Z",
    terminationReason: "duration-limit",
    exitCode: 9,
    target: "TARGET_CANARY",
    argv: ["ARGV_CANARY"],
    output: "OUTPUT_CANARY"
  }), {
    runId: "run_1111111111111111",
    manifestId: "manifest_2222222222222222",
    engagementId: "engagement_3333333333333333",
    status: "failed",
    observedAt: "2026-10-13T12:00:02.000Z",
    result: "duration-limit"
  });
});
