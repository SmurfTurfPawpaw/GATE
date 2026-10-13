import assert from "node:assert/strict";
import test from "node:test";

import { reconcileRefreshResults } from "./app.js";

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
