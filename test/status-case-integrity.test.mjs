import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { ensureRuntime, runtimePaths } from "../src/lib/paths.mjs";
import { buildStatus } from "../src/lib/status.mjs";
import { statusSummary } from "../src/lib/summaries.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const observedAt = "2026-10-15T12:00:00.000Z";

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
}

function canonicalText(value) {
  return `${JSON.stringify(stableValue(value), null, 2)}\n`;
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-status-case-integrity-"));
  const base = runtimePaths({ home: path.join(root, "home"), repo });
  ensureRuntime(base);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, base };
}

function seedStaleCase(base, id, marker) {
  const scoped = runtimePaths({ home: base.home, repo: base.repo, caseId: id });
  const record = {
    $schema: "https://gate.local/schemas/case.schema.json",
    apiVersion: "gate.dev/case/v1",
    kind: "Case",
    metadata: { id, displayName: `Status ${id}`, createdAt: observedAt },
    program: { id: "missing-program", profileSha256: "a".repeat(64) },
    project: null,
    isolation: {
      stateNamespace: "isolated-directory",
      processBoundary: "shared-user",
      networkBoundary: "adapter-dependent"
    },
    scopeSha256: "0".repeat(64)
  };
  const envelope = structuredClone(record);
  delete envelope.scopeSha256;
  record.scopeSha256 = crypto.createHash("sha256").update(canonicalText(envelope), "utf8").digest("hex");

  fs.mkdirSync(scoped.stateHome, { recursive: true, mode: 0o700 });
  fs.writeFileSync(scoped.caseScope, canonicalText(record), { mode: 0o600 });
  fs.writeFileSync(
    scoped.caseBinding,
    canonicalText({ caseId: id, scopeSha256: record.scopeSha256 }),
    { mode: 0o600 }
  );
  ensureRuntime(scoped);
  fs.writeFileSync(
    path.join(scoped.engagements, `${marker}.json`),
    `${JSON.stringify({ marker })}\n`,
    { mode: 0o600 }
  );
  return scoped;
}

test("selected status opens the immutable case and keeps stale state observable", async (t) => {
  const { base } = fixture(t);
  const scoped = seedStaleCase(base, "stale-case", "CASE_ONLY_CANARY");

  const selected = await buildStatus({ paths: scoped, now: observedAt });
  assert.deepEqual(selected.selection, {
    mode: "case",
    caseId: "stale-case",
    bindingHealth: { status: "stale", programCurrent: false, projectCurrent: true }
  });
  assert.deepEqual(statusSummary(selected).selection, {
    mode: "case",
    caseId: "stale-case",
    bindingHealth: { status: "stale", programCurrent: false, projectCurrent: true }
  });
  assert.equal(selected.selectedCaseId, "stale-case");
  assert.deepEqual(selected.engagements, [{ marker: "CASE_ONLY_CANARY" }]);
  assert.deepEqual(selected.projects, []);
  assert.deepEqual(selected.upstreams, []);
  assert.equal(selected.toolRuntimes, null);
  assert.deepEqual(selected.cases, []);
  assert.equal(fs.existsSync(path.join(base.engagements, "CASE_ONLY_CANARY.json")), false);

  const selectedFromCoordinates = await buildStatus({
    home: base.home,
    repo: base.repo,
    caseId: "stale-case",
    now: observedAt
  });
  assert.equal(selectedFromCoordinates.selectedCaseId, "stale-case");
  assert.deepEqual(selectedFromCoordinates.engagements, [{ marker: "CASE_ONLY_CANARY" }]);

  const aggregate = await buildStatus({ paths: base, now: observedAt });
  assert.deepEqual(aggregate.selection, { mode: "aggregate", caseId: null });
  const item = aggregate.cases.find((candidate) => candidate.id === "stale-case");
  assert.equal(item.status, "stale");
  assert.equal(item.binding.program.current, false);
  assert.deepEqual(item.runtimeHealth, { status: "available", reason: null });
  assert.deepEqual(item.runtime.engagements, []);
  assert.deepEqual(item.runtime.engagementScan, {
    availability: "not-loaded",
    reason: "aggregate-case-detail-elided",
    recordsRead: 0,
    complete: false
  });

  const unassigned = await buildStatus({ paths: base, selectionMode: "unassigned", now: observedAt });
  assert.deepEqual(unassigned.selection, { mode: "unassigned", caseId: null });
  assert.deepEqual(unassigned.cases, []);
  assert.equal(unassigned.caseScan.attempted, false);
});

test("aggregate case status never opens or retains private engagement records", async (t) => {
  const { base } = fixture(t);
  const scoped = seedStaleCase(base, "opaque-case", "ordinary-record");
  const poison = path.join(scoped.engagements, "000-poison.json");
  const canary = "PRIVATE_ENGAGEMENT_BODY_MUST_NOT_BE_READ";
  fs.writeFileSync(poison, `${canary}${"x".repeat(2 * 1024 * 1024)}\n`, { mode: 0o600 });

  const originalOpen = fs.openSync;
  const originalRead = fs.readSync;
  const originalClose = fs.closeSync;
  const poisonDescriptors = new Set();
  let poisonRead = false;
  fs.openSync = function guardedOpen(file, ...args) {
    const descriptor = originalOpen.call(this, file, ...args);
    if (path.resolve(String(file)) === path.resolve(poison)) poisonDescriptors.add(descriptor);
    return descriptor;
  };
  fs.readSync = function guardedRead(descriptor, ...args) {
    if (poisonDescriptors.has(descriptor)) poisonRead = true;
    return originalRead.call(this, descriptor, ...args);
  };
  fs.closeSync = function guardedClose(descriptor, ...args) {
    poisonDescriptors.delete(descriptor);
    return originalClose.call(this, descriptor, ...args);
  };
  let aggregate;
  try {
    aggregate = await buildStatus({ paths: base, now: observedAt });
  } finally {
    fs.openSync = originalOpen;
    fs.readSync = originalRead;
    fs.closeSync = originalClose;
  }

  assert.equal(poisonRead, false);
  const item = aggregate.cases.find((candidate) => candidate.id === "opaque-case");
  assert.deepEqual(item.runtime.engagements, []);
  assert.equal(item.runtime.engagementScan.recordsRead, 0);
  assert.equal(JSON.stringify(aggregate).includes(canary), false);
});

test("status rejects redirected, relabelled, and phantom case path tables", async (t) => {
  const { base } = fixture(t);
  const scoped = seedStaleCase(base, "bound-case", "BOUND_CASE_CANARY");

  await assert.rejects(
    buildStatus({ paths: { ...scoped, events: base.events }, now: observedAt }),
    /status runtime path does not match its derived location: events/u
  );
  await assert.rejects(
    buildStatus({ paths: { ...scoped, caseId: "other-case" }, now: observedAt }),
    /case stateHome must match|status runtime path does not match/u
  );

  const phantom = runtimePaths({ home: base.home, repo: base.repo, caseId: "phantom-case" });
  await assert.rejects(
    buildStatus({ paths: phantom, now: observedAt }),
    /private case phantom-case does not exist|ENOENT/u
  );
  assert.equal(fs.existsSync(phantom.caseRoot), false);
});
