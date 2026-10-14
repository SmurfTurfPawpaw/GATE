import assert from "node:assert/strict";
import test from "node:test";

import {
  executionPresentation,
  executionRunPresentation,
  offlineAnalysisPresentation,
  offlineAnalysisRunPresentation,
  reconcileRefreshResults
} from "./app.js";

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

test("offline analysis presentation shows lane truth and opaque isolation state only", () => {
  assert.deepEqual(offlineAnalysisPresentation({
    configured: true,
    laneAvailable: true,
    mode: "bubblewrap-offline",
    reason: null,
    runningCount: 2,
    retention: {
      retainedBytes: 512,
      quotaBytes: 2 * 1024 * 1024 * 1024,
      retainedArtifacts: 1,
      quotaArtifacts: 64,
      pendingManifests: 1,
      expiredManifests: 2,
      overQuota: false,
      missingArtifacts: 0,
      invalidEntries: 0,
      orphanedArtifacts: 0,
      orphanedBytes: 0,
      purgePendingManifests: 0,
      unknownManifests: 0,
      retentionLockState: "absent",
      snapshotState: "consistent",
      pendingTransactions: 0,
      invalidTransactionRecords: 0,
      creatingManifests: 0,
      invalidCreationIntents: 0,
      invalidClaimRecords: 0,
      invalidPurgeRecords: 0,
      invalidRunRecords: 0,
      blockedManifests: 0,
      mutationBlocked: false
    }
  }), {
    laneState: "available",
    laneLabel: "Available",
    configuredLabel: "Configured",
    modeLabel: "Bubblewrap offline",
    reasonLabel: null,
    runningLabel: "2",
    retentionLabel: "512 B / 2.0 GiB retained · 1 / 64 artifacts · 1 pending · 2 expired",
    retentionState: "healthy",
    retentionStateLabel: "Healthy",
    retentionOverQuotaLabel: "No",
    retentionMissingLabel: "0",
    retentionInvalidLabel: "0",
    retentionOrphanedLabel: "0",
    retentionOrphanedBytesLabel: "0 B",
    retentionPurgePendingLabel: "0",
    retentionUnknownLabel: "0",
    controlState: "healthy",
    controlStateLabel: "Controls healthy",
    controlMutationLabel: "Available",
    controlLockLabel: "Absent",
    controlSnapshotLabel: "Consistent",
    controlPendingLabel: "0",
    controlInvalidTransactionsLabel: "0",
    controlCreatingLabel: "0",
    controlInvalidCreationsLabel: "0",
    controlInvalidClaimsLabel: "0",
    controlInvalidPurgesLabel: "0",
    controlInvalidRunsLabel: "0",
    controlBlockedManifestsLabel: "0"
  });

  assert.deepEqual(offlineAnalysisRunPresentation({
    runId: "run_aaaaaaaaaaaaaaaa",
    status: "succeeded",
    isolationVerified: true,
    manifestId: "manifest_PRIVATE_CANARY",
    projectId: "project_PRIVATE_CANARY",
    path: "/private/OFFLINE_PATH_CANARY",
    output: "OFFLINE_OUTPUT_CANARY"
  }), {
    runId: "run_aaaaaaaaaaaaaaaa",
    status: "succeeded",
    isolationState: "verified",
    isolationLabel: "Isolation verified"
  });
  assert.equal(offlineAnalysisRunPresentation({ isolationVerified: false }).isolationLabel, "Isolation not verified");
  assert.equal(offlineAnalysisRunPresentation({}).isolationLabel, "Isolation pending");
});

test("offline analysis presentation raises aggregate retention faults without copying private details", () => {
  const presentation = offlineAnalysisPresentation({
    retention: {
      overQuota: true,
      missingArtifacts: 2,
      invalidEntries: 3,
      orphanedArtifacts: 4,
      orphanedBytes: 1536,
      purgePendingManifests: 1,
      unknownManifests: 5,
      retentionLockState: "invalid",
      snapshotState: "indeterminate",
      pendingTransactions: 6,
      invalidTransactionRecords: 7,
      creatingManifests: 8,
      invalidCreationIntents: 9,
      invalidClaimRecords: 10,
      invalidPurgeRecords: 11,
      invalidRunRecords: 13,
      blockedManifests: 12,
      mutationBlocked: true,
      privatePath: "/private/RETENTION_PATH_CANARY",
      manifestDigest: "RETENTION_DIGEST_CANARY"
    }
  });

  assert.equal(presentation.retentionState, "attention");
  assert.equal(presentation.retentionStateLabel, "Needs attention");
  assert.equal(presentation.retentionOverQuotaLabel, "Yes");
  assert.equal(presentation.retentionMissingLabel, "2");
  assert.equal(presentation.retentionInvalidLabel, "3");
  assert.equal(presentation.retentionOrphanedLabel, "4");
  assert.equal(presentation.retentionOrphanedBytesLabel, "1.5 KiB");
  assert.equal(presentation.retentionPurgePendingLabel, "1");
  assert.equal(presentation.retentionUnknownLabel, "5");
  assert.equal(presentation.controlState, "blocked");
  assert.equal(presentation.controlStateLabel, "Mutation blocked");
  assert.equal(presentation.controlMutationLabel, "Blocked");
  assert.equal(presentation.controlLockLabel, "Invalid");
  assert.equal(presentation.controlSnapshotLabel, "Indeterminate");
  assert.equal(presentation.controlPendingLabel, "6");
  assert.equal(presentation.controlInvalidTransactionsLabel, "7");
  assert.equal(presentation.controlCreatingLabel, "8");
  assert.equal(presentation.controlInvalidCreationsLabel, "9");
  assert.equal(presentation.controlInvalidClaimsLabel, "10");
  assert.equal(presentation.controlInvalidPurgesLabel, "11");
  assert.equal(presentation.controlInvalidRunsLabel, "13");
  assert.equal(presentation.controlBlockedManifestsLabel, "12");
  assert.equal(JSON.stringify(presentation).includes("RETENTION_PATH_CANARY"), false);
  assert.equal(JSON.stringify(presentation).includes("RETENTION_DIGEST_CANARY"), false);

  const unknown = offlineAnalysisPresentation({ retention: {} });
  assert.equal(unknown.retentionState, "unknown");
  assert.equal(unknown.retentionMissingLabel, "—");
  assert.equal(unknown.controlState, "unknown");
  assert.equal(unknown.controlMutationLabel, "—");

  const invalidLockText = offlineAnalysisPresentation({
    retention: {
      retentionLockState: "/private/LOCK_OWNER_CANARY",
      snapshotState: "/private/SNAPSHOT_CANARY"
    }
  });
  assert.equal(invalidLockText.controlLockLabel, "—");
  assert.equal(invalidLockText.controlSnapshotLabel, "—");
  assert.equal(JSON.stringify(invalidLockText).includes("LOCK_OWNER_CANARY"), false);
  assert.equal(JSON.stringify(invalidLockText).includes("SNAPSHOT_CANARY"), false);
});

test("offline control presentation distinguishes active and manifest-scoped fault states", () => {
  const base = {
    mutationBlocked: false,
    retentionLockState: "absent",
    snapshotState: "consistent",
    pendingTransactions: 0,
    invalidTransactionRecords: 0,
    creatingManifests: 0,
    invalidCreationIntents: 0,
    invalidClaimRecords: 0,
    invalidPurgeRecords: 0,
    invalidRunRecords: 0,
    blockedManifests: 0
  };
  assert.equal(offlineAnalysisPresentation({
    retention: { ...base, retentionLockState: "active", pendingTransactions: 1 }
  }).controlState, "active");
  assert.equal(offlineAnalysisPresentation({
    retention: { ...base, invalidClaimRecords: 1, blockedManifests: 1 }
  }).controlState, "attention");
  assert.equal(offlineAnalysisPresentation({
    retention: { ...base, invalidRunRecords: 1, blockedManifests: 1 }
  }).controlState, "attention");
  assert.equal(offlineAnalysisPresentation({
    retention: { ...base, mutationBlocked: false, invalidTransactionRecords: 1 }
  }).controlState, "blocked");
  const indeterminate = offlineAnalysisPresentation({
    retention: { ...base, mutationBlocked: false, snapshotState: "indeterminate" }
  });
  assert.equal(indeterminate.controlState, "blocked");
  assert.equal(indeterminate.controlMutationLabel, "Blocked");
});
