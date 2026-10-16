import assert from "node:assert/strict";
import test from "node:test";

import {
  activateLiveDetailShortcut,
  captureCaseRenderContinuity,
  captureLiveDetailContinuity,
  caseFleetRowPresentation,
  casePresentation,
  caseScanPresentation,
  cycleCaseSelection,
  engagementScanPresentation,
  executionPresentation,
  executionRunPresentation,
  fleetSummaryPresentation,
  observerShortcutAllowed,
  offlineAnalysisPresentation,
  offlineAnalysisRunPresentation,
  profileSetupPresentation,
  profileSetupScanPresentation,
  reconcileRefreshResults,
  revealDisclosureAndFocus,
  restoreCaseRenderContinuity,
  restoreLiveDetailContinuity,
  toolRuntimeItemPresentation,
  toolRuntimePresentation,
  usageScopeLabel
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

function statusEnvelope(overrides = {}) {
  return {
    apiVersion: "gate.observer/v1",
    at,
    state: "running",
    counts: {},
    telemetry: {},
    cases: [],
    profileSetups: [],
    profileSetupScan: {},
    ...overrides
  };
}

test("partial endpoint failures preserve the last valid event and learning projections", () => {
  const current = currentState();
  const next = reconcileRefreshResults(current, {
    status: fulfilled(statusEnvelope()),
    events: rejected(),
    learnings: rejected()
  }, 200);

  assert.strictEqual(next.events, current.events);
  assert.strictEqual(next.learnings, current.learnings);
  assert.deepEqual([...next.failedEndpoints], ["/api/events", "/api/learnings"]);
  assert.equal(next.lastNetworkSuccess, 200);
});

test("malformed successful status envelopes preserve the last valid status and report endpoint failure", () => {
  const current = currentState();
  for (const malformed of [
    { at, state: "running", counts: {}, telemetry: {}, cases: [] },
    statusEnvelope({ apiVersion: "wrong/v1" }),
    statusEnvelope({ at: "not-a-time" }),
    statusEnvelope({ counts: null }),
    statusEnvelope({ cases: null }),
    statusEnvelope({ profileSetups: null }),
    statusEnvelope({ profileSetupScan: null })
  ]) {
    const next = reconcileRefreshResults(current, {
      status: fulfilled(malformed),
      events: rejected(),
      learnings: rejected()
    }, 250);
    assert.strictEqual(next.status, current.status);
    assert.equal(next.failedEndpoints.has("/api/status"), true);
    assert.equal(next.lastNetworkSuccess, current.lastNetworkSuccess);
  }
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

test("managed runtime presentation distinguishes aggregate health and per-tool readiness", () => {
  assert.deepEqual(toolRuntimePresentation({
    ok: true,
    verificationMode: "current-bytes-and-install-smoke-evidence",
    platform: "linux-x64",
    catalog: 126,
    locked: 4,
    installed: 3,
    verified: 2,
    executable: 1,
    unresolved: 125
  }), {
    healthState: "partial",
    healthLabel: "125 unresolved",
    modeLabel: "Current bytes and install smoke evidence",
    platformLabel: "linux-x64",
    catalogLabel: "126",
    lockedLabel: "4",
    installedLabel: "3",
    verifiedLabel: "2",
    executableLabel: "1",
    unresolvedLabel: "125"
  });
  assert.equal(toolRuntimePresentation({ ok: false }).healthLabel, "Lock invalid");
  assert.equal(toolRuntimePresentation({ ok: true, unresolved: 0 }).healthLabel, "Ready");
  assert.deepEqual(
    {
      currentBytesLabel: toolRuntimePresentation({ currentBytesChecked: false, executableHashReads: 0 }).currentBytesLabel,
      hashReadsLabel: toolRuntimePresentation({ currentBytesChecked: false, executableHashReads: 0 }).hashReadsLabel
    },
    { currentBytesLabel: "Receipt only", hashReadsLabel: "0" }
  );
  assert.deepEqual(toolRuntimeItemPresentation({
    id: "nuclei",
    name: "Nuclei",
    state: "verified-install-evidence",
    locked: true,
    installed: true,
    verified: true,
    executable: true,
    reasons: []
  }), {
    id: "nuclei",
    name: "Nuclei",
    state: "verified-install-evidence",
    stateLabel: "Verified install evidence",
    tone: "ready",
    flags: ["locked yes", "installed yes", "verified yes", "executable yes"],
    reasons: []
  });
  const receipt = toolRuntimeItemPresentation({
    id: "nuclei",
    state: "receipt-only",
    verificationEvidence: {
      kind: "installation-receipt",
      lastVerifiedAt: "2026-10-14T16:00:00.000Z",
      ageSeconds: 1,
      currentBytesChecked: false
    }
  }, Date.parse("2026-10-14T16:00:12.000Z"));
  assert.match(receipt.evidenceLabel, /Last verified/);
  assert.match(receipt.evidenceLabel, /12s ago/);
  assert.match(receipt.evidenceLabel, /current bytes not checked/);
  assert.equal(toolRuntimeItemPresentation({ state: "invalid-receipt" }).tone, "invalid");
});

test("case terminal presentation greets once and exposes lifecycle metadata without raw operation data", () => {
  const display = casePresentation({
    id: `case_${"1".repeat(16)}`,
    displayName: "Primary assessment",
    status: "ready",
    binding: {
      program: { id: `program_${"2".repeat(16)}`, current: true },
      project: { id: `project_${"3".repeat(16)}`, current: true }
    },
    isolation: {
      stateNamespace: "isolated-directory",
      processBoundary: "shared-user",
      networkBoundary: "adapter-dependent"
    },
    runtimeHealth: { status: "available", reason: null },
    state: "running",
    counts: { running: 1, queued: 0, waiting: 0, blocked: 0, failed: 0, succeeded: 0 },
    telemetry: { state: "live", lastActivityAt: at },
    usage: { availability: "exact", totalTokens: 2048 },
    execution: {
      queuedCount: 0,
      runningCount: 1,
      stoppingCount: 0,
      recent: [{
        runId: `run_${"4".repeat(16)}`,
        manifestId: `manifest_${"5".repeat(16)}`,
        engagementId: `engagement_${"6".repeat(16)}`,
        status: "running",
        createdAt: at,
        startedAt: at,
        finishedAt: null,
        terminationReason: null,
        command: "RUN_COMMAND_CANARY",
        argv: ["RUN_ARGV_CANARY"],
        output: "RUN_OUTPUT_CANARY",
        target: "RUN_TARGET_CANARY"
      }]
    },
    offlineAnalysis: { counts: { queued: 0, running: 0 } },
    engagementScan: {
      availability: "loaded",
      scanned: 3,
      discoveredAtLeast: 3,
      omittedAtLeast: 0,
      invalid: 1,
      complete: false,
      truncated: false
    },
    workflows: {
      instances: [{
        instanceId: `workflow_${"7".repeat(16)}`,
        activePhase: { id: "active-testing", toolId: "httpx", target: "PHASE_TARGET_CANARY" }
      }]
    },
    activity: [{
      at,
      kind: "tool.started",
      status: "running",
      action: { toolName: "httpx", command: "EVENT_COMMAND_CANARY" },
      summary: "EVENT_SUMMARY_CANARY"
    }],
    command: "CASE_COMMAND_CANARY",
    output: "CASE_OUTPUT_CANARY",
    target: "CASE_TARGET_CANARY"
  }, { displayName: "Giovanni" });

  assert.equal(display.greeting, "GATE // Welcome, Giovanni.");
  assert.equal(display.indeterminate, true);
  assert.equal(display.active, true);
  assert.equal(display.lines.some((line) => line.label === "phase" && /active-testing · tool httpx/.test(line.value)), true);
  assert.equal(display.lines.some((line) => line.label === "run" && /running/.test(line.value)), true);
  assert.equal(display.lines.some((line) => line.label === "execution" && /1 running/.test(line.value)), true);
  assert.equal(display.lines.some((line) => line.label === "analysis" && /0 running/.test(line.value)), true);
  assert.equal(display.lines.some((line) => line.label === "engagements" && /1 invalid/.test(line.value)), true);
  assert.equal(display.lines.some((line) => line.label === "isolation" && /shared user/.test(line.value)), true);
  assert.equal(display.lines.some((line) => line.label === "tokens" && /exact · 2.048 tokens observed/.test(line.value)), true);
  assert.deepEqual(
    display.lines.find((line) => line.label === "telemetry"),
    { label: "telemetry", value: "live", tone: "active", observedAt: at }
  );
  assert.equal(display.lines.find((line) => line.label === "run").observedAt, at);
  assert.equal(display.lines.find((line) => line.label === "activity").observedAt, at);
  const rendered = JSON.stringify(display);
  assert.equal(rendered.split("GATE // Welcome, Giovanni.").length - 1, 1);
  for (const canary of [
    "RUN_COMMAND_CANARY", "RUN_ARGV_CANARY", "RUN_OUTPUT_CANARY", "RUN_TARGET_CANARY", "PHASE_TARGET_CANARY",
    "EVENT_COMMAND_CANARY", "EVENT_SUMMARY_CANARY", "CASE_COMMAND_CANARY", "CASE_OUTPUT_CANARY", "CASE_TARGET_CANARY"
  ]) assert.equal(rendered.includes(canary), false, `terminal presentation leaked ${canary}`);
});

test("case terminal animation is indeterminate only for fresh active lifecycle state", () => {
  const base = {
    id: `case_${"a".repeat(16)}`,
    displayName: "Case A",
    status: "ready",
    binding: { program: { id: `program_${"b".repeat(16)}`, current: true }, project: null },
    isolation: {
      stateNamespace: "isolated-directory",
      processBoundary: "shared-user",
      networkBoundary: "adapter-dependent"
    },
    runtimeHealth: { status: "available", reason: null },
    counts: {},
    usage: { availability: "unavailable" },
    execution: { queuedCount: 0, runningCount: 0, stoppingCount: 0, recent: [] },
    offlineAnalysis: { counts: { queued: 0, running: 0 } },
    workflows: { instances: [] },
    activity: []
  };
  assert.equal(casePresentation({ ...base, state: "queued", telemetry: { state: "live" } }).indeterminate, true);
  assert.equal(casePresentation({ ...base, state: "succeeded", telemetry: { state: "live" } }).indeterminate, false);
  const staleActive = casePresentation({ ...base, state: "running", status: "stale", telemetry: { state: "live" } });
  assert.equal(staleActive.active, true);
  assert.equal(staleActive.indeterminate, false);
  assert.equal(casePresentation({
    ...base,
    state: "idle",
    telemetry: { state: "live" },
    workflows: { instances: [{ activePhase: { id: "mapping", toolId: null } }] }
  }).indeterminate, true);
  assert.equal(casePresentation({
    ...base,
    state: "idle",
    telemetry: { state: "live" },
    execution: { queuedCount: 0, runningCount: 1, stoppingCount: 0, recent: [] }
  }).indeterminate, true, "exact execution counts keep older active runs visible");
  assert.equal(casePresentation({
    ...base,
    state: "idle",
    telemetry: { state: "live" },
    offlineAnalysis: { counts: { queued: 0, running: 1 } }
  }).indeterminate, true, "offline analysis counts keep active local work visible");
  const staleTelemetry = casePresentation({
    ...base,
    state: "idle",
    telemetry: { state: "stale" },
    execution: { queuedCount: 0, runningCount: 1, stoppingCount: 0, recent: [] }
  });
  assert.equal(staleTelemetry.active, true);
  assert.equal(staleTelemetry.indeterminate, false, "stale telemetry must stop progress animation");
});

test("compact campaign rows expose current operational metadata without inferring findings", () => {
  const display = caseFleetRowPresentation({
    id: `case_${"a".repeat(16)}`,
    displayName: "Parallel assessment",
    status: "ready",
    runtimeHealth: { status: "available", reason: null },
    state: "running",
    counts: { running: 1, queued: 0, waiting: 0, blocked: 0, failed: 0 },
    telemetry: { state: "live", lastActivityAt: at },
    usage: { availability: "exact", totalTokens: 2048 },
    workflows: {
      counts: { active: 1, degraded: 0 },
      instances: [{ activePhase: { id: "active-testing", toolId: "httpx", target: "PHASE_TARGET_CANARY" } }]
    },
    execution: { queuedCount: 0, runningCount: 1, stoppingCount: 0, argv: ["ARGV_CANARY"] },
    offlineAnalysis: { counts: { queued: 0, running: 1 } },
    engagementScan: { availability: "loaded", invalid: 1, complete: false, truncated: false },
    learningCount: 4,
    findings: [{ title: "FINDING_CANARY" }],
    command: "COMMAND_CANARY",
    target: "TARGET_CANARY"
  }, Date.parse(at) + 1_000);

  assert.equal(display.phaseLabel, "Active testing");
  assert.equal(display.toolLabel, "httpx");
  assert.equal(display.lastSignalLabel, "Live · just now");
  assert.equal(display.activeWorkLabel, "1 phase · 1 run · 1 analysis");
  assert.equal(display.attentionLabel, "1 invalid engagement · Engagement scan partial");
  assert.equal(display.attentionTone, "critical");
  assert.equal(display.learningCount, 4);
  assert.equal(display.findingsLabel, "Unavailable");
  assert.match(display.tokensLabel, /exact/u);
  const rendered = JSON.stringify(display);
  for (const canary of ["PHASE_TARGET_CANARY", "ARGV_CANARY", "FINDING_CANARY", "COMMAND_CANARY", "TARGET_CANARY"]) {
    assert.equal(rendered.includes(canary), false, `fleet row leaked ${canary}`);
  }
});

test("compact campaign rows distinguish unavailable runtime state from observed idle work", () => {
  const unavailable = caseFleetRowPresentation({
    status: "invalid",
    state: "blocked",
    runtimeHealth: { status: "unavailable", reason: "invalid-case" },
    telemetry: { state: "unknown", lastActivityAt: null },
    usage: { availability: "unavailable" },
    workflows: { counts: {}, instances: [] },
    execution: {},
    offlineAnalysis: { counts: {} },
    learningCount: 0
  }, Date.parse(at));
  assert.equal(unavailable.phaseLabel, "Unavailable");
  assert.equal(unavailable.activeWorkLabel, "Unavailable");
  assert.match(unavailable.attentionLabel, /Invalid case/u);
  assert.match(unavailable.attentionLabel, /Runtime unavailable/u);
  assert.equal(unavailable.tokensLabel, "Unavailable");

  const idle = caseFleetRowPresentation({
    status: "ready",
    state: "idle",
    runtimeHealth: { status: "available", reason: null },
    telemetry: { state: "live", lastActivityAt: at },
    usage: { availability: "estimated", totalTokens: null },
    workflows: { counts: { active: 0, degraded: 0 }, instances: [] },
    execution: { queuedCount: 0, runningCount: 0, stoppingCount: 0 },
    offlineAnalysis: { counts: { queued: 0, running: 0 } },
    engagementScan: { availability: "not-loaded" },
    learningCount: 0
  }, Date.parse(at));
  assert.equal(idle.activeWorkLabel, "None observed");
  assert.equal(idle.attentionLabel, "None observed");
  assert.equal(idle.findingsLabel, "Unavailable");
});

test("offline telemetry is critical while stale and unknown telemetry require attention", () => {
  const base = {
    id: `case_${"e".repeat(16)}`,
    displayName: "Telemetry truth",
    status: "ready",
    runtimeHealth: { status: "available", reason: null },
    state: "idle",
    counts: { queued: 0, running: 0, waiting: 0, blocked: 0, failed: 0 },
    usage: { availability: "unavailable" },
    workflows: { counts: { active: 0, degraded: 0 }, instances: [] },
    execution: { queuedCount: 0, runningCount: 0, stoppingCount: 0 },
    offlineAnalysis: { counts: { queued: 0, running: 0 } },
    engagementScan: { availability: "not-loaded" },
    learningCount: 0
  };
  const offline = caseFleetRowPresentation({ ...base, telemetry: { state: "offline", lastActivityAt: at } });
  const stale = caseFleetRowPresentation({ ...base, telemetry: { state: "stale", lastActivityAt: at } });
  const unknown = caseFleetRowPresentation({ ...base, telemetry: { state: "unknown", lastActivityAt: null } });
  assert.equal(offline.attentionLabel, "Telemetry offline");
  assert.equal(offline.attentionTone, "critical");
  assert.equal(stale.attentionLabel, "Telemetry stale");
  assert.equal(stale.attentionTone, "warning");
  assert.equal(unknown.attentionLabel, "Telemetry unknown");
  assert.equal(unknown.attentionTone, "warning");

  const exactScan = { availability: "available", discovered: 1, scanned: 1, complete: true, truncated: false, omitted: 0, invalid: 0 };
  const fleet = fleetSummaryPresentation({
    observedAt: at,
    cases: [{ ...base, telemetry: { state: "offline", lastActivityAt: at } }],
    profileSetups: [],
    caseScan: exactScan,
    profileSetupScan: { ...exactScan, discovered: 0, scanned: 0 }
  });
  assert.equal(fleet.availability, "exact");
  assert.equal(fleet.attentionLabel, "1");
});

test("fleet summary cards distinguish unavailable, lower-bound, and exact coverage", () => {
  const initial = fleetSummaryPresentation({});
  assert.equal(initial.availability, "unavailable");
  assert.equal(initial.activeLabel, "—");
  assert.equal(initial.waitingLabel, "—");
  assert.equal(initial.attentionLabel, "—");
  assert.equal(
    fleetSummaryPresentation({ observedAt: at, caseScan: null, profileSetupScan: null }).availability,
    "lower-bound"
  );

  const visibleCase = {
    id: `case_${"f".repeat(16)}`,
    displayName: "Visible campaign",
    status: "ready",
    runtimeHealth: { status: "available", reason: null },
    state: "running",
    counts: { queued: 0, running: 1, waiting: 0, blocked: 0, failed: 0 },
    telemetry: { state: "live", lastActivityAt: at },
    usage: { availability: "unavailable" },
    workflows: { counts: { active: 0, degraded: 0 }, instances: [] },
    execution: { queuedCount: 0, runningCount: 0, stoppingCount: 0 },
    offlineAnalysis: { counts: { queued: 0, running: 0 } },
    engagementScan: { availability: "not-loaded" },
    learningCount: 0
  };
  const partial = fleetSummaryPresentation({
    observedAt: at,
    cases: [visibleCase],
    profileSetups: [],
    caseScan: { complete: false, truncated: true, omitted: 1, invalid: 1 },
    profileSetupScan: { discovered: 0, scanned: 0, complete: true, truncated: false, omitted: 0, invalid: 0 }
  });
  assert.equal(partial.availability, "lower-bound");
  assert.equal(partial.activeLabel, "1+");
  assert.equal(partial.waitingLabel, "0+");
  assert.equal(partial.attentionLabel, "0+");
  assert.match(partial.detail, /Lower bound/u);

  const unavailable = fleetSummaryPresentation({
    observedAt: at,
    cases: [visibleCase],
    profileSetups: [],
    caseScan: { availability: "unavailable", discovered: 1, scanned: 1, complete: true, truncated: false, omitted: 0, invalid: 0 },
    profileSetupScan: { availability: "available", discovered: 0, scanned: 0, complete: true, truncated: false, omitted: 0, invalid: 0 }
  });
  assert.equal(unavailable.availability, "lower-bound", "an unavailable scan cannot claim an exact visible subset");
  assert.equal(unavailable.activeLabel, "1+");

  const exactScan = { availability: "available", discovered: 1, scanned: 1, complete: true, truncated: false, omitted: 0, invalid: 0 };
  const exact = fleetSummaryPresentation({
    observedAt: at,
    cases: [visibleCase],
    profileSetups: [],
    caseScan: exactScan,
    profileSetupScan: { ...exactScan, discovered: 0, scanned: 0 }
  });
  assert.equal(exact.availability, "exact");
  assert.equal(exact.activeLabel, "1");
  assert.equal(exact.waitingLabel, "0");
  assert.equal(exact.attentionLabel, "0");
});

test("private profile setup rows show guided progress without inventing a target identity", () => {
  const display = profileSetupPresentation({
    id: `program_${"c".repeat(16)}`,
    displayName: null,
    stage: "questionnaire",
    readiness: "not-ready",
    progress: { answered: 41, total: 66 },
    blockerCount: 2,
    nextSection: "scope-assets",
    recommendationMode: "mixed",
    updatedAt: at,
    freshness: "fresh",
    targetName: "PRIVATE_TARGET_CANARY",
    answers: "PRIVATE_ANSWER_CANARY"
  }, Date.parse(at) + 1_000);

  assert.equal(display.displayName, "Private profile · cccccc");
  assert.equal(display.state, "waiting");
  assert.equal(display.phaseLabel, "Scope assets");
  assert.equal(display.toolLabel, "Mixed recommendations");
  assert.equal(display.activeWorkLabel, "41 / 66 answered");
  assert.equal(display.attentionLabel, "2 blockers");
  assert.equal(display.tokensLabel, "Unavailable");
  assert.equal(display.findingsLabel, "Unavailable");
  assert.equal(JSON.stringify(display).includes("PRIVATE_TARGET_CANARY"), false);
  assert.equal(JSON.stringify(display).includes("PRIVATE_ANSWER_CANARY"), false);

  assert.equal(
    profileSetupScanPresentation({
      discovered: 5,
      scanned: 4,
      omitted: 1,
      invalid: 1,
      visible: 2,
      representedByCases: 2,
      discoveredAtLeast: true,
      omittedAtLeast: true,
      complete: false,
      truncated: true
    }, 2),
    "2 setups visible / 5+ discovered · 2 represented by cases · 1+ omitted · 1 invalid · partial"
  );
  assert.equal(
    profileSetupScanPresentation({ availability: "unavailable", visible: 1, complete: false, truncated: true }, 1),
    "1 cached setup visible · scan unavailable · partial"
  );
});

test("invalid case tombstones render unavailable binding and isolation metadata", () => {
  const display = casePresentation({
    id: `case_${"d".repeat(16)}`,
    displayName: "Invalid case",
    status: "invalid",
    binding: null,
    isolation: null,
    runtimeHealth: { status: "unavailable", reason: "invalid-case" },
    state: "blocked",
    counts: {},
    telemetry: { state: "unknown" },
    usage: { availability: "unavailable" },
    execution: { stoppingCount: 0, recent: [] },
    workflows: { instances: [] },
    activity: []
  }, { displayName: "Giovanni" });

  assert.equal(display.active, false);
  assert.equal(display.indeterminate, false);
  assert.equal(display.lines.find((line) => line.label === "program").value, "unavailable");
  assert.equal(display.lines.find((line) => line.label === "project").value, "unavailable");
  assert.equal(display.lines.find((line) => line.label === "isolation").value, "unavailable");
});

test("engagement scan presentation keeps partial, invalid, and elided status visible", () => {
  assert.deepEqual(engagementScanPresentation({
    availability: "loaded",
    scanned: 64,
    discoveredAtLeast: 65,
    omittedAtLeast: 1,
    invalid: 2,
    complete: false,
    truncated: true
  }), {
    label: "64 scanned · 65+ discovered · 1+ omitted · 2 invalid · truncated",
    attention: true
  });
  assert.deepEqual(engagementScanPresentation({ availability: "not-loaded" }), {
    label: "details not loaded",
    attention: false
  });
});

test("case keyboard selection remains stable and wraps in both directions", () => {
  const cases = [
    { id: `case_${"1".repeat(16)}` },
    { id: `case_${"2".repeat(16)}` },
    { id: `case_${"3".repeat(16)}` }
  ];
  assert.equal(cycleCaseSelection(cases, cases[1].id, 0), cases[1].id);
  assert.equal(cycleCaseSelection(cases, cases[2].id, 1), cases[0].id);
  assert.equal(cycleCaseSelection(cases, cases[0].id, -1), cases[2].id);
  assert.equal(cycleCaseSelection(cases, "missing", 1), cases[0].id);
  assert.equal(cycleCaseSelection([], null, 1), null);
});

test("case render continuity restores focused cards and independent terminal scroll positions", () => {
  const focusedChild = {};
  const oldCards = [
    {
      dataset: { caseId: `case_${"1".repeat(16)}` },
      querySelector: () => ({ scrollTop: 91, scrollLeft: 4, scrollHeight: 291, clientHeight: 200 }),
      contains: (candidate) => candidate === focusedChild
    },
    {
      dataset: { caseId: `case_${"2".repeat(16)}` },
      querySelector: () => ({ scrollTop: 23, scrollLeft: 0, scrollHeight: 300, clientHeight: 200 }),
      contains: () => false
    }
  ];
  const snapshot = captureCaseRenderContinuity({ querySelectorAll: () => oldCards }, focusedChild);
  assert.equal(snapshot.focusedCaseId, oldCards[0].dataset.caseId);
  assert.deepEqual(snapshot.scrollPositions.get(oldCards[1].dataset.caseId), { top: 23, left: 0, atBottom: false });

  const restoredTerminals = [
    { scrollTop: 0, scrollLeft: 0, scrollHeight: 350, clientHeight: 200 },
    { scrollTop: 0, scrollLeft: 0, scrollHeight: 300, clientHeight: 200 }
  ];
  const focusCalls = [];
  const newCards = oldCards.map((card, index) => ({
    dataset: { ...card.dataset },
    querySelector: () => restoredTerminals[index],
    focus: (options) => focusCalls.push({ id: card.dataset.caseId, options })
  }));
  restoreCaseRenderContinuity({ querySelectorAll: () => newCards }, snapshot);
  assert.deepEqual(restoredTerminals, [
    { scrollTop: 150, scrollLeft: 4, scrollHeight: 350, clientHeight: 200 },
    { scrollTop: 23, scrollLeft: 0, scrollHeight: 300, clientHeight: 200 }
  ]);
  assert.deepEqual(focusCalls, [{ id: oldCards[0].dataset.caseId, options: { preventScroll: true } }]);

  const fallbackCalls = [];
  restoreCaseRenderContinuity({
    querySelectorAll: () => [{
      dataset: { caseId: oldCards[1].dataset.caseId },
      querySelector: () => null,
      focus: (options) => fallbackCalls.push(options)
    }]
  }, {
    focusedCaseId: `case_${"f".repeat(16)}`,
    fallbackFocusCaseId: oldCards[1].dataset.caseId,
    scrollPositions: new Map()
  });
  assert.deepEqual(fallbackCalls, [{ preventScroll: true }], "a removed focused case transfers focus to the selected fallback");
});

test("selected live activity preserves terminal scroll and focus across polling renders", () => {
  const childFocusCalls = [];
  const focusedChild = { focus: (options) => childFocusCalls.push(options) };
  const terminal = { scrollTop: 100, scrollLeft: 5, scrollHeight: 300, clientHeight: 200 };
  const detail = {
    dataset: { caseId: `case_${"1".repeat(16)}` },
    querySelector: () => terminal,
    contains: (candidate) => candidate === focusedChild
  };
  const snapshot = captureLiveDetailContinuity(detail, focusedChild);
  assert.deepEqual(snapshot, {
    caseId: detail.dataset.caseId,
    position: { top: 100, left: 5, atBottom: true },
    focusTarget: focusedChild,
    detailFocused: false
  });

  const restoredTerminal = { scrollTop: 0, scrollLeft: 0, scrollHeight: 420, clientHeight: 200 };
  const detailFocusCalls = [];
  const restored = {
    dataset: { ...detail.dataset },
    querySelector: () => restoredTerminal,
    contains: (candidate) => candidate === focusedChild,
    focus: (options) => detailFocusCalls.push(options)
  };
  restoreLiveDetailContinuity(restored, snapshot);
  assert.equal(restoredTerminal.scrollTop, 220);
  assert.equal(restoredTerminal.scrollLeft, 5);
  assert.deepEqual(childFocusCalls, [{ preventScroll: true }], "polling keeps focus on the persistent collapse control");
  assert.deepEqual(detailFocusCalls, [], "polling must not transfer descendant focus to the detail container");

  restoredTerminal.scrollTop = 17;
  restoreLiveDetailContinuity(restored, { ...snapshot, caseId: `case_${"2".repeat(16)}` });
  assert.equal(restoredTerminal.scrollTop, 17, "a different selected case must not receive another terminal's scroll position");
});

test("a zero-overflow terminal remains bottom-anchored when polling adds overflow", () => {
  const terminal = { scrollTop: 0, scrollLeft: 0, scrollHeight: 200, clientHeight: 200 };
  const detail = {
    dataset: { caseId: `case_${"3".repeat(16)}` },
    querySelector: () => terminal,
    contains: () => false
  };
  const snapshot = captureLiveDetailContinuity(detail, null);
  assert.equal(snapshot.position.atBottom, true);

  const grown = { scrollTop: 0, scrollLeft: 0, scrollHeight: 340, clientHeight: 200 };
  restoreLiveDetailContinuity({
    dataset: { ...detail.dataset },
    querySelector: () => grown,
    contains: () => false
  }, snapshot);
  assert.equal(grown.scrollTop, 140);
});

test("observer shortcuts ignore browser modifiers and an open shortcuts dialog", () => {
  assert.equal(observerShortcutAllowed({ key: "r" }), true);
  assert.equal(observerShortcutAllowed({ key: "r", ctrlKey: true }), false);
  assert.equal(observerShortcutAllowed({ key: "p", metaKey: true }), false);
  assert.equal(observerShortcutAllowed({ key: "[", altKey: true }), false);
  assert.equal(observerShortcutAllowed({ key: "r", defaultPrevented: true }), false);
  assert.equal(observerShortcutAllowed({ key: "r", isComposing: true }), false);
  assert.equal(observerShortcutAllowed({ key: "?", shiftKey: true }), true);
  assert.equal(observerShortcutAllowed({ key: "r" }, true), false);
});

test("shortcut 1 reopens and focuses the selected live detail", () => {
  const order = [];
  let collapsed = true;
  const detail = {
    closest: () => null,
    focus: (options) => order.push(["focus", options]),
    scrollIntoView: (options) => order.push(["scroll", options])
  };
  const activated = activateLiveDetailShortcut({
    selectedId: "case_selected",
    availableIds: ["case_selected"],
    setCollapsed(value) { collapsed = value; order.push(["collapse", value]); },
    render() { order.push(["render", collapsed]); },
    detail,
    announce() { order.push(["announce"]); }
  });
  assert.equal(activated, true);
  assert.equal(collapsed, false);
  assert.deepEqual(order, [
    ["collapse", false],
    ["render", false],
    ["focus", { preventScroll: true }],
    ["scroll", { block: "nearest", inline: "nearest" }],
    ["announce"]
  ]);
  assert.equal(activateLiveDetailShortcut({ selectedId: null, availableIds: [] }), false);
});

test("shortcut 2 opens System health and focuses and scrolls its summary", () => {
  const disclosure = { open: false };
  const calls = [];
  const summary = {
    closest: (selector) => selector === "details" ? disclosure : null,
    focus: (options) => calls.push(["focus", options]),
    scrollIntoView: (options) => calls.push(["scroll", options])
  };
  assert.equal(revealDisclosureAndFocus(summary), true);
  assert.equal(disclosure.open, true);
  assert.deepEqual(calls, [
    ["focus", { preventScroll: true }],
    ["scroll", { block: "nearest", inline: "nearest" }]
  ]);
});

test("token scope labels distinguish host sessions from base records", () => {
  assert.equal(usageScopeLabel({ source: "codex-session-jsonl" }), "Host-wide, unattributed sessions");
  assert.equal(usageScopeLabel({ source: "gate-token-log" }), "Base/unassigned token log");
  assert.equal(usageScopeLabel({}), "Host/base scope unavailable");
});

test("case scan presentation exposes invalid and partial scan state", () => {
  assert.equal(
    caseScanPresentation({
      discovered: 1024,
      scanned: 32,
      omitted: 992,
      invalid: 2,
      discoveredAtLeast: true,
      omittedAtLeast: true,
      complete: false
    }, 32),
    "32 scanned / 1024+ discovered · 992+ omitted · 2 invalid · partial"
  );
  assert.equal(caseScanPresentation({}, 2), "2 scanned / 2 discovered · partial");
});
