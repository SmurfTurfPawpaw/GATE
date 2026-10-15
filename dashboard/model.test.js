import assert from "node:assert/strict";
import test from "node:test";
import {
  boundedPercent,
  deriveCounts,
  freshness,
  safeLearningText,
  sanitizeEventsPayload,
  sanitizeLearningsPayload,
  sanitizeStatusPayload
} from "./model.js";

test("event projection excludes prose, targets, evidence, arguments, results, and paths", () => {
  const [event] = sanitizeEventsPayload({
    events: [
      {
        id: "evt_20261013_abcdef12",
        at: "2026-10-13T12:00:00.000Z",
        runId: "run_20261013",
        taskId: "task_dashboard",
        component: "gate-observer",
        agent: "codex-worker",
        kind: "tool.completed",
        status: "succeeded",
        summary: "secret prompt text",
        prompt: "do not render me",
        path: "/private/operator/project",
        effect: {
          class: "local-read",
          targetRef: "private-target",
          engagementId: "eng_private",
          planDigest: "deadbeef"
        },
        evidenceRefs: ["private://raw-output"],
        action: {
          category: "test",
          toolName: "node-test",
          durationMs: 42,
          exitCode: 0,
          arguments: ["--secret"],
          result: "raw output",
          command: "cat /private/operator/project"
        }
      }
    ]
  });

  assert.deepEqual(event, {
    id: "evt_20261013_abcdef12",
    at: "2026-10-13T12:00:00.000Z",
    runId: "run_20261013",
    taskId: "task_dashboard",
    component: "gate-observer",
    agent: "codex-worker",
    kind: "tool.completed",
    status: "succeeded",
    effect: "local-read",
    action: {
      category: "test",
      toolName: "node-test",
      durationMs: 42,
      exitCode: 0
    }
  });
  const serialized = JSON.stringify(event);
  for (const forbidden of ["secret prompt", "/private", "private-target", "raw-output", "--secret", "raw output", "deadbeef"]) {
    assert.equal(serialized.includes(forbidden), false, `projection leaked ${forbidden}`);
  }
});

test("invalid identifiers cannot smuggle URLs or paths into event metadata", () => {
  const [event] = sanitizeEventsPayload([
    {
      id: "evt_20261013_abcdef12",
      at: "2026-10-13T12:00:00Z",
      kind: "tool.started",
      status: "running",
      agent: "https://example.invalid/private",
      component: "/home/operator/repo",
      taskId: "../../secret",
      action: { toolName: "C:\\private\\tool.exe", category: "network/probe" }
    }
  ]);

  assert.equal(event.agent, null);
  assert.equal(event.component, null);
  assert.equal(event.taskId, null);
  assert.equal(event.action.toolName, null);
  assert.equal(event.action.category, null);
});

test("publication effect classes remain visible in metadata-only views", () => {
  const effects = sanitizeEventsPayload([
    {
      id: "evt_publish_abcdef",
      at: "2026-10-13T12:00:00Z",
      kind: "publication.started",
      status: "running",
      effect: { class: "external-publish" }
    },
    {
      id: "evt_forge_abcdef12",
      at: "2026-10-13T11:59:59Z",
      kind: "publication.prepared",
      status: "succeeded",
      effect: { class: "forge-write" }
    }
  ]).map((event) => event.effect);

  assert.deepEqual(effects, ["external-publish", "forge-write"]);
});

test("learning projection allows reviewed prose and withholds common sensitive references", () => {
  const cause = "Failure in /home/operator/private/repo called https://internal.invalid and exposed sk-abcdefghijklmnopqrstuvwxyz";
  const change = "Read C:\\Users\\operator\\secret.txt with Authorization: Bearer-value";
  const text = `${safeLearningText(cause)} ${safeLearningText(change)}`;

  assert.match(text, /\[path withheld\]/);
  assert.match(text, /\[reference withheld\]/);
  assert.match(text, /\[secret withheld\]/);
  assert.doesNotMatch(text, /operator|internal\.invalid|abcdefghijklmnopqrstuvwxyz|Bearer-value/);

  const [learning] = sanitizeLearningsPayload({
    learnings: [
      {
        id: "lrn_20261013_abcdef12",
        at: "2026-10-13T12:00:00Z",
        scope: "repository",
        cause,
        change,
        status: "active",
        sensitivity: "private",
        evidence: ["private://raw-target"],
        configurationRefs: ["/private/config"]
      }
    ]
  });
  assert.equal(learning.sensitivity, "private");
  assert.equal("evidence" in learning, false);
  assert.equal("configurationRefs" in learning, false);
});

test("learning redaction consumes complete authorization and cookie header values", () => {
  const cases = [
    "Authorization: Digest username=\"synthetic-user\", realm=\"synthetic-realm\", response=\"synthetic-response\"",
    "Authorization: AWS4-HMAC-SHA256 Credential=SYNTHETIC/20261013/test/aws4_request, SignedHeaders=host;x-date, Signature=synthetic-signature",
    "Cookie: session=synthetic-session; preference=dark",
    "Set-Cookie: session=synthetic-session; Path=/; HttpOnly; SameSite=Strict"
  ];

  for (const header of cases) {
    assert.equal(safeLearningText(`Observed ${header}`), "Observed [secret withheld]");
  }
});

test("unavailable token data stays null even when a source emits zero placeholders", () => {
  const status = sanitizeStatusPayload({
    at: "2026-10-13T12:00:00Z",
    tokens: {
      availability: "unavailable",
      source: "codex-session-jsonl",
      totals: { input: 0, cached_input: 0, output: 0, reasoning: 0, total: 0 }
    }
  });

  assert.equal(status.usage.availability, "unavailable");
  assert.equal(status.usage.inputTokens, null);
  assert.equal(status.usage.cachedInputTokens, null);
  assert.equal(status.usage.outputTokens, null);
  assert.equal(status.usage.reasoningTokens, null);
  assert.equal(status.usage.totalTokens, null);
});

test("current buildStatus token shape is accepted without inferring context use", () => {
  const status = sanitizeStatusPayload({
    at: "2026-10-13T12:00:00Z",
    tokens: {
      availability: "exact",
      source: "codex-session-jsonl",
      totals: { input: 120, cached_input: 80, output: 40, reasoning: 10, total: 160 },
      sessions: [
        {
          id: "session_1",
          modified_at: "2026-10-13T11:59:59Z",
          context_window: 200000,
          model: "gpt-6"
        }
      ]
    }
  });

  assert.deepEqual(
    {
      availability: status.usage.availability,
      input: status.usage.inputTokens,
      cached: status.usage.cachedInputTokens,
      output: status.usage.outputTokens,
      reasoning: status.usage.reasoningTokens,
      total: status.usage.totalTokens,
      window: status.usage.context.windowTokens,
      used: status.usage.context.usedTokens,
      model: status.usage.model
    },
    {
      availability: "exact",
      input: 120,
      cached: 80,
      output: 40,
      reasoning: 10,
      total: 160,
      window: 200000,
      used: null,
      model: "gpt-6"
    }
  );
});

test("agent projection ignores task descriptions and derives stable status counts", () => {
  const status = sanitizeStatusPayload({
    at: "2026-10-13T12:00:00Z",
    agents: [
      {
        id: "agent_1",
        agent: "codex-worker",
        taskId: "task_1",
        status: "active",
        stage: "implementation",
        description: "full private user request",
        prompt: "private prompt",
        effect: "host-write"
      },
      { id: "agent_2", agent: "reviewer", taskId: "task_2", status: "blocked", stage: "review" }
    ]
  });

  assert.equal(JSON.stringify(status).includes("private"), false);
  assert.deepEqual(deriveCounts(status), {
    running: 1,
    waiting: 0,
    blocked: 1,
    failed: 0,
    queued: 0,
    succeeded: 0
  });
});

test("missing fleet counters remain unknown while explicit empty counters remain zero", () => {
  const unknown = deriveCounts(sanitizeStatusPayload({}));
  assert.equal(unknown.running, null);
  assert.equal(unknown.failed, null);

  const empty = deriveCounts(sanitizeStatusPayload({ counts: { running: 0, waiting: 0, blocked: 0, failed: 0 } }));
  assert.equal(empty.running, 0);
  assert.equal(empty.waiting, 0);
  assert.equal(empty.blocked, 0);
  assert.equal(empty.failed, 0);
});

test("execution projection keeps capability truth and drops unreviewed or sensitive fields", () => {
  const enforced = [
    "engagement-binding", "workflow-phase-binding", "workflow-reservation", "target-argument-binding",
    "declared-action-label-binding", "tool-allowlist", "exact-argv",
    "shell-disabled", "executable-descriptor-observed-sha256", "minimal-environment", "private-stdout-stderr",
    "one-shot-claim", "declared-bounds-within-receipt"
  ];
  const bestEffort = ["authorization-revocation-polling", "wall-duration", "process-group-termination"];
  const unavailable = [
    "egress-target-restriction", "request-count-measurement", "request-rate-measurement",
    "tool-concurrency-measurement", "token-measurement", "daemon-escape-containment", "filesystem-isolation",
    "credential-broker", "tool-artifact-inventory", "known-good-executable-provenance",
    "argv-action-semantics-validation", "supervisor-crash-containment", "immutable-executable-snapshot"
  ];
  const status = sanitizeStatusPayload({
    execution: {
      configured: true,
      laneAvailable: true,
      mode: "supervised-generic",
      reason: "SENSITIVE_REASON_CANARY",
      runningCount: 2,
      counts: { running: 2, stopping: 1 },
      enforced: [...enforced, "SENSITIVE_ENFORCEMENT_CANARY"],
      bestEffort: [...bestEffort, "/private/capability"],
      unavailable: [...unavailable, "target.invalid"],
      recent: [{
        runId: `run_${"1".repeat(16)}`,
        manifestId: `manifest_${"2".repeat(16)}`,
        engagementId: `engagement_${"3".repeat(16)}`,
        status: "cancelled",
        createdAt: "2026-10-13T12:00:00.000Z",
        startedAt: "2026-10-13T12:00:01.000Z",
        finishedAt: "2026-10-13T12:00:02.000Z",
        terminationReason: "process-group-remained",
        exitCode: null,
        signal: null,
        workflow: {
          instanceId: `workflow_${"4".repeat(16)}`,
          phaseId: "active-testing",
          phaseAttemptId: `phase-attempt_${"5".repeat(16)}`,
          reservationId: `reservation_${"6".repeat(16)}`
        },
        argv: ["--secret"],
        target: "TARGET_CANARY",
        output: "OUTPUT_CANARY"
      }],
      executablePath: "/private/tool",
      evidence: "EVIDENCE_CANARY"
    }
  });

  assert.equal(status.execution.configured, true);
  assert.equal(status.execution.laneAvailable, true);
  assert.equal(status.execution.mode, "supervised-generic");
  assert.equal(status.execution.reason, null);
  assert.equal(status.execution.runningCount, 2);
  assert.equal(status.execution.stoppingCount, 1);
  assert.deepEqual(status.execution.enforced, enforced);
  assert.deepEqual(status.execution.bestEffort, bestEffort);
  assert.deepEqual(status.execution.unavailable, unavailable);
  assert.deepEqual(status.execution.recent, [{
    runId: `run_${"1".repeat(16)}`,
    manifestId: `manifest_${"2".repeat(16)}`,
    engagementId: `engagement_${"3".repeat(16)}`,
    status: "cancelled",
    createdAt: "2026-10-13T12:00:00.000Z",
    startedAt: "2026-10-13T12:00:01.000Z",
    finishedAt: "2026-10-13T12:00:02.000Z",
    terminationReason: "process-group-remained",
    exitCode: null,
    signal: null,
    workflow: {
      instanceId: `workflow_${"4".repeat(16)}`,
      phaseId: "active-testing",
      phaseAttemptId: `phase-attempt_${"5".repeat(16)}`,
      reservationId: `reservation_${"6".repeat(16)}`
    }
  }]);
  const serialized = JSON.stringify(status);
  for (const forbidden of [
    "SENSITIVE", "TARGET_CANARY", "OUTPUT_CANARY", "EVIDENCE_CANARY", "/private/capability",
    "/private/tool", "target.invalid", "--secret"
  ]) assert.equal(serialized.includes(forbidden), false, `projection leaked ${forbidden}`);
});

test("execution lane availability cannot become true without explicit configuration", () => {
  const missing = sanitizeStatusPayload({ execution: { laneAvailable: true, mode: "supervised-generic" } });
  assert.equal(missing.execution.configured, null);
  assert.equal(missing.execution.laneAvailable, false);

  const unsupported = sanitizeStatusPayload({
    execution: {
      configured: true,
      laneAvailable: false,
      mode: "supervised-generic",
      reason: "unsupported-platform",
      runningCount: 0
    }
  });
  assert.equal(unsupported.execution.laneAvailable, false);
  assert.equal(unsupported.execution.reason, "unsupported-platform");
  assert.equal(unsupported.execution.runningCount, 0);
});

test("execution lane availability requires every workflow enforcement control", () => {
  const enforced = [
    "engagement-binding", "workflow-phase-binding", "workflow-reservation", "target-argument-binding",
    "declared-action-label-binding", "tool-allowlist", "exact-argv", "shell-disabled",
    "executable-descriptor-observed-sha256", "minimal-environment", "private-stdout-stderr",
    "one-shot-claim", "declared-bounds-within-receipt"
  ];
  const bestEffort = ["authorization-revocation-polling", "wall-duration", "process-group-termination"];
  const unavailable = [
    "egress-target-restriction", "request-count-measurement", "request-rate-measurement",
    "tool-concurrency-measurement", "token-measurement", "daemon-escape-containment", "filesystem-isolation",
    "credential-broker", "tool-artifact-inventory", "known-good-executable-provenance",
    "argv-action-semantics-validation", "supervisor-crash-containment", "immutable-executable-snapshot"
  ];

  for (const required of ["workflow-phase-binding", "workflow-reservation"]) {
    const status = sanitizeStatusPayload({
      execution: {
        configured: true,
        laneAvailable: true,
        mode: "supervised-generic",
        enforced: enforced.filter((value) => value !== required),
        bestEffort,
        unavailable
      }
    });

    assert.equal(status.execution.laneAvailable, false, `missing ${required} must fail closed`);
    assert.equal(status.execution.enforced.includes(required), false);
  }
});

test("workflow projection preserves bounded operational state and drops private fields", () => {
  const status = sanitizeStatusPayload({
    workflows: {
      counts: {
        total: 2,
        active: 1,
        open: 1,
        stopped: 0,
        "recovery-hold": 0,
        reported: 0,
        closed: 0,
        degraded: 1,
        unknown: 1
      },
      instances: [{
        instanceId: `workflow_${"a".repeat(16)}`,
        status: "open",
        activePhase: {
          id: "active-testing",
          lane: "active-testing",
          effectClass: "A2",
          toolId: "nuclei",
          envelopeControls: {
            wallTime: "enforced",
            requests: "measured-only",
            rate: "unavailable",
            parallel: "enforced",
            tokens: "measured-only",
            evidenceBytes: "enforced",
            spend: "unavailable"
          }
        },
        journalSequence: 8,
        reservations: 1,
        stops: 0,
        health: "bounded-replay-verified",
        privateBody: "PRIVATE_WORKFLOW_CANARY"
      }],
      scan: { discovered: 2, scanned: 1, omitted: 1, complete: false, truncated: true },
      privatePath: "/private/workflows"
    }
  });

  assert.deepEqual(status.workflows, {
    counts: {
      total: 2,
      active: 1,
      open: 1,
      stopped: 0,
      "recovery-hold": 0,
      reported: 0,
      closed: 0,
      degraded: 1,
      unknown: 1
    },
    instances: [{
      instanceId: `workflow_${"a".repeat(16)}`,
      status: "open",
      activePhase: {
        id: "active-testing",
        lane: "active-testing",
        effectClass: "A2",
        toolId: "nuclei",
        envelopeControls: {
          wallTime: "enforced",
          requests: "measured-only",
          rate: "unavailable",
          parallel: "enforced",
          tokens: "measured-only",
          evidenceBytes: "enforced",
          spend: "unavailable"
        }
      },
      journalSequence: 8,
      reservations: 1,
      stops: 0,
      health: "bounded-replay-verified"
    }],
    scan: { discovered: 2, scanned: 1, omitted: 1, complete: false, truncated: true }
  });
  assert.equal(JSON.stringify(status.workflows).includes("PRIVATE_WORKFLOW_CANARY"), false);
  assert.equal(JSON.stringify(status.workflows).includes("/private/workflows"), false);
});

test("offline analysis projection keeps only lane, counts, and opaque run isolation state", () => {
  const enforced = [
    "project-contract-binding", "typed-path-binding", "artifact-snapshot-sha256", "pinned-upstream-integrity",
    "fixed-adapter-argv", "bubblewrap-network-namespace", "read-only-runtime-mounts", "ephemeral-sandbox-writes",
    "shell-disabled", "cleared-environment", "private-bounded-evidence", "one-shot-claim", "wall-duration"
  ];
  const unavailable = [
    "cpu-limit", "memory-limit", "immutable-managed-upstream-snapshot",
    "same-uid-gate-home-tamper-resistance", "unix-socket-system-call-denial"
  ];
  const status = sanitizeStatusPayload({
    offlineAnalysis: {
      configured: true,
      laneAvailable: true,
      mode: "bubblewrap-offline",
      reason: "PRIVATE_REASON_CANARY",
      runningCount: 1,
      counts: { queued: 2, running: 1, succeeded: 3, failed: 4, cancelled: 5, blocked: 6, unknown: 7 },
      retention: {
        quotaBytes: 2_147_483_648,
        quotaArtifacts: 64,
        retainedBytes: 512,
        availableBytes: 2_147_483_136,
        overQuota: false,
        retainedArtifacts: 1,
        availableArtifacts: 63,
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
        mutationBlocked: false,
        pendingManifests: 1,
        expiredManifests: 0,
        activeManifests: 0,
        terminalManifests: 0,
        unknownManifests: 0,
        purgePendingManifests: 0,
        purgedManifests: 0,
        orphanedArtifacts: 0,
        orphanedBytes: 0,
        missingArtifacts: 0,
        invalidEntries: 0,
        privatePath: "/private/OFFLINE_RETENTION_CANARY"
      },
      enforced: [...enforced, "PRIVATE_CAPABILITY_CANARY"],
      unavailable: [...unavailable, "/private/capability"],
      recent: [{
        runId: `run_${"a".repeat(16)}`,
        status: "succeeded",
        isolationVerified: true,
        manifestId: `manifest_${"b".repeat(16)}`,
        projectId: `project_${"c".repeat(16)}`,
        path: "/private/OFFLINE_PATH_CANARY.exe",
        sha256: "OFFLINE_HASH_CANARY",
        evidence: "OFFLINE_EVIDENCE_CANARY",
        output: "OFFLINE_OUTPUT_CANARY",
        confirmation: "OFFLINE_CONFIRMATION_CANARY"
      }]
    }
  });

  assert.deepEqual(status.offlineAnalysis, {
    configured: true,
    laneAvailable: true,
    mode: "bubblewrap-offline",
    reason: null,
    runningCount: 1,
    counts: { queued: 2, running: 1, succeeded: 3, failed: 4, cancelled: 5, blocked: 6, unknown: 7 },
    retention: {
      quotaBytes: 2_147_483_648,
      quotaArtifacts: 64,
      retainedBytes: 512,
      availableBytes: 2_147_483_136,
      overQuota: false,
      retainedArtifacts: 1,
      availableArtifacts: 63,
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
      mutationBlocked: false,
      pendingManifests: 1,
      expiredManifests: 0,
      activeManifests: 0,
      terminalManifests: 0,
      unknownManifests: 0,
      purgePendingManifests: 0,
      purgedManifests: 0,
      orphanedArtifacts: 0,
      orphanedBytes: 0,
      missingArtifacts: 0,
      invalidEntries: 0
    },
    recent: [{ runId: `run_${"a".repeat(16)}`, status: "succeeded", isolationVerified: true }]
  });
  const serialized = JSON.stringify(status.offlineAnalysis);
  for (const forbidden of [
    "PRIVATE", "manifest_", "project_", "OFFLINE_PATH_CANARY", "OFFLINE_HASH_CANARY",
    "OFFLINE_EVIDENCE_CANARY", "OFFLINE_OUTPUT_CANARY", "OFFLINE_CONFIRMATION_CANARY",
    "OFFLINE_RETENTION_CANARY", "/private/capability"
  ]) assert.equal(serialized.includes(forbidden), false, `projection leaked ${forbidden}`);
});

test("offline analysis availability fails closed on incomplete capability metadata", () => {
  const projected = sanitizeStatusPayload({
    offlineAnalysis: {
      configured: true,
      laneAvailable: true,
      mode: "bubblewrap-offline",
      reason: "unavailable",
      counts: { running: 0 },
      enforced: ["shell-disabled"],
      unavailable: []
    }
  });
  assert.equal(projected.offlineAnalysis.laneAvailable, false);
  assert.equal(projected.offlineAnalysis.reason, "unavailable");
  assert.equal(projected.offlineAnalysis.runningCount, 0);

  const absent = sanitizeStatusPayload({});
  assert.equal(absent.offlineAnalysis.configured, null);
  assert.equal(absent.offlineAnalysis.laneAvailable, false);
  assert.equal(absent.offlineAnalysis.runningCount, null);
});

test("offline retention projection preserves aggregate fault signals and discards private details", () => {
  const status = sanitizeStatusPayload({
    offlineAnalysis: {
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
    }
  });

  assert.deepEqual({
    overQuota: status.offlineAnalysis.retention.overQuota,
    missingArtifacts: status.offlineAnalysis.retention.missingArtifacts,
    invalidEntries: status.offlineAnalysis.retention.invalidEntries,
    orphanedArtifacts: status.offlineAnalysis.retention.orphanedArtifacts,
    orphanedBytes: status.offlineAnalysis.retention.orphanedBytes,
    purgePendingManifests: status.offlineAnalysis.retention.purgePendingManifests,
    unknownManifests: status.offlineAnalysis.retention.unknownManifests,
    retentionLockState: status.offlineAnalysis.retention.retentionLockState,
    snapshotState: status.offlineAnalysis.retention.snapshotState,
    pendingTransactions: status.offlineAnalysis.retention.pendingTransactions,
    invalidTransactionRecords: status.offlineAnalysis.retention.invalidTransactionRecords,
    creatingManifests: status.offlineAnalysis.retention.creatingManifests,
    invalidCreationIntents: status.offlineAnalysis.retention.invalidCreationIntents,
    invalidClaimRecords: status.offlineAnalysis.retention.invalidClaimRecords,
    invalidPurgeRecords: status.offlineAnalysis.retention.invalidPurgeRecords,
    invalidRunRecords: status.offlineAnalysis.retention.invalidRunRecords,
    blockedManifests: status.offlineAnalysis.retention.blockedManifests,
    mutationBlocked: status.offlineAnalysis.retention.mutationBlocked
  }, {
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
    mutationBlocked: true
  });
  const serialized = JSON.stringify(status.offlineAnalysis.retention);
  assert.equal(serialized.includes("RETENTION_PATH_CANARY"), false);
  assert.equal(serialized.includes("RETENTION_DIGEST_CANARY"), false);

  const invalidLockText = sanitizeStatusPayload({
    offlineAnalysis: { retention: {
      retentionLockState: "/private/LOCK_OWNER_CANARY",
      snapshotState: "/private/SNAPSHOT_CANARY"
    } }
  });
  assert.equal(invalidLockText.offlineAnalysis.retention.retentionLockState, null);
  assert.equal(invalidLockText.offlineAnalysis.retention.snapshotState, null);
  assert.equal(JSON.stringify(invalidLockText).includes("LOCK_OWNER_CANARY"), false);
  assert.equal(JSON.stringify(invalidLockText).includes("SNAPSHOT_CANARY"), false);
});

test("managed runtime projection preserves safe readiness metadata and rejects private fields", () => {
  const status = sanitizeStatusPayload({
    toolRuntimes: {
      ok: true,
      verificationMode: "current-bytes-and-install-smoke-evidence",
      platform: "linux-x64",
      catalog: 2,
      locked: 2,
      installed: 1,
      verified: 1,
      executable: 1,
      unresolved: 1,
      unresolvedConstraints: [
        { reason: "managed-runtime-absent", count: 1, path: "/private/CONSTRAINT_CANARY" },
        { reason: "https://target.invalid/REASON_CANARY", count: 900 }
      ],
      tools: [{
        id: "searchsploit",
        name: "SearchSploit / ExploitDB",
        state: "verified-install-evidence",
        locked: true,
        installed: true,
        verified: true,
        executable: true,
        reasons: ["reviewed-data-dependencies-unavailable", "/private/REASON_PATH_CANARY"],
        path: "/private/TOOL_PATH_CANARY",
        sha256: "TOOL_HASH_CANARY",
        url: "https://target.invalid/TOOL_URL_CANARY"
      }]
    }
  });

  assert.deepEqual(status.toolRuntimes, {
    ok: true,
    verificationMode: "current-bytes-and-install-smoke-evidence",
    platform: "linux-x64",
    catalog: 2,
    locked: 2,
    installed: 1,
    verified: 1,
    executable: 1,
    unresolved: 1,
    unresolvedConstraints: [{ reason: "managed-runtime-absent", count: 1 }],
    tools: [{
      id: "searchsploit",
      name: "SearchSploit / ExploitDB",
      state: "verified-install-evidence",
      locked: true,
      installed: true,
      verified: true,
      executable: true,
      reasons: ["reviewed-data-dependencies-unavailable"]
    }]
  });
  const serialized = JSON.stringify(status.toolRuntimes);
  for (const canary of [
    "CONSTRAINT_CANARY", "target.invalid", "REASON_CANARY", "REASON_PATH_CANARY",
    "TOOL_PATH_CANARY", "TOOL_HASH_CANARY", "TOOL_URL_CANARY"
  ]) assert.equal(serialized.includes(canary), false, `dashboard model leaked ${canary}`);

  const fullCatalog = sanitizeStatusPayload({
    toolRuntimes: {
      tools: Array.from({ length: 126 }, (_, index) => ({
        id: `tool-${String(index).padStart(3, "0")}`,
        name: `Tool ${index}`,
        state: "unmanaged",
        locked: false,
        installed: false,
        verified: false,
        executable: false,
        reasons: ["reviewed-runtime-lock-unavailable"]
      }))
    }
  });
  assert.equal(fullCatalog.toolRuntimes.tools.length, 126);
});

test("managed runtime projection preserves only bounded verification-age evidence", () => {
  const status = sanitizeStatusPayload({
    toolRuntimes: {
      ok: true,
      verificationMode: "receipt-only",
      currentBytesChecked: false,
      executableHashReads: 0,
      tools: [{
        id: "nuclei",
        state: "receipt-only",
        verificationEvidence: {
          kind: "installation-receipt",
          lastVerifiedAt: "2026-10-14T16:00:00.000Z",
          ageSeconds: 12,
          current: false,
          currentBytesChecked: false,
          liveSmokeExecutedNow: false,
          receiptPath: "/private/RECEIPT_CANARY"
        }
      }]
    }
  });
  assert.equal(status.toolRuntimes.currentBytesChecked, false);
  assert.equal(status.toolRuntimes.executableHashReads, 0);
  assert.deepEqual(status.toolRuntimes.tools[0].verificationEvidence, {
    kind: "installation-receipt",
    lastVerifiedAt: "2026-10-14T16:00:00.000Z",
    ageSeconds: 12,
    current: false,
    currentBytesChecked: false,
    liveSmokeExecutedNow: false
  });
  assert.equal(JSON.stringify(status).includes("RECEIPT_CANARY"), false);
});

test("event limit keeps the newest records regardless of source ordering", () => {
  const events = Array.from({ length: 110 }, (_, index) => ({
    id: `evt_record_${String(index).padStart(3, "0")}`,
    at: new Date(Date.UTC(2026, 9, 13, 12, 0, index)).toISOString(),
    kind: "task.updated",
    status: "running"
  }));
  const projected = sanitizeEventsPayload({ events: events.reverse() });
  assert.equal(projected.length, 100);
  assert.equal(projected[0].id, "evt_record_109");
  assert.equal(projected.at(-1).id, "evt_record_010");
});

test("freshness and bounded percentages preserve unknown and stale states", () => {
  const now = Date.parse("2026-10-13T12:00:00Z");
  assert.deepEqual(freshness(null, now), { state: "unknown", ageMs: null });
  assert.equal(freshness("2026-10-13T11:59:55Z", now).state, "live");
  assert.equal(freshness("2026-10-13T11:59:40Z", now).state, "stale");
  assert.equal(freshness("2026-10-13T11:58:00Z", now).state, "offline");
  assert.equal(boundedPercent(null, 100), null);
  assert.equal(boundedPercent(80, 100), 80);
  assert.equal(boundedPercent(120, 100), 100);
});
