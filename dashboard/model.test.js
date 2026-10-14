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
    "engagement-binding", "target-argument-binding", "declared-action-label-binding", "tool-allowlist", "exact-argv",
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
    signal: null
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
