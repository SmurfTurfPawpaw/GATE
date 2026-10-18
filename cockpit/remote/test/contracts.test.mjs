import assert from "node:assert/strict";
import test from "node:test";

import {
  RemoteContractError,
  containsLikelyRemoteCredential,
  digestRemotePayload,
  normalizeRemoteCommandBinding,
  normalizeRemoteCommandEvent,
  normalizeRemoteCommandStatusRequest,
  normalizeRemoteFleetProjection,
  normalizeRemoteMessageRequest,
  normalizeRemoteQuestionResponse,
  normalizeRemoteStateProjection,
  remoteQueuedReceipt,
  remoteCommandStatusResponse,
  sanitizeRemoteActivityEvent
} from "../contracts.mjs";

const requestId = "request-12345678";
const sessionRevision = 7;
const observedAt = "2026-10-18T12:00:00.000Z";

function message(overrides = {}) {
  return {
    apiVersion: "gate.remote-message-request/v1",
    requestId,
    sessionRevision,
    message: "Continue the reviewed plan.",
    ...overrides
  };
}

function stateProjection(overrides = {}) {
  return {
    apiVersion: "gate.remote-cockpit-state/v1",
    sessionRevision,
    stateRevision: 3,
    observedAt,
    validUntil: "2026-10-18T12:01:00.000Z",
    runner: { state: "connected", observedAt },
    codex: { state: "idle" },
    tokens: null,
    conversation: [],
    pendingQuestions: [],
    ...overrides
  };
}

function fleetProjection(overrides = {}) {
  const metric = (value = 0) => ({ value, precision: "exact" });
  const scan = (profile = false) => ({
    availability: "available",
    discovered: 1,
    scanned: 1,
    omitted: 0,
    invalid: 0,
    discoveredAtLeast: false,
    omittedAtLeast: false,
    complete: true,
    truncated: false,
    ...(profile ? { visible: 1, representedByCases: 1 } : {})
  });
  return {
    apiVersion: "gate.remote-fleet/v1",
    sessionRevision,
    revision: 4,
    observedAt,
    receivedAt: observedAt,
    connection: "connected",
    sourceFreshness: "current",
    coverage: { state: "exact", cases: scan(), profiles: scan(true) },
    summary: {
      campaigns: metric(1),
      active: metric(1),
      waiting: metric(),
      attention: metric(),
      profileAnswers: { answered: 1, total: 2, precision: "exact" },
      runningExecutions: metric(),
      activeWorkflows: metric(1),
      runningAnalyses: metric(),
      setupBlockers: metric(),
      campaignTokens: { availability: "exact", total: 100 },
      hostTokens: {
        availability: "exact",
        input: 50,
        cachedInput: 10,
        output: 40,
        total: 100,
        cost: { availability: "unavailable", amountMicros: null, unit: null }
      }
    },
    campaigns: [{
      alias: "Campaign 1",
      kind: "case",
      stage: "active-testing",
      state: "running",
      progress: null,
      attention: "steady",
      freshness: "current",
      work: {
        runningExecutions: metric(),
        activeWorkflows: metric(1),
        runningAnalyses: metric(),
        setupBlockers: metric()
      },
      tokens: { availability: "exact", total: 100 }
    }],
    ...overrides
  };
}

test("normalizes exact bounded message and binding contracts", () => {
  assert.deepEqual(normalizeRemoteMessageRequest(message({ message: "  Continue.\r\nNow.  " })), {
    apiVersion: "gate.remote-message-request/v1",
    requestId,
    sessionRevision,
    message: "Continue.\nNow."
  });
  assert.deepEqual(normalizeRemoteCommandBinding({
    operatorId: "operator-123",
    browserSessionId: "browser-12345678",
    caseId: "alpha-case",
    sessionRevision
  }), {
    operatorId: "operator-123",
    browserSessionId: "browser-12345678",
    caseId: "alpha-case",
    sessionRevision
  });
});

test("message contract rejects unknown fields, controls, excessive text, and likely credentials", () => {
  const githubToken = `${"gh"}p_${"A".repeat(36)}`;
  const basicCredential = Buffer.from("operator:canary", "utf8").toString("base64");
  const samples = [
    { ...message(), target: "CANARY_TARGET" },
    message({ message: "bad\u0000text" }),
    message({ message: "x".repeat(1_001) }),
    message({ message: "x\n".repeat(12) + "x" }),
    message({ message: "api_key=CANARY_CREDENTIAL_123456789" }),
    message({ message: "Bearer abcdefghijklmnopqrstuvwxyz" }),
    message({ message: `Use ${githubToken}` }),
    message({ message: `Authorization: Basic ${basicCredential}` }),
    message({ message: "https://operator:canary@example.test/private" }),
    message({ requestId: "short" }),
    message({ sessionRevision: 0 })
  ];
  for (const sample of samples) {
    assert.throws(() => normalizeRemoteMessageRequest(sample), RemoteContractError);
  }
});

test("credential pattern filter catches common standalone, header, URL, and private-key shapes", () => {
  const samples = [
    `${"gh"}p_${"A".repeat(36)}`,
    `${"s"}k-proj-${"B".repeat(40)}`,
    `${"AK"}IA${"C".repeat(16)}`,
    `Basic ${Buffer.from("operator:canary", "utf8").toString("base64")}`,
    "https://operator:canary@example.test/private",
    `${"-----BEGIN "}ENCRYPTED PRIVATE KEY-----`,
    '{"client_secret":"CANARY_CREDENTIAL"}'
  ];
  for (const sample of samples) assert.equal(containsLikelyRemoteCredential(sample), true, sample);
  for (const sample of ["Continue the reviewed plan.", "Discuss OAuth token rotation.", "example.test/path"]) {
    assert.equal(containsLikelyRemoteCredential(sample), false, sample);
  }
});

test("question replies are exact, bounded, and canonically digested", () => {
  const first = normalizeRemoteQuestionResponse({
    apiVersion: "gate.remote-question-response/v1",
    requestId,
    sessionRevision,
    questionToken: `q_${"a".repeat(43)}`,
    answers: { priority: "Recommended", timing: "Now" }
  });
  const second = normalizeRemoteQuestionResponse({
    apiVersion: "gate.remote-question-response/v1",
    requestId,
    sessionRevision,
    questionToken: `q_${"a".repeat(43)}`,
    answers: { timing: "Now", priority: "Recommended" }
  });
  assert.equal(digestRemotePayload(first), digestRemotePayload(second));
  assert.throws(() => normalizeRemoteQuestionResponse({ ...first, answers: {} }), /invalid/u);
  assert.throws(() => normalizeRemoteQuestionResponse({ ...first, extra: true }), /Reload/u);
  assert.throws(() => normalizeRemoteQuestionResponse({
    ...first,
    answers: { priority: "password=CANARY_SECRET_VALUE" }
  }), /credentials/u);
});

test("receipt and lifecycle event contracts are closed and monotonic", () => {
  assert.deepEqual(remoteQueuedReceipt({
    requestId,
    sessionRevision,
    commandId: "cmd_1234567890abcdef",
    sequence: 11,
    acceptedAt: observedAt
  }), {
    apiVersion: "gate.remote-cockpit-receipt/v1",
    requestId,
    sessionRevision,
    commandId: "cmd_1234567890abcdef",
    sequence: 11,
    status: "queued",
    acceptedAt: observedAt
  });
  assert.deepEqual(normalizeRemoteCommandEvent({
    apiVersion: "gate.remote-command-event/v1",
    sequence: 12,
    at: observedAt,
    requestId,
    commandId: "cmd_1234567890abcdef",
    state: "accepted"
  }).state, "accepted");
  assert.throws(() => normalizeRemoteCommandEvent({
    apiVersion: "gate.remote-command-event/v1",
    sequence: 12,
    at: observedAt,
    requestId,
    commandId: "cmd_1234567890abcdef",
    state: "delivered"
  }), /invalid/u);
});

test("command status reconciliation is exact, session-bound, and bounded", () => {
  const statusRequest = normalizeRemoteCommandStatusRequest({
    apiVersion: "gate.remote-command-status-request/v1",
    caseId: "alpha-case",
    sessionRevision,
    commands: [{ requestId, commandId: "cmd_1234567890abcdef" }]
  });
  assert.deepEqual(remoteCommandStatusResponse({
    caseId: statusRequest.caseId,
    sessionRevision: statusRequest.sessionRevision,
    commands: [{ ...statusRequest.commands[0], state: "completed" }]
  }), {
    apiVersion: "gate.remote-command-status-response/v1",
    caseId: "alpha-case",
    sessionRevision,
    commands: [{ requestId, commandId: "cmd_1234567890abcdef", state: "completed" }]
  });
  assert.throws(() => normalizeRemoteCommandStatusRequest({
    ...statusRequest,
    commands: Array.from({ length: 17 }, (_, index) => ({
      requestId: `request-${String(index).padStart(8, "0")}`,
      commandId: `cmd_${String(index).padStart(16, "0")}`
    }))
  }), /invalid/u);
  assert.throws(() => normalizeRemoteCommandStatusRequest({
    ...statusRequest,
    commands: [statusRequest.commands[0], statusRequest.commands[0]]
  }), /invalid/u);
});

test("state projections bind freshness and sanitize the bounded visible conversation", () => {
  const projection = normalizeRemoteStateProjection(stateProjection({
    conversation: [{ role: "operator", text: "  Continue.  ", at: observedAt }],
    pendingQuestions: [{
      token: `q_${"b".repeat(43)}`,
      questions: [{
        id: "priority",
        header: "Priority",
        question: "What should run next?",
        options: [
          { label: "Map first (Recommended)", description: "Start with bounded mapping.", recommended: true },
          { label: "Wait", description: "Keep this case idle.", recommended: false }
        ]
      }]
    }]
  }));
  assert.equal(projection.conversation[0].text, "Continue.");
  assert.equal(projection.runner.state, "connected");
  assert.throws(() => normalizeRemoteStateProjection(stateProjection({ unexpected: true })), /invalid/u);
  assert.throws(() => normalizeRemoteStateProjection(stateProjection({
    validUntil: "2026-10-18T12:10:00.000Z"
  })), /invalid/u);
  assert.throws(() => normalizeRemoteStateProjection(stateProjection({
    conversation: [{ role: "codex", text: "access_token=CANARY_SECRET_TOKEN", at: observedAt }]
  })), /credentials/u);
});

test("fleet projections are exact, revision-bound, and byte bounded", () => {
  assert.equal(normalizeRemoteFleetProjection(fleetProjection()).revision, 4);
  assert.throws(() => normalizeRemoteFleetProjection(fleetProjection({ extra: true })), /invalid/u);
  assert.throws(() => normalizeRemoteFleetProjection(fleetProjection({
    campaigns: [{ ...fleetProjection().campaigns[0], path: "/CANARY_PRIVATE_PATH" }]
  })), /invalid/u);
  for (const forbidden of ["command", "target", "evidence"]) {
    assert.throws(() => normalizeRemoteFleetProjection(fleetProjection({
      campaigns: [{ ...fleetProjection().campaigns[0], [forbidden]: `CANARY_${forbidden.toUpperCase()}` }]
    })), /invalid/u);
  }
  assert.throws(() => normalizeRemoteFleetProjection(fleetProjection({
    connection: "unavailable",
    sourceFreshness: "unavailable"
  })), /invalid/u);
});

test("activity events accept only exact categorical summaries", () => {
  const event = sanitizeRemoteActivityEvent({
    category: "testing",
    state: "progress",
    completed: 2,
    total: 5,
    tokens: { total: 100, contextWindow: 10_000 }
  }, 9, new Date(observedAt));
  assert.deepEqual(event, {
    apiVersion: "gate.remote-cockpit-event/v1",
    sequence: 9,
    at: observedAt,
    category: "testing",
    state: "progress",
    completed: 2,
    total: 5,
    tokens: { total: 100, contextWindow: 10_000 }
  });
  assert.equal(sanitizeRemoteActivityEvent({
    category: "shell",
    state: "progress",
    completed: null,
    total: null,
    tokens: null
  }, 10, new Date(observedAt)), null);
  assert.equal(sanitizeRemoteActivityEvent({
    category: "testing",
    state: "progress",
    completed: null,
    total: null,
    tokens: null,
    command: "CANARY_COMMAND"
  }, 10, new Date(observedAt)), null);
});
