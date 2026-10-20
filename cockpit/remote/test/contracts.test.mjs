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
    apiVersion: "gate.remote-fleet/v4",
    sessionRevision,
    revision: 4,
    selectionEpoch: "0".repeat(32),
    observedAt,
    receivedAt: observedAt,
    validUntil: "2026-10-18T12:00:15.000Z",
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
      blockers: metric(),
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
      context: { label: "HackerOne CTF", nextSection: null },
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
      tokens: { availability: "exact", total: 100 },
      mirror: { availability: "unavailable", reason: "disabled", attempts: [] },
      latestEvent: { availability: "available", category: "campaign", status: "running", at: observedAt }
    }],
    ...overrides
  };
}

function executionMirror(overrides = {}) {
  return {
    availability: "available",
    reason: null,
    attempts: [{
      alias: "Attempt 1",
      kind: "supervised-execution",
      state: "running",
      phase: "active-surface-validation",
      tool: "httpx",
      action: "metadata-observation",
      startedAt: "2026-10-18T11:59:50.000Z",
      finishedAt: null,
      updatedAt: observedAt,
      elapsedMs: 10_000,
      progress: { availability: "exact", completed: 1, total: 2, percent: 50 },
      usage: {
        tokens: { availability: "unavailable", total: null },
        cost: { availability: "unavailable", amountMicros: null, unit: null },
        requests: { availability: "unavailable", value: null },
        retries: { availability: "unavailable", value: null },
        toolRuns: { availability: "exact", value: 1 }
      },
      entries: [{
        sequence: 1,
        at: observedAt,
        channel: "stdout",
        state: "running",
        fidelity: "redacted",
        truncated: false,
        text: "HTTP 200 [credential redacted]"
      }]
    }],
    ...overrides
  };
}

function pilotProjection() {
  const metric = value => ({ availability: "available", value });
  return {
    availability: "available", reason: null, observedAt,
    validUntil: new Date(Date.parse(observedAt) + 180_000).toISOString(),
    solving: {
      availability: "available", verdict: "pass", now: "complete", actionNeeded: "none", updatedAt: observedAt,
      completion: { state: "complete", reproduction: "confirmed", externalAcceptance: "accepted" },
      objectives: { availability: "available", completed: 1, total: 1 },
      depth: {
        level: "systematic", branchesExplored: metric(7), techniquesAttempted: metric(5), deadEndsRetired: metric(2)
      },
      efficiency: {
        elapsedSeconds: metric(900), activeSeconds: metric(600), tokens: metric(12_000),
        toolRuns: metric(8), requests: metric(31), retries: metric(1)
      }
    },
    learning: {
      availability: "available", verdict: "provisional", now: "checking", actionNeeded: "review", updatedAt: observedAt,
      stages: {
        observations: metric(6), candidates: metric(4), validated: metric(3), applied: metric(2),
        transferred: metric(1), regressed: metric(0)
      }
    },
    cockpit: {
      availability: "available", verdict: "pass", now: "current", actionNeeded: "none", updatedAt: observedAt,
      signals: { availability: "available", available: 10, total: 10 },
      updatesPublished: metric(12), updatesMissed: metric(0)
    },
    integrity: {
      availability: "available", status: "consistent",
      checks: { availability: "available", available: 6, total: 6 }, issues: metric(0), checkedAt: observedAt
    }
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
  const normalized = normalizeRemoteFleetProjection(fleetProjection());
  assert.equal(normalized.revision, 4);
  assert.equal(normalized.campaigns[0].alias, "Campaign 1");
  assert.deepEqual(normalized.campaigns[0].context, {
    label: "HackerOne CTF",
    nextSection: null
  });
  assert.equal(Object.isFrozen(normalized.campaigns[0].context), true);
  const withPilot = fleetProjection({
    campaigns: [{ ...fleetProjection().campaigns[0], pilot: pilotProjection() }]
  });
  const normalizedPilot = normalizeRemoteFleetProjection(withPilot).campaigns[0].pilot;
  assert.deepEqual([
    normalizedPilot.solving.verdict,
    normalizedPilot.learning.verdict,
    normalizedPilot.cockpit.verdict,
    normalizedPilot.learning.stages.transferred.value
  ], ["pass", "provisional", "pass", 1]);
  assert.equal(Object.hasOwn(normalizedPilot, "score"), false);
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

test("fleet campaign context accepts bounded labels and valid profile sections only", () => {
  const source = fleetProjection();
  const campaign = source.campaigns[0];
  const { context: _context, ...withoutContext } = campaign;
  assert.throws(() => normalizeRemoteFleetProjection({
    ...source,
    apiVersion: "gate.remote-fleet/v3"
  }), /invalid/u);
  assert.throws(() => normalizeRemoteFleetProjection(fleetProjection({
    campaigns: [withoutContext]
  })), /invalid/u);
  assert.throws(() => normalizeRemoteFleetProjection(fleetProjection({
    campaigns: [{ ...campaign, context: { ...campaign.context, extra: true } }]
  })), /invalid/u);
  assert.equal(normalizeRemoteFleetProjection(fleetProjection({
    campaigns: [{ ...campaign, context: { label: null, nextSection: null } }]
  })).campaigns[0].context.label, null);

  const questionnaire = {
    ...campaign,
    context: { label: "Uber Bug Bounty", nextSection: "authority-sources" },
    kind: "profile",
    stage: "profile-questionnaire",
    state: "waiting",
    progress: { completed: 14, total: 70, percent: 20 }
  };
  assert.deepEqual(normalizeRemoteFleetProjection(fleetProjection({
    campaigns: [questionnaire]
  })).campaigns[0].context, {
    label: "Uber Bug Bounty",
    nextSection: "authority-sources"
  });

  for (const label of [
    " leading space",
    "line\nbreak",
    "control\u0007value",
    "<script>alert(1)</script>",
    "https://example.com/program",
    "www.example.com",
    "example.com",
    "Project (api.example.com)",
    "Project example.com, next",
    "Target 10.0.0.1",
    "/private/program",
    "C:\\private\\program",
    "Bearer abcdefghijklmnop",
    "A".repeat(81)
  ]) {
    assert.throws(() => normalizeRemoteFleetProjection(fleetProjection({
      campaigns: [{ ...campaign, context: { label, nextSection: null } }]
    })), /invalid/u);
  }

  const invalidCampaigns = [
    { ...campaign, context: { label: "HackerOne CTF", nextSection: "not-a-section" } },
    { ...campaign, context: { label: "HackerOne CTF", nextSection: "scope-assets" } },
    { ...questionnaire, context: { label: "Uber Bug Bounty", nextSection: null } },
    {
      ...questionnaire,
      context: { label: "Uber Bug Bounty", nextSection: "scope-assets" },
      stage: "profile-ready"
    }
  ];
  for (const invalidCampaign of invalidCampaigns) {
    assert.throws(() => normalizeRemoteFleetProjection(fleetProjection({
      campaigns: [invalidCampaign]
    })), /invalid/u);
  }
});

test("fleet blocker metrics stay bound to kind, stage, and visible aggregates", () => {
  const caseFleet = fleetProjection();
  caseFleet.campaigns[0].work.setupBlockers = { value: 7, precision: "exact" };
  caseFleet.summary.setupBlockers = { value: 7, precision: "exact" };
  caseFleet.summary.blockers = { value: 7, precision: "exact" };
  assert.throws(() => normalizeRemoteFleetProjection(caseFleet), /invalid/u);

  const questionnaire = fleetProjection();
  questionnaire.campaigns[0] = {
    ...questionnaire.campaigns[0],
    context: { label: "Example Program", nextSection: "authority-sources" },
    kind: "profile",
    stage: "profile-questionnaire",
    state: "waiting",
    progress: { completed: 14, total: 70, percent: 20 },
    work: { ...questionnaire.campaigns[0].work, setupBlockers: { value: 5, precision: "exact" } }
  };
  questionnaire.summary.setupBlockers = { value: 5, precision: "exact" };
  questionnaire.summary.blockers = { value: 5, precision: "exact" };
  assert.throws(() => normalizeRemoteFleetProjection(questionnaire), /invalid/u);

  const inconsistent = fleetProjection();
  inconsistent.summary.blockers = { value: 1, precision: "exact" };
  assert.throws(() => normalizeRemoteFleetProjection(inconsistent), /invalid/u);

  const blocked = fleetProjection();
  blocked.campaigns[0].state = "blocked";
  blocked.summary.blockers = { value: 1, precision: "exact" };
  assert.equal(normalizeRemoteFleetProjection(blocked).summary.blockers.value, 1);
});

test("remote fleet validates and deeply freezes the exact execution mirror", () => {
  const source = fleetProjection({
    campaigns: [{ ...fleetProjection().campaigns[0], mirror: executionMirror() }]
  });
  const normalized = normalizeRemoteFleetProjection(source);
  assert.equal(normalized.campaigns[0].mirror.attempts[0].progress.percent, 50);
  assert.equal(Object.isFrozen(normalized.campaigns[0].mirror.attempts[0].entries[0]), true);

  const nonContiguous = executionMirror();
  nonContiguous.attempts[0].alias = "Attempt 150";
  nonContiguous.attempts.push({ ...structuredClone(nonContiguous.attempts[0]), alias: "Attempt 148" });
  const stableAliases = normalizeRemoteFleetProjection(fleetProjection({
    campaigns: [{ ...fleetProjection().campaigns[0], mirror: nonContiguous }]
  })).campaigns[0].mirror.attempts.map((attempt) => attempt.alias);
  assert.deepEqual(stableAliases, ["Attempt 150", "Attempt 148"]);

  const badProgress = executionMirror();
  badProgress.attempts[0].progress.percent = 49;
  assert.throws(() => normalizeRemoteFleetProjection(fleetProjection({
    campaigns: [{ ...fleetProjection().campaigns[0], mirror: badProgress }]
  })), /invalid/u);

  const unsafe = executionMirror();
  unsafe.attempts[0].entries[0].text = `${"gh"}p_${"A".repeat(36)}`;
  assert.throws(() => normalizeRemoteFleetProjection(fleetProjection({
    campaigns: [{ ...fleetProjection().campaigns[0], mirror: unsafe }]
  })), /invalid/u);

  for (const privateText of [
    "saved /home/operator/.gate/evidence/result.txt",
    "saved /srv/unrelated/service/result.txt",
    "opened (/etc/passwd)",
    "inspected [/opt/application/config.json]",
    "wrote result>/var/output/result.txt",
    "saved C:\\Users\\operator\\gate\\result.txt",
    "saved \\\\private-host\\gate\\result.txt",
    "evidence://private-result",
    `run xrun_${"a".repeat(32)}`,
    "--token abc123",
    "auth=abc123",
    '{"token":"abc123"}',
    '{"secret":"abc123"}',
    "file:///etc/passwd",
    "file://localhost/etc/passwd",
    "//server/share/file",
    "curl -u alice:hunter2 https://example.invalid/path"
  ]) {
    const privateMirror = executionMirror();
    privateMirror.attempts[0].entries[0].text = privateText;
    assert.throws(() => normalizeRemoteFleetProjection(fleetProjection({
      campaigns: [{ ...fleetProjection().campaigns[0], mirror: privateMirror }]
    })), /invalid/u);
  }

  for (const redactedText of ["tool --token=[secret withheld]", '{"token":[secret withheld]}']) {
    const redactedMirror = executionMirror();
    redactedMirror.attempts[0].entries[0].text = redactedText;
    assert.equal(normalizeRemoteFleetProjection(fleetProjection({
      campaigns: [{ ...fleetProjection().campaigns[0], mirror: redactedMirror }]
    })).campaigns[0].mirror.attempts[0].entries[0].text, redactedText);
  }

  const publicUrl = executionMirror();
  publicUrl.attempts[0].entries[0].text = "GET https://example.invalid/public/path?q=value";
  assert.equal(normalizeRemoteFleetProjection(fleetProjection({
    campaigns: [{ ...fleetProjection().campaigns[0], mirror: publicUrl }]
  })).campaigns[0].mirror.attempts[0].entries[0].text, publicUrl.attempts[0].entries[0].text);
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
