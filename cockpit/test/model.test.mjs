import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  executionMirrorIsFresh,
  hasAvailableFleetMetric,
  parseRemoteSseFrame,
  parsePublicSnapshot,
  publicCockpitModel,
  readPublicSnapshotResponse,
  readRemoteJsonResponse,
  remoteStateIsFresh,
  toDisplayModel
} from "../assets/model.js";

const now = new Date("2026-10-16T12:00:00Z");

async function fixture() {
  return JSON.parse(await readFile(new URL("../data/status.json", import.meta.url), "utf8"));
}

test("accepts the exact gate.public-cockpit/v1 fixture", async () => {
  const source = await fixture();
  const parsed = parsePublicSnapshot(source, { now });
  assert.equal(parsed.kind, "available");
  assert.equal(parsed.schema, publicCockpitModel.schema);
  assert.equal(parsed.campaigns.length, 2);
  assert.equal(toDisplayModel(parsed).waitingCount, 1);
  assert.equal(toDisplayModel(parsed).mode, "preview");
  assert.equal(toDisplayModel(parsed).siteVersion, source.site.version);
  assert.equal(toDisplayModel(parsed).gateVersion, source.gate.version);
  assert.equal(parsed.campaigns[0].mirror.attempts[0].entries[1].channel, "command");
});

test("execution mirror is bounded, exact-keyed, and rejects unmasked secrets", async () => {
  const { validateExecutionMirror } = await import("../assets/model.js");
  const source = (await fixture()).campaigns[0].mirror;
  const accepted = validateExecutionMirror(source, { upperBound: "2026-10-16T11:15:00Z", remote: true });
  assert.equal(accepted?.attempts[0].state, "running");
  assert.equal(accepted?.attempts[0].usage.toolRuns.value, 1);

  for (const remote of [false, true]) {
    const spaced = structuredClone(source);
    spaced.attempts[0].entries[0].text = " checking ";
    assert.equal(validateExecutionMirror(spaced, { remote })?.attempts[0].entries[0].text, " checking ");
  }

  const nonContiguous = structuredClone(source);
  nonContiguous.attempts[0].alias = "Attempt 150";
  nonContiguous.attempts.push({ ...structuredClone(nonContiguous.attempts[0]), alias: "Attempt 148" });
  assert.deepEqual(
    validateExecutionMirror(nonContiguous, { upperBound: "2026-10-16T11:15:00Z", remote: true })
      ?.attempts.map((attempt) => attempt.alias),
    ["Attempt 150", "Attempt 148"]
  );
  for (const alias of ["Attempt 0", "Attempt 9007199254740992", "Attempt 1"]) {
    const invalidAlias = structuredClone(source);
    invalidAlias.attempts.push({ ...structuredClone(invalidAlias.attempts[0]), alias });
    assert.equal(validateExecutionMirror(invalidAlias, { upperBound: "2026-10-16T11:15:00Z", remote: true }), null);
  }

  const secret = structuredClone(source);
  secret.attempts[0].entries[1].text = `curl -H "Authorization: Bearer ${"a".repeat(32)}" example.invalid`;
  assert.equal(validateExecutionMirror(secret, { upperBound: "2026-10-16T11:15:00Z", remote: true }), null);

  for (const unsafeText of [
    "/srv/unrelated/service/output.txt",
    "open (/etc/passwd)",
    "inspect [/opt/application/config.json]",
    "echo result>/var/output/result.txt",
    "--token abc123",
    "--auth abc123",
    "token=abc123",
    "auth=abc123",
    '{"token":"abc123"}',
    '{"secret":"abc123"}',
    "file:///etc/passwd",
    "file://localhost/etc/passwd",
    "//server/share/file",
    "curl -u alice:hunter2 https://example.invalid/path"
  ]) {
    const unsafe = structuredClone(source);
    unsafe.attempts[0].entries[1].text = unsafeText;
    assert.equal(validateExecutionMirror(unsafe, { upperBound: "2026-10-16T11:15:00Z", remote: true }), null);
  }

  for (const redactedText of ["tool --token=[secret withheld]", '{"token":[secret withheld]}']) {
    const redacted = structuredClone(source);
    redacted.attempts[0].entries[1].text = redactedText;
    assert.ok(validateExecutionMirror(redacted, { upperBound: "2026-10-16T11:15:00Z", remote: true }));
  }

  const publicUrl = structuredClone(source);
  publicUrl.attempts[0].entries[1].text = "GET https://example.invalid/public/path?q=value";
  assert.ok(validateExecutionMirror(publicUrl, { upperBound: "2026-10-16T11:15:00Z", remote: true }));

  const rawField = structuredClone(source);
  rawField.attempts[0].entries[0].rawOutput = "CANARY";
  assert.equal(validateExecutionMirror(rawField), null);

  const inconsistent = structuredClone(source);
  inconsistent.attempts[0].progress.percent = 44;
  assert.equal(validateExecutionMirror(inconsistent), null);

  const tooMany = structuredClone(source);
  tooMany.attempts[0].entries = Array.from({ length: 9 }, (_, index) => ({
    ...source.attempts[0].entries[0], sequence: index + 1,
    at: new Date(Date.parse("2026-10-16T11:00:00Z") + index * 1_000).toISOString()
  }));
  assert.equal(validateExecutionMirror(tooMany), null);
});

test("preview is an explicit non-expiring, never-observed union", async () => {
  const preview = await fixture();
  assert.equal(parsePublicSnapshot(preview, { now }).mode, "preview");

  const observed = { ...preview, mode: "observed" };
  assert.equal(parsePublicSnapshot(observed, { now }).kind, "unavailable");
  preview.snapshot.validUntil = "2026-10-16T12:10:00Z";
  assert.equal(parsePublicSnapshot(preview, { now }).kind, "unavailable");


});

test("fails closed when any unknown key is present", async () => {
  const samples = [
    (value) => { value.target = "CANARY_TARGET"; },
    (value) => { value.campaigns[0].tool = "CANARY_TOOL"; },
    (value) => { value.activity[0].detail = "CANARY_DETAIL"; },
    (value) => { value.aggregate.rawTokens = 12345; }
  ];

  for (const mutate of samples) {
    const value = await fixture();
    mutate(value);
    assert.deepEqual(parsePublicSnapshot(value, { now }), { kind: "unavailable", reason: "invalid" });
  }
});

test("rejects free-form aliases, HTML, activity categories, and versions", async () => {
  const samples = [
    (value) => { value.campaigns[0].alias = "Real target"; },
    (value) => { value.campaigns[0].alias = "<img src=x onerror=alert(1)>"; },
    (value) => { value.activity[0].category = "free form activity"; },
    (value) => { value.site.version = "<b>1</b>"; }
  ];

  for (const mutate of samples) {
    const value = await fixture();
    mutate(value);
    assert.equal(parsePublicSnapshot(value, { now }).kind, "unavailable");
  }
});

test("display projection contains allowlisted labels and strips payload canaries by rejection", async () => {
  const value = await fixture();
  value.activity[0].privatePrompt = "CANARY_PRIVATE_PROMPT";
  const display = toDisplayModel(parsePublicSnapshot(value, { now }));
  assert.equal(display.kind, "unavailable");
  assert.equal(JSON.stringify(display).includes("CANARY_PRIVATE_PROMPT"), false);

  const validDisplay = toDisplayModel(parsePublicSnapshot(await fixture(), { now }));
  const serialized = JSON.stringify(validDisplay);
  assert.equal(serialized.includes("How deeply should Codex explore the current lead?"), true);
  assert.equal(serialized.includes("choose-depth"), true);
  assert.equal(serialized.includes("privatePrompt"), false);
});

test("unavailable token usage requires null and never implies zero", async () => {
  const value = await fixture();
  value.aggregate.tokenStatus = "unavailable";
  value.aggregate.tokensUsed = null;
  value.aggregate.tokenBudget = null;
  const display = toDisplayModel(parsePublicSnapshot(value, { now }));
  assert.equal(display.kind, "available");
  assert.equal(display.aggregate.tokenStatus, "unavailable");
  assert.equal(display.aggregate.tokensUsed, null);
  assert.equal(display.aggregate.tokenBudget, null);

  value.aggregate.tokensUsed = 0;
  assert.equal(parsePublicSnapshot(value, { now }).kind, "unavailable");
});

test("aggregate counters and token budgets enforce bounded progress invariants", async () => {
  const samples = [
    (value) => { value.aggregate.overallProgress = 101; },
    (value) => { value.aggregate.testsPassed = value.aggregate.testsTotal + 1; },
    (value) => { value.aggregate.tokensUsed = value.aggregate.tokenBudget + 1; },
    (value) => { value.aggregate.blockerCount = -1; }
  ];
  for (const mutate of samples) {
    const value = await fixture();
    mutate(value);
    assert.equal(parsePublicSnapshot(value, { now }).kind, "unavailable");
  }
});

test("decision choices are bounded enums with one in-list recommendation", async () => {
  const value = await fixture();
  assert.equal(toDisplayModel(parsePublicSnapshot(value, { now })).decision.choices.length, 3);

  value.decision.choices.push("continue");
  assert.equal(parsePublicSnapshot(value, { now }).kind, "unavailable");

  const unknown = await fixture();
  unknown.decision.choices[0] = "send-secret";
  assert.equal(parsePublicSnapshot(unknown, { now }).kind, "unavailable");

  const clear = await fixture();
  clear.decision = { id: null, revision: null, expiresAt: null, state: "clear", campaign: null, prompt: null, choices: [], recommended: null };
  assert.equal(parsePublicSnapshot(clear, { now }).kind, "available");
});

test("bridge, messages, and receipts use exact bounded contracts", async () => {
  const { validateLocalBridge, validateBridgeReceipt, validateOperatorMessage, validateRemoteOperatorMessage } = await import("../assets/model.js");
  const submitMessage = async () => undefined;
  const submitQuestion = async () => undefined;
  const bridge = { apiVersion: "gate.local-cockpit-bridge/v1", submitMessage, submitQuestion };
  assert.equal(validateLocalBridge(bridge), bridge);
  assert.equal(validateLocalBridge({ ...bridge, endpoint: "CANARY" }), null);
  assert.equal(validateLocalBridge({ apiVersion: bridge.apiVersion, submitMessage }), null);

  assert.deepEqual(validateOperatorMessage("  hello\r\nGiovanni  "), { valid: true, message: "hello\nGiovanni", length: 14, bytes: 14 });
  assert.equal(validateOperatorMessage("Review https://example.test/program").valid, true);
  for (const invalid of [
    "", "x".repeat(1_001), `${"a\n".repeat(12)}b`, "bad\u0000text", "bad\u202Etext",
    "api_key=CANARY_CREDENTIAL_123456789", "password=fixture",
    "Bearer abcdefghijklmnopqrstuvwxyz", "-----BEGIN OPENSSH PRIVATE KEY-----", "😀".repeat(1_001)
  ]) {
    assert.equal(validateOperatorMessage(invalid).valid, false);
  }
  for (const invalid of [
    "Basic abcdefghijklmnopqrstuvwxyz",
    `ghp_${"A".repeat(36)}`,
    "https://fixture-user:fixture-password@example.test/path",
    `Cookie: session=${"a".repeat(32)}`
  ]) {
    assert.equal(validateRemoteOperatorMessage(invalid).valid, false);
  }

  const requestId = "req_123";
  assert.deepEqual(validateBridgeReceipt({ apiVersion: "gate.local-cockpit-receipt/v1", requestId, status: "accepted" }, requestId), {
    apiVersion: "gate.local-cockpit-receipt/v1", requestId, status: "accepted"
  });
  assert.equal(validateBridgeReceipt(undefined, requestId), null);
  assert.equal(validateBridgeReceipt({ apiVersion: "gate.local-cockpit-receipt/v1", requestId: "wrong", status: "accepted" }, requestId), null);
  assert.equal(validateBridgeReceipt({ apiVersion: "gate.local-cockpit-receipt/v1", requestId, status: "accepted", delivered: true }, requestId), null);
});

test("private local state and activity accept exact bounded projections only", async () => {
  const { validateLocalActivityEvent, validateLocalCompanionState } = await import("../assets/model.js");
  const observedAt = "2026-10-16T12:00:00.000Z";
  const state = {
    apiVersion: "gate.local-companion-state/v1",
    sessionRevision: 8,
    stateRevision: 3,
    observedAt,
    connected: true,
    turn: "waiting",
    tokens: {
      availability: "exact",
      source: "codex-notification",
      input: 900,
      cachedInput: 400,
      output: 300,
      reasoningOutput: 100,
      total: 1200,
      contextWindow: 200000,
      cost: { availability: "estimated", amountMicros: 12000, unit: "USD" }
    },
    conversation: [{ role: "codex", text: "Choose the next path.", at: observedAt }],
    pendingQuestions: [{
      token: `q_${"a".repeat(43)}`,
      questions: [{
        id: "priority",
        header: "Priority",
        question: "Which path should Codex take?",
        options: [
          { label: "Deep review (Recommended)", description: "Use the reviewed default.", recommended: true },
          { label: "Pause", description: "Wait for operator review.", recommended: false }
        ]
      }]
    }]
  };
  assert.equal(validateLocalCompanionState(state, { now: new Date(observedAt) })?.pendingQuestions.length, 1);
  assert.equal(validateLocalCompanionState({ ...state, reasoning: "CANARY_REASONING" }, { now: new Date(observedAt) }), null);
  assert.equal(validateLocalCompanionState({
    ...state,
    conversation: [{ ...state.conversation[0], command: "CANARY_COMMAND" }]
  }, { now: new Date(observedAt) }), null);

  const activity = {
    apiVersion: "gate.local-cockpit-event/v1",
    sequence: 4,
    at: observedAt,
    category: "testing",
    state: "progress",
    completed: 2,
    total: 5,
    tokens: null
  };
  assert.equal(validateLocalActivityEvent(activity)?.sequence, 4);
  assert.equal(validateLocalActivityEvent({ ...activity, output: "CANARY_OUTPUT" }), null);
});

test("structured activity accepts counts only and rejects inconsistent or unknown fields", async () => {
  const over = await fixture();
  over.activity[0].completed = over.activity[0].total + 1;
  assert.equal(parsePublicSnapshot(over, { now }).kind, "unavailable");

  const prose = await fixture();
  prose.activity[0].command = "CANARY_RAW_COMMAND";
  assert.equal(parsePublicSnapshot(prose, { now }).kind, "unavailable");
  assert.equal(JSON.stringify(toDisplayModel(parsePublicSnapshot(prose, { now }))).includes("CANARY_RAW_COMMAND"), false);
});

test("response boundary rejects redirects, non-JSON, oversized, and malformed bodies", async () => {
  const valid = JSON.stringify(await fixture());
  const accepted = await readPublicSnapshotResponse(new Response(valid, {
    headers: { "content-type": "application/json" }
  }), { now });
  assert.equal(accepted.kind, "available");

  const samples = [
    new Response(valid, { headers: { "content-type": "text/html" } }),
    new Response("{", { headers: { "content-type": "application/json" } }),
    new Response(" ".repeat(65_537), { headers: { "content-type": "application/json" } }),
    new Response(valid, { status: 404, headers: { "content-type": "application/json" } })
  ];
  for (const response of samples) {
    assert.equal((await readPublicSnapshotResponse(response, { now })).kind, "unavailable");
  }

  const redirected = new Response(valid, { headers: { "content-type": "application/json" } });
  Object.defineProperty(redirected, "redirected", { value: true });
  assert.equal((await readPublicSnapshotResponse(redirected, { now })).kind, "unavailable");
});

test("older snapshots cannot roll back an established session", async () => {
  const value = await fixture();
  assert.equal(parsePublicSnapshot(value, {
    now,
    minimumGeneratedAt: "2026-10-16T11:16:00Z"
  }).kind, "unavailable");
  assert.equal(parsePublicSnapshot(value, {
    now,
    minimumGeneratedAt: value.snapshot.generatedAt
  }).kind, "available");
});

test("fleet attention remains unavailable while private state arrives before fleet state", () => {
  assert.equal(hasAvailableFleetMetric(undefined), false);
  assert.equal(hasAvailableFleetMetric(null), false);
  assert.equal(hasAvailableFleetMetric({ value: null, precision: "unavailable" }), false);
  assert.equal(hasAvailableFleetMetric({ value: 0, precision: "exact" }), true);
});

function remoteState(overrides = {}) {
  return {
    apiVersion: "gate.remote-cockpit-state/v1",
    sessionRevision: 9,
    stateRevision: 4,
    observedAt: "2026-10-16T12:00:00.000Z",
    validUntil: "2026-10-16T12:05:00.000Z",
    runner: { state: "connected", observedAt: "2026-10-16T12:00:00.000Z" },
    codex: { state: "waiting" },
    tokens: null,
    conversation: [{ role: "codex", text: "Choose a path.", at: "2026-10-16T12:00:00.000Z" }],
    pendingQuestions: [],
    ...overrides
  };
}

function unavailableRemoteFleet(overrides = {}) {
  const unavailable = () => ({ value: null, precision: "unavailable" });
  const scan = (profile = false) => ({
    availability: "unavailable", discovered: null, scanned: null, omitted: null, invalid: null,
    discoveredAtLeast: false, omittedAtLeast: false, complete: false, truncated: true,
    ...(profile ? { visible: null, representedByCases: null } : {})
  });
  return {
    apiVersion: "gate.remote-fleet/v4", sessionRevision: 9, revision: 1, selectionEpoch: "0".repeat(32),
    observedAt: null, receivedAt: "2026-10-16T12:00:00.000Z",
    validUntil: "2026-10-16T12:00:15.000Z",
    connection: "unavailable", sourceFreshness: "unavailable",
    coverage: { state: "unavailable", cases: scan(), profiles: scan(true) },
    summary: {
      campaigns: unavailable(), active: unavailable(), waiting: unavailable(), attention: unavailable(),
      profileAnswers: { answered: null, total: null, precision: "unavailable" },
      runningExecutions: unavailable(), activeWorkflows: unavailable(), runningAnalyses: unavailable(), setupBlockers: unavailable(), blockers: unavailable(),
      campaignTokens: { availability: "unavailable", total: null },
      hostTokens: {
        availability: "unavailable", input: null, cachedInput: null, output: null, total: null,
        cost: { availability: "unavailable", amountMicros: null, unit: null }
      }
    },
    campaigns: [],
    ...overrides
  };
}

function connectedRemoteFleet(overrides = {}) {
  const fleet = unavailableRemoteFleet();
  const metric = (value = 0) => ({ value, precision: "exact" });
  const scan = (profile = false) => ({
    availability: "available", discovered: 1, scanned: 1, omitted: 0, invalid: 0,
    discoveredAtLeast: false, omittedAtLeast: false, complete: true, truncated: false,
    ...(profile ? { visible: 1, representedByCases: 1 } : {})
  });
  fleet.observedAt = fleet.receivedAt;
  fleet.connection = "connected";
  fleet.sourceFreshness = "current";
  fleet.coverage = { state: "exact", cases: scan(), profiles: scan(true) };
  fleet.summary = {
    campaigns: metric(1), active: metric(1), waiting: metric(), attention: metric(),
    profileAnswers: { answered: 1, total: 2, precision: "exact" },
    runningExecutions: metric(), activeWorkflows: metric(1), runningAnalyses: metric(),
    setupBlockers: metric(), blockers: metric(), campaignTokens: { availability: "unavailable", total: null },
    hostTokens: {
      availability: "unavailable", input: null, cachedInput: null, output: null, total: null,
      cost: { availability: "unavailable", amountMicros: null, unit: null }
    }
  };
  fleet.campaigns = [{
    alias: "Campaign 1",
    context: { label: "HackerOne CTF", nextSection: null },
    kind: "case",
    stage: "active-testing",
    state: "running",
    progress: null,
    attention: "steady",
    freshness: "current",
    work: {
      runningExecutions: metric(), activeWorkflows: metric(1),
      runningAnalyses: metric(), setupBlockers: metric()
    },
    tokens: { availability: "unavailable", total: null },
    mirror: { availability: "unavailable", reason: "disabled", attempts: [] },
    latestEvent: { availability: "unavailable", category: null, status: null, at: null }
  }];
  return { ...fleet, ...overrides };
}

test("remote live contracts are exact, session-bound, and freshness-bounded", async () => {
  const {
    validateRemoteActivityEvent,
    validateRemoteBridge,
    validateRemoteCommandEvent,
    validateRemoteCommandStatusRequest,
    validateRemoteCommandStatusResponse,
    validateRemoteConnection,
    validateRemoteFleet,
    validateRemoteQueuedReceipt,
    validateRemoteSession,
    validateRemoteState
  } = await import("../assets/model.js");
  const submitMessage = async () => undefined;
  const submitQuestion = async () => undefined;
  const reconcileCommands = async () => undefined;
  const bridge = {
    apiVersion: "gate.remote-cockpit-bridge/v1", caseId: "alpha-case", sessionRevision: 9,
    reconcileCommands, submitMessage, submitQuestion
  };
  assert.equal(validateRemoteBridge(bridge), bridge);
  assert.equal(validateRemoteBridge({ ...bridge, caseId: "INVALID CASE" }), null);
  assert.equal(validateRemoteBridge({ ...bridge, endpoint: "CANARY" }), null);

  const session = {
    apiVersion: "gate.remote-cockpit-session/v1", sessionRevision: 9,
    csrf: "a".repeat(43), expiresAt: "2026-10-16T13:00:00.000Z", caseId: "alpha-case"
  };
  assert.equal(validateRemoteSession(session, { now })?.caseId, "alpha-case");
  assert.equal(validateRemoteSession({ ...session, csrf: "short" }, { now }), null);
  assert.equal(validateRemoteSession({ ...session, extra: true }, { now }), null);

  const state = remoteState();
  assert.equal(validateRemoteState(state, { now, sessionRevision: 9 })?.codex.state, "waiting");
  assert.equal(validateRemoteState(state, { now, sessionRevision: 8 }), null);
  assert.equal(validateRemoteState({ ...state, privateReasoning: "CANARY" }, { now }), null);
  assert.equal(validateRemoteState({ ...state, validUntil: "2026-10-16T12:05:00.001Z" }, { now }), null);
  assert.equal(remoteStateIsFresh(state, { now: new Date("2026-10-16T12:04:59.000Z") }), true);
  assert.equal(remoteStateIsFresh(state, { now: new Date("2026-10-16T12:05:00.000Z") }), false);
  assert.equal(remoteStateIsFresh(state, { now: new Date("2026-10-16T12:05:00.001Z") }), false);

  const fleet = unavailableRemoteFleet();
  assert.equal(validateRemoteFleet(fleet, { now, sessionRevision: 9 })?.sessionRevision, 9);
  assert.equal(validateRemoteFleet(fleet, { now, sessionRevision: 10 }), null);
  assert.equal(validateRemoteFleet({ ...fleet, privateCase: "CANARY" }, { now }), null);

  const activity = {
    apiVersion: "gate.remote-cockpit-event/v1", sequence: 12, at: "2026-10-16T12:00:00.000Z",
    category: "testing", state: "progress", completed: 1, total: 2, tokens: null
  };
  assert.equal(validateRemoteActivityEvent(activity)?.sequence, 12);
  assert.equal(validateRemoteActivityEvent({ ...activity, output: "CANARY" }), null);

  assert.equal(validateRemoteConnection({
    apiVersion: "gate.remote-cockpit-connection/v1", state: "connected", at: "2026-10-16T12:00:00.000Z"
  }, { now })?.state, "connected");
  assert.equal(validateRemoteConnection({
    apiVersion: "gate.remote-cockpit-connection/v1", state: "unknown", at: "2026-10-16T12:00:00.000Z"
  }, { now }), null);

  const requestId = "req_00000000-0000-4000-8000-000000000000";
  const receipt = {
    apiVersion: "gate.remote-cockpit-receipt/v1", requestId, sessionRevision: 9,
    commandId: `cmd_${"a".repeat(36)}`, sequence: 3, status: "queued", acceptedAt: "2026-10-16T12:00:00.000Z"
  };
  assert.equal(validateRemoteQueuedReceipt(receipt, requestId, 9, { now })?.status, "queued");
  assert.equal(validateRemoteQueuedReceipt({ ...receipt, delivered: true }, requestId, 9, { now }), null);
  const command = {
    apiVersion: "gate.remote-command-event/v1", sequence: 13, at: "2026-10-16T12:00:01.000Z",
    requestId, commandId: receipt.commandId, state: "running"
  };
  assert.equal(validateRemoteCommandEvent(command, { now, acceptedAt: receipt.acceptedAt })?.state, "running");
  assert.equal(validateRemoteCommandEvent({ ...command, at: "2026-10-16T11:59:59.000Z" }, { now, acceptedAt: receipt.acceptedAt }), null);

  const statusRequest = {
    apiVersion: "gate.remote-command-status-request/v1",
    caseId: "alpha-case",
    sessionRevision: 9,
    commands: [{ requestId, commandId: receipt.commandId }]
  };
  assert.equal(validateRemoteCommandStatusRequest(statusRequest, {
    caseId: "alpha-case", sessionRevision: 9
  })?.commands.length, 1);
  const statusResponse = {
    apiVersion: "gate.remote-command-status-response/v1",
    caseId: "alpha-case",
    sessionRevision: 9,
    commands: [{ requestId, commandId: receipt.commandId, state: "completed" }]
  };
  assert.equal(validateRemoteCommandStatusResponse(statusResponse, statusRequest)?.commands[0].state, "completed");
  assert.equal(validateRemoteCommandStatusResponse({
    ...statusResponse,
    commands: [{ requestId, commandId: `cmd_${"b".repeat(36)}`, state: "completed" }]
  }, statusRequest), null);
});

test("remote fleet campaign context is exact, bounded, and state-consistent", async () => {
  const { validateRemoteFleet } = await import("../assets/model.js");
  const source = connectedRemoteFleet();
  const accepted = validateRemoteFleet(source, { now, sessionRevision: 9 });
  assert.equal(accepted?.campaigns[0].alias, "Campaign 1");
  assert.deepEqual(accepted?.campaigns[0].context, {
    label: "HackerOne CTF",
    nextSection: null
  });
  assert.equal(Object.isFrozen(accepted.campaigns[0].context), true);

  const campaign = source.campaigns[0];
  const { context: _context, ...withoutContext } = campaign;
  assert.equal(validateRemoteFleet({
    ...source,
    apiVersion: "gate.remote-fleet/v3"
  }, { now, sessionRevision: 9 }), null);
  assert.equal(validateRemoteFleet(connectedRemoteFleet({
    campaigns: [withoutContext]
  }), { now, sessionRevision: 9 }), null);
  assert.equal(validateRemoteFleet(connectedRemoteFleet({
    campaigns: [{ ...campaign, context: { ...campaign.context, extra: true } }]
  }), { now, sessionRevision: 9 }), null);
  assert.equal(validateRemoteFleet(connectedRemoteFleet({
    campaigns: [{ ...campaign, context: { label: null, nextSection: null } }]
  }), { now, sessionRevision: 9 })?.campaigns[0].context.label, null);

  const questionnaire = {
    ...campaign,
    context: { label: "Uber Bug Bounty", nextSection: "authority-sources" },
    kind: "profile",
    stage: "profile-questionnaire",
    state: "waiting",
    progress: { completed: 14, total: 70, percent: 20 }
  };
  assert.equal(validateRemoteFleet(connectedRemoteFleet({
    campaigns: [questionnaire]
  }), { now, sessionRevision: 9 })?.campaigns[0].context.nextSection, "authority-sources");

  for (const label of [
    " trailing space ",
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
    assert.equal(validateRemoteFleet(connectedRemoteFleet({
      campaigns: [{ ...campaign, context: { label, nextSection: null } }]
    }), { now, sessionRevision: 9 }), null);
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
    assert.equal(validateRemoteFleet(connectedRemoteFleet({
      campaigns: [invalidCampaign]
    }), { now, sessionRevision: 9 }), null);
  }
});

test("remote fleet blocker metrics stay bound to kind, stage, and visible aggregates", async () => {
  const { validateRemoteFleet } = await import("../assets/model.js");

  const caseFleet = connectedRemoteFleet();
  caseFleet.campaigns[0].work.setupBlockers = { value: 7, precision: "exact" };
  caseFleet.summary.setupBlockers = { value: 7, precision: "exact" };
  caseFleet.summary.blockers = { value: 7, precision: "exact" };
  assert.equal(validateRemoteFleet(caseFleet, { now, sessionRevision: 9 }), null);

  const questionnaire = connectedRemoteFleet();
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
  assert.equal(validateRemoteFleet(questionnaire, { now, sessionRevision: 9 }), null);

  const inconsistent = connectedRemoteFleet();
  inconsistent.summary.blockers = { value: 1, precision: "exact" };
  assert.equal(validateRemoteFleet(inconsistent, { now, sessionRevision: 9 }), null);

  const blocked = connectedRemoteFleet();
  blocked.campaigns[0].state = "blocked";
  blocked.summary.blockers = { value: 1, precision: "exact" };
  assert.equal(validateRemoteFleet(blocked, { now, sessionRevision: 9 })?.summary.blockers.value, 1);
});

test("remote JSON boundary rejects redirects, types, malformed lengths, and oversized bodies", async () => {
  const valid = new Response('{"ok":true}', { headers: { "content-type": "application/json" } });
  assert.deepEqual(await readRemoteJsonResponse(valid, 64), { ok: true });
  const samples = [
    new Response('{"ok":true}', { headers: { "content-type": "text/html" } }),
    new Response("{", { headers: { "content-type": "application/json" } }),
    new Response('"scalar"', { headers: { "content-type": "application/json" } }),
    new Response(" ".repeat(65), { headers: { "content-type": "application/json" } }),
    new Response('{"ok":true}', { status: 500, headers: { "content-type": "application/json" } })
  ];
  for (const response of samples) assert.equal(await readRemoteJsonResponse(response, 64), null);
  const redirected = new Response('{"ok":true}', { headers: { "content-type": "application/json" } });
  Object.defineProperty(redirected, "redirected", { value: true });
  assert.equal(await readRemoteJsonResponse(redirected, 64), null);
});

test("remote SSE frames use exact bounded cursor and control contracts", () => {
  assert.deepEqual(parseRemoteSseFrame(
    'event: ready\ndata: {"apiVersion":"gate.remote-events-ready/v1","cursor":4}'
  ), {
    id: null, name: "ready", value: { apiVersion: "gate.remote-events-ready/v1", cursor: 4 }
  });
  assert.deepEqual(parseRemoteSseFrame(
    'id: 2\nevent: resync\ndata: {"apiVersion":"gate.remote-resync/v1","cursor":2}'
  ), {
    id: 2, name: "resync", value: { apiVersion: "gate.remote-resync/v1", cursor: 2 }
  });
  assert.equal(parseRemoteSseFrame('id: 2\nevent: ready\ndata: {"cursor":2}'), null);
  assert.equal(parseRemoteSseFrame('event: activity\ndata: {}'), null);
  assert.equal(parseRemoteSseFrame('id: 01\nevent: activity\ndata: {}'), null);
  assert.equal(parseRemoteSseFrame('id: 1\nevent: activity\ndata: {}\ndata: {}'), null);
  assert.equal(parseRemoteSseFrame(`id: 1\nevent: activity\ndata: {"x":"${"a".repeat(200)}"}`, 64), null);
});


test("mirror freshness follows observations and attempt updates during long runs", () => {
  const clock = Date.parse("2026-10-20T12:05:00.000Z");
  const at = new Date(clock).toISOString();
  assert.equal(executionMirrorIsFresh({ startedAt: "2026-10-20T12:00:00.000Z", updatedAt: at }, at, clock), true);
  assert.equal(executionMirrorIsFresh({ updatedAt: at }, at, clock + 30_001), false);
  assert.equal(executionMirrorIsFresh({ updatedAt: new Date(clock - 30_001).toISOString() }, at, clock), false);
  assert.equal(executionMirrorIsFresh({ updatedAt: new Date(clock + 1).toISOString() }, at, clock), false);
  assert.equal(executionMirrorIsFresh({ updatedAt: at }, null, clock), false);
});
