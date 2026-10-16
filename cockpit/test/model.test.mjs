import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  hasAvailableFleetMetric,
  parsePublicSnapshot,
  publicCockpitModel,
  readPublicSnapshotResponse,
  toDisplayModel
} from "../assets/model.js";

const now = new Date("2026-10-16T12:00:00Z");

async function fixture() {
  return JSON.parse(await readFile(new URL("../data/status.json", import.meta.url), "utf8"));
}

async function observedFixture() {
  const value = await fixture();
  value.mode = "observed";
  value.snapshot.generatedAt = "2026-10-16T11:55:00Z";
  value.snapshot.validUntil = "2026-10-16T12:10:00Z";
  value.campaigns.forEach((campaign) => { campaign.freshness = "current"; });
  value.decision.expiresAt = "2026-10-16T12:05:00Z";
  return value;
}

test("accepts the exact gate.public-cockpit/v1 fixture", async () => {
  const parsed = parsePublicSnapshot(await fixture(), { now });
  assert.equal(parsed.kind, "available");
  assert.equal(parsed.schema, publicCockpitModel.schema);
  assert.equal(parsed.campaigns.length, 2);
  assert.equal(toDisplayModel(parsed).waitingCount, 1);
  assert.equal(toDisplayModel(parsed).mode, "preview");
  assert.equal(toDisplayModel(parsed).siteVersion, "0.2.0");
  assert.equal(toDisplayModel(parsed).gateVersion, "0.1.2");
});

test("preview is an explicit non-expiring, never-observed union", async () => {
  const preview = await fixture();
  assert.equal(parsePublicSnapshot(preview, { now }).mode, "preview");

  preview.snapshot.validUntil = "2026-10-16T12:10:00Z";
  assert.equal(parsePublicSnapshot(preview, { now }).kind, "unavailable");

  const observed = await observedFixture();
  observed.snapshot.validUntil = null;
  assert.equal(parsePublicSnapshot(observed, { now }).kind, "unavailable");

  const mismatchedFreshness = await observedFixture();
  mismatchedFreshness.campaigns[0].freshness = "preview";
  assert.equal(parsePublicSnapshot(mismatchedFreshness, { now }).kind, "unavailable");
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

test("stale snapshots fail closed without campaign or activity projection", async () => {
  const parsed = parsePublicSnapshot(await observedFixture(), { now: new Date("2026-10-16T12:11:00Z") });
  assert.deepEqual(parsed, { kind: "unavailable", reason: "stale" });
  const display = toDisplayModel(parsed);
  assert.deepEqual(display, { kind: "unavailable", reason: "stale" });
  assert.equal("campaigns" in display, false);
  assert.equal("activity" in display, false);
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

test("observed snapshots have a short TTL and bounded decision expiry", async () => {
  const long = await observedFixture();
  long.snapshot.validUntil = "2026-10-16T12:11:00Z";
  assert.equal(parsePublicSnapshot(long, { now }).kind, "unavailable");

  const badDecision = await observedFixture();
  badDecision.decision.expiresAt = "2026-10-16T12:11:00Z";
  assert.equal(parsePublicSnapshot(badDecision, { now }).kind, "unavailable");
});

test("bridge, messages, and receipts use exact bounded contracts", async () => {
  const { validateDecisionBridge, validateBridgeReceipt, validateOperatorMessage } = await import("../assets/model.js");
  const submitDecision = async () => undefined;
  const submitMessage = async () => undefined;
  const submitQuestion = async () => undefined;
  const bridge = { apiVersion: "gate.local-cockpit-bridge/v1", submitDecision, submitMessage, submitQuestion };
  assert.equal(validateDecisionBridge(bridge), bridge);
  assert.equal(validateDecisionBridge({ ...bridge, endpoint: "CANARY" }), null);
  assert.equal(validateDecisionBridge({ apiVersion: bridge.apiVersion, submitDecision, submitMessage }), null);

  assert.deepEqual(validateOperatorMessage("  hello\r\nGiovanni  "), { valid: true, message: "hello\nGiovanni", length: 14, bytes: 14 });
  assert.equal(validateOperatorMessage("Review https://example.test/program").valid, true);
  for (const invalid of ["", "x".repeat(1_001), `${"a\n".repeat(12)}b`, "bad\u0000text", "bad\u202Etext", "api_key=CANARY_CREDENTIAL_123456789", "Bearer abcdefghijklmnopqrstuvwxyz", "😀".repeat(1_001)]) {
    assert.equal(validateOperatorMessage(invalid).valid, false);
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
