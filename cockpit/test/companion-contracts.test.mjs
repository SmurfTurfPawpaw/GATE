import assert from "node:assert/strict";
import test from "node:test";

import {
  CompanionContractError,
  acceptedReceipt,
  normalizeDecisionRequest,
  normalizeMessageRequest,
  normalizeQuestionResponse,
  sanitizeActivityEvent
} from "../companion/contracts.mjs";

const generatedAt = "2026-10-16T14:00:00Z";
const requestId = "request-12345678";
const sessionRevision = 7;

test("normalizes the exact bounded local message contract", () => {
  const value = normalizeMessageRequest({
    apiVersion: "gate.local-message-request/v1",
    requestId,
    sessionRevision,
    message: "  Continue the reviewed mapping plan.  "
  });
  assert.equal(value.message, "Continue the reviewed mapping plan.");
  assert.deepEqual(acceptedReceipt(requestId), {
    apiVersion: "gate.local-cockpit-receipt/v1",
    requestId,
    status: "accepted"
  });
});

test("message contract rejects unknown fields, control characters, oversize text, and likely credentials", () => {
  const baseline = {
    apiVersion: "gate.local-message-request/v1",
    requestId,
    sessionRevision,
    message: "Continue"
  };
  const samples = [
    { ...baseline, target: "CANARY_TARGET" },
    { ...baseline, message: "bad\u0000text" },
    { ...baseline, message: "x".repeat(1_001) },
    { ...baseline, message: "api_key=CANARY_CREDENTIAL_123456789" },
    { ...baseline, message: "Bearer abcdefghijklmnopqrstuvwxyz" }
  ];
  for (const value of samples) {
    assert.throws(() => normalizeMessageRequest(value), CompanionContractError);
  }
  assert.equal(normalizeMessageRequest({ ...baseline, message: "Review https://example.test/program and continue." }).message,
    "Review https://example.test/program and continue.");
});

test("decision and local question replies use exact replay-bound contracts", () => {
  assert.deepEqual(normalizeDecisionRequest({
    apiVersion: "gate.local-decision-request/v1",
    requestId,
    decisionId: "dec_0123456789abcdef",
    decisionRevision: 2,
    snapshotGeneratedAt: generatedAt,
    choice: "recommended-depth"
  }), {
    apiVersion: "gate.local-decision-request/v1",
    requestId,
    decisionId: "dec_0123456789abcdef",
    decisionRevision: 2,
    snapshotGeneratedAt: generatedAt,
    choice: "recommended-depth"
  });

  const response = normalizeQuestionResponse({
    apiVersion: "gate.local-question-response/v1",
    requestId,
    sessionRevision,
    questionToken: `q_${"a".repeat(43)}`,
    answers: { priority: "Recommended" }
  });
  assert.equal(response.answers.priority, "Recommended");
});

test("activity projection is closed, categorical, and contains no source prose", () => {
  const event = sanitizeActivityEvent({
    category: "testing",
    state: "progress",
    completed: 3,
    total: 5,
    tokens: { total: 1200, contextWindow: 200000 },
    command: "CANARY_COMMAND",
    prompt: "CANARY_PROMPT",
    target: "CANARY_TARGET"
  }, 7, new Date(generatedAt));
  assert.deepEqual(event, {
    apiVersion: "gate.local-cockpit-event/v1",
    sequence: 7,
    at: "2026-10-16T14:00:00.000Z",
    category: "testing",
    state: "progress",
    completed: 3,
    total: 5,
    tokens: { total: 1200, contextWindow: 200000 }
  });
  const serialized = JSON.stringify(event);
  assert.doesNotMatch(serialized, /CANARY_(?:COMMAND|PROMPT|TARGET)/u);
  assert.equal(sanitizeActivityEvent({ category: "shell", state: "started" }, 8), null);
});
