import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";

import { CodexCompanionAdapter, appServerInternals } from "../companion/app-server.mjs";
import { ActivityStore } from "../companion/activity.mjs";

class FakeTransport extends EventEmitter {
  calls = [];
  responses = [];
  errors = [];
  started = false;
  usageResponse = {};

  async start() { this.started = true; }
  notify(method, params) { this.calls.push({ kind: "notify", method, params }); }
  async request(method, params) {
    this.calls.push({ kind: "request", method, params });
    if (method === "initialize") return { userAgent: "fixture" };
    if (method === "thread/start" || method === "thread/resume") {
      return { thread: { id: "thread-fixture", status: { type: "idle" } } };
    }
    if (method === "turn/start") return { turn: { id: "turn-1", status: "inProgress", items: [] } };
    if (method === "turn/steer") return { turnId: "turn-1" };
    if (method === "account/usage/read") return this.usageResponse;
    return {};
  }
  respond(id, result) { this.responses.push({ id, result }); }
  respondError(id, code, message) { this.errors.push({ id, code, message }); }
  async close() { this.emit("closed"); }
}

function message(messageText, id = "request-12345678") {
  return { requestId: id, message: messageText };
}

test("adapter creates one isolated app-server thread and starts or steers turns", async () => {
  const transport = new FakeTransport();
  const adapter = new CodexCompanionAdapter({ transport, cwd: process.cwd() });
  await adapter.connect();
  assert.equal(transport.started, true);
  assert.deepEqual(transport.calls.slice(0, 3).map((call) => [call.kind, call.method]), [
    ["request", "initialize"],
    ["notify", "initialized"],
    ["request", "thread/start"]
  ]);
  assert.deepEqual(transport.calls[2].params, {
    cwd: process.cwd(),
    ephemeral: true,
    threadSource: "gate-cockpit"
  });

  await adapter.sendMessage(message("Map the reviewed surface."));
  assert.equal(transport.calls.at(-1).method, "turn/start");
  assert.deepEqual(transport.calls.at(-1).params.input, [{ type: "text", text: "Map the reviewed surface." }]);
  await adapter.sendMessage(message("Prioritize the current lead.", "request-87654321"));
  assert.equal(transport.calls.at(-1).method, "turn/steer");
  assert.equal(transport.calls.at(-1).params.expectedTurnId, "turn-1");
  assert.equal(adapter.privateState().conversation.length, 2);
  assert.equal(adapter.activityStore.since().filter((entry) => entry.category === "thinking" && entry.state === "started").length, 0);
  transport.emit("notification", "turn/started", { threadId: "thread-fixture", turn: { id: "turn-1" } });
  assert.equal(adapter.activityStore.since().filter((entry) => entry.category === "thinking" && entry.state === "started").length, 1);
});

test("adapter projects only categorical tool activity and aggregate tokens", async () => {
  const transport = new FakeTransport();
  const activity = new ActivityStore();
  const adapter = new CodexCompanionAdapter({ transport, activityStore: activity });
  await adapter.connect();
  await adapter.sendMessage(message("Run the bounded checks."));

  transport.emit("notification", "item/started", {
    threadId: "thread-fixture",
    turnId: "turn-1",
    item: { type: "commandExecution", command: "CANARY_COMMAND", cwd: "/CANARY/PATH", id: "item-1", status: "inProgress" }
  });
  transport.emit("notification", "item/completed", {
    threadId: "thread-fixture",
    turnId: "turn-1",
    item: { type: "commandExecution", command: "CANARY_COMMAND", aggregatedOutput: "CANARY_OUTPUT", id: "item-1", status: "completed" }
  });
  transport.emit("notification", "thread/tokenUsage/updated", {
    threadId: "thread-fixture",
    turnId: "turn-1",
    tokenUsage: {
      total: {
        inputTokens: 250,
        cachedInputTokens: 120,
        outputTokens: 71,
        reasoningOutputTokens: 40,
        totalTokens: 321
      },
      modelContextWindow: 200000
    }
  });
  const serialized = JSON.stringify(activity.since());
  assert.match(serialized, /"category":"tool"/u);
  assert.match(serialized, /"total":321/u);
  assert.doesNotMatch(serialized, /CANARY_(?:COMMAND|OUTPUT)|\/CANARY\/PATH/u);
  assert.deepEqual(adapter.privateState().tokens, {
    availability: "exact",
    source: "codex-notification",
    input: 250,
    cachedInput: 120,
    output: 71,
    reasoningOutput: 40,
    total: 321,
    contextWindow: 200000,
    cost: { availability: "unavailable", amountMicros: null, unit: null }
  });
});

test("adapter projects estimated thread cost without account or thread metadata", async () => {
  const transport = new FakeTransport();
  transport.usageResponse = {
    threadUsage: {
      threadId: "thread-fixture",
      estimatedUsageCreditsMicros: 9000000,
      estimatedUsageUsdMicros: 12500,
      groups: [{ model: "PRIVATE_MODEL_CANARY", reasoningEffort: "PRIVATE_REASONING_CANARY" }]
    },
    summary: { lifetimeTokens: 999999999 },
    dailyUsageBuckets: [{ startDate: "PRIVATE_DATE_CANARY", tokens: 12 }]
  };
  const adapter = new CodexCompanionAdapter({ transport });
  await adapter.connect();
  await adapter.sendMessage(message("Measure the dedicated thread."));
  transport.emit("notification", "thread/tokenUsage/updated", {
    threadId: "thread-fixture",
    turnId: "turn-1",
    tokenUsage: {
      total: { inputTokens: 10, cachedInputTokens: 4, outputTokens: 5, reasoningOutputTokens: 2, totalTokens: 15 },
      modelContextWindow: 200000
    }
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(adapter.privateState().tokens.cost, {
    availability: "estimated", amountMicros: 12500, unit: "USD"
  });
  assert.doesNotMatch(JSON.stringify(adapter.privateState()), /thread-fixture|PRIVATE_|lifetimeTokens|dailyUsageBuckets/u);
});

test("adapter exposes final user-visible messages but never reasoning content", async () => {
  const transport = new FakeTransport();
  const adapter = new CodexCompanionAdapter({ transport });
  await adapter.connect();
  await adapter.sendMessage(message("Summarize visible results."));
  transport.emit("notification", "item/completed", {
    threadId: "thread-fixture",
    turnId: "turn-1",
    item: { type: "reasoning", id: "reasoning-1", content: [{ text: "CANARY_REASONING" }] }
  });
  transport.emit("notification", "item/completed", {
    threadId: "thread-fixture",
    turnId: "turn-1",
    item: { type: "agentMessage", id: "answer-1", text: "Three checks passed." }
  });
  const serialized = JSON.stringify(adapter.privateState());
  assert.match(serialized, /Three checks passed\./u);
  assert.doesNotMatch(serialized, /CANARY_REASONING/u);

  transport.emit("notification", "item/completed", {
    threadId: "thread-fixture",
    turnId: "turn-1",
    item: { type: "agentMessage", id: "answer-2", text: "api_key=CANARY_SECRET_123456789" }
  });
  assert.doesNotMatch(JSON.stringify(adapter.privateState()), /CANARY_SECRET/u);
});

test("bounded non-secret request_user_input questions can be answered through the adapter", async () => {
  const transport = new FakeTransport();
  const adapter = new CodexCompanionAdapter({ transport });
  await adapter.connect();
  await adapter.sendMessage(message("Ask for a bounded choice."));
  transport.emit("request", {
    id: 44,
    method: "item/tool/requestUserInput",
    params: {
      threadId: "thread-fixture",
      turnId: "turn-1",
      itemId: "question-1",
      isBlocking: true,
      questions: [{
        id: "priority",
        header: "Priority",
        question: "Which path should Codex take?",
        options: [
          { label: "Deep review (Recommended)", description: "Use the reviewed default." },
          { label: "Pause", description: "Wait for operator review." }
        ]
      }]
    }
  });
  const pending = adapter.privateState().pendingQuestions[0];
  assert.match(pending.token, /^q_[A-Za-z0-9_-]{43}$/u);
  await adapter.answerQuestion({
    questionToken: pending.token,
    answers: { priority: "Deep review (Recommended)" }
  });
  assert.deepEqual(transport.responses, [{
    id: 44,
    result: { answers: { priority: { answers: ["Deep review (Recommended)"] } } }
  }]);
  assert.equal(adapter.privateState().pendingQuestions.length, 0);
});

test("secret, free-form, malformed, and unrelated app-server requests stay out of the cockpit", async () => {
  const transport = new FakeTransport();
  const adapter = new CodexCompanionAdapter({ transport });
  await adapter.connect();
  await adapter.sendMessage(message("Ask for input."));
  transport.emit("request", {
    id: 45,
    method: "item/tool/requestUserInput",
    params: {
      threadId: "thread-fixture",
      turnId: "turn-1",
      itemId: "question-secret",
      isBlocking: true,
      questions: [{
        id: "credential",
        header: "Credential",
        question: "Enter a password",
        isSecret: true,
        options: [{ label: "One", description: "One" }, { label: "Two", description: "Two" }]
      }]
    }
  });
  transport.emit("request", { id: 46, method: "item/commandExecution/requestApproval", params: {} });
  assert.equal(adapter.privateState().pendingQuestions.length, 0);
  assert.deepEqual(transport.errors.map((entry) => entry.id), [45, 46]);
});

test("foreign threads, stale turns, and nonblocking questions cannot affect the dedicated session", async () => {
  const transport = new FakeTransport();
  const activity = new ActivityStore();
  const adapter = new CodexCompanionAdapter({ transport, activityStore: activity });
  await adapter.connect();
  await adapter.sendMessage(message("Keep this turn isolated."));
  const baseline = activity.since().length;

  transport.emit("notification", "item/started", {
    threadId: "thread-foreign",
    turnId: "turn-1",
    item: { type: "commandExecution", id: "foreign-item", status: "inProgress" }
  });
  transport.emit("notification", "item/started", {
    threadId: "thread-fixture",
    turnId: "turn-stale",
    item: { type: "commandExecution", id: "stale-item", status: "inProgress" }
  });
  assert.equal(activity.since().length, baseline);

  const question = {
    questions: [{
      id: "priority",
      header: "Priority",
      question: "Which path should Codex take?",
      options: [
        { label: "Deep review (Recommended)", description: "Use the reviewed default." },
        { label: "Pause", description: "Wait for operator review." }
      ]
    }],
    itemId: "question-isolation"
  };
  transport.emit("request", { id: 50, method: "item/tool/requestUserInput", params: { ...question, threadId: "thread-foreign", turnId: "turn-1", isBlocking: true } });
  transport.emit("request", { id: 51, method: "item/tool/requestUserInput", params: { ...question, threadId: "thread-fixture", turnId: "turn-stale", isBlocking: true } });
  transport.emit("request", { id: 52, method: "item/tool/requestUserInput", params: { ...question, threadId: "thread-fixture", turnId: "turn-1", isBlocking: false } });
  assert.deepEqual(transport.errors.slice(-3).map((entry) => entry.id), [50, 51, 52]);
  assert.equal(adapter.privateState().pendingQuestions.length, 0);
});

test("item categorization does not inspect command or tool prose", () => {
  assert.equal(appServerInternals.itemCategory("commandExecution"), "tool");
  assert.equal(appServerInternals.itemCategory("fileChange"), "file-change");
  assert.equal(appServerInternals.itemCategory("reasoning"), null);
});
