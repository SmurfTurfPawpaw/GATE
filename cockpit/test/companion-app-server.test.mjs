import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import path from "node:path";
import test from "node:test";

import { CodexCompanionAdapter, appServerInternals } from "../companion/app-server.mjs";
import { ActivityStore } from "../companion/activity.mjs";

const REMOTE_CODEX_HOME = path.resolve(".gate-test-remote-codex-home");

function remoteConfig(overrides = {}) {
  return {
    config: {
      mcp_servers: {},
      notify: [],
      web_search: "disabled",
      orchestrator: { mcp: { enabled: false } },
      features: Object.fromEntries(appServerInternals.REMOTE_DISABLED_FEATURES.map((feature) => [feature, false])),
      ...overrides
    }
  };
}

class FakeTransport extends EventEmitter {
  calls = [];
  responses = [];
  errors = [];
  started = false;
  usageResponse = {};
  threadResponse = null;
  configResponse = remoteConfig();
  initializeResponse = {
    userAgent: `gate-cockpit/${appServerInternals.REMOTE_CODEX_APP_SERVER_VERSION} fixture`,
    codexHome: REMOTE_CODEX_HOME
  };

  async start() { this.started = true; }
  notify(method, params) { this.calls.push({ kind: "notify", method, params }); }
  async request(method, params) {
    this.calls.push({ kind: "request", method, params });
    if (method === "initialize") return this.initializeResponse;
    if (method === "config/read") return this.configResponse;
    if (method === "thread/start" || method === "thread/resume") {
      return this.threadResponse ?? { thread: { id: "thread-fixture", status: { type: "idle" } } };
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
  assert.equal(adapter.threadId, null);
  await adapter.connect();
  assert.equal(adapter.threadId, "thread-fixture");
  assert.equal(transport.started, true);
  assert.deepEqual(transport.calls.slice(0, 3).map((call) => [call.kind, call.method]), [
    ["request", "initialize"],
    ["notify", "initialized"],
    ["request", "thread/start"]
  ]);
  assert.deepEqual(transport.calls[0].params, {
    clientInfo: { name: "gate-cockpit", title: "GATE Local Cockpit", version: "0.7.0" },
    capabilities: { experimentalApi: true }
  });
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

test("remote adapter pins and verifies a read-only posture on thread and turn start", async () => {
  const transport = new FakeTransport();
  const lifecycle = [];
  transport.threadResponse = {
    approvalPolicy: "never",
    sandbox: { type: "readOnly", networkAccess: false },
    thread: { id: "thread-fixture", status: { type: "idle" }, turns: [], environments: [] }
  };
  const adapter = new CodexCompanionAdapter({
    transport,
    cwd: process.cwd(),
    codexHome: REMOTE_CODEX_HOME,
    executionPosture: "remote-read-only",
    beforeThreadCreate: () => {
      assert.equal(transport.calls.at(-1).method, "config/read");
      lifecycle.push("creating");
    },
    afterThreadCreate: (threadId) => {
      assert.equal(transport.calls.at(-1).method, "thread/start");
      assert.equal(threadId, "thread-fixture");
      lifecycle.push("provisional");
    },
    beforeFirstTurn: (threadId) => {
      assert.equal(transport.calls.some((call) => call.method === "turn/start"), false);
      assert.equal(threadId, "thread-fixture");
      lifecycle.push("used");
    }
  });
  await adapter.connect();
  assert.deepEqual(lifecycle, ["creating", "provisional"]);
  assert.deepEqual(transport.calls[0].params, {
    clientInfo: { name: "gate-cockpit", title: "GATE Remote Cockpit", version: "0.7.0" },
    capabilities: { experimentalApi: true }
  });
  assert.deepEqual(transport.calls[2], {
    kind: "request",
    method: "config/read",
    params: { cwd: process.cwd(), includeLayers: false }
  });
  assert.deepEqual(transport.calls[3].params, {
    cwd: process.cwd(),
    ephemeral: true,
    threadSource: "gate-cockpit",
    approvalPolicy: "never",
    sandbox: "read-only",
    environments: [],
    dynamicTools: [],
    selectedCapabilityRoots: []
  });
  await adapter.sendMessage(message("Map the reviewed surface."));
  assert.deepEqual(lifecycle, ["creating", "provisional", "used"]);
  assert.deepEqual(transport.calls.at(-1).params, {
    threadId: "thread-fixture",
    clientUserMessageId: "request-12345678",
    input: [{ type: "text", text: "Map the reviewed surface." }],
    approvalPolicy: "never",
    sandboxPolicy: { type: "readOnly", networkAccess: false },
    environments: []
  });
});

test("remote adapter fails closed before thread creation when external tools remain configured", async () => {
  const configuredMcp = new FakeTransport();
  let creationPrepared = false;
  configuredMcp.configResponse = remoteConfig({
    mcp_servers: { unsafe: { command: "/bin/unsafe", enabled: true } }
  });
  await assert.rejects(new CodexCompanionAdapter({
    transport: configuredMcp,
    codexHome: REMOTE_CODEX_HOME,
    executionPosture: "remote-read-only",
    beforeThreadCreate: () => { creationPrepared = true; }
  }).connect(), /did not confirm the remote tool boundary/u);
  assert.equal(creationPrepared, false);
  assert.equal(configuredMcp.calls.some((call) => call.method === "thread/start"), false);

  const legacyNotify = new FakeTransport();
  legacyNotify.configResponse = remoteConfig({ notify: ["/bin/unsafe"] });
  await assert.rejects(new CodexCompanionAdapter({
    transport: legacyNotify,
    codexHome: REMOTE_CODEX_HOME,
    executionPosture: "remote-read-only"
  }).connect(), /did not confirm the remote tool boundary/u);
  assert.equal(legacyNotify.calls.some((call) => call.method === "thread/start"), false);

  const enabledApps = new FakeTransport();
  enabledApps.configResponse = remoteConfig({
    features: {
      ...remoteConfig().config.features,
      apps: true
    }
  });
  await assert.rejects(new CodexCompanionAdapter({
    transport: enabledApps,
    codexHome: REMOTE_CODEX_HOME,
    executionPosture: "remote-read-only"
  }).connect(), /did not confirm the remote tool boundary/u);
  assert.equal(enabledApps.calls.some((call) => call.method === "thread/start"), false);

  for (const feature of ["memories", "multi_agent_v2", "token_budget"]) {
    assert.throws(() => appServerInternals.assertRemoteToolBoundary(remoteConfig({
      features: {
        ...remoteConfig().config.features,
        [feature]: true
      }
    })), /did not confirm the remote tool boundary/u, feature);
  }

  const wrongHome = new FakeTransport();
  wrongHome.initializeResponse = {
    userAgent: `gate-cockpit/${appServerInternals.REMOTE_CODEX_APP_SERVER_VERSION} fixture`,
    codexHome: path.resolve(".ambient-codex-home")
  };
  await assert.rejects(new CodexCompanionAdapter({
    transport: wrongHome,
    codexHome: REMOTE_CODEX_HOME,
    executionPosture: "remote-read-only"
  }).connect(), /did not use the dedicated remote Codex home/u);
  assert.equal(wrongHome.calls.some((call) => call.method === "config/read"), false);

  const wrongVersion = new FakeTransport();
  wrongVersion.initializeResponse = { userAgent: "gate-cockpit/0.0.0 fixture", codexHome: REMOTE_CODEX_HOME };
  await assert.rejects(new CodexCompanionAdapter({
    transport: wrongVersion,
    codexHome: REMOTE_CODEX_HOME,
    executionPosture: "remote-read-only"
  }).connect(), /requires app-server 0\.159\.2/u);
  assert.equal(wrongVersion.calls.some((call) => call.method === "config/read"), false);
});

test("remote lifecycle callbacks fail closed before their corresponding app-server request", async () => {
  const beforeCreate = new FakeTransport();
  await assert.rejects(new CodexCompanionAdapter({
    transport: beforeCreate,
    codexHome: REMOTE_CODEX_HOME,
    executionPosture: "remote-read-only",
    beforeThreadCreate: () => { throw new Error("record unavailable"); }
  }).connect(), /record unavailable/u);
  assert.equal(beforeCreate.calls.some((call) => call.method === "thread/start"), false);

  const beforeTurn = new FakeTransport();
  beforeTurn.threadResponse = {
    approvalPolicy: "never",
    sandbox: { type: "readOnly", networkAccess: false },
    thread: { id: "thread-fixture", status: { type: "idle" }, turns: [], environments: [] }
  };
  const adapter = new CodexCompanionAdapter({
    transport: beforeTurn,
    codexHome: REMOTE_CODEX_HOME,
    executionPosture: "remote-read-only",
    beforeFirstTurn: () => { throw new Error("use record unavailable"); }
  });
  await adapter.connect();
  await assert.rejects(adapter.sendMessage(message("Do not dispatch this.")), /use record unavailable/u);
  assert.equal(beforeTurn.calls.some((call) => call.method === "turn/start"), false);

  assert.throws(() => new CodexCompanionAdapter({
    beforeThreadCreate: () => {}
  }), /requires the remote Codex posture/u);
});

test("remote app-server launch arguments disable every non-host tool source", async () => {
  const pinnedCommand = path.resolve("fixture-codex");
  let command;
  let args;
  const adapter = new CodexCompanionAdapter({
    codexHome: REMOTE_CODEX_HOME,
    command: pinnedCommand,
    executionPosture: "remote-read-only",
    spawnProcess: (actualCommand, actualArgs) => {
      command = actualCommand;
      args = actualArgs;
      throw new Error("launch captured");
    }
  });
  await assert.rejects(adapter.connect(), /launch captured/u);
  assert.equal(appServerInternals.REMOTE_CODEX_APP_SERVER_VERSION, "0.159.2");
  assert.equal(command, pinnedCommand);
  assert.deepEqual(args.slice(0, 3), ["app-server", "--stdio", "--strict-config"]);
  for (const feature of [
    "apps", "browser_use", "browser_use_external", "browser_use_full_cdp_access",
    "code_mode", "code_mode_host", "computer_use", "enable_mcp_apps", "hooks",
    "image_generation", "in_app_browser", "in_app_local_automation", "memories",
    "multi_agent", "multi_agent_v2", "plugins", "remote_plugin",
    "shell_snapshot", "shell_snapshot_v2", "shell_tool", "skill_search",
    "skill_mcp_dependency_install", "sleep_tool", "token_budget", "tool_suggest",
    "unified_exec", "unified_exec_tty", "view_image", "workspace_dependencies", "worktrees"
  ]) {
    const index = args.findIndex((value, position) => value === "--disable" && args[position + 1] === feature);
    assert.notEqual(index, -1, `missing disabled feature ${feature}`);
  }
  assert.ok(args.includes('web_search="disabled"'));
  assert.ok(args.includes("tools.web_search=false"));
  assert.ok(args.includes("notify=[]"));
  assert.ok(args.includes("orchestrator.mcp.enabled=false"));
  assert.throws(() => new CodexCompanionAdapter({
    codexHome: REMOTE_CODEX_HOME,
    executionPosture: "remote-read-only"
  }), /requires a pinned absolute executable/u);
  assert.throws(() => new CodexCompanionAdapter({
    codexHome: REMOTE_CODEX_HOME,
    command: "codex",
    executionPosture: "remote-read-only"
  }), /requires a pinned absolute executable/u);
  assert.throws(() => new CodexCompanionAdapter({
    codexHome: REMOTE_CODEX_HOME,
    command: pinnedCommand,
    executionPosture: "remote-read-only",
    args: ["app-server", "--stdio"]
  }), /arguments are fixed/u);
});

test("remote adapter rejects unconfirmed posture and an active resumed turn", async () => {
  const unconfirmed = new FakeTransport();
  unconfirmed.threadResponse = {
    approvalPolicy: "on-request",
    sandbox: { type: "workspaceWrite" },
    thread: { id: "thread-fixture", status: { type: "idle" }, turns: [], environments: [] }
  };
  await assert.rejects(
    new CodexCompanionAdapter({
      transport: unconfirmed,
      codexHome: REMOTE_CODEX_HOME,
      executionPosture: "remote-read-only"
    }).connect(),
    /did not confirm the remote read-only posture/u
  );

  const active = new FakeTransport();
  active.threadResponse = {
    approvalPolicy: "never",
    sandbox: { type: "readOnly", networkAccess: false },
    thread: {
      id: "thread-fixture",
      status: { type: "active" },
      environments: [],
      turns: [{ id: "turn-existing", status: "inProgress" }]
    }
  };
  const adapter = new CodexCompanionAdapter({
    transport: active,
    threadId: "thread-fixture",
    codexHome: REMOTE_CODEX_HOME,
    executionPosture: "remote-read-only"
  });
  await assert.rejects(adapter.connect(), /active turn with unknown posture/u);
  assert.deepEqual(active.calls[3].params, {
    threadId: "thread-fixture",
    cwd: process.cwd(),
    approvalPolicy: "never",
    sandbox: "read-only"
  });
  assert.equal(active.calls.some((call) => call.method === "turn/steer"), false);

  const wrongThread = new FakeTransport();
  wrongThread.threadResponse = {
    approvalPolicy: "never",
    sandbox: { type: "readOnly", networkAccess: false },
    thread: { id: "thread-different", status: { type: "idle" }, turns: [], environments: [] }
  };
  await assert.rejects(new CodexCompanionAdapter({
    transport: wrongThread,
    threadId: "thread-fixture",
    codexHome: REMOTE_CODEX_HOME,
    executionPosture: "remote-read-only"
  }).connect(), /resumed a different thread/u);
  assert.equal(wrongThread.calls.some((call) => call.method === "thread/start"), false);
});

test("resumed threads hydrate only bounded visible conversation with explicit omissions", async () => {
  const transport = new FakeTransport();
  transport.threadResponse = {
    approvalPolicy: "never",
    sandbox: { type: "readOnly", networkAccess: false },
    turnsBackwardsCursor: "older-turns",
    thread: {
      id: "thread-fixture",
      status: { type: "idle" },
      environments: [],
      turns: [{
        id: "turn-history",
        status: "completed",
        completedAt: 1_700_000_000,
        itemsView: "full",
        items: [
          { id: "user-1", type: "userMessage", content: [{ type: "text", text: "Previous request" }] },
          { id: "agent-1", type: "agentMessage", phase: "final_answer", text: "Previous answer" },
          { id: "agent-long", type: "agentMessage", phase: "final_answer", text: "x".repeat(4_001) },
          { id: "reasoning-1", type: "reasoning", summary: ["CANARY_REASONING"] }
        ]
      }]
    }
  };
  const adapter = new CodexCompanionAdapter({
    transport,
    threadId: "thread-fixture",
    codexHome: REMOTE_CODEX_HOME,
    executionPosture: "remote-read-only"
  });
  await adapter.connect();
  const conversation = adapter.privateState().conversation;
  assert.deepEqual(conversation.map((entry) => entry.text), [
    appServerInternals.HISTORY_UNAVAILABLE_NOTICE,
    appServerInternals.HISTORY_MESSAGE_OMITTED_NOTICE,
    "Previous request",
    "Previous answer"
  ]);
  assert.deepEqual(conversation.slice(2).map((entry) => entry.role), ["operator", "codex"]);
  assert.equal(JSON.stringify(conversation).includes("CANARY_REASONING"), false);
  assert.equal(conversation[2].at, "2023-11-14T22:13:20.000Z");

  const many = appServerInternals.historyConversation({
    thread: {
      turns: [{
        id: "turn-many",
        status: "completed",
        itemsView: "full",
        items: Array.from({ length: 60 }, (_, index) => ({
          id: `agent-${index}`,
          type: "agentMessage",
          text: `Message ${index}`
        }))
      }]
    }
  }, "2026-10-18T00:00:00.000Z");
  assert.equal(many.length, appServerInternals.MAX_CONVERSATION_ENTRIES);
  assert.equal(many[0].text, appServerInternals.HISTORY_TRUNCATED_NOTICE);
  assert.equal(many.at(-1).text, "Message 59");
});

test("adapter emits one closed signal when its app-server transport closes", async () => {
  const transport = new FakeTransport();
  const adapter = new CodexCompanionAdapter({ transport });
  let closed = 0;
  adapter.on("closed", () => { closed += 1; });
  await adapter.connect();
  transport.emit("closed");
  transport.emit("closed");
  assert.equal(closed, 1);
  assert.equal(adapter.privateState().connected, false);
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

  transport.emit("notification", "item/completed", {
    threadId: "thread-fixture",
    turnId: "turn-1",
    item: { type: "agentMessage", id: "answer-long", text: "x".repeat(4_001) }
  });
  assert.equal(adapter.privateState().conversation.at(-1).text,
    appServerInternals.HISTORY_MESSAGE_OMITTED_NOTICE);

  for (let index = 0; index < 50; index += 1) {
    transport.emit("notification", "item/completed", {
      threadId: "thread-fixture",
      turnId: "turn-1",
      item: { type: "agentMessage", id: `bounded-${index}`, text: `Bounded ${index}` }
    });
  }
  const bounded = adapter.privateState().conversation;
  assert.equal(bounded.length, appServerInternals.MAX_CONVERSATION_ENTRIES);
  assert.equal(bounded[0].text, appServerInternals.HISTORY_TRUNCATED_NOTICE);
  assert.equal(bounded.at(-1).text, "Bounded 49");
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

test("a failed question response remains pending and can be retried", async () => {
  const transport = new FakeTransport();
  const adapter = new CodexCompanionAdapter({ transport });
  await adapter.connect();
  await adapter.sendMessage(message("Ask for a bounded choice."));
  transport.emit("request", {
    id: 54,
    method: "item/tool/requestUserInput",
    params: {
      threadId: "thread-fixture",
      turnId: "turn-1",
      itemId: "question-retry",
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
  const originalRespond = transport.respond.bind(transport);
  transport.respond = () => { throw new Error("transport unavailable"); };

  const response = {
    questionToken: pending.token,
    answers: { priority: "Deep review (Recommended)" }
  };
  await assert.rejects(adapter.answerQuestion(response), /transport unavailable/u);
  assert.equal(adapter.privateState().pendingQuestions.length, 1);

  transport.respond = originalRespond;
  await adapter.answerQuestion(response);
  assert.equal(adapter.privateState().pendingQuestions.length, 0);
  assert.deepEqual(transport.responses, [{
    id: 54,
    result: { answers: { priority: { answers: ["Deep review (Recommended)"] } } }
  }]);
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
