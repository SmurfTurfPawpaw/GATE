import assert from "node:assert/strict";
import crypto from "node:crypto";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { ActivityStore } from "../../companion/activity.mjs";
import {
  REMOTE_MESSAGE_VERSION,
  REMOTE_QUESTION_VERSION,
  digestRemotePayload
} from "../contracts.mjs";
import { MemoryRunnerNonceStore, verifyRunnerRequest } from "../runner-auth.mjs";
import { runnerCliInternals } from "../runner-cli.mjs";
import {
  RemoteCockpitRunner,
  projectRemoteFleet,
  projectRemoteState,
  remoteRunnerInternals
} from "../runner.mjs";

const RUNNER_ID = "runner_test_01";
const CASE_ID = "case-one";
const SESSION_REVISION = 7;
const NOW = Date.parse("2026-10-18T02:00:00.000Z");

function ownerDirectory(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "gate-remote-runner-"));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function response(value) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "content-type": "application/json; charset=utf-8" }
  });
}

function ack() {
  return response({
    apiVersion: remoteRunnerInternals.ACK_VERSION,
    acceptedAt: new Date(NOW).toISOString()
  });
}

function localState(overrides = {}) {
  return {
    apiVersion: "gate.local-companion-state/v1",
    sessionRevision: 991,
    stateRevision: 4,
    observedAt: new Date(NOW).toISOString(),
    connected: true,
    turn: "idle",
    tokens: null,
    conversation: [],
    pendingQuestions: [],
    threadId: "must-not-cross",
    privatePath: "/private/must-not-cross",
    ...overrides
  };
}

function unavailableFleet(overrides = {}) {
  return {
    apiVersion: "gate.local-fleet/v1",
    revision: 1,
    observedAt: null,
    receivedAt: new Date(NOW).toISOString(),
    connection: "unavailable",
    sourceFreshness: "unavailable",
    coverage: {
      state: "unavailable",
      cases: {
        availability: "unavailable", discovered: null, scanned: null, omitted: null, invalid: null,
        discoveredAtLeast: false, omittedAtLeast: false, complete: false, truncated: true
      },
      profiles: {
        availability: "unavailable", discovered: null, scanned: null, omitted: null, invalid: null,
        discoveredAtLeast: false, omittedAtLeast: false, complete: false, truncated: true,
        visible: null, representedByCases: null
      }
    },
    summary: {
      campaigns: { value: null, precision: "unavailable" },
      active: { value: null, precision: "unavailable" },
      waiting: { value: null, precision: "unavailable" },
      attention: { value: null, precision: "unavailable" },
      profileAnswers: { answered: null, total: null, precision: "unavailable" },
      runningExecutions: { value: null, precision: "unavailable" },
      activeWorkflows: { value: null, precision: "unavailable" },
      runningAnalyses: { value: null, precision: "unavailable" },
      setupBlockers: { value: null, precision: "unavailable" },
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

function adapter(overrides = {}) {
  const activityStore = new ActivityStore();
  const calls = [];
  return {
    activityStore,
    calls,
    connected: 0,
    closed: 0,
    connect: async function connect() { this.connected += 1; },
    close: async function close() { this.closed += 1; },
    privateState: () => localState(),
    sendMessage: async (value) => { calls.push(["message", value]); },
    answerQuestion: async (value) => { calls.push(["question", value]); },
    ...overrides
  };
}

function command(kind, payload, suffix = "AAAAAAAAAAAAAAAA") {
  return {
    commandId: `cmd_${suffix}`,
    kind,
    payloadSha256: digestRemotePayload(payload),
    payload,
    issuedAt: new Date(NOW - 1_000).toISOString(),
    expiresAt: new Date(NOW + 120_000).toISOString(),
    lease: {
      leaseId: `lease_${suffix}`,
      expiresAt: new Date(NOW + 30_000).toISOString()
    }
  };
}

function runnerOptions(t, values = {}) {
  const keys = crypto.generateKeyPairSync("ed25519");
  let nonce = 0;
  return {
    options: {
      controlPlaneUrl: "https://gate.example.test",
      runnerId: RUNNER_ID,
      caseId: CASE_ID,
      sessionRevision: SESSION_REVISION,
      privateKey: keys.privateKey,
      adapter: values.adapter ?? adapter(),
      journalDirectory: values.journalDirectory ?? ownerDirectory(t),
      clock: values.clock ?? (() => NOW),
      random: values.random ?? (() => 0.5),
      nonceFactory: () => `${String(++nonce).padStart(32, "A")}`,
      requestTimeoutMs: 5_000,
      pollIntervalMs: 10,
      heartbeatIntervalMs: 100,
      projectionIntervalMs: 100,
      fleetIntervalMs: 100,
      backoffBaseMs: 20,
      backoffMaxMs: 80,
      ...values.options
    },
    publicKey: keys.publicKey
  };
}

function signedControlPlane({ publicKey, commandValue, onTerminal, requests }) {
  const nonceStore = new MemoryRunnerNonceStore({ now: () => NOW });
  let leased = false;
  return async (urlValue, init) => {
    const url = new URL(urlValue);
    const body = Buffer.from(init.body, "utf8");
    const verified = await verifyRunnerRequest({
      headers: Object.entries(init.headers),
      publicKeys: new Map([[RUNNER_ID, publicKey]]),
      nonceStore,
      method: init.method,
      path: url.pathname,
      body,
      now: () => NOW
    });
    assert.equal(verified.runnerId, RUNNER_ID);
    assert.equal(url.protocol, "https:");
    assert.equal(init.redirect, "error");
    assert.equal(init.headers.Accept, "application/json");
    assert.equal(init.headers["Content-Type"], "application/json");
    const value = JSON.parse(init.body);
    requests.push({ path: url.pathname, value, headers: init.headers });
    if (url.pathname.endsWith("/lease")) {
      const leasedCommand = leased ? null : commandValue;
      leased = true;
      return response({ apiVersion: remoteRunnerInternals.LEASE_RESPONSE_VERSION, command: leasedCommand });
    }
    if (url.pathname.endsWith("/transition")) {
      if (value.state === "completed" || value.state === "failed") onTerminal?.(value.state);
      return ack();
    }
    return ack();
  };
}

test("runner signs every request and dispatches one message through the exact lifecycle", async (t) => {
  const selectedAdapter = adapter();
  const payload = {
    apiVersion: REMOTE_MESSAGE_VERSION,
    requestId: "request-message-01",
    sessionRevision: SESSION_REVISION,
    message: "Continue with the reviewed plan."
  };
  const requests = [];
  const prepared = runnerOptions(t, { adapter: selectedAdapter });
  let runner;
  prepared.options.fetch = signedControlPlane({
    publicKey: prepared.publicKey,
    commandValue: command("message", payload),
    requests,
    onTerminal: () => queueMicrotask(() => { void runner.stop(); })
  });
  prepared.options.delay = async () => {};
  runner = new RemoteCockpitRunner(prepared.options);
  await runner.start();

  assert.deepEqual(selectedAdapter.calls, [["message", payload]]);
  assert.deepEqual(requests.filter((item) => item.path.endsWith("/transition"))
    .map((item) => item.value.state), ["accepted", "running", "completed"]);
  assert.ok(requests.every((item) => typeof item.headers["X-GATE-Signature"] === "string"));
  assert.equal(requests.filter((item) => item.path.endsWith("/lease")).length, 1);
  assert.deepEqual(requests.find((item) => item.path.endsWith("/lease")).value, {
    apiVersion: remoteRunnerInternals.LEASE_REQUEST_VERSION,
    caseId: CASE_ID,
    sessionRevision: SESSION_REVISION
  });
  assert.equal(selectedAdapter.connected, 1);
  assert.equal(selectedAdapter.closed, 1);
});

test("runner safely retries an idempotent lease-bound transition after a lost response", async (t) => {
  const selectedAdapter = adapter();
  const payload = {
    apiVersion: REMOTE_MESSAGE_VERSION,
    requestId: "request-retry-001",
    sessionRevision: SESSION_REVISION,
    message: "Run this once after the retry."
  };
  const requests = [];
  const prepared = runnerOptions(t, { adapter: selectedAdapter });
  let runner;
  const controlPlane = signedControlPlane({
    publicKey: prepared.publicKey,
    commandValue: command("message", payload, "DDDDDDDDDDDDDDDD"),
    requests,
    onTerminal: () => queueMicrotask(() => { void runner.stop(); })
  });
  let responseLost = false;
  prepared.options.fetch = async (url, init) => {
    const result = await controlPlane(url, init);
    const body = JSON.parse(init.body);
    if (!responseLost && new URL(url).pathname.endsWith("/transition") && body.state === "accepted") {
      responseLost = true;
      throw new Error("response lost after commit");
    }
    return result;
  };
  prepared.options.delay = async () => {};
  runner = new RemoteCockpitRunner(prepared.options);
  await runner.start();

  assert.equal(selectedAdapter.calls.length, 1);
  assert.deepEqual(requests.filter((item) => item.path.endsWith("/transition"))
    .map((item) => item.value.state), ["accepted", "accepted", "running", "completed"]);
});

test("runner renews a short lease until slow adapter delivery reaches a terminal acknowledgement", async (t) => {
  const payload = {
    apiVersion: REMOTE_MESSAGE_VERSION,
    requestId: "request-slow-delivery-01",
    sessionRevision: SESSION_REVISION,
    message: "Wait for the local adapter to accept this exactly once."
  };
  const leased = command("message", payload, "LLLLLLLLLLLLLLLL");
  leased.lease.expiresAt = new Date(NOW + 1_000).toISOString();
  const selectedAdapter = adapter({
    sendMessage: async (value) => {
      selectedAdapter.calls.push(["message", value]);
      await new Promise((resolve) => setTimeout(resolve, 1_100));
    }
  });
  const requests = [];
  const prepared = runnerOptions(t, { adapter: selectedAdapter });
  let runner;
  prepared.options.fetch = signedControlPlane({
    publicKey: prepared.publicKey,
    commandValue: leased,
    requests,
    onTerminal: () => queueMicrotask(() => { void runner.stop(); })
  });
  prepared.options.delay = async () => {};
  runner = new RemoteCockpitRunner(prepared.options);
  await runner.start();

  assert.equal(selectedAdapter.calls.length, 1);
  const transitions = requests.filter((item) => item.path.endsWith("/transition"))
    .map((item) => item.value.state);
  assert.deepEqual(transitions.slice(0, 2), ["accepted", "running"]);
  assert.ok(transitions.slice(2, -1).every((state) => state === "renewed"));
  assert.ok(transitions.includes("renewed"));
  assert.equal(transitions.at(-1), "completed");
});

test("a terminal acknowledgement remains authoritative when an in-flight renewal is rejected afterward", async (t) => {
  const payload = {
    apiVersion: REMOTE_MESSAGE_VERSION,
    requestId: "request-terminal-renewal-race-01",
    sessionRevision: SESSION_REVISION,
    message: "Finalize once even when the renewal response arrives late."
  };
  const leased = command("message", payload, "RRRRRRRRRRRRRRRR");
  leased.lease.expiresAt = new Date(NOW + 1_000).toISOString();
  let renewalObserved;
  const renewalStarted = new Promise((resolve) => { renewalObserved = resolve; });
  const selectedAdapter = adapter({ sendMessage: async () => renewalStarted });
  const requests = [];
  const responseOrder = [];
  const prepared = runnerOptions(t, { adapter: selectedAdapter });
  let runner;
  const controlPlane = signedControlPlane({
    publicKey: prepared.publicKey,
    commandValue: leased,
    requests,
    onTerminal: () => queueMicrotask(() => { void runner.stop(); })
  });
  let releaseRenewal;
  prepared.options.fetch = async (url, init) => {
    const result = await controlPlane(url, init);
    const route = new URL(url).pathname;
    const value = JSON.parse(init.body);
    if (route.endsWith("/transition") && value.state === "renewed") {
      renewalObserved();
      return new Promise((resolve) => { releaseRenewal = resolve; });
    }
    if (route.endsWith("/transition") && value.state === "completed") {
      responseOrder.push("completed");
      setImmediate(() => {
        responseOrder.push("renewed");
        releaseRenewal(new Response("{}", {
          status: 409,
          headers: { "content-type": "application/json; charset=utf-8" }
        }));
      });
    }
    return result;
  };
  prepared.options.delay = async () => {};
  runner = new RemoteCockpitRunner(prepared.options);
  await runner.start();

  assert.deepEqual(responseOrder, ["completed", "renewed"]);
  assert.deepEqual(requests.filter((item) => item.path.endsWith("/transition"))
    .map((item) => item.value.state), ["accepted", "running", "renewed", "completed"]);
});

test("runner stops before leasing when its connected adapter closes", async (t) => {
  let connected = true;
  const selectedAdapter = Object.assign(new EventEmitter(), adapter({
    privateState: () => localState({ connected })
  }));
  const requests = [];
  const prepared = runnerOptions(t, { adapter: selectedAdapter });
  const controlPlane = signedControlPlane({
    publicKey: prepared.publicKey,
    commandValue: null,
    requests
  });
  prepared.options.fetch = async (url, init) => {
    const result = await controlPlane(url, init);
    if (new URL(url).pathname.endsWith("/heartbeat")) {
      connected = false;
      selectedAdapter.emit("closed");
    }
    return result;
  };
  prepared.options.delay = async () => {};
  const runner = new RemoteCockpitRunner(prepared.options);

  await assert.rejects(runner.start(), (error) => error?.code === "adapter-unavailable");
  assert.equal(requests.some((item) => item.path.endsWith("/lease")), false);
  assert.equal(selectedAdapter.closed, 1);
});

test("adapter death during delivery never reports the command failed or leases another command", async (t) => {
  let connected = true;
  const selectedAdapter = Object.assign(new EventEmitter(), adapter({
    privateState: () => localState({ connected }),
    sendMessage: async () => {
      connected = false;
      selectedAdapter.emit("closed");
      throw new Error("private app-server failure");
    }
  }));
  const payload = {
    apiVersion: REMOTE_MESSAGE_VERSION,
    requestId: "request-adapter-death-01",
    sessionRevision: SESSION_REVISION,
    message: "Do not consume another command after the adapter exits."
  };
  const requests = [];
  const prepared = runnerOptions(t, { adapter: selectedAdapter });
  prepared.options.fetch = signedControlPlane({
    publicKey: prepared.publicKey,
    commandValue: command("message", payload, "XXXXXXXXXXXXXXXX"),
    requests
  });
  prepared.options.delay = async () => {};
  const runner = new RemoteCockpitRunner(prepared.options);

  await assert.rejects(runner.start(), (error) => error?.code === "adapter-unavailable");
  assert.deepEqual(requests.filter((item) => item.path.endsWith("/transition"))
    .map((item) => item.value.state), ["accepted", "running"]);
  assert.equal(requests.filter((item) => item.path.endsWith("/lease")).length, 1);
});

test("a command durably accepted by a prior runner is failed without replay after restart", async (t) => {
  const directory = ownerDirectory(t);
  const keys = crypto.generateKeyPairSync("ed25519");
  const payload = {
    apiVersion: REMOTE_MESSAGE_VERSION,
    requestId: "request-restart-01",
    sessionRevision: SESSION_REVISION,
    message: "This must run once."
  };
  const leased = command("message", payload, "BBBBBBBBBBBBBBBB");
  let nonce = 0;

  const run = async (selectedAdapter, expectedTerminal) => {
    const requests = [];
    let runner;
    const fetch = signedControlPlane({
      publicKey: keys.publicKey,
      commandValue: leased,
      requests,
      onTerminal: (state) => {
        if (state === expectedTerminal) queueMicrotask(() => { void runner.stop(); });
      }
    });
    runner = new RemoteCockpitRunner({
      ...runnerOptions(t, { adapter: selectedAdapter, journalDirectory: directory }).options,
      privateKey: keys.privateKey,
      nonceFactory: () => `${String(++nonce).padStart(32, "B")}`,
      fetch,
      delay: async () => {}
    });
    await runner.start();
    return requests;
  };

  const firstAdapter = adapter();
  const first = await run(firstAdapter, "completed");
  assert.equal(firstAdapter.calls.length, 1);
  assert.deepEqual(first.filter((item) => item.path.endsWith("/transition")).map((item) => item.value.state),
    ["accepted", "running", "completed"]);

  const restartedAdapter = adapter();
  const second = await run(restartedAdapter, "failed");
  assert.equal(restartedAdapter.calls.length, 0);
  assert.deepEqual(second.filter((item) => item.path.endsWith("/transition")).map((item) => item.value.state),
    ["accepted", "failed"]);
});

test("journal retention prunes only the oldest terminal entry and preserves in-flight dedupe", async (t) => {
  const directory = ownerDirectory(t);
  const accepted = Array.from({ length: remoteRunnerInternals.MAX_JOURNAL_ENTRIES }, (_, index) => ({
    commandId: `cmd_${index.toString(36).padStart(16, "0")}`,
    payloadSha256: "a".repeat(64),
    acceptedAt: new Date(NOW - index).toISOString(),
    terminalState: index === 0 ? null : "completed"
  }));
  const journalFile = path.join(directory, "remote-runner-journal.json");
  fs.writeFileSync(journalFile, `${JSON.stringify({
    apiVersion: remoteRunnerInternals.JOURNAL_VERSION,
    runnerId: RUNNER_ID,
    caseId: CASE_ID,
    sessionRevision: SESSION_REVISION,
    projectionRevisions: { state: 0, fleet: 0 },
    accepted
  })}\n`, { mode: 0o600 });

  const selectedAdapter = adapter();
  const payload = {
    apiVersion: REMOTE_MESSAGE_VERSION,
    requestId: "request-retain-001",
    sessionRevision: SESSION_REVISION,
    message: "Retain the in-flight replay guard."
  };
  const requests = [];
  const prepared = runnerOptions(t, { adapter: selectedAdapter, journalDirectory: directory });
  let runner;
  prepared.options.fetch = signedControlPlane({
    publicKey: prepared.publicKey,
    commandValue: command("message", payload, "EEEEEEEEEEEEEEEE"),
    requests,
    onTerminal: () => queueMicrotask(() => { void runner.stop(); })
  });
  prepared.options.delay = async () => {};
  runner = new RemoteCockpitRunner(prepared.options);
  await runner.start();

  const saved = JSON.parse(fs.readFileSync(journalFile, "utf8"));
  assert.equal(saved.accepted.length, remoteRunnerInternals.MAX_JOURNAL_ENTRIES);
  assert.ok(saved.accepted.some((entry) => entry.commandId === "cmd_0000000000000000" && entry.terminalState === null));
  assert.equal(saved.accepted.some((entry) => entry.commandId === "cmd_0000000000000001"), false);
  assert.ok(saved.accepted.some((entry) => entry.commandId === "cmd_EEEEEEEEEEEEEEEE"
    && entry.terminalState === "completed"));
});

test("runner dispatches a bounded question response to the adapter", async (t) => {
  const selectedAdapter = adapter();
  const payload = {
    apiVersion: REMOTE_QUESTION_VERSION,
    requestId: "request-question-01",
    sessionRevision: SESSION_REVISION,
    questionToken: `q_${"C".repeat(32)}`,
    answers: { next_step: "Proceed (Recommended)" }
  };
  const requests = [];
  const prepared = runnerOptions(t, { adapter: selectedAdapter });
  let runner;
  prepared.options.fetch = signedControlPlane({
    publicKey: prepared.publicKey,
    commandValue: command("question", payload, "CCCCCCCCCCCCCCCC"),
    requests,
    onTerminal: () => queueMicrotask(() => { void runner.stop(); })
  });
  prepared.options.delay = async () => {};
  runner = new RemoteCockpitRunner(prepared.options);
  await runner.start();
  assert.equal(selectedAdapter.calls.length, 1);
  assert.equal(selectedAdapter.calls[0][0], "question");
  assert.equal(selectedAdapter.calls[0][1].requestId, payload.requestId);
  assert.equal(selectedAdapter.calls[0][1].questionToken, payload.questionToken);
  assert.equal(selectedAdapter.calls[0][1].answers.next_step, payload.answers.next_step);
});

test("state and fleet projection expose only the reviewed remote shape", () => {
  const state = projectRemoteState(localState({
    turn: "working",
    conversation: [{ role: "operator", text: "Continue.", at: new Date(NOW - 1).toISOString() }]
  }), { sessionRevision: SESSION_REVISION, now: NOW, ttlMs: 30_000 });
  assert.deepEqual(Object.keys(state).sort(), [
    "apiVersion", "codex", "conversation", "observedAt", "pendingQuestions", "runner",
    "sessionRevision", "stateRevision", "tokens", "validUntil"
  ].sort());
  assert.equal(state.codex.state, "working");
  assert.equal("threadId" in state, false);
  assert.equal("privatePath" in state, false);

  const fleet = projectRemoteFleet(unavailableFleet({
    secretReference: "must-not-cross"
  }), { sessionRevision: SESSION_REVISION });
  assert.equal(fleet.apiVersion, "gate.remote-fleet/v1");
  assert.equal(fleet.sessionRevision, SESSION_REVISION);
  assert.equal("secretReference" in fleet, false);
});

test("state projection withholds whole credential-like messages and omits unsafe questions", () => {
  const canary = "CANARY_REMOTE_SECRET_123456";
  const standalone = `${"gh"}p_${"A".repeat(36)}`;
  const state = projectRemoteState(localState({
    turn: "waiting",
    conversation: [
      {
        role: "codex",
        text: `password=${canary}`,
        at: new Date(NOW - 2).toISOString()
      },
      {
        role: "codex",
        text: `Use ${standalone}`,
        at: new Date(NOW - 1).toISOString()
      }
    ],
    pendingQuestions: [{
      token: `q_${"S".repeat(32)}`,
      questions: [{
        id: "credential_path",
        header: "Next step",
        question: "Which reviewed path should run?",
        options: [
          { label: "Continue (Recommended)", description: `password=${canary}`, recommended: true },
          { label: "Pause", description: "Wait locally.", recommended: false }
        ]
      }]
    }]
  }), { sessionRevision: SESSION_REVISION, now: NOW });

  assert.equal(state.codex.state, "waiting");
  assert.equal(state.conversation[0].text, remoteRunnerInternals.WITHHELD_REMOTE_CONTENT);
  assert.equal(state.conversation[1].text, remoteRunnerInternals.WITHHELD_REMOTE_CONTENT);
  assert.deepEqual(state.pendingQuestions, []);
  assert.doesNotMatch(JSON.stringify(state), /CANARY_REMOTE_SECRET/u);
  assert.doesNotMatch(JSON.stringify(state), /ghp_/u);
});

test("maximum local state is reduced to a valid projection below the remote byte envelope", () => {
  const conversation = Array.from({ length: 48 }, () => ({
    role: "operator",
    text: "\\".repeat(4_000),
    at: new Date(NOW - 1).toISOString()
  }));
  const pendingQuestions = Array.from({ length: 8 }, (_, pendingIndex) => ({
    token: `q_${pendingIndex.toString(36).padStart(43, "Q")}`,
    questions: Array.from({ length: 3 }, (_, questionIndex) => ({
      id: `question_${questionIndex}`,
      header: "H".repeat(24),
      question: "\\".repeat(500),
      options: [
        { label: "A".repeat(100), description: "\\".repeat(300), recommended: true },
        { label: "B".repeat(100), description: "\\".repeat(300), recommended: false },
        { label: "C".repeat(100), description: "\\".repeat(300), recommended: false }
      ]
    }))
  }));
  const state = projectRemoteState(localState({ conversation, pendingQuestions }), {
    sessionRevision: SESSION_REVISION,
    now: NOW
  });
  const serialized = JSON.stringify(state);
  assert.equal(state.conversation.length, remoteRunnerInternals.MAX_PROJECTED_CONVERSATION_ENTRIES);
  assert.match(state.conversation[0].text, /^\[37 earlier conversation entries were omitted/u);
  assert.ok(state.conversation.slice(1).every((entry) => entry.text.endsWith("[Remote cockpit truncated this message]")));
  assert.equal(state.pendingQuestions.length, remoteRunnerInternals.MAX_PROJECTED_PENDING_QUESTIONS);
  assert.ok(Buffer.byteLength(serialized, "utf8") < remoteRunnerInternals.MAX_REMOTE_PROJECTION_BYTES);
});

test("conversation projection marks multibyte truncation within its byte envelope", () => {
  const original = "🙂".repeat(1_000);
  const state = projectRemoteState(localState({
    conversation: [{ role: "codex", text: original, at: new Date(NOW - 1).toISOString() }]
  }), { sessionRevision: SESSION_REVISION, now: NOW });
  assert.equal(state.conversation.length, 1);
  assert.notEqual(state.conversation[0].text, original);
  assert.ok(state.conversation[0].text.endsWith("[Remote cockpit truncated this message]"));
  assert.ok(Buffer.byteLength(state.conversation[0].text, "utf8") <= 2_000);
  assert.ok([...state.conversation[0].text].length <= 1_000);
});

test("remote projection bounds multiline replies and preserves question answer identities", () => {
  const pending = {
    token: `q_${"Q".repeat(43)}`,
    questions: [{
      id: "next_step", header: "Next", question: "Choose.",
      options: [
        { label: "Continue (Recommended)", description: "Proceed.", recommended: true },
        { label: "Pause", description: "Wait.", recommended: false }
      ]
    }]
  };
  const project = (pendingQuestions) => projectRemoteState(localState({
    conversation: [{ role: "codex", text: Array(25).fill("line").join("\n"), at: new Date(NOW - 1).toISOString() }],
    pendingQuestions
  }), { sessionRevision: SESSION_REVISION, now: NOW });
  const ordinary = project([pending]);
  assert.equal(ordinary.conversation[0].text.split("\n").length, 24);
  assert.match(ordinary.conversation[0].text, /truncated this message/u);
  assert.deepEqual(ordinary.pendingQuestions, [pending]);
  for (const [field, lines] of [["header", 2], ["question", 13], ["label", 3], ["description", 7]]) {
    const oversized = structuredClone(pending);
    const destination = ["label", "description"].includes(field)
      ? oversized.questions[0].options[0] : oversized.questions[0];
    destination[field] = Array(lines).fill("x").join("\n");
    const state = project([oversized]);
    assert.deepEqual(state.pendingQuestions, []);
    assert.match(state.conversation.at(-1).text, /questions omitted.*answer locally/u);
  }
});

test("durable remote projection revisions advance when local revisions reset after restart", async (t) => {
  const directory = ownerDirectory(t);
  const keys = crypto.generateKeyPairSync("ed25519");
  let nonce = 0;

  const run = async () => {
    const requests = [];
    const selectedAdapter = adapter({
      privateState: () => localState({ stateRevision: 0 })
    });
    const prepared = runnerOptions(t, { adapter: selectedAdapter, journalDirectory: directory });
    let runner;
    const controlPlane = signedControlPlane({
      publicKey: keys.publicKey,
      commandValue: null,
      requests
    });
    const fetch = async (url, init) => {
      const result = await controlPlane(url, init);
      if (new URL(url).pathname.endsWith("/lease")) {
        queueMicrotask(() => { void runner.stop(); });
      }
      return result;
    };
    runner = new RemoteCockpitRunner({
      ...prepared.options,
      privateKey: keys.privateKey,
      nonceFactory: () => `${String(++nonce).padStart(32, "R")}`,
      fleetProvider: async () => unavailableFleet({ revision: 1 }),
      fetch,
      delay: async () => {}
    });
    await runner.start();
    return {
      state: requests.find((item) => item.path.endsWith("/state")).value.stateRevision,
      fleet: requests.find((item) => item.path.endsWith("/fleet")).value.revision
    };
  };

  const first = await run();
  const restarted = await run();
  assert.equal(first.state, 1);
  assert.equal(first.fleet, 1);
  assert.ok(restarted.state > first.state);
  assert.ok(restarted.fleet > first.fleet);
});

test("runner applies bounded exponential backoff to control-plane failures", async (t) => {
  const delays = [];
  const prepared = runnerOptions(t);
  let runner;
  prepared.options.fetch = async () => { throw new Error("sensitive network detail"); };
  prepared.options.delay = async (milliseconds) => {
    delays.push(milliseconds);
    if (delays.length === 3) queueMicrotask(() => { void runner.stop(); });
  };
  runner = new RemoteCockpitRunner(prepared.options);
  await runner.start();
  assert.deepEqual(delays, [20, 40, 80]);
});

test("runner stops on a permanent coordinator rejection instead of retrying forever", async (t) => {
  const delays = [];
  const prepared = runnerOptions(t);
  prepared.options.fetch = async () => new Response("{}", {
    status: 401,
    headers: { "content-type": "application/json; charset=utf-8" }
  });
  prepared.options.delay = async (milliseconds) => { delays.push(milliseconds); };
  const runner = new RemoteCockpitRunner(prepared.options);
  await assert.rejects(runner.start(), (error) => error?.code === "request-rejected" && error?.status === 401);
  assert.deepEqual(delays, []);
  assert.equal(runner.running, false);
});

test("stop aborts an outstanding poll and closes the owned adapter", async (t) => {
  const selectedAdapter = adapter();
  const prepared = runnerOptions(t, { adapter: selectedAdapter });
  let observedSignal;
  let fetchStarted;
  const started = new Promise((resolve) => { fetchStarted = resolve; });
  prepared.options.fetch = async (_url, init) => {
    observedSignal = init.signal;
    fetchStarted();
    await new Promise((resolve, reject) => {
      init.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
    });
  };
  const runner = new RemoteCockpitRunner(prepared.options);
  const running = runner.start();
  await started;
  await runner.stop();
  await running;
  assert.equal(observedSignal.aborted, true);
  assert.equal(selectedAdapter.closed, 1);
});

test("response deadline aborts a stalled body and bounds stop during command delivery", async (t) => {
  const selectedAdapter = adapter();
  const payload = {
    apiVersion: REMOTE_MESSAGE_VERSION,
    requestId: "request-stalled-body-01",
    sessionRevision: SESSION_REVISION,
    message: "Deliver this through the bounded response path."
  };
  const requests = [];
  const prepared = runnerOptions(t, {
    adapter: selectedAdapter,
    options: { requestTimeoutMs: 250 }
  });
  const controlPlane = signedControlPlane({
    publicKey: prepared.publicKey,
    commandValue: command("message", payload, "SSSSSSSSSSSSSSSS"),
    requests
  });
  let bodyStarted;
  const started = new Promise((resolve) => { bodyStarted = resolve; });
  let bodyCancelled = false;
  let observedSignal;
  let stalled = false;
  prepared.options.fetch = async (url, init) => {
    const result = await controlPlane(url, init);
    const value = JSON.parse(init.body);
    if (!stalled && new URL(url).pathname.endsWith("/transition") && value.state === "completed") {
      stalled = true;
      observedSignal = init.signal;
      return new Response(new ReadableStream({
        start() { bodyStarted(); },
        cancel() { bodyCancelled = true; }
      }), {
        status: 200,
        headers: { "content-type": "application/json; charset=utf-8" }
      });
    }
    return result;
  };
  prepared.options.delay = async () => {};
  const runner = new RemoteCockpitRunner(prepared.options);
  const running = runner.start();
  await started;
  const stopStartedAt = Date.now();
  await runner.stop();
  await running;
  assert.equal(observedSignal.aborted, true);
  assert.equal(bodyCancelled, true);
  assert.ok(Date.now() - stopStartedAt < 1_500);
  assert.equal(selectedAdapter.closed, 1);
});

test("runner CLI resolves exact environment configuration without accepting an ambiguous origin", (t) => {
  const directory = ownerDirectory(t);
  const keyFile = path.join(directory, "runner-key.pem");
  const codexHome = path.join(directory, "codex-home");
  const threadFile = path.join(directory, "thread.json");
  const values = runnerCliInternals.parseArguments([], {
    GATE_REMOTE_CONTROL_PLANE: "https://gate.example.test",
    GATE_REMOTE_CASE_ID: CASE_ID,
    GATE_REMOTE_SESSION_REVISION: String(SESSION_REVISION),
    GATE_REMOTE_RUNNER_ID: RUNNER_ID,
    GATE_REMOTE_PRIVATE_KEY_FILE: keyFile,
    GATE_REMOTE_JOURNAL_DIR: directory,
    GATE_REMOTE_CODEX_HOME: codexHome,
    GATE_REMOTE_THREAD_ID_FILE: threadFile,
    GATE_REPO: process.cwd()
  });
  assert.equal(values.controlPlaneUrl, "https://gate.example.test");
  assert.equal(values.codexHome, codexHome);
  assert.equal(values.threadIdFile, threadFile);
  assert.throws(() => runnerCliInternals.parseArguments([
    "--control-plane", "https://gate.example.test/"
  ], {
    GATE_REMOTE_CASE_ID: CASE_ID,
    GATE_REMOTE_SESSION_REVISION: String(SESSION_REVISION),
    GATE_REMOTE_RUNNER_ID: RUNNER_ID,
    GATE_REMOTE_PRIVATE_KEY_FILE: keyFile,
    GATE_REMOTE_JOURNAL_DIR: directory,
    GATE_REMOTE_CODEX_HOME: codexHome,
    GATE_REMOTE_THREAD_ID_FILE: threadFile
  }), /exact HTTPS origin/u);
  assert.throws(() => runnerCliInternals.parseArguments([], {
    GATE_REMOTE_CONTROL_PLANE: "https://gate.example.test",
    GATE_REMOTE_CASE_ID: CASE_ID,
    GATE_REMOTE_SESSION_REVISION: String(SESSION_REVISION),
    GATE_REMOTE_RUNNER_ID: RUNNER_ID,
    GATE_REMOTE_PRIVATE_KEY_FILE: keyFile,
    GATE_REMOTE_JOURNAL_DIR: directory,
    GATE_REMOTE_CODEX_HOME: path.join(path.dirname(directory), "shared-codex-home"),
    GATE_REMOTE_THREAD_ID_FILE: threadFile
  }), /directly under the journal directory/u);
});

test("runner CLI gives remote Codex only the minimal runtime and login environment", () => {
  const codexHome = "/private/gate-remote/codex-home";
  const environment = runnerCliInternals.remoteCodexEnvironment({
    PATH: "/usr/bin",
    HOME: "/home/operator",
    CODEX_HOME: "/home/operator/.codex",
    LANG: "C.UTF-8",
    OPENAI_API_KEY: "CANARY_OPENAI_KEY",
    GITHUB_TOKEN: "CANARY_GITHUB_TOKEN",
    GATE_REMOTE_PRIVATE_KEY_FILE: "/private/runner.pem",
    HTTP_PROXY: "http://credential@example.test",
    NODE_OPTIONS: "--require=/tmp/canary.js"
  }, codexHome);
  assert.deepEqual(environment, {
    PATH: "/usr/bin",
    LANG: "C.UTF-8",
    CODEX_HOME: codexHome,
    HOME: codexHome,
    USERPROFILE: codexHome,
    APPDATA: path.join(codexHome, "appdata"),
    LOCALAPPDATA: path.join(codexHome, "local-appdata"),
    XDG_CACHE_HOME: path.join(codexHome, "xdg-cache"),
    XDG_CONFIG_HOME: path.join(codexHome, "xdg-config"),
    XDG_DATA_HOME: path.join(codexHome, "xdg-data")
  });
  assert.equal(Object.isFrozen(environment), true);
  assert.deepEqual(runnerCliInternals.remoteCodexEnvironment({ Path: "/usr/bin" }, codexHome), {
    PATH: "/usr/bin",
    CODEX_HOME: codexHome,
    HOME: codexHome,
    USERPROFILE: codexHome,
    APPDATA: path.join(codexHome, "appdata"),
    LOCALAPPDATA: path.join(codexHome, "local-appdata"),
    XDG_CACHE_HOME: path.join(codexHome, "xdg-cache"),
    XDG_CONFIG_HOME: path.join(codexHome, "xdg-config"),
    XDG_DATA_HOME: path.join(codexHome, "xdg-data")
  });
  assert.throws(
    () => runnerCliInternals.remoteCodexEnvironment({ Path: "/trusted", PATH: "/shadowed" }, codexHome),
    /conflicting case aliases/u
  );
  assert.throws(() => runnerCliInternals.remoteCodexEnvironment({}, "relative"), /must be absolute/u);
});

test("runner rejects a writable or private-state Codex executable search path", (t) => {
  const directory = ownerDirectory(t);
  const codexHome = path.join(directory, "codex-home");
  const binaryDirectory = path.join(directory, "bin");
  fs.mkdirSync(codexHome, { mode: 0o700 });
  fs.mkdirSync(binaryDirectory, { mode: 0o700 });
  const executable = path.join(binaryDirectory, process.platform === "win32" ? "codex.EXE" : "codex");
  fs.writeFileSync(executable, "not a trusted runtime\n", { mode: 0o700 });
  assert.throws(
    () => runnerCliInternals.prepareRemoteCodexLaunch({ PATH: binaryDirectory }, codexHome),
    /protected absolute Codex executable is unavailable/u
  );
  assert.throws(
    () => runnerCliInternals.prepareRemoteCodexLaunch({ PATH: binaryDirectory }, codexHome, [directory]),
    /protected absolute Codex executable is unavailable/u
  );
  assert.throws(
    () => runnerCliInternals.prepareRemoteCodexLaunch({ PATH: binaryDirectory }, codexHome, ["relative"]),
    /forbidden roots must be absolute/u
  );
});

test("runner selects only an absolute protected Codex executable and omits a writable PATH poison", (t) => {
  const directory = ownerDirectory(t);
  const poisonedDirectory = path.join(directory, "poisoned-bin");
  fs.mkdirSync(poisonedDirectory, { mode: 0o700 });
  const poisoned = path.join(poisonedDirectory, process.platform === "win32" ? "codex.EXE" : "codex");
  fs.writeFileSync(poisoned, "poisoned runtime\n", { mode: 0o700 });
  let launch;
  try {
    launch = runnerCliInternals.prepareRemoteCodexLaunch({
      PATH: `${poisonedDirectory}${path.delimiter}${process.env.PATH || ""}`,
      PATHEXT: process.env.PATHEXT || ""
    }, path.join(directory, "codex-home"), [directory]);
  } catch (error) {
    if (/protected absolute Codex executable is unavailable/u.test(error.message)) {
      return t.skip("this host has no administrator-protected Codex executable");
    }
    throw error;
  }
  assert.equal(path.isAbsolute(launch.command), true);
  assert.equal(launch.command, fs.realpathSync.native(launch.command));
  assert.notEqual(launch.command, poisoned);
  assert.equal(launch.environment.PATH.split(path.delimiter).includes(poisonedDirectory), false);
  assert.equal(Object.isFrozen(launch), true);
  assert.equal(Object.isFrozen(launch.environment), true);
});

test("runner working directory boundary covers journal, Codex, key, and thread state", (t) => {
  const root = ownerDirectory(t);
  const values = {
    journalDirectory: path.join(root, "journal"),
    codexHome: path.join(root, "codex-home"),
    privateKeyFile: path.join(root, "keys", "runner.pem"),
    threadIdFile: path.join(root, "threads", "thread.json")
  };
  assert.doesNotThrow(() => runnerCliInternals.assertWorkingDirectoryBoundary(path.join(root, "work"), values));
  for (const [cwd, label] of [
    [path.join(values.journalDirectory, "nested"), /runner journal/u],
    [values.codexHome, /remote Codex home/u],
    [path.dirname(values.privateKeyFile), /runner private-key state/u],
    [values.threadIdFile, /runner thread state/u]
  ]) {
    assert.throws(() => runnerCliInternals.assertWorkingDirectoryBoundary(cwd, values), label);
  }
});

test("runner startup rejects a working directory that contains private state before taking its lock", async (t) => {
  const root = ownerDirectory(t);
  const journalDirectory = path.join(root, "private-runner-state");
  const codexHome = path.join(journalDirectory, "codex-home");
  const privateKeyFile = path.join(journalDirectory, "runner-private.pem");
  fs.mkdirSync(journalDirectory, { mode: 0o700 });
  fs.mkdirSync(codexHome, { mode: 0o700 });
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  fs.writeFileSync(privateKeyFile, privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  await assert.rejects(runnerCliInternals.run({
    cwd: root,
    journalDirectory,
    codexHome,
    privateKeyFile,
    threadIdFile: path.join(journalDirectory, "thread.json")
  }), /must not overlap runner journal/u);
  assert.equal(fs.existsSync(path.join(journalDirectory, ".remote-runner.lock")), false);
});

test("runner CLI records the v3 thread lifecycle and safely discards a clean unused thread", (t) => {
  const directory = ownerDirectory(t);
  const file = path.join(directory, "thread.json");
  const codexHome = path.join(directory, "codex-home");
  const configuration = { file, runnerId: RUNNER_ID, caseId: CASE_ID, cwd: process.cwd(), codexHome };
  const record = new runnerCliInternals.ThreadRecord(configuration);
  assert.equal(runnerCliInternals.THREAD_RECORD_VERSION, "gate.remote-runner-thread/v3");
  assert.equal(record.threadId, null);
  record.begin();
  assert.equal(fs.statSync(file).mode & 0o077, 0);
  const unresolvedCreating = new runnerCliInternals.ThreadRecord(configuration);
  assert.throws(() => unresolvedCreating.threadId, /creation is unresolved/u);
  assert.throws(() => unresolvedCreating.begin(), /already recorded/u);

  record.provisional("thread-fixture");
  const unresolvedProvisional = new runnerCliInternals.ThreadRecord(configuration);
  assert.throws(() => unresolvedProvisional.threadId, /creation is unresolved/u);
  assert.throws(() => unresolvedProvisional.discardCleanProvisional("thread-fixture"),
    /matching clean provisional/u);
  assert.equal(record.discardCleanProvisional("thread-fixture"), true);
  assert.equal(fs.existsSync(file), false);

  const restarted = new runnerCliInternals.ThreadRecord(configuration);
  assert.equal(restarted.threadId, null);
  restarted.begin();
  restarted.provisional("thread-restarted");
  assert.equal(restarted.markUsed("thread-restarted"), true);
  assert.equal(restarted.markUsed("thread-restarted"), false);
  const resumed = new runnerCliInternals.ThreadRecord(configuration);
  assert.equal(resumed.threadId, "thread-restarted");
  assert.equal(resumed.discardCleanProvisional("thread-restarted"), false);
  assert.equal(fs.existsSync(file), true);
  assert.throws(() => new runnerCliInternals.ThreadRecord({ ...configuration, caseId: "case-two" }),
    /does not match this runner/u);
  assert.throws(() => new runnerCliInternals.ThreadRecord({
    ...configuration,
    codexHome: path.join(directory, "other-codex-home")
  }), /does not match this runner/u);
});

test("runner CLI refuses a persisted v2 thread from the older remote lifecycle", (t) => {
  const directory = ownerDirectory(t);
  const file = path.join(directory, "thread.json");
  fs.writeFileSync(file, `${JSON.stringify({
    apiVersion: "gate.remote-runner-thread/v2",
    toolBoundaryRevision: "gate.remote-tool-boundary/v1",
    codexAppServerVersion: "0.159.2",
    executionPosture: "remote-read-only",
    runnerId: RUNNER_ID,
    caseId: CASE_ID,
    cwd: process.cwd(),
    codexHome: path.join(directory, "codex-home"),
    state: "bound",
    threadId: "thread-legacy"
  })}\n`, { mode: 0o600 });
  assert.throws(() => new runnerCliInternals.ThreadRecord({
    file,
    runnerId: RUNNER_ID,
    caseId: CASE_ID,
    cwd: process.cwd(),
    codexHome: path.join(directory, "codex-home")
  }), /does not match this runner/u);
});

test("runner CLI accepts only owner-only Ed25519 private-key files and exclusive state locks", (t) => {
  const directory = ownerDirectory(t);
  const file = path.join(directory, "runner-key.pem");
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  fs.writeFileSync(file, privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  const loaded = runnerCliInternals.readPrivateKey(file);
  assert.equal(loaded.type, "private");
  assert.equal(loaded.asymmetricKeyType, "ed25519");
  const release = runnerCliInternals.acquireInstanceLock(directory);
  assert.throws(() => runnerCliInternals.acquireInstanceLock(directory), /already own/u);
  assert.throws(() => runnerCliInternals.acquireInstanceLock(directory), /already own/u);
  release();
  const releaseAgain = runnerCliInternals.acquireInstanceLock(directory);
  releaseAgain();
  fs.chmodSync(file, 0o644);
  assert.throws(() => runnerCliInternals.readPrivateKey(file), /owner-only/u);
});

test("runner CLI lock release never removes a replacement path", (t) => {
  const directory = ownerDirectory(t);
  const lock = path.join(directory, ".remote-runner.lock");
  const displaced = path.join(directory, ".remote-runner.displaced");
  const release = runnerCliInternals.acquireInstanceLock(directory);
  fs.renameSync(lock, displaced);
  fs.writeFileSync(lock, "replacement\n", { mode: 0o600 });
  release();
  assert.equal(fs.readFileSync(lock, "utf8"), "replacement\n");
  assert.ok(fs.existsSync(displaced));
});
