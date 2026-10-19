import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  DEFAULT_RUNNER_CLOCK_SKEW_MS,
  RunnerAuthError,
  signRunnerRequest,
  verifyRunnerRequest
} from "../runner-auth.mjs";
import { RemoteBridgeStore, RemoteStoreError } from "../store.mjs";

const operatorId = "operator-123";
const browserSessionId = "browser-12345678";
const caseId = "alpha-case";
const sessionRevision = 7;

const browserBinding = Object.freeze({ operatorId, browserSessionId, caseId, sessionRevision });
const caseBinding = Object.freeze({ operatorId, caseId, sessionRevision });

function message(requestId = "request-12345678", text = "Continue.") {
  return {
    apiVersion: "gate.remote-message-request/v1",
    requestId,
    sessionRevision,
    message: text
  };
}

function stateProjection(revision = 1, overrides = {}) {
  return {
    apiVersion: "gate.remote-cockpit-state/v1",
    sessionRevision,
    stateRevision: revision,
    observedAt: "2026-10-18T12:00:00.000Z",
    validUntil: "2026-10-18T12:01:00.000Z",
    runner: { state: "connected", observedAt: "2026-10-18T12:00:00.000Z" },
    codex: { state: "idle" },
    tokens: null,
    conversation: [],
    pendingQuestions: [],
    ...overrides
  };
}

function fleetProjection(revision = 1, overrides = {}) {
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
    revision,
    observedAt: "2026-10-18T12:00:00.000Z",
    receivedAt: "2026-10-18T12:00:00.000Z",
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
    campaigns: [],
    ...overrides
  };
}

function fixture(t, overrides = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "gate-remote-store-"));
  fs.chmodSync(directory, 0o700);
  const databasePath = path.join(directory, "remote.sqlite");
  let nowMilliseconds = Date.parse("2026-10-18T12:00:00.000Z");
  let id = 0;
  const options = {
    databasePath,
    now: () => new Date(nowMilliseconds),
    idGenerator: (kind) => `${kind}_${String(++id).padStart(16, "0")}`,
    busyTimeoutMs: 2_000,
    ...overrides
  };
  const store = new RemoteBridgeStore(options);
  store.claimCaseBinding(caseBinding);
  t.after(() => {
    store.close();
    fs.rmSync(directory, { recursive: true, force: true });
  });
  return {
    store,
    databasePath,
    options,
    advance(milliseconds) { nowMilliseconds += milliseconds; }
  };
}

function runnerClaim(overrides = {}) {
  return {
    operatorId,
    caseId,
    sessionRevision,
    runnerId: "runner-12345678",
    leaseMs: 30_000,
    ...overrides
  };
}

function runnerBinding(command, overrides = {}) {
  return {
    commandId: command.commandId,
    operatorId,
    caseId,
    sessionRevision,
    runnerId: command.lease.runnerId,
    leaseId: command.lease.leaseId,
    ...overrides
  };
}

function browserCommandBinding(command, overrides = {}) {
  return {
    commandId: command.commandId,
    ...browserBinding,
    ...overrides
  };
}

test("opens an owner-only WAL database with required durable settings", (t) => {
  const { store, databasePath } = fixture(t);
  assert.deepEqual(store.configuration(), {
    schemaVersion: 1,
    journalMode: "wal",
    foreignKeys: true,
    synchronous: "full",
    busyTimeoutMs: 2_000,
    maxEvents: 20_000,
    maxCommands: 50_000,
    retainedEvents: 0,
    retainedCommands: 0,
    eventPrunedThrough: 0,
    eventHeadCursor: 0
  });
  assert.equal(fs.statSync(databasePath).mode & 0o777, 0o600);
  assert.equal(store.isOpen(), true);
  store.close();
  store.close();
  assert.equal(store.isOpen(), false);
  assert.throws(() => store.configuration(), (error) => error.code === "store-closed");
});

test("refuses group-readable parents and pre-existing database files", (t) => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "gate-remote-permissions-"));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  fs.chmodSync(parent, 0o750);
  assert.throws(() => new RemoteBridgeStore({ databasePath: path.join(parent, "remote.sqlite") }),
    (error) => error.code === "store-permissions-invalid");
  fs.chmodSync(parent, 0o700);
  const databasePath = path.join(parent, "remote.sqlite");
  fs.writeFileSync(databasePath, "", { mode: 0o640 });
  fs.chmodSync(databasePath, 0o640);
  assert.throws(() => new RemoteBridgeStore({ databasePath }),
    (error) => error.code === "store-permissions-invalid");
});

test("durably enqueues once across browser refresh, replays the exact receipt, and rejects changed replay", (t) => {
  const { store, databasePath, options } = fixture(t);
  const refreshedBinding = { ...browserBinding, browserSessionId: "browser-87654321" };
  const first = store.enqueue(browserBinding, message());
  const sameSessionReplay = store.enqueue(browserBinding, message());
  const refreshedReplay = store.enqueue(refreshedBinding, message());
  assert.equal(first.replayed, false);
  assert.equal(sameSessionReplay.replayed, true);
  assert.equal(refreshedReplay.replayed, true);
  assert.deepEqual(refreshedReplay.receipt, first.receipt);
  assert.equal(refreshedReplay.command.commandId, first.command.commandId);
  assert.deepEqual(store.eventsSince(refreshedBinding).events.map((event) => event.payload.state),
    ["queued", "queued", "queued"],
    "each exact replay republishes the current state without dispatching another command");
  assert.throws(() => store.enqueue(refreshedBinding, message("request-12345678", "Changed.")),
    (error) => error.code === "request-replay-conflict");
  store.claimCaseBinding({ ...caseBinding, caseId: "other-case" });
  const otherCase = store.enqueue({ ...refreshedBinding, caseId: "other-case" }, message());
  assert.notEqual(otherCase.command.commandId, first.command.commandId,
    "request identifiers are isolated by exact case binding");

  store.close();
  const reopened = new RemoteBridgeStore(options);
  t.after(() => reopened.close());
  const durableReplay = reopened.enqueue(refreshedBinding, message());
  assert.equal(durableReplay.replayed, true);
  assert.deepEqual(durableReplay.receipt, first.receipt);
  assert.equal(fs.statSync(databasePath).mode & 0o777, 0o600);
});

test("runner nonces are atomically single-use across close and reopen", (t) => {
  const { store, options, advance } = fixture(t);
  const runnerId = "runner-12345678";
  const nonce = "A".repeat(32);
  const expiresAt = Date.parse("2026-10-18T12:01:00.000Z");
  const adapter = store.runnerNonceStore();
  assert.equal(adapter, store.runnerNonceStore(), "nonce adapter identity is stable");
  assert.equal(adapter.consume(runnerId, nonce, expiresAt), true);
  assert.equal(adapter.consume(runnerId, nonce, expiresAt), false);

  store.close();
  const reopened = new RemoteBridgeStore(options);
  t.after(() => reopened.close());
  assert.equal(reopened.consumeRunnerNonce(runnerId, nonce, expiresAt), false,
    "accepted nonce remains consumed after restart");
  advance(60_001);
  assert.equal(reopened.consumeRunnerNonce(runnerId, nonce, expiresAt + 60_001), true,
    "an expired nonce row is pruned before an otherwise valid new request");
});

test("SQLite rejects an identical signed request through the final accepted skew millisecond", async (t) => {
  const { store, advance } = fixture(t);
  const now = Date.parse("2026-10-18T12:00:00.000Z");
  const timestamp = now - DEFAULT_RUNNER_CLOCK_SKEW_MS + 1;
  const runnerId = "runner-12345678";
  const nonce = "Z".repeat(32);
  const body = Buffer.from('{"kind":"lease"}\n');
  const keys = crypto.generateKeyPairSync("ed25519");
  const headers = signRunnerRequest({
    runnerId,
    privateKey: keys.privateKey,
    method: "POST",
    path: "/api/runner/v1/lease",
    body,
    timestamp,
    nonce
  });
  const request = {
    headers,
    publicKeys: new Map([[runnerId, keys.publicKey]]),
    nonceStore: store.runnerNonceStore(),
    method: "POST",
    path: "/api/runner/v1/lease",
    body,
    now
  };

  assert.deepEqual(await verifyRunnerRequest(request), { runnerId });
  await assert.rejects(verifyRunnerRequest(request), (error) => {
    assert.ok(error instanceof RunnerAuthError);
    assert.equal(error.code, "runner-auth-replayed");
    return true;
  });

  advance(1);
  await assert.rejects(verifyRunnerRequest({ ...request, now: now + 1 }), (error) => {
    assert.ok(error instanceof RunnerAuthError);
    assert.equal(error.code, "runner-auth-rejected");
    return true;
  });
});

test("case session high-water survives reopen and fences every obsolete session path", (t) => {
  const { store, options } = fixture(t);
  store.enqueue(browserBinding, message("request-before-advance"));
  store.close();

  const reopened = new RemoteBridgeStore(options);
  t.after(() => reopened.close());
  assert.throws(() => reopened.claimCaseBinding({ ...caseBinding, sessionRevision: sessionRevision - 1 }),
    (error) => error.code === "session-changed");
  assert.deepEqual(reopened.claimCaseBinding(caseBinding), { sessionRevision, advanced: false });

  const nextRevision = sessionRevision + 1;
  const nextCaseBinding = { ...caseBinding, sessionRevision: nextRevision };
  const nextBrowserBinding = { ...browserBinding, sessionRevision: nextRevision };
  assert.deepEqual(reopened.claimCaseBinding(nextCaseBinding), {
    sessionRevision: nextRevision,
    advanced: true
  });
  for (const action of [
    () => reopened.enqueue(browserBinding, message("request-stale")),
    () => reopened.leaseNext(runnerClaim()),
    () => reopened.appendActivity(caseBinding, {
      category: "testing", state: "progress", completed: null, total: null, tokens: null
    }),
    () => reopened.putStateProjection(caseBinding, stateProjection()),
    () => reopened.eventsSince(browserBinding)
  ]) {
    assert.throws(action, (error) => error.code === "session-changed");
  }

  const nextMessage = { ...message("request-after-advance"), sessionRevision: nextRevision };
  assert.equal(reopened.enqueue(nextBrowserBinding, nextMessage).command.sessionRevision, nextRevision);
  const nextState = { ...stateProjection(), sessionRevision: nextRevision };
  const nextFleet = { ...fleetProjection(), sessionRevision: nextRevision };
  reopened.putStateProjection(nextCaseBinding, nextState);
  reopened.putFleetProjection(nextCaseBinding, nextFleet);
  reopened.appendActivity(nextCaseBinding, {
    category: "testing", state: "progress", completed: null, total: null, tokens: null
  });
  assert.equal(reopened.getStateProjection(nextCaseBinding).sessionRevision, nextRevision);
  assert.equal(reopened.getFleetProjection(nextCaseBinding).sessionRevision, nextRevision);
  assert.equal(reopened.eventsSince(nextBrowserBinding).events.length, 4);
});

test("runner nonce capacity is bounded and expired rows are pruned in the insert transaction", (t) => {
  const { store, advance } = fixture(t, { maxRunnerNonces: 2 });
  const firstExpiry = Date.parse("2026-10-18T12:00:01.000Z");
  assert.equal(store.consumeRunnerNonce("runner-12345678", "A".repeat(32), firstExpiry), true);
  assert.equal(store.consumeRunnerNonce("runner-12345678", "B".repeat(32), firstExpiry), true);
  assert.throws(() => store.consumeRunnerNonce(
    "runner-12345678", "C".repeat(32), firstExpiry
  ), (error) => error.code === "runner-nonce-store-full");
  advance(1_001);
  assert.equal(store.consumeRunnerNonce(
    "runner-12345678", "C".repeat(32), firstExpiry + 1_001
  ), true);
  assert.throws(() => store.consumeRunnerNonce("runner-12345678", "short", firstExpiry + 2_000),
    (error) => error.code === "runner-nonce-invalid");
});

test("command capacity prunes only the oldest expired terminal row after its events are gone", (t) => {
  const { store, options, advance } = fixture(t, { maxEvents: 2, maxCommands: 3 });
  const oldest = store.enqueue(browserBinding, message("request-12345678"), { ttlMs: 1_000 }).command;
  const second = store.enqueue(browserBinding, message("request-22345678")).command;
  const third = store.enqueue(browserBinding, message("request-32345678")).command;
  const leased = store.leaseNext(runnerClaim());
  const leaseBinding = runnerBinding(leased);
  store.acceptCommand(leaseBinding);
  store.startCommand(leaseBinding);
  store.completeCommand(leaseBinding);
  advance(1_001);

  assert.throws(() => store.enqueue(browserBinding, message("request-42345678")),
    (error) => error.code === "command-store-full",
    "a retained lifecycle event prevents premature command deletion");
  assert.equal(store.enqueue(browserBinding, message("request-12345678"), { ttlMs: 1_000 }).replayed, true,
    "an existing request remains idempotent while its command row exists");

  for (const state of ["started", "completed"]) {
    store.appendActivity(caseBinding, {
      category: "testing",
      state,
      completed: null,
      total: null,
      tokens: null
    });
  }
  assert.equal(store.configuration().retainedEvents, 2);

  store.close();
  const reopened = new RemoteBridgeStore(options);
  t.after(() => reopened.close());
  const replacement = reopened.enqueue(browserBinding, message("request-42345678")).command;
  assert.equal(reopened.getCommand(browserCommandBinding(oldest)), null);
  assert.equal(reopened.getCommand(browserCommandBinding(second)).commandId, second.commandId);
  assert.equal(reopened.getCommand(browserCommandBinding(third)).commandId, third.commandId);
  assert.equal(reopened.getCommand(browserCommandBinding(replacement)).commandId, replacement.commandId);
  assert.equal(reopened.configuration().retainedCommands, 3);
});

test("command capacity preserves active idempotency and fails closed when no safe slot exists", (t) => {
  const { store, options } = fixture(t, { maxEvents: 1, maxCommands: 2 });
  const first = store.enqueue(browserBinding, message("request-12345678")).command;
  const leased = store.leaseNext(runnerClaim());
  const leaseBinding = runnerBinding(leased);
  store.acceptCommand(leaseBinding);
  store.startCommand(leaseBinding);
  store.completeCommand(leaseBinding);
  store.enqueue(browserBinding, message("request-22345678"));
  assert.throws(() => store.enqueue(browserBinding, message("request-32345678")),
    (error) => error.code === "command-store-full");
  assert.equal(store.enqueue(browserBinding, message("request-12345678")).command.commandId, first.commandId);

  store.close();
  const reopened = new RemoteBridgeStore(options);
  t.after(() => reopened.close());
  assert.equal(reopened.enqueue(browserBinding, message("request-12345678")).command.commandId, first.commandId);
  assert.throws(() => reopened.enqueue(browserBinding, message("request-32345678")),
    (error) => error.code === "command-store-full");
  assert.equal(reopened.configuration().retainedCommands, 2);
});

test("leases and lifecycle transitions enforce session, case, runner, and lease bindings", (t) => {
  const { store } = fixture(t);
  const queued = store.enqueue(browserBinding, message()).command;
  assert.throws(() => store.leaseNext(runnerClaim({ sessionRevision: sessionRevision + 1 })),
    (error) => error.code === "session-changed");
  const leased = store.leaseNext(runnerClaim());
  assert.equal(leased.state, "leased");
  assert.equal(leased.commandId, queued.commandId);

  assert.throws(() => store.acceptCommand(runnerBinding(leased, { caseId: "other-case" })),
    (error) => error.code === "session-changed");
  assert.throws(() => store.acceptCommand(runnerBinding(leased, { runnerId: "runner-wrong-123" })),
    (error) => error.code === "command-not-found");
  assert.throws(() => store.acceptCommand(runnerBinding(leased, { sessionRevision: sessionRevision + 1 })),
    (error) => error.code === "session-changed");

  const accepted = store.acceptCommand(runnerBinding(leased));
  assert.equal(accepted.state, "accepted");
  assert.equal(store.acceptCommand(runnerBinding(leased)).state, "accepted", "transition retry is idempotent");
  const running = store.startCommand(runnerBinding(leased));
  assert.equal(running.state, "running");
  const completed = store.completeCommand(runnerBinding(leased));
  assert.equal(completed.state, "completed");
  assert.equal(store.completeCommand(runnerBinding(leased)).state, "completed");
  assert.throws(() => store.cancelCommand(browserCommandBinding(completed)),
    (error) => error.code === "command-terminal");

  assert.deepEqual(store.eventsSince(browserBinding).events.map((event) => event.payload.state),
    ["queued", "leased", "accepted", "running", "completed"]);
});

test("expired leases can be reclaimed before acceptance but accepted commands are never re-leased", (t) => {
  const { store, advance } = fixture(t);
  store.enqueue(browserBinding, message());
  const firstLease = store.leaseNext(runnerClaim({ leaseMs: 1_000 }));
  advance(1_001);
  const secondLease = store.leaseNext(runnerClaim({ runnerId: "runner-87654321" }));
  assert.equal(secondLease.commandId, firstLease.commandId);
  assert.notEqual(secondLease.lease.leaseId, firstLease.lease.leaseId);
  assert.throws(() => store.acceptCommand(runnerBinding(firstLease)),
    (error) => error.code === "command-not-found");
  const secondBinding = runnerBinding(secondLease, { runnerId: secondLease.lease.runnerId });
  store.acceptCommand(secondBinding);
  advance(30_001);
  assert.equal(store.leaseNext(runnerClaim({ runnerId: "runner-33333333" })), null);
});

test("lease renewal is bounded and expiry makes queued commands terminal", (t) => {
  const { store, advance } = fixture(t);
  const command = store.enqueue(browserBinding, message(), { ttlMs: 2_000 }).command;
  const leased = store.leaseNext(runnerClaim({ leaseMs: 1_000 }));
  const renewed = store.renewLease(runnerBinding(leased), { leaseMs: 1_500 });
  assert.ok(Date.parse(renewed.lease.expiresAt) <= Date.parse(command.expiresAt),
    "pre-run lease cannot outlive the command");
  advance(2_001);
  assert.equal(store.expireDue(), 1);
  assert.equal(store.getCommand(browserCommandBinding(command)).state, "expired");
  assert.equal(store.leaseNext(runnerClaim()), null);
});

test("an abandoned running delivery fails terminally and is never re-dispatched", (t) => {
  const { store, advance } = fixture(t, { maxEvents: 2, maxCommands: 1 });
  const command = store.enqueue(browserBinding, message(), { ttlMs: 60_000 }).command;
  const leased = store.leaseNext(runnerClaim({ leaseMs: 1_000 }));
  const binding = runnerBinding(leased);
  store.acceptCommand(binding);
  store.startCommand(binding);
  const runningCursor = store.configuration().eventHeadCursor;

  advance(1_001);
  assert.equal(store.expireDue(), 1);
  assert.equal(store.getCommand(browserCommandBinding(command)).state, "failed");
  assert.equal(store.leaseNext(runnerClaim()), null, "an uncertain delivery is never replayed");
  assert.deepEqual(store.eventsSince(browserBinding, runningCursor).events.map((event) => event.payload.state), ["failed"]);

  advance(59_000);
  for (const state of ["started", "completed"]) {
    store.appendActivity(caseBinding, {
      category: "waiting",
      state,
      completed: null,
      total: null,
      tokens: null
    });
  }
  const replacement = store.enqueue(browserBinding, message("request-22345678"));
  assert.equal(replacement.command.state, "queued", "terminal retention can release capacity normally");
});

test("cancellation and lookup survive browser refresh but enforce the durable case binding", (t) => {
  const { store } = fixture(t);
  const command = store.enqueue(browserBinding, message()).command;
  const refreshedBinding = {
    ...browserCommandBinding(command),
    browserSessionId: "browser-87654321"
  };
  assert.equal(store.getCommand(refreshedBinding).commandId, command.commandId);
  assert.throws(() => store.getCommand({ ...refreshedBinding, caseId: "other-case" }),
    (error) => error.code === "session-changed");
  assert.throws(() => store.getCommand({ ...refreshedBinding, sessionRevision: sessionRevision + 1 }),
    (error) => error.code === "session-changed");
  assert.throws(() => store.cancelCommand({ ...refreshedBinding, operatorId: "operator-999" }),
    (error) => error.code === "session-changed");
  assert.equal(store.cancelCommand(refreshedBinding).state, "cancelled");
  assert.equal(store.cancelCommand(refreshedBinding).state, "cancelled");
});

test("bounded status reconciliation survives browser refresh and pruned lifecycle events", (t) => {
  const { store } = fixture(t, { maxEvents: 2 });
  const request = message("request-status-after-prune");
  const command = store.enqueue(browserBinding, request).command;
  const leased = store.leaseNext(runnerClaim());
  const binding = runnerBinding(leased);
  store.acceptCommand(binding);
  store.startCommand(binding);
  store.completeCommand(binding);
  for (const state of ["started", "completed"]) {
    store.appendActivity(caseBinding, {
      category: "testing", state, completed: null, total: null, tokens: null
    });
  }
  assert.equal(store.eventsSince(browserBinding, 0).resyncRequired, true);

  const statusRequest = {
    apiVersion: "gate.remote-command-status-request/v1",
    caseId,
    sessionRevision,
    commands: [{ requestId: request.requestId, commandId: command.commandId }]
  };
  assert.deepEqual(store.getCommandStatuses({
    ...browserBinding,
    browserSessionId: "browser-87654321"
  }, statusRequest), [{ requestId: request.requestId, commandId: command.commandId, state: "completed" }]);
  assert.deepEqual(store.getCommandStatuses(browserBinding, {
    ...statusRequest,
    commands: [{ requestId: "request-wrong-id", commandId: command.commandId }]
  }), [], "a command id cannot reconcile a different retained request id");
  assert.throws(() => store.getCommandStatuses(browserBinding, { ...statusRequest, caseId: "other-case" }),
    (error) => error.code === "session-changed");
  assert.throws(() => store.getCommandStatuses(browserBinding, {
    ...statusRequest,
    commands: Array.from({ length: 17 }, (_, index) => ({
      requestId: `request-${String(index).padStart(8, "0")}`,
      commandId: `cmd_${String(index).padStart(16, "0")}`
    }))
  }), (error) => error.code === "command-status-request-invalid");
});

test("state and fleet projections advance monotonically and survive restart", (t) => {
  const { store, options } = fixture(t);
  const first = store.putStateProjection(caseBinding, stateProjection(1));
  assert.equal(first.replayed, false);
  assert.equal(store.putStateProjection(caseBinding, stateProjection(1)).replayed, true);
  assert.throws(() => store.putStateProjection(caseBinding, stateProjection(1, { codex: { state: "working" } })),
    (error) => error.code === "projection-replay-conflict");
  store.putStateProjection(caseBinding, stateProjection(2, { codex: { state: "working" } }));
  assert.throws(() => store.putStateProjection(caseBinding, stateProjection(1)),
    (error) => error.code === "projection-stale");

  store.putFleetProjection(caseBinding, fleetProjection(1));
  const updatedFleet = fleetProjection(2);
  updatedFleet.summary = { ...updatedFleet.summary, campaigns: { value: 2, precision: "exact" } };
  store.putFleetProjection(caseBinding, updatedFleet);
  assert.equal(store.getStateProjection(caseBinding).stateRevision, 2);
  assert.equal(store.getFleetProjection(caseBinding).revision, 2);

  store.close();
  const reopened = new RemoteBridgeStore(options);
  t.after(() => reopened.close());
  assert.equal(reopened.getStateProjection(caseBinding).codex.state, "working");
  assert.equal(reopened.getFleetProjection(caseBinding).summary.campaigns.value, 2);
});

test("activity and all projection signals share a durable scoped cursor", (t) => {
  const { store } = fixture(t);
  store.putStateProjection(caseBinding, stateProjection());
  store.putFleetProjection(caseBinding, fleetProjection());
  const activity = store.appendActivity(caseBinding, {
    category: "testing",
    state: "progress",
    completed: 1,
    total: 3,
    tokens: null
  });
  assert.equal(activity.payload.sequence, activity.sequence);
  store.enqueue(browserBinding, message());

  const firstPage = store.eventsSince(browserBinding, 0, { limit: 2 });
  assert.equal(firstPage.events.length, 2);
  assert.equal(firstPage.hasMore, true);
  assert.equal(firstPage.resyncRequired, false);
  assert.ok(firstPage.headCursor > firstPage.nextCursor);
  const secondPage = store.eventsSince(browserBinding, firstPage.nextCursor, { limit: 10 });
  assert.deepEqual([...firstPage.events, ...secondPage.events].map((event) => event.kind),
    ["state", "fleet", "activity", "command"]);
  assert.equal(secondPage.nextCursor, secondPage.headCursor);

  const ahead = store.eventsSince(browserBinding, secondPage.headCursor + 100);
  assert.equal(ahead.resyncRequired, true);
  assert.equal(ahead.nextCursor, secondPage.headCursor);
  assert.deepEqual(ahead.events, []);

  assert.throws(() => store.eventsSince({ ...browserBinding, operatorId: "operator-999" }),
    (error) => error.code === "session-changed");
  const refreshed = store.eventsSince({ ...browserBinding, browserSessionId: "browser-87654321" });
  assert.deepEqual(refreshed.events.map((event) => event.kind), ["state", "fleet", "activity", "command"],
    "browser-session rotation does not hide the durable case lifecycle");
});

test("event retention stays bounded and its durable watermark drives explicit resync", (t) => {
  const { store, options } = fixture(t, { maxEvents: 3 });
  store.putStateProjection(caseBinding, stateProjection(1)); // sequence 1
  store.putFleetProjection(caseBinding, fleetProjection(1)); // sequence 2
  store.appendActivity(caseBinding, {
    category: "testing",
    state: "started",
    completed: null,
    total: null,
    tokens: null
  }); // sequence 3
  const currentCursor = store.eventsSince(browserBinding).headCursor;
  assert.equal(currentCursor, 3);

  store.putStateProjection(caseBinding, stateProjection(2, { codex: { state: "working" } })); // sequence 4
  store.putFleetProjection(caseBinding, fleetProjection(2)); // sequence 5
  assert.deepEqual(store.configuration(), {
    schemaVersion: 1,
    journalMode: "wal",
    foreignKeys: true,
    synchronous: "full",
    busyTimeoutMs: 2_000,
    maxEvents: 3,
    maxCommands: 50_000,
    retainedEvents: 3,
    retainedCommands: 0,
    eventPrunedThrough: 2,
    eventHeadCursor: 5
  });

  for (const staleCursor of [0, 1, 2]) {
    const stale = store.eventsSince(browserBinding, staleCursor);
    assert.equal(stale.resyncRequired, true);
    assert.equal(stale.nextCursor, 5);
    assert.deepEqual(stale.events, []);
  }
  const current = store.eventsSince(browserBinding, currentCursor);
  assert.equal(current.resyncRequired, false);
  assert.deepEqual(current.events.map((event) => event.sequence), [4, 5]);

  store.close();
  const reopened = new RemoteBridgeStore(options);
  t.after(() => reopened.close());
  assert.equal(reopened.configuration().eventPrunedThrough, 2);
  assert.equal(reopened.eventsSince(browserBinding, 0).resyncRequired, true,
    "fresh clients resync snapshots instead of replaying retained history after compaction");
  reopened.appendActivity(caseBinding, {
    category: "testing",
    state: "completed",
    completed: null,
    total: null,
    tokens: null
  });
  const continued = reopened.eventsSince(browserBinding, 5);
  assert.equal(continued.resyncRequired, false);
  assert.deepEqual(continued.events.map((event) => event.sequence), [6]);
  assert.equal(reopened.configuration().retainedEvents, 3);
  assert.equal(reopened.configuration().eventPrunedThrough, 3);
});

test("exact replay republishes terminal state after its original lifecycle was pruned", (t) => {
  const { store } = fixture(t, { maxEvents: 2 });
  const request = message("request-replay-after-prune");
  const command = store.enqueue(browserBinding, request).command;
  const leased = store.leaseNext(runnerClaim());
  const binding = runnerBinding(leased);
  store.acceptCommand(binding);
  store.startCommand(binding);
  store.completeCommand(binding);
  for (const state of ["started", "completed"]) {
    store.appendActivity(caseBinding, {
      category: "testing", state, completed: null, total: null, tokens: null
    });
  }

  const resync = store.eventsSince(browserBinding, 0);
  assert.equal(resync.resyncRequired, true);
  assert.equal(resync.events.length, 0);
  const replay = store.enqueue(browserBinding, request);
  assert.equal(replay.replayed, true);
  assert.equal(replay.command.commandId, command.commandId);
  assert.equal(replay.command.state, "completed");
  assert.equal(store.configuration().retainedCommands, 1);
  assert.deepEqual(store.eventsSince(browserBinding, resync.headCursor).events.map((event) => event.payload.state),
    ["completed"], "the reconnect can observe terminal state without creating a second command");
});

test("invalid activity and stale session projections fail without durable events", (t) => {
  const { store } = fixture(t);
  assert.throws(() => store.appendActivity(caseBinding, {
    category: "shell",
    state: "started",
    completed: null,
    total: null,
    tokens: null
  }), (error) => error.code === "activity-invalid");
  assert.throws(() => store.putStateProjection({ ...caseBinding, sessionRevision: sessionRevision + 1 }, stateProjection()),
    (error) => error.code === "session-changed");
  assert.equal(store.eventsSince(browserBinding).events.length, 0);
});
