import assert from "node:assert/strict";
import test from "node:test";

import { validateLocalFleet } from "../assets/model.js";
import {
  createGateFleetProvider,
  normalizeGateObserverUrl,
  projectGateObserverStatus
} from "../companion/gate-fleet.mjs";

const NOW = new Date("2026-10-16T14:40:00.000Z");

function caseScan(overrides = {}) {
  return {
    availability: "available",
    discovered: 1,
    scanned: 1,
    omitted: 0,
    invalid: 0,
    discoveredAtLeast: false,
    omittedAtLeast: false,
    complete: true,
    truncated: false,
    ...overrides
  };
}

function profileScan(overrides = {}) {
  return {
    ...caseScan({ discovered: 1, scanned: 1 }),
    visible: 1,
    representedByCases: 0,
    ...overrides
  };
}

function sourceCase(overrides = {}) {
  return {
    id: "case_0123456789abcdef",
    displayName: "PRIVATE TARGET CANARY",
    status: "ready",
    binding: { privateTarget: "https://TARGET_CANARY.invalid" },
    isolation: { privatePath: "/private/PATH_CANARY" },
    runtimeHealth: { status: "available", reason: null },
    state: "running",
    counts: { privateSummary: "PROMPT_CANARY" },
    telemetry: { freshness: "fresh", lastActivityAt: "2026-10-16T14:39:59.000Z", ageSeconds: 1 },
    usage: { availability: "exact", totalTokens: 1200 },
    execution: { runningCount: 1, privateCommand: "COMMAND_CANARY" },
    workflows: {
      counts: { active: 1 },
      scan: { complete: true, truncated: false },
      instances: [{ activePhase: { lane: "active-testing", privateTool: "TOOL_CANARY" } }]
    },
    engagementScan: { privateAuthority: "AUTH_CANARY" },
    offlineAnalysis: { runningCount: 0, privateEvidence: "EVIDENCE_CANARY" },
    activity: [{ summary: "RAW_OUTPUT_CANARY" }],
    learningCount: 99,
    ...overrides
  };
}

function sourceProfile(overrides = {}) {
  return {
    id: "program_fedcba9876543210",
    displayName: null,
    stage: "questionnaire",
    readiness: "not-ready",
    progress: { answered: 14, total: 70 },
    blockerCount: 2,
    nextSection: "authority-sources",
    recommendationMode: "mixed",
    updatedAt: "2026-10-16T14:39:58.000Z",
    freshness: "fresh",
    ...overrides
  };
}

function observer(overrides = {}) {
  return {
    apiVersion: "gate.observer/v1",
    at: "2026-10-16T14:39:59.000Z",
    state: "running",
    counts: {},
    agents: [],
    tasks: [],
    usage: {
      availability: "exact",
      inputTokens: 800000000,
      cachedInputTokens: 400000000,
      outputTokens: 199999999,
      totalTokens: 999999999,
      privateSession: "HOST_TOKEN_CANARY"
    },
    budget: {},
    telemetry: {},
    execution: {},
    workflows: {},
    engagementScan: {},
    offlineAnalysis: {},
    toolRuntimes: {},
    operator: { displayName: "OPERATOR_CANARY" },
    cases: [sourceCase()],
    caseScan: caseScan(),
    profileSetups: [sourceProfile()],
    profileSetupScan: profileScan(),
    engagements: [{ target: "ENGAGEMENT_CANARY" }],
    projects: [{ repository: "PROJECT_CANARY" }],
    upstreams: [{ path: "UPSTREAM_CANARY" }],
    ...overrides
  };
}

test("projects exact GATE campaign numbers without private observer prose", () => {
  const fleet = projectGateObserverStatus(observer(), { receivedAt: NOW, revision: 7 });
  assert.equal(fleet.apiVersion, "gate.local-fleet/v1");
  assert.equal(fleet.coverage.state, "exact");
  assert.deepEqual(fleet.summary.campaigns, { value: 2, precision: "exact" });
  assert.deepEqual(fleet.summary.profileAnswers, { answered: 14, total: 70, precision: "exact" });
  assert.deepEqual(fleet.summary.activeWorkflows, { value: 1, precision: "exact" });
  assert.deepEqual(fleet.summary.runningExecutions, { value: 1, precision: "exact" });
  assert.deepEqual(fleet.summary.campaignTokens, { availability: "exact", total: 1200 });
  assert.deepEqual(fleet.summary.hostTokens, {
    availability: "exact",
    input: 800000000,
    cachedInput: 400000000,
    output: 199999999,
    total: 999999999,
    cost: { availability: "unavailable", amountMicros: null, unit: null }
  });
  assert.equal(fleet.campaigns[0].progress, null, "case completion must remain indeterminate");
  assert.deepEqual(fleet.campaigns[1].progress, { completed: 14, total: 70, percent: 20 });
  assert.deepEqual(fleet.campaigns.map((item) => item.alias), ["Campaign 1", "Campaign 2"]);
  assert.ok(validateLocalFleet(fleet, { now: NOW }));

  const serialized = JSON.stringify(fleet);
  for (const canary of [
    "PRIVATE TARGET CANARY", "TARGET_CANARY", "PATH_CANARY", "PROMPT_CANARY", "COMMAND_CANARY", "TOOL_CANARY",
    "AUTH_CANARY", "EVIDENCE_CANARY", "RAW_OUTPUT_CANARY", "HOST_TOKEN_CANARY",
    "OPERATOR_CANARY", "ENGAGEMENT_CANARY", "PROJECT_CANARY", "UPSTREAM_CANARY", "0123456789abcdef", "fedcba9876543210"
  ]) assert.equal(serialized.includes(canary), false, `projection leaked ${canary}`);
});

test("partial coverage and missing tokens remain explicit lower bounds, never invented zeros", () => {
  const value = observer({
    caseScan: caseScan({ discovered: 2, scanned: 1, omitted: 1, complete: false, truncated: true, omittedAtLeast: true }),
    cases: [sourceCase({ usage: { availability: "unavailable", totalTokens: null } })]
  });
  const fleet = projectGateObserverStatus(value, { receivedAt: NOW });
  assert.equal(fleet.coverage.state, "lower-bound");
  assert.equal(fleet.coverage.cases.discoveredAtLeast, false);
  assert.equal(fleet.coverage.cases.omittedAtLeast, true);
  assert.deepEqual(fleet.summary.campaigns, { value: 2, precision: "lower-bound" });
  assert.deepEqual(fleet.summary.activeWorkflows, { value: 1, precision: "lower-bound" });
  assert.deepEqual(fleet.summary.campaignTokens, { availability: "unavailable", total: null });
  assert.deepEqual(fleet.campaigns[0].tokens, { availability: "unavailable", total: null });
  assert.ok(validateLocalFleet(fleet, { now: NOW }));
});

test("unavailable scans withhold their cached rows and fleet totals", () => {
  const unavailableCases = {
    availability: "unavailable",
    discovered: null,
    scanned: null,
    omitted: null,
    invalid: null,
    discoveredAtLeast: false,
    omittedAtLeast: false,
    complete: false,
    truncated: true
  };
  const fleet = projectGateObserverStatus(observer({ caseScan: unavailableCases }), { receivedAt: NOW });
  assert.equal(fleet.coverage.state, "unavailable");
  assert.deepEqual(fleet.summary.campaigns, { value: null, precision: "unavailable" });
  assert.equal(fleet.campaigns.some((item) => item.kind === "case"), false);
  assert.equal(fleet.campaigns.some((item) => item.kind === "profile"), true);
  assert.deepEqual(fleet.summary.campaignTokens, { availability: "unavailable", total: null });
  assert.ok(validateLocalFleet(fleet, { now: NOW }));

  const unavailableProfiles = {
    availability: "unavailable",
    discovered: null,
    scanned: null,
    omitted: null,
    invalid: null,
    visible: 1,
    representedByCases: null,
    discoveredAtLeast: false,
    omittedAtLeast: false,
    complete: false,
    truncated: true
  };
  const warmFailure = projectGateObserverStatus(observer({ profileSetupScan: unavailableProfiles }), { receivedAt: NOW });
  assert.equal(warmFailure.campaigns.some((item) => item.kind === "profile"), false, "cached profiles are not current rows");
  assert.equal(warmFailure.coverage.profiles.visible, null, "cached source counts are withheld with unavailable coverage");
  assert.deepEqual(warmFailure.summary.profileAnswers, { answered: null, total: null, precision: "unavailable" });
  assert.ok(validateLocalFleet(warmFailure, { now: NOW }));
});

test("runtime loss prevents exact work and token claims", () => {
  const fleet = projectGateObserverStatus(observer({
    cases: [sourceCase({
      runtimeHealth: { status: "unavailable", reason: "runtime-observation-failed" },
      usage: { availability: "unavailable", totalTokens: null },
      execution: { runningCount: null },
      workflows: { counts: { active: null }, scan: { complete: false, truncated: true }, instances: [] },
      offlineAnalysis: { runningCount: null }
    })]
  }), { receivedAt: NOW });
  assert.equal(fleet.coverage.state, "lower-bound");
  assert.deepEqual(fleet.campaigns[0].work.runningExecutions, { value: null, precision: "unavailable" });
  assert.deepEqual(fleet.summary.runningExecutions, { value: null, precision: "unavailable" });
  assert.deepEqual(fleet.summary.campaignTokens, { availability: "unavailable", total: null });
});

test("contradictory exact scans and unknown source fields fail closed", () => {
  assert.throws(() => projectGateObserverStatus(observer({
    caseScan: caseScan({ discovered: 2, scanned: 1 })
  }), { receivedAt: NOW }), /coverage/u);
  assert.throws(() => projectGateObserverStatus({ ...observer(), secretCanary: "SECRET_CANARY" }, { receivedAt: NOW }), /invalid/u);
  assert.throws(() => projectGateObserverStatus(observer({
    cases: [sourceCase({ state: "secret-state-canary" })]
  }), { receivedAt: NOW }), /campaign/u);
  assert.throws(() => projectGateObserverStatus(observer({ state: "future-state-canary" }), { receivedAt: NOW }), /invalid/u);
  assert.throws(() => projectGateObserverStatus(observer({
    cases: [sourceCase(), sourceCase()],
    caseScan: caseScan({ discovered: 2, scanned: 2 })
  }), { receivedAt: NOW }), /duplicate/u);
});

test("invalid tombstone rows follow observer scan accounting without becoming exact", () => {
  const tombstone = sourceCase({
    id: "case_1111111111111111",
    displayName: "Invalid case",
    status: "invalid",
    binding: null,
    isolation: null,
    runtimeHealth: { status: "unavailable", reason: "invalid-case" },
    state: "blocked",
    telemetry: { freshness: "unknown", lastActivityAt: null, ageSeconds: null },
    usage: { availability: "unavailable", totalTokens: null },
    execution: { runningCount: null },
    workflows: { counts: { active: null }, scan: { complete: false, truncated: true }, instances: [] },
    offlineAnalysis: { runningCount: null }
  });
  const fleet = projectGateObserverStatus(observer({
    cases: [sourceCase(), tombstone],
    caseScan: caseScan({ discovered: 3, scanned: 3, invalid: 2, complete: false, truncated: true })
  }), { receivedAt: NOW });
  assert.equal(fleet.coverage.state, "lower-bound");
  assert.equal(fleet.campaigns.filter((item) => item.kind === "case").length, 2);
  assert.ok(validateLocalFleet(fleet, { now: NOW }));
});

test("missing token totals downgrade safely and large cumulative totals remain valid", () => {
  const missing = projectGateObserverStatus(observer({
    cases: [sourceCase({ usage: { availability: "estimated", totalTokens: null } })]
  }), { receivedAt: NOW });
  assert.deepEqual(missing.campaigns[0].tokens, { availability: "unavailable", total: null });
  assert.deepEqual(missing.summary.campaignTokens, { availability: "unavailable", total: null });

  const large = projectGateObserverStatus(observer({
    cases: [sourceCase({ usage: { availability: "estimated", totalTokens: 5_000_000_000 } })]
  }), { receivedAt: NOW });
  assert.deepEqual(large.campaigns[0].tokens, { availability: "estimated", total: 5_000_000_000 });
  assert.deepEqual(large.summary.campaignTokens, { availability: "estimated", total: 5_000_000_000 });
  assert.ok(validateLocalFleet(large, { now: NOW }));
});

test("campaign aliases remain bounded across observer pseudonym churn", () => {
  const aliases = new Map();
  for (let index = 0; index < 1_100; index += 1) {
    const sourceId = `case_${index.toString(16).padStart(16, "0")}`;
    const fleet = projectGateObserverStatus(observer({ cases: [sourceCase({ id: sourceId })] }), {
      aliases,
      receivedAt: NOW,
      revision: index + 1
    });
    assert.ok(fleet.campaigns.every((item) => /^Campaign (?:[1-9]|[1-5]\d|6[0-4])$/u.test(item.alias)));
    assert.ok(aliases.size <= 2);
  }
});

test("observer endpoint is fixed to explicit HTTP loopback", () => {
  assert.equal(normalizeGateObserverUrl("http://127.0.0.1:4173/api/status"), "http://127.0.0.1:4173/api/status");
  assert.equal(normalizeGateObserverUrl("http://[::1]:4173/api/status"), "http://[::1]:4173/api/status");
  for (const value of [
    "https://127.0.0.1:4173/api/status",
    "http://localhost:4173/api/status",
    "http://127.0.0.1:0/api/status",
    "http://user:pass@127.0.0.1:4173/api/status",
    "http://127.0.0.1:4173/api/events",
    "http://127.0.0.1:4173/api/status?",
    "http://127.0.0.1:4173/api/status#",
    "http://127.0.0.1:4173/api/status?private=yes",
    "http://192.168.1.4:4173/api/status"
  ]) assert.throws(() => normalizeGateObserverUrl(value), /loopback/u);
});

test("provider rejects redirects, wrong MIME, oversized bodies, and malformed status as unavailable", async () => {
  const responses = [
    new Response("", { status: 302, headers: { Location: "http://127.0.0.1:4173/api/status" } }),
    new Response("{}", { status: 200, headers: { "Content-Type": "text/plain" } }),
    new Response("{}", { status: 200, headers: { "Content-Type": "application/json", "Content-Length": "2000001" } }),
    new Response(JSON.stringify({ ...observer(), apiVersion: "gate.observer/v2" }), { status: 200, headers: { "Content-Type": "application/json" } })
  ];
  for (const response of responses) {
    const provider = createGateFleetProvider({
      fetchImpl: async () => response,
      cacheMs: 0,
      now: () => NOW.getTime()
    });
    const fleet = await provider();
    assert.equal(fleet.connection, "unavailable");
    assert.deepEqual(fleet.campaigns, []);
    assert.ok(validateLocalFleet(fleet, { now: NOW }));
  }
});

test("provider bounds streamed bodies and observer response time", async () => {
  const oversizedStream = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(700));
      controller.enqueue(new Uint8Array(700));
      controller.close();
    }
  });
  const oversized = createGateFleetProvider({
    fetchImpl: async () => new Response(oversizedStream, { status: 200, headers: { "Content-Type": "application/json" } }),
    maximumBytes: 1_024,
    cacheMs: 0,
    now: () => NOW.getTime()
  });
  assert.equal((await oversized()).connection, "unavailable");

  const timedOut = createGateFleetProvider({
    fetchImpl: async (_url, options) => new Promise((resolve, reject) => {
      options.signal.addEventListener("abort", () => reject(options.signal.reason), { once: true });
    }),
    timeoutMs: 50,
    cacheMs: 0,
    now: () => NOW.getTime()
  });
  const before = Date.now();
  assert.equal((await timedOut()).connection, "unavailable");
  assert.ok(Date.now() - before < 1_000, "timeout should fail closed promptly");
});

test("provider keeps host/session and canonical case token scopes separate", async () => {
  const provider = createGateFleetProvider({
    fetchImpl: async () => new Response(JSON.stringify(observer()), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    }),
    cacheMs: 0,
    now: () => NOW.getTime()
  });
  const fleet = await provider();
  assert.equal(fleet.connection, "connected");
  assert.deepEqual(fleet.summary.campaignTokens, { availability: "exact", total: 1200 });
  assert.notEqual(fleet.summary.campaignTokens.total, 999999999);
  assert.equal(fleet.summary.hostTokens.total, 999999999);
  assert.equal(fleet.summary.hostTokens.cost.availability, "unavailable");
  assert.equal(validateLocalFleet({ ...fleet, privateCanary: "PRIVATE_FLEET_CANARY" }, { now: NOW }), null);
});

test("host token projection preserves unavailable provenance and never leaks session records", () => {
  const fleet = projectGateObserverStatus(observer({
    usage: {
      availability: "unavailable",
      inputTokens: 123,
      cachedInputTokens: 456,
      outputTokens: 789,
      totalTokens: 1368,
      sessions: [{ id: "PRIVATE_SESSION_CANARY", path: "/private/session.jsonl" }]
    }
  }), { receivedAt: NOW });
  assert.deepEqual(fleet.summary.hostTokens, {
    availability: "unavailable",
    input: null,
    cachedInput: null,
    output: null,
    total: null,
    cost: { availability: "unavailable", amountMicros: null, unit: null }
  });
  assert.doesNotMatch(JSON.stringify(fleet), /PRIVATE_SESSION_CANARY|session\.jsonl/u);
});

test("an empty case fleet awaits attribution instead of inventing exact zero", () => {
  const fleet = projectGateObserverStatus(observer({
    cases: [],
    caseScan: caseScan({ discovered: 0, scanned: 0 }),
    profileSetups: [],
    profileSetupScan: profileScan({ discovered: 0, scanned: 0, visible: 0 })
  }), { receivedAt: NOW });
  assert.deepEqual(fleet.summary.campaignTokens, { availability: "unavailable", total: null });
});
