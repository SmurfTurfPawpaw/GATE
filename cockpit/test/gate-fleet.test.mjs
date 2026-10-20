import assert from "node:assert/strict";
import test from "node:test";

import { pilotCockpitPresentation, validateLocalFleet } from "../assets/model.js";
import {
  createGateFleetProvider,
  normalizeGateObserverUrl,
  projectGateObserverStatus
} from "../companion/gate-fleet.mjs";

const NOW = new Date("2026-10-16T14:40:00.000Z");
const pilotMetric = (value) => ({ availability: "available", value });

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
      startedAt: "2026-10-16T14:39:50.000Z",
      finishedAt: null,
      updatedAt: "2026-10-16T14:39:59.000Z",
      elapsedMs: 9_000,
      progress: { availability: "unavailable", completed: null, total: null, percent: null },
      usage: {
        tokens: { availability: "unavailable", total: null },
        cost: { availability: "unavailable", amountMicros: null, unit: null },
        requests: { availability: "unavailable", value: null },
        retries: { availability: "unavailable", value: null },
        toolRuns: { availability: "exact", value: 1 }
      },
      entries: [{
        sequence: 1,
        at: "2026-10-16T14:39:50.000Z",
        channel: "command",
        state: "running",
        fidelity: "redacted",
        truncated: false,
        text: "httpx -u [redacted]"
      }]
    }],
    ...overrides
  };
}

function pilotProjection(overrides = {}) {
  return {
    availability: "available",
    reason: null,
    observedAt: "2026-10-16T14:39:59.000Z",
    validUntil: "2026-10-16T14:42:59.000Z",
    solving: {
      availability: "available", verdict: "pass", now: "complete", actionNeeded: "none",
      updatedAt: "2026-10-16T14:39:59.000Z",
      completion: { state: "complete", reproduction: "confirmed", externalAcceptance: "accepted" },
      objectives: { availability: "available", completed: 1, total: 1 },
      depth: { level: "systematic", branchesExplored: pilotMetric(7), techniquesAttempted: pilotMetric(5), deadEndsRetired: pilotMetric(2) },
      efficiency: { elapsedSeconds: pilotMetric(900), activeSeconds: pilotMetric(600), tokens: pilotMetric(12000), toolRuns: pilotMetric(8), requests: pilotMetric(31), retries: pilotMetric(1) }
    },
    learning: {
      availability: "available", verdict: "provisional", now: "checking", actionNeeded: "review",
      updatedAt: "2026-10-16T14:39:59.000Z",
      stages: { observations: pilotMetric(6), candidates: pilotMetric(4), validated: pilotMetric(3), applied: pilotMetric(2), transferred: pilotMetric(0), regressed: pilotMetric(0) }
    },
    cockpit: {
      availability: "available", verdict: "pass", now: "current", actionNeeded: "none",
      updatedAt: "2026-10-16T14:39:59.000Z",
      signals: { availability: "available", available: 10, total: 10 },
      updatesPublished: pilotMetric(12), updatesMissed: pilotMetric(0)
    },
    integrity: {
      availability: "available", status: "consistent",
      checks: { availability: "available", available: 6, total: 6 },
      issues: pilotMetric(0), checkedAt: "2026-10-16T14:39:59.000Z"
    },
    ...overrides
  };
}

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
  const value = {
    id: "case_0123456789abcdef",
    displayName: "HackerOne CTF",
    status: "ready",
    binding: { privateTarget: "https://TARGET_CANARY.invalid" },
    isolation: { privatePath: "/private/PATH_CANARY" },
    runtimeHealth: { status: "available", reason: null },
    state: "running",
    counts: { privateSummary: "PROMPT_CANARY" },
    telemetry: { freshness: "fresh", lastActivityAt: "2026-10-16T14:39:59.000Z", ageSeconds: 1 },
    usage: { availability: "exact", totalTokens: 1200 },
    execution: {
      runningCount: 1,
      privateCommand: "COMMAND_CANARY",
      mirror: { availability: "unavailable", reason: "no-attempts", attempts: [] }
    },
    workflows: {
      counts: { active: 1 },
      scan: { complete: true, truncated: false },
      instances: [{ activePhase: { lane: "active-testing", privateTool: "TOOL_CANARY" } }]
    },
    engagementScan: { privateAuthority: "AUTH_CANARY" },
    offlineAnalysis: { runningCount: 0, privateEvidence: "EVIDENCE_CANARY" },
    activity: [
      { at: "2026-10-16T14:39:59.000Z", kind: "campaign.job", status: "running", summary: "RAW_OUTPUT_CANARY" },
      { summary: "RAW_OUTPUT_CANARY" }
    ],
    learningCount: 99,
  };
  return {
    ...value,
    ...overrides,
    execution: { ...value.execution, ...(overrides.execution || {}) }
  };
}

function sourceProfile(overrides = {}) {
  return {
    id: "program_fedcba9876543210",
    displayName: "Uber Bug Bounty",
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
  assert.equal(fleet.apiVersion, "gate.local-fleet/v4");
  assert.equal(fleet.coverage.state, "exact");
  assert.deepEqual(fleet.summary.campaigns, { value: 2, precision: "exact" });
  assert.deepEqual(fleet.summary.profileAnswers, { answered: 14, total: 70, precision: "exact" });
  assert.deepEqual(fleet.summary.activeWorkflows, { value: 1, precision: "exact" });
  assert.deepEqual(fleet.summary.runningExecutions, { value: 1, precision: "exact" });
  assert.deepEqual(fleet.summary.setupBlockers, { value: 0, precision: "exact" });
  assert.deepEqual(fleet.summary.blockers, { value: 0, precision: "exact" });
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
  assert.deepEqual(fleet.campaigns.map((item) => item.context), [
    { label: "HackerOne CTF", nextSection: null },
    { label: "Uber Bug Bounty", nextSection: "authority-sources" }
  ]);
  assert.ok(validateLocalFleet(fleet, { now: NOW }));

  const serialized = JSON.stringify(fleet);
  for (const canary of [
    "TARGET_CANARY", "PATH_CANARY", "PROMPT_CANARY", "COMMAND_CANARY", "TOOL_CANARY",
    "AUTH_CANARY", "EVIDENCE_CANARY", "RAW_OUTPUT_CANARY", "HOST_TOKEN_CANARY",
    "OPERATOR_CANARY", "ENGAGEMENT_CANARY", "PROJECT_CANARY", "UPSTREAM_CANARY", "0123456789abcdef", "fedcba9876543210"
  ]) assert.equal(serialized.includes(canary), false, `projection leaked ${canary}`);
});

test("unsafe campaign labels become null without invalidating campaigns", () => {
  const unsafeLabels = [
    "https://example.invalid/program",
    "/home/operator/program",
    "C:\\Users\\operator\\program",
    "password=private-canary",
    "Bearer abcdefghijklmnopqrstuvwxyz",
    "Basic abcdefghijklmnopqrstuvwxyz",
    "Bad\u0007Title",
    "A".repeat(81),
    "portal.example.com",
    "Project (api.example.com)",
    "Project example.com, next",
    "Target 10.0.0.1",
    "ghp_ABCDEFGHIJKL1234",
    "glpat-ABCDEFGHIJKLMNOPQRST",
    "eyJabcdefgh.abcdefghijkl.abcdefghijkl"
  ];
  for (const displayName of unsafeLabels) {
    const fleet = projectGateObserverStatus(observer({
      cases: [sourceCase({ displayName })],
      profileSetups: [sourceProfile({ displayName })]
    }), { receivedAt: NOW });
    assert.deepEqual(fleet.campaigns.map((item) => item.context), [
      { label: null, nextSection: null },
      { label: null, nextSection: "authority-sources" }
    ]);
    assert.deepEqual(fleet.campaigns.map((item) => item.alias), ["Campaign 1", "Campaign 2"]);
  }
});

test("questionnaire findings remain remaining work instead of becoming blocker totals", () => {
  const fleet = projectGateObserverStatus(observer({
    profileSetups: [sourceProfile({ blockerCount: 255 })]
  }), { receivedAt: NOW });
  const profile = fleet.campaigns.find((item) => item.kind === "profile");

  assert.deepEqual(profile.progress, { completed: 14, total: 70, percent: 20 });
  assert.equal(profile.attention, "response-needed");
  assert.equal(profile.context.nextSection, "authority-sources");
  assert.deepEqual(profile.work.setupBlockers, { value: 0, precision: "exact" });
  assert.deepEqual(fleet.summary.setupBlockers, { value: 0, precision: "exact" });
  assert.deepEqual(fleet.summary.blockers, { value: 0, precision: "exact" });

  const reviewFleet = projectGateObserverStatus(observer({
    profileSetups: [sourceProfile({
      stage: "operator-review",
      progress: { answered: 70, total: 70 },
      blockerCount: 2,
      nextSection: null
    })]
  }), { receivedAt: NOW });
  const reviewProfile = reviewFleet.campaigns.find((item) => item.kind === "profile");
  assert.deepEqual(reviewProfile.work.setupBlockers, { value: 2, precision: "exact" });
  assert.deepEqual(reviewFleet.summary.setupBlockers, { value: 2, precision: "exact" });
  assert.deepEqual(reviewFleet.summary.blockers, { value: 2, precision: "exact" });
});

test("execution mirror is opt-in, strictly bounded, and suppressed for unavailable runtimes", () => {
  const source = observer({ cases: [sourceCase({ execution: { mirror: executionMirror() } })] });
  const disabled = projectGateObserverStatus(source, { receivedAt: NOW, revision: 19 });
  assert.deepEqual(disabled.campaigns[0].mirror, { availability: "unavailable", reason: "disabled", attempts: [] });

  const enabled = projectGateObserverStatus(source, {
    receivedAt: NOW,
    revision: 20,
    includeExecutionMirror: true
  });
  assert.equal(enabled.campaigns[0].mirror.availability, "available");
  assert.equal(enabled.campaigns[0].mirror.attempts[0].entries[0].text, "httpx -u [redacted]");
  assert.equal(Object.isFrozen(enabled.campaigns[0].mirror.attempts[0].entries), true);
  assert.ok(validateLocalFleet(enabled, { now: NOW }));

  const unavailable = projectGateObserverStatus(observer({
    cases: [sourceCase({
      status: "invalid",
      runtimeHealth: { status: "unavailable", reason: "invalid-case" },
      state: "blocked",
      usage: { availability: "unavailable", totalTokens: null },
      execution: { runningCount: null, mirror: executionMirror() },
      workflows: { counts: { active: null }, scan: { complete: false, truncated: true }, instances: [] },
      offlineAnalysis: { runningCount: null }
    })]
  }), { receivedAt: NOW, revision: 21, includeExecutionMirror: true });
  assert.deepEqual(unavailable.campaigns[0].mirror, {
    availability: "unavailable", reason: "source-unavailable", attempts: []
  });

  const unsafe = sourceCase({ execution: { mirror: executionMirror() } });
  unsafe.execution.mirror.attempts[0].entries[0].text = `password=${"C".repeat(32)}`;
  assert.throws(() => projectGateObserverStatus(observer({ cases: [unsafe] }), {
    receivedAt: NOW,
    revision: 22,
    includeExecutionMirror: true
  }), /invalid GATE observer campaign/u);
});

test("active cases and blocked cases remain visible when workflow and profile blocker counts are zero", () => {
  const runningFleet = projectGateObserverStatus(observer({
    cases: [sourceCase({
      state: "running",
      execution: { runningCount: 0 },
      workflows: { counts: { active: 0 }, scan: { complete: true, truncated: false }, instances: [] },
      offlineAnalysis: { runningCount: 0 }
    })],
    profileSetups: [],
    profileSetupScan: profileScan({ discovered: 0, scanned: 0, visible: 0 })
  }), { receivedAt: NOW, revision: 17 });
  assert.deepEqual(runningFleet.summary.active, { value: 1, precision: "exact" });
  assert.deepEqual(runningFleet.summary.activeWorkflows, { value: 0, precision: "exact" });
  assert.deepEqual(runningFleet.summary.blockers, { value: 0, precision: "exact" });

  const blockedFleet = projectGateObserverStatus(observer({
    cases: [sourceCase({
      state: "blocked",
      execution: { runningCount: 0 },
      workflows: { counts: { active: 0 }, scan: { complete: true, truncated: false }, instances: [] },
      offlineAnalysis: { runningCount: 0 }
    })],
    profileSetups: [],
    profileSetupScan: profileScan({ discovered: 0, scanned: 0, visible: 0 })
  }), { receivedAt: NOW, revision: 18 });
  assert.deepEqual(blockedFleet.summary.setupBlockers, { value: 0, precision: "exact" });
  assert.deepEqual(blockedFleet.summary.blockers, { value: 1, precision: "exact" });
  assert.ok(validateLocalFleet(blockedFleet, { now: NOW }));
});

test("projects independent CTF pilot verdicts without a composite score", () => {
  const fleet = projectGateObserverStatus(observer({
    cases: [sourceCase({ ctfPilot: pilotProjection() })]
  }), { receivedAt: NOW, revision: 8 });
  const campaign = fleet.campaigns.find((item) => item.kind === "case");
  assert.equal(campaign.pilot.solving.verdict, "pass");
  assert.equal(campaign.pilot.learning.verdict, "provisional");
  assert.equal(campaign.pilot.cockpit.verdict, "pass");
  assert.equal(Object.hasOwn(campaign.pilot, "score"), false);
  assert.ok(validateLocalFleet(fleet, { now: NOW }));

  const view = pilotCockpitPresentation(fleet, campaign.alias);
  assert.equal(view.alias, campaign.alias);
  assert.equal(view.solving.verdict, "pass");
  assert.equal(view.solving.now, "complete");
  assert.equal(view.depth.techniquesAttempted, 5);
  assert.equal(view.learning.stages.applied, 2);
  assert.equal(view.learning.stages.transferred, 0);
  assert.equal(view.cockpit.signals.available, 10);
  assert.equal(view.integrity.status, "consistent");
  assert.deepEqual(view.latestEvent, { category: "campaign", status: "running", at: "2026-10-16T14:39:59.000Z" });

  const soleCaseView = pilotCockpitPresentation(fleet);
  assert.equal(soleCaseView.state, "available");
  assert.equal(soleCaseView.alias, campaign.alias);
});

test("a near-expiry pilot caps fleet lifetime and is withheld at its exact deadline", () => {
  const deadline = new Date(NOW.getTime() + 500);
  const pilot = pilotProjection({ validUntil: deadline.toISOString() });
  const source = observer({ cases: [sourceCase({ ctfPilot: pilot })] });

  const beforeExpiry = projectGateObserverStatus(source, { receivedAt: NOW, revision: 9 });
  assert.equal(beforeExpiry.campaigns[0].pilot.availability, "available");
  assert.equal(beforeExpiry.campaigns[0].pilot.validUntil, deadline.toISOString());
  assert.equal(beforeExpiry.validUntil, deadline.toISOString());
  assert.ok(validateLocalFleet(beforeExpiry, { now: NOW }));
  assert.equal(validateLocalFleet(beforeExpiry, { now: deadline }), null);

  const atExpiry = projectGateObserverStatus(source, { receivedAt: deadline, revision: 10 });
  assert.equal(atExpiry.campaigns[0].pilot.availability, "unavailable");
  assert.equal(atExpiry.campaigns[0].pilot.reason, "expired");
  assert.equal(atExpiry.campaigns[0].pilot.validUntil, null);
  assert.ok(validateLocalFleet(atExpiry, { now: deadline }));
});

test("observer outage is explicit, actionable, and never rendered as idle or zero", () => {
  const view = pilotCockpitPresentation(null);
  assert.equal(view.state, "feed-unavailable");
  assert.equal(view.title, "Pilot feed unavailable");
  assert.match(view.recovery, /observer and dedicated runner/u);
  assert.equal(view.solving.verdict, null);
  assert.equal(view.solving.now, null);
  assert.equal(view.solving.actionNeeded, null);
  assert.equal(JSON.stringify(view).includes('"idle"'), false);
  assert.equal(JSON.stringify(view).includes('"outcome":0'), false);
});

test("the primary pilot never silently selects the first of multiple cases", () => {
  const fleet = projectGateObserverStatus(observer({
    cases: [
      sourceCase({ id: "case_0123456789abcdef", ctfPilot: pilotProjection() }),
      sourceCase({ id: "case_fedcba9876543210", ctfPilot: pilotProjection() })
    ],
    caseScan: caseScan({ discovered: 2, scanned: 2 })
  }), { receivedAt: NOW, revision: 9 });
  const unselected = pilotCockpitPresentation(fleet);
  assert.equal(unselected.state, "selection-required");
  assert.equal(unselected.alias, null);
  assert.deepEqual(unselected.aliases, ["Campaign 1", "Campaign 2"]);
  assert.equal(unselected.solving.verdict, null);
  const selected = pilotCockpitPresentation(fleet, "Campaign 2");
  assert.equal(selected.state, "available");
  assert.equal(selected.alias, "Campaign 2");
});

test("expired fleet projections are unavailable rather than idle or zero", () => {
  const fleet = projectGateObserverStatus(observer(), { receivedAt: NOW, revision: 11 });
  assert.equal(validateLocalFleet(fleet, { now: new Date(Date.parse(fleet.validUntil)) }), null);
  const view = pilotCockpitPresentation(null);
  assert.equal(view.state, "feed-unavailable");
  assert.equal(view.solving.verdict, null);
  assert.equal(view.efficiency.tokens, null);
});

test("pilot projection rejects unallowlisted target and operation details", () => {
  assert.throws(() => projectGateObserverStatus(observer({
    cases: [sourceCase({ ctfPilot: { ...pilotProjection(), flag: "FLAG_CANARY", target: "TARGET_CANARY" } })]
  }), { receivedAt: NOW }), /campaign/u);
});

test("fleet validators reject impossible learning transfer counts even with partial stage telemetry", () => {
  const impossiblePilot = structuredClone(pilotProjection());
  impossiblePilot.learning.stages.observations = { availability: "unavailable", value: null };
  impossiblePilot.learning.stages.transferred = pilotMetric(3);
  assert.throws(() => projectGateObserverStatus(observer({
    cases: [sourceCase({ ctfPilot: impossiblePilot })]
  }), { receivedAt: NOW, revision: 9 }), /campaign/u);

  const fleet = projectGateObserverStatus(observer({
    cases: [sourceCase({ ctfPilot: pilotProjection() })]
  }), { receivedAt: NOW, revision: 10 });
  const malformed = structuredClone(fleet);
  const stages = malformed.campaigns.find((item) => item.kind === "case").pilot.learning.stages;
  stages.observations = { availability: "unavailable", value: null };
  stages.transferred = pilotMetric(3);
  assert.equal(validateLocalFleet(malformed, { now: NOW }), null);
});

test("contradictory PASS verdicts and future pilot timestamps fail closed", () => {
  const cases = [
    (() => {
      const pilot = structuredClone(pilotProjection());
      pilot.solving.objectives.completed = 0;
      return pilot;
    })(),
    (() => {
      const pilot = structuredClone(pilotProjection());
      pilot.learning.verdict = "pass";
      return pilot;
    })(),
    (() => {
      const pilot = structuredClone(pilotProjection());
      pilot.cockpit.signals.available = 9;
      return pilot;
    })(),
    (() => {
      const pilot = structuredClone(pilotProjection());
      pilot.solving.updatedAt = "2026-10-16T14:40:01.000Z";
      return pilot;
    })()
  ];
  for (const pilot of cases) {
    assert.throws(() => projectGateObserverStatus(observer({
      cases: [sourceCase({ ctfPilot: pilot })]
    }), { receivedAt: NOW }), /campaign/u);
  }
});

test("a stale pilot is downgraded while the current fleet remains available", () => {
  const pilot = structuredClone(pilotProjection());
  pilot.observedAt = "2026-10-16T14:36:59.000Z";
  pilot.validUntil = "2026-10-16T14:39:59.000Z";
  for (const axis of [pilot.solving, pilot.learning, pilot.cockpit]) axis.updatedAt = pilot.observedAt;
  pilot.integrity.checkedAt = pilot.observedAt;
  const fleet = projectGateObserverStatus(observer({
    cases: [sourceCase({ ctfPilot: pilot })]
  }), { receivedAt: NOW });
  assert.equal(fleet.connection, "connected");
  assert.equal(fleet.campaigns[0].pilot.availability, "unavailable");
  assert.equal(fleet.campaigns[0].pilot.solving.verdict, null);
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

test("provider includes execution mirrors only when explicitly enabled", async () => {
  const source = observer({ cases: [sourceCase({ execution: { mirror: executionMirror() } })] });
  const response = () => new Response(JSON.stringify(source), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
  const disabled = createGateFleetProvider({
    fetchImpl: async () => response(),
    cacheMs: 0,
    now: () => NOW.getTime()
  });
  const enabled = createGateFleetProvider({
    fetchImpl: async () => response(),
    cacheMs: 0,
    now: () => NOW.getTime(),
    includeExecutionMirror: true
  });
  assert.equal((await disabled()).campaigns[0].mirror.reason, "disabled");
  assert.equal((await enabled()).campaigns[0].mirror.availability, "available");
  assert.throws(() => createGateFleetProvider({ includeExecutionMirror: "yes" }), /option is invalid/u);
});

test("provider keeps host/session and canonical case token scopes separate", async () => {
  let source = observer();
  const provider = createGateFleetProvider({
    fetchImpl: async () => new Response(JSON.stringify(source), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    }),
    cacheMs: 0,
    now: () => NOW.getTime()
  });
  const fleet = await provider();
  const nextFleet = await provider();
  assert.equal(fleet.connection, "connected");
  assert.match(fleet.selectionEpoch, /^[a-f0-9]{32}$/u);
  assert.equal(nextFleet.selectionEpoch, fleet.selectionEpoch, "one provider lifetime must keep one alias-selection epoch");
  source = observer({ cases: [sourceCase({ id: "case_fedcba9876543210" })] });
  const reboundFleet = await provider();
  assert.notEqual(reboundFleet.selectionEpoch, fleet.selectionEpoch,
    "an alias binding change must rotate the selection epoch");
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
