import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  createObserver,
  isLoopbackHost,
  projectSnapshot,
  startObserver,
  summarizeToolRuntimes
} from "../src/observer/server.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const paths = { repo };
const at = "2026-10-13T12:00:00.000Z";

function canonicalEvent(overrides = {}) {
  return {
    apiVersion: "gate.event/v1",
    id: "evt_observer001",
    at,
    runId: "run_CLIENT_CONTEXT_CANARY",
    taskId: "task_CLIENT_CONTEXT_CANARY",
    component: "gate-observer",
    agent: "CLIENT_MEMBER_CANARY",
    kind: "tool.started",
    status: "running",
    summary: "PROMPT_CANARY must stay private",
    effect: {
      class: "network-probe",
      targetRef: "https://target.invalid/private",
      engagementId: "eng_observer",
      planDigest: "a".repeat(64)
    },
    evidenceRefs: ["private://raw-output-canary"],
    usageRef: "usage://observer",
    ...overrides
  };
}

function canonicalLearning(overrides = {}) {
  return {
    apiVersion: "gate.learning/v1",
    id: "lrn_observer001",
    at,
    scope: "repository",
    cause: "A retry exposed https://target.invalid/private and /secret/path with api-key=topsecret and Authorization: Bearer JWT_SUFFIX_CANARY.",
    change: "Classify the retry before recording its result.",
    evidence: ["private://learning-evidence-canary"],
    status: "active",
    sensitivity: "public",
    supersedes: null,
    configurationRefs: ["config/private-canary.json"],
    ...overrides
  };
}

function executionFixture(overrides = {}) {
  return {
    capability: {
      configured: true,
      laneAvailable: true,
      mode: "supervised-generic",
      reason: null,
      enforced: [
        "engagement-binding",
        "target-argument-binding",
        "declared-action-label-binding",
        "tool-allowlist",
        "exact-argv",
        "shell-disabled",
        "executable-descriptor-observed-sha256",
        "minimal-environment",
        "private-stdout-stderr",
        "one-shot-claim",
        "declared-bounds-within-receipt",
        "PRIVATE_CAPABILITY_CANARY"
      ],
      bestEffort: ["authorization-revocation-polling", "wall-duration", "process-group-termination"],
      unavailable: [
        "egress-target-restriction",
        "request-count-measurement",
        "request-rate-measurement",
        "tool-concurrency-measurement",
        "token-measurement",
        "daemon-escape-containment",
        "filesystem-isolation",
        "credential-broker",
        "tool-artifact-inventory",
        "known-good-executable-provenance",
        "argv-action-semantics-validation",
        "supervisor-crash-containment",
        "immutable-executable-snapshot"
      ]
    },
    counts: {
      queued: 0,
      running: 1,
      stopping: 0,
      succeeded: 2,
      failed: 0,
      cancelled: 0,
      blocked: 0,
      unknown: 0
    },
    recent: [
      {
        runId: `xrun_${"1".repeat(32)}`,
        manifestId: `xmf_${"2".repeat(32)}`,
        engagementId: "customer-canary",
        status: "running",
        createdAt: at,
        startedAt: at,
        finishedAt: null,
        terminationReason: null,
        exitCode: null,
        signal: null,
        targetArgument: "TARGET_ARGUMENT_CANARY",
        argv: ["ARGV_CANARY"],
        executablePath: "/private/EXECUTABLE_PATH_CANARY",
        stdout: "STDOUT_CANARY",
        evidence: "EVIDENCE_CONTENT_CANARY"
      }
    ],
    ...overrides
  };
}

function offlineAnalysisFixture(overrides = {}) {
  return {
    capability: {
      configured: true,
      laneAvailable: true,
      mode: "bubblewrap-offline",
      reason: "PRIVATE_OFFLINE_REASON_CANARY",
      enforced: [
        "project-contract-binding",
        "typed-path-binding",
        "artifact-snapshot-sha256",
        "pinned-upstream-integrity",
        "fixed-adapter-argv",
        "bubblewrap-network-namespace",
        "read-only-runtime-mounts",
        "ephemeral-sandbox-writes",
        "shell-disabled",
        "cleared-environment",
        "private-bounded-evidence",
        "one-shot-claim",
        "wall-duration",
        "PRIVATE_OFFLINE_CAPABILITY_CANARY"
      ],
      unavailable: [
        "cpu-limit",
        "memory-limit",
        "immutable-managed-upstream-snapshot",
        "same-uid-gate-home-tamper-resistance",
        "unix-socket-system-call-denial"
      ]
    },
    counts: {
      queued: 0,
      running: 1,
      succeeded: 2,
      failed: 0,
      cancelled: 0,
      blocked: 0,
      unknown: 0
    },
    retention: {
      quotaBytes: 2_147_483_648,
      quotaArtifacts: 64,
      retainedBytes: 512,
      availableBytes: 2_147_483_136,
      overQuota: false,
      retainedArtifacts: 1,
      availableArtifacts: 63,
      retentionLockState: "absent",
      snapshotState: "consistent",
      pendingTransactions: 0,
      invalidTransactionRecords: 0,
      creatingManifests: 0,
      invalidCreationIntents: 0,
      invalidClaimRecords: 0,
      invalidPurgeRecords: 0,
      invalidRunRecords: 0,
      blockedManifests: 0,
      mutationBlocked: false,
      pendingManifests: 1,
      expiredManifests: 0,
      activeManifests: 0,
      terminalManifests: 0,
      unknownManifests: 0,
      purgePendingManifests: 0,
      purgedManifests: 0,
      orphanedArtifacts: 0,
      orphanedBytes: 0,
      missingArtifacts: 0,
      invalidEntries: 0,
      privatePath: "/private/OFFLINE_RETENTION_CANARY"
    },
    recent: [{
      runId: `arun_${"3".repeat(32)}`,
      manifestId: `amf_${"4".repeat(32)}`,
      projectId: "private-project-canary",
      status: "running",
      createdAt: at,
      startedAt: at,
      finishedAt: null,
      terminationReason: null,
      isolationVerified: null,
      artifactPath: "/private/OFFLINE_ARTIFACT_PATH_CANARY.exe",
      artifactSha256: "OFFLINE_ARTIFACT_HASH_CANARY",
      evidence: "OFFLINE_EVIDENCE_CANARY"
    }],
    ...overrides
  };
}

function statusFixture(overrides = {}) {
  return {
    at,
    repository: "/workspace/REPOSITORY_CANARY",
    gate_home: "/home/operator/GATE_HOME_CANARY",
    events: [
      canonicalEvent(),
      canonicalEvent({
        id: "evt_observer002",
        at: "2026-10-13T11:59:59.000Z",
        component: "C:/COMPONENT_PATH_CANARY/tool",
        agent: "home/AGENT_PATH_CANARY"
      })
    ],
    learnings: [
      canonicalLearning(),
      canonicalLearning({
        id: "lrn_observer002",
        scope: "session",
        cause: "PRIVATE_PROMPT_CANARY",
        change: "PRIVATE_CHANGE_CANARY",
        sensitivity: "private"
      })
    ],
    engagements: [
      {
        metadata: { id: "eng_CUSTOMER_CANARY", status: "approved" },
        authorization: { validUntil: "2026-10-14T12:00:00.000Z" },
        review: {
          noMistakes: { status: "passed" },
          operatorReceipt: { status: "approved" }
        },
        limits: { maxTokens: 25000 }
      }
    ],
    execution: executionFixture(),
    offlineAnalysis: offlineAnalysisFixture(),
    toolRuntimes: {
      ok: true,
      verificationMode: "current-bytes-and-install-smoke-evidence",
      platform: "linux-x64",
      catalog: 2,
      locked: 1,
      installed: 1,
      verified: 1,
      executable: 1,
      unresolved: 1,
      unresolvedConstraints: [{ reason: "managed-runtime-absent", count: 1 }],
      tools: [
        {
          id: "nuclei",
          name: "Nuclei",
          state: "verified-install-evidence",
          locked: true,
          installed: true,
          verified: true,
          executable: true,
          reasons: [],
          path: "/private/TOOL_RUNTIME_PATH_CANARY",
          sha256: "TOOL_RUNTIME_HASH_CANARY",
          url: "https://example.invalid/TOOL_RUNTIME_URL_CANARY"
        },
        {
          id: "wireshark",
          name: "Wireshark",
          state: "unmanaged",
          locked: false,
          installed: false,
          verified: false,
          executable: false,
          reasons: ["native-runtime-unavailable"]
        }
      ]
    },
    projects: [
      {
        id: "project_CUSTOMER_PROJECT_CANARY",
        status: "ready",
        provider: "github",
        executionProfile: "CLIENT_EXECUTION_PROFILE_CANARY",
        environment: "host",
        deliveryMode: "no-mistakes",
        deploymentEnabled: false,
        securityProfile: "CLIENT_SECURITY_PROFILE_CANARY",
        activeTestingEnabled: true,
        repositoryUrl: "https://github.com/CLIENT_OWNER_CANARY/CLIENT_REPOSITORY_CANARY",
        displayName: "CLIENT_DISPLAY_NAME_CANARY"
      }
    ],
    upstreams: [],
    tokens: {
      availability: "exact",
      source: "codex-session-jsonl",
      scannedFiles: 1,
      totals: {
        inputTokens: 11,
        cachedInputTokens: 3,
        outputTokens: 6,
        reasoningTokens: 2,
        totalTokens: 17
      },
      records: [
        {
          apiVersion: "gate.usage/v1",
          id: "use_observer001",
          at,
          runId: "codex.observer",
          taskId: null,
          agent: "codex",
          provider: "openai",
          model: "gpt-6",
          availability: "exact",
          measure: "cumulative",
          inputTokens: 11,
          cachedInputTokens: 3,
          outputTokens: 6,
          reasoningTokens: 2,
          totalTokens: 17,
          source: "codex-session-jsonl"
        }
      ]
    },
    ...overrides
  };
}

async function listen(t, statusBuilder, options = {}) {
  const server = await startObserver({
    paths,
    statusBuilder,
    host: "127.0.0.1",
    port: 0,
    refreshMs: 60_000,
    quiet: true,
    ...options
  });
  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
    server.closeAllConnections?.();
  }));
  const address = server.address();
  return { server, origin: `http://127.0.0.1:${address.port}` };
}

function request({ port, method = "GET", pathname = "/", headers = {} }) {
  return new Promise((resolve, reject) => {
    const operation = http.request({ host: "127.0.0.1", port, method, path: pathname, headers }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({
        status: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(chunks).toString("utf8")
      }));
    });
    operation.on("error", reject);
    operation.end();
  });
}

test("observer endpoints coalesce status reads and expose metadata-only projections", async (t) => {
  let calls = 0;
  let release;
  const waiting = new Promise((resolve) => { release = resolve; });
  const { origin } = await listen(t, async () => {
    calls += 1;
    await waiting;
    return statusFixture();
  });

  const responses = ["status", "events", "learnings"].map((name) => fetch(`${origin}/api/${name}`));
  for (let attempt = 0; attempt < 50 && calls === 0; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  release();
  assert.equal(calls, 1, "concurrent endpoint reads should share one buildStatus call");
  const [statusResponse, eventsResponse, learningsResponse] = await Promise.all(responses);
  const [status, events, learnings] = await Promise.all([
    statusResponse.json(),
    eventsResponse.json(),
    learningsResponse.json()
  ]);

  assert.equal(status.apiVersion, "gate.observer/v1");
  assert.equal(status.state, "running");
  assert.equal(status.counts.running, 2);
  assert.equal(status.counts.queued, 0);
  assert.equal(status.agents[0].stage, "tool.started");
  assert.equal(status.agents[0].effect, "network-probe");
  assert.equal(status.agents[0].updatedAt, at);
  assert.match(status.agents[0].id, /^member_[a-f0-9]{16}$/);
  assert.match(status.agents[0].runId, /^run_[a-f0-9]{16}$/);
  assert.match(status.agents[0].taskId, /^task_[a-f0-9]{16}$/);
  assert.equal(status.agents[0].agent, status.agents[0].id);
  assert.equal(status.agents[0].component, "gate-observer");
  assert.match(status.tasks[0].id, /^task_[a-f0-9]{16}$/);
  assert.equal(status.tasks[0].id, status.agents[0].taskId);
  for (const [prefix, raw, projected] of [
    ["member", "CLIENT_MEMBER_CANARY", status.agents[0].id],
    ["run", "run_CLIENT_CONTEXT_CANARY", status.agents[0].runId],
    ["task", "task_CLIENT_CONTEXT_CANARY", status.agents[0].taskId]
  ]) {
    assert.notEqual(
      projected,
      `${prefix}_${crypto.createHash("sha256").update(raw).digest("hex").slice(0, 16)}`,
      `${prefix} pseudonym must use the process key`
    );
  }
  assert.equal(status.usage.availability, "exact");
  assert.equal(status.usage.totalTokens, 17);
  assert.equal(status.usage.model, "gpt-6");
  assert.match(status.usage.sessions[0].id, /^session_[a-f0-9]{16}$/);
  assert.match(status.engagements[0].id, /^engagement_[a-f0-9]{16}$/);
  assert.notEqual(
    status.engagements[0].id,
    `engagement_${crypto.createHash("sha256").update("eng_CUSTOMER_CANARY").digest("hex").slice(0, 16)}`
  );
  assert.equal(status.engagements[0].status, "approved");
  assert.equal(status.engagements[0].manifestRequired, true);
  assert.equal(status.engagements[0].executionLaneAvailable, true);
  assert.equal(status.engagements[0].executionMode, "supervised-generic");
  assert.equal(status.engagements[0].executionEligibility, "manifest-required");
  assert.equal("preflightOnly" in status.engagements[0], false);
  assert.equal("executionAvailable" in status.engagements[0], false);
  assert.equal(status.engagements[0].attestation.operatorProvenance, "local-unverified");
  assert.equal(status.execution.configured, true);
  assert.equal(status.execution.laneAvailable, true);
  assert.equal(status.execution.mode, "supervised-generic");
  assert.equal(status.execution.runningCount, 1);
  assert.equal(status.execution.counts.succeeded, 2);
  assert.equal(status.execution.bestEffort.length, 3);
  assert.equal(status.execution.unavailable.length, 13);
  assert.match(status.execution.recent[0].runId, /^run_[a-f0-9]{16}$/);
  assert.match(status.execution.recent[0].manifestId, /^manifest_[a-f0-9]{16}$/);
  assert.match(status.execution.recent[0].engagementId, /^engagement_[a-f0-9]{16}$/);
  assert.equal(status.execution.recent[0].status, "running");
  assert.notEqual(
    status.execution.recent[0].runId,
    `run_${crypto.createHash("sha256").update(`xrun_${"1".repeat(32)}`).digest("hex").slice(0, 16)}`
  );
  assert.equal(status.offlineAnalysis.configured, true);
  assert.equal(status.offlineAnalysis.laneAvailable, true);
  assert.equal(status.offlineAnalysis.mode, "bubblewrap-offline");
  assert.equal(status.offlineAnalysis.reason, null);
  assert.equal(status.offlineAnalysis.runningCount, 1);
  assert.equal(status.offlineAnalysis.counts.succeeded, 2);
  assert.equal(status.offlineAnalysis.retention.retainedBytes, 512);
  assert.equal(status.offlineAnalysis.retention.quotaArtifacts, 64);
  assert.equal(status.offlineAnalysis.retention.pendingManifests, 1);
  assert.equal(status.offlineAnalysis.retention.availableArtifacts, 63);
  assert.equal(status.offlineAnalysis.retention.expiredManifests, 0);
  assert.equal(status.offlineAnalysis.retention.overQuota, false);
  assert.equal(status.offlineAnalysis.retention.retentionLockState, "absent");
  assert.equal(status.offlineAnalysis.retention.snapshotState, "consistent");
  assert.equal(status.offlineAnalysis.retention.mutationBlocked, false);
  assert.equal(status.offlineAnalysis.retention.pendingTransactions, 0);
  assert.equal(status.offlineAnalysis.retention.blockedManifests, 0);
  assert.equal(status.offlineAnalysis.enforced.length, 13);
  assert.equal(status.offlineAnalysis.unavailable.length, 5);
  assert.match(status.offlineAnalysis.recent[0].runId, /^run_[a-f0-9]{16}$/);
  assert.equal(status.offlineAnalysis.recent[0].status, "running");
  assert.equal(status.offlineAnalysis.recent[0].isolationVerified, null);
  assert.deepEqual(Object.keys(status.offlineAnalysis.recent[0]).sort(), ["isolationVerified", "runId", "status"]);
  assert.notEqual(
    status.offlineAnalysis.recent[0].runId,
    `run_${crypto.createHash("sha256").update(`arun_${"3".repeat(32)}`).digest("hex").slice(0, 16)}`
  );
  assert.equal(status.toolRuntimes.ok, true);
  assert.equal(status.toolRuntimes.verificationMode, "current-bytes-and-install-smoke-evidence");
  assert.equal(status.toolRuntimes.platform, "linux-x64");
  assert.equal(status.toolRuntimes.catalog, 2);
  assert.equal(status.toolRuntimes.executable, 1);
  assert.deepEqual(status.toolRuntimes.unresolvedConstraints, [{ reason: "managed-runtime-absent", count: 1 }]);
  assert.deepEqual(status.toolRuntimes.tools[0], {
    id: "nuclei",
    name: "Nuclei",
    state: "verified-install-evidence",
    locked: true,
    installed: true,
    verified: true,
    executable: true,
    reasons: []
  });
  assert.match(status.projects[0].id, /^project_[a-f0-9]{16}$/);
  assert.equal(status.projects[0].status, "ready");
  assert.equal(status.projects[0].provider, "github");
  assert.equal(status.projects[0].environment, "host");
  assert.equal(status.projects[0].deliveryMode, "no-mistakes");
  assert.equal(status.projects[0].activeTestingConfigured, true);
  assert.equal(status.projects[0].deploymentConfigured, false);
  assert.equal(status.projects[0].executionLaneAvailable, true);
  assert.equal(status.projects[0].executionEligibility, "not-evaluated");
  assert.equal("activeTestingEnabled" in status.projects[0], false);

  assert.equal(events.apiVersion, "gate.observer/v1");
  assert.deepEqual(events.events[0].effect, { class: "network-probe" });
  assert.equal(events.events[0].action.category, "tool");
  assert.equal(events.events[0].runId, status.agents[0].runId);
  assert.equal(events.events[0].taskId, status.agents[0].taskId);
  assert.equal(events.events[0].agent, status.agents[0].agent);
  assert.equal(events.events[0].component, "gate-observer");
  assert.equal(learnings.apiVersion, "gate.observer/v1");
  assert.equal(learnings.learnings[1].cause, "Private learning recorded.");
  assert.equal(learnings.learnings[1].change, "Details withheld from observer.");

  const serialized = JSON.stringify({ status, events, learnings });
  for (const canary of [
    "PROMPT_CANARY",
    "PRIVATE_PROMPT_CANARY",
    "PRIVATE_CHANGE_CANARY",
    "run_CLIENT_CONTEXT_CANARY",
    "task_CLIENT_CONTEXT_CANARY",
    "CLIENT_MEMBER_CANARY",
    "target.invalid",
    "/secret/path",
    "topsecret",
    "JWT_SUFFIX_CANARY",
    "raw-output-canary",
    "COMPONENT_PATH_CANARY",
    "AGENT_PATH_CANARY",
    "learning-evidence-canary",
    "private-canary.json",
    "CUSTOMER_CANARY",
    "CUSTOMER_PROJECT_CANARY",
    "CLIENT_EXECUTION_PROFILE_CANARY",
    "CLIENT_SECURITY_PROFILE_CANARY",
    "CLIENT_OWNER_CANARY",
    "CLIENT_REPOSITORY_CANARY",
    "CLIENT_DISPLAY_NAME_CANARY",
    "REPOSITORY_CANARY",
    "GATE_HOME_CANARY",
    "PRIVATE_CAPABILITY_CANARY",
    "PRIVATE_OFFLINE_REASON_CANARY",
    "PRIVATE_OFFLINE_CAPABILITY_CANARY",
    "OFFLINE_ARTIFACT_PATH_CANARY",
    "OFFLINE_ARTIFACT_HASH_CANARY",
    "OFFLINE_EVIDENCE_CANARY",
    "OFFLINE_RETENTION_CANARY",
    "TOOL_RUNTIME_PATH_CANARY",
    "TOOL_RUNTIME_HASH_CANARY",
    "TOOL_RUNTIME_URL_CANARY",
    "private-project-canary",
    `arun_${"3".repeat(32)}`,
    `amf_${"4".repeat(32)}`,
    "TARGET_ARGUMENT_CANARY",
    "ARGV_CANARY",
    "EXECUTABLE_PATH_CANARY",
    "STDOUT_CANARY",
    "EVIDENCE_CONTENT_CANARY",
    "customer-canary",
    `xrun_${"1".repeat(32)}`,
    `xmf_${"2".repeat(32)}`
  ]) {
    assert.equal(serialized.includes(canary), false, `observer leaked ${canary}`);
  }

  for (const response of [statusResponse, eventsResponse, learningsResponse]) {
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(response.headers.get("access-control-allow-origin"), null);
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  }
});

test("tool runtime observer summary allowlists metadata and withholds raw verification errors", () => {
  const summary = summarizeToolRuntimes({
    ok: false,
    verificationMode: "receipt-only",
    platform: "darwin-arm64",
    catalog: 2,
    locked: 2,
    installed: 1,
    verified: 0,
    executable: 0,
    unresolved: 2,
    unresolvedConstraints: [
      { reason: "managed-runtime-absent", count: 1 },
      { reason: "failed at /private/AGGREGATE_PATH_CANARY https://target.invalid", count: 1 }
    ],
    tools: [
      {
        id: "searchsploit",
        name: "SearchSploit / ExploitDB",
        state: "invalid",
        locked: true,
        installed: true,
        verified: false,
        executable: false,
        reasons: ["receipt at /private/TOOL_PATH_CANARY contains TOOL_SECRET_CANARY"],
        executablePath: "/private/EXECUTABLE_CANARY",
        artifactSha256: "ARTIFACT_HASH_CANARY",
        source: { url: "https://target.invalid/SOURCE_URL_CANARY" }
      },
      {
        id: "bad/id",
        name: "/private/NAME_CANARY",
        state: "verified",
        locked: true,
        installed: true,
        verified: true,
        executable: true,
        reasons: []
      }
    ],
    error: "LOCK_ERROR_CANARY /private/lock"
  });

  assert.deepEqual(summary, {
    ok: false,
    verificationMode: "receipt-only",
    platform: "darwin-arm64",
    catalog: 2,
    locked: 2,
    installed: 1,
    verified: 0,
    executable: 0,
    unresolved: 2,
    unresolvedConstraints: [
      { reason: "managed-runtime-absent", count: 1 },
      { reason: "runtime-integrity-invalid", count: 1 }
    ],
    tools: [{
      id: "searchsploit",
      name: "SearchSploit / ExploitDB",
      state: "invalid",
      locked: true,
      installed: true,
      verified: false,
      executable: false,
      reasons: ["runtime-integrity-invalid"]
    }]
  });
  const serialized = JSON.stringify(summary);
  for (const canary of [
    "AGGREGATE_PATH_CANARY", "target.invalid", "TOOL_PATH_CANARY", "TOOL_SECRET_CANARY",
    "EXECUTABLE_CANARY", "ARTIFACT_HASH_CANARY", "SOURCE_URL_CANARY", "NAME_CANARY", "LOCK_ERROR_CANARY"
  ]) assert.equal(serialized.includes(canary), false, `observer leaked ${canary}`);
});

test("missing token telemetry remains unavailable instead of becoming zero", () => {
  const projected = projectSnapshot(statusFixture({
    events: [],
    learnings: [],
    tokens: {
      availability: "unavailable",
      source: "codex-session-jsonl",
      totals: {
        inputTokens: 0,
        cachedInputTokens: 0,
        outputTokens: 0,
        reasoningTokens: 0,
        totalTokens: 0
      },
      records: []
    }
  }), paths);

  assert.equal(projected.status.usage.availability, "unavailable");
  for (const key of ["inputTokens", "cachedInputTokens", "outputTokens", "reasoningTokens", "totalTokens"]) {
    assert.equal(projected.status.usage[key], null);
  }
  assert.equal(projected.status.usage.context.usedTokens, null);
  assert.equal(projected.status.usage.budget.usedTokens, null);
});

test("execution metadata keeps opaque joins while excluding command and evidence data", () => {
  const rawRunId = `xrun_${"a".repeat(32)}`;
  const rawManifestId = `xmf_${"b".repeat(32)}`;
  const rawEngagementId = "safe-test-engagement";
  const projected = projectSnapshot(statusFixture({
    events: [canonicalEvent({ runId: rawRunId })],
    engagements: [{
      metadata: { id: rawEngagementId, status: "active" },
      review: {
        noMistakes: { status: "passed" },
        operatorReceipt: { status: "approved" }
      }
    }],
    execution: executionFixture({
      recent: [{
        runId: rawRunId,
        manifestId: rawManifestId,
        engagementId: rawEngagementId,
        status: "cancelled",
        createdAt: at,
        startedAt: at,
        finishedAt: at,
        terminationReason: "process-group-remained",
        exitCode: null,
        signal: null,
        argv: ["JOIN_ARGV_CANARY"],
        target: "JOIN_TARGET_CANARY",
        evidence: "JOIN_EVIDENCE_CANARY"
      }]
    })
  }), paths);

  const run = projected.status.execution.recent[0];
  assert.equal(run.runId, projected.events.events[0].runId);
  assert.equal(run.engagementId, projected.status.engagements[0].id);
  assert.equal(run.status, "cancelled");
  assert.equal(run.terminationReason, "process-group-remained");
  assert.notEqual(run.runId, `run_${crypto.createHash("sha256").update(rawRunId).digest("hex").slice(0, 16)}`);
  const serialized = JSON.stringify(projected);
  for (const forbidden of [rawRunId, rawManifestId, rawEngagementId, "JOIN_ARGV_CANARY", "JOIN_TARGET_CANARY", "JOIN_EVIDENCE_CANARY"]) {
    assert.equal(serialized.includes(forbidden), false, `observer leaked ${forbidden}`);
  }
});

test("execution availability fails closed on incomplete capabilities and malformed recent records", () => {
  const execution = executionFixture();
  execution.capability.enforced = execution.capability.enforced.filter((value) => value !== "shell-disabled");
  execution.recent = [
    {
      runId: "/private/run-canary",
      manifestId: `xmf_${"2".repeat(32)}`,
      engagementId: "safe-test-engagement",
      status: "running",
      createdAt: at,
      startedAt: at,
      finishedAt: null,
      terminationReason: null,
      exitCode: 2 ** 40,
      signal: "SIG_PRIVATE_CANARY"
    }
  ];
  const projected = projectSnapshot(statusFixture({ execution }), paths);

  assert.equal(projected.status.execution.configured, true);
  assert.equal(projected.status.execution.laneAvailable, false);
  assert.equal(projected.status.execution.recent.length, 0);
  const serialized = JSON.stringify(projected.status.execution);
  assert.equal(serialized.includes("/private/run-canary"), false);
  assert.equal(serialized.includes("SIG_PRIVATE_CANARY"), false);

  const unavailable = projectSnapshot(statusFixture({ execution: undefined }), paths);
  assert.equal(unavailable.status.execution.configured, null);
  assert.equal(unavailable.status.execution.laneAvailable, false);
  assert.equal(unavailable.status.execution.runningCount, null);
});

test("offline analysis projection fails closed and withholds artifact and evidence details", () => {
  const analysis = offlineAnalysisFixture();
  analysis.capability.enforced = analysis.capability.enforced.filter((value) => value !== "shell-disabled");
  analysis.capability.reason = "/private/OFFLINE_FAILURE_DETAIL_CANARY";
  analysis.recent = [{
    runId: "/private/OFFLINE_RUN_CANARY",
    manifestId: `amf_${"4".repeat(32)}`,
    projectId: "private-project-canary",
    status: "running",
    createdAt: at,
    artifactPath: "/private/OFFLINE_PATH_CANARY",
    artifactSha256: "OFFLINE_HASH_CANARY",
    evidence: "OFFLINE_OUTPUT_CANARY"
  }];
  const projected = projectSnapshot(statusFixture({ offlineAnalysis: analysis }), paths);

  assert.equal(projected.status.offlineAnalysis.configured, true);
  assert.equal(projected.status.offlineAnalysis.laneAvailable, false);
  assert.equal(projected.status.offlineAnalysis.reason, "unavailable");
  assert.equal(projected.status.offlineAnalysis.recent.length, 0);
  const serialized = JSON.stringify(projected.status.offlineAnalysis);
  for (const forbidden of [
    "OFFLINE_FAILURE_DETAIL_CANARY",
    "OFFLINE_RUN_CANARY",
    "private-project-canary",
    "OFFLINE_PATH_CANARY",
    "OFFLINE_HASH_CANARY",
    "OFFLINE_OUTPUT_CANARY"
  ]) assert.equal(serialized.includes(forbidden), false, `observer leaked ${forbidden}`);

  const absent = projectSnapshot(statusFixture({ offlineAnalysis: undefined }), paths);
  assert.equal(absent.status.offlineAnalysis.configured, null);
  assert.equal(absent.status.offlineAnalysis.laneAvailable, false);
  assert.equal(absent.status.offlineAnalysis.reason, "unavailable");
  assert.equal(absent.status.offlineAnalysis.runningCount, null);
});

test("observer exposes only aggregate offline retention fault signals", () => {
  const analysis = offlineAnalysisFixture();
  Object.assign(analysis.retention, {
    overQuota: true,
    missingArtifacts: 2,
    invalidEntries: 3,
    orphanedArtifacts: 4,
    orphanedBytes: 1536,
    purgePendingManifests: 1,
    unknownManifests: 5,
    retentionLockState: "invalid",
    snapshotState: "indeterminate",
    pendingTransactions: 6,
    invalidTransactionRecords: 7,
    creatingManifests: 8,
    invalidCreationIntents: 9,
    invalidClaimRecords: 10,
    invalidPurgeRecords: 11,
    invalidRunRecords: 13,
    blockedManifests: 12,
    mutationBlocked: true,
    privatePath: "/private/RETENTION_PATH_CANARY",
    manifestDigest: "RETENTION_DIGEST_CANARY"
  });
  const projected = projectSnapshot(statusFixture({ offlineAnalysis: analysis }), paths);
  const retention = projected.status.offlineAnalysis.retention;

  assert.deepEqual({
    overQuota: retention.overQuota,
    missingArtifacts: retention.missingArtifacts,
    invalidEntries: retention.invalidEntries,
    orphanedArtifacts: retention.orphanedArtifacts,
    orphanedBytes: retention.orphanedBytes,
    purgePendingManifests: retention.purgePendingManifests,
    unknownManifests: retention.unknownManifests,
    retentionLockState: retention.retentionLockState,
    snapshotState: retention.snapshotState,
    pendingTransactions: retention.pendingTransactions,
    invalidTransactionRecords: retention.invalidTransactionRecords,
    creatingManifests: retention.creatingManifests,
    invalidCreationIntents: retention.invalidCreationIntents,
    invalidClaimRecords: retention.invalidClaimRecords,
    invalidPurgeRecords: retention.invalidPurgeRecords,
    invalidRunRecords: retention.invalidRunRecords,
    blockedManifests: retention.blockedManifests,
    mutationBlocked: retention.mutationBlocked
  }, {
    overQuota: true,
    missingArtifacts: 2,
    invalidEntries: 3,
    orphanedArtifacts: 4,
    orphanedBytes: 1536,
    purgePendingManifests: 1,
    unknownManifests: 5,
    retentionLockState: "invalid",
    snapshotState: "indeterminate",
    pendingTransactions: 6,
    invalidTransactionRecords: 7,
    creatingManifests: 8,
    invalidCreationIntents: 9,
    invalidClaimRecords: 10,
    invalidPurgeRecords: 11,
    invalidRunRecords: 13,
    blockedManifests: 12,
    mutationBlocked: true
  });
  const serialized = JSON.stringify(retention);
  assert.equal(serialized.includes("RETENTION_PATH_CANARY"), false);
  assert.equal(serialized.includes("RETENTION_DIGEST_CANARY"), false);

  analysis.retention.retentionLockState = "/private/LOCK_OWNER_CANARY";
  analysis.retention.snapshotState = "/private/SNAPSHOT_CANARY";
  const invalidLockText = projectSnapshot(statusFixture({ offlineAnalysis: analysis }), paths);
  assert.equal(invalidLockText.status.offlineAnalysis.retention.retentionLockState, null);
  assert.equal(invalidLockText.status.offlineAnalysis.retention.snapshotState, null);
  assert.equal(JSON.stringify(invalidLockText).includes("LOCK_OWNER_CANARY"), false);
  assert.equal(JSON.stringify(invalidLockText).includes("SNAPSHOT_CANARY"), false);
});

test("observer retains an opaque invalid project for filesystem-valid corrupt names", () => {
  const corruptName = `${"x".repeat(180)}\rprivate`;
  const projected = projectSnapshot(statusFixture({
    projects: [{ id: null, registryEntry: corruptName, status: "invalid" }]
  }), paths);

  assert.equal(projected.status.projects.length, 1);
  assert.match(projected.status.projects[0].id, /^project_[a-f0-9]{16}$/);
  assert.equal(projected.status.projects[0].status, "invalid");
  assert.equal(JSON.stringify(projected).includes(corruptName), false);
});

test("observer preserves canonical forge and publication effects", () => {
  const neutralEffect = (effectClass) => ({
    class: effectClass,
    targetRef: null,
    engagementId: null,
    planDigest: null
  });
  const projected = projectSnapshot(statusFixture({
    events: [
      canonicalEvent({ id: "evt_publish001", effect: neutralEffect("external-publish") }),
      canonicalEvent({
        id: "evt_forgewrite01",
        at: "2026-10-13T11:59:59.000Z",
        effect: neutralEffect("forge-write")
      })
    ]
  }), paths);

  assert.deepEqual(projected.events.events.map((event) => event.effect.class), ["external-publish", "forge-write"]);
});

test("observer never presents receipt-only or unknown upstream state as verified readiness", () => {
  const projected = projectSnapshot(statusFixture({
    upstreams: [
      { id: "receipt-tool", version: "1.0.0", installed: true, integrityState: "receipt-only", ready: true },
      { id: "commit-tool", version: null, installed: true, integrityState: "commit-only", ready: true },
      { id: "legacy-tool", version: "2.0.0", installed: true, ready: true },
      { id: "verified-tool", version: "3.0.0", installed: true, integrityState: "verified", ready: true }
    ]
  }), paths);

  const [receipt, commit, legacy, verified] = projected.status.upstreams;
  assert.deepEqual(
    [receipt.integrityState, receipt.installed, receipt.ready],
    ["receipt-only", true, false]
  );
  assert.deepEqual([commit.integrityState, commit.ready], ["commit-only", false]);
  assert.deepEqual([legacy.integrityState, legacy.ready], ["unknown", false]);
  assert.deepEqual([verified.integrityState, verified.ready], ["verified", true]);
});

test("observer redacts complete authorization and cookie header values", () => {
  const headers = [
    "Authorization: Digest username=\"SERVER_DIGEST_CANARY\", realm=\"synthetic\", response=\"synthetic\"",
    "Authorization: AWS4-HMAC-SHA256 Credential=SERVER_AWS4_CANARY/20261013/test/aws4_request, SignedHeaders=host;x-date, Signature=synthetic",
    "Cookie: session=SERVER_COOKIE_CANARY; preference=dark",
    "Set-Cookie: session=SERVER_SET_COOKIE_CANARY; Path=/; HttpOnly"
  ];
  const projected = projectSnapshot(statusFixture({
    events: [],
    learnings: headers.map((header, index) => canonicalLearning({
      id: `lrn_header00${index}`,
      cause: `Observed ${header}`
    }))
  }), paths);

  assert.deepEqual(
    projected.learnings.learnings.map((learning) => learning.cause),
    headers.map(() => "Observed [secret withheld]")
  );
  assert.doesNotMatch(JSON.stringify(projected.learnings), /SERVER_(?:DIGEST|AWS4|COOKIE|SET_COOKIE)_CANARY/);
});

test("dashboard routes use an exact allowlist and strict browser headers", async (t) => {
  const { origin } = await listen(t, async () => statusFixture());

  for (const [pathname, type] of [
    ["/", "text/html"],
    ["/dashboard/", "text/html"],
    ["/dashboard/styles.css", "text/css"],
    ["/dashboard/app.js", "text/javascript"],
    ["/dashboard/favicon.svg", "image/svg\\+xml"],
    ["/dashboard/model.js", "text/javascript"]
  ]) {
    const response = await fetch(`${origin}${pathname}`);
    assert.equal(response.status, 200, pathname);
    assert.match(response.headers.get("content-type"), new RegExp(`^${type}`));
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.match(response.headers.get("content-security-policy"), /default-src 'self'/);
    assert.equal(response.headers.get("cross-origin-resource-policy"), "same-origin");
  }

  for (const pathname of ["/dashboard/README.md", "/dashboard/model.test.js", "/package.json", "/dashboard/%2e%2e/package.json"]) {
    const response = await fetch(`${origin}${pathname}`);
    assert.equal(response.status, 404, pathname);
  }
});

test("dashboard assets remain the preloaded snapshot after path substitution", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-observer-static-"));
  const dashboardRoot = path.join(root, "dashboard");
  const asset = path.join(dashboardRoot, "app.js");
  const original = path.join(dashboardRoot, "original.js");
  const privateFile = path.join(root, "outside-dashboard.txt");
  fs.mkdirSync(dashboardRoot);
  fs.writeFileSync(asset, "SAFE_PRELOADED_ASSET", "utf8");
  fs.writeFileSync(privateFile, "STATIC_SUBSTITUTION_CANARY", "utf8");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const { origin } = await listen(t, async () => statusFixture(), { dashboardRoot });
  assert.equal(await (await fetch(`${origin}/dashboard/app.js`)).text(), "SAFE_PRELOADED_ASSET");

  fs.renameSync(asset, original);
  fs.symlinkSync(privateFile, asset);
  const response = await fetch(`${origin}/dashboard/app.js`);
  const body = await response.text();

  assert.equal(response.status, 200);
  assert.equal(body, "SAFE_PRELOADED_ASSET");
  assert.doesNotMatch(body, /STATIC_SUBSTITUTION_CANARY/);
});

test("observer accepts read-only local requests and rejects foreign authorities and origins", async (t) => {
  const { server, origin } = await listen(t, async () => statusFixture());
  const port = server.address().port;

  const head = await fetch(`${origin}/api/status`, { method: "HEAD" });
  assert.equal(head.status, 200);
  assert.equal(await head.text(), "");

  const write = await request({ port, method: "POST", pathname: "/api/status" });
  assert.equal(write.status, 405);
  assert.equal(write.headers.allow, "GET, HEAD");

  const foreignHost = await request({ port, pathname: "/api/status", headers: { Host: "evil.example" } });
  assert.equal(foreignHost.status, 403);
  const foreignOrigin = await request({
    port,
    pathname: "/api/status",
    headers: { Host: `127.0.0.1:${port}`, Origin: "https://evil.example" }
  });
  assert.equal(foreignOrigin.status, 403);
  const crossSiteFetch = await request({
    port,
    pathname: "/api/status",
    headers: { Host: `127.0.0.1:${port}`, "Sec-Fetch-Site": "cross-site" }
  });
  assert.equal(crossSiteFetch.status, 403);

  assert.equal(isLoopbackHost("127.0.0.42"), true);
  assert.equal(isLoopbackHost("::1"), true);
  assert.equal(isLoopbackHost("localhost"), true);
  assert.equal(isLoopbackHost("0.0.0.0"), false);
  assert.equal(isLoopbackHost("127.example"), false);
  assert.throws(() => createObserver({ paths, host: "0.0.0.0" }), /loopback/);
});

test("status failures return a generic service error without exception details", async (t) => {
  const { origin } = await listen(t, () => {
    throw new Error("SENSITIVE_BUILDER_FAILURE");
  });
  const response = await fetch(`${origin}/api/status`);
  assert.equal(response.status, 503);
  const body = await response.text();
  assert.match(body, /observer status unavailable/);
  assert.doesNotMatch(body, /SENSITIVE_BUILDER_FAILURE/);
});
