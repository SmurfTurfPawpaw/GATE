import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  campaignInternals,
  campaignStatus,
  createCampaign,
  enqueueLabCampaignJob,
  recoverCampaign,
  resumeCampaign,
  runNextCampaignJob,
  startNextManagedCampaignJob,
  stopCampaign
} from "../src/lib/campaigns.mjs";
import {
  campaignWorkerInternals,
  campaignWorkerProjection,
  runCampaignWorker,
  runNextCampaignWorkerJob
} from "../src/lib/campaign-worker.mjs";
import {
  nextCtfPilotTimestamp,
  readCtfPilotStatus,
  updateCtfPilotState
} from "../src/lib/ctf-pilot.mjs";
import { buildStatus } from "../src/lib/status.mjs";
import { projectSnapshot } from "../src/observer/server.mjs";
import { cliInternals } from "../src/cli.mjs";
import {
  CASE_SCOPE_API_VERSION,
  CASE_SCOPE_ISOLATION,
  CASE_SCOPE_KIND,
  CASE_SCOPE_SCHEMA,
  canonicalCaseScopeText,
  caseScopeDigest
} from "../src/lib/case-scope.mjs";
import { ensureRuntime, runtimePaths } from "../src/lib/paths.mjs";
import { validateDocument } from "../src/lib/schema.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const gate = path.join(repo, "bin", "gate.mjs");
const fixedAt = "2026-10-19T12:00:00.000Z";
const expiresAt = "2026-10-20T12:00:00.000Z";
const programId = "campaign-program";
const profileSha256 = "a".repeat(64);
const sourceId = "program-rules";

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-campaign-"));
  const home = path.join(root, "home");
  const base = runtimePaths({ home, repo });
  const caseId = "campaign-case";
  const caseRoot = path.join(home, "cases", caseId);
  const state = path.join(caseRoot, "state");
  fs.mkdirSync(state, { recursive: true, mode: 0o700 });
  const scope = {
    $schema: CASE_SCOPE_SCHEMA,
    apiVersion: CASE_SCOPE_API_VERSION,
    kind: CASE_SCOPE_KIND,
    metadata: { id: caseId, displayName: "Campaign case", createdAt: fixedAt },
    program: { id: programId, profileSha256 },
    project: null,
    isolation: { ...CASE_SCOPE_ISOLATION },
    scopeSha256: "0".repeat(64)
  };
  scope.scopeSha256 = caseScopeDigest(scope);
  fs.writeFileSync(path.join(caseRoot, "scope.json"), canonicalCaseScopeText(scope), { mode: 0o600 });
  fs.writeFileSync(
    path.join(state, ".case-binding.json"),
    `${JSON.stringify({ caseId, scopeSha256: scope.scopeSha256 }, null, 2)}\n`,
    { mode: 0o600 }
  );
  const paths = runtimePaths({ home, repo, caseId });
  ensureRuntime(paths);
  const source = sourceSnapshot();
  const options = {
    paths,
    now: fixedAt,
    readCurrentProgramProfileBinding: () => ({
      id: programId,
      profileSha256,
      sources: [{ id: sourceId, contentSha256: source.metadata.contentSha256 }]
    }),
    readCurrentProgramSource: () => structuredClone(source)
  };
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, base, paths, scope, source, options };
}

function sourceSnapshot(overrides = {}) {
  const contentSha256 = overrides.contentSha256 || "b".repeat(64);
  const projectionSha256 = overrides.projectionSha256 || "c".repeat(64);
  const snapshotSha256 = overrides.snapshotSha256 || "d".repeat(64);
  return {
    $schema: "https://gate.local/schemas/program-source-snapshot.schema.json",
    apiVersion: "gate.dev/program-source-snapshot/v1",
    kind: "ProgramSourceSnapshot",
    metadata: {
      programId,
      sourceId,
      revision: 1,
      capturedAt: fixedAt,
      contentSha256,
      projectionSha256,
      snapshotSha256,
      bodyBytes: 12
    },
    source: {
      id: sourceId,
      type: "program-rules",
      title: "Published program rules",
      reference: `private://program-sources/${programId}/${sourceId}/bodies/${contentSha256}.bin`,
      contentSha256,
      observedAt: fixedAt,
      claimState: "observed",
      notes: null
    },
    acquisition: {
      method: "local-file",
      requestedUrl: null,
      finalUrl: null,
      redirects: 0,
      httpStatus: null,
      mediaType: "text/plain",
      contentEncoding: null
    },
    projection: { scope: [], rules: [] },
    storage: {
      bodyRef: `private://program-sources/${programId}/${sourceId}/bodies/${contentSha256}.bin`
    },
    predecessor: null
  };
}

function ceilings(overrides = {}) {
  return {
    maxWallMinutes: 60,
    maxRequests: 100,
    maxRatePerSecond: 2,
    maxConcurrency: 1,
    maxInputTokens: 10_000,
    maxOutputTokens: 10_000,
    maxTotalTokens: 20_000,
    maxSpend: 10,
    maxEvidenceBytes: 16 * 1024 * 1024,
    ...overrides
  };
}

function dryCampaign(jobs = [{ id: "controller-check", type: "non-contact-dry-run", summary: "Verify durable scheduling without target contact." }]) {
  return {
    id: "first-campaign",
    expiresAt,
    source: {
      id: sourceId,
      contentSha256: "b".repeat(64),
      projectionSha256: "c".repeat(64),
      snapshotSha256: "d".repeat(64)
    },
    engagementId: null,
    operations: [],
    selectors: [],
    environment: "host",
    ceilings: ceilings(),
    jobs
  };
}

function httpJob(id, url) {
  return {
    id,
    type: "managed-adapter",
    engagementId: "ctf-engagement",
    workflow: { instanceId: "ctf-workflow", phaseAttemptId: `wpa_${"1".repeat(32)}` },
    adapter: { id: "httpx-url-fetch", action: "observe", toolId: "httpx" },
    selector: { type: "url", value: url },
    operation: {
      kind: "http-fetch",
      method: "GET",
      allowedIp: "127.0.0.1",
      timeoutSeconds: 5,
      maxResponseBytes: 4096
    },
    bounds: {
      maxMinutes: 1,
      estimatedRequests: 1,
      maxParallel: 1,
      maxRatePerSecond: 1,
      maxTokens: 1000,
      maxSpend: 0,
      maxEvidenceBytes: 2 * 1024 * 1024
    }
  };
}

function labCampaign() {
  return {
    ...dryCampaign(),
    engagementId: "ctf-engagement",
    operations: [{ adapterId: "httpx-url-fetch", action: "observe", toolId: "httpx" }],
    selectors: [{ type: "url", value: "http://127.0.0.1:8080/challenge/" }],
    jobs: [httpJob("initial-fetch", "http://127.0.0.1:8080/challenge/")]
  };
}

function authorizedLabStatus() {
  return {
    authorityId: "ctf-lab-authority",
    campaignId: "first-campaign",
    status: "authorized",
    confirmed: true
  };
}

function successfulLabDispatch(job, overrides = {}) {
  return {
    ok: true,
    status: "succeeded",
    authorityId: "ctf-lab-authority",
    capabilityId: `lcap_${"a".repeat(32)}`,
    campaignId: "first-campaign",
    jobId: job.metadata.id,
    manifestId: `xmf_${"b".repeat(32)}`,
    runId: `xrun_${"c".repeat(32)}`,
    metrics: {
      wallMilliseconds: 25,
      requests: 1,
      inputTokens: 0,
      outputTokens: 0,
      totalTokens: 0,
      spend: 0,
      evidenceBytes: 120
    },
    stopCondition: null,
    ...overrides
  };
}

function enqueuePermit(job, grant, overrides = {}) {
  const permit = {
    authorityId: "ctf-lab-authority",
    authoritySha256: "1".repeat(64),
    receiptSha256: "2".repeat(64),
    campaignId: grant.metadata.id,
    grantSha256: grant.grantSha256,
    origin: "http://127.0.0.1:8080",
    pathPrefix: "/challenge/",
    frozenIps: ["127.0.0.1"],
    adapter: {
      id: "httpx-url-fetch",
      action: "observe",
      toolId: "httpx",
      registrySha256: grant.allow.adapterRegistrySha256,
      entrySha256: "3".repeat(64),
      compilerSourceSha256: "4".repeat(64),
      runtimeSha256: "5".repeat(64)
    },
    workflow: {
      instanceId: "ctf-workflow",
      phaseId: "active-surface-validation",
      phaseAttemptId: `wpa_${"1".repeat(32)}`,
      admissionSha256: "6".repeat(64),
      authorityReceiptSha256: "7".repeat(64)
    },
    ceilings: structuredClone(grant.ceilings),
    dynamic: {
      maxJobs: 10,
      allowedMethods: ["GET", "HEAD"],
      maxResponseBytes: 8192,
      maxTimeoutSeconds: 10
    },
    jobId: job.metadata.id,
    jobSha256: job.jobSha256,
    ...overrides,
    permitSha256: "0".repeat(64)
  };
  const digestInput = structuredClone(permit);
  delete digestInput.permitSha256;
  permit.permitSha256 = campaignInternals.canonicalSha256(digestInput, "gate.lab-campaign-enqueue-permit.v1");
  return permit;
}

function readJournal(paths, campaign = "first-campaign") {
  const file = campaignInternals.campaignPaths(paths, campaign).journal;
  return fs.readFileSync(file, "utf8").trim().split(/\r?\n/u).map(JSON.parse);
}

function invoke(args, home) {
  return spawnSync(process.execPath, [gate, ...args], {
    cwd: repo,
    env: { ...process.env, GATE_HOME: home, GATE_CASE: "" },
    encoding: "utf8",
    timeout: 10_000
  });
}

test("campaign controller persists a digest-bound private grant and completes a foreground dry-run", (t) => {
  const { paths, options } = fixture(t);
  const created = createCampaign(dryCampaign(), options);
  assert.equal(created.created, true);
  assert.equal(created.state.status, "paused");
  assert.equal(created.state.queue.queued, 1);
  assert.equal(created.state.capability.managedAdapterDispatch, "confirmed-dedicated-lab-only");
  assert.equal(created.grant.binding.case.id, paths.caseId);
  assert.equal(created.grant.binding.program.profileSha256, profileSha256);
  assert.equal(created.grant.binding.source.contentSha256, "b".repeat(64));
  assert.equal(validateDocument(created.grant, "campaign-grant.schema.json", { paths }).ok, true);
  const invalidExact = structuredClone(created.state);
  invalidExact.kpis.jobsAttempted.value = null;
  assert.equal(validateDocument(invalidExact, "campaign-state.schema.json", { paths }).ok, false);
  const invalidUnavailable = structuredClone(created.state);
  invalidUnavailable.kpis.hypotheses.value = 5;
  assert.equal(validateDocument(invalidUnavailable, "campaign-state.schema.json", { paths }).ok, false);

  const location = campaignInternals.campaignPaths(paths, "first-campaign");
  assert.equal(fs.statSync(location.directory).mode & 0o777, 0o700);
  assert.equal(fs.statSync(location.grant).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.join(location.jobs, "controller-check.json")).mode & 0o777, 0o600);

  const resumed = resumeCampaign("first-campaign", options);
  assert.equal(resumed.state.status, "running");
  const transitions = [];
  const result = runNextCampaignJob("first-campaign", {
    ...options,
    onTransition(transition) {
      transitions.push({
        type: transition.type,
        status: transition.state.status,
        queue: transition.state.queue
      });
    }
  });
  assert.equal(result.ok, true);
  assert.equal(result.contactAttempted, false);
  assert.equal(result.result.type, "non-contact-dry-run");
  assert.equal(result.state.status, "completed");
  assert.equal(result.state.queue.completed, 1);
  assert.equal(result.state.kpis.jobsAttempted.value, 1);
  assert.equal(result.state.kpis.jobsCompleted.value, 1);
  assert.equal(result.state.kpis.hypotheses.availability, "unavailable");
  assert.equal(result.state.usage.observed.requests.value, 0);
  assert.equal(result.state.usage.observed.totalTokens.value, 0);
  assert.deepEqual(transitions, [
    {
      type: "job-started",
      status: "running",
      queue: { total: 1, queued: 0, running: 1, completed: 0, blocked: 0, failed: 0 }
    },
    {
      type: "job-completed",
      status: "running",
      queue: { total: 1, queued: 0, running: 0, completed: 1, blocked: 0, failed: 0 }
    },
    {
      type: "campaign-completed",
      status: "completed",
      queue: { total: 1, queued: 0, running: 0, completed: 1, blocked: 0, failed: 0 }
    }
  ]);

  const status = campaignStatus("first-campaign", options);
  assert.equal(status.bindingHealth.schedulingReady, true);
  assert.equal(status.bindingHealth.executionAuthorityReady, false);
  assert.deepEqual(status.projection, { available: true, current: true });
  assert.deepEqual(readJournal(paths).map((entry) => entry.type), [
    "campaign-created",
    "campaign-resumed",
    "job-started",
    "job-completed",
    "campaign-completed"
  ]);
});

test("run-next blocks before work when the current source snapshot no longer matches the grant", (t) => {
  const { options } = fixture(t);
  createCampaign(dryCampaign(), options);
  resumeCampaign("first-campaign", options);
  const changed = sourceSnapshot({ contentSha256: "e".repeat(64), snapshotSha256: "f".repeat(64) });
  const staleOptions = { ...options, readCurrentProgramSource: () => changed };
  const result = runNextCampaignJob("first-campaign", staleOptions);
  assert.equal(result.ok, false);
  assert.equal(result.contactAttempted, false);
  assert.equal(result.state.status, "blocked");
  assert.equal(result.state.queue.queued, 1);
  assert.equal(result.state.stop.condition, "source-binding-change");
  assert.equal(campaignStatus("first-campaign", staleOptions).bindingHealth.sourceCurrent, false);
});

test("campaign creation rejects an intake source revision that changed before commit", (t) => {
  const { options } = fixture(t);
  const changed = sourceSnapshot({
    contentSha256: "e".repeat(64),
    projectionSha256: "f".repeat(64),
    snapshotSha256: "9".repeat(64)
  });
  assert.throws(
    () => createCampaign(dryCampaign(), { ...options, readCurrentProgramSource: () => changed }),
    /does not match the exact expected source binding/u
  );
});

test("campaign creation rechecks source bindings immediately before atomic publication", (t) => {
  const { paths, options } = fixture(t);
  const changed = sourceSnapshot({ contentSha256: "e".repeat(64), snapshotSha256: "f".repeat(64) });
  let reads = 0;
  assert.throws(
    () => createCampaign(dryCampaign(), {
      ...options,
      readCurrentProgramSource: () => structuredClone(reads++ === 0 ? sourceSnapshot() : changed)
    }),
    /source-binding-changed/u
  );
  assert.equal(fs.existsSync(campaignInternals.campaignPaths(paths, "first-campaign").directory), false);
});

test("campaign creation accepts only a content-bound source cited by the reviewed profile", (t) => {
  const { options } = fixture(t);
  const uncited = {
    ...options,
    readCurrentProgramProfileBinding: () => ({ id: programId, profileSha256, sources: [] })
  };
  assert.throws(
    () => createCampaign(dryCampaign(), uncited),
    /not the exact content-bound source in the reviewed program profile ledger/u
  );
  const missingExpected = dryCampaign();
  delete missingExpected.source.snapshotSha256;
  assert.throws(
    () => createCampaign(missingExpected, options),
    /expected source binding fields changed/u
  );
});

test("managed adapter envelopes cannot become commands and remain visibly blocked without target contact", (t) => {
  const { options } = fixture(t);
  const input = {
    id: "first-campaign",
    expiresAt,
    source: {
      id: sourceId,
      contentSha256: "b".repeat(64),
      projectionSha256: "c".repeat(64),
      snapshotSha256: "d".repeat(64)
    },
    engagementId: "ctf-engagement",
    operations: [{ adapterId: "dnsx-domain-observe", action: "observe", toolId: "dnsx" }],
    selectors: [{ type: "domain", value: "challenge.example.test" }],
    environment: "host",
    ceilings: ceilings(),
    jobs: [{
      id: "exact-domain-check",
      type: "managed-adapter",
      engagementId: "ctf-engagement",
      workflow: { instanceId: "ctf-workflow", phaseAttemptId: `wpa_${"1".repeat(32)}` },
      adapter: { id: "dnsx-domain-observe", action: "observe", toolId: "dnsx" },
      selector: { type: "domain", value: "challenge.example.test" },
      operation: { kind: "dns-query", recordType: "A", resolver: "1.1.1.1:53", timeoutSeconds: 5 },
      bounds: {
        maxMinutes: 1,
        estimatedRequests: 1,
        maxParallel: 1,
        maxRatePerSecond: 1,
        maxTokens: 1000,
        maxSpend: 0,
        maxEvidenceBytes: 2 * 1024 * 1024
      }
    }]
  };
  const created = createCampaign(input, options);
  assert.equal(created.state.usage.reserved.wallMinutes, 1);
  assert.equal(created.state.usage.reserved.requests, 1);
  assert.equal(created.state.usage.reserved.totalTokens, 1000);
  assert.equal(created.state.usage.reserved.evidenceBytes, 2 * 1024 * 1024);
  resumeCampaign("first-campaign", options);
  const result = runNextCampaignJob("first-campaign", options);
  assert.equal(result.ok, false);
  assert.equal(result.contactAttempted, false);
  assert.equal(result.state.status, "blocked");
  assert.equal(result.state.queue.blocked, 1);
  assert.match(result.reason, /confirmed dedicated-lab authority/u);

  const commandJob = structuredClone(input);
  commandJob.id = "second-campaign";
  commandJob.jobs[0].operation.command = "echo never";
  assert.throws(() => createCampaign(commandJob, options), /command, argv, shell, script, or executable surface/u);
});

test("campaign worker integration durably dispatches and finalizes one confirmed lab job", async (t) => {
  const { paths, options } = fixture(t);
  createCampaign(labCampaign(), options);
  resumeCampaign("first-campaign", options);
  const transitions = [];
  let dispatches = 0;
  const result = await runNextCampaignWorkerJob("first-campaign", {
    ...options,
    labAuthorityId: "ctf-lab-authority",
    labCampaignAuthorityStatus: () => authorizedLabStatus(),
    dispatchAuthorizedLabCampaignJob: async (authorityId, job) => {
      dispatches += 1;
      assert.equal(authorityId, "ctf-lab-authority");
      assert.equal(job.metadata.id, "initial-fetch");
      const running = campaignStatus("first-campaign", options).state;
      assert.equal(running.jobs[0].status, "running");
      assert.equal(readJournal(paths).at(-1).payload.authorityId, "ctf-lab-authority");
      return successfulLabDispatch(job);
    },
    onTransition(transition) {
      transitions.push({ type: transition.type, status: transition.state.status });
    }
  });
  assert.equal(dispatches, 1);
  assert.equal(result.ok, true);
  assert.equal(result.contactAttempted, true);
  assert.equal(result.state.status, "completed");
  assert.equal(result.state.queue.completed, 1);
  assert.equal(result.state.usage.observed.requests.value, 1);
  assert.equal(result.state.usage.observed.evidenceBytes.value, 120);
  assert.deepEqual(transitions, [
    { type: "job-started", status: "running" },
    { type: "job-completed", status: "running" },
    { type: "campaign-completed", status: "completed" }
  ]);
  assert.deepEqual(readJournal(paths).slice(-3).map((entry) => entry.type), [
    "job-started",
    "job-completed",
    "campaign-completed"
  ]);
});

test("campaign worker integration defers without confirmed authority and fails closed on dispatch error", async (t) => {
  const deferredFixture = fixture(t);
  createCampaign(labCampaign(), deferredFixture.options);
  resumeCampaign("first-campaign", deferredFixture.options);
  let deferredDispatches = 0;
  const deferred = await runNextCampaignWorkerJob("first-campaign", {
    ...deferredFixture.options,
    labAuthorityId: "ctf-lab-authority",
    labCampaignAuthorityStatus: () => ({ ...authorizedLabStatus(), status: "proposed", confirmed: false }),
    dispatchAuthorizedLabCampaignJob: async () => { deferredDispatches += 1; }
  });
  assert.equal(deferred.deferred, true);
  assert.equal(deferred.contactAttempted, false);
  assert.equal(deferredDispatches, 0);
  assert.equal(campaignStatus("first-campaign", deferredFixture.options).state.queue.queued, 1);
  assert.deepEqual(readJournal(deferredFixture.paths).map((entry) => entry.type), [
    "campaign-created",
    "campaign-resumed"
  ]);

  const failedFixture = fixture(t);
  createCampaign(labCampaign(), failedFixture.options);
  resumeCampaign("first-campaign", failedFixture.options);
  let failedDispatches = 0;
  const failed = await runNextCampaignWorkerJob("first-campaign", {
    ...failedFixture.options,
    labAuthorityId: "ctf-lab-authority",
    labCampaignAuthorityStatus: () => authorizedLabStatus(),
    dispatchAuthorizedLabCampaignJob: async () => {
      failedDispatches += 1;
      throw new Error("broker terminal result unavailable");
    }
  });
  assert.equal(failedDispatches, 1);
  assert.equal(failed.ok, false);
  assert.equal(failed.contactAttempted, null);
  assert.equal(failed.contactStatus, "indeterminate");
  assert.equal(failed.state.status, "blocked");
  assert.equal(failed.state.queue.blocked, 1);
  assert.equal(failed.state.stop.condition, "execution-ambiguity");
  for (const key of ["requests", "wallMinutes", "evidenceBytes"]) {
    assert.deepEqual(failed.state.usage.observed[key], { availability: "unavailable", value: null });
    assert.deepEqual(campaignStatus("first-campaign", failedFixture.options).state.usage.observed[key], { availability: "unavailable", value: null });
  }
  assert.deepEqual(readJournal(failedFixture.paths).slice(-3).map((entry) => entry.type), [
    "job-started",
    "job-blocked",
    "campaign-blocked"
  ]);
});

test("campaign worker restart preserves an interrupted managed dispatch as ambiguity without retry", async (t) => {
  const { paths, options } = fixture(t);
  createCampaign(labCampaign(), options);
  resumeCampaign("first-campaign", options);
  const started = startNextManagedCampaignJob("first-campaign", "ctf-lab-authority", options);
  assert.equal(started.state.queue.running, 1);

  const abort = new AbortController();
  let dispatches = 0;
  const restarted = await runCampaignWorker("first-campaign", {
    ...options,
    labAuthorityId: "ctf-lab-authority",
    labCampaignAuthorityStatus: () => authorizedLabStatus(),
    dispatchAuthorizedLabCampaignJob: async () => { dispatches += 1; },
    signal: abort.signal,
    processSignals: false,
    pollMs: 250,
    heartbeatMs: 1_000,
    wait: async () => abort.abort()
  });
  assert.equal(dispatches, 0);
  assert.equal(restarted.ok, true);
  assert.equal(restarted.reason, "signal");
  assert.equal(restarted.counters.recoveries, 1);
  const recovered = campaignStatus("first-campaign", options).state;
  assert.equal(recovered.status, "blocked");
  assert.equal(recovered.queue.blocked, 1);
  assert.equal(recovered.stop.condition, "execution-ambiguity");
  const pilot = readCtfPilotStatus({ paths, now: fixedAt });
  assert.equal(pilot.state.solving.efficiency.requests.availability, "unavailable");
  assert.deepEqual(readJournal(paths).slice(-1).map((entry) => entry.type), ["campaign-recovered"]);
});

test("verified dedicated-lab jobs can be durably enqueued only inside the bound origin and path prefix", (t) => {
  const { options } = fixture(t);
  const created = createCampaign(labCampaign(), options);
  const candidate = httpJob("discovered-route", "http://127.0.0.1:8080/challenge/next?step=1");
  const result = enqueueLabCampaignJob("first-campaign", {
    authorityId: "ctf-lab-authority",
    job: candidate
  }, {
    ...options,
    verifyLabEnqueue: (_authorityId, envelope) => enqueuePermit(envelope, created.grant)
  });
  assert.equal(result.ok, true);
  assert.equal(result.state.status, "paused");
  assert.equal(result.state.queue.total, 2);
  assert.equal(result.state.queue.queued, 2);
  assert.equal(result.state.usage.reserved.requests, 2);
  assert.equal(result.state.usage.reserved.totalTokens, 2000);
  assert.equal(readJournal(options.paths).at(-1).type, "job-enqueued");
  const replayed = campaignStatus("first-campaign", options);
  assert.equal(replayed.state.jobs[1].id, "discovered-route");
  assert.deepEqual(replayed.state.jobs[1].authority, {
    id: "ctf-lab-authority",
    authoritySha256: "1".repeat(64),
    receiptSha256: "2".repeat(64),
    permitSha256: result.authority.permitSha256
  });

  const exactEnvelope = campaignInternals.loadCampaignContext("first-campaign", options).jobs
    .find((job) => job.metadata.id === "discovered-route");
  const retried = enqueueLabCampaignJob("first-campaign", {
    authorityId: "ctf-lab-authority",
    job: exactEnvelope
  }, {
    ...options,
    verifyLabEnqueue: (_authorityId, envelope) => enqueuePermit(envelope, created.grant)
  });
  assert.equal(retried.ok, true);
  assert.equal(retried.reconciled, true);
  assert.equal(campaignStatus("first-campaign", options).state.queue.total, 2);

  const escaped = httpJob("escaped-route", "http://127.0.0.1:8080/other/route");
  assert.throws(() => enqueueLabCampaignJob("first-campaign", {
    authorityId: "ctf-lab-authority",
    job: escaped
  }, {
    ...options,
    verifyLabEnqueue: (_authorityId, envelope) => enqueuePermit(envelope, created.grant)
  }), /leaves the exact origin or path prefix/u);

  const substitution = httpJob("substituted-route", "http://127.0.0.1:8080/challenge/substituted");
  assert.throws(() => enqueueLabCampaignJob("first-campaign", {
    authorityId: "ctf-lab-authority",
    job: substitution
  }, {
    ...options,
    verifyLabEnqueue: (_authorityId, envelope) => enqueuePermit(envelope, created.grant, {
      jobSha256: "8".repeat(64)
    })
  }), /names a different immutable job/u);

  const capped = httpJob("over-job-cap", "http://127.0.0.1:8080/challenge/capped");
  assert.throws(() => enqueueLabCampaignJob("first-campaign", {
    authorityId: "ctf-lab-authority",
    job: capped
  }, {
    ...options,
    verifyLabEnqueue: (_authorityId, envelope) => enqueuePermit(envelope, created.grant, {
      dynamic: {
        maxJobs: 1,
        allowedMethods: ["GET", "HEAD"],
        maxResponseBytes: 8192,
        maxTimeoutSeconds: 10
      }
    })
  }), /job-count ceiling/u);
});

test("campaign worker keeps one kernel-backed lease, runs typed dry work, and projects no process identity", async (t) => {
  const { paths, options } = fixture(t);
  createCampaign(dryCampaign(), options);
  resumeCampaign("first-campaign", options);
  const firstObserverPoll = projectSnapshot(await buildStatus({ paths, scanHostTokens: false }), paths);
  assert.equal(firstObserverPoll.status.ctfPilot.availability, "unavailable");
  const resolved = campaignInternals.campaignPaths(paths, "first-campaign");
  const firstLease = campaignWorkerInternals.acquireWorkerLease(resolved, fixedAt);
  assert.throws(
    () => campaignWorkerInternals.acquireWorkerLease(resolved, fixedAt),
    /already active or its lease is indeterminate/u
  );
  firstLease.release();

  const abort = new AbortController();
  const pilotErrors = [];
  let clockMs = Date.parse(fixedAt);
  let workerWaiting;
  const reachedWaiting = new Promise((resolve) => { workerWaiting = resolve; });
  const workerRun = runCampaignWorker("first-campaign", {
    ...options,
    now: () => new Date(clockMs++).toISOString(),
    signal: abort.signal,
    processSignals: false,
    pollMs: 250,
    heartbeatMs: 1000,
    onPilotError: (error) => pilotErrors.push(error.message),
    wait: async (_milliseconds, signal) => {
      workerWaiting();
      if (signal.aborted) return;
      await new Promise((resolve) => signal.addEventListener("abort", resolve, { once: true }));
    }
  });
  await reachedWaiting;
  assert.deepEqual(pilotErrors, []);
  const status = campaignStatus("first-campaign", options);
  assert.equal(status.state.status, "completed");
  const observationAt = new Date(clockMs + 100).toISOString();
  const privatePilot = readCtfPilotStatus({ paths, now: observationAt });
  assert.equal(privatePilot.availability, "available");
  assert.equal(privatePilot.state.solving.verdict, "unknown");
  assert.deepEqual(privatePilot.state.solving.completion, {
    state: "unknown",
    reproduction: "unknown",
    externalAcceptance: "unknown"
  });
  assert.deepEqual(privatePilot.state.solving.efficiency.toolRuns, {
    availability: "unavailable",
    value: null
  });
  assert.ok(privatePilot.state.metadata.revision >= 4);
  assert.equal(privatePilot.state.learning.availability, "unavailable");
  const secondObserverPoll = projectSnapshot(await buildStatus({
    paths,
    now: observationAt,
    scanHostTokens: false
  }), paths);
  assert.equal(secondObserverPoll.status.ctfPilot.availability, "available");
  assert.equal(secondObserverPoll.status.ctfPilot.solving.efficiency.requests.value, 0);
  assert.equal(secondObserverPoll.status.ctfPilot.solving.efficiency.toolRuns.availability, "unavailable");
  const reconnectedObserverPoll = projectSnapshot(await buildStatus({
    paths,
    now: observationAt,
    scanHostTokens: false
  }), paths);
  assert.deepEqual(reconnectedObserverPoll.status.ctfPilot, secondObserverPoll.status.ctfPilot);
  const liveProjection = campaignWorkerProjection("first-campaign", { ...options, now: observationAt });
  assert.equal(liveProjection.availability, "available");
  assert.equal(liveProjection.freshness, "current");
  assert.equal(liveProjection.reason, null);

  abort.abort();
  const result = await workerRun;
  assert.equal(result.ok, true);
  assert.equal(result.reason, "signal");
  assert.equal(result.counters.runNextCalls, 1);
  assert.equal(result.counters.pilotSemanticUpdates, 4);
  const afterStopAt = new Date(clockMs + 200).toISOString();
  const stoppedObserverPoll = projectSnapshot(await buildStatus({
    paths,
    now: afterStopAt,
    scanHostTokens: false
  }), paths);
  assert.equal(stoppedObserverPoll.status.ctfPilot.availability, "unavailable");
  assert.equal(stoppedObserverPoll.status.ctfPilot.reason, "worker-unavailable");
  const projection = campaignWorkerProjection("first-campaign", { ...options, now: afterStopAt });
  assert.equal(projection.availability, "available");
  assert.equal(projection.freshness, "stale");
  assert.equal(projection.reason, "worker-inactive");
  assert.equal(projection.workerState, "stopping");
  assert.equal(projection.campaign.status, "completed");
  assert.equal("controller" in projection, false);
  assert.doesNotMatch(JSON.stringify(projection), /startTimeTicks|bootId|pid/u);
  assert.equal(campaignWorkerProjection("first-campaign", {
    ...options,
    now: "2026-10-19T11:59:59.000Z"
  }).reason, "heartbeat-invalid");
});

test("campaign worker bounds long polls by heartbeat due time", async (t) => {
  const { options } = fixture(t);
  createCampaign(dryCampaign(), options);
  const abort = new AbortController();
  const waits = [];
  const result = await runCampaignWorker("first-campaign", {
    ...options,
    signal: abort.signal,
    processSignals: false,
    pollMs: 60_000,
    heartbeatMs: 1_000,
    wait: async (milliseconds) => {
      waits.push(milliseconds);
      abort.abort();
    }
  });
  assert.equal(result.ok, true);
  assert.equal(waits.length, 1);
  assert.ok(waits[0] > 0 && waits[0] <= 1_000, `unexpected heartbeat-bounded wait: ${waits[0]}`);
});

test("campaign worker projection distinguishes current, delayed, and expired live heartbeats", async (t) => {
  const { paths, options } = fixture(t);
  createCampaign(dryCampaign(), options);
  const abort = new AbortController();
  let reachedWait;
  const waiting = new Promise((resolve) => { reachedWait = resolve; });
  const running = runCampaignWorker("first-campaign", {
    ...options,
    signal: abort.signal,
    processSignals: false,
    pollMs: 60_000,
    heartbeatMs: 60_000,
    wait: async (_milliseconds, signal) => {
      reachedWait();
      if (!signal.aborted) await new Promise((resolve) => signal.addEventListener("abort", resolve, { once: true }));
    }
  });
  await waiting;
  const location = campaignInternals.campaignPaths(paths, "first-campaign");
  const heartbeat = campaignWorkerInternals.readHeartbeat(location.worker, paths);
  const observed = Date.parse(heartbeat.heartbeatAt);
  const current = campaignWorkerProjection("first-campaign", {
    ...options,
    now: new Date(observed + 1_000).toISOString()
  });
  const delayed = campaignWorkerProjection("first-campaign", {
    ...options,
    now: new Date(observed + 30_000).toISOString()
  });
  const expired = campaignWorkerProjection("first-campaign", {
    ...options,
    now: heartbeat.validUntil
  });
  assert.equal(current.freshness, "current");
  assert.equal(current.reason, null);
  assert.equal(delayed.freshness, "delayed");
  assert.equal(delayed.reason, null);
  assert.equal(expired.freshness, "stale");
  assert.equal(expired.reason, "heartbeat-expired");
  abort.abort();
  await running;
});

test("campaign worker feed counters remain additive across process generations", async (t) => {
  const { paths, options } = fixture(t);
  createCampaign(dryCampaign(), options);
  let clockMs = Date.parse(fixedAt);

  async function runOneGeneration() {
    const abort = new AbortController();
    const result = await runCampaignWorker("first-campaign", {
      ...options,
      now: () => new Date(clockMs++).toISOString(),
      signal: abort.signal,
      processSignals: false,
      pollMs: 250,
      heartbeatMs: 1_000,
      wait: async () => abort.abort()
    });
    assert.equal(result.counters.pilotSemanticUpdates, 1);
  }

  await runOneGeneration();
  const afterFirst = readCtfPilotStatus({
    paths,
    now: new Date(clockMs + 10).toISOString()
  });
  assert.equal(afterFirst.availability, "available");
  assert.equal(afterFirst.state.cockpit.updatesPublished.value, 1);

  await runOneGeneration();
  const afterSecond = readCtfPilotStatus({
    paths,
    now: new Date(clockMs + 10).toISOString()
  });
  assert.equal(afterSecond.availability, "available");
  assert.equal(afterSecond.state.cockpit.updatesPublished.value, 2);
  assert.equal(afterSecond.state.cockpit.updatesMissed.value, 0);
  assert.equal(afterSecond.state.solving.verdict, "unknown");
  assert.equal(afterSecond.state.integrity.availability, "unavailable");
});

test("campaign worker merges interleaved case-pilot counters without rollback", async (t) => {
  const { paths, options } = fixture(t);
  createCampaign(dryCampaign(), options);
  const abort = new AbortController();
  let clockMs = Date.parse(fixedAt);
  let waits = 0;
  const result = await runCampaignWorker("first-campaign", {
    ...options,
    now: () => new Date(clockMs++).toISOString(),
    signal: abort.signal,
    processSignals: false,
    pollMs: 250,
    heartbeatMs: 1_000,
    wait: async () => {
      waits += 1;
      if (waits > 1) {
        abort.abort();
        return;
      }
      updateCtfPilotState((current) => {
        assert.equal(current.availability, "available");
        const updatedAt = nextCtfPilotTimestamp(
          current.state.metadata.updatedAt,
          new Date(clockMs++).toISOString()
        );
        return {
          ...current.state,
          metadata: {
            ...current.state.metadata,
            revision: current.state.metadata.revision + 1,
            updatedAt,
            validUntil: new Date(Date.parse(updatedAt) + 15_000).toISOString()
          },
          cockpit: {
            ...current.state.cockpit,
            updatedAt,
            updatesPublished: {
              availability: "available",
              value: current.state.cockpit.updatesPublished.value + 10
            },
            updatesMissed: { availability: "available", value: 3 }
          }
        };
      }, { paths });
      resumeCampaign("first-campaign", options);
    }
  });
  assert.equal(result.ok, true);
  assert.equal(result.counters.pilotSemanticUpdates, 5);
  const pilot = readCtfPilotStatus({ paths, now: new Date(clockMs + 10).toISOString() });
  assert.equal(pilot.availability, "available");
  assert.equal(
    pilot.state.cockpit.updatesPublished.value,
    10 + result.counters.pilotSemanticUpdates
  );
  assert.equal(pilot.state.cockpit.updatesMissed.value, 3);
});

test("heartbeat preserves same-generation solver and cockpit assessments", async (t) => {
  const { paths, options } = fixture(t);
  createCampaign(dryCampaign(), options);
  resumeCampaign("first-campaign", options);
  const abort = new AbortController();
  let clockMs = Date.parse(fixedAt);
  let waits = 0;
  let expected;
  await runCampaignWorker("first-campaign", {
    ...options, now: () => new Date(clockMs++).toISOString(),
    signal: abort.signal, processSignals: false, pollMs: 250, heartbeatMs: 1000,
    wait: async () => {
      if (waits++ === 0) {
        updateCtfPilotState((current) => {
          const updatedAt = nextCtfPilotTimestamp(current.state.metadata.updatedAt, new Date(clockMs++).toISOString());
          const state = structuredClone(current.state);
          state.metadata = { ...state.metadata, revision: state.metadata.revision + 1, updatedAt,
            validUntil: new Date(Date.parse(updatedAt) + 15000).toISOString() };
          state.solving = { ...state.solving, verdict: "pass", now: "complete", actionNeeded: "none", updatedAt,
            completion: { state: "complete", reproduction: "confirmed", externalAcceptance: "accepted" },
            objectives: { availability: "available", completed: 1, total: 1 } };
          state.cockpit = { ...state.cockpit, verdict: "pass", now: "current", actionNeeded: "none", updatedAt,
            signals: { availability: "available", available: 1, total: 1 } };
          expected = state;
          return state;
        }, { paths });
        clockMs += 1100;
      } else {
        const current = readCtfPilotStatus({ paths, now: new Date(clockMs).toISOString() }).state;
        for (const axis of ["solving", "cockpit"]) {
          for (const key of ["verdict", "now", "actionNeeded", "updatedAt"]) assert.equal(current[axis][key], expected[axis][key]);
        }
        abort.abort();
      }
    }
  });
});

test("campaign worker honors an already-aborted caller without polling", async (t) => {
  const { options } = fixture(t);
  createCampaign(dryCampaign(), options);
  const abort = new AbortController();
  abort.abort();
  const result = await runCampaignWorker("first-campaign", {
    ...options,
    signal: abort.signal,
    processSignals: false,
    pollMs: 250,
    heartbeatMs: 1_000,
    wait: async () => assert.fail("pre-aborted worker must not poll")
  });
  assert.equal(result.ok, true);
  assert.equal(result.reason, "signal");
  assert.equal(result.counters.cycles, 0);
});

test("campaign worker fails closed after repairing ambiguous controller storage", async (t) => {
  const { paths, options } = fixture(t);
  createCampaign(dryCampaign(), options);
  resumeCampaign("first-campaign", options);
  const location = campaignInternals.campaignPaths(paths, "first-campaign");
  fs.appendFileSync(location.journal, Buffer.from('{"sequence":3,"at":"torn'));
  fs.writeFileSync(location.lock, `${JSON.stringify({
    pid: 2_147_483_647,
    startTimeTicks: "1",
    bootId: fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim(),
    acquiredAt: fixedAt
  })}\n`, { mode: 0o600 });

  const abort = new AbortController();
  const result = await runCampaignWorker("first-campaign", {
    ...options,
    signal: abort.signal,
    processSignals: false,
    pollMs: 250,
    heartbeatMs: 1_000,
    wait: async () => abort.abort()
  });
  assert.equal(result.ok, true);
  assert.equal(result.reason, "stopped");
  assert.equal(result.counters.recoveries, 1);
  const status = campaignStatus("first-campaign", options);
  assert.equal(status.state.status, "stopped");
  assert.equal(status.state.stop.condition, "controller-recovery-required");
  assert.equal(status.state.queue.queued, 1);
  assert.throws(() => runNextCampaignJob("first-campaign", options), /requires running state/u);
  assert.equal(fs.existsSync(location.lock), false);
  assert.equal(
    fs.readdirSync(location.directory).filter((name) => name.startsWith("journal.jsonl.torn.")).length,
    1
  );
  assert.equal(
    fs.readdirSync(location.directory).filter((name) => name.startsWith(".campaign.lock.retired.")).length,
    1
  );
});

test("recovery replays the journal and safely requeues an interrupted non-contact job", (t) => {
  const { paths, options } = fixture(t);
  createCampaign(dryCampaign(), options);
  resumeCampaign("first-campaign", options);
  const bundlePath = campaignInternals.campaignPaths(paths, "first-campaign");
  const before = readJournal(paths);
  const state = campaignStatus("first-campaign", options).state;
  const job = state.jobs[0];
  const started = campaignInternals.journalEntry(before.at(-1), "job-started", {
    jobId: job.id,
    jobSha256: job.jobSha256,
    authorityId: null
  }, fixedAt);
  fs.appendFileSync(bundlePath.journal, `${JSON.stringify(started)}\n`, { encoding: "utf8" });

  const stale = campaignStatus("first-campaign", options);
  assert.equal(stale.state.queue.running, 1);
  assert.equal(stale.projection.current, false);
  const recovered = recoverCampaign("first-campaign", options);
  assert.equal(recovered.ok, true);
  assert.deepEqual(recovered.recoveredJobs, ["controller-check"]);
  assert.equal(recovered.state.status, "running");
  assert.equal(recovered.state.queue.queued, 1);
  assert.equal(recovered.state.queue.running, 0);
  assert.equal(recovered.state.kpis.recoveries.value, 1);
  assert.equal(campaignStatus("first-campaign", options).projection.current, true);
  assert.deepEqual(readJournal(paths).slice(-1).map((entry) => entry.type), ["campaign-recovered"]);

  const repeated = recoverCampaign("first-campaign", options);
  assert.deepEqual(repeated.recoveredJobs, []);
  assert.equal(repeated.state.kpis.recoveries.value, 1);
  assert.deepEqual(readJournal(paths).slice(-1).map((entry) => entry.type), ["campaign-recovered"]);
});

test("recovery atomically blocks an interrupted managed job as execution ambiguity", (t) => {
  const { paths, options } = fixture(t);
  const input = dryCampaign();
  input.engagementId = "ctf-engagement";
  input.operations = [{ adapterId: "dnsx-domain-observe", action: "observe", toolId: "dnsx" }];
  input.selectors = [{ type: "domain", value: "challenge.example.test" }];
  input.jobs = [{
    id: "ambiguous-contact",
    type: "managed-adapter",
    engagementId: "ctf-engagement",
    workflow: { instanceId: "ctf-workflow", phaseAttemptId: `wpa_${"1".repeat(32)}` },
    adapter: { id: "dnsx-domain-observe", action: "observe", toolId: "dnsx" },
    selector: { type: "domain", value: "challenge.example.test" },
    operation: { kind: "dns-query", recordType: "A", resolver: "1.1.1.1:53", timeoutSeconds: 5 },
    bounds: {
      maxMinutes: 1,
      estimatedRequests: 1,
      maxParallel: 1,
      maxRatePerSecond: 1,
      maxTokens: 1000,
      maxSpend: 0,
      maxEvidenceBytes: 2 * 1024 * 1024
    }
  }];
  createCampaign(input, options);
  resumeCampaign("first-campaign", options);
  const location = campaignInternals.campaignPaths(paths, "first-campaign");
  const before = readJournal(paths);
  const job = campaignStatus("first-campaign", options).state.jobs[0];
  const started = campaignInternals.journalEntry(before.at(-1), "job-started", {
    jobId: job.id,
    jobSha256: job.jobSha256,
    authorityId: "ctf-lab-authority"
  }, fixedAt);
  fs.appendFileSync(location.journal, `${JSON.stringify(started)}\n`, { encoding: "utf8" });

  const recovered = recoverCampaign("first-campaign", options);
  assert.deepEqual(recovered.recoveredJobs, ["ambiguous-contact"]);
  assert.equal(recovered.state.status, "blocked");
  assert.equal(recovered.state.queue.blocked, 1);
  assert.equal(recovered.state.stop.condition, "execution-ambiguity");
  assert.equal(recovered.state.kpis.recoveries.value, 1);
  for (const key of ["requests", "wallMinutes", "evidenceBytes"]) {
    assert.deepEqual(recovered.state.usage.observed[key], { availability: "unavailable", value: null });
  }
  assert.equal(readJournal(paths).at(-1).type, "campaign-recovered");
});

test("recovery retires a provably dead lock but preserves malformed lock evidence", (t) => {
  const { paths, options } = fixture(t);
  createCampaign(dryCampaign(), options);
  const location = campaignInternals.campaignPaths(paths, "first-campaign");
  const owner = {
    pid: 2_147_483_647,
    startTimeTicks: "1",
    bootId: fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim(),
    acquiredAt: fixedAt
  };
  fs.writeFileSync(location.lock, `${JSON.stringify(owner)}\n`, { mode: 0o600 });
  const recovered = recoverCampaign("first-campaign", options);
  assert.equal(recovered.retiredLock, true);
  assert.equal(fs.existsSync(location.lock), false);
  assert.equal(fs.readdirSync(location.directory).filter((name) => name.startsWith(".campaign.lock.retired.")).length, 1);

  fs.writeFileSync(location.lock, "", { mode: 0o600 });
  assert.throws(() => recoverCampaign("first-campaign", options), /malformed and was preserved/u);
  assert.equal(fs.existsSync(location.lock), true);
  fs.writeFileSync(location.lock, "{}\n", { mode: 0o600 });
  assert.throws(() => recoverCampaign("first-campaign", options), /invalid and was preserved/u);
  assert.equal(fs.existsSync(location.lock), true);
});

test("grant and journal tampering fail closed", (t) => {
  const { paths, options } = fixture(t);
  createCampaign(dryCampaign(), options);
  const location = campaignInternals.campaignPaths(paths, "first-campaign");
  const grant = JSON.parse(fs.readFileSync(location.grant, "utf8"));
  grant.ceilings.maxRequests += 1;
  fs.writeFileSync(location.grant, `${JSON.stringify(grant, null, 2)}\n`, { mode: 0o600 });
  assert.throws(() => campaignStatus("first-campaign", options), /grant digest changed/u);

  const second = dryCampaign();
  second.id = "second-campaign";
  createCampaign(second, options);
  const secondPath = campaignInternals.campaignPaths(paths, "second-campaign");
  const journal = fs.readFileSync(secondPath.journal, "utf8").trim().split(/\r?\n/u).map(JSON.parse);
  journal[0].payload.jobs[0].jobSha256 = "f".repeat(64);
  fs.writeFileSync(secondPath.journal, `${journal.map(JSON.stringify).join("\n")}\n`, { mode: 0o600 });
  assert.throws(() => campaignStatus("second-campaign", options), /entry digest changed/u);
});

test("journal replay rejects an incomplete tail and backward time", (t) => {
  const { paths, options } = fixture(t);
  createCampaign(dryCampaign(), options);
  const location = campaignInternals.campaignPaths(paths, "first-campaign");
  const complete = fs.readFileSync(location.journal, "utf8");
  fs.writeFileSync(location.journal, complete.slice(0, -1), { mode: 0o600 });
  assert.throws(() => campaignStatus("first-campaign", options), /incomplete trailing record/u);

  fs.writeFileSync(location.journal, complete, { mode: 0o600 });
  const before = readJournal(paths);
  const reversed = campaignInternals.journalEntry(
    before.at(-1),
    "campaign-resumed",
    {},
    "2026-10-18T12:00:00.000Z"
  );
  fs.appendFileSync(location.journal, `${JSON.stringify(reversed)}\n`, { encoding: "utf8" });
  assert.throws(() => campaignStatus("first-campaign", options), /time moved backwards/u);
});

test("a clock rollback is rejected before it can poison the authoritative journal", (t) => {
  const { paths, options } = fixture(t);
  createCampaign(dryCampaign(), options);
  const before = fs.readFileSync(campaignInternals.campaignPaths(paths, "first-campaign").journal, "utf8");
  assert.throws(
    () => resumeCampaign("first-campaign", { ...options, now: "2026-10-18T12:00:00.000Z" }),
    /time moved backwards/u
  );
  const after = fs.readFileSync(campaignInternals.campaignPaths(paths, "first-campaign").journal, "utf8");
  assert.equal(after, before);
  assert.equal(campaignStatus("first-campaign", options).state.status, "paused");
});

test("recovery quarantines a partial stop record and durably stops the campaign", (t) => {
  const { paths, options } = fixture(t);
  createCampaign(dryCampaign(), options);
  resumeCampaign("first-campaign", options);
  const location = campaignInternals.campaignPaths(paths, "first-campaign");
  const committed = fs.readFileSync(location.journal);
  const prior = readJournal(paths).at(-1);
  const completeStop = JSON.stringify(campaignInternals.journalEntry(prior, "campaign-stopped", {
    condition: "operator-stop",
    reason: "Stop before the next scheduled action."
  }, fixedAt));
  const partialStop = Buffer.from(completeStop.slice(0, -32), "utf8");
  fs.appendFileSync(location.journal, partialStop);
  assert.throws(() => campaignStatus("first-campaign", options), /incomplete trailing record/u);

  const recovered = recoverCampaign("first-campaign", options);
  assert.equal(recovered.repairedJournalTail, true);
  assert.deepEqual(recovered.journalRepair, {
    repaired: true,
    mode: "incomplete-tail-quarantined"
  });
  assert.equal(fs.readFileSync(location.journal).subarray(0, committed.length).equals(committed), true);
  assert.equal(recovered.state.status, "stopped");
  assert.equal(recovered.state.stop.condition, "controller-recovery-required");
  assert.equal(recovered.state.kpis.recoveries.value, 0);
  assert.equal(readJournal(paths).at(-1).type, "campaign-stopped");
  assert.throws(() => runNextCampaignJob("first-campaign", options), /requires running state/u);
  const quarantined = fs.readdirSync(location.directory)
    .filter((name) => /^journal\.jsonl\.torn\.[a-f0-9]{16}\.bin$/u.test(name));
  assert.equal(quarantined.length, 1);
  assert.deepEqual(fs.readFileSync(path.join(location.directory, quarantined[0])), partialStop);
});

test("recovery restores a missing delimiter without discarding a complete stop record", (t) => {
  const { paths, options } = fixture(t);
  createCampaign(dryCampaign(), options);
  resumeCampaign("first-campaign", options);
  stopCampaign("first-campaign", { reason: "End the local pilot window." }, options);
  const location = campaignInternals.campaignPaths(paths, "first-campaign");
  const committed = fs.readFileSync(location.journal);
  assert.equal(committed.at(-1), 0x0a);
  fs.writeFileSync(location.journal, committed.subarray(0, committed.length - 1), { mode: 0o600 });
  assert.throws(() => campaignStatus("first-campaign", options), /incomplete trailing record/u);

  const recovered = recoverCampaign("first-campaign", options);
  assert.equal(recovered.repairedJournalTail, true);
  assert.deepEqual(recovered.journalRepair, { repaired: true, mode: "delimiter-restored" });
  assert.deepEqual(recovered.recoveredJobs, []);
  assert.deepEqual(fs.readFileSync(location.journal), committed);
  assert.equal(recovered.state.status, "stopped");
  assert.equal(recovered.state.stop.condition, "operator-stop");
  assert.equal(readJournal(paths).at(-1).type, "campaign-stopped");
  assert.equal(
    fs.readdirSync(location.directory).filter((name) => name.startsWith("journal.jsonl.torn.")).length,
    0
  );
  assert.throws(() => runNextCampaignJob("first-campaign", options), /requires running state/u);
});

test("ambiguous tail recovery closes a completed campaign against later enqueue", (t) => {
  const { paths, options } = fixture(t);
  createCampaign(dryCampaign(), options);
  resumeCampaign("first-campaign", options);
  runNextCampaignJob("first-campaign", options);
  assert.equal(campaignStatus("first-campaign", options).state.status, "completed");
  const location = campaignInternals.campaignPaths(paths, "first-campaign");
  const prior = readJournal(paths).at(-1);
  const stop = JSON.stringify(campaignInternals.journalEntry(prior, "campaign-stopped", {
    condition: "operator-stop",
    reason: "Keep the completed campaign closed."
  }, fixedAt));
  fs.appendFileSync(location.journal, stop.slice(0, -32), { encoding: "utf8" });

  const recovered = recoverCampaign("first-campaign", options);
  assert.equal(recovered.state.status, "stopped");
  assert.equal(recovered.state.stop.condition, "controller-recovery-required");
  assert.equal(readJournal(paths).at(-1).type, "campaign-stopped");
});

test("operator stop is durable and terminal", (t) => {
  const { options } = fixture(t);
  createCampaign(dryCampaign(), options);
  resumeCampaign("first-campaign", options);
  const stopped = stopCampaign("first-campaign", { reason: "End the local pilot window." }, options);
  assert.equal(stopped.state.status, "stopped");
  assert.equal(stopped.state.stop.condition, "operator-stop");
  assert.throws(() => runNextCampaignJob("first-campaign", options), /requires running state/u);
});

test("campaign CLI requires a case and exposes replayed status without target execution", (t) => {
  const { paths, options } = fixture(t);
  createCampaign(dryCampaign(), options);
  const missingCase = invoke(["campaign", "status", "first-campaign", "--json"], paths.home);
  assert.notEqual(missingCase.status, 0);
  assert.match(missingCase.stderr, /requires --case ID/u);

  const status = invoke(["--case", paths.caseId, "campaign", "status", "first-campaign", "--json"], paths.home);
  assert.equal(status.status, 0, status.stderr);
  const value = JSON.parse(status.stdout);
  assert.equal(value.state.status, "paused");
  assert.equal(value.state.capability.managedAdapterDispatch, "confirmed-dedicated-lab-only");
  assert.equal(value.state.kpis.hypotheses.availability, "unavailable");

  const unassigned = invoke(["--unassigned", "campaign", "status", "first-campaign", "--json"], paths.home);
  assert.notEqual(unassigned.status, 0);
  assert.match(unassigned.stderr, /--unassigned is not supported/u);
});

test("campaign CLI input stays inside private case state and creation output is redacted", (t) => {
  const { root, paths } = fixture(t);
  const inside = path.join(paths.stateHome, "campaign-input.json");
  fs.writeFileSync(inside, `${JSON.stringify(dryCampaign())}\n`, { mode: 0o600 });
  assert.equal(cliInternals.readPrivateCampaignInput(inside, paths).id, "first-campaign");

  fs.chmodSync(inside, 0o640);
  assert.throws(() => cliInternals.readPrivateCampaignInput(inside, paths), /mode 0600/u);
  fs.chmodSync(inside, 0o600);

  const alias = path.join(paths.stateHome, "campaign-input-link.json");
  fs.symlinkSync(inside, alias);
  assert.throws(() => cliInternals.readPrivateCampaignInput(alias, paths), /must not contain symbolic links/u);

  const outside = path.join(root, "outside-campaign-input.json");
  fs.writeFileSync(outside, `${JSON.stringify(dryCampaign())}\n`, { mode: 0o600 });
  assert.throws(
    () => cliInternals.readPrivateCampaignInput(outside, paths),
    /must be stored inside the selected case state directory/u
  );

  const projection = cliInternals.campaignCreationProjection({
    created: true,
    grant: { selectors: [{ value: "secret-selector.example" }], source: "secret-source" },
    state: {
      campaignId: "first-campaign",
      grantSha256: "a".repeat(64),
      status: "paused",
      queue: { total: 0 },
      kpis: {},
      usage: {},
      capability: {}
    },
    bindingHealth: { schedulingReady: true, executionAuthorityReady: false }
  });
  const serialized = JSON.stringify(projection);
  assert.doesNotMatch(serialized, /secret-selector|secret-source/u);
  assert.equal(projection.bindingHealth.executionAuthorityReady, false);
});

test("persistent user-service renderer emits fixed observer, campaign, and remote-runner units", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-campaign-services-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const outputDirectory = path.join(root, "units");
  const render = spawnSync(process.execPath, [
    path.join(repo, "deploy", "local", "systemd", "render.mjs"),
    "--repo", repo,
    "--node", process.execPath,
    "--output", outputDirectory
  ], { cwd: repo, encoding: "utf8", timeout: 10_000 });
  assert.equal(render.status, 0, render.stderr);
  const observer = fs.readFileSync(path.join(outputDirectory, "gate-observer.service"), "utf8");
  const campaign = fs.readFileSync(path.join(outputDirectory, "gate-campaign@.service"), "utf8");
  const remoteRunner = fs.readFileSync(path.join(outputDirectory, "gate-remote-runner@.service"), "utf8");
  function service(text) {
    let section;
    const values = new Map();
    for (const raw of text.split("\n")) {
      const line = raw.trim();
      if (!line || line.startsWith("#") || line.startsWith(";")) continue;
      if (line.startsWith("[")) { section = line; continue; }
      if (section !== "[Service]") continue;
      const index = line.indexOf("=");
      assert.ok(index > 0);
      const key = line.slice(0, index).trim();
      const value = line.slice(index + 1).trim();
      if (key === "EnvironmentFile" || key === "Environment") {
        values.set(key, value ? [...(values.get(key) || []), value] : []);
      } else values.set(key, value);
    }
    return values;
  }
  const [observed, managed, remote] = [observer, campaign, remoteRunner].map(service);
  for (const unit of [observed, managed, remote]) {
    assert.equal(unit.get("Type"), "simple");
    assert.equal(unit.get("UMask"), "0077");
    assert.equal(unit.get("NoNewPrivileges"), "true");
    assert.equal(unit.get("WorkingDirectory"), repo);
  }
  assert.equal(observed.get("Restart"), "on-failure");
  assert.equal(managed.get("Restart"), "on-failure");
  assert.equal(remote.get("Restart"), "on-abnormal");
  assert.equal(observed.get("ExecStart"), `"${process.execPath}" "${gate}" up --host 127.0.0.1 --port 4173`);
  assert.equal(managed.get("ExecStart"), `"${process.execPath}" "${gate}" campaign worker ` + "${GATE_CAMPAIGN}");
  assert.equal(remote.get("ExecStart"), `"${process.execPath}" "${path.join(repo, "cockpit/remote/runner-cli.mjs")}"`);
  assert.deepEqual(managed.get("EnvironmentFile"), ["%h/.config/gate/gate.env", "%h/.config/gate/campaign-%i.env"]);
  assert.deepEqual(remote.get("EnvironmentFile"), ["%h/.config/gate/remote-runner-%i.env"]);
  assert.deepEqual(remote.get("Environment"), ["NODE_OPTIONS=", "PATH=/usr/bin:/bin"]);
  const verify = spawnSync("systemd-analyze", [
    "verify",
    path.join(outputDirectory, "gate-observer.service"),
    path.join(outputDirectory, "gate-campaign@.service"),
    path.join(outputDirectory, "gate-remote-runner@.service")
  ], { cwd: repo, encoding: "utf8", timeout: 10_000 });
  if (!verify.error || verify.error.code !== "ENOENT") {
    assert.equal(verify.status, 0, `${verify.stdout}\n${verify.stderr}`);
  }
});
