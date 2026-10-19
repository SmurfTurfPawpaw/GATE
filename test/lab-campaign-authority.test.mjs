import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { compileHttpxUrlFetch } from "../src/adapters/httpx-url-fetch.mjs";
import {
  campaignInternals,
  campaignStatus,
  createCampaign,
  enqueueLabCampaignJob,
  resumeCampaign
} from "../src/lib/campaigns.mjs";
import { runNextCampaignWorkerJob } from "../src/lib/campaign-worker.mjs";
import {
  confirmLabCampaignAuthority,
  createLabCampaignAuthority,
  dispatchAuthorizedLabCampaignJob,
  enqueueAuthorizedLabCampaignFetch,
  labCampaignAuthorityInternals,
  labCampaignAuthorityStatus,
  recoverLabCampaignAuthority,
  stopLabCampaignAuthority,
  verifyLabCampaignExecutionCapability,
  verifyLabCampaignWorkflowReservation
} from "../src/lib/lab-campaign-authority.mjs";
import {
  CASE_SCOPE_API_VERSION,
  CASE_SCOPE_ISOLATION,
  CASE_SCOPE_KIND,
  CASE_SCOPE_SCHEMA,
  canonicalCaseScopeText,
  caseScopeDigest
} from "../src/lib/case-scope.mjs";
import { ensureRuntime, runtimePaths } from "../src/lib/paths.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sha = (character) => character.repeat(64);

function setup(t, { jobCount = 2, basis = "dedicated-lab", crossOrigin = false } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-lab-authority-"));
  const home = path.join(root, "home");
  const caseId = "hacker101-pilot";
  const caseRoot = path.join(home, "cases", caseId);
  const stateHome = path.join(caseRoot, "state");
  fs.mkdirSync(stateHome, { recursive: true, mode: 0o700 });
  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 15 * 60_000).toISOString();
  const scope = {
    $schema: CASE_SCOPE_SCHEMA,
    apiVersion: CASE_SCOPE_API_VERSION,
    kind: CASE_SCOPE_KIND,
    metadata: { id: caseId, displayName: "Hacker101 pilot", createdAt },
    program: { id: "hacker101", profileSha256: sha("a") },
    project: null,
    isolation: { ...CASE_SCOPE_ISOLATION },
    scopeSha256: sha("0")
  };
  scope.scopeSha256 = caseScopeDigest(scope);
  fs.writeFileSync(path.join(caseRoot, "scope.json"), canonicalCaseScopeText(scope), { mode: 0o600 });
  fs.writeFileSync(path.join(stateHome, ".case-binding.json"), `${JSON.stringify({
    caseId, scopeSha256: scope.scopeSha256
  }, null, 2)}\n`, { mode: 0o600 });
  const paths = runtimePaths({ home, repo, caseId });
  ensureRuntime(paths);

  const bounds = {
    maxMinutes: 2,
    estimatedRequests: 1,
    maxParallel: 1,
    maxRatePerSecond: 2,
    maxTokens: 1000,
    maxSpend: 0,
    maxEvidenceBytes: 2 * 1024 * 1024
  };
  const target = crossOrigin ? "https://other.example.test/levels/0" : "https://ctf.example.test/levels/0";
  const jobs = Array.from({ length: jobCount }, (_, index) => {
    const job = {
      $schema: "https://gate.local/schemas/campaign-job.schema.json",
      apiVersion: "gate.dev/campaign-job/v1",
      kind: "CampaignJob",
      metadata: { id: `fetch-${index + 1}`, createdAt },
      campaignId: "baseline-campaign",
      grantSha256: sha("0"),
      job: {
        type: "managed-adapter",
        engagementId: "hacker101-lab",
        workflow: { instanceId: "pilot-workflow", phaseAttemptId: `wpa_${"1".repeat(32)}` },
        adapter: { id: "httpx-url-fetch", action: "observe", toolId: "httpx" },
        selector: { type: "url", value: target },
        operation: { kind: "http-fetch", method: index % 2 === 0 ? "GET" : "HEAD", allowedIp: "192.0.2.10", timeoutSeconds: 5, maxResponseBytes: 4096 },
        bounds,
      },
      jobSha256: sha("0")
    };
    return job;
  });
  const grant = {
    $schema: "https://gate.local/schemas/campaign-grant.schema.json",
    apiVersion: "gate.dev/campaign-grant/v1",
    kind: "CampaignGrant",
    metadata: { id: "baseline-campaign", createdAt, expiresAt },
    binding: {
      case: { id: caseId, scopeSha256: scope.scopeSha256 },
      program: { id: "hacker101", profileSha256: sha("a") },
      source: { id: "program-rules", contentSha256: sha("b"), projectionSha256: sha("c"), snapshotSha256: sha("d") },
      engagement: { id: "hacker101-lab" }
    },
    allow: {
      operations: [{ adapterId: "httpx-url-fetch", action: "observe", toolId: "httpx" }],
      adapterRegistrySha256: sha("e"),
      selectors: [{ type: "url", value: "https://ctf.example.test/levels/0" }],
      environment: "host"
    },
    ceilings: {
      maxWallMinutes: 30,
      maxRequests: 20,
      maxRatePerSecond: 2,
      maxConcurrency: 1,
      maxInputTokens: 10_000,
      maxOutputTokens: 10_000,
      maxTotalTokens: 20_000,
      maxSpend: 1,
      maxEvidenceBytes: 64 * 1024 * 1024
    },
    stopConditions: ["operator-stop", "campaign-expiry", "execution-ambiguity", "execution-blocked"],
    grantSha256: sha("0")
  };
  grant.grantSha256 = labCampaignAuthorityInternals.grantDigest(grant);
  for (const job of jobs) {
    job.grantSha256 = grant.grantSha256;
    job.jobSha256 = labCampaignAuthorityInternals.jobDigest(job);
  }
  const state = {
    campaignId: grant.metadata.id,
    grantSha256: grant.grantSha256,
    status: "paused",
    jobs: jobs.map((job) => ({ id: job.metadata.id, jobSha256: job.jobSha256, status: "queued" }))
  };
  const context = { grant, jobs, state, activeStart: null, bindingHealth: { schedulingReady: true, reasons: [] } };
  const envelope = {
    maxMinutes: 20,
    maxRequests: 20,
    maxRatePerSecond: 2,
    maxParallel: 1,
    maxInputTokens: 10_000,
    maxOutputTokens: 10_000,
    maxTotalTokens: 20_000,
    maxEvidenceBytes: 64 * 1024 * 1024,
    maxSpend: 1,
    controls: {
      wallTime: "enforced", requests: "enforced", rate: "enforced", parallel: "enforced",
      tokens: "enforced", evidenceBytes: "enforced", spend: "enforced"
    }
  };
  const admission = {
    $schema: "https://gate.local/schemas/workflow-admission.schema.json",
    apiVersion: "gate.workflow-admission/v1",
    kind: "WorkflowAdmission",
    instanceId: "pilot-workflow",
    workflowDefinitionSha256: sha("f"),
    phaseId: "active-surface-validation",
    target: "https://ctf.example.test/levels/0",
    action: "observe",
    toolId: "httpx",
    toolMappingSha256: sha("1"),
    adapterConstraint: "Use only the reviewed httpx-url-fetch adapter.",
    authority: {
      engagementId: "hacker101-lab",
      planSha256: sha("2"),
      envelopeSha256: sha("3"),
      receiptSha256: sha("4"),
      authorizationValidUntil: expiresAt,
      checkedAt: createdAt
    },
    envelope,
    issuedAt: createdAt,
    expiresAt
  };
  const admissionFile = path.join(root, "admission.json");
  fs.writeFileSync(admissionFile, `${JSON.stringify(admission, null, 2)}\n`, { mode: 0o600 });
  const admissionSha256 = cryptoSha(fs.readFileSync(admissionFile));
  const destinationObservationFile = path.join(root, "destination-observation.json");
  fs.writeFileSync(destinationObservationFile, `${JSON.stringify({
    $schema: "https://gate.local/schemas/lab-destination-observation.schema.json",
    apiVersion: "gate.lab-destination-observation/v1",
    kind: "LabDestinationObservation",
    origin: "https://ctf.example.test",
    hostname: "ctf.example.test",
    ips: ["192.0.2.10"],
    observedAt: createdAt,
    source: { kind: "dns-a-aaaa", reference: "private://observations/ctf-dns.json", sha256: sha("d") }
  }, null, 2)}\n`, { mode: 0o600 });
  const engagementCheck = () => ({
    allowed: true,
    reasons: [],
    engagement: {
      authorization: { basis },
      limits: { maxMinutes: 30, maxRequests: 20, maxParallel: 1, maxRatePerSecond: 2, maxTokens: 20_000 }
    },
    executionBinding: {
      engagementId: "hacker101-lab",
      planSha256: sha("2"),
      envelopeSha256: sha("3"),
      receiptSha256: sha("4"),
      authorizationValidUntil: expiresAt,
      target: { type: "url", value: target },
      action: "observe",
      environment: "host",
      allowedDestinations: ["gate-home"],
      permittedTools: ["httpx"]
    }
  });
  const workflowStatus = () => ({
    ok: true,
    instanceId: "pilot-workflow",
    status: "running",
    contract: { sha256: sha("9") },
    activePhase: {
      id: "active-surface-validation",
      attemptId: `wpa_${"1".repeat(32)}`,
      effectClass: "A1",
      toolId: "httpx",
      admissionSha256,
      authorityReceiptSha256: sha("4"),
      envelope,
      stopConditions: ["operator-stop", "unexpected-sensitive-data"]
    }
  });
  const prepareManagedAdapterInvocation = (input) => {
    const compiled = compileHttpxUrlFetch({ target: input.target, operation: input.operation, bounds: input });
    const runtime = {
      provider: "verified-release", version: "1.12.0", platform: "linux-x64",
      lockEntrySha256: sha("5"), catalogEntrySha256: sha("6"), artifactSha256: sha("7"), executableSha256: sha("8")
    };
    const binding = {
      id: "httpx-url-fetch", version: 1, registrySha256: sha("e"), entrySha256: sha("a"),
      compiler: { id: "httpx-exact-url-fetch-v1", source: "src/adapters/httpx-url-fetch.mjs", sourceSha256: sha("b") },
      selectorType: "url", action: "observe", effectClass: "A1", allowedPhases: ["active-surface-validation"],
      operation: compiled.typedOperation,
      operationSha256: labCampaignAuthorityInternals.canonicalSha256(compiled.typedOperation),
      argvSha256: labCampaignAuthorityInternals.canonicalSha256(compiled.argv),
      runtime,
      controls: compiled.controls,
      allowedFeatures: ["exact-url"],
      forbiddenFeatures: ["redirect"]
    };
    return {
      adapter: { tool: { id: "httpx" } },
      binding,
      compiled,
      normalized: {
        workflowId: input.workflowId,
        phaseAttemptId: input.phaseAttemptId,
        target: input.target,
        action: "observe",
        toolId: "httpx",
        argv: compiled.argv,
        targetArgIndex: 1,
        declaredBounds: {
          maxMinutes: input.maxMinutes,
          estimatedRequests: input.estimatedRequests,
          maxParallel: input.maxParallel,
          maxRatePerSecond: input.maxRatePerSecond,
          maxTokens: input.maxTokens,
          maxEvidenceBytes: input.maxEvidenceBytes
        }
      }
    };
  };
  const options = {
    paths,
    now: () => createdAt,
    loadCampaignContext: () => context,
    checkEngagement: engagementCheck,
    workflowStatus,
    prepareManagedAdapterInvocation
  };
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return {
    root, paths, createdAt, expiresAt, admissionFile, admissionSha256, destinationObservationFile,
    context, jobs, options, prepareManagedAdapterInvocation
  };
}

function setControllerStart(fixture, index = 0, authorityId = "hacker101-baseline") {
  const job = fixture.jobs[index];
  fixture.context.state.status = "running";
  fixture.context.state.jobs[index].status = "running";
  fixture.context.activeStart = {
    jobId: job.metadata.id,
    jobSha256: job.jobSha256,
    authorityId
  };
}

function cryptoSha(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function currentSourceSnapshot(fixture) {
  return {
    $schema: "https://gate.local/schemas/program-source-snapshot.schema.json",
    apiVersion: "gate.dev/program-source-snapshot/v1",
    kind: "ProgramSourceSnapshot",
    metadata: {
      programId: "hacker101",
      sourceId: "program-rules",
      revision: 1,
      capturedAt: fixture.createdAt,
      contentSha256: sha("b"),
      projectionSha256: sha("c"),
      snapshotSha256: sha("d"),
      bodyBytes: 12
    },
    source: {
      id: "program-rules",
      type: "program-rules",
      title: "Published challenge rules",
      reference: `private://program-sources/hacker101/program-rules/bodies/${sha("b")}.bin`,
      contentSha256: sha("b"),
      observedAt: fixture.createdAt,
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
      bodyRef: `private://program-sources/hacker101/program-rules/bodies/${sha("b")}.bin`
    },
    predecessor: null
  };
}

function proposal(fixture) {
  return createLabCampaignAuthority({
    authorityId: "hacker101-baseline",
    campaignId: "baseline-campaign",
    challengeOrigin: "https://ctf.example.test",
    frozenIps: ["192.0.2.10"],
    destinationObservationFile: fixture.destinationObservationFile,
    admissionFile: fixture.admissionFile,
    expiresAt: fixture.expiresAt
  }, fixture.options);
}

test("one exact confirmation authorizes an immutable repeated-request lab campaign", (t) => {
  const fixture = setup(t);
  const created = proposal(fixture);
  assert.equal(created.authority.binding.engagement.basis, "dedicated-lab");
  assert.equal(created.authority.binding.challenge.exactUrl, "https://ctf.example.test/levels/0");
  assert.deepEqual(created.authority.campaign.jobs.map((job) => job.id), ["fetch-1", "fetch-2"]);
  assert.match(created.confirmationRequired, /^AUTHORIZE LAB CAMPAIGN hacker101-baseline [a-f0-9]{64}$/u);
  const confirmed = confirmLabCampaignAuthority("hacker101-baseline", {
    confirm: created.confirmationRequired
  }, fixture.options);
  assert.equal(confirmed.confirmed, true);
  assert.equal(labCampaignAuthorityStatus("hacker101-baseline", fixture.options).status, "authorized");
  assert.throws(
    () => confirmLabCampaignAuthority("hacker101-baseline", { confirm: created.confirmationRequired }, fixture.options),
    /already confirmed/u
  );
});

test("confirmation is exact and dedicated-lab is mandatory", (t) => {
  const fixture = setup(t, { basis: "owner" });
  assert.throws(() => proposal(fixture), /authorization\.basis=dedicated-lab/u);

  const accepted = setup(t);
  const created = proposal(accepted);
  assert.throws(
    () => confirmLabCampaignAuthority("hacker101-baseline", { confirm: `${created.confirmationRequired} ` }, accepted.options),
    /must be exactly/u
  );
});

test("operator stop is exact, durable, and prevents later adaptive permits", async (t) => {
  const fixture = setup(t, { jobCount: 1 });
  const created = proposal(fixture);
  confirmLabCampaignAuthority("hacker101-baseline", {
    confirm: created.confirmationRequired
  }, fixture.options);
  const status = labCampaignAuthorityStatus("hacker101-baseline", fixture.options);
  assert.match(status.stopConfirmationRequired, /^STOP LAB CAMPAIGN hacker101-baseline [a-f0-9]{64}$/u);
  assert.throws(() => stopLabCampaignAuthority("hacker101-baseline", {
    confirm: `${status.stopConfirmationRequired} `
  }, fixture.options), /must be exactly/u);
  const stopped = stopLabCampaignAuthority("hacker101-baseline", {
    confirm: status.stopConfirmationRequired
  }, fixture.options);
  assert.equal(stopped.stopped, true);
  assert.equal(labCampaignAuthorityStatus("hacker101-baseline", fixture.options).status, "stopped");
  await assert.rejects(enqueueAuthorizedLabCampaignFetch("hacker101-baseline", {
    jobId: "fetch-after-stop",
    target: "https://ctf.example.test/levels/0/after-stop",
    allowedIp: "192.0.2.10",
    method: "GET"
  }, { ...fixture.options, enqueueLabCampaignJob: () => assert.fail("controller must not be called") }), /authority is stopped/u);
});

test("missing, empty, and receipt-inconsistent authority journals fail closed", async (t) => {
  const missing = setup(t, { jobCount: 1 });
  const missingCreated = proposal(missing);
  confirmLabCampaignAuthority("hacker101-baseline", {
    confirm: missingCreated.confirmationRequired
  }, missing.options);
  stopLabCampaignAuthority("hacker101-baseline", {
    confirm: labCampaignAuthorityInternals.exactStopConfirmation(missingCreated.authority)
  }, missing.options);
  const missingJournal = path.join(
    missing.paths.stateHome,
    "lab-campaign-authorities",
    "hacker101-baseline",
    "journal.jsonl"
  );
  fs.unlinkSync(missingJournal);
  assert.throws(
    () => labCampaignAuthorityStatus("hacker101-baseline", missing.options),
    /journal is missing and authority state is indeterminate/u
  );
  setControllerStart(missing);
  let brokerCalls = 0;
  await assert.rejects(
    dispatchAuthorizedLabCampaignJob("hacker101-baseline", missing.jobs[0], {
      ...missing.options,
      createManagedExecutionManifest: () => { brokerCalls += 1; },
      executeExecutionManifest: async () => { brokerCalls += 1; }
    }),
    /journal is missing and authority state is indeterminate/u
  );
  assert.equal(brokerCalls, 0);

  const empty = setup(t, { jobCount: 1 });
  const emptyCreated = proposal(empty);
  confirmLabCampaignAuthority("hacker101-baseline", {
    confirm: emptyCreated.confirmationRequired
  }, empty.options);
  const emptyJournal = path.join(
    empty.paths.stateHome,
    "lab-campaign-authorities",
    "hacker101-baseline",
    "journal.jsonl"
  );
  fs.writeFileSync(emptyJournal, "", { mode: 0o600 });
  assert.throws(
    () => labCampaignAuthorityStatus("hacker101-baseline", empty.options),
    /journal is empty and authority state is indeterminate/u
  );

  const prefix = setup(t, { jobCount: 1 });
  const prefixCreated = proposal(prefix);
  confirmLabCampaignAuthority("hacker101-baseline", {
    confirm: prefixCreated.confirmationRequired
  }, prefix.options);
  const prefixJournal = path.join(
    prefix.paths.stateHome,
    "lab-campaign-authorities",
    "hacker101-baseline",
    "journal.jsonl"
  );
  const createdLine = fs.readFileSync(prefixJournal, "utf8").split("\n")[0];
  fs.writeFileSync(prefixJournal, `${createdLine}\n`, { encoding: "utf8", mode: 0o600 });
  assert.throws(
    () => labCampaignAuthorityStatus("hacker101-baseline", prefix.options),
    /missing its exact bound authority-confirmed prefix/u
  );
});

test("cross-origin jobs cannot be lifted into a lab campaign authority", (t) => {
  const fixture = setup(t, { crossOrigin: true, jobCount: 1 });
  fixture.context.grant.allow.selectors = [{ type: "url", value: "https://other.example.test/levels/0" }];
  fixture.context.grant.grantSha256 = labCampaignAuthorityInternals.grantDigest(fixture.context.grant);
  fixture.jobs[0].grantSha256 = fixture.context.grant.grantSha256;
  fixture.jobs[0].jobSha256 = labCampaignAuthorityInternals.jobDigest(fixture.jobs[0]);
  fixture.context.state.grantSha256 = fixture.context.grant.grantSha256;
  fixture.context.state.jobs[0].jobSha256 = fixture.jobs[0].jobSha256;
  assert.throws(() => proposal(fixture), /differs from the exact active workflow admission|leaves the exact challenge origin/u);
});

test("confirmed authority derives one-shot capabilities and keeps broker confirmation internal", async (t) => {
  const fixture = setup(t);
  const created = proposal(fixture);
  confirmLabCampaignAuthority("hacker101-baseline", { confirm: created.confirmationRequired }, fixture.options);
  setControllerStart(fixture);
  let executions = 0;
  let labCampaign;
  let preparedForExecution;
  const dispatchOptions = {
    ...fixture.options,
    createManagedExecutionManifest: (_engagementId, input) => {
      const prepared = fixture.prepareManagedAdapterInvocation(input);
      const preparedExpected = {
        engagementId: _engagementId,
        target: prepared.normalized.target,
        action: prepared.normalized.action,
        toolId: prepared.normalized.toolId,
        adapterId: prepared.binding.id,
        operationSha256: prepared.binding.operationSha256,
        argvSha256: prepared.binding.argvSha256,
        workflowId: prepared.normalized.workflowId,
        phaseAttemptId: prepared.normalized.phaseAttemptId,
        declaredBounds: prepared.normalized.declaredBounds,
        adapterBinding: prepared.binding
      };
      assert.throws(() => verifyLabCampaignExecutionCapability(input.labCampaignCapability, {
        ...preparedExpected,
        declaredBounds: { ...preparedExpected.declaredBounds, maxMinutes: preparedExpected.declaredBounds.maxMinutes + 1 }
      }, fixture.options), /bounds or reviewed adapter binding differs/u);
      labCampaign = verifyLabCampaignExecutionCapability(input.labCampaignCapability, preparedExpected, fixture.options);
      preparedForExecution = prepared;
      verifyLabCampaignWorkflowReservation(labCampaign, {
        engagementId: "hacker101-lab",
        workflowInstanceId: "pilot-workflow",
        phaseId: "active-surface-validation",
        phaseAttemptId: `wpa_${"1".repeat(32)}`,
        admissionSha256: fixture.admissionSha256,
        authorityReceiptSha256: sha("4"),
        target: input.target,
        targetSha256: cryptoSha(Buffer.from(input.target)),
        action: "observe",
        toolId: "httpx",
        envelope: {
          maxMinutes: 2, maxRequests: 1, maxRatePerSecond: 2, maxParallel: 1,
          maxInputTokens: 0, maxOutputTokens: 0, maxTotalTokens: 1000,
          maxEvidenceBytes: 2 * 1024 * 1024, maxSpend: 0
        },
        requireUnbound: true
      }, fixture.options);
      const manifestId = `xmf_${"a".repeat(32)}`;
      const manifestSha256 = "c".repeat(64);
      return {
        ok: true,
        manifestId,
        manifestSha256,
        expiresAt: fixture.expiresAt,
        confirmationRequired: `EXECUTE ${manifestId} ${manifestSha256} UNMETERED`,
        operation: { targetArgument: input.target, adapter: prepared.binding, argv: prepared.compiled.argv },
        declaredBounds: prepared.normalized.declaredBounds,
        labCampaign,
        workflow: {
          instanceId: "pilot-workflow",
          phaseId: "active-surface-validation",
          phaseAttemptId: `wpa_${"1".repeat(32)}`,
          admissionSha256: fixture.admissionSha256,
          authorityReceiptSha256: sha("4"),
          definitionSha256: sha("f"),
          reservationId: `wxr_${"2".repeat(32)}`
        }
      };
    },
    executeExecutionManifest: async (_engagementId, input) => {
      executions += 1;
      assert.equal(input.confirm, `EXECUTE xmf_${"a".repeat(32)} ${"c".repeat(64)} UNMETERED`);
      verifyLabCampaignExecutionCapability(labCampaign, {
        engagementId: _engagementId,
        target: preparedForExecution.normalized.target,
        action: preparedForExecution.normalized.action,
        toolId: preparedForExecution.normalized.toolId,
        adapterId: preparedForExecution.binding.id,
        operationSha256: preparedForExecution.binding.operationSha256,
        argvSha256: preparedForExecution.binding.argvSha256,
        workflowId: preparedForExecution.normalized.workflowId,
        phaseAttemptId: preparedForExecution.normalized.phaseAttemptId,
        declaredBounds: preparedForExecution.normalized.declaredBounds,
        adapterBinding: preparedForExecution.binding,
        manifestId: `xmf_${"a".repeat(32)}`,
        manifestSha256: "c".repeat(64)
      }, fixture.options);
      return {
        ok: true,
        status: "succeeded",
        runId: `xrun_${"b".repeat(32)}`,
        durationMs: 25,
        evidence: {
          stdout: { bytes: 120 }, stderr: { bytes: 0 }, resultAvailable: false,
          resultRef: `private://evidence/execution-xrun_${"b".repeat(32)}-result.json`
        },
        adapterOutput: {
          ok: true,
          status: "observed",
          metrics: {
            requestCount: 1, method: "GET", statusCode: 200, responseBodyBytes: 64,
            responseContentLength: 64, rateLimitPerSecond: 2, redirectsFollowed: 0,
            redirectStatus: "not-followed", retries: 0, backoffStatus: "disabled-no-retries"
          }
        }
      };
    }
  };
  const result = await dispatchAuthorizedLabCampaignJob("hacker101-baseline", fixture.jobs[0], dispatchOptions);
  assert.equal(result.ok, true);
  assert.equal(result.metrics.requests, 1);
  assert.equal(result.metrics.evidenceBytes, 120);
  assert.equal(executions, 1);
  assert.equal(
    fs.readFileSync(path.join(fixture.paths.stateHome, "lab-campaign-authorities", "hacker101-baseline", "journal.jsonl"), "utf8").includes("response body"),
    false
  );
  await assert.rejects(
    dispatchAuthorizedLabCampaignJob("hacker101-baseline", fixture.jobs[0], dispatchOptions),
    /already consumed/u
  );
  const status = labCampaignAuthorityStatus("hacker101-baseline", fixture.options);
  assert.equal(status.jobs.completed, 1);
  assert.equal(status.usage.requests, 1);
});

test("real campaign worker path starts, authority-dispatches, and finalizes one managed HTTP job", async (t) => {
  const fixture = setup(t, { jobCount: 1 });
  const source = currentSourceSnapshot(fixture);
  const controllerOptions = {
    ...fixture.options,
    readCurrentProgramProfileBinding: () => ({
      id: "hacker101",
      profileSha256: sha("a"),
      sources: [{ id: "program-rules", contentSha256: sha("b") }]
    }),
    readCurrentProgramSource: () => structuredClone(source)
  };
  const createdCampaign = createCampaign({
    id: "baseline-campaign",
    expiresAt: fixture.expiresAt,
    source: {
      id: "program-rules",
      contentSha256: sha("b"),
      projectionSha256: sha("c"),
      snapshotSha256: sha("d")
    },
    engagementId: "hacker101-lab",
    operations: [{ adapterId: "httpx-url-fetch", action: "observe", toolId: "httpx" }],
    selectors: [{ type: "url", value: "https://ctf.example.test/levels/0" }],
    environment: "host",
    ceilings: structuredClone(fixture.context.grant.ceilings),
    jobs: [{ id: "fetch-1", ...structuredClone(fixture.jobs[0].job) }]
  }, controllerOptions);
  const loadCampaignContext = (id, supplied = {}) => campaignInternals.loadCampaignContext(id, {
    ...controllerOptions,
    ...supplied,
    paths: fixture.paths,
    readCurrentProgramProfileBinding: controllerOptions.readCurrentProgramProfileBinding,
    readCurrentProgramSource: controllerOptions.readCurrentProgramSource
  });
  const prepareManagedAdapterInvocation = (input) => {
    const prepared = fixture.prepareManagedAdapterInvocation(input);
    prepared.binding.registrySha256 = createdCampaign.grant.allow.adapterRegistrySha256;
    return prepared;
  };
  const authorityOptions = {
    ...controllerOptions,
    loadCampaignContext,
    prepareManagedAdapterInvocation
  };
  const created = proposal({ ...fixture, options: authorityOptions });
  confirmLabCampaignAuthority("hacker101-baseline", {
    confirm: created.confirmationRequired
  }, authorityOptions);
  const alternate = createLabCampaignAuthority({
    authorityId: "hacker101-alternate",
    campaignId: "baseline-campaign",
    challengeOrigin: "https://ctf.example.test",
    frozenIps: ["192.0.2.10"],
    destinationObservationFile: fixture.destinationObservationFile,
    admissionFile: fixture.admissionFile,
    expiresAt: fixture.expiresAt
  }, authorityOptions);
  confirmLabCampaignAuthority("hacker101-alternate", {
    confirm: alternate.confirmationRequired
  }, authorityOptions);
  resumeCampaign("baseline-campaign", controllerOptions);

  let preparedForExecution;
  let capabilityContext;
  let executions = 0;
  let alternateManifestCreates = 0;
  const result = await runNextCampaignWorkerJob("baseline-campaign", {
    ...authorityOptions,
    labAuthorityId: "hacker101-baseline",
    dispatchAuthorizedLabCampaignJob: async (authorityId, job, dispatchOptions) => {
      await assert.rejects(
        dispatchAuthorizedLabCampaignJob("hacker101-alternate", job, {
          ...dispatchOptions,
          createManagedExecutionManifest: () => { alternateManifestCreates += 1; }
        }),
        /active start binding differs from the exact lab authority and job/u
      );
      assert.equal(alternateManifestCreates, 0, "the wrong authority must be rejected before manifest creation");
      return dispatchAuthorizedLabCampaignJob(authorityId, job, dispatchOptions);
    },
    createManagedExecutionManifest: (engagementId, input) => {
      const prepared = prepareManagedAdapterInvocation(input);
      preparedForExecution = prepared;
      capabilityContext = verifyLabCampaignExecutionCapability(input.labCampaignCapability, {
        engagementId,
        target: prepared.normalized.target,
        action: prepared.normalized.action,
        toolId: prepared.normalized.toolId,
        adapterId: prepared.binding.id,
        operationSha256: prepared.binding.operationSha256,
        argvSha256: prepared.binding.argvSha256,
        workflowId: prepared.normalized.workflowId,
        phaseAttemptId: prepared.normalized.phaseAttemptId,
        declaredBounds: prepared.normalized.declaredBounds,
        adapterBinding: prepared.binding
      }, authorityOptions);
      const manifestId = `xmf_${"3".repeat(32)}`;
      const manifestSha256 = sha("4");
      return {
        ok: true,
        manifestId,
        manifestSha256,
        expiresAt: fixture.expiresAt,
        confirmationRequired: `EXECUTE ${manifestId} ${manifestSha256} UNMETERED`,
        operation: { targetArgument: input.target, adapter: prepared.binding, argv: prepared.compiled.argv },
        declaredBounds: prepared.normalized.declaredBounds,
        labCampaign: capabilityContext,
        workflow: {
          instanceId: "pilot-workflow",
          phaseId: "active-surface-validation",
          phaseAttemptId: `wpa_${"1".repeat(32)}`,
          admissionSha256: fixture.admissionSha256,
          authorityReceiptSha256: sha("4"),
          definitionSha256: sha("f"),
          reservationId: `wxr_${"5".repeat(32)}`
        }
      };
    },
    executeExecutionManifest: async (engagementId, input) => {
      executions += 1;
      assert.equal(input.confirm, `EXECUTE xmf_${"3".repeat(32)} ${sha("4")} UNMETERED`);
      verifyLabCampaignExecutionCapability(capabilityContext, {
        engagementId,
        target: preparedForExecution.normalized.target,
        action: preparedForExecution.normalized.action,
        toolId: preparedForExecution.normalized.toolId,
        adapterId: preparedForExecution.binding.id,
        operationSha256: preparedForExecution.binding.operationSha256,
        argvSha256: preparedForExecution.binding.argvSha256,
        workflowId: preparedForExecution.normalized.workflowId,
        phaseAttemptId: preparedForExecution.normalized.phaseAttemptId,
        declaredBounds: preparedForExecution.normalized.declaredBounds,
        adapterBinding: preparedForExecution.binding,
        manifestId: `xmf_${"3".repeat(32)}`,
        manifestSha256: sha("4")
      }, authorityOptions);
      return {
        ok: true,
        status: "succeeded",
        runId: `xrun_${"6".repeat(32)}`,
        durationMs: 20,
        evidence: { stdout: { bytes: 96 }, stderr: { bytes: 0 }, resultAvailable: false },
        adapterOutput: {
          ok: true,
          status: "observed",
          metrics: {
            requestCount: 1,
            method: "GET",
            statusCode: 200,
            responseBodyBytes: 48,
            responseContentLength: 48,
            rateLimitPerSecond: 2,
            redirectsFollowed: 0,
            redirectStatus: "not-followed",
            retries: 0,
            backoffStatus: "disabled-no-retries"
          }
        }
      };
    }
  });
  assert.equal(executions, 1);
  assert.equal(alternateManifestCreates, 0);
  assert.equal(result.ok, true);
  assert.equal(result.state.status, "completed");
  assert.equal(result.state.queue.completed, 1);
  assert.equal(result.state.usage.observed.requests.value, 1);
  assert.equal(labCampaignAuthorityStatus("hacker101-baseline", authorityOptions).jobs.completed, 1);
  const campaignJournal = fs.readFileSync(
    campaignInternals.campaignPaths(fixture.paths, "baseline-campaign").journal,
    "utf8"
  ).trim().split(/\r?\n/u).map(JSON.parse);
  assert.equal(campaignJournal.find((entry) => entry.type === "job-started").payload.authorityId, "hacker101-baseline");
  assert.deepEqual(campaignJournal.slice(-3).map((entry) => entry.type), [
    "job-started",
    "job-completed",
    "campaign-completed"
  ]);
});

test("a started request without a terminal record blocks every later dispatch", async (t) => {
  const fixture = setup(t, { jobCount: 2 });
  const created = proposal(fixture);
  assert.equal(created.authority.ceilings.maxConcurrency, 1);
  confirmLabCampaignAuthority("hacker101-baseline", { confirm: created.confirmationRequired }, fixture.options);
  setControllerStart(fixture);

  let manifestCreates = 0;
  let prepared;
  const manifestId = `xmf_${"7".repeat(32)}`;
  const manifestSha256 = "8".repeat(64);
  const broker = {
    ...fixture.options,
    createManagedExecutionManifest: (engagementId, input) => {
      manifestCreates += 1;
      assert.equal(manifestCreates, 1, "a later unresolved request must be rejected before manifest creation");
      prepared = fixture.prepareManagedAdapterInvocation(input);
      const labCampaign = verifyLabCampaignExecutionCapability(input.labCampaignCapability, {
        engagementId,
        target: prepared.normalized.target,
        action: prepared.normalized.action,
        toolId: prepared.normalized.toolId,
        adapterId: prepared.binding.id,
        operationSha256: prepared.binding.operationSha256,
        argvSha256: prepared.binding.argvSha256,
        workflowId: prepared.normalized.workflowId,
        phaseAttemptId: prepared.normalized.phaseAttemptId,
        declaredBounds: prepared.normalized.declaredBounds,
        adapterBinding: prepared.binding
      }, fixture.options);
      return {
        ok: true,
        manifestId,
        manifestSha256,
        expiresAt: fixture.expiresAt,
        confirmationRequired: `EXECUTE ${manifestId} ${manifestSha256} UNMETERED`,
        operation: { targetArgument: input.target, adapter: prepared.binding, argv: prepared.compiled.argv },
        declaredBounds: prepared.normalized.declaredBounds,
        labCampaign,
        workflow: {
          instanceId: "pilot-workflow",
          phaseId: "active-surface-validation",
          phaseAttemptId: `wpa_${"1".repeat(32)}`,
          admissionSha256: fixture.admissionSha256,
          authorityReceiptSha256: sha("4"),
          definitionSha256: sha("f"),
          reservationId: `wxr_${"7".repeat(32)}`
        }
      };
    },
    executeExecutionManifest: async () => {
      await assert.rejects(
        dispatchAuthorizedLabCampaignJob("hacker101-baseline", fixture.jobs[0], broker),
        /unresolved started request that requires execution reconciliation/u
      );
      return {
        ok: true,
        status: "succeeded",
        runId: `xrun_${"7".repeat(32)}`,
        durationMs: 1,
        evidence: { stdout: { bytes: 0 }, stderr: { bytes: 0 }, resultAvailable: false },
        adapterOutput: {
          ok: true,
          status: "observed",
          metrics: {
            requestCount: 1,
            method: prepared.binding.operation.method,
            statusCode: 200,
            responseBodyBytes: 0,
            responseContentLength: 0,
            rateLimitPerSecond: 2,
            redirectsFollowed: 0,
            redirectStatus: "not-followed",
            retries: 0,
            backoffStatus: "disabled-no-retries"
          }
        }
      };
    }
  };

  const result = await dispatchAuthorizedLabCampaignJob("hacker101-baseline", fixture.jobs[0], broker);
  assert.equal(result.ok, true);
  assert.equal(manifestCreates, 1);
});

test("redirect observations stop the authority without following them", async (t) => {
  const fixture = setup(t, { jobCount: 1 });
  const created = proposal(fixture);
  confirmLabCampaignAuthority("hacker101-baseline", { confirm: created.confirmationRequired }, fixture.options);
  setControllerStart(fixture);
  const prepared = fixture.prepareManagedAdapterInvocation({
    adapterId: "httpx-url-fetch",
    workflowId: fixture.jobs[0].job.workflow.instanceId,
    phaseAttemptId: fixture.jobs[0].job.workflow.phaseAttemptId,
    target: fixture.jobs[0].job.selector.value,
    operation: fixture.jobs[0].job.operation,
    ...fixture.jobs[0].job.bounds
  });
  const manifestId = `xmf_${"d".repeat(32)}`;
  const manifestSha256 = "e".repeat(64);
  const result = await dispatchAuthorizedLabCampaignJob("hacker101-baseline", fixture.jobs[0], {
    ...fixture.options,
    createManagedExecutionManifest: (_engagementId, input) => {
      const labCampaign = verifyLabCampaignExecutionCapability(input.labCampaignCapability, {
        engagementId: _engagementId,
        target: prepared.normalized.target,
        action: prepared.normalized.action,
        toolId: prepared.normalized.toolId,
        adapterId: prepared.binding.id,
        operationSha256: prepared.binding.operationSha256,
        argvSha256: prepared.binding.argvSha256,
        workflowId: prepared.normalized.workflowId,
        phaseAttemptId: prepared.normalized.phaseAttemptId,
        declaredBounds: prepared.normalized.declaredBounds,
        adapterBinding: prepared.binding
      }, fixture.options);
      return {
        ok: true, manifestId, manifestSha256,
        expiresAt: fixture.expiresAt,
        confirmationRequired: `EXECUTE ${manifestId} ${manifestSha256} UNMETERED`,
        operation: { targetArgument: fixture.jobs[0].job.selector.value, adapter: prepared.binding, argv: prepared.compiled.argv },
        declaredBounds: prepared.normalized.declaredBounds,
        labCampaign,
        workflow: {
          instanceId: "pilot-workflow", phaseId: "active-surface-validation",
          phaseAttemptId: `wpa_${"1".repeat(32)}`, admissionSha256: fixture.admissionSha256,
          authorityReceiptSha256: sha("4"), definitionSha256: sha("f"), reservationId: `wxr_${"3".repeat(32)}`
        }
      };
    },
    executeExecutionManifest: async () => ({
      ok: true, status: "succeeded", runId: `xrun_${"e".repeat(32)}`, durationMs: 10,
      evidence: { stdout: { bytes: 80 }, stderr: { bytes: 0 }, resultAvailable: false },
      adapterOutput: {
        ok: true,
        status: "observed",
        metrics: {
          requestCount: 1, method: "GET", statusCode: 302, responseBodyBytes: 0,
          responseContentLength: 0, rateLimitPerSecond: 2, redirectsFollowed: 0,
          redirectStatus: "not-followed", retries: 0, backoffStatus: "disabled-no-retries"
        }
      }
    })
  });
  assert.equal(result.ok, false);
  assert.equal(result.stopCondition, "redirect-observed");
  assert.equal(labCampaignAuthorityStatus("hacker101-baseline", fixture.options).status, "stopped");
});

test("adaptive enqueue admits only a bounded same-origin child path", async (t) => {
  const fixture = setup(t, { jobCount: 1 });
  const created = proposal(fixture);
  confirmLabCampaignAuthority("hacker101-baseline", { confirm: created.confirmationRequired }, fixture.options);
  const enqueueLabCampaignJob = (campaignId, input, options) => {
    assert.equal(campaignId, "baseline-campaign");
    assert.equal(input.authorityId, "hacker101-baseline");
    const permit = options.verifyLabEnqueue(input.authorityId, input.job, {
      paths: fixture.paths,
      campaignId,
      grantSha256: fixture.context.grant.grantSha256
    });
    assert.equal(permit.jobId, input.job.metadata.id);
    assert.equal(permit.jobSha256, input.job.jobSha256);
    fixture.context.jobs.push(structuredClone(input.job));
    fixture.context.state.jobs.push({
      id: input.job.metadata.id,
      jobSha256: input.job.jobSha256,
      status: "queued"
    });
    return { ok: true, campaignId, jobId: input.job.metadata.id, permitSha256: permit.permitSha256 };
  };
  const accepted = await enqueueAuthorizedLabCampaignFetch("hacker101-baseline", {
    jobId: "fetch-child",
    target: "https://ctf.example.test/levels/0/assets/app.js",
    allowedIp: "192.0.2.10",
    method: "GET"
  }, { ...fixture.options, enqueueLabCampaignJob });
  assert.equal(accepted.ok, true);
  assert.equal(accepted.permit.origin, "https://ctf.example.test");
  assert.equal(accepted.permit.pathPrefix, "/levels/0");
  assert.equal(accepted.permit.jobId, "fetch-child");
  await assert.rejects(enqueueAuthorizedLabCampaignFetch("hacker101-baseline", {
    jobId: "fetch-controller-rejected",
    target: "https://ctf.example.test/levels/0/rejected.js",
    allowedIp: "192.0.2.10",
    method: "GET"
  }, {
    ...fixture.options,
    enqueueLabCampaignJob: () => { throw new Error("controller rejected before commit"); }
  }), /controller rejected before commit/u);
  const afterControllerRejection = labCampaignAuthorityStatus("hacker101-baseline", fixture.options);
  assert.deepEqual({
    total: afterControllerRejection.jobs.total,
    dynamic: afterControllerRejection.jobs.dynamic,
    pending: afterControllerRejection.jobs.pending
  }, { total: 2, dynamic: 1, pending: 1 });
  await assert.rejects(enqueueAuthorizedLabCampaignFetch("hacker101-baseline", {
    jobId: "fetch-sibling",
    target: "https://ctf.example.test/levels/01",
    allowedIp: "192.0.2.10",
    method: "GET"
  }, { ...fixture.options, enqueueLabCampaignJob }), /outside the immutable campaign grant|path prefix/u);
});

test("adaptive authority and the real campaign controller commit the same immutable job and permit", async (t) => {
  const fixture = setup(t, { jobCount: 1 });
  const source = currentSourceSnapshot(fixture);
  const controllerOptions = {
    ...fixture.options,
    readCurrentProgramProfileBinding: () => ({
      id: "hacker101",
      profileSha256: sha("a"),
      sources: [{ id: "program-rules", contentSha256: sha("b") }]
    }),
    readCurrentProgramSource: () => structuredClone(source)
  };
  const createdCampaign = createCampaign({
    id: "baseline-campaign",
    expiresAt: fixture.expiresAt,
    source: {
      id: "program-rules",
      contentSha256: sha("b"),
      projectionSha256: sha("c"),
      snapshotSha256: sha("d")
    },
    engagementId: "hacker101-lab",
    operations: [{ adapterId: "httpx-url-fetch", action: "observe", toolId: "httpx" }],
    selectors: [{ type: "url", value: "https://ctf.example.test/levels/0" }],
    environment: "host",
    ceilings: structuredClone(fixture.context.grant.ceilings),
    jobs: [{ id: "fetch-1", ...structuredClone(fixture.jobs[0].job) }]
  }, controllerOptions);
  const loadCampaignContext = (id, supplied = {}) => campaignInternals.loadCampaignContext(id, {
    ...controllerOptions,
    ...supplied,
    paths: fixture.paths,
    readCurrentProgramProfileBinding: controllerOptions.readCurrentProgramProfileBinding,
    readCurrentProgramSource: controllerOptions.readCurrentProgramSource
  });
  const basePrepare = fixture.prepareManagedAdapterInvocation;
  const prepareManagedAdapterInvocation = (input) => {
    const prepared = basePrepare(input);
    prepared.binding.registrySha256 = createdCampaign.grant.allow.adapterRegistrySha256;
    return prepared;
  };
  const authorityOptions = {
    ...controllerOptions,
    loadCampaignContext,
    prepareManagedAdapterInvocation
  };
  const created = proposal({ ...fixture, options: authorityOptions });
  confirmLabCampaignAuthority("hacker101-baseline", {
    confirm: created.confirmationRequired
  }, authorityOptions);

  const adaptiveInput = {
    jobId: "fetch-real-child",
    target: "https://ctf.example.test/levels/0/assets/app.js",
    allowedIp: "192.0.2.10",
    method: "GET"
  };
  await assert.rejects(enqueueAuthorizedLabCampaignFetch("hacker101-baseline", adaptiveInput, {
    ...authorityOptions,
    enqueueLabCampaignJob: (...args) => {
      enqueueLabCampaignJob(...args);
      throw new Error("simulated crash after controller commit");
    }
  }), /simulated crash after controller commit/u);

  const pending = labCampaignAuthorityStatus("hacker101-baseline", authorityOptions);
  assert.deepEqual(
    { total: pending.jobs.total, dynamic: pending.jobs.dynamic, pending: pending.jobs.pending },
    { total: 1, dynamic: 0, pending: 1 }
  );

  const controller = campaignStatus("baseline-campaign", controllerOptions);
  assert.equal(controller.state.queue.total, 2);
  const committedJobSha256 = controller.state.jobs.find((job) => job.id === "fetch-real-child").jobSha256;
  const campaignJournalFile = campaignInternals.campaignPaths(fixture.paths, "baseline-campaign").journal;
  const secondary = createLabCampaignAuthority({
    authorityId: "hacker101-secondary",
    campaignId: "baseline-campaign",
    challengeOrigin: "https://ctf.example.test",
    frozenIps: ["192.0.2.10"],
    destinationObservationFile: fixture.destinationObservationFile,
    admissionFile: fixture.admissionFile,
    expiresAt: fixture.expiresAt
  }, authorityOptions);
  confirmLabCampaignAuthority("hacker101-secondary", {
    confirm: secondary.confirmationRequired
  }, authorityOptions);
  const secondaryEnqueue = await enqueueAuthorizedLabCampaignFetch("hacker101-secondary", {
    jobId: "fetch-secondary-child",
    target: "https://ctf.example.test/levels/0/secondary.js",
    allowedIp: "192.0.2.10",
    method: "HEAD"
  }, { ...authorityOptions, enqueueLabCampaignJob });
  assert.equal(secondaryEnqueue.controller.reconciled, false);
  assert.equal(campaignStatus("baseline-campaign", controllerOptions).state.queue.total, 3);
  const campaignJournalEntries = fs.readFileSync(campaignJournalFile, "utf8").trim().split(/\r?\n/u).length;

  const expiredAuthorityOptions = {
    ...authorityOptions,
    now: () => Date.parse(fixture.expiresAt) + 1
  };
  const accepted = await enqueueAuthorizedLabCampaignFetch("hacker101-baseline", adaptiveInput, {
    ...expiredAuthorityOptions,
    enqueueLabCampaignJob
  });
  assert.equal(accepted.ok, true);
  assert.equal(accepted.controller.reconciled, true);
  assert.equal(accepted.permit.pathPrefix, "/levels/0");
  assert.equal(accepted.controller.job.id, "fetch-real-child");
  assert.equal(accepted.controller.job.jobSha256, committedJobSha256);
  assert.equal(accepted.controller.authority.permitSha256, accepted.permit.permitSha256);
  assert.equal(
    fs.readFileSync(campaignJournalFile, "utf8").trim().split(/\r?\n/u).length,
    campaignJournalEntries
  );
  const reconciledStatus = labCampaignAuthorityStatus("hacker101-baseline", authorityOptions);
  assert.equal(reconciledStatus.status, "authorized");
  assert.deepEqual(
    { total: reconciledStatus.jobs.total, dynamic: reconciledStatus.jobs.dynamic, pending: reconciledStatus.jobs.pending },
    { total: 2, dynamic: 1, pending: 0 }
  );

  let controllerCalls = 0;
  await assert.rejects(enqueueAuthorizedLabCampaignFetch("hacker101-baseline", {
    ...adaptiveInput,
    jobId: "fetch-after-expired-commit",
    target: "https://ctf.example.test/levels/0/expired.js"
  }, {
    ...expiredAuthorityOptions,
    enqueueLabCampaignJob: () => { controllerCalls += 1; }
  }), /authority expired/u);
  assert.equal(controllerCalls, 0);

  const authorityJournalFile = path.join(
    fixture.paths.stateHome,
    "lab-campaign-authorities",
    "hacker101-baseline",
    "journal.jsonl"
  );
  const beforeStopJournal = fs.readFileSync(authorityJournalFile, "utf8").trim().split(/\r?\n/u).map(JSON.parse);
  assert.equal(beforeStopJournal.at(-1).type, "dynamic-job-enqueued");
  assert.equal(beforeStopJournal.at(-1).payload.permitSha256, accepted.permit.permitSha256);

  stopLabCampaignAuthority("hacker101-baseline", {
    confirm: pending.stopConfirmationRequired
  }, expiredAuthorityOptions);
  const stoppedJournalEntries = fs.readFileSync(authorityJournalFile, "utf8").trim().split(/\r?\n/u).length;

  const retried = await enqueueAuthorizedLabCampaignFetch("hacker101-baseline", adaptiveInput, {
    ...expiredAuthorityOptions,
    enqueueLabCampaignJob
  });
  assert.equal(retried.controller.reconciled, true);
  assert.equal(retried.job.jobSha256, accepted.job.jobSha256);
  assert.equal(
    fs.readFileSync(campaignJournalFile, "utf8").trim().split(/\r?\n/u).length,
    campaignJournalEntries
  );
  assert.equal(
    fs.readFileSync(authorityJournalFile, "utf8").trim().split(/\r?\n/u).length,
    stoppedJournalEntries
  );
  assert.equal(labCampaignAuthorityStatus("hacker101-baseline", expiredAuthorityOptions).status, "stopped");

  await assert.rejects(enqueueAuthorizedLabCampaignFetch("hacker101-baseline", {
    ...adaptiveInput,
    jobId: "fetch-after-stopped-commit",
    target: "https://ctf.example.test/levels/0/next.js"
  }, {
    ...expiredAuthorityOptions,
    enqueueLabCampaignJob: () => { controllerCalls += 1; }
  }), /authority is stopped/u);
  assert.equal(controllerCalls, 0);
});

test("a provably dead authority lock is recovered without weakening malformed-lock failure", (t) => {
  const fixture = setup(t, { jobCount: 1 });
  const created = proposal(fixture);
  const directory = path.join(
    fixture.paths.stateHome,
    "lab-campaign-authorities",
    "hacker101-baseline"
  );
  const bootId = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim().toLowerCase();
  fs.writeFileSync(path.join(directory, ".authority.lock"), `${JSON.stringify({
    apiVersion: "gate.lab-campaign-lock/v1",
    pid: 2_147_483_647,
    bootId,
    startTimeTicks: "1",
    nonce: "a".repeat(32),
    createdAt: fixture.createdAt
  })}\n`, { mode: 0o600 });
  const serializationFile = path.join(directory, ".authority.serialization");
  const serializationDescriptor = fs.openSync(
    serializationFile,
    fs.constants.O_CREAT | fs.constants.O_RDWR | fs.constants.O_NOFOLLOW,
    0o600
  );
  const held = spawnSync(
    "/usr/bin/flock",
    ["--exclusive", "3"],
    { stdio: ["ignore", "pipe", "pipe", serializationDescriptor] }
  );
  assert.equal(held.status, 0);
  try {
    assert.throws(() => confirmLabCampaignAuthority("hacker101-baseline", {
      confirm: created.confirmationRequired
    }, fixture.options), /serialization is active or indeterminate/u);
    assert.equal(fs.existsSync(path.join(directory, ".authority.lock")), true);
  } finally {
    fs.closeSync(serializationDescriptor);
  }
  assert.equal(confirmLabCampaignAuthority("hacker101-baseline", {
    confirm: created.confirmationRequired
  }, fixture.options).confirmed, true);

  const malformed = setup(t, { jobCount: 1 });
  const malformedCreated = proposal(malformed);
  const malformedDirectory = path.join(
    malformed.paths.stateHome,
    "lab-campaign-authorities",
    "hacker101-baseline"
  );
  fs.writeFileSync(path.join(malformedDirectory, ".authority.lock"), "{}\n", { mode: 0o600 });
  assert.throws(() => confirmLabCampaignAuthority("hacker101-baseline", {
    confirm: malformedCreated.confirmationRequired
  }, malformed.options), /malformed and requires reviewed recovery/u);
});

test("orphan claim recovery remains stopped after a crash during retirement", async (t) => {
  const fixture = setup(t, { jobCount: 1 });
  const created = proposal(fixture);
  confirmLabCampaignAuthority("hacker101-baseline", { confirm: created.confirmationRequired }, fixture.options);
  setControllerStart(fixture);
  const write = fs.writeFileSync;
  t.mock.method(fs, "writeFileSync", (...args) => {
    if (typeof args[1] === "string" && args[1].startsWith("{")) {
      const record = JSON.parse(args[1]);
      if (record.type === "capability-issued") throw new Error("crash after capability claim");
    }
    return write(...args);
  });
  await assert.rejects(dispatchAuthorizedLabCampaignJob("hacker101-baseline", fixture.jobs[0], fixture.options), /crash after capability claim/u);
  t.mock.restoreAll();
  t.mock.method(fs, "writeFileSync", (...args) => {
    const result = write(...args);
    if (typeof args[1] === "string" && args[1].startsWith("{") && JSON.parse(args[1]).type === "request-failed") {
      throw new Error("crash after retirement append");
    }
    return result;
  });
  assert.throws(() => recoverLabCampaignAuthority("hacker101-baseline", {
    confirm: labCampaignAuthorityInternals.exactRecoveryConfirmation(created.authority)
  }, fixture.options), /crash after retirement append/u);
  t.mock.restoreAll();
  assert.equal(labCampaignAuthorityStatus("hacker101-baseline", fixture.options).status, "stopped");
  await assert.rejects(dispatchAuthorizedLabCampaignJob("hacker101-baseline", fixture.jobs[0], fixture.options), /stopped/u);
});

test("reviewed recovery quarantines a torn journal tail and restores a missing delimiter", (t) => {
  const torn = setup(t, { jobCount: 1 });
  const tornCreated = proposal(torn);
  confirmLabCampaignAuthority("hacker101-baseline", {
    confirm: tornCreated.confirmationRequired
  }, torn.options);
  const tornDirectory = path.join(
    torn.paths.stateHome,
    "lab-campaign-authorities",
    "hacker101-baseline"
  );
  const tornJournal = path.join(tornDirectory, "journal.jsonl");
  const tornStop = "{\"apiVersion\":\"gate.lab-campaign-journal/v1\",\"type\":\"authority-stopped\"";
  fs.appendFileSync(tornJournal, tornStop, { encoding: "utf8" });
  assert.throws(
    () => labCampaignAuthorityStatus("hacker101-baseline", torn.options),
    /journal has an incomplete final record/u
  );
  const rename = fs.renameSync;
  const injectedCrash = new Error("crash after journal replacement");
  t.mock.method(fs, "renameSync", (...args) => {
    const result = rename(...args);
    if (args[1] === tornJournal) throw injectedCrash;
    return result;
  });
  assert.throws(() => recoverLabCampaignAuthority("hacker101-baseline", {
    confirm: labCampaignAuthorityInternals.exactRecoveryConfirmation(tornCreated.authority)
  }, torn.options), /crash after journal replacement/u);
  t.mock.restoreAll();
  assert.equal(labCampaignAuthorityStatus("hacker101-baseline", torn.options).status, "stopped");
  const quarantined = fs.readdirSync(tornDirectory)
    .filter((name) => /^journal\.jsonl\.torn\.[a-f0-9]{16}\.bin$/u.test(name));
  assert.equal(quarantined.length, 1);
  assert.equal(fs.readFileSync(path.join(tornDirectory, quarantined[0]), "utf8"), tornStop);

  const delimiter = setup(t, { jobCount: 1 });
  const delimiterCreated = proposal(delimiter);
  confirmLabCampaignAuthority("hacker101-baseline", {
    confirm: delimiterCreated.confirmationRequired
  }, delimiter.options);
  const delimiterJournal = path.join(
    delimiter.paths.stateHome,
    "lab-campaign-authorities",
    "hacker101-baseline",
    "journal.jsonl"
  );
  const completeBytes = fs.readFileSync(delimiterJournal);
  assert.equal(completeBytes.at(-1), 0x0a);
  fs.writeFileSync(delimiterJournal, completeBytes.subarray(0, completeBytes.length - 1), { mode: 0o600 });
  const undelimitedBytes = fs.readFileSync(delimiterJournal);
  assert.throws(() => stopLabCampaignAuthority("hacker101-baseline", {
    confirm: labCampaignAuthorityInternals.exactStopConfirmation(delimiterCreated.authority)
  }, delimiter.options), /journal has an incomplete final record/u);
  assert.deepEqual(fs.readFileSync(delimiterJournal), undelimitedBytes);
  const recoveredDelimiter = recoverLabCampaignAuthority("hacker101-baseline", {
    confirm: labCampaignAuthorityInternals.exactRecoveryConfirmation(delimiterCreated.authority)
  }, delimiter.options);
  assert.deepEqual(recoveredDelimiter.journalRepair, {
    repaired: true,
    mode: "delimiter-restored"
  });
  assert.equal(fs.readFileSync(delimiterJournal).at(-1), 0x0a);
  assert.equal(stopLabCampaignAuthority("hacker101-baseline", {
    confirm: labCampaignAuthorityInternals.exactStopConfirmation(delimiterCreated.authority)
  }, delimiter.options).stopped, true);

  const firstRecord = setup(t, { jobCount: 1 });
  const firstRecordCreated = proposal(firstRecord);
  const firstRecordDirectory = path.join(
    firstRecord.paths.stateHome,
    "lab-campaign-authorities",
    "hacker101-baseline"
  );
  const firstRecordJournal = path.join(firstRecordDirectory, "journal.jsonl");
  const firstRecordBytes = fs.readFileSync(firstRecordJournal);
  fs.writeFileSync(firstRecordJournal, firstRecordBytes.subarray(0, firstRecordBytes.length - 1), { mode: 0o600 });
  assert.throws(() => confirmLabCampaignAuthority("hacker101-baseline", {
    confirm: firstRecordCreated.confirmationRequired
  }, firstRecord.options), /journal has an incomplete final record/u);
  assert.equal(fs.existsSync(path.join(firstRecordDirectory, "authorization-receipt.json")), false);
  const recoveredFirstRecord = recoverLabCampaignAuthority("hacker101-baseline", {
    confirm: labCampaignAuthorityInternals.exactRecoveryConfirmation(firstRecordCreated.authority)
  }, firstRecord.options);
  assert.equal(recoveredFirstRecord.journalRepair.mode, "delimiter-restored");
  assert.equal(confirmLabCampaignAuthority("hacker101-baseline", {
    confirm: firstRecordCreated.confirmationRequired
  }, firstRecord.options).confirmed, true);

  const invalid = setup(t, { jobCount: 1 });
  const invalidCreated = proposal(invalid);
  confirmLabCampaignAuthority("hacker101-baseline", {
    confirm: invalidCreated.confirmationRequired
  }, invalid.options);
  const invalidJournal = path.join(
    invalid.paths.stateHome,
    "lab-campaign-authorities",
    "hacker101-baseline",
    "journal.jsonl"
  );
  const invalidLines = fs.readFileSync(invalidJournal, "utf8").trim().split(/\r?\n/u);
  const invalidTail = JSON.parse(invalidLines.at(-1));
  invalidTail.entrySha256 = sha("f");
  const invalidBytes = `${invalidLines.slice(0, -1).join("\n")}\n${JSON.stringify(invalidTail)}`;
  fs.writeFileSync(invalidJournal, invalidBytes, { encoding: "utf8", mode: 0o600 });
  assert.throws(() => recoverLabCampaignAuthority("hacker101-baseline", {
    confirm: labCampaignAuthorityInternals.exactRecoveryConfirmation(invalidCreated.authority)
  }, invalid.options), /complete but invalid and was preserved/u);
  assert.equal(fs.readFileSync(invalidJournal, "utf8"), invalidBytes);
});

test("authority expiry is rechecked after a rate wait before a second request can be claimed", async (t) => {
  const fixture = setup(t, { jobCount: 2 });
  let clock = Date.parse(fixture.createdAt);
  const shortExpiry = new Date(clock + 60_000).toISOString();
  const timedOptions = {
    ...fixture.options,
    now: () => clock,
    wait: async (milliseconds) => { clock += milliseconds + 60_000; }
  };
  const created = createLabCampaignAuthority({
    authorityId: "hacker101-baseline",
    campaignId: "baseline-campaign",
    challengeOrigin: "https://ctf.example.test",
    frozenIps: ["192.0.2.10"],
    destinationObservationFile: fixture.destinationObservationFile,
    admissionFile: fixture.admissionFile,
    expiresAt: shortExpiry
  }, timedOptions);
  confirmLabCampaignAuthority("hacker101-baseline", { confirm: created.confirmationRequired }, timedOptions);
  setControllerStart(fixture);
  let brokerCreates = 0;
  let prepared;
  let labCampaign;
  const broker = {
    ...timedOptions,
    createManagedExecutionManifest: (engagementId, input) => {
      brokerCreates += 1;
      prepared = fixture.prepareManagedAdapterInvocation(input);
      labCampaign = verifyLabCampaignExecutionCapability(input.labCampaignCapability, {
        engagementId,
        target: prepared.normalized.target,
        action: prepared.normalized.action,
        toolId: prepared.normalized.toolId,
        adapterId: prepared.binding.id,
        operationSha256: prepared.binding.operationSha256,
        argvSha256: prepared.binding.argvSha256,
        workflowId: prepared.normalized.workflowId,
        phaseAttemptId: prepared.normalized.phaseAttemptId,
        declaredBounds: prepared.normalized.declaredBounds,
        adapterBinding: prepared.binding
      }, timedOptions);
      const manifestId = `xmf_${String(brokerCreates).repeat(32)}`;
      const manifestSha256 = String(brokerCreates + 1).repeat(64);
      return {
        ok: true, manifestId, manifestSha256, expiresAt: shortExpiry,
        confirmationRequired: `EXECUTE ${manifestId} ${manifestSha256} UNMETERED`,
        operation: { targetArgument: input.target, adapter: prepared.binding, argv: prepared.compiled.argv },
        declaredBounds: prepared.normalized.declaredBounds,
        labCampaign,
        workflow: {
          instanceId: "pilot-workflow", phaseId: "active-surface-validation",
          phaseAttemptId: `wpa_${"1".repeat(32)}`, admissionSha256: fixture.admissionSha256,
          authorityReceiptSha256: sha("4"), definitionSha256: sha("f"),
          reservationId: `wxr_${String(brokerCreates + 2).repeat(32)}`
        }
      };
    },
    executeExecutionManifest: async () => ({
      ok: true, status: "succeeded", runId: `xrun_${"9".repeat(32)}`, durationMs: 1,
      evidence: { stdout: { bytes: 0 }, stderr: { bytes: 0 }, resultAvailable: false },
      adapterOutput: {
        ok: true, status: "observed",
        metrics: {
          requestCount: 1, method: prepared.binding.operation.method, statusCode: 200,
          responseBodyBytes: 0, responseContentLength: 0, rateLimitPerSecond: 2,
          redirectsFollowed: 0, redirectStatus: "not-followed", retries: 0,
          backoffStatus: "disabled-no-retries"
        }
      }
    })
  };
  await dispatchAuthorizedLabCampaignJob("hacker101-baseline", fixture.jobs[0], broker);
  fixture.context.state.jobs[0].status = "completed";
  setControllerStart(fixture, 1);
  await assert.rejects(
    dispatchAuthorizedLabCampaignJob("hacker101-baseline", fixture.jobs[1], broker),
    /authority expired/u
  );
  assert.equal(brokerCreates, 1);
  assert.equal(labCampaignAuthorityStatus("hacker101-baseline", timedOptions).jobs.claimed, 1);
});
