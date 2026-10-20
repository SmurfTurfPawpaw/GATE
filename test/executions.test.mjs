import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  approveEngagement,
  attachPlan,
  checkEngagement,
  createEngagement,
  recordTechnicalReview,
  revokeEngagement
} from "../src/lib/engagements.mjs";
import { consultLearnings } from "../src/lib/learnings.mjs";
import {
  createExecutionManifest,
  executeExecutionManifest,
  executionCapability,
  executionInternals,
  executionStatus,
  reconcileExecution,
  requestExecutionStop
} from "../src/lib/executions.mjs";
import { runtimePaths } from "../src/lib/paths.mjs";
import { validateDocument } from "../src/lib/schema.mjs";
import {
  addWorkflowEvidence,
  cancelWorkflowExecution,
  completeWorkflowExecution,
  createWorkflowInstance,
  finishWorkflowPhase,
  planWorkflowTest,
  reviewWorkflowTest,
  startWorkflowPhase,
  workflowRuntimeInternals,
  workflowStatus
} from "../src/lib/workflow-runtime.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const gate = path.join(repo, "bin", "gate.mjs");
const workflowDefinition = JSON.parse(fs.readFileSync(path.join(repo, "config", "workflows", "pentest-e2e.json"), "utf8"));
const fixtureScopes = new WeakMap();

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-execution-"));
  const paths = runtimePaths({ home: path.join(root, "home"), repo });
  const scopes = [];
  fixtureScopes.set(paths, scopes);
  t.after(() => {
    try {
      for (const scope of scopes) finalizeFixtureCycle(scope, paths);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
  return { root, paths };
}

function requireLane(t) {
  const capability = executionCapability();
  if (!capability.laneAvailable) t.skip(`supervised execution unavailable: ${capability.reason}`);
}

function approve(paths, root, options = {}) {
  const id = options.id || "execution-test";
  const target = options.target || "127.0.0.1";
  const action = options.action || "scan";
  const toolId = "dnsx";
  const plan = path.join(root, `${id}.md`);
  fs.writeFileSync(plan, `# Plan\nBounded fixture execution for ${id}.\n`);
  createEngagement({
    id,
    targets: [target],
    actions: [action],
    tools: [toolId],
    environment: options.environment || "host",
    maxMinutes: 30,
    maxRequests: 500,
    maxParallel: 2,
    maxRate: 10,
    maxTokens: 100_000,
    allowedDestinations: options.allowedDestinations
  }, { paths });
  const planned = attachPlan(id, plan, { paths });
  recordTechnicalReview(id, {
    run: `no-mistakes/${id}`,
    headSha: "a".repeat(40),
    status: "passed"
  }, { paths });
  approveEngagement(id, { sha256: planned.plan.sha256, confirm: `APPROVE ${id}` }, { paths });
  if (options.workflow === false) {
    return {
      id,
      target,
      action,
      toolId,
      workflowId: `${id}-workflow`,
      phaseAttemptId: `wpa_${"0".repeat(32)}`
    };
  }

  const workflowId = `${id}-workflow`;
  createWorkflowInstance(workflowId, { engagementId: id }, { paths });
  for (const phaseId of ["authorization-and-roe", "target-and-architecture-map"]) {
    const phase = workflowDefinition.phases.find((candidate) => candidate.id === phaseId);
    startWorkflowPhase(workflowId, {
      phaseId,
      sourcePhase: phaseId === "target-and-architecture-map" ? "authorization-and-roe" : undefined
    }, { paths });
    for (const evidence of phase.evidence.filter((record) => record.required)) {
      const file = path.join(root, `${id}-${phaseId}-${evidence.id}.txt`);
      fs.writeFileSync(file, `${evidence.id}: execution fixture evidence\n`, { mode: 0o600 });
      addWorkflowEvidence(workflowId, {
        phaseId,
        evidenceId: evidence.id,
        claimState: evidence.claimState,
        file
      }, { paths });
    }
    finishWorkflowPhase(workflowId, { phaseId, disposition: "tested" }, { paths });
  }
  const status = workflowStatus(workflowId, { paths });
  assert.equal(status.ok, true);
  const phaseId = "active-surface-validation";
  const phase = workflowDefinition.phases.find((candidate) => candidate.id === phaseId);
  const mapping = phase.toolMappings.find((candidate) => candidate.toolId === toolId);
  const authority = checkEngagement(id, {
    target,
    action,
    maxMinutes: 5,
    estimatedRequests: 20,
    maxParallel: 2,
    maxRatePerSecond: 10,
    maxTokens: 20_000
  }, { paths }).executionBinding;
  const admission = {
    $schema: "../../schemas/workflow-admission.schema.json",
    apiVersion: "gate.workflow-admission/v1",
    kind: "WorkflowAdmission",
    instanceId: workflowId,
    workflowDefinitionSha256: status.contract.sha256,
    phaseId,
    target,
    action,
    toolId,
    toolMappingSha256: workflowRuntimeInternals.canonicalDigest(mapping, "gate.workflow.tool-mapping.v1"),
    adapterConstraint: mapping.adapterConstraint,
    authority: {
      engagementId: authority.engagementId,
      planSha256: authority.planSha256,
      envelopeSha256: authority.envelopeSha256,
      receiptSha256: authority.receiptSha256,
      authorizationValidUntil: authority.authorizationValidUntil,
      checkedAt: new Date().toISOString()
    },
    envelope: {
      maxMinutes: 5,
      maxRequests: 20,
      maxRatePerSecond: 10,
      maxParallel: 2,
      maxInputTokens: 0,
      maxOutputTokens: 0,
      maxTotalTokens: 20_000,
      maxEvidenceBytes: 32 * 1024 * 1024,
      maxSpend: 0,
      controls: {
        wallTime: "measured-only",
        requests: "unavailable",
        rate: "unavailable",
        parallel: "unavailable",
        tokens: "unavailable",
        evidenceBytes: "enforced",
        spend: "unavailable"
      }
    },
    issuedAt: new Date(Date.now() - 1_000).toISOString(),
    expiresAt: authority.authorizationValidUntil
  };
  const admissionFile = path.join(root, `${id}-admission.json`);
  fs.writeFileSync(admissionFile, `${JSON.stringify(admission, null, 2)}\n`, { mode: 0o600 });
  const started = startWorkflowPhase(workflowId, {
    phaseId,
    sourcePhase: "target-and-architecture-map",
    admissionFile
  }, { paths });
  const scope = {
    id,
    target,
    action,
    toolId,
    workflowId,
    phaseAttemptId: started.projection.activePhase.attemptId,
    feedback: {
      root,
      cycle: 0,
      latestReviewEntrySha256: null,
      planned: null,
      evidenceSha256: [],
      finish: options.finishFeedback !== false
    }
  };
  if (options.feedback !== false) {
    planFixtureCycle(scope, paths);
    fixtureScopes.get(paths)?.push(scope);
  }
  return scope;
}

function planFixtureCycle(scope, paths) {
  const workflow = workflowStatus(scope.workflowId, { paths });
  const feedbackApplicability = [
    {
      kind: "workflow",
      id: workflow.contract.id,
      version: String(workflow.contract.version),
      digest: workflow.contract.sha256
    },
    { kind: "phase", id: "active-surface-validation" },
    { kind: "tool", id: scope.toolId }
  ];
  const consultation = consultLearnings({ applicability: feedbackApplicability }, { paths });
  const priorReviewEntrySha256 = scope.feedback.latestReviewEntrySha256;
  const planned = planWorkflowTest(scope.workflowId, {
    phaseId: "active-surface-validation",
    attemptId: scope.phaseAttemptId,
    hypothesis: "The bounded execution fixture should produce a terminal result and declared phase evidence.",
    method: "Run one supervised fixture execution under the active admission and preserve its result.",
    expectedSignal: "The execution reaches a terminal state with its declared evidence recorded.",
    contrarySignal: "The execution cannot reach a terminal state or its evidence cannot be preserved.",
    learningApplicability: feedbackApplicability,
    learningIds: consultation.selected.map((learning) => learning.id),
    learningLedgerHeadSha256: consultation.ledgerHeadSha256,
    learningProjectionSha256: consultation.projectionSha256,
    basisEvidenceSha256: [],
    priorReviewEntrySha256,
    adaptation: priorReviewEntrySha256
      ? "Retry only the changed manifest or executable condition identified by the prior review."
      : null
  }, { paths });
  scope.feedback.cycle += 1;
  const phase = workflowDefinition.phases.find((candidate) => candidate.id === "active-surface-validation");
  const evidenceSha256 = [];
  for (const evidence of phase.evidence.filter((record) => record.required)) {
    const file = path.join(scope.feedback.root,
      `${scope.id}-feedback-${scope.feedback.cycle}-${evidence.id}.txt`);
    const bytes = Buffer.from(`${evidence.id}: execution feedback cycle ${scope.feedback.cycle}\n`);
    fs.writeFileSync(file, bytes, { mode: 0o600 });
    const added = addWorkflowEvidence(scope.workflowId, {
      phaseId: phase.id,
      evidenceId: evidence.id,
      claimState: evidence.claimState,
      file
    }, { paths });
    evidenceSha256.push(added.entry.payload.sha256);
  }
  scope.feedback.planned = planned;
  scope.feedback.evidenceSha256 = evidenceSha256;
  return planned;
}

function finalizeFixtureCycle(scope, paths, options = {}) {
  const planned = scope.feedback?.planned;
  if (!planned) return null;
  const projectionFile = workflowRuntimeInternals.workflowPaths(paths, scope.workflowId).workflowProjection;
  let projection = JSON.parse(fs.readFileSync(projectionFile, "utf8"));
  let reservation = Object.values(projection.executionReservations)
    .find((candidate) => candidate.testId === planned.entry.payload.testId);
  if (reservation?.status === "reserved") {
    cancelWorkflowExecution(scope.workflowId, {
      reservationId: reservation.reservationId,
      reason: "Fixture cleanup terminalized an unused planned execution."
    }, { paths });
  } else if (reservation?.status === "claimed") {
    completeWorkflowExecution(scope.workflowId, {
      reservationId: reservation.reservationId,
      status: "blocked",
      runSha256: "e".repeat(64),
      terminationReason: "Fixture cleanup terminalized an incomplete claimed execution."
    }, { paths });
  }
  projection = JSON.parse(fs.readFileSync(projectionFile, "utf8"));
  reservation = Object.values(projection.executionReservations)
    .find((candidate) => candidate.testId === planned.entry.payload.testId);
  let reviewEvidenceSha256 = scope.feedback.evidenceSha256;
  let completedResultBound = false;
  if (reservation?.status === "completed" && reservation.resultSha256) {
    const resultFile = path.join(paths.evidence, `execution-${reservation.runId}-result.json`);
    if (fs.existsSync(resultFile)) {
      const phase = workflowDefinition.phases.find((candidate) => candidate.id === "active-surface-validation");
      const evidence = phase.evidence.find((candidate) => candidate.required);
      const added = addWorkflowEvidence(scope.workflowId, {
        phaseId: phase.id,
        evidenceId: evidence.id,
        claimState: evidence.claimState,
        file: resultFile
      }, { paths });
      assert.equal(added.entry.payload.sha256, reservation.resultSha256);
      reviewEvidenceSha256 = [reservation.resultSha256];
      completedResultBound = true;
    }
  }
  const disposition = options.disposition || (reservation ? "inconclusive" : "invalid-test");
  const reviewed = reviewWorkflowTest(scope.workflowId, {
    testId: planned.entry.payload.testId,
    phaseId: planned.entry.payload.phaseId,
    attemptId: planned.entry.payload.attemptId,
    planEntrySha256: planned.entry.entrySha256,
    disposition,
    observation: reservation
      ? `The fixture reservation reached terminal state ${reservation.status}.`
      : "Manifest validation ended before a target-contact reservation was created.",
    evidenceSha256: reviewEvidenceSha256,
    metrics: null,
    usefulMistake: null,
    nextStrategy: { decision: "stop", rationale: "The focused execution assertion is complete." }
  }, { paths });
  scope.feedback.latestReviewEntrySha256 = reviewed.entry.entrySha256;
  scope.feedback.planned = null;
  scope.feedback.evidenceSha256 = [];
  projection = JSON.parse(fs.readFileSync(projectionFile, "utf8"));
  const finish = options.finish ?? scope.feedback.finish;
  if (finish && projection.status === "open" &&
    projection.activePhase?.attemptId === scope.phaseAttemptId) {
    const tested = completedResultBound;
    finishWorkflowPhase(scope.workflowId, {
      phaseId: "active-surface-validation",
      disposition: tested ? "tested" : "blocked",
      ...(tested ? {} : {
        rationale: "The fixture execution did not complete successfully, so it cannot establish tested coverage."
      })
    }, { paths });
  }
  return reviewed;
}

function resolver(toolId, executable = process.execPath, riskClass = "A1") {
  return (id) => ({
    id,
    installed: id === toolId,
    executable,
    compatible: true,
    genericLaneEligible: true,
    executionAvailable: true,
    host: process.env.WSL_DISTRO_NAME ? "wsl2" : "linux",
    riskClass
  });
}

function manifestInput(scope, argv) {
  return {
    workflowId: scope.workflowId,
    phaseAttemptId: scope.phaseAttemptId,
    target: scope.target,
    action: scope.action,
    toolId: scope.toolId,
    argv,
    maxMinutes: 1,
    estimatedRequests: 1,
    maxParallel: 1,
    maxRatePerSecond: 1,
    maxTokens: 1_000,
    maxEvidenceBytes: 2 * 1024 * 1024
  };
}

function evidenceFile(paths, reference) {
  return path.join(paths.evidence, reference.slice("private://evidence/".length));
}

async function withTimeout(promise, milliseconds = 5_000) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`operation exceeded ${milliseconds}ms`)), milliseconds);
      })
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function waitFor(check, milliseconds = 3_000) {
  const deadline = Date.now() + milliseconds;
  while (Date.now() < deadline) {
    const value = check();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`condition was not met within ${milliseconds}ms`);
}

function nonZombie(pid) {
  try {
    const text = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    return text.slice(text.lastIndexOf(")") + 2).split(/\s+/u)[0] !== "Z";
  } catch {
    return false;
  }
}

test("one-shot loopback execution binds exact argv and strips ambient credentials", async (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  let requests = 0;
  const server = http.createServer((request, response) => {
    requests += 1;
    response.end("fixture-ok");
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(() => server.close());
  const address = server.address();
  const target = `http://127.0.0.1:${address.port}/probe?q=%24%28touch%20never%29%3B%26`;
  const scope = approve(paths, root, { id: "loopback", target });
  const script = [
    "const http=require('node:http');",
    "const target=process.argv[1];",
    "http.get(target,(response)=>{response.resume();response.on('end',()=>{",
    "process.stdout.write(JSON.stringify({target,hostname:new URL(target).hostname,argv:process.argv.slice(1),env:Object.keys(process.env).sort()}));",
    "});}).on('error',(error)=>{console.error(error.message);process.exitCode=2;});"
  ].join("");
  const created = createExecutionManifest(
    scope.id,
    manifestInput(scope, ["-e", script, "{{GATE_TARGET}}"]),
    { paths, resolveTool: resolver(scope.toolId) }
  );
  const createdManifest = JSON.parse(fs.readFileSync(
    path.join(paths.executionManifests, `${created.manifestId}.json`),
    "utf8"
  ));
  assert.equal(createdManifest.metadata.attemptOrdinal, 1);

  assert.deepEqual(created.operation.argv.slice(0, 2), ["-e", script]);
  assert.equal(created.operation.argv[2], target);
  assert.ok(created.enforcement.enforced.includes("executable-descriptor-observed-sha256"));
  assert.ok(created.enforcement.unavailable.includes("immutable-executable-snapshot"));
  await assert.rejects(
    executeExecutionManifest(scope.id, { manifestId: created.manifestId, confirm: "EXECUTE wrong" }, { paths }),
    /confirmation must be exactly/
  );
  assert.equal(requests, 0);

  const result = await withTimeout(executeExecutionManifest(scope.id, {
    manifestId: created.manifestId,
    confirm: created.confirmationRequired
  }, { paths, pollIntervalMs: 20, terminationGraceMs: 50 }));
  assert.equal(result.status, "succeeded");
  assert.equal(result.terminationReason, "completed");
  assert.deepEqual(result.workflow, {
    instanceId: scope.workflowId,
    phaseId: "active-surface-validation",
    phaseAttemptId: scope.phaseAttemptId,
    reservationId: created.workflow.reservationId
  });
  assert.equal(requests, 1);
  assert.equal(result.evidence.stdout.available, true);
  assert.equal(result.evidence.resultAvailable, true);
  const captured = JSON.parse(fs.readFileSync(evidenceFile(paths, result.evidence.stdout.ref), "utf8"));
  assert.equal(captured.target, target);
  assert.equal(captured.hostname, new URL(target).hostname);
  assert.deepEqual(captured.argv, [target]);
  assert.deepEqual(captured.env, ["HOME", "LANG", "LC_ALL", "NO_COLOR", "PATH", "TERM", "TMPDIR"]);
  for (const ref of [result.evidence.stdout.ref, result.evidence.stderr.ref, result.evidence.resultRef]) {
    assert.equal(fs.statSync(evidenceFile(paths, ref)).mode & 0o777, 0o600);
  }
  await assert.rejects(
    executeExecutionManifest(scope.id, { manifestId: created.manifestId, confirm: created.confirmationRequired }, { paths }),
    /already consumed/
  );
  assert.equal(requests, 1);
  for (const stream of [result.evidence.stdout.ref, result.evidence.stderr.ref]) {
    fs.writeFileSync(evidenceFile(paths, stream),
      `Cookie: pad=${"p".repeat(5000)}; sid=hunter2; padding=${"q".repeat(4000)}\n checking \n`);
  }
  const execution = executionStatus({
    paths,
    now: new Date("2026-10-20T12:00:00.000Z"),
    includeExecutionMirror: true
  });
  assert.equal(execution.counts.succeeded, 1);
  assert.equal(execution.mirror.availability, "available");
  assert.equal(Object.isFrozen(execution.mirror), true);
  assert.equal(execution.mirror.attempts.length, 1);
  const mirrored = execution.mirror.attempts[0];
  assert.equal(mirrored.alias, "Attempt 1");
  assert.equal(mirrored.kind, "supervised-execution");
  assert.equal(mirrored.state, "succeeded");
  assert.equal(mirrored.usage.toolRuns.availability, "exact");
  assert.equal(mirrored.usage.toolRuns.value, 1);
  const workOrderEntry = mirrored.entries.find((entry) => entry.channel === "work-order");
  const commandEntry = mirrored.entries.find((entry) => entry.channel === "command");
  const resultEntry = mirrored.entries.find((entry) => entry.channel === "result");
  assert.equal(workOrderEntry.at, execution.recent[0].createdAt);
  assert.equal(commandEntry.at, execution.recent[0].startedAt);
  assert.equal(resultEntry.at, execution.recent[0].finishedAt);
  assert.ok(mirrored.entries.some((entry) => entry.channel === "stdout"));
  const mirrorJson = JSON.stringify(execution.mirror);
  for (const privateValue of [target, created.runId, created.manifestId, scope.id, scope.workflowId,
    scope.phaseAttemptId, created.workflow.reservationId, new URL(target).hostname]) {
    assert.equal(mirrorJson.includes(privateValue), false);
  }
  assert.equal(mirrorJson.includes("private://"), false);
  assert.equal(mirrorJson.includes("hunter2"), false);
  for (const channel of ["stdout", "stderr"]) {
    assert.ok(mirrored.entries.some((entry) => entry.channel === channel && entry.text === " checking " && entry.truncated));
  }
  const later = executionStatus({
    paths,
    now: new Date("2026-10-20T12:05:00.000Z"),
    includeExecutionMirror: true
  });
  assert.deepEqual(later.mirror, execution.mirror);
  const nonContiguous = structuredClone(execution.mirror);
  nonContiguous.attempts[0].alias = "Attempt 150";
  nonContiguous.attempts.push({ ...structuredClone(mirrored), alias: "Attempt 148" });
  assert.doesNotThrow(() => executionInternals.validateExecutionMirror(nonContiguous));
  for (const alias of ["Attempt 0", "Attempt 9007199254740992", "Attempt 1"]) {
    const invalidAlias = structuredClone(execution.mirror);
    invalidAlias.attempts.push({ ...structuredClone(mirrored), alias });
    assert.throws(() => executionInternals.validateExecutionMirror(invalidAlias), /attempt is invalid/u);
  }
  for (const unsafeText of [
    "/home/operator/GATE_HOME/evidence/output.txt",
    "/srv/unrelated/service/output.txt",
    "open (/etc/passwd)",
    "inspect [/opt/application/config.json]",
    "echo result>/var/output/result.txt",
    "C:\\Users\\Operator\\capture.pcap",
    "\\\\laptop\\Users\\Operator\\capture.pcap",
    "--token abc123",
    "auth=abc123",
    "curl -u alice:hunter2 https://example.invalid/path"
  ]) {
    const unsafeMirror = structuredClone(execution.mirror);
    unsafeMirror.attempts[0].entries[1].text = unsafeText;
    assert.throws(() => executionInternals.validateExecutionMirror(unsafeMirror), /private execution metadata/);
  }
  for (const redactedText of [
    executionInternals.sanitizeMirrorText("tool --token=abc123").text,
    executionInternals.sanitizeMirrorText('{"token":"abc123"}').text
  ]) {
    const redactedMirror = structuredClone(execution.mirror);
    redactedMirror.attempts[0].entries[1].text = redactedText;
    assert.doesNotThrow(() => executionInternals.validateExecutionMirror(redactedMirror));
  }
  const workflow = workflowStatus(scope.workflowId, { paths });
  assert.deepEqual(workflow.executionReservations, []);
  assert.equal(workflow.activePhase.allocation.conservativelyReserved.maxMinutes, 1);
  assert.equal(workflow.activePhase.allocation.conservativelyReserved.maxRequests, 1);
  assert.equal(workflow.activePhase.allocation.conservativelyReserved.maxTotalTokens, 1_000);
  assert.equal(workflow.activePhase.allocation.conservativelyReserved.maxEvidenceBytes, 2 * 1024 * 1024);
  assert.throws(
    () => reconcileExecution(scope.id, { manifestId: created.manifestId, confirm: "RECONCILE wrong" }, { paths }),
    /confirmation must be exactly/
  );
  const reconciled = reconcileExecution(scope.id, {
    manifestId: created.manifestId,
    confirm: `RECONCILE EXECUTION ${created.manifestId} ${created.manifestSha256}`
  }, { paths });
  assert.equal(reconciled.status, "succeeded");
  assert.equal(reconciled.workflow.reservationId, created.workflow.reservationId);
});

test("execution mirror text sanitization masks credentials, private paths, controls, and opaque secrets", () => {
  const sanitize = executionInternals.sanitizeMirrorText;
  const privatePaths = ["/srv/operator/gate-state"];
  for (const credential of [
    "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345 trailing",
    "api_key=github_pat_abcdefghijklmnopqrstuvwxyz012345 useful",
    "--token abc123 --mode useful",
    "--auth abc123 --mode useful",
    "token=abc123 useful",
    "auth=abc123 useful",
    '{"token":"abc123","mode":"useful"}',
    '{"secret":"abc123","mode":"useful"}',
    "curl -u alice:hunter2 https://example.invalid/path"
  ]) {
    const projected = sanitize(credential);
    assert.equal(projected.fidelity, "redacted");
    assert.equal(projected.text.includes("abcdefghijklmnopqrstuvwxyz012345"), false);
  }
  const projected = sanitize([
    "/home/giovanni/GATE_HOME/evidence/result.json",
    "(/etc/passwd)",
    "[/opt/application/config.json]",
    "echo result>/var/output/result.txt",
    "C:\\Users\\Giovanni\\private\\capture.pcap",
    "\\\\laptop\\Users\\Giovanni\\notes.txt",
    "/srv/operator/gate-state/runs/output.log",
    "\u001b[31mcolored\u001b[0m"
  ].join(" "), { privatePaths });
  assert.equal(projected.fidelity, "redacted");
  assert.equal(projected.text.includes("giovanni"), false);
  assert.equal(projected.text.includes("Giovanni"), false);
  assert.equal(projected.text.includes("laptop"), false);
  assert.equal(projected.text.includes("/srv/operator/gate-state"), false);
  assert.equal(projected.text.includes("/runs/output.log"), false);
  assert.equal(projected.text.includes("passwd"), false);
  assert.equal(projected.text.includes("config.json"), false);
  assert.equal(projected.text.includes("\\u001B"), true);
  assert.equal(projected.text.includes("[private path withheld"), true);

  const networkPaths = sanitize([
    "file:///etc/shadow",
    "file://laptop/private/share.txt",
    "//laptop/private/share.txt"
  ].join(" "));
  assert.equal(networkPaths.fidelity, "redacted");
  assert.equal(networkPaths.text, [
    "[private path withheld]",
    "[private path withheld]",
    "[private path withheld]"
  ].join(" "));

  assert.deepEqual(sanitize("tool --token=abc123"), {
    text: "tool --token=[secret withheld]",
    fidelity: "redacted",
    truncated: false
  });

  const overlappingMarker = sanitize("value", { privateValues: ["value"] });
  assert.equal(overlappingMarker.text, "[private id withheld]");

  const target = "https://private.example/account/123";
  const targeted = sanitize(`tool --url ${target} --flag useful`, { targetValues: [target] });
  assert.equal(targeted.text.includes(target), false);
  assert.equal(targeted.text.includes("[target withheld]"), true);
  assert.equal(targeted.text.includes("--flag useful"), true);

  const publicUrl = "https://example.invalid/public/path?q=value";
  assert.deepEqual(sanitize(publicUrl), { text: publicUrl, fidelity: "exact", truncated: false });

  const opaque = sanitize("mF9/4xJ7Qp2_Za8+Vr6Ls1Nd0Kc5Ty3H");
  assert.deepEqual(opaque, {
    text: "[withheld: possible secret]",
    fidelity: "redacted",
    truncated: false
  });

  const unicode = sanitize("😀".repeat(241));
  assert.equal(unicode.truncated, true);
  assert.equal([...unicode.text].length, 240);
  assert.equal([...unicode.text].at(-1), "😀");
});

test("execution mirror reflects output and elapsed time while the supervised process is still running", async (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const scope = approve(paths, root, { id: "live-mirror", target: "127.0.0.1" });
  const releaseSecondLine = path.join(root, "release-second-line");
  const releaseExit = path.join(root, "release-exit");
  const script = [
    "const fs=require('node:fs');",
    "const second=process.argv[1];const finish=process.argv[2];",
    "process.stdout.write('phase-one\\n');",
    "let emitted=false;",
    "const timer=setInterval(()=>{",
    "if(!emitted&&fs.existsSync(second)){emitted=true;process.stdout.write('phase-two\\n');}",
    "if(emitted&&fs.existsSync(finish)){clearInterval(timer);process.exit(0);}",
    "},10);"
  ].join("");
  const created = createExecutionManifest(
    scope.id,
    manifestInput(scope, ["-e", script, releaseSecondLine, releaseExit, "{{GATE_TARGET}}"]),
    { paths, resolveTool: resolver(scope.toolId) }
  );
  let spawnedResolve;
  const spawned = new Promise((resolve) => { spawnedResolve = resolve; });
  const running = executeExecutionManifest(scope.id, {
    manifestId: created.manifestId,
    confirm: created.confirmationRequired
  }, {
    paths,
    pollIntervalMs: 20,
    terminationGraceMs: 50,
    afterSpawn: () => spawnedResolve()
  });
  try {
    await withTimeout(spawned);
    const stdoutFile = path.join(paths.evidence, `execution-${created.runId}-stdout.bin`);
    await waitFor(() => fs.existsSync(stdoutFile) && fs.readFileSync(stdoutFile, "utf8").includes("phase-one"));

    const first = executionStatus({ paths, includeExecutionMirror: true });
    const firstAttempt = first.mirror.attempts.find((attempt) => attempt.state === "running");
    assert.ok(firstAttempt, "the active attempt must be visible before the process exits");
    assert.ok(firstAttempt.entries.some((entry) => entry.channel === "stdout" && entry.text === "phase-one"));
    assert.equal(firstAttempt.entries.some((entry) => entry.text === "phase-two"), false);

    fs.writeFileSync(releaseSecondLine, "continue\n", { mode: 0o600 });
    await waitFor(() => fs.readFileSync(stdoutFile, "utf8").includes("phase-two"));
    const secondObservedAt = new Date(Date.parse(firstAttempt.updatedAt) + 1_000);
    const second = executionStatus({ paths, includeExecutionMirror: true, now: secondObservedAt });
    const secondAttempt = second.mirror.attempts.find((attempt) => attempt.alias === firstAttempt.alias);
    assert.equal(secondAttempt.state, "running");
    assert.equal(secondAttempt.elapsedMs, firstAttempt.elapsedMs + 1_000);
    assert.ok(secondAttempt.entries.some((entry) => entry.channel === "stdout" && entry.text === "phase-two"),
      "a later in-progress snapshot must contain newly written output");

    fs.writeFileSync(releaseExit, "finish\n", { mode: 0o600 });
    const result = await withTimeout(running);
    assert.equal(result.status, "succeeded");
    const finished = executionStatus({ paths, includeExecutionMirror: true });
    const finishedAttempt = finished.mirror.attempts.find((attempt) => attempt.alias === firstAttempt.alias);
    assert.equal(finishedAttempt.state, "succeeded");
    assert.ok(finishedAttempt.entries.some((entry) => entry.channel === "result"));
  } finally {
    if (!fs.existsSync(releaseSecondLine)) fs.writeFileSync(releaseSecondLine, "continue\n", { mode: 0o600 });
    if (!fs.existsSync(releaseExit)) fs.writeFileSync(releaseExit, "finish\n", { mode: 0o600 });
    await running.catch(() => {});
  }
});

test("execution mirror aliases use persisted positive ordinals", () => {
  const alias = executionInternals.mirrorAttemptAlias;
  assert.equal(alias(1), "Attempt 1");
  assert.equal(alias(2), "Attempt 2");
  assert.equal(alias(150), "Attempt 150");
  for (const value of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => alias(value), /ordinal is invalid/u);
  }
});

test("execution attempt ordinals stay append-only across tied and backdated manifests", (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const scope = approve(paths, root, { id: "attempt-ordinals", target: "ordinal.example.test" });
  const createdAt = Date.now() - 5_000;
  const create = (at) => createExecutionManifest(
    scope.id,
    manifestInput(scope, ["{{GATE_TARGET}}"]),
    { paths, now: () => new Date(at), resolveTool: resolver(scope.toolId) }
  );
  const readOrdinal = (created) => JSON.parse(fs.readFileSync(
    path.join(paths.executionManifests, `${created.manifestId}.json`),
    "utf8"
  )).metadata.attemptOrdinal;
  const retireAndReplan = (created) => {
    cancelWorkflowExecution(scope.workflowId, {
      reservationId: created.workflow.reservationId,
      reason: "The ordinal fixture does not launch its reserved execution."
    }, { paths });
    finalizeFixtureCycle(scope, paths, { finish: false, disposition: "invalid-test" });
    planFixtureCycle(scope, paths);
  };

  const first = create(createdAt);
  assert.equal(readOrdinal(first), 1);
  retireAndReplan(first);

  const tied = create(createdAt);
  assert.equal(readOrdinal(tied), 2);
  retireAndReplan(tied);

  const backdated = create(createdAt - 1_000);
  assert.equal(readOrdinal(backdated), 3);
  retireAndReplan(backdated);

  // Simulate a pre-ordinal manifest and a missing derived sequence. Recovery
  // reserves every retained historical manifest position without relabeling
  // the legacy record.
  const legacyFile = path.join(paths.executionManifests, `${first.manifestId}.json`);
  const legacy = JSON.parse(fs.readFileSync(legacyFile, "utf8"));
  delete legacy.metadata.attemptOrdinal;
  legacy.manifestSha256 = executionInternals.manifestDigest(legacy);
  fs.writeFileSync(legacyFile, `${JSON.stringify(legacy, null, 2)}\n`, { mode: 0o600 });
  fs.rmSync(path.join(paths.executions, ".attempt-sequence.json"));

  const afterRecovery = create(createdAt - 2_000);
  assert.equal(readOrdinal(afterRecovery), 4);
  assert.equal(fs.statSync(path.join(paths.executions, ".attempt-sequence.json")).mode & 0o777, 0o600);
});

test("execution attempt ordinal allocation is serialized across processes", async (t) => {
  requireLane(t);
  const { paths } = fixture(t);
  executionStatus({ paths });
  const script = [
    "import { executionInternals } from './src/lib/executions.mjs';",
    "import { runtimePaths } from './src/lib/paths.mjs';",
    "const paths=runtimePaths({home:process.env.GATE_ORDINAL_HOME,repo:process.cwd()});",
    "process.stdout.write(String(executionInternals.reserveExecutionAttemptOrdinal(paths)));"
  ].join("");
  const allocate = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--input-type=module", "-e", script], {
      cwd: repo,
      env: {
        PATH: process.env.PATH || "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
        GATE_ORDINAL_HOME: paths.home
      },
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
    child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", (code) => {
      if (code === 0) resolve(Number(stdout));
      else reject(new Error(`ordinal child exited ${code}: ${stderr}`));
    });
  });
  const ordinals = await withTimeout(Promise.all([allocate(), allocate(), allocate(), allocate()]), 10_000);
  assert.deepEqual(ordinals.toSorted((left, right) => left - right), [1, 2, 3, 4]);
});

test("fast descriptor execution cannot outrun lifecycle listeners or the one-shot claim", async (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const executable = ["/usr/bin/true", "/bin/true"].find((candidate) => fs.existsSync(candidate));
  if (!executable) t.skip("true executable unavailable");
  const scope = approve(paths, root, { id: "fast-tool", target: "fast.example.test" });
  const created = createExecutionManifest(scope.id, manifestInput(scope, ["{{GATE_TARGET}}"]), {
    paths,
    resolveTool: resolver(scope.toolId, executable, "P0")
  });
  const input = { manifestId: created.manifestId, confirm: created.confirmationRequired };
  const attempts = await withTimeout(Promise.allSettled([
    executeExecutionManifest(scope.id, input, { paths }),
    executeExecutionManifest(scope.id, input, { paths })
  ]), 3_000);
  const fulfilled = attempts.filter((attempt) => attempt.status === "fulfilled");
  const rejected = attempts.filter((attempt) => attempt.status === "rejected");
  assert.equal(fulfilled.length, 1);
  assert.equal(fulfilled[0].value.status, "succeeded");
  assert.equal(rejected.length, 1);
  assert.match(rejected[0].reason.message, /already consumed/);
});

test("reconciliation records recovery hold after a crash between the durable claims", (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const scope = approve(paths, root, { id: "claim-gap", target: "claim-gap.example.test" });
  const created = createExecutionManifest(scope.id, manifestInput(scope, ["{{GATE_TARGET}}"]), {
    paths,
    resolveTool: resolver(scope.toolId)
  });
  const manifest = JSON.parse(fs.readFileSync(
    path.join(paths.executionManifests, `${created.manifestId}.json`),
    "utf8"
  ));
  const deadSupervisor = executionInternals.processIdentity(process.pid);
  deadSupervisor.startTimeTicks = String(BigInt(deadSupervisor.startTimeTicks) + 1n);
  fs.writeFileSync(path.join(paths.executionClaims, `${created.manifestId}.json`), `${JSON.stringify({
    apiVersion: "gate.execution-claim/v1",
    manifestId: created.manifestId,
    runId: created.runId,
    manifestSha256: created.manifestSha256,
    engagementId: scope.id,
    workflow: { ...manifest.workflow },
    claimedAt: new Date().toISOString(),
    createdAt: manifest.metadata.createdAt,
    supervisor: deadSupervisor
  })}\n`, { mode: 0o600 });

  assert.equal(workflowStatus(scope.workflowId, { paths }).executionReservations[0].status, "reserved");
  const reconciled = reconcileExecution(scope.id, {
    manifestId: created.manifestId,
    confirm: `RECONCILE EXECUTION ${created.manifestId} ${created.manifestSha256}`
  }, { paths });
  assert.equal(reconciled.status, "unknown");
  assert.equal(reconciled.terminationReason, "supervision-lost");
  const workflow = workflowStatus(scope.workflowId, { paths });
  assert.equal(workflow.status, "recovery-hold");
  assert.deepEqual(workflow.executionReservations, [{
    id: created.workflow.reservationId,
    status: "unknown",
    phaseId: "active-surface-validation"
  }]);
  assert.equal(JSON.parse(fs.readFileSync(
    path.join(paths.executionRuns, `${created.runId}.json`),
    "utf8"
  )).status, "unknown");

  const replayed = reconcileExecution(scope.id, {
    manifestId: created.manifestId,
    confirm: `RECONCILE EXECUTION ${created.manifestId} ${created.manifestSha256}`
  }, { paths });
  assert.equal(replayed.status, "unknown");
});

test("CLI reports a nonzero exit status when an executed tool fails", (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const scope = approve(paths, root, { id: "cli-tool-failure", target: "127.0.0.1" });
  const created = createExecutionManifest(
    scope.id,
    manifestInput(scope, ["-e", "setTimeout(()=>process.exit(7),100)", "{{GATE_TARGET}}"]),
    { paths, resolveTool: resolver(scope.toolId) }
  );
  const result = spawnSync(process.execPath, [
    gate,
    "--unassigned", "engagement", "exec", scope.id,
    "--manifest", created.manifestId,
    "--confirm", created.confirmationRequired,
    "--json"
  ], {
    cwd: repo,
    env: { ...process.env, GATE_HOME: paths.home },
    encoding: "utf8",
    timeout: 5_000
  });

  assert.equal(result.status, 2, result.stderr);
  assert.equal(result.signal, null);
  const output = JSON.parse(result.stdout);
  assert.equal(output.ok, false);
  assert.equal(output.status, "failed");
  assert.equal(output.exitCode, 7);
});

test("manifest creation rejects environment, target, argv0, and placeholder mismatches", (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const vm = approve(paths, root, { id: "vm-scope", target: "vm.example.test", environment: "vm", workflow: false });
  assert.throws(
    () => createExecutionManifest(vm.id, manifestInput(vm, ["{{GATE_TARGET}}"]), {
      paths,
      resolveTool: resolver(vm.toolId)
    }),
    /requires an approved host environment/
  );

  const externalEvidence = approve(paths, root, {
    id: "external-evidence",
    target: "evidence.example.test",
    allowedDestinations: ["client-destination"],
    workflow: false
  });
  assert.throws(
    () => createExecutionManifest(externalEvidence.id, manifestInput(externalEvidence, ["{{GATE_TARGET}}"]), {
      paths,
      resolveTool: resolver(externalEvidence.toolId)
    }),
    /requires gate-home as an approved evidence destination/
  );

  const canonical = approve(paths, root, { id: "canonical", target: "some app" });
  assert.throws(
    () => createExecutionManifest(canonical.id, { ...manifestInput(canonical, ["{{GATE_TARGET}}"]), target: "  some\tapp  " }, {
      paths,
      resolveTool: resolver(canonical.toolId)
    }),
    /canonical approved form exactly/
  );
  assert.throws(
    () => createExecutionManifest(canonical.id, manifestInput(canonical, [path.basename(process.execPath), "{{GATE_TARGET}}"]), {
      paths,
      resolveTool: resolver(canonical.toolId)
    }),
    /pass tool arguments only/
  );
  assert.throws(
    () => createExecutionManifest(canonical.id, manifestInput(canonical, ["--version"]), {
      paths,
      resolveTool: resolver(canonical.toolId)
    }),
    /exactly one whole-argument/
  );
});

test("generic manifest creation rejects a forged A3 phase before persistence", (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const scope = approve(paths, root, {
    id: "a3-generic", target: "a3.example.test", feedback: false
  });
  const workflowDirectory = path.join(paths.workflows, scope.workflowId);
  const journalFile = path.join(workflowDirectory, "journal.jsonl");
  const projectionFile = path.join(workflowDirectory, "instance.json");
  const entries = fs.readFileSync(journalFile, "utf8").trimEnd().split("\n").map((line) => JSON.parse(line));
  const activePhaseEntry = entries.at(-1);
  assert.equal(activePhaseEntry.type, "phase.started");

  // Exercise the execution boundary directly while retaining a valid journal chain.
  activePhaseEntry.payload.effectClass = "A3";
  activePhaseEntry.entrySha256 = workflowRuntimeInternals.entryDigest(activePhaseEntry);
  fs.writeFileSync(journalFile, `${entries.map((entry) => JSON.stringify(entry)).join("\n")}\n`, { mode: 0o600 });
  fs.rmSync(projectionFile);

  assert.throws(
    () => createExecutionManifest(scope.id, manifestInput(scope, ["{{GATE_TARGET}}"]), {
      paths,
      resolveTool: resolver(scope.toolId)
    }),
    /phase start journal entry differs from the installed phase: effectClass/u
  );
  const blocked = workflowStatus(scope.workflowId, { paths });
  assert.equal(blocked.ok, false);
  assert.match(blocked.blocker, /phase start journal entry differs from the installed phase: effectClass/u);
  assert.deepEqual(fs.readdirSync(paths.executionManifests), []);
});

test("manifest invariants and launch-time executable identity fail closed", async (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const tool = path.join(root, "fixture-tool");
  fs.writeFileSync(tool, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
  const scope = approve(paths, root, { id: "identity", target: "identity.example.test" });
  const first = createExecutionManifest(scope.id, manifestInput(scope, ["{{GATE_TARGET}}"]), {
    paths,
    resolveTool: resolver(scope.toolId, tool, "P0")
  });
  const firstFile = path.join(paths.executionManifests, `${first.manifestId}.json`);
  const tampered = JSON.parse(fs.readFileSync(firstFile, "utf8"));
  tampered.operation.argv[tampered.operation.targetArgIndex] = "outside.example.test";
  tampered.manifestSha256 = executionInternals.manifestDigest(tampered);
  fs.writeFileSync(firstFile, `${JSON.stringify(tampered, null, 2)}\n`, { mode: 0o600 });
  await assert.rejects(
    executeExecutionManifest(scope.id, {
      manifestId: first.manifestId,
      confirm: `EXECUTE ${first.manifestId} ${tampered.manifestSha256} UNMETERED`
    }, { paths }),
    /target argument binding is invalid/
  );
  cancelWorkflowExecution(scope.workflowId, {
    reservationId: first.workflow.reservationId,
    reason: "The tampered fixture manifest will not be executed."
  }, { paths });
  finalizeFixtureCycle(scope, paths, { finish: false, disposition: "invalid-test" });
  planFixtureCycle(scope, paths);

  const second = createExecutionManifest(scope.id, manifestInput(scope, ["{{GATE_TARGET}}"]), {
    paths,
    resolveTool: resolver(scope.toolId, tool, "P0")
  });
  fs.appendFileSync(tool, "# changed\n");
  await assert.rejects(
    executeExecutionManifest(scope.id, { manifestId: second.manifestId, confirm: second.confirmationRequired }, { paths }),
    /executable .* changed after manifest creation/
  );
  const status = executionStatus({ paths });
  assert.equal(status.counts.blocked, 1);
  const events = fs.readFileSync(paths.events, "utf8").trim().split("\n").map((line) => JSON.parse(line));
  const blockedEvents = events.filter((event) => event.runId === second.runId);
  assert.equal(blockedEvents.at(-1).kind, "execution.completed");
  assert.equal(blockedEvents.at(-1).status, "blocked");

  const manifestDocument = JSON.parse(fs.readFileSync(path.join(paths.executionManifests, `${second.manifestId}.json`), "utf8"));
  manifestDocument.operation.executable.inode = "-1";
  assert.equal(validateDocument(manifestDocument, "execution-manifest.schema.json", { paths }).ok, true);
});

test("execution status keeps exact large-history counts and a deterministic bounded recent view", (t) => {
  const { paths } = fixture(t);
  executionStatus({ paths });
  const records = [];
  const supervisor = {
    pid: 2_147_483_647,
    pgid: 2_147_483_647,
    sessionId: 1,
    bootId: "00000000-0000-0000-0000-000000000000",
    startTimeTicks: "1"
  };
  for (let index = 0; index < 150; index += 1) {
    const suffix = index.toString(16).padStart(32, "0");
    const runId = `xrun_${suffix}`;
    const manifestId = `xmf_${suffix}`;
    const createdAt = new Date(Date.UTC(2026, 0, 1) + Math.floor(index / 2) * 1_000).toISOString();
    const record = {
      $schema: "../../schemas/execution-run.schema.json",
      apiVersion: "gate.execution-run/v1",
      kind: "ExecutionRun",
      runId,
      manifestId,
      manifestSha256: "a".repeat(64),
      engagementId: "status-stress",
      workflow: {
        instanceId: "status-workflow",
        phaseId: "active-surface-validation",
        phaseAttemptId: `wpa_${suffix}`,
        reservationId: `wxr_${suffix}`,
        executionEpochSha256: "b".repeat(64)
      },
      status: "succeeded",
      createdAt,
      startedAt: createdAt,
      finishedAt: createdAt,
      supervisor,
      process: null,
      terminationReason: "completed",
      result: { exitCode: 0, signal: null, durationMs: 0 },
      evidence: {
        stdout: {
          ref: `private://evidence/execution-${runId}-stdout.bin`,
          available: false,
          sha256: null,
          bytes: 0
        },
        stderr: {
          ref: `private://evidence/execution-${runId}-stderr.bin`,
          available: false,
          sha256: null,
          bytes: 0
        },
        resultRef: `private://evidence/execution-${runId}-result.json`,
        resultAvailable: false,
        sandboxRef: `private://executions/sandboxes/${runId}`
      }
    };
    fs.writeFileSync(
      path.join(paths.executionRuns, `${runId}.json`),
      `${JSON.stringify(record)}\n`,
      { mode: 0o600 }
    );
    records.push(record);
  }

  const originalReadFileSync = fs.readFileSync;
  let terminalSupervisorProbes = 0;
  fs.readFileSync = (file, ...args) => {
    if (file === "/proc/2147483647/stat") terminalSupervisorProbes += 1;
    return originalReadFileSync(file, ...args);
  };
  let status;
  try {
    status = executionStatus({ paths });
  } finally {
    fs.readFileSync = originalReadFileSync;
  }

  const expected = records.toSorted((left, right) =>
    Date.parse(right.createdAt) - Date.parse(left.createdAt) || left.runId.localeCompare(right.runId)
  ).slice(0, 100).map(({ runId }) => runId);
  assert.equal(status.counts.succeeded, 150);
  assert.equal(status.counts.unknown, 0);
  assert.equal(status.recent.length, 100);
  assert.deepEqual(status.recent.map(({ runId }) => runId), expected);
  assert.equal(terminalSupervisorProbes, 0);
});

test("execution status counts malformed claim entries as unknown", (t) => {
  const { paths } = fixture(t);
  executionStatus({ paths });
  fs.writeFileSync(path.join(paths.executionClaims, "unexpected.json"), "{}\n", { mode: 0o600 });
  const status = executionStatus({ paths });
  assert.equal(status.counts.unknown, 1);
  assert.deepEqual(status.recent, []);
});

test("evidence limiting durably records a bounded prefix and terminal audit", async (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const scope = approve(paths, root, { id: "evidence-cap", target: "127.0.0.1" });
  const script = "process.stdout.write(Buffer.alloc(2*1024*1024,120));setInterval(()=>{},1000);";
  const created = createExecutionManifest(scope.id, manifestInput(scope, ["-e", script, "{{GATE_TARGET}}"]), {
    paths,
    resolveTool: resolver(scope.toolId)
  });
  const result = await withTimeout(executeExecutionManifest(scope.id, {
    manifestId: created.manifestId,
    confirm: created.confirmationRequired
  }, { paths, pollIntervalMs: 20, terminationGraceMs: 50 }), 10_000);
  assert.equal(result.status, "failed");
  assert.equal(result.terminationReason, "evidence-limit");
  assert.equal(result.evidence.stdout.available, true);
  assert.ok(result.evidence.stdout.bytes > 0);
  assert.ok(result.evidence.stdout.bytes <= 1024 * 1024);
  assert.equal(fs.statSync(evidenceFile(paths, result.evidence.stdout.ref)).size, result.evidence.stdout.bytes);
  const events = fs.readFileSync(paths.events, "utf8").trim().split("\n").map((line) => JSON.parse(line));
  const terminal = events.filter((event) => event.runId === created.runId).at(-1);
  assert.equal(terminal.kind, "execution.completed");
  assert.equal(terminal.status, "failed");
});

test("authorization revocation polling terminates the authenticated process group", async (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const scope = approve(paths, root, {
    id: "revoke-running", target: "127.0.0.1", finishFeedback: false
  });
  const script = "process.on('SIGTERM',()=>{});setInterval(()=>{},1000);";
  const created = createExecutionManifest(scope.id, manifestInput(scope, ["-e", script, "{{GATE_TARGET}}"]), {
    paths,
    resolveTool: resolver(scope.toolId)
  });
  const executing = executeExecutionManifest(scope.id, {
    manifestId: created.manifestId,
    confirm: created.confirmationRequired
  }, { paths, pollIntervalMs: 20, terminationGraceMs: 50 });
  const runFile = path.join(paths.executionRuns, `${created.runId}.json`);
  const running = await waitFor(() => {
    try {
      const value = JSON.parse(fs.readFileSync(runFile, "utf8"));
      return value.status === "running" ? value : null;
    } catch {
      return null;
    }
  });
  revokeEngagement(scope.id, { confirm: `REVOKE ${scope.id}` }, { paths });
  const result = await withTimeout(executing, 10_000);
  assert.equal(result.status, "cancelled");
  assert.equal(result.terminationReason, "engagement-invalidated");
  assert.equal(nonZombie(running.process.pid), false);
});

test("operator stop kills a TERM-resistant same-session grandchild before returning", async (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const scope = approve(paths, root, { id: "group-stop", target: "127.0.0.1" });
  const grandchild = "process.on('SIGTERM',()=>{});setInterval(()=>{},1000);";
  const leader = [
    "const {spawn}=require('node:child_process');",
    `const child=spawn(process.execPath,['-e',${JSON.stringify(grandchild)}],{stdio:'ignore'});`,
    "process.stdout.write(String(child.pid)+'\\n');",
    "process.on('SIGTERM',()=>process.exit(0));",
    "setInterval(()=>{},1000);"
  ].join("");
  const created = createExecutionManifest(scope.id, manifestInput(scope, ["-e", leader, "{{GATE_TARGET}}"]), {
    paths,
    resolveTool: resolver(scope.toolId)
  });
  const executing = executeExecutionManifest(scope.id, {
    manifestId: created.manifestId,
    confirm: created.confirmationRequired
  }, { paths, pollIntervalMs: 20, terminationGraceMs: 80 });
  const runFile = path.join(paths.executionRuns, `${created.runId}.json`);
  await waitFor(() => fs.existsSync(runFile) && JSON.parse(fs.readFileSync(runFile, "utf8")).status === "running");
  const stdoutFile = path.join(paths.evidence, `execution-${created.runId}-stdout.bin`);
  const grandchildPid = await waitFor(() => {
    try {
      const value = Number(fs.readFileSync(stdoutFile, "utf8").trim());
      return Number.isSafeInteger(value) && value > 1 ? value : null;
    } catch {
      return null;
    }
  });
  requestExecutionStop(scope.id, { runId: created.runId }, { paths });
  const result = await withTimeout(executing, 10_000);
  assert.equal(result.status, "cancelled");
  assert.equal(result.terminationReason, "operator-stop");
  assert.equal(nonZombie(grandchildPid), false);
});

test("a leader cannot report success while a same-session descendant survives", async (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const scope = approve(paths, root, { id: "completion-escape", target: "127.0.0.1" });
  const grandchild = "process.on('SIGTERM',()=>{});setInterval(()=>{},1000);";
  const leader = [
    "const {spawn}=require('node:child_process');",
    `const child=spawn(process.execPath,['-e',${JSON.stringify(grandchild)}],{stdio:'ignore'});`,
    "child.unref();",
    "process.stdout.write(String(child.pid)+'\\n');"
  ].join("");
  const created = createExecutionManifest(scope.id, manifestInput(scope, ["-e", leader, "{{GATE_TARGET}}"]), {
    paths,
    resolveTool: resolver(scope.toolId)
  });
  const result = await withTimeout(executeExecutionManifest(scope.id, {
    manifestId: created.manifestId,
    confirm: created.confirmationRequired
  }, { paths, pollIntervalMs: 20, terminationGraceMs: 50 }), 10_000);
  const grandchildPid = Number(fs.readFileSync(evidenceFile(paths, result.evidence.stdout.ref), "utf8").trim());
  assert.equal(result.status, "cancelled");
  assert.equal(result.terminationReason, "process-group-remained");
  assert.equal(nonZombie(grandchildPid), false);
});

test("post-spawn supervisor failure awaits SIGKILL for a TERM-resistant tool", async (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const scope = approve(paths, root, { id: "spawn-failure", target: "127.0.0.1" });
  const script = "process.on('SIGTERM',()=>{});setInterval(()=>{},1000);";
  const created = createExecutionManifest(scope.id, manifestInput(scope, ["-e", script, "{{GATE_TARGET}}"]), {
    paths,
    resolveTool: resolver(scope.toolId)
  });
  let pid;
  await assert.rejects(withTimeout(executeExecutionManifest(scope.id, {
    manifestId: created.manifestId,
    confirm: created.confirmationRequired
  }, {
    paths,
    pollIntervalMs: 20,
    terminationGraceMs: 50,
    afterSpawn(value) {
      pid = value.pid;
      throw new Error("injected post-spawn failure");
    }
  }), 10_000), /injected post-spawn failure/);
  assert.equal(nonZombie(pid), false);
  assert.equal(JSON.parse(fs.readFileSync(path.join(paths.executionRuns, `${created.runId}.json`), "utf8")).status, "failed");
});

test("audit effect uses the higher catalog risk and stale supervisors project unknown", async (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const scope = approve(paths, root, {
    id: "risk-floor",
    target: "127.0.0.1",
    action: "observe"
  });
  const created = createExecutionManifest(scope.id, manifestInput(scope, ["-e", "process.exit(0)", "{{GATE_TARGET}}"]), {
    paths,
    resolveTool: resolver(scope.toolId, process.execPath, "A3")
  });
  await withTimeout(executeExecutionManifest(scope.id, {
    manifestId: created.manifestId,
    confirm: created.confirmationRequired
  }, { paths }));
  const events = fs.readFileSync(paths.events, "utf8").trim().split("\n").map((line) => JSON.parse(line));
  const executionEvents = events.filter((event) => event.runId === created.runId);
  assert.ok(executionEvents.length >= 3);
  assert.ok(executionEvents.every((event) => event.effect.class === "high-impact"));

  const runFile = path.join(paths.executionRuns, `${created.runId}.json`);
  const stale = JSON.parse(fs.readFileSync(runFile, "utf8"));
  stale.status = "queued";
  stale.startedAt = null;
  stale.finishedAt = null;
  stale.process = null;
  stale.terminationReason = null;
  stale.result = { exitCode: null, signal: null, durationMs: null };
  stale.evidence.stdout = { ...stale.evidence.stdout, available: false, sha256: null, bytes: 0 };
  stale.evidence.stderr = { ...stale.evidence.stderr, available: false, sha256: null, bytes: 0 };
  stale.evidence.resultAvailable = false;
  stale.supervisor.startTimeTicks = String(BigInt(stale.supervisor.startTimeTicks) + 1n);
  fs.writeFileSync(runFile, `${JSON.stringify(stale, null, 2)}\n`, { mode: 0o600 });
  const status = executionStatus({ paths });
  assert.equal(status.recent[0].status, "unknown");
  assert.equal(status.counts.unknown, 1);
});
