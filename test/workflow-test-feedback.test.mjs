import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { runtimePaths } from "../src/lib/paths.mjs";
import {
  addLearningCycle,
  consultLearnings,
  learningCandidateSha256,
  promoteLearning
} from "../src/lib/learnings.mjs";
import {
  approveEngagement,
  attachPlan,
  checkEngagement,
  createEngagement,
  recordTechnicalReview
} from "../src/lib/engagements.mjs";
import {
  addWorkflowEvidence,
  cancelWorkflowExecution,
  claimWorkflowExecution,
  completeWorkflowExecution,
  createWorkflowInstance,
  finishWorkflowPhase,
  planWorkflowTest,
  reserveWorkflowExecution,
  reviewWorkflowTest,
  startWorkflowPhase,
  workflowRuntimeInternals,
  workflowStatus
} from "../src/lib/workflow-runtime.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const requestId = (digit) => `wreq_${digit.repeat(32)}`;
const definition = JSON.parse(fs.readFileSync(path.join(repo, "config", "workflows", "pentest-e2e.json"), "utf8"));
function learningApplicability(paths, phaseId, toolId = null) {
  const definition = workflowRuntimeInternals.loadDefinition(paths);
  return [
    {
      kind: "workflow",
      id: definition.value.metadata.id,
      version: String(definition.value.metadata.version),
      digest: definition.contractSha256
    },
    { kind: "phase", id: phaseId },
    ...(toolId ? [{ kind: "tool", id: toolId }] : [])
  ];
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-workflow-feedback-"));
  const paths = {
    ...runtimePaths({ home: path.join(root, "home"), repo }),
    publicLearningRecords: path.join(root, "memory", "learnings.jsonl"),
    publicLearnings: path.join(root, "memory", "LEARNINGS.md")
  };
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, paths };
}

function beginPhase(id, paths) {
  createWorkflowInstance(id, {}, { paths });
  return startWorkflowPhase(id, { phaseId: "authorization-and-roe" }, { paths }).projection.activePhase;
}

function planInput(active, paths, overrides = {}) {
  const applicability = learningApplicability(paths, active.phaseId, active.toolId);
  const consultation = consultLearnings({ applicability }, { paths });
  return {
    phaseId: active.phaseId,
    attemptId: active.attemptId,
    hypothesis: "A bounded fixture condition may produce the expected signal.",
    method: "Exercise one local fixture branch and preserve its exact output.",
    expectedSignal: "The fixture emits the expected marker.",
    contrarySignal: "The fixture omits the marker or emits a contradictory marker.",
    learningApplicability: applicability,
    learningIds: consultation.selected.map((learning) => learning.id),
    learningLedgerHeadSha256: consultation.ledgerHeadSha256,
    learningProjectionSha256: consultation.projectionSha256,
    basisEvidenceSha256: [],
    priorReviewEntrySha256: null,
    adaptation: null,
    ...overrides
  };
}

function reviewInput(plan, overrides = {}) {
  return {
    testId: plan.entry.payload.testId,
    phaseId: plan.entry.payload.phaseId,
    attemptId: plan.entry.payload.attemptId,
    planEntrySha256: plan.entry.entrySha256,
    disposition: "inconclusive",
    observation: "The fixture produced a stable response without the discriminating marker.",
    evidenceSha256: [],
    metrics: { "duration-ms": 14, requests: "unavailable" },
    usefulMistake: {
      cause: "The first method could not distinguish the two candidate explanations.",
      change: "Vary one fixture state at a time in the next test."
    },
    nextStrategy: {
      decision: "iterate-within-current-envelope",
      rationale: "Change one state variable while retaining the same workflow authority."
    },
    ...overrides
  };
}

function writeJson(root, name, value) {
  const file = path.join(root, name);
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  return file;
}

function rewriteWorkflowJournal(paths, id, edit) {
  const files = workflowRuntimeInternals.workflowPaths(paths, id);
  const entries = fs.readFileSync(files.workflowJournal, "utf8").trimEnd().split("\n").map(JSON.parse);
  const originalPayloads = entries.map((entry) =>
    workflowRuntimeInternals.canonicalDigest(entry.payload, "gate.workflow.test-payload.v1"));
  edit(entries);
  let previousEntrySha256 = null;
  entries.forEach((entry, sequence) => {
    entry.sequence = sequence;
    entry.previousEntrySha256 = previousEntrySha256;
    if (!originalPayloads[sequence] || originalPayloads[sequence] !==
      workflowRuntimeInternals.canonicalDigest(entry.payload, "gate.workflow.test-payload.v1")) {
      entry.requestSha256 = workflowRuntimeInternals.canonicalDigest(
        { type: entry.type, payload: entry.payload }, "gate.workflow.request.v1"
      );
    }
    entry.entrySha256 = workflowRuntimeInternals.entryDigest(entry);
    previousEntrySha256 = entry.entrySha256;
  });
  fs.writeFileSync(files.workflowJournal, `${entries.map((entry) => JSON.stringify(entry)).join("\n")}\n`, {
    mode: 0o600
  });
  fs.rmSync(files.workflowProjection, { force: true });
  return files;
}

function approve(root, paths, id, target) {
  createEngagement({
    id,
    targets: [target],
    actions: ["observe"],
    tools: ["dnsx"],
    environment: "host",
    maxMinutes: 30,
    maxRequests: 500,
    maxParallel: 4,
    maxRate: 20,
    maxTokens: 100_000,
    allowedDestinations: ["gate-home"]
  }, { paths });
  const planFile = path.join(root, `${id}-plan.md`);
  fs.writeFileSync(planFile, `# ${id}\n\nSynthetic workflow feedback fixture.\n`, { mode: 0o600 });
  const attached = attachPlan(id, planFile, { paths });
  recordTechnicalReview(id, { run: `no-mistakes/${id}`, headSha: "a".repeat(40), status: "passed" }, { paths });
  approveEngagement(id, { sha256: attached.plan.sha256, confirm: `APPROVE ${id}` }, { paths });
}

function addEvidence(root, paths, workflowId, phaseId, evidenceId, claimState, suffix, suppliedBytes = null) {
  const bytes = suppliedBytes || Buffer.from(`${phaseId}:${evidenceId}:${suffix}\n`);
  const file = path.join(root, `${phaseId}-${evidenceId}-${suffix}.txt`);
  fs.writeFileSync(file, bytes, { mode: 0o600 });
  addWorkflowEvidence(workflowId, { phaseId, evidenceId, claimState, file }, { paths });
  return sha256(bytes);
}

function completeFoundation(root, paths, workflowId) {
  for (const phaseId of ["authorization-and-roe", "target-and-architecture-map"]) {
    startWorkflowPhase(workflowId, {
      phaseId,
      ...(phaseId === "target-and-architecture-map" ? { sourcePhase: "authorization-and-roe" } : {})
    }, { paths });
    const phase = definition.phases.find((candidate) => candidate.id === phaseId);
    for (const expected of phase.evidence.filter((item) => item.required)) {
      addEvidence(root, paths, workflowId, phaseId, expected.id, expected.claimState, "foundation");
    }
    finishWorkflowPhase(workflowId, { phaseId, disposition: "tested" }, { paths });
  }
}

function activeSurfaceAdmission(root, paths, workflowId, engagementId, target) {
  const phase = definition.phases.find((candidate) => candidate.id === "active-surface-validation");
  const mapping = phase.toolMappings.find((candidate) => candidate.toolId === "dnsx");
  const envelope = {
    maxMinutes: 5,
    maxRequests: 20,
    maxRatePerSecond: 5,
    maxParallel: 1,
    maxInputTokens: 0,
    maxOutputTokens: 0,
    maxTotalTokens: 10_000,
    maxEvidenceBytes: 4 * 1024 * 1024,
    maxSpend: 0,
    controls: {
      wallTime: "measured-only",
      requests: "measured-only",
      rate: "unavailable",
      parallel: "unavailable",
      tokens: "unavailable",
      evidenceBytes: "enforced",
      spend: "unavailable"
    }
  };
  const checked = checkEngagement(engagementId, {
    target,
    action: "observe",
    maxMinutes: envelope.maxMinutes,
    estimatedRequests: envelope.maxRequests,
    maxParallel: envelope.maxParallel,
    maxRatePerSecond: envelope.maxRatePerSecond,
    maxTokens: envelope.maxTotalTokens
  }, { paths });
  assert.equal(checked.allowed, true, checked.reasons?.join("; "));
  const authority = checked.executionBinding;
  const status = workflowStatus(workflowId, { paths });
  const admission = {
    $schema: "../../schemas/workflow-admission.schema.json",
    apiVersion: "gate.workflow-admission/v1",
    kind: "WorkflowAdmission",
    instanceId: workflowId,
    workflowDefinitionSha256: status.contract.sha256,
    phaseId: phase.id,
    target,
    action: "observe",
    toolId: "dnsx",
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
    envelope,
    issuedAt: new Date(Date.now() - 1_000).toISOString(),
    expiresAt: authority.authorizationValidUntil
  };
  return { file: writeJson(root, "feedback-admission.json", admission), envelope };
}

function promoteFixtureLearning(paths, domain, applicability, overrides = {}) {
  const candidate = addLearningCycle({
    trigger: "test-outcome",
    domain,
    applicability,
    cycle: {
      hypothesis: "A deterministic workflow fixture can isolate the behavior.",
      method: "Run the focused workflow fixture once.",
      outcome: { disposition: "confirmed", summary: "The fixture isolated the behavior." },
      lesson: `Use the focused ${domain} fixture before broad execution.`,
      nextAdjustment: `Consult the ${domain} fixture result before the next test.`
    }
  }, { paths });
  return promoteLearning(candidate.id, {
    sensitivity: "public",
    validationRefs: [`evidence://test/workflow-feedback-${domain}`],
    changeRefs: [`evidence://test/workflow-feedback-${domain}`],
    review: {
      owner: "no-mistakes",
      attestationRef: `evidence://no-mistakes/workflow-feedback-${domain}`,
      attestationSha256: "b".repeat(64),
      candidateSha256: learningCandidateSha256(candidate),
      headSha: "c".repeat(40)
    },
    ...overrides
  }, { paths });
}

test("workflow test feedback is hash-chained, replayable, and absent from compact narratives", (t) => {
  const { paths } = fixture(t);
  const id = "feedback-lifecycle";
  const active = beginPhase(id, paths);
  const privateHypothesis = "A private-only hypothesis marker may distinguish the fixture response.";
  const privateObservation = "A private-only observation marker showed the response stayed ambiguous.";
  const input = planInput(active, paths, { hypothesis: privateHypothesis });
  const options = { paths, requestId: requestId("1") };

  const planned = planWorkflowTest(id, input, options);
  assert.equal(planned.entry.type, "test.planned");
  assert.match(planned.entry.payload.testId, /^wtest_[a-f0-9]{32}$/u);
  assert.equal(planned.projection.activePhase.tests[planned.entry.payload.testId].planEntrySha256,
    planned.entry.entrySha256);
  assert.equal(planned.entry.payload.learningLedgerHeadSha256, input.learningLedgerHeadSha256);
  assert.equal(planned.entry.payload.learningProjectionSha256, input.learningProjectionSha256);

  const replayedPlan = planWorkflowTest(id, structuredClone(input), options);
  assert.equal(replayedPlan.replayed, true);
  assert.equal(replayedPlan.entry.entrySha256, planned.entry.entrySha256);
  assert.equal(replayedPlan.entry.payload.testId, planned.entry.payload.testId);

  const reviewed = reviewWorkflowTest(id, reviewInput(planned, { observation: privateObservation }), {
    paths,
    requestId: requestId("2")
  });
  assert.equal(reviewed.entry.type, "test.reviewed");
  const record = reviewed.projection.phases[active.phaseId].tests[planned.entry.payload.testId];
  assert.equal(record.status, "reviewed");
  assert.equal(record.review.reviewEntrySha256, reviewed.entry.entrySha256);
  assert.deepEqual(record.review.metrics, { "duration-ms": 14, requests: "unavailable" });

  const compact = workflowStatus(id, { paths });
  assert.deepEqual(compact.testFeedback, {
    total: 1,
    reviewed: 1,
    open: 0,
    openTestId: null,
    latestReviewSha256: reviewed.entry.entrySha256
  });
  const visible = JSON.stringify(compact);
  assert.equal(visible.includes(privateHypothesis), false);
  assert.equal(visible.includes(privateObservation), false);
  assert.equal(visible.includes(record.method), false);
  assert.equal(visible.includes(record.review.usefulMistake.cause), false);
  assert.equal(visible.includes(input.learningLedgerHeadSha256), false);
  assert.equal(visible.includes(input.learningProjectionSha256), false);

  const projection = path.join(paths.workflows, id, "instance.json");
  fs.unlinkSync(projection);
  const rebuilt = workflowStatus(id, { paths });
  assert.equal(rebuilt.ok, true);
  assert.deepEqual(rebuilt.testFeedback, compact.testFeedback);
  const rebuiltProjection = JSON.parse(fs.readFileSync(projection, "utf8"));
  assert.equal(rebuiltProjection.phases[active.phaseId].tests[planned.entry.payload.testId]
    .review.reviewEntrySha256, reviewed.entry.entrySha256);
});

test("test plans freeze the exact conflict-free learning consultation", (t) => {
  const compatible = fixture(t);
  const compatibleApplicability = learningApplicability(compatible.paths, "authorization-and-roe");
  promoteFixtureLearning(compatible.paths, "active-testing", compatibleApplicability);
  promoteFixtureLearning(compatible.paths, "tooling", compatibleApplicability);
  const active = beginPhase("feedback-consultation", compatible.paths);
  const fresh = planInput(active, compatible.paths);
  assert.equal(fresh.learningIds.length, 2);
  assert.throws(() => planWorkflowTest("feedback-consultation", {
    ...fresh,
    learningIds: [...fresh.learningIds].reverse()
  }, { paths: compatible.paths }), /selection and order/u);
  assert.throws(() => planWorkflowTest("feedback-consultation", {
    ...fresh,
    learningProjectionSha256: "f".repeat(64)
  }, { paths: compatible.paths }), /differs from the fresh consultation/u);
  assert.throws(() => planWorkflowTest("feedback-consultation", {
    ...fresh,
    learningApplicability: fresh.learningApplicability.map((reference) =>
      reference.kind === "workflow" ? { ...reference, version: "1" } : reference)
  }, { paths: compatible.paths }), /exact active workflow reference/u);
  assert.throws(() => planWorkflowTest("feedback-consultation", {
    ...fresh,
    learningApplicability: fresh.learningApplicability.filter((reference) => reference.kind !== "phase")
  }, { paths: compatible.paths }), /exact active phase reference/u);
  const paddedApplicability = [
    ...fresh.learningApplicability,
    { kind: "environment", id: "invented-learning-bypass" }
  ];
  const paddedConsultation = consultLearnings({ applicability: paddedApplicability }, { paths: compatible.paths });
  assert.equal(paddedConsultation.selected.length, 0);
  assert.throws(() => planWorkflowTest("feedback-consultation", {
    ...fresh,
    learningApplicability: paddedApplicability,
    learningIds: paddedConsultation.selected.map((learning) => learning.id),
    learningLedgerHeadSha256: paddedConsultation.ledgerHeadSha256,
    learningProjectionSha256: paddedConsultation.projectionSha256
  }, { paths: compatible.paths }), /exactly match the runtime-derived active context/u);
  const accepted = planWorkflowTest("feedback-consultation", fresh, { paths: compatible.paths });
  assert.deepEqual(accepted.entry.payload.learningIds, fresh.learningIds);
  assert.deepEqual(new Set(accepted.entry.payload.learningApplicability.map((item) => item.id)),
    new Set(["authorization-and-roe", "pentest-e2e"]));

  const truncated = fixture(t);
  const truncatedApplicability = learningApplicability(truncated.paths, "authorization-and-roe");
  for (let index = 0; index < 9; index += 1) {
    promoteFixtureLearning(truncated.paths, "active-testing", truncatedApplicability);
  }
  const truncatedActive = beginPhase("feedback-truncated", truncated.paths);
  const incomplete = planInput(truncatedActive, truncated.paths);
  assert.equal(incomplete.learningIds.length, 8);
  assert.throws(() => planWorkflowTest("feedback-truncated", incomplete, { paths: truncated.paths }),
    /consultation is incomplete/u);

  const conflicted = fixture(t);
  const conflictedApplicability = learningApplicability(conflicted.paths, "authorization-and-roe");
  const left = promoteFixtureLearning(conflicted.paths, "active-testing", conflictedApplicability);
  promoteFixtureLearning(conflicted.paths, "active-testing", conflictedApplicability, { conflictsWith: [left.id] });
  const conflictActive = beginPhase("feedback-conflict", conflicted.paths);
  assert.throws(() => planWorkflowTest("feedback-conflict",
    planInput(conflictActive, conflicted.paths), { paths: conflicted.paths }),
  /consultation has unresolved conflicts/u);
});

test("one open cycle is allowed and each later plan binds the exact prior review", (t) => {
  const { paths } = fixture(t);
  const id = "feedback-sequencing";
  const active = beginPhase(id, paths);
  assert.throws(
    () => planWorkflowTest(id, planInput(active, paths, {
      learningLedgerHeadSha256: null,
      learningProjectionSha256: null
    }), { paths }),
    /learning ledger head digest is invalid/u
  );
  assert.throws(
    () => planWorkflowTest(id, planInput(active, paths, {
      learningIds: ["lrn_alpha1"]
    }), { paths }),
    /do not match the fresh consultation selection and order/u
  );
  const first = planWorkflowTest(id, planInput(active, paths), { paths });

  assert.throws(
    () => planWorkflowTest(id, planInput(active, paths), { paths }),
    /already has an open test cycle/u
  );
  assert.throws(
    () => reviewWorkflowTest(id, reviewInput(first, { planEntrySha256: "a".repeat(64) }), { paths }),
    /exact plan entry/u
  );
  assert.throws(
    () => finishWorkflowPhase(id, {
      phaseId: active.phaseId,
      disposition: "blocked",
      rationale: "The fixture phase cannot finish while its feedback cycle remains open."
    }, { paths }),
    /test cycle is open/u
  );

  const review = reviewWorkflowTest(id, reviewInput(first), { paths });
  assert.throws(
    () => planWorkflowTest(id, planInput(active, paths), { paths }),
    /exact latest review entry/u
  );
  assert.throws(
    () => planWorkflowTest(id, planInput(active, paths, {
      priorReviewEntrySha256: "b".repeat(64),
      adaptation: "Vary one fixture state."
    }), { paths }),
    /exact latest review entry/u
  );
  assert.throws(
    () => planWorkflowTest(id, planInput(active, paths, {
      priorReviewEntrySha256: review.entry.entrySha256
    }), { paths }),
    /requires an adaptation/u
  );

  const second = planWorkflowTest(id, planInput(active, paths, {
    priorReviewEntrySha256: review.entry.entrySha256,
    adaptation: "Vary only the fixture state identified by the prior review.",
    hypothesis: "The varied fixture state may now expose the discriminating marker."
  }), { paths });
  assert.equal(second.entry.payload.priorReviewEntrySha256, review.entry.entrySha256);
  assert.equal(workflowStatus(id, { paths }).testFeedback.openTestId, second.entry.payload.testId);
});

test("journal replay rejects a test plan whose active applicability was rewritten", (t) => {
  const { paths } = fixture(t);
  const id = "feedback-replay-applicability";
  const active = beginPhase(id, paths);
  planWorkflowTest(id, planInput(active, paths), { paths });
  const files = workflowRuntimeInternals.workflowPaths(paths, id);
  const entries = fs.readFileSync(files.workflowJournal, "utf8").trimEnd().split("\n").map(JSON.parse);
  const planned = entries.at(-1);
  planned.payload.learningApplicability = planned.payload.learningApplicability.map((reference) =>
    reference.kind === "phase" ? { ...reference, id: "wrong-phase" } : reference);
  planned.requestSha256 = workflowRuntimeInternals.canonicalDigest(
    { type: planned.type, payload: planned.payload }, "gate.workflow.request.v1"
  );
  planned.entrySha256 = workflowRuntimeInternals.entryDigest(planned);
  fs.writeFileSync(files.workflowJournal, `${entries.map((entry) => JSON.stringify(entry)).join("\n")}\n`, {
    mode: 0o600
  });
  fs.unlinkSync(files.workflowProjection);

  const replayed = workflowStatus(id, { paths });
  assert.equal(replayed.ok, false);
  assert.match(replayed.blocker, /exact active phase reference/u);
});

test("journal replay verifies the exact historical learning consultation", (t) => {
  const { paths } = fixture(t);
  const id = "feedback-replay-consultation";
  const applicability = learningApplicability(paths, "authorization-and-roe");
  promoteFixtureLearning(paths, "active-testing", applicability);
  const active = beginPhase(id, paths);
  const input = planInput(active, paths);
  assert.equal(input.learningIds.length, 1);
  planWorkflowTest(id, input, { paths });
  const files = workflowRuntimeInternals.workflowPaths(paths, id);
  const entries = fs.readFileSync(files.workflowJournal, "utf8").trimEnd().split("\n").map(JSON.parse);
  const planned = entries.at(-1);
  planned.payload.learningIds = [];
  planned.payload.learningProjectionSha256 = "b".repeat(64);
  planned.requestSha256 = workflowRuntimeInternals.canonicalDigest(
    { type: planned.type, payload: planned.payload }, "gate.workflow.request.v1"
  );
  planned.entrySha256 = workflowRuntimeInternals.entryDigest(planned);
  fs.writeFileSync(files.workflowJournal, `${entries.map((entry) => JSON.stringify(entry)).join("\n")}\n`, {
    mode: 0o600
  });
  fs.unlinkSync(files.workflowProjection);

  const replayed = workflowStatus(id, { paths });
  assert.equal(replayed.ok, false);
  assert.match(replayed.blocker, /learning ids do not match the historical projection/u);
});

test("journal replay rejects completion without a prior bound claim", (t) => {
  const { root, paths } = fixture(t);
  const id = "feedback-replay-completion";
  const target = "127.0.0.1";
  createWorkflowInstance(id, {}, { paths });
  completeFoundation(root, paths, id);
  approve(root, paths, "feedback-replay-authority", target);
  const admission = activeSurfaceAdmission(root, paths, id, "feedback-replay-authority", target);
  const started = startWorkflowPhase(id, {
    phaseId: "active-surface-validation",
    sourcePhase: "target-and-architecture-map",
    admissionFile: admission.file
  }, { paths });
  planWorkflowTest(id, planInput(started.projection.activePhase, paths), { paths });
  const reservation = reserveWorkflowExecution(id, {
    phaseAttemptId: started.projection.activePhase.attemptId,
    manifestId: `xmf_${"d".repeat(32)}`,
    runId: `xrun_${"d".repeat(32)}`,
    target,
    action: "observe",
    toolId: "dnsx",
    envelope: admission.envelope
  }, { paths });
  const files = workflowRuntimeInternals.workflowPaths(paths, id);
  const entries = fs.readFileSync(files.workflowJournal, "utf8").trimEnd().split("\n").map(JSON.parse);
  const previous = entries.at(-1);
  const payload = {
    reservationId: reservation.reservationId,
    manifestId: reservation.manifestId,
    manifestSha256: "e".repeat(64),
    runId: reservation.runId,
    status: "succeeded",
    runSha256: "f".repeat(64),
    resultSha256: "1".repeat(64),
    terminationReason: "forged completion without a claim"
  };
  const forged = {
    apiVersion: "gate.workflow-journal/v1",
    kind: "WorkflowJournalEntry",
    instanceId: id,
    sequence: previous.sequence + 1,
    at: new Date().toISOString(),
    requestId: `wreq_${"d".repeat(32)}`,
    requestSha256: workflowRuntimeInternals.canonicalDigest(
      { type: "execution.completed", payload }, "gate.workflow.request.v1"
    ),
    type: "execution.completed",
    definitionSha256: previous.definitionSha256,
    previousEntrySha256: previous.entrySha256,
    payload,
    entrySha256: "0".repeat(64)
  };
  forged.entrySha256 = workflowRuntimeInternals.entryDigest(forged);
  fs.appendFileSync(files.workflowJournal, `${JSON.stringify(forged)}\n`, { mode: 0o600 });
  fs.unlinkSync(files.workflowProjection);

  const replayed = workflowStatus(id, { paths });
  assert.equal(replayed.ok, false);
  assert.match(replayed.blocker, /does not bind a claimed execution/u);
});

test("v2 replay derives phase admission, budget, and evidence from durable records", (t) => {
  const tamperedStart = fixture(t);
  const target = "127.0.0.1";
  const startId = "feedback-replay-phase-start";
  createWorkflowInstance(startId, {}, { paths: tamperedStart.paths });
  completeFoundation(tamperedStart.root, tamperedStart.paths, startId);
  approve(tamperedStart.root, tamperedStart.paths, "feedback-replay-start-authority", target);
  const startAdmission = activeSurfaceAdmission(
    tamperedStart.root,
    tamperedStart.paths,
    startId,
    "feedback-replay-start-authority",
    target
  );
  startWorkflowPhase(startId, {
    phaseId: "active-surface-validation",
    sourcePhase: "target-and-architecture-map",
    admissionFile: startAdmission.file
  }, { paths: tamperedStart.paths });
  rewriteWorkflowJournal(tamperedStart.paths, startId, (entries) => {
    entries.find((entry) => entry.type === "phase.started" &&
      entry.payload.phaseId === "active-surface-validation").payload.targetContact = false;
  });
  const replayedStart = workflowStatus(startId, { paths: tamperedStart.paths });
  assert.equal(replayedStart.ok, false);
  assert.match(replayedStart.blocker, /installed phase: targetContact/u);

  const tamperedBudget = fixture(t);
  const budgetId = "feedback-replay-budget";
  createWorkflowInstance(budgetId, {}, { paths: tamperedBudget.paths });
  completeFoundation(tamperedBudget.root, tamperedBudget.paths, budgetId);
  approve(tamperedBudget.root, tamperedBudget.paths, "feedback-replay-budget-authority", target);
  const budgetAdmission = activeSurfaceAdmission(
    tamperedBudget.root,
    tamperedBudget.paths,
    budgetId,
    "feedback-replay-budget-authority",
    target
  );
  startWorkflowPhase(budgetId, {
    phaseId: "active-surface-validation",
    sourcePhase: "target-and-architecture-map",
    admissionFile: budgetAdmission.file
  }, { paths: tamperedBudget.paths });
  rewriteWorkflowJournal(tamperedBudget.paths, budgetId, (entries) => {
    const started = entries.find((entry) => entry.type === "phase.started" &&
      entry.payload.phaseId === "active-surface-validation");
    started.payload.budget.total.maxRequests = 999_999_999;
    started.payload.budget.used.maxRequests = 0;
    started.payload.budget.cleanup.maxRequests = 0;
    started.payload.budget.reporting.maxRequests = 0;
  });
  const replayedBudget = workflowStatus(budgetId, { paths: tamperedBudget.paths });
  assert.equal(replayedBudget.ok, false);
  assert.match(replayedBudget.blocker, /budget differs from the approved engagement allocation/u);

  const missingEvidence = fixture(t);
  const evidenceId = "feedback-replay-evidence";
  const active = beginPhase(evidenceId, missingEvidence.paths);
  const digest = addEvidence(missingEvidence.root, missingEvidence.paths, evidenceId, active.phaseId,
    "authorization-evidence", "observed", "pre-plan");
  const evidenceFiles = workflowRuntimeInternals.workflowPaths(missingEvidence.paths, evidenceId);
  fs.unlinkSync(path.join(evidenceFiles.workflowEvidence, `${digest}.bin`));
  fs.unlinkSync(evidenceFiles.workflowProjection);
  const replayedEvidence = workflowStatus(evidenceId, { paths: missingEvidence.paths });
  assert.equal(replayedEvidence.ok, false);
  assert.match(replayedEvidence.blocker, /workflow evidence|no such file/u);
});

test("v2 replay rejects a direct disposition that live phase finish rejects", (t) => {
  const { paths } = fixture(t);
  const id = "feedback-replay-phase-finish";
  createWorkflowInstance(id, {}, { paths });
  rewriteWorkflowJournal(paths, id, (entries) => {
    const previous = entries.at(-1);
    entries.push({
      apiVersion: "gate.workflow-journal/v1",
      kind: "WorkflowJournalEntry",
      instanceId: id,
      sequence: previous.sequence + 1,
      at: new Date().toISOString(),
      requestId: `wreq_${"e".repeat(32)}`,
      requestSha256: "0".repeat(64),
      type: "phase.finished",
      definitionSha256: previous.definitionSha256,
      previousEntrySha256: previous.entrySha256,
      payload: {
        phaseId: "authorization-and-roe",
        attemptId: `wpa_${"e".repeat(32)}`,
        direct: true,
        disposition: "blocked",
        rationale: "A forged direct disposition must not bypass an always phase.",
        evidenceSha256: []
      },
      entrySha256: "0".repeat(64)
    });
  });
  const replayed = workflowStatus(id, { paths });
  assert.equal(replayed.ok, false);
  assert.match(replayed.blocker, /always phase must be started and tested/u);
});

test("target-contact execution binds one planned test and review accepts only later same-attempt evidence", (t) => {
  const { root, paths } = fixture(t);
  const id = "feedback-target-contact";
  const target = "127.0.0.1";
  createWorkflowInstance(id, {}, { paths });
  completeFoundation(root, paths, id);
  approve(root, paths, "feedback-authority", target);
  const admission = activeSurfaceAdmission(root, paths, id, "feedback-authority", target);
  const started = startWorkflowPhase(id, {
    phaseId: "active-surface-validation",
    sourcePhase: "target-and-architecture-map",
    admissionFile: admission.file
  }, { paths });
  const active = started.projection.activePhase;
  const earlyEvidence = addEvidence(root, paths, id, active.phaseId,
    "active-surface-inventory", "observed", "before-plan");
  addEvidence(root, paths, id, active.phaseId,
    "hypothesis-reconciliation", "inferred", "before-plan");

  assert.throws(() => finishWorkflowPhase(id, {
    phaseId: active.phaseId,
    disposition: "tested"
  }, { paths }), /post-completion result evidence/u);

  assert.throws(() => reserveWorkflowExecution(id, {
    phaseAttemptId: active.attemptId,
    manifestId: `xmf_${"1".repeat(32)}`,
    runId: `xrun_${"1".repeat(32)}`,
    target,
    action: "observe",
    toolId: "dnsx",
    envelope: admission.envelope
  }, { paths }), /exactly one open workflow test/u);

  const missingToolApplicability = planInput(active, paths);
  assert.throws(() => planWorkflowTest(id, {
    ...missingToolApplicability,
    learningApplicability: missingToolApplicability.learningApplicability
      .filter((reference) => reference.kind !== "tool")
  }, { paths }), /exact active tool reference/u);

  const planned = planWorkflowTest(id, planInput(active, paths, {
    basisEvidenceSha256: [earlyEvidence]
  }), { paths });
  assert.throws(() => reviewWorkflowTest(id, reviewInput(planned, {
    disposition: "blocked",
    evidenceSha256: [earlyEvidence]
  }), { paths }), /same phase attempt and follow the plan/u);
  assert.throws(() => reviewWorkflowTest(id, reviewInput(planned, {
    disposition: "inconclusive",
    evidenceSha256: []
  }), { paths }), /without an execution reservation may only be blocked or invalid-test/u);

  const reservationInput = {
    phaseAttemptId: active.attemptId,
    manifestId: `xmf_${"2".repeat(32)}`,
    runId: `xrun_${"2".repeat(32)}`,
    target,
    action: "observe",
    toolId: "dnsx",
    envelope: admission.envelope
  };
  assert.throws(() => reserveWorkflowExecution(id, {
    ...reservationInput,
    envelope: { ...admission.envelope, maxSpend: -1 }
  }, { paths }), /maxSpend is invalid/u);
  const reservation = reserveWorkflowExecution(id, reservationInput, { paths });
  assert.equal(reservation.testId, planned.entry.payload.testId);
  assert.equal(reservation.testPlanEntrySha256, planned.entry.entrySha256);
  assert.throws(() => reviewWorkflowTest(id, reviewInput(planned, {
    disposition: "blocked"
  }), { paths }), /must be terminal before review/u);
  cancelWorkflowExecution(id, {
    reservationId: reservation.reservationId,
    reason: "Synthetic fixture ends the reserved execution before review."
  }, { paths });
  assert.throws(() => reserveWorkflowExecution(id, {
    ...reservationInput,
    manifestId: `xmf_${"3".repeat(32)}`,
    runId: `xrun_${"3".repeat(32)}`
  }, { paths }), /already has an execution reservation/u);

  const laterEvidence = addEvidence(root, paths, id, active.phaseId,
    "hypothesis-reconciliation", "inferred", "after-plan");
  assert.throws(() => reviewWorkflowTest(id, reviewInput(planned, {
    disposition: "supported",
    evidenceSha256: []
  }), { paths }), /requires evidence/u);
  assert.throws(() => reviewWorkflowTest(id, reviewInput(planned, {
    disposition: "supported",
    evidenceSha256: [laterEvidence]
  }), { paths }), /successfully completed linked execution/u);
  const cancelledReview = reviewWorkflowTest(id, reviewInput(planned, {
    disposition: "inconclusive",
    evidenceSha256: [laterEvidence]
  }), { paths });
  assert.throws(() => finishWorkflowPhase(id, {
    phaseId: active.phaseId,
    disposition: "tested"
  }, { paths }), /post-completion result evidence/u);

  const secondPlan = planWorkflowTest(id, planInput(active, paths, {
    priorReviewEntrySha256: cancelledReview.entry.entrySha256,
    adaptation: "Replace the cancelled dry run with one claimed execution and inspect its terminal result."
  }), { paths });
  const secondReservation = reserveWorkflowExecution(id, {
    ...reservationInput,
    manifestId: `xmf_${"4".repeat(32)}`,
    runId: `xrun_${"4".repeat(32)}`,
    envelope: {
      maxMinutes: 1,
      maxRequests: 1,
      maxRatePerSecond: 1,
      maxParallel: 1,
      maxInputTokens: 0,
      maxOutputTokens: 0,
      maxTotalTokens: 1_000,
      maxEvidenceBytes: 1_000_000,
      maxSpend: 0
    }
  }, { paths });
  claimWorkflowExecution(id, {
    reservationId: secondReservation.reservationId,
    manifestSha256: "5".repeat(64)
  }, { paths });
  const failedResultBytes = Buffer.from("synthetic failed execution result\n");
  const failedResultSha256 = sha256(failedResultBytes);
  completeWorkflowExecution(id, {
    reservationId: secondReservation.reservationId,
    status: "failed",
    runSha256: "6".repeat(64),
    resultSha256: failedResultSha256,
    terminationReason: "Synthetic failure."
  }, { paths });
  const failedResultEvidence = addEvidence(root, paths, id, active.phaseId,
    "active-surface-inventory", "observed", "failed-execution-result", failedResultBytes);
  assert.throws(() => reviewWorkflowTest(id, reviewInput(secondPlan, {
    disposition: "contradicted",
    evidenceSha256: [failedResultEvidence]
  }), { paths }), /successfully completed linked execution/u);
  const failedReview = reviewWorkflowTest(id, reviewInput(secondPlan, {
    disposition: "inconclusive",
    evidenceSha256: [failedResultEvidence]
  }), { paths });
  assert.throws(() => finishWorkflowPhase(id, {
    phaseId: active.phaseId,
    disposition: "tested"
  }, { paths }), /post-completion result evidence/u);

  const thirdPlan = planWorkflowTest(id, planInput(active, paths, {
    priorReviewEntrySha256: failedReview.entry.entrySha256,
    adaptation: "Retry the failed execution once and require its completed result as post-run evidence."
  }), { paths });
  const thirdReservation = reserveWorkflowExecution(id, {
    ...reservationInput,
    manifestId: `xmf_${"7".repeat(32)}`,
    runId: `xrun_${"7".repeat(32)}`,
    envelope: {
      maxMinutes: 1,
      maxRequests: 1,
      maxRatePerSecond: 1,
      maxParallel: 1,
      maxInputTokens: 0,
      maxOutputTokens: 0,
      maxTotalTokens: 1_000,
      maxEvidenceBytes: 1_000_000,
      maxSpend: 0
    }
  }, { paths });
  claimWorkflowExecution(id, {
    reservationId: thirdReservation.reservationId,
    manifestSha256: "8".repeat(64)
  }, { paths });
  const resultBytes = Buffer.from("synthetic successful execution result\n");
  const resultSha256 = sha256(resultBytes);
  const prematureResultEvidence = addEvidence(root, paths, id, active.phaseId,
    "active-surface-inventory", "observed", "premature-execution-result", resultBytes);
  completeWorkflowExecution(id, {
    reservationId: thirdReservation.reservationId,
    status: "succeeded",
    runSha256: "9".repeat(64),
    resultSha256,
    terminationReason: "completed"
  }, { paths });
  assert.throws(() => reviewWorkflowTest(id, reviewInput(thirdPlan, {
    disposition: "supported",
    evidenceSha256: [prematureResultEvidence]
  }), { paths }), /recorded after and include the linked execution result/u);
  const prematureReview = reviewWorkflowTest(id, reviewInput(thirdPlan, {
    disposition: "inconclusive",
    evidenceSha256: [prematureResultEvidence]
  }), { paths });
  addEvidence(root, paths, id, active.phaseId,
    "active-surface-inventory", "observed", "retroactive-result-evidence", resultBytes);
  assert.throws(() => finishWorkflowPhase(id, {
    phaseId: active.phaseId,
    disposition: "tested"
  }, { paths }), /post-completion result evidence/u);

  const fourthPlan = planWorkflowTest(id, planInput(active, paths, {
    priorReviewEntrySha256: prematureReview.entry.entrySha256,
    adaptation: "Record the completed result into phase evidence before reviewing the retry."
  }), { paths });
  const fourthReservation = reserveWorkflowExecution(id, {
    ...reservationInput,
    manifestId: `xmf_${"a".repeat(32)}`,
    runId: `xrun_${"a".repeat(32)}`,
    envelope: {
      maxMinutes: 1,
      maxRequests: 1,
      maxRatePerSecond: 1,
      maxParallel: 1,
      maxInputTokens: 0,
      maxOutputTokens: 0,
      maxTotalTokens: 1_000,
      maxEvidenceBytes: 1_000_000,
      maxSpend: 0
    }
  }, { paths });
  claimWorkflowExecution(id, {
    reservationId: fourthReservation.reservationId,
    manifestSha256: "b".repeat(64)
  }, { paths });
  const finalResultBytes = Buffer.from("synthetic final successful execution result\n");
  const finalResultSha256 = sha256(finalResultBytes);
  completeWorkflowExecution(id, {
    reservationId: fourthReservation.reservationId,
    status: "succeeded",
    runSha256: "c".repeat(64),
    resultSha256: finalResultSha256,
    terminationReason: "completed"
  }, { paths });
  const resultEvidence = addEvidence(root, paths, id, active.phaseId,
    "active-surface-inventory", "observed", "execution-result", finalResultBytes);
  const reviewed = reviewWorkflowTest(id, reviewInput(fourthPlan, {
    disposition: "supported",
    evidenceSha256: [resultEvidence]
  }), { paths });
  assert.equal(reviewed.projection.phases[active.phaseId].tests[fourthPlan.entry.payload.testId].status, "reviewed");
  finishWorkflowPhase(id, { phaseId: active.phaseId, disposition: "tested" }, { paths });

  const projectionFile = path.join(paths.workflows, id, "instance.json");
  fs.unlinkSync(projectionFile);
  workflowStatus(id, { paths });
  const replayed = JSON.parse(fs.readFileSync(projectionFile, "utf8"));
  assert.equal(replayed.executionReservations[reservation.reservationId].testId, planned.entry.payload.testId);
  assert.equal(replayed.executionReservations[reservation.reservationId].testPlanEntrySha256,
    planned.entry.entrySha256);
  assert.equal(replayed.executionReservations[secondReservation.reservationId].testPlanEntrySha256,
    secondPlan.entry.entrySha256);
  assert.equal(replayed.executionReservations[thirdReservation.reservationId].testPlanEntrySha256,
    thirdPlan.entry.entrySha256);
  assert.equal(replayed.executionReservations[fourthReservation.reservationId].testPlanEntrySha256,
    fourthPlan.entry.entrySha256);

  const journalFile = path.join(paths.workflows, id, "journal.jsonl");
  const legacyEntries = fs.readFileSync(journalFile, "utf8").trimEnd().split("\n").map(JSON.parse)
    .filter((entry) => !entry.type.startsWith("test.") && !entry.type.startsWith("execution."));
  legacyEntries[0].payload.definition.version = 1;
  let previousEntrySha256 = null;
  legacyEntries.forEach((entry, sequence) => {
    entry.sequence = sequence;
    entry.previousEntrySha256 = previousEntrySha256;
    entry.requestSha256 = workflowRuntimeInternals.canonicalDigest(
      { type: entry.type, payload: entry.payload }, "gate.workflow.request.v1"
    );
    entry.entrySha256 = workflowRuntimeInternals.entryDigest(entry);
    previousEntrySha256 = entry.entrySha256;
  });
  fs.writeFileSync(journalFile, `${legacyEntries.map((entry) => JSON.stringify(entry)).join("\n")}\n`, {
    mode: 0o600
  });
  fs.unlinkSync(projectionFile);
  const legacyTarget = workflowStatus(id, { paths });
  assert.equal(legacyTarget.ok, false);
  assert.match(legacyTarget.blocker, /definition no longer matches the installed contract/u);
});

test("v2 evidence replay binds its journal sequence without requiring test feedback", (t) => {
  const { root, paths } = fixture(t);
  const id = "feedback-legacy";
  const active = beginPhase(id, paths);
  const expected = definition.phases.find((phase) => phase.id === active.phaseId).evidence[0];
  addEvidence(root, paths, id, active.phaseId, expected.id, expected.claimState, "legacy-evidence");
  const projection = path.join(paths.workflows, id, "instance.json");
  const existing = JSON.parse(fs.readFileSync(projection, "utf8"));
  assert.equal(Object.hasOwn(existing.evidence[0], "journalSequence"), true);
  assert.equal(workflowStatus(id, { paths }).ok, true);
  fs.unlinkSync(projection);

  const status = workflowStatus(id, { paths });
  assert.equal(status.ok, true);
  assert.deepEqual(status.testFeedback, {
    total: 0,
    reviewed: 0,
    open: 0,
    openTestId: null,
    latestReviewSha256: null
  });
  const rebuilt = JSON.parse(fs.readFileSync(projection, "utf8"));
  assert.equal(rebuilt.projectionSha256, existing.projectionSha256);
  assert.equal(Object.hasOwn(rebuilt.evidence[0], "journalSequence"), true);
  assert.equal(Object.hasOwn(rebuilt.phases[active.phaseId], "tests"), false);
  assert.equal(Object.hasOwn(rebuilt.activePhase, "tests"), false);
});
