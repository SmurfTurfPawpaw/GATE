import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  approveEngagement,
  attachPlan,
  checkEngagement,
  createEngagement,
  recordTechnicalReview
} from "../src/lib/engagements.mjs";
import { consultLearnings } from "../src/lib/learnings.mjs";
import { runtimePaths } from "../src/lib/paths.mjs";
import {
  addWorkflowEvidence,
  createWorkflowInstance,
  checkWorkflowExecution,
  claimWorkflowExecution,
  completeWorkflowExecution,
  reserveWorkflowExecution,
  finishWorkflowPhase,
  openWorkflowLedger,
  planWorkflowTest,
  preflightWorkflowPhase,
  preflightWorkflowPivot,
  setWorkflowCoverage,
  startWorkflowPhase,
  reviewWorkflowTest,
  workflowRuntimeInternals,
  workflowStatus
} from "../src/lib/workflow-runtime.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const gate = path.join(repo, "bin", "gate.mjs");
const definition = JSON.parse(fs.readFileSync(path.join(repo, "config", "workflows", "pentest-e2e.json"), "utf8"));
function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-workflow-preflight-"));
  const paths = runtimePaths({ home: path.join(root, "home"), repo });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, paths };
}

function invoke(args, paths) {
  const result = spawnSync(process.execPath, [gate, ...args], {
    cwd: repo,
    env: { ...process.env, GATE_HOME: paths.home },
    encoding: "utf8",
    // Journal replay can exceed ten seconds under concurrent integration load.
    timeout: 60_000
  });
  assert.ifError(result.error);
  assert.equal(result.signal, null, `CLI terminated by ${result.signal}: ${result.stderr}`);
  return result;
}

function writeJson(root, name, value) {
  const file = path.join(root, name);
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
  fs.writeFileSync(file, bytes, { mode: 0o600 });
  return { file, bytes, sha256: sha256(bytes) };
}

function approve(root, paths, { id, actions, tools, target = "127.0.0.1" }) {
  createEngagement({
    id,
    targets: [target],
    actions,
    tools,
    environment: "host",
    maxMinutes: 30,
    maxRequests: 500,
    maxParallel: 4,
    maxRate: 20,
    maxTokens: 100_000,
    allowedDestinations: ["gate-home"]
  }, { paths });
  const planFile = path.join(root, `${id}-plan.md`);
  fs.writeFileSync(planFile, `# ${id}\n\nSynthetic preflight fixture plan.\n`, { mode: 0o600 });
  const planned = attachPlan(id, planFile, { paths });
  recordTechnicalReview(id, {
    run: `no-mistakes/${id}`,
    headSha: "a".repeat(40),
    status: "passed"
  }, { paths });
  approveEngagement(id, { sha256: planned.plan.sha256, confirm: `APPROVE ${id}` }, { paths });
  return { id, target };
}

function buildAdmission(root, paths, {
  engagementId,
  workflowId,
  phaseId,
  target,
  action,
  toolId,
  name
}) {
  const phase = definition.phases.find((candidate) => candidate.id === phaseId);
  const mapping = phase.toolMappings.find((candidate) => candidate.toolId === toolId);
  assert.ok(mapping, `${toolId} must be mapped to ${phaseId}`);
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
    action,
    maxMinutes: envelope.maxMinutes,
    estimatedRequests: envelope.maxRequests,
    maxParallel: envelope.maxParallel,
    maxRatePerSecond: envelope.maxRatePerSecond,
    maxTokens: envelope.maxTotalTokens
  }, { paths });
  assert.equal(checked.allowed, true, checked.reasons?.join("; "));
  const binding = checked.executionBinding;
  const status = workflowStatus(workflowId, { paths });
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
      engagementId: binding.engagementId,
      planSha256: binding.planSha256,
      envelopeSha256: binding.envelopeSha256,
      receiptSha256: binding.receiptSha256,
      authorizationValidUntil: binding.authorizationValidUntil,
      checkedAt: new Date().toISOString()
    },
    envelope,
    issuedAt: new Date(Date.now() - 1_000).toISOString(),
    expiresAt: binding.authorizationValidUntil
  };
  return { admission, ...writeJson(root, `${name}-admission.json`, admission) };
}

function addRequiredEvidence(root, paths, workflowId, phaseId) {
  const phase = definition.phases.find((candidate) => candidate.id === phaseId);
  return phase.evidence.filter((record) => record.required).map((record) => {
    const bytes = Buffer.from(`${phaseId}:${record.id}:synthetic-preflight-evidence\n`);
    const file = path.join(root, `${phaseId}-${record.id}.txt`);
    fs.writeFileSync(file, bytes, { mode: 0o600 });
    addWorkflowEvidence(workflowId, {
      phaseId,
      evidenceId: record.id,
      claimState: record.claimState,
      file
    }, { paths });
    return { evidenceId: record.id, claimState: record.claimState, sha256: sha256(bytes) };
  });
}

function planFixtureTest(paths, workflowId, active) {
  const workflow = workflowStatus(workflowId, { paths });
  const feedbackApplicability = [
    {
      kind: "workflow",
      id: workflow.contract.id,
      version: String(workflow.contract.version),
      digest: workflow.contract.sha256
    },
    { kind: "phase", id: active.phaseId },
    ...(active.toolId ? [{ kind: "tool", id: active.toolId }] : [])
  ];
  const consultation = consultLearnings({ applicability: feedbackApplicability }, { paths });
  const priorReviewEntrySha256 = workflow.testFeedback.latestReviewSha256;
  return planWorkflowTest(workflowId, {
    phaseId: active.phaseId,
    attemptId: active.attemptId,
    hypothesis: "The bounded preflight fixture should produce the declared phase evidence.",
    method: "Exercise the preflight fixture under its current admission and record declared evidence.",
    expectedSignal: "The declared fixture evidence is recorded for this phase attempt.",
    contrarySignal: "The fixture cannot produce the declared evidence under its current admission.",
    learningApplicability: feedbackApplicability,
    learningIds: consultation.selected.map((learning) => learning.id),
    learningLedgerHeadSha256: consultation.ledgerHeadSha256,
    learningProjectionSha256: consultation.projectionSha256,
    basisEvidenceSha256: [],
    priorReviewEntrySha256,
    adaptation: priorReviewEntrySha256
      ? "Apply the prior fixture review to the next bounded phase while retaining the current authority."
      : null
  }, { paths });
}

function reviewFixtureTest(paths, workflowId, planned, evidenceSha256, disposition = "supported") {
  return reviewWorkflowTest(workflowId, {
    testId: planned.entry.payload.testId,
    phaseId: planned.entry.payload.phaseId,
    attemptId: planned.entry.payload.attemptId,
    planEntrySha256: planned.entry.entrySha256,
    disposition,
    observation: disposition === "invalid-test"
      ? "This fixture phase validates workflow transitions without reserving a target-contact execution."
      : "The reserved fixture execution reached a terminal state and its phase evidence was preserved.",
    evidenceSha256,
    metrics: null,
    usefulMistake: null,
    nextStrategy: { decision: "stop", rationale: "The focused fixture assertion is complete." }
  }, { paths });
}

function completeFixtureExecution(root, paths, workflowId, active, admissionFile) {
  const admission = JSON.parse(fs.readFileSync(admissionFile, "utf8"));
  const reservation = reserveWorkflowExecution(workflowId, {
    phaseAttemptId: active.attemptId,
    manifestId: `xmf_${crypto.randomBytes(16).toString("hex")}`,
    runId: `xrun_${crypto.randomBytes(16).toString("hex")}`,
    target: admission.target,
    action: admission.action,
    toolId: admission.toolId,
    envelope: admission.envelope
  }, { paths });
  claimWorkflowExecution(workflowId, {
    reservationId: reservation.reservationId,
    manifestSha256: sha256(Buffer.from(`fixture-manifest:${reservation.manifestId}`))
  }, { paths });
  const resultBytes = Buffer.from(`fixture-result:${active.phaseId}:${reservation.runId}\n`);
  const resultSha256 = sha256(resultBytes);
  completeWorkflowExecution(workflowId, {
    reservationId: reservation.reservationId,
    status: "succeeded",
    runSha256: sha256(Buffer.from(`fixture-run:${reservation.runId}`)),
    resultSha256,
    terminationReason: "Synthetic preflight fixture completed successfully."
  }, { paths });
  const phase = definition.phases.find((candidate) => candidate.id === active.phaseId);
  const resultEvidence = phase.evidence.find((candidate) => candidate.required);
  const file = path.join(root, `${active.phaseId}-${resultEvidence.id}-execution-result.txt`);
  fs.writeFileSync(file, resultBytes, { mode: 0o600 });
  const added = addWorkflowEvidence(workflowId, {
    phaseId: active.phaseId,
    evidenceId: resultEvidence.id,
    claimState: resultEvidence.claimState,
    file
  }, { paths });
  assert.equal(added.entry.payload.sha256, resultSha256);
  return resultSha256;
}

function completeFoundation(root, paths, workflowId) {
  for (const phaseId of ["authorization-and-roe", "target-and-architecture-map"]) {
    startWorkflowPhase(workflowId, {
      phaseId,
      sourcePhase: phaseId === "target-and-architecture-map" ? "authorization-and-roe" : undefined
    }, { paths });
    addRequiredEvidence(root, paths, workflowId, phaseId);
    finishWorkflowPhase(workflowId, { phaseId, disposition: "tested" }, { paths });
  }
}

function completeContactPhase(root, paths, workflowId, {
  phaseId,
  sourcePhase,
  admissionFile
}) {
  const started = startWorkflowPhase(workflowId, { phaseId, sourcePhase, admissionFile }, { paths });
  const planned = planFixtureTest(paths, workflowId, started.projection.activePhase);
  const evidence = addRequiredEvidence(root, paths, workflowId, phaseId);
  const resultSha256 = completeFixtureExecution(
    root, paths, workflowId, started.projection.activePhase, admissionFile
  );
  reviewFixtureTest(paths, workflowId, planned, [resultSha256]);
  finishWorkflowPhase(workflowId, { phaseId, disposition: "tested" }, { paths });
  return { attemptId: started.projection.activePhase.attemptId, evidence };
}

test("A3 and pivot preflights expose exact confirmations without persisting prospective documents", (t) => {
  const { root, paths } = fixture(t);
  const workflowId = "preflight-flow";
  const target = "127.0.0.1";
  createWorkflowInstance(workflowId, {}, { paths });
  completeFoundation(root, paths, workflowId);

  const mappingAuthority = approve(root, paths, {
    id: "mapping-authority",
    target,
    actions: ["observe", "scan"],
    tools: ["dnsx", "nmap"]
  });
  const surfaceAdmission = buildAdmission(root, paths, {
    engagementId: mappingAuthority.id,
    workflowId,
    phaseId: "active-surface-validation",
    target,
    action: "observe",
    toolId: "dnsx",
    name: "surface"
  });
  completeContactPhase(root, paths, workflowId, {
    phaseId: "active-surface-validation",
    sourcePhase: "target-and-architecture-map",
    admissionFile: surfaceAdmission.file
  });
  const networkAdmission = buildAdmission(root, paths, {
    engagementId: mappingAuthority.id,
    workflowId,
    phaseId: "network-service-enumeration",
    target,
    action: "scan",
    toolId: "nmap",
    name: "network"
  });
  const network = completeContactPhase(root, paths, workflowId, {
    phaseId: "network-service-enumeration",
    sourcePhase: "active-surface-validation",
    admissionFile: networkAdmission.file
  });

  const a3Authority = approve(root, paths, {
    id: "a3-authority",
    target,
    actions: ["exploit-safe"],
    tools: ["metasploit-framework"]
  });
  const a3Admission = buildAdmission(root, paths, {
    engagementId: a3Authority.id,
    workflowId,
    phaseId: "controlled-exploitation",
    target,
    action: "exploit-safe",
    toolId: "metasploit-framework",
    name: "a3"
  });
  const admissionDirectory = path.join(paths.workflows, workflowId, "admissions");
  const handoffDirectory = path.join(paths.workflows, workflowId, "handoffs");
  const beforePreflight = workflowStatus(workflowId, { paths });
  assert.equal(fs.existsSync(path.join(admissionDirectory, `${a3Admission.sha256}.json`)), false);

  const admissionOnly = preflightWorkflowPhase(workflowId, {
    phaseId: "controlled-exploitation",
    sourcePhase: "network-service-enumeration",
    handoffId: "high-impact-handoff-07",
    admissionFile: a3Admission.file
  }, { paths });
  assert.equal(admissionOnly.readOnly, true);
  assert.equal(admissionOnly.admissionSha256, a3Admission.sha256);
  assert.equal(admissionOnly.handoffRequired, true);
  assert.equal(admissionOnly.handoffSha256, null);
  assert.equal(admissionOnly.confirmationRequired, null);
  assert.equal(admissionOnly.readyForMutation, false);
  assert.equal(admissionOnly.journal.sequence, beforePreflight.journal.sequence);
  assert.equal(admissionOnly.journal.headSha256, beforePreflight.journal.headSha256);
  assert.equal(fs.existsSync(path.join(admissionDirectory, `${a3Admission.sha256}.json`)), false);

  const handoff = {
    $schema: "../../schemas/workflow-handoff.schema.json",
    apiVersion: "gate.workflow-handoff/v1",
    kind: "WorkflowHandoff",
    instanceId: workflowId,
    workflowDefinitionSha256: beforePreflight.contract.sha256,
    handoffId: "high-impact-handoff-07",
    policyId: "a3-structured-v1",
    type: "approval-boundary",
    fromPhase: "network-service-enumeration",
    toPhase: "controlled-exploitation",
    sourceAttemptId: network.attemptId,
    hypothesis: "The observed synthetic service may permit one bounded execution proof.",
    target,
    action: a3Admission.admission.action,
    toolId: a3Admission.admission.toolId,
    toolMappingSha256: a3Admission.admission.toolMappingSha256,
    adapterConstraint: a3Admission.admission.adapterConstraint,
    admissionSha256: a3Admission.sha256,
    authority: a3Admission.admission.authority,
    envelope: a3Admission.admission.envelope,
    scopeDelta: {
      changes: ["action", "tool"],
      justification: "The fresh authority adds only the named synthetic minimal proof."
    },
    priorEvidence: network.evidence,
    proofCeiling: {
      effectClass: "A3",
      capability: "Demonstrate one synthetic marker under the approved fixture identity.",
      successCondition: "The synthetic marker is observed once and the operation stops.",
      prohibitedEffects: ["No persistence, credential access, lateral movement, or production data access."]
    },
    stateChangePlan: {
      ledgerRef: "engagement-state-change-ledger",
      plannedChanges: ["Create one synthetic marker scoped to the fixture identity."],
      cleanupActions: ["Remove the synthetic marker and verify its absence."],
      monitoringOwner: "fixture-operator",
      abortCondition: "Abort on any mandatory stop or unexpected effect.",
      residualStateAction: "Enter recovery hold and preserve the synthetic evidence."
    },
    mandatoryStopConditions: definition.stopConditions.map(({ id }) => id),
    issuedAt: a3Admission.admission.issuedAt,
    expiresAt: a3Admission.admission.expiresAt
  };
  const handoffFile = writeJson(root, "a3-handoff.json", handoff);
  const fullPreflight = preflightWorkflowPhase(workflowId, {
    phaseId: "controlled-exploitation",
    sourcePhase: "network-service-enumeration",
    handoffId: "high-impact-handoff-07",
    admissionFile: a3Admission.file,
    handoffFile: handoffFile.file
  }, { paths });
  assert.equal(fullPreflight.handoffSha256, handoffFile.sha256);
  assert.match(fullPreflight.authorizationSha256, /^[a-f0-9]{64}$/u);
  assert.equal(fullPreflight.confirmationRequired,
    `AUTHORIZE A3 ${workflowId} controlled-exploitation ${handoffFile.sha256} ${fullPreflight.authorizationSha256}`);
  assert.equal(fullPreflight.readyForMutation, true);
  assert.equal(workflowStatus(workflowId, { paths }).journal.headSha256, beforePreflight.journal.headSha256);
  assert.equal(fs.existsSync(path.join(admissionDirectory, `${a3Admission.sha256}.json`)), false);
  assert.equal(fs.existsSync(path.join(handoffDirectory, `${handoffFile.sha256}.json`)), false);

  const cliPreflight = invoke([
    "--unassigned", "workflow", "phase", "preflight", workflowId,
    "--phase", "controlled-exploitation",
    "--from", "network-service-enumeration",
    "--handoff-id", "high-impact-handoff-07",
    "--admission", a3Admission.file,
    "--handoff", handoffFile.file,
    "--json"
  ], paths);
  assert.equal(cliPreflight.status, 0, cliPreflight.stderr);
  assert.equal(JSON.parse(cliPreflight.stdout).confirmationRequired, fullPreflight.confirmationRequired);

  assert.throws(() => startWorkflowPhase(workflowId, {
    phaseId: "controlled-exploitation",
    sourcePhase: "network-service-enumeration",
    handoffId: "high-impact-handoff-07",
    admissionFile: a3Admission.file,
    handoffFile: handoffFile.file,
    confirm: fullPreflight.confirmationRequired
  }, { paths }), /requires the exact --expected-sequence and --expected-head returned by preflight/u);
  assert.equal(fs.existsSync(path.join(admissionDirectory, `${a3Admission.sha256}.json`)), false);
  assert.equal(fs.existsSync(path.join(handoffDirectory, `${handoffFile.sha256}.json`)), false);

  assert.throws(() => startWorkflowPhase(workflowId, {
    phaseId: "controlled-exploitation",
    sourcePhase: "network-service-enumeration",
    handoffId: "high-impact-handoff-07",
    admissionFile: a3Admission.file,
    handoffFile: handoffFile.file
  }, {
    paths,
    expectedSequence: fullPreflight.journal.sequence,
    expectedHead: fullPreflight.journal.headSha256
  }), /high-impact confirmation must be exactly/u);
  assert.equal(fs.existsSync(path.join(admissionDirectory, `${a3Admission.sha256}.json`)), false);
  assert.equal(fs.existsSync(path.join(handoffDirectory, `${handoffFile.sha256}.json`)), false);

  fs.appendFileSync(handoffFile.file, " ");
  const alteredHandoffSha256 = sha256(fs.readFileSync(handoffFile.file));
  assert.throws(() => startWorkflowPhase(workflowId, {
    phaseId: "controlled-exploitation",
    sourcePhase: "network-service-enumeration",
    handoffId: "high-impact-handoff-07",
    admissionFile: a3Admission.file,
    handoffFile: handoffFile.file,
    confirm: fullPreflight.confirmationRequired
  }, {
    paths,
    expectedSequence: fullPreflight.journal.sequence,
    expectedHead: fullPreflight.journal.headSha256
  }), /high-impact confirmation must be exactly/u);
  assert.equal(fs.existsSync(path.join(handoffDirectory, `${alteredHandoffSha256}.json`)), false);
  fs.writeFileSync(handoffFile.file, handoffFile.bytes, { mode: 0o600 });
  assert.equal(fs.existsSync(path.join(admissionDirectory, `${a3Admission.sha256}.json`)), false);

  setWorkflowCoverage(workflowId, {
    domain: definition.coverageDomains[0],
    disposition: "untested",
    rationale: "Synthetic stale-preflight mutation."
  }, { paths });
  assert.throws(() => startWorkflowPhase(workflowId, {
    phaseId: "controlled-exploitation",
    sourcePhase: "network-service-enumeration",
    handoffId: "high-impact-handoff-07",
    admissionFile: a3Admission.file,
    handoffFile: handoffFile.file,
    confirm: fullPreflight.confirmationRequired
  }, {
    paths,
    expectedSequence: fullPreflight.journal.sequence,
    expectedHead: fullPreflight.journal.headSha256
  }), /workflow sequence changed/u);
  assert.equal(fs.existsSync(path.join(admissionDirectory, `${a3Admission.sha256}.json`)), false);

  const afterStaleMutation = workflowStatus(workflowId, { paths });
  assert.throws(() => startWorkflowPhase(workflowId, {
    phaseId: "controlled-exploitation",
    sourcePhase: "network-service-enumeration",
    handoffId: "high-impact-handoff-07",
    admissionFile: a3Admission.file,
    handoffFile: handoffFile.file,
    confirm: fullPreflight.confirmationRequired
  }, {
    paths,
    expectedSequence: afterStaleMutation.journal.sequence,
    expectedHead: afterStaleMutation.journal.headSha256
  }), /high-impact confirmation must be exactly/u);
  assert.equal(fs.existsSync(path.join(admissionDirectory, `${a3Admission.sha256}.json`)), false);
  assert.equal(fs.existsSync(path.join(handoffDirectory, `${handoffFile.sha256}.json`)), false);

  const refreshed = preflightWorkflowPhase(workflowId, {
    phaseId: "controlled-exploitation",
    sourcePhase: "network-service-enumeration",
    handoffId: "high-impact-handoff-07",
    admissionFile: a3Admission.file,
    handoffFile: handoffFile.file
  }, { paths });
  const phaseStartCli = invoke([
    "--unassigned", "workflow", "phase", "start", workflowId,
    "--phase", "controlled-exploitation",
    "--from", "network-service-enumeration",
    "--handoff-id", "high-impact-handoff-07",
    "--admission", a3Admission.file,
    "--handoff", handoffFile.file,
    "--expected-sequence", String(refreshed.journal.sequence),
    "--expected-head", refreshed.journal.headSha256,
    "--confirm", refreshed.confirmationRequired,
    "--json"
  ], paths);
  assert.equal(phaseStartCli.status, 0, phaseStartCli.stderr);
  const phaseStartResult = JSON.parse(phaseStartCli.stdout);
  assert.equal(phaseStartResult.activePhaseId, "controlled-exploitation");
  const afterPhaseStart = workflowStatus(workflowId, { paths });
  assert.equal(afterPhaseStart.activePhase.admissionSha256, a3Admission.sha256);
  assert.equal(afterPhaseStart.activePhase.handoffSha256, handoffFile.sha256);
  assert.equal(fs.existsSync(path.join(admissionDirectory, `${a3Admission.sha256}.json`)), true);
  assert.equal(fs.existsSync(path.join(handoffDirectory, `${handoffFile.sha256}.json`)), true);
  assert.throws(() => reserveWorkflowExecution(workflowId, {
    phaseAttemptId: afterPhaseStart.activePhase.attemptId,
    manifestId: `xmf_${"f".repeat(32)}`,
    runId: `xrun_${"f".repeat(32)}`,
    target,
    action: a3Admission.admission.action,
    toolId: a3Admission.admission.toolId,
    envelope: a3Admission.admission.envelope
  }, { paths }), /generic execution lane cannot execute an A3 phase/u);

  const [beforeEvidence, alternateEvidence] = addRequiredEvidence(root, paths, workflowId, "controlled-exploitation");
  const pivotAuthority = approve(root, paths, {
    id: "pivot-authority",
    target,
    actions: ["exploit-stateful"],
    tools: ["metasploit-framework"]
  });
  const pivotAdmission = buildAdmission(root, paths, {
    engagementId: pivotAuthority.id,
    workflowId,
    phaseId: "controlled-exploitation",
    target,
    action: "exploit-stateful",
    toolId: "metasploit-framework",
    name: "pivot"
  });
  const pivotInput = {
    changeType: "pivot",
    targetSelectorSha256: sha256(Buffer.from(target)),
    beforeEvidenceSha256: beforeEvidence.sha256,
    cleanupAction: "Remove the synthetic pivot marker and verify its absence.",
    pivotAdmissionFile: pivotAdmission.file
  };
  const beforePivot = workflowStatus(workflowId, { paths });
  const pivotPreflight = preflightWorkflowPivot(workflowId, pivotInput, { paths });
  assert.equal(pivotPreflight.admissionSha256, pivotAdmission.sha256);
  assert.match(pivotPreflight.authorizationSha256, /^[a-f0-9]{64}$/u);
  assert.equal(pivotPreflight.targetSelectorSha256, pivotInput.targetSelectorSha256);
  assert.equal(pivotPreflight.beforeEvidenceSha256, pivotInput.beforeEvidenceSha256);
  assert.equal(pivotPreflight.cleanupActionSha256, sha256(Buffer.from(pivotInput.cleanupAction)));
  assert.equal(pivotPreflight.confirmationRequired,
    `AUTHORIZE PIVOT ${workflowId} controlled-exploitation ${pivotAdmission.sha256} ${pivotPreflight.authorizationSha256}`);
  assert.equal(pivotPreflight.journal.sequence, beforePivot.journal.sequence);
  assert.equal(pivotPreflight.journal.headSha256, beforePivot.journal.headSha256);
  assert.equal(fs.existsSync(path.join(admissionDirectory, `${pivotAdmission.sha256}.json`)), false);

  const pivotCli = invoke([
    "--unassigned", "workflow", "ledger", "preflight", workflowId,
    "--type", "pivot",
    "--target-sha", pivotInput.targetSelectorSha256,
    "--before-sha", pivotInput.beforeEvidenceSha256,
    "--cleanup", pivotInput.cleanupAction,
    "--pivot-admission", pivotAdmission.file,
    "--json"
  ], paths);
  assert.equal(pivotCli.status, 0, pivotCli.stderr);
  assert.equal(JSON.parse(pivotCli.stdout).confirmationRequired, pivotPreflight.confirmationRequired);

  assert.throws(() => openWorkflowLedger(workflowId, {
    ...pivotInput,
    pivotConfirm: pivotPreflight.confirmationRequired
  }, { paths }), /requires the exact --expected-sequence and --expected-head returned by preflight/u);
  assert.equal(fs.existsSync(path.join(admissionDirectory, `${pivotAdmission.sha256}.json`)), false);

  assert.throws(() => openWorkflowLedger(workflowId, pivotInput, {
    paths,
    expectedSequence: pivotPreflight.journal.sequence,
    expectedHead: pivotPreflight.journal.headSha256
  }), /pivot confirmation must be exactly/u);
  assert.equal(fs.existsSync(path.join(admissionDirectory, `${pivotAdmission.sha256}.json`)), false);

  assert.throws(() => openWorkflowLedger(workflowId, {
    ...pivotInput,
    cleanupAction: "Leave the synthetic pivot marker in place.",
    pivotConfirm: pivotPreflight.confirmationRequired
  }, {
    paths,
    expectedSequence: pivotPreflight.journal.sequence,
    expectedHead: pivotPreflight.journal.headSha256
  }), /pivot confirmation must be exactly/u);
  assert.equal(fs.existsSync(path.join(admissionDirectory, `${pivotAdmission.sha256}.json`)), false);

  assert.throws(() => openWorkflowLedger(workflowId, {
    ...pivotInput,
    beforeEvidenceSha256: alternateEvidence.sha256,
    pivotConfirm: pivotPreflight.confirmationRequired
  }, {
    paths,
    expectedSequence: pivotPreflight.journal.sequence,
    expectedHead: pivotPreflight.journal.headSha256
  }), /pivot confirmation must be exactly/u);
  assert.equal(fs.existsSync(path.join(admissionDirectory, `${pivotAdmission.sha256}.json`)), false);

  assert.throws(() => openWorkflowLedger(workflowId, {
    ...pivotInput,
    pivotConfirm: pivotPreflight.confirmationRequired
  }, {
    paths,
    expectedSequence: pivotPreflight.journal.sequence,
    expectedHead: "0".repeat(64)
  }), /workflow journal head changed before mutation/u);
  assert.equal(fs.existsSync(path.join(admissionDirectory, `${pivotAdmission.sha256}.json`)), false);

  openWorkflowLedger(workflowId, {
    changeType: "synthetic-marker",
    targetSelectorSha256: pivotInput.targetSelectorSha256,
    beforeEvidenceSha256: pivotInput.beforeEvidenceSha256,
    cleanupAction: "Remove the unrelated synthetic marker."
  }, { paths });
  const afterPivotStaleMutation = workflowStatus(workflowId, { paths });
  assert.throws(() => openWorkflowLedger(workflowId, {
    ...pivotInput,
    pivotConfirm: pivotPreflight.confirmationRequired
  }, {
    paths,
    expectedSequence: afterPivotStaleMutation.journal.sequence,
    expectedHead: afterPivotStaleMutation.journal.headSha256
  }), /pivot confirmation must be exactly/u);
  assert.equal(fs.existsSync(path.join(admissionDirectory, `${pivotAdmission.sha256}.json`)), false);

  const refreshedPivot = preflightWorkflowPivot(workflowId, pivotInput, { paths });
  const pivotOpenCli = invoke([
    "--unassigned", "workflow", "ledger", "open", workflowId,
    "--type", "pivot",
    "--target-sha", pivotInput.targetSelectorSha256,
    "--before-sha", pivotInput.beforeEvidenceSha256,
    "--cleanup", pivotInput.cleanupAction,
    "--pivot-admission", pivotAdmission.file,
    "--expected-sequence", String(refreshedPivot.journal.sequence),
    "--expected-head", refreshedPivot.journal.headSha256,
    "--pivot-confirm", refreshedPivot.confirmationRequired,
    "--json"
  ], paths);
  assert.equal(pivotOpenCli.status, 0, pivotOpenCli.stderr);
  const pivotOpenResult = JSON.parse(pivotOpenCli.stdout);
  const projectionFile = workflowRuntimeInternals.workflowPaths(paths, workflowId).workflowProjection;
  const projection = JSON.parse(fs.readFileSync(projectionFile, "utf8"));
  const openedPivot = projection.ledger[pivotOpenResult.event.details.entryId].pivot;
  assert.deepEqual(projection.budget.used, { maxMinutes: 20, maxRequests: 80, maxTotalTokens: 40_000 });
  assert.equal(openedPivot.admissionSha256, pivotAdmission.sha256);
  assert.equal(openedPivot.authorizationSha256, refreshedPivot.authorizationSha256);
  assert.equal(fs.existsSync(path.join(admissionDirectory, `${pivotAdmission.sha256}.json`)), true);
  approve(root, paths, {
    id: "second-pivot-authority", target, actions: ["exploit-stateful"], tools: ["metasploit-framework"]
  });
  const second = buildAdmission(root, paths, {
    engagementId: "second-pivot-authority", workflowId, phaseId: "controlled-exploitation",
    target, action: "exploit-stateful", toolId: "metasploit-framework", name: "second-pivot"
  });
  for (const [field, amount] of [["maxMinutes", 5], ["maxRequests", 321], ["maxTotalTokens", 40_001]]) {
    const value = structuredClone(second.admission);
    Object.assign(value.envelope, { maxMinutes: 1, maxRequests: 1, maxTotalTokens: 1, [field]: amount });
    const candidate = writeJson(root, `second-${field}.json`, value);
    assert.throws(() => preflightWorkflowPivot(workflowId, {
      ...pivotInput, pivotAdmissionFile: candidate.file
    }, { paths }), new RegExp(`workflow ${field} exceeds remaining capacity`, "u"));
  }
});


test("admission expiry blocks reservation, claim, and execution despite valid engagement authority", (t) => {
  const { root, paths } = fixture(t);
  const workflowId = "admission-expiry";
  const target = "127.0.0.1";
  createWorkflowInstance(workflowId, {}, { paths });
  completeFoundation(root, paths, workflowId);
  approve(root, paths, { id: "expiry-authority", target, actions: ["observe"], tools: ["dnsx"] });
  const built = buildAdmission(root, paths, {
    engagementId: "expiry-authority", workflowId, phaseId: "active-surface-validation",
    target, action: "observe", toolId: "dnsx", name: "expiry"
  });
  const expiresAt = Date.now() + 10 * 60_000;
  built.admission.expiresAt = new Date(expiresAt).toISOString();
  const admission = writeJson(root, "expiry-admission.json", built.admission);
  const started = startWorkflowPhase(workflowId, {
    phaseId: "active-surface-validation", sourcePhase: "target-and-architecture-map", admissionFile: admission.file
  }, { paths });
  const plannedTest = planFixtureTest(paths, workflowId, started.projection.activePhase);
  const phaseEvidence = addRequiredEvidence(root, paths, workflowId, "active-surface-validation");
  const input = {
    phaseAttemptId: started.projection.activePhase.attemptId,
    manifestId: `xmf_${"1".repeat(32)}`, runId: `xrun_${"1".repeat(32)}`,
    target, action: "observe", toolId: "dnsx", envelope: built.admission.envelope
  };
  const now = Date.now;
  t.mock.method(Date, "now", () => expiresAt);
  assert.equal(checkEngagement("expiry-authority", { target, action: "observe" }, { paths }).allowed, true);
  assert.throws(() => reserveWorkflowExecution(workflowId, input, { paths }), /admission is not currently valid/u);
  t.mock.method(Date, "now", now);
  const reservation = reserveWorkflowExecution(workflowId, input, { paths });
  const claim = { reservationId: reservation.reservationId, manifestSha256: "a".repeat(64) };
  assert.equal(checkWorkflowExecution(workflowId, claim, { paths }).ok, true);
  t.mock.method(Date, "now", () => expiresAt);
  assert.throws(() => claimWorkflowExecution(workflowId, claim, { paths }), /admission is not currently valid/u);
  assert.throws(() => checkWorkflowExecution(workflowId, claim, { paths }), /admission is not currently valid/u);
  t.mock.method(Date, "now", now);
  claimWorkflowExecution(workflowId, claim, { paths });
  assert.equal(checkWorkflowExecution(workflowId, claim, { paths }).ok, true);
  t.mock.method(Date, "now", () => expiresAt + 60_000);
  assert.throws(() => checkWorkflowExecution(workflowId, claim, { paths }), /admission is not currently valid/u);
  t.mock.method(Date, "now", now);
  completeWorkflowExecution(workflowId, {
    reservationId: reservation.reservationId,
    status: "blocked",
    runSha256: "b".repeat(64),
    terminationReason: "Synthetic admission-expiry fixture completed after its assertions."
  }, { paths });
  reviewFixtureTest(paths, workflowId, plannedTest, phaseEvidence.map((item) => item.sha256), "blocked");
  finishWorkflowPhase(workflowId, {
    phaseId: "active-surface-validation",
    disposition: "blocked",
    rationale: "The admission expiry fixture deliberately ended without a successful execution."
  }, { paths });
});
