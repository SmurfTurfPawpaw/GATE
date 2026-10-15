import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { validateDocument } from "../src/lib/schema.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sha = (digit) => digit.repeat(64);
const mandatoryStops = [
  "scope-mismatch",
  "plan-digest-change",
  "authorization-expiry",
  "unexpected-data-loss",
  "target-instability",
  "third-party-system-discovered",
  "rate-limit-exceeded",
  "evidence-integrity-failure",
  "operator-stop",
  "unexpected-sensitive-data",
  "unplanned-privilege-or-persistence",
  "defensive-control-impact",
  "cleanup-incomplete"
];

const authority = {
  engagementId: "engagement-one",
  planSha256: sha("1"),
  envelopeSha256: sha("2"),
  receiptSha256: sha("3"),
  authorizationValidUntil: "2026-10-15T12:00:00.000Z",
  checkedAt: "2026-10-14T12:00:00.000Z"
};

const envelope = {
  maxMinutes: 30,
  maxRequests: 100,
  maxRatePerSecond: 2,
  maxParallel: 1,
  maxInputTokens: 0,
  maxOutputTokens: 0,
  maxTotalTokens: 1000,
  maxEvidenceBytes: 2097152,
  maxSpend: 0,
  controls: {
    wallTime: "enforced",
    requests: "measured-only",
    rate: "unavailable",
    parallel: "unavailable",
    tokens: "unavailable",
    evidenceBytes: "enforced",
    spend: "unavailable"
  }
};

const admission = {
  $schema: "../../schemas/workflow-admission.schema.json",
  apiVersion: "gate.workflow-admission/v1",
  kind: "WorkflowAdmission",
  instanceId: "workflow-one",
  workflowDefinitionSha256: sha("4"),
  phaseId: "controlled-exploitation",
  target: "example.test",
  action: "exploit-safe",
  toolId: "metasploit-framework",
  toolMappingSha256: sha("5"),
  adapterConstraint: "Run one reviewed minimal proof and stop at the declared capability ceiling.",
  authority,
  envelope,
  issuedAt: "2026-10-14T12:00:00.000Z",
  expiresAt: "2026-10-14T13:00:00.000Z"
};

const handoff = {
  $schema: "../../schemas/workflow-handoff.schema.json",
  apiVersion: "gate.workflow-handoff/v1",
  kind: "WorkflowHandoff",
  instanceId: admission.instanceId,
  workflowDefinitionSha256: admission.workflowDefinitionSha256,
  handoffId: "high-impact-handoff-07",
  policyId: "a3-structured-v1",
  type: "approval-boundary",
  fromPhase: "network-service-enumeration",
  toPhase: admission.phaseId,
  sourceAttemptId: `wpa_${"a".repeat(32)}`,
  hypothesis: "The observed service version may permit one bounded execution proof.",
  target: admission.target,
  action: admission.action,
  toolId: admission.toolId,
  toolMappingSha256: admission.toolMappingSha256,
  adapterConstraint: admission.adapterConstraint,
  admissionSha256: sha("6"),
  authority,
  envelope,
  scopeDelta: {
    changes: ["action"],
    justification: "The fresh engagement adds only the named minimal exploit proof."
  },
  priorEvidence: [
    {
      evidenceId: "bounded-service-inventory",
      sha256: sha("7"),
      claimState: "observed"
    }
  ],
  proofCeiling: {
    effectClass: "A3",
    capability: "Demonstrate one synthetic marker under the approved test identity.",
    successCondition: "The marker is observed once and no persistence is attempted.",
    prohibitedEffects: ["No credential access, persistence, lateral movement, or production data access."]
  },
  stateChangePlan: {
    ledgerRef: "engagement-state-change-ledger",
    plannedChanges: ["Create one synthetic marker scoped to the test identity."],
    cleanupActions: ["Remove the synthetic marker and independently verify its absence."],
    monitoringOwner: "named-engagement-operator",
    abortCondition: "Abort on instability, unexpected data, or any mandatory stop.",
    residualStateAction: "Enter recovery hold and notify the named recovery owner."
  },
  mandatoryStopConditions: mandatoryStops,
  issuedAt: admission.issuedAt,
  expiresAt: admission.expiresAt
};

const validate = (value, schema) => validateDocument(value, schema, { paths: { repo } });

test("workflow admission schema accepts the complete binding and rejects unbound fields", () => {
  assert.deepEqual(validate(admission, "workflow-admission.schema.json").errors, []);

  const withAttempt = structuredClone(admission);
  withAttempt.phaseAttemptId = `wpa_${"b".repeat(32)}`;
  assert.equal(validate(withAttempt, "workflow-admission.schema.json").ok, false);

  const withoutAdapter = structuredClone(admission);
  delete withoutAdapter.adapterConstraint;
  assert.equal(validate(withoutAdapter, "workflow-admission.schema.json").ok, false);

  const invalidDigest = structuredClone(admission);
  invalidDigest.toolMappingSha256 = "not-a-digest";
  assert.equal(validate(invalidDigest, "workflow-admission.schema.json").ok, false);

  const unknownControl = structuredClone(admission);
  unknownControl.envelope.controls.tokens = "best-effort";
  assert.equal(validate(unknownControl, "workflow-admission.schema.json").ok, false);
});

test("workflow handoff schema binds source evidence, fresh admission, proof, stops, and cleanup", () => {
  assert.deepEqual(validate(handoff, "workflow-handoff.schema.json").errors, []);

  const missingSourceAttempt = structuredClone(handoff);
  delete missingSourceAttempt.sourceAttemptId;
  assert.equal(validate(missingSourceAttempt, "workflow-handoff.schema.json").ok, false);

  const unverifiedEvidence = structuredClone(handoff);
  unverifiedEvidence.priorEvidence[0].claimState = "unverified";
  assert.equal(validate(unverifiedEvidence, "workflow-handoff.schema.json").ok, false);

  const incompleteStops = structuredClone(handoff);
  incompleteStops.mandatoryStopConditions.pop();
  assert.equal(validate(incompleteStops, "workflow-handoff.schema.json").ok, false);

  const inventedStop = structuredClone(handoff);
  inventedStop.mandatoryStopConditions[0] = "invented-stop";
  assert.equal(validate(inventedStop, "workflow-handoff.schema.json").ok, false);

  const extraField = structuredClone(handoff);
  extraField.automaticPromotion = false;
  assert.equal(validate(extraField, "workflow-handoff.schema.json").ok, false);
});
