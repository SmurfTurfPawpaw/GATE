import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { projectLearning, projectSnapshot } from "../src/observer/server.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const at = "2026-10-15T12:00:00.000Z";
const learningId = "lrn_20261015120000_abcdef01";
const candidateId = "lrn_20261015115900_abcdef02";
const conflictId = "lrn_20261015115800_abcdef03";
const replacementId = "lrn_20261015115700_abcdef04";

function adaptiveLearning(overrides = {}) {
  return {
    apiVersion: "gate.learning/v2",
    id: learningId,
    at,
    scope: "repository",
    cause: "A repeated test exposed a more discriminating follow-up.",
    change: "Consult the recorded adjustment before planning the next test.",
    evidence: ["event://V2_EVIDENCE_CANARY"],
    status: "active",
    sensitivity: "public",
    supersedes: candidateId,
    configurationRefs: ["config/V2_CONFIG_CANARY.json"],
    trigger: "test-result",
    domain: "active-testing",
    cycle: {
      hypothesis: "CYCLE_HYPOTHESIS_CANARY",
      method: "CYCLE_METHOD_CANARY",
      outcome: {
        disposition: "inconclusive",
        summary: "CYCLE_OUTCOME_CANARY"
      },
      lesson: "CYCLE_LESSON_CANARY",
      nextAdjustment: "CYCLE_ADJUSTMENT_CANARY"
    },
    applicability: [
      {
        kind: "component",
        id: "observer-cycle-canary",
        version: "1.0.0",
        digest: "a".repeat(64)
      }
    ],
    promotion: {
      state: "validated",
      candidateId,
      candidateSha256: "b".repeat(64),
      validatedAt: at,
      validationRefs: ["evidence://V2_VALIDATION_CANARY"],
      changeRefs: ["evidence://V2_CHANGE_CANARY"],
      review: {
        owner: "no-mistakes",
        attestationRef: "evidence://no-mistakes/V2_REVIEW_CANARY",
        attestationSha256: "c".repeat(64),
        candidateSha256: "b".repeat(64),
        headSha: "d".repeat(40)
      },
      conflictsWith: [conflictId],
      replaces: [replacementId]
    },
    ...overrides
  };
}

function publicLearnings(...learnings) {
  return projectSnapshot({ at, learnings }, { repo }).learnings.learnings;
}

test("observer projects a valid v2 learning through the existing public shape", () => {
  const [learning] = publicLearnings(adaptiveLearning());
  assert.deepEqual(learning, {
    id: learningId,
    at,
    scope: "repository",
    cause: "A repeated test exposed a more discriminating follow-up.",
    change: "Consult the recorded adjustment before planning the next test.",
    status: "active",
    sensitivity: "public",
    supersedes: candidateId,
    evidenceCount: 1,
    configurationCount: 1
  });
});

test("observer masks private v2 cause and change", () => {
  const [learning] = publicLearnings(adaptiveLearning({
    sensitivity: "private",
    cause: "PRIVATE_V2_CAUSE_CANARY",
    change: "PRIVATE_V2_CHANGE_CANARY"
  }));
  assert.equal(learning.cause, "Private learning recorded.");
  assert.equal(learning.change, "Details withheld from observer.");
  assert.notEqual(learning.id, learningId);
  assert.notEqual(learning.supersedes, candidateId);
  assert.match(learning.id, /^learning_[a-f0-9]{16}$/u);
  assert.match(learning.supersedes, /^learning_[a-f0-9]{16}$/u);
  assert.equal(JSON.stringify(learning).includes("PRIVATE_V2"), false);
});

test("observer rejects malformed v2 adaptive fields", () => {
  const malformedOutcome = adaptiveLearning();
  malformedOutcome.cycle.outcome.disposition = "maybe";
  assert.equal(projectLearning(malformedOutcome), null);

  const unknownField = adaptiveLearning({ unexpected: "PRIVATE_UNKNOWN_CANARY" });
  assert.equal(projectLearning(unknownField), null);

  const missingReview = adaptiveLearning();
  delete missingReview.promotion.review;
  assert.equal(projectLearning(missingReview), null);

  const malformedConflicts = adaptiveLearning();
  malformedConflicts.promotion.conflictsWith = ["not-a-learning-id"];
  assert.equal(projectLearning(malformedConflicts), null);

  const malformedReplaces = adaptiveLearning();
  malformedReplaces.promotion.replaces = ["not-a-learning-id"];
  assert.equal(projectLearning(malformedReplaces), null);

  const mismatchedCandidate = adaptiveLearning();
  mismatchedCandidate.promotion.review.candidateSha256 = "e".repeat(64);
  assert.equal(projectLearning(mismatchedCandidate), null);

  const malformedHead = adaptiveLearning();
  malformedHead.promotion.review.headSha = "f".repeat(39);
  assert.equal(projectLearning(malformedHead), null);
});

test("observer rejects impossible v2 promotion lifecycles and public private evidence", () => {
  const publicPrivateEvidence = adaptiveLearning({ evidence: ["private://PUBLIC_PRIVATE_EVIDENCE_CANARY"] });
  assert.equal(projectLearning(publicPrivateEvidence), null);
  const privateValidationEvidence = adaptiveLearning();
  privateValidationEvidence.promotion.validationRefs = ["private://PUBLIC_VALIDATION_EVIDENCE_CANARY"];
  assert.equal(projectLearning(privateValidationEvidence), null);

  for (const overrides of [
    { status: "proposed" },
    { supersedes: null },
    { supersedes: "lrn_20261015115600_abcdef05" }
  ]) {
    assert.equal(projectLearning(adaptiveLearning(overrides)), null);
  }

  const candidatePromotion = {
    state: "candidate",
    candidateId: null,
    candidateSha256: null,
    validatedAt: null,
    validationRefs: [],
    changeRefs: [],
    review: null,
    conflictsWith: [],
    replaces: []
  };
  const candidate = adaptiveLearning({
    status: "proposed",
    sensitivity: "private",
    supersedes: null,
    promotion: candidatePromotion
  });
  assert.notEqual(projectLearning(candidate), null);
  assert.equal(projectLearning({ ...candidate, status: "active" }), null);
  assert.equal(projectLearning({ ...candidate, sensitivity: "public" }), null);
  assert.equal(projectLearning({ ...candidate, supersedes: candidateId }), null);
});

test("observer never exposes v2 cycle, applicability, promotion, evidence, or configuration contents", () => {
  const [learning] = publicLearnings(adaptiveLearning());
  const serialized = JSON.stringify(learning);
  for (const canary of [
    "CYCLE_HYPOTHESIS_CANARY",
    "CYCLE_METHOD_CANARY",
    "CYCLE_OUTCOME_CANARY",
    "CYCLE_LESSON_CANARY",
    "CYCLE_ADJUSTMENT_CANARY",
    "observer-cycle-canary",
    "V2_EVIDENCE_CANARY",
    "V2_CONFIG_CANARY",
    "V2_VALIDATION_CANARY",
    "V2_CHANGE_CANARY",
    "V2_REVIEW_CANARY",
    conflictId,
    replacementId
  ]) {
    assert.equal(serialized.includes(canary), false, canary);
  }
  assert.deepEqual(Object.keys(learning).sort(), [
    "at",
    "cause",
    "change",
    "configurationCount",
    "evidenceCount",
    "id",
    "scope",
    "sensitivity",
    "status",
    "supersedes"
  ]);
});

test("observer pseudonymizes a public legacy learning id that predates opaque generated ids", () => {
  const [learning] = publicLearnings({
    apiVersion: "gate.learning/v1",
    id: "lrn_named_legacy_canary",
    at,
    scope: "repository",
    cause: "A legacy record remains readable.",
    change: "Mask identifying legacy metadata at the observer boundary.",
    evidence: ["evidence://legacy-canary"],
    status: "active",
    sensitivity: "public",
    supersedes: "lrn_named_parent_canary",
    configurationRefs: []
  });
  assert.match(learning.id, /^learning_[a-f0-9]{16}$/u);
  assert.match(learning.supersedes, /^learning_[a-f0-9]{16}$/u);
  assert.notEqual(learning.id, "lrn_named_legacy_canary");
  assert.notEqual(learning.supersedes, "lrn_named_parent_canary");
});

test("observer withholds sensitive identifiers from manually supplied public narratives", () => {
  const narratives = [
    "Observed canary-target.invalid during the retry.",
    "Observed 198.51.100.7 during the retry.",
    "Observed operator@canary.invalid during the retry.",
    "Observed [2001:db8::7] during the retry.",
    "Observed customer-production during the retry.",
    "Observed /tenant-secret during the retry.",
    `Observed AKIA${"A".repeat(16)} during the retry.`,
    "Observed abcdefgh.ijklmnop.qrstuvwx during the retry.",
    "Observed Bearer abcdefghijklmnop during the retry."
  ];
  const records = narratives.map((cause, index) => ({
    apiVersion: "gate.learning/v1",
    id: `lrn_manual_canary_${index}`,
    at: `2026-10-15T12:00:0${index}.000Z`,
    scope: "repository",
    cause,
    change: narratives[(index + 1) % narratives.length],
    evidence: [`evidence://manual-${index}`],
    status: "active",
    sensitivity: "public",
    supersedes: null,
    configurationRefs: []
  }));
  const projected = publicLearnings(...records);
  assert.equal(projected.length, narratives.length);
  assert.ok(projected.every((learning) => learning.cause && learning.change));
  const serialized = JSON.stringify(projected);
  for (const canary of [
    "canary-target.invalid",
    "198.51.100.7",
    "operator@canary.invalid",
    "2001:db8::7",
    "customer-production",
    "/tenant-secret",
    `AKIA${"A".repeat(16)}`,
    "abcdefgh.ijklmnop.qrstuvwx",
    "Bearer abcdefghijklmnop"
  ]) {
    assert.equal(serialized.includes(canary), false, canary);
  }
});

test("observer presents replaced ancestors as historical without exposing replacement edges", () => {
  const record = ({ id, candidate, replaces, timestamp }) => {
    const learning = adaptiveLearning({ id, at: timestamp, supersedes: candidate });
    learning.promotion = {
      ...learning.promotion,
      candidateId: candidate,
      validatedAt: timestamp,
      conflictsWith: [],
      replaces
    };
    return learning;
  };
  const firstId = "lrn_20261015130000_abcdef11";
  const secondId = "lrn_20261015140000_abcdef12";
  const thirdId = "lrn_20261015150000_abcdef13";
  const first = record({
    id: firstId,
    candidate: "lrn_20261015125900_abcdef21",
    replaces: [],
    timestamp: "2026-10-15T13:00:00.000Z"
  });
  const second = record({
    id: secondId,
    candidate: "lrn_20261015135900_abcdef22",
    replaces: [firstId],
    timestamp: "2026-10-15T14:00:00.000Z"
  });
  second.applicability = [{
    digest: "a".repeat(64),
    version: "1.0.0",
    id: "observer-cycle-canary",
    kind: "component"
  }];
  const third = record({
    id: thirdId,
    candidate: "lrn_20261015145900_abcdef23",
    replaces: [secondId],
    timestamp: "2026-10-15T15:00:00.000Z"
  });

  const projected = publicLearnings(first, second, third);
  assert.deepEqual(projected.map(({ id, status }) => ({ id, status })), [
    { id: thirdId, status: "active" },
    { id: secondId, status: "superseded" },
    { id: firstId, status: "superseded" }
  ]);
  const serialized = JSON.stringify(projected);
  assert.equal(serialized.includes('"replaces"'), false);
});
