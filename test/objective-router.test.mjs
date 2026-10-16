import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  objectiveCanonicalSha256,
  objectiveRouteCatalogSemanticErrors,
  objectiveRoutingProposalSemanticErrors,
  objectiveRouterInternals,
  resolveObjectiveRecommendation
} from "../src/lib/objective-router.mjs";
import { validateDocument } from "../src/lib/schema.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const paths = { repo };
const catalog = JSON.parse(fs.readFileSync(path.join(repo, "config", "objective-routes.json"), "utf8"));
const toolCatalog = JSON.parse(fs.readFileSync(path.join(repo, "catalog", "security-tools.json"), "utf8"));

function inferred(code = "objective-classification") {
  return { provenance: "model-derived", claimState: "inferred", code, sourceRefs: [] };
}

function stated() {
  return { provenance: "operator-stated", claimState: "observed", code: "operator-explicit", sourceRefs: [] };
}

function unknownBasis() {
  return { provenance: "model-derived", claimState: "unverified", code: "insufficient-evidence", sourceRefs: [] };
}

function proposal(overrides = {}) {
  const dimensions = {
    domain: { value: "security-incident", basis: inferred() },
    deliverable: { value: "investigation-report", basis: inferred() },
    relationship: { value: "unknown", basis: inferred() },
    highestEffect: { value: "local-write", basis: inferred() },
    dataClass: { value: "sensitive", basis: inferred() },
    ...(overrides.dimensions || {})
  };
  const value = {
    $schema: "https://gate.local/schemas/objective-routing-proposal.schema.json",
    apiVersion: "gate.dev/objective-routing-proposal/v1",
    kind: "ObjectiveRoutingProposal",
    metadata: {
      objectiveHandle: "obj_0123456789abcdef",
      createdAt: "2026-10-16T08:00:00.000Z",
      routeCatalogSha256: objectiveCanonicalSha256(catalog),
      ...(overrides.metadata || {})
    },
    dimensions,
    signals: overrides.signals || ["account", "payment", "order"].map((id) => ({
      id,
      basis: inferred()
    })),
    answers: overrides.answers || {
      "immediate-goal": {
        choiceId: "explain",
        mode: "recommendation",
        basis: inferred()
      }
    }
  };
  return value;
}

test("objective route catalog is schema-valid, internally closed, and uses registered security-tool ids", () => {
  assert.deepEqual(validateDocument(catalog, "objective-route-catalog.schema.json", { paths }).errors, []);
  assert.deepEqual(objectiveRouteCatalogSemanticErrors(catalog, {
    paths,
    toolIds: toolCatalog.tools.map((tool) => tool.id)
  }), []);

  const widenedBasis = structuredClone(catalog);
  widenedBasis.basisCodes.find((entry) => entry.id === "operator-explicit")
    .allowedProvenance.push("model-derived");
  assert.match(
    objectiveRouteCatalogSemanticErrors(widenedBasis, { paths }).join("; "),
    /must use its exact allowed provenance/u
  );
});

test("an account/payment/order abuse objective receives an incident plan without becoming a Program Profile", () => {
  // This is the categorical form of the operator's meal-delivery account-abuse example.
  const input = proposal();
  const first = resolveObjectiveRecommendation(catalog, input, { paths });
  const second = resolveObjectiveRecommendation(catalog, structuredClone(input), { paths });

  assert.deepEqual(second, first, "the resolver must be deterministic");
  assert.equal(first.route.id, "security-incident-investigation");
  assert.equal(first.route.handler.id, "incident-investigation-plan");
  assert.equal(first.route.handler.state, "planning-only");
  assert.equal(first.executionAuthority, false);
  assert.equal(first.planStatus, "ready-to-plan");
  assert.deepEqual(first.unresolvedQuestionIds, [
    "subject-relationship",
    "data-access-basis",
    "immediate-goal"
  ]);
  assert.equal(first.questions.find((question) => question.id === "immediate-goal").recommendedChoiceId, "explain");
  assert.equal(first.questions.find((question) => question.id === "data-access-basis").recommendedChoiceId, null);
  assert.equal(first.nextActions.find((action) => action.id === "outline-incident-evidence").state, "ready-to-plan");
  assert.equal(first.nextActions.find((action) => action.id === "build-incident-timeline").state, "needs-input");
  assert.ok(first.dataRequests.some((request) => request.id === "account-order-history"));
  assert.ok(first.dataRequests.some((request) => request.id === "payment-transaction-records"));
  assert.ok(first.evidencePlan.some((step) => step.id === "competing-hypotheses"));
  assert.ok(first.capabilities.some((capability) => capability.id === "timeline-correlation"));
  assert.ok(first.capabilities.flatMap((capability) => capability.tools).every((tool) =>
    tool.state === "route-listed" && tool.suitable === "unknown"
  ));
  assert.doesNotMatch(JSON.stringify(first), /meal-delivery|uber|objective concerns account activity/iu);
  assert.equal(validateDocument(first, "objective-recommendation.schema.json", { paths }).ok, true);
  assert.equal(first.metadata.recommendationSha256, objectiveRouterInternals.recommendationDigest(first));
});

test("bug bounty and generic security assessments use different handlers", () => {
  const securityDimensions = {
    domain: { value: "security-assessment", basis: inferred() },
    deliverable: { value: "investigation-report", basis: inferred() },
    relationship: { value: "unknown", basis: inferred() },
    highestEffect: { value: "target-contact", basis: inferred() },
    dataClass: { value: "sensitive", basis: inferred() }
  };
  const bounty = proposal({
    dimensions: securityDimensions,
    signals: [{ id: "bounty-program", basis: inferred() }],
    answers: {}
  });
  const generic = proposal({ dimensions: securityDimensions, signals: [], answers: {} });

  const bountyResult = resolveObjectiveRecommendation(catalog, bounty, { paths });
  const genericResult = resolveObjectiveRecommendation(catalog, generic, { paths });
  assert.equal(bountyResult.route.id, "bug-bounty-assessment");
  assert.equal(bountyResult.route.handler.id, "program-profile-intake");
  assert.equal(bountyResult.route.handler.state, "ready");
  assert.equal(genericResult.route.id, "security-assessment-planning");
  assert.equal(genericResult.route.handler.state, "planning-only");
});

test("software change and investigation proposals route to distinct Firstmate handoffs", () => {
  const shared = {
    relationship: { value: "owned", basis: stated() },
    highestEffect: { value: "local-write", basis: inferred() },
    dataClass: { value: "internal", basis: inferred() }
  };
  const answer = {
    "project-binding": {
      choiceId: "registered-project",
      mode: "explicit",
      basis: stated()
    }
  };
  const change = proposal({
    dimensions: {
      domain: { value: "software", basis: inferred() },
      deliverable: { value: "change", basis: inferred() },
      ...shared
    },
    signals: [{ id: "repository", basis: inferred() }],
    answers: answer
  });
  const investigation = structuredClone(change);
  investigation.dimensions.deliverable = {
    value: "investigation-report",
    basis: inferred()
  };

  assert.equal(resolveObjectiveRecommendation(catalog, change, { paths }).route.handler.id, "firstmate-ship");
  assert.equal(resolveObjectiveRecommendation(catalog, investigation, { paths }).route.handler.id, "firstmate-scout");
});

test("manual facts cannot be recommendations or model-inferred relationship claims", () => {
  const recommendedAccess = proposal({
    answers: {
      "data-access-basis": {
        choiceId: "own-records",
        mode: "recommendation",
        basis: inferred()
      }
    }
  });
  assert.match(
    objectiveRoutingProposalSemanticErrors(catalog, recommendedAccess, { paths }).join("; "),
    /manual-only and cannot be recommended/u
  );

  const inferredOwnership = proposal({
    dimensions: {
      relationship: { value: "owned", basis: inferred() }
    }
  });
  assert.match(
    objectiveRoutingProposalSemanticErrors(catalog, inferredOwnership, { paths }).join("; "),
    /must remain unknown unless directly stated by the operator/u
  );

  const explicitAccess = proposal({
    dimensions: {
      relationship: { value: "owned", basis: stated() }
    },
    answers: {
      "data-access-basis": {
        choiceId: "own-records",
        mode: "explicit",
        basis: stated()
      },
      "immediate-goal": {
        choiceId: "explain",
        mode: "recommendation",
        basis: inferred()
      }
    }
  });
  const result = resolveObjectiveRecommendation(catalog, explicitAccess, { paths });
  const access = result.questions.find((question) => question.id === "data-access-basis");
  assert.equal(access.resolved, true);
  assert.equal(access.selectedChoiceId, "own-records");
  assert.equal(access.recommendedChoiceId, null);
});

test("resolved manual choices gate access-dependent actions by allowed choice", () => {
  const reportOnly = proposal({
    dimensions: {
      relationship: { value: "owned", basis: stated() }
    },
    answers: {
      "subject-relationship": { choiceId: "owned", mode: "explicit", basis: stated() },
      "data-access-basis": { choiceId: "report-only", mode: "explicit", basis: stated() },
      "immediate-goal": { choiceId: "explain", mode: "explicit", basis: stated() }
    }
  });
  const reportOnlyResult = resolveObjectiveRecommendation(catalog, reportOnly, { paths });
  assert.equal(reportOnlyResult.nextActions.find((action) => action.id === "outline-incident-evidence").state, "ready-to-plan");
  for (const actionId of ["preserve-accessible-records", "build-incident-timeline", "test-leading-explanations"]) {
    const action = reportOnlyResult.nextActions.find((entry) => entry.id === actionId);
    assert.equal(action.state, "blocked");
    assert.ok(action.reasonIds.includes("choice-precondition-not-met:data-access-basis"));
  }

  const accessible = structuredClone(reportOnly);
  accessible.answers["data-access-basis"].choiceId = "own-records";
  const accessibleResult = resolveObjectiveRecommendation(catalog, accessible, { paths });
  assert.ok(accessibleResult.nextActions
    .filter((action) => action.id !== "outline-incident-evidence")
    .every((action) => action.state === "ready-to-plan"));

  const unknownArtifact = proposal({
    dimensions: {
      domain: { value: "data-analysis", basis: inferred() },
      deliverable: { value: "investigation-report", basis: inferred() },
      highestEffect: { value: "local-read", basis: inferred() }
    },
    signals: [{ id: "artifact", basis: inferred("signal-classification") }],
    answers: {
      "artifact-possession": { choiceId: "unknown", mode: "explicit", basis: stated() }
    }
  });
  const artifactResult = resolveObjectiveRecommendation(catalog, unknownArtifact, { paths });
  assert.equal(artifactResult.route.id, "local-artifact-analysis");
  assert.ok(artifactResult.nextActions.every((action) =>
    action.state === "blocked" && action.reasonIds.includes("choice-precondition-not-met:artifact-possession")
  ));

  const unknownSystem = proposal({
    dimensions: {
      domain: { value: "system-operations", basis: inferred() },
      deliverable: { value: "operation", basis: inferred() },
      highestEffect: { value: "local-read", basis: inferred() },
      dataClass: { value: "internal", basis: inferred() }
    },
    signals: [],
    answers: {
      "operation-scope": { choiceId: "unknown-system", mode: "explicit", basis: stated() }
    }
  });
  const systemResult = resolveObjectiveRecommendation(catalog, unknownSystem, { paths });
  assert.equal(systemResult.route.id, "system-operation");
  assert.equal(systemResult.nextActions[0].state, "blocked");
  assert.ok(systemResult.nextActions[0].reasonIds.includes("choice-precondition-not-met:operation-scope"));
});

test("unknown and mixed objectives surface a bounded clarification and decomposition route", () => {
  const unknown = proposal({
    dimensions: {
      domain: { value: "unknown", basis: unknownBasis() },
      deliverable: { value: "unknown", basis: unknownBasis() },
      relationship: { value: "unknown", basis: unknownBasis() },
      highestEffect: { value: "unknown", basis: unknownBasis() },
      dataClass: { value: "unknown", basis: unknownBasis() }
    },
    signals: [],
    answers: {}
  });
  const unknownResult = resolveObjectiveRecommendation(catalog, unknown, { paths });
  assert.equal(unknownResult.route.id, "objective-clarification");
  assert.equal(unknownResult.route.handler.id, "objective-decomposition-plan");
  assert.equal(unknownResult.route.handler.state, "planning-only");
  assert.equal(unknownResult.route.claimState, "unverified");
  assert.deepEqual(unknownResult.unresolvedQuestionIds, ["primary-workstream", "decomposition-mode"]);
  assert.ok(unknownResult.questions.length >= 1 && unknownResult.questions.length <= 3);
  assert.equal(unknownResult.executionAuthority, false);

  const mixed = proposal({
    dimensions: {
      domain: { value: "mixed", basis: inferred("mixed-workstreams") },
      deliverable: { value: "unknown", basis: unknownBasis() }
    },
    signals: [],
    answers: {}
  });
  assert.equal(resolveObjectiveRecommendation(catalog, mixed, { paths }).route.id, "objective-clarification");

  const bountyAndIncident = proposal({
    dimensions: {
      domain: { value: "security-assessment", basis: inferred() },
      deliverable: { value: "investigation-report", basis: inferred() },
      highestEffect: { value: "target-contact", basis: inferred() }
    },
    signals: ["bounty-program", "account", "payment"].map((id) => ({
      id,
      basis: inferred("signal-classification")
    })),
    answers: {}
  });
  const mixedResult = resolveObjectiveRecommendation(catalog, bountyAndIncident, { paths });
  assert.equal(mixedResult.route.id, "mixed-bounty-incident-decomposition");
  assert.notEqual(mixedResult.route.handler.id, "program-profile-intake");
  assert.deepEqual(mixedResult.unresolvedQuestionIds, ["primary-workstream", "decomposition-mode"]);
});

test("stale, non-categorical, structurally expanded, and false-observation proposals are rejected", () => {
  const stale = proposal({ metadata: { routeCatalogSha256: "0".repeat(64) } });
  assert.match(
    objectiveRoutingProposalSemanticErrors(catalog, stale, { paths }).join("; "),
    /not bound to the current route catalog digest/u
  );

  const unverified = proposal({
    dimensions: {
      domain: {
        value: "security-incident",
        basis: { provenance: "model-derived", claimState: "unverified", code: "insufficient-evidence", sourceRefs: [] }
      }
    }
  });
  assert.match(
    objectiveRoutingProposalSemanticErrors(catalog, unverified, { paths }).join("; "),
    /may be unverified only when its value is unknown/u
  );

  const falseObservation = proposal({
    dimensions: {
      domain: {
        value: "security-incident",
        basis: { provenance: "model-derived", claimState: "observed", code: "objective-classification", sourceRefs: [] }
      }
    }
  });
  assert.match(
    objectiveRoutingProposalSemanticErrors(catalog, falseObservation, { paths }).join("; "),
    /model-derived evidence cannot be observed/u
  );

  const expanded = { ...proposal(), objective: "raw objective text must not enter this envelope" };
  assert.equal(validateDocument(expanded, "objective-routing-proposal.schema.json", { paths }).ok, false);

  const freeTextBasis = proposal();
  freeTextBasis.dimensions.domain.basis.summary = "https://private.example/a/local/path";
  assert.equal(validateDocument(freeTextBasis, "objective-routing-proposal.schema.json", { paths }).ok, false);

  const unregisteredCode = proposal();
  unregisteredCode.dimensions.domain.basis.code = "target-specific-explanation";
  assert.match(
    objectiveRoutingProposalSemanticErrors(catalog, unregisteredCode, { paths }).join("; "),
    /unregistered basis code/u
  );
});

test("handler availability and objective effect bounds remain visible", () => {
  const unavailableCatalog = structuredClone(catalog);
  const route = unavailableCatalog.routes.find((entry) => entry.id === "security-incident-investigation");
  route.handler.state = "unavailable";
  route.handler.reason = "No reviewed incident handler is available.";
  const input = proposal({ metadata: { routeCatalogSha256: objectiveCanonicalSha256(unavailableCatalog) } });
  const unavailable = resolveObjectiveRecommendation(unavailableCatalog, input, { paths });
  assert.equal(unavailable.planStatus, "unsupported");
  assert.ok(unavailable.nextActions.every((action) => action.state === "blocked"));
  assert.ok(unavailable.nextActions.every((action) => action.reasonIds.includes("handler-unavailable")));

  const readOnly = proposal({
    dimensions: {
      highestEffect: { value: "local-read", basis: inferred() }
    }
  });
  const bounded = resolveObjectiveRecommendation(catalog, readOnly, { paths });
  assert.equal(bounded.nextActions.find((action) => action.id === "build-incident-timeline").state, "blocked");
  assert.ok(
    bounded.nextActions.find((action) => action.id === "build-incident-timeline")
      .reasonIds.includes("effect-exceeds-objective-boundary")
  );
  assert.equal(bounded.executionAuthority, false);

  const unknownEffect = proposal({
    dimensions: {
      highestEffect: { value: "unknown", basis: inferred() }
    }
  });
  const unknown = resolveObjectiveRecommendation(catalog, unknownEffect, { paths });
  assert.equal(unknown.nextActions.find((action) => action.effect === "none").state, "ready-to-plan");
  assert.ok(unknown.nextActions.filter((action) => action.effect !== "none").every((action) =>
    action.state === "needs-input" && action.reasonIds.includes("effect-boundary-unresolved")
  ));
});
