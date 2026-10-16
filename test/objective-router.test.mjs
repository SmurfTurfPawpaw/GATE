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

function inferred(summary) {
  return { provenance: "model-derived", claimState: "inferred", summary, sourceRefs: [] };
}

function stated(summary) {
  return { provenance: "operator-stated", claimState: "observed", summary, sourceRefs: [] };
}

function proposal(overrides = {}) {
  const dimensions = {
    domain: { value: "security-incident", basis: inferred("A reported account and payment event needs investigation.") },
    deliverable: { value: "investigation-report", basis: inferred("The requested result is an explanation.") },
    relationship: { value: "unknown", basis: inferred("The relationship to the affected records is not stated.") },
    highestEffect: { value: "local-write", basis: inferred("The initial plan uses private local analysis.") },
    dataClass: { value: "sensitive", basis: inferred("Account and payment records are sensitive.") },
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
      basis: inferred(`The objective concerns ${id} activity.`)
    })),
    answers: overrides.answers || {
      "immediate-goal": {
        choiceId: "explain",
        mode: "recommendation",
        basis: inferred("The requested result is an explanation.")
      }
    }
  };
  return value;
}

test("objective route catalog is schema-valid, internally closed, and uses catalogued tool ids", () => {
  assert.deepEqual(validateDocument(catalog, "objective-route-catalog.schema.json", { paths }).errors, []);
  assert.deepEqual(objectiveRouteCatalogSemanticErrors(catalog, {
    paths,
    toolIds: toolCatalog.tools.map((tool) => tool.id)
  }), []);
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
    tool.state === "catalogued" && tool.suitable === "unknown"
  ));
  assert.doesNotMatch(JSON.stringify(first), /meal-delivery|uber|objective concerns account activity/iu);
  assert.equal(validateDocument(first, "objective-recommendation.schema.json", { paths }).ok, true);
  assert.equal(first.metadata.recommendationSha256, objectiveRouterInternals.recommendationDigest(first));
});

test("bug bounty and generic security assessments use different handlers", () => {
  const securityDimensions = {
    domain: { value: "security-assessment", basis: inferred("The objective is a security assessment.") },
    deliverable: { value: "investigation-report", basis: inferred("The requested result is an assessment report.") },
    relationship: { value: "unknown", basis: inferred("The relationship is not established in routing input.") },
    highestEffect: { value: "target-contact", basis: inferred("The eventual assessment may include target contact.") },
    dataClass: { value: "sensitive", basis: inferred("Assessment scope information is sensitive.") }
  };
  const bounty = proposal({
    dimensions: securityDimensions,
    signals: [{ id: "bounty-program", basis: inferred("The objective explicitly names a bounty program.") }],
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
    relationship: { value: "owned", basis: stated("The operator stated that this is their project.") },
    highestEffect: { value: "local-write", basis: inferred("The work changes a local project copy.") },
    dataClass: { value: "internal", basis: inferred("Repository work is internal by default.") }
  };
  const answer = {
    "project-binding": {
      choiceId: "registered-project",
      mode: "explicit",
      basis: stated("The operator selected the registered project context.")
    }
  };
  const change = proposal({
    dimensions: {
      domain: { value: "software", basis: inferred("The objective requests software work.") },
      deliverable: { value: "change", basis: inferred("The requested result is a change.") },
      ...shared
    },
    signals: [{ id: "repository", basis: inferred("The objective refers to a repository.") }],
    answers: answer
  });
  const investigation = structuredClone(change);
  investigation.dimensions.deliverable = {
    value: "investigation-report",
    basis: inferred("The requested result is a separate investigation report.")
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
        basis: inferred("The model guessed that the records are accessible.")
      }
    }
  });
  assert.match(
    objectiveRoutingProposalSemanticErrors(catalog, recommendedAccess, { paths }).join("; "),
    /manual-only and cannot be recommended/u
  );

  const inferredOwnership = proposal({
    dimensions: {
      relationship: { value: "owned", basis: inferred("The model guessed ownership.") }
    }
  });
  assert.match(
    objectiveRoutingProposalSemanticErrors(catalog, inferredOwnership, { paths }).join("; "),
    /must remain unknown unless directly stated by the operator/u
  );

  const explicitAccess = proposal({
    dimensions: {
      relationship: { value: "owned", basis: stated("The operator directly stated ownership.") }
    },
    answers: {
      "data-access-basis": {
        choiceId: "own-records",
        mode: "explicit",
        basis: stated("The operator selected access to their own records.")
      },
      "immediate-goal": {
        choiceId: "explain",
        mode: "recommendation",
        basis: inferred("The requested result is an explanation.")
      }
    }
  });
  const result = resolveObjectiveRecommendation(catalog, explicitAccess, { paths });
  const access = result.questions.find((question) => question.id === "data-access-basis");
  assert.equal(access.resolved, true);
  assert.equal(access.selectedChoiceId, "own-records");
  assert.equal(access.recommendedChoiceId, null);
});

test("stale, unverified, structurally expanded, and false-observation proposals are rejected", () => {
  const stale = proposal({ metadata: { routeCatalogSha256: "0".repeat(64) } });
  assert.match(
    objectiveRoutingProposalSemanticErrors(catalog, stale, { paths }).join("; "),
    /not bound to the current route catalog digest/u
  );

  const unverified = proposal({
    dimensions: {
      domain: {
        value: "security-incident",
        basis: { provenance: "model-derived", claimState: "unverified", summary: "The domain is uncertain.", sourceRefs: [] }
      }
    }
  });
  assert.match(
    objectiveRoutingProposalSemanticErrors(catalog, unverified, { paths }).join("; "),
    /cannot route from unverified evidence/u
  );

  const falseObservation = proposal({
    dimensions: {
      domain: {
        value: "security-incident",
        basis: { provenance: "model-derived", claimState: "observed", summary: "The model labeled the domain.", sourceRefs: [] }
      }
    }
  });
  assert.match(
    objectiveRoutingProposalSemanticErrors(catalog, falseObservation, { paths }).join("; "),
    /model-derived evidence cannot be observed/u
  );

  const expanded = { ...proposal(), objective: "raw objective text must not enter this envelope" };
  assert.equal(validateDocument(expanded, "objective-routing-proposal.schema.json", { paths }).ok, false);

  const oversized = proposal();
  oversized.dimensions.domain.basis.summary = "x".repeat(65 * 1024);
  const oversizedErrors = objectiveRoutingProposalSemanticErrors(catalog, oversized, { paths });
  assert.ok(oversizedErrors.some((error) => /must NOT have more than 240 characters|64 KiB limit/u.test(error)));
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
      highestEffect: { value: "local-read", basis: inferred("The objective is bounded to local reads.") }
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
      highestEffect: { value: "unknown", basis: inferred("The eventual effect is not established.") }
    }
  });
  const unknown = resolveObjectiveRecommendation(catalog, unknownEffect, { paths });
  assert.equal(unknown.nextActions.find((action) => action.effect === "none").state, "ready-to-plan");
  assert.ok(unknown.nextActions.filter((action) => action.effect !== "none").every((action) =>
    action.state === "needs-input" && action.reasonIds.includes("effect-boundary-unresolved")
  ));
});
