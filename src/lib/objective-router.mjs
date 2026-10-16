import crypto from "node:crypto";

import { validateDocument } from "./schema.mjs";
import { assertNoLikelySecret, assertNoUnsafeText } from "./text.mjs";

export const OBJECTIVE_DOMAINS = Object.freeze([
  "software",
  "security-assessment",
  "security-incident",
  "research",
  "data-analysis",
  "system-operations",
  "communication",
  "personal-administration",
  "other"
]);

export const OBJECTIVE_DELIVERABLES = Object.freeze([
  "change",
  "answer",
  "investigation-report",
  "decision",
  "operation",
  "monitor",
  "communication"
]);

export const OBJECTIVE_RELATIONSHIPS = Object.freeze([
  "owned",
  "authorized",
  "public",
  "third-party",
  "unknown"
]);

export const OBJECTIVE_EFFECTS = Object.freeze([
  "none",
  "local-read",
  "local-write",
  "external-read",
  "external-write",
  "target-contact",
  "high-impact",
  "unknown"
]);

export const OBJECTIVE_DATA_CLASSES = Object.freeze([
  "public",
  "internal",
  "sensitive",
  "secret"
]);

export const OBJECTIVE_SIGNALS = Object.freeze([
  "repository",
  "bounty-program",
  "account",
  "payment",
  "order",
  "identity",
  "device",
  "network",
  "artifact",
  "application",
  "public-source",
  "external-recipient",
  "unknown"
]);

const DIMENSION_FIELDS = Object.freeze([
  ["domain", "domains", OBJECTIVE_DOMAINS],
  ["deliverable", "deliverables", OBJECTIVE_DELIVERABLES],
  ["relationship", "relationships", OBJECTIVE_RELATIONSHIPS],
  ["highestEffect", "effects", OBJECTIVE_EFFECTS],
  ["dataClass", "dataClasses", OBJECTIVE_DATA_CLASSES]
]);

const EFFECT_ORDER = new Map([
  "none",
  "local-read",
  "local-write",
  "external-read",
  "external-write",
  "target-contact",
  "high-impact"
].map((value, index) => [value, index]));
const MAX_ROUTE_CATALOG_BYTES = 1024 * 1024;
const MAX_ROUTING_PROPOSAL_BYTES = 64 * 1024;

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
}

export function objectiveCanonicalSha256(value) {
  return crypto.createHash("sha256").update(JSON.stringify(stableValue(value))).digest("hex");
}

function duplicateIds(items) {
  const seen = new Set();
  const duplicates = new Set();
  for (const item of items || []) {
    if (seen.has(item.id)) duplicates.add(item.id);
    seen.add(item.id);
  }
  return [...duplicates].sort();
}

function sameList(left, right) {
  return Array.isArray(left) && left.length === right.length && left.every((value, index) => value === right[index]);
}

function referencesUnknown(values, known) {
  return (values || []).filter((value) => !known.has(value));
}

function basisErrors(basis, label) {
  const errors = [];
  try {
    assertNoUnsafeText(basis.summary, `${label} summary`);
    assertNoLikelySecret(basis.summary, `${label} summary`);
  } catch (error) {
    errors.push(error.message);
  }
  if (basis.provenance === "model-derived" && basis.claimState === "observed") {
    errors.push(`${label} model-derived evidence cannot be observed`);
  }
  if (basis.provenance === "source-derived" && basis.sourceRefs.length === 0) {
    errors.push(`${label} source-derived evidence requires an opaque source reference`);
  }
  if (basis.provenance !== "source-derived" && basis.sourceRefs.length > 0) {
    errors.push(`${label} may cite source references only with source-derived provenance`);
  }
  return errors;
}

export function objectiveRouteCatalogSemanticErrors(catalog, options = {}) {
  const errors = [];
  const structural = validateDocument(catalog, "objective-route-catalog.schema.json", options);
  if (!structural.ok) return [...structural.errors];
  if (Buffer.byteLength(JSON.stringify(catalog), "utf8") > MAX_ROUTE_CATALOG_BYTES) {
    errors.push("objective route catalog exceeds the 1 MiB limit");
  }

  for (const [, catalogField, expected] of DIMENSION_FIELDS) {
    if (!sameList(catalog.dimensions[catalogField], expected)) {
      errors.push(`objective route catalog dimensions.${catalogField} must match the exact GATE vocabulary`);
    }
  }
  if (!sameList(catalog.dimensions.signals, OBJECTIVE_SIGNALS)) {
    errors.push("objective route catalog dimensions.signals must match the exact GATE vocabulary");
  }

  const collections = [
    ["question", catalog.questions],
    ["evidence step", catalog.evidenceSteps],
    ["data request category", catalog.dataRequestCategories],
    ["capability", catalog.capabilities],
    ["route", catalog.routes]
  ];
  for (const [label, items] of collections) {
    for (const duplicate of duplicateIds(items)) errors.push(`duplicate ${label} id ${duplicate}`);
  }

  const questions = new Map(catalog.questions.map((question) => [question.id, question]));
  const evidenceSteps = new Set(catalog.evidenceSteps.map((entry) => entry.id));
  const dataRequests = new Set(catalog.dataRequestCategories.map((entry) => entry.id));
  const capabilities = new Set(catalog.capabilities.map((entry) => entry.id));
  const priorities = new Set();
  let fallbackCount = 0;

  for (const question of catalog.questions) {
    const choiceIds = question.choices.map((choice) => choice.id);
    if (new Set(choiceIds).size !== choiceIds.length) {
      errors.push(`objective route question ${question.id} has duplicate choice ids`);
    }
    const defaultChoiceId = question.policy.defaultChoiceId;
    if (question.policy.class === "operator-preference") {
      if (!defaultChoiceId || !choiceIds.includes(defaultChoiceId)) {
        errors.push(`objective route question ${question.id} requires a supported operator-preference default`);
      }
    } else if (defaultChoiceId !== undefined) {
      errors.push(`objective route question ${question.id} may not default ${question.policy.class} input`);
    }
  }

  const knownToolIds = options.toolIds ? new Set(options.toolIds) : null;
  for (const capability of catalog.capabilities) {
    if (knownToolIds) {
      for (const toolId of capability.toolCandidates) {
        if (!knownToolIds.has(toolId)) errors.push(`objective capability ${capability.id} references unknown tool ${toolId}`);
      }
    }
  }

  for (const route of catalog.routes) {
    if (priorities.has(route.priority)) errors.push(`objective route priority is duplicated: ${route.priority}`);
    priorities.add(route.priority);
    if (Object.keys(route.match).length === 0) fallbackCount += 1;

    const matchChecks = [
      ["domains", "domains"],
      ["deliverables", "deliverables"],
      ["relationships", "relationships"],
      ["highestEffects", "effects"],
      ["dataClasses", "dataClasses"],
      ["signalsAny", "signals"],
      ["signalsAll", "signals"]
    ];
    for (const [matchField, dimensionField] of matchChecks) {
      for (const unknown of referencesUnknown(route.match[matchField], new Set(catalog.dimensions[dimensionField]))) {
        errors.push(`objective route ${route.id} match.${matchField} references unknown value ${unknown}`);
      }
    }

    const routeQuestions = new Set(route.plan.questionIds);
    for (const unknown of referencesUnknown(route.plan.questionIds, new Set(questions.keys()))) {
      errors.push(`objective route ${route.id} references unknown question ${unknown}`);
    }
    for (const unknown of referencesUnknown(route.plan.evidenceStepIds, evidenceSteps)) {
      errors.push(`objective route ${route.id} references unknown evidence step ${unknown}`);
    }
    for (const unknown of referencesUnknown(route.plan.dataRequestCategoryIds, dataRequests)) {
      errors.push(`objective route ${route.id} references unknown data request ${unknown}`);
    }
    for (const unknown of referencesUnknown(route.plan.capabilityIds, capabilities)) {
      errors.push(`objective route ${route.id} references unknown capability ${unknown}`);
    }
    const actionIds = route.plan.nextActions.map((action) => action.id);
    if (new Set(actionIds).size !== actionIds.length) {
      errors.push(`objective route ${route.id} has duplicate next-action ids`);
    }
    for (const action of route.plan.nextActions) {
      for (const questionId of action.requiresQuestionIds) {
        if (!routeQuestions.has(questionId)) {
          errors.push(`objective route ${route.id} action ${action.id} requires an unlisted question ${questionId}`);
        }
      }
    }
  }
  if (fallbackCount !== 1) errors.push("objective route catalog requires exactly one unconditional fallback route");
  return errors;
}

function proposalStructuralErrors(proposal, options) {
  const result = validateDocument(proposal, "objective-routing-proposal.schema.json", options);
  return result.ok ? [] : result.errors;
}

export function objectiveRoutingProposalSemanticErrors(catalog, proposal, options = {}) {
  const errors = [];
  const catalogErrors = objectiveRouteCatalogSemanticErrors(catalog, options);
  if (catalogErrors.length > 0) return catalogErrors.map((error) => `route catalog: ${error}`);
  const structural = proposalStructuralErrors(proposal, options);
  if (structural.length > 0) return structural;
  if (Buffer.byteLength(JSON.stringify(proposal), "utf8") > MAX_ROUTING_PROPOSAL_BYTES) {
    errors.push("objective routing proposal exceeds the 64 KiB limit");
  }

  const catalogSha256 = objectiveCanonicalSha256(catalog);
  if (proposal.metadata.routeCatalogSha256 !== catalogSha256) {
    errors.push("objective routing proposal is not bound to the current route catalog digest");
  }

  for (const [proposalField, catalogField] of DIMENSION_FIELDS) {
    const fact = proposal.dimensions[proposalField];
    if (!catalog.dimensions[catalogField].includes(fact.value)) {
      errors.push(`objective dimension ${proposalField} uses an unknown value ${fact.value}`);
    }
    errors.push(...basisErrors(fact.basis, `objective dimension ${proposalField}`));
    if (fact.basis.claimState === "unverified") {
      errors.push(`objective dimension ${proposalField} cannot route from unverified evidence`);
    }
  }

  const relationship = proposal.dimensions.relationship;
  if (relationship.value !== "unknown" && !(
    relationship.basis.provenance === "operator-stated" && relationship.basis.claimState === "observed"
  )) {
    errors.push("objective relationship must remain unknown unless directly stated by the operator");
  }

  const signalIds = proposal.signals.map((signal) => signal.id);
  if (new Set(signalIds).size !== signalIds.length) errors.push("objective proposal signals must be unique");
  for (const signal of proposal.signals) {
    if (!catalog.dimensions.signals.includes(signal.id)) {
      errors.push(`objective signal is not registered: ${signal.id}`);
    }
    errors.push(...basisErrors(signal.basis, `objective signal ${signal.id}`));
    if (signal.basis.claimState === "unverified") {
      errors.push(`objective signal ${signal.id} cannot route from unverified evidence`);
    }
  }

  const questions = new Map(catalog.questions.map((question) => [question.id, question]));
  for (const [questionId, answer] of Object.entries(proposal.answers)) {
    const question = questions.get(questionId);
    if (!question) {
      errors.push(`objective proposal answers unknown question ${questionId}`);
      continue;
    }
    if (!question.choices.some((choice) => choice.id === answer.choiceId)) {
      errors.push(`objective proposal question ${questionId} uses unknown choice ${answer.choiceId}`);
    }
    errors.push(...basisErrors(answer.basis, `objective answer ${questionId}`));
    if (answer.basis.claimState === "unverified") {
      errors.push(`objective answer ${questionId} cannot use unverified evidence`);
    }
    if (answer.mode === "explicit" && !(
      answer.basis.provenance === "operator-stated" && answer.basis.claimState === "observed"
    )) {
      errors.push(`objective answer ${questionId} is explicit only when directly stated by the operator`);
    }
    if (question.policy.class === "manual-only" && answer.mode !== "explicit") {
      errors.push(`objective answer ${questionId} is manual-only and cannot be recommended`);
    }
  }
  return errors;
}

function routeMatches(route, proposal) {
  const match = route.match;
  const dimensions = proposal.dimensions;
  const signals = new Set(proposal.signals.map((signal) => signal.id));
  if (match.domains && !match.domains.includes(dimensions.domain.value)) return false;
  if (match.deliverables && !match.deliverables.includes(dimensions.deliverable.value)) return false;
  if (match.relationships && !match.relationships.includes(dimensions.relationship.value)) return false;
  if (match.highestEffects && !match.highestEffects.includes(dimensions.highestEffect.value)) return false;
  if (match.dataClasses && !match.dataClasses.includes(dimensions.dataClass.value)) return false;
  if (match.signalsAny && !match.signalsAny.some((signal) => signals.has(signal))) return false;
  if (match.signalsAll && !match.signalsAll.every((signal) => signals.has(signal))) return false;
  return true;
}

function selectRoute(catalog, proposal) {
  const matches = catalog.routes.filter((route) => routeMatches(route, proposal));
  const maximumPriority = Math.max(...matches.map((route) => route.priority));
  const selected = matches.filter((route) => route.priority === maximumPriority);
  if (selected.length !== 1) throw new Error("objective route resolution did not produce one highest-priority route");
  return selected[0];
}

function publicBasis(basis) {
  return {
    provenance: basis.provenance,
    claimState: basis.claimState,
    sourceCount: basis.sourceRefs.length
  };
}

function questionProjection(question, answer) {
  const explicit = answer?.mode === "explicit";
  let recommendedChoiceId = null;
  let recommendationBasis = null;
  if (!explicit && answer?.mode === "recommendation" && question.policy.class !== "manual-only") {
    recommendedChoiceId = answer.choiceId;
    recommendationBasis = publicBasis(answer.basis);
  } else if (!explicit && question.policy.class === "operator-preference") {
    recommendedChoiceId = question.policy.defaultChoiceId;
    recommendationBasis = {
      provenance: "reviewed-policy",
      claimState: "observed",
      sourceCount: 0
    };
  }
  return {
    id: question.id,
    prompt: question.prompt,
    choices: question.choices.map((choice) => ({ ...choice })),
    policyClass: question.policy.class,
    resolved: explicit,
    selectedChoiceId: explicit ? answer.choiceId : null,
    recommendedChoiceId,
    recommendationBasis
  };
}

function actionProjection(action, proposal, resolvedQuestionIds, handlerState) {
  const reasonIds = [];
  for (const questionId of action.requiresQuestionIds) {
    if (!resolvedQuestionIds.has(questionId)) reasonIds.push(`unresolved-question:${questionId}`);
  }
  const maximumEffect = proposal.dimensions.highestEffect.value;
  if (maximumEffect === "unknown" && action.effect !== "none") {
    reasonIds.push("effect-boundary-unresolved");
  } else if (EFFECT_ORDER.get(action.effect) > EFFECT_ORDER.get(maximumEffect)) {
    reasonIds.push("effect-exceeds-objective-boundary");
  }
  if (handlerState === "unavailable") reasonIds.push("handler-unavailable");
  const blocked = reasonIds.includes("handler-unavailable") || reasonIds.includes("effect-exceeds-objective-boundary");
  return {
    id: action.id,
    description: action.description,
    effect: action.effect,
    maxMinutes: action.maxMinutes,
    maxItems: action.maxItems,
    state: blocked ? "blocked" : reasonIds.length > 0 ? "needs-input" : "ready-to-plan",
    reasonIds
  };
}

function recommendationDigest(value) {
  const copy = structuredClone(value);
  delete copy.metadata.recommendationSha256;
  return objectiveCanonicalSha256(copy);
}

export function resolveObjectiveRecommendation(catalog, proposal, options = {}) {
  const errors = objectiveRoutingProposalSemanticErrors(catalog, proposal, options);
  if (errors.length > 0) throw new Error(`objective routing proposal rejected: ${errors.join("; ")}`);

  const route = selectRoute(catalog, proposal);
  const routeQuestionIds = new Set(route.plan.questionIds);
  const extraneousAnswerIds = Object.keys(proposal.answers).filter((questionId) => !routeQuestionIds.has(questionId));
  if (extraneousAnswerIds.length > 0) {
    throw new Error(`objective routing proposal contains answers outside the selected route: ${extraneousAnswerIds.sort().join(", ")}`);
  }

  const questionsById = new Map(catalog.questions.map((question) => [question.id, question]));
  const questions = route.plan.questionIds.map((questionId) =>
    questionProjection(questionsById.get(questionId), proposal.answers[questionId])
  );
  const unresolvedQuestionIds = questions.filter((question) => !question.resolved).map((question) => question.id);
  const resolvedQuestionIds = new Set(questions.filter((question) => question.resolved).map((question) => question.id));

  const evidenceById = new Map(catalog.evidenceSteps.map((entry) => [entry.id, entry]));
  const dataById = new Map(catalog.dataRequestCategories.map((entry) => [entry.id, entry]));
  const capabilitiesById = new Map(catalog.capabilities.map((entry) => [entry.id, entry]));
  const nextActions = route.plan.nextActions.map((action) =>
    actionProjection(action, proposal, resolvedQuestionIds, route.handler.state)
  );
  const planStatus = route.handler.state === "unavailable"
    ? "unsupported"
    : nextActions.some((action) => action.state === "ready-to-plan")
      ? "ready-to-plan"
      : "needs-input";

  const routeInputs = [
    ...Object.entries(proposal.dimensions).map(([field, fact]) => ({ field: `dimension:${field}`, basis: fact.basis })),
    ...proposal.signals.map((signal) => ({ field: `signal:${signal.id}`, basis: signal.basis }))
  ];
  const routeClaimState = routeInputs.some((entry) => entry.basis.claimState === "inferred")
    ? "inferred"
    : "observed";

  const recommendation = {
    $schema: "https://gate.local/schemas/objective-recommendation.schema.json",
    apiVersion: "gate.dev/objective-recommendation/v1",
    kind: "ObjectiveRecommendation",
    metadata: {
      objectiveHandle: proposal.metadata.objectiveHandle,
      createdAt: proposal.metadata.createdAt,
      routeCatalogSha256: proposal.metadata.routeCatalogSha256,
      proposalSha256: objectiveCanonicalSha256(proposal),
      recommendationSha256: "0".repeat(64)
    },
    route: {
      id: route.id,
      rationale: route.rationale,
      claimState: routeClaimState,
      handler: structuredClone(route.handler)
    },
    planStatus,
    evidencePlan: route.plan.evidenceStepIds.map((id) => structuredClone(evidenceById.get(id))),
    dataRequests: route.plan.dataRequestCategoryIds.map((id) => structuredClone(dataById.get(id))),
    capabilities: route.plan.capabilityIds.map((id) => {
      const capability = capabilitiesById.get(id);
      return {
        id: capability.id,
        description: capability.description,
        state: "required",
        tools: capability.toolCandidates.map((toolId) => ({
          toolId,
          state: "catalogued",
          suitable: "unknown"
        }))
      };
    }),
    nextActions,
    questions,
    unresolvedQuestionIds,
    provenance: routeInputs.map(({ field, basis }) => ({ field, ...publicBasis(basis) })),
    executionAuthority: false
  };
  recommendation.metadata.recommendationSha256 = recommendationDigest(recommendation);
  const validation = validateDocument(recommendation, "objective-recommendation.schema.json", options);
  if (!validation.ok) {
    throw new Error(`objective recommendation generation failed: ${validation.errors.join("; ")}`);
  }
  return structuredClone(recommendation);
}

export const objectiveRouterInternals = Object.freeze({
  EFFECT_ORDER,
  MAX_ROUTE_CATALOG_BYTES,
  MAX_ROUTING_PROPOSAL_BYTES,
  recommendationDigest,
  routeMatches,
  selectRoute
});
