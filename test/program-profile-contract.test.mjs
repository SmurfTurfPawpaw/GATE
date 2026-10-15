import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import {
  PROGRAM_PROFILE_ACTIONS,
  PROGRAM_PROFILE_ASSISTANCE_MODES,
  PROGRAM_PROFILE_CLAIM_STATES,
  PROGRAM_PROFILE_COVERAGE_DOMAINS,
  PROGRAM_PROFILE_DISPOSITIONS,
  PROGRAM_PROFILE_EXECUTION_LIMITS,
  PROGRAM_PROFILE_MODULE_IDS,
  PROGRAM_PROFILE_MODULE_QUESTIONS,
  PROGRAM_PROFILE_QUESTIONS,
  PROGRAM_PROFILE_QUESTIONNAIRE,
  PROGRAM_PROFILE_SECTION_IDS,
  PROGRAM_PROFILE_SECTIONS,
  PROGRAM_PROFILE_STOP_CONDITIONS,
  assertValidProgramProfile,
  loadProgramProfileQuestionnaire,
  normalizeProgramProfile,
  programProfileQuestionAnswerIsComplete,
  validateProgramProfile,
  validateProgramProfileAnswers,
  validateProgramProfileQuestionnaire
} from "../src/lib/program-profile-contract.mjs";

const repo = path.resolve(".");
const at = "2026-01-01T00:00:00.000Z";

function decision(disposition = "unknown", sourceRefs = []) {
  return {
    disposition,
    claimState: disposition === "unknown" ? "unverified" : "observed",
    sourceRefs,
    rationale: disposition === "unknown" ? null : `The cited program source marks this ${disposition}.`,
    conditions: []
  };
}

function draftProfile() {
  return {
    $schema: "https://gate.local/schemas/bug-bounty-program-profile.schema.json",
    apiVersion: "gate.dev/program-profile/v1",
    kind: "BugBountyProgramProfile",
    metadata: {
      id: "example-program",
      title: "Example program",
      owner: "local-operator",
      status: "draft",
      revision: 1,
      createdAt: at,
      updatedAt: at
    },
    questionnaire: {
      sectionStatus: Object.fromEntries(PROGRAM_PROFILE_SECTION_IDS.map((id) => [id, "not-started"])),
      applicableModules: [],
      activeSection: PROGRAM_PROFILE_SECTION_IDS[0]
    },
    identity: {
      programName: "Example program",
      objective: "Operator input required.",
      depth: "thorough",
      deliverables: [],
      successCriteria: []
    },
    sources: [],
    authorization: {
      basis: "public-bug-bounty-program",
      programUrl: "https://example.invalid/security",
      safeHarbor: decision(),
      validFrom: null,
      validUntil: null,
      lastVerifiedAt: at,
      sourceRefs: [],
      operatorConfirmed: false,
      contacts: []
    },
    scope: {
      assets: [],
      thirdPartyHandling: decision(),
      redirectHandling: decision(),
      discoveredAssetHandling: decision()
    },
    techniquePolicy: {
      actions: Object.fromEntries(PROGRAM_PROFILE_ACTIONS.map((id) => [id, decision()])),
      techniques: []
    },
    executionPolicy: {
      requestedAssistanceModes: [],
      phases: []
    },
    limits: {
      timezone: "Etc/UTC",
      windows: [],
      maxMinutes: 60,
      maxRequests: 100,
      maxParallel: 2,
      maxRatePerSecond: 1,
      maxTokens: 10000,
      maxSpendUsd: null,
      sourceRefs: []
    },
    access: { accounts: [], identityProviderNotes: null },
    architecture: { components: [], trustBoundaries: [], dataFlows: [], unknowns: [], sourceRefs: [] },
    coverage: Object.fromEntries(PROGRAM_PROFILE_COVERAGE_DOMAINS.map((id) => [id, decision()])),
    dataEvidence: {
      classification: "internal",
      allowedDestinations: ["gate-home"],
      retentionDays: 30,
      redactionRules: [],
      minimumProof: "Retain only the least evidence needed to establish the finding.",
      secretRefs: [],
      sourceRefs: []
    },
    stops: {
      conditions: Object.fromEntries(PROGRAM_PROFILE_STOP_CONDITIONS.map((id) => [id, {
        enabled: true,
        response: "Stop affected work, preserve bounded evidence, and escalate.",
        claimState: "unverified",
        sourceRefs: []
      }])),
      escalationContacts: [],
      cleanup: {
        required: true,
        steps: [],
        verification: "Verify restoration with the named program contact.",
        sourceRefs: []
      }
    },
    reporting: {
      severityStandard: "program-defined",
      submissionChannel: "Operator input required.",
      disclosurePolicy: "Operator input required.",
      retestPolicy: "Operator input required.",
      requiredSections: [],
      sourceRefs: []
    },
    modules: Object.fromEntries(PROGRAM_PROFILE_MODULE_IDS.map((id) => [id, {
      ...decision(),
      answers: {}
    }])),
    ambiguities: [],
    attestation: {
      operator: "local-operator",
      answersComplete: false,
      sourceClaimsReviewed: false,
      exactScopeReviewed: false,
      attestedAt: null,
      attestedRevision: null
    }
  };
}

function readyProfile() {
  const value = draftProfile();
  const sourceRefs = ["program-rules"];
  value.metadata.status = "ready-to-materialize";
  value.questionnaire.sectionStatus = Object.fromEntries(PROGRAM_PROFILE_SECTION_IDS.map((id) => [id, "complete"]));
  value.questionnaire.applicableModules = ["web-api"];
  value.questionnaire.activeSection = null;
  value.identity.deliverables = ["Private technical report", "Coverage map"];
  value.identity.successCriteria = ["Every applicable coverage domain has a source-backed disposition"];
  value.sources = [{
    id: "program-rules",
    type: "program-rules",
    title: "Example program rules",
    reference: "private://programs/example-program/sources/program-rules.txt",
    contentSha256: "a".repeat(64),
    observedAt: at,
    claimState: "observed",
    notes: null
  }];
  value.authorization.safeHarbor = decision("allowed", sourceRefs);
  value.authorization.sourceRefs = sourceRefs;
  value.authorization.operatorConfirmed = true;
  value.authorization.contacts = [{
    name: "Program security team",
    role: "security contact",
    channel: "private program channel",
    purpose: "Clarification, stop, and escalation",
    sourceRefs
  }];
  value.scope.assets = [{
    id: "example-app",
    selector: { type: "domain", value: "app.example.invalid" },
    ...decision("allowed", sourceRefs),
    actionOverrides: {},
    limitOverrides: {}
  }];
  value.scope.thirdPartyHandling = decision("denied", sourceRefs);
  value.scope.redirectHandling = decision("conditional", sourceRefs);
  value.scope.redirectHandling.conditions = ["Follow only when the destination also matches an allowed selector."];
  value.scope.discoveredAssetHandling = decision("denied", sourceRefs);
  value.techniquePolicy.actions = Object.fromEntries(PROGRAM_PROFILE_ACTIONS.map((id) => [
    id,
    decision(["observe", "scan"].includes(id) ? "allowed" : "denied", sourceRefs)
  ]));
  value.scope.assets[0].actionOverrides = Object.fromEntries(PROGRAM_PROFILE_ACTIONS.map((id) => [
    id,
    structuredClone(value.techniquePolicy.actions[id])
  ]));
  value.scope.assets[0].limitOverrides = Object.fromEntries(PROGRAM_PROFILE_EXECUTION_LIMITS.map((id) => [
    id,
    value.limits[id]
  ]));
  value.executionPolicy = {
    requestedAssistanceModes: [...PROGRAM_PROFILE_ASSISTANCE_MODES],
    phases: [{
      id: "active-surface",
      phaseId: "active-surface-validation",
      assetRefs: ["example-app"],
      actions: ["observe", "scan"],
      allowedToolIds: ["httpx"],
      deniedToolIds: [],
      conditions: [],
      claimState: "observed",
      sourceRefs,
      limits: { maxMinutes: 30, maxRequests: 50 }
    }]
  };
  value.limits.windows = [{
    days: ["monday", "tuesday", "wednesday", "thursday", "friday"],
    start: "09:00",
    end: "17:00"
  }];
  value.limits.sourceRefs = sourceRefs;
  value.architecture.sourceRefs = sourceRefs;
  value.coverage = Object.fromEntries(PROGRAM_PROFILE_COVERAGE_DOMAINS.map((id) => [id, decision("allowed", sourceRefs)]));
  value.dataEvidence.redactionRules = ["Remove authentication material and unrelated personal data."];
  value.dataEvidence.sourceRefs = sourceRefs;
  value.stops.conditions = Object.fromEntries(PROGRAM_PROFILE_STOP_CONDITIONS.map((id) => [id, {
    enabled: true,
    response: "Stop affected work, preserve bounded evidence, and escalate.",
    claimState: "observed",
    sourceRefs
  }]));
  value.stops.escalationContacts = structuredClone(value.authorization.contacts);
  value.stops.cleanup.steps = ["Remove test-created state and verify the original state."];
  value.stops.cleanup.sourceRefs = sourceRefs;
  value.reporting.requiredSections = ["Scope", "Reproduction", "Impact", "Evidence", "Limitations"];
  value.reporting.sourceRefs = sourceRefs;
  value.modules["web-api"] = { ...decision("allowed", sourceRefs), answers: { entryPoints: ["app.example.invalid"], authenticationFlows: ["Researcher login"], automationRules: "Use reviewed limits." } };
  value.attestation = {
    operator: "local-operator",
    answersComplete: true,
    sourceClaimsReviewed: true,
    exactScopeReviewed: true,
    attestedAt: at,
    attestedRevision: value.metadata.revision
  };
  return value;
}

function answerEnvelope(answers) {
  return {
    $schema: "https://gate.local/schemas/bug-bounty-program-profile-answers.schema.json",
    apiVersion: "gate.dev/program-profile-answers/v1",
    kind: "BugBountyProgramProfileAnswers",
    metadata: { programId: "example-program", title: "Example answers", updatedAt: at },
    answers
  };
}

test("questionnaire exposes the exact 12-section, 9-module, 13-action, 13-stop, and 18-domain contracts", () => {
  assert.equal(PROGRAM_PROFILE_SECTIONS.length, 12);
  assert.deepEqual(PROGRAM_PROFILE_SECTIONS.map((section) => section.id), PROGRAM_PROFILE_SECTION_IDS);
  assert.equal(PROGRAM_PROFILE_MODULE_IDS.length, 9);
  assert.equal(PROGRAM_PROFILE_ACTIONS.length, 13);
  assert.deepEqual(PROGRAM_PROFILE_ASSISTANCE_MODES, [
    "plan", "analyze", "generate-command", "execute", "report", "retest"
  ]);
  assert.deepEqual(PROGRAM_PROFILE_EXECUTION_LIMITS, [
    "maxMinutes", "maxRequests", "maxParallel", "maxRatePerSecond", "maxTokens", "maxSpendUsd"
  ]);
  assert.equal(PROGRAM_PROFILE_STOP_CONDITIONS.length, 13);
  assert.equal(PROGRAM_PROFILE_COVERAGE_DOMAINS.length, 18);
  assert.deepEqual(PROGRAM_PROFILE_DISPOSITIONS, ["allowed", "denied", "conditional", "unknown"]);
  assert.deepEqual(PROGRAM_PROFILE_CLAIM_STATES, ["observed", "inferred", "unverified"]);

  const questionnaire = loadProgramProfileQuestionnaire({ repo });
  assert.deepEqual(validateProgramProfileQuestionnaire(questionnaire, { repo }).errors, []);
  assert.equal(questionnaire.apiVersion, "gate.dev/program-profile-questionnaire/v2");
  assert.equal(questionnaire.metadata.version, 4);
  assert.deepEqual(questionnaire.interaction, {
    style: "choice-first",
    preferredSurface: "native-choice-controls",
    deriveBeforeAsk: true,
    maxQuestionsPerBatch: 3,
    maxChoicesPerQuestion: 3,
    recommendation: "best-supported-first",
    freeText: "short-exact-or-unrepresentable-only",
    structuredAnswers: "draft-review-or-decomposed-choices"
  });
  assert.deepEqual(questionnaire.semantics.actions, PROGRAM_PROFILE_ACTIONS);
  assert.deepEqual(questionnaire.semantics.assistanceModes, PROGRAM_PROFILE_ASSISTANCE_MODES);
  assert.deepEqual(questionnaire.semantics.stopConditions, PROGRAM_PROFILE_STOP_CONDITIONS);
  assert.deepEqual(questionnaire.semantics.coverageDomains, PROGRAM_PROFILE_COVERAGE_DOMAINS);
  assert.ok(PROGRAM_PROFILE_QUESTIONS.every((question) => question.section || question.module));
  assert.ok(PROGRAM_PROFILE_MODULE_QUESTIONS.every((question) =>
    question.condition.path === "questionnaire.applicableModules" && question.condition.includes === question.module
  ));
  assert.equal(Object.isFrozen(PROGRAM_PROFILE_QUESTIONNAIRE), true);

  const questions = new Map(PROGRAM_PROFILE_QUESTIONS.map((question) => [question.id, question]));
  assert.match(questions.get("identity-depth").why, /Surface checks alone/u);
  assert.match(questions.get("identity-success-criteria").prompt, /promising signals/u);
  assert.match(questions.get("actions-techniques").prompt, /stateful.*webhook/u);
  assert.match(questions.get("execution-phase-policies").why, /high-friction follow-up/u);
  assert.match(questions.get("web-api-automation-rules").why, /costly or error-prone/u);
});

test("questionnaire v2 requires choice-first interaction metadata while v1 remains readable", () => {
  const questionnaire = loadProgramProfileQuestionnaire({ repo });
  const missingInteraction = structuredClone(questionnaire);
  delete missingInteraction.interaction;
  assert.ok(validateProgramProfileQuestionnaire(missingInteraction, { repo }).errors.some((error) =>
    error.includes("interaction")
  ));

  const legacy = structuredClone(missingInteraction);
  legacy.apiVersion = "gate.dev/program-profile-questionnaire/v1";
  assert.deepEqual(validateProgramProfileQuestionnaire(legacy, { repo }).errors, []);
});

test("questionnaire validation requires exact execution-policy questions and assistance choices", () => {
  const missing = structuredClone(PROGRAM_PROFILE_QUESTIONNAIRE);
  for (const section of missing.sections) {
    section.questions = section.questions.filter((question) => ![
      "execution-requested-assistance-modes",
      "execution-phase-policies"
    ].includes(question.id));
  }
  const missingResult = validateProgramProfileQuestionnaire(missing, { repo });
  assert.equal(missingResult.ok, false);
  assert.ok(missingResult.errors.some((error) =>
    error.includes("requires question execution-requested-assistance-modes")
  ));
  assert.ok(missingResult.errors.some((error) => error.includes("requires question execution-phase-policies")));

  const reduced = structuredClone(PROGRAM_PROFILE_QUESTIONNAIRE);
  reduced.sections.find((item) => item.id === "actions-techniques").questions
    .find((question) => question.id === "execution-requested-assistance-modes").choices = ["plan"];
  const reducedResult = validateProgramProfileQuestionnaire(reduced, { repo });
  assert.equal(reducedResult.ok, false);
  assert.ok(reducedResult.errors.some((error) =>
    error.includes("execution assistance choices must exactly match")
  ));

  const incompleteAttestation = structuredClone(PROGRAM_PROFILE_QUESTIONNAIRE);
  incompleteAttestation.sections.find((item) => item.id === "ambiguities-attestation").questions
    .find((question) => question.id === "attestation-at").required = false;
  const attestationResult = validateProgramProfileQuestionnaire(incompleteAttestation, { repo });
  assert.equal(attestationResult.ok, false);
  assert.ok(attestationResult.errors.some((error) => error.includes("questionnaire question attestation-at")));
});

test("program-profile vocabularies stay aligned with engagement and pentest workflow contracts", () => {
  const engagementSchema = JSON.parse(fs.readFileSync(path.join(repo, "schemas", "engagement.schema.json"), "utf8"));
  const workflow = JSON.parse(fs.readFileSync(path.join(repo, "config", "workflows", "pentest-e2e.json"), "utf8"));
  const engagementStops = engagementSchema.properties.stopOn.items.enum;
  const workflowStops = [...new Set([
    ...workflow.defaultStopConditions,
    ...workflow.phases.flatMap((phase) => phase.stopPolicy?.additional || [])
  ])];
  assert.deepEqual(engagementSchema.$defs.action.enum, PROGRAM_PROFILE_ACTIONS);
  assert.deepEqual(new Set(engagementStops), new Set(PROGRAM_PROFILE_STOP_CONDITIONS));
  assert.deepEqual(new Set(workflowStops), new Set(PROGRAM_PROFILE_STOP_CONDITIONS));
  assert.deepEqual(workflow.coverageDomains, PROGRAM_PROFILE_COVERAGE_DOMAINS);
});

test("a no-answer profile is a schema-valid resumable draft but is not ready", () => {
  const value = draftProfile();
  assert.deepEqual(validateProgramProfile(value, { repo }).errors, []);

  value.metadata.status = "ready-to-materialize";
  const validation = validateProgramProfile(value, { repo });
  assert.equal(validation.ok, false);
  assert.ok(validation.errors.some((error) => error.includes("sources must contain at least one item")));
  assert.ok(validation.errors.some((error) => error.includes("remains unknown")));
  assert.ok(validation.errors.some((error) => error.includes("attestation.answersComplete")));
});

test("a complete source-backed profile validates for deterministic materialization", () => {
  const value = readyProfile();
  assert.equal(assertValidProgramProfile(value, { repo }), value);
  assert.deepEqual(validateProgramProfile(value, { repo }).errors, []);
});

test("normalized selector collisions cannot encode conflicting scope entries", () => {
  const value = draftProfile();
  value.scope.assets = [
    {
      id: "network-a",
      selector: { type: "cidr", value: "192.0.2.17/24" },
      ...decision("denied"),
      actionOverrides: {},
      limitOverrides: {}
    },
    {
      id: "network-b",
      selector: { type: "cidr", value: "192.0.2.0/24" },
      ...decision("allowed"),
      actionOverrides: {},
      limitOverrides: {}
    },
    {
      id: "idna-a",
      selector: { type: "domain", value: "éxample.com" },
      ...decision("denied"),
      actionOverrides: {},
      limitOverrides: {}
    },
    {
      id: "idna-b",
      selector: { type: "domain", value: "xn--xample-9ua.com." },
      ...decision("allowed"),
      actionOverrides: {},
      limitOverrides: {}
    }
  ];
  const validation = validateProgramProfile(value, { repo });
  assert.equal(validation.ok, false);
  assert.ok(validation.errors.some((error) =>
    error.includes("duplicates normalized selector from asset network-a: cidr:192.0.2.0/24")
  ));
  assert.ok(validation.errors.some((error) =>
    error.includes("duplicates normalized selector from asset idna-a: domain:xn--xample-9ua.com")
  ));
});

test("allowed tools must be mapped to their selected workflow phase", () => {
  const value = readyProfile();
  value.executionPolicy.phases[0].phaseId = "reporting-and-closeout";
  value.executionPolicy.phases[0].allowedToolIds = ["sqlmap"];
  const validation = validateProgramProfile(value, { repo });
  assert.equal(validation.ok, false);
  assert.ok(validation.errors.some((error) =>
    error.includes("tool sqlmap is not mapped to workflow phase reporting-and-closeout")
  ));
});

test("execution phase policies resolve workflow, asset, tool, and source references", () => {
  const value = readyProfile();
  value.executionPolicy.phases[0] = {
    ...value.executionPolicy.phases[0],
    phaseId: "invented-phase",
    assetRefs: ["missing-asset"],
    allowedToolIds: ["missing-tool", "nmap"],
    deniedToolIds: ["nmap"],
    sourceRefs: ["missing-source"]
  };
  const validation = validateProgramProfile(value, { repo });
  assert.equal(validation.ok, false);
  assert.ok(validation.errors.some((error) => error.includes("unknown pentest workflow phase: invented-phase")));
  assert.ok(validation.errors.some((error) => error.includes("references unknown scope asset: missing-asset")));
  assert.ok(validation.errors.some((error) => error.includes("references unknown tool: missing-tool")));
  assert.ok(validation.errors.some((error) => error.includes("both allows and denies tool: nmap")));
  assert.ok(validation.errors.some((error) => error.includes("references unknown source: missing-source")));
});

test("asset and phase policy overrides cannot broaden global ceilings", () => {
  const value = readyProfile();
  value.scope.assets[0].actionOverrides["destructive-test"] = decision("allowed", ["program-rules"]);
  value.scope.assets[0].limitOverrides.maxRequests = value.limits.maxRequests + 1;
  value.executionPolicy.phases[0].limits.maxMinutes = value.limits.maxMinutes + 1;
  const validation = validateProgramProfile(value, { repo });
  assert.equal(validation.ok, false);
  assert.ok(validation.errors.some((error) =>
    error.includes("actionOverrides/destructive-test broadens the global action disposition")
  ));
  assert.ok(validation.errors.some((error) =>
    error.includes("limitOverrides/maxRequests broadens the global execution limit")
  ));
  assert.ok(validation.errors.some((error) =>
    error.includes("executionPolicy/phases/0/limits/maxMinutes broadens the global execution limit")
  ));
});

test("ready profiles require exact per-asset policies, execution intent, and a current attestation", () => {
  const value = readyProfile();
  delete value.scope.assets[0].actionOverrides.scan;
  delete value.scope.assets[0].limitOverrides.maxRequests;
  value.executionPolicy.requestedAssistanceModes = [];
  value.executionPolicy.phases = [];
  value.attestation.attestedRevision = value.metadata.revision + 1;
  const validation = validateProgramProfile(value, { repo });
  assert.equal(validation.ok, false);
  assert.ok(validation.errors.some((error) =>
    error.includes("executionPolicy.requestedAssistanceModes must contain at least one item")
  ));
  assert.ok(validation.errors.some((error) =>
    error.includes("executionPolicy.phases must contain at least one item")
  ));
  assert.ok(validation.errors.some((error) => error.includes("exact decision for scan when ready")));
  assert.ok(validation.errors.some((error) => error.includes("exact maxRequests ceiling when ready")));
  assert.ok(validation.errors.some((error) => error.includes("has no execution phase policy")));
  assert.ok(validation.errors.some((error) =>
    error.includes("attestation.attestedRevision must equal metadata.revision")
  ));
});

test("conditional and unknown decisions cannot masquerade as allowed decisions", () => {
  const conditional = readyProfile();
  conditional.techniquePolicy.actions.fuzz = decision("conditional", ["program-rules"]);
  const missingCondition = validateProgramProfile(conditional, { repo });
  assert.equal(missingCondition.ok, false);
  assert.ok(missingCondition.errors.some((error) => error.includes("must NOT have fewer than 1 items")));

  const unknown = readyProfile();
  unknown.coverage.inputs = decision("unknown", ["program-rules"]);
  const unknownResult = validateProgramProfile(unknown, { repo });
  assert.equal(unknownResult.ok, false);
  assert.ok(unknownResult.errors.some((error) => error.includes("/coverage/inputs remains unknown")));

  const mislabeled = draftProfile();
  mislabeled.techniquePolicy.actions.scan.claimState = "observed";
  assert.equal(validateProgramProfile(mislabeled, { repo }).ok, false);
});

test("provenance references must resolve even while a profile is a draft", () => {
  const value = draftProfile();
  value.authorization.sourceRefs = ["missing-source"];
  const validation = validateProgramProfile(value, { repo });
  assert.equal(validation.ok, false);
  assert.ok(validation.errors.some((error) => error.includes("references unknown source: missing-source")));
});

test("ready supporting claims retain their own provenance", () => {
  const value = readyProfile();
  value.authorization.contacts[0].sourceRefs = [];
  const validation = validateProgramProfile(value, { repo });
  assert.equal(validation.ok, false);
  assert.ok(validation.errors.some((error) => error.includes("/authorization/contacts/0 requires sourceRefs")));
});

test("headless answers accept known question ids and reject unknown ids", () => {
  const envelope = answerEnvelope({
    "identity-objective": "Validate authorization and tenant isolation with source-backed coverage.",
    "coverage-applicable-modules": ["web-api"]
  });
  assert.deepEqual(validateProgramProfileAnswers(envelope, { repo }).errors, []);
  const unknown = answerEnvelope({ "invented-question": true });
  const validation = validateProgramProfileAnswers(unknown, { repo });
  assert.equal(validation.ok, false);
  assert.deepEqual(validation.errors, ["answers contains unknown question id: invented-question"]);
});

test("answer envelope v2 requires an explicit paired base binding while v1 remains readable", () => {
  const unbound = answerEnvelope({ "identity-objective": "Create a new private profile." });
  unbound.apiVersion = "gate.dev/program-profile-answers/v2";
  unbound.metadata.baseRevision = null;
  unbound.metadata.baseProfileSha256 = null;
  assert.deepEqual(validateProgramProfileAnswers(unbound, { repo }).errors, []);

  const missing = structuredClone(unbound);
  delete missing.metadata.baseProfileSha256;
  assert.ok(validateProgramProfileAnswers(missing, { repo }).errors.some((error) =>
    error.includes("metadata.baseProfileSha256 is required")
  ));

  const unpaired = structuredClone(unbound);
  unpaired.metadata.baseRevision = 1;
  assert.ok(validateProgramProfileAnswers(unpaired, { repo }).errors.some((error) =>
    error.includes("must both be null or both identify a base profile")
  ));

  const legacyWithBinding = answerEnvelope({});
  legacyWithBinding.metadata.baseRevision = 1;
  legacyWithBinding.metadata.baseProfileSha256 = "a".repeat(64);
  assert.ok(validateProgramProfileAnswers(legacyWithBinding, { repo }).errors.some((error) =>
    error.includes("v1 cannot claim a v2 base binding")
  ));
});

test("normalization is pure and produces stable ids, vocabularies, and source references", () => {
  const value = readyProfile();
  value.sources.push({ ...value.sources[0], id: "operator-statement", title: "Operator statement" });
  value.scope.assets.push({
    id: "aaa-excluded",
    selector: { type: "ip", value: "192.0.2.10" },
    ...decision("denied", ["program-rules"]),
    actionOverrides: {},
    limitOverrides: {}
  });
  value.questionnaire.applicableModules = ["desktop", "web-api", "desktop"];
  value.authorization.sourceRefs = ["program-rules", "program-rules"];
  value.executionPolicy.requestedAssistanceModes = [...PROGRAM_PROFILE_ASSISTANCE_MODES].reverse();
  value.executionPolicy.phases[0].actions = ["scan", "observe"];
  value.executionPolicy.phases[0].allowedToolIds = ["httpx", "amass"];
  value.scope.assets[0].actionOverrides = Object.fromEntries(
    Object.entries(value.scope.assets[0].actionOverrides).reverse()
  );
  value.scope.assets[0].limitOverrides = Object.fromEntries(
    Object.entries(value.scope.assets[0].limitOverrides).reverse()
  );
  const before = structuredClone(value);
  const normalized = normalizeProgramProfile(value);
  assert.deepEqual(value, before);
  assert.deepEqual(normalized.questionnaire.applicableModules, ["web-api", "desktop"]);
  assert.deepEqual(normalized.authorization.sourceRefs, ["program-rules"]);
  assert.deepEqual(normalized.scope.assets.map((asset) => asset.id), ["aaa-excluded", "example-app"]);
  assert.deepEqual(normalized.executionPolicy.requestedAssistanceModes, PROGRAM_PROFILE_ASSISTANCE_MODES);
  assert.deepEqual(normalized.executionPolicy.phases[0].actions, ["observe", "scan"]);
  assert.deepEqual(normalized.executionPolicy.phases[0].allowedToolIds, ["amass", "httpx"]);
  assert.deepEqual(Object.keys(normalized.scope.assets[1].actionOverrides), PROGRAM_PROFILE_ACTIONS);
  assert.deepEqual(Object.keys(normalized.scope.assets[1].limitOverrides), PROGRAM_PROFILE_EXECUTION_LIMITS);
  assert.deepEqual(Object.keys(normalized.techniquePolicy.actions), PROGRAM_PROFILE_ACTIONS);
  assert.deepEqual(Object.keys(normalized.coverage), PROGRAM_PROFILE_COVERAGE_DOMAINS);
  assert.deepEqual(Object.keys(normalized.stops.conditions), PROGRAM_PROFILE_STOP_CONDITIONS);
});

test("module answer types hold for individual answers, nested answers, and stored profiles", () => {
  for (const question of PROGRAM_PROFILE_MODULE_QUESTIONS.filter((item) => item.path.includes(".answers."))) {
    const key = question.path.split(".").at(-1);
    const valid = question.type === "structured-list" ? ["Reviewed fixture"] : "Reviewed fixture";
    const invalid = question.type === "structured-list" ? [null, 42, {}] : [null, 42, {}, []];
    assert.equal(validateProgramProfileAnswers(answerEnvelope({ [question.id]: valid }), { repo }).ok, true);
    for (const answer of invalid) {
      const individual = validateProgramProfileAnswers(answerEnvelope({ [question.id]: answer }), { repo });
      assert.equal(individual.ok, false, question.id);
      const parent = PROGRAM_PROFILE_MODULE_QUESTIONS.find((item) => item.path === `modules.${question.module}`);
      const nested = validateProgramProfileAnswers(answerEnvelope({
        [parent.id]: { ...decision("allowed", ["program-rules"]), answers: { [key]: answer } }
      }), { repo });
      assert.equal(nested.ok, false, parent.id);
      const profile = draftProfile();
      profile.modules[question.module].answers[key] = answer;
      const stored = validateProgramProfile(profile, { repo });
      assert.equal(stored.ok, false, question.path);
      assert.ok(stored.errors.some((error) => error.startsWith(question.path)));
    }
  }
  const missing = readyProfile();
  delete missing.modules["web-api"].answers.automationRules;
  assert.equal(validateProgramProfile(missing, { repo }).ok, false);
});

test("applicable required module answers contain non-empty content when ready", () => {
  const cases = [
    ["entryPoints", [], "modules.web-api.answers.entryPoints must contain at least one item when ready"],
    ["entryPoints", [null], "modules.web-api.answers.entryPoints.0 must be non-empty text or an object containing non-empty text when ready"],
    ["entryPoints", ["  \t"], "modules.web-api.answers.entryPoints.0 must be non-empty text or an object containing non-empty text when ready"],
    ["entryPoints", ["\u200b\u200d"], "modules.web-api.answers.entryPoints.0 must be non-empty text or an object containing non-empty text when ready"],
    ["entryPoints", [{}], "modules.web-api.answers.entryPoints.0 must be non-empty text or an object containing non-empty text when ready"],
    ["entryPoints", [[]], "modules.web-api.answers.entryPoints.0 must be non-empty text or an object containing non-empty text when ready"],
    ["entryPoints", [{ selector: "", note: null }], "modules.web-api.answers.entryPoints.0 must be non-empty text or an object containing non-empty text when ready"],
    ["entryPoints", [{ arbitrary: true }], "modules.web-api.answers.entryPoints.0 must be non-empty text or an object containing non-empty text when ready"],
    ["entryPoints", [false], "modules.web-api.answers.entryPoints.0 must be non-empty text or an object containing non-empty text when ready"],
    ["authenticationFlows", [], "modules.web-api.answers.authenticationFlows must contain at least one item when ready"],
    ["automationRules", "", "modules.web-api.answers.automationRules must contain non-whitespace text when ready"],
    ["automationRules", " \n\t", "modules.web-api.answers.automationRules must contain non-whitespace text when ready"],
    ["automationRules", "\u200b\u200d", "modules.web-api.answers.automationRules must contain non-whitespace text when ready"]
  ];
  for (const [key, answer, message] of cases) {
    const value = readyProfile();
    value.modules["web-api"].answers[key] = answer;
    const validation = validateProgramProfile(value, { repo });
    assert.equal(validation.ok, false, key);
    assert.ok(validation.errors.includes(message), key);
  }

  const explicitOptionalValue = readyProfile();
  explicitOptionalValue.modules["web-api"].answers.entryPoints = [{
    selector: "https://example.test",
    note: null
  }];
  assert.equal(validateProgramProfile(explicitOptionalValue, { repo }).ok, true);
});

test("architecture unknowns require visible supplied entries while allowing an empty list", () => {
  const question = PROGRAM_PROFILE_QUESTIONS.find((item) => item.path === "architecture.unknowns");
  for (const unknowns of [[""], [" \t"], ["\u200b"], ["\u200b\u200d"], ["Unverified data flow", "\u200b"]]) {
    const value = readyProfile();
    value.architecture.unknowns = unknowns;
    assert.equal(validateProgramProfile(value, { repo }).ok, false, JSON.stringify(unknowns));
    assert.equal(programProfileQuestionAnswerIsComplete(question, unknowns), false, JSON.stringify(unknowns));
  }
  for (const unknowns of [[], ["The session storage boundary is unverified"]]) {
    const value = readyProfile();
    value.architecture.unknowns = unknowns;
    assert.equal(validateProgramProfile(value, { repo }).ok, true);
    assert.equal(programProfileQuestionAnswerIsComplete(question, unknowns), true);
  }
});

test("ready profiles reject invisible-only text outside conditional modules", () => {
  for (const [pathName, mutate] of [
    ["identity.objective", (value) => { value.identity.objective = "\u200b\u200d"; }],
    ["identity.deliverables.0", (value) => { value.identity.deliverables[0] = "\u200b\u200d"; }]
  ]) {
    const value = readyProfile();
    mutate(value);
    const validation = validateProgramProfile(value, { repo });
    assert.equal(validation.ok, false, pathName);
    assert.ok(validation.errors.some((error) =>
      error.includes(pathName.replaceAll(".", "/")) || error.includes(pathName)
    ), pathName);
  }

  const literalPayload = readyProfile();
  literalPayload.techniquePolicy.techniques.push({
    id: "literal-invisible-payload",
    name: "Literal invisible-character payload",
    action: "observe",
    ...decision("allowed", ["program-rules"]),
    parameters: { payload: "\u200b" }
  });
  const literalValidation = validateProgramProfile(literalPayload, { repo });
  assert.equal(literalValidation.ok, false);
  assert.ok(literalValidation.errors.some((error) =>
    error.includes("techniquePolicy.techniques.0.parameters.payload") && error.includes("invisible")
  ));

  const invisibleKey = readyProfile();
  invisibleKey.techniquePolicy.techniques.push({
    id: "invisible-key-payload",
    name: "Invisible-key payload",
    action: "observe",
    ...decision("allowed", ["program-rules"]),
    parameters: { ["safe\u001b]52;c;payload\u0007"]: "benign" }
  });
  const keyValidation = validateProgramProfile(invisibleKey, { repo });
  assert.equal(keyValidation.ok, false);
  assert.ok(keyValidation.errors.some((error) =>
    error.includes("techniquePolicy.techniques.0.parameters property name") && error.includes("terminal control")
  ));
});
