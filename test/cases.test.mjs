import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  applyProgramProfileAuthorityConfirmation,
  bountyProfileInternals,
  createProgramProfile,
  resumeProgramProfile,
  verifyProgramProfile
} from "../src/lib/bounty-profiles.mjs";
import {
  caseFleetStatus,
  createCase,
  listCases,
  openCaseRuntime,
  selectCaseRuntime,
  showCase
} from "../src/lib/cases.mjs";
import { createEngagement } from "../src/lib/engagements.mjs";
import { runtimePaths } from "../src/lib/paths.mjs";
import {
  PROGRAM_PROFILE_ACTIONS,
  PROGRAM_PROFILE_COVERAGE_DOMAINS,
  PROGRAM_PROFILE_MODULE_IDS,
  PROGRAM_PROFILE_SECTION_IDS,
  PROGRAM_PROFILE_STOP_CONDITIONS
} from "../src/lib/program-profile-contract.mjs";
import { projectContractBinding, registerProject } from "../src/lib/projects.mjs";
import { buildStatus } from "../src/lib/status.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const gate = path.join(repo, "bin", "gate.mjs");
const fixedAt = "2026-10-14T12:00:00.000Z";
const targetCanary = "https://profile-target-canary.example.test/api";

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-cases-"));
  const paths = runtimePaths({ home: path.join(root, "home"), repo });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, paths };
}

function invoke(args, home, extraEnvironment = {}) {
  return spawnSync(process.execPath, [gate, ...args], {
    cwd: repo,
    env: { ...process.env, GATE_HOME: home, GATE_CASE: "", ...extraEnvironment },
    encoding: "utf8",
    timeout: 10_000
  });
}

function sourceDecision(disposition, options = {}) {
  return {
    disposition,
    claimState: options.claimState || (disposition === "unknown" ? "unverified" : "observed"),
    sourceRefs: ["program-rules"],
    rationale: options.rationale || `The program rules mark this item ${disposition}.`,
    conditions: options.conditions || (disposition === "conditional" ? ["Use the named test account only."] : [])
  };
}

function contact() {
  return {
    name: "Program security team",
    role: "Escalation contact",
    channel: "platform://program-inbox",
    purpose: "Receive incident escalation and vulnerability reports.",
    sourceRefs: ["program-rules"]
  };
}

function completeProfile(id) {
  const value = bountyProfileInternals.initialProfile(id, { now: fixedAt, title: "Canary bounty program" });
  value.metadata.status = "ready-to-materialize";
  value.questionnaire.sectionStatus = Object.fromEntries(PROGRAM_PROFILE_SECTION_IDS.map((section) => [section, "complete"]));
  value.questionnaire.applicableModules = [];
  value.questionnaire.activeSection = null;
  value.identity = {
    programName: "Canary bounty program",
    objective: "Assess the exact listed application and produce reproducible findings.",
    depth: "exhaustive",
    deliverables: ["Technical vulnerability report", "Coverage ledger"],
    successCriteria: ["Every applicable coverage domain has a sourced disposition"]
  };
  value.sources = [{
    id: "program-rules",
    type: "program-rules",
    title: "Published program rules",
    reference: "https://program-rules-canary.example.test/rules",
    contentSha256: "a".repeat(64),
    observedAt: fixedAt,
    claimState: "observed",
    notes: "Rules were copied into operator-controlled private evidence."
  }];
  value.authorization = {
    basis: "public-bug-bounty-program",
    programUrl: "https://program-rules-canary.example.test/rules",
    safeHarbor: sourceDecision("allowed", { rationale: "The cited rules provide safe harbor for compliant research." }),
    validFrom: "2026-01-01T00:00:00.000Z",
    validUntil: "2027-01-01T00:00:00.000Z",
    lastVerifiedAt: fixedAt,
    sourceRefs: ["program-rules"],
    operatorConfirmed: true,
    contacts: [contact()]
  };
  value.scope = {
    assets: [
      {
        id: "primary-web",
        selector: { type: "url", value: targetCanary },
        ...sourceDecision("allowed", { rationale: "The exact URL appears in the in-scope table." }),
        actionOverrides: {},
        limitOverrides: {}
      },
      {
        id: "third-party-auth",
        selector: { type: "domain", value: "identity-provider-canary.example.test" },
        ...sourceDecision("denied", { rationale: "The identity provider is explicitly excluded." }),
        actionOverrides: {},
        limitOverrides: {}
      }
    ],
    thirdPartyHandling: sourceDecision("denied", { rationale: "Do not contact third-party systems." }),
    redirectHandling: sourceDecision("denied", { rationale: "Stop before following a redirect outside the exact selector." }),
    discoveredAssetHandling: sourceDecision("denied", { rationale: "Newly discovered assets need a program clarification." })
  };
  value.techniquePolicy.actions = Object.fromEntries(PROGRAM_PROFILE_ACTIONS.map((action) => [
    action,
    sourceDecision(new Set(["observe", "scan", "authenticate"]).has(action) ? "allowed" : "denied")
  ]));
  value.scope.assets[0].actionOverrides = structuredClone(value.techniquePolicy.actions);
  value.scope.assets[0].limitOverrides = {
    maxMinutes: 120,
    maxRequests: 1000,
    maxParallel: 2,
    maxRatePerSecond: 2,
    maxTokens: 200000,
    maxSpendUsd: 25
  };
  value.techniquePolicy.techniques = [
    {
      id: "header-observation",
      name: "Observe response headers",
      action: "observe",
      ...sourceDecision("allowed"),
      parameters: { method: "GET" }
    },
    {
      id: "header-replay",
      name: "Replay captured authorization headers",
      action: "observe",
      ...sourceDecision("denied"),
      parameters: {}
    }
  ];
  value.limits = {
    timezone: "Etc/UTC",
    windows: [{ days: ["monday", "tuesday", "wednesday", "thursday", "friday"], start: "08:00", end: "18:00" }],
    maxMinutes: 120,
    maxRequests: 1000,
    maxParallel: 2,
    maxRatePerSecond: 2,
    maxTokens: 200000,
    maxSpendUsd: 25,
    sourceRefs: ["program-rules"]
  };
  value.access = {
    accounts: [{
      id: "researcher-account",
      persona: "Researcher",
      role: "Standard user",
      environment: "production bug bounty tenant",
      secretRefs: ["env://GATE_PROFILE_TEST_CREDENTIAL"],
      sourceRefs: ["program-rules"]
    }],
    identityProviderNotes: "Use only the dedicated researcher account."
  };
  value.architecture = {
    components: [
      { id: "browser", name: "Research browser", type: "client", claimState: "observed", sourceRefs: ["program-rules"] },
      { id: "web-api", name: "Program web API", type: "service", claimState: "inferred", sourceRefs: ["program-rules"] }
    ],
    trustBoundaries: [{
      id: "browser-to-api",
      from: "browser",
      to: "web-api",
      description: "Public TLS boundary.",
      claimState: "inferred",
      sourceRefs: ["program-rules"]
    }],
    dataFlows: [{
      id: "request-flow",
      from: "browser",
      to: "web-api",
      dataClassification: "internal",
      description: "Research account requests and responses.",
      claimState: "inferred",
      sourceRefs: ["program-rules"]
    }],
    unknowns: ["Internal service topology is not published."],
    sourceRefs: ["program-rules"]
  };
  value.coverage = Object.fromEntries(PROGRAM_PROFILE_COVERAGE_DOMAINS.map((domain) => [
    domain,
    sourceDecision(new Set(["asset-discovery", "architecture", "authentication", "authorization", "sessions", "inputs", "business-logic", "client-behavior", "data-exposure", "infrastructure"]).has(domain) ? "allowed" : "denied")
  ]));
  value.dataEvidence = {
    classification: "confidential",
    allowedDestinations: ["gate-home"],
    retentionDays: 90,
    redactionRules: ["Remove credentials and unrelated personal data."],
    minimumProof: "Retain the smallest response fragment that establishes impact.",
    secretRefs: ["env://GATE_PROFILE_TEST_CREDENTIAL"],
    sourceRefs: ["program-rules"]
  };
  value.stops = {
    conditions: Object.fromEntries(PROGRAM_PROFILE_STOP_CONDITIONS.map((condition) => [condition, {
      enabled: true,
      response: `Stop affected work on ${condition}, preserve bounded evidence, and escalate.`,
      claimState: "observed",
      sourceRefs: ["program-rules"]
    }])),
    escalationContacts: [contact()],
    cleanup: {
      required: true,
      steps: ["Remove test data and revoke temporary sessions."],
      verification: "Recheck the exact changed object and record restoration evidence.",
      sourceRefs: ["program-rules"]
    }
  };
  value.reporting = {
    severityStandard: "CVSS 4.0 with program impact",
    submissionChannel: "Submit through the program platform inbox.",
    disclosurePolicy: "Do not disclose before written program approval.",
    retestPolicy: "Retest only after the program requests validation.",
    requiredSections: ["Summary", "Reproduction", "Impact", "Evidence", "Remediation"],
    sourceRefs: ["program-rules"]
  };
  value.executionPolicy = {
    requestedAssistanceModes: ["plan", "analyze", "generate-command", "execute", "report", "retest"],
    phases: [{
      id: "primary-active-validation",
      phaseId: "active-surface-validation",
      assetRefs: ["primary-web"],
      actions: ["observe", "scan", "authenticate"],
      allowedToolIds: ["httpx"],
      deniedToolIds: [],
      conditions: [],
      claimState: "observed",
      sourceRefs: ["program-rules"],
      limits: {
        maxMinutes: 120,
        maxRequests: 1000,
        maxParallel: 2,
        maxRatePerSecond: 2,
        maxTokens: 200000,
        maxSpendUsd: 25
      }
    }]
  };
  value.modules = Object.fromEntries(PROGRAM_PROFILE_MODULE_IDS.map((moduleId) => [moduleId, {
    ...sourceDecision("denied", { rationale: `${moduleId} is not applicable to this profile.` }),
    answers: {}
  }]));
  value.ambiguities = [];
  value.attestation = {
    operator: "local-operator",
    answersComplete: true,
    sourceClaimsReviewed: true,
    exactScopeReviewed: true,
    attestedAt: fixedAt,
    attestedRevision: 1
  };
  return value;
}

function createReadyProgram(id, paths) {
  const profile = completeProfile(id);
  createProgramProfile(id, profile, {
    paths,
    now: new Date(Date.parse(fixedAt) - 1).toISOString()
  });
  const reviewed = resumeProgramProfile(id, { paths }).answers;
  Object.assign(reviewed.answers, {
    "authority-operator-confirmed": true,
    "attestation-operator": profile.attestation.operator,
    "attestation-answers-complete": profile.attestation.answersComplete,
    "attestation-sources-reviewed": profile.attestation.sourceClaimsReviewed,
    "attestation-scope-reviewed": profile.attestation.exactScopeReviewed,
    "attestation-at": profile.attestation.attestedAt
  });
  reviewed.metadata.updatedAt = fixedAt;
  applyProgramProfileAuthorityConfirmation(id, reviewed, { paths, now: fixedAt });
  const verification = verifyProgramProfile(id, { paths, now: fixedAt });
  assert.equal(verification.ok, true);
  assert.equal(verification.ready, true);
  return { id, profileSha256: verification.profileSha256 };
}

function managedProject(id) {
  const value = JSON.parse(fs.readFileSync(path.join(repo, "templates", "project.json"), "utf8"));
  value.metadata = { id, displayName: "Case test project" };
  value.repository.url = `https://github.com/example/${id}`;
  return value;
}

function createManagedProject(root, id, paths) {
  const source = path.join(root, `${id}.json`);
  fs.writeFileSync(source, `${JSON.stringify(managedProject(id), null, 2)}\n`, { mode: 0o600 });
  registerProject(source, { paths });
  return projectContractBinding(id, { paths });
}

function mode(file) {
  return fs.statSync(file).mode & 0o777;
}

test("case creation binds ready authority and isolates mutable state while sharing registries", (t) => {
  const { root, paths } = fixture(t);
  const program = createReadyProgram("case-program", paths);
  const project = createManagedProject(root, "case-project", paths);

  const first = createCase("alpha-case", {
    displayName: "Alpha program run",
    program,
    project
  }, { paths, now: fixedAt });
  const second = createCase("beta-case", {
    displayName: "Beta program run",
    program,
    project: null
  }, { paths, now: fixedAt });

  assert.equal(first.created, true);
  assert.equal(first.case.metadata.createdAt, fixedAt);
  assert.equal(first.case.scopeSha256.length, 64);
  assert.equal(second.case.project, null);
  assert.throws(
    () => createCase("alpha-case", { displayName: "Replacement", program }, { paths, now: fixedAt }),
    /already exists/u
  );

  const alpha = selectCaseRuntime("alpha-case", { paths, now: fixedAt });
  const beta = selectCaseRuntime("beta-case", { paths, now: fixedAt });
  assert.equal(alpha.case.scopeSha256, first.case.scopeSha256);
  assert.notEqual(alpha.paths.workflows, beta.paths.workflows);
  assert.notEqual(alpha.paths.executionRuns, beta.paths.executionRuns);
  assert.notEqual(alpha.paths.events, beta.paths.events);
  for (const key of ["projects", "programs", "upstreams", "upstreamTools", "toolRuntimes", "toolCache", "toolArtifactCache"]) {
    assert.equal(alpha.paths[key], beta.paths[key], key);
    assert.equal(alpha.paths[key], paths[key], key);
  }

  const sharedRuntimeId = "shared-runtime-id.json";
  const alphaLookup = path.join(alpha.paths.executionRuns, sharedRuntimeId);
  const betaLookup = path.join(beta.paths.executionRuns, sharedRuntimeId);
  fs.writeFileSync(alphaLookup, "alpha\n", { mode: 0o600 });
  fs.writeFileSync(betaLookup, "beta\n", { mode: 0o600 });
  assert.notEqual(alphaLookup, betaLookup);
  assert.equal(fs.readFileSync(alphaLookup, "utf8"), "alpha\n");
  assert.equal(fs.readFileSync(betaLookup, "utf8"), "beta\n");

  assert.deepEqual(showCase("alpha-case", { paths }), first.case);
  const listed = listCases({ paths });
  assert.equal(listed.scan.complete, true);
  assert.equal(listed.scan.invalid, 0);
  assert.deepEqual(listed.cases.map((item) => item.metadata.id).sort(), ["alpha-case", "beta-case"]);

  const fleet = caseFleetStatus({ paths, now: fixedAt });
  assert.equal(fleet.scan.complete, true);
  assert.equal(fleet.scan.invalid, 0);
  const alphaFleet = fleet.cases.find((item) => item.id === "alpha-case");
  assert.deepEqual(alphaFleet.binding, {
    program: { ...program, current: true },
    project: { ...project, current: true }
  });
  assert.equal(alphaFleet.status, "ready");
  assert.equal(Object.hasOwn(alphaFleet, "paths"), false);
  assert.equal(JSON.stringify(fleet).includes(paths.home), false);

  if (process.platform !== "win32") {
    assert.equal(mode(path.join(paths.cases, "alpha-case")), 0o700);
    assert.equal(mode(alpha.paths.stateHome), 0o700);
    assert.equal(mode(path.join(paths.cases, "alpha-case", "scope.json")), 0o600);
  }
});

test("stale cases remain observable and revocable while new admission stays blocked", async (t) => {
  const { paths } = fixture(t);
  const program = createReadyProgram("drift-program", paths);
  const created = createCase("drift-case", {
    displayName: "Digest drift case",
    program
  }, { paths, now: fixedAt });
  const scoped = selectCaseRuntime("drift-case", { paths, now: fixedAt });
  createEngagement({
    id: "rescue-engagement",
    targets: ["app.example.test"],
    actions: ["scan"],
    tools: ["nmap"]
  }, { paths: scoped.paths });

  const profileFile = path.join(paths.programs, program.id, "program-profile.json");
  const profile = JSON.parse(fs.readFileSync(profileFile, "utf8"));
  profile.metadata.title = "Changed after the case was bound";
  fs.writeFileSync(profileFile, `${JSON.stringify(profile, null, 2)}\n`, { mode: 0o600 });

  assert.deepEqual(showCase("drift-case", { paths }), created.case);
  const opened = openCaseRuntime("drift-case", { paths, now: fixedAt });
  assert.equal(opened.case.scopeSha256, created.case.scopeSha256);
  assert.equal(opened.paths.stateHome, scoped.paths.stateHome);
  assert.deepEqual(opened.caseRef, { id: "drift-case", scopeSha256: created.case.scopeSha256 });
  assert.deepEqual(opened.bindingHealth, {
    status: "stale",
    programCurrent: false,
    projectCurrent: true
  });
  assert.throws(
    () => selectCaseRuntime("drift-case", { paths, now: fixedAt }),
    /program-profile binding is stale or not ready/u
  );
  const status = caseFleetStatus({ paths, now: fixedAt });
  assert.equal(status.cases[0].status, "stale");
  assert.equal(status.cases[0].binding.program.current, false);

  const listedCases = invoke(["case", "list", "--json"], paths.home);
  assert.equal(listedCases.status, 0, listedCases.stderr);
  const listedCase = JSON.parse(listedCases.stdout).cases.find((item) => item.id === "drift-case");
  assert.equal(listedCase.status, "stale");
  assert.equal(listedCase.binding.program.current, false);

  const shownCase = invoke(["case", "show", "drift-case", "--json"], paths.home);
  assert.equal(shownCase.status, 0, shownCase.stderr);
  assert.equal(JSON.parse(shownCase.stdout).program.profileSha256, created.case.program.profileSha256);
  assert.equal(Object.hasOwn(JSON.parse(shownCase.stdout).program, "current"), false);

  const aggregate = await buildStatus({ paths, now: fixedAt });
  const aggregateCase = aggregate.cases.find((item) => item.id === "drift-case");
  assert.equal(aggregateCase.status, "stale");
  assert.equal(aggregateCase.binding.program.current, false);
  assert.ok(aggregateCase.runtime);
  assert.deepEqual(aggregateCase.runtime.engagements, []);
  assert.equal(aggregateCase.runtime.engagementScan.availability, "not-loaded");
  assert.equal(aggregateCase.runtime.engagementScan.recordsRead, 0);
  assert.deepEqual(aggregateCase.runtime.learnings, []);
  assert.equal(fs.existsSync(path.join(paths.engagements, "rescue-engagement.json")), false);

  const caseStatus = invoke(["--case", "drift-case", "status", "--json"], paths.home);
  assert.equal(caseStatus.status, 0, caseStatus.stderr);
  const selectedStatus = JSON.parse(caseStatus.stdout);
  assert.deepEqual(selectedStatus.selection, {
    mode: "case",
    caseId: "drift-case",
    bindingHealth: { status: "stale", programCurrent: false, projectCurrent: true }
  });
  assert.equal(selectedStatus.selectedCaseId, "drift-case");
  assert.deepEqual(selectedStatus.engagements.map((item) => item.metadata.id), ["rescue-engagement"]);
  assert.deepEqual(selectedStatus.learnings, []);

  const aggregateStatus = invoke(["status", "--json"], paths.home);
  assert.equal(aggregateStatus.status, 0, aggregateStatus.stderr);
  const aggregateStatusValue = JSON.parse(aggregateStatus.stdout);
  assert.deepEqual(aggregateStatusValue.selection, { mode: "aggregate", caseId: null });
  assert.equal(aggregateStatusValue.cases.some((item) => item.id === "drift-case"), true);

  const unassignedStatus = invoke(["--unassigned", "status", "--json"], paths.home);
  assert.equal(unassignedStatus.status, 0, unassignedStatus.stderr);
  const unassignedStatusValue = JSON.parse(unassignedStatus.stdout);
  assert.deepEqual(unassignedStatusValue.selection, { mode: "unassigned", caseId: null });
  assert.deepEqual(unassignedStatusValue.cases, []);
  assert.equal(unassignedStatusValue.caseScan.attempted, false);

  const publicLearningBefore = fs.readFileSync(paths.publicLearningRecords, "utf8");
  const rejectedPublicLearning = invoke([
    "--case", "drift-case", "learn",
    "--cause", "A stale case still needs an isolated learning lane.",
    "--change", "Keep the record in the case runtime.",
    "--json"
  ], paths.home);
  assert.notEqual(rejectedPublicLearning.status, 0);
  assert.match(rejectedPublicLearning.stderr, /case-scoped learning must use --private/u);
  assert.equal(fs.readFileSync(paths.publicLearningRecords, "utf8"), publicLearningBefore);

  const privateLearning = invoke([
    "--case", "drift-case", "learn",
    "--cause", "A stale case still needs an isolated learning lane.",
    "--change", "Keep the record in the case runtime.",
    "--private", "--json"
  ], paths.home);
  assert.equal(privateLearning.status, 0, privateLearning.stderr);
  assert.equal(JSON.parse(privateLearning.stdout).sensitivity, "private");
  assert.equal(fs.readFileSync(paths.publicLearningRecords, "utf8"), publicLearningBefore);

  const learnedStatus = invoke(["--case", "drift-case", "status", "--json"], paths.home);
  assert.equal(learnedStatus.status, 0, learnedStatus.stderr);
  assert.equal(JSON.parse(learnedStatus.stdout).learnings.length, 1);

  const engagementStatus = invoke([
    "--case", "drift-case", "engagement", "status", "rescue-engagement", "--json"
  ], paths.home);
  assert.equal(engagementStatus.status, 0, engagementStatus.stderr);
  assert.equal(JSON.parse(engagementStatus.stdout).metadata.id, "rescue-engagement");

  const blockedAdmission = invoke([
    "--case", "drift-case", "engagement", "new", "blocked-new",
    "--targets", "app.example.test", "--actions", "scan", "--tools", "nmap", "--json"
  ], paths.home);
  assert.notEqual(blockedAdmission.status, 0);
  assert.match(blockedAdmission.stderr, /program-profile binding is stale or not ready/u);
  assert.equal(fs.existsSync(path.join(scoped.paths.engagements, "blocked-new.json")), false);

  const workflowsBeforeBlockedPlan = fs.readdirSync(scoped.paths.workflows).sort();
  const blockedTestPlan = invoke([
    "--case", "drift-case", "workflow", "test", "plan", "missing-workflow",
    "--file", path.join(paths.home, "missing-test-plan.json"), "--json"
  ], paths.home);
  assert.notEqual(blockedTestPlan.status, 0);
  assert.match(blockedTestPlan.stderr, /program-profile binding is stale or not ready/u);
  assert.deepEqual(fs.readdirSync(scoped.paths.workflows).sort(), workflowsBeforeBlockedPlan);

  const revoked = invoke([
    "--case", "drift-case", "engagement", "revoke", "rescue-engagement",
    "--confirm", "REVOKE rescue-engagement", "--json"
  ], paths.home);
  assert.equal(revoked.status, 0, revoked.stderr);
  const revokedResult = JSON.parse(revoked.stdout);
  assert.equal(revokedResult.ok, true);
  assert.equal(revokedResult.engagement.metadata.status, "revoked");
  const persistedRevocation = JSON.parse(fs.readFileSync(
    path.join(scoped.paths.engagements, "rescue-engagement.json"),
    "utf8"
  ));
  assert.equal(persistedRevocation.metadata.status, "revoked");
  assert.equal(fs.existsSync(path.join(paths.engagements, "rescue-engagement.json")), false);
});

test("case records reject invalid labels and linked state while remediating private modes", {
  skip: process.platform === "win32" && "Windows uses profile ACLs and may restrict symlink creation"
}, (t) => {
  const { root, paths } = fixture(t);
  const program = createReadyProgram("private-program", paths);
  for (const [id, displayName, expected] of [
    ["Bad_Case", "Valid name", /case id must start/u],
    ["valid-case", "line one\u000bline two", /case display name/u],
    ["valid-case", "", /case display name/u],
    ["valid-case", "1 starts with a number", /case display name/u],
    ["valid-case", "Contains_an_underscore", /case display name/u],
    ["valid-case", `A${"b".repeat(60)}`, /case display name/u]
  ]) {
    assert.throws(() => createCase(id, { displayName, program }, { paths, now: fixedAt }), expected);
  }

  createCase("private-case", { displayName: "Private case", program }, { paths, now: fixedAt });
  const caseRoot = path.join(paths.cases, "private-case");
  const state = path.join(caseRoot, "state");
  const scope = path.join(caseRoot, "scope.json");
  fs.chmodSync(caseRoot, 0o777);
  fs.chmodSync(state, 0o755);
  fs.chmodSync(scope, 0o644);
  showCase("private-case", { paths });
  assert.equal(mode(caseRoot), 0o700);
  assert.equal(mode(state), 0o700);
  assert.equal(mode(scope), 0o600);

  const outside = path.join(root, "outside-scope.json");
  fs.copyFileSync(scope, outside);
  fs.unlinkSync(scope);
  fs.symlinkSync(outside, scope);
  assert.throws(() => showCase("private-case", { paths }), /must not be a symbolic link|without following links/u);
  const fleet = caseFleetStatus({ paths, now: fixedAt });
  assert.equal(fleet.scan.invalid, 1);
  assert.equal(fleet.scan.complete, false);
  assert.deepEqual(fleet.cases[0], {
    id: "private-case",
    displayName: null,
    status: "invalid",
    binding: null,
    isolation: null,
    scopeSha256: null
  });
});

test("aggregate status keeps binding health separate from runtime observation failure", {
  skip: process.platform === "win32" && "creating directory links can require elevated Windows privileges"
}, async (t) => {
  const { root, paths } = fixture(t);
  const program = createReadyProgram("runtime-health-program", paths);
  createCase("runtime-health-case", {
    displayName: "Runtime Health Case",
    program
  }, { paths, now: fixedAt });
  const scoped = selectCaseRuntime("runtime-health-case", { paths, now: fixedAt });
  const outside = path.join(root, "outside-workflows");
  fs.mkdirSync(outside, { mode: 0o700 });
  fs.rmSync(scoped.paths.workflows, { recursive: true, force: true });
  fs.symlinkSync(outside, scoped.paths.workflows, "dir");

  const aggregate = await buildStatus({ paths, now: fixedAt });
  const item = aggregate.cases.find((candidate) => candidate.id === "runtime-health-case");
  assert.equal(item.status, "ready");
  assert.equal(item.binding.program.current, true);
  assert.deepEqual(item.runtimeHealth, {
    status: "unavailable",
    reason: "runtime-observation-failed"
  });
  assert.equal(item.runtime, null);
});

test("case selection rejects a symlinked mutable state root", {
  skip: process.platform === "win32" && "creating directory links can require elevated Windows privileges"
}, (t) => {
  const { root, paths } = fixture(t);
  const program = createReadyProgram("linked-program", paths);
  createCase("linked-case", { displayName: "Linked state case", program }, { paths, now: fixedAt });
  const state = path.join(paths.cases, "linked-case", "state");
  const outside = path.join(root, "outside-state");
  fs.mkdirSync(outside, { mode: 0o700 });
  fs.rmSync(state, { recursive: true, force: true });
  fs.symlinkSync(outside, state, "dir");
  assert.throws(
    () => selectCaseRuntime("linked-case", { paths, now: fixedAt }),
    /must not be a symbolic link/u
  );
});

test("case state-root markers reject missing and cross-case copied bindings", (t) => {
  const { paths } = fixture(t);
  const program = createReadyProgram("marker-program", paths);
  createCase("marker-alpha", { displayName: "Marker Alpha", program }, { paths, now: fixedAt });
  createCase("marker-beta", { displayName: "Marker Beta", program }, { paths, now: fixedAt });

  const alpha = runtimePaths({ home: paths.home, repo: paths.repo, caseId: "marker-alpha" });
  const beta = runtimePaths({ home: paths.home, repo: paths.repo, caseId: "marker-beta" });
  fs.copyFileSync(alpha.caseBinding, beta.caseBinding);
  assert.throws(() => openCaseRuntime("marker-beta", { paths, now: fixedAt }), /state-root binding does not match/u);

  fs.unlinkSync(alpha.caseBinding);
  assert.throws(() => openCaseRuntime("marker-alpha", { paths, now: fixedAt }), /state binding .* does not exist/u);
  const fleet = caseFleetStatus({ paths, now: fixedAt });
  assert.equal(fleet.scan.invalid, 2);
  assert.ok(fleet.cases.every((item) => item.status === "invalid"));
});

test("case creation rechecks source digests immediately before scope publication", (t) => {
  const { paths } = fixture(t);
  const program = createReadyProgram("recheck-program", paths);
  const profileFile = path.join(paths.programs, program.id, "program-profile.json");
  const originalWrite = fs.writeFileSync;
  let changed = false;
  fs.writeFileSync = function injectedWrite(file, ...args) {
    const result = originalWrite.call(this, file, ...args);
    if (!changed && typeof file === "number") {
      changed = true;
      const profile = JSON.parse(fs.readFileSync(profileFile, "utf8"));
      profile.metadata.title = "Changed between the initial and publication checks";
      originalWrite.call(fs, profileFile, `${JSON.stringify(profile, null, 2)}\n`, { mode: 0o600 });
    }
    return result;
  };
  try {
    assert.throws(
      () => createCase("recheck-case", { displayName: "Recheck Case", program }, { paths, now: fixedAt }),
      /program-profile binding is stale or not ready/u
    );
  } finally {
    fs.writeFileSync = originalWrite;
  }
  assert.equal(changed, true);
  assert.equal(fs.existsSync(path.join(paths.cases, "recheck-case")), false);
});

test("failed creation never recursively deletes a replacement case directory", {
  skip: process.platform === "win32" && "renaming an open directory is platform-dependent"
}, (t) => {
  const { root, paths } = fixture(t);
  const program = createReadyProgram("rollback-program", paths);
  const caseRoot = path.join(paths.cases, "rollback-case");
  const displaced = path.join(root, "displaced-created-case");
  const sentinel = path.join(caseRoot, "replacement-sentinel.txt");
  const originalWrite = fs.writeFileSync;
  let replaced = false;
  fs.writeFileSync = function injectedWrite(file, ...args) {
    if (!replaced && typeof file === "number") {
      replaced = true;
      fs.renameSync(caseRoot, displaced);
      fs.mkdirSync(caseRoot, { mode: 0o700 });
      originalWrite.call(fs, sentinel, "replacement must survive\n", { mode: 0o600 });
      throw new Error("injected marker publication failure");
    }
    return originalWrite.call(this, file, ...args);
  };
  try {
    assert.throws(
      () => createCase("rollback-case", { displayName: "Rollback Case", program }, { paths, now: fixedAt }),
      /injected marker publication failure/u
    );
  } finally {
    fs.writeFileSync = originalWrite;
  }
  assert.equal(replaced, true);
  assert.equal(fs.readFileSync(sentinel, "utf8"), "replacement must survive\n");
  assert.equal(fs.existsSync(displaced), true);
});

test("case creation rolls back its exact directory when scoped runtime initialization fails", {
  skip: process.platform === "win32" && "creating directory links can require elevated Windows privileges"
}, (t) => {
  const { root, paths } = fixture(t);
  const program = createReadyProgram("initialize-program", paths);
  const caseRoot = path.join(paths.cases, "initialize-case");
  const outside = path.join(root, "outside-initialize-case");
  fs.mkdirSync(outside, { mode: 0o700 });
  const originalWrite = fs.writeFileSync;
  let privateWrites = 0;
  fs.writeFileSync = function injectedWrite(file, ...args) {
    const result = originalWrite.call(this, file, ...args);
    if (typeof file === "number" && ++privateWrites === 2) {
      fs.symlinkSync(outside, path.join(caseRoot, "state", "engagements"), "dir");
    }
    return result;
  };
  try {
    assert.throws(
      () => createCase("initialize-case", { displayName: "Initialize Case", program }, { paths, now: fixedAt }),
      /must not be a symbolic link/u
    );
  } finally {
    fs.writeFileSync = originalWrite;
  }
  assert.equal(privateWrites >= 2, true);
  assert.equal(fs.existsSync(caseRoot), false);
  assert.equal(fs.existsSync(outside), true);
});

test("case fleet deterministically projects 32 of 40 entries and reports exact omission", (t) => {
  const { paths } = fixture(t);
  fs.mkdirSync(paths.cases, { recursive: true, mode: 0o700 });
  for (let index = 39; index >= 0; index -= 1) {
    fs.mkdirSync(path.join(paths.cases, `case-${String(index).padStart(2, "0")}`), { mode: 0o700 });
  }

  const fleet = caseFleetStatus({ paths, now: fixedAt });
  assert.equal(fleet.cases.length, 32);
  assert.deepEqual(fleet.scan, {
    limit: 32,
    discoveryLimit: 1024,
    discovered: 40,
    scanned: 32,
    omitted: 8,
    discoveredAtLeast: false,
    omittedAtLeast: false,
    complete: false,
    truncated: true,
    invalid: 32
  });
  assert.deepEqual(
    fleet.cases.map((item) => item.id),
    Array.from({ length: 32 }, (_, index) => `case-${String(index).padStart(2, "0")}`)
  );
  assert.ok(fleet.cases.every((item) => item.status === "invalid"));
});

test("case fleet reports lower-bound discovery beyond its hard cap", (t) => {
  const { paths } = fixture(t);
  fs.mkdirSync(paths.cases, { recursive: true, mode: 0o700 });
  for (let index = 0; index < 1025; index += 1) {
    fs.mkdirSync(path.join(paths.cases, `case-${String(index).padStart(4, "0")}`), { mode: 0o700 });
  }

  const fleet = caseFleetStatus({ paths, now: fixedAt });
  assert.equal(fleet.scan.discovered, 1025);
  assert.equal(fleet.scan.omitted, 993);
  assert.equal(fleet.scan.discoveredAtLeast, true);
  assert.equal(fleet.scan.omittedAtLeast, true);
  assert.equal(fleet.scan.complete, false);
  assert.equal(fleet.scan.truncated, true);
});
