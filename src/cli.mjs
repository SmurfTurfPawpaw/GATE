import fs from "node:fs";
import path from "node:path";
import { createInterface } from "node:readline/promises";
import { parseArgs, listFlag, requiredFlag } from "./lib/args.mjs";
import {
  applyProgramProfileRecommendation,
  applyProgramProfileRecommendations,
  applyProgramProfileAnswers,
  applyProgramProfileAuthorityConfirmation,
  compileProgramProfile,
  createProgramProfile,
  createProgramProfileWithRecommendations,
  loadProgramProfileAnswers,
  loadProgramProfileRecommendations,
  programProfileRecommendation,
  programProfileStatus,
  resumeProgramProfile,
  showProgramProfile,
  verifyProgramProfile
} from "./lib/bounty-profiles.mjs";
import { caseFleetStatus, createCase, openCaseRuntime, selectCaseRuntime, showCase } from "./lib/cases.mjs";
import { loadConfig, writeJsonAtomic } from "./lib/config.mjs";
import { runDoctor } from "./lib/doctor.mjs";
import {
  approveEngagement,
  attachAuthorization,
  attachPlan,
  checkEngagement,
  closeEngagement,
  createEngagement,
  getEngagement,
  recordTechnicalReview,
  revokeEngagement
} from "./lib/engagements.mjs";
import {
  createExecutionManifest,
  createManagedExecutionManifest,
  executeExecutionManifest,
  reconcileExecution,
  requestEngagementStops,
  requestExecutionStop
} from "./lib/executions.mjs";
import { recordEvent } from "./lib/events.mjs";
import {
  addLearning,
  addLearningCycle,
  consultLearnings,
  learningCandidateSha256,
  promoteLearning
} from "./lib/learnings.mjs";
import {
  createOfflineAnalysisManifest,
  executeOfflineAnalysisManifest,
  offlineAnalysisCapability,
  offlineAnalysisStatus,
  purgeOfflineAnalysisArtifact
} from "./lib/offline-analysis.mjs";
import { recommendObjectiveFromPrivateFile } from "./lib/objectives.mjs";
import { ensureRuntime, runtimePaths } from "./lib/paths.mjs";
import { checkPublication, publishPullRequest } from "./lib/publication.mjs";
import {
  listProjects,
  projectContractBinding,
  registerProject,
  showProject,
  verifyProject
} from "./lib/projects.mjs";
import { buildStatus } from "./lib/status.mjs";
import { statusSummary, toolDetailSummary, toolInventorySummary } from "./lib/summaries.mjs";
import { readOperatorDisplayName } from "./lib/terminal-ui.mjs";
import { escapeUnsafeText } from "./lib/text.mjs";
import { runManagedToolOperation } from "./lib/tool-runtimes.mjs";
import { toolInventory, toolPlan, toolShow } from "./lib/tools.mjs";
import { installUpstream, syncUpstream, upstreamStatus } from "./lib/upstreams.mjs";
import { validateRepository } from "./lib/validation.mjs";
import { leaseWorkspace, verifyWorkspace, workspaceStatus } from "./lib/workspaces.mjs";
import {
  PROGRAM_PROFILE_ACTIONS,
  PROGRAM_PROFILE_COVERAGE_DOMAINS,
  PROGRAM_PROFILE_EXECUTION_LIMITS,
  PROGRAM_PROFILE_QUESTIONS,
  PROGRAM_PROFILE_SECTIONS,
  PROGRAM_PROFILE_STOP_CONDITIONS,
  programProfileQuestionAnswerIsComplete
} from "./lib/program-profile-contract.mjs";
import {
  addWorkflowEvidence,
  attachWorkflowReport,
  cancelWorkflowExecution,
  closeWorkflow,
  createWorkflowInstance,
  finishWorkflowPhase,
  holdWorkflowLedger,
  joinWorkflowCoverage,
  openWorkflowLedger,
  planWorkflowTest,
  preflightWorkflowPhase,
  preflightWorkflowPivot,
  recordWorkflowLedgerCleanup,
  reviewWorkflowTest,
  setWorkflowCoverage,
  startWorkflowPhase,
  stopWorkflow,
  verifyWorkflowLedger,
  workflowStatus
} from "./lib/workflow-runtime.mjs";

const help = `GATE — Gateway for Agentic Tooling & Engineering

Usage: gate [--case ID|--unassigned] <command> [options]

Core
  bootstrap                         Create private runtime directories and verify config
  doctor [--full] [--json]          Inspect the host, repository, and optional integrations
  status [--summary] [--json]       Show full status or an agent-sized bounded summary
  up [--host 127.0.0.1] [--port 4173]
                                    Run the read-only local cockpit
  validate [--json]                 Validate tracked configuration and pins

Operations
  event <kind> --summary TEXT       Append a sanitized activity event
  learn --cause TEXT --change TEXT [--private] [--scope session|project|repository]
                                    Record one cause → change learning candidate
  learn cycle --file FILE           Record one private structured learning candidate
  learn promote ID --file FILE      Promote with a candidate-bound review attestation
  learn consult --file FILE [--limit N] [--max-bytes N]
                                    Select a bounded sanitized active-learning projection

Projects
  project register --file PATH      Register a private validated project contract
  project list                      List registered project summaries
  project show ID                   Show one registered project contract
  project verify ID                 Verify one registered project contract

Objectives
  objective recommend --proposal PRIVATE_FILE --json
                                    Route one private categorical objective proposal

Cases
  case create ID --program PROFILE --name NAME [--project ID]
                                    Create a bug-program case with a separate state directory
  case list                         List case bindings and scope health
  case show ID                      Show one immutable private case scope

Case-owned engagement, workflow, profile-compilation, and analysis commands
require an explicit runtime: --case ID (or GATE_CASE), or leading --unassigned.
The writable --unassigned base runtime creates unscoped state and opts out of
case attribution. Cases separate state directories but share the operator user
and host; network containment depends on the adapter or environment. Setup and
shared-registry commands reject runtime selectors. Aggregate status, events,
and private learning remain available without a selector and use base state.

Bug bounty program profiles
  bounty profile create ID [--answers FILE] [--apply-recommended]
                                    Create a private profile interactively or from answers
  bounty profile resume ID [--answers FILE] [--apply-recommended]
                                    Resume the questionnaire or apply another answer file
    --recommendations FILE          Supply a private, base-bound recommendation proposal envelope
    --apply-recommended             Atomically apply supported unanswered recommendations
  bounty profile ui ID [--host 127.0.0.1] [--port N] [--open] [--recommendations FILE]
                                    Open the local-only choice-first profile wizard
  bounty profile status [ID]        Show one profile or the private profile index
  bounty profile show ID [--format json|review|model-context]
                                    Render the canonical profile or a bounded derived view
  bounty profile verify ID          Verify sources, completeness, and compile readiness
  bounty profile compile ID [--engagement ID] [--workflow ID] [--provider-profile FILE]
                                    Emit a deterministic no-contact proposed assessment bundle

Offline analysis
  analysis capability               Check the zero-network Bubblewrap analysis lane
  analysis manifest --project ID --path EXACT [--minutes N]
                                    Snapshot one local artifact and bind an offline run
  analysis run --project ID --manifest ID --confirm "ANALYZE ID SHA256 OFFLINE"
                                    Execute the one-shot fixed REA adapter manifest
  analysis purge --project ID --manifest ID --confirm "PURGE ID SHA256 OFFLINE ARTIFACT"
                                    Purge one retained digest-bound artifact snapshot
  analysis status                   Show capability and recent offline analysis runs

Workspaces
  workspace lease --repo PATH --task ID --branch REF [--base REF]
                                    Acquire a verified Treehouse lease
  workspace status --repo PATH      Inspect Treehouse workspace state
  workspace verify --repo PATH --path PATH --task ID --lease ID --landed-ref REF
                                    Verify landing and retain the durable lease

Engagements
  engagement new ID --targets CSV --actions CSV --tools CSV
  engagement plan ID --file PATH
  engagement authorization ID --file PATH
  engagement review ID --run RUN --head GIT_SHA --result passed|failed
  engagement approve ID --sha SHA256 --confirm "APPROVE ID"
  engagement check ID --target TARGET --action ACTION
  engagement manifest ID --workflow ID --phase-attempt ID --target TARGET --action ACTION --tool TOOL --minutes N
                         --requests N --parallel N --rate N --tokens N [--evidence-bytes N] -- ARGV...
  engagement adapter-manifest ID --adapter dnsx-domain-observe|httpx-url-observe --workflow ID
                         --phase-attempt ID --target TARGET --minutes N --requests 1 --parallel 1 --rate 1
                         --tokens N [adapter operation flags]
  engagement exec ID --manifest ID --confirm "EXECUTE ID SHA256 UNMETERED"
  engagement reconcile ID --manifest ID --confirm "RECONCILE EXECUTION ID SHA256"
  engagement stop ID --run RUN
  engagement revoke ID --confirm "REVOKE ID"
  engagement status ID
  engagement close ID

Pentest workflows
  workflow new ID [--engagement ID]  Create a private map-first workflow instance
  workflow status ID                 Show the compact journal-derived projection
  workflow phase preflight ID --phase PHASE --from PHASE --admission FILE [--handoff-id ID] [--handoff FILE]
  workflow phase start ID --phase PHASE [--from PHASE] [--admission FILE]
  workflow phase finish ID --phase PHASE --disposition DISPOSITION
  workflow test plan ID --file FILE Plan one immutable private test attempt
  workflow test review ID --file FILE
                                    Review an attempt without launching its successor
  workflow evidence add ID --phase PHASE --evidence ID --file PATH
  workflow coverage set ID --domain DOMAIN --disposition DISPOSITION
  workflow ledger preflight|open|cleanup|verify|hold ID [options]
  workflow execution cancel ID --reservation ID --reason TEXT
  workflow stop ID --condition ID --reason TEXT
  workflow join ID                    Enforce the 18-domain and clean-ledger barrier
  workflow report ID --file PATH      Attach a content-addressed private report
  workflow close ID --confirm "CLOSE ID REPORT_SHA256"

Upstreams
  upstream list
  upstream sync ID|all
  upstream install ID|all              Install integrity-pinned managed upstreams
  upstream path ID                     Print its source or package directory

Security tools
  tool list [--profile ID] [--category ID] [--summary] [--limit N] [--cursor N]
  tool show ID                         Show one bounded receipt-only tool projection
  tool plan ID                         Show host, lane, risk, and admission needs
  tool prefetch ID|--profile ID        Cache reviewed release bytes without activating them
  tool install ID|--profile ID         Install and zero-egress-smoke reviewed runtimes
  tool verify ID|--profile ID          Recheck current bytes, lock, platform, and smoke
  tool remove ID|--profile ID          Remove runtimes; retain cache bytes for re-verification

Publication
  publication check|dry-run|merge --repo OWNER/REPO --pr N --head SHA --run RUN
                            [--mode squash|merge|rebase]
                            merge requires the trusted reviewed-run attestation

Use --json for machine-readable output. Active target contact needs an approved,
digest-bound engagement. GATE never treats a worktree or container as a sandbox.
`;

function output(value, json = false) {
  if (json || typeof value !== "string") process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
  else process.stdout.write(`${value}\n`);
}

function assertFlags(flags, allowed = []) {
  const accepted = new Set(allowed);
  for (const name of Object.keys(flags)) {
    if (!accepted.has(name)) throw new Error(`unsupported option: --${name}`);
  }
}

function assertPositionals(positional, count, usage) {
  if (positional.length !== count) throw new Error(`expected ${usage}`);
}

const MAX_STRUCTURED_COMMAND_BYTES = 1024 * 1024;

function sameInputFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function readStructuredCommandFile(file, label, maximumBytes = MAX_STRUCTURED_COMMAND_BYTES) {
  const resolved = path.resolve(String(file || ""));
  let before;
  try {
    before = fs.lstatSync(resolved, { bigint: true });
  } catch (error) {
    throw new Error(`${label} is unavailable: ${error.message}`, { cause: error });
  }
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) {
    throw new Error(`${label} must be a single-link regular non-symlink file`);
  }
  if (before.size > BigInt(maximumBytes)) {
    throw new Error(`${label} exceeds the ${maximumBytes}-byte limit`);
  }
  if (process.platform !== "win32" && !fs.constants.O_NOFOLLOW) {
    throw new Error(`${label} cannot be opened without following links on this platform`);
  }
  const descriptor = fs.openSync(
    resolved,
    fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK || 0) |
      (process.platform === "win32" ? 0 : fs.constants.O_NOFOLLOW)
  );
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n || !sameInputFileIdentity(before, opened)) {
      throw new Error(`${label} changed while it was opened`);
    }
    const chunks = [];
    let total = 0;
    while (total <= maximumBytes) {
      const buffer = Buffer.allocUnsafe(Math.min(64 * 1024, maximumBytes + 1 - total));
      const count = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      chunks.push(buffer.subarray(0, count));
      total += count;
    }
    if (total > maximumBytes) throw new Error(`${label} exceeds the ${maximumBytes}-byte limit`);
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (!sameInputFileIdentity(opened, after) || after.size !== BigInt(total)) {
      throw new Error(`${label} changed while it was read`);
    }
    const final = fs.lstatSync(resolved, { bigint: true });
    if (!sameInputFileIdentity(after, final)) throw new Error(`${label} changed while it was verified`);
    try {
      return JSON.parse(Buffer.concat(chunks, total).toString("utf8"));
    } catch (error) {
      throw new Error(`${label} is malformed JSON`, { cause: error });
    }
  } finally {
    fs.closeSync(descriptor);
  }
}

function assertUnambiguousAnalysisArgs(argv) {
  const seen = new Set();
  for (const value of argv) {
    if (value === "--") throw new Error("analysis commands do not accept -- passthrough arguments");
    if (!value.startsWith("--")) continue;
    const equals = value.indexOf("=");
    const name = value.slice(2, equals === -1 ? undefined : equals);
    if (!name) throw new Error("analysis options must have a name");
    if (seen.has(name)) throw new Error(`analysis option must not be repeated: --${name}`);
    seen.add(name);
  }
}

function assertBooleanSwitch(flags, name) {
  if (flags[name] !== undefined && flags[name] !== true) {
    throw new Error(`--${name} does not accept a value`);
  }
}

function assertUnambiguousToolArgs(argv) {
  const seen = new Set();
  for (const value of argv) {
    if (value === "--") throw new Error("tool commands do not accept -- passthrough arguments");
    if (!value.startsWith("--")) continue;
    const equals = value.indexOf("=");
    const name = value.slice(2, equals === -1 ? undefined : equals);
    if (!name) throw new Error("tool options must have a name");
    if (seen.has(name)) throw new Error(`tool option must not be repeated: --${name}`);
    seen.add(name);
  }
}

function assertUnambiguousLearningArgs(argv) {
  const seen = new Set();
  for (const value of argv) {
    if (value === "--") throw new Error("learning commands do not accept passthrough arguments");
    if (!value.startsWith("--")) continue;
    const equals = value.indexOf("=");
    const name = value.slice(2, equals === -1 ? undefined : equals);
    if (!name) throw new Error("learning options must have a name");
    if (seen.has(name)) throw new Error(`learning option must not be repeated: --${name}`);
    seen.add(name);
  }
}

function assertUnambiguousWorkflowArgs(argv) {
  const seen = new Set();
  for (const value of argv) {
    if (value === "--") throw new Error("workflow commands do not accept passthrough arguments");
    if (!value.startsWith("--")) continue;
    const equals = value.indexOf("=");
    const name = value.slice(2, equals === -1 ? undefined : equals);
    if (!name) throw new Error("workflow options must have a name");
    if (seen.has(name)) throw new Error(`workflow option must not be repeated: --${name}`);
    seen.add(name);
  }
}

function assertUnambiguousBountyArgs(argv) {
  const seen = new Set();
  for (const value of argv) {
    if (value === "--") throw new Error("bounty profile commands do not accept passthrough arguments");
    if (!value.startsWith("--")) continue;
    const equals = value.indexOf("=");
    const name = value.slice(2, equals === -1 ? undefined : equals);
    if (!name) throw new Error("bounty profile options must have a name");
    if (seen.has(name)) throw new Error(`bounty profile option must not be repeated: --${name}`);
    seen.add(name);
  }
}

function assertUnambiguousObjectiveArgs(argv) {
  const seen = new Set();
  for (const value of argv) {
    if (value === "--") throw new Error("objective commands do not accept passthrough arguments");
    if (!value.startsWith("--")) continue;
    const equals = value.indexOf("=");
    const name = value.slice(2, equals === -1 ? undefined : equals);
    if (!name) throw new Error("objective options must have a name");
    if (seen.has(name)) throw new Error(`objective option must not be repeated: --${name}`);
    seen.add(name);
  }
}

function profilePathParts(value) {
  const parts = value.split(".");
  if (!parts.length || parts.some((part) => !part || new Set(["__proto__", "prototype", "constructor"]).has(part))) {
    throw new Error(`invalid program-profile question path: ${String(value)}`);
  }
  return parts;
}

function profileValueAt(value, fieldPath) {
  let current = value;
  for (const part of profilePathParts(fieldPath)) {
    if (current === null || typeof current !== "object" || !Object.hasOwn(current, part)) return undefined;
    current = current[part];
  }
  return current;
}

function questionApplies(question, profile) {
  if (!question.condition) return true;
  const actual = profileValueAt(profile, question.condition.path);
  if (Object.hasOwn(question.condition, "equals")) return actual === question.condition.equals;
  if (Object.hasOwn(question.condition, "includes")) {
    return Array.isArray(actual)
      ? actual.includes(question.condition.includes)
      : typeof actual === "string" && actual.includes(question.condition.includes);
  }
  return false;
}

function selectableQuestionChoices(question) {
  if (question.type === "boolean") return ["yes", "no"];
  if (["enum", "multi-enum"].includes(question.type)) return question.choices || [];
  return [];
}

function resolveChoiceToken(raw, choices) {
  const token = String(raw).trim();
  if (/^[1-9]\d*$/u.test(token)) {
    const selected = choices[Number(token) - 1];
    if (selected === undefined) throw new Error(`choice number must be between 1 and ${choices.length}`);
    return selected;
  }
  return token;
}

function questionChoicePrompt(question, recommendation = programProfileRecommendation(question.id)) {
  const choices = selectableQuestionChoices(question);
  const lines = [];
  if (choices.length) {
    lines.push(...choices.map((choice, index) => `  ${index + 1}. ${choice}`));
    lines.push(question.type === "multi-enum"
      ? "Choose one or more by number or value; separate selections with commas."
      : "Choose one by number or value.");
  }
  if (recommendation.available) {
    const claimState = new Set(["observed", "inferred"]).has(recommendation.basis?.claimState)
      ? ` [evidence: ${recommendation.basis.claimState}]`
      : "";
    lines.push(`  R. Use recommended${claimState} — ${recommendation.summary}`);
  } else if (recommendation.reason === "manual-only") {
    lines.push("Recommendation unavailable — direct local operator review is required.");
  } else {
    lines.push(`Recommendation unavailable — ${recommendation.summary || "a validated private proposal is required."}`);
  }
  return lines.length ? `\n${lines.join("\n")}` : "";
}

function parseQuestionAnswer(question, raw) {
  const value = raw.trim();
  if (!value) return undefined;
  if (question.allowNull === true && value === "null") return null;
  if (question.type === "boolean") {
    if (value === "0") return false;
    const selected = resolveChoiceToken(value, selectableQuestionChoices(question));
    if (/^(?:y|yes|true)$/iu.test(selected)) return true;
    if (/^(?:n|no|false)$/iu.test(selected)) return false;
    throw new Error("choose 1 for yes or 2 for no, or enter yes or no");
  }
  if (question.type === "integer") {
    if (!/^-?\d+$/u.test(value) || !Number.isSafeInteger(Number(value))) throw new Error("enter a whole number");
    return Number(value);
  }
  if (question.type === "number") {
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) throw new Error("enter a finite number");
    return numeric;
  }
  if (question.type === "enum") {
    const choices = (question.choices || []);
    const selected = resolveChoiceToken(value, choices);
    if (choices.length && !choices.includes(selected)) throw new Error(`choose one of: ${choices.join(", ")}`);
    return selected;
  }
  if (question.type === "multi-enum") {
    const values = value.startsWith("[")
      ? JSON.parse(value)
      : value.split(",").map((item) => item.trim()).filter(Boolean);
    if (!Array.isArray(values) || values.some((item) => !["string", "number"].includes(typeof item))) {
      throw new Error("choose comma-separated numbers or values, or enter a JSON string array");
    }
    const choices = (question.choices || []);
    const selected = values.map((item) => resolveChoiceToken(item, choices));
    const unsupported = choices.length ? selected.filter((item) => !choices.includes(item)) : [];
    if (unsupported.length) throw new Error(`unsupported choice: ${unsupported.join(", ")}`);
    const unique = new Set(selected);
    return choices.length ? choices.filter((choice) => unique.has(choice)) : [...unique];
  }
  if (question.type === "secret-ref-list") {
    const values = value.startsWith("[")
      ? JSON.parse(value)
      : value.split(",").map((item) => item.trim()).filter(Boolean);
    if (!Array.isArray(values) || values.some((item) => typeof item !== "string")) {
      throw new Error("enter symbolic secret references as a comma-separated list or JSON string array");
    }
    return values;
  }
  if (new Set([
    "decision", "source-list", "selector-decisions", "action-decisions", "coverage-decisions", "stop-responses",
    "contact-list", "schedule-windows", "structured-list"
  ]).has(question.type)) {
    let structured;
    try {
      structured = JSON.parse(value);
    } catch (error) {
      throw new Error(`enter valid JSON for this structured answer: ${error.message}`);
    }
    return structured;
  }
  return value;
}

async function readMultilineAnswer(terminal, firstLine, terminalOutput) {
  const lines = [firstLine];
  terminalOutput.write("Multiline input: enter . on its own line to finish.\n");
  while (true) {
    const line = await terminal.question("... ");
    if (line === ".") return lines.join("\n");
    lines.push(line);
  }
}

function questionHasAnswer(question, profile, answers = null) {
  if (answers?.answers && typeof answers.answers === "object") {
    if (!Object.hasOwn(answers.answers, question.id)) return false;
    return programProfileQuestionAnswerIsComplete(question, answers.answers[question.id]);
  }
  return programProfileQuestionAnswerIsComplete(question, profileValueAt(profile, question.path));
}

function questionSection(question) {
  const sectionId = question.section || question.sectionId || "profile";
  return PROGRAM_PROFILE_SECTIONS.find((section) => section.id === sectionId) || { id: sectionId, title: sectionId };
}

function verificationQuestionIndex(questions, blockers = []) {
  const blockerPaths = blockers.map((blocker) => blocker.path).filter(Boolean);

  // A broad semantic blocker can precede a more precise ready-contract
  // blocker for the same field. Resolve the exact field first so resume does
  // not send the operator to the first sibling below the broad path.
  const exact = questions.findIndex((question) => blockerPaths.includes(question.path));
  if (exact !== -1) return exact;

  const nested = questions
    .map((question, index) => ({ question, index }))
    .filter(({ question }) => blockerPaths.some((blockerPath) => blockerPath.startsWith(`${question.path}.`)))
    .sort((left, right) => right.question.path.length - left.question.path.length || left.index - right.index);
  if (nested.length) return nested[0].index;

  if (blockerPaths.some((blockerPath) => blockerPath === "attestation" || blockerPath.startsWith("attestation."))) {
    const timestamp = questions.findIndex((question) => question.path === "attestation.attestedAt");
    if (timestamp !== -1) return timestamp;
  }

  const broad = questions.findIndex((question) => blockerPaths.some((blockerPath) =>
    question.path.startsWith(`${blockerPath}.`)
  ));
  return broad;
}

function boundedTerminalValue(value) {
  const serialized = typeof value === "string" ? value : JSON.stringify(value);
  const escaped = escapeUnsafeText(serialized ?? String(value)).replace(/[\t\n]/gu, (character) =>
    character === "\t" ? "\\u0009" : "\\u000A"
  );
  return escaped.length <= 160 ? escaped : `${escaped.slice(0, 157)}...`;
}

function exampleDecision(disposition = "unknown") {
  return {
    disposition,
    claimState: "unverified",
    sourceRefs: ["program-rules"],
    rationale: "Replace this example with the exact source-backed decision.",
    conditions: []
  };
}

function exampleStructuredList(question) {
  const stringLists = {
    "identity-deliverables": ["Technical vulnerability report"],
    "identity-success-criteria": [
      "Every selected coverage domain has a sourced disposition.",
      "Every promising signal has a recorded hypothesis and evidence-backed conclusion.",
      "Every applicable high-friction scenario is tested, not applicable, blocked, or explicitly untested."
    ],
    "authority-source-refs": ["program-rules"],
    "limits-source-refs": ["program-rules"],
    "architecture-unknowns": [],
    "architecture-source-refs": ["program-rules"],
    "data-redaction-rules": ["Remove credentials and unrelated personal data."],
    "data-source-refs": ["program-rules"],
    "stops-cleanup-steps": ["Remove test data and revoke temporary sessions."],
    "stops-cleanup-source-refs": ["program-rules"],
    "reporting-required-sections": ["Summary", "Reproduction", "Impact", "Evidence", "Remediation"],
    "reporting-source-refs": ["program-rules"],
    "web-api-entry-points": ["https://app.example.test/"],
    "web-api-auth-flows": ["OIDC sign-in and account recovery for the recorded test tenant."],
    "cloud-container-footprint": ["Example Cloud project program-test in region example-1."],
    "cloud-container-identities": ["Workload identity program-test-runner with its recorded trust relationship."],
    "mobile-builds": ["Android package test.example.app, version 1.2.3, from the program test channel."],
    "desktop-artifacts": ["Windows x64 installer version 1.2.3 with the source-recorded SHA-256."],
    "ai-llm-system-map": ["Hosted model, retrieval store, support agent, and report output consumer."],
    "ai-llm-input-surfaces": ["Direct chat input and source-backed document ingestion in the test tenant."],
    "network-identity-ranges": ["192.0.2.0/24 on TCP 443 from the recorded test source address."],
    "network-identity-systems": ["Test identity provider and VPN with standard-user and administrator tiers."],
    "wireless-radio-footprint": ["Program lab Wi-Fi on the recorded channel, location, distance, and window."],
    "wireless-radio-equipment": ["Program-approved adapter and antenna within the recorded power limit."],
    "human-physical-population": ["Named test site and participating role during the recorded business-hours window."],
    "human-physical-pretexts": ["Program-approved support message sent only to the recorded participant group."],
    "embedded-iot-ot-assets": ["Test device model, firmware version, interface, protocol, and isolated lab network."],
    "embedded-iot-ot-safety": ["Named safety owner, isolated state, maintenance window, and emergency stop procedure."]
  };
  if (Object.hasOwn(stringLists, question.id)) return stringLists[question.id];

  const examples = {
    "actions-techniques": [{
      id: "webhook-open-connection-mutation",
      name: "Mutate a synthetic webhook event while the reviewed connection remains open",
      action: "exploit-stateful",
      disposition: "conditional",
      claimState: "observed",
      sourceRefs: ["program-rules"],
      rationale: "The program permits bounded webhook testing in its dedicated test tenant.",
      conditions: ["Use only the named callback endpoint, synthetic events, and recorded cleanup procedure."],
      parameters: { stateModel: "connect-mutate-observe-cleanup" }
    }],
    "execution-phase-policies": [{
      id: "active-web-validation",
      phaseId: "active-surface-validation",
      assetRefs: ["primary-web"],
      actions: ["observe"],
      allowedToolIds: ["httpx"],
      deniedToolIds: [],
      conditions: ["Use the recorded test account only."],
      claimState: "unverified",
      sourceRefs: ["program-rules"],
      limits: {
        maxMinutes: 60,
        maxRequests: 500,
        maxParallel: 2,
        maxRatePerSecond: 1,
        maxTokens: 50000,
        maxSpendUsd: 0
      }
    }],
    "accounts-personas": [{
      id: "researcher-account",
      persona: "Researcher",
      role: "Standard user",
      environment: "program test tenant",
      secretRefs: ["env://GATE_TEST_ACCOUNT"],
      sourceRefs: ["program-rules"]
    }],
    "architecture-components": [
      {
        id: "browser",
        name: "Researcher browser",
        type: "client",
        claimState: "unverified",
        sourceRefs: ["program-rules"]
      },
      {
        id: "web-api",
        name: "Program web API",
        type: "service",
        claimState: "unverified",
        sourceRefs: ["program-rules"]
      }
    ],
    "architecture-trust-boundaries": [{
      id: "browser-to-api",
      from: "browser",
      to: "web-api",
      description: "Public TLS boundary.",
      claimState: "unverified",
      sourceRefs: ["program-rules"]
    }],
    "architecture-data-flows": [{
      id: "request-flow",
      from: "browser",
      to: "web-api",
      dataClassification: "confidential",
      description: "Research account requests and responses.",
      claimState: "unverified",
      sourceRefs: ["program-rules"]
    }],
    "ambiguities-items": []
  };
  if (Object.hasOwn(examples, question.id)) return examples[question.id];

  return [{
    item: "Replace this example with the exact source-backed detail requested by the prompt.",
    sourceRefs: ["program-rules"]
  }];
}

function questionFormatGuidance(question) {
  let accepted;
  let example;
  switch (question.type) {
    case "text": {
      const examples = {
        "identity-program-name": "Acme bug bounty",
        "authority-program-url": "https://program.example.test/rules",
        "limits-timezone": "Etc/UTC",
        "reporting-severity-standard": "CVSS 4.0 with program-specific overrides",
        "attestation-operator": "local-operator"
      };
      accepted = "plain text on one line";
      example = examples[question.id] || "Recorded value";
      break;
    }
    case "multiline": {
      const examples = {
        "web-api-automation-rules": "Automate reviewed callback, webhook, role and tenant, state-transition, timing, and differential scenarios when manual orchestration would be costly or error-prone."
      };
      accepted = "plain text; finish multiline input with . on its own line";
      example = examples[question.id] || "Describe the exact source-backed rule.";
      break;
    }
    case "boolean":
      accepted = "choice 1 or 2 (also accepts yes/no, true/false, or legacy 1/0)";
      example = "yes";
      break;
    case "integer": {
      const examples = {
        "limits-max-minutes": "60",
        "limits-max-requests": "1000",
        "limits-max-parallel": "2",
        "limits-max-tokens": "50000",
        "data-retention-days": "30"
      };
      accepted = question.allowNull ? "a whole number, or null" : "a whole number";
      example = examples[question.id] || "1";
      break;
    }
    case "number":
      accepted = question.allowNull ? "a finite number, or null" : "a finite number";
      example = "2.5";
      break;
    case "datetime": {
      const examples = {
        "authority-valid-from": "2026-01-01T00:00:00Z",
        "authority-valid-until": "2026-12-01T00:00:00Z",
        "authority-last-verified": "2026-10-01T00:00:00Z",
        "attestation-at": "2026-10-01T00:00:00Z"
      };
      accepted = question.allowNull ? "an ISO 8601 date-time, or null" : "an ISO 8601 date-time";
      example = examples[question.id] || "2026-10-01T00:00:00Z";
      break;
    }
    case "enum":
      accepted = `one numbered choice or exact value: ${(question.choices || []).join(", ")}`;
      example = question.id === "data-classification" ? "confidential" : question.choices?.[0] || "value";
      break;
    case "multi-enum":
      accepted = `comma-separated choice numbers or exact values using: ${(question.choices || []).join(", ")}`;
      example = question.choices?.length ? [question.choices[0]] : [];
      break;
    case "secret-ref-list":
      accepted = "a comma-separated list or JSON string array of env://, keychain://, or file:// references";
      example = ["env://GATE_TEST_ACCOUNT"];
      break;
    case "decision":
      accepted = "a JSON decision object with disposition, claimState, sourceRefs, rationale, and conditions";
      example = exampleDecision();
      break;
    case "source-list":
      accepted = "a JSON array of source records";
      example = [{
        id: "program-rules",
        type: "program-rules",
        title: "Published program rules",
        reference: "https://program.example.test/rules",
        contentSha256: "a".repeat(64),
        observedAt: "2026-10-01T00:00:00Z",
        claimState: "observed",
        notes: "Captured in operator-controlled private storage."
      }];
      break;
    case "selector-decisions":
      accepted = "a JSON array of exact asset selectors and their decisions";
      example = [{
        id: "primary-web",
        selector: { type: "url", value: "https://app.example.test/" },
        ...exampleDecision("allowed"),
        actionOverrides: Object.fromEntries(PROGRAM_PROFILE_ACTIONS.map((action) => [
          action,
          exampleDecision(action === "observe" ? "allowed" : "unknown")
        ])),
        limitOverrides: Object.fromEntries(PROGRAM_PROFILE_EXECUTION_LIMITS.map((limit) => [limit, ({
          maxMinutes: 60,
          maxRequests: 500,
          maxParallel: 2,
          maxRatePerSecond: 1,
          maxTokens: 50000,
          maxSpendUsd: 0
        })[limit]]))
      }];
      break;
    case "action-decisions":
      accepted = "a JSON object containing every action class and its decision";
      example = Object.fromEntries(PROGRAM_PROFILE_ACTIONS.map((action) => [
        action,
        exampleDecision(action === "observe" ? "allowed" : "unknown")
      ]));
      break;
    case "coverage-decisions":
      accepted = "a JSON object containing every coverage domain and its decision";
      example = Object.fromEntries(PROGRAM_PROFILE_COVERAGE_DOMAINS.map((domain) => [domain, exampleDecision()]));
      break;
    case "stop-responses":
      accepted = "a JSON object containing every mandatory stop condition and response";
      example = Object.fromEntries(PROGRAM_PROFILE_STOP_CONDITIONS.map((condition) => [condition, {
        enabled: true,
        response: `Stop affected work on ${condition}, preserve bounded evidence, and escalate.`,
        claimState: "unverified",
        sourceRefs: ["program-rules"]
      }]));
      break;
    case "contact-list":
      accepted = "a JSON array of contact records (terminal fallback); use `gate bounty profile ui ID` for the normal field-by-field editor";
      example = [{
        name: "Program security team",
        role: "Escalation contact",
        channel: "platform://program-inbox",
        purpose: "Receive incident escalation and vulnerability reports.",
        sourceRefs: ["program-rules"]
      }];
      break;
    case "schedule-windows":
      accepted = "a JSON array of day and UTC/local-time windows";
      example = [{ days: ["monday", "tuesday"], start: "09:00", end: "17:00" }];
      break;
    case "structured-list":
      accepted = question.module
        ? "a non-empty JSON array matching the records requested by this prompt"
        : "a JSON array matching the records requested by this prompt; use [] when the recorded answer is none and the field permits it";
      example = exampleStructuredList(question);
      break;
    default:
      accepted = question.type;
      example = "value";
  }
  const rendered = typeof example === "string" ? example : JSON.stringify(example, null, 2);
  const guidance = [
    `Accepted format: ${accepted}.`,
    "Example only; replace every sample value with the exact recorded facts:",
    rendered
  ];
  if (question.allowNull === true) guidance.push("Alternative: null");
  return guidance.join("\n");
}

function applicableQuestionProgress(questions, profile, index) {
  const applicable = questions
    .map((question, questionIndex) => ({ question, questionIndex }))
    .filter(({ question }) => questionApplies(question, profile));
  const position = applicable.findIndex(({ questionIndex }) => questionIndex === index);
  return { position: position === -1 ? 0 : position + 1, total: applicable.length };
}

function questionnaireResult(status, outcome) {
  const blockerCount = Array.isArray(status.blockers)
    ? status.blockers.length
    : status.profile?.blockerCount || 0;
  return {
    saved: true,
    outcome,
    id: status.id,
    status: status.status,
    ready: status.ready === true,
    structuralValid: status.structuralValid === true,
    blockerCount,
    warningCount: Array.isArray(status.warnings) ? status.warnings.length : 0,
    profileRef: status.profile?.profileRef || null,
    profileSha256: status.profileSha256 || status.profile?.profileSha256 || null,
    nextCommand: status.ready
      ? `./bin/gate.mjs bounty profile verify ${status.id}`
      : `./bin/gate.mjs bounty profile resume ${status.id}`
  };
}

function newProgramProfileAnswers(id) {
  return {
    $schema: "https://gate.local/schemas/bug-bounty-program-profile-answers.schema.json",
    apiVersion: "gate.dev/program-profile-answers/v2",
    kind: "BugBountyProgramProfileAnswers",
    metadata: {
      programId: id,
      title: id,
      updatedAt: new Date().toISOString(),
      baseRevision: null,
      baseProfileSha256: null
    },
    answers: {}
  };
}

function firstUnansweredQuestionIndex(questions, profile, answers) {
  return questions.findIndex((question) =>
    question.required && questionApplies(question, profile) && !questionHasAnswer(question, profile, answers)
  );
}

async function runProgramProfileQuestionnaire(id, mode, options = {}) {
  const input = options.input || process.stdin;
  const terminalOutput = options.output || process.stderr;
  const interactive = options.interactive ?? (input.isTTY === true && terminalOutput.isTTY === true);
  if (!interactive) {
    throw new Error("interactive bug-bounty profile questionnaire requires a TTY; pass --answers FILE for headless use");
  }
  const paths = options.paths;
  const recommendations = options.recommendations || null;
  if (mode === "create") createProgramProfile(id, newProgramProfileAnswers(id), { paths });

  let resumed = resumeProgramProfile(id, { paths });
  let profile = resumed.profile;
  let answers = resumed.answers || newProgramProfileAnswers(id);
  const questions = PROGRAM_PROFILE_QUESTIONS;
  let index = firstUnansweredQuestionIndex(questions, profile, answers);
  if (index === -1) {
    const verification = verifyProgramProfile(id, { paths });
    index = verificationQuestionIndex(questions, verification.blockers || []);
    if (index === -1) index = questions.findIndex((question) => question.path.startsWith("attestation."));
    if (index === -1) index = 0;
    terminalOutput.write(
      verification.ready
        ? `All required answers are recorded. Opening ${questions[index].id} for review; use edit QUESTION_ID to change another answer.\n`
        : `All required answers are recorded. Verification still has ${verification.blockers?.length || 0} blocker(s); opening ${questions[index].id} for review.\n`
    );
  } else if (mode === "resume") {
    terminalOutput.write(`Resuming at unanswered required question: ${questions[index].id}.\n`);
  }
  const terminal = createInterface({ input, output: terminalOutput, terminal: options.terminal ?? true });
  const notices = new Set();
  terminalOutput.write(
    "Commands: back, edit QUESTION_ID, why, format, recommended, apply recommended, save, quit. " +
    "Choice questions accept numbers; format shows advanced typed shapes.\n"
  );

  try {
    while (index < questions.length) {
      const question = questions[index];
      if (!questionApplies(question, profile)) {
        index += 1;
        continue;
      }
      const section = questionSection(question);
      const current = profileValueAt(profile, question.path);
      const recorded = questionHasAnswer(question, profile, answers);
      const currentHint = current === undefined || question.sensitive
        ? ""
        : recorded
          ? ` [current: ${boundedTerminalValue(current)}]`
          : ` [unconfirmed draft: ${boundedTerminalValue(current)}; enter explicitly to confirm]`;
      const recommendation = programProfileRecommendation(question.id, { profile, recommendations });
      const choiceHint = questionChoicePrompt(question, recommendation);
      const requiredHint = question.required ? " [required]" : "";
      const multilineHint = question.type === "multiline" ? " [multiline; finish with . on its own line]" : "";
      const progress = applicableQuestionProgress(questions, profile, index);
      if (!notices.has(question.id) && question.id === "authority-operator-confirmed") {
        terminalOutput.write(
          `Before answering this question, review the exact private draft locally with ` +
          `./bin/gate.mjs bounty profile show ${id} --format review. ` +
          "Choosing yes means that review actually occurred; it is never a wizard default or recommendation.\n"
        );
        notices.add(question.id);
      }
      if (!notices.has(question.id) && question.path.startsWith("attestation.")) {
        terminalOutput.write(
          "Final attestation requires the operator's exact local review. GATE does not recommend or infer attestation answers.\n"
        );
        notices.add(question.id);
      }
      if (!notices.has(question.id) && question.type === "contact-list") {
        terminalOutput.write(
          `For normal field-by-field contact entry, quit and run ./bin/gate.mjs bounty profile ui ${id}. ` +
          "The terminal prompt remains a typed JSON fallback.\n"
        );
        notices.add(question.id);
      }
      const raw = await terminal.question(
        `\n${section.title} · ${progress.position}/${progress.total} applicable · ${question.id}\n${question.prompt}${requiredHint}${multilineHint}${currentHint}${choiceHint}\n> `
      );
      const command = raw.trim();
      if (command === "why") {
        terminalOutput.write(`${question.why || "This answer is required to produce an exact, bounded assessment profile."}\n`);
        continue;
      }
      if (command === "format") {
        terminalOutput.write(`${questionFormatGuidance(question)}\n`);
        continue;
      }
      if (command === "save") {
        terminalOutput.write("Saved. Every accepted answer is already persisted privately.\n");
        continue;
      }
      if (command === "quit") {
        return questionnaireResult(programProfileStatus(id, { paths }), "saved");
      }
      if (command === "apply recommended") {
        try {
          const result = applyProgramProfileRecommendations(id, recommendations, {
            paths,
            expectedRevision: profile.metadata.revision,
            expectedProfileSha256: resumed.summary.profileSha256
          });
          terminalOutput.write(result.appliedCount
            ? `Applied ${result.appliedCount} supported unanswered recommendation(s) in one profile revision.\n`
            : "No supported unanswered recommendations were eligible; the profile revision was unchanged.\n");
          resumed = resumeProgramProfile(id, { paths });
          profile = resumed.profile;
          answers = resumed.answers || answers;
          const unanswered = firstUnansweredQuestionIndex(questions, profile, answers);
          if (unanswered !== -1) index = unanswered;
        } catch (error) {
          terminalOutput.write(`Recommendations were not applied: ${error.message}\n`);
        }
        continue;
      }
      if (command === "back") {
        index = Math.max(0, index - 1);
        while (index > 0 && !questionApplies(questions[index], profile)) index -= 1;
        continue;
      }
      if (command.startsWith("edit ")) {
        const wanted = command.slice(5).trim();
        const editIndex = questions.findIndex((entry) => entry.id === wanted);
        if (editIndex === -1) {
          terminalOutput.write(`Unknown question id: ${wanted}\n`);
          continue;
        }
        index = editIndex;
        continue;
      }
      if (!command) {
        if (question.required && !questionHasAnswer(question, profile, answers)) {
          terminalOutput.write("This answer is required. Enter a value, or type save or quit.\n");
          continue;
        }
        index += 1;
        continue;
      }
      let answer;
      let usedRecommendation = false;
      try {
        if (/^(?:r|recommend|recommended)$/iu.test(command)) {
          if (!recommendation.available) {
            throw new Error(recommendation.summary || "no supported recommendation is available for this question");
          }
          answer = structuredClone(recommendation.value);
          usedRecommendation = true;
        } else {
          const answerInput = question.type === "multiline"
            ? await readMultilineAnswer(terminal, raw, terminalOutput)
            : raw;
          answer = parseQuestionAnswer(question, answerInput);
        }
        if (question.required && !programProfileQuestionAnswerIsComplete(question, answer)) {
          throw new Error("enter a substantive non-empty answer for this required question");
        }
      } catch (error) {
        terminalOutput.write(`${error.message}\n`);
        continue;
      }
      const updatedAnswers = structuredClone(answers);
      updatedAnswers.metadata.programId = id;
      updatedAnswers.metadata.updatedAt = new Date().toISOString();
      updatedAnswers.answers[question.id] = answer;
      try {
        if (usedRecommendation) {
          applyProgramProfileRecommendation(id, question.id, recommendations, {
            paths,
            expectedRevision: profile.metadata.revision,
            expectedProfileSha256: resumed.summary.profileSha256,
            now: updatedAnswers.metadata.updatedAt
          });
        } else {
          const applyAnswer = question.id === "authority-operator-confirmed" && answer === true
            ? applyProgramProfileAuthorityConfirmation
            : applyProgramProfileAnswers;
          applyAnswer(id, updatedAnswers, { paths });
        }
      } catch (error) {
        terminalOutput.write(`Answer was not accepted: ${error.message}\n`);
        continue;
      }
      resumed = resumeProgramProfile(id, { paths });
      profile = resumed.profile;
      answers = resumed.answers || updatedAnswers;
      terminalOutput.write(
        usedRecommendation
          ? `Saved ${question.id} from the ${recommendation.provenance} recommendation.\n`
          : `Saved ${question.id}.\n`
      );
      index += 1;
    }
  } finally {
    terminal.close();
  }
  return questionnaireResult(programProfileStatus(id, { paths }), "questions-complete");
}

export const cliInternals = Object.freeze({
  applicableQuestionProgress,
  boundedTerminalValue,
  caseSelectorRequired,
  caseSelectionMode,
  parseQuestionAnswer,
  questionChoicePrompt,
  questionFormatGuidance,
  questionnaireResult,
  questionHasAnswer,
  runProgramProfileQuestionnaire,
  verificationQuestionIndex
});

function optionalValueFlag(flags, name) {
  if (flags[name] === undefined) return undefined;
  if (typeof flags[name] !== "string" || !flags[name].trim()) throw new Error(`--${name} needs a value`);
  return flags[name];
}

function workflowMutationOptions(flags, paths) {
  const expectedSequence = optionalValueFlag(flags, "expected-sequence");
  return {
    paths,
    requestId: optionalValueFlag(flags, "request"),
    expectedSequence: expectedSequence === undefined ? undefined : Number(expectedSequence),
    expectedHead: optionalValueFlag(flags, "expected-head")
  };
}

function learningCommit(learning) {
  return {
    ok: true,
    id: learning.id,
    apiVersion: learning.apiVersion,
    at: learning.at,
    status: learning.status,
    scope: learning.scope,
    sensitivity: learning.sensitivity,
    supersedes: learning.supersedes,
    promotionState: learning.promotion.state,
    candidateSha256: learning.promotion.state === "candidate"
      ? learningCandidateSha256(learning)
      : learning.promotion.candidateSha256,
    applicabilityCount: learning.applicability.length,
    evidenceCount: learning.evidence.length
  };
}

function workflowCommit(result) {
  const payload = result.entry.payload;
  const details = (() => {
    switch (result.entry.type) {
      case "phase.started": return { phaseId: payload.phaseId, attemptId: payload.attemptId };
      case "phase.finished": return { phaseId: payload.phaseId, disposition: payload.disposition };
      case "test.planned": return {
        phaseId: payload.phaseId,
        attemptId: payload.attemptId,
        testId: payload.testId,
        learningCount: payload.learningIds.length
      };
      case "test.reviewed": return {
        phaseId: payload.phaseId,
        attemptId: payload.attemptId,
        testId: payload.testId,
        disposition: payload.disposition,
        nextDecision: payload.nextStrategy.decision
      };
      case "evidence.added": return { evidenceId: payload.evidenceId, sha256: payload.sha256 };
      case "coverage.set": return { domain: payload.domain, disposition: payload.disposition };
      case "ledger.opened": return { entryId: payload.entryId };
      case "ledger.cleanup-recorded":
      case "ledger.verified":
      case "ledger.held": return { entryId: payload.entryId };
      case "execution.cancelled": return { reservationId: payload.reservationId };
      case "stop.triggered": return { condition: payload.condition };
      case "coverage.joined": return { coverageSha256: payload.coverageSha256 };
      case "report.attached": return { reportSha256: payload.sha256 };
      case "workflow.closed": return { reportSha256: payload.reportSha256 };
      default: return {};
    }
  })();
  return {
    ok: true,
    instanceId: result.projection.instanceId,
    status: result.projection.status,
    event: {
      type: result.entry.type,
      sequence: result.entry.sequence,
      headSha256: result.entry.entrySha256,
      requestId: result.entry.requestId,
      replayed: result.replayed,
      details
    },
    activePhaseId: result.projection.activePhase?.phaseId || null,
    coverageCount: Object.keys(result.projection.coverage).length,
    ledgerEntries: Object.keys(result.projection.ledger).length
  };
}

function printValidation(validation, json) {
  if (json) return output(validation, true);
  for (const check of validation.checks) {
    process.stdout.write(`${check.ok ? "ok" : "fail"}\t${check.name}\t${check.detail}\n`);
  }
  process.stdout.write(`\n${validation.ok ? "GATE configuration is valid." : "GATE configuration has failures."}\n`);
}

function printDoctor(doctor, json) {
  if (json) return output(doctor, true);
  process.stdout.write(`host\t${doctor.host.platform}/${doctor.host.architecture}${doctor.host.wsl ? " (WSL)" : ""}\n`);
  for (const tool of doctor.tools) {
    const state = tool.available ? "ready" : tool.required ? "missing" : "optional";
    process.stdout.write(`${state}\t${tool.id}\t${tool.version || "unavailable"}\n`);
  }
  process.stdout.write(`config\t${doctor.repository.ok ? "valid" : "invalid"}\n`);
  if (doctor.toolRuntimes) {
    process.stdout.write(
      `tool-runtimes\tcatalog=${doctor.toolRuntimes.catalog} locked=${doctor.toolRuntimes.locked} installed=${doctor.toolRuntimes.installed} verified=${doctor.toolRuntimes.verified} executable=${doctor.toolRuntimes.executable} unresolved=${doctor.toolRuntimes.unresolved}\n`
    );
  }
  if (doctor.capabilities) {
    const { capture, debugger: debuggerCapability, usb, containers } = doctor.capabilities;
    process.stdout.write(`capture\tinterfaces=${capture.nonLoopbackInterfaceCount} cap_net_raw=${capture.rawSocketCapability ?? "unknown"} cap_net_admin=${capture.networkAdminCapability ?? "unknown"}\n`);
    process.stdout.write(`debugger\tptrace_scope=${debuggerCapability.ptraceScope ?? "unknown"}\n`);
    process.stdout.write(`usb\tdevice_bus=${usb.linuxDeviceBusPresent}\n`);
    process.stdout.write(`docker-engine\t${containers.engineReachability}${containers.dockerSocketPresent === null ? "" : ` socket=${containers.dockerSocketPresent}`}\n`);
  }
}

function publicationRequest(flags) {
  return {
    repository: requiredFlag(flags, "repo"),
    pullRequest: requiredFlag(flags, "pr"),
    expectedHead: requiredFlag(flags, "head").toLowerCase(),
    noMistakesRunId: requiredFlag(flags, "run"),
    mergeMode: typeof flags.mode === "string" ? flags.mode : "squash"
  };
}

function persistPublicationEvidence(result, paths) {
  ensureRuntime(paths);
  const stamp = new Date().toISOString().replace(/[-:.TZ]/g, "");
  const file = path.join(paths.evidence, `publication-${stamp}-${process.pid}.json`);
  writeJsonAtomic(file, result, 0o600);
  recordEvent(
    {
      kind: `publication.${result.outcome || "unknown"}`,
      status: result.ok ? "succeeded" : "blocked",
      component: "gate-publication",
      summary: `Publication ${result.operation || "check"} ${result.ok ? "passed" : "was blocked"} for PR ${result.pullRequestNumber || "unknown"}.`,
      effect: {
        class: result.mutationAttempted ? "forge-write" : "network-observe",
        targetRef: result.repository && result.pullRequestNumber ? `${result.repository}#${result.pullRequestNumber}` : null,
        engagementId: null,
        planDigest: null
      },
      evidenceRefs: [`file://${file}`]
    },
    { paths }
  );
  return file;
}

function parseCaseInvocation(argv, env = process.env) {
  const args = [...argv];
  let explicit = null;
  let unassigned = false;
  while (args.length > 0) {
    if (args[0] === "--unassigned") {
      if (unassigned) throw new Error("--unassigned may only be provided once");
      if (explicit) throw new Error("--unassigned and --case are mutually exclusive");
      unassigned = true;
      args.splice(0, 1);
      continue;
    }
    if (args[0] === "--case") {
      if (explicit) throw new Error("--case may only be provided once");
      if (unassigned) throw new Error("--unassigned and --case are mutually exclusive");
      if (typeof args[1] !== "string" || !args[1] || args[1].startsWith("--")) {
        throw new Error("--case requires a case id");
      }
      explicit = args[1];
      args.splice(0, 2);
      continue;
    }
    if (typeof args[0] === "string" && args[0].startsWith("--case=")) {
      if (explicit) throw new Error("--case may only be provided once");
      if (unassigned) throw new Error("--unassigned and --case are mutually exclusive");
      explicit = args[0].slice("--case=".length);
      if (!explicit) throw new Error("--case requires a case id");
      args.splice(0, 1);
      continue;
    }
    break;
  }
  const fromEnvironment = typeof env.GATE_CASE === "string" && env.GATE_CASE ? env.GATE_CASE : null;
  if (unassigned && fromEnvironment) {
    throw new Error("--unassigned and GATE_CASE are mutually exclusive");
  }
  if (explicit && fromEnvironment && explicit !== fromEnvironment) {
    throw new Error("--case does not match GATE_CASE");
  }
  return { argv: args, caseId: explicit || fromEnvironment, unassigned };
}

const GLOBAL_CASE_COMMANDS = new Set([
  "bootstrap",
  "validate",
  "doctor",
  "up",
  "case",
  "project",
  "objective",
  "workspace",
  "upstream",
  "publication"
]);
const GLOBAL_BOUNTY_PROFILE_ACTIONS = new Set(["create", "resume", "ui", "status", "show", "verify"]);
const GLOBAL_TOOL_ACTIONS = new Set(["list", "show", "plan", "prefetch", "install", "verify", "remove"]);
const STALE_SAFE_ENGAGEMENT_ACTIONS = new Set(["status", "stop", "revoke", "reconcile", "close"]);
const STALE_SAFE_ANALYSIS_ACTIONS = new Set(["status", "purge"]);
const CASE_OWNED_ANALYSIS_ACTIONS = new Set(["manifest", "run", "purge", "status"]);
const GLOBAL_META_COMMANDS = new Set(["help", "--help", "-h", "version", "--version", "-v"]);

function staleSafeWorkflowRoute(positionals) {
  const [area, action] = positionals;
  if (new Set(["status", "stop", "join", "report", "close"]).has(area)) return true;
  if (area === "phase" && action === "finish") return true;
  if (area === "test" && action === "review") return true;
  if (area === "evidence" && action === "add") return true;
  if (area === "coverage" && action === "set") return true;
  if (area === "ledger" && new Set(["cleanup", "verify", "hold"]).has(action)) return true;
  return area === "execution" && action === "cancel";
}

function caseSelectionMode(command, parsed) {
  if (GLOBAL_META_COMMANDS.has(command) || GLOBAL_CASE_COMMANDS.has(command)) return "global";
  if (command === "bounty") {
    const [area, action] = parsed.positional;
    if (area === "profile" && GLOBAL_BOUNTY_PROFILE_ACTIONS.has(action)) return "global";
  }
  if (command === "tool") {
    const [action = "list"] = parsed.positional;
    if (GLOBAL_TOOL_ACTIONS.has(action)) return "global";
  }
  if (command === "status" || command === "event" || command === "learn") return "stale-safe";
  if (command === "engagement" && STALE_SAFE_ENGAGEMENT_ACTIONS.has(parsed.positional[0])) {
    return "stale-safe";
  }
  if (command === "analysis" && parsed.positional[0] === "capability") return "global";
  if (command === "analysis" && STALE_SAFE_ANALYSIS_ACTIONS.has(parsed.positional[0])) {
    return "stale-safe";
  }
  if (command === "workflow" && staleSafeWorkflowRoute(parsed.positional)) return "stale-safe";
  return "strict";
}

function caseSelectorRequired(command, parsed) {
  if (command === "engagement" || command === "workflow") return true;
  if (command === "bounty") {
    const [area, action] = parsed.positional;
    return area === "profile" && action === "compile";
  }
  return command === "analysis" && CASE_OWNED_ANALYSIS_ACTIONS.has(parsed.positional[0]);
}

function assertRuntimeSelectorContract(command, parsed, mode, invocation) {
  const selected = Boolean(invocation.caseId) || invocation.unassigned;
  if (mode === "global" && selected) {
    throw new Error(
      `gate ${command} uses shared state and does not accept --case, GATE_CASE, or --unassigned`
    );
  }
  if (!selected && caseSelectorRequired(command, parsed)) {
    throw new Error(
      `gate ${command} requires --case ID (or GATE_CASE) or explicit --unassigned`
    );
  }
}

function assertSelectedCaseProgram(selectedCase, programId) {
  if (selectedCase && selectedCase.case.program.id !== programId) {
    throw new Error(`selected case is bound to program profile ${selectedCase.case.program.id}`);
  }
}

function assertSelectedCaseProject(selectedCase, projectId) {
  if (!selectedCase) return;
  if (!selectedCase.case.project) {
    throw new Error("selected case has no managed project binding for offline analysis");
  }
  if (selectedCase.case.project.id !== projectId) {
    throw new Error(`selected case is bound to managed project ${selectedCase.case.project.id}`);
  }
}

function recheckSelectedCaseBindings(selectedCase, basePaths) {
  if (!selectedCase) return;
  const current = selectCaseRuntime(selectedCase.case.metadata.id, { paths: basePaths });
  if (current.case.scopeSha256 !== selectedCase.case.scopeSha256) {
    throw new Error("selected case scope changed before command dispatch");
  }
}

export async function main(argv) {
  const invocation = parseCaseInvocation(argv);
  const [command = "help", ...rest] = invocation.argv;
  const parsed = parseArgs(rest);
  const json = parsed.flags.json === true;
  const basePaths = runtimePaths();

  const selectionMode = caseSelectionMode(command, parsed);
  assertRuntimeSelectorContract(command, parsed, selectionMode, invocation);

  if (["help", "--help", "-h"].includes(command)) return output(help);
  if (["version", "--version", "-v"].includes(command)) {
    const pkg = JSON.parse(fs.readFileSync(path.join(basePaths.repo, "package.json"), "utf8"));
    return output(pkg.version);
  }

  const selectedCase = invocation.caseId
    ? selectionMode === "stale-safe"
      ? openCaseRuntime(invocation.caseId, { paths: basePaths })
      : selectCaseRuntime(invocation.caseId, { paths: basePaths })
    : null;
  const paths = selectedCase?.paths || basePaths;

  if (command === "bootstrap") {
    assertFlags(parsed.flags, ["json"]);
    assertPositionals(parsed.positional, 0, "gate bootstrap");
    ensureRuntime(paths);
    const validation = validateRepository({ paths });
    recordEvent({ kind: "gate.bootstrapped", summary: "Prepared GATE private runtime directories." }, { paths });
    output({ ok: validation.ok, gate_home: paths.home, repository: paths.repo, next: "gate doctor --full" }, json);
    if (!validation.ok) process.exitCode = 1;
    return;
  }

  if (command === "validate") {
    assertFlags(parsed.flags, ["json"]);
    assertPositionals(parsed.positional, 0, "gate validate");
    const validation = validateRepository({ paths });
    printValidation(validation, json);
    if (!validation.ok) process.exitCode = 1;
    return;
  }

  if (command === "doctor") {
    assertFlags(parsed.flags, ["full", "json"]);
    assertPositionals(parsed.positional, 0, "gate doctor [--full] [--json]");
    const doctor = runDoctor({ paths, full: parsed.flags.full === true });
    printDoctor(doctor, json);
    if (!doctor.ok) process.exitCode = 1;
    return;
  }

  if (command === "status") {
    assertFlags(parsed.flags, ["summary", "json"]);
    assertBooleanSwitch(parsed.flags, "summary");
    assertBooleanSwitch(parsed.flags, "json");
    assertPositionals(parsed.positional, 0, "gate status [--summary] [--json]");
    const status = await buildStatus({
      paths,
      selectionMode: invocation.caseId ? "case" : invocation.unassigned ? "unassigned" : "aggregate"
    });
    return output(parsed.flags.summary === true ? statusSummary(status) : status, json);
  }

  if (command === "up") {
    assertFlags(parsed.flags, ["host", "port"]);
    assertPositionals(parsed.positional, 0, "gate up [--host HOST] [--port PORT]");
    const { startObserver } = await import("./observer/server.mjs");
    const { config } = loadConfig({ paths: basePaths });
    await startObserver({
      paths: basePaths,
      host: typeof parsed.flags.host === "string" ? parsed.flags.host : "127.0.0.1",
      port: Number(parsed.flags.port || 4173),
      operatorDisplayName: readOperatorDisplayName(config)
    });
    return;
  }

  if (command === "case") {
    const [action = "list", id] = parsed.positional;
    if (action === "create") {
      assertPositionals(parsed.positional, 2, "gate case create ID --program PROFILE --name NAME [--project ID]");
      assertFlags(parsed.flags, ["program", "name", "project", "json"]);
      const programId = requiredFlag(parsed.flags, "program");
      const profile = verifyProgramProfile(programId, { paths: basePaths });
      if (!profile.ok || !profile.structuralValid || !profile.ready || !profile.profileSha256) {
        throw new Error(`program profile is not ready for a case: ${programId}`);
      }
      const projectId = optionalValueFlag(parsed.flags, "project");
      return output(createCase(id, {
        displayName: requiredFlag(parsed.flags, "name"),
        program: { id: programId, profileSha256: profile.profileSha256 },
        project: projectId ? projectContractBinding(projectId, { paths: basePaths }) : null
      }, { paths: basePaths }), json);
    }
    if (action === "list") {
      assertPositionals(parsed.positional, 1, "gate case list");
      assertFlags(parsed.flags, ["json"]);
      return output(caseFleetStatus({ paths: basePaths }), json);
    }
    if (action === "show") {
      assertPositionals(parsed.positional, 2, "gate case show ID");
      assertFlags(parsed.flags, ["json"]);
      if (!id) throw new Error("case id is required");
      return output(showCase(id, { paths: basePaths }), json);
    }
    throw new Error(`unknown case action: ${action}`);
  }

  if (command === "project") {
    const [action = "list", id] = parsed.positional;
    if (action === "register") {
      assertPositionals(parsed.positional, 1, "gate project register --file PATH");
      assertFlags(parsed.flags, ["file", "json"]);
      return output(registerProject(requiredFlag(parsed.flags, "file"), { paths }), json);
    }
    if (action === "list") {
      assertPositionals(parsed.positional, 1, "gate project list");
      assertFlags(parsed.flags, ["json"]);
      return output(listProjects({ paths }), json);
    }
    if (action === "show") {
      assertPositionals(parsed.positional, 2, "gate project show ID");
      assertFlags(parsed.flags, ["json"]);
      if (!id) throw new Error("project id is required");
      return output(showProject(id, { paths }), json);
    }
    if (action === "verify") {
      assertPositionals(parsed.positional, 2, "gate project verify ID");
      assertFlags(parsed.flags, ["json"]);
      if (!id) throw new Error("project id is required");
      const verification = verifyProject(id, { paths });
      output(verification, json);
      if (!verification.ok) process.exitCode = 2;
      return;
    }
    throw new Error(`unknown project action: ${action}`);
  }

  if (command === "objective") {
    assertUnambiguousObjectiveArgs(rest);
    const [action] = parsed.positional;
    if (action !== "recommend") throw new Error(`unknown objective action: ${action || "missing"}`);
    assertPositionals(parsed.positional, 1, "gate objective recommend --proposal PRIVATE_FILE --json");
    assertFlags(parsed.flags, ["proposal", "json"]);
    assertBooleanSwitch(parsed.flags, "json");
    if (parsed.flags.json !== true) throw new Error("gate objective recommend requires --json");
    const recommendation = recommendObjectiveFromPrivateFile(
      requiredFlag(parsed.flags, "proposal"),
      { paths: basePaths }
    );
    return output(recommendation, true);
  }

  if (command === "bounty") {
    assertUnambiguousBountyArgs(rest);
    const [area, action, id] = parsed.positional;
    if (area !== "profile") throw new Error(`unknown bounty area: ${area || "missing"}`);
    if (!action) throw new Error("bounty profile action is required");
    assertBooleanSwitch(parsed.flags, "json");

    if (new Set(["create", "resume"]).has(action)) {
      assertPositionals(
        parsed.positional,
        3,
        `gate bounty profile ${action} ID [--answers FILE] [--recommendations FILE] [--apply-recommended]`
      );
      assertFlags(parsed.flags, ["answers", "recommendations", "apply-recommended", "json"]);
      assertBooleanSwitch(parsed.flags, "apply-recommended");
      if (!id) throw new Error("program profile id is required");
      const answersFile = optionalValueFlag(parsed.flags, "answers");
      const recommendationsFile = optionalValueFlag(parsed.flags, "recommendations");
      const applyRecommended = parsed.flags["apply-recommended"] === true;
      if (action === "create" && recommendationsFile && !applyRecommended) {
        throw new Error("create-time --recommendations requires --apply-recommended");
      }
      if (answersFile && (applyRecommended || recommendationsFile)) {
        throw new Error("--answers and --recommendations are separate atomic operations; apply one, then reload the current base");
      }
      if (answersFile) {
        const answers = loadProgramProfileAnswers(answersFile, { paths });
        const result = action === "create"
          ? createProgramProfile(id, answers, { paths })
          : applyProgramProfileAnswers(id, answers, { paths });
        return output(result, json);
      }
      if (applyRecommended) {
        const recommendations = recommendationsFile
          ? loadProgramProfileRecommendations(recommendationsFile, { paths })
          : null;
        const result = action === "create"
          ? createProgramProfileWithRecommendations(id, recommendations, { paths })
          : applyProgramProfileRecommendations(id, recommendations, { paths });
        return output(result, json);
      }
      const recommendations = recommendationsFile
        ? loadProgramProfileRecommendations(recommendationsFile, { paths })
        : null;
      return output(await runProgramProfileQuestionnaire(id, action, { paths, recommendations }), json);
    }

    if (action === "ui") {
      assertPositionals(
        parsed.positional,
        3,
        "gate bounty profile ui ID [--host 127.0.0.1] [--port N] [--open] [--recommendations FILE]"
      );
      assertFlags(parsed.flags, ["host", "port", "open", "recommendations", "json"]);
      assertBooleanSwitch(parsed.flags, "open");
      if (!id) throw new Error("program profile id is required");
      const host = optionalValueFlag(parsed.flags, "host") || "127.0.0.1";
      const portFlag = optionalValueFlag(parsed.flags, "port");
      const port = portFlag === undefined ? 0 : Number(portFlag);
      const recommendationsFile = optionalValueFlag(parsed.flags, "recommendations");
      const recommendations = recommendationsFile
        ? loadProgramProfileRecommendations(recommendationsFile, { paths })
        : null;
      const { startProfileWizardServer } = await import("./profile-ui/server.mjs");
      const started = await startProfileWizardServer({
        profileId: id,
        paths,
        host,
        port,
        recommendations,
        openBrowser: parsed.flags.open === true
      });
      const summary = {
        started: true,
        profileId: started.profileId,
        host: started.host,
        port: started.port,
        origin: started.origin,
        url: started.url,
        browserOpened: started.browserOpened
      };
      if (json) output(summary, true);
      else {
        process.stdout.write(`GATE profile wizard: ${started.url}\n`);
        process.stdout.write(`Private loopback session for ${started.profileId}. Press Ctrl+C to stop.\n`);
        if (parsed.flags.open === true && !started.browserOpened) {
          process.stdout.write("Automatic browser launch was unavailable; open the private URL above.\n");
        }
      }
      await new Promise((resolve, reject) => {
        let stopping = false;
        const stop = (signal) => {
          if (stopping) return;
          stopping = true;
          process.off("SIGINT", onSigint);
          process.off("SIGTERM", onSigterm);
          process.exitCode = signal === "SIGINT" ? 130 : 143;
          started.close().then(resolve, reject);
        };
        const onSigint = () => stop("SIGINT");
        const onSigterm = () => stop("SIGTERM");
        process.once("SIGINT", onSigint);
        process.once("SIGTERM", onSigterm);
      });
      return;
    }

    if (action === "status") {
      if (parsed.positional.length < 2 || parsed.positional.length > 3) {
        throw new Error("expected gate bounty profile status [ID]");
      }
      assertFlags(parsed.flags, ["json"]);
      return output(programProfileStatus(id || null, { paths }), json);
    }

    if (action === "show") {
      assertPositionals(parsed.positional, 3, "gate bounty profile show ID [--format json|review|model-context]");
      assertFlags(parsed.flags, ["format", "json"]);
      if (!id) throw new Error("program profile id is required");
      const format = optionalValueFlag(parsed.flags, "format") || (json ? "json" : "review");
      if (!new Set(["json", "review", "model-context"]).has(format)) {
        throw new Error("--format must be json, review, or model-context");
      }
      return output(showProgramProfile(id, { paths, format }), json);
    }

    if (action === "verify") {
      assertPositionals(parsed.positional, 3, "gate bounty profile verify ID");
      assertFlags(parsed.flags, ["json"]);
      if (!id) throw new Error("program profile id is required");
      const result = verifyProgramProfile(id, { paths });
      output(result, json);
      if (!result.ok || !result.ready) process.exitCode = 2;
      return;
    }

    if (action === "compile") {
      assertPositionals(
        parsed.positional,
        3,
        "gate bounty profile compile ID [--engagement ID] [--workflow ID] [--provider-profile FILE]"
      );
      assertFlags(parsed.flags, ["engagement", "workflow", "provider-profile", "json"]);
      if (!id) throw new Error("program profile id is required");
      assertSelectedCaseProgram(selectedCase, id);
      const providerProfile = optionalValueFlag(parsed.flags, "provider-profile");
      recheckSelectedCaseBindings(selectedCase, basePaths);
      const result = compileProgramProfile(
        id,
        {
          engagementId: optionalValueFlag(parsed.flags, "engagement"),
          workflowId: optionalValueFlag(parsed.flags, "workflow"),
          providerProfile
        },
        {
          paths,
          ...(selectedCase
            ? { expectedProfileSha256: selectedCase.case.program.profileSha256 }
            : {})
        }
      );
      output(result, json);
      if (!result.ok || !result.ready || (providerProfile && !result.routeReady)) process.exitCode = 2;
      return;
    }

    throw new Error(`unknown bounty profile action: ${action}`);
  }

  if (command === "analysis") {
    assertUnambiguousAnalysisArgs(rest);
    const [action] = parsed.positional;
    if (!action) throw new Error("analysis action is required");
    assertPositionals(parsed.positional, 1, "gate analysis capability|manifest|run|purge|status [options]");
    assertBooleanSwitch(parsed.flags, "json");
    if (action === "capability") {
      assertFlags(parsed.flags, ["json"]);
      const capability = offlineAnalysisCapability({ paths });
      output(capability, json);
      if (!capability.laneAvailable) process.exitCode = 2;
      return;
    }
    if (action === "manifest") {
      assertFlags(parsed.flags, ["project", "path", "minutes", "json"]);
      const projectId = requiredFlag(parsed.flags, "project");
      assertSelectedCaseProject(selectedCase, projectId);
      recheckSelectedCaseBindings(selectedCase, basePaths);
      return output(
        createOfflineAnalysisManifest(
          projectId,
          {
            path: requiredFlag(parsed.flags, "path"),
            maxMinutes: optionalValueFlag(parsed.flags, "minutes")
          },
          {
            paths,
            ...(selectedCase
              ? { expectedProjectContractSha256: selectedCase.case.project.contractSha256 }
              : {})
          }
        ),
        json
      );
    }
    if (action === "run") {
      assertFlags(parsed.flags, ["project", "manifest", "confirm", "json"]);
      const projectId = requiredFlag(parsed.flags, "project");
      assertSelectedCaseProject(selectedCase, projectId);
      recheckSelectedCaseBindings(selectedCase, basePaths);
      const result = await executeOfflineAnalysisManifest(
        projectId,
        {
          manifestId: requiredFlag(parsed.flags, "manifest"),
          confirm: requiredFlag(parsed.flags, "confirm")
        },
        { paths }
      );
      output(result, json);
      if (!result.ok) process.exitCode = 2;
      return;
    }
    if (action === "purge") {
      assertFlags(parsed.flags, ["project", "manifest", "confirm", "json"]);
      const projectId = requiredFlag(parsed.flags, "project");
      assertSelectedCaseProject(selectedCase, projectId);
      return output(
        purgeOfflineAnalysisArtifact(
          projectId,
          {
            manifestId: requiredFlag(parsed.flags, "manifest"),
            confirm: requiredFlag(parsed.flags, "confirm")
          },
          { paths }
        ),
        json
      );
    }
    if (action === "status") {
      assertFlags(parsed.flags, ["json"]);
      return output(offlineAnalysisStatus({ paths }), json);
    }
    throw new Error(`unknown analysis action: ${action}`);
  }

  if (command === "workspace") {
    const [action] = parsed.positional;
    if (!action) throw new Error("workspace action is required");
    assertPositionals(parsed.positional, 1, "gate workspace ACTION [options]");
    if (action === "lease") {
      assertFlags(parsed.flags, ["repo", "task", "branch", "base", "json"]);
      return output(leaseWorkspace({
        repository: requiredFlag(parsed.flags, "repo"),
        taskId: requiredFlag(parsed.flags, "task"),
        branch: requiredFlag(parsed.flags, "branch"),
        baseBranch: typeof parsed.flags.base === "string" ? parsed.flags.base : undefined
      }, { paths }), json);
    }
    if (action === "status") {
      assertFlags(parsed.flags, ["repo", "json"]);
      return output(workspaceStatus({
        repository: requiredFlag(parsed.flags, "repo")
      }, { paths }), json);
    }
    if (action === "verify") {
      assertFlags(parsed.flags, ["repo", "path", "task", "lease", "landed-ref", "json"]);
      return output(verifyWorkspace({
        repository: requiredFlag(parsed.flags, "repo"),
        path: requiredFlag(parsed.flags, "path"),
        taskId: requiredFlag(parsed.flags, "task"),
        leaseId: requiredFlag(parsed.flags, "lease"),
        landedRef: requiredFlag(parsed.flags, "landed-ref")
      }, { paths }), json);
    }
    throw new Error(`unknown workspace action: ${action}`);
  }

  if (command === "event") {
    assertFlags(parsed.flags, ["summary", "json"]);
    assertPositionals(parsed.positional, 1, "gate event KIND --summary TEXT");
    const kind = parsed.positional[0];
    if (!kind) throw new Error("event kind is required");
    return output(recordEvent({ kind, summary: requiredFlag(parsed.flags, "summary") }, { paths }), json);
  }

  if (command === "learn") {
    assertUnambiguousLearningArgs(rest);
    const [action, id] = parsed.positional;
    if (!action) {
      assertFlags(parsed.flags, ["cause", "change", "private", "scope", "json"]);
      assertPositionals(parsed.positional, 0, "gate learn --cause TEXT --change TEXT");
      if (selectedCase && parsed.flags.private !== true) {
        throw new Error("case-scoped learning must use --private; unset GATE_CASE to record shared public learning");
      }
      return output(
        addLearning(
          {
            cause: requiredFlag(parsed.flags, "cause"),
            change: requiredFlag(parsed.flags, "change"),
            scope: typeof parsed.flags.scope === "string" ? parsed.flags.scope : undefined,
            sensitivity: parsed.flags.private === true ? "private" : "public"
          },
          { paths }
        ),
        json
      );
    }
    if (action === "cycle") {
      assertPositionals(parsed.positional, 1, "gate learn cycle --file FILE");
      assertFlags(parsed.flags, ["file", "json"]);
      const input = readStructuredCommandFile(requiredFlag(parsed.flags, "file"), "learning cycle file");
      return output(learningCommit(addLearningCycle(input, { paths })), json);
    }
    if (action === "promote") {
      assertPositionals(parsed.positional, 2, "gate learn promote ID --file FILE");
      assertFlags(parsed.flags, ["file", "json"]);
      const input = readStructuredCommandFile(requiredFlag(parsed.flags, "file"), "learning promotion file");
      return output(learningCommit(promoteLearning(id, input, { paths })), json);
    }
    if (action === "consult") {
      assertPositionals(parsed.positional, 1, "gate learn consult --file FILE [--limit N] [--max-bytes N]");
      assertFlags(parsed.flags, ["file", "limit", "max-bytes", "json"]);
      const input = readStructuredCommandFile(requiredFlag(parsed.flags, "file"), "learning consultation file");
      const limit = optionalValueFlag(parsed.flags, "limit");
      const maxBytes = optionalValueFlag(parsed.flags, "max-bytes");
      const request = {
        ...input,
        ...(limit === undefined ? {} : { limit }),
        ...(maxBytes === undefined ? {} : { maxBytes })
      };
      return output(consultLearnings(request, { paths }), json);
    }
    throw new Error(`unknown learn action: ${action}`);
  }

  if (command === "run") {
    throw new Error("raw command execution is disabled; run local development commands directly and use a reviewed scope-aware adapter for target contact");
  }

  if (command === "engagement") {
    const [action, id] = parsed.positional;
    if (!action || !id) throw new Error("engagement action and id are required");
    assertPositionals(parsed.positional, 2, "gate engagement ACTION ID [options]");
    if (selectionMode === "strict") recheckSelectedCaseBindings(selectedCase, basePaths);
    if (action === "new") {
      assertFlags(parsed.flags, [
        "title", "owner", "basis", "targets", "actions", "tools", "exclude", "environment", "depth",
        "valid-from", "valid-until", "max-minutes", "max-requests", "max-parallel", "max-rate", "max-tokens",
        "retention-days", "hypotheses", "classification", "allowed-destinations", "secret-refs", "stop-on", "json"
      ]);
      return output(
        createEngagement(
          {
            id,
            title: parsed.flags.title,
            owner: parsed.flags.owner,
            basis: parsed.flags.basis,
            targets: listFlag(parsed.flags, "targets"),
            actions: listFlag(parsed.flags, "actions"),
            tools: listFlag(parsed.flags, "tools"),
            exclude: listFlag(parsed.flags, "exclude"),
            environment: parsed.flags.environment,
            depth: parsed.flags.depth,
            validFrom: parsed.flags["valid-from"],
            validUntil: parsed.flags["valid-until"],
            maxMinutes: parsed.flags["max-minutes"],
            maxRequests: parsed.flags["max-requests"],
            maxParallel: parsed.flags["max-parallel"],
            maxRate: parsed.flags["max-rate"],
            maxTokens: parsed.flags["max-tokens"],
            retentionDays: parsed.flags["retention-days"],
            hypotheses: listFlag(parsed.flags, "hypotheses"),
            classification: parsed.flags.classification,
            allowedDestinations: listFlag(parsed.flags, "allowed-destinations"),
            secretRefs: listFlag(parsed.flags, "secret-refs"),
            stopOn: listFlag(parsed.flags, "stop-on")
          },
          { paths }
        ),
        json
      );
    }
    if (action === "plan") {
      assertFlags(parsed.flags, ["file", "json"]);
      return output(attachPlan(id, requiredFlag(parsed.flags, "file"), { paths }), json);
    }
    if (action === "authorization") {
      assertFlags(parsed.flags, ["file", "json"]);
      return output(attachAuthorization(id, requiredFlag(parsed.flags, "file"), { paths }), json);
    }
    if (action === "review") {
      assertFlags(parsed.flags, ["run", "head", "result", "json"]);
      return output(
        recordTechnicalReview(
          id,
          {
            run: requiredFlag(parsed.flags, "run"),
            headSha: requiredFlag(parsed.flags, "head"),
            status: requiredFlag(parsed.flags, "result")
          },
          { paths }
        ),
        json
      );
    }
    if (action === "approve") {
      assertFlags(parsed.flags, ["sha", "confirm", "json"]);
      return output(
        approveEngagement(
          id,
          { sha256: requiredFlag(parsed.flags, "sha"), confirm: requiredFlag(parsed.flags, "confirm") },
          { paths }
        ),
        json
      );
    }
    if (action === "check") {
      assertFlags(parsed.flags, ["target", "action", "minutes", "requests", "parallel", "rate", "tokens", "json"]);
      const check = checkEngagement(
        id,
        {
          target: requiredFlag(parsed.flags, "target"),
          action: requiredFlag(parsed.flags, "action"),
          maxMinutes: parsed.flags.minutes,
          estimatedRequests: parsed.flags.requests,
          maxParallel: parsed.flags.parallel,
          maxRatePerSecond: parsed.flags.rate,
          maxTokens: parsed.flags.tokens
        },
        { paths }
      );
      output(check, json);
      if (!check.allowed) process.exitCode = 2;
      return;
    }
    if (action === "manifest") {
      assertFlags(parsed.flags, [
        "workflow", "phase-attempt", "target", "action", "tool", "minutes", "requests", "parallel", "rate",
        "tokens", "evidence-bytes", "json"
      ]);
      if (parsed.passthrough.length === 0) {
        throw new Error("manifest command arguments are required after --");
      }
      return output(
        createExecutionManifest(
          id,
          {
            workflowId: requiredFlag(parsed.flags, "workflow"),
            phaseAttemptId: requiredFlag(parsed.flags, "phase-attempt"),
            target: requiredFlag(parsed.flags, "target"),
            action: requiredFlag(parsed.flags, "action"),
            toolId: requiredFlag(parsed.flags, "tool"),
            argv: parsed.passthrough,
            maxMinutes: requiredFlag(parsed.flags, "minutes"),
            estimatedRequests: requiredFlag(parsed.flags, "requests"),
            maxParallel: requiredFlag(parsed.flags, "parallel"),
            maxRatePerSecond: requiredFlag(parsed.flags, "rate"),
            maxTokens: requiredFlag(parsed.flags, "tokens"),
            maxEvidenceBytes: optionalValueFlag(parsed.flags, "evidence-bytes")
          },
          { paths }
        ),
        json
      );
    }
    if (action === "adapter-manifest") {
      if (parsed.passthrough.length > 0) throw new Error("adapter-manifest does not accept raw command arguments");
      const adapterId = requiredFlag(parsed.flags, "adapter");
      const common = [
        "adapter", "workflow", "phase-attempt", "target", "minutes", "requests", "parallel", "rate",
        "tokens", "evidence-bytes", "timeout-seconds", "json"
      ];
      let operation;
      if (adapterId === "dnsx-domain-observe") {
        assertFlags(parsed.flags, [...common, "record-type", "resolver"]);
        operation = {
          kind: "dns-query",
          recordType: requiredFlag(parsed.flags, "record-type"),
          resolver: requiredFlag(parsed.flags, "resolver"),
          timeoutSeconds: Number(requiredFlag(parsed.flags, "timeout-seconds"))
        };
      } else if (adapterId === "httpx-url-observe") {
        assertFlags(parsed.flags, [...common, "method", "allowed-ip", "max-response-bytes"]);
        operation = {
          kind: "http-get",
          method: requiredFlag(parsed.flags, "method"),
          allowedIp: requiredFlag(parsed.flags, "allowed-ip"),
          timeoutSeconds: Number(requiredFlag(parsed.flags, "timeout-seconds")),
          maxResponseBytes: Number(requiredFlag(parsed.flags, "max-response-bytes"))
        };
      } else {
        throw new Error(`unknown managed target-contact adapter: ${adapterId}`);
      }
      return output(createManagedExecutionManifest(id, {
        adapterId,
        workflowId: requiredFlag(parsed.flags, "workflow"),
        phaseAttemptId: requiredFlag(parsed.flags, "phase-attempt"),
        target: requiredFlag(parsed.flags, "target"),
        operation,
        maxMinutes: requiredFlag(parsed.flags, "minutes"),
        estimatedRequests: requiredFlag(parsed.flags, "requests"),
        maxParallel: requiredFlag(parsed.flags, "parallel"),
        maxRatePerSecond: requiredFlag(parsed.flags, "rate"),
        maxTokens: requiredFlag(parsed.flags, "tokens"),
        maxEvidenceBytes: optionalValueFlag(parsed.flags, "evidence-bytes")
      }, { paths }), json);
    }
    if (action === "exec") {
      assertFlags(parsed.flags, ["manifest", "confirm", "json"]);
      if (parsed.passthrough.length > 0) throw new Error("engagement exec does not accept command arguments");
      const result = await executeExecutionManifest(
        id,
        {
          manifestId: requiredFlag(parsed.flags, "manifest"),
          confirm: requiredFlag(parsed.flags, "confirm")
        },
        { paths }
      );
      output(result, json);
      if (!result.ok) process.exitCode = 2;
      return;
    }
    if (action === "reconcile") {
      assertFlags(parsed.flags, ["manifest", "confirm", "json"]);
      if (parsed.passthrough.length > 0) throw new Error("engagement reconcile does not accept command arguments");
      const result = reconcileExecution(
        id,
        {
          manifestId: requiredFlag(parsed.flags, "manifest"),
          confirm: requiredFlag(parsed.flags, "confirm")
        },
        { paths }
      );
      output(result, json);
      if (!result.ok) process.exitCode = 2;
      return;
    }
    if (action === "stop") {
      assertFlags(parsed.flags, ["run", "json"]);
      return output(
        requestExecutionStop(id, { runId: requiredFlag(parsed.flags, "run") }, { paths }),
        json
      );
    }
    if (action === "revoke") {
      assertFlags(parsed.flags, ["confirm", "json"]);
      const engagement = revokeEngagement(
        id,
        { confirm: requiredFlag(parsed.flags, "confirm") },
        { paths }
      );
      const stops = requestEngagementStops(id, { paths });
      return output({ ok: true, engagement, stops }, json);
    }
    if (action === "status") {
      assertFlags(parsed.flags, ["json"]);
      return output(getEngagement(id, { paths }), json);
    }
    if (action === "close") {
      assertFlags(parsed.flags, ["json"]);
      return output(closeEngagement(id, { paths }), json);
    }
    throw new Error(`unknown engagement action: ${action}`);
  }

  if (command === "workflow") {
    assertUnambiguousWorkflowArgs(rest);
    assertBooleanSwitch(parsed.flags, "json");
    const [area, actionOrId, maybeId] = parsed.positional;
    const mutationFlags = ["request", "expected-sequence", "expected-head", "json"];
    if (selectionMode === "strict") recheckSelectedCaseBindings(selectedCase, basePaths);
    if (area === "new") {
      assertPositionals(parsed.positional, 2, "gate workflow new ID [--engagement ID]");
      assertFlags(parsed.flags, ["engagement", "request", "json"]);
      const result = createWorkflowInstance(actionOrId, {
        engagementId: optionalValueFlag(parsed.flags, "engagement")
      }, workflowMutationOptions(parsed.flags, paths));
      return output(result, json);
    }
    if (area === "status") {
      assertPositionals(parsed.positional, 2, "gate workflow status ID");
      assertFlags(parsed.flags, ["json"]);
      const result = workflowStatus(actionOrId, { paths });
      output(result, json);
      if (!result.ok) process.exitCode = 2;
      return;
    }
    if (area === "phase" && actionOrId === "preflight") {
      assertPositionals(parsed.positional, 3, "gate workflow phase preflight ID --phase PHASE --from PHASE --admission FILE [--handoff-id ID] [--handoff FILE]");
      assertFlags(parsed.flags, ["phase", "from", "admission", "handoff", "handoff-id", "json"]);
      const result = preflightWorkflowPhase(maybeId, {
        phaseId: requiredFlag(parsed.flags, "phase"),
        sourcePhase: optionalValueFlag(parsed.flags, "from"),
        admissionFile: requiredFlag(parsed.flags, "admission"),
        handoffFile: optionalValueFlag(parsed.flags, "handoff"),
        handoffId: optionalValueFlag(parsed.flags, "handoff-id")
      }, { paths });
      return output(result, json);
    }
    if (area === "phase" && actionOrId === "start") {
      assertPositionals(parsed.positional, 3, "gate workflow phase start ID --phase PHASE [options]");
      assertFlags(parsed.flags, [
        "phase", "from", "admission", "handoff", "handoff-id", "confirm", ...mutationFlags
      ]);
      const result = startWorkflowPhase(maybeId, {
        phaseId: requiredFlag(parsed.flags, "phase"),
        sourcePhase: optionalValueFlag(parsed.flags, "from"),
        admissionFile: optionalValueFlag(parsed.flags, "admission"),
        handoffFile: optionalValueFlag(parsed.flags, "handoff"),
        handoffId: optionalValueFlag(parsed.flags, "handoff-id"),
        confirm: optionalValueFlag(parsed.flags, "confirm")
      }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "phase" && actionOrId === "finish") {
      assertPositionals(parsed.positional, 3, "gate workflow phase finish ID --phase PHASE --disposition DISPOSITION");
      assertFlags(parsed.flags, ["phase", "disposition", "rationale", "evidence-sha", ...mutationFlags]);
      const result = finishWorkflowPhase(maybeId, {
        phaseId: requiredFlag(parsed.flags, "phase"),
        disposition: requiredFlag(parsed.flags, "disposition"),
        rationale: optionalValueFlag(parsed.flags, "rationale"),
        evidenceSha256: listFlag(parsed.flags, "evidence-sha")
      }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "test" && new Set(["plan", "review"]).has(actionOrId)) {
      assertPositionals(parsed.positional, 3, `gate workflow test ${actionOrId} ID --file FILE`);
      assertFlags(parsed.flags, ["file", ...mutationFlags]);
      const input = readStructuredCommandFile(
        requiredFlag(parsed.flags, "file"),
        `workflow test ${actionOrId} file`
      );
      const result = actionOrId === "plan"
        ? planWorkflowTest(maybeId, input, workflowMutationOptions(parsed.flags, paths))
        : reviewWorkflowTest(maybeId, input, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "evidence" && actionOrId === "add") {
      assertPositionals(parsed.positional, 3, "gate workflow evidence add ID --phase PHASE --evidence ID --file PATH");
      assertFlags(parsed.flags, ["phase", "evidence", "file", "claim", ...mutationFlags]);
      const result = addWorkflowEvidence(maybeId, {
        phaseId: requiredFlag(parsed.flags, "phase"),
        evidenceId: requiredFlag(parsed.flags, "evidence"),
        file: requiredFlag(parsed.flags, "file"),
        claimState: optionalValueFlag(parsed.flags, "claim")
      }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "coverage" && actionOrId === "set") {
      assertPositionals(parsed.positional, 3, "gate workflow coverage set ID --domain DOMAIN --disposition DISPOSITION");
      assertFlags(parsed.flags, ["domain", "disposition", "evidence-sha", "rationale", ...mutationFlags]);
      const result = setWorkflowCoverage(maybeId, {
        domain: requiredFlag(parsed.flags, "domain"),
        disposition: requiredFlag(parsed.flags, "disposition"),
        evidenceSha256: listFlag(parsed.flags, "evidence-sha"),
        rationale: optionalValueFlag(parsed.flags, "rationale")
      }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "ledger" && actionOrId === "preflight") {
      assertPositionals(parsed.positional, 3, "gate workflow ledger preflight ID --type pivot [options]");
      assertFlags(parsed.flags, ["type", "target-sha", "before-sha", "cleanup", "pivot-admission", "json"]);
      const result = preflightWorkflowPivot(maybeId, {
        changeType: requiredFlag(parsed.flags, "type"),
        targetSelectorSha256: requiredFlag(parsed.flags, "target-sha"),
        beforeEvidenceSha256: requiredFlag(parsed.flags, "before-sha"),
        cleanupAction: requiredFlag(parsed.flags, "cleanup"),
        pivotAdmissionFile: requiredFlag(parsed.flags, "pivot-admission")
      }, { paths });
      return output(result, json);
    }
    if (area === "ledger" && actionOrId === "open") {
      assertPositionals(parsed.positional, 3, "gate workflow ledger open ID [options]");
      assertFlags(parsed.flags, [
        "type", "target-sha", "before-sha", "cleanup", "pivot-admission", "pivot-confirm", ...mutationFlags
      ]);
      const result = openWorkflowLedger(maybeId, {
        changeType: requiredFlag(parsed.flags, "type"),
        targetSelectorSha256: requiredFlag(parsed.flags, "target-sha"),
        beforeEvidenceSha256: requiredFlag(parsed.flags, "before-sha"),
        cleanupAction: requiredFlag(parsed.flags, "cleanup"),
        pivotAdmissionFile: optionalValueFlag(parsed.flags, "pivot-admission"),
        pivotConfirm: optionalValueFlag(parsed.flags, "pivot-confirm")
      }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "ledger" && actionOrId === "cleanup") {
      assertPositionals(parsed.positional, 3, "gate workflow ledger cleanup ID --entry ID --evidence-sha SHA256");
      assertFlags(parsed.flags, ["entry", "evidence-sha", ...mutationFlags]);
      const result = recordWorkflowLedgerCleanup(maybeId, {
        entryId: requiredFlag(parsed.flags, "entry"),
        cleanupEvidenceSha256: requiredFlag(parsed.flags, "evidence-sha")
      }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "ledger" && actionOrId === "verify") {
      assertPositionals(parsed.positional, 3, "gate workflow ledger verify ID --entry ID --evidence-sha SHA256");
      assertFlags(parsed.flags, ["entry", "evidence-sha", ...mutationFlags]);
      const result = verifyWorkflowLedger(maybeId, {
        entryId: requiredFlag(parsed.flags, "entry"),
        verificationEvidenceSha256: requiredFlag(parsed.flags, "evidence-sha")
      }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "ledger" && actionOrId === "hold") {
      assertPositionals(parsed.positional, 3, "gate workflow ledger hold ID --entry ID --reason TEXT");
      assertFlags(parsed.flags, ["entry", "reason", ...mutationFlags]);
      const result = holdWorkflowLedger(maybeId, {
        entryId: requiredFlag(parsed.flags, "entry"),
        reason: requiredFlag(parsed.flags, "reason")
      }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "execution" && actionOrId === "cancel") {
      assertPositionals(parsed.positional, 3, "gate workflow execution cancel ID --reservation ID --reason TEXT");
      assertFlags(parsed.flags, ["reservation", "reason", ...mutationFlags]);
      const result = cancelWorkflowExecution(maybeId, {
        reservationId: requiredFlag(parsed.flags, "reservation"),
        reason: requiredFlag(parsed.flags, "reason")
      }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "stop") {
      assertPositionals(parsed.positional, 2, "gate workflow stop ID --condition CONDITION --reason TEXT");
      assertFlags(parsed.flags, ["condition", "reason", "evidence-sha", ...mutationFlags]);
      const result = stopWorkflow(actionOrId, {
        condition: requiredFlag(parsed.flags, "condition"),
        reason: requiredFlag(parsed.flags, "reason"),
        evidenceSha256: optionalValueFlag(parsed.flags, "evidence-sha")
      }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "join") {
      assertPositionals(parsed.positional, 2, "gate workflow join ID");
      assertFlags(parsed.flags, mutationFlags);
      const result = joinWorkflowCoverage(actionOrId, {}, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "report") {
      assertPositionals(parsed.positional, 2, "gate workflow report ID --file PATH");
      assertFlags(parsed.flags, ["file", ...mutationFlags]);
      const result = attachWorkflowReport(actionOrId, { file: requiredFlag(parsed.flags, "file") }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "close") {
      assertPositionals(parsed.positional, 2, "gate workflow close ID --confirm TEXT");
      assertFlags(parsed.flags, ["confirm", ...mutationFlags]);
      const result = closeWorkflow(actionOrId, { confirm: requiredFlag(parsed.flags, "confirm") }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    throw new Error(`unknown workflow action: ${parsed.positional.join(" ") || "missing"}`);
  }

  if (command === "upstream") {
    const [action = "list", id] = parsed.positional;
    if (action === "list") {
      assertPositionals(parsed.positional, 1, "gate upstream list");
      assertFlags(parsed.flags, ["json"]);
      return output(upstreamStatus({ paths }), json);
    }
    if (action === "sync") {
      assertPositionals(parsed.positional, 2, "gate upstream sync ID|all");
      assertFlags(parsed.flags, ["json"]);
      if (!id) throw new Error("upstream id is required");
      if (id === "all") {
        const results = [];
        for (const item of upstreamStatus({ paths })) results.push(syncUpstream(item.id, { paths }));
        return output(results, json);
      }
      return output(syncUpstream(id, { paths }), json);
    }
    if (action === "install") {
      assertPositionals(parsed.positional, 2, "gate upstream install ID|all");
      assertFlags(parsed.flags, ["json"]);
      if (!id) throw new Error("upstream id is required");
      if (id === "all") {
        const results = [];
        for (const item of upstreamStatus({ paths }).filter((entry) => ["npm", "github-release"].includes(entry.install?.lane))) {
          results.push(installUpstream(item.id, { paths }));
        }
        return output(results, json);
      }
      return output(installUpstream(id, { paths }), json);
    }
    if (action === "path") {
      assertPositionals(parsed.positional, 2, "gate upstream path ID");
      assertFlags(parsed.flags, ["json"]);
      if (!id) throw new Error("upstream id is required");
      const item = upstreamStatus({ paths }).find((entry) => entry.id === id);
      if (!item) throw new Error(`unknown upstream: ${id}`);
      return output(item.packageReady ? item.toolDirectory : item.directory, json);
    }
    if (action === "exec") {
      throw new Error("raw upstream execution is disabled; use the reviewed upstream directly for local work or add a scope-aware GATE adapter before target contact");
    }
    throw new Error(`unknown upstream action: ${action}`);
  }

  if (command === "tool") {
    assertUnambiguousToolArgs(rest);
    const [action = "list", id] = parsed.positional;
    if (action === "list") {
      assertPositionals(parsed.positional, 1, "gate tool list [--profile ID] [--category ID] [--summary] [--limit N] [--cursor N]");
      assertFlags(parsed.flags, ["profile", "category", "summary", "limit", "cursor", "json"]);
      assertBooleanSwitch(parsed.flags, "summary");
      assertBooleanSwitch(parsed.flags, "json");
      if ((parsed.flags.limit !== undefined || parsed.flags.cursor !== undefined) && parsed.flags.summary !== true) {
        throw new Error("--limit and --cursor require --summary");
      }
      const profile = optionalValueFlag(parsed.flags, "profile");
      const category = optionalValueFlag(parsed.flags, "category");
      const inventory = toolInventory({
        paths,
        profile: profile || null,
        category: category || null
      });
      return output(
        parsed.flags.summary === true
          ? toolInventorySummary(inventory, {
              limit: optionalValueFlag(parsed.flags, "limit"),
              cursor: optionalValueFlag(parsed.flags, "cursor"),
              profile: profile || null,
              category: category || null
            })
          : inventory,
        json
      );
    }
    if (action === "show") {
      assertPositionals(parsed.positional, 2, "gate tool show ID [--json]");
      assertFlags(parsed.flags, ["json"]);
      assertBooleanSwitch(parsed.flags, "json");
      if (!id) throw new Error("security tool id is required");
      return output(toolDetailSummary(toolShow(id, { paths })), json);
    }
    if (action === "plan") {
      assertPositionals(parsed.positional, 2, "gate tool plan ID");
      assertFlags(parsed.flags, ["json"]);
      if (!id) throw new Error("security tool id is required");
      return output(toolPlan(id, { paths }), json);
    }
    if (new Set(["prefetch", "install", "verify", "remove"]).has(action)) {
      assertFlags(parsed.flags, ["profile", "json"]);
      assertBooleanSwitch(parsed.flags, "json");
      const profile = optionalValueFlag(parsed.flags, "profile");
      if (Boolean(id) === Boolean(profile)) {
        throw new Error(`gate tool ${action} requires exactly one tool id or --profile ID`);
      }
      assertPositionals(
        parsed.positional,
        id ? 2 : 1,
        `gate tool ${action} ID|--profile ID [--json]`
      );
      const result = await runManagedToolOperation(action, { paths, id, profile });
      output(result, json);
      if (!result.ok) process.exitCode = 2;
      return;
    }
    throw new Error(`unknown tool action: ${action}`);
  }

  if (command === "publication") {
    const [action = "check"] = parsed.positional;
    assertPositionals(parsed.positional, 1, "gate publication check|dry-run|merge [options]");
    assertFlags(parsed.flags, ["repo", "pr", "head", "run", "mode", "json"]);
    const request = publicationRequest(parsed.flags);
    let result;
    if (action === "check") result = checkPublication(request);
    else if (action === "dry-run") result = publishPullRequest(request, { dryRun: true });
    else if (action === "merge") result = publishPullRequest(request);
    else throw new Error(`unknown publication action: ${action}`);
    const evidenceFile = persistPublicationEvidence(result, paths);
    output({ ...result, evidenceFile }, json);
    if (!result.ok) process.exitCode = 2;
    return;
  }

  throw new Error(`unknown command: ${command}\n\n${help}`);
}
