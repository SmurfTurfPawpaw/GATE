import fs from "node:fs";
import { isIP } from "node:net";
import path from "node:path";
import { domainToASCII } from "node:url";

import { runtimePaths } from "./paths.mjs";
import { validateDocument } from "./schema.mjs";

export const PROGRAM_PROFILE_DISPOSITIONS = Object.freeze([
  "allowed",
  "denied",
  "conditional",
  "unknown"
]);

export const PROGRAM_PROFILE_CLAIM_STATES = Object.freeze([
  "observed",
  "inferred",
  "unverified"
]);

export const PROGRAM_PROFILE_ACTIONS = Object.freeze([
  "observe",
  "scan",
  "intercept",
  "authenticate",
  "fuzz",
  "exploit-safe",
  "exploit-stateful",
  "persist",
  "denial-of-service",
  "destructive-test",
  "data-access",
  "data-removal",
  "exfiltration-simulation"
]);

export const PROGRAM_PROFILE_ASSISTANCE_MODES = Object.freeze([
  "plan",
  "analyze",
  "generate-command",
  "execute",
  "report",
  "retest"
]);

export const PROGRAM_PROFILE_EXECUTION_LIMITS = Object.freeze([
  "maxMinutes",
  "maxRequests",
  "maxParallel",
  "maxRatePerSecond",
  "maxTokens",
  "maxSpendUsd"
]);

export const PROGRAM_PROFILE_STOP_CONDITIONS = Object.freeze([
  "scope-mismatch",
  "plan-digest-change",
  "authorization-expiry",
  "unexpected-data-loss",
  "target-instability",
  "third-party-system-discovered",
  "rate-limit-exceeded",
  "evidence-integrity-failure",
  "unexpected-sensitive-data",
  "unplanned-privilege-or-persistence",
  "defensive-control-impact",
  "cleanup-incomplete",
  "operator-stop"
]);

export const PROGRAM_PROFILE_COVERAGE_DOMAINS = Object.freeze([
  "asset-discovery",
  "architecture",
  "authentication",
  "authorization",
  "sessions",
  "inputs",
  "business-logic",
  "client-behavior",
  "data-exposure",
  "infrastructure",
  "supply-chain",
  "post-exploitation-impact",
  "host-local-privilege",
  "wireless-radio",
  "internal-segmentation",
  "ai-llm-systems",
  "embedded-iot-ot",
  "human-physical-security"
]);

export const PROGRAM_PROFILE_SECTION_IDS = Object.freeze([
  "identity-objectives",
  "authority-sources",
  "actions-techniques",
  "limits-schedule",
  "scope-assets",
  "accounts-identities",
  "architecture-data-flows",
  "workflow-coverage",
  "data-evidence",
  "stops-escalation-cleanup",
  "reporting-disclosure",
  "ambiguities-attestation"
]);

export const PROGRAM_PROFILE_MODULE_IDS = Object.freeze([
  "web-api",
  "cloud-container",
  "mobile",
  "desktop",
  "ai-llm",
  "network-identity",
  "wireless-radio",
  "human-physical",
  "embedded-iot-ot"
]);

const QUESTIONNAIRE_MAXIMUM_BYTES = 1024 * 1024;

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function sameList(left, right) {
  return Array.isArray(left) && left.length === right.length && left.every((value, index) => value === right[index]);
}

function duplicateValues(values) {
  const seen = new Set();
  const duplicates = new Set();
  for (const value of values) {
    if (seen.has(value)) duplicates.add(value);
    seen.add(value);
  }
  return [...duplicates].sort();
}

function semanticQuestionnaireErrors(value) {
  const errors = [];
  const expectedSemantics = [
    ["dispositions", PROGRAM_PROFILE_DISPOSITIONS],
    ["claimStates", PROGRAM_PROFILE_CLAIM_STATES],
    ["actions", PROGRAM_PROFILE_ACTIONS],
    ["assistanceModes", PROGRAM_PROFILE_ASSISTANCE_MODES],
    ["stopConditions", PROGRAM_PROFILE_STOP_CONDITIONS],
    ["coverageDomains", PROGRAM_PROFILE_COVERAGE_DOMAINS],
    ["moduleIds", PROGRAM_PROFILE_MODULE_IDS]
  ];
  for (const [name, expected] of expectedSemantics) {
    if (!sameList(value.semantics?.[name], expected)) {
      errors.push(`questionnaire semantics.${name} must exactly match the GATE program-profile vocabulary`);
    }
  }

  const sectionIds = (value.sections || []).map((section) => section.id);
  if (!sameList(sectionIds, PROGRAM_PROFILE_SECTION_IDS)) {
    errors.push("questionnaire sections must contain the 12 required section ids in contract order");
  }
  const moduleIds = (value.conditionalModules || []).map((module) => module.id);
  if (!sameList(moduleIds, PROGRAM_PROFILE_MODULE_IDS)) {
    errors.push("questionnaire conditional modules must contain the nine required module ids in contract order");
  }

  const baseQuestions = (value.sections || []).flatMap((section) =>
    (section.questions || []).map((question) => ({ ...question, section: section.id }))
  );
  const moduleQuestions = (value.conditionalModules || []).flatMap((module) =>
    (module.questions || []).map((question) => ({ ...question, module: module.id }))
  );
  const questions = [...baseQuestions, ...moduleQuestions];
  for (const duplicate of duplicateValues(questions.map((question) => question.id))) {
    errors.push(`questionnaire question id is duplicated: ${duplicate}`);
  }
  for (const duplicate of duplicateValues(questions.map((question) => question.path))) {
    errors.push(`questionnaire answer path is duplicated: ${duplicate}`);
  }
  for (const question of questions) {
    if (["enum", "multi-enum"].includes(question.type) && !question.choices?.length) {
      errors.push(`questionnaire question ${question.id} requires choices`);
    }
    if (question.allowNull && !["text", "integer", "number", "datetime"].includes(question.type)) {
      errors.push(`questionnaire question ${question.id} cannot allow null for type ${question.type}`);
    }
    if (question.condition) {
      const modes = [Object.hasOwn(question.condition, "includes"), Object.hasOwn(question.condition, "equals")]
        .filter(Boolean).length;
      if (modes !== 1) errors.push(`questionnaire question ${question.id} must use exactly one condition operator`);
    }
  }
  const questionsById = new Map(questions.map((question) => [question.id, question]));
  const requiredContractQuestions = [
    {
      id: "execution-requested-assistance-modes",
      path: "executionPolicy.requestedAssistanceModes",
      type: "multi-enum",
      section: "actions-techniques"
    },
    {
      id: "execution-phase-policies",
      path: "executionPolicy.phases",
      type: "structured-list",
      section: "scope-assets"
    },
    {
      id: "limits-max-spend",
      path: "limits.maxSpendUsd",
      type: "number",
      section: "limits-schedule",
      allowNull: true
    },
    {
      id: "attestation-at",
      path: "attestation.attestedAt",
      type: "datetime",
      section: "ambiguities-attestation"
    }
  ];
  for (const expected of requiredContractQuestions) {
    const question = questionsById.get(expected.id);
    if (!question) {
      errors.push(`questionnaire requires question ${expected.id}`);
      continue;
    }
    if (
      question.path !== expected.path ||
      question.type !== expected.type ||
      question.section !== expected.section ||
      question.required !== true ||
      (expected.allowNull !== undefined && question.allowNull !== expected.allowNull)
    ) {
      errors.push(
        `questionnaire question ${expected.id} must be a required ${expected.type} at ${expected.path} in ${expected.section}`
      );
    }
  }
  const assistanceQuestion = questionsById.get("execution-requested-assistance-modes");
  if (assistanceQuestion && !sameList(assistanceQuestion.choices, PROGRAM_PROFILE_ASSISTANCE_MODES)) {
    errors.push("questionnaire execution assistance choices must exactly match the program-profile vocabulary");
  }
  for (const module of value.conditionalModules || []) {
    const activationModes = [
      Object.hasOwn(module.activation || {}, "includes"),
      Object.hasOwn(module.activation || {}, "equals")
    ].filter(Boolean).length;
    if (activationModes !== 1) errors.push(`questionnaire module ${module.id} must use exactly one activation operator`);
    if (
      module.activation?.path !== "questionnaire.applicableModules" ||
      module.activation?.includes !== module.id
    ) {
      errors.push(`questionnaire module ${module.id} must activate from its applicableModules id`);
    }
  }
  return errors;
}

export function validateProgramProfileQuestionnaire(value, options = {}) {
  const paths = options.paths || runtimePaths(options);
  const structural = validateDocument(value, "program-profile-questionnaire.schema.json", { paths });
  if (!structural.ok) return structural;
  const errors = semanticQuestionnaireErrors(value);
  return { ok: errors.length === 0, errors };
}

export function loadProgramProfileQuestionnaire(options = {}) {
  const paths = options.paths || runtimePaths(options);
  const file = path.join(paths.repo, "config", "questionnaires", "bug-bounty-program-profile.json");
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error("program profile questionnaire must be a regular non-symlink file");
  }
  if (stat.size > QUESTIONNAIRE_MAXIMUM_BYTES) {
    throw new Error(`program profile questionnaire exceeds the ${QUESTIONNAIRE_MAXIMUM_BYTES}-byte limit`);
  }
  const value = JSON.parse(fs.readFileSync(file, "utf8"));
  const validation = validateProgramProfileQuestionnaire(value, { paths });
  if (!validation.ok) {
    throw new Error(`program profile questionnaire validation failed: ${validation.errors.join("; ")}`);
  }
  return value;
}

function baseQuestions(questionnaire) {
  return questionnaire.sections.flatMap((section) => section.questions.map((question) => deepFreeze({
    ...question,
    section: section.id
  })));
}

function moduleQuestions(questionnaire) {
  return questionnaire.conditionalModules.flatMap((module) => module.questions.map((question) => deepFreeze({
    ...question,
    module: module.id,
    condition: question.condition || module.activation
  })));
}

export const PROGRAM_PROFILE_QUESTIONNAIRE = deepFreeze(loadProgramProfileQuestionnaire());
export const PROGRAM_PROFILE_SECTIONS = deepFreeze(PROGRAM_PROFILE_QUESTIONNAIRE.sections.map((section) => ({
  id: section.id,
  title: section.title,
  purpose: section.purpose
})));
export const PROGRAM_PROFILE_MODULE_QUESTIONS = deepFreeze(moduleQuestions(PROGRAM_PROFILE_QUESTIONNAIRE));
export const PROGRAM_PROFILE_QUESTIONS = deepFreeze([
  ...baseQuestions(PROGRAM_PROFILE_QUESTIONNAIRE).filter((question) => question.section !== "ambiguities-attestation"),
  ...PROGRAM_PROFILE_MODULE_QUESTIONS,
  ...baseQuestions(PROGRAM_PROFILE_QUESTIONNAIRE).filter((question) => question.section === "ambiguities-attestation")
]);

function collectIds(items, label, errors) {
  const ids = (items || []).map((item) => item?.id).filter((id) => typeof id === "string");
  for (const duplicate of duplicateValues(ids)) errors.push(`${label} id is duplicated: ${duplicate}`);
  return new Set(ids);
}

function visitSourceRefs(value, callback, location = "") {
  if (Array.isArray(value)) {
    value.forEach((item, index) => visitSourceRefs(item, callback, `${location}/${index}`));
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    const next = `${location}/${key}`;
    if (key === "sourceRefs" && Array.isArray(child)) callback(child, next);
    else visitSourceRefs(child, callback, next);
  }
}

function decisionEntries(value) {
  return [
    ["/authorization/safeHarbor", value.authorization.safeHarbor],
    ["/scope/thirdPartyHandling", value.scope.thirdPartyHandling],
    ["/scope/redirectHandling", value.scope.redirectHandling],
    ["/scope/discoveredAssetHandling", value.scope.discoveredAssetHandling],
    ...value.scope.assets.map((item, index) => [`/scope/assets/${index}`, item]),
    ...value.scope.assets.flatMap((item, index) => Object.entries(item.actionOverrides).map(([action, decision]) => [
      `/scope/assets/${index}/actionOverrides/${action}`,
      decision
    ])),
    ...PROGRAM_PROFILE_ACTIONS.map((id) => [`/techniquePolicy/actions/${id}`, value.techniquePolicy.actions[id]]),
    ...value.techniquePolicy.techniques.map((item, index) => [`/techniquePolicy/techniques/${index}`, item]),
    ...PROGRAM_PROFILE_COVERAGE_DOMAINS.map((id) => [`/coverage/${id}`, value.coverage[id]]),
    ...value.questionnaire.applicableModules.map((id) => [`/modules/${id}`, value.modules[id]])
  ];
}

const referenceVocabularyCache = new Map();

function readReferenceVocabulary(paths, errors) {
  if (referenceVocabularyCache.has(paths.repo)) return referenceVocabularyCache.get(paths.repo);
  try {
    const catalogFile = path.join(paths.repo, "catalog", "security-tools.json");
    const workflowFile = path.join(paths.repo, "config", "workflows", "pentest-e2e.json");
    for (const [file, label] of [[catalogFile, "security tool catalog"], [workflowFile, "pentest workflow"]]) {
      const stat = fs.lstatSync(file);
      if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`${label} must be a regular non-symlink file`);
    }
    const catalog = JSON.parse(fs.readFileSync(catalogFile, "utf8"));
    const workflow = JSON.parse(fs.readFileSync(workflowFile, "utf8"));
    if (!Array.isArray(catalog.tools) || !Array.isArray(workflow.phases)) {
      throw new Error("reference documents do not expose tools and workflow phases");
    }
    const toolIds = catalog.tools.map((item) => item?.id);
    const phaseIds = workflow.phases.map((item) => item?.id);
    const phaseToolIds = new Map(workflow.phases.map((phase) => [
      phase?.id,
      new Set((phase?.toolMappings || []).map((mapping) => mapping?.toolId))
    ]));
    if (
      toolIds.some((id) => typeof id !== "string") ||
      phaseIds.some((id) => typeof id !== "string") ||
      workflow.phases.some((phase) => !Array.isArray(phase?.toolMappings)) ||
      [...phaseToolIds.values()].some((ids) => [...ids].some((id) => typeof id !== "string"))
    ) {
      throw new Error("reference documents contain an invalid id");
    }
    const duplicateToolIds = duplicateValues(toolIds);
    const duplicatePhaseIds = duplicateValues(phaseIds);
    const catalogToolIds = new Set(toolIds);
    const invalidMappedTool = [...phaseToolIds.values()].flatMap((ids) => [...ids])
      .find((id) => !catalogToolIds.has(id));
    if (duplicateToolIds.length || duplicatePhaseIds.length || invalidMappedTool) {
      throw new Error("reference documents contain duplicate or inconsistent ids");
    }
    const result = {
      toolIds: new Set(toolIds),
      phaseIds: new Set(phaseIds),
      phaseToolIds
    };
    referenceVocabularyCache.set(paths.repo, result);
    return result;
  } catch (error) {
    errors.push(`execution policy references cannot be validated: ${error.message}`);
    return { toolIds: new Set(), phaseIds: new Set(), phaseToolIds: new Map() };
  }
}

function normalizedIpAddress(value) {
  const version = isIP(value);
  if (version === 4) return value.split(".").map((part) => String(Number(part))).join(".");
  if (version === 6) {
    const hostname = new URL(`http://[${value}]/`).hostname;
    return hostname.replace(/^\[/u, "").replace(/\]$/u, "").toLowerCase();
  }
  throw new Error("must contain a valid IP address");
}

function normalizedCidrNetwork(address, version, prefix) {
  if (version === 4) {
    const numeric = address.split(".").reduce((result, part) => (result << 8n) | BigInt(Number(part)), 0n);
    const hostBits = 32n - BigInt(prefix);
    const network = hostBits === 0n ? numeric : (numeric >> hostBits) << hostBits;
    return [24n, 16n, 8n, 0n].map((shift) => String(Number((network >> shift) & 255n))).join(".");
  }
  const canonical = normalizedIpAddress(address);
  const halves = canonical.split("::");
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const expanded = halves.length === 2
    ? [...left, ...Array(8 - left.length - right.length).fill("0"), ...right]
    : left;
  const numeric = expanded.reduce((result, part) => (result << 16n) | BigInt(`0x${part}`), 0n);
  const hostBits = 128n - BigInt(prefix);
  const network = hostBits === 0n ? numeric : (numeric >> hostBits) << hostBits;
  const full = Array.from({ length: 8 }, (_, index) =>
    ((network >> BigInt((7 - index) * 16)) & 0xffffn).toString(16)
  ).join(":");
  return normalizedIpAddress(full);
}

function normalizedSelectorValue(selector) {
  const raw = selector.value.normalize("NFC").trim();
  if (!raw) throw new Error("must not be empty after normalization");
  if (selector.type === "domain") {
    const withoutFinalDot = raw.replace(/\.+$/u, "");
    const wildcard = withoutFinalDot.startsWith("*.");
    const domain = wildcard ? withoutFinalDot.slice(2) : withoutFinalDot;
    const ascii = domainToASCII(domain).toLowerCase();
    if (!ascii) throw new Error("must contain a valid domain selector");
    return `${wildcard ? "*." : ""}${ascii}`;
  }
  if (selector.type === "ip") return normalizedIpAddress(raw);
  if (selector.type === "cidr") {
    const separator = raw.lastIndexOf("/");
    if (separator <= 0 || raw.indexOf("/") !== separator) throw new Error("must contain a valid CIDR");
    const address = raw.slice(0, separator);
    const version = isIP(address);
    const prefixText = raw.slice(separator + 1);
    const prefix = Number(prefixText);
    if (!version || !/^\d+$/u.test(prefixText) || prefix > (version === 4 ? 32 : 128)) {
      throw new Error("must contain a valid CIDR");
    }
    return `${normalizedCidrNetwork(address, version, prefix)}/${prefix}`;
  }
  if (selector.type === "url") {
    const parsed = new URL(raw);
    parsed.hash = "";
    if (!parsed.hostname.startsWith("[")) {
      parsed.hostname = parsed.hostname.toLowerCase().replace(/\.+$/u, "");
    }
    return parsed.href;
  }
  return raw;
}

function decisionBroadens(ceiling, candidate) {
  if (candidate.disposition === "allowed") return ceiling.disposition !== "allowed";
  if (candidate.disposition === "conditional") {
    return !["allowed", "conditional"].includes(ceiling.disposition);
  }
  return false;
}

function isAuthorizedDecision(decision) {
  return ["allowed", "conditional"].includes(decision?.disposition);
}

function limitBroadens(ceiling, candidate) {
  if (ceiling === null) return false;
  if (candidate === null) return true;
  return candidate > ceiling;
}

function validateExecutionPolicies(value, paths, assetIds, errors) {
  const references = readReferenceVocabulary(paths, errors);
  const assetsById = new Map(value.scope.assets.map((asset) => [asset.id, asset]));
  const selectors = new Map();
  for (const [index, asset] of value.scope.assets.entries()) {
    try {
      const normalized = normalizedSelectorValue(asset.selector);
      const key = `${asset.selector.type}\u0000${normalized}`;
      if (selectors.has(key)) {
        errors.push(
          `/scope/assets/${index}/selector duplicates normalized selector from asset ${selectors.get(key)}: ` +
          `${asset.selector.type}:${normalized}`
        );
      } else {
        selectors.set(key, asset.id);
      }
    } catch (error) {
      errors.push(`/scope/assets/${index}/selector ${error.message}`);
    }

    for (const [action, override] of Object.entries(asset.actionOverrides)) {
      const globalDecision = value.techniquePolicy.actions[action];
      if (decisionBroadens(globalDecision, override)) {
        errors.push(`/scope/assets/${index}/actionOverrides/${action} broadens the global action disposition`);
      }
      if (decisionBroadens(asset, override)) {
        errors.push(`/scope/assets/${index}/actionOverrides/${action} broadens the asset disposition`);
      }
    }
    for (const [limit, override] of Object.entries(asset.limitOverrides)) {
      if (limitBroadens(value.limits[limit], override)) {
        errors.push(`/scope/assets/${index}/limitOverrides/${limit} broadens the global execution limit`);
      }
    }
  }

  collectIds(value.executionPolicy.phases, "execution phase policy", errors);
  const policySlices = new Map();
  for (const [index, phase] of value.executionPolicy.phases.entries()) {
    const location = `/executionPolicy/phases/${index}`;
    if (!references.phaseIds.has(phase.phaseId)) {
      errors.push(`${location}/phaseId references unknown pentest workflow phase: ${phase.phaseId}`);
    }
    const allowedTools = new Set(phase.allowedToolIds);
    const mappedTools = references.phaseToolIds.get(phase.phaseId);
    for (const toolId of phase.allowedToolIds) {
      if (!references.toolIds.has(toolId)) errors.push(`${location}/allowedToolIds references unknown tool: ${toolId}`);
      else if (mappedTools && !mappedTools.has(toolId)) {
        errors.push(`${location}/allowedToolIds tool ${toolId} is not mapped to workflow phase ${phase.phaseId}`);
      }
    }
    for (const toolId of phase.deniedToolIds) {
      if (!references.toolIds.has(toolId)) errors.push(`${location}/deniedToolIds references unknown tool: ${toolId}`);
      if (allowedTools.has(toolId)) errors.push(`${location} both allows and denies tool: ${toolId}`);
    }
    for (const [limit, override] of Object.entries(phase.limits)) {
      if (limitBroadens(value.limits[limit], override)) {
        errors.push(`${location}/limits/${limit} broadens the global execution limit`);
      }
    }
    for (const assetRef of phase.assetRefs) {
      if (!assetIds.has(assetRef)) {
        errors.push(`${location}/assetRefs references unknown scope asset: ${assetRef}`);
        continue;
      }
      const asset = assetsById.get(assetRef);
      if (asset.disposition !== "allowed") {
        errors.push(`${location}/assetRefs references asset that is not allowed: ${assetRef}`);
      }
      for (const [limit, override] of Object.entries(phase.limits)) {
        if (Object.hasOwn(asset.limitOverrides, limit) && limitBroadens(asset.limitOverrides[limit], override)) {
          errors.push(`${location}/limits/${limit} broadens asset ${assetRef}'s execution limit`);
        }
      }
      for (const action of phase.actions) {
        const sliceKey = `${phase.phaseId}\u0000${assetRef}\u0000${action}`;
        if (policySlices.has(sliceKey)) {
          errors.push(`${location} overlaps phase/asset/action slice from policy ${policySlices.get(sliceKey)}`);
        } else {
          policySlices.set(sliceKey, phase.id);
        }
        const globalDecision = value.techniquePolicy.actions[action];
        const assetDecision = asset.actionOverrides[action];
        if (!isAuthorizedDecision(globalDecision)) {
          errors.push(`${location}/actions includes globally unauthorized action: ${action}`);
        }
        if (!assetDecision) {
          errors.push(`${location}/actions has no per-asset decision for ${assetRef}: ${action}`);
          continue;
        }
        if (!isAuthorizedDecision(assetDecision)) {
          errors.push(`${location}/actions includes action unauthorized for ${assetRef}: ${action}`);
        }
        if (
          (globalDecision.disposition === "conditional" || assetDecision.disposition === "conditional") &&
          phase.conditions.length === 0
        ) {
          errors.push(`${location}/conditions must bind conditional action ${action} for asset ${assetRef}`);
        }
      }
    }
  }
}

function requiredReadyList(value, pathName, errors) {
  if (!Array.isArray(value) || value.length === 0) {
    errors.push(`${pathName} must contain at least one item when ready`);
    return;
  }
  value.forEach((item, index) => {
    if (typeof item === "string" && !meaningfulText(item)) {
      errors.push(`${pathName}.${index} must contain visible text when ready`);
    }
  });
}

function meaningfulText(value) {
  const visible = value.normalize("NFKC").replace(/[\p{White_Space}\p{Default_Ignorable_Code_Point}]/gu, "");
  return /[\p{Letter}\p{Number}\p{Punctuation}\p{Symbol}]/u.test(visible);
}

function valueAtQuestionPath(value, fieldPath) {
  return fieldPath.split(".").reduce((current, part) =>
    current && typeof current === "object" && Object.hasOwn(current, part) ? current[part] : undefined
  , value);
}

function baseQuestionApplies(question, value) {
  if (question.module) return false;
  if (!question.condition) return true;
  const actual = valueAtQuestionPath(value, question.condition.path);
  if (Object.hasOwn(question.condition, "equals")) return actual === question.condition.equals;
  if (Object.hasOwn(question.condition, "includes")) {
    return Array.isArray(actual)
      ? actual.includes(question.condition.includes)
      : typeof actual === "string" && actual.includes(question.condition.includes);
  }
  return false;
}

function semanticProfileErrors(value, paths) {
  const errors = [];
  const sourceIds = collectIds(value.sources, "source", errors);
  const assetIds = collectIds(value.scope.assets, "scope asset", errors);
  collectIds(value.techniquePolicy.techniques, "technique", errors);
  collectIds(value.access.accounts, "account", errors);
  const componentIds = collectIds(value.architecture.components, "architecture component", errors);
  collectIds(value.architecture.trustBoundaries, "trust boundary", errors);
  collectIds(value.architecture.dataFlows, "data flow", errors);
  collectIds(value.ambiguities, "ambiguity", errors);

  validateExecutionPolicies(value, paths, assetIds, errors);

  visitSourceRefs(value, (refs, location) => {
    for (const sourceRef of refs) {
      if (!sourceIds.has(sourceRef)) errors.push(`${location} references unknown source: ${sourceRef}`);
    }
  });

  for (const [index, boundary] of value.architecture.trustBoundaries.entries()) {
    if (!componentIds.has(boundary.from)) errors.push(`/architecture/trustBoundaries/${index}/from references unknown component: ${boundary.from}`);
    if (!componentIds.has(boundary.to)) errors.push(`/architecture/trustBoundaries/${index}/to references unknown component: ${boundary.to}`);
  }
  for (const [index, flow] of value.architecture.dataFlows.entries()) {
    if (!componentIds.has(flow.from)) errors.push(`/architecture/dataFlows/${index}/from references unknown component: ${flow.from}`);
    if (!componentIds.has(flow.to)) errors.push(`/architecture/dataFlows/${index}/to references unknown component: ${flow.to}`);
  }
  if (Date.parse(value.metadata.updatedAt) < Date.parse(value.metadata.createdAt)) {
    errors.push("metadata.updatedAt must not precede metadata.createdAt");
  }
  if (
    value.authorization.validFrom !== null &&
    value.authorization.validUntil !== null &&
    Date.parse(value.authorization.validUntil) <= Date.parse(value.authorization.validFrom)
  ) {
    errors.push("authorization.validUntil must be later than authorization.validFrom");
  }

  if (value.metadata.status !== "ready-to-materialize") return errors;

  for (const question of PROGRAM_PROFILE_QUESTIONS) {
    if (!question.required || !baseQuestionApplies(question, value)) continue;
    const answer = valueAtQuestionPath(value, question.path);
    if (typeof answer === "string" && !meaningfulText(answer)) {
      errors.push(`${question.path} must contain visible text when ready`);
    }
    if (question.path === "architecture.unknowns" && !programProfileQuestionAnswerIsComplete(question, answer)) {
      errors.push(`${question.path} must contain visible text in every supplied entry when ready`);
    }
  }

  for (const sectionId of PROGRAM_PROFILE_SECTION_IDS) {
    if (value.questionnaire.sectionStatus[sectionId] !== "complete") {
      errors.push(`questionnaire section is not complete: ${sectionId}`);
    }
  }
  requiredReadyList(value.sources, "sources", errors);
  requiredReadyList(value.identity.deliverables, "identity.deliverables", errors);
  requiredReadyList(value.identity.successCriteria, "identity.successCriteria", errors);
  requiredReadyList(value.authorization.sourceRefs, "authorization.sourceRefs", errors);
  requiredReadyList(value.authorization.contacts, "authorization.contacts", errors);
  requiredReadyList(value.scope.assets, "scope.assets", errors);
  requiredReadyList(value.executionPolicy.requestedAssistanceModes, "executionPolicy.requestedAssistanceModes", errors);
  requiredReadyList(value.executionPolicy.phases, "executionPolicy.phases", errors);
  requiredReadyList(value.limits.windows, "limits.windows", errors);
  requiredReadyList(value.limits.sourceRefs, "limits.sourceRefs", errors);
  requiredReadyList(value.architecture.sourceRefs, "architecture.sourceRefs", errors);
  requiredReadyList(value.dataEvidence.redactionRules, "dataEvidence.redactionRules", errors);
  requiredReadyList(value.dataEvidence.sourceRefs, "dataEvidence.sourceRefs", errors);
  requiredReadyList(value.stops.escalationContacts, "stops.escalationContacts", errors);
  requiredReadyList(value.stops.cleanup.steps, "stops.cleanup.steps", errors);
  requiredReadyList(value.stops.cleanup.sourceRefs, "stops.cleanup.sourceRefs", errors);
  requiredReadyList(value.reporting.requiredSections, "reporting.requiredSections", errors);
  requiredReadyList(value.reporting.sourceRefs, "reporting.sourceRefs", errors);

  if (!value.authorization.operatorConfirmed) errors.push("authorization must be confirmed by the operator when ready");
  for (const [location, item] of decisionEntries(value)) {
    if (item.disposition === "unknown") errors.push(`${location} remains unknown`);
    if (typeof item.rationale !== "string" || !meaningfulText(item.rationale)) {
      errors.push(`${location} requires a rationale when ready`);
    }
    item.conditions.forEach((condition, index) => {
      if (!meaningfulText(condition)) errors.push(`${location}/conditions/${index} must contain visible text when ready`);
    });
    if (!item.sourceRefs.length) errors.push(`${location} requires sourceRefs when ready`);
  }
  if (!value.scope.assets.some((item) => item.disposition === "allowed")) {
    errors.push("scope.assets must contain at least one allowed selector when ready");
  }
  const referencedAssets = new Set(value.executionPolicy.phases.flatMap((phase) => phase.assetRefs));
  for (const [index, asset] of value.scope.assets.entries()) {
    if (asset.disposition !== "allowed") continue;
    for (const action of PROGRAM_PROFILE_ACTIONS) {
      if (!Object.hasOwn(asset.actionOverrides, action)) {
        errors.push(`/scope/assets/${index}/actionOverrides requires an exact decision for ${action} when ready`);
      } else if (asset.actionOverrides[action].disposition === "unknown") {
        errors.push(`/scope/assets/${index}/actionOverrides/${action} remains unknown`);
      }
    }
    for (const limit of PROGRAM_PROFILE_EXECUTION_LIMITS) {
      if (!Object.hasOwn(asset.limitOverrides, limit)) {
        errors.push(`/scope/assets/${index}/limitOverrides requires an exact ${limit} ceiling when ready`);
      }
    }
    if (!referencedAssets.has(asset.id)) {
      errors.push(`/scope/assets/${index} is allowed but has no execution phase policy`);
    }
  }
  for (const [index, phase] of value.executionPolicy.phases.entries()) {
    if (!phase.sourceRefs.length) errors.push(`/executionPolicy/phases/${index} requires sourceRefs when ready`);
  }
  if (!PROGRAM_PROFILE_ACTIONS.some((id) => value.techniquePolicy.actions[id].disposition === "allowed")) {
    errors.push("techniquePolicy.actions must contain at least one allowed action when ready");
  }
  for (const stopId of PROGRAM_PROFILE_STOP_CONDITIONS) {
    if (!value.stops.conditions[stopId].sourceRefs.length) {
      errors.push(`/stops/conditions/${stopId} requires sourceRefs when ready`);
    }
  }
  const supportingClaims = [
    ...value.authorization.contacts.map((item, index) => [`/authorization/contacts/${index}`, item]),
    ...value.access.accounts.map((item, index) => [`/access/accounts/${index}`, item]),
    ...value.architecture.components.map((item, index) => [`/architecture/components/${index}`, item]),
    ...value.architecture.trustBoundaries.map((item, index) => [`/architecture/trustBoundaries/${index}`, item]),
    ...value.architecture.dataFlows.map((item, index) => [`/architecture/dataFlows/${index}`, item]),
    ...value.stops.escalationContacts.map((item, index) => [`/stops/escalationContacts/${index}`, item]),
    ...value.ambiguities.map((item, index) => [`/ambiguities/${index}`, item])
  ];
  for (const [location, item] of supportingClaims) {
    if (!item.sourceRefs.length) errors.push(`${location} requires sourceRefs when ready`);
  }
  for (const ambiguity of value.ambiguities) {
    if (ambiguity.status === "unresolved") errors.push(`ambiguity remains unresolved: ${ambiguity.id}`);
  }
  if (!value.attestation.answersComplete) errors.push("attestation.answersComplete must be true when ready");
  if (!value.attestation.sourceClaimsReviewed) errors.push("attestation.sourceClaimsReviewed must be true when ready");
  if (!value.attestation.exactScopeReviewed) errors.push("attestation.exactScopeReviewed must be true when ready");
  if (value.attestation.attestedAt === null) errors.push("attestation.attestedAt is required when ready");
  if (value.attestation.attestedRevision !== value.metadata.revision) {
    errors.push("attestation.attestedRevision must equal metadata.revision when ready");
  }
  return errors;
}

function meaningfulStructuredAnswer(value) {
  if (typeof value === "string") return meaningfulText(value);
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value === "boolean") return true;
  if (Array.isArray(value)) return value.length > 0 && value.some(meaningfulStructuredAnswer);
  if (value && typeof value === "object") {
    const entries = Object.values(value);
    return entries.length > 0 && entries.some(meaningfulStructuredAnswer);
  }
  return false;
}

export function programProfileQuestionAnswerIsComplete(question, value) {
  if (question?.path === "architecture.unknowns") {
    return Array.isArray(value) && value.every((entry) => typeof entry === "string" && meaningfulText(entry));
  }
  if (value === undefined) return false;
  if (value === null) return question?.allowNull === true;
  if (typeof value === "string") return meaningfulText(value);
  if (!question?.module) return true;
  if (question?.type === "structured-list") {
    return Array.isArray(value) && value.length > 0 && value.every(meaningfulStructuredAnswer);
  }
  if (Array.isArray(value)) return value.length > 0 && value.every(meaningfulStructuredAnswer);
  if (value && typeof value === "object") return meaningfulStructuredAnswer(value);
  return typeof value === "number" ? Number.isFinite(value) : typeof value === "boolean";
}

function moduleAnswerErrors(moduleId, answers, required = false) {
  const errors = [];
  for (const question of PROGRAM_PROFILE_MODULE_QUESTIONS) {
    const prefix = `modules.${moduleId}.answers.`;
    if (!question.path.startsWith(prefix)) continue;
    const key = question.path.slice(prefix.length);
    if (!Object.hasOwn(answers, key)) {
      if (required && question.required) errors.push(`${question.path} is required when ready`);
      continue;
    }
    const answer = answers[key];
    if (question.type === "structured-list") {
      if (!Array.isArray(answer)) {
        errors.push(`${question.path} must be an array`);
      } else if (required && question.required && answer.length === 0) {
        errors.push(`${question.path} must contain at least one item when ready`);
      } else if (required && question.required) {
        answer.forEach((item, index) => {
          if (!meaningfulStructuredAnswer(item)) {
            errors.push(`${question.path}.${index} must contain only meaningful non-empty values when ready`);
          }
        });
      }
    } else if (question.type === "multiline") {
      if (typeof answer !== "string") {
        errors.push(`${question.path} must be a string`);
      } else if (required && question.required && !meaningfulStructuredAnswer(answer)) {
        errors.push(`${question.path} must contain non-whitespace text when ready`);
      }
    }
  }
  return errors;
}

export function validateProgramProfile(value, options = {}) {
  const paths = options.paths || runtimePaths(options);
  const structural = validateDocument(value, "bug-bounty-program-profile.schema.json", { paths });
  if (!structural.ok) return structural;
  const errors = semanticProfileErrors(value, paths);
  for (const moduleId of PROGRAM_PROFILE_MODULE_IDS) {
    errors.push(...moduleAnswerErrors(moduleId, value.modules[moduleId].answers,
      value.metadata.status === "ready-to-materialize" && value.questionnaire.applicableModules.includes(moduleId)));
  }
  return { ok: errors.length === 0, errors };
}

export function assertValidProgramProfile(value, options = {}) {
  const validation = validateProgramProfile(value, options);
  if (!validation.ok) throw new Error(`bug bounty program profile validation failed: ${validation.errors.join("; ")}`);
  return value;
}

export function validateProgramProfileAnswers(value, options = {}) {
  const paths = options.paths || runtimePaths(options);
  const structural = validateDocument(value, "bug-bounty-program-profile-answers.schema.json", { paths });
  if (!structural.ok) return structural;
  const known = new Set([
    ...PROGRAM_PROFILE_QUESTIONS,
    ...PROGRAM_PROFILE_MODULE_QUESTIONS
  ].map((question) => question.id));
  const errors = Object.keys(value.answers).filter((id) => !known.has(id)).sort()
    .map((id) => `answers contains unknown question id: ${id}`);
  for (const question of PROGRAM_PROFILE_MODULE_QUESTIONS) {
    if (!Object.hasOwn(value.answers, question.id)) continue;
    const answer = value.answers[question.id];
    const prefix = `modules.${question.module}.answers.`;
    if (question.path.startsWith(prefix)) {
      errors.push(...moduleAnswerErrors(question.module, { [question.path.slice(prefix.length)]: answer }));
    } else if (answer?.answers && typeof answer.answers === "object" && !Array.isArray(answer.answers)) {
      errors.push(...moduleAnswerErrors(question.module, answer.answers));
    }
  }
  return { ok: errors.length === 0, errors };
}

function normalizeSourceRefs(value) {
  if (Array.isArray(value)) return value.map(normalizeSourceRefs);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [
    key,
    key === "sourceRefs" && Array.isArray(child)
      ? [...new Set(child)].sort()
      : normalizeSourceRefs(child)
  ]));
}

function sortedById(items) {
  if (!Array.isArray(items)) return items;
  return [...items].sort((left, right) => {
    const leftId = typeof left?.id === "string" ? left.id : "";
    const rightId = typeof right?.id === "string" ? right.id : "";
    return leftId < rightId ? -1 : leftId > rightId ? 1 : 0;
  });
}

function orderedMatrix(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return value;
  if (Object.keys(value).some((key) => !keys.includes(key))) return value;
  return Object.fromEntries(keys.filter((key) => Object.hasOwn(value, key)).map((key) => [key, value[key]]));
}

function orderedKnownList(value, keys) {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || !keys.includes(item))) return value;
  const selected = new Set(value);
  return keys.filter((key) => selected.has(key));
}

export function normalizeProgramProfile(value) {
  const result = normalizeSourceRefs(structuredClone(value));
  if (Array.isArray(result.questionnaire?.applicableModules)) {
    result.questionnaire.applicableModules = orderedKnownList(
      result.questionnaire.applicableModules,
      PROGRAM_PROFILE_MODULE_IDS
    );
  }
  if (Array.isArray(result.sources)) result.sources = sortedById(result.sources);
  if (Array.isArray(result.scope?.assets)) {
    result.scope.assets = sortedById(result.scope.assets).map((asset) => {
      if (!asset || typeof asset !== "object" || Array.isArray(asset)) return asset;
      return {
        ...asset,
        actionOverrides: orderedMatrix(asset.actionOverrides, PROGRAM_PROFILE_ACTIONS),
        limitOverrides: orderedMatrix(asset.limitOverrides, PROGRAM_PROFILE_EXECUTION_LIMITS)
      };
    });
  }
  if (
    result.executionPolicy &&
    Array.isArray(result.executionPolicy.requestedAssistanceModes) &&
    Array.isArray(result.executionPolicy.phases)
  ) {
    result.executionPolicy.requestedAssistanceModes = orderedKnownList(
      result.executionPolicy.requestedAssistanceModes,
      PROGRAM_PROFILE_ASSISTANCE_MODES
    );
    result.executionPolicy.phases = sortedById(result.executionPolicy.phases).map((phase) => {
      if (!phase || typeof phase !== "object" || Array.isArray(phase)) return phase;
      return {
        ...phase,
        assetRefs: Array.isArray(phase.assetRefs) ? [...phase.assetRefs].sort() : phase.assetRefs,
        actions: orderedKnownList(phase.actions, PROGRAM_PROFILE_ACTIONS),
        allowedToolIds: Array.isArray(phase.allowedToolIds) ? [...phase.allowedToolIds].sort() : phase.allowedToolIds,
        deniedToolIds: Array.isArray(phase.deniedToolIds) ? [...phase.deniedToolIds].sort() : phase.deniedToolIds,
        limits: orderedMatrix(phase.limits, PROGRAM_PROFILE_EXECUTION_LIMITS)
      };
    });
  }
  if (Array.isArray(result.techniquePolicy?.techniques)) result.techniquePolicy.techniques = sortedById(result.techniquePolicy.techniques);
  if (Array.isArray(result.access?.accounts)) result.access.accounts = sortedById(result.access.accounts);
  if (Array.isArray(result.architecture?.components)) result.architecture.components = sortedById(result.architecture.components);
  if (Array.isArray(result.architecture?.trustBoundaries)) result.architecture.trustBoundaries = sortedById(result.architecture.trustBoundaries);
  if (Array.isArray(result.architecture?.dataFlows)) result.architecture.dataFlows = sortedById(result.architecture.dataFlows);
  if (Array.isArray(result.ambiguities)) result.ambiguities = sortedById(result.ambiguities);
  if (result.techniquePolicy?.actions) {
    result.techniquePolicy.actions = orderedMatrix(result.techniquePolicy.actions, PROGRAM_PROFILE_ACTIONS);
  }
  if (result.coverage) result.coverage = orderedMatrix(result.coverage, PROGRAM_PROFILE_COVERAGE_DOMAINS);
  if (result.stops?.conditions) {
    result.stops.conditions = orderedMatrix(result.stops.conditions, PROGRAM_PROFILE_STOP_CONDITIONS);
  }
  if (result.modules) result.modules = orderedMatrix(result.modules, PROGRAM_PROFILE_MODULE_IDS);
  return result;
}
