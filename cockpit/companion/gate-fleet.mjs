import crypto from "node:crypto";
import { unavailableExecutionMirror, validateExecutionMirror } from "../execution-mirror.mjs";
import { containsLikelyCredential } from "./contracts.mjs";

const LOCAL_FLEET_VERSION = "gate.local-fleet/v3";
const OBSERVER_VERSION = "gate.observer/v1";
const DEFAULT_OBSERVER_URL = "http://127.0.0.1:4173/api/status";
const DEFAULT_TIMEOUT_MS = 3_500;
const DEFAULT_CACHE_MS = 2_000;
const DEFAULT_FLEET_TTL_MS = 15_000;
const MAX_OBSERVER_BYTES = 2_000_000;
const MAX_COUNT = 1_000_000_000;
const MAX_TOKENS = Number.MAX_SAFE_INTEGER;
const PILOT_TTL_MS = 180_000;

const OBSERVER_ROOT_KEYS = [
  "apiVersion", "at", "state", "counts", "agents", "tasks", "usage", "budget", "telemetry",
  "execution", "workflows", "engagementScan", "offlineAnalysis", "toolRuntimes", "operator", "cases",
  "caseScan", "profileSetups", "profileSetupScan", "engagements", "projects", "upstreams"
];
const CASE_KEYS = [
  "id", "displayName", "status", "binding", "isolation", "runtimeHealth", "state", "counts", "telemetry",
  "usage", "execution", "workflows", "engagementScan", "offlineAnalysis", "activity", "learningCount", "ctfPilot"
];
const PROFILE_KEYS = [
  "id", "displayName", "stage", "readiness", "progress", "blockerCount", "nextSection",
  "recommendationMode", "updatedAt", "freshness"
];
const CASE_SCAN_KEYS = [
  "availability", "discovered", "scanned", "omitted", "invalid", "discoveredAtLeast", "omittedAtLeast",
  "complete", "truncated"
];
const PROFILE_SCAN_KEYS = [...CASE_SCAN_KEYS, "visible", "representedByCases"];

const CASE_STATES = new Set(["queued", "running", "waiting", "blocked", "succeeded", "failed", "cancelled", "unknown", "idle"]);
const CASE_STATUSES = new Set(["ready", "stale", "invalid"]);
const PROFILE_STAGES = new Set(["questionnaire", "operator-review", "ready", "superseded"]);
const PROFILE_READINESS = new Set(["not-ready", "ready"]);
const LANES = new Set([
  "governance", "offline-static", "offline-dynamic", "passive-research", "active-observation",
  "active-testing", "high-impact-controlled", "closure"
]);
const SOURCE_FRESHNESS = new Set(["fresh", "stale", "unknown"]);
const USAGE_AVAILABILITY = new Set(["exact", "estimated", "unavailable"]);
const RUNTIME_REASONS = new Set(["invalid-case", "runtime-observation-failed"]);
const PROFILE_NEXT_SECTIONS = new Set([
  "identity-objectives", "authority-sources", "actions-techniques", "limits-schedule", "scope-assets",
  "accounts-identities", "architecture-data-flows", "workflow-coverage", "data-evidence",
  "stops-escalation-cleanup", "reporting-disclosure", "ambiguities-attestation", "conditional-modules"
]);
const PILOT_REASONS = new Set(["not-case-scoped", "missing", "invalid", "expired", "worker-unavailable"]);
const PILOT_SOLVING_VERDICTS = new Set(["pass", "provisional", "fail", "blocked", "unknown"]);
const PILOT_SOLVING_NOW = new Set(["idle", "intake", "mapping", "enumerating", "exploiting", "validating", "submitting", "complete", "blocked"]);
const PILOT_LEARNING_VERDICTS = new Set(["pass", "provisional", "fail", "blocked", "unknown", "not-applicable"]);
const PILOT_LEARNING_NOW = new Set(["observing", "extracting", "validating", "applying", "checking", "idle", "blocked"]);
const PILOT_COCKPIT_VERDICTS = new Set(["pass", "provisional", "fail", "blocked", "unknown"]);
const PILOT_COCKPIT_NOW = new Set(["collecting", "projecting", "current", "delayed", "blocked"]);
const PILOT_ACTIONS = new Set(["none", "operator", "solver", "platform", "review"]);
const PILOT_DEPTH = new Set(["unavailable", "baseline", "systematic", "deep"]);
const PILOT_INTEGRITY = new Set(["consistent", "degraded"]);
const PILOT_COMPLETION_STATES = new Set(["complete", "incomplete", "unknown"]);
const PILOT_REPRODUCTION = new Set(["confirmed", "not-confirmed", "not-applicable", "unknown"]);
const PILOT_EXTERNAL_ACCEPTANCE = new Set(["accepted", "pending", "rejected", "not-applicable", "unknown"]);
const EVENT_STATUSES = new Set(["queued", "running", "waiting", "blocked", "succeeded", "failed", "cancelled", "unknown"]);
const EVENT_CATEGORIES = new Set(["campaign", "workflow", "execution", "test", "evidence", "learning", "analysis", "tool", "operator", "system"]);
const SELECTION_EPOCH = /^[a-f0-9]{32}$/u;

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, expected) {
  if (!record(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function timestamp(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(value)) return null;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return null;
  const canonical = value.includes(".") ? value : value.replace("Z", ".000Z");
  return new Date(parsed).toISOString() === canonical ? value : null;
}

function count(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_COUNT ? value : null;
}

function tokenCount(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_TOKENS ? value : null;
}

function pilotMetricUnavailable() {
  return Object.freeze({ availability: "unavailable", value: null });
}

function pilotUnavailable(reason = "missing") {
  const axis = () => Object.freeze({ availability: "unavailable", verdict: null, now: null, actionNeeded: null, updatedAt: null });
  return Object.freeze({
    availability: "unavailable",
    reason: PILOT_REASONS.has(reason) ? reason : "invalid",
    observedAt: null,
    validUntil: null,
    solving: Object.freeze({
      ...axis(),
      completion: Object.freeze({ state: null, reproduction: null, externalAcceptance: null }),
      objectives: Object.freeze({ availability: "unavailable", completed: null, total: null }),
      depth: Object.freeze({
        level: "unavailable",
        branchesExplored: pilotMetricUnavailable(),
        techniquesAttempted: pilotMetricUnavailable(),
        deadEndsRetired: pilotMetricUnavailable()
      }),
      efficiency: Object.freeze(Object.fromEntries(
        ["elapsedSeconds", "activeSeconds", "tokens", "toolRuns", "requests", "retries"]
          .map((key) => [key, pilotMetricUnavailable()])
      ))
    }),
    learning: Object.freeze({
      ...axis(),
      stages: Object.freeze(Object.fromEntries(
        ["observations", "candidates", "validated", "applied", "transferred", "regressed"]
          .map((key) => [key, pilotMetricUnavailable()])
      ))
    }),
    cockpit: Object.freeze({
      ...axis(),
      signals: Object.freeze({ availability: "unavailable", available: null, total: null }),
      updatesPublished: pilotMetricUnavailable(),
      updatesMissed: pilotMetricUnavailable()
    }),
    integrity: Object.freeze({
      availability: "unavailable",
      status: null,
      checks: Object.freeze({ availability: "unavailable", available: null, total: null }),
      issues: pilotMetricUnavailable(),
      checkedAt: null
    })
  });
}

function validatePilotMetric(value) {
  if (!exactKeys(value, ["availability", "value"])) return null;
  if (value.availability === "unavailable" && value.value === null) return pilotMetricUnavailable();
  return value.availability === "available" && tokenCount(value.value) !== null
    ? Object.freeze({ availability: "available", value: value.value })
    : null;
}

function pilotLearningStagesAreConsistent(stages) {
  const value = key => stages[key].availability === "available" ? stages[key].value : null;
  const exceeds = (left, right) => left !== null && right !== null && left > right;
  return !exceeds(value("candidates"), value("observations"))
    && !exceeds(value("validated"), value("candidates"))
    && !exceeds(value("applied"), value("validated"))
    && !exceeds(value("transferred"), value("applied"))
    && !exceeds(value("regressed"), value("applied"));
}

function validatePilotCoverage(value) {
  if (!exactKeys(value, ["availability", "available", "total"])) return null;
  if (value.availability === "unavailable" && value.available === null && value.total === null) {
    return Object.freeze({ availability: "unavailable", available: null, total: null });
  }
  return value.availability === "available" && count(value.available) !== null && count(value.total) !== null
    && value.total > 0 && value.available <= value.total
    ? Object.freeze({ ...value })
    : null;
}

function validatePilotAxis(value, verdicts, stages) {
  if (!record(value) || !new Set(["available", "unavailable"]).has(value.availability)) return null;
  if (value.availability === "unavailable") {
    return value.verdict === null && value.now === null && value.actionNeeded === null && value.updatedAt === null
      ? Object.freeze({ availability: "unavailable", verdict: null, now: null, actionNeeded: null, updatedAt: null })
      : null;
  }
  return verdicts.has(value.verdict) && stages.has(value.now) && PILOT_ACTIONS.has(value.actionNeeded) && timestamp(value.updatedAt)
    ? Object.freeze({ availability: "available", verdict: value.verdict, now: value.now, actionNeeded: value.actionNeeded, updatedAt: value.updatedAt })
    : null;
}

function validatePilot(value) {
  if (!record(value) || !exactKeys(value, ["availability", "reason", "observedAt", "validUntil", "solving", "learning", "cockpit", "integrity"])) return null;
  if (value.availability === "unavailable") {
    if (!PILOT_REASONS.has(value.reason) || value.observedAt !== null || value.validUntil !== null) return null;
  } else if (value.availability !== "available" || value.reason !== null
      || !timestamp(value.observedAt) || !timestamp(value.validUntil)
      || Date.parse(value.validUntil) <= Date.parse(value.observedAt)
      || Date.parse(value.validUntil) - Date.parse(value.observedAt) > PILOT_TTL_MS) return null;
  if (!exactKeys(value.solving, ["availability", "verdict", "now", "actionNeeded", "updatedAt", "completion", "objectives", "depth", "efficiency"]) ||
      !exactKeys(value.learning, ["availability", "verdict", "now", "actionNeeded", "updatedAt", "stages"]) ||
      !exactKeys(value.cockpit, ["availability", "verdict", "now", "actionNeeded", "updatedAt", "signals", "updatesPublished", "updatesMissed"]) ||
      !exactKeys(value.integrity, ["availability", "status", "checks", "issues", "checkedAt"])) return null;
  const solving = validatePilotAxis(value.solving, PILOT_SOLVING_VERDICTS, PILOT_SOLVING_NOW);
  const learning = validatePilotAxis(value.learning, PILOT_LEARNING_VERDICTS, PILOT_LEARNING_NOW);
  const cockpit = validatePilotAxis(value.cockpit, PILOT_COCKPIT_VERDICTS, PILOT_COCKPIT_NOW);
  const objectives = value.solving.objectives;
  const completion = value.solving.completion;
  if (!solving || !learning || !cockpit || !exactKeys(objectives, ["availability", "completed", "total"])
      || !exactKeys(completion, ["state", "reproduction", "externalAcceptance"])) return null;
  const completionProjection = solving.availability === "unavailable"
    ? completion.state === null && completion.reproduction === null && completion.externalAcceptance === null
      ? Object.freeze({ ...completion }) : null
    : PILOT_COMPLETION_STATES.has(completion.state) && PILOT_REPRODUCTION.has(completion.reproduction)
      && PILOT_EXTERNAL_ACCEPTANCE.has(completion.externalAcceptance) ? Object.freeze({ ...completion }) : null;
  const objectiveProjection = objectives.availability === "unavailable" && objectives.completed === null && objectives.total === null
    ? Object.freeze({ ...objectives })
    : objectives.availability === "available" && count(objectives.completed) !== null && count(objectives.total) !== null
      && objectives.total > 0 && objectives.completed <= objectives.total ? Object.freeze({ ...objectives }) : null;
  if (!completionProjection || !objectiveProjection || !exactKeys(value.solving.depth, ["level", "branchesExplored", "techniquesAttempted", "deadEndsRetired"]) ||
      !PILOT_DEPTH.has(value.solving.depth.level) ||
      !exactKeys(value.solving.efficiency, ["elapsedSeconds", "activeSeconds", "tokens", "toolRuns", "requests", "retries"]) ||
      !exactKeys(value.learning.stages, ["observations", "candidates", "validated", "applied", "transferred", "regressed"])) return null;
  const depth = {};
  for (const key of ["branchesExplored", "techniquesAttempted", "deadEndsRetired"]) {
    depth[key] = validatePilotMetric(value.solving.depth[key]);
    if (!depth[key]) return null;
  }
  const efficiency = {};
  for (const key of ["elapsedSeconds", "activeSeconds", "tokens", "toolRuns", "requests", "retries"]) {
    efficiency[key] = validatePilotMetric(value.solving.efficiency[key]);
    if (!efficiency[key]) return null;
  }
  const learningStages = {};
  for (const key of ["observations", "candidates", "validated", "applied", "transferred", "regressed"]) {
    learningStages[key] = validatePilotMetric(value.learning.stages[key]);
    if (!learningStages[key]) return null;
  }
  if (!pilotLearningStagesAreConsistent(learningStages)) return null;
  const signals = validatePilotCoverage(value.cockpit.signals);
  const updatesPublished = validatePilotMetric(value.cockpit.updatesPublished);
  const updatesMissed = validatePilotMetric(value.cockpit.updatesMissed);
  const checks = validatePilotCoverage(value.integrity.checks);
  const issues = validatePilotMetric(value.integrity.issues);
  if (!signals || !updatesPublished || !updatesMissed || !checks || !issues) return null;
  let integrity;
  if (value.integrity.availability === "unavailable") {
    if (value.integrity.status !== null || value.integrity.checkedAt !== null) return null;
    integrity = Object.freeze({ availability: "unavailable", status: null, checks, issues, checkedAt: null });
  } else if (value.integrity.availability === "available" && PILOT_INTEGRITY.has(value.integrity.status) && timestamp(value.integrity.checkedAt)) {
    integrity = Object.freeze({ ...value.integrity, checks, issues });
  } else return null;
  const observedMs = value.observedAt === null ? null : Date.parse(value.observedAt);
  const axisTimes = [solving, learning, cockpit]
    .filter((axis) => axis.availability === "available")
    .map((axis) => Date.parse(axis.updatedAt));
  if (value.availability === "unavailable") {
    if (solving.availability !== "unavailable" || learning.availability !== "unavailable"
        || cockpit.availability !== "unavailable" || integrity.availability !== "unavailable") return null;
  } else if (axisTimes.some((at) => at > observedMs)
      || integrity.availability === "available" && Date.parse(integrity.checkedAt) > observedMs) return null;
  const objectiveComplete = objectiveProjection.availability === "available"
    && objectiveProjection.completed === objectiveProjection.total;
  if (solving.verdict === "pass" && !(solving.now === "complete" && solving.actionNeeded === "none"
      && completionProjection.state === "complete" && objectiveComplete
      && new Set(["confirmed", "not-applicable"]).has(completionProjection.reproduction)
      && new Set(["accepted", "not-applicable"]).has(completionProjection.externalAcceptance))) return null;
  if (learning.verdict === "pass" && !(learningStages.transferred.availability === "available"
      && learningStages.transferred.value > 0)) return null;
  if (cockpit.verdict === "pass" && !(cockpit.now === "current" && cockpit.actionNeeded === "none"
      && signals.availability === "available" && signals.available === signals.total
      && updatesMissed.availability === "available" && updatesMissed.value === 0)) return null;
  return Object.freeze({
    availability: value.availability,
    reason: value.reason,
    observedAt: value.observedAt,
    validUntil: value.validUntil,
    solving: Object.freeze({ ...solving, completion: completionProjection, objectives: objectiveProjection, depth: Object.freeze({ level: value.solving.depth.level, ...depth }), efficiency: Object.freeze(efficiency) }),
    learning: Object.freeze({ ...learning, stages: Object.freeze(learningStages) }),
    cockpit: Object.freeze({ ...cockpit, signals, updatesPublished, updatesMissed }),
    integrity
  });
}

function latestCaseEvent(value) {
  if (!Array.isArray(value) || value.length > 20) return null;
  let latest = null;
  for (const item of value) {
    if (!record(item) || !timestamp(item.at) || typeof item.kind !== "string"
        || !/^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$/u.test(item.kind)
        || !EVENT_STATUSES.has(item.status)) continue;
    const prefix = item.kind.split(".", 1)[0];
    const candidate = Object.freeze({
      availability: "available",
      category: EVENT_CATEGORIES.has(prefix) ? prefix : "other",
      status: item.status,
      at: item.at
    });
    if (!latest || Date.parse(candidate.at) > Date.parse(latest.at)) latest = candidate;
  }
  return latest || Object.freeze({ availability: "unavailable", category: null, status: null, at: null });
}

function metric(value, precision) {
  return Object.freeze({ value: precision === "unavailable" ? null : value, precision });
}

function unavailableMetric() {
  return metric(null, "unavailable");
}

function unavailableCost() {
  return Object.freeze({ availability: "unavailable", amountMicros: null, unit: null });
}

function projectHostTokens(value) {
  const usage = record(value) ? value : {};
  const availability = USAGE_AVAILABILITY.has(usage.availability) ? usage.availability : "unavailable";
  const counters = {
    input: tokenCount(usage.inputTokens),
    cachedInput: tokenCount(usage.cachedInputTokens),
    output: tokenCount(usage.outputTokens),
    total: tokenCount(usage.totalTokens)
  };
  const usable = availability !== "unavailable" && Object.values(counters).some((count) => count !== null);
  return Object.freeze({
    availability: usable ? availability : "unavailable",
    input: usable ? counters.input : null,
    cachedInput: usable ? counters.cachedInput : null,
    output: usable ? counters.output : null,
    total: usable ? counters.total : null,
    cost: unavailableCost()
  });
}

function unavailableScan(profile = false) {
  return Object.freeze({
    availability: "unavailable",
    discovered: null,
    scanned: null,
    omitted: null,
    invalid: null,
    discoveredAtLeast: false,
    omittedAtLeast: false,
    complete: false,
    truncated: true,
    ...(profile ? { visible: null, representedByCases: null } : {})
  });
}

function validateScan(value, profile = false) {
  if (!exactKeys(value, profile ? PROFILE_SCAN_KEYS : CASE_SCAN_KEYS)) return null;
  if (!new Set(["available", "unavailable"]).has(value.availability)
      || typeof value.complete !== "boolean" || typeof value.truncated !== "boolean"
      || typeof value.discoveredAtLeast !== "boolean" || typeof value.omittedAtLeast !== "boolean") return null;
  const numericKeys = ["discovered", "scanned", "omitted", "invalid", ...(profile ? ["visible", "representedByCases"] : [])];
  if (value.availability === "unavailable") {
    const unavailableNumericKeys = profile
      ? ["discovered", "scanned", "omitted", "invalid", "representedByCases"]
      : numericKeys;
    if (unavailableNumericKeys.some((key) => value[key] !== null)
        || profile && count(value.visible) === null
        || value.discoveredAtLeast !== false || value.omittedAtLeast !== false
        || value.complete !== false || value.truncated !== true) return null;
    return unavailableScan(profile);
  }
  if (numericKeys.some((key) => count(value[key]) === null)) return null;
  if (value.discovered !== value.scanned + value.omitted || value.invalid > value.scanned) return null;
  if (profile && value.visible + value.representedByCases + value.invalid !== value.scanned) return null;
  if (value.complete && (value.truncated || value.discoveredAtLeast || value.omittedAtLeast || value.omitted !== 0 || value.invalid !== 0)) return null;
  return Object.freeze({
    availability: value.availability,
    discovered: value.discovered,
    scanned: value.scanned,
    omitted: value.omitted,
    invalid: value.invalid,
    discoveredAtLeast: value.discoveredAtLeast,
    omittedAtLeast: value.omittedAtLeast,
    complete: value.complete,
    truncated: value.truncated,
    ...(profile ? { visible: value.visible, representedByCases: value.representedByCases } : {})
  });
}

function scanPrecision(scan, visible, profile = false) {
  if (scan.availability !== "available") return "unavailable";
  const visibleCoverage = profile
    ? scan.scanned === visible + scan.representedByCases
    : scan.scanned === visible;
  return scan.complete && !scan.truncated && scan.discoveredAtLeast === false && scan.omittedAtLeast === false
    && scan.discovered === scan.scanned && scan.omitted === 0 && scan.invalid === 0 && visibleCoverage
    ? "exact"
    : "lower-bound";
}

function validateCase(value, options = {}) {
  const caseKeysValid = exactKeys(value, CASE_KEYS) || exactKeys(value, CASE_KEYS.filter((key) => key !== "ctfPilot"));
  if (!caseKeysValid || typeof value.id !== "string" || !/^case_[a-f0-9]{16}$/u.test(value.id)
      || !CASE_STATUSES.has(value.status) || !CASE_STATES.has(value.state)) return null;
  if (!exactKeys(value.runtimeHealth, ["status", "reason"])
      || !new Set(["available", "unavailable"]).has(value.runtimeHealth.status)
      || !(value.runtimeHealth.reason === null || RUNTIME_REASONS.has(value.runtimeHealth.reason))
      || value.runtimeHealth.status === "available" && value.runtimeHealth.reason !== null
      || value.runtimeHealth.status === "unavailable" && value.runtimeHealth.reason === null
      || value.status === "invalid" && (value.runtimeHealth.status !== "unavailable" || value.state !== "blocked")) return null;
  if (!exactKeys(value.telemetry, ["freshness", "lastActivityAt", "ageSeconds"])
      || !SOURCE_FRESHNESS.has(value.telemetry.freshness)
      || !(value.telemetry.lastActivityAt === null || timestamp(value.telemetry.lastActivityAt))
      || !(value.telemetry.ageSeconds === null || count(value.telemetry.ageSeconds) !== null)) return null;
  if (!exactKeys(value.usage, ["availability", "totalTokens"]) || !USAGE_AVAILABILITY.has(value.usage.availability)) return null;
  if (value.usage.availability === "unavailable"
    ? value.usage.totalTokens !== null
    : !(value.usage.totalTokens === null || tokenCount(value.usage.totalTokens) !== null)) return null;
  if (!record(value.execution) || !record(value.offlineAnalysis)) return null;
  const sourceMirror = validateExecutionMirror(value.execution.mirror, { isUnsafeText: containsLikelyCredential });
  if (!sourceMirror) return null;
  const executionRunning = value.execution.runningCount === null ? null : count(value.execution.runningCount);
  const analysisRunning = value.offlineAnalysis.runningCount === null ? null : count(value.offlineAnalysis.runningCount);
  const workflowActive = value.workflows?.counts?.active === null ? null : count(value.workflows?.counts?.active);
  if (value.execution.runningCount !== null && executionRunning === null
      || value.offlineAnalysis.runningCount !== null && analysisRunning === null || !record(value.workflows)
      || !record(value.workflows.counts) || !record(value.workflows.scan)
      || value.workflows.counts.active !== null && workflowActive === null
      || typeof value.workflows.scan.complete !== "boolean"
      || typeof value.workflows.scan.truncated !== "boolean" || !Array.isArray(value.workflows.instances)
      || value.workflows.instances.length > 12) return null;
  if (value.runtimeHealth.status === "unavailable" && (value.usage.availability !== "unavailable"
      || executionRunning !== null || analysisRunning !== null || workflowActive !== null)) return null;
  const lanes = new Set();
  for (const instance of value.workflows.instances) {
    if (!record(instance) || !(instance.activePhase === null || record(instance.activePhase))) return null;
    if (instance.activePhase !== null) {
      if (!LANES.has(instance.activePhase.lane)) return null;
      lanes.add(instance.activePhase.lane);
    }
  }
  const ctfPilot = value.ctfPilot === undefined ? pilotUnavailable("missing") : validatePilot(value.ctfPilot);
  const latestEvent = latestCaseEvent(value.activity);
  if (!ctfPilot || !latestEvent) return null;
  return Object.freeze({
    sourceId: value.id,
    sourceStatus: value.status,
    runtimeAvailable: value.runtimeHealth.status === "available",
    state: value.state,
    freshness: value.telemetry.freshness === "fresh" ? "current" : value.telemetry.freshness === "stale" ? "delayed" : "unknown",
    usage: Object.freeze({
      availability: value.usage.totalTokens === null ? "unavailable" : value.usage.availability,
      total: value.usage.totalTokens
    }),
    executionRunning,
    workflowActive,
    workflowComplete: value.workflows.scan.complete === true && value.workflows.scan.truncated === false,
    analysisRunning,
    stage: lanes.size === 1 ? [...lanes][0] : lanes.size > 1 ? "multiple" : value.state === "idle" ? "idle" : "unknown",
    mirror: value.runtimeHealth.status === "unavailable"
      ? unavailableExecutionMirror("source-unavailable")
      : options.includeExecutionMirror === true ? sourceMirror : unavailableExecutionMirror("disabled"),
    ctfPilot,
    latestEvent
  });
}

function validateProfile(value) {
  if (!exactKeys(value, PROFILE_KEYS) || typeof value.id !== "string" || !/^program_[a-f0-9]{16}$/u.test(value.id)
      || value.displayName !== null || !PROFILE_STAGES.has(value.stage) || !PROFILE_READINESS.has(value.readiness)
      || !exactKeys(value.progress, ["answered", "total"]) || count(value.progress.answered) === null
      || count(value.progress.total) === null || value.progress.answered > value.progress.total
      || count(value.blockerCount) === null || !(value.recommendationMode === null
        || new Set(["policy", "proposal", "mixed"]).has(value.recommendationMode))
      || !(value.nextSection === null || PROFILE_NEXT_SECTIONS.has(value.nextSection))
      || !timestamp(value.updatedAt) || !new Set(["fresh", "stale"]).has(value.freshness)) return null;
  const complete = value.progress.total > 0 && value.progress.answered === value.progress.total;
  const consistent = value.stage === "questionnaire"
    ? value.readiness === "not-ready" && value.progress.answered < value.progress.total
      && value.blockerCount > 0 && value.nextSection !== null
    : value.stage === "operator-review"
      ? value.readiness === "not-ready" && complete && value.blockerCount > 0 && value.nextSection === null
      : value.stage === "ready"
        ? value.readiness === "ready" && complete && value.blockerCount === 0 && value.nextSection === null
        : value.readiness === "not-ready" && value.nextSection === null;
  if (!consistent) return null;
  return Object.freeze({
    sourceId: value.id,
    stage: value.stage,
    readiness: value.readiness,
    answered: value.progress.answered,
    total: value.progress.total,
    blockerCount: value.blockerCount,
    freshness: value.freshness === "fresh" ? "current" : "delayed"
  });
}

function attentionForCase(item) {
  if (item.sourceStatus !== "ready" || !item.runtimeAvailable || ["waiting", "blocked", "failed"].includes(item.state)) return "response-needed";
  if (item.freshness !== "current" || ["unknown", "cancelled"].includes(item.state)) return "watch";
  return "steady";
}

function attentionForProfile(item) {
  if (item.blockerCount > 0 || item.stage === "operator-review") return "response-needed";
  if (item.freshness !== "current" || item.stage === "superseded") return "watch";
  return "steady";
}

function precisionForCaseMetric(item, value, fleetPrecision, workflow = false) {
  if (!item.runtimeAvailable || value === null) return "unavailable";
  if (fleetPrecision !== "exact" || (workflow && !item.workflowComplete)) return "lower-bound";
  return "exact";
}

function caseCampaign(item, alias, fleetPrecision, receivedTime) {
  const pilot = item.ctfPilot.availability === "available"
    && receivedTime >= Date.parse(item.ctfPilot.validUntil)
    ? pilotUnavailable("expired")
    : item.ctfPilot;
  return Object.freeze({
    alias,
    kind: "case",
    stage: item.stage,
    state: item.state,
    progress: null,
    attention: attentionForCase(item),
    freshness: item.freshness,
    work: Object.freeze({
      runningExecutions: metric(item.executionRunning, precisionForCaseMetric(item, item.executionRunning, fleetPrecision)),
      activeWorkflows: metric(item.workflowActive, precisionForCaseMetric(item, item.workflowActive, fleetPrecision, true)),
      runningAnalyses: metric(item.analysisRunning, precisionForCaseMetric(item, item.analysisRunning, fleetPrecision)),
      setupBlockers: unavailableMetric()
    }),
    tokens: Object.freeze({ availability: item.usage.availability, total: item.usage.total }),
    mirror: item.mirror,
    pilot,
    latestEvent: item.latestEvent
  });
}

function profileCampaign(item, alias, profilePrecision) {
  const percent = item.total > 0 ? Math.round(item.answered / item.total * 100) : null;
  return Object.freeze({
    alias,
    kind: "profile",
    stage: `profile-${item.stage}`,
    state: item.stage === "ready" ? "idle" : item.stage === "superseded" ? "cancelled" : "waiting",
    progress: Object.freeze({ completed: item.answered, total: item.total, percent }),
    attention: attentionForProfile(item),
    freshness: item.freshness,
    work: Object.freeze({
      runningExecutions: unavailableMetric(),
      activeWorkflows: unavailableMetric(),
      runningAnalyses: unavailableMetric(),
      setupBlockers: metric(item.blockerCount, profilePrecision)
    }),
    tokens: Object.freeze({ availability: "unavailable", total: null }),
    mirror: unavailableExecutionMirror("not-applicable"),
    pilot: pilotUnavailable("not-case-scoped"),
    latestEvent: Object.freeze({ availability: "unavailable", category: null, status: null, at: null })
  });
}

function addMetrics(campaigns, field, overallPrecision) {
  const cases = campaigns.filter((item) => item.kind === "case");
  const available = cases.map((item) => item.work[field]).filter((item) => item.precision !== "unavailable");
  if (overallPrecision === "unavailable" || available.length === 0 && cases.length > 0) return unavailableMetric();
  const value = available.reduce((sum, item) => sum + item.value, 0);
  const exact = overallPrecision === "exact" && available.length === cases.length
    && available.every((item) => item.precision === "exact");
  return metric(value, exact ? "exact" : "lower-bound");
}

function aggregateBlockers(campaigns, casePrecision, profilePrecision) {
  const parts = [];
  if (casePrecision !== "unavailable") {
    parts.push(metric(
      campaigns.filter((item) => item.kind === "case" && item.state === "blocked").length,
      casePrecision
    ));
  }
  if (profilePrecision !== "unavailable") {
    parts.push(metric(
      campaigns.filter((item) => item.kind === "profile")
        .reduce((sum, item) => sum + item.work.setupBlockers.value, 0),
      profilePrecision
    ));
  }
  if (parts.length === 0) return unavailableMetric();
  return metric(
    parts.reduce((sum, item) => sum + item.value, 0),
    parts.length === 2 && parts.every((item) => item.precision === "exact") ? "exact" : "lower-bound"
  );
}

function aggregateCampaignTokens(cases, casePrecision) {
  if (casePrecision === "unavailable") return Object.freeze({ availability: "unavailable", total: null });
  if (cases.length === 0) return Object.freeze({ availability: "unavailable", total: null });
  const known = cases.filter((item) => item.usage.availability !== "unavailable" && item.usage.total !== null);
  if (known.length === 0) return Object.freeze({ availability: "unavailable", total: null });
  const total = known.reduce((sum, item) => sum + item.usage.total, 0);
  if (casePrecision !== "exact" || known.length !== cases.length || cases.some((item) => !item.runtimeAvailable)) {
    return Object.freeze({ availability: "partial", total });
  }
  return Object.freeze({
    availability: known.some((item) => item.usage.availability === "estimated") ? "estimated" : "exact",
    total
  });
}

function unavailableProjection(receivedAt, revision, selectionEpoch = crypto.randomBytes(16).toString("hex")) {
  if (!SELECTION_EPOCH.test(selectionEpoch)) throw new Error("invalid fleet selection epoch");
  const validUntil = new Date(Date.parse(receivedAt) + DEFAULT_FLEET_TTL_MS).toISOString();
  return Object.freeze({
    apiVersion: LOCAL_FLEET_VERSION,
    revision,
    selectionEpoch,
    observedAt: null,
    receivedAt,
    validUntil,
    connection: "unavailable",
    sourceFreshness: "unavailable",
    coverage: Object.freeze({ state: "unavailable", cases: unavailableScan(), profiles: unavailableScan(true) }),
    summary: Object.freeze({
      campaigns: unavailableMetric(), active: unavailableMetric(), waiting: unavailableMetric(), attention: unavailableMetric(),
      profileAnswers: Object.freeze({ answered: null, total: null, precision: "unavailable" }),
      runningExecutions: unavailableMetric(), activeWorkflows: unavailableMetric(), runningAnalyses: unavailableMetric(),
      setupBlockers: unavailableMetric(), blockers: unavailableMetric(),
      campaignTokens: Object.freeze({ availability: "unavailable", total: null }),
      hostTokens: projectHostTokens(null)
    }),
    campaigns: Object.freeze([])
  });
}

function aliasFor(aliases, sourceId) {
  if (!aliases.has(sourceId)) {
    const used = new Set(aliases.values());
    let next = 1;
    while (used.has(next) && next <= 64) next += 1;
    if (next > 64) throw new Error("too many GATE campaign aliases");
    aliases.set(sourceId, next);
  }
  return `Campaign ${aliases.get(sourceId)}`;
}

function aliasBindingSignature(aliases) {
  return [...aliases.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([sourceId, number]) => `${sourceId}:${number}`)
    .join("|");
}

export function projectGateObserverStatus(value, options = {}) {
  const receivedAt = options.receivedAt instanceof Date ? options.receivedAt : new Date(options.receivedAt || Date.now());
  const revision = options.revision ?? 1;
  const aliases = options.aliases || new Map();
  const selectionEpoch = options.selectionEpoch ?? crypto.randomBytes(16).toString("hex");
  if (!Number.isSafeInteger(revision) || revision < 1 || !(aliases instanceof Map)
      || !(options.includeExecutionMirror === undefined || typeof options.includeExecutionMirror === "boolean")
      || !SELECTION_EPOCH.test(selectionEpoch)
      || !(exactKeys(value, OBSERVER_ROOT_KEYS) || exactKeys(value, [...OBSERVER_ROOT_KEYS, "ctfPilot"]))
      || value.apiVersion !== OBSERVER_VERSION || !timestamp(value.at) || !CASE_STATES.has(value.state)
      || !Array.isArray(value.cases) || value.cases.length > 32
      || !Array.isArray(value.profileSetups) || value.profileSetups.length > 32) {
    throw new Error("invalid GATE observer status");
  }
  const sourceTime = Date.parse(value.at);
  if (sourceTime > receivedAt.getTime() + 300_000) throw new Error("invalid GATE observer timestamp");
  const caseScan = validateScan(value.caseScan, false);
  const profileScan = validateScan(value.profileSetupScan, true);
  if (!caseScan || !profileScan) throw new Error("invalid GATE observer coverage");
  const sourceCases = value.cases.map((item) => validateCase(item, {
    includeExecutionMirror: options.includeExecutionMirror === true
  }));
  const sourceProfiles = value.profileSetups.map(validateProfile);
  if (sourceCases.some((item) => !item) || sourceProfiles.some((item) => !item)) throw new Error("invalid GATE observer campaign");
  if (sourceCases.some((item) => item.ctfPilot.availability === "available"
      && Date.parse(item.ctfPilot.observedAt) > sourceTime)) throw new Error("invalid GATE observer campaign timestamp");
  if (sourceCases.some((item) => item.latestEvent.availability === "available"
      && Date.parse(item.latestEvent.at) > sourceTime)) throw new Error("invalid GATE observer event timestamp");

  const visibleCases = caseScan.availability === "available" ? sourceCases : [];
  const visibleProfiles = profileScan.availability === "available" ? sourceProfiles : [];
  if (caseScan.availability === "available" && visibleCases.length > caseScan.scanned
      || profileScan.availability === "available" && profileScan.visible !== visibleProfiles.length
      || profileScan.availability === "available" && profileScan.representedByCases > sourceCases.length) {
    throw new Error("contradictory GATE observer coverage");
  }
  const casePrecision = scanPrecision(caseScan, visibleCases.length, false);
  const profilePrecision = scanPrecision(profileScan, visibleProfiles.length, true);
  if ((caseScan.complete && casePrecision !== "exact") || (profileScan.complete && profilePrecision !== "exact")) {
    throw new Error("contradictory GATE observer coverage");
  }
  const currentSourceIds = new Set([
    ...visibleCases.map((item) => `case:${item.sourceId}`),
    ...visibleProfiles.map((item) => `profile:${item.sourceId}`)
  ]);
  if (currentSourceIds.size !== visibleCases.length + visibleProfiles.length) {
    throw new Error("duplicate GATE observer campaign");
  }
  for (const sourceId of aliases.keys()) if (!currentSourceIds.has(sourceId)) aliases.delete(sourceId);
  const retainedAliases = new Set();
  for (const [sourceId, number] of aliases) {
    if (!Number.isSafeInteger(number) || number < 1 || number > 64 || retainedAliases.has(number)) aliases.delete(sourceId);
    else retainedAliases.add(number);
  }
  const allRuntimesAvailable = visibleCases.every((item) => item.runtimeAvailable);
  const coverageState = casePrecision === "unavailable" || profilePrecision === "unavailable"
    ? "unavailable"
    : casePrecision === "exact" && profilePrecision === "exact" && allRuntimesAvailable
      ? "exact"
      : "lower-bound";
  const campaigns = [
    ...visibleCases.map((item) => caseCampaign(item, aliasFor(aliases, `case:${item.sourceId}`), casePrecision, receivedAt.getTime())),
    ...visibleProfiles.map((item) => profileCampaign(item, aliasFor(aliases, `profile:${item.sourceId}`), profilePrecision))
  ];
  const aggregatePrecision = coverageState;
  const profileAnswered = visibleProfiles.reduce((sum, item) => sum + item.answered, 0);
  const profileTotal = visibleProfiles.reduce((sum, item) => sum + item.total, 0);
  const precisionCount = (predicate) => aggregatePrecision === "unavailable"
    ? unavailableMetric()
    : metric(campaigns.filter(predicate).length, aggregatePrecision);
  const profileAnswers = profilePrecision === "unavailable"
    ? Object.freeze({ answered: null, total: null, precision: "unavailable" })
    : Object.freeze({ answered: profileAnswered, total: profileTotal, precision: profilePrecision });
  const sourceAge = Math.max(0, receivedAt.getTime() - sourceTime);
  const fleetValidUntil = campaigns.reduce((deadline, campaign) => campaign.pilot.availability === "available"
    ? Math.min(deadline, Date.parse(campaign.pilot.validUntil))
    : deadline, receivedAt.getTime() + DEFAULT_FLEET_TTL_MS);
  return Object.freeze({
    apiVersion: LOCAL_FLEET_VERSION,
    revision,
    selectionEpoch,
    observedAt: value.at,
    receivedAt: receivedAt.toISOString(),
    validUntil: new Date(fleetValidUntil).toISOString(),
    connection: "connected",
    sourceFreshness: sourceAge <= 15_000 ? "current" : "delayed",
    coverage: Object.freeze({ state: coverageState, cases: caseScan, profiles: profileScan }),
    summary: Object.freeze({
      campaigns: precisionCount(() => true),
      active: precisionCount((item) => ["queued", "running", "waiting", "blocked"].includes(item.state)),
      waiting: precisionCount((item) => item.state === "waiting"),
      attention: precisionCount((item) => item.attention === "response-needed"),
      profileAnswers,
      runningExecutions: addMetrics(campaigns, "runningExecutions", casePrecision),
      activeWorkflows: addMetrics(campaigns, "activeWorkflows", casePrecision),
      runningAnalyses: addMetrics(campaigns, "runningAnalyses", casePrecision),
      setupBlockers: profilePrecision === "unavailable"
        ? unavailableMetric()
        : metric(visibleProfiles.reduce((sum, item) => sum + item.blockerCount, 0), profilePrecision),
      blockers: aggregateBlockers(campaigns, casePrecision, profilePrecision),
      campaignTokens: aggregateCampaignTokens(visibleCases, casePrecision),
      hostTokens: projectHostTokens(value.usage)
    }),
    campaigns: Object.freeze(campaigns)
  });
}

export function normalizeGateObserverUrl(value = DEFAULT_OBSERVER_URL) {
  if (typeof value !== "string" || value.includes("?") || value.includes("#")) {
    throw new Error("GATE observer URL must be an exact HTTP loopback /api/status endpoint");
  }
  let parsed;
  try { parsed = new URL(value); } catch { throw new Error("GATE observer URL is invalid"); }
  if (parsed.protocol !== "http:" || !new Set(["127.0.0.1", "::1", "[::1]"]).has(parsed.hostname)
      || parsed.port === "0" || parsed.username || parsed.password || parsed.pathname !== "/api/status" || parsed.search || parsed.hash) {
    throw new Error("GATE observer URL must be an exact HTTP loopback /api/status endpoint");
  }
  return parsed.href;
}

async function boundedJson(response, maximumBytes) {
  if (!response || response.ok !== true || response.redirected === true) throw new Error("GATE observer unavailable");
  const contentType = response.headers?.get?.("content-type") || "";
  if (!/^application\/json(?:\s*;|$)/iu.test(contentType)) throw new Error("GATE observer returned an invalid content type");
  const declared = Number(response.headers?.get?.("content-length"));
  if (Number.isFinite(declared) && declared > maximumBytes) throw new Error("GATE observer response is too large");
  if (!response.body?.getReader) throw new Error("GATE observer response body is unavailable");
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maximumBytes) {
      await reader.cancel().catch(() => {});
      throw new Error("GATE observer response is too large");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  let parsed;
  try { parsed = JSON.parse(new TextDecoder().decode(bytes)); } catch { throw new Error("GATE observer returned invalid JSON"); }
  if (!record(parsed)) throw new Error("GATE observer returned invalid JSON");
  return parsed;
}

export function createGateFleetProvider(options = {}) {
  const observerUrl = normalizeGateObserverUrl(options.observerUrl || DEFAULT_OBSERVER_URL);
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== "function") throw new Error("GATE observer fetch is unavailable");
  if (!(options.includeExecutionMirror === undefined || typeof options.includeExecutionMirror === "boolean")) {
    throw new Error("GATE execution mirror option is invalid");
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const cacheMs = options.cacheMs ?? DEFAULT_CACHE_MS;
  const maximumBytes = options.maximumBytes ?? MAX_OBSERVER_BYTES;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 50 || timeoutMs > 30_000
      || !Number.isSafeInteger(cacheMs) || cacheMs < 0 || cacheMs > 30_000
      || !Number.isSafeInteger(maximumBytes) || maximumBytes < 1024 || maximumBytes > 2 * 1024 * 1024) {
    throw new Error("GATE observer provider limits are invalid");
  }
  const aliases = new Map();
  let selectionEpoch = crypto.randomBytes(16).toString("hex");
  let publishedAliasSignature = "";
  let revision = 0;
  let cached = null;
  let cachedAt = 0;
  let inFlight = null;
  return async function gateFleet() {
    const nowMs = typeof options.now === "function" ? options.now() : Date.now();
    if (cached && nowMs - cachedAt < cacheMs && Date.parse(cached.validUntil) > nowMs) return cached;
    if (inFlight) return inFlight;
    inFlight = (async () => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      revision += 1;
      try {
        const response = await fetchImpl(observerUrl, {
          method: "GET",
          redirect: "error",
          cache: "no-store",
          signal: controller.signal,
          headers: { Accept: "application/json" }
        });
        const source = await boundedJson(response, maximumBytes);
        const receivedAt = new Date(typeof options.now === "function" ? options.now() : Date.now());
        let projection = projectGateObserverStatus(source, {
          aliases,
          revision,
          receivedAt,
          selectionEpoch,
          includeExecutionMirror: options.includeExecutionMirror === true
        });
        const aliasSignature = aliasBindingSignature(aliases);
        if (aliasSignature !== publishedAliasSignature) {
          selectionEpoch = crypto.randomBytes(16).toString("hex");
          projection = projectGateObserverStatus(source, {
            aliases,
            revision,
            receivedAt,
            selectionEpoch,
            includeExecutionMirror: options.includeExecutionMirror === true
          });
          publishedAliasSignature = aliasSignature;
        }
        return projection;
      } catch {
        const receivedAt = new Date(typeof options.now === "function" ? options.now() : Date.now());
        return unavailableProjection(receivedAt.toISOString(), revision, selectionEpoch);
      } finally {
        clearTimeout(timer);
      }
    })();
    try {
      cached = await inFlight;
      cachedAt = nowMs;
      return cached;
    } finally {
      inFlight = null;
    }
  };
}

export function createUnavailableFleetProvider(options = {}) {
  let revision = 0;
  const selectionEpoch = crypto.randomBytes(16).toString("hex");
  return async () => unavailableProjection(
    new Date(typeof options.now === "function" ? options.now() : Date.now()).toISOString(),
    ++revision,
    selectionEpoch
  );
}

export const gateFleetInternals = Object.freeze({
  DEFAULT_CACHE_MS,
  DEFAULT_FLEET_TTL_MS,
  DEFAULT_OBSERVER_URL,
  DEFAULT_TIMEOUT_MS,
  LOCAL_FLEET_VERSION,
  MAX_OBSERVER_BYTES,
  MAX_TOKENS,
  exactKeys,
  scanPrecision,
  unavailableProjection,
  validateCase,
  validateProfile,
  validateScan
});
