import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { normalizeBuildIdentity, observeBuildIdentity } from "../lib/build-identity.mjs";
import { programProfileSetupFleetStatus } from "../lib/bounty-profiles.mjs";
import { buildStatus } from "../lib/status.mjs";
import { ctfPilotInternals } from "../lib/ctf-pilot.mjs";
import { sanitizeOperatorDisplayName, terminalWelcomeBanner } from "../lib/terminal-ui.mjs";
import { assertNoLikelySecret, redactSensitiveHeaders } from "../lib/text.mjs";

const EVENT_STATUSES = new Set([
  "queued",
  "running",
  "waiting",
  "blocked",
  "succeeded",
  "failed",
  "cancelled",
  "unknown"
]);
const EFFECT_CLASSES = new Set([
  "none",
  "local-read",
  "host-write",
  "forge-write",
  "external-publish",
  "network-observe",
  "network-probe",
  "target-mutate",
  "high-impact"
]);
const LEARNING_SCOPES = new Set(["session", "project", "repository"]);
const LEARNING_STATUSES = new Set(["proposed", "active", "superseded", "reverted"]);
const LEARNING_SENSITIVITIES = new Set(["public", "private"]);
const LEARNING_DOMAINS = new Set(["active-testing", "software-testing", "orchestration", "tooling", "general"]);
const LEARNING_OUTCOMES = new Set(["confirmed", "contradicted", "inconclusive", "blocked", "error"]);
const LEARNING_APPLICABILITY_KINDS = new Set(["component", "workflow", "phase", "tool", "adapter", "test", "environment"]);
const USAGE_AVAILABILITY = new Set(["exact", "estimated", "unavailable"]);
const UPSTREAM_INTEGRITY = new Set(["verified", "receipt-only", "commit-only", "invalid", "not-installed"]);
const PROJECT_STATUSES = new Set(["ready", "invalid"]);
const PROJECT_PROVIDERS = new Set(["github", "gitlab", "forgejo", "gitea", "local"]);
const PROJECT_ENVIRONMENTS = new Set(["host", "rootless-container", "container", "vm", "remote-lab"]);
const PROJECT_DELIVERY_MODES = new Set(["no-mistakes", "direct-pr", "local-only"]);
const CASE_STATUSES = new Set(["ready", "stale", "invalid"]);
const CASE_RUNTIME_STATES = new Set([
  "queued", "running", "waiting", "blocked", "succeeded", "failed", "cancelled", "unknown", "idle"
]);
const CASE_RUNTIME_HEALTH_STATUSES = new Set(["available", "unavailable"]);
const CASE_RUNTIME_HEALTH_REASONS = new Set(["invalid-case", "runtime-observation-failed"]);
const CASE_STATE_NAMESPACES = new Set(["isolated-directory"]);
const CASE_PROCESS_BOUNDARIES = new Set(["shared-user"]);
const CASE_NETWORK_BOUNDARIES = new Set(["adapter-dependent"]);
const CASE_SCAN_AVAILABILITY = new Set(["available", "unavailable"]);
const PROFILE_SETUP_STAGES = new Set(["questionnaire", "operator-review", "ready", "superseded"]);
const PROFILE_SETUP_READINESS = new Set(["not-ready", "ready"]);
const PROFILE_SETUP_NEXT_SECTIONS = new Set([
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
  "ambiguities-attestation",
  "conditional-modules"
]);
const PROFILE_SETUP_RECOMMENDATION_MODES = new Set(["policy", "proposal", "mixed"]);
const PROFILE_SETUP_SCAN_AVAILABILITY = new Set(["available", "unavailable"]);
const EXECUTION_MODES = new Set(["supervised-generic"]);
const EXECUTION_REASONS = new Set([
  "unsupported-platform",
  "proc-descriptor-unavailable",
  "proc-process-identity-unavailable"
]);
const EXECUTION_STATUSES = new Set([
  "queued",
  "running",
  "stopping",
  "succeeded",
  "failed",
  "cancelled",
  "blocked",
  "unknown"
]);
const EXECUTION_TERMINATION_REASONS = new Set([
  "completed",
  "operator-stop",
  "engagement-invalidated",
  "authorization-expired",
  "duration-limit",
  "evidence-limit",
  "evidence-write-failure",
  "spawn-failure",
  "supervisor-signal",
  "process-group-remained",
  "supervision-lost",
  "workflow-claim-failed",
  "managed-runtime-invalidated",
  "indeterminate-output",
  "output-validation-failed"
]);
const EXECUTION_SIGNALS = new Set(Object.keys(os.constants.signals || {}));
const EXECUTION_ENFORCED = new Set([
  "engagement-binding",
  "workflow-phase-binding",
  "workflow-reservation",
  "target-argument-binding",
  "declared-action-label-binding",
  "tool-allowlist",
  "exact-argv",
  "shell-disabled",
  "executable-descriptor-observed-sha256",
  "minimal-environment",
  "private-stdout-stderr",
  "one-shot-claim",
  "declared-bounds-within-receipt"
]);
const EXECUTION_BEST_EFFORT = new Set([
  "authorization-revocation-polling",
  "wall-duration",
  "process-group-termination"
]);
const EXECUTION_UNAVAILABLE = new Set([
  "egress-target-restriction",
  "request-count-measurement",
  "request-rate-measurement",
  "tool-concurrency-measurement",
  "token-measurement",
  "daemon-escape-containment",
  "filesystem-isolation",
  "credential-broker",
  "tool-artifact-inventory",
  "known-good-executable-provenance",
  "argv-action-semantics-validation",
  "supervisor-crash-containment",
  "immutable-executable-snapshot"
]);
const OFFLINE_ANALYSIS_MODES = new Set(["bubblewrap-offline"]);
const OFFLINE_ANALYSIS_STATUSES = new Set([
  "queued",
  "running",
  "succeeded",
  "failed",
  "cancelled",
  "blocked",
  "unknown"
]);
const OFFLINE_ANALYSIS_ENFORCED = new Set([
  "project-contract-binding",
  "typed-path-binding",
  "artifact-snapshot-sha256",
  "pinned-upstream-integrity",
  "fixed-adapter-argv",
  "bubblewrap-network-namespace",
  "read-only-runtime-mounts",
  "ephemeral-sandbox-writes",
  "shell-disabled",
  "cleared-environment",
  "private-bounded-evidence",
  "one-shot-claim",
  "wall-duration"
]);
const OFFLINE_ANALYSIS_UNAVAILABLE = new Set([
  "cpu-limit",
  "memory-limit",
  "immutable-managed-upstream-snapshot",
  "same-uid-gate-home-tamper-resistance",
  "unix-socket-system-call-denial"
]);
const OFFLINE_RETENTION_LOCK_STATES = new Set(["absent", "active", "stale", "invalid", "indeterminate"]);
const OFFLINE_SNAPSHOT_STATES = new Set(["stable", "consistent", "mutation-active", "indeterminate"]);
const TOOL_RUNTIME_VERIFICATION_MODES = new Set([
  "current-bytes-and-live-zero-egress-smoke",
  "current-bytes-and-install-smoke-evidence",
  "receipt-only"
]);
const TOOL_RUNTIME_PLATFORMS = new Set(["linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64"]);
const TOOL_RUNTIME_STATES = new Set([
  "absent",
  "invalid",
  "invalid-lock",
  "invalid-receipt",
  "receipt-only",
  "unmanaged",
  "unsupported-platform",
  "verified",
  "verified-install-evidence"
]);
const TOOL_RUNTIME_REASONS = new Set([
  "explicit-integrity-and-smoke-verification-required",
  "external-or-licensed-runtime-unavailable",
  "hardware-runtime-unavailable",
  "java-runtime-unavailable",
  "language-runtime-unavailable",
  "managed-runtime-absent",
  "native-runtime-unavailable",
  "oci-runtime-unavailable",
  "reviewed-data-dependencies-unavailable",
  "reviewed-platform-artifact-unavailable",
  "reviewed-runtime-lock-unavailable",
  "runtime-integrity-invalid",
  "runtime-lock-invalid",
  "runtime-privilege-adapter-unavailable",
  "workflow-phase-admission-unavailable",
  "zero-egress-smoke-sandbox-unavailable"
]);
const WORKFLOW_STATUSES = new Set(["open", "stopped", "recovery-hold", "reported", "closed", "unknown"]);
const WORKFLOW_HEALTH = new Set(["bounded-replay-verified", "degraded"]);
const WORKFLOW_LANES = new Set([
  "governance", "offline-static", "offline-dynamic", "passive-research", "active-observation",
  "active-testing", "high-impact-controlled", "closure"
]);
const WORKFLOW_EFFECTS = new Set(["P0", "P1", "A1", "A2", "A3"]);
const WORKFLOW_CONTROLS = new Set(["enforced", "measured-only", "unavailable"]);
const CTF_PILOT_REASONS = new Set(["not-case-scoped", "missing", "invalid", "expired", "worker-unavailable"]);
const CTF_SOLVING_VERDICTS = new Set(["pass", "provisional", "fail", "blocked", "unknown"]);
const CTF_SOLVING_STAGES = new Set(["idle", "intake", "mapping", "enumerating", "exploiting", "validating", "submitting", "complete", "blocked"]);
const CTF_LEARNING_VERDICTS = new Set(["pass", "provisional", "fail", "blocked", "unknown", "not-applicable"]);
const CTF_LEARNING_STAGES = new Set(["observing", "extracting", "validating", "applying", "checking", "idle", "blocked"]);
const CTF_COCKPIT_VERDICTS = new Set(["pass", "provisional", "fail", "blocked", "unknown"]);
const CTF_COCKPIT_STAGES = new Set(["collecting", "projecting", "current", "delayed", "blocked"]);
const CTF_ACTIONS = new Set(["none", "operator", "solver", "platform", "review"]);
const CTF_DEPTH_LEVELS = new Set(["unavailable", "baseline", "systematic", "deep"]);
const CTF_INTEGRITY = new Set(["consistent", "degraded"]);
const CTF_COMPLETION_STATES = new Set(["complete", "incomplete", "unknown"]);
const CTF_REPRODUCTION = new Set(["confirmed", "not-confirmed", "not-applicable", "unknown"]);
const CTF_EXTERNAL_ACCEPTANCE = new Set(["accepted", "pending", "rejected", "not-applicable", "unknown"]);
const CTF_PILOT_TTL_MS = 180_000;
const MAX_TOOL_RUNTIMES = 256;
const MAX_WORKFLOW_RECORDS = 64;
const MAX_CASE_RECORDS = 32;
const MAX_PROFILE_SETUP_RECORDS = 32;
const ENGAGEMENT_STATUSES = new Set(["draft", "proposed", "approved", "active", "paused", "closed", "expired", "revoked"]);
const TECHNICAL_REVIEW_STATUSES = new Set(["pending", "passed", "failed"]);
const OPERATOR_RECEIPT_STATUSES = new Set(["pending", "approved", "revoked"]);
const OBSERVER_API_VERSION = "gate.observer/v1";
const PUBLIC_USAGE_SOURCES = new Map([
  ["codex-session-jsonl", "codex-session-jsonl"],
  ["codex-session-jsonl:host-session-roots", "codex-session-jsonl"],
  ["gate-token-log", "gate-token-log"]
]);
const MAX_STATIC_ASSET_BYTES = 1_048_576;
// Pseudonyms only need to be stable for one observer process. A random HMAC
// key prevents low-entropy private names from being recovered with an offline
// dictionary built against unsalted hashes.
const OPAQUE_ID_KEY = crypto.randomBytes(32);
const MIME_TYPES = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".ico", "image/x-icon"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".svg", "image/svg+xml"],
  [".webmanifest", "application/manifest+json; charset=utf-8"]
]);
const STATIC_FILES = new Map([
  ["/", "index.html"],
  ["/dashboard", "index.html"],
  ["/dashboard/", "index.html"],
  ["/dashboard/app.js", "app.js"],
  ["/dashboard/favicon.svg", "favicon.svg"],
  ["/dashboard/model.js", "model.js"],
  ["/dashboard/styles.css", "styles.css"]
]);

function object(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function exactObjectKeys(value, keys) {
  const candidate = object(value);
  if (!candidate) return false;
  const actual = Object.keys(candidate).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function unavailablePilot(reason = "invalid") {
  const metric = () => ({ availability: "unavailable", value: null });
  const axis = () => ({ availability: "unavailable", verdict: null, now: null, actionNeeded: null, updatedAt: null });
  return {
    availability: "unavailable",
    reason: CTF_PILOT_REASONS.has(reason) ? reason : "invalid",
    observedAt: null,
    validUntil: null,
    solving: {
      ...axis(),
      completion: { state: null, reproduction: null, externalAcceptance: null },
      objectives: { availability: "unavailable", completed: null, total: null },
      depth: { level: "unavailable", branchesExplored: metric(), techniquesAttempted: metric(), deadEndsRetired: metric() },
      efficiency: {
        elapsedSeconds: metric(), activeSeconds: metric(), tokens: metric(), toolRuns: metric(), requests: metric(), retries: metric()
      }
    },
    learning: {
      ...axis(),
      stages: { observations: metric(), candidates: metric(), validated: metric(), applied: metric(), transferred: metric(), regressed: metric() }
    },
    cockpit: {
      ...axis(),
      signals: { availability: "unavailable", available: null, total: null },
      updatesPublished: metric(),
      updatesMissed: metric()
    },
    integrity: {
      availability: "unavailable",
      status: null,
      checks: { availability: "unavailable", available: null, total: null },
      issues: metric(),
      checkedAt: null
    }
  };
}

function projectPilotMetric(value) {
  if (!exactObjectKeys(value, ["availability", "value"])) return null;
  if (value.availability === "unavailable" && value.value === null) return { availability: "unavailable", value: null };
  const count = nonNegativeInteger(value.value);
  return value.availability === "available" && count !== null ? { availability: "available", value: count } : null;
}

function projectPilotCoverage(value) {
  if (!exactObjectKeys(value, ["availability", "available", "total"])) return null;
  if (value.availability === "unavailable" && value.available === null && value.total === null) {
    return { availability: "unavailable", available: null, total: null };
  }
  const available = nonNegativeInteger(value.available);
  const total = nonNegativeInteger(value.total);
  return value.availability === "available" && total !== null && total > 0 && available !== null && available <= total
    ? { availability: "available", available, total }
    : null;
}

function projectPilotAxis(value, verdicts, stages) {
  if (!object(value) || !new Set(["available", "unavailable"]).has(value.availability)) return null;
  if (value.availability === "unavailable") {
    if (value.verdict !== null || value.now !== null || value.actionNeeded !== null || value.updatedAt !== null) return null;
    return { availability: "unavailable", verdict: null, now: null, actionNeeded: null, updatedAt: null };
  }
  const updatedAt = timestamp(value.updatedAt);
  if (!verdicts.has(value.verdict) || !stages.has(value.now) || !CTF_ACTIONS.has(value.actionNeeded) || !updatedAt) return null;
  return { availability: "available", verdict: value.verdict, now: value.now, actionNeeded: value.actionNeeded, updatedAt };
}

/** Project one private pilot record through a prose-free, identifier-free allowlist. */
export function summarizeCtfPilot(value, options = {}) {
  const source = object(value);
  if (!exactObjectKeys(source, ["availability", "reason", "state"])) return unavailablePilot();
  if (source.availability === "unavailable") {
    return source.state === null && CTF_PILOT_REASONS.has(source.reason) ? unavailablePilot(source.reason) : unavailablePilot();
  }
  const state = object(source.state);
  if (source.availability !== "available" || source.reason !== null || !state ||
      !exactObjectKeys(state, ["$schema", "apiVersion", "kind", "metadata", "solving", "learning", "cockpit", "integrity"]) ||
      state.$schema !== "https://gate.local/schemas/ctf-pilot-state.schema.json" ||
      state.apiVersion !== "gate.dev/ctf-pilot-state/v1" || state.kind !== "CtfPilotState") return unavailablePilot();
  try {
    if (!ctfPilotInternals.stateIsConsistent(state)) return unavailablePilot();
  } catch {
    return unavailablePilot();
  }
  if (!exactObjectKeys(state.metadata, ["id", "caseId", "revision", "updatedAt", "validUntil", "producer"]) ||
      !identifier(state.metadata.id) || !identifier(state.metadata.caseId) ||
      nonNegativeInteger(state.metadata.revision) === null || state.metadata.revision < 1) return unavailablePilot();
  const observedAt = timestamp(state.metadata.updatedAt);
  const validUntil = timestamp(state.metadata.validUntil);
  const producer = state.metadata.producer;
  const producerValid = producer === null || exactObjectKeys(producer, ["kind", "campaignId", "generation"])
    && producer.kind === "campaign-worker" && identifier(producer.campaignId)
    && typeof producer.generation === "string" && /^[a-f0-9]{32}$/u.test(producer.generation);
  if (!observedAt || !validUntil || !producerValid || Date.parse(observedAt) >= Date.parse(validUntil)
      || Date.parse(validUntil) - Date.parse(observedAt) > CTF_PILOT_TTL_MS) return unavailablePilot();
  const enclosingAt = options.observedAt === undefined ? null : timestamp(options.observedAt);
  if (options.observedAt !== undefined && (!enclosingAt
      || Date.parse(observedAt) > Date.parse(enclosingAt)
      || Date.parse(enclosingAt) >= Date.parse(validUntil)
      || Date.parse(enclosingAt) - Date.parse(observedAt) >= CTF_PILOT_TTL_MS)) return unavailablePilot();
  const solvingAxis = projectPilotAxis(state.solving, CTF_SOLVING_VERDICTS, CTF_SOLVING_STAGES);
  const learningAxis = projectPilotAxis(state.learning, CTF_LEARNING_VERDICTS, CTF_LEARNING_STAGES);
  const cockpitAxis = projectPilotAxis(state.cockpit, CTF_COCKPIT_VERDICTS, CTF_COCKPIT_STAGES);
  if (!observedAt || !solvingAxis || !learningAxis || !cockpitAxis ||
      !exactObjectKeys(state.solving, ["availability", "verdict", "now", "actionNeeded", "updatedAt", "completion", "objectives", "depth", "efficiency"]) ||
      !exactObjectKeys(state.learning, ["availability", "verdict", "now", "actionNeeded", "updatedAt", "stages"]) ||
      !exactObjectKeys(state.cockpit, ["availability", "verdict", "now", "actionNeeded", "updatedAt", "signals", "updatesPublished", "updatesMissed"]) ||
      !exactObjectKeys(state.integrity, ["availability", "status", "checks", "issues", "checkedAt"])) return unavailablePilot();

  const completion = state.solving.availability === "unavailable"
    && exactObjectKeys(state.solving.completion, ["state", "reproduction", "externalAcceptance"])
    && state.solving.completion.state === null && state.solving.completion.reproduction === null
    && state.solving.completion.externalAcceptance === null
    ? { ...state.solving.completion }
    : state.solving.availability === "available"
      && exactObjectKeys(state.solving.completion, ["state", "reproduction", "externalAcceptance"])
      && CTF_COMPLETION_STATES.has(state.solving.completion.state)
      && CTF_REPRODUCTION.has(state.solving.completion.reproduction)
      && CTF_EXTERNAL_ACCEPTANCE.has(state.solving.completion.externalAcceptance)
      ? { ...state.solving.completion }
      : null;
  const objectives = state.solving.objectives?.availability === "unavailable"
    && state.solving.objectives.completed === null && state.solving.objectives.total === null
    ? { availability: "unavailable", completed: null, total: null }
    : state.solving.objectives?.availability === "available"
      && nonNegativeInteger(state.solving.objectives.completed) !== null
      && nonNegativeInteger(state.solving.objectives.total) > 0
      && state.solving.objectives.completed <= state.solving.objectives.total
      ? { availability: "available", completed: state.solving.objectives.completed, total: state.solving.objectives.total }
      : null;
  if (!completion || !objectives || !exactObjectKeys(state.solving.depth, ["level", "branchesExplored", "techniquesAttempted", "deadEndsRetired"]) ||
      !CTF_DEPTH_LEVELS.has(state.solving.depth.level) ||
      !exactObjectKeys(state.solving.efficiency, ["elapsedSeconds", "activeSeconds", "tokens", "toolRuns", "requests", "retries"]) ||
      !exactObjectKeys(state.learning.stages, ["observations", "candidates", "validated", "applied", "transferred", "regressed"])) return unavailablePilot();
  const depthMetrics = Object.fromEntries(["branchesExplored", "techniquesAttempted", "deadEndsRetired"]
    .map((key) => [key, projectPilotMetric(state.solving.depth[key])]));
  const efficiency = Object.fromEntries(["elapsedSeconds", "activeSeconds", "tokens", "toolRuns", "requests", "retries"]
    .map((key) => [key, projectPilotMetric(state.solving.efficiency[key])]));
  const stages = Object.fromEntries(["observations", "candidates", "validated", "applied", "transferred", "regressed"]
    .map((key) => [key, projectPilotMetric(state.learning.stages[key])]));
  const signals = projectPilotCoverage(state.cockpit.signals);
  const updatesPublished = projectPilotMetric(state.cockpit.updatesPublished);
  const updatesMissed = projectPilotMetric(state.cockpit.updatesMissed);
  const checks = projectPilotCoverage(state.integrity.checks);
  const issues = projectPilotMetric(state.integrity.issues);
  if ([...Object.values(depthMetrics), ...Object.values(efficiency), ...Object.values(stages), signals,
    updatesPublished, updatesMissed, checks, issues].some((item) => !item)) return unavailablePilot();
  let integrity;
  if (state.integrity.availability === "unavailable" && state.integrity.status === null && state.integrity.checkedAt === null) {
    integrity = { availability: "unavailable", status: null, checks, issues, checkedAt: null };
  } else {
    const checkedAt = timestamp(state.integrity.checkedAt);
    if (state.integrity.availability !== "available" || !CTF_INTEGRITY.has(state.integrity.status) || !checkedAt) return unavailablePilot();
    integrity = { availability: "available", status: state.integrity.status, checks, issues, checkedAt };
  }
  const axisTimes = [solvingAxis, learningAxis, cockpitAxis]
    .filter((axis) => axis.availability === "available")
    .map((axis) => Date.parse(axis.updatedAt));
  if (axisTimes.some((at) => at > Date.parse(observedAt))
      || integrity.availability === "available" && Date.parse(integrity.checkedAt) > Date.parse(observedAt)) return unavailablePilot();
  return {
    availability: "available",
    reason: null,
    observedAt,
    validUntil,
    solving: { ...solvingAxis, completion, objectives, depth: { level: state.solving.depth.level, ...depthMetrics }, efficiency },
    learning: { ...learningAxis, stages },
    cockpit: { ...cockpitAxis, signals, updatesPublished, updatesMissed },
    integrity
  };
}

function boundedString(value, maximum = 500) {
  if (typeof value !== "string" || !value || value.length > maximum || /[\r\n]/u.test(value)) return null;
  return value;
}

function safeLearningText(value) {
  const text = boundedString(value, 500);
  if (!text) return null;
  const redacted = text
    .replace(/\b(?:https?|file):\/\/\S+/giu, "[reference withheld]")
    .replace(/\b[A-Za-z]:[\\/][^\s,;]+/gu, "[path withheld]")
    .replace(/(^|\s)(?:~\/[^\s,;]*|\/[^\s,;]+)/gu, "$1[path withheld]")
    .replace(/\b(?:sk|pk|ghp|github_pat|xox[baprs])-?[A-Za-z0-9_-]{12,}\b/giu, "[secret withheld]")
    .replace(/\b(?:api[-_ ]?key|access[-_ ]?token)\s*[:=]\s*\S+/giu, "[secret withheld]");
  const sanitized = redactSensitiveHeaders(redacted);
  try {
    assertNoLikelySecret(sanitized, "observer learning narrative");
  } catch {
    return "Learning detail withheld.";
  }
  const colonCandidates = sanitized.match(/\[?[A-Fa-f0-9:]{2,}\]?/gu) || [];
  if (/private:\/\//iu.test(sanitized) ||
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/u.test(sanitized) ||
    /\b(?:\d{1,3}\.){3}\d{1,3}\b/u.test(sanitized) ||
    colonCandidates.some((candidate) => net.isIP(candidate.replace(/^\[|\]$/gu, "")) === 6) ||
    /(?<![A-Za-z0-9_.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/iu.test(sanitized) ||
    /\b[A-Za-z0-9][A-Za-z0-9_-]*[-_.](?:prod(?:uction)?|stag(?:e|ing)?|dev(?:elopment)?|qa|uat)\b/iu.test(sanitized)) {
    return "Learning detail withheld.";
  }
  return sanitized.slice(0, 240);
}

function identifier(value, maximum = 160) {
  const text = boundedString(value, maximum);
  return text && /^[A-Za-z0-9][A-Za-z0-9_.:/-]*$/u.test(text) ? text : null;
}

function publicName(value, maximum = 160) {
  const text = boundedString(value, maximum);
  return text && /^[A-Za-z0-9][A-Za-z0-9_.:-]*$/u.test(text) ? text : null;
}

function publicUsageProvider(value) {
  const text = boundedString(value, 80);
  return text && /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/u.test(text) ? text : null;
}

function publicModelName(value) {
  const text = boundedString(value, 80);
  return text && /^[A-Za-z0-9][A-Za-z0-9._:+-]{0,79}$/u.test(text) ? text : null;
}

function publicUsageSource(value) {
  return PUBLIC_USAGE_SOURCES.get(value) || null;
}

function localDisplayName(value, maximum = 60) {
  const text = boundedString(value, maximum);
  if (!text || !/^[A-Za-z][A-Za-z0-9 .'-]*$/u.test(text)) return null;
  return text;
}

function id(value) {
  const text = boundedString(value, 128);
  return text && /^[A-Za-z0-9][A-Za-z0-9_.-]{1,127}$/u.test(text) ? text : null;
}

function timestamp(value) {
  const text = boundedString(value, 64);
  return text && Number.isFinite(Date.parse(text)) ? new Date(text).toISOString() : null;
}

function nonNegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function signedInteger(value) {
  return Number.isInteger(value) && value >= -2_147_483_648 && value <= 2_147_483_647 ? value : null;
}

function safeEnum(value, allowed, fallback) {
  return allowed.has(value) ? value : fallback;
}

function opaqueId(prefix, value) {
  if (typeof value !== "string" || !value) return null;
  return `${prefix}_${crypto.createHmac("sha256", OPAQUE_ID_KEY).update(value).digest("hex").slice(0, 16)}`;
}

function projectEffect(value) {
  const effect = object(value) || {};
  const effectClass = safeEnum(effect.class, EFFECT_CLASSES, "none");
  const targetRef = boundedString(effect.targetRef, 240);
  const engagementId = id(effect.engagementId);
  const planDigest = typeof effect.planDigest === "string" && /^[a-f0-9]{64}$/u.test(effect.planDigest)
    ? effect.planDigest
    : null;
  if (["network-probe", "target-mutate", "high-impact"].includes(effectClass)) {
    if (!targetRef || !engagementId || !planDigest) return null;
  }
  return { class: effectClass, targetRef, engagementId, planDigest };
}

/**
 * Reduce an event to the canonical gate.event/v1 allowlist. Unknown keys are
 * deliberately discarded here, before an event can cross the HTTP boundary.
 */
export function projectEvent(value) {
  const event = object(value);
  if (!event || event.apiVersion !== "gate.event/v1") return null;
  const eventId = typeof event.id === "string" && /^evt_[A-Za-z0-9][A-Za-z0-9_-]{5,127}$/u.test(event.id)
    ? event.id
    : null;
  const at = timestamp(event.at);
  const runId = id(event.runId);
  const taskId = event.taskId === null ? null : id(event.taskId);
  const component = identifier(event.component);
  const agent = event.agent === null ? null : identifier(event.agent);
  const kind = typeof event.kind === "string" && /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$/u.test(event.kind)
    ? event.kind
    : null;
  const status = safeEnum(event.status, EVENT_STATUSES, null);
  const summary = boundedString(event.summary, 500);
  const effect = projectEffect(event.effect);
  if (!eventId || !at || !runId || event.taskId !== null && !taskId || !component || event.agent !== null && !agent || !kind || !status || !summary || !effect) {
    return null;
  }
  const evidenceRefs = Array.isArray(event.evidenceRefs)
    ? [...new Set(event.evidenceRefs.filter((item) => typeof item === "string" && /^(?:private|event|evidence|file):\/\/\S+$/u.test(item)))]
    : [];
  const usageRef = event.usageRef === null
    ? null
    : typeof event.usageRef === "string" && /^usage:\/\/[A-Za-z0-9_.-]+$/u.test(event.usageRef)
      ? event.usageRef
      : null;
  if (event.usageRef !== null && !usageRef) return null;
  return {
    apiVersion: "gate.event/v1",
    id: eventId,
    at,
    runId,
    taskId,
    component,
    agent,
    kind,
    status,
    summary,
    effect,
    evidenceRefs,
    usageRef
  };
}

function hasOnlyKeys(value, allowed) {
  return Object.keys(value).every((key) => allowed.has(key));
}

function uniqueArray(value, minimum, maximum, predicate) {
  return Array.isArray(value) && value.length >= minimum && value.length <= maximum &&
    value.every(predicate) && new Set(value.map((item) => JSON.stringify(item))).size === value.length;
}

function learningApplicabilityKey(value) {
  return JSON.stringify(value.map((item) => [
    item.kind,
    item.id,
    item.version ?? "",
    item.digest ?? ""
  ]).sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right))));
}

function validV2LearningExtension(learning) {
  const rootKeys = new Set([
    "apiVersion", "id", "at", "scope", "cause", "change", "evidence", "status", "sensitivity",
    "supersedes", "configurationRefs", "trigger", "domain", "cycle", "applicability", "promotion"
  ]);
  if (!hasOnlyKeys(learning, rootKeys) || Object.keys(learning).length !== rootKeys.size) return false;
  const evidenceValid = uniqueArray(learning.evidence, 1, 64, (item) => {
    return typeof item === "string" && /^(?:event|evidence|private|commit):\/\/\S+$/u.test(item);
  });
  const configurationValid = uniqueArray(learning.configurationRefs, 0, 64, (item) => {
    return typeof item === "string" && item.length <= 500 && !item.startsWith("/") &&
      !/(?:^|\/)\.\.(?:\/|$)/u.test(item) && !/[\u0000\r\n]/u.test(item);
  });
  if (!evidenceValid || !configurationValid) return false;
  if (learning.sensitivity === "public" && learning.evidence.some((item) => item.startsWith("private://"))) return false;
  if (typeof learning.trigger !== "string" || !/^[a-z][a-z0-9-]{1,127}$/u.test(learning.trigger)) return false;
  if (!LEARNING_DOMAINS.has(learning.domain)) return false;

  const cycle = object(learning.cycle);
  const outcome = object(cycle?.outcome);
  if (!cycle || !hasOnlyKeys(cycle, new Set(["hypothesis", "method", "outcome", "lesson", "nextAdjustment"])) ||
    !boundedString(cycle.hypothesis, 500) || !boundedString(cycle.method, 500) ||
    !boundedString(cycle.lesson, 500) || !boundedString(cycle.nextAdjustment, 500) ||
    !outcome || !hasOnlyKeys(outcome, new Set(["disposition", "summary"])) ||
    !LEARNING_OUTCOMES.has(outcome.disposition) || !boundedString(outcome.summary, 500)) {
    return false;
  }

  const applicabilityValid = uniqueArray(learning.applicability, 1, 16, (candidate) => {
    const item = object(candidate);
    if (!item || !hasOnlyKeys(item, new Set(["kind", "id", "version", "digest"]))) return false;
    if (!LEARNING_APPLICABILITY_KINDS.has(item.kind) || typeof item.id !== "string" || !/^[a-z][a-z0-9._-]{1,127}$/u.test(item.id)) return false;
    if (item.version !== undefined && (typeof item.version !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/u.test(item.version))) return false;
    return item.digest === undefined || typeof item.digest === "string" && /^[a-f0-9]{64}$/u.test(item.digest);
  });
  const applicabilityKeys = Array.isArray(learning.applicability)
    ? learning.applicability.map((item) => [item.kind, item.id, item.version ?? "", item.digest ?? ""].join("\u0000"))
    : [];
  if (!applicabilityValid || new Set(applicabilityKeys).size !== applicabilityKeys.length) return false;

  const promotion = object(learning.promotion);
  const promotionKeys = new Set([
    "state", "candidateId", "candidateSha256", "validatedAt", "validationRefs", "changeRefs", "review", "conflictsWith", "replaces"
  ]);
  if (!promotion || !hasOnlyKeys(promotion, promotionKeys)) return false;
  const conflictsValid = uniqueArray(promotion.conflictsWith, 0, 64, (item) => {
    return typeof item === "string" && /^lrn_[A-Za-z0-9][A-Za-z0-9_-]{5,127}$/u.test(item);
  });
  const replacesValid = uniqueArray(promotion.replaces, 0, 64, (item) => {
    return typeof item === "string" && /^lrn_[A-Za-z0-9][A-Za-z0-9_-]{5,127}$/u.test(item);
  });
  if (promotion.state === "candidate") {
    return learning.status === "proposed" && learning.sensitivity === "private" && learning.supersedes === null &&
      promotion.candidateId === null && promotion.candidateSha256 === null && promotion.validatedAt === null &&
      Array.isArray(promotion.validationRefs) && promotion.validationRefs.length === 0 &&
      Array.isArray(promotion.changeRefs) && promotion.changeRefs.length === 0 && promotion.review === null &&
      conflictsValid && promotion.conflictsWith.length === 0 && replacesValid;
  }
  if (promotion.state !== "validated") return false;
  const learningId = typeof promotion.candidateId === "string" && /^lrn_[A-Za-z0-9][A-Za-z0-9_-]{5,127}$/u.test(promotion.candidateId);
  const digest = typeof promotion.candidateSha256 === "string" && /^[a-f0-9]{64}$/u.test(promotion.candidateSha256);
  const validatedAt = timestamp(promotion.validatedAt);
  const validationRefs = uniqueArray(promotion.validationRefs, 1, 64, (item) => {
    return typeof item === "string" && /^(?:event|evidence|private|commit):\/\/\S+$/u.test(item);
  });
  const privateEvidenceInPublic = learning.sensitivity === "public" && Array.isArray(promotion.validationRefs) &&
    promotion.validationRefs.some((item) => typeof item === "string" && item.startsWith("private://"));
  const changeRefs = uniqueArray(promotion.changeRefs, 1, 64, (item) => {
    return typeof item === "string" && /^(?:evidence|commit):\/\/\S+$/u.test(item);
  });
  const review = object(promotion.review);
  const reviewValid = review && hasOnlyKeys(review, new Set([
    "owner", "attestationRef", "attestationSha256", "candidateSha256", "headSha"
  ])) &&
    Object.keys(review).length === 5 && review.owner === "no-mistakes" &&
    typeof review.attestationRef === "string" && /^evidence:\/\/no-mistakes\/\S+$/u.test(review.attestationRef) &&
    typeof review.attestationSha256 === "string" && /^[a-f0-9]{64}$/u.test(review.attestationSha256) &&
    review.candidateSha256 === promotion.candidateSha256 &&
    typeof review.headSha === "string" && /^[a-f0-9]{40}$/u.test(review.headSha);
  return Boolean(!privateEvidenceInPublic && learning.status === "active" && learning.supersedes === promotion.candidateId && learningId && digest &&
    validatedAt && validationRefs && changeRefs && reviewValid && conflictsValid && replacesValid);
}

/** Apply a strict common allowlist to validated gate.learning/v1 and v2 records. */
export function projectLearning(value) {
  const learning = object(value);
  if (!learning || !["gate.learning/v1", "gate.learning/v2"].includes(learning.apiVersion)) return null;
  const learningId = typeof learning.id === "string" && /^lrn_[A-Za-z0-9][A-Za-z0-9_-]{5,127}$/u.test(learning.id)
    ? learning.id
    : null;
  const at = timestamp(learning.at);
  const scope = safeEnum(learning.scope, LEARNING_SCOPES, null);
  const cause = boundedString(learning.cause, 500);
  const change = boundedString(learning.change, 500);
  const status = safeEnum(learning.status, LEARNING_STATUSES, null);
  const sensitivity = safeEnum(learning.sensitivity, LEARNING_SENSITIVITIES, null);
  const supersedes = learning.supersedes === null
    ? null
    : typeof learning.supersedes === "string" && /^lrn_[A-Za-z0-9][A-Za-z0-9_-]{5,127}$/u.test(learning.supersedes)
      ? learning.supersedes
      : null;
  if (!learningId || !at || !scope || !cause || !change || !status || !sensitivity || learning.supersedes !== null && !supersedes) {
    return null;
  }
  const evidence = Array.isArray(learning.evidence)
    ? [...new Set(learning.evidence.filter((item) => typeof item === "string" && /^(?:event|evidence|private|commit):\/\/\S+$/u.test(item)))]
    : [];
  if (!evidence.length) return null;
  const configurationRefs = Array.isArray(learning.configurationRefs)
    ? [...new Set(learning.configurationRefs.filter((item) => {
        return typeof item === "string" && item.length <= 500 && !item.startsWith("/") && !/(?:^|\/)\.\.(?:\/|$)/u.test(item) && !/[\u0000\r\n]/u.test(item);
      }))]
    : [];
  if (learning.apiVersion === "gate.learning/v2" && !validV2LearningExtension(learning)) return null;
  return {
    apiVersion: learning.apiVersion,
    id: learningId,
    at,
    scope,
    cause,
    change,
    evidence,
    status,
    sensitivity,
    supersedes,
    configurationRefs
  };
}

function usageCounts(value, availability) {
  const usage = object(value) || {};
  if (availability === "unavailable") {
    return {
      inputTokens: null,
      cachedInputTokens: null,
      outputTokens: null,
      reasoningTokens: null,
      totalTokens: null
    };
  }
  return {
    inputTokens: nonNegativeInteger(usage.inputTokens ?? usage.input),
    cachedInputTokens: nonNegativeInteger(usage.cachedInputTokens ?? usage.cached_input),
    outputTokens: nonNegativeInteger(usage.outputTokens ?? usage.output),
    reasoningTokens: nonNegativeInteger(usage.reasoningTokens ?? usage.reasoning),
    totalTokens: nonNegativeInteger(usage.totalTokens ?? usage.total)
  };
}

function projectScannedUsage(tokens) {
  const raw = object(tokens) || {};
  const recorded = Array.isArray(raw.records) ? projectRecordedUsage(raw.records) : null;
  let availability = safeEnum(raw.availability, USAGE_AVAILABILITY, recorded?.availability || "unavailable");
  const scannedSessions = Array.isArray(raw.sessions)
    ? raw.sessions.map((value) => {
        const session = object(value);
        if (!session) return null;
        const sessionAvailability = safeEnum(session.availability, USAGE_AVAILABILITY, "unavailable");
        return {
          id: opaqueId("session", session.id),
          at: timestamp(session.modifiedAt ?? session.modified_at),
          updatedAt: timestamp(session.modifiedAt ?? session.modified_at),
          provider: publicUsageProvider(session.provider),
          model: publicModelName(session.model),
          source: publicUsageSource(session.source),
          availability: sessionAvailability,
          contextWindow: nonNegativeInteger(session.contextWindow ?? session.context_window),
          ...usageCounts(session.usage, sessionAvailability)
        };
      }).filter((value) => value?.id)
    : [];
  const recordSessions = recorded?.sessions || [];
  const sessions = (scannedSessions.length ? scannedSessions : recordSessions)
    .sort((left, right) => Date.parse(right.at || 0) - Date.parse(left.at || 0))
    .slice(0, 100);
  let counts = usageCounts(raw.totals, availability);
  const knownCount = [counts, ...sessions].some((value) => {
    return ["inputTokens", "cachedInputTokens", "outputTokens", "reasoningTokens", "totalTokens"]
      .some((key) => Number.isSafeInteger(value[key]));
  });
  if (availability !== "unavailable" && !knownCount) {
    availability = "unavailable";
    counts = usageCounts(null, availability);
  }
  return {
    availability,
    source: publicUsageSource(raw.source) || recorded?.source || null,
    scannedFiles: nonNegativeInteger(raw.scannedFiles ?? raw.scanned_files),
    inputTokens: counts.inputTokens ?? recorded?.inputTokens ?? null,
    cachedInputTokens: counts.cachedInputTokens ?? recorded?.cachedInputTokens ?? null,
    outputTokens: counts.outputTokens ?? recorded?.outputTokens ?? null,
    reasoningTokens: counts.reasoningTokens ?? recorded?.reasoningTokens ?? null,
    totalTokens: counts.totalTokens ?? recorded?.totalTokens ?? null,
    sessions
  };
}

function projectUsageRecord(value) {
  const record = object(value);
  if (!record || record.apiVersion !== "gate.usage/v1") return null;
  const usageId = typeof record.id === "string" && /^use_[A-Za-z0-9][A-Za-z0-9_-]{5,127}$/u.test(record.id)
    ? record.id
    : null;
  const at = timestamp(record.at);
  const runId = id(record.runId);
  const taskId = record.taskId === null ? null : id(record.taskId);
  const agent = identifier(record.agent);
  const provider = identifier(record.provider);
  const model = record.model === null ? null : boundedString(record.model, 160);
  const availability = safeEnum(record.availability, USAGE_AVAILABILITY, "unavailable");
  const measure = ["delta", "cumulative", "unavailable"].includes(record.measure) ? record.measure : null;
  const source = boundedString(record.source, 160);
  const counts = usageCounts(record, availability);
  const hasCount = [counts.inputTokens, counts.outputTokens, counts.totalTokens].some(Number.isSafeInteger);
  if (
    !usageId || !at || !runId || record.taskId !== null && !taskId || !agent || !provider ||
    record.model !== null && !model || !measure || !source ||
    availability === "unavailable" && measure !== "unavailable" ||
    availability !== "unavailable" && (!hasCount || measure === "unavailable")
  ) return null;
  return { at, runId, taskId, agent, provider, model, availability, measure, source, ...counts };
}

function sumKnown(records, key) {
  const values = records.map((record) => record[key]).filter((value) => Number.isSafeInteger(value));
  return values.length ? values.reduce((sum, value) => sum + value, 0) : null;
}

function latestUsageRecord(records) {
  return records.reduce((selected, record) => {
    if (!selected) return record;
    return Date.parse(record.at) >= Date.parse(selected.at) ? record : selected;
  }, null);
}

function usageSession(record) {
  return {
    id: opaqueId("session", [record.runId, record.taskId, record.agent, record.provider, record.model].join("\u0000")),
    at: record.at,
    updatedAt: record.at,
    provider: publicUsageProvider(record.provider),
    model: publicModelName(record.model),
    source: publicUsageSource(record.source),
    availability: record.availability,
    contextWindow: null,
    inputTokens: record.inputTokens,
    cachedInputTokens: record.cachedInputTokens,
    outputTokens: record.outputTokens,
    reasoningTokens: record.reasoningTokens,
    totalTokens: record.totalTokens
  };
}

function projectRecordedUsage(records) {
  const projected = records.map(projectUsageRecord).filter((record) => {
    if (!record?.at || !record.runId || !record.agent || !record.provider || !record.source) return false;
    if (record.availability === "unavailable") return record.measure === "unavailable";
    return record.measure === "delta" || record.measure === "cumulative";
  });
  const groups = new Map();
  for (const record of projected) {
    const key = [record.runId, record.taskId, record.agent, record.provider, record.model].join("\u0000");
    const group = groups.get(key) || { deltas: [], cumulative: [], unavailable: [] };
    group[record.measure === "delta" ? "deltas" : record.measure === "cumulative" ? "cumulative" : "unavailable"].push(record);
    groups.set(key, group);
  }
  const selected = [];
  for (const group of groups.values()) {
    if (group.deltas.length) {
      selected.push({
        ...latestUsageRecord(group.deltas),
        availability: group.deltas.some((record) => record.availability === "estimated") ? "estimated" : "exact",
        inputTokens: sumKnown(group.deltas, "inputTokens"),
        cachedInputTokens: sumKnown(group.deltas, "cachedInputTokens"),
        outputTokens: sumKnown(group.deltas, "outputTokens"),
        reasoningTokens: sumKnown(group.deltas, "reasoningTokens"),
        totalTokens: sumKnown(group.deltas, "totalTokens")
      });
    } else if (group.cumulative.length) {
      selected.push(latestUsageRecord(group.cumulative));
    } else if (group.unavailable.length) {
      selected.push(latestUsageRecord(group.unavailable));
    }
  }
  const available = selected.filter((record) => record.availability !== "unavailable");
  const availability = available.length === 0
    ? "unavailable"
    : available.some((record) => record.availability === "estimated")
      ? "estimated"
      : "exact";
  return {
    availability,
    source: "gate-token-log",
    scannedFiles: null,
    inputTokens: sumKnown(available, "inputTokens"),
    cachedInputTokens: sumKnown(available, "cachedInputTokens"),
    outputTokens: sumKnown(available, "outputTokens"),
    reasoningTokens: sumKnown(available, "reasoningTokens"),
    totalTokens: sumKnown(available, "totalTokens"),
    sessions: selected
      .map(usageSession)
      .sort((left, right) => Date.parse(right.at) - Date.parse(left.at))
      .slice(0, 100)
  };
}

export function projectUsage(tokens) {
  return Array.isArray(tokens) ? projectRecordedUsage(tokens) : projectScannedUsage(tokens);
}

function latestBy(values, keyFor) {
  const result = new Map();
  for (const value of values) {
    const key = keyFor(value);
    if (!key) continue;
    const current = result.get(key);
    if (!current || Date.parse(value.at) > Date.parse(current.at)) result.set(key, value);
  }
  return [...result.values()].sort((left, right) => Date.parse(right.at) - Date.parse(left.at));
}

function projectMember(event, name, memberType) {
  const memberId = opaqueId(memberType, name);
  return {
    id: memberId,
    runId: opaqueId("run", event.runId),
    taskId: event.taskId ? opaqueId("task", event.taskId) : null,
    component: publicName(event.component),
    agent: event.agent ? opaqueId("member", event.agent) : null,
    role: null,
    stage: event.kind,
    status: event.status,
    effect: event.effect.class,
    updatedAt: event.at,
    startedAt: null
  };
}

function publicEvent(event) {
  const component = publicName(event.component);
  return {
    id: event.id,
    at: event.at,
    runId: opaqueId("run", event.runId),
    taskId: event.taskId ? opaqueId("task", event.taskId) : null,
    component,
    agent: event.agent ? opaqueId("member", event.agent) : null,
    kind: event.kind,
    status: event.status,
    effect: { class: event.effect.class },
    action: {
      category: event.kind.split(".", 1)[0],
      toolName: component,
      durationMs: null,
      exitCode: null
    }
  };
}

function publicLearning(learning, effectiveStatus = learning.status) {
  const privateRecord = learning.sensitivity === "private";
  const publicId = (value) => value === null
    ? null
    : !privateRecord && /^lrn_[0-9]{14}_[a-f0-9]{8}$/u.test(value)
      ? value
      : opaqueId("learning", value);
  return {
    id: publicId(learning.id),
    at: learning.at,
    scope: learning.scope,
    cause: privateRecord ? "Private learning recorded." : safeLearningText(learning.cause),
    change: privateRecord ? "Details withheld from observer." : safeLearningText(learning.change),
    status: effectiveStatus,
    sensitivity: learning.sensitivity,
    supersedes: publicId(learning.supersedes),
    evidenceCount: learning.evidence.length,
    configurationCount: learning.configurationRefs.length
  };
}

function executionCapabilityList(value, allowed) {
  if (!Array.isArray(value)) return [];
  const supplied = new Set(value);
  return [...allowed].filter((item) => supplied.has(item));
}

function summarizeExecutionRun(value) {
  const run = object(value);
  if (!run) return null;
  const status = safeEnum(run.status, EXECUTION_STATUSES, null);
  if (!status) return null;
  const privateRunId = typeof run.runId === "string" && /^xrun_[a-f0-9]{32}$/u.test(run.runId) ? run.runId : null;
  const privateManifestId = typeof run.manifestId === "string" && /^xmf_[a-f0-9]{32}$/u.test(run.manifestId)
    ? run.manifestId
    : null;
  const privateEngagementId = id(run.engagementId);
  if (!privateRunId || !privateManifestId || !privateEngagementId) return null;
  const workflow = object(run.workflow);
  const workflowInstanceId = id(workflow?.instanceId);
  const phaseId = publicName(workflow?.phaseId, 80);
  const phaseAttemptId = typeof workflow?.phaseAttemptId === "string" && /^wpa_[a-f0-9]{32}$/u.test(workflow.phaseAttemptId)
    ? workflow.phaseAttemptId
    : null;
  const reservationId = typeof workflow?.reservationId === "string" && /^wxr_[a-f0-9]{32}$/u.test(workflow.reservationId)
    ? workflow.reservationId
    : null;
  if (!workflowInstanceId || !phaseId || !phaseAttemptId || !reservationId) return null;
  return {
    runId: opaqueId("run", privateRunId),
    manifestId: opaqueId("manifest", privateManifestId),
    engagementId: opaqueId("engagement", privateEngagementId),
    status,
    createdAt: timestamp(run.createdAt),
    startedAt: timestamp(run.startedAt),
    finishedAt: timestamp(run.finishedAt),
    terminationReason: safeEnum(run.terminationReason, EXECUTION_TERMINATION_REASONS, null),
    exitCode: signedInteger(run.exitCode),
    signal: safeEnum(run.signal, EXECUTION_SIGNALS, null),
    workflow: {
      instanceId: opaqueId("workflow", workflowInstanceId),
      phaseId,
      phaseAttemptId: opaqueId("phase-attempt", phaseAttemptId),
      reservationId: opaqueId("reservation", reservationId)
    }
  };
}

function summarizeExecution(value) {
  const execution = object(value) || {};
  const capability = object(execution.capability) || {};
  const rawCounts = object(execution.counts) || {};
  const configured = typeof capability.configured === "boolean" ? capability.configured : null;
  const mode = safeEnum(capability.mode, EXECUTION_MODES, null);
  const enforced = executionCapabilityList(capability.enforced, EXECUTION_ENFORCED);
  const bestEffort = executionCapabilityList(capability.bestEffort, EXECUTION_BEST_EFFORT);
  const unavailable = executionCapabilityList(capability.unavailable, EXECUTION_UNAVAILABLE);
  const completeCapability = enforced.length === EXECUTION_ENFORCED.size &&
    bestEffort.length === EXECUTION_BEST_EFFORT.size &&
    unavailable.length === EXECUTION_UNAVAILABLE.size;
  const laneAvailable = configured === true && capability.laneAvailable === true && mode !== null && completeCapability;
  const counts = Object.fromEntries(
    [...EXECUTION_STATUSES].map((status) => [status, nonNegativeInteger(rawCounts[status])])
  );
  return {
    configured,
    laneAvailable,
    mode,
    reason: laneAvailable ? null : safeEnum(capability.reason, EXECUTION_REASONS, null),
    queuedCount: counts.queued,
    runningCount: counts.running,
    stoppingCount: counts.stopping,
    counts,
    enforced,
    bestEffort,
    unavailable,
    recent: Array.isArray(execution.recent)
      ? execution.recent
        .slice(0, 100)
        .map(summarizeExecutionRun)
        .filter(Boolean)
        .sort((left, right) => Date.parse(right.createdAt || 0) - Date.parse(left.createdAt || 0))
        .slice(0, 30)
      : []
  };
}

function summarizeCaseUsage(value) {
  const usage = object(value) || {};
  const availability = safeEnum(usage.availability, USAGE_AVAILABILITY, "unavailable");
  return {
    availability,
    totalTokens: availability === "unavailable" ? null : nonNegativeInteger(usage.totalTokens)
  };
}

function summarizeCaseState(value) {
  const status = object(value) || {};
  const state = safeEnum(status.state, CASE_RUNTIME_STATES, "unknown");
  // Exact aggregate counts cover active records that may be older than the
  // bounded recent-run projection. They may promote an otherwise terminal or
  // unknown summary to active, without hiding an existing failure, block, or
  // wait signal.
  if (!["failed", "blocked", "waiting"].includes(state)) {
    const execution = object(status.execution) || {};
    const offline = object(status.offlineAnalysis) || {};
    const executionCounts = object(execution.counts) || {};
    const offlineCounts = object(offline.counts) || {};
    if (
      Number(executionCounts.running || 0) > 0 ||
      Number(executionCounts.stopping || 0) > 0 ||
      Number(offlineCounts.running || 0) > 0
    ) return "running";
    if (Number(executionCounts.queued || 0) > 0 || Number(offlineCounts.queued || 0) > 0) return "queued";
  }
  return state;
}

function summarizeWorkflowInstance(value) {
  const workflow = object(value);
  if (!workflow) return null;
  const privateInstanceId = id(workflow.instanceId);
  const status = safeEnum(workflow.status, WORKFLOW_STATUSES, "unknown");
  const health = safeEnum(workflow.health, WORKFLOW_HEALTH, "degraded");
  if (!privateInstanceId) return null;
  const active = object(workflow.activePhase);
  let activePhase = null;
  if (active) {
    const phaseId = publicName(active.id, 80);
    const lane = safeEnum(active.lane, WORKFLOW_LANES, null);
    const effectClass = safeEnum(active.effectClass, WORKFLOW_EFFECTS, null);
    const toolId = active.toolId === null ? null : publicName(active.toolId, 80);
    const controls = object(active.envelopeControls);
    if (!phaseId || !lane || !effectClass || (active.toolId !== null && !toolId)) return null;
    activePhase = {
      id: phaseId,
      lane,
      effectClass,
      toolId,
      envelopeControls: controls ? Object.fromEntries([
        "wallTime", "requests", "rate", "parallel", "tokens", "evidenceBytes", "spend"
      ].map((key) => [key, safeEnum(controls[key], WORKFLOW_CONTROLS, null)])) : null
    };
  }
  return {
    instanceId: opaqueId("workflow", privateInstanceId),
    status,
    activePhase,
    journalSequence: nonNegativeInteger(workflow.journalSequence),
    reservations: nonNegativeInteger(workflow.reservations),
    stops: nonNegativeInteger(workflow.stops),
    health
  };
}

function summarizeWorkflows(value) {
  const workflows = object(value) || {};
  const rawCounts = object(workflows.counts) || {};
  const rawScan = object(workflows.scan) || {};
  const counts = Object.fromEntries([
    "total", "active", "open", "stopped", "recovery-hold", "reported", "closed", "degraded", "unknown"
  ].map((key) => [key, nonNegativeInteger(rawCounts[key])]));
  return {
    counts,
    instances: Array.isArray(workflows.instances)
      ? workflows.instances.slice(0, MAX_WORKFLOW_RECORDS).map(summarizeWorkflowInstance).filter(Boolean)
      : [],
    scan: {
      discovered: nonNegativeInteger(rawScan.discovered),
      scanned: nonNegativeInteger(rawScan.scanned),
      omitted: nonNegativeInteger(rawScan.omitted),
      complete: typeof rawScan.complete === "boolean" ? rawScan.complete : false,
      truncated: typeof rawScan.truncated === "boolean" ? rawScan.truncated : true
    }
  };
}

function summarizeOfflineAnalysisRun(value) {
  const run = object(value);
  if (!run) return null;
  const status = safeEnum(run.status, OFFLINE_ANALYSIS_STATUSES, null);
  const privateRunId = typeof run.runId === "string" && /^arun_[a-f0-9]{32}$/u.test(run.runId)
    ? run.runId
    : null;
  if (!status || !privateRunId) return null;
  return {
    runId: opaqueId("run", privateRunId),
    status,
    isolationVerified: typeof run.isolationVerified === "boolean" ? run.isolationVerified : null
  };
}

function summarizeOfflineRetention(value) {
  const retention = object(value) || {};
  const projected = {};
  for (const field of [
    "quotaBytes", "quotaArtifacts", "retainedBytes", "availableBytes", "retainedArtifacts", "availableArtifacts", "pendingManifests",
    "pendingTransactions", "invalidTransactionRecords", "creatingManifests", "invalidCreationIntents",
    "invalidClaimRecords", "invalidPurgeRecords", "invalidRunRecords", "blockedManifests",
    "expiredManifests", "activeManifests", "terminalManifests", "unknownManifests",
    "purgePendingManifests", "purgedManifests", "orphanedArtifacts", "orphanedBytes",
    "missingArtifacts", "invalidEntries"
  ]) projected[field] = nonNegativeInteger(retention[field]);
  projected.retentionLockState = safeEnum(retention.retentionLockState, OFFLINE_RETENTION_LOCK_STATES, null);
  projected.snapshotState = safeEnum(retention.snapshotState, OFFLINE_SNAPSHOT_STATES, null);
  projected.overQuota = typeof retention.overQuota === "boolean" ? retention.overQuota : null;
  projected.mutationBlocked = typeof retention.mutationBlocked === "boolean" ? retention.mutationBlocked : null;
  return projected;
}

function summarizeOfflineAnalysis(value) {
  const analysis = object(value) || {};
  const capability = object(analysis.capability) || {};
  const rawCounts = object(analysis.counts) || {};
  const configured = typeof capability.configured === "boolean" ? capability.configured : null;
  const mode = safeEnum(capability.mode, OFFLINE_ANALYSIS_MODES, null);
  const enforced = executionCapabilityList(capability.enforced, OFFLINE_ANALYSIS_ENFORCED);
  const unavailable = executionCapabilityList(capability.unavailable, OFFLINE_ANALYSIS_UNAVAILABLE);
  const completeCapability = enforced.length === OFFLINE_ANALYSIS_ENFORCED.size &&
    unavailable.length === OFFLINE_ANALYSIS_UNAVAILABLE.size;
  const laneAvailable = configured === true && capability.laneAvailable === true && mode !== null && completeCapability;
  const counts = Object.fromEntries(
    [...OFFLINE_ANALYSIS_STATUSES].map((status) => [status, nonNegativeInteger(rawCounts[status])])
  );
  return {
    configured,
    laneAvailable,
    mode,
    reason: laneAvailable ? null : "unavailable",
    runningCount: counts.running,
    counts,
    retention: summarizeOfflineRetention(analysis.retention),
    enforced,
    unavailable,
    recent: Array.isArray(analysis.recent)
      ? analysis.recent
        .slice(0, 100)
        .map(summarizeOfflineAnalysisRun)
        .filter(Boolean)
        .slice(0, 25)
      : []
  };
}

function toolRuntimeName(value) {
  const text = boundedString(value, 80);
  if (!text || text.includes("://") || text.includes("\\")) return null;
  return /^[A-Za-z0-9][A-Za-z0-9+._ -]*(?: \/ [A-Za-z0-9][A-Za-z0-9+._ -]*)?$/u.test(text) ? text : null;
}

function toolRuntimeReason(value) {
  if (TOOL_RUNTIME_REASONS.has(value)) return value;
  // Runtime verification can return filesystem-derived exception text. Keep
  // the fault visible without exposing that text across the observer boundary.
  return boundedString(value, 500) ? "runtime-integrity-invalid" : null;
}

function toolRuntimeReasons(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.slice(0, 32).map(toolRuntimeReason).filter(Boolean))];
}

function summarizeToolRuntime(value) {
  const runtime = object(value);
  const rawId = boundedString(runtime?.id, 128);
  const toolId = rawId && /^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(rawId)
    ? rawId
    : null;
  if (!toolId) return null;
  const evidence = object(runtime.verificationEvidence);
  return {
    id: toolId,
    name: toolRuntimeName(runtime.name),
    state: safeEnum(runtime.state, TOOL_RUNTIME_STATES, "unknown"),
    locked: typeof runtime.locked === "boolean" ? runtime.locked : null,
    installed: typeof runtime.installed === "boolean" ? runtime.installed : null,
    verified: typeof runtime.verified === "boolean" ? runtime.verified : null,
    executable: typeof runtime.executable === "boolean" ? runtime.executable : null,
    ...(evidence ? { verificationEvidence: {
      kind: safeEnum(evidence.kind, new Set([
        "installation-receipt",
        "current-bytes-and-install-smoke-evidence",
        "current-bytes-and-live-zero-egress-smoke"
      ]), null),
      lastVerifiedAt: timestamp(evidence.lastVerifiedAt),
      ageSeconds: nonNegativeInteger(evidence.ageSeconds),
      current: typeof evidence.current === "boolean" ? evidence.current : null,
      currentBytesChecked: typeof evidence.currentBytesChecked === "boolean" ? evidence.currentBytesChecked : null,
      liveSmokeExecutedNow: typeof evidence.liveSmokeExecutedNow === "boolean" ? evidence.liveSmokeExecutedNow : null
    } } : {}),
    reasons: toolRuntimeReasons(runtime.reasons)
  };
}

/**
 * Project managed runtime status through an explicit metadata allowlist. Raw
 * verification exceptions may contain private paths, so unknown reason text is
 * represented by one generic integrity signal rather than copied verbatim.
 */
export function summarizeToolRuntimes(value) {
  const summary = object(value) || {};
  const reasonCounts = new Map();
  if (Array.isArray(summary.unresolvedConstraints)) {
    for (const raw of summary.unresolvedConstraints.slice(0, MAX_TOOL_RUNTIMES)) {
      const constraint = object(raw);
      const reason = toolRuntimeReason(constraint?.reason);
      const count = nonNegativeInteger(constraint?.count);
      if (!reason || count === null) continue;
      reasonCounts.set(reason, Math.min(Number.MAX_SAFE_INTEGER, (reasonCounts.get(reason) || 0) + count));
    }
  }
  return {
    ok: typeof summary.ok === "boolean" ? summary.ok : null,
    verificationMode: safeEnum(summary.verificationMode, TOOL_RUNTIME_VERIFICATION_MODES, null),
    ...(typeof summary.currentBytesChecked === "boolean"
      ? { currentBytesChecked: summary.currentBytesChecked }
      : {}),
    ...(nonNegativeInteger(summary.executableHashReads) !== null
      ? { executableHashReads: nonNegativeInteger(summary.executableHashReads) }
      : {}),
    platform: safeEnum(summary.platform, TOOL_RUNTIME_PLATFORMS, null),
    catalog: nonNegativeInteger(summary.catalog),
    locked: nonNegativeInteger(summary.locked),
    installed: nonNegativeInteger(summary.installed),
    verified: nonNegativeInteger(summary.verified),
    executable: nonNegativeInteger(summary.executable),
    unresolved: nonNegativeInteger(summary.unresolved),
    unresolvedConstraints: [...reasonCounts]
      .map(([reason, count]) => ({ reason, count }))
      .sort((left, right) => right.count - left.count || left.reason.localeCompare(right.reason)),
    tools: Array.isArray(summary.tools)
      ? summary.tools.slice(0, MAX_TOOL_RUNTIMES).map(summarizeToolRuntime).filter(Boolean)
      : []
  };
}

function summarizeEngagement(value, execution) {
  const engagement = object(value);
  if (!engagement) return null;
  const metadata = object(engagement.metadata);
  const review = object(engagement.review) || {};
  const noMistakes = object(review.noMistakes ?? review.technical) || {};
  const operator = object(review.operatorReceipt ?? review.operator) || {};
  const authorization = object(engagement.authorization) || {};
  const limits = object(engagement.limits) || {};
  const engagementId = id(metadata?.id ?? engagement.id);
  const status = safeEnum(metadata?.status ?? engagement.status, ENGAGEMENT_STATUSES, null);
  if (!engagementId || !status) return null;
  return {
    id: opaqueId("engagement", engagementId),
    status,
    technicalReview: safeEnum(noMistakes.status, TECHNICAL_REVIEW_STATUSES, "unknown"),
    operatorReceipt: safeEnum(operator.status, OPERATOR_RECEIPT_STATUSES, "unknown"),
    manifestRequired: true,
    executionLaneAvailable: execution.laneAvailable,
    executionMode: execution.mode,
    executionEligibility: "manifest-required",
    attestation: {
      operatorProvenance: "local-unverified",
      noMistakesReview: "local-unverified"
    },
    validUntil: timestamp(authorization.validUntil ?? authorization.valid_until),
    maxTokens: nonNegativeInteger(limits.maxTokens ?? limits.max_tokens)
  };
}

function summarizeUpstream(value) {
  const upstream = object(value);
  const upstreamId = identifier(upstream?.id);
  if (!upstreamId) return null;
  const integrityState = safeEnum(upstream.integrityState, UPSTREAM_INTEGRITY, "unknown");
  return {
    id: upstreamId,
    version: boundedString(upstream.version, 80),
    installed: upstream.installed === true,
    integrityState,
    ready: integrityState === "verified" && upstream.ready === true,
    commit: typeof upstream.commit === "string" && /^[a-f0-9]{40}$/u.test(upstream.commit) ? upstream.commit : null
  };
}

function summarizeProject(value, execution) {
  const project = object(value);
  const status = safeEnum(project?.status, PROJECT_STATUSES, null);
  // Invalid registry entries can contain any filesystem-valid name. Hash the
  // raw nonempty name so corrupt entries remain visible without exposing it.
  const privateId = status === "invalid" && typeof project?.registryEntry === "string" && project.registryEntry
    ? project.registryEntry
    : boundedString(project?.id, 128);
  if (!privateId || !status) return null;
  return {
    id: opaqueId("project", privateId),
    status,
    provider: safeEnum(project.provider, PROJECT_PROVIDERS, null),
    environment: safeEnum(project.environment, PROJECT_ENVIRONMENTS, null),
    deliveryMode: safeEnum(project.deliveryMode, PROJECT_DELIVERY_MODES, null),
    deploymentConfigured: typeof project.deploymentEnabled === "boolean" ? project.deploymentEnabled : null,
    activeTestingConfigured: typeof project.activeTestingEnabled === "boolean" ? project.activeTestingEnabled : null,
    executionLaneAvailable: execution.laneAvailable,
    executionEligibility: "not-evaluated"
  };
}

function summarizeCaseBinding(value, prefix) {
  const binding = object(value);
  const privateId = id(binding?.id);
  if (!privateId || typeof binding.current !== "boolean") return null;
  return { id: opaqueId(prefix, privateId), current: binding.current };
}

function summarizeCaseRuntimeHealth(value, caseStatus, hasRuntime) {
  const health = object(value);
  const status = safeEnum(health?.status, CASE_RUNTIME_HEALTH_STATUSES, null);
  const reason = health?.reason === null ? null : safeEnum(health?.reason, CASE_RUNTIME_HEALTH_REASONS, null);
  if (caseStatus === "invalid") return { status: "unavailable", reason: "invalid-case" };
  if (status === "available" && reason === null) return { status, reason };
  if (status === "unavailable" && reason === "runtime-observation-failed") return { status, reason };
  return hasRuntime
    ? { status: "available", reason: null }
    : { status: "unavailable", reason: "runtime-observation-failed" };
}

function summarizeCase(value, paths) {
  const item = object(value);
  const privateId = id(item?.id);
  const status = safeEnum(item?.status, CASE_STATUSES, null);
  if (!privateId || !status) return null;
  if (status === "invalid") {
    return {
      id: opaqueId("case", privateId),
      displayName: "Invalid case",
      status,
      binding: null,
      isolation: null,
      runtimeHealth: summarizeCaseRuntimeHealth(item?.runtimeHealth, status, false),
      state: "blocked",
      counts: {},
      telemetry: { freshness: "unknown", lastActivityAt: null, ageSeconds: null },
      usage: summarizeCaseUsage(null),
      execution: summarizeExecution(null),
      workflows: summarizeWorkflows(null),
      engagementScan: summarizeEngagementScan(null),
      offlineAnalysis: summarizeOfflineAnalysis(null),
      activity: [],
      learningCount: 0,
      ctfPilot: unavailablePilot("invalid")
    };
  }
  const displayName = localDisplayName(item?.displayName);
  const binding = object(item?.binding);
  const program = summarizeCaseBinding(binding?.program, "program");
  const project = binding?.project === null ? null : summarizeCaseBinding(binding?.project, "project");
  const isolation = object(item?.isolation);
  if (!displayName || !program || (binding?.project !== null && !project) ||
    !isolation || !CASE_STATE_NAMESPACES.has(isolation.stateNamespace) ||
    !CASE_PROCESS_BOUNDARIES.has(isolation.processBoundary) ||
    !CASE_NETWORK_BOUNDARIES.has(isolation.networkBoundary)) return null;

  const bindingsCurrent = program.current === true && (project === null || project.current === true);
  const bindingStatus = status === "ready" && !bindingsCurrent
    ? "stale"
    : status === "stale" && bindingsCurrent
      ? "ready"
      : status;
  const runtimeHealth = summarizeCaseRuntimeHealth(item?.runtimeHealth, bindingStatus, object(item.runtime) !== null);

  let runtime = null;
  if (runtimeHealth.status === "available" && object(item.runtime)) {
    // Reuse the same strict projection used by the top-level observer and then
    // retain a bounded per-case subset. This keeps case terminals unable to
    // cross the raw event/argv/evidence boundary.
    const projected = projectSnapshot({ ...item.runtime, cases: [], caseScan: null }, paths);
    runtime = {
      state: summarizeCaseState(projected.status),
      counts: projected.status.counts,
      telemetry: projected.status.telemetry,
      usage: summarizeCaseUsage(projected.status.usage),
      execution: {
        ...projected.status.execution,
        recent: projected.status.execution.recent.slice(0, 8)
      },
      workflows: {
        ...projected.status.workflows,
        instances: projected.status.workflows.instances.slice(0, 12)
      },
      engagementScan: summarizeEngagementScan(projected.status.engagementScan),
      offlineAnalysis: {
        ...projected.status.offlineAnalysis,
        recent: projected.status.offlineAnalysis.recent.slice(0, 6)
      },
      activity: projected.events.events.slice(0, 20),
      learningCount: projected.learnings.learnings.length,
      ctfPilot: projected.status.ctfPilot
    };
  }
  return {
    id: opaqueId("case", privateId),
    displayName,
    status: bindingStatus,
    binding: { program, project },
    isolation: {
      stateNamespace: isolation.stateNamespace,
      processBoundary: isolation.processBoundary,
      networkBoundary: isolation.networkBoundary
    },
    runtimeHealth,
    state: runtime?.state || "blocked",
    counts: runtime?.counts || {},
    telemetry: runtime?.telemetry || { freshness: "unknown", lastActivityAt: null, ageSeconds: null },
    usage: runtime?.usage || summarizeCaseUsage(null),
    execution: runtime?.execution || summarizeExecution(null),
    workflows: runtime?.workflows || summarizeWorkflows(null),
    engagementScan: runtime?.engagementScan || summarizeEngagementScan(null),
    offlineAnalysis: runtime?.offlineAnalysis || summarizeOfflineAnalysis(null),
    activity: runtime?.activity || [],
    learningCount: runtime?.learningCount ?? 0,
    ctfPilot: runtime?.ctfPilot || unavailablePilot(runtimeHealth.status === "available" ? "missing" : "invalid")
  };
}

function summarizeCaseScan(value, visible, projectionInvalid, overflow) {
  const scan = object(value) || {};
  const hasScanObservation = ["discovered", "scanned", "omitted", "invalid", "complete", "truncated"]
    .some((key) => Object.hasOwn(scan, key));
  const availability = scan.attempted === false
    ? "unavailable"
    : Object.hasOwn(scan, "availability")
      ? safeEnum(scan.availability, CASE_SCAN_AVAILABILITY, "unavailable")
      : hasScanObservation || scan.attempted === true ? "available" : "unavailable";
  if (availability === "unavailable") {
    return {
      availability,
      discovered: null,
      scanned: null,
      omitted: null,
      invalid: null,
      discoveredAtLeast: false,
      omittedAtLeast: false,
      complete: false,
      truncated: true
    };
  }
  const rawDiscovered = nonNegativeInteger(scan.discovered);
  const rawScanned = nonNegativeInteger(scan.scanned);
  const rawOmitted = nonNegativeInteger(scan.omitted);
  const rawInvalidValue = nonNegativeInteger(scan.invalid);
  const rawInvalid = rawInvalidValue ?? 0;
  const projectedScanned = visible + projectionInvalid;
  const scanOverflow = Math.max(overflow, Math.max(0, (rawScanned ?? 0) - MAX_CASE_RECORDS));
  const scanned = Math.min(
    MAX_CASE_RECORDS,
    Math.max(projectedScanned, Math.min(rawScanned ?? projectedScanned, MAX_CASE_RECORDS))
  );
  const omitted = Math.max(
    rawOmitted ?? 0,
    scanOverflow,
    Math.max(0, (rawDiscovered ?? scanned) - scanned)
  );
  const discovered = Math.max(rawDiscovered ?? 0, scanned + omitted);
  const invalid = Math.min(scanned, Math.max(rawInvalid, projectionInvalid));
  const discoveredAtLeast = typeof scan.discoveredAtLeast === "boolean" ? scan.discoveredAtLeast : false;
  const omittedAtLeast = typeof scan.omittedAtLeast === "boolean" ? scan.omittedAtLeast : false;
  const countersPresent = [rawDiscovered, rawScanned, rawOmitted, rawInvalidValue]
    .every((item) => item !== null);
  const counterInconsistent = !countersPresent ||
    (rawScanned !== null && rawScanned < projectedScanned) ||
    (rawDiscovered !== null && rawScanned !== null && rawDiscovered < rawScanned) ||
    rawInvalid > scanned;
  const projectionConsistent = projectedScanned === scanned;
  const coverageConsistent = discovered === scanned + omitted;
  const consistencyFailure = counterInconsistent || !projectionConsistent || !coverageConsistent;
  const exactCoverage = invalid === 0 && omitted === 0 && projectionInvalid === 0 && scanOverflow === 0 &&
    !discoveredAtLeast && !omittedAtLeast && !consistencyFailure;
  const contradictoryCompleteClaim = scan.complete === true && (scan.truncated !== false || !exactCoverage);
  return {
    availability,
    discovered: discovered ?? visible,
    scanned: scanned ?? visible,
    omitted: omitted ?? 0,
    invalid: invalid ?? 0,
    discoveredAtLeast,
    omittedAtLeast,
    complete: scan.complete === true && scan.truncated === false && exactCoverage,
    truncated: (typeof scan.truncated === "boolean" ? scan.truncated : true) || omitted > 0 ||
      scanOverflow > 0 || discoveredAtLeast || omittedAtLeast || consistencyFailure || contradictoryCompleteClaim
  };
}

function summarizeProfileSetup(value) {
  const setup = object(value);
  const hasNextSection = Boolean(setup && Object.hasOwn(setup, "nextSection"));
  const privateId = id(setup?.id);
  const stage = safeEnum(setup?.stage, PROFILE_SETUP_STAGES, null);
  const readiness = safeEnum(setup?.readiness, PROFILE_SETUP_READINESS, null);
  const progress = object(setup?.progress);
  const answered = nonNegativeInteger(progress?.answered);
  const total = nonNegativeInteger(progress?.total);
  const blockerCount = nonNegativeInteger(setup?.blockerCount);
  const rawNextSection = setup?.nextSection;
  const nextSection = rawNextSection === null
    ? null
    : safeEnum(rawNextSection, PROFILE_SETUP_NEXT_SECTIONS, null);
  const recommendationMode = setup?.recommendationMode === null || setup?.recommendationMode === undefined
    ? null
    : safeEnum(setup?.recommendationMode, PROFILE_SETUP_RECOMMENDATION_MODES, null);
  const updatedAt = timestamp(setup?.updatedAt);
  const boundedProgress = answered !== null && total !== null && answered <= total;
  const completeProgress = boundedProgress && total > 0 && answered === total;
  const pendingProgress = boundedProgress && answered < total;
  // Superseded is terminal, so a legacy or abandoned 0/0 intake remains a
  // truthful aggregate as long as it has no actionable next section.
  const stateConsistent = stage === "questionnaire"
    ? readiness === "not-ready" && pendingProgress && blockerCount > 0 && nextSection !== null
    : stage === "operator-review"
      ? readiness === "not-ready" && completeProgress && blockerCount > 0 && nextSection === null
      : stage === "ready"
        ? readiness === "ready" && completeProgress && blockerCount === 0 && nextSection === null
        : stage === "superseded" && readiness === "not-ready" && boundedProgress && nextSection === null;
  if (!privateId || !stage || !readiness || answered === null || total === null || answered > total ||
      blockerCount === null || updatedAt === null || !hasNextSection || !stateConsistent ||
      (rawNextSection !== null && nextSection === null) ||
      (setup?.recommendationMode !== null && setup?.recommendationMode !== undefined && recommendationMode === null)) {
    return null;
  }
  return {
    id: opaqueId("program", privateId),
    displayName: null,
    stage,
    readiness,
    progress: { answered, total },
    blockerCount,
    nextSection,
    recommendationMode,
    updatedAt,
    freshness: "fresh"
  };
}

function summarizeProfileSetupScan(value, visible, representedByCases, projectionInvalid, overflow) {
  const scan = object(value) || {};
  const rawDiscovered = nonNegativeInteger(scan.discovered);
  const rawScanned = nonNegativeInteger(scan.scanned);
  const rawOmitted = nonNegativeInteger(scan.omitted);
  const rawInvalidValue = nonNegativeInteger(scan.invalid);
  const rawInvalid = rawInvalidValue ?? 0;
  const projectedValid = visible + representedByCases;
  const projectedScanned = projectedValid + projectionInvalid;
  const scanOverflow = Math.max(overflow, Math.max(0, (rawScanned ?? 0) - MAX_PROFILE_SETUP_RECORDS));
  const scanned = Math.min(
    MAX_PROFILE_SETUP_RECORDS,
    Math.max(projectedScanned, Math.min(rawScanned ?? projectedScanned, MAX_PROFILE_SETUP_RECORDS))
  );
  const invalidCapacity = Math.max(0, scanned - projectedValid);
  const invalid = Math.min(invalidCapacity, projectionInvalid + rawInvalid);
  const countersPresent = [rawDiscovered, rawScanned, rawOmitted, rawInvalidValue]
    .every((item) => item !== null);
  const counterInconsistent = !countersPresent ||
    (rawScanned !== null && rawScanned < projectedScanned) ||
    (rawDiscovered !== null && rawScanned !== null && rawDiscovered < rawScanned) ||
    projectionInvalid + rawInvalid > invalidCapacity;
  const omitted = Math.max(
    rawOmitted ?? 0,
    scanOverflow,
    Math.max(0, (rawDiscovered ?? scanned) - scanned)
  );
  const discovered = Math.max(rawDiscovered ?? 0, scanned + omitted);
  const discoveredAtLeast = typeof scan.discoveredAtLeast === "boolean" ? scan.discoveredAtLeast : false;
  const omittedAtLeast = typeof scan.omittedAtLeast === "boolean" ? scan.omittedAtLeast : false;
  const accountingConsistent = projectedValid + invalid === scanned;
  const coverageConsistent = discovered === scanned + omitted;
  const hasScanObservation = ["discovered", "scanned", "omitted", "invalid", "complete", "truncated"]
    .some((key) => Object.hasOwn(scan, key));
  const availability = Object.hasOwn(scan, "availability")
    ? safeEnum(scan.availability, PROFILE_SETUP_SCAN_AVAILABILITY, "unavailable")
    : hasScanObservation ? "available" : "unavailable";
  const unavailable = availability === "unavailable";
  const consistencyFailure = counterInconsistent || !accountingConsistent || !coverageConsistent;
  const exactCoverage = projectionInvalid === 0 && invalid === 0 && omitted === 0 && scanOverflow === 0 &&
    !discoveredAtLeast && !omittedAtLeast && !consistencyFailure;
  const contradictoryCompleteClaim = scan.complete === true && (scan.truncated !== false || !exactCoverage);
  return {
    availability,
    discovered: unavailable ? null : discovered,
    scanned: unavailable ? null : scanned,
    omitted: unavailable ? null : omitted,
    invalid: unavailable ? null : invalid,
    visible,
    representedByCases: unavailable ? null : representedByCases,
    discoveredAtLeast: unavailable ? false : discoveredAtLeast,
    omittedAtLeast: unavailable ? false : omittedAtLeast,
    complete: !unavailable && scan.complete === true && scan.truncated === false && exactCoverage,
    truncated: unavailable || (typeof scan.truncated === "boolean" ? scan.truncated : true) ||
      omitted > 0 || scanOverflow > 0 || discoveredAtLeast || omittedAtLeast || consistencyFailure ||
      contradictoryCompleteClaim
  };
}

function summarizeEngagementScan(value) {
  const scan = object(value) || {};
  const notLoaded = scan.availability === "not-loaded";
  const loaded = !notLoaded && (
    typeof scan.complete === "boolean" ||
    nonNegativeInteger(scan.scanned) !== null ||
    nonNegativeInteger(scan.discoveredAtLeast) !== null ||
    nonNegativeInteger(scan.invalid) !== null
  );
  return {
    availability: notLoaded ? "not-loaded" : loaded ? "loaded" : "unavailable",
    reason: notLoaded && scan.reason === "aggregate-case-detail-elided" ? scan.reason : null,
    limit: nonNegativeInteger(scan.limit),
    discoveryLimit: nonNegativeInteger(scan.discoveryLimit),
    entriesInspected: nonNegativeInteger(scan.entriesInspected),
    discoveredAtLeast: nonNegativeInteger(scan.discoveredAtLeast),
    scanned: nonNegativeInteger(scan.scanned),
    omittedAtLeast: nonNegativeInteger(scan.omittedAtLeast),
    invalid: nonNegativeInteger(scan.invalid),
    recordsRead: nonNegativeInteger(scan.recordsRead),
    complete: typeof scan.complete === "boolean" ? scan.complete : false,
    truncated: loaded
      ? typeof scan.truncated === "boolean" ? scan.truncated : true
      : !notLoaded,
    discoveryTruncated: typeof scan.discoveryTruncated === "boolean" ? scan.discoveryTruncated : false
  };
}

function configuredBudget(paths) {
  try {
    const config = JSON.parse(fs.readFileSync(path.join(paths.repo, "config", "gate.config.json"), "utf8"));
    const limitTokens = nonNegativeInteger(config?.execution?.boundedLoops?.maxTokens);
    return {
      limitTokens,
      usedTokens: null,
      remainingTokens: null,
      status: limitTokens === null ? "unavailable" : "configured",
      source: limitTokens === null ? "unavailable" : "bounded-loop-default"
    };
  } catch {
    return { limitTokens: null, usedTokens: null, remainingTokens: null, status: "unavailable", source: "unavailable" };
  }
}

export function projectSnapshot(rawStatus, paths) {
  const raw = object(rawStatus) || {};
  const events = Array.isArray(raw.events) ? raw.events.map(projectEvent).filter(Boolean) : [];
  events.sort((left, right) => Date.parse(right.at) - Date.parse(left.at));
  const learningPairs = Array.isArray(raw.learnings)
    ? raw.learnings.map((source) => ({ source, projected: projectLearning(source) }))
      .filter(({ projected }) => Boolean(projected))
    : [];
  const learningById = new Map(learningPairs.map((pair) => [pair.source.id, pair]));
  const replacedLearningIds = new Set();
  for (const pair of learningPairs) {
    const source = pair.source;
    if (source.apiVersion !== "gate.learning/v2" || source.status !== "active" || source.promotion?.state !== "validated") continue;
    for (const replacedId of source.promotion.replaces) {
      const target = learningById.get(replacedId)?.source;
      if (!target || target.apiVersion !== "gate.learning/v2" || target.status !== "active" ||
        target.promotion?.state !== "validated" || target.sensitivity !== source.sensitivity ||
        target.domain !== source.domain ||
        learningApplicabilityKey(target.applicability) !== learningApplicabilityKey(source.applicability)) continue;
      replacedLearningIds.add(replacedId);
    }
  }
  learningPairs.sort((left, right) => Date.parse(right.projected.at) - Date.parse(left.projected.at));
  const agents = latestBy(
    events,
    (event) => event.agent ? [event.runId, event.taskId || "", event.agent].join(":") : null
  ).map((event) => projectMember(event, event.agent, "member"));
  const tasks = latestBy(events, (event) => event.taskId || event.runId).map((event) => {
    return projectMember(event, event.taskId || event.runId, event.taskId ? "task" : "run");
  });
  const members = agents.length ? agents : tasks;
  const count = (status) => members.filter((member) => member.status === status).length;
  const counts = {
    queued: count("queued"),
    running: count("running"),
    waiting: count("waiting"),
    blocked: count("blocked"),
    failed: count("failed"),
    succeeded: count("succeeded"),
    unknown: count("unknown"),
    agents: agents.length,
    tasks: tasks.length
  };
  const rawCases = Array.isArray(raw.cases) ? raw.cases : [];
  const boundedCases = rawCases.slice(0, MAX_CASE_RECORDS);
  const cases = boundedCases.map((value) => summarizeCase(value, paths)).filter(Boolean);
  const caseProjectionInvalid = boundedCases.length - cases.length;
  const caseOverflow = Math.max(0, rawCases.length - boundedCases.length);
  const representedPrograms = new Set(cases
    .filter((item) => item.binding?.program?.current === true)
    .map((item) => item.binding.program.id));
  const rawProfileSetups = Array.isArray(raw.profileSetups) ? raw.profileSetups : [];
  const boundedProfileSetups = rawProfileSetups.slice(0, MAX_PROFILE_SETUP_RECORDS);
  const profileSetupOverflow = Math.max(0, rawProfileSetups.length - boundedProfileSetups.length);
  const projectedProfileSetupRows = boundedProfileSetups.map(summarizeProfileSetup).filter(Boolean);
  const profileSetupIdCounts = new Map();
  for (const item of projectedProfileSetupRows) {
    profileSetupIdCounts.set(item.id, (profileSetupIdCounts.get(item.id) || 0) + 1);
  }
  const projectedProfileSetups = projectedProfileSetupRows.filter((item) => profileSetupIdCounts.get(item.id) === 1);
  const profileSetupProjectionInvalid = boundedProfileSetups.length - projectedProfileSetups.length;
  const representedByCases = projectedProfileSetups.reduce(
    (total, item) => total + (representedPrograms.has(item.id) ? 1 : 0),
    0
  );
  const profileSetups = projectedProfileSetups.filter((item) => !representedPrograms.has(item.id));
  for (const key of ["queued", "running", "waiting", "blocked", "failed", "succeeded", "unknown"]) {
    counts[key] += cases.reduce((total, item) => total + Number(item.counts?.[key] || 0), 0);
  }
  const workflowInputPresent = object(raw.workflows) !== null;
  const workflows = summarizeWorkflows(raw.workflows);
  const workflowBlocked = workflowInputPresent && (
    workflows.scan.complete !== true ||
    Number(workflows.counts.stopped || 0) > 0 ||
    Number(workflows.counts["recovery-hold"] || 0) > 0 ||
    Number(workflows.counts.degraded || 0) > 0 ||
    Number(workflows.counts.unknown || 0) > 0
  );
  const workflowRunning = workflowInputPresent && Number(workflows.counts.active || 0) > 0;
  const workflowWaiting = workflowInputPresent && (
    Number(workflows.counts.open || 0) > 0 || Number(workflows.counts.reported || 0) > 0
  );
  const caseStates = new Set(cases.map((item) => item.state));
  const state = counts.failed > 0 || caseStates.has("failed")
    ? "failed"
    : counts.blocked > 0 || workflowBlocked || caseStates.has("blocked")
      ? "blocked"
      : counts.waiting > 0 || caseStates.has("waiting")
        ? "waiting"
        : counts.running > 0 || workflowRunning || caseStates.has("running")
          ? "running"
          : workflowWaiting
            ? "waiting"
            : members.length || workflowInputPresent
              ? "idle"
              : "unknown";
  const usage = projectUsage(raw.tokens);
  const lastActivityAt = [
    events[0]?.at,
    usage.sessions.map((session) => session.at).filter(Boolean).sort().at(-1),
    ...cases.map((item) => item.telemetry.lastActivityAt)
  ].filter(Boolean).sort((left, right) => Date.parse(right) - Date.parse(left))[0] || null;
  const generatedAt = timestamp(raw.at) || new Date().toISOString();
  const ageSeconds = lastActivityAt ? Math.max(0, Math.floor((Date.now() - Date.parse(lastActivityAt)) / 1000)) : null;
  const freshness = ageSeconds === null ? "unknown" : ageSeconds > 30 ? "stale" : "fresh";
  const budget = configuredBudget(paths);
  const latestSession = usage.sessions
    .filter((session) => session.at)
    .sort((left, right) => Date.parse(right.at) - Date.parse(left.at))[0];
  const dashboardUsage = {
    ...usage,
    updatedAt: latestSession?.at || null,
    model: latestSession?.model || null,
    context: { usedTokens: null, windowTokens: latestSession?.contextWindow ?? null },
    budget: { usedTokens: null, limitTokens: budget.limitTokens }
  };
  const execution = summarizeExecution(raw.execution);
  const offlineAnalysis = summarizeOfflineAnalysis(raw.offlineAnalysis);
  const toolRuntimes = summarizeToolRuntimes(raw.toolRuntimes);
  return {
    status: {
      apiVersion: OBSERVER_API_VERSION,
      at: generatedAt,
      state,
      counts,
      agents,
      tasks,
      usage: dashboardUsage,
      budget,
      telemetry: { freshness, lastActivityAt, ageSeconds },
      execution,
      workflows,
      engagementScan: summarizeEngagementScan(raw.engagementScan),
      offlineAnalysis,
      toolRuntimes,
      ctfPilot: summarizeCtfPilot(raw.ctfPilot, { observedAt: generatedAt }),
      operator: {
        displayName: sanitizeOperatorDisplayName(raw.operator?.displayName)
      },
      cases,
      caseScan: summarizeCaseScan(raw.caseScan, cases.length, caseProjectionInvalid, caseOverflow),
      profileSetups,
      profileSetupScan: summarizeProfileSetupScan(
        raw.profileSetupScan,
        profileSetups.length,
        representedByCases,
        profileSetupProjectionInvalid,
        profileSetupOverflow
      ),
      engagements: Array.isArray(raw.engagements)
        ? raw.engagements.map((value) => summarizeEngagement(value, execution)).filter(Boolean)
        : [],
      projects: Array.isArray(raw.projects)
        ? raw.projects.map((value) => summarizeProject(value, execution)).filter(Boolean)
        : [],
      upstreams: Array.isArray(raw.upstreams) ? raw.upstreams.map(summarizeUpstream).filter(Boolean) : []
    },
    events: { apiVersion: OBSERVER_API_VERSION, at: generatedAt, events: events.map(publicEvent) },
    learnings: {
      apiVersion: OBSERVER_API_VERSION,
      at: generatedAt,
      learnings: learningPairs.map(({ source, projected }) =>
        publicLearning(projected, replacedLearningIds.has(source.id) ? "superseded" : projected.status)
      )
    }
  };
}

export function isLoopbackHost(host) {
  if (typeof host !== "string") return false;
  const normalized = host.trim().toLowerCase().replace(/^\[(.*)\]$/u, "$1");
  return normalized === "localhost" || normalized === "::1" || normalized === "0:0:0:0:0:0:0:1" || net.isIP(normalized) === 4 && normalized.startsWith("127.");
}

function requestAuthorityIsLocal(request) {
  const host = request.headers.host;
  if (!host) return false;
  try {
    return isLoopbackHost(new URL(`http://${host}`).hostname);
  } catch {
    return false;
  }
}

function requestOriginIsLocal(request) {
  const origin = request.headers.origin;
  if (!origin || origin === "null") return true;
  try {
    return isLoopbackHost(new URL(origin).hostname);
  } catch {
    return false;
  }
}

function requestFetchSiteIsLocal(request) {
  const fetchSite = request.headers["sec-fetch-site"];
  return typeof fetchSite !== "string" || fetchSite.trim().toLowerCase() !== "cross-site";
}

function securityHeaders(contentType, cacheControl = "no-store") {
  return {
    "Cache-Control": cacheControl,
    "Content-Security-Policy": "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; form-action 'none'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self'",
    "Content-Type": contentType,
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY"
  };
}

function send(response, statusCode, body, contentType, method = "GET", extraHeaders = {}) {
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
  response.writeHead(statusCode, {
    ...securityHeaders(contentType),
    ...extraHeaders,
    "Content-Length": payload.byteLength
  });
  response.end(method === "HEAD" ? undefined : payload);
}

function json(response, statusCode, value, method = "GET", extraHeaders = {}) {
  send(response, statusCode, `${JSON.stringify(value)}\n`, "application/json; charset=utf-8", method, extraHeaders);
}

function preloadStaticFile(root, relative) {
  const file = path.resolve(root, relative);
  const prefix = `${path.resolve(root)}${path.sep}`;
  if (!file.startsWith(prefix) || !MIME_TYPES.has(path.extname(file).toLowerCase())) return null;
  let descriptor;
  try {
    const before = fs.lstatSync(file, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink() || before.size > BigInt(MAX_STATIC_ASSET_BYTES)) return null;
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (
      !opened.isFile() || opened.size > BigInt(MAX_STATIC_ASSET_BYTES) ||
      opened.dev !== before.dev || opened.ino !== before.ino
    ) return null;

    const body = Buffer.alloc(Number(opened.size));
    let offset = 0;
    while (offset < body.byteLength) {
      const read = fs.readSync(descriptor, body, offset, body.byteLength - offset, offset);
      if (read === 0) return null;
      offset += read;
    }
    if (fs.readSync(descriptor, Buffer.alloc(1), 0, 1, offset) !== 0) return null;

    const after = fs.fstatSync(descriptor, { bigint: true });
    if (
      after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size ||
      after.mtimeNs !== opened.mtimeNs || after.ctimeNs !== opened.ctimeNs
    ) return null;
    return {
      body,
      contentType: MIME_TYPES.get(path.extname(file).toLowerCase())
    };
  } catch {
    return null;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function decorateIndexAsset(asset, buildIdentity) {
  const replacements = new Map([
    ["__GATE_VERSION__", buildIdentity.version ?? "unavailable"],
    ["__GATE_VERSION_LABEL__", buildIdentity.version ? `v${buildIdentity.version}` : "version unavailable"],
    ["__GATE_COMMIT_SHORT__", buildIdentity.commitShort ?? "unavailable"],
    ["__GATE_COMMIT_FULL__", buildIdentity.commit ?? "unavailable"],
    ["__GATE_SOURCE_STATE__", buildIdentity.state]
  ]);
  let body = asset.body.toString("utf8");
  for (const [placeholder, replacement] of replacements) body = body.replaceAll(placeholder, replacement);
  return { ...asset, body: Buffer.from(body, "utf8") };
}

function preloadStaticAssets(root) {
  const byFile = new Map();
  for (const relative of new Set(STATIC_FILES.values())) {
    const asset = preloadStaticFile(root, relative);
    if (asset) byFile.set(relative, asset);
  }
  return new Map(
    [...STATIC_FILES].flatMap(([pathname, relative]) => {
      const asset = byFile.get(relative);
      return asset ? [[pathname, asset]] : [];
    })
  );
}

function decorateStaticAssets(assets, buildIdentity) {
  const decorated = new Map();
  let indexAsset;
  for (const [pathname, asset] of assets) {
    if (STATIC_FILES.get(pathname) === "index.html") {
      indexAsset ||= decorateIndexAsset(asset, buildIdentity);
      decorated.set(pathname, indexAsset);
    } else {
      decorated.set(pathname, asset);
    }
  }
  return decorated;
}

function identitiesMatch(left, right) {
  return left.version === right.version && left.commit === right.commit && left.state === right.state;
}

function reconcileBuildIdentity(left, right) {
  if (identitiesMatch(left, right)) return left;
  const version = left.version && left.version === right.version ? left.version : null;
  const commit = left.commit && left.commit === right.commit ? left.commit : null;
  const state = commit && (left.state === "modified" || right.state === "modified")
    ? "modified"
    : "unavailable";
  return normalizeBuildIdentity({ version, commit, state });
}

function safelyObserveBuildIdentity(observer, repo) {
  try {
    return normalizeBuildIdentity(observer(repo));
  } catch {
    return normalizeBuildIdentity(null);
  }
}

function unavailableProfileSetupScan(visible) {
  return {
    availability: "unavailable",
    discovered: null,
    scanned: null,
    omitted: null,
    invalid: null,
    visible,
    representedByCases: null,
    discoveredAtLeast: false,
    omittedAtLeast: false,
    complete: false,
    truncated: true
  };
}

function unavailableCaseScan() {
  return {
    availability: "unavailable",
    discovered: null,
    scanned: null,
    omitted: null,
    invalid: null,
    discoveredAtLeast: false,
    omittedAtLeast: false,
    complete: false,
    truncated: true
  };
}

function projectWithoutCurrentProfileSetups(status, previous, paths) {
  const projected = projectSnapshot({
    ...status,
    profileSetups: [],
    profileSetupScan: { availability: "unavailable" }
  }, paths);
  const representedPrograms = new Set(projected.status.cases
    .filter((item) => item.binding?.program?.current === true)
    .map((item) => item.binding.program.id));
  const cachedSetups = Array.isArray(previous?.status?.profileSetups)
    ? previous.status.profileSetups
      .filter((item) => !representedPrograms.has(item.id))
      .map((item) => ({ ...item, freshness: "stale" }))
    : [];
  projected.status.profileSetups = cachedSetups;
  projected.status.profileSetupScan = unavailableProfileSetupScan(cachedSetups.length);
  return projected;
}

export function createObserver(options = {}) {
  const paths = options.paths;
  if (!paths?.repo) throw new Error("observer paths.repo is required");
  const host = options.host || "127.0.0.1";
  if (!isLoopbackHost(host)) throw new Error("observer must bind to a loopback address");
  const dashboardRoot = path.resolve(options.dashboardRoot || path.join(paths.repo, "dashboard"));
  const suppliedBuildIdentity = options.buildIdentity === undefined
    ? null
    : normalizeBuildIdentity(options.buildIdentity);
  const identityObserver = typeof options.buildIdentityObserver === "function"
    ? options.buildIdentityObserver
    : observeBuildIdentity;
  const identityBeforeSnapshot = suppliedBuildIdentity || safelyObserveBuildIdentity(identityObserver, paths.repo);
  // Static content is snapshotted before the server can listen. Requests never
  // reopen a path, so later replacement or symlink exchange cannot cross the
  // dashboard-root trust boundary.
  const preloadedStaticAssets = preloadStaticAssets(dashboardRoot);
  const buildIdentity = suppliedBuildIdentity || reconcileBuildIdentity(
    identityBeforeSnapshot,
    safelyObserveBuildIdentity(identityObserver, paths.repo)
  );
  const staticAssets = decorateStaticAssets(preloadedStaticAssets, buildIdentity);
  const statusBuilder = options.statusBuilder || buildStatus;
  const profileSetupBuilder = options.profileSetupBuilder === null
    ? null
    : options.profileSetupBuilder || (paths.home ? programProfileSetupFleetStatus : null);
  const requestedRefreshMs = Number(options.refreshMs ?? 2_000);
  const refreshMs = Number.isFinite(requestedRefreshMs) ? Math.max(250, requestedRefreshMs) : 2_000;
  let cached = null;
  let cachedAt = 0;
  let inFlight = null;

  async function snapshot() {
    const now = Date.now();
    if (cached && now - cachedAt < refreshMs) return cached;
    if (inFlight) return inFlight;
    const statusPromise = Promise.resolve().then(() => statusBuilder({ paths }));
    const profileSetupPromise = profileSetupBuilder
      ? Promise.resolve().then(() => profileSetupBuilder({ paths }))
      : Promise.resolve(null);
    inFlight = Promise.allSettled([statusPromise, profileSetupPromise])
      .then(([statusResult, setupResult]) => {
        if (statusResult.status === "rejected") throw statusResult.reason;
        const status = statusResult.value;
        if (setupResult.status === "rejected") {
          cached = projectWithoutCurrentProfileSetups(status, cached, paths);
        } else {
          const setupFleet = setupResult.value;
          const input = setupFleet
            ? { ...status, profileSetups: setupFleet.profiles, profileSetupScan: setupFleet.scan }
            : status;
          cached = projectSnapshot(input, paths);
        }
        cachedAt = Date.now();
        return cached;
      })
      .finally(() => {
        inFlight = null;
      });
    try {
      return await inFlight;
    } catch {
      if (cached) return {
        ...cached,
        status: {
          ...cached.status,
          telemetry: { ...cached.status.telemetry, freshness: "stale" },
          cases: Array.isArray(cached.status.cases)
            ? cached.status.cases.map((item) => ({
                ...item,
                telemetry: { ...item.telemetry, freshness: "stale" }
              }))
            : [],
          caseScan: unavailableCaseScan(),
          profileSetups: Array.isArray(cached.status.profileSetups)
            ? cached.status.profileSetups.map((item) => ({ ...item, freshness: "stale" }))
            : [],
          profileSetupScan: unavailableProfileSetupScan(
            Array.isArray(cached.status.profileSetups) ? cached.status.profileSetups.length : 0
          )
        }
      };
      throw new Error("observer status unavailable");
    }
  }

  return http.createServer(async (request, response) => {
    const method = request.method || "GET";
    if (!requestAuthorityIsLocal(request) || !requestOriginIsLocal(request) || !requestFetchSiteIsLocal(request)) {
      return json(response, 403, { error: "forbidden" }, method);
    }
    if (method !== "GET" && method !== "HEAD") {
      return json(response, 405, { error: "method not allowed" }, method, { Allow: "GET, HEAD" });
    }
    let pathname;
    try {
      pathname = new URL(request.url || "/", `http://${request.headers.host}`).pathname;
    } catch {
      return json(response, 400, { error: "bad request" }, method);
    }
    if (pathname === "/healthz") {
      return json(response, 200, {
        ok: true,
        service: "gate-observer",
        at: new Date().toISOString(),
        build: buildIdentity
      }, method);
    }
    if (pathname === "/api/status" || pathname === "/api/events" || pathname === "/api/learnings") {
      try {
        const current = await snapshot();
        const key = pathname.slice("/api/".length);
        return json(response, 200, current[key], method);
      } catch {
        return json(response, 503, { error: "observer status unavailable" }, method);
      }
    }
    const asset = staticAssets.get(pathname);
    if (!asset) return json(response, 404, { error: "not found" }, method);
    return send(response, 200, asset.body, asset.contentType, method);
  });
}

export async function startObserver(options = {}) {
  const host = options.host || "127.0.0.1";
  const port = Number(options.port ?? 4173);
  if (!Number.isInteger(port) || port < 0 || port > 65_535) throw new Error("observer port must be an integer from 0 to 65535");
  const server = createObserver({ ...options, host });
  await new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, host);
  });
  const address = server.address();
  const listeningPort = typeof address === "object" && address ? address.port : port;
  if (options.quiet !== true) {
    process.stdout.write(terminalWelcomeBanner({ operator: { displayName: options.operatorDisplayName } }));
    process.stdout.write(`GATE observer: http://${host.includes(":") ? `[${host}]` : host}:${listeningPort}\n`);
  }
  return server;
}
