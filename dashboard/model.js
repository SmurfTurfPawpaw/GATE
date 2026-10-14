/*
 * The dashboard treats every response as untrusted. Only fields projected by
 * this module can reach the DOM. Free-form event summaries, prompt content,
 * arguments, results, output, target references, evidence, and paths are never
 * copied into the view model.
 */

const RECORD_LIMIT = 100;
const STRING_LIMIT = 160;
const MAX_COUNT = Number.MAX_SAFE_INTEGER;

const STATUSES = new Set([
  "queued",
  "running",
  "waiting",
  "blocked",
  "succeeded",
  "failed",
  "cancelled",
  "unknown"
]);

const STATUS_ALIASES = new Map([
  ["active", "running"],
  ["in-progress", "running"],
  ["in_progress", "running"],
  ["complete", "succeeded"],
  ["completed", "succeeded"],
  ["passed", "succeeded"],
  ["success", "succeeded"],
  ["error", "failed"],
  ["paused", "waiting"]
]);

const EFFECTS = new Set([
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

const AVAILABILITY = new Set(["exact", "estimated", "unavailable"]);
const FRESHNESS = new Set(["live", "fresh", "stale", "offline", "unknown"]);
const LEARNING_STATUS = new Set(["proposed", "active", "superseded", "reverted"]);
const LEARNING_SCOPE = new Set(["session", "project", "repository"]);
const EXECUTION_MODES = new Set(["supervised-generic"]);
const EXECUTION_REASONS = new Set([
  "unsupported-platform",
  "proc-descriptor-unavailable",
  "proc-process-identity-unavailable"
]);
const EXECUTION_ENFORCED = new Set([
  "engagement-binding",
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
const EXECUTION_RUN_STATUSES = new Set([
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
  "supervision-lost"
]);
const EXECUTION_SIGNALS = new Set([
  "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT", "SIGBUS", "SIGFPE", "SIGKILL",
  "SIGUSR1", "SIGSEGV", "SIGUSR2", "SIGPIPE", "SIGALRM", "SIGTERM", "SIGCHLD", "SIGCONT", "SIGSTOP",
  "SIGTSTP", "SIGTTIN", "SIGTTOU", "SIGURG", "SIGXCPU", "SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH",
  "SIGIO", "SIGPWR", "SIGSYS", "SIGBREAK"
]);
const OFFLINE_ANALYSIS_MODES = new Set(["bubblewrap-offline"]);
const OFFLINE_ANALYSIS_REASONS = new Set(["unavailable"]);
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
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$/;
const EVENT_KIND = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$/;

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function firstDefined(...values) {
  return values.find((value) => value !== undefined && value !== null);
}

function enumValue(value, allowed, fallback) {
  return typeof value === "string" && allowed.has(value) ? value : fallback;
}

function identifier(value, fallback = null, maximum = STRING_LIMIT) {
  if (typeof value !== "string") return fallback;
  const normalized = value.trim().slice(0, maximum);
  return IDENTIFIER.test(normalized) ? normalized : fallback;
}

function timestamp(value) {
  if (typeof value !== "string" || value.length > 40) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
}

function count(value) {
  const numeric = typeof value === "string" && /^\d+$/.test(value) ? Number(value) : value;
  if (!Number.isFinite(numeric) || numeric < 0) return null;
  return Math.min(Math.trunc(numeric), MAX_COUNT);
}

function signedInteger(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return null;
  return Math.max(-2147483648, Math.min(2147483647, Math.trunc(numeric)));
}

function status(value) {
  if (typeof value !== "string") return "unknown";
  const normalized = value.trim().toLowerCase();
  return enumValue(STATUS_ALIASES.get(normalized) || normalized, STATUSES, "unknown");
}

function oneLine(value, maximum = 220) {
  if (typeof value !== "string") return null;
  const normalized = value.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim();
  if (!normalized) return null;
  return normalized.slice(0, maximum);
}

/**
 * Learning cause/change are the only reviewed prose accepted by this client.
 * The server must sanitize them first; this second pass withholds common path,
 * URL, credential, and authorization-header forms before display.
 */
export function safeLearningText(value) {
  const normalized = oneLine(value, 500);
  if (!normalized) return null;

  const redacted = normalized
    .replace(/\b(?:https?|file):\/\/\S+/gi, "[reference withheld]")
    .replace(/\b[A-Za-z]:[\\/][^\s,;]+/g, "[path withheld]")
    .replace(/(^|[\s(])(?:~\/|\.{1,2}\/|\/(?!\/))[A-Za-z0-9._-]+(?:\/[^\s,;)]*)?/g, "$1[path withheld]")
    .replace(/(^|\s)(?:[A-Za-z0-9._-]+\/)+(?:[A-Za-z0-9._-]+\.[A-Za-z0-9_-]+)/g, "$1[path withheld]")
    .replace(/\b(?:sk|pk|ghp|github_pat|xox[baprs])-?[A-Za-z0-9_-]{12,}\b/gi, "[secret withheld]")
    .replace(/\b(?:api[-_ ]?key|access[-_ ]?token)\s*[:=]\s*\S+/gi, "[secret withheld]")
    .replace(/\b(?:authorization|cookie|set-cookie)\s*[:=]\s*[^\r\n]*/gi, "[secret withheld]");
  return redacted.slice(0, 240);
}

function usageShape(input, fallbackUpdatedAt = null) {
  const value = record(input);
  const totals = record(value.totals);
  const nested = record(value.usage);
  const sourceValues = Object.keys(totals).length ? totals : Object.keys(nested).length ? nested : value;
  const availability = enumValue(value.availability, AVAILABILITY, "unavailable");

  const sessions = Array.isArray(value.sessions) ? value.sessions : [];
  const newestSession = sessions
    .map((session) => record(session))
    .filter((session) => timestamp(firstDefined(session.modified_at, session.updatedAt)))
    .sort((left, right) => Date.parse(firstDefined(right.modified_at, right.updatedAt)) - Date.parse(firstDefined(left.modified_at, left.updatedAt)))[0];

  const contextObject = record(value.context);
  const budgetObject = record(value.budget);
  const unavailable = availability === "unavailable";
  const sessionContextWindow = count(firstDefined(newestSession?.context_window, newestSession?.contextWindow));

  return {
    availability,
    source: identifier(value.source, null, 80),
    model: identifier(firstDefined(value.model, newestSession?.model), null, 80),
    updatedAt: timestamp(firstDefined(value.updatedAt, value.at, newestSession?.modified_at, fallbackUpdatedAt)),
    inputTokens: unavailable ? null : count(firstDefined(sourceValues.inputTokens, sourceValues.input, sourceValues.input_tokens)),
    cachedInputTokens: unavailable
      ? null
      : count(firstDefined(sourceValues.cachedInputTokens, sourceValues.cached_input, sourceValues.cached_input_tokens)),
    outputTokens: unavailable ? null : count(firstDefined(sourceValues.outputTokens, sourceValues.output, sourceValues.output_tokens)),
    reasoningTokens: unavailable
      ? null
      : count(firstDefined(sourceValues.reasoningTokens, sourceValues.reasoning, sourceValues.reasoning_tokens)),
    totalTokens: unavailable ? null : count(firstDefined(sourceValues.totalTokens, sourceValues.total, sourceValues.total_tokens)),
    context: {
      usedTokens: unavailable
        ? null
        : count(firstDefined(contextObject.usedTokens, contextObject.used, value.contextUsedTokens, value.context_used_tokens)),
      windowTokens: count(
        firstDefined(contextObject.windowTokens, contextObject.window, value.modelContextWindow, value.context_window, sessionContextWindow)
      )
    },
    budget: {
      usedTokens: unavailable
        ? null
        : count(firstDefined(budgetObject.usedTokens, budgetObject.used, value.budgetUsedTokens, value.budget_used_tokens)),
      limitTokens: count(
        firstDefined(budgetObject.limitTokens, budgetObject.limit, value.budgetLimitTokens, value.budget_limit_tokens)
      )
    }
  };
}

function safeCounts(input) {
  const value = record(input);
  return {
    running: count(value.running),
    waiting: count(value.waiting),
    blocked: count(value.blocked),
    failed: count(value.failed),
    queued: count(value.queued),
    succeeded: count(value.succeeded)
  };
}

function capabilityList(value, allowed) {
  if (!Array.isArray(value)) return [];
  const supplied = new Set(value);
  return [...allowed].filter((item) => supplied.has(item));
}

function executionRunShape(input) {
  const value = record(input);
  const runId = typeof value.runId === "string" && /^run_[a-f0-9]{16}$/.test(value.runId) ? value.runId : null;
  const manifestId = typeof value.manifestId === "string" && /^manifest_[a-f0-9]{16}$/.test(value.manifestId)
    ? value.manifestId
    : null;
  const engagementId = typeof value.engagementId === "string" && /^engagement_[a-f0-9]{16}$/.test(value.engagementId)
    ? value.engagementId
    : null;
  const runStatus = enumValue(value.status, EXECUTION_RUN_STATUSES, null);
  const createdAt = timestamp(value.createdAt);
  if (!runId || !manifestId || !engagementId || !runStatus || !createdAt) return null;
  const exitCode = Number.isInteger(value.exitCode) && value.exitCode >= -2_147_483_648 && value.exitCode <= 2_147_483_647
    ? value.exitCode
    : null;
  return {
    runId,
    manifestId,
    engagementId,
    status: runStatus,
    createdAt,
    startedAt: timestamp(value.startedAt),
    finishedAt: timestamp(value.finishedAt),
    terminationReason: enumValue(value.terminationReason, EXECUTION_TERMINATION_REASONS, null),
    exitCode,
    signal: enumValue(value.signal, EXECUTION_SIGNALS, null)
  };
}

function executionShape(input) {
  const value = record(input);
  const counts = record(value.counts);
  const configured = typeof value.configured === "boolean" ? value.configured : null;
  const mode = enumValue(value.mode, EXECUTION_MODES, null);
  const enforced = capabilityList(value.enforced, EXECUTION_ENFORCED);
  const bestEffort = capabilityList(value.bestEffort, EXECUTION_BEST_EFFORT);
  const unavailable = capabilityList(value.unavailable, EXECUTION_UNAVAILABLE);
  const completeCapability = enforced.length === EXECUTION_ENFORCED.size &&
    bestEffort.length === EXECUTION_BEST_EFFORT.size &&
    unavailable.length === EXECUTION_UNAVAILABLE.size;
  const laneAvailable = configured === true && value.laneAvailable === true && mode !== null && completeCapability;
  return {
    configured,
    laneAvailable,
    mode,
    reason: laneAvailable ? null : enumValue(value.reason, EXECUTION_REASONS, null),
    runningCount: count(firstDefined(value.runningCount, counts.running)),
    stoppingCount: count(counts.stopping),
    enforced,
    bestEffort,
    unavailable,
    recent: Array.isArray(value.recent)
      ? value.recent
        .slice(0, RECORD_LIMIT)
        .map(executionRunShape)
        .filter(Boolean)
        .sort((left, right) => Date.parse(right.createdAt) - Date.parse(left.createdAt))
        .slice(0, 30)
      : []
  };
}

function offlineAnalysisRunShape(input) {
  const value = record(input);
  const runId = typeof value.runId === "string" && /^run_[a-f0-9]{16}$/.test(value.runId) ? value.runId : null;
  const runStatus = enumValue(value.status, OFFLINE_ANALYSIS_STATUSES, null);
  if (!runId || !runStatus) return null;
  return {
    runId,
    status: runStatus,
    isolationVerified: typeof value.isolationVerified === "boolean" ? value.isolationVerified : null
  };
}

function offlineRetentionShape(input) {
  const value = record(input);
  const retention = {};
  for (const field of [
    "quotaBytes", "quotaArtifacts", "retainedBytes", "availableBytes", "retainedArtifacts", "availableArtifacts", "pendingManifests",
    "pendingTransactions", "invalidTransactionRecords", "creatingManifests", "invalidCreationIntents",
    "invalidClaimRecords", "invalidPurgeRecords", "invalidRunRecords", "blockedManifests",
    "expiredManifests", "activeManifests", "terminalManifests", "unknownManifests",
    "purgePendingManifests", "purgedManifests", "orphanedArtifacts", "orphanedBytes",
    "missingArtifacts", "invalidEntries"
  ]) retention[field] = count(value[field]);
  retention.retentionLockState = enumValue(value.retentionLockState, OFFLINE_RETENTION_LOCK_STATES, null);
  retention.snapshotState = enumValue(value.snapshotState, OFFLINE_SNAPSHOT_STATES, null);
  retention.overQuota = typeof value.overQuota === "boolean" ? value.overQuota : null;
  retention.mutationBlocked = typeof value.mutationBlocked === "boolean" ? value.mutationBlocked : null;
  return retention;
}

function offlineAnalysisShape(input) {
  const value = record(input);
  const rawCounts = record(value.counts);
  const configured = typeof value.configured === "boolean" ? value.configured : null;
  const mode = enumValue(value.mode, OFFLINE_ANALYSIS_MODES, null);
  const enforced = capabilityList(value.enforced, OFFLINE_ANALYSIS_ENFORCED);
  const unavailable = capabilityList(value.unavailable, OFFLINE_ANALYSIS_UNAVAILABLE);
  const completeCapability = enforced.length === OFFLINE_ANALYSIS_ENFORCED.size &&
    unavailable.length === OFFLINE_ANALYSIS_UNAVAILABLE.size;
  const laneAvailable = configured === true && value.laneAvailable === true && mode !== null && completeCapability;
  const counts = Object.fromEntries(
    [...OFFLINE_ANALYSIS_STATUSES].map((runStatus) => [runStatus, count(rawCounts[runStatus])])
  );
  return {
    configured,
    laneAvailable,
    mode,
    reason: laneAvailable ? null : enumValue(value.reason, OFFLINE_ANALYSIS_REASONS, null),
    runningCount: count(firstDefined(value.runningCount, rawCounts.running)),
    counts,
    retention: offlineRetentionShape(value.retention),
    recent: Array.isArray(value.recent)
      ? value.recent
        .slice(0, RECORD_LIMIT)
        .map(offlineAnalysisRunShape)
        .filter(Boolean)
        .slice(0, 25)
      : []
  };
}

function agentShape(input) {
  const value = record(input);
  const agentName = identifier(firstDefined(value.agent, value.name, value.agentId, value.id), null);
  const taskId = identifier(firstDefined(value.taskId, value.task_id), null);
  if (!agentName && !taskId) return null;

  const rawEffect = typeof value.effect === "string" ? value.effect : record(value.effect).class;
  const usage = usageShape(record(value.usage), firstDefined(value.updatedAt, value.at));

  return {
    id: identifier(value.id, agentName || taskId),
    agent: agentName || "unknown",
    role: identifier(value.role, null, 80),
    taskId,
    runId: identifier(firstDefined(value.runId, value.run_id), null),
    status: status(firstDefined(value.status, value.state, value.phase)),
    stage: identifier(firstDefined(value.stage, value.kind), null, 80),
    effect: enumValue(rawEffect, EFFECTS, "none"),
    updatedAt: timestamp(firstDefined(value.updatedAt, value.at)),
    startedAt: timestamp(value.startedAt),
    totalTokens: usage.totalTokens
  };
}

export function sanitizeStatusPayload(input) {
  const value = record(record(input).status && typeof record(input).status === "object" ? record(input).status : input);
  const observedAt = timestamp(firstDefined(value.at, value.observedAt, value.updatedAt));
  const rawAgents = Array.isArray(value.agents) && value.agents.length
    ? value.agents
    : Array.isArray(value.tasks)
      ? value.tasks
      : [];
  const agents = rawAgents
    .slice(0, RECORD_LIMIT)
    .map(agentShape)
    .filter(Boolean);
  const telemetry = record(value.telemetry);
  const telemetryState = enumValue(telemetry.freshness, FRESHNESS, "unknown");

  return {
    observedAt,
    state: status(firstDefined(value.state, value.status)),
    counts: safeCounts(value.counts),
    agents,
    execution: executionShape(value.execution),
    offlineAnalysis: offlineAnalysisShape(value.offlineAnalysis),
    usage: usageShape(firstDefined(value.usage, value.tokenUsage, value.tokens)),
    telemetry: {
      state: telemetryState === "fresh" ? "live" : telemetryState,
      lastActivityAt: timestamp(firstDefined(telemetry.lastActivityAt, telemetry.last_activity_at)),
      ageSeconds: count(firstDefined(telemetry.ageSeconds, telemetry.age_seconds))
    }
  };
}

function actionShape(input) {
  const value = record(input);
  return {
    category: identifier(value.category, null, 80),
    toolName: identifier(firstDefined(value.toolName, value.tool), null, 80),
    durationMs: count(firstDefined(value.durationMs, value.duration_ms)),
    exitCode: signedInteger(firstDefined(value.exitCode, value.exit_code))
  };
}

function eventShape(input) {
  const value = record(input);
  const id = identifier(value.id, null);
  const at = timestamp(value.at);
  const kind = typeof value.kind === "string" && EVENT_KIND.test(value.kind) ? value.kind : null;
  if (!id || !at || !kind) return null;

  const effectValue = typeof value.effect === "string" ? value.effect : record(value.effect).class;
  return {
    id,
    at,
    runId: identifier(firstDefined(value.runId, value.run_id), null),
    taskId: identifier(firstDefined(value.taskId, value.task_id), null),
    component: identifier(value.component, null, 80),
    agent: identifier(value.agent, null, 80),
    kind,
    status: status(firstDefined(value.status, value.phase)),
    effect: enumValue(effectValue, EFFECTS, "none"),
    action: actionShape(value.action)
  };
}

export function sanitizeEventsPayload(input) {
  const root = record(input);
  const source = Array.isArray(input) ? input : Array.isArray(root.events) ? root.events : [];
  return source
    .map(eventShape)
    .filter(Boolean)
    .sort((left, right) => Date.parse(right.at) - Date.parse(left.at))
    .slice(0, RECORD_LIMIT);
}

function learningShape(input) {
  const value = record(input);
  const id = identifier(value.id, null);
  const at = timestamp(value.at);
  const cause = safeLearningText(value.cause);
  const change = safeLearningText(value.change);
  if (!id || !at || !cause || !change) return null;

  return {
    id,
    at,
    scope: enumValue(value.scope, LEARNING_SCOPE, "session"),
    cause,
    change,
    status: enumValue(value.status, LEARNING_STATUS, "proposed"),
    sensitivity: value.sensitivity === "private" ? "private" : "public"
  };
}

export function sanitizeLearningsPayload(input) {
  const root = record(input);
  const source = Array.isArray(input) ? input : Array.isArray(root.learnings) ? root.learnings : [];
  return source
    .map(learningShape)
    .filter(Boolean)
    .sort((left, right) => Date.parse(right.at) - Date.parse(left.at))
    .slice(0, RECORD_LIMIT);
}

export function deriveCounts(statusView) {
  const agents = Array.isArray(statusView?.agents) ? statusView.agents : [];
  const derived = {
    running: agents.length ? agents.filter((agent) => agent.status === "running").length : null,
    waiting: agents.length ? agents.filter((agent) => agent.status === "waiting").length : null,
    blocked: agents.length ? agents.filter((agent) => agent.status === "blocked").length : null,
    failed: agents.length ? agents.filter((agent) => agent.status === "failed").length : null,
    queued: agents.length ? agents.filter((agent) => agent.status === "queued").length : null,
    succeeded: agents.length ? agents.filter((agent) => agent.status === "succeeded").length : null
  };

  const supplied = record(statusView?.counts);
  for (const key of Object.keys(derived)) {
    if (supplied[key] !== null && supplied[key] !== undefined) derived[key] = supplied[key];
  }
  return derived;
}

export function freshness(observedAt, now = Date.now(), staleAfterMs = 10_000, offlineAfterMs = 45_000) {
  const observed = typeof observedAt === "string" ? Date.parse(observedAt) : NaN;
  if (!Number.isFinite(observed)) return { state: "unknown", ageMs: null };
  const ageMs = Math.max(0, now - observed);
  if (ageMs > offlineAfterMs) return { state: "offline", ageMs };
  if (ageMs > staleAfterMs) return { state: "stale", ageMs };
  return { state: "live", ageMs };
}

export function boundedPercent(used, limit) {
  if (!Number.isFinite(used) || !Number.isFinite(limit) || limit <= 0 || used < 0) return null;
  return Math.max(0, Math.min(100, (used / limit) * 100));
}

export const observerContract = Object.freeze({
  status: "/api/status",
  events: "/api/events",
  learnings: "/api/learnings"
});
