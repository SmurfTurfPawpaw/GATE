/*
 * The dashboard treats every response as untrusted. Only fields projected by
 * this module can reach the DOM. Free-form event summaries, prompt content,
 * arguments, results, output, target references, evidence, and paths are never
 * copied into the view model.
 */

const RECORD_LIMIT = 100;
const CASE_LIMIT = 64;
const PROFILE_SETUP_LIMIT = 64;
const TOOL_RUNTIME_LIMIT = 256;
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
  "unknown",
  "idle"
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
const USAGE_SOURCES = new Set(["codex-session-jsonl", "gate-token-log"]);
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
  "supervision-lost",
  "workflow-claim-failed",
  "managed-runtime-invalidated",
  "indeterminate-output",
  "output-validation-failed"
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
const TOOL_RUNTIME_VERIFICATION_MODES = new Set([
  "current-bytes-and-live-zero-egress-smoke",
  "current-bytes-and-install-smoke-evidence",
  "receipt-only"
]);
const TOOL_RUNTIME_EVIDENCE_KINDS = new Set([
  "installation-receipt",
  "current-bytes-and-install-smoke-evidence",
  "current-bytes-and-live-zero-egress-smoke"
]);
const TOOL_RUNTIME_PLATFORMS = new Set(["linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64"]);
const TOOL_RUNTIME_STATES = new Set([
  "absent", "invalid", "invalid-lock", "invalid-receipt", "receipt-only", "unmanaged",
  "unsupported-platform", "verified", "verified-install-evidence", "unknown"
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
const CASE_STATUSES = new Set(["ready", "stale", "invalid"]);
const CASE_STATES = new Set([
  "queued", "running", "waiting", "blocked", "succeeded", "failed", "cancelled", "unknown", "idle"
]);
const CASE_STATE_NAMESPACES = new Set(["isolated-directory"]);
const CASE_PROCESS_BOUNDARIES = new Set(["shared-user"]);
const CASE_NETWORK_BOUNDARIES = new Set(["adapter-dependent"]);
const CASE_RUNTIME_HEALTH_STATUSES = new Set(["available", "unavailable"]);
const CASE_RUNTIME_HEALTH_REASONS = new Set(["invalid-case", "runtime-observation-failed"]);
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
const PROFILE_SETUP_FRESHNESS = new Set(["fresh", "stale"]);
const PROFILE_SETUP_SCAN_AVAILABILITY = new Set(["available", "unavailable"]);
const ENGAGEMENT_SCAN_AVAILABILITY = new Set(["loaded", "not-loaded", "unavailable"]);
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$/;
const EVENT_KIND = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$/;
const CASE_ID = /^case_[a-f0-9]{16}$/;
const PROGRAM_ID = /^program_[a-f0-9]{16}$/;
const PROJECT_ID = /^project_[a-f0-9]{16}$/;

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

function displayName(value, maximum = 80) {
  if (typeof value !== "string") return null;
  const normalized = value.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim();
  if (!normalized || normalized.length > maximum) return null;
  if (/[:][/][/]|[\\/]|\b(?:authorization|cookie|set-cookie|api[-_ ]?key|access[-_ ]?token)\b/i.test(normalized)) {
    return null;
  }
  return /^[\p{L}\p{N}][\p{L}\p{N} ._()'&+:-]*$/u.test(normalized) ? normalized : null;
}

function caseDisplayName(value) {
  if (typeof value !== "string" || !value || value.length > 60) return null;
  return /^[A-Za-z][A-Za-z0-9 .'-]*$/u.test(value) ? value.trim() : null;
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
    source: enumValue(value.source, USAGE_SOURCES, null),
    model: typeof firstDefined(value.model, newestSession?.model) === "string" &&
      /^[A-Za-z0-9][A-Za-z0-9._:+-]{0,79}$/.test(firstDefined(value.model, newestSession?.model))
      ? firstDefined(value.model, newestSession?.model)
      : null,
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
  const workflow = record(value.workflow);
  const workflowInstanceId = typeof workflow.instanceId === "string" && /^workflow_[a-f0-9]{16}$/.test(workflow.instanceId)
    ? workflow.instanceId
    : null;
  const phaseId = typeof workflow.phaseId === "string" && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$/.test(workflow.phaseId)
    ? workflow.phaseId
    : null;
  const phaseAttemptId = typeof workflow.phaseAttemptId === "string" && /^phase-attempt_[a-f0-9]{16}$/.test(workflow.phaseAttemptId)
    ? workflow.phaseAttemptId
    : null;
  const reservationId = typeof workflow.reservationId === "string" && /^reservation_[a-f0-9]{16}$/.test(workflow.reservationId)
    ? workflow.reservationId
    : null;
  if (
    !runId || !manifestId || !engagementId || !runStatus || !createdAt ||
    !workflowInstanceId || !phaseId || !phaseAttemptId || !reservationId
  ) return null;
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
    signal: enumValue(value.signal, EXECUTION_SIGNALS, null),
    workflow: { instanceId: workflowInstanceId, phaseId, phaseAttemptId, reservationId }
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
    queuedCount: count(firstDefined(value.queuedCount, counts.queued)),
    runningCount: count(firstDefined(value.runningCount, counts.running)),
    stoppingCount: count(firstDefined(value.stoppingCount, counts.stopping)),
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

function workflowInstanceShape(input) {
  const value = record(input);
  const instanceId = typeof value.instanceId === "string" && /^workflow_[a-f0-9]{16}$/.test(value.instanceId)
    ? value.instanceId
    : null;
  if (!instanceId) return null;
  const active = record(value.activePhase);
  const hasActive = Object.keys(active).length > 0;
  let activePhase = null;
  if (hasActive) {
    const id = identifier(active.id, null, 80);
    const lane = enumValue(active.lane, WORKFLOW_LANES, null);
    const effectClass = enumValue(active.effectClass, WORKFLOW_EFFECTS, null);
    const toolId = active.toolId === null ? null : identifier(active.toolId, null, 80);
    if (!id || !lane || !effectClass || (active.toolId !== null && !toolId)) return null;
    const rawControls = record(active.envelopeControls);
    activePhase = {
      id,
      lane,
      effectClass,
      toolId,
      envelopeControls: Object.keys(rawControls).length ? Object.fromEntries([
        "wallTime", "requests", "rate", "parallel", "tokens", "evidenceBytes", "spend"
      ].map((key) => [key, enumValue(rawControls[key], WORKFLOW_CONTROLS, null)])) : null
    };
  }
  return {
    instanceId,
    status: enumValue(value.status, WORKFLOW_STATUSES, "unknown"),
    activePhase,
    journalSequence: count(value.journalSequence),
    reservations: count(value.reservations),
    stops: count(value.stops),
    health: enumValue(value.health, WORKFLOW_HEALTH, "degraded")
  };
}

function workflowsShape(input) {
  const value = record(input);
  const rawCounts = record(value.counts);
  const rawScan = record(value.scan);
  return {
    counts: Object.fromEntries([
      "total", "active", "open", "stopped", "recovery-hold", "reported", "closed", "degraded", "unknown"
    ].map((key) => [key, count(rawCounts[key])])),
    instances: Array.isArray(value.instances)
      ? value.instances.slice(0, RECORD_LIMIT).map(workflowInstanceShape).filter(Boolean)
      : [],
    scan: {
      discovered: count(rawScan.discovered),
      scanned: count(rawScan.scanned),
      omitted: count(rawScan.omitted),
      complete: typeof rawScan.complete === "boolean" ? rawScan.complete : false,
      truncated: typeof rawScan.truncated === "boolean" ? rawScan.truncated : true
    }
  };
}

function caseBindingShape(input, pattern) {
  const value = record(input);
  const id = typeof value.id === "string" && pattern.test(value.id) ? value.id : null;
  if (!id || typeof value.current !== "boolean") return null;
  return { id, current: value.current };
}

function caseCountsShape(input) {
  const value = record(input);
  return Object.fromEntries([
    "total", "queued", "running", "waiting", "blocked", "succeeded", "failed", "cancelled", "unknown", "idle"
  ].map((key) => [key, count(value[key])]));
}

function caseTelemetryShape(input) {
  const value = record(input);
  const telemetryState = enumValue(value.freshness, FRESHNESS, "unknown");
  return {
    state: telemetryState === "fresh" ? "live" : telemetryState,
    lastActivityAt: timestamp(firstDefined(value.lastActivityAt, value.last_activity_at)),
    ageSeconds: count(firstDefined(value.ageSeconds, value.age_seconds))
  };
}

function caseRuntimeHealthShape(input, caseStatus) {
  const value = record(input);
  const status = enumValue(value.status, CASE_RUNTIME_HEALTH_STATUSES, "unavailable");
  const reason = value.reason === null ? null : enumValue(value.reason, CASE_RUNTIME_HEALTH_REASONS, null);
  if (caseStatus === "invalid") return { status: "unavailable", reason: "invalid-case" };
  if (status === "available" && reason === null) return { status, reason };
  return { status: "unavailable", reason: "runtime-observation-failed" };
}

function engagementScanShape(input) {
  const value = record(input);
  const requestedAvailability = enumValue(value.availability, ENGAGEMENT_SCAN_AVAILABILITY, "unavailable");
  const loaded = requestedAvailability === "loaded" && (
    typeof value.complete === "boolean" || count(value.scanned) !== null ||
    count(value.discoveredAtLeast) !== null || count(value.invalid) !== null
  );
  const availability = requestedAvailability === "not-loaded"
    ? "not-loaded"
    : loaded
      ? "loaded"
      : "unavailable";
  return {
    availability,
    reason: availability === "not-loaded" && value.reason === "aggregate-case-detail-elided" ? value.reason : null,
    limit: count(value.limit),
    discoveryLimit: count(value.discoveryLimit),
    entriesInspected: count(value.entriesInspected),
    discoveredAtLeast: count(value.discoveredAtLeast),
    scanned: count(value.scanned),
    omittedAtLeast: count(value.omittedAtLeast),
    invalid: count(value.invalid),
    recordsRead: count(value.recordsRead),
    complete: typeof value.complete === "boolean" ? value.complete : false,
    truncated: typeof value.truncated === "boolean" ? value.truncated : true,
    discoveryTruncated: typeof value.discoveryTruncated === "boolean" ? value.discoveryTruncated : false
  };
}

function caseShape(input) {
  const value = record(input);
  const id = typeof value.id === "string" && CASE_ID.test(value.id) ? value.id : null;
  const label = caseDisplayName(value.displayName);
  const caseStatus = enumValue(value.status, CASE_STATUSES, null);
  if (!id || !label || !caseStatus) return null;
  if (caseStatus === "invalid") {
    if (label !== "Invalid case" || value.binding !== null || value.isolation !== null || value.state !== "blocked") {
      return null;
    }
    return {
      id,
      displayName: label,
      status: caseStatus,
      binding: null,
      isolation: null,
      runtimeHealth: caseRuntimeHealthShape(value.runtimeHealth, caseStatus),
      state: "blocked",
      counts: caseCountsShape({}),
      telemetry: caseTelemetryShape({}),
      usage: usageShape({}),
      execution: executionShape({}),
      workflows: workflowsShape({}),
      engagementScan: engagementScanShape({}),
      offlineAnalysis: offlineAnalysisShape({}),
      activity: [],
      learningCount: count(value.learningCount) ?? 0
    };
  }
  const binding = record(value.binding);
  const program = caseBindingShape(binding.program, PROGRAM_ID);
  const project = binding.project === null ? null : caseBindingShape(binding.project, PROJECT_ID);
  const isolation = record(value.isolation);
  const stateNamespace = enumValue(isolation.stateNamespace, CASE_STATE_NAMESPACES, null);
  const processBoundary = enumValue(isolation.processBoundary, CASE_PROCESS_BOUNDARIES, null);
  const networkBoundary = enumValue(isolation.networkBoundary, CASE_NETWORK_BOUNDARIES, null);
  if (
    !program ||
    (binding.project !== null && !project) ||
    !stateNamespace || !processBoundary || !networkBoundary
  ) return null;

  const bindingsCurrent = program.current === true && (project === null || project.current === true);
  const normalizedStatus = caseStatus === "ready" && !bindingsCurrent
    ? "stale"
    : caseStatus === "stale" && bindingsCurrent
      ? "ready"
      : caseStatus;
  const runtimeHealth = caseRuntimeHealthShape(value.runtimeHealth, normalizedStatus);
  const runtimeAvailable = runtimeHealth.status === "available";

  const activity = Array.isArray(value.activity)
    ? value.activity
      .slice(0, RECORD_LIMIT)
      .map(eventShape)
      .filter(Boolean)
      .sort((left, right) => Date.parse(right.at) - Date.parse(left.at))
      .slice(0, 30)
    : [];
  return {
    id,
    displayName: label,
    status: normalizedStatus,
    binding: { program, project },
    isolation: { stateNamespace, processBoundary, networkBoundary },
    runtimeHealth,
    state: runtimeAvailable ? enumValue(value.state, CASE_STATES, "unknown") : "blocked",
    counts: caseCountsShape(runtimeAvailable ? value.counts : {}),
    telemetry: caseTelemetryShape(runtimeAvailable ? value.telemetry : {}),
    usage: usageShape(runtimeAvailable ? value.usage : {}),
    execution: executionShape(runtimeAvailable ? value.execution : {}),
    workflows: workflowsShape(runtimeAvailable ? value.workflows : {}),
    engagementScan: engagementScanShape(runtimeAvailable ? value.engagementScan : {}),
    offlineAnalysis: offlineAnalysisShape(runtimeAvailable ? value.offlineAnalysis : {}),
    activity: runtimeAvailable ? activity : [],
    learningCount: count(value.learningCount) ?? 0
  };
}

function caseScanShape(input) {
  const value = record(input);
  return {
    discovered: count(value.discovered),
    scanned: count(value.scanned),
    omitted: count(value.omitted),
    invalid: count(value.invalid),
    discoveredAtLeast: typeof value.discoveredAtLeast === "boolean" ? value.discoveredAtLeast : false,
    omittedAtLeast: typeof value.omittedAtLeast === "boolean" ? value.omittedAtLeast : false,
    complete: typeof value.complete === "boolean" ? value.complete : false,
    truncated: typeof value.truncated === "boolean" ? value.truncated : true
  };
}

function profileSetupShape(input) {
  const value = record(input);
  const hasNextSection = Object.hasOwn(value, "nextSection");
  const id = typeof value.id === "string" && PROGRAM_ID.test(value.id) ? value.id : null;
  const stage = enumValue(value.stage, PROFILE_SETUP_STAGES, null);
  const readiness = enumValue(value.readiness, PROFILE_SETUP_READINESS, null);
  const progress = record(value.progress);
  const answered = count(progress.answered);
  const total = count(progress.total);
  const blockerCount = count(value.blockerCount);
  const nextSection = value.nextSection === null
    ? null
    : enumValue(value.nextSection, PROFILE_SETUP_NEXT_SECTIONS, null);
  const recommendationMode = value.recommendationMode === null
    ? null
    : enumValue(value.recommendationMode, PROFILE_SETUP_RECOMMENDATION_MODES, null);
  const updatedAt = timestamp(value.updatedAt);
  const setupFreshness = enumValue(value.freshness, PROFILE_SETUP_FRESHNESS, null);
  const ready = stage === "ready" && readiness === "ready";
  const nonReady = stage !== "ready" && readiness === "not-ready";
  const completeProgress = answered !== null && total !== null && total > 0 && answered === total;
  const pendingProgress = answered !== null && total !== null && total > 0 && answered < total;
  const stateConsistent = ready
    ? completeProgress && blockerCount === 0 && nextSection === null
    : nonReady && blockerCount !== null && blockerCount > 0 &&
      ((completeProgress && nextSection === null) || (pendingProgress && nextSection !== null));
  if (!id || value.displayName !== null || !stage || !readiness || answered === null || total === null || answered > total ||
      blockerCount === null || !updatedAt || !setupFreshness || !hasNextSection || !stateConsistent ||
      (value.nextSection !== null && nextSection === null) ||
      (value.recommendationMode !== null && recommendationMode === null)) return null;
  return {
    id,
    displayName: null,
    stage,
    readiness,
    progress: { answered, total },
    blockerCount,
    nextSection,
    recommendationMode,
    updatedAt,
    freshness: setupFreshness
  };
}

function profileSetupScanShape(input) {
  const value = record(input);
  const availability = enumValue(value.availability, PROFILE_SETUP_SCAN_AVAILABILITY, "unavailable");
  return {
    availability,
    discovered: availability === "available" ? count(value.discovered) : null,
    scanned: availability === "available" ? count(value.scanned) : null,
    omitted: availability === "available" ? count(value.omitted) : null,
    invalid: availability === "available" ? count(value.invalid) : null,
    visible: count(value.visible),
    representedByCases: availability === "available" ? count(value.representedByCases) : null,
    discoveredAtLeast: typeof value.discoveredAtLeast === "boolean" ? value.discoveredAtLeast : false,
    omittedAtLeast: typeof value.omittedAtLeast === "boolean" ? value.omittedAtLeast : false,
    complete: availability === "available" && value.complete === true,
    truncated: availability === "unavailable" || (typeof value.truncated === "boolean" ? value.truncated : true)
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

function toolRuntimeName(value) {
  if (typeof value !== "string" || value.length > 80 || value.includes("://") || value.includes("\\")) return null;
  return /^[A-Za-z0-9][A-Za-z0-9+._ -]*(?: \/ [A-Za-z0-9][A-Za-z0-9+._ -]*)?$/.test(value)
    ? value
    : null;
}

function toolRuntimeReasons(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.slice(0, 32).filter((reason) => TOOL_RUNTIME_REASONS.has(reason)))];
}

function toolRuntimeEvidenceShape(input) {
  const value = record(input);
  const kind = enumValue(value.kind, TOOL_RUNTIME_EVIDENCE_KINDS, null);
  const lastVerifiedAt = timestamp(value.lastVerifiedAt);
  if (!kind || !lastVerifiedAt) return null;
  return {
    kind,
    lastVerifiedAt,
    ageSeconds: count(value.ageSeconds),
    current: typeof value.current === "boolean" ? value.current : null,
    currentBytesChecked: typeof value.currentBytesChecked === "boolean" ? value.currentBytesChecked : null,
    liveSmokeExecutedNow: typeof value.liveSmokeExecutedNow === "boolean" ? value.liveSmokeExecutedNow : null
  };
}

function toolRuntimeShape(input) {
  const value = record(input);
  const toolId = typeof value.id === "string" && value.id.length <= 128 && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(value.id)
    ? value.id
    : null;
  if (!toolId) return null;
  const verificationEvidence = toolRuntimeEvidenceShape(value.verificationEvidence);
  return {
    id: toolId,
    name: toolRuntimeName(value.name),
    state: enumValue(value.state, TOOL_RUNTIME_STATES, "unknown"),
    locked: typeof value.locked === "boolean" ? value.locked : null,
    installed: typeof value.installed === "boolean" ? value.installed : null,
    verified: typeof value.verified === "boolean" ? value.verified : null,
    executable: typeof value.executable === "boolean" ? value.executable : null,
    ...(verificationEvidence ? { verificationEvidence } : {}),
    reasons: toolRuntimeReasons(value.reasons)
  };
}

function toolRuntimesShape(input) {
  const value = record(input);
  const reasonCounts = new Map();
  if (Array.isArray(value.unresolvedConstraints)) {
    for (const raw of value.unresolvedConstraints.slice(0, TOOL_RUNTIME_LIMIT)) {
      const constraint = record(raw);
      const reason = TOOL_RUNTIME_REASONS.has(constraint.reason) ? constraint.reason : null;
      const total = count(constraint.count);
      if (!reason || total === null) continue;
      reasonCounts.set(reason, Math.min(MAX_COUNT, (reasonCounts.get(reason) || 0) + total));
    }
  }
  const executableHashReads = count(value.executableHashReads);
  return {
    ok: typeof value.ok === "boolean" ? value.ok : null,
    verificationMode: enumValue(value.verificationMode, TOOL_RUNTIME_VERIFICATION_MODES, null),
    ...(typeof value.currentBytesChecked === "boolean" ? { currentBytesChecked: value.currentBytesChecked } : {}),
    ...(executableHashReads !== null ? { executableHashReads } : {}),
    platform: enumValue(value.platform, TOOL_RUNTIME_PLATFORMS, null),
    catalog: count(value.catalog),
    locked: count(value.locked),
    installed: count(value.installed),
    verified: count(value.verified),
    executable: count(value.executable),
    unresolved: count(value.unresolved),
    unresolvedConstraints: [...reasonCounts]
      .map(([reason, total]) => ({ reason, count: total }))
      .sort((left, right) => right.count - left.count || left.reason.localeCompare(right.reason)),
    tools: Array.isArray(value.tools)
      ? value.tools.slice(0, TOOL_RUNTIME_LIMIT).map(toolRuntimeShape).filter(Boolean)
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
  const operator = record(value.operator);
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
    operator: { displayName: displayName(operator.displayName, 80) },
    state: status(firstDefined(value.state, value.status)),
    counts: safeCounts(value.counts),
    agents,
    cases: Array.isArray(value.cases)
      ? value.cases.slice(0, CASE_LIMIT).map(caseShape).filter(Boolean)
      : [],
    caseScan: caseScanShape(value.caseScan),
    profileSetups: Array.isArray(value.profileSetups)
      ? value.profileSetups.slice(0, PROFILE_SETUP_LIMIT).map(profileSetupShape).filter(Boolean)
      : [],
    profileSetupScan: profileSetupScanShape(value.profileSetupScan),
    engagementScan: engagementScanShape(value.engagementScan),
    execution: executionShape(value.execution),
    workflows: workflowsShape(value.workflows),
    offlineAnalysis: offlineAnalysisShape(value.offlineAnalysis),
    toolRuntimes: toolRuntimesShape(value.toolRuntimes),
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
