import {
  boundedPercent,
  deriveCounts,
  freshness,
  observerContract,
  sanitizeEventsPayload,
  sanitizeLearningsPayload,
  sanitizeStatusPayload
} from "./model.js";

const POLL_INTERVAL_MS = 2_000;
const REQUEST_TIMEOUT_MS = 3_500;
const MAX_RESPONSE_BYTES = 2_000_000;
const OBSERVER_API_VERSION = "gate.observer/v1";
const OBSERVER_STATUS_STATES = new Set([
  "queued", "running", "waiting", "blocked", "succeeded", "failed", "cancelled", "unknown", "idle"
]);
const browserAvailable = typeof document !== "undefined" && typeof window !== "undefined";

function select(selector) {
  return browserAvailable ? document.querySelector(selector) : null;
}

const view = {
  connectionIndicator: select("#connection-indicator"),
  connectionLabel: select("#connection-label"),
  clock: select("#clock"),
  pauseButton: select("#pause-button"),
  refreshButton: select("#refresh-button"),
  shortcutsButton: select("#shortcuts-button"),
  shortcutsDialog: select("#shortcuts-dialog"),
  eventSearch: select("#event-search"),
  agentList: select("#agent-list"),
  eventList: select("#event-list"),
  learningList: select("#learning-list"),
  learningCount: select("#learning-count"),
  casePanel: select("#case-panel"),
  caseGrid: select("#case-grid"),
  caseCount: select("#case-count"),
  caseScan: select("#case-scan"),
  executionLane: select("#execution-lane"),
  executionMode: select("#execution-mode"),
  executionRunning: select("#execution-running"),
  executionStopping: select("#execution-stopping"),
  executionConfigured: select("#execution-configured"),
  executionEnforced: select("#execution-enforced"),
  executionBestEffort: select("#execution-best-effort"),
  executionUnavailable: select("#execution-unavailable"),
  executionRuns: select("#execution-runs"),
  executionNote: select("#execution-note"),
  offlineAnalysisLane: select("#offline-analysis-lane"),
  offlineAnalysisMode: select("#offline-analysis-mode"),
  offlineAnalysisConfigured: select("#offline-analysis-configured"),
  offlineAnalysisQueued: select("#offline-analysis-queued"),
  offlineAnalysisRunning: select("#offline-analysis-running"),
  offlineAnalysisSucceeded: select("#offline-analysis-succeeded"),
  offlineAnalysisFailed: select("#offline-analysis-failed"),
  offlineAnalysisCancelled: select("#offline-analysis-cancelled"),
  offlineAnalysisBlocked: select("#offline-analysis-blocked"),
  offlineAnalysisUnknown: select("#offline-analysis-unknown"),
  offlineAnalysisRuns: select("#offline-analysis-runs"),
  offlineAnalysisRetentionHealth: select("#offline-analysis-retention-health"),
  offlineAnalysisRetentionOverQuota: select("#offline-analysis-retention-over-quota"),
  offlineAnalysisRetentionMissing: select("#offline-analysis-retention-missing"),
  offlineAnalysisRetentionInvalid: select("#offline-analysis-retention-invalid"),
  offlineAnalysisRetentionOrphaned: select("#offline-analysis-retention-orphaned"),
  offlineAnalysisRetentionOrphanedBytes: select("#offline-analysis-retention-orphaned-bytes"),
  offlineAnalysisRetentionPurgePending: select("#offline-analysis-retention-purge-pending"),
  offlineAnalysisRetentionUnknown: select("#offline-analysis-retention-unknown"),
  offlineAnalysisControlHealth: select("#offline-analysis-control-health"),
  offlineAnalysisControlMutation: select("#offline-analysis-control-mutation"),
  offlineAnalysisControlLock: select("#offline-analysis-control-lock"),
  offlineAnalysisControlSnapshot: select("#offline-analysis-control-snapshot"),
  offlineAnalysisControlPending: select("#offline-analysis-control-pending"),
  offlineAnalysisControlInvalidTransactions: select("#offline-analysis-control-invalid-transactions"),
  offlineAnalysisControlCreating: select("#offline-analysis-control-creating"),
  offlineAnalysisControlInvalidCreations: select("#offline-analysis-control-invalid-creations"),
  offlineAnalysisControlInvalidClaims: select("#offline-analysis-control-invalid-claims"),
  offlineAnalysisControlInvalidPurges: select("#offline-analysis-control-invalid-purges"),
  offlineAnalysisControlInvalidRuns: select("#offline-analysis-control-invalid-runs"),
  offlineAnalysisControlBlockedManifests: select("#offline-analysis-control-blocked-manifests"),
  offlineAnalysisNote: select("#offline-analysis-note"),
  toolRuntimeHealth: select("#tool-runtime-health"),
  toolRuntimeMode: select("#tool-runtime-mode"),
  toolRuntimePlatform: select("#tool-runtime-platform"),
  toolRuntimeCatalog: select("#tool-runtime-catalog"),
  toolRuntimeLocked: select("#tool-runtime-locked"),
  toolRuntimeInstalled: select("#tool-runtime-installed"),
  toolRuntimeVerified: select("#tool-runtime-verified"),
  toolRuntimeExecutable: select("#tool-runtime-executable"),
  toolRuntimeUnresolved: select("#tool-runtime-unresolved"),
  toolRuntimeCurrentBytes: select("#tool-runtime-current-bytes"),
  toolRuntimeHashReads: select("#tool-runtime-hash-reads"),
  toolRuntimeConstraints: select("#tool-runtime-constraints"),
  toolRuntimeList: select("#tool-runtime-list"),
  toolRuntimeCount: select("#tool-runtime-count"),
  metricRunning: select("#metric-running"),
  metricRunningDetail: select("#metric-running-detail"),
  metricWaiting: select("#metric-waiting"),
  metricAttention: select("#metric-attention"),
  metricTokens: select("#metric-tokens"),
  metricTokensDetail: select("#metric-tokens-detail"),
  metricContext: select("#metric-context"),
  metricContextDetail: select("#metric-context-detail"),
  metricFreshness: select("#metric-freshness"),
  metricFreshnessDetail: select("#metric-freshness-detail"),
  usageAvailability: select("#usage-availability"),
  contextLabel: select("#context-label"),
  contextMeter: select("#context-meter"),
  contextFill: select("#context-fill"),
  budgetLabel: select("#budget-label"),
  budgetMeter: select("#budget-meter"),
  budgetFill: select("#budget-fill"),
  tokenInput: select("#token-input"),
  tokenCached: select("#token-cached"),
  tokenOutput: select("#token-output"),
  tokenReasoning: select("#token-reasoning"),
  usageSource: select("#usage-source"),
  usageUpdated: select("#usage-updated"),
  pollDetail: select("#poll-detail"),
  screenReaderStatus: select("#screen-reader-status")
};

const state = {
  status: sanitizeStatusPayload({}),
  events: [],
  learnings: [],
  agentFilter: "all",
  search: "",
  selectedCaseId: null,
  paused: false,
  refreshing: false,
  timer: null,
  failedEndpoints: new Set(),
  lastNetworkSuccess: null,
  connectionState: "unknown"
};

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function setText(node, value) {
  const next = String(value);
  if (node.textContent !== next) node.textContent = next;
}

function formatTokens(value) {
  if (!Number.isFinite(value)) return "—";
  if (value < 1_000) return new Intl.NumberFormat().format(value);
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: value < 100_000 ? 1 : 2 }).format(value);
}

function fullNumber(value) {
  return Number.isFinite(value) ? new Intl.NumberFormat().format(value) : "unavailable";
}

function formatBytes(value) {
  if (!Number.isFinite(value) || value < 0) return "unavailable";
  const units = ["B", "KiB", "MiB", "GiB"];
  let amount = value;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  const precision = unit === 0 || amount >= 10 ? 0 : 1;
  return `${amount.toFixed(precision)} ${units[unit]}`;
}

function formatAge(ageMs) {
  if (!Number.isFinite(ageMs)) return "unknown age";
  if (ageMs < 2_000) return "just now";
  if (ageMs < 60_000) return `${Math.floor(ageMs / 1_000)}s ago`;
  if (ageMs < 3_600_000) return `${Math.floor(ageMs / 60_000)}m ago`;
  return `${Math.floor(ageMs / 3_600_000)}h ago`;
}

function dateTime(value) {
  if (!value) return "Unknown time";
  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  }).format(new Date(value));
}

function relativeTime(value) {
  if (!value) return "unknown";
  return formatAge(Math.max(0, Date.now() - Date.parse(value)));
}

function readableKind(kind) {
  const words = kind.replace(/[.-]/g, " ");
  return `${words.charAt(0).toUpperCase()}${words.slice(1)}`;
}

function readableCapability(value) {
  if (!value) return "Unknown";
  const words = value.replace(/-/g, " ");
  return `${words.charAt(0).toUpperCase()}${words.slice(1)}`;
}

export function executionPresentation(execution = {}) {
  const configured = execution.configured;
  const laneAvailable = configured === true && execution.laneAvailable === true;
  const laneState = configured === null || configured === undefined
    ? "unknown"
    : configured === false
      ? "not-configured"
      : laneAvailable
        ? "available"
        : "unavailable";
  return {
    laneState,
    laneLabel: laneState === "not-configured" ? "Not configured" : readableCapability(laneState),
    configuredLabel: configured === true ? "Configured" : configured === false ? "Not configured" : "Unknown",
    modeLabel: execution.mode ? readableCapability(execution.mode) : "Unknown",
    reasonLabel: execution.reason ? readableCapability(execution.reason) : null,
    runningLabel: Number.isFinite(execution.runningCount) ? String(execution.runningCount) : "—",
    stoppingLabel: Number.isFinite(execution.stoppingCount) ? String(execution.stoppingCount) : "—"
  };
}

export function executionRunPresentation(run = {}) {
  const observedAt = run.finishedAt || run.startedAt || run.createdAt || null;
  const result = run.terminationReason || run.signal || (Number.isFinite(run.exitCode) ? `exit-${run.exitCode}` : null);
  return {
    runId: run.runId || null,
    manifestId: run.manifestId || null,
    engagementId: run.engagementId || null,
    status: run.status || "unknown",
    observedAt,
    result
  };
}

function greetingName(operator = {}) {
  const value = typeof operator.displayName === "string" ? operator.displayName.trim() : "";
  if (!value || value.length > 80 || /[\u0000-\u001f\u007f\\/]/.test(value)) return "Operator";
  return value;
}

function caseCountSummary(counts = {}) {
  const parts = [];
  for (const key of ["running", "queued", "waiting", "blocked", "failed", "succeeded"]) {
    if (Number.isFinite(counts[key])) parts.push(`${counts[key]} ${key}`);
  }
  return parts.length ? parts.join(" · ") : "counts unavailable";
}

function terminalLine(label, value, tone = "neutral") {
  return { label, value, tone, observedAt: null };
}

function observedTerminalLine(label, value, tone, observedAt, unavailableLabel = "time unavailable") {
  const parsed = typeof observedAt === "string" ? Date.parse(observedAt) : NaN;
  const valid = Number.isFinite(parsed);
  return {
    label,
    value: valid ? value : `${value} · ${unavailableLabel}`,
    tone,
    observedAt: valid ? new Date(parsed).toISOString() : null
  };
}

function caseTokenLabel(usage = {}) {
  const availability = usage.availability || "unavailable";
  if (availability === "unavailable") return "unavailable";
  if (!Number.isFinite(usage.totalTokens)) return `${availability} · total unavailable`;
  return `${availability} · ${fullNumber(usage.totalTokens)} tokens observed`;
}

export function usageScopeLabel(usage = {}) {
  if (usage.source === "codex-session-jsonl") return "Host-wide, unattributed sessions";
  if (usage.source === "gate-token-log") return "Base/unassigned token log";
  return "Host/base scope unavailable";
}

export function engagementScanPresentation(scan = {}) {
  if (scan.availability === "not-loaded") {
    return { label: "details not loaded", attention: false };
  }
  if (scan.availability !== "loaded") {
    return { label: "unavailable", attention: true };
  }
  const parts = [];
  if (Number.isFinite(scan.scanned)) parts.push(`${scan.scanned} scanned`);
  if (Number.isFinite(scan.discoveredAtLeast)) parts.push(`${scan.discoveredAtLeast}+ discovered`);
  if (Number.isFinite(scan.omittedAtLeast) && scan.omittedAtLeast > 0) parts.push(`${scan.omittedAtLeast}+ omitted`);
  if (Number.isFinite(scan.invalid) && scan.invalid > 0) parts.push(`${scan.invalid} invalid`);
  if (scan.truncated === true) parts.push("truncated");
  if (scan.complete !== true && scan.truncated !== true) parts.push("partial");
  return {
    label: parts.length ? parts.join(" · ") : "no records observed",
    attention: scan.complete !== true || scan.truncated === true || Number(scan.invalid || 0) > 0
  };
}

export function casePresentation(caseView = {}, operator = {}) {
  const runtimeHealth = caseView.runtimeHealth || { status: "unavailable", reason: "runtime-observation-failed" };
  const runtimeAvailable = runtimeHealth.status === "available";
  const execution = caseView.execution || {};
  const offlineAnalysis = caseView.offlineAnalysis || {};
  const offlineCounts = offlineAnalysis.counts || {};
  const workflows = caseView.workflows || {};
  const workflowInstances = Array.isArray(workflows.instances) ? workflows.instances : [];
  const executionRuns = Array.isArray(execution.recent) ? execution.recent : [];
  const activity = Array.isArray(caseView.activity) ? caseView.activity : [];
  const activeWorkflows = workflowInstances.filter((workflow) => workflow.activePhase);
  const liveRun = executionRuns.some((run) => ["queued", "running", "stopping"].includes(run.status));
  const active = runtimeAvailable && (["queued", "running"].includes(caseView.state) || liveRun || activeWorkflows.length > 0 ||
    Number(execution.queuedCount || 0) > 0 || Number(execution.runningCount || 0) > 0 ||
    Number(execution.stoppingCount || 0) > 0 || Number(offlineCounts.queued || 0) > 0 ||
    Number(offlineCounts.running || 0) > 0);
  const telemetryLive = caseView.telemetry?.state === "live";
  const indeterminate = active && caseView.status === "ready" && telemetryLive;
  const bindingAvailable = caseView.binding !== null && typeof caseView.binding === "object";
  const isolationAvailable = caseView.isolation !== null && typeof caseView.isolation === "object";
  const engagementScan = engagementScanPresentation(caseView.engagementScan);
  const telemetryState = caseView.telemetry?.state || "unknown";
  const telemetryTone = telemetryState === "offline"
    ? "blocked"
    : telemetryState === "stale"
      ? "waiting"
      : telemetryState === "live"
        ? "active"
        : "neutral";
  const lines = [
    terminalLine("case", `${caseView.displayName || "Unnamed case"} · ${caseView.id || "unknown"}`, "identity"),
    terminalLine("program", bindingAvailable ? caseView.binding?.program?.id || "unavailable" : "unavailable"),
    terminalLine(
      "project",
      bindingAvailable ? caseView.binding?.project?.id || (caseView.binding?.project === null ? "not bound" : "unavailable") : "unavailable"
    ),
    terminalLine(
      "isolation",
      isolationAvailable
        ? `state ${readableCapability(caseView.isolation?.stateNamespace || "unknown").toLowerCase()} · ` +
          `process ${readableCapability(caseView.isolation?.processBoundary || "unknown").toLowerCase()} · ` +
          `network ${readableCapability(caseView.isolation?.networkBoundary || "unknown").toLowerCase()}`
        : "unavailable"
    ),
    terminalLine(
      "runtime",
      runtimeAvailable ? "available" : `unavailable · ${readableCapability(runtimeHealth.reason || "runtime-observation-failed").toLowerCase()}`,
      runtimeAvailable ? "neutral" : "blocked"
    ),
    terminalLine("state", `${caseView.state || "unknown"} · case ${caseView.status || "unknown"}`, caseView.state || "unknown"),
    observedTerminalLine("telemetry", telemetryState, telemetryTone, caseView.telemetry?.lastActivityAt, "age unavailable"),
    terminalLine("counts", caseCountSummary(caseView.counts)),
    terminalLine(
      "execution",
      Number.isFinite(execution.queuedCount) && Number.isFinite(execution.runningCount) && Number.isFinite(execution.stoppingCount)
        ? `${execution.queuedCount} queued · ${execution.runningCount} running · ${execution.stoppingCount} stopping`
        : "counts unavailable"
    ),
    terminalLine(
      "analysis",
      Number.isFinite(offlineCounts.queued) && Number.isFinite(offlineCounts.running)
        ? `${offlineCounts.queued} queued · ${offlineCounts.running} running`
        : "counts unavailable"
    ),
    terminalLine("engagements", engagementScan.label, engagementScan.attention ? "blocked" : "neutral"),
    terminalLine("tokens", caseTokenLabel(caseView.usage))
  ];

  for (const workflow of activeWorkflows.slice(0, 4)) {
    lines.push(terminalLine(
      "phase",
      `${workflow.instanceId} · ${workflow.activePhase.id} · tool ${workflow.activePhase.toolId || "none"}`,
      "active"
    ));
  }
  for (const run of executionRuns.slice(0, 4)) {
    const display = executionRunPresentation(run);
    lines.push(observedTerminalLine(
      "run",
      `${display.runId || "unknown"} · ${display.status}${display.result ? ` · ${readableCapability(display.result)}` : ""}`,
      display.status,
      display.observedAt
    ));
  }
  for (const event of activity.slice(0, 4)) {
    const details = [readableKind(event.kind || "activity.unknown"), event.status || "unknown"];
    if (event.action?.toolName) details.push(`tool ${event.action.toolName}`);
    lines.push(observedTerminalLine("activity", details.join(" · "), event.status || "unknown", event.at));
  }

  return {
    id: caseView.id || null,
    displayName: caseView.displayName || "Unnamed case",
    state: caseView.state || "unknown",
    status: caseView.status || "invalid",
    greeting: `GATE // Welcome, ${greetingName(operator)}.`,
    active,
    indeterminate,
    lines
  };
}

export function cycleCaseSelection(cases, currentId, direction = 0) {
  const ids = [...new Set((Array.isArray(cases) ? cases : [])
    .map((item) => typeof item === "string" ? item : item?.id)
    .filter((id) => typeof id === "string" && id))];
  if (!ids.length) return null;
  const currentIndex = ids.indexOf(currentId);
  if (direction === 0) return currentIndex >= 0 ? currentId : ids[0];
  if (currentIndex < 0) return direction < 0 ? ids.at(-1) : ids[0];
  const step = direction < 0 ? -1 : 1;
  return ids[(currentIndex + step + ids.length) % ids.length];
}

export function captureCaseRenderContinuity(caseGrid, activeElement) {
  const scrollPositions = new Map();
  let focusedCaseId = null;
  if (!caseGrid?.querySelectorAll) return { focusedCaseId, scrollPositions };
  for (const card of caseGrid.querySelectorAll("[data-case-id]")) {
    const caseId = card?.dataset?.caseId;
    if (!caseId) continue;
    const terminal = card.querySelector?.(".case-terminal");
    if (terminal) {
      const maximumTop = Number.isFinite(terminal.scrollHeight) && Number.isFinite(terminal.clientHeight)
        ? Math.max(0, terminal.scrollHeight - terminal.clientHeight)
        : null;
      scrollPositions.set(caseId, {
        top: Number.isFinite(terminal.scrollTop) ? Math.max(0, terminal.scrollTop) : 0,
        left: Number.isFinite(terminal.scrollLeft) ? Math.max(0, terminal.scrollLeft) : 0,
        atBottom: maximumTop !== null && maximumTop > 0 && terminal.scrollTop >= maximumTop - 1
      });
    }
    if (card === activeElement || card.contains?.(activeElement)) focusedCaseId = caseId;
  }
  return { focusedCaseId, scrollPositions };
}

export function restoreCaseRenderContinuity(caseGrid, snapshot = {}) {
  if (!caseGrid?.querySelectorAll) return;
  let focusedCard = null;
  let fallbackCard = null;
  const terminals = [];
  for (const card of caseGrid.querySelectorAll("[data-case-id]")) {
    const caseId = card?.dataset?.caseId;
    if (!caseId) continue;
    const terminal = card.querySelector?.(".case-terminal");
    const position = snapshot.scrollPositions instanceof Map ? snapshot.scrollPositions.get(caseId) : null;
    if (terminal && position) terminals.push({ terminal, position });
    if (caseId === snapshot.focusedCaseId) focusedCard = card;
    if (caseId === snapshot.fallbackFocusCaseId) fallbackCard = card;
  }
  if (!focusedCard && snapshot.focusedCaseId) focusedCard = fallbackCard;
  if (focusedCard?.focus) {
    try {
      focusedCard.focus({ preventScroll: true });
    } catch {
      focusedCard.focus();
    }
  }
  for (const { terminal, position } of terminals) {
    terminal.scrollTop = position.atBottom && Number.isFinite(terminal.scrollHeight) && Number.isFinite(terminal.clientHeight)
      ? Math.max(0, terminal.scrollHeight - terminal.clientHeight)
      : position.top;
    terminal.scrollLeft = position.left;
  }
}

export function caseScanPresentation(scan = {}, visibleCount = 0) {
  const visible = Number.isFinite(visibleCount) && visibleCount >= 0 ? visibleCount : 0;
  const scanned = Number.isFinite(scan.scanned) ? scan.scanned : visible;
  const discovered = Number.isFinite(scan.discovered) ? scan.discovered : visible;
  const omitted = Number.isFinite(scan.omitted) ? scan.omitted : Math.max(0, discovered - scanned);
  const invalid = Number.isFinite(scan.invalid) ? scan.invalid : 0;
  const discoveredLabel = `${discovered}${scan.discoveredAtLeast === true ? "+" : ""}`;
  const omittedLabel = `${omitted}${scan.omittedAtLeast === true ? "+" : ""}`;
  return `${scanned} scanned / ${discoveredLabel} discovered${omitted ? ` · ${omittedLabel} omitted` : ""}${invalid ? ` · ${invalid} invalid` : ""}${scan.complete === true ? "" : " · partial"}`;
}

export function offlineAnalysisPresentation(analysis = {}) {
  const base = executionPresentation(analysis);
  const retention = analysis.retention || {};
  const lockState = ["absent", "active", "stale", "invalid", "indeterminate"].includes(retention.retentionLockState)
    ? retention.retentionLockState
    : null;
  const snapshotState = ["stable", "consistent", "mutation-active", "indeterminate"].includes(retention.snapshotState)
    ? retention.snapshotState
    : null;
  const faultCounts = [
    retention.missingArtifacts,
    retention.invalidEntries,
    retention.orphanedArtifacts,
    retention.orphanedBytes,
    retention.purgePendingManifests,
    retention.unknownManifests
  ];
  const faultSignalComplete = typeof retention.overQuota === "boolean" && faultCounts.every(Number.isFinite);
  const needsAttention = retention.overQuota === true || faultCounts.some((value) => Number.isFinite(value) && value > 0);
  const retentionState = needsAttention ? "attention" : faultSignalComplete ? "healthy" : "unknown";
  const blockingControlCounts = [retention.invalidTransactionRecords, retention.invalidCreationIntents];
  const scopedControlFaultCounts = [
    retention.invalidClaimRecords,
    retention.invalidPurgeRecords,
    retention.invalidRunRecords,
    retention.blockedManifests
  ];
  const activeControlCounts = [retention.pendingTransactions, retention.creatingManifests];
  const allControlCounts = [...blockingControlCounts, ...scopedControlFaultCounts, ...activeControlCounts];
  const controlSignalComplete = typeof retention.mutationBlocked === "boolean" &&
    lockState !== null && snapshotState !== null && allControlCounts.every(Number.isFinite);
  const controlBlocked = retention.mutationBlocked === true ||
    ["invalid", "indeterminate"].includes(lockState) ||
    ["mutation-active", "indeterminate"].includes(snapshotState) ||
    blockingControlCounts.some((value) => Number.isFinite(value) && value > 0);
  const controlNeedsAttention = lockState === "stale" ||
    scopedControlFaultCounts.some((value) => Number.isFinite(value) && value > 0);
  const controlActive = lockState === "active" ||
    activeControlCounts.some((value) => Number.isFinite(value) && value > 0);
  const controlState = controlBlocked
    ? "blocked"
    : controlNeedsAttention
      ? "attention"
      : controlActive
        ? "active"
        : controlSignalComplete
          ? "healthy"
          : "unknown";
  const retentionLabel = Number.isFinite(retention.retainedBytes) && Number.isFinite(retention.quotaBytes)
    ? `${formatBytes(retention.retainedBytes)} / ${formatBytes(retention.quotaBytes)} retained · ` +
      `${Number.isFinite(retention.retainedArtifacts) ? retention.retainedArtifacts : "—"} / ` +
      `${Number.isFinite(retention.quotaArtifacts) ? retention.quotaArtifacts : "—"} artifacts · ` +
      `${Number.isFinite(retention.pendingManifests) ? retention.pendingManifests : "—"} pending · ` +
      `${Number.isFinite(retention.expiredManifests) ? retention.expiredManifests : "—"} expired`
    : "Retention unavailable";
  return {
    laneState: base.laneState,
    laneLabel: base.laneLabel,
    configuredLabel: base.configuredLabel,
    modeLabel: base.modeLabel,
    reasonLabel: base.reasonLabel,
    runningLabel: base.runningLabel,
    retentionLabel,
    retentionState,
    retentionStateLabel: retentionState === "healthy" ? "Healthy" : retentionState === "attention" ? "Needs attention" : "Unknown",
    retentionOverQuotaLabel: retention.overQuota === true ? "Yes" : retention.overQuota === false ? "No" : "—",
    retentionMissingLabel: Number.isFinite(retention.missingArtifacts) ? fullNumber(retention.missingArtifacts) : "—",
    retentionInvalidLabel: Number.isFinite(retention.invalidEntries) ? fullNumber(retention.invalidEntries) : "—",
    retentionOrphanedLabel: Number.isFinite(retention.orphanedArtifacts) ? fullNumber(retention.orphanedArtifacts) : "—",
    retentionOrphanedBytesLabel: Number.isFinite(retention.orphanedBytes) ? formatBytes(retention.orphanedBytes) : "—",
    retentionPurgePendingLabel: Number.isFinite(retention.purgePendingManifests) ? fullNumber(retention.purgePendingManifests) : "—",
    retentionUnknownLabel: Number.isFinite(retention.unknownManifests) ? fullNumber(retention.unknownManifests) : "—",
    controlState,
    controlStateLabel: controlState === "blocked"
      ? "Mutation blocked"
      : controlState === "attention"
        ? "Needs attention"
        : controlState === "active"
          ? "Controls active"
          : controlState === "healthy"
            ? "Controls healthy"
            : "Unknown",
    controlMutationLabel: controlBlocked ? "Blocked" : retention.mutationBlocked === false ? "Available" : "—",
    controlLockLabel: lockState ? readableCapability(lockState) : "—",
    controlSnapshotLabel: snapshotState ? readableCapability(snapshotState) : "—",
    controlPendingLabel: Number.isFinite(retention.pendingTransactions) ? fullNumber(retention.pendingTransactions) : "—",
    controlInvalidTransactionsLabel: Number.isFinite(retention.invalidTransactionRecords) ? fullNumber(retention.invalidTransactionRecords) : "—",
    controlCreatingLabel: Number.isFinite(retention.creatingManifests) ? fullNumber(retention.creatingManifests) : "—",
    controlInvalidCreationsLabel: Number.isFinite(retention.invalidCreationIntents) ? fullNumber(retention.invalidCreationIntents) : "—",
    controlInvalidClaimsLabel: Number.isFinite(retention.invalidClaimRecords) ? fullNumber(retention.invalidClaimRecords) : "—",
    controlInvalidPurgesLabel: Number.isFinite(retention.invalidPurgeRecords) ? fullNumber(retention.invalidPurgeRecords) : "—",
    controlInvalidRunsLabel: Number.isFinite(retention.invalidRunRecords) ? fullNumber(retention.invalidRunRecords) : "—",
    controlBlockedManifestsLabel: Number.isFinite(retention.blockedManifests) ? fullNumber(retention.blockedManifests) : "—"
  };
}

export function offlineAnalysisRunPresentation(run = {}) {
  const isolationState = run.isolationVerified === true
    ? "verified"
    : run.isolationVerified === false
      ? "unverified"
      : "pending";
  return {
    runId: run.runId || null,
    status: run.status || "unknown",
    isolationState,
    isolationLabel: isolationState === "verified"
      ? "Isolation verified"
      : isolationState === "unverified"
        ? "Isolation not verified"
        : "Isolation pending"
  };
}

export function toolRuntimePresentation(summary = {}) {
  const unresolved = Number.isFinite(summary.unresolved) ? summary.unresolved : null;
  const healthState = summary.ok === false
    ? "invalid"
    : summary.ok === true && unresolved === 0
      ? "ready"
      : summary.ok === true
        ? "partial"
        : "unknown";
  const result = {
    healthState,
    healthLabel: healthState === "invalid"
      ? "Lock invalid"
      : healthState === "ready"
        ? "Ready"
        : healthState === "partial"
          ? `${fullNumber(unresolved)} unresolved`
          : "Unknown",
    modeLabel: summary.verificationMode ? readableCapability(summary.verificationMode) : "Unknown",
    platformLabel: summary.platform || "Unknown",
    catalogLabel: Number.isFinite(summary.catalog) ? fullNumber(summary.catalog) : "—",
    lockedLabel: Number.isFinite(summary.locked) ? fullNumber(summary.locked) : "—",
    installedLabel: Number.isFinite(summary.installed) ? fullNumber(summary.installed) : "—",
    verifiedLabel: Number.isFinite(summary.verified) ? fullNumber(summary.verified) : "—",
    executableLabel: Number.isFinite(summary.executable) ? fullNumber(summary.executable) : "—",
    unresolvedLabel: unresolved === null ? "—" : fullNumber(unresolved)
  };
  if (typeof summary.currentBytesChecked === "boolean") {
    result.currentBytesLabel = summary.currentBytesChecked ? "Checked now" : "Receipt only";
  }
  if (Number.isFinite(summary.executableHashReads)) result.hashReadsLabel = fullNumber(summary.executableHashReads);
  return result;
}

export function toolRuntimeItemPresentation(tool = {}, now = Date.now()) {
  const flags = [
    ["locked", tool.locked],
    ["installed", tool.installed],
    ["verified", tool.verified],
    ["executable", tool.executable]
  ].map(([label, value]) => `${label} ${value === true ? "yes" : value === false ? "no" : "unknown"}`);
  const tone = tool.executable === true
    ? "ready"
    : ["invalid", "invalid-lock", "invalid-receipt"].includes(tool.state)
      ? "invalid"
      : "unresolved";
  const evidence = tool.verificationEvidence;
  const verifiedAt = Date.parse(evidence?.lastVerifiedAt || "");
  const observedAt = now instanceof Date ? now.getTime() : Number(now);
  const evidenceAgeMs = Number.isFinite(verifiedAt) && Number.isFinite(observedAt)
    ? Math.max(0, observedAt - verifiedAt)
    : null;
  const evidenceLabel = evidence?.lastVerifiedAt
    ? `Last verified ${dateTime(evidence.lastVerifiedAt)} ` +
      `(${formatAge(evidenceAgeMs)}) · ` +
      `${readableCapability(evidence.kind || "unknown")} · ` +
      `${evidence.currentBytesChecked === true ? "current bytes checked" : "current bytes not checked"}`
    : null;
  return {
    id: tool.id || "unknown",
    name: tool.name || tool.id || "Unknown tool",
    state: tool.state || "unknown",
    stateLabel: readableCapability(tool.state || "unknown"),
    tone,
    flags,
    ...(evidenceLabel ? { evidenceLabel } : {}),
    reasons: Array.isArray(tool.reasons) ? tool.reasons.map(readableCapability) : []
  };
}

function shortId(value) {
  if (!value) return "—";
  return value.length > 24 ? `${value.slice(0, 10)}…${value.slice(-7)}` : value;
}

function initials(value) {
  return value
    .split(/[_.:-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("") || "?";
}

function emptyState(glyph, title, detail, small = false) {
  const container = element("div", `empty-state${small ? " small" : ""}`);
  container.append(
    element("span", "empty-glyph", glyph),
    element("strong", "", title),
    element("span", "", detail)
  );
  container.firstElementChild.setAttribute("aria-hidden", "true");
  return container;
}

function deriveAgentsFromEvents(events) {
  const latest = new Map();
  for (const event of events) {
    const agent = event.agent || event.component;
    if (!agent && !event.taskId) continue;
    const key = `${agent || "unknown"}:${event.taskId || event.runId || "unassigned"}`;
    if (latest.has(key)) continue;
    latest.set(key, {
      id: key,
      agent: agent || "unknown",
      role: event.component,
      taskId: event.taskId,
      runId: event.runId,
      status: event.status,
      stage: event.kind,
      effect: event.effect,
      updatedAt: event.at,
      startedAt: null,
      totalTokens: null
    });
  }
  return [...latest.values()].slice(0, 50);
}

function activeAgents() {
  return state.status.agents.length ? state.status.agents : deriveAgentsFromEvents(state.events);
}

function renderAgents() {
  const agents = activeAgents().filter((agent) => {
    if (state.agentFilter === "active") return ["queued", "running", "waiting"].includes(agent.status);
    if (state.agentFilter === "attention") return ["blocked", "failed"].includes(agent.status);
    return true;
  });

  if (!agents.length) {
    view.agentList.replaceChildren(
      emptyState(
        "◇",
        state.agentFilter === "all" ? "No active agent metadata" : "No agents match this filter",
        state.agentFilter === "all" ? "The observer will reconcile when work starts." : "Choose another state to continue."
      )
    );
    return;
  }

  const fragment = document.createDocumentFragment();
  for (const agent of agents) {
    const card = element("article", `agent-card ${agent.status}`);
    const head = element("div", "agent-card-head");
    const name = element("div", "agent-name");
    const avatar = element("span", "agent-avatar", initials(agent.agent));
    avatar.setAttribute("aria-hidden", "true");
    const title = element("span", "agent-title", agent.agent);
    title.title = agent.agent;
    name.append(avatar, title);
    head.append(name, element("span", `state-pill ${agent.status}`, agent.status));

    const references = element("dl", "task-reference");
    references.append(
      element("dt", "", "Task"),
      element("dd", "", shortId(agent.taskId)),
      element("dt", "", "Stage"),
      element("dd", "", agent.stage || "unknown"),
      element("dt", "", "Run"),
      element("dd", "", shortId(agent.runId))
    );

    const foot = element("div", "agent-card-foot");
    const effect = element("span", `effect-pill ${agent.effect}`, agent.effect);
    const observed = element("time", "", relativeTime(agent.updatedAt));
    if (agent.updatedAt) {
      observed.dateTime = agent.updatedAt;
      observed.title = dateTime(agent.updatedAt);
    }
    foot.append(effect, observed);
    card.append(head, references, foot);
    fragment.append(card);
  }
  view.agentList.replaceChildren(fragment);
}

function eventSearchText(event) {
  return [event.kind, event.status, event.effect, event.agent, event.component, event.taskId, event.action.category, event.action.toolName]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function renderEvents() {
  const query = state.search.trim().toLowerCase();
  const events = query ? state.events.filter((event) => eventSearchText(event).includes(query)) : state.events;
  if (!events.length) {
    const item = element("li", "");
    item.append(
      emptyState(
        "⌁",
        query ? "No safe metadata matches" : "No activity received",
        query ? "Try a status, agent, tool, or effect class." : "The observer will reconcile automatically."
      )
    );
    view.eventList.replaceChildren(item);
    return;
  }

  const fragment = document.createDocumentFragment();
  for (const event of events) {
    const item = element("li", `timeline-item ${event.status}`);
    item.append(element("span", "timeline-dot"));
    item.firstElementChild.setAttribute("aria-hidden", "true");

    const body = element("article", "timeline-event");
    const meta = element("div", "timeline-meta");
    const kind = element("span", "timeline-kind", readableKind(event.kind));
    kind.title = event.kind;
    const time = element("time", "timeline-time", relativeTime(event.at));
    time.dateTime = event.at;
    time.title = dateTime(event.at);
    meta.append(kind, time);

    const details = element("div", "timeline-details");
    const statusNode = element("span", `state-pill ${event.status}`, event.status);
    details.append(statusNode);
    if (event.agent || event.component) details.append(element("code", "", event.agent || event.component));
    if (event.taskId) details.append(element("span", "", `task ${shortId(event.taskId)}`));
    if (event.action.toolName) details.append(element("span", "", `tool ${event.action.toolName}`));
    if (Number.isFinite(event.action.durationMs)) details.append(element("span", "", `${event.action.durationMs} ms`));
    if (event.effect !== "none") details.append(element("span", `effect-pill ${event.effect}`, event.effect));

    body.append(meta, details);
    item.append(body);
    fragment.append(item);
  }
  view.eventList.replaceChildren(fragment);
}

function renderLearnings() {
  setText(view.learningCount, state.learnings.length ? String(state.learnings.length) : "—");
  if (!state.learnings.length) {
    const item = element("li", "");
    item.append(emptyState("△", "No learning records", "Applied changes will appear with evidence state.", true));
    view.learningList.replaceChildren(item);
    return;
  }

  const fragment = document.createDocumentFragment();
  for (const learning of state.learnings) {
    const item = element("li", "learning-item");
    const meta = element("div", "learning-meta");
    const statusNode = element("span", `learning-status ${learning.status}`, learning.status);
    const scope = element("span", "", learning.scope);
    const id = element("span", "learning-id", shortId(learning.id));
    id.title = learning.id;
    meta.append(statusNode, scope, id);

    const text = element("dl", "learning-text");
    text.append(
      element("dt", "", "Cause"),
      element("dd", "", learning.cause),
      element("dt", "", "Change"),
      element("dd", "change", learning.change)
    );

    const observed = element("time", "timeline-time", relativeTime(learning.at));
    observed.dateTime = learning.at;
    observed.title = dateTime(learning.at);
    observed.style.display = "block";
    observed.style.marginTop = "9px";
    item.append(meta, text, observed);
    fragment.append(item);
  }
  view.learningList.replaceChildren(fragment);
}

function applyCaseSelection({ focus = false } = {}) {
  if (!view.caseGrid) return;
  let selected = null;
  for (const card of view.caseGrid.querySelectorAll("[data-case-id]")) {
    const active = card.dataset.caseId === state.selectedCaseId;
    card.tabIndex = active ? 0 : -1;
    if (active) {
      card.setAttribute("aria-current", "true");
      selected = card;
    } else {
      card.removeAttribute("aria-current");
    }
  }
  if (focus) selected?.focus();
}

function renderCases() {
  const continuity = captureCaseRenderContinuity(view.caseGrid, document.activeElement);
  const cases = Array.isArray(state.status.cases) ? state.status.cases : [];
  state.selectedCaseId = cycleCaseSelection(cases, state.selectedCaseId, 0);
  continuity.fallbackFocusCaseId = state.selectedCaseId;
  setText(view.caseCount, String(cases.length));
  const scan = state.status.caseScan || {};
  setText(view.caseScan, caseScanPresentation(scan, cases.length));

  if (!cases.length) {
    view.caseGrid.replaceChildren(
      emptyState("▱", "No cases observed", "Create or bind a case to open its separate activity terminal.")
    );
    return;
  }

  const fragment = document.createDocumentFragment();
  for (const caseView of cases) {
    const display = casePresentation(caseView, state.status.operator);
    const card = element("article", `case-card state-${display.state} case-${display.status}`);
    card.dataset.caseId = display.id;
    card.tabIndex = display.id === state.selectedCaseId ? 0 : -1;
    const headingId = `case-title-${display.id}`;
    card.setAttribute("aria-labelledby", headingId);
    if (display.id === state.selectedCaseId) card.setAttribute("aria-current", "true");
    card.addEventListener("focus", () => {
      state.selectedCaseId = display.id;
      applyCaseSelection();
    });
    card.addEventListener("click", () => {
      state.selectedCaseId = display.id;
      applyCaseSelection();
    });

    const header = element("header", "case-card-header");
    const identity = element("div", "case-card-identity");
    identity.append(
      element("p", "eyebrow", "Case terminal"),
      element("h3", "", display.displayName),
      element("code", "", shortId(display.id))
    );
    identity.querySelector("h3").id = headingId;
    const stateGroup = element("div", "case-card-state");
    if (display.indeterminate) {
      const spinner = element("span", "terminal-spinner");
      spinner.setAttribute("aria-hidden", "true");
      stateGroup.append(spinner);
    }
    stateGroup.append(element("span", `state-pill ${display.state}`, display.state));
    header.append(identity, stateGroup);

    const terminal = element("section", "case-terminal");
    terminal.setAttribute("role", "log");
    terminal.setAttribute("aria-live", "off");
    terminal.setAttribute("aria-busy", String(display.active));
    terminal.setAttribute("aria-label", `${display.displayName} structured lifecycle activity`);
    terminal.append(element("p", "terminal-greeting", display.greeting));
    const lines = element("ol", "terminal-lines");
    for (const line of display.lines) {
      const item = element("li", `terminal-line tone-${line.tone}`);
      const value = element("span", "terminal-value", line.value);
      if (line.observedAt) {
        const observed = element("time", "terminal-observed", relativeTime(line.observedAt));
        observed.dateTime = line.observedAt;
        observed.title = dateTime(line.observedAt);
        value.append(" · ", observed);
      }
      item.append(
        element("span", "terminal-label", line.label),
        value
      );
      lines.append(item);
    }
    terminal.append(lines);

    const progress = element(
      "div",
      `terminal-progress${display.indeterminate ? " indeterminate" : ""}${display.active ? " active" : ""}`
    );
    if (display.indeterminate) {
      progress.setAttribute("role", "progressbar");
      progress.setAttribute("aria-label", `${display.displayName} activity`);
      progress.setAttribute("aria-valuetext", "In progress; completion percentage unavailable");
      progress.append(element("span", ""));
    }
    card.append(header, terminal, progress);
    fragment.append(card);
  }
  view.caseGrid.replaceChildren(fragment);
  restoreCaseRenderContinuity(view.caseGrid, continuity);
}

function renderCapabilityList(node, values, emptyLabel) {
  const entries = values.length ? values : [emptyLabel];
  const fragment = document.createDocumentFragment();
  for (const value of entries) fragment.append(element("li", values.length ? "" : "empty", readableCapability(value)));
  node.replaceChildren(fragment);
}

function renderExecution() {
  const execution = state.status.execution;
  const presentation = executionPresentation(execution);
  setText(view.executionLane, presentation.laneLabel);
  view.executionLane.className = `source-badge execution-${presentation.laneState}`;
  setText(view.executionMode, presentation.modeLabel);
  setText(view.executionRunning, presentation.runningLabel);
  setText(view.executionStopping, presentation.stoppingLabel);
  setText(view.executionConfigured, presentation.configuredLabel);
  renderCapabilityList(
    view.executionEnforced,
    execution.enforced,
    execution.configured === null ? "awaiting-status" : "none-reported"
  );
  renderCapabilityList(
    view.executionBestEffort,
    execution.bestEffort,
    execution.configured === null ? "awaiting-status" : "none-reported"
  );
  renderCapabilityList(
    view.executionUnavailable,
    execution.unavailable,
    execution.configured === null ? "awaiting-status" : "none-reported"
  );
  if (!execution.recent.length) {
    view.executionRuns.replaceChildren(element("li", "execution-run-empty", "No execution records observed"));
  } else {
    const fragment = document.createDocumentFragment();
    for (const run of execution.recent.slice(0, 12)) {
      const display = executionRunPresentation(run);
      const item = element("li", "execution-run");
      const head = element("div", "execution-run-head");
      const runId = element("code", "", shortId(display.runId));
      runId.title = display.runId;
      head.append(runId, element("span", `state-pill ${display.status}`, display.status));
      const detail = element("div", "execution-run-detail");
      detail.append(
        element("span", "", `manifest ${shortId(display.manifestId)}`),
        element("span", "", `engagement ${shortId(display.engagementId)}`)
      );
      if (display.result) detail.append(element("span", "", readableCapability(display.result)));
      const observed = element("time", "timeline-time", relativeTime(display.observedAt));
      if (display.observedAt) {
        observed.dateTime = display.observedAt;
        observed.title = dateTime(display.observedAt);
      }
      item.append(head, detail, observed);
      fragment.append(item);
    }
    view.executionRuns.replaceChildren(fragment);
  }
  setText(
    view.executionNote,
    `${presentation.reasonLabel ? `${presentation.reasonLabel}. ` : ""}` +
      "Every launch requires an approved, digest-bound one-shot manifest. Running counts reflect durable records, not independent process proof. " +
      `Engagement registry: ${engagementScanPresentation(state.status.engagementScan).label}.`
  );
}

function renderOfflineAnalysis() {
  const analysis = state.status.offlineAnalysis;
  const presentation = offlineAnalysisPresentation(analysis);
  setText(view.offlineAnalysisLane, presentation.laneLabel);
  view.offlineAnalysisLane.className = `source-badge execution-${presentation.laneState}`;
  setText(view.offlineAnalysisMode, presentation.modeLabel);
  setText(view.offlineAnalysisConfigured, presentation.configuredLabel);
  const countNodes = {
    queued: view.offlineAnalysisQueued,
    running: view.offlineAnalysisRunning,
    succeeded: view.offlineAnalysisSucceeded,
    failed: view.offlineAnalysisFailed,
    cancelled: view.offlineAnalysisCancelled,
    blocked: view.offlineAnalysisBlocked,
    unknown: view.offlineAnalysisUnknown
  };
  for (const [name, node] of Object.entries(countNodes)) {
    const value = analysis.counts[name];
    setText(node, Number.isFinite(value) ? String(value) : "—");
  }
  setText(view.offlineAnalysisRetentionHealth, presentation.retentionStateLabel);
  view.offlineAnalysisRetentionHealth.className = `source-badge retention-${presentation.retentionState}`;
  setText(view.offlineAnalysisRetentionOverQuota, presentation.retentionOverQuotaLabel);
  setText(view.offlineAnalysisRetentionMissing, presentation.retentionMissingLabel);
  setText(view.offlineAnalysisRetentionInvalid, presentation.retentionInvalidLabel);
  setText(view.offlineAnalysisRetentionOrphaned, presentation.retentionOrphanedLabel);
  setText(view.offlineAnalysisRetentionOrphanedBytes, presentation.retentionOrphanedBytesLabel);
  setText(view.offlineAnalysisRetentionPurgePending, presentation.retentionPurgePendingLabel);
  setText(view.offlineAnalysisRetentionUnknown, presentation.retentionUnknownLabel);
  setText(view.offlineAnalysisControlHealth, presentation.controlStateLabel);
  view.offlineAnalysisControlHealth.className = `source-badge control-${presentation.controlState}`;
  setText(view.offlineAnalysisControlMutation, presentation.controlMutationLabel);
  setText(view.offlineAnalysisControlLock, presentation.controlLockLabel);
  setText(view.offlineAnalysisControlSnapshot, presentation.controlSnapshotLabel);
  setText(view.offlineAnalysisControlPending, presentation.controlPendingLabel);
  setText(view.offlineAnalysisControlInvalidTransactions, presentation.controlInvalidTransactionsLabel);
  setText(view.offlineAnalysisControlCreating, presentation.controlCreatingLabel);
  setText(view.offlineAnalysisControlInvalidCreations, presentation.controlInvalidCreationsLabel);
  setText(view.offlineAnalysisControlInvalidClaims, presentation.controlInvalidClaimsLabel);
  setText(view.offlineAnalysisControlInvalidPurges, presentation.controlInvalidPurgesLabel);
  setText(view.offlineAnalysisControlInvalidRuns, presentation.controlInvalidRunsLabel);
  setText(view.offlineAnalysisControlBlockedManifests, presentation.controlBlockedManifestsLabel);

  if (!analysis.recent.length) {
    view.offlineAnalysisRuns.replaceChildren(element("li", "execution-run-empty", "No offline analysis records observed"));
  } else {
    const fragment = document.createDocumentFragment();
    for (const run of analysis.recent.slice(0, 8)) {
      const display = offlineAnalysisRunPresentation(run);
      const item = element("li", "offline-analysis-run");
      const head = element("div", "offline-analysis-run-head");
      const runId = element("code", "", shortId(display.runId));
      runId.title = display.runId;
      head.append(runId, element("span", `state-pill ${display.status}`, display.status));
      item.append(
        head,
        element("span", `isolation-state ${display.isolationState}`, display.isolationLabel)
      );
      fragment.append(item);
    }
    view.offlineAnalysisRuns.replaceChildren(fragment);
  }
  setText(
    view.offlineAnalysisNote,
    `${presentation.retentionLabel}. ${presentation.reasonLabel ? `${presentation.reasonLabel}. ` : ""}` +
      "Run labels are process-scoped pseudonyms. Artifact identity, paths, evidence, output, and confirmations stay private."
  );
}

function renderToolRuntimes() {
  const runtimes = state.status.toolRuntimes;
  const presentation = toolRuntimePresentation(runtimes);
  setText(view.toolRuntimeHealth, presentation.healthLabel);
  view.toolRuntimeHealth.className = `source-badge runtime-${presentation.healthState}`;
  setText(view.toolRuntimeMode, presentation.modeLabel);
  setText(view.toolRuntimePlatform, presentation.platformLabel);
  setText(view.toolRuntimeCatalog, presentation.catalogLabel);
  setText(view.toolRuntimeLocked, presentation.lockedLabel);
  setText(view.toolRuntimeInstalled, presentation.installedLabel);
  setText(view.toolRuntimeVerified, presentation.verifiedLabel);
  setText(view.toolRuntimeExecutable, presentation.executableLabel);
  setText(view.toolRuntimeUnresolved, presentation.unresolvedLabel);
  setText(view.toolRuntimeCurrentBytes, presentation.currentBytesLabel || "Unknown");
  setText(view.toolRuntimeHashReads, presentation.hashReadsLabel || "—");

  const constraints = Array.isArray(runtimes.unresolvedConstraints) ? runtimes.unresolvedConstraints : [];
  if (!constraints.length) {
    view.toolRuntimeConstraints.replaceChildren(element("li", "empty", "none reported"));
  } else {
    const fragment = document.createDocumentFragment();
    for (const constraint of constraints) {
      fragment.append(element("li", "", `${readableCapability(constraint.reason)} · ${fullNumber(constraint.count)}`));
    }
    view.toolRuntimeConstraints.replaceChildren(fragment);
  }

  const tools = Array.isArray(runtimes.tools) ? runtimes.tools : [];
  setText(view.toolRuntimeCount, Number.isFinite(runtimes.catalog) ? `${tools.length} / ${runtimes.catalog}` : String(tools.length));
  if (!tools.length) {
    view.toolRuntimeList.replaceChildren(element("li", "execution-run-empty", "No managed runtime metadata observed"));
    return;
  }
  const fragment = document.createDocumentFragment();
  for (const tool of tools) {
    const display = toolRuntimeItemPresentation(tool);
    const item = element("li", `tool-runtime-item ${display.tone}`);
    const head = element("div", "tool-runtime-head");
    const identity = element("span", "tool-runtime-identity");
    identity.append(element("strong", "", display.name), element("code", "", display.id));
    head.append(identity, element("span", `runtime-state ${display.tone}`, display.stateLabel));
    const flags = element("div", "tool-runtime-flags");
    for (const flag of display.flags) flags.append(element("span", "", flag));
    item.append(head, flags);
    if (display.evidenceLabel) item.append(element("p", "tool-runtime-evidence", display.evidenceLabel));
    if (display.reasons.length) item.append(element("p", "tool-runtime-reasons", display.reasons.join(" · ")));
    fragment.append(item);
  }
  view.toolRuntimeList.replaceChildren(fragment);
}

function setMeter(meter, fill, percent, label) {
  const available = Number.isFinite(percent);
  const width = available ? percent : 0;
  fill.style.width = `${width}%`;
  fill.classList.toggle("warning", available && percent >= 80 && percent < 95);
  fill.classList.toggle("critical", available && percent >= 95);
  meter.setAttribute("aria-valuetext", label);
  if (available) meter.setAttribute("aria-valuenow", String(Math.round(percent)));
  else meter.removeAttribute("aria-valuenow");
}

function renderUsage() {
  const usage = state.status.usage;
  const available = usage.availability !== "unavailable";
  const scopeLabel = usageScopeLabel(usage);
  const contextPercent = boundedPercent(usage.context.usedTokens, usage.context.windowTokens);
  const budgetPercent = boundedPercent(usage.budget.usedTokens, usage.budget.limitTokens);
  const contextWindowKnown = Number.isFinite(usage.context.windowTokens);
  const budgetLimitKnown = Number.isFinite(usage.budget.limitTokens);

  setText(view.usageAvailability, usage.availability);
  view.usageAvailability.className = `source-badge ${usage.availability}`;

  const contextLabel = Number.isFinite(contextPercent)
    ? `${formatTokens(usage.context.usedTokens)} / ${formatTokens(usage.context.windowTokens)} · ${Math.round(contextPercent)}%`
    : contextWindowKnown
      ? `Window ${formatTokens(usage.context.windowTokens)} · use unavailable`
      : "Unavailable";
  setText(view.contextLabel, contextLabel);
  setMeter(view.contextMeter, view.contextFill, contextPercent, contextLabel);

  const budgetLabel = Number.isFinite(budgetPercent)
    ? `${formatTokens(usage.budget.usedTokens)} / ${formatTokens(usage.budget.limitTokens)} · ${Math.round(budgetPercent)}%`
    : budgetLimitKnown
      ? `Limit ${formatTokens(usage.budget.limitTokens)} · use unavailable`
      : "Unavailable";
  setText(view.budgetLabel, budgetLabel);
  setMeter(view.budgetMeter, view.budgetFill, budgetPercent, budgetLabel);

  setText(view.tokenInput, available ? formatTokens(usage.inputTokens) : "—");
  setText(view.tokenCached, available ? formatTokens(usage.cachedInputTokens) : "—");
  setText(view.tokenOutput, available ? formatTokens(usage.outputTokens) : "—");
  setText(view.tokenReasoning, available ? formatTokens(usage.reasoningTokens) : "—");
  for (const [node, number] of [
    [view.tokenInput, usage.inputTokens],
    [view.tokenCached, usage.cachedInputTokens],
    [view.tokenOutput, usage.outputTokens],
    [view.tokenReasoning, usage.reasoningTokens]
  ]) {
    node.title = available ? `${fullNumber(number)} tokens` : "Token data unavailable";
  }

  setText(view.usageSource, usage.source ? `${scopeLabel} · source ${usage.source}` : scopeLabel);
  setText(view.usageUpdated, usage.updatedAt ? `Updated ${relativeTime(usage.updatedAt)}` : "Never observed");

  setText(view.metricTokens, available && Number.isFinite(usage.totalTokens) ? formatTokens(usage.totalTokens) : "Unavailable");
  view.metricTokens.title = available ? `${fullNumber(usage.totalTokens)} total tokens` : "Token data unavailable";
  setText(
    view.metricTokensDetail,
    available
      ? `${scopeLabel} · ${usage.availability}${usage.model ? ` · ${usage.model}` : ""}`
      : `${scopeLabel} · no provider data`
  );
  setText(
    view.metricContext,
    Number.isFinite(contextPercent) ? `${Math.round(contextPercent)}%` : contextWindowKnown ? formatTokens(usage.context.windowTokens) : "Unavailable"
  );
  setText(
    view.metricContextDetail,
    Number.isFinite(contextPercent)
      ? `${formatTokens(usage.context.windowTokens - usage.context.usedTokens)} tokens left`
      : contextWindowKnown
        ? "Window known · use unavailable"
        : "No active window"
  );
}

function latestObservedAt() {
  if (state.status.telemetry.lastActivityAt) return state.status.telemetry.lastActivityAt;
  const candidates = [state.status.usage.updatedAt, state.events[0]?.at, state.learnings[0]?.at].filter(Boolean);
  if (!candidates.length) return null;
  return candidates.sort((left, right) => Date.parse(right) - Date.parse(left))[0];
}

function syncMotionState() {
  if (!browserAvailable) return;
  const suspended = state.paused || document.hidden || ["stale", "offline", "unknown"].includes(state.connectionState);
  document.documentElement.dataset.motion = suspended ? "paused" : "running";
}

function renderConnection() {
  const observedAt = latestObservedAt();
  const computedTelemetry = freshness(observedAt);
  const telemetry = observedAt
    ? computedTelemetry
    : state.status.telemetry.state !== "unknown"
      ? {
          state: state.status.telemetry.state,
          ageMs: Number.isFinite(state.status.telemetry.ageSeconds) ? state.status.telemetry.ageSeconds * 1_000 : null
        }
      : computedTelemetry;
  const endpointFailures = state.failedEndpoints.size;
  const network = freshness(state.lastNetworkSuccess ? new Date(state.lastNetworkSuccess).toISOString() : null);
  let connectionState = network.state;
  let label = network.state === "live" ? "Live" : network.state === "unknown" ? "Connecting" : network.state;

  if (state.paused) {
    connectionState = "paused";
    label = "Paused";
  } else if (endpointFailures > 0 && endpointFailures < 3) {
    connectionState = "stale";
    label = "Partial";
  } else if (endpointFailures === 3) {
    connectionState = "offline";
    label = "Disconnected";
  }

  state.connectionState = connectionState;
  syncMotionState();
  view.connectionIndicator.className = `pulse ${connectionState}`;
  setText(view.connectionLabel, label.charAt(0).toUpperCase() + label.slice(1));
  setText(view.metricFreshness, telemetry.state === "unknown" ? "Unknown" : telemetry.state.charAt(0).toUpperCase() + telemetry.state.slice(1));
  setText(view.metricFreshnessDetail, telemetry.ageMs === null ? "No observation yet" : `Observed ${formatAge(telemetry.ageMs)}`);
  setText(
    view.pollDetail,
    state.paused
      ? "Live refresh paused"
      : endpointFailures
        ? `${endpointFailures} endpoint${endpointFailures === 1 ? "" : "s"} unavailable · retrying`
        : "Refresh every 2 seconds"
  );
}

function renderMetrics() {
  const agents = activeAgents();
  const counts = deriveCounts({ ...state.status, agents });
  const countText = (value) => Number.isFinite(value) ? String(value) : "—";
  const attention = Number.isFinite(counts.blocked) && Number.isFinite(counts.failed) ? counts.blocked + counts.failed : null;
  setText(view.metricRunning, countText(counts.running));
  setText(
    view.metricRunningDetail,
    Number.isFinite(counts.queued) ? `${counts.queued} fleet queued · ${agents.length} base members observed` : "Waiting for status"
  );
  setText(view.metricWaiting, countText(counts.waiting));
  setText(view.metricAttention, countText(attention));
  renderUsage();
  renderConnection();
}

function render() {
  renderMetrics();
  renderCases();
  renderExecution();
  renderOfflineAnalysis();
  renderToolRuntimes();
  renderAgents();
  renderEvents();
  renderLearnings();
}

async function fetchJson(url) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      cache: "no-store",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
      mode: "same-origin",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: controller.signal
    });
    if (!response.ok) throw new Error(`${url} returned ${response.status}`);
    const text = await response.text();
    if (text.length > MAX_RESPONSE_BYTES) throw new Error(`${url} response exceeds local dashboard limit`);
    return JSON.parse(text);
  } finally {
    window.clearTimeout(timeout);
  }
}

function validCollectionPayload(value, key) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    value.apiVersion === OBSERVER_API_VERSION && Array.isArray(value[key]);
}

function validStatusPayload(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    value.apiVersion === OBSERVER_API_VERSION &&
    typeof value.at === "string" && Number.isFinite(Date.parse(value.at)) &&
    OBSERVER_STATUS_STATES.has(value.state) &&
    value.counts !== null && typeof value.counts === "object" && !Array.isArray(value.counts) &&
    value.telemetry !== null && typeof value.telemetry === "object" && !Array.isArray(value.telemetry) &&
    Array.isArray(value.cases);
}

/**
 * Reconcile independently fetched projections without discarding a last-known
 * valid collection when one endpoint is unavailable or malformed.
 */
export function reconcileRefreshResults(current, results, now = Date.now()) {
  const failedEndpoints = new Set();
  let status = current.status;
  let events = current.events;
  let learnings = current.learnings;
  let networkSucceeded = false;

  if (results.status.status === "fulfilled" && validStatusPayload(results.status.value)) {
    status = sanitizeStatusPayload(results.status.value);
    networkSucceeded = true;
  } else {
    failedEndpoints.add(observerContract.status);
  }

  if (results.events.status === "fulfilled" && validCollectionPayload(results.events.value, "events")) {
    events = sanitizeEventsPayload(results.events.value);
    networkSucceeded = true;
  } else {
    failedEndpoints.add(observerContract.events);
  }

  if (results.learnings.status === "fulfilled" && validCollectionPayload(results.learnings.value, "learnings")) {
    learnings = sanitizeLearningsPayload(results.learnings.value);
    networkSucceeded = true;
  } else {
    failedEndpoints.add(observerContract.learnings);
  }

  return {
    ...current,
    status,
    events,
    learnings,
    failedEndpoints,
    lastNetworkSuccess: networkSucceeded ? now : current.lastNetworkSuccess
  };
}

async function refresh({ announce = false } = {}) {
  if (state.refreshing || (state.paused && !announce)) return;
  state.refreshing = true;
  view.refreshButton.disabled = true;

  const endpoints = [observerContract.status, observerContract.events, observerContract.learnings];
  const [statusResult, eventsResult, learningsResult] = await Promise.allSettled(endpoints.map(fetchJson));
  Object.assign(state, reconcileRefreshResults(state, {
    status: statusResult,
    events: eventsResult,
    learnings: learningsResult
  }));

  state.refreshing = false;
  view.refreshButton.disabled = false;
  render();
  if (announce) {
    setText(
      view.screenReaderStatus,
      state.failedEndpoints.size ? `Refresh complete. ${state.failedEndpoints.size} endpoints unavailable.` : "Observer refreshed."
    );
  }
}

function schedule() {
  window.clearTimeout(state.timer);
  state.timer = window.setTimeout(async () => {
    if (!state.paused) await refresh();
    schedule();
  }, POLL_INTERVAL_MS);
}

function togglePause() {
  state.paused = !state.paused;
  view.pauseButton.setAttribute("aria-pressed", String(state.paused));
  view.pauseButton.querySelector(".button-label").textContent = state.paused ? "Resume" : "Pause";
  view.pauseButton.querySelector(".button-icon").textContent = state.paused ? "▶" : "Ⅱ";
  renderConnection();
  setText(view.screenReaderStatus, state.paused ? "Live updates paused." : "Live updates resumed.");
  if (!state.paused) refresh({ announce: true });
}

function showShortcuts() {
  if (!view.shortcutsDialog.open && typeof view.shortcutsDialog.showModal === "function") view.shortcutsDialog.showModal();
}

export function observerShortcutAllowed(event = {}, dialogOpen = false) {
  return event.defaultPrevented !== true && event.isComposing !== true &&
    event.altKey !== true && event.ctrlKey !== true && event.metaKey !== true && !dialogOpen;
}

function cycleCaseFocus(direction) {
  const cases = Array.isArray(state.status.cases) ? state.status.cases : [];
  const selected = cycleCaseSelection(cases, state.selectedCaseId, direction);
  if (!selected) {
    view.casePanel?.focus();
    setText(view.screenReaderStatus, "No case terminals are available.");
    return;
  }
  state.selectedCaseId = selected;
  applyCaseSelection({ focus: true });
  const current = cases.find((item) => item.id === selected);
  setText(view.screenReaderStatus, `Focused case ${current?.displayName || selected}.`);
}

function handleKeyboard(event) {
  if (!observerShortcutAllowed(event, view.shortcutsDialog?.open === true)) return;
  const target = event.target;
  const editing = target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || target?.isContentEditable;
  if (editing && event.key !== "Escape") return;

  const focusTargets = {
    "0": "#case-panel",
    "1": "#fleet-panel",
    "2": "#timeline-panel",
    "3": "#execution-panel",
    "4": "#telemetry-panel",
    "5": "#learning-panel",
    "6": "#offline-analysis-panel",
    "7": "#tool-runtime-panel"
  };
  if (focusTargets[event.key]) {
    event.preventDefault();
    document.querySelector(focusTargets[event.key])?.focus();
    return;
  }
  if (event.key === "/") {
    event.preventDefault();
    view.eventSearch.focus();
  } else if (event.key === "[") {
    event.preventDefault();
    cycleCaseFocus(-1);
  } else if (event.key === "]") {
    event.preventDefault();
    cycleCaseFocus(1);
  } else if (event.key.toLowerCase() === "r") {
    event.preventDefault();
    refresh({ announce: true });
  } else if (event.key.toLowerCase() === "p") {
    event.preventDefault();
    togglePause();
  } else if (event.key === "?") {
    event.preventDefault();
    showShortcuts();
  } else if (event.key === "Escape" && editing) {
    target.blur();
  }
}

if (browserAvailable) {
  document.querySelectorAll("[data-agent-filter]").forEach((button) => {
    button.addEventListener("click", () => {
      state.agentFilter = button.dataset.agentFilter;
      document.querySelectorAll("[data-agent-filter]").forEach((candidate) => {
        const selected = candidate === button;
        candidate.classList.toggle("selected", selected);
        candidate.setAttribute("aria-pressed", String(selected));
      });
      renderAgents();
    });
  });

  view.eventSearch.addEventListener("input", () => {
    state.search = view.eventSearch.value.slice(0, 80);
    renderEvents();
  });
  view.pauseButton.addEventListener("click", togglePause);
  view.refreshButton.addEventListener("click", () => refresh({ announce: true }));
  view.shortcutsButton.addEventListener("click", showShortcuts);
  document.addEventListener("keydown", handleKeyboard);
  document.addEventListener("visibilitychange", syncMotionState);

  window.setInterval(() => {
    const now = new Date();
    view.clock.dateTime = now.toISOString();
    setText(view.clock, now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }));
    renderConnection();
  }, 1_000);

  render();
  refresh();
  schedule();
}
