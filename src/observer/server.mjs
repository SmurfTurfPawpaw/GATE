import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { buildStatus } from "../lib/status.mjs";
import { redactSensitiveHeaders } from "../lib/text.mjs";

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
const USAGE_AVAILABILITY = new Set(["exact", "estimated", "unavailable"]);
const UPSTREAM_INTEGRITY = new Set(["verified", "receipt-only", "commit-only", "invalid", "not-installed"]);
const PROJECT_STATUSES = new Set(["ready", "invalid"]);
const PROJECT_PROVIDERS = new Set(["github", "gitlab", "forgejo", "gitea", "local"]);
const PROJECT_ENVIRONMENTS = new Set(["host", "rootless-container", "container", "vm", "remote-lab"]);
const PROJECT_DELIVERY_MODES = new Set(["no-mistakes", "direct-pr", "local-only"]);
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
  "supervision-lost"
]);
const EXECUTION_SIGNALS = new Set(Object.keys(os.constants.signals || {}));
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
const ENGAGEMENT_STATUSES = new Set(["draft", "proposed", "approved", "active", "paused", "closed", "expired", "revoked"]);
const TECHNICAL_REVIEW_STATUSES = new Set(["pending", "passed", "failed"]);
const OPERATOR_RECEIPT_STATUSES = new Set(["pending", "approved", "revoked"]);
const OBSERVER_API_VERSION = "gate.observer/v1";
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
    .replace(/(^|\s)(?:~\/|\/(?:[^\s/]+\/)+[^\s,;]*)/gu, "$1[path withheld]")
    .replace(/\b(?:sk|pk|ghp|github_pat|xox[baprs])-?[A-Za-z0-9_-]{12,}\b/giu, "[secret withheld]")
    .replace(/\b(?:api[-_ ]?key|access[-_ ]?token)\s*[:=]\s*\S+/giu, "[secret withheld]");
  return redactSensitiveHeaders(redacted).slice(0, 240);
}

function identifier(value, maximum = 160) {
  const text = boundedString(value, maximum);
  return text && /^[A-Za-z0-9][A-Za-z0-9_.:/-]*$/u.test(text) ? text : null;
}

function publicName(value, maximum = 160) {
  const text = boundedString(value, maximum);
  return text && /^[A-Za-z0-9][A-Za-z0-9_.:-]*$/u.test(text) ? text : null;
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

/** Apply the same strict allowlist to gate.learning/v1 records. */
export function projectLearning(value) {
  const learning = object(value);
  if (!learning || learning.apiVersion !== "gate.learning/v1") return null;
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
  return {
    apiVersion: "gate.learning/v1",
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
          provider: identifier(session.provider) || null,
          model: boundedString(session.model, 160),
          source: boundedString(session.source, 160) || "codex-session-jsonl",
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
    source: boundedString(raw.source, 160) || recorded?.source || "codex-session-jsonl",
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

function usageSession(record) {
  return {
    id: opaqueId("session", [record.runId, record.taskId, record.agent, record.provider, record.model].join("\u0000")),
    at: record.at,
    updatedAt: record.at,
    provider: publicName(record.provider),
    model: record.model,
    source: record.source,
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
      group.deltas.sort((left, right) => Date.parse(right.at) - Date.parse(left.at));
      selected.push({
        ...group.deltas[0],
        availability: group.deltas.some((record) => record.availability === "estimated") ? "estimated" : "exact",
        inputTokens: sumKnown(group.deltas, "inputTokens"),
        cachedInputTokens: sumKnown(group.deltas, "cachedInputTokens"),
        outputTokens: sumKnown(group.deltas, "outputTokens"),
        reasoningTokens: sumKnown(group.deltas, "reasoningTokens"),
        totalTokens: sumKnown(group.deltas, "totalTokens")
      });
    } else if (group.cumulative.length) {
      group.cumulative.sort((left, right) => Date.parse(right.at) - Date.parse(left.at));
      selected.push(group.cumulative[0]);
    } else if (group.unavailable.length) {
      group.unavailable.sort((left, right) => Date.parse(right.at) - Date.parse(left.at));
      selected.push(group.unavailable[0]);
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

function publicLearning(learning) {
  const privateRecord = learning.sensitivity === "private";
  return {
    id: learning.id,
    at: learning.at,
    scope: learning.scope,
    cause: privateRecord ? "Private learning recorded." : safeLearningText(learning.cause),
    change: privateRecord ? "Details withheld from observer." : safeLearningText(learning.change),
    status: learning.status,
    sensitivity: learning.sensitivity,
    supersedes: learning.supersedes,
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
    signal: safeEnum(run.signal, EXECUTION_SIGNALS, null)
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
    runningCount: counts.running,
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
  const learnings = Array.isArray(raw.learnings) ? raw.learnings.map(projectLearning).filter(Boolean) : [];
  learnings.sort((left, right) => Date.parse(right.at) - Date.parse(left.at));
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
  const state = counts.failed > 0
    ? "failed"
    : counts.blocked > 0
      ? "blocked"
      : counts.waiting > 0
        ? "waiting"
        : counts.running > 0
          ? "running"
          : members.length
            ? "idle"
            : "unknown";
  const usage = projectUsage(raw.tokens);
  const lastActivityAt = events[0]?.at || usage.sessions.map((session) => session.at).filter(Boolean).sort().at(-1) || null;
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
      offlineAnalysis,
      engagements: Array.isArray(raw.engagements)
        ? raw.engagements.map((value) => summarizeEngagement(value, execution)).filter(Boolean)
        : [],
      projects: Array.isArray(raw.projects)
        ? raw.projects.map((value) => summarizeProject(value, execution)).filter(Boolean)
        : [],
      upstreams: Array.isArray(raw.upstreams) ? raw.upstreams.map(summarizeUpstream).filter(Boolean) : []
    },
    events: { apiVersion: OBSERVER_API_VERSION, at: generatedAt, events: events.map(publicEvent) },
    learnings: { apiVersion: OBSERVER_API_VERSION, at: generatedAt, learnings: learnings.map(publicLearning) }
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

export function createObserver(options = {}) {
  const paths = options.paths;
  if (!paths?.repo) throw new Error("observer paths.repo is required");
  const host = options.host || "127.0.0.1";
  if (!isLoopbackHost(host)) throw new Error("observer must bind to a loopback address");
  const dashboardRoot = path.resolve(options.dashboardRoot || path.join(paths.repo, "dashboard"));
  // Static content is snapshotted before the server can listen. Requests never
  // reopen a path, so later replacement or symlink exchange cannot cross the
  // dashboard-root trust boundary.
  const staticAssets = preloadStaticAssets(dashboardRoot);
  const statusBuilder = options.statusBuilder || buildStatus;
  const requestedRefreshMs = Number(options.refreshMs ?? 2_000);
  const refreshMs = Number.isFinite(requestedRefreshMs) ? Math.max(250, requestedRefreshMs) : 2_000;
  let cached = null;
  let cachedAt = 0;
  let inFlight = null;

  async function snapshot() {
    const now = Date.now();
    if (cached && now - cachedAt < refreshMs) return cached;
    if (inFlight) return inFlight;
    inFlight = Promise.resolve()
      .then(() => statusBuilder({ paths }))
      .then((status) => {
        cached = projectSnapshot(status, paths);
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
          telemetry: { ...cached.status.telemetry, freshness: "stale" }
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
      return json(response, 200, { ok: true, service: "gate-observer", at: new Date().toISOString() }, method);
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
    process.stdout.write(`GATE observer: http://${host.includes(":") ? `[${host}]` : host}:${listeningPort}\n`);
  }
  return server;
}
