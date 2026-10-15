import crypto from "node:crypto";

export const AGENT_SUMMARY_MAX_BYTES = 8 * 1024;
const TOOL_PAGE_DEFAULT = 10;
const TOOL_PAGE_MAX = 12;
const STATUS_CASE_MAX = 8;
const EXECUTION_COUNT_KEYS = ["queued", "running", "stopping", "succeeded", "failed", "cancelled", "blocked", "unknown"];
const OFFLINE_COUNT_KEYS = ["queued", "running", "succeeded", "failed", "cancelled", "blocked", "unknown"];
const WORKFLOW_COUNT_KEYS = ["active", "open", "stopped", "recovery-hold", "reported", "closed", "degraded", "unknown"];

function serializedEvidence(value) {
  const bytes = Buffer.from(JSON.stringify(value));
  return {
    sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
    bytes: bytes.length
  };
}

function prettyOutputBytes(value) {
  return Buffer.byteLength(`${JSON.stringify(value, null, 2)}\n`);
}

function boundedString(value, maximum = 96) {
  if (typeof value !== "string") return null;
  return value.length <= maximum ? value : `${value.slice(0, maximum - 1)}…`;
}

function nonNegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function categoryCounts(values, selector, maximum = 6) {
  const counts = new Map();
  for (const value of Array.isArray(values) ? values : []) {
    const key = boundedString(selector(value), 48);
    if (key) counts.set(key, (counts.get(key) || 0) + 1);
  }
  const ordered = [...counts].sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]));
  return {
    counts: Object.fromEntries(ordered.slice(0, maximum)),
    omittedKinds: Math.max(0, ordered.length - maximum)
  };
}

function usageSummary(value) {
  const tokenKeys = ["inputTokens", "cachedInputTokens", "outputTokens", "reasoningTokens", "totalTokens"];
  if (!Array.isArray(value)) {
    const availability = new Set(["exact", "estimated", "unavailable"]).has(value?.availability)
      ? value.availability
      : "unavailable";
    return {
      availability,
      source: boundedString(value?.source, 160) || "unavailable",
      totals: Object.fromEntries(tokenKeys.map((key) => [
        key,
        availability === "unavailable" ? null : nonNegativeInteger(value?.totals?.[key])
      ])),
      sessions: nonNegativeInteger(value?.matchedFiles) ?? (Array.isArray(value?.sessions) ? value.sessions.length : 0),
      scan: {
        discoveredFiles: nonNegativeInteger(value?.discoveredFiles),
        scannedFiles: nonNegativeInteger(value?.scannedFiles),
        payloadBytesRead: nonNegativeInteger(value?.bytesRead),
        cacheHits: nonNegativeInteger(value?.cacheHits),
        filesRead: nonNegativeInteger(value?.filesRead),
        partial: typeof value?.partial === "boolean" ? value.partial : null,
        truncated: typeof value?.truncated === "boolean" ? value.truncated : null
      }
    };
  }

  const tokenGroupKey = (record) => [
    record?.runId,
    record?.taskId,
    record?.agent,
    record?.provider,
    record?.model
  ].map((item) => item ?? "").join("\u0000");
  const groups = new Map();
  for (const record of value) {
    const availability = new Set(["exact", "estimated", "unavailable"]).has(record?.availability)
      ? record.availability
      : "unavailable";
    const measure = new Set(["delta", "cumulative", "unavailable"]).has(record?.measure)
      ? record.measure
      : "unavailable";
    if (
      availability === "unavailable" && measure !== "unavailable" ||
      availability !== "unavailable" && measure === "unavailable"
    ) continue;
    const key = tokenGroupKey(record);
    const group = groups.get(key) || { delta: [], cumulative: [], unavailable: [] };
    group[measure].push({ ...record, availability });
    groups.set(key, group);
  }
  const sumKnown = (records, key) => {
    const known = records.map((record) => record?.[key]).filter((item) => Number.isSafeInteger(item) && item >= 0);
    return known.length ? known.reduce((sum, item) => sum + item, 0) : null;
  };
  const latest = (records) => records.reduce((selected, record) => {
    if (!selected) return record;
    const selectedTime = Date.parse(selected?.at || 0);
    const recordTime = Date.parse(record?.at || 0);
    return (Number.isFinite(recordTime) ? recordTime : 0) >=
      (Number.isFinite(selectedTime) ? selectedTime : 0)
      ? record
      : selected;
  }, null);
  const selected = [];
  for (const group of groups.values()) {
    if (group.delta.length) {
      selected.push({
        availability: group.delta.some((record) => record.availability === "estimated") ? "estimated" : "exact",
        ...Object.fromEntries(tokenKeys.map((key) => [key, sumKnown(group.delta, key)]))
      });
    } else if (group.cumulative.length) selected.push(latest(group.cumulative));
    else if (group.unavailable.length) selected.push(latest(group.unavailable));
  }
  const available = selected.filter((record) => record?.availability !== "unavailable");
  const availability = available.length === 0
    ? "unavailable"
    : available.some((record) => record.availability === "estimated")
      ? "estimated"
      : "exact";
  const totals = Object.fromEntries(tokenKeys.map((key) => [key, sumKnown(available, key)]));
  return {
    availability,
    source: available.length ? "gate-token-log" : "unavailable",
    totals,
    sessions: selected.length,
    scan: {
      discoveredFiles: null,
      scannedFiles: null,
      payloadBytesRead: null,
      cacheHits: null,
      filesRead: null,
      partial: selected.some((record) => record.availability === "estimated"),
      truncated: null
    }
  };
}

function compactCounts(value, maximum = 6) {
  const entries = !value || typeof value !== "object" || Array.isArray(value)
    ? []
    : Object.entries(value)
      .filter(([, count]) => Number.isSafeInteger(count) && count >= 0)
      .map(([key, count]) => [boundedString(key, 48), count])
      .filter(([key]) => key)
      .sort(([left], [right]) => left.localeCompare(right));
  return {
    counts: Object.fromEntries(entries.slice(0, maximum)),
    omittedKinds: Math.max(0, entries.length - maximum)
  };
}

function runtimeEvidence(tool) {
  const evidence = tool?.verificationEvidence;
  const evidenceKinds = new Set([
    "installation-receipt",
    "current-bytes-and-install-smoke-evidence",
    "current-bytes-and-live-zero-egress-smoke"
  ]);
  return {
    id: boundedString(tool?.id, 64),
    state: boundedString(tool?.state, 40),
    installed: tool?.installed === true,
    verifiedNow: tool?.verified === true,
    evidence: evidence && typeof evidence === "object" ? {
      kind: evidenceKinds.has(evidence.kind) ? evidence.kind : null,
      lastVerifiedAt: boundedString(evidence.lastVerifiedAt, 40),
      ageSeconds: nonNegativeInteger(evidence.ageSeconds),
      current: evidence.current === true,
      currentBytesChecked: evidence.currentBytesChecked === true,
      liveSmokeExecutedNow: evidence.liveSmokeExecutedNow === true
    } : null
  };
}

function workflowInstanceSummary(value) {
  const instanceId = boundedString(value?.instanceId, 63);
  const statuses = new Set(["open", "stopped", "recovery-hold", "reported", "closed", "unknown"]);
  const health = new Set(["bounded-replay-verified", "degraded"]).has(value?.health) ? value.health : "degraded";
  const active = value?.activePhase && typeof value.activePhase === "object" ? value.activePhase : null;
  const controls = active?.envelopeControls && typeof active.envelopeControls === "object"
    ? Object.fromEntries(["wallTime", "requests", "rate", "parallel", "tokens", "evidenceBytes", "spend"].map((key) => [
      key,
      new Set(["enforced", "measured-only", "unavailable"]).has(active.envelopeControls[key])
        ? active.envelopeControls[key]
        : null
    ]))
    : null;
  return {
    instanceId,
    status: statuses.has(value?.status) ? value.status : "unknown",
    activePhase: active ? {
      id: boundedString(active.id, 80),
      lane: boundedString(active.lane, 40),
      effectClass: boundedString(active.effectClass, 8),
      toolId: boundedString(active.toolId, 80),
      envelopeControls: controls
    } : null,
    journalSequence: nonNegativeInteger(value?.journalSequence),
    reservations: nonNegativeInteger(value?.reservations),
    stops: nonNegativeInteger(value?.stops),
    health
  };
}

function workflowSummary(value) {
  const workflows = value && typeof value === "object" ? value : {};
  const rawCounts = workflows.counts && typeof workflows.counts === "object" ? workflows.counts : {};
  const rawScan = workflows.scan && typeof workflows.scan === "object" ? workflows.scan : {};
  const instances = Array.isArray(workflows.instances)
    ? workflows.instances.slice(0, 12).map(workflowInstanceSummary)
    : [];
  const total = nonNegativeInteger(rawCounts.total);
  return {
    counts: Object.fromEntries([
      "total", "active", "open", "stopped", "recovery-hold", "reported", "closed", "degraded", "unknown"
    ].map((key) => [key, nonNegativeInteger(rawCounts[key])])),
    instances,
    omittedInstances: total === null ? null : Math.max(0, total - instances.length),
    scan: {
      discovered: nonNegativeInteger(rawScan.discovered),
      scanned: nonNegativeInteger(rawScan.scanned),
      omitted: nonNegativeInteger(rawScan.omitted),
      complete: typeof rawScan.complete === "boolean" ? rawScan.complete : false,
      truncated: typeof rawScan.truncated === "boolean" ? rawScan.truncated : true
    }
  };
}

function statusSelectionSummary(status) {
  const source = status?.selection;
  const mode = new Set(["aggregate", "unassigned", "case"]).has(source?.mode)
    ? source.mode
    : "unknown";
  return {
    mode,
    caseId: mode === "case" ? boundedString(source?.caseId ?? status?.selectedCaseId, 63) : null,
    bindingHealth: mode === "case" ? {
      status: new Set(["ready", "stale"]).has(source?.bindingHealth?.status)
        ? source.bindingHealth.status
        : null,
      programCurrent: typeof source?.bindingHealth?.programCurrent === "boolean"
        ? source.bindingHealth.programCurrent
        : null,
      projectCurrent: typeof source?.bindingHealth?.projectCurrent === "boolean"
        ? source.bindingHealth.projectCurrent
        : null
    } : null
  };
}

function caseScanSummary(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return {
    attempted: typeof value.attempted === "boolean" ? value.attempted : null,
    limit: nonNegativeInteger(value.limit),
    discoveryLimit: nonNegativeInteger(value.discoveryLimit),
    discovered: nonNegativeInteger(value.discovered),
    scanned: nonNegativeInteger(value.scanned),
    omitted: nonNegativeInteger(value.omitted),
    invalid: nonNegativeInteger(value.invalid),
    discoveredAtLeast: typeof value.discoveredAtLeast === "boolean" ? value.discoveredAtLeast : null,
    omittedAtLeast: typeof value.omittedAtLeast === "boolean" ? value.omittedAtLeast : null,
    complete: typeof value.complete === "boolean" ? value.complete : false,
    truncated: typeof value.truncated === "boolean" ? value.truncated : true
  };
}

function exactLaneCounts(value, keys, totalKey = null) {
  const input = value && typeof value === "object" && !Array.isArray(value) ? value : null;
  const complete = input !== null && keys.every((key) => nonNegativeInteger(input[key]) !== null);
  const counts = {};
  let calculatedTotal = 0;
  if (input) {
    for (const key of keys) {
      const count = nonNegativeInteger(input[key]);
      if (count !== null) {
        calculatedTotal += count;
        if (count > 0) counts[key] = count;
      }
    }
  }
  const declaredTotal = totalKey === null ? calculatedTotal : nonNegativeInteger(input?.[totalKey]);
  return {
    total: complete && declaredTotal !== null ? declaredTotal : null,
    nonzero: counts,
    complete: complete && declaredTotal !== null
  };
}

function engagementLaneSummary(runtime) {
  const scan = runtime?.engagementScan;
  if (scan?.availability === "not-loaded") {
    return {
      availability: "not-loaded",
      visibleRecords: 0,
      statuses: {},
      scan: { complete: false, omittedAtLeast: null, invalid: null }
    };
  }
  const records = Array.isArray(runtime?.engagements) ? runtime.engagements : [];
  const statuses = categoryCounts(records, (engagement) => engagement?.metadata?.status || engagement?.status);
  return {
    availability: Array.isArray(runtime?.engagements) ? "loaded" : "unavailable",
    visibleRecords: records.length,
    statuses: statuses.counts,
    omittedStatusKinds: statuses.omittedKinds,
    scan: {
      complete: typeof scan?.complete === "boolean" ? scan.complete : false,
      omittedAtLeast: nonNegativeInteger(scan?.omittedAtLeast),
      invalid: nonNegativeInteger(scan?.invalid)
    }
  };
}

function caseBindingSummary(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return {
    id: boundedString(value.id, 80),
    current: typeof value.current === "boolean" ? value.current : null
  };
}

function compactCaseLaneCounts(value, keys, totalKey = null) {
  const projection = exactLaneCounts(value, keys, totalKey);
  if (!projection.complete) return { total: null };
  return Object.keys(projection.nonzero).length > 0
    ? { total: projection.total, nonzero: projection.nonzero }
    : { total: projection.total };
}

function caseStatusProjection(value) {
  const runtime = value?.runtime && typeof value.runtime === "object" && !Array.isArray(value.runtime)
    ? value.runtime
    : null;
  const tokenUsage = usageSummary(runtime?.tokens);
  const engagements = engagementLaneSummary(runtime);
  return {
    id: boundedString(value?.id, 63),
    displayName: boundedString(value?.displayName, 60),
    status: boundedString(value?.status, 16),
    binding: value?.binding && typeof value.binding === "object" ? {
      program: caseBindingSummary(value.binding.program),
      project: value.binding.project === null ? null : caseBindingSummary(value.binding.project)
    } : null,
    runtimeHealth: {
      status: new Set(["available", "unavailable"]).has(value?.runtimeHealth?.status)
        ? value.runtimeHealth.status
        : null,
      reason: new Set(["invalid-case", "runtime-observation-failed"]).has(value?.runtimeHealth?.reason)
        ? value.runtimeHealth.reason
        : null
    },
    runtimeAvailable: runtime !== null,
    lanes: {
      engagements: engagements.availability === "loaded"
        ? { availability: "loaded", visibleRecords: engagements.visibleRecords, statuses: engagements.statuses }
        : { availability: engagements.availability },
      execution: compactCaseLaneCounts(runtime?.execution?.counts, EXECUTION_COUNT_KEYS),
      workflows: compactCaseLaneCounts(runtime?.workflows?.counts, WORKFLOW_COUNT_KEYS, "total"),
      offlineAnalysis: compactCaseLaneCounts(runtime?.offlineAnalysis?.counts, OFFLINE_COUNT_KEYS),
      tokens: {
        availability: tokenUsage.availability,
        totalTokens: tokenUsage.totals.totalTokens
      }
    }
  };
}

function caseProjectionPriority(value) {
  if (value?.runtimeHealth?.status === "unavailable") return 2;
  const runtime = value?.runtime;
  if (!runtime || typeof runtime !== "object" || Array.isArray(runtime)) {
    return new Set(["stale", "invalid"]).has(value?.status) ? 1 : 0;
  }
  const positive = (counts, keys) => keys.some((key) => nonNegativeInteger(counts?.[key]) > 0);
  const active = positive(runtime?.execution?.counts, ["queued", "running", "stopping", "failed", "blocked", "unknown"]) ||
    positive(runtime?.workflows?.counts, ["active", "open", "stopped", "recovery-hold", "reported", "degraded", "unknown"]) ||
    positive(runtime?.offlineAnalysis?.counts, ["queued", "running", "failed", "blocked", "unknown"]);
  if (active) return 2;
  return new Set(["stale", "invalid"]).has(value?.status) ? 1 : 0;
}

function aggregateCaseLaneCounts(cases, source, keys, totalKey = null) {
  const totals = Object.fromEntries(keys.map((key) => [key, 0]));
  let total = 0;
  let caseRuntimes = 0;
  let complete = true;
  for (const item of cases) {
    const runtime = item?.runtime;
    if (!runtime || typeof runtime !== "object" || Array.isArray(runtime)) continue;
    caseRuntimes += 1;
    const value = source(runtime);
    const projection = exactLaneCounts(value, keys, totalKey);
    if (!projection.complete) complete = false;
    if (projection.total !== null) total += projection.total;
    for (const key of keys) {
      const count = nonNegativeInteger(value?.[key]);
      if (count !== null) totals[key] += count;
    }
  }
  return {
    caseRuntimes,
    total: complete ? total : null,
    nonzero: Object.fromEntries(Object.entries(totals).filter(([, count]) => count > 0)),
    complete
  };
}

function caseFleetSummary(status) {
  if (!Array.isArray(status?.cases) && (!status?.caseScan || typeof status.caseScan !== "object")) {
    return null;
  }
  const cases = Array.isArray(status?.cases) ? status.cases : [];
  const scan = caseScanSummary(status?.caseScan);
  const aggregateSelection = status?.selection?.mode === "aggregate" ||
    (!status?.selection && cases.length > 0);
  const statusCounts = categoryCounts(cases, (item) => item?.status);
  const items = cases
    .map((item, index) => ({ item, index, priority: caseProjectionPriority(item) }))
    .sort((left, right) => right.priority - left.priority || left.index - right.index)
    .slice(0, STATUS_CASE_MAX)
    .map(({ item }) => caseStatusProjection(item));
  const runtimeCases = cases.filter((item) => item?.runtime && typeof item.runtime === "object").length;
  const execution = aggregateCaseLaneCounts(cases, (runtime) => runtime?.execution?.counts, EXECUTION_COUNT_KEYS);
  const workflows = aggregateCaseLaneCounts(
    cases,
    (runtime) => runtime?.workflows?.counts,
    WORKFLOW_COUNT_KEYS,
    "total"
  );
  const offlineAnalysis = aggregateCaseLaneCounts(
    cases,
    (runtime) => runtime?.offlineAnalysis?.counts,
    OFFLINE_COUNT_KEYS
  );
  return {
    scan,
    observedCases: cases.length,
    runtimeCases,
    statuses: statusCounts.counts,
    omittedStatusKinds: statusCounts.omittedKinds,
    observedLaneCounts: aggregateSelection ? {
      coverageComplete: scan?.complete === true && runtimeCases === cases.length &&
        execution.complete && workflows.complete && offlineAnalysis.complete,
      execution,
      workflows,
      offlineAnalysis,
      engagements: { availability: "not-loaded-in-aggregate", recordsRead: 0 }
    } : null,
    projectionOrder: "active-or-unavailable-then-binding-source-stable",
    items,
    omittedObservedCases: Math.max(0, cases.length - items.length),
    retrieval: {
      list: "gate case list --json",
      caseStatus: "gate --case ID status --summary --json",
      aggregateStatus: "gate status --summary --json"
    }
  };
}

export function statusSummary(status) {
  const source = serializedEvidence(status);
  const runtimes = status?.toolRuntimes || {};
  const eventKinds = categoryCounts(status?.events, (event) => event?.kind);
  const learningStatuses = categoryCounts(status?.learnings, (learning) => learning?.status);
  const engagementStatuses = categoryCounts(
    status?.engagements,
    (engagement) => engagement?.metadata?.status || engagement?.status
  );
  const projectStatuses = categoryCounts(status?.projects, (project) => project?.status);
  const upstreamIntegrityStates = categoryCounts(status?.upstreams, (item) => item?.integrityState);
  const installedRuntimes = Array.isArray(runtimes.tools)
    ? runtimes.tools.filter((tool) => tool?.installed).slice(0, 5).map(runtimeEvidence)
    : [];
  const executionCounts = compactCounts(status?.execution?.counts);
  const offlineCounts = compactCounts(status?.offlineAnalysis?.counts);
  const workflows = workflowSummary(status?.workflows);
  const selection = statusSelectionSummary(status);
  const caseFleet = caseFleetSummary(status);
  const fullStatusCommand = selection.mode === "case"
    ? "gate --case ID status --json"
    : selection.mode === "unassigned"
      ? "gate --unassigned status --json"
      : "gate status --json";
  const workflowDetailCommand = selection.mode === "unassigned"
    ? "gate --unassigned workflow status ID --json"
    : "gate --case ID workflow status ID --json";
  const result = {
    apiVersion: "gate.status-summary/v1",
    at: boundedString(status?.at, 40),
    source: { ...source, projection: "bounded-summary", complete: false },
    selection,
    caseFleet,
    activity: {
      visibleEvents: Array.isArray(status?.events) ? status.events.length : 0,
      eventKinds: eventKinds.counts,
      visibleLearnings: Array.isArray(status?.learnings) ? status.learnings.length : 0,
      learningStatuses: learningStatuses.counts,
      engagements: engagementStatuses.counts,
      projects: projectStatuses.counts
    },
    execution: {
      laneAvailable: status?.execution?.capability?.laneAvailable === true,
      mode: boundedString(status?.execution?.capability?.mode, 80),
      counts: executionCounts.counts,
      omittedCountKinds: executionCounts.omittedKinds
    },
    workflows,
    offlineAnalysis: {
      laneAvailable: status?.offlineAnalysis?.capability?.laneAvailable === true,
      mode: boundedString(status?.offlineAnalysis?.capability?.mode, 80),
      counts: offlineCounts.counts,
      omittedCountKinds: offlineCounts.omittedKinds,
      retainedArtifacts: nonNegativeInteger(status?.offlineAnalysis?.retention?.retainedArtifacts),
      retainedBytes: nonNegativeInteger(status?.offlineAnalysis?.retention?.retainedBytes),
      mutationBlocked: typeof status?.offlineAnalysis?.retention?.mutationBlocked === "boolean"
        ? status.offlineAnalysis.retention.mutationBlocked
        : null
    },
    tokens: usageSummary(status?.tokens),
    upstreams: {
      total: Array.isArray(status?.upstreams) ? status.upstreams.length : 0,
      installed: Array.isArray(status?.upstreams) ? status.upstreams.filter((item) => item?.installed).length : 0,
      ready: Array.isArray(status?.upstreams) ? status.upstreams.filter((item) => item?.ready).length : 0,
      integrityStates: upstreamIntegrityStates.counts
    },
    toolRuntimes: {
      verificationMode: boundedString(runtimes.verificationMode, 80),
      currentBytesChecked: typeof runtimes.currentBytesChecked === "boolean" ? runtimes.currentBytesChecked : null,
      executableHashReads: nonNegativeInteger(runtimes.executableHashReads),
      catalog: nonNegativeInteger(runtimes.catalog),
      locked: nonNegativeInteger(runtimes.locked),
      installed: nonNegativeInteger(runtimes.installed),
      verifiedNow: nonNegativeInteger(runtimes.verified),
      executable: nonNegativeInteger(runtimes.executable),
      unresolved: nonNegativeInteger(runtimes.unresolved),
      installedRuntimes,
      omittedInstalledRuntimes: Math.max(0, (nonNegativeInteger(runtimes.installed) || 0) - installedRuntimes.length)
    },
    omitted: {
      eventBodies: Array.isArray(status?.events) ? status.events.length : 0,
      learningBodies: Array.isArray(status?.learnings) ? status.learnings.length : 0,
      engagementBodies: Array.isArray(status?.engagements) ? status.engagements.length : 0,
      projectBodies: Array.isArray(status?.projects) ? status.projects.length : 0,
      upstreamBodies: Array.isArray(status?.upstreams) ? status.upstreams.length : 0,
      runtimeBodies: Array.isArray(runtimes.tools) ? runtimes.tools.length : 0,
      workflowBodies: Array.isArray(status?.workflows?.instances) ? status.workflows.instances.length : 0,
      eventKinds: eventKinds.omittedKinds,
      learningStatuses: learningStatuses.omittedKinds,
      engagementStatuses: engagementStatuses.omittedKinds,
      projectStatuses: projectStatuses.omittedKinds,
      upstreamIntegrityStates: upstreamIntegrityStates.omittedKinds
    },
    retrieval: {
      fullStatus: fullStatusCommand,
      unassignedStatus: "gate --unassigned status --summary --json",
      selectedCaseStatus: "gate --case ID status --summary --json",
      workflowDetail: workflowDetailCommand,
      toolPage: "gate tool list --summary --limit 10 --cursor 0 --json",
      toolDetail: "gate tool show ID --json"
    }
  };
  while (prettyOutputBytes(result) >= AGENT_SUMMARY_MAX_BYTES && result.workflows.instances.length > 0) {
    result.workflows.instances.pop();
    result.workflows.omittedInstances = result.workflows.counts.total === null
      ? null
      : Math.max(0, result.workflows.counts.total - result.workflows.instances.length);
  }
  while (prettyOutputBytes(result) >= AGENT_SUMMARY_MAX_BYTES && result.caseFleet?.items.length > 0) {
    result.caseFleet.items.pop();
    result.caseFleet.omittedObservedCases = Math.max(
      0,
      result.caseFleet.observedCases - result.caseFleet.items.length
    );
  }
  while (prettyOutputBytes(result) >= AGENT_SUMMARY_MAX_BYTES && result.toolRuntimes.installedRuntimes.length > 0) {
    result.toolRuntimes.installedRuntimes.pop();
    result.toolRuntimes.omittedInstalledRuntimes = Math.max(
      0,
      (nonNegativeInteger(runtimes.installed) || 0) - result.toolRuntimes.installedRuntimes.length
    );
  }
  if (prettyOutputBytes(result) >= AGENT_SUMMARY_MAX_BYTES) {
    throw new Error("status summary exceeded its 8 KiB output contract");
  }
  return result;
}

function pageInteger(value, fallback, maximum = Number.MAX_SAFE_INTEGER) {
  if (value === undefined || value === null) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > maximum) {
    throw new Error(`summary page value must be an integer from 0 to ${maximum}`);
  }
  return parsed;
}

function compactTool(tool) {
  return {
    id: boundedString(tool?.id, 80),
    name: boundedString(tool?.name, 96),
    category: boundedString(tool?.category, 40),
    riskClass: boundedString(tool?.riskClass, 8),
    readiness: boundedString(tool?.readiness, 80),
    compatible: tool?.compatible === true,
    locked: tool?.managedRuntimeLocked === true,
    installed: tool?.installed === true,
    integrityVerifiedNow: tool?.integrityVerified === true,
    adapterReady: tool?.adapterReady === true,
    executionAvailable: tool?.executionAvailable === true
  };
}

export function toolInventorySummary(inventory, options = {}) {
  const tools = Array.isArray(inventory?.tools) ? inventory.tools : [];
  const limit = pageInteger(options.limit, TOOL_PAGE_DEFAULT, TOOL_PAGE_MAX);
  if (limit < 1) throw new Error(`summary page limit must be an integer from 1 to ${TOOL_PAGE_MAX}`);
  const cursor = pageInteger(options.cursor, 0, tools.length);
  const page = tools.slice(cursor, cursor + limit).map(compactTool);
  const result = {
    apiVersion: "gate.tool-summary/v1",
    source: { ...serializedEvidence(inventory), projection: "bounded-page", complete: false },
    host: boundedString(inventory?.host, 40),
    filters: {
      profile: boundedString(options.profile ?? inventory?.profile?.id, 80),
      category: boundedString(options.category, 80)
    },
    profile: inventory?.profile ? {
      id: boundedString(inventory.profile.id, 80),
      maxRiskClass: boundedString(inventory.profile.maxRiskClass, 8)
    } : null,
    verificationMode: boundedString(inventory?.verificationMode, 40),
    counts: {
      selected: nonNegativeInteger(inventory?.count) ?? tools.length,
      locked: nonNegativeInteger(inventory?.locked),
      installed: nonNegativeInteger(inventory?.installed),
      receiptOnly: nonNegativeInteger(inventory?.receiptOnly),
      verifiedNow: nonNegativeInteger(inventory?.verified),
      executable: nonNegativeInteger(inventory?.executable),
      unresolved: nonNegativeInteger(inventory?.unresolved)
    },
    page: {
      cursor,
      limit,
      shown: page.length,
      omittedBefore: cursor,
      omittedAfter: Math.max(0, tools.length - cursor - page.length),
      omittedCount: Math.max(0, tools.length - page.length),
      nextCursor: null
    },
    tools: page,
    retrieval: {
      nextPage: null,
      pageCommand: "gate tool list [same filters] --summary --limit N --cursor N --json",
      detail: "gate tool show ID --json"
    }
  };
  const updatePage = () => {
    const shown = result.tools.length;
    const nextCursor = cursor + shown < tools.length ? cursor + shown : null;
    result.page.shown = shown;
    result.page.omittedAfter = Math.max(0, tools.length - cursor - shown);
    result.page.omittedCount = Math.max(0, tools.length - shown);
    result.page.nextCursor = nextCursor;
    result.retrieval.nextPage = nextCursor === null ? null : { cursor: nextCursor, limit, preserveFilters: true };
  };
  updatePage();
  while (prettyOutputBytes(result) >= AGENT_SUMMARY_MAX_BYTES && result.tools.length > 1) {
    result.tools.pop();
    updatePage();
  }
  if (prettyOutputBytes(result) >= AGENT_SUMMARY_MAX_BYTES) {
    throw new Error("tool summary exceeded its 8 KiB output contract");
  }
  return result;
}

function boundedArray(values, maximum = 12) {
  const source = Array.isArray(values) ? values : [];
  return { values: source.slice(0, maximum).map((value) => boundedString(value, 160)), omittedCount: Math.max(0, source.length - maximum) };
}

export function toolDetailSummary(tool) {
  const source = serializedEvidence(tool);
  const unavailable = boundedArray(tool?.unavailable);
  const executionModes = boundedArray(tool?.executionModes);
  const result = {
    apiVersion: "gate.tool-detail/v1",
    source: { ...source, projection: "bounded-detail", complete: false },
    tool: compactTool(tool),
    metadata: {
      openSource: typeof tool?.openSource === "boolean" ? tool.openSource : null,
      license: boundedString(tool?.license, 80),
      upstream: boundedString(tool?.upstream, 240),
      command: boundedString(tool?.command, 80),
      version: boundedString(tool?.version, 80),
      approval: boundedString(tool?.approval, 80),
      knownGoodProvenance: tool?.knownGoodProvenance === true,
      targetAuthority: boundedString(tool?.targetAuthority, 80),
      installationGrantsAuthority: tool?.installationGrantsAuthority === true
    },
    constraints: {
      unavailable: unavailable.values,
      omittedUnavailable: unavailable.omittedCount,
      executionModes: executionModes.values,
      omittedExecutionModes: executionModes.omittedCount
    },
    retrieval: { plan: `gate tool plan ${boundedString(tool?.id, 80) || "ID"} --json` }
  };
  if (prettyOutputBytes(result) >= AGENT_SUMMARY_MAX_BYTES) {
    throw new Error("tool detail exceeded its 8 KiB output contract");
  }
  return result;
}
