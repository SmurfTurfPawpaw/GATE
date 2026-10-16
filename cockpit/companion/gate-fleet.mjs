const LOCAL_FLEET_VERSION = "gate.local-fleet/v1";
const OBSERVER_VERSION = "gate.observer/v1";
const DEFAULT_OBSERVER_URL = "http://127.0.0.1:4173/api/status";
const DEFAULT_TIMEOUT_MS = 3_500;
const DEFAULT_CACHE_MS = 2_000;
const MAX_OBSERVER_BYTES = 2_000_000;
const MAX_COUNT = 1_000_000_000;
const MAX_TOKENS = Number.MAX_SAFE_INTEGER;

const OBSERVER_ROOT_KEYS = [
  "apiVersion", "at", "state", "counts", "agents", "tasks", "usage", "budget", "telemetry",
  "execution", "workflows", "engagementScan", "offlineAnalysis", "toolRuntimes", "operator", "cases",
  "caseScan", "profileSetups", "profileSetupScan", "engagements", "projects", "upstreams"
];
const CASE_KEYS = [
  "id", "displayName", "status", "binding", "isolation", "runtimeHealth", "state", "counts", "telemetry",
  "usage", "execution", "workflows", "engagementScan", "offlineAnalysis", "activity", "learningCount"
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

function validateCase(value) {
  if (!exactKeys(value, CASE_KEYS) || typeof value.id !== "string" || !/^case_[a-f0-9]{16}$/u.test(value.id)
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
    stage: lanes.size === 1 ? [...lanes][0] : lanes.size > 1 ? "multiple" : value.state === "idle" ? "idle" : "unknown"
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

function caseCampaign(item, alias, fleetPrecision) {
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
    tokens: Object.freeze({ availability: item.usage.availability, total: item.usage.total })
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
    tokens: Object.freeze({ availability: "unavailable", total: null })
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

function unavailableProjection(receivedAt, revision) {
  return Object.freeze({
    apiVersion: LOCAL_FLEET_VERSION,
    revision,
    observedAt: null,
    receivedAt,
    connection: "unavailable",
    sourceFreshness: "unavailable",
    coverage: Object.freeze({ state: "unavailable", cases: unavailableScan(), profiles: unavailableScan(true) }),
    summary: Object.freeze({
      campaigns: unavailableMetric(), active: unavailableMetric(), waiting: unavailableMetric(), attention: unavailableMetric(),
      profileAnswers: Object.freeze({ answered: null, total: null, precision: "unavailable" }),
      runningExecutions: unavailableMetric(), activeWorkflows: unavailableMetric(), runningAnalyses: unavailableMetric(),
      setupBlockers: unavailableMetric(), campaignTokens: Object.freeze({ availability: "unavailable", total: null }),
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

export function projectGateObserverStatus(value, options = {}) {
  const receivedAt = options.receivedAt instanceof Date ? options.receivedAt : new Date(options.receivedAt || Date.now());
  const revision = options.revision ?? 1;
  const aliases = options.aliases || new Map();
  if (!Number.isSafeInteger(revision) || revision < 1 || !(aliases instanceof Map)
      || !exactKeys(value, OBSERVER_ROOT_KEYS)
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
  const sourceCases = value.cases.map(validateCase);
  const sourceProfiles = value.profileSetups.map(validateProfile);
  if (sourceCases.some((item) => !item) || sourceProfiles.some((item) => !item)) throw new Error("invalid GATE observer campaign");

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
    ...visibleCases.map((item) => caseCampaign(item, aliasFor(aliases, `case:${item.sourceId}`), casePrecision)),
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
  return Object.freeze({
    apiVersion: LOCAL_FLEET_VERSION,
    revision,
    observedAt: value.at,
    receivedAt: receivedAt.toISOString(),
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
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const cacheMs = options.cacheMs ?? DEFAULT_CACHE_MS;
  const maximumBytes = options.maximumBytes ?? MAX_OBSERVER_BYTES;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 50 || timeoutMs > 30_000
      || !Number.isSafeInteger(cacheMs) || cacheMs < 0 || cacheMs > 30_000
      || !Number.isSafeInteger(maximumBytes) || maximumBytes < 1024 || maximumBytes > 2 * 1024 * 1024) {
    throw new Error("GATE observer provider limits are invalid");
  }
  const aliases = new Map();
  let revision = 0;
  let cached = null;
  let cachedAt = 0;
  let inFlight = null;
  return async function gateFleet() {
    const nowMs = typeof options.now === "function" ? options.now() : Date.now();
    if (cached && nowMs - cachedAt < cacheMs) return cached;
    if (inFlight) return inFlight;
    inFlight = (async () => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      revision += 1;
      const receivedAt = new Date(typeof options.now === "function" ? options.now() : Date.now());
      try {
        const response = await fetchImpl(observerUrl, {
          method: "GET",
          redirect: "error",
          cache: "no-store",
          signal: controller.signal,
          headers: { Accept: "application/json" }
        });
        const source = await boundedJson(response, maximumBytes);
        return projectGateObserverStatus(source, { aliases, revision, receivedAt });
      } catch {
        return unavailableProjection(receivedAt.toISOString(), revision);
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
  return async () => unavailableProjection(new Date(typeof options.now === "function" ? options.now() : Date.now()).toISOString(), ++revision);
}

export const gateFleetInternals = Object.freeze({
  DEFAULT_CACHE_MS,
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
