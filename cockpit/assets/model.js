const SCHEMA = "gate.public-cockpit/v1";

const ROOT_KEYS = ["schema", "mode", "site", "gate", "snapshot", "aggregate", "campaigns", "decision", "activity"];
const SITE_KEYS = ["version"];
const GATE_KEYS = ["version"];
const SNAPSHOT_KEYS = ["generatedAt", "validUntil"];
const AGGREGATE_KEYS = ["overallProgress", "testsPassed", "testsTotal", "tokenStatus", "tokensUsed", "tokenBudget", "learningCount", "blockerCount"];
const CAMPAIGN_KEYS = ["alias", "stage", "progress", "attention", "freshness", "codex", "currentAction"];
const DECISION_KEYS = ["id", "revision", "expiresAt", "state", "campaign", "prompt", "choices", "recommended"];
const ACTIVITY_KEYS = ["at", "campaign", "category", "completed", "total", "result", "progress"];

const STAGES = new Set(["intake", "mapping", "testing", "validating", "reporting", "paused", "complete"]);
const ATTENTION = new Set(["steady", "watch", "response-needed"]);
const FRESHNESS = new Set(["preview", "current", "delayed"]);
const CODEX_STATES = new Set(["working", "waiting", "idle"]);
const TOKEN_STATES = new Set(["available", "unavailable"]);
const MODES = new Set(["preview", "observed"]);
const ACTIONS = new Set(["profiling", "mapping-surface", "running-tests", "reviewing-evidence", "awaiting-reply", "preparing-report", "idle"]);
const DECISION_STATES = new Set(["clear", "waiting"]);
const PROMPTS = new Set(["choose-depth", "confirm-priority", "select-next-step"]);
const CHOICES = new Set(["recommended-depth", "balanced-depth", "focused-depth", "continue", "review-first", "pause"]);
const ACTIVITY_CATEGORIES = new Set(["profile", "map", "test", "validate", "report", "learn"]);
const ACTIVITY_RESULTS = new Set(["progress", "passed", "attention", "recorded"]);

const ACTION_LABELS = Object.freeze({
  profiling: "Building the campaign profile",
  "mapping-surface": "Mapping the authorized surface",
  "running-tests": "Running structured tests",
  "reviewing-evidence": "Reviewing collected evidence",
  "awaiting-reply": "Waiting for Giovanni",
  "preparing-report": "Preparing the report",
  idle: "No active action"
});

const CATEGORY_LABELS = Object.freeze({
  profile: "Profile",
  map: "Map",
  test: "Test",
  validate: "Validate",
  report: "Report",
  learn: "Learn"
});

const RESULT_LABELS = Object.freeze({
  progress: "Advanced",
  passed: "Checks passed",
  attention: "Needs attention",
  recorded: "Learning retained"
});

const PROMPT_LABELS = Object.freeze({
  "choose-depth": "How deeply should Codex explore the current lead?",
  "confirm-priority": "Which campaign should Codex prioritize next?",
  "select-next-step": "What should Codex do at this checkpoint?"
});

const CHOICE_LABELS = Object.freeze({
  "recommended-depth": "Explore deeply",
  "balanced-depth": "Keep a balanced pace",
  "focused-depth": "Focus only on this lead",
  continue: "Continue",
  "review-first": "Let me review first",
  pause: "Pause this campaign"
});

const STAGE_LABELS = Object.freeze({
  intake: "Intake",
  mapping: "Mapping",
  testing: "Testing",
  validating: "Validating",
  reporting: "Reporting",
  paused: "Paused",
  complete: "Complete"
});

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, keys) {
  if (!record(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function safeVersion(value) {
  return typeof value === "string" && /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(value);
}

function timestamp(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) return null;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return null;
  const canonicalInput = value.includes(".") ? value : value.replace("Z", ".000Z");
  return new Date(parsed).toISOString() === canonicalInput ? parsed : null;
}

function boundedInteger(value, minimum, maximum) {
  return Number.isInteger(value) && value >= minimum && value <= maximum;
}

function safeAlias(value) {
  return typeof value === "string" && /^Campaign [1-9]\d{0,2}$/.test(value);
}

function unavailable(reason) {
  return Object.freeze({ kind: "unavailable", reason });
}

export function parsePublicSnapshot(input, options = {}) {
  const now = options.now instanceof Date ? options.now.getTime() : Date.now();

  if (!exactKeys(input, ROOT_KEYS)) return unavailable("invalid");
  if (input.schema !== SCHEMA) return unavailable("invalid");
  if (!MODES.has(input.mode)) return unavailable("invalid");
  if (!exactKeys(input.site, SITE_KEYS) || !safeVersion(input.site.version)) return unavailable("invalid");
  if (!exactKeys(input.gate, GATE_KEYS) || !safeVersion(input.gate.version)) return unavailable("invalid");
  if (!exactKeys(input.snapshot, SNAPSHOT_KEYS)) return unavailable("invalid");

  const generatedAt = timestamp(input.snapshot.generatedAt);
  const validUntil = input.snapshot.validUntil === null ? null : timestamp(input.snapshot.validUntil);
  if (generatedAt === null || generatedAt > now + 300_000) return unavailable("invalid");
  if (input.mode === "preview") {
    if (input.snapshot.validUntil !== null) return unavailable("invalid");
  } else {
    if (validUntil === null || generatedAt >= validUntil || validUntil - generatedAt > 900_000) return unavailable("invalid");
    if (now > validUntil) return unavailable("stale");
  }
  if (options.minimumGeneratedAt !== undefined) {
    const minimumGeneratedAt = timestamp(options.minimumGeneratedAt);
    if (minimumGeneratedAt === null || generatedAt < minimumGeneratedAt) return unavailable("invalid");
  }

  if (!exactKeys(input.aggregate, AGGREGATE_KEYS)) return unavailable("invalid");
  if (!TOKEN_STATES.has(input.aggregate.tokenStatus)) return unavailable("invalid");
  const tokenUsageValid = input.aggregate.tokenStatus === "available"
    ? boundedInteger(input.aggregate.tokensUsed, 0, 1_000_000_000)
      && boundedInteger(input.aggregate.tokenBudget, 1, 1_000_000_000)
      && input.aggregate.tokensUsed <= input.aggregate.tokenBudget
    : input.aggregate.tokensUsed === null && input.aggregate.tokenBudget === null;
  if (!tokenUsageValid
    || !boundedInteger(input.aggregate.overallProgress, 0, 100)
    || !boundedInteger(input.aggregate.testsPassed, 0, 999_999)
    || !boundedInteger(input.aggregate.testsTotal, 0, 999_999)
    || input.aggregate.testsPassed > input.aggregate.testsTotal
    || !boundedInteger(input.aggregate.learningCount, 0, 999_999)
    || !boundedInteger(input.aggregate.blockerCount, 0, 999_999)) return unavailable("invalid");

  if (!Array.isArray(input.campaigns) || input.campaigns.length > 24) return unavailable("invalid");
  const aliases = new Set();
  const campaigns = [];
  for (const item of input.campaigns) {
    if (!exactKeys(item, CAMPAIGN_KEYS) || !safeAlias(item.alias) || aliases.has(item.alias)) return unavailable("invalid");
    if (!STAGES.has(item.stage) || !boundedInteger(item.progress, 0, 100)) return unavailable("invalid");
    if (!ATTENTION.has(item.attention) || !FRESHNESS.has(item.freshness) || !CODEX_STATES.has(item.codex) || !ACTIONS.has(item.currentAction)) {
      return unavailable("invalid");
    }
    if ((input.mode === "preview") !== (item.freshness === "preview")) return unavailable("invalid");
    aliases.add(item.alias);
    campaigns.push(Object.freeze({ ...item }));
  }

  if (!exactKeys(input.decision, DECISION_KEYS) || !DECISION_STATES.has(input.decision.state)) return unavailable("invalid");
  const decisionEmpty = input.decision.state === "clear";
  if (decisionEmpty) {
    if (input.decision.id !== null || input.decision.revision !== null || input.decision.expiresAt !== null
      || input.decision.campaign !== null || input.decision.prompt !== null || !Array.isArray(input.decision.choices)
      || input.decision.choices.length !== 0 || input.decision.recommended !== null) {
      return unavailable("invalid");
    }
  } else {
    const decisionExpiry = input.decision.expiresAt === null ? null : timestamp(input.decision.expiresAt);
    if (!/^dec_[a-f0-9]{16}$/.test(input.decision.id) || !boundedInteger(input.decision.revision, 1, 999_999)
      || !aliases.has(input.decision.campaign) || !PROMPTS.has(input.decision.prompt)
      || !Array.isArray(input.decision.choices) || input.decision.choices.length < 2 || input.decision.choices.length > 3
      || new Set(input.decision.choices).size !== input.decision.choices.length
      || input.decision.choices.some((choice) => !CHOICES.has(choice))
      || !input.decision.choices.includes(input.decision.recommended)) return unavailable("invalid");
    if (input.mode === "preview" ? input.decision.expiresAt !== null : decisionExpiry === null || decisionExpiry <= generatedAt || decisionExpiry > validUntil) {
      return unavailable("invalid");
    }
  }

  if (!Array.isArray(input.activity) || input.activity.length > 32) return unavailable("invalid");
  const activity = [];
  let previousActivityAt = Number.POSITIVE_INFINITY;
  for (const item of input.activity) {
    const activityAt = timestamp(item.at);
    if (!exactKeys(item, ACTIVITY_KEYS) || activityAt === null || activityAt > generatedAt || activityAt > previousActivityAt) return unavailable("invalid");
    if (!aliases.has(item.campaign) || !ACTIVITY_CATEGORIES.has(item.category) || !ACTIVITY_RESULTS.has(item.result)
      || !boundedInteger(item.completed, 0, 999_999) || !boundedInteger(item.total, 1, 999_999)
      || item.completed > item.total || !boundedInteger(item.progress, 0, 100)) return unavailable("invalid");
    activity.push(Object.freeze({ ...item }));
    previousActivityAt = activityAt;
  }

  return Object.freeze({
    kind: "available",
    schema: SCHEMA,
    mode: input.mode,
    siteVersion: input.site.version,
    gateVersion: input.gate.version,
    generatedAt: input.snapshot.generatedAt,
    validUntil: input.snapshot.validUntil,
    aggregate: Object.freeze({ ...input.aggregate }),
    campaigns: Object.freeze(campaigns),
    decision: Object.freeze({ ...input.decision, choices: Object.freeze([...input.decision.choices]) }),
    activity: Object.freeze(activity)
  });
}

export async function readPublicSnapshotResponse(response, options = {}) {
  if (!response || response.ok !== true || response.redirected === true) return unavailable("invalid");
  const contentType = response.headers?.get?.("content-type") ?? "";
  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) return unavailable("invalid");

  const declaredLength = Number(response.headers?.get?.("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > 65_536) return unavailable("invalid");

  let text;
  try {
    text = await response.text();
  } catch {
    return unavailable("invalid");
  }
  if (new TextEncoder().encode(text).byteLength > 65_536) return unavailable("invalid");

  try {
    return parsePublicSnapshot(JSON.parse(text), options);
  } catch {
    return unavailable("invalid");
  }
}

export function toDisplayModel(snapshot) {
  if (!snapshot || snapshot.kind !== "available") return unavailable(snapshot?.reason === "stale" ? "stale" : "invalid");

  const campaigns = snapshot.campaigns.map((campaign) => Object.freeze({
    alias: campaign.alias,
    stage: STAGE_LABELS[campaign.stage],
    stageCode: campaign.stage,
    progress: campaign.progress,
    attention: campaign.attention,
    freshness: campaign.freshness,
    codex: campaign.codex,
    currentAction: ACTION_LABELS[campaign.currentAction],
    waiting: campaign.codex === "waiting"
  }));

  const activity = snapshot.activity.map((entry) => Object.freeze({
    at: entry.at,
    campaign: entry.campaign,
    category: CATEGORY_LABELS[entry.category],
    result: RESULT_LABELS[entry.result],
    completed: entry.completed,
    total: entry.total,
    progress: entry.progress
  }));

  const decision = snapshot.decision.state === "clear" ? Object.freeze({ state: "clear" }) : Object.freeze({
    state: snapshot.decision.state,
    campaign: snapshot.decision.campaign,
    promptCode: snapshot.decision.prompt,
    prompt: PROMPT_LABELS[snapshot.decision.prompt],
    choices: Object.freeze(snapshot.decision.choices.map((value) => Object.freeze({
      value,
      label: CHOICE_LABELS[value],
      recommended: value === snapshot.decision.recommended
    }))),
    id: snapshot.decision.id,
    revision: snapshot.decision.revision,
    expiresAt: snapshot.decision.expiresAt
  });

  return Object.freeze({
    kind: "available",
    mode: snapshot.mode,
    siteVersion: snapshot.siteVersion,
    gateVersion: snapshot.gateVersion,
    generatedAt: snapshot.generatedAt,
    validUntil: snapshot.validUntil,
    aggregate: snapshot.aggregate,
    waitingCount: campaigns.filter((campaign) => campaign.waiting).length,
    campaigns: Object.freeze(campaigns),
    decision,
    activity: Object.freeze(activity)
  });
}

export function validateDecisionBridge(value) {
  if (!exactKeys(value, ["apiVersion", "submitDecision", "submitMessage", "submitQuestion"])) return null;
  if (value.apiVersion !== "gate.local-cockpit-bridge/v1"
    || typeof value.submitDecision !== "function"
    || typeof value.submitMessage !== "function"
    || typeof value.submitQuestion !== "function") return null;
  return value;
}

export function validateBridgeReceipt(value, requestId) {
  if (!exactKeys(value, ["apiVersion", "requestId", "status"])) return null;
  if (value.apiVersion !== "gate.local-cockpit-receipt/v1" || value.requestId !== requestId || value.status !== "accepted") return null;
  return Object.freeze({ apiVersion: value.apiVersion, requestId: value.requestId, status: value.status });
}

export function validateOperatorMessage(value) {
  if (typeof value !== "string") return Object.freeze({ valid: false });
  const message = value.normalize("NFC").replace(/\r\n?/g, "\n").trim();
  const length = [...message].length;
  const bytes = new TextEncoder().encode(message).byteLength;
  if (length < 1 || length > 1_000 || bytes > 4_096 || message.split("\n").length > 12
    || /[\u0000-\u0009\u000B\u000C\u000E-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/u.test(message)
    || /(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|private[_-]?key|session[_-]?(?:id|key|token))\s*[:=]\s*\S+/iu.test(message)
    || /\bbearer\s+[A-Za-z0-9._~+/-]{16,}={0,2}\b/iu.test(message)
    || /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u.test(message)) {
    return Object.freeze({ valid: false });
  }
  return Object.freeze({ valid: true, message, length, bytes });
}

const LOCAL_TURNS = new Set(["idle", "working", "waiting"]);
const LOCAL_ROLES = new Set(["operator", "codex"]);
const LOCAL_EVENT_CATEGORIES = new Set(["thinking", "testing", "build", "repository", "research", "file-change", "tool", "agent", "waiting"]);
const LOCAL_EVENT_STATES = new Set(["started", "progress", "completed", "failed", "blocked"]);
const LOCAL_FLEET_PRECISION = new Set(["exact", "lower-bound", "unavailable"]);
const LOCAL_FLEET_CONNECTION = new Set(["connected", "unavailable"]);
const LOCAL_FLEET_SOURCE_FRESHNESS = new Set(["current", "delayed", "unavailable"]);
const LOCAL_FLEET_KINDS = new Set(["case", "profile"]);
const LOCAL_FLEET_STAGES = new Set([
  "governance", "offline-static", "offline-dynamic", "passive-research", "active-observation",
  "active-testing", "high-impact-controlled", "closure", "multiple", "idle", "unknown",
  "profile-questionnaire", "profile-operator-review", "profile-ready", "profile-superseded"
]);
const LOCAL_FLEET_STATES = new Set(["queued", "running", "waiting", "blocked", "succeeded", "failed", "cancelled", "unknown", "idle"]);
const LOCAL_FLEET_ATTENTION = new Set(["steady", "watch", "response-needed"]);
const LOCAL_FLEET_FRESHNESS = new Set(["current", "delayed", "unknown"]);
const LOCAL_FLEET_TOKEN_AVAILABILITY = new Set(["exact", "estimated", "partial", "unavailable"]);
const TOKEN_PROVENANCE = new Set(["exact", "estimated", "unavailable"]);
const TOKEN_COST_UNITS = new Set(["USD", "credits"]);

function safeLocalText(value, maximum, maximumBytes = maximum * 4) {
  return typeof value === "string" && [...value].length >= 1 && [...value].length <= maximum
    && new TextEncoder().encode(value).byteLength <= maximumBytes
    && !/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/u.test(value);
}

function validateTokenCost(value) {
  if (!exactKeys(value, ["availability", "amountMicros", "unit"])
      || !new Set(["estimated", "unavailable"]).has(value.availability)) return null;
  if (value.availability === "unavailable") {
    return value.amountMicros === null && value.unit === null ? Object.freeze({ ...value }) : null;
  }
  return boundedInteger(value.amountMicros, 0, Number.MAX_SAFE_INTEGER) && TOKEN_COST_UNITS.has(value.unit)
    ? Object.freeze({ ...value })
    : null;
}

function validateCompanionTokens(value) {
  if (!exactKeys(value, [
    "availability", "source", "input", "cachedInput", "output", "reasoningOutput", "total", "contextWindow", "cost"
  ]) || value.availability !== "exact" || value.source !== "codex-notification") return null;
  for (const key of ["input", "cachedInput", "output", "reasoningOutput", "total"]) {
    if (!boundedInteger(value[key], 0, Number.MAX_SAFE_INTEGER)) return null;
  }
  if (!(value.contextWindow === null || boundedInteger(value.contextWindow, 1, Number.MAX_SAFE_INTEGER))) return null;
  const cost = validateTokenCost(value.cost);
  return cost ? Object.freeze({ ...value, cost }) : null;
}

function validateHostTokens(value) {
  if (!exactKeys(value, ["availability", "input", "cachedInput", "output", "total", "cost"])
      || !TOKEN_PROVENANCE.has(value.availability)) return null;
  const counters = ["input", "cachedInput", "output", "total"];
  if (value.availability === "unavailable") {
    if (counters.some((key) => value[key] !== null)) return null;
  } else {
    if (counters.some((key) => !(value[key] === null || boundedInteger(value[key], 0, Number.MAX_SAFE_INTEGER)))
        || counters.every((key) => value[key] === null)) return null;
  }
  const cost = validateTokenCost(value.cost);
  return cost ? Object.freeze({ ...value, cost }) : null;
}

export function validateLocalCompanionState(value, options = {}) {
  if (!exactKeys(value, [
    "apiVersion", "sessionRevision", "stateRevision", "observedAt", "connected", "turn", "tokens", "conversation", "pendingQuestions"
  ]) || value.apiVersion !== "gate.local-companion-state/v1"
    || !boundedInteger(value.sessionRevision, 1, 2_147_483_647)
    || !boundedInteger(value.stateRevision, 0, 2_147_483_647)
    || typeof value.connected !== "boolean" || !LOCAL_TURNS.has(value.turn)) return null;
  const observedAt = timestamp(value.observedAt);
  const now = options.now instanceof Date ? options.now.getTime() : Date.now();
  if (observedAt === null || observedAt > now + 300_000) return null;

  let tokens = null;
  if (value.tokens !== null) {
    tokens = validateCompanionTokens(value.tokens);
    if (!tokens) return null;
  }

  if (!Array.isArray(value.conversation) || value.conversation.length > 48) return null;
  const conversation = [];
  let previousConversationAt = 0;
  for (const entry of value.conversation) {
    const at = timestamp(entry?.at);
    if (!exactKeys(entry, ["role", "text", "at"]) || !LOCAL_ROLES.has(entry.role)
      || !safeLocalText(entry.text, 4_000, 16_000) || at === null || at > observedAt || at < previousConversationAt) return null;
    previousConversationAt = at;
    conversation.push(Object.freeze({ ...entry }));
  }

  if (!Array.isArray(value.pendingQuestions) || value.pendingQuestions.length > 8) return null;
  const pendingQuestions = [];
  const tokensSeen = new Set();
  for (const pending of value.pendingQuestions) {
    if (!exactKeys(pending, ["token", "questions"]) || typeof pending.token !== "string"
      || !/^q_[A-Za-z0-9_-]{43}$/u.test(pending.token) || tokensSeen.has(pending.token)
      || !Array.isArray(pending.questions) || pending.questions.length < 1 || pending.questions.length > 3) return null;
    tokensSeen.add(pending.token);
    const ids = new Set();
    const questions = [];
    for (const question of pending.questions) {
      if (!exactKeys(question, ["id", "header", "question", "options"])
        || typeof question.id !== "string" || !/^[a-z][a-z0-9_-]{0,63}$/u.test(question.id) || ids.has(question.id)
        || !safeLocalText(question.header, 24) || !safeLocalText(question.question, 500, 2_000)
        || !Array.isArray(question.options) || question.options.length < 2 || question.options.length > 3) return null;
      ids.add(question.id);
      const labels = new Set();
      const choices = [];
      for (const [index, option] of question.options.entries()) {
        if (!exactKeys(option, ["label", "description", "recommended"])
          || !safeLocalText(option.label, 100) || !safeLocalText(option.description, 300, 1_200)
          || typeof option.recommended !== "boolean" || option.recommended !== (index === 0)
          || labels.has(option.label)) return null;
        labels.add(option.label);
        choices.push(Object.freeze({ ...option }));
      }
      questions.push(Object.freeze({ ...question, options: Object.freeze(choices) }));
    }
    pendingQuestions.push(Object.freeze({ token: pending.token, questions: Object.freeze(questions) }));
  }

  return Object.freeze({
    ...value,
    tokens,
    conversation: Object.freeze(conversation),
    pendingQuestions: Object.freeze(pendingQuestions)
  });
}

export function validateLocalActivityEvent(value) {
  if (!exactKeys(value, ["apiVersion", "sequence", "at", "category", "state", "completed", "total", "tokens"])
    || value.apiVersion !== "gate.local-cockpit-event/v1" || !boundedInteger(value.sequence, 1, 2_147_483_647)
    || timestamp(value.at) === null || !LOCAL_EVENT_CATEGORIES.has(value.category) || !LOCAL_EVENT_STATES.has(value.state)) return null;
  const indeterminate = value.completed === null && value.total === null;
  const determinate = boundedInteger(value.completed, 0, 999_999) && boundedInteger(value.total, 1, 999_999)
    && value.completed <= value.total;
  if (!indeterminate && !determinate) return null;
  if (value.tokens !== null && (!exactKeys(value.tokens, ["total", "contextWindow"])
    || !boundedInteger(value.tokens.total, 0, 1_000_000_000)
    || !(value.tokens.contextWindow === null || boundedInteger(value.tokens.contextWindow, 1, 1_000_000_000)))) return null;
  return Object.freeze({ ...value, tokens: value.tokens === null ? null : Object.freeze({ ...value.tokens }) });
}

function validateFleetMetric(value) {
  if (!exactKeys(value, ["value", "precision"]) || !LOCAL_FLEET_PRECISION.has(value.precision)) return null;
  if (value.precision === "unavailable") return value.value === null ? Object.freeze({ ...value }) : null;
  return boundedInteger(value.value, 0, 1_000_000_000) ? Object.freeze({ ...value }) : null;
}

export function hasAvailableFleetMetric(value) {
  return Boolean(value && value.precision !== "unavailable" && value.value !== null);
}

function validateFleetScan(value, profile = false) {
  const keys = ["availability", "discovered", "scanned", "omitted", "invalid", "discoveredAtLeast", "omittedAtLeast", "complete", "truncated",
    ...(profile ? ["visible", "representedByCases"] : [])];
  if (!exactKeys(value, keys) || !new Set(["available", "unavailable"]).has(value.availability)
      || typeof value.discoveredAtLeast !== "boolean" || typeof value.omittedAtLeast !== "boolean"
      || typeof value.complete !== "boolean" || typeof value.truncated !== "boolean") return null;
  const numeric = ["discovered", "scanned", "omitted", "invalid", ...(profile ? ["visible", "representedByCases"] : [])];
  if (value.availability === "unavailable") {
    if (numeric.some((key) => value[key] !== null) || value.discoveredAtLeast !== false || value.omittedAtLeast !== false
        || value.complete !== false || value.truncated !== true) return null;
  } else if (numeric.some((key) => !boundedInteger(value[key], 0, 1_000_000_000))) return null;
  return Object.freeze({ ...value });
}

function validateFleetTokens(value, allowPartial = false) {
  const allowed = allowPartial ? LOCAL_FLEET_TOKEN_AVAILABILITY : new Set(["exact", "estimated", "unavailable"]);
  if (!exactKeys(value, ["availability", "total"]) || !allowed.has(value.availability)) return null;
  if (value.availability === "unavailable") return value.total === null ? Object.freeze({ ...value }) : null;
  return boundedInteger(value.total, 0, Number.MAX_SAFE_INTEGER) ? Object.freeze({ ...value }) : null;
}

export function validateLocalFleet(value, options = {}) {
  if (!exactKeys(value, [
    "apiVersion", "revision", "observedAt", "receivedAt", "connection", "sourceFreshness", "coverage", "summary", "campaigns"
  ]) || value.apiVersion !== "gate.local-fleet/v1" || !boundedInteger(value.revision, 1, 2_147_483_647)
      || !LOCAL_FLEET_CONNECTION.has(value.connection) || !LOCAL_FLEET_SOURCE_FRESHNESS.has(value.sourceFreshness)) return null;
  const receivedAt = timestamp(value.receivedAt);
  const now = options.now instanceof Date ? options.now.getTime() : Date.now();
  if (receivedAt === null || receivedAt > now + 300_000) return null;
  const observedAt = value.observedAt === null ? null : timestamp(value.observedAt);
  if (value.connection === "unavailable") {
    if (observedAt !== null || value.sourceFreshness !== "unavailable") return null;
  } else if (observedAt === null || observedAt > receivedAt + 300_000 || value.sourceFreshness === "unavailable") return null;

  if (!exactKeys(value.coverage, ["state", "cases", "profiles"]) || !LOCAL_FLEET_PRECISION.has(value.coverage.state)) return null;
  const casesScan = validateFleetScan(value.coverage.cases);
  const profilesScan = validateFleetScan(value.coverage.profiles, true);
  if (!casesScan || !profilesScan) return null;

  const summaryKeys = [
    "campaigns", "active", "waiting", "attention", "profileAnswers", "runningExecutions", "activeWorkflows",
    "runningAnalyses", "setupBlockers", "campaignTokens", "hostTokens"
  ];
  if (!exactKeys(value.summary, summaryKeys)) return null;
  const summary = {};
  for (const key of ["campaigns", "active", "waiting", "attention", "runningExecutions", "activeWorkflows", "runningAnalyses", "setupBlockers"]) {
    summary[key] = validateFleetMetric(value.summary[key]);
    if (!summary[key]) return null;
  }
  if (!exactKeys(value.summary.profileAnswers, ["answered", "total", "precision"])
      || !LOCAL_FLEET_PRECISION.has(value.summary.profileAnswers.precision)) return null;
  if (value.summary.profileAnswers.precision === "unavailable") {
    if (value.summary.profileAnswers.answered !== null || value.summary.profileAnswers.total !== null) return null;
  } else if (!boundedInteger(value.summary.profileAnswers.answered, 0, 1_000_000_000)
      || !boundedInteger(value.summary.profileAnswers.total, 0, 1_000_000_000)
      || value.summary.profileAnswers.answered > value.summary.profileAnswers.total) return null;
  summary.profileAnswers = Object.freeze({ ...value.summary.profileAnswers });
  summary.campaignTokens = validateFleetTokens(value.summary.campaignTokens, true);
  summary.hostTokens = validateHostTokens(value.summary.hostTokens);
  if (!summary.campaignTokens || !summary.hostTokens) return null;

  if (!Array.isArray(value.campaigns) || value.campaigns.length > 64) return null;
  const aliases = new Set();
  const campaigns = [];
  for (const item of value.campaigns) {
    if (!exactKeys(item, ["alias", "kind", "stage", "state", "progress", "attention", "freshness", "work", "tokens"])
        || typeof item.alias !== "string" || !/^Campaign [1-9]\d{0,2}$/u.test(item.alias) || aliases.has(item.alias)
        || !LOCAL_FLEET_KINDS.has(item.kind) || !LOCAL_FLEET_STAGES.has(item.stage) || !LOCAL_FLEET_STATES.has(item.state)
        || !LOCAL_FLEET_ATTENTION.has(item.attention) || !LOCAL_FLEET_FRESHNESS.has(item.freshness)) return null;
    aliases.add(item.alias);
    let progress = null;
    if (item.kind === "case") {
      if (item.progress !== null || item.stage.startsWith("profile-")) return null;
    } else {
      if (!item.stage.startsWith("profile-") || !exactKeys(item.progress, ["completed", "total", "percent"])
          || !boundedInteger(item.progress.completed, 0, 1_000_000_000)
          || !boundedInteger(item.progress.total, 0, 1_000_000_000) || item.progress.completed > item.progress.total
          || !(item.progress.percent === null || boundedInteger(item.progress.percent, 0, 100))) return null;
      progress = Object.freeze({ ...item.progress });
    }
    if (!exactKeys(item.work, ["runningExecutions", "activeWorkflows", "runningAnalyses", "setupBlockers"])) return null;
    const work = {};
    for (const key of ["runningExecutions", "activeWorkflows", "runningAnalyses", "setupBlockers"]) {
      work[key] = validateFleetMetric(item.work[key]);
      if (!work[key]) return null;
    }
    const tokens = validateFleetTokens(item.tokens);
    if (!tokens) return null;
    campaigns.push(Object.freeze({ ...item, progress, work: Object.freeze(work), tokens }));
  }
  if (value.connection === "unavailable" && (value.coverage.state !== "unavailable" || campaigns.length !== 0
      || Object.values(summary).some((item) => item?.precision && item.precision !== "unavailable"))) return null;
  return Object.freeze({
    ...value,
    coverage: Object.freeze({ state: value.coverage.state, cases: casesScan, profiles: profilesScan }),
    summary: Object.freeze(summary),
    campaigns: Object.freeze(campaigns)
  });
}

export const publicCockpitModel = Object.freeze({
  schema: SCHEMA,
  modes: Object.freeze([...MODES]),
  stages: Object.freeze([...STAGES]),
  attention: Object.freeze([...ATTENTION]),
  freshness: Object.freeze([...FRESHNESS]),
  codexStates: Object.freeze([...CODEX_STATES]),
  actions: Object.freeze([...ACTIONS]),
  activityCategories: Object.freeze([...ACTIVITY_CATEGORIES]),
  activityResults: Object.freeze([...ACTIVITY_RESULTS]),
  prompts: Object.freeze([...PROMPTS]),
  choices: Object.freeze([...CHOICES])
});
