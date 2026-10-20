const SCHEMA = "gate.public-cockpit/v1";

const ROOT_KEYS = ["schema", "mode", "site", "gate", "snapshot", "aggregate", "campaigns", "decision", "activity"];
const SITE_KEYS = ["version"];
const GATE_KEYS = ["version"];
const SNAPSHOT_KEYS = ["generatedAt", "validUntil"];
const AGGREGATE_KEYS = ["overallProgress", "testsPassed", "testsTotal", "tokenStatus", "tokensUsed", "tokenBudget", "learningCount", "blockerCount"];
const CAMPAIGN_KEYS = ["alias", "stage", "progress", "attention", "freshness", "codex", "currentAction", "mirror"];
const DECISION_KEYS = ["id", "revision", "expiresAt", "state", "campaign", "prompt", "choices", "recommended"];
const ACTIVITY_KEYS = ["at", "campaign", "category", "completed", "total", "result", "progress"];

const STAGES = new Set(["intake", "mapping", "testing", "validating", "reporting", "paused", "complete"]);
const ATTENTION = new Set(["steady", "watch", "response-needed"]);
const FRESHNESS = new Set(["preview"]);
const CODEX_STATES = new Set(["working", "waiting", "idle"]);
const TOKEN_STATES = new Set(["available", "unavailable"]);
const ACTIONS = new Set(["profiling", "mapping-surface", "running-tests", "reviewing-evidence", "awaiting-reply", "preparing-report", "idle"]);
const DECISION_STATES = new Set(["clear", "waiting"]);
const PROMPTS = new Set(["choose-depth", "confirm-priority", "select-next-step"]);
const CHOICES = new Set(["recommended-depth", "balanced-depth", "focused-depth", "continue", "review-first", "pause"]);
const ACTIVITY_CATEGORIES = new Set(["profile", "map", "test", "validate", "report", "learn"]);
const ACTIVITY_RESULTS = new Set(["progress", "passed", "attention", "recorded"]);
const MIRROR_AVAILABILITY = new Set(["available", "unavailable"]);
const MIRROR_REASONS = new Set(["disabled", "not-applicable", "no-attempts", "source-unavailable"]);
const MIRROR_ATTEMPT_STATES = new Set(["queued", "running", "stopping", "succeeded", "failed", "cancelled", "blocked", "unknown"]);
const MIRROR_ENTRY_STATES = new Set(["queued", "running", "waiting", "blocked", "succeeded", "failed", "cancelled", "unknown"]);
const MIRROR_CHANNELS = new Set(["work-order", "command", "stdout", "stderr", "browser", "tool", "file", "test", "agent", "system", "result"]);
const MIRROR_FIDELITY = new Set(["exact", "redacted", "summarized", "unavailable"]);
const MIRROR_TOKEN_AVAILABILITY = new Set(["exact", "estimated", "partial", "unavailable"]);
const MIRROR_METRIC_AVAILABILITY = new Set(["exact", "estimated", "unavailable"]);
const MIRROR_POSIX_ABSOLUTE_PATH = /(?:^|[^A-Za-z0-9_./\\-])\/(?!\/)[^\s"'`<>\])},;]*/u;
const MIRROR_WINDOWS_DRIVE_PATH = /(?:^|[^A-Za-z0-9_./\\-])[A-Za-z]:[\\/][^\s"'`<>\])},;]*/u;
const MIRROR_WINDOWS_UNC_PATH = /(?:^|[^A-Za-z0-9_./\\-])\\\\[^\s\\"'<>]+\\[^\s"'`<>\])},;]*/u;
const MIRROR_PROTOCOL_RELATIVE_PATH = /(?:^|[^A-Za-z0-9_+.:/\\-])\/\/[^\s"'`<>\])},;]*/u;
const MIRROR_FILE_URI_PATH = /\bfile:\/\/[^\s"'`<>\])},;]*/iu;
const MIRROR_LOW_ENTROPY_CREDENTIAL = /(?:["'](?:api[_-]?key|access[_-]?token|auth(?:entication|orization)?|bearer|client[_-]?secret|credential|key|password|passwd|secret|session[_-]?(?:id|key|token)|token)["']\s*:\s*(?!["']?\[secret withheld\]["']?(?:$|[\s,}\]]))(?:(?:"[^"]*"|'[^']*'|[^,\s}\]]+))|\b(?:auth(?:entication|orization)?|bearer|credential|key|secret|token)\b\s*[:=]\s*(?!["']?\[secret withheld\]["']?(?:$|[\s,}\]]))(?:(?:"[^"]*"|'[^']*'|\S+))|(?:^|\s)--?(?:api[_-]?key|access[_-]?token|auth(?:entication|orization)?|bearer|client[_-]?secret|credential|key|password|passwd|secret|session[_-]?(?:id|key|token)|token)(?:\s+|=)(?!["']?\[secret withheld\]["']?(?:$|[\s,}\]]))(?:(?:"[^"]*"|'[^']*'|\S+))|\bcurl\b[^\n]*?\s(?:-u|--user)(?:\s+|=)(?!["']?\[secret withheld\]["']?(?:$|[\s,}\]]))(?:(?:"[^"]*"|'[^']*'|\S+)))/iu;

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

function nullableMirrorText(value, maximum) {
  return value === null || safeLocalText(value, maximum) && value === value.normalize("NFC").trim()
    && !containsUnsafeMirrorText(value, false);
}

function containsUnsafeMirrorText(value, remote) {
  return MIRROR_POSIX_ABSOLUTE_PATH.test(value) || MIRROR_WINDOWS_DRIVE_PATH.test(value)
    || MIRROR_WINDOWS_UNC_PATH.test(value) || MIRROR_PROTOCOL_RELATIVE_PATH.test(value)
    || MIRROR_FILE_URI_PATH.test(value) || MIRROR_LOW_ENTROPY_CREDENTIAL.test(value)
    || (remote ? containsLikelyRemoteCredential(value) : containsLikelyLocalCredential(value));
}

function validateMirrorMetric(value) {
  if (!exactKeys(value, ["availability", "value"]) || !MIRROR_METRIC_AVAILABILITY.has(value.availability)) return null;
  if (value.availability === "unavailable") return value.value === null ? Object.freeze({ ...value }) : null;
  return boundedInteger(value.value, 0, Number.MAX_SAFE_INTEGER) ? Object.freeze({ ...value }) : null;
}

function validateMirrorTokens(value) {
  if (!exactKeys(value, ["availability", "total"]) || !MIRROR_TOKEN_AVAILABILITY.has(value.availability)) return null;
  if (value.availability === "unavailable") return value.total === null ? Object.freeze({ ...value }) : null;
  return boundedInteger(value.total, 0, Number.MAX_SAFE_INTEGER) ? Object.freeze({ ...value }) : null;
}

function validateMirrorCost(value) {
  if (!exactKeys(value, ["availability", "amountMicros", "unit"])
      || !new Set(["estimated", "unavailable"]).has(value.availability)) return null;
  if (value.availability === "unavailable") {
    return value.amountMicros === null && value.unit === null ? Object.freeze({ ...value }) : null;
  }
  return boundedInteger(value.amountMicros, 0, Number.MAX_SAFE_INTEGER) && new Set(["USD", "credits"]).has(value.unit)
    ? Object.freeze({ ...value }) : null;
}

function validMirrorAttemptAlias(value) {
  const match = typeof value === "string" ? /^Attempt ([1-9][0-9]{0,15})$/u.exec(value) : null;
  return Boolean(match && Number.isSafeInteger(Number(match[1])));
}

/** Validate the bounded, operator-visible execution stream shared by preview and live fleet projections. */
export function validateExecutionMirror(value, options = {}) {
  if (!exactKeys(value, ["availability", "reason", "attempts"]) || !MIRROR_AVAILABILITY.has(value.availability)
      || !Array.isArray(value.attempts) || value.attempts.length > 8) return null;
  if (value.availability === "unavailable") {
    return MIRROR_REASONS.has(value.reason) && value.attempts.length === 0
      ? Object.freeze({ availability: "unavailable", reason: value.reason, attempts: Object.freeze([]) }) : null;
  }
  if (value.reason !== null || value.attempts.length === 0) return null;
  const remote = options.remote === true;
  const upperBound = options.upperBound === undefined ? null : timestamp(options.upperBound);
  if (options.upperBound !== undefined && upperBound === null) return null;
  const aliases = new Set();
  const attempts = [];
  for (const attempt of value.attempts) {
    if (!exactKeys(attempt, [
      "alias", "kind", "state", "phase", "tool", "action", "startedAt", "finishedAt", "updatedAt", "elapsedMs", "progress", "usage", "entries"
    ]) || !validMirrorAttemptAlias(attempt.alias) || aliases.has(attempt.alias)
      || attempt.kind !== "supervised-execution" || !MIRROR_ATTEMPT_STATES.has(attempt.state)
      || !nullableMirrorText(attempt.phase, 80) || !nullableMirrorText(attempt.tool, 64) || !nullableMirrorText(attempt.action, 64)) return null;
    const startedAt = attempt.startedAt === null ? null : timestamp(attempt.startedAt);
    const finishedAt = attempt.finishedAt === null ? null : timestamp(attempt.finishedAt);
    const updatedAt = timestamp(attempt.updatedAt);
    if (updatedAt === null || upperBound !== null && updatedAt > upperBound
      || attempt.startedAt !== null && startedAt === null || attempt.finishedAt !== null && finishedAt === null
      || startedAt !== null && startedAt > updatedAt || finishedAt !== null && (finishedAt > updatedAt || startedAt !== null && finishedAt < startedAt)
      || !(attempt.elapsedMs === null || boundedInteger(attempt.elapsedMs, 0, Number.MAX_SAFE_INTEGER))) return null;
    if (!exactKeys(attempt.progress, ["availability", "completed", "total", "percent"])
        || !new Set(["exact", "unavailable"]).has(attempt.progress.availability)) return null;
    let progress;
    if (attempt.progress.availability === "unavailable") {
      if (attempt.progress.completed !== null || attempt.progress.total !== null || attempt.progress.percent !== null) return null;
      progress = Object.freeze({ ...attempt.progress });
    } else {
      if (!boundedInteger(attempt.progress.completed, 0, Number.MAX_SAFE_INTEGER)
          || !boundedInteger(attempt.progress.total, 1, Number.MAX_SAFE_INTEGER)
          || attempt.progress.completed > attempt.progress.total
          || !boundedInteger(attempt.progress.percent, 0, 100)
          || attempt.progress.percent !== Math.round(attempt.progress.completed / attempt.progress.total * 100)) return null;
      progress = Object.freeze({ ...attempt.progress });
    }
    if (!exactKeys(attempt.usage, ["tokens", "cost", "requests", "retries", "toolRuns"])) return null;
    const tokens = validateMirrorTokens(attempt.usage.tokens);
    const cost = validateMirrorCost(attempt.usage.cost);
    const requests = validateMirrorMetric(attempt.usage.requests);
    const retries = validateMirrorMetric(attempt.usage.retries);
    const toolRuns = validateMirrorMetric(attempt.usage.toolRuns);
    if (!tokens || !cost || !requests || !retries || !toolRuns
        || toolRuns.availability !== "exact" || toolRuns.value !== 1
        || !Array.isArray(attempt.entries) || attempt.entries.length > 8) return null;
    const entries = [];
    let priorSequence = 0;
    let priorAt = Number.NEGATIVE_INFINITY;
    for (const entry of attempt.entries) {
      const at = timestamp(entry?.at);
      if (!exactKeys(entry, ["sequence", "at", "channel", "state", "fidelity", "truncated", "text"])
          || !boundedInteger(entry.sequence, 1, Number.MAX_SAFE_INTEGER) || entry.sequence <= priorSequence
          || at === null || at < priorAt || at > updatedAt
          || !MIRROR_CHANNELS.has(entry.channel) || !MIRROR_ENTRY_STATES.has(entry.state)
          || !MIRROR_FIDELITY.has(entry.fidelity) || typeof entry.truncated !== "boolean"
          || !safeLocalText(entry.text, 240) || entry.text !== entry.text.normalize("NFC") || /[\r\n\t]/u.test(entry.text)
          || containsUnsafeMirrorText(entry.text, remote)) return null;
      entries.push(Object.freeze({ ...entry }));
      priorSequence = entry.sequence;
      priorAt = at;
    }
    attempts.push(Object.freeze({
      ...attempt,
      progress,
      usage: Object.freeze({ tokens, cost, requests, retries, toolRuns }),
      entries: Object.freeze(entries)
    }));
    aliases.add(attempt.alias);
  }
  return Object.freeze({ availability: "available", reason: null, attempts: Object.freeze(attempts) });
}

export function parsePublicSnapshot(input, options = {}) {
  const now = options.now instanceof Date ? options.now.getTime() : Date.now();

  if (!exactKeys(input, ROOT_KEYS)) return unavailable("invalid");
  if (input.schema !== SCHEMA) return unavailable("invalid");
  if (input.mode !== "preview") return unavailable("invalid");
  if (!exactKeys(input.site, SITE_KEYS) || !safeVersion(input.site.version)) return unavailable("invalid");
  if (!exactKeys(input.gate, GATE_KEYS) || !safeVersion(input.gate.version)) return unavailable("invalid");
  if (!exactKeys(input.snapshot, SNAPSHOT_KEYS)) return unavailable("invalid");

  const generatedAt = timestamp(input.snapshot.generatedAt);
  if (generatedAt === null || generatedAt > now + 300_000 || input.snapshot.validUntil !== null) return unavailable("invalid");
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
    const mirror = validateExecutionMirror(item.mirror, { upperBound: input.snapshot.generatedAt });
    if (!mirror) return unavailable("invalid");
    aliases.add(item.alias);
    campaigns.push(Object.freeze({ ...item, mirror }));
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
    if (!/^dec_[a-f0-9]{16}$/.test(input.decision.id) || !boundedInteger(input.decision.revision, 1, 999_999)
      || !aliases.has(input.decision.campaign) || !PROMPTS.has(input.decision.prompt)
      || !Array.isArray(input.decision.choices) || input.decision.choices.length < 2 || input.decision.choices.length > 3
      || new Set(input.decision.choices).size !== input.decision.choices.length
      || input.decision.choices.some((choice) => !CHOICES.has(choice))
      || !input.decision.choices.includes(input.decision.recommended)) return unavailable("invalid");
    if (input.decision.expiresAt !== null) {
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
  if (!snapshot || snapshot.kind !== "available") return unavailable("invalid");

  const campaigns = snapshot.campaigns.map((campaign) => Object.freeze({
    alias: campaign.alias,
    stage: STAGE_LABELS[campaign.stage],
    stageCode: campaign.stage,
    progress: campaign.progress,
    attention: campaign.attention,
    freshness: campaign.freshness,
    codex: campaign.codex,
    currentAction: ACTION_LABELS[campaign.currentAction],
    waiting: campaign.codex === "waiting",
    mirror: campaign.mirror
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

export function validateLocalBridge(value) {
  if (!exactKeys(value, ["apiVersion", "submitMessage", "submitQuestion"])) return null;
  if (value.apiVersion !== "gate.local-cockpit-bridge/v1"
    || typeof value.submitMessage !== "function"
    || typeof value.submitQuestion !== "function") return null;
  return value;
}

export function validateBridgeReceipt(value, requestId) {
  if (!exactKeys(value, ["apiVersion", "requestId", "status"])) return null;
  if (value.apiVersion !== "gate.local-cockpit-receipt/v1" || value.requestId !== requestId || value.status !== "accepted") return null;
  return Object.freeze({ apiVersion: value.apiVersion, requestId: value.requestId, status: value.status });
}

const REMOTE_REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/u;
const REMOTE_COMMAND_ID = /^cmd_[A-Za-z0-9_-]{16,128}$/u;
const REMOTE_CSRF = /^[A-Za-z0-9_-]{43}$/u;
const REMOTE_CASE_ID = /^[a-z][a-z0-9-]{1,62}$/u;
const REMOTE_RUNNER_STATES = new Set(["connected", "stale", "offline"]);
const REMOTE_CODEX_STATES = new Set(["idle", "working", "waiting", "offline"]);
const REMOTE_CONNECTION_STATES = new Set(["connecting", "connected", "offline", "revoked"]);
const REMOTE_COMMAND_STATES = new Set(["queued", "leased", "accepted", "running", "completed", "failed", "expired", "cancelled"]);
const LOCAL_SECRET_PATTERNS = Object.freeze([
  /(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|private[_-]?key|session[_-]?(?:id|key|token))\s*[:=]\s*\S+/iu,
  /\bbearer\s+[A-Za-z0-9._~+/-]{16,}={0,2}\b/iu,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u
]);
const REMOTE_SECRET_PATTERNS = Object.freeze([
  /["']?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|private[_-]?key|session[_-]?(?:id|key|token)|aws[_-]?(?:access[_-]?key[_-]?id|secret[_-]?access[_-]?key)|authorization|cookie|secret)["']?\s*[:=]\s*(?:"[^"\r\n]+"|'[^'\r\n]+'|\S+)/iu,
  /\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{12,}={0,2}\b/iu,
  /-----BEGIN (?:(?:[A-Z0-9][A-Z0-9 -]* )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----/u,
  /\b[a-z][a-z0-9+.-]{1,31}:\/\/[^\s/:@]{1,128}:[^\s/@]{1,256}@/iu,
  /(?:^|\n)\s*(?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\r\n]+/iu,
  /(?:\b(?:github_pat_[A-Za-z0-9_]{20,255}|gh[pousr]_[A-Za-z0-9]{20,255}|glpat-[A-Za-z0-9_-]{20,255}|sk-(?:proj-|ant-api\d{2}-)?[A-Za-z0-9_-]{16,255}|(?:sk|rk)_live_[A-Za-z0-9]{16,255}|xox[baprs]-[A-Za-z0-9-]{10,255}|npm_[A-Za-z0-9]{30,255}|pypi-[A-Za-z0-9_-]{30,255}|hf_[A-Za-z0-9]{20,255}|ya29\.[A-Za-z0-9_-]{20,255}|AIza[A-Za-z0-9_-]{35}|(?:AKIA|ASIA)[A-Z0-9]{16})\b|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b)/u
]);

function containsLikelyRemoteCredential(value) {
  return typeof value === "string" && REMOTE_SECRET_PATTERNS.some((pattern) => pattern.test(value));
}

function containsLikelyLocalCredential(value) {
  return typeof value === "string" && LOCAL_SECRET_PATTERNS.some((pattern) => pattern.test(value));
}

export function validateRemoteBridge(value) {
  if (!exactKeys(value, [
    "apiVersion", "caseId", "sessionRevision", "reconcileCommands", "submitMessage", "submitQuestion"
  ])) return null;
  if (value.apiVersion !== "gate.remote-cockpit-bridge/v1"
      || typeof value.caseId !== "string" || !REMOTE_CASE_ID.test(value.caseId)
      || !boundedInteger(value.sessionRevision, 1, 2_147_483_647)
      || typeof value.reconcileCommands !== "function"
      || typeof value.submitMessage !== "function"
      || typeof value.submitQuestion !== "function") return null;
  return value;
}

export function validateRemoteSession(value, options = {}) {
  if (!exactKeys(value, ["apiVersion", "sessionRevision", "csrf", "expiresAt", "caseId"])
      || value.apiVersion !== "gate.remote-cockpit-session/v1"
      || !boundedInteger(value.sessionRevision, 1, 2_147_483_647)
      || typeof value.csrf !== "string" || !REMOTE_CSRF.test(value.csrf)
      || typeof value.caseId !== "string" || !REMOTE_CASE_ID.test(value.caseId)) return null;
  const expiresAt = timestamp(value.expiresAt);
  const now = options.now instanceof Date ? options.now.getTime() : Date.now();
  if (expiresAt === null || expiresAt <= now) return null;
  return Object.freeze({ ...value });
}

export function validateRemoteQueuedReceipt(value, requestId, sessionRevision, options = {}) {
  if (!exactKeys(value, ["apiVersion", "requestId", "sessionRevision", "commandId", "sequence", "status", "acceptedAt"])
      || value.apiVersion !== "gate.remote-cockpit-receipt/v1"
      || value.requestId !== requestId || !REMOTE_REQUEST_ID.test(value.requestId)
      || value.sessionRevision !== sessionRevision
      || !REMOTE_COMMAND_ID.test(value.commandId)
      || !boundedInteger(value.sequence, 1, Number.MAX_SAFE_INTEGER)
      || value.status !== "queued") return null;
  const acceptedAt = timestamp(value.acceptedAt);
  const now = options.now instanceof Date ? options.now.getTime() : Date.now();
  if (acceptedAt === null || acceptedAt > now + 300_000) return null;
  return Object.freeze({ ...value });
}

export function validateRemoteCommandStatusRequest(value, options = {}) {
  if (!exactKeys(value, ["apiVersion", "caseId", "sessionRevision", "commands"])
      || value.apiVersion !== "gate.remote-command-status-request/v1"
      || typeof value.caseId !== "string" || !REMOTE_CASE_ID.test(value.caseId)
      || !boundedInteger(value.sessionRevision, 1, 2_147_483_647)
      || options.caseId !== undefined && value.caseId !== options.caseId
      || options.sessionRevision !== undefined && value.sessionRevision !== options.sessionRevision
      || !Array.isArray(value.commands) || value.commands.length < 1 || value.commands.length > 16) return null;
  const requestIds = new Set();
  const commandIds = new Set();
  const commands = [];
  for (const reference of value.commands) {
    if (!exactKeys(reference, ["requestId", "commandId"])
        || !REMOTE_REQUEST_ID.test(reference.requestId) || !REMOTE_COMMAND_ID.test(reference.commandId)
        || requestIds.has(reference.requestId) || commandIds.has(reference.commandId)) return null;
    requestIds.add(reference.requestId);
    commandIds.add(reference.commandId);
    commands.push(Object.freeze({ ...reference }));
  }
  return Object.freeze({ ...value, commands: Object.freeze(commands) });
}

export function validateRemoteCommandStatusResponse(value, request) {
  const expected = validateRemoteCommandStatusRequest(request);
  if (!expected || !exactKeys(value, ["apiVersion", "caseId", "sessionRevision", "commands"])
      || value.apiVersion !== "gate.remote-command-status-response/v1"
      || value.caseId !== expected.caseId || value.sessionRevision !== expected.sessionRevision
      || !Array.isArray(value.commands) || value.commands.length > expected.commands.length) return null;
  const expectedPairs = new Set(expected.commands.map((reference) => `${reference.requestId}\0${reference.commandId}`));
  const seen = new Set();
  const commands = [];
  for (const status of value.commands) {
    const key = `${status?.requestId}\0${status?.commandId}`;
    if (!exactKeys(status, ["requestId", "commandId", "state"])
        || !expectedPairs.has(key) || seen.has(key) || !REMOTE_COMMAND_STATES.has(status.state)) return null;
    seen.add(key);
    commands.push(Object.freeze({ ...status }));
  }
  return Object.freeze({ ...value, commands: Object.freeze(commands) });
}

export async function readRemoteJsonResponse(response, maximumBytes) {
  if (!response || response.ok !== true || response.redirected === true
      || !boundedInteger(maximumBytes, 1, 2 * 1024 * 1024)) return null;
  const contentType = response.headers?.get?.("content-type") ?? "";
  if (!/^application\/json(?:\s*;|$)/iu.test(contentType)) return null;
  const contentLength = response.headers?.get?.("content-length");
  if (contentLength !== null) {
    if (!/^\d+$/u.test(contentLength)) return null;
    const declared = Number(contentLength);
    if (!Number.isSafeInteger(declared) || declared > maximumBytes) return null;
  }
  let text;
  try {
    text = await response.text();
  } catch {
    return null;
  }
  if (new TextEncoder().encode(text).byteLength > maximumBytes) return null;
  try {
    const value = JSON.parse(text);
    return record(value) ? value : null;
  } catch {
    return null;
  }
}

export function parseRemoteSseFrame(frame, maximumBytes = 136 * 1024) {
  if (typeof frame !== "string" || !boundedInteger(maximumBytes, 1, 160 * 1024)
      || new TextEncoder().encode(frame).byteLength > maximumBytes) return null;
  let id = null;
  let name = "message";
  let eventSeen = false;
  let data = null;
  for (const rawLine of frame.replace(/\r\n/gu, "\n").split("\n")) {
    if (rawLine === "" || rawLine.startsWith(":") || rawLine.startsWith("retry:")) continue;
    if (rawLine.startsWith("id: ")) {
      const candidate = rawLine.slice(4);
      if (id !== null || !/^(?:0|[1-9]\d{0,15})$/u.test(candidate)) return null;
      id = Number(candidate);
      if (!Number.isSafeInteger(id)) return null;
      continue;
    }
    if (rawLine.startsWith("event: ")) {
      if (eventSeen) return null;
      eventSeen = true;
      name = rawLine.slice(7);
      continue;
    }
    if (rawLine.startsWith("data: ")) {
      if (data !== null) return null;
      data = rawLine.slice(6);
      continue;
    }
    return null;
  }
  if (data === null || !new Set(["ready", "resync", "activity", "command", "state", "fleet", "revoked"]).has(name)) return null;
  if (name === "ready" ? id !== null : id === null) return null;
  let value;
  try { value = JSON.parse(data); } catch { return null; }
  if (!record(value)) return null;
  return Object.freeze({ id, name, value });
}

export function validateOperatorMessage(value) {
  if (typeof value !== "string") return Object.freeze({ valid: false });
  const message = value.normalize("NFC").replace(/\r\n?/g, "\n").trim();
  const length = [...message].length;
  const bytes = new TextEncoder().encode(message).byteLength;
  if (length < 1 || length > 1_000 || bytes > 4_096 || message.split("\n").length > 12
    || /[\u0000-\u0009\u000B\u000C\u000E-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/u.test(message)
    || containsLikelyLocalCredential(message)) {
    return Object.freeze({ valid: false });
  }
  return Object.freeze({ valid: true, message, length, bytes });
}

export function validateRemoteOperatorMessage(value) {
  const result = validateOperatorMessage(value);
  if (!result.valid || containsLikelyRemoteCredential(result.message)) {
    return Object.freeze({ valid: false });
  }
  return result;
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
const LOCAL_FLEET_EVENT_CATEGORIES = new Set(["campaign", "workflow", "execution", "test", "evidence", "learning", "analysis", "tool", "operator", "system", "other"]);
const LOCAL_FLEET_EVENT_STATUSES = new Set(["queued", "running", "waiting", "blocked", "succeeded", "failed", "cancelled", "unknown"]);
const LOCAL_FLEET_TOKEN_AVAILABILITY = new Set(["exact", "estimated", "partial", "unavailable"]);
const PILOT_REASONS = new Set(["not-case-scoped", "missing", "invalid", "expired", "worker-unavailable"]);
const PILOT_ACTIONS = new Set(["none", "operator", "solver", "platform", "review"]);
const PILOT_DEPTH = new Set(["unavailable", "baseline", "systematic", "deep"]);
const PILOT_SOLVING_VERDICTS = new Set(["pass", "provisional", "fail", "blocked", "unknown"]);
const PILOT_SOLVING_NOW = new Set(["idle", "intake", "mapping", "enumerating", "exploiting", "validating", "submitting", "complete", "blocked"]);
const PILOT_LEARNING_VERDICTS = new Set(["pass", "provisional", "fail", "blocked", "unknown", "not-applicable"]);
const PILOT_LEARNING_NOW = new Set(["observing", "extracting", "validating", "applying", "checking", "idle", "blocked"]);
const PILOT_COCKPIT_VERDICTS = new Set(["pass", "provisional", "fail", "blocked", "unknown"]);
const PILOT_COCKPIT_NOW = new Set(["collecting", "projecting", "current", "delayed", "blocked"]);
const PILOT_INTEGRITY = new Set(["consistent", "degraded"]);
const PILOT_COMPLETION_STATES = new Set(["complete", "incomplete", "unknown"]);
const PILOT_REPRODUCTION = new Set(["confirmed", "not-confirmed", "not-applicable", "unknown"]);
const PILOT_EXTERNAL_ACCEPTANCE = new Set(["accepted", "pending", "rejected", "not-applicable", "unknown"]);
const TOKEN_PROVENANCE = new Set(["exact", "estimated", "unavailable"]);
const TOKEN_COST_UNITS = new Set(["USD", "credits"]);

function safeLocalText(value, maximum, maximumBytes = maximum * 4) {
  return typeof value === "string" && [...value].length >= 1 && [...value].length <= maximum
    && new TextEncoder().encode(value).byteLength <= maximumBytes
    && !/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/u.test(value);
}

function safeRemoteProjectionText(value, maximumLines) {
  return value === value.normalize("NFC").replace(/\r\n?/gu, "\n").trim()
    && value.split("\n").length <= maximumLines
    && !containsLikelyRemoteCredential(value);
}

function boundedProjection(value) {
  try {
    return new TextEncoder().encode(JSON.stringify(value)).byteLength <= 128 * 1024;
  } catch {
    return false;
  }
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

export function validateRemoteState(value, options = {}) {
  if (!exactKeys(value, [
    "apiVersion", "sessionRevision", "stateRevision", "observedAt", "validUntil", "runner", "codex", "tokens", "conversation", "pendingQuestions"
  ]) || value.apiVersion !== "gate.remote-cockpit-state/v1"
      || !exactKeys(value.runner, ["state", "observedAt"])
      || !REMOTE_RUNNER_STATES.has(value.runner.state)
      || !exactKeys(value.codex, ["state"])
      || !REMOTE_CODEX_STATES.has(value.codex.state)) return null;
  if (options.sessionRevision !== undefined && value.sessionRevision !== options.sessionRevision) return null;
  const observedAt = timestamp(value.observedAt);
  const validUntil = timestamp(value.validUntil);
  const runnerObservedAt = timestamp(value.runner.observedAt);
  if (observedAt === null || validUntil === null || runnerObservedAt === null
      || runnerObservedAt > observedAt || validUntil <= observedAt || validUntil > observedAt + 300_000) return null;

  const common = validateLocalCompanionState({
    apiVersion: "gate.local-companion-state/v1",
    sessionRevision: value.sessionRevision,
    stateRevision: value.stateRevision,
    observedAt: value.observedAt,
    connected: value.runner.state === "connected",
    turn: value.codex.state === "offline" ? "idle" : value.codex.state,
    tokens: value.tokens,
    conversation: value.conversation,
    pendingQuestions: value.pendingQuestions
  }, options);
  if (!common) return null;
  if (!common.conversation.every((entry) => safeRemoteProjectionText(entry.text, 24))
      || !common.pendingQuestions.every((pending) => pending.questions.every((question) =>
        safeRemoteProjectionText(question.header, 1)
          && safeRemoteProjectionText(question.question, 12)
          && question.options.every((option) => safeRemoteProjectionText(option.label, 2)
            && safeRemoteProjectionText(option.description, 6))))
      || !boundedProjection(value)) return null;
  return Object.freeze({
    ...value,
    runner: Object.freeze({ ...value.runner }),
    codex: Object.freeze({ ...value.codex }),
    tokens: common.tokens,
    conversation: common.conversation,
    pendingQuestions: common.pendingQuestions
  });
}

export const validateRemoteCompanionState = validateRemoteState;

export function remoteStateIsFresh(value, options = {}) {
  const now = options.now instanceof Date ? options.now.getTime() : Date.now();
  return Boolean(value && timestamp(value.validUntil) !== null && now < timestamp(value.validUntil));
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

export function validateRemoteActivityEvent(value) {
  if (!record(value) || value.apiVersion !== "gate.remote-cockpit-event/v1") return null;
  const local = validateLocalActivityEvent({ ...value, apiVersion: "gate.local-cockpit-event/v1" });
  return local && boundedProjection(value) ? Object.freeze({ ...local, apiVersion: value.apiVersion }) : null;
}

export function validateRemoteConnection(value, options = {}) {
  if (!exactKeys(value, ["apiVersion", "state", "at"])
      || value.apiVersion !== "gate.remote-cockpit-connection/v1"
      || !REMOTE_CONNECTION_STATES.has(value.state)) return null;
  const at = timestamp(value.at);
  const now = options.now instanceof Date ? options.now.getTime() : Date.now();
  if (at === null || at > now + 300_000) return null;
  return Object.freeze({ ...value });
}

export function validateRemoteCommandEvent(value, options = {}) {
  if (!exactKeys(value, ["apiVersion", "sequence", "at", "requestId", "commandId", "state"])
      || value.apiVersion !== "gate.remote-command-event/v1"
      || !boundedInteger(value.sequence, 1, Number.MAX_SAFE_INTEGER)
      || !REMOTE_REQUEST_ID.test(value.requestId)
      || !REMOTE_COMMAND_ID.test(value.commandId)
      || !REMOTE_COMMAND_STATES.has(value.state)) return null;
  const at = timestamp(value.at);
  const now = options.now instanceof Date ? options.now.getTime() : Date.now();
  const acceptedAt = options.acceptedAt === undefined ? null : timestamp(options.acceptedAt);
  if (at === null || at > now + 300_000
      || (options.acceptedAt !== undefined && (acceptedAt === null || at < acceptedAt))) return null;
  return Object.freeze({ ...value });
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

function unavailablePilotMetric() {
  return Object.freeze({ availability: "unavailable", value: null });
}

function unavailablePilot(reason = "missing") {
  const axis = () => ({ availability: "unavailable", verdict: null, now: null, actionNeeded: null, updatedAt: null });
  return Object.freeze({
    availability: "unavailable", reason, observedAt: null, validUntil: null,
    solving: Object.freeze({
      ...axis(), completion: Object.freeze({ state: null, reproduction: null, externalAcceptance: null }),
      objectives: Object.freeze({ availability: "unavailable", completed: null, total: null }),
      depth: Object.freeze({ level: "unavailable", branchesExplored: unavailablePilotMetric(), techniquesAttempted: unavailablePilotMetric(), deadEndsRetired: unavailablePilotMetric() }),
      efficiency: Object.freeze(Object.fromEntries(["elapsedSeconds", "activeSeconds", "tokens", "toolRuns", "requests", "retries"].map((key) => [key, unavailablePilotMetric()])))
    }),
    learning: Object.freeze({ ...axis(), stages: Object.freeze(Object.fromEntries(["observations", "candidates", "validated", "applied", "transferred", "regressed"].map((key) => [key, unavailablePilotMetric()]))) }),
    cockpit: Object.freeze({ ...axis(), signals: Object.freeze({ availability: "unavailable", available: null, total: null }), updatesPublished: unavailablePilotMetric(), updatesMissed: unavailablePilotMetric() }),
    integrity: Object.freeze({ availability: "unavailable", status: null, checks: Object.freeze({ availability: "unavailable", available: null, total: null }), issues: unavailablePilotMetric(), checkedAt: null })
  });
}

export function unavailablePilotProjection(reason = "missing") {
  return PILOT_REASONS.has(reason) ? unavailablePilot(reason) : unavailablePilot("invalid");
}

function validatePilotMetric(value) {
  if (!exactKeys(value, ["availability", "value"])) return null;
  if (value.availability === "unavailable" && value.value === null) return unavailablePilotMetric();
  return value.availability === "available" && boundedInteger(value.value, 0, Number.MAX_SAFE_INTEGER)
    ? Object.freeze({ ...value }) : null;
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
  if (value.availability === "unavailable" && value.available === null && value.total === null) return Object.freeze({ ...value });
  return value.availability === "available" && boundedInteger(value.available, 0, 1_000_000_000)
    && boundedInteger(value.total, 1, 1_000_000_000) && value.available <= value.total ? Object.freeze({ ...value }) : null;
}

function validatePilotAxis(value, verdicts, stages) {
  if (!record(value)) return null;
  if (value.availability === "unavailable") {
    return value.verdict === null && value.now === null && value.actionNeeded === null && value.updatedAt === null
      ? Object.freeze({ availability: "unavailable", verdict: null, now: null, actionNeeded: null, updatedAt: null }) : null;
  }
  return value.availability === "available" && verdicts.has(value.verdict) && stages.has(value.now)
    && PILOT_ACTIONS.has(value.actionNeeded) && timestamp(value.updatedAt) !== null
    ? Object.freeze({ availability: "available", verdict: value.verdict, now: value.now, actionNeeded: value.actionNeeded, updatedAt: value.updatedAt }) : null;
}

export function validatePilotProjection(value, options = {}) {
  if (!exactKeys(value, ["availability", "reason", "observedAt", "validUntil", "solving", "learning", "cockpit", "integrity"])) return null;
  if (value.availability === "unavailable") {
    if (!PILOT_REASONS.has(value.reason) || value.observedAt !== null || value.validUntil !== null) return null;
  } else {
    const observedAt = timestamp(value.observedAt);
    const validUntil = timestamp(value.validUntil);
    const now = options.now instanceof Date ? options.now.getTime() : null;
    if (value.availability !== "available" || value.reason !== null || observedAt === null || validUntil === null
        || validUntil <= observedAt || validUntil - observedAt > 180_000
        || now !== null && now >= validUntil) return null;
  }
  if (!exactKeys(value.solving, ["availability", "verdict", "now", "actionNeeded", "updatedAt", "completion", "objectives", "depth", "efficiency"])
      || !exactKeys(value.learning, ["availability", "verdict", "now", "actionNeeded", "updatedAt", "stages"])
      || !exactKeys(value.cockpit, ["availability", "verdict", "now", "actionNeeded", "updatedAt", "signals", "updatesPublished", "updatesMissed"])
      || !exactKeys(value.integrity, ["availability", "status", "checks", "issues", "checkedAt"])) return null;
  const solvingAxis = validatePilotAxis(value.solving, PILOT_SOLVING_VERDICTS, PILOT_SOLVING_NOW);
  const learningAxis = validatePilotAxis(value.learning, PILOT_LEARNING_VERDICTS, PILOT_LEARNING_NOW);
  const cockpitAxis = validatePilotAxis(value.cockpit, PILOT_COCKPIT_VERDICTS, PILOT_COCKPIT_NOW);
  const objectives = value.solving.objectives;
  const completion = value.solving.completion;
  if (!solvingAxis || !learningAxis || !cockpitAxis || !exactKeys(objectives, ["availability", "completed", "total"])
      || !exactKeys(completion, ["state", "reproduction", "externalAcceptance"])) return null;
  const completionProjection = solvingAxis.availability === "unavailable"
    ? completion.state === null && completion.reproduction === null && completion.externalAcceptance === null
      ? Object.freeze({ ...completion }) : null
    : PILOT_COMPLETION_STATES.has(completion.state) && PILOT_REPRODUCTION.has(completion.reproduction)
      && PILOT_EXTERNAL_ACCEPTANCE.has(completion.externalAcceptance) ? Object.freeze({ ...completion }) : null;
  const objectiveProjection = objectives.availability === "unavailable" && objectives.completed === null && objectives.total === null
    ? Object.freeze({ ...objectives })
    : objectives.availability === "available" && boundedInteger(objectives.completed, 0, 1_000_000_000)
      && boundedInteger(objectives.total, 1, 1_000_000_000) && objectives.completed <= objectives.total
      ? Object.freeze({ ...objectives }) : null;
  if (!completionProjection || !objectiveProjection || !exactKeys(value.solving.depth, ["level", "branchesExplored", "techniquesAttempted", "deadEndsRetired"])
      || !PILOT_DEPTH.has(value.solving.depth.level)
      || !exactKeys(value.solving.efficiency, ["elapsedSeconds", "activeSeconds", "tokens", "toolRuns", "requests", "retries"])
      || !exactKeys(value.learning.stages, ["observations", "candidates", "validated", "applied", "transferred", "regressed"])) return null;
  const projectMetricMap = (source, keys) => {
    const output = {};
    for (const key of keys) {
      output[key] = validatePilotMetric(source[key]);
      if (!output[key]) return null;
    }
    return Object.freeze(output);
  };
  const depth = projectMetricMap(value.solving.depth, ["branchesExplored", "techniquesAttempted", "deadEndsRetired"]);
  const efficiency = projectMetricMap(value.solving.efficiency, ["elapsedSeconds", "activeSeconds", "tokens", "toolRuns", "requests", "retries"]);
  const learningStages = projectMetricMap(value.learning.stages, ["observations", "candidates", "validated", "applied", "transferred", "regressed"]);
  const signals = validatePilotCoverage(value.cockpit.signals);
  const updatesPublished = validatePilotMetric(value.cockpit.updatesPublished);
  const updatesMissed = validatePilotMetric(value.cockpit.updatesMissed);
  const checks = validatePilotCoverage(value.integrity.checks);
  const issues = validatePilotMetric(value.integrity.issues);
  if (!depth || !efficiency || !learningStages || !pilotLearningStagesAreConsistent(learningStages) ||
      !signals || !updatesPublished || !updatesMissed || !checks || !issues) return null;
  let integrity;
  if (value.integrity.availability === "unavailable" && value.integrity.status === null && value.integrity.checkedAt === null) {
    integrity = Object.freeze({ availability: "unavailable", status: null, checks, issues, checkedAt: null });
  } else if (value.integrity.availability === "available" && PILOT_INTEGRITY.has(value.integrity.status) && timestamp(value.integrity.checkedAt) !== null) {
    integrity = Object.freeze({ ...value.integrity, checks, issues });
  } else return null;
  const observedMillis = value.observedAt === null ? null : timestamp(value.observedAt);
  const axisTimes = [solvingAxis, learningAxis, cockpitAxis]
    .filter((axis) => axis.availability === "available")
    .map((axis) => timestamp(axis.updatedAt));
  if (value.availability === "unavailable") {
    if (solvingAxis.availability !== "unavailable" || learningAxis.availability !== "unavailable"
        || cockpitAxis.availability !== "unavailable" || integrity.availability !== "unavailable") return null;
  } else if (axisTimes.some((at) => at > observedMillis)
      || integrity.availability === "available" && timestamp(integrity.checkedAt) > observedMillis) return null;
  const objectiveComplete = objectiveProjection.availability === "available"
    && objectiveProjection.completed === objectiveProjection.total;
  if (solvingAxis.verdict === "pass" && !(solvingAxis.now === "complete" && solvingAxis.actionNeeded === "none"
      && completionProjection.state === "complete" && objectiveComplete
      && new Set(["confirmed", "not-applicable"]).has(completionProjection.reproduction)
      && new Set(["accepted", "not-applicable"]).has(completionProjection.externalAcceptance))) return null;
  if (learningAxis.verdict === "pass" && !(learningStages.transferred.availability === "available"
      && learningStages.transferred.value > 0)) return null;
  if (cockpitAxis.verdict === "pass" && !(cockpitAxis.now === "current" && cockpitAxis.actionNeeded === "none"
      && signals.availability === "available" && signals.available === signals.total
      && updatesMissed.availability === "available" && updatesMissed.value === 0)) return null;
  return Object.freeze({
    availability: value.availability, reason: value.reason, observedAt: value.observedAt, validUntil: value.validUntil,
    solving: Object.freeze({ ...solvingAxis, completion: completionProjection, objectives: objectiveProjection, depth: Object.freeze({ level: value.solving.depth.level, ...depth }), efficiency }),
    learning: Object.freeze({ ...learningAxis, stages: learningStages }),
    cockpit: Object.freeze({ ...cockpitAxis, signals, updatesPublished, updatesMissed }), integrity
  });
}

function pilotMetricValue(metric) {
  return metric?.availability === "available" ? metric.value : null;
}

/** Build the primary CTF pilot view without inventing missing measurements. */
export function pilotCockpitPresentation(fleet, selectedAlias = null) {
  const unavailableSolving = () => Object.freeze({ verdict: null, now: null, actionNeeded: null, objectives: null });
  const unavailableLearning = () => Object.freeze({
    verdict: null, now: null, actionNeeded: null,
    stages: Object.freeze({ observations: null, candidates: null, validated: null, applied: null, transferred: null, regressed: null })
  });
  const unavailableCockpit = () => Object.freeze({
    verdict: null, now: null, actionNeeded: null, signals: null, updatesPublished: null, updatesMissed: null
  });
  const offline = !fleet || fleet.connection !== "connected";
  if (offline) {
    return Object.freeze({
      state: "feed-unavailable",
      title: "Pilot feed unavailable",
      recovery: "Check the laptop observer and dedicated runner.",
      alias: null,
      aliases: Object.freeze([]),
      latestEvent: null,
      heartbeat: "offline",
      observedAt: null,
      solving: unavailableSolving(),
      depth: Object.freeze({ level: null, branchesExplored: null, techniquesAttempted: null, deadEndsRetired: null }),
      efficiency: Object.freeze({ elapsedSeconds: null, activeSeconds: null, tokens: null, toolRuns: null, requests: null, retries: null }),
      learning: unavailableLearning(),
      cockpit: unavailableCockpit(),
      integrity: Object.freeze({ status: null, checks: null, issues: null }),
      timeline: Object.freeze([])
    });
  }
  const cases = Array.isArray(fleet.campaigns) ? fleet.campaigns.filter((item) => item.kind === "case") : [];
  const aliases = Object.freeze(cases.map((item) => item.alias));
  // A lone case is unambiguous. More than one case always requires an
  // explicit (or previously persisted) alias so the primary panel can never
  // drift to whichever case happens to sort first.
  const effectiveAlias = typeof selectedAlias === "string"
    ? selectedAlias
    : cases.length === 1 ? cases[0].alias : null;
  const campaign = effectiveAlias === null
    ? null
    : cases.find((item) => item.alias === effectiveAlias) || null;
  if (!campaign) {
    return Object.freeze({
      state: cases.length === 0 ? "pilot-unavailable" : "selection-required",
      title: cases.length === 0 ? "CTF pilot state unavailable" : "Select a case",
      recovery: cases.length === 0
        ? "Start a case worker so it can publish a pilot scorecard."
        : "Choose a case to view its independent scorecard.",
      alias: null,
      aliases,
      latestEvent: null,
      heartbeat: fleet.sourceFreshness,
      observedAt: fleet.receivedAt,
      solving: unavailableSolving(),
      depth: Object.freeze({ level: null, branchesExplored: null, techniquesAttempted: null, deadEndsRetired: null }),
      efficiency: Object.freeze({ elapsedSeconds: null, activeSeconds: null, tokens: null, toolRuns: null, requests: null, retries: null }),
      learning: unavailableLearning(),
      cockpit: unavailableCockpit(),
      integrity: Object.freeze({ status: null, checks: null, issues: null }),
      timeline: Object.freeze([])
    });
  }
  const pilot = campaign?.pilot;
  if (!pilot || pilot.availability !== "available") {
    return Object.freeze({
      state: "pilot-unavailable",
      title: "CTF pilot state unavailable",
      recovery: "Start the case worker so it can publish the pilot scorecard.",
      alias: campaign?.alias || null,
      aliases,
      latestEvent: campaign?.latestEvent?.availability === "available"
        ? Object.freeze({ category: campaign.latestEvent.category, status: campaign.latestEvent.status, at: campaign.latestEvent.at }) : null,
      heartbeat: fleet.sourceFreshness,
      observedAt: fleet.receivedAt,
      solving: unavailableSolving(),
      depth: Object.freeze({ level: null, branchesExplored: null, techniquesAttempted: null, deadEndsRetired: null }),
      efficiency: Object.freeze({ elapsedSeconds: null, activeSeconds: null, tokens: null, toolRuns: null, requests: null, retries: null }),
      learning: unavailableLearning(),
      cockpit: unavailableCockpit(),
      integrity: Object.freeze({ status: null, checks: null, issues: null }),
      timeline: Object.freeze([])
    });
  }
  const timelineStages = Object.freeze(["intake", "mapping", "enumerating", "exploiting", "validating", "submitting", "complete"]);
  const activeStage = pilot.solving.availability === "available" ? pilot.solving.now : null;
  return Object.freeze({
    state: "available",
    title: "CTF pilot",
    recovery: null,
    alias: campaign.alias,
    aliases,
    latestEvent: campaign.latestEvent.availability === "available"
      ? Object.freeze({ category: campaign.latestEvent.category, status: campaign.latestEvent.status, at: campaign.latestEvent.at }) : null,
    heartbeat: fleet.sourceFreshness,
    observedAt: pilot.observedAt,
    solving: Object.freeze({
      verdict: pilot.solving.verdict,
      now: pilot.solving.now,
      actionNeeded: pilot.solving.actionNeeded,
      objectives: pilot.solving.objectives.availability === "available"
        ? Object.freeze({ completed: pilot.solving.objectives.completed, total: pilot.solving.objectives.total }) : null
    }),
    depth: Object.freeze({
      level: pilot.solving.depth.level === "unavailable" ? null : pilot.solving.depth.level,
      branchesExplored: pilotMetricValue(pilot.solving.depth.branchesExplored),
      techniquesAttempted: pilotMetricValue(pilot.solving.depth.techniquesAttempted),
      deadEndsRetired: pilotMetricValue(pilot.solving.depth.deadEndsRetired)
    }),
    efficiency: Object.freeze(Object.fromEntries(Object.entries(pilot.solving.efficiency)
      .map(([key, metric]) => [key, pilotMetricValue(metric)]))),
    learning: Object.freeze({
      verdict: pilot.learning.verdict,
      now: pilot.learning.now,
      actionNeeded: pilot.learning.actionNeeded,
      stages: Object.freeze(Object.fromEntries(Object.entries(pilot.learning.stages)
        .map(([key, metric]) => [key, pilotMetricValue(metric)])))
    }),
    cockpit: Object.freeze({
      verdict: pilot.cockpit.verdict,
      now: pilot.cockpit.now,
      actionNeeded: pilot.cockpit.actionNeeded,
      signals: pilot.cockpit.signals.availability === "available"
        ? Object.freeze({ available: pilot.cockpit.signals.available, total: pilot.cockpit.signals.total }) : null,
      updatesPublished: pilotMetricValue(pilot.cockpit.updatesPublished),
      updatesMissed: pilotMetricValue(pilot.cockpit.updatesMissed)
    }),
    integrity: Object.freeze({
      status: pilot.integrity.status,
      checks: pilot.integrity.checks.availability === "available"
        ? Object.freeze({ available: pilot.integrity.checks.available, total: pilot.integrity.checks.total }) : null,
      issues: pilotMetricValue(pilot.integrity.issues)
    }),
    timeline: Object.freeze(timelineStages.map((stage) => Object.freeze({ stage, current: stage === activeStage })))
  });
}

export function validateLocalFleet(value, options = {}) {
  if (!exactKeys(value, [
    "apiVersion", "revision", "selectionEpoch", "observedAt", "receivedAt", "validUntil", "connection", "sourceFreshness", "coverage", "summary", "campaigns"
  ]) || value.apiVersion !== "gate.local-fleet/v3" || !boundedInteger(value.revision, 1, 2_147_483_647)
      || typeof value.selectionEpoch !== "string" || !/^[a-f0-9]{32}$/u.test(value.selectionEpoch)
      || !LOCAL_FLEET_CONNECTION.has(value.connection) || !LOCAL_FLEET_SOURCE_FRESHNESS.has(value.sourceFreshness)) return null;
  const receivedAt = timestamp(value.receivedAt);
  const validUntil = timestamp(value.validUntil);
  const now = options.now instanceof Date ? options.now.getTime() : Date.now();
  if (receivedAt === null || validUntil === null || receivedAt > now + 300_000
      || validUntil <= receivedAt || validUntil - receivedAt > 15_000 || validUntil <= now) return null;
  const observedAt = value.observedAt === null ? null : timestamp(value.observedAt);
  if (value.connection === "unavailable") {
    if (observedAt !== null || value.sourceFreshness !== "unavailable") return null;
  } else if (observedAt === null || observedAt > receivedAt || value.sourceFreshness === "unavailable") return null;

  if (!exactKeys(value.coverage, ["state", "cases", "profiles"]) || !LOCAL_FLEET_PRECISION.has(value.coverage.state)) return null;
  const casesScan = validateFleetScan(value.coverage.cases);
  const profilesScan = validateFleetScan(value.coverage.profiles, true);
  if (!casesScan || !profilesScan) return null;

  const summaryKeys = [
    "campaigns", "active", "waiting", "attention", "profileAnswers", "runningExecutions", "activeWorkflows",
    "runningAnalyses", "setupBlockers", "blockers", "campaignTokens", "hostTokens"
  ];
  if (!exactKeys(value.summary, summaryKeys)) return null;
  const summary = {};
  for (const key of ["campaigns", "active", "waiting", "attention", "runningExecutions", "activeWorkflows", "runningAnalyses", "setupBlockers", "blockers"]) {
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
    const campaignKeys = ["alias", "kind", "stage", "state", "progress", "attention", "freshness", "work", "tokens", "pilot", "latestEvent", "mirror"];
    if (!(exactKeys(item, campaignKeys) || exactKeys(item, campaignKeys.filter((key) => key !== "pilot")))
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
    const pilot = item.pilot === undefined
      ? unavailablePilot("missing")
      : validatePilotProjection(item.pilot, { now: new Date(now) });
    const mirror = validateExecutionMirror(item.mirror, {
      remote: options.remote === true,
      ...(observedAt === null ? {} : { upperBound: value.observedAt })
    });
    if (!tokens || !pilot || !mirror || !exactKeys(item.latestEvent, ["availability", "category", "status", "at"])) return null;
    const latestEvent = item.latestEvent.availability === "unavailable"
      && item.latestEvent.category === null && item.latestEvent.status === null && item.latestEvent.at === null
      ? Object.freeze({ ...item.latestEvent })
      : item.latestEvent.availability === "available" && LOCAL_FLEET_EVENT_CATEGORIES.has(item.latestEvent.category)
        && LOCAL_FLEET_EVENT_STATUSES.has(item.latestEvent.status) && timestamp(item.latestEvent.at) !== null
        ? Object.freeze({ ...item.latestEvent }) : null;
    if (!latestEvent || latestEvent.availability === "available" && observedAt !== null
        && timestamp(latestEvent.at) > observedAt) return null;
    campaigns.push(Object.freeze({ ...item, progress, work: Object.freeze(work), tokens, pilot, latestEvent, mirror }));
  }
  if (value.connection === "connected" && campaigns.some((item) => item.pilot.availability === "available"
      && (timestamp(item.pilot.observedAt) > observedAt || validUntil > timestamp(item.pilot.validUntil)))) return null;
  if (value.connection === "unavailable" && (value.coverage.state !== "unavailable" || campaigns.length !== 0
      || Object.values(summary).some((item) => item?.precision && item.precision !== "unavailable"))) return null;
  return Object.freeze({
    ...value,
    coverage: Object.freeze({ state: value.coverage.state, cases: casesScan, profiles: profilesScan }),
    summary: Object.freeze(summary),
    campaigns: Object.freeze(campaigns)
  });
}

export function validateRemoteFleet(value, options = {}) {
  if (!record(value) || value.apiVersion !== "gate.remote-fleet/v3") return null;
  if (!exactKeys(value, [
    "apiVersion", "sessionRevision", "revision", "selectionEpoch", "observedAt", "receivedAt", "validUntil", "connection", "sourceFreshness", "coverage", "summary", "campaigns"
  ]) || !boundedInteger(value.sessionRevision, 1, 2_147_483_647)
      || options.sessionRevision !== undefined && value.sessionRevision !== options.sessionRevision) return null;
  const { sessionRevision, ...withoutSession } = value;
  const local = validateLocalFleet({ ...withoutSession, apiVersion: "gate.local-fleet/v3" }, { ...options, remote: true });
  return local && boundedProjection(value) ? Object.freeze({ ...local, apiVersion: value.apiVersion, sessionRevision }) : null;
}

export function validateRemoteRevocation(value) {
  if (!exactKeys(value, ["apiVersion"]) || value.apiVersion !== "gate.remote-revocation/v1") return null;
  return Object.freeze({ ...value });
}

export const publicCockpitModel = Object.freeze({
  schema: SCHEMA,
  modes: Object.freeze(["preview"]),
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


export function executionMirrorIsFresh(attempt, observedAt, now = Date.now()) {
  const observed = Date.parse(observedAt);
  const updated = Date.parse(attempt?.updatedAt);
  return Number.isFinite(observed) && Number.isFinite(updated)
    && observed <= now && now - observed <= 30_000
    && updated <= observed && observed - updated <= 30_000;
}
