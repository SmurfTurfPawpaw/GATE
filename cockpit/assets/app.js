import {
  hasAvailableFleetMetric,
  pilotCockpitPresentation,
  readPublicSnapshotResponse,
  remoteStateIsFresh,
  toDisplayModel,
  validateBridgeReceipt,
  validateLocalBridge,
  validateLocalActivityEvent,
  validateLocalCompanionState,
  validateLocalFleet,
  validateOperatorMessage,
  validateRemoteActivityEvent,
  validateRemoteBridge,
  validateRemoteCommandEvent,
  validateRemoteCommandStatusResponse,
  validateRemoteCompanionState,
  validateRemoteConnection,
  validateRemoteFleet,
  validateRemoteOperatorMessage,
  validateRemoteQueuedReceipt
} from "./model.js";

const byId = (id) => document.getElementById(id);
const elements = {
  siteVersion: byId("site-version"), gateVersion: byId("gate-version"),
  runningMetricLabel: byId("running-metric-label"), runningCount: byId("running-count"),
  runningSummary: byId("running-summary"),
  tokenMetricLabel: byId("token-metric-label"), tokenUsage: byId("token-usage"),
  tokenSummary: byId("token-summary"), blockerCount: byId("blocker-count"),
  blockerSummary: byId("blocker-summary"),
  questionMetricLabel: byId("question-metric-label"), questionCount: byId("question-count"),
  questionSummary: byId("question-summary"), campaignList: byId("campaign-list"), connectionState: byId("connection-state"),
  conversation: byId("conversation"), choiceList: byId("choice-list"), activityFeed: byId("activity-feed"),
  modeBanner: byId("mode-banner"), decisionPanel: byId("decision-panel"), messageComposer: byId("message-composer"),
  messageInput: byId("message-input"), messageSend: byId("message-send"), messageCount: byId("message-count"),
  messageStatus: byId("message-status"),
  pilotPanel: byId("pilot-panel"), pilotHeartbeat: byId("pilot-heartbeat"), pilotAlert: byId("pilot-alert"),
  pilotCaseAlias: byId("pilot-case-alias"), pilotCaseSelect: byId("pilot-case-select"),
  pilotSolvingVerdict: byId("pilot-solving-verdict"), pilotSolvingDetail: byId("pilot-solving-detail"),
  pilotLearningVerdict: byId("pilot-learning-verdict"), pilotLearningVerdictDetail: byId("pilot-learning-verdict-detail"),
  pilotCockpitVerdict: byId("pilot-cockpit-verdict"), pilotCockpitVerdictDetail: byId("pilot-cockpit-verdict-detail"),
  pilotNow: byId("pilot-now"),
  pilotTimestamp: byId("pilot-timestamp"), pilotAction: byId("pilot-action"), pilotActionDetail: byId("pilot-action-detail"),
  pilotEvent: byId("pilot-event"), pilotEventDetail: byId("pilot-event-detail"),
  pilotTimeline: byId("pilot-timeline"), pilotDepth: byId("pilot-depth"), pilotDepthDetail: byId("pilot-depth-detail"),
  pilotEfficiency: byId("pilot-efficiency"), pilotEfficiencyDetail: byId("pilot-efficiency-detail"),
  pilotLearning: byId("pilot-learning"), pilotLearningDetail: byId("pilot-learning-detail"),
  pilotCockpit: byId("pilot-cockpit"), pilotCockpitDetail: byId("pilot-cockpit-detail"),
  pilotIntegrity: byId("pilot-integrity"), pilotIntegrityDetail: byId("pilot-integrity-detail")
};

let latestGeneratedAt;
let currentDisplay;
let submitting = false;
let localState;
let localFleet;
const PILOT_SELECTION_STORAGE_KEY = "gate.pilot-case-selection/v2";
const PILOT_SELECTION_VERSION = "gate.pilot-case-selection/v2";
const PILOT_ALIAS = /^Campaign [1-9]\d{0,2}$/u;
const PILOT_SELECTION_EPOCH = /^[a-f0-9]{32}$/u;

function readPilotSelection() {
  try {
    const raw = globalThis.sessionStorage?.getItem(PILOT_SELECTION_STORAGE_KEY);
    if (typeof raw !== "string" || new TextEncoder().encode(raw).byteLength > 256) return null;
    const value = JSON.parse(raw);
    return exactObjectKeys(value, ["apiVersion", "selectionEpoch", "alias"])
      && value.apiVersion === PILOT_SELECTION_VERSION
      && PILOT_SELECTION_EPOCH.test(value.selectionEpoch)
      && PILOT_ALIAS.test(value.alias)
      ? Object.freeze({ alias: value.alias, selectionEpoch: value.selectionEpoch }) : null;
  } catch {
    return null;
  }
}

function writePilotSelection(alias, selectionEpoch) {
  try {
    if (alias === null) globalThis.sessionStorage?.removeItem(PILOT_SELECTION_STORAGE_KEY);
    else if (PILOT_ALIAS.test(alias) && PILOT_SELECTION_EPOCH.test(selectionEpoch || "")) {
      globalThis.sessionStorage?.setItem(PILOT_SELECTION_STORAGE_KEY, JSON.stringify({
        apiVersion: PILOT_SELECTION_VERSION,
        selectionEpoch,
        alias
      }));
    }
  } catch {
    // Selection persistence is optional; explicit selection remains usable.
  }
}

const storedPilotSelection = readPilotSelection();
let selectedPilotAlias = storedPilotSelection?.alias || null;
let selectedPilotEpoch = storedPilotSelection?.selectionEpoch || null;
let localTransportConnected = null;
let localActivity = [];
let remoteState;
let remoteFleet;
let remoteConnection;
let remoteActivity = [];
const remoteCommands = new Map();
let pendingMessageRequest;
const pendingQuestionRequests = new Map();
let reconcilingRemoteCommands = false;
let interactionStatus = "";
const acknowledgedQuestions = new Set();
const nativeSelections = new Map();
const REMOTE_RETRY_STORAGE_KEY = "gate.remote-cockpit-retry/v1";
const REMOTE_RETRY_VERSION = "gate.remote-cockpit-retry/v1";
const REMOTE_RETRY_DIGEST = /^[0-9a-f]{64}$/u;
const REMOTE_RETRY_REQUEST_ID = /^req-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const REMOTE_RETRY_QUESTION_TOKEN = /^q_[A-Za-z0-9_-]{43}$/u;
const REMOTE_RETRY_COMMAND_ID = /^cmd_[A-Za-z0-9_-]{16,128}$/u;
const REMOTE_TERMINAL_COMMAND_STATES = new Set(["completed", "failed", "expired", "cancelled"]);
const MAX_REMOTE_RETRY_ENTRIES = 16;
const MAX_REMOTE_RETRY_BYTES = 8 * 1024;

function rememberRemoteCommand(commandId, value) {
  remoteCommands.set(commandId, value);
  while (remoteCommands.size > 256) remoteCommands.delete(remoteCommands.keys().next().value);
}

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function clear(element) {
  while (element.firstChild) element.removeChild(element.firstChild);
}

function formatTime(value) {
  const reference = Date.parse(currentDisplay?.generatedAt ?? new Date().toISOString());
  const minutes = Math.max(0, Math.floor((reference - Date.parse(value)) / 60_000));
  if (minutes < 1) return "now";
  if (minutes < 60) return `${minutes}m`;
  return `${Math.floor(minutes / 60)}h`;
}

function compactNumber(value) {
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(value);
}

function readablePilotValue(value) {
  if (!value) return "Unavailable";
  const words = value.replace(/-/gu, " ");
  return `${words.charAt(0).toUpperCase()}${words.slice(1)}`;
}

function pilotCount(value) {
  return Number.isSafeInteger(value) ? compactNumber(value) : "Unavailable";
}

function pilotDuration(value) {
  if (!Number.isSafeInteger(value)) return "Unavailable";
  if (value < 60) return `${value}s`;
  if (value < 3_600) return `${Math.floor(value / 60)}m`;
  return `${Math.floor(value / 3_600)}h ${Math.floor(value % 3_600 / 60)}m`;
}

function pilotAge(value) {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return "Feed unavailable";
  const seconds = Math.max(0, Math.floor((Date.now() - parsed) / 1_000));
  if (seconds < 5) return "Updated just now";
  if (seconds < 60) return `Updated ${seconds}s ago`;
  if (seconds < 3_600) return `Updated ${Math.floor(seconds / 60)}m ago`;
  return `Updated ${Math.floor(seconds / 3_600)}h ago`;
}

function renderPilot(fleet) {
  if (fleet?.connection === "connected" && selectedPilotEpoch !== null
      && selectedPilotEpoch !== fleet.selectionEpoch) {
    selectedPilotAlias = null;
    selectedPilotEpoch = null;
    writePilotSelection(null, null);
  }
  let pilot = pilotCockpitPresentation(fleet, selectedPilotAlias);
  if (selectedPilotAlias !== null && fleet?.connection === "connected" && !pilot.aliases.includes(selectedPilotAlias)) {
    selectedPilotAlias = null;
    selectedPilotEpoch = null;
    writePilotSelection(null, null);
    pilot = pilotCockpitPresentation(fleet, null);
  }
  clear(elements.pilotCaseSelect);
  const placeholder = node("option", "", pilot.aliases.length > 0 ? "Select a case" : "Case feed unavailable");
  placeholder.value = "";
  elements.pilotCaseSelect.append(placeholder);
  for (const alias of pilot.aliases) {
    const option = node("option", "", alias);
    option.value = alias;
    elements.pilotCaseSelect.append(option);
  }
  elements.pilotCaseSelect.disabled = pilot.aliases.length === 0;
  elements.pilotCaseSelect.value = pilot.alias || "";
  elements.pilotCaseAlias.textContent = pilot.alias || "No case selected";
  elements.pilotHeartbeat.className = `pilot-heartbeat ${pilot.heartbeat === "current" ? "current" : pilot.heartbeat === "delayed" ? "delayed" : "unavailable"}`;
  elements.pilotHeartbeat.textContent = pilot.state === "feed-unavailable"
    ? "Feed unavailable"
    : pilot.heartbeat === "current" ? "Observer heartbeat current"
      : pilot.heartbeat === "delayed" ? "Observer heartbeat delayed" : "Observer heartbeat unavailable";
  elements.pilotAlert.hidden = pilot.state === "available";
  if (pilot.state !== "available") {
    clear(elements.pilotAlert);
    elements.pilotAlert.append(node("strong", "", pilot.title), node("span", "", pilot.recovery));
  }
  elements.pilotSolvingVerdict.textContent = readablePilotValue(pilot.solving.verdict);
  elements.pilotSolvingDetail.textContent = pilot.solving.objectives
    ? `${pilot.solving.objectives.completed} of ${pilot.solving.objectives.total} objectives complete`
    : "Objectives unavailable";
  elements.pilotLearningVerdict.textContent = readablePilotValue(pilot.learning.verdict);
  elements.pilotLearningVerdictDetail.textContent = pilot.learning.stages.transferred === null
    ? "Transfer unavailable"
    : `${pilotCount(pilot.learning.stages.transferred)} transferred learning`;
  elements.pilotCockpitVerdict.textContent = readablePilotValue(pilot.cockpit.verdict);
  elements.pilotCockpitVerdictDetail.textContent = pilot.cockpit.signals
    ? `${pilot.cockpit.signals.available} of ${pilot.cockpit.signals.total} signals available`
    : "Signals unavailable";
  elements.pilotNow.textContent = readablePilotValue(pilot.solving.now);
  elements.pilotTimestamp.textContent = pilotAge(pilot.observedAt);
  const axisActions = [pilot.solving.actionNeeded, pilot.learning.actionNeeded, pilot.cockpit.actionNeeded];
  const availableActions = axisActions.filter(Boolean);
  const activeActions = [...new Set(availableActions.filter((value) => value !== "none"))];
  const action = availableActions.length === 0 ? null : activeActions.length === 0 ? "none"
    : activeActions.length === 1 ? activeActions[0] : "multiple";
  elements.pilotAction.textContent = readablePilotValue(action);
  elements.pilotActionDetail.textContent = availableActions.length === 0 ? "Observer status required"
    : `Solving ${readablePilotValue(axisActions[0])} · Learning ${readablePilotValue(axisActions[1])} · Cockpit ${readablePilotValue(axisActions[2])}`;
  elements.pilotEvent.textContent = pilot.latestEvent
    ? `${readablePilotValue(pilot.latestEvent.category)} ${readablePilotValue(pilot.latestEvent.status)}`
    : "Unavailable";
  elements.pilotEventDetail.textContent = pilot.latestEvent ? pilotAge(pilot.latestEvent.at) : "Verified event unavailable";

  clear(elements.pilotTimeline);
  if (pilot.timeline.length === 0) {
    elements.pilotTimeline.append(node("li", "unavailable", "Plan timeline unavailable"));
  } else {
    for (const item of pilot.timeline) elements.pilotTimeline.append(node("li", item.current ? "current" : "", item.stage));
  }
  elements.pilotDepth.textContent = readablePilotValue(pilot.depth.level);
  elements.pilotDepthDetail.textContent = pilot.depth.level
    ? `${pilotCount(pilot.depth.branchesExplored)} branches · ${pilotCount(pilot.depth.techniquesAttempted)} techniques · ${pilotCount(pilot.depth.deadEndsRetired)} retired`
    : "Measurements unavailable";
  const elapsed = pilotDuration(pilot.efficiency.elapsedSeconds);
  const active = pilotDuration(pilot.efficiency.activeSeconds);
  const resourceParts = [
    pilot.efficiency.tokens === null ? null : `${pilotCount(pilot.efficiency.tokens)} tokens`,
    pilot.efficiency.toolRuns === null ? null : `${pilotCount(pilot.efficiency.toolRuns)} tools`,
    pilot.efficiency.requests === null ? null : `${pilotCount(pilot.efficiency.requests)} requests`,
    pilot.efficiency.retries === null ? null : `${pilotCount(pilot.efficiency.retries)} retries`
  ].filter(Boolean);
  elements.pilotEfficiency.textContent = pilot.efficiency.activeSeconds !== null
    ? `${active} active`
    : pilot.efficiency.tokens !== null ? `${pilotCount(pilot.efficiency.tokens)} tokens` : "Unavailable";
  elements.pilotEfficiencyDetail.textContent = [
    pilot.efficiency.elapsedSeconds === null && pilot.efficiency.activeSeconds === null
      ? "Duration unavailable"
      : `${elapsed} elapsed · ${active} active`,
    ...resourceParts
  ].join(" · ");
  elements.pilotLearning.textContent = readablePilotValue(pilot.learning.now);
  const stages = pilot.learning.stages;
  elements.pilotLearningDetail.textContent = pilot.learning.now
    ? `${pilotCount(stages.observations)} observed · ${pilotCount(stages.candidates)} candidate · ${pilotCount(stages.validated)} validated · ${pilotCount(stages.applied)} applied · ${pilotCount(stages.transferred)} transferred · ${pilotCount(stages.regressed)} regressed`
    : "Stages unavailable";
  elements.pilotCockpit.textContent = readablePilotValue(pilot.cockpit.now);
  elements.pilotCockpitDetail.textContent = pilot.cockpit.signals
    ? `${pilot.cockpit.signals.available} of ${pilot.cockpit.signals.total} signals · ${pilotCount(pilot.cockpit.updatesPublished)} updates · ${pilotCount(pilot.cockpit.updatesMissed)} missed`
    : "Signals unavailable";
  elements.pilotIntegrity.textContent = readablePilotValue(pilot.integrity.status);
  elements.pilotIntegrityDetail.textContent = pilot.integrity.checks
    ? `${pilot.integrity.checks.available} of ${pilot.integrity.checks.total} checks · ${pilotCount(pilot.integrity.issues)} issues`
    : "Checks unavailable";
}

function transport() {
  const localPresent = globalThis.GATE_PUBLIC_COCKPIT_BRIDGE !== undefined;
  const remotePresent = globalThis.GATE_REMOTE_COCKPIT_BRIDGE !== undefined;
  if (localPresent && remotePresent) return Object.freeze({ kind: "conflict", bridge: null });
  const local = validateLocalBridge(globalThis.GATE_PUBLIC_COCKPIT_BRIDGE);
  if (local) return Object.freeze({ kind: "local", bridge: local });
  const remote = validateRemoteBridge(globalThis.GATE_REMOTE_COCKPIT_BRIDGE);
  if (remote) return Object.freeze({ kind: "remote", bridge: remote });
  return Object.freeze({ kind: "none", bridge: null });
}

function exactBridge() {
  return transport().bridge;
}

function localReady() {
  const selected = transport();
  return selected.kind === "local" && localState?.connected === true && localTransportConnected !== false;
}

function remoteReady() {
  const selected = transport();
  return selected.kind === "remote"
    && remoteConnection?.state === "connected"
    && remoteState?.sessionRevision === selected.bridge.sessionRevision
    && remoteState?.runner.state === "connected"
    && remoteState?.codex.state !== "offline"
    && remoteStateIsFresh(remoteState);
}

function remoteTelemetryReady() {
  const selected = transport();
  return selected.kind === "remote"
    && remoteConnection?.state === "connected"
    && remoteState?.sessionRevision === selected.bridge.sessionRevision
    && remoteState?.runner.state === "connected"
    && remoteStateIsFresh(remoteState);
}

function liveReady() {
  const selected = transport();
  return selected.kind === "local" ? localReady() : selected.kind === "remote" ? remoteReady() : false;
}

function validateComposerMessage(value, kind = transport().kind) {
  return kind === "remote" ? validateRemoteOperatorMessage(value) : validateOperatorMessage(value);
}

function requestId() {
  return `req-${globalThis.crypto.randomUUID()}`;
}

function exactObjectKeys(value, expected) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function remoteRetryScope(selected, sessionRevision) {
  if (selected.kind !== "remote" || !selected.bridge
      || !Number.isSafeInteger(sessionRevision) || sessionRevision < 1) return null;
  return Object.freeze({ caseId: selected.bridge.caseId, sessionRevision });
}

function validRemoteRetryEntry(value) {
  if (value?.kind === "message") {
    const keys = value.commandId === undefined
      ? ["kind", "requestId", "digest"]
      : ["kind", "requestId", "digest", "commandId"];
    return exactObjectKeys(value, keys)
      && REMOTE_RETRY_REQUEST_ID.test(value.requestId) && REMOTE_RETRY_DIGEST.test(value.digest)
      && (value.commandId === undefined || REMOTE_RETRY_COMMAND_ID.test(value.commandId));
  }
  const keys = value?.commandId === undefined
    ? ["kind", "requestId", "digest", "questionToken"]
    : ["kind", "requestId", "digest", "questionToken", "commandId"];
  return value?.kind === "question"
    && exactObjectKeys(value, keys)
    && REMOTE_RETRY_REQUEST_ID.test(value.requestId) && REMOTE_RETRY_DIGEST.test(value.digest)
    && REMOTE_RETRY_QUESTION_TOKEN.test(value.questionToken)
    && (value.commandId === undefined || REMOTE_RETRY_COMMAND_ID.test(value.commandId));
}

function readRemoteRetryMetadata(scope) {
  if (!scope) return [];
  try {
    const raw = globalThis.sessionStorage?.getItem(REMOTE_RETRY_STORAGE_KEY);
    if (typeof raw !== "string" || new TextEncoder().encode(raw).byteLength > MAX_REMOTE_RETRY_BYTES) return [];
    const value = JSON.parse(raw);
    if (!exactObjectKeys(value, ["apiVersion", "caseId", "sessionRevision", "entries"])
        || value.apiVersion !== REMOTE_RETRY_VERSION || value.caseId !== scope.caseId
        || value.sessionRevision !== scope.sessionRevision || !Array.isArray(value.entries)
        || value.entries.length > MAX_REMOTE_RETRY_ENTRIES || !value.entries.every(validRemoteRetryEntry)) return [];
    return value.entries;
  } catch {
    return [];
  }
}

function writeRemoteRetryMetadata(scope, entries) {
  if (!scope) return;
  try {
    const bounded = entries.slice(-MAX_REMOTE_RETRY_ENTRIES);
    const serialized = JSON.stringify({
      apiVersion: REMOTE_RETRY_VERSION,
      caseId: scope.caseId,
      sessionRevision: scope.sessionRevision,
      entries: bounded
    });
    if (new TextEncoder().encode(serialized).byteLength <= MAX_REMOTE_RETRY_BYTES) {
      globalThis.sessionStorage?.setItem(REMOTE_RETRY_STORAGE_KEY, serialized);
    }
  } catch {
    // Retry persistence is an optional resilience layer; live submission remains available.
  }
}

function rememberRemoteRetry(scope, entry) {
  if (!scope || !entry) return;
  const entries = readRemoteRetryMetadata(scope)
    .filter((candidate) => candidate.requestId !== entry.requestId
      && !(candidate.kind === entry.kind && candidate.digest === entry.digest
        && (entry.kind !== "question" || candidate.questionToken === entry.questionToken)));
  writeRemoteRetryMetadata(scope, [...entries, entry]);
}

function forgetRemoteRetry(scope, retryRequestId) {
  if (!scope) return;
  writeRemoteRetryMetadata(scope, readRemoteRetryMetadata(scope)
    .filter((candidate) => candidate.requestId !== retryRequestId));
}

function remoteRetryForCommand(scope, value) {
  if (!scope || !value) return null;
  return readRemoteRetryMetadata(scope).find((candidate) => candidate.requestId === value.requestId
    && candidate.commandId === value.commandId) || null;
}

function queuedRemoteQuestion(scope, questionToken) {
  if (!scope) return null;
  return readRemoteRetryMetadata(scope).find((candidate) => candidate.kind === "question"
    && candidate.questionToken === questionToken && candidate.commandId !== undefined) || null;
}

function settleRemoteRetry(scope, status) {
  const persisted = remoteRetryForCommand(scope, status);
  const prior = remoteCommands.get(status.commandId);
  if ((!persisted && !prior) || !REMOTE_TERMINAL_COMMAND_STATES.has(status.state)) return false;
  if (prior?.requestId === status.requestId) {
    rememberRemoteCommand(status.commandId, Object.freeze({ ...prior, state: status.state }));
  }
  forgetRemoteRetry(scope, status.requestId);
  const questionToken = persisted?.questionToken || status.questionToken || prior?.questionToken;
  if (questionToken) {
    pendingQuestionRequests.delete(questionToken);
    if (status.state === "completed") acknowledgedQuestions.add(questionToken);
    else acknowledgedQuestions.delete(questionToken);
  }
  return true;
}

async function reconcileRemoteRetries() {
  if (reconcilingRemoteCommands || !remoteReady()) return;
  const selected = transport();
  const bridge = selected.bridge;
  const scope = remoteRetryScope(selected, remoteState?.sessionRevision);
  const references = readRemoteRetryMetadata(scope)
    .filter((entry) => entry.commandId !== undefined)
    .map((entry) => Object.freeze({ requestId: entry.requestId, commandId: entry.commandId }));
  if (!bridge || !scope || references.length === 0) return;
  const request = Object.freeze({
    apiVersion: "gate.remote-command-status-request/v1",
    caseId: scope.caseId,
    sessionRevision: scope.sessionRevision,
    commands: Object.freeze(references)
  });
  reconcilingRemoteCommands = true;
  try {
    const response = validateRemoteCommandStatusResponse(await bridge.reconcileCommands(request), request);
    if (!response || transport().bridge !== bridge || remoteState?.sessionRevision !== scope.sessionRevision) return;
    let changed = false;
    const returned = new Set();
    for (const status of response.commands) {
      returned.add(`${status.requestId}\0${status.commandId}`);
      changed = settleRemoteRetry(scope, status) || changed;
    }
    // A successful, exactly bound response omits only references that the
    // durable coordinator no longer retains. Release those local retries as
    // expired so capacity pruning cannot leave a question disabled forever.
    for (const reference of references) {
      if (returned.has(`${reference.requestId}\0${reference.commandId}`)) continue;
      changed = settleRemoteRetry(scope, { ...reference, state: "expired" }) || changed;
    }
    if (changed) {
      interactionStatus = "Queued command status restored.";
      renderRemoteMode();
    }
  } catch {
    // Live SSE remains authoritative; the next authenticated reconnect retries reconciliation.
  } finally {
    reconcilingRemoteCommands = false;
  }
}

async function remoteRetryDigest(scope, kind, payload, retryRequestId) {
  try {
    if (!scope || !REMOTE_RETRY_REQUEST_ID.test(retryRequestId)) return null;
    const bytes = new TextEncoder().encode(
      `${REMOTE_RETRY_VERSION}\0${scope.caseId}\0${scope.sessionRevision}\0${retryRequestId}\0${kind}\0${payload}`
    );
    const digest = await globalThis.crypto?.subtle?.digest("SHA-256", bytes);
    if (!digest) return null;
    return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  } catch {
    return null;
  }
}

async function findRemoteRetry(scope, kind, payload, questionToken) {
  if (!scope) return null;
  const candidates = readRemoteRetryMetadata(scope).filter((candidate) => candidate.kind === kind
    && (kind !== "question" || candidate.questionToken === questionToken));
  for (const candidate of candidates) {
    const digest = await remoteRetryDigest(scope, kind, payload, candidate.requestId);
    if (digest && digest === candidate.digest) return candidate;
  }
  return null;
}

function setMode(mode) {
  clear(elements.modeBanner);
  if (mode === "preview") {
    elements.modeBanner.className = "mode-banner mode-preview";
    elements.modeBanner.append(node("strong", "", "PREVIEW · NOT LIVE"), node("span", "", "Example data. Open the private local companion to steer Codex."));
  } else if (mode === "local") {
    elements.modeBanner.className = "mode-banner mode-local";
    elements.modeBanner.append(node("strong", "", "LIVE · PRIVATE"), node("span", "", "Local companion connected."));
  } else if (mode === "remote") {
    elements.modeBanner.className = "mode-banner mode-remote";
    elements.modeBanner.append(node("strong", "", "LIVE · REMOTE"), node("span", "", "Authenticated control plane connected."));
  } else if (mode === "remote-conversation-offline") {
    const fleetLive = remoteFleet?.connection === "connected";
    elements.modeBanner.className = "mode-banner mode-remote mode-remote-connecting";
    elements.modeBanner.append(node("strong", "", fleetLive
      ? "LIVE · FLEET · CODEX OFFLINE" : "RUNNER LIVE · CODEX OFFLINE"),
    node("span", "", fleetLive
      ? "Operational telemetry continues; conversation steering is paused."
      : "The signed runner is current; fleet telemetry is unavailable and conversation steering is paused."));
  } else if (mode === "remote-connecting") {
    elements.modeBanner.className = "mode-banner mode-remote mode-remote-connecting";
    elements.modeBanner.append(node("strong", "", "LIVE · REMOTE · CONNECTING"), node("span", "", "Restoring the live connection."));
  } else if (mode === "remote-offline") {
    elements.modeBanner.className = "mode-banner mode-remote mode-remote-offline";
    elements.modeBanner.append(node("strong", "", "LIVE · REMOTE · OFFLINE"), node("span", "", "Live connection required."));
  } else {
    elements.modeBanner.className = "mode-banner mode-unavailable";
    elements.modeBanner.append(node("strong", "", "SNAPSHOT UNAVAILABLE"), node("span", "", "No operational state is being shown."));
  }
}

function renderBridgeState(connected, mode = currentDisplay?.mode) {
  const connecting = mode === "remote-connecting";
  const telemetryOnly = mode === "remote-conversation-offline";
  elements.connectionState.className = `connection-state ${connected ? "connected" : connecting || telemetryOnly ? "connecting" : "unavailable"}`;
  clear(elements.connectionState);
  const label = connected ? mode === "remote" ? "Remote connected" : "Connected"
    : connecting ? "Connecting"
      : telemetryOnly ? remoteFleet?.connection === "connected"
        ? "Fleet live · Codex offline" : "Runner live · Codex offline"
      : mode === "preview" ? "Preview · interaction off" : "Offline";
  elements.connectionState.append(node("i", ""), document.createTextNode(label));
}

function renderUnavailable() {
  currentDisplay = undefined;
  elements.decisionPanel.hidden = false;
  setMode("unavailable");
  renderPilot(null);
  elements.siteVersion.textContent = "Unavailable";
  elements.gateVersion.textContent = "Unavailable";
  elements.runningMetricLabel.textContent = "ACTIVE WORK";
  elements.runningCount.textContent = "Unavailable";
  elements.runningSummary.textContent = "Work unavailable";
  elements.tokenMetricLabel.textContent = "TOKENS";
  elements.tokenUsage.textContent = "Unavailable";
  elements.tokenSummary.textContent = "Telemetry unavailable";
  elements.blockerCount.textContent = "Unavailable";
  elements.blockerSummary.textContent = "Status unavailable";
  elements.questionMetricLabel.textContent = "NEEDS YOU";
  elements.questionCount.textContent = "Unavailable";
  elements.questionSummary.textContent = "Queue unavailable";

  clear(elements.campaignList);
  const empty = node("div", "empty-state");
  empty.append(node("p", "", "No valid public snapshot is available."));
  elements.campaignList.append(empty);
  clear(elements.conversation);
  elements.conversation.append(node("div", "conversation-empty", "Decision state withheld until a valid snapshot arrives."));
  clear(elements.choiceList);
  elements.messageInput.disabled = true;
  elements.messageSend.disabled = true;
  updateComposer();
  elements.messageStatus.textContent = "Live connection required.";
  renderBridgeState(false);
  clear(elements.activityFeed);
  const line = node("li", "activity-row muted");
  line.append(node("time", "", "--:--"), node("span", "", "Activity withheld until a valid snapshot arrives"));
  elements.activityFeed.append(line);
  const selected = transport();
  if (localReady()) renderLocalMode();
  else if (selected.kind === "remote" || (selected.kind === "none" && remoteConnection)) renderRemoteMode();
}

function campaignCard(campaign) {
  const article = node("article", `campaign-card attention-${campaign.attention}`);
  const header = node("header", "campaign-card-header");
  const identity = node("div", "campaign-identity");
  identity.append(node("span", "campaign-glyph", campaign.alias.slice(-1)), node("h3", "", campaign.alias));
  const freshLabel = campaign.freshness === "preview" ? "Preview" : campaign.freshness === "current" ? "Current" : "Delayed";
  const fresh = node("span", `freshness freshness-${campaign.freshness}`, freshLabel);
  header.append(identity, fresh);

  const stageRow = node("div", "campaign-stage");
  const stage = node("div", "");
  stage.append(node("small", "", "STAGE"), node("strong", "", campaign.stage));
  stageRow.append(stage, node("strong", "progress-number", `${campaign.progress}%`));
  const track = node("div", "progress-track");
  track.setAttribute("role", "progressbar");
  track.setAttribute("aria-label", `${campaign.alias} progress`);
  track.setAttribute("aria-valuemin", "0");
  track.setAttribute("aria-valuemax", "100");
  track.setAttribute("aria-valuenow", String(campaign.progress));
  const fill = node("span", "progress-fill");
  fill.style.setProperty("--progress", `${campaign.progress}%`);
  track.append(fill);

  const action = node("p", "campaign-action", campaign.currentAction);
  const footer = node("footer", "campaign-card-footer");
  const attention = node("span", `attention attention-${campaign.attention}`);
  attention.append(node("i", ""), node("span", "", campaign.attention === "response-needed" ? "Response needed" : campaign.attention === "watch" ? "Watch" : "Steady"));
  const codex = node("span", `codex-state codex-${campaign.codex}`);
  codex.append(node("i", ""), node("span", "", campaign.waiting ? "Codex has a question" : campaign.codex === "working" ? "Codex working" : "Codex idle"));
  footer.append(attention, codex);
  article.append(header, stageRow, track, action, footer);
  return article;
}

function renderDecision(model) {
  clear(elements.conversation);
  clear(elements.choiceList);
  const bridge = exactBridge(model);
  renderBridgeState(Boolean(bridge), model.mode);
  elements.decisionPanel.hidden = false;
  if (model.decision.state === "clear") {
    elements.conversation.append(node("div", "conversation-empty", "Codex does not need a decision right now."));
    configureComposer(model, bridge);
    return;
  }

  const codexMessage = node("div", "message message-codex");
  codexMessage.append(node("small", "", `CODEX · ${model.decision.campaign}`), node("p", "", model.decision.prompt));
  elements.conversation.append(codexMessage);
  model.decision.choices.forEach((choice) => {
    const button = node("button", `choice-button${choice.recommended ? " recommended" : ""}`);
    button.type = "button";
    button.disabled = true;
    button.append(node("span", "", choice.label));
    if (choice.recommended) button.append(node("small", "", "Recommended"));
    elements.choiceList.append(button);
  });
  configureComposer(model, bridge);
}

function configureComposer(model, bridge) {
  const enabled = Boolean(bridge) && liveReady();
  const conversationOffline = transport().kind === "remote" && remoteTelemetryReady()
    && remoteState?.codex.state === "offline";
  elements.messageInput.disabled = !enabled;
  elements.messageInput.placeholder = enabled ? "Write a short message…"
    : conversationOffline ? "Codex conversation offline" : "Live connection required";
  elements.messageStatus.textContent = enabled
    ? interactionStatus || "Ready."
    : conversationOffline ? "Fleet telemetry is live. Conversation commands are paused." : "Live connection required.";
  updateComposer();
}

function updateComposer() {
  const validation = validateComposerMessage(elements.messageInput.value);
  elements.messageCount.textContent = `${[...elements.messageInput.value].length} / 1000`;
  elements.messageSend.disabled = elements.messageInput.disabled || submitting || !validation.valid;
}

async function submitMessage(event) {
  event.preventDefault();
  const selected = transport();
  const bridge = selected.bridge;
  const validation = validateComposerMessage(elements.messageInput.value, selected.kind);
  if (!bridge || !liveReady() || !validation.valid || submitting) return;
  const sessionRevision = selected.kind === "remote" ? remoteState?.sessionRevision : localState?.sessionRevision;
  const retryScope = remoteRetryScope(selected, sessionRevision);
  submitting = true;
  interactionStatus = selected.kind === "remote" ? "Preparing command…" : "Requesting local companion acceptance…";
  updateComposer();
  elements.messageStatus.textContent = interactionStatus;
  try {
    if (transport().bridge !== bridge || !liveReady()) throw new Error("connection changed");
    const memoryRetry = pendingMessageRequest?.sessionRevision === sessionRevision
      && pendingMessageRequest.message === validation.message ? pendingMessageRequest : null;
    const persistedRetry = retryScope ? await findRemoteRetry(retryScope, "message", validation.message) : null;
    const id = memoryRetry?.requestId || persistedRetry?.requestId || requestId();
    const digest = retryScope ? await remoteRetryDigest(retryScope, "message", validation.message, id) : null;
    pendingMessageRequest = Object.freeze({ requestId: id, sessionRevision, message: validation.message });
    rememberRemoteRetry(retryScope, digest ? Object.freeze({ kind: "message", requestId: id, digest }) : null);
    interactionStatus = selected.kind === "remote" ? "Queueing command…" : interactionStatus;
    elements.messageStatus.textContent = interactionStatus;
    const receipt = await bridge.submitMessage(Object.freeze({
      apiVersion: selected.kind === "remote" ? "gate.remote-message-request/v1" : "gate.local-message-request/v1",
      requestId: id,
      sessionRevision,
      message: validation.message
    }));
    if (selected.kind === "remote") {
      const queued = validateRemoteQueuedReceipt(receipt, id, sessionRevision);
      if (!queued || remoteState?.sessionRevision !== sessionRevision || !remoteReady()) throw new Error("invalid receipt");
      const observed = remoteCommands.get(queued.commandId);
      const current = observed?.requestId === id ? observed : null;
      rememberRemoteCommand(queued.commandId, Object.freeze({
        ...queued, ...current, kind: "message", state: current?.state || "queued",
        eventSequence: current?.eventSequence || 0
      }));
      if (digest && !REMOTE_TERMINAL_COMMAND_STATES.has(current?.state)) {
        rememberRemoteRetry(retryScope, Object.freeze({
          kind: "message", requestId: id, digest, commandId: queued.commandId
        }));
      } else {
        forgetRemoteRetry(retryScope, id);
      }
      interactionStatus = "Queued for Codex.";
    } else {
      if (!validateBridgeReceipt(receipt, id) || localState?.sessionRevision !== sessionRevision || !localReady()) throw new Error("invalid receipt");
      interactionStatus = "Local companion accepted the message. Delivery to Codex is not confirmed here.";
    }
    elements.messageInput.value = "";
    pendingMessageRequest = undefined;
    elements.messageStatus.textContent = interactionStatus;
  } catch {
    interactionStatus = selected.kind === "remote"
      ? "No valid queued receipt was received. Your message remains in the composer."
      : "No valid local receipt was received. Your message remains in the composer.";
    elements.messageStatus.textContent = interactionStatus;
  } finally {
    submitting = false;
    if (selected.kind === "remote") renderRemoteMode();
    else updateComposer();
  }
}

function localTime(value) {
  const selected = transport();
  const state = selected.kind === "remote" ? remoteState : localState;
  const reference = Date.parse(state?.observedAt || new Date().toISOString());
  const minutes = Math.max(0, Math.floor((reference - Date.parse(value)) / 60_000));
  if (minutes < 1) return "now";
  if (minutes < 60) return `${minutes}m`;
  return `${Math.floor(minutes / 60)}h`;
}

function selectionsFor(pending) {
  let selections = nativeSelections.get(pending.token);
  if (!selections) {
    selections = Object.fromEntries(pending.questions.map((question) => [question.id, question.options[0].label]));
    nativeSelections.set(pending.token, selections);
  }
  return selections;
}

async function submitNativeQuestion(pending) {
  const selected = transport();
  const bridge = selected.bridge;
  const sessionRevision = selected.kind === "remote" ? remoteState?.sessionRevision : localState?.sessionRevision;
  const retryScope = remoteRetryScope(selected, sessionRevision);
  if (!bridge || !liveReady() || submitting || acknowledgedQuestions.has(pending.token)
      || queuedRemoteQuestion(retryScope, pending.token)) return;
  const answers = { ...selectionsFor(pending) };
  const answerKey = JSON.stringify(answers);
  submitting = true;
  interactionStatus = selected.kind === "remote" ? "Preparing choices…" : "Sending choices…";
  renderLiveMode();
  try {
    if (transport().bridge !== bridge || !liveReady()) throw new Error("connection changed");
    const retry = pendingQuestionRequests.get(pending.token);
    const digestPayload = `${pending.token}\0${answerKey}`;
    const persistedRetry = retryScope ? await findRemoteRetry(retryScope, "question", digestPayload, pending.token) : null;
    const id = retry?.sessionRevision === sessionRevision && retry.answerKey === answerKey
      ? retry.requestId : persistedRetry?.requestId || requestId();
    const digest = retryScope ? await remoteRetryDigest(retryScope, "question", digestPayload, id) : null;
    pendingQuestionRequests.set(pending.token, Object.freeze({ requestId: id, sessionRevision, answerKey }));
    rememberRemoteRetry(retryScope, digest ? Object.freeze({
      kind: "question", requestId: id, digest, questionToken: pending.token
    }) : null);
    interactionStatus = selected.kind === "remote" ? "Queueing choices…" : interactionStatus;
    renderLiveMode();
    const receipt = await bridge.submitQuestion(Object.freeze({
      apiVersion: selected.kind === "remote" ? "gate.remote-question-response/v1" : "gate.local-question-response/v1",
      requestId: id,
      sessionRevision,
      questionToken: pending.token,
      answers: Object.freeze(answers)
    }));
    if (selected.kind === "remote") {
      const queued = validateRemoteQueuedReceipt(receipt, id, sessionRevision);
      if (!queued || remoteState?.sessionRevision !== sessionRevision || !remoteReady()) throw new Error("invalid receipt");
      const observed = remoteCommands.get(queued.commandId);
      const current = observed?.requestId === id ? observed : null;
      rememberRemoteCommand(queued.commandId, Object.freeze({
        ...queued, ...current, kind: "question", questionToken: pending.token,
        state: current?.state || "queued", eventSequence: current?.eventSequence || 0
      }));
      if (digest && !REMOTE_TERMINAL_COMMAND_STATES.has(current?.state)) {
        rememberRemoteRetry(retryScope, Object.freeze({
          kind: "question", requestId: id, digest, questionToken: pending.token,
          commandId: queued.commandId
        }));
      } else {
        forgetRemoteRetry(retryScope, id);
      }
      if (current && new Set(["failed", "expired", "cancelled"]).has(current.state)) {
        acknowledgedQuestions.delete(pending.token);
      } else {
        acknowledgedQuestions.add(pending.token);
      }
    } else if (!validateBridgeReceipt(receipt, id) || localState?.sessionRevision !== sessionRevision) {
      throw new Error("invalid receipt");
    } else {
      acknowledgedQuestions.add(pending.token);
    }
    pendingQuestionRequests.delete(pending.token);
    interactionStatus = selected.kind === "remote"
      ? "Choices queued for Codex."
      : "Local companion accepted the choices. Codex will continue in the dedicated thread.";
  } catch {
    interactionStatus = selected.kind === "remote"
      ? "No valid queued receipt was received. Your choices remain selected."
      : "No valid local receipt was received. Your choices remain selected.";
  } finally {
    submitting = false;
    renderLiveMode();
  }
}

function renderNativeQuestions(pending, bridge) {
  const usable = Boolean(bridge) && liveReady();
  const selectedTransport = transport();
  const sessionRevision = selectedTransport.kind === "remote"
    ? remoteState?.sessionRevision : localState?.sessionRevision;
  const queued = queuedRemoteQuestion(remoteRetryScope(selectedTransport, sessionRevision), pending.token);
  const acknowledged = acknowledgedQuestions.has(pending.token);
  const locked = acknowledged || Boolean(queued);
  const selections = queued && !acknowledged ? {} : selectionsFor(pending);
  for (const question of pending.questions) {
    const group = node("section", "native-question");
    group.setAttribute("aria-labelledby", `native-${question.id}`);
    const heading = node("div", "native-question-heading");
    heading.append(node("small", "", question.header), node("p", "", question.question));
    heading.querySelector("p").id = `native-${question.id}`;
    const choices = node("div", "native-options");
    for (const option of question.options) {
      const selected = selections[question.id] === option.label;
      const button = node("button", `choice-button native-option${selected ? " selected" : ""}${option.recommended ? " recommended" : ""}`);
      button.type = "button";
      button.disabled = !usable || submitting || locked;
      button.setAttribute("aria-pressed", String(selected));
      button.append(node("span", "", option.label), node("small", "", option.description));
      button.addEventListener("click", () => {
        selections[question.id] = option.label;
        renderLiveMode();
      });
      choices.append(button);
    }
    group.append(heading, choices);
    elements.choiceList.append(group);
  }
  const submit = node("button", "native-submit", locked
    ? transport().kind === "remote" || remoteConnection ? "Queued" : "Accepted locally"
    : "Continue with selected answers");
  submit.type = "button";
  submit.disabled = !usable || submitting || locked;
  submit.addEventListener("click", () => submitNativeQuestion(pending));
  elements.choiceList.append(submit);
}

function renderLiveConversation(state) {
  clear(elements.conversation);
  clear(elements.choiceList);
  const entries = state.conversation.slice(-12);
  if (entries.length === 0) {
    elements.conversation.append(node("div", "conversation-empty", state.turn === "working" ? "Codex is working…" : "Send a short message to steer Codex."));
  } else {
    for (const entry of entries) {
      const message = node("div", `message ${entry.role === "operator" ? "message-operator" : "message-codex"}`);
      message.append(
        node("small", "", `${entry.role === "operator" ? "GIOVANNI" : "CODEX"} · ${localTime(entry.at)}`),
        node("p", "", entry.text)
      );
      elements.conversation.append(message);
    }
  }
  const pending = state.pendingQuestions.find((item) => !acknowledgedQuestions.has(item.token));
  if (pending) renderNativeQuestions(pending, exactBridge());
}

function localActivityLine(entry, latest) {
  const line = node("li", `activity-row local-activity${latest ? " latest" : ""}`);
  const identity = node("div", "activity-identity");
  identity.append(node("strong", "", "CODEX"), node("span", "", entry.category.replace("-", " ")));
  const determinate = entry.completed !== null && entry.total !== null;
  const progress = node("div", `activity-progress${determinate ? "" : " indeterminate"}`);
  progress.setAttribute("role", "progressbar");
  progress.setAttribute("aria-label", `${entry.category} ${entry.state}`);
  if (determinate) {
    const percentage = Math.round(entry.completed / entry.total * 100);
    progress.setAttribute("aria-valuemin", "0");
    progress.setAttribute("aria-valuemax", "100");
    progress.setAttribute("aria-valuenow", String(percentage));
    const fill = node("i", "");
    fill.style.setProperty("--activity-progress", `${percentage}%`);
    progress.append(fill);
  } else {
    const activityState = entry.state === "completed" ? "Completed"
      : entry.state === "failed" ? "Failed"
        : entry.state === "blocked" ? "Needs attention"
          : entry.state === "started" ? "Running" : "Updated";
    progress.setAttribute("aria-valuetext", activityState);
    progress.append(node("i", ""));
  }
  const result = entry.state === "completed" ? "Done" : entry.state === "failed" ? "Failed" : entry.state === "blocked" ? "Needs attention" : entry.state === "started" ? "Running" : "Updated";
  line.append(
    node("time", "", localTime(entry.at)),
    identity,
    node("span", "activity-count", determinate ? `${entry.completed} / ${entry.total}` : "Unavailable"),
    node("span", "activity-result", result),
    progress
  );
  return line;
}

function fleetMetricText(value) {
  if (!value || value.precision === "unavailable" || value.value === null) return "Unavailable";
  return `${compactNumber(value.value)}${value.precision === "lower-bound" ? "+" : ""}`;
}

function fleetStageLabel(value) {
  const labels = {
    governance: "Governance",
    "offline-static": "Offline static",
    "offline-dynamic": "Offline dynamic",
    "passive-research": "Passive research",
    "active-observation": "Active observation",
    "active-testing": "Active testing",
    "high-impact-controlled": "Controlled high impact",
    closure: "Closure",
    multiple: "Multiple active lanes",
    idle: "Idle",
    unknown: "Stage unavailable",
    "profile-questionnaire": "Profile intake",
    "profile-operator-review": "Operator review",
    "profile-ready": "Profile ready",
    "profile-superseded": "Superseded"
  };
  return labels[value] || "Stage unavailable";
}

function fleetWorkSummary(campaign) {
  if (campaign.kind === "profile") {
    const blockers = fleetMetricText(campaign.work.setupBlockers);
    return `${campaign.progress.completed} / ${campaign.progress.total} answers · ${blockers} blockers`;
  }
  if (campaign.pilot?.availability === "available") {
    const tokens = campaign.tokens.availability === "unavailable"
      ? "tokens unavailable"
      : `${compactNumber(campaign.tokens.total)} ${campaign.tokens.availability} tokens`;
    return `Solving ${readablePilotValue(campaign.pilot.solving.verdict)} · Learning ${readablePilotValue(campaign.pilot.learning.verdict)} · Cockpit ${readablePilotValue(campaign.pilot.cockpit.verdict)} · ${tokens}`;
  }
  const workflows = fleetMetricText(campaign.work.activeWorkflows);
  const executions = fleetMetricText(campaign.work.runningExecutions);
  const analyses = fleetMetricText(campaign.work.runningAnalyses);
  const tokens = campaign.tokens.availability === "unavailable"
    ? "Awaiting attribution"
    : `${compactNumber(campaign.tokens.total)} ${campaign.tokens.availability} · canonical case tokens`;
  return `${workflows} workflows · ${executions} runs · ${analyses} analyses · ${tokens}`;
}

function localFleetCampaignCard(campaign) {
  const article = node("article", `campaign-card attention-${campaign.attention}`);
  const header = node("header", "campaign-card-header");
  const identity = node("div", "campaign-identity");
  identity.append(node("span", "campaign-glyph", campaign.alias.slice(-1)), node("h3", "", campaign.alias));
  const freshness = campaign.freshness === "current" ? "Current" : campaign.freshness === "delayed" ? "Delayed" : "Unknown";
  header.append(identity, node("span", `freshness freshness-${campaign.freshness}`, freshness));

  const stageRow = node("div", "campaign-stage");
  const stage = node("div", "");
  const pilotActive = campaign.kind === "case" && campaign.pilot?.availability === "available";
  stage.append(
    node("small", "", campaign.kind === "profile" ? "PROFILE" : pilotActive ? "CURRENT PLAN STEP" : "CURRENT LANE"),
    node("strong", "", pilotActive ? readablePilotValue(campaign.pilot.solving.now) : fleetStageLabel(campaign.stage))
  );
  const objectiveMetric = pilotActive && campaign.pilot.solving.objectives.availability === "available"
    ? campaign.pilot.solving.objectives : null;
  const objectiveProgress = objectiveMetric ? `${objectiveMetric.completed}/${objectiveMetric.total}` : null;
  const progressPercent = objectiveMetric
    ? Math.floor(objectiveMetric.completed / objectiveMetric.total * 100)
    : campaign.progress?.percent ?? null;
  stageRow.append(stage, node("strong", "progress-number", objectiveProgress || (progressPercent === null ? "Unavailable" : `${progressPercent}%`)));
  const track = node("div", `progress-track${progressPercent === null ? " unavailable" : ""}`);
  track.setAttribute("role", "progressbar");
  track.setAttribute("aria-label", `${campaign.alias} progress`);
  const fill = node("span", "progress-fill");
  if (progressPercent === null) {
    track.setAttribute("aria-valuetext", campaign.kind === "case" ? "Objective progress unavailable" : "No percentage available");
  } else {
    track.setAttribute("aria-valuemin", "0");
    track.setAttribute("aria-valuemax", "100");
    track.setAttribute("aria-valuenow", String(progressPercent));
    fill.style.setProperty("--progress", `${progressPercent}%`);
  }
  track.append(fill);
  const footer = node("footer", "campaign-card-footer");
  const attention = node("span", `attention attention-${campaign.attention}`);
  attention.append(node("i", ""), node("span", "", campaign.attention === "response-needed" ? "Response needed" : campaign.attention === "watch" ? "Watch" : "Steady"));
  const pilotUnavailable = campaign.kind === "case" && campaign.pilot?.availability !== "available";
  const state = node("span", `codex-state codex-${pilotUnavailable ? "waiting" : campaign.state === "running" ? "working" : campaign.state === "waiting" ? "waiting" : "idle"}`);
  state.append(node("i", ""), node("span", "", pilotUnavailable ? "Pilot unavailable" : campaign.state.replace("-", " ")));
  footer.append(attention, state);
  article.append(header, stageRow, track, node("p", "campaign-action", fleetWorkSummary(campaign)), footer);
  return article;
}

function remoteViewState() {
  if (!remoteState) return null;
  return Object.freeze({
    ...remoteState,
    connected: remoteState.runner.state === "connected",
    turn: remoteState.codex.state === "offline" ? "idle" : remoteState.codex.state
  });
}

function remoteCommandLine(entry, latest) {
  const line = node("li", `activity-row local-activity command-activity${latest ? " latest" : ""}`);
  const identity = node("div", "activity-identity");
  identity.append(node("strong", "", "CODEX"), node("span", "", "command"));
  const progress = node("div", `activity-progress${new Set(["completed", "failed", "expired", "cancelled"]).has(entry.state) ? "" : " indeterminate"}`);
  progress.setAttribute("role", "progressbar");
  progress.setAttribute("aria-label", `Command ${entry.state}`);
  progress.setAttribute("aria-valuetext", entry.state);
  progress.append(node("i", ""));
  const when = entry.at || entry.acceptedAt;
  line.append(
    node("time", "", localTime(when)),
    identity,
    node("span", "activity-count", "Unavailable"),
    node("span", "activity-result", entry.state === "queued" ? "Queued" : entry.state.replace("-", " ")),
    progress
  );
  return line;
}

function renderRemoteWithoutState() {
  const mode = remoteConnection?.state === "connecting" ? "remote-connecting" : "remote-offline";
  setMode(mode);
  renderPilot(null);
  elements.decisionPanel.hidden = false;
  for (const [count, summary, text] of [
    [elements.runningCount, elements.runningSummary, "Work unavailable"],
    [elements.questionCount, elements.questionSummary, "Queue unavailable"],
    [elements.blockerCount, elements.blockerSummary, "Status unavailable"],
    [elements.tokenUsage, elements.tokenSummary, "Telemetry unavailable"]
  ]) {
    count.textContent = "Unavailable";
    summary.textContent = text;
  }
  clear(elements.campaignList);
  const empty = node("div", "empty-state");
  empty.append(node("p", "", "Live connection required."));
  elements.campaignList.append(empty);
  clear(elements.conversation);
  elements.conversation.append(node("div", "conversation-empty", "Live connection required."));
  clear(elements.choiceList);
  renderBridgeState(false, mode);
  configureComposer(currentDisplay || { mode }, exactBridge());
  clear(elements.activityFeed);
  const line = node("li", "activity-row muted");
  line.append(node("time", "", "now"), node("span", "", "Live connection required"));
  elements.activityFeed.append(line);
}

function renderLiveMode() {
  const selected = transport();
  const remoteMode = selected.kind === "remote" || (selected.kind === "none" && Boolean(remoteConnection));
  if (selected.kind === "conflict") {
    renderUnavailable();
    return;
  }
  if (remoteMode && !remoteState) {
    renderRemoteWithoutState();
    return;
  }
  if (selected.kind === "local" && !localReady()) return;
  if (selected.kind !== "local" && !remoteMode) return;
  const state = remoteMode ? remoteViewState() : localState;
  const fleet = remoteMode ? remoteFleet : localFleet;
  const activity = remoteMode ? remoteActivity : localActivity;
  const ready = remoteMode ? remoteReady() : localReady();
  const mode = !remoteMode ? "local"
    : ready ? "remote"
      : remoteTelemetryReady() && remoteState?.codex.state === "offline" ? "remote-conversation-offline"
      : remoteConnection?.state === "connecting" ? "remote-connecting" : "remote-offline";
  const fleetConnected = fleet?.connection === "connected";
  renderPilot(fleet);
  const fleetSummary = fleet?.summary;
  setMode(mode);
  elements.decisionPanel.hidden = false;
  elements.runningMetricLabel.textContent = "ACTIVE WORK";
  elements.runningCount.textContent = fleetMetricText(fleetSummary?.active);
  elements.runningSummary.textContent = fleetConnected
    ? `${fleetMetricText(fleetSummary.activeWorkflows)} workflow lanes · ${fleetMetricText(fleetSummary.runningExecutions)} runs · ${fleetMetricText(fleetSummary.runningAnalyses)} analyses`
    : state.turn === "working" ? "Codex active · fleet unavailable" : "Fleet unavailable";
  const campaignTokens = fleetSummary?.campaignTokens;
  if (fleetConnected && campaignTokens?.availability !== "unavailable") {
    elements.tokenMetricLabel.textContent = "TOKENS";
    elements.tokenUsage.textContent = `${compactNumber(campaignTokens.total)}${campaignTokens.availability === "partial" ? "+" : ""}`;
    elements.tokenSummary.textContent = state.tokens
      ? `${campaignTokens.availability} fleet · ${compactNumber(state.tokens.total)} session`
      : `${campaignTokens.availability} fleet attribution`;
  } else if (state.tokens) {
    elements.tokenMetricLabel.textContent = "TOKENS";
    elements.tokenUsage.textContent = compactNumber(state.tokens.total);
    elements.tokenSummary.textContent = "Exact dedicated session";
  } else {
    elements.tokenMetricLabel.textContent = "TOKENS";
    elements.tokenUsage.textContent = "Unavailable";
    elements.tokenSummary.textContent = "Telemetry unavailable";
  }
  elements.blockerCount.textContent = fleetMetricText(fleetSummary?.blockers);
  elements.blockerSummary.textContent = fleetConnected ? "Blocked cases and profile setup" : "Status unavailable";
  const visiblePendingCount = state.pendingQuestions.reduce((total, pending) => total + pending.questions.length, 0);
  const hasWithheldRemoteQuestion = remoteMode && state.turn === "waiting" && visiblePendingCount === 0;
  const pendingCount = visiblePendingCount + (hasWithheldRemoteQuestion ? 1 : 0);
  const attentionMetric = fleetSummary?.attention;
  const attentionKnown = hasAvailableFleetMetric(attentionMetric);
  elements.questionMetricLabel.textContent = "NEEDS YOU";
  elements.questionCount.textContent = attentionKnown
    ? `${compactNumber(pendingCount + attentionMetric.value)}${attentionMetric.precision === "lower-bound" ? "+" : ""}`
    : pendingCount > 0 ? `${compactNumber(pendingCount)}+` : "Unavailable";
  elements.questionSummary.textContent = hasWithheldRemoteQuestion
    ? attentionKnown
      ? `Open laptop · ${fleetMetricText(attentionMetric)} fleet alert${attentionMetric.value === 1 ? "" : "s"}`
      : "Open laptop · fleet status unavailable"
    : attentionKnown
      ? `${pendingCount} question${pendingCount === 1 ? "" : "s"} · ${fleetMetricText(attentionMetric)} fleet alert${attentionMetric.value === 1 ? "" : "s"}`
      : `${pendingCount} question${pendingCount === 1 ? "" : "s"} · fleet status unavailable`;

  clear(elements.campaignList);
  if (fleetConnected && fleet.campaigns.length > 0) {
    fleet.campaigns.forEach((campaign) => elements.campaignList.append(localFleetCampaignCard(campaign)));
  } else {
    const empty = node("div", "empty-state");
    empty.append(node("p", "", fleetConnected
      ? fleet.coverage.state === "exact" ? "No active projects." : "No projects in the current partial view."
      : "Fleet signal unavailable."));
    elements.campaignList.append(empty);
  }

  renderLiveConversation(state);
  renderBridgeState(ready, mode);
  configureComposer(currentDisplay || { mode: "preview" }, exactBridge());
  clear(elements.activityFeed);
  const events = [...activity].sort((left, right) => right.sequence - left.sequence);
  const commands = remoteMode
    ? [...remoteCommands.values()].sort((left, right) => Date.parse(right.at || right.acceptedAt) - Date.parse(left.at || left.acceptedAt))
    : [];
  if (events.length === 0 && commands.length === 0) {
    const line = node("li", "activity-row muted");
    line.append(node("time", "", "now"), node("span", "", state.turn === "working" ? "Codex is starting…" : "No live activity yet"));
    elements.activityFeed.append(line);
  } else {
    const combined = [
      ...commands.map((entry) => ({ kind: "command", entry, at: entry.at || entry.acceptedAt })),
      ...events.map((entry) => ({ kind: "activity", entry, at: entry.at }))
    ].sort((left, right) => Date.parse(right.at) - Date.parse(left.at)).slice(0, 24);
    combined.forEach((item, index) => elements.activityFeed.append(item.kind === "command"
      ? remoteCommandLine(item.entry, index === 0)
      : localActivityLine(item.entry, index === 0)));
  }
}

function renderLocalMode() {
  if (localReady()) renderLiveMode();
}

function renderRemoteMode() {
  renderLiveMode();
}

function activityLine(entry, latest) {
  const line = node("li", `activity-row${latest ? " latest" : ""}`);
  const identity = node("div", "activity-identity");
  identity.append(node("strong", "", entry.campaign), node("span", "", entry.category));
  const progress = node("div", "activity-progress");
  progress.setAttribute("role", "progressbar");
  progress.setAttribute("aria-label", `${entry.campaign} ${entry.category} progress`);
  progress.setAttribute("aria-valuemin", "0");
  progress.setAttribute("aria-valuemax", "100");
  progress.setAttribute("aria-valuenow", String(entry.progress));
  const fill = node("i", "");
  fill.style.setProperty("--activity-progress", `${entry.progress}%`);
  progress.append(fill);
  line.append(node("time", "", formatTime(entry.at)), identity, node("span", "activity-count", `${entry.completed} / ${entry.total}`), node("span", "activity-result", entry.result), progress);
  return line;
}

function renderAvailable(model) {
  currentDisplay = model;
  setMode(model.mode);
  renderPilot(null);
  elements.siteVersion.textContent = `v${model.siteVersion}`;
  elements.gateVersion.textContent = `v${model.gateVersion}`;
  const runningCount = model.campaigns.filter((campaign) => campaign.codex === "working").length;
  const activeCount = model.campaigns.filter((campaign) => !["Complete", "Paused"].includes(campaign.stage)).length;
  elements.runningMetricLabel.textContent = "RUNNING";
  elements.runningCount.textContent = String(runningCount);
  elements.runningSummary.textContent = `${activeCount} active project${activeCount === 1 ? "" : "s"}`;
  elements.tokenMetricLabel.textContent = "TOKENS";
  if (model.aggregate.tokenStatus === "available") {
    elements.tokenUsage.textContent = `${compactNumber(model.aggregate.tokensUsed)} / ${compactNumber(model.aggregate.tokenBudget)}`;
    elements.tokenSummary.textContent = `Example budget · ${Math.round(model.aggregate.tokensUsed / model.aggregate.tokenBudget * 100)}%`;
  } else {
    elements.tokenUsage.textContent = "Unavailable";
    elements.tokenSummary.textContent = "Telemetry unavailable";
  }
  elements.blockerCount.textContent = String(model.aggregate.blockerCount);
  elements.blockerSummary.textContent = model.aggregate.blockerCount === 1 ? "Preview blocker" : "Preview blockers";
  const waiting = model.decision.state === "waiting" ? 1 : 0;
  elements.questionMetricLabel.textContent = "NEEDS YOU";
  elements.questionCount.textContent = String(waiting);
  elements.questionSummary.textContent = waiting ? "One decision queued" : "Nothing queued";

  clear(elements.campaignList);
  if (model.campaigns.length === 0) {
    const empty = node("div", "empty-state");
    empty.append(node("p", "", "No projects in this snapshot."));
    elements.campaignList.append(empty);
  } else {
    model.campaigns.forEach((campaign) => elements.campaignList.append(campaignCard(campaign)));
  }
  renderDecision(model);
  clear(elements.activityFeed);
  if (model.activity.length === 0) {
    const line = node("li", "activity-row muted");
    line.append(node("time", "", "--:--"), node("span", "", "No public activity signals"));
    elements.activityFeed.append(line);
  } else {
    model.activity.forEach((entry, index) => elements.activityFeed.append(activityLine(entry, index === 0)));
  }
  if (localReady()) renderLocalMode();
  else if (transport().kind === "remote" || remoteConnection) renderRemoteMode();
}

async function refresh() {
  try {
    const response = await fetch("./data/status.json", {
      cache: "no-store", credentials: "same-origin", redirect: "error", headers: { Accept: "application/json" }
    });
    const parsed = await readPublicSnapshotResponse(response, { minimumGeneratedAt: latestGeneratedAt });
    const display = toDisplayModel(parsed);
    if (display.kind !== "available") {
      renderUnavailable();
      return;
    }
    if (currentDisplay && display.generatedAt === currentDisplay.generatedAt && display.mode === currentDisplay.mode) return;
    latestGeneratedAt = display.generatedAt;
    renderAvailable(display);
  } catch {
    renderUnavailable();
  }
}

refresh();
window.setInterval(refresh, 60_000);
window.setInterval(() => {
  const now = Date.now();
  let changed = false;
  if (localFleet && Date.parse(localFleet.validUntil) <= now) { localFleet = undefined; changed = true; }
  if (remoteFleet && Date.parse(remoteFleet.validUntil) <= now) { remoteFleet = undefined; changed = true; }
  if (changed) renderLiveMode();
}, 1_000);
globalThis.addEventListener("gate:companion-snapshot", refresh);
globalThis.addEventListener("gate:companion-private-state", (event) => {
  const next = validateLocalCompanionState(event.detail);
  if (!next) return;
  if (localState?.sessionRevision === next.sessionRevision && next.stateRevision < localState.stateRevision) return;
  if (localState && localState.sessionRevision !== next.sessionRevision) {
    localActivity = [];
    acknowledgedQuestions.clear();
    nativeSelections.clear();
    interactionStatus = "";
    pendingMessageRequest = undefined;
    pendingQuestionRequests.clear();
  }
  localState = next;
  localTransportConnected = next.connected;
  if (localReady()) renderLocalMode();
  else if (currentDisplay?.kind === "available") renderAvailable(currentDisplay);
  else renderUnavailable();
});
globalThis.addEventListener("gate:companion-activity", (event) => {
  const next = validateLocalActivityEvent(event.detail);
  if (!next) return;
  localActivity = [...localActivity.filter((entry) => entry.sequence !== next.sequence), next]
    .sort((left, right) => left.sequence - right.sequence)
    .slice(-64);
  if (localReady()) renderLocalMode();
});
globalThis.addEventListener("gate:companion-fleet", (event) => {
  const next = validateLocalFleet(event.detail);
  if (!next || localFleet?.revision > next.revision) return;
  localFleet = next;
  if (localReady()) renderLocalMode();
});
globalThis.addEventListener("gate:companion-connection", (event) => {
  if (typeof event.detail?.connected !== "boolean") return;
  localTransportConnected = event.detail.connected;
  if (localReady()) renderLocalMode();
  else if (currentDisplay?.kind === "available") renderAvailable(currentDisplay);
});
globalThis.addEventListener("gate:remote-private-state", (event) => {
  const bridge = validateRemoteBridge(globalThis.GATE_REMOTE_COCKPIT_BRIDGE);
  const next = validateRemoteCompanionState(event.detail, bridge ? { sessionRevision: bridge.sessionRevision } : {});
  if (!next || remoteState?.sessionRevision === next.sessionRevision && next.stateRevision < remoteState.stateRevision) return;
  if (remoteState && remoteState.sessionRevision !== next.sessionRevision) {
    remoteActivity = [];
    remoteCommands.clear();
    acknowledgedQuestions.clear();
    nativeSelections.clear();
    interactionStatus = "";
    pendingMessageRequest = undefined;
    pendingQuestionRequests.clear();
  }
  remoteState = next;
  renderRemoteMode();
  void reconcileRemoteRetries();
});
globalThis.addEventListener("gate:remote-activity", (event) => {
  const next = validateRemoteActivityEvent(event.detail);
  if (!next) return;
  remoteActivity = [...remoteActivity.filter((entry) => entry.sequence !== next.sequence), next]
    .sort((left, right) => left.sequence - right.sequence)
    .slice(-64);
  renderRemoteMode();
});
globalThis.addEventListener("gate:remote-fleet", (event) => {
  const bridge = validateRemoteBridge(globalThis.GATE_REMOTE_COCKPIT_BRIDGE);
  const next = validateRemoteFleet(event.detail, bridge ? { sessionRevision: bridge.sessionRevision } : {});
  if (!next || remoteFleet?.revision > next.revision) return;
  remoteFleet = next;
  renderRemoteMode();
});
globalThis.addEventListener("gate:remote-projection-unavailable", (event) => {
  if (!exactObjectKeys(event.detail, ["apiVersion", "projection"])
      || event.detail.apiVersion !== "gate.remote-projection-unavailable/v1"
      || !new Set(["state", "fleet"]).has(event.detail.projection)) return;
  if (event.detail.projection === "state") remoteState = undefined;
  remoteFleet = undefined;
  renderRemoteMode();
});
globalThis.addEventListener("gate:remote-command", (event) => {
  const prior = event.detail?.commandId ? remoteCommands.get(event.detail.commandId) : null;
  const next = validateRemoteCommandEvent(event.detail, prior?.acceptedAt ? { acceptedAt: prior.acceptedAt } : {});
  if (!next || prior && (prior.requestId !== next.requestId || prior.eventSequence >= next.sequence)) return;
  const selected = transport();
  const retryScope = remoteRetryScope(selected, remoteState?.sessionRevision ?? selected.bridge?.sessionRevision);
  const persisted = remoteRetryForCommand(retryScope, next);
  const questionToken = prior?.questionToken || persisted?.questionToken;
  rememberRemoteCommand(next.commandId, Object.freeze({
    ...prior,
    ...next,
    kind: prior?.kind || persisted?.kind || "command",
    ...(questionToken ? { questionToken } : {}),
    eventSequence: next.sequence
  }));
  if (REMOTE_TERMINAL_COMMAND_STATES.has(next.state)) {
    settleRemoteRetry(retryScope, { ...next, ...(questionToken ? { questionToken } : {}) });
  }
  interactionStatus = `Command ${next.state}.`;
  renderRemoteMode();
});
globalThis.addEventListener("gate:remote-connection", (event) => {
  const next = validateRemoteConnection(event.detail);
  if (!next || remoteConnection && Date.parse(next.at) < Date.parse(remoteConnection.at)) return;
  remoteConnection = next;
  renderRemoteMode();
  void reconcileRemoteRetries();
});
globalThis.addEventListener("gate:remote-revoked", () => {
  remoteState = undefined;
  remoteFleet = undefined;
  remoteActivity = [];
  remoteCommands.clear();
  acknowledgedQuestions.clear();
  nativeSelections.clear();
  interactionStatus = "";
  pendingMessageRequest = undefined;
  pendingQuestionRequests.clear();
  elements.messageInput.value = "";
  renderRemoteMode();
});
elements.messageInput.addEventListener("input", () => {
  interactionStatus = "";
  const validation = validateComposerMessage(elements.messageInput.value);
  if (!validation.valid || pendingMessageRequest?.message !== validation.message) pendingMessageRequest = undefined;
  updateComposer();
});
elements.messageComposer.addEventListener("submit", submitMessage);
elements.pilotCaseSelect.addEventListener("change", () => {
  selectedPilotAlias = elements.pilotCaseSelect.value || null;
  const selected = transport();
  const fleet = selected.kind === "remote" || (selected.kind === "none" && remoteConnection) ? remoteFleet : localFleet;
  selectedPilotEpoch = selectedPilotAlias === null ? null : fleet?.selectionEpoch || null;
  writePilotSelection(selectedPilotAlias, selectedPilotEpoch);
  renderPilot(fleet);
});
