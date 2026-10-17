import {
  hasAvailableFleetMetric,
  readPublicSnapshotResponse,
  toDisplayModel,
  validateBridgeReceipt,
  validateLocalBridge,
  validateLocalActivityEvent,
  validateLocalCompanionState,
  validateLocalFleet,
  validateOperatorMessage
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
  messageStatus: byId("message-status")
};

let latestGeneratedAt;
let currentDisplay;
let submitting = false;
let localState;
let localFleet;
let localTransportConnected = null;
let localActivity = [];
let questionReceiptStatus = "";
let messageReceiptStatus = "";
const acknowledgedQuestions = new Set();
const nativeSelections = new Map();

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

function exactBridge() {
  return validateLocalBridge(globalThis.GATE_PUBLIC_COCKPIT_BRIDGE);
}

function localReady() {
  return Boolean(exactBridge() && localState?.connected === true && localTransportConnected !== false);
}

function requestId() {
  return `req_${globalThis.crypto.randomUUID()}`;
}

function setMode(mode) {
  clear(elements.modeBanner);
  if (mode === "preview") {
    elements.modeBanner.className = "mode-banner mode-preview";
    elements.modeBanner.append(node("strong", "", "PREVIEW · NOT LIVE"), node("span", "", "Example data. Open the private local companion to steer Codex."));
  } else if (mode === "local") {
    elements.modeBanner.className = "mode-banner mode-local";
    elements.modeBanner.append(node("strong", "", "LIVE · PRIVATE"), node("span", "", "Local companion connected."));
  } else {
    elements.modeBanner.className = "mode-banner mode-unavailable";
    elements.modeBanner.append(node("strong", "", "SNAPSHOT UNAVAILABLE"), node("span", "", "No operational state is being shown."));
  }
}

function renderBridgeState(connected, mode = currentDisplay?.mode) {
  elements.connectionState.className = `connection-state ${connected ? "connected" : "unavailable"}`;
  clear(elements.connectionState);
  const label = connected ? "Connected" : mode === "preview" ? "Preview · interaction off" : "Companion unavailable";
  elements.connectionState.append(node("i", ""), document.createTextNode(label));
}

function renderUnavailable() {
  currentDisplay = undefined;
  elements.decisionPanel.hidden = false;
  setMode("unavailable");
  elements.siteVersion.textContent = "v—";
  elements.gateVersion.textContent = "v—";
  elements.runningMetricLabel.textContent = "RUNNING";
  elements.runningCount.textContent = "—";
  elements.runningSummary.textContent = "Work unavailable";
  elements.tokenMetricLabel.textContent = "TOKENS";
  elements.tokenUsage.textContent = "—";
  elements.tokenSummary.textContent = "Telemetry unavailable";
  elements.blockerCount.textContent = "—";
  elements.blockerSummary.textContent = "Status unavailable";
  elements.questionMetricLabel.textContent = "NEEDS YOU";
  elements.questionCount.textContent = "—";
  elements.questionSummary.textContent = "Queue unavailable";

  clear(elements.campaignList);
  const empty = node("div", "empty-state");
  empty.append(node("span", "", "—"), node("p", "", "No valid public snapshot is available."));
  elements.campaignList.append(empty);
  clear(elements.conversation);
  elements.conversation.append(node("div", "conversation-empty", "Decision state withheld until a valid snapshot arrives."));
  clear(elements.choiceList);
  elements.messageInput.disabled = true;
  elements.messageSend.disabled = true;
  updateComposer();
  elements.messageStatus.textContent = "Composer unavailable without the private local companion.";
  renderBridgeState(false);
  clear(elements.activityFeed);
  const line = node("li", "activity-row muted");
  line.append(node("time", "", "--:--"), node("span", "", "Activity withheld until a valid snapshot arrives"));
  elements.activityFeed.append(line);
  if (localReady()) renderLocalMode();
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
  const enabled = Boolean(bridge) && localReady();
  elements.messageInput.disabled = !enabled;
  elements.messageInput.placeholder = enabled ? "Write a short message…" : "Local companion required";
  elements.messageStatus.textContent = enabled
    ? messageReceiptStatus || "Ready."
    : model.mode === "preview" ? "Available in the private local companion." : "Companion unavailable.";
  updateComposer();
}

function updateComposer() {
  const validation = validateOperatorMessage(elements.messageInput.value);
  elements.messageCount.textContent = `${[...elements.messageInput.value].length} / 1000`;
  elements.messageSend.disabled = elements.messageInput.disabled || submitting || !validation.valid;
}

async function submitMessage(event) {
  event.preventDefault();
  const bridge = exactBridge();
  const validation = validateOperatorMessage(elements.messageInput.value);
  if (!bridge || !validation.valid || submitting) return;
  const sessionRevision = localState?.sessionRevision;
  const id = requestId();
  submitting = true;
  messageReceiptStatus = "";
  updateComposer();
  elements.messageStatus.textContent = "Requesting local companion acceptance…";
  try {
    const receipt = await bridge.submitMessage(Object.freeze({
      apiVersion: "gate.local-message-request/v1",
      requestId: id,
      sessionRevision,
      message: validation.message
    }));
    if (!validateBridgeReceipt(receipt, id) || localState?.sessionRevision !== sessionRevision || !localReady()) throw new Error("invalid receipt");
    elements.messageInput.value = "";
    messageReceiptStatus = "Local companion accepted the message. Delivery to Codex is not confirmed here.";
    elements.messageStatus.textContent = messageReceiptStatus;
  } catch {
    messageReceiptStatus = "No valid local receipt was received. Your message remains in the composer.";
    elements.messageStatus.textContent = messageReceiptStatus;
  } finally {
    submitting = false;
    updateComposer();
  }
}

function localTime(value) {
  const reference = Date.parse(localState?.observedAt || new Date().toISOString());
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
  const bridge = exactBridge();
  if (!bridge || !localReady() || submitting || acknowledgedQuestions.has(pending.token)) return;
  const sessionRevision = localState.sessionRevision;
  const id = requestId();
  const answers = { ...selectionsFor(pending) };
  submitting = true;
  renderLocalMode();
  elements.messageStatus.textContent = "Sending choices…";
  try {
    const receipt = await bridge.submitQuestion(Object.freeze({
      apiVersion: "gate.local-question-response/v1",
      requestId: id,
      sessionRevision,
      questionToken: pending.token,
      answers: Object.freeze(answers)
    }));
    if (!validateBridgeReceipt(receipt, id) || localState?.sessionRevision !== sessionRevision) throw new Error("invalid receipt");
    acknowledgedQuestions.add(pending.token);
    questionReceiptStatus = "Local companion accepted the choices. Codex will continue in the dedicated thread.";
  } catch {
    questionReceiptStatus = "No valid local receipt was received. Your choices remain selected.";
  } finally {
    submitting = false;
    renderLocalMode();
  }
}

function renderNativeQuestions(pending, bridge) {
  const selections = selectionsFor(pending);
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
      button.disabled = !bridge || submitting || acknowledgedQuestions.has(pending.token);
      button.setAttribute("aria-pressed", String(selected));
      button.append(node("span", "", option.label), node("small", "", option.description));
      button.addEventListener("click", () => {
        selections[question.id] = option.label;
        renderLocalMode();
      });
      choices.append(button);
    }
    group.append(heading, choices);
    elements.choiceList.append(group);
  }
  const submit = node("button", "native-submit", acknowledgedQuestions.has(pending.token) ? "Accepted locally" : "Continue with selected answers");
  submit.type = "button";
  submit.disabled = !bridge || submitting || acknowledgedQuestions.has(pending.token);
  submit.addEventListener("click", () => submitNativeQuestion(pending));
  elements.choiceList.append(submit);
}

function renderLocalConversation() {
  clear(elements.conversation);
  clear(elements.choiceList);
  const entries = localState.conversation.slice(-12);
  if (entries.length === 0) {
    elements.conversation.append(node("div", "conversation-empty", localState.turn === "working" ? "Codex is working…" : "Send a short message to start the dedicated Codex session."));
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
  const pending = localState.pendingQuestions.find((item) => !acknowledgedQuestions.has(item.token));
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
    node("span", "activity-count", determinate ? `${entry.completed} / ${entry.total}` : "—"),
    node("span", "activity-result", result),
    progress
  );
  return line;
}

function fleetMetricText(value) {
  if (!value || value.precision === "unavailable" || value.value === null) return "—";
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
  stage.append(node("small", "", campaign.kind === "profile" ? "PROFILE" : "CURRENT LANE"), node("strong", "", fleetStageLabel(campaign.stage)));
  stageRow.append(stage, node("strong", "progress-number", campaign.progress?.percent === null || campaign.progress === null ? "—" : `${campaign.progress.percent}%`));
  const track = node("div", `progress-track${campaign.progress === null ? " local-session-progress indeterminate" : ""}`);
  track.setAttribute("role", "progressbar");
  track.setAttribute("aria-label", `${campaign.alias} progress`);
  const fill = node("span", "progress-fill");
  if (campaign.progress === null || campaign.progress.percent === null) {
    track.setAttribute("aria-valuetext", campaign.kind === "case" ? "In progress; completion percentage unavailable" : "No percentage available");
  } else {
    track.setAttribute("aria-valuemin", "0");
    track.setAttribute("aria-valuemax", "100");
    track.setAttribute("aria-valuenow", String(campaign.progress.percent));
    fill.style.setProperty("--progress", `${campaign.progress.percent}%`);
  }
  track.append(fill);
  const footer = node("footer", "campaign-card-footer");
  const attention = node("span", `attention attention-${campaign.attention}`);
  attention.append(node("i", ""), node("span", "", campaign.attention === "response-needed" ? "Response needed" : campaign.attention === "watch" ? "Watch" : "Steady"));
  const state = node("span", `codex-state codex-${campaign.state === "running" ? "working" : campaign.state === "waiting" ? "waiting" : "idle"}`);
  state.append(node("i", ""), node("span", "", campaign.state.replace("-", " ")));
  footer.append(attention, state);
  article.append(header, stageRow, track, node("p", "campaign-action", fleetWorkSummary(campaign)), footer);
  return article;
}

function renderLocalMode() {
  if (!localReady()) return;
  const fleetConnected = localFleet?.connection === "connected";
  const fleetSummary = localFleet?.summary;
  setMode("local");
  elements.decisionPanel.hidden = false;
  elements.runningMetricLabel.textContent = "RUNNING";
  elements.runningCount.textContent = fleetMetricText(fleetSummary?.activeWorkflows);
  elements.runningSummary.textContent = fleetConnected
    ? `${fleetMetricText(fleetSummary.runningExecutions)} runs · ${fleetMetricText(fleetSummary.runningAnalyses)} analyses`
    : localState.turn === "working" ? "Codex active · fleet unavailable" : "Fleet unavailable";
  const campaignTokens = fleetSummary?.campaignTokens;
  if (fleetConnected && campaignTokens?.availability !== "unavailable") {
    elements.tokenMetricLabel.textContent = "TOKENS";
    elements.tokenUsage.textContent = `${compactNumber(campaignTokens.total)}${campaignTokens.availability === "partial" ? "+" : ""}`;
    elements.tokenSummary.textContent = localState.tokens
      ? `${campaignTokens.availability} fleet · ${compactNumber(localState.tokens.total)} session`
      : `${campaignTokens.availability} fleet attribution`;
  } else if (localState.tokens) {
    elements.tokenMetricLabel.textContent = "TOKENS";
    elements.tokenUsage.textContent = compactNumber(localState.tokens.total);
    elements.tokenSummary.textContent = "Exact dedicated session";
  } else {
    elements.tokenMetricLabel.textContent = "TOKENS";
    elements.tokenUsage.textContent = "—";
    elements.tokenSummary.textContent = "Telemetry unavailable";
  }
  elements.blockerCount.textContent = fleetMetricText(fleetSummary?.setupBlockers);
  elements.blockerSummary.textContent = fleetConnected ? "Profile setup blockers" : "Status unavailable";
  const pendingCount = localState.pendingQuestions.reduce((total, pending) => total + pending.questions.length, 0);
  const attentionMetric = fleetSummary?.attention;
  const attentionKnown = hasAvailableFleetMetric(attentionMetric);
  elements.questionMetricLabel.textContent = "NEEDS YOU";
  elements.questionCount.textContent = attentionKnown
    ? `${compactNumber(pendingCount + attentionMetric.value)}${attentionMetric.precision === "lower-bound" ? "+" : ""}`
    : pendingCount > 0 ? `${compactNumber(pendingCount)}+` : "—";
  elements.questionSummary.textContent = attentionKnown
    ? `${pendingCount} question${pendingCount === 1 ? "" : "s"} · ${fleetMetricText(attentionMetric)} fleet alert${attentionMetric.value === 1 ? "" : "s"}`
    : `${pendingCount} question${pendingCount === 1 ? "" : "s"} · fleet status unavailable`;

  clear(elements.campaignList);
  if (fleetConnected && localFleet.campaigns.length > 0) {
    localFleet.campaigns.forEach((campaign) => elements.campaignList.append(localFleetCampaignCard(campaign)));
  } else {
    const empty = node("div", "empty-state");
    empty.append(node("p", "", fleetConnected
      ? localFleet.coverage.state === "exact" ? "No active projects." : "No projects in the current partial view."
      : "Fleet signal unavailable."));
    elements.campaignList.append(empty);
  }

  renderLocalConversation();
  renderBridgeState(true, "local");
  configureComposer(currentDisplay || { mode: "preview" }, exactBridge());
  if (questionReceiptStatus) elements.messageStatus.textContent = questionReceiptStatus;
  clear(elements.activityFeed);
  const events = [...localActivity].sort((left, right) => right.sequence - left.sequence).slice(0, 24);
  if (events.length === 0) {
    const line = node("li", "activity-row muted");
    line.append(node("time", "", "now"), node("span", "", localState.turn === "working" ? "Codex is starting…" : "No local activity yet"));
    elements.activityFeed.append(line);
  } else {
    events.forEach((entry, index) => elements.activityFeed.append(localActivityLine(entry, index === 0)));
  }
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
    elements.tokenUsage.textContent = "—";
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
globalThis.addEventListener("gate:companion-snapshot", refresh);
globalThis.addEventListener("gate:companion-private-state", (event) => {
  const next = validateLocalCompanionState(event.detail);
  if (!next) return;
  if (localState?.sessionRevision === next.sessionRevision && next.stateRevision < localState.stateRevision) return;
  if (localState && localState.sessionRevision !== next.sessionRevision) {
    localActivity = [];
    acknowledgedQuestions.clear();
    nativeSelections.clear();
    questionReceiptStatus = "";
    messageReceiptStatus = "";
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
elements.messageInput.addEventListener("input", () => {
  messageReceiptStatus = "";
  updateComposer();
});
elements.messageComposer.addEventListener("submit", submitMessage);
