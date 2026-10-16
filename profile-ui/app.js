import { isoFromUtcInput, utcDisplayFromIso, utcInputFromIso } from "./time.js";
import {
  bindFieldLabel,
  focusAfterRepeatedItemRemoval,
  focusLastRepeatedControl,
  renderQuestionAndFocus
} from "./accessibility.js";

const $ = (selector) => globalThis.document?.querySelector(selector);

const elements = {
  profileTitle: $("#profile-title"),
  profileStatus: $("#profile-status"),
  profileRevision: $("#profile-revision"),
  progressLabel: $("#progress-label"),
  progressPercent: $("#progress-percent"),
  progressBar: $("#progress-bar"),
  sectionNav: $("#section-nav"),
  recommendationCount: $("#recommendation-count"),
  recommendAll: $("#recommend-all"),
  questionSection: $("#question-section"),
  questionPosition: $("#question-position"),
  questionCard: $("#question-card"),
  questionFlags: $("#question-flags"),
  questionTitle: $("#question-title"),
  questionWhy: $("#question-why"),
  sourceReview: $("#source-review"),
  answerForm: $("#answer-form"),
  answerControl: $("#answer-control"),
  answerError: $("#answer-error"),
  previousQuestion: $("#previous-question"),
  nextQuestion: $("#next-question"),
  backButton: $("#back-button"),
  leaveUnresolved: $("#leave-unresolved"),
  useRecommendation: $("#use-recommendation"),
  saveContinue: $("#save-continue"),
  recommendationTitle: $("#recommendation-title"),
  recommendationSummary: $("#recommendation-summary"),
  recommendationValue: $("#recommendation-value"),
  recommendationBasis: $("#recommendation-basis"),
  answerState: $("#answer-state"),
  saveState: $("#save-state"),
  toast: $("#toast")
};

const STRING_LIST_QUESTIONS = new Set([
  "identity-deliverables", "identity-success-criteria", "architecture-unknowns", "data-redaction-rules",
  "stops-cleanup-steps", "reporting-required-sections"
]);

const SOURCE_REF_QUESTIONS = new Set([
  "authority-source-refs", "limits-source-refs", "architecture-source-refs", "data-source-refs",
  "stops-cleanup-source-refs", "reporting-source-refs"
]);

const OBJECT_LIST_SHAPES = {
  "actions-techniques": [
    ["id", "ID", "text"], ["name", "Technique name", "text"], ["action", "Action", "action"],
    ["disposition", "Disposition", "disposition"], ["claimState", "Claim state", "claimState"],
    ["rationale", "Rationale", "textarea", true], ["conditions", "Conditions (one per line)", "lines", true],
    ["sourceRefs", "Source IDs (one per line)", "lines", true]
  ],
  "execution-phase-policies": [
    ["id", "Policy ID", "text"], ["phaseId", "Workflow phase ID", "text"],
    ["assetRefs", "Asset IDs (one per line)", "lines", true], ["actions", "Actions (one per line)", "lines", true],
    ["allowedToolIds", "Allowed tool IDs", "lines"], ["deniedToolIds", "Denied tool IDs", "lines"],
    ["conditions", "Conditions", "lines", true], ["claimState", "Claim state", "claimState"],
    ["sourceRefs", "Source IDs", "lines", true]
  ],
  "accounts-personas": [
    ["id", "Account ID", "text"], ["persona", "Persona", "text"], ["role", "Role", "text"],
    ["environment", "Environment", "text"], ["secretRefs", "Secret references", "lines", true],
    ["sourceRefs", "Source IDs", "lines", true]
  ],
  "architecture-components": [
    ["id", "Component ID", "text"], ["name", "Name", "text"], ["type", "Type", "text"],
    ["claimState", "Claim state", "claimState"], ["sourceRefs", "Source IDs", "lines", true]
  ],
  "architecture-trust-boundaries": [
    ["id", "Boundary ID", "text"], ["from", "From component ID", "text"], ["to", "To component ID", "text"],
    ["description", "Description", "textarea", true], ["claimState", "Claim state", "claimState"],
    ["sourceRefs", "Source IDs", "lines", true]
  ],
  "architecture-data-flows": [
    ["id", "Flow ID", "text"], ["from", "From component ID", "text"], ["to", "To component ID", "text"],
    ["dataClassification", "Data classification", "classification"], ["description", "Description", "textarea", true],
    ["claimState", "Claim state", "claimState"], ["sourceRefs", "Source IDs", "lines", true]
  ],
  "ambiguities-items": [
    ["id", "Ambiguity ID", "text"], ["question", "Question to resolve", "textarea", true],
    ["status", "Status", "ambiguityStatus"], ["resolution", "Resolution", "textarea", true],
    ["sourceRefs", "Source IDs", "lines", true]
  ]
};

let credentials = null;
let state = null;
let questions = [];
let currentQuestionId = null;
let activeCollector = null;
let busy = false;
let toastTimer = null;

class FormError extends Error {}

function node(tag, options = {}, children = []) {
  const result = document.createElement(tag);
  if (options.className) result.className = options.className;
  if (options.text !== undefined) result.textContent = String(options.text);
  for (const [name, value] of Object.entries(options.attrs || {})) {
    if (value !== undefined && value !== null) result.setAttribute(name, String(value));
  }
  for (const child of Array.isArray(children) ? children : [children]) {
    if (child !== null && child !== undefined) result.append(child);
  }
  return result;
}

function replaceChildren(parent, ...children) {
  parent.replaceChildren(...children.filter((child) => child !== null && child !== undefined));
}

function getCredentials() {
  const fragment = new URLSearchParams(location.hash.slice(1));
  const session = fragment.get("session") || sessionStorage.getItem("gate.profile.session");
  const csrf = fragment.get("csrf") || sessionStorage.getItem("gate.profile.csrf");
  if (fragment.has("session") && fragment.has("csrf")) {
    sessionStorage.setItem("gate.profile.session", session);
    sessionStorage.setItem("gate.profile.csrf", csrf);
    history.replaceState(null, "", `${location.pathname}${location.search}`);
  }
  return session && csrf ? { session, csrf } : null;
}

async function api(path, body) {
  const headers = { "X-GATE-Session": credentials.session };
  const options = { method: body === undefined ? "GET" : "POST", headers, cache: "no-store" };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    headers["X-GATE-CSRF"] = credentials.csrf;
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  const payload = await response.json();
  if (!response.ok || payload.ok !== true) {
    const error = new Error(payload?.error?.message || "The local profile form could not complete that action.");
    error.code = payload?.error?.code;
    error.status = response.status;
    error.fields = Array.isArray(payload?.error?.fields) ? payload.error.fields : [];
    throw error;
  }
  return payload.state;
}

function setBusy(value, label = value ? "Saving…" : "Saved locally") {
  busy = value;
  elements.saveState.textContent = label;
  for (const button of [elements.previousQuestion, elements.nextQuestion, elements.backButton,
    elements.leaveUnresolved, elements.useRecommendation, elements.saveContinue, elements.recommendAll]) {
    button.disabled = value;
  }
  elements.questionCard.setAttribute("aria-busy", String(value));
}

function showToast(message, type = "success") {
  clearTimeout(toastTimer);
  elements.toast.textContent = message;
  elements.toast.className = `toast${type === "error" ? " error" : ""}`;
  elements.toast.hidden = false;
  toastTimer = setTimeout(() => { elements.toast.hidden = true; }, 4200);
}

function friendlyFieldPath(value) {
  return String(value).replace(/^\//u, "").split(/[./]/u).filter(Boolean).map((part) => {
    if (/^\d+$/u.test(part)) return `Item ${Number(part) + 1}`;
    return titleCase(part.replace(/([a-z])([A-Z])/gu, "$1-$2"));
  }).join(" › ");
}

function showError(message, fields = []) {
  const details = fields
    .filter((field) => typeof field?.path === "string" && typeof field?.message === "string")
    .slice(0, 8)
    .map((field) => `${friendlyFieldPath(field.path)}: ${field.message}`);
  elements.answerError.textContent = [message, ...details].join("\n");
  elements.answerError.hidden = false;
  elements.answerError.focus?.();
}

function clearError() {
  elements.answerError.textContent = "";
  elements.answerError.hidden = true;
}

function titleCase(value) {
  return String(value).split(/[-_]/u).map((word) => word ? word[0].toUpperCase() + word.slice(1) : "").join(" ");
}

function summaryValue(value) {
  if (value === null) return "No value supplied";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "string" || typeof value === "number") return String(value);
  if (Array.isArray(value)) return value.length ? value.map((item) => typeof item === "string" ? item : "Structured item").join(" · ") : "Empty list";
  return "Structured answer prepared";
}

function applicableQuestions() {
  return state.sections.flatMap((section) => section.questions.filter((question) => question.applicable)
    .map((question) => ({ ...question, sectionTitle: section.title, sectionKey: section.id })));
}

function currentQuestion() {
  return questions.find((question) => question.id === currentQuestionId) || questions[0];
}

function goToQuestion(id, focus = true) {
  if (!questions.some((question) => question.id === id)) return;
  currentQuestionId = id;
  renderQuestion();
  renderSectionNav();
  if (focus) elements.questionTitle.focus?.();
}

function moveQuestion(offset) {
  const index = questions.findIndex((question) => question.id === currentQuestionId);
  const next = Math.max(0, Math.min(questions.length - 1, index + offset));
  if (questions[next]) goToQuestion(questions[next].id);
}

function renderHeader() {
  elements.profileTitle.textContent = state.profile.title;
  elements.profileStatus.textContent = titleCase(state.profile.status);
  elements.profileRevision.textContent = `Revision ${state.profile.revision}`;
  elements.progressLabel.textContent = `${state.progress.answered} of ${state.progress.total} answered`;
  const percent = state.progress.total ? Math.round((state.progress.answered / state.progress.total) * 100) : 0;
  elements.progressPercent.textContent = `${percent}%`;
  elements.progressBar.style.width = `${percent}%`;
  elements.recommendationCount.textContent = state.recommendationCount
    ? `${state.recommendationCount} unanswered question${state.recommendationCount === 1 ? "" : "s"} can use a reviewed recommendation.`
    : "No unanswered reviewed recommendations are available right now.";
  elements.recommendAll.disabled = busy || state.recommendationCount === 0;
}

function renderSectionNav() {
  const active = currentQuestion();
  const applicableSections = state.sections.filter((section) => section.applicable && section.progress.total > 0);
  replaceChildren(elements.sectionNav, ...applicableSections.map((section, index) => {
    const first = section.questions.find((question) => question.applicable);
    const button = node("button", {
      className: `section-link${section.progress.answered === section.progress.total ? " complete" : ""}`,
      attrs: { type: "button", "aria-current": active?.sectionKey === section.id ? "step" : undefined }
    }, [
      node("span", { className: "section-number", text: section.progress.answered === section.progress.total ? "✓" : index + 1 }),
      node("span", { className: "section-name", text: section.title }),
      node("span", { className: "section-count", text: `${section.progress.answered}/${section.progress.total}` })
    ]);
    button.addEventListener("click", () => first && goToQuestion(first.id));
    return button;
  }));
}

function flag(text, className = "") {
  return node("span", { className: `flag ${className}`.trim(), text });
}

function field(label, input, options = {}) {
  const wrapper = node("div", { className: `field${options.wide ? " wide" : ""}` });
  if (input.tagName === "FIELDSET") {
    const legend = input.querySelector("legend") || node("legend");
    legend.textContent = label;
    legend.className = "field-label";
    if (!legend.parentElement) input.prepend(legend);
    wrapper.append(input);
  } else {
    const labelNode = node("label", { text: label });
    if (!bindFieldLabel(labelNode, input)) throw new Error("field requires a labelable control");
    wrapper.append(labelNode, input);
  }
  if (options.help) wrapper.append(node("p", { className: "field-help", text: options.help }));
  return wrapper;
}

function textInput(value = "", options = {}) {
  const input = node(options.multiline ? "textarea" : "input", {
    attrs: options.multiline ? { placeholder: options.placeholder || "" } : {
      type: options.type || "text",
      value: value ?? "",
      placeholder: options.placeholder || "",
      step: options.step
    }
  });
  if (options.multiline) input.value = value ?? "";
  return input;
}

function choiceControl(name, choices, selected, multiple = false, legend = "Available choices") {
  const root = node("fieldset", { className: `choice-grid${multiple ? " checkbox-grid" : ""}` });
  root.append(node("legend", { className: "sr-only", text: legend }));
  for (const choice of choices) {
    const id = `${name}-${String(choice).replace(/[^a-z0-9]/giu, "-")}`;
    const input = node("input", {
      attrs: {
        type: multiple ? "checkbox" : "radio",
        id,
        name,
        value: choice
      }
    });
    input.checked = multiple ? (selected || []).includes(choice) : selected === choice;
    root.append(node("div", { className: "choice-card" }, [input, node("label", { text: titleCase(choice), attrs: { for: id } })]));
  }
  return root;
}

function optionalControl(question, input, reader) {
  if (!question.allowNull) return { root: input, read: reader };
  const wrapper = node("div");
  input.dataset.fieldControl = "primary";
  const nullId = `null-${question.id}`;
  const toggle = node("input", { attrs: { type: "checkbox", id: nullId } });
  toggle.checked = question.value === null;
  const row = node("label", { className: "advanced-toggle", attrs: { for: nullId } }, [toggle, node("span", { text: "No value is supplied by the source" })]);
  const setDisabled = () => { input.disabled = toggle.checked; };
  toggle.addEventListener("change", setDisabled);
  setDisabled();
  wrapper.append(input, row);
  return { root: wrapper, read: () => toggle.checked ? null : reader() };
}

function advancedFallback(root, initialValue, guidedReader) {
  const details = node("details", { className: "advanced-editor" });
  const textarea = textInput(JSON.stringify(initialValue ?? null, null, 2), { multiline: true });
  const checkbox = node("input", { attrs: { type: "checkbox", id: `advanced-${crypto.randomUUID()}` } });
  details.append(
    node("summary", { text: "Advanced JSON fallback" }),
    node("p", { className: "field-help", text: "Use only when the guided fields cannot represent a program-specific structure." }),
    field("Advanced JSON value", textarea),
    node("label", { className: "advanced-toggle", attrs: { for: checkbox.id } }, [checkbox, node("span", { text: "Use this advanced JSON value" })])
  );
  root.append(details);
  return () => {
    if (!checkbox.checked) return guidedReader();
    try { return JSON.parse(textarea.value); } catch { throw new FormError("The advanced JSON value is not valid JSON."); }
  };
}

function renderScalar(question) {
  const value = question.value;
  if (question.type === "boolean") {
    const root = choiceControl(question.id, [true, false], value, false, question.prompt);
    return { root, read: () => {
      const checked = root.querySelector("input:checked");
      if (!checked) throw new FormError("Choose Yes or No, or leave this question unresolved.");
      return checked.value === "true";
    } };
  }
  if (question.type === "enum") {
    const root = choiceControl(question.id, question.choices, value, false, question.prompt);
    return { root, read: () => {
      const checked = root.querySelector("input:checked");
      if (!checked) throw new FormError("Choose one of the available options.");
      return checked.value;
    } };
  }
  if (question.type === "multi-enum") {
    const root = choiceControl(question.id, question.choices, value || [], true, question.prompt);
    return { root, read: () => [...root.querySelectorAll("input:checked")].map((input) => input.value) };
  }
  const isMultiline = question.type === "multiline";
  let shown = value ?? "";
  let type = "text";
  let step;
  if (question.type === "datetime") {
    type = "datetime-local";
    step = "0.001";
    shown = utcInputFromIso(value);
  } else if (question.type === "integer" || question.type === "number") {
    type = "number";
    step = question.type === "integer" ? "1" : "any";
  }
  const input = textInput(shown, { multiline: isMultiline, type, step });
  const optional = optionalControl(question, input, () => {
    const raw = input.value.trim();
    if (!raw) throw new FormError("Enter an answer, or leave this question unresolved.");
    if (question.type === "datetime") {
      try {
        return isoFromUtcInput(input.value);
      } catch (error) {
        throw new FormError(error.message);
      }
    }
    if (question.type === "integer") {
      const parsed = Number(raw);
      if (!Number.isSafeInteger(parsed)) throw new FormError("Enter a whole number.");
      return parsed;
    }
    if (question.type === "number") {
      const parsed = Number(raw);
      if (!Number.isFinite(parsed)) throw new FormError("Enter a valid number.");
      return parsed;
    }
    return raw;
  });
  return {
    root: field(
      question.type === "multiline" ? "Your answer" : question.type === "datetime" ? "UTC date and time" : "Answer",
      optional.root,
      question.type === "datetime" ? { help: "Displayed and stored in UTC. The value will not shift with your laptop timezone." } : {}
    ),
    read: optional.read
  };
}

function lines(value) {
  return Array.isArray(value) ? value.join("\n") : "";
}

function readLines(value) {
  return value.split(/\r?\n/u).map((item) => item.trim()).filter(Boolean);
}

function renderStringList(question) {
  let values = Array.isArray(question.value) ? structuredClone(question.value) : [];
  const root = node("div", { className: "structured-list" });
  const list = node("div", { className: "structured-list" });
  const readGuided = () => [...list.querySelectorAll("input[data-list-item]")]
    .map((input) => input.value.trim());
  const paint = () => {
    replaceChildren(list, ...values.map((value, index) => {
      const input = textInput(value, { placeholder: "Add one clear item" });
      input.dataset.listItem = "true";
      input.id = `list-${question.id}-${index}`;
      const remove = node("button", { className: "remove-item", text: "Remove", attrs: { type: "button" } });
      remove.addEventListener("click", () => {
        values = readGuided();
        values.splice(index, 1);
        paint();
        focusAfterRepeatedItemRemoval(list, index, add);
      });
      return node("div", { className: "repeat-card" }, [
        node("div", { className: "repeat-card-header" }, [
          node("label", { className: "repeat-card-title", text: `Item ${index + 1}`, attrs: { for: input.id } }),
          remove
        ]),
        input
      ]);
    }));
  };
  paint();
  const add = node("button", { className: "button button-secondary add-item", text: "+ Add item", attrs: { type: "button" } });
  add.addEventListener("click", () => {
    values = readGuided();
    values.push("");
    paint();
    focusLastRepeatedControl(list);
  });
  root.append(list, add);
  return { root, read: advancedFallback(root, question.value || [], () => readGuided().filter(Boolean)) };
}

function contactCard(value, index, removeHandler, sources) {
  const card = node("div", { className: "repeat-card", attrs: { "data-contact": "true" } });
  const remove = node("button", { className: "remove-item", text: "Remove", attrs: { type: "button" } });
  remove.addEventListener("click", removeHandler);
  const name = textInput(value.name || "", { placeholder: "Program security team" });
  const role = textInput(value.role || "", { placeholder: "Authority and escalation contact" });
  const channel = textInput(value.channel || "", { placeholder: "Copy the exact published channel" });
  const purpose = textInput(value.purpose || "", { multiline: true, placeholder: "What this contact can clarify or stop" });
  const sourceRefs = node("fieldset", { className: "choice-grid checkbox-grid", attrs: { "data-key": "sourceRefs" } });
  sourceRefs.append(node("legend", { className: "sr-only", text: `Supporting sources for contact ${index + 1}` }));
  for (const source of sources) {
    const id = `contact-${index}-source-${source.id}`;
    const input = node("input", { attrs: { type: "checkbox", id, value: source.id, "data-source-ref": "true" } });
    input.checked = (value.sourceRefs || []).includes(source.id);
    sourceRefs.append(node("div", { className: "choice-card" }, [
      input,
      node("label", { text: source.title, attrs: { for: id, title: source.id } })
    ]));
  }
  name.dataset.key = "name"; role.dataset.key = "role"; channel.dataset.key = "channel";
  purpose.dataset.key = "purpose";
  card.append(
    node("div", { className: "repeat-card-header" }, [node("span", { className: "repeat-card-title", text: `Contact ${index + 1}` }), remove]),
    node("div", { className: "form-grid" }, [
      field("Name or team", name), field("Role", role),
      field("Published channel (exact)", channel, { wide: true, help: "Copy the program's exact platform inbox, email, or other published channel. GATE does not invent it." }),
      field("Purpose", purpose, { wide: true }),
      field("Supporting sources", sourceRefs, { wide: true, help: sources.length ? "Choose every local source that supports this contact." : "Add the source ledger first, or leave this contact unresolved." })
    ])
  );
  return card;
}

function renderContacts(question) {
  let values = Array.isArray(question.value) ? structuredClone(question.value) : [];
  const root = node("div");
  const quick = node("div", { className: "quick-actions" });
  const list = node("div", { className: "structured-list" });
  const collectContacts = (validate) => {
    let contacts = [...list.querySelectorAll("[data-contact]")].map((card) => ({
      name: card.querySelector('[data-key="name"]').value.trim(),
      role: card.querySelector('[data-key="role"]').value.trim(),
      channel: card.querySelector('[data-key="channel"]').value.trim(),
      purpose: card.querySelector('[data-key="purpose"]').value.trim(),
      sourceRefs: [...card.querySelectorAll('[data-key="sourceRefs"] input:checked')].map((input) => input.value)
    }));
    if (!validate) return contacts;
    contacts = contacts.filter((contact) => Object.values(contact).some((value) => Array.isArray(value) ? value.length : value));
    if (!contacts.length) throw new FormError("Add at least one contact, or choose Skip for now.");
    contacts.forEach((contact, index) => {
      for (const key of ["name", "role", "channel", "purpose"]) {
        if (!contact[key]) throw new FormError(`Contact ${index + 1}: ${key === "channel" ? "published channel" : titleCase(key)} is required.`);
      }
    });
    return contacts;
  };
  const readGuided = () => collectContacts(true);
  const paint = () => replaceChildren(list, ...values.map((value, index) => contactCard(value, index, () => {
    values = collectContacts(false);
    values.splice(index, 1);
    paint();
    focusAfterRepeatedItemRemoval(list, index, add);
  }, state.sources)));
  const addContact = (value = {}) => {
    values = collectContacts(false);
    values.push(value);
    paint();
    focusLastRepeatedControl(list);
  };
  const add = node("button", { className: "button button-secondary", text: "+ Add contact", attrs: { type: "button" } });
  add.addEventListener("click", () => addContact());
  const platform = node("button", { className: "button button-secondary", text: "Add platform contact", attrs: { type: "button" } });
  platform.addEventListener("click", () => addContact({
    name: "",
    role: "Program contact",
    channel: "",
    purpose: "Clarify authority, receive escalation, or stop the assessment.",
    sourceRefs: []
  }));
  quick.append(platform, add);
  paint();
  root.append(quick, list);
  return { root, read: advancedFallback(root, question.value || [], readGuided) };
}

function renderSourceRefs(question) {
  const selected = new Set(Array.isArray(question.value) ? question.value : []);
  const root = node("div");
  const choices = node("fieldset", { className: "choice-grid checkbox-grid" });
  choices.append(node("legend", { className: "sr-only", text: "Supporting sources" }));
  for (const source of state.sources) {
    const id = `${question.id}-${source.id}`;
    const input = node("input", { attrs: { type: "checkbox", id, value: source.id } });
    input.checked = selected.has(source.id);
    choices.append(node("div", { className: "choice-card" }, [
      input,
      node("label", { text: source.title, attrs: { for: id, title: `${source.id} · ${titleCase(source.type)}` } })
    ]));
  }
  root.append(
    state.sources.length
      ? choices
      : node("p", { className: "field-help", text: "No sources are in the local ledger yet. Complete the source-ledger question first." })
  );
  const readGuided = () => [...choices.querySelectorAll("input:checked")].map((input) => input.value);
  return { root, read: advancedFallback(root, question.value || [], readGuided) };
}

function renderSources(question) {
  let values = Array.isArray(question.value) ? structuredClone(question.value) : [];
  const root = node("div");
  const list = node("div", { className: "structured-list" });
  const types = ["operator-statement", "program-rules", "safe-harbor", "scope-list", "contract", "platform-page", "architecture", "account-instructions", "other"];
  const claims = state.semantics.claimStates;
  const collectSources = (validate) => [...list.querySelectorAll("[data-source]")].map((card) => {
    const observedAt = card.querySelector('[data-key="observedAt"]').value;
    return {
      id: card.querySelector('[data-key="id"]').value.trim(),
      type: card.querySelector('[data-key="type"]').value,
      title: card.querySelector('[data-key="title"]').value.trim(),
      reference: card.querySelector('[data-key="reference"]').value.trim(),
      contentSha256: card.querySelector('[data-key="contentSha256"]').value.trim() || null,
      observedAt: validate ? isoFromUtcInput(observedAt) : observedAt,
      claimState: card.querySelector('[data-key="claimState"]').value,
      notes: card.querySelector('[data-key="notes"]').value.trim() || null
    };
  });
  const readGuided = () => collectSources(true);
  const paint = () => replaceChildren(list, ...values.map((value, index) => {
    const card = node("div", { className: "repeat-card", attrs: { "data-source": "true" } });
    const remove = node("button", { className: "remove-item", text: "Remove", attrs: { type: "button" } });
    remove.addEventListener("click", () => {
      values = collectSources(false);
      values.splice(index, 1);
      paint();
      focusAfterRepeatedItemRemoval(list, index, add);
    });
    const controls = {};
    for (const [key, label, type] of [
      ["id", "Source ID", "text"], ["title", "Title", "text"], ["reference", "Canonical reference", "text"],
      ["contentSha256", "Content SHA-256 (when recorded)", "text"], ["observedAt", "Observed at", "datetime-local"],
      ["notes", "Short source note", "textarea"]
    ]) {
      let shown = value[key] || "";
      if (type === "datetime-local") shown = utcInputFromIso(shown) || shown;
      controls[key] = textInput(shown, {
        multiline: type === "textarea",
        type: type === "textarea" ? "text" : type,
        step: type === "datetime-local" ? "0.001" : undefined
      });
      controls[key].dataset.key = key;
    }
    controls.type = node("select", { attrs: { "data-key": "type" } }, types.map((type) => node("option", { text: titleCase(type), attrs: { value: type } })));
    controls.type.value = value.type || "program-rules";
    controls.claimState = node("select", { attrs: { "data-key": "claimState" } }, claims.map((claim) => node("option", { text: titleCase(claim), attrs: { value: claim } })));
    controls.claimState.value = value.claimState || "unverified";
    card.append(node("div", { className: "repeat-card-header" }, [node("span", { className: "repeat-card-title", text: `Source ${index + 1}` }), remove]),
      node("div", { className: "form-grid" }, [
        field("Source ID", controls.id), field("Source type", controls.type), field("Title", controls.title, { wide: true }),
        field("Canonical reference", controls.reference, { wide: true }), field("Content SHA-256", controls.contentSha256),
        field("Observed at (UTC)", controls.observedAt, { help: "This control always represents UTC." }),
        field("Claim state", controls.claimState), field("Short source note", controls.notes, { wide: true })
      ]));
    return card;
  }));
  paint();
  const add = node("button", { className: "button button-secondary add-item", text: "+ Add source", attrs: { type: "button" } });
  add.addEventListener("click", () => {
    values = collectSources(false);
    values.push({ type: "program-rules", claimState: "unverified", observedAt: new Date().toISOString() });
    paint();
    focusLastRepeatedControl(list);
  });
  root.append(list, add);
  return { root, read: advancedFallback(root, question.value || [], readGuided) };
}

function decisionFields(value = {}, includeAnswers = false) {
  const root = node("div", { className: "form-grid" });
  const disposition = node("select", {}, state.semantics.dispositions.map((item) => node("option", { text: titleCase(item), attrs: { value: item } })));
  disposition.value = value.disposition || "unknown";
  const claim = node("select", {}, state.semantics.claimStates.map((item) => node("option", { text: titleCase(item), attrs: { value: item } })));
  claim.value = value.claimState || "unverified";
  const rationale = textInput(value.rationale || "", { multiline: true });
  const conditions = textInput(lines(value.conditions), { multiline: true });
  const refs = textInput(lines(value.sourceRefs), { multiline: true });
  root.append(field("Disposition", disposition), field("Claim state", claim), field("Rationale", rationale, { wide: true }),
    field("Conditions", conditions, { wide: true, help: "One condition per line." }), field("Source IDs", refs, { wide: true, help: "One source ID per line." }));
  return {
    root,
    read: () => ({
      disposition: disposition.value,
      claimState: disposition.value === "unknown" ? "unverified" : claim.value,
      sourceRefs: readLines(refs.value),
      rationale: rationale.value.trim() || null,
      conditions: readLines(conditions.value),
      ...(includeAnswers ? { answers: value.answers && typeof value.answers === "object" ? value.answers : {} } : {})
    })
  };
}

function renderDecision(question) {
  const value = question.value && typeof question.value === "object" ? question.value : {};
  const guided = decisionFields(value, Boolean(question.moduleId));
  const root = node("div", {}, [guided.root]);
  return { root, read: advancedFallback(root, question.value || {}, guided.read) };
}

function renderMatrix(question, keys, kind) {
  const values = question.value && typeof question.value === "object" ? structuredClone(question.value) : {};
  const root = node("div");
  const matrix = node("div", { className: "matrix" });
  const readers = new Map();
  for (const key of keys) {
    const existing = values[key] || {};
    if (kind === "stop") {
      const response = textInput(existing.response || "Stop affected work, preserve evidence, and escalate to the operator.", { multiline: true });
      const claim = node("select", {}, state.semantics.claimStates.map((item) => node("option", { text: titleCase(item), attrs: { value: item } })));
      claim.value = existing.claimState || "unverified";
      const refs = textInput(lines(existing.sourceRefs), { multiline: true });
      const details = node("details", { className: "matrix-row" }, [
        node("summary", { className: "matrix-name", text: titleCase(key) }),
        field("Response", response), field("Claim state", claim), field("Source IDs", refs)
      ]);
      matrix.append(details);
      readers.set(key, () => ({ enabled: true, response: response.value.trim(), claimState: claim.value, sourceRefs: readLines(refs.value) }));
      continue;
    }
    const disposition = node("select", {}, state.semantics.dispositions.map((item) => node("option", { text: titleCase(item), attrs: { value: item } })));
    disposition.value = existing.disposition || "unknown";
    const claim = node("select", {}, state.semantics.claimStates.map((item) => node("option", { text: titleCase(item), attrs: { value: item } })));
    claim.value = existing.claimState || "unverified";
    const rationale = textInput(existing.rationale || "", { multiline: true });
    const conditions = textInput(lines(existing.conditions), { multiline: true });
    const refs = textInput(lines(existing.sourceRefs), { multiline: true });
    const row = node("div", { className: "matrix-row" }, [
      node("div", { className: "matrix-name", text: titleCase(key) }),
      field("Disposition", disposition), field("Claim state", claim)
    ]);
    const detail = node("details", { className: "advanced-editor" }, [
      node("summary", { text: "Rationale, conditions, and sources" }),
      field("Rationale", rationale), field("Conditions", conditions), field("Source IDs", refs)
    ]);
    const wrapper = node("div", {}, [row, detail]);
    matrix.append(wrapper);
    readers.set(key, () => ({
      disposition: disposition.value,
      claimState: disposition.value === "unknown" ? "unverified" : claim.value,
      sourceRefs: readLines(refs.value), rationale: rationale.value.trim() || null, conditions: readLines(conditions.value)
    }));
  }
  const readGuided = () => Object.fromEntries(keys.map((key) => [key, readers.get(key)()]));
  root.append(matrix);
  return { root, read: advancedFallback(root, question.value || {}, readGuided) };
}

function renderSchedule(question) {
  let values = Array.isArray(question.value) ? structuredClone(question.value) : [];
  const root = node("div");
  const list = node("div", { className: "structured-list" });
  const days = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"];
  const readGuided = () => [...list.querySelectorAll("[data-window]")].map((card) => ({
    days: [...card.querySelectorAll('input[type="checkbox"]:checked')].map((input) => input.value),
    start: card.querySelector('[data-key="start"]').value,
    end: card.querySelector('[data-key="end"]').value
  }));
  const paint = () => replaceChildren(list, ...values.map((value, index) => {
    const card = node("div", { className: "repeat-card", attrs: { "data-window": "true" } });
    const remove = node("button", { className: "remove-item", text: "Remove", attrs: { type: "button" } });
    remove.addEventListener("click", () => {
      values = readGuided();
      values.splice(index, 1);
      paint();
      focusAfterRepeatedItemRemoval(list, index, add);
    });
    const dayControl = choiceControl(`days-${index}`, days, value.days || [], true, `Days for window ${index + 1}`);
    const start = textInput(value.start || "09:00", { type: "time" }); start.dataset.key = "start";
    const end = textInput(value.end || "17:00", { type: "time" }); end.dataset.key = "end";
    card.append(node("div", { className: "repeat-card-header" }, [node("span", { className: "repeat-card-title", text: `Window ${index + 1}` }), remove]),
      node("p", { className: "field-label", text: "Days" }), dayControl,
      node("div", { className: "form-grid" }, [field("Start", start), field("End", end)]));
    return card;
  }));
  paint();
  const add = node("button", { className: "button button-secondary add-item", text: "+ Add testing window", attrs: { type: "button" } });
  add.addEventListener("click", () => {
    values = readGuided();
    values.push({ days: ["monday", "tuesday", "wednesday", "thursday", "friday"], start: "09:00", end: "17:00" });
    paint();
    focusLastRepeatedControl(list);
  });
  root.append(list, add);
  return { root, read: advancedFallback(root, question.value || [], readGuided) };
}

function valueAt(object, path) {
  return path.split(".").reduce((cursor, part) => cursor?.[part], object);
}

function setAt(object, path, value) {
  const parts = path.split(".");
  let cursor = object;
  for (const part of parts.slice(0, -1)) cursor = cursor[part] ||= {};
  cursor[parts.at(-1)] = value;
}

function renderLimits(value) {
  const root = node("fieldset", { className: "form-grid" });
  const readers = ["maxMinutes", "maxRequests", "maxParallel", "maxRatePerSecond", "maxTokens", "maxSpendUsd"].map((key) => {
    const input = textInput(value[key] ?? "", { type: "number", step: ["maxRatePerSecond", "maxSpendUsd"].includes(key) ? "any" : "1" });
    const noCeiling = node("input", { attrs: { type: "checkbox" } });
    noCeiling.checked = value[key] === null;
    root.append(field(key, input));
    if (key === "maxSpendUsd") root.append(field("No monetary ceiling supplied", noCeiling));
    return [key, () => {
      if (key === "maxSpendUsd" && noCeiling.checked) return null;
      if (!input.value.trim()) return undefined;
      const parsed = Number(input.value);
      if (!Number.isFinite(parsed)) throw new FormError(`Enter a valid ${key}.`);
      return parsed;
    }];
  });
  return { root, read: () => Object.fromEntries(readers.map(([key, read]) => [key, read()]).filter(([, value]) => value !== undefined)) };
}

function renderTypedValue(initial, allowedTypes = ["string", "number", "boolean", "null", "object", "array"], childTypes = allowedTypes) {
  const root = node("fieldset", { className: "structured-list" });
  const type = node("select", {}, allowedTypes.map((value) => node("option", { text: titleCase(value), attrs: { value } })));
  type.value = initial === null ? "null" : Array.isArray(initial) ? "array" : typeof initial;
  const body = node("div", { className: "structured-list" });
  let read;
  const paint = (value) => {
    replaceChildren(body);
    if (["object", "array"].includes(type.value)) {
      const isArray = type.value === "array";
      const entries = node("div", { className: "structured-list" });
      const rows = [];
      const addRow = (key, item) => {
        const row = node("div", { className: "repeat-card" });
        const name = textInput(key);
        const editor = renderTypedValue(item, childTypes);
        const remove = node("button", { text: "Remove", attrs: { type: "button" } });
        const record = { row, name, editor };
        rows.push(record);
        remove.addEventListener("click", () => { rows.splice(rows.indexOf(record), 1); row.remove(); });
        if (!isArray) row.append(field("Parameter or field name", name));
        row.append(editor.root, remove);
        entries.append(row);
      };
      for (const [key, item] of Object.entries(value || {})) addRow(key, item);
      const add = node("button", { text: isArray ? "+ Add item" : "+ Add field", attrs: { type: "button" } });
      add.addEventListener("click", () => addRow("", ""));
      body.append(entries, add);
      read = () => {
        if (isArray) return rows.map(({ editor }) => editor.read());
        const keys = rows.map(({ name }) => name.value.trim());
        if (keys.some((key) => !key) || new Set(keys).size !== keys.length) throw new FormError("Use unique nonempty field names.");
        return Object.fromEntries(rows.map(({ editor }, index) => [keys[index], editor.read()]));
      };
    } else {
      const input = textInput(value ?? "", { type: type.value === "number" ? "number" : "text", step: "any" });
      if (type.value === "boolean") { input.type = "checkbox"; input.checked = value === true; }
      if (type.value !== "null") body.append(field("Value", input));
      read = () => {
        if (type.value === "null") return null;
        if (type.value === "boolean") return input.checked;
        if (type.value === "number") {
          if (!input.value.trim() || !Number.isFinite(Number(input.value))) throw new FormError("Enter a valid number.");
          return Number(input.value);
        }
        return input.value;
      };
    }
  };
  type.addEventListener("change", () => paint(type.value === "object" ? {} : type.value === "array" ? [] : ""));
  root.append(field("Value type", type), body);
  paint(initial);
  return { root, read: () => read() };
}

function renderObjectList(question, shape) {
  let values = Array.isArray(question.value) ? structuredClone(question.value) : [];
  const root = node("div");
  const list = node("div", { className: "structured-list" });
  const choicesFor = (type) => ({
    action: state.semantics.actions,
    disposition: state.semantics.dispositions,
    claimState: state.semantics.claimStates,
    classification: ["public", "internal", "confidential", "restricted", "unknown"],
    ambiguityStatus: ["unresolved", "resolved"]
    ,selectorType: ["domain", "ip", "cidr", "url", "application", "account", "repository", "device", "path"]
  }[type]);
  const readGuided = () => [...list.querySelectorAll("[data-object-item]")].map((card) => {
    const result = structuredClone(values[[...list.children].indexOf(card)] || {});
    for (const [path, , type] of shape) {
      const control = card.querySelector(`[data-field-path="${path}"]`);
      let parsed = type === "lines" ? readLines(control.value) : control.value.trim();
      if (["rationale", "resolution"].includes(path) && parsed === "") parsed = null;
      setAt(result, path, parsed);
    }
    for (const [key, reader] of card.structuredReaders || []) result[key] = reader();
    if (question.id === "ambiguities-items") result.resolution ||= null;
    return result;
  });
  const paint = () => replaceChildren(list, ...values.map((value, index) => {
    const card = node("div", { className: "repeat-card", attrs: { "data-object-item": "true" } });
    const remove = node("button", { className: "remove-item", text: "Remove", attrs: { type: "button" } });
    remove.addEventListener("click", () => {
      values = readGuided();
      values.splice(index, 1);
      paint();
      focusAfterRepeatedItemRemoval(list, index, add);
    });
    const grid = node("div", { className: "form-grid" });
    for (const [fieldPath, label, type, wide] of shape) {
      const choices = choicesFor(type);
      let control;
      if (choices) {
        control = node("select", {}, choices.map((choice) => node("option", { text: titleCase(choice), attrs: { value: choice } })));
        control.value = valueAt(value, fieldPath) || choices[0];
      } else {
        control = textInput(type === "lines" ? lines(valueAt(value, fieldPath)) : valueAt(value, fieldPath) || "", { multiline: type === "textarea" || type === "lines" });
      }
      control.dataset.fieldPath = fieldPath;
      grid.append(field(label, control, { wide }));
    }
    card.structuredReaders = new Map();
    const attach = (key, label, editor) => {
      grid.append(field(label, editor.root, { wide: true }));
      card.structuredReaders.set(key, editor.read);
    };
    if (question.id === "actions-techniques") attach("parameters", "Technique parameters", renderTypedValue(value.parameters || {}, ["object"], ["string", "number", "boolean", "null"]));
    if (question.id === "execution-phase-policies") attach("limits", "Phase limits", renderLimits(value.limits || {}));
    if (question.id === "scope-assets") {
      attach("limitOverrides", "Asset limits", renderLimits(value.limitOverrides || {}));
      const root = node("fieldset");
      const readers = state.semantics.actions.map((action) => {
        const enabled = node("input", { attrs: { type: "checkbox" } });
        enabled.checked = Object.hasOwn(value.actionOverrides || {}, action);
        const decision = decisionFields(value.actionOverrides?.[action]);
        root.append(field(`Override ${action}`, enabled), decision.root);
        return [action, () => enabled.checked ? decision.read() : undefined];
      });
      attach("actionOverrides", "Asset action overrides", { root, read: () => Object.fromEntries(readers.map(([key, read]) => [key, read()]).filter(([, value]) => value !== undefined)) });
    }
    card.append(node("div", { className: "repeat-card-header" }, [node("span", { className: "repeat-card-title", text: `Item ${index + 1}` }), remove]), grid);
    return card;
  }));
  paint();
  const add = node("button", { className: "button button-secondary add-item", text: "+ Add item", attrs: { type: "button" } });
  add.addEventListener("click", () => {
    values = readGuided();
    values.push({});
    paint();
    focusLastRepeatedControl(list);
  });
  root.append(list, add);
  return { root, read: advancedFallback(root, question.value || [], readGuided) };
}

function renderGenericList(question) {
  if (SOURCE_REF_QUESTIONS.has(question.id)) return renderSourceRefs(question);
  if (STRING_LIST_QUESTIONS.has(question.id)) return renderStringList(question);
  if (question.moduleId) {
    const editor = renderTypedValue(question.value || []);
    return { root: editor.root, read: advancedFallback(editor.root, question.value || [], editor.read) };
  }
  const shape = OBJECT_LIST_SHAPES[question.id];
  if (shape) return renderObjectList(question, shape);
  const root = node("div", {}, [node("p", { className: "field-help", text: "This program-specific structure uses the advanced editor. GATE validates it before saving." })]);
  return { root, read: advancedFallback(root, question.value || [], () => question.value || []) };
}

function renderControl(question) {
  if (["text", "multiline", "boolean", "enum", "multi-enum", "integer", "number", "datetime"].includes(question.type)) return renderScalar(question);
  if (question.type === "contact-list") return renderContacts(question);
  if (question.type === "source-list") return renderSources(question);
  if (question.type === "schedule-windows") return renderSchedule(question);
  if (question.type === "decision") return renderDecision(question);
  if (question.type === "action-decisions") return renderMatrix(question, state.semantics.actions, "decision");
  if (question.type === "coverage-decisions") return renderMatrix(question, state.semantics.coverageDomains, "decision");
  if (question.type === "stop-responses") return renderMatrix(question, state.semantics.stopConditions, "stop");
  if (question.type === "selector-decisions") {
    return renderObjectList(question, [
      ["id", "Asset ID", "text"], ["selector.type", "Selector type", "selectorType"], ["selector.value", "Exact selector", "text", true],
      ["disposition", "Disposition", "disposition"], ["claimState", "Claim state", "claimState"],
      ["rationale", "Rationale", "textarea", true], ["conditions", "Conditions", "lines", true],
      ["sourceRefs", "Source IDs", "lines", true]
    ]);
  }
  if (question.type === "secret-ref-list") return renderStringList(question);
  return renderGenericList(question);
}

function renderSourceReview(question) {
  if (question.id !== "authority-operator-confirmed") {
    elements.sourceReview.hidden = true;
    replaceChildren(elements.sourceReview);
    return;
  }
  elements.sourceReview.hidden = false;
  const list = node("div", { className: "source-list" });
  if (state.authorizationSources.length) {
    for (const source of state.authorizationSources) {
      const observedAt = utcDisplayFromIso(source.observedAt);
      const freshness = observedAt ? `Observed ${observedAt}` : "Observation time unresolved";
      list.append(node("div", { className: "source-item", attrs: { tabindex: "-1" } }, [
        node("strong", { text: source.title }),
        node("span", {
          text: source.missing
            ? `${source.id} · missing from the local source ledger`
            : `${titleCase(source.type)} · ${titleCase(source.claimState)} · ${freshness}${source.contentDigestRecorded ? " · digest recorded" : ""}${source.resolved ? "" : " · unresolved"}`
        })
      ]));
    }
  } else {
    list.append(node("div", { className: "source-item" }, [node("strong", { text: "No locally recorded sources" }), node("span", { text: "Leave authority unresolved until the source ledger is complete." })]));
  }
  const check = node("input", { attrs: { type: "checkbox", id: "source-review-ack" } });
  const reviewReady = state.authorizationSources.length > 0 && state.authorizationSources.every((source) => source.resolved);
  check.disabled = !reviewReady;
  const continueReview = node("button", { className: "button button-secondary", text: "Continue review", attrs: { type: "button" } });
  continueReview.addEventListener("click", () => {
    if (questions.some((item) => item.id === "authority-sources")) {
      goToQuestion("authority-sources");
      return;
    }
    list.querySelector(".source-item")?.focus?.();
  });
  const confirm = node("button", { className: "button button-primary", text: "I reviewed and confirm", attrs: { type: "button" } });
  confirm.disabled = !reviewReady;
  confirm.addEventListener("click", () => {
    check.checked = true;
    const yes = elements.answerControl.querySelector('input[value="true"]');
    if (yes) yes.checked = true;
    elements.saveContinue.focus();
  });
  replaceChildren(elements.sourceReview,
    node("h3", { text: "Review the authority source summary first" }),
    node("p", { text: "These are exactly the sources currently cited as the basis for authority. GATE does not infer confirmation from them. Review the actual source material you control before answering Yes." }),
    list,
    node("label", { className: "review-check", attrs: { for: "source-review-ack" } }, [check, node("span", { text: "I reviewed the applicable source material and am ready to answer this authority question." })]),
    node("div", { className: "quick-actions" }, [continueReview, confirm])
  );
}

function renderRecommendation(question) {
  const recommendation = question.recommendation;
  elements.useRecommendation.hidden = !recommendation.available;
  if (question.manualOnly) {
    elements.recommendationTitle.textContent = "Your confirmation is required";
    elements.recommendationSummary.textContent = recommendation.summary || "GATE cannot infer or recommend this answer.";
    elements.recommendationValue.hidden = true;
    elements.recommendationBasis.textContent = "Manual-only answers are excluded from individual and bulk recommendations.";
    return;
  }
  if (!recommendation.available) {
    elements.recommendationTitle.textContent = "Needs source evidence";
    elements.recommendationSummary.textContent = recommendation.summary || "GATE has no defensible recommendation for this question yet.";
    elements.recommendationValue.hidden = true;
    elements.recommendationBasis.textContent = recommendation.reason ? titleCase(recommendation.reason) : "";
    return;
  }
  elements.recommendationTitle.textContent = "Recommended answer available";
  elements.recommendationSummary.textContent = recommendation.summary;
  elements.recommendationValue.textContent = "Ready to apply locally";
  elements.recommendationValue.hidden = false;
  const evidenceState = recommendation.claimState
    ? `Evidence state: ${titleCase(recommendation.claimState)}`
    : null;
  const basis = recommendation.basis
    ? `Basis: ${recommendation.basis}`
    : !question.sensitive && recommendation.provenance
      ? `Basis: ${titleCase(recommendation.provenance)}`
      : !question.sensitive
        ? "Reviewed GATE policy"
        : null;
  elements.recommendationBasis.textContent = [evidenceState, basis].filter(Boolean).join(" · ");
}

function renderQuestion() {
  const question = currentQuestion();
  if (!question) return;
  const index = questions.findIndex((item) => item.id === question.id);
  elements.questionSection.textContent = question.sectionTitle;
  elements.questionPosition.textContent = `Question ${index + 1} of ${questions.length}`;
  elements.questionTitle.textContent = question.prompt;
  elements.questionTitle.setAttribute("tabindex", "-1");
  elements.questionWhy.textContent = question.why;
  replaceChildren(elements.questionFlags,
    question.required ? flag("Required", "required") : flag("Optional"),
    question.sensitive ? flag("Sensitive · stays local", "sensitive") : null,
    question.answered ? flag("Answered", "answered") : question.answerPresent ? flag("Incomplete") : flag("Unresolved")
  );
  clearError();
  renderSourceReview(question);
  const rendered = renderControl(question);
  activeCollector = rendered.read;
  replaceChildren(elements.answerControl, rendered.root);
  elements.answerState.textContent = question.answered
    ? `Saved in revision ${state.profile.revision}`
    : question.answerPresent
      ? `Saved but incomplete in revision ${state.profile.revision}`
      : "Not answered yet";
  elements.leaveUnresolved.textContent = question.answerPresent ? "Clear answer" : "Skip for now";
  renderRecommendation(question);
  elements.previousQuestion.disabled = busy || index === 0;
  elements.backButton.disabled = busy || index === 0;
  elements.nextQuestion.disabled = busy || index === questions.length - 1;
}

function render(nextQuestionId = null) {
  questions = applicableQuestions();
  if (nextQuestionId && questions.some((question) => question.id === nextQuestionId)) currentQuestionId = nextQuestionId;
  if (!currentQuestionId || !questions.some((question) => question.id === currentQuestionId)) {
    currentQuestionId = questions.find((question) => !question.answered)?.id || questions[0]?.id;
  }
  renderHeader();
  renderSectionNav();
  renderQuestion();
  elements.questionCard.setAttribute("aria-busy", "false");
}

function baseMutation(question) {
  return {
    questionId: question.id,
    baseRevision: state.profile.revision,
    baseProfileSha256: state.profile.profileSha256
  };
}

async function saveCurrent(event) {
  event?.preventDefault();
  if (busy) return;
  clearError();
  const question = currentQuestion();
  try {
    const value = activeCollector();
    const reviewAcknowledged = question.id === "authority-operator-confirmed"
      ? $("#source-review-ack")?.checked === true
      : undefined;
    const reviewedSourceRefs = question.id === "authority-operator-confirmed" && reviewAcknowledged
      ? [...state.authorizationSourceRefs]
      : undefined;
    setBusy(true);
    const previousIndex = questions.findIndex((item) => item.id === question.id);
    state = await api("/api/answer", { ...baseMutation(question), value, reviewAcknowledged, reviewedSourceRefs });
    const nextQuestions = state.sections.flatMap((section) => section.questions.filter((item) => item.applicable));
    const next = nextQuestions[Math.min(previousIndex + 1, nextQuestions.length - 1)]?.id || question.id;
    currentQuestionId = question.id;
    setBusy(false);
    renderQuestionAndFocus(render, next, elements.questionTitle);
    showToast("Answer saved locally.");
  } catch (error) {
    setBusy(false, "Not saved");
    showError(error.message, error.fields);
    if (error.code === "stale-profile") showToast("The profile changed. Reload this page before continuing.", "error");
  }
}

async function applyRecommendation() {
  if (busy) return;
  clearError();
  const question = currentQuestion();
  try {
    setBusy(true, "Applying recommendation…");
    const previousIndex = questions.findIndex((item) => item.id === question.id);
    state = await api("/api/recommendation", baseMutation(question));
    const nextQuestions = state.sections.flatMap((section) => section.questions.filter((item) => item.applicable));
    setBusy(false);
    renderQuestionAndFocus(
      render,
      nextQuestions[Math.min(previousIndex + 1, nextQuestions.length - 1)]?.id,
      elements.questionTitle
    );
    showToast("Reviewed recommendation applied.");
  } catch (error) {
    setBusy(false, "Not saved");
    showError(error.message, error.fields);
  }
}

async function skipOrClearCurrent() {
  if (busy) return;
  const question = currentQuestion();
  if (!question.answerPresent) {
    moveQuestion(1);
    return;
  }
  try {
    clearError();
    setBusy(true, "Clearing answer…");
    state = await api("/api/answer/clear", baseMutation(question));
    setBusy(false);
    render(question.id);
    showToast("Answer cleared. Dependent confirmations were reset when required.");
  } catch (error) {
    setBusy(false, "Not cleared");
    showError(error.message, error.fields);
  }
}

async function applyAllRecommendations() {
  if (busy || state.recommendationCount === 0) return;
  try {
    setBusy(true, "Applying supported recommendations…");
    state = await api("/api/recommendations/apply", {
      baseRevision: state.profile.revision,
      baseProfileSha256: state.profile.profileSha256
    });
    setBusy(false);
    currentQuestionId = null;
    renderQuestionAndFocus(render, undefined, elements.questionTitle);
    showToast("Supported recommendations applied. Source facts and confirmations remain for you.");
  } catch (error) {
    setBusy(false, "Not saved");
    showToast(error.message, "error");
  }
}

async function bootstrap() {
  credentials = getCredentials();
  if (!credentials) {
    elements.questionTitle.textContent = "This private form needs a fresh GATE session";
    elements.questionWhy.textContent = "Close this tab and run the profile UI command again. Session credentials stay in the local launch URL and are never embedded in the page.";
    elements.saveState.textContent = "Session missing";
    elements.questionCard.setAttribute("aria-busy", "false");
    return;
  }
  try {
    state = await api("/api/state");
    elements.saveState.textContent = "Ready · local";
    render();
  } catch (error) {
    elements.questionTitle.textContent = "GATE could not open this profile";
    elements.questionWhy.textContent = error.message;
    elements.saveState.textContent = "Connection failed";
    elements.questionCard.setAttribute("aria-busy", "false");
  }
}

export function renderProfileControl(question, semantics, sources = []) {
  state = { semantics, sources };
  return renderControl(question);
}

if (globalThis.document) {
elements.answerForm.addEventListener("submit", saveCurrent);
elements.previousQuestion.addEventListener("click", () => moveQuestion(-1));
elements.backButton.addEventListener("click", () => moveQuestion(-1));
elements.nextQuestion.addEventListener("click", () => moveQuestion(1));
elements.leaveUnresolved.addEventListener("click", skipOrClearCurrent);
elements.useRecommendation.addEventListener("click", applyRecommendation);
elements.recommendAll.addEventListener("click", applyAllRecommendations);
window.addEventListener("keydown", (event) => {
  if (!event.altKey || busy) return;
  if (event.key === "ArrowLeft") { event.preventDefault(); moveQuestion(-1); }
  if (event.key === "ArrowRight") { event.preventDefault(); moveQuestion(1); }
});

bootstrap();
}
