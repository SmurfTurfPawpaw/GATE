import assert from "node:assert/strict";
import test from "node:test";

import {
  bindFieldLabel,
  focusAfterRepeatedItemRemoval,
  focusLastRepeatedControl,
  renderQuestionAndFocus
} from "../profile-ui/accessibility.js";

test("field labels bind to the inner input of an optional scalar control", () => {
  const attributes = new Map();
  const label = { setAttribute: (name, value) => attributes.set(name, value) };
  const innerInput = { tagName: "INPUT", id: "" };
  const optionalWrapper = {
    tagName: "DIV",
    querySelector(selector) {
      assert.equal(selector, '[data-field-control="primary"]');
      return innerInput;
    }
  };

  const bound = bindFieldLabel(label, optionalWrapper, () => "optional-scalar");
  assert.equal(bound, innerInput);
  assert.equal(innerInput.id, "field-optional-scalar");
  assert.equal(attributes.get("for"), innerInput.id);
});

test("successful question changes render before moving focus to the heading", () => {
  const events = [];
  const heading = { focus: () => events.push("focus") };
  renderQuestionAndFocus((id) => events.push(`render:${id}`), "next-question", heading);
  assert.deepEqual(events, ["render:next-question", "focus"]);
});

test("removing a repeated item restores focus to the next item or the add button", () => {
  const events = [];
  const firstControl = { focus: () => events.push("first") };
  const secondControl = { focus: () => events.push("second") };
  const container = {
    children: [
      { querySelector: () => firstControl },
      { querySelector: () => secondControl }
    ]
  };
  assert.equal(focusAfterRepeatedItemRemoval(container, 1), secondControl);
  assert.deepEqual(events, ["second"]);

  const add = { focus: () => events.push("add") };
  assert.equal(focusAfterRepeatedItemRemoval({ children: [] }, 0, add), add);
  assert.deepEqual(events, ["second", "add"]);
});

test("adding a repeated item focuses the newly appended control", () => {
  const events = [];
  const firstControl = { focus: () => events.push("first") };
  const lastControl = { focus: () => events.push("last") };
  const container = {
    children: [
      { querySelector: () => firstControl },
      { querySelector: () => lastControl }
    ]
  };
  assert.equal(focusLastRepeatedControl(container), lastControl);
  assert.deepEqual(events, ["last"]);
});


import { renderProfileControl } from "../profile-ui/app.js";
import { loadProgramProfileQuestionnaire } from "../src/lib/program-profile-contract.mjs";

class Element {
  constructor(tag) {
    this.tagName = tag.toUpperCase(); this.children = []; this.dataset = {};
    this.value = ""; this.events = {}; this.textContent = "";
  }
  setAttribute(key, value) {
    if (key.startsWith("data-")) this.dataset[key.slice(5).replace(/-([a-z])/gu, (_, c) => c.toUpperCase())] = value;
    else this[key] = value;
  }
  append(...children) { for (const child of children) { child.parentElement = this; this.children.push(child); } }
  prepend(child) { child.parentElement = this; this.children.unshift(child); }
  replaceChildren(...children) { this.children = []; this.append(...children); }
  remove() { this.parentElement.children.splice(this.parentElement.children.indexOf(this), 1); }
  addEventListener(event, handler) { this.events[event] = handler; }
  click() { this.events.click?.({ preventDefault() {} }); }
  focus() {}
  querySelectorAll(selector) {
    const matches = (element) => selector.split(", ").some((part) => {
      const tag = part.match(/^[a-z]+/u)?.[0];
      if (tag && element.tagName !== tag.toUpperCase()) return false;
      if (part.includes(":checked") && !element.checked) return false;
      if (part.includes(":not([disabled])") && element.disabled) return false;
      return [...part.replace(":not([disabled])", "").matchAll(/\[([^=\]]+)(?:="([^"\]]*)")?\]/gu)].every(([, key, value]) => {
        const actual = key.startsWith("data-") ? element.dataset[key.slice(5).replace(/-([a-z])/gu, (_, c) => c.toUpperCase())] : element[key];
        return value === undefined ? actual !== undefined : actual === value;
      });
    });
    return this.children.flatMap((child) => [...(matches(child) ? [child] : []), ...child.querySelectorAll(selector)]);
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
}

const questionnaire = loadProgramProfileQuestionnaire();
const semantics = questionnaire.semantics;
function control(id, value) {
  globalThis.document = { createElement: (tag) => new Element(tag) };
  try {
    const records = [...questionnaire.sections, ...questionnaire.conditionalModules];
    const question = records.flatMap((section) => section.questions).find((item) => item.id === id);
    assert.ok(question, id);
    return renderProfileControl({ ...question, value, moduleId: id.startsWith("ai-llm-") ? "ai-llm" : undefined }, semantics);
  } finally { delete globalThis.document; }
}
function withDom(action) {
  globalThis.document = { createElement: (tag) => new Element(tag) };
  try { return action(); } finally { delete globalThis.document; }
}
function labelled(root, label) {
  const item = root.querySelectorAll("label").find((node) => node.textContent === label);
  assert.ok(item, label);
  return root.querySelectorAll("input, textarea, select").find((node) => node.id === item.for);
}

test("guided phase edits retain tighter ceilings and allow native limit changes", () => {
  const value = { id: "phase-one", phaseId: "active-surface-validation", assetRefs: ["asset-one"], actions: ["observe"], allowedToolIds: ["httpx"], deniedToolIds: [], claimState: "observed", sourceRefs: ["rules"], rationale: "Authorized", conditions: ["old"], limits: { maxRequests: 10, maxSpendUsd: null } };
  const editor = withDom(() => control("execution-phase-policies", [value]));
  editor.root.querySelector('[data-field-path="conditions"]').value = "new";
  assert.deepEqual(editor.read(), [{ ...value, conditions: ["new"] }]);
  labelled(editor.root, "maxRequests").value = "5";
  assert.equal(editor.read()[0].limits.maxRequests, 5);
});

test("guided technique and module edits preserve typed structured values", () => {
  const technique = { id: "timing", name: "Timing", action: "observe", disposition: "allowed", claimState: "observed", sourceRefs: ["rules"], rationale: "Authorized", conditions: [], parameters: { count: 3, enabled: true, missing: null, mode: "serial" } };
  const editor = withDom(() => control("actions-techniques", [technique]));
  assert.deepEqual(editor.read(), [technique]);
  const count = editor.root.querySelectorAll('input[type="number"]')[0];
  count.value = "4";
  assert.equal(editor.read()[0].parameters.count, 4);
  const module = withDom(() => control("ai-llm-system-map", [{ name: "model", nested: { enabled: true }, ports: [1, 2] }]));
  assert.deepEqual(module.read(), [{ name: "model", nested: { enabled: true }, ports: [1, 2] }]);
});

test("new assets support native action overrides and numeric ceilings", () => {
  const editor = withDom(() => control("scope-assets", []));
  withDom(() => editor.root.querySelectorAll("button").find((button) => button.textContent === "+ Add item").click());
  labelled(editor.root, "Override observe").checked = true;
  labelled(editor.root, "maxRequests").value = "10";
  const asset = editor.read()[0];
  assert.equal(asset.limitOverrides.maxRequests, 10);
  assert.equal(asset.actionOverrides.observe.disposition, "unknown");
  assert.deepEqual(Object.keys(asset.actionOverrides), ["observe"]);
});

test("source add and remove preserve an unfinished UTC draft", () => {
  const editor = withDom(() => control("authority-sources", []));
  const add = editor.root.querySelectorAll("button").find((button) => button.textContent.startsWith("+ Add"));
  assert.ok(add);
  withDom(() => add.click());
  const observed = editor.root.querySelector('input[type="datetime-local"]');
  observed.value = "2026-10";
  withDom(() => add.click());
  assert.equal(editor.root.querySelector('input[type="datetime-local"]').value, "2026-10");
  withDom(() => editor.root.querySelectorAll("button").filter((button) => button.textContent === "Remove")[1].click());
  assert.equal(editor.root.querySelector('input[type="datetime-local"]').value, "2026-10");
});
