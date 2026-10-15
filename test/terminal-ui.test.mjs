import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import { validateDocument } from "../src/lib/schema.mjs";
import {
  readOperatorDisplayName,
  sanitizeOperatorDisplayName,
  terminalWelcomeBanner,
  terminalWelcomeLines
} from "../src/lib/terminal-ui.mjs";

const config = { operator: { displayName: "Giovanni" } };

test("tracked operator display name satisfies the bounded single-line config contract", () => {
  const tracked = JSON.parse(fs.readFileSync(new URL("../config/gate.config.json", import.meta.url), "utf8"));
  assert.equal(validateDocument(tracked, "gate-config.schema.json").ok, true);

  for (const displayName of ["Giovanni\nINJECTED", "\u001b[31mGiovanni", "Giovanni\u2028INJECTED", "x".repeat(65)]) {
    const changed = structuredClone(tracked);
    changed.operator.displayName = displayName;
    assert.equal(validateDocument(changed, "gate-config.schema.json").ok, false, JSON.stringify(displayName));
  }
});

test("terminal welcome starts with the exact personalized greeting and static readiness lines", () => {
  assert.deepEqual(terminalWelcomeLines(config), [
    "GATE // Welcome, Giovanni.",
    "GATE // Cockpit: preparing local read-only observer.",
    "GATE // Progress: waiting for observed runtime state."
  ]);
  assert.equal(
    terminalWelcomeBanner(config),
    "GATE // Welcome, Giovanni.\n" +
      "GATE // Cockpit: preparing local read-only observer.\n" +
      "GATE // Progress: waiting for observed runtime state.\n"
  );
});

test("terminal display names trim harmless outer spacing", () => {
  assert.equal(sanitizeOperatorDisplayName("  Giovanni  "), "Giovanni");
  assert.equal(readOperatorDisplayName({ operator: { displayName: "  Giovanni  " } }), "Giovanni");
});

test("terminal display names reject newline and control injection as a whole", () => {
  for (const unsafe of [
    "Giovanni\nINJECTED",
    "Giovanni\rINJECTED",
    "Giovanni\tINJECTED",
    "Giovanni\u0000INJECTED",
    "Giovanni\u0085INJECTED",
    "Giovanni\u2028INJECTED",
    "Giovanni\u2029INJECTED"
  ]) {
    const banner = terminalWelcomeBanner({ operator: { displayName: unsafe } });
    assert.equal(banner.split("\n")[0], "GATE // Welcome, Operator.");
    assert.equal(banner.includes("INJECTED"), false);
  }
});

test("terminal display names reject ANSI and C1 escape sequences", () => {
  for (const unsafe of ["\u001b[31mGiovanni\u001b[0m", "\u009b31mGiovanni"]) {
    assert.equal(sanitizeOperatorDisplayName(unsafe), "Operator");
    const banner = terminalWelcomeBanner({ operator: { displayName: unsafe } });
    assert.equal(banner.includes("\u001b"), false);
    assert.equal(banner.includes("\u009b"), false);
    assert.equal(banner.split("\n")[0], "GATE // Welcome, Operator.");
  }
});

test("terminal display names use a bounded deterministic fallback", () => {
  assert.equal(sanitizeOperatorDisplayName(""), "Operator");
  assert.equal(sanitizeOperatorDisplayName("x".repeat(65)), "Operator");
  assert.equal(readOperatorDisplayName({}), "Operator");
});
