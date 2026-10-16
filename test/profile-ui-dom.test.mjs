import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { bindFieldLabel } from "../profile-ui/accessibility.js";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const html = fs.readFileSync(path.join(repo, "profile-ui", "index.html"), "utf8");
const css = fs.readFileSync(path.join(repo, "profile-ui", "styles.css"), "utf8");
const app = fs.readFileSync(path.join(repo, "profile-ui", "app.js"), "utf8");
const accessibility = fs.readFileSync(path.join(repo, "profile-ui", "accessibility.js"), "utf8");
const time = fs.readFileSync(path.join(repo, "profile-ui", "time.js"), "utf8");

test("profile UI is an external-asset-only local application", () => {
  assert.match(html, /src="\/profile-ui\/app\.js"/u);
  assert.match(html, /href="\/profile-ui\/styles\.css"/u);
  assert.doesNotMatch(html, /<script(?![^>]*src=)/u);
  assert.doesNotMatch(html, /style=/u);
  assert.doesNotMatch(`${html}\n${css}\n${app}\n${accessibility}\n${time}`, /https?:\/\//u);
  assert.doesNotMatch(`${html}\n${css}\n${app}`, /telemetry|analytics|segment\.com|sentry|googleapis/u);
});

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

test("profile UI uses safe DOM construction without HTML injection sinks", () => {
  assert.doesNotMatch(app, /\.innerHTML\s*=|insertAdjacentHTML|document\.write|\beval\s*\(|new Function/u);
  assert.match(app, /textContent/u);
  assert.match(app, /replaceChildren/u);
});

test("profile UI exposes the required guided and native controls", () => {
  assert.match(html, /id="section-nav"/u);
  assert.match(html, /id="progress-bar"/u);
  assert.match(html, /id="use-recommendation"/u);
  assert.match(html, /id="recommend-all"/u);
  assert.match(html, /id="source-review"/u);
  assert.match(app, /type = "datetime-local"/u);
  assert.match(app, /UTC date and time/u);
  assert.match(app, /Displayed and stored in UTC/u);
  assert.match(app, /type = "number"/u);
  assert.match(app, /type: multiple \? "checkbox" : "radio"/u);
  assert.match(app, /Add platform contact/u);
  assert.match(app, /GATE does not invent it/u);
  assert.doesNotMatch(app, /platform:\/\/program-inbox/u);
  assert.match(app, /data-contact/u);
  assert.match(app, /Advanced JSON fallback/u);
  assert.match(app, /I reviewed the applicable source material/u);
  assert.match(app, /question\.answered \? "Clear answer" : "Skip for now"/u);
  assert.match(app, /reviewedSourceRefs/u);
  assert.match(app, /Evidence state:/u);
  assert.match(app, /!question\.sensitive/u);
  assert.match(css, /input:focus-visible \+ label/u);
  assert.match(app, /node\("fieldset"/u);
});

test("profile UI communicates local privacy and unresolved authority", () => {
  assert.match(html, /Private · local only/u);
  assert.match(html, /never contacts the program or target/u);
  assert.match(html, /Authority and attestations always need your explicit answer/u);
  assert.match(html, /Skip for now/u);
});
