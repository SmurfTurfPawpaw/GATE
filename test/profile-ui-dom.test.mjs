import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const html = fs.readFileSync(path.join(repo, "profile-ui", "index.html"), "utf8");
const css = fs.readFileSync(path.join(repo, "profile-ui", "styles.css"), "utf8");
const app = fs.readFileSync(path.join(repo, "profile-ui", "app.js"), "utf8");

test("profile UI is an external-asset-only local application", () => {
  assert.match(html, /src="\/profile-ui\/app\.js"/u);
  assert.match(html, /href="\/profile-ui\/styles\.css"/u);
  assert.doesNotMatch(html, /<script(?![^>]*src=)/u);
  assert.doesNotMatch(html, /style=/u);
  assert.doesNotMatch(`${html}\n${css}\n${app}`, /https?:\/\//u);
  assert.doesNotMatch(`${html}\n${css}\n${app}`, /telemetry|analytics|segment\.com|sentry|googleapis/u);
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
  assert.match(app, /type = "number"/u);
  assert.match(app, /type: multiple \? "checkbox" : "radio"/u);
  assert.match(app, /Add platform contact/u);
  assert.match(app, /GATE does not invent it/u);
  assert.doesNotMatch(app, /platform:\/\/program-inbox/u);
  assert.match(app, /data-contact/u);
  assert.match(app, /Advanced JSON fallback/u);
  assert.match(app, /I reviewed the applicable source material/u);
});

test("profile UI communicates local privacy and unresolved authority", () => {
  assert.match(html, /Private · local only/u);
  assert.match(html, /never contacts the program or target/u);
  assert.match(html, /Authority and attestations always need your explicit answer/u);
  assert.match(html, /Leave unresolved/u);
});
