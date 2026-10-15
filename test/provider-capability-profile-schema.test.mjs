import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { PROGRAM_PROFILE_ACTIONS } from "../src/lib/program-profile-contract.mjs";
import { validateDocument } from "../src/lib/schema.mjs";
import { validateRepository } from "../src/lib/validation.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const schemaName = "provider-capability-profile.schema.json";
const modes = ["plan", "analyze", "generate-command", "execute", "report", "retest"];
const template = JSON.parse(fs.readFileSync(path.join(repo, "templates", "provider-capability-profile.json"), "utf8"));
const clone = (value) => structuredClone(value);

test("the sanitized provider profile template is complete, closed, and repository-validated", () => {
  assert.equal(template.contextWindow, null);
  assert.deepEqual(Object.keys(template.capabilities), PROGRAM_PROFILE_ACTIONS);
  for (const action of PROGRAM_PROFILE_ACTIONS) {
    assert.deepEqual(Object.keys(template.capabilities[action]), modes, action);
    assert.deepEqual(new Set(Object.values(template.capabilities[action])), new Set(["unknown"]), action);
  }

  const direct = validateDocument(template, schemaName, { paths: { repo } });
  assert.deepEqual(direct.errors, []);
  assert.equal(direct.ok, true);

  const repository = validateRepository({ paths: { repo } });
  const registered = repository.checks.find(
    (candidate) => candidate.name === "contract:templates/provider-capability-profile.json"
  );
  assert.deepEqual(registered, {
    name: "contract:templates/provider-capability-profile.json",
    ok: true,
    detail: schemaName
  });
});

test("provider context accounting is explicit, bounded, and closed", () => {
  const omitted = clone(template);
  delete omitted.contextWindow;
  assert.equal(validateDocument(omitted, schemaName, { paths: { repo } }).ok, true);

  const declared = clone(template);
  declared.metadata.model = "fixture-model";
  declared.contextWindow = {
    maxTokens: 128000,
    reservedOutputTokens: 16000,
    requestOverheadTokensUpperBound: 8000,
    countingMethod: "utf8-bytes-upper-bound"
  };
  assert.equal(validateDocument(declared, schemaName, { paths: { repo } }).ok, true);

  const legacy = clone(template);
  legacy.apiVersion = "gate.dev/provider-capability-profile/v1";
  delete legacy.contextWindow;
  assert.equal(validateDocument(legacy, schemaName, { paths: { repo } }).ok, true);
  legacy.contextWindow = declared.contextWindow;
  assert.equal(validateDocument(legacy, schemaName, { paths: { repo } }).ok, false);

  for (const mutate of [
    (value) => { value.contextWindow.countingMethod = "bytes-divided-by-four"; },
    (value) => { value.contextWindow.maxTokens = 0; },
    (value) => { value.contextWindow.reservedOutputTokens = 0; },
    (value) => { value.contextWindow.reservedOutputTokens = -1; },
    (value) => { value.contextWindow.requestOverheadTokensUpperBound = -1; },
    (value) => { value.contextWindow.unreviewed = true; },
    (value) => { delete value.contextWindow.requestOverheadTokensUpperBound; }
  ]) {
    const invalid = clone(declared);
    mutate(invalid);
    assert.equal(validateDocument(invalid, schemaName, { paths: { repo } }).ok, false);
  }

  const unbound = clone(declared);
  delete unbound.metadata.model;
  assert.equal(validateDocument(unbound, schemaName, { paths: { repo } }).ok, false);
});

test("provider profile schema rejects incomplete action and assistance-mode matrices", () => {
  const missingAction = clone(template);
  delete missingAction.capabilities.scan;
  const actionResult = validateDocument(missingAction, schemaName, { paths: { repo } });
  assert.equal(actionResult.ok, false);
  assert.ok(actionResult.errors.some((error) => /required property 'scan'/u.test(error)));

  const missingMode = clone(template);
  delete missingMode.capabilities.observe.execute;
  const modeResult = validateDocument(missingMode, schemaName, { paths: { repo } });
  assert.equal(modeResult.ok, false);
  assert.ok(modeResult.errors.some((error) => /required property 'execute'/u.test(error)));
});

test("provider profile schema rejects unknown fields, invalid dispositions, and malformed freshness bounds", () => {
  const extra = clone(template);
  extra.metadata.notes = "unreviewed extension";
  assert.equal(validateDocument(extra, schemaName, { paths: { repo } }).ok, false);

  const disposition = clone(template);
  disposition.capabilities.observe.plan = "permit";
  assert.equal(validateDocument(disposition, schemaName, { paths: { repo } }).ok, false);

  const timestamp = clone(template);
  timestamp.metadata.expiresAt = "tomorrow";
  assert.equal(validateDocument(timestamp, schemaName, { paths: { repo } }).ok, false);
});

test("provider identity text rejects terminal and direction-formatting controls", () => {
  for (const model of ["fixture\u001b]52;c;payload\u0007", "safe\u202Etxt.exe", "safe\u200Bhidden", "safe\u{E0001}hidden"]) {
    const invalid = clone(template);
    invalid.metadata.model = model;
    assert.equal(validateDocument(invalid, schemaName, { paths: { repo } }).ok, false);
  }
  const visibleJoiner = clone(template);
  visibleJoiner.metadata.model = "Persian می‌رود model";
  assert.equal(validateDocument(visibleJoiner, schemaName, { paths: { repo } }).ok, true);
});
