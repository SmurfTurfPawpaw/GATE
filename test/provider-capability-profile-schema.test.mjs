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
