import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { PassThrough, Writable } from "node:stream";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { cliInternals } from "../src/cli.mjs";
import {
  applyProgramProfileAnswers,
  createProgramProfile,
  resumeProgramProfile
} from "../src/lib/bounty-profiles.mjs";
import { PROGRAM_PROFILE_ACTIONS, PROGRAM_PROFILE_QUESTIONS } from "../src/lib/program-profile-contract.mjs";
import { runtimePaths } from "../src/lib/paths.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const gate = path.join(repo, "bin", "gate.mjs");

function invoke(args, home) {
  return spawnSync(process.execPath, [gate, ...args], {
    cwd: repo,
    env: { ...process.env, GATE_HOME: home },
    encoding: "utf8",
    timeout: 10_000
  });
}

function profileValueAt(profile, dottedPath) {
  return dottedPath.split(".").reduce((value, part) => value?.[part], profile);
}

test("help exposes the private bug-bounty profile workflow", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-bounty-help-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const result = invoke(["help"], path.join(root, "home"));

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /bounty profile create ID \[--answers FILE\]/u);
  assert.match(result.stdout, /bounty profile resume ID \[--answers FILE\]/u);
  assert.match(result.stdout, /bounty profile compile ID/u);
  assert.match(result.stdout, /deterministic no-contact proposed assessment bundle/u);
});

test("interactive profile creation and resume require a terminal before private state is created", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-bounty-nontty-"));
  const home = path.join(root, "home");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  for (const action of ["create", "resume"]) {
    const result = invoke(["bounty", "profile", action, `nontty-${action}`], home);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /requires a TTY; pass --answers FILE for headless use/u);
  }
  assert.equal(fs.existsSync(home), false);
});

test("interactive questionnaire commands persist each accepted answer for resume", { timeout: 5000 }, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-bounty-wizard-"));
  const home = path.join(root, "home");
  const paths = runtimePaths({ repo, home });
  const input = new PassThrough();
  let transcript = "";
  const terminalOutput = new Writable({
    write(chunk, _encoding, callback) {
      transcript += chunk.toString();
      callback();
    }
  });
  const timers = [];
  t.after(() => {
    for (const timer of timers) clearTimeout(timer);
    fs.rmSync(root, { recursive: true, force: true });
  });

  const responses = ["why\n", "Interactive fixture\n", "save\n", "quit\n"];
  responses.forEach((response, index) => {
    timers.push(setTimeout(() => input.write(response), 40 * (index + 1)));
  });
  const result = await cliInternals.runProgramProfileQuestionnaire("interactive-profile", "create", {
    paths,
    input,
    output: terminalOutput,
    interactive: true,
    terminal: false
  });
  input.end();

  assert.equal(result.id, "interactive-profile");
  assert.equal(result.saved, true);
  assert.equal(result.outcome, "saved");
  assert.equal(result.ready, false);
  assert.ok(result.blockerCount > 0);
  assert.equal(Object.hasOwn(result, "blockers"), false);
  assert.equal(Object.hasOwn(result, "checks"), false);
  assert.equal(Object.hasOwn(result, "profile"), false);
  assert.equal(result.nextCommand, "./bin/gate.mjs bounty profile resume interactive-profile");
  assert.ok(JSON.stringify(result).length < 1000);
  const profileRoot = path.join(home, "programs", "interactive-profile");
  const envelope = JSON.parse(fs.readFileSync(path.join(profileRoot, "answers.json"), "utf8"));
  assert.equal(envelope.answers[PROGRAM_PROFILE_QUESTIONS[0].id], "Interactive fixture");
  const profile = JSON.parse(fs.readFileSync(path.join(profileRoot, "program-profile.json"), "utf8"));
  assert.equal(profile.questionnaire.sectionStatus[PROGRAM_PROFILE_QUESTIONS[0].section], "in-progress");
  assert.equal(profile.questionnaire.activeSection, PROGRAM_PROFILE_QUESTIONS[0].section);
  assert.match(transcript, new RegExp(PROGRAM_PROFILE_QUESTIONS[0].why.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  assert.match(transcript, new RegExp(`Saved ${PROGRAM_PROFILE_QUESTIONS[0].id}\\.`, "u"));
  assert.match(transcript, /Every accepted answer is already persisted privately\./u);
  assert.match(transcript, /1\/66 applicable · identity-program-name/u);
  assert.match(transcript, /unconfirmed draft: interactive-profile; enter explicitly to confirm/u);
  assert.doesNotMatch(transcript, /identity-program-name[^\n]*\n[^\n]*\[current: interactive-profile\]/u);
});

test("interactive format guidance explains contract-backed structured answer shapes", { timeout: 5000 }, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-bounty-format-"));
  const home = path.join(root, "home");
  const paths = runtimePaths({ repo, home });
  const input = new PassThrough();
  let transcript = "";
  const terminalOutput = new Writable({
    write(chunk, _encoding, callback) {
      transcript += chunk.toString();
      callback();
    }
  });
  const timers = [];
  t.after(() => {
    for (const timer of timers) clearTimeout(timer);
    fs.rmSync(root, { recursive: true, force: true });
  });

  [
    "edit identity-deliverables\n",
    "format\n",
    "edit authority-safe-harbor\n",
    "format\n",
    "edit actions-all\n",
    "format\n",
    "quit\n"
  ].forEach((response, index) => {
    timers.push(setTimeout(() => input.write(response), 40 * (index + 1)));
  });
  const result = await cliInternals.runProgramProfileQuestionnaire("format-profile", "create", {
    paths,
    input,
    output: terminalOutput,
    interactive: true,
    terminal: false
  });
  input.end();

  assert.equal(result.outcome, "saved");
  assert.match(transcript, /Commands: back, edit QUESTION_ID, why, format, save, quit\./u);
  assert.match(transcript, /Accepted format: a JSON array matching the records requested by this prompt/u);
  assert.match(transcript, /"Technical vulnerability report"/u);
  assert.match(transcript, /Accepted format: a JSON decision object with disposition, claimState, sourceRefs, rationale, and conditions\./u);
  assert.match(transcript, /Example only; replace every sample value with the exact recorded facts:/u);
  assert.match(transcript, /Accepted format: a JSON object containing every action class and its decision\./u);
  for (const action of ["observe", "scan", "exploit-safe", "exfiltration-simulation"]) {
    assert.match(transcript, new RegExp(`"${action}"`, "u"));
  }
});

test("interactive progress counts only questions applicable to the current profile", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-bounty-progress-"));
  const paths = runtimePaths({ repo, home: path.join(root, "home") });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  createProgramProfile("progress-profile", {}, { paths, now: "2026-10-14T00:00:00.000Z" });
  const profile = resumeProgramProfile("progress-profile", { paths }).profile;
  const firstIndex = 0;
  const baseQuestions = PROGRAM_PROFILE_QUESTIONS.filter((question) => !question.module);
  const base = cliInternals.applicableQuestionProgress(PROGRAM_PROFILE_QUESTIONS, profile, firstIndex);
  assert.deepEqual(base, { position: 1, total: baseQuestions.length });

  profile.questionnaire.applicableModules = ["web-api"];
  const withWeb = cliInternals.applicableQuestionProgress(PROGRAM_PROFILE_QUESTIONS, profile, firstIndex);
  const webQuestions = PROGRAM_PROFILE_QUESTIONS.filter((question) => question.module === "web-api");
  assert.deepEqual(withWeb, { position: 1, total: baseQuestions.length + webQuestions.length });
});

test("format guidance uses valid field-specific scalar examples", () => {
  const guidance = (id) => cliInternals.questionFormatGuidance(
    PROGRAM_PROFILE_QUESTIONS.find((question) => question.id === id)
  );
  assert.match(guidance("limits-timezone"), /Etc\/UTC/u);
  assert.match(guidance("limits-max-parallel"), /\n2$/u);
  assert.doesNotMatch(guidance("limits-max-parallel"), /1000/u);
  assert.match(guidance("limits-max-tokens"), /50000/u);
  assert.match(guidance("data-retention-days"), /\n30$/u);
  assert.match(guidance("data-classification"), /\nconfidential$/u);
  assert.match(guidance("attestation-operator"), /local-operator/u);
  assert.match(guidance("architecture-unknowns"), /use \[\] when the recorded answer is none/u);
  assert.match(guidance("architecture-unknowns"), /\n\[\]$/u);
  assert.match(guidance("authority-valid-from"), /2026-01-01T00:00:00Z/u);
  assert.match(guidance("authority-valid-until"), /2026-12-01T00:00:00Z/u);
  for (const id of ["limits-max-spend", "authority-program-url", "authority-valid-from", "authority-valid-until"]) {
    assert.match(guidance(id), /\nAlternative: null$/u);
    assert.doesNotMatch(guidance(id), /\(or null\)/u);
  }
});

test("terminal fallback renders numbered choices and stores their canonical values", () => {
  const question = (id) => PROGRAM_PROFILE_QUESTIONS.find((candidate) => candidate.id === id);
  const depth = question("identity-depth");
  assert.match(cliInternals.questionChoicePrompt(depth), /1\. targeted/u);
  assert.match(cliInternals.questionChoicePrompt(depth), /2\. thorough/u);
  assert.equal(cliInternals.parseQuestionAnswer(depth, "2"), "thorough");
  assert.equal(cliInternals.parseQuestionAnswer(depth, "exhaustive"), "exhaustive");
  assert.throws(() => cliInternals.parseQuestionAnswer(depth, "9"), /between 1 and 3/u);

  const assistance = question("execution-requested-assistance-modes");
  assert.deepEqual(cliInternals.parseQuestionAnswer(assistance, "4,1,4"), ["plan", "execute"]);
  assert.deepEqual(cliInternals.parseQuestionAnswer(assistance, "report,analyze"), ["analyze", "report"]);

  const attestation = question("attestation-answers-complete");
  assert.match(cliInternals.questionChoicePrompt(attestation), /1\. yes[\s\S]*2\. no/u);
  assert.equal(cliInternals.parseQuestionAnswer(attestation, "1"), true);
  assert.equal(cliInternals.parseQuestionAnswer(attestation, "2"), false);
  assert.equal(cliInternals.parseQuestionAnswer(attestation, "0"), false);
});

test("persisted legacy values are escaped before terminal display", () => {
  const rendered = cliInternals.boundedTerminalValue("before\u202Eafter\u2028tag\u{E0001}\n> forged prompt\tvalue");
  assert.equal(rendered, "before\\u202Eafter\\u2028tag\\uE0001\\u000A> forged prompt\\u0009value");
  assert.doesNotMatch(rendered, /[\t\n\u2028\u202E\u{E0001}]/u);
});

test("structured format examples use coherent architecture and execution references", () => {
  const example = (id) => {
    const guidance = cliInternals.questionFormatGuidance(
      PROGRAM_PROFILE_QUESTIONS.find((question) => question.id === id)
    );
    return JSON.parse(guidance.split("\n").slice(2).join("\n"));
  };

  const components = example("architecture-components");
  const componentIds = new Set(components.map(({ id }) => id));
  for (const relationship of [
    ...example("architecture-trust-boundaries"),
    ...example("architecture-data-flows")
  ]) {
    assert.equal(componentIds.has(relationship.from), true, relationship.from);
    assert.equal(componentIds.has(relationship.to), true, relationship.to);
  }

  const assets = example("scope-assets");
  const actions = example("actions-all");
  const phases = example("execution-phase-policies");
  const namedTechniques = example("actions-techniques");
  assert.equal(namedTechniques[0].id, "webhook-open-connection-mutation");
  assert.equal(namedTechniques[0].action, "exploit-stateful");
  assert.equal(namedTechniques[0].parameters.stateModel, "connect-mutate-observe-cleanup");
  assert.equal(namedTechniques[0].conditions.length > 0, true);
  const assetIds = new Set(assets.map(({ id }) => id));
  assert.deepEqual(Object.keys(assets[0].actionOverrides), PROGRAM_PROFILE_ACTIONS);
  assert.deepEqual(Object.keys(assets[0].limitOverrides), [
    "maxMinutes", "maxRequests", "maxParallel", "maxRatePerSecond", "maxTokens", "maxSpendUsd"
  ]);
  for (const phase of phases) {
    assert.equal(phase.assetRefs.every((id) => assetIds.has(id)), true);
    assert.equal(phase.actions.every((action) => actions[action]?.disposition === "allowed"), true);
    for (const assetRef of phase.assetRefs) {
      const asset = assets.find(({ id }) => id === assetRef);
      assert.equal(asset.disposition, "allowed");
      assert.equal(phase.actions.every((action) => asset.actionOverrides[action]?.disposition === "allowed"), true);
    }
  }
});

test("questionnaire completion returns a bounded next-step summary", () => {
  const result = cliInternals.questionnaireResult({
    id: "complete-profile",
    status: "ready-to-materialize",
    ready: true,
    structuralValid: true,
    profileSha256: "a".repeat(64),
    blockers: [],
    warnings: [],
    checks: Array.from({ length: 500 }, () => ({ detail: "not returned" })),
    profile: {
      profileRef: "private://programs/complete-profile/program-profile.json",
      profileSha256: "a".repeat(64)
    }
  }, "questions-complete");

  assert.deepEqual(result, {
    saved: true,
    outcome: "questions-complete",
    id: "complete-profile",
    status: "ready-to-materialize",
    ready: true,
    structuralValid: true,
    blockerCount: 0,
    warningCount: 0,
    profileRef: "private://programs/complete-profile/program-profile.json",
    profileSha256: "a".repeat(64),
    nextCommand: "./bin/gate.mjs bounty profile verify complete-profile"
  });
  assert.ok(JSON.stringify(result).length < 1000);
});

test("interactive multiline answers preserve lines until the explicit terminator", { timeout: 5000 }, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-bounty-multiline-"));
  const home = path.join(root, "home");
  const paths = runtimePaths({ repo, home });
  const input = new PassThrough();
  let transcript = "";
  const terminalOutput = new Writable({
    write(chunk, _encoding, callback) {
      transcript += chunk.toString();
      callback();
    }
  });
  const timers = [];
  t.after(() => {
    for (const timer of timers) clearTimeout(timer);
    fs.rmSync(root, { recursive: true, force: true });
  });

  [
    "edit identity-objective\n",
    "Validate tenant isolation\n",
    "and authorization boundaries.\n",
    ".\n",
    "quit\n"
  ].forEach((response, index) => {
    timers.push(setTimeout(() => input.write(response), 40 * (index + 1)));
  });
  await cliInternals.runProgramProfileQuestionnaire("multiline-profile", "create", {
    paths,
    input,
    output: terminalOutput,
    interactive: true,
    terminal: false
  });
  input.end();

  const envelope = JSON.parse(fs.readFileSync(path.join(home, "programs", "multiline-profile", "answers.json"), "utf8"));
  assert.equal(
    envelope.answers["identity-objective"],
    "Validate tenant isolation\nand authorization boundaries."
  );
  assert.match(transcript, /multiline; finish with \. on its own line/u);
  assert.match(transcript, /Multiline input: enter \. on its own line to finish\./u);
});

test("interactive numeric questions can record an explicit allowed null", { timeout: 5000 }, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-bounty-null-"));
  const home = path.join(root, "home");
  const paths = runtimePaths({ repo, home });
  const input = new PassThrough();
  const terminalOutput = new Writable({ write(_chunk, _encoding, callback) { callback(); } });
  const timers = [];
  t.after(() => {
    for (const timer of timers) clearTimeout(timer);
    fs.rmSync(root, { recursive: true, force: true });
  });

  ["edit limits-max-spend\n", "null\n", "edit authority-program-url\n", "null\n", "edit authority-valid-from\n", "null\n", "edit authority-valid-until\n", "null\n", "quit\n"].forEach((response, index) => {
    timers.push(setTimeout(() => input.write(response), 40 * (index + 1)));
  });
  await cliInternals.runProgramProfileQuestionnaire("null-spend-profile", "create", {
    paths,
    input,
    output: terminalOutput,
    interactive: true,
    terminal: false
  });
  input.end();

  const envelope = JSON.parse(fs.readFileSync(path.join(home, "programs", "null-spend-profile", "answers.json"), "utf8"));
  assert.equal(Object.hasOwn(envelope.answers, "limits-max-spend"), true);
  for (const id of ["limits-max-spend", "authority-program-url", "authority-valid-from", "authority-valid-until"]) {
    assert.equal(envelope.answers[id], null);
  }
});

test("interactive answer completeness rejects placeholders and preserves explicit values", () => {
  const profile = {};
  const structured = PROGRAM_PROFILE_QUESTIONS.find(({ id }) => id === "web-api-entry-points");
  const multiline = PROGRAM_PROFILE_QUESTIONS.find(({ id }) => id === "web-api-automation-rules");
  const boolean = PROGRAM_PROFILE_QUESTIONS.find(({ type }) => type === "boolean");
  const nullable = PROGRAM_PROFILE_QUESTIONS.find(({ id }) => id === "limits-max-spend");
  const applicableModules = PROGRAM_PROFILE_QUESTIONS.find(({ id }) => id === "coverage-applicable-modules");
  const objective = PROGRAM_PROFILE_QUESTIONS.find(({ id }) => id === "identity-objective");
  const envelope = (value, question = structured) => ({ answers: { [question.id]: value } });

  for (const value of [[], [null], [" \t"], ["\u200b\u200d"], [{}], [[]], [{ selector: "", note: null }]]) {
    assert.equal(cliInternals.questionHasAnswer(structured, profile, envelope(value)), false);
  }
  assert.equal(cliInternals.questionHasAnswer(
    structured,
    profile,
    envelope([{ selector: "https://example.test", note: null }])
  ), true);
  assert.equal(cliInternals.questionHasAnswer(multiline, profile, envelope(" \n\t", multiline)), false);
  assert.equal(cliInternals.questionHasAnswer(multiline, profile, envelope("\u200b\u200d", multiline)), false);
  assert.equal(cliInternals.questionHasAnswer(boolean, profile, envelope(false, boolean)), true);
  assert.equal(cliInternals.questionHasAnswer(nullable, profile, envelope(null, nullable)), true);
  assert.equal(cliInternals.questionHasAnswer(applicableModules, profile, envelope([], applicableModules)), true);
  assert.equal(cliInternals.questionHasAnswer(objective, profile, envelope("\u200b\u200d", objective)), false);
});

test("interactive resume prefers the exact attestation blocker over its broad parent", () => {
  const blockers = [
    { code: "operator-attestation-incomplete", path: "attestation" },
    { code: "ready-contract-incomplete", path: "attestation.answersComplete" }
  ];
  const index = cliInternals.verificationQuestionIndex(PROGRAM_PROFILE_QUESTIONS, blockers);

  assert.equal(PROGRAM_PROFILE_QUESTIONS[index].id, "attestation-answers-complete");
});

test("resume maps a ready-required empty list back to its exact question", { timeout: 5000 }, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-bounty-attestation-resume-"));
  const home = path.join(root, "home");
  const paths = runtimePaths({ repo, home });
  const id = "attestation-resume-profile";
  const now = "2026-10-14T00:00:00.000Z";
  const attestedAt = "2026-10-14T00:01:00.000Z";
  createProgramProfile(id, {}, { paths, now });
  const current = resumeProgramProfile(id, { paths });
  const profile = current.profile;
  const answers = Object.fromEntries(PROGRAM_PROFILE_QUESTIONS
    .filter((question) => question.section && question.required)
    .map((question) => [
      question.id,
      question.id === "attestation-at"
        ? attestedAt
        : ["attestation-answers-complete", "attestation-sources-reviewed", "attestation-scope-reviewed"].includes(question.id)
          ? true
          : structuredClone(profileValueAt(profile, question.path))
    ]));
  const answerEnvelope = structuredClone(current.answers);
  answerEnvelope.metadata.title = "Attestation resume fixture";
  answerEnvelope.metadata.updatedAt = now;
  answerEnvelope.answers = answers;
  applyProgramProfileAnswers(id, answerEnvelope, { paths, now: "2026-10-14T00:01:00.000Z" });

  const input = new PassThrough();
  let transcript = "";
  const terminalOutput = new Writable({
    write(chunk, _encoding, callback) {
      transcript += chunk.toString();
      callback();
    }
  });
  const timer = setTimeout(() => input.write("quit\n"), 40);
  t.after(() => {
    clearTimeout(timer);
    fs.rmSync(root, { recursive: true, force: true });
  });

  await cliInternals.runProgramProfileQuestionnaire(id, "resume", {
    paths,
    input,
    output: terminalOutput,
    interactive: true,
    terminal: false
  });
  input.end();

  assert.match(transcript, /All required answers are recorded\. Verification still has \d+ blocker\(s\); opening identity-deliverables for review\./u);
  assert.match(transcript, /identity-deliverables/u);
  assert.doesNotMatch(transcript, /Resuming at unanswered required question: identity-program-name\./u);
});

test("profile CLI rejects ambiguous and unsupported command surfaces before mutation", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-bounty-boundary-"));
  const home = path.join(root, "home");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const attempts = [
    {
      args: ["bounty", "profile", "create", "duplicate", "--answers", "one.json", "--answers=two.json"],
      message: /option must not be repeated: --answers/u
    },
    {
      args: ["bounty", "profile", "create", "passthrough", "--", "unexpected"],
      message: /do not accept passthrough arguments/u
    },
    {
      args: ["bounty", "profile", "status", "--json=true"],
      message: /--json does not accept a value/u
    },
    {
      args: ["bounty", "profile", "show", "missing", "--format", "yaml"],
      message: /--format must be json, review, or model-context/u
    },
    {
      args: ["bounty", "profile", "compile", "missing", "--contact-target"],
      message: /unsupported option: --contact-target/u
    },
    {
      args: ["bounty", "profile", "status", "one", "two"],
      message: /expected gate bounty profile status \[ID\]/u
    },
    {
      args: ["bounty", "execute", "anything"],
      message: /unknown bounty area: execute/u
    }
  ];

  for (const attempt of attempts) {
    const result = invoke(attempt.args, home);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, attempt.message);
  }
  assert.equal(fs.existsSync(home), false);
});

test("headless answer files create and resume a private draft without activating work", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-bounty-headless-"));
  const home = path.join(root, "home");
  const answersFile = path.join(root, "answers.json");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(answersFile, `${JSON.stringify({
    $schema: "https://gate.local/schemas/bug-bounty-program-profile-answers.schema.json",
    apiVersion: "gate.dev/program-profile-answers/v1",
    kind: "BugBountyProgramProfileAnswers",
    metadata: {
      programId: "headless-profile",
      title: "Headless fixture",
      updatedAt: "2026-10-14T00:00:00.000Z"
    },
    answers: {}
  }, null, 2)}\n`, { mode: 0o600 });

  const created = invoke([
    "bounty", "profile", "create", "headless-profile", "--answers", answersFile, "--json"
  ], home);
  assert.equal(created.status, 0, created.stderr);
  assert.equal(JSON.parse(created.stdout).id, "headless-profile");

  const unboundResume = invoke([
    "bounty", "profile", "resume", "headless-profile", "--answers", answersFile, "--json"
  ], home);
  assert.notEqual(unboundResume.status, 0);
  assert.match(unboundResume.stderr, /not bound to a base profile/u);

  const status = invoke(["bounty", "profile", "status", "headless-profile", "--json"], home);
  assert.equal(status.status, 0, status.stderr);
  const current = JSON.parse(status.stdout);
  const boundAnswers = JSON.parse(fs.readFileSync(answersFile, "utf8"));
  boundAnswers.apiVersion = "gate.dev/program-profile-answers/v2";
  boundAnswers.metadata.baseRevision = current.profile.revision;
  boundAnswers.metadata.baseProfileSha256 = current.profileSha256;
  fs.writeFileSync(answersFile, `${JSON.stringify(boundAnswers, null, 2)}\n`, { mode: 0o600 });

  const resumed = invoke([
    "bounty", "profile", "resume", "headless-profile", "--answers", answersFile, "--json"
  ], home);
  assert.equal(resumed.status, 0, resumed.stderr);
  assert.equal(JSON.parse(resumed.stdout).id, "headless-profile");

  const updatedStatus = invoke(["bounty", "profile", "status", "headless-profile", "--json"], home);
  assert.equal(updatedStatus.status, 0, updatedStatus.stderr);
  assert.equal(JSON.parse(updatedStatus.stdout).id, "headless-profile");

  const shown = invoke([
    "bounty", "profile", "show", "headless-profile", "--format", "json", "--json"
  ], home);
  assert.equal(shown.status, 0, shown.stderr);
  assert.equal(JSON.parse(shown.stdout).metadata.id, "headless-profile");

  const verification = invoke(["bounty", "profile", "verify", "headless-profile", "--json"], home);
  assert.equal(verification.status, 2, verification.stderr);
  assert.equal(JSON.parse(verification.stdout).ready, false);

  const compileArgs = [
    "bounty", "profile", "compile", "headless-profile",
    "--engagement", "headless-assessment", "--workflow", "headless-workflow", "--json"
  ];
  const compiled = invoke(compileArgs, home);
  assert.equal(compiled.status, 2, compiled.stderr);
  const compilation = JSON.parse(compiled.stdout);
  assert.equal(compilation.ok, true);
  assert.equal(compilation.ready, false);
  assert.equal(compilation.targetContact, false);
  assert.equal(compilation.executionAuthority, false);
  assert.ok(Object.values(compilation.artifacts).every((artifact) => artifact.ref.startsWith("private://programs/")));

  const repeated = invoke(compileArgs, home);
  assert.equal(repeated.status, 2, repeated.stderr);
  const repeatedCompilation = JSON.parse(repeated.stdout);
  assert.notEqual(repeatedCompilation.compilationId, compilation.compilationId);
  assert.equal(repeatedCompilation.created, true);
  assert.deepEqual(fs.readdirSync(path.join(home, "engagements")), []);
  assert.deepEqual(fs.readdirSync(path.join(home, "workflows")), []);
});
