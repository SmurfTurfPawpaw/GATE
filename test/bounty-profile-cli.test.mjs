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
import { PROGRAM_PROFILE_QUESTIONS } from "../src/lib/program-profile-contract.mjs";
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
  const profileRoot = path.join(home, "programs", "interactive-profile");
  const envelope = JSON.parse(fs.readFileSync(path.join(profileRoot, "answers.json"), "utf8"));
  assert.equal(envelope.answers[PROGRAM_PROFILE_QUESTIONS[0].id], "Interactive fixture");
  const profile = JSON.parse(fs.readFileSync(path.join(profileRoot, "program-profile.json"), "utf8"));
  assert.equal(profile.questionnaire.sectionStatus[PROGRAM_PROFILE_QUESTIONS[0].section], "in-progress");
  assert.equal(profile.questionnaire.activeSection, PROGRAM_PROFILE_QUESTIONS[0].section);
  assert.match(transcript, new RegExp(PROGRAM_PROFILE_QUESTIONS[0].why.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  assert.match(transcript, new RegExp(`Saved ${PROGRAM_PROFILE_QUESTIONS[0].id}\\.`, "u"));
  assert.match(transcript, /Every accepted answer is already persisted privately\./u);
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
  createProgramProfile(id, {}, { paths, now });
  const profile = resumeProgramProfile(id, { paths }).profile;
  const answers = Object.fromEntries(PROGRAM_PROFILE_QUESTIONS
    .filter((question) => question.section && question.required)
    .map((question) => [
      question.id,
      question.id === "attestation-at" ? now : structuredClone(profileValueAt(profile, question.path))
    ]));
  applyProgramProfileAnswers(id, {
    $schema: "https://gate.local/schemas/bug-bounty-program-profile-answers.schema.json",
    apiVersion: "gate.dev/program-profile-answers/v1",
    kind: "BugBountyProgramProfileAnswers",
    metadata: { programId: id, title: "Attestation resume fixture", updatedAt: now },
    answers
  }, { paths, now: "2026-10-14T00:01:00.000Z" });

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

  const resumed = invoke([
    "bounty", "profile", "resume", "headless-profile", "--answers", answersFile, "--json"
  ], home);
  assert.equal(resumed.status, 0, resumed.stderr);
  assert.equal(JSON.parse(resumed.stdout).id, "headless-profile");

  const status = invoke(["bounty", "profile", "status", "headless-profile", "--json"], home);
  assert.equal(status.status, 0, status.stderr);
  assert.equal(JSON.parse(status.stdout).id, "headless-profile");

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
