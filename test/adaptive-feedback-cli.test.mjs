import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

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

function fixture(t, prefix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const home = path.join(root, "home");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, home };
}

function jsonFile(root, name, value) {
  const file = path.join(root, name);
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  return file;
}

function parsed(result) {
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

function repositoryHead() {
  const result = spawnSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const head = result.stdout.trim();
  assert.match(head, /^[a-f0-9]{40}$/u);
  return head;
}

test("help exposes file-driven adaptive learning and workflow feedback", (t) => {
  const { home } = fixture(t, "gate-adaptive-help-");
  const result = invoke(["help"], home);

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /learn cycle --file FILE/u);
  assert.match(result.stdout, /learn promote ID --file FILE/u);
  assert.match(result.stdout, /learn consult --file FILE \[--limit N\] \[--max-bytes N\]/u);
  assert.match(result.stdout, /workflow test plan ID --file FILE/u);
  assert.match(result.stdout, /workflow test review ID --file FILE/u);
});

test("legacy private learning remains compatible", (t) => {
  const { home } = fixture(t, "gate-adaptive-legacy-");
  const result = invoke([
    "learn",
    "--cause", "A bounded legacy CLI fixture observed a retry.",
    "--change", "Keep the legacy cause and change command available.",
    "--private",
    "--scope", "session",
    "--json"
  ], home);
  const learning = parsed(result);

  assert.equal(learning.scope, "session");
  assert.equal(learning.sensitivity, "private");
  assert.equal(learning.cause, "A bounded legacy CLI fixture observed a retry.");
  assert.equal(learning.change, "Keep the legacy cause and change command available.");
});

test("learning cycle, promotion, and bounded consultation use files without echoing private narrative", (t) => {
  const { root, home } = fixture(t, "gate-adaptive-learning-");
  const applicability = [
    { kind: "component", id: "adaptive-cli", version: "1.0.0" },
    { kind: "environment", id: "local-test" }
  ];
  const privateNarratives = [
    "PRIVATE_HYPOTHESIS_CANARY tests a bounded local behavior.",
    "PRIVATE_METHOD_CANARY uses the local fixture once.",
    "PRIVATE_OUTCOME_CANARY showed the oracle was ambiguous.",
    "PRIVATE_LESSON_CANARY says the oracle needs another signal.",
    "PRIVATE_ADJUSTMENT_CANARY adds that signal before retrying."
  ];
  const cycleFile = jsonFile(root, "learning-cycle.json", {
    trigger: "test-strategy-revision",
    domain: "software-testing",
    cycle: {
      hypothesis: privateNarratives[0],
      method: privateNarratives[1],
      outcome: { disposition: "inconclusive", summary: privateNarratives[2] },
      lesson: privateNarratives[3],
      nextAdjustment: privateNarratives[4]
    },
    applicability
  });
  const cycleResult = invoke(["learn", "cycle", "--file", cycleFile], home);
  const candidate = parsed(cycleResult);

  assert.equal(candidate.ok, true);
  assert.match(candidate.id, /^lrn_[A-Za-z0-9_-]+$/u);
  assert.equal(candidate.status, "proposed");
  assert.equal(candidate.scope, "session");
  assert.equal(candidate.sensitivity, "private");
  assert.equal(candidate.promotionState, "candidate");
  assert.match(candidate.candidateSha256, /^[a-f0-9]{64}$/u);
  assert.equal(candidate.applicabilityCount, applicability.length);
  assert.doesNotMatch(cycleResult.stdout, /PRIVATE_[A-Z_]+_CANARY/u);

  const promotionFile = jsonFile(root, "learning-promotion.json", {
    validationRefs: ["private://workflows/adaptive-cli/review"],
    changeRefs: ["evidence://adaptive-cli-regression"],
    review: {
      owner: "no-mistakes",
      attestationRef: "evidence://no-mistakes/adaptive-cli",
      attestationSha256: "b".repeat(64),
      candidateSha256: candidate.candidateSha256,
      headSha: repositoryHead()
    }
  });
  const promotionResult = invoke([
    "learn", "promote", candidate.id,
    "--file", promotionFile
  ], home);
  const promoted = parsed(promotionResult);

  assert.equal(promoted.ok, true);
  assert.equal(promoted.status, "active");
  assert.equal(promoted.sensitivity, "private");
  assert.equal(promoted.supersedes, candidate.id);
  assert.equal(promoted.promotionState, "validated");
  assert.equal(promoted.candidateSha256, candidate.candidateSha256);
  assert.doesNotMatch(promotionResult.stdout, /PRIVATE_[A-Z_]+_CANARY/u);

  const consultationFile = jsonFile(root, "learning-consultation.json", { applicability });
  const consultation = parsed(invoke([
    "learn", "consult", "--file", consultationFile,
    "--limit", "2", "--max-bytes", "1024"
  ], home));

  assert.equal(consultation.apiVersion, "gate.learning-consultation/v1");
  assert.deepEqual(consultation.selected, []);
  assert.match(consultation.ledgerHeadSha256, /^[a-f0-9]{64}$/u);
  assert.match(consultation.projectionSha256, /^[a-f0-9]{64}$/u);
  assert.doesNotMatch(JSON.stringify(consultation), /PRIVATE_[A-Z_]+_CANARY/u);

  const privateLedger = fs.readFileSync(path.join(home, "memory", "private", "learnings.jsonl"), "utf8");
  for (const narrative of privateNarratives) assert.match(privateLedger, new RegExp(narrative.split(" ")[0], "u"));
});

test("workflow test plan and review accept private JSON files and emit compact receipts", (t) => {
  const { root, home } = fixture(t, "gate-adaptive-workflow-");
  const instanceId = "adaptive-cli";
  parsed(invoke(["--unassigned", "workflow", "new", instanceId, "--json"], home));
  const started = parsed(invoke([
    "--unassigned", "workflow", "phase", "start", instanceId,
    "--phase", "authorization-and-roe",
    "--json"
  ], home));
  const attemptId = started.event.details.attemptId;
  const workflow = parsed(invoke(["--unassigned", "workflow", "status", instanceId, "--json"], home));
  const learningApplicability = [
    {
      kind: "workflow",
      id: workflow.contract.id,
      version: String(workflow.contract.version),
      digest: workflow.contract.sha256
    },
    { kind: "phase", id: "authorization-and-roe" }
  ];
  const consultationFile = jsonFile(root, "workflow-learning-consultation.json", {
    applicability: learningApplicability
  });
  const consultation = parsed(invoke([
    "learn", "consult", "--file", consultationFile
  ], home));

  const hypothesis = "PRIVATE_HYPOTHESIS_CANARY only appears in the plan file.";
  const method = "PRIVATE_METHOD_CANARY describes the exact local experiment.";
  const planFile = jsonFile(root, "test-plan.json", {
    phaseId: "authorization-and-roe",
    attemptId,
    hypothesis,
    method,
    expectedSignal: "PRIVATE_EXPECTED_CANARY is observed.",
    contrarySignal: "PRIVATE_CONTRARY_CANARY is observed.",
    learningApplicability,
    learningIds: consultation.selected.map((learning) => learning.id),
    learningLedgerHeadSha256: consultation.ledgerHeadSha256,
    learningProjectionSha256: consultation.projectionSha256,
    basisEvidenceSha256: [],
    priorReviewEntrySha256: null,
    adaptation: null
  });
  const plannedResult = invoke([
    "--unassigned", "workflow", "test", "plan", instanceId,
    "--file", planFile,
    "--expected-sequence", String(started.event.sequence),
    "--expected-head", started.event.headSha256
  ], home);
  const planned = parsed(plannedResult);

  assert.equal(planned.event.type, "test.planned");
  assert.match(planned.event.details.testId, /^wtest_[a-f0-9]{32}$/u);
  assert.equal(planned.event.details.attemptId, attemptId);
  assert.equal(planned.event.details.learningCount, 0);
  assert.doesNotMatch(plannedResult.stdout, /PRIVATE_(?:HYPOTHESIS|METHOD|EXPECTED|CONTRARY)_CANARY/u);

  const reviewFile = jsonFile(root, "test-review.json", {
    testId: planned.event.details.testId,
    phaseId: "authorization-and-roe",
    attemptId,
    planEntrySha256: planned.event.headSha256,
    disposition: "inconclusive",
    observation: "PRIVATE_OBSERVATION_CANARY remains only in private workflow state.",
    evidenceSha256: [],
    metrics: { "duration-ms": 12, tokens: "unavailable" },
    usefulMistake: {
      cause: "PRIVATE_CAUSE_CANARY identified an ambiguous oracle.",
      change: "PRIVATE_CHANGE_CANARY will add a discriminating local fixture."
    },
    nextStrategy: {
      decision: "iterate-within-current-envelope",
      rationale: "PRIVATE_RATIONALE_CANARY explains the bounded successor."
    }
  });
  const reviewedResult = invoke([
    "--unassigned", "workflow", "test", "review", instanceId,
    "--file", reviewFile,
    "--expected-sequence", String(planned.event.sequence),
    "--expected-head", planned.event.headSha256
  ], home);
  const reviewed = parsed(reviewedResult);

  assert.equal(reviewed.event.type, "test.reviewed");
  assert.equal(reviewed.event.details.testId, planned.event.details.testId);
  assert.equal(reviewed.event.details.disposition, "inconclusive");
  assert.equal(reviewed.event.details.nextDecision, "iterate-within-current-envelope");
  assert.doesNotMatch(
    reviewedResult.stdout,
    /PRIVATE_(?:OBSERVATION|CAUSE|CHANGE|RATIONALE)_CANARY/u
  );

  const status = parsed(invoke(["--unassigned", "workflow", "status", instanceId, "--json"], home));
  assert.deepEqual(status.testFeedback, {
    total: 1,
    reviewed: 1,
    open: 0,
    openTestId: null,
    latestReviewSha256: reviewed.event.headSha256
  });
});

test("file-driven adaptive commands reject malformed JSON before mutation", (t) => {
  const { root, home } = fixture(t, "gate-adaptive-malformed-");
  const file = path.join(root, "malformed.json");
  fs.writeFileSync(file, "{not-json\n", { mode: 0o600 });
  const attempts = [
    ["learn", "cycle", "--file", file],
    ["learn", "promote", "lrn_fixture01", "--file", file],
    ["learn", "consult", "--file", file],
    ["--unassigned", "workflow", "test", "plan", "missing-workflow", "--file", file],
    ["--unassigned", "workflow", "test", "review", "missing-workflow", "--file", file]
  ];

  for (const args of attempts) {
    const result = invoke(args, home);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /file is malformed JSON/u);
  }
  assert.equal(fs.existsSync(home), false);
});
