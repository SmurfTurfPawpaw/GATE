import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { PENTEST_COVERAGE_DOMAINS } from "../src/lib/pentest-workflow.mjs";
import { runtimePaths } from "../src/lib/paths.mjs";
import {
  addWorkflowEvidence,
  attachWorkflowReport,
  closeWorkflow,
  createWorkflowInstance,
  finishWorkflowPhase,
  joinWorkflowCoverage,
  setWorkflowCoverage,
  startWorkflowPhase,
  stopWorkflow,
  workflowRuntimeInternals,
  workflowStatus
} from "../src/lib/workflow-runtime.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const definition = JSON.parse(fs.readFileSync(path.join(repo, "config", "workflows", "pentest-e2e.json"), "utf8"));
const requestId = (digit) => `wreq_${digit.repeat(32)}`;

function fixture(t, prefix = "gate-workflow-runtime-") {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const paths = runtimePaths({ home: path.join(root, "home"), repo });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, paths };
}

function inputFile(root, name, contents = `${name}\n`) {
  const file = path.join(root, name);
  fs.writeFileSync(file, contents, { mode: 0o600 });
  return file;
}

function addDeclaredEvidence(id, phaseId, records, root, paths) {
  for (const record of records) {
    addWorkflowEvidence(id, {
      phaseId,
      evidenceId: record.id,
      claimState: record.claimState,
      file: inputFile(root, `${phaseId}-${record.id}.txt`, `${record.id}: bounded offline fixture evidence\n`)
    }, { paths });
  }
}

function completeFoundation(id, root, paths) {
  const authorization = definition.phases.find((phase) => phase.id === "authorization-and-roe");
  const mapping = definition.phases.find((phase) => phase.id === "target-and-architecture-map");

  startWorkflowPhase(id, { phaseId: authorization.id }, { paths });
  addDeclaredEvidence(id, authorization.id, authorization.evidence.filter((record) => record.required), root, paths);
  finishWorkflowPhase(id, { phaseId: authorization.id, disposition: "tested" }, { paths });

  startWorkflowPhase(id, {
    phaseId: mapping.id,
    sourcePhase: authorization.id
  }, { paths });
  addDeclaredEvidence(id, mapping.id, mapping.evidence.filter((record) => record.required), root, paths);
  finishWorkflowPhase(id, { phaseId: mapping.id, disposition: "tested" }, { paths });
}

function instanceFiles(paths, id) {
  const directory = path.join(paths.workflows, id);
  return {
    directory,
    journal: path.join(directory, "journal.jsonl"),
    projection: path.join(directory, "instance.json")
  };
}

test("offline workflow cannot report or close with blocked retest", (t) => {
  const { root, paths } = fixture(t, "gate-workflow-lifecycle-");
  const id = "offline-lifecycle";
  const created = createWorkflowInstance(id, {}, { paths });
  assert.equal(created.ok, true);
  assert.equal(created.contract.coverageDomainCount, 18);

  completeFoundation(id, root, paths);

  const conditional = definition.phases.filter((phase) =>
    phase.applicability.mode === "conditional" && phase.id !== "recovery-hold"
  );
  for (const phase of conditional) {
    finishWorkflowPhase(id, {
      phaseId: phase.id,
      disposition: "blocked",
      rationale: "Offline fixture has no authorized live target; the workstream remains explicitly untested."
    }, { paths });
  }

  assert.deepEqual(PENTEST_COVERAGE_DOMAINS, definition.coverageDomains);
  for (const domain of PENTEST_COVERAGE_DOMAINS) {
    setWorkflowCoverage(id, {
      domain,
      disposition: "blocked",
      evidenceSha256: [],
      rationale: "No authorized live target was supplied to this offline workflow fixture."
    }, { paths });
  }

  const joined = joinWorkflowCoverage(id, {}, { paths });
  assert.equal(joined.entry.type, "coverage.joined");
  assert.equal(joined.projection.joined.ledgerState, "empty");

  const reportBytes = Buffer.from("# Offline workflow report\n\nAll target-contact coverage is explicitly blocked.\n");
  const reportFile = inputFile(root, "report.md", reportBytes);
  const reportSha256 = crypto.createHash("sha256").update(reportBytes).digest("hex");
  assert.throws(() => attachWorkflowReport(id, { file: reportFile }, { paths }), /completed retest/u);
  assert.throws(() => closeWorkflow(id, { confirm: `CLOSE ${id} ${reportSha256}` }, { paths }), /completed retest/u);
  const status = workflowStatus(id, { paths });
  assert.equal(status.ok, true);
  assert.equal(status.status, "open");
  assert.equal(status.coverage.recorded, 18);
  assert.equal(status.joined, true);
  assert.equal(status.reportSha256, null);

  const files = instanceFiles(paths, id);
  assert.equal(fs.statSync(files.directory).mode & 0o777, 0o700);
  assert.equal(fs.statSync(files.journal).mode & 0o777, 0o600);
  assert.equal(fs.statSync(files.projection).mode & 0o777, 0o600);
});

test("request IDs replay exact content once and reject content changes", (t) => {
  const { paths } = fixture(t, "gate-workflow-replay-");
  const id = "request-replay";
  createWorkflowInstance(id, {}, { paths });
  const input = {
    domain: PENTEST_COVERAGE_DOMAINS[0],
    disposition: "blocked",
    evidenceSha256: [],
    rationale: "No authorized target exists in this offline replay fixture."
  };
  const options = { paths, requestId: requestId("1") };

  const first = setWorkflowCoverage(id, input, options);
  assert.equal(first.replayed, false);
  const replay = setWorkflowCoverage(id, structuredClone(input), options);
  assert.equal(replay.replayed, true);
  assert.equal(replay.entry.entrySha256, first.entry.entrySha256);
  assert.equal(replay.projection.appliedSequence, first.projection.appliedSequence);

  assert.throws(
    () => setWorkflowCoverage(id, { ...input, rationale: "Different request content." }, options),
    /request id was reused with different content/u
  );
  const lines = fs.readFileSync(instanceFiles(paths, id).journal, "utf8").trimEnd().split("\n");
  assert.equal(lines.length, 2);
});

test("an exact projection prefix is repaired but a validly resealed same-head mismatch blocks", (t) => {
  const { paths } = fixture(t, "gate-workflow-projection-");
  const id = "projection-recovery";
  createWorkflowInstance(id, {}, { paths });
  const files = instanceFiles(paths, id);
  const genesisProjection = fs.readFileSync(files.projection);

  const started = startWorkflowPhase(id, { phaseId: "authorization-and-roe" }, { paths });
  assert.equal(started.projection.appliedSequence, 1);
  fs.writeFileSync(files.projection, genesisProjection, { mode: 0o600 });

  const repaired = workflowStatus(id, { paths });
  assert.equal(repaired.ok, true);
  assert.equal(repaired.journal.sequence, 1);
  const current = JSON.parse(fs.readFileSync(files.projection, "utf8"));
  assert.equal(current.appliedSequence, 1);
  assert.equal(current.journalHeadSha256, started.entry.entrySha256);

  current.status = "stopped";
  current.projectionSha256 = workflowRuntimeInternals.canonicalDigest(
    workflowRuntimeInternals.projectionEnvelope(current),
    "gate.workflow.projection.v1"
  );
  fs.writeFileSync(files.projection, `${JSON.stringify(current, null, 2)}\n`, { mode: 0o600 });
  const blocked = workflowStatus(id, { paths });
  assert.equal(blocked.ok, false);
  assert.equal(blocked.status, "blocked");
  assert.match(blocked.blocker, /differs from the journal at the same head/u);
});

test("projection recovery validates the current workflow contract before writing repairs", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-workflow-contract-recovery-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const isolatedRepo = path.join(root, "repo");
  for (const directory of ["catalog", "config", "policies", "schemas"]) {
    fs.cpSync(path.join(repo, directory), path.join(isolatedRepo, directory), { recursive: true });
  }
  const paths = runtimePaths({ home: path.join(root, "home"), repo: isolatedRepo });
  const id = "contract-recovery";
  createWorkflowInstance(id, {}, { paths });
  const files = instanceFiles(paths, id);
  const genesisProjection = fs.readFileSync(files.projection);

  startWorkflowPhase(id, { phaseId: "authorization-and-roe" }, { paths });
  fs.writeFileSync(files.projection, genesisProjection, { mode: 0o600 });

  const workflowFile = path.join(isolatedRepo, "config", "workflows", "pentest-e2e.json");
  const upgraded = JSON.parse(fs.readFileSync(workflowFile, "utf8"));
  upgraded.metadata.version += 1;
  fs.writeFileSync(workflowFile, `${JSON.stringify(upgraded, null, 2)}\n`);

  const blockedPrefixRepair = workflowStatus(id, { paths });
  assert.equal(blockedPrefixRepair.ok, false);
  assert.match(blockedPrefixRepair.blocker, /no longer matches the installed contract/u);
  assert.equal(JSON.parse(fs.readFileSync(files.projection, "utf8")).appliedSequence, 0);

  fs.unlinkSync(files.projection);
  const blockedMissingRepair = workflowStatus(id, { paths });
  assert.equal(blockedMissingRepair.ok, false);
  assert.match(blockedMissingRepair.blocker, /no longer matches the installed contract/u);
  assert.equal(fs.existsSync(files.projection), false);
});

test("a truncated authoritative journal blocks status", (t) => {
  const { paths } = fixture(t, "gate-workflow-truncated-");
  const id = "truncated-journal";
  createWorkflowInstance(id, {}, { paths });
  const journal = instanceFiles(paths, id).journal;
  const bytes = fs.readFileSync(journal);
  fs.writeFileSync(journal, bytes.subarray(0, bytes.length - 1), { mode: 0o600 });

  const status = workflowStatus(id, { paths });
  assert.equal(status.ok, false);
  assert.equal(status.status, "blocked");
  assert.match(status.blocker, /truncated tail/u);
});

test("a structurally valid journal edit without a matching digest blocks status", (t) => {
  const { paths } = fixture(t, "gate-workflow-tampered-");
  const id = "tampered-journal";
  createWorkflowInstance(id, {}, { paths });
  const journal = instanceFiles(paths, id).journal;
  const entry = JSON.parse(fs.readFileSync(journal, "utf8"));
  entry.payload.engagementId = "other-engagement";
  fs.writeFileSync(journal, `${JSON.stringify(entry)}\n`, { mode: 0o600 });

  const status = workflowStatus(id, { paths });
  assert.equal(status.ok, false);
  assert.equal(status.status, "blocked");
  assert.match(status.blocker, /entry digest is invalid/u);
});

test("stale expected sequence and journal head reject mutations without appending", (t) => {
  const { paths } = fixture(t, "gate-workflow-stale-");
  const id = "stale-writer";
  const created = createWorkflowInstance(id, {}, { paths });
  setWorkflowCoverage(id, {
    domain: PENTEST_COVERAGE_DOMAINS[0],
    disposition: "untested",
    rationale: "Initial offline disposition."
  }, { paths });

  assert.throws(
    () => setWorkflowCoverage(id, {
      domain: PENTEST_COVERAGE_DOMAINS[1],
      disposition: "untested",
      rationale: "Stale sequence fixture."
    }, { paths, expectedSequence: created.journal.sequence }),
    /workflow sequence changed/u
  );
  assert.throws(
    () => setWorkflowCoverage(id, {
      domain: PENTEST_COVERAGE_DOMAINS[1],
      disposition: "untested",
      rationale: "Stale head fixture."
    }, { paths, expectedSequence: 1, expectedHead: created.journal.headSha256 }),
    /journal head changed/u
  );
  assert.equal(workflowStatus(id, { paths }).journal.sequence, 1);
});

test("invalid traversal-like instance IDs fail before runtime state is written", (t) => {
  const { paths } = fixture(t, "gate-workflow-id-");
  assert.equal(fs.existsSync(paths.home), false);
  assert.throws(
    () => createWorkflowInstance("../escape", {}, { paths }),
    /workflow instance id must use/u
  );
  assert.equal(fs.existsSync(paths.home), false);
});

test("a mandatory stop blocks normal phase progress", (t) => {
  const { paths } = fixture(t, "gate-workflow-stop-");
  const id = "stopped-workflow";
  createWorkflowInstance(id, {}, { paths });
  stopWorkflow(id, {
    condition: "operator-stop",
    reason: "Operator stopped the offline fixture before work began."
  }, { paths });

  assert.throws(
    () => startWorkflowPhase(id, { phaseId: "authorization-and-roe" }, { paths }),
    /fired stop blocks normal phase progress/u
  );
  const status = workflowStatus(id, { paths });
  assert.equal(status.status, "stopped");
  assert.equal(status.activePhase, null);
  assert.equal(status.journal.sequence, 1);
});

test("an A3 phase fails closed before target contact when admission and handoff are absent", (t) => {
  const { root, paths } = fixture(t, "gate-workflow-a3-");
  const id = "a3-fail-closed";
  createWorkflowInstance(id, {}, { paths });
  completeFoundation(id, root, paths);
  const before = workflowStatus(id, { paths });

  assert.throws(
    () => startWorkflowPhase(id, {
      phaseId: "embedded-iot-ot-testing",
      sourcePhase: "target-and-architecture-map",
      handoffId: "high-impact-handoff-01"
    }, { paths }),
    /requires a reviewed admission file/u
  );
  const after = workflowStatus(id, { paths });
  assert.equal(after.ok, true);
  assert.equal(after.activePhase, null);
  assert.equal(after.journal.sequence, before.journal.sequence);
  assert.equal(after.journal.headSha256, before.journal.headSha256);
});

test("workflow creation rejects alternate definition selection", (t) => {
  const { paths } = fixture(t);
  assert.throws(() => createWorkflowInstance("alternate-definition", { definitionId: "pentest-e2e" }, { paths }), /unsupported/u);
});
