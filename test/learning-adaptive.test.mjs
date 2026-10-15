import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { runtimePaths } from "../src/lib/paths.mjs";
import {
  addLearning,
  addLearningCycle,
  consultLearnings,
  learningCandidateSha256,
  promoteLearning,
  verifyLearningConsultationSnapshot
} from "../src/lib/learnings.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const learningModule = pathToFileURL(path.join(repo, "src", "lib", "learnings.mjs")).href;
const execFileAsync = promisify(execFile);
const reviewedHead = "c".repeat(40);

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-adaptive-learning-"));
  const fixtureRepo = path.join(root, "repository");
  fs.mkdirSync(fixtureRepo, { recursive: true });
  fs.cpSync(path.join(repo, "schemas"), path.join(fixtureRepo, "schemas"), { recursive: true });
  fs.copyFileSync(path.join(repo, "package.json"), path.join(fixtureRepo, "package.json"));
  const paths = runtimePaths({ home: path.join(root, "home"), repo: fixtureRepo });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return paths;
}

const applicability = Object.freeze([
  { kind: "component", id: "learning-runtime", version: "1.0.0" },
  { kind: "test", id: "learning-adaptive", digest: "a".repeat(64) }
]);

function cycle(overrides = {}) {
  const base = {
    hypothesis: "A focused test will isolate the behavior.",
    method: "Run the deterministic focused test once.",
    outcome: {
      disposition: "confirmed",
      summary: "The focused test isolated the behavior."
    },
    lesson: "Focused tests make this behavior easier to diagnose.",
    nextAdjustment: "Run the focused test before the full suite."
  };
  return {
    ...base,
    ...overrides,
    outcome: { ...base.outcome, ...(overrides.outcome || {}) }
  };
}

function addCandidate(paths, overrides = {}) {
  return addLearningCycle({
    trigger: "test-outcome",
    domain: "software-testing",
    cycle: cycle(),
    applicability,
    ...overrides
  }, { paths });
}

function reviewFor(candidate, overrides = {}) {
  return {
    owner: "no-mistakes",
    attestationRef: "evidence://no-mistakes/learning-adaptive",
    attestationSha256: "b".repeat(64),
    candidateSha256: learningCandidateSha256(candidate),
    headSha: reviewedHead,
    ...overrides
  };
}

function promotePublic(paths, candidate, overrides = {}) {
  return promoteLearning(candidate.id, {
    sensitivity: "public",
    validationRefs: ["evidence://test/learning-adaptive"],
    changeRefs: ["evidence://test/learning-adaptive"],
    review: reviewFor(candidate),
    ...overrides
  }, { paths });
}

test("v1 records remain readable and invalid input emits no observed event", (t) => {
  const paths = fixture(t);
  const learning = addLearning({
    cause: "A legacy behavior was observed.",
    change: "Keep the legacy record readable."
  }, { paths });
  assert.equal(learning.apiVersion, "gate.learning/v1");
  assert.equal(JSON.parse(fs.readFileSync(paths.publicLearningRecords, "utf8")).apiVersion, "gate.learning/v1");

  const rejectedPaths = fixture(t);
  assert.throws(
    () => addLearning({
      cause: "An invalid evidence reference was supplied.",
      change: "Reject it before recording an event.",
      evidence: ["invalid-reference"]
    }, { paths: rejectedPaths }),
    /learning\.schema\.json validation failed/u
  );
  assert.equal(fs.existsSync(rejectedPaths.events), false);

  const namedIdPaths = fixture(t);
  assert.throws(
    () => addLearning({
      id: "lrn_named_client_canary",
      cause: "A legacy behavior was observed.",
      change: "Use an opaque generated identifier."
    }, { paths: namedIdPaths }),
    /opaque GATE-generated ids/u
  );
  assert.throws(
    () => addLearning({
      cause: "A legacy behavior was updated.",
      change: "Use an opaque generated predecessor identifier.",
      supersedes: "lrn_named_client_canary"
    }, { paths: namedIdPaths }),
    /opaque GATE-generated ids/u
  );
});

test("structured cycles default to private proposed candidates", (t) => {
  const paths = fixture(t);
  const learning = addCandidate(paths);
  assert.equal(learning.apiVersion, "gate.learning/v2");
  assert.equal(learning.sensitivity, "private");
  assert.equal(learning.scope, "session");
  assert.equal(learning.status, "proposed");
  assert.equal(learning.supersedes, null);
  assert.deepEqual(learning.promotion, {
    state: "candidate",
    candidateId: null,
    candidateSha256: null,
    validatedAt: null,
    validationRefs: [],
    changeRefs: [],
    review: null,
    conflictsWith: [],
    replaces: []
  });
  assert.equal(learning.cause, learning.cycle.outcome.summary);
  assert.equal(learning.change, learning.cycle.nextAdjustment);
  assert.equal(fs.readFileSync(paths.privateLearnings, "utf8").trim().split("\n").length, 1);
  assert.throws(
    () => addCandidate(paths, { sensitivity: "public" }),
    /must remain private/u
  );
});

test("every structured-cycle narrative is secret checked before audit", (t) => {
  const names = ["hypothesis", "method", "summary", "lesson", "nextAdjustment"];
  for (const name of names) {
    const paths = fixture(t);
    const secret = ["api", "_key=", "synthetic-secret-value"].join("");
    const value = cycle();
    if (name === "summary") value.outcome.summary = `Observed ${secret}`;
    else value[name] = `Observed ${secret}`;
    assert.throws(
      () => addCandidate(paths, { cycle: value }),
      /credential/u,
      name
    );
    assert.equal(fs.existsSync(paths.events), false, name);
  }
});

test("promotion is append-only, digest-bound, and requires validation and change references", (t) => {
  const paths = fixture(t);
  const candidate = addCandidate(paths);
  assert.throws(
    () => promoteLearning(candidate.id, {
      validationRefs: [],
      changeRefs: ["evidence://test/learning-adaptive"],
      review: reviewFor(candidate)
    }, { paths }),
    /validationRefs must contain at least 1 reference/u
  );
  assert.throws(
    () => promoteLearning(candidate.id, {
      validationRefs: ["evidence://test/learning-adaptive"],
      changeRefs: ["evidence://test/learning-adaptive"]
    }, { paths }),
    /review must be a No Mistakes attestation object/u
  );
  assert.throws(
    () => promoteLearning(candidate.id, {
      validationRefs: ["evidence://test/learning-adaptive"],
      changeRefs: ["evidence://test/learning-adaptive"],
      review: reviewFor(candidate, { candidateSha256: "d".repeat(64) })
    }, { paths }),
    /does not match the exact learning candidate/u
  );
  assert.throws(
    () => promoteLearning(candidate.id, {
      id: candidate.id,
      sensitivity: "public",
      validationRefs: ["evidence://test/learning-adaptive"],
      changeRefs: ["evidence://test/learning-adaptive"],
      review: reviewFor(candidate)
    }, { paths }),
    /already exists across the learning ledgers/u
  );
  for (const [field, value] of [
    ["cause", "Replace the candidate cause."],
    ["change", "Replace the candidate change."],
    ["configurationRefs", []],
    ["trigger", "replacement-trigger"],
    ["domain", "general"],
    ["cycle", cycle({ lesson: "Replace the candidate lesson." })],
    ["applicability", [{ kind: "component", id: "replacement" }]]
  ]) {
    assert.throws(
      () => promoteLearning(candidate.id, {
        validationRefs: ["evidence://test/learning-adaptive"],
        changeRefs: ["evidence://test/learning-adaptive"],
        review: reviewFor(candidate),
        [field]: value
      }, { paths }),
      /cannot replace candidate content/u,
      field
    );
  }
  const promoted = promoteLearning(candidate.id, {
    validationRefs: ["private://workflows/example/result"],
    changeRefs: ["evidence://test/learning-adaptive"],
    review: reviewFor(candidate)
  }, { paths });
  assert.equal(promoted.status, "active");
  assert.equal(promoted.sensitivity, "private");
  assert.equal(promoted.supersedes, candidate.id);
  assert.equal(promoted.promotion.state, "validated");
  assert.equal(promoted.promotion.candidateId, candidate.id);
  assert.match(promoted.promotion.candidateSha256, /^[a-f0-9]{64}$/u);
  assert.equal(promoted.promotion.review.candidateSha256, promoted.promotion.candidateSha256);
  assert.equal(promoted.promotion.review.headSha, reviewedHead);
  assert.deepEqual(promoted.cycle, candidate.cycle);
  assert.deepEqual(promoted.applicability, candidate.applicability);
  assert.equal(fs.readFileSync(paths.privateLearnings, "utf8").trim().split("\n").length, 2);
  assert.throws(
    () => promoteLearning(candidate.id, {
      validationRefs: ["evidence://test/learning-adaptive"],
      changeRefs: ["evidence://test/learning-adaptive"],
      review: reviewFor(candidate)
    }, { paths }),
    /already promoted/u
  );
});

test("public promotion rejects private evidence, target identifiers, and private paths", (t) => {
  const privateRefPaths = fixture(t);
  const privateRefCandidate = addCandidate(privateRefPaths);
  assert.throws(
    () => promotePublic(privateRefPaths, privateRefCandidate, {
      validationRefs: ["private://workflows/example/result"]
    }),
    /private:\/\/ evidence/u
  );

  const targetPaths = fixture(t);
  const targetCandidate = addCandidate(targetPaths, {
    cycle: cycle({ hypothesis: "Probe https://target.example/private for the observed behavior." })
  });
  assert.throws(
    () => promotePublic(targetPaths, targetCandidate),
    /target or source URL/u
  );

  const bareHostnamePaths = fixture(t);
  const bareHostnameCandidate = addCandidate(bareHostnamePaths, {
    cycle: cycle({ lesson: "Replay the discriminating check against canary-target.invalid." })
  });
  assert.throws(
    () => promotePublic(bareHostnamePaths, bareHostnameCandidate),
    /likely target hostname/u
  );

  const hostnameReferencePaths = fixture(t);
  const hostnameReferenceCandidate = addCandidate(hostnameReferencePaths);
  assert.throws(
    () => promotePublic(hostnameReferencePaths, hostnameReferenceCandidate, {
      validationRefs: ["evidence://canary-target.invalid"]
    }),
    /likely target hostname/u
  );

  const dottedIdentifierPaths = fixture(t);
  const dottedIdentifierCandidate = addCandidate(dottedIdentifierPaths, {
    cycle: cycle({ lesson: "Replay the client-specific synthetic-module.py behavior." })
  });
  assert.throws(
    () => promotePublic(dottedIdentifierPaths, dottedIdentifierCandidate),
    /dotted identifier/u
  );

  const ipv6Paths = fixture(t);
  const ipv6Candidate = addCandidate(ipv6Paths, {
    cycle: cycle({ nextAdjustment: "Retry against 2001:db8::1234 after validation." })
  });
  assert.throws(
    () => promotePublic(ipv6Paths, ipv6Candidate),
    /IP address/u
  );

  const environmentIdentifierPaths = fixture(t);
  const environmentIdentifierCandidate = addCandidate(environmentIdentifierPaths, {
    cycle: cycle({ lesson: "Retain the clientcanary-production distinction." })
  });
  assert.throws(
    () => promotePublic(environmentIdentifierPaths, environmentIdentifierCandidate),
    /target environment identifier/u
  );

  const credentialReferencePaths = fixture(t);
  const credentialReferenceCandidate = addCandidate(credentialReferencePaths);
  assert.throws(
    () => promotePublic(credentialReferencePaths, credentialReferenceCandidate, {
      validationRefs: ["evidence://sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX"]
    }),
    /credential/u
  );

  const namedCandidatePaths = fixture(t);
  const namedCandidate = addCandidate(namedCandidatePaths, { id: "lrn_clientcanary_target" });
  assert.throws(
    () => promotePublic(namedCandidatePaths, namedCandidate),
    /opaque GATE-generated ids/u
  );

  const namedPromotionPaths = fixture(t);
  const namedPromotionCandidate = addCandidate(namedPromotionPaths);
  assert.throws(
    () => promotePublic(namedPromotionPaths, namedPromotionCandidate, { id: "lrn_clientcanary_result" }),
    /opaque GATE-generated ids/u
  );

  const pathPaths = fixture(t);
  const pathCandidate = addCandidate(pathPaths, {
    cycle: cycle({ method: "Replay the fixture from /home/operator/private/fixture.json." })
  });
  assert.throws(
    () => promotePublic(pathPaths, pathCandidate),
    /absolute or private path/u
  );

  const singlePathPaths = fixture(t);
  const singlePathCandidate = addCandidate(singlePathPaths, {
    cycle: cycle({ method: "Replay the fixture from /tenant-secret." })
  });
  assert.throws(
    () => promotePublic(singlePathPaths, singlePathCandidate),
    /absolute or private path/u
  );

  const hostnamePaths = fixture(t);
  const hostnameCandidate = addCandidate(hostnamePaths, {
    applicability: [{ kind: "component", id: "canary-target.invalid" }]
  });
  assert.throws(
    () => promotePublic(hostnamePaths, hostnameCandidate),
    /likely target hostname/u
  );

  const clientPathPaths = fixture(t);
  const clientPathCandidate = addCandidate(clientPathPaths, {
    configurationRefs: ["clients/clientcanary.json"]
  });
  assert.throws(
    () => promotePublic(clientPathPaths, clientPathCandidate),
    /likely client or private path/u
  );

  const missingPathPaths = fixture(t);
  const missingPathCandidate = addCandidate(missingPathPaths, {
    configurationRefs: ["config/does-not-exist.json"]
  });
  assert.throws(
    () => promotePublic(missingPathPaths, missingPathCandidate),
    /existing repository file/u
  );

  const repositoryFilePaths = fixture(t);
  const repositoryFileCandidate = addCandidate(repositoryFilePaths, {
    configurationRefs: ["package.json"]
  });
  const repositoryFileLearning = promotePublic(repositoryFilePaths, repositoryFileCandidate);
  assert.deepEqual(repositoryFileLearning.configurationRefs, ["package.json"]);
});

test("consult uses exact canonical applicability and emits a deterministic bounded projection", (t) => {
  const paths = fixture(t);
  const candidate = addCandidate(paths);
  const promoted = promotePublic(paths, candidate);
  const reversed = [...applicability].reverse();
  const first = consultLearnings({ applicability: reversed }, { paths });
  const second = consultLearnings({ applicability: reversed }, { paths });
  assert.deepEqual(first, second);
  assert.deepEqual(first.selected.map((item) => item.id), [promoted.id]);
  assert.match(first.ledgerHeadSha256, /^[a-f0-9]{64}$/u);
  assert.match(first.projectionSha256, /^[a-f0-9]{64}$/u);
  assert.ok(Buffer.byteLength(JSON.stringify(first)) <= 4096);
  assert.doesNotMatch(JSON.stringify(first), /evidence:\/\/|private:\/\/|configurationRefs/u);

  const stale = consultLearnings({
    applicability: [
      { kind: "component", id: "learning-runtime", version: "2.0.0" },
      applicability[1]
    ]
  }, { paths });
  assert.deepEqual(stale.selected, []);
});

test("consultation selects the newest instant across timezone offsets with a limit of one", (t) => {
  const paths = fixture(t);
  const older = promotePublic(paths, addCandidate(paths), { at: "2026-10-15T12:00:00+02:00" });
  const newer = promotePublic(paths, addCandidate(paths), { at: "2026-10-15T11:00:00Z" });
  const limited = consultLearnings({ applicability, limit: 1 }, { paths });
  assert.deepEqual(limited.selected.map((item) => item.id), [newer.id]);
  const full = consultLearnings({ applicability }, { paths });
  assert.deepEqual(full.selected.map((item) => item.id), [newer.id, older.id]);
  const verified = verifyLearningConsultationSnapshot({
    applicability,
    learningIds: [newer.id, older.id],
    ledgerHeadSha256: full.ledgerHeadSha256,
    projectionSha256: full.projectionSha256
  }, { paths });
  assert.deepEqual(verified.selected.map((item) => item.id), [newer.id, older.id]);
});

test("equivalent validation instants use domain then ID tie-breakers", (t) => {
  const paths = fixture(t);
  const software = promotePublic(paths, addCandidate(paths), {
    at: "2026-10-15T13:00:00+02:00",
    id: "lrn_20261015110000_00000001"
  });
  const activeLaterId = promotePublic(paths, addCandidate(paths, { domain: "active-testing" }), {
    at: "2026-10-15T11:00:00Z",
    id: "lrn_20261015110000_00000003"
  });
  const activeEarlierId = promotePublic(paths, addCandidate(paths, { domain: "active-testing" }), {
    at: "2026-10-15T06:00:00-05:00",
    id: "lrn_20261015110000_00000002"
  });
  assert.deepEqual(consultLearnings({ applicability, limit: 1 }, { paths }).selected.map((item) => item.id),
    [activeEarlierId.id]);
  assert.deepEqual(consultLearnings({ applicability }, { paths }).selected.map((item) => item.id),
    [activeEarlierId.id, activeLaterId.id, software.id]);
});

test("historical consultation verification replays an exact retained ledger prefix", (t) => {
  const paths = fixture(t);
  const first = promotePublic(paths, addCandidate(paths), { at: "2026-10-15T10:00:00.000Z" });
  const consultation = consultLearnings({ applicability }, { paths });
  const snapshot = {
    applicability,
    learningIds: consultation.selected.map((learning) => learning.id),
    ledgerHeadSha256: consultation.ledgerHeadSha256,
    projectionSha256: consultation.projectionSha256
  };
  promotePublic(paths, addCandidate(paths), { at: "2026-10-15T11:00:00.000Z" });

  const verified = verifyLearningConsultationSnapshot(snapshot, { paths });
  assert.deepEqual(verified.selected.map((learning) => learning.id), [first.id]);
  assert.throws(
    () => verifyLearningConsultationSnapshot({
      ...snapshot,
      learningIds: ["lrn_20261015120000_deadbeef"]
    }, { paths }),
    /learning ids do not match/u
  );
  assert.throws(
    () => verifyLearningConsultationSnapshot({
      ...snapshot,
      ledgerHeadSha256: "f".repeat(64)
    }, { paths }),
    /does not name a retained public-ledger prefix/u
  );
  assert.throws(
    () => verifyLearningConsultationSnapshot({
      ...snapshot,
      projectionSha256: "e".repeat(64)
    }, { paths }),
    /digest does not match/u
  );
});

test("historical consultation verification rejects conflicted or truncated projections", (t) => {
  const conflictPaths = fixture(t);
  const left = promotePublic(conflictPaths, addCandidate(conflictPaths));
  promotePublic(conflictPaths, addCandidate(conflictPaths), { conflictsWith: [left.id] });
  const conflicted = consultLearnings({ applicability }, { paths: conflictPaths });
  assert.throws(
    () => verifyLearningConsultationSnapshot({
      applicability,
      learningIds: [],
      ledgerHeadSha256: conflicted.ledgerHeadSha256,
      projectionSha256: conflicted.projectionSha256
    }, { paths: conflictPaths }),
    /unresolved conflicts/u
  );

  const truncatedPaths = fixture(t);
  for (let index = 0; index < 9; index += 1) {
    promotePublic(truncatedPaths, addCandidate(truncatedPaths), {
      at: `2026-10-15T${String(index).padStart(2, "0")}:00:00.000Z`
    });
  }
  const truncated = consultLearnings({ applicability }, { paths: truncatedPaths });
  assert.equal(truncated.truncation.omittedLearnings, 1);
  assert.throws(
    () => verifyLearningConsultationSnapshot({
      applicability,
      learningIds: truncated.selected.map((learning) => learning.id),
      ledgerHeadSha256: truncated.ledgerHeadSha256,
      projectionSha256: truncated.projectionSha256
    }, { paths: truncatedPaths }),
    /omits applicable guidance/u
  );
});

test("public learning reads enforce the record-count bound before parsing", (t) => {
  const paths = fixture(t);
  fs.mkdirSync(path.dirname(paths.publicLearningRecords), { recursive: true });
  fs.writeFileSync(paths.publicLearningRecords, "{}\n".repeat(10_001), "utf8");
  assert.throws(
    () => consultLearnings({ applicability }, { paths }),
    /10000-record limit/u
  );
});

test("compatible lessons coexist while explicit conflicts are surfaced and excluded", (t) => {
  const paths = fixture(t);
  const left = addCandidate(paths, { cycle: cycle({ lesson: "Use the focused test first." }) });
  const right = addCandidate(paths, { cycle: cycle({ lesson: "Use the full suite first." }) });
  const leftActive = promotePublic(paths, left);
  const rightActive = promotePublic(paths, right, {
    validationRefs: ["evidence://test/learning-adaptive-second"],
    changeRefs: ["evidence://test/learning-adaptive-second"],
    conflictsWith: [leftActive.id]
  });
  const result = consultLearnings({ applicability }, { paths });
  assert.deepEqual(result.selected, []);
  assert.equal(result.conflicts.length, 1);
  assert.deepEqual(result.conflicts[0].learningIds, [leftActive.id, rightActive.id].sort());

  const compatiblePaths = fixture(t);
  const firstCompatible = promotePublic(compatiblePaths, addCandidate(compatiblePaths));
  const secondCompatible = promotePublic(compatiblePaths, addCandidate(compatiblePaths), {
    validationRefs: ["evidence://test/compatible-second"],
    changeRefs: ["evidence://test/compatible-second"]
  });
  const compatible = consultLearnings({ applicability }, { paths: compatiblePaths });
  assert.deepEqual(compatible.conflicts, []);
  assert.deepEqual(
    compatible.selected.map((item) => item.id).sort(),
    [firstCompatible.id, secondCompatible.id].sort()
  );
});

test("reviewed replacement chains keep history while consultation selects only newest effective guidance", (t) => {
  const paths = fixture(t);
  const first = promotePublic(paths, addCandidate(paths), {
    at: "2026-10-15T10:00:00.000Z"
  });
  const secondCandidate = addCandidate(paths, {
    replaces: [first.id],
    cycle: cycle({
      lesson: "Run the discriminating check before broad coverage.",
      nextAdjustment: "Prefer the discriminating check on the next matching run."
    })
  });
  assert.deepEqual(secondCandidate.promotion.replaces, [first.id]);
  const second = promotePublic(paths, secondCandidate, {
    at: "2026-10-15T11:00:00.000Z"
  });
  assert.deepEqual(second.promotion.replaces, [first.id]);

  const thirdCandidate = addCandidate(paths, {
    replaces: [second.id],
    cycle: cycle({
      lesson: "Use the smallest discriminating fixture first.",
      nextAdjustment: "Start the next matching run with the smallest reviewed fixture."
    })
  });
  const third = promotePublic(paths, thirdCandidate, {
    at: "2026-10-15T12:00:00.000Z"
  });

  const consultation = consultLearnings({ applicability }, { paths });
  assert.deepEqual(consultation.selected.map((item) => item.id), [third.id]);
  const ledger = fs.readFileSync(paths.publicLearnings, "utf8");
  const activeSection = ledger.slice(ledger.indexOf("## Active"), ledger.indexOf("## Proposed"));
  const historicalSection = ledger.slice(ledger.indexOf("## Superseded or reverted"));
  assert.match(activeSection, new RegExp(third.cause.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  assert.doesNotMatch(activeSection, new RegExp(first.change.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  assert.match(historicalSection, /Status: superseded/u);
  assert.match(historicalSection, new RegExp(first.change.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  assert.match(historicalSection, new RegExp(second.change.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
});

test("removed configuration files preserve replacement selection and frozen consultation", (t) => {
  const paths = fixture(t);
  const reference = path.join(paths.repo, "reviewed.json");
  fs.writeFileSync(reference, "{}\n");
  const first = promotePublic(paths, addCandidate(paths));
  const candidate = addCandidate(paths, {
    replaces: [first.id],
    configurationRefs: ["reviewed.json"]
  });
  const second = promotePublic(paths, candidate);
  const consultation = consultLearnings({ applicability }, { paths });
  assert.deepEqual(consultation.selected.map((item) => item.id), [second.id]);
  const snapshot = {
    applicability,
    learningIds: [second.id],
    ledgerHeadSha256: consultation.ledgerHeadSha256,
    projectionSha256: consultation.projectionSha256
  };
  fs.renameSync(reference, path.join(paths.repo, "renamed.json"));
  assert.deepEqual(consultLearnings({ applicability }, { paths }), consultation);
  assert.deepEqual(verifyLearningConsultationSnapshot(snapshot, { paths }), consultation);
  const missingReference = addCandidate(paths, { configurationRefs: ["reviewed.json"] });
  assert.throws(() => promotePublic(paths, missingReference), /existing repository file/u);
  const records = fs.readFileSync(paths.publicLearningRecords, "utf8").trim().split("\n").map(JSON.parse);
  records.find((record) => record.id === second.id).cycle.lesson = "Inspect https://example.invalid next.";
  fs.writeFileSync(paths.publicLearningRecords, records.map((record) => JSON.stringify(record)).join("\n") + "\n");
  assert.deepEqual(consultLearnings({ applicability }, { paths }).selected, []);
});

test("replacement intent is candidate-digest-bound and cannot be chosen during promotion", (t) => {
  const paths = fixture(t);
  const active = promotePublic(paths, addCandidate(paths));
  const candidate = addCandidate(paths, { replaces: [active.id] });
  const reviewedDigest = learningCandidateSha256(candidate);

  assert.throws(
    () => promotePublic(paths, candidate, { replaces: [] }),
    /cannot replace candidate content/u
  );

  const tampered = structuredClone(candidate);
  tampered.promotion.replaces = [];
  assert.notEqual(learningCandidateSha256(tampered), reviewedDigest);
  fs.writeFileSync(paths.privateLearnings, `${JSON.stringify(tampered)}\n`, { mode: 0o600 });
  assert.throws(
    () => promoteLearning(candidate.id, {
      sensitivity: "public",
      validationRefs: ["evidence://test/replacement-tamper"],
      changeRefs: ["evidence://test/replacement-tamper"],
      review: reviewFor(candidate)
    }, { paths }),
    /does not match the exact learning candidate/u
  );
});

test("replacement validation rejects mismatched, conflicting, and forked lineage", (t) => {
  const paths = fixture(t);
  const active = promotePublic(paths, addCandidate(paths));

  assert.throws(
    () => addCandidate(paths, {
      domain: "orchestration",
      replaces: [active.id]
    }),
    /same domain and applicability/u
  );
  assert.throws(
    () => addCandidate(paths, {
      applicability: [{ kind: "component", id: "different-runtime", version: "1.0.0" }],
      replaces: [active.id]
    }),
    /same domain and applicability/u
  );

  const privatePromotionCandidate = addCandidate(paths, { replaces: [active.id] });
  assert.throws(
    () => promoteLearning(privatePromotionCandidate.id, {
      validationRefs: ["evidence://test/private-replacement"],
      changeRefs: ["evidence://test/private-replacement"],
      review: reviewFor(privatePromotionCandidate)
    }, { paths }),
    /same sensitivity, domain, and applicability/u
  );

  const overlappingCandidate = addCandidate(paths, { replaces: [active.id] });
  assert.throws(
    () => promotePublic(paths, overlappingCandidate, { conflictsWith: [active.id] }),
    /cannot both conflict with and replace/u
  );

  const firstSuccessorCandidate = addCandidate(paths, { replaces: [active.id] });
  const forkCandidate = addCandidate(paths, { replaces: [active.id] });
  promotePublic(paths, firstSuccessorCandidate);
  assert.throws(
    () => promotePublic(paths, forkCandidate),
    /currently effective guidance/u
  );
});

test("consultation prioritizes the newest effective compatible guidance", (t) => {
  const paths = fixture(t);
  const older = promotePublic(paths, addCandidate(paths), { at: "2026-10-15T10:00:00.000Z" });
  const newer = promotePublic(paths, addCandidate(paths), { at: "2026-10-15T12:00:00.000Z" });
  const consultation = consultLearnings({ applicability }, { paths });
  assert.deepEqual(consultation.selected.map((item) => item.id), [newer.id, older.id]);
});

test("unreviewed and historical supersedes values cannot hide active reviewed guidance", (t) => {
  const paths = fixture(t);
  const active = promotePublic(paths, addCandidate(paths));
  for (const status of ["proposed", "active", "superseded", "reverted"]) {
    addLearning({
      cause: `A legacy ${status} transition was recorded.`,
      change: "Do not treat an unreviewed legacy edge as effective.",
      status,
      supersedes: active.id,
      evidence: [`evidence://test/legacy-${status}`]
    }, { paths });
  }
  const result = consultLearnings({ applicability }, { paths });
  assert.deepEqual(result.selected.map((item) => item.id), [active.id]);
});

test("concurrent cross-ledger promotions produce exactly one winner", async (t) => {
  const paths = fixture(t);
  const candidate = addCandidate(paths);
  const baseInput = {
    validationRefs: ["evidence://test/concurrent-promotion"],
    changeRefs: ["evidence://test/concurrent-promotion"],
    review: reviewFor(candidate)
  };
  const writer = `
    import { promoteLearning } from ${JSON.stringify(learningModule)};
    const paths = JSON.parse(process.env.GATE_TEST_PATHS);
    const input = JSON.parse(process.env.GATE_TEST_INPUT);
    try {
      const learning = promoteLearning(process.env.GATE_TEST_CANDIDATE, input, { paths });
      process.stdout.write(JSON.stringify({ ok: true, id: learning.id }));
    } catch (error) {
      process.stdout.write(JSON.stringify({ ok: false, message: error.message }));
    }
  `;
  const inputs = [
    { ...baseInput, sensitivity: "public" },
    baseInput
  ];
  const outputs = await Promise.all(inputs.map((input) => execFileAsync(
    process.execPath,
    ["--input-type=module", "--eval", writer],
    {
      env: {
        ...process.env,
        GATE_TEST_PATHS: JSON.stringify(paths),
        GATE_TEST_INPUT: JSON.stringify(input),
        GATE_TEST_CANDIDATE: candidate.id
      },
      timeout: 20_000
    }
  )));
  const results = outputs.map(({ stdout }) => JSON.parse(stdout));
  assert.equal(results.filter((result) => result.ok).length, 1);
  assert.equal(results.filter((result) => !result.ok && /already promoted/u.test(result.message)).length, 1);

  const publicRecords = fs.existsSync(paths.publicLearningRecords)
    ? fs.readFileSync(paths.publicLearningRecords, "utf8").trim().split("\n").filter(Boolean).map(JSON.parse)
    : [];
  const privateRecords = fs.readFileSync(paths.privateLearnings, "utf8").trim().split("\n").map(JSON.parse);
  const validated = [...publicRecords, ...privateRecords].filter((record) => record.promotion?.state === "validated");
  assert.equal(validated.length, 1);
  assert.equal(fs.existsSync(`${paths.publicLearningRecords}.lock`), false);
  assert.equal(fs.existsSync(`${paths.privateLearnings}.lock`), false);
});

test("consult caps record count and excludes legacy public active learning", (t) => {
  const paths = fixture(t);
  for (const domain of ["active-testing", "software-testing", "orchestration", "tooling", "general"]) {
    const candidate = addCandidate(paths, { domain });
    promotePublic(paths, candidate, {
      validationRefs: [`evidence://test/${domain}`],
      changeRefs: [`evidence://test/${domain}`]
    });
  }
  const legacy = addLearning({
    cause: "A reviewed legacy behavior was observed.",
    change: "Retain this explicitly active legacy guidance.",
    status: "active",
    evidence: ["evidence://test/legacy-learning"]
  }, { paths });
  const limited = consultLearnings({ applicability, limit: 2 }, { paths });
  assert.equal(limited.selected.length, 2);
  assert.equal(limited.truncation.truncated, true);
  assert.equal(limited.truncation.omittedLearnings, 3);
  const full = consultLearnings({ applicability }, { paths });
  assert.equal(full.selected.length, 5);
  assert.ok(full.selected.every((item) => item.id !== legacy.id));
});
