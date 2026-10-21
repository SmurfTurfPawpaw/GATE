import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  createCtfPilotTransferReceipt,
  ctfPilotLearningDigest,
  nextCtfPilotTimestamp,
  readCtfPilotStatus,
  readCtfPilotTransferSummary,
  recordCtfPilotTransferReceipt,
  updateCtfPilotState,
  writeCtfPilotState
} from "../src/lib/ctf-pilot.mjs";
import { summarizeCtfPilot } from "../src/observer/server.mjs";

const AT = "2026-10-19T20:00:00.000Z";
const CTF_PILOT_MODULE = new URL("../src/lib/ctf-pilot.mjs", import.meta.url).href;
const metric = (value) => value === null
  ? { availability: "unavailable", value: null }
  : { availability: "available", value };

function pilotState(overrides = {}) {
  return {
    $schema: "https://gate.local/schemas/ctf-pilot-state.schema.json",
    apiVersion: "gate.dev/ctf-pilot-state/v1",
    kind: "CtfPilotState",
    metadata: {
      id: "pilot-alpha",
      caseId: "alpha-case",
      revision: 1,
      updatedAt: AT,
      validUntil: "2026-10-19T20:03:00.000Z",
      producer: null
    },
    solving: {
      availability: "available",
      verdict: "pass",
      now: "complete",
      actionNeeded: "none",
      updatedAt: AT,
      completion: { state: "complete", reproduction: "confirmed", externalAcceptance: "accepted" },
      objectives: { availability: "available", completed: 1, total: 1 },
      depth: {
        level: "systematic",
        branchesExplored: metric(7),
        techniquesAttempted: metric(5),
        deadEndsRetired: metric(2)
      },
      efficiency: {
        elapsedSeconds: metric(900),
        activeSeconds: metric(600),
        tokens: metric(12000),
        toolRuns: metric(8),
        requests: metric(31),
        retries: metric(1)
      }
    },
    learning: {
      availability: "available",
      verdict: "provisional",
      now: "checking",
      actionNeeded: "review",
      updatedAt: AT,
      stages: {
        observations: metric(6),
        candidates: metric(4),
        validated: metric(3),
        applied: metric(2),
        transferred: metric(0),
        regressed: metric(0)
      }
    },
    cockpit: {
      availability: "available",
      verdict: "pass",
      now: "current",
      actionNeeded: "none",
      updatedAt: AT,
      signals: { availability: "available", available: 10, total: 10 },
      updatesPublished: metric(12),
      updatesMissed: metric(0)
    },
    integrity: {
      availability: "available",
      status: "consistent",
      checks: { availability: "available", available: 6, total: 6 },
      issues: metric(0),
      checkedAt: AT
    },
    ...overrides
  };
}

function privateFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-ctf-pilot-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const stateHome = path.join(root, "home", "cases", "alpha-case", "state");
  const ctfPilotRoot = path.join(stateHome, "ctf-pilot");
  const ctfPilotTransfers = path.join(ctfPilotRoot, "transfers");
  fs.mkdirSync(ctfPilotTransfers, { recursive: true, mode: 0o700 });
  fs.chmodSync(path.join(root, "home"), 0o700);
  fs.chmodSync(path.join(root, "home", "cases"), 0o700);
  fs.chmodSync(path.join(root, "home", "cases", "alpha-case"), 0o700);
  fs.chmodSync(stateHome, 0o700);
  fs.chmodSync(ctfPilotRoot, 0o700);
  fs.chmodSync(ctfPilotTransfers, 0o700);
  return {
    root,
    paths: {
      repo: path.resolve("."),
      home: path.join(root, "home"),
      stateHome,
      caseId: "alpha-case",
      ctfPilotRoot,
      ctfPilotState: path.join(ctfPilotRoot, "state.json"),
      ctfPilotTransfers
    }
  };
}

function writeState(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

function transferReceipt(state, overrides = {}) {
  return createCtfPilotTransferReceipt({
    caseId: "alpha-case",
    recordedAt: "2026-10-19T20:01:00.000Z",
    learningDigest: ctfPilotLearningDigest(state.learning),
    sourceTask: { pseudonym: "source-task", digest: "1".repeat(64) },
    distinctTask: { pseudonym: "distinct-task", digest: "2".repeat(64) },
    appliedChangeDigest: "3".repeat(64),
    validationEvidenceDigest: "4".repeat(64),
    ...overrides
  });
}

test("reads one schema-valid case-bound private pilot scorecard", (t) => {
  const fixture = privateFixture(t);
  writeState(fixture.paths.ctfPilotState, pilotState());
  const result = readCtfPilotStatus({ paths: fixture.paths, now: AT });
  assert.equal(result.availability, "available");
  assert.equal(result.state.solving.verdict, "pass");
  assert.equal(result.state.learning.verdict, "provisional");
  assert.equal(result.state.learning.stages.applied.value, 2);
  assert.equal(result.state.learning.stages.transferred.value, 0);
});

test("writer publishes only monotonic validated state", (t) => {
  const fixture = privateFixture(t);
  const first = pilotState();
  writeCtfPilotState(first, { paths: fixture.paths });
  assert.equal(readCtfPilotStatus({ paths: fixture.paths, now: AT }).state.metadata.revision, 1);
  assert.throws(() => writeCtfPilotState(first, { paths: fixture.paths }), /exact next revision/u);
  assert.throws(() => writeCtfPilotState(pilotState({
    metadata: { ...first.metadata, revision: 3, updatedAt: "2026-10-19T20:01:00.000Z" }
  }), { paths: fixture.paths }), /exact next revision/u);
  assert.throws(() => writeCtfPilotState(pilotState({
    metadata: { ...first.metadata, revision: 2 }
  }), { paths: fixture.paths }), /strictly later time/u);
  const next = pilotState({
    metadata: { ...first.metadata, revision: 2, updatedAt: "2026-10-19T20:01:00.000Z" }
  });
  writeCtfPilotState(next, { paths: fixture.paths });
  assert.equal(readCtfPilotStatus({ paths: fixture.paths, now: "2026-10-19T20:01:00.000Z" }).state.metadata.revision, 2);
});

test("pilot state expires at its bounded validity deadline", (t) => {
  const fixture = privateFixture(t);
  writeCtfPilotState(pilotState(), { paths: fixture.paths });
  assert.equal(readCtfPilotStatus({
    paths: fixture.paths,
    now: "2026-10-19T20:02:59.999Z"
  }).availability, "available");
  assert.deepEqual(readCtfPilotStatus({
    paths: fixture.paths,
    now: "2026-10-19T20:03:00.000Z"
  }), { availability: "unavailable", reason: "expired", state: null });

  const other = privateFixture(t);
  assert.throws(() => writeCtfPilotState(pilotState({
    metadata: { ...pilotState().metadata, validUntil: "2026-10-19T20:03:00.001Z" }
  }), { paths: other.paths }), /state is invalid/u);
});

test("rapid publishers can derive a strictly monotonic millisecond timestamp", () => {
  assert.equal(
    nextCtfPilotTimestamp(AT, AT),
    "2026-10-19T20:00:00.001Z"
  );
  assert.equal(
    nextCtfPilotTimestamp(AT, "2026-10-19T20:00:02.000Z"),
    "2026-10-19T20:00:02.000Z"
  );
});

test("the mutation lock remains held across the read, merge, and write callback", (t) => {
  const fixture = privateFixture(t);
  const first = pilotState();
  writeCtfPilotState(first, { paths: fixture.paths });
  let contender;
  updateCtfPilotState((current) => {
    const next = pilotState({
      metadata: { ...current.state.metadata, revision: 2, updatedAt: "2026-10-19T20:01:00.000Z" }
    });
    const script = `
      import { writeCtfPilotState } from ${JSON.stringify(CTF_PILOT_MODULE)};
      const paths = JSON.parse(process.env.GATE_TEST_PATHS);
      const state = JSON.parse(process.env.GATE_TEST_STATE);
      try {
        writeCtfPilotState(state, { paths });
        process.stdout.write("unexpected-write");
        process.exitCode = 2;
      } catch (error) {
        process.stdout.write(error.message);
      }
    `;
    contender = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
      encoding: "utf8",
      env: {
        ...process.env,
        GATE_TEST_PATHS: JSON.stringify(fixture.paths),
        GATE_TEST_STATE: JSON.stringify(next)
      }
    });
    assert.equal(contender.status, 0);
    assert.match(contender.stdout, /already being updated|lock is indeterminate/u);
    return next;
  }, { paths: fixture.paths });
  assert.equal(readCtfPilotStatus({ paths: fixture.paths, now: "2026-10-19T20:01:00.000Z" }).state.metadata.revision, 2);
});

test("the kernel releases a killed writer's pilot lock", { skip: process.platform !== "linux" }, async (t) => {
  const fixture = privateFixture(t);
  writeCtfPilotState(pilotState(), { paths: fixture.paths });
  const ready = path.join(fixture.root, "child-ready");
  const script = `
    import fs from "node:fs";
    import { updateCtfPilotState } from ${JSON.stringify(CTF_PILOT_MODULE)};
    const paths = JSON.parse(process.env.GATE_TEST_PATHS);
    updateCtfPilotState((current) => {
      fs.writeFileSync(process.env.GATE_TEST_READY, "ready", { mode: 0o600 });
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 60000);
      return current.state;
    }, { paths });
  `;
  const child = spawn(process.execPath, ["--input-type=module", "-e", script], {
    stdio: "ignore",
    env: {
      ...process.env,
      GATE_TEST_PATHS: JSON.stringify(fixture.paths),
      GATE_TEST_READY: ready
    }
  });
  t.after(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  });
  for (let attempt = 0; attempt < 100 && !fs.existsSync(ready); attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.equal(fs.existsSync(ready), true, "child acquired and held the pilot lock");
  const exited = new Promise((resolve) => child.once("exit", resolve));
  child.kill("SIGKILL");
  await exited;

  updateCtfPilotState((current) => ({
    ...current.state,
    metadata: {
      ...current.state.metadata,
      revision: 2,
      updatedAt: "2026-10-19T20:01:00.000Z"
    }
  }), { paths: fixture.paths });
  assert.equal(readCtfPilotStatus({
    paths: fixture.paths,
    now: "2026-10-19T20:01:00.000Z"
  }).state.metadata.revision, 2);
});

test("serialized axis updaters preserve earlier independent changes", (t) => {
  const fixture = privateFixture(t);
  writeCtfPilotState(pilotState(), { paths: fixture.paths });
  updateCtfPilotState((current) => ({
    ...current.state,
    metadata: { ...current.state.metadata, revision: 2, updatedAt: "2026-10-19T20:01:00.000Z" },
    solving: {
      ...current.state.solving,
      updatedAt: "2026-10-19T20:01:00.000Z",
      efficiency: { ...current.state.solving.efficiency, requests: metric(32) }
    }
  }), { paths: fixture.paths });
  updateCtfPilotState((current) => ({
    ...current.state,
    metadata: { ...current.state.metadata, revision: 3, updatedAt: "2026-10-19T20:02:00.000Z" },
    cockpit: {
      ...current.state.cockpit,
      updatedAt: "2026-10-19T20:02:00.000Z",
      updatesPublished: metric(13)
    }
  }), { paths: fixture.paths });
  const merged = readCtfPilotStatus({ paths: fixture.paths, now: "2026-10-19T20:02:00.000Z" }).state;
  assert.equal(merged.metadata.revision, 3);
  assert.equal(merged.solving.efficiency.requests.value, 32);
  assert.equal(merged.cockpit.updatesPublished.value, 13);
});

test("PASS verdicts and axis timestamps require their mechanical evidence", (t) => {
  const invalidStates = [
    pilotState({ solving: { ...pilotState().solving, now: "validating" } }),
    pilotState({ solving: {
      ...pilotState().solving,
      objectives: { availability: "available", completed: 0, total: 1 }
    } }),
    pilotState({ solving: {
      ...pilotState().solving,
      completion: { state: "complete", reproduction: "unknown", externalAcceptance: "accepted" }
    } }),
    pilotState({ solving: {
      ...pilotState().solving,
      completion: { state: "complete", reproduction: "confirmed", externalAcceptance: "pending" }
    } }),
    pilotState({ learning: {
      ...pilotState().learning,
      verdict: "pass",
      actionNeeded: "none"
    } }),
    pilotState({ cockpit: {
      ...pilotState().cockpit,
      updatesMissed: metric(1)
    } }),
    pilotState({ cockpit: {
      ...pilotState().cockpit,
      signals: { availability: "available", available: 9, total: 10 }
    } }),
    pilotState({ learning: {
      ...pilotState().learning,
      updatedAt: "2026-10-19T20:00:00.001Z"
    } })
  ];
  for (const state of invalidStates) {
    const fixture = privateFixture(t);
    assert.throws(() => writeCtfPilotState(state, { paths: fixture.paths }), /state is invalid/u);
  }

  const fixture = privateFixture(t);
  const base = pilotState();
  writeCtfPilotState(pilotState({
    learning: { ...base.learning, verdict: "not-applicable" }
  }), { paths: fixture.paths });
  assert.equal(readCtfPilotStatus({ paths: fixture.paths, now: AT }).state.learning.verdict, "not-applicable");
});

test("transfer counts come only from bound deduplicated private receipts", (t) => {
  const fixture = privateFixture(t);
  const first = pilotState();
  writeCtfPilotState(first, { paths: fixture.paths });
  assert.deepEqual(readCtfPilotTransferSummary({ paths: fixture.paths }), {
    availability: "available", reason: null, count: 0
  });

  const receipt = transferReceipt(first);
  const recorded = recordCtfPilotTransferReceipt(receipt, { paths: fixture.paths });
  assert.equal(recorded.created, true);
  assert.equal(recorded.count, 1);
  assert.equal(recorded.state.metadata.revision, 2);
  assert.equal(recorded.state.learning.stages.transferred.value, 1);
  assert.deepEqual(readCtfPilotTransferSummary({ paths: fixture.paths }), {
    availability: "available", reason: null, count: 1
  });
  assert.equal(JSON.stringify(readCtfPilotTransferSummary({ paths: fixture.paths })).includes("source-task"), false);
  assert.equal(JSON.stringify(readCtfPilotTransferSummary({ paths: fixture.paths })).includes("1".repeat(64)), false);

  const duplicate = recordCtfPilotTransferReceipt(receipt, { paths: fixture.paths });
  assert.equal(duplicate.created, false);
  assert.equal(duplicate.count, 1);
  assert.equal(duplicate.state.metadata.revision, 2);
  assert.equal(fs.readdirSync(fixture.paths.ctfPilotTransfers).length, 1);
  const conflictingDuplicate = transferReceipt(recorded.state, {
    recordedAt: "2026-10-19T20:02:00.000Z",
    appliedChangeDigest: "5".repeat(64)
  });
  assert.throws(
    () => recordCtfPilotTransferReceipt(conflictingDuplicate, { paths: fixture.paths }),
    /existing deduplicated task transfer/u
  );
  const reusedAppliedLearning = transferReceipt(recorded.state, {
    recordedAt: "2026-10-19T20:02:00.000Z",
    distinctTask: { pseudonym: "second-task", digest: "6".repeat(64) },
    validationEvidenceDigest: "7".repeat(64)
  });
  assert.throws(
    () => recordCtfPilotTransferReceipt(reusedAppliedLearning, { paths: fixture.paths }),
    /already transferred applied learning/u
  );
  assert.equal(readCtfPilotTransferSummary({ paths: fixture.paths }).count, 1);
  const receiptPath = path.join(fixture.paths.ctfPilotTransfers, fs.readdirSync(fixture.paths.ctfPilotTransfers)[0]);
  if (process.platform !== "win32") {
    assert.equal(fs.statSync(fixture.paths.ctfPilotTransfers).mode & 0o7777, 0o700);
    assert.equal(fs.statSync(receiptPath).mode & 0o7777, 0o600);
  }

  const passing = {
    ...recorded.state,
    metadata: { ...recorded.state.metadata, revision: 3, updatedAt: "2026-10-19T20:02:00.000Z" },
    learning: {
      ...recorded.state.learning,
      verdict: "pass",
      actionNeeded: "none",
      updatedAt: "2026-10-19T20:02:00.000Z"
    }
  };
  writeCtfPilotState(passing, { paths: fixture.paths });
  assert.equal(readCtfPilotStatus({
    paths: fixture.paths,
    now: "2026-10-19T20:02:00.000Z"
  }).state.learning.verdict, "pass");

  const mismatched = {
    ...passing,
    metadata: { ...passing.metadata, revision: 4, updatedAt: "2026-10-19T20:02:30.000Z" },
    learning: {
      ...passing.learning,
      updatedAt: "2026-10-19T20:02:30.000Z",
      stages: { ...passing.learning.stages, transferred: metric(0) }
    }
  };
  assert.throws(() => writeCtfPilotState(mismatched, { paths: fixture.paths }), /state is invalid/u);
});

test("transfer receipts reject reused tasks, stale learning, and ledger tampering", (t) => {
  const firstFixture = privateFixture(t);
  const first = pilotState();
  writeCtfPilotState(first, { paths: firstFixture.paths });
  assert.throws(() => transferReceipt(first, {
    distinctTask: { pseudonym: "source-task", digest: "1".repeat(64) }
  }), /distinct destination task/u);
  const stale = transferReceipt(first, { learningDigest: "9".repeat(64) });
  assert.throws(
    () => recordCtfPilotTransferReceipt(stale, { paths: firstFixture.paths }),
    /does not bind the current learning state/u
  );

  const secondFixture = privateFixture(t);
  writeCtfPilotState(first, { paths: secondFixture.paths });
  const recorded = recordCtfPilotTransferReceipt(transferReceipt(first), { paths: secondFixture.paths });
  const poisoned = {
    ...recorded.state,
    learning: {
      ...recorded.state.learning,
      stages: { ...recorded.state.learning.stages, transferred: metric(0) }
    }
  };
  writeState(secondFixture.paths.ctfPilotState, poisoned);
  assert.equal(readCtfPilotStatus({ paths: secondFixture.paths, now: "2026-10-19T20:01:00.000Z" }).reason, "invalid");

  const thirdFixture = privateFixture(t);
  writeCtfPilotState(first, { paths: thirdFixture.paths });
  recordCtfPilotTransferReceipt(transferReceipt(first), { paths: thirdFixture.paths });
  const receiptFile = path.join(thirdFixture.paths.ctfPilotTransfers, fs.readdirSync(thirdFixture.paths.ctfPilotTransfers)[0]);
  const tamperedReceipt = JSON.parse(fs.readFileSync(receiptFile, "utf8"));
  tamperedReceipt.validationEvidenceDigest = "8".repeat(64);
  writeState(receiptFile, tamperedReceipt);
  assert.equal(readCtfPilotTransferSummary({ paths: thirdFixture.paths }).reason, "invalid");
  assert.equal(readCtfPilotStatus({
    paths: thirdFixture.paths,
    now: "2026-10-19T20:01:00.000Z"
  }).reason, "invalid");
});

test("a killed transfer publisher is reconciled before its receipt is retried", {
  skip: process.platform !== "linux"
}, async (t) => {
  const fixture = privateFixture(t);
  const first = pilotState();
  writeCtfPilotState(first, { paths: fixture.paths });
  const receipt = transferReceipt(first);
  const ready = path.join(fixture.root, "transfer-receipt-durable");
  const script = `
    import fs from "node:fs";
    import { recordCtfPilotTransferReceipt } from ${JSON.stringify(CTF_PILOT_MODULE)};
    const paths = JSON.parse(process.env.GATE_TEST_PATHS);
    const receipt = JSON.parse(process.env.GATE_TEST_RECEIPT);
    recordCtfPilotTransferReceipt(receipt, {
      paths,
      afterReceiptDurable() {
        fs.writeFileSync(process.env.GATE_TEST_READY, "ready", { mode: 0o600 });
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 60000);
      }
    });
  `;
  const child = spawn(process.execPath, ["--input-type=module", "-e", script], {
    stdio: "ignore",
    env: {
      ...process.env,
      GATE_TEST_PATHS: JSON.stringify(fixture.paths),
      GATE_TEST_RECEIPT: JSON.stringify(receipt),
      GATE_TEST_READY: ready
    }
  });
  t.after(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  });
  for (let attempt = 0; attempt < 500 && !fs.existsSync(ready); attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.equal(fs.existsSync(ready), true, "child durably wrote the receipt before pausing");
  const exited = new Promise((resolve) => child.once("exit", resolve));
  child.kill("SIGKILL");
  await exited;
  assert.equal(readCtfPilotStatus({
    paths: fixture.paths,
    now: "2026-10-19T20:01:00.000Z"
  }).reason, "invalid", "the unmatched receipt is never projected as current state");

  const retried = recordCtfPilotTransferReceipt(receipt, { paths: fixture.paths });
  assert.equal(retried.created, true);
  assert.equal(retried.count, 1);
  assert.equal(retried.state.metadata.revision, 2);
  assert.equal(fs.existsSync(path.join(fixture.paths.ctfPilotRoot, ".transfer.transaction.json")), false);
  assert.equal(fs.readdirSync(fixture.paths.ctfPilotTransfers).length, 1);
});

test("missing, malformed, contradictory, and cross-case state stay unavailable", (t) => {
  const fixture = privateFixture(t);
  assert.deepEqual(readCtfPilotStatus({ paths: fixture.paths, now: AT }), {
    availability: "unavailable", reason: "missing", state: null
  });

  writeState(fixture.paths.ctfPilotState, pilotState({
    solving: { ...pilotState().solving, objectives: { availability: "available", completed: 5, total: 4 } }
  }));
  assert.equal(readCtfPilotStatus({ paths: fixture.paths, now: AT }).reason, "invalid");

  const mixedStages = pilotState().learning.stages;
  writeState(fixture.paths.ctfPilotState, pilotState({
    learning: {
      ...pilotState().learning,
      stages: { ...mixedStages, observations: metric(null), transferred: metric(3) }
    }
  }));
  assert.equal(readCtfPilotStatus({ paths: fixture.paths, now: AT }).reason, "invalid",
    "an unrelated unavailable stage must not hide transferred greater than applied");

  writeState(fixture.paths.ctfPilotState, pilotState({ metadata: { ...pilotState().metadata, caseId: "other-case" } }));
  assert.equal(readCtfPilotStatus({ paths: fixture.paths, now: AT }).reason, "invalid");

  assert.throws(() => readCtfPilotStatus({ paths: {
    ...fixture.paths,
    ctfPilotState: path.join(fixture.root, "escaped.json")
  } }), /case-local location/u);
});

test("axis verdict vocabularies are aligned while learning alone admits not-applicable", () => {
  const common = ["pass", "provisional", "fail", "blocked", "unknown"];
  for (const verdict of common) {
    for (const axis of ["solving", "learning", "cockpit"]) {
      const base = pilotState();
      const axisState = { ...base[axis], verdict };
      if (axis === "learning" && verdict === "pass") {
        axisState.actionNeeded = "none";
        axisState.stages = { ...base.learning.stages, transferred: metric(1) };
      }
      const state = pilotState({ [axis]: axisState });
      assert.equal(summarizeCtfPilot({ availability: "available", reason: null, state }).availability, "available",
        `${axis} should accept ${verdict}`);
    }
  }
  const learningBase = pilotState();
  assert.equal(summarizeCtfPilot({
    availability: "available", reason: null,
    state: pilotState({ learning: { ...learningBase.learning, verdict: "not-applicable" } })
  }).availability, "available");
  for (const axis of ["solving", "cockpit"]) {
    const base = pilotState();
    assert.equal(summarizeCtfPilot({
      availability: "available", reason: null,
      state: pilotState({ [axis]: { ...base[axis], verdict: "not-applicable" } })
    }).availability, "unavailable");
  }
  for (const [axis, verdict] of [["solving", "solved"], ["learning", "applied"], ["cockpit", "current"]]) {
    const base = pilotState();
    assert.equal(summarizeCtfPilot({
      availability: "available", reason: null,
      state: pilotState({ [axis]: { ...base[axis], verdict } })
    }).availability, "unavailable");
  }
});

test("an audited positive transfer count survives the bounded observer projection", (t) => {
  const fixture = privateFixture(t);
  const state = pilotState();
  writeCtfPilotState(state, { paths: fixture.paths });
  recordCtfPilotTransferReceipt(transferReceipt(state), { paths: fixture.paths });
  const projected = summarizeCtfPilot(readCtfPilotStatus({
    paths: fixture.paths,
    now: "2026-10-19T20:01:00.000Z"
  }));
  assert.equal(projected.availability, "available");
  assert.deepEqual(projected.learning.stages.transferred, { availability: "available", value: 1 });
});

test("observer projection exposes only enums, counts, timestamps, and resource use", () => {
  const state = pilotState();
  const projected = summarizeCtfPilot({ availability: "available", reason: null, state });
  assert.equal(projected.availability, "available");
  assert.equal(projected.validUntil, state.metadata.validUntil);
  assert.equal(projected.solving.verdict, "pass");
  assert.equal(projected.learning.verdict, "provisional");
  assert.equal(projected.learning.stages.applied.value, 2);
  assert.equal(projected.learning.stages.transferred.value, 0);
  assert.equal(JSON.stringify(projected).includes("pilot-alpha"), false);
  assert.equal(JSON.stringify(projected).includes("alpha-case"), false);

  const canaries = pilotState({
    target: "TARGET_CANARY",
    flag: "FLAG_CANARY",
    prompt: "PROMPT_CANARY",
    command: "COMMAND_CANARY",
    evidenceSha256: "a".repeat(64),
    privatePath: "/private/PATH_CANARY"
  });
  const withheld = summarizeCtfPilot({ availability: "available", reason: null, state: canaries });
  assert.equal(withheld.availability, "unavailable");
  const serialized = JSON.stringify(withheld);
  for (const canary of ["TARGET_CANARY", "FLAG_CANARY", "PROMPT_CANARY", "COMMAND_CANARY", "PATH_CANARY", "a".repeat(64)]) {
    assert.equal(serialized.includes(canary), false);
  }
  assert.equal(summarizeCtfPilot({ availability: "unavailable", reason: "expired", state: null }).validUntil, null);
});

test("unavailable axes retain null measurements instead of invented zeroes", () => {
  const unavailableMetric = metric(null);
  const state = pilotState({
    solving: {
      availability: "unavailable", verdict: null, now: null, actionNeeded: null, updatedAt: null,
      completion: { state: null, reproduction: null, externalAcceptance: null },
      objectives: { availability: "unavailable", completed: null, total: null },
      depth: { level: "unavailable", branchesExplored: unavailableMetric, techniquesAttempted: unavailableMetric, deadEndsRetired: unavailableMetric },
      efficiency: { elapsedSeconds: unavailableMetric, activeSeconds: unavailableMetric, tokens: unavailableMetric, toolRuns: unavailableMetric, requests: unavailableMetric, retries: unavailableMetric }
    }
  });
  const projected = summarizeCtfPilot({ availability: "available", reason: null, state });
  assert.equal(projected.availability, "available");
  assert.equal(projected.solving.verdict, null);
  assert.equal(projected.solving.efficiency.tokens.value, null);
  assert.equal(projected.solving.efficiency.tokens.availability, "unavailable");
});
