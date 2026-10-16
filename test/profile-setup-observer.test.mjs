import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  createProgramProfile,
  programProfileSetupFleetStatus
} from "../src/lib/bounty-profiles.mjs";
import { runtimePaths } from "../src/lib/paths.mjs";
import { projectSnapshot, startObserver } from "../src/observer/server.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const observedAt = "2026-10-16T08:00:00.000Z";

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-profile-setup-observer-"));
  const paths = runtimePaths({ repo, home: path.join(root, "home") });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, paths };
}

function rawStatus(overrides = {}) {
  return {
    at: observedAt,
    events: [],
    learnings: [],
    engagements: [],
    tokens: [],
    projects: [],
    upstreams: [],
    cases: [],
    caseScan: {
      discovered: 0,
      scanned: 0,
      omitted: 0,
      invalid: 0,
      complete: true,
      truncated: false
    },
    operator: { displayName: "Giovanni" },
    ...overrides
  };
}

function rawCase(programId, options = {}) {
  return {
    id: options.id || "private-duplicate-case",
    displayName: options.displayName || "Duplicate case",
    status: options.status || "ready",
    binding: {
      program: { id: programId, current: options.programCurrent ?? true },
      project: null
    },
    isolation: {
      stateNamespace: "isolated-directory",
      processBoundary: "shared-user",
      networkBoundary: "adapter-dependent"
    },
    runtimeHealth: { status: "unavailable", reason: "runtime-observation-failed" },
    runtime: null
  };
}

function rawSetup(id, overrides = {}) {
  return {
    id,
    stage: "questionnaire",
    readiness: "not-ready",
    progress: { answered: 10, total: 66 },
    blockerCount: 3,
    nextSection: "authority-sources",
    recommendationMode: null,
    updatedAt: observedAt,
    ...overrides
  };
}

async function listen(t, options) {
  const server = await startObserver({
    host: "127.0.0.1",
    port: 0,
    refreshMs: 250,
    quiet: true,
    ...options
  });
  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
    server.closeAllConnections?.();
  }));
  return `http://127.0.0.1:${server.address().port}`;
}

test("bounded profile setup scan returns aggregate intake state without private profile content", (t) => {
  const { paths } = fixture(t);
  createProgramProfile("private-program-canary", {
    identity: { programName: "PROFILE_TITLE_PRIVATE_CANARY" }
  }, { paths, now: observedAt });

  const fleet = programProfileSetupFleetStatus({ paths, now: observedAt });
  assert.deepEqual(fleet.scan, {
    limit: 32,
    discoveryLimit: 1024,
    discovered: 1,
    scanned: 1,
    omitted: 0,
    discoveredAtLeast: false,
    omittedAtLeast: false,
    complete: true,
    truncated: false,
    invalid: 0
  });
  assert.deepEqual(fleet.profiles, [{
    id: "private-program-canary",
    stage: "questionnaire",
    readiness: "not-ready",
    progress: { answered: 1, total: 66 },
    blockerCount: fleet.profiles[0].blockerCount,
    nextSection: "identity-objectives",
    recommendationMode: null,
    updatedAt: observedAt
  }]);
  assert.ok(fleet.profiles[0].blockerCount > 0);
  assert.equal(JSON.stringify(fleet).includes("PROFILE_TITLE_PRIVATE_CANARY"), false);
});

test("profile setup scan bounds discovery and fails closed on invalid entries", (t) => {
  const { paths } = fixture(t);
  programProfileSetupFleetStatus({ paths, now: observedAt });
  for (let index = 0; index < 33; index += 1) {
    fs.mkdirSync(path.join(paths.programs, `profile-${String(index).padStart(2, "0")}`), { mode: 0o700 });
  }
  const fleet = programProfileSetupFleetStatus({ paths, now: observedAt });
  assert.equal(fleet.profiles.length, 0);
  assert.equal(fleet.scan.discovered, 33);
  assert.equal(fleet.scan.scanned, 32);
  assert.equal(fleet.scan.omitted, 1);
  assert.equal(fleet.scan.invalid, 32);
  assert.equal(fleet.scan.complete, false);
  assert.equal(fleet.scan.truncated, true);
});

test("profile setup scan does not enumerate unrelated runtime roots after bounded initialization", (t) => {
  const { paths } = fixture(t);
  createProgramProfile("bounded-root-profile", {}, { paths, now: observedAt });
  fs.writeFileSync(
    path.join(paths.executionSandboxes, "UNRELATED_RUNTIME_ENTRY_PRIVATE_CANARY"),
    "not a sandbox directory",
    { mode: 0o600 }
  );

  const fleet = programProfileSetupFleetStatus({ paths, now: observedAt });
  assert.equal(fleet.profiles.length, 1);
  assert.equal(fleet.profiles[0].id, "bounded-root-profile");
  assert.equal(fleet.scan.scanned, 1);
  assert.equal(fleet.scan.complete, true);
  assert.equal(JSON.stringify(fleet).includes("UNRELATED_RUNTIME_ENTRY_PRIVATE_CANARY"), false);
});

test("observer projects opaque intake aggregates, rejects malformed rows, and removes case duplicates", () => {
  const duplicateProgram = "DUPLICATE_PROGRAM_PRIVATE_CANARY";
  const visibleProgram = "VISIBLE_PROGRAM_PRIVATE_CANARY";
  const raw = rawStatus({
    cases: [rawCase(duplicateProgram)],
    caseScan: {
      discovered: 1,
      scanned: 1,
      omitted: 0,
      invalid: 0,
      complete: true,
      truncated: false
    },
    profileSetups: [
      {
        id: duplicateProgram,
        stage: "questionnaire",
        readiness: "not-ready",
        progress: { answered: 10, total: 66 },
        blockerCount: 3,
        nextSection: "authority-sources",
        recommendationMode: null,
        updatedAt: observedAt,
        answers: { target: "https://DUPLICATE_TARGET_PRIVATE_CANARY.invalid" }
      },
      {
        id: visibleProgram,
        displayName: "VISIBLE_PROFILE_TITLE_PRIVATE_CANARY",
        stage: "operator-review",
        readiness: "not-ready",
        progress: { answered: 66, total: 66 },
        blockerCount: 2,
        nextSection: null,
        recommendationMode: "mixed",
        updatedAt: observedAt,
        blockers: ["EXACT_BLOCKER_TEXT_PRIVATE_CANARY"],
        profileSha256: "a".repeat(64),
        sourceIds: ["SOURCE_ID_PRIVATE_CANARY"],
        path: "/private/PROFILE_PATH_PRIVATE_CANARY"
      },
      {
        id: "MALFORMED_PROGRAM_PRIVATE_CANARY",
        stage: "questionnaire",
        readiness: "not-ready",
        progress: { answered: 67, total: 66 },
        blockerCount: 1,
        nextSection: "identity-objectives",
        recommendationMode: null,
        updatedAt: observedAt
      }
    ],
    profileSetupScan: {
      discovered: 3,
      scanned: 3,
      omitted: 0,
      invalid: 0,
      complete: true,
      truncated: false
    }
  });

  const status = projectSnapshot(raw, { repo }).status;
  assert.equal(status.profileSetups.length, 1);
  assert.deepEqual(status.profileSetups[0], {
    id: status.profileSetups[0].id,
    displayName: null,
    stage: "operator-review",
    readiness: "not-ready",
    progress: { answered: 66, total: 66 },
    blockerCount: 2,
    nextSection: null,
    recommendationMode: "mixed",
    updatedAt: observedAt,
    freshness: "fresh"
  });
  assert.match(status.profileSetups[0].id, /^program_[a-f0-9]{16}$/u);
  assert.deepEqual(status.profileSetupScan, {
    availability: "available",
    discovered: 3,
    scanned: 3,
    omitted: 0,
    invalid: 1,
    visible: 1,
    representedByCases: 1,
    discoveredAtLeast: false,
    omittedAtLeast: false,
    complete: false,
    truncated: false
  });

  const serialized = JSON.stringify(status);
  for (const canary of [
    duplicateProgram,
    visibleProgram,
    "MALFORMED_PROGRAM_PRIVATE_CANARY",
    "DUPLICATE_TARGET_PRIVATE_CANARY",
    "VISIBLE_PROFILE_TITLE_PRIVATE_CANARY",
    "EXACT_BLOCKER_TEXT_PRIVATE_CANARY",
    "SOURCE_ID_PRIVATE_CANARY",
    "PROFILE_PATH_PRIVATE_CANARY"
  ]) assert.equal(serialized.includes(canary), false, `profile setup projection leaked ${canary}`);
});

test("a stale case program binding does not hide the current profile setup", () => {
  const programId = "STALE_BINDING_PROGRAM_PRIVATE_CANARY";
  const status = projectSnapshot(rawStatus({
    cases: [rawCase(programId, {
      id: "stale-binding-case",
      displayName: "Stale binding case",
      status: "stale",
      programCurrent: false
    })],
    caseScan: {
      discovered: 1,
      scanned: 1,
      omitted: 0,
      invalid: 0,
      complete: true,
      truncated: false
    },
    profileSetups: [{
      id: programId,
      stage: "questionnaire",
      readiness: "not-ready",
      progress: { answered: 10, total: 66 },
      blockerCount: 3,
      nextSection: "authority-sources",
      recommendationMode: null,
      updatedAt: observedAt
    }],
    profileSetupScan: {
      discovered: 1,
      scanned: 1,
      omitted: 0,
      invalid: 0,
      complete: true,
      truncated: false
    }
  }), { repo }).status;

  assert.equal(status.cases[0].binding.program.current, false);
  assert.equal(status.profileSetups.length, 1);
  assert.equal(status.profileSetupScan.visible, 1);
  assert.equal(status.profileSetupScan.representedByCases, 0);
  assert.equal(JSON.stringify(status).includes(programId), false);
});

test("profile setup projection accounts for rows beyond its hard limit", () => {
  const profileSetups = Array.from({ length: 34 }, (_, index) => rawSetup(
    `OVERFLOW_PROGRAM_PRIVATE_CANARY_${String(index).padStart(2, "0")}`
  ));
  const status = projectSnapshot(rawStatus({
    profileSetups,
    profileSetupScan: {
      discovered: 34,
      scanned: 34,
      omitted: 0,
      invalid: 0,
      complete: true,
      truncated: false
    }
  }), { repo }).status;

  assert.equal(status.profileSetups.length, 32);
  assert.deepEqual(status.profileSetupScan, {
    availability: "available",
    discovered: 34,
    scanned: 32,
    omitted: 2,
    invalid: 0,
    visible: 32,
    representedByCases: 0,
    discoveredAtLeast: false,
    omittedAtLeast: false,
    complete: false,
    truncated: true
  });
  assert.equal(
    status.profileSetupScan.scanned + status.profileSetupScan.omitted,
    status.profileSetupScan.discovered
  );
  assert.equal(JSON.stringify(status).includes("OVERFLOW_PROGRAM_PRIVATE_CANARY"), false);
});

test("profile setup projection rejects contradictory lifecycle aggregates", () => {
  const contradictions = [
    rawSetup("contradiction-ready-readiness", {
      stage: "ready", readiness: "not-ready", progress: { answered: 66, total: 66 }, blockerCount: 0, nextSection: null
    }),
    rawSetup("contradiction-ready-blocker", {
      stage: "ready", readiness: "ready", progress: { answered: 66, total: 66 }, blockerCount: 1, nextSection: null
    }),
    rawSetup("contradiction-ready-progress", {
      stage: "ready", readiness: "ready", progress: { answered: 65, total: 66 }, blockerCount: 0, nextSection: null
    }),
    rawSetup("contradiction-ready-next", {
      stage: "ready", readiness: "ready", progress: { answered: 66, total: 66 }, blockerCount: 0, nextSection: "reporting-disclosure"
    }),
    rawSetup("contradiction-draft-readiness", {
      stage: "questionnaire", readiness: "ready"
    }),
    rawSetup("contradiction-draft-blocker", {
      blockerCount: 0
    }),
    rawSetup("contradiction-draft-next-missing", {
      nextSection: null
    }),
    rawSetup("contradiction-review-next-present", {
      stage: "operator-review", progress: { answered: 66, total: 66 }, nextSection: "reporting-disclosure"
    })
  ];
  const status = projectSnapshot(rawStatus({
    profileSetups: contradictions,
    profileSetupScan: {
      discovered: contradictions.length,
      scanned: contradictions.length,
      omitted: 0,
      invalid: 0,
      complete: true,
      truncated: false
    }
  }), { repo }).status;

  assert.equal(status.profileSetups.length, 0);
  assert.equal(status.profileSetupScan.invalid, contradictions.length);
  assert.equal(status.profileSetupScan.complete, false);
  assert.equal(status.profileSetupScan.truncated, false);
});

test("a cold profile scan failure preserves fresh status and reports unavailable setup coverage", async (t) => {
  const paths = { repo };
  const origin = await listen(t, {
    paths,
    statusBuilder: () => rawStatus({ at: "2026-10-16T08:00:01.000Z" }),
    profileSetupBuilder: () => {
      throw new Error("COLD_PROFILE_SCAN_FAILURE_PRIVATE_CANARY");
    }
  });

  const response = await fetch(`${origin}/api/status`);
  const status = await response.json();
  assert.equal(response.status, 200);
  assert.equal(status.at, "2026-10-16T08:00:01.000Z");
  assert.deepEqual(status.profileSetups, []);
  assert.deepEqual(status.profileSetupScan, {
    availability: "unavailable",
    discovered: null,
    scanned: null,
    omitted: null,
    invalid: null,
    visible: 0,
    representedByCases: null,
    discoveredAtLeast: false,
    omittedAtLeast: false,
    complete: false,
    truncated: true
  });
  assert.equal(JSON.stringify(status).includes("COLD_PROFILE_SCAN_FAILURE_PRIVATE_CANARY"), false);
});

test("a warm profile scan failure advances status while retaining stale setup rows as incomplete", async (t) => {
  const paths = { repo };
  let statusCalls = 0;
  let setupCalls = 0;
  const origin = await listen(t, {
    paths,
    statusBuilder: () => rawStatus({
      at: statusCalls++ === 0 ? "2026-10-16T08:00:01.000Z" : "2026-10-16T08:00:02.000Z"
    }),
    profileSetupBuilder: () => {
      setupCalls += 1;
      if (setupCalls > 1) throw new Error("WARM_PROFILE_SCAN_FAILURE_PRIVATE_CANARY");
      return {
        profiles: [rawSetup("warm-private-program")],
        scan: {
          discovered: 1,
          scanned: 1,
          omitted: 0,
          invalid: 0,
          complete: true,
          truncated: false
        }
      };
    }
  });

  const first = await (await fetch(`${origin}/api/status`)).json();
  assert.equal(first.at, "2026-10-16T08:00:01.000Z");
  assert.equal(first.profileSetups[0].freshness, "fresh");
  assert.equal(first.profileSetupScan.availability, "available");
  assert.equal(first.profileSetupScan.complete, true);

  await new Promise((resolve) => setTimeout(resolve, 275));
  const secondResponse = await fetch(`${origin}/api/status`);
  const second = await secondResponse.json();
  assert.equal(secondResponse.status, 200);
  assert.equal(second.at, "2026-10-16T08:00:02.000Z", "fresh base status must not freeze with the setup cache");
  assert.equal(second.profileSetups.length, 1);
  assert.equal(second.profileSetups[0].id, first.profileSetups[0].id);
  assert.equal(second.profileSetups[0].freshness, "stale");
  assert.equal(second.profileSetupScan.availability, "unavailable");
  assert.equal(second.profileSetupScan.complete, false);
  assert.equal(second.profileSetupScan.truncated, true);
  assert.equal(second.profileSetupScan.visible, 1);
  assert.equal(JSON.stringify(second).includes("WARM_PROFILE_SCAN_FAILURE_PRIVATE_CANARY"), false);
});

test("observer API reads the bounded private fleet and marks cached setup state stale", async (t) => {
  const { paths } = fixture(t);
  createProgramProfile("http-private-program", {
    identity: { programName: "HTTP_PROFILE_TITLE_PRIVATE_CANARY" }
  }, { paths, now: observedAt });
  let calls = 0;
  const origin = await listen(t, {
    paths,
    statusBuilder: () => {
      calls += 1;
      if (calls > 1) throw new Error("HTTP_STATUS_FAILURE_PRIVATE_CANARY");
      return rawStatus();
    }
  });

  const first = await (await fetch(`${origin}/api/status`)).json();
  assert.equal(first.profileSetups.length, 1);
  assert.equal(first.profileSetups[0].freshness, "fresh");
  assert.equal(first.profileSetups[0].displayName, null);
  assert.match(first.profileSetups[0].id, /^program_[a-f0-9]{16}$/u);
  assert.equal(JSON.stringify(first).includes("http-private-program"), false);
  assert.equal(JSON.stringify(first).includes("HTTP_PROFILE_TITLE_PRIVATE_CANARY"), false);

  await new Promise((resolve) => setTimeout(resolve, 275));
  const fallbackResponse = await fetch(`${origin}/api/status`);
  const fallback = await fallbackResponse.json();
  assert.equal(fallbackResponse.status, 200);
  assert.equal(fallback.profileSetups[0].freshness, "stale");
  assert.equal(fallback.profileSetupScan.availability, "unavailable");
  assert.equal(fallback.profileSetupScan.complete, false);
  assert.equal(fallback.profileSetupScan.truncated, true);
  assert.equal(JSON.stringify(fallback).includes("HTTP_STATUS_FAILURE_PRIVATE_CANARY"), false);
});
