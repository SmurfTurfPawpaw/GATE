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

function rawCase(programId) {
  return {
    id: "private-duplicate-case",
    displayName: "Duplicate case",
    status: "ready",
    binding: {
      program: { id: programId, current: true },
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
        nextSection: "conditional-modules",
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
    nextSection: "conditional-modules",
    recommendationMode: "mixed",
    updatedAt: observedAt,
    freshness: "fresh"
  });
  assert.match(status.profileSetups[0].id, /^program_[a-f0-9]{16}$/u);
  assert.deepEqual(status.profileSetupScan, {
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
  assert.equal(JSON.stringify(fallback).includes("HTTP_STATUS_FAILURE_PRIVATE_CANARY"), false);
});
