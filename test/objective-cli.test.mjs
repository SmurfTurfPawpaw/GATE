import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { objectiveCanonicalSha256 } from "../src/lib/objective-router.mjs";
import { validateRepository } from "../src/lib/validation.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const gate = path.join(repo, "bin", "gate.mjs");
const catalog = JSON.parse(fs.readFileSync(path.join(repo, "config", "objective-routes.json"), "utf8"));

function inferred(code = "objective-classification") {
  return { provenance: "model-derived", claimState: "inferred", code, sourceRefs: [] };
}

function incidentProposal(overrides = {}) {
  return {
    $schema: "https://gate.local/schemas/objective-routing-proposal.schema.json",
    apiVersion: "gate.dev/objective-routing-proposal/v1",
    kind: "ObjectiveRoutingProposal",
    metadata: {
      objectiveHandle: "obj_abcdef0123456789",
      createdAt: "2026-10-16T08:00:00.000Z",
      routeCatalogSha256: objectiveCanonicalSha256(catalog),
      ...(overrides.metadata || {})
    },
    dimensions: {
      domain: { value: "security-incident", basis: inferred() },
      deliverable: { value: "investigation-report", basis: inferred("requested-outcome") },
      relationship: { value: "unknown", basis: inferred() },
      highestEffect: { value: "local-write", basis: inferred("effect-estimate") },
      dataClass: { value: "sensitive", basis: inferred("data-classification") },
      ...(overrides.dimensions || {})
    },
    signals: overrides.signals || ["account", "payment", "order"].map((id) => ({
      id,
      basis: inferred("signal-classification")
    })),
    answers: overrides.answers || {
      "immediate-goal": {
        choiceId: "explain",
        mode: "recommendation",
        basis: inferred("requested-outcome")
      }
    },
    ...(overrides.extra || {})
  };
}

function writePrivateJson(directory, name, value, mode = 0o600) {
  const file = path.join(directory, name);
  fs.writeFileSync(file, `${JSON.stringify(value)}\n`, { mode });
  if (process.platform !== "win32") fs.chmodSync(file, mode);
  return file;
}

function invoke(root, args) {
  return spawnSync(process.execPath, [gate, ...args], {
    cwd: repo,
    env: { ...process.env, GATE_HOME: path.join(root, "gate-home"), GATE_CASE: "" },
    encoding: "utf8",
    timeout: 10_000
  });
}

test("objective recommend emits only a deterministic sanitized incident recommendation", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-objective-cli-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const privateTarget = "pokerstars.com";
  const callerHandle = `obj_${Buffer.from(privateTarget, "utf8").toString("hex")}`;
  const callerSourceRef = `src_${Buffer.from(privateTarget, "utf8").toString("hex")}`;
  const privateFraction = "314159265358979323846264338327950288419716939937510";
  const callerCreatedAt = `2026-10-16T08:00:00.${privateFraction}Z`;
  const proposalFile = writePrivateJson(root, "proposal.json", incidentProposal({
    metadata: { objectiveHandle: callerHandle, createdAt: callerCreatedAt },
    signals: [{
      id: "account",
      basis: {
        provenance: "source-derived",
        claimState: "inferred",
        code: "source-classification",
        sourceRefs: [callerSourceRef]
      }
    }]
  }));

  const result = invoke(root, ["objective", "recommend", "--proposal", proposalFile, "--json"]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  const recommendation = JSON.parse(result.stdout);
  assert.equal(recommendation.route.id, "security-incident-investigation");
  assert.equal(recommendation.route.handler.state, "planning-only");
  assert.equal(recommendation.executionAuthority, false);
  assert.match(recommendation.metadata.objectiveHandle, /^obj_[a-f0-9]{64}$/u);
  assert.notEqual(recommendation.metadata.objectiveHandle, callerHandle);
  assert.equal(recommendation.metadata.createdAt, "2026-10-16T08:00:00.314Z");
  assert.ok(recommendation.capabilities.flatMap((entry) => entry.tools).every((tool) =>
    tool.state === "route-listed" && tool.suitable === "unknown"
  ));
  assert.doesNotMatch(result.stdout, /raw objective|sourceRefs|basis summary|private path|pokerstars\.com/iu);
  assert.doesNotMatch(result.stdout, new RegExp(callerHandle, "u"));
  assert.doesNotMatch(result.stdout, new RegExp(callerSourceRef, "u"));
  assert.doesNotMatch(result.stdout, new RegExp(privateFraction, "u"));
  assert.equal(fs.existsSync(path.join(root, "gate-home")), false);
});

test("objective recommend rejects stale proposals without exposing their digest or path", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-objective-stale-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const staleDigest = "0".repeat(64);
  const proposalFile = writePrivateJson(root, "stale-private.json", incidentProposal({
    metadata: { routeCatalogSha256: staleDigest }
  }));

  const result = invoke(root, ["objective", "recommend", "--proposal", proposalFile, "--json"]);
  assert.notEqual(result.status, 0);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /proposal is stale for the checked-in route catalog/u);
  assert.doesNotMatch(result.stderr, new RegExp(staleDigest, "u"));
  assert.doesNotMatch(result.stderr, new RegExp(path.basename(proposalFile), "u"));
});

test("objective recommend rejects links, oversized files, non-files, and permissive modes", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-objective-files-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const proposalFile = writePrivateJson(root, "target.json", incidentProposal());

  if (process.platform !== "win32") {
    const linked = path.join(root, "linked.json");
    fs.symlinkSync(proposalFile, linked);
    const symlinkResult = invoke(root, ["objective", "recommend", "--proposal", linked, "--json"]);
    assert.notEqual(symlinkResult.status, 0);
    assert.match(symlinkResult.stderr, /must not be a symbolic link/u);

    const hardLinked = path.join(root, "hard-linked.json");
    fs.linkSync(proposalFile, hardLinked);
    const hardLinkResult = invoke(root, ["objective", "recommend", "--proposal", hardLinked, "--json"]);
    assert.notEqual(hardLinkResult.status, 0);
    assert.match(hardLinkResult.stderr, /must be a single-link regular file/u);

    const permissive = writePrivateJson(root, "permissive.json", incidentProposal(), 0o644);
    const modeResult = invoke(root, ["objective", "recommend", "--proposal", permissive, "--json"]);
    assert.notEqual(modeResult.status, 0);
    assert.match(modeResult.stderr, /permissions are not owner-only/u);
    assert.equal(fs.statSync(permissive).mode & 0o777, 0o644, "the read-only command must not remediate permissions");
  }

  const oversized = path.join(root, "oversized.json");
  fs.writeFileSync(oversized, "x".repeat((64 * 1024) + 1), { mode: 0o600 });
  if (process.platform !== "win32") fs.chmodSync(oversized, 0o600);
  const sizeResult = invoke(root, ["objective", "recommend", "--proposal", oversized, "--json"]);
  assert.notEqual(sizeResult.status, 0);
  assert.match(sizeResult.stderr, /exceeds the 65536-byte limit/u);

  const directory = path.join(root, "directory.json");
  fs.mkdirSync(directory, { mode: 0o700 });
  const directoryResult = invoke(root, ["objective", "recommend", "--proposal", directory, "--json"]);
  assert.notEqual(directoryResult.status, 0);
  assert.match(directoryResult.stderr, /must be a single-link regular file/u);
});

test("objective recommend keeps malformed and private proposal contents out of errors", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-objective-private-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const marker = "PRIVATE-OBJECTIVE-MARKER-75319";
  const malformed = path.join(root, "malformed-private.json");
  fs.writeFileSync(malformed, `{${marker}`, { mode: 0o600 });
  if (process.platform !== "win32") fs.chmodSync(malformed, 0o600);

  const malformedResult = invoke(root, ["objective", "recommend", "--proposal", malformed, "--json"]);
  assert.notEqual(malformedResult.status, 0);
  assert.equal(malformedResult.stdout, "");
  assert.match(malformedResult.stderr, /proposal is malformed JSON/u);
  assert.doesNotMatch(malformedResult.stderr, new RegExp(marker, "u"));
  assert.doesNotMatch(malformedResult.stderr, new RegExp(path.basename(malformed), "u"));

  const expanded = writePrivateJson(root, "expanded-private.json", incidentProposal({
    extra: { objective: marker }
  }));
  const expandedResult = invoke(root, ["objective", "recommend", "--proposal", expanded, "--json"]);
  assert.notEqual(expandedResult.status, 0);
  assert.equal(expandedResult.stdout, "");
  assert.match(expandedResult.stderr, /proposal failed categorical validation/u);
  assert.doesNotMatch(expandedResult.stderr, new RegExp(marker, "u"));
  assert.doesNotMatch(expandedResult.stderr, new RegExp(path.basename(expanded), "u"));
});

test("objective recommend rejects ambiguous options and case selectors before state creation", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-objective-args-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const proposalFile = writePrivateJson(root, "proposal.json", incidentProposal());

  const repeated = invoke(root, [
    "objective", "recommend", "--proposal", proposalFile, "--proposal", proposalFile, "--json"
  ]);
  assert.notEqual(repeated.status, 0);
  assert.match(repeated.stderr, /objective option must not be repeated/u);

  const selector = invoke(root, [
    "--case", "phantom-case", "objective", "recommend", "--proposal", proposalFile, "--json"
  ]);
  assert.notEqual(selector.status, 0);
  assert.match(selector.stderr, /uses shared state and does not accept/u);
  assert.equal(fs.existsSync(path.join(root, "gate-home")), false);
});

test("repository validation binds the objective catalog to its schema and known tools", () => {
  const validation = validateRepository({ paths: { repo } });
  const objectiveContract = validation.checks.find((check) =>
    check.name === "contract:config/objective-routes.json"
  );
  assert.deepEqual(objectiveContract, {
    name: "contract:config/objective-routes.json",
    ok: true,
    detail: "objective-route-catalog.schema.json"
  });
});
