import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const gate = path.join(repo, "bin", "gate.mjs");

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-program-source-cli-"));
  const home = path.join(root, "home");
  const body = path.join(root, "saved-rules.html");
  const projection = path.join(root, "projection.json");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, home, body, projection };
}

function invoke(args, home) {
  const result = spawnSync(process.execPath, [gate, ...args], {
    cwd: repo,
    env: { ...process.env, GATE_HOME: home, GATE_CASE: "" },
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: 2 * 1024 * 1024
  });
  assert.ifError(result.error);
  assert.equal(result.signal, null, `CLI terminated by ${result.signal}: ${result.stderr}`);
  return result;
}

function writeProjection(file, suffix = "one") {
  const value = {
    scope: [{
      id: "challenge-web",
      selector: { type: "domain", value: `private-selector-${suffix}.example.test` },
      disposition: "allowed",
      claimState: "observed",
      conditions: ["Use only the intentionally vulnerable challenge."],
      locator: { kind: "section", value: "Scope" }
    }],
    rules: [{
      id: "challenge-rule",
      category: "other",
      disposition: "allowed",
      claimState: "observed",
      summary: `private-rule-summary-${suffix}`,
      conditions: [],
      locator: { kind: "section", value: "Rules" }
    }]
  };
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

function importArgs(body, projection) {
  return [
    "source", "import", "training-ctf", "published-rules",
    "--file", body,
    "--type", "program-rules",
    "--title", "Published challenge rules",
    "--reference", "https://challenge.example.org/rules",
    "--media-type", "text/html",
    "--projection", projection,
    "--json"
  ];
}

test("source CLI imports, shows, and diffs private revisions without printing bodies or claims", (t) => {
  const { home, body, projection } = fixture(t);
  const firstBody = "RAW-SOURCE-CANARY-FIRST";
  fs.writeFileSync(body, firstBody, { mode: 0o600 });
  writeProjection(projection, "one");

  const first = invoke(importArgs(body, projection), home);
  assert.equal(first.status, 0, first.stderr);
  const firstReceipt = JSON.parse(first.stdout);
  assert.equal(firstReceipt.snapshot.revision, 1);
  assert.equal(firstReceipt.snapshot.projection.scopeClaims, 1);
  assert.equal(firstReceipt.snapshot.projection.ruleClaims, 1);
  assert.equal(firstReceipt.diff.firstRevision, true);
  assert.equal(first.stdout.includes(firstBody), false);
  assert.equal(first.stdout.includes("private-selector-one"), false);
  assert.equal(first.stdout.includes("private-rule-summary-one"), false);
  assert.equal(first.stdout.includes(body), false);
  assert.equal(Object.hasOwn(firstReceipt.snapshot, "storage"), false);

  const secondBody = "RAW-SOURCE-CANARY-SECOND";
  fs.writeFileSync(body, secondBody, { mode: 0o600 });
  writeProjection(projection, "two");
  const second = invoke(importArgs(body, projection), home);
  assert.equal(second.status, 0, second.stderr);
  assert.equal(JSON.parse(second.stdout).snapshot.revision, 2);
  assert.equal(second.stdout.includes(secondBody), false);
  assert.equal(second.stdout.includes("private-selector-two"), false);

  const shown = invoke(["source", "show", "training-ctf", "published-rules", "--json"], home);
  assert.equal(shown.status, 0, shown.stderr);
  const metadata = JSON.parse(shown.stdout);
  assert.equal(metadata.revision, 2);
  assert.equal(metadata.body.bytes, Buffer.byteLength(secondBody));
  assert.match(metadata.identities.contentSha256, /^[a-f0-9]{64}$/u);
  assert.equal(shown.stdout.includes(secondBody), false);
  assert.equal(shown.stdout.includes("private-selector-two"), false);

  const diff = invoke(["source", "diff", "training-ctf", "published-rules", "--json"], home);
  assert.equal(diff.status, 0, diff.stderr);
  assert.deepEqual(JSON.parse(diff.stdout), {
    firstRevision: false,
    previousRevision: 1,
    currentRevision: 2,
    changed: true,
    contentChanged: true,
    projectionChanged: true,
    sourceMetadataChanged: false,
    scope: { added: 0, removed: 0, changed: 1, unchanged: 0 },
    rules: { added: 0, removed: 0, changed: 1, unchanged: 0 }
  });
  assert.equal(diff.stdout.includes("private-selector"), false);
  assert.equal(diff.stdout.includes("private-rule-summary"), false);

  const explicit = invoke([
    "source", "diff", "training-ctf", "published-rules", "--from", "1", "--to", "2", "--json"
  ], home);
  assert.equal(explicit.status, 0, explicit.stderr);
  assert.deepEqual(JSON.parse(explicit.stdout), JSON.parse(diff.stdout));
});

test("source CLI makes public retrieval explicit and keeps the shared registry selector-free", (t) => {
  const { home } = fixture(t);
  const common = [
    "source", "fetch", "training-ctf", "published-rules",
    "--url", "https://challenge.example.org/rules",
    "--type", "program-rules",
    "--title", "Published challenge rules",
    "--json"
  ];
  const disabled = invoke(common, home);
  assert.notEqual(disabled.status, 0);
  assert.match(disabled.stderr, /requires explicit --allow-network/u);

  const valued = invoke([...common, "--allow-network=yes"], home);
  assert.notEqual(valued.status, 0);
  assert.match(valued.stderr, /--allow-network does not accept a value/u);

  const repeated = invoke([...common, "--allow-network=no", "--allow-network"], home);
  assert.notEqual(repeated.status, 0);
  assert.match(repeated.stderr, /program source option must not be repeated/u);

  const selected = invoke([
    "--unassigned", "source", "show", "training-ctf", "published-rules", "--json"
  ], home);
  assert.notEqual(selected.status, 0);
  assert.match(selected.stderr, /uses shared state and does not accept/u);
});

test("CLI help exposes the complete program source operator path", (t) => {
  const { home } = fixture(t);
  const result = invoke(["help"], home);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /source import PROGRAM SOURCE/u);
  assert.match(result.stdout, /source fetch PROGRAM SOURCE/u);
  assert.match(result.stdout, /source show PROGRAM SOURCE/u);
  assert.match(result.stdout, /source diff PROGRAM SOURCE/u);
  assert.match(result.stdout, /--allow-network/u);
});
