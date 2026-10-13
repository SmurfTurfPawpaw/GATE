import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { addLearning } from "../src/lib/learnings.mjs";

const execFileAsync = promisify(execFile);
const learningModule = pathToFileURL(
  path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../src/lib/learnings.mjs")
).href;

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-learning-"));
  const paths = {
    repo: path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."),
    home: path.join(root, "home"),
    engagements: path.join(root, "home", "engagements"),
    authorizations: path.join(root, "home", "authorizations"),
    plans: path.join(root, "home", "plans"),
    evidence: path.join(root, "home", "evidence"),
    upstreams: path.join(root, "home", "upstreams"),
    events: path.join(root, "home", "events.jsonl"),
    tokens: path.join(root, "home", "tokens.jsonl"),
    publicLearningRecords: path.join(root, "memory", "learnings.jsonl"),
    publicLearnings: path.join(root, "memory", "LEARNINGS.md"),
    privateLearnings: path.join(root, "home", "memory", "private", "learnings.jsonl")
  };
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return paths;
}

test("learning writes a single public cause-change record and event", (t) => {
  const paths = fixture(t);
  const learning = addLearning(
    { cause: "A tool returned a changed schema.", change: "Validate the schema before parsing." },
    { paths }
  );
  assert.equal(learning.sensitivity, "public");
  assert.equal(learning.status, "proposed");
  const lines = fs.readFileSync(paths.publicLearningRecords, "utf8").trim().split("\n");
  assert.equal(lines.length, 1);
  assert.equal(JSON.parse(lines[0]).change, "Validate the schema before parsing.");
  assert.match(fs.readFileSync(paths.publicLearnings, "utf8"), /Cause: A tool returned a changed schema\./);
  assert.match(fs.readFileSync(paths.events, "utf8"), /learning\.recorded/);
});

test("learning rejects common credential formats without writing an event", (t) => {
  const paths = fixture(t);
  const candidates = [
    ["api", "_key=", "synthetic-value"].join(""),
    ["gh", "p_", "x".repeat(24)].join(""),
    ["github", "_pat_", "x".repeat(24)].join(""),
    ["Bear", "er ", "synthetic-opaque-token-value"].join(""),
    [["ey", "J", "x".repeat(9)].join(""), "y".repeat(12), "z".repeat(12)].join("."),
    ["xo", "xb-", "1234567890-", "x".repeat(16)].join(""),
    ["s", "k-proj-", "x".repeat(24)].join(""),
    "Authorization: Digest username=\"synthetic\", response=\"synthetic\"",
    "Authorization: AWS4-HMAC-SHA256 Credential=SYNTHETIC/20261013/test/aws4_request, Signature=synthetic",
    "Cookie: session=synthetic-session; preference=dark",
    "Set-Cookie: session=synthetic-session; Path=/; HttpOnly"
  ];
  for (const candidate of candidates) {
    assert.throws(
      () => addLearning({ cause: `Observed ${candidate}`, change: "Keep the value private." }, { paths }),
      /credential/
    );
  }
  assert.equal(fs.existsSync(paths.events), false);
});

test("public project learning fails closed until a destination exists", (t) => {
  const paths = fixture(t);
  assert.throws(
    () => addLearning(
      { cause: "A project behavior changed.", change: "Record the project behavior.", scope: "project" },
      { paths }
    ),
    /use --private --scope project/
  );
  assert.equal(fs.existsSync(paths.publicLearningRecords), false);
  assert.equal(fs.existsSync(paths.publicLearnings), false);
  assert.equal(fs.existsSync(paths.events), false);

  const learning = addLearning(
    {
      cause: "A private project behavior changed.",
      change: "Record it in private project memory.",
      scope: "project",
      sensitivity: "private"
    },
    { paths }
  );
  assert.equal(learning.scope, "project");
  assert.equal(learning.sensitivity, "private");
  assert.equal(fs.readFileSync(paths.privateLearnings, "utf8").trim().split("\n").length, 1);
});

test("learning recovers an abandoned public-ledger lock", (t) => {
  const paths = fixture(t);
  const lockFile = `${paths.publicLearningRecords}.lock`;
  fs.mkdirSync(path.dirname(lockFile), { recursive: true });
  fs.writeFileSync(lockFile, "abandoned-owner", "utf8");
  const stale = new Date(Date.now() - 60_000);
  fs.utimesSync(lockFile, stale, stale);

  addLearning(
    { cause: "A writer stopped while holding the lock.", change: "Recover bounded stale locks." },
    { paths, lock: { staleMs: 10, retryMs: 1, timeoutMs: 500 } }
  );

  assert.equal(fs.existsSync(lockFile), false);
  assert.match(fs.readFileSync(paths.publicLearnings, "utf8"), /Recover bounded stale locks\./);
});

test("concurrent public writers preserve every JSONL and Markdown record", async (t) => {
  const paths = fixture(t);
  const writer = `
    import { addLearning } from ${JSON.stringify(learningModule)};
    const paths = JSON.parse(process.env.GATE_TEST_PATHS);
    const index = process.env.GATE_TEST_INDEX;
    addLearning(
      { cause: \`Concurrent cause \${index}.\`, change: \`Preserve concurrent change \${index}.\` },
      { paths }
    );
  `;
  const count = 8;
  await Promise.all(
    Array.from({ length: count }, (_, index) => execFileAsync(
      process.execPath,
      ["--input-type=module", "--eval", writer],
      {
        env: {
          ...process.env,
          GATE_TEST_PATHS: JSON.stringify(paths),
          GATE_TEST_INDEX: String(index)
        },
        timeout: 20_000
      }
    ))
  );

  const records = fs.readFileSync(paths.publicLearningRecords, "utf8").trim().split("\n").map(JSON.parse);
  const ledger = fs.readFileSync(paths.publicLearnings, "utf8");
  assert.equal(records.length, count);
  assert.equal(new Set(records.map((record) => record.cause)).size, count);
  for (let index = 0; index < count; index += 1) {
    assert.match(ledger, new RegExp(`Cause: Concurrent cause ${index}\\.`));
  }
  assert.equal((ledger.match(/Cause: Concurrent cause/g) || []).length, count);
  assert.equal(fs.existsSync(`${paths.publicLearningRecords}.lock`), false);
});
