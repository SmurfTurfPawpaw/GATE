import assert from "node:assert/strict";
import { execFile, execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { addLearning, withLearningLedgerSnapshot } from "../src/lib/learnings.mjs";
import { runtimePaths } from "../src/lib/paths.mjs";

const execFileAsync = promisify(execFile);
const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const learningModule = pathToFileURL(
  path.join(repo, "src", "lib", "learnings.mjs")
).href;

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-learning-"));
  const fixtureRepo = path.join(root, "repository");
  fs.mkdirSync(fixtureRepo, { recursive: true });
  fs.cpSync(path.join(repo, "schemas"), path.join(fixtureRepo, "schemas"), { recursive: true });
  const paths = runtimePaths({ home: path.join(root, "home"), repo: fixtureRepo });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return paths;
}

function processStartTicks(pid = process.pid) {
  const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
  const close = stat.lastIndexOf(")");
  return stat.slice(close + 2).trim().split(/\s+/u)[19];
}

function lockOwner(overrides = {}) {
  if (process.platform !== "linux") throw new Error("learning lock identity fixture requires Linux");
  return {
    apiVersion: "gate.learning-lock/v1",
    pid: process.pid,
    platform: "linux",
    bootId: fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim().toLowerCase(),
    startTimeTicks: processStartTicks(),
    nonce: "a".repeat(32),
    createdAt: "2026-10-15T12:00:00.000Z",
    ...overrides
  };
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

test("generated public ledger preserves lifecycle statuses across multiple records", (t) => {
  const paths = fixture(t);
  const statuses = ["active", "active", "proposed", "proposed", "superseded", "reverted"];
  for (const [index, status] of statuses.entries()) {
    addLearning({
      cause: `Lifecycle observation number ${index} was recorded.`,
      change: "Display the recorded lifecycle status.",
      status
    }, { paths });
  }
  const ledger = fs.readFileSync(paths.publicLearnings, "utf8");
  const displayed = ledger.split("\n").filter((line) => line.startsWith("- "))
    .map((line) => line.split(" | Status: ")[1]);
  assert.deepEqual(displayed, statuses);
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

test("learning recovers a valid public-ledger lock only when its owner is provably dead", (t) => {
  if (process.platform !== "linux") return t.skip("provable process identity recovery requires Linux");
  const paths = fixture(t);
  const lockFile = `${paths.publicLearningRecords}.lock`;
  fs.mkdirSync(path.dirname(lockFile), { recursive: true });
  fs.writeFileSync(lockFile, `${JSON.stringify(lockOwner({
    bootId: "00000000-0000-0000-0000-000000000000"
  }))}\n`, { mode: 0o600 });
  const stale = new Date(Date.now() - 60_000);
  fs.utimesSync(lockFile, stale, stale);

  addLearning(
    { cause: "A writer stopped while holding the lock.", change: "Recover only locks with a provably dead owner." },
    { paths, lock: { retryMs: 1, timeoutMs: 500 } }
  );

  assert.equal(fs.existsSync(lockFile), false);
  assert.match(fs.readFileSync(paths.publicLearnings, "utf8"), /Recover only locks with a provably dead owner\./);
});

test("learning recovers a lock owned by an unreaped zombie process", async (t) => {
  if (process.platform !== "linux") return t.skip("zombie process identity recovery requires Linux");
  const parent = spawn("python3", ["-c", `
import os, time
pid = os.fork()
if pid == 0:
    os._exit(0)
while True:
    with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as handle:
        value = handle.read()
    state = value[value.rfind(")") + 2:].split()[0]
    if state == "Z":
        break
    time.sleep(0.01)
print(pid, flush=True)
time.sleep(30)
`], { stdio: ["ignore", "pipe", "pipe"] });
  t.after(() => {
    if (parent.exitCode === null && parent.signalCode === null) parent.kill("SIGKILL");
  });
  const zombiePid = await new Promise((resolve, reject) => {
    let output = "";
    parent.stdout.on("data", (chunk) => {
      output += chunk;
      const line = output.split(/\r?\n/u)[0];
      if (/^\d+$/u.test(line)) resolve(Number(line));
    });
    parent.once("error", reject);
    parent.once("exit", (code) => reject(new Error(`zombie fixture exited before reporting its child (${code})`)));
  });
  const stat = fs.readFileSync(`/proc/${zombiePid}/stat`, "utf8");
  assert.equal(stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\s+/u)[0], "Z");

  const paths = fixture(t);
  const lockFile = `${paths.publicLearningRecords}.lock`;
  fs.mkdirSync(path.dirname(lockFile), { recursive: true });
  fs.writeFileSync(lockFile, `${JSON.stringify(lockOwner({
    pid: zombiePid,
    startTimeTicks: processStartTicks(zombiePid)
  }))}\n`, { mode: 0o600 });
  addLearning(
    { cause: "A killed writer remained unreaped.", change: "Treat zombie lock owners as provably dead." },
    { paths, lock: { retryMs: 1, timeoutMs: 500 } }
  );
  assert.equal(fs.existsSync(lockFile), false);
});

test("an old lock owned by this live process is never stolen", (t) => {
  if (process.platform !== "linux") return t.skip("stable live-owner identity fixture requires Linux");
  const paths = fixture(t);
  const lockFile = `${paths.publicLearningRecords}.lock`;
  fs.mkdirSync(path.dirname(lockFile), { recursive: true });
  fs.writeFileSync(lockFile, `${JSON.stringify(lockOwner())}\n`, { mode: 0o600 });
  const old = new Date(Date.now() - 86_400_000);
  fs.utimesSync(lockFile, old, old);

  assert.throws(
    () => addLearning(
      { cause: "A live writer held an old lock.", change: "Wait for its release without stealing it." },
      { paths, lock: { staleMs: 1, retryMs: 1, timeoutMs: 30 } }
    ),
    /timed out waiting for learning ledger lock/u
  );
  assert.deepEqual(JSON.parse(fs.readFileSync(lockFile, "utf8")), lockOwner());
  assert.equal(fs.existsSync(paths.publicLearningRecords), false);
});

test("a disappeared lock marker is reported as ownership loss", (t) => {
  const paths = fixture(t);
  const lockFile = `${paths.publicLearningRecords}.lock`;
  assert.throws(
    () => withLearningLedgerSnapshot({ paths }, () => fs.unlinkSync(lockFile)),
    /lock disappeared before release/u
  );
});

test("a complete lock marker is published atomically after owner bytes are durable", (t) => {
  const paths = fixture(t);
  const lockFile = `${paths.publicLearningRecords}.lock`;
  let hookCalls = 0;
  withLearningLedgerSnapshot({
    paths,
    lock: {
      beforePublish(pending) {
        hookCalls += 1;
        assert.equal(fs.existsSync(pending), true);
        assert.equal(fs.existsSync(lockFile), false);
        execFileSync(process.execPath, ["--input-type=module", "--eval", `
          import { addLearning } from ${JSON.stringify(learningModule)};
          const paths = JSON.parse(process.env.GATE_TEST_PATHS);
          addLearning(
            { cause: "A contender arrived before publication.", change: "Publish only complete owner records." },
            { paths }
          );
        `], {
          env: { ...process.env, GATE_TEST_PATHS: JSON.stringify(paths) },
          cwd: path.dirname(paths.home),
          timeout: 20_000
        });
        assert.equal(fs.existsSync(lockFile), false);
      }
    }
  }, () => {
    assert.equal(fs.existsSync(lockFile), true);
    assert.doesNotThrow(() => JSON.parse(fs.readFileSync(lockFile, "utf8")));
  });
  assert.equal(hookCalls, 1);
  assert.match(fs.readFileSync(paths.publicLearnings, "utf8"), /Publish only complete owner records\./u);
  assert.equal(fs.existsSync(lockFile), false);
  assert.deepEqual(fs.readdirSync(path.join(path.dirname(lockFile), ".gate-learning-locks")), []);
});

test("concurrent contenders serialize recovery and cannot displace a replacement owner", async (t) => {
  if (process.platform !== "linux") return t.skip("serialized dead-owner recovery requires Linux flock");
  const paths = fixture(t);
  const lockFile = `${paths.publicLearningRecords}.lock`;
  fs.mkdirSync(path.dirname(lockFile), { recursive: true });
  fs.writeFileSync(lockFile, `${JSON.stringify(lockOwner({
    bootId: "00000000-0000-0000-0000-000000000000"
  }))}\n`, { mode: 0o600 });
  const writer = `
    import { addLearning } from ${JSON.stringify(learningModule)};
    const paths = JSON.parse(process.env.GATE_TEST_PATHS);
    const index = process.env.GATE_TEST_INDEX;
    addLearning(
      { cause: \`Recovery contender \${index} observed a dead owner.\`, change: \`Serialize recovery contender \${index}.\` },
      { paths, lock: { retryMs: 1, timeoutMs: 5000 } }
    );
  `;
  const workingDirectories = Array.from({ length: 3 }, (_, index) => {
    const directory = path.join(path.dirname(paths.home), `contender-${index}`);
    fs.mkdirSync(directory);
    return directory;
  });
  await Promise.all(Array.from({ length: 3 }, (_, index) => execFileAsync(
    process.execPath,
    ["--input-type=module", "--eval", writer],
    {
      env: {
        ...process.env,
        TMPDIR: workingDirectories[index],
        GATE_TEST_PATHS: JSON.stringify(paths),
        GATE_TEST_INDEX: String(index)
      },
      cwd: workingDirectories[index],
      timeout: 20_000
    }
  )));

  const records = fs.readFileSync(paths.publicLearningRecords, "utf8").trim().split("\n").map(JSON.parse);
  assert.equal(records.length, 3);
  assert.equal(new Set(records.map((record) => record.id)).size, 3);
  assert.equal(fs.existsSync(lockFile), false);
  assert.equal(fs.existsSync(`${lockFile}.recovery`), false);
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
