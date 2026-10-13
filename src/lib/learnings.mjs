import fs from "node:fs";
import path from "node:path";
import { appendJsonLine } from "./jsonl.mjs";
import { newId, recordEvent } from "./events.mjs";
import { ensureRuntime, runtimePaths } from "./paths.mjs";
import { assertValidDocument } from "./schema.mjs";
import { assertNoLikelySecret, oneLine } from "./text.mjs";

const LEDGER_PREAMBLE = `# GATE learnings

This reviewed public ledger contains sanitized repository-wide lessons. The machine-readable append log is \`memory/learnings.jsonl\`; promotion updates this ledger with the same cause and change. Target identifiers, credentials, private paths, captures, client material, and unpublished findings belong in the private learning record under \`GATE_HOME\`.

Format:

\`\`\`text
YYYY-MM-DD | Cause: what happened | Change: the durable behavior or configuration change | Evidence: public reference | Status: proposed|active|superseded|reverted
\`\`\`
`;

const waitBuffer = new Int32Array(new SharedArrayBuffer(4));

function sleep(milliseconds) {
  Atomics.wait(waitBuffer, 0, 0, milliseconds);
}

function lockOwner() {
  return `${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function releaseLock(file, descriptor, owner) {
  try {
    fs.closeSync(descriptor);
  } finally {
    try {
      if (fs.readFileSync(file, "utf8") === owner) fs.unlinkSync(file);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
}

function withFileLock(file, action, options = {}) {
  const timeoutMs = options.timeoutMs ?? 5_000;
  const retryMs = options.retryMs ?? 10;
  const staleMs = options.staleMs ?? 30_000;
  const lockFile = `${file}.lock`;
  const owner = lockOwner();
  const deadline = Date.now() + timeoutMs;
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });

  while (true) {
    let descriptor;
    try {
      descriptor = fs.openSync(lockFile, "wx", 0o600);
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
    }
    if (descriptor !== undefined) {
      try {
        fs.writeFileSync(descriptor, owner, "utf8");
        fs.fsyncSync(descriptor);
      } catch (error) {
        fs.closeSync(descriptor);
        fs.rmSync(lockFile, { force: true });
        throw error;
      }
      try {
        return action();
      } finally {
        releaseLock(lockFile, descriptor, owner);
      }
    }

    try {
      const stat = fs.statSync(lockFile);
      if (Date.now() - stat.mtimeMs > staleMs) {
        const staleFile = `${lockFile}.stale-${owner}`;
        try {
          fs.renameSync(lockFile, staleFile);
          fs.rmSync(staleFile, { force: true });
          continue;
        } catch (error) {
          if (!["ENOENT", "EEXIST"].includes(error.code)) throw error;
        }
      }
    } catch (error) {
      if (error.code === "ENOENT") continue;
      throw error;
    }

    if (Date.now() >= deadline) {
      throw new Error(`timed out waiting for learning ledger lock: ${lockFile}`);
    }
    sleep(Math.min(retryMs, Math.max(1, deadline - Date.now())));
  }
}

function learningLine(learning) {
  const evidence = learning.evidence.join(", ");
  return `- ${learning.at.slice(0, 10)} | Cause: ${learning.cause} | Change: ${learning.change} | Evidence: ${evidence} | Status: ${learning.status}`;
}

function readPublicRecords(file, paths) {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, "utf8")
    .split(/\r?\n/)
    .filter((line) => line.trim())
    .map((line, index) => {
      let learning;
      try {
        learning = JSON.parse(line);
      } catch {
        throw new Error(`public learning record ${index + 1} is not valid JSON`);
      }
      assertValidDocument(learning, "learning.schema.json", { paths });
      if (learning.sensitivity !== "public") {
        throw new Error(`public learning record ${index + 1} is not public`);
      }
      return learning;
    });
}

function renderLedger(learnings) {
  const active = learnings.filter((learning) => learning.status === "active").map(learningLine);
  const proposed = learnings.filter((learning) => learning.status === "proposed").map(learningLine);
  const historical = learnings
    .filter((learning) => ["superseded", "reverted"].includes(learning.status))
    .map(learningLine);
  return `${LEDGER_PREAMBLE}
## Active

${active.join("\n")}

## Proposed

Add proposed lessons here only after removing sensitive context. Promotion must include the behavior, policy, configuration, test, or documentation change that makes the lesson real.
${proposed.join("\n")}

## Superseded or reverted

Move old entries here with the new evidence and replacement learning. Do not erase history.
${historical.join("\n")}
`;
}

function writeAtomically(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temporary = path.join(
    path.dirname(file),
    `.${path.basename(file)}.${process.pid}.${Math.random().toString(16).slice(2)}.tmp`
  );
  try {
    fs.writeFileSync(temporary, content, { encoding: "utf8", mode: 0o644, flag: "wx" });
    fs.renameSync(temporary, file);
  } finally {
    fs.rmSync(temporary, { force: true });
  }
}

function appendPublicLearning(paths, learning, lockOptions) {
  withFileLock(paths.publicLearningRecords, () => {
    const learnings = [...readPublicRecords(paths.publicLearningRecords, paths), learning];
    appendJsonLine(paths.publicLearningRecords, learning, 0o644);
    writeAtomically(paths.publicLearnings, renderLedger(learnings));
  }, lockOptions);
}

export function addLearning(input, options = {}) {
  const paths = options.paths || runtimePaths(options);
  ensureRuntime(paths);
  const cause = oneLine(input.cause, { name: "cause" });
  const change = oneLine(input.change, { name: "change" });
  assertNoLikelySecret(cause, "cause");
  assertNoLikelySecret(change, "change");
  const sensitivity = input.sensitivity || "public";
  if (!["public", "private"].includes(sensitivity)) {
    throw new Error("sensitivity must be public or private");
  }
  const scope = input.scope || (sensitivity === "private" ? "session" : "repository");
  if (!["session", "project", "repository"].includes(scope)) {
    throw new Error("scope must be session, project, or repository");
  }
  if (scope === "project" && sensitivity === "public") {
    throw new Error(
      "public project learning has no configured registry or destination; use --private --scope project"
    );
  }
  const status = input.status || (sensitivity === "private" ? "active" : "proposed");
  if (!["proposed", "active", "superseded", "reverted"].includes(status)) {
    throw new Error("status must be proposed, active, superseded, or reverted");
  }
  const evidenceEvent = recordEvent(
    {
      kind: "learning.observed",
      summary: `${cause} → ${change}`
    },
    { paths }
  );
  const learning = {
    apiVersion: "gate.learning/v1",
    id: input.id || newId("lrn"),
    at: input.at || new Date().toISOString(),
    scope,
    cause,
    change,
    evidence: Array.isArray(input.evidence) && input.evidence.length ? input.evidence : [`event://${evidenceEvent.id}`],
    status,
    sensitivity,
    supersedes: input.supersedes || null,
    configurationRefs: Array.isArray(input.configurationRefs) ? input.configurationRefs : []
  };
  assertValidDocument(learning, "learning.schema.json", { paths });
  if (sensitivity === "private") {
    appendJsonLine(paths.privateLearnings, learning);
  } else {
    appendPublicLearning(paths, learning, options.lock);
  }
  recordEvent(
    {
      kind: "learning.recorded",
      summary: `${cause} → ${change}`,
      evidenceRefs: [`event://${evidenceEvent.id}`]
    },
    { paths }
  );
  return learning;
}
