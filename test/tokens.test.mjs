import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { buildStatus } from "../src/lib/status.mjs";
import { projectUsage } from "../src/observer/server.mjs";
import { validateDocument } from "../src/lib/schema.mjs";
import { extractTokenRecord, normalizeUsage, scanCodexUsage } from "../src/lib/tokens.mjs";

test("normalizes Codex cumulative token events", () => {
  const record = {
    timestamp: "2026-10-13T09:08:07.000Z",
    type: "event_msg",
    payload: {
      type: "token_count",
      info: {
        total_token_usage: {
          input_tokens: 120,
          cached_input_tokens: 80,
          output_tokens: 40,
          reasoning_output_tokens: 10,
          total_tokens: 160
        },
        model_context_window: 200000
      }
    }
  };
  assert.deepEqual(extractTokenRecord(record), {
    usage: { input: 120, cached_input: 80, output: 40, reasoning: 10, total: 160 },
    context_window: 200000,
    provider: "openai",
    model: null,
    at: "2026-10-13T09:08:07.000Z"
  });
});

test("reports missing usage as unavailable rather than zero", () => {
  assert.equal(normalizeUsage({}), null);
  assert.deepEqual(normalizeUsage({ input_tokens: 12, total_tokens: 12 }), {
    input: 12,
    cached_input: null,
    output: null,
    reasoning: null,
    total: 12
  });
  assert.deepEqual(normalizeUsage({ input_tokens: 0, output_tokens: 0 }), {
    input: 0,
    cached_input: null,
    output: 0,
    reasoning: null,
    total: 0
  });
});

test("an empty session scan uses null unavailable totals", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-tokens-empty-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const result = await scanCodexUsage({ roots: [root] });
  assert.equal(result.availability, "unavailable");
  assert.equal(result.partial, false);
  for (const value of Object.values(result.totals)) assert.equal(value, null);
});

test("session scans return canonical validated usage records", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-tokens-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(
    path.join(root, "session.jsonl"),
    `${JSON.stringify({
      timestamp: "2026-10-13T12:34:56.000Z",
      payload: {
        type: "token_count",
        info: {
          total_token_usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 },
          model_context_window: 200000
        }
      }
    })}\n`
  );
  const result = await scanCodexUsage({ roots: [root] });
  assert.equal(result.availability, "exact");
  assert.equal(result.totals.totalTokens, 15);
  assert.equal(result.totals.cachedInputTokens, null);
  assert.equal(result.records[0].at, "2026-10-13T12:34:56.000Z");
  assert.equal(result.sessions[0].context_window, 200000);
  assert.equal(result.source, "codex-session-jsonl:host-session-roots");
  const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  assert.equal(validateDocument(result.records[0], "token-usage.schema.json", { paths: { repo } }).ok, true);
  const projected = projectUsage(result);
  assert.equal(projected.totalTokens, 15);
  assert.equal(projected.cachedInputTokens, null);
  assert.equal(projected.sessions[0].contextWindow, 200000);
});

test("discovers and sorts all sessions before applying the scan cap", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-tokens-cap-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const writeSession = (name, total, modified, timestamp) => {
    const file = path.join(root, name);
    fs.writeFileSync(file, `${JSON.stringify({
      timestamp,
      payload: { type: "token_count", info: { total_token_usage: { total_tokens: total } } }
    })}\n`);
    fs.utimesSync(file, modified, modified);
  };
  writeSession("old.jsonl", 1, new Date("2026-10-01T00:00:00.000Z"), "2026-10-01T00:00:00.000Z");
  writeSession("new.jsonl", 9, new Date("2026-10-03T00:00:00.000Z"), "2026-10-03T01:02:03.000Z");
  writeSession("middle.jsonl", 5, new Date("2026-10-02T00:00:00.000Z"), "2026-10-02T00:00:00.000Z");

  const result = await scanCodexUsage({ roots: [root], maximumFiles: 1 });
  assert.equal(result.discoveredFiles, 3);
  assert.equal(result.scannedFiles, 1);
  assert.equal(result.matchedFiles, 1);
  assert.equal(result.truncated, true);
  assert.equal(result.partial, true);
  assert.equal(result.availability, "estimated");
  assert.equal(result.totals.totalTokens, 9);
  assert.equal(result.records[0].at, "2026-10-03T01:02:03.000Z");
  assert.equal(projectUsage(result).availability, "estimated");
});

test("marks an aggregate estimated when a scanned session has no usage event", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-tokens-partial-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(path.join(root, "usage.jsonl"), `${JSON.stringify({
    payload: { type: "token_count", info: { total_token_usage: { total_tokens: 3 } } }
  })}\n`);
  fs.writeFileSync(path.join(root, "missing.jsonl"), `${JSON.stringify({ type: "session_meta" })}\n`);

  const result = await scanCodexUsage({ roots: [root] });
  assert.equal(result.availability, "estimated");
  assert.equal(result.partial, true);
  assert.equal(result.matchedFiles, 1);
  assert.equal(result.totals.totalTokens, 3);
});

test("tail scanning bounds bytes and labels the recovered aggregate estimated", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-tokens-tail-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const event = JSON.stringify({
    timestamp: "2026-10-13T15:00:00.000Z",
    payload: { type: "token_count", info: { total_token_usage: { total_tokens: 21 } } }
  });
  fs.writeFileSync(path.join(root, "large.jsonl"), `${"x".repeat(4096)}\n${event}\n`, "utf8");

  const result = await scanCodexUsage({ roots: [root], maximumBytes: 512, maximumBytesPerFile: 512 });
  assert.ok(result.bytesRead <= 512);
  assert.equal(result.tailTruncatedFiles, 1);
  assert.equal(result.partial, true);
  assert.equal(result.availability, "estimated");
  assert.equal(result.totals.totalTokens, 21);
});

test("session discovery reports directory, depth, file, and time cutoffs", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-tokens-bounds-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const event = `${JSON.stringify({
    payload: { type: "token_count", info: { total_token_usage: { total_tokens: 1 } } }
  })}\n`;
  fs.writeFileSync(path.join(root, "one.jsonl"), event);
  fs.writeFileSync(path.join(root, "two.jsonl"), event);
  fs.mkdirSync(path.join(root, "nested", "deeper"), { recursive: true });
  fs.writeFileSync(path.join(root, "nested", "deep.jsonl"), event);

  const fileLimited = await scanCodexUsage({ roots: [root], maximumDiscoveredFiles: 1 });
  assert.equal(fileLimited.discoveryFileLimited, true);
  assert.equal(fileLimited.discoveredFiles, 1);
  assert.equal(fileLimited.availability, "estimated");

  const directoryLimited = await scanCodexUsage({ roots: [root], maximumDirectories: 1 });
  assert.equal(directoryLimited.directoryLimited, true);
  assert.equal(directoryLimited.partial, true);

  const depthLimited = await scanCodexUsage({ roots: [root], maximumDepth: 0 });
  assert.equal(depthLimited.depthLimited, true);
  assert.equal(depthLimited.partial, true);

  const timedOut = await scanCodexUsage({ roots: [root], maximumDurationMs: 0 });
  assert.equal(timedOut.timedOut, true);
  assert.equal(timedOut.partial, true);
  assert.equal(timedOut.availability, "unavailable");
  for (const value of Object.values(timedOut.totals)) assert.equal(value, null);
});

test("build status prefers deduplicated canonical usage over its session-scan fallback", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-token-status-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const home = path.join(root, "home");
  const sessionRoot = path.join(root, "sessions");
  fs.mkdirSync(path.join(home, "memory", "private"), { recursive: true });
  fs.mkdirSync(sessionRoot, { recursive: true });
  const paths = {
    repo,
    home,
    events: path.join(home, "events.jsonl"),
    tokens: path.join(home, "tokens.jsonl"),
    engagements: path.join(home, "engagements"),
    authorizations: path.join(home, "authorizations"),
    plans: path.join(home, "plans"),
    evidence: path.join(home, "evidence"),
    upstreams: path.join(home, "upstreams"),
    upstreamTools: path.join(home, "upstream-tools"),
    publicLearningRecords: path.join(root, "public-learnings.jsonl"),
    publicLearnings: path.join(root, "LEARNINGS.md"),
    privateLearnings: path.join(home, "memory", "private", "learnings.jsonl")
  };
  const canonical = {
    apiVersion: "gate.usage/v1",
    id: "use_statuscanonical",
    at: "2026-10-13T13:00:00.000Z",
    runId: "run.status-canonical",
    taskId: null,
    agent: "codex",
    provider: "openai",
    model: "gpt-6",
    availability: "exact",
    measure: "cumulative",
    inputTokens: 25,
    cachedInputTokens: null,
    outputTokens: 15,
    reasoningTokens: null,
    totalTokens: 40,
    source: "gate-app-server"
  };
  fs.writeFileSync(paths.tokens, `${Array(501).fill(JSON.stringify(canonical)).join("\n")}\n`, "utf8");
  fs.writeFileSync(path.join(sessionRoot, "session.jsonl"), `${JSON.stringify({
    payload: { type: "token_count", info: { total_token_usage: { total_tokens: 10 } } }
  })}\n`, "utf8");

  const rootsThatMustNotBeScanned = {
    [Symbol.iterator]() {
      throw new Error("canonical usage must bypass host session scanning");
    }
  };
  const status = await buildStatus({ paths, tokens: { roots: rootsThatMustNotBeScanned } });
  assert.equal(Array.isArray(status.tokens), true);
  assert.equal(status.tokens.length, 1);
  const usage = projectUsage(status.tokens);
  assert.equal(usage.availability, "estimated");
  assert.equal(usage.source, "gate-token-log");
  assert.equal(usage.totalTokens, 40);
});

test("build status falls back to scoped session telemetry when the token log has no valid record", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-token-fallback-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const home = path.join(root, "home");
  const sessionRoot = path.join(root, "sessions");
  fs.mkdirSync(path.join(home, "memory", "private"), { recursive: true });
  fs.mkdirSync(sessionRoot, { recursive: true });
  const paths = {
    repo,
    home,
    events: path.join(home, "events.jsonl"),
    tokens: path.join(home, "tokens.jsonl"),
    engagements: path.join(home, "engagements"),
    authorizations: path.join(home, "authorizations"),
    plans: path.join(home, "plans"),
    evidence: path.join(home, "evidence"),
    upstreams: path.join(home, "upstreams"),
    upstreamTools: path.join(home, "upstream-tools"),
    publicLearningRecords: path.join(root, "public-learnings.jsonl"),
    publicLearnings: path.join(root, "LEARNINGS.md"),
    privateLearnings: path.join(home, "memory", "private", "learnings.jsonl")
  };
  fs.writeFileSync(paths.tokens, `${JSON.stringify({ apiVersion: "wrong" })}\n`, "utf8");
  fs.writeFileSync(path.join(sessionRoot, "session.jsonl"), `${JSON.stringify({
    payload: {
      type: "token_count",
      info: { total_token_usage: { total_tokens: 10 }, model_context_window: 100000 }
    }
  })}\n`, "utf8");

  const status = await buildStatus({ paths, tokens: { roots: [sessionRoot] } });
  assert.equal(Array.isArray(status.tokens), false);
  assert.equal(status.tokens.source, "codex-session-jsonl:host-session-roots");
  assert.equal(projectUsage(status.tokens).sessions[0].contextWindow, 100000);
});
