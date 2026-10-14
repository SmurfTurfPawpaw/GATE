import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { appendJsonLine, readJsonLines } from "../src/lib/jsonl.mjs";

test("JSONL reads are tail-bounded and never parse a truncated leading line", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-jsonl-"));
  const file = path.join(root, "events.jsonl");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const lines = Array.from({ length: 20 }, (_, index) => JSON.stringify({ index, padding: "x".repeat(40) }));
  fs.writeFileSync(file, `${lines.join("\n")}\n`);

  const metadata = {};
  const values = await readJsonLines(file, { limit: 3, maxBytes: 220, metadata });
  assert.deepEqual(values.map((value) => value.index), [17, 18, 19]);
  assert.equal(values.some((value) => value.kind === "invalid-jsonl"), false);
  assert.equal(metadata.byteTruncated, true);
  assert.equal(metadata.limitTruncated, false);

  const limitMetadata = {};
  await readJsonLines(file, { limit: 3, maxBytes: 10_000, metadata: limitMetadata });
  assert.equal(limitMetadata.byteTruncated, false);
  assert.equal(limitMetadata.limitTruncated, true);
});

test("large JSONL tails retain ordered records without repeatedly shifting the result", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-jsonl-large-"));
  const file = path.join(root, "events.jsonl");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const lineCount = 100_000;
  const limit = 8_192;
  const invalidIndex = lineCount - 11;
  const lines = Array.from({ length: lineCount }, (_, index) => (
    index === invalidIndex ? "{malformed" : JSON.stringify({ index })
  ));
  const payload = `${lines.join("\n")}\n`;
  fs.writeFileSync(file, payload);

  const metadata = {};
  const values = await readJsonLines(file, {
    limit,
    maxBytes: Buffer.byteLength(payload) + 1,
    metadata
  });

  assert.equal(values.length, limit);
  assert.deepEqual(values[0], { index: lineCount - limit });
  assert.deepEqual(values.at(-1), { index: lineCount - 1 });
  assert.deepEqual(values[invalidIndex - (lineCount - limit)], {
    kind: "invalid-jsonl",
    summary: "A malformed local record was skipped."
  });
  assert.deepEqual(metadata, { byteTruncated: false, limitTruncated: true });
});

test("a zero JSONL limit reports truncation without retaining records", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-jsonl-zero-"));
  const file = path.join(root, "events.jsonl");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(file, `${JSON.stringify({ index: 0 })}\n{malformed\n`);

  const metadata = {};
  assert.deepEqual(await readJsonLines(file, { limit: 0, metadata }), []);
  assert.deepEqual(metadata, { byteTruncated: false, limitTruncated: true });
});

test("private JSONL append and read never follow a pre-positioned symlink", {
  skip: process.platform === "win32" && "creating symlinks can require elevated Windows privileges"
}, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-jsonl-link-"));
  const target = path.join(root, "outside.jsonl");
  const link = path.join(root, "events.jsonl");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(target, `${JSON.stringify({ outside: true })}\n`);
  fs.symlinkSync(target, link);

  assert.throws(() => appendJsonLine(link, { appended: true }), /must not be a symbolic link/);
  await assert.rejects(() => readJsonLines(link, { privateFile: true }), /must not be a symbolic link/);
  assert.equal(fs.readFileSync(target, "utf8"), `${JSON.stringify({ outside: true })}\n`);
});

test("private JSONL reads reject a dangling symlink instead of treating it as absent", {
  skip: process.platform === "win32" && "creating symlinks can require elevated Windows privileges"
}, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-jsonl-dangling-"));
  const link = path.join(root, "tokens.jsonl");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.symlinkSync(path.join(root, "missing.jsonl"), link);

  await assert.rejects(() => readJsonLines(link, { privateFile: true }), /must not be a symbolic link/);
});
