import fs from "node:fs";
import path from "node:path";
import { appendPrivateFile, openPrivateFile } from "./private-fs.mjs";

export function appendJsonLine(file, value, mode = 0o600, options = {}) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const line = `${JSON.stringify(value)}\n`;
  if (mode === 0o600) {
    appendPrivateFile(file, line, {
      encoding: "utf8",
      label: `private JSONL file ${file}`,
      sync: options.sync === true
    });
  }
  else fs.appendFileSync(file, line, { encoding: "utf8", mode });
}

export async function readJsonLines(file, {
  limit = 500,
  maxBytes = 2 * 1024 * 1024,
  metadata = null,
  privateFile = false
} = {}) {
  if (metadata && typeof metadata === "object") Object.assign(metadata, { byteTruncated: false, limitTruncated: false });
  if (!Number.isSafeInteger(limit) || limit < 0) throw new TypeError("JSONL limit must be a non-negative integer");
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new TypeError("JSONL maxBytes must be a positive integer");
  let privateDescriptor = null;
  if (privateFile) {
    try {
      privateDescriptor = openPrivateFile(file, { operation: "read", label: `private JSONL file ${file}` });
    } catch (error) {
      if (error.code === "ENOENT") return [];
      throw error;
    }
  } else if (!fs.existsSync(file)) {
    return [];
  }
  const stat = privateDescriptor === null ? await fs.promises.stat(file) : fs.fstatSync(privateDescriptor);
  const start = Math.max(0, stat.size - maxBytes);
  if (metadata && typeof metadata === "object") metadata.byteTruncated = start > 0;
  const handle = privateDescriptor === null ? await fs.promises.open(file, "r") : null;
  let text;
  try {
    const length = stat.size - start;
    const buffer = Buffer.allocUnsafe(length);
    const bytesRead = privateDescriptor === null
      ? (await handle.read(buffer, 0, length, start)).bytesRead
      : fs.readSync(privateDescriptor, buffer, 0, length, start);
    text = buffer.subarray(0, bytesRead).toString("utf8");
  } finally {
    if (privateDescriptor === null) await handle.close();
    else fs.closeSync(privateDescriptor);
  }
  if (start > 0) {
    const firstCompleteLine = text.indexOf("\n");
    text = firstCompleteLine === -1 ? "" : text.slice(firstCompleteLine + 1);
  }
  const retainedLines = [];
  let nextLine = 0;
  let parsedLines = 0;
  let lineStart = 0;
  while (lineStart <= text.length) {
    const newline = text.indexOf("\n", lineStart);
    const lineEnd = newline === -1 ? text.length : newline;
    const contentEnd = lineEnd > lineStart && text[lineEnd - 1] === "\r" ? lineEnd - 1 : lineEnd;
    const line = text.slice(lineStart, contentEnd);
    lineStart = newline === -1 ? text.length + 1 : newline + 1;
    if (!line.trim()) continue;
    parsedLines += 1;
    if (limit > 0) {
      if (retainedLines.length < limit) retainedLines.push(line);
      else {
        retainedLines[nextLine] = line;
        nextLine = (nextLine + 1) % limit;
      }
    }
  }
  const values = [];
  for (let index = 0; index < retainedLines.length; index += 1) {
    const line = retainedLines[(nextLine + index) % retainedLines.length];
    try {
      values.push(JSON.parse(line));
    } catch {
      values.push({ kind: "invalid-jsonl", summary: "A malformed local record was skipped." });
    }
  }
  if (metadata && typeof metadata === "object") metadata.limitTruncated = parsedLines > limit;
  return values;
}
