import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const SESSION_SOURCE = "codex-session-jsonl:host-session-roots";
const TOKEN_KEYS = ["inputTokens", "cachedInputTokens", "outputTokens", "reasoningTokens", "totalTokens"];
const usageTailCache = new Map();
const MAX_USAGE_CACHE_ENTRIES = 1_000;
const MAX_CACHED_TRAILING_BYTES = 32 * 1024;
const MAX_USAGE_APPEND_WITNESS_BYTES = 4 * 1024;
const DEFAULT_LIMITS = Object.freeze({
  maximumFiles: 500,
  maximumDiscoveredFiles: 5_000,
  maximumDirectories: 2_000,
  maximumDepth: 8,
  maximumDurationMs: 750,
  maximumBytes: 8 * 1024 * 1024,
  maximumBytesPerFile: 256 * 1024
});

function limit(value, fallback) {
  const numeric = Number(value ?? fallback);
  return Number.isSafeInteger(numeric) && numeric >= 0 ? numeric : fallback;
}

function tokenNumber(object, ...names) {
  for (const name of names) {
    if (Number.isFinite(object?.[name]) && Number(object[name]) >= 0) return Number(object[name]);
  }
  return null;
}

function eventTimestamp(record) {
  const payload = record?.payload;
  for (const value of [record?.timestamp, record?.at, record?.created_at, payload?.timestamp, payload?.at]) {
    if (typeof value !== "string" && typeof value !== "number") continue;
    const parsed = new Date(value);
    if (!Number.isNaN(parsed.getTime())) return parsed.toISOString();
  }
  return null;
}

export function normalizeUsage(value) {
  if (!value || typeof value !== "object") return null;
  const input = tokenNumber(value, "input_tokens", "inputTokens", "prompt_tokens", "promptTokens");
  const cachedInput = tokenNumber(value, "cached_input_tokens", "cachedInputTokens", "cache_read_input_tokens");
  const output = tokenNumber(value, "output_tokens", "outputTokens", "completion_tokens", "completionTokens");
  const reasoning = tokenNumber(value, "reasoning_output_tokens", "reasoningTokens", "reasoning_tokens");
  const reportedTotal = tokenNumber(value, "total_tokens", "totalTokens");
  const total = reportedTotal ?? (input !== null && output !== null ? input + output : null);
  if ([input, cachedInput, output, reasoning, total].every((count) => count === null)) return null;
  return { input, cached_input: cachedInput, output, reasoning, total };
}

export function extractTokenRecord(record) {
  const payload = record?.payload || record;
  const info = payload?.info || record?.info;
  const candidates = [
    info?.total_token_usage,
    info?.totalTokenUsage,
    payload?.total_token_usage,
    payload?.token_usage,
    payload?.usage,
    record?.usage
  ];
  for (const candidate of candidates) {
    const usage = normalizeUsage(candidate);
    if (usage) {
      return {
        usage,
        context_window: tokenNumber(info, "model_context_window", "modelContextWindow") || null,
        provider: payload?.provider || record?.provider || "openai",
        model: payload?.model || info?.model || record?.model || null,
        at: eventTimestamp(record)
      };
    }
  }
  return null;
}

function statSignature(stat) {
  return {
    device: String(stat.dev),
    inode: String(stat.ino),
    size: stat.size,
    modified: stat.mtimeMs,
    changed: stat.ctimeMs
  };
}

function sameFileIdentity(left, right) {
  return left.device === right.device && left.inode === right.inode;
}

function sameFileVersion(left, right) {
  return sameFileIdentity(left, right) && left.size === right.size &&
    left.modified === right.modified && left.changed === right.changed;
}

function parseUsageText(text, initialLatest = null) {
  let latest = initialLatest;
  let cursor = 0;
  while (cursor <= text.length) {
    const newline = text.indexOf("\n", cursor);
    const end = newline === -1 ? text.length : newline;
    const line = text.slice(cursor, end).replace(/\r$/u, "");
    if (
      line.includes('"token_count"') ||
      line.includes('"total_token_usage"') ||
      line.includes('"token_usage"')
    ) {
      try {
        const extracted = extractTokenRecord(JSON.parse(line));
        // JSONL event order is the only sound ordering shared by usage records.
        // Individual counters can be absent, reset, or use incomparable units,
        // so always retain the latest parseable usage event in file order.
        if (extracted) latest = extracted;
      } catch {
        // Session logs can be concurrently appended. Retain the trailing bytes
        // so an append can complete the record without rereading the file.
      }
    }
    if (newline === -1) break;
    cursor = newline + 1;
  }
  const lastNewline = text.lastIndexOf("\n");
  return {
    extracted: latest,
    trailing: lastNewline === -1 ? text : text.slice(lastNewline + 1)
  };
}

function retainUsageCache(file, value) {
  usageTailCache.delete(file);
  usageTailCache.set(file, value);
  while (usageTailCache.size > MAX_USAGE_CACHE_ENTRIES) {
    usageTailCache.delete(usageTailCache.keys().next().value);
  }
}

async function readRange(handle, start, length) {
  const buffer = Buffer.allocUnsafe(length);
  let bytesRead = 0;
  while (bytesRead < length) {
    const result = await handle.read(buffer, bytesRead, length - bytesRead, start + bytesRead);
    if (result.bytesRead === 0) break;
    bytesRead += result.bytesRead;
  }
  const bytes = buffer.subarray(0, bytesRead);
  return { bytesRead, buffer: bytes, text: bytes.toString("utf8") };
}

function suffixWitness(buffer, endOffset) {
  const length = Math.min(buffer.length, MAX_USAGE_APPEND_WITNESS_BYTES);
  if (length < 1) return null;
  const bytes = buffer.subarray(buffer.length - length);
  return {
    start: endOffset - length,
    length,
    sha256: crypto.createHash("sha256").update(bytes).digest("hex")
  };
}

function validSuffixWitness(value, fileSize) {
  return value && Number.isSafeInteger(value.start) && value.start >= 0 &&
    Number.isSafeInteger(value.length) && value.length > 0 &&
    value.length <= MAX_USAGE_APPEND_WITNESS_BYTES && value.start + value.length === fileSize &&
    typeof value.sha256 === "string" && /^[a-f0-9]{64}$/u.test(value.sha256);
}

async function latestUsage(file, maximumBytes) {
  const resolved = path.resolve(file);
  const handle = await fs.promises.open(resolved, "r");
  try {
    const beforeStat = await handle.stat();
    if (!beforeStat.isFile()) throw new Error("Codex session source is not a regular file");
    const before = statSignature(beforeStat);
    const cached = usageTailCache.get(resolved);
    if (cached && cached.maximumBytes === maximumBytes && sameFileVersion(cached.signature, before)) {
      return {
        extracted: cached.extracted,
        bytesRead: 0,
        truncated: cached.truncated,
        cacheHit: true,
        incremental: false,
        changedDuringRead: false
      };
    }

    // A size increase alone cannot prove append-only behavior: the same inode
    // can be truncated, rewritten, and regrown between observations. A suffix
    // witness can prove the old EOF boundary, but it cannot prove that earlier
    // cached usage bytes survived. Never seed an incremental parse with cached
    // usage. Reuse the delta only when it contains a complete newer event;
    // otherwise reconstruct and rescan the complete current tail.
    const growth = cached ? before.size - cached.signature.size : 0;
    const appendCandidate = cached && cached.truncated === true && cached.appendSafe === true &&
      cached.maximumBytes === maximumBytes &&
      sameFileIdentity(cached.signature, before) && before.size > cached.signature.size &&
      validSuffixWitness(cached.witness, cached.signature.size) &&
      cached.witness.length + growth <= maximumBytes;
    let witnessRead = null;
    let growthRead = null;
    let bytesRead = 0;
    let incremental = false;
    let completeRead = false;
    let start = 0;
    let truncated = false;
    let parsed = null;
    let witnessedBytes = null;
    if (appendCandidate) {
      witnessRead = await readRange(handle, cached.witness.start, cached.witness.length);
      growthRead = await readRange(handle, cached.signature.size, growth);
      bytesRead = witnessRead.bytesRead + growthRead.bytesRead;
      const witnessMatches = witnessRead.bytesRead === cached.witness.length &&
        crypto.createHash("sha256").update(witnessRead.buffer).digest("hex") === cached.witness.sha256;
      const deltaAtLineBoundary = cached.trailing === "" &&
        witnessRead.buffer[witnessRead.buffer.length - 1] === 0x0a;
      if (witnessMatches && growthRead.bytesRead === growth && deltaAtLineBoundary) {
        const deltaParsed = parseUsageText(growthRead.text);
        // A usage event in the delta is later than every byte that may have
        // changed in the old window, so it is safe without cached state.
        if (deltaParsed.extracted) {
          incremental = true;
          completeRead = true;
          start = cached.signature.size;
          truncated = cached.truncated;
          parsed = deltaParsed;
          witnessedBytes = Buffer.concat([witnessRead.buffer, growthRead.buffer]);
        }
      }
    }

    if (appendCandidate && !incremental) {
      // The witness and growth are both part of the current tail. Read only
      // the missing prefix so the complete rescan remains within the byte cap.
      const requestedBytes = Math.min(before.size, maximumBytes);
      start = Math.max(0, before.size - requestedBytes);
      const prefixLength = cached.witness.start - start;
      const prefixRead = await readRange(handle, start, prefixLength);
      bytesRead += prefixRead.bytesRead;
      const currentTail = Buffer.concat([
        prefixRead.buffer,
        witnessRead.buffer,
        growthRead.buffer
      ]);
      completeRead = prefixRead.bytesRead === prefixLength &&
        witnessRead.bytesRead === cached.witness.length && growthRead.bytesRead === growth &&
        currentTail.length === requestedBytes;
      let text = currentTail.toString("utf8");
      truncated = start > 0 || !completeRead;
      if (start > 0) {
        const firstCompleteLine = text.indexOf("\n");
        text = firstCompleteLine === -1 ? "" : text.slice(firstCompleteLine + 1);
      }
      parsed = parseUsageText(text);
      witnessedBytes = currentTail;
    } else if (!appendCandidate) {
      const requestedBytes = Math.min(before.size, maximumBytes);
      start = Math.max(0, before.size - requestedBytes);
      if (requestedBytes > 0) {
        const read = await readRange(handle, start, requestedBytes);
        bytesRead = read.bytesRead;
        completeRead = read.bytesRead === requestedBytes;
        let text = read.text;
        truncated = start > 0 || !completeRead;
        if (start > 0) {
          const firstCompleteLine = text.indexOf("\n");
          text = firstCompleteLine === -1 ? "" : text.slice(firstCompleteLine + 1);
        }
        parsed = parseUsageText(text);
        witnessedBytes = read.buffer;
      }
    }

    if (!parsed) {
      const truncated = before.size > 0;
      const empty = {
        signature: before,
        maximumBytes,
        extracted: null,
        trailing: "",
        appendSafe: !truncated,
        truncated,
        witness: null
      };
      retainUsageCache(resolved, empty);
      return {
        extracted: null,
        bytesRead,
        truncated,
        cacheHit: false,
        incremental: false,
        changedDuringRead: false
      };
    }

    const afterStat = await handle.stat();
    const after = statSignature(afterStat);
    const changedDuringRead = !sameFileVersion(before, after);
    const cacheable = !changedDuringRead && completeRead;
    if (cacheable) {
      const appendSafe = Buffer.byteLength(parsed.trailing) <= MAX_CACHED_TRAILING_BYTES;
      retainUsageCache(resolved, {
        signature: after,
        maximumBytes,
        extracted: parsed.extracted,
        trailing: appendSafe ? parsed.trailing : "",
        appendSafe: appendSafe && witnessedBytes.length > 0,
        truncated,
        witness: suffixWitness(witnessedBytes, after.size)
      });
    } else {
      usageTailCache.delete(resolved);
    }
    return {
      extracted: parsed.extracted,
      bytesRead,
      truncated: truncated || changedDuringRead,
      cacheHit: false,
      incremental,
      changedDuringRead
    };
  } finally {
    await handle.close();
  }
}

function collectFiles(directory, output, state, depth = 0) {
  if (state.discoveryFileLimited) return;
  if (state.expired()) {
    state.timedOut = true;
    return;
  }
  const resolved = path.resolve(directory);
  if (state.visitedDirectories.has(resolved) || !fs.existsSync(resolved)) return;
  if (state.directoriesVisited >= state.limits.maximumDirectories) {
    state.directoryLimited = true;
    return;
  }
  state.visitedDirectories.add(resolved);
  state.directoriesVisited += 1;
  let handle;
  try {
    handle = fs.opendirSync(resolved);
  } catch {
    state.unreadableDirectories += 1;
    return;
  }
  try {
    let entry;
    while ((entry = handle.readSync()) !== null) {
      if (state.discoveryFileLimited) return;
      if (state.expired()) {
        state.timedOut = true;
        return;
      }
      const child = path.join(resolved, entry.name);
      if (entry.isDirectory()) {
        if (depth >= state.limits.maximumDepth) state.depthLimited = true;
        else collectFiles(child, output, state, depth + 1);
        continue;
      }
      if (!entry.isFile() || !entry.name.endsWith(".jsonl")) continue;
      if (output.size >= state.limits.maximumDiscoveredFiles) {
        state.discoveryFileLimited = true;
        return;
      }
      try {
        const stat = fs.statSync(child);
        output.set(path.resolve(child), { file: path.resolve(child), modified: stat.mtimeMs, size: stat.size });
      } catch {
        state.unreadableFiles += 1;
      }
    }
  } catch {
    state.unreadableDirectories += 1;
  } finally {
    handle.closeSync();
  }
}

export function defaultCodexSessionRoots(env = process.env) {
  const roots = [];
  if (env.CODEX_HOME) roots.push(path.join(env.CODEX_HOME, "sessions"));
  roots.push(path.join(os.homedir(), ".codex", "sessions"));
  return [...new Set(roots.map((root) => path.resolve(root)))];
}

export async function scanCodexUsage(options = {}) {
  const limits = {
    maximumFiles: limit(options.maximumFiles, DEFAULT_LIMITS.maximumFiles),
    maximumDiscoveredFiles: limit(options.maximumDiscoveredFiles, DEFAULT_LIMITS.maximumDiscoveredFiles),
    maximumDirectories: limit(options.maximumDirectories, DEFAULT_LIMITS.maximumDirectories),
    maximumDepth: limit(options.maximumDepth, DEFAULT_LIMITS.maximumDepth),
    maximumDurationMs: limit(options.maximumDurationMs, DEFAULT_LIMITS.maximumDurationMs),
    maximumBytes: limit(options.maximumBytes, DEFAULT_LIMITS.maximumBytes),
    maximumBytesPerFile: limit(options.maximumBytesPerFile, DEFAULT_LIMITS.maximumBytesPerFile)
  };
  const startedAt = Date.now();
  const deadline = startedAt + limits.maximumDurationMs;
  const discovered = new Map();
  const discovery = {
    limits,
    expired: () => Date.now() >= deadline,
    visitedDirectories: new Set(),
    directoriesVisited: 0,
    unreadableDirectories: 0,
    unreadableFiles: 0,
    directoryLimited: false,
    discoveryFileLimited: false,
    depthLimited: false,
    timedOut: false
  };
  for (const root of options.roots || defaultCodexSessionRoots(options.env)) {
    collectFiles(root, discovered, discovery);
    if (discovery.timedOut || discovery.discoveryFileLimited) break;
  }
  const files = [...discovered.values()];
  files.sort((a, b) => b.modified - a.modified || a.file.localeCompare(b.file));
  const selectedFiles = files.slice(0, limits.maximumFiles);
  const records = [];
  const sessions = [];
  let unreadableFiles = discovery.unreadableFiles;
  let scannedFiles = 0;
  let bytesRead = 0;
  let tailTruncatedFiles = 0;
  let cacheHits = 0;
  let incrementalFiles = 0;
  let filesRead = 0;
  let changedDuringReadFiles = 0;
  let byteLimited = false;
  let timedOut = discovery.timedOut;
  for (let index = 0; index < selectedFiles.length; index += 1) {
    if (Date.now() >= deadline) {
      timedOut = true;
      break;
    }
    const remainingBytes = limits.maximumBytes - bytesRead;
    if (remainingBytes <= 0) {
      byteLimited = true;
      break;
    }
    const item = selectedFiles[index];
    let result;
    scannedFiles += 1;
    try {
      result = await latestUsage(item.file, Math.min(limits.maximumBytesPerFile, remainingBytes));
    } catch {
      unreadableFiles += 1;
      continue;
    }
    bytesRead += result.bytesRead;
    if (result.cacheHit) cacheHits += 1;
    if (result.incremental) incrementalFiles += 1;
    if (result.bytesRead > 0) filesRead += 1;
    if (result.changedDuringRead) changedDuringReadFiles += 1;
    if (result.truncated) tailTruncatedFiles += 1;
    const extracted = result.extracted;
    if (!extracted) continue;
    const fingerprint = crypto.createHash("sha256").update(path.resolve(item.file)).digest("hex").slice(0, 20);
    const at = extracted.at || new Date(item.modified).toISOString();
    const recordAvailability = result.truncated ? "estimated" : "exact";
    const record = {
      apiVersion: "gate.usage/v1",
      id: `use_${fingerprint}`,
      at,
      runId: `codex.${fingerprint}`,
      taskId: null,
      agent: "codex",
      provider: extracted.provider,
      model: extracted.model,
      availability: recordAvailability,
      measure: "cumulative",
      inputTokens: extracted.usage.input,
      cachedInputTokens: extracted.usage.cached_input,
      outputTokens: extracted.usage.output,
      reasoningTokens: extracted.usage.reasoning,
      totalTokens: extracted.usage.total,
      source: SESSION_SOURCE
    };
    records.push(record);
    sessions.push({
      id: fingerprint,
      modifiedAt: at,
      provider: record.provider,
      model: record.model,
      source: SESSION_SOURCE,
      availability: recordAvailability,
      context_window: extracted.context_window,
      usage: extracted.usage
    });
  }
  const totals = Object.fromEntries(TOKEN_KEYS.map((key) => {
    const known = records.map((record) => record[key]).filter((value) => Number.isSafeInteger(value));
    return [key, known.length ? known.reduce((sum, value) => sum + value, 0) : null];
  }));
  const discoveryPartial = discovery.directoryLimited || discovery.discoveryFileLimited || discovery.depthLimited ||
    discovery.unreadableDirectories > 0 || discovery.unreadableFiles > 0 || discovery.timedOut;
  const truncated = selectedFiles.length < files.length || scannedFiles < selectedFiles.length || discoveryPartial;
  const partial = truncated || byteLimited || timedOut || tailTruncatedFiles > 0 || unreadableFiles > 0 ||
    records.length < scannedFiles;
  const availability = records.length ? (partial ? "estimated" : "exact") : "unavailable";
  return {
    availability,
    source: SESSION_SOURCE,
    scannedFiles,
    discoveredFiles: files.length,
    matchedFiles: records.length,
    unreadableFiles,
    unreadableDirectories: discovery.unreadableDirectories,
    directoriesVisited: discovery.directoriesVisited,
    bytesRead,
    filesRead,
    cacheHits,
    incrementalFiles,
    changedDuringReadFiles,
    tailTruncatedFiles,
    directoryLimited: discovery.directoryLimited,
    discoveryFileLimited: discovery.discoveryFileLimited,
    depthLimited: discovery.depthLimited,
    byteLimited,
    timedOut,
    truncated,
    partial,
    limits,
    sessions,
    records,
    totals: availability === "unavailable"
      ? Object.fromEntries(TOKEN_KEYS.map((key) => [key, null]))
      : totals
  };
}
