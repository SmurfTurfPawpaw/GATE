import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const SESSION_SOURCE = "codex-session-jsonl:host-session-roots";
const TOKEN_KEYS = ["inputTokens", "cachedInputTokens", "outputTokens", "reasoningTokens", "totalTokens"];
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

async function latestUsage(file, maximumBytes) {
  let latest = null;
  const handle = await fs.promises.open(file, "r");
  try {
    const stat = await handle.stat();
    const requestedBytes = Math.min(stat.size, maximumBytes);
    if (requestedBytes === 0) return { extracted: null, bytesRead: 0, truncated: stat.size > 0 };
    const start = Math.max(0, stat.size - requestedBytes);
    const buffer = Buffer.allocUnsafe(requestedBytes);
    const { bytesRead } = await handle.read(buffer, 0, requestedBytes, start);
    let text = buffer.subarray(0, bytesRead).toString("utf8");
    if (start > 0) {
      const firstCompleteLine = text.indexOf("\n");
      text = firstCompleteLine === -1 ? "" : text.slice(firstCompleteLine + 1);
    }
    for (const line of text.split(/\r?\n/u)) {
      if (
        !line.includes('"token_count"') &&
        !line.includes('"total_token_usage"') &&
        !line.includes('"token_usage"')
      ) continue;
      try {
        const extracted = extractTokenRecord(JSON.parse(line));
        if (extracted && (!latest || extracted.usage.total >= latest.usage.total)) latest = extracted;
      } catch {
        // Session logs can be concurrently appended. Ignore incomplete or unrelated lines.
      }
    }
    return { extracted: latest, bytesRead, truncated: start > 0 || bytesRead < stat.size };
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
    if (result.truncated) tailTruncatedFiles += 1;
    const extracted = result.extracted;
    if (!extracted) continue;
    const fingerprint = crypto.createHash("sha256").update(path.resolve(item.file)).digest("hex").slice(0, 20);
    const at = extracted.at || new Date(item.modified).toISOString();
    const record = {
      apiVersion: "gate.usage/v1",
      id: `use_${fingerprint}`,
      at,
      runId: `codex.${fingerprint}`,
      taskId: null,
      agent: "codex",
      provider: extracted.provider,
      model: extracted.model,
      availability: "exact",
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
      availability: "exact",
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
