import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import { spawnSync } from "node:child_process";
import { readJson, writeJsonAtomic } from "./config.mjs";
import { recordEvent } from "./events.mjs";
import { ensureRuntime, runtimePaths } from "./paths.mjs";
import { readPrivateFileBounded, securePrivateDirectory, securePrivateFile } from "./private-fs.mjs";
import { assertValidDocument, validateDocument } from "./schema.mjs";
import { inspectReleaseArchive, readVerifiedReleaseExecutable } from "./upstreams.mjs";

const MAX_RECEIPT_BYTES = 64 * 1024;
const MAX_ARTIFACT_BYTES = 256 * 1024 * 1024;
const MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024;
const MUTATION_LOCK_OWNER_GRACE_MS = 60_000;
const RELEASE_REDIRECT_HOSTS = new Set([
  "github.com",
  "objects.githubusercontent.com",
  "release-assets.githubusercontent.com"
]);
const TOOL_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const PLATFORM_KEYS = new Set(["linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64"]);

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
}

export function canonicalSha256(value) {
  return crypto.createHash("sha256").update(JSON.stringify(canonicalValue(value))).digest("hex");
}

export function catalogEntrySha256(tool) {
  return canonicalSha256(tool);
}

function completeManagedRuntimePaths(options = {}) {
  if (!options.paths) return runtimePaths(options);
  const supplied = options.paths;
  if (typeof supplied.home !== "string") return supplied;
  const toolRuntimes = supplied.toolRuntimes || path.join(supplied.home, "tool-runtimes");
  const toolCache = supplied.toolCache || path.join(supplied.home, "tool-cache");
  return {
    ...supplied,
    toolRuntimes,
    toolRuntimeStaging: supplied.toolRuntimeStaging || path.join(toolRuntimes, ".staging"),
    toolCache,
    toolArtifactCache: supplied.toolArtifactCache || path.join(toolCache, "sha256")
  };
}

function normalizeRepository(value) {
  return String(value || "").replace(/\.git$/u, "").replace(/\/$/u, "");
}

export function currentRuntimePlatform(environment = process.env) {
  const wsl = process.platform === "linux" && (
    Boolean(environment.WSL_DISTRO_NAME) || os.release().toLowerCase().includes("microsoft")
  );
  const osName = process.platform === "darwin" ? "darwin" : process.platform === "linux" ? "linux" : null;
  const architecture = process.arch === "x64" ? "x64" : process.arch === "arm64" ? "arm64" : null;
  return {
    key: osName && architecture ? `${osName}-${architecture}` : null,
    host: wsl ? "wsl2" : osName === "darwin" ? "macos" : osName,
    os: osName,
    architecture,
    wsl
  };
}

function safeRelativePath(value) {
  if (typeof value !== "string" || !value || path.isAbsolute(value) || /^[A-Za-z]:[\\/]/u.test(value)) return false;
  if (value.includes("\\") || value.includes("\0")) return false;
  const parts = value.split("/");
  return parts.every((part) => part && part !== "." && part !== "..");
}

function validateEntrySemantics(entry, tool) {
  if (entry.id !== entry.toolId) throw new Error(`tool runtime id must equal toolId: ${entry.id}`);
  if (!tool) throw new Error(`tool runtime references unknown catalog entry: ${entry.toolId}`);
  if (entry.catalogEntrySha256 !== catalogEntrySha256(tool)) {
    throw new Error(`tool runtime catalog digest mismatch: ${entry.id}`);
  }
  if (normalizeRepository(entry.source.repository) !== normalizeRepository(tool.upstream)) {
    throw new Error(`tool runtime repository does not match the catalog: ${entry.id}`);
  }
  if (entry.executable.name !== tool.command) {
    throw new Error(`tool runtime executable does not match the catalog command: ${entry.id}`);
  }
  if (entry.executable.relativePath !== `bin/${entry.executable.name}`) {
    throw new Error(`tool runtime executable path is not canonical: ${entry.id}`);
  }
  if (entry.version.replace(/^v/u, "") !== entry.source.tag.replace(/^v/u, "")) {
    throw new Error(`tool runtime version and release tag differ: ${entry.id}`);
  }
  if (!/^[a-f0-9]{40}$/u.test(entry.source.commit) || /^(?:latest|main|master|head)$/iu.test(entry.source.tag)) {
    throw new Error(`tool runtime source is not immutable: ${entry.id}`);
  }
  if (entry.source.commit === "0".repeat(40)) throw new Error(`tool runtime source commit is empty: ${entry.id}`);
  const repositorySlug = normalizeRepository(entry.source.repository).replace("https://github.com/", "");
  if (
    entry.releaseEvidence.releaseApiUrl !== `https://api.github.com/repos/${repositorySlug}/releases/${entry.releaseEvidence.releaseId}` ||
    entry.releaseEvidence.checksumManifest.assetApiUrl !==
      `https://api.github.com/repos/${repositorySlug}/releases/assets/${entry.releaseEvidence.checksumManifest.assetId}`
  ) throw new Error(`tool runtime release evidence identity mismatch: ${entry.id}`);
  const checksumPrefix = `${normalizeRepository(entry.source.repository)}/releases/download/${encodeURIComponent(entry.source.tag)}/`;
  if (!entry.releaseEvidence.checksumManifest.url.startsWith(checksumPrefix)) {
    throw new Error(`tool runtime checksum evidence is not bound to its exact release: ${entry.id}`);
  }
  const platforms = new Set();
  for (const artifact of entry.artifacts) {
    if (!PLATFORM_KEYS.has(artifact.platform) || platforms.has(artifact.platform)) {
      throw new Error(`tool runtime has duplicate or unsupported platform: ${entry.id}`);
    }
    platforms.add(artifact.platform);
    const parsed = new URL(artifact.url);
    const expectedPrefix = `${normalizeRepository(entry.source.repository)}/releases/download/${encodeURIComponent(entry.source.tag)}/`;
    if (parsed.origin !== "https://github.com" || !artifact.url.startsWith(expectedPrefix) || parsed.search || parsed.hash) {
      throw new Error(`tool runtime artifact URL is not bound to its exact release: ${entry.id}`);
    }
    if (artifact.assetApiUrl !== `https://api.github.com/repos/${repositorySlug}/releases/assets/${artifact.assetId}`) {
      throw new Error(`tool runtime artifact identity mismatch: ${entry.id}/${artifact.platform}`);
    }
    const artifactName = path.basename(parsed.pathname).toLowerCase();
    if (
      (artifact.archiveType === "zip" && !artifactName.endsWith(".zip")) ||
      (artifact.archiveType === "tar.gz" && !artifactName.endsWith(".tar.gz"))
    ) throw new Error(`tool runtime archive type does not match its URL: ${entry.id}/${artifact.platform}`);
    if (!SHA256.test(artifact.sha256) || !SHA256.test(artifact.executableSha256)) {
      throw new Error(`tool runtime artifact is missing a SHA-256: ${entry.id}`);
    }
    if (!safeRelativePath(artifact.executablePath) || !artifact.entries.includes(artifact.executablePath)) {
      throw new Error(`tool runtime executable archive path is invalid: ${entry.id}/${artifact.platform}`);
    }
    if (path.basename(artifact.executablePath) !== entry.executable.name) {
      throw new Error(`tool runtime archive executable name mismatch: ${entry.id}/${artifact.platform}`);
    }
    const exact = new Set();
    const folded = new Set();
    for (const member of artifact.entries) {
      if (!safeRelativePath(member) || exact.has(member) || folded.has(member.toLowerCase())) {
        throw new Error(`tool runtime archive members are unsafe or ambiguous: ${entry.id}/${artifact.platform}`);
      }
      exact.add(member);
      folded.add(member.toLowerCase());
    }
  }
  if (!entry.smoke.argv.every((argument) => typeof argument === "string" && !/[\0\r\n]/u.test(argument))) {
    throw new Error(`tool runtime smoke argv is unsafe: ${entry.id}`);
  }
  return entry;
}

export function readToolRuntimeLock(options = {}) {
  const paths = completeManagedRuntimePaths(options);
  const lockFile = path.join(paths.repo, "locks", "tool-runtimes.lock.json");
  const catalogFile = path.join(paths.repo, "catalog", "security-tools.json");
  const lock = readJson(lockFile);
  const catalog = readJson(catalogFile);
  assertValidDocument(lock, "tool-runtime-lock.schema.json", { paths });
  const byTool = new Map(catalog.tools.map((tool) => [tool.id, tool]));
  const ids = new Set();
  for (const entry of lock.runtimes) {
    if (ids.has(entry.id)) throw new Error(`duplicate tool runtime id: ${entry.id}`);
    ids.add(entry.id);
    validateEntrySemantics(entry, byTool.get(entry.toolId));
  }
  return { paths, lock, catalog, lockFile, catalogFile };
}

function entryFor(id, options = {}) {
  if (!TOOL_ID.test(String(id || ""))) throw new Error(`invalid tool id: ${id}`);
  const loaded = readToolRuntimeLock(options);
  const tool = loaded.catalog.tools.find((candidate) => candidate.id === id);
  if (!tool) throw new Error(`unknown security tool: ${id}`);
  const entry = loaded.lock.runtimes.find((candidate) => candidate.toolId === id) || null;
  return { ...loaded, entry, tool };
}

function artifactFor(entry, platform) {
  return entry?.artifacts.find((candidate) => candidate.platform === platform.key) || null;
}

function containedChild(root, name) {
  if (!TOOL_ID.test(name)) throw new Error(`unsafe managed tool path: ${name}`);
  const resolvedRoot = path.resolve(root);
  const child = path.resolve(resolvedRoot, name);
  if (!child.startsWith(`${resolvedRoot}${path.sep}`)) throw new Error(`managed tool path escapes its root: ${name}`);
  return child;
}

function digestBuffer(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function readBoundedRegularFile(file, maximumBytes, label, options = {}) {
  const before = fs.lstatSync(file, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) throw new Error(`${label} is not a single-link regular file`);
  if (before.size < 1n || before.size > BigInt(maximumBytes)) throw new Error(`${label} exceeds its byte limit`);
  if (process.platform !== "win32" && typeof process.geteuid === "function" && before.uid !== BigInt(process.geteuid())) {
    throw new Error(`${label} is not owned by the current user`);
  }
  if (process.platform !== "win32" && options.mode !== undefined && (before.mode & 0o7777n) !== BigInt(options.mode)) {
    throw new Error(`${label} permissions differ from the reviewed mode ${options.mode.toString(8)}`);
  }
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino) throw new Error(`${label} changed while opened`);
    if (process.platform !== "win32" && options.mode !== undefined && (opened.mode & 0o7777n) !== BigInt(options.mode)) {
      throw new Error(`${label} permissions changed while opened`);
    }
    const bytes = Buffer.alloc(Number(opened.size));
    let offset = 0;
    while (offset < bytes.length) {
      const read = fs.readSync(descriptor, bytes, offset, bytes.length - offset, null);
      if (read === 0) throw new Error(`${label} changed while read`);
      offset += read;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    const named = fs.lstatSync(file, { bigint: true });
    if (after.dev !== opened.dev || after.ino !== opened.ino || named.dev !== opened.dev || named.ino !== opened.ino) {
      throw new Error(`${label} changed while read`);
    }
    return bytes;
  } finally {
    fs.closeSync(descriptor);
  }
}

function verifyArtifactFile(file, artifact) {
  const bytes = readBoundedRegularFile(file, MAX_ARTIFACT_BYTES, "managed tool artifact", { mode: 0o600 });
  if (bytes.length !== artifact.size) throw new Error(`artifact size mismatch for ${artifact.platform}`);
  if (digestBuffer(bytes) !== artifact.sha256) throw new Error(`artifact SHA-256 mismatch for ${artifact.platform}`);
  return bytes;
}

function zipEndRecord(bytes) {
  const minimum = 22;
  const earliest = Math.max(0, bytes.length - minimum - 0xffff);
  for (let offset = bytes.length - minimum; offset >= earliest; offset -= 1) {
    if (bytes.readUInt32LE(offset) !== 0x06054b50) continue;
    const commentLength = bytes.readUInt16LE(offset + 20);
    if (offset + minimum + commentLength === bytes.length) return offset;
  }
  throw new Error("ZIP end-of-central-directory record is missing or ambiguous");
}

function zipName(bytes, utf8) {
  if (!bytes.length || bytes.includes(0)) throw new Error("ZIP entry name is empty or contains NUL");
  if (!utf8 && bytes.some((value) => value < 0x20 || value > 0x7e)) {
    throw new Error("ZIP entry name is not reviewed ASCII or UTF-8");
  }
  const value = bytes.toString(utf8 ? "utf8" : "ascii");
  if (utf8 && !Buffer.from(value, "utf8").equals(bytes)) throw new Error("ZIP entry name is invalid UTF-8");
  return value;
}

function parseReviewedZip(bytes) {
  const end = zipEndRecord(bytes);
  const disk = bytes.readUInt16LE(end + 4);
  const centralDisk = bytes.readUInt16LE(end + 6);
  const diskEntries = bytes.readUInt16LE(end + 8);
  const entryCount = bytes.readUInt16LE(end + 10);
  const centralSize = bytes.readUInt32LE(end + 12);
  const centralOffset = bytes.readUInt32LE(end + 16);
  if (
    disk !== 0 || centralDisk !== 0 || diskEntries !== entryCount || entryCount < 1 || entryCount > 64 ||
    entryCount === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff ||
    centralOffset + centralSize !== end
  ) throw new Error("ZIP archive is split, ZIP64, oversized, or structurally ambiguous");

  const entries = [];
  const localOffsets = new Set();
  let totalUncompressed = 0;
  let cursor = centralOffset;
  for (let index = 0; index < entryCount; index += 1) {
    if (cursor + 46 > end || bytes.readUInt32LE(cursor) !== 0x02014b50) {
      throw new Error("ZIP central directory is malformed");
    }
    const versionMadeBy = bytes.readUInt16LE(cursor + 4);
    const flags = bytes.readUInt16LE(cursor + 8);
    const method = bytes.readUInt16LE(cursor + 10);
    const compressedSize = bytes.readUInt32LE(cursor + 20);
    const uncompressedSize = bytes.readUInt32LE(cursor + 24);
    const nameLength = bytes.readUInt16LE(cursor + 28);
    const extraLength = bytes.readUInt16LE(cursor + 30);
    const commentLength = bytes.readUInt16LE(cursor + 32);
    const startDisk = bytes.readUInt16LE(cursor + 34);
    const externalAttributes = bytes.readUInt32LE(cursor + 38);
    const localOffset = bytes.readUInt32LE(cursor + 42);
    const next = cursor + 46 + nameLength + extraLength + commentLength;
    if (
      next > end || startDisk !== 0 || compressedSize === 0xffffffff || uncompressedSize === 0xffffffff ||
      localOffset === 0xffffffff || (flags & 0x41) !== 0 || !new Set([0, 8]).has(method) ||
      uncompressedSize > MAX_EXECUTABLE_BYTES
    ) throw new Error("ZIP entry uses unsupported size, encryption, disk, or compression metadata");
    const nameBytes = bytes.subarray(cursor + 46, cursor + 46 + nameLength);
    const name = zipName(nameBytes, Boolean(flags & 0x800));
    const creator = versionMadeBy >>> 8;
    const unixMode = externalAttributes >>> 16;
    const fileType = unixMode & 0o170000;
    if (creator === 3 && fileType !== 0 && fileType !== 0o100000 && fileType !== 0o040000) {
      throw new Error(`ZIP archive contains a link or special entry: ${name}`);
    }
    const directory = name.endsWith("/") || fileType === 0o040000 || Boolean(externalAttributes & 0x10);
    if (directory) throw new Error(`ZIP archive contains an unreviewed directory entry: ${name}`);
    if (localOffsets.has(localOffset) || localOffset + 30 > centralOffset || bytes.readUInt32LE(localOffset) !== 0x04034b50) {
      throw new Error("ZIP local entry identity is duplicated or malformed");
    }
    localOffsets.add(localOffset);
    const localFlags = bytes.readUInt16LE(localOffset + 6);
    const localMethod = bytes.readUInt16LE(localOffset + 8);
    const localNameLength = bytes.readUInt16LE(localOffset + 26);
    const localExtraLength = bytes.readUInt16LE(localOffset + 28);
    const localNameStart = localOffset + 30;
    const dataStart = localNameStart + localNameLength + localExtraLength;
    const dataEnd = dataStart + compressedSize;
    if (
      localFlags !== flags || localMethod !== method || dataEnd > centralOffset ||
      !bytes.subarray(localNameStart, localNameStart + localNameLength).equals(nameBytes)
    ) throw new Error(`ZIP local entry differs from its central directory: ${name}`);
    totalUncompressed += uncompressedSize;
    if (!Number.isSafeInteger(totalUncompressed) || totalUncompressed > MAX_ARTIFACT_BYTES * 2) {
      throw new Error("ZIP archive exceeds its reviewed expanded-size ceiling");
    }
    entries.push({ name, method, compressedSize, uncompressedSize, dataStart, dataEnd });
    cursor = next;
  }
  if (cursor !== end) throw new Error("ZIP central directory has trailing unreviewed records");
  return entries;
}

function readReviewedZipExecutable(archive, artifact) {
  const bytes = readBoundedRegularFile(archive, MAX_ARTIFACT_BYTES, "managed tool artifact", { mode: 0o600 });
  const entries = parseReviewedZip(bytes);
  const selected = entries.filter((entry) => entry.name === artifact.executablePath);
  if (selected.length !== 1) throw new Error("ZIP archive does not contain the exact reviewed executable path");
  const entry = selected[0];
  const compressed = bytes.subarray(entry.dataStart, entry.dataEnd);
  const executable = entry.method === 0
    ? Buffer.from(compressed)
    : zlib.inflateRawSync(compressed, { maxOutputLength: Math.min(MAX_EXECUTABLE_BYTES, entry.uncompressedSize + 1) });
  if (executable.length !== entry.uncompressedSize || digestBuffer(executable) !== artifact.executableSha256) {
    throw new Error("ZIP executable bytes differ from the reviewed lock");
  }
  return { executable, entries: entries.map((entry) => entry.name) };
}

function cacheFile(paths, artifact) {
  return path.join(paths.toolArtifactCache, artifact.sha256);
}

async function responseForReviewedUrl(initialUrl, options = {}) {
  const fetcher = options.fetch || globalThis.fetch;
  if (typeof fetcher !== "function") throw new Error("HTTPS download support is unavailable");
  let current = new URL(initialUrl);
  for (let redirects = 0; redirects <= 5; redirects += 1) {
    if (
      current.protocol !== "https:" || !RELEASE_REDIRECT_HOSTS.has(current.hostname) ||
      current.username || current.password || (current.port && current.port !== "443")
    ) {
      throw new Error(`artifact download host is not reviewed: ${current.hostname}`);
    }
    const response = await fetcher(current, {
      method: "GET",
      redirect: "manual",
      headers: { "user-agent": "GATE-managed-tool-runtime/1" },
      signal: AbortSignal.timeout(options.timeoutMs || 120_000)
    });
    if (new Set([301, 302, 303, 307, 308]).has(response.status)) {
      const location = response.headers.get("location");
      if (!location || redirects === 5) throw new Error("artifact download exceeded its redirect limit");
      current = new URL(location, current);
      continue;
    }
    if (!response.ok || !response.body) throw new Error(`artifact download failed with HTTP ${response.status}`);
    return response;
  }
  throw new Error("artifact download exceeded its redirect limit");
}

function proxyEnvironment() {
  const environment = {
    HOME: "/nonexistent",
    PATH: "/usr/bin:/bin",
    LANG: "C",
    LC_ALL: "C"
  };
  for (const name of [
    "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE"
  ]) {
    if (process.env[name]) environment[name] = process.env[name];
  }
  return environment;
}

function downloadReviewedArtifactWithCurl(artifact, destination, options = {}) {
  const curl = trustedSystemExecutable(["/usr/bin/curl", "/bin/curl"], "curl");
  fs.writeFileSync(destination, Buffer.alloc(0), { flag: "wx", mode: 0o600 });
  let current = new URL(artifact.url);
  for (let redirects = 0; redirects <= 5; redirects += 1) {
    if (
      current.protocol !== "https:" || !RELEASE_REDIRECT_HOSTS.has(current.hostname) ||
      current.username || current.password || (current.port && current.port !== "443")
    ) {
      throw new Error(`artifact download host is not reviewed: ${current.hostname}`);
    }
    const header = `${destination}.headers`;
    try {
      const result = spawnSync(curl, [
        "--disable",
        "--silent",
        "--show-error",
        "--proto", "=https",
        "--max-redirs", "0",
        "--connect-timeout", "15",
        "--max-time", String(Math.ceil((options.timeoutMs || 120_000) / 1000)),
        "--max-filesize", String(artifact.size),
        "--dump-header", header,
        "--output", destination,
        "--write-out", "%{http_code}",
        current.href
      ], {
        shell: false,
        windowsHide: true,
        encoding: "utf8",
        timeout: options.timeoutMs || 120_000,
        maxBuffer: 64 * 1024,
        env: proxyEnvironment()
      });
      if (result.error || result.status !== 0) {
        throw new Error(`artifact download failed: ${(result.stderr || result.error?.message || `curl exited ${result.status}`).trim()}`);
      }
      const status = Number(String(result.stdout || "").trim());
      const headers = readBoundedRegularFile(header, 64 * 1024, "artifact response headers").toString("latin1");
      if (status >= 300 && status < 400) {
        const location = headers.match(/^location:\s*([^\r\n]+)$/imu)?.[1]?.trim();
        if (!location || redirects === 5) throw new Error("artifact download exceeded its redirect limit");
        current = new URL(location, current);
        continue;
      }
      if (status !== 200) throw new Error(`artifact download failed with HTTP ${status}`);
      return;
    } finally {
      fs.rmSync(header, { force: true });
    }
  }
  throw new Error("artifact download exceeded its redirect limit");
}

async function downloadReviewedArtifact(artifact, destination, options = {}) {
  if (!options.fetch && (process.env.HTTPS_PROXY || process.env.https_proxy)) {
    downloadReviewedArtifactWithCurl(artifact, destination, options);
    return;
  }
  const response = await responseForReviewedUrl(artifact.url, options);
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && Number(contentLength) !== artifact.size) {
    throw new Error(`artifact Content-Length mismatch for ${artifact.platform}`);
  }
  const descriptor = fs.openSync(destination, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
  let total = 0;
  try {
    for await (const chunk of response.body) {
      const bytes = Buffer.from(chunk);
      total += bytes.length;
      if (total > artifact.size || total > MAX_ARTIFACT_BYTES) throw new Error("artifact exceeded its reviewed byte size");
      fs.writeSync(descriptor, bytes);
    }
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  if (total !== artifact.size) throw new Error(`artifact download size mismatch for ${artifact.platform}`);
}

export async function prefetchManagedTool(id, options = {}) {
  const { paths, entry, tool } = entryFor(id, options);
  if (!entry) return unresolvedResult("prefetch", tool, ["reviewed-runtime-lock-unavailable"]);
  const platform = options.platform || currentRuntimePlatform(options.environment);
  const artifact = artifactFor(entry, platform);
  if (!platform.key || !artifact) return unresolvedResult("prefetch", tool, ["reviewed-platform-artifact-unavailable"], entry, platform);
  ensureRuntime(paths);
  const destination = cacheFile(paths, artifact);
  if (fs.existsSync(destination)) {
    verifyArtifactFile(destination, artifact);
    return baseResult("prefetch", tool, entry, platform, { ok: true, state: "cached", cache: destination });
  }
  const temporary = path.join(paths.toolArtifactCache, `.${artifact.sha256}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`);
  try {
    const downloader = options.downloadArtifact || downloadReviewedArtifact;
    await downloader(artifact, temporary, { ...options, paths, entry, tool });
    fs.chmodSync(temporary, 0o600);
    verifyArtifactFile(temporary, artifact);
    try {
      fs.renameSync(temporary, destination);
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      verifyArtifactFile(destination, artifact);
    }
    securePrivateFile(destination, { allowMissing: false, label: `managed tool artifact ${artifact.sha256}` });
    return baseResult("prefetch", tool, entry, platform, { ok: true, state: "cached", cache: destination });
  } finally {
    fs.rmSync(temporary, { force: true });
  }
}

function assertExactArchive(archive, artifact) {
  const bytes = readBoundedRegularFile(archive, MAX_ARTIFACT_BYTES, "managed tool artifact", { mode: 0o600 });
  const isGzip = bytes[0] === 0x1f && bytes[1] === 0x8b;
  const isZip = bytes[0] === 0x50 && bytes[1] === 0x4b && new Set([0x03, 0x05, 0x07]).has(bytes[2]);
  if (
    (artifact.archiveType === "tar.gz" && !isGzip) ||
    (artifact.archiveType === "zip" && !isZip)
  ) throw new Error(`release archive bytes do not match the reviewed type: ${artifact.platform}`);
  const observed = artifact.archiveType === "zip"
    ? parseReviewedZip(bytes).map((entry) => entry.name)
    : inspectReleaseArchive(archive);
  const observedSet = new Set();
  const folded = new Set();
  for (const member of observed) {
    if (!safeRelativePath(member) || observedSet.has(member) || folded.has(member.toLowerCase())) {
      throw new Error(`release archive has duplicate, case-colliding, or unsafe members: ${artifact.platform}`);
    }
    observedSet.add(member);
    folded.add(member.toLowerCase());
  }
  const expected = [...artifact.entries].sort();
  const actual = [...observedSet].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`release archive entries differ from the reviewed lock: ${artifact.platform}`);
  }
}

function trustedSystemExecutable(candidates, label) {
  for (const candidate of candidates) {
    try {
      const resolved = fs.realpathSync(candidate);
      if (resolved !== candidate) continue;
      const stat = fs.lstatSync(candidate);
      if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o022) !== 0) continue;
      if (typeof process.geteuid === "function" && stat.uid === process.geteuid()) continue;
      try {
        fs.accessSync(candidate, fs.constants.W_OK);
        continue;
      } catch (error) {
        if (!new Set(["EACCES", "EPERM", "EROFS"]).has(error.code)) throw error;
      }
      let current = path.dirname(candidate);
      let protectedPath = true;
      while (true) {
        const parentStat = fs.statSync(current);
        if (
          (parentStat.mode & 0o022) !== 0 ||
          (typeof process.geteuid === "function" && parentStat.uid === process.geteuid())
        ) { protectedPath = false; break; }
        try {
          fs.accessSync(current, fs.constants.W_OK);
          protectedPath = false;
          break;
        } catch (error) {
          if (!new Set(["EACCES", "EPERM", "EROFS"]).has(error.code)) throw error;
        }
        const parent = path.dirname(current);
        if (parent === current) break;
        current = parent;
      }
      if (protectedPath) return candidate;
    } catch {
      // Try the next fixed system path.
    }
  }
  throw new Error(`${label} is unavailable from a protected system path`);
}

function defaultSmokeRunner(executable, spec, options = {}) {
  const platform = options.platform || currentRuntimePlatform(options.environment);
  if (platform.os !== "linux") {
    throw new Error(`zero-egress smoke sandbox is unavailable for ${platform.key || process.platform}`);
  }
  const bwrap = trustedSystemExecutable(["/usr/bin/bwrap", "/bin/bwrap"], "Bubblewrap");
  const prlimit = trustedSystemExecutable(["/usr/bin/prlimit", "/bin/prlimit"], "prlimit");
  const args = [
    "--die-with-parent",
    "--new-session",
    "--unshare-all",
    "--cap-drop", "ALL",
    "--clearenv",
    "--ro-bind", "/usr", "/usr",
    ...["/lib", "/lib64"].filter((directory) => fs.existsSync(directory)).flatMap((directory) => ["--ro-bind", directory, directory]),
    "--ro-bind", executable, "/tool",
    "--proc", "/proc",
    "--dev", "/dev",
    "--tmpfs", "/tmp",
    "--tmpfs", "/run",
    "--tmpfs", "/home",
    "--setenv", "HOME", "/home",
    "--setenv", "TMPDIR", "/tmp",
    "--setenv", "PATH", "/nonexistent",
    "--setenv", "LANG", "C.UTF-8",
    "--setenv", "LC_ALL", "C.UTF-8",
    "--setenv", "NO_COLOR", "1",
    "--",
    prlimit,
    `--nproc=${spec.maxProcesses}`,
    "--",
    "/tool",
    ...spec.argv
  ];
  const result = spawnSync(bwrap, args, {
    shell: false,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
    encoding: "buffer",
    timeout: spec.timeoutMs,
    maxBuffer: spec.maxOutputBytes,
    killSignal: "SIGKILL",
    env: {
      PATH: "/usr/bin:/bin",
      LANG: "C.UTF-8",
      LC_ALL: "C.UTF-8",
      NO_COLOR: "1"
    }
  });
  if (result.error) throw new Error(`managed tool smoke failed: ${result.error.code || result.error.message}`);
  const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.from(result.stdout || "");
  const stderr = Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.from(result.stderr || "");
  if (stdout.length + stderr.length > spec.maxOutputBytes) throw new Error("managed tool smoke exceeded its output limit");
  const combined = Buffer.concat([stdout, stderr]);
  if (result.status !== 0) throw new Error(`managed tool smoke exited ${result.status}`);
  if (!combined.toString("utf8").toLowerCase().includes(spec.expectedOutputContains.toLowerCase())) {
    throw new Error("managed tool smoke output did not match the reviewed expectation");
  }
  return { exitCode: 0, output: combined };
}

function runReviewedSmoke(executable, entry, platform, options = {}) {
  const runner = options.runSmoke || defaultSmokeRunner;
  const observed = runner(executable, entry.smoke, { ...options, entry, platform });
  if (observed && typeof observed.then === "function") throw new Error("managed tool smoke runner must be synchronous");
  const output = Buffer.isBuffer(observed?.output) ? observed.output : Buffer.from(observed?.output || "");
  if (observed?.exitCode !== 0 || output.length > entry.smoke.maxOutputBytes) {
    throw new Error("managed tool smoke result violated its reviewed bounds");
  }
  if (!output.toString("utf8").toLowerCase().includes(entry.smoke.expectedOutputContains.toLowerCase())) {
    throw new Error("managed tool smoke output did not match the reviewed expectation");
  }
  return {
    specSha256: canonicalSha256(entry.smoke),
    status: "passed",
    network: "none",
    sandbox: entry.smoke.sandbox,
    exitCode: 0,
    outputSha256: digestBuffer(output),
    completedAt: new Date().toISOString()
  };
}

function promoteDirectory(staging, destination, validatePublished = () => {}) {
  const backup = `${destination}.previous-${process.pid}-${crypto.randomBytes(4).toString("hex")}`;
  let movedExisting = false;
  let published = false;
  try {
    if (fs.existsSync(destination)) {
      fs.renameSync(destination, backup);
      movedExisting = true;
    }
    fs.renameSync(staging, destination);
    published = true;
    validatePublished();
  } catch (error) {
    if (published && fs.existsSync(destination)) fs.rmSync(destination, { recursive: true, force: true });
    if (movedExisting && fs.existsSync(backup)) fs.renameSync(backup, destination);
    throw error;
  }
  if (!movedExisting) return { cleanupPending: null };
  try {
    fs.rmSync(backup, { recursive: true, force: true });
    return { cleanupPending: null };
  } catch {
    // Validation is the commit point. Never replace a fully verified new
    // runtime with a backup whose recursive deletion may already be partial.
    return { cleanupPending: backup };
  }
}

function procStartTimeFor(pid) {
  const text = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
  const close = text.lastIndexOf(")");
  if (close === -1) throw new Error("process stat is malformed");
  const fields = text.slice(close + 2).trim().split(/\s+/u);
  if (!/^\d+$/u.test(fields[19] || "")) throw new Error("process start identity is unavailable");
  return fields[19];
}

function mutationProcessIdentity(pid = process.pid) {
  if (process.platform !== "linux") return null;
  const bootId = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim().toLowerCase();
  if (!/^[a-f0-9-]{36}$/u.test(bootId)) throw new Error("host boot identity is unavailable");
  return { pid, bootId, startTimeTicks: procStartTimeFor(pid) };
}

function mutationOwnerIsLive(owner) {
  if (
    process.platform !== "linux" || !Number.isSafeInteger(owner?.pid) || owner.pid < 1 ||
    !/^[a-f0-9-]{36}$/u.test(owner.bootId || "") || !/^\d+$/u.test(owner.startTimeTicks || "")
  ) return null;
  let currentBoot;
  try {
    currentBoot = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim().toLowerCase();
  } catch {
    return null;
  }
  if (currentBoot !== owner.bootId) return false;
  try {
    return procStartTimeFor(owner.pid) === owner.startTimeTicks;
  } catch (error) {
    if (error.code === "ENOENT" || error.code === "ESRCH") return false;
    return null;
  }
}

function reclaimableMutationLock(lock) {
  const stat = fs.lstatSync(lock);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("managed tool mutation lock is not a private directory");
  if (process.platform !== "win32") {
    if (typeof process.geteuid === "function" && stat.uid !== process.geteuid()) {
      throw new Error("managed tool mutation lock is not owned by the current user");
    }
    if ((stat.mode & 0o7777) !== 0o700) throw new Error("managed tool mutation lock permissions are not owner-only");
  }
  try {
    const owner = JSON.parse(readPrivateFileBounded(path.join(lock, "owner.json"), 16 * 1024, "utf8", {
      label: "managed tool mutation owner"
    }));
    if (
      owner.apiVersion !== "gate.tool-mutation/v1" || !/^[a-f0-9]{32}$/u.test(owner.token || "") ||
      !Number.isFinite(Date.parse(owner.createdAt || ""))
    ) return false;
    return mutationOwnerIsLive(owner) === false;
  } catch (error) {
    if (error.code !== "ENOENT") return false;
    return Date.now() - stat.mtimeMs >= MUTATION_LOCK_OWNER_GRACE_MS;
  }
}

function acquireMutationLock(paths, id) {
  const lock = path.join(paths.toolRuntimeStaging, `.${id}.mutation-lock`);
  let owner;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    let created = false;
    try {
      fs.mkdirSync(lock, { mode: 0o700 });
      created = true;
      const identity = mutationProcessIdentity();
      owner = {
        apiVersion: "gate.tool-mutation/v1",
        token: crypto.randomBytes(16).toString("hex"),
        pid: identity?.pid || process.pid,
        bootId: identity?.bootId || "unavailable",
        startTimeTicks: identity?.startTimeTicks || "unavailable",
        createdAt: new Date().toISOString()
      };
      writeJsonAtomic(path.join(lock, "owner.json"), owner, 0o600);
      break;
    } catch (error) {
      if (created) {
        owner = null;
        fs.rmSync(lock, { recursive: true, force: true });
        throw error;
      }
      if (error.code !== "EEXIST") throw error;
      if (!reclaimableMutationLock(lock)) {
        throw new Error(`managed tool mutation is already active or indeterminate: ${id}`);
      }
      const stale = `${lock}.stale-${process.pid}-${crypto.randomBytes(4).toString("hex")}`;
      try {
        fs.renameSync(lock, stale);
      } catch (renameError) {
        if (renameError.code === "ENOENT") continue;
        throw renameError;
      }
      fs.rmSync(stale, { recursive: true, force: true });
    }
  }
  if (!owner) throw new Error(`managed tool mutation lock could not be acquired: ${id}`);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    const current = JSON.parse(readPrivateFileBounded(path.join(lock, "owner.json"), 16 * 1024, "utf8", {
      label: "managed tool mutation owner"
    }));
    if (current.token !== owner.token) throw new Error(`managed tool mutation ownership changed: ${id}`);
    fs.unlinkSync(path.join(lock, "owner.json"));
    fs.rmdirSync(lock);
  };
}

function receiptFor(entry, artifact, platform, executable, smoke) {
  const stat = fs.statSync(executable);
  return {
    apiVersion: "gate.tool-install/v1",
    id: entry.id,
    toolId: entry.toolId,
    provider: entry.provider,
    version: entry.version,
    platform: platform.key,
    lockEntrySha256: canonicalSha256(entry),
    catalogEntrySha256: entry.catalogEntrySha256,
    artifact: { assetId: artifact.assetId, url: artifact.url, size: artifact.size, sha256: artifact.sha256 },
    executable: {
      relativePath: entry.executable.relativePath,
      sha256: artifact.executableSha256,
      size: stat.size
    },
    smoke,
    installedAt: new Date().toISOString(),
    authority: "none-installation-does-not-authorize-target-contact"
  };
}

export async function installManagedTool(id, options = {}) {
  const selected = entryFor(id, options);
  const { paths, entry, tool } = selected;
  if (!entry) return unresolvedResult("install", tool, ["reviewed-runtime-lock-unavailable"]);
  const platform = options.platform || currentRuntimePlatform(options.environment);
  const artifact = artifactFor(entry, platform);
  if (!platform.key || !artifact) return unresolvedResult("install", tool, ["reviewed-platform-artifact-unavailable"], entry, platform);
  if (platform.os !== "linux") {
    return unresolvedResult("install", tool, ["zero-egress-smoke-sandbox-unavailable"], entry, platform);
  }
  ensureRuntime(paths);
  const releaseMutation = acquireMutationLock(paths, entry.id);
  try {
    const cached = await prefetchManagedTool(id, { ...options, paths, platform });
    if (!cached.ok) return cached;
    const archive = cacheFile(paths, artifact);
    verifyArtifactFile(archive, artifact);
    assertExactArchive(archive, artifact);
    const extracted = artifact.archiveType === "zip"
      ? readReviewedZipExecutable(archive, artifact)
      : readVerifiedReleaseExecutable(
          archive,
          {
            name: path.basename(new URL(artifact.url).pathname),
            sha256: artifact.sha256,
            executableSha256: artifact.executableSha256
          },
          entry.executable.name
        );
    const destination = containedChild(paths.toolRuntimes, entry.id);
    const staging = fs.mkdtempSync(path.join(paths.toolRuntimeStaging, `${entry.id}-`));
    try {
      securePrivateDirectory(staging, { create: false, label: `managed tool staging ${entry.id}` });
      const bin = path.join(staging, "bin");
      fs.mkdirSync(bin, { mode: 0o700 });
      const executable = path.join(staging, entry.executable.relativePath);
      fs.writeFileSync(executable, extracted.executable, { flag: "wx", mode: 0o700 });
      const smoke = runReviewedSmoke(executable, entry, platform, options);
      const receipt = receiptFor(entry, artifact, platform, executable, smoke);
      assertValidDocument(receipt, "tool-install-receipt.schema.json", { paths });
      writeJsonAtomic(path.join(staging, "install.json"), receipt, 0o600);
      if (typeof options.beforePublish === "function") options.beforePublish({ staging, destination, receipt });
      let verified;
      const publication = promoteDirectory(staging, destination, () => {
        verified = verifyManagedTool(id, { ...options, paths, platform });
        if (!verified.ok) throw new Error(`published managed tool failed verification: ${verified.reasons.join(", ")}`);
      });
      recordEvent({
        kind: "tool-runtime.installed",
        summary: `Installed ${entry.id} ${entry.version} from reviewed release bytes.`,
        effect: { class: "host-write", targetRef: destination, engagementId: null, planDigest: null },
        evidenceRefs: [`file://${path.join(destination, "install.json")}`]
      }, { paths });
      return { ...verified, operation: "install", state: "installed", cleanupPending: publication.cleanupPending };
    } finally {
      fs.rmSync(staging, { recursive: true, force: true });
    }
  } finally {
    releaseMutation();
  }
}

function readReceipt(file, paths) {
  const receipt = JSON.parse(readPrivateFileBounded(file, MAX_RECEIPT_BYTES, "utf8", {
    label: "managed tool installation receipt"
  }));
  assertValidDocument(receipt, "tool-install-receipt.schema.json", { paths });
  return receipt;
}

function assertPrivateRuntimeDirectory(directory, label) {
  const stat = fs.lstatSync(directory, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`${label} is not a regular directory`);
  if (process.platform !== "win32") {
    if (typeof process.geteuid === "function" && stat.uid !== BigInt(process.geteuid())) {
      throw new Error(`${label} is not owned by the current user`);
    }
    if ((stat.mode & 0o7777n) !== 0o700n) throw new Error(`${label} permissions are not owner-only (expected 0700)`);
  }
}

function exactInstalledTree(directory, entry) {
  assertPrivateRuntimeDirectory(directory, "managed tool installation");
  const rootEntries = fs.readdirSync(directory, { withFileTypes: true });
  if (rootEntries.length !== 2 || !rootEntries.some((item) => item.name === "bin" && item.isDirectory()) ||
      !rootEntries.some((item) => item.name === "install.json" && item.isFile())) {
    throw new Error("managed tool installation contains unreviewed extra paths");
  }
  const bin = path.join(directory, "bin");
  assertPrivateRuntimeDirectory(bin, "managed tool bin directory");
  const binEntries = fs.readdirSync(bin, { withFileTypes: true });
  if (binEntries.length !== 1 || binEntries[0].name !== path.basename(entry.executable.relativePath) || !binEntries[0].isFile()) {
    throw new Error("managed tool bin directory differs from the reviewed lock");
  }
}

function verifyReceiptBindings(receipt, entry, artifact, platform) {
  const expected = {
    id: entry.id,
    toolId: entry.toolId,
    provider: entry.provider,
    version: entry.version,
    platform: platform.key,
    lockEntrySha256: canonicalSha256(entry),
    catalogEntrySha256: entry.catalogEntrySha256,
    authority: "none-installation-does-not-authorize-target-contact"
  };
  for (const [key, value] of Object.entries(expected)) {
    if (receipt[key] !== value) throw new Error(`managed tool receipt ${key} mismatch`);
  }
  if (
    receipt.artifact.assetId !== artifact.assetId || receipt.artifact.url !== artifact.url ||
    receipt.artifact.size !== artifact.size || receipt.artifact.sha256 !== artifact.sha256 ||
    receipt.executable.relativePath !== entry.executable.relativePath ||
    receipt.executable.sha256 !== artifact.executableSha256 ||
    receipt.smoke.specSha256 !== canonicalSha256(entry.smoke) ||
    receipt.smoke.network !== "none" || receipt.smoke.status !== "passed"
  ) throw new Error("managed tool receipt evidence does not match the reviewed lock");
}

function reviewedProvenance(entry, artifact, platform) {
  return {
    provider: entry.provider,
    version: entry.version,
    platform: platform.key,
    lockEntrySha256: canonicalSha256(entry),
    catalogEntrySha256: entry.catalogEntrySha256,
    artifactSha256: artifact.sha256,
    executableSha256: artifact.executableSha256
  };
}

export function verifyManagedTool(id, options = {}) {
  let selected;
  try {
    selected = entryFor(id, options);
  } catch (error) {
    return {
      operation: "verify", id, toolId: id, ok: false, state: "invalid-lock",
      installed: false, verified: false, executable: null, reasons: [String(error.message || error)]
    };
  }
  const { paths, entry, tool } = selected;
  if (!entry) return unresolvedResult("verify", tool, ["reviewed-runtime-lock-unavailable"]);
  const platform = options.platform || currentRuntimePlatform(options.environment);
  const artifact = artifactFor(entry, platform);
  if (!platform.key || !artifact) return unresolvedResult("verify", tool, ["reviewed-platform-artifact-unavailable"], entry, platform);
  const directory = containedChild(paths.toolRuntimes, entry.id);
  if (!fs.existsSync(directory)) return baseResult("verify", tool, entry, platform, {
    ok: false, state: "absent", installed: false, verified: false, executable: null, reasons: ["managed-runtime-absent"]
  });
  try {
    securePrivateDirectory(directory, { create: false, label: `managed tool runtime ${entry.id}` });
    exactInstalledTree(directory, entry);
    const receipt = readReceipt(path.join(directory, "install.json"), paths);
    verifyReceiptBindings(receipt, entry, artifact, platform);
    const executable = path.join(directory, entry.executable.relativePath);
    const bytes = readBoundedRegularFile(executable, MAX_EXECUTABLE_BYTES, `managed executable ${entry.id}`, { mode: 0o700 });
    if (bytes.length !== receipt.executable.size || digestBuffer(bytes) !== artifact.executableSha256) {
      throw new Error("managed tool executable differs from the reviewed lock");
    }
    const smoke = runReviewedSmoke(executable, entry, platform, options);
    if (smoke.outputSha256 !== receipt.smoke.outputSha256) {
      throw new Error("managed tool smoke output changed from the installation evidence");
    }
    return baseResult("verify", tool, entry, platform, {
      ok: true,
      state: "verified",
      installed: true,
      verified: true,
      executable,
      provenance: reviewedProvenance(entry, artifact, platform),
      receipt: { installedAt: receipt.installedAt, smokeCompletedAt: smoke.completedAt },
      reasons: []
    });
  } catch (error) {
    return baseResult("verify", tool, entry, platform, {
      ok: false,
      state: "invalid",
      installed: true,
      verified: false,
      executable: null,
      reasons: [String(error.message || error)]
    });
  }
}

export function managedToolReceiptStatus(id, options = {}) {
  let selected;
  try {
    selected = entryFor(id, options);
  } catch (error) {
    return { id, toolId: id, locked: false, installed: false, state: "invalid-lock", reasons: [String(error.message || error)] };
  }
  const { paths, entry, tool } = selected;
  if (!entry) return { id, toolId: id, name: tool.name, locked: false, installed: false, state: "unmanaged", reasons: ["reviewed-runtime-lock-unavailable"] };
  const platform = options.platform || currentRuntimePlatform(options.environment);
  const artifact = artifactFor(entry, platform);
  if (!platform.key || !artifact) return {
    id, toolId: id, name: tool.name, locked: true, installed: false, state: "unsupported-platform",
    version: entry.version, platform: platform.key, reasons: ["reviewed-platform-artifact-unavailable"]
  };
  const directory = containedChild(paths.toolRuntimes, entry.id);
  if (!fs.existsSync(directory)) return {
    id, toolId: id, name: tool.name, locked: true, installed: false, state: "absent",
    version: entry.version, platform: platform.key, reasons: ["managed-runtime-absent"]
  };
  try {
    const receipt = readReceipt(path.join(directory, "install.json"), paths);
    verifyReceiptBindings(receipt, entry, artifact, platform);
    return {
      id, toolId: id, name: tool.name, locked: true, installed: true, verified: false,
      executable: null, state: "receipt-only", version: entry.version, platform: platform.key,
      reasons: ["explicit-integrity-and-smoke-verification-required"]
    };
  } catch (error) {
    return {
      id, toolId: id, name: tool.name, locked: true, installed: true, verified: false,
      executable: null, state: "invalid-receipt", version: entry.version, platform: platform.key,
      reasons: [String(error.message || error)]
    };
  }
}

function managedToolStaticStatus(id, options = {}) {
  const selected = entryFor(id, options);
  const { paths, entry, tool } = selected;
  if (!entry) return { id, toolId: id, name: tool.name, locked: false, installed: false, verified: false, state: "unmanaged", reasons: ["reviewed-runtime-lock-unavailable"] };
  const platform = options.platform || currentRuntimePlatform(options.environment);
  const artifact = artifactFor(entry, platform);
  if (!platform.key || !artifact) return {
    id, toolId: id, name: tool.name, locked: true, installed: false, verified: false,
    executable: null, state: "unsupported-platform", version: entry.version, platform: platform.key,
    reasons: ["reviewed-platform-artifact-unavailable"]
  };
  const directory = containedChild(paths.toolRuntimes, entry.id);
  if (!fs.existsSync(directory)) return {
    id, toolId: id, name: tool.name, locked: true, installed: false, verified: false,
    executable: null, state: "absent", version: entry.version, platform: platform.key,
    reasons: ["managed-runtime-absent"]
  };
  try {
    securePrivateDirectory(directory, { create: false, label: `managed tool runtime ${entry.id}` });
    exactInstalledTree(directory, entry);
    const receipt = readReceipt(path.join(directory, "install.json"), paths);
    verifyReceiptBindings(receipt, entry, artifact, platform);
    const executable = path.join(directory, entry.executable.relativePath);
    const bytes = readBoundedRegularFile(executable, MAX_EXECUTABLE_BYTES, `managed executable ${entry.id}`, { mode: 0o700 });
    if (bytes.length !== receipt.executable.size || digestBuffer(bytes) !== artifact.executableSha256) {
      throw new Error("managed tool executable differs from the reviewed lock");
    }
    return {
      id, toolId: id, name: tool.name, locked: true, installed: true, verified: true,
      executable, state: "verified-install-evidence", version: entry.version, platform: platform.key,
      smokeExecutedNow: false, reasons: []
    };
  } catch (error) {
    return {
      id, toolId: id, name: tool.name, locked: true, installed: true, verified: false,
      executable: null, state: "invalid", version: entry.version, platform: platform.key,
      smokeExecutedNow: false, reasons: [String(error.message || error)]
    };
  }
}

export function removeManagedTool(id, options = {}) {
  const { paths, entry, tool } = entryFor(id, options);
  if (!entry) return unresolvedResult("remove", tool, ["reviewed-runtime-lock-unavailable"]);
  ensureRuntime(paths);
  const directory = containedChild(paths.toolRuntimes, entry.id);
  if (!fs.existsSync(directory)) return baseResult("remove", tool, entry, currentRuntimePlatform(options.environment), {
    ok: true, state: "absent", installed: false, verified: false, executable: null, reasons: []
  });
  const releaseMutation = acquireMutationLock(paths, entry.id);
  try {
    securePrivateDirectory(directory, { create: false, label: `managed tool runtime ${entry.id}` });
    const retired = path.join(paths.toolRuntimeStaging, `${entry.id}-removed-${process.pid}-${crypto.randomBytes(4).toString("hex")}`);
    fs.renameSync(directory, retired);
    try {
      fs.rmSync(retired, { recursive: true, force: true });
    } catch (error) {
      if (!fs.existsSync(directory) && fs.existsSync(retired)) fs.renameSync(retired, directory);
      throw error;
    }
  } finally {
    releaseMutation();
  }
  recordEvent({
    kind: "tool-runtime.removed",
    summary: `Removed managed runtime ${entry.id}; cached artifact bytes were retained for re-verification before reuse.`,
    effect: { class: "host-write", targetRef: directory, engagementId: null, planDigest: null }
  }, { paths });
  return baseResult("remove", tool, entry, currentRuntimePlatform(options.environment), {
    ok: true, state: "removed", installed: false, verified: false, executable: null, reasons: []
  });
}

function baseResult(operation, tool, entry, platform, extra = {}) {
  return {
    operation,
    id: tool.id,
    toolId: tool.id,
    name: tool.name,
    provider: entry?.provider || null,
    version: entry?.version || null,
    platform: platform?.key || null,
    targetAuthority: "engagement-receipt-required",
    installationGrantsAuthority: false,
    ...extra
  };
}

function unresolvedResult(operation, tool, reasons, entry = null, platform = currentRuntimePlatform()) {
  return baseResult(operation, tool, entry, platform, {
    ok: false,
    state: "unresolved",
    installed: false,
    verified: false,
    executable: null,
    reasons
  });
}

function selection(options, catalog) {
  if (options.id && options.profile) throw new Error("select one tool id or --profile, not both");
  if (options.id) {
    const tool = catalog.tools.find((candidate) => candidate.id === options.id);
    if (!tool) throw new Error(`unknown security tool: ${options.id}`);
    return { selector: { type: "tool", id: options.id }, tools: [tool] };
  }
  if (!options.profile) throw new Error("a tool id or --profile is required");
  if (!/^[a-z][a-z0-9-]*$/u.test(options.profile)) throw new Error(`invalid profile id: ${options.profile}`);
  const profile = readJson(path.join(options.paths.repo, "config", "profiles", `${options.profile}.json`));
  const riskOrder = new Map(["P0", "P1", "A1", "A2", "A3"].map((value, index) => [value, index]));
  if (
    profile.apiVersion !== "gate.dev/profile/v1" || profile.kind !== "SecurityToolProfile" ||
    profile.id !== options.profile || profile.catalog !== "../../catalog/security-tools.json" ||
    !riskOrder.has(profile.maxRiskClass) || !Array.isArray(profile.toolIds) || profile.toolIds.length < 1 ||
    new Set(profile.toolIds).size !== profile.toolIds.length
  ) throw new Error(`invalid tool profile: ${options.profile}`);
  const byId = new Map(catalog.tools.map((tool) => [tool.id, tool]));
  const tools = profile.toolIds.map((id) => {
    const tool = byId.get(id);
    if (!tool) throw new Error(`tool profile ${profile.id} references unknown tool: ${id}`);
    if (!riskOrder.has(tool.riskClass) || riskOrder.get(tool.riskClass) > riskOrder.get(profile.maxRiskClass)) {
      throw new Error(`tool profile ${profile.id} exceeds maxRiskClass ${profile.maxRiskClass}: ${id}`);
    }
    return tool;
  });
  return { selector: { type: "profile", id: profile.id }, tools };
}

export async function runManagedToolOperation(operation, options = {}) {
  if (!new Set(["prefetch", "install", "verify", "remove"]).has(operation)) {
    throw new Error(`unsupported managed tool operation: ${operation}`);
  }
  const paths = options.paths || runtimePaths(options);
  const { catalog } = readToolRuntimeLock({ ...options, paths });
  const selected = selection({ ...options, paths }, catalog);
  const results = [];
  for (const tool of selected.tools) {
    try {
      if (operation === "prefetch") results.push(await prefetchManagedTool(tool.id, { ...options, paths }));
      if (operation === "install") results.push(await installManagedTool(tool.id, { ...options, paths }));
      if (operation === "verify") results.push(verifyManagedTool(tool.id, { ...options, paths }));
      if (operation === "remove") results.push(removeManagedTool(tool.id, { ...options, paths }));
    } catch (error) {
      results.push({
        operation, id: tool.id, toolId: tool.id, name: tool.name, ok: false, state: "failed",
        installed: false, verified: false, executable: null,
        targetAuthority: "engagement-receipt-required", installationGrantsAuthority: false,
        reasons: [String(error.message || error)]
      });
    }
  }
  const unresolved = results.filter((result) => !result.ok).map((result) => ({ id: result.id, state: result.state, reasons: result.reasons }));
  return {
    operation,
    selector: selected.selector,
    ok: unresolved.length === 0,
    complete: unresolved.length === 0,
    counts: {
      selected: results.length,
      succeeded: results.length - unresolved.length,
      unresolved: unresolved.length,
      installed: results.filter((result) => result.installed).length,
      verified: results.filter((result) => result.verified).length
    },
    results,
    unresolved,
    targetAuthority: "engagement-receipt-required",
    installationGrantsAuthority: false
  };
}

export function managedToolPlan(id, options = {}) {
  const { paths, entry, tool } = entryFor(id, options);
  const platform = options.platform || currentRuntimePlatform(options.environment);
  if (!entry) return {
    ...unresolvedResult("plan", tool, ["reviewed-runtime-lock-unavailable"], null, platform),
    effects: null,
    nextAction: "Add a reviewed provider lock before prefetch or install."
  };
  const artifact = artifactFor(entry, platform);
  const installSupported = Boolean(artifact && platform.os === "linux");
  const suppliedVerification = options.verification || null;
  const receipt = suppliedVerification ? null : managedToolReceiptStatus(id, { ...options, paths, platform });
  let verification = suppliedVerification;
  if (!verification && options.verify === true && receipt.installed) {
    verification = verifyManagedTool(id, { ...options, paths, platform });
  }
  const effective = verification || receipt;
  const unresolved = [];
  if (!artifact) unresolved.push("reviewed-platform-artifact-unavailable");
  if (artifact && !installSupported) unresolved.push("zero-egress-smoke-sandbox-unavailable");
  if (Array.isArray(tool.dataDependencies) && tool.dataDependencies.length) unresolved.push("reviewed-data-dependencies-unavailable");
  if (tool.privileges.some((value) => value !== "user")) unresolved.push("runtime-privilege-adapter-unavailable");
  if (effective.verified === true) unresolved.push("workflow-phase-admission-unavailable");
  return baseResult("plan", tool, entry, platform, {
    ok: Boolean(artifact),
    state: effective.state,
    installed: effective.installed === true,
    verified: effective.verified === true,
    executable: effective.executable || null,
    provenance: effective.provenance || null,
    executionAdmitted: false,
    artifact: artifact ? { url: artifact.url, bytes: artifact.size, sha256: artifact.sha256 } : null,
    prefetchSupported: Boolean(artifact),
    installSupported,
    cachePresent: Boolean(artifact && fs.existsSync(cacheFile(paths, artifact))),
    effects: {
      networkDuringPrefetch: entry.effects.networkDuringInstall,
      writes: [paths.toolArtifactCache, paths.toolRuntimes],
      administrator: entry.effects.adminRequired,
      services: entry.effects.services,
      devices: entry.effects.devices,
      executesDuringInstall: true,
      smoke: {
        argv: [entry.executable.relativePath, ...entry.smoke.argv],
        network: entry.smoke.network,
        timeoutMs: entry.smoke.timeoutMs,
        maxOutputBytes: entry.smoke.maxOutputBytes,
        maxProcesses: entry.smoke.maxProcesses
      }
    },
    unresolved,
    reasons: effective.reasons || [],
    nextAction: !artifact
      ? "Add a reviewed artifact for this platform."
      : !installSupported
        ? "Run gate tool prefetch; managed install awaits a reviewed zero-egress smoke sandbox for this platform."
      : effective.verified
        ? "Add a reviewed workflow-phase adapter before any one-shot target execution manifest."
        : effective.installed
          ? `Run gate tool verify ${id}.`
          : `Run gate tool install ${id}.`
  });
}

export function managedToolSummary(options = {}) {
  let loaded;
  try {
    loaded = readToolRuntimeLock(options);
  } catch (error) {
    return {
      ok: false,
      catalog: 0,
      locked: 0,
      installed: 0,
      verified: 0,
      executable: 0,
      unresolved: 0,
      unresolvedConstraints: [{ reason: "runtime-lock-invalid", count: 1 }],
      tools: [],
      error: String(error.message || error)
    };
  }
  const platform = options.platform || currentRuntimePlatform(options.environment);
  const tools = loaded.catalog.tools.map((tool) => {
    const entry = loaded.lock.runtimes.find((candidate) => candidate.toolId === tool.id);
    if (!entry) return {
      id: tool.id, name: tool.name, locked: false, installed: false, verified: false,
      executable: false, state: "unmanaged", reasons: [unmanagedReason(tool)]
    };
    const status = options.verify === true
      ? verifyManagedTool(tool.id, { ...options, paths: loaded.paths, platform })
      : options.staticIntegrity === true
        ? managedToolStaticStatus(tool.id, { ...options, paths: loaded.paths, platform })
        : managedToolReceiptStatus(tool.id, { ...options, paths: loaded.paths, platform });
    const dependencyBlocked = Array.isArray(tool.dataDependencies) && tool.dataDependencies.length > 0;
    const privilegeBlocked = tool.privileges.some((value) => value !== "user");
    const phaseAdmissionBlocked = status.verified === true;
    return {
      id: tool.id,
      name: tool.name,
      locked: true,
      installed: status.installed === true,
      verified: status.verified === true,
      executable: false,
      state: status.state,
      reasons: [
        ...(status.reasons || []),
        ...(dependencyBlocked ? ["reviewed-data-dependencies-unavailable"] : []),
        ...(privilegeBlocked ? ["runtime-privilege-adapter-unavailable"] : []),
        ...(phaseAdmissionBlocked ? ["workflow-phase-admission-unavailable"] : [])
      ]
    };
  });
  const reasonCounts = new Map();
  for (const tool of tools) {
    for (const reason of tool.reasons) reasonCounts.set(reason, (reasonCounts.get(reason) || 0) + 1);
  }
  return {
    ok: true,
    verificationMode: options.verify === true
      ? "current-bytes-and-live-zero-egress-smoke"
      : options.staticIntegrity === true
        ? "current-bytes-and-install-smoke-evidence"
        : "receipt-only",
    platform: platform.key,
    catalog: tools.length,
    locked: tools.filter((tool) => tool.locked).length,
    installed: tools.filter((tool) => tool.installed).length,
    verified: tools.filter((tool) => tool.verified).length,
    executable: tools.filter((tool) => tool.executable).length,
    unresolved: tools.filter((tool) => !tool.executable).length,
    unresolvedConstraints: [...reasonCounts].map(([reason, count]) => ({ reason, count })).sort((a, b) => b.count - a.count || a.reason.localeCompare(b.reason)),
    tools
  };
}

function unmanagedReason(tool) {
  const lanes = new Set(tool.installLanes || []);
  if (lanes.has("hardware")) return "hardware-runtime-unavailable";
  if (lanes.has("external-user-install")) return "external-or-licensed-runtime-unavailable";
  if (lanes.has("oci")) return "oci-runtime-unavailable";
  if (lanes.has("native-os")) return "native-runtime-unavailable";
  if (lanes.has("java-archive")) return "java-runtime-unavailable";
  if (lanes.has("isolated-python") || lanes.has("isolated-node")) return "language-runtime-unavailable";
  return "reviewed-runtime-lock-unavailable";
}

export function validateToolRuntimeContract(options = {}) {
  const paths = options.paths || runtimePaths(options);
  const checks = [];
  try {
    const { lock, catalog } = readToolRuntimeLock({ ...options, paths });
    checks.push({ name: "tool-runtimes:contract", ok: true, detail: `${lock.runtimes.length} reviewed runtimes` });
    const locked = new Set(lock.runtimes.map((entry) => entry.toolId));
    checks.push({
      name: "tool-runtimes:catalog-bindings",
      ok: lock.runtimes.every((entry) => catalog.tools.some((tool) => tool.id === entry.toolId)),
      detail: `${locked.size} catalog bindings`
    });
  } catch (error) {
    checks.push({ name: "tool-runtimes:contract", ok: false, detail: String(error.message || error) });
  }
  return checks;
}

export function validateToolInstallReceipt(value, options = {}) {
  const paths = options.paths || runtimePaths(options);
  return validateDocument(value, "tool-install-receipt.schema.json", { paths });
}
