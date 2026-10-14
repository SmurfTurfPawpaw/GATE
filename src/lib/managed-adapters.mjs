import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { compileDnsxDomainObserve } from "../adapters/dnsx-domain-observe.mjs";
import { compileHttpxUrlObserve } from "../adapters/httpx-url-observe.mjs";
import { readJson } from "./config.mjs";
import { runtimePaths } from "./paths.mjs";
import { assertValidDocument } from "./schema.mjs";
import {
  canonicalSha256,
  catalogEntrySha256,
  currentRuntimePlatform,
  readToolRuntimeLock,
  verifyManagedTool
} from "./tool-runtimes.mjs";

const COMPILERS = Object.freeze({
  "dnsx-exact-domain-v1": Object.freeze({
    compile: compileDnsxDomainObserve,
    source: "src/adapters/dnsx-domain-observe.mjs",
    sourceSha256: "8802f81ffd813ba6246e63e0fb058c55720154422330db50e1ef6daac3d924c6"
  }),
  "httpx-exact-url-get-v2": Object.freeze({
    compile: compileHttpxUrlObserve,
    source: "src/adapters/httpx-url-observe.mjs",
    sourceSha256: "ba1d336153866bf71f061d392ac6cd0ab57960a6fbf1066030ac52c5bb99e5ae"
  })
});

const ADAPTER_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;

function fileSha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function canonicalEqual(left, right) {
  return canonicalSha256(left) === canonicalSha256(right);
}

function exactRelativeFile(repo, relative, label) {
  if (typeof relative !== "string" || path.isAbsolute(relative) || relative.includes("\\") || relative.includes("\0")) {
    throw new Error(`${label} path is invalid`);
  }
  const file = path.resolve(repo, relative);
  const root = `${path.resolve(repo)}${path.sep}`;
  if (!file.startsWith(root)) throw new Error(`${label} escapes the repository`);
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`${label} must be a regular non-symlink file`);
  return file;
}

function validateRegistryEntry(entry, loaded, paths) {
  const runtime = loaded.lock.runtimes.find((candidate) => candidate.toolId === entry.tool.id);
  const tool = loaded.catalog.tools.find((candidate) => candidate.id === entry.tool.id);
  if (!runtime || !tool) throw new Error(`managed adapter references an unavailable runtime: ${entry.id}`);
  if (runtime.version !== entry.tool.version || runtime.toolId !== entry.tool.id) {
    throw new Error(`managed adapter tool version changed: ${entry.id}`);
  }
  if (canonicalSha256(runtime) !== entry.tool.lockEntrySha256) {
    throw new Error(`managed adapter runtime lock digest changed: ${entry.id}`);
  }
  if (catalogEntrySha256(tool) !== entry.tool.catalogEntrySha256 ||
      runtime.catalogEntrySha256 !== entry.tool.catalogEntrySha256) {
    throw new Error(`managed adapter catalog digest changed: ${entry.id}`);
  }
  if (tool.riskClass !== entry.tool.riskClass || tool.approval !== "engagement") {
    throw new Error(`managed adapter catalog effect or approval changed: ${entry.id}`);
  }
  for (const platform of ["linux-x64", "linux-arm64"]) {
    const artifact = runtime.artifacts.find((candidate) => candidate.platform === platform);
    if (!artifact || artifact.executableSha256 !== entry.tool.executableSha256[platform]) {
      throw new Error(`managed adapter executable digest changed: ${entry.id}/${platform}`);
    }
  }
  const compiler = COMPILERS[entry.compiler.id];
  if (!compiler) throw new Error(`managed adapter compiler is unavailable: ${entry.compiler.id}`);
  if (entry.compiler.source !== compiler.source || entry.compiler.sourceSha256 !== compiler.sourceSha256) {
    throw new Error(`managed adapter compiler identity changed: ${entry.id}`);
  }
  const source = exactRelativeFile(paths.repo, entry.compiler.source, `managed adapter compiler ${entry.id}`);
  if (fileSha256(source) !== entry.compiler.sourceSha256) {
    throw new Error(`managed adapter compiler digest changed: ${entry.id}`);
  }
  return entry;
}

export function loadManagedAdapterRegistry(options = {}) {
  const paths = options.paths || runtimePaths(options);
  const file = path.join(paths.repo, "config", "managed-adapters.json");
  const registry = readJson(file);
  assertValidDocument(registry, "managed-adapter-registry.schema.json", { paths });
  const ids = registry.adapters.map((entry) => entry.id);
  if (new Set(ids).size !== ids.length) throw new Error("managed adapter registry contains duplicate identifiers");
  const loaded = readToolRuntimeLock({ paths });
  for (const entry of registry.adapters) validateRegistryEntry(entry, loaded, paths);
  return {
    registry,
    registrySha256: canonicalSha256(registry),
    adapters: new Map(registry.adapters.map((entry) => [entry.id, entry]))
  };
}

function normalizeBounds(input, adapter) {
  const maxMinutes = Number(input.maxMinutes);
  const estimatedRequests = Number(input.estimatedRequests);
  const maxParallel = Number(input.maxParallel);
  const maxRatePerSecond = Number(input.maxRatePerSecond);
  const maxTokens = Number(input.maxTokens);
  const maxEvidenceBytes = Number(input.maxEvidenceBytes ?? 2 * 1024 * 1024);
  const integers = [
    [maxMinutes, "maxMinutes", 1],
    [estimatedRequests, "estimatedRequests", 1],
    [maxParallel, "maxParallel", 1],
    [maxTokens, "maxTokens", 1000],
    [maxEvidenceBytes, "maxEvidenceBytes", 2 * 1024 * 1024]
  ];
  for (const [value, name, minimum] of integers) {
    if (!Number.isSafeInteger(value) || value < minimum) throw new Error(`${name} must be an integer of at least ${minimum}`);
  }
  if (!Number.isFinite(maxRatePerSecond) || maxRatePerSecond <= 0) throw new Error("maxRatePerSecond must be positive");
  const bounds = { maxMinutes, estimatedRequests, maxParallel, maxRatePerSecond, maxTokens, maxEvidenceBytes };
  const maxima = adapter.limits;
  for (const [field, maximum] of [
    ["maxMinutes", maxima.maxMinutes],
    ["estimatedRequests", maxima.maxRequests],
    ["maxParallel", maxima.maxParallel],
    ["maxRatePerSecond", maxima.maxRatePerSecond],
    ["maxEvidenceBytes", maxima.maxEvidenceBytes]
  ]) {
    if (bounds[field] > maximum) throw new Error(`${field} exceeds the reviewed adapter limit of ${maximum}`);
  }
  return bounds;
}

function adapterBinding(registrySha256, adapter, compiled, runtime) {
  const operation = structuredClone(compiled.typedOperation);
  return {
    id: adapter.id,
    version: adapter.version,
    registrySha256,
    entrySha256: canonicalSha256(adapter),
    compiler: { ...adapter.compiler },
    selectorType: adapter.selectorType,
    action: adapter.action,
    effectClass: adapter.effectClass,
    allowedPhases: [...adapter.allowedPhases],
    operation,
    operationSha256: canonicalSha256(operation),
    argvSha256: canonicalSha256(compiled.argv),
    runtime: { ...runtime },
    controls: structuredClone(compiled.controls),
    allowedFeatures: [...adapter.allowedFeatures],
    forbiddenFeatures: [...adapter.forbiddenFeatures]
  };
}

function expectedRuntimeBinding(adapter, options = {}) {
  const loaded = readToolRuntimeLock({ paths: options.paths });
  const lockedRuntime = loaded.lock.runtimes.find((candidate) => candidate.toolId === adapter.tool.id);
  const platform = currentRuntimePlatform(options.environment);
  const artifact = lockedRuntime?.artifacts.find((candidate) => candidate.platform === platform.key);
  if (!platform.key || !artifact || canonicalSha256(lockedRuntime) !== adapter.tool.lockEntrySha256) {
    throw new Error(`managed adapter runtime lock changed for ${adapter.tool.id}`);
  }
  const runtime = {
    provider: "verified-release",
    version: adapter.tool.version,
    platform: platform.key,
    lockEntrySha256: adapter.tool.lockEntrySha256,
    catalogEntrySha256: adapter.tool.catalogEntrySha256,
    artifactSha256: artifact.sha256,
    executableSha256: adapter.tool.executableSha256[platform.key]
  };
  if (
    lockedRuntime.provider !== runtime.provider || lockedRuntime.version !== runtime.version ||
    lockedRuntime.catalogEntrySha256 !== runtime.catalogEntrySha256 ||
    artifact.executableSha256 !== runtime.executableSha256
  ) {
    throw new Error(`managed adapter runtime identity changed for ${adapter.tool.id}`);
  }
  return {
    runtime,
    platform,
    executable: path.join(options.paths.toolRuntimes, lockedRuntime.id, lockedRuntime.executable.relativePath)
  };
}

function requireVerifiedRuntime(adapter, options = {}) {
  const verify = options.verifyManagedTool || verifyManagedTool;
  const expected = expectedRuntimeBinding(adapter, options);
  const verified = verify(adapter.tool.id, {
    paths: options.paths,
    ...(options.runManagedSmoke ? { runSmoke: options.runManagedSmoke } : {})
  });
  if (!verified || verified.ok !== true || verified.verified !== true || verified.installed !== true ||
      typeof verified.executable !== "string" || !verified.provenance ||
      verified.verificationEvidence?.current !== true ||
      verified.verificationEvidence?.currentBytesChecked !== true ||
      verified.verificationEvidence?.liveSmokeExecutedNow !== true) {
    throw new Error(`managed adapter runtime verification failed for ${adapter.tool.id}: ${(verified?.reasons || ["unverified runtime"]).join("; ")}`);
  }
  if (verified.executable !== expected.executable) throw new Error(`managed adapter executable path changed for ${adapter.tool.id}`);
  if (!canonicalEqual(verified.provenance, expected.runtime)) {
    throw new Error(`managed adapter runtime provenance changed for ${adapter.tool.id}`);
  }
  return { verified, runtime: expected.runtime, platform: expected.platform };
}

export function prepareManagedAdapterInvocation(input, options = {}) {
  if (Object.hasOwn(input, "argv")) throw new Error("managed adapter manifests do not accept raw argv");
  const adapterId = String(input.adapterId || "");
  if (!ADAPTER_ID.test(adapterId)) throw new Error("adapterId must be a managed adapter identifier");
  const paths = options.paths || runtimePaths(options);
  const loaded = loadManagedAdapterRegistry({ paths });
  const adapter = loaded.adapters.get(adapterId);
  if (!adapter) throw new Error(`unknown managed target-contact adapter: ${adapterId}`);
  const bounds = normalizeBounds(input, adapter);
  const compiler = COMPILERS[adapter.compiler.id].compile;
  const compiled = compiler({ target: input.target, operation: input.operation, bounds });
  if (compiled.requestEstimate !== bounds.estimatedRequests) {
    throw new Error("compiled adapter request estimate differs from the declared bound");
  }
  const verifiedRuntime = requireVerifiedRuntime(adapter, { ...options, paths });
  const binding = adapterBinding(loaded.registrySha256, adapter, compiled, verifiedRuntime.runtime);
  return {
    adapter,
    binding,
    compiled,
    verifiedRuntime,
    normalized: {
      workflowId: String(input.workflowId || ""),
      phaseAttemptId: String(input.phaseAttemptId || ""),
      target: String(input.target || ""),
      action: adapter.action,
      toolId: adapter.tool.id,
      argv: [...compiled.argv],
      targetArgIndex: 1,
      declaredBounds: bounds
    }
  };
}

export function assertManagedAdapterManifest(manifest, options = {}) {
  const binding = manifest?.operation?.adapter;
  if (!binding) return null;
  const paths = options.paths || runtimePaths(options);
  const loaded = loadManagedAdapterRegistry({ paths });
  const adapter = loaded.adapters.get(binding.id);
  if (!adapter) throw new Error(`managed execution adapter is no longer registered: ${binding.id}`);
  if (loaded.registrySha256 !== binding.registrySha256 || canonicalSha256(adapter) !== binding.entrySha256) {
    throw new Error("managed execution adapter registry binding changed");
  }
  if (!adapter.allowedPhases.includes(manifest.workflow.phaseId)) {
    throw new Error(`managed adapter does not admit workflow phase ${manifest.workflow.phaseId}`);
  }
  if (manifest.operation.targetSelector.type !== adapter.selectorType || manifest.operation.action !== adapter.action ||
      manifest.operation.tool.id !== adapter.tool.id) {
    throw new Error("managed execution selector, action, or tool differs from the adapter contract");
  }
  const compiler = COMPILERS[adapter.compiler.id].compile;
  const compiled = compiler({
    target: manifest.operation.targetArgument,
    operation: binding.operation,
    bounds: manifest.declaredBounds
  });
  const expectedRuntime = expectedRuntimeBinding(adapter, { paths });
  const expected = adapterBinding(loaded.registrySha256, adapter, compiled, expectedRuntime.runtime);
  if (!canonicalEqual(binding, expected) || !canonicalEqual(manifest.operation.argv, compiled.argv)) {
    throw new Error("managed execution operation or deterministic argv binding changed");
  }
  return { adapter, compiled, binding };
}

export function reverifyManagedAdapterManifest(manifest, options = {}) {
  const checked = assertManagedAdapterManifest(manifest, options);
  if (!checked) return null;
  const paths = options.paths || runtimePaths(options);
  const current = requireVerifiedRuntime(checked.adapter, { ...options, paths });
  if (!canonicalEqual(current.runtime, checked.binding.runtime) || current.verified.executable !== manifest.operation.executable.resolvedPath) {
    throw new Error("managed execution runtime changed after manifest creation");
  }
  return current;
}

export function validateManagedAdapterOutput(manifest, bytes, options = {}) {
  const checked = assertManagedAdapterManifest(manifest, options);
  if (!checked) return null;
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { return { ok: false, status: "invalid", reason: "output-validation-failed", records: 0 }; }
  const lines = text.split(/\r?\n/u).filter((line) => line.length > 0);
  if (lines.length === 0) return { ok: false, status: "indeterminate", reason: "indeterminate-output", records: 0 };
  if (lines.length !== 1) return { ok: false, status: "invalid", reason: "output-validation-failed", records: lines.length };
  let record;
  try { record = JSON.parse(lines[0]); }
  catch { return { ok: false, status: "invalid", reason: "output-validation-failed", records: 1 }; }
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    return { ok: false, status: "invalid", reason: "output-validation-failed", records: 1 };
  }
  const target = manifest.operation.targetArgument;
  if (checked.adapter.id === "dnsx-domain-observe") {
    const observed = [record.host, record.input, record.name].filter((value) => typeof value === "string");
    if (!observed.includes(target)) {
      return { ok: false, status: "invalid", reason: "output-validation-failed", records: 1 };
    }
  } else if (checked.adapter.id === "httpx-url-observe") {
    const observed = [record.url, record.input].filter((value) => typeof value === "string");
    if (!observed.includes(checked.compiled.controls.dialUrl) ||
        record.host_ip !== checked.binding.operation.allowedIp) {
      return { ok: false, status: "invalid", reason: "output-validation-failed", records: 1 };
    }
  } else {
    return { ok: false, status: "invalid", reason: "output-validation-failed", records: 1 };
  }
  return { ok: true, status: "observed", reason: null, records: 1 };
}

export function validateManagedAdapterRegistry(options = {}) {
  try {
    const loaded = loadManagedAdapterRegistry(options);
    return [{
      name: "managed-adapters:registry",
      ok: true,
      detail: `${loaded.adapters.size} digest-bound reviewed adapters (${loaded.registrySha256})`
    }];
  } catch (error) {
    return [{ name: "managed-adapters:registry", ok: false, detail: String(error.message || error) }];
  }
}

export const managedAdapterInternals = Object.freeze({ adapterBinding, canonicalSha256 });
