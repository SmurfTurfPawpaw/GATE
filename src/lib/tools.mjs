import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { readJson } from "./config.mjs";
import { loadManagedAdapterRegistry } from "./managed-adapters.mjs";
import { offlineAnalysisCapability } from "./offline-analysis.mjs";
import { runtimePaths } from "./paths.mjs";
import { readPrivateFileBounded } from "./private-fs.mjs";
import {
  managedToolPlan,
  managedToolReceiptStatus,
  readToolRuntimeLock,
  verifyManagedTool
} from "./tool-runtimes.mjs";
import { readUpstreamLock, resolveUpstreamBinary } from "./upstreams.mjs";

const MAX_INSTALL_RECEIPT_BYTES = 64 * 1024;
const noFollow = fs.constants.O_NOFOLLOW || 0;
const nonBlocking = fs.constants.O_NONBLOCK || 0;
const riskClassOrder = new Map(["P0", "P1", "A1", "A2", "A3"].map((value, index) => [value, index]));

function currentHost() {
  if (process.platform === "win32") return "windows";
  if (process.platform === "darwin") return "macos";
  if (process.env.WSL_DISTRO_NAME || os.release().toLowerCase().includes("microsoft")) return "wsl2";
  return "linux";
}

function environmentValue(environment, name) {
  if (process.platform !== "win32") return environment[name] || "";
  const key = Object.keys(environment).find((candidate) => candidate.toUpperCase() === name);
  return key ? environment[key] || "" : "";
}

function executableNames(command, environment) {
  if (process.platform !== "win32") return [command];
  const extensions = (environmentValue(environment, "PATHEXT") || ".COM;.EXE;.BAT;.CMD")
    .split(";")
    .map((extension) => extension.trim())
    .filter((extension) => /^\.[A-Za-z0-9]+$/.test(extension));
  const commandExtension = path.extname(command).toLowerCase();
  if (extensions.some((extension) => extension.toLowerCase() === commandExtension)) return [command];
  return extensions.map((extension) => `${command}${extension}`);
}

function commandAvailable(command, environment = process.env) {
  if (!/^[A-Za-z0-9._+-]{1,80}$/.test(command)) return null;
  const delimiter = process.platform === "win32" ? ";" : ":";
  const directories = environmentValue(environment, "PATH")
    .split(delimiter)
    .map((directory) => directory.trim().replace(/^"(.*)"$/, "$1"))
    .filter(Boolean);

  for (const directory of directories) {
    for (const name of executableNames(command, environment)) {
      const candidate = path.resolve(directory, name);
      try {
        const stat = fs.statSync(candidate);
        if (!stat.isFile()) continue;
        fs.accessSync(candidate, process.platform === "win32" ? fs.constants.F_OK : fs.constants.X_OK);
        return candidate;
      } catch {
        // Continue through PATH without executing a locator helper or the candidate.
      }
    }
  }
  return null;
}

function repositoryEntrypoint(repo, relative) {
  if (typeof relative !== "string" || path.isAbsolute(relative)) return null;
  try {
    const root = fs.realpathSync(path.resolve(repo));
    const candidate = path.resolve(root, ...relative.split("/"));
    if (!candidate.startsWith(`${root}${path.sep}`)) return null;
    const stat = fs.lstatSync(candidate);
    if (!stat.isFile() || stat.isSymbolicLink()) return null;
    const resolved = fs.realpathSync(candidate);
    return resolved.startsWith(`${root}${path.sep}`) ? resolved : null;
  } catch {
    return null;
  }
}

function sameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function plainOwnedDirectory(directory) {
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) return null;
  if (typeof process.geteuid === "function" && stat.uid !== process.geteuid()) return null;
  return stat;
}

function containedUpstreamRoot(paths) {
  if (typeof paths.home !== "string" || typeof paths.upstreamTools !== "string") return null;
  try {
    const home = path.resolve(paths.home);
    const root = path.resolve(paths.upstreamTools);
    const relative = path.relative(home, root);
    if (!relative || path.isAbsolute(relative) || relative === ".." || relative.startsWith(`..${path.sep}`)) return null;
    if (!plainOwnedDirectory(home)) return null;
    let current = home;
    for (const part of relative.split(path.sep)) {
      if (!part || part === "." || part === "..") return null;
      current = path.join(current, part);
      if (!plainOwnedDirectory(current)) return null;
    }
    const realHome = fs.realpathSync(home);
    const realRoot = fs.realpathSync(root);
    if (!realRoot.startsWith(`${realHome}${path.sep}`)) return null;
    return realRoot;
  } catch {
    return null;
  }
}

function managedDirectory(root, id) {
  if (!root || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(id)) return null;
  try {
    const directory = path.resolve(root, id);
    if (!directory.startsWith(`${root}${path.sep}`) || !plainOwnedDirectory(directory)) return null;
    const real = fs.realpathSync(directory);
    return real.startsWith(`${root}${path.sep}`) ? real : null;
  } catch {
    return null;
  }
}

function stableRegularFile(root, relative) {
  if (typeof relative !== "string" || path.isAbsolute(relative)) return null;
  const parts = relative.split("/");
  if (!parts.length || parts.some((part) => !part || part === "." || part === "..")) return null;
  try {
    let parent = root;
    for (const part of parts.slice(0, -1)) {
      parent = path.join(parent, part);
      if (!plainOwnedDirectory(parent)) return null;
    }
    const file = path.join(parent, parts.at(-1));
    if (!file.startsWith(`${root}${path.sep}`)) return null;
    const before = fs.lstatSync(file);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1) return null;
    if (typeof process.geteuid === "function" && before.uid !== process.geteuid()) return null;
    if (process.platform !== "win32" && !fs.constants.O_NOFOLLOW) return null;
    const descriptor = fs.openSync(file, fs.constants.O_RDONLY | noFollow | nonBlocking);
    try {
      const opened = fs.fstatSync(descriptor);
      if (!opened.isFile() || opened.nlink !== 1 || !sameFile(before, opened)) return null;
      const after = fs.lstatSync(file);
      if (!after.isFile() || after.isSymbolicLink() || after.nlink !== 1 || !sameFile(opened, after)) return null;
      const real = fs.realpathSync(file);
      return real.startsWith(`${root}${path.sep}`) && real === file ? file : null;
    } finally {
      fs.closeSync(descriptor);
    }
  } catch {
    return null;
  }
}

function receiptOnlyInstallation(adapter, lockEntry, paths) {
  if (!lockEntry || lockEntry.install?.lane !== "npm") return null;
  const root = containedUpstreamRoot(paths);
  const directory = managedDirectory(root, adapter.upstreamId);
  if (!directory) return null;
  try {
    const receiptFile = path.join(directory, "install.json");
    const receipt = JSON.parse(readPrivateFileBounded(
      receiptFile,
      MAX_INSTALL_RECEIPT_BYTES,
      "utf8",
      { label: `managed upstream receipt ${adapter.upstreamId}` }
    ));
    if (
      receipt.apiVersion !== "gate.upstream-install/v2" || receipt.id !== adapter.upstreamId ||
      receipt.lane !== "npm" || receipt.package !== lockEntry.install.package ||
      receipt.version !== lockEntry.version || receipt.integrity !== lockEntry.install.integrity ||
      receipt.lockSha256 !== lockEntry.install.lockSha256 || !Number.isFinite(Date.parse(receipt.verifiedAt))
    ) return null;
    const executable = stableRegularFile(directory, adapter.upstreamEntrypoint);
    const currentRoot = containedUpstreamRoot(paths);
    const currentDirectory = managedDirectory(currentRoot, adapter.upstreamId);
    if (!executable || currentRoot !== root || currentDirectory !== directory) return null;
    return { directory, executable, verifiedAt: receipt.verifiedAt };
  } catch {
    return null;
  }
}

function managedAdapterStatus(tool, paths, host, environment, options) {
  const adapters = tool.managedAdapters || [];
  if (!adapters.length) return [];
  const resolver = options.resolveUpstreamBinary || resolveUpstreamBinary;
  let lock = null;
  try {
    ({ lock } = (options.readUpstreamLock || readUpstreamLock)({ paths }));
  } catch {
    // Each adapter reports the reviewed lock as unavailable below.
  }

  return adapters.map((adapter) => {
    const hostCompatible = adapter.supportedHosts.includes(host);
    const entrypoint = repositoryEntrypoint(paths.repo, adapter.entrypoint);
    const sandboxExecutable = commandAvailable(adapter.sandboxCommand, environment);
    const lockEntry = lock?.upstreams?.find((entry) => entry.id === adapter.upstreamId) || null;
    const receipt = receiptOnlyInstallation(adapter, lockEntry, paths);
    let adapterCapability = { available: false, reason: "unknown-managed-adapter-mode" };
    try {
      if (options.resolveAdapterCapability) {
        const observed = options.resolveAdapterCapability(adapter, { paths });
        if (typeof observed?.available !== "boolean") throw new Error("managed adapter capability result is invalid");
        adapterCapability = observed;
      } else if (adapter.mode === "offline-static-pe-resources") {
        const capability = offlineAnalysisCapability({ paths });
        adapterCapability = { available: capability.laneAvailable, reason: capability.reason };
      }
    } catch (error) {
      adapterCapability = { available: false, reason: String(error?.message || error) };
    }
    let resolved = null;
    if (options.verifyManagedIntegrity === true) {
      try {
        const candidate = resolver(adapter.upstreamId, adapter.binary, { paths });
        const currentReceipt = receiptOnlyInstallation(adapter, lockEntry, paths);
        if (
          candidate?.id !== adapter.upstreamId || candidate?.name !== adapter.binary ||
          typeof candidate.executable !== "string" || !path.isAbsolute(candidate.executable) ||
          !receipt || !currentReceipt || currentReceipt.directory !== receipt.directory ||
          currentReceipt.executable !== receipt.executable || currentReceipt.verifiedAt !== receipt.verifiedAt ||
          fs.realpathSync(candidate.directory) !== currentReceipt.directory ||
          fs.realpathSync(candidate.executable) !== currentReceipt.executable ||
          stableRegularFile(currentReceipt.directory, adapter.upstreamEntrypoint) !== currentReceipt.executable
        ) throw new Error("managed executable identity mismatch");
        resolved = { ...candidate, executable: currentReceipt.executable, directory: currentReceipt.directory };
      } catch {
        // A PATH namesake never substitutes for failed managed-upstream verification.
      }
    }

    const upstreamVerified = Boolean(resolved && lockEntry && receipt);
    const ready = Boolean(hostCompatible && entrypoint && adapterCapability.available && upstreamVerified);
    const unavailable = [];
    if (!hostCompatible) unavailable.push("unsupported-host");
    if (!entrypoint) unavailable.push("fixed-adapter-unavailable");
    if (!adapterCapability.available) unavailable.push("fixed-adapter-capability-unavailable");
    if (!lockEntry) unavailable.push("reviewed-upstream-lock-unavailable");
    if (!receipt) unavailable.push("managed-upstream-receipt-unavailable");
    if (!upstreamVerified) unavailable.push("managed-upstream-integrity-unverified");

    return {
      id: adapter.id,
      mode: adapter.mode,
      capability: adapter.capability,
      upstreamId: adapter.upstreamId,
      binary: adapter.binary,
      version: lockEntry?.version || null,
      commit: lockEntry?.commit || null,
      receiptPresent: Boolean(receipt),
      receiptVerifiedAt: receipt?.verifiedAt || null,
      integrityChecked: options.verifyManagedIntegrity === true,
      upstreamVerified,
      executable: upstreamVerified ? resolved.executable : null,
      entrypoint,
      sandboxExecutable,
      adapterCapabilityAvailable: Boolean(adapterCapability.available),
      adapterCapabilityReason: adapterCapability.reason || null,
      hostCompatible,
      ready,
      unavailable
    };
  });
}

function reviewedTargetContactAdapterStatus(tool, host, managedRuntimeVerified, options) {
  const adapters = options.targetContactAdapters?.filter((adapter) => adapter.tool.id === tool.id) || [];
  return adapters.map((adapter) => {
    const hostCompatible = new Set(["linux", "wsl2"]).has(host);
    const ready = Boolean(hostCompatible && managedRuntimeVerified);
    return {
      id: adapter.id,
      mode: "reviewed-managed-adapter",
      capability: "managed-target-contact",
      version: adapter.version,
      toolVersion: adapter.tool.version,
      selectorType: adapter.selectorType,
      action: adapter.action,
      effectClass: adapter.effectClass,
      allowedPhases: [...adapter.allowedPhases],
      registrySha256: options.targetContactAdapterRegistrySha256,
      integrityChecked: managedRuntimeVerified,
      upstreamVerified: managedRuntimeVerified,
      executable: managedRuntimeVerified ? options.managedRuntimeExecutable : null,
      hostCompatible,
      ready,
      unavailable: [
        ...(!hostCompatible ? ["unsupported-host"] : []),
        ...(!managedRuntimeVerified ? ["managed-runtime-integrity-unverified"] : [])
      ]
    };
  });
}

function resolvedTool(tool, paths, host, options) {
  const environment = options.environment || process.env;
  const commandCandidate = commandAvailable(tool.command, environment);
  const identity = tool.commandIdentity || {
    pathDiscovery: "command-name",
    genericLaneAdmission: "reviewed-admission",
    reason: "This catalog entry has no explicit reviewed PATH-discovery admission."
  };
  const acceptsPathDiscovery = identity.genericLaneAdmission === "path-discovery";
  const dataDependencyAdmissionRequired = Array.isArray(tool.dataDependencies) && tool.dataDependencies.length > 0;
  const compatible = tool.supportedHosts.includes(host);
  const runtimeEntry = options.runtimeEntries?.get(tool.id) || null;
  let managedRuntime = null;
  if (runtimeEntry) {
    if (paths.toolRuntimes) {
      managedRuntime = options.verifyManagedIntegrity === true
        ? verifyManagedTool(tool.id, { ...options, paths })
        : managedToolReceiptStatus(tool.id, { ...options, paths });
    } else {
      managedRuntime = {
        id: tool.id,
        toolId: tool.id,
        locked: true,
        installed: false,
        verified: false,
        executable: null,
        state: "absent",
        version: runtimeEntry.version,
        reasons: ["managed-runtime-path-unavailable"]
      };
    }
  }
  const managedRuntimeVerified = Boolean(managedRuntime?.verified && managedRuntime?.executable);
  const privilegeAdapterRequired = tool.privileges.some((value) => value !== "user");
  // A reviewed release establishes byte identity. It becomes invocable only
  // for operations exposed by a digest-bound phase-specific adapter.
  const upstreamAdapterStatuses = managedAdapterStatus(tool, paths, host, environment, options);
  const targetContactAdapterStatuses = reviewedTargetContactAdapterStatus(tool, host, managedRuntimeVerified, {
    ...options,
    managedRuntimeExecutable: managedRuntime?.executable || null
  });
  const managedAdapterStatuses = [...upstreamAdapterStatuses, ...targetContactAdapterStatuses];
  const receiptManagedAdapter = managedAdapterStatuses.find((adapter) => adapter.receiptPresent) || null;
  const verifiedManagedAdapter = managedAdapterStatuses.find((adapter) => adapter.upstreamVerified) || null;
  const readyManagedAdapters = managedAdapterStatuses.filter((adapter) => adapter.ready);
  const managedRuntimeAdmissionRequired = managedRuntimeVerified && targetContactAdapterStatuses.every((adapter) => !adapter.ready);
  const pathGenericLaneEligible = Boolean(commandCandidate) && acceptsPathDiscovery && compatible &&
    new Set(["linux", "wsl2"]).has(host);
  const genericLaneEligible = !managedRuntimeVerified && pathGenericLaneEligible;
  const executionModes = [...new Set([
    ...(genericLaneEligible ? ["supervised-generic"] : []),
    ...readyManagedAdapters.map((adapter) => adapter.mode)
  ])];
  const installed = Boolean(
    managedRuntime?.installed || receiptManagedAdapter || verifiedManagedAdapter || (commandCandidate && acceptsPathDiscovery)
  );
  const readiness = readyManagedAdapters.length
    ? "adapter-ready"
    : managedRuntimeVerified
      ? dataDependencyAdmissionRequired
        ? "managed-verified-data-required"
        : privilegeAdapterRequired
          ? "managed-verified-adapter-required"
          : "managed-verified-admission-required"
      : managedRuntime?.installed
        ? "managed-receipt"
    : verifiedManagedAdapter
      ? "managed-verified"
      : receiptManagedAdapter
        ? "managed-receipt"
        : commandCandidate && !acceptsPathDiscovery
          ? "identity-unverified"
          : commandCandidate
            ? "discovered"
            : "candidate";
  const executable = managedRuntimeVerified
    ? managedRuntime.executable
    : verifiedManagedAdapter?.executable || (acceptsPathDiscovery ? commandCandidate : null);
  const next = managedRuntimeVerified && dataDependencyAdmissionRequired
      ? "Admit the reviewed data dependencies before creating an execution manifest."
      : managedRuntimeVerified && privilegeAdapterRequired
        ? "Use a reviewed privilege-aware adapter before creating an execution manifest."
        : targetContactAdapterStatuses.some((adapter) => adapter.ready)
          ? `Use the reviewed ${targetContactAdapterStatuses.find((adapter) => adapter.ready).id} manifest; broader ${tool.name} capability remains unadmitted.`
        : managedRuntimeAdmissionRequired
          ? "Add a reviewed workflow-phase adapter that binds action and argv semantics before creating an execution manifest."
        : genericLaneEligible
    ? "Prepare a one-shot supervised execution manifest; launch-time hashing proves executable identity, not trusted provenance."
    : readyManagedAdapters.length
      ? `Use the reviewed ${readyManagedAdapters[0].mode} adapter; broader ${tool.name} capability remains unadmitted.`
      : commandCandidate && !acceptsPathDiscovery
        ? "Admit a pinned executable or reviewed adapter; this command name alone is not accepted as product identity."
        : managedRuntime?.installed
          ? `Run gate tool verify ${tool.id}; a receipt alone never admits execution.`
          : runtimeEntry
            ? `Run gate tool install ${tool.id} to materialize its reviewed release.`
        : verifiedManagedAdapter
          ? "Restore the fixed adapter host prerequisites before execution; the managed upstream alone does not grant broad execution."
          : receiptManagedAdapter
            ? "Run full managed-upstream integrity verification before treating the configured adapter as ready."
            : commandCandidate
              ? "Use a reviewed host-specific adapter; the supervised generic lane requires Linux or WSL2."
              : "Resolve an exact artifact, integrity, license record, and smoke test through the admission workflow before use.";

  return {
    ...tool,
    commandIdentity: identity,
    host,
    compatible,
    installed,
    executable,
    commandCandidate,
    readiness,
    versionVerified: managedRuntimeVerified || Boolean(verifiedManagedAdapter),
    integrityVerified: managedRuntimeVerified || Boolean(verifiedManagedAdapter),
    knownGoodProvenance: managedRuntimeVerified || Boolean(verifiedManagedAdapter),
    managedRuntime,
    managedRuntimeLocked: Boolean(runtimeEntry),
    managedRuntimeVerified,
    managedRuntimeAdmissionRequired,
    adapterConfigured: managedAdapterStatuses.length > 0,
    adapterReady: readyManagedAdapters.length > 0,
    managedAdapterStatus: managedAdapterStatuses,
    dataDependencyAdmissionRequired,
    dataDependencyReadiness: dataDependencyAdmissionRequired ? "admission-required" : "not-declared",
    identityAdmissionRequired: !acceptsPathDiscovery,
    genericLaneEligible,
    broadCapabilityReady: genericLaneEligible && !managedRuntimeAdmissionRequired,
    executionModes,
    executionMode: executionModes[0] || null,
    executionAvailable: executionModes.length > 0,
    targetAuthority: "engagement-receipt-required",
    installationGrantsAuthority: false,
    next
  };
}

function targetContactRegistry(options, paths) {
  if (options.targetContactAdapters) {
    return {
      adapters: options.targetContactAdapters,
      registrySha256: options.targetContactAdapterRegistrySha256 || null
    };
  }
  try {
    const loaded = loadManagedAdapterRegistry({ paths });
    return { adapters: [...loaded.adapters.values()], registrySha256: loaded.registrySha256 };
  } catch {
    return { adapters: [], registrySha256: null };
  }
}

export function loadToolCatalog(options = {}) {
  const paths = options.paths || runtimePaths(options);
  return { paths, catalog: readJson(path.join(paths.repo, "catalog", "security-tools.json")) };
}

function validateToolProfile(profile, catalog, id) {
  if (profile?.id !== id) throw new Error(`tool profile identity mismatch: ${id}`);
  if (!riskClassOrder.has(profile.maxRiskClass)) {
    throw new Error(`tool profile ${id} has an invalid maxRiskClass`);
  }
  if (!Array.isArray(profile.toolIds) || profile.toolIds.length === 0) {
    throw new Error(`tool profile ${id} has no tools`);
  }
  if (new Set(profile.toolIds).size !== profile.toolIds.length) {
    throw new Error(`tool profile ${id} contains duplicate tool ids`);
  }
  const toolsById = new Map(catalog.tools.map((tool) => [tool.id, tool]));
  for (const toolId of profile.toolIds) {
    const tool = toolsById.get(toolId);
    if (!tool) throw new Error(`tool profile ${id} references unknown tool: ${toolId}`);
    if (!riskClassOrder.has(tool.riskClass)) {
      throw new Error(`tool profile ${id} references ${toolId} with an invalid riskClass`);
    }
    if (riskClassOrder.get(tool.riskClass) > riskClassOrder.get(profile.maxRiskClass)) {
      throw new Error(
        `tool profile ${id} exceeds maxRiskClass ${profile.maxRiskClass}: ${toolId} is ${tool.riskClass}`
      );
    }
  }
  return profile;
}

export function loadToolProfile(id, options = {}) {
  const paths = options.paths || runtimePaths(options);
  const clean = String(id || "default").toLowerCase();
  if (!/^[a-z][a-z0-9-]*$/.test(clean)) throw new Error(`invalid profile id: ${id}`);
  const file = path.join(paths.repo, "config", "profiles", `${clean}.json`);
  if (!fs.existsSync(file)) throw new Error(`unknown tool profile: ${clean}`);
  const profile = readJson(file);
  const catalog = options.catalog || readJson(path.join(paths.repo, "catalog", "security-tools.json"));
  return validateToolProfile(profile, catalog, clean);
}

export function toolInventory(options = {}) {
  const { paths, catalog } = loadToolCatalog(options);
  const profile = options.profile ? loadToolProfile(options.profile, { paths, catalog }) : null;
  const selected = profile ? new Set(profile.toolIds) : null;
  const host = currentHost();
  let runtimeEntries = new Map();
  try {
    const runtimeLock = options.runtimeLock || readToolRuntimeLock({ paths }).lock;
    runtimeEntries = new Map(runtimeLock.runtimes.map((entry) => [entry.toolId, entry]));
  } catch {
    // Inventory remains available when the optional runtime lock is invalid;
    // repository validation and tool plan surface the lock error explicitly.
  }
  const targetAdapters = targetContactRegistry(options, paths);
  const tools = catalog.tools
    .filter((tool) => !selected || selected.has(tool.id))
    .filter((tool) => !options.category || tool.category === options.category)
    .map((tool) => resolvedTool(tool, paths, host, {
      ...options,
      runtimeEntries,
      targetContactAdapters: targetAdapters.adapters,
      targetContactAdapterRegistrySha256: targetAdapters.registrySha256
    }));
  return {
    host,
    profile: profile ? { id: profile.id, description: profile.description, maxRiskClass: profile.maxRiskClass } : null,
    count: tools.length,
    locked: tools.filter((tool) => tool.managedRuntimeLocked).length,
    installed: tools.filter((tool) => tool.installed).length,
    receiptOnly: tools.filter((tool) => tool.managedRuntime?.state === "receipt-only").length,
    verified: tools.filter((tool) => tool.integrityVerified).length,
    executable: tools.filter((tool) => tool.executionAvailable).length,
    unresolved: tools.filter((tool) => !tool.executionAvailable).length,
    verificationMode: options.verifyManagedIntegrity === true ? "full" : "receipt-only",
    tools
  };
}

export function toolShow(id, options = {}) {
  const { paths, catalog } = loadToolCatalog(options);
  const tool = catalog.tools.find((candidate) => candidate.id === id);
  if (!tool) throw new Error(`unknown security tool: ${id}`);
  let runtimeEntries = new Map();
  try {
    const runtimeLock = options.runtimeLock || readToolRuntimeLock({ paths }).lock;
    runtimeEntries = new Map(runtimeLock.runtimes.map((entry) => [entry.toolId, entry]));
  } catch {
    // Validation and plan expose the exact lock failure. This read-only detail
    // path stays available but cannot become execution-ready.
  }
  const targetAdapters = targetContactRegistry(options, paths);
  return resolvedTool(tool, paths, currentHost(), {
    ...options,
    runtimeEntries,
    targetContactAdapters: targetAdapters.adapters,
    targetContactAdapterRegistrySha256: targetAdapters.registrySha256,
    verifyManagedIntegrity: false
  });
}

export function toolPlan(id, options = {}) {
  const { paths, catalog } = loadToolCatalog(options);
  const tool = catalog.tools.find((candidate) => candidate.id === id);
  if (!tool) throw new Error(`unknown security tool: ${id}`);
  let runtimeEntries = new Map();
  try {
    const runtimeLock = options.runtimeLock || readToolRuntimeLock({ paths }).lock;
    runtimeEntries = new Map(runtimeLock.runtimes.map((entry) => [entry.toolId, entry]));
  } catch {
    // managedToolPlan below returns the exact invalid-lock diagnostic.
  }
  const targetAdapters = targetContactRegistry(options, paths);
  const resolved = resolvedTool(tool, paths, currentHost(), {
    ...options,
    runtimeEntries,
    targetContactAdapters: targetAdapters.adapters,
    targetContactAdapterRegistrySha256: targetAdapters.registrySha256,
    verifyManagedIntegrity: options.verifyManagedIntegrity !== false
  });
  let runtimePlan = null;
  try {
    runtimePlan = managedToolPlan(id, {
      ...options,
      paths,
      verify: options.verifyManagedIntegrity !== false,
      verification: options.verifyManagedIntegrity !== false ? resolved.managedRuntime : null
    });
  } catch (error) {
    runtimePlan = { ok: false, state: "invalid-lock", reasons: [String(error.message || error)] };
  }
  return {
    ...resolved,
    preferredLane: runtimeEntries.has(id) ? "managed-verified-release" : tool.installLanes[0],
    alternateLanes: runtimeEntries.has(id) ? tool.installLanes : tool.installLanes.slice(1),
    runtimePlan
  };
}
