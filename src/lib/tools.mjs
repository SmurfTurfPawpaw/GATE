import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { readJson } from "./config.mjs";
import { runtimePaths } from "./paths.mjs";

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

export function loadToolCatalog(options = {}) {
  const paths = options.paths || runtimePaths(options);
  return { paths, catalog: readJson(path.join(paths.repo, "catalog", "security-tools.json")) };
}

export function loadToolProfile(id, options = {}) {
  const paths = options.paths || runtimePaths(options);
  const clean = String(id || "default").toLowerCase();
  if (!/^[a-z][a-z0-9-]*$/.test(clean)) throw new Error(`invalid profile id: ${id}`);
  const file = path.join(paths.repo, "config", "profiles", `${clean}.json`);
  if (!fs.existsSync(file)) throw new Error(`unknown tool profile: ${clean}`);
  return readJson(file);
}

export function toolInventory(options = {}) {
  const { paths, catalog } = loadToolCatalog(options);
  const profile = options.profile ? loadToolProfile(options.profile, { paths }) : null;
  const selected = profile ? new Set(profile.toolIds) : null;
  const host = currentHost();
  const tools = catalog.tools
    .filter((tool) => !selected || selected.has(tool.id))
    .filter((tool) => !options.category || tool.category === options.category)
    .map((tool) => {
      const executable = commandAvailable(tool.command);
      return {
        ...tool,
        host,
        compatible: tool.supportedHosts.includes(host),
        installed: Boolean(executable),
        executable,
        readiness: executable ? "discovered" : "candidate",
        versionVerified: false,
        integrityVerified: false,
        adapterReady: false,
        executionAvailable: false
      };
    });
  return {
    host,
    profile: profile ? { id: profile.id, description: profile.description, maxRiskClass: profile.maxRiskClass } : null,
    count: tools.length,
    installed: tools.filter((tool) => tool.installed).length,
    tools
  };
}

export function toolPlan(id, options = {}) {
  const { catalog } = loadToolCatalog(options);
  const tool = catalog.tools.find((candidate) => candidate.id === id);
  if (!tool) throw new Error(`unknown security tool: ${id}`);
  const host = currentHost();
  const executable = commandAvailable(tool.command);
  return {
    id: tool.id,
    name: tool.name,
    installed: Boolean(executable),
    executable,
    readiness: executable ? "discovered" : "candidate",
    versionVerified: false,
    integrityVerified: false,
    adapterReady: false,
    executionAvailable: false,
    compatible: tool.supportedHosts.includes(host),
    host,
    preferredLane: tool.installLanes[0],
    alternateLanes: tool.installLanes.slice(1),
    approval: tool.approval,
    riskClass: tool.riskClass,
    privileges: tool.privileges,
    upstream: tool.upstream,
    license: tool.license,
    openSource: tool.openSource,
    next: executable
      ? "Run through a scope-aware adapter; catalog presence does not grant target authority."
      : "Resolve an exact artifact, integrity, license record, and smoke test through the admission workflow before use."
  };
}
