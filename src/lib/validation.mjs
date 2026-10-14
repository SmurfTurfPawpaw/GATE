import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { readJson } from "./config.mjs";
import { runtimePaths } from "./paths.mjs";
import { pentestWorkflowSemanticErrors } from "./pentest-workflow.mjs";
import { validateManagedAdapterRegistry } from "./managed-adapters.mjs";
import { validateDocument } from "./schema.mjs";
import { validateToolRuntimeContract } from "./tool-runtimes.mjs";

const riskClassOrder = new Map(["P0", "P1", "A1", "A2", "A3"].map((value, index) => [value, index]));

function walk(directory) {
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const child = path.join(directory, entry.name);
    return entry.isDirectory() ? walk(child) : [child];
  });
}

function result(name, ok, detail) {
  return { name, ok, detail };
}

export function validateRepository(options = {}) {
  const paths = options.paths || runtimePaths(options);
  const checks = [];
  const required = [
    "package.json",
    "config/gate.config.json",
    "AGENTS.md",
    "README.md",
    "SECURITY.md",
    "locks/upstreams.lock.json",
    "locks/tool-runtimes.lock.json",
    "catalog/security-tools.json"
  ];
  for (const relative of required) {
    checks.push(result(`file:${relative}`, fs.existsSync(path.join(paths.repo, relative)), "required"));
  }

  const jsonFiles = ["config", "schemas", "catalog", "locks", "templates"]
    .flatMap((directory) => walk(path.join(paths.repo, directory)))
    .filter((file) => file.endsWith(".json"));
  for (const file of jsonFiles) {
    try {
      readJson(file);
      checks.push(result(`json:${path.relative(paths.repo, file)}`, true, "valid JSON"));
    } catch (error) {
      checks.push(result(`json:${path.relative(paths.repo, file)}`, false, error.message));
    }
  }

  const lockFile = path.join(paths.repo, "locks", "upstreams.lock.json");
  if (fs.existsSync(lockFile)) {
    try {
      const lock = readJson(lockFile);
      const entries = lock.upstreams || [];
      const ids = entries.map((entry) => entry.id);
      checks.push(result("pins:unique-ids", new Set(ids).size === ids.length, `${ids.length} upstreams`));
      for (const entry of entries) {
        checks.push(
          result(
            `pin:${entry.id || "unknown"}`,
            /^[0-9a-f]{40}$/.test(entry.commit || ""),
            entry.commit || "missing commit"
          )
        );
        if (entry.install?.lane === "npm") {
          const lockPath = path.resolve(paths.repo, entry.install.lockfile || "");
          const insideRepository = lockPath.startsWith(`${path.resolve(paths.repo)}${path.sep}`);
          let valid = insideRepository && fs.existsSync(lockPath);
          let detail = valid ? entry.install.lockfile : "missing or unsafe npm lockfile";
          if (valid) {
            try {
              const digest = crypto.createHash("sha256").update(fs.readFileSync(lockPath)).digest("hex");
              const npmLock = readJson(lockPath);
              const direct = npmLock.packages?.[`node_modules/${entry.install.package}`];
              valid = digest === entry.install.lockSha256 &&
                npmLock.packages?.[""]?.dependencies?.[entry.install.package] === entry.version &&
                direct?.version === entry.version && direct?.integrity === entry.install.integrity;
              detail = valid ? `${entry.install.lockfile} ${digest}` : `npm lock mismatch: ${entry.install.lockfile}`;
            } catch (error) {
              valid = false;
              detail = error.message;
            }
          }
          checks.push(result(`npm-lock:${entry.id}`, valid, detail));
        }
      }
    } catch {
      // The JSON parse check above owns the diagnostic.
    }
  }

  const catalogFile = path.join(paths.repo, "catalog", "security-tools.json");
  let catalogIds = new Set();
  let catalogToolsById = new Map();
  if (fs.existsSync(catalogFile)) {
    try {
      const catalog = readJson(catalogFile);
      const tools = catalog.tools || [];
      const ids = tools.map((tool) => tool.id);
      catalogIds = new Set(ids);
      catalogToolsById = new Map(tools.map((tool) => [tool.id, tool]));
      checks.push(result("catalog:unique-ids", new Set(ids).size === ids.length, `${ids.length} tools`));
      for (const tool of tools) {
        checks.push(
          result(
            `catalog:${tool.id}`,
            Boolean(tool.id && tool.name && tool.license && tool.upstream && tool.riskClass && tool.approval),
            "required metadata"
          )
        );
      }
    } catch {
      // The JSON parse check above owns the diagnostic.
    }
  }

  const profileFiles = walk(path.join(paths.repo, "config", "profiles")).filter((file) => file.endsWith(".json"));
  for (const file of profileFiles) {
    try {
      const profile = readJson(file);
      const expectedId = path.basename(file, ".json");
      const ids = Array.isArray(profile.toolIds) ? profile.toolIds : [];
      const missing = ids.filter((id) => !catalogIds.has(id));
      const invalidCeiling = !riskClassOrder.has(profile.maxRiskClass);
      const invalidRisk = ids.filter((id) => {
        const tool = catalogToolsById.get(id);
        return tool && !riskClassOrder.has(tool.riskClass);
      });
      const overCeiling = invalidCeiling || invalidRisk.length ? [] : ids.filter((id) => {
        const tool = catalogToolsById.get(id);
        return tool && riskClassOrder.get(tool.riskClass) > riskClassOrder.get(profile.maxRiskClass);
      });
      const valid = profile.id === expectedId && ids.length > 0 && new Set(ids).size === ids.length && missing.length === 0 &&
        !invalidCeiling && invalidRisk.length === 0 && overCeiling.length === 0;
      const detail = profile.id !== expectedId
        ? `profile id ${profile.id || "missing"} does not match filename ${expectedId}`
        : missing.length
          ? `unknown tools: ${missing.join(", ")}`
          : invalidCeiling
            ? `invalid maxRiskClass: ${profile.maxRiskClass || "missing"}`
            : invalidRisk.length
              ? `tools have invalid riskClass: ${invalidRisk.join(", ")}`
              : overCeiling.length
                ? `tools exceed ${profile.maxRiskClass}: ${overCeiling.map((id) => `${id} (${catalogToolsById.get(id).riskClass})`).join(", ")}`
                : `${ids.length} resolved tools at or below ${profile.maxRiskClass}`;
      checks.push(
        result(
          `profile:${expectedId}`,
          valid,
          detail
        )
      );
    } catch (error) {
      checks.push(result(`profile:${path.basename(file)}`, false, error.message));
    }
  }

  const schemas = walk(path.join(paths.repo, "schemas")).filter((file) => file.endsWith(".schema.json"));
  for (const file of schemas) {
    try {
      const schema = readJson(file);
      checks.push(
        result(
          `schema:${path.basename(file)}`,
          schema.$schema === "https://json-schema.org/draft/2020-12/schema",
          schema.$schema || "missing $schema"
        )
      );
    } catch {
      // The JSON parse check above owns the diagnostic.
    }
  }

  const documents = [
    ["config/gate.config.json", "gate-config.schema.json"],
    ["locks/upstreams.lock.json", "upstream-lock.schema.json"],
    ["locks/tool-runtimes.lock.json", "tool-runtime-lock.schema.json"],
    ["config/managed-adapters.json", "managed-adapter-registry.schema.json"],
    ["policies/autonomy.json", "autonomy-policy.schema.json"],
    ["policies/data-handling.json", "data-policy.schema.json"],
    ["policies/engagements.json", "engagement-policy.schema.json"],
    ["policies/learning.json", "learning-policy.schema.json"],
    ["policies/updates.json", "update-policy.schema.json"],
    ["catalog/security-tools.json", "tool-catalog.schema.json"],
    ["config/workflows/pentest-e2e.json", "pentest-workflow.schema.json"],
    ["templates/engagement.json", "engagement.schema.json"],
    ["templates/learning.json", "learning.schema.json"],
    ["templates/project.json", "project.schema.json"]
  ];
  for (const [relative, schema] of documents) {
    const file = path.join(paths.repo, relative);
    if (!fs.existsSync(file)) {
      checks.push(result(`contract:${relative}`, false, "missing document"));
      continue;
    }
    try {
      const document = readJson(file);
      const validation = validateDocument(document, schema, { paths });
      const errors = [...validation.errors];
      if (validation.ok && relative === "config/workflows/pentest-e2e.json") {
        errors.push(...pentestWorkflowSemanticErrors(document, {
          catalog: readJson(path.join(paths.repo, "catalog", "security-tools.json")),
          engagementPolicy: readJson(path.join(paths.repo, "policies", "engagements.json"))
        }));
      }
      checks.push(result(`contract:${relative}`, errors.length === 0, errors.length ? errors.join("; ") : schema));
    } catch (error) {
      checks.push(result(`contract:${relative}`, false, error.message));
    }
  }

  checks.push(...validateToolRuntimeContract({ paths }));
  checks.push(...validateManagedAdapterRegistry({ paths }));


  const learningLog = path.join(paths.repo, "memory", "learnings.jsonl");
  if (fs.existsSync(learningLog)) {
    const lines = fs.readFileSync(learningLog, "utf8").split(/\r?\n/).filter(Boolean);
    lines.forEach((line, index) => {
      try {
        const validation = validateDocument(JSON.parse(line), "learning.schema.json", { paths });
        checks.push(
          result(
            `learning:${index + 1}`,
            validation.ok,
            validation.ok ? "learning.schema.json" : validation.errors.join("; ")
          )
        );
      } catch (error) {
        checks.push(result(`learning:${index + 1}`, false, error.message));
      }
    });
  }

  return { ok: checks.every((check) => check.ok), checks };
}
