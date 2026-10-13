import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { readJson } from "./config.mjs";
import { runtimePaths } from "./paths.mjs";
import { validateDocument } from "./schema.mjs";

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
  if (fs.existsSync(catalogFile)) {
    try {
      const catalog = readJson(catalogFile);
      const tools = catalog.tools || [];
      const ids = tools.map((tool) => tool.id);
      catalogIds = new Set(ids);
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
      const ids = Array.isArray(profile.toolIds) ? profile.toolIds : [];
      const missing = ids.filter((id) => !catalogIds.has(id));
      checks.push(
        result(
          `profile:${profile.id || path.basename(file)}`,
          ids.length > 0 && new Set(ids).size === ids.length && missing.length === 0,
          missing.length ? `unknown tools: ${missing.join(", ")}` : `${ids.length} resolved tools`
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
    ["policies/autonomy.json", "autonomy-policy.schema.json"],
    ["policies/data-handling.json", "data-policy.schema.json"],
    ["policies/engagements.json", "engagement-policy.schema.json"],
    ["policies/learning.json", "learning-policy.schema.json"],
    ["policies/updates.json", "update-policy.schema.json"],
    ["catalog/security-tools.json", "tool-catalog.schema.json"],
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
      const validation = validateDocument(readJson(file), schema, { paths });
      checks.push(result(`contract:${relative}`, validation.ok, validation.ok ? schema : validation.errors.join("; ")));
    } catch (error) {
      checks.push(result(`contract:${relative}`, false, error.message));
    }
  }


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
