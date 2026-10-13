import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { gateConfigHome, runtimePaths } from "./paths.mjs";
import { readPrivateFile, writePrivateFileAtomic } from "./private-fs.mjs";

export function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

export function readPrivateJson(file) {
  return JSON.parse(readPrivateFile(file, "utf8", { label: `private JSON file ${file}` }));
}

export function writeJsonAtomic(file, value, mode = 0o600) {
  const content = `${JSON.stringify(value, null, 2)}\n`;
  if (mode === 0o600) {
    writePrivateFileAtomic(file, content, { encoding: "utf8", label: `private JSON file ${file}` });
    return;
  }
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  try {
    fs.writeFileSync(temporary, content, { encoding: "utf8", mode, flag: "wx" });
    fs.renameSync(temporary, file);
  } finally {
    fs.rmSync(temporary, { force: true });
  }
}

export function mergeObjects(base, overlay) {
  if (Array.isArray(base) || Array.isArray(overlay)) return structuredClone(overlay);
  if (!base || typeof base !== "object" || !overlay || typeof overlay !== "object") {
    return structuredClone(overlay);
  }
  const result = structuredClone(base);
  for (const [key, value] of Object.entries(overlay)) {
    result[key] = key in result ? mergeObjects(result[key], value) : structuredClone(value);
  }
  return result;
}

export function loadConfig(options = {}) {
  const paths = options.paths || runtimePaths(options);
  const rootFile = path.join(paths.repo, "config", "gate.config.json");
  if (!fs.existsSync(rootFile)) throw new Error(`GATE config is missing: ${rootFile}`);
  let config = readJson(rootFile);
  const localFile = options.localFile || path.join(gateConfigHome(options.env), "config.json");
  if (fs.existsSync(localFile)) config = mergeObjects(config, readJson(localFile));
  return { config, paths, rootFile, localFile };
}
