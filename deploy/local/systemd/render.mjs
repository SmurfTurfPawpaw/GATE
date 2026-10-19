#!/usr/bin/env node

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const templates = [
  "gate-observer.service",
  "gate-campaign@.service",
  "gate-remote-runner@.service"
];

function usage() {
  return "usage: node deploy/local/systemd/render.mjs --repo ABSOLUTE_PATH --node ABSOLUTE_PATH [--output DIRECTORY]\n";
}

function argumentsFrom(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!new Set(["--repo", "--node", "--output"]).has(flag) || !value || value.startsWith("--")) {
      throw new Error(usage().trim());
    }
    if (result[flag]) throw new Error(`${flag} may only be supplied once`);
    result[flag] = value;
  }
  return result;
}

function exactPath(value, label, kind) {
  if (!value || !path.isAbsolute(value)) throw new Error(`${label} must be an absolute path`);
  const resolved = fs.realpathSync(value);
  if (/[\r\n\0%$]/u.test(resolved)) throw new Error(`${label} contains a character unsupported by the unit renderer`);
  const stat = fs.statSync(resolved);
  if (kind === "file" && !stat.isFile()) throw new Error(`${label} must be a regular file`);
  if (kind === "directory" && !stat.isDirectory()) throw new Error(`${label} must be a directory`);
  return resolved;
}

function unitQuote(value) {
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

function unitPath(value) {
  return [...Buffer.from(value, "utf8")]
    .map((byte) => {
      const character = String.fromCharCode(byte);
      return /[A-Za-z0-9/._:+,@~-]/u.test(character)
        ? character
        : `\\x${byte.toString(16).padStart(2, "0")}`;
    })
    .join("");
}

function writeAtomic(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.tmp.${process.pid}`;
  fs.writeFileSync(temporary, content, { encoding: "utf8", mode: 0o644, flag: "wx" });
  fs.renameSync(temporary, file);
}

try {
  const args = argumentsFrom(process.argv.slice(2));
  const repo = exactPath(args["--repo"], "--repo", "directory");
  const node = exactPath(args["--node"], "--node", "file");
  const gate = exactPath(path.join(repo, "bin", "gate.mjs"), "GATE entrypoint", "file");
  const remoteRunner = exactPath(
    path.join(repo, "cockpit", "remote", "runner-cli.mjs"),
    "GATE remote runner entrypoint",
    "file"
  );
  const output = path.resolve(args["--output"] || path.join(os.homedir(), ".config", "systemd", "user"));
  for (const name of templates) {
    const source = path.join(here, "user", `${name}.example`);
    const rendered = fs.readFileSync(source, "utf8")
      .replaceAll("@GATE_WORKDIR@", unitPath(repo))
      .replaceAll("@GATE_BIN@", unitQuote(gate))
      .replaceAll("@REMOTE_RUNNER@", unitQuote(remoteRunner))
      .replaceAll("@NODE@", unitQuote(node));
    if (/@[A-Z_]+@/u.test(rendered)) throw new Error(`unit template still contains a placeholder: ${name}`);
    writeAtomic(path.join(output, name), rendered);
  }
  process.stdout.write(`${output}\n`);
} catch (error) {
  process.stderr.write(`gate service renderer: ${error.message}\n`);
  process.exitCode = 1;
}
