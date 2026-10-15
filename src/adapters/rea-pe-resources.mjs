import crypto from "node:crypto";
import fs from "node:fs";
import { spawnSync } from "node:child_process";

const EXPECTED_REA_ENTRY = "/opt/gate/rea/node_modules/rea-agents/scripts/rea.mjs";
const EXPECTED_ARTIFACT = "/input/artifact";
const MAX_TOOL_OUTPUT_BYTES = 48 * 1024 * 1024;

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(2);
}

function boundedInteger(value, name, minimum, maximum) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum) {
    fail(`${name} must be an integer from ${minimum} to ${maximum}`);
  }
  return number;
}

function artifactIdentity(file, maximumBytes) {
  const stat = fs.statSync(file);
  if (!stat.isFile() || stat.size < 1 || stat.size > maximumBytes) {
    fail("artifact is not a bounded regular file");
  }
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY);
  try {
    const hash = crypto.createHash("sha256");
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let bytes = 0;
    while (true) {
      const read = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (read === 0) break;
      bytes += read;
      hash.update(buffer.subarray(0, read));
    }
    return { sha256: hash.digest("hex"), bytes };
  } finally {
    fs.closeSync(descriptor);
  }
}

function isolationEvidence() {
  const interfaces = fs.readFileSync("/proc/net/dev", "utf8")
    .split(/\r?\n/u)
    .slice(2)
    .map((line) => line.includes(":") ? line.slice(0, line.indexOf(":")).trim() : "")
    .filter(Boolean)
    .sort();
  const ipv4Routes = fs.readFileSync("/proc/net/route", "utf8")
    .split(/\r?\n/u)
    .slice(1)
    .map((line) => line.trim())
    .filter(Boolean);
  const status = Object.fromEntries(fs.readFileSync("/proc/self/status", "utf8")
    .split(/\r?\n/u)
    .map((line) => line.match(/^(Cap(?:Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs):\s*(\S+)$/u))
    .filter(Boolean)
    .map((match) => [match[1], match[2]]));
  const capabilityFields = ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"];
  if (interfaces.length !== 1 || interfaces[0] !== "lo") fail("offline namespace has an unexpected network interface");
  if (ipv4Routes.length !== 0) fail("offline namespace has an IPv4 route");
  if (capabilityFields.some((field) => status[field] !== "0000000000000000")) {
    fail("offline process retained a Linux capability");
  }
  if (status.NoNewPrivs !== "1") fail("offline process is missing NoNewPrivs");
  return {
    interfaces,
    ipv4Routes,
    capabilities: Object.fromEntries(capabilityFields.map((field) => [field, status[field]])),
    noNewPrivileges: true
  };
}

const [reaEntry, artifactPath, maxFileBytesText, maxEntriesText] = process.argv.slice(2);
if (process.argv.length !== 6 || reaEntry !== EXPECTED_REA_ENTRY || artifactPath !== EXPECTED_ARTIFACT) {
  fail("adapter arguments do not match the fixed REA PE-resource contract");
}
const maxFileBytes = boundedInteger(maxFileBytesText, "maxFileBytes", 1, 512 * 1024 * 1024);
const maxEntries = boundedInteger(maxEntriesText, "maxEntries", 1, 16_384);
const isolation = isolationEvidence();
const artifact = artifactIdentity(artifactPath, maxFileBytes);
const tool = spawnSync(process.execPath, [
  reaEntry,
  "inspect-pe-resources",
  artifactPath,
  "--max-file-bytes", String(maxFileBytes),
  "--max-entries", String(maxEntries),
  "--format", "json",
  "--full-output"
], {
  cwd: "/tmp",
  env: { ...process.env },
  encoding: "utf8",
  maxBuffer: MAX_TOOL_OUTPUT_BYTES,
  windowsHide: true
});

if (tool.error) fail(`REA failed to start: ${tool.error.message}`);
if (tool.status !== 0) {
  const detail = String(tool.stderr || "REA PE-resource inspection failed").trim().slice(0, 16_384);
  fail(detail || "REA PE-resource inspection failed");
}

let result;
try {
  result = JSON.parse(tool.stdout);
} catch {
  fail("REA returned invalid JSON");
}

process.stdout.write(`${JSON.stringify({
  apiVersion: "gate.offline-adapter-result/v1",
  adapterId: "rea-inspect-pe-resources-v1",
  action: "local-static-analysis",
  networkPolicy: "none",
  artifact,
  isolation,
  result
})}\n`);
