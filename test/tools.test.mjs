import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { toolInventory, toolPlan } from "../src/lib/tools.mjs";
import { upstreamStatus } from "../src/lib/upstreams.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const paths = { repo };

test("tool profiles resolve catalog entries and report host compatibility", () => {
  const result = toolInventory({ paths, profile: "web" });
  assert.equal(result.profile.id, "web");
  assert.ok(result.tools.length > 5);
  assert.ok(result.tools.every((tool) => typeof tool.compatible === "boolean"));
});

test("tool plans preserve admission and licensing metadata", () => {
  const result = toolPlan("owasp-zap", { paths });
  assert.equal(result.openSource, true);
  assert.equal(result.approval, "no-mistakes");
  assert.match(result.upstream, /^https:\/\//);
});

test("tool discovery reads PATH directly without executing a locator or candidate", (t) => {
  if (process.platform === "win32") return t.skip("executable fixture targets the WSL/Linux control plane");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-tool-lookup-"));
  const helperCanary = path.join(root, "locator-ran");
  const candidateCanary = path.join(root, "candidate-ran");
  const fakeHelper = path.join(root, "which");
  const fakeCandidate = path.join(root, "nmap");
  const previousPath = process.env.PATH;
  const previousSecret = process.env.GATE_TOOL_LOOKUP_SECRET;

  fs.writeFileSync(
    fakeHelper,
    `#!/bin/sh\nprintf '%s' "$GATE_TOOL_LOOKUP_SECRET" > ${JSON.stringify(helperCanary)}\nprintf '%s\\n' ${JSON.stringify(fakeCandidate)}\n`,
    { mode: 0o700 }
  );
  fs.writeFileSync(
    fakeCandidate,
    `#!/bin/sh\nprintf '%s' "$GATE_TOOL_LOOKUP_SECRET" > ${JSON.stringify(candidateCanary)}\n`,
    { mode: 0o700 }
  );
  process.env.PATH = root;
  process.env.GATE_TOOL_LOOKUP_SECRET = "TOOL_LOOKUP_SECRET_CANARY";
  t.after(() => {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
    if (previousSecret === undefined) delete process.env.GATE_TOOL_LOOKUP_SECRET;
    else process.env.GATE_TOOL_LOOKUP_SECRET = previousSecret;
    fs.rmSync(root, { recursive: true, force: true });
  });

  const result = toolPlan("nmap", { paths });
  assert.equal(result.installed, true);
  assert.equal(result.executable, fakeCandidate);
  assert.equal(fs.existsSync(helperCanary), false);
  assert.equal(fs.existsSync(candidateCanary), false);
});

test("receipt-only upstream status is cheap while the default verifies installed content", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-upstream-status-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const paths = {
    repo,
    home: root,
    upstreams: path.join(root, "upstreams"),
    upstreamTools: path.join(root, "upstream-tools")
  };
  const lock = JSON.parse(fs.readFileSync(path.join(repo, "locks", "upstreams.lock.json"), "utf8"));
  const entry = lock.upstreams.find((candidate) => candidate.id === "gnhf");
  const directory = path.join(paths.upstreamTools, entry.id);
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, "install.json"), `${JSON.stringify({
    apiVersion: "gate.upstream-install/v2",
    id: entry.id,
    lane: "npm",
    package: entry.install.package,
    version: entry.version,
    integrity: entry.install.integrity,
    lockSha256: entry.install.lockSha256,
    verifiedAt: "2026-10-13T15:00:00.000Z"
  })}\n`, "utf8");

  const receiptOnly = upstreamStatus({ paths, verifyIntegrity: false }).find((item) => item.id === entry.id);
  assert.equal(receiptOnly.installedVersion, entry.version);
  assert.equal(receiptOnly.integrityState, "receipt-only");
  assert.equal(receiptOnly.installed, true);
  assert.equal(receiptOnly.packageReady, false);
  assert.equal(receiptOnly.ready, false);

  const verified = upstreamStatus({ paths }).find((item) => item.id === entry.id);
  assert.equal(verified.installedVersion, null);
  assert.equal(verified.integrityState, "invalid");
  assert.equal(verified.packageReady, false);
});
