import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { runtimePaths } from "../src/lib/paths.mjs";
import { validateDocument } from "../src/lib/schema.mjs";
import { toolInventory, toolPlan } from "../src/lib/tools.mjs";
import { upstreamStatus } from "../src/lib/upstreams.mjs";
import { validateRepository } from "../src/lib/validation.mjs";

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
  assert.ok(["candidate", "identity-unverified"].includes(result.readiness));
  assert.equal(result.versionVerified, false);
  assert.equal(result.integrityVerified, false);
  assert.equal(result.knownGoodProvenance, false);
  assert.equal(result.adapterReady, false);
  assert.equal(result.commandIdentity.genericLaneAdmission, "reviewed-admission");
  assert.equal(result.identityAdmissionRequired, true);
  assert.equal(result.genericLaneEligible, false);
  assert.equal(result.executionAvailable, false);
  assert.equal(result.executionMode, null);
});

test("tool discovery reads PATH directly without executing a locator or candidate", (t) => {
  if (process.platform === "win32") return t.skip("executable fixture targets the WSL/Linux control plane");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-tool-lookup-"));
  const helperCanary = path.join(root, "locator-ran");
  const candidateCanary = path.join(root, "candidate-ran");
  const fakeHelper = path.join(root, "which");
  const fakeCandidate = path.join(root, "gitleaks");
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

  const result = toolPlan("gitleaks", { paths });
  assert.equal(result.installed, true);
  assert.equal(result.executable, fakeCandidate);
  assert.equal(result.readiness, "discovered");
  assert.equal(result.knownGoodProvenance, false);
  assert.equal(result.adapterReady, false);
  assert.equal(result.genericLaneEligible, true);
  assert.equal(result.executionMode, "supervised-generic");
  assert.equal(result.executionAvailable, true);
  assert.equal(fs.existsSync(helperCanary), false);
  assert.equal(fs.existsSync(candidateCanary), false);
});

test("missing command identity fails closed even when a matching command is on PATH", (t) => {
  if (process.platform === "win32") return t.skip("executable fixture targets the WSL/Linux control plane");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-tool-default-admission-"));
  const canary = path.join(root, "nmap-ran");
  const fakeCandidate = path.join(root, "nmap");
  fs.writeFileSync(fakeCandidate, `#!/bin/sh\nprintf blocked > ${JSON.stringify(canary)}\n`, { mode: 0o700 });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const result = toolPlan("nmap", {
    paths,
    environment: { PATH: root },
    verifyManagedIntegrity: false
  });
  assert.equal(result.commandCandidate, fakeCandidate);
  assert.equal(result.commandIdentity.genericLaneAdmission, "reviewed-admission");
  assert.match(result.commandIdentity.reason, /no explicit reviewed PATH-discovery admission/i);
  assert.equal(result.installed, false);
  assert.equal(result.executable, null);
  assert.equal(result.readiness, "identity-unverified");
  assert.equal(result.identityAdmissionRequired, true);
  assert.equal(result.genericLaneEligible, false);
  assert.equal(result.executionAvailable, false);
  assert.equal(fs.existsSync(canary), false);
});

test("an ambiguous httpx command is evidence of a candidate, not product identity", (t) => {
  if (process.platform === "win32") return t.skip("executable fixture targets the WSL/Linux control plane");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-httpx-collision-"));
  const canary = path.join(root, "python-httpx-ran");
  const fakeHttpx = path.join(root, "httpx");
  fs.writeFileSync(fakeHttpx, `#!/bin/sh\nprintf collision > ${JSON.stringify(canary)}\n`, { mode: 0o700 });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const result = toolPlan("httpx", {
    paths,
    environment: { PATH: root },
    verifyManagedIntegrity: false
  });
  assert.equal(result.commandCandidate, fakeHttpx);
  assert.equal(result.installed, false);
  assert.equal(result.executable, null);
  assert.equal(result.readiness, "identity-unverified");
  assert.equal(result.identityAdmissionRequired, true);
  assert.equal(result.genericLaneEligible, false);
  assert.equal(result.broadCapabilityReady, false);
  assert.equal(result.executionAvailable, false);
  assert.equal(result.executionMode, null);
  assert.equal(fs.existsSync(canary), false);
});

test("catalog schema keeps ambiguous names and narrow managed adapters out of PATH admission", () => {
  const catalog = JSON.parse(fs.readFileSync(path.join(repo, "catalog", "security-tools.json"), "utf8"));
  const unsafe = structuredClone(catalog);
  const httpx = unsafe.tools.find((tool) => tool.id === "httpx");
  httpx.commandIdentity.genericLaneAdmission = "path-discovery";
  const ambiguous = validateDocument(unsafe, "tool-catalog.schema.json", { paths });
  assert.equal(ambiguous.ok, false);
  assert.ok(ambiguous.errors.some((error) => error.includes("must be equal to constant")));

  const broadAdapter = structuredClone(catalog);
  broadAdapter.tools.find((tool) => tool.id === "rea").commandIdentity.genericLaneAdmission = "path-discovery";
  const managed = validateDocument(broadAdapter, "tool-catalog.schema.json", { paths });
  assert.equal(managed.ok, false);
  assert.ok(managed.errors.some((error) => error.includes("must be equal to constant")));

  const highImpact = structuredClone(catalog);
  highImpact.tools.find((tool) => tool.id === "nmap").commandIdentity = {
    pathDiscovery: "command-name",
    genericLaneAdmission: "path-discovery",
    reason: "An invalid test mutation attempts to admit a high-impact command by PATH name."
  };
  assert.equal(validateDocument(highImpact, "tool-catalog.schema.json", { paths }).ok, false);

  const externalData = structuredClone(catalog);
  externalData.tools.find((tool) => tool.id === "capa").commandIdentity = {
    pathDiscovery: "command-name",
    genericLaneAdmission: "path-discovery",
    reason: "An invalid test mutation attempts to bypass external data dependency admission."
  };
  assert.equal(validateDocument(externalData, "tool-catalog.schema.json", { paths }).ok, false);

  const missingIdentity = structuredClone(catalog);
  delete missingIdentity.tools.find((tool) => tool.id === "httpx").commandIdentity;
  assert.equal(validateDocument(missingIdentity, "tool-catalog.schema.json", { paths }).ok, false);

  const missingAdapter = structuredClone(catalog);
  delete missingAdapter.tools.find((tool) => tool.id === "rea").managedAdapters;
  assert.equal(validateDocument(missingAdapter, "tool-catalog.schema.json", { paths }).ok, false);
});

test("PATH admission is an explicit narrow allowlist and service stacks remain blocked", (t) => {
  if (process.platform === "win32") return t.skip("executable fixtures target the WSL/Linux control plane");
  const catalog = JSON.parse(fs.readFileSync(path.join(repo, "catalog", "security-tools.json"), "utf8"));
  const allowed = [
    "apktool",
    "bandit",
    "bulk-extractor",
    "exiftool",
    "gitleaks",
    "gosec",
    "hcxtools",
    "jadx",
    "plaso",
    "sleuthkit"
  ];
  const admitted = catalog.tools
    .filter((tool) => tool.commandIdentity?.genericLaneAdmission === "path-discovery")
    .map((tool) => tool.id)
    .sort();
  assert.deepEqual(admitted, [...allowed].sort());
  assert.ok(catalog.tools.every((tool) => (
    tool.commandIdentity?.pathDiscovery !== "ambiguous-command-name" ||
    tool.commandIdentity.genericLaneAdmission === "reviewed-admission"
  )));

  const blocked = [
    "arkime",
    "bloodhound-ce",
    "greenbone-openvas",
    "impacket",
    "kali-toolbox",
    "mobsf",
    "sliver",
    "timesketch"
  ];
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-service-stack-admission-"));
  const canaries = [];
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const id of blocked) {
    const tool = catalog.tools.find((candidate) => candidate.id === id);
    const executable = path.join(root, tool.command);
    const canary = path.join(root, `${id}-ran`);
    canaries.push(canary);
    fs.writeFileSync(executable, `#!/bin/sh\nprintf blocked > ${JSON.stringify(canary)}\n`, { mode: 0o700 });
    const result = toolPlan(id, {
      paths,
      environment: { PATH: root },
      verifyManagedIntegrity: false
    });
    assert.equal(result.commandCandidate, executable, id);
    assert.equal(result.readiness, "identity-unverified", id);
    assert.equal(result.executable, null, id);
    assert.equal(result.genericLaneEligible, false, id);
    assert.equal(result.executionAvailable, false, id);
  }
  assert.ok(canaries.every((canary) => !fs.existsSync(canary)));
});

test("catalog risk ceilings and approvals match broad tool surfaces", () => {
  const catalog = JSON.parse(fs.readFileSync(path.join(repo, "catalog", "security-tools.json"), "utf8"));
  const byId = new Map(catalog.tools.map((tool) => [tool.id, tool]));
  const expected = {
    "searchsploit": ["P0", "automatic"],
    "cartography": ["A1", "engagement"],
    "cloudfox": ["A1", "engagement"],
    "scoutsuite": ["A1", "engagement"],
    "kube-bench": ["A1", "engagement"],
    "kubeaudit": ["A1", "engagement"],
    "kubescape": ["A1", "engagement"],
    "syft": ["A1", "engagement"],
    "trivy": ["A1", "engagement"],
    "grype": ["A1", "engagement"],
    "naabu": ["A2", "no-mistakes"],
    "rustscan": ["A2", "no-mistakes"],
    "testssl-sh": ["A2", "no-mistakes"],
    "falco": ["A2", "no-mistakes"],
    "trufflehog": ["A2", "no-mistakes"],
    "nmap": ["A3", "operator-receipt"],
    "nuclei": ["A3", "operator-receipt"],
    "scapy": ["A3", "operator-receipt"],
    "hackrf-tools": ["A3", "operator-receipt"],
    "gnuradio": ["A3", "operator-receipt"],
    "proxmark3": ["A3", "operator-receipt"],
    "killerbee": ["A3", "operator-receipt"]
  };
  for (const [id, [riskClass, approval]] of Object.entries(expected)) {
    assert.equal(byId.get(id)?.riskClass, riskClass, id);
    assert.equal(byId.get(id)?.approval, approval, id);
  }
});

test("profile risk ceilings fail closed in inventory and repository validation", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-profile-risk-ceiling-"));
  const catalogDirectory = path.join(root, "catalog");
  const profileDirectory = path.join(root, "config", "profiles");
  fs.mkdirSync(catalogDirectory, { recursive: true });
  fs.mkdirSync(profileDirectory, { recursive: true });
  fs.copyFileSync(
    path.join(repo, "catalog", "security-tools.json"),
    path.join(catalogDirectory, "security-tools.json")
  );
  fs.writeFileSync(path.join(profileDirectory, "risky.json"), `${JSON.stringify({
    apiVersion: "gate.dev/profile/v1",
    kind: "SecurityToolProfile",
    id: "risky",
    catalog: "../../catalog/security-tools.json",
    description: "A regression fixture that must reject Nmap above the P1 ceiling.",
    maxRiskClass: "P1",
    toolIds: ["nmap"]
  }, null, 2)}\n`);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  assert.throws(
    () => toolInventory({ paths: { repo: root }, profile: "risky", environment: { PATH: "" } }),
    /tool profile risky exceeds maxRiskClass P1: nmap is A3/
  );

  const validation = validateRepository({ paths: { repo: root } });
  const profileCheck = validation.checks.find((check) => check.name === "profile:risky");
  assert.equal(profileCheck?.ok, false);
  assert.equal(profileCheck?.detail, "tools exceed P1: nmap (A3)");

  fs.writeFileSync(path.join(profileDirectory, "risky.json"), `${JSON.stringify({
    apiVersion: "gate.dev/profile/v1",
    kind: "SecurityToolProfile",
    id: "renamed",
    catalog: "../../catalog/security-tools.json",
    description: "A regression fixture whose id must match its filename.",
    maxRiskClass: "P1",
    toolIds: ["apktool"]
  }, null, 2)}\n`);

  assert.throws(
    () => toolInventory({ paths: { repo: root }, profile: "risky", environment: { PATH: "" } }),
    /tool profile identity mismatch: risky/
  );
  const identityValidation = validateRepository({ paths: { repo: root } });
  const identityCheck = identityValidation.checks.find((check) => check.name === "profile:risky");
  assert.equal(identityCheck?.ok, false);
  assert.equal(identityCheck?.detail, "profile id renamed does not match filename risky");
});

test("external data dependencies are admission requirements rather than readiness claims", () => {
  const catalog = JSON.parse(fs.readFileSync(path.join(repo, "catalog", "security-tools.json"), "utf8"));
  const withData = catalog.tools.filter((tool) => tool.dataDependencies?.length);
  assert.ok(withData.length >= 10);
  for (const tool of withData) {
    assert.notEqual(tool.commandIdentity?.genericLaneAdmission, "path-discovery", tool.id);
    const ids = tool.dataDependencies.map((dependency) => dependency.id);
    assert.equal(new Set(ids).size, ids.length, tool.id);
    const plan = toolPlan(tool.id, { paths, environment: { PATH: "" }, verifyManagedIntegrity: false });
    assert.equal(plan.dataDependencyAdmissionRequired, true, tool.id);
    assert.equal(plan.dataDependencyReadiness, "admission-required", tool.id);
    assert.equal(plan.executionAvailable, false, tool.id);
  }
});

test("the pentest profile covers every workflow tool and keeps Kali environment-only", () => {
  const catalog = JSON.parse(fs.readFileSync(path.join(repo, "catalog", "security-tools.json"), "utf8"));
  const profile = JSON.parse(fs.readFileSync(path.join(repo, "config", "profiles", "pentest.json"), "utf8"));
  const workflow = JSON.parse(fs.readFileSync(path.join(repo, "config", "workflows", "pentest-e2e.json"), "utf8"));
  const mapped = new Set(workflow.phases.flatMap((phase) => phase.toolMappings.map((mapping) => mapping.toolId)));
  const expectedExecutable = catalog.tools.filter((tool) => tool.id !== "kali-toolbox").map((tool) => tool.id);
  assert.deepEqual([...mapped].sort(), [...expectedExecutable].sort());
  assert.deepEqual([...profile.toolIds].sort(), [...expectedExecutable].sort());
  assert.equal(profile.toolIds.includes("kali-toolbox"), false);
  assert.equal(workflow.environments.some((environment) => environment.toolId === "kali-toolbox"), true);
});

test("AI red-team candidates have reviewed CLI metadata and stay candidate-only", () => {
  const catalog = JSON.parse(fs.readFileSync(path.join(repo, "catalog", "security-tools.json"), "utf8"));
  const expected = new Map([
    ["garak", ["garak", "Apache-2.0"]],
    ["inspect-ai", ["inspect", "MIT"]],
    ["promptfoo", ["promptfoo", "MIT"]],
    ["pyrit", ["pyrit_scan", "MIT"]]
  ]);
  for (const [id, [command, license]] of expected) {
    const tool = catalog.tools.find((candidate) => candidate.id === id);
    assert.equal(tool?.category, "ai-systems", id);
    assert.equal(tool?.command, command, id);
    assert.equal(tool?.license, license, id);
    assert.equal(tool?.riskClass, "A2", id);
    assert.equal(tool?.approval, "no-mistakes", id);
    assert.equal(tool?.commandIdentity.genericLaneAdmission, "reviewed-admission", id);
  }
  assert.equal(
    catalog.tools.find((candidate) => candidate.id === "pyrit")?.upstream,
    "https://github.com/microsoft/PyRIT"
  );
});

for (const host of ["linux", "wsl2"]) {
  test(`REA receipt projection stays cheap and full planning admits only the fixed adapter on ${host}`, (t) => {
    if (process.platform !== "linux") return t.skip("the reviewed REA adapter requires Linux or WSL2");
    const originalDistro = process.env.WSL_DISTRO_NAME;
    if (host === "wsl2") process.env.WSL_DISTRO_NAME = "GATE-test";
    else delete process.env.WSL_DISTRO_NAME;
    t.mock.method(os, "release", () => host === "wsl2" ? "6.6.0-microsoft-standard-WSL2" : "6.6.0");
    t.after(() => {
      if (originalDistro === undefined) delete process.env.WSL_DISTRO_NAME;
      else process.env.WSL_DISTRO_NAME = originalDistro;
    });
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-rea-tool-plan-"));
    const upstreamTools = path.join(root, "upstream-tools");
    const directory = path.join(upstreamTools, "rea-stable");
    const bin = path.join(directory, "node_modules", ".bin");
    const managedEntrypoint = path.join(directory, "node_modules", "rea-agents", "scripts", "rea.mjs");
    const pathBin = path.join(root, "path-bin");
    const pathCanary = path.join(root, "path-rea-ran");
    const sandboxCanary = path.join(root, "bwrap-ran");
    const managedWrapper = path.join(bin, "rea");
    const pathRea = path.join(pathBin, "rea");
    const fakeBwrap = path.join(pathBin, "bwrap");
    fs.mkdirSync(bin, { recursive: true });
    fs.mkdirSync(path.dirname(managedEntrypoint), { recursive: true });
    fs.mkdirSync(pathBin, { recursive: true });
    fs.writeFileSync(managedEntrypoint, "#!/usr/bin/env node\n", { mode: 0o700 });
    fs.symlinkSync("../rea-agents/scripts/rea.mjs", managedWrapper);
    fs.writeFileSync(pathRea, `#!/bin/sh\nprintf path > ${JSON.stringify(pathCanary)}\n`, { mode: 0o700 });
    fs.writeFileSync(fakeBwrap, `#!/bin/sh\nprintf sandbox > ${JSON.stringify(sandboxCanary)}\n`, { mode: 0o700 });
    const lock = JSON.parse(fs.readFileSync(path.join(repo, "locks", "upstreams.lock.json"), "utf8"));
    const entry = lock.upstreams.find((candidate) => candidate.id === "rea-stable");
    fs.writeFileSync(path.join(directory, "install.json"), `${JSON.stringify({
      apiVersion: "gate.upstream-install/v2",
      id: entry.id,
      lane: "npm",
      package: entry.install.package,
      version: entry.version,
      integrity: entry.install.integrity,
      lockSha256: entry.install.lockSha256,
      verifiedAt: "2026-10-14T10:00:00.000Z"
    })}\n`, { mode: 0o600 });
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const runtime = { repo, home: root, upstreamTools };
    let resolveCalls = 0;

    const inventory = toolInventory({
      paths: runtime,
      category: "reverse-engineering",
      environment: { PATH: pathBin },
      resolveUpstreamBinary() {
        resolveCalls += 1;
        throw new Error("inventory must not perform full managed verification");
      },
      resolveAdapterCapability() {
        return { available: true, reason: null };
      }
    });
    const projected = inventory.tools.find((tool) => tool.id === "rea");
    assert.equal(resolveCalls, 0);
    assert.equal(projected.installed, true);
    assert.equal(projected.readiness, "managed-receipt");
    assert.equal(projected.integrityVerified, false);
    assert.equal(projected.adapterReady, false);
    assert.equal(projected.executable, null);
    assert.equal(projected.commandCandidate, pathRea);
    assert.equal(projected.genericLaneEligible, false);
    assert.equal(projected.executionAvailable, false);

    const planned = toolPlan("rea", {
      paths: runtime,
      environment: { PATH: pathBin },
      resolveUpstreamBinary(id, name) {
        resolveCalls += 1;
        assert.equal(id, "rea-stable");
        assert.equal(name, "rea");
        return { id, name, executable: managedWrapper, directory };
      },
      resolveAdapterCapability() {
        return { available: true, reason: null };
      }
    });
    assert.equal(resolveCalls, 1);
    assert.equal(planned.installed, true);
    assert.equal(planned.executable, managedEntrypoint);
    assert.equal(planned.readiness, "adapter-ready");
    assert.equal(planned.versionVerified, true);
    assert.equal(planned.integrityVerified, true);
    assert.equal(planned.knownGoodProvenance, true);
    assert.equal(planned.adapterReady, true);
    assert.equal(planned.genericLaneEligible, false);
    assert.equal(planned.broadCapabilityReady, false);
    assert.deepEqual(planned.executionModes, ["offline-static-pe-resources"]);
    assert.equal(planned.executionMode, "offline-static-pe-resources");
    assert.equal(planned.executionAvailable, true);
    assert.equal(planned.managedAdapterStatus[0].upstreamVerified, true);
    assert.equal(planned.managedAdapterStatus[0].entrypoint, path.join(repo, "src", "adapters", "rea-pe-resources.mjs"));
    assert.equal(fs.existsSync(pathCanary), false);
    assert.equal(fs.existsSync(sandboxCanary), false);

    const failedVerification = toolPlan("rea", {
      paths: runtime,
      environment: { PATH: pathBin },
      resolveUpstreamBinary() {
        throw new Error("tampered managed tree");
      },
      resolveAdapterCapability() {
        return { available: true, reason: null };
      }
    });
    assert.equal(failedVerification.readiness, "managed-receipt");
    assert.equal(failedVerification.integrityVerified, false);
    assert.equal(failedVerification.adapterReady, false);
    assert.equal(failedVerification.genericLaneEligible, false);
    assert.equal(failedVerification.executionAvailable, false);
    assert.equal(failedVerification.executable, null);
  });
}

test("REA receipt projection rejects symlinked state and upstream roots outside GATE_HOME", (t) => {
  if (process.platform !== "linux") return t.skip("no-follow fixtures target the Linux control plane");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-rea-receipt-safety-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const lock = JSON.parse(fs.readFileSync(path.join(repo, "locks", "upstreams.lock.json"), "utf8"));
  const entry = lock.upstreams.find((candidate) => candidate.id === "rea-stable");
  const receipt = `${JSON.stringify({
    apiVersion: "gate.upstream-install/v2",
    id: entry.id,
    lane: "npm",
    package: entry.install.package,
    version: entry.version,
    integrity: entry.install.integrity,
    lockSha256: entry.install.lockSha256,
    verifiedAt: "2026-10-14T10:00:00.000Z"
  })}\n`;

  function populate(upstreamTools, scenario, options = {}) {
    const directory = path.join(upstreamTools, "rea-stable");
    const entrypoint = path.join(directory, "node_modules", "rea-agents", "scripts", "rea.mjs");
    fs.mkdirSync(path.dirname(entrypoint), { recursive: true, mode: 0o700 });
    if (options.symlinkEntrypoint) {
      const outside = path.join(scenario, "outside-rea.mjs");
      fs.writeFileSync(outside, "#!/usr/bin/env node\n", { mode: 0o700 });
      fs.symlinkSync(outside, entrypoint);
    } else {
      fs.writeFileSync(entrypoint, "#!/usr/bin/env node\n", { mode: 0o700 });
    }
    const receiptFile = path.join(directory, "install.json");
    if (options.symlinkReceipt) {
      const outside = path.join(scenario, "outside-install.json");
      fs.writeFileSync(outside, receipt, { mode: 0o600 });
      fs.symlinkSync(outside, receiptFile);
    } else {
      fs.writeFileSync(receiptFile, receipt, { mode: 0o600 });
    }
  }

  function projected(pathsForScenario) {
    const inventory = toolInventory({
      paths: { repo, ...pathsForScenario },
      category: "reverse-engineering",
      environment: { PATH: "" },
      resolveUpstreamBinary() {
        throw new Error("cheap inventory must not resolve a managed executable");
      },
      resolveAdapterCapability() {
        return { available: true, reason: null };
      }
    });
    return inventory.tools.find((tool) => tool.id === "rea");
  }

  const receiptCase = path.join(root, "receipt-link");
  const receiptHome = path.join(receiptCase, "home");
  const receiptTools = path.join(receiptHome, "upstream-tools");
  fs.mkdirSync(receiptTools, { recursive: true, mode: 0o700 });
  populate(receiptTools, receiptCase, { symlinkReceipt: true });

  const executableCase = path.join(root, "entrypoint-link");
  const executableHome = path.join(executableCase, "home");
  const executableTools = path.join(executableHome, "upstream-tools");
  fs.mkdirSync(executableTools, { recursive: true, mode: 0o700 });
  populate(executableTools, executableCase, { symlinkEntrypoint: true });

  const escapedCase = path.join(root, "escaped-root");
  const escapedHome = path.join(escapedCase, "home");
  const escapedTools = path.join(escapedCase, "outside", "upstream-tools");
  fs.mkdirSync(escapedHome, { recursive: true, mode: 0o700 });
  fs.mkdirSync(escapedTools, { recursive: true, mode: 0o700 });
  populate(escapedTools, escapedCase);

  const rootLinkCase = path.join(root, "root-link");
  const rootLinkHome = path.join(rootLinkCase, "home");
  const realTools = path.join(rootLinkCase, "outside", "upstream-tools");
  const linkedTools = path.join(rootLinkHome, "upstream-tools");
  fs.mkdirSync(rootLinkHome, { recursive: true, mode: 0o700 });
  fs.mkdirSync(realTools, { recursive: true, mode: 0o700 });
  populate(realTools, rootLinkCase);
  fs.symlinkSync(realTools, linkedTools);

  for (const [name, result] of [
    ["symlinked receipt", projected({ home: receiptHome, upstreamTools: receiptTools })],
    ["symlinked entrypoint", projected({ home: executableHome, upstreamTools: executableTools })],
    ["escaped root", projected({ home: escapedHome, upstreamTools: escapedTools })],
    ["symlinked root", projected({ home: rootLinkHome, upstreamTools: linkedTools })]
  ]) {
    assert.equal(result.installed, false, name);
    assert.equal(result.managedAdapterStatus[0].receiptPresent, false, name);
    assert.equal(result.integrityVerified, false, name);
    assert.equal(result.adapterReady, false, name);
    assert.equal(result.executionAvailable, false, name);
  }
});

test("receipt-only upstream status is cheap while the default verifies installed content", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-upstream-status-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const paths = runtimePaths({ home: root, repo });
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
