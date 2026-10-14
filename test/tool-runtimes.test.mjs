import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { runtimePaths } from "../src/lib/paths.mjs";
import {
  canonicalSha256,
  catalogEntrySha256,
  installManagedTool,
  managedToolPlan,
  prefetchManagedTool,
  readToolRuntimeLock,
  runManagedToolOperation,
  verifyManagedTool
} from "../src/lib/tool-runtimes.mjs";
import { toolInventory, toolPlan } from "../src/lib/tools.mjs";
import { validateDocument } from "../src/lib/schema.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const platform = { key: "linux-x64", host: "linux", os: "linux", architecture: "x64", wsl: false };

function digest(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function fixtureTool(id = "fixture-tool", command = "fixture") {
  return {
    id,
    name: id === "fixture-tool" ? "Fixture Tool" : "Unmanaged Fixture",
    category: "osint",
    riskClass: "P1",
    approval: "declared-source",
    license: "MIT",
    openSource: true,
    upstream: `https://github.com/example/${id}`,
    command,
    installLanes: ["pinned-release"],
    supportedHosts: ["linux", "wsl2"],
    privileges: ["user"],
    notes: "A harmless local test fixture for managed runtime boundary verification."
  };
}

function writeArchive(root, files, options = {}) {
  const content = path.join(root, `content-${crypto.randomBytes(3).toString("hex")}`);
  fs.mkdirSync(content);
  for (const [name, value] of Object.entries(files)) {
    const target = path.join(content, name);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    if (value?.symlink) fs.symlinkSync(value.symlink, target);
    else fs.writeFileSync(target, value, { mode: name === "fixture" ? 0o700 : 0o600 });
  }
  const archive = path.join(root, `fixture-${crypto.randomBytes(3).toString("hex")}.tar.gz`);
  const result = spawnSync("/usr/bin/tar", ["-czf", archive, ...Object.keys(files)], {
    cwd: content,
    encoding: "utf8",
    shell: false
  });
  assert.equal(result.status, 0, result.stderr);
  if (options.transformTraversal) {
    const traversal = path.join(root, `traversal-${crypto.randomBytes(3).toString("hex")}.tar.gz`);
    const transformed = spawnSync(
      "/usr/bin/tar",
      ["-czf", traversal, "--transform=s,^,../,", ...Object.keys(files)],
      { cwd: content, encoding: "utf8", shell: false }
    );
    assert.equal(transformed.status, 0, transformed.stderr);
    return traversal;
  }
  return archive;
}

function writeZipArchive(root, files) {
  const content = path.join(root, `zip-content-${crypto.randomBytes(3).toString("hex")}`);
  fs.mkdirSync(content);
  for (const [name, value] of Object.entries(files)) {
    const target = path.join(content, name);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    if (value?.symlink) fs.symlinkSync(value.symlink, target);
    else fs.writeFileSync(target, value, { mode: name === "fixture" ? 0o700 : 0o600 });
  }
  const archive = path.join(root, `fixture-${crypto.randomBytes(3).toString("hex")}.zip`);
  const result = spawnSync("/usr/bin/zip", ["-q", "--symlinks", archive, ...Object.keys(files)], {
    cwd: content,
    encoding: "utf8",
    shell: false
  });
  assert.equal(result.status, 0, result.stderr);
  return archive;
}

function createFixture(t, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-tool-runtime-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const repo = path.join(root, "repo");
  const home = path.join(root, "home");
  fs.mkdirSync(path.join(repo, "schemas"), { recursive: true });
  fs.mkdirSync(path.join(repo, "catalog"), { recursive: true });
  fs.mkdirSync(path.join(repo, "locks"), { recursive: true });
  fs.mkdirSync(path.join(repo, "config", "profiles"), { recursive: true });
  for (const name of ["tool-runtime-lock.schema.json", "tool-install-receipt.schema.json", "event.schema.json"]) {
    fs.copyFileSync(path.join(repository, "schemas", name), path.join(repo, "schemas", name));
  }
  const executableBytes = Buffer.from("#!/bin/sh\nprintf 'fixture 1.2.3\\n'\n");
  const files = options.files || { fixture: executableBytes };
  const archive = options.archiveFormat === "zip"
    ? writeZipArchive(root, files)
    : writeArchive(root, files, options);
  const archiveBytes = fs.readFileSync(archive);
  const tool = fixtureTool();
  const extraTools = options.extraTools || [];
  const catalog = {
    $schema: "../schemas/tool-catalog.schema.json",
    apiVersion: "gate.dev/catalog/v1",
    kind: "SecurityToolCatalog",
    policy: {},
    tools: [tool, ...extraTools]
  };
  fs.writeFileSync(path.join(repo, "catalog", "security-tools.json"), `${JSON.stringify(catalog, null, 2)}\n`);
  const entry = {
    id: tool.id,
    toolId: tool.id,
    catalogEntrySha256: catalogEntrySha256(tool),
    version: "1.2.3",
    source: {
      repository: tool.upstream,
      commit: "1".repeat(40),
      tag: "v1.2.3"
    },
    releaseEvidence: {
      provider: "github",
      releaseId: 123,
      releaseApiUrl: `https://api.github.com/repos/example/${tool.id}/releases/123`,
      immutableObserved: false,
      sourceCommitVerification: "unverified",
      checksumManifest: {
        assetId: 124,
        assetApiUrl: `https://api.github.com/repos/example/${tool.id}/releases/assets/124`,
        url: `${tool.upstream}/releases/download/v1.2.3/checksums.txt`,
        size: 64,
        sha256: "2".repeat(64)
      }
    },
    provider: "verified-release",
    executable: { name: tool.command, relativePath: `bin/${tool.command}` },
    artifacts: [{
      platform: platform.key,
      assetId: 125,
      assetApiUrl: `https://api.github.com/repos/example/${tool.id}/releases/assets/125`,
      url: `${tool.upstream}/releases/download/v1.2.3/${path.basename(archive)}`,
      size: archiveBytes.length,
      sha256: digest(archiveBytes),
      archiveType: options.archiveFormat === "zip" ? "zip" : "tar.gz",
      entries: options.lockedEntries || Object.keys(files),
      executablePath: "fixture",
      executableSha256: digest(executableBytes)
    }],
    smoke: {
      argv: ["--version"],
      expectedOutputContains: "fixture 1.2.3",
      timeoutMs: 1000,
      maxOutputBytes: 4096,
      maxProcesses: 4,
      network: "none",
      sandbox: "bubblewrap-prlimit-v1"
    },
    effects: {
      networkDuringInstall: true,
      hostWrites: false,
      adminRequired: false,
      services: false,
      devices: false
    }
  };
  const lock = {
    $schema: "../schemas/tool-runtime-lock.schema.json",
    apiVersion: "gate.dev/tool-runtime-lock/v1",
    kind: "ToolRuntimeLock",
    updatePolicy: "reviewed-pull-request",
    runtimes: [entry]
  };
  fs.writeFileSync(path.join(repo, "locks", "tool-runtimes.lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
  const paths = runtimePaths({ repo, home });
  const downloadArtifact = async (_artifact, destination) => {
    fs.copyFileSync(archive, destination, fs.constants.COPYFILE_EXCL);
  };
  const runSmoke = (_executable, spec) => {
    assert.deepEqual(spec.argv, ["--version"]);
    return { exitCode: 0, output: Buffer.from("fixture 1.2.3\n") };
  };
  return { root, repo, home, paths, archive, executableBytes, tool, entry, lock, catalog, downloadArtifact, runSmoke };
}

test("managed install binds reviewed bytes, uses a private receipt, and grants no target authority", async (t) => {
  const fixture = createFixture(t);
  const installed = await installManagedTool("fixture-tool", {
    paths: fixture.paths,
    platform,
    downloadArtifact: fixture.downloadArtifact,
    runSmoke: fixture.runSmoke
  });
  assert.equal(installed.ok, true);
  assert.equal(installed.verified, true);
  assert.equal(installed.installationGrantsAuthority, false);
  assert.equal(installed.targetAuthority, "engagement-receipt-required");
  assert.equal(fs.existsSync(path.join(fixture.home, "engagements", "fixture-tool.json")), false);

  const receiptFile = path.join(fixture.paths.toolRuntimes, "fixture-tool", "install.json");
  const receipt = JSON.parse(fs.readFileSync(receiptFile, "utf8"));
  assert.equal(receipt.authority, "none-installation-does-not-authorize-target-contact");
  assert.equal(receipt.lockEntrySha256, canonicalSha256(fixture.entry));
  assert.equal(fs.statSync(receiptFile).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.dirname(receiptFile)).mode & 0o777, 0o700);
});

test("a PATH namesake cannot replace a verified managed executable", async (t) => {
  if (process.platform !== "linux") return t.skip("fixture uses the Linux managed execution lane");
  const fixture = createFixture(t);
  await installManagedTool("fixture-tool", {
    paths: fixture.paths,
    platform,
    downloadArtifact: fixture.downloadArtifact,
    runSmoke: fixture.runSmoke
  });
  const fakeBin = path.join(fixture.root, "fake-bin");
  const canary = path.join(fixture.root, "namesake-ran");
  fs.mkdirSync(fakeBin);
  fs.writeFileSync(path.join(fakeBin, "fixture"), `#!/bin/sh\nprintf bad > ${JSON.stringify(canary)}\n`, { mode: 0o700 });

  let planSmokeCalls = 0;
  const plan = toolPlan("fixture-tool", {
    paths: fixture.paths,
    environment: { PATH: fakeBin },
    platform,
    runSmoke: (executable, spec) => {
      planSmokeCalls += 1;
      return fixture.runSmoke(executable, spec);
    }
  });
  assert.equal(planSmokeCalls, 1);
  assert.equal(plan.managedRuntimeVerified, true);
  assert.equal(plan.knownGoodProvenance, true);
  assert.equal(plan.genericLaneEligible, false);
  assert.equal(plan.executionAvailable, false);
  assert.equal(plan.managedRuntimeAdmissionRequired, true);
  assert.ok(plan.runtimePlan.unresolved.includes("workflow-phase-admission-unavailable"));
  assert.equal(plan.executable, path.join(fixture.paths.toolRuntimes, "fixture-tool", "bin", "fixture"));
  assert.notEqual(plan.executable, path.join(fakeBin, "fixture"));
  assert.equal(fs.existsSync(canary), false);
});

test("forged receipts and executable drift never admit a runtime", async (t) => {
  const fixture = createFixture(t);
  await installManagedTool("fixture-tool", {
    paths: fixture.paths,
    platform,
    downloadArtifact: fixture.downloadArtifact,
    runSmoke: fixture.runSmoke
  });
  const directory = path.join(fixture.paths.toolRuntimes, "fixture-tool");
  const receiptFile = path.join(directory, "install.json");
  const receipt = JSON.parse(fs.readFileSync(receiptFile, "utf8"));
  receipt.lockEntrySha256 = "0".repeat(64);
  fs.writeFileSync(receiptFile, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
  let result = verifyManagedTool("fixture-tool", { paths: fixture.paths, platform, runSmoke: fixture.runSmoke });
  assert.equal(result.verified, false);
  assert.equal(result.executable, null);
  assert.match(result.reasons.join(" "), /receipt lockEntrySha256 mismatch/);

  receipt.lockEntrySha256 = canonicalSha256(fixture.entry);
  fs.writeFileSync(receiptFile, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
  const executable = path.join(directory, "bin", "fixture");
  if (process.platform !== "win32") {
    fs.chmodSync(path.join(directory, "bin"), 0o777);
    result = verifyManagedTool("fixture-tool", { paths: fixture.paths, platform, runSmoke: fixture.runSmoke });
    assert.equal(result.verified, false);
    assert.match(result.reasons.join(" "), /permissions are not owner-only/);
    fs.chmodSync(path.join(directory, "bin"), 0o700);

    fs.chmodSync(executable, 0o777);
    result = verifyManagedTool("fixture-tool", { paths: fixture.paths, platform, runSmoke: fixture.runSmoke });
    assert.equal(result.verified, false);
    assert.match(result.reasons.join(" "), /permissions differ from the reviewed mode/);
    fs.chmodSync(executable, 0o700);
  }
  fs.appendFileSync(executable, "tampered");
  result = verifyManagedTool("fixture-tool", { paths: fixture.paths, platform, runSmoke: fixture.runSmoke });
  assert.equal(result.verified, false);
  assert.equal(result.executable, null);
  assert.match(result.reasons.join(" "), /differs from the reviewed lock/);
});

test("catalog and lock drift invalidate readiness", async (t) => {
  const fixture = createFixture(t);
  await installManagedTool("fixture-tool", {
    paths: fixture.paths,
    platform,
    downloadArtifact: fixture.downloadArtifact,
    runSmoke: fixture.runSmoke
  });
  fixture.catalog.tools[0].notes += " Changed after review.";
  fs.writeFileSync(
    path.join(fixture.repo, "catalog", "security-tools.json"),
    `${JSON.stringify(fixture.catalog, null, 2)}\n`
  );
  const result = verifyManagedTool("fixture-tool", { paths: fixture.paths, platform, runSmoke: fixture.runSmoke });
  assert.equal(result.ok, false);
  assert.equal(result.state, "invalid-lock");
  assert.match(result.reasons.join(" "), /catalog digest mismatch/);
});

test("failed smoke and failed prepublication work preserve the previous install", async (t) => {
  const fixture = createFixture(t);
  await installManagedTool("fixture-tool", {
    paths: fixture.paths,
    platform,
    downloadArtifact: fixture.downloadArtifact,
    runSmoke: fixture.runSmoke
  });
  const executable = path.join(fixture.paths.toolRuntimes, "fixture-tool", "bin", "fixture");
  const before = digest(fs.readFileSync(executable));
  await assert.rejects(
    installManagedTool("fixture-tool", {
      paths: fixture.paths,
      platform,
      downloadArtifact: fixture.downloadArtifact,
      runSmoke: () => { throw new Error("injected smoke failure"); }
    }),
    /injected smoke failure/
  );
  assert.equal(digest(fs.readFileSync(executable)), before);

  await assert.rejects(
    installManagedTool("fixture-tool", {
      paths: fixture.paths,
      platform,
      downloadArtifact: fixture.downloadArtifact,
      runSmoke: fixture.runSmoke,
      beforePublish: () => { throw new Error("injected publication failure"); }
    }),
    /injected publication failure/
  );
  assert.equal(digest(fs.readFileSync(executable)), before);

  let smokeCalls = 0;
  await assert.rejects(
    installManagedTool("fixture-tool", {
      paths: fixture.paths,
      platform,
      downloadArtifact: fixture.downloadArtifact,
      runSmoke: (candidate, spec) => {
        smokeCalls += 1;
        if (smokeCalls === 2) throw new Error("injected post-publication verification failure");
        return fixture.runSmoke(candidate, spec);
      }
    }),
    /published managed tool failed verification/
  );
  assert.equal(digest(fs.readFileSync(executable)), before);
  assert.equal(verifyManagedTool("fixture-tool", { paths: fixture.paths, platform, runSmoke: fixture.runSmoke }).ok, true);
});

test("an active mutation lock blocks overlapping installs", async (t) => {
  const fixture = createFixture(t);
  await prefetchManagedTool("fixture-tool", {
    paths: fixture.paths,
    platform,
    downloadArtifact: fixture.downloadArtifact
  });
  const lock = path.join(fixture.paths.toolRuntimeStaging, ".fixture-tool.mutation-lock");
  fs.mkdirSync(lock, { mode: 0o700 });
  t.after(() => fs.rmSync(lock, { recursive: true, force: true }));
  await assert.rejects(
    installManagedTool("fixture-tool", {
      paths: fixture.paths,
      platform,
      downloadArtifact: fixture.downloadArtifact,
      runSmoke: fixture.runSmoke
    }),
    /mutation is already active/
  );
  assert.equal(fs.existsSync(path.join(fixture.paths.toolRuntimes, "fixture-tool")), false);
});

test("a definitively stale mutation lock is reclaimed after its owner grace period", async (t) => {
  const fixture = createFixture(t);
  await prefetchManagedTool("fixture-tool", {
    paths: fixture.paths,
    platform,
    downloadArtifact: fixture.downloadArtifact
  });
  const lock = path.join(fixture.paths.toolRuntimeStaging, ".fixture-tool.mutation-lock");
  fs.mkdirSync(lock, { mode: 0o700 });
  const old = new Date(Date.now() - 120_000);
  fs.utimesSync(lock, old, old);
  const installed = await installManagedTool("fixture-tool", {
    paths: fixture.paths,
    platform,
    downloadArtifact: fixture.downloadArtifact,
    runSmoke: fixture.runSmoke
  });
  assert.equal(installed.ok, true);
  assert.equal(fs.existsSync(lock), false);
});

test("a tampered content-addressed cache is rejected and never installed", async (t) => {
  const fixture = createFixture(t);
  await prefetchManagedTool("fixture-tool", {
    paths: fixture.paths,
    platform,
    downloadArtifact: fixture.downloadArtifact
  });
  const cached = path.join(fixture.paths.toolArtifactCache, fixture.entry.artifacts[0].sha256);
  fs.appendFileSync(cached, "tampered");
  await assert.rejects(
    installManagedTool("fixture-tool", {
      paths: fixture.paths,
      platform,
      downloadArtifact: fixture.downloadArtifact,
      runSmoke: fixture.runSmoke
    }),
    /artifact size mismatch/
  );
  assert.equal(fs.existsSync(path.join(fixture.paths.toolRuntimes, "fixture-tool")), false);
});

test("archives with extra files or links are rejected before publication", async (t) => {
  const extra = createFixture(t, {
    files: {
      fixture: Buffer.from("#!/bin/sh\nprintf 'fixture 1.2.3\\n'\n"),
      unexpected: Buffer.from("extra")
    },
    lockedEntries: ["fixture"]
  });
  await assert.rejects(
    installManagedTool("fixture-tool", {
      paths: extra.paths,
      platform,
      downloadArtifact: extra.downloadArtifact,
      runSmoke: extra.runSmoke
    }),
    /entries differ from the reviewed lock/
  );
  assert.equal(fs.existsSync(path.join(extra.paths.toolRuntimes, "fixture-tool")), false);

  const linked = createFixture(t, {
    files: { fixture: { symlink: "elsewhere" } },
    lockedEntries: ["fixture"]
  });
  await assert.rejects(
    installManagedTool("fixture-tool", {
      paths: linked.paths,
      platform,
      downloadArtifact: linked.downloadArtifact,
      runSmoke: linked.runSmoke
    }),
    /unsafe paths or entry types/
  );
  assert.equal(fs.existsSync(path.join(linked.paths.toolRuntimes, "fixture-tool")), false);
});

test("ZIP releases use exact central-directory paths and reject symbolic links", async (t) => {
  const fixture = createFixture(t, { archiveFormat: "zip" });
  const installed = await installManagedTool("fixture-tool", {
    paths: fixture.paths,
    platform,
    downloadArtifact: fixture.downloadArtifact,
    runSmoke: fixture.runSmoke
  });
  assert.equal(installed.ok, true);
  assert.equal(installed.verified, true);

  const linked = createFixture(t, {
    archiveFormat: "zip",
    files: { fixture: { symlink: "elsewhere" } },
    lockedEntries: ["fixture"]
  });
  await assert.rejects(
    installManagedTool("fixture-tool", {
      paths: linked.paths,
      platform,
      downloadArtifact: linked.downloadArtifact,
      runSmoke: linked.runSmoke
    }),
    /link or special entry/
  );
});

test("floating refs, unsafe paths, missing hashes, and case collisions fail the reviewed lock", (t) => {
  const fixture = createFixture(t);
  const mutations = [];
  const floating = structuredClone(fixture.lock);
  floating.runtimes[0].source.tag = "latest";
  mutations.push(floating);
  const missingHash = structuredClone(fixture.lock);
  delete missingHash.runtimes[0].artifacts[0].sha256;
  mutations.push(missingHash);
  const traversal = structuredClone(fixture.lock);
  traversal.runtimes[0].artifacts[0].entries = ["../fixture"];
  traversal.runtimes[0].artifacts[0].executablePath = "../fixture";
  mutations.push(traversal);
  const collision = structuredClone(fixture.lock);
  collision.runtimes[0].artifacts[0].entries = ["fixture", "FIXTURE"];
  mutations.push(collision);

  for (const value of mutations.slice(0, 3)) {
    assert.equal(validateDocument(value, "tool-runtime-lock.schema.json", { paths: fixture.paths }).ok, false);
  }
  fs.writeFileSync(
    path.join(fixture.repo, "locks", "tool-runtimes.lock.json"),
    `${JSON.stringify(collision, null, 2)}\n`
  );
  assert.throws(() => readToolRuntimeLock({ paths: fixture.paths }), /unsafe or ambiguous/);

  const wrongArchiveType = structuredClone(fixture.lock);
  wrongArchiveType.runtimes[0].artifacts[0].archiveType = "zip";
  fs.writeFileSync(
    path.join(fixture.repo, "locks", "tool-runtimes.lock.json"),
    `${JSON.stringify(wrongArchiveType, null, 2)}\n`
  );
  assert.throws(() => readToolRuntimeLock({ paths: fixture.paths }), /archive type does not match/);
});

test("profile operations return partial structured results for unmanaged catalog tools", async (t) => {
  const unmanaged = fixtureTool("unmanaged-tool", "unmanaged");
  const fixture = createFixture(t, { extraTools: [unmanaged] });
  fs.writeFileSync(path.join(fixture.repo, "config", "profiles", "core.json"), `${JSON.stringify({
    apiVersion: "gate.dev/profile/v1",
    kind: "SecurityToolProfile",
    id: "core",
    catalog: "../../catalog/security-tools.json",
    description: "Fixture profile with one locked and one unresolved tool.",
    maxRiskClass: "P1",
    toolIds: ["fixture-tool", "unmanaged-tool"]
  }, null, 2)}\n`);

  const result = await runManagedToolOperation("prefetch", {
    paths: fixture.paths,
    profile: "core",
    platform,
    downloadArtifact: fixture.downloadArtifact
  });
  assert.equal(result.ok, false);
  assert.deepEqual(result.counts, { selected: 2, succeeded: 1, unresolved: 1, installed: 0, verified: 0 });
  assert.equal(result.results[0].state, "cached");
  assert.equal(result.results[1].state, "unresolved");
  assert.deepEqual(result.results[1].reasons, ["reviewed-runtime-lock-unavailable"]);

  const malformed = JSON.parse(fs.readFileSync(path.join(fixture.repo, "config", "profiles", "core.json"), "utf8"));
  malformed.toolIds.push("fixture-tool");
  fs.writeFileSync(
    path.join(fixture.repo, "config", "profiles", "core.json"),
    `${JSON.stringify(malformed, null, 2)}\n`
  );
  await assert.rejects(
    runManagedToolOperation("verify", { paths: fixture.paths, profile: "core", platform }),
    /invalid tool profile/
  );
});

test("tool list performs no process execution or network access", (t) => {
  if (process.platform === "win32") return t.skip("canary executable targets POSIX hosts");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-tool-list-cheap-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const canary = path.join(root, "httpx-ran");
  fs.writeFileSync(path.join(root, "httpx"), `#!/bin/sh\nprintf ran > ${JSON.stringify(canary)}\n`, { mode: 0o700 });
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = async () => { fetchCalls += 1; throw new Error("network forbidden"); };
  t.after(() => { globalThis.fetch = originalFetch; });

  const inventory = toolInventory({
    paths: { repo: repository },
    environment: { PATH: root },
    verifyManagedIntegrity: false
  });
  assert.equal(inventory.count, 126);
  assert.equal(inventory.verificationMode, "receipt-only");
  assert.equal(fetchCalls, 0);
  assert.equal(fs.existsSync(canary), false);
});

test("tool plan exposes exact install effects without granting authority", (t) => {
  const fixture = createFixture(t);
  const plan = managedToolPlan("fixture-tool", { paths: fixture.paths, platform });
  assert.equal(plan.installationGrantsAuthority, false);
  assert.equal(plan.targetAuthority, "engagement-receipt-required");
  assert.equal(plan.executionAdmitted, false);
  assert.deepEqual(plan.effects.smoke.argv, ["bin/fixture", "--version"]);
  assert.equal(plan.effects.smoke.network, "none");
  assert.equal(plan.effects.administrator, false);
  assert.equal(plan.effects.services, false);
  assert.equal(plan.effects.devices, false);

  const macPlan = managedToolPlan("ffuf", {
    paths: runtimePaths({ repo: repository, home: path.join(fixture.root, "mac-home") }),
    platform: { key: "darwin-x64", host: "macos", os: "darwin", architecture: "x64", wsl: false }
  });
  assert.equal(macPlan.prefetchSupported, true);
  assert.equal(macPlan.installSupported, false);
  assert.ok(macPlan.unresolved.includes("zero-egress-smoke-sandbox-unavailable"));
  assert.match(macPlan.nextAction, /prefetch/);
});
