import assert from "node:assert/strict";
import crypto from "node:crypto";
import dgram from "node:dgram";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  approveEngagement,
  attachPlan,
  checkEngagement,
  createEngagement,
  recordTechnicalReview
} from "../src/lib/engagements.mjs";
import {
  createManagedExecutionManifest,
  executeExecutionManifest,
  executionCapability,
  executionStatus
} from "../src/lib/executions.mjs";
import {
  prepareManagedAdapterInvocation,
  validateManagedAdapterOutput
} from "../src/lib/managed-adapters.mjs";
import { ensureRuntime, runtimePaths } from "../src/lib/paths.mjs";
import { canonicalSha256, currentRuntimePlatform } from "../src/lib/tool-runtimes.mjs";
import { toolPlan } from "../src/lib/tools.mjs";
import {
  addWorkflowEvidence,
  createWorkflowInstance,
  finishWorkflowPhase,
  startWorkflowPhase,
  stopWorkflow,
  workflowRuntimeInternals,
  workflowStatus
} from "../src/lib/workflow-runtime.mjs";

const sourceRepo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sourceWorkflow = JSON.parse(fs.readFileSync(
  path.join(sourceRepo, "config", "workflows", "pentest-e2e.json"),
  "utf8"
));
const platform = currentRuntimePlatform();
const executionLane = executionCapability();
const managedTest = executionLane.laneAvailable && new Set(["linux-x64", "linux-arm64"]).has(platform.key)
  ? test
  : test.skip;

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function writeExecutable(file, source) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `#!${process.execPath}\n${source}\n`, { mode: 0o700 });
  fs.chmodSync(file, 0o700);
  return sha256(fs.readFileSync(file));
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-managed-adapter-"));
  const contractRepo = path.join(root, "repo");
  fs.mkdirSync(contractRepo, { recursive: true });
  for (const directory of ["catalog", "config", "locks", "policies", "schemas", "templates"]) {
    fs.cpSync(path.join(sourceRepo, directory), path.join(contractRepo, directory), { recursive: true });
  }
  fs.mkdirSync(path.join(contractRepo, "src"), { recursive: true });
  fs.cpSync(path.join(sourceRepo, "src", "adapters"), path.join(contractRepo, "src", "adapters"), { recursive: true });

  const paths = runtimePaths({ home: path.join(root, "home"), repo: contractRepo });
  const executablePaths = {
    dnsx: path.join(paths.toolRuntimes, "dnsx", "bin", "dnsx"),
    httpx: path.join(paths.toolRuntimes, "httpx", "bin", "httpx")
  };
  const executableSha256 = {
    dnsx: writeExecutable(executablePaths.dnsx, [
      "const dgram = require('node:dgram');",
      "const args = process.argv.slice(2);",
      "const at = (name) => args[args.indexOf(name) + 1];",
      "const target = at('-l');",
      "const resolver = at('-resolver');",
      "const separator = resolver.lastIndexOf(':');",
      "const resolverHost = resolver.slice(0, separator);",
      "const resolverPort = Number(resolver.slice(separator + 1));",
      "const labels = target.split('.').map((label) => Buffer.concat([Buffer.from([Buffer.byteLength(label)]), Buffer.from(label)]));",
      "const qname = Buffer.concat([...labels, Buffer.from([0])]);",
      "const query = Buffer.alloc(12);",
      "query.writeUInt16BE(0x4741, 0);",
      "query.writeUInt16BE(0x0100, 2);",
      "query.writeUInt16BE(1, 4);",
      "const question = Buffer.concat([query, qname, Buffer.from([0, 1, 0, 1])]);",
      "const socket = dgram.createSocket('udp4');",
      "const timer = setTimeout(() => { console.error('DNS fixture timed out'); socket.close(); process.exitCode = 2; }, 2000);",
      "socket.once('message', (response) => {",
      "  clearTimeout(timer);",
      "  if (response.length < 16 || response.readUInt16BE(0) !== 0x4741) { socket.close(); process.exitCode = 3; return; }",
      "  const address = [...response.subarray(response.length - 4)].join('.');",
      "  process.stdout.write(JSON.stringify({host: target, a: [address], resolver}) + '\\n');",
      "  socket.close();",
      "});",
      "socket.send(question, resolverPort, resolverHost);"
    ].join("\n")),
    httpx: writeExecutable(executablePaths.httpx, [
      "const http = require('node:http');",
      "const args = process.argv.slice(2);",
      "const at = (name) => args[args.indexOf(name) + 1];",
      "const target = at('-u');",
      "const allowedIp = at('-allow');",
      "const hostHeader = at('-H').replace(/^Host:\\s*/i, '');",
      "const parsed = new URL(target);",
      "const dialHost = parsed.hostname.replace(/^\\[|\\]$/g, '');",
      "if (parsed.protocol !== 'http:' || at('-x') !== 'GET' || !args.includes('-nfs') || dialHost !== allowedIp) process.exit(9);",
      "const request = http.request({",
      "  hostname: dialHost,",
      "  port: parsed.port || 80,",
      "  path: `${parsed.pathname}${parsed.search}` ,",
      "  method: 'GET',",
      "  headers: { host: hostHeader }",
      "}, (response) => {",
      "  response.resume();",
      "  response.on('end', () => process.stdout.write(JSON.stringify({",
      "    input: target, url: target, host_ip: dialHost, status_code: response.statusCode",
      "  }) + '\\n'));",
      "});",
      "request.on('error', (error) => { console.error(error.message); process.exitCode = 2; });",
      "request.end();"
    ].join("\n"))
  };

  const lockFile = path.join(contractRepo, "locks", "tool-runtimes.lock.json");
  const lock = JSON.parse(fs.readFileSync(lockFile, "utf8"));
  const registryFile = path.join(contractRepo, "config", "managed-adapters.json");
  const registry = JSON.parse(fs.readFileSync(registryFile, "utf8"));
  for (const toolId of ["dnsx", "httpx"]) {
    const runtime = lock.runtimes.find((candidate) => candidate.toolId === toolId);
    const artifact = runtime.artifacts.find((candidate) => candidate.platform === platform.key);
    artifact.executableSha256 = executableSha256[toolId];
    const adapter = registry.adapters.find((candidate) => candidate.tool.id === toolId);
    adapter.tool.executableSha256[platform.key] = executableSha256[toolId];
    adapter.tool.lockEntrySha256 = canonicalSha256(runtime);
  }
  fs.writeFileSync(lockFile, `${JSON.stringify(lock, null, 2)}\n`);
  fs.writeFileSync(registryFile, `${JSON.stringify(registry, null, 2)}\n`);

  const runSmoke = (_executable, spec) => ({
    exitCode: 0,
    output: Buffer.from(`${spec.expectedOutputContains}\n`)
  });
  for (const toolId of ["dnsx", "httpx"]) {
    const runtime = lock.runtimes.find((candidate) => candidate.toolId === toolId);
    const artifact = runtime.artifacts.find((candidate) => candidate.platform === platform.key);
    const executable = executablePaths[toolId];
    const smokeOutput = runSmoke(executable, runtime.smoke).output;
    const completedAt = new Date().toISOString();
    const receipt = {
      apiVersion: "gate.tool-install/v1",
      id: runtime.id,
      toolId: runtime.toolId,
      provider: runtime.provider,
      version: runtime.version,
      platform: platform.key,
      lockEntrySha256: canonicalSha256(runtime),
      catalogEntrySha256: runtime.catalogEntrySha256,
      artifact: {
        assetId: artifact.assetId,
        url: artifact.url,
        size: artifact.size,
        sha256: artifact.sha256
      },
      executable: {
        relativePath: runtime.executable.relativePath,
        sha256: artifact.executableSha256,
        size: fs.statSync(executable).size
      },
      smoke: {
        specSha256: canonicalSha256(runtime.smoke),
        status: "passed",
        network: "none",
        sandbox: runtime.smoke.sandbox,
        exitCode: 0,
        outputSha256: sha256(smokeOutput),
        completedAt
      },
      installedAt: completedAt,
      authority: "none-installation-does-not-authorize-target-contact"
    };
    fs.writeFileSync(path.join(paths.toolRuntimes, toolId, "install.json"), `${JSON.stringify(receipt, null, 2)}\n`, {
      mode: 0o600
    });
  }
  ensureRuntime(paths);

  const verifyManagedTool = (toolId) => {
    const runtime = lock.runtimes.find((candidate) => candidate.toolId === toolId);
    const artifact = runtime.artifacts.find((candidate) => candidate.platform === platform.key);
    return {
      ok: true,
      verified: true,
      installed: true,
      executable: executablePaths[toolId],
      provenance: {
        provider: runtime.provider,
        version: runtime.version,
        platform: platform.key,
        lockEntrySha256: canonicalSha256(runtime),
        catalogEntrySha256: runtime.catalogEntrySha256,
        artifactSha256: artifact.sha256,
        executableSha256: executableSha256[toolId]
      },
      verificationEvidence: {
        current: true,
        currentBytesChecked: true,
        liveSmokeExecutedNow: true
      },
      reasons: []
    };
  };
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, contractRepo, paths, verifyManagedTool, runSmoke };
}

function approve(paths, root, { id, target, toolId }) {
  const plan = path.join(root, `${id}-plan.md`);
  fs.writeFileSync(plan, `# Plan\nObserve the exact local fixture target for ${id}.\n`, { mode: 0o600 });
  createEngagement({
    id,
    targets: [target],
    actions: ["observe"],
    tools: [toolId],
    environment: "host",
    maxMinutes: 5,
    maxRequests: 4,
    maxParallel: 1,
    maxRate: 2,
    maxTokens: 20_000,
    allowedDestinations: ["gate-home"]
  }, { paths });
  const planned = attachPlan(id, plan, { paths });
  recordTechnicalReview(id, {
    run: `no-mistakes/${id}`,
    headSha: "a".repeat(40),
    status: "passed"
  }, { paths });
  approveEngagement(id, { sha256: planned.plan.sha256, confirm: `APPROVE ${id}` }, { paths });

  const workflowId = `${id}-workflow`;
  createWorkflowInstance(workflowId, { engagementId: id }, { paths });
  for (const phaseId of ["authorization-and-roe", "target-and-architecture-map"]) {
    const phase = sourceWorkflow.phases.find((candidate) => candidate.id === phaseId);
    startWorkflowPhase(workflowId, {
      phaseId,
      ...(phaseId === "target-and-architecture-map" ? { sourcePhase: "authorization-and-roe" } : {})
    }, { paths });
    for (const evidence of phase.evidence.filter((candidate) => candidate.required)) {
      const file = path.join(root, `${id}-${phaseId}-${evidence.id}.txt`);
      fs.writeFileSync(file, `${evidence.id}: local managed-adapter fixture\n`, { mode: 0o600 });
      addWorkflowEvidence(workflowId, {
        phaseId,
        evidenceId: evidence.id,
        claimState: evidence.claimState,
        file
      }, { paths });
    }
    finishWorkflowPhase(workflowId, { phaseId, disposition: "tested" }, { paths });
  }

  const status = workflowStatus(workflowId, { paths });
  const phaseId = "active-surface-validation";
  const phase = sourceWorkflow.phases.find((candidate) => candidate.id === phaseId);
  const mapping = phase.toolMappings.find((candidate) => candidate.toolId === toolId);
  const authority = checkEngagement(id, {
    target,
    action: "observe",
    maxMinutes: 1,
    estimatedRequests: 1,
    maxParallel: 1,
    maxRatePerSecond: 1,
    maxTokens: 1_000,
    maxEvidenceBytes: 2 * 1024 * 1024
  }, { paths }).executionBinding;
  const admission = {
    $schema: "../../schemas/workflow-admission.schema.json",
    apiVersion: "gate.workflow-admission/v1",
    kind: "WorkflowAdmission",
    instanceId: workflowId,
    workflowDefinitionSha256: status.contract.sha256,
    phaseId,
    target,
    action: "observe",
    toolId,
    toolMappingSha256: workflowRuntimeInternals.canonicalDigest(mapping, "gate.workflow.tool-mapping.v1"),
    adapterConstraint: mapping.adapterConstraint,
    authority: {
      engagementId: authority.engagementId,
      planSha256: authority.planSha256,
      envelopeSha256: authority.envelopeSha256,
      receiptSha256: authority.receiptSha256,
      authorizationValidUntil: authority.authorizationValidUntil,
      checkedAt: new Date().toISOString()
    },
    envelope: {
      maxMinutes: 1,
      maxRequests: 1,
      maxRatePerSecond: 2,
      maxParallel: 1,
      maxInputTokens: 0,
      maxOutputTokens: 0,
      maxTotalTokens: 1_000,
      maxEvidenceBytes: 32 * 1024 * 1024,
      maxSpend: 0,
      controls: {
        wallTime: "measured-only",
        requests: "unavailable",
        rate: "unavailable",
        parallel: "unavailable",
        tokens: "unavailable",
        evidenceBytes: "enforced",
        spend: "unavailable"
      }
    },
    issuedAt: new Date(Date.now() - 1_000).toISOString(),
    expiresAt: authority.authorizationValidUntil
  };
  const admissionFile = path.join(root, `${id}-admission.json`);
  fs.writeFileSync(admissionFile, `${JSON.stringify(admission, null, 2)}\n`, { mode: 0o600 });
  const started = startWorkflowPhase(workflowId, {
    phaseId,
    sourcePhase: "target-and-architecture-map",
    admissionFile
  }, { paths });
  return {
    id,
    target,
    toolId,
    workflowId,
    phaseAttemptId: started.projection.activePhase.attemptId
  };
}

function managedInput(scope, adapterId, operation) {
  return {
    adapterId,
    workflowId: scope.workflowId,
    phaseAttemptId: scope.phaseAttemptId,
    target: scope.target,
    operation,
    maxMinutes: 1,
    estimatedRequests: 1,
    maxParallel: 1,
    maxRatePerSecond: 1,
    maxTokens: 1_000,
    maxEvidenceBytes: 2 * 1024 * 1024
  };
}

function manifestFile(paths, manifestId) {
  return path.join(paths.executionManifests, `${manifestId}.json`);
}

function evidenceFile(paths, reference) {
  return path.join(paths.evidence, reference.slice("private://evidence/".length));
}

async function listen(t, handler) {
  const server = http.createServer(handler);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return server.address().port;
}

async function listenDns(t, handler) {
  const server = dgram.createSocket("udp4");
  server.on("message", (message, remote) => handler(server, message, remote));
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.bind(0, "127.0.0.1", resolve);
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return server.address().port;
}

managedTest("managed adapter compilers are strict, deterministic, and expose no raw argv", (t) => {
  const { paths, verifyManagedTool } = fixture(t);
  const base = {
    workflowId: "compiler-workflow",
    phaseAttemptId: `wpa_${"0".repeat(32)}`,
    maxMinutes: 1,
    estimatedRequests: 1,
    maxParallel: 1,
    maxRatePerSecond: 2,
    maxTokens: 1_000,
    maxEvidenceBytes: 2 * 1024 * 1024
  };
  const dns = prepareManagedAdapterInvocation({
    ...base,
    adapterId: "dnsx-domain-observe",
    target: "fixture.example",
    operation: { kind: "dns-query", recordType: "A", resolver: "127.0.0.1:5353", timeoutSeconds: 5 }
  }, { paths, verifyManagedTool });
  assert.deepEqual(dns.compiled.argv, [
    "-l", "fixture.example", "-a", "-retry", "1", "-t", "1", "-rl", "2",
    "-timeout", "5s", "-resolver", "127.0.0.1:5353", "-json", "-omit-raw",
    "-silent", "-nc", "-disable-update-check", "-auth=false"
  ]);
  const httpPrepared = prepareManagedAdapterInvocation({
    ...base,
    adapterId: "httpx-url-observe",
    target: "http://fixture.invalid/probe?x=1",
    operation: {
      kind: "http-get", method: "GET", allowedIp: "127.0.0.1", timeoutSeconds: 5, maxResponseBytes: 4096
    }
  }, { paths, verifyManagedTool });
  assert.deepEqual(httpPrepared.compiled.argv, [
    "-u", "http://127.0.0.1/probe?x=1", "-x", "GET", "-allow", "127.0.0.1",
    "-H", "Host: fixture.invalid",
    "-nfs", "-no-stdin", "-t", "1", "-rl", "2", "-retries", "0", "-timeout", "5",
    "-rstr", "4096", "-rsts", "4096", "-json", "-omit-body", "-status-code",
    "-content-length", "-content-type", "-location", "-method", "-ip", "-silent", "-nc",
    "-disable-update-check", "-auth=false", "-random-agent=false", "-cdn=false"
  ]);
  const httpsPrepared = prepareManagedAdapterInvocation({
    ...base,
    adapterId: "httpx-url-observe",
    target: "https://fixture.invalid:444/probe",
    operation: {
      kind: "http-get", method: "GET", allowedIp: "127.0.0.1", timeoutSeconds: 5, maxResponseBytes: 4096
    }
  }, { paths, verifyManagedTool });
  assert.equal(httpsPrepared.compiled.argv[1], "https://127.0.0.1:444/probe");
  assert.equal(httpsPrepared.compiled.argv[httpsPrepared.compiled.argv.indexOf("-H") + 1], "Host: fixture.invalid:444");
  assert.equal(httpsPrepared.compiled.argv[httpsPrepared.compiled.argv.indexOf("-sni-name") + 1], "fixture.invalid");
  const ipv6Prepared = prepareManagedAdapterInvocation({
    ...base,
    adapterId: "httpx-url-observe",
    target: "https://[::1]:444/probe",
    operation: {
      kind: "http-get", method: "GET", allowedIp: "::1", timeoutSeconds: 5, maxResponseBytes: 4096
    }
  }, { paths, verifyManagedTool });
  assert.equal(ipv6Prepared.compiled.argv[1], "https://[::1]:444/probe");
  assert.equal(ipv6Prepared.compiled.argv[ipv6Prepared.compiled.argv.indexOf("-H") + 1], "Host: [::1]:444");
  assert.equal(ipv6Prepared.compiled.argv.includes("-sni-name"), false);

  assert.throws(
    () => prepareManagedAdapterInvocation({
      ...base,
      adapterId: "dnsx-domain-observe",
      target: "fixture.example",
      argv: ["-l", "another.example"],
      operation: { kind: "dns-query", recordType: "A", resolver: "127.0.0.1:53", timeoutSeconds: 5 }
    }, { paths, verifyManagedTool }),
    /do not accept raw argv/u
  );
  assert.throws(
    () => prepareManagedAdapterInvocation({
      ...base,
      adapterId: "dnsx-domain-observe",
      target: "first.example,second.example",
      operation: { kind: "dns-query", recordType: "A", resolver: "127.0.0.1:53", timeoutSeconds: 5 }
    }, { paths, verifyManagedTool }),
    /one exact DNS domain name/u
  );
  assert.throws(
    () => prepareManagedAdapterInvocation({
      ...base,
      adapterId: "httpx-url-observe",
      target: "http://fixture.invalid/",
      operation: {
        kind: "http-get", method: "GET", allowedIp: "127.0.0.1", timeoutSeconds: 5,
        maxResponseBytes: 4096, headers: { authorization: "never" }
      }
    }, { paths, verifyManagedTool }),
    /must contain exactly/u
  );
  assert.throws(
    () => prepareManagedAdapterInvocation({
      ...base,
      adapterId: "httpx-url-observe",
      target: "http://127.0.0.2/probe",
      operation: {
        kind: "http-get", method: "GET", allowedIp: "127.0.0.1", timeoutSeconds: 5,
        maxResponseBytes: 4096
      }
    }, { paths, verifyManagedTool }),
    /must equal the literal IP in the approved URL/u
  );
});

managedTest("tool readiness exposes only verified reviewed adapter capability and fails closed on registry drift", (t) => {
  const { contractRepo, paths, runSmoke } = fixture(t);
  for (const [toolId, adapterId] of [
    ["dnsx", "dnsx-domain-observe"],
    ["httpx", "httpx-url-observe"]
  ]) {
    const planned = toolPlan(toolId, { paths, runSmoke });
    assert.equal(planned.readiness, "adapter-ready");
    assert.equal(planned.adapterConfigured, true);
    assert.equal(planned.adapterReady, true);
    assert.equal(planned.executionAvailable, true);
    assert.equal(planned.broadCapabilityReady, false);
    assert.equal(planned.managedRuntimeAdmissionRequired, false);
    assert.deepEqual(planned.executionModes, ["reviewed-managed-adapter"]);
    const status = planned.managedAdapterStatus.find((candidate) => candidate.id === adapterId);
    assert.equal(status?.ready, true);
    assert.equal(status?.integrityChecked, true);
    assert.equal(status?.registrySha256?.length, 64);
  }

  const registryFile = path.join(contractRepo, "config", "managed-adapters.json");
  const drifted = JSON.parse(fs.readFileSync(registryFile, "utf8"));
  drifted.adapters.find((candidate) => candidate.tool.id === "httpx").compiler.sourceSha256 = "0".repeat(64);
  fs.writeFileSync(registryFile, `${JSON.stringify(drifted, null, 2)}\n`);
  const blocked = toolPlan("httpx", { paths, runSmoke });
  assert.equal(blocked.adapterConfigured, false);
  assert.equal(blocked.adapterReady, false);
  assert.equal(blocked.executionAvailable, false);
  assert.equal(blocked.readiness, "managed-verified-admission-required");
  assert.equal(blocked.managedRuntimeAdmissionRequired, true);
});

managedTest("DNSx adapter emits one exact A query to the explicit loopback resolver", async (t) => {
  const { root, paths, verifyManagedTool } = fixture(t);
  const queries = [];
  const resolverPort = await listenDns(t, (server, message, remote) => {
    let offset = 12;
    const labels = [];
    while (offset < message.length && message[offset] !== 0) {
      const length = message[offset];
      labels.push(message.subarray(offset + 1, offset + 1 + length).toString("ascii"));
      offset += length + 1;
    }
    offset += 1;
    const type = message.readUInt16BE(offset);
    const recordClass = message.readUInt16BE(offset + 2);
    const questionEnd = offset + 4;
    queries.push({
      name: labels.join("."),
      type,
      recordClass,
      remoteAddress: remote.address
    });

    const header = Buffer.alloc(12);
    message.copy(header, 0, 0, 2);
    header.writeUInt16BE(0x8180, 2);
    header.writeUInt16BE(1, 4);
    header.writeUInt16BE(1, 6);
    const answer = Buffer.alloc(16);
    answer.writeUInt16BE(0xc00c, 0);
    answer.writeUInt16BE(1, 2);
    answer.writeUInt16BE(1, 4);
    answer.writeUInt32BE(30, 6);
    answer.writeUInt16BE(4, 10);
    Buffer.from([127, 0, 0, 42]).copy(answer, 12);
    const response = Buffer.concat([header, message.subarray(12, questionEnd), answer]);
    server.send(response, remote.port, remote.address);
  });
  const target = "fixture.example";
  const resolver = `127.0.0.1:${resolverPort}`;
  const scope = approve(paths, root, { id: "managed-dns", target, toolId: "dnsx" });
  const created = createManagedExecutionManifest(scope.id, managedInput(scope, "dnsx-domain-observe", {
    kind: "dns-query",
    recordType: "A",
    resolver,
    timeoutSeconds: 5
  }), { paths, verifyManagedTool });
  assert.deepEqual(created.operation.argv.slice(-6), [
    "-json", "-omit-raw", "-silent", "-nc", "-disable-update-check", "-auth=false"
  ]);
  assert.equal(created.operation.argv[created.operation.argv.indexOf("-resolver") + 1], resolver);

  const result = await executeExecutionManifest(scope.id, {
    manifestId: created.manifestId,
    confirm: created.confirmationRequired
  }, { paths, verifyManagedTool, pollIntervalMs: 20, terminationGraceMs: 50 });
  assert.equal(result.status, "succeeded");
  assert.deepEqual(result.adapterOutput, { ok: true, status: "observed", reason: null, records: 1 });
  assert.deepEqual(queries, [{
    name: target,
    type: 1,
    recordClass: 1,
    remoteAddress: "127.0.0.1"
  }]);
  const observed = JSON.parse(fs.readFileSync(evidenceFile(paths, result.evidence.stdout.ref), "utf8"));
  assert.deepEqual(observed, { host: target, a: ["127.0.0.42"], resolver });
});

managedTest("HTTPx adapter dials only the approved IP while preserving the approved Host header", async (t) => {
  const { root, paths, verifyManagedTool } = fixture(t);
  const requests = [];
  const port = await listen(t, (request, response) => {
    requests.push({ method: request.method, url: request.url, host: request.headers.host });
    response.writeHead(302, { location: "/redirected" });
    response.end("do not follow");
  });
  const target = `http://fixture.invalid:${port}/probe?x=1`;
  const scope = approve(paths, root, { id: "managed-http", target, toolId: "httpx" });
  const created = createManagedExecutionManifest(scope.id, managedInput(scope, "httpx-url-observe", {
    kind: "http-get",
    method: "GET",
    allowedIp: "127.0.0.1",
    timeoutSeconds: 5,
    maxResponseBytes: 4096
  }), { paths, verifyManagedTool });
  assert.equal(created.operation.adapter.id, "httpx-url-observe");
  const persisted = JSON.parse(fs.readFileSync(manifestFile(paths, created.manifestId), "utf8"));
  assert.equal(persisted.runtime.mode, "reviewed-managed-adapter");
  assert.equal(created.operation.argv.includes("-fr"), false);
  assert.equal(created.operation.argv[created.operation.targetArgIndex], `http://127.0.0.1:${port}/probe?x=1`);
  assert.equal(created.operation.adapter.controls.approvedUrl, target);
  assert.equal(created.operation.adapter.controls.socketDestinationPinned, true);

  const result = await executeExecutionManifest(scope.id, {
    manifestId: created.manifestId,
    confirm: created.confirmationRequired
  }, { paths, verifyManagedTool, pollIntervalMs: 20, terminationGraceMs: 50 });
  assert.equal(result.status, "succeeded");
  assert.deepEqual(result.adapterOutput, { ok: true, status: "observed", reason: null, records: 1 });
  assert.deepEqual(requests, [{
    method: "GET",
    url: "/probe?x=1",
    host: `fixture.invalid:${port}`
  }]);
  for (const ref of [result.evidence.stdout.ref, result.evidence.stderr.ref, result.evidence.resultRef]) {
    assert.equal(fs.statSync(evidenceFile(paths, ref)).mode & 0o777, 0o600);
  }
});

managedTest("HTTPx adapter does not fall back from an unreachable approved IP to the URL hostname", async (t) => {
  const { root, paths, verifyManagedTool } = fixture(t);
  let requests = 0;
  const port = await listen(t, (_request, response) => {
    requests += 1;
    response.end("unexpected");
  });
  const target = `http://localhost:${port}/probe`;
  const scope = approve(paths, root, { id: "managed-http-filter", target, toolId: "httpx" });
  const created = createManagedExecutionManifest(scope.id, managedInput(scope, "httpx-url-observe", {
    kind: "http-get",
    method: "GET",
    allowedIp: "127.0.0.2",
    timeoutSeconds: 5,
    maxResponseBytes: 4096
  }), { paths, verifyManagedTool });

  const result = await executeExecutionManifest(scope.id, {
    manifestId: created.manifestId,
    confirm: created.confirmationRequired
  }, { paths, verifyManagedTool, pollIntervalMs: 20, terminationGraceMs: 50 });
  assert.equal(result.status, "failed");
  assert.equal(result.adapterOutput, undefined);
  assert.equal(requests, 0);
});

managedTest("workflow stop invalidates a managed manifest before target contact", async (t) => {
  const { root, paths, verifyManagedTool } = fixture(t);
  let requests = 0;
  const port = await listen(t, (_request, response) => {
    requests += 1;
    response.end("unexpected");
  });
  const target = `http://stopped.invalid:${port}/probe`;
  const scope = approve(paths, root, { id: "managed-stop", target, toolId: "httpx" });
  const created = createManagedExecutionManifest(scope.id, managedInput(scope, "httpx-url-observe", {
    kind: "http-get", method: "GET", allowedIp: "127.0.0.1", timeoutSeconds: 5, maxResponseBytes: 4096
  }), { paths, verifyManagedTool });
  stopWorkflow(scope.workflowId, { condition: "operator-stop", reason: "fixture stop before contact" }, { paths });
  await assert.rejects(
    executeExecutionManifest(scope.id, {
      manifestId: created.manifestId,
      confirm: created.confirmationRequired
    }, { paths, verifyManagedTool }),
    /workflow status stopped cannot authorize execution/u
  );
  assert.equal(requests, 0);
});

managedTest("managed runtime re-verification failure blocks launch before target contact", async (t) => {
  const { root, paths, verifyManagedTool } = fixture(t);
  let requests = 0;
  const port = await listen(t, (_request, response) => {
    requests += 1;
    response.end("unexpected");
  });
  const target = `http://invalidated.invalid:${port}/probe`;
  const scope = approve(paths, root, { id: "managed-runtime", target, toolId: "httpx" });
  const created = createManagedExecutionManifest(scope.id, managedInput(scope, "httpx-url-observe", {
    kind: "http-get", method: "GET", allowedIp: "127.0.0.1", timeoutSeconds: 5, maxResponseBytes: 4096
  }), { paths, verifyManagedTool });
  const invalidVerifier = (toolId) => ({
    ...verifyManagedTool(toolId),
    ok: false,
    verified: false,
    reasons: ["fixture runtime invalidated"]
  });
  await assert.rejects(
    executeExecutionManifest(scope.id, {
      manifestId: created.manifestId,
      confirm: created.confirmationRequired
    }, { paths, verifyManagedTool: invalidVerifier }),
    /fixture runtime invalidated/u
  );
  assert.equal(requests, 0);
  assert.equal(executionStatus({ paths }).counts.blocked, 1);
});

managedTest("empty managed output is indeterminate and manifest tampering fails closed", async (t) => {
  const { root, paths, verifyManagedTool } = fixture(t);
  let requests = 0;
  const port = await listen(t, (_request, response) => {
    requests += 1;
    response.end("unexpected");
  });
  const target = `http://tampered.invalid:${port}/probe`;
  const scope = approve(paths, root, { id: "managed-tamper", target, toolId: "httpx" });
  const created = createManagedExecutionManifest(scope.id, managedInput(scope, "httpx-url-observe", {
    kind: "http-get", method: "GET", allowedIp: "127.0.0.1", timeoutSeconds: 5, maxResponseBytes: 4096
  }), { paths, verifyManagedTool });
  const file = manifestFile(paths, created.manifestId);
  const manifest = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.deepEqual(validateManagedAdapterOutput(manifest, Buffer.alloc(0), { paths }), {
    ok: false,
    status: "indeterminate",
    reason: "indeterminate-output",
    records: 0
  });

  manifest.operation.adapter.operation.allowedIp = "127.0.0.2";
  fs.writeFileSync(file, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
  await assert.rejects(
    executeExecutionManifest(scope.id, {
      manifestId: created.manifestId,
      confirm: created.confirmationRequired
    }, { paths, verifyManagedTool }),
    /manifest digest|deterministic argv binding changed|operation/u
  );
  assert.equal(requests, 0);
});
