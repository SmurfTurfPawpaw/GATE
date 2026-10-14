import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
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
  recordTechnicalReview,
  revokeEngagement
} from "../src/lib/engagements.mjs";
import {
  createExecutionManifest,
  executeExecutionManifest,
  executionCapability,
  executionInternals,
  executionStatus,
  reconcileExecution,
  requestExecutionStop
} from "../src/lib/executions.mjs";
import { runtimePaths } from "../src/lib/paths.mjs";
import { validateDocument } from "../src/lib/schema.mjs";
import {
  addWorkflowEvidence,
  cancelWorkflowExecution,
  createWorkflowInstance,
  finishWorkflowPhase,
  startWorkflowPhase,
  workflowRuntimeInternals,
  workflowStatus
} from "../src/lib/workflow-runtime.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const gate = path.join(repo, "bin", "gate.mjs");
const workflowDefinition = JSON.parse(fs.readFileSync(path.join(repo, "config", "workflows", "pentest-e2e.json"), "utf8"));

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-execution-"));
  const paths = runtimePaths({ home: path.join(root, "home"), repo });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, paths };
}

function requireLane(t) {
  const capability = executionCapability();
  if (!capability.laneAvailable) t.skip(`supervised execution unavailable: ${capability.reason}`);
}

function approve(paths, root, options = {}) {
  const id = options.id || "execution-test";
  const target = options.target || "127.0.0.1";
  const action = options.action || "scan";
  const toolId = "dnsx";
  const plan = path.join(root, `${id}.md`);
  fs.writeFileSync(plan, `# Plan\nBounded fixture execution for ${id}.\n`);
  createEngagement({
    id,
    targets: [target],
    actions: [action],
    tools: [toolId],
    environment: options.environment || "host",
    maxMinutes: 5,
    maxRequests: 20,
    maxParallel: 2,
    maxRate: 10,
    maxTokens: 20_000,
    allowedDestinations: options.allowedDestinations
  }, { paths });
  const planned = attachPlan(id, plan, { paths });
  recordTechnicalReview(id, {
    run: `no-mistakes/${id}`,
    headSha: "a".repeat(40),
    status: "passed"
  }, { paths });
  approveEngagement(id, { sha256: planned.plan.sha256, confirm: `APPROVE ${id}` }, { paths });
  if (options.workflow === false) {
    return {
      id,
      target,
      action,
      toolId,
      workflowId: `${id}-workflow`,
      phaseAttemptId: `wpa_${"0".repeat(32)}`
    };
  }

  const workflowId = `${id}-workflow`;
  createWorkflowInstance(workflowId, { engagementId: id }, { paths });
  for (const phaseId of ["authorization-and-roe", "target-and-architecture-map"]) {
    const phase = workflowDefinition.phases.find((candidate) => candidate.id === phaseId);
    startWorkflowPhase(workflowId, {
      phaseId,
      sourcePhase: phaseId === "target-and-architecture-map" ? "authorization-and-roe" : undefined
    }, { paths });
    for (const evidence of phase.evidence.filter((record) => record.required)) {
      const file = path.join(root, `${id}-${phaseId}-${evidence.id}.txt`);
      fs.writeFileSync(file, `${evidence.id}: execution fixture evidence\n`, { mode: 0o600 });
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
  assert.equal(status.ok, true);
  const phaseId = "active-surface-validation";
  const phase = workflowDefinition.phases.find((candidate) => candidate.id === phaseId);
  const mapping = phase.toolMappings.find((candidate) => candidate.toolId === toolId);
  const authority = checkEngagement(id, {
    target,
    action,
    maxMinutes: 5,
    estimatedRequests: 20,
    maxParallel: 2,
    maxRatePerSecond: 10,
    maxTokens: 20_000
  }, { paths }).executionBinding;
  const admission = {
    $schema: "../../schemas/workflow-admission.schema.json",
    apiVersion: "gate.workflow-admission/v1",
    kind: "WorkflowAdmission",
    instanceId: workflowId,
    workflowDefinitionSha256: status.contract.sha256,
    phaseId,
    target,
    action,
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
      maxMinutes: 5,
      maxRequests: 20,
      maxRatePerSecond: 10,
      maxParallel: 2,
      maxInputTokens: 0,
      maxOutputTokens: 0,
      maxTotalTokens: 20_000,
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
  return { id, target, action, toolId, workflowId, phaseAttemptId: started.projection.activePhase.attemptId };
}

function resolver(toolId, executable = process.execPath, riskClass = "A1") {
  return (id) => ({
    id,
    installed: id === toolId,
    executable,
    compatible: true,
    genericLaneEligible: true,
    executionAvailable: true,
    host: process.env.WSL_DISTRO_NAME ? "wsl2" : "linux",
    riskClass
  });
}

function manifestInput(scope, argv) {
  return {
    workflowId: scope.workflowId,
    phaseAttemptId: scope.phaseAttemptId,
    target: scope.target,
    action: scope.action,
    toolId: scope.toolId,
    argv,
    maxMinutes: 1,
    estimatedRequests: 1,
    maxParallel: 1,
    maxRatePerSecond: 1,
    maxTokens: 1_000,
    maxEvidenceBytes: 2 * 1024 * 1024
  };
}

function evidenceFile(paths, reference) {
  return path.join(paths.evidence, reference.slice("private://evidence/".length));
}

async function withTimeout(promise, milliseconds = 5_000) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`operation exceeded ${milliseconds}ms`)), milliseconds);
      })
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function waitFor(check, milliseconds = 3_000) {
  const deadline = Date.now() + milliseconds;
  while (Date.now() < deadline) {
    const value = check();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`condition was not met within ${milliseconds}ms`);
}

function nonZombie(pid) {
  try {
    const text = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    return text.slice(text.lastIndexOf(")") + 2).split(/\s+/u)[0] !== "Z";
  } catch {
    return false;
  }
}

test("one-shot loopback execution binds exact argv and strips ambient credentials", async (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  let requests = 0;
  const server = http.createServer((request, response) => {
    requests += 1;
    response.end("fixture-ok");
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(() => server.close());
  const address = server.address();
  const target = `http://127.0.0.1:${address.port}/probe?q=%24%28touch%20never%29%3B%26`;
  const scope = approve(paths, root, { id: "loopback", target });
  const script = [
    "const http=require('node:http');",
    "const target=process.argv[1];",
    "http.get(target,(response)=>{response.resume();response.on('end',()=>{",
    "process.stdout.write(JSON.stringify({target,argv:process.argv.slice(1),env:Object.keys(process.env).sort()}));",
    "});}).on('error',(error)=>{console.error(error.message);process.exitCode=2;});"
  ].join("");
  const created = createExecutionManifest(
    scope.id,
    manifestInput(scope, ["-e", script, "{{GATE_TARGET}}"]),
    { paths, resolveTool: resolver(scope.toolId) }
  );

  assert.deepEqual(created.operation.argv.slice(0, 2), ["-e", script]);
  assert.equal(created.operation.argv[2], target);
  assert.ok(created.enforcement.enforced.includes("executable-descriptor-observed-sha256"));
  assert.ok(created.enforcement.unavailable.includes("immutable-executable-snapshot"));
  await assert.rejects(
    executeExecutionManifest(scope.id, { manifestId: created.manifestId, confirm: "EXECUTE wrong" }, { paths }),
    /confirmation must be exactly/
  );
  assert.equal(requests, 0);

  const result = await withTimeout(executeExecutionManifest(scope.id, {
    manifestId: created.manifestId,
    confirm: created.confirmationRequired
  }, { paths, pollIntervalMs: 20, terminationGraceMs: 50 }));
  assert.equal(result.status, "succeeded");
  assert.equal(result.terminationReason, "completed");
  assert.deepEqual(result.workflow, {
    instanceId: scope.workflowId,
    phaseId: "active-surface-validation",
    phaseAttemptId: scope.phaseAttemptId,
    reservationId: created.workflow.reservationId
  });
  assert.equal(requests, 1);
  assert.equal(result.evidence.stdout.available, true);
  assert.equal(result.evidence.resultAvailable, true);
  const captured = JSON.parse(fs.readFileSync(evidenceFile(paths, result.evidence.stdout.ref), "utf8"));
  assert.equal(captured.target, target);
  assert.deepEqual(captured.argv, [target]);
  assert.deepEqual(captured.env, ["HOME", "LANG", "LC_ALL", "NO_COLOR", "PATH", "TERM", "TMPDIR"]);
  for (const ref of [result.evidence.stdout.ref, result.evidence.stderr.ref, result.evidence.resultRef]) {
    assert.equal(fs.statSync(evidenceFile(paths, ref)).mode & 0o777, 0o600);
  }
  await assert.rejects(
    executeExecutionManifest(scope.id, { manifestId: created.manifestId, confirm: created.confirmationRequired }, { paths }),
    /already consumed/
  );
  assert.equal(requests, 1);
  assert.equal(executionStatus({ paths }).counts.succeeded, 1);
  const workflow = workflowStatus(scope.workflowId, { paths });
  assert.deepEqual(workflow.executionReservations, []);
  assert.equal(workflow.activePhase.allocation.conservativelyReserved.maxMinutes, 1);
  assert.equal(workflow.activePhase.allocation.conservativelyReserved.maxRequests, 1);
  assert.equal(workflow.activePhase.allocation.conservativelyReserved.maxTotalTokens, 1_000);
  assert.equal(workflow.activePhase.allocation.conservativelyReserved.maxEvidenceBytes, 2 * 1024 * 1024);
  assert.throws(
    () => reconcileExecution(scope.id, { manifestId: created.manifestId, confirm: "RECONCILE wrong" }, { paths }),
    /confirmation must be exactly/
  );
  const reconciled = reconcileExecution(scope.id, {
    manifestId: created.manifestId,
    confirm: `RECONCILE EXECUTION ${created.manifestId} ${created.manifestSha256}`
  }, { paths });
  assert.equal(reconciled.status, "succeeded");
  assert.equal(reconciled.workflow.reservationId, created.workflow.reservationId);
});

test("fast descriptor execution cannot outrun lifecycle listeners or the one-shot claim", async (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const executable = ["/usr/bin/true", "/bin/true"].find((candidate) => fs.existsSync(candidate));
  if (!executable) t.skip("true executable unavailable");
  const scope = approve(paths, root, { id: "fast-tool", target: "fast.example.test" });
  const created = createExecutionManifest(scope.id, manifestInput(scope, ["{{GATE_TARGET}}"]), {
    paths,
    resolveTool: resolver(scope.toolId, executable, "P0")
  });
  const input = { manifestId: created.manifestId, confirm: created.confirmationRequired };
  const attempts = await withTimeout(Promise.allSettled([
    executeExecutionManifest(scope.id, input, { paths }),
    executeExecutionManifest(scope.id, input, { paths })
  ]), 3_000);
  const fulfilled = attempts.filter((attempt) => attempt.status === "fulfilled");
  const rejected = attempts.filter((attempt) => attempt.status === "rejected");
  assert.equal(fulfilled.length, 1);
  assert.equal(fulfilled[0].value.status, "succeeded");
  assert.equal(rejected.length, 1);
  assert.match(rejected[0].reason.message, /already consumed/);
});

test("reconciliation records recovery hold after a crash between the durable claims", (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const scope = approve(paths, root, { id: "claim-gap", target: "claim-gap.example.test" });
  const created = createExecutionManifest(scope.id, manifestInput(scope, ["{{GATE_TARGET}}"]), {
    paths,
    resolveTool: resolver(scope.toolId)
  });
  const manifest = JSON.parse(fs.readFileSync(
    path.join(paths.executionManifests, `${created.manifestId}.json`),
    "utf8"
  ));
  const deadSupervisor = executionInternals.processIdentity(process.pid);
  deadSupervisor.startTimeTicks = String(BigInt(deadSupervisor.startTimeTicks) + 1n);
  fs.writeFileSync(path.join(paths.executionClaims, `${created.manifestId}.json`), `${JSON.stringify({
    apiVersion: "gate.execution-claim/v1",
    manifestId: created.manifestId,
    runId: created.runId,
    manifestSha256: created.manifestSha256,
    engagementId: scope.id,
    workflow: { ...manifest.workflow },
    claimedAt: new Date().toISOString(),
    createdAt: manifest.metadata.createdAt,
    supervisor: deadSupervisor
  })}\n`, { mode: 0o600 });

  assert.equal(workflowStatus(scope.workflowId, { paths }).executionReservations[0].status, "reserved");
  const reconciled = reconcileExecution(scope.id, {
    manifestId: created.manifestId,
    confirm: `RECONCILE EXECUTION ${created.manifestId} ${created.manifestSha256}`
  }, { paths });
  assert.equal(reconciled.status, "unknown");
  assert.equal(reconciled.terminationReason, "supervision-lost");
  const workflow = workflowStatus(scope.workflowId, { paths });
  assert.equal(workflow.status, "recovery-hold");
  assert.deepEqual(workflow.executionReservations, [{
    id: created.workflow.reservationId,
    status: "unknown",
    phaseId: "active-surface-validation"
  }]);
  assert.equal(JSON.parse(fs.readFileSync(
    path.join(paths.executionRuns, `${created.runId}.json`),
    "utf8"
  )).status, "unknown");

  const replayed = reconcileExecution(scope.id, {
    manifestId: created.manifestId,
    confirm: `RECONCILE EXECUTION ${created.manifestId} ${created.manifestSha256}`
  }, { paths });
  assert.equal(replayed.status, "unknown");
});

test("CLI reports a nonzero exit status when an executed tool fails", (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const scope = approve(paths, root, { id: "cli-tool-failure", target: "127.0.0.1" });
  const created = createExecutionManifest(
    scope.id,
    manifestInput(scope, ["-e", "setTimeout(()=>process.exit(7),100)", "{{GATE_TARGET}}"]),
    { paths, resolveTool: resolver(scope.toolId) }
  );
  const result = spawnSync(process.execPath, [
    gate,
    "engagement", "exec", scope.id,
    "--manifest", created.manifestId,
    "--confirm", created.confirmationRequired,
    "--json"
  ], {
    cwd: repo,
    env: { ...process.env, GATE_HOME: paths.home },
    encoding: "utf8",
    timeout: 5_000
  });

  assert.equal(result.status, 2, result.stderr);
  assert.equal(result.signal, null);
  const output = JSON.parse(result.stdout);
  assert.equal(output.ok, false);
  assert.equal(output.status, "failed");
  assert.equal(output.exitCode, 7);
});

test("manifest creation rejects environment, target, argv0, and placeholder mismatches", (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const vm = approve(paths, root, { id: "vm-scope", target: "vm.example.test", environment: "vm", workflow: false });
  assert.throws(
    () => createExecutionManifest(vm.id, manifestInput(vm, ["{{GATE_TARGET}}"]), {
      paths,
      resolveTool: resolver(vm.toolId)
    }),
    /requires an approved host environment/
  );

  const externalEvidence = approve(paths, root, {
    id: "external-evidence",
    target: "evidence.example.test",
    allowedDestinations: ["client-destination"],
    workflow: false
  });
  assert.throws(
    () => createExecutionManifest(externalEvidence.id, manifestInput(externalEvidence, ["{{GATE_TARGET}}"]), {
      paths,
      resolveTool: resolver(externalEvidence.toolId)
    }),
    /requires gate-home as an approved evidence destination/
  );

  const canonical = approve(paths, root, { id: "canonical", target: "some app" });
  assert.throws(
    () => createExecutionManifest(canonical.id, { ...manifestInput(canonical, ["{{GATE_TARGET}}"]), target: "  some\tapp  " }, {
      paths,
      resolveTool: resolver(canonical.toolId)
    }),
    /canonical approved form exactly/
  );
  assert.throws(
    () => createExecutionManifest(canonical.id, manifestInput(canonical, [path.basename(process.execPath), "{{GATE_TARGET}}"]), {
      paths,
      resolveTool: resolver(canonical.toolId)
    }),
    /pass tool arguments only/
  );
  assert.throws(
    () => createExecutionManifest(canonical.id, manifestInput(canonical, ["--version"]), {
      paths,
      resolveTool: resolver(canonical.toolId)
    }),
    /exactly one whole-argument/
  );
});

test("generic manifest creation rejects an active A3 workflow phase before persistence", (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const scope = approve(paths, root, { id: "a3-generic", target: "a3.example.test" });
  const workflowDirectory = path.join(paths.workflows, scope.workflowId);
  const journalFile = path.join(workflowDirectory, "journal.jsonl");
  const projectionFile = path.join(workflowDirectory, "instance.json");
  const entries = fs.readFileSync(journalFile, "utf8").trimEnd().split("\n").map((line) => JSON.parse(line));
  const activePhaseEntry = entries.at(-1);
  assert.equal(activePhaseEntry.type, "phase.started");

  // Exercise the execution boundary directly while retaining a valid journal chain.
  activePhaseEntry.payload.effectClass = "A3";
  activePhaseEntry.entrySha256 = workflowRuntimeInternals.entryDigest(activePhaseEntry);
  fs.writeFileSync(journalFile, `${entries.map((entry) => JSON.stringify(entry)).join("\n")}\n`, { mode: 0o600 });
  fs.rmSync(projectionFile);

  assert.throws(
    () => createExecutionManifest(scope.id, manifestInput(scope, ["{{GATE_TARGET}}"]), {
      paths,
      resolveTool: resolver(scope.toolId)
    }),
    /generic execution lane cannot execute an A3 phase/u
  );
  assert.deepEqual(workflowStatus(scope.workflowId, { paths }).executionReservations, []);
  assert.deepEqual(fs.readdirSync(paths.executionManifests), []);
});

test("manifest invariants and launch-time executable identity fail closed", async (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const tool = path.join(root, "fixture-tool");
  fs.writeFileSync(tool, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
  const scope = approve(paths, root, { id: "identity", target: "identity.example.test" });
  const first = createExecutionManifest(scope.id, manifestInput(scope, ["{{GATE_TARGET}}"]), {
    paths,
    resolveTool: resolver(scope.toolId, tool, "P0")
  });
  const firstFile = path.join(paths.executionManifests, `${first.manifestId}.json`);
  const tampered = JSON.parse(fs.readFileSync(firstFile, "utf8"));
  tampered.operation.argv[tampered.operation.targetArgIndex] = "outside.example.test";
  tampered.manifestSha256 = executionInternals.manifestDigest(tampered);
  fs.writeFileSync(firstFile, `${JSON.stringify(tampered, null, 2)}\n`, { mode: 0o600 });
  await assert.rejects(
    executeExecutionManifest(scope.id, {
      manifestId: first.manifestId,
      confirm: `EXECUTE ${first.manifestId} ${tampered.manifestSha256} UNMETERED`
    }, { paths }),
    /target argument binding is invalid/
  );
  cancelWorkflowExecution(scope.workflowId, {
    reservationId: first.workflow.reservationId,
    reason: "The tampered fixture manifest will not be executed."
  }, { paths });

  const second = createExecutionManifest(scope.id, manifestInput(scope, ["{{GATE_TARGET}}"]), {
    paths,
    resolveTool: resolver(scope.toolId, tool, "P0")
  });
  fs.appendFileSync(tool, "# changed\n");
  await assert.rejects(
    executeExecutionManifest(scope.id, { manifestId: second.manifestId, confirm: second.confirmationRequired }, { paths }),
    /executable .* changed after manifest creation/
  );
  const status = executionStatus({ paths });
  assert.equal(status.counts.blocked, 1);
  const events = fs.readFileSync(paths.events, "utf8").trim().split("\n").map((line) => JSON.parse(line));
  const blockedEvents = events.filter((event) => event.runId === second.runId);
  assert.equal(blockedEvents.at(-1).kind, "execution.completed");
  assert.equal(blockedEvents.at(-1).status, "blocked");

  const manifestDocument = JSON.parse(fs.readFileSync(path.join(paths.executionManifests, `${second.manifestId}.json`), "utf8"));
  manifestDocument.operation.executable.inode = "-1";
  assert.equal(validateDocument(manifestDocument, "execution-manifest.schema.json", { paths }).ok, true);
});

test("evidence limiting durably records a bounded prefix and terminal audit", async (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const scope = approve(paths, root, { id: "evidence-cap", target: "127.0.0.1" });
  const script = "process.stdout.write(Buffer.alloc(2*1024*1024,120));setInterval(()=>{},1000);";
  const created = createExecutionManifest(scope.id, manifestInput(scope, ["-e", script, "{{GATE_TARGET}}"]), {
    paths,
    resolveTool: resolver(scope.toolId)
  });
  const result = await withTimeout(executeExecutionManifest(scope.id, {
    manifestId: created.manifestId,
    confirm: created.confirmationRequired
  }, { paths, pollIntervalMs: 20, terminationGraceMs: 50 }), 10_000);
  assert.equal(result.status, "failed");
  assert.equal(result.terminationReason, "evidence-limit");
  assert.equal(result.evidence.stdout.available, true);
  assert.ok(result.evidence.stdout.bytes > 0);
  assert.ok(result.evidence.stdout.bytes <= 1024 * 1024);
  assert.equal(fs.statSync(evidenceFile(paths, result.evidence.stdout.ref)).size, result.evidence.stdout.bytes);
  const events = fs.readFileSync(paths.events, "utf8").trim().split("\n").map((line) => JSON.parse(line));
  const terminal = events.filter((event) => event.runId === created.runId).at(-1);
  assert.equal(terminal.kind, "execution.completed");
  assert.equal(terminal.status, "failed");
});

test("authorization revocation polling terminates the authenticated process group", async (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const scope = approve(paths, root, { id: "revoke-running", target: "127.0.0.1" });
  const script = "process.on('SIGTERM',()=>{});setInterval(()=>{},1000);";
  const created = createExecutionManifest(scope.id, manifestInput(scope, ["-e", script, "{{GATE_TARGET}}"]), {
    paths,
    resolveTool: resolver(scope.toolId)
  });
  const executing = executeExecutionManifest(scope.id, {
    manifestId: created.manifestId,
    confirm: created.confirmationRequired
  }, { paths, pollIntervalMs: 20, terminationGraceMs: 50 });
  const runFile = path.join(paths.executionRuns, `${created.runId}.json`);
  const running = await waitFor(() => {
    try {
      const value = JSON.parse(fs.readFileSync(runFile, "utf8"));
      return value.status === "running" ? value : null;
    } catch {
      return null;
    }
  });
  revokeEngagement(scope.id, { confirm: `REVOKE ${scope.id}` }, { paths });
  const result = await withTimeout(executing, 10_000);
  assert.equal(result.status, "cancelled");
  assert.equal(result.terminationReason, "engagement-invalidated");
  assert.equal(nonZombie(running.process.pid), false);
});

test("operator stop kills a TERM-resistant same-session grandchild before returning", async (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const scope = approve(paths, root, { id: "group-stop", target: "127.0.0.1" });
  const grandchild = "process.on('SIGTERM',()=>{});setInterval(()=>{},1000);";
  const leader = [
    "const {spawn}=require('node:child_process');",
    `const child=spawn(process.execPath,['-e',${JSON.stringify(grandchild)}],{stdio:'ignore'});`,
    "process.stdout.write(String(child.pid)+'\\n');",
    "process.on('SIGTERM',()=>process.exit(0));",
    "setInterval(()=>{},1000);"
  ].join("");
  const created = createExecutionManifest(scope.id, manifestInput(scope, ["-e", leader, "{{GATE_TARGET}}"]), {
    paths,
    resolveTool: resolver(scope.toolId)
  });
  const executing = executeExecutionManifest(scope.id, {
    manifestId: created.manifestId,
    confirm: created.confirmationRequired
  }, { paths, pollIntervalMs: 20, terminationGraceMs: 80 });
  const runFile = path.join(paths.executionRuns, `${created.runId}.json`);
  await waitFor(() => fs.existsSync(runFile) && JSON.parse(fs.readFileSync(runFile, "utf8")).status === "running");
  const stdoutFile = path.join(paths.evidence, `execution-${created.runId}-stdout.bin`);
  const grandchildPid = await waitFor(() => {
    try {
      const value = Number(fs.readFileSync(stdoutFile, "utf8").trim());
      return Number.isSafeInteger(value) && value > 1 ? value : null;
    } catch {
      return null;
    }
  });
  requestExecutionStop(scope.id, { runId: created.runId }, { paths });
  const result = await withTimeout(executing, 10_000);
  assert.equal(result.status, "cancelled");
  assert.equal(result.terminationReason, "operator-stop");
  assert.equal(nonZombie(grandchildPid), false);
});

test("a leader cannot report success while a same-session descendant survives", async (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const scope = approve(paths, root, { id: "completion-escape", target: "127.0.0.1" });
  const grandchild = "process.on('SIGTERM',()=>{});setInterval(()=>{},1000);";
  const leader = [
    "const {spawn}=require('node:child_process');",
    `const child=spawn(process.execPath,['-e',${JSON.stringify(grandchild)}],{stdio:'ignore'});`,
    "child.unref();",
    "process.stdout.write(String(child.pid)+'\\n');"
  ].join("");
  const created = createExecutionManifest(scope.id, manifestInput(scope, ["-e", leader, "{{GATE_TARGET}}"]), {
    paths,
    resolveTool: resolver(scope.toolId)
  });
  const result = await withTimeout(executeExecutionManifest(scope.id, {
    manifestId: created.manifestId,
    confirm: created.confirmationRequired
  }, { paths, pollIntervalMs: 20, terminationGraceMs: 50 }), 10_000);
  const grandchildPid = Number(fs.readFileSync(evidenceFile(paths, result.evidence.stdout.ref), "utf8").trim());
  assert.equal(result.status, "cancelled");
  assert.equal(result.terminationReason, "process-group-remained");
  assert.equal(nonZombie(grandchildPid), false);
});

test("post-spawn supervisor failure awaits SIGKILL for a TERM-resistant tool", async (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const scope = approve(paths, root, { id: "spawn-failure", target: "127.0.0.1" });
  const script = "process.on('SIGTERM',()=>{});setInterval(()=>{},1000);";
  const created = createExecutionManifest(scope.id, manifestInput(scope, ["-e", script, "{{GATE_TARGET}}"]), {
    paths,
    resolveTool: resolver(scope.toolId)
  });
  let pid;
  await assert.rejects(withTimeout(executeExecutionManifest(scope.id, {
    manifestId: created.manifestId,
    confirm: created.confirmationRequired
  }, {
    paths,
    pollIntervalMs: 20,
    terminationGraceMs: 50,
    afterSpawn(value) {
      pid = value.pid;
      throw new Error("injected post-spawn failure");
    }
  }), 10_000), /injected post-spawn failure/);
  assert.equal(nonZombie(pid), false);
  assert.equal(JSON.parse(fs.readFileSync(path.join(paths.executionRuns, `${created.runId}.json`), "utf8")).status, "failed");
});

test("audit effect uses the higher catalog risk and stale supervisors project unknown", async (t) => {
  requireLane(t);
  const { root, paths } = fixture(t);
  const scope = approve(paths, root, {
    id: "risk-floor",
    target: "127.0.0.1",
    action: "observe"
  });
  const created = createExecutionManifest(scope.id, manifestInput(scope, ["-e", "process.exit(0)", "{{GATE_TARGET}}"]), {
    paths,
    resolveTool: resolver(scope.toolId, process.execPath, "A3")
  });
  await withTimeout(executeExecutionManifest(scope.id, {
    manifestId: created.manifestId,
    confirm: created.confirmationRequired
  }, { paths }));
  const events = fs.readFileSync(paths.events, "utf8").trim().split("\n").map((line) => JSON.parse(line));
  const executionEvents = events.filter((event) => event.runId === created.runId);
  assert.ok(executionEvents.length >= 3);
  assert.ok(executionEvents.every((event) => event.effect.class === "high-impact"));

  const runFile = path.join(paths.executionRuns, `${created.runId}.json`);
  const stale = JSON.parse(fs.readFileSync(runFile, "utf8"));
  stale.status = "queued";
  stale.startedAt = null;
  stale.finishedAt = null;
  stale.process = null;
  stale.terminationReason = null;
  stale.result = { exitCode: null, signal: null, durationMs: null };
  stale.evidence.stdout = { ...stale.evidence.stdout, available: false, sha256: null, bytes: 0 };
  stale.evidence.stderr = { ...stale.evidence.stderr, available: false, sha256: null, bytes: 0 };
  stale.evidence.resultAvailable = false;
  stale.supervisor.startTimeTicks = String(BigInt(stale.supervisor.startTimeTicks) + 1n);
  fs.writeFileSync(runFile, `${JSON.stringify(stale, null, 2)}\n`, { mode: 0o600 });
  const status = executionStatus({ paths });
  assert.equal(status.recent[0].status, "unknown");
  assert.equal(status.counts.unknown, 1);
});
