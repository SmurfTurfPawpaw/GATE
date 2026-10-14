import fs from "node:fs";
import path from "node:path";
import { parseArgs, listFlag, requiredFlag } from "./lib/args.mjs";
import { writeJsonAtomic } from "./lib/config.mjs";
import { runDoctor } from "./lib/doctor.mjs";
import {
  approveEngagement,
  attachAuthorization,
  attachPlan,
  checkEngagement,
  closeEngagement,
  createEngagement,
  getEngagement,
  recordTechnicalReview,
  revokeEngagement
} from "./lib/engagements.mjs";
import {
  createExecutionManifest,
  executeExecutionManifest,
  reconcileExecution,
  requestEngagementStops,
  requestExecutionStop
} from "./lib/executions.mjs";
import { recordEvent } from "./lib/events.mjs";
import { addLearning } from "./lib/learnings.mjs";
import {
  createOfflineAnalysisManifest,
  executeOfflineAnalysisManifest,
  offlineAnalysisCapability,
  offlineAnalysisStatus,
  purgeOfflineAnalysisArtifact
} from "./lib/offline-analysis.mjs";
import { ensureRuntime, runtimePaths } from "./lib/paths.mjs";
import { checkPublication, publishPullRequest } from "./lib/publication.mjs";
import { listProjects, registerProject, showProject, verifyProject } from "./lib/projects.mjs";
import { buildStatus } from "./lib/status.mjs";
import { statusSummary, toolDetailSummary, toolInventorySummary } from "./lib/summaries.mjs";
import { runManagedToolOperation } from "./lib/tool-runtimes.mjs";
import { toolInventory, toolPlan, toolShow } from "./lib/tools.mjs";
import { installUpstream, syncUpstream, upstreamStatus } from "./lib/upstreams.mjs";
import { validateRepository } from "./lib/validation.mjs";
import { leaseWorkspace, verifyWorkspace, workspaceStatus } from "./lib/workspaces.mjs";
import {
  addWorkflowEvidence,
  attachWorkflowReport,
  cancelWorkflowExecution,
  closeWorkflow,
  createWorkflowInstance,
  finishWorkflowPhase,
  holdWorkflowLedger,
  joinWorkflowCoverage,
  openWorkflowLedger,
  preflightWorkflowPhase,
  preflightWorkflowPivot,
  recordWorkflowLedgerCleanup,
  setWorkflowCoverage,
  startWorkflowPhase,
  stopWorkflow,
  verifyWorkflowLedger,
  workflowStatus
} from "./lib/workflow-runtime.mjs";

const help = `GATE — Gateway for Agentic Tooling & Engineering

Usage: gate <command> [options]

Core
  bootstrap                         Create private runtime directories and verify config
  doctor [--full] [--json]          Inspect the host, repository, and optional integrations
  status [--summary] [--json]       Show full status or an agent-sized bounded summary
  up [--host 127.0.0.1] [--port 4173]
                                    Run the read-only local cockpit
  validate [--json]                 Validate tracked configuration and pins

Operations
  event <kind> --summary TEXT       Append a sanitized activity event
  learn --cause TEXT --change TEXT [--private] [--scope session|project|repository]
                                    Record one cause → change learning candidate

Projects
  project register --file PATH      Register a private validated project contract
  project list                      List registered project summaries
  project show ID                   Show one registered project contract
  project verify ID                 Verify one registered project contract

Offline analysis
  analysis capability               Check the zero-network Bubblewrap analysis lane
  analysis manifest --project ID --path EXACT [--minutes N]
                                    Snapshot one local artifact and bind an offline run
  analysis run --project ID --manifest ID --confirm "ANALYZE ID SHA256 OFFLINE"
                                    Execute the one-shot fixed REA adapter manifest
  analysis purge --project ID --manifest ID --confirm "PURGE ID SHA256 OFFLINE ARTIFACT"
                                    Purge one retained digest-bound artifact snapshot
  analysis status                   Show capability and recent offline analysis runs

Workspaces
  workspace lease --repo PATH --task ID --branch REF [--base REF]
                                    Acquire a verified Treehouse lease
  workspace status --repo PATH      Inspect Treehouse workspace state
  workspace verify --repo PATH --path PATH --task ID --lease ID --landed-ref REF
                                    Verify landing and retain the durable lease

Engagements
  engagement new ID --targets CSV --actions CSV --tools CSV
  engagement plan ID --file PATH
  engagement authorization ID --file PATH
  engagement review ID --run RUN --head GIT_SHA --result passed|failed
  engagement approve ID --sha SHA256 --confirm "APPROVE ID"
  engagement check ID --target TARGET --action ACTION
  engagement manifest ID --workflow ID --phase-attempt ID --target TARGET --action ACTION --tool TOOL --minutes N
                         --requests N --parallel N --rate N --tokens N [--evidence-bytes N] -- ARGV...
  engagement exec ID --manifest ID --confirm "EXECUTE ID SHA256 UNMETERED"
  engagement reconcile ID --manifest ID --confirm "RECONCILE EXECUTION ID SHA256"
  engagement stop ID --run RUN
  engagement revoke ID --confirm "REVOKE ID"
  engagement status ID
  engagement close ID

Pentest workflows
  workflow new ID [--engagement ID]  Create a private map-first workflow instance
  workflow status ID                 Show the compact journal-derived projection
  workflow phase preflight ID --phase PHASE --from PHASE --admission FILE [--handoff-id ID] [--handoff FILE]
  workflow phase start ID --phase PHASE [--from PHASE] [--admission FILE]
  workflow phase finish ID --phase PHASE --disposition DISPOSITION
  workflow evidence add ID --phase PHASE --evidence ID --file PATH
  workflow coverage set ID --domain DOMAIN --disposition DISPOSITION
  workflow ledger preflight|open|cleanup|verify|hold ID [options]
  workflow execution cancel ID --reservation ID --reason TEXT
  workflow stop ID --condition ID --reason TEXT
  workflow join ID                    Enforce the 18-domain and clean-ledger barrier
  workflow report ID --file PATH      Attach a content-addressed private report
  workflow close ID --confirm "CLOSE ID REPORT_SHA256"

Upstreams
  upstream list
  upstream sync ID|all
  upstream install ID|all              Install integrity-pinned managed upstreams
  upstream path ID                     Print its source or package directory

Security tools
  tool list [--profile ID] [--category ID] [--summary] [--limit N] [--cursor N]
  tool show ID                         Show one bounded receipt-only tool projection
  tool plan ID                         Show host, lane, risk, and admission needs
  tool prefetch ID|--profile ID        Cache reviewed release bytes without activating them
  tool install ID|--profile ID         Install and zero-egress-smoke reviewed runtimes
  tool verify ID|--profile ID          Recheck current bytes, lock, platform, and smoke
  tool remove ID|--profile ID          Remove runtimes; retain cache bytes for re-verification

Publication
  publication check|dry-run --repo OWNER/REPO --pr N --head SHA --run RUN
                            [--mode squash|merge|rebase]

Use --json for machine-readable output. Active target contact needs an approved,
digest-bound engagement. GATE never treats a worktree or container as a sandbox.
`;

function output(value, json = false) {
  if (json || typeof value !== "string") process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
  else process.stdout.write(`${value}\n`);
}

function assertFlags(flags, allowed = []) {
  const accepted = new Set(allowed);
  for (const name of Object.keys(flags)) {
    if (!accepted.has(name)) throw new Error(`unsupported option: --${name}`);
  }
}

function assertPositionals(positional, count, usage) {
  if (positional.length !== count) throw new Error(`expected ${usage}`);
}

function assertUnambiguousAnalysisArgs(argv) {
  const seen = new Set();
  for (const value of argv) {
    if (value === "--") throw new Error("analysis commands do not accept -- passthrough arguments");
    if (!value.startsWith("--")) continue;
    const equals = value.indexOf("=");
    const name = value.slice(2, equals === -1 ? undefined : equals);
    if (!name) throw new Error("analysis options must have a name");
    if (seen.has(name)) throw new Error(`analysis option must not be repeated: --${name}`);
    seen.add(name);
  }
}

function assertBooleanSwitch(flags, name) {
  if (flags[name] !== undefined && flags[name] !== true) {
    throw new Error(`--${name} does not accept a value`);
  }
}

function assertUnambiguousToolArgs(argv) {
  const seen = new Set();
  for (const value of argv) {
    if (value === "--") throw new Error("tool commands do not accept -- passthrough arguments");
    if (!value.startsWith("--")) continue;
    const equals = value.indexOf("=");
    const name = value.slice(2, equals === -1 ? undefined : equals);
    if (!name) throw new Error("tool options must have a name");
    if (seen.has(name)) throw new Error(`tool option must not be repeated: --${name}`);
    seen.add(name);
  }
}

function assertUnambiguousWorkflowArgs(argv) {
  const seen = new Set();
  for (const value of argv) {
    if (value === "--") throw new Error("workflow commands do not accept passthrough arguments");
    if (!value.startsWith("--")) continue;
    const equals = value.indexOf("=");
    const name = value.slice(2, equals === -1 ? undefined : equals);
    if (!name) throw new Error("workflow options must have a name");
    if (seen.has(name)) throw new Error(`workflow option must not be repeated: --${name}`);
    seen.add(name);
  }
}

function optionalValueFlag(flags, name) {
  if (flags[name] === undefined) return undefined;
  if (typeof flags[name] !== "string" || !flags[name].trim()) throw new Error(`--${name} needs a value`);
  return flags[name];
}

function workflowMutationOptions(flags, paths) {
  const expectedSequence = optionalValueFlag(flags, "expected-sequence");
  return {
    paths,
    requestId: optionalValueFlag(flags, "request"),
    expectedSequence: expectedSequence === undefined ? undefined : Number(expectedSequence),
    expectedHead: optionalValueFlag(flags, "expected-head")
  };
}

function workflowCommit(result) {
  const payload = result.entry.payload;
  const details = (() => {
    switch (result.entry.type) {
      case "phase.started": return { phaseId: payload.phaseId, attemptId: payload.attemptId };
      case "phase.finished": return { phaseId: payload.phaseId, disposition: payload.disposition };
      case "evidence.added": return { evidenceId: payload.evidenceId, sha256: payload.sha256 };
      case "coverage.set": return { domain: payload.domain, disposition: payload.disposition };
      case "ledger.opened": return { entryId: payload.entryId };
      case "ledger.cleanup-recorded":
      case "ledger.verified":
      case "ledger.held": return { entryId: payload.entryId };
      case "execution.cancelled": return { reservationId: payload.reservationId };
      case "stop.triggered": return { condition: payload.condition };
      case "coverage.joined": return { coverageSha256: payload.coverageSha256 };
      case "report.attached": return { reportSha256: payload.sha256 };
      case "workflow.closed": return { reportSha256: payload.reportSha256 };
      default: return {};
    }
  })();
  return {
    ok: true,
    instanceId: result.projection.instanceId,
    status: result.projection.status,
    event: {
      type: result.entry.type,
      sequence: result.entry.sequence,
      headSha256: result.entry.entrySha256,
      requestId: result.entry.requestId,
      replayed: result.replayed,
      details
    },
    activePhaseId: result.projection.activePhase?.phaseId || null,
    coverageCount: Object.keys(result.projection.coverage).length,
    ledgerEntries: Object.keys(result.projection.ledger).length
  };
}

function printValidation(validation, json) {
  if (json) return output(validation, true);
  for (const check of validation.checks) {
    process.stdout.write(`${check.ok ? "ok" : "fail"}\t${check.name}\t${check.detail}\n`);
  }
  process.stdout.write(`\n${validation.ok ? "GATE configuration is valid." : "GATE configuration has failures."}\n`);
}

function printDoctor(doctor, json) {
  if (json) return output(doctor, true);
  process.stdout.write(`host\t${doctor.host.platform}/${doctor.host.architecture}${doctor.host.wsl ? " (WSL)" : ""}\n`);
  for (const tool of doctor.tools) {
    const state = tool.available ? "ready" : tool.required ? "missing" : "optional";
    process.stdout.write(`${state}\t${tool.id}\t${tool.version || "unavailable"}\n`);
  }
  process.stdout.write(`config\t${doctor.repository.ok ? "valid" : "invalid"}\n`);
  if (doctor.toolRuntimes) {
    process.stdout.write(
      `tool-runtimes\tcatalog=${doctor.toolRuntimes.catalog} locked=${doctor.toolRuntimes.locked} installed=${doctor.toolRuntimes.installed} verified=${doctor.toolRuntimes.verified} executable=${doctor.toolRuntimes.executable} unresolved=${doctor.toolRuntimes.unresolved}\n`
    );
  }
  if (doctor.capabilities) {
    const { capture, debugger: debuggerCapability, usb, containers } = doctor.capabilities;
    process.stdout.write(`capture\tinterfaces=${capture.nonLoopbackInterfaceCount} cap_net_raw=${capture.rawSocketCapability ?? "unknown"} cap_net_admin=${capture.networkAdminCapability ?? "unknown"}\n`);
    process.stdout.write(`debugger\tptrace_scope=${debuggerCapability.ptraceScope ?? "unknown"}\n`);
    process.stdout.write(`usb\tdevice_bus=${usb.linuxDeviceBusPresent}\n`);
    process.stdout.write(`docker-engine\t${containers.engineReachability}${containers.dockerSocketPresent === null ? "" : ` socket=${containers.dockerSocketPresent}`}\n`);
  }
}

function publicationRequest(flags) {
  return {
    repository: requiredFlag(flags, "repo"),
    pullRequest: requiredFlag(flags, "pr"),
    expectedHead: requiredFlag(flags, "head").toLowerCase(),
    noMistakesRunId: requiredFlag(flags, "run"),
    mergeMode: typeof flags.mode === "string" ? flags.mode : "squash"
  };
}

function persistPublicationEvidence(result, paths) {
  ensureRuntime(paths);
  const stamp = new Date().toISOString().replace(/[-:.TZ]/g, "");
  const file = path.join(paths.evidence, `publication-${stamp}-${process.pid}.json`);
  writeJsonAtomic(file, result, 0o600);
  recordEvent(
    {
      kind: `publication.${result.outcome || "unknown"}`,
      status: result.ok ? "succeeded" : "blocked",
      component: "gate-publication",
      summary: `Publication ${result.operation || "check"} ${result.ok ? "passed" : "was blocked"} for PR ${result.pullRequestNumber || "unknown"}.`,
      effect: {
        class: result.mutationAttempted ? "forge-write" : "network-observe",
        targetRef: result.repository && result.pullRequestNumber ? `${result.repository}#${result.pullRequestNumber}` : null,
        engagementId: null,
        planDigest: null
      },
      evidenceRefs: [`file://${file}`]
    },
    { paths }
  );
  return file;
}

export async function main(argv) {
  const [command = "help", ...rest] = argv;
  const parsed = parseArgs(rest);
  const json = parsed.flags.json === true;
  const paths = runtimePaths();

  if (["help", "--help", "-h"].includes(command)) return output(help);
  if (["version", "--version", "-v"].includes(command)) {
    const pkg = JSON.parse(fs.readFileSync(path.join(paths.repo, "package.json"), "utf8"));
    return output(pkg.version);
  }

  if (command === "bootstrap") {
    assertFlags(parsed.flags, ["json"]);
    assertPositionals(parsed.positional, 0, "gate bootstrap");
    ensureRuntime(paths);
    const validation = validateRepository({ paths });
    recordEvent({ kind: "gate.bootstrapped", summary: "Prepared GATE private runtime directories." }, { paths });
    output({ ok: validation.ok, gate_home: paths.home, repository: paths.repo, next: "gate doctor --full" }, json);
    if (!validation.ok) process.exitCode = 1;
    return;
  }

  if (command === "validate") {
    assertFlags(parsed.flags, ["json"]);
    assertPositionals(parsed.positional, 0, "gate validate");
    const validation = validateRepository({ paths });
    printValidation(validation, json);
    if (!validation.ok) process.exitCode = 1;
    return;
  }

  if (command === "doctor") {
    assertFlags(parsed.flags, ["full", "json"]);
    assertPositionals(parsed.positional, 0, "gate doctor [--full] [--json]");
    const doctor = runDoctor({ paths, full: parsed.flags.full === true });
    printDoctor(doctor, json);
    if (!doctor.ok) process.exitCode = 1;
    return;
  }

  if (command === "status") {
    assertFlags(parsed.flags, ["summary", "json"]);
    assertBooleanSwitch(parsed.flags, "summary");
    assertBooleanSwitch(parsed.flags, "json");
    assertPositionals(parsed.positional, 0, "gate status [--summary] [--json]");
    const status = await buildStatus({ paths });
    return output(parsed.flags.summary === true ? statusSummary(status) : status, json);
  }

  if (command === "up") {
    assertFlags(parsed.flags, ["host", "port"]);
    assertPositionals(parsed.positional, 0, "gate up [--host HOST] [--port PORT]");
    const { startObserver } = await import("./observer/server.mjs");
    await startObserver({
      paths,
      host: typeof parsed.flags.host === "string" ? parsed.flags.host : "127.0.0.1",
      port: Number(parsed.flags.port || 4173)
    });
    return;
  }

  if (command === "project") {
    const [action = "list", id] = parsed.positional;
    if (action === "register") {
      assertPositionals(parsed.positional, 1, "gate project register --file PATH");
      assertFlags(parsed.flags, ["file", "json"]);
      return output(registerProject(requiredFlag(parsed.flags, "file"), { paths }), json);
    }
    if (action === "list") {
      assertPositionals(parsed.positional, 1, "gate project list");
      assertFlags(parsed.flags, ["json"]);
      return output(listProjects({ paths }), json);
    }
    if (action === "show") {
      assertPositionals(parsed.positional, 2, "gate project show ID");
      assertFlags(parsed.flags, ["json"]);
      if (!id) throw new Error("project id is required");
      return output(showProject(id, { paths }), json);
    }
    if (action === "verify") {
      assertPositionals(parsed.positional, 2, "gate project verify ID");
      assertFlags(parsed.flags, ["json"]);
      if (!id) throw new Error("project id is required");
      const verification = verifyProject(id, { paths });
      output(verification, json);
      if (!verification.ok) process.exitCode = 2;
      return;
    }
    throw new Error(`unknown project action: ${action}`);
  }

  if (command === "analysis") {
    assertUnambiguousAnalysisArgs(rest);
    const [action] = parsed.positional;
    if (!action) throw new Error("analysis action is required");
    assertPositionals(parsed.positional, 1, "gate analysis capability|manifest|run|purge|status [options]");
    assertBooleanSwitch(parsed.flags, "json");
    if (action === "capability") {
      assertFlags(parsed.flags, ["json"]);
      const capability = offlineAnalysisCapability({ paths });
      output(capability, json);
      if (!capability.laneAvailable) process.exitCode = 2;
      return;
    }
    if (action === "manifest") {
      assertFlags(parsed.flags, ["project", "path", "minutes", "json"]);
      return output(
        createOfflineAnalysisManifest(
          requiredFlag(parsed.flags, "project"),
          {
            path: requiredFlag(parsed.flags, "path"),
            maxMinutes: optionalValueFlag(parsed.flags, "minutes")
          },
          { paths }
        ),
        json
      );
    }
    if (action === "run") {
      assertFlags(parsed.flags, ["project", "manifest", "confirm", "json"]);
      const result = await executeOfflineAnalysisManifest(
        requiredFlag(parsed.flags, "project"),
        {
          manifestId: requiredFlag(parsed.flags, "manifest"),
          confirm: requiredFlag(parsed.flags, "confirm")
        },
        { paths }
      );
      output(result, json);
      if (!result.ok) process.exitCode = 2;
      return;
    }
    if (action === "purge") {
      assertFlags(parsed.flags, ["project", "manifest", "confirm", "json"]);
      return output(
        purgeOfflineAnalysisArtifact(
          requiredFlag(parsed.flags, "project"),
          {
            manifestId: requiredFlag(parsed.flags, "manifest"),
            confirm: requiredFlag(parsed.flags, "confirm")
          },
          { paths }
        ),
        json
      );
    }
    if (action === "status") {
      assertFlags(parsed.flags, ["json"]);
      return output(offlineAnalysisStatus({ paths }), json);
    }
    throw new Error(`unknown analysis action: ${action}`);
  }

  if (command === "workspace") {
    const [action] = parsed.positional;
    if (!action) throw new Error("workspace action is required");
    assertPositionals(parsed.positional, 1, "gate workspace ACTION [options]");
    if (action === "lease") {
      assertFlags(parsed.flags, ["repo", "task", "branch", "base", "json"]);
      return output(leaseWorkspace({
        repository: requiredFlag(parsed.flags, "repo"),
        taskId: requiredFlag(parsed.flags, "task"),
        branch: requiredFlag(parsed.flags, "branch"),
        baseBranch: typeof parsed.flags.base === "string" ? parsed.flags.base : undefined
      }, { paths }), json);
    }
    if (action === "status") {
      assertFlags(parsed.flags, ["repo", "json"]);
      return output(workspaceStatus({
        repository: requiredFlag(parsed.flags, "repo")
      }, { paths }), json);
    }
    if (action === "verify") {
      assertFlags(parsed.flags, ["repo", "path", "task", "lease", "landed-ref", "json"]);
      return output(verifyWorkspace({
        repository: requiredFlag(parsed.flags, "repo"),
        path: requiredFlag(parsed.flags, "path"),
        taskId: requiredFlag(parsed.flags, "task"),
        leaseId: requiredFlag(parsed.flags, "lease"),
        landedRef: requiredFlag(parsed.flags, "landed-ref")
      }, { paths }), json);
    }
    throw new Error(`unknown workspace action: ${action}`);
  }

  if (command === "event") {
    assertFlags(parsed.flags, ["summary", "json"]);
    assertPositionals(parsed.positional, 1, "gate event KIND --summary TEXT");
    const kind = parsed.positional[0];
    if (!kind) throw new Error("event kind is required");
    return output(recordEvent({ kind, summary: requiredFlag(parsed.flags, "summary") }, { paths }), json);
  }

  if (command === "learn") {
    assertFlags(parsed.flags, ["cause", "change", "private", "scope", "json"]);
    assertPositionals(parsed.positional, 0, "gate learn --cause TEXT --change TEXT");
    return output(
      addLearning(
        {
          cause: requiredFlag(parsed.flags, "cause"),
          change: requiredFlag(parsed.flags, "change"),
          scope: typeof parsed.flags.scope === "string" ? parsed.flags.scope : undefined,
          sensitivity: parsed.flags.private === true ? "private" : "public"
        },
        { paths }
      ),
      json
    );
  }

  if (command === "run") {
    throw new Error("raw command execution is disabled; run local development commands directly and use a reviewed scope-aware adapter for target contact");
  }

  if (command === "engagement") {
    const [action, id] = parsed.positional;
    if (!action || !id) throw new Error("engagement action and id are required");
    assertPositionals(parsed.positional, 2, "gate engagement ACTION ID [options]");
    if (action === "new") {
      assertFlags(parsed.flags, [
        "title", "owner", "basis", "targets", "actions", "tools", "exclude", "environment", "depth",
        "valid-from", "valid-until", "max-minutes", "max-requests", "max-parallel", "max-rate", "max-tokens",
        "retention-days", "hypotheses", "classification", "allowed-destinations", "secret-refs", "stop-on", "json"
      ]);
      return output(
        createEngagement(
          {
            id,
            title: parsed.flags.title,
            owner: parsed.flags.owner,
            basis: parsed.flags.basis,
            targets: listFlag(parsed.flags, "targets"),
            actions: listFlag(parsed.flags, "actions"),
            tools: listFlag(parsed.flags, "tools"),
            exclude: listFlag(parsed.flags, "exclude"),
            environment: parsed.flags.environment,
            depth: parsed.flags.depth,
            validFrom: parsed.flags["valid-from"],
            validUntil: parsed.flags["valid-until"],
            maxMinutes: parsed.flags["max-minutes"],
            maxRequests: parsed.flags["max-requests"],
            maxParallel: parsed.flags["max-parallel"],
            maxRate: parsed.flags["max-rate"],
            maxTokens: parsed.flags["max-tokens"],
            retentionDays: parsed.flags["retention-days"],
            hypotheses: listFlag(parsed.flags, "hypotheses"),
            classification: parsed.flags.classification,
            allowedDestinations: listFlag(parsed.flags, "allowed-destinations"),
            secretRefs: listFlag(parsed.flags, "secret-refs"),
            stopOn: listFlag(parsed.flags, "stop-on")
          },
          { paths }
        ),
        json
      );
    }
    if (action === "plan") {
      assertFlags(parsed.flags, ["file", "json"]);
      return output(attachPlan(id, requiredFlag(parsed.flags, "file"), { paths }), json);
    }
    if (action === "authorization") {
      assertFlags(parsed.flags, ["file", "json"]);
      return output(attachAuthorization(id, requiredFlag(parsed.flags, "file"), { paths }), json);
    }
    if (action === "review") {
      assertFlags(parsed.flags, ["run", "head", "result", "json"]);
      return output(
        recordTechnicalReview(
          id,
          {
            run: requiredFlag(parsed.flags, "run"),
            headSha: requiredFlag(parsed.flags, "head"),
            status: requiredFlag(parsed.flags, "result")
          },
          { paths }
        ),
        json
      );
    }
    if (action === "approve") {
      assertFlags(parsed.flags, ["sha", "confirm", "json"]);
      return output(
        approveEngagement(
          id,
          { sha256: requiredFlag(parsed.flags, "sha"), confirm: requiredFlag(parsed.flags, "confirm") },
          { paths }
        ),
        json
      );
    }
    if (action === "check") {
      assertFlags(parsed.flags, ["target", "action", "minutes", "requests", "parallel", "rate", "tokens", "json"]);
      const check = checkEngagement(
        id,
        {
          target: requiredFlag(parsed.flags, "target"),
          action: requiredFlag(parsed.flags, "action"),
          maxMinutes: parsed.flags.minutes,
          estimatedRequests: parsed.flags.requests,
          maxParallel: parsed.flags.parallel,
          maxRatePerSecond: parsed.flags.rate,
          maxTokens: parsed.flags.tokens
        },
        { paths }
      );
      output(check, json);
      if (!check.allowed) process.exitCode = 2;
      return;
    }
    if (action === "manifest") {
      assertFlags(parsed.flags, [
        "workflow", "phase-attempt", "target", "action", "tool", "minutes", "requests", "parallel", "rate",
        "tokens", "evidence-bytes", "json"
      ]);
      if (parsed.passthrough.length === 0) {
        throw new Error("manifest command arguments are required after --");
      }
      return output(
        createExecutionManifest(
          id,
          {
            workflowId: requiredFlag(parsed.flags, "workflow"),
            phaseAttemptId: requiredFlag(parsed.flags, "phase-attempt"),
            target: requiredFlag(parsed.flags, "target"),
            action: requiredFlag(parsed.flags, "action"),
            toolId: requiredFlag(parsed.flags, "tool"),
            argv: parsed.passthrough,
            maxMinutes: requiredFlag(parsed.flags, "minutes"),
            estimatedRequests: requiredFlag(parsed.flags, "requests"),
            maxParallel: requiredFlag(parsed.flags, "parallel"),
            maxRatePerSecond: requiredFlag(parsed.flags, "rate"),
            maxTokens: requiredFlag(parsed.flags, "tokens"),
            maxEvidenceBytes: optionalValueFlag(parsed.flags, "evidence-bytes")
          },
          { paths }
        ),
        json
      );
    }
    if (action === "exec") {
      assertFlags(parsed.flags, ["manifest", "confirm", "json"]);
      if (parsed.passthrough.length > 0) throw new Error("engagement exec does not accept command arguments");
      const result = await executeExecutionManifest(
        id,
        {
          manifestId: requiredFlag(parsed.flags, "manifest"),
          confirm: requiredFlag(parsed.flags, "confirm")
        },
        { paths }
      );
      output(result, json);
      if (!result.ok) process.exitCode = 2;
      return;
    }
    if (action === "reconcile") {
      assertFlags(parsed.flags, ["manifest", "confirm", "json"]);
      if (parsed.passthrough.length > 0) throw new Error("engagement reconcile does not accept command arguments");
      const result = reconcileExecution(
        id,
        {
          manifestId: requiredFlag(parsed.flags, "manifest"),
          confirm: requiredFlag(parsed.flags, "confirm")
        },
        { paths }
      );
      output(result, json);
      if (!result.ok) process.exitCode = 2;
      return;
    }
    if (action === "stop") {
      assertFlags(parsed.flags, ["run", "json"]);
      return output(
        requestExecutionStop(id, { runId: requiredFlag(parsed.flags, "run") }, { paths }),
        json
      );
    }
    if (action === "revoke") {
      assertFlags(parsed.flags, ["confirm", "json"]);
      const engagement = revokeEngagement(
        id,
        { confirm: requiredFlag(parsed.flags, "confirm") },
        { paths }
      );
      const stops = requestEngagementStops(id, { paths });
      return output({ ok: true, engagement, stops }, json);
    }
    if (action === "status") {
      assertFlags(parsed.flags, ["json"]);
      return output(getEngagement(id, { paths }), json);
    }
    if (action === "close") {
      assertFlags(parsed.flags, ["json"]);
      return output(closeEngagement(id, { paths }), json);
    }
    throw new Error(`unknown engagement action: ${action}`);
  }

  if (command === "workflow") {
    assertUnambiguousWorkflowArgs(rest);
    assertBooleanSwitch(parsed.flags, "json");
    const [area, actionOrId, maybeId] = parsed.positional;
    const mutationFlags = ["request", "expected-sequence", "expected-head", "json"];
    if (area === "new") {
      assertPositionals(parsed.positional, 2, "gate workflow new ID [--engagement ID]");
      assertFlags(parsed.flags, ["engagement", "request", "json"]);
      const result = createWorkflowInstance(actionOrId, {
        engagementId: optionalValueFlag(parsed.flags, "engagement")
      }, workflowMutationOptions(parsed.flags, paths));
      return output(result, json);
    }
    if (area === "status") {
      assertPositionals(parsed.positional, 2, "gate workflow status ID");
      assertFlags(parsed.flags, ["json"]);
      const result = workflowStatus(actionOrId, { paths });
      output(result, json);
      if (!result.ok) process.exitCode = 2;
      return;
    }
    if (area === "phase" && actionOrId === "preflight") {
      assertPositionals(parsed.positional, 3, "gate workflow phase preflight ID --phase PHASE --from PHASE --admission FILE [--handoff-id ID] [--handoff FILE]");
      assertFlags(parsed.flags, ["phase", "from", "admission", "handoff", "handoff-id", "json"]);
      const result = preflightWorkflowPhase(maybeId, {
        phaseId: requiredFlag(parsed.flags, "phase"),
        sourcePhase: optionalValueFlag(parsed.flags, "from"),
        admissionFile: requiredFlag(parsed.flags, "admission"),
        handoffFile: optionalValueFlag(parsed.flags, "handoff"),
        handoffId: optionalValueFlag(parsed.flags, "handoff-id")
      }, { paths });
      return output(result, json);
    }
    if (area === "phase" && actionOrId === "start") {
      assertPositionals(parsed.positional, 3, "gate workflow phase start ID --phase PHASE [options]");
      assertFlags(parsed.flags, [
        "phase", "from", "admission", "handoff", "handoff-id", "confirm", ...mutationFlags
      ]);
      const result = startWorkflowPhase(maybeId, {
        phaseId: requiredFlag(parsed.flags, "phase"),
        sourcePhase: optionalValueFlag(parsed.flags, "from"),
        admissionFile: optionalValueFlag(parsed.flags, "admission"),
        handoffFile: optionalValueFlag(parsed.flags, "handoff"),
        handoffId: optionalValueFlag(parsed.flags, "handoff-id"),
        confirm: optionalValueFlag(parsed.flags, "confirm")
      }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "phase" && actionOrId === "finish") {
      assertPositionals(parsed.positional, 3, "gate workflow phase finish ID --phase PHASE --disposition DISPOSITION");
      assertFlags(parsed.flags, ["phase", "disposition", "rationale", "evidence-sha", ...mutationFlags]);
      const result = finishWorkflowPhase(maybeId, {
        phaseId: requiredFlag(parsed.flags, "phase"),
        disposition: requiredFlag(parsed.flags, "disposition"),
        rationale: optionalValueFlag(parsed.flags, "rationale"),
        evidenceSha256: listFlag(parsed.flags, "evidence-sha")
      }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "evidence" && actionOrId === "add") {
      assertPositionals(parsed.positional, 3, "gate workflow evidence add ID --phase PHASE --evidence ID --file PATH");
      assertFlags(parsed.flags, ["phase", "evidence", "file", "claim", ...mutationFlags]);
      const result = addWorkflowEvidence(maybeId, {
        phaseId: requiredFlag(parsed.flags, "phase"),
        evidenceId: requiredFlag(parsed.flags, "evidence"),
        file: requiredFlag(parsed.flags, "file"),
        claimState: optionalValueFlag(parsed.flags, "claim")
      }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "coverage" && actionOrId === "set") {
      assertPositionals(parsed.positional, 3, "gate workflow coverage set ID --domain DOMAIN --disposition DISPOSITION");
      assertFlags(parsed.flags, ["domain", "disposition", "evidence-sha", "rationale", ...mutationFlags]);
      const result = setWorkflowCoverage(maybeId, {
        domain: requiredFlag(parsed.flags, "domain"),
        disposition: requiredFlag(parsed.flags, "disposition"),
        evidenceSha256: listFlag(parsed.flags, "evidence-sha"),
        rationale: optionalValueFlag(parsed.flags, "rationale")
      }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "ledger" && actionOrId === "preflight") {
      assertPositionals(parsed.positional, 3, "gate workflow ledger preflight ID --type pivot [options]");
      assertFlags(parsed.flags, ["type", "target-sha", "before-sha", "cleanup", "pivot-admission", "json"]);
      const result = preflightWorkflowPivot(maybeId, {
        changeType: requiredFlag(parsed.flags, "type"),
        targetSelectorSha256: requiredFlag(parsed.flags, "target-sha"),
        beforeEvidenceSha256: requiredFlag(parsed.flags, "before-sha"),
        cleanupAction: requiredFlag(parsed.flags, "cleanup"),
        pivotAdmissionFile: requiredFlag(parsed.flags, "pivot-admission")
      }, { paths });
      return output(result, json);
    }
    if (area === "ledger" && actionOrId === "open") {
      assertPositionals(parsed.positional, 3, "gate workflow ledger open ID [options]");
      assertFlags(parsed.flags, [
        "type", "target-sha", "before-sha", "cleanup", "pivot-admission", "pivot-confirm", ...mutationFlags
      ]);
      const result = openWorkflowLedger(maybeId, {
        changeType: requiredFlag(parsed.flags, "type"),
        targetSelectorSha256: requiredFlag(parsed.flags, "target-sha"),
        beforeEvidenceSha256: requiredFlag(parsed.flags, "before-sha"),
        cleanupAction: requiredFlag(parsed.flags, "cleanup"),
        pivotAdmissionFile: optionalValueFlag(parsed.flags, "pivot-admission"),
        pivotConfirm: optionalValueFlag(parsed.flags, "pivot-confirm")
      }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "ledger" && actionOrId === "cleanup") {
      assertPositionals(parsed.positional, 3, "gate workflow ledger cleanup ID --entry ID --evidence-sha SHA256");
      assertFlags(parsed.flags, ["entry", "evidence-sha", ...mutationFlags]);
      const result = recordWorkflowLedgerCleanup(maybeId, {
        entryId: requiredFlag(parsed.flags, "entry"),
        cleanupEvidenceSha256: requiredFlag(parsed.flags, "evidence-sha")
      }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "ledger" && actionOrId === "verify") {
      assertPositionals(parsed.positional, 3, "gate workflow ledger verify ID --entry ID --evidence-sha SHA256");
      assertFlags(parsed.flags, ["entry", "evidence-sha", ...mutationFlags]);
      const result = verifyWorkflowLedger(maybeId, {
        entryId: requiredFlag(parsed.flags, "entry"),
        verificationEvidenceSha256: requiredFlag(parsed.flags, "evidence-sha")
      }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "ledger" && actionOrId === "hold") {
      assertPositionals(parsed.positional, 3, "gate workflow ledger hold ID --entry ID --reason TEXT");
      assertFlags(parsed.flags, ["entry", "reason", ...mutationFlags]);
      const result = holdWorkflowLedger(maybeId, {
        entryId: requiredFlag(parsed.flags, "entry"),
        reason: requiredFlag(parsed.flags, "reason")
      }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "execution" && actionOrId === "cancel") {
      assertPositionals(parsed.positional, 3, "gate workflow execution cancel ID --reservation ID --reason TEXT");
      assertFlags(parsed.flags, ["reservation", "reason", ...mutationFlags]);
      const result = cancelWorkflowExecution(maybeId, {
        reservationId: requiredFlag(parsed.flags, "reservation"),
        reason: requiredFlag(parsed.flags, "reason")
      }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "stop") {
      assertPositionals(parsed.positional, 2, "gate workflow stop ID --condition CONDITION --reason TEXT");
      assertFlags(parsed.flags, ["condition", "reason", "evidence-sha", ...mutationFlags]);
      const result = stopWorkflow(actionOrId, {
        condition: requiredFlag(parsed.flags, "condition"),
        reason: requiredFlag(parsed.flags, "reason"),
        evidenceSha256: optionalValueFlag(parsed.flags, "evidence-sha")
      }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "join") {
      assertPositionals(parsed.positional, 2, "gate workflow join ID");
      assertFlags(parsed.flags, mutationFlags);
      const result = joinWorkflowCoverage(actionOrId, {}, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "report") {
      assertPositionals(parsed.positional, 2, "gate workflow report ID --file PATH");
      assertFlags(parsed.flags, ["file", ...mutationFlags]);
      const result = attachWorkflowReport(actionOrId, { file: requiredFlag(parsed.flags, "file") }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    if (area === "close") {
      assertPositionals(parsed.positional, 2, "gate workflow close ID --confirm TEXT");
      assertFlags(parsed.flags, ["confirm", ...mutationFlags]);
      const result = closeWorkflow(actionOrId, { confirm: requiredFlag(parsed.flags, "confirm") }, workflowMutationOptions(parsed.flags, paths));
      return output(workflowCommit(result), json);
    }
    throw new Error(`unknown workflow action: ${parsed.positional.join(" ") || "missing"}`);
  }

  if (command === "upstream") {
    const [action = "list", id] = parsed.positional;
    if (action === "list") {
      assertPositionals(parsed.positional, 1, "gate upstream list");
      assertFlags(parsed.flags, ["json"]);
      return output(upstreamStatus({ paths }), json);
    }
    if (action === "sync") {
      assertPositionals(parsed.positional, 2, "gate upstream sync ID|all");
      assertFlags(parsed.flags, ["json"]);
      if (!id) throw new Error("upstream id is required");
      if (id === "all") {
        const results = [];
        for (const item of upstreamStatus({ paths })) results.push(syncUpstream(item.id, { paths }));
        return output(results, json);
      }
      return output(syncUpstream(id, { paths }), json);
    }
    if (action === "install") {
      assertPositionals(parsed.positional, 2, "gate upstream install ID|all");
      assertFlags(parsed.flags, ["json"]);
      if (!id) throw new Error("upstream id is required");
      if (id === "all") {
        const results = [];
        for (const item of upstreamStatus({ paths }).filter((entry) => ["npm", "github-release"].includes(entry.install?.lane))) {
          results.push(installUpstream(item.id, { paths }));
        }
        return output(results, json);
      }
      return output(installUpstream(id, { paths }), json);
    }
    if (action === "path") {
      assertPositionals(parsed.positional, 2, "gate upstream path ID");
      assertFlags(parsed.flags, ["json"]);
      if (!id) throw new Error("upstream id is required");
      const item = upstreamStatus({ paths }).find((entry) => entry.id === id);
      if (!item) throw new Error(`unknown upstream: ${id}`);
      return output(item.packageReady ? item.toolDirectory : item.directory, json);
    }
    if (action === "exec") {
      throw new Error("raw upstream execution is disabled; use the reviewed upstream directly for local work or add a scope-aware GATE adapter before target contact");
    }
    throw new Error(`unknown upstream action: ${action}`);
  }

  if (command === "tool") {
    assertUnambiguousToolArgs(rest);
    const [action = "list", id] = parsed.positional;
    if (action === "list") {
      assertPositionals(parsed.positional, 1, "gate tool list [--profile ID] [--category ID] [--summary] [--limit N] [--cursor N]");
      assertFlags(parsed.flags, ["profile", "category", "summary", "limit", "cursor", "json"]);
      assertBooleanSwitch(parsed.flags, "summary");
      assertBooleanSwitch(parsed.flags, "json");
      if ((parsed.flags.limit !== undefined || parsed.flags.cursor !== undefined) && parsed.flags.summary !== true) {
        throw new Error("--limit and --cursor require --summary");
      }
      const profile = optionalValueFlag(parsed.flags, "profile");
      const category = optionalValueFlag(parsed.flags, "category");
      const inventory = toolInventory({
        paths,
        profile: profile || null,
        category: category || null
      });
      return output(
        parsed.flags.summary === true
          ? toolInventorySummary(inventory, {
              limit: optionalValueFlag(parsed.flags, "limit"),
              cursor: optionalValueFlag(parsed.flags, "cursor"),
              profile: profile || null,
              category: category || null
            })
          : inventory,
        json
      );
    }
    if (action === "show") {
      assertPositionals(parsed.positional, 2, "gate tool show ID [--json]");
      assertFlags(parsed.flags, ["json"]);
      assertBooleanSwitch(parsed.flags, "json");
      if (!id) throw new Error("security tool id is required");
      return output(toolDetailSummary(toolShow(id, { paths })), json);
    }
    if (action === "plan") {
      assertPositionals(parsed.positional, 2, "gate tool plan ID");
      assertFlags(parsed.flags, ["json"]);
      if (!id) throw new Error("security tool id is required");
      return output(toolPlan(id, { paths }), json);
    }
    if (new Set(["prefetch", "install", "verify", "remove"]).has(action)) {
      assertFlags(parsed.flags, ["profile", "json"]);
      assertBooleanSwitch(parsed.flags, "json");
      const profile = optionalValueFlag(parsed.flags, "profile");
      if (Boolean(id) === Boolean(profile)) {
        throw new Error(`gate tool ${action} requires exactly one tool id or --profile ID`);
      }
      assertPositionals(
        parsed.positional,
        id ? 2 : 1,
        `gate tool ${action} ID|--profile ID [--json]`
      );
      const result = await runManagedToolOperation(action, { paths, id, profile });
      output(result, json);
      if (!result.ok) process.exitCode = 2;
      return;
    }
    throw new Error(`unknown tool action: ${action}`);
  }

  if (command === "publication") {
    const [action = "check"] = parsed.positional;
    assertPositionals(parsed.positional, 1, "gate publication check|dry-run|merge [options]");
    assertFlags(parsed.flags, ["repo", "pr", "head", "run", "mode", "json"]);
    const request = publicationRequest(parsed.flags);
    let result;
    if (action === "check") result = checkPublication(request);
    else if (action === "dry-run") result = publishPullRequest(request, { dryRun: true });
    else if (action === "merge") result = publishPullRequest(request);
    else throw new Error(`unknown publication action: ${action}`);
    const evidenceFile = persistPublicationEvidence(result, paths);
    output({ ...result, evidenceFile }, json);
    if (!result.ok) process.exitCode = 2;
    return;
  }

  throw new Error(`unknown command: ${command}\n\n${help}`);
}
