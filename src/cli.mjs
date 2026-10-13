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
  recordTechnicalReview
} from "./lib/engagements.mjs";
import { recordEvent } from "./lib/events.mjs";
import { addLearning } from "./lib/learnings.mjs";
import { ensureRuntime, runtimePaths } from "./lib/paths.mjs";
import { checkPublication, publishPullRequest } from "./lib/publication.mjs";
import { buildStatus } from "./lib/status.mjs";
import { toolInventory, toolPlan } from "./lib/tools.mjs";
import { installUpstream, syncUpstream, upstreamStatus } from "./lib/upstreams.mjs";
import { validateRepository } from "./lib/validation.mjs";

const help = `GATE — Gateway for Agentic Tooling & Engineering

Usage: gate <command> [options]

Core
  bootstrap                         Create private runtime directories and verify config
  doctor [--full] [--json]          Inspect the host, repository, and optional integrations
  status [--json]                   Show activity, tokens, learnings, engagements, and pins
  up [--host 127.0.0.1] [--port 4173]
                                    Run the read-only local cockpit
  validate [--json]                 Validate tracked configuration and pins

Operations
  event <kind> --summary TEXT       Append a sanitized activity event
  learn --cause TEXT --change TEXT [--private] [--scope session|project|repository]
                                    Record one cause → change learning candidate

Engagements
  engagement new ID --targets CSV --actions CSV
  engagement plan ID --file PATH
  engagement authorization ID --file PATH
  engagement review ID --run RUN --head GIT_SHA --result passed|failed
  engagement approve ID --sha SHA256 --confirm "APPROVE ID"
  engagement check ID --target TARGET --action ACTION
  engagement status ID
  engagement close ID

Upstreams
  upstream list
  upstream sync ID|all
  upstream install ID|all              Install integrity-pinned managed upstreams
  upstream path ID                     Print its source or package directory

Security tools
  tool list [--profile ID] [--category ID]
  tool plan ID                         Show host, lane, risk, and admission needs

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
    assertFlags(parsed.flags, ["json"]);
    assertPositionals(parsed.positional, 0, "gate status [--json]");
    return output(await buildStatus({ paths }), json);
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
        "title", "owner", "basis", "targets", "actions", "exclude", "environment", "depth",
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
      assertFlags(parsed.flags, ["target", "action", "json"]);
      const check = checkEngagement(
        id,
        { target: requiredFlag(parsed.flags, "target"), action: requiredFlag(parsed.flags, "action") },
        { paths }
      );
      output(check, json);
      if (!check.allowed) process.exitCode = 2;
      return;
    }
    if (action === "exec") {
      throw new Error("active execution is disabled until a reviewed scope-aware adapter can bind command arguments to the approved target and enforce actual limits");
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
    const [action = "list", id] = parsed.positional;
    if (action === "list") {
      assertPositionals(parsed.positional, 1, "gate tool list [--profile ID] [--category ID]");
      assertFlags(parsed.flags, ["profile", "category", "json"]);
      return output(
        toolInventory({
          paths,
          profile: typeof parsed.flags.profile === "string" ? parsed.flags.profile : null,
          category: typeof parsed.flags.category === "string" ? parsed.flags.category : null
        }),
        json
      );
    }
    if (action === "plan") {
      assertPositionals(parsed.positional, 2, "gate tool plan ID");
      assertFlags(parsed.flags, ["json"]);
      if (!id) throw new Error("security tool id is required");
      return output(toolPlan(id, { paths }), json);
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
