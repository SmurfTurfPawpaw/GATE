import fs from "node:fs";
import path from "node:path";
import { loadConfig } from "./config.mjs";
import { readCtfPilotStatus } from "./ctf-pilot.mjs";
import { caseFleetStatus, openCaseRuntime } from "./cases.mjs";
import { executionStatus } from "./executions.mjs";
import { readJsonLines } from "./jsonl.mjs";
import { offlineAnalysisStatus } from "./offline-analysis.mjs";
import { ensureRuntime, runtimePaths } from "./paths.mjs";
import { readPrivateFileBounded } from "./private-fs.mjs";
import { projectRegistryStatus } from "./projects.mjs";
import { validateDocument } from "./schema.mjs";
import { scanCodexUsage } from "./tokens.mjs";
import { managedToolSummary } from "./tool-runtimes.mjs";
import { upstreamStatus } from "./upstreams.mjs";
import { workflowFleetStatus } from "./workflow-runtime.mjs";

const MAX_ENGAGEMENT_BYTES = 2 * 1024 * 1024;
const MAX_ENGAGEMENT_DISCOVERY = 4096;
const MAX_ENGAGEMENT_PROJECTION = 64;

function statusSelection(options, paths) {
  const requested = options.selectionMode ?? (paths.caseId ? "case" : "aggregate");
  if (!new Set(["aggregate", "unassigned", "case"]).has(requested)) {
    throw new Error("status selection mode must be aggregate, unassigned, or case");
  }
  if (paths.caseId && requested !== "case") {
    throw new Error("case-scoped status requires case selection mode");
  }
  if (!paths.caseId && requested === "case") {
    throw new Error("case status selection requires a case-scoped runtime");
  }
  return requested;
}

function unscannedCaseFleet() {
  return {
    limit: 0,
    discoveryLimit: 0,
    discovered: 0,
    scanned: 0,
    omitted: 0,
    discoveredAtLeast: false,
    omittedAtLeast: false,
    complete: false,
    truncated: false,
    invalid: 0,
    attempted: false
  };
}

function omittedEngagementProjection() {
  return {
    engagements: [],
    scan: {
      availability: "not-loaded",
      reason: "aggregate-case-detail-elided",
      recordsRead: 0,
      complete: false
    }
  };
}

function sameRuntimePathValue(left, right) {
  if (left === null || right === null) return left === right;
  if (typeof left === "string" && typeof right === "string") {
    return path.resolve(left) === path.resolve(right);
  }
  return Object.is(left, right);
}

function exactStatusPaths(options) {
  if (options.paths === undefined) return runtimePaths(options);
  const supplied = options.paths;
  if (!supplied || typeof supplied !== "object" || Array.isArray(supplied)) {
    throw new Error("status paths must be a runtime path object");
  }
  const expected = runtimePaths({
    home: supplied.home,
    repo: supplied.repo,
    caseId: supplied.caseId,
    stateHome: supplied.stateHome,
    env: options.env
  });
  for (const [key, derived] of Object.entries(expected)) {
    if (!Object.hasOwn(supplied, key)) continue;
    if (!sameRuntimePathValue(supplied[key], derived)) {
      throw new Error(`status runtime path does not match its derived location: ${key}`);
    }
  }
  return expected;
}

function canonicalUsageRecords(values, paths, partial = false) {
  const records = new Map();
  for (const value of values) {
    if (!validateDocument(value, "token-usage.schema.json", { paths }).ok) continue;
    // Repeated reads or retries can append the same canonical record. Its ID is
    // the idempotency boundary, so retain one copy rather than counting it twice.
    records.delete(value.id);
    records.set(
      value.id,
      partial && value.availability !== "unavailable" ? { ...value, availability: "estimated" } : value
    );
  }
  return [...records.values()];
}

function operatorStatus(paths) {
  const { config } = loadConfig({ paths });
  const validation = validateDocument(config, "gate-config.schema.json", { paths });
  if (!validation.ok) throw new Error(`GATE config validation failed: ${validation.errors.join("; ")}`);
  return { displayName: config.operator.displayName };
}

function boundedEngagements(paths) {
  const discoveredNames = [];
  let discoveryTruncated = false;
  const directory = fs.opendirSync(paths.engagements);
  try {
    while (discoveredNames.length <= MAX_ENGAGEMENT_DISCOVERY) {
      const entry = directory.readSync();
      if (!entry) break;
      discoveredNames.push(entry.name);
    }
    discoveryTruncated = discoveredNames.length > MAX_ENGAGEMENT_DISCOVERY;
  } finally {
    directory.closeSync();
  }

  const inspected = discoveredNames.slice(0, MAX_ENGAGEMENT_DISCOVERY);
  const candidates = inspected.filter((name) => name.endsWith(".json")).sort();
  const selected = candidates.slice(0, MAX_ENGAGEMENT_PROJECTION);
  let invalid = inspected.length - candidates.length;
  const engagements = selected.map((name) => {
    try {
      return JSON.parse(readPrivateFileBounded(
        path.join(paths.engagements, name),
        MAX_ENGAGEMENT_BYTES,
        "utf8",
        { label: `private engagement status ${name}` }
      ));
    } catch {
      invalid += 1;
      return { id: name, status: "invalid" };
    }
  });
  const projectionTruncated = candidates.length > selected.length;
  return {
    engagements,
    scan: {
      limit: MAX_ENGAGEMENT_PROJECTION,
      discoveryLimit: MAX_ENGAGEMENT_DISCOVERY,
      entriesInspected: inspected.length,
      discoveredAtLeast: candidates.length,
      scanned: selected.length,
      omittedAtLeast: Math.max(0, candidates.length - selected.length),
      invalid,
      complete: !discoveryTruncated && !projectionTruncated && invalid === 0,
      truncated: discoveryTruncated || projectionTruncated,
      discoveryTruncated
    }
  };
}

async function buildRuntimeStatus(paths, options = {}) {
  ensureRuntime(paths);
  const observedAt = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
  const includeShared = options.includeShared !== false;
  const tokenRead = {};
  const [events, publicLearnings, privateLearnings, tokenLog] = await Promise.all([
    readJsonLines(paths.events, { limit: 100, privateFile: true }),
    includeShared ? readJsonLines(paths.publicLearningRecords, { limit: 100 }) : [],
    readJsonLines(paths.privateLearnings, { limit: 100, privateFile: true }),
    readJsonLines(paths.tokens, { limit: 500, metadata: tokenRead, privateFile: true })
  ]);
  const tokenLogPartial = tokenRead.byteTruncated || tokenRead.limitTruncated ||
    tokenLog.some((value) => value?.kind === "invalid-jsonl");
  const recordedTokens = canonicalUsageRecords(tokenLog, paths, tokenLogPartial);
  // A canonical feed can contain usage derived from these same Codex session
  // files. Prefer it wholesale when present; summing both sources would claim
  // usage twice. The host/session-root scan remains the discovery fallback.
  // Host-wide Codex session discovery has no trustworthy case binding. Only
  // the unscoped status lane may use it as a fallback; case lanes remain
  // unavailable until a reviewed producer writes case-bound token records.
  const tokens = recordedTokens.length
    ? recordedTokens
    : options.scanHostTokens === false
      ? []
      : await scanCodexUsage(options.tokens || {});
  // Aggregate case terminals need lane state, not private engagement bodies.
  // Avoid opening those records during fleet refreshes; selected-case status
  // remains the explicit detail surface and retains the bounded record read.
  const engagementProjection = options.includeEngagements === false
    ? omittedEngagementProjection()
    : boundedEngagements(paths);
  const ctfPilot = readCtfPilotStatus({ paths, now: observedAt });
  return {
    // Capture the enclosing snapshot after all component reads. A worker may
    // publish while status is being assembled; using the start time would make
    // that legitimate component update appear to come from the future.
    at: options.now === undefined ? new Date().toISOString() : observedAt.toISOString(),
    repository: paths.repo,
    gate_home: paths.home,
    events: events.slice(-30).reverse(),
    learnings: [...publicLearnings, ...privateLearnings]
      .sort((left, right) => Date.parse(left.at || 0) - Date.parse(right.at || 0))
      .slice(-30)
      .reverse(),
    engagements: engagementProjection.engagements,
    engagementScan: engagementProjection.scan,
    execution: executionStatus({
      paths,
      now: observedAt,
      includeExecutionMirror: options.includeExecutionMirror === true
    }),
    workflows: workflowFleetStatus({ paths, runtimeEnsured: true }),
    ctfPilot,
    offlineAnalysis: offlineAnalysisStatus({ paths }),
    projects: includeShared ? projectRegistryStatus({ paths }) : [],
    tokens,
    upstreams: includeShared ? upstreamStatus({ paths, verifyIntegrity: false }) : [],
    // Observer/status refreshes use validated installation receipts. They do
    // not reread large executables and never present that cached evidence as a
    // current verification. Explicit tool verify, doctor --full, planning and
    // pre-execution paths retain exact current-byte checks.
    toolRuntimes: includeShared
      ? managedToolSummary({
          paths,
          staticIntegrity: false,
          now: observedAt
        })
      : null
  };
}

export async function buildStatus(options = {}) {
  const requestedPaths = exactStatusPaths(options);
  const selectionMode = statusSelection(options, requestedPaths);
  if (requestedPaths.caseId) {
    // Never trust a caller-supplied scoped path table as the case identity.
    // Open the immutable case record from the base registry, then use only the
    // exact scoped table returned by that operation. openCaseRuntime keeps a
    // structurally valid stale case observable for stop and cleanup work while
    // rejecting phantom, relabelled, or state-marker-mismatched cases.
    const basePaths = runtimePaths({
      home: requestedPaths.home,
      repo: requestedPaths.repo,
      env: options.env
    });
    const opened = openCaseRuntime(requestedPaths.caseId, { paths: basePaths, now: options.now });
    const selectedCase = await buildRuntimeStatus(opened.paths, {
      ...options,
      scanHostTokens: false,
      includeShared: false
    });
    return {
      ...selectedCase,
      operator: operatorStatus(opened.paths),
      selection: {
        mode: "case",
        caseId: opened.case.metadata.id,
        bindingHealth: { ...opened.bindingHealth }
      },
      selectedCaseId: opened.case.metadata.id,
      cases: [],
      caseScan: unscannedCaseFleet()
    };
  }

  const paths = requestedPaths;
  const base = await buildRuntimeStatus(paths, { ...options, scanHostTokens: true, includeShared: true });
  if (selectionMode === "unassigned") {
    return {
      ...base,
      operator: operatorStatus(paths),
      selection: { mode: "unassigned", caseId: null },
      selectedCaseId: null,
      cases: [],
      caseScan: unscannedCaseFleet()
    };
  }
  const fleet = caseFleetStatus({ paths, now: options.now });
  const cases = [];
  for (const item of fleet.cases) {
    if (item.status === "invalid" || !item.id) {
      cases.push({
        ...item,
        runtimeHealth: { status: "unavailable", reason: "invalid-case" },
        runtime: null
      });
      continue;
    }
    try {
      const opened = openCaseRuntime(item.id, { paths, now: options.now });
      const runtime = await buildRuntimeStatus(opened.paths, {
        ...options,
        scanHostTokens: false,
        includeShared: false,
        includeEngagements: false
      });
      cases.push({
        ...item,
        status: opened.bindingHealth.status,
        binding: {
          program: { ...item.binding.program, current: opened.bindingHealth.programCurrent },
          project: item.binding.project === null
            ? null
            : { ...item.binding.project, current: opened.bindingHealth.projectCurrent }
        },
        runtimeHealth: { status: "available", reason: null },
        runtime
      });
    } catch {
      // A case may change or become unreadable between the bounded fleet scan
      // and runtime observation. Its independently verified binding status is
      // still truthful; report runtime availability as a separate dimension.
      cases.push({
        ...item,
        runtimeHealth: { status: "unavailable", reason: "runtime-observation-failed" },
        runtime: null
      });
    }
  }
  return {
    ...base,
    operator: operatorStatus(paths),
    selection: { mode: "aggregate", caseId: null },
    selectedCaseId: null,
    cases,
    caseScan: { ...fleet.scan, attempted: true }
  };
}
