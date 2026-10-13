import { spawnSync } from "node:child_process";

const API_VERSION = "gate.publication/v1";
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const REPOSITORY_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})\/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$/;
const SUCCESSFUL_CHECK_BUCKETS = new Set(["pass"]);
const CHECK_BUCKETS = new Set(["pass", "fail", "pending", "skipping", "cancel"]);
const PR_STATES = new Set(["OPEN", "CLOSED", "MERGED"]);
const MERGE_STATES = new Set([
  "BEHIND",
  "BLOCKED",
  "CLEAN",
  "DIRTY",
  "DRAFT",
  "HAS_HOOKS",
  "UNKNOWN",
  "UNSTABLE"
]);

export const MERGE_MODES = Object.freeze(["merge", "squash", "rebase"]);

function reason(code, message) {
  return { code, message };
}

function plainObject(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object`);
  }
  return value;
}

function boundedString(value, name, maximum = 500) {
  if (typeof value !== "string" || !value.length || value.length > maximum || /[\r\n\0]/.test(value)) {
    throw new TypeError(`${name} must be a non-empty single-line string no longer than ${maximum} characters`);
  }
  return value;
}

function optionalString(value, name, maximum = 500) {
  if (value === null || value === undefined || value === "") return null;
  return boundedString(value, name, maximum);
}

function normalizeTimestamp(value, name) {
  if (value === null || value === undefined) return null;
  const text = boundedString(value, name, 100);
  if (!Number.isFinite(Date.parse(text))) throw new TypeError(`${name} must be an ISO-compatible timestamp or null`);
  return text;
}

/**
 * Project the small, trusted subset of a `gh pr view --json` response used by
 * the publication gate. Unknown fields are deliberately discarded.
 */
export function projectPullRequest(raw) {
  const value = plainObject(raw, "pull request response");
  if (!Number.isInteger(value.number) || value.number < 1) {
    throw new TypeError("pull request number must be a positive integer");
  }
  const state = boundedString(value.state, "pull request state", 20).toUpperCase();
  if (!PR_STATES.has(state)) throw new TypeError(`unrecognized pull request state: ${state}`);
  if (typeof value.isDraft !== "boolean") throw new TypeError("pull request draft state must be boolean");
  const headSha = boundedString(value.headRefOid, "pull request head SHA", 40).toLowerCase();
  if (!SHA_PATTERN.test(headSha)) throw new TypeError("pull request head SHA must contain exactly 40 lowercase hex characters");
  const mergeState = boundedString(value.mergeStateStatus, "pull request merge state", 30).toUpperCase();
  if (!MERGE_STATES.has(mergeState)) throw new TypeError(`unrecognized pull request merge state: ${mergeState}`);

  return {
    number: value.number,
    url: optionalString(value.url, "pull request URL", 2_000),
    state,
    isDraft: value.isDraft,
    headSha,
    mergeState,
    mergedAt: normalizeTimestamp(value.mergedAt, "pull request mergedAt")
  };
}

/** Project and validate the required-check response from GitHub CLI. */
export function projectRequiredChecks(raw) {
  if (!Array.isArray(raw)) throw new TypeError("required checks response must be an array");
  return raw.map((candidate, index) => {
    const value = plainObject(candidate, `required check ${index}`);
    const name = boundedString(value.name, `required check ${index} name`, 300);
    const bucket = boundedString(value.bucket, `required check ${index} bucket`, 30).toLowerCase();
    if (!CHECK_BUCKETS.has(bucket)) throw new TypeError(`unrecognized bucket for required check ${name}: ${bucket}`);
    return {
      name,
      bucket,
      state: optionalString(value.state, `required check ${index} state`, 100),
      workflow: optionalString(value.workflow, `required check ${index} workflow`, 300),
      link: optionalString(value.link, `required check ${index} link`, 2_000)
    };
  });
}

/** Pure request validation. No command is run until this succeeds. */
export function validatePublicationRequest(input) {
  const errors = [];
  const value = {};
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { ok: false, value: null, reasons: [reason("invalid-request", "publication request must be an object")] };
  }

  if (typeof input.repository !== "string" || !REPOSITORY_PATTERN.test(input.repository)) {
    errors.push(reason("invalid-repository", "repository must be an owner/name GitHub repository identifier"));
  } else {
    value.repository = input.repository;
  }

  const pullRequest = typeof input.pullRequest === "string" && /^\d+$/.test(input.pullRequest)
    ? Number(input.pullRequest)
    : input.pullRequest;
  if (!Number.isSafeInteger(pullRequest) || pullRequest < 1) {
    errors.push(reason("invalid-pull-request", "pullRequest must be a positive integer"));
  } else {
    value.pullRequest = pullRequest;
  }

  if (typeof input.expectedHead !== "string" || !SHA_PATTERN.test(input.expectedHead)) {
    errors.push(reason("invalid-expected-head", "expectedHead must contain exactly 40 lowercase hex characters"));
  } else {
    value.expectedHead = input.expectedHead;
  }

  if (
    typeof input.noMistakesRunId !== "string" ||
    !input.noMistakesRunId.trim().length ||
    input.noMistakesRunId.length > 200 ||
    /[\r\n\0]/.test(input.noMistakesRunId)
  ) {
    errors.push(reason("missing-no-mistakes-run", "a single-line No Mistakes run id is required"));
  } else {
    value.noMistakesRunId = input.noMistakesRunId;
  }

  if (!MERGE_MODES.includes(input.mergeMode)) {
    errors.push(reason("invalid-merge-mode", `mergeMode must be one of: ${MERGE_MODES.join(", ")}`));
  } else {
    value.mergeMode = input.mergeMode;
  }

  return { ok: errors.length === 0, value: errors.length ? null : value, reasons: errors };
}

/**
 * Pure fail-closed evaluation of a projected PR and its required checks.
 * `viewEstablished` and `checksEstablished` let callers distinguish an empty
 * required-check list from an unavailable check list.
 */
export function evaluatePublication({
  request,
  pullRequest,
  requiredChecks,
  viewEstablished = true,
  checksEstablished = true
}) {
  const reasons = [];

  if (!viewEstablished || !pullRequest) {
    reasons.push(reason("pull-request-state-unavailable", "GitHub pull request state could not be established"));
  } else {
    if (pullRequest.number !== request.pullRequest) {
      reasons.push(reason("pull-request-number-mismatch", "GitHub returned a different pull request number"));
    }
    if (pullRequest.state !== "OPEN") {
      reasons.push(reason("pull-request-not-open", `pull request state is ${pullRequest.state}`));
    }
    if (pullRequest.isDraft) {
      reasons.push(reason("pull-request-is-draft", "draft pull requests cannot be published"));
    }
    if (pullRequest.headSha !== request.expectedHead) {
      reasons.push(reason("head-mismatch", "pull request head does not match the expected immutable head"));
    }
    if (pullRequest.mergeState !== "CLEAN") {
      reasons.push(reason("merge-state-not-clean", `pull request merge state is ${pullRequest.mergeState}`));
    }
  }

  if (!checksEstablished || !Array.isArray(requiredChecks)) {
    reasons.push(reason("required-check-state-unavailable", "required check state could not be established"));
  } else if (requiredChecks.length === 0) {
    reasons.push(reason("no-required-checks", "the pull request has no required checks to validate"));
  } else {
    for (const check of requiredChecks) {
      if (!SUCCESSFUL_CHECK_BUCKETS.has(check.bucket)) {
        reasons.push(reason("required-check-not-green", `required check ${check.name} is ${check.bucket}`));
      }
    }
  }

  return { ok: reasons.length === 0, reasons };
}

function defaultRunner(command, args, options) {
  return spawnSync(command, args, options);
}

function textOutput(value) {
  if (Buffer.isBuffer(value)) return value.toString("utf8");
  return typeof value === "string" ? value : "";
}

function runGh(runner, operation, args) {
  let result;
  try {
    result = runner("gh", args, {
      shell: false,
      encoding: "utf8",
      windowsHide: true,
      timeout: 60_000,
      maxBuffer: 1024 * 1024
    });
    if (result && typeof result.then === "function") throw new TypeError("publication command runner must be synchronous");
  } catch (error) {
    return {
      output: "",
      evidence: {
        operation,
        command: "gh",
        args: [...args],
        exitCode: null,
        ok: false,
        error: String(error?.message || error).slice(0, 500)
      }
    };
  }

  const exitCode = Number.isInteger(result?.status)
    ? result.status
    : Number.isInteger(result?.exitCode)
      ? result.exitCode
      : null;
  const processError = result?.error ? String(result.error.message || result.error).slice(0, 500) : null;
  return {
    output: textOutput(result?.stdout),
    evidence: {
      operation,
      command: "gh",
      args: [...args],
      exitCode,
      ok: exitCode === 0 && !processError,
      error: processError
    }
  };
}

function parseJson(command, projector) {
  try {
    return { established: true, value: projector(JSON.parse(command.output)), error: null };
  } catch (error) {
    return { established: false, value: null, error: String(error?.message || error).slice(0, 500) };
  }
}

function timestamp(now) {
  const candidate = typeof now === "function" ? now() : now;
  const date = candidate === undefined ? new Date() : candidate instanceof Date ? candidate : new Date(candidate);
  if (!Number.isFinite(date.getTime())) throw new TypeError("now must resolve to a valid date");
  return date.toISOString();
}

function baseEvidence(operation, checkedAt, request, requestReasons = []) {
  return {
    apiVersion: API_VERSION,
    kind: "PublicationEvidence",
    operation,
    checkedAt,
    repository: request?.repository || null,
    pullRequestNumber: request?.pullRequest || null,
    expectedHead: request?.expectedHead || null,
    noMistakesRunId: request?.noMistakesRunId || null,
    mergeMode: request?.mergeMode || null,
    pullRequest: null,
    requiredChecks: null,
    commands: [],
    mutationAttempted: false,
    outcome: "blocked",
    ok: false,
    reasons: requestReasons
  };
}

function inspectPublication(request, runner, checkedAt, operation) {
  const evidence = baseEvidence(operation, checkedAt, request);
  const reference = String(request.pullRequest);
  const common = [reference, "--repo", request.repository];
  const view = runGh(runner, "read-pull-request", [
    "pr",
    "view",
    ...common,
    "--json",
    "number,url,state,isDraft,headRefOid,mergeStateStatus,mergedAt"
  ]);
  evidence.commands.push(view.evidence);
  const projectedView = parseJson(view, projectPullRequest);
  if (!view.evidence.ok) projectedView.established = false;
  if (projectedView.error) {
    evidence.reasons.push(reason("invalid-pull-request-response", projectedView.error));
  } else if (!view.evidence.ok) {
    evidence.reasons.push(reason("pull-request-command-failed", "gh could not read the pull request"));
  }
  evidence.pullRequest = projectedView.value;

  const checks = runGh(runner, "read-required-checks", [
    "pr",
    "checks",
    ...common,
    "--required",
    "--json",
    "name,state,bucket,link,workflow"
  ]);
  evidence.commands.push(checks.evidence);
  const projectedChecks = parseJson(checks, projectRequiredChecks);
  if (!checks.evidence.ok) projectedChecks.established = false;
  if (projectedChecks.error) {
    evidence.reasons.push(reason("invalid-required-check-response", projectedChecks.error));
  } else if (!checks.evidence.ok) {
    evidence.reasons.push(reason("required-check-command-failed", "gh could not establish required check state"));
  }
  evidence.requiredChecks = projectedChecks.value;

  const decision = evaluatePublication({
    request,
    pullRequest: projectedView.value,
    requiredChecks: projectedChecks.value,
    viewEstablished: projectedView.established,
    checksEstablished: projectedChecks.established
  });
  evidence.reasons.push(...decision.reasons);
  evidence.ok = evidence.reasons.length === 0;
  evidence.outcome = evidence.ok ? "ready" : "blocked";
  return evidence;
}

/** Perform the read-only GitHub publication preflight. */
export function checkPublication(input, options = {}) {
  const checkedAt = timestamp(options.now);
  const validated = validatePublicationRequest(input);
  if (!validated.ok) return baseEvidence("check", checkedAt, input, validated.reasons);
  return inspectPublication(validated.value, options.runner || defaultRunner, checkedAt, "check");
}

/**
 * Run the exact read-only publication preflight. Mutation remains fail closed
 * until a trusted adapter can verify a No Mistakes attestation for the exact
 * head. A caller-supplied run label is provenance, not authorization.
 */
export function publishPullRequest(input, options = {}) {
  const checkedAt = timestamp(options.now);
  const validated = validatePublicationRequest(input);
  const operation = options.dryRun ? "dry-run" : "merge";
  if (!validated.ok) return baseEvidence(operation, checkedAt, input, validated.reasons);

  const request = validated.value;
  const runner = options.runner || defaultRunner;
  const evidence = inspectPublication(request, runner, checkedAt, operation);
  if (!evidence.ok || options.dryRun) return evidence;
  evidence.ok = false;
  evidence.outcome = "blocked";
  evidence.reasons.push(
    reason(
      "verified-publication-adapter-unavailable",
      "merge is disabled until a trusted adapter verifies a No Mistakes attestation bound to this exact head"
    )
  );
  return evidence;
}
