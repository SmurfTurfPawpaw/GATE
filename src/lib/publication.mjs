import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const API_VERSION = "gate.publication/v1";
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const REPOSITORY_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})\/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$/;
const MAX_REQUIRED_CHECK_CONTEXTS = 100;
const SUCCESSFUL_CHECK_BUCKETS = new Set(["pass"]);
const CHECK_BUCKETS = new Set(["pass", "fail", "pending", "skipping", "cancel"]);
const CHECK_RUN_STATUSES = new Set(["COMPLETED", "IN_PROGRESS", "PENDING", "QUEUED", "REQUESTED", "WAITING"]);
const CHECK_RUN_CONCLUSIONS = new Set([
  "ACTION_REQUIRED",
  "CANCELLED",
  "FAILURE",
  "NEUTRAL",
  "SKIPPED",
  "STALE",
  "STARTUP_FAILURE",
  "SUCCESS",
  "TIMED_OUT"
]);
const PASSING_CHECK_RUN_CONCLUSIONS = new Set(["SUCCESS"]);
const SKIPPING_CHECK_RUN_CONCLUSIONS = new Set(["NEUTRAL", "SKIPPED"]);
const PENDING_CHECK_RUN_CONCLUSIONS = new Set(["STALE", "STARTUP_FAILURE"]);
const CHECK_CONTEXT_TYPES = new Set(["CheckRun", "StatusContext"]);
const FAILING_STATUS_CONTEXT_STATES = new Set(["ERROR", "FAILURE"]);
const STATUS_CONTEXT_STATES = new Set(["ERROR", "EXPECTED", "FAILURE", "PENDING", "SUCCESS"]);
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

const PUBLICATION_QUERY = `query GatePublicationPreflight($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    nameWithOwner
    pullRequest(number: $number) {
      number
      url
      state
      isDraft
      headRefOid
      mergeStateStatus
      mergedAt
      commits(last: 1) {
        totalCount
        nodes {
          commit {
            oid
            statusCheckRollup {
              contexts(first: ${MAX_REQUIRED_CHECK_CONTEXTS}) {
                totalCount
                nodes {
                  __typename
                  ... on CheckRun {
                    name
                    status
                    conclusion
                    detailsUrl
                    isRequired(pullRequestNumber: $number)
                    checkSuite { workflowRun { workflow { name } } }
                  }
                  ... on StatusContext {
                    context
                    state
                    targetUrl
                    isRequired(pullRequestNumber: $number)
                  }
                }
                pageInfo { hasNextPage endCursor }
              }
            }
          }
        }
      }
    }
  }
}`;

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
 * Project the small, trusted pull-request subset used by the publication
 * gate. Unknown fields are deliberately discarded.
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

function checkRunBucket(status, conclusion) {
  if (status !== "COMPLETED") return "pending";
  if (PASSING_CHECK_RUN_CONCLUSIONS.has(conclusion)) return "pass";
  if (SKIPPING_CHECK_RUN_CONCLUSIONS.has(conclusion)) return "skipping";
  if (conclusion === "CANCELLED") return "cancel";
  if (PENDING_CHECK_RUN_CONCLUSIONS.has(conclusion)) return "pending";
  return "fail";
}

function projectWorkflow(value, index) {
  if (value === null || value === undefined) return null;
  const suite = plainObject(value, `required check ${index} check suite`);
  if (suite.workflowRun === null || suite.workflowRun === undefined) return null;
  const run = plainObject(suite.workflowRun, `required check ${index} workflow run`);
  if (run.workflow === null || run.workflow === undefined) return null;
  const workflow = plainObject(run.workflow, `required check ${index} workflow`);
  return boundedString(workflow.name, `required check ${index} workflow name`, 300);
}

function projectRequiredContext(candidate, index) {
  const value = plainObject(candidate, `check context ${index}`);
  const type = boundedString(value.__typename, `check context ${index} type`, 30);
  if (!CHECK_CONTEXT_TYPES.has(type)) {
    throw new TypeError(`unrecognized check context type: ${type}`);
  }
  if (typeof value.isRequired !== "boolean") {
    throw new TypeError(`check context ${index} required state must be boolean`);
  }

  if (type === "CheckRun") {
    const name = boundedString(value.name, `check context ${index} name`, 300);
    const status = boundedString(value.status, `check context ${index} status`, 30).toUpperCase();
    if (!CHECK_RUN_STATUSES.has(status)) throw new TypeError(`unrecognized check run status for ${name}: ${status}`);
    const conclusion = value.conclusion === null || value.conclusion === undefined
      ? null
      : boundedString(value.conclusion, `check context ${index} conclusion`, 30).toUpperCase();
    if (conclusion !== null && !CHECK_RUN_CONCLUSIONS.has(conclusion)) {
      throw new TypeError(`unrecognized check run conclusion for ${name}: ${conclusion}`);
    }
    if (status === "COMPLETED" && conclusion === null) {
      throw new TypeError(`completed check run ${name} must have a conclusion`);
    }
    const projected = {
      name,
      bucket: checkRunBucket(status, conclusion),
      state: conclusion || status,
      workflow: projectWorkflow(value.checkSuite, index),
      link: optionalString(value.detailsUrl, `check context ${index} details URL`, 2_000)
    };
    return value.isRequired ? projected : null;
  }

  const name = boundedString(value.context, `check context ${index} name`, 300);
  const state = boundedString(value.state, `check context ${index} state`, 30).toUpperCase();
  if (!STATUS_CONTEXT_STATES.has(state)) throw new TypeError(`unrecognized status context state for ${name}: ${state}`);
  const projected = {
    name,
    bucket: state === "SUCCESS" ? "pass" : FAILING_STATUS_CONTEXT_STATES.has(state) ? "fail" : "pending",
    state,
    workflow: null,
    link: optionalString(value.targetUrl, `check context ${index} target URL`, 2_000)
  };
  return value.isRequired ? projected : null;
}

/** Project one bounded, exact-PR GraphQL publication response. */
export function projectPublicationResponse(raw, request) {
  const envelope = plainObject(raw, "publication GraphQL response");
  if (envelope.errors !== null && envelope.errors !== undefined) {
    if (!Array.isArray(envelope.errors) || envelope.errors.length > 0) {
      throw new TypeError("publication GraphQL response contains errors");
    }
  }
  const data = plainObject(envelope.data, "publication GraphQL data");
  const repository = plainObject(data.repository, "publication GraphQL repository");
  const repositoryName = boundedString(repository.nameWithOwner, "publication GraphQL repository name", 201);
  if (repositoryName.toLowerCase() !== request.repository.toLowerCase()) {
    throw new TypeError("GitHub returned a different repository");
  }

  const rawPullRequest = plainObject(repository.pullRequest, "publication GraphQL pull request");
  const pullRequest = projectPullRequest(rawPullRequest);
  const commits = plainObject(rawPullRequest.commits, "publication GraphQL commit connection");
  if (!Number.isSafeInteger(commits.totalCount) || commits.totalCount < 1) {
    throw new TypeError("publication GraphQL commit count must be a positive integer");
  }
  if (!Array.isArray(commits.nodes) || commits.nodes.length !== 1) {
    throw new TypeError("publication GraphQL response must contain exactly one latest commit");
  }
  const commitNode = plainObject(commits.nodes[0], "publication GraphQL latest commit node");
  const commit = plainObject(commitNode.commit, "publication GraphQL latest commit");
  const commitOid = boundedString(commit.oid, "publication GraphQL latest commit OID", 40).toLowerCase();
  if (!SHA_PATTERN.test(commitOid)) throw new TypeError("publication GraphQL latest commit OID must be a full SHA");
  if (commitOid !== pullRequest.headSha) {
    throw new TypeError("publication GraphQL check rollup is not bound to the pull request head");
  }

  if (commit.statusCheckRollup === null || commit.statusCheckRollup === undefined) {
    return { pullRequest, requiredChecks: [] };
  }
  const rollup = plainObject(commit.statusCheckRollup, "publication GraphQL status check rollup");
  const contexts = plainObject(rollup.contexts, "publication GraphQL check context connection");
  if (!Number.isSafeInteger(contexts.totalCount) || contexts.totalCount < 0) {
    throw new TypeError("publication GraphQL check context count must be a non-negative integer");
  }
  if (!Array.isArray(contexts.nodes) || contexts.nodes.length > MAX_REQUIRED_CHECK_CONTEXTS) {
    throw new TypeError(`publication GraphQL response exceeds ${MAX_REQUIRED_CHECK_CONTEXTS} check contexts`);
  }
  const pageInfo = plainObject(contexts.pageInfo, "publication GraphQL check context page information");
  if (typeof pageInfo.hasNextPage !== "boolean") {
    throw new TypeError("publication GraphQL check context pagination state must be boolean");
  }
  if (pageInfo.hasNextPage || contexts.totalCount !== contexts.nodes.length) {
    throw new TypeError(`publication GraphQL response exceeds the bounded ${MAX_REQUIRED_CHECK_CONTEXTS}-context page`);
  }

  const requiredChecks = [];
  for (const [index, candidate] of contexts.nodes.entries()) {
    const projected = projectRequiredContext(candidate, index);
    if (projected) requiredChecks.push(projected);
  }
  return { pullRequest, requiredChecks };
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

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mode === right.mode && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function assertProtectedPathChain(file, label) {
  let current = fs.realpathSync.native ? fs.realpathSync.native(file) : fs.realpathSync(file);
  while (true) {
    const stat = fs.lstatSync(current, { bigint: true });
    if (stat.isSymbolicLink()) throw new Error(`${label} path contains a symbolic link: ${current}`);
    if (
      (stat.mode & 0o022n) !== 0n ||
      (typeof process.geteuid === "function" && stat.uid === BigInt(process.geteuid()))
    ) throw new Error(`${label} is controlled by the current process identity: ${current}`);
    try {
      fs.accessSync(current, fs.constants.W_OK);
      throw new Error(`${label} is writable by the current process: ${current}`);
    } catch (error) {
      if (!new Set(["EACCES", "EPERM", "EROFS"]).has(error.code)) throw error;
    }
    const parent = path.dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

function observeProtectedGitHubCli(file) {
  const resolved = fs.realpathSync.native ? fs.realpathSync.native(file) : fs.realpathSync(file);
  const allowed = process.platform === "darwin"
    ? resolved === "/usr/bin/gh" || /^\/(?:opt\/homebrew|usr\/local)\/Cellar\/gh\/[^/]+\/bin\/gh$/u.test(resolved)
    : new Set(["/usr/bin/gh", "/bin/gh", "/usr/local/bin/gh"]).has(resolved);
  if (!allowed) throw new Error(`trusted system GitHub CLI resolved outside an approved location: ${resolved}`);
  assertProtectedPathChain(resolved, "trusted system GitHub CLI");
  if (process.platform !== "win32" && !fs.constants.O_NOFOLLOW) {
    throw new Error("trusted system GitHub CLI cannot be opened without following links on this platform");
  }
  const before = fs.lstatSync(resolved, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || (before.mode & 0o111n) === 0n) {
    throw new Error("trusted system GitHub CLI is not a regular executable");
  }
  const descriptor = fs.openSync(resolved, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    const after = fs.lstatSync(resolved, { bigint: true });
    if (!opened.isFile() || !sameFileIdentity(before, opened) || !sameFileIdentity(opened, after)) {
      throw new Error("trusted system GitHub CLI changed while its identity was checked");
    }
    return { path: resolved, identity: opened };
  } finally {
    fs.closeSync(descriptor);
  }
}

function resolveProtectedGitHubCli() {
  if (process.platform === "win32") {
    throw new Error("protected GitHub CLI execution is unavailable on native Windows; run GATE inside WSL");
  }
  const candidates = process.platform === "darwin"
    ? ["/opt/homebrew/bin/gh", "/usr/local/bin/gh", "/usr/bin/gh"]
    : ["/usr/bin/gh", "/bin/gh", "/usr/local/bin/gh"];
  const failures = [];
  for (const candidate of candidates) {
    try {
      const runtime = observeProtectedGitHubCli(candidate);
      const probe = spawnSync(runtime.path, ["api", "--help"], {
        shell: false,
        encoding: "utf8",
        env: controlledGitHubEnvironment(),
        windowsHide: true,
        timeout: 10_000,
        maxBuffer: 1024 * 1024
      });
      const help = probe.stdout || "";
      const requiredFlags = ["--field", "--hostname", "--method", "--raw-field"];
      if (probe.status !== 0 || requiredFlags.some((flag) => !help.includes(flag))) {
        throw new Error("GitHub CLI lacks required api graphql field support");
      }
      const after = observeProtectedGitHubCli(runtime.path);
      if (!sameFileIdentity(runtime.identity, after.identity)) {
        throw new Error("trusted system GitHub CLI changed during its capability probe");
      }
      return after;
    } catch (error) {
      failures.push(`${candidate}: ${String(error?.message || error)}`);
      // Try the next fixed protected location, then fail closed.
    }
  }
  throw new Error(`no compatible protected system GitHub CLI is available for ${process.platform}: ${failures.join("; ")}`);
}

function protectedGitHubConfigDirectory() {
  const roots = process.platform === "darwin" ? ["/var/empty", "/usr/share"] : ["/usr/share"];
  for (const root of roots) {
    try {
      assertProtectedPathChain(root, "sterile GitHub configuration root");
      const directory = path.join(root, "gate-empty-gh-config");
      try {
        const stat = fs.lstatSync(directory);
        if (stat.isSymbolicLink() || !stat.isDirectory()) {
          throw new Error("sterile GitHub configuration path must be a directory");
        }
        assertProtectedPathChain(directory, "sterile GitHub configuration directory");
        if (fs.readdirSync(directory).length !== 0) {
          throw new Error("sterile GitHub configuration directory must be empty");
        }
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      return directory;
    } catch {
      // Try the next fixed root, then fail closed.
    }
  }
  throw new Error("no protected sterile GitHub configuration location is available");
}

function protectedTlsPath(value, name, expectedType) {
  const entries = expectedType === "directory" ? value.split(path.delimiter) : [value];
  if (!entries.length || entries.some((entry) => !entry || !path.isAbsolute(entry))) {
    throw new Error(`${name} must contain only absolute paths`);
  }
  return entries.map((entry) => {
    const resolved = fs.realpathSync.native ? fs.realpathSync.native(entry) : fs.realpathSync(entry);
    assertProtectedPathChain(resolved, name);
    const stat = fs.lstatSync(resolved);
    if (stat.isSymbolicLink() || (expectedType === "file" ? !stat.isFile() : !stat.isDirectory())) {
      throw new Error(`${name} must resolve to a protected ${expectedType}`);
    }
    return resolved;
  }).join(path.delimiter);
}

function controlledGitHubEnvironment(source = process.env) {
  const sterileConfig = protectedGitHubConfigDirectory();
  const environment = {
    GH_HOST: "github.com",
    GH_PROMPT_DISABLED: "1",
    GH_NO_UPDATE_NOTIFIER: "1",
    LANG: "C",
    LC_ALL: "C",
    NO_COLOR: "1",
    PATH: "/usr/bin:/bin",
    HOME: sterileConfig,
    XDG_CONFIG_HOME: sterileConfig,
    GH_CONFIG_DIR: sterileConfig,
    TMPDIR: "/tmp",
    TMP: "/tmp",
    TEMP: "/tmp"
  };
  for (const name of [
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy"
  ]) {
    if (typeof source[name] === "string") environment[name] = source[name];
  }
  if (typeof source.SSL_CERT_FILE === "string" && source.SSL_CERT_FILE.length) {
    environment.SSL_CERT_FILE = protectedTlsPath(source.SSL_CERT_FILE, "SSL_CERT_FILE", "file");
  }
  if (typeof source.SSL_CERT_DIR === "string" && source.SSL_CERT_DIR.length) {
    environment.SSL_CERT_DIR = protectedTlsPath(source.SSL_CERT_DIR, "SSL_CERT_DIR", "directory");
  }
  return environment;
}

function defaultRunner(command, args, options) {
  if (command !== "gh") throw new Error(`unsupported publication command: ${command}`);
  const runtime = resolveProtectedGitHubCli();
  const result = spawnSync(runtime.path, args, {
    ...options,
    env: controlledGitHubEnvironment()
  });
  const after = observeProtectedGitHubCli(runtime.path);
  if (after.path !== runtime.path || !sameFileIdentity(runtime.identity, after.identity)) {
    throw new Error("trusted system GitHub CLI changed while it was used");
  }
  return result;
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
      env: controlledGitHubEnvironment(),
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
  const [owner, name] = request.repository.split("/");
  const query = runGh(runner, "read-publication-state", [
    "api",
    "graphql",
    "--hostname",
    "github.com",
    "--method",
    "POST",
    "--raw-field",
    `query=${PUBLICATION_QUERY}`,
    "--raw-field",
    `owner=${owner}`,
    "--raw-field",
    `name=${name}`,
    "--field",
    `number=${request.pullRequest}`
  ]);
  evidence.commands.push(query.evidence);
  const projected = parseJson(query, (raw) => projectPublicationResponse(raw, request));
  if (!query.evidence.ok) projected.established = false;
  if (projected.error) {
    evidence.reasons.push(reason("invalid-publication-response", projected.error));
  } else if (!query.evidence.ok) {
    evidence.reasons.push(reason("publication-command-failed", "gh could not establish publication state"));
  }
  evidence.pullRequest = projected.value?.pullRequest || null;
  evidence.requiredChecks = projected.value?.requiredChecks || null;

  const decision = evaluatePublication({
    request,
    pullRequest: evidence.pullRequest,
    requiredChecks: evidence.requiredChecks,
    viewEstablished: projected.established,
    checksEstablished: projected.established
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

export const publicationInternals = Object.freeze({
  controlledGitHubEnvironment,
  defaultRunner,
  publicationQuery: PUBLICATION_QUERY,
  protectedGitHubConfigDirectory,
  protectedTlsPath,
  resolveProtectedGitHubCli
});
