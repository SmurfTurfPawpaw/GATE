import assert from "node:assert/strict";
import test from "node:test";
import {
  checkPublication,
  evaluatePublication,
  projectPullRequest,
  projectRequiredChecks,
  publishPullRequest,
  validatePublicationRequest
} from "../src/lib/publication.mjs";

const HEAD = "a".repeat(40);
const REQUEST = Object.freeze({
  repository: "example/gate",
  pullRequest: 42,
  expectedHead: HEAD,
  noMistakesRunId: "no-mistakes/run-42",
  mergeMode: "squash"
});

function pullRequest(overrides = {}) {
  return {
    number: 42,
    url: "https://github.com/example/gate/pull/42",
    state: "OPEN",
    isDraft: false,
    headRefOid: HEAD,
    mergeStateStatus: "CLEAN",
    mergedAt: null,
    ignored: { untrusted: true },
    ...overrides
  };
}

function checks(overrides = {}) {
  return [
    {
      name: "validate",
      state: "SUCCESS",
      bucket: "pass",
      link: "https://github.com/example/gate/actions/runs/1",
      workflow: "Validate",
      ...overrides
    }
  ];
}

function queuedRunner(responses, calls = []) {
  let index = 0;
  const runner = (command, args, options) => {
    calls.push({ command, args, options });
    const response = responses[index++];
    if (!response) throw new Error(`unexpected command ${command} ${args.join(" ")}`);
    if (response.throw) throw response.throw;
    return {
      status: response.status ?? 0,
      stdout: typeof response.stdout === "string" ? response.stdout : JSON.stringify(response.stdout),
      stderr: response.stderr || ""
    };
  };
  return { runner, calls };
}

test("untrusted GitHub JSON is projected into a bounded representation", () => {
  assert.deepEqual(projectPullRequest(pullRequest()), {
    number: 42,
    url: "https://github.com/example/gate/pull/42",
    state: "OPEN",
    isDraft: false,
    headSha: HEAD,
    mergeState: "CLEAN",
    mergedAt: null
  });
  assert.deepEqual(projectRequiredChecks(checks()), [
    {
      name: "validate",
      bucket: "pass",
      state: "SUCCESS",
      workflow: "Validate",
      link: "https://github.com/example/gate/actions/runs/1"
    }
  ]);
  assert.throws(() => projectPullRequest(pullRequest({ headRefOid: "main" })), /40 lowercase hex/);
  assert.throws(() => projectRequiredChecks([{ name: "validate", bucket: "mystery" }]), /unrecognized bucket/);
});

test("request and state validation fail closed", () => {
  assert.equal(validatePublicationRequest(REQUEST).ok, true);
  assert.deepEqual(
    validatePublicationRequest({ ...REQUEST, noMistakesRunId: "" }).reasons.map((item) => item.code),
    ["missing-no-mistakes-run"]
  );
  assert.deepEqual(
    validatePublicationRequest({ ...REQUEST, mergeMode: "fast-forward" }).reasons.map((item) => item.code),
    ["invalid-merge-mode"]
  );

  const request = validatePublicationRequest(REQUEST).value;
  const projected = projectPullRequest(pullRequest({ isDraft: true, headRefOid: "b".repeat(40) }));
  const decision = evaluatePublication({
    request,
    pullRequest: projected,
    requiredChecks: projectRequiredChecks(checks({ bucket: "pending" }))
  });
  assert.equal(decision.ok, false);
  assert.deepEqual(
    decision.reasons.map((item) => item.code),
    ["pull-request-is-draft", "head-mismatch", "required-check-not-green"]
  );
  assert.equal(
    evaluatePublication({ request, pullRequest: projected, requiredChecks: null, checksEstablished: false }).ok,
    false
  );
});

test("checkPublication is read-only, uses gh without a shell, and returns evidence", () => {
  const fake = queuedRunner([{ stdout: pullRequest() }, { stdout: checks() }]);
  const result = checkPublication(REQUEST, { runner: fake.runner, now: "2026-10-13T12:00:00Z" });

  assert.equal(result.ok, true);
  assert.equal(result.outcome, "ready");
  assert.equal(result.noMistakesRunId, REQUEST.noMistakesRunId);
  assert.equal(fake.calls.length, 2);
  assert.deepEqual(fake.calls.map((call) => call.args.slice(0, 2)), [["pr", "view"], ["pr", "checks"]]);
  for (const call of fake.calls) {
    assert.equal(call.command, "gh");
    assert.equal(call.options.shell, false);
  }
});

test("an unavailable or malformed required-check response blocks publication", () => {
  const unavailable = queuedRunner([
    { stdout: pullRequest() },
    { status: 1, stdout: "", stderr: "network unavailable" }
  ]);
  const unavailableResult = checkPublication(REQUEST, { runner: unavailable.runner });
  assert.equal(unavailableResult.ok, false);
  assert.ok(unavailableResult.reasons.some((item) => item.code === "required-check-state-unavailable"));

  const malformed = queuedRunner([{ stdout: pullRequest() }, { stdout: { unexpected: true } }]);
  const malformedResult = checkPublication(REQUEST, { runner: malformed.runner });
  assert.equal(malformedResult.ok, false);
  assert.ok(malformedResult.reasons.some((item) => item.code === "invalid-required-check-response"));

  const absent = queuedRunner([{ stdout: pullRequest() }, { stdout: [] }]);
  const absentResult = checkPublication(REQUEST, { runner: absent.runner });
  assert.equal(absentResult.ok, false);
  assert.ok(absentResult.reasons.some((item) => item.code === "no-required-checks"));
});

test("dry-run performs the full preflight and never invokes merge", () => {
  const fake = queuedRunner([{ stdout: pullRequest() }, { stdout: checks() }]);
  const result = publishPullRequest(REQUEST, { runner: fake.runner, dryRun: true });

  assert.equal(result.ok, true);
  assert.equal(result.operation, "dry-run");
  assert.equal(result.outcome, "ready");
  assert.equal(fake.calls.length, 2);
  assert.equal(fake.calls.some((call) => call.args[1] === "merge"), false);
});

test("merge remains blocked without a verified external No Mistakes attestation", () => {
  const fake = queuedRunner([{ stdout: pullRequest() }, { stdout: checks() }]);
  const result = publishPullRequest(REQUEST, { runner: fake.runner });

  assert.equal(result.ok, false);
  assert.equal(result.outcome, "blocked");
  assert.equal(result.mutationAttempted, false);
  assert.equal(fake.calls.length, 2);
  assert.equal(fake.calls.some((call) => call.args[1] === "merge"), false);
  assert.ok(result.reasons.some((item) => item.code === "verified-publication-adapter-unavailable"));
});
