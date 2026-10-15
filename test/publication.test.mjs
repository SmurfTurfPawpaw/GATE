import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  checkPublication,
  evaluatePublication,
  publicationInternals,
  projectChecks,
  projectPublicationResponse,
  projectPullRequest,
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

function checkRun(overrides = {}) {
  return {
    __typename: "CheckRun",
    name: "validate",
    status: "COMPLETED",
    conclusion: "SUCCESS",
    detailsUrl: "https://github.com/example/gate/actions/runs/1",
    checkSuite: { workflowRun: { workflow: { name: "Validate" } } },
    ...overrides
  };
}

function publicationResponse({
  repository = "example/gate",
  pullRequestOverrides = {},
  commitOid = pullRequestOverrides.headRefOid || HEAD,
  contexts = [checkRun()],
  contextTotal = contexts.length,
  hasNextPage = false,
  statusCheckRollup = undefined,
  errors = undefined
} = {}) {
  const response = {
    data: {
      repository: {
        nameWithOwner: repository,
        pullRequest: {
          ...pullRequest(pullRequestOverrides),
          commits: {
            totalCount: 3,
            nodes: [
              {
                commit: {
                  oid: commitOid,
                  statusCheckRollup: statusCheckRollup === undefined
                    ? {
                        contexts: {
                          totalCount: contextTotal,
                          nodes: contexts,
                          pageInfo: { hasNextPage, endCursor: hasNextPage ? "cursor" : null }
                        }
                      }
                    : statusCheckRollup
                }
              }
            ]
          }
        }
      }
    }
  };
  if (errors !== undefined) response.errors = errors;
  return response;
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
  assert.deepEqual(projectChecks(checks()), [
    {
      name: "validate",
      bucket: "pass",
      state: "SUCCESS",
      workflow: "Validate",
      link: "https://github.com/example/gate/actions/runs/1"
    }
  ]);
  assert.throws(() => projectPullRequest(pullRequest({ headRefOid: "main" })), /40 lowercase hex/);
  assert.throws(() => projectChecks([{ name: "validate", bucket: "mystery" }]), /unrecognized bucket/);

  assert.deepEqual(projectPublicationResponse(publicationResponse(), REQUEST), {
    pullRequest: {
      number: 42,
      url: "https://github.com/example/gate/pull/42",
      state: "OPEN",
      isDraft: false,
      headSha: HEAD,
      mergeState: "CLEAN",
      mergedAt: null
    },
    checks: checks()
  });
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
    checks: projectChecks(checks({ bucket: "pending" }))
  });
  assert.equal(decision.ok, false);
  assert.deepEqual(
    decision.reasons.map((item) => item.code),
    ["pull-request-is-draft", "head-mismatch", "check-not-green"]
  );
  assert.equal(
    evaluatePublication({ request, pullRequest: projected, checks: null, checksEstablished: false }).ok,
    false
  );
});

test("checkPublication is read-only, uses gh without a shell, and returns evidence", () => {
  const fake = queuedRunner([{ stdout: publicationResponse() }]);
  const result = checkPublication(REQUEST, { runner: fake.runner, now: "2026-10-13T12:00:00Z" });

  assert.equal(result.ok, true);
  assert.equal(result.outcome, "ready");
  assert.equal(result.noMistakesRunId, REQUEST.noMistakesRunId);
  assert.equal(result.apiVersion, "gate.publication/v2");
  assert.equal(fake.calls.length, 1);
  assert.equal(publicationInternals.publicationQuery.includes("isRequired"), false);
  assert.deepEqual(fake.calls[0].args.slice(0, 2), ["api", "graphql"]);
  for (const call of fake.calls) {
    assert.equal(call.command, "gh");
    assert.equal(call.options.shell, false);
    assert.equal(call.args.includes("github.com"), true);
    assert.equal(call.args.includes("owner=example"), true);
    assert.equal(call.args.includes("name=gate"), true);
    assert.equal(call.args.includes("number=42"), true);
    assert.equal(call.args.includes(`query=${publicationInternals.publicationQuery}`), true);
  }
});

test("publication preserves literal-looking repository strings at the gh boundary", () => {
  for (const literal of ["123", "true", "false", "null"]) {
    for (const repository of [`example/${literal}`, `${literal}/gate`]) {
      for (const invoke of [checkPublication, publishPullRequest]) {
        const fake = queuedRunner([{ stdout: publicationResponse({ repository }) }]);
        const result = invoke({ ...REQUEST, repository }, { runner: fake.runner, dryRun: true });
        assert.equal(result.ok, true);
        assert.equal(fake.calls.length, 1);
        const args = fake.calls[0].args;
        const [owner, name] = repository.split("/");
        assert.equal(args[args.indexOf(`owner=${owner}`) - 1], "--raw-field");
        assert.equal(args[args.indexOf(`name=${name}`) - 1], "--raw-field");
        assert.equal(args[args.indexOf("number=42") - 1], "--field");
      }
    }
  }
});

test("publication remains sterile when the host makes /usr/share writable", (t) => {
  const accessSync = fs.accessSync;
  t.mock.method(fs, "accessSync", (file, mode) => {
    // Hosted runners may grant the test user write access to shared tool data.
    if (file === "/usr/share" && mode === fs.constants.W_OK) return;
    return accessSync(file, mode);
  });
  const fake = queuedRunner([{ stdout: publicationResponse() }]);
  const result = checkPublication(REQUEST, { runner: fake.runner });
  assert.equal(result.ok, true);
  assert.equal(fake.calls.length, 1);
  const environment = fake.calls[0].options.env;
  assert.ok(["/etc/gate-empty-gh-config", "/var/empty/gate-empty-gh-config"].includes(environment.GH_CONFIG_DIR));
  assert.equal(environment.HOME, environment.GH_CONFIG_DIR);
  assert.equal(environment.XDG_CONFIG_HOME, environment.GH_CONFIG_DIR);
});

test("publication child environment keeps only reviewed authentication and network inputs", (t) => {
  if (!fs.existsSync("/etc/ssl/certs/ca-certificates.crt") || !fs.existsSync("/etc/ssl/certs")) {
    return t.skip("this host does not expose the distribution CA bundle paths used by the WSL2 contract");
  }
  const environment = publicationInternals.controlledGitHubEnvironment({
    PATH: "/tmp/hostile-bin",
    HOME: "/home/operator",
    GH_CONFIG_DIR: "/home/operator/.config/gh",
    GH_TOKEN: "PUBLICATION_TOKEN_CANARY",
    HTTPS_PROXY: "http://proxy.example.test:8080",
    SSL_CERT_FILE: "/etc/ssl/certs/ca-certificates.crt",
    SSL_CERT_DIR: "/etc/ssl/certs",
    GH_HOST: "attacker.example.test",
    NODE_OPTIONS: "--require=/tmp/hostile.cjs",
    LD_PRELOAD: "/tmp/hostile.so",
    GATE_AMBIENT_SECRET: "AMBIENT_SECRET_CANARY"
  });

  assert.equal(environment.PATH, "/usr/bin:/bin");
  assert.equal(environment.HOME, publicationInternals.protectedGitHubConfigDirectory());
  assert.equal(environment.XDG_CONFIG_HOME, environment.HOME);
  assert.equal(environment.GH_CONFIG_DIR, environment.HOME);
  assert.notEqual(environment.HOME, "/home/operator");
  assert.equal(environment.GH_HOST, "github.com");
  assert.equal(environment.GH_TOKEN, "PUBLICATION_TOKEN_CANARY");
  assert.equal(environment.HTTPS_PROXY, "http://proxy.example.test:8080");
  assert.equal(environment.SSL_CERT_FILE, "/etc/ssl/certs/ca-certificates.crt");
  assert.equal(environment.SSL_CERT_DIR, "/etc/ssl/certs");
  for (const name of ["NODE_OPTIONS", "LD_PRELOAD", "GATE_AMBIENT_SECRET"]) {
    assert.equal(Object.hasOwn(environment, name), false, `${name} must not reach GitHub CLI`);
  }
});

test("publication rejects a user-writable TLS trust anchor", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-publication-ca-"));
  const ca = path.join(root, "operator-ca.pem");
  fs.writeFileSync(ca, "TEST CA\n", { mode: 0o600 });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  assert.throws(
    () => publicationInternals.controlledGitHubEnvironment({ HTTPS_PROXY: "http://proxy.example.test", SSL_CERT_FILE: ca }),
    /SSL_CERT_FILE.*controlled by the current process identity/u
  );

  const previous = process.env.SSL_CERT_FILE;
  process.env.SSL_CERT_FILE = ca;
  const fake = queuedRunner([]);
  try {
    const result = checkPublication(REQUEST, { runner: fake.runner });
    assert.equal(result.ok, false);
    assert.equal(result.outcome, "blocked");
    assert.equal(result.mutationAttempted, false);
    assert.equal(fake.calls.length, 0);
    assert.equal(result.commands.every((command) => /SSL_CERT_FILE.*controlled by the current process identity/u.test(command.error)), true);
  } finally {
    if (previous === undefined) delete process.env.SSL_CERT_FILE;
    else process.env.SSL_CERT_FILE = previous;
  }
});

test("the default publication runner ignores PATH and supports GraphQL on gh 2.46", (t) => {
  if (process.platform === "win32") return t.skip("protected publication execution requires WSL2 on Windows");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-publication-path-"));
  const fake = path.join(root, "gh");
  const marker = path.join(root, "captured-token.txt");
  fs.writeFileSync(fake, `#!/bin/sh\nprintf '%s' "$GH_TOKEN" > '${marker}'\nexit 97\n`, { mode: 0o700 });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const names = ["PATH", "GH_TOKEN", "NODE_OPTIONS", "LD_PRELOAD"];
  const previous = Object.fromEntries(names.map((name) => [name, process.env[name]]));
  t.after(() => {
    for (const name of names) {
      if (previous[name] === undefined) delete process.env[name];
      else process.env[name] = previous[name];
    }
  });
  process.env.PATH = root;
  process.env.GH_TOKEN = "PUBLICATION_TOKEN_CANARY";
  process.env.NODE_OPTIONS = `--require=${path.join(root, "missing-preload.cjs")}`;
  process.env.LD_PRELOAD = path.join(root, "missing-preload.so");

  const runtime = publicationInternals.resolveProtectedGitHubCli();
  assert.equal(path.isAbsolute(runtime.path), true);
  assert.notEqual(runtime.path, fake);
  const result = publicationInternals.defaultRunner("gh", ["--version"], {
    shell: false,
    encoding: "utf8",
    timeout: 10_000,
    maxBuffer: 1024 * 1024
  });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  assert.equal(fs.existsSync(marker), false, "PATH-first gh must never receive the publication token");
});

test("ambient GitHub configuration cannot redirect publication evidence from github.com", (t) => {
  const fake = queuedRunner([{ stdout: publicationResponse() }]);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-hostile-gh-config-"));
  fs.writeFileSync(path.join(root, "config.yml"), "http_unix_socket: /tmp/attacker.sock\n", { mode: 0o600 });
  const names = ["GH_HOST", "GH_CONFIG_DIR", "XDG_CONFIG_HOME", "HOME"];
  const previous = Object.fromEntries(names.map((name) => [name, process.env[name]]));
  t.after(() => {
    fs.rmSync(root, { recursive: true, force: true });
    for (const name of names) {
      if (previous[name] === undefined) delete process.env[name];
      else process.env[name] = previous[name];
    }
  });
  process.env.GH_HOST = "attacker.example.test";
  process.env.GH_CONFIG_DIR = root;
  process.env.XDG_CONFIG_HOME = root;
  process.env.HOME = root;
  const result = checkPublication(REQUEST, { runner: fake.runner });
  assert.equal(result.ok, true);
  assert.equal(fake.calls.length, 1);
  const [call] = fake.calls;
  assert.equal(call.options.env.GH_HOST, "github.com");
  assert.equal(call.options.env.GH_CONFIG_DIR, publicationInternals.protectedGitHubConfigDirectory());
  assert.notEqual(call.options.env.GH_CONFIG_DIR, root);
  assert.deepEqual(call.args.slice(call.args.indexOf("--hostname"), call.args.indexOf("--hostname") + 2), [
    "--hostname",
    "github.com"
  ]);
  assert.equal(call.args.includes("owner=example"), true);
  assert.equal(call.args.includes("name=gate"), true);
});

test("an unavailable, malformed, or empty exact-head check response blocks publication", () => {
  const unavailable = queuedRunner([{ status: 1, stdout: "", stderr: "network unavailable" }]);
  const unavailableResult = checkPublication(REQUEST, { runner: unavailable.runner });
  assert.equal(unavailableResult.ok, false);
  assert.ok(unavailableResult.reasons.some((item) => item.code === "check-state-unavailable"));

  const malformed = queuedRunner([{ stdout: { unexpected: true } }]);
  const malformedResult = checkPublication(REQUEST, { runner: malformed.runner });
  assert.equal(malformedResult.ok, false);
  assert.ok(malformedResult.reasons.some((item) => item.code === "invalid-publication-response"));

  const absent = queuedRunner([{ stdout: publicationResponse({ contexts: [] }) }]);
  const absentResult = checkPublication(REQUEST, { runner: absent.runner });
  assert.equal(absentResult.ok, false);
  assert.ok(absentResult.reasons.some((item) => item.code === "no-checks"));

  const noRollup = queuedRunner([{ stdout: publicationResponse({ statusCheckRollup: null }) }]);
  const noRollupResult = checkPublication(REQUEST, { runner: noRollup.runner });
  assert.equal(noRollupResult.ok, false);
  assert.ok(noRollupResult.reasons.some((item) => item.code === "no-checks"));
});

test("GraphQL publication state is exact-head-bound, protection-independent, and bounded", () => {
  const optionalFailure = checkRun({ name: "optional", conclusion: "FAILURE" });
  const legacy = {
    __typename: "StatusContext",
    context: "legacy",
    state: "SUCCESS",
    targetUrl: "https://github.com/example/gate/status/1"
  };
  const blockedOptional = checkPublication(REQUEST, {
    runner: queuedRunner([{ stdout: publicationResponse({ contexts: [optionalFailure, checkRun(), legacy] }) }]).runner
  });
  assert.equal(blockedOptional.ok, false);
  assert.deepEqual(blockedOptional.checks.map((check) => check.name), ["optional", "validate", "legacy"]);
  assert.ok(blockedOptional.reasons.some(({ code }) => code === "check-not-green"));

  const unprotectedReady = checkPublication(REQUEST, {
    runner: queuedRunner([{ stdout: publicationResponse({ contexts: [
      checkRun({ name: "Node 22.20.0" }),
      checkRun({ name: "Node 24.x" })
    ] }) }]).runner
  });
  assert.equal(unprotectedReady.ok, true);
  assert.deepEqual(unprotectedReady.checks.map((check) => check.name), ["Node 22.20.0", "Node 24.x"]);

  for (const conclusion of ["ACTION_REQUIRED", "CANCELLED", "FAILURE", "NEUTRAL", "SKIPPED", "STALE", "STARTUP_FAILURE", "TIMED_OUT"]) {
    const nonSuccess = checkPublication(REQUEST, {
      runner: queuedRunner([{ stdout: publicationResponse({ contexts: [checkRun({ conclusion })] }) }]).runner
    });
    assert.equal(nonSuccess.ok, false, conclusion);
    assert.notEqual(nonSuccess.checks[0].bucket, "pass", conclusion);
    assert.ok(nonSuccess.reasons.some(({ code }) => code === "check-not-green"), conclusion);
  }

  const running = checkPublication(REQUEST, {
    runner: queuedRunner([{ stdout: publicationResponse({ contexts: [checkRun({ status: "IN_PROGRESS", conclusion: null })] }) }]).runner
  });
  assert.equal(running.ok, false);
  assert.equal(running.checks[0].bucket, "pending");
  assert.ok(running.reasons.some(({ code }) => code === "check-not-green"));

  for (const response of [
    publicationResponse({ commitOid: "b".repeat(40) }),
    publicationResponse({ hasNextPage: true, contextTotal: 101 }),
    publicationResponse({ contextTotal: 2 }),
    publicationResponse({ errors: [{ type: "FORBIDDEN" }] }),
    publicationResponse({ repository: "attacker/other" })
  ]) {
    const blocked = checkPublication(REQUEST, { runner: queuedRunner([{ stdout: response }]).runner });
    assert.equal(blocked.ok, false);
    assert.ok(blocked.reasons.some((item) => item.code === "invalid-publication-response"));
  }
});

test("dry-run performs the full preflight and never invokes merge", () => {
  const fake = queuedRunner([{ stdout: publicationResponse() }]);
  const result = publishPullRequest(REQUEST, { runner: fake.runner, dryRun: true });

  assert.equal(result.ok, true);
  assert.equal(result.operation, "dry-run");
  assert.equal(result.outcome, "ready");
  assert.equal(fake.calls.length, 1);
  assert.equal(fake.calls.some((call) => call.args[1] === "merge"), false);
});

test("merge remains blocked without a verified external No Mistakes attestation", () => {
  const fake = queuedRunner([{ stdout: publicationResponse() }]);
  const result = publishPullRequest(REQUEST, { runner: fake.runner });

  assert.equal(result.ok, false);
  assert.equal(result.outcome, "blocked");
  assert.equal(result.mutationAttempted, false);
  assert.equal(fake.calls.length, 1);
  assert.equal(fake.calls.some((call) => call.args[1] === "merge"), false);
  assert.ok(result.reasons.some((item) => item.code === "verified-publication-adapter-unavailable"));
});
