import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  createObserver,
  isLoopbackHost,
  projectSnapshot,
  startObserver
} from "../src/observer/server.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const paths = { repo };
const at = "2026-10-13T12:00:00.000Z";

function canonicalEvent(overrides = {}) {
  return {
    apiVersion: "gate.event/v1",
    id: "evt_observer001",
    at,
    runId: "run_CLIENT_CONTEXT_CANARY",
    taskId: "task_CLIENT_CONTEXT_CANARY",
    component: "gate-observer",
    agent: "CLIENT_MEMBER_CANARY",
    kind: "tool.started",
    status: "running",
    summary: "PROMPT_CANARY must stay private",
    effect: {
      class: "network-probe",
      targetRef: "https://target.invalid/private",
      engagementId: "eng_observer",
      planDigest: "a".repeat(64)
    },
    evidenceRefs: ["private://raw-output-canary"],
    usageRef: "usage://observer",
    ...overrides
  };
}

function canonicalLearning(overrides = {}) {
  return {
    apiVersion: "gate.learning/v1",
    id: "lrn_observer001",
    at,
    scope: "repository",
    cause: "A retry exposed https://target.invalid/private and /secret/path with api-key=topsecret and Authorization: Bearer JWT_SUFFIX_CANARY.",
    change: "Classify the retry before recording its result.",
    evidence: ["private://learning-evidence-canary"],
    status: "active",
    sensitivity: "public",
    supersedes: null,
    configurationRefs: ["config/private-canary.json"],
    ...overrides
  };
}

function statusFixture(overrides = {}) {
  return {
    at,
    repository: "/workspace/REPOSITORY_CANARY",
    gate_home: "/home/operator/GATE_HOME_CANARY",
    events: [
      canonicalEvent(),
      canonicalEvent({
        id: "evt_observer002",
        at: "2026-10-13T11:59:59.000Z",
        component: "C:/COMPONENT_PATH_CANARY/tool",
        agent: "home/AGENT_PATH_CANARY"
      })
    ],
    learnings: [
      canonicalLearning(),
      canonicalLearning({
        id: "lrn_observer002",
        scope: "session",
        cause: "PRIVATE_PROMPT_CANARY",
        change: "PRIVATE_CHANGE_CANARY",
        sensitivity: "private"
      })
    ],
    engagements: [
      {
        metadata: { id: "eng_CUSTOMER_CANARY", status: "approved" },
        authorization: { validUntil: "2026-10-14T12:00:00.000Z" },
        review: {
          noMistakes: { status: "passed" },
          operatorReceipt: { status: "approved" }
        },
        limits: { maxTokens: 25000 }
      }
    ],
    upstreams: [],
    tokens: {
      availability: "exact",
      source: "codex-session-jsonl",
      scannedFiles: 1,
      totals: {
        inputTokens: 11,
        cachedInputTokens: 3,
        outputTokens: 6,
        reasoningTokens: 2,
        totalTokens: 17
      },
      records: [
        {
          apiVersion: "gate.usage/v1",
          id: "use_observer001",
          at,
          runId: "codex.observer",
          taskId: null,
          agent: "codex",
          provider: "openai",
          model: "gpt-6",
          availability: "exact",
          measure: "cumulative",
          inputTokens: 11,
          cachedInputTokens: 3,
          outputTokens: 6,
          reasoningTokens: 2,
          totalTokens: 17,
          source: "codex-session-jsonl"
        }
      ]
    },
    ...overrides
  };
}

async function listen(t, statusBuilder, options = {}) {
  const server = await startObserver({
    paths,
    statusBuilder,
    host: "127.0.0.1",
    port: 0,
    refreshMs: 60_000,
    quiet: true,
    ...options
  });
  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
    server.closeAllConnections?.();
  }));
  const address = server.address();
  return { server, origin: `http://127.0.0.1:${address.port}` };
}

function request({ port, method = "GET", pathname = "/", headers = {} }) {
  return new Promise((resolve, reject) => {
    const operation = http.request({ host: "127.0.0.1", port, method, path: pathname, headers }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({
        status: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(chunks).toString("utf8")
      }));
    });
    operation.on("error", reject);
    operation.end();
  });
}

test("observer endpoints coalesce status reads and expose metadata-only projections", async (t) => {
  let calls = 0;
  let release;
  const waiting = new Promise((resolve) => { release = resolve; });
  const { origin } = await listen(t, async () => {
    calls += 1;
    await waiting;
    return statusFixture();
  });

  const responses = ["status", "events", "learnings"].map((name) => fetch(`${origin}/api/${name}`));
  for (let attempt = 0; attempt < 50 && calls === 0; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  release();
  assert.equal(calls, 1, "concurrent endpoint reads should share one buildStatus call");
  const [statusResponse, eventsResponse, learningsResponse] = await Promise.all(responses);
  const [status, events, learnings] = await Promise.all([
    statusResponse.json(),
    eventsResponse.json(),
    learningsResponse.json()
  ]);

  assert.equal(status.apiVersion, "gate.observer/v1");
  assert.equal(status.state, "running");
  assert.equal(status.counts.running, 2);
  assert.equal(status.counts.queued, 0);
  assert.equal(status.agents[0].stage, "tool.started");
  assert.equal(status.agents[0].effect, "network-probe");
  assert.equal(status.agents[0].updatedAt, at);
  assert.match(status.agents[0].id, /^member_[a-f0-9]{16}$/);
  assert.match(status.agents[0].runId, /^run_[a-f0-9]{16}$/);
  assert.match(status.agents[0].taskId, /^task_[a-f0-9]{16}$/);
  assert.equal(status.agents[0].agent, status.agents[0].id);
  assert.equal(status.agents[0].component, "gate-observer");
  assert.match(status.tasks[0].id, /^task_[a-f0-9]{16}$/);
  assert.equal(status.tasks[0].id, status.agents[0].taskId);
  for (const [prefix, raw, projected] of [
    ["member", "CLIENT_MEMBER_CANARY", status.agents[0].id],
    ["run", "run_CLIENT_CONTEXT_CANARY", status.agents[0].runId],
    ["task", "task_CLIENT_CONTEXT_CANARY", status.agents[0].taskId]
  ]) {
    assert.notEqual(
      projected,
      `${prefix}_${crypto.createHash("sha256").update(raw).digest("hex").slice(0, 16)}`,
      `${prefix} pseudonym must use the process key`
    );
  }
  assert.equal(status.usage.availability, "exact");
  assert.equal(status.usage.totalTokens, 17);
  assert.equal(status.usage.model, "gpt-6");
  assert.match(status.usage.sessions[0].id, /^session_[a-f0-9]{16}$/);
  assert.match(status.engagements[0].id, /^engagement_[a-f0-9]{16}$/);
  assert.notEqual(
    status.engagements[0].id,
    `engagement_${crypto.createHash("sha256").update("eng_CUSTOMER_CANARY").digest("hex").slice(0, 16)}`
  );
  assert.equal(status.engagements[0].status, "approved");
  assert.equal(status.engagements[0].preflightOnly, true);
  assert.equal(status.engagements[0].executionAvailable, false);
  assert.equal(status.engagements[0].attestation.operatorProvenance, "local-unverified");

  assert.equal(events.apiVersion, "gate.observer/v1");
  assert.deepEqual(events.events[0].effect, { class: "network-probe" });
  assert.equal(events.events[0].action.category, "tool");
  assert.equal(events.events[0].runId, status.agents[0].runId);
  assert.equal(events.events[0].taskId, status.agents[0].taskId);
  assert.equal(events.events[0].agent, status.agents[0].agent);
  assert.equal(events.events[0].component, "gate-observer");
  assert.equal(learnings.apiVersion, "gate.observer/v1");
  assert.equal(learnings.learnings[1].cause, "Private learning recorded.");
  assert.equal(learnings.learnings[1].change, "Details withheld from observer.");

  const serialized = JSON.stringify({ status, events, learnings });
  for (const canary of [
    "PROMPT_CANARY",
    "PRIVATE_PROMPT_CANARY",
    "PRIVATE_CHANGE_CANARY",
    "run_CLIENT_CONTEXT_CANARY",
    "task_CLIENT_CONTEXT_CANARY",
    "CLIENT_MEMBER_CANARY",
    "target.invalid",
    "/secret/path",
    "topsecret",
    "JWT_SUFFIX_CANARY",
    "raw-output-canary",
    "COMPONENT_PATH_CANARY",
    "AGENT_PATH_CANARY",
    "learning-evidence-canary",
    "private-canary.json",
    "CUSTOMER_CANARY",
    "REPOSITORY_CANARY",
    "GATE_HOME_CANARY"
  ]) {
    assert.equal(serialized.includes(canary), false, `observer leaked ${canary}`);
  }

  for (const response of [statusResponse, eventsResponse, learningsResponse]) {
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(response.headers.get("access-control-allow-origin"), null);
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  }
});

test("missing token telemetry remains unavailable instead of becoming zero", () => {
  const projected = projectSnapshot(statusFixture({
    events: [],
    learnings: [],
    tokens: {
      availability: "unavailable",
      source: "codex-session-jsonl",
      totals: {
        inputTokens: 0,
        cachedInputTokens: 0,
        outputTokens: 0,
        reasoningTokens: 0,
        totalTokens: 0
      },
      records: []
    }
  }), paths);

  assert.equal(projected.status.usage.availability, "unavailable");
  for (const key of ["inputTokens", "cachedInputTokens", "outputTokens", "reasoningTokens", "totalTokens"]) {
    assert.equal(projected.status.usage[key], null);
  }
  assert.equal(projected.status.usage.context.usedTokens, null);
  assert.equal(projected.status.usage.budget.usedTokens, null);
});

test("observer preserves canonical forge and publication effects", () => {
  const neutralEffect = (effectClass) => ({
    class: effectClass,
    targetRef: null,
    engagementId: null,
    planDigest: null
  });
  const projected = projectSnapshot(statusFixture({
    events: [
      canonicalEvent({ id: "evt_publish001", effect: neutralEffect("external-publish") }),
      canonicalEvent({
        id: "evt_forgewrite01",
        at: "2026-10-13T11:59:59.000Z",
        effect: neutralEffect("forge-write")
      })
    ]
  }), paths);

  assert.deepEqual(projected.events.events.map((event) => event.effect.class), ["external-publish", "forge-write"]);
});

test("observer never presents receipt-only or unknown upstream state as verified readiness", () => {
  const projected = projectSnapshot(statusFixture({
    upstreams: [
      { id: "receipt-tool", version: "1.0.0", installed: true, integrityState: "receipt-only", ready: true },
      { id: "commit-tool", version: null, installed: true, integrityState: "commit-only", ready: true },
      { id: "legacy-tool", version: "2.0.0", installed: true, ready: true },
      { id: "verified-tool", version: "3.0.0", installed: true, integrityState: "verified", ready: true }
    ]
  }), paths);

  const [receipt, commit, legacy, verified] = projected.status.upstreams;
  assert.deepEqual(
    [receipt.integrityState, receipt.installed, receipt.ready],
    ["receipt-only", true, false]
  );
  assert.deepEqual([commit.integrityState, commit.ready], ["commit-only", false]);
  assert.deepEqual([legacy.integrityState, legacy.ready], ["unknown", false]);
  assert.deepEqual([verified.integrityState, verified.ready], ["verified", true]);
});

test("observer redacts complete authorization and cookie header values", () => {
  const headers = [
    "Authorization: Digest username=\"SERVER_DIGEST_CANARY\", realm=\"synthetic\", response=\"synthetic\"",
    "Authorization: AWS4-HMAC-SHA256 Credential=SERVER_AWS4_CANARY/20261013/test/aws4_request, SignedHeaders=host;x-date, Signature=synthetic",
    "Cookie: session=SERVER_COOKIE_CANARY; preference=dark",
    "Set-Cookie: session=SERVER_SET_COOKIE_CANARY; Path=/; HttpOnly"
  ];
  const projected = projectSnapshot(statusFixture({
    events: [],
    learnings: headers.map((header, index) => canonicalLearning({
      id: `lrn_header00${index}`,
      cause: `Observed ${header}`
    }))
  }), paths);

  assert.deepEqual(
    projected.learnings.learnings.map((learning) => learning.cause),
    headers.map(() => "Observed [secret withheld]")
  );
  assert.doesNotMatch(JSON.stringify(projected.learnings), /SERVER_(?:DIGEST|AWS4|COOKIE|SET_COOKIE)_CANARY/);
});

test("dashboard routes use an exact allowlist and strict browser headers", async (t) => {
  const { origin } = await listen(t, async () => statusFixture());

  for (const [pathname, type] of [
    ["/", "text/html"],
    ["/dashboard/", "text/html"],
    ["/dashboard/styles.css", "text/css"],
    ["/dashboard/app.js", "text/javascript"],
    ["/dashboard/favicon.svg", "image/svg\\+xml"],
    ["/dashboard/model.js", "text/javascript"]
  ]) {
    const response = await fetch(`${origin}${pathname}`);
    assert.equal(response.status, 200, pathname);
    assert.match(response.headers.get("content-type"), new RegExp(`^${type}`));
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.match(response.headers.get("content-security-policy"), /default-src 'self'/);
    assert.equal(response.headers.get("cross-origin-resource-policy"), "same-origin");
  }

  for (const pathname of ["/dashboard/README.md", "/dashboard/model.test.js", "/package.json", "/dashboard/%2e%2e/package.json"]) {
    const response = await fetch(`${origin}${pathname}`);
    assert.equal(response.status, 404, pathname);
  }
});

test("dashboard assets remain the preloaded snapshot after path substitution", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-observer-static-"));
  const dashboardRoot = path.join(root, "dashboard");
  const asset = path.join(dashboardRoot, "app.js");
  const original = path.join(dashboardRoot, "original.js");
  const privateFile = path.join(root, "outside-dashboard.txt");
  fs.mkdirSync(dashboardRoot);
  fs.writeFileSync(asset, "SAFE_PRELOADED_ASSET", "utf8");
  fs.writeFileSync(privateFile, "STATIC_SUBSTITUTION_CANARY", "utf8");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const { origin } = await listen(t, async () => statusFixture(), { dashboardRoot });
  assert.equal(await (await fetch(`${origin}/dashboard/app.js`)).text(), "SAFE_PRELOADED_ASSET");

  fs.renameSync(asset, original);
  fs.symlinkSync(privateFile, asset);
  const response = await fetch(`${origin}/dashboard/app.js`);
  const body = await response.text();

  assert.equal(response.status, 200);
  assert.equal(body, "SAFE_PRELOADED_ASSET");
  assert.doesNotMatch(body, /STATIC_SUBSTITUTION_CANARY/);
});

test("observer accepts read-only local requests and rejects foreign authorities and origins", async (t) => {
  const { server, origin } = await listen(t, async () => statusFixture());
  const port = server.address().port;

  const head = await fetch(`${origin}/api/status`, { method: "HEAD" });
  assert.equal(head.status, 200);
  assert.equal(await head.text(), "");

  const write = await request({ port, method: "POST", pathname: "/api/status" });
  assert.equal(write.status, 405);
  assert.equal(write.headers.allow, "GET, HEAD");

  const foreignHost = await request({ port, pathname: "/api/status", headers: { Host: "evil.example" } });
  assert.equal(foreignHost.status, 403);
  const foreignOrigin = await request({
    port,
    pathname: "/api/status",
    headers: { Host: `127.0.0.1:${port}`, Origin: "https://evil.example" }
  });
  assert.equal(foreignOrigin.status, 403);
  const crossSiteFetch = await request({
    port,
    pathname: "/api/status",
    headers: { Host: `127.0.0.1:${port}`, "Sec-Fetch-Site": "cross-site" }
  });
  assert.equal(crossSiteFetch.status, 403);

  assert.equal(isLoopbackHost("127.0.0.42"), true);
  assert.equal(isLoopbackHost("::1"), true);
  assert.equal(isLoopbackHost("localhost"), true);
  assert.equal(isLoopbackHost("0.0.0.0"), false);
  assert.equal(isLoopbackHost("127.example"), false);
  assert.throws(() => createObserver({ paths, host: "0.0.0.0" }), /loopback/);
});

test("status failures return a generic service error without exception details", async (t) => {
  const { origin } = await listen(t, () => {
    throw new Error("SENSITIVE_BUILDER_FAILURE");
  });
  const response = await fetch(`${origin}/api/status`);
  assert.equal(response.status, 503);
  const body = await response.text();
  assert.match(body, /observer status unavailable/);
  assert.doesNotMatch(body, /SENSITIVE_BUILDER_FAILURE/);
});
