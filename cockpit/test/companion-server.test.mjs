import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import http from "node:http";
import test from "node:test";

import { ActivityStore } from "../companion/activity.mjs";
import { createUnavailableFleetProvider } from "../companion/gate-fleet.mjs";
import { startCompanionServer } from "../companion/server.mjs";

function request({ port, pathname = "/", method = "GET", headers = {}, body = "" }) {
  return new Promise((resolve, reject) => {
    const call = http.request({ hostname: "127.0.0.1", port, path: pathname, method, headers }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({
        status: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(chunks).toString("utf8")
      }));
    });
    call.on("error", reject);
    if (body) call.end(body);
    else call.end();
  });
}

class FakeAdapter extends EventEmitter {
  activityStore = new ActivityStore();
  messages = [];
  questions = [];
  closed = false;
  sessionRevision = 41;
  stateRevision = 1;

  constructor() { super(); }

  async sendMessage(value) { this.messages.push(value); }
  async answerQuestion(value) { this.questions.push(value); }
  privateState() {
    return {
      apiVersion: "gate.local-companion-state/v1",
      sessionRevision: this.sessionRevision,
      stateRevision: this.stateRevision,
      observedAt: new Date().toISOString(),
      connected: true,
      turn: "idle",
      tokens: null,
      conversation: [],
      pendingQuestions: []
    };
  }
  async close() { this.closed = true; }
}

function credentials(started) {
  const url = new URL(started.url);
  const fragment = new URLSearchParams(url.hash.slice(1));
  return { session: fragment.get("session"), csrf: fragment.get("csrf") };
}

async function post(started, pathname, value, auth = credentials(started)) {
  const body = JSON.stringify(value);
  return request({
    port: started.port,
    pathname,
    method: "POST",
    headers: {
      Host: `127.0.0.1:${started.port}`,
      Origin: started.origin,
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(body),
      "X-GATE-Session": auth.session,
      "X-GATE-CSRF": auth.csrf
    },
    body
  });
}

test("loopback companion injects its bridge before the public app without embedding capabilities", async (t) => {
  const adapter = new FakeAdapter();
  const started = await startCompanionServer({ adapter });
  t.after(() => started.close());
  assert.match(started.url, /^http:\/\/127\.0\.0\.1:\d+\/#session=[A-Za-z0-9_-]+&csrf=[A-Za-z0-9_-]+$/u);

  const page = await request({ port: started.port, headers: { Host: `127.0.0.1:${started.port}` } });
  assert.equal(page.status, 200);
  assert.ok(page.body.indexOf("./companion/client.js") < page.body.indexOf("./assets/app.js"));
  assert.doesNotMatch(page.body, new RegExp(credentials(started).session, "u"));
  assert.equal(page.headers["cache-control"], "no-store, max-age=0");
  assert.match(page.headers["content-security-policy"], /connect-src 'self'/u);
});

test("message submission requires the local session, same-origin CSRF, and exact idempotency", async (t) => {
  const adapter = new FakeAdapter();
  const started = await startCompanionServer({ adapter });
  t.after(() => started.close());
  const value = {
    apiVersion: "gate.local-message-request/v1",
    requestId: "request-12345678",
    sessionRevision: adapter.sessionRevision,
    message: "Continue with the reviewed plan."
  };

  const missing = await post(started, "/api/message", value, { session: "missing", csrf: "missing" });
  assert.equal(missing.status, 401);
  const first = await post(started, "/api/message", value);
  assert.equal(first.status, 202);
  assert.deepEqual(JSON.parse(first.body), {
    apiVersion: "gate.local-cockpit-receipt/v1",
    requestId: value.requestId,
    status: "accepted"
  });
  const replay = await post(started, "/api/message", value);
  assert.equal(replay.status, 202);
  assert.equal(adapter.messages.length, 1);

  const changed = await post(started, "/api/message", { ...value, message: "Different" });
  assert.equal(changed.status, 409);
  assert.equal(adapter.messages.length, 1);

  adapter.sessionRevision += 1;
  const replaced = await post(started, "/api/message", { ...value, requestId: "request-12345679" });
  assert.equal(replaced.status, 409);
  assert.equal(adapter.messages.length, 1);
});

test("private chat works independently of public snapshots", async (t) => {
  const adapter = new FakeAdapter();
  const started = await startCompanionServer({ adapter });
  t.after(() => started.close());
  const value = {
    apiVersion: "gate.local-message-request/v1",
    requestId: "request-abcdefgh",
    sessionRevision: adapter.sessionRevision,
    message: "Continue"
  };
  assert.equal((await post(started, "/api/message", value)).status, 202);
  assert.equal(adapter.messages.length, 1);


  assert.equal((await post(started, "/api/decision", {})).status, 405);
});

test("native question replies are bound to the private session and idempotent", async (t) => {
  const adapter = new FakeAdapter();
  const started = await startCompanionServer({ adapter });
  t.after(() => started.close());
  const value = {
    apiVersion: "gate.local-question-response/v1",
    requestId: "request-question1",
    sessionRevision: adapter.sessionRevision,
    questionToken: `q_${"a".repeat(43)}`,
    answers: {
      scope: "Recommended (Recommended)",
      depth: "Deep"
    }
  };
  assert.equal((await post(started, "/api/question", value)).status, 202);
  assert.equal((await post(started, "/api/question", value)).status, 202);
  assert.equal(adapter.questions.length, 1);
  adapter.sessionRevision += 1;
  assert.equal((await post(started, "/api/question", { ...value, requestId: "request-question2" })).status, 409);
});

test("private state and event stream require the fragment-derived session capability", async (t) => {
  const adapter = new FakeAdapter();
  const started = await startCompanionServer({ adapter });
  t.after(() => started.close());
  const auth = credentials(started);
  const missing = await request({
    port: started.port,
    pathname: "/api/private-state",
    headers: { Host: `127.0.0.1:${started.port}` }
  });
  assert.equal(missing.status, 401);
  const accepted = await request({
    port: started.port,
    pathname: "/api/private-state",
    headers: { Host: `127.0.0.1:${started.port}`, "X-GATE-Session": auth.session }
  });
  assert.equal(accepted.status, 200);
  assert.equal(JSON.parse(accepted.body).state.connected, true);
});

test("private fleet projection requires the fragment session and stays on its read-only endpoint", async (t) => {
  const adapter = new FakeAdapter();
  let providerCalls = 0;
  const unavailable = createUnavailableFleetProvider({ now: () => Date.parse("2026-10-16T14:40:00.000Z") });
  const started = await startCompanionServer({
    adapter,
    fleetProvider: async () => {
      providerCalls += 1;
      return unavailable();
    }
  });
  t.after(() => started.close());
  const auth = credentials(started);
  const missing = await request({
    port: started.port,
    pathname: "/api/fleet",
    headers: { Host: `127.0.0.1:${started.port}` }
  });
  assert.equal(missing.status, 401);
  assert.equal(providerCalls, 0, "unauthenticated callers must not trigger observer reads");

  const accepted = await request({
    port: started.port,
    pathname: "/api/fleet",
    headers: { Host: `127.0.0.1:${started.port}`, "X-GATE-Session": auth.session }
  });
  assert.equal(accepted.status, 200);
  assert.equal(accepted.headers["cache-control"], "no-store, max-age=0");
  assert.deepEqual(JSON.parse(accepted.body), {
    ok: true,
    fleet: {
      apiVersion: "gate.local-fleet/v1",
      revision: 1,
      observedAt: null,
      receivedAt: "2026-10-16T14:40:00.000Z",
      connection: "unavailable",
      sourceFreshness: "unavailable",
      coverage: {
        state: "unavailable",
        cases: {
          availability: "unavailable", discovered: null, scanned: null, omitted: null, invalid: null,
          discoveredAtLeast: false, omittedAtLeast: false, complete: false, truncated: true
        },
        profiles: {
          availability: "unavailable", discovered: null, scanned: null, omitted: null, invalid: null,
          discoveredAtLeast: false, omittedAtLeast: false, complete: false, truncated: true,
          visible: null, representedByCases: null
        }
      },
      summary: {
        campaigns: { value: null, precision: "unavailable" },
        active: { value: null, precision: "unavailable" },
        waiting: { value: null, precision: "unavailable" },
        attention: { value: null, precision: "unavailable" },
        profileAnswers: { answered: null, total: null, precision: "unavailable" },
        runningExecutions: { value: null, precision: "unavailable" },
        activeWorkflows: { value: null, precision: "unavailable" },
        runningAnalyses: { value: null, precision: "unavailable" },
        setupBlockers: { value: null, precision: "unavailable" },
        campaignTokens: { availability: "unavailable", total: null },
        hostTokens: {
          availability: "unavailable", input: null, cachedInput: null, output: null, total: null,
          cost: { availability: "unavailable", amountMicros: null, unit: null }
        }
      },
      campaigns: []
    }
  });
  assert.equal(providerCalls, 1);
  assert.equal(adapter.messages.length + adapter.questions.length, 0);
});

test("authenticated event streams remain open beyond the ordinary request timeout", async (t) => {
  const adapter = new FakeAdapter();
  const started = await startCompanionServer({
    adapter,
    requestTimeoutMs: 50
  });
  t.after(() => started.close());
  const auth = credentials(started);
  let call;
  const received = new Promise((resolve, reject) => {
    call = http.request({
      hostname: "127.0.0.1",
      port: started.port,
      path: "/api/events",
      headers: {
        Host: `127.0.0.1:${started.port}`,
        Accept: "text/event-stream",
        "X-GATE-Session": auth.session
      }
    }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => {
        body += chunk;
        if (body.includes('"category":"testing"')) resolve({ response, body });
      });
      response.on("error", reject);
    });
    call.on("error", reject);
    call.end();
  });
  await new Promise((resolve) => setTimeout(resolve, 125));
  adapter.activityStore.append({ category: "testing", state: "started" });
  const result = await Promise.race([
    received,
    new Promise((_, reject) => setTimeout(() => reject(new Error("event stream closed or stalled")), 2_000))
  ]);
  assert.equal(result.response.statusCode, 200);
  assert.match(result.body, /event: activity/u);
  call.destroy();
});

test("foreign Host, Origin, and cross-site browser requests fail closed", async (t) => {
  const adapter = new FakeAdapter();
  const started = await startCompanionServer({ adapter });
  t.after(() => started.close());
  assert.equal((await request({
    port: started.port,
    headers: { Host: "attacker.example" }
  })).status, 421);
  assert.equal((await request({
    port: started.port,
    headers: { Host: `127.0.0.1:${started.port}`, Origin: "https://attacker.example" }
  })).status, 403);
  assert.equal((await request({
    port: started.port,
    headers: { Host: `127.0.0.1:${started.port}`, "Sec-Fetch-Site": "cross-site" }
  })).status, 403);
});
