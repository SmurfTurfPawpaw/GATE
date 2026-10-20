import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { signRunnerRequest } from "../runner-auth.mjs";
import { serverCliInternals } from "../server-cli.mjs";
import { startRemoteCockpitServer } from "../server.mjs";
import { SessionStore } from "../sessions.mjs";
import { RemoteBridgeStore } from "../store.mjs";

const ORIGIN = "https://gate.example";
const OPERATOR_ID = "operator@example";
const CASE_ID = "demo-case";
const SESSION_REVISION = 7;
const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

function remoteCliConfig(keyPath, databasePath) {
  return {
    apiVersion: "gate.remote-server-config/v1",
    origin: ORIGIN,
    host: "127.0.0.1",
    port: 8443,
    operatorId: OPERATOR_ID,
    caseId: CASE_ID,
    sessionRevision: SESSION_REVISION,
    databasePath,
    identityAssertionHeader: "cf-access-jwt-assertion",
    oidc: {
      issuer: "https://identity.example",
      audience: "gate-audience",
      operatorSubject: OPERATOR_ID,
      jwksUrl: "https://identity.example/.well-known/jwks.json"
    },
    runner: { id: "runner-main", publicKeyPath: keyPath }
  };
}

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

function externalHeaders(extra = {}) {
  return { Host: "gate.example", "X-Forwarded-Proto": "https", ...extra };
}

function cookieFrom(response) {
  const value = response.headers["set-cookie"]?.[0];
  assert.match(value, /^__Host-gate-session=[A-Za-z0-9_-]{43};/u);
  return value.split(";", 1)[0];
}

async function makeFixture(t, overrides = {}) {
  const { storeOptions = {}, ...serverOverrides } = overrides;
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "gate-remote-server-"));
  fs.chmodSync(directory, 0o700);
  const store = new RemoteBridgeStore({ databasePath: path.join(directory, "bridge.sqlite"), ...storeOptions });
  const keys = crypto.generateKeyPairSync("ed25519");
  let verificationCount = 0;
  const oidcVerifier = {
    async verify(assertion) {
      verificationCount += 1;
      if (assertion !== "verified-assertion") throw new Error("invalid test assertion");
      return Object.freeze({
        issuer: "https://identity.example",
        subject: OPERATOR_ID,
        audience: "gate",
        algorithm: "EdDSA",
        keyId: "test-key",
        issuedAt: Math.floor(Date.now() / 1_000),
        expiresAt: Math.floor(Date.now() / 1_000) + 300
      });
    }
  };
  const started = await startRemoteCockpitServer({
    origin: ORIGIN,
    host: "127.0.0.1",
    port: 0,
    operatorId: OPERATOR_ID,
    caseId: CASE_ID,
    sessionRevision: SESSION_REVISION,
    store,
    oidcVerifier,
    runnerPublicKeys: new Map([["runner-main", keys.publicKey]]),
    closeStore: true,
    ssePollMs: 100,
    sseKeepAliveMs: 1_000,
    sseMaxDurationMs: 5_000,
    ...serverOverrides
  });
  t.after(async () => {
    await started.close();
    fs.rmSync(directory, { recursive: true, force: true });
  });
  return { started, store, privateKey: keys.privateKey, verificationCount: () => verificationCount };
}

async function login(fixture) {
  const response = await request({
    port: fixture.started.port,
    pathname: "/api/cockpit/v1/session",
    headers: externalHeaders({
      "X-GATE-OIDC-Assertion": "verified-assertion", "Sec-Fetch-Site": "same-origin", Accept: "application/json"
    })
  });
  assert.equal(response.status, 200, response.body);
  const session = JSON.parse(response.body);
  assert.deepEqual(Object.keys(session).sort(), ["apiVersion", "caseId", "csrf", "expiresAt", "sessionRevision"].sort());
  assert.equal(session.apiVersion, "gate.remote-cockpit-session/v1");
  assert.equal(session.caseId, CASE_ID);
  assert.equal(session.sessionRevision, SESSION_REVISION);
  assert.match(session.csrf, /^[A-Za-z0-9_-]{43}$/u);
  return { cookie: cookieFrom(response), session, response };
}

async function browserPost(fixture, auth, pathname, value, headers = {}) {
  const body = JSON.stringify(value);
  return request({
    port: fixture.started.port,
    pathname,
    method: "POST",
    headers: externalHeaders({
      Cookie: auth.cookie,
      Origin: ORIGIN,
      "Sec-Fetch-Site": "same-origin",
      "X-GATE-CSRF": auth.session.csrf,
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(body),
      ...headers
    }),
    body
  });
}

async function runnerPost(fixture, pathname, value, { privateKey = fixture.privateKey, mutateHeaders } = {}) {
  const body = JSON.stringify(value);
  let signed = signRunnerRequest({ runnerId: "runner-main", privateKey, method: "POST", path: pathname, body });
  if (mutateHeaders) signed = mutateHeaders({ ...signed });
  return request({
    port: fixture.started.port,
    pathname,
    method: "POST",
    headers: externalHeaders({
      ...signed,
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(body)
    }),
    body
  });
}

function message(requestId = "request-message-1", message = "Continue with the reviewed plan.") {
  return {
    apiVersion: "gate.remote-message-request/v1",
    requestId,
    sessionRevision: SESSION_REVISION,
    message
  };
}

function heartbeat() {
  return {
    apiVersion: "gate.remote-runner-heartbeat/v1",
    caseId: CASE_ID,
    sessionRevision: SESSION_REVISION,
    observedAt: new Date().toISOString()
  };
}

function stateProjection(revision = 1) {
  const observedAt = new Date();
  return {
    apiVersion: "gate.remote-cockpit-state/v1",
    sessionRevision: SESSION_REVISION,
    stateRevision: revision,
    observedAt: observedAt.toISOString(),
    validUntil: new Date(observedAt.getTime() + 60_000).toISOString(),
    runner: { state: "connected", observedAt: observedAt.toISOString() },
    codex: { state: "idle" },
    tokens: null,
    conversation: [],
    pendingQuestions: []
  };
}

function fleetProjection(revision = 1) {
  const metric = { value: null, precision: "unavailable" };
  const scan = {
    availability: "unavailable", discovered: null, scanned: null, omitted: null, invalid: null,
    discoveredAtLeast: false, omittedAtLeast: false, complete: false, truncated: true
  };
  return {
    apiVersion: "gate.remote-fleet/v4",
    sessionRevision: SESSION_REVISION,
    revision,
    selectionEpoch: "0".repeat(32),
    observedAt: null,
    receivedAt: new Date().toISOString(),
    validUntil: new Date(Date.now() + 15_000).toISOString(),
    connection: "unavailable",
    sourceFreshness: "unavailable",
    coverage: {
      state: "unavailable",
      cases: { ...scan },
      profiles: { ...scan, visible: null, representedByCases: null }
    },
    summary: {
      campaigns: { ...metric }, active: { ...metric }, waiting: { ...metric }, attention: { ...metric },
      profileAnswers: { answered: null, total: null, precision: "unavailable" },
      runningExecutions: { ...metric }, activeWorkflows: { ...metric }, runningAnalyses: { ...metric },
      setupBlockers: { ...metric }, blockers: { ...metric }, campaignTokens: { availability: "unavailable", total: null },
      hostTokens: {
        availability: "unavailable", input: null, cachedInput: null, output: null, total: null,
        cost: { availability: "unavailable", amountMicros: null, unit: null }
      }
    },
    campaigns: []
  };
}

function connectedFleetProjection(revision = 1) {
  const fleet = fleetProjection(revision);
  const exact = { value: 0, precision: "exact" };
  const scan = {
    availability: "available", discovered: 0, scanned: 0, omitted: 0, invalid: 0,
    discoveredAtLeast: false, omittedAtLeast: false, complete: true, truncated: false
  };
  fleet.observedAt = fleet.receivedAt;
  fleet.connection = "connected";
  fleet.sourceFreshness = "current";
  fleet.coverage = {
    state: "exact",
    cases: { ...scan },
    profiles: { ...scan, visible: 0, representedByCases: 0 }
  };
  fleet.summary = {
    campaigns: { ...exact }, active: { ...exact }, waiting: { ...exact }, attention: { ...exact },
    profileAnswers: { answered: 0, total: 0, precision: "exact" },
    runningExecutions: { ...exact }, activeWorkflows: { ...exact }, runningAnalyses: { ...exact },
    setupBlockers: { ...exact }, blockers: { ...exact }, campaignTokens: { availability: "exact", total: 0 },
    hostTokens: fleet.summary.hostTokens
  };
  return fleet;
}

function activity() {
  return {
    apiVersion: "gate.remote-runner-activity/v1",
    caseId: CASE_ID,
    sessionRevision: SESSION_REVISION,
    event: { category: "testing", state: "progress", completed: 2, total: 5, tokens: null }
  };
}

function readSse({ port, pathname, headers, until, timeoutMs = 3_000 }) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let output = "";
    const call = http.request({ hostname: "127.0.0.1", port, path: pathname, method: "GET", headers }, (response) => {
      if (response.statusCode !== 200) {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => reject(new Error(`SSE ${response.statusCode}: ${Buffer.concat(chunks)}`)));
        return;
      }
      response.on("data", (chunk) => {
        output += chunk.toString("utf8");
        if (!settled && until(output)) {
          settled = true;
          clearTimeout(timer);
          resolve({ headers: response.headers, body: output });
          call.destroy();
        }
      });
      response.on("error", (error) => { if (!settled) reject(error); });
    });
    call.on("error", (error) => { if (!settled) reject(error); });
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      call.destroy();
      reject(new Error(`timed out waiting for SSE: ${output}`));
    }, timeoutMs);
    call.end();
  });
}

async function openSse({ port, pathname, headers, timeoutMs = 3_000 }) {
  let output = "";
  let ready = false;
  let readyResolve;
  let readyReject;
  let endedResolve;
  const readyPromise = new Promise((resolve, reject) => {
    readyResolve = resolve;
    readyReject = reject;
  });
  const ended = new Promise((resolve) => {
    endedResolve = resolve;
  });
  const call = http.request({ hostname: "127.0.0.1", port, path: pathname, method: "GET", headers }, (response) => {
    if (response.statusCode !== 200) {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => readyReject(new Error(`SSE ${response.statusCode}: ${Buffer.concat(chunks)}`)));
      return;
    }
    response.on("data", (chunk) => {
      output += chunk.toString("utf8");
      if (!ready && output.includes("event: ready")) {
        ready = true;
        readyResolve();
      }
    });
    response.on("end", () => {
      if (!ready) readyReject(new Error(`SSE ended before ready: ${output}`));
      endedResolve(output);
    });
    response.on("error", (error) => {
      if (!ready) readyReject(error);
      endedResolve(output);
    });
  });
  call.on("error", (error) => {
    if (!ready) readyReject(error);
    endedResolve(output);
  });
  call.end();

  await within(readyPromise, timeoutMs, `timed out opening SSE: ${output}`);
  return Object.freeze({
    ended,
    body: () => output,
    close: () => call.destroy()
  });
}

async function within(promise, milliseconds, message) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(message)), milliseconds);
      })
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function mutableClock(initial) {
  let now = initial;
  const clock = () => now;
  clock.advance = (milliseconds) => {
    now += milliseconds;
  };
  return clock;
}

test("serves only the configured HTTPS origin and injects the remote bridge outside the Pages build", async (t) => {
  const fixture = await makeFixture(t);
  const health = await request({ port: fixture.started.port, pathname: "/healthz" });
  assert.equal(health.status, 200);
  const ready = await request({ port: fixture.started.port, pathname: "/readyz" });
  assert.equal(ready.status, 200);

  const foreign = await request({
    port: fixture.started.port,
    headers: { Host: "foreign.example", "X-Forwarded-Proto": "https" }
  });
  assert.equal(foreign.status, 421);
  const cleartext = await request({ port: fixture.started.port, headers: { Host: "gate.example" } });
  assert.equal(cleartext.status, 421);

  const page = await request({ port: fixture.started.port, headers: externalHeaders() });
  assert.equal(page.status, 200);
  assert.ok(page.body.indexOf("./remote/client.js") < page.body.indexOf("./assets/app.js"));
  assert.match(page.headers["content-security-policy"], /default-src 'none'/u);
  assert.equal(page.headers["strict-transport-security"], "max-age=31536000");
  assert.equal(page.headers["cache-control"], "no-store, max-age=0");
});

test("remote server CLI accepts one explicit owner-only config and Ed25519 public key", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "gate-remote-cli-"));
  fs.chmodSync(directory, 0o700);
  try {
    const keyPath = path.join(directory, "runner-public.pem");
    const configPath = path.join(directory, "server.json");
    const databasePath = path.join(directory, "bridge.sqlite");
    const { publicKey } = crypto.generateKeyPairSync("ed25519");
    fs.writeFileSync(keyPath, publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
    fs.writeFileSync(configPath, JSON.stringify(remoteCliConfig(keyPath, databasePath)), { mode: 0o600 });
    assert.equal(serverCliInternals.parseArguments([], { GATE_REMOTE_CONFIG: configPath }).configPath, configPath);
    const config = serverCliInternals.readConfiguration(configPath);
    assert.equal(config.identityAssertionHeader, "cf-access-jwt-assertion");
    assert.equal(serverCliInternals.loadRunnerPublicKey(keyPath).asymmetricKeyType, "ed25519");
    assert.deepEqual(
      serverCliInternals.readConfiguration(configPath, { includeOwnership: true }).ownership,
      "current-user"
    );
    assert.throws(
      () => serverCliInternals.loadRunnerPublicKey(keyPath, { expectedOwnership: "administrator" }),
      /same protected ownership class/u,
      "an administrator config must not enroll a replaceable service-owned key"
    );

    const linkedConfig = path.join(directory, "linked-config.json");
    fs.symlinkSync(configPath, linkedConfig);
    assert.throws(() => serverCliInternals.readConfiguration(linkedConfig));
    const unsafeDirectory = path.join(directory, "unsafe");
    fs.mkdirSync(unsafeDirectory, { mode: 0o700 });
    const unsafeConfig = path.join(unsafeDirectory, "server.json");
    fs.copyFileSync(configPath, unsafeConfig);
    fs.chmodSync(unsafeConfig, 0o600);
    fs.chmodSync(unsafeDirectory, 0o777);
    assert.throws(() => serverCliInternals.readConfiguration(unsafeConfig), /ancestors/u);

    fs.chmodSync(configPath, 0o640);
    assert.throws(() => serverCliInternals.readConfiguration(configPath), /owner-only/u);
    assert.equal(serverCliInternals.startupDiagnostic({ code: "ENOENT", message: `/private/value ${configPath}` }),
      "A required protected file, owner-only database, or listener is unavailable.");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("remote server CLI accepts protected root-owned static files for a read-only service identity", (t) => {
  if (process.platform === "win32" || typeof process.getuid !== "function") return;
  if (process.getuid() !== 0) return t.skip("creating a root-owned service fixture requires a root test runner");
  const directory = fs.mkdtempSync(path.join(path.dirname(REPOSITORY_ROOT), ".gate-remote-admin-cli-"));
  fs.chmodSync(directory, 0o750);
  try {
    const keyPath = path.join(directory, "runner-public.pem");
    const configPath = path.join(directory, "server.json");
    const databasePath = path.join(directory, "state", "bridge.sqlite");
    const { publicKey } = crypto.generateKeyPairSync("ed25519");
    fs.writeFileSync(keyPath, publicKey.export({ type: "spki", format: "pem" }), { mode: 0o440 });
    fs.writeFileSync(configPath, JSON.stringify(remoteCliConfig(keyPath, databasePath)), { mode: 0o440 });
    fs.chmodSync(keyPath, 0o440);
    fs.chmodSync(configPath, 0o440);

    const stat = fs.statSync(directory, { bigint: true });
    const identity = Object.freeze({
      uid: BigInt(process.getuid()) + 10_000n,
      gids: new Set([stat.gid]),
      actual: false
    });
    const options = { identity };
    const loaded = serverCliInternals.readConfiguration(configPath, { ...options, includeOwnership: true });
    assert.equal(loaded.configuration.databasePath, databasePath);
    assert.equal(loaded.ownership, "administrator");
    assert.equal(serverCliInternals.loadRunnerPublicKey(keyPath, {
      ...options,
      expectedOwnership: loaded.ownership
    }).asymmetricKeyType, "ed25519");

    fs.chmodSync(configPath, 0o460);
    assert.throws(
      () => serverCliInternals.readConfiguration(configPath, options),
      /not writable by the current user/u
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("remote server CLI trusts only a root-owned group-read-only static-file mode for a service identity", () => {
  const identity = Object.freeze({ uid: 10_001n, gids: new Set([10_002n]), actual: false });
  const file = (uid, mode) => ({
    uid,
    gid: 10_002n,
    mode,
    isFile: () => true,
    isSymbolicLink: () => false
  });
  assert.equal(
    serverCliInternals.assertProtectedStaticFile(file(0n, 0o100440n), "Remote config", identity),
    "administrator"
  );
  assert.throws(
    () => serverCliInternals.assertProtectedStaticFile(file(10_003n, 0o100440n), "Remote config", identity),
    /root-owned/u
  );
  assert.throws(
    () => serverCliInternals.assertProtectedStaticFile(file(0n, 0o100460n), "Remote config", identity),
    /not writable by the current user/u
  );
});

test("request limits recover on the next bounded window instead of bricking the service", async (t) => {
  let now = 10_000;
  const fixture = await makeFixture(t, {
    clock: () => now,
    maxRequestsPerWindow: 2,
    requestWindowMs: 1_000
  });
  assert.equal((await request({ port: fixture.started.port, pathname: "/healthz" })).status, 200);
  assert.equal((await request({ port: fixture.started.port, pathname: "/healthz" })).status, 200);
  assert.equal((await request({ port: fixture.started.port, pathname: "/healthz" })).status, 429);
  now += 1_000;
  assert.equal((await request({ port: fixture.started.port, pathname: "/healthz" })).status, 200);
});

test("public and unsigned traffic cannot spend authenticated browser or verified runner budgets", async (t) => {
  const fixture = await makeFixture(t, { maxRequestsPerWindow: 2, requestWindowMs: 60_000 });

  assert.equal((await request({ port: fixture.started.port, pathname: "/healthz" })).status, 200);
  assert.equal((await request({ port: fixture.started.port, pathname: "/healthz" })).status, 200);
  assert.equal((await request({ port: fixture.started.port, pathname: "/healthz" })).status, 429);

  const unsignedBody = JSON.stringify(heartbeat());
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const unsigned = await request({
      port: fixture.started.port,
      pathname: "/api/runner/v1/heartbeat",
      method: "POST",
      headers: externalHeaders({
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(unsignedBody)
      }),
      body: unsignedBody
    });
    assert.equal(unsigned.status, 400);
  }

  assert.equal((await runnerPost(fixture, "/api/runner/v1/heartbeat", heartbeat())).status, 200);
  assert.equal((await runnerPost(fixture, "/api/runner/v1/heartbeat", heartbeat())).status, 200);
  assert.equal((await runnerPost(fixture, "/api/runner/v1/heartbeat", heartbeat())).status, 429);

  const auth = await login(fixture);
  const browserHeaders = externalHeaders({ Cookie: auth.cookie, Accept: "application/json" });
  assert.equal((await request({
    port: fixture.started.port,
    pathname: "/api/cockpit/v1/state",
    headers: browserHeaders
  })).status, 503);
  assert.equal((await request({
    port: fixture.started.port,
    pathname: "/api/cockpit/v1/state",
    headers: browserHeaders
  })).status, 429);
});

test("requires a fresh gateway assertion to establish or refresh a server-side Host cookie session", async (t) => {
  const fixture = await makeFixture(t);
  const missing = await request({
    port: fixture.started.port,
    pathname: "/api/cockpit/v1/session",
    headers: externalHeaders({ "Sec-Fetch-Site": "same-origin" })
  });
  assert.equal(missing.status, 400);
  const auth = await login(fixture);
  assert.equal(fixture.verificationCount(), 1);
  assert.match(auth.response.headers["set-cookie"][0],
    /^__Host-gate-session=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Strict;/u);
  const crossSiteBootstrap = await request({
    port: fixture.started.port,
    pathname: "/api/cockpit/v1/session",
    headers: externalHeaders({ "X-GATE-OIDC-Assertion": "verified-assertion", "Sec-Fetch-Site": "cross-site" })
  });
  assert.equal(crossSiteBootstrap.status, 403);
  assert.equal(fixture.verificationCount(), 1, "cross-site bootstrap must be rejected before assertion verification");
  const resumed = await request({
    port: fixture.started.port,
    pathname: "/api/cockpit/v1/session",
    headers: externalHeaders({ Cookie: auth.cookie, "Sec-Fetch-Site": "same-origin" })
  });
  assert.equal(resumed.status, 400, resumed.body);
  const refreshed = await request({
    port: fixture.started.port,
    pathname: "/api/cockpit/v1/session",
    headers: externalHeaders({
      Cookie: auth.cookie, "X-GATE-OIDC-Assertion": "verified-assertion", "Sec-Fetch-Site": "same-origin"
    })
  });
  assert.equal(refreshed.status, 200, refreshed.body);
  assert.equal(fixture.verificationCount(), 2, "every page-session bootstrap must reverify the gateway assertion");
});

test("the HTTP header budget admits the complete bounded OIDC assertion contract", async (t) => {
  const assertion = "A".repeat(24 * 1024);
  let verified = 0;
  const fixture = await makeFixture(t, {
    oidcVerifier: {
      async verify(value) {
        assert.equal(value, assertion);
        verified += 1;
        return Object.freeze({ subject: OPERATOR_ID });
      }
    }
  });
  const accepted = await request({
    port: fixture.started.port,
    pathname: "/api/cockpit/v1/session",
    headers: externalHeaders({
      "X-GATE-OIDC-Assertion": assertion,
      "Sec-Fetch-Site": "same-origin",
      Accept: "application/json"
    })
  });
  assert.equal(accepted.status, 200, accepted.body);
  assert.equal(verified, 1);

  const oversized = await request({
    port: fixture.started.port,
    pathname: "/api/cockpit/v1/session",
    headers: externalHeaders({
      "X-GATE-OIDC-Assertion": `${assertion}A`,
      "Sec-Fetch-Site": "same-origin",
      Accept: "application/json"
    })
  });
  assert.equal(oversized.status, 400, oversized.body);
  assert.equal(verified, 1, "application-level bounds must reject before identity verification");
});

test("cookie rotation survives parallel reads and returns the replacement on malformed authenticated requests", async (t) => {
  const sessionClock = mutableClock(10_000);
  const sessionStore = new SessionStore({
    clock: sessionClock,
    rotationIntervalMs: 1_000,
    rotationGraceMs: 100
  });
  const fixture = await makeFixture(t, { sessionStore, closeSessionStore: true });
  assert.equal((await runnerPost(fixture, "/api/runner/v1/state", stateProjection())).status, 200);
  assert.equal((await runnerPost(fixture, "/api/runner/v1/fleet", fleetProjection())).status, 200);
  const auth = await login(fixture);

  sessionClock.advance(1_000);
  const [state, fleet] = await Promise.all(["state", "fleet"].map((route) => request({
    port: fixture.started.port,
    pathname: `/api/cockpit/v1/${route}`,
    headers: externalHeaders({ Cookie: auth.cookie })
  })));
  assert.equal(state.status, 200, state.body);
  assert.equal(fleet.status, 200, fleet.body);
  const rotatedCookie = cookieFrom(state);
  assert.equal(cookieFrom(fleet), rotatedCookie,
    "parallel requests using the previous credential must receive one current credential");

  sessionClock.advance(1_000);
  const malformed = await request({
    port: fixture.started.port,
    pathname: "/api/cockpit/v1/events?cursor=bad",
    headers: externalHeaders({ Cookie: rotatedCookie, Accept: "text/event-stream" })
  });
  assert.equal(malformed.status, 400, malformed.body);
  const replacement = cookieFrom(malformed);
  assert.notEqual(replacement, rotatedCookie);

  sessionClock.advance(101);
  const recovered = await request({
    port: fixture.started.port,
    pathname: "/api/cockpit/v1/state",
    headers: externalHeaders({ Cookie: rotatedCookie })
  });
  assert.equal(recovered.status, 200,
    "a rejected response must not expire the only credential the browser may still hold");
  assert.equal(cookieFrom(recovered), replacement);
  assert.equal((await request({
    port: fixture.started.port,
    pathname: "/api/cockpit/v1/state",
    headers: externalHeaders({ Cookie: replacement })
  })).status, 200, "presenting the replacement acknowledges rotation");
  sessionClock.advance(101);
  assert.equal((await request({
    port: fixture.started.port,
    pathname: "/api/cockpit/v1/state",
    headers: externalHeaders({ Cookie: rotatedCookie })
  })).status, 401, "the acknowledged previous credential must expire after the bounded grace");
});

test("browser writes require exact Origin, same-origin fetch context, CSRF, strict input, and durable idempotency", async (t) => {
  const fixture = await makeFixture(t);
  const auth = await login(fixture);
  const value = message();

  const foreign = await browserPost(fixture, auth, "/api/cockpit/v1/messages", value, { Origin: "https://evil.example" });
  assert.equal(foreign.status, 403);
  const crossSite = await browserPost(fixture, auth, "/api/cockpit/v1/messages", value, { "Sec-Fetch-Site": "cross-site" });
  assert.equal(crossSite.status, 403);
  const badCsrf = await browserPost(fixture, auth, "/api/cockpit/v1/messages", value, { "X-GATE-CSRF": "x".repeat(43) });
  assert.equal(badCsrf.status, 403);
  const secret = await browserPost(fixture, auth, "/api/cockpit/v1/messages",
    message("request-message-2", "api_key=supersecretvalue"));
  assert.equal(secret.status, 400);
  const extra = await browserPost(fixture, auth, "/api/cockpit/v1/messages", { ...value, operatorId: OPERATOR_ID });
  assert.equal(extra.status, 400);

  const first = await browserPost(fixture, auth, "/api/cockpit/v1/messages", value);
  assert.equal(first.status, 202, first.body);
  const receipt = JSON.parse(first.body);
  assert.equal(receipt.status, "queued");
  assert.equal(receipt.sessionRevision, SESSION_REVISION);
  const replay = await browserPost(fixture, auth, "/api/cockpit/v1/messages", value);
  assert.equal(replay.status, 202);
  assert.deepEqual(JSON.parse(replay.body), receipt);
  const conflict = await browserPost(fixture, auth, "/api/cockpit/v1/messages", { ...value, message: "Changed input" });
  assert.equal(conflict.status, 409);
});

test("a lost response replays one command after session refresh and keeps its lifecycle visible", async (t) => {
  const fixture = await makeFixture(t);
  const original = await login(fixture);
  const value = message("request-refresh-replay");

  // The client may lose this response after the coordinator has committed it.
  const presumedLost = await browserPost(fixture, original, "/api/cockpit/v1/messages", value);
  assert.equal(presumedLost.status, 202, presumedLost.body);
  const originalReceipt = JSON.parse(presumedLost.body);

  const leaseResponse = await runnerPost(fixture, "/api/runner/v1/lease", {
    apiVersion: "gate.remote-runner-lease-request/v1",
    caseId: CASE_ID,
    sessionRevision: SESSION_REVISION
  });
  assert.equal(leaseResponse.status, 200, leaseResponse.body);
  const leased = JSON.parse(leaseResponse.body).command;
  assert.equal(leased.commandId, originalReceipt.commandId);
  for (const state of ["accepted", "running", "completed"]) {
    const transition = await runnerPost(fixture, "/api/runner/v1/transition", {
      apiVersion: "gate.remote-runner-transition/v1",
      caseId: CASE_ID,
      sessionRevision: SESSION_REVISION,
      commandId: leased.commandId,
      leaseId: leased.lease.leaseId,
      state
    });
    assert.equal(transition.status, 200, `${state}: ${transition.body}`);
  }

  const refreshResponse = await request({
    port: fixture.started.port,
    pathname: "/api/cockpit/v1/session",
    headers: externalHeaders({
      Cookie: original.cookie,
      "X-GATE-OIDC-Assertion": "verified-assertion",
      "Sec-Fetch-Site": "same-origin",
      Accept: "application/json"
    })
  });
  assert.equal(refreshResponse.status, 200, refreshResponse.body);
  const refreshed = { cookie: cookieFrom(refreshResponse), session: JSON.parse(refreshResponse.body) };
  assert.notEqual(refreshed.cookie, original.cookie, "refresh rotates the server-side browser session");
  assert.notEqual(refreshed.session.csrf, original.session.csrf, "refresh rotates the CSRF proof");
  assert.equal(fixture.verificationCount(), 2, "refresh still requires a fresh verified OIDC assertion");

  const revokedRetry = await browserPost(fixture, original, "/api/cockpit/v1/messages", value);
  assert.equal(revokedRetry.status, 401, "the replaced browser session remains revoked");
  const replay = await browserPost(fixture, refreshed, "/api/cockpit/v1/messages", value);
  assert.equal(replay.status, 202, replay.body);
  assert.deepEqual(JSON.parse(replay.body), originalReceipt,
    "the durable request scope returns the original command receipt");

  const lifecycle = await readSse({
    port: fixture.started.port,
    pathname: "/api/cockpit/v1/events?cursor=0",
    headers: externalHeaders({
      Cookie: refreshed.cookie,
      Accept: "text/event-stream",
      "Last-Event-ID": "0"
    }),
    until: (body) => body.includes(`\"commandId\":\"${originalReceipt.commandId}\"`)
      && body.includes("\"state\":\"completed\"")
  });
  for (const state of ["queued", "leased", "accepted", "running", "completed"]) {
    assert.ok(lifecycle.body.includes(`\"state\":\"${state}\"`), `missing ${state} lifecycle event`);
  }
});

test("authenticated status reconciliation restores terminal commands after lifecycle pruning", async (t) => {
  const fixture = await makeFixture(t, { storeOptions: { maxEvents: 2 } });
  const original = await login(fixture);
  const submitted = message("request-status-after-prune", "Private instruction stays out of status responses.");
  const queued = JSON.parse((await browserPost(
    fixture, original, "/api/cockpit/v1/messages", submitted
  )).body);
  const leased = JSON.parse((await runnerPost(fixture, "/api/runner/v1/lease", {
    apiVersion: "gate.remote-runner-lease-request/v1",
    caseId: CASE_ID,
    sessionRevision: SESSION_REVISION
  })).body).command;
  for (const state of ["accepted", "running", "completed"]) {
    assert.equal((await runnerPost(fixture, "/api/runner/v1/transition", {
      apiVersion: "gate.remote-runner-transition/v1",
      caseId: CASE_ID,
      sessionRevision: SESSION_REVISION,
      commandId: leased.commandId,
      leaseId: leased.lease.leaseId,
      state
    })).status, 200);
  }
  for (const state of ["started", "completed"]) {
    assert.equal((await runnerPost(fixture, "/api/runner/v1/activity", {
      ...activity(),
      event: { category: "testing", state, completed: null, total: null, tokens: null }
    })).status, 200);
  }
  assert.equal(fixture.store.eventsSince({
    operatorId: OPERATOR_ID,
    browserSessionId: "browser-test-123",
    caseId: CASE_ID,
    sessionRevision: SESSION_REVISION
  }, 0).resyncRequired, true);

  const refreshed = await login(fixture);
  const statusRequest = {
    apiVersion: "gate.remote-command-status-request/v1",
    caseId: CASE_ID,
    sessionRevision: SESSION_REVISION,
    commands: [{ requestId: submitted.requestId, commandId: queued.commandId }]
  };
  const reconciled = await browserPost(
    fixture, refreshed, "/api/cockpit/v1/commands/status", statusRequest
  );
  assert.equal(reconciled.status, 200, reconciled.body);
  assert.deepEqual(JSON.parse(reconciled.body), {
    apiVersion: "gate.remote-command-status-response/v1",
    caseId: CASE_ID,
    sessionRevision: SESSION_REVISION,
    commands: [{ requestId: submitted.requestId, commandId: queued.commandId, state: "completed" }]
  });
  assert.doesNotMatch(reconciled.body, /Private instruction/u);

  const body = JSON.stringify(statusRequest);
  const unauthenticated = await request({
    port: fixture.started.port,
    pathname: "/api/cockpit/v1/commands/status",
    method: "POST",
    headers: externalHeaders({
      Origin: ORIGIN,
      "Sec-Fetch-Site": "same-origin",
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(body)
    }),
    body
  });
  assert.equal(unauthenticated.status, 401);
  assert.equal((await browserPost(fixture, refreshed, "/api/cockpit/v1/commands/status", {
    ...statusRequest,
    caseId: "other-case"
  })).status, 409);
});

test("signed outbound runner polling leases only the configured session and drives bounded lifecycle transitions", async (t) => {
  const fixture = await makeFixture(t);
  const auth = await login(fixture);
  const queued = await browserPost(fixture, auth, "/api/cockpit/v1/messages", message());
  assert.equal(queued.status, 202, queued.body);

  const heartbeatResponse = await runnerPost(fixture, "/api/runner/v1/heartbeat", heartbeat());
  assert.equal(heartbeatResponse.status, 200, heartbeatResponse.body);
  assert.deepEqual(Object.keys(JSON.parse(heartbeatResponse.body)).sort(), ["acceptedAt", "apiVersion"]);

  const leaseResponse = await runnerPost(fixture, "/api/runner/v1/lease", {
    apiVersion: "gate.remote-runner-lease-request/v1",
    caseId: CASE_ID,
    sessionRevision: SESSION_REVISION
  });
  assert.equal(leaseResponse.status, 200, leaseResponse.body);
  const leased = JSON.parse(leaseResponse.body).command;
  assert.deepEqual(Object.keys(leased).sort(),
    ["commandId", "expiresAt", "issuedAt", "kind", "lease", "payload", "payloadSha256"].sort());
  assert.equal(leased.payload.message, message().message);
  assert.equal(leased.operatorId, undefined);
  assert.equal(leased.browserSessionId, undefined);

  for (const state of ["accepted", "running", "renewed", "completed"]) {
    const transition = await runnerPost(fixture, "/api/runner/v1/transition", {
      apiVersion: "gate.remote-runner-transition/v1",
      caseId: CASE_ID,
      sessionRevision: SESSION_REVISION,
      commandId: leased.commandId,
      leaseId: leased.lease.leaseId,
      state
    });
    assert.equal(transition.status, 200, `${state}: ${transition.body}`);
  }
  const empty = await runnerPost(fixture, "/api/runner/v1/lease", {
    apiVersion: "gate.remote-runner-lease-request/v1",
    caseId: CASE_ID,
    sessionRevision: SESSION_REVISION
  });
  assert.deepEqual(JSON.parse(empty.body), { apiVersion: "gate.remote-runner-lease/v1", command: null });
});

test("the coordinator sweep terminalizes abandoned commands without later queue traffic", async (t) => {
  const storeClock = mutableClock(Date.now());
  const fixture = await makeFixture(t, {
    storeOptions: { now: () => new Date(storeClock()) },
    commandTtlMs: 1_000,
    runnerLeaseMs: 1_000,
    expirySweepMs: 100
  });
  const auth = await login(fixture);
  const acceptedRequest = message("request-expire-accepted");
  const queuedRequest = message("request-expire-queued");
  const acceptedReceipt = JSON.parse((await browserPost(
    fixture, auth, "/api/cockpit/v1/messages", acceptedRequest
  )).body);
  const queuedReceipt = JSON.parse((await browserPost(
    fixture, auth, "/api/cockpit/v1/messages", queuedRequest
  )).body);
  const leasedAccepted = JSON.parse((await runnerPost(fixture, "/api/runner/v1/lease", {
    apiVersion: "gate.remote-runner-lease-request/v1",
    caseId: CASE_ID,
    sessionRevision: SESSION_REVISION
  })).body).command;
  assert.equal(leasedAccepted.commandId, acceptedReceipt.commandId);
  assert.equal((await runnerPost(fixture, "/api/runner/v1/transition", {
    apiVersion: "gate.remote-runner-transition/v1",
    caseId: CASE_ID,
    sessionRevision: SESSION_REVISION,
    commandId: leasedAccepted.commandId,
    leaseId: leasedAccepted.lease.leaseId,
    state: "accepted"
  })).status, 200);

  const commandState = (commandId) => fixture.store.getCommand({
    commandId,
    operatorId: OPERATOR_ID,
    browserSessionId: "browser-test-123",
    caseId: CASE_ID,
    sessionRevision: SESSION_REVISION
  })?.state;
  const waitForState = async (commandId, expected) => {
    for (let attempt = 0; attempt < 30; attempt += 1) {
      if (commandState(commandId) === expected) return;
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.equal(commandState(commandId), expected);
  };

  storeClock.advance(1_001);
  await Promise.all([
    waitForState(acceptedReceipt.commandId, "expired"),
    waitForState(queuedReceipt.commandId, "expired")
  ]);
  const replay = await browserPost(fixture, auth, "/api/cockpit/v1/messages", acceptedRequest);
  assert.equal(replay.status, 202, replay.body);
  assert.equal(commandState(acceptedReceipt.commandId), "expired");
  assert.equal(fixture.store.configuration().retainedCommands, 2,
    "an exact retry must expose current state without creating another command");

  const runningReceipt = JSON.parse((await browserPost(
    fixture, auth, "/api/cockpit/v1/messages", message("request-expire-running")
  )).body);
  const leasedRunning = JSON.parse((await runnerPost(fixture, "/api/runner/v1/lease", {
    apiVersion: "gate.remote-runner-lease-request/v1",
    caseId: CASE_ID,
    sessionRevision: SESSION_REVISION
  })).body).command;
  for (const state of ["accepted", "running"]) {
    assert.equal((await runnerPost(fixture, "/api/runner/v1/transition", {
      apiVersion: "gate.remote-runner-transition/v1",
      caseId: CASE_ID,
      sessionRevision: SESSION_REVISION,
      commandId: leasedRunning.commandId,
      leaseId: leasedRunning.lease.leaseId,
      state
    })).status, 200);
  }
  assert.equal(leasedRunning.commandId, runningReceipt.commandId);
  storeClock.advance(1_001);
  await waitForState(runningReceipt.commandId, "failed");

  let laterSweeps = 0;
  const expireDue = fixture.store.expireDue.bind(fixture.store);
  fixture.store.expireDue = () => {
    laterSweeps += 1;
    return expireDue();
  };
  await new Promise(resolve => setTimeout(resolve, 120));
  assert.ok(laterSweeps >= 1);
  await fixture.started.close();
  const stoppedAt = laterSweeps;
  await new Promise(resolve => setTimeout(resolve, 220));
  assert.equal(laterSweeps, stoppedAt, "closing the coordinator must stop expiry sweeps before closing the store");
});

test("runner signatures bind exact method, path, body, nonce, and configured case", async (t) => {
  const fixture = await makeFixture(t);
  const value = heartbeat();
  const body = JSON.stringify(value);
  const signed = signRunnerRequest({
    runnerId: "runner-main",
    privateKey: fixture.privateKey,
    method: "POST",
    path: "/api/runner/v1/heartbeat",
    body
  });
  const send = () => request({
    port: fixture.started.port,
    pathname: "/api/runner/v1/heartbeat",
    method: "POST",
    headers: externalHeaders({ ...signed, "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) }),
    body
  });
  assert.equal((await send()).status, 200);
  assert.equal((await send()).status, 409, "the signed nonce must be single-use");

  const duplicateSigned = signRunnerRequest({
    runnerId: "runner-main",
    privateKey: fixture.privateKey,
    method: "POST",
    path: "/api/runner/v1/heartbeat",
    body
  });
  const duplicateHeaders = ["Host", "gate.example", "X-Forwarded-Proto", "https"];
  for (const [name, value] of Object.entries(duplicateSigned)) duplicateHeaders.push(name, value);
  duplicateHeaders.push("X-GATE-Nonce", duplicateSigned["X-GATE-Nonce"]);
  duplicateHeaders.push("Content-Type", "application/json", "Content-Length", String(Buffer.byteLength(body)));
  const duplicate = await request({
    port: fixture.started.port,
    pathname: "/api/runner/v1/heartbeat",
    method: "POST",
    headers: duplicateHeaders,
    body
  });
  assert.equal(duplicate.status, 400, "duplicate signed headers must be rejected before verification");

  const wrongCase = await runnerPost(fixture, "/api/runner/v1/heartbeat", { ...heartbeat(), caseId: "other-case" });
  assert.equal(wrongCase.status, 409);
  const tampered = await runnerPost(fixture, "/api/runner/v1/heartbeat", heartbeat(), {
    mutateHeaders(headers) {
      headers["X-GATE-Body-SHA256"] = "0".repeat(64);
      return headers;
    }
  });
  assert.equal(tampered.status, 401);
});

test("runner nonce replay remains rejected after the server and durable store reopen", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "gate-remote-replay-"));
  fs.chmodSync(directory, 0o700);
  const databasePath = path.join(directory, "bridge.sqlite");
  const keys = crypto.generateKeyPairSync("ed25519");
  const oidcVerifier = { verify: async () => ({ subject: OPERATOR_ID }) };
  const start = async () => {
    const store = new RemoteBridgeStore({ databasePath });
    return startRemoteCockpitServer({
      origin: ORIGIN,
      host: "127.0.0.1",
      port: 0,
      operatorId: OPERATOR_ID,
      caseId: CASE_ID,
      sessionRevision: SESSION_REVISION,
      store,
      oidcVerifier,
      runnerPublicKeys: new Map([["runner-main", keys.publicKey]]),
      closeStore: true
    });
  };
  const value = heartbeat();
  const body = JSON.stringify(value);
  const signed = signRunnerRequest({
    runnerId: "runner-main",
    privateKey: keys.privateKey,
    method: "POST",
    path: "/api/runner/v1/heartbeat",
    body
  });
  const send = (port) => request({
    port,
    pathname: "/api/runner/v1/heartbeat",
    method: "POST",
    headers: externalHeaders({ ...signed, "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) }),
    body
  });
  let first;
  let second;
  try {
    first = await start();
    assert.equal((await send(first.port)).status, 200);
    await first.close();
    first = null;
    second = await start();
    assert.equal((await send(second.port)).status, 409, "durable nonce reuse must fail after restart");
  } finally {
    await first?.close().catch(() => {});
    await second?.close().catch(() => {});
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("runner projections are normalized before authenticated browser reads", async (t) => {
  const fixture = await makeFixture(t);
  const auth = await login(fixture);
  const state = stateProjection();
  const fleet = fleetProjection();
  assert.equal((await runnerPost(fixture, "/api/runner/v1/state", state)).status, 200);
  assert.equal((await runnerPost(fixture, "/api/runner/v1/fleet", fleet)).status, 200);

  for (const [route, expected] of [["state", state], ["fleet", fleet]]) {
    const response = await request({
      port: fixture.started.port,
      pathname: `/api/cockpit/v1/${route}`,
      headers: externalHeaders({ Cookie: auth.cookie })
    });
    assert.equal(response.status, 200, response.body);
    assert.deepEqual(JSON.parse(response.body), expected);
    assert.equal(response.headers["cache-control"], "no-store, max-age=0");
  }

  const stale = stateProjection(0);
  stale.sessionRevision = SESSION_REVISION - 1;
  assert.equal((await runnerPost(fixture, "/api/runner/v1/state", stale)).status, 409);
});

test("coordinator preserves current fleet telemetry beside an explicit offline conversation state", async (t) => {
  const fixture = await makeFixture(t);
  const auth = await login(fixture);
  const state = stateProjection();
  state.codex.state = "offline";
  const fleet = connectedFleetProjection();
  assert.equal((await runnerPost(fixture, "/api/runner/v1/state", state)).status, 200);
  assert.equal((await runnerPost(fixture, "/api/runner/v1/fleet", fleet)).status, 200);

  const [visibleState, visibleFleet] = await Promise.all(["state", "fleet"].map(async (route) => {
    const result = await request({
      port: fixture.started.port,
      pathname: `/api/cockpit/v1/${route}`,
      headers: externalHeaders({ Cookie: auth.cookie })
    });
    assert.equal(result.status, 200, result.body);
    return JSON.parse(result.body);
  }));
  assert.equal(visibleState.runner.state, "connected");
  assert.equal(visibleState.codex.state, "offline");
  assert.equal(visibleFleet.connection, "connected");
  assert.equal(visibleFleet.summary.active.value, 0);
  assert.equal(visibleFleet.summary.active.precision, "exact");
});

test("remote fleet upload and reads expire at the exact fleet deadline", async (t) => {
  let now = Date.now();
  const fixture = await makeFixture(t, { clock: () => now });
  const auth = await login(fixture);
  const fleet = fleetProjection();
  fleet.receivedAt = new Date(now).toISOString();
  fleet.validUntil = new Date(now + 15_000).toISOString();
  assert.equal((await runnerPost(fixture, "/api/runner/v1/fleet", fleet)).status, 200);

  now += 15_000;
  const expiredRead = await request({
    port: fixture.started.port,
    pathname: "/api/cockpit/v1/fleet",
    headers: externalHeaders({ Cookie: auth.cookie })
  });
  assert.equal(expiredRead.status, 503);
  assert.equal(JSON.parse(expiredRead.body).error.code, "projection-expired");

  const expiredUpload = fleetProjection(2);
  expiredUpload.receivedAt = new Date(now - 10_000).toISOString();
  expiredUpload.validUntil = new Date(now).toISOString();
  assert.equal((await runnerPost(fixture, "/api/runner/v1/fleet", expiredUpload)).status, 409);
});

test("SSE replays durable monotonic events and emits an explicit resync for an unsatisfiable cursor", async (t) => {
  const fixture = await makeFixture(t);
  const auth = await login(fixture);
  assert.equal((await runnerPost(fixture, "/api/runner/v1/activity", activity())).status, 200);

  const replay = await readSse({
    port: fixture.started.port,
    pathname: "/api/cockpit/v1/events?cursor=0",
    headers: externalHeaders({ Cookie: auth.cookie, Accept: "text/event-stream", "Last-Event-ID": "0" }),
    until: (body) => body.includes("event: activity")
  });
  assert.match(replay.body, /event: ready\ndata: \{"apiVersion":"gate.remote-events-ready\/v1","cursor":0\}/u);
  assert.match(replay.body, /id: [1-9][0-9]*\nevent: activity\ndata: \{"apiVersion":"gate.remote-cockpit-event\/v1"/u);

  const resync = await readSse({
    port: fixture.started.port,
    pathname: "/api/cockpit/v1/events?cursor=999999",
    headers: externalHeaders({ Cookie: auth.cookie, Accept: "text/event-stream", "Last-Event-ID": "999999" }),
    until: (body) => body.includes("event: resync") && body.lastIndexOf("event: ready") > body.indexOf("event: resync")
  });
  assert.match(resync.body, /id: [1-9][0-9]*\nevent: resync\ndata: \{"apiVersion":"gate.remote-resync\/v1","cursor":[1-9][0-9]*\}/u);
  assert.ok(resync.body.indexOf("event: resync") < resync.body.lastIndexOf("event: ready"));
});

test("refreshing the browser session promptly closes its existing SSE before later private events", async (t) => {
  const fixture = await makeFixture(t);
  const original = await login(fixture);
  const stream = await openSse({
    port: fixture.started.port,
    pathname: "/api/cockpit/v1/events?cursor=0",
    headers: externalHeaders({ Cookie: original.cookie, Accept: "text/event-stream", "Last-Event-ID": "0" })
  });
  t.after(() => stream.close());

  const refresh = await request({
    port: fixture.started.port,
    pathname: "/api/cockpit/v1/session",
    headers: externalHeaders({
      Cookie: original.cookie,
      "X-GATE-OIDC-Assertion": "verified-assertion",
      "Sec-Fetch-Site": "same-origin",
      Accept: "application/json"
    })
  });
  assert.equal(refresh.status, 200, refresh.body);
  assert.notEqual(cookieFrom(refresh), original.cookie);
  assert.equal((await runnerPost(fixture, "/api/runner/v1/activity", activity())).status, 200);

  const output = await within(stream.ended, 1_500, "revoked SSE remained open");
  assert.doesNotMatch(output, /event: activity/u, "a revoked stream must not receive later private events");
});

test("an idle-expired browser session promptly closes its SSE without disclosing later events", async (t) => {
  const clock = mutableClock(10_000);
  const sessionStore = new SessionStore({
    clock,
    idleTtlMs: 100,
    absoluteTtlMs: 1_000,
    rotationIntervalMs: 1_000
  });
  const fixture = await makeFixture(t, { sessionStore, closeSessionStore: true });
  const auth = await login(fixture);
  const stream = await openSse({
    port: fixture.started.port,
    pathname: "/api/cockpit/v1/events?cursor=0",
    headers: externalHeaders({ Cookie: auth.cookie, Accept: "text/event-stream", "Last-Event-ID": "0" })
  });
  t.after(() => stream.close());

  clock.advance(100);
  assert.equal((await runnerPost(fixture, "/api/runner/v1/activity", activity())).status, 200);
  const output = await within(stream.ended, 1_500, "expired SSE remained open");
  assert.doesNotMatch(output, /event: activity/u, "an expired stream must not receive later private events");
});

