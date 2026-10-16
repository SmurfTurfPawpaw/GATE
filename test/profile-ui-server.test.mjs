import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { createProgramProfile, resumeProgramProfile } from "../src/lib/bounty-profiles.mjs";
import { runtimePaths } from "../src/lib/paths.mjs";
import { startProfileWizardServer } from "../src/profile-ui/server.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixedAt = "2026-10-16T08:00:00.000Z";
const privateCanary = "PRIVATE_PROFILE_NOTE_CANARY_83d75e";
const secretCanary = "Bearer PROFILE_UI_SECRET_CANARY_74f92c";

function fixture(t, id = "browser-profile") {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-profile-ui-"));
  const paths = runtimePaths({ repo, home: path.join(root, "home") });
  createProgramProfile(id, {
    sources: [{
      id: "program-rules",
      type: "program-rules",
      title: "Published program rules",
      reference: "https://private-reference-canary.example.test/rules",
      contentSha256: "a".repeat(64),
      observedAt: fixedAt,
      claimState: "observed",
      notes: privateCanary
    }]
  }, { paths, now: fixedAt });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { paths, id };
}

function launchCredentials(started) {
  const url = new URL(started.url);
  const fragment = new URLSearchParams(url.hash.slice(1));
  return {
    origin: started.origin,
    session: fragment.get("session"),
    csrf: fragment.get("csrf")
  };
}

async function api(started, credentials, pathname, options = {}) {
  const headers = { "X-GATE-Session": credentials.session, ...(options.headers || {}) };
  if (options.body !== undefined) {
    headers.Origin = started.origin;
    headers["X-GATE-CSRF"] = credentials.csrf;
    headers["Content-Type"] = "application/json";
  }
  return fetch(`${started.origin}${pathname}`, {
    method: options.body === undefined ? "GET" : "POST",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body)
  });
}

test("profile UI binds only explicit loopback addresses", async (t) => {
  const { paths, id } = fixture(t);
  await assert.rejects(
    startProfileWizardServer({ profileId: id, paths, host: "0.0.0.0" }),
    /explicit loopback/u
  );
  await assert.rejects(
    startProfileWizardServer({ profileId: id, paths, host: "localhost" }),
    /explicit loopback/u
  );
});

test("profile UI serves a no-telemetry shell with strict browser policy", async (t) => {
  const { paths, id } = fixture(t);
  const started = await startProfileWizardServer({ profileId: id, paths });
  t.after(() => started.close());

  const response = await fetch(`${started.origin}/`);
  const html = await response.text();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-security-policy"), /default-src 'none'/u);
  assert.match(response.headers.get("content-security-policy"), /script-src 'self'/u);
  assert.match(response.headers.get("content-security-policy"), /frame-ancestors 'none'/u);
  assert.equal(response.headers.get("cache-control"), "no-store, max-age=0");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  assert.doesNotMatch(html, /https?:\/\//u);
  assert.doesNotMatch(html, new RegExp(privateCanary, "u"));
  assert.doesNotMatch(html, /private-reference-canary/u);
  assert.doesNotMatch(html, /session=|csrf=/u);
});

test("profile state requires its unguessable in-memory session", async (t) => {
  const { paths, id } = fixture(t);
  const started = await startProfileWizardServer({ profileId: id, paths });
  t.after(() => started.close());
  const credentials = launchCredentials(started);

  assert.ok(credentials.session?.length >= 40);
  assert.ok(credentials.csrf?.length >= 40);
  assert.notEqual(credentials.session, credentials.csrf);

  const missing = await fetch(`${started.origin}/api/state`);
  const missingBody = await missing.text();
  assert.equal(missing.status, 401);
  assert.doesNotMatch(missingBody, new RegExp(privateCanary, "u"));
  assert.doesNotMatch(missingBody, /private-reference-canary/u);

  const response = await api(started, credentials, "/api/state");
  const payload = await response.json();
  assert.equal(response.status, 200);
  assert.equal(payload.state.profile.id, id);
  assert.deepEqual(payload.state.sources, [{
    id: "program-rules",
    title: "Published program rules",
    type: "program-rules",
    observedAt: fixedAt,
    claimState: "observed",
    contentDigestRecorded: true
  }]);
  assert.doesNotMatch(JSON.stringify(payload.state.sources), new RegExp(privateCanary, "u"));
  assert.doesNotMatch(JSON.stringify(payload.state.sources), /private-reference-canary/u);
  for (const question of payload.state.sections.flatMap((section) => section.questions)) {
    assert.equal(Object.hasOwn(question.recommendation, "value"), false);
  }
});

test("profile UI resolves recommendations inside the local controller", async (t) => {
  const { paths, id } = fixture(t);
  const started = await startProfileWizardServer({ profileId: id, paths });
  t.after(() => started.close());
  const credentials = launchCredentials(started);
  const stateResponse = await api(started, credentials, "/api/state");
  const current = (await stateResponse.json()).state;
  const depth = current.sections.flatMap((section) => section.questions)
    .find((question) => question.id === "identity-depth");
  assert.equal(depth.recommendation.available, true);
  assert.equal(Object.hasOwn(depth.recommendation, "value"), false);

  const response = await api(started, credentials, "/api/recommendation", { body: {
    questionId: depth.id,
    baseRevision: current.profile.revision,
    baseProfileSha256: current.profile.profileSha256
  } });
  assert.equal(response.status, 200);
  assert.equal(resumeProgramProfile(id, { paths }).answers.answers[depth.id], "thorough");
});

test("profile UI requires an explicit source-review acknowledgement before authority confirmation", async (t) => {
  const { paths, id } = fixture(t);
  const started = await startProfileWizardServer({ profileId: id, paths });
  t.after(() => started.close());
  const credentials = launchCredentials(started);
  const stateResponse = await api(started, credentials, "/api/state");
  const current = (await stateResponse.json()).state;
  const answer = {
    questionId: "authority-operator-confirmed",
    value: true,
    baseRevision: current.profile.revision,
    baseProfileSha256: current.profile.profileSha256
  };

  const blind = await api(started, credentials, "/api/answer", { body: answer });
  assert.equal(blind.status, 422);
  assert.equal((await blind.json()).error.code, "source-review-required");

  const reviewed = await api(started, credentials, "/api/answer", { body: { ...answer, reviewAcknowledged: true } });
  assert.equal(reviewed.status, 200);
  assert.equal(resumeProgramProfile(id, { paths }).answers.answers[answer.questionId], true);
});

test("profile mutations require exact origin and CSRF headers", async (t) => {
  const { paths, id } = fixture(t);
  const started = await startProfileWizardServer({ profileId: id, paths });
  t.after(() => started.close());
  const credentials = launchCredentials(started);
  const stateResponse = await api(started, credentials, "/api/state");
  const current = (await stateResponse.json()).state;
  const body = {
    questionId: "identity-objective",
    value: "Produce a bounded, evidence-backed assessment.",
    baseRevision: current.profile.revision,
    baseProfileSha256: current.profile.profileSha256
  };

  const missingOrigin = await fetch(`${started.origin}/api/answer`, {
    method: "POST",
    headers: {
      "X-GATE-Session": credentials.session,
      "X-GATE-CSRF": credentials.csrf,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });
  assert.equal(missingOrigin.status, 403);

  const wrongCsrf = await fetch(`${started.origin}/api/answer`, {
    method: "POST",
    headers: {
      Origin: started.origin,
      "X-GATE-Session": credentials.session,
      "X-GATE-CSRF": "wrong-token",
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });
  assert.equal(wrongCsrf.status, 403);

  const accepted = await api(started, credentials, "/api/answer", { body });
  assert.equal(accepted.status, 200);
  assert.equal((await accepted.json()).state.profile.revision, current.profile.revision + 1);
  assert.equal(resumeProgramProfile(id, { paths }).answers.answers["identity-objective"], body.value);
});

test("profile UI rejects stale writes instead of overwriting a newer revision", async (t) => {
  const { paths, id } = fixture(t);
  const started = await startProfileWizardServer({ profileId: id, paths });
  t.after(() => started.close());
  const credentials = launchCredentials(started);
  const stateResponse = await api(started, credentials, "/api/state");
  const initial = (await stateResponse.json()).state;
  const base = {
    baseRevision: initial.profile.revision,
    baseProfileSha256: initial.profile.profileSha256
  };

  const first = await api(started, credentials, "/api/answer", { body: {
    ...base,
    questionId: "identity-objective",
    value: "First writer's assessment objective."
  } });
  assert.equal(first.status, 200);

  const stale = await api(started, credentials, "/api/answer", { body: {
    ...base,
    questionId: "identity-objective",
    value: "Stale writer must not replace this."
  } });
  const stalePayload = await stale.json();
  assert.equal(stale.status, 409);
  assert.equal(stalePayload.error.code, "stale-profile");
  assert.equal(resumeProgramProfile(id, { paths }).answers.answers["identity-objective"], "First writer's assessment objective.");
});

test("profile UI never reflects a rejected sensitive answer in its error", async (t) => {
  const { paths, id } = fixture(t);
  const started = await startProfileWizardServer({ profileId: id, paths });
  t.after(() => started.close());
  const credentials = launchCredentials(started);
  const stateResponse = await api(started, credentials, "/api/state");
  const current = (await stateResponse.json()).state;

  const rejected = await api(started, credentials, "/api/answer", { body: {
    questionId: "authority-contacts",
    value: secretCanary,
    baseRevision: current.profile.revision,
    baseProfileSha256: current.profile.profileSha256
  } });
  const body = await rejected.text();
  assert.equal(rejected.status, 422);
  assert.doesNotMatch(body, new RegExp(secretCanary, "u"));
});

test("profile UI rejects DNS-rebinding Host values", async (t) => {
  const { paths, id } = fixture(t);
  const started = await startProfileWizardServer({ profileId: id, paths });
  t.after(() => started.close());
  const status = await new Promise((resolve, reject) => {
    const request = http.request({
      host: started.host,
      port: started.port,
      path: "/",
      method: "GET",
      headers: { Host: "attacker.example" }
    }, (response) => {
      response.resume();
      response.on("end", () => resolve(response.statusCode));
    });
    request.on("error", reject);
    request.end();
  });
  assert.equal(status, 421);
});

test("profile UI enforces its bounded request budget", async (t) => {
  const { paths, id } = fixture(t);
  const started = await startProfileWizardServer({ profileId: id, paths, maxRequests: 1 });
  t.after(() => started.close());
  assert.equal((await fetch(`${started.origin}/`)).status, 200);
  assert.equal((await fetch(`${started.origin}/`)).status, 429);
});

test("profile UI can hand its private launch URL to an injected browser opener", async (t) => {
  const { paths, id } = fixture(t);
  let openedUrl = null;
  const started = await startProfileWizardServer({
    profileId: id,
    paths,
    openBrowser: true,
    browserOpener: async (url) => { openedUrl = url; }
  });
  t.after(() => started.close());
  assert.equal(started.browserOpened, true);
  assert.equal(openedUrl, started.url);
  assert.match(openedUrl, /#session=[A-Za-z0-9_-]+&csrf=[A-Za-z0-9_-]+$/u);
});
