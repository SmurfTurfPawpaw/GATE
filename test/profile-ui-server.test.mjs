import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { createProgramProfile, resumeProgramProfile } from "../src/lib/bounty-profiles.mjs";
import { runtimePaths } from "../src/lib/paths.mjs";
import { loadProgramProfileQuestionnaire } from "../src/lib/program-profile-contract.mjs";
import { profileUiControllerInternals } from "../src/profile-ui/controller.mjs";
import { profileUiServerInternals, startProfileWizardServer } from "../src/profile-ui/server.mjs";
import { isoFromUtcInput, utcDisplayFromIso, utcInputFromIso } from "../profile-ui/time.js";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixedAt = "2026-10-16T08:00:00.000Z";
const privateCanary = "PRIVATE_PROFILE_NOTE_CANARY_83d75e";
const secretCanary = "Bearer PROFILE_UI_SECRET_CANARY_74f92c";

function fixture(t, id = "browser-profile", options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-profile-ui-"));
  const paths = runtimePaths({ repo, home: path.join(root, "home") });
  const additionalAnswers = structuredClone(options.answers || {});
  createProgramProfile(id, {
    ...additionalAnswers,
    authorization: {
      sourceRefs: options.authorityRefs === undefined ? ["program-rules"] : options.authorityRefs,
      ...(additionalAnswers.authorization || {})
    },
    sources: additionalAnswers.sources || [
      {
        id: "program-rules",
        type: "program-rules",
        title: "Published program rules",
        reference: "https://private-reference-canary.example.test/rules",
        contentSha256: "a".repeat(64),
        observedAt: options.authorityObservedAt || fixedAt,
        claimState: options.authorityClaimState || "observed",
        notes: privateCanary
      },
      {
        id: "account-source",
        type: "account-instructions",
        title: "Research account instructions",
        reference: "https://account-reference-canary.example.test/rules",
        contentSha256: "b".repeat(64),
        observedAt: fixedAt,
        claimState: "observed",
        notes: "Separate source outside the current authority basis."
      }
    ]
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

test("profile UI canonicalizes the default HTTP port for browser Host headers", () => {
  assert.equal(profileUiServerInternals.expectedHost("127.0.0.1", 80), "127.0.0.1");
  assert.equal(profileUiServerInternals.expectedHost("::1", 80), "[::1]");
  assert.equal(profileUiServerInternals.expectedHost("127.0.0.1", 4173), "127.0.0.1:4173");
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

  const accessibilityModule = await fetch(`${started.origin}/profile-ui/accessibility.js`);
  assert.equal(accessibilityModule.status, 200);
  assert.match(accessibilityModule.headers.get("content-type"), /text\/javascript/u);
  assert.match(await accessibilityModule.text(), /bindFieldLabel/u);
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
  assert.equal(payload.state.sources.length, 2);
  assert.deepEqual(payload.state.authorizationSources, [{
    id: "program-rules",
    title: "Published program rules",
    type: "program-rules",
    observedAt: fixedAt,
    claimState: "observed",
    contentDigestRecorded: true,
    resolved: true,
    missing: false
  }]);
  assert.doesNotMatch(JSON.stringify(payload.state.sources), new RegExp(privateCanary, "u"));
  assert.doesNotMatch(JSON.stringify(payload.state.sources), /private-reference-canary/u);
  for (const question of payload.state.sections.flatMap((section) => section.questions)) {
    assert.equal(Object.hasOwn(question.recommendation, "value"), false);
  }
});

test("serialized recommendations expose bounded claim state but hide sensitive values and basis", (t) => {
  const { paths, id } = fixture(t, "recommendation-privacy");
  const valueCanary = "PRIVATE_RECOMMENDATION_VALUE_CANARY_29ad";
  const basisCanary = "PRIVATE_RECOMMENDATION_BASIS_CANARY_f631";
  const stateCanary = "PRIVATE_RECOMMENDATION_STATE_CANARY_3b90";
  const questionnaire = loadProgramProfileQuestionnaire({ paths });
  const resolveRecommendation = (question) => {
    if (question.id === "authority-contacts") {
      return {
        available: true,
        value: [{ name: valueCanary }],
        provenance: "local-derived",
        summary: basisCanary,
        reason: basisCanary,
        basis: { claimState: "inferred", sourceCount: 1, policy: basisCanary }
      };
    }
    if (question.id === "identity-objective") {
      return {
        available: true,
        value: "A bounded assessment objective.",
        provenance: "source-derived",
        summary: "A reviewed source supports this objective.",
        basis: { claimState: "observed", sourceCount: 2 }
      };
    }
    if (question.id === "identity-success-criteria") {
      return {
        available: true,
        value: ["Produce a reproducible report."],
        provenance: "source-derived",
        summary: "A supported recommendation.",
        basis: { claimState: stateCanary, sourceCount: 1 }
      };
    }
    return { available: false, reason: "unavailable", summary: "No recommendation." };
  };
  const serialized = profileUiControllerInternals.serializeState(
    id,
    resumeProgramProfile(id, { paths }),
    questionnaire,
    resolveRecommendation
  );
  const questions = serialized.sections.flatMap((section) => section.questions);
  const sensitive = questions.find((question) => question.id === "authority-contacts").recommendation;
  assert.equal(sensitive.available, true);
  assert.equal(sensitive.claimState, "inferred");
  assert.equal(sensitive.basis, null);
  assert.equal(sensitive.reason, null);
  assert.equal(Object.hasOwn(sensitive, "value"), false);
  assert.match(sensitive.summary, /supporting details remain hidden/u);
  assert.doesNotMatch(JSON.stringify(serialized), new RegExp(`${valueCanary}|${basisCanary}|${stateCanary}`, "u"));

  const nonsensitive = questions.find((question) => question.id === "identity-objective").recommendation;
  assert.equal(nonsensitive.claimState, "observed");
  assert.equal(nonsensitive.basis, "2 cited local sources");
  const bounded = questions.find((question) => question.id === "identity-success-criteria").recommendation;
  assert.equal(bounded.claimState, null);
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
  assert.equal(reviewed.status, 422);
  const exactReview = await api(started, credentials, "/api/answer", { body: {
    ...answer,
    reviewAcknowledged: true,
    reviewedSourceRefs: ["program-rules"]
  } });
  assert.equal(exactReview.status, 200);
  assert.equal(resumeProgramProfile(id, { paths }).answers.answers[answer.questionId], true);
});

test("future-dated observed authority sources remain unresolved and cannot be confirmed", async (t) => {
  const decisionAt = "2026-10-16T08:30:00.000Z";
  const { paths, id } = fixture(t, "future-authority-source", {
    authorityObservedAt: "2026-10-16T09:00:00.000Z"
  });
  const started = await startProfileWizardServer({ profileId: id, paths, now: () => decisionAt });
  t.after(() => started.close());
  const credentials = launchCredentials(started);
  const stateResponse = await api(started, credentials, "/api/state");
  const current = (await stateResponse.json()).state;
  assert.equal(current.authorizationSources[0].claimState, "observed");
  assert.equal(current.authorizationSources[0].resolved, false);

  const response = await api(started, credentials, "/api/answer", { body: {
    questionId: "authority-operator-confirmed",
    value: true,
    reviewAcknowledged: true,
    reviewedSourceRefs: ["program-rules"],
    baseRevision: current.profile.revision,
    baseProfileSha256: current.profile.profileSha256
  } });
  const payload = await response.json();
  assert.equal(response.status, 422);
  assert.equal(payload.error.code, "source-review-required");
  assert.deepEqual(payload.error.fields, [{
    path: "authorization.sourceRefs",
    message: "Every authority source must have a valid observation time at or before this review."
  }]);
  assert.equal(resumeProgramProfile(id, { paths }).profile.metadata.revision, current.profile.revision);
  assert.equal(resumeProgramProfile(id, { paths }).profile.authorization.operatorConfirmed, false);
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

  const structurallyRejected = await api(started, credentials, "/api/answer", { body: {
    questionId: "authority-contacts",
    value: [{
      name: "Program security team",
      role: "Authority contact",
      channel: `${secretCanary}\n/authorization/PRIVATE_VALUE_CANARY`,
      purpose: "Clarify authority and receive escalation.",
      sourceRefs: ["program-rules"]
    }],
    baseRevision: current.profile.revision,
    baseProfileSha256: current.profile.profileSha256
  } });
  const structuralBody = await structurallyRejected.text();
  assert.equal(structurallyRejected.status, 422);
  assert.doesNotMatch(structuralBody, new RegExp(secretCanary, "u"));
  assert.doesNotMatch(structuralBody, /PRIVATE_VALUE_CANARY/u);
  assert.deepEqual(JSON.parse(structuralBody).error.fields, [{
    path: "authorization.contacts",
    message: "This answer did not match its required structure."
  }]);
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

test("profile UI round-trips authority and attestation instants under Europe/Brussels without drift", async (t) => {
  const previousTimezone = process.env.TZ;
  process.env.TZ = "Europe/Brussels";
  t.after(() => {
    if (previousTimezone === undefined) delete process.env.TZ;
    else process.env.TZ = previousTimezone;
  });
  const { paths, id } = fixture(t);
  const started = await startProfileWizardServer({ profileId: id, paths });
  t.after(() => started.close());
  const credentials = launchCredentials(started);
  const instant = "2026-07-19T10:27:45.123Z";
  assert.equal(utcInputFromIso(instant), "2026-07-19T10:27:45.123");
  assert.equal(utcInputFromIso("2026-07-19T12:27:45.123+02:00"), "2026-07-19T10:27:45.123");
  assert.equal(utcInputFromIso("2026-07-19T10:27"), "");
  assert.equal(utcDisplayFromIso("2026-07-19T12:27:45.123+02:00"), "2026-07-19 10:27:45.123 UTC");
  assert.equal(isoFromUtcInput(utcInputFromIso(instant)), instant);

  let response = await api(started, credentials, "/api/state");
  let current = (await response.json()).state;
  for (const questionId of ["authority-valid-from", "attestation-at"]) {
    let browserValue = isoFromUtcInput(utcInputFromIso(instant));
    for (let save = 0; save < 2; save += 1) {
      response = await api(started, credentials, "/api/answer", { body: {
        questionId,
        value: browserValue,
        baseRevision: current.profile.revision,
        baseProfileSha256: current.profile.profileSha256
      } });
      assert.equal(response.status, 200);
      current = (await response.json()).state;
      assert.equal(
        resumeProgramProfile(id, { paths }).answers.answers[questionId],
        instant,
        `${questionId} was not preserved in the private answer envelope after save ${save + 1}`
      );
      const saved = current.sections.flatMap((section) => section.questions)
        .find((question) => question.id === questionId).value;
      assert.equal(saved, instant, `${questionId} changed after save ${save + 1}`);
      browserValue = isoFromUtcInput(utcInputFromIso(saved));
    }
  }
  const answers = resumeProgramProfile(id, { paths }).answers.answers;
  assert.equal(answers["authority-valid-from"], instant);
  assert.equal(answers["attestation-at"], instant);
});

test("required module lists remain incomplete when a stored or submitted answer is empty", async (t) => {
  const { paths, id } = fixture(t, "empty-required-module-answer", {
    answers: {
      questionnaire: { applicableModules: ["web-api"] },
      modules: { "web-api": { answers: { entryPoints: [] } } },
      authorization: { programUrl: null }
    }
  });
  const questionnaire = loadProgramProfileQuestionnaire({ paths });
  const recommendationState = profileUiControllerInternals.serializeState(
    id,
    resumeProgramProfile(id, { paths }),
    questionnaire,
    (question) => question.id === "web-api-entry-points"
      ? { available: true, value: ["https://example.test/api"], summary: "Reviewed entry point." }
      : { available: false, summary: "No recommendation." }
  );
  const recommendedEntryPoints = recommendationState.sections.flatMap((section) => section.questions)
    .find((question) => question.id === "web-api-entry-points");
  assert.equal(recommendedEntryPoints.answered, false);
  assert.equal(recommendedEntryPoints.answerPresent, true);
  assert.equal(recommendedEntryPoints.recommendation.available, true);
  assert.equal(recommendationState.recommendationCount, 0, "a saved incomplete value remains an explicit answer");

  const started = await startProfileWizardServer({ profileId: id, paths });
  t.after(() => started.close());
  const credentials = launchCredentials(started);
  const stateResponse = await api(started, credentials, "/api/state");
  const current = (await stateResponse.json()).state;
  const questions = current.sections.flatMap((section) => section.questions);
  const entryPoints = questions.find((question) => question.id === "web-api-entry-points");
  assert.equal(entryPoints.applicable, true);
  assert.deepEqual(entryPoints.value, []);
  assert.equal(entryPoints.answered, false);
  assert.equal(entryPoints.answerPresent, true);
  assert.equal(
    current.progress.requiredRemaining,
    questions.filter((question) => question.applicable && question.required && !question.answered).length
  );
  assert.equal(
    current.recommendationCount,
    questions.filter((question) =>
      question.applicable && !question.answerPresent && question.recommendation.available && !question.manualOnly).length
  );
  const optionalProgramUrl = questions.find((question) => question.id === "authority-program-url");
  assert.equal(optionalProgramUrl.required, false);
  assert.equal(optionalProgramUrl.answered, true);
  assert.equal(optionalProgramUrl.answerPresent, true);

  const response = await api(started, credentials, "/api/answer", { body: {
    questionId: "web-api-entry-points",
    value: [],
    baseRevision: current.profile.revision,
    baseProfileSha256: current.profile.profileSha256
  } });
  const payload = await response.json();
  assert.equal(response.status, 422);
  assert.equal(payload.error.code, "answer-incomplete");
  assert.deepEqual(payload.error.fields, [{
    path: "modules.web-api.answers.entryPoints",
    message: "Add at least one meaningful item or leave this question unresolved for now."
  }]);
  assert.equal(resumeProgramProfile(id, { paths }).profile.metadata.revision, current.profile.revision);

  const clearedResponse = await api(started, credentials, "/api/answer/clear", { body: {
    questionId: "web-api-entry-points",
    baseRevision: current.profile.revision,
    baseProfileSha256: current.profile.profileSha256
  } });
  const cleared = (await clearedResponse.json()).state;
  assert.equal(clearedResponse.status, 200);
  assert.equal(Object.hasOwn(resumeProgramProfile(id, { paths }).answers.answers, "web-api-entry-points"), false);
  const clearedEntryPoints = cleared.sections.flatMap((section) => section.questions)
    .find((question) => question.id === "web-api-entry-points");
  assert.equal(clearedEntryPoints.answerPresent, false);
  assert.equal(clearedEntryPoints.answered, false);
});

test("required core lists use semantic completeness while an empty module selection remains valid", async (t) => {
  const { paths, id } = fixture(t, "empty-required-core-answer", {
    answers: {
      identity: { deliverables: [] },
      questionnaire: { applicableModules: [] }
    }
  });
  const started = await startProfileWizardServer({ profileId: id, paths });
  t.after(() => started.close());
  const credentials = launchCredentials(started);
  const stateResponse = await api(started, credentials, "/api/state");
  const current = (await stateResponse.json()).state;
  const questions = current.sections.flatMap((section) => section.questions);
  const deliverables = questions.find((question) => question.id === "identity-deliverables");
  assert.deepEqual(deliverables.value, []);
  assert.equal(deliverables.answerPresent, true);
  assert.equal(deliverables.answered, false);
  const modules = questions.find((question) => question.id === "coverage-applicable-modules");
  assert.deepEqual(modules.value, []);
  assert.equal(modules.answerPresent, true);
  assert.equal(modules.answered, true);

  const response = await api(started, credentials, "/api/answer", { body: {
    questionId: "identity-deliverables",
    value: [],
    baseRevision: current.profile.revision,
    baseProfileSha256: current.profile.profileSha256
  } });
  const payload = await response.json();
  assert.equal(response.status, 422);
  assert.equal(payload.error.code, "answer-incomplete");
  assert.deepEqual(payload.error.fields, [{
    path: "identity.deliverables",
    message: "Add at least one meaningful item or leave this question unresolved for now."
  }]);
  assert.equal(resumeProgramProfile(id, { paths }).profile.metadata.revision, current.profile.revision);
});

test("UTC date-time parser rejects calendar rollover instead of normalizing it", () => {
  assert.throws(() => isoFromUtcInput("2026-02-30T12:00"), /valid UTC date and time/u);
});

test("authority confirmation rejects unresolved sources and reports a safe field path", async (t) => {
  const { paths, id } = fixture(t, "unresolved-authority", { authorityClaimState: "unverified" });
  const started = await startProfileWizardServer({ profileId: id, paths });
  t.after(() => started.close());
  const credentials = launchCredentials(started);
  const stateResponse = await api(started, credentials, "/api/state");
  const current = (await stateResponse.json()).state;
  assert.equal(current.authorizationSources[0].resolved, false);
  const response = await api(started, credentials, "/api/answer", { body: {
    questionId: "authority-operator-confirmed",
    value: true,
    reviewAcknowledged: true,
    reviewedSourceRefs: ["program-rules"],
    baseRevision: current.profile.revision,
    baseProfileSha256: current.profile.profileSha256
  } });
  const payload = await response.json();
  assert.equal(response.status, 422);
  assert.equal(payload.error.code, "source-review-required");
  assert.deepEqual(payload.error.fields, [{
    path: "authorization.sourceRefs",
    message: "Every authority source must be observed before confirmation."
  }]);
  assert.doesNotMatch(JSON.stringify(payload.error), /PRIVATE_PROFILE|private-reference|account-reference/u);
});

test("authority confirmation rejects an empty current source basis", async (t) => {
  const { paths, id } = fixture(t, "authority-without-sources", { authorityRefs: [] });
  const started = await startProfileWizardServer({ profileId: id, paths });
  t.after(() => started.close());
  const credentials = launchCredentials(started);
  const stateResponse = await api(started, credentials, "/api/state");
  const current = (await stateResponse.json()).state;
  assert.deepEqual(current.authorizationSources, []);

  const response = await api(started, credentials, "/api/answer", { body: {
    questionId: "authority-operator-confirmed",
    value: true,
    reviewAcknowledged: true,
    reviewedSourceRefs: [],
    baseRevision: current.profile.revision,
    baseProfileSha256: current.profile.profileSha256
  } });
  const payload = await response.json();
  assert.equal(response.status, 422);
  assert.equal(payload.error.code, "source-review-required");
  assert.deepEqual(payload.error.fields, [{
    path: "authorization.sourceRefs",
    message: "Add the sources that establish authority before confirming."
  }]);
});

test("guided contact validation returns actionable paths without reflecting values", async (t) => {
  const { paths, id } = fixture(t, "contact-validation");
  const started = await startProfileWizardServer({ profileId: id, paths });
  t.after(() => started.close());
  const credentials = launchCredentials(started);
  const stateResponse = await api(started, credentials, "/api/state");
  const current = (await stateResponse.json()).state;
  const response = await api(started, credentials, "/api/answer", { body: {
    questionId: "authority-contacts",
    value: [{
      name: "",
      role: "Program authority",
      channel: secretCanary,
      purpose: "Clarify authority and receive escalation.",
      sourceRefs: ["program-rules"]
    }],
    baseRevision: current.profile.revision,
    baseProfileSha256: current.profile.profileSha256
  } });
  const payload = await response.json();
  assert.equal(response.status, 422);
  assert.equal(payload.error.code, "required-fields-missing");
  assert.deepEqual(payload.error.fields, [{
    path: "authorization.contacts.0.name",
    message: "Name is required."
  }]);
  assert.doesNotMatch(JSON.stringify(payload), new RegExp(secretCanary, "u"));
});

test("changing the current authority source set requires a fresh confirmation", async (t) => {
  const { paths, id } = fixture(t, "authority-source-change");
  const started = await startProfileWizardServer({ profileId: id, paths });
  t.after(() => started.close());
  const credentials = launchCredentials(started);
  let response = await api(started, credentials, "/api/state");
  let current = (await response.json()).state;
  response = await api(started, credentials, "/api/answer", { body: {
    questionId: "authority-operator-confirmed",
    value: true,
    reviewAcknowledged: true,
    reviewedSourceRefs: ["program-rules"],
    baseRevision: current.profile.revision,
    baseProfileSha256: current.profile.profileSha256
  } });
  current = (await response.json()).state;
  response = await api(started, credentials, "/api/answer", { body: {
    questionId: "authority-source-refs",
    value: ["account-source"],
    baseRevision: current.profile.revision,
    baseProfileSha256: current.profile.profileSha256
  } });
  assert.equal(response.status, 200);
  current = (await response.json()).state;
  const confirmation = current.sections.flatMap((section) => section.questions)
    .find((question) => question.id === "authority-operator-confirmed");
  assert.equal(confirmation.answered, false);
  assert.deepEqual(current.authorizationSourceRefs, ["account-source"]);
  assert.deepEqual(current.authorizationSources.map((source) => source.id), ["account-source"]);
});

test("clear answer is stale-base protected and removes the saved envelope value", async (t) => {
  const { paths, id } = fixture(t, "clear-answer-profile");
  const started = await startProfileWizardServer({ profileId: id, paths });
  t.after(() => started.close());
  const credentials = launchCredentials(started);
  let response = await api(started, credentials, "/api/state");
  const initial = (await response.json()).state;
  response = await api(started, credentials, "/api/answer", { body: {
    questionId: "identity-objective",
    value: "A temporary assessment objective.",
    baseRevision: initial.profile.revision,
    baseProfileSha256: initial.profile.profileSha256
  } });
  const answered = (await response.json()).state;
  const stale = await api(started, credentials, "/api/answer/clear", { body: {
    questionId: "identity-objective",
    baseRevision: initial.profile.revision,
    baseProfileSha256: initial.profile.profileSha256
  } });
  assert.equal(stale.status, 409);

  const cleared = await api(started, credentials, "/api/answer/clear", { body: {
    questionId: "identity-objective",
    baseRevision: answered.profile.revision,
    baseProfileSha256: answered.profile.profileSha256
  } });
  assert.equal(cleared.status, 200);
  assert.equal(Object.hasOwn(resumeProgramProfile(id, { paths }).answers.answers, "identity-objective"), false);
});
