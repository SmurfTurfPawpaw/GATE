import assert from "node:assert/strict";
import { test } from "node:test";

import {
  SESSION_COOKIE_NAME,
  SessionStore,
  SessionStoreError
} from "../sessions.mjs";

const ORIGIN = "https://gate.example.test";

test("create returns only a sanitized immutable session, CSRF proof, and hardened cookie", () => {
  const clock = mutableClock(1_000);
  const identity = { provider: "oidc", subject: "operator-1", roles: ["operator"] };
  const store = new SessionStore({ clock, randomBytes: deterministicRandom() });

  const created = store.create(identity);
  identity.subject = "changed";

  assert.equal(created.session.identity.subject, "operator-1");
  assert.equal(Object.isFrozen(created.session), true);
  assert.equal(Object.isFrozen(created.session.identity), true);
  assert.match(created.session.id, /^session_[A-Za-z0-9_-]{43}$/u);
  assert.match(created.csrf, /^[A-Za-z0-9_-]{43}$/u);
  assert.match(created.setCookie, new RegExp(`^${SESSION_COOKIE_NAME}=[A-Za-z0-9_-]{43}; `, "u"));
  assert.match(created.setCookie, /; Path=\//u);
  assert.match(created.setCookie, /; Secure/u);
  assert.match(created.setCookie, /; HttpOnly/u);
  assert.match(created.setCookie, /; SameSite=Strict/u);
  assert.doesNotMatch(created.setCookie, /Domain=/iu);
  assert.equal("token" in created.session, false);
  assert.equal("csrf" in created.session, false);
  assert.equal(JSON.stringify(created).includes(cookieValue(created.setCookie)), true);
});

test("idle and absolute expiry are enforced and expired credentials are erased", () => {
  const clock = mutableClock(10_000);
  const store = new SessionStore({
    clock,
    randomBytes: deterministicRandom(),
    idleTtlMs: 100,
    absoluteTtlMs: 250,
    rotationIntervalMs: 1_000
  });

  const first = store.create("operator-1");
  clock.advance(99);
  const touched = store.authenticateCookie(cookieHeader(first));
  assert.ok(touched);
  assert.equal(touched.session.idleExpiresAt, 10_199);

  clock.advance(100);
  assert.equal(store.authenticateCookie(cookieHeader(touched)), null);
  assert.equal(store.size, 0);

  const second = store.create("operator-2");
  clock.advance(90);
  const secondTouch = store.authenticateCookie(cookieHeader(second));
  clock.advance(90);
  const thirdTouch = store.authenticateCookie(cookieHeader(secondTouch));
  assert.equal(thirdTouch.session.idleExpiresAt, thirdTouch.session.absoluteExpiresAt);
  clock.advance(70);
  assert.equal(store.authenticateCookie(cookieHeader(thirdTouch)), null);
});

test("rotation changes epoch and gives parallel requests one bounded previous-cookie grace", () => {
  const clock = mutableClock(2_000);
  const store = new SessionStore({
    clock,
    randomBytes: deterministicRandom(),
    rotationIntervalMs: 50,
    rotationGraceMs: 25
  });
  const created = store.create({ subject: "operator-1" });
  const originalToken = cookieValue(created.setCookie);

  clock.advance(50);
  const authenticated = store.authenticateCookie(cookieHeader(created));
  assert.ok(authenticated);
  assert.notEqual(cookieValue(authenticated.setCookie), originalToken);
  assert.equal(authenticated.session.epoch, created.session.epoch + 1);
  assert.equal(authenticated.session.revision, created.session.revision + 1);
  assert.deepEqual(authenticated.session.identity, created.session.identity);
  const parallel = store.authenticateCookie(`${SESSION_COOKIE_NAME}=${originalToken}`);
  assert.equal(parallel.session.id, created.session.id);
  assert.equal(parallel.setCookie, authenticated.setCookie,
    "a parallel request receives the already-rotated current credential");
  assert.equal(store.authenticateCookie(cookieHeader(authenticated))?.session.id, created.session.id,
    "presenting the replacement starts the bounded overlap window");
  clock.advance(25);
  assert.equal(store.authenticateCookie(`${SESSION_COOKIE_NAME}=${originalToken}`), null);
  assert.equal(store.authenticateCookie(cookieHeader(authenticated))?.session.id, created.session.id);

  assert.equal(store.revoke(created.session.id), true);
  assert.equal(store.revoke(created.session.id), false);
  assert.equal(store.authenticateCookie(cookieHeader(authenticated)), null);
});

test("active snapshot checks fail closed after rotation, revocation, and expiry without extending idle life", () => {
  const clock = mutableClock(2_500);
  const store = new SessionStore({
    clock,
    randomBytes: deterministicRandom(),
    idleTtlMs: 100,
    absoluteTtlMs: 500,
    rotationIntervalMs: 50
  });

  const created = store.create({ subject: "operator-1" });
  assert.equal(store.isActive(created.session), true);
  assert.equal(store.isActive({ session: created.session }), true);
  assert.equal(store.isActive(null), false);

  clock.advance(50);
  const rotated = store.authenticateCookie(cookieHeader(created));
  assert.equal(store.isActive(created.session), false, "a replaced epoch is no longer active");
  assert.equal(store.isActive(rotated.session), true);
  assert.equal(store.revoke(rotated.session.id), true);
  assert.equal(store.isActive(rotated.session), false);

  const expiring = store.create({ subject: "operator-2" });
  clock.advance(100);
  assert.equal(store.isActive(expiring.session), false, "checking the stream snapshot must not refresh idle expiry");
});

test("strict cookie parsing rejects duplicate, malformed, multiple-header, and oversized input", () => {
  const store = new SessionStore({
    clock: mutableClock(3_000),
    randomBytes: deterministicRandom(),
    maxCookieHeaderBytes: 200
  });
  const created = store.create("operator-1");
  const valid = cookieHeader(created);

  assert.throws(
    () => store.authenticateCookie(`${valid}; ${valid}`),
    (error) => error instanceof SessionStoreError && error.code === "cookie-header-duplicate"
  );
  assert.throws(
    () => store.authenticateCookie("broken"),
    (error) => error instanceof SessionStoreError && error.code === "cookie-header-malformed"
  );
  assert.throws(
    () => store.authenticateCookie([valid, valid]),
    (error) => error instanceof SessionStoreError && error.code === "cookie-header-malformed"
  );
  assert.throws(
    () => store.authenticateCookie(`noise=${"a".repeat(201)}`),
    (error) => error instanceof SessionStoreError && error.code === "cookie-header-oversized"
  );
});

test("CSRF validation requires an active epoch, exact origin, and same-site browser context", () => {
  const store = new SessionStore({ clock: mutableClock(4_000), randomBytes: deterministicRandom() });
  const created = store.create("operator-1");
  const authenticated = store.authenticateCookie(cookieHeader(created));
  const headers = { "x-gate-csrf": created.csrf, "sec-fetch-site": "same-origin" };

  assert.equal(
    store.requireCsrf(authenticated.session, ORIGIN, ORIGIN, headers).id,
    created.session.id
  );
  assert.equal(
    store.requireCsrf(authenticated, ORIGIN, ORIGIN, {
      "X-GATE-CSRF": created.csrf,
      "Sec-Fetch-Site": "same-site"
    }).id,
    created.session.id
  );
  assert.throws(
    () => store.requireCsrf(authenticated.session, `${ORIGIN}/`, ORIGIN, headers),
    hasCode("origin-rejected")
  );
  assert.throws(
    () => store.requireCsrf(authenticated.session, ORIGIN, ORIGIN, { "x-gate-csrf": created.csrf }),
    hasCode("fetch-site-rejected")
  );
  assert.throws(
    () => store.requireCsrf(authenticated.session, ORIGIN, ORIGIN, {
      "x-gate-csrf": created.csrf,
      "sec-fetch-site": "cross-site"
    }),
    hasCode("fetch-site-rejected")
  );
  assert.throws(
    () => store.requireCsrf(authenticated.session, ORIGIN, ORIGIN, {
      "x-gate-csrf": "A".repeat(43),
      "sec-fetch-site": "same-origin"
    }),
    hasCode("csrf-rejected")
  );
});

test("bounded store evicts the least recently used session deterministically", () => {
  const clock = mutableClock(5_000);
  const store = new SessionStore({
    clock,
    randomBytes: deterministicRandom(),
    maxSessions: 2,
    rotationIntervalMs: 1_000
  });
  const first = store.create("operator-1");
  clock.advance(1);
  const second = store.create("operator-2");
  clock.advance(1);
  const refreshedFirst = store.authenticateCookie(cookieHeader(first));
  clock.advance(1);
  const third = store.create("operator-3");

  assert.equal(store.size, 2);
  assert.equal(store.authenticateCookie(cookieHeader(second)), null);
  assert.ok(store.authenticateCookie(cookieHeader(refreshedFirst)));
  assert.ok(store.authenticateCookie(cookieHeader(third)));
});

test("clear permits reuse while close permanently rejects further operations", () => {
  const store = new SessionStore({ clock: mutableClock(6_000), randomBytes: deterministicRandom() });
  store.create("operator-1");
  assert.equal(store.clear(), 1);
  assert.equal(store.size, 0);
  store.create("operator-2");
  assert.equal(store.close(), 1);
  assert.equal(store.close(), 0);
  assert.throws(() => store.create("operator-3"), hasCode("store-closed"));
});

test("create rejects absent and mutable-structure identities", () => {
  const store = new SessionStore({ clock: mutableClock(7_000), randomBytes: deterministicRandom() });
  for (const identity of [undefined, null, true, 1, [], {}, new Date(0)]) {
    assert.throws(() => store.create(identity), hasCode("identity-invalid"));
  }
});

function cookieHeader(result) {
  return `${SESSION_COOKIE_NAME}=${cookieValue(result.setCookie)}`;
}

function cookieValue(setCookie) {
  return setCookie.slice(0, setCookie.indexOf(";")).slice(SESSION_COOKIE_NAME.length + 1);
}

function deterministicRandom() {
  let counter = 0;
  return (size) => {
    counter += 1;
    return Buffer.alloc(size, counter);
  };
}

function hasCode(code) {
  return (error) => error instanceof SessionStoreError && error.code === code;
}

function mutableClock(initial) {
  let now = initial;
  const clock = () => now;
  clock.advance = (milliseconds) => {
    now += milliseconds;
  };
  return clock;
}

