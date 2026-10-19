import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  DEFAULT_RUNNER_CLOCK_SKEW_MS,
  MemoryRunnerNonceStore,
  RUNNER_AUTH_HEADERS,
  RunnerAuthError,
  canonicalRunnerRequest,
  createRunnerRequestSigner,
  signRunnerRequest,
  verifyRunnerRequest
} from "../runner-auth.mjs";

const NOW = 1_800_000_000_000;
const NONCE = "0123456789abcdef0123456789abcdef";
const RUNNER_ID = "runner.primary-1";
const METHOD = "POST";
const PATH = "/v1/runner/events?case=alpha%2Fone&view=compact";
const BODY = Buffer.from('{"kind":"heartbeat","sequence":7}\n', "utf8");
const primary = crypto.generateKeyPairSync("ed25519");
const secondary = crypto.generateKeyPairSync("ed25519");

function freshStore() {
  return new MemoryRunnerNonceStore({ now: () => NOW });
}

function signed(overrides = {}) {
  return signRunnerRequest({
    runnerId: RUNNER_ID,
    privateKey: primary.privateKey,
    method: METHOD,
    path: PATH,
    body: BODY,
    timestamp: NOW,
    nonce: NONCE,
    ...overrides
  });
}

function verification(overrides = {}) {
  return {
    headers: signed(),
    publicKeys: new Map([[RUNNER_ID, primary.publicKey]]),
    nonceStore: freshStore(),
    method: METHOD,
    path: PATH,
    body: BODY,
    now: NOW,
    ...overrides
  };
}

async function rejectsAuth(value, code = "runner-auth-rejected") {
  await assert.rejects(verifyRunnerRequest(value), (error) => {
    assert.ok(error instanceof RunnerAuthError);
    assert.equal(error.code, code);
    assert.doesNotMatch(error.message, new RegExp(`${RUNNER_ID}|${NONCE}`, "u"));
    return true;
  });
}

test("signs and verifies the exact request with only a sanitized runner identity", async () => {
  const headers = signed();
  assert.deepEqual(Object.keys(headers), Object.values(RUNNER_AUTH_HEADERS));
  assert.equal(headers["X-GATE-Runner"], RUNNER_ID);
  assert.match(headers["X-GATE-Body-SHA256"], /^[a-f0-9]{64}$/u);
  assert.match(headers["X-GATE-Signature"], /^[A-Za-z0-9_-]{86}$/u);

  const identity = await verifyRunnerRequest(verification({ headers }));
  assert.deepEqual(identity, { runnerId: RUNNER_ID });
  assert.deepEqual(Object.keys(identity), ["runnerId"]);
  assert.ok(Object.isFrozen(identity));
});

test("canonical request binds the version and every request field without path normalization", () => {
  const bodySha256 = crypto.createHash("sha256").update(BODY).digest("hex");
  const canonical = canonicalRunnerRequest({
    runnerId: RUNNER_ID,
    method: METHOD,
    path: PATH,
    timestamp: NOW,
    nonce: NONCE,
    bodySha256
  });
  for (const value of ["gate.runner-request/v1", RUNNER_ID, METHOD, PATH, String(NOW), NONCE, bodySha256]) {
    assert.ok(canonical.includes(value));
  }
  assert.notEqual(canonical, canonicalRunnerRequest({
    runnerId: RUNNER_ID,
    method: METHOD,
    path: PATH.replace("%2F", "%2f"),
    timestamp: NOW,
    nonce: NONCE,
    bodySha256
  }));
});

test("factory signer retains but never exposes the supplied private key", async () => {
  const signer = createRunnerRequestSigner({
    runnerId: RUNNER_ID,
    privateKey: primary.privateKey,
    now: () => NOW,
    nonceFactory: () => NONCE
  });
  assert.deepEqual(Object.keys(signer), ["sign"]);
  const headers = signer.sign({ method: METHOD, path: PATH, body: BODY });
  assert.equal(headers["X-GATE-Timestamp"], String(NOW));
  assert.equal(headers["X-GATE-Nonce"], NONCE);
  assert.deepEqual(await verifyRunnerRequest(verification({ headers })), { runnerId: RUNNER_ID });
});

test("rejects tampering with method, exact path and query, or body", async () => {
  await rejectsAuth(verification({ method: "PUT" }));
  await rejectsAuth(verification({ path: "/v1/runner/events?view=compact&case=alpha%2Fone" }));
  await rejectsAuth(verification({ path: `${PATH}&extra=1` }));
  await rejectsAuth(verification({ body: Buffer.from('{"kind":"heartbeat","sequence":8}\n') }));

  const signatureHeaders = { ...signed() };
  signatureHeaders["X-GATE-Signature"] = `${signatureHeaders["X-GATE-Signature"][0] === "A" ? "B" : "A"}${signatureHeaders["X-GATE-Signature"].slice(1)}`;
  await rejectsAuth(verification({ headers: signatureHeaders }));
});

test("validates the body digest before attempting signature verification", async () => {
  const headers = { ...signed(), "X-GATE-Body-SHA256": "0".repeat(64) };
  const publicKeys = new Proxy(Object.create(null), {
    getOwnPropertyDescriptor() {
      throw new Error("public key must not be read before digest validation");
    }
  });
  await rejectsAuth(verification({ headers, publicKeys }));
});

test("atomically rejects replay of a previously accepted runner nonce", async () => {
  const store = freshStore();
  const request = verification({ nonceStore: store });
  assert.deepEqual(await verifyRunnerRequest(request), { runnerId: RUNNER_ID });
  await rejectsAuth(request, "runner-auth-replayed");
});

test("rejects timestamps at and beyond the default skew in either direction", async () => {
  for (const timestamp of [
    NOW - DEFAULT_RUNNER_CLOCK_SKEW_MS - 1,
    NOW - DEFAULT_RUNNER_CLOCK_SKEW_MS,
    NOW + DEFAULT_RUNNER_CLOCK_SKEW_MS,
    NOW + DEFAULT_RUNNER_CLOCK_SKEW_MS + 1
  ]) {
    await rejectsAuth(verification({ headers: signed({ timestamp }) }));
  }
  assert.deepEqual(await verifyRunnerRequest(verification({
    headers: signed({ timestamp: NOW - DEFAULT_RUNNER_CLOCK_SKEW_MS + 1 })
  })), { runnerId: RUNNER_ID });
});

test("retains an accepted nonce through the final millisecond of its verification window", async () => {
  const timestamp = NOW - DEFAULT_RUNNER_CLOCK_SKEW_MS + 1;
  let storeNow = NOW;
  const store = new MemoryRunnerNonceStore({ now: () => storeNow });
  const request = verification({
    headers: signed({ timestamp }),
    nonceStore: store,
    now: NOW
  });
  assert.deepEqual(await verifyRunnerRequest(request), { runnerId: RUNNER_ID });
  storeNow = timestamp + DEFAULT_RUNNER_CLOCK_SKEW_MS - 1;
  await rejectsAuth({ ...request, now: storeNow }, "runner-auth-replayed");
  await rejectsAuth({ ...request, now: timestamp + DEFAULT_RUNNER_CLOCK_SKEW_MS });
});

test("selects the public key by an exact runner ID and rejects wrong identities and keys", async () => {
  await rejectsAuth(verification({ publicKeys: new Map([[RUNNER_ID, secondary.publicKey]]) }));
  await rejectsAuth(verification({ publicKeys: new Map([[`${RUNNER_ID}-other`, primary.publicKey]]) }));

  const changedIdentityHeaders = { ...signed(), "X-GATE-Runner": "runner.secondary-1" };
  await rejectsAuth(verification({
    headers: changedIdentityHeaders,
    publicKeys: new Map([["runner.secondary-1", primary.publicKey]])
  }));

  const otherRunner = "runner.secondary-1";
  const headers = signed({ runnerId: otherRunner });
  await rejectsAuth(verification({
    headers,
    publicKeys: new Map([[RUNNER_ID, primary.publicKey], [otherRunner, secondary.publicKey]])
  }));
});

test("accepts an Ed25519 public PEM without returning key material", async () => {
  const publicPem = primary.publicKey.export({ type: "spki", format: "pem" });
  const identity = await verifyRunnerRequest(verification({
    publicKeys: Object.freeze({ [RUNNER_ID]: publicPem })
  }));
  assert.deepEqual(identity, { runnerId: RUNNER_ID });
  assert.doesNotMatch(JSON.stringify(identity), /PUBLIC KEY/u);
});

test("rejects duplicate, array, merged, missing, and unknown GATE header representations", async () => {
  const headers = signed();
  const malformed = [
    { ...headers, "x-gate-runner": RUNNER_ID },
    { ...headers, "X-GATE-Nonce": [NONCE, NONCE] },
    { ...headers, "X-GATE-Signature": `${headers["X-GATE-Signature"]}, ${headers["X-GATE-Signature"]}` },
    Object.fromEntries(Object.entries(headers).filter(([name]) => name !== "X-GATE-Timestamp")),
    { ...headers, "X-GATE-Version": "v1" },
    { ...headers, "X-GATE-Timestamp": ` ${NOW}` }
  ];
  for (const candidate of malformed) {
    await rejectsAuth(verification({ headers: candidate }), "runner-auth-invalid");
  }

  const rawHeaders = Object.entries(headers).flat();
  rawHeaders.push("x-gate-nonce", NONCE);
  await rejectsAuth(verification({ headers: rawHeaders }), "runner-auth-invalid");

  const fetchHeaders = new Headers(headers);
  fetchHeaders.append("X-GATE-Nonce", NONCE);
  await rejectsAuth(verification({ headers: fetchHeaders }), "runner-auth-invalid");
});

test("rejects malformed request fields and non-Ed25519 key material", async () => {
  const ec = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  assert.throws(() => signed({ privateKey: ec.privateKey }), /Ed25519/u);
  for (const overrides of [
    { runnerId: "bad runner" },
    { method: "post" },
    { path: "https://gate.example/v1/runner" },
    { path: "/v1/runner#fragment" },
    { nonce: "too-short" },
    { timestamp: "01800000000000" }
  ]) {
    assert.throws(() => signed(overrides), RunnerAuthError);
  }
});

test("fails closed when the replay store is absent, full, or unavailable", async () => {
  await assert.rejects(verifyRunnerRequest({ ...verification(), nonceStore: undefined }), TypeError);
  await rejectsAuth(verification({ nonceStore: { consume: async () => { throw new Error("down"); } } }),
    "runner-auth-unavailable");
  await rejectsAuth(verification({ nonceStore: { consume: async () => undefined } }), "runner-auth-replayed");
});
