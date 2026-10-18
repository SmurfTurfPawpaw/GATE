import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import { createOidcVerifier, OidcVerificationError } from "../auth.mjs";

const NOW_MS = 1_800_000_000_000;
const NOW = Math.floor(NOW_MS / 1_000);
const ISSUER = "https://identity.example";
const AUDIENCE = "gate-remote";
const SUBJECT = "operator-immutable-id";
const JWKS_URL = "https://identity.example/.well-known/jwks.json";

const rsa = generateKeyPairSync("rsa", { modulusLength: 2_048 });
const ec = generateKeyPairSync("ec", { namedCurve: "prime256v1" });

function publicJwk(pair, kid, alg) {
  return { ...pair.publicKey.export({ format: "jwk" }), kid, alg, use: "sig", key_ops: ["verify"] };
}

const RSA_JWK = publicJwk(rsa, "rsa-key-1", "RS256");
const EC_JWK = publicJwk(ec, "ec-key-1", "ES256");

function encode(value) {
  return Buffer.from(typeof value === "string" ? value : JSON.stringify(value), "utf8").toString("base64url");
}

function makeToken({
  pair = rsa,
  alg = "RS256",
  kid = alg === "RS256" ? RSA_JWK.kid : EC_JWK.kid,
  header = { alg, kid, typ: "JWT" },
  claims = {},
  rawHeader,
  rawClaims
} = {}) {
  const completeClaims = {
    iss: ISSUER,
    sub: SUBJECT,
    aud: AUDIENCE,
    iat: NOW - 30,
    nbf: NOW - 30,
    exp: NOW + 270,
    ...claims
  };
  const encodedHeader = encode(rawHeader ?? header);
  const encodedClaims = encode(rawClaims ?? completeClaims);
  const input = `${encodedHeader}.${encodedClaims}`;
  const signature = sign(
    "sha256",
    Buffer.from(input, "ascii"),
    alg === "ES256" ? { key: pair.privateKey, dsaEncoding: "ieee-p1363" } : pair.privateKey
  );
  return `${input}.${signature.toString("base64url")}`;
}

function response(value, init = {}) {
  return new Response(typeof value === "string" ? value : JSON.stringify(value), {
    status: init.status ?? 200,
    headers: { "content-type": "application/json", ...init.headers }
  });
}

function verifier({ keys = [RSA_JWK], fetch, config = {}, clock = () => NOW_MS } = {}) {
  return createOidcVerifier(
    {
      issuer: ISSUER,
      audience: AUDIENCE,
      operatorSubject: SUBJECT,
      jwksUrl: JWKS_URL,
      clockSkewSeconds: 30,
      maxTokenLifetimeSeconds: 600,
      jwksCacheMs: 60_000,
      jwksTimeoutMs: 100,
      ...config
    },
    { fetch: fetch ?? (async () => response({ keys })), clock }
  );
}

async function rejectsCode(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof OidcVerificationError);
    assert.equal(error.message, "Identity assertion verification failed");
    assert.equal(error.code, code);
    return true;
  });
}

test("verifies RS256 and returns only frozen sanitized identity metadata", async () => {
  const token = makeToken();
  const identity = await verifier().verify(token);

  assert.deepEqual(identity, {
    issuer: ISSUER,
    subject: SUBJECT,
    audience: AUDIENCE,
    algorithm: "RS256",
    keyId: RSA_JWK.kid,
    issuedAt: NOW - 30,
    expiresAt: NOW + 270,
    notBefore: NOW - 30
  });
  assert.equal(Object.isFrozen(identity), true);
  assert.equal("token" in identity, false);
  assert.equal("claims" in identity, false);
  assert.throws(() => {
    identity.subject = "changed";
  }, TypeError);
});

test("verifies an ES256 P-256 assertion", async () => {
  const token = makeToken({ pair: ec, alg: "ES256" });
  const identity = await verifier({ keys: [EC_JWK] }).verify(token);
  assert.equal(identity.algorithm, "ES256");
  assert.equal(identity.keyId, EC_JWK.kid);
});

test("refreshes JWKS once for an unknown kid and then caches the result", async () => {
  let calls = 0;
  const verify = verifier({
    fetch: async () => {
      calls += 1;
      return response({ keys: calls === 1 ? [RSA_JWK] : [EC_JWK] });
    }
  });
  const token = makeToken({ pair: ec, alg: "ES256" });
  await verify.verify(token);
  await verify.verify(token);
  assert.equal(calls, 2);
});

test("refreshes only once before rejecting an unknown kid", async () => {
  let calls = 0;
  const verify = verifier({ fetch: async () => (calls += 1, response({ keys: [RSA_JWK] })) });
  await rejectsCode(verify.verify(makeToken({ kid: "missing-key" })), "unknown-key-id");
  assert.equal(calls, 2);
});

test("rejects unsafe, duplicate, unsupported and malformed protected headers", async (t) => {
  const verify = verifier();
  await t.test("alg none", () => rejectsCode(verify.verify("eyJhbGciOiJub25lIiwia2lkIjoieCJ9.e30.AA"), "unsupported-algorithm"));
  await t.test("missing kid", () => rejectsCode(verify.verify(makeToken({ header: { alg: "RS256", typ: "JWT" } })), "invalid-key-id"));
  await t.test("remote key selector", () => rejectsCode(verify.verify(makeToken({ header: { alg: "RS256", kid: RSA_JWK.kid, jku: JWKS_URL } })), "unsafe-header"));
  await t.test("duplicate alg", () => rejectsCode(verify.verify(makeToken({ rawHeader: `{"alg":"RS256","alg":"ES256","kid":"${RSA_JWK.kid}"}` })), "duplicate-json-member"));
  await t.test("padded segment", () => rejectsCode(verify.verify(`${makeToken()}=`), "malformed-signature"));
  await t.test("more than three segments", () => rejectsCode(verify.verify(`${makeToken()}.extra`), "malformed-assertion"));
});

test("rejects duplicate claims before accepting an otherwise valid signature", async () => {
  const rawClaims = `{"iss":"${ISSUER}","sub":"${SUBJECT}","aud":"${AUDIENCE}","iat":${NOW - 30},"exp":${NOW + 270},"exp":${NOW + 500}}`;
  await rejectsCode(verifier().verify(makeToken({ rawClaims })), "duplicate-json-member");
});

test("requires an exact immutable issuer, subject and audience", async (t) => {
  const arrayAudience = await verifier().verify(makeToken({ claims: { aud: [AUDIENCE] } }));
  assert.equal(arrayAudience.audience, AUDIENCE);
  const cases = [
    ["issuer", { iss: `${ISSUER}/other` }],
    ["subject", { sub: "another-operator" }],
    ["empty audience", { aud: [] }],
    ["duplicate audience", { aud: [AUDIENCE, AUDIENCE] }],
    ["extra audience", { aud: [AUDIENCE, "other"] }]
  ];
  for (const [name, claims] of cases) {
    await t.test(name, () => rejectsCode(verifier().verify(makeToken({ claims })), "identity-mismatch"));
  }
});

test("enforces expiration, activation, issue time and bounded lifetime", async (t) => {
  await t.test("expired", () =>
    rejectsCode(verifier().verify(makeToken({ claims: { iat: NOW - 300, exp: NOW - 31 } })), "expired-assertion"));
  await t.test("future nbf", () => rejectsCode(verifier().verify(makeToken({ claims: { nbf: NOW + 31 } })), "assertion-not-active"));
  await t.test("future iat", () => rejectsCode(verifier().verify(makeToken({ claims: { iat: NOW + 31, exp: NOW + 60 } })), "future-issued-at"));
  await t.test("excess lifetime", () => rejectsCode(verifier().verify(makeToken({ claims: { iat: NOW - 500, exp: NOW + 101 } })), "invalid-token-lifetime"));
  await t.test("missing iat", () => {
    const claims = { iss: ISSUER, sub: SUBJECT, aud: AUDIENCE, exp: NOW + 60 };
    return rejectsCode(verifier().verify(makeToken({ rawClaims: JSON.stringify(claims) })), "invalid-issued-at");
  });
});

test("rejects invalid signatures and key/algorithm confusion", async (t) => {
  const otherRsa = generateKeyPairSync("rsa", { modulusLength: 2_048 });
  await t.test("wrong private key", () => rejectsCode(verifier().verify(makeToken({ pair: otherRsa })), "invalid-signature"));
  await t.test("EC key labeled for RSA", () =>
    rejectsCode(verifier({ keys: [{ ...EC_JWK, kid: RSA_JWK.kid, alg: "RS256" }] }).verify(makeToken()), "invalid-verification-key"));
  await t.test("private key material in JWKS", () =>
    rejectsCode(
      verifier({ keys: [{ ...rsa.privateKey.export({ format: "jwk" }), kid: RSA_JWK.kid, alg: "RS256", use: "sig" }] }).verify(makeToken()),
      "invalid-verification-key"
    ));
});

test("rejects redirect, HTTP, media type, oversized and ambiguous JWKS responses", async (t) => {
  await t.test("redirect status", () =>
    rejectsCode(verifier({ fetch: async () => response("", { status: 302 }) }).verify(makeToken()), "jwks-http-rejected"));
  await t.test("non-JSON media type", () =>
    rejectsCode(
      verifier({ fetch: async () => response("{}", { headers: { "content-type": "text/html" } }) }).verify(makeToken()),
      "jwks-content-type-rejected"
    ));
  await t.test("oversized body", () =>
    rejectsCode(verifier({ fetch: async () => response("x".repeat(65 * 1024)) }).verify(makeToken()), "jwks-too-large"));
  await t.test("duplicate kid", () =>
    rejectsCode(verifier({ keys: [RSA_JWK, { ...RSA_JWK }] }).verify(makeToken()), "duplicate-jwks-key-id"));
  await t.test("too many keys", () => {
    const keys = Array.from({ length: 33 }, (_, index) => ({ ...RSA_JWK, kid: `key-${index}` }));
    return rejectsCode(verifier({ keys }).verify(makeToken()), "invalid-jwks");
  });
});

test("bounds the complete JWKS request duration", async (t) => {
  await t.test("stalled fetch", async () => {
    const verify = verifier({
      config: { jwksTimeoutMs: 10 },
      fetch: async () => new Promise(() => {})
    });
    await rejectsCode(verify.verify(makeToken()), "jwks-fetch-failed");
  });
  await t.test("stalled response body", async () => {
    const verify = verifier({
      config: { jwksTimeoutMs: 10 },
      fetch: async () =>
        new Response(new ReadableStream({ start() {} }), {
          status: 200,
          headers: { "content-type": "application/json" }
        })
    });
    await rejectsCode(verify.verify(makeToken()), "jwks-fetch-failed");
  });
});

test("production transport rejects insecure and private JWKS URLs before fetch", async (t) => {
  const base = { issuer: ISSUER, audience: AUDIENCE, operatorSubject: SUBJECT };
  await t.test("plain HTTP", () => {
    assert.throws(() => createOidcVerifier({ ...base, jwksUrl: "http://identity.example/jwks" }), /HTTPS/u);
  });
  await t.test("loopback literal", () => {
    assert.throws(() => createOidcVerifier({ ...base, jwksUrl: "https://127.0.0.1/jwks" }), /private/u);
  });
  await t.test("local name", () => {
    assert.throws(() => createOidcVerifier({ ...base, jwksUrl: "https://issuer.local/jwks" }), /local/u);
  });
  await t.test("name resolving to a private address", async () => {
    const verify = createOidcVerifier(
      {
        ...base,
        jwksUrl: JWKS_URL,
        maxTokenLifetimeSeconds: 600,
        jwksTimeoutMs: 100
      },
      { clock: () => NOW_MS, lookup: async () => [{ address: "10.0.0.7", family: 4 }] }
    );
    await rejectsCode(verify.verify(makeToken()), "private-jwks-destination");
  });
});

test("an explicitly injected test fetch may serve a non-HTTPS fixture", async () => {
  const verify = createOidcVerifier(
    {
      issuer: ISSUER,
      audience: AUDIENCE,
      operatorSubject: SUBJECT,
      jwksUrl: "http://127.0.0.1/test-jwks",
      maxTokenLifetimeSeconds: 600
    },
    { fetch: async () => response({ keys: [RSA_JWK] }), clock: () => NOW_MS }
  );
  assert.equal((await verify.verify(makeToken())).subject, SUBJECT);
});

test("rejects unknown configuration and dependency option members", () => {
  const config = { issuer: ISSUER, audience: AUDIENCE, operatorSubject: SUBJECT, jwksUrl: JWKS_URL };
  assert.throws(() => createOidcVerifier({ ...config, clockSkewSecond: 300 }), /unknown member/u);
  assert.throws(
    () => createOidcVerifier(config, { fetch: async () => response({ keys: [RSA_JWK] }), fallbackIssuer: ISSUER }),
    /unknown member/u
  );
});
