import assert from "node:assert/strict";
import test from "node:test";

import { assertNoLikelySecret, assertNoUnsafeText, escapeUnsafeText, oneLine } from "../src/lib/text.mjs";

test("credential scanning rejects sensitive URL parameters and user information", () => {
  const token = "aB9_Zx7Qp2Lm8Nv4Rk6Ts1Wd3Hy5";
  assert.throws(
    () => assertNoLikelySecret(`https://example.invalid/callback?session_token=${token}`, "program URL"),
    /credential/u
  );
  assert.throws(
    () => assertNoLikelySecret("https://operator:private-value@example.invalid/", "program URL"),
    /URL user information/u
  );
  assert.throws(
    () => assertNoLikelySecret(token, "module answer"),
    /opaque credential/u
  );
  assert.throws(
    () => assertNoLikelySecret("9f4c2d8b7a6e1c3f5d0b4a8e2c7f1d6b", "module answer"),
    /opaque credential/u
  );
  assert.throws(
    () => assertNoLikelySecret("https://storage.invalid/blob?sv=2024-01-01&sig=AbCdEf12%2FGhIjKl34%2BMnOpQr56%3D", "evidence URL"),
    /credential-bearing URL parameter/u
  );
  assert.throws(
    () => assertNoLikelySecret("https://example.invalid/program?key=short-private-value", "program URL"),
    /credential-bearing URL parameter/u
  );
  assert.throws(
    () => assertNoLikelySecret("https://example.invalid/program#token=550e8400-e29b-41d4-a716-446655440000", "program URL"),
    /credential-bearing URL parameter/u
  );
  assert.throws(
    () => assertNoLikelySecret("https://example.invalid/session/nL5/7CWl1jUPQ8u+Q5nD2uA9kM4gXxR3VfE0bZcYpS8=", "program URL"),
    /opaque credential in a URL/u
  );
  assert.throws(
    () => assertNoLikelySecret("https://example.invalid/program#nL5/7CWl1jUPQ8u+Q5nD2uA9kM4gXxR3VfE0bZcYpS8=", "program URL"),
    /opaque credential in a URL/u
  );
  assert.throws(
    () => assertNoLikelySecret("Use nL5/7CWl1jUPQ8u+Q5nD2uA9kM4gXxR3VfE0bZcYpS8= for the session.", "module answer"),
    /opaque credential/u
  );
  assert.throws(
    () => assertNoLikelySecret("550e8400-e29b-41d4-a716-446655440000", "technique.parameters.sessionToken"),
    /opaque credential/u
  );
  for (const value of [
    "aB9Zx7Qp2Lm8Nv4-Rk6Ts1Wd3Hy5Ua7",
    "aB9Zx7Qp2Lm8Nv4.Rk6Ts1Wd3Hy5Ua7",
    "/nL57CWl1jUPQ8u+Q5nD2uA9kM4gXxR3VfE0bZcYpS8="
  ]) {
    assert.throws(() => assertNoLikelySecret(value, "module answer"), /opaque credential/u, value);
  }
  const opaque = "nL57CWl1jUPQ8uQ5nD2uA9kM4gXxR3VfE0bZcYpS8";
  for (const value of [
    `https://example.invalid/callback?${opaque}&view=details`,
    `https://example.invalid/callback?${opaque}=ignored&view=details`,
    `https://example.invalid/program#${opaque}&view=details`,
    `https://example.invalid/program#route/${opaque}?view=details`,
    `https://example.invalid/program#${opaque}=ignored&view=details`
  ]) {
    assert.throws(() => assertNoLikelySecret(value, "program URL"), /credential|opaque/u, value);
  }
  const encoded = [..."nL5/7CWl1jUPQ8u+Q5nD2uA9kM4gXxR3VfE0bZcYpS8="].map((character) =>
    `%${character.codePointAt(0).toString(16).padStart(2, "0")}`
  ).join("");
  const doubleEncoded = encodeURIComponent(encoded);
  const separatorDense = "aB9+/Zx7+/Qp2+/Lm8+/Nv4+/Rk6+/Ts1+/Wd3+/Hy5=";
  for (const value of [
    `https://example.invalid/session/${encoded}`,
    `https://example.invalid/program#${encoded}`,
    `https://example.invalid/program#route/${encoded}?view=details`,
    `https://example.invalid/callback?credential_name=${doubleEncoded}`,
    `https://example.invalid/callback?${doubleEncoded}=ignored`,
    `https://example.invalid/session/${encodeURIComponent(separatorDense)}`,
    `https://example.invalid/session/${encodeURIComponent(encodeURIComponent(separatorDense))}`
  ]) {
    assert.throws(() => assertNoLikelySecret(value, "program URL"), /credential|opaque/u, value);
  }
});

test("credential scanning permits ordinary URLs, prose, and labeled digests", () => {
  assert.doesNotThrow(() => assertNoLikelySecret("https://example.invalid/search?page=2&lang=en", "program URL"));
  assert.doesNotThrow(() => assertNoLikelySecret("https://hackerone.com/programs/acme-v2", "program URL"));
  assert.doesNotThrow(() => assertNoLikelySecret("https://bugcrowd.com/engagements/company2026", "program URL"));
  assert.doesNotThrow(() => assertNoLikelySecret(
    "The assessment should map authorization boundaries and retain minimal evidence.",
    "objective"
  ));
  assert.doesNotThrow(() => assertNoLikelySecret("a".repeat(64), "source.contentSha256"));
  for (const value of [
    "gate.dev/program-profile/v1",
    "https://gate.local/schemas/bug-bounty-program-profile.schema.json",
    "v2.46.0",
    "long-research-project-2026-alpha",
    "active-surface-validation-v2",
    "cve-2026-12345-example-case",
    "researcher_account_2026_primary",
    "/tmp/gate-bounty-ABC123/source-text-executed",
    "CVE-2026-12345-Authorization-Bypass",
    "OWASP-API-Security-Top-10-2023",
    "primaryWebApplication2026Version2",
    "CustomerIdentityProvider-v2-2026",
    "https://example.invalid/session/primaryWebApplication2026Version2",
    "https://example.invalid/programs/CVE-2026-12345-Authorization-Bypass",
    "https://example.invalid/engagements/CustomerIdentityProvider-v2-2026",
    "https://example.invalid/tmp/gate-bounty-ABC123/source-text-executed",
    "https://example.invalid/docs/OWASP-API-Security-Top-10-2023",
    "192.0.2.0/24"
  ]) {
    assert.doesNotThrow(() => assertNoLikelySecret(value, "profile value"), value);
  }
});

test("URL credential scanning permits encoded percent literals without skipping credentials", () => {
  for (const component of ["100%25", "100%2525", "%25E0%25A4"]) {
    for (const suffix of [
      `/docs/${component}`,
      `/search?q=${component}`,
      `/search?${component}=public`,
      `/docs#${component}`,
      `/docs#q=${component}`,
      `/docs#${component}=public`
    ]) {
      assert.doesNotThrow(() => assertNoLikelySecret(`https://example.invalid${suffix}`), suffix);
      assert.throws(
        () => assertNoLikelySecret(`https://example.invalid${suffix} https://example.invalid/?token=private`),
        /credential/u
      );
    }
  }
  const token = "aB9_Zx7Qp2Lm8Nv4Rk6Ts1Wd3Hy5";
  for (const suffix of [
    `/docs/${token}%25`,
    `/search?q=${token}%25`,
    `/search?${token}%25=public`,
    `/docs#${token}%25`,
    `/docs#q=${token}%25`,
    `/docs#${token}%25=public`,
    "/search?%2574oken=private&percent=100%25"
  ]) {
    assert.throws(() => assertNoLikelySecret(`https://example.invalid${suffix}`), /credential/u, suffix);
  }
});

test("text boundaries reject terminal controls and invisible direction formatting", () => {
  for (const value of [
    "copy\u001b]52;c;payload\u0007",
    "line one\rline two",
    "line one\u2028line two",
    "safe\u202Etxt.exe",
    "safe\u2066hidden\u2069",
    "safe\u200Bhidden",
    "safe\u{E0001}hidden"
  ]) {
    assert.throws(() => assertNoUnsafeText(value, "profile value"), /terminal control|direction-formatting/u);
    assert.throws(() => oneLine(value, { name: "profile value" }), /terminal control|direction-formatting/u);
  }
  assert.doesNotThrow(() => assertNoUnsafeText("ordinary multiline\ncontent\twith spacing", "profile value"));
  assert.doesNotThrow(() => assertNoUnsafeText("Persian می‌رود and emoji 👩‍💻 remain visible", "profile value"));
  const escaped = escapeUnsafeText("copy\u001b]52;c;payload\u0007 and safe\ntext\u202E");
  assert.equal(escaped, "copy\\u001B]52;c;payload\\u0007 and safe\ntext\\u202E");
  assert.doesNotMatch(escaped, /[\u0007\u001B\u202E]/u);
});
