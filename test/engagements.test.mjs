import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  approveEngagement,
  attachAuthorization,
  attachPlan,
  checkEngagement,
  createEngagement,
  getEngagement,
  recordTechnicalReview,
  revokeEngagement,
  targetMatches
} from "../src/lib/engagements.mjs";
import { runtimePaths } from "../src/lib/paths.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-engagement-"));
  const paths = runtimePaths({ home: path.join(root, "home"), repo });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, paths };
}

test("target matching handles exact, wildcard, URL, IPv4, and IPv6 CIDR scopes", () => {
  assert.equal(targetMatches("example.test", "https://example.test/login"), true);
  assert.equal(targetMatches("*.example.test", "api.example.test"), true);
  assert.equal(targetMatches("*.example.test", "example.test"), false);
  assert.equal(targetMatches("https://app.example.test/api", "https://app.example.test/api/users"), true);
  assert.equal(targetMatches("https://app.example.test/api", "https://app.example.test/apix"), false);
  assert.equal(targetMatches("https://app.example.test/api?tenant=alpha", "https://app.example.test/api/users?tenant=alpha"), true);
  assert.equal(targetMatches("https://app.example.test/api?tenant=alpha", "https://app.example.test/api/users?tenant=beta"), false);
  assert.equal(targetMatches("https://app.example.test/api?tenant=alpha", "https://app.example.test/api/users?tenant=alpha&mode=read"), false);
  assert.equal(targetMatches("https://app.example.test/api?a=1&a=2", "https://app.example.test/api?a=2&a=1"), false);
  assert.equal(targetMatches("https://app.example.test/api?value=a", "https://app.example.test/api?value=%61"), false);
  assert.equal(targetMatches("https://app.example.test/api?", "https://app.example.test/api?"), true);
  assert.equal(targetMatches("https://app.example.test/api?", "https://app.example.test/api"), false);
  assert.equal(targetMatches("https://app.example.test/api?", "https://app.example.test/api?tenant=alpha"), false);
  assert.equal(targetMatches("https://app.example.test/api?tenant=alpha", "https://app.example.test/api?tenant=alpha#admin"), false);
  assert.equal(targetMatches("example.test", "https://example.test/#"), false);
  assert.equal(targetMatches("https://app.example.test/api#admin", "https://app.example.test/api"), false);
  assert.equal(targetMatches("https://app.example.test/api#", "https://app.example.test/api"), false);
  assert.equal(targetMatches("192.0.2.0/28", "192.0.2.9"), true);
  assert.equal(targetMatches("192.0.2.0/28", "192.0.2.20"), false);
  assert.equal(targetMatches("2001:db8::/48", "2001:db8:0:1::7"), true);
  assert.equal(targetMatches("2001:db8::/48", "2001:db9::1"), false);
});

test("engagement creation requires and normalizes an explicit tool scope", (t) => {
  const { paths } = fixture(t);
  assert.throws(
    () => createEngagement({ id: "missing-tools", targets: ["app.example.test"], actions: ["scan"] }, { paths }),
    /at least one permitted tool is required/
  );
  assert.throws(
    () => createEngagement(
      { id: "invalid-tools", targets: ["app.example.test"], actions: ["scan"], tools: ["bad_tool"] },
      { paths }
    ),
    /tool ids must use/
  );

  const engagement = createEngagement(
    {
      id: "tool-scope",
      targets: ["app.example.test"],
      actions: ["scan"],
      tools: ["NMAP", "nmap", "ffuf"]
    },
    { paths }
  );
  assert.deepEqual(engagement.scope.permittedTools, ["nmap", "ffuf"]);
});

test("engagements retain every mandatory workflow stop on creation and load", (t) => {
  const { paths } = fixture(t);
  const workflow = JSON.parse(
    fs.readFileSync(path.join(paths.repo, "config", "workflows", "pentest-e2e.json"), "utf8")
  );
  const mandatory = [...new Set([
    ...workflow.defaultStopConditions,
    ...workflow.phases.flatMap((phase) => phase.stopPolicy?.additional || [])
  ])].sort();
  assert.equal(mandatory.length, 13);
  const engagement = createEngagement(
    {
      id: "mandatory-stops",
      targets: ["app.example.test"],
      actions: ["scan"],
      tools: ["nmap"],
      stopOn: ["operator-stop"]
    },
    { paths }
  );
  assert.deepEqual(engagement.stopOn, mandatory);

  const file = path.join(paths.engagements, "mandatory-stops.json");
  const weakened = JSON.parse(fs.readFileSync(file, "utf8"));
  weakened.stopOn = ["operator-stop"];
  fs.writeFileSync(file, `${JSON.stringify(weakened, null, 2)}\n`, { mode: 0o600 });
  assert.throws(
    () => getEngagement("mandatory-stops", { paths }),
    /engagement is missing mandatory stop conditions/
  );
});

test("URL query constraints apply to engagement inclusions and exclusions", (t) => {
  const { root, paths } = fixture(t);
  const plan = path.join(root, "plan.md");
  fs.writeFileSync(plan, "# Plan\nQuery-bounded scan.\n");

  createEngagement(
    {
      id: "query-scope",
      targets: ["https://app.example.test/api?tenant=alpha"],
      actions: ["scan"],
      tools: ["nmap"]
    },
    { paths }
  );
  const includedPlan = attachPlan("query-scope", plan, { paths });
  recordTechnicalReview(
    "query-scope",
    { run: "no-mistakes/query-scope", headSha: "e".repeat(40), status: "passed" },
    { paths }
  );
  approveEngagement(
    "query-scope",
    { sha256: includedPlan.plan.sha256, confirm: "APPROVE query-scope" },
    { paths }
  );

  assert.equal(
    checkEngagement("query-scope", { target: "https://app.example.test/api/users?tenant=alpha", action: "scan" }, { paths }).allowed,
    true
  );
  const mismatchedInclude = checkEngagement(
    "query-scope",
    { target: "https://app.example.test/api/users?tenant=beta", action: "scan" },
    { paths }
  );
  assert.equal(mismatchedInclude.allowed, false);
  assert.ok(mismatchedInclude.reasons.some((reason) => reason.startsWith("target is outside scope:")));

  createEngagement(
    {
      id: "query-exclusion",
      targets: ["https://app.example.test/api"],
      exclude: ["https://app.example.test/api/admin?tenant=alpha"],
      actions: ["scan"],
      tools: ["nmap"]
    },
    { paths }
  );
  const excludedPlan = attachPlan("query-exclusion", plan, { paths });
  recordTechnicalReview(
    "query-exclusion",
    { run: "no-mistakes/query-exclusion", headSha: "f".repeat(40), status: "passed" },
    { paths }
  );
  approveEngagement(
    "query-exclusion",
    { sha256: excludedPlan.plan.sha256, confirm: "APPROVE query-exclusion" },
    { paths }
  );

  const exactExclusion = checkEngagement(
    "query-exclusion",
    { target: "https://app.example.test/api/admin/users?tenant=alpha", action: "scan" },
    { paths }
  );
  assert.equal(exactExclusion.allowed, false);
  assert.ok(exactExclusion.reasons.some((reason) => reason.startsWith("target is explicitly excluded:")));
  assert.equal(
    checkEngagement("query-exclusion", { target: "https://app.example.test/api/admin/users?tenant=beta", action: "scan" }, { paths }).allowed,
    true
  );
});

test("engagement creation rejects URL selectors with fragments", (t) => {
  const { paths } = fixture(t);
  assert.throws(
    () => createEngagement(
      { id: "fragment-scope", targets: ["https://app.example.test/api#admin"], actions: ["scan"], tools: ["nmap"] },
      { paths }
    ),
    /must not contain fragments/
  );
  assert.throws(
    () => createEngagement(
      { id: "empty-fragment-scope", targets: ["https://app.example.test/api#"], actions: ["scan"], tools: ["nmap"] },
      { paths }
    ),
    /must not contain fragments/
  );
});

test("external authorization evidence cannot be injected or reused across engagements", (t) => {
  const { root, paths } = fixture(t);
  const plan = path.join(root, "plan.md");
  const authorization = path.join(root, "authorization.txt");
  fs.writeFileSync(plan, "# Plan\nOne bounded request.\n");
  fs.writeFileSync(authorization, "Client authorization fixture.\n");

  fs.mkdirSync(paths.authorizations, { recursive: true });
  fs.writeFileSync(path.join(paths.authorizations, "preexisting.evidence"), "Unattached evidence.\n");
  assert.throws(
    () => createEngagement(
      {
        id: "preexisting",
        basis: "client-written-authorization",
        evidenceRef: "private://authorizations/preexisting.evidence",
        targets: ["app.example.test"],
        actions: ["scan"],
        tools: ["nmap"]
      },
      { paths }
    ),
    /must be added with attachAuthorization/
  );
  assert.equal(fs.existsSync(path.join(paths.engagements, "preexisting.json")), false);

  createEngagement(
    { id: "first-client", basis: "client-written-authorization", targets: ["first.example.test"], actions: ["scan"], tools: ["nmap"] },
    { paths }
  );
  createEngagement(
    { id: "second-client", basis: "client-written-authorization", targets: ["second.example.test"], actions: ["scan"], tools: ["nmap"] },
    { paths }
  );
  attachAuthorization("first-client", authorization, { paths });
  const planned = attachPlan("second-client", plan, { paths });
  recordTechnicalReview(
    "second-client",
    { run: "no-mistakes/second-client", headSha: "9".repeat(40), status: "passed" },
    { paths }
  );

  const secondFile = path.join(paths.engagements, "second-client.json");
  const second = JSON.parse(fs.readFileSync(secondFile, "utf8"));
  second.authorization.evidenceRef = "private://authorizations/first-client.evidence";
  fs.writeFileSync(secondFile, `${JSON.stringify(second, null, 2)}\n`);
  assert.throws(
    () => approveEngagement(
      "second-client",
      { sha256: planned.plan.sha256, confirm: "APPROVE second-client" },
      { paths }
    ),
    /attached specifically to engagement second-client/
  );

  attachAuthorization("second-client", authorization, { paths });
  recordTechnicalReview(
    "second-client",
    { run: "no-mistakes/second-client-attached", headSha: "8".repeat(40), status: "passed" },
    { paths }
  );
  approveEngagement(
    "second-client",
    { sha256: planned.plan.sha256, confirm: "APPROVE second-client" },
    { paths }
  );
  const approved = JSON.parse(fs.readFileSync(secondFile, "utf8"));
  approved.authorization.evidenceRef = "private://authorizations/first-client.evidence";
  fs.writeFileSync(secondFile, `${JSON.stringify(approved, null, 2)}\n`);
  const swapped = checkEngagement(
    "second-client",
    { target: "second.example.test", action: "scan" },
    { paths }
  );
  assert.equal(swapped.allowed, false);
  assert.ok(swapped.reasons.includes("authorization evidence is not attached specifically to this engagement"));
});

test("client authorization is copied privately, digest-bound, and independently invalidating", (t) => {
  const { root, paths } = fixture(t);
  const plan = path.join(root, "plan.md");
  const authorization = path.join(root, "authorization.txt");
  fs.writeFileSync(plan, "# Plan\nOne bounded request.\n");
  fs.writeFileSync(authorization, "Client authorization fixture.\n");
  createEngagement(
    { id: "client-demo", basis: "client-written-authorization", targets: ["app.example.test"], actions: ["scan"], tools: ["nmap"] },
    { paths }
  );
  const planned = attachPlan("client-demo", plan, { paths });
  recordTechnicalReview(
    "client-demo",
    { run: "no-mistakes/client", headSha: "b".repeat(40), status: "passed" },
    { paths }
  );
  assert.throws(
    () => approveEngagement("client-demo", { sha256: planned.plan.sha256, confirm: "APPROVE client-demo" }, { paths }),
    /requires private authorization evidence/
  );
  attachAuthorization("client-demo", authorization, { paths });
  recordTechnicalReview(
    "client-demo",
    { run: "no-mistakes/client-2", headSha: "c".repeat(40), status: "passed" },
    { paths }
  );
  approveEngagement("client-demo", { sha256: planned.plan.sha256, confirm: "APPROVE client-demo" }, { paths });
  assert.equal(checkEngagement("client-demo", { target: "app.example.test", action: "scan" }, { paths }).allowed, true);
  fs.appendFileSync(path.join(paths.authorizations, "client-demo.evidence"), "Changed.\n");
  const changed = checkEngagement("client-demo", { target: "app.example.test", action: "scan" }, { paths });
  assert.equal(changed.allowed, false);
  assert.ok(changed.reasons.includes("authorization evidence changed"));
  assert.equal(Object.hasOwn(changed, "executionBinding"), false);
});

test("an exact reviewed plan is required and later changes invalidate approval", (t) => {
  const { root, paths } = fixture(t);
  const plan = path.join(root, "plan.md");
  fs.writeFileSync(plan, "# Plan\nBounded scan.\n");
  createEngagement({ id: "demo", targets: ["*.example.test"], actions: ["scan"], tools: ["nmap"] }, { paths });
  const planned = attachPlan("demo", plan, { paths });
  recordTechnicalReview(
    "demo",
    { run: "no-mistakes/run-1", headSha: "a".repeat(40), status: "passed" },
    { paths }
  );
  approveEngagement(
    "demo",
    { sha256: planned.plan.sha256, confirm: "APPROVE demo" },
    { paths }
  );
  const preflight = checkEngagement("demo", { target: "api.example.test", action: "scan" }, { paths });
  assert.equal(preflight.allowed, true);
  assert.equal(preflight.preflightOnly, true);
  assert.deepEqual(preflight.attestation, {
    operatorProvenance: "local-unverified",
    noMistakesReview: "local-unverified"
  });
  const receiptFile = path.join(paths.authorizations, "demo.receipt.json");
  const receiptBytes = fs.readFileSync(receiptFile);
  const receipt = JSON.parse(receiptBytes.toString("utf8"));
  assert.deepEqual(preflight.executionBinding, {
    engagementId: "demo",
    planSha256: planned.plan.sha256,
    envelopeSha256: receipt.envelopeSha256,
    receiptSha256: crypto.createHash("sha256").update(receiptBytes).digest("hex"),
    authorizationValidUntil: preflight.engagement.authorization.validUntil,
    target: { type: "domain", value: "api.example.test" },
    action: "scan",
    environment: "host",
    allowedDestinations: ["gate-home"],
    permittedTools: ["nmap"]
  });
  assert.equal(checkEngagement("demo", { target: "outside.test", action: "scan" }, { paths }).allowed, false);
  const engagementFile = path.join(paths.engagements, "demo.json");
  const engagement = JSON.parse(fs.readFileSync(engagementFile, "utf8"));
  receipt.confirmation = "APPROVE another-engagement";
  fs.writeFileSync(receiptFile, `${JSON.stringify(receipt, null, 2)}\n`);
  const forged = checkEngagement("demo", { target: "api.example.test", action: "scan" }, { paths });
  assert.equal(forged.allowed, false);
  assert.ok(forged.reasons.includes("operator authorization receipt confirmation changed"));
  receipt.confirmation = "APPROVE demo";
  fs.writeFileSync(receiptFile, `${JSON.stringify(receipt, null, 2)}\n`);

  engagement.scope.include.push({ type: "domain", value: "added.example.test" });
  fs.writeFileSync(engagementFile, `${JSON.stringify(engagement, null, 2)}\n`);
  const expanded = checkEngagement("demo", { target: "added.example.test", action: "scan" }, { paths });
  assert.equal(expanded.allowed, false);
  assert.ok(expanded.reasons.includes("approved engagement envelope changed"));
  engagement.scope.include.pop();
  engagement.scope.permittedTools.push("ffuf");
  fs.writeFileSync(engagementFile, `${JSON.stringify(engagement, null, 2)}\n`);
  const broadenedTools = checkEngagement("demo", { target: "api.example.test", action: "scan" }, { paths });
  assert.equal(broadenedTools.allowed, false);
  assert.ok(broadenedTools.reasons.includes("approved engagement envelope changed"));
  assert.equal(Object.hasOwn(broadenedTools, "executionBinding"), false);
  engagement.scope.permittedTools.pop();
  fs.writeFileSync(engagementFile, `${JSON.stringify(engagement, null, 2)}\n`);
  fs.appendFileSync(path.join(paths.plans, "demo.md"), "Changed.\n");
  const changed = checkEngagement("demo", { target: "api.example.test", action: "scan" }, { paths });
  assert.equal(changed.allowed, false);
  assert.ok(changed.reasons.includes("approved plan digest changed"));
});

test("engagement revocation requires exact confirmation and appends a durable event", (t) => {
  const { root, paths } = fixture(t);
  const plan = path.join(root, "plan.md");
  fs.writeFileSync(plan, "# Plan\nBounded scan.\n");
  createEngagement(
    { id: "revoke-demo", targets: ["app.example.test"], actions: ["scan"], tools: ["nmap"] },
    { paths }
  );
  const planned = attachPlan("revoke-demo", plan, { paths });
  recordTechnicalReview(
    "revoke-demo",
    { run: "no-mistakes/revoke", headSha: "e".repeat(40), status: "passed" },
    { paths }
  );
  approveEngagement(
    "revoke-demo",
    { sha256: planned.plan.sha256, confirm: "APPROVE revoke-demo" },
    { paths }
  );

  const before = fs.readFileSync(path.join(paths.engagements, "revoke-demo.json"), "utf8");
  assert.throws(
    () => revokeEngagement("revoke-demo", { confirm: "REVOKE another" }, { paths }),
    /must be exactly: REVOKE revoke-demo/
  );
  assert.equal(fs.readFileSync(path.join(paths.engagements, "revoke-demo.json"), "utf8"), before);

  const revoked = revokeEngagement("revoke-demo", { confirm: "REVOKE revoke-demo" }, { paths });
  assert.equal(revoked.metadata.status, "revoked");
  assert.equal(revoked.review.operatorReceipt.status, "revoked");
  const check = checkEngagement("revoke-demo", { target: "app.example.test", action: "scan" }, { paths });
  assert.equal(check.allowed, false);
  assert.ok(check.reasons.includes("engagement is not approved"));
  assert.ok(check.reasons.includes("operator receipt is not approved"));
  assert.equal(Object.hasOwn(check, "executionBinding"), false);

  const events = fs.readFileSync(paths.events, "utf8").trim().split("\n").map((line) => JSON.parse(line));
  const event = events.at(-1);
  assert.equal(event.kind, "engagement.revoked");
  assert.equal(event.effect.engagementId, "revoke-demo");
  assert.equal(event.effect.planDigest, planned.plan.sha256);
});

test("declared execution cannot outlive the authorization window", (t) => {
  const { root, paths } = fixture(t);
  const plan = path.join(root, "plan.md");
  fs.writeFileSync(plan, "# Plan\nTime-bounded scan.\n");
  createEngagement(
    {
      id: "short-window",
      targets: ["app.example.test"],
      actions: ["scan"],
      tools: ["nmap"],
      validUntil: new Date(Date.now() + 30_000).toISOString(),
      maxMinutes: 1
    },
    { paths }
  );
  const planned = attachPlan("short-window", plan, { paths });
  recordTechnicalReview(
    "short-window",
    { run: "no-mistakes/short-window", headSha: "d".repeat(40), status: "passed" },
    { paths }
  );
  approveEngagement(
    "short-window",
    { sha256: planned.plan.sha256, confirm: "APPROVE short-window" },
    { paths }
  );
  const check = checkEngagement(
    "short-window",
    { target: "app.example.test", action: "scan", maxMinutes: 1 },
    { paths }
  );
  assert.equal(check.allowed, false);
  assert.ok(check.reasons.includes("declared duration extends beyond the authorization window"));
});

test("plan and authorization attachments reject symlink sources", (t) => {
  const { root, paths } = fixture(t);
  const source = path.join(root, "source.txt");
  const link = path.join(root, "source-link.txt");
  fs.writeFileSync(source, "private evidence\n");
  fs.symlinkSync(source, link);
  createEngagement(
    { id: "regular-files", basis: "client-written-authorization", targets: ["app.example.test"], actions: ["scan"], tools: ["nmap"] },
    { paths }
  );
  assert.throws(() => attachPlan("regular-files", link, { paths }), /regular non-symlink file/);
  assert.throws(() => attachAuthorization("regular-files", link, { paths }), /regular non-symlink file/);
});

test("plan attachment rejects a source replaced with a symlink between inspection and open", {
  skip: process.platform === "win32" && "creating symlinks can require elevated Windows privileges"
}, (t) => {
  const { root, paths } = fixture(t);
  const source = path.join(root, "plan.md");
  const original = path.join(root, "plan-original.md");
  const outside = path.join(root, "outside.md");
  fs.writeFileSync(source, "reviewed plan\n");
  fs.writeFileSync(outside, "substituted bytes\n");
  createEngagement({ id: "source-race", targets: ["app.example.test"], actions: ["scan"], tools: ["nmap"] }, { paths });

  const openSync = fs.openSync;
  let substituted = false;
  t.mock.method(fs, "openSync", function (file, ...args) {
    if (!substituted && path.resolve(String(file)) === source) {
      substituted = true;
      fs.renameSync(source, original);
      fs.symlinkSync(outside, source);
    }
    return openSync.call(this, file, ...args);
  });

  assert.throws(() => attachPlan("source-race", source, { paths }), /ELOOP|symbolic link|changed/);
  assert.equal(substituted, true);
  assert.equal(fs.existsSync(path.join(paths.plans, "source-race.md")), false);
});

test("engagement loads reject a symlinked private record", {
  skip: process.platform === "win32" && "creating symlinks can require elevated Windows privileges"
}, (t) => {
  const { root, paths } = fixture(t);
  createEngagement({ id: "linked-record", targets: ["app.example.test"], actions: ["scan"], tools: ["nmap"] }, { paths });
  const record = path.join(paths.engagements, "linked-record.json");
  const outside = path.join(root, "outside-engagement.json");
  fs.renameSync(record, outside);
  fs.symlinkSync(outside, record);

  assert.throws(() => getEngagement("linked-record", { paths }), /must not be a symbolic link/);
  assert.match(fs.readFileSync(outside, "utf8"), /linked-record/);
});
