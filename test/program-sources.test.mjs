import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { runtimePaths } from "../src/lib/paths.mjs";
import {
  diffProgramSourceSnapshots,
  fetchPublicProgramSource,
  importProgramSource,
  isPublicProgramSourceAddress,
  programProfileSourceFromSnapshot,
  programSourcePaths,
  readCurrentProgramSource,
  resolvePublicProgramSourceUrl
} from "../src/lib/program-sources.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-program-source-"));
  const paths = runtimePaths({ home: path.join(root, "home"), repo });
  const saved = path.join(root, "saved-source.html");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, paths, saved };
}

function source(overrides = {}) {
  return {
    id: "public-rules",
    type: "program-rules",
    title: "Public challenge rules",
    reference: "https://challenge.example.org/rules",
    ...overrides
  };
}

function projection(overrides = {}) {
  return {
    scope: [{
      id: "challenge-web",
      selector: { type: "domain", value: "challenge.example.org" },
      disposition: "allowed",
      claimState: "observed",
      conditions: ["Use the intentionally vulnerable challenge environment."],
      locator: { kind: "section", value: "Scope" }
    }],
    rules: [{
      id: "automation-rule",
      category: "automation",
      disposition: "conditional",
      claimState: "observed",
      summary: "Automation is permitted within the published challenge limits.",
      conditions: ["Keep activity within the challenge host."],
      locator: { kind: "section", value: "Rules" }
    }],
    ...overrides
  };
}

test("local source import retains exact private bytes and emits only a bounded projection", async (t) => {
  const { paths, saved } = fixture(t);
  const body = Buffer.from("<html><body>intentionally vulnerable challenge rules</body></html>\n", "utf8");
  fs.writeFileSync(saved, body, { mode: 0o600 });

  const imported = await importProgramSource({
    paths,
    programId: "training-ctf",
    source: source(),
    acquisition: { kind: "local-file", path: saved, mediaType: "text/html" },
    projection: projection(),
    now: "2026-10-19T20:00:00.000Z"
  });

  assert.equal(imported.snapshot.metadata.revision, 1);
  assert.equal(imported.snapshot.metadata.bodyBytes, body.length);
  assert.match(imported.snapshot.metadata.contentSha256, /^[a-f0-9]{64}$/u);
  assert.match(imported.snapshot.metadata.projectionSha256, /^[a-f0-9]{64}$/u);
  assert.match(imported.snapshot.metadata.snapshotSha256, /^[a-f0-9]{64}$/u);
  assert.equal(imported.snapshot.acquisition.method, "local-file");
  assert.equal(imported.snapshot.acquisition.requestedUrl, null);
  assert.equal(imported.snapshot.acquisition.finalUrl, null);
  assert.equal(imported.diff.firstRevision, true);
  assert.equal(imported.diff.scope.added, 1);
  assert.equal(imported.diff.rules.added, 1);
  assert.deepEqual(imported.profileSource, programProfileSourceFromSnapshot(imported.snapshot));
  assert.equal(imported.profileSource.contentSha256, imported.snapshot.metadata.contentSha256);

  const locations = programSourcePaths(paths, "training-ctf", "public-rules");
  const bodyFile = path.join(locations.bodies, `${imported.snapshot.metadata.contentSha256}.bin`);
  assert.deepEqual(fs.readFileSync(bodyFile), body);
  if (process.platform !== "win32") {
    assert.equal(fs.statSync(bodyFile).mode & 0o777, 0o600);
    assert.equal(fs.statSync(locations.source).mode & 0o777, 0o700);
  }
  const retainedControlText = [
    fs.readFileSync(locations.current, "utf8"),
    ...fs.readdirSync(locations.revisions).map((name) => fs.readFileSync(path.join(locations.revisions, name), "utf8"))
  ].join("\n");
  assert.equal(retainedControlText.includes(saved), false);
  assert.equal(retainedControlText.includes(body.toString("utf8")), false);
  assert.deepEqual(readCurrentProgramSource("training-ctf", "public-rules", { paths }), imported.snapshot);
});

test("successive snapshots diff scope and rules without returning raw source bodies", async (t) => {
  const { paths, saved } = fixture(t);
  fs.writeFileSync(saved, "first public revision\n", { mode: 0o600 });
  const first = await importProgramSource({
    paths,
    programId: "training-ctf",
    source: source(),
    acquisition: { kind: "local-file", path: saved, mediaType: "text/plain" },
    projection: projection(),
    now: "2026-10-19T20:00:00.000Z"
  });

  fs.writeFileSync(saved, "second public revision\n", { mode: 0o600 });
  const nextProjection = projection({
    scope: [
      { ...projection().scope[0], conditions: ["Use only the challenge environment."] },
      {
        id: "challenge-api",
        selector: { type: "domain", value: "api.challenge.example.org" },
        disposition: "allowed",
        claimState: "observed",
        conditions: [],
        locator: { kind: "section", value: "API scope" }
      }
    ],
    rules: []
  });
  const second = await importProgramSource({
    paths,
    programId: "training-ctf",
    source: source({ title: "Updated public challenge rules" }),
    acquisition: { kind: "local-file", path: saved, mediaType: "text/plain" },
    projection: nextProjection,
    now: "2026-10-19T20:05:00.000Z"
  });

  assert.equal(second.snapshot.metadata.revision, 2);
  assert.equal(second.snapshot.predecessor.snapshotSha256, first.snapshot.metadata.snapshotSha256);
  assert.deepEqual(second.diff, diffProgramSourceSnapshots(first.snapshot, second.snapshot));
  assert.equal(second.diff.contentChanged, true);
  assert.equal(second.diff.projectionChanged, true);
  assert.equal(second.diff.sourceMetadataChanged, true);
  assert.deepEqual(second.diff.scope, { added: 1, removed: 0, changed: 1, unchanged: 0 });
  assert.deepEqual(second.diff.rules, { added: 0, removed: 1, changed: 0, unchanged: 0 });
  const serialized = JSON.stringify(second);
  assert.equal(serialized.includes("second public revision"), false);
});

test("re-observing unchanged bytes produces a fresh revision with an unchanged diff", async (t) => {
  const { paths, saved } = fixture(t);
  fs.writeFileSync(saved, "stable rules\n", { mode: 0o600 });
  const input = {
    paths,
    programId: "training-ctf",
    source: source(),
    acquisition: { kind: "local-file", path: saved, mediaType: "text/plain" },
    projection: projection()
  };
  const first = await importProgramSource({ ...input, now: "2026-10-19T20:00:00.000Z" });
  const second = await importProgramSource({ ...input, now: "2026-10-19T20:10:00.000Z" });

  assert.equal(second.snapshot.metadata.revision, 2);
  assert.equal(second.diff.changed, false);
  assert.equal(second.diff.contentChanged, false);
  assert.equal(second.diff.projectionChanged, false);
  assert.equal(second.diff.scope.unchanged, 1);
  const locations = programSourcePaths(paths, "training-ctf", "public-rules");
  assert.equal(fs.readdirSync(locations.bodies).length, 1);
  assert.equal(fs.readdirSync(locations.revisions).length, 2);
  assert.notEqual(first.snapshot.metadata.snapshotSha256, second.snapshot.metadata.snapshotSha256);
});

test("source imports reject unsafe inputs and unsupported projection claims before publication", async (t) => {
  const { root, paths, saved } = fixture(t);
  fs.writeFileSync(saved, "rules\n", { mode: 0o600 });
  const linked = path.join(root, "linked-rules.txt");
  fs.symlinkSync(saved, linked);

  await assert.rejects(importProgramSource({
    paths,
    programId: "training-ctf",
    source: source(),
    acquisition: { kind: "local-file", path: linked },
    projection: projection()
  }), /regular, non-linked file/u);

  await assert.rejects(importProgramSource({
    paths,
    programId: "training-ctf",
    source: source(),
    acquisition: { kind: "local-file", path: saved },
    projection: projection({
      rules: [{ ...projection().rules[0], disposition: "unknown", claimState: "observed" }]
    })
  }), /unknown program source projection rules claims must be unverified/u);

  await assert.rejects(importProgramSource({
    paths,
    programId: "training-ctf",
    source: source(),
    acquisition: { kind: "local-file", path: saved },
    projection: projection({ extra: true })
  }), /unknown field/u);

  await assert.rejects(importProgramSource({
    paths,
    programId: "training-ctf",
    source: source(),
    acquisition: { kind: "local-file", path: saved },
    projection: { scope: null, rules: [] }
  }), /projection scope must be an array/u);

  await assert.rejects(importProgramSource({
    paths,
    programId: "training-ctf",
    source: source({ reference: "https://challenge.example.org/rules?access_token=secret-value-12345678901234567890" }),
    acquisition: { kind: "local-file", path: saved },
    projection: projection()
  }), /credential|opaque credential/u);
});

test("an oversized valid projection is rejected before publishing body or revision state", async (t) => {
  const { paths, saved } = fixture(t);
  fs.writeFileSync(saved, "bounded source body\n", { mode: 0o600 });
  const longConditions = (prefix) => Array.from({ length: 50 }, (_, index) =>
    `${prefix}-${String(index).padStart(2, "0")}-${"x".repeat(5_985)}`);
  const oversized = projection({
    rules: [
      { ...projection().rules[0], id: "large-rule-one", conditions: longConditions("one") },
      { ...projection().rules[0], id: "large-rule-two", conditions: longConditions("two") }
    ]
  });

  await assert.rejects(importProgramSource({
    paths,
    programId: "training-ctf",
    source: source(),
    acquisition: { kind: "local-file", path: saved, mediaType: "text/plain" },
    projection: oversized,
    now: "2026-10-19T20:00:00.000Z"
  }), /manifest limit/u);

  const locations = programSourcePaths(paths, "training-ctf", "public-rules");
  assert.deepEqual(fs.readdirSync(locations.bodies), []);
  assert.deepEqual(fs.readdirSync(locations.revisions), []);
  assert.equal(fs.existsSync(locations.current), false);
  assert.equal(fs.existsSync(locations.lock), false);
});

test("snapshot verification detects retained body mutation", async (t) => {
  const { paths, saved } = fixture(t);
  fs.writeFileSync(saved, "trusted snapshot\n", { mode: 0o600 });
  const imported = await importProgramSource({
    paths,
    programId: "training-ctf",
    source: source(),
    acquisition: { kind: "local-file", path: saved },
    projection: projection(),
    now: "2026-10-19T20:00:00.000Z"
  });
  const locations = programSourcePaths(paths, "training-ctf", "public-rules");
  fs.writeFileSync(
    path.join(locations.bodies, `${imported.snapshot.metadata.contentSha256}.bin`),
    "changed snapshot\n",
    { mode: 0o600 }
  );
  assert.throws(
    () => readCurrentProgramSource("training-ctf", "public-rules", { paths }),
    /body changed after snapshot publication/u
  );
});

test("current source verification detects missing or mutated historical bodies", async (t) => {
  const { paths, saved } = fixture(t);
  const firstBody = Buffer.from("historical source body one\n", "utf8");
  fs.writeFileSync(saved, firstBody, { mode: 0o600 });
  const first = await importProgramSource({
    paths,
    programId: "training-ctf",
    source: source(),
    acquisition: { kind: "local-file", path: saved },
    projection: projection(),
    now: "2026-10-19T20:00:00.000Z"
  });
  fs.writeFileSync(saved, "current source body two\n", { mode: 0o600 });
  await importProgramSource({
    paths,
    programId: "training-ctf",
    source: source(),
    acquisition: { kind: "local-file", path: saved },
    projection: projection(),
    now: "2026-10-19T20:05:00.000Z"
  });

  const locations = programSourcePaths(paths, "training-ctf", "public-rules");
  const historicalBody = path.join(locations.bodies, `${first.snapshot.metadata.contentSha256}.bin`);
  fs.writeFileSync(historicalBody, "historical source body XXX\n", { mode: 0o600 });
  assert.throws(
    () => readCurrentProgramSource("training-ctf", "public-rules", { paths }),
    /body changed after snapshot publication/u
  );

  fs.writeFileSync(historicalBody, firstBody, { mode: 0o600 });
  fs.unlinkSync(historicalBody);
  assert.throws(
    () => readCurrentProgramSource("training-ctf", "public-rules", { paths }),
    /private program source body|unavailable|ENOENT/u
  );
});

test("current source reads reject orphaned or non-contiguous revision history", async (t) => {
  const { paths, saved } = fixture(t);
  fs.writeFileSync(saved, "trusted snapshot\n", { mode: 0o600 });
  await importProgramSource({
    paths,
    programId: "training-ctf",
    source: source(),
    acquisition: { kind: "local-file", path: saved },
    projection: projection(),
    now: "2026-10-19T20:00:00.000Z"
  });
  const locations = programSourcePaths(paths, "training-ctf", "public-rules");
  fs.writeFileSync(
    path.join(locations.revisions, `r000002-${"a".repeat(16)}.json`),
    "{}\n",
    { mode: 0o600 }
  );
  assert.throws(
    () => readCurrentProgramSource("training-ctf", "public-rules", { paths }),
    /revision history and current pointer diverged/u
  );
});

test("public URL resolution rejects local, private, reserved, and mixed DNS answers", async () => {
  for (const address of ["127.0.0.1", "10.0.0.4", "169.254.169.254", "192.168.1.2", "::1", "fd00::1", "2001:db8::1", "::ffff:127.0.0.1"]) {
    assert.equal(isPublicProgramSourceAddress(address), false, address);
  }
  for (const address of ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"]) {
    assert.equal(isPublicProgramSourceAddress(address), true, address);
  }
  await assert.rejects(
    resolvePublicProgramSourceUrl("http://program.example.org/rules", { lookup: async () => [] }),
    /must use HTTPS/u
  );
  await assert.rejects(
    resolvePublicProgramSourceUrl("https://localhost/rules", { lookup: async () => [] }),
    /hostname is not public/u
  );
  await assert.rejects(
    resolvePublicProgramSourceUrl("https://program.example.org/rules", {
      lookup: async () => [{ address: "8.8.8.8", family: 4 }, { address: "127.0.0.1", family: 4 }]
    }),
    /non-public or unsupported/u
  );
});

test("bounded public retrieval revalidates redirects and records exact response metadata", async () => {
  const requests = [];
  const lookup = async () => [{ address: "8.8.8.8", family: 4 }];
  const transport = async ({ url, maximumBytes, timeoutMs }) => {
    requests.push({ url, maximumBytes, timeoutMs });
    if (requests.length === 1) {
      return {
        status: 302,
        headers: { location: "https://rules.example.org/current" },
        body: Buffer.alloc(0)
      };
    }
    return {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8", "content-encoding": "identity" },
      body: Buffer.from("public rules\n", "utf8")
    };
  };
  const result = await fetchPublicProgramSource("https://program.example.org/rules", { lookup, transport });
  assert.equal(requests.length, 2);
  assert.equal(result.requestedUrl, "https://program.example.org/rules");
  assert.equal(result.finalUrl, "https://rules.example.org/current");
  assert.equal(result.redirects, 1);
  assert.equal(result.httpStatus, 200);
  assert.equal(result.mediaType, "text/plain");
  assert.equal(result.contentEncoding, "identity");
  assert.equal(result.body.toString("utf8"), "public rules\n");
});

test("public retrieval applies one cumulative byte budget and one absolute deadline", async () => {
  const lookup = async () => [{ address: "8.8.8.8", family: 4 }];
  let request = 0;
  await assert.rejects(fetchPublicProgramSource("https://program.example.org/rules", {
    lookup,
    maximumBytes: 10,
    transport: async () => {
      request += 1;
      return request === 1
        ? { status: 302, headers: { location: "https://rules.example.org/current" }, body: Buffer.alloc(6) }
        : { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.alloc(5) };
    }
  }), /cumulative 10-byte limit/u);

  await assert.rejects(fetchPublicProgramSource("https://program.example.org/rules", {
    lookup,
    timeoutMs: 100,
    transport: async () => new Promise(() => {})
  }), /timed out/u);

  await assert.rejects(fetchPublicProgramSource("https://program.example.org/rules", {
    timeoutMs: 100,
    lookup: async () => new Promise(() => {})
  }), /timed out during DNS resolution/u);
});

test("URL imports require an explicit network decision and accept only bounded retriever output", async (t) => {
  const { paths } = fixture(t);
  const input = {
    paths,
    programId: "training-ctf",
    source: source({ reference: "https://PROGRAM.example.org:443/a/../rules#not-requested" }),
    acquisition: { kind: "public-url", url: "https://PROGRAM.example.org:443/a/../rules#not-requested" },
    projection: projection()
  };
  await assert.rejects(importProgramSource(input), /explicit allowNetwork: true/u);

  const imported = await importProgramSource({
    ...input,
    allowNetwork: true,
    fetchPublicSource: async () => ({
      body: Buffer.from("public program body\n", "utf8"),
      requestedUrl: "https://program.example.org/rules",
      finalUrl: "https://program.example.org/rules",
      redirects: 0,
      httpStatus: 200,
      mediaType: "text/plain",
      contentEncoding: null
    }),
    now: "2026-10-19T20:00:00.000Z"
  });
  assert.equal(imported.snapshot.acquisition.method, "public-url");
  assert.equal(imported.snapshot.acquisition.requestedUrl, "https://program.example.org/rules");
  assert.equal(imported.snapshot.source.reference, "https://program.example.org/rules");
  assert.equal(imported.snapshot.acquisition.httpStatus, 200);
  assert.equal(imported.snapshot.metadata.revision, 1);

  await assert.rejects(importProgramSource({
    ...input,
    programId: "other-training-ctf",
    source: source({ reference: "https://different.example.org/rules" }),
    allowNetwork: true,
    fetchPublicSource: async () => ({
      body: Buffer.from("public program body\n", "utf8"),
      requestedUrl: "https://program.example.org/rules",
      finalUrl: "https://program.example.org/rules",
      redirects: 0,
      httpStatus: 200,
      mediaType: "text/plain",
      contentEncoding: null
    })
  }), /reference must match the exact requested URL/u);
});
