import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  listProjects,
  projectContractBinding,
  projectRegistryStatus,
  registerProject,
  showProject,
  verifyProject
} from "../src/lib/projects.mjs";
import { runtimePaths } from "../src/lib/paths.mjs";

const execFileAsync = promisify(execFile);
const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const gate = path.join(repo, "bin", "gate.mjs");
const projectModule = pathToFileURL(path.join(repo, "src", "lib", "projects.mjs")).href;
const MAX_PROJECT_BYTES = 128 * 1024;

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-projects-"));
  const paths = runtimePaths({ home: path.join(root, "home"), repo });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, paths };
}

function project(id = "demo-project", overrides = {}) {
  const value = JSON.parse(fs.readFileSync(path.join(repo, "templates", "project.json"), "utf8"));
  value.metadata = { id, displayName: "Demo Project" };
  value.repository.url = `https://github.com/example/${id}`;
  return {
    ...value,
    ...overrides,
    metadata: { ...value.metadata, ...overrides.metadata },
    repository: { ...value.repository, ...overrides.repository },
    execution: { ...value.execution, ...overrides.execution },
    delivery: {
      ...value.delivery,
      ...overrides.delivery,
      deployment: { ...value.delivery.deployment, ...overrides.delivery?.deployment }
    },
    security: { ...value.security, ...overrides.security },
    learning: { ...value.learning, ...overrides.learning }
  };
}

function writeSource(root, value, name = "project.json") {
  const file = path.join(root, name);
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  return file;
}

function mode(file) {
  return fs.statSync(file).mode & 0o777;
}

test("project registry validates, stores, lists, shows, and verifies a private contract", (t) => {
  const { root, paths } = fixture(t);
  const value = project();
  const source = writeSource(root, value);

  const registered = registerProject(source, { paths });
  assert.equal(registered.created, true);
  assert.equal(registered.project.id, "demo-project");
  assert.equal(registered.project.repository.url, undefined, "summary must omit the repository URL");
  assert.ok(registered.checks.every((item) => item.ok));

  const stored = path.join(paths.projects, "demo-project.json");
  assert.deepEqual(showProject("demo-project", { paths }), value);
  assert.equal(verifyProject("demo-project", { paths }).ok, true);
  assert.equal(listProjects({ paths }).length, 1);
  assert.deepEqual(projectRegistryStatus({ paths }), [{
    id: "demo-project",
    status: "ready",
    provider: "github",
    executionProfile: "default",
    environment: "host",
    deliveryMode: "no-mistakes",
    deploymentEnabled: false,
    securityProfile: "pentest",
    activeTestingEnabled: true
  }]);
  const storedBytes = fs.readFileSync(stored);
  const event = JSON.parse(fs.readFileSync(paths.events, "utf8"));
  const contractSha256 = crypto.createHash("sha256").update(storedBytes).digest("hex");
  assert.deepEqual(projectContractBinding("demo-project", { paths }), {
    id: "demo-project",
    contractSha256
  });
  assert.equal(event.kind, "project.registered");
  assert.ok(event.evidenceRefs.some((reference) => reference.endsWith(`/${contractSha256}`)));
  if (process.platform !== "win32") {
    assert.equal(mode(paths.projects), 0o700);
    assert.equal(mode(stored), 0o600);
  }
});

test("registration is idempotent but rejects replacement and duplicate repository identity", (t) => {
  const { root, paths } = fixture(t);
  const original = project();
  const first = writeSource(root, original, "first.json");
  const reordered = Object.fromEntries(Object.entries(original).reverse());
  const second = writeSource(root, reordered, "second.json");

  assert.equal(registerProject(first, { paths }).created, true);
  assert.equal(registerProject(second, { paths }).created, false, "JSON key order and whitespace are not contract changes");

  const changed = writeSource(root, project("demo-project", { metadata: { displayName: "Changed" } }), "changed.json");
  assert.throws(() => registerProject(changed, { paths }), /different content/);

  const duplicate = project("another-project", { repository: { url: "https://github.com/example/demo-project.git" } });
  assert.throws(() => registerProject(writeSource(root, duplicate, "duplicate.json"), { paths }), /already registered/);
  const caseAlias = project("case-alias", { repository: { url: "https://github.com/EXAMPLE/DEMO-PROJECT" } });
  assert.throws(() => registerProject(writeSource(root, caseAlias, "case-alias.json"), { paths }), /already registered/);
  assert.equal(listProjects({ paths }).length, 1);
  assert.equal(fs.readFileSync(paths.events, "utf8").trim().split("\n").length, 1, "idempotent reads must not emit another registration event");
});

test("registration never steals an old registry lock without operator recovery", (t) => {
  const { root, paths } = fixture(t);
  fs.mkdirSync(paths.projects, { recursive: true, mode: 0o700 });
  const lock = path.join(paths.projects, ".registry.lock");
  fs.writeFileSync(lock, `${JSON.stringify({
    pid: process.pid,
    nonce: "live-owner",
    createdAt: new Date(Date.now() - 60_000).toISOString()
  })}\n`, { mode: 0o600 });
  const stale = new Date(Date.now() - 60_000);
  fs.utimesSync(lock, stale, stale);

  assert.throws(
    () => registerProject(writeSource(root, project("blocked-project")), { paths, lock: { timeoutMs: 25 } }),
    /verify no registration process is active/
  );
  assert.equal(fs.existsSync(lock), true);
  assert.equal(verifyProject("blocked-project", { paths }).ok, false);
});

test("local repository identities reject remote hosts and collapse path aliases", (t) => {
  const { root, paths } = fixture(t);
  const localRepository = path.join(root, "local-repository");
  fs.mkdirSync(localRepository);
  const first = project("local-project", {
    repository: { provider: "local", url: `${pathToFileURL(localRepository).href}/` }
  });
  assert.equal(registerProject(writeSource(root, first, "local.json"), { paths }).created, true);

  const trailingAlias = project("local-alias", {
    repository: { provider: "local", url: pathToFileURL(localRepository).href }
  });
  assert.throws(() => registerProject(writeSource(root, trailingAlias, "local-alias.json"), { paths }), /already registered/);
  if (process.platform !== "win32") {
    const linkedRepository = path.join(root, "linked-local-repository");
    fs.symlinkSync(localRepository, linkedRepository, "dir");
    const symlinkAlias = project("local-symlink-alias", {
      repository: { provider: "local", url: pathToFileURL(linkedRepository).href }
    });
    assert.throws(() => registerProject(writeSource(root, symlinkAlias, "local-symlink.json"), { paths }), /already registered/);
  }

  const remoteFile = project("remote-file", {
    repository: { provider: "local", url: "file://server/share/repository" }
  });
  assert.throws(() => registerProject(writeSource(root, remoteFile, "remote-file.json"), { paths }), /remote file host/);

  const missing = project("missing-local", {
    repository: { provider: "local", url: pathToFileURL(path.join(localRepository, "missing")).href }
  });
  assert.throws(() => registerProject(writeSource(root, missing, "missing-local.json"), { paths }), /must exist/);

  const regularFile = path.join(root, "not-a-directory");
  fs.writeFileSync(regularFile, "not a repository directory\n");
  const wrongType = project("file-local", {
    repository: { provider: "local", url: pathToFileURL(regularFile).href }
  });
  assert.throws(() => registerProject(writeSource(root, wrongType, "file-local.json"), { paths }), /must be a directory/);
});

test("local registrations persist a physical path when an input symlink later moves", {
  skip: process.platform === "win32" && "creating directory links can require elevated Windows privileges"
}, (t) => {
  const { root, paths } = fixture(t);
  const firstRepository = path.join(root, "repository-one");
  const secondRepository = path.join(root, "repository-two");
  const current = path.join(root, "current-repository");
  fs.mkdirSync(firstRepository);
  fs.mkdirSync(secondRepository);
  fs.symlinkSync(firstRepository, current, "dir");

  const first = project("first-local", {
    repository: { provider: "local", url: pathToFileURL(current).href }
  });
  assert.equal(registerProject(writeSource(root, first, "first-local.json"), { paths }).created, true);
  assert.equal(showProject("first-local", { paths }).repository.url, pathToFileURL(fs.realpathSync(firstRepository)).href);

  fs.unlinkSync(current);
  fs.symlinkSync(secondRepository, current, "dir");
  const second = project("second-local", {
    repository: { provider: "local", url: pathToFileURL(current).href }
  });
  assert.equal(registerProject(writeSource(root, second, "second-local.json"), { paths }).created, true);
  assert.equal(verifyProject("first-local", { paths }).ok, true);
  assert.equal(showProject("second-local", { paths }).repository.url, pathToFileURL(fs.realpathSync(secondRepository)).href);
});

test("a registered local locator fails closed after its canonical path becomes an alias", {
  skip: process.platform === "win32" && "creating directory links can require elevated Windows privileges"
}, (t) => {
  const { root, paths } = fixture(t);
  const firstRepository = path.join(root, "canonical-one");
  const secondRepository = path.join(root, "canonical-two");
  const movedFirst = path.join(root, "canonical-one-moved");
  fs.mkdirSync(firstRepository);
  fs.mkdirSync(secondRepository);
  assert.equal(registerProject(writeSource(root, project("first-canonical", {
    repository: { provider: "local", url: pathToFileURL(firstRepository).href }
  }), "first-canonical.json"), { paths }).created, true);
  assert.equal(registerProject(writeSource(root, project("second-canonical", {
    repository: { provider: "local", url: pathToFileURL(secondRepository).href }
  }), "second-canonical.json"), { paths }).created, true);

  fs.renameSync(firstRepository, movedFirst);
  fs.symlinkSync(secondRepository, firstRepository, "dir");
  const firstVerification = verifyProject("first-canonical", { paths });
  assert.equal(firstVerification.ok, false);
  assert.match(firstVerification.checks.find((item) => item.name === "repository-locator").detail, /no longer resolves/);
  assert.equal(verifyProject("second-canonical", { paths }).ok, true);
  assert.throws(() => showProject("first-canonical", { paths }), /no longer resolves/);
});

test("remote identities reject provider relabeling and forge web-view paths", (t) => {
  const { root, paths } = fixture(t);
  const invalid = [
    [project("gitlab-web-view", { repository: { provider: "gitlab", url: "https://gitlab.com/example/repository/-/tree/main" } }), /web-view route/],
    [project("gitea-web-view", { repository: { provider: "gitea", url: "https://code.example.test/owner/repository/src/branch/main" } }), /exactly an owner and repository/],
    [project("forgejo-web-view", { repository: { provider: "forgejo", url: "https://code.example.test/owner/repository/src/branch/main" } }), /exactly an owner and repository/],
    [project("public-host-mismatch", { repository: { provider: "gitlab", url: "https://github.com/example/repository" } }), /must use the github provider/]
  ];
  for (const [value, expected] of invalid) {
    assert.throws(() => registerProject(writeSource(root, value, `${value.metadata.id}.json`), { paths }), expected);
  }

  const original = project("custom-gitea", {
    repository: { provider: "gitea", url: "https://code.example.test/owner/repository" }
  });
  assert.equal(registerProject(writeSource(root, original, "custom-gitea.json"), { paths }).created, true);
  const giteaCaseAlias = project("custom-gitea-case", {
    repository: { provider: "gitea", url: "https://code.example.test/OWNER/REPOSITORY" }
  });
  assert.throws(() => registerProject(writeSource(root, giteaCaseAlias, "custom-gitea-case.json"), { paths }), /already registered/);
  const relabeled = project("custom-forgejo", {
    repository: { provider: "forgejo", url: "https://code.example.test/owner/repository" }
  });
  assert.throws(() => registerProject(writeSource(root, relabeled, "custom-forgejo.json"), { paths }), /already registered/);

  const forgejo = project("forgejo-case", {
    repository: { provider: "forgejo", url: "https://forge.example.test/team/repository" }
  });
  assert.equal(registerProject(writeSource(root, forgejo, "forgejo-case.json"), { paths }).created, true);
  const forgejoAlias = project("forgejo-alias", {
    repository: { provider: "forgejo", url: "https://forge.example.test/TEAM/REPOSITORY" }
  });
  assert.throws(() => registerProject(writeSource(root, forgejoAlias, "forgejo-alias.json"), { paths }), /already registered/);

  const gitlab = project("gitlab-case", {
    repository: { provider: "gitlab", url: "https://gitlab.com/Group/Subgroup/Repository" }
  });
  assert.equal(registerProject(writeSource(root, gitlab, "gitlab-case.json"), { paths }).created, true);
  const gitlabAlias = project("gitlab-alias", {
    repository: { provider: "gitlab", url: "https://gitlab.com/group/subgroup/repository" }
  });
  assert.throws(() => registerProject(writeSource(root, gitlabAlias, "gitlab-alias.json"), { paths }), /already registered/);
});

test("audit failure preserves a transaction-bound contract for reconciliation", (t) => {
  const { root, paths } = fixture(t);
  const source = writeSource(root, project("audit-failure"));
  assert.throws(
    () => registerProject(source, {
      paths,
      eventRecorder() {
        throw new Error("fixture audit failure");
      }
    }),
    /audit outcome is uncertain; the contract and pending marker were preserved/
  );
  const stored = path.join(paths.projects, "audit-failure.json");
  const pending = path.join(paths.projects, ".registry.pending");
  assert.equal(fs.existsSync(stored), true);
  assert.equal(fs.existsSync(pending), true);
  assert.equal(fs.existsSync(paths.events), false);
  assert.equal(verifyProject("audit-failure", { paths }).ok, false);
  assert.equal(listProjects({ paths }).every((entry) => entry.status === "invalid"), true);

  const marker = JSON.parse(fs.readFileSync(pending, "utf8"));
  assert.equal(marker.apiVersion, "gate.project-registration/v1");
  assert.equal(marker.kind, "ProjectRegistrationPending");
  assert.equal(marker.projectId, "audit-failure");
  assert.match(marker.transactionNonce, /^[a-f0-9]{32}$/);
  assert.equal(marker.eventId, `evt_project_${marker.transactionNonce}`);
  assert.equal(marker.contractSha256, crypto.createHash("sha256").update(fs.readFileSync(stored)).digest("hex"));
});

test("close-after-write audit ambiguity preserves exact event reconciliation state", (t) => {
  const { root, paths } = fixture(t);
  const source = writeSource(root, project("ambiguous-audit"));
  const auditDescriptors = new Set();
  const originalWrite = fs.writeFileSync;
  const originalSync = fs.fsyncSync;
  const originalClose = fs.closeSync;
  let auditWasSynced = false;
  fs.writeFileSync = function injectedWrite(file, data, ...rest) {
    const result = originalWrite.call(this, file, data, ...rest);
    if (typeof file === "number" && String(data).includes('"kind":"project.registered"')) {
      auditDescriptors.add(file);
    }
    return result;
  };
  fs.fsyncSync = function injectedSync(descriptor) {
    if (auditDescriptors.has(descriptor)) auditWasSynced = true;
    return originalSync.call(this, descriptor);
  };
  fs.closeSync = function injectedClose(descriptor) {
    if (auditDescriptors.delete(descriptor)) {
      originalClose.call(this, descriptor);
      throw Object.assign(new Error("fixture audit close ambiguity"), { code: "EIO" });
    }
    return originalClose.call(this, descriptor);
  };
  try {
    assert.throws(
      () => registerProject(source, { paths }),
      /audit outcome is uncertain; the contract and pending marker were preserved/
    );
  } finally {
    fs.writeFileSync = originalWrite;
    fs.fsyncSync = originalSync;
    fs.closeSync = originalClose;
  }

  const stored = path.join(paths.projects, "ambiguous-audit.json");
  const marker = JSON.parse(fs.readFileSync(path.join(paths.projects, ".registry.pending"), "utf8"));
  const events = fs.readFileSync(paths.events, "utf8").trim().split("\n").map((line) => JSON.parse(line));
  const event = events.find((candidate) => candidate.id === marker.eventId);
  assert.equal(fs.existsSync(stored), true);
  assert.equal(verifyProject("ambiguous-audit", { paths }).ok, false);
  assert.equal(auditWasSynced, true, "the event line must be flushed before close can report ambiguous failure");
  assert.ok(event, "the complete event line may exist even though close reported failure");
  assert.equal(marker.contractSha256, crypto.createHash("sha256").update(fs.readFileSync(stored)).digest("hex"));
  assert.ok(event.evidenceRefs.includes(
    `evidence://project-registration/${marker.transactionNonce}/${marker.contractSha256}`
  ));
  assert.ok(event.evidenceRefs.includes("private://projects/ambiguous-audit.json"));
});

test("a post-rename verification failure rolls back before clearing pending state", (t) => {
  const { root, paths } = fixture(t);
  const source = writeSource(root, project("publish-failure"));
  const destination = path.join(paths.projects, "publish-failure.json");
  const originalOpen = fs.openSync;
  fs.openSync = function injectedOpen(file, flags, ...rest) {
    if (path.resolve(file) === path.resolve(destination) && fs.existsSync(destination)) {
      throw Object.assign(new Error("fixture post-rename I/O failure"), { code: "EIO" });
    }
    return originalOpen.call(this, file, flags, ...rest);
  };
  try {
    assert.throws(() => registerProject(source, { paths }), /fixture post-rename I\/O failure/);
  } finally {
    fs.openSync = originalOpen;
  }

  assert.equal(fs.existsSync(destination), false);
  assert.equal(fs.existsSync(path.join(paths.projects, ".registry.pending")), false);
  assert.equal(fs.existsSync(paths.events), false);
  assert.deepEqual(listProjects({ paths }), []);
  assert.equal(registerProject(source, { paths }).created, true);
});

test("a post-rename staging cleanup failure also rolls back the published contract", (t) => {
  const { root, paths } = fixture(t);
  const source = writeSource(root, project("cleanup-failure"));
  const destination = path.join(paths.projects, "cleanup-failure.json");
  const originalRemove = fs.rmSync;
  fs.rmSync = function injectedRemove(file, options) {
    if (path.basename(file).startsWith(".project-cleanup-failure.") && fs.existsSync(destination)) {
      throw Object.assign(new Error("fixture staging cleanup I/O failure"), { code: "EIO" });
    }
    return originalRemove.call(this, file, options);
  };
  try {
    assert.throws(() => registerProject(source, { paths }), /fixture staging cleanup I\/O failure/);
  } finally {
    fs.rmSync = originalRemove;
  }

  assert.equal(fs.existsSync(destination), false);
  assert.equal(fs.existsSync(path.join(paths.projects, ".registry.pending")), false);
  assert.equal(fs.existsSync(paths.events), false);
  assert.equal(registerProject(source, { paths }).created, true);
});

test("an interrupted registration remains invalid after stale-lock removal", async (t) => {
  const { root, paths } = fixture(t);
  const source = writeSource(root, project("interrupted-project"));
  const script = `
    import { registerProject } from ${JSON.stringify(projectModule)};
    registerProject(process.env.GATE_PROJECT_SOURCE, {
      paths: JSON.parse(process.env.GATE_PROJECT_PATHS),
      eventRecorder() { process.exit(70); }
    });
  `;
  await assert.rejects(execFileAsync(
    process.execPath,
    ["--input-type=module", "--eval", script],
    {
      env: {
        ...process.env,
        GATE_PROJECT_SOURCE: source,
        GATE_PROJECT_PATHS: JSON.stringify(paths)
      },
      timeout: 20_000
    }
  ), (error) => error.code === 70);

  assert.equal(fs.existsSync(path.join(paths.projects, "interrupted-project.json")), true);
  assert.equal(fs.existsSync(path.join(paths.projects, ".registry.lock")), true);
  assert.equal(fs.existsSync(path.join(paths.projects, ".registry.pending")), true);
  assert.equal(fs.existsSync(paths.events), false);
  assert.equal(verifyProject("interrupted-project", { paths }).ok, false);
  assert.equal(projectRegistryStatus({ paths }).every((entry) => entry.status === "invalid"), true);

  fs.unlinkSync(path.join(paths.projects, ".registry.lock"));
  assert.equal(verifyProject("interrupted-project", { paths }).ok, false, "pending marker survives stale-lock recovery");
  assert.equal(projectRegistryStatus({ paths }).every((entry) => entry.status === "invalid"), true);
  assert.throws(
    () => registerProject(source, { paths }),
    /reconcile its project and project\.registered event/,
    "an identical retry must not bypass the durable pending marker"
  );
});

test("schema, repository, profile, and source failures leave the registry unchanged", (t) => {
  const { root, paths } = fixture(t);
  const cases = [
    [project("bad-credential", { repository: { url: "https://user:secret@github.com/example/bad-credential" } }), /credentials/],
    [project("wrong-host", { repository: { url: "https://gitlab.com/example/wrong-host" } }), /must use the gitlab provider/],
    [project("web-view", { repository: { url: "https://github.com/example/web-view/tree/main" } }), /exactly an owner and repository/],
    [project("unknown-profile", { execution: { profile: "missing-profile" } }), /unknown profile/],
    [project("unsafe-branch", { repository: { defaultBranch: ".hidden" } }), /valid Git branch/],
    [{ ...project("missing-learning"), learning: undefined }, /required property/]
  ];
  for (const [value, expected] of cases) {
    const clean = JSON.parse(JSON.stringify(value));
    const source = writeSource(root, clean, `${clean.metadata.id}.json`);
    assert.throws(() => registerProject(source, { paths }), expected);
  }
  assert.deepEqual(listProjects({ paths }), []);
  assert.equal(fs.existsSync(paths.events), false);

  if (process.platform !== "win32") {
    const target = writeSource(root, project("linked-source"), "source-target.json");
    const linked = path.join(root, "source-link.json");
    fs.symlinkSync(target, linked);
    assert.throws(() => registerProject(linked, { paths }), /non-symlink/);
  }
});

test("invalid registry content remains visible as an invalid verification", (t) => {
  const { paths } = fixture(t);
  fs.mkdirSync(paths.projects, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(paths.projects, "broken-project.json"), "{not-json}\n", { mode: 0o600 });

  const verification = verifyProject("broken-project", { paths });
  assert.equal(verification.ok, false);
  assert.equal(verification.status, "invalid");
  const entries = listProjects({ paths });
  assert.equal(entries.length, 1);
  assert.equal(entries[0].status, "invalid");
  assert.deepEqual(projectRegistryStatus({ paths }), [{ id: "broken-project", registryEntry: "broken-project", status: "invalid" }]);

  fs.writeFileSync(path.join(paths.projects, "unexpected.tmp"), "unexpected\n", { mode: 0o600 });
  const withUnexpected = listProjects({ paths });
  assert.equal(withUnexpected.length, 2);
  assert.equal(withUnexpected.find((entry) => entry.entry === "unexpected.tmp").status, "invalid");
  const source = writeSource(path.dirname(paths.home), project("new-project"), "new-project.json");
  assert.throws(() => registerProject(source, { paths }), /project registry contains/);
});

test("persisted project records retain the import byte ceiling", (t) => {
  const { paths } = fixture(t);
  fs.mkdirSync(paths.projects, { recursive: true, mode: 0o700 });
  const file = path.join(paths.projects, "oversized-project.json");
  fs.writeFileSync(file, " ".repeat(129 * 1024), { mode: 0o600 });
  const result = verifyProject("oversized-project", { paths });
  assert.equal(result.ok, false);
  assert.match(result.checks[0].detail, /131072-byte limit/);
});

test("registration rejects canonical pretty JSON that exceeds the import byte ceiling", (t) => {
  const { root, paths } = fixture(t);
  const value = project("canonical-oversized");
  value.$schema = "";
  const minifiedOverhead = Buffer.byteLength(JSON.stringify(value), "utf8");
  value.$schema = "x".repeat(MAX_PROJECT_BYTES - minifiedOverhead);
  const minified = JSON.stringify(value);
  assert.equal(Buffer.byteLength(minified, "utf8"), MAX_PROJECT_BYTES, "fixture source must fit the exact import ceiling");
  assert.ok(
    Buffer.byteLength(`${JSON.stringify(value, null, 2)}\n`, "utf8") > MAX_PROJECT_BYTES,
    "canonical pretty representation must exceed the ceiling"
  );
  const source = path.join(root, "canonical-oversized.json");
  fs.writeFileSync(source, minified, { mode: 0o600 });

  assert.throws(
    () => registerProject(source, { paths }),
    /canonical project contract exceeds the 131072-byte limit/
  );
  assert.deepEqual(fs.readdirSync(paths.projects), []);
  assert.equal(fs.existsSync(paths.events), false);
});

test("concurrent identical registrations produce one contract and one event", async (t) => {
  const { root, paths } = fixture(t);
  const source = writeSource(root, project("parallel-project"));
  const script = `
    import { registerProject } from ${JSON.stringify(projectModule)};
    registerProject(process.env.GATE_PROJECT_SOURCE, { paths: JSON.parse(process.env.GATE_PROJECT_PATHS) });
  `;
  const environment = {
    ...process.env,
    GATE_PROJECT_SOURCE: source,
    GATE_PROJECT_PATHS: JSON.stringify(paths)
  };
  const registrations = Array.from({ length: 4 }, () => execFileAsync(
    process.execPath,
    ["--input-type=module", "--eval", script],
    { env: environment, timeout: 20_000 }
  ));
  for (let index = 0; index < 50; index += 1) {
    assert.doesNotThrow(() => listProjects({ paths }), "read-only registry inspection must tolerate the transient writer lock");
  }
  await Promise.all(registrations);

  assert.equal(listProjects({ paths }).length, 1);
  assert.equal(fs.readFileSync(paths.events, "utf8").trim().split("\n").length, 1);
  assert.equal(fs.existsSync(path.join(paths.projects, ".registry.lock")), false);
});

test("project CLI exposes register, list, show, and failing verify", async (t) => {
  const { root, paths } = fixture(t);
  const source = writeSource(root, project("cli-project"));
  const environment = { ...process.env, GATE_HOME: paths.home };

  const registered = await execFileAsync(process.execPath, [gate, "project", "register", "--file", source, "--json"], {
    cwd: repo,
    env: environment,
    timeout: 10_000
  });
  assert.equal(JSON.parse(registered.stdout).created, true);

  const listed = await execFileAsync(process.execPath, [gate, "project", "list", "--json"], { cwd: repo, env: environment });
  assert.equal(JSON.parse(listed.stdout)[0].project.id, "cli-project");

  const shown = await execFileAsync(process.execPath, [gate, "project", "show", "cli-project", "--json"], { cwd: repo, env: environment });
  assert.equal(JSON.parse(shown.stdout).repository.url, "https://github.com/example/cli-project");

  await assert.rejects(
    execFileAsync(process.execPath, [gate, "project", "verify", "missing-project", "--json"], { cwd: repo, env: environment }),
    (error) => error.code === 2 && JSON.parse(error.stdout).ok === false
  );
});
