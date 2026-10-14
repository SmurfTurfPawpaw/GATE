import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";
import { leaseWorkspace, returnWorkspace, verifyWorkspace, workspaceStatus } from "../src/lib/workspaces.mjs";

const sourceRepo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const LEASE_ID = "0123456789abcdef0123456789abcdef";
const LEASED_AT = "2026-10-13T22:00:00.000Z";

function git(cwd, ...args) {
  return execFileSync("git", args, { cwd, encoding: "utf8" }).trim();
}

function gitResult(cwd, ...args) {
  return spawnSync("git", args, { cwd, encoding: "utf8" });
}

function writeCloneBinding(repository, treehouseRoot) {
  const repositoryStat = fs.lstatSync(repository, { bigint: true });
  const gitDirectory = fs.realpathSync(path.join(repository, ".git"));
  const gitStat = fs.lstatSync(gitDirectory, { bigint: true });
  const value = {
    version: 1,
    repository: fs.realpathSync(repository),
    repositoryDevice: repositoryStat.dev.toString(),
    repositoryInode: repositoryStat.ino.toString(),
    gitDirectory,
    gitDevice: gitStat.dev.toString(),
    gitInode: gitStat.ino.toString()
  };
  fs.mkdirSync(treehouseRoot, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(treehouseRoot, ".gate-clone-binding.json"), `${JSON.stringify(value)}\n`, { mode: 0o600 });
}

function writeTaskBinding(repository, taskRoot, taskId = "task-1") {
  const repositoryStat = fs.lstatSync(repository, { bigint: true });
  const gitDirectory = fs.realpathSync(path.join(repository, ".git"));
  const gitStat = fs.lstatSync(gitDirectory, { bigint: true });
  const taskHash = crypto.createHash("sha256").update(taskId).digest("hex");
  const value = {
    version: 1,
    repository: fs.realpathSync(repository),
    repositoryDevice: repositoryStat.dev.toString(),
    repositoryInode: repositoryStat.ino.toString(),
    gitDirectory,
    gitDevice: gitStat.dev.toString(),
    gitInode: gitStat.ino.toString(),
    taskId,
    taskHash
  };
  fs.mkdirSync(taskRoot, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(taskRoot, ".gate-task-binding.json"), `${JSON.stringify(value)}\n`, { mode: 0o600 });
  return value;
}

function treehouseSeedDigest(key, entry) {
  const payload = JSON.stringify({
    name: entry.name,
    path: path.normalize(entry.path),
    seeded_paths: entry.seeded_paths || [],
    seed_backend: entry.seed_backend || "",
    seed_auth_identity: entry.seed_auth_identity || ""
  }).replace(/[<>&\u2028\u2029]/gu, (character) => {
    return `\\u${character.codePointAt(0).toString(16).padStart(4, "0")}`;
  });
  return crypto.createHmac("sha256", key).update(payload).digest("hex");
}

function writeTreehouseState(fixture, overrides = {}) {
  const key = overrides.key || Buffer.alloc(32, 0x47);
  const entry = {
    name: "1",
    path: fixture.workspace,
    created_at: LEASED_AT,
    leased: true,
    lease_id: LEASE_ID,
    lease_holder: "gate:task-1",
    leased_at: LEASED_AT,
    base_branch: "main",
    seed_inventory_known: true,
    ...overrides.entry
  };
  entry.seed_inventory_digest = treehouseSeedDigest(key, entry);
  const state = { version: 4, worktrees: [entry], ...overrides.state };
  const stateBytes = Buffer.from(`${JSON.stringify(state, null, 2)}\n`);
  fs.mkdirSync(fixture.poolDirectory, { recursive: true, mode: 0o755 });
  fs.mkdirSync(path.dirname(fixture.workspace), { recursive: true, mode: 0o755 });
  fs.mkdirSync(path.join(fixture.treehouseRoot, ".treehouse"), { recursive: true, mode: 0o755 });
  fs.writeFileSync(path.join(fixture.treehouseRoot, ".treehouse", ".gitignore"), "*\n", { mode: 0o644 });
  fs.writeFileSync(path.join(fixture.poolDirectory, "treehouse-state.json"), stateBytes, { mode: 0o644 });
  fs.writeFileSync(path.join(fixture.poolDirectory, "treehouse-state.key"), key, { mode: 0o600 });
  fs.writeFileSync(path.join(fixture.poolDirectory, "treehouse-state.lock"), "", { mode: 0o644 });
  return { entry, key, stateBytes };
}

function writeGateLeaseBinding(fixture, state, {
  taskId = "task-1",
  branch = "gate/task-1",
  baseBranch = "main"
} = {}) {
  const task = writeTaskBinding(fixture.repository, fixture.treehouseRoot, taskId);
  const event = {
    id: `evt_fixture_${taskId}`,
    kind: "workspace.leased",
    taskId,
    effect: { targetRef: `private://workspaces/${state.entry.lease_id}` }
  };
  const value = {
    ...task,
    phase: "complete",
    workspacePath: fixture.workspace,
    poolDirectory: fixture.poolDirectory,
    branch,
    leaseId: state.entry.lease_id,
    leaseHolder: state.entry.lease_holder,
    leasedAt: state.entry.leased_at,
    baseBranch,
    stateSha256: crypto.createHash("sha256").update(state.stateBytes).digest("hex"),
    keySha256: crypto.createHash("sha256").update(state.key).digest("hex"),
    eventId: event.id,
    eventSha256: crypto.createHash("sha256").update(JSON.stringify(event)).digest("hex")
  };
  fs.writeFileSync(path.join(fixture.treehouseRoot, ".gate-lease-binding.json"), `${JSON.stringify(value)}\n`, { mode: 0o600 });
  return value;
}

function writePendingGateLeaseBinding(fixture, {
  taskId = "task-1",
  branch = "gate/task-1",
  baseBranch = "main"
} = {}) {
  const taskBindingFile = path.join(fixture.treehouseRoot, ".gate-task-binding.json");
  const task = fs.existsSync(taskBindingFile)
    ? JSON.parse(fs.readFileSync(taskBindingFile, "utf8"))
    : writeTaskBinding(fixture.repository, fixture.treehouseRoot, taskId);
  const value = {
    ...task,
    phase: "pending",
    branch,
    leaseHolder: `gate:${taskId}`,
    requestedBaseBranch: baseBranch
  };
  fs.writeFileSync(
    path.join(fixture.treehouseRoot, ".gate-lease-binding.json"),
    `${JSON.stringify(value)}\n`,
    { mode: 0o600 }
  );
  return value;
}

function repositoryFixture(t, { objectFormat = "sha1" } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-workspace-"));
  const repository = path.join(root, "repository");
  fs.mkdirSync(repository);
  const repositoryIdentity = crypto.createHash("sha256").update(fs.realpathSync(repository)).digest("hex");
  const repositoryRoot = path.join(root, "gate-home", "treehouse", "repos", repositoryIdentity);
  const taskIdentity = crypto.createHash("sha256").update("task-1").digest("hex");
  const treehouseRoot = path.join(repositoryRoot, "tasks", taskIdentity);
  const poolDirectory = path.join(treehouseRoot, ".treehouse", "repository-a1b2c3");
  const workspace = path.join(poolDirectory, "1", "repository");
  const initArgs = ["init", "-q", "-b", "main"];
  if (objectFormat === "sha256") initArgs.splice(1, 0, "--object-format=sha256");
  git(repository, ...initArgs);
  git(repository, "config", "user.name", "GATE Test");
  git(repository, "config", "user.email", "gate-test@example.invalid");
  fs.writeFileSync(path.join(repository, "README.md"), "fixture\n");
  git(repository, "add", "README.md");
  git(repository, "commit", "-q", "-m", "initial");
  writeCloneBinding(repository, repositoryRoot);
  writeTaskBinding(repository, treehouseRoot);
  fs.mkdirSync(path.dirname(workspace), { recursive: true, mode: 0o700 });
  git(repository, "worktree", "add", "-q", "-b", "gate/task-1", workspace, "main");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const fixture = {
    root,
    repository: fs.realpathSync(repository),
    workspace: fs.realpathSync(workspace),
    repositoryRoot,
    treehouseRoot,
    poolDirectory,
    paths: {
      repo: sourceRepo,
      home: path.join(root, "gate-home"),
      events: path.join(root, "gate-home", "events.jsonl")
    }
  };
  const state = writeTreehouseState(fixture);
  writeGateLeaseBinding(fixture, state);
  return fixture;
}

function freshLeaseFixture(t, options = {}) {
  const fixture = repositoryFixture(t, options);
  git(fixture.repository, "worktree", "remove", "--force", fixture.workspace);
  git(fixture.repository, "branch", "-D", "gate/task-1");
  fs.rmSync(fixture.treehouseRoot, { recursive: true, force: true });
  return fixture;
}

function forgeCommitGraphParent(graphFile, parent, forgedParent, descendant) {
  const graph = fs.readFileSync(graphFile);
  assert.equal(graph.subarray(0, 4).toString("ascii"), "CGPH");
  assert.equal(graph[4], 1, "commit-graph version");
  assert.equal(graph[5], 1, "SHA-1 commit-graph fixture");
  assert.equal(graph[7], 0, "unsplit commit-graph fixture");
  const chunks = new Map();
  let tableOffset = 8;
  for (let index = 0; index <= graph[6]; index += 1) {
    const id = graph.subarray(tableOffset, tableOffset + 4).toString("ascii");
    chunks.set(id, Number(graph.readBigUInt64BE(tableOffset + 4)));
    tableOffset += 12;
  }
  assert.equal(chunks.has("GDA2"), false, "fixture must use topology-only commit generations");
  assert.equal(chunks.has("GDO2"), false, "fixture must not use corrected-date overflow storage");
  const fanout = chunks.get("OIDF");
  const lookup = chunks.get("OIDL");
  const commitData = chunks.get("CDAT");
  assert.ok(Number.isSafeInteger(fanout) && Number.isSafeInteger(lookup) && Number.isSafeInteger(commitData));
  const count = graph.readUInt32BE(fanout + (255 * 4));
  const objectIds = Array.from({ length: count }, (_, index) => {
    return graph.subarray(lookup + (index * 20), lookup + ((index + 1) * 20)).toString("hex");
  });
  const parentPosition = objectIds.indexOf(parent);
  const forgedPosition = objectIds.indexOf(forgedParent);
  const descendantPosition = objectIds.indexOf(descendant);
  assert.notEqual(parentPosition, -1);
  assert.notEqual(forgedPosition, -1);
  assert.notEqual(descendantPosition, -1);
  const record = commitData + (parentPosition * 36);
  graph.writeUInt32BE(forgedPosition, record + 20);
  graph.writeUInt32BE(0x70000000, record + 24);
  const setGeneration = (position, generation) => {
    const generationRecord = commitData + (position * 36);
    const generationAndTime = graph.readUInt32BE(generationRecord + 28);
    graph.writeUInt32BE((generation << 2) | (generationAndTime & 3), generationRecord + 28);
  };
  setGeneration(parentPosition, 2);
  setGeneration(descendantPosition, 3);
  crypto.createHash("sha1").update(graph.subarray(0, -20)).digest().copy(graph, graph.length - 20);
  fs.chmodSync(graphFile, 0o600);
  fs.writeFileSync(graphFile, graph, { mode: 0o600 });
}

function forgeLooseCommitParent(repository, commit, forgedParent) {
  const body = execFileSync("git", ["cat-file", "commit", commit], { cwd: repository });
  const firstLine = body.indexOf(0x0a);
  assert.notEqual(firstLine, -1, "commit body must contain a tree header");
  const forged = Buffer.concat([
    body.subarray(0, firstLine + 1),
    Buffer.from(`parent ${forgedParent}\n`, "ascii"),
    body.subarray(firstLine + 1)
  ]);
  const raw = Buffer.concat([Buffer.from(`commit ${forged.length}\0`, "ascii"), forged]);
  const objectPath = path.join(repository, ".git", "objects", commit.slice(0, 2), commit.slice(2));
  fs.chmodSync(objectPath, 0o600);
  fs.writeFileSync(objectPath, zlib.deflateSync(raw), { mode: 0o600 });
}

function forgeIndexStat(indexFile, targetFile) {
  const index = fs.readFileSync(indexFile);
  assert.equal(index.subarray(0, 4).toString("ascii"), "DIRC");
  assert.equal(index.readUInt32BE(8), 1, "fixture index entry count");
  const stat = fs.statSync(targetFile, { bigint: true });
  const seconds = (nanoseconds) => Number((nanoseconds / 1_000_000_000n) & 0xffffffffn);
  const nanos = (nanoseconds) => Number(nanoseconds % 1_000_000_000n);
  const oldMode = index.readUInt32BE(36);
  const values = [
    seconds(stat.ctimeNs), nanos(stat.ctimeNs),
    seconds(stat.mtimeNs), nanos(stat.mtimeNs),
    Number(stat.dev & 0xffffffffn), Number(stat.ino & 0xffffffffn), oldMode,
    Number(stat.uid & 0xffffffffn), Number(stat.gid & 0xffffffffn), Number(stat.size & 0xffffffffn)
  ];
  values.forEach((value, offset) => index.writeUInt32BE(value, 12 + (offset * 4)));
  crypto.createHash("sha1").update(index.subarray(0, -20)).digest().copy(index, index.length - 20);
  fs.chmodSync(indexFile, 0o600);
  fs.writeFileSync(indexFile, index, { mode: 0o600 });
}

function mountInfoPath(value) {
  return value.replace(/\\/gu, "\\134").replace(/ /gu, "\\040").replace(/\t/gu, "\\011").replace(/\n/gu, "\\012");
}

function rawStatus(state) {
  if (state.destroyed) return [];
  if (!fs.existsSync(state.workspace) && !state.returned) return [];
  const status = state.returned ? "available" : state.status || "leased";
  const leased = status === "leased" || status === "in-use" || status === "you're here";
  return [{
    name: "1",
    path: state.workspace,
    status,
    branch: leased ? "gate/task-1" : "",
    detached: !leased,
    flavor: "git",
    lease_id: leased ? state.statusLeaseId || LEASE_ID : "",
    lease_holder: leased ? state.statusHolder || "gate:task-1" : "",
    leased_at: leased ? LEASED_AT : null,
    processes: state.processes || []
  }];
}

function harness(fixture, overrides = {}) {
  const calls = [];
  const events = [];
  const executable = path.join(fixture.root, process.platform === "win32" ? "treehouse.exe" : "treehouse");
  const state = {
    workspace: fixture.workspace,
    destroyed: false,
    returned: false,
    ...overrides.state
  };
  if (fs.existsSync(fixture.workspace) && (state.statusLeaseId || state.statusHolder)) {
    writeTreehouseState(fixture, {
      entry: {
        lease_id: state.statusLeaseId || LEASE_ID,
        lease_holder: state.statusHolder || "gate:task-1"
      }
    });
  }
  const options = {
    paths: fixture.paths,
    env: {
      ...process.env,
      BASH_ENV: path.join(fixture.repository, "malicious-bash-env"),
      DYLD_INSERT_LIBRARIES: path.join(fixture.repository, "malicious.dylib"),
      GATE_ENV_CANARY: "must-not-reach-children",
      GCONV_PATH: fixture.repository,
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "core.hooksPath",
      GIT_CONFIG_VALUE_0: path.join(fixture.repository, "hooks"),
      LD_LIBRARY_PATH: fixture.repository,
      LD_PRELOAD: path.join(fixture.repository, "malicious.so"),
      NODE_OPTIONS: `--require=${path.join(fixture.repository, "malicious.cjs")}`,
      TREEHOUSE_APFS_SHARING: "fresh",
      TREEHOUSE_LEASE_HOLDER: "untrusted-environment-holder",
      TREEHOUSE_ROOT: fixture.repository,
      TREEHOUSE_WORKTREE_PATH: "{repo_parent}/{repo}-{slot}"
    },
    recordEvent(input, eventOptions) {
      events.push({ input: structuredClone(input), options: eventOptions });
      return input;
    },
    workspaceProcesses() {
      return state.processes || [];
    },
    readUpstreamStatus(input) {
      calls.push({ kind: "upstream-status", input });
      return overrides.upstreams || [{
        id: "treehouse",
        version: "3.1.3",
        integrityState: "verified",
        ready: true
      }];
    },
    resolveUpstreamBinary(id, name, input) {
      calls.push({ kind: "resolve", id, name, input });
      if (overrides.resolveError) throw overrides.resolveError;
      return { id: "treehouse", name: "treehouse", executable };
    },
    runner(command, args, invocation) {
      for (const name of [
        "BASH_ENV", "DYLD_INSERT_LIBRARIES", "GATE_ENV_CANARY", "GCONV_PATH",
        "LD_LIBRARY_PATH", "LD_PRELOAD", "NODE_OPTIONS"
      ]) assert.equal(invocation.env[name], undefined, `${name} reached a workspace subprocess`);
      if (command !== executable) {
        calls.push({ kind: "git", command, args: [...args], invocation });
        const result = spawnSync(command, args, invocation);
        if (overrides.afterGit) overrides.afterGit(result, args, invocation, fixture, calls);
        return result;
      }
      calls.push({ kind: "treehouse", command, args: [...args], invocation });
      assert.equal(command, executable);
      if (args[0] === "get") {
        if (!fs.existsSync(fixture.workspace)) {
          fs.mkdirSync(path.dirname(fixture.workspace), { recursive: true, mode: 0o700 });
          git(fixture.repository, "worktree", "add", "-q", "-b", "gate/task-1", fixture.workspace, "main");
        }
        const lease = overrides.lease || {
          path: fixture.workspace,
          lease_id: LEASE_ID,
          lease_holder: "gate:task-1",
          leased_at: LEASED_AT,
          base_branch: "main"
        };
        writeTreehouseState(fixture, {
          entry: {
            lease_id: state.statusLeaseId || lease.lease_id,
            lease_holder: state.statusHolder || lease.lease_holder,
            leased_at: lease.leased_at,
            base_branch: lease.base_branch
          }
        });
        if (overrides.afterGet) overrides.afterGet(state, fixture);
        return { status: 0, stdout: `${JSON.stringify(lease)}\n`, stderr: "lease banner\n" };
      }
      if (args[0] === "status") {
        const status = overrides.statusOutput ? overrides.statusOutput(state, invocation) : rawStatus(state);
        return { status: 0, stdout: `${JSON.stringify(status)}\n`, stderr: "" };
      }
      if (args[0] === "return") {
        if (overrides.returnFailure) return { status: 3, stdout: "", stderr: overrides.returnFailure };
        state.returned = true;
        if (overrides.afterReturn) overrides.afterReturn(state, fixture);
        return { status: 0, stdout: "", stderr: "returned\n" };
      }
      if (args[0] === "destroy") {
        if (overrides.destroyFailure) return { status: 3, stdout: "", stderr: overrides.destroyFailure };
        if (fs.existsSync(fixture.workspace)) {
          git(fixture.repository, "worktree", "remove", "--force", fixture.workspace);
        }
        state.destroyed = true;
        return { status: 0, stdout: "", stderr: "destroyed\n" };
      }
      return { status: 2, stdout: "", stderr: `unexpected command: ${args.join(" ")}` };
    }
  };
  return { calls, events, executable, options, state };
}

function treehouseCalls(harnessValue, verb = null) {
  return harnessValue.calls.filter((call) => call.kind === "treehouse" && (!verb || call.args[0] === verb));
}

test("leaseWorkspace runs only the verified Treehouse JSON lease contract", (t) => {
  const fixture = freshLeaseFixture(t);
  const fake = harness(fixture);
  const result = leaseWorkspace({
    repository: fixture.repository,
    taskId: "task-1",
    branch: "gate/task-1",
    baseBranch: "main"
  }, fake.options);

  assert.equal(result.provider, "treehouse");
  assert.equal(result.version, "3.1.3");
  assert.equal(result.integrityState, "verified");
  assert.equal(result.path, fixture.workspace);
  assert.equal(result.leaseId, LEASE_ID);
  assert.equal(result.leaseHolder, "gate:task-1");
  assert.equal(result.baseBranch, "main");
  assert.deepEqual(fake.calls.slice(0, 2).map((call) => call.kind), ["upstream-status", "resolve"]);

  const commands = treehouseCalls(fake);
  assert.deepEqual(commands.map((call) => call.args), [
    [
      "get", "--lease", "--json", "--no-fetch", "--branch", "gate/task-1",
      "--lease-holder", "gate:task-1", "--base", "main"
    ]
  ]);
  for (const command of commands) {
    assert.equal(command.invocation.cwd, fixture.repository);
    assert.equal(command.invocation.shell, false);
    assert.equal(command.invocation.env.TREEHOUSE_NO_UPDATE_CHECK, "1");
    assert.equal(command.invocation.env.TREEHOUSE_ROOT, fixture.treehouseRoot);
    assert.equal(command.invocation.env.TREEHOUSE_LEASE_HOLDER, undefined);
    assert.equal(command.invocation.env.TREEHOUSE_WORKTREE_PATH, "{pool}/{slot}/{repo}");
    assert.equal(command.invocation.env.TREEHOUSE_APFS_SHARING, "off");
    assert.equal(command.invocation.env.TREEHOUSE_VCS, "git");
    assert.equal(command.invocation.env.TREEHOUSE_MAX_TREES, undefined);
    assert.equal(command.invocation.env.GIT_ALLOW_PROTOCOL, "");
    assert.equal(command.invocation.env.GIT_NO_LAZY_FETCH, "1");
    const configCount = Number(command.invocation.env.GIT_CONFIG_COUNT);
    const protections = Object.fromEntries(Array.from({ length: configCount }, (_, index) => [
      command.invocation.env[`GIT_CONFIG_KEY_${index}`],
      command.invocation.env[`GIT_CONFIG_VALUE_${index}`]
    ]));
    assert.equal(protections["core.hooksPath"], process.platform === "win32" ? "NUL" : "/dev/null");
    assert.equal(protections["core.commitGraph"], "false");
    assert.equal(protections["core.trustctime"], "true");
    assert.equal(protections["core.checkStat"], "default");
    assert.equal(protections["core.ignoreStat"], "false");
    assert.equal(protections["protocol.allow"], "never");
    if (process.platform !== "win32") {
      assert.equal(protections["core.fileMode"], "true");
      assert.equal(protections["core.symlinks"], "true");
    }
    assert.equal(command.invocation.stdio[0], "ignore");
  }
  if (process.platform !== "win32") {
    assert.equal(fs.statSync(path.join(fixture.paths.home, "treehouse")).mode & 0o777, 0o700);
  }
  assert.equal(fake.events.length, 1);
  assert.equal(fake.events[0].input.kind, "workspace.leased");
  assert.equal(fake.events[0].input.effect.class, "host-write");
  assert.equal(fake.events[0].input.summary, "Treehouse workspace lease was acquired.");
  assert.equal(fake.events[0].input.effect.targetRef, `private://workspaces/${LEASE_ID}`);
  assert.equal(JSON.stringify(fake.events[0]).includes(fixture.workspace), false);
  const readyBinding = JSON.parse(fs.readFileSync(
    path.join(fixture.treehouseRoot, ".gate-lease-binding.json"),
    "utf8"
  ));
  assert.equal(readyBinding.phase, "complete");
  assert.equal(readyBinding.eventId, fake.events[0].input.id);
  assert.equal(
    readyBinding.eventSha256,
    crypto.createHash("sha256").update(JSON.stringify(fake.events[0].input)).digest("hex")
  );
});

test("leaseWorkspace persists a sanitized private event through the real recorder", (t) => {
  const fixture = freshLeaseFixture(t);
  const fake = harness(fixture);
  delete fake.options.recordEvent;
  leaseWorkspace({
    repository: fixture.repository,
    taskId: "task-1",
    branch: "gate/task-1",
    baseBranch: "main"
  }, fake.options);

  const events = fs.readFileSync(fixture.paths.events, "utf8").trim().split("\n").map(JSON.parse);
  assert.equal(events.length, 1);
  assert.equal(events[0].kind, "workspace.leased");
  assert.equal(events[0].summary, "Treehouse workspace lease was acquired.");
  assert.equal(events[0].taskId, "task-1");
  assert.equal(events[0].effect.targetRef, `private://workspaces/${LEASE_ID}`);
  assert.equal(JSON.stringify(events[0]).includes(fixture.workspace), false);
  assert.equal(JSON.stringify(events[0]).includes(fixture.repository), false);
});

test("lease readiness remains unverified until event and atomic binding publication succeed", async (t) => {
  await t.test("event append failure", (t) => {
    const fixture = freshLeaseFixture(t);
    const fake = harness(fixture);
    fake.options.recordEvent = () => {
      throw new Error("injected durable event failure");
    };

    assert.throws(
      () => leaseWorkspace({
        repository: fixture.repository,
        taskId: "task-1",
        branch: "gate/task-1",
        baseBranch: "main"
      }, fake.options),
      /injected durable event failure/
    );
    const binding = JSON.parse(fs.readFileSync(path.join(fixture.treehouseRoot, ".gate-lease-binding.json"), "utf8"));
    assert.equal(binding.phase, "pending");
    const status = workspaceStatus({ repository: fixture.repository }, harness(fixture).options);
    assert.equal(status.workspaces[0].status, "unverified");
    assert.equal(status.workspaces[0].phase, "unbound");
  });

  await t.test("interruption after durable event", (t) => {
    const fixture = freshLeaseFixture(t);
    const fake = harness(fixture);
    fake.options.beforeLeaseReadyPublish = () => {
      throw new Error("injected final binding publication fault");
    };

    assert.throws(
      () => leaseWorkspace({
        repository: fixture.repository,
        taskId: "task-1",
        branch: "gate/task-1",
        baseBranch: "main"
      }, fake.options),
      /injected final binding publication fault/
    );
    assert.equal(fake.events.length, 1, "durable event must precede readiness publication");
    const binding = JSON.parse(fs.readFileSync(path.join(fixture.treehouseRoot, ".gate-lease-binding.json"), "utf8"));
    assert.equal(binding.phase, "pending");
    const status = workspaceStatus({ repository: fixture.repository }, harness(fixture).options);
    assert.equal(status.workspaces[0].status, "unverified");
    assert.equal(status.workspaces[0].phase, "unbound");
  });
});

test("Treehouse cannot inherit a repository-controlled Git from PATH", (t) => {
  const fixture = freshLeaseFixture(t);
  const fakeBin = path.join(fixture.repository, "fake-bin");
  const marker = path.join(fixture.root, "fake-git-ran");
  fs.mkdirSync(fakeBin);
  const fakeGit = path.join(fakeBin, process.platform === "win32" ? "git.exe" : "git");
  fs.writeFileSync(fakeGit, `#!/bin/sh\nprintf bad > ${JSON.stringify(marker)}\n`);
  if (process.platform !== "win32") fs.chmodSync(fakeGit, 0o755);
  const fake = harness(fixture);
  fake.options.env.PATH = `${fakeBin}${path.delimiter}${process.env.PATH || ""}`;

  leaseWorkspace({
    repository: fixture.repository,
    taskId: "task-1",
    branch: "gate/task-1",
    baseBranch: "main"
  }, fake.options);

  for (const call of treehouseCalls(fake)) {
    assert.equal(call.invocation.env.PATH.split(path.delimiter).some((entry) => entry === fakeBin), false);
  }
  assert.equal(fs.existsSync(marker), false);
});

test("workspace operations never select Git from caller PATH", (t) => {
  if (process.platform === "win32") return t.skip("native Windows requires an explicitly configured trusted Git executable");
  const fixture = repositoryFixture(t);
  const fakeBin = path.join(fixture.root, "caller-bin");
  const marker = path.join(fixture.root, "caller-git-ran");
  fs.mkdirSync(fakeBin, { mode: 0o700 });
  const fakeGit = path.join(fakeBin, "git");
  fs.writeFileSync(fakeGit, `#!/bin/sh\nprintf bad > ${JSON.stringify(marker)}\n`, { mode: 0o700 });
  const fake = harness(fixture);
  fake.options.env.PATH = `${fakeBin}${path.delimiter}${process.env.PATH || ""}`;

  workspaceStatus({ repository: fixture.repository }, fake.options);

  assert.equal(fs.existsSync(marker), false);
  assert.equal(fake.calls.filter((call) => call.kind === "git").some((call) => call.command === fakeGit), false);
  for (const call of treehouseCalls(fake)) {
    assert.equal(call.invocation.env.PATH.split(path.delimiter).includes(fakeBin), false);
  }
});

test("workspace subprocesses receive a minimal environment", (t) => {
  const fixture = freshLeaseFixture(t);
  const fake = harness(fixture);
  leaseWorkspace({
    repository: fixture.repository,
    taskId: "task-1",
    branch: "gate/task-1",
    baseBranch: "main"
  }, fake.options);

  const invocation = treehouseCalls(fake, "get")[0].invocation;
  assert.ok(invocation.env.HOME.startsWith(path.join(fixture.repositoryRoot, "tmp", "operation-")));
  assert.equal(invocation.env.XDG_CONFIG_HOME, path.join(invocation.env.HOME, ".config"));
  assert.equal(fs.existsSync(invocation.env.HOME), false, "ephemeral child home must be removed after the operation");
  assert.equal(invocation.env.TREEHOUSE_ROOT, fixture.treehouseRoot);
  assert.equal(invocation.env.TREEHOUSE_NO_UPDATE_CHECK, "1");
  assert.equal(invocation.env.GATE_ENV_CANARY, undefined);
  assert.deepEqual(
    Object.keys(invocation.env).filter((name) => /^(?:LD_|DYLD_)|^(?:GCONV_PATH|BASH_ENV|NODE_OPTIONS)$/u.test(name)),
    []
  );
});

test("workspace operations reject a Treehouse root that upstream would environment-expand", (t) => {
  const fixture = freshLeaseFixture(t);
  const unsafeHome = path.join(fixture.root, "gate-$NO_COLOR-home");
  const fake = harness(fixture);
  fake.options.paths = {
    ...fixture.paths,
    home: unsafeHome,
    events: path.join(unsafeHome, "events.jsonl")
  };

  assert.throws(
    () => leaseWorkspace({
      repository: fixture.repository,
      taskId: "task-1",
      branch: "gate/task-1",
      baseBranch: "main"
    }, fake.options),
    /GATE_HOME cannot contain '\$'.*TREEHOUSE_ROOT/
  );
  assert.equal(treehouseCalls(fake).length, 0);
  assert.equal(fake.calls.some((call) => call.kind === "git"), false);
  assert.equal(fake.events.length, 0);
});

test("workspace operations refuse an unverified upstream before resolving or executing it", (t) => {
  const fixture = repositoryFixture(t);
  const fake = harness(fixture, {
    upstreams: [{ id: "treehouse", version: "3.1.3", integrityState: "receipt-only", ready: true }]
  });
  assert.throws(
    () => workspaceStatus({ repository: fixture.repository }, fake.options),
    /not integrity-verified/
  );
  assert.deepEqual(fake.calls.map((call) => call.kind), ["upstream-status"]);

  const resolverFailure = harness(fixture, { resolveError: new Error("reviewed bytes changed") });
  assert.throws(
    () => workspaceStatus({ repository: fixture.repository }, resolverFailure.options),
    /reviewed bytes changed/
  );
  assert.equal(treehouseCalls(resolverFailure).length, 0);
});

test("leaseWorkspace fails closed when JSON evidence and current status disagree", (t) => {
  const mismatchFixture = freshLeaseFixture(t);
  const fake = harness(mismatchFixture, { state: { statusLeaseId: "f".repeat(32) } });
  assert.throws(
    () => leaseWorkspace({
      repository: mismatchFixture.repository,
      taskId: "task-1",
      branch: "gate/task-1"
    }, fake.options),
    /state lease identity does not match the trusted acquisition receipt/
  );
  assert.deepEqual(treehouseCalls(fake).map((call) => call.args[0]), ["get"]);
  assert.equal(fake.events.length, 0);

  const malformedFixture = freshLeaseFixture(t);
  const malformed = harness(malformedFixture, {
    lease: { path: malformedFixture.workspace, lease_id: "short", lease_holder: "gate:task-1", leased_at: LEASED_AT, base_branch: "main" }
  });
  assert.throws(
    () => leaseWorkspace({
      repository: malformedFixture.repository,
      taskId: "task-1",
      branch: "gate/task-1"
    }, malformed.options),
    /128-bit lowercase hexadecimal/
  );
  assert.deepEqual(treehouseCalls(malformed).map((call) => call.args[0]), ["get"]);
  assert.equal(malformed.events.length, 0);

  const wrongBaseFixture = freshLeaseFixture(t);
  const wrongBase = harness(wrongBaseFixture, {
    lease: {
      path: wrongBaseFixture.workspace,
      lease_id: LEASE_ID,
      lease_holder: "gate:task-1",
      leased_at: LEASED_AT,
      base_branch: "develop"
    }
  });
  assert.throws(
    () => leaseWorkspace({
      repository: wrongBaseFixture.repository,
      taskId: "task-1",
      branch: "gate/task-1",
      baseBranch: "main"
    }, wrongBase.options),
    /different workspace base branch/
  );
  assert.equal(wrongBase.events.length, 0);

  const invalidBaseFixture = freshLeaseFixture(t);
  const invalidBase = harness(invalidBaseFixture, {
    lease: {
      path: invalidBaseFixture.workspace,
      lease_id: LEASE_ID,
      lease_holder: "gate:task-1",
      leased_at: LEASED_AT,
      base_branch: "bad..ref"
    }
  });
  assert.throws(
    () => leaseWorkspace({
      repository: invalidBaseFixture.repository,
      taskId: "task-1",
      branch: "gate/task-1"
    }, invalidBase.options),
    /Treehouse base branch is not a supported Git ref/
  );
  const pendingBinding = JSON.parse(fs.readFileSync(
    path.join(invalidBaseFixture.treehouseRoot, ".gate-lease-binding.json"),
    "utf8"
  ));
  assert.equal(pendingBinding.phase, "pending");
  assert.equal(invalidBase.events.length, 0);

  const receiptMismatchFixture = freshLeaseFixture(t);
  const receiptMismatch = harness(receiptMismatchFixture, {
    afterGet() {
      writeTreehouseState(receiptMismatchFixture, { entry: { base_branch: "develop" } });
    }
  });
  assert.throws(
    () => leaseWorkspace({
      repository: receiptMismatchFixture.repository,
      taskId: "task-1",
      branch: "gate/task-1"
    }, receiptMismatch.options),
    /state base branch does not match the trusted acquisition receipt/
  );
  const mismatchBinding = JSON.parse(fs.readFileSync(
    path.join(receiptMismatchFixture.treehouseRoot, ".gate-lease-binding.json"),
    "utf8"
  ));
  assert.equal(mismatchBinding.phase, "pending");
  assert.equal(receiptMismatch.events.length, 0);
});

test("leaseWorkspace leaves a reused slot held when ignored files remain", (t) => {
  const fixture = freshLeaseFixture(t);
  const secret = path.join(fixture.workspace, ".secret");
  const fake = harness(fixture, {
    afterGet() {
      fs.writeFileSync(path.join(fixture.workspace, ".gitignore"), ".secret\n");
      git(fixture.workspace, "add", ".gitignore");
      git(fixture.workspace, "commit", "-q", "-m", "ignore local secret");
      fs.writeFileSync(secret, "TOP SECRET\n");
      assert.equal(git(fixture.workspace, "status", "--porcelain=v1", "--untracked-files=all"), "");
    }
  });

  assert.throws(
    () => leaseWorkspace({
      repository: fixture.repository,
      taskId: "task-1",
      branch: "gate/task-1",
      baseBranch: "main"
    }, fake.options),
    /newly leased Treehouse workspace is not a raw HEAD match.*lease remains held/
  );
  assert.deepEqual(treehouseCalls(fake).map((call) => call.args[0]), ["get"]);
  assert.equal(fake.state.returned, false);
  assert.equal(fake.events.length, 0);
  assert.equal(fs.readFileSync(secret, "utf8"), "TOP SECRET\n");
  const held = workspaceStatus({ repository: fixture.repository }, harness(fixture).options);
  assert.equal(held.workspaces.length, 1);
  assert.equal(held.workspaces[0].status, "unverified");
  assert.equal(held.workspaces[0].phase, "unbound");
  assert.equal(held.workspaces[0].leaseId, LEASE_ID);
});

test("workspaceStatus returns bounded normalized status without invoking Treehouse", (t) => {
  const fixture = repositoryFixture(t);
  const fake = harness(fixture, {
    state: { processes: [{ pid: 1234, name: "codex" }] }
  });
  const result = workspaceStatus({ repository: fixture.repository }, fake.options);
  assert.equal(result.provider, "treehouse");
  assert.equal(result.workspaces.length, 1);
  assert.deepEqual(result.workspaces[0].processes, [{ pid: 1234, name: "codex" }]);
  assert.equal(result.workspaces[0].leaseId, LEASE_ID);
  assert.deepEqual(treehouseCalls(fake).map((call) => call.args), []);
  assert.equal(fake.events.length, 0);

  const corruptFixture = repositoryFixture(t);
  writeTreehouseState(corruptFixture, { state: { version: 3 } });
  const unknown = harness(corruptFixture);
  const corruptStatus = workspaceStatus({ repository: corruptFixture.repository }, unknown.options);
  assert.equal(corruptStatus.workspaces.length, 1);
  assert.equal(corruptStatus.workspaces[0].status, "unverified");
  assert.equal(corruptStatus.workspaces[0].phase, "reconciliation");
  assert.equal(corruptStatus.workspaces[0].path, null);
  assert.equal(corruptStatus.workspaces[0].leaseId, "");
  assert.match(corruptStatus.workspaces[0].recoveryReason, /state must be version 4/);
  assert.equal(treehouseCalls(unknown).length, 0);
});

test("workspaceStatus reports interrupted acquisition phases without invoking Treehouse", async (t) => {
  await t.test("pending before provider state", (t) => {
    const fixture = freshLeaseFixture(t);
    writePendingGateLeaseBinding(fixture);
    const fake = harness(fixture);

    const result = workspaceStatus({ repository: fixture.repository }, fake.options);
    assert.equal(result.workspaces.length, 1);
    assert.equal(result.workspaces[0].taskId, "task-1");
    assert.equal(result.workspaces[0].status, "unverified");
    assert.equal(result.workspaces[0].phase, "pending");
    assert.equal(result.workspaces[0].path, null);
    assert.equal(result.workspaces[0].branch, "");
    assert.match(result.workspaces[0].branchError, /expected branch gate\/task-1.*not verified/);
    assert.match(result.workspaces[0].recoveryReason, /task id remains burned/);
    assert.equal(treehouseCalls(fake).length, 0);
  });

  await t.test("durable provider lease without final GATE binding", (t) => {
    const fixture = repositoryFixture(t);
    writePendingGateLeaseBinding(fixture);
    const fake = harness(fixture);

    const result = workspaceStatus({ repository: fixture.repository }, fake.options);
    assert.equal(result.workspaces.length, 1);
    assert.equal(result.workspaces[0].taskId, "task-1");
    assert.equal(result.workspaces[0].status, "unverified");
    assert.equal(result.workspaces[0].phase, "unbound");
    assert.equal(result.workspaces[0].path, fixture.workspace);
    assert.equal(result.workspaces[0].leaseId, LEASE_ID);
    assert.equal(result.workspaces[0].branch, "");
    assert.match(result.workspaces[0].branchError, /expected branch gate\/task-1.*not verified/);
    assert.match(result.workspaces[0].recoveryReason, /durable lease without a complete immutable GATE receipt/);
    assert.equal(treehouseCalls(fake).length, 0);
  });
});

test("leased workspace paths must stay under the private Treehouse root", (t) => {
  const leaseFixture = freshLeaseFixture(t);
  const outsideLease = harness(leaseFixture, {
    lease: {
      path: leaseFixture.repository,
      lease_id: LEASE_ID,
      lease_holder: "gate:task-1",
      leased_at: LEASED_AT,
      base_branch: "main"
    }
  });
  assert.throws(
    () => leaseWorkspace({
      repository: leaseFixture.repository,
      taskId: "task-1",
      branch: "gate/task-1",
      baseBranch: "main"
    }, outsideLease.options),
    /strict descendant of the private GATE-owned Treehouse root/
  );
  assert.deepEqual(treehouseCalls(outsideLease).map((call) => call.args[0]), ["get"]);
  assert.equal(outsideLease.events.length, 0);

  const fixture = repositoryFixture(t);
  const bindingFile = path.join(fixture.treehouseRoot, ".gate-lease-binding.json");
  const outsideBinding = JSON.parse(fs.readFileSync(bindingFile, "utf8"));
  outsideBinding.workspacePath = fixture.repository;
  fs.writeFileSync(bindingFile, `${JSON.stringify(outsideBinding)}\n`, { mode: 0o600 });
  const outsideStatus = harness(fixture);
  const result = workspaceStatus({ repository: fixture.repository }, outsideStatus.options);
  assert.equal(result.workspaces.length, 1);
  assert.equal(result.workspaces[0].status, "unverified");
  assert.equal(result.workspaces[0].phase, "reconciliation");
  assert.equal(result.workspaces[0].path, null);
  assert.equal(result.workspaces[0].leaseId, "");
  assert.match(result.workspaces[0].recoveryReason, /strict descendant of the private GATE-owned Treehouse root/);
  assert.equal(JSON.stringify(result).includes(fixture.repository), true, "repository identity remains part of the top-level result");
  assert.equal(JSON.stringify(result.workspaces).includes(outsideBinding.workspacePath), false);
  assert.equal(treehouseCalls(outsideStatus).length, 0);
  assert.equal(outsideStatus.events.length, 0);
});

test("verifyWorkspace proves landing while retaining the durable lease", (t) => {
  const fixture = repositoryFixture(t);
  const fake = harness(fixture);
  const result = verifyWorkspace({
    repository: fixture.repository,
    path: fixture.workspace,
    taskId: "task-1",
    leaseId: LEASE_ID,
    landedRef: "main"
  }, fake.options);

  assert.equal(result.verified, true);
  assert.equal(result.returned, false);
  assert.equal(result.retained, true);
  assert.match(result.head, /^[a-f0-9]{40}$/u);
  assert.equal(result.head, result.landedCommit);
  assert.deepEqual(treehouseCalls(fake).map((call) => call.args), []);
  assert.equal(treehouseCalls(fake).flatMap((call) => call.args).includes("--force"), false);
  assert.equal(fake.events.length, 1);
  assert.equal(fake.events[0].input.kind, "workspace.verified");
  assert.equal(fake.events[0].input.summary, "Treehouse workspace landing was verified; its durable lease remains held.");
  assert.equal(fake.events[0].input.effect.targetRef, `private://workspaces/${LEASE_ID}`);
  assert.equal(JSON.stringify(fake.events[0]).includes(fixture.workspace), false);
});

test("verifyWorkspace preserves dirty and unlanded leases", async (t) => {
  await t.test("dirty worktree", (t) => {
    const fixture = repositoryFixture(t);
    fs.writeFileSync(path.join(fixture.workspace, "dirty.txt"), "keep\n");
    const fake = harness(fixture);
    assert.throws(
      () => verifyWorkspace({
        repository: fixture.repository,
        path: fixture.workspace,
        taskId: "task-1",
        leaseId: LEASE_ID,
        landedRef: "main"
      }, fake.options),
      /uncommitted changes.*remain leased/
    );
    assert.equal(treehouseCalls(fake, "return").length, 0);
    assert.equal(fake.state.returned, false);
    assert.equal(fake.events.length, 0);
  });

  await t.test("clean but unlanded commit", (t) => {
    const fixture = repositoryFixture(t);
    fs.writeFileSync(path.join(fixture.workspace, "unlanded.txt"), "keep\n");
    git(fixture.workspace, "add", "unlanded.txt");
    git(fixture.workspace, "commit", "-q", "-m", "unlanded");
    const fake = harness(fixture);
    assert.throws(
      () => verifyWorkspace({
        repository: fixture.repository,
        path: fixture.workspace,
        taskId: "task-1",
        leaseId: LEASE_ID,
        landedRef: "main"
      }, fake.options),
      /has not landed.*remain held/
    );
    assert.equal(treehouseCalls(fake, "return").length, 0);
    assert.equal(fake.state.returned, false);
    assert.equal(fake.events.length, 0);
  });

  for (const flag of ["--assume-unchanged", "--skip-worktree"]) {
    await t.test(`${flag} cannot conceal modified bytes`, (t) => {
      const fixture = repositoryFixture(t);
      git(fixture.workspace, "update-index", flag, "README.md");
      fs.writeFileSync(path.join(fixture.workspace, "README.md"), "concealed change\n");
      const fake = harness(fixture);
      assert.throws(
        () => verifyWorkspace({
          repository: fixture.repository,
          path: fixture.workspace,
          taskId: "task-1",
          leaseId: LEASE_ID,
          landedRef: "main"
        }, fake.options),
        /assume-unchanged or skip-worktree/
      );
      assert.equal(treehouseCalls(fake, "return").length, 0);
      assert.equal(fake.events.length, 0);
    });
  }
});

test("verifyWorkspace preserves a lease that contains ignored files", (t) => {
  const fixture = repositoryFixture(t);
  fs.writeFileSync(path.join(fixture.workspace, ".gitignore"), ".secret\n");
  git(fixture.workspace, "add", ".gitignore");
  git(fixture.workspace, "commit", "-q", "-m", "ignore local secret");
  git(fixture.repository, "merge", "-q", "--ff-only", "gate/task-1");
  const secret = path.join(fixture.workspace, ".secret");
  fs.writeFileSync(secret, "TOP SECRET\n");
  assert.equal(git(fixture.workspace, "status", "--porcelain=v1", "--untracked-files=all"), "");
  const fake = harness(fixture);

  assert.throws(
    () => verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, fake.options),
    /raw, ignored, nested, or uncommitted changes.*remain leased/
  );
  assert.equal(treehouseCalls(fake, "return").length, 0);
  assert.equal(fake.state.returned, false);
  assert.equal(fake.events.length, 0);
  assert.equal(fs.readFileSync(secret, "utf8"), "TOP SECRET\n");
});

test("verifyWorkspace allows Git-confirmed ignored caches only in the main worktree", (t) => {
  const fixture = repositoryFixture(t);
  fs.writeFileSync(path.join(fixture.workspace, ".gitignore"), "node_modules/\n");
  git(fixture.workspace, "add", ".gitignore");
  git(fixture.workspace, "commit", "-q", "-m", "ignore cache");
  git(fixture.repository, "merge", "-q", "--ff-only", "gate/task-1");
  const cache = path.join(fixture.repository, "node_modules", "package", "cache.bin");
  fs.mkdirSync(path.dirname(cache), { recursive: true });
  fs.writeFileSync(cache, "cache\n");
  assert.equal(git(fixture.repository, "status", "--porcelain=v1", "--untracked-files=all"), "");
  const fake = harness(fixture);

  const result = verifyWorkspace({
    repository: fixture.repository,
    path: fixture.workspace,
    taskId: "task-1",
    leaseId: LEASE_ID,
    landedRef: "main"
  }, fake.options);
  assert.equal(result.returned, false);
  assert.equal(result.retained, true);
  assert.equal(fs.readFileSync(cache, "utf8"), "cache\n");
});

test("workspace operations reject executable local filters before they can run", (t) => {
  if (process.platform === "win32") return t.skip("fixture uses a POSIX executable filter canary");
  const fixture = repositoryFixture(t);
  const marker = path.join(fixture.root, "filter-executed");
  const helper = path.join(fixture.root, "clean-filter.sh");
  fs.writeFileSync(helper, `#!/bin/sh\ncat >/dev/null\nprintf 'fixture\\n'\nprintf executed >${JSON.stringify(marker)}\n`);
  fs.chmodSync(helper, 0o700);
  fs.mkdirSync(path.join(fixture.repository, ".git", "info"), { recursive: true });
  fs.writeFileSync(path.join(fixture.repository, ".git", "info", "attributes"), "README.md filter=gate-hide\n");
  git(fixture.repository, "config", "filter.gate-hide.clean", helper);
  fs.writeFileSync(path.join(fixture.workspace, "README.md"), "evil\n");
  const fake = harness(fixture);
  assert.equal(fs.existsSync(marker), false, "filter marker precondition");
  const baseRunner = fake.options.runner;
  fake.options.runner = (command, args, invocation) => {
    const existed = fs.existsSync(marker);
    const result = baseRunner(command, args, invocation);
    if (!existed && fs.existsSync(marker)) {
      throw new Error(`repository filter executed in ${invocation.cwd} with GIT_CONFIG=${invocation.env.GIT_CONFIG}: ${args.join(" ")}`);
    }
    return result;
  };

  assert.throws(
    () => verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, fake.options),
    /repository-local Git configuration can execute a command \(filter\.gate-hide\.clean\)/
  );
  assert.equal(fs.existsSync(marker), false, "repository clean filter must not execute");
  assert.equal(treehouseCalls(fake, "return").length, 0);
});

test("workspace status rejects command-capable per-worktree configuration", (t) => {
  const fixture = repositoryFixture(t);
  git(fixture.repository, "config", "extensions.worktreeConfig", "true");
  git(fixture.workspace, "config", "--worktree", "filter.worktree-canary.clean", "dangerous-helper");
  const fake = harness(fixture);

  assert.throws(
    () => workspaceStatus({ repository: fixture.repository }, fake.options),
    /repository-local Git configuration can execute a command \(filter\.worktree-canary\.clean\)/
  );
  assert.equal(treehouseCalls(fake).length, 0);
});

test("workspace operations block promisor remote helpers before Treehouse can execute them", (t) => {
  if (process.platform === "win32") return t.skip("fixture uses a POSIX executable remote helper canary");
  const fixture = repositoryFixture(t);
  const marker = path.join(fixture.root, "remote-helper-ran");
  const helper = path.join(fixture.root, "remote-helper.sh");
  fs.writeFileSync(helper, `#!/bin/sh\nprintf executed > ${JSON.stringify(marker)}\n`, { mode: 0o700 });
  git(fixture.repository, "config", "remote.origin.vcs", "ext");
  git(fixture.repository, "config", "remote.origin.url", helper);
  git(fixture.repository, "config", "remote.origin.promisor", "true");
  const fake = harness(fixture);

  assert.throws(
    () => workspaceStatus({ repository: fixture.repository }, fake.options),
    /repository-local Git configuration can execute a command \(remote\.origin\.vcs\)/
  );
  assert.equal(fs.existsSync(marker), false);
  assert.equal(treehouseCalls(fake).length, 0);
});

test("workspace operations reject generic and protocol-specific transport overrides", async (t) => {
  for (const name of ["protocol.allow", "protocol.ext.allow", "protocol.custom.allow"]) {
    await t.test(name, (t) => {
      const fixture = repositoryFixture(t);
      git(fixture.repository, "config", name, "always");
      const fake = harness(fixture);
      assert.throws(
        () => workspaceStatus({ repository: fixture.repository }, fake.options),
        new RegExp(`can execute a command \\(${name.replaceAll(".", "\\.")}\\)`)
      );
      assert.equal(treehouseCalls(fake).length, 0);
    });
  }
});

test("verifyWorkspace rejects grafted ancestry", (t) => {
  const fixture = repositoryFixture(t);
  fs.writeFileSync(path.join(fixture.workspace, "unlanded.txt"), "preserve\n");
  git(fixture.workspace, "add", "unlanded.txt");
  git(fixture.workspace, "commit", "-q", "-m", "unlanded");
  const workspaceHead = git(fixture.workspace, "rev-parse", "HEAD");
  const mainHead = git(fixture.repository, "rev-parse", "HEAD");
  const info = path.join(fixture.repository, ".git", "info");
  fs.mkdirSync(info, { recursive: true });
  fs.writeFileSync(path.join(info, "grafts"), `${mainHead} ${workspaceHead}\n`);
  const fake = harness(fixture);

  assert.throws(
    () => verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, fake.options),
    /Git grafts are incompatible/
  );
  assert.equal(treehouseCalls(fake, "return").length, 0);
});

test("verifyWorkspace ignores a checksum-valid forged commit graph", (t) => {
  const fixture = repositoryFixture(t);
  const parent = git(fixture.repository, "rev-parse", "HEAD");
  fs.writeFileSync(path.join(fixture.repository, "main-tip.txt"), "main\n");
  git(fixture.repository, "add", "main-tip.txt");
  git(fixture.repository, "commit", "-q", "-m", "main tip");
  const landedTip = git(fixture.repository, "rev-parse", "HEAD");

  git(fixture.workspace, "switch", "-q", "--orphan", "unrelated");
  git(fixture.workspace, "rm", "-q", "-r", "--ignore-unmatch", ".");
  fs.writeFileSync(path.join(fixture.workspace, "workspace-only.txt"), "unrelated\n");
  git(fixture.workspace, "add", "workspace-only.txt");
  git(fixture.workspace, "commit", "-q", "-m", "unrelated workspace head");
  const workspaceHead = git(fixture.workspace, "rev-parse", "HEAD");
  git(fixture.workspace, "branch", "-f", "gate/task-1", workspaceHead);
  git(fixture.workspace, "switch", "-q", "gate/task-1");

  assert.equal(gitResult(
    fixture.repository,
    "-c", "core.commitGraph=true", "merge-base", "--is-ancestor", workspaceHead, landedTip
  ).status, 1, "unrelated history precondition");
  git(fixture.repository, "-c", "commitGraph.generationVersion=1", "commit-graph", "write", "--reachable");
  const graphFile = path.join(fixture.repository, ".git", "objects", "info", "commit-graph");
  forgeCommitGraphParent(graphFile, parent, workspaceHead, landedTip);
  assert.equal(gitResult(
    fixture.repository,
    "-c", "core.commitGraph=true", "merge-base", "--is-ancestor", workspaceHead, landedTip
  ).status, 0, "forged commit graph must fool an unprotected ancestry check");
  assert.notEqual(
    gitResult(fixture.repository, "commit-graph", "verify").status,
    0,
    "forged graph must disagree with commit objects"
  );
  assert.equal(gitResult(
    fixture.repository,
    "-c", "core.commitGraph=false", "merge-base", "--is-ancestor", workspaceHead, landedTip
  ).status, 1, "protected ancestry must read commit objects");

  const fake = harness(fixture);
  assert.throws(
    () => verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, fake.options),
    /has not landed.*remain held/
  );
  assert.equal(treehouseCalls(fake, "return").length, 0);
  assert.equal(fake.state.returned, false);
  assert.equal(fake.events.length, 0);
});

test("workspace operations reject known command-capable aliases without executing them", (t) => {
  if (process.platform === "win32") return t.skip("fixture uses a POSIX command canary");
  const fixture = repositoryFixture(t);
  const marker = path.join(fixture.root, "alias-executed");
  git(fixture.repository, "config", "alias.innocent", `!sh -c 'printf ran >${marker}'`);
  const fake = harness(fixture);
  assert.throws(
    () => workspaceStatus({ repository: fixture.repository }, fake.options),
    /can execute a command \(alias\.innocent\)/
  );
  assert.equal(treehouseCalls(fake).length, 0);
  assert.equal(fs.existsSync(marker), false);
});

test("workspace config allowlist rejects reviewed command selectors and unknown keys", async (t) => {
  const commandSelectors = [
    ["diff.external", "dangerous-helper"],
    ["rebase.instructionFormat", "%s%x0aexec dangerous-helper"],
    ["gpg.ssh.defaultKeyCommand", "dangerous-helper"],
    ["diff.tool", "../../dangerous-helper"],
    ["merge.guitool", "../../dangerous-helper"],
    ["instaweb.port", "1234; dangerous-helper"],
    ["mergetool.vimdiff.layout", "dangerous-helper()"],
    ["branch.main.mergeOptions", "-s dangerous-helper"],
    ["pull.twohead", "dangerous-helper"]
  ];
  for (const [name, value] of commandSelectors) {
    await t.test(name, (t) => {
      const fixture = repositoryFixture(t);
      git(fixture.repository, "config", name, value);
      const fake = harness(fixture);
      assert.throws(
        () => workspaceStatus({ repository: fixture.repository }, fake.options),
        new RegExp(`can execute a command \\(${name.toLowerCase().replaceAll(".", "\\.")}\\)`)
      );
      assert.equal(treehouseCalls(fake).length, 0);
      assert.equal(fake.events.length, 0);
    });
  }

  await t.test("unknown future key", (t) => {
    const fixture = repositoryFixture(t);
    git(fixture.repository, "config", "future.workspaceSetting", "value");
    const fake = harness(fixture);
    assert.throws(
      () => workspaceStatus({ repository: fixture.repository }, fake.options),
      /outside the reviewed workspace allowlist \(future\.workspacesetting\)/
    );
    assert.equal(treehouseCalls(fake).length, 0);
  });
});

test("verifyWorkspace detects an executable hook persisted in the shared Git directory", (t) => {
  if (process.platform === "win32") return t.skip("fixture uses POSIX executable-mode semantics");
  const fixture = repositoryFixture(t);
  const hook = path.join(fixture.repository, ".git", "hooks", "post-checkout");
  fs.writeFileSync(hook, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
  const fake = harness(fixture);
  assert.throws(
    () => verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, fake.options),
    /shared Git hook surface is unsafe \(post-checkout\)/
  );
  assert.equal(treehouseCalls(fake).length, 0);
  assert.equal(fake.events.length, 0);
});

test("verifyWorkspace pins the linked-worktree marker to its unique registered admin directory", (t) => {
  const fixture = repositoryFixture(t);
  const registered = git(fixture.workspace, "rev-parse", "--path-format=absolute", "--absolute-git-dir");
  const forged = path.join(fixture.root, "forged-worktree-admin");
  fs.cpSync(registered, forged, { recursive: true });
  fs.writeFileSync(path.join(forged, "commondir"), `${path.join(fixture.repository, ".git")}\n`);
  fs.writeFileSync(path.join(forged, "gitdir"), `${path.join(fixture.workspace, ".git")}\n`);
  fs.writeFileSync(path.join(fixture.workspace, ".git"), `gitdir: ${forged}\n`);
  const fake = harness(fixture);

  assert.throws(
    () => verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, fake.options),
    /administrative directory is not a direct registered entry/
  );
  assert.equal(treehouseCalls(fake).length, 0);
  assert.equal(fake.events.length, 0);
});

test("workspace operations reject repository-local commit-graph overrides", (t) => {
  const fixture = repositoryFixture(t);
  git(fixture.repository, "config", "core.commitGraph", "true");
  const fake = harness(fixture);
  assert.throws(
    () => workspaceStatus({ repository: fixture.repository }, fake.options),
    /redirect repository behavior \(core\.commitgraph\)/
  );
  assert.equal(treehouseCalls(fake).length, 0);
});

test("verifyWorkspace rejects ancestry forged through a hash-mismatched loose object", (t) => {
  const fixture = repositoryFixture(t);
  const parent = git(fixture.repository, "rev-parse", "HEAD");
  fs.writeFileSync(path.join(fixture.repository, "main-tip.txt"), "main\n");
  git(fixture.repository, "add", "main-tip.txt");
  git(fixture.repository, "commit", "-q", "-m", "main tip");
  const landedTip = git(fixture.repository, "rev-parse", "HEAD");

  git(fixture.workspace, "switch", "-q", "--orphan", "unrelated");
  git(fixture.workspace, "rm", "-q", "-r", "--ignore-unmatch", ".");
  fs.writeFileSync(path.join(fixture.workspace, "workspace-only.txt"), "unrelated\n");
  git(fixture.workspace, "add", "workspace-only.txt");
  git(fixture.workspace, "commit", "-q", "-m", "unrelated workspace head");
  const workspaceHead = git(fixture.workspace, "rev-parse", "HEAD");
  git(fixture.workspace, "branch", "-f", "gate/task-1", workspaceHead);
  git(fixture.workspace, "switch", "-q", "gate/task-1");

  assert.equal(
    gitResult(fixture.repository, "-c", "core.commitGraph=false", "merge-base", "--is-ancestor", workspaceHead, landedTip).status,
    1,
    "unrelated history precondition"
  );
  forgeLooseCommitParent(fixture.repository, parent, workspaceHead);
  assert.equal(
    gitResult(fixture.repository, "-c", "core.commitGraph=false", "merge-base", "--is-ancestor", workspaceHead, landedTip).status,
    0,
    "forged commit body must fool an ancestry check that does not authenticate objects"
  );
  assert.notEqual(
    gitResult(fixture.repository, "fsck", "--full", "--strict", "--no-reflogs", "--no-dangling", "--no-progress").status,
    0,
    "full fsck must detect the object-id/body mismatch"
  );

  const fake = harness(fixture);
  assert.throws(
    () => verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, fake.options),
    /Git fsck failed/
  );
  assert.equal(treehouseCalls(fake, "return").length, 0);
  assert.equal(fake.state.returned, false);
  assert.equal(fake.events.length, 0);
});

test("repository-local fsck controls cannot suppress forged-object rejection", (t) => {
  const fixture = repositoryFixture(t);
  const parent = git(fixture.repository, "rev-parse", "HEAD");
  const skipList = path.join(fixture.root, "fsck-skip-list");
  fs.writeFileSync(skipList, `${parent}\n`);
  git(fixture.repository, "config", "fsck.skipList", skipList);
  const fake = harness(fixture);

  assert.throws(
    () => verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, fake.options),
    /redirect repository behavior \(fsck\.skiplist\)/
  );
  assert.equal(treehouseCalls(fake).length, 0);
  assert.equal(fake.events.length, 0);
});

test("verifyWorkspace rejects caller-selected or locally moved landing refs", (t) => {
  const fixture = repositoryFixture(t);
  fs.writeFileSync(path.join(fixture.workspace, "unlanded.txt"), "keep\n");
  git(fixture.workspace, "add", "unlanded.txt");
  git(fixture.workspace, "commit", "-q", "-m", "unlanded");

  const selfRef = harness(fixture);
  assert.throws(
    () => verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "HEAD"
    }, selfRef.options),
    /must match the main worktree's checked-out branch/
  );
  assert.equal(treehouseCalls(selfRef, "return").length, 0);

  git(fixture.workspace, "update-ref", "refs/heads/main", "HEAD");
  const moved = harness(fixture);
  assert.throws(
    () => verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, moved.options),
    /main Git worktree has (?:staged|raw) changes/
  );
  assert.equal(treehouseCalls(moved, "return").length, 0);
  assert.equal(moved.events.length, 0);
});

test("verifyWorkspace rejects core.worktree redirection before releasing landed-looking work", (t) => {
  const fixture = repositoryFixture(t);
  const landedOnly = path.join(fixture.workspace, "landed-only.txt");
  const actualMainFile = path.join(fixture.repository, "landed-only.txt");
  fs.writeFileSync(landedOnly, "workspace content\n");
  git(fixture.workspace, "add", "landed-only.txt");
  git(fixture.workspace, "commit", "-q", "-m", "workspace commit");
  const workspaceHead = git(fixture.workspace, "rev-parse", "HEAD");

  // Forge local reachability and make the main index describe W without
  // updating the real main worktree. core.worktree then redirects status to
  // the linked workspace, where those bytes do exist.
  git(fixture.workspace, "update-ref", "refs/heads/main", workspaceHead);
  git(fixture.repository, "read-tree", workspaceHead);
  git(fixture.repository, "config", "core.worktree", fixture.workspace);
  assert.equal(git(fixture.repository, "status", "--porcelain=v1", "--untracked-files=all"), "");
  assert.equal(fs.existsSync(actualMainFile), false, "main worktree precondition");

  const fake = harness(fixture);
  assert.throws(
    () => verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, fake.options),
    /redirect repository behavior \(core\.worktree\)/
  );
  assert.equal(treehouseCalls(fake, "return").length, 0);
  assert.equal(fake.events.length, 0);
  assert.equal(fs.existsSync(actualMainFile), false, "main worktree must remain unchanged");
});

test("workspace identity checks reject a mismatched Git top-level", (t) => {
  const fixture = repositoryFixture(t);
  const fake = harness(fixture);
  const baseRunner = fake.options.runner;
  fake.options.runner = (command, args, invocation) => {
    if (
      command !== fake.executable && invocation.cwd === fixture.workspace &&
      args.at(-2) === "rev-parse" && args.at(-1) === "--show-toplevel"
    ) {
      return { status: 0, stdout: `${fixture.repository}\n`, stderr: "" };
    }
    return baseRunner(command, args, invocation);
  };

  assert.throws(
    () => workspaceStatus({ repository: fixture.repository }, fake.options),
    /Git worktree is redirected to a different Git worktree/
  );
  assert.equal(treehouseCalls(fake).length, 0);
});

test("verifyWorkspace rejects stat-cache weakening that conceals changed bytes", (t) => {
  const fixture = repositoryFixture(t);
  const workspaceFile = path.join(fixture.workspace, "README.md");
  const mainFile = path.join(fixture.repository, "README.md");
  fs.writeFileSync(workspaceFile, "AAAA\n");
  git(fixture.workspace, "add", "README.md");
  git(fixture.workspace, "commit", "-q", "-m", "landed baseline");
  git(fixture.repository, "merge", "-q", "--ff-only", "gate/task-1");

  const old = new Date(Date.now() - 120_000);
  fs.utimesSync(workspaceFile, old, old);
  git(fixture.workspace, "update-index", "--refresh");
  fs.writeFileSync(workspaceFile, "BBBB\n");
  fs.utimesSync(workspaceFile, old, old);
  git(fixture.repository, "config", "core.trustctime", "false");
  git(fixture.repository, "config", "core.checkStat", "minimal");
  assert.equal(git(fixture.workspace, "status", "--porcelain=v1"), "", "weakened-stat precondition");
  assert.equal(fs.readFileSync(mainFile, "utf8"), "AAAA\n");
  assert.equal(fs.readFileSync(workspaceFile, "utf8"), "BBBB\n");

  const fake = harness(fixture);
  assert.throws(
    () => verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, fake.options),
    /redirect repository behavior \(core\.(?:trustctime|checkstat)\)/
  );
  assert.equal(treehouseCalls(fake, "return").length, 0);
  assert.equal(fake.events.length, 0);
  assert.equal(fs.readFileSync(workspaceFile, "utf8"), "BBBB\n", "concealed bytes must remain leased");
});

test("verifyWorkspace rehashes worktree bytes through a fresh private index", (t) => {
  const fixture = repositoryFixture(t);
  const workspaceFile = path.join(fixture.workspace, "README.md");
  fs.writeFileSync(workspaceFile, "changed\n");
  assert.notEqual(git(fixture.workspace, "status", "--porcelain=v1"), "", "dirty precondition");
  const old = new Date(Date.now() - 120_000);
  fs.utimesSync(workspaceFile, old, old);
  const indexOutput = git(fixture.workspace, "rev-parse", "--git-path", "index");
  const indexFile = path.isAbsolute(indexOutput) ? indexOutput : path.resolve(fixture.workspace, indexOutput);
  forgeIndexStat(indexFile, workspaceFile);
  assert.equal(
    git(
      fixture.workspace,
      "-c", "core.fsmonitor=false",
      "-c", "core.trustctime=true",
      "-c", "core.checkStat=default",
      "-c", "core.ignoreStat=false",
      "status", "--porcelain=v1", "--untracked-files=all"
    ),
    "",
    "forged real index must fool an ordinary protected status check"
  );

  const fake = harness(fixture);
  assert.throws(
    () => verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, fake.options),
    /uncommitted changes.*remain leased/
  );
  assert.equal(treehouseCalls(fake, "return").length, 0);
  assert.equal(fake.events.length, 0);
  assert.equal(fs.readFileSync(workspaceFile, "utf8"), "changed\n");
});

test("workspace operations reject gitlinks before nested index state is consulted", (t) => {
  const fixture = repositoryFixture(t);
  const source = path.join(fixture.root, "submodule-source");
  fs.mkdirSync(source);
  git(source, "init", "-q", "-b", "main");
  git(source, "config", "user.name", "GATE Test");
  git(source, "config", "user.email", "gate-test@example.invalid");
  fs.writeFileSync(path.join(source, "file"), "AAAA\n");
  git(source, "add", "file");
  git(source, "commit", "-q", "-m", "submodule fixture");
  git(fixture.workspace, "-c", "protocol.file.allow=always", "submodule", "add", "-q", source, "sub");
  git(fixture.workspace, "commit", "-q", "-m", "add submodule");
  git(fixture.repository, "merge", "-q", "--ff-only", "gate/task-1");

  const submodule = path.join(fixture.workspace, "sub");
  const target = path.join(submodule, "file");
  fs.writeFileSync(target, "BBBB\n");
  assert.notEqual(
    git(fixture.workspace, "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"),
    "",
    "dirty nested worktree precondition"
  );
  const old = new Date(Date.now() - 120_000);
  fs.utimesSync(target, old, old);
  const indexOutput = git(submodule, "rev-parse", "--git-path", "index");
  const indexFile = path.isAbsolute(indexOutput) ? indexOutput : path.resolve(submodule, indexOutput);
  forgeIndexStat(indexFile, target);
  assert.equal(
    git(
      fixture.workspace,
      "-c", "core.fsmonitor=false",
      "-c", "core.trustctime=true",
      "-c", "core.checkStat=default",
      "-c", "core.ignoreStat=false",
      "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"
    ),
    "",
    "forged nested index must fool recursive status"
  );

  const fake = harness(fixture);
  assert.throws(
    () => verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, fake.options),
    /Git submodules are incompatible with workspace operations/
  );
  assert.equal(treehouseCalls(fake).length, 0);
  assert.equal(fake.events.length, 0);
  assert.equal(fs.readFileSync(target, "utf8"), "BBBB\n");
});

test("POSIX workspace operations reject mode and symlink integrity weakening", async (t) => {
  if (process.platform === "win32") return t.skip("Windows uses different file-mode and symlink semantics");
  for (const name of ["core.filemode", "core.symlinks"]) {
    await t.test(name, (t) => {
      const fixture = repositoryFixture(t);
      git(fixture.repository, "config", name, "false");
      const fake = harness(fixture);
      assert.throws(
        () => workspaceStatus({ repository: fixture.repository }, fake.options),
        new RegExp(`weakens worktree integrity \\(${name.replace(".", "\\.")}\\)`)
      );
      assert.equal(treehouseCalls(fake).length, 0);
    });
  }
});

test("workspace operations reject unsupported reference storage", (t) => {
  const fixture = repositoryFixture(t);
  git(fixture.repository, "config", "core.repositoryformatversion", "1");
  git(fixture.repository, "config", "extensions.refStorage", "reftable");
  const fake = harness(fixture);

  assert.throws(
    () => workspaceStatus({ repository: fixture.repository }, fake.options),
    /unsupported reference storage.*files ref backend/
  );
  assert.equal(treehouseCalls(fake).length, 0);
  assert.equal(fake.events.length, 0);
});

test("verifyWorkspace accepts Git SHA-256 commit identities when supported", (t) => {
  try {
    const fixture = repositoryFixture(t, { objectFormat: "sha256" });
    const fake = harness(fixture);
    const result = verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, fake.options);
    assert.match(result.head, /^[a-f0-9]{64}$/u);
    assert.equal(result.returned, false);
    assert.equal(result.retained, true);
  } catch (error) {
    if (/unknown option|unknown hash algorithm|not supported/iu.test(String(error?.message || error))) t.skip("Git SHA-256 repositories are unavailable");
    else throw error;
  }
});

test("verifyWorkspace preserves a lease with active processes or changed identity", (t) => {
  const fixture = repositoryFixture(t);
  const active = harness(fixture, { state: { processes: [{ pid: 22, name: "codex" }] } });
  assert.throws(
    () => verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, active.options),
    /still has running processes/
  );
  assert.equal(treehouseCalls(active, "return").length, 0);
  assert.equal(active.events.length, 0);

  const changed = harness(fixture, { state: { statusHolder: "gate:another-task" } });
  assert.throws(
    () => verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, changed.options),
    /state lease holder does not match the trusted acquisition receipt/
  );
  assert.equal(treehouseCalls(changed, "return").length, 0);
  assert.equal(changed.events.length, 0);
});

test("leaseWorkspace never reuses a burned task root and leaves its data untouched", (t) => {
  const fixture = repositoryFixture(t);
  const secret = path.join(fixture.workspace, ".legacy-secret");
  fs.writeFileSync(secret, "preserve me\n");
  const fake = harness(fixture, { state: { status: "available" } });

  assert.throws(
    () => leaseWorkspace({
      repository: fixture.repository,
      taskId: "task-1",
      branch: "gate/task-2",
      baseBranch: "main"
    }, fake.options),
    /task id already has a burned or active Treehouse root/
  );
  assert.deepEqual(treehouseCalls(fake).map((call) => call.args[0]), []);
  assert.equal(fs.readFileSync(secret, "utf8"), "preserve me\n");
  assert.equal(fake.events.length, 0);
});

test("interrupted task-root activation never publishes a partial registry entry", (t) => {
  const fixture = freshLeaseFixture(t);
  const fake = harness(fixture);
  fake.options.beforeTaskRootPublish = () => {
    throw new Error("injected task-root publication fault");
  };

  assert.throws(
    () => leaseWorkspace({
      repository: fixture.repository,
      taskId: "task-1",
      branch: "gate/task-1",
      baseBranch: "main"
    }, fake.options),
    /injected task-root publication fault/
  );
  assert.equal(fs.existsSync(fixture.treehouseRoot), false);
  assert.equal(treehouseCalls(fake).length, 0);
  assert.equal(fake.events.length, 0);
  const status = workspaceStatus({ repository: fixture.repository }, harness(fixture).options);
  assert.deepEqual(status.workspaces, []);
});

test("task-root lifetime capacity fails before provider mutation", (t) => {
  const fixture = freshLeaseFixture(t);
  const tasksRoot = path.dirname(fixture.treehouseRoot);
  for (let index = 0; index < 511; index += 1) {
    const taskId = `capacity-${index}`;
    const taskHash = crypto.createHash("sha256").update(taskId).digest("hex");
    writeTaskBinding(fixture.repository, path.join(tasksRoot, taskHash), taskId);
  }
  const targetId = "capacity-target";
  const targetRoot = path.join(tasksRoot, crypto.createHash("sha256").update(targetId).digest("hex"));
  const fake = harness(fixture);

  assert.throws(
    () => leaseWorkspace({
      repository: fixture.repository,
      taskId: targetId,
      branch: "gate/capacity-target",
      baseBranch: "main"
    }, fake.options),
    /task-specific Treehouse root capacity \(511\) is exhausted before creating a new lease/
  );
  assert.equal(fs.existsSync(targetRoot), false);
  assert.equal(treehouseCalls(fake).length, 0);
  assert.equal(fake.events.length, 0);
});

test("verifyWorkspace rejects staged-only changes even when worktree bytes match HEAD", (t) => {
  const fixture = repositoryFixture(t);
  const tracked = path.join(fixture.workspace, "README.md");
  fs.writeFileSync(tracked, "staged replacement\n");
  git(fixture.workspace, "add", "README.md");
  fs.writeFileSync(tracked, "fixture\n");
  assert.match(git(fixture.workspace, "status", "--porcelain=v1"), /^MM README\.md$/mu);
  const fake = harness(fixture);

  assert.throws(
    () => verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, fake.options),
    /staged changes.*remain leased/
  );
  assert.equal(treehouseCalls(fake, "return").length, 0);
  assert.equal(fs.readFileSync(tracked, "utf8"), "fixture\n");
});

test("verifyWorkspace rejects nested Git metadata before releasing a clean outer tree", (t) => {
  const fixture = repositoryFixture(t);
  const nested = path.join(fixture.workspace, "nested");
  fs.mkdirSync(nested);
  fs.writeFileSync(path.join(nested, "payload"), "tracked\n");
  git(fixture.workspace, "add", "nested/payload");
  git(fixture.workspace, "commit", "-q", "-m", "tracked directory");
  git(fixture.repository, "merge", "-q", "--ff-only", "gate/task-1");
  git(nested, "init", "-q");
  assert.equal(git(fixture.workspace, "status", "--porcelain=v1", "--untracked-files=all"), "");
  const fake = harness(fixture);

  assert.throws(
    () => verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, fake.options),
    /contains nested Git metadata/
  );
  assert.equal(treehouseCalls(fake, "return").length, 0);
  assert.equal(fs.existsSync(path.join(nested, ".git")), true);
});

test("verifyWorkspace rejects in-progress merge state", (t) => {
  const fixture = repositoryFixture(t);
  fs.writeFileSync(path.join(fixture.repository, "main-only.txt"), "main\n");
  git(fixture.repository, "add", "main-only.txt");
  git(fixture.repository, "commit", "-q", "-m", "main advance");
  git(fixture.workspace, "merge", "--no-ff", "--no-commit", "main");
  const mergeHead = git(fixture.workspace, "rev-parse", "--git-path", "MERGE_HEAD");
  assert.equal(fs.existsSync(path.isAbsolute(mergeHead) ? mergeHead : path.resolve(fixture.workspace, mergeHead)), true);
  const fake = harness(fixture);

  assert.throws(
    () => verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, fake.options),
    /in-progress Git operation \((?:AUTO_MERGE|MERGE_HEAD)\)/
  );
  assert.equal(treehouseCalls(fake, "return").length, 0);
});

test("workspace verification rejects linked-worktree and shared Git transaction locks", async (t) => {
  const cases = [
    ["linked index lock", (fixture) => path.join(git(fixture.workspace, "rev-parse", "--absolute-git-dir"), "index.lock")],
    ["linked HEAD lock", (fixture) => path.join(git(fixture.workspace, "rev-parse", "--absolute-git-dir"), "HEAD.lock")],
    ["linked config.worktree lock", (fixture) => path.join(git(fixture.workspace, "rev-parse", "--absolute-git-dir"), "config.worktree.lock")],
    ["linked private ref lock", (fixture) => path.join(git(fixture.workspace, "rev-parse", "--absolute-git-dir"), "refs", "worktree", "topic.lock")],
    ["shared config lock", (fixture) => path.join(fixture.repository, ".git", "config.lock")],
    ["shared shallow lock", (fixture) => path.join(fixture.repository, ".git", "shallow.lock")],
    ["shared packed-refs lock", (fixture) => path.join(fixture.repository, ".git", "packed-refs.lock")],
    ["nested ref lock", (fixture) => path.join(fixture.repository, ".git", "refs", "heads", "main.lock")]
  ];
  for (const [name, lockPath] of cases) {
    await t.test(name, (t) => {
      const fixture = repositoryFixture(t);
      const candidate = lockPath(fixture);
      fs.mkdirSync(path.dirname(candidate), { recursive: true });
      fs.writeFileSync(candidate, "stale\n");
      const fake = harness(fixture);

      assert.throws(
        () => verifyWorkspace({
          repository: fixture.repository,
          path: fixture.workspace,
          taskId: "task-1",
          leaseId: LEASE_ID,
          landedRef: "main"
        }, fake.options),
        /workspace state is not quiescent|active or stale Git ref lock/
      );
      assert.equal(treehouseCalls(fake).length, 0);
      assert.equal(fake.events.length, 0);
      assert.equal(fs.readFileSync(candidate, "utf8"), "stale\n");
    });
  }
});

test("workspace verification rechecks transaction locks after ancestry proof", (t) => {
  const fixture = repositoryFixture(t);
  const administrative = git(fixture.workspace, "rev-parse", "--absolute-git-dir");
  const lateLock = path.join(administrative, "index.lock");
  let replacementScans = 0;
  const fake = harness(fixture, {
    afterGit(result, args) {
      if (result.status !== 0 || !args.includes("for-each-ref") || args.at(-1) !== "refs/replace") return;
      replacementScans += 1;
      if (replacementScans === 2) fs.writeFileSync(lateLock, "late writer\n");
    }
  });

  assert.throws(
    () => verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, fake.options),
    /Treehouse workspace index\.lock exists; workspace state is not quiescent/
  );
  assert.equal(replacementScans, 2);
  assert.equal(fs.readFileSync(lateLock, "utf8"), "late writer\n");
  assert.equal(treehouseCalls(fake).length, 0);
  assert.equal(fake.events.length, 0);
});

test("lease preflight rejects Git transaction locks before burning a task id", (t) => {
  const fixture = freshLeaseFixture(t);
  const lockPath = path.join(fixture.repository, ".git", "index.lock");
  fs.writeFileSync(lockPath, "stale\n");
  const fake = harness(fixture);

  assert.throws(
    () => leaseWorkspace({
      repository: fixture.repository,
      taskId: "task-1",
      branch: "gate/task-1",
      baseBranch: "main"
    }, fake.options),
    /main Git worktree index\.lock exists; workspace state is not quiescent/
  );
  assert.equal(fs.existsSync(fixture.treehouseRoot), false);
  assert.equal(treehouseCalls(fake).length, 0);
  assert.equal(fake.events.length, 0);
});

test("verifyWorkspace preserves unreachable work after a commit is reset", (t) => {
  const fixture = repositoryFixture(t);
  fs.writeFileSync(path.join(fixture.workspace, "recover-me.txt"), "recover me\n");
  git(fixture.workspace, "add", "recover-me.txt");
  git(fixture.workspace, "commit", "-q", "-m", "recoverable work");
  const abandoned = git(fixture.workspace, "rev-parse", "HEAD");
  git(fixture.workspace, "reset", "--hard", "HEAD^");
  assert.match(git(fixture.workspace, "fsck", "--unreachable", "--no-reflogs"), new RegExp(abandoned));
  const fake = harness(fixture);

  assert.throws(
    () => verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, fake.options),
    /contains unreachable objects.*preserve them with a ref/
  );
  assert.equal(treehouseCalls(fake, "return").length, 0);
  assert.equal(fake.events.length, 0);
});

test("verifyWorkspace rejects tracked hard links to external files", (t) => {
  if (process.platform === "win32") return t.skip("hard-link ownership semantics differ on Windows");
  const fixture = repositoryFixture(t);
  const outside = path.join(fixture.root, "outside-data");
  const tracked = path.join(fixture.workspace, "README.md");
  fs.writeFileSync(outside, "fixture\n");
  fs.unlinkSync(tracked);
  fs.linkSync(outside, tracked);
  assert.equal(git(fixture.workspace, "status", "--porcelain=v1"), "");
  const fake = harness(fixture);

  assert.throws(
    () => verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, fake.options),
    /tracked file has multiple hard links/
  );
  assert.equal(treehouseCalls(fake, "return").length, 0);
  assert.equal(fs.readFileSync(outside, "utf8"), "fixture\n");
});

test("canonical checkout proof supports ident and eol transforms but detects altered ident bytes", async (t) => {
  await t.test("legitimate ident expansion", (t) => {
    const fixture = repositoryFixture(t);
    fs.writeFileSync(path.join(fixture.workspace, ".gitattributes"), "note.txt ident\n");
    fs.writeFileSync(path.join(fixture.workspace, "note.txt"), "$Id$\n");
    git(fixture.workspace, "add", ".gitattributes", "note.txt");
    git(fixture.workspace, "commit", "-q", "-m", "ident fixture");
    git(fixture.repository, "merge", "-q", "--ff-only", "gate/task-1");
    fs.rmSync(path.join(fixture.workspace, "note.txt"));
    git(fixture.workspace, "checkout", "--", "note.txt");
    assert.match(fs.readFileSync(path.join(fixture.workspace, "note.txt"), "utf8"), /^\$Id: [a-f0-9]+ \$$/mu);
    const fake = harness(fixture);
    assert.equal(verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, fake.options).retained, true);
  });

  await t.test("altered ident expansion", (t) => {
    const fixture = repositoryFixture(t);
    fs.writeFileSync(path.join(fixture.workspace, ".gitattributes"), "note.txt ident\n");
    fs.writeFileSync(path.join(fixture.workspace, "note.txt"), "$Id$\n");
    git(fixture.workspace, "add", ".gitattributes", "note.txt");
    git(fixture.workspace, "commit", "-q", "-m", "ident fixture");
    git(fixture.repository, "merge", "-q", "--ff-only", "gate/task-1");
    fs.rmSync(path.join(fixture.workspace, "note.txt"));
    git(fixture.workspace, "checkout", "--", "note.txt");
    const note = path.join(fixture.workspace, "note.txt");
    const expanded = fs.readFileSync(note, "utf8");
    const altered = expanded.replace(/^(\$Id: )([a-f0-9])/u, (_match, prefix, nibble) => {
      return `${prefix}${nibble === "0" ? "1" : "0"}`;
    });
    assert.notEqual(altered, expanded, "ident fixture mutation must change bytes");
    fs.writeFileSync(note, altered);
    assert.equal(git(fixture.workspace, "status", "--porcelain=v1"), "", "ident conversion precondition");
    const fake = harness(fixture);
    assert.throws(
      () => verifyWorkspace({
        repository: fixture.repository,
        path: fixture.workspace,
        taskId: "task-1",
        leaseId: LEASE_ID,
        landedRef: "main"
      }, fake.options),
      /remain leased:.*tracked bytes changed/
    );
    assert.equal(treehouseCalls(fake, "return").length, 0);
  });

  await t.test("CRLF checkout", (t) => {
    const fixture = repositoryFixture(t);
    fs.writeFileSync(path.join(fixture.workspace, ".gitattributes"), "windows.txt text eol=crlf\n");
    fs.writeFileSync(path.join(fixture.workspace, "windows.txt"), "one\ntwo\n");
    git(fixture.workspace, "add", ".gitattributes", "windows.txt");
    git(fixture.workspace, "commit", "-q", "-m", "eol fixture");
    git(fixture.repository, "merge", "-q", "--ff-only", "gate/task-1");
    fs.rmSync(path.join(fixture.workspace, "windows.txt"));
    git(fixture.workspace, "checkout", "--", "windows.txt");
    assert.equal(fs.readFileSync(path.join(fixture.workspace, "windows.txt")).includes(Buffer.from("\r\n")), true);
    const fake = harness(fixture);
    assert.equal(verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, fake.options).retained, true);
  });
});

test("verifyWorkspace rejects mounts anywhere in the Treehouse slot container", (t) => {
  if (process.platform !== "linux") return t.skip("Linux mountinfo boundary test");
  const fixture = repositoryFixture(t);
  const siblingMount = path.join(path.dirname(fixture.workspace), "sibling mount");
  fs.mkdirSync(siblingMount);
  fs.writeFileSync(path.join(siblingMount, "outside-secret"), "preserve\n");
  const fake = harness(fixture);
  const realMountInfo = fs.readFileSync("/proc/self/mountinfo", "utf8");
  fake.options.readMountInfo = () => `${realMountInfo.trimEnd()}\n99999 1 0:999 / ${mountInfoPath(siblingMount)} rw - tmpfs tmpfs rw\n`;

  assert.throws(
    () => verifyWorkspace({
      repository: fixture.repository,
      path: fixture.workspace,
      taskId: "task-1",
      leaseId: LEASE_ID,
      landedRef: "main"
    }, fake.options),
    /workspace contains a nested mount/
  );
  assert.equal(treehouseCalls(fake, "return").length, 0);
  assert.equal(treehouseCalls(fake, "destroy").length, 0);
  assert.equal(fs.readFileSync(path.join(siblingMount, "outside-secret"), "utf8"), "preserve\n");
});

test("verifyWorkspace never invokes Treehouse return or destroy", (t) => {
  const fixture = repositoryFixture(t);
  const fake = harness(fixture);
  const result = verifyWorkspace({
    repository: fixture.repository,
    path: fixture.workspace,
    taskId: "task-1",
    leaseId: LEASE_ID,
    landedRef: "main"
  }, fake.options);
  assert.equal(result.verified, true);
  assert.equal(result.retained, true);
  assert.equal(fake.state.returned, false);
  assert.equal(fs.existsSync(fixture.workspace), true);
  assert.equal(treehouseCalls(fake, "return").length, 0);
  assert.equal(treehouseCalls(fake, "destroy").length, 0);
  assert.throws(() => returnWorkspace(), /workspace return is disabled.*use workspace verify/);
});

test("an existing operation lock blocks lease mutation and is never auto-broken", (t) => {
  const fixture = repositoryFixture(t);
  const lock = path.join(fixture.repositoryRoot, ".gate-workspace-operation.lock");
  fs.writeFileSync(lock, "stale\n", { mode: 0o600 });
  const fake = harness(fixture);
  assert.throws(
    () => leaseWorkspace({
      repository: fixture.repository,
      taskId: "task-1",
      branch: "gate/task-2",
      baseBranch: "main"
    }, fake.options),
    /stale GATE workspace operation lock exists.*reconcile it manually/
  );
  assert.equal(treehouseCalls(fake).length, 0);
  assert.equal(fs.readFileSync(lock, "utf8"), "stale\n");
});

test("workspaceStatus reports a stale operation lock before manual pending-root reconciliation", (t) => {
  const fixture = freshLeaseFixture(t);
  writePendingGateLeaseBinding(fixture);
  const lock = path.join(fixture.repositoryRoot, ".gate-workspace-operation.lock");
  fs.writeFileSync(lock, `999999 ${LEASED_AT}\n`, { mode: 0o600 });
  const blocked = harness(fixture);

  const blockedStatus = workspaceStatus({ repository: fixture.repository }, blocked.options);
  assert.equal(blockedStatus.workspaces.length, 1);
  assert.equal(blockedStatus.workspaces[0].status, "unverified");
  assert.equal(blockedStatus.workspaces[0].phase, "operation-lock-present");
  assert.equal(blockedStatus.workspaces[0].path, null);
  assert.equal(blockedStatus.workspaces[0].taskId, null);
  assert.match(blockedStatus.workspaces[0].recoveryReason, /recorded owner PID 999999/);
  assert.match(blockedStatus.workspaces[0].recoveryReason, /follow the ordered operation-lock recovery procedure.*leave it in place while that PID.*only remove the exact unchanged lock.*retrying status/);
  assert.equal(blocked.calls.some((call) => call.kind === "git" || call.kind === "treehouse"), false);
  assert.equal(fs.readFileSync(lock, "utf8"), `999999 ${LEASED_AT}\n`);

  fs.unlinkSync(lock);
  const reconciled = harness(fixture);
  const pendingStatus = workspaceStatus({ repository: fixture.repository }, reconciled.options);
  assert.equal(pendingStatus.workspaces.length, 1);
  assert.equal(pendingStatus.workspaces[0].phase, "pending");
  assert.equal(treehouseCalls(reconciled).length, 0);
});

test("workspaceStatus preserves malformed operation-lock evidence without inspecting tasks", (t) => {
  const fixture = freshLeaseFixture(t);
  writePendingGateLeaseBinding(fixture);
  const lock = path.join(fixture.repositoryRoot, ".gate-workspace-operation.lock");
  const fake = harness(fixture);

  for (const malformed of [
    "malformed owner evidence\nsecond line\n",
    "999999 1\n"
  ]) {
    fs.writeFileSync(lock, malformed, { mode: 0o600 });
    const result = workspaceStatus({ repository: fixture.repository }, fake.options);
    assert.equal(result.workspaces.length, 1);
    assert.equal(result.workspaces[0].status, "unverified");
    assert.equal(result.workspaces[0].phase, "operation-lock-present");
    assert.equal(result.workspaces[0].path, null);
    assert.match(result.workspaces[0].recoveryReason, /owner metadata could not be verified/);
    assert.match(result.workspaces[0].recoveryReason, /leave it in place.*owner evidence is not trustworthy.*do not inspect or mutate task state/);
    assert.doesNotMatch(result.workspaces[0].recoveryReason, /remove .*lock/);
    assert.equal(fake.calls.some((call) => call.kind === "git" || call.kind === "treehouse"), false);
    assert.equal(fs.readFileSync(lock, "utf8"), malformed);
  }
  assert.equal(fs.existsSync(fixture.treehouseRoot), true);
});

test("clone-specific Treehouse roots isolate same-remote clones", (t) => {
  const fixture = repositoryFixture(t);
  const sibling = path.join(fixture.root, "same-remote-clone");
  git(fixture.root, "clone", "-q", fixture.repository, sibling);
  const siblingRepository = fs.realpathSync(sibling);
  const siblingIdentity = crypto.createHash("sha256").update(siblingRepository).digest("hex");
  const siblingRepositoryRoot = path.join(fixture.paths.home, "treehouse", "repos", siblingIdentity);
  writeCloneBinding(siblingRepository, siblingRepositoryRoot);
  const siblingFixture = {
    ...fixture,
    repository: siblingRepository,
    repositoryRoot: siblingRepositoryRoot,
    treehouseRoot: path.join(
      siblingRepositoryRoot,
      "tasks",
      crypto.createHash("sha256").update("task-1").digest("hex")
    )
  };
  const first = harness(fixture);
  const second = harness(siblingFixture);
  const firstStatus = workspaceStatus({ repository: fixture.repository }, first.options);
  const secondStatus = workspaceStatus({ repository: siblingRepository }, second.options);
  assert.equal(firstStatus.workspaces.length, 1);
  assert.equal(secondStatus.workspaces.length, 0);
  assert.notEqual(fixture.repositoryRoot, siblingRepositoryRoot);
  assert.equal(treehouseCalls(first).length + treehouseCalls(second).length, 0);
});

test("workspaceStatus aggregates retained leases across validated one-shot task roots", (t) => {
  const fixture = repositoryFixture(t);
  const taskId = "task-2";
  const taskHash = crypto.createHash("sha256").update(taskId).digest("hex");
  const taskRoot = path.join(fixture.repositoryRoot, "tasks", taskHash);
  const poolDirectory = path.join(taskRoot, ".treehouse", "repository-d4e5f6");
  const workspace = path.join(poolDirectory, "1", "repository");
  fs.mkdirSync(path.dirname(workspace), { recursive: true, mode: 0o700 });
  git(fixture.repository, "worktree", "add", "-q", "-b", "gate/task-2", workspace, "main");
  const secondLease = "fedcba9876543210fedcba9876543210";
  const secondFixture = {
    ...fixture,
    treehouseRoot: taskRoot,
    poolDirectory,
    workspace
  };
  const secondState = writeTreehouseState(secondFixture, {
    entry: {
      lease_id: secondLease,
      lease_holder: "gate:task-2"
    }
  });
  writeGateLeaseBinding(secondFixture, secondState, { taskId, branch: "gate/task-2" });
  const scaleRefs = path.join(fixture.repository, ".git", "refs", "heads", "scale");
  fs.mkdirSync(scaleRefs, { recursive: true });
  const mainCommit = git(fixture.repository, "rev-parse", "main");
  for (let index = 0; index < 128; index += 1) {
    fs.writeFileSync(path.join(scaleRefs, `ref-${index}`), `${mainCommit}\n`);
  }
  const fake = harness(fixture);

  const result = workspaceStatus({ repository: fixture.repository }, fake.options);
  assert.equal(result.workspaces.length, 2);
  assert.deepEqual(new Set(result.workspaces.map((entry) => entry.taskId)), new Set(["task-1", "task-2"]));
  assert.equal(
    fake.calls.filter((call) => call.kind === "git" && call.args.includes("--git-common-dir")).length,
    4,
    "shared common locks and refs must be scanned a constant number of times"
  );
  assert.equal(treehouseCalls(fake).length, 0);
});

test("workspaceStatus rejects an unregistered commondir alias", (t) => {
  const fixture = repositoryFixture(t);
  const alias = path.join(fixture.root, "alias-main");
  fs.mkdirSync(path.join(alias, ".git"), { recursive: true });
  fs.writeFileSync(path.join(alias, ".git", "HEAD"), "ref: refs/heads/main\n");
  fs.writeFileSync(path.join(alias, ".git", "commondir"), `${path.join(fixture.repository, ".git")}\n`);
  fs.copyFileSync(path.join(fixture.repository, ".git", "index"), path.join(alias, ".git", "index"));
  fs.copyFileSync(path.join(fixture.repository, "README.md"), path.join(alias, "README.md"));
  const aliasRepository = fs.realpathSync(alias);
  const aliasIdentity = crypto.createHash("sha256").update(aliasRepository).digest("hex");
  const fake = harness({
    ...fixture,
    repository: aliasRepository,
    repositoryRoot: path.join(fixture.paths.home, "treehouse", "repos", aliasIdentity),
    treehouseRoot: path.join(
      fixture.paths.home,
      "treehouse",
      "repos",
      aliasIdentity,
      "tasks",
      crypto.createHash("sha256").update("task-1").digest("hex")
    )
  }, { statusOutput: () => [] });

  assert.throws(
    () => workspaceStatus({ repository: aliasRepository }, fake.options),
    /repository path must be the registered primary Git worktree/
  );
  assert.equal(treehouseCalls(fake).length, 0);
});

test("workspace CLI rejects invalid surfaces and absent Treehouse before execution", (t) => {
  const fixture = repositoryFixture(t);
  const bin = path.join(fixture.root, "bin");
  const marker = path.join(fixture.root, "treehouse-ran");
  fs.mkdirSync(bin);
  const executable = path.join(bin, process.platform === "win32" ? "treehouse.cmd" : "treehouse");
  fs.writeFileSync(executable, process.platform === "win32"
    ? `@echo bad>${marker}\r\n`
    : `#!/bin/sh\nprintf bad > ${JSON.stringify(marker)}\n`);
  if (process.platform !== "win32") fs.chmodSync(executable, 0o755);
  const invoke = (args) => spawnSync(process.execPath, [path.join(sourceRepo, "bin", "gate.mjs"), ...args], {
    cwd: sourceRepo,
    env: {
      ...process.env,
      GATE_HOME: path.join(fixture.root, "cli-home"),
      PATH: `${bin}${path.delimiter}${process.env.PATH || ""}`
    },
    encoding: "utf8",
    timeout: 10_000
  });

  const absent = invoke(["workspace", "status", "--repo", fixture.repository, "--json"]);
  assert.notEqual(absent.status, 0);
  assert.match(absent.stderr, /Treehouse is absent or not integrity-verified/);

  const unknown = invoke(["workspace", "status", "--repo", fixture.repository, "--surprise", "yes"]);
  assert.notEqual(unknown.status, 0);
  assert.match(unknown.stderr, /unsupported option: --surprise/);

  const extra = invoke(["workspace", "status", "extra", "--repo", fixture.repository]);
  assert.notEqual(extra.status, 0);
  assert.match(extra.stderr, /expected gate workspace ACTION/);
  assert.equal(fs.existsSync(marker), false);
});
