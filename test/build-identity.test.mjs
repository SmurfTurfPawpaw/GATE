import { spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { normalizeBuildIdentity, observeBuildIdentity } from "../src/lib/build-identity.mjs";

const SHA1 = "79a33b82d1cd5e1e73016646da438149d733e32e";
const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("build identity combines a bounded package version with exact clean Git identity", () => {
  const calls = [];
  const identity = observeBuildIdentity("/synthetic/repository", {
    readPackage(file) {
      assert.equal(file, "/synthetic/repository/package.json");
      return { version: "1.2.3-beta.1+build.7" };
    },
    runGit(repo, arguments_) {
      calls.push([repo, arguments_]);
      return arguments_[0] === "rev-parse" ? `${SHA1.toUpperCase()}\n` : "";
    }
  });

  assert.deepEqual(identity, {
    version: "1.2.3-beta.1+build.7",
    commit: SHA1,
    commitShort: SHA1.slice(0, 12),
    state: "clean"
  });
  assert.deepEqual(calls, [
    ["/synthetic/repository", ["rev-parse", "--verify", "HEAD^{commit}"]],
    ["/synthetic/repository", ["ls-files", "-v", "-z"]],
    ["/synthetic/repository", ["diff-index", "--cached", "--raw", "--no-renames", "--ignore-submodules=all", SHA1, "--"]],
    ["/synthetic/repository", ["ls-files", "--others", "--exclude-standard", "-z"]],
    ["/synthetic/repository", ["ls-files", "--stage", "-z"]]
  ]);
  assert.equal(Object.isFrozen(identity), true);
});

test("build identity distinguishes modified and unobservable source state", () => {
  const modified = observeBuildIdentity("/synthetic/repository", {
    readPackage: () => ({ version: "0.1.0" }),
    runGit: (_repo, arguments_) => arguments_[0] === "rev-parse" ? SHA1 : " M dashboard/index.html\n"
  });
  assert.equal(modified.state, "modified");
  assert.equal(modified.commit, SHA1);

  const failedCommands = observeBuildIdentity("/synthetic/repository", {
    readPackage: () => {
      throw new Error("unreadable package");
    },
    runGit: () => {
      throw new Error("git unavailable");
    }
  });
  assert.deepEqual(failedCommands, {
    version: null,
    commit: null,
    commitShort: null,
    state: "unavailable"
  });

  const statusUnavailable = observeBuildIdentity("/synthetic/repository", {
    readPackage: () => ({ version: "0.1.0" }),
    runGit: (_repo, arguments_) => {
      if (arguments_[0] === "rev-parse") return SHA1;
      throw new Error("status unavailable");
    }
  });
  assert.deepEqual(statusUnavailable, {
    version: "0.1.0",
    commit: SHA1,
    commitShort: SHA1.slice(0, 12),
    state: "unavailable"
  });
});

test("hidden index flags cannot make changed source appear clean", () => {
  for (const hidden of ["h package.json\0", "S dashboard/index.html\0"]) {
    const identity = observeBuildIdentity("/synthetic/repository", {
      readPackage: () => ({ version: "0.1.0" }),
      runGit: (_repo, arguments_) => {
        if (arguments_[0] === "rev-parse") return SHA1;
        if (arguments_[0] === "status") return "";
        return hidden;
      }
    });
    assert.equal(identity.state, "modified");
  }
});

test("default identity observation never resolves Git from ambient PATH", {
  skip: process.platform === "win32" ? "native Windows uses the explicit unavailable fallback" : false
}, () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-build-path-"));
  const fakeGit = path.join(root, "git");
  const marker = `${fakeGit}.ran`;
  fs.writeFileSync(fakeGit, "#!/bin/sh\n: > \"$0.ran\"\nexit 1\n", { mode: 0o700 });
  const previousPath = process.env.PATH;
  let ambientGitRan;
  try {
    process.env.PATH = root;
    const identity = observeBuildIdentity(repo, { readPackage: () => ({ version: "0.1.1" }) });
    assert.equal(identity.version, "0.1.1");
    assert.ok(identity.commit === null || /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u.test(identity.commit));
    ambientGitRan = fs.existsSync(marker);
  } finally {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
    fs.rmSync(root, { recursive: true, force: true });
  }
  assert.equal(ambientGitRan, false);
});

test("injected build identity cannot claim clean source without a valid exact commit", () => {
  assert.deepEqual(normalizeBuildIdentity({
    version: "01.2.3",
    commit: "not-a-commit",
    state: "clean"
  }), {
    version: null,
    commit: null,
    commitShort: null,
    state: "unavailable"
  });

  assert.equal(normalizeBuildIdentity({ version: "0.1.0", commit: SHA1, state: "unexpected" }).state, "unavailable");
});

 test("raw identity verification never invokes clean or process filters", () => {
  const root = fs.mkdtempSync(path.join(repo, ".build-filter-test-"));
  const git = (_repo, args) => {
    const result = spawnSync("git", args, { cwd: root, encoding: "utf8", timeout: 2000 });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout;
  };
  try {
    git(root, ["init", "--quiet"]);
    fs.writeFileSync(path.join(root, "file"), "original\n");
    fs.writeFileSync(path.join(root, ".gitattributes"), "file filter=trap\n");
    git(root, ["add", "."]);
    git(root, ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "fixture"]);
    for (const kind of ["clean", "process"]) {
      git(root, ["config", `filter.trap.${kind}`, "touch filter-ran; exit 1"]);
    }
    const observe = () => observeBuildIdentity(root, { runGit: git, readPackage: () => ({ version: "0.1.1" }) });
    assert.equal(observe().state, "clean");
    fs.writeFileSync(path.join(root, "file"), "changed\n");
    assert.equal(observe().state, "modified");
    assert.equal(fs.existsSync(path.join(root, "filter-ran")), false);
    fs.writeFileSync(path.join(root, "file"), "original\n");
    fs.writeFileSync(path.join(root, "extra"), "untracked");
    assert.equal(observe().state, "modified");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
