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
    ["/synthetic/repository", [
      "status", "--porcelain=v1", "--untracked-files=normal", "--ignore-submodules=none"
    ]],
    ["/synthetic/repository", ["ls-files", "-v", "-z"]]
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
