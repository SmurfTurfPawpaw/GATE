import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const gate = path.join(repo, "bin", "gate.mjs");

function invoke(args, home) {
  return spawnSync(process.execPath, [gate, ...args], {
    cwd: repo,
    env: { ...process.env, GATE_HOME: home },
    encoding: "utf8",
    timeout: 10_000
  });
}

test("raw command surfaces fail closed before spawning passthrough commands", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-cli-boundary-"));
  const home = path.join(root, "home");
  const marker = path.join(root, "spawned");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const payload = `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'bad')`;

  const attempts = [
    {
      args: ["run", "--label", "unsafe", "--", process.execPath, "-e", payload],
      message: /raw command execution is disabled/
    },
    {
      args: ["upstream", "exec", "gnhf", "--", "--help"],
      message: /raw upstream execution is disabled/
    },
    {
      args: [
        "engagement", "exec", "demo", "--target", "example.test", "--action", "scan",
        "--requests", "1", "--parallel", "1", "--rate", "1", "--minutes", "1", "--tokens", "1000",
        "--", process.execPath, "-e", payload
      ],
      message: /active execution is disabled/
    }
  ];

  for (const attempt of attempts) {
    const result = invoke(attempt.args, home);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, attempt.message);
    assert.equal(fs.existsSync(marker), false);
  }
});

test("engagement creation rejects caller-supplied authorization evidence references", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-cli-evidence-boundary-"));
  const home = path.join(root, "home");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const result = invoke([
    "engagement", "new", "cli-client",
    "--basis", "client-written-authorization",
    "--evidence-ref", "private://authorizations/cli-client.evidence",
    "--targets", "app.example.test",
    "--actions", "scan"
  ], home);

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unsupported option: --evidence-ref/);
  assert.equal(fs.existsSync(path.join(home, "engagements", "cli-client.json")), false);
});
