import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runDoctor } from "../src/lib/doctor.mjs";

test("doctor does not execute optional tools and strips credentials from required version probes", (t) => {
  if (process.platform === "win32") return t.skip("executable fixture targets the WSL/Linux control plane");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-doctor-"));
  const optionalMarker = path.join(root, "optional-ran");
  const requiredEnvironment = path.join(root, "required-env.json");
  const treehouse = path.join(root, "treehouse");
  const codex = path.join(root, "codex");
  fs.writeFileSync(
    treehouse,
    `#!/usr/bin/env node\nrequire("node:fs").writeFileSync(${JSON.stringify(optionalMarker)}, "ran");\n`,
    { mode: 0o700 }
  );
  fs.writeFileSync(
    codex,
    `#!/usr/bin/env node\nrequire("node:fs").writeFileSync(${JSON.stringify(requiredEnvironment)}, JSON.stringify(process.env)); console.log("codex-cli test");\n`,
    { mode: 0o700 }
  );

  const oldPath = process.env.PATH;
  const oldGitHubToken = process.env.GH_TOKEN;
  const oldAwsSecret = process.env.AWS_SECRET_ACCESS_KEY;
  process.env.PATH = `${root}${path.delimiter}${oldPath || ""}`;
  process.env.GH_TOKEN = "DOCTOR_GITHUB_SECRET_CANARY";
  process.env.AWS_SECRET_ACCESS_KEY = "DOCTOR_AWS_SECRET_CANARY";
  t.after(() => {
    process.env.PATH = oldPath;
    if (oldGitHubToken === undefined) delete process.env.GH_TOKEN;
    else process.env.GH_TOKEN = oldGitHubToken;
    if (oldAwsSecret === undefined) delete process.env.AWS_SECRET_ACCESS_KEY;
    else process.env.AWS_SECRET_ACCESS_KEY = oldAwsSecret;
    fs.rmSync(root, { recursive: true, force: true });
  });

  const report = runDoctor({ full: true });
  const optional = report.tools.find((tool) => tool.id === "treehouse");
  assert.equal(optional.available, true);
  assert.equal(optional.probe, "presence-only");
  assert.equal(fs.existsSync(optionalMarker), false);

  const captured = JSON.parse(fs.readFileSync(requiredEnvironment, "utf8"));
  assert.equal(captured.GH_TOKEN, undefined);
  assert.equal(captured.AWS_SECRET_ACCESS_KEY, undefined);
  assert.equal(captured.DISABLE_TELEMETRY, "1");
});
