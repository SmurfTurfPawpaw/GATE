import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const bundle = path.join(root, "deploy", "remote", "cloudflare-vps");

function read(name) {
  return fs.readFileSync(path.join(bundle, name), "utf8");
}

test("Cloudflare route contract preserves the exact browser, runner, and private-health split", () => {
  const value = JSON.parse(read("access-route-contract.example.json"));
  const server = JSON.parse(read("server-config.cloudflare.example.json"));
  assert.equal(value.apiVersion, "gate.remote-cloudflare-route-contract/v1");
  assert.equal(value.templateOnly, true);
  assert.equal(server.databasePath, "/var/lib/gate-remote/REPLACE_CASE_ID/bridge.sqlite");
  assert.equal(server.runner.publicKeyPath, "/etc/gate-remote/REPLACE_CASE_ID/runner-public.pem");
  assert.deepEqual(value.originRouteClasses.browser, [
    "/", "/index.html", "/assets/*", "/remote/client.js", "/data/status.json", "/robots.txt", "/.nojekyll",
    "/api/cockpit/v1/*"
  ]);
  assert.deepEqual(value.originRouteClasses.runner, ["/api/runner/v1/*"]);
  assert.deepEqual(value.originRouteClasses.hostPrivate, ["/healthz", "/readyz"]);
  assert.equal(value.originRouteClasses.default, "deny");
  assert.deepEqual(value.cloudflareAccessApplications.map((entry) => [entry.hostnameAndPath, entry.policyAction]), [
    ["REPLACE_PUBLIC_HOSTNAME/api/runner/v1/*", "bypass"],
    ["REPLACE_PUBLIC_HOSTNAME", "allow"]
  ]);
  assert.equal(value.cloudflareAccessApplications[0].interactiveLogin, false);
  assert.equal(value.cloudflareAccessApplications[1].include, "REPLACE_EXACT_OPERATOR_IDP_RULE");
  assert.equal(value.cloudflareAccessApplications[1].sessionDuration,
    `${server.oidc.maxTokenLifetimeSeconds / 3_600}h`);
  assert.deepEqual(value.originHeaderContract.runner.preserveHeaders, [
    "X-GATE-Runner", "X-GATE-Timestamp", "X-GATE-Nonce", "X-GATE-Body-SHA256", "X-GATE-Signature"
  ]);
});

test("readiness script accepts an exact HTTPS origin and reaches every bounded probe", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "gate-cloudflare-readiness-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const curl = path.join(directory, "curl");
  fs.writeFileSync(curl, [
    "#!/usr/bin/env bash",
    "set -euo pipefail",
    "url=",
    "header_file=",
    "output_file=/dev/null",
    "runner_headers=0",
    "content_type='application/json; charset=utf-8'",
    "previous=",
    "for argument in \"$@\"; do",
    "  if [[ \"$previous\" == --dump-header ]]; then header_file=$argument; fi",
    "  if [[ \"$previous\" == --output ]]; then output_file=$argument; fi",
    "  if [[ \"$previous\" == --header && \"$argument\" == X-GATE-* ]]; then runner_headers=$((runner_headers + 1)); fi",
    "  if [[ \"$argument\" == http://* || \"$argument\" == https://* ]]; then url=$argument; fi",
    "  previous=$argument",
    "done",
    "case \"$url\" in",
    "  http://127.0.0.1:43180/healthz|http://127.0.0.1:43180/readyz) status=200 ;;",
    "  http://127.0.0.1:43179/*) status=404 ;;",
    "  http://127.0.0.1:49312/ready) status=200 ;;",
    "  https://gate.example.test/healthz|https://gate.example.test/readyz) status=404 ;;",
    "  https://gate.example.test/api/runner/v1/lease)",
    "    if [[ ${GATE_TEST_EDGE_REJECTION:-0} == 1 ]]; then",
    "      status=401; content_type=text/html",
    "    elif [[ $runner_headers -eq 5 ]]; then status=401; else status=400; fi",
    "    ;;",
    "  *) status=599 ;;",
    "esac",
    "if [[ -n \"$header_file\" ]]; then",
    "  printf 'HTTP/2 %s\\r\\nContent-Type: %s\\r\\n\\r\\n' \"$status\" \"$content_type\" > \"$header_file\"",
    "fi",
    "if [[ \"$url\" == https://gate.example.test/api/runner/v1/lease && $status -eq 401 && ${GATE_TEST_EDGE_REJECTION:-0} != 1 ]]; then",
    "  printf '%s\\n' '{\"ok\":false,\"error\":{\"code\":\"runner-auth-rejected\",\"message\":\"The runner authentication request was rejected.\"}}' > \"$output_file\"",
    "elif [[ \"$url\" == https://gate.example.test/api/runner/v1/lease && $status -eq 401 ]]; then",
    "  printf '%s\\n' 'Access denied' > \"$output_file\"",
    "fi",
    "printf '%s' \"$status\""
  ].join("\n"), { mode: 0o755 });
  const script = path.join(bundle, "readiness-check.sh");
  assert.notEqual(fs.statSync(script).mode & 0o111, 0);
  const result = spawnSync("bash", [script], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${directory}:${process.env.PATH}`,
      GATE_REMOTE_PUBLIC_ORIGIN: "https://gate.example.test",
      GATE_REMOTE_COORDINATOR_URL: "http://127.0.0.1:43180",
      GATE_REMOTE_GATEWAY_URL: "http://127.0.0.1:43179",
      GATE_REMOTE_CLOUDFLARED_METRICS_URL: "http://127.0.0.1:49312"
    }
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Smoke checks passed/u);

  const edgeRejection = spawnSync("bash", [script], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${directory}:${process.env.PATH}`,
      GATE_TEST_EDGE_REJECTION: "1",
      GATE_REMOTE_PUBLIC_ORIGIN: "https://gate.example.test",
      GATE_REMOTE_COORDINATOR_URL: "http://127.0.0.1:43180",
      GATE_REMOTE_GATEWAY_URL: "http://127.0.0.1:43179",
      GATE_REMOTE_CLOUDFLARED_METRICS_URL: "http://127.0.0.1:49312"
    }
  });
  assert.notEqual(edgeRejection.status, 0);
  assert.match(edgeRejection.stderr, /coordinator JSON content type/u);

  for (const origin of ["http://gate.example.test", "https://gate.example.test/path", "https://user@gate.example.test"]) {
    const rejected = spawnSync("bash", [script], {
      encoding: "utf8",
      env: { ...process.env, PATH: `${directory}:${process.env.PATH}`, GATE_REMOTE_PUBLIC_ORIGIN: origin }
    });
    assert.equal(rejected.status, 2, `${origin}: ${rejected.stderr}`);
  }
});
