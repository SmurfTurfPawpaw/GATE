#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"

fail() {
  printf 'smoke: %s\n' "$*" >&2
  exit 1
}

note() {
  printf 'smoke: %s\n' "$*"
}

for command_name in node npm git gh codex; do
  command -v "${command_name}" >/dev/null 2>&1 || fail "missing required command: ${command_name}"
done

cd "${REPO_ROOT}"
[[ -d node_modules ]] || fail "dependencies are absent; run ./scripts/bootstrap.sh first"

export DISABLE_TELEMETRY=1
export DO_NOT_TRACK=1
export GNHF_TELEMETRY=0
export NO_MISTAKES_TELEMETRY=0
export LAVISH_AXI_TELEMETRY=0

note "validating tracked configuration and running tests"
npm run validate

doctor_file="$(mktemp "${TMPDIR:-/tmp}/gate-doctor.XXXXXX")"
status_file="$(mktemp "${TMPDIR:-/tmp}/gate-status.XXXXXX")"
cleanup() {
  rm -f -- "${doctor_file}" "${status_file}"
}
trap cleanup EXIT

node ./bin/gate.mjs doctor --full --json >"${doctor_file}"
node -e '
  const fs = require("node:fs");
  const report = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  if (!report.ok) {
    for (const tool of report.tools.filter((item) => item.required && !item.available)) {
      console.error(`missing required integration: ${tool.id}`);
    }
    process.exit(1);
  }
' "${doctor_file}" || fail "doctor reported a required integration failure"

node ./bin/gate.mjs status --json >"${status_file}"
node -e '
  const fs = require("node:fs");
  const status = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  if (!status.repository || !status.gate_home || !Array.isArray(status.events)) process.exit(1);
' "${status_file}" || fail "status output did not satisfy the smoke contract"

node ./bin/gate.mjs upstream list --json >/dev/null
node ./bin/gate.mjs tool list --profile default --json >/dev/null

if command -v docker >/dev/null 2>&1; then
  note "optional Docker CLI found; engine reachability is not probed automatically (run docker info explicitly)"
else
  note "Docker is optional and was not found; host-first GATE remains usable"
fi

note "all required smoke checks passed"
