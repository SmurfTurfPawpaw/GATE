#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
REQUIRE_CORE_TOOLS="${GATE_REQUIRE_CORE_TOOLS:-0}"

usage() {
  cat <<'EOF'
Usage: ./scripts/smoke.sh [--require-core-tools]

Run the repository validation and local smoke suite. The optional core-tools
check requires installed managed runtimes with current zero-egress verification.

Options:
  --require-core-tools  Require a nonempty installed and byte-verified core pack.
  -h, --help            Show this help.

Environment:
  GATE_REQUIRE_CORE_TOOLS=1  Enable the same managed core runtime assertion.
EOF
}

fail() {
  printf 'smoke: %s\n' "$*" >&2
  exit 1
}

note() {
  printf 'smoke: %s\n' "$*"
}

case "${REQUIRE_CORE_TOOLS}" in
  0|1) ;;
  *) fail "GATE_REQUIRE_CORE_TOOLS must be 0 or 1" ;;
esac

for argument in "$@"; do
  case "${argument}" in
    --require-core-tools) REQUIRE_CORE_TOOLS=1 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown option: ${argument}" ;;
  esac
done

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

if ((REQUIRE_CORE_TOOLS)); then
  node -e '
    const fs = require("node:fs");
    const doctor = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const status = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
    const profile = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
    const coreIds = new Set(profile.toolIds || []);
    if (profile.id !== "core" || coreIds.size < 1) process.exit(1);

    const countCore = (report, key) => {
      if (!report?.ok || !Array.isArray(report.tools)) return 0;
      return report.tools.filter((tool) => coreIds.has(tool.id) && tool[key] === true).length;
    };
    const live = doctor.toolRuntimes;
    const observerStatus = status.toolRuntimes;
    if (
      live?.verificationMode !== "current-bytes-and-live-zero-egress-smoke" ||
      observerStatus?.verificationMode !== "receipt-only" ||
      observerStatus?.currentBytesChecked !== false ||
      observerStatus?.executableHashReads !== 0 ||
      countCore(live, "installed") < 1 ||
      countCore(live, "verified") < 1 ||
      countCore(observerStatus, "installed") < 1 ||
      countCore(observerStatus, "verified") !== 0
    ) process.exit(1);
  ' "${doctor_file}" "${status_file}" "${REPO_ROOT}/config/profiles/core.json" || \
    fail "managed core runtimes are not installed and byte-verified"
  note "managed core runtime assertion passed"
fi

node ./bin/gate.mjs upstream list --json >/dev/null
node ./bin/gate.mjs tool list --profile default --json >/dev/null

if command -v docker >/dev/null 2>&1; then
  note "optional Docker CLI found; engine reachability is not probed automatically (run docker info explicitly)"
else
  note "Docker is optional and was not found; host-first GATE remains usable"
fi

note "all required smoke checks passed"
