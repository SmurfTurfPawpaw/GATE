#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"

CHECK_ONLY=0
INSTALL_UPSTREAMS=0
INSTALL_CORE_TOOLS=0

usage() {
  cat <<'EOF'
Usage: ./scripts/bootstrap.sh [--check-only] [--install-upstreams] [--install-core-tools]

Prepare a Linux, macOS, or WSL checkout of GATE without changing system
packages. The default flow installs the locked npm dependencies, creates the
private GATE runtime, and runs the smoke suite.

Options:
  --check-only         Check the host and authentication without writing files.
  --install-upstreams  Install integrity-pinned managed upstreams after base setup.
  --install-core-tools Download, verify, and install the reviewed core security-tool profile.
  -h, --help           Show this help.

Environment:
  GATE_HOME            Private state root. Defaults to the GATE CLI default.
EOF
}

fail() {
  printf 'bootstrap: %s\n' "$*" >&2
  exit 1
}

note() {
  printf 'bootstrap: %s\n' "$*"
}

for argument in "$@"; do
  case "${argument}" in
    --check-only) CHECK_ONLY=1 ;;
    --install-upstreams) INSTALL_UPSTREAMS=1 ;;
    --install-core-tools) INSTALL_CORE_TOOLS=1 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown option: ${argument}" ;;
  esac
done

case "$(uname -s)" in
  Linux|Darwin) ;;
  MINGW*|MSYS*|CYGWIN*)
    fail "native Windows is not a supported control-plane host; run scripts/bootstrap.ps1 to use WSL2"
    ;;
  *) fail "unsupported host: $(uname -s)" ;;
esac

missing=()
for command_name in git node npm gh codex; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    missing+=("${command_name}")
  fi
done
if ((${#missing[@]})); then
  fail "missing required commands: ${missing[*]}. Follow docs/setup.md, then rerun this script."
fi

node_version="$(node -p 'process.versions.node')"
if ! node -e '
  const [major, minor] = process.versions.node.split(".").map(Number);
  process.exit(major > 22 || major === 22 && minor >= 20 ? 0 : 1);
'; then
  fail "Node ${node_version} is too old; GATE needs Node 22.20 or newer and recommends Node 24"
fi
if ! node -e 'process.exit(Number(process.versions.node.split(".")[0]) === 24 ? 0 : 1)'; then
  note "Node ${node_version} is supported; Node 24 is recommended for the broadest pinned-upstream compatibility."
fi

git -C "${REPO_ROOT}" rev-parse --show-toplevel >/dev/null 2>&1 || fail "${REPO_ROOT} is not a Git checkout"
[[ -f "${REPO_ROOT}/package-lock.json" ]] || fail "package-lock.json is missing"
[[ -f "${REPO_ROOT}/config/gate.config.json" ]] || fail "config/gate.config.json is missing"

if [[ -z "${GH_TOKEN:-}" && -z "${GITHUB_TOKEN:-}" ]]; then
  fail 'GitHub release installation requires GH_TOKEN or GITHUB_TOKEN; after gh auth login, run: export GH_TOKEN="$(gh auth token)"'
fi
gh auth status >/dev/null 2>&1 || fail "the exported GitHub token is not accepted; refresh GH_TOKEN or GITHUB_TOKEN"
codex login status >/dev/null 2>&1 || fail "Codex CLI is not authenticated; run: codex login"

if [[ -n "${WSL_DISTRO_NAME:-}" ]] || grep -qi microsoft /proc/sys/kernel/osrelease 2>/dev/null; then
  note "detected WSL2 (${WSL_DISTRO_NAME:-unknown distribution})"
fi

note "host preflight passed (Node ${node_version}, npm $(npm --version), Git $(git --version | awk '{print $3}'))"

if ((CHECK_ONLY)); then
  if ((INSTALL_UPSTREAMS || INSTALL_CORE_TOOLS)); then
    fail "--check-only cannot be combined with an install option"
  fi
  note "check-only complete; no files were intentionally changed"
  exit 0
fi

export DISABLE_TELEMETRY=1
export DO_NOT_TRACK=1
export GNHF_TELEMETRY=0
export NO_MISTAKES_TELEMETRY=0
export LAVISH_AXI_TELEMETRY=0
export NPM_CONFIG_IGNORE_SCRIPTS=true

cd "${REPO_ROOT}"
note "installing the repository lock with lifecycle scripts disabled"
npm ci

note "creating private runtime directories"
node ./bin/gate.mjs bootstrap --json

if ((INSTALL_UPSTREAMS)); then
  note "installing integrity-pinned managed upstreams into GATE_HOME"
  node ./bin/gate.mjs upstream install all --json
fi

smoke_arguments=()
if ((INSTALL_CORE_TOOLS)); then
  case "$(uname -s)" in
    Linux) ;;
    *) fail "--install-core-tools currently requires Linux or WSL2 for the zero-egress smoke sandbox" ;;
  esac

  core_install_file="$(mktemp "${TMPDIR:-/tmp}/gate-core-install.XXXXXX")"
  cleanup_core_install() {
    rm -f -- "${core_install_file}"
  }
  trap cleanup_core_install EXIT

  note "downloading and installing the reviewed core security-tool profile"
  if ! node ./bin/gate.mjs tool install --profile core --json >"${core_install_file}"; then
    cat -- "${core_install_file}"
    fail "the reviewed core security-tool profile did not install completely"
  fi
  cat -- "${core_install_file}"
  node -e '
    const fs = require("node:fs");
    const result = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const counts = result.counts || {};
    if (
      result.operation !== "install" ||
      result.selector?.type !== "profile" ||
      result.selector?.id !== "core" ||
      result.ok !== true ||
      result.complete !== true ||
      !Number.isInteger(counts.selected) ||
      counts.selected < 1 ||
      counts.installed !== counts.selected ||
      counts.verified !== counts.selected ||
      counts.unresolved !== 0
    ) process.exit(1);
  ' "${core_install_file}" || fail "core install output did not satisfy the reviewed profile contract"
  smoke_arguments+=(--require-core-tools)
fi

"${SCRIPT_DIR}/smoke.sh" "${smoke_arguments[@]}"
note "ready; start the local cockpit with: npm run dashboard"
