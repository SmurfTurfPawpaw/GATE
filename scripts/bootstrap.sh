#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"

CHECK_ONLY=0
INSTALL_UPSTREAMS=0

usage() {
  cat <<'EOF'
Usage: ./scripts/bootstrap.sh [--check-only] [--install-upstreams]

Prepare a Linux, macOS, or WSL checkout of GATE without changing system
packages. The default flow installs the locked npm dependencies, creates the
private GATE runtime, and runs the smoke suite.

Options:
  --check-only         Check the host and authentication without writing files.
  --install-upstreams  Install integrity-pinned managed upstreams after base setup.
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
  if ((INSTALL_UPSTREAMS)); then
    fail "--check-only and --install-upstreams cannot be combined"
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

"${SCRIPT_DIR}/smoke.sh"
note "ready; start the local cockpit with: npm run dashboard"
