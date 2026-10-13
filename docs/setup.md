# Laptop and cloud setup

GATE uses the laptop as its primary execution environment. On Windows, the control plane runs in WSL2 while hardware-facing and Windows-target tools stay native. Docker is optional and organizes conflicting command-line stacks; the base workflow does not depend on it.

The setup has four layers:

1. Windows provides Codex access to the laptop, native browsers, certificate stores, packet capture, USB devices, and Windows applications.
2. WSL2 provides the Linux control plane, Git worktrees, Node tooling, and agent CLIs.
3. GATE keeps private runtime state outside the public repository.
4. Planned pinned OCI profiles will provide repeatable dependency-heavy tool environments. The repository does not ship Docker Compose tool profiles in v0.1.

## Supported baseline

The recommended Windows baseline is:

- Windows 11 with current WSL2 and Ubuntu 24.04;
- Git, GitHub CLI, and Codex CLI inside WSL;
- Node 24.x with npm 11.x; the minimum for the GATE package is Node 22.20;
- Python 3.12 managed by `uv` for isolated Python tools;
- Go installed only when a pinned Go upstream requires it;
- Docker Desktop with WSL integration when OCI tool profiles are needed;
- Wireshark with Npcap, Burp Suite or OWASP ZAP, and hardware-specific utilities installed on Windows when they need host integration.

Node 24 is the common compatible choice for GATE, the Skills CLI, AXI, Lavish, GNHF, and current REA work. Python 3.12 has broader security-tool compatibility than using the newest interpreter globally. GATE's target `isolated-python` lane gives each admitted Python tool its own environment; that general per-tool installer is not implemented in v0.1.

## 1. Prepare WSL2 on Windows

Open an elevated PowerShell and run:

```powershell
wsl --install -d Ubuntu-24.04
wsl --update
```

Restart Windows if requested. The ordinary lifecycle does not need an AI:

```powershell
wsl -d Ubuntu-24.04
wsl --shutdown
```

Inside Ubuntu, install the small native base:

```bash
sudo apt update
sudo apt install --yes build-essential ca-certificates curl git jq tmux unzip
```

Install Node 24 from the official Node.js distribution or a version manager you already trust, then verify it:

```bash
node --version
npm --version
```

Install and authenticate the two required CLIs inside WSL:

```bash
sudo apt install --yes gh
npm install --global @openai/codex
gh auth login
codex login
gh auth status
codex login status
```

If Codex was installed by another supported method, keep that installation and only run the verification commands.

## 2. Clone into the WSL filesystem

Git worktrees and file watching are faster and more predictable under the WSL filesystem than under `/mnt/c`. From the Ubuntu shell:

```bash
mkdir -p ~/src
cd ~/src
git clone https://github.com/SmurfTurfPawpaw/GATE.git
cd GATE
```

If the repository is already checked out on a Windows drive, `scripts/bootstrap.ps1` can launch it through WSL, but it will warn about the slower mount.

## 3. Bootstrap GATE

First run the read-only preflight:

```bash
./scripts/bootstrap.sh --check-only
```

Then prepare the locked JavaScript dependencies and private runtime:

```bash
./scripts/bootstrap.sh
```

The script runs `npm ci` with package lifecycle scripts disabled, creates the private runtime with `gate bootstrap`, and executes the smoke suite. It does not install system packages or broad security suites.

By default, private state is stored under `~/.local/share/gate`. Set `GATE_HOME` before bootstrap if it belongs on another local disk:

```bash
export GATE_HOME="$HOME/.local/share/gate"
./scripts/bootstrap.sh
```

Keep this directory out of cloud-synced folders and Git. It contains events, private learnings, engagement records, plans, and evidence.

Keep upstream telemetry disabled in interactive shells as well as bootstrap runs. Add these values to the WSL shell profile used for GATE:

```bash
export DO_NOT_TRACK=1
export DISABLE_TELEMETRY=1
export GNHF_TELEMETRY=0
export NO_MISTAKES_TELEMETRY=0
export LAVISH_AXI_TELEMETRY=0
```

Restart the shell after editing the profile. A later explicit operator choice may enable a named provider, but GATE's default remains disabled.

GATE-managed npm and verified-release upstreams can be installed into this private root after the base smoke test passes:

```bash
./scripts/bootstrap.sh --install-upstreams
```

For npm upstreams, this verifies the committed dependency-lock digest recorded in `locks/upstreams.lock.json`, runs `npm ci` with lifecycle scripts disabled, and verifies the installed tree against a second offline reconstruction. Full integrity checks later repeat that clean reconstruction from the lock and GATE's integrity-addressed npm cache before comparing the deterministic tree digest. On supported hosts, bootstrap also downloads the locked Treehouse and No Mistakes GitHub release artifacts, rejects unsafe archive entries, and verifies the locked archive and executable SHA-256 values. It records version metadata from the reviewed lock and deliberately does not execute the freshly downloaded binary during installation. Receipts are evidence; the reviewed repository locks remain the trust anchor. Source, skill, native, GUI, and hardware tools follow their own reviewed lanes.

`gate upstream sync` always builds a fresh staged source clone with system and global Git configuration and templates isolated, verifies it against the locked commit, then atomically replaces the managed checkout. Full readiness compares the commit tree, index, and raw worktree bytes and rejects Git replacement mechanisms, hidden index flags, and every extra path, including ignored files and empty directories. Submodules are not initialized in v0.1 and therefore fail source readiness. Do not keep local work in a GATE-managed upstream checkout.

From Windows PowerShell, the equivalent launcher is:

```powershell
.\scripts\bootstrap.ps1 -Distribution Ubuntu-24.04
.\scripts\smoke.ps1 -Distribution Ubuntu-24.04
```

## 4. Run and inspect

These commands use the current package interface:

```bash
npm run doctor
npm run validate
npm run dashboard
```

For ordinary repository work, start Codex with only the checkout writable:

```bash
codex -C "$HOME/src/GATE" --sandbox workspace-write --ask-for-approval on-request --search
```

Only add private state for a task that must run GATE control commands, and expose the narrowest suitable path. Adding the whole root is a deliberate trusted-session choice:

```bash
export GATE_HOME="${GATE_HOME:-$HOME/.local/share/gate}"
codex -C "$HOME/src/GATE" --add-dir "$GATE_HOME" \
  --sandbox workspace-write --ask-for-approval on-request --search
```

In v0.1, any process with write access to all of `GATE_HOME` can change local engagement records, unsigned approval receipts, and evidence. It can therefore forge local engagement consistency by rewriting both state and receipt. Managed-upstream bytes remain anchored to the reviewed repository locks rather than their writable installation receipts. Keep credential values outside this broad writable root in an OS secret store or narrowly permissioned file, and use symbolic references in GATE state.

Operations that need Npcap, a debugger, a certificate store, USB, or another host capability are operator-run native operations today. Record their versions, exact commands, and bounded evidence manually. Narrow native capability providers and their event bridges are a target design; v0.1 does not supply them.

The dashboard binds to `127.0.0.1:4173` by default. Open `http://127.0.0.1:4173` from Windows. WSL normally forwards the loopback port automatically. Do not bind the observer to a LAN address; it is a local view of private operational state.

Run the smoke suite after a runtime, dependency, or host change:

```bash
./scripts/smoke.sh
```

The smoke suite validates schemas and pins, runs the tests, verifies required CLIs, exercises status and catalog reads, and reports only the presence of optional executables such as Docker. It does not execute optional tools or probe the Docker engine.

## Optional Docker provider

Install Docker Desktop on Windows only when a selected tool profile needs OCI. Enable its WSL integration for Ubuntu, then verify from WSL:

```bash
docker version
docker compose version
docker info
```

Docker is useful for reproducible command-line dependencies. Native Windows installs remain the correct lane for Wireshark/Npcap capture, Windows trust-store interception, Burp's desktop UI, Sysinternals, WinDbg, USB/ADB, GPU tools, and radio hardware.

A container is not a security boundary once it receives host networking, raw devices, broad capabilities, privileged mode, or the Docker socket. GATE must display and record those effects before using such a profile.

## Native security-tool bridge

Install host-integrated tools from their official distribution channels. At minimum, the first Windows security profile should expose:

- Wireshark and TShark with Npcap for host traffic capture and saved-capture analysis;
- OWASP ZAP as the open-source intercepting proxy and scanner;
- Burp Suite as an optional user-licensed provider;
- Sysinternals and WinDbg for Windows process, filesystem, and debugger evidence;
- Android platform tools when a mobile engagement needs USB or ADB.

The target design treats each native program as a provider: a probe records its executable path and version, and an adapter supplies explicit arguments and evidence destinations. v0.1 provides catalog metadata and executable discovery, not these native probes or adapters. Until they exist, verify the program manually, record bounded evidence, and do not add an entire installation directory to prompts or grant an agent an unrestricted shell merely because the program is installed.

Kali can be added later as a named WSL distribution or pinned container image. It is a compatibility toolbox, not GATE's version source. The catalog and lock records remain authoritative for the tools an agent may select.

## Cloud environment

Codex cloud is suitable for repository edits, tests, builds, static analysis, and offline evidence processing when the selected image provides the required CLIs. Run the preflight on each image rather than assuming Node, npm, GitHub CLI, Codex CLI, Python, or Docker is present. The base bootstrap and tests can use a worker-local writable `GATE_HOME` such as `/tmp/gate`.

Managed cloud workers may lack raw sockets, packet interfaces, debugger attachment, USB devices, kernel capabilities, and unrestricted target routing. In v0.1, `gate doctor --full` reports the OS, architecture, WSL detection, repository validation, presence-only results for optional executables, visible non-loopback interfaces, Linux `CAP_NET_RAW` and `CAP_NET_ADMIN`, Yama `ptrace_scope`, `/dev/bus/usb` presence, and whether the default Linux Docker socket path exists. It deliberately leaves Docker-engine reachability unprobed and does not execute optional tools. Those facts do not prove that debugger attachment, a specific capture, USB hardware, Docker, or target routing works. Probe the exact required capability before planning work and record an unavailable result when it cannot run. Live capture, interception of Windows applications, device analysis, and low-level active testing should remain on a deliberately configured laptop or lab until a narrow provider exists.

Example cloud smoke run:

```bash
export GATE_HOME=/tmp/gate
./scripts/bootstrap.sh
```

## Troubleshooting

If bootstrap reports an authentication failure, repair it directly and rerun:

```bash
gh auth login
codex login
```

If the dashboard does not open from Windows, confirm it is listening inside WSL and retry the loopback address:

```bash
curl http://127.0.0.1:4173/api/status
```

If Docker commands exist but `docker info` fails, start Docker Desktop and confirm WSL integration for the selected distribution. Docker remains optional for base GATE operation.

If a tool is missing, inspect its catalog plan before installing it:

```bash
node ./bin/gate.mjs tool plan TOOL_ID --json
```

Use the catalog's installation lane. Record any setup failure or compatibility workaround as a cause-to-change learning before promoting it into the shared defaults.
