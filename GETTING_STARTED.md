# Getting started

GATE is a private, single-operator control plane for agentic engineering and authorized security work. This guide installs the managed core tools, opens the local cockpit, and starts a map-first assessment.

Run the control plane on Linux or on Windows 11 through WSL2. Keep Windows-native tools such as Wireshark, Burp Suite, debuggers, and hardware utilities on Windows. See [Laptop and cloud setup](docs/setup.md) for the complete host setup.

## 1. Bootstrap GATE

Install Git, GitHub CLI, Codex CLI, `curl`, `tar`, Bubblewrap, `prlimit` (from `util-linux` on Ubuntu), and Node.js 22.20 or newer. Node 24 is recommended. Managed installation requires OS- or administrator-owned Git, GitHub CLI, `curl`, `tar`, Node, and npm paths; do not run it as root or through a user-writable Node manager.

```bash
gh auth status >/dev/null 2>&1 || gh auth login
gh auth setup-git
codex login status >/dev/null 2>&1 || codex login

mkdir -p "$HOME/src"
gh repo clone SmurfTurfPawpaw/GATE "$HOME/src/GATE"
cd ~/src/GATE

export GATE_HOME="$HOME/.local/share/gate"
export GH_TOKEN="$(gh auth token)"

./scripts/bootstrap.sh --check-only
./scripts/bootstrap.sh --install-upstreams --install-core-tools
```

Keep `GATE_HOME` outside the repository and outside cloud-synced folders. It contains private plans, target details, authorization records, receipts, evidence, tool installations, and learning records.

The core profile installs integrity-pinned releases of:

- `subfinder`
- `dnsx`
- `httpx`
- `katana`
- `naabu`
- `ffuf`
- `nuclei`

Verify their current bytes and bounded zero-egress version smokes:

```bash
./scripts/smoke.sh --require-core-tools
./bin/gate.mjs tool verify --profile core --json
./bin/gate.mjs tool list \
  --profile core --summary --limit 10 --cursor 0 --json
```

Installation proves exact runtime identity. Target authority and workflow admission are separate checks.

## 2. Open the cockpit

```bash
npm run dashboard
```

Open <http://127.0.0.1:4173> and keep the terminal running. The cockpit shows activity, workflow state, active execution, offline analysis, managed tools, learning, and available Codex token telemetry. Press `?` for keyboard shortcuts, `R` to refresh, and `P` to pause or resume polling. Stop it with `Ctrl+C`.

Use the bounded agent-readable views in terminals and Codex sessions:

```bash
./bin/gate.mjs status --summary --json
./bin/gate.mjs tool list --summary --limit 10 --cursor 0 --json
```

Token data is labelled `exact`, `estimated`, or `unavailable`. Missing telemetry is never reported as zero.

## 3. Start a map-first assessment

For passive research, source review, or offline work that will not contact a target:

```bash
ASSESSMENT_ID="assessment-$(date -u +%Y%m%d-%H%M%S)"

./bin/gate.mjs workflow new "$ASSESSMENT_ID" --json
./bin/gate.mjs workflow phase start "$ASSESSMENT_ID" \
  --phase authorization-and-roe --json
./bin/gate.mjs workflow status "$ASSESSMENT_ID" --json
```

The workflow records authorization and rules of engagement first, then builds the target and trust map before selecting technical workstreams. These commands do not contact a target.

Follow the [end-to-end penetration-testing workflow](docs/pentest-workflow.md) to attach evidence, disposition each workstream, reserve closeout capacity, record target-side changes, clean up in LIFO order, retest, and close the assessment.

For a bug bounty program, complete the [Program Profile wizard](docs/bug-bounty-program-profile.md) first. It records the program sources, exact asset and technique rules, limits, evidence handling, and reporting expectations in private state, then compiles no-contact model context and a compatibility preflight. A compiled profile supports planning; it does not replace the exact engagement, reviewed plan, operator receipt, workflow admission, or execution confirmation required for active target contact.

## 4. Analyze a saved Windows artifact offline

The implemented offline lane inspects PE resources without executing the supplied file or giving the adapter network access.

```bash
mkdir -p "$HOME/.config/gate/projects"
cp templates/project.json "$HOME/.config/gate/projects/my-project.json"

# Edit metadata.id, repository.url, and the remaining project settings.
./bin/gate.mjs project register \
  --file "$HOME/.config/gate/projects/my-project.json" --json
./bin/gate.mjs project verify my-project --json

./bin/gate.mjs analysis capability --json
```

If capability reports that REA is absent, install its integrity-pinned upstream before creating the manifest:

```bash
./bin/gate.mjs upstream install rea-stable --json
```

Then create the one-shot offline manifest:

```bash
./bin/gate.mjs analysis manifest \
  --project my-project \
  --path "$HOME/private/client-installer.exe" \
  --minutes 15 --json
```

Review the returned digest, limits, evidence paths, and `confirmationRequired`, then use that exact confirmation:

```bash
./bin/gate.mjs analysis run \
  --project my-project \
  --manifest MANIFEST_ID \
  --confirm "ANALYZE MANIFEST_ID MANIFEST_SHA256 OFFLINE" \
  --json

./bin/gate.mjs analysis status --json
```

Dynamic Windows execution still needs a resettable Windows Sandbox or VM.

## 5. Prepare active target contact

Active work starts with an exact engagement, written authorization where applicable, a bounded plan, a real No Mistakes review, and the operator receipt for that plan digest. Bind the engagement when creating the workflow:

```bash
./bin/gate.mjs workflow new ACTIVE_WORKFLOW_ID \
  --engagement ENGAGEMENT_ID --json
```

Complete `authorization-and-roe` and `target-and-architecture-map`. Before a target-contact phase can start, attach a reviewed workflow admission that binds the exact target, action, tool mapping, adapter, environment, destinations, limits, and all mandatory stops. See [Target-contact admission and execution](docs/pentest-workflow.md#target-contact-admission-and-execution).

This release has two narrow reviewed active adapters:

- DNSx 1.3.1: one exact-domain `A` observation through one explicit resolver.
- HTTPx 1.12.0: one exact-URL `GET`, dialled through one operator-approved literal IP while preserving the approved Host header and HTTPS SNI.

After the matching `active-surface-validation` phase is admitted, create a typed manifest with no raw argument surface:

```bash
./bin/gate.mjs engagement adapter-manifest ENGAGEMENT_ID \
  --adapter dnsx-domain-observe \
  --workflow WORKFLOW_ID --phase-attempt PHASE_ATTEMPT_ID \
  --target exact.example \
  --record-type A --resolver 192.0.2.53:53 --timeout-seconds 5 \
  --minutes 1 --requests 1 --parallel 1 --rate 1 \
  --tokens 1000 --evidence-bytes 2097152 --json

./bin/gate.mjs engagement adapter-manifest ENGAGEMENT_ID \
  --adapter httpx-url-observe \
  --workflow WORKFLOW_ID --phase-attempt PHASE_ATTEMPT_ID \
  --target https://exact.example/path \
  --method GET --allowed-ip 192.0.2.10 \
  --timeout-seconds 5 --max-response-bytes 65536 \
  --minutes 1 --requests 1 --parallel 1 --rate 1 \
  --tokens 1000 --evidence-bytes 2097152 --json
```

Review the immutable manifest and execute it only with its exact returned confirmation through `gate engagement exec`. DNSx and HTTPx retain broader catalog capabilities, but these adapters admit only the operations above. The other five managed core runtimes remain available for verified planning while their active adapters are added.

## 6. Record learning

When a failure, correction, better tool, or environment constraint changes future behavior, record the cause and the concrete change:

```bash
./bin/gate.mjs learn --private --scope session \
  --cause "Describe what changed the assessment." \
  --change "Describe the specific behavior that will change."
```

Use private learning for target, client, credential, evidence, unpublished finding, or private-path details.

## Current release boundaries

- The catalog describes 126 tools; seven core command-line runtimes have managed installation and verification.
- DNSx and HTTPx have narrow reviewed active adapters. Broader operations and the other tools need matching adapters or the separately reviewed generic lane where eligible.
- Windows dynamic analysis, resettable lab lifecycle, and native GUI-tool control remain separate host workflows.
- Publication commands perform read-only exact-head preflight. Merge, deploy, and publish mutation require a trusted adapter.
- Dashboard token totals depend on local Codex usage records and do not include account quota or billing data.

See [Current limits](README.md#current-limits) for the complete boundary list.
