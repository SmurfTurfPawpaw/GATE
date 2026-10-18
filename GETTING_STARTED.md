# Getting started

GATE is a local-first, single-operator control plane for agentic engineering and authorized security work. Its reusable source is public; private plans, target details, authorization records, evidence, credentials, and runtime state stay outside Git under `GATE_HOME`. This guide installs the managed core tools, opens the aggregate local cockpit, and starts a map-first assessment in its own bug-program case.

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
unset GATE_CASE

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
# Terminal 1: keep GATE_CASE unset so the observer builds the bounded fleet view.
unset GATE_CASE
# If Codex runs on Windows and GATE runs in WSL, point the observer at that
# existing Codex state. Replace WINDOWS_USER; do not commit the local path.
# export CODEX_HOME="/mnt/c/Users/WINDOWS_USER/.codex"
npm run dashboard

# Terminal 2, from the same GATE checkout:
unset GATE_CASE
codex login status >/dev/null 2>&1 || codex login
npm run cockpit
```

Keep both terminals running. The companion prints and normally opens a private capability-bearing URL on an ephemeral loopback port. It provides the progress-first cockpit, one dedicated Codex thread, bounded operator and final Codex messages, native one-to-three-choice questions, categorical activity, exact companion input/cached-input/output/total counters, estimated thread cost when Codex supplies it, and the observer's separate bounded fleet projection. Keep its URL fragment private. The companion does not attach to the current Codex cloud chat, show hidden reasoning or raw command output, or grant execution authority. See [Local cockpit companion](docs/local-companion.md).

The observer remains available directly at <http://127.0.0.1:4173> for detailed read-only diagnostics. The startup terminal and selected case detail greet the operator using `operator.displayName` from the merged configuration. The tracked default is `Giovanni`.

The observer dashboard uses a compact table for concurrent campaigns. It shows at most 32 case rows from a discovery window of 1,024 entries, plus a separately bounded set of current Program Profile setup rows that are not represented in the current bounded case projection. When the case scan is partial, an off-projection current case may still exist. Select a row to open the single live-activity or setup-detail panel. Setup rows expose only pseudonymous progress, blocker, next-section, readiness, and freshness metadata. Recommendation mode is nullable and appears only when a reviewed producer supplies it; learning count remains unavailable on a setup-only row because learning attribution is case-backed. Case rows and details include the operator-controlled case display name, so keep sensitive selectors out of that name. The remaining content is allowlisted lifecycle data. Apart from that display name, neither view is an interactive PTY or shows raw stdout or stderr, argv, commands, exact target selectors, answers, sources, evidence, or private paths.

Fleet summary cards distinguish exact counts, lower bounds (`+`), and unavailable observations (`—`); see the [count precision and cached-state rules](docs/architecture.md#observation-and-token-accounting). Scan text keeps omissions, invalid entries, partial coverage, and a failed setup scan visible. Active fresh work uses an indeterminate animation because GATE has no defensible percentage unless a producer supplies actual completed and total counts. Retrieve a known omitted case with `gate case show ID --json` or `gate --case ID status --summary --json`; removing `--summary` does not bypass fleet or recent-history bounds. Press `0` to focus the fleet, `1` to open the selected detail, `2` to open System health, arrow keys or `[` and `]` to change campaigns, `?` for all shortcuts, `R` to refresh, and `P` to pause or resume polling. Stop the observer with `Ctrl+C`.

The public Pages site is a separate, non-interactive design preview. Its checked-in data is explicitly labeled `PREVIEW · NOT LIVE`; the build excludes the local companion, observer responses, capabilities, prompts, targets, and private state.

To steer a dedicated laptop Codex thread from another device, use the separate [remote cockpit bridge](docs/remote-cockpit.md). It needs an authenticated HTTPS coordinator on an always-on host and an outbound signed runner on the laptop. It does not attach to this cloud chat and it does not make the Pages preview interactive. Finish the coordinator, identity, storage, and runner readiness checks before describing it as live.

Use the bounded agent-readable views in terminals and Codex sessions:

```bash
./bin/gate.mjs status --summary --json
./bin/gate.mjs tool list --summary --limit 10 --cursor 0 --json
```

See the [companion display rules](docs/local-companion.md#what-is-working) for compact status, token provenance, and missing-attribution labels.

## 3. Route a new objective

Start with the outcome, even when it is not a bug bounty program. Ask the agent to use the [`gate-objective-router` skill](skills/gate-objective-router/SKILL.md). It derives a categorical proposal from conversation material permitted for the configured provider, writes only that bounded proposal to a private file outside the repository, and runs the following command. The file must be owned by the current user with exact mode `0600` on POSIX or WSL2; native Windows ACL ownership is not verified.

```bash
unset GATE_CASE
./bin/gate.mjs objective recommend \
  --proposal "$GATE_HOME/input/objective-routing.json" --json
```

The operator does not have to design the workflow or write raw JSON. The agent recommends the route, evidence plan, capabilities, and bounded next actions, then asks no more than one to three registered choices when material facts remain unresolved. Unknown or mixed work is clarified or split first. For example, a report about unexplained meal-delivery orders and payment activity routes to a security-incident investigation; it does not become a bug bounty Program Profile unless a separate authorized bounty objective is established.

The command is deterministic and planning-only. Its categorical schema provides no dedicated field for the raw objective or exact private values; the agent must also generate opaque handles and references instead of encoding private values into them. The output projects caller-controlled metadata, does not persist or dispatch the objective, and always carries `executionAuthority: false`. The selected domain workflow owns its later evidence, access, authorization, confirmation, and execution steps. See [Objective routing](docs/objective-routing.md) for the exact envelope and current limits.

## 4. Create a case and start a map-first assessment

Create one private Program Profile, then use the local browser wizard for the normal choice-first flow:

```bash
unset GATE_CASE
./bin/gate.mjs bounty profile create example-program --apply-recommended --json
./bin/gate.mjs bounty profile ui example-program --open
```

The initialization command applies only eligible reviewed deterministic preferences. The UI command binds an ephemeral server to loopback, prints its private session URL, optionally opens it on the same laptop, and remains attached until you press `Ctrl+C`. It edits exactly one profile through native fields, guided contacts and sources, section navigation, and per-question or bulk recommendations. Existing explicit answers win; unsupported, unverified, source-missing, authority-confirmation, and attestation questions remain for review. Keep the printed session URL private. The aggregate observer is a separate read-only service; see [Open the cockpit](#2-open-the-cockpit) for the interactive companion.

If you prefer the numbered terminal fallback, or want to resume without the browser:

```bash
./bin/gate.mjs bounty profile resume example-program
./bin/gate.mjs bounty profile verify example-program --json
```

For contact entry choices, deferral, and recovery from an older running terminal, see the [browser wizard and terminal fallback](docs/bug-bounty-program-profile.md#browser-wizard-and-terminal-fallback).

Follow the [Program Profile intake](docs/bug-bounty-program-profile.md) for the browser form, preferred Codex-native choice skill, terminal fallback, and headless answer and recommendation envelopes. The profile must be current and ready before case creation.

Create an immutable case for that exact profile. Add `--project my-project` only when a registered managed project is already available and this case needs its provenance for offline analysis:

```bash
./bin/gate.mjs case create example-web \
  --program example-program \
  --name "Example web program" --json

./bin/gate.mjs case list --json
./bin/gate.mjs case show example-web --json
```

Open a separate terminal for each concurrent program and select its case once. An explicit leading `--case ID` is equivalent. If both are present, they must match. Every engagement and workflow command, Program Profile compilation, and `analysis manifest`, `run`, `purge`, or `status` requires an explicit runtime selector. Leading `--unassigned` selects the writable base-state compatibility namespace and can create new unscoped records; it opts out of case attribution and state separation. GATE never chooses it implicitly, so prefer a case for program work.

```bash
export GATE_CASE=example-web

ASSESSMENT_ID="assessment-$(date -u +%Y%m%d-%H%M%S)"

./bin/gate.mjs workflow new "$ASSESSMENT_ID" --json
./bin/gate.mjs workflow phase start "$ASSESSMENT_ID" \
  --phase authorization-and-roe --json
./bin/gate.mjs workflow status "$ASSESSMENT_ID" --json
```

The target-specific Program Profile remains in GATE's shared private profile registry. The selected case places campaign execution observations, events, engagements, workflows, execution state, offline-analysis state, evidence, token records, and private learning under `GATE_HOME/cases/example-web/state`; its immutable scope binds that Program Profile and an optional managed project by digest. If a bound source record changes, the case becomes stale; create a new case rather than rewriting its scope.

For parallel programs, follow the [campaign acceptance and GATE improvement checklist](docs/campaign-acceptance.md). It verifies that profile intake, case state, live activity, resources, and learning stay correctly attributed while reusable improvements move through a separate sanitized and reviewed path.

Setup and shared-registry commands reject `--case`, `GATE_CASE`, and `--unassigned`. This includes `bootstrap`, `doctor`, `validate`, `up`, project, case, workspace, upstream, tool, publication, Program Profile intake, and `analysis capability`. Run those from a separate terminal with `GATE_CASE` unset, as the cockpit example does. Plain `gate status` aggregates the bounded case fleet, `gate --unassigned status` reads only base state, and `gate --case ID status` reads one case. Events and private learning without a selector also use base state.

This directory boundary prevents accidental state mixing between programs. Processes still share the same user, host, credentials available to that user, kernel, and network. Network containment depends on the admitted adapter or execution environment. Case selection grants no target authority.

The workflow records authorization and rules of engagement first, then builds the target and trust map before selecting technical workstreams. These commands do not contact a target.

Follow the [end-to-end penetration-testing workflow](docs/pentest-workflow.md) to attach evidence, disposition each workstream, reserve closeout capacity, record target-side changes, clean up in LIFO order, retest, and close the assessment.

A compiled Program Profile supports planning, and the case preserves its exact identity. Neither replaces the exact engagement, reviewed plan, operator receipt, workflow admission, or execution confirmation required for active target contact.

## 5. Analyze a saved Windows artifact offline

The implemented offline lane inspects PE resources without executing the supplied file or giving the adapter network access.

```bash
# The first example case has no project binding. Leave it before registering
# the shared project, then create a new project-bound case for this lane.
unset GATE_CASE

mkdir -p "$HOME/.config/gate/projects"
cp templates/project.json "$HOME/.config/gate/projects/my-project.json"

# Edit metadata.id, repository.url, and the remaining project settings.
./bin/gate.mjs project register \
  --file "$HOME/.config/gate/projects/my-project.json" --json
./bin/gate.mjs project verify my-project --json

./bin/gate.mjs case create example-artifact \
  --program example-program \
  --project my-project \
  --name "Example artifact analysis" --json

./bin/gate.mjs analysis capability --json
```

If capability reports that REA is absent, install its integrity-pinned upstream before creating the manifest:

```bash
./bin/gate.mjs upstream install rea-stable --json
```

Then create the one-shot offline manifest:

```bash
export GATE_CASE=example-artifact

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

## 6. Prepare active target contact

Active work starts with an exact engagement, written authorization where applicable, a bounded plan, a real No Mistakes review, and the operator receipt for that plan digest. Bind the engagement when creating the workflow:

```bash
export GATE_CASE=example-web
./bin/gate.mjs workflow new ACTIVE_WORKFLOW_ID \
  --engagement ENGAGEMENT_ID --json
```

Complete `authorization-and-roe` and `target-and-architecture-map`. Before a target-contact phase can start, attach a reviewed workflow admission that binds the exact target, action, tool mapping, adapter, environment, destinations, limits, and all mandatory stops. See [Target-contact admission and execution](docs/pentest-workflow.md#target-contact-admission-and-execution).

This release has two narrow reviewed active adapters:

- DNSx 1.3.1: one exact-domain `A` observation through one explicit resolver.
- HTTPx 1.12.0: one exact-URL `GET`, dialled through one operator-approved literal IP while preserving the approved Host header and HTTPS SNI.

After the matching `active-surface-validation` phase is admitted, retain its `activePhase.attemptId`, `activePhase.toolId`, and the workflow `contract.sha256` from `workflow status`. Before creating a manifest, consult the exact learning projection for that workflow contract, phase, and admitted tool. This DNSx example uses the default consultation limits that `workflow test plan` will recompute:

```bash
mkdir -p "$GATE_HOME/input"
cat >"$GATE_HOME/input/active-surface-learning.json" <<'JSON'
{
  "applicability": [
    {
      "kind": "workflow",
      "id": "pentest-e2e",
      "version": "2",
      "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    { "kind": "phase", "id": "active-surface-validation" },
    { "kind": "tool", "id": "dnsx" }
  ]
}
JSON
chmod 600 "$GATE_HOME/input/active-surface-learning.json"

./bin/gate.mjs learn consult \
  --file "$GATE_HOME/input/active-surface-learning.json" \
  --limit 8 --max-bytes 4096 --json
```

Replace the example workflow digest with `contract.sha256`. If the admission uses HTTPx, replace the tool reference with `httpx` and rewrite the hypothesis, method, and signals for that exact HTTP request. The plan's applicability must equal this runtime-derived workflow, phase, and optional tool set; v0.1 rejects every extra reference. Copy the complete applicability array, returned `selected[].id` values in order, `ledgerHeadSha256`, and `projectionSha256` into the first private test plan:

```bash
cat >"$GATE_HOME/input/active-surface-test-plan.json" <<'JSON'
{
  "phaseId": "active-surface-validation",
  "attemptId": "wpa_0123456789abcdef0123456789abcdef",
  "hypothesis": "The exact approved name resolves through the admitted resolver.",
  "method": "Send one admitted DNS A observation and preserve its execution result.",
  "expectedSignal": "The bounded result contains one validated A response.",
  "contrarySignal": "The bounded result is empty, invalid, or contradicts the mapped name.",
  "learningApplicability": [
    {
      "kind": "workflow",
      "id": "pentest-e2e",
      "version": "2",
      "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    { "kind": "phase", "id": "active-surface-validation" },
    { "kind": "tool", "id": "dnsx" }
  ],
  "learningIds": [],
  "learningLedgerHeadSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "learningProjectionSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "basisEvidenceSha256": [],
  "priorReviewEntrySha256": null,
  "adaptation": null
}
JSON
chmod 600 "$GATE_HOME/input/active-surface-test-plan.json"

./bin/gate.mjs workflow test plan WORKFLOW_ID \
  --file "$GATE_HOME/input/active-surface-test-plan.json" --json
```

Replace the attempt ID, applicability values, selected learning IDs, and consultation digests with the immediately preceding results. Retain the plan's `event.details.testId` and `event.headSha256`. With exactly one test plan open, create one typed manifest; its reservation automatically binds that test and plan entry. The following commands are alternatives for matching admissions, not a sequence to run together:

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

```bash
./bin/gate.mjs engagement exec ENGAGEMENT_ID \
  --manifest MANIFEST_ID \
  --confirm "EXECUTE MANIFEST_ID MANIFEST_SHA256 UNMETERED" \
  --json
```

After the run is terminal, add its exact result file as the required inventory and add the reconciliation created from that result. The inventory digest must therefore equal the linked execution result digest:

```bash
./bin/gate.mjs workflow evidence add WORKFLOW_ID \
  --phase active-surface-validation \
  --evidence active-surface-inventory \
  --claim observed \
  --file "$GATE_HOME/evidence/execution-RUN_ID-result.json" \
  --json

./bin/gate.mjs workflow evidence add WORKFLOW_ID \
  --phase active-surface-validation \
  --evidence hypothesis-reconciliation \
  --claim inferred \
  --file "$HOME/private/hypothesis-reconciliation.json" \
  --json
```

Retain both returned `event.details.sha256` values. A supported or contradicted target-contact review must follow the completed reservation, include the linked execution result digest, and cite only evidence added after the plan:

```bash
cat >"$GATE_HOME/input/active-surface-test-review.json" <<'JSON'
{
  "testId": "wtest_0123456789abcdef0123456789abcdef",
  "phaseId": "active-surface-validation",
  "attemptId": "wpa_0123456789abcdef0123456789abcdef",
  "planEntrySha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  "disposition": "supported",
  "observation": "The admitted DNS observation returned the expected in-scope A response.",
  "evidenceSha256": [
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  ],
  "metrics": { "requests": 1, "tokens": "unavailable" },
  "usefulMistake": null,
  "nextStrategy": {
    "decision": "stop",
    "rationale": "The bounded observation resolved this hypothesis."
  }
}
JSON
chmod 600 "$GATE_HOME/input/active-surface-test-review.json"

./bin/gate.mjs workflow test review WORKFLOW_ID \
  --file "$GATE_HOME/input/active-surface-test-review.json" --json

./bin/gate.mjs workflow phase finish WORKFLOW_ID \
  --phase active-surface-validation \
  --disposition tested --json
```

Replace every example ID and digest with the plan and evidence results. A failed, blocked, or ambiguous run needs the matching review disposition and rationale; do not reuse the successful example. A target-contact phase reaches `tested` only after its required evidence exists and a reviewed cycle is bound to the successfully completed execution's result evidence added after completion; no reservation may remain pending.

## 7. Record and apply adaptive learning

Use the private workflow journal for immediate test feedback and the learning ledger for reusable behavior changes. Store input files under `GATE_HOME`, keep them owner-only, and substitute IDs and digests returned by your own workflow.

Before planning, request the small learning projection that exactly matches the work:

```bash
mkdir -p "$GATE_HOME/input"
cat >"$GATE_HOME/input/learning-consult.json" <<'JSON'
{
  "applicability": [
    {
      "kind": "workflow",
      "id": "pentest-e2e",
      "version": "2",
      "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    { "kind": "phase", "id": "authorization-and-roe" }
  ]
}
JSON
chmod 600 "$GATE_HOME/input/learning-consult.json"

./bin/gate.mjs learn consult \
  --file "$GATE_HOME/input/learning-consult.json" \
  --limit 8 --max-bytes 4096 --json
```

Consultation returns only public, sanitized, active lessons with that exact applicability set. Replace the example workflow digest with `contract.sha256` from `workflow status`. Every test plan's applicability must equal exactly one workflow reference with its current version and digest, exactly one reference to the active phase, and the exact admitted tool reference when the active phase has one; v0.1 accepts no additional references. Retain the applicability array, `selected[].id`, `ledgerHeadSha256`, and `projectionSha256` together. Copy the selected IDs in their returned order and both returned digests into the plan even when `selected` is empty. `workflow test plan` recomputes this default 8-record, 4096-byte consultation and rejects stale values, unresolved conflicts, or any omitted applicable lesson.

Create the first private test plan for the active phase attempt:

```bash
cat >"$GATE_HOME/input/test-plan.json" <<'JSON'
{
  "phaseId": "authorization-and-roe",
  "attemptId": "wpa_0123456789abcdef0123456789abcdef",
  "hypothesis": "One bounded observation may distinguish the two current explanations.",
  "method": "Exercise one admitted path and preserve its exact evidence.",
  "expectedSignal": "The response contains the discriminating marker.",
  "contrarySignal": "The response omits the marker or contradicts the hypothesis.",
  "learningApplicability": [
    {
      "kind": "workflow",
      "id": "pentest-e2e",
      "version": "2",
      "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    { "kind": "phase", "id": "authorization-and-roe" }
  ],
  "learningIds": [],
  "learningLedgerHeadSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "learningProjectionSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "basisEvidenceSha256": [],
  "priorReviewEntrySha256": null,
  "adaptation": null
}
JSON
chmod 600 "$GATE_HOME/input/test-plan.json"

./bin/gate.mjs workflow test plan "$ASSESSMENT_ID" \
  --file "$GATE_HOME/input/test-plan.json" --json
```

Replace the example attempt ID with the active `attemptId`, and replace both learning digests with the values returned by the immediately preceding consultation. Retain the plan's returned `event.details.testId` and `event.headSha256`, then bind both into the review:

```bash
cat >"$GATE_HOME/input/test-review.json" <<'JSON'
{
  "testId": "wtest_0123456789abcdef0123456789abcdef",
  "phaseId": "authorization-and-roe",
  "attemptId": "wpa_0123456789abcdef0123456789abcdef",
  "planEntrySha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "disposition": "inconclusive",
  "observation": "The response was stable but did not distinguish the explanations.",
  "evidenceSha256": [],
  "metrics": { "duration-ms": 1200, "tokens": "unavailable" },
  "usefulMistake": {
    "cause": "The first method varied two conditions at once.",
    "change": "Vary one condition at a time in the next test."
  },
  "nextStrategy": {
    "decision": "iterate-within-current-envelope",
    "rationale": "A single-variable comparison can resolve the ambiguity."
  }
}
JSON
chmod 600 "$GATE_HOME/input/test-review.json"

./bin/gate.mjs workflow test review "$ASSESSMENT_ID" \
  --file "$GATE_HOME/input/test-review.json" --json
```

Use only evidence digests already known to this workflow. The next plan must set `priorReviewEntrySha256` to this review's returned `event.headSha256` and give a one-line `adaptation`. One workflow can have only one open test cycle. Planning and reviewing record feedback; they do not execute a test or change its authority. Launches still use the separately admitted engagement adapters.

When a result warrants a reusable change, record a structured private candidate:

```bash
cat >"$GATE_HOME/input/learning-cycle.json" <<'JSON'
{
  "trigger": "strategy-improvement",
  "domain": "active-testing",
  "cycle": {
    "hypothesis": "A single-variable comparison will produce a clearer oracle.",
    "method": "Repeat the bounded test while changing one condition only.",
    "outcome": {
      "disposition": "confirmed",
      "summary": "The isolated condition produced a stable discriminating signal."
    },
    "lesson": "Change one condition at a time when the first oracle is ambiguous.",
    "nextAdjustment": "Use a single-variable comparison before adding more probes."
  },
  "applicability": [
    {
      "kind": "workflow",
      "id": "pentest-e2e",
      "version": "2",
      "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    { "kind": "phase", "id": "authorization-and-roe" }
  ],
  "evidence": ["evidence://sanitized-workflow-review"],
  "configurationRefs": ["config/workflows/pentest-e2e.json"],
  "replaces": [],
  "sensitivity": "private",
  "scope": "session"
}
JSON
chmod 600 "$GATE_HOME/input/learning-cycle.json"

./bin/gate.mjs learn cycle \
  --file "$GATE_HOME/input/learning-cycle.json" --json
```

The command returns both the candidate ID and `candidateSha256`. Routine passes and expected negative results remain workflow evidence. Leave `replaces` empty for compatible guidance. When this candidate corrects or reverts an effective validated lesson, put that learning ID in `replaces` before review. GATE accepts only currently effective validated records with the same domain and exact applicability, prevents replacement forks, and includes the ordered replacement set in the candidate digest. A candidate intended for public promotion must already contain only reviewer- and operator-sanitized narratives, applicability, evidence references, and canonical configuration references to existing regular non-symlink files inside the repository; promotion cannot rewrite that content. Automatic checks catch known secret and identifier patterns, but they cannot recognize every arbitrary single-token proper name or client alias. Passing them does not prove that a candidate has no target or client identifier, so keep uncertain material private. After independent validation and the durable behavior, policy, configuration, test, or documentation change, have No Mistakes review the exact candidate digest and implementation Git head. Then use `learn promote` as the deliberate reviewed bridge from this case-private candidate into the shared public ledger:

```bash
cat >"$GATE_HOME/input/learning-promotion.json" <<'JSON'
{
  "sensitivity": "public",
  "scope": "repository",
  "validationRefs": ["evidence://reviewed-validation"],
  "changeRefs": ["commit://0123456789abcdef0123456789abcdef01234567"],
  "review": {
    "owner": "no-mistakes",
    "attestationRef": "evidence://no-mistakes/reviewed-run",
    "attestationSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "candidateSha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "headSha": "0123456789abcdef0123456789abcdef01234567"
  }
}
JSON
chmod 600 "$GATE_HOME/input/learning-promotion.json"

./bin/gate.mjs learn promote CANDIDATE_ID \
  --file "$GATE_HOME/input/learning-promotion.json" --json
```

Replace every example ID, digest, evidence reference, commit, and review attestation with its real value. `review.candidateSha256` must equal the `learn cycle` receipt, and `review.headSha` must be the full 40-character lowercase Git head reported by the review. Promotion creates a new active record that supersedes the candidate and preserves its cycle, applicability, cause, change, configuration references, and replacement lineage exactly. Each replacement target must match the promoted record's sensitivity as well as its domain and exact applicability. Promotion rejects an attempt to choose or alter `replaces`, and a record cannot both replace and conflict with the same lesson. GATE validates the candidate binding and field shapes, but `headSha` and the external attestation remain locally asserted provenance: v0.1 does not invoke No Mistakes, verify the commit against a repository, or cryptographically verify the review's authenticity. If the new record contradicts another existing effective lesson without replacing it, add that learning ID to the optional `conflictsWith` array; otherwise the records coexist. A later consult excludes and reports explicitly conflicting records, excludes replaced ancestors, and prefers the newest effective compatible guidance. The default projection is capped at eight records and 4096 bytes, and consultation itself makes no model call. Tokens are used only when a caller places that bounded projection in model context.

The legacy `learn --cause ... --change ...` command remains available for a simple cause-and-change observation. Use private learning for target, client, credential, evidence, unpublished finding, or private-path details.

## Current release boundaries

- Cases provide immutable Program Profile and optional project bindings with separate state directories. They share the same user and host, and network containment remains adapter-dependent.
- Safety-critical execution and offline-analysis status and reconciliation still inspect retained control history so an old live, orphaned, or ambiguous operation cannot disappear behind a display cap. Those paths remain `O(history)`; a crash-safe active/recovery index is required for a hard history-independent time and I/O bound.
- The catalog describes 126 tools; seven core command-line runtimes have managed installation and verification.
- DNSx and HTTPx have narrow reviewed active adapters. Broader operations and the other tools need matching adapters or the separately reviewed generic lane where eligible.
- Windows dynamic analysis, resettable lab lifecycle, and native GUI-tool control remain separate host workflows.
- Publication commands perform read-only exact-head preflight. Merge, deploy, and publish mutation require a trusted adapter.
- Workflow test feedback is journal-bound and does not launch or authorize execution. Learning promotion binds an attestation to the exact candidate digest and Git head but does not invoke No Mistakes or cryptographically verify external authenticity; execution adapters remain separate.
- Aggregate dashboard token totals depend on local Codex usage records and do not include account quota or billing data. Per-case attribution is unavailable without case-bound records.
- The remote cockpit code still needs an operator-provided HTTPS/OIDC coordinator deployment, durable volume, and enrolled laptop runner. One coordinator and runner instance serves one operator/case/session binding; concurrent cases use separate instances and hostnames in this release.

See [Current limits](README.md#current-limits) for the complete boundary list.
