# GATE

**Gateway for Agentic Tooling & Engineering** is a personal, single-operator control plane for agentic software delivery and authorized security work. GATE keeps the reusable system in a version-controlled repository while events, target details, credential references, evidence, receipts, and private learning stay under `GATE_HOME`; credential values should remain in an OS secret store or narrowly permissioned file.

> **New here?** Follow [Getting started](GETTING_STARTED.md) to bootstrap GATE, install and verify the core tools, open the cockpit, and route your first objective. The [`gate-objective-router` skill](skills/gate-objective-router/SKILL.md) selects the best-supported domain path before a specialist intake begins. Bug bounty work then uses the [`gate-program-profile` skill](skills/gate-program-profile/SKILL.md) and [Program Profile guide](docs/bug-bounty-program-profile.md).

GATE is host-first. It is designed to run on a Windows 11 laptop through WSL2 with Codex CLI as the primary harness. Native tools remain appropriate when a GUI, the Windows certificate store, packet capture, USB, a GPU, or radio hardware needs direct host access. Containers can organize conflicting dependencies, but GATE does not treat a container, WSL2, or a Git worktree as a security boundary.

> **Status: v0.1 foundation.** The checked-in policy, schemas, CLI, categorical objective router, private project registry, source-backed bug bounty Program Profile intake, immutable per-program cases, local interactive cockpit, static public cockpit preview, project-bound zero-network PE-resource analysis, verified Treehouse lease bridge, engagement receipts, one-shot supervised generic execution, two narrow managed active adapters, observer, token reader, upstream pins, 126-tool security catalog, seven-tool managed core runtime, and journaled end-to-end penetration-testing workflow work today. Complete objective persistence and dispatch, Firstmate, GNHF, and No Mistakes orchestration, broader reviewed adapters and runtime locks, application deployment, and lab lifecycle remain integration work. See [Current limits](#current-limits).

## Start on Windows 11 with WSL2

Install WSL2 once from an elevated PowerShell prompt, then restart Windows if prompted:

```powershell
wsl --install -d Ubuntu-24.04
```

Inside Ubuntu, install Node.js **22.20 or newer** (Node 24 is also tested) from an OS- or administrator-owned location that your normal account cannot modify, plus distribution-owned Git, `curl`, `tar`, and GitHub CLI, and install Codex CLI. User-owned Node managers are incompatible with managed-upstream verification because they can replace npm between verification and launch. Authenticate `gh` and `codex`, then export a GitHub token for the isolated release downloader. [docs/setup.md](docs/setup.md) gives verified Node 24 installation commands and the complete laptop, native-tool, Docker, cloud, and troubleshooting guide. The repeatable base setup is:

```bash
git clone https://github.com/SmurfTurfPawpaw/GATE.git ~/src/GATE
cd ~/src/GATE
export GH_TOKEN="$(gh auth token)"
unset GATE_CASE
./scripts/bootstrap.sh --check-only
./scripts/bootstrap.sh
```

The bootstrap script does not install system packages or broad security suites. It installs the exact npm lock with lifecycle scripts disabled, creates private runtime directories, validates contracts and pins, runs the tests and doctor, and smoke-checks status and the default catalog profile. After the base preflight, `./scripts/bootstrap.sh --install-core-tools` installs the seven reviewed release runtimes and requires a nonempty installed and byte-verified core result from the smoke suite.

After bootstrap, keep two terminals open in the checkout. Start the read-only observer backend with `npm run dashboard`, then start the private interactive surface with `npm run cockpit`. The companion prints and normally opens a capability-bearing loopback URL on an ephemeral port; keep that URL private. The observer remains available directly at <http://127.0.0.1:4173> for detailed diagnostics. Both services reject non-loopback bind addresses and stop with `Ctrl+C`. See [Local cockpit companion](docs/local-companion.md).

The CLI works directly from the checkout:

```bash
./bin/gate.mjs status
```

Private state defaults to `~/.local/share/gate` inside WSL2. Set `GATE_HOME` before `bootstrap` to use another private location:

```bash
export GATE_HOME="$HOME/.local/share/gate"
```

Do not place `GATE_HOME` inside this repository or a cloud-synced public folder. GATE rejects lexical or physical overlap between the private root and repository in either direction, repairs owner-only POSIX permissions, and rejects linked control-state paths. Each case gets a separate owner-only state directory, while all case directories remain inside one local trust domain: a process that can write the whole `GATE_HOME` can also change case scopes, project records, offline snapshots and manifests, engagement records, receipts, active-execution manifests, claims, runs, stops, evidence, managed tool caches and runtimes, and installation receipts. Give write access only to the operator and trusted GATE processes, and keep credential values in a separate OS secret store or narrowly permissioned file referenced by `env://`, `keychain://`, or `file://`.

## Route any new objective

Tell the agent the outcome you want in ordinary language. Before it opens a specialist workflow, the [`gate-objective-router` skill](skills/gate-objective-router/SKILL.md) classifies the objective across domain, deliverable, relationship, highest effect, data class, and bounded signals. It prepares a private categorical proposal outside the repository and resolves it with the exact reviewed catalog. The CLI enforces current-user ownership and exact mode `0600` on POSIX and WSL2; native Windows ACL ownership is not verified.

```bash
unset GATE_CASE
./bin/gate.mjs objective recommend \
  --proposal "$GATE_HOME/input/objective-routing.json" --json
```

The proposal has no dedicated field for the raw objective, a target, account, contact, URL, private path, credential, command, or source body. Its producer must generate the opaque handle and references randomly and must never encode private values into them. The recommendation replaces caller-controlled metadata with bounded projections, then selects a route, evidence plan, category-only data requests, capability needs, bounded next actions, and at most a few registered choices. It always reports `executionAuthority: false`. Mixed work is decomposed before routing; a bug bounty objective can hand off to Program Profile, while an account or payment-abuse report routes to incident investigation. See [Objective routing](docs/objective-routing.md) for the proposal contract and current planning-only boundaries.

## What owns each transition

GATE composes upstream projects at exact commits rather than merging their source trees.

| Component | Role |
| --- | --- |
| **GATE objective router** | General categorical recommendation before domain-specific intake |
| **GATE case registry** | Immutable Program Profile and optional managed-project bindings with separate per-case runtime state |
| **Firstmate** | Intake, supervision, dispatch, and the operator decision inbox |
| **Treehouse** | Exclusive development workspace allocation and durable leases |
| **Codex CLI** | Primary implementation and investigation harness |
| **GNHF** | Optional bounded iteration inside one fresh Treehouse lease |
| **No Mistakes** | Immutable handoff, review, tests, documentation, lint, push, PR, and CI |
| **GATE publication authority** | Read-only exact-head publication preflight; future trusted mutation adapters |
| **GATE engagement broker** | Digest-bound scope preflight, one-shot supervised generic execution, and reviewed adapter admission |
| **GATE offline-analysis lane** | Project-bound, zero-network execution of one fixed REA PE-resource adapter |
| **REA** | Analysis of saved artifacts, captures, binaries, and runtime evidence |
| **Lavish** | Local interactive planning and decision artifacts |
| **AXI** | Agent-facing command and output conventions |
| **Skills CLI** | Distribution of reviewed project-scoped skills |
| **Observer** | Read-only compact campaign fleet, one selected live-activity view, setup progress, shared health, learning, upstream, and token views |
| **Local cockpit companion** | Private loopback operator conversation, native Codex choices, categorical activity, and the observer's bounded fleet projection |
| **Public cockpit** | Static, non-interactive Pages preview built from an explicit public allowlist |

The full ownership and recovery model is in [docs/architecture.md](docs/architecture.md) and [docs/operating-model.md](docs/operating-model.md). Exact upstream commits, versions, and artifact integrity values live in [locks/upstreams.lock.json](locks/upstreams.lock.json); committed npm dependency trees live under [locks/npm](locks/npm).

### Register a private project

Copy the contract template to a private working directory, edit every placeholder, then register it. Registration validates the schema, repository identity, default branch, and named execution and security profiles before storing a canonical owner-only copy at `GATE_HOME/projects/PROJECT_ID.json`:

```bash
mkdir -p "$HOME/.config/gate/projects"
cp templates/project.json "$HOME/.config/gate/projects/my-project.json"
# Edit the private copy, including metadata.id and repository.url.

./bin/gate.mjs project register \
  --file "$HOME/.config/gate/projects/my-project.json" --json
./bin/gate.mjs project verify my-project --json
./bin/gate.mjs project list --json
./bin/gate.mjs project show my-project --json
```

Registering the same canonical contract again is idempotent. A different contract with the same ID, or a second project that resolves to the same repository identity, is rejected. Local `file://` repositories are stored at their physical realpath and fail later verification if a moved or replaced alias resolves elsewhere. A contract-write failure rolls back the exact new file when that can be proved safe. An audit append, flush, or close error is ambiguous because the event may already be durable, so GATE preserves the contract and its nonce-and-digest-bound `.registry.pending` marker for reconciliation. An abrupt interruption can leave the same fail-closed state. While a lock or pending marker exists, full reads fail or report invalid/degraded registry state. Never delete either control blindly; follow the evidence-based recovery procedure in [docs/operating-model.md](docs/operating-model.md#private-project-contracts). `list`, healthy `status`, and the observer expose bounded summaries without repository URLs or deployment destinations; the observer also replaces the private project ID with a process-local pseudonym. `show` deliberately returns the complete private contract, so treat its terminal output accordingly. v0.1 has no project update or delete command, and registration does not clone a repository or make the contract an authorization grant.

### Isolate concurrent bug-program cases

A case is an immutable private scope for one ready bug bounty Program Profile and, when local project provenance is needed, one optional registered project. Creation captures the exact current profile and project digests. If either bound record later changes, the case becomes stale instead of silently following the replacement.

```bash
# Prepare and verify the Program Profile first.
./bin/gate.mjs bounty profile verify example-program --json

./bin/gate.mjs case create example-web \
  --program example-program \
  --name "Example web program" \
  --project my-project --json

./bin/gate.mjs case list --json
./bin/gate.mjs case show example-web --json

# Prefix each command, or export GATE_CASE in that case's terminal.
./bin/gate.mjs --case example-web workflow new example-web-map --json
GATE_CASE=example-web ./bin/gate.mjs workflow status example-web-map --json
```

Omit `--project` when the case does not need a managed-project binding. Target-specific Program Profiles live in the shared private registry, while scoped commands place campaign execution observations, engagements, workflows, execution state, offline-analysis state, evidence, tokens, and private learning under `GATE_HOME/cases/CASE_ID/state`. Registered projects, managed tools, upstreams, and reviewed public learning also remain shared. Every engagement and workflow command, Program Profile compilation, and `analysis manifest`, `run`, `purge`, or `status` requires a leading `--case ID` or `GATE_CASE`. Profile compilation must use the bound Program Profile, and offline analysis must use the bound project. `--case ID` and `GATE_CASE` must agree when both are present.

Every case-owned command requires an explicit runtime selection: leading `--case ID`, matching `GATE_CASE`, or leading `--unassigned`. `--unassigned` selects the writable base-state compatibility namespace and can create new unscoped records; using it opts out of case attribution and state separation. GATE never selects it implicitly, so prefer a case for program work. Setup and shared-registry commands—including project, case, workspace, upstream, tool, publication, Program Profile intake, and `analysis capability`—reject all runtime selectors. Plain `gate status` is the bounded aggregate fleet view; `gate --unassigned status` reads only base state, while `gate --case ID status` reads one case. Events and private learning without a selector also write to base state.

This is filesystem separation for organizing concurrent work. Case processes still run as the same operating-system user on the same host, with the same host-access implications. Network containment comes only from the selected execution adapter or environment. A case does not grant target authority or strengthen an adapter's isolation.

Run `gate up` without a runtime selector. It presents the bounded fleet cockpit and refuses `--case`, `GATE_CASE`, and `--unassigned` because a scoped observer would hide the other visible campaigns. The compact table combines case rows with private, pseudonymous Program Profile setup rows that are not represented in the current bounded case projection; when the case scan is partial, an off-projection current case may still exist. Selecting a row opens one live-activity or setup-detail panel. One snapshot projects at most 32 cases selected from at most 1,024 discovered entries, and the Program Profile setup projection has its own 32-row bound. Summary counts use a `+` suffix when they are only lower bounds and show unavailable when no trustworthy observation exists. Retrieve a known omitted case directly with `gate case show ID --json` or `gate --case ID status --summary --json`.

When two or more programs run concurrently, use the [campaign acceptance and GATE improvement checklist](docs/campaign-acceptance.md) to verify state separation, fleet clarity, adaptive testing, recovery, and the sanitized path from campaign friction to a reusable repository change.

### Lease and verify a Treehouse workspace

The workspace bridge runs only on Linux or WSL2. Install the locked Treehouse 3.1.3 release once, then use GATE for lease state. Every operation revalidates the managed executable against the repository lock and refuses an absent, modified, or receipt-only installation:

```bash
./bin/gate.mjs upstream install treehouse --json
./bin/gate.mjs workspace status --repo "$HOME/src/my-project" --json

./bin/gate.mjs workspace lease \
  --repo "$HOME/src/my-project" \
  --task issue-123 \
  --branch gate/issue-123 \
  --base main --json
```

Lease acquisition is the only path that invokes Treehouse. GATE calls the verified binary as `treehouse get --lease --json --no-fetch --branch BRANCH --lease-holder HOLDER [--base BASE]`; omitting `--base` leaves base selection to the repository's Treehouse configuration. GATE never invokes Treehouse `status`, `return`, `destroy`, `prune`, or `enter`. It also disables lazy fetches and Git transports, uses a fixed trusted system Git, and gives each subprocess a minimal environment with an empty private home and temporary directory. The bridge has no credential, proxy, SSH-agent, or network broker. Fetch or update every required ref through a separate reviewed workflow before running the offline lease command.

GATE binds private Treehouse state to the physical clone and allocates a fresh task-ID-hashed root for each lease. A task ID is one-shot: its root is never reused, even after failure, so retry with a new task ID. Each physical clone can consume at most 511 retained task roots over its lifetime. When that limit is reached, use a new physical clone or wait for a future mount-safe upstream lifecycle primitive; do not delete old roots to make room. Before and after lease acquisition, GATE accepts only a narrow reviewed set of shared repository-local and per-worktree Git configuration keys and validates their values; every unreviewed key fails closed. This excludes includes, credential/SSH/proxy helpers, filters, diff/merge drivers, editors, pagers, external protocols, repository redirection, and weakened stat handling. Git LFS repositories remain blocked until their command-capable filters have a reviewed adapter.

`workspace status` does not run Treehouse. It stable-reads every clone and task binding, the exact version-4 state with one healthy lease, and the exact 32-byte owner-only state key. It authenticates the seed inventory with its HMAC, then requires the raw state-file and key SHA-256 digests to match the immutable completed GATE binding. The HMAC authenticates only the seed inventory; lease identity also depends on the trusted `get` receipt and the immutable raw-file digests. Treehouse 3.1.3 status recovery can move user files, which is why neither GATE nor the operator may use it for inspection.

Before `get`, GATE durably publishes a `pending` binding. After Treehouse returns, GATE checks the returned base, path, lease ID, holder, timestamp, requested branch, exact state, in-progress Git state, submodules, nested metadata, indexes, objects, and controlled checkout. It then writes the durable `workspace.leased` event and atomically replaces `pending` with a `complete` binding containing the event receipt and immutable state/key digests, followed by another state read. An interruption leaves the root retained and status reports it as unverified for manual reconciliation. Keep the returned workspace path, lease ID, and task ID, and work only in that path.

After the workspace commit has landed, stop its processes and verify the exact lease. `--repo` must name the main worktree, and `--landed-ref` must be the branch currently checked out there:

```bash
./bin/gate.mjs workspace verify \
  --repo "$HOME/src/my-project" \
  --path WORKSPACE_PATH \
  --task issue-123 \
  --lease 0123456789abcdef0123456789abcdef \
  --landed-ref main --json
```

`workspace verify` is nonmutating. It rechecks the lease identity, common Git state, real indexes, full object integrity, zero unreachable objects, process state, and exact filesystem bytes, then proves that the workspace's current `HEAD` is locally reachable from the branch checked out in the main worktree. Ignored cache paths may remain in the main worktree; extras or ignored paths in the leased workspace fail verification. This is local reachability evidence only, not proof of a provider push, No Mistakes completion, or publication. The command emits `workspace.verified` and deliberately retains the durable lease.

Automatic Treehouse return, reset, destroy, and slot reuse are disabled. Reproduced bind-mount races in Treehouse 3.1.3 can make those destructive operations alter or delete host data, and the upstream release has no safe cleanup primitive. Never run any Treehouse command directly against a GATE root, including `treehouse status`; use GATE's workspace commands and the ordered recovery procedure in [the operating model](docs/operating-model.md#operation-lock-recovery). Retained task roots consume disk until a mount-safe upstream operation exists. Treehouse is change isolation, not a boundary for same-user code: a task can still mutate the clone's shared common `.git`, including refs, hooks, and configuration. Use a standalone clone or an OS sandbox for unknown or hostile code.

### Preflight an exact reviewed head

For a GitHub pull request that has completed the real No Mistakes pipeline, bind publication to the immutable 40-character head and its No Mistakes run ID. `check` and `dry-run` are read-only:

```bash
./bin/gate.mjs publication check \
  --repo OWNER/REPOSITORY --pr 123 \
  --head 0123456789abcdef0123456789abcdef01234567 \
  --run NO_MISTAKES_RUN_ID --mode squash

./bin/gate.mjs publication dry-run \
  --repo OWNER/REPOSITORY --pr 123 \
  --head 0123456789abcdef0123456789abcdef01234567 \
  --run NO_MISTAKES_RUN_ID --mode squash
```

The preflight requires an open, non-draft pull request whose head matches exactly, a `CLEAN` GitHub merge state, and a nonempty set of checks on that exact head, all in successful buckets. It does not require GitHub branch protection. A head change, an empty check set, or unavailable PR/check state fails closed.

Preflight evidence is fixed to `github.com` and runs only an absolute GitHub CLI from a protected system path with a minimal environment. Caller `PATH`, home and GitHub configuration, host overrides, language loaders, and unrelated credential variables do not reach the child; export `GH_TOKEN` or `GITHUB_TOKEN` explicitly because stored `gh auth login` state is intentionally isolated. Proxy settings remain available, while `SSL_CERT_FILE` and `SSL_CERT_DIR` must resolve through protected absolute paths. One `gh api graphql` request binds the repository, pull request, current head, latest commit, and complete evaluated status context set; the documented distribution baseline (`gh` 2.46) supports it. The response is capped at 100 contexts and fails closed on pagination, inconsistent counts, unrecognized states, or a rollup for another head. Install `gh` through the WSL distribution as shown in [setup](docs/setup.md#1-prepare-wsl2-on-windows). Native Windows must use WSL2, and running GATE as root or supplying a user-owned or user-writable `gh` fails closed.

Publication mutation is disabled in v0.1. The adapter treats `--run` as operator-supplied provenance; it does not invoke No Mistakes, correlate the ID with the head, or verify an attestation. A future trusted adapter must verify a No Mistakes attestation bound to the exact head and enforce the registered repository, base branch, merge posture, and destination before it can merge, deploy, or publish. `check` and `dry-run` create reviewable evidence without mutation.

## Offline artifact analysis

GATE has one narrow implemented offline adapter for a supplied Windows PE file. It runs REA's `inspect-pe-resources` operation without executing the input. The lane is bound to a registered project but is separate from the engagement broker because the operation has no target contact. Install the pinned `rea-stable` upstream and Bubblewrap on Linux or WSL2, then inspect capability:

```bash
./bin/gate.mjs upstream install rea-stable --json
./bin/gate.mjs analysis capability --json
```

Capability checks prerequisite presence and launches a minimal Bubblewrap namespace; it does not verify the full managed REA tree. Register a private project and create a case bound to it, then create and review a manifest for one exact absolute regular-file path in that case:

```bash
./bin/gate.mjs --case example-web analysis manifest \
  --project my-project \
  --path "$HOME/private/client-installer.exe" \
  --minutes 15 --json

./bin/gate.mjs --case example-web analysis run \
  --project my-project \
  --manifest MANIFEST_ID \
  --confirm "ANALYZE MANIFEST_ID MANIFEST_SHA256 OFFLINE" --json

./bin/gate.mjs --case example-web analysis status --json
```

Use the exact returned confirmation after reviewing the complete manifest. The [offline-analysis operating procedure](docs/operating-model.md#offline-static-artifact-analysis) owns the integrity checks, bindings, isolation guarantees and unavailable controls, evidence limits, snapshot quotas, crash recovery, and digest-bound purge procedure. This adapter supplies PE-resource inspection, rather than a general reverse-engineering or dynamic-analysis environment.

Possession of a local file authorizes neither network access nor testing of its publisher. A proprietary client or other proprietary artifact must be lawfully supplied by the operator and remains private under `GATE_HOME`. Strings, hostnames, URLs, certificate names, and update endpoints found in it are offline hypotheses. GATE must not resolve, browse, scan, authenticate to, intercept, or otherwise contact those systems until separate written authority and an exact active engagement cover the selector and action.

The machine-readable [end-to-end penetration-testing workflow](config/workflows/pentest-e2e.json) and [operator guide](docs/pentest-workflow.md#admission-execution-and-a3-handoff) carry offline observations through passive corroboration, active mapping, specialist workstreams, controlled exploitation, impact validation, cleanup, retest, and reporting. The workflow does not itself grant authority or prove that a cataloged tool is installed.

## Active security workflow

Local source review, hypothesis generation, declared passive research, and analysis of saved evidence can proceed without an active receipt under their data and provider rules. Contacting a target through scanning, crawling, interception, authentication, fuzzing, exploitation, persistence, denial-of-service testing, or data access requires an engagement whose reviewed report and operator receipt match the exact plan digest. Each launch then uses either a reviewed scope-aware adapter or the Linux/WSL2 supervised generic lane described below. The generic lane supports only receipt-bound `scope.environment: host`; container, rootless-container, VM, and remote-lab engagements need a lane that implements that environment. Follow the [end-to-end workflow](docs/pentest-workflow.md) to map prerequisites, evidence, stop conditions, and handoffs before selecting a tool.

For bug bounty work, the [`gate-program-profile` skill](skills/gate-program-profile/SKILL.md) is the preferred interactive intake. It derives a draft from current-conversation evidence permitted for the configured provider, structural questionnaire metadata, and manually sanitized categorical outcomes, then uses native choice controls for only the unresolved decisions. Exact selectors, contacts, authorization text, source bodies, and other private literals belong in the loopback-only browser wizard. Initialize a missing draft with reviewed deterministic recommendations, then launch the form:

```bash
unset GATE_CASE
./bin/gate.mjs bounty profile create example-program --apply-recommended --json
./bin/gate.mjs bounty profile ui example-program --open
```

The second command prints a private session URL, edits exactly one profile through typed controls, and keeps its terminal attached until `Ctrl+C`; if browser launch is unavailable, open the printed URL on the same laptop. Each eligible question offers its reviewed recommendation, and the bulk action applies only supported unanswered recommendations. Source-dependent questions remain unresolved until a current private proposal and its cited source records exist. Authority confirmation and final attestation are always manual. The dashboard stays read-only and does not host this form. The [Program Profile guide](docs/bug-bounty-program-profile.md) documents the browser flow, numbered terminal fallback, and headless answer and recommendation envelopes. Source bodies stay in operator-controlled private storage; GATE records their references and supplied digests under `GATE_HOME` but does not fetch or rehash them in v0.1. Its private output improves planning and model compatibility checks, but target contact still depends on an exact engagement, reviewed plan, operator receipt, workflow admission, and execution confirmation.

Nmap remains a planning example: `./bin/gate.mjs tool plan nmap --json` reports its admission requirements. It is blocked from generic execution pending reviewed runtime admission, even when installed and permitted by an engagement.

The boundary walkthrough below uses ExifTool and an operator-supplied copied image to exercise the engagement broker through exact preflight inside `example-web`. It deliberately stops before manifest creation. ExifTool is mapped only to the non-contact `local-artifact-analysis` phase, while every generic execution manifest now requires an active target-contact phase with a reviewed admission and matching tool mapping. No valid workflow or phase-attempt ID can make this ExifTool example executable. `tool plan exiftool` may report PATH eligibility, but that does not create the missing workflow admission. Use the local-artifact procedure and retain ExifTool output as external evidence with its real provenance, or add a separately reviewed adapter and workflow mapping before exposing it through GATE.

1. Create the envelope. Use exact targets and exclusions; catalog profiles do not grant authority. URL paths match only on segment boundaries. A query written into an approved URL selector must match exactly, while fragments are rejected because they are not sent to a server.

   ```bash
   ./bin/gate.mjs --case example-web engagement new acme-web \
     --title "Authorized Acme artifact inspection" \
     --targets "$GATE_HOME/artifacts/sample.jpg" \
     --actions observe \
     --tools exiftool \
     --environment host \
     --allowed-destinations gate-home \
     --basis client-written-authorization \
     --valid-until "$(date -u -d '+7 days' +%Y-%m-%dT%H:%M:%SZ)"
   ```

2. Attach the written authorization from a private source path. GATE copies it into `GATE_HOME` as a regular private file. Contract and client-written authorization engagements cannot be approved without it.

   ```bash
   ./bin/gate.mjs --case example-web engagement authorization acme-web \
     --file "$HOME/private/acme-web-written-authorization.pdf"
   ```

3. Write the concrete engagement report from [templates/plan-review.md](templates/plan-review.md). It must name targets, actions, tools, expected effects, coverage, limits, data handling, stop conditions, risks, and completion tests. Attach it; GATE copies it to private state and returns `plan.sha256`.

   ```bash
   ./bin/gate.mjs --case example-web engagement plan acme-web \
     --file "$HOME/private/acme-web-plan.md"
   ```

4. Run a real No Mistakes review against an immutable commit. Record its run ID, full 40-character head SHA, and result. Recording a value is not a substitute for running the review.

   ```bash
   ./bin/gate.mjs --case example-web engagement review acme-web \
     --run NO_MISTAKES_RUN_ID \
     --head 0123456789abcdef0123456789abcdef01234567 \
     --result passed
   ```

5. Show the operator the complete report and digest. The operator supplies an exact receipt for that digest. Agents must never invent or infer the confirmation string. The receipt binds the plan, engagement envelope, and SHA-256 of the written authorization; changing any of them invalidates active preflight.

   ```bash
   ./bin/gate.mjs --case example-web engagement approve acme-web \
     --sha PLAN_SHA256 \
     --confirm "APPROVE acme-web"
   ```

6. Check the target and declared action label immediately before the proposed active command. An allowed result includes an `executionBinding` for the exact engagement, plan, envelope, receipt, authorization expiry, target, action label, environment, permitted tool list, and allowed destinations. The generic lane requires receipt-approved `gate-home` because its raw evidence always lands under `GATE_HOME`. The recorded operator and No Mistakes provenance remains `local-unverified` rather than a cryptographic external attestation.

   ```bash
   ./bin/gate.mjs --case example-web engagement check acme-web \
     --target "$GATE_HOME/artifacts/sample.jpg" \
     --action observe
   ```

7. Stop at the execution boundary. Do not invent a workflow ID, phase-attempt ID, admission, or tool mapping to force this local-only example through `engagement manifest`. The [workflow admission procedure](docs/pentest-workflow.md#admission-execution-and-a3-handoff) shows the manifest and execution grammar for a future target-contact operation whose reviewed adapter and exact mapping are available.

8. Revoke the complete engagement when its authority should end.

   ```bash
   ./bin/gate.mjs --case example-web engagement revoke acme-web \
     --confirm "REVOKE acme-web" --json
   ```

9. Close the engagement when work ends.

   ```bash
   ./bin/gate.mjs --case example-web engagement close acme-web
   ```

   `close` is an administrative state change. It does not inspect the coverage map, validate findings, run completion tests, or certify that the assessment is complete.

Changing a target, exclusion, permitted action or tool, execution environment, plan, written authorization, data destination, authorization window, or material limit requires a new report, review, and receipt. Raw `gate run`, `gate upstream exec`, and argument-taking execution shortcuts remain disabled. [policies/engagements.json](policies/engagements.json) is the authority contract.

## Security-tool catalog

[catalog/security-tools.json](catalog/security-tools.json) currently describes **126 distinct tools** across web/API, network, identity, exploitation, reverse engineering, mobile, DFIR, OSINT, cloud/Kubernetes, source security, and wireless/radio work. Profiles under [config/profiles](config/profiles) select useful subsets:

```bash
./bin/gate.mjs tool list --profile pentest --json
./bin/gate.mjs tool list --category network --json
./bin/gate.mjs tool list --profile pentest --summary --limit 10 --cursor 0 --json
./bin/gate.mjs tool show nmap --json
./bin/gate.mjs tool plan wireshark --json
```

**Cataloged does not mean installed, trusted, licensed for redistribution, configured, or authorized for a target.** Inventory results report the current host, compatibility, and PATH candidate where one exists. A compatible Linux/WSL2 candidate can be `genericLaneEligible` without verified version, integrity, provenance, or adapter readiness only when its catalog `commandIdentity.genericLaneAdmission` is `path-discovery`. Entries marked `reviewed-admission` report a PATH namesake as `identity-unverified`, withhold it as the executable, and block the generic lane. This prevents the ambiguous `httpx` command from being mistaken for ProjectDiscovery httpx and keeps REA's broader A2 command surface outside generic execution.

The `core` profile adds reviewed release runtimes for `subfinder`, `dnsx`, `httpx`, `katana`, `naabu`, `ffuf`, and `nuclei`:

```bash
./bin/gate.mjs tool prefetch --profile core --json
./bin/gate.mjs tool install --profile core --json
./bin/gate.mjs tool verify --profile core --json
./bin/gate.mjs tool remove --profile core --json
```

Every operation also accepts one tool ID in place of `--profile`; the two selectors are mutually exclusive. The reviewed lock binds the exact catalog entry, version, full source commit, release evidence, artifact URL and size, archive and executable SHA-256, exact archive members, platform, and bounded smoke specification. Release artifacts are pinned for Linux and macOS on x64 and ARM64. Installation and live verification currently require the Bubblewrap/prlimit zero-egress smoke supervisor on Linux or WSL2; macOS can prefetch and verify the archive bytes but cannot activate the runtime until an equivalent reviewed smoke sandbox exists. DNSx 1.3.1 and HTTPx 1.12.0 now have one narrow, typed A1 observation adapter each; their broader surfaces and the other five verified binaries remain invocation-blocked. `naabu` additionally needs a raw-network privilege adapter, and `nuclei` additionally needs reviewed template admission. The other catalog entries still use their documented native, GUI, hardware, OCI, language, or external installation lanes.

Release bytes, staging directories, installed executables, and receipts stay private under `GATE_HOME`. Cockpit and `status` refreshes show dated receipt evidence rather than current integrity. See the [managed-runtime verification boundary](docs/security-tooling.md#managed-core-runtime) for inventory, doctor, planning, explicit verification, and pre-execution checks. Installation grants no target authority or execution admission.

For managed REA, cheap inventory can report a matching install receipt as `managed-receipt`, but that is no integrity or readiness claim. `tool plan rea` performs full managed-upstream verification; when its host prerequisites pass, it exposes only the `offline-static-pe-resources` adapter while `genericLaneEligible` and `broadCapabilityReady` remain false. `tool plan` otherwise explains the preferred install lane, privileges, risk class, license, generic-lane status, and admission work. A persistent addition needs an official source, exact version or commit, integrity evidence where available, license record, effect classification, telemetry decision, smoke test, learning record, and No Mistakes validation.

OWASP ZAP and mitmproxy are the open-source web interception defaults. Burp Suite is an optional, proprietary, operator-supplied integration. If a Kali profile is added, it must remain an optional compatibility toolbox with a pinned package subset, image digest, and SBOM rather than becoming GATE's source of truth. See [docs/security-tooling.md](docs/security-tooling.md).

## Cockpit, observer, and token visibility

Run `npm run dashboard` and `npm run cockpit` in separate terminals. The first command serves the dependency-free, read-only observer at `127.0.0.1:4173`; the second serves the interactive cockpit on an ephemeral loopback port and connects one dedicated Codex app-server thread. The companion can show the operator's bounded messages, final Codex replies, native one-to-three-choice questions, categorical activity, exact companion-thread token counters, an estimated thread cost when Codex supplies one, and a separately bounded projection fetched from the observer. It does not show hidden reasoning, commands, arguments, stdout or stderr, tool names, target selectors, evidence, credentials, or private paths. It does not connect to the current cloud chat or grant execution authority. See the [local companion boundary](docs/local-companion.md).

The static Pages build is different from the local companion. It copies exactly eight allowlisted files: `.nojekyll`, `index.html`, `robots.txt`, four named browser assets, and `data/status.json`. The checked-in snapshot is visibly labeled `PREVIEW · NOT LIVE`, disables interaction, and contains only opaque example campaigns. Companion modules, session capabilities, observer code and responses, prompts, target data, and `GATE_HOME` never enter that artifact.

The observer's compact fleet table shows up to 32 valid or attention-worthy cases from the bounded case scan and up to 32 current Program Profile setups that are not represented in that bounded case projection. A setup row is not proof that no off-projection current case exists when the case scan is incomplete. Case rows show allowlisted campaign identity, state, current phase or tool, last signal, active work, attention, case-attributed token availability, and a case-backed learning count. Setup rows use a process-local pseudonym and show only questionnaire stage and progress, blocker count, next section, update freshness, and readiness. Recommendation mode is nullable and appears only when a reviewed producer supplies it. Learning count is unavailable on setup-only rows because only case rows carry case-backed learning attribution. Setup rows do not expose the program name, answers, sources, contacts, or target details.

Selecting a table row opens one detail panel. A case detail contains its bounded structured lifecycle feed; a setup detail contains its guided intake state. These are presentation views, not PTYs. Apart from the operator-controlled case display name, they never expose raw stdout or stderr, argv, commands, target selectors, evidence contents, or private paths. An active case uses a spinner and indeterminate bar while fresh lifecycle events show work in progress. GATE does not invent a completion percentage: determinate progress requires a source that supplies an actual completed and total count. Motion is disabled when the browser requests reduced motion. The welcome line uses `operator.displayName` from the merged GATE configuration; the tracked default is `Giovanni`.

Summary cards distinguish exact counts, lower bounds (`+`), and unavailable observations (`—`) under the [count precision and cached-state rules](docs/architecture.md#observation-and-token-accounting). The collapsible **System health** area contains base/unassigned activity, agent/task, active-execution, and offline-analysis views. Managed runtime counts, learnings, telemetry freshness, and aggregate host token use are shared views. The bounded status API also carries base engagement and upstream summaries; v0.1 does not yet render dedicated panels for those two summaries. Runtime `unresolved` is full-catalog readiness rather than a failed-install count. The normal receipt-only view still withholds every managed executable because it performs no current-byte or live-smoke verification; full planning can report the two reviewed DNSx and HTTPx operations adapter-ready after exact verification. Keyboard shortcuts are:

Agents should use `gate status --summary --json` and `gate tool list --summary --json`; use `gate tool show ID --json` for one bounded item. The status summary identifies its aggregate, unassigned, or selected-case lane and retains bounded per-case lane counts, case-scan omissions, and case-detail retrieval pointers. See [observation and token accounting](docs/architecture.md#observation-and-token-accounting) for output bounds, pagination, source digests, and telemetry limitations.

| Key | Action |
| --- | --- |
| `0` | Focus the campaign fleet |
| `1` | Open and focus the selected campaign detail |
| `2` | Open System health |
| `3` | Focus active execution |
| `4` | Focus resource posture |
| `5` | Focus learning |
| `6` | Focus offline analysis |
| `7` | Focus managed tool runtimes |
| `↑` / `↓` or `[` / `]` | Select the previous or next campaign |
| `Enter` | Open the selected campaign detail |
| `/` | Focus the safe metadata filter |
| `R` | Refresh now |
| `P` | Pause or resume polling |
| `?` | Open shortcut help |

GATE streams local Codex session JSONL files under `CODEX_HOME/sessions` or `~/.codex/sessions` and parses only token-count/usage records. When WSL should use Windows-hosted Codex sessions, set a local symbolic override such as `CODEX_HOME=/mnt/c/Users/WINDOWS_USER/.codex`; do not commit the resolved path. Provider counters are labeled `exact`; a missing value is `unavailable`, never zero. The cockpit keeps the selected dedicated-thread or host input, cached input, output, total, cost availability, and provenance visible in its sticky token rail. Host session files do not carry a trustworthy case binding, so their totals stay separate from case totals. A case row reports `Awaiting attribution` until a reviewed producer writes canonical token records inside that case's state directory. The scanner necessarily reads session-file bytes, but it never returns prompt bodies, paths, IDs, or raw records. Apart from the operator-controlled case display name, the observer's browser API omits prompts, responses, commands, tool output, target selectors, absolute paths, and evidence contents.

## Learn and adapt

GATE uses two linked feedback layers. During an assessment, `workflow test plan` and `workflow test review` keep the hypothesis, method, expected and contrary signals, observation, metrics, useful mistake, and next strategy in the private hash-chained workflow journal. Only one test cycle may remain open. Each later plan cites the preceding review and states the adaptation, so a retry cannot silently repeat the same method. These records explain how the assessment changed; they do not launch a tool, reserve execution, alter an admission, or grant authority.

Reusable changes enter the durable learning layer. `learn cycle` records a private structured candidate and returns its digest. When new guidance replaces an effective lesson, the candidate names that reviewed predecessor in `promotion.replaces`; the replacement choice is therefore part of the candidate digest. `learn promote` is the deliberate reviewed bridge from a case-private candidate to shared public learning: it requires a No Mistakes attestation bound to that exact digest and a full Git head recorded as local provenance, then creates a validated active record without rewriting the candidate or its replacement lineage. Replacement targets must still be effective and have the same sensitivity, domain, and exact applicability when promotion occurs. A public promotion therefore requires the original candidate to be reviewer- and operator-sanitized. Automated checks catch known secret and identifier patterns but cannot recognize every arbitrary single-token proper name or client alias; passing them does not prove that a candidate has no target or client identifier. Keep uncertain material private. `learn consult` selects only effective guidance in a bounded public projection for an exact applicability set; replaced ancestors remain immutable history and render as superseded. A plan freezes that applicability set, its ordered learning IDs, the learning-ledger head, and the projection digest. Journal replay verifies that frozen projection against an exact retained public-ledger prefix and rejects changed IDs, order, conflicts, omissions, or digests. Historical replay cannot independently prove that the named prefix was the newest one when the entry was written because v0.1 has no external cross-ledger time anchor; live plan creation enforces current-head freshness while holding the shared ledger lock. A workflow test plan's applicability equals exactly one workflow reference with the current ID, version, and contract digest, exactly one active-phase reference, and the exact admitted tool reference when present; v0.1 accepts no extra references. GATE recomputes the default consultation during planning and rejects stale provenance, unresolved declared conflicts, or omitted applicable lessons, including when the selected ID list is empty. A later regression appends a reviewed replacement or reversion without erasing earlier guidance. GATE does not hot-reload a learning into a running attempt or use learning to expand target scope, execution authority, or policy boundaries.

The legacy cause-and-change command remains available for a simple observation:

```bash
./bin/gate.mjs learn \
  --scope repository \
  --cause "The selected scanner omitted HTTP/2 coverage." \
  --change "Include the admitted HTTP/2 probe in the web profile and its completion check."
```

Public learnings append one machine-readable line to `memory/learnings.jsonl` and one sanitized line to [memory/LEARNINGS.md](memory/LEARNINGS.md). Use `--private` whenever the cause or change could expose a target, client, credential, private path, capture, or unpublished finding:

```bash
./bin/gate.mjs learn --private --scope session \
  --cause "SANITIZED_CAUSE" --change "SPECIFIC_CHANGE"
```

Public project-scoped learning still fails closed because no public project-promotion destination is configured. The private registry does not make project details releasable. Record project learning with `--private --scope project` in the meantime; repository-scoped sanitized learning continues to use the reviewed public ledger.

A learning is complete only when the behavior, policy, configuration, test, or documentation actually changes. Routine passes and expected negative results stay in workflow evidence. Promote a candidate only when the lesson is reusable, independently validated, and backed by the change that implements it. Repository-level promotion goes through No Mistakes, but GATE does not invoke that review automatically. Target or tool output is untrusted data: it may suggest a learning, but it cannot directly alter memory, policy, authorization, or publication rights.

Consultation is deterministic local retrieval and makes no model call. It returns at most eight records and 4096 bytes by default, contains no raw evidence excerpts, and reports truncation. A workflow test plan refuses a consultation that omitted an applicable lesson. Tokens are consumed only if a caller later places that bounded projection in model context. See [Record and apply adaptive learning](GETTING_STARTED.md#7-record-and-apply-adaptive-learning) for the file-driven commands and accepted JSON shapes.

## Upstreams

Inspect pins before installing anything:

```bash
./bin/gate.mjs upstream list --json
```

`upstream sync ID` clones the named source and detaches it at the locked full commit under `GATE_HOME`. Source verification invokes only a fixed, non-group-writable system Git with a minimal configuration and command path; an ambient `PATH`, loader variable, Git configuration, hook, filter, or helper cannot select the verifier. For npm entries, `upstream install ID` verifies the committed package-lock digest, runs `npm ci` with lifecycle scripts disabled, and verifies the installed tree against a second offline reconstruction. Npm execution uses the `npm-cli.js` bundled inside the real installation of the currently running Node executable, invokes it through that exact Node path, hashes the complete npm package tree before and after use, and supplies a minimal environment with fresh empty user/global config files; ambient `PATH`, `NODE_OPTIONS`, and npm configuration do not reach the child. GATE also installs the locked Treehouse and No Mistakes release artifacts after verifying their SHA-256, archive paths, and single executable. Release downloads use a fixed GitHub CLI with a fresh configuration directory and only the required token and proxy variables. The installer reads each bounded archive once, verifies and inspects those exact bytes, and asks fixed tar to emit only the locked executable to stdout; it never unpacks the archive tree. Export `GH_TOKEN` or `GITHUB_TOKEN` because stored GitHub CLI configuration is intentionally isolated. Git, tar, GitHub CLI, Node, npm, and their path chains must be protected from writes by the current process; root execution, user-owned Node managers, user-writable Homebrew installations, and writable `/usr/local` tools therefore fail closed. Native Windows cannot establish this protected-runtime contract and must use WSL2. Use OS- or administrator-owned read-only installations for these upstream operations. The installer records the version from the reviewed lock and does not execute a freshly downloaded binary. Later full status and path-resolution checks revalidate the npm tree or release executable. `upstream install all` covers both managed lanes. Source, skill, and other lanes still require their documented sync or installer and smoke test.

Installation receipts under `GATE_HOME` are evidence, not the trust anchor. Full npm verification rebuilds a clean tree offline from the repository-tracked dependency lock and integrity-addressed GATE npm cache, then compares the deterministic tree digest. Release verification compares the archive and executable bytes with SHA-256 values in the reviewed upstream lock. A process that can write only `GATE_HOME` cannot re-anchor modified installed bytes by rewriting a receipt; a process that can also alter the trusted repository lock or verifier is outside this check's trust boundary.

Source sync creates a fresh staged clone with system and global Git configuration and templates isolated, verifies it, and atomically replaces the managed checkout. Full readiness compares the locked commit tree, index, and raw worktree bytes; replacement refs, grafts, alternates, hidden index flags, ignored files, empty extra directories, and every other extra path fail closed. Submodules are not initialized and source trees that require them are not ready in v0.1. Treat the managed checkout as replaceable state rather than a place for local edits.

### Install GATE skills into a project

Install the integrity-checked Skills CLI once through GATE. Raw `gate upstream exec` is deliberately disabled; for local, non-target work, invoke the verified installation directly from the path GATE reports:

```bash
./bin/gate.mjs upstream install skills-cli
SKILLS_ROOT="$(./bin/gate.mjs upstream path skills-cli)"
"$SKILLS_ROOT/node_modules/.bin/skills" add "$PWD/skills" --list
```

From the root of a destination project, point the same command at a reviewed GATE checkout and select only the skills that project needs:

```bash
GATE_SKILLS_ROOT="$(~/src/GATE/bin/gate.mjs upstream path skills-cli)"
"$GATE_SKILLS_ROOT/node_modules/.bin/skills" add ~/src/GATE/skills \
  --skill gate-objective-router \
  --skill gate-program-profile \
  --skill gate-workflow \
  --skill gate-security-engagement \
  --skill gate-continuous-learning \
  --agent codex --yes
```

`gate-objective-router` selects the first evidence-led domain route for any new objective. `gate-program-profile` then runs the preferred source-first, choice-first intake when the selected route is a bug bounty program. Its model-visible choices use provider-approved current-conversation evidence and manually sanitized categorical outcomes; exact private values remain in local capture and review surfaces. `gate-workflow`, `gate-security-engagement`, and `gate-continuous-learning` cover software delivery, active-assessment admission, and durable learning respectively.

This is a project-scoped install. Do not add `--global`; review and pin the GATE source commit before distributing its skill content.

## Current limits

The v0.1 boundary is intentionally explicit:

- Objective routing is deterministic over a caller-prepared categorical proposal and emits a sanitized planning recommendation. It does not store the raw objective, verify opaque source references, bind a learning projection, inspect live tool readiness, provide a browser intake, create a cockpit row, persist an accepted plan, dispatch a domain owner, or grant execution authority.
- GATE implements the Linux/WSL2 Treehouse `lease`, aggregate `status`, and nonmutating `verify` bridge. Firstmate intake/dispatch, Codex launch, bounded GNHF execution, No Mistakes handoff, and the complete cross-owner lifecycle are not orchestrated.
- The CLI records a No Mistakes review result but does not invoke No Mistakes or cryptographically verify an external attestation. An operator or trusted adapter must provide truthful run data.
- Operator approval receipts are digest-checked local files, not signed identities or remotely attested approvals. Their provenance relies on the single-operator process and filesystem permissions around `GATE_HOME`. This limitation applies to engagement authority; managed-upstream byte integrity is independently anchored to reviewed repository locks.
- GitHub exact-head PR and observed-check preflight is implemented read-only without depending on branch protection. Merge, deploy, and publish remain blocked until a trusted adapter can verify an external No Mistakes attestation for the exact head and enforce project policy. `status --watch`, `down`, and the documented `gate lab` lifecycle are not implemented yet.
- The private project registry validates, deduplicates, stores, lists, shows, and verifies contracts. It does not update or delete them, select a project implicitly, clone repositories, bind workspace commands to a registered contract, or enforce registered delivery and deployment fields in publication adapters.
- Cases bind one exact ready Program Profile and at most one exact managed project into separate private state directories. Their bindings are immutable and become stale when the source profile or project digest changes. This is state separation, not process, credential, filesystem, kernel, or host isolation: every case runs under the same user, and network containment remains adapter-dependent. `gate up` aggregates only the bounded case and Program Profile setup scans, and case token attribution remains unavailable without canonical case-bound records.
- Safety-critical execution and offline-analysis status and reconciliation scan retained control state so old live, orphaned, or ambiguous work is not hidden by the recent-item display caps. Those paths remain `O(history)`; a hard history-independent time and I/O bound requires a crash-safe active/recovery index that is not implemented in v0.1.
- Bug bounty Program Profiles store a private questionnaire and compile deterministic review, scope, technique, coverage, model-context, compatibility, and engagement-proposal artifacts without target contact. The `gate-program-profile` skill is an interaction layer: it can reason from provider-approved current-conversation material, structural questionnaire metadata, and manually sanitized categorical outcomes, then prepare the non-sensitive structure of answer envelopes. It cannot safely ingest arbitrary source bodies or `GATE_HOME` records, attest for the operator, or turn a choice into execution authority. Exact private values require local capture, and raw status, verification, review, and model-context output remain local rather than model input. v0.1 has no built-in model-safe Program Profile projector; an operator or reviewed local controller must supply categorical outcomes manually. Profiles do not retrieve or rehash operator-held source bodies, establish the truth or legal effect of operator-supplied terms, create active engagement authority, obtain a No Mistakes review or operator receipt, admit a workflow phase, or guarantee provider acceptance. Provider predictions depend on a complete, truthful, current operator-supplied capability profile; unsupported or unverified entries must remain `unknown`.
- The Treehouse bridge requires the exact integrity-verified 3.1.3 release, fixed system Git, local refs, and clone-bound one-shot task roots. It invokes only `get` for acquisition; status and verification read bound state directly, and GATE never invokes Treehouse `status`, `return`, or `destroy`. It has no credential/proxy/SSH/network broker, rejects unsafe local Git state including Git LFS filters and submodules, and accepts only the main worktree's checked-out branch as local proof of landing. Verification retains every lease; automatic return, reset, destruction, reuse, and mount-safe cleanup are unavailable. The lifetime limit is 511 retained task roots per physical clone, after which work continues from a new physical clone or waits for future safe upstream lifecycle support. Worktrees do not isolate same-user access to the shared common `.git`, processes, credentials, the kernel, or the host filesystem.
- The 126-tool catalog remains mostly declarative. Seven `core` entries have exact managed release locks and private prefetch/install/verify/remove operations; the other 119 entries remain discovery and admission-planning metadata and require their documented native, GUI, hardware, OCI, language, or external lane.
- Managed-runtime smoke bounds wall time, output, process count, and network access. It does not independently cap memory, open file descriptors, or file size beyond its private temporary filesystems and the host's limits. See [managed-runtime recovery guidance](docs/security-tooling.md#managed-core-runtime) for publication rollback, removal recovery, lock contention, and crash cleanup.
- Offline analysis is implemented only on Linux/WSL2 for one project-bound, fixed-argument REA PE-resource adapter. It requires the pinned `rea-stable` managed upstream and Bubblewrap. The manifest fixes network requests, request rate, and model tokens at zero and parallelism at one; it creates a private input snapshot and bounded evidence, rechecks exact project, artifact, upstream, and runtime identities, and is consumed once. Retained snapshots are capped at 64 files and 2 GiB, with explicit digest-bound purge; aggregate evidence retention remains unbounded. Bubblewrap supplies a fresh network namespace and the adapter verifies loopback-only/no-route/no-capability state, but CPU and memory limits, immutable same-UID protection for the managed REA tree or `GATE_HOME`, and syscall-level Unix-socket denial are unavailable. Installer extraction, signature verification, broader reverse engineering, dynamic Wine analysis, and a resettable Windows VM are not implemented by this lane.
- v0.1 has no general per-tool artifact lock or admission-record store beyond the seven-tool managed core. A discovered Linux/WSL2 executable may enter the supervised generic lane only when its catalog command identity permits PATH discovery; `reviewed-admission` entries remain blocked. For PATH-only entries, `executable-descriptor-observed-sha256` is an observation rather than an immutable snapshot or known-good provenance. A verified managed core runtime establishes exact byte provenance for planning. Only the DNSx exact-domain A observation and HTTPx exact-URL GET observation have reviewed active adapters; broader operations still require exact artifact records and reviewed adapters.
- Engagement creation, review recording, local receipt validation, exact target, `declared-action-label-binding`, tool binding, one-shot manifest generation, supervised execution, stop, and revocation are implemented for host engagements whose approved destinations include `gate-home`. The generic lane enforces immutable argv, target and tool binding, no-shell descriptor execution, private evidence, and one-shot claims. `argv-action-semantics-validation` is unavailable; audit events conservatively use the maximum of the declared action effect and catalog risk ceiling without blocking launch. Wall duration, revocation polling, and process-group termination are best effort while the original supervisor is alive. Egress, request/rate/concurrency/token measurement, daemon containment, `supervisor-crash-containment`, `immutable-executable-snapshot`, filesystem isolation, credential brokering, complete artifact inventory, and known-good provenance are unavailable for the current PATH-discovery generic lane.
- GATE can guide evidence-led custom harness design and offline fixture validation, but v0.1 has no reviewed general harness runner. The generic lane does not bind arbitrary script, plug-in, configuration, dependency, or input bytes, so an active custom harness that depends on those bindings remains blocked until a reviewed adapter or future harness manifest provides them.
- Raw `gate run` and `gate upstream exec` command launchers are disabled. `gate engagement exec` launches only a previously reviewed manifest and accepts no raw command arguments. Run ordinary local development commands directly; target contact requires a reviewed adapter or a separately confirmed supervised generic manifest.
- Engagement completion fields are validated as data, but `engagement close` does not enforce coverage or completion tests; closing is administrative.
- Workflow test plans and reviews are private journal feedback. They do not launch, reserve, admit, stop, or authorize execution; the existing engagement broker and execution adapters remain separate.
- Structured learning promotion binds validation and change references, the exact candidate digest, and a No Mistakes attestation to a full Git head. It does not invoke No Mistakes or cryptographically verify the external attestation's authenticity in v0.1. Consultation reads only bounded public, sanitized active records; private candidates remain outside the projection.
- Repository configuration and policy files are schema-validated contracts. The project registry, Treehouse bridge, broker, publication adapter, observer, learning path, and upstream manager enforce only the fields they explicitly load; v0.1 has no general policy engine that applies every declared provider, limit, data, or lifecycle rule at runtime.
- The local cockpit companion owns one dedicated Codex app-server thread and consumes only the observer's bounded loopback projection. It does not attach to the current cloud chat, expose raw operation details, or replace the separate Program Profile capture surface. GitHub Pages deploys only a checked-in static preview; no reviewed producer publishes live campaign state in v0.1.
- `gate up` is a foreground loopback server; service installation and boot-time startup are pending.
- Aggregate token totals depend on fields present in local Codex session logs. The v0.1 scanner must read those file bytes even though it parses only usage records and never returns prompt bodies; those host records cannot be attributed to a case without a separate case-bound producer. A direct harness telemetry adapter is future work. Account quota and billing data are outside this reader.
- WSL2 cannot provide every native capture, monitor-mode, packet-injection, USB-radio, GPU, or GUI path. `gate doctor` reports host facts; native Linux or Windows tooling may still be required.

Commands that are unavailable must be reported as unavailable. GATE never treats an unverified action, empty scanner result, or missing telemetry as success.

## Repository map

| Path | Purpose |
| --- | --- |
| `AGENTS.md`, `OPINIONS.md` | Repository instructions and durable operator preferences for choices left open by enforced contracts |
| `config/` | Public defaults, questionnaires, security-tool profiles, and the end-to-end penetration-testing workflow |
| `policies/` | Autonomy, data, engagement, learning, and update authority |
| `schemas/` | Machine-readable contracts |
| `catalog/` | Reviewed security-tool metadata |
| `locks/` | Exact upstream and managed-tool runtime pins and integrity values |
| `templates/` | Engagement, learning, project, and report starting points |
| `skills/` | Project-scoped operating skills |
| `src/`, `bin/` | CLI, broker, observer, and supporting libraries |
| `dashboard/` | Read-only observer dashboard and bounded browser projection |
| `cockpit/` | Public static shell, local-only companion, allowlisted Pages build, and boundary tests |
| `memory/` | Sanitized, reviewed repository learning |

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing contracts or adding tools. Follow the private reporting process in [SECURITY.md](SECURITY.md) when reporting a vulnerability.

## License

GATE's original code is available under the [MIT License](LICENSE). Third-party projects and tool installations retain their own licenses; see [THIRD_PARTY.md](THIRD_PARTY.md).
