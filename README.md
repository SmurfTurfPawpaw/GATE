# GATE

**Gateway for Agentic Tooling & Engineering** is a personal, single-operator control plane for agentic software delivery and authorized security work. GATE keeps the reusable system in a version-controlled repository while events, target details, credential references, evidence, receipts, and private learning stay under `GATE_HOME`; credential values should remain in an OS secret store or narrowly permissioned file.

GATE is host-first. It is designed to run on a Windows 11 laptop through WSL2 with Codex CLI as the primary harness. Native tools remain appropriate when a GUI, the Windows certificate store, packet capture, USB, a GPU, or radio hardware needs direct host access. Containers can organize conflicting dependencies, but GATE does not treat a container, WSL2, or a Git worktree as a security boundary.

> **Status: v0.1 foundation.** The checked-in policy, schemas, CLI, private project registry, project-bound zero-network PE-resource analysis, verified Treehouse lease bridge, engagement receipts, one-shot supervised generic execution, observer, token reader, upstream pins, 126-tool security catalog, seven-tool managed core runtime, and end-to-end penetration-testing map work today. Complete Firstmate, GNHF, and No Mistakes orchestration, broader reviewed per-tool adapters and runtime locks, deployment, and lab lifecycle remain integration work. See [Current limits](#current-limits).

## Start on Windows 11 with WSL2

Install WSL2 once from an elevated PowerShell prompt, then restart Windows if prompted:

```powershell
wsl --install -d Ubuntu-24.04
```

Inside Ubuntu, install Node.js **22.20 or newer** (Node 24 is also tested) from an OS- or administrator-owned location that your normal account cannot modify, plus Git, GitHub CLI, and Codex CLI. User-owned Node managers are incompatible with managed-upstream verification because they can replace npm between verification and launch. Authenticate `gh` and `codex`, then export a GitHub token for the isolated release downloader. [docs/setup.md](docs/setup.md) gives verified Node 24 installation commands and the complete laptop, native-tool, Docker, cloud, and troubleshooting guide. The repeatable base setup is:

```bash
git clone https://github.com/SmurfTurfPawpaw/GATE.git ~/src/GATE
cd ~/src/GATE
export GH_TOKEN="$(gh auth token)"
./scripts/bootstrap.sh --check-only
./scripts/bootstrap.sh
npm run dashboard
```

The bootstrap script does not install system packages or broad security suites. It installs the exact npm lock with lifecycle scripts disabled, creates private runtime directories, validates contracts and pins, runs the tests and doctor, and smoke-checks status and the default catalog profile. After the base preflight, `./scripts/bootstrap.sh --install-core-tools` installs the seven reviewed release runtimes and requires a nonempty installed and byte-verified core result from the smoke suite.

Open <http://127.0.0.1:4173> from Windows. `gate up` stays in the foreground in v0.1, so keep that terminal open or run it in a session manager such as `tmux`. Stop it with `Ctrl+C`. The server rejects non-loopback bind addresses.

The CLI works directly from the checkout:

```bash
./bin/gate.mjs status
```

Private state defaults to `~/.local/share/gate` inside WSL2. Set `GATE_HOME` before `bootstrap` to use another private location:

```bash
export GATE_HOME="$HOME/.local/share/gate"
```

Do not place `GATE_HOME` inside this repository or a cloud-synced public folder. GATE rejects lexical or physical overlap between the private root and repository in either direction, repairs owner-only POSIX permissions, and rejects linked control-state paths. In v0.1 it is one local trust domain: a process that can write the whole directory can also change project records, offline snapshots and manifests, engagement records, receipts, active-execution manifests, claims, runs, stops, evidence, managed tool caches and runtimes, and installation receipts. Give write access only to the operator and trusted GATE processes, and keep credential values in a separate OS secret store or narrowly permissioned file referenced by `env://`, `keychain://`, or `file://`.

## What owns each transition

GATE composes upstream projects at exact commits rather than merging their source trees.

| Component | Role |
| --- | --- |
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
| **Observer** | Read-only activity, gate, learning, upstream, and token views |

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

The preflight requires an open, non-draft pull request whose head matches exactly, a `CLEAN` GitHub merge state, and a nonempty set of required checks in successful buckets. A head change, an empty required-check set, or unavailable PR/check state fails closed.

Publication mutation is disabled in v0.1. The adapter treats `--run` as operator-supplied provenance; it does not invoke No Mistakes, correlate the ID with the head, or verify an attestation. A future trusted adapter must verify a No Mistakes attestation bound to the exact head and enforce the registered repository, base branch, merge posture, and destination before it can merge, deploy, or publish. `check` and `dry-run` create reviewable evidence without mutation.

## Offline artifact analysis

GATE has one narrow implemented offline adapter for a supplied Windows PE file. It runs REA's `inspect-pe-resources` operation without executing the input. The lane is bound to a registered project but is separate from the engagement broker because the operation has no target contact. Install the pinned `rea-stable` upstream and Bubblewrap on Linux or WSL2, then inspect capability:

```bash
./bin/gate.mjs upstream install rea-stable --json
./bin/gate.mjs analysis capability --json
```

Capability checks prerequisite presence and launches a minimal Bubblewrap namespace; it does not verify the full managed REA tree. Register a private project, then create and review a manifest for one exact absolute regular-file path:

```bash
./bin/gate.mjs analysis manifest \
  --project my-project \
  --path "$HOME/private/client-installer.exe" \
  --minutes 15 --json

./bin/gate.mjs analysis run \
  --project my-project \
  --manifest MANIFEST_ID \
  --confirm "ANALYZE MANIFEST_ID MANIFEST_SHA256 OFFLINE" --json

./bin/gate.mjs analysis status --json
```

Use the exact returned confirmation after reviewing the complete manifest. The [offline-analysis operating procedure](docs/operating-model.md#offline-static-artifact-analysis) owns the integrity checks, bindings, isolation guarantees and unavailable controls, evidence limits, snapshot quotas, crash recovery, and digest-bound purge procedure. This adapter supplies PE-resource inspection, rather than a general reverse-engineering or dynamic-analysis environment.

Possession of a local file authorizes neither network access nor testing of its publisher. A proprietary client or other proprietary artifact must be lawfully supplied by the operator and remains private under `GATE_HOME`. Strings, hostnames, URLs, certificate names, and update endpoints found in it are offline hypotheses. GATE must not resolve, browse, scan, authenticate to, intercept, or otherwise contact those systems until separate written authority and an exact active engagement cover the selector and action.

The machine-readable [end-to-end penetration-testing workflow](config/workflows/pentest-e2e.json) and [operator guide](docs/pentest-workflow.md) carry offline observations through passive corroboration, active mapping, specialist workstreams, controlled exploitation, impact validation, cleanup, retest, and reporting. The workflow does not itself grant authority or prove that a cataloged tool is installed.

## Active security workflow

Local source review, hypothesis generation, declared passive research, and analysis of saved evidence can proceed without an active receipt under their data and provider rules. Contacting a target through scanning, crawling, interception, authentication, fuzzing, exploitation, persistence, denial-of-service testing, or data access requires an engagement whose reviewed report and operator receipt match the exact plan digest. Each launch then uses either a reviewed scope-aware adapter or the Linux/WSL2 supervised generic lane described below. The generic lane supports only receipt-bound `scope.environment: host`; container, rootless-container, VM, and remote-lab engagements need a lane that implements that environment. Follow the [end-to-end workflow](docs/pentest-workflow.md) to map prerequisites, evidence, stop conditions, and handoffs before selecting a tool.

Nmap remains a planning example: `./bin/gate.mjs tool plan nmap --json` reports its admission requirements. It is blocked from generic execution pending reviewed runtime admission, even when installed and permitted by an engagement.

The runnable walkthrough below uses ExifTool to read metadata from an operator-supplied copied image. Before starting, set `GATE_HOME` to your private runtime root and place the authorized copy at `$GATE_HOME/artifacts/sample.jpg`. Install a reviewed, exactly versioned ExifTool from its official source through its `native-os` lane; GATE does not install it from the catalog. Its catalog ID and command are `exiftool`, risk class is `P0`, and command identity requires `pathDiscovery: command-name` and `genericLaneAdmission: path-discovery`. Linux/WSL2 with `/proc` mounted and the executable on `PATH` are required. Check `./bin/gate.mjs tool plan exiftool --json` and require `genericLaneEligible: true` before creating a manifest; that result does not verify version, integrity, or provenance. The plan and receipt must cover this exact file, `observe`, `exiftool`, the host environment, and `gate-home`. This generic metadata example has host access; use the separate fixed offline lane when zero-egress isolation is required.

1. Create the envelope. Use exact targets and exclusions; catalog profiles do not grant authority. URL paths match only on segment boundaries. A query written into an approved URL selector must match exactly, while fragments are rejected because they are not sent to a server.

   ```bash
   ./bin/gate.mjs engagement new acme-web \
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
   ./bin/gate.mjs engagement authorization acme-web \
     --file "$HOME/private/acme-web-written-authorization.pdf"
   ```

3. Write the concrete engagement report from [templates/plan-review.md](templates/plan-review.md). It must name targets, actions, tools, expected effects, coverage, limits, data handling, stop conditions, risks, and completion tests. Attach it; GATE copies it to private state and returns `plan.sha256`.

   ```bash
   ./bin/gate.mjs engagement plan acme-web \
     --file "$HOME/private/acme-web-plan.md"
   ```

4. Run a real No Mistakes review against an immutable commit. Record its run ID, full 40-character head SHA, and result. Recording a value is not a substitute for running the review.

   ```bash
   ./bin/gate.mjs engagement review acme-web \
     --run NO_MISTAKES_RUN_ID \
     --head 0123456789abcdef0123456789abcdef01234567 \
     --result passed
   ```

5. Show the operator the complete report and digest. The operator supplies an exact receipt for that digest. Agents must never invent or infer the confirmation string. The receipt binds the plan, engagement envelope, and SHA-256 of the written authorization; changing any of them invalidates active preflight.

   ```bash
   ./bin/gate.mjs engagement approve acme-web \
     --sha PLAN_SHA256 \
     --confirm "APPROVE acme-web"
   ```

6. Check the target and declared action label immediately before the proposed active command. An allowed result includes an `executionBinding` for the exact engagement, plan, envelope, receipt, authorization expiry, target, action label, environment, permitted tool list, and allowed destinations. The generic lane requires receipt-approved `gate-home` because its raw evidence always lands under `GATE_HOME`. The recorded operator and No Mistakes provenance remains `local-unverified` rather than a cryptographic external attestation.

   ```bash
   ./bin/gate.mjs engagement check acme-web \
     --target "$GATE_HOME/artifacts/sample.jpg" \
     --action observe
   ```

7. Create a private one-shot manifest. The values after `--` are the complete tool argument array; `--tool` selects the executable. The arguments must contain exactly one whole value equal to `{{GATE_TARGET}}`, which GATE replaces with the checked target. The tool ID must be in the receipt-bound `--tools` list, its catalog `commandIdentity.genericLaneAdmission` must be `path-discovery`, its command must resolve on `PATH`, its host must be supported, and the requested bounds must fit within the approved engagement limits. A verified managed core runtime does not satisfy this execution gate until a reviewed workflow-phase adapter binds its action and argument semantics.

   ```bash
   ./bin/gate.mjs engagement manifest acme-web \
     --target "$GATE_HOME/artifacts/sample.jpg" \
     --action observe \
     --tool exiftool \
     --minutes 15 \
     --requests 500 \
     --parallel 2 \
     --rate 5 \
     --tokens 1000 \
     --json -- -json "{{GATE_TARGET}}"
   ```

   Review the returned `operation`, `argv0`, expanded `argv`, target argument index, catalog risk class, executable descriptor and observed SHA-256, declared bounds, expiry, and complete `enforcement` object. Inspect the owner-only manifest named by `manifestRef` for its receipt-bound `gate-home` destination, private sandbox, and stdout, stderr, and result paths. The manifest binds the current plan, envelope, receipt, host environment, allowed destinations, target, declared action label, permitted tool, catalog risk class, observed executable identity, exact arguments, and evidence paths. It expires and can be claimed only once; a failed or interrupted attempt does not make it reusable.

8. Ask the operator to supply the exact `confirmationRequired` value. It has the form `EXECUTE MANIFEST_ID MANIFEST_SHA256 UNMETERED`. Agents must never generate, infer, shorten, or reuse this second confirmation. Execute only by manifest ID; `engagement exec` accepts no new target, tool, or command arguments.

   ```bash
   ./bin/gate.mjs engagement exec acme-web \
     --manifest MANIFEST_ID \
     --confirm "EXECUTE MANIFEST_ID MANIFEST_SHA256 UNMETERED" \
     --json
   ```

   On Linux or WSL2, GATE opens and hashes the executable, rechecks its descriptor metadata immediately before spawn, launches that descriptor through `/proc/self/fd` with `shell: false`, supplies an empty stdin and minimal environment, creates a fresh process group, and writes bounded stdout, stderr, result metadata, and the working sandbox privately under `GATE_HOME`. While the original `gate engagement exec` supervisor remains alive, it polls engagement validity and operator stop state, applies the declared wall-duration bound, and attempts `SIGTERM` then `SIGKILL` for the process group when required.

   The `UNMETERED` suffix acknowledges the generic lane's exact limits. `argv-action-semantics-validation`, egress-target restriction, request counting, rate measurement, tool concurrency measurement, token measurement, daemon-escape containment, `supervisor-crash-containment`, `immutable-executable-snapshot`, filesystem isolation, credential brokering, complete tool artifact inventory, and known-good executable provenance are `unavailable`. `declared-action-label-binding` does not prove the arbitrary argv implements that class; the operator must review it, and only a reviewed adapter validates tool-specific flags. For audit visibility, execution events use the more severe of the declared action effect and the catalog tool's risk ceiling. That conservative classification does not block launch. Revocation polling, duration enforcement, and process-group termination are best effort and require the original supervisor to remain alive. The child runs with the same UID and host access as GATE. `executable-descriptor-observed-sha256` records bytes read through the opened descriptor. A same-UID writer can mutate a writable inode before or during exec, so the digest does not prove an atomically frozen launched byte snapshot or the identity of interpreters, shared libraries, plug-ins, configuration, inputs, or child processes. Use a reviewed adapter or a separately isolated lab when those guarantees matter.

9. From another terminal, request a stop for one run, or revoke the complete engagement. Stop and revocation are durable requests, but only the live original supervisor polls and acts on them. A supervisor crash or `SIGKILL` has no takeover path and can leave the ordinary tool process group alive; same-user processes that leave the process group also remain outside supervision. If authenticated group identity is lost during teardown, the run becomes `unknown` with termination reason `supervision-lost` instead of claiming termination.

   ```bash
   ./bin/gate.mjs engagement stop acme-web --run RUN_ID --json
   ./bin/gate.mjs engagement revoke acme-web \
     --confirm "REVOKE acme-web" --json
   ```

10. Close the engagement when work ends.

   ```bash
   ./bin/gate.mjs engagement close acme-web
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

Every operation also accepts one tool ID in place of `--profile`; the two selectors are mutually exclusive. The reviewed lock binds the exact catalog entry, version, full source commit, release evidence, artifact URL and size, archive and executable SHA-256, exact archive members, platform, and bounded smoke specification. Release artifacts are pinned for Linux and macOS on x64 and ARM64. Installation and live verification currently require the Bubblewrap/prlimit zero-egress smoke supervisor on Linux or WSL2; macOS can prefetch and verify the archive bytes but cannot activate the runtime until an equivalent reviewed smoke sandbox exists. All seven verified binaries remain invocation-blocked pending reviewed workflow-phase adapters that bind each action and argument shape. `naabu` additionally needs a raw-network privilege adapter, and `nuclei` additionally needs reviewed template admission. The other catalog entries still use their documented native, GUI, hardware, OCI, language, or external installation lanes.

Release bytes, staging directories, installed executables, and receipts stay private under `GATE_HOME`. Cockpit and `status` refreshes show dated receipt evidence rather than current integrity. See the [managed-runtime verification boundary](docs/security-tooling.md#managed-core-runtime) for inventory, doctor, planning, explicit verification, and pre-execution checks. Installation grants no target authority or execution admission.

For managed REA, cheap inventory can report a matching install receipt as `managed-receipt`, but that is no integrity or readiness claim. `tool plan rea` performs full managed-upstream verification; when its host prerequisites pass, it exposes only the `offline-static-pe-resources` adapter while `genericLaneEligible` and `broadCapabilityReady` remain false. `tool plan` otherwise explains the preferred install lane, privileges, risk class, license, generic-lane status, and admission work. A persistent addition needs an official source, exact version or commit, integrity evidence where available, license record, effect classification, telemetry decision, smoke test, learning record, and No Mistakes validation.

OWASP ZAP and mitmproxy are the open-source web interception defaults. Burp Suite is an optional, proprietary, operator-supplied integration. If a Kali profile is added, it must remain an optional compatibility toolbox with a pinned package subset, image digest, and SBOM rather than becoming GATE's source of truth. See [docs/security-tooling.md](docs/security-tooling.md).

## Observer and token visibility

`gate up` serves a dependency-free, read-only cockpit on loopback. The browser shows activity, agent/task state, active execution, a privacy-filtered offline-analysis panel, managed runtime counts and constraints, learnings, telemetry freshness, and token use. Its bounded status API also carries engagement and upstream summaries; v0.1 does not yet render dedicated panels for those two summaries. Runtime `unresolved` is full-catalog readiness rather than a failed-install count: even with all seven core releases verified, `executable` remains zero and all 126 entries are unresolved because the core still needs workflow-phase admission and the other 119 entries remain unmanaged. Keyboard shortcuts are:

Agents should use `gate status --summary --json` and `gate tool list --summary --json`; use `gate tool show ID --json` for one bounded item. See [observation and token accounting](docs/architecture.md#observation-and-token-accounting) for output bounds, pagination, source digests, and telemetry limitations.

| Key | Action |
| --- | --- |
| `1` | Focus agents and tasks |
| `2` | Focus activity |
| `3` | Focus active execution |
| `4` | Focus resource posture |
| `5` | Focus learning |
| `6` | Focus offline analysis |
| `7` | Focus managed tool runtimes |
| `/` | Focus the safe metadata filter |
| `R` | Refresh now |
| `P` | Pause or resume polling |
| `?` | Open shortcut help |

GATE streams local Codex session JSONL files under `CODEX_HOME/sessions` or `~/.codex/sessions` and parses only token-count/usage records. Provider counters are labeled `exact`; a missing value is `unavailable`, never zero. The scanner necessarily reads session-file bytes, but it never returns prompt bodies. The observer's browser API omits prompts, responses, commands, tool output, target selectors, absolute paths, and evidence contents.

## Learn and adapt

Every operator correction, failed action, retry, workaround, tool gap, better-tool discovery, policy violation, benchmark regression, evidence contradiction, or unexpected environment constraint must result in a recorded cause-and-change learning candidate.

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

A learning is complete only when the behavior, policy, configuration, test, or documentation actually changes. Repository-level promotion goes through No Mistakes, and new evidence supersedes or reverts earlier guidance without erasing history. Target or tool output is untrusted data: it may suggest a learning, but it cannot directly alter memory, policy, authorization, or publication rights.

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
  --skill gate-workflow \
  --skill gate-security-engagement \
  --skill gate-continuous-learning \
  --agent codex --yes
```

This is a project-scoped install. Do not add `--global`; review and pin the GATE source commit before distributing its skill content.

## Current limits

The v0.1 boundary is intentionally explicit:

- GATE implements the Linux/WSL2 Treehouse `lease`, aggregate `status`, and nonmutating `verify` bridge. Firstmate intake/dispatch, Codex launch, bounded GNHF execution, No Mistakes handoff, and the complete cross-owner lifecycle are not orchestrated.
- The CLI records a No Mistakes review result but does not invoke No Mistakes or cryptographically verify an external attestation. An operator or trusted adapter must provide truthful run data.
- Operator approval receipts are digest-checked local files, not signed identities or remotely attested approvals. Their provenance relies on the single-operator process and filesystem permissions around `GATE_HOME`. This limitation applies to engagement authority; managed-upstream byte integrity is independently anchored to reviewed repository locks.
- GitHub exact-head PR and required-check preflight is implemented read-only. Merge, deploy, and publish remain blocked until a trusted adapter can verify an external No Mistakes attestation for the exact head and enforce project policy. `status --watch`, `down`, and the documented `gate lab` lifecycle are not implemented yet.
- The private project registry validates, deduplicates, stores, lists, shows, and verifies contracts. It does not update or delete them, select a project implicitly, clone repositories, bind workspace commands to a registered contract, or enforce registered delivery and deployment fields in publication adapters.
- The Treehouse bridge requires the exact integrity-verified 3.1.3 release, fixed system Git, local refs, and clone-bound one-shot task roots. It invokes only `get` for acquisition; status and verification read bound state directly, and GATE never invokes Treehouse `status`, `return`, or `destroy`. It has no credential/proxy/SSH/network broker, rejects unsafe local Git state including Git LFS filters and submodules, and accepts only the main worktree's checked-out branch as local proof of landing. Verification retains every lease; automatic return, reset, destruction, reuse, and mount-safe cleanup are unavailable. The lifetime limit is 511 retained task roots per physical clone, after which work continues from a new physical clone or waits for future safe upstream lifecycle support. Worktrees do not isolate same-user access to the shared common `.git`, processes, credentials, the kernel, or the host filesystem.
- The 126-tool catalog remains mostly declarative. Seven `core` entries have exact managed release locks and private prefetch/install/verify/remove operations; the other 119 entries remain discovery and admission-planning metadata and require their documented native, GUI, hardware, OCI, language, or external lane.
- Managed-runtime smoke bounds wall time, output, process count, and network access. It does not independently cap memory, open file descriptors, or file size beyond its private temporary filesystems and the host's limits. See [managed-runtime recovery guidance](docs/security-tooling.md#managed-core-runtime) for publication rollback, removal recovery, lock contention, and crash cleanup.
- Offline analysis is implemented only on Linux/WSL2 for one project-bound, fixed-argument REA PE-resource adapter. It requires the pinned `rea-stable` managed upstream and Bubblewrap. The manifest fixes network requests, request rate, and model tokens at zero and parallelism at one; it creates a private input snapshot and bounded evidence, rechecks exact project, artifact, upstream, and runtime identities, and is consumed once. Retained snapshots are capped at 64 files and 2 GiB, with explicit digest-bound purge; aggregate evidence retention remains unbounded. Bubblewrap supplies a fresh network namespace and the adapter verifies loopback-only/no-route/no-capability state, but CPU and memory limits, immutable same-UID protection for the managed REA tree or `GATE_HOME`, and syscall-level Unix-socket denial are unavailable. Installer extraction, signature verification, broader reverse engineering, dynamic Wine analysis, and a resettable Windows VM are not implemented by this lane.
- v0.1 has no general per-tool artifact lock or admission-record store beyond the seven-tool managed core. A discovered Linux/WSL2 executable may enter the supervised generic lane only when its catalog command identity permits PATH discovery; `reviewed-admission` entries remain blocked. For PATH-only entries, `executable-descriptor-observed-sha256` is an observation rather than an immutable snapshot or known-good provenance. A verified managed core runtime establishes exact byte provenance for planning but remains execution-blocked until a reviewed workflow-phase adapter binds action and argument semantics. Broader normal admission still requires exact artifact records and reviewed adapters.
- Engagement creation, review recording, local receipt validation, exact target, `declared-action-label-binding`, tool binding, one-shot manifest generation, supervised execution, stop, and revocation are implemented for host engagements whose approved destinations include `gate-home`. The generic lane enforces immutable argv, target and tool binding, no-shell descriptor execution, private evidence, and one-shot claims. `argv-action-semantics-validation` is unavailable; audit events conservatively use the maximum of the declared action effect and catalog risk ceiling without blocking launch. Wall duration, revocation polling, and process-group termination are best effort while the original supervisor is alive. Egress, request/rate/concurrency/token measurement, daemon containment, `supervisor-crash-containment`, `immutable-executable-snapshot`, filesystem isolation, credential brokering, complete artifact inventory, and known-good provenance are unavailable for the current PATH-discovery generic lane.
- Raw `gate run` and `gate upstream exec` command launchers are disabled. `gate engagement exec` launches only a previously reviewed manifest and accepts no raw command arguments. Run ordinary local development commands directly; target contact requires a reviewed adapter or a separately confirmed supervised generic manifest.
- Engagement completion fields are validated as data, but `engagement close` does not enforce coverage or completion tests; closing is administrative.
- Repository configuration and policy files are schema-validated contracts. The project registry, Treehouse bridge, broker, publication adapter, observer, learning path, and upstream manager enforce only the fields they explicitly load; v0.1 has no general policy engine that applies every declared provider, limit, data, or lifecycle rule at runtime.
- `gate up` is a foreground loopback server; service installation and boot-time startup are pending.
- Token totals depend on fields present in local Codex session logs. The v0.1 scanner must read those file bytes even though it parses only usage records and never returns prompt bodies; a direct harness telemetry adapter is future work. Account quota and billing data are outside this reader.
- WSL2 cannot provide every native capture, monitor-mode, packet-injection, USB-radio, GPU, or GUI path. `gate doctor` reports host facts; native Linux or Windows tooling may still be required.

Commands that are unavailable must be reported as unavailable. GATE never treats an unverified action, empty scanner result, or missing telemetry as success.

## Repository map

| Path | Purpose |
| --- | --- |
| `config/` | Public defaults, security-tool profiles, and the end-to-end penetration-testing workflow |
| `policies/` | Autonomy, data, engagement, learning, and update authority |
| `schemas/` | Machine-readable contracts |
| `catalog/` | Reviewed security-tool metadata |
| `locks/` | Exact upstream and managed-tool runtime pins and integrity values |
| `templates/` | Engagement, learning, project, and report starting points |
| `skills/` | Project-scoped operating skills |
| `src/`, `bin/` | CLI, broker, observer, and supporting libraries |
| `dashboard/` | Read-only local cockpit |
| `memory/` | Sanitized, reviewed repository learning |

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing contracts or adding tools. Follow the interim private-contact process in [SECURITY.md](SECURITY.md) when reporting a vulnerability.

## License

GATE's original code is available under the [MIT License](LICENSE). Third-party projects and tool installations retain their own licenses; see [THIRD_PARTY.md](THIRD_PARTY.md).
