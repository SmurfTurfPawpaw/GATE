# GATE

**Gateway for Agentic Tooling & Engineering** is a personal, single-operator control plane for agentic software delivery and authorized security work. GATE keeps the reusable system in a public repository while events, target details, credential references, evidence, receipts, and private learning stay under `GATE_HOME`; credential values should remain in an OS secret store or narrowly permissioned file.

GATE is host-first. It is designed to run on a Windows 11 laptop through WSL2 with Codex CLI as the primary harness. Native tools remain appropriate when a GUI, the Windows certificate store, packet capture, USB, a GPU, or radio hardware needs direct host access. Containers can organize conflicting dependencies, but GATE does not treat a container, WSL2, or a Git worktree as a security boundary.

> **Status: v0.1 foundation.** The checked-in policy, schemas, CLI, engagement receipts, observer, token reader, upstream pins, and security-tool catalog work today. The complete Firstmate/Treehouse/No Mistakes publication pipeline, background service management, scope-aware adapters for every security tool, automatic tool installation, deployment, and lab lifecycle remain integration work. See [Current limits](#current-limits).

## Start on Windows 11 with WSL2

Install WSL2 once from an elevated PowerShell prompt, then restart Windows if prompted:

```powershell
wsl --install -d Ubuntu-24.04
```

Inside Ubuntu, install a user-scoped Node.js **22.20 or newer** (Node 24 is also tested), Git, GitHub CLI, and Codex CLI. Authenticate `gh` and `codex` before running the preflight. [docs/setup.md](docs/setup.md) gives the complete laptop, native-tool, Docker, cloud, and troubleshooting guide. The repeatable base setup is:

```bash
git clone https://github.com/SmurfTurfPawpaw/GATE.git ~/src/GATE
cd ~/src/GATE
./scripts/bootstrap.sh --check-only
./scripts/bootstrap.sh
npm run dashboard
```

The bootstrap script does not install system packages or broad security suites. It installs the exact npm lock with lifecycle scripts disabled, creates private runtime directories, validates contracts and pins, runs the tests and doctor, and smoke-checks status and the default catalog profile.

Open <http://127.0.0.1:4173> from Windows. `gate up` stays in the foreground in v0.1, so keep that terminal open or run it in a session manager such as `tmux`. Stop it with `Ctrl+C`. The server rejects non-loopback bind addresses.

The CLI works directly as `./bin/gate.mjs`. If Node was installed with a user-scoped version manager, `npm link` also exposes it as `gate` without `sudo`:

```bash
npm link
gate status
```

Private state defaults to `~/.local/share/gate` inside WSL2. Set `GATE_HOME` before `bootstrap` to use another private location:

```bash
export GATE_HOME="$HOME/.local/share/gate"
```

Do not place `GATE_HOME` inside this repository or a cloud-synced public folder. GATE rejects lexical or physical overlap between the private root and repository in either direction, repairs owner-only POSIX permissions, and rejects linked private paths. In v0.1 it is one local trust domain: a process that can write the whole directory can also change local engagement records, receipts, evidence, and installation receipts. Give write access only to the operator and trusted GATE processes, and keep credential values in a separate OS secret store or narrowly permissioned file referenced by `env://`, `keychain://`, or `file://`.

## What owns each transition

GATE composes upstream projects at exact commits rather than merging their source trees.

| Component | Role |
| --- | --- |
| **Firstmate** | Intake, supervision, dispatch, and the operator decision inbox |
| **Treehouse** | Exclusive development workspace leases and their lifecycle |
| **Codex CLI** | Primary implementation and investigation harness |
| **GNHF** | Optional bounded iteration inside one fresh Treehouse lease |
| **No Mistakes** | Immutable handoff, review, tests, documentation, lint, push, PR, and CI |
| **GATE publication authority** | Read-only exact-head publication preflight; future trusted mutation adapters |
| **GATE engagement broker** | Digest-bound scope preflight; future scope-aware active-security adapters |
| **REA** | Analysis of saved artifacts, captures, binaries, and runtime evidence |
| **Lavish** | Local interactive planning and decision artifacts |
| **AXI** | Agent-facing command and output conventions |
| **Skills CLI** | Distribution of reviewed project-scoped skills |
| **Observer** | Read-only activity, gate, learning, upstream, and token views |

The full ownership and recovery model is in [docs/architecture.md](docs/architecture.md) and [docs/operating-model.md](docs/operating-model.md). Exact upstream commits, versions, and artifact integrity values live in [locks/upstreams.lock.json](locks/upstreams.lock.json); committed npm dependency trees live under [locks/npm](locks/npm).

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

## Active security workflow

Local source review, hypothesis generation, passive research, and analysis of saved evidence can proceed without an active receipt. Contacting a target through scanning, crawling, interception, authentication, fuzzing, exploitation, persistence, denial-of-service testing, or data access requires an engagement whose reviewed report and operator receipt match the exact plan digest, plus a reviewed scope-aware adapter. No such generic execution adapter exists in v0.1.

1. Create the envelope. Use exact targets and exclusions; catalog profiles do not grant authority. URL paths match only on segment boundaries. A query written into an approved URL selector must match exactly, while fragments are rejected because they are not sent to a server.

   ```bash
   ./bin/gate.mjs engagement new acme-web \
     --title "Authorized Acme web assessment" \
     --targets app.acme.example \
     --exclude status.acme.example \
     --actions observe,scan,fuzz,exploit-safe \
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

6. Check the target and action immediately before the proposed active command.

   ```bash
   ./bin/gate.mjs engagement check acme-web \
     --target app.acme.example \
     --action scan
   ```

   The result explicitly reports `preflightOnly: true`, `executionAvailable: false`, and `local-unverified` operator and No Mistakes attestation status. Active execution is disabled in v0.1. A future reviewed adapter must bind the exact tool arguments to the approved target, enforce actual request, rate, concurrency, duration, and token limits, monitor stop conditions and revocation, terminate the whole process group, and preserve evidence. The current `check` result is preflight evidence and does not authorize bypassing that missing adapter.

7. Close the engagement when planning or adapter-driven work ends.

   ```bash
   ./bin/gate.mjs engagement close acme-web
   ```

   `close` is an administrative state change. It does not inspect the coverage map, validate findings, run completion tests, or certify that the assessment is complete.

Changing a target, exclusion, permitted action, plan, written authorization, data destination, authorization window, or material limit requires a new report, review, and receipt. [policies/engagements.json](policies/engagements.json) is the authority contract.

## Security-tool catalog

[catalog/security-tools.json](catalog/security-tools.json) currently describes **122 distinct tools** across web/API, network, identity, exploitation, reverse engineering, mobile, DFIR, OSINT, cloud/Kubernetes, source security, and wireless/radio work. Profiles under [config/profiles](config/profiles) select useful subsets:

```bash
./bin/gate.mjs tool list --profile pentest --json
./bin/gate.mjs tool list --category network --json
./bin/gate.mjs tool plan wireshark --json
```

**Cataloged does not mean installed, trusted, licensed for redistribution, configured, or authorized for a target.** Inventory results report the current host, compatibility, and whether the executable is found. `tool plan` explains the preferred install lane, privileges, risk class, license, and admission work. A persistent addition needs an official source, exact version or commit, integrity evidence where available, license record, effect classification, telemetry decision, smoke test, learning record, and No Mistakes validation.

OWASP ZAP and mitmproxy are the open-source web interception defaults. Burp Suite is an optional, proprietary, operator-supplied integration. If a Kali profile is added, it must remain an optional compatibility toolbox with a pinned package subset, image digest, and SBOM rather than becoming GATE's source of truth. See [docs/security-tooling.md](docs/security-tooling.md).

## Observer and token visibility

`gate up` serves a dependency-free, read-only cockpit on loopback. The browser shows activity, agent/task state, learnings, telemetry freshness, and token use. Its bounded status API also carries engagement and upstream summaries; v0.1 does not yet render dedicated panels for those summaries. Keyboard shortcuts are:

| Key | Action |
| --- | --- |
| `1`–`4` | Focus fleet, activity, usage, or learning |
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

Public project-scoped learning fails closed until GATE has a project registry and destination. Record it with `--private --scope project` in the meantime; repository-scoped sanitized learning continues to use the reviewed public ledger.

A learning is complete only when the behavior, policy, configuration, test, or documentation actually changes. Repository-level promotion goes through No Mistakes, and new evidence supersedes or reverts earlier guidance without erasing history. Target or tool output is untrusted data: it may suggest a learning, but it cannot directly alter memory, policy, authorization, or publication rights.

## Upstreams

Inspect pins before installing anything:

```bash
./bin/gate.mjs upstream list --json
```

`upstream sync ID` clones the named source and detaches it at the locked full commit under `GATE_HOME`. For npm entries, `upstream install ID` verifies the committed package-lock digest, runs `npm ci` with lifecycle scripts disabled, and verifies the installed tree against a second offline reconstruction. It also installs the locked Treehouse and No Mistakes release artifacts on supported hosts after verifying their SHA-256, archive paths, and single executable. The installer records the version from the reviewed lock and does not execute a freshly downloaded binary. Later full status and path-resolution checks revalidate the npm tree or release executable. `upstream install all` covers both managed lanes. Source, skill, and other lanes still require their documented sync or installer and smoke test.

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

- Firstmate, Treehouse, GNHF, No Mistakes, REA, Lavish, AXI, and Skills CLI are pinned composition points; the GATE CLI does not yet orchestrate their complete lifecycle.
- The CLI records a No Mistakes review result but does not invoke No Mistakes or cryptographically verify an external attestation. An operator or trusted adapter must provide truthful run data.
- Operator approval receipts are digest-checked local files, not signed identities or remotely attested approvals. Their provenance relies on the single-operator process and filesystem permissions around `GATE_HOME`. This limitation applies to engagement authority; managed-upstream byte integrity is independently anchored to reviewed repository locks.
- GitHub exact-head PR and required-check preflight is implemented read-only. Merge, deploy, and publish remain blocked until a trusted adapter can verify an external No Mistakes attestation for the exact head and enforce project policy. The project registry, `status --watch`, `down`, and the documented `gate lab` lifecycle are also not implemented yet.
- The 122-tool catalog is declarative. GATE detects executables and produces admission plans, but it does not automatically install the catalog.
- v0.1 has no per-tool artifact lock or admission-record store. Catalog entries are capability metadata; they are not executable admissions until a reviewed adapter and immutable lock record exist.
- Engagement creation, review recording, local receipt validation, and exact target/action checks are implemented. Arbitrary active execution is disabled until reviewed scope-aware adapters can validate tool arguments, enforce actual limits and stop conditions, terminate process groups, and preserve evidence.
- Raw `gate run` and `gate upstream exec` command launchers are disabled. Run ordinary local development commands directly; target contact requires a reviewed scope-aware adapter.
- Engagement completion fields are validated as data, but `engagement close` does not enforce coverage or completion tests; closing is administrative.
- Repository configuration and policy files are schema-validated contracts. The broker, publication adapter, observer, learning path, and upstream manager enforce only the fields they explicitly load; v0.1 has no general policy engine that applies every declared provider, lease, limit, data, or lifecycle rule at runtime.
- `gate up` is a foreground loopback server; service installation and boot-time startup are pending.
- Token totals depend on fields present in local Codex session logs. The v0.1 scanner must read those file bytes even though it parses only usage records and never returns prompt bodies; a direct harness telemetry adapter is future work. Account quota and billing data are outside this reader.
- WSL2 cannot provide every native capture, monitor-mode, packet-injection, USB-radio, GPU, or GUI path. `gate doctor` reports host facts; native Linux or Windows tooling may still be required.

Commands that are unavailable must be reported as unavailable. GATE never treats an unverified action, empty scanner result, or missing telemetry as success.

## Repository map

| Path | Purpose |
| --- | --- |
| `config/` | Public defaults and security-tool profiles |
| `policies/` | Autonomy, data, engagement, learning, and update authority |
| `schemas/` | Machine-readable contracts |
| `catalog/` | Reviewed security-tool metadata |
| `locks/` | Exact upstream pins and integrity values |
| `templates/` | Engagement, learning, project, and report starting points |
| `skills/` | Project-scoped operating skills |
| `src/`, `bin/` | CLI, broker, observer, and supporting libraries |
| `dashboard/` | Read-only local cockpit |
| `memory/` | Sanitized, reviewed repository learning |

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing contracts or adding tools. Follow the interim private-contact process in [SECURITY.md](SECURITY.md) when reporting a vulnerability.

## License

GATE's original code is available under the [MIT License](LICENSE). Third-party projects and tool installations retain their own licenses; see [THIRD_PARTY.md](THIRD_PARTY.md).
