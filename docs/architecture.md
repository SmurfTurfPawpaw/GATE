# GATE architecture

GATE is a personal, single-operator control plane for software delivery and evidence-led security work. It composes pinned upstream tools and adds only the coordination that those tools do not provide: a shared policy model, a private project registry, a verified Treehouse lease bridge, an append-only observer, a publication authority, an active-security authority, and durable learning. This document describes the target architecture; [README.md](../README.md#current-limits) identifies which v0.1 paths are wired today.

The repository is the reusable public distribution. Live sessions, target details, raw evidence, credential references, and private learning stay outside Git under `GATE_HOME`. Credential values should remain in an OS secret store or narrowly permissioned file outside broad agent-writable roots.

## Design constraints

- The laptop is the default execution environment.
- Codex CLI is the primary runtime harness. Firstmate does not currently support Codex App as a runtime backend.
- A person must be able to bootstrap, inspect, start, stop, and reset GATE without an AI.
- Upstream projects remain pinned dependencies. GATE does not combine their source trees.
- Each state transition has one owner.
- Active target contact follows a reviewed, digest-bound engagement plan.
- Every claim distinguishes observation, inference, and what remains unverified.
- Every persistent lesson records the cause and the resulting change.
- Missing token data is shown as unavailable; estimates are labeled.

## Control flow

```mermaid
flowchart TD
    O[Operator] --> R[Private project contract]
    R --> P[Lavish plan or direct intent]
    P --> F[Firstmate supervisor]
    F --> T[Verified Treehouse lease]
    T --> W[Codex worker]
    W --> G{Bounded loop needed?}
    G -->|yes| H[GNHF in the leased workspace]
    G -->|no| C[Immutable commit]
    H --> C
    C --> N[No Mistakes validation, push, PR, CI]
    N --> A[GATE publication authority]
    A --> M[Merge, deploy, or publish]
    W --> E[Events, evidence, and token usage]
    N --> E
    A --> E
    E --> V[Read-only observer]
    E --> L[Learning candidates]
    L --> N
```

Security work adds a separate authority path:

```mermaid
flowchart LR
    I[Local research and hypotheses] --> R[Plan and coverage map]
    R --> Q[No Mistakes plan review]
    Q --> U[Operator sees and approves exact digest]
    U --> B[GATE engagement broker]
    B --> X[In-scope tools]
    X --> E[Private evidence]
    E --> REA[REA analysis]
    REA --> D[Validated report and retest]
    D --> L[Learning candidates]
```

Changing a target, action class, exclusion, data destination, or limit invalidates the receipt. In the target design, a reviewed adapter can continue autonomously inside the approved envelope. v0.1 stops at target/action preflight because no generic active adapter meets that contract.

## Ownership

| Component | Owns | Does not own |
|---|---|---|
| GATE project registry | Private validated project contracts and canonical repository identity | Repository checkout, task dispatch, authorization, or policy-wide enforcement |
| Firstmate | Intake, supervisor state, dispatch, decision inbox | Worktree lifecycle, target authorization, publication |
| Treehouse | Development workspace allocation, durable leases, and its versioned state format | Orchestration, safe destructive cleanup, or security isolation |
| GNHF | A bounded iterative task inside one exclusive lease | Worktree creation, push, PR, or policy |
| No Mistakes | Handoff, rebase, review, tests, documentation, lint, push, PR, CI | Merge, deployment, target authorization, arbitrary tool execution |
| GATE publication authority | Read-only exact-head and required-check preflight in v0.1; trusted mutation adapters in the target design | Editing or reviewing the change |
| GATE engagement broker | Plan receipt and target/action preflight; future scope-aware adapter admission | Creating its own authorization or launching arbitrary commands |
| REA | Analysis of binaries, artifacts, saved captures, and runtime evidence | Traffic acquisition or active target operations |
| AXI | Agent-facing command and output conventions | Trust, policy, or orchestration |
| Skills CLI | Installation and synchronization of reviewed skills | Deciding whether a skill is trustworthy |
| Lavish | A local interactive plan or decision artifact | Continuous operations monitoring |
| Observer | Read-only GATE activity, derived agent/task, learning, status, and token views | Execution |
| Learning pipeline | Correction capture and validated memory changes | Expanding authorization or releasing data |

No Mistakes deliberately stops when a PR is ready. In v0.1, the publication authority can only inspect PR state, exact head, mergeability, and required checks. A future mutation adapter must verify a No Mistakes attestation bound to that head before it can merge, deploy, or publish. GATE never reports that upstream No Mistakes performed those actions.

## State and data boundaries

Tracked repository content:

- schemas, policies, templates, and configuration defaults;
- reviewed project-scoped skills and exact dependency locks;
- sanitized repository-wide lessons;
- documentation and adapters.

Private runtime content under `GATE_HOME`:

- `events.jsonl` and `tokens.jsonl`;
- engagement plans, authorization evidence, receipts, and audit trails;
- registered project contracts, including repository and delivery references;
- raw captures, binaries, screenshots, recordings, and tool output;
- private learning records;
- upstream checkouts, private clone-bound and task-bound Treehouse roots, process state, and logs.

The default is `$HOME/.local/share/gate`. `GATE_HOME` overrides it. Machine-specific settings may be placed at `$HOME/.config/gate/config.json`; v0.1 has a merge helper for that file but most commands do not yet load a complete merged provider/profile configuration. The target precedence is repository defaults, selected profile, local override, then explicit command-line arguments.

Tracked secrets may appear only as `env://`, `keychain://`, or `file://` references. v0.1 validates those shapes and redacts recognized sensitive text in supported event paths, but it has no general secret resolver or data-flow policy engine. Keep credential values in an OS secret store or narrowly permissioned file outside broad agent-writable roots.

`GATE_HOME` is one local trust domain for project configuration, engagement authority, and private evidence in v0.1. A process that can rewrite project or engagement state can change the local configuration it describes, and one that can rewrite both engagement state and its unsigned local receipt can forge consistency. Managed-upstream installation receipts are evidence only: full npm verification reconstructs a clean tree from the repository-tracked dependency lock and integrity cache, while release verification checks bytes against hashes in the reviewed upstream lock. A writer limited to `GATE_HOME` cannot re-anchor altered upstream bytes. Whole-root write access still belongs only to trusted operator processes.

### Project registry boundary

`gate project register` imports a bounded regular non-symlink JSON source, validates it with [project.schema.json](../schemas/project.schema.json), canonicalizes its repository identity, checks the default branch and referenced profiles, and writes an owner-only canonical record under `GATE_HOME/projects`. Both imported and canonical stored UTF-8 representations must fit the registry byte ceiling. Local `file://` locators are normalized to their physical realpath and must continue to resolve there during later loads. A serialized writer lock prevents concurrent replacement. The registry accepts an identical registration idempotently and rejects changed content for an existing ID or a second ID for the same case-normalized forge repository. Registration writes `.registry.pending` before publishing the contract and removes it only after the transaction-bound private audit event is flushed. A contract-write failure rolls back the exact record when safe. An audit append, flush, or close error preserves both contract and marker because the event outcome is ambiguous; an abrupt interruption leaves the same fail-closed state. The marker binds the project ID, event ID, random transaction nonce, and SHA-256 of the canonical contract to the event evidence reference. While either the lock or pending marker exists, full reads fail or return invalid/degraded status rather than treating the transaction as complete.

`project show` is the explicit full-contract read. `project list`, general status, and the observer use summaries that omit repository URLs and deployment destinations; the observer replaces the project ID with a process-local keyed pseudonym. Invalid and unexpected entries remain visible as invalid. v0.1 has no update or delete transition, and the registry is not a source of security authorization.

The registry does not yet dispatch Firstmate, clone a repository, select a project implicitly, bind a Treehouse repository path to a registered identity, or make publication and deployment adapters enforce every delivery field. Those transitions require narrow owner bridges rather than treating schema validity as runtime enforcement.

## Execution environments

Host execution is the default because the operator has authorized laptop use and several security tools need a GUI, browser certificate store, raw host capture, USB or ADB, a GPU, or a physical network interface.

Pinned rootless OCI profiles are the target design for conflicting or heavy command-line tools; v0.1 does not ship those profiles. They will organize dependencies and will not be treated as a security boundary for hostile code. A broader Kali container can provide compatibility after a pinned image and SBOM exist, while purpose-specific packs remain the reproducible source of truth. A VM is optional and should be introduced only after its setup, start, smoke-test, reset, and stop flow is repeatable without an AI.

Treehouse worktrees provide change isolation. They do not isolate processes, credentials, networks, caches, the kernel, or the host filesystem. Worktrees from one clone also share the common `.git`: unknown or hostile same-user code can mutate hooks, configuration, objects, and refs outside its worktree. Such code requires a standalone clone or an OS sandbox.

The v0.1 workspace bridge runs only on Linux or WSL2 and implements three GATE operations: lease, aggregate status, and nonmutating verification. Before every operation it requires the managed Treehouse 3.1.3 executable to be `integrityState: verified` and selects a fixed trusted system Git. Lease acquisition is the only Treehouse subprocess: `treehouse get --lease --json --no-fetch --branch BRANCH --lease-holder HOLDER [--base BASE]`, with update checks and interaction disabled. Omitting `--base` leaves base selection to repository Treehouse configuration. GATE never invokes Treehouse `status`, `return`, `destroy`, `prune`, or `enter`. Treehouse and Git receive a constructed minimal environment with an empty private home and private temporary directory. Inherited credentials, proxies, SSH agents, language loaders, and general session variables are absent.

Private Treehouse state is partitioned first by a binding to the physical main clone and then by a SHA-256 task-ID root. A lease creates its task root exclusively; an existing root burns that task ID and is never reused. Fresh task IDs therefore allocate fresh roots. Each physical clone has a lifetime ceiling of 511 retained task roots. Capacity recovery requires a new physical clone or future mount-safe upstream lifecycle support, never deletion or reuse of a retained root.

GATE status and verification never query Treehouse. They stable-read the clone and task bindings, exact version-4 state with one healthy lease, and exact 32-byte owner-only state key. The bridge verifies the seed-inventory HMAC and binds SHA-256 of the raw state and key bytes into the immutable completed receipt. The HMAC covers only the seed inventory; lease evidence also depends on the trusted `get` receipt and immutable raw-file digests. Treehouse 3.1.3 status recovery can move user files, so treating it as a read-only query is unsafe.

Lease always uses Treehouse `--no-fetch`; GATE also disables Git lazy fetch and every transport. Any requested branch, base, object, or blob must already be local. Acquiring or refreshing refs is a separate reviewed network workflow because the bridge supplies no credential, proxy, SSH, or network broker. Before and after Treehouse execution, GATE accepts only a narrow reviewed allowlist of shared repository-local and per-worktree configuration keys with validated values; every unreviewed key fails closed. This excludes includes, filters, diff/merge drivers, credential and SSH commands, editors, pagers, external protocols, worktree redirection, commit graphs, and weakened stat behavior. Git LFS filters are blocked until a reviewed integration exists. Separate inspections cannot exclude a concurrent same-user writer to the shared Git directory.

Before acquisition, GATE durably writes a `pending` lease binding. After `get`, it checks the returned base, path, lease ID, holder, timestamp, and branch against the direct state read and requires the path to remain within the bound private task root. Before reporting success it rejects Git operation and transaction locks, submodules, nested Git metadata, hidden or staged real-index state, corrupt or altered object graphs, and unreachable objects. It builds a controlled checkout of exact `HEAD` with a private fresh index and compares file types, modes, links, symlinks, paths, and bytes against the real workspace under bounded entry, byte, and time limits. Extra and ignored workspace paths fail. GATE then persists the durable `workspace.leased` event and atomically replaces `pending` with a `complete` binding containing the event receipt and immutable state/key digests, followed by another state read. Treehouse persists the lease beyond the GATE process; interruption leaves a retained pending or unbound lease that aggregate status reports as unverified.

`workspace verify` repeats the lease and repository identity checks without mutating Treehouse. The supplied repository must be the main worktree, both worktrees must share one common Git directory, and the landed-ref name must equal the branch checked out in the main worktree. Verification rejects active processes, in-progress operations, submodules, nested metadata, grafts, alternates, replacement refs, altered or unreachable objects, hidden or staged index state, and any leased-workspace bytes outside the exact current `HEAD`. Ignored cache paths are allowed only in the main worktree. After rechecking object integrity, it proves that the exact workspace `HEAD` is an ancestor of `refs/heads/BRANCH`. This establishes local reachability only; it is not provider, No Mistakes, or publication proof. The command records `workspace.verified` and retains the durable lease.

Automatic return, reset, destruction, and slot reuse are disabled. Reproduced Treehouse 3.1.3 bind-mount races can cause destructive cleanup to alter or delete host data, and the upstream release exposes no primitive that can make that transition safe. Operators and agents must never invoke any Treehouse command directly against a GATE root, including status. Each retained lease and one-shot task root consumes disk. Cleanup remains a future mount-safe upstream integration; GATE does not claim a power-loss durability guarantee.

Workspace operations are serialized by an owner-only clone-specific lock. When aggregate status reports `operation-lock-present`, it has inspected no task or Git state. Manual clearance must prove no GATE operation or related Treehouse/Git child remains, reject malformed or unsafe lock metadata, treat a live `/proc/PID` as non-removable even after PID reuse or reboot, revalidate the exact lock's device, inode, metadata, and content immediately before unlinking only that file, and rerun GATE status before mutation. The ordered procedure is in [the operating model](operating-model.md#operation-lock-recovery).

## Code lifecycle

1. The operator registers and verifies the private project contract; Firstmate records intent, acceptance criteria, risk, delivery mode, and merge posture outside GATE's current bridge.
2. GATE invokes the verified Treehouse bridge, which grants a fresh exclusive durable lease and returns its checked identity.
3. Codex works inside the lease using reviewed skills and admitted tools.
4. GNHF may run only as a bounded leaf task in that lease. Iteration, time, token, and failure caps are mandatory.
5. The worker hands an immutable commit to No Mistakes.
6. No Mistakes owns review through green CI. No other reviewer or publisher mutates the same branch during this stage.
7. The v0.1 publication authority performs a read-only exact-head and required-check preflight. A future trusted adapter verifies the external No Mistakes attestation and project policy before any merge, deployment, or publication.
8. The observer records available GATE state. GATE verifies that the exact clean, inactive workspace head is locally reachable from the named checked-out branch, then retains the lease for manual reconciliation.

Only the project registry and Treehouse lease/status/verify portions of this lifecycle are newly wired. GATE still does not invoke Firstmate, launch Codex or GNHF, hand a branch to No Mistakes, verify No Mistakes attestations, land a change, safely destroy a Treehouse root, or perform publication mutation.

## Security lifecycle

Passive public research, local static analysis, hypothesis generation, and saved-evidence analysis can proceed without an engagement receipt. Network probes, interception, authentication, fuzzing, exploitation, persistence, destructive tests, denial-of-service tests, or data removal require a valid receipt.

An engagement contains:

- authorization basis, evidence, and validity window;
- precise included and excluded selectors;
- permitted action classes and execution environment;
- hypotheses, depth, commands, coverage, and completion tests;
- request, rate, concurrency, duration, and token limits;
- data destinations, retention, and secret references;
- stop conditions;
- No Mistakes review evidence and an operator receipt for the exact plan digest.

The broker can check the receipt for an exact target and action. Its result is explicitly marked `preflightOnly: true` and `executionAvailable: false`, with both operator and No Mistakes attestation status set to `local-unverified`. Arbitrary active execution is disabled in v0.1: raw `gate run`, `gate upstream exec`, and `gate engagement exec` launchers fail closed. A future reviewed tool-specific adapter must bind exact arguments to scope, record versions and evidence hashes, enforce approved limits and stop conditions, terminate the process group, and reject unknown flags. Scope expansion requires a new plan and receipt.

The completion contract covers asset discovery, architecture, authentication, authorization, sessions, inputs, business logic, client behavior, data exposure, infrastructure, supply chain, and post-exploitation impact. Each surface should be covered or carry an explicit limitation, and empty scanner output is not sufficient. v0.1 validates these fields as data; `engagement close` is administrative and does not evaluate or certify completion.

## Evidence model

Every finding carries:

- a stable claim ID and concise statement;
- `observed`, `inferred`, or `unverified`;
- raw evidence references and hashes;
- tool, version, command, target, and timestamp;
- an independent validation or an explicit reason it was not possible;
- limitations and residual unknowns;
- impact, reproduction, remediation, and retest state.

Target output, webpages, binaries, captures, and tool responses are untrusted data. They may create a learning candidate but cannot directly change memory, policy, or authorization.

## Observation and token accounting

GATE commands append normalized events and the observer only reads state. Today it shows GATE activity, derived agent/task state, effect classes, learning, freshness, upstream, engagement, and privacy-filtered project summaries through the status API, and token data when available. Treehouse workspace state is available on demand through `gate workspace status`; Firstmate, Treehouse, GNHF, No Mistakes, ordinary Codex turns, and tool adapters still need complete event bridges before this is a complete fleet view.

Token records state whether values are `exact`, `estimated`, or `unavailable`, and identify the source and whether a value is a delta or cumulative counter. The v0.1 scanner streams local Codex session JSONL and parses only lines carrying recognized usage markers; prompt-bearing bytes can therefore pass through the scanner, but prompt bodies are never returned by the observer. A direct harness adapter is the target design. Missing values are never rendered as zero.

## Learning and evolution

Corrections, failures, retries, workarounds, tool gaps, better-tool discoveries, policy violations, benchmark regressions, evidence contradictions, and environment constraints create learning candidates.

Agents record session observations privately through the explicit learning command. Project and repository behavior changes must pass through No Mistakes before promotion, but v0.1 does not invoke that workflow automatically. Each machine record in `memory/learnings.jsonl` is one physical line with a cause, a concrete change, evidence, status, sensitivity, and affected configuration. [LEARNINGS.md](../memory/LEARNINGS.md) is the reviewed human-readable ledger. Public lessons omit secrets and target identifiers.

Learning cannot expand target scope, authorization, data destinations, secret release, publication permission, or destructive-action permission.

When an operator or agent finds a better tool, the operating contract requires comparison of task success, reproducibility, maintenance, license, platform compatibility, effects, token cost, and ergonomics. The agent evaluates it in an isolated install root, runs a smoke test, pins the selected version and integrity data, records the lesson, and passes the persistent change through No Mistakes. v0.1 does not discover or admit catalog tools automatically.

## Authoritative contracts

- [gate.config.json](../config/gate.config.json) declares the target providers and runtime defaults.
- [autonomy.json](../policies/autonomy.json) defines action authority.
- [data-handling.json](../policies/data-handling.json) owns classification and release.
- [engagements.json](../policies/engagements.json) owns active-security receipts and completion.
- [learning.json](../policies/learning.json) owns durable adaptation.
- [updates.json](../policies/updates.json) owns dependency and tool admission.
- Files under [schemas](../schemas/) define the accepted machine-readable shape.

These files are normative contracts and are schema-validated. v0.1 has no general policy engine: the project registry, Treehouse workspace bridge, engagement broker, publication preflight, observer, learning path, and upstream manager enforce only the fields they explicitly load. Cross-component provider selection, project-policy propagation, full data-flow rules, and many lifecycle transitions remain procedural or planned. A missing, unreadable, unknown, expired, or digest-mismatched value must never be treated as authorization, and unavailable mutation adapters remain blocked.
