# GATE operating model

This document defines how the operator and agents use GATE. Commands are the canonical interface contract; an unavailable command must report that it is unavailable and must not simulate success.

## Start and inspect

The working v0.1 non-AI lifecycle is:

```bash
./scripts/bootstrap.sh
./bin/gate.mjs doctor --full
./bin/gate.mjs up
# In a second terminal:
./bin/gate.mjs status
```

`scripts/bootstrap.sh` installs the repository lock with lifecycle scripts disabled, creates private runtime directories, validates the repository, and runs the smoke suite. The CLI's `bootstrap` command only creates those directories and validates tracked configuration. `doctor` reports OS and architecture facts, WSL detection, versions from required CLIs under a reduced environment, presence-only results for optional executables, and repository validity. `--full` also reports visible interfaces, Linux raw-network capabilities, Yama `ptrace_scope`, USB-bus presence, and default Docker-socket presence. It does not execute optional tools, probe Docker-engine reachability, or prove a specific capture, debugger attachment, USB device, or route works. `up` starts the foreground loopback observer; stop it with `Ctrl+C`. Managed background startup, `status --watch`, and `down` remain future integration work.

On Windows, the intended v0.1 setup runs in WSL2 because Firstmate supports macOS and Linux. The doctor reports the platform and WSL state; it does not yet provide a dedicated native-Windows remediation flow.

## Private project contracts

Prepare a project contract from [project.json](../templates/project.json) in a private working directory, then register and verify it:

```bash
./bin/gate.mjs project register --file "$HOME/.config/gate/projects/my-project.json" --json
./bin/gate.mjs project verify my-project --json
./bin/gate.mjs project list --json
./bin/gate.mjs project show my-project --json
```

The registry validates the contract schema, canonical repository identity, default branch, and referenced execution and security profiles. It stores the canonical contract as an owner-only file under `GATE_HOME/projects`; repository URLs, destination references, and other project-specific settings therefore remain private. General status and the observer receive only a contract summary, and the observer pseudonymizes the project ID. `project show` is the explicit full-detail read and can disclose the complete contract to its caller.

Registration is append-only in v0.1. Registration and verification reject the template's unchanged project ID, display name, or canonical repository identity; replace all three before use. Re-registering identical content is an idempotent read, while replacement under the same ID and duplicate canonical repository identities fail closed. Remote forge path segments are case-normalized before comparison. A local `file://` locator is rewritten to its physical realpath in the stored contract; load and verification fail if a moved or replaced alias later resolves to another path. There is no update or delete command. A writer lock serializes registration and is never declared stale or stolen automatically. Invalid or unexpected registry entries remain visible as opaque invalid rows and block new registrations instead of being ignored. Both source and canonical stored JSON are byte-bounded. A contract-write failure rolls back the exact new file when safe; an audit append, flush, or close error preserves both the contract and durable `.registry.pending` marker because the event may already have been written.

While `.registry.lock` or `.registry.pending` exists, `project show` fails and verify, list, general status, and observer status report invalid or degraded registry state. The pending marker survives removal of a stale lock so an unaudited contract cannot silently become ready. Reconcile an interruption in this order:

1. Verify that no registration process is active; inspect the lock and pending owner details before changing anything.
2. Require the pending marker to identify `gate.project-registration/v1`, `ProjectRegistrationPending`, its `projectId`, 32-character `transactionNonce`, `eventId`, and 64-character `contractSha256`. Hash the exact stored contract bytes and require that SHA-256 to equal `contractSha256` before trusting either file.
3. Locate the event whose ID exactly equals `eventId`. Require kind `project.registered`, target and evidence reference `private://projects/PROJECT_ID.json`, and evidence reference `evidence://project-registration/TRANSACTION_NONCE/CONTRACT_SHA256`. Reject a conflicting, duplicate, malformed, or digest-mismatched record as unresolved rather than choosing one.
4. If that exact event is absent, remove the unaudited project contract and pending marker, then remove the stale lock and retry registration. If the exact bound event exists, remove only the pending marker and stale lock, then run `project verify`.

Never blindly delete either control file or treat removal of only the lock as recovery.

The project record is configuration, not authority. Registration does not clone a repository, acquire a workspace, authorize target contact, verify a No Mistakes run, or enable merge, deployment, or publication. The offline-analysis lane uses its canonical digest to bind a supplied artifact to one project, but that provenance binding still grants no authority over a publisher, vendor, account, service, or embedded endpoint. Current workspace and publication commands also require explicit repository inputs; they do not yet resolve or enforce every registered project field.

## Verified Treehouse leases

The GATE workspace bridge runs only on Linux or WSL2 and accepts only managed Treehouse 3.1.3 whose executable bytes pass full verification against [upstreams.lock.json](../locks/upstreams.lock.json). Install it through the reviewed release lane, and inspect the repository's durable Treehouse state before acquiring work:

```bash
./bin/gate.mjs upstream install treehouse --json
./bin/gate.mjs workspace status --repo "$HOME/src/my-project" --json
./bin/gate.mjs workspace lease \
  --repo "$HOME/src/my-project" \
  --task issue-123 \
  --branch gate/issue-123 \
  --base main --json
```

Lease acquisition is the only operation that invokes Treehouse. GATE runs the exact verified executable as `treehouse get --lease --json --no-fetch --branch BRANCH --lease-holder HOLDER [--base BASE]`, with update checks and interactive prompting disabled. Omitting `--base` lets the repository's Treehouse configuration select it. GATE never invokes Treehouse `status`, `return`, `destroy`, `prune`, or `enter`. It selects Git from fixed trusted system locations rather than the caller's `PATH`, and gives each subprocess a minimal environment with an empty private home and private temporary directory. Inherited credentials, proxies, SSH agents, language loaders, and general session variables are absent.

Lease always passes `--no-fetch`; GATE also disables Git lazy fetch and all transports. Any requested branch, base, object, or blob must already resolve locally. Fetching or refreshing refs is a separate reviewed workflow with its own narrow network and credential handling. The workspace bridge itself has no credential, proxy, SSH-agent, or network broker.

GATE inspects the shared repository-local config and every per-worktree config before and after lease acquisition. It accepts only a narrow reviewed allowlist of keys with validated values; every unreviewed key fails closed. Includes, filters, credential/SSH/proxy commands, diff and merge drivers, editors, pagers, external protocols, commit graphs, and similar command or object-redirection paths therefore block workspace operations. Git LFS `filter.lfs.*` is unsupported. Repository-redirecting and integrity-weakening settings also fail closed, including `core.worktree`, `core.gitdir`, repository input-file overrides, weakened stat settings, and a non-false `core.bare`. On POSIX, configured `core.filemode` and `core.symlinks` must be true. GATE confirms that Git's top-level path is the intended worktree. Separate inspections cannot exclude a concurrent same-user writer to the shared Git directory.

GATE binds one private root to the physical main clone and allocates a separate SHA-256 task-ID root for each lease. Creation is exclusive: once a task ID has a root, it is burned and can never be reused, including after an interrupted or failed lease attempt. Choose a fresh task ID for every retry. A physical clone has a lifetime limit of 511 retained task roots. At the limit, continue with a new physical clone or wait for future mount-safe upstream lifecycle support; never delete retained roots to recover a slot.

`workspace status` never invokes Treehouse. It stable-reads each clone and task binding, the exact version-4 state containing one healthy lease, and the exact 32-byte owner-only state key. It validates the seed-inventory HMAC and requires SHA-256 of the raw state and key bytes to match the immutable completed GATE binding. The HMAC authenticates only the seed inventory. Lease evidence also depends on the trusted `get` receipt and immutable raw-file digests. Treehouse 3.1.3 `status` can run recovery and move user files, so it cannot serve as a read-only query.

Before `get`, GATE durably publishes a `pending` binding for holder `gate:TASK_ID`. After Treehouse returns, GATE checks the returned base, path, 128-bit lease ID, holder, timestamp, requested branch, and direct state read. It rejects in-progress Git operations and transaction locks, submodules, nested Git metadata, hidden or staged real-index state, corrupt or unreachable objects, and a filesystem that differs from a fresh private-index checkout of exact `HEAD`. It then records the durable `workspace.leased` event and atomically replaces `pending` with `complete`, binding the event receipt and immutable state/key digests, before stable-reading state again. Treehouse persists the lease independently of the CLI process. Save the returned path, task ID, and lease ID. If interruption leaves a pending binding or a durable lease without a complete receipt, GATE status reports it as unverified for manual reconciliation; this local evidence is not a power-loss durability guarantee.

After the exact workspace commit has landed, stop its processes and verify the lease:

```bash
./bin/gate.mjs workspace verify \
  --repo "$HOME/src/my-project" \
  --path WORKSPACE_PATH \
  --task issue-123 \
  --lease 0123456789abcdef0123456789abcdef \
  --landed-ref main --json
```

`workspace verify` does not return, reset, destroy, or otherwise mutate the Treehouse lease. `--repo` must be the main worktree and `--landed-ref` must exactly name the branch checked out there; GATE resolves that branch through `refs/heads/BRANCH` instead of accepting an arbitrary revision. The main and leased worktrees must share one Git common directory. Verification rechecks the lease ID and derived holder, requires no recorded processes or in-progress Git operation, rejects submodules and nested Git metadata, and rejects grafts, filesystem or HTTP object alternates, replacement refs, corrupt objects, and any unreachable object. It checks the real indexes as well as fresh controlled checkouts, so assume-unchanged, skip-worktree, staged, tracked-byte, mode, link, untracked, and ignored workspace changes all fail. Git-confirmed ignored cache paths may remain in the main worktree; other main-worktree extras and every leased-workspace extra fail.

After a second object-integrity and zero-unreachable check, GATE proves that the exact current workspace `HEAD` is an ancestor of the checked-out main branch. “Landed” means only local Git reachability. It is not evidence that a provider accepted a push, that a pull request completed No Mistakes, or that publication occurred. A successful check appends `workspace.verified` and returns `retained: true`; the durable lease and its task root remain allocated.

Automatic Treehouse return, reset, destruction, and reuse are disabled. Reproduced bind-mount races in Treehouse 3.1.3 can make those destructive paths alter or delete host data, and the upstream release has no mount-safe primitive GATE can call. Never invoke any Treehouse command directly against a GATE root, including `treehouse status`, `return`, `destroy`, `prune`, or `enter`. Use GATE workspace commands only. Retained leases consume disk until future mount-safe upstream support exists.

### Operation-lock recovery

If `gate workspace status` returns phase `operation-lock-present`, it did not inspect any task or Git state. The lock is `$GATE_HOME/treehouse/repos/<sha256(realpath repo)>/.gate-workspace-operation.lock`. Its age is never enough to declare it stale, and its PID plus timestamp does not record a process-start identity. PID reuse, reboot, or an orphan Treehouse or Git child can therefore make a plausible lock misleading. Reconcile it in this order:

1. Stop new workspace operations for this physical clone. Identify every GATE workspace operation and every Treehouse or Git process whose working directory, arguments, or open files refer to the repository or its clone-specific or task-specific GATE roots. Wait for or stop the owning operation and its children. If this cannot be proved, leave the lock in place.
2. Inspect only the exact clone-specific lock. It must be owned by the current operator, mode `0600`, a physical single-link regular file, and contain exactly `<positive PID> <canonical UTC timestamp>`, where the timestamp has the millisecond form emitted by `new Date().toISOString()`. A malformed, unreadable, unowned, symlinked, multi-link, or changing lock remains unresolved; leave it in place and do not repair or replace it.
3. Check `/proc/PID`. If that PID exists, do not remove the lock, even if it appears unrelated or may have been reused. Wait for or stop the owning operation, then rerun GATE status. Apply the same PID check after a reboot; reboot alone does not prove staleness.
4. If `/proc/PID` is absent and step 1 proved that no related GATE, Treehouse, or Git process remains, record the lock's device, inode, ownership, mode, link count, metadata, and exact content. Immediately re-read and revalidate all of them. Any difference leaves recovery unresolved.
5. Unlink only that exact unchanged `.gate-workspace-operation.lock`. Do not delete task roots, pending or complete bindings, Treehouse state, keys, provider lock files, or Git locks, and do not invoke Treehouse directly.
6. Immediately rerun `gate workspace status --repo PATH --json`. Do not mutate or lease a workspace unless that GATE status completes and its task entries have been reviewed. Use a fresh task ID for any new acquisition.

Treehouse provides change isolation only. Every worktree for a clone shares the common `.git`, so unknown or hostile same-user work can mutate hooks, configuration, objects, and refs outside its allocated directory. Use a standalone clone or OS-level sandbox for that work; the verified bridge cannot turn a shared worktree into a security boundary.

## Daily software work

1. Register and verify the private project contract.
2. State the outcome and acceptance criteria to the Firstmate session. GATE does not yet invoke or persist that Firstmate flow.
3. Acquire a verified Treehouse lease for a named task and branch, then give Codex only the returned workspace path. GATE does not launch Codex or GNHF.
4. Watch GATE-emitted activity, project summaries, derived agent/task state, learning, freshness, and available token totals in the observer. Firstmate, Treehouse, GNHF, and No Mistakes do not yet emit their complete lifecycle into it.
5. Answer only decisions that are ambiguous, scope-expanding, destructive, or blocked by unavailable evidence.
6. Run the real No Mistakes workflow with `axi run --no-publish-intent` for review, tests, documentation, push, PR, and CI, and retain its genuine run evidence. The caller-side omission withholds private intent from PR drafting; GATE does not yet orchestrate that handoff or verify a run ID against an external attestation.
7. Run `gate publication check` and `gate publication dry-run` for the expected repository, pull request, exact head, genuine No Mistakes run reference, and intended merge mode. The v0.1 adapter checks PR state, head, mergeability, and a nonempty green required-check set, but it does not verify the external run or automatically enforce the registered project contract.
8. Report publication as blocked. A future trusted adapter may merge, deploy, or publish only after it verifies a No Mistakes attestation bound to that head and enforces the registered base branch, merge posture, and destination.
9. After the exact workspace head has landed, stop its processes and run nonmutating `workspace verify`. Record the local reachability result and retain the lease for manual reconciliation.
10. Review the outcome, limitations, costs, and learning entries.

The target operating model routes edit, test, commit, push, PR, CI, merge, deploy, and publication through the named owners. v0.1 wires local GATE primitives and read-only exact-head GitHub PR preflight. Mutation adapters and other owner bridges remain explicit integration work. No component may bypass a missing owner or adapter because another tool offers a similar command.

### Bootstrap the No Mistakes repository controls

No Mistakes trusts repository controls from the fetched default branch. The first pull request that adds `.no-mistakes.yaml` cannot use that same unmerged file to govern or approve itself. Run that bootstrap review with `--no-publish-intent`, independently run `npm ci --ignore-scripts`, `npm test`, and `npm run check`, perform a manual diff and policy review, and require the normal CI checks. Rely on the repository config only after that pull request has merged and the default branch has been fetched again. Later `.no-mistakes.yaml` changes follow the same rule: the proposed version does not take effect until it is trusted on the fetched default branch.

Keep `--no-publish-intent` on later runs as well. Trusted `pr.publish_intent: false` prevents a generated Intent section, but only the caller-side omission also removes the full intent from the PR-drafting prompts. The local No Mistakes global config carries the same default for this environment; the explicit flag keeps the behavior portable.

## Offline static artifact analysis

Use this lane for a lawfully supplied local Windows PE when the fixed REA PE-resource operation can answer the first question. It is separate from active engagements and never executes the artifact. Linux or WSL2 must provide Bubblewrap, and the managed `rea-stable` upstream must pass its repository-locked integrity checks:

```bash
./bin/gate.mjs upstream install rea-stable --json
./bin/gate.mjs analysis capability --json
```

Capability performs cheap presence checks for Linux, Node, the fixed adapter, the expected managed REA entrypoint, and Bubblewrap, then launches `/usr/bin/true` through the actual minimal Bubblewrap namespace shape. It does not reconstruct or hash the full managed REA npm tree. Register and verify the private project first. Then create one manifest from an exact absolute regular-file path:

```bash
./bin/gate.mjs analysis manifest \
  --project my-project \
  --path "$HOME/private/client-installer.exe" \
  --minutes 15 --json
```

Creation first performs full reviewed-lock integrity reconstruction for the managed REA tree and observes the runtime hashes and file identities. It then copies at most 512 MiB into an owner-only snapshot under `GATE_HOME`, preserving spaces and commas in the resolved path value while rejecting a symlink, directory, device, or pipe at that path and rejecting relative paths. The stored digest-bound manifest binds:

- the current canonical project-contract digest;
- the source identity and copied artifact SHA-256 and byte count;
- the pinned `rea-stable` version, full source commit, npm integrity, and dependency-lock digest;
- observed Bubblewrap, Node, adapter, and REA entrypoint paths, SHA-256 values, and filesystem identities;
- the single fixed REA `inspect-pe-resources` adapter, its arguments, read-only mounts, cleared environment, and private evidence references;
- a zero-network policy, zero requests, zero request rate, parallelism one, zero model tokens, one to 60 minutes of wall duration, and a validity window no longer than 15 minutes;
- the controls that are enforced and unavailable.

Review the complete manifest and use only the exact returned confirmation:

```bash
./bin/gate.mjs analysis run \
  --project my-project \
  --manifest MANIFEST_ID \
  --confirm "ANALYZE MANIFEST_ID MANIFEST_SHA256 OFFLINE" --json

./bin/gate.mjs analysis status --json
```

The retained-snapshot pool is owner-only and capped at 64 artifacts and 2 GiB of logical bytes. Linux/WSL2 system `flock` on the existing analysis directory serializes retention-lock acquisition, stale recovery, publication, mutation, and release for manifest snapshots, execution claims, and purges; malformed lock metadata or input entries fail closed. A durable creation intent covers snapshot creation through manifest publication. Recovery after a definitively dead creator removes a verified incomplete snapshot or retains one protected by a durably published manifest. Status accounts for retained capacity and pending, expired, active, terminal, purge-pending, purged, orphaned, missing, and invalid state. To retire one exact snapshot, use the digest-bound value returned with its manifest:

```bash
./bin/gate.mjs analysis purge \
  --project my-project \
  --manifest MANIFEST_ID \
  --confirm "PURGE MANIFEST_ID MANIFEST_SHA256 OFFLINE ARTIFACT" --json
```

An unclaimed current manifest transitions through `abandoned`, an unclaimed expired manifest through `expired`, and a succeeded, failed, cancelled, or blocked run through `terminal`. Queued, running, unknown, malformed, or mismatched state blocks purge. The operation removes only the bound snapshot and an empty sandbox. It retains the manifest, claim, run, purge receipt, and evidence. It is logical retention cleanup rather than secure media erasure. Stdout and stderr have per-run bounds, while their aggregate retention remains separate and has no fixed quota.

The durable one-shot claim is written before launch. Success, tool failure, interruption, preflight ambiguity after claim, or a later parse failure does not make the manifest reusable. The launcher repeats the full managed-upstream reconstruction and rechecks every binding, invokes no shell, and creates fresh user, PID, network, IPC, and UTS namespaces, requests a cgroup namespace where supported, and uses dropped capabilities, a cleared environment, read-only runtime/input mounts, and ephemeral writable directories. The adapter accepts only the fixed command, hashes the mounted artifact again, and refuses to report success unless it observes loopback only, no IPv4 route, zero inherited, permitted, effective, bounding, and ambient capabilities, and `NoNewPrivs`. Stdout and stderr are each limited to 64 MiB and stored with result metadata under private evidence paths.

The lane does not set CPU or memory quotas, freeze the managed REA tree against a same-UID writer, protect `GATE_HOME` from another process running as the operator, or deny Unix-socket syscalls. It supplies neither installer extraction nor a general reverse-engineering or dynamic-analysis environment. A successful run proves the recorded fixed analysis and its in-namespace observations; it does not prove a finding, an artifact's safety, or the absence of every egress mechanism.

Local possession does not authorize vendor contact. A proprietary client or other proprietary artifact must be supplied lawfully by the operator and stays private under `GATE_HOME`. Embedded domains, URLs, certificate names, update paths, and service identifiers remain offline hypotheses. Do not resolve or contact them, download another artifact, use a vendor account, or test a live updater without separate written authority and an active engagement that names the exact selector and action.

Continue from the local result through the [end-to-end penetration-testing workflow](pentest-workflow.md). Its `local-to-network-hypothesis` handoff requires independent ownership resolution, explicit exclusions for vendors and shared services, the smallest sufficient next observation, a new plan and receipt for target contact, and a reviewed adapter or separately confirmed active manifest. If those checks do not pass, keep the hypothesis offline and unverified.

## Active security work

Create an engagement from [engagement.json](../templates/engagement.json). Drafting, local research, and an offline-analysis result do not authorize target contact. Use the [end-to-end workflow](pentest-workflow.md) to map prerequisites, evidence, stop conditions, and allowed handoffs before selecting a command.

The active flow is:

1. **Establish authority.** Store the written authority or ownership evidence privately and reference it from the engagement.
2. **Map scope.** Add exact targets, exclusions, declared action classes, permitted catalog tool IDs, execution environment, validity times, data destinations, and limits. Include `gate-home` when the generic lane may run, because its raw evidence always lands there. URL path prefixes stop at segment boundaries; an approved query is exact, and URL fragments are rejected.
3. **Build the plan.** Record hypotheses, exact command shapes, likely effects, credentials, rollback, stop conditions, coverage, completion tests, and which launches require a reviewed adapter or the supervised generic lane.
4. **Validate the plan.** Run No Mistakes against the immutable plan, then record its run and head. v0.1 accepts that record but does not invoke No Mistakes or verify an attestation.
5. **Report before engaging.** Present the target, actions, likely effects, limits, stop conditions, and plan digest directly to the operator. A dedicated local decision view is not implemented in v0.1.
6. **Approve the plan.** The operator supplies the exact `APPROVE ID` confirmation for the plan digest. GATE stores a local unsigned receipt whose provenance depends on the operator workflow and `GATE_HOME` permissions. It can cover repeated launches that stay within the receipt-bound target, action, tool, environment, limits, data, and validity envelope.
7. **Check each operation.** `gate engagement check ID --target TARGET --action ACTION` produces an `executionBinding` for the current plan, envelope, receipt bytes, authorization expiry, exact target, declared action label, execution environment, permitted tools, and allowed destinations. It remains preflight evidence and does not select or launch a command. The label does not prove that arbitrary argv implements that action class.
8. **Choose an execution lane.** Prefer a reviewed adapter when it supplies the guarantees the plan needs. The generic lane accepts only receipt-bound `scope.environment: host` whose allowed destinations include `gate-home`; container, rootless-container, VM, and remote-lab engagements require a lane that implements that environment. A qualifying host engagement also needs an active target-contact phase attempt with a matching reviewed admission; the generic lane rejects `A3`. Follow the authoritative [workflow admission and execution procedure](pentest-workflow.md#target-contact-admission-and-execution), including its current adapter-availability boundary, before creating an expiring one-shot manifest with `gate engagement manifest`. The argument array after `--` must contain exactly one whole argument equal to `{{GATE_TARGET}}`; GATE expands it and binds the resulting target argument, declared action label, permitted tool, catalog risk class, allowed destinations, catalog-resolved executable descriptor and observed hash, declared bounds, and private evidence paths.
9. **Confirm that exact manifest.** Present the expanded `operation`, catalog risk class, executable identity, bounds, expiry, and all `enforced`, `bestEffort`, and `unavailable` entries to the operator. Review whether the exact argv actually matches the selected action class, because only a reviewed adapter validates tool-specific flag semantics. Only the exact `EXECUTE MANIFEST_ID MANIFEST_SHA256 UNMETERED` value can launch it. The one-shot claim is durable before spawn; success, failure, interruption, or ambiguity all consume the manifest.
10. **Execute and monitor.** `gate engagement exec` accepts a manifest ID and confirmation, never a new command. GATE launches without a shell or stdin through the already hashed Linux descriptor, uses a minimal environment and private sandbox, and captures bounded private stdout and stderr. While that original supervisor remains alive, it polls receipt validity and stop requests, applies wall duration, and attempts process-group termination. Use `gate engagement stop ID --run RUN_ID` for one run or `gate engagement revoke ID --confirm "REVOKE ID"` to end the engagement's authority.
11. **Validate findings.** Reproduce with an independent method where possible and separate observed facts from inference.
12. **Report and retest.** Use [security-report.md](../templates/security-report.md), include limitations and residual unknowns, and assess the completion contract before closing. `engagement close` is an administrative state change; it does not inspect coverage, run completion tests, or certify completeness.

The operator receipt is necessary authority for target contact. No Mistakes supplies technical review; it does not create permission to test a target. Both provenance steps are procedural in v0.1: their identifiers are recorded and digest-checked locally, not cryptographically attested by their external principals.

The generic lane enforces the engagement and host-environment binding, receipt-bound allowed destinations including `gate-home`, target argument, `declared-action-label-binding`, tool allowlist and catalog risk class, exact argv, `executable-descriptor-observed-sha256`, no-shell launch, minimal environment, private evidence, receipt-bounded declarations, and one-shot claim. Authorization/revocation/stop polling, wall duration, and process-group termination are best effort and require the original supervisor to remain alive. `argv-action-semantics-validation`, `supervisor-crash-containment`, and `immutable-executable-snapshot` are unavailable, as are egress enforcement and measurement of target requests, request rate, tool concurrency, or tokens; the lane also provides no daemon containment, filesystem isolation, credential broker, complete artifact inventory, or known-good executable provenance. A supervisor crash or force-kill can leave the ordinary tool process group alive, durable request files have no takeover worker, and processes may leave the supervised group. If authenticated group identity is lost during teardown, the run becomes `unknown` with termination reason `supervision-lost` rather than claiming termination. The observed digest records bytes read through the opened descriptor, but a same-UID writer can mutate a writable inode before or during exec, so it does not prove atomically frozen or launched bytes. Arbitrary argv can exceed the declared label. Audit events therefore use the maximum of the declared action effect and catalog risk ceiling; this conservative classification does not block launch. The child shares GATE's UID and host access. `UNMETERED` is an explicit acceptance of those unavailable controls, not a claim that the approved numeric limits disappeared.

## Plan changes

These changes invalidate an existing receipt:

- any target is added;
- an exclusion is removed;
- an action class is added;
- a permitted tool is added;
- the execution environment changes;
- a request, rate, concurrency, duration, or token limit is increased;
- a data destination is added;
- the plan content changes;
- authorization expires or is revoked.

The agent may prepare the revised plan automatically. It reports the delta and obtains a receipt for the new digest before resuming.

## Tool use and admission

An admitted tool has an official source, license record, exact version or commit, integrity record when available, supported platform, effect classification, telemetry setting, smoke test, and owner.

PATH discovery is an execution candidate only when the catalog entry sets `commandIdentity.genericLaneAdmission` to `path-discovery`. A `reviewed-admission` entry records a found namesake as `identity-unverified` but withholds it as the executable and blocks the generic lane. This protects ambiguous commands such as `httpx` and prevents REA's narrow offline adapter from authorizing its broader A2 command. `tool list` uses cheap presence and matched-receipt checks; a REA `managed-receipt` result is not an integrity or readiness claim. `tool plan rea` performs full managed-upstream verification and, when ready, exposes only `offline-static-pe-resources`; generic and broad REA execution stay false.

When a task needs a better tool:

1. Record the capability gap.
2. Compare candidates using evidence from the actual workload.
3. Evaluate the selected candidate in an isolated install root.
4. Classify its filesystem, process, network, target, credential, and privilege effects.
5. Run a smoke test and record the result.
6. Pin the artifact, image digest, package version, or full Git commit.
7. Add the catalog and lock changes.
8. Log one line stating the cause and resulting change.
9. Pass the persistent change through No Mistakes.

Skills follow the same review rule. They are privileged instructions, not harmless documentation. Install them at project scope, pin their content, and do not use popularity as evidence of trust.

## Learning

Capture a learning whenever the operator corrects the system, an action fails, a workaround is needed, evidence contradicts a claim, a tool is missing or inferior, a benchmark regresses, a policy is violated, or the environment behaves unexpectedly.

The required human-readable form is:

```text
YYYY-MM-DD | Cause: what happened | Change: the durable behavior or configuration change | Evidence: reference | Status: proposed|active|superseded|reverted
```

Sensitive detail belongs in the private JSONL record. The public line explains behavior without naming targets, credentials, private paths, or unreleased findings.

A lesson is complete only when the related behavior, configuration, test, or documentation changes. The operating contract assigns deduplication, redaction, validation, and project or repository promotion to No Mistakes, but v0.1 does not invoke that workflow automatically. Run it externally and retain truthful evidence. New evidence may supersede or revert a lesson; history is retained.

## Evidence and reports

Raw evidence stays under `GATE_HOME`. The tracked repository contains only sanitized summaries that have explicit release authority. Evidence references are stable URIs such as `private://`, `evidence://`, or `event://`.

Offline artifact snapshots, their typed source paths, runtime identities, stdout, stderr, and result records follow the same private rule. Findings derived from proprietary client material remain private unless the operator has separate release authority.

Never turn inability to inspect into a negative claim. State that a surface is unverified or limited, include the cause, and describe the next test that would resolve it.

## Token usage

The observer displays aggregate usage and per-session or recorded-run values when its sources provide them. See [observation and token accounting](architecture.md#observation-and-token-accounting) for source selection, aggregation, and exact, estimated, or unavailable values. Complete live Codex fleet and account-quota telemetry, plus grouping by day, require a future harness adapter.

Token budgets are required declared bounds for GNHF loops and engagements. GATE does not yet orchestrate the GNHF loop. A reviewed active-tool adapter may meter tokens when it can establish that counter, while the generic lane records token measurement as unavailable and requires `UNMETERED` confirmation. A budget must never trigger a silent provider, model, account, or billing-mode change.

## Local tool environments

Host execution is normal. Use native installs for GUI applications, browser trust stores, host packet capture, USB and ADB, GPU workloads, wireless interfaces, and other hardware-facing tools.

Use pinned OCI profiles for dependency-heavy command-line suites. The planned manual contract is shown below; these `gate lab` commands are not implemented in v0.1:

```text
gate lab up
gate lab smoke
gate lab shell
gate lab reset
gate lab down
```

These commands must be idempotent and documented before a profile is considered usable. Containers organize dependencies; they do not prove containment of hostile code. A VM becomes an optional profile only when the same lifecycle works reliably on the operator's laptop without agent assistance.

## Recovery

- A stopped or crashed observer rebuilds its current GATE view from append-only events.
- Use `gate workspace status --repo PATH` to reconcile the bounded aggregate of clone-bound, one-shot Treehouse task roots after an interruption. This reads bound state directly and never invokes Treehouse status. If it reports `operation-lock-present`, follow [Operation-lock recovery](#operation-lock-recovery); no task or Git state was inspected. Verification retains every lease. Automatic reset, return, destruction, and reuse remain disabled until Treehouse exposes a mount-safe primitive; the 511-root lifetime ceiling is recovered only with a new physical clone or future safe upstream lifecycle support. Firstmate task reconciliation, GNHF recovery, No Mistakes branch ownership, and their cross-owner bridges remain incomplete.
- A changed PR head invalidates publication authority until the exact head passes again.
- A changed security plan invalidates active authority until a new receipt exists.
- An offline manifest is never recovered for a second attempt. Its claim survives success, failure, interruption, and ambiguity. Inspect the private run and evidence records, rerun `analysis capability`, and create a new snapshot and manifest after verifying the current project and artifact.
- A generic manifest is never recovered for a second attempt. Inspect its private claim and run record; treat a missing or ambiguous terminal record as consumed. Use a newly generated manifest after rechecking current authority. `engagement stop` and revocation are durable requests, but only the live original supervisor polls and acts on them. Wall duration and process-group termination are best effort; supervisor crash containment, takeover, and escaped-daemon containment are unavailable.
- Offline-analysis provenance, local engagement approvals, and active-execution provenance share the operator-writable `GATE_HOME` with the state they describe. A process allowed to rewrite the whole root can alter snapshots, receipts, manifests, claims, runs, stops, and evidence, so these records are not tamper-proof against that same-user writer. Managed-upstream integrity uses the reviewed repository locks as its anchor; writable installation receipts are evidence only.

Recovery never uses an unverified reset, force push, cleanup, scope expansion, credential substitution, or silent approval.
