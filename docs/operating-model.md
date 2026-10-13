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

## Daily software work

1. Prepare and validate a project contract from [project.json](../templates/project.json). The persistent project registry is not implemented in v0.1, so retain the reviewed contract with the project's private operating records.
2. State the outcome and acceptance criteria to the Firstmate session.
3. Watch GATE-emitted activity, derived agent/task state, learning, freshness, and available token totals in the observer. Firstmate and Treehouse do not yet emit their complete lifecycle into it.
4. Answer only decisions that are ambiguous, scope-expanding, destructive, or blocked by unavailable evidence.
5. Run the real No Mistakes workflow for review, tests, documentation, push, PR, and CI, and retain its genuine run evidence. GATE does not yet orchestrate that complete lifecycle or verify a run ID against an external attestation.
6. Run `gate publication check` and `gate publication dry-run` for the expected repository, pull request, exact head, genuine No Mistakes run reference, and intended merge mode. The v0.1 adapter checks PR state, head, mergeability, and a nonempty green required-check set, but it does not verify the external run or project-level facts.
7. Report publication as blocked. A future trusted adapter may merge, deploy, or publish only after it verifies a No Mistakes attestation bound to that head and enforces the registered base branch, merge posture, and destination.
8. Review the outcome, limitations, costs, and learning entries.

The target operating model routes edit, test, commit, push, PR, CI, merge, deploy, and publication through the named owners. v0.1 wires local GATE primitives and read-only exact-head GitHub PR preflight. Mutation adapters and other owner bridges remain explicit integration work. No component may bypass a missing owner or adapter because another tool offers a similar command.

## Active security work

Create an engagement from [engagement.json](../templates/engagement.json). Drafting and local research do not authorize target contact.

The active flow is:

1. **Establish authority.** Store the written authority or ownership evidence privately and reference it from the engagement.
2. **Map scope.** Add exact targets, exclusions, action classes, validity times, data destinations, and limits. URL path prefixes stop at segment boundaries; an approved query is exact, and URL fragments are rejected.
3. **Build the plan.** Record hypotheses, commands, likely effects, credentials, rollback, stop conditions, coverage, and completion tests.
4. **Validate the plan.** Run No Mistakes against the immutable plan, then record its run and head. v0.1 accepts that record but does not invoke No Mistakes or verify an attestation.
5. **Report before engaging.** Present the target, actions, likely effects, limits, stop conditions, and plan digest directly to the operator. A dedicated local decision view is not implemented in v0.1.
6. **Approve once.** The operator supplies the exact confirmation for the digest. GATE stores a local unsigned receipt whose provenance depends on the operator workflow and `GATE_HOME` permissions. In the target design it can cover repeated in-scope adapter launches until expiry or invalidation; v0.1 has no generic active adapter.
7. **Stop at preflight in v0.1.** `gate engagement check` produces target/action decision evidence, but arbitrary active execution is disabled. A reviewed scope-aware adapter must bind exact arguments to scope, preserve tool-native evidence, and enforce the approved limits before target contact.
8. **Execute and monitor through the future adapter.** Explore the stated hypotheses and new in-scope branches without stopping at a clean scanner result. The adapter must watch revocation and configured stop conditions, terminate the process group when one occurs, and preserve full commands, versions, timestamps, hashes, and raw output privately.
9. **Validate findings.** Reproduce with an independent method where possible and separate observed facts from inference.
10. **Report and retest.** Use [security-report.md](../templates/security-report.md), include limitations and residual unknowns, and assess the completion contract before closing. In v0.1, `engagement close` is an administrative state change; it does not inspect coverage, run completion tests, or certify completeness.

The operator receipt is necessary authority for target contact. No Mistakes supplies technical review; it does not create permission to test a target. Both provenance steps are procedural in v0.1: their identifiers are recorded and digest-checked locally, not cryptographically attested by their external principals.

## Plan changes

These changes invalidate an existing receipt:

- any target is added;
- an exclusion is removed;
- an action class is added;
- a request, rate, concurrency, duration, or token limit is increased;
- a data destination is added;
- the plan content changes;
- authorization expires or is revoked.

The agent may prepare the revised plan automatically. It reports the delta and obtains a receipt for the new digest before resuming.

## Tool use and admission

An admitted tool has an official source, license record, exact version or commit, integrity record when available, supported platform, effect classification, telemetry setting, smoke test, and owner.

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

Raw evidence stays under `GATE_HOME`. The public repository contains only sanitized summaries that have explicit release authority. Evidence references are stable URIs such as `private://`, `evidence://`, or `event://`.

Never turn inability to inspect into a negative claim. State that a surface is unverified or limited, include the cause, and describe the next test that would resolve it.

## Token usage

The observer displays aggregate usage and per-session or recorded-run values when its sources provide them. Provider-reported values are exact; explicitly modeled values are estimated; missing provider data is unavailable. Complete live Codex fleet and account-quota telemetry, plus grouping by day, require a future harness adapter.

Token budgets are required bounds for GNHF loops and engagements. GATE does not yet orchestrate the GNHF loop or active engagement execution; the future adapter or external owner must enforce the runtime budget. A budget must never trigger a silent provider, model, account, or billing-mode change.

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
- Target integrations require Firstmate to reconcile durable task state, Treehouse to preserve dirty or unlanded leases, GNHF to preserve interrupted work, and No Mistakes to retain branch ownership during validation. These bridges are not complete in v0.1.
- A changed PR head invalidates publication authority until the exact head passes again.
- A changed security plan invalidates active authority until a new receipt exists.
- Active execution is disabled in v0.1. A future adapter must enforce timeout and process-group termination while polling receipt revocation and other stop conditions.
- Local engagement approvals share the operator-writable `GATE_HOME` with the state they describe and are not tamper-proof against a process allowed to rewrite both files. Managed-upstream integrity uses the reviewed repository locks as its anchor; writable installation receipts are evidence only.

Recovery never uses an unverified reset, force push, cleanup, scope expansion, credential substitution, or silent approval.
