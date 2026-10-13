# Contributing to GATE

GATE is a personal control plane with public, reusable contracts. Contributions should strengthen evidence, reproducibility, laptop compatibility, and clear authority boundaries without copying upstream implementations into this repository.

## Set up

On Windows 11, work inside WSL2. Use Node.js 22.20 or newer (Node 24 is also tested), npm, Git, GitHub CLI, and Codex CLI.

```bash
git clone https://github.com/SmurfTurfPawpaw/GATE.git
cd GATE
npm ci --ignore-scripts
npm test
npm run check
```

Set `GATE_HOME` to a private directory outside the repository before running commands that create runtime state. Never commit events, engagement records, evidence, credential references or values, upstream checkouts, or private learning. Prefer an OS secret store or a narrowly permissioned file outside the broad agent-writable root for credential values.

## Choose the right contract

Read [AGENTS.md](AGENTS.md), [docs/architecture.md](docs/architecture.md), and the relevant policy and schema before editing. Each state transition has one owner. Avoid a parallel workflow that competes with Firstmate, Treehouse, No Mistakes, GATE publication authority, or the engagement broker.

Keep pull requests focused. Explain the concrete problem, resulting behavior, evidence, tests, and remaining limitations. A change that alters public behavior should update the corresponding documentation and schema or policy when applicable.

## Development lifecycle

Treehouse owns normal development workspaces. Work in one exclusive lease and preserve it if work is dirty or unlanded. GNHF, when used, is an opt-in bounded task within that lease.

Before immutable handoff, run:

```bash
npm test
npm run check
```

No Mistakes owns the branch after handoff through review, tests, documentation, lint, push, pull request, and CI. Do not mutate the branch concurrently. GATE v0.1 provides read-only exact-head and required-check preflight. Merge or publication remains blocked until a trusted adapter verifies a No Mistakes attestation bound to that head and enforces project policy.

Tests should cover meaningful contracts and failure modes. Receipt invalidation, target and exclusion matching, redaction, schema rejection, private/public storage, command invocation, cancellation, and recovery deserve direct tests. Do not add tests that only repeat implementation text.

## Change schemas and policies

Treat policy and schema edits as behavior changes. Include:

- the authority or invariant being changed;
- migration or compatibility impact;
- valid and invalid examples;
- tests showing fail-closed behavior;
- documentation for the operator;
- a learning record when the change arose from a correction, failure, workaround, or new evidence.

Do not weaken validation to accept an existing invalid document. Correct the document or propose an explicit, reviewed contract change.

## Add or update an upstream

Do not use floating branches, unresolved tags, abbreviated SHAs, mutable image tags, or unpinned package ranges. Update [locks/upstreams.lock.json](locks/upstreams.lock.json) with a full Git commit and exact artifact integrity where available. Verify the official source, license, platform support, telemetry, and smoke test. Update [THIRD_PARTY.md](THIRD_PARTY.md) when the version, revision, license, or integration role changes.

Upstream source remains external. Prefer a small adapter over copying or forking implementation code.

## Add a security tool

A catalog entry is an admission record, not an installation or authority grant. A new tool needs:

1. a concrete capability gap and comparison with current entries;
2. canonical source, maintenance evidence, and license;
3. exact version, full commit, artifact digest, and signature result where available;
4. supported hosts, install lane, executable, privileges, telemetry, and data behavior;
5. risk and approval classification for its highest normal effect;
6. a bounded smoke test on a fixture or explicitly approved target;
7. structured evidence and cancellation behavior;
8. the appropriate profile selection;
9. a sanitized cause-and-change learning;
10. No Mistakes validation.

Tool and target output is untrusted data. Adapters must use argument arrays without a shell, reject unknown flags, validate scope, enforce resource limits, preserve raw evidence and hashes, and redact secrets.

v0.1 does not yet define a per-tool lock or admission-record store. A catalog-only addition therefore remains a capability candidate. Put the evaluated version, commit, artifact digest, signature result, and smoke evidence in the reviewed change, and do not call the tool admitted or installed until its adapter and immutable lock record are added under an approved contract.

## Add a skill

Skills are privileged project instructions. Put each package under `skills/<name>/SKILL.md` with a precise trigger, explicit non-triggers, required policy checks, and truthful completion criteria. Review its full content and pin distributed content. Do not install a skill globally, in bulk, or because it is popular.

## Record learning

Use a one-line cause and concrete behavior change for corrections, failures, retries, workarounds, tool gaps, evidence contradictions, regressions, policy violations, and environment constraints:

```bash
./bin/gate.mjs learn --cause "WHAT_HAPPENED" --change "WHAT_WILL_NOW_CHANGE"
```

Use `--private` for target, client, credential, private-path, capture, or unpublished-finding context. A public learning must be sanitized and backed by the code, configuration, test, policy, or documentation change it describes.

## Report security issues

Do not disclose vulnerability details in a public issue or pull request. Follow the interim private-contact process in [SECURITY.md](SECURITY.md).
