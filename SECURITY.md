# Security policy

## Report a vulnerability

GATE is a public repository. If **Report a vulnerability** is visible on the repository's Security tab, use that private form. If the form is unavailable, contact the repository owner through an existing private channel, confirm the recipient and channel, and only then share technical details. Do not open a public issue or disclose vulnerability details merely to request a private contact.

Include, when available:

- the affected GATE commit or version;
- operating system and whether the issue occurs in WSL2;
- the affected command, policy, schema, adapter, or observer route;
- minimal reproduction steps on a local fixture;
- observed impact and the boundary crossed;
- sanitized logs or artifact hashes;
- a suggested mitigation.

Remove credentials, cookies, API tokens, private keys, client data, packet payloads, precise target selectors, and unpublished third-party findings. Reference sensitive evidence without copying it into the report. There is no guaranteed response SLA for this personal project; disclosure should remain coordinated until a fix and release decision are ready.

## Supported versions

GATE is currently a v0.1 pre-release. Only the latest commit on the default branch is supported. Historical commits, local forks, altered policies, and unpinned upstream combinations do not receive fixes unless the maintainer states otherwise.

## Scope

Useful reports include vulnerabilities in GATE's:

- engagement scope matching, digest validation, or receipt invalidation;
- command construction and process execution;
- secret and private-data handling;
- observer loopback, origin, projection, or browser protections;
- local cockpit companion session, origin, projection, or Pages-publication protections;
- schema or policy validation;
- upstream integrity and update handling;
- evidence provenance, redaction, or learning promotion;
- exact-head publication checks.

The projects and security tools listed in GATE remain independent upstream software. Report an upstream vulnerability to that project's security contact, and privately report any unsafe GATE integration behavior here. Catalog presence does not mean GATE redistributes or warrants a tool.

## Authorization boundary

GATE is intended for systems the operator owns or has explicit permission to test. Authorization to change this repository or install a tool does not authorize contact with a third-party target.

Local static analysis and saved-evidence analysis can run without an active receipt. Scanning, crawling, interception, authentication attempts, fuzzing, exploitation, persistence, denial-of-service testing, destructive testing, data access, data removal, and exfiltration simulation require a valid engagement with exact targets, actions, limits, exclusions, data rules, a reviewed plan digest, and an operator receipt. A material change invalidates the receipt.

If a scope mismatch, third-party system, target instability, unexpected data loss, authorization expiry, rate violation, evidence-integrity failure, or operator stop occurs, stop the active operation and preserve the audit record. A reviewed adapter may enforce tool-specific conditions. While its original supervisor remains alive, the supervised generic lane polls engagement validity and stop requests, applies a wall-duration limit, and attempts process-group termination, all on a best-effort basis. A supervisor crash or `SIGKILL` has no takeover path, so durable stop and revocation requests remain recorded but inactive and the ordinary tool process group can remain alive. Its separate exact `UNMETERED` confirmation acknowledges that `argv-action-semantics-validation` and `supervisor-crash-containment` are unavailable and that it cannot establish egress, request, rate, concurrency, token, daemon, filesystem, credential-broker, complete artifact, or trusted-provenance guarantees. Do not test public infrastructure merely to demonstrate a GATE issue; use a local fixture or a target whose authorization explicitly covers the test.

## Data boundary

Live sessions, targets, reports, receipts, execution manifests and claims, captures, binaries, client material, raw tool output, and private learning belong under `GATE_HOME`, outside Git. Runtime setup rejects lexical or canonical overlap between that private root and the repository, rejects linked control-state paths, and enforces owner-only POSIX modes. Generic tool sandboxes contain opaque tool-created content and remain private. Keep credential values in an OS secret store or narrowly permissioned file and place only symbolic references in GATE state when possible. Tracked examples must use non-resolving names such as `example.test` or clearly local fixtures. Secrets in tracked configuration must be references using the allowed schemes, never literal values.

In v0.1, `GATE_HOME` is a single local trust domain for engagement authority, execution provenance, and private evidence. Engagement receipts are digest-checked but unsigned and stored beside operator-writable manifests, claims, runs, stops, and evidence, so a process that can modify the whole root can forge or erase local consistency. Exclusive files and hashes coordinate trusted processes; they are not protection from that same-user writer. Managed-upstream receipts are metadata rather than trust anchors: npm trees are reconstructed from the committed dependency lock and integrity-addressed cache, while release archives and executables are checked against SHA-256 values in the reviewed repository lock. A writer limited to `GATE_HOME` cannot re-anchor modified upstream bytes.

The observer and interactive cockpit companion are designed for loopback use. Do not expose either through a public bind, port forward, tunnel, or unauthenticated reverse proxy. The GitHub Pages artifact is a separate static preview built from an explicit allowlist; it must never contain companion modules, session capabilities, observer responses, prompts, target data, or private runtime state. The v0.1 token scanner streams local Codex session JSONL bytes and parses only usage records; it never returns prompt bodies, but direct harness telemetry that avoids session-file access is not yet available. Missing telemetry is `unavailable`; it must not be interpreted as zero activity.

## Known v0.1 security limitations

The present engagement broker verifies declared target, action-label, permitted-tool, and execution-environment metadata, authorization dates, plan and envelope integrity, review state, and the local operator receipt. `declared-action-label-binding` does not prove that arbitrary tool arguments implement that action class. Contract and client-written authorization also require copied private evidence whose SHA-256 is bound into the receipt and rechecked during preflight. It does not authenticate the operator cryptographically or correlate a No Mistakes run ID with an external attestation.

On Linux and WSL2, `gate engagement exec` can launch only a digest-bound, one-shot manifest for a receipt-bound `host` engagement whose approved destinations include `gate-home`, because raw evidence always lands there, and only after the exact `EXECUTE MANIFEST_ID MANIFEST_SHA256 UNMETERED` confirmation. Container, rootless-container, VM, and remote-lab receipts require a lane that actually creates that environment. GATE expands one whole-argument target placeholder, opens and hashes the executable, rechecks descriptor metadata immediately before spawn, invokes the descriptor through `/proc/self/fd` without a shell, removes inherited environment and stdin, and records bounded private evidence. The operator must review whether the exact argv matches the declared action; only a reviewed adapter validates tool-specific flag semantics. GATE binds the catalog risk class and labels audit events with the more severe of that risk ceiling and the declared action effect, but this conservative label does not block the launch. `executable-descriptor-observed-sha256` records bytes read through the opened descriptor. `immutable-executable-snapshot` is unavailable: a same-UID writer can mutate a writable inode before or during exec, so the digest does not prove atomically frozen or launched bytes, source, version, signature, trust, or the identity of interpreters, libraries, plug-ins, configuration, inputs, or processes that tool starts. The child has the same UID and host authority as GATE, so the minimal environment is not filesystem, network, process, or credential isolation. Same-user code can alter accessible dependencies and state, leave the supervised process group, survive loss of the original supervisor, or create a daemon outside that group. Use a reviewed adapter and an appropriately isolated host or lab when the generic lane's recorded unavailable guarantees are required. High-impact work still needs independent command review and a deliberately controlled environment.

Publication is read-only in v0.1. `publication check` and `publication dry-run` inspect exact-head PR state and every observed check on that head without requiring branch protection; merge, deploy, and publish stay blocked until a trusted adapter verifies a No Mistakes attestation for the exact head and enforces the project destination and merge policy.

See [README.md](README.md#current-limits) and [docs/architecture.md](docs/architecture.md) before relying on GATE for an engagement.
