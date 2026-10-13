# Security policy

## Report a vulnerability

GitHub private vulnerability reporting is not enabled on the current repository. Until it is available, open one minimal public issue titled **Private security contact requested**. Include no vulnerability details, reproduction steps, logs, links, target information, or attachments. The maintainer can then establish a private channel before you share technical material.

After the repository is renamed to GATE, its owner should manually enable **Settings → Code security and analysis → Private vulnerability reporting**. Once the repository's **Report a vulnerability** form is visible under the Security tab, use that form instead of the interim public issue.

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
- schema or policy validation;
- upstream integrity and update handling;
- evidence provenance, redaction, or learning promotion;
- exact-head publication checks.

The projects and security tools listed in GATE remain independent upstream software. Report an upstream vulnerability to that project's security contact, and privately report any unsafe GATE integration behavior here. Catalog presence does not mean GATE redistributes or warrants a tool.

## Authorization boundary

GATE is intended for systems the operator owns or has explicit permission to test. Authorization to change this repository or install a tool does not authorize contact with a third-party target.

Local static analysis and saved-evidence analysis can run without an active receipt. Scanning, crawling, interception, authentication attempts, fuzzing, exploitation, persistence, denial-of-service testing, destructive testing, data access, data removal, and exfiltration simulation require a valid engagement with exact targets, actions, limits, exclusions, data rules, a reviewed plan digest, and an operator receipt. A material change invalidates the receipt.

If a scope mismatch, third-party system, target instability, unexpected data loss, authorization expiry, rate violation, evidence-integrity failure, or operator stop occurs, stop the active operation and preserve the audit record. A future active-tool adapter must monitor and enforce those conditions. Raw active execution is disabled in v0.1 because the generic launcher could not establish those guarantees. Do not test public infrastructure merely to demonstrate a GATE issue; use a local fixture or a target whose authorization explicitly covers the test.

## Data boundary

Live sessions, targets, reports, receipts, captures, binaries, client material, raw tool output, and private learning belong under `GATE_HOME`, outside Git. Runtime setup rejects lexical or canonical overlap between that private root and the repository, rejects linked state paths, and enforces owner-only POSIX modes. Keep credential values in an OS secret store or narrowly permissioned file and place only symbolic references in GATE state when possible. Tracked examples must use non-resolving names such as `example.test` or clearly local fixtures. Secrets in tracked configuration must be references using the allowed schemes, never literal values.

In v0.1, `GATE_HOME` is a single local trust domain for engagement authority and private evidence. Engagement receipts are digest-checked but unsigned and stored beside operator-writable state, so a process that can modify the whole root can forge engagement content and its matching local receipt. Managed-upstream receipts are metadata rather than trust anchors: npm trees are reconstructed from the committed dependency lock and integrity-addressed cache, while release archives and executables are checked against SHA-256 values in the reviewed repository lock. A writer limited to `GATE_HOME` cannot re-anchor modified upstream bytes.

The observer is designed for loopback use. Do not expose it through a public bind, port forward, or unauthenticated reverse proxy. The v0.1 token scanner streams local Codex session JSONL bytes and parses only usage records; it never returns prompt bodies, but direct harness telemetry that avoids session-file access is not yet available. Missing telemetry is `unavailable`; it must not be interpreted as zero activity.

## Known v0.1 security limitations

The present engagement broker verifies declared target/action metadata, authorization dates, plan and envelope integrity, review state, and the local operator receipt. Contract and client-written authorization also require copied private evidence whose SHA-256 is bound into the receipt and rechecked during preflight. It does not authenticate the operator cryptographically or correlate a No Mistakes run ID with an external attestation. `gate engagement exec` is disabled until a reviewed adapter can bind downstream arguments to scope, enforce actual limits and stop conditions, terminate the process group, and preserve evidence. High-impact work also needs independent command review and a deliberately controlled lab.

Publication is read-only in v0.1. `publication check` and `publication dry-run` inspect exact-head PR state and required checks; merge, deploy, and publish stay blocked until a trusted adapter verifies a No Mistakes attestation for the exact head and enforces the project destination and merge policy.

See [README.md](README.md#current-limits) and [docs/architecture.md](docs/architecture.md) before relying on GATE for an engagement.
