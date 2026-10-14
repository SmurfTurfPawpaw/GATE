# Engagement plan review

## Decision

- Engagement:
- Plan digest:
- Review status:
- Authorization evidence:
- Validity window:
- Permitted tool IDs:
- Execution lane for each tool: reviewed adapter | supervised generic
- Receipt-bound execution environment:
- Receipt-bound allowed destinations (include `gate-home` for supervised generic execution):

## What will be contacted

List exact included selectors and exclusions.

## What will be attempted

List the permitted action classes, exact catalog tool IDs, commands, authentication contexts, and expected effects. For each generic command, show the declared action label, catalog risk class, catalog-selected `argv0`, and complete proposed tool argument array with exactly one whole-argument `{{GATE_TARGET}}` placeholder and its expected expanded index. Explain why those arbitrary arguments match the selected action; only a reviewed adapter validates tool-specific flag semantics. Record the executable source/path and whether version, integrity, and known-good provenance are verified or unavailable. Supervised generic execution requires `scope.environment: host` and receipt-approved `gate-home` because raw evidence always lands there; name a different implementing lane for container, rootless-container, VM, or remote-lab work.

## Why this depth is appropriate

List hypotheses, coverage expectations, independent validation, completion tests, and known limitations.

## Bounds

List request, rate, concurrency, duration, token, data retention, and destination limits. For a generic launch, distinguish receipt-bounded declarations from measured limits.

## Execution controls

For each lane, record what is enforced, best effort, and unavailable. A supervised generic manifest must state:

- enforced: engagement and host-environment binding, receipt-bound allowed destinations including `gate-home`, target argument, `declared-action-label-binding`, tool allowlist and catalog risk binding, exact argv, no shell, `executable-descriptor-observed-sha256`, minimal environment, private stdout/stderr, one-shot claim, and declared bounds within the receipt;
- best effort: authorization/revocation/stop polling, wall duration, and process-group termination, all requiring the original supervisor to remain alive;
- unavailable: `argv-action-semantics-validation`; egress-target restriction; request, rate, concurrency, and token measurement; daemon-escape containment; `supervisor-crash-containment`; `immutable-executable-snapshot`; filesystem isolation; credential brokering; complete tool-artifact inventory; and known-good executable provenance.

Describe same-UID host effects, accessible files and local services, likely children or daemons, mutable interpreters/libraries/plug-ins/configuration, and why this lane is suitable. State that durable stop and revocation files have no takeover worker, so a crash or force-kill of the original supervisor can leave its ordinary process group alive, while same-user processes may also leave that group. Record that loss of authenticated group identity during teardown produces status `unknown` and termination reason `supervision-lost`. State that the observed descriptor SHA-256 is bytes read through the opened descriptor and that a same-UID writer can mutate a writable inode before or during exec, so it does not prove atomically frozen or launched bytes. Record that audit events use the maximum of the declared action effect and catalog risk ceiling without blocking launch. Name the private sandbox, stdout, stderr, result, and tool-native evidence destinations without copying sensitive values into this tracked report template.

## Stop conditions

List every automatic stop and the recovery path.

## Material risks

Describe target instability, state changes, account effects, data access, destructive potential, persistence, denial-of-service potential, and third-party dependencies.

## Receipt

The plan receipt applies only to the exact digest above. A target, exclusion, action class, permitted tool, data destination, environment, or limit change requires a new report and receipt.

Each supervised generic launch also requires a separate exact `EXECUTE MANIFEST_ID MANIFEST_SHA256 UNMETERED` confirmation after the operator reviews the expanded argv, executable identity, evidence paths, expiry, and unavailable controls. The plan receipt is not that one-shot confirmation.
