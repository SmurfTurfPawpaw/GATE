# Dedicated-lab campaign authority

`LabCampaignAuthority` is a narrow standing execution contract for a dedicated
HTTP challenge such as one Hacker101 CTF instance. It permits repeated,
single-request `httpx-url-fetch` jobs after one exact operator confirmation. It
does not change the ordinary production engagement lane: every non-lab
execution still requires its own exact `EXECUTE … UNMETERED` confirmation.

## What the authority binds

The private proposal and receipt bind all of the following before confirmation:

- the immutable case scope, ready Program Profile, cited source snapshot, and
  campaign grant digests;
- a current engagement whose `authorization.basis` is exactly `dedicated-lab`,
  including its plan, envelope, receipt, validity window, host environment, and
  private evidence destination;
- the active `active-surface-validation` A1 workflow attempt, admission bytes,
  workflow definition, tool mapping, resource envelope, and stop conditions;
- one canonical HTTP(S) challenge origin, a segment-bound URL path prefix, and
  a frozen IP set copied from a cited, timestamped destination observation;
- the reviewed `httpx-url-fetch` registry entry, compiler source, runtime lock,
  installed executable identity, and exact `observe`/`httpx` tuple;
- cumulative request, rate, concurrency, wall-time, token, spend, evidence, and
  job-count ceilings, plus per-job GET/HEAD, timeout, response-byte, and resource
  bounds;
- expiry and every mandatory stop condition.

The proposal returns one literal confirmation:

```text
AUTHORIZE LAB CAMPAIGN AUTHORITY_ID AUTHORITY_SHA256
```

GATE stores that receipt once. For each job it derives and durably claims a
single-use capability, journals the request intent before target contact, asks
the unchanged execution broker for an exact manifest, and supplies the
broker-returned confirmation internally. A capability cannot bind two workflow
reservations or two manifests, including after cancellation or restart. The lab
lane has an exact concurrency ceiling of one. A started request without a
durable terminal record blocks every later request pending execution
reconciliation; it is never treated as spare concurrency after a restart.

The production campaign handoff is two-phase. The controller first journals
`job-started` with the exact authority ID and releases its lock. The authority
then claims and dispatches the one-shot capability through the broker. Only a
bound terminal result lets the controller journal metrics and completion. A
dispatch error blocks the controller as execution ambiguity, and a worker
restart blocks any still-running managed job without replaying target contact.
The controller context exposes the active start only after validating the
hash-chained campaign journal. Dispatch and broker capability verification
require its authority ID, job ID, and job digest to match exactly, including
after any bounded rate wait.

## HTTP contract

Each job is one GET or HEAD request. The URL must use the confirmed origin and
path prefix exactly. The adapter dials one literal IP in the frozen set while
preserving the URL hostname for Host and TLS SNI. It accepts no request body,
authentication, operator headers, redirects, retries, discovery expansion, raw
argv, shell, or command surface. A redirect is recorded and stops the campaign;
it is never followed. HTTP 429, target instability, evidence-integrity failure,
changed authority, changed runtime, exhausted budget, ambiguity, expiry, and an
operator stop also stop before another request.

GET response bytes are bounded and remain private under `GATE_HOME`. Public or
compact status exposes only typed metrics such as request count, duration,
method, status, bounded byte counts, rate, redirect/retry state, evidence
integrity, and recovery state. It never exposes a response body or flag.

`lab-status` reports `expired` when the authority reaches its expiry, so workers
leave queued jobs untouched instead of starting them. Stopped and unresolved
recovery states retain precedence. Its `usage.precision` is `exact` only when
every journaled request start has completion metrics; otherwise it is
`lower-bound`. Lower-bound totals include only completed requests and must not
be interpreted as exact totals, including when they are zero.

## Adaptive same-origin jobs

An authorized controller transition may append a new immutable job only after
the authority verifier returns a permit bound to the exact job ID and digest.
The permit repeats the origin, path prefix, frozen IPs, adapter/runtime,
workflow, ceilings, and dynamic bounds. The authority journal records intent
before the controller append and completion after it. Both locks cover the
commit boundary. Status counts only controller-committed dynamic jobs and
reports pre-commit intents separately as `jobs.pending`. An exact retry
reconciles the already committed job and permit even if the authority has since
expired or stopped; that bookkeeping-only path cannot admit a different job.

Workflow feedback remains one test per execution. After each result, the
orchestrator must add the immutable result evidence, review the planned test,
consult the current learning projection, and open one fresh test that cites the
previous review and its adaptation. Only then may it enqueue and execute the
next discovered same-origin URL. The campaign worker schedules and recovers
jobs; it does not invent this review or learning record. Until that typed
review/plan orchestrator is wired, adaptive discovery is assisted rather than
unattended.

## Operator commands

All files and commands are case-scoped. Proposal input is an owner-only JSON
file under the selected case state and contains `campaignId`,
`challengeOrigin`, `frozenIps`, `destinationObservationFile`, `admissionFile`,
`expiresAt`, and optional adaptive ceilings.

```bash
./bin/gate.mjs --case CASE_ID campaign lab-create AUTHORITY_ID \
  --file "$GATE_HOME/cases/CASE_ID/state/lab-authority-input.json" --json
./bin/gate.mjs --case CASE_ID campaign lab-confirm AUTHORITY_ID \
  --confirm "AUTHORIZE LAB CAMPAIGN AUTHORITY_ID AUTHORITY_SHA256" --json
./bin/gate.mjs --case CASE_ID campaign lab-status AUTHORITY_ID --json
./bin/gate.mjs --case CASE_ID campaign resume CAMPAIGN_ID --json
./bin/gate.mjs --case CASE_ID campaign run-next CAMPAIGN_ID \
  --lab-authority AUTHORITY_ID --json
./bin/gate.mjs --case CASE_ID campaign lab-enqueue AUTHORITY_ID \
  --file "$GATE_HOME/cases/CASE_ID/state/next-fetch.json" --json
./bin/gate.mjs --case CASE_ID campaign lab-stop AUTHORITY_ID \
  --confirm "STOP LAB CAMPAIGN AUTHORITY_ID AUTHORITY_SHA256" --json
./bin/gate.mjs --case CASE_ID campaign lab-recover AUTHORITY_ID \
  --confirm "RECOVER LAB CAMPAIGN AUTHORITY_ID AUTHORITY_SHA256" --json
```

An enqueue file contains only `jobId`, canonical `target`, frozen `allowedIp`,
and optional `method`, `timeoutSeconds`, and `maxResponseBytes`. It has no raw
command fields.

For a persistent initial-job worker, put `GATE_LAB_AUTHORITY=AUTHORITY_ID` in
the owner-only campaign service environment file. Adaptive jobs already carry
their exact authority ID in the durable enqueue permit.

Linux authority locks bind boot ID, PID, process start time, and a nonce. Every
acquire, dead-owner retirement, mutation, and release is serialized by a
kernel-backed lock; retirement also rechecks the lock inode and bytes before
renaming it as evidence. A malformed or indeterminate lock remains blocked for
host inspection. `campaign lab-recover` with the exact
authority-bound confirmation can retire only a capability claimed before any
request intent was written; a started request remains blocked pending execution
reconciliation. The same explicit recovery validates the complete journal
prefix before repairing one interrupted final append. It restores a complete,
hash-valid record that lost only its newline, or quarantines a nonparseable
tail before truncating to the validated prefix. Normal reads reject an absent
final delimiter, and a valid first record can be repaired before confirmation.
Because a quarantined fragment might have been a stop record, recovery appends
an `execution-ambiguity` stop before returning. A complete but hash-invalid
record is preserved and remains blocked for review. The journal is mandatory:
a missing or empty file, a first record other than the exact bound
`authority-created` record, or a confirmed receipt without the exact second
`authority-confirmed` record leaves authority state indeterminate and blocks
status, permits, capability verification, and execution.

Before publishing an append or repaired journal, GATE validates the complete
proposed journal, including nondecreasing timestamps. A backward host-clock
transition that would violate that ordering is rejected while preserving the
previous readable journal; confirmation likewise validates before persisting
its receipt. Restore a consistent host clock before retrying the transition.
