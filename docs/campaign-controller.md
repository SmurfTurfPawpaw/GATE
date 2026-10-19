# Campaign controller

The campaign controller is a case-bound, foreground scheduler for repeatable
assessment work. It provides durable queueing, replay, binding checks,
recovery, and cockpit-ready counters for non-contact dry runs. Its only managed
target-contact path is one exact `httpx-url-fetch` job dispatched through a
separately confirmed `LabCampaignAuthority`; the generic controller path never
turns a managed job into target contact.

## Contract and authority boundary

Every campaign is private state under
`GATE_HOME/cases/CASE_ID/state/campaigns/CAMPAIGN_ID`. Its immutable
[`CampaignGrant`](../schemas/campaign-grant.schema.json) binds:

- the immutable case ID and scope digest;
- the current Program Profile ID and digest;
- one selected, cited program-source content, projection, and whole-snapshot
  digest set supplied by intake and matched against both the current imported
  snapshot and the reviewed Program Profile source ledger;
- an optional engagement ID;
- exact managed-adapter, action, and tool tuples;
- exact typed selectors and one execution environment;
- cumulative time, request, rate, concurrency, input-token, output-token,
  total-token, spend, and evidence ceilings;
- an expiry and the complete stop-condition set.

`grantSha256` is a scheduling constraint. It is not target-contact authority
and must never be reinterpreted as an engagement receipt, workflow admission,
or execution confirmation. The existing engagement broker and workflow runtime
continue to own those records.

Managed-adapter jobs use immutable typed fields and have no command, argv,
shell, executable, script, or stdin surface. `campaign run-next` and `campaign
worker` leave a managed queue head untouched until an exact confirmed
dedicated-lab authority is selected. They journal the authority ID and running
job before calling the authority, which revalidates the engagement, workflow,
adapter/runtime, destination, budgets, expiry, and single-use capability before
the unchanged broker can make one request. The controller commits only the
authority-bound terminal metrics. A missing or untrusted terminal result blocks
the job and campaign as execution ambiguity and is never retried automatically.

The generic `runNextCampaignJob` library path still preserves an unsupported
managed job as blocked without target contact. A dedicated-lab campaign
authority remains a separate contract, not an upgrade of a scheduling grant.

## Durable state

The controller writes owner-only files:

```text
campaigns/CAMPAIGN_ID/
├── grant.json
├── jobs/JOB_ID.json
├── journal.jsonl
└── state.json
```

The grant and job definitions are immutable and content-bound. The journal is
append-only, sequence-numbered, and hash-chained. `state.json` is a replayable
cache; the journal remains authoritative. A campaign lock includes the Linux
boot ID, PID, and process start time so recovery does not mistake a reused PID
for the original owner.

The projection reports queued, running, completed, blocked, and failed job
counts. It reports attempted and completed jobs and recoveries as exact
measurements. Hypothesis accounting remains explicitly unavailable until the
workflow journal supplies a reviewed canonical projection. Time, requests,
tokens, spend, and evidence keep exact, estimated, or unavailable provenance;
the dry-run lane records exact zero target requests, tokens, spend, and evidence.

## Foreground commands

Campaign commands require an explicit case. Create an owner-only mode `0600`
input file inside the selected case state directory. The `source` object must
contain the exact digests returned by intake. Creation fails if the source was
revised after preparation or is not the exact content-bound entry in the ready
Program Profile ledger:

```json
{
  "expiresAt": "2026-10-20T12:00:00.000Z",
  "source": {
    "id": "program-rules",
    "contentSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "projectionSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "snapshotSha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  },
  "engagementId": null,
  "operations": [],
  "selectors": [],
  "environment": "host",
  "ceilings": {
    "maxWallMinutes": 60,
    "maxRequests": 0,
    "maxRatePerSecond": 0,
    "maxConcurrency": 1,
    "maxInputTokens": 10000,
    "maxOutputTokens": 10000,
    "maxTotalTokens": 20000,
    "maxSpend": 0,
    "maxEvidenceBytes": 0
  },
  "jobs": [
    {
      "id": "controller-check",
      "type": "non-contact-dry-run",
      "summary": "Verify durable scheduling without target contact."
    }
  ]
}
```

Run one action at a time in the foreground:

```bash
chmod 600 "$GATE_HOME/cases/CASE_ID/state/campaign-input.json"
./bin/gate.mjs --case CASE_ID campaign create pilot \
  --file "$GATE_HOME/cases/CASE_ID/state/campaign-input.json" --json
./bin/gate.mjs --case CASE_ID campaign resume pilot --json
./bin/gate.mjs --case CASE_ID campaign run-next pilot --json
./bin/gate.mjs --case CASE_ID campaign status pilot --json
./bin/gate.mjs --case CASE_ID campaign pause pilot --json
./bin/gate.mjs --case CASE_ID campaign stop pilot --reason "End the pilot window." --json
./bin/gate.mjs --case CASE_ID campaign recover pilot --json
```

Creation starts paused. `resume` rechecks the case, profile, and current source
snapshot. `run-next` rechecks them again before choosing one queued job. A
changed or expired binding stops or blocks before work. `pause` and `stop` are
durable transitions. `recover` retires only a provably dead lock, replays the
journal, safely requeues an interrupted non-contact dry-run, and marks any
ambiguous target-contact job blocked. A missing or malformed lock owner record
is preserved for manual forensic review because the controller cannot prove
that its owner is dead. If a complete, hash-valid final record lost only its
newline delimiter, recovery restores the delimiter and preserves that record.
If the final bytes are an ambiguous fragment, recovery quarantines those exact
bytes and atomically replaces the journal with the validated prefix plus a
terminal `controller-recovery-required` stop; any interrupted jobs are resolved
first in that same replacement. The campaign therefore never becomes runnable
because a possible final stop record was torn. Corruption in an earlier record,
or a complete but invalid final record, remains unchanged and fail closed for
manual review.

The create command returns a bounded operational projection and never echoes
the source record, selectors, or full private grant. `status` reports counts,
ceilings, binding health, capability, and exact/estimated/unavailable metric
provenance. `bindingHealth.schedulingReady` means only that the private queue
bindings are current. `executionAuthorityReady` is a separate value and remains
false in the plain status projection because status does not select or attest a
lab authority. `capability.managedAdapterDispatch` reports
`confirmed-dedicated-lab-only`.

## Dedicated-lab adaptive enqueue

The controller has one deliberately narrow dynamic queue transition for the
dedicated-lab HTTP lane. It is not exposed as a general CLI command. A trusted
LabCampaignAuthority verifier must synchronously return a candidate-bound
permit naming the exact immutable job ID and digest, authority and receipt,
campaign and grant, HTTPx adapter/runtime binding, workflow phase attempt,
canonical origin and segment-bound path prefix, frozen destination IP set,
methods, response and timeout bounds, job-count limit, and cumulative
ceilings. The permit itself is digest-bound.

Only a schema-valid `httpx-url-fetch` `observe` job can pass. The controller
rechecks the exact URL, path boundary, allowed IP, typed operation, workflow,
adapter tuple, per-job limits, and both campaign and authority cumulative
reservations. It writes the immutable job definition before appending a
hash-chained `job-enqueued` record, and dispatch cannot see the job until that
record exists. No argv, command, shell, script, executable, stdin, arbitrary
adapter, cross-origin URL, or unconfirmed broad selector enters this path. The
separate authority/workflow layer still owns one reviewed test cycle and one
single-use execution capability per request.

After creating and confirming the authority, resume the campaign and either run
one job explicitly or start the worker:

```bash
./bin/gate.mjs --case CASE_ID campaign resume CAMPAIGN_ID --json
./bin/gate.mjs --case CASE_ID campaign run-next CAMPAIGN_ID \
  --lab-authority AUTHORITY_ID --json

GATE_LAB_AUTHORITY=AUTHORITY_ID \
  ./bin/gate.mjs --case CASE_ID campaign worker CAMPAIGN_ID --json
```

An adaptive job already carries its authority ID in the controller's durable
enqueue permit, so the worker can select that exact authority without the
environment variable. An initial managed job requires `--lab-authority` or
`GATE_LAB_AUTHORITY`. An absent, proposed, stopped, expired, recovery-required,
or campaign-mismatched authority defers the queued job without contact.

Both `run-next` and the persistent worker also require one fresh, unreserved
workflow test in the queued job's exact workflow and phase attempt. A missing,
already reserved, or unreadable test defers the job before the controller
records a start or the authority claims a capability. After a completed job,
review its result and open the next test through the
[workflow feedback procedure](pentest-workflow.md#target-contact-admission-and-execution)
before dispatching another queued managed job. The broker revalidates test
readiness when reserving execution.

The immutable context loader also projects the current hash-validated
`job-started` authority ID, job ID, and job digest. The authority checks that
exact start binding before capability creation and again after any rate wait,
so a second confirmed authority for the same campaign cannot dispatch the job.

## Persistent laptop services

`campaign worker ID` is an implemented foreground loop over the typed
controller. It holds a kernel-backed singleton lease, conditionally recovers a
proven interrupted job, schedules only controller jobs, and never converts
model or cockpit text into a command. For an authorized managed queue head, it
performs the durable start → authority/broker dispatch → durable finalization
handoff described above. It atomically writes an owner-only
`worker.json` heartbeat with a process generation, exact journal and queue
state, counters, and a bounded validity window. The sanitized projector removes
PID, boot identity, paths, selectors, reasons, job identities, and journal
digests. It checks both the live Linux process identity and the active kernel
lease before reporting current state; an expired heartbeat or dead worker is
stale.

Every worker startup, cycle, recovery, and job transition also advances the
case-local CTF pilot record through a serialized read/merge/write update. Known
campaign attempts and exact request/token counts are published; challenge
objectives, depth, retries, learning, and other facts remain unavailable unless
a richer producer already supplied them. Receipt-backed learning persists; a
new worker generation resets solving, cockpit, and integrity verdicts it has
not re-established. Observer polling already projects this record, so a worker change is
visible on the next uncached observer poll. The generic worker projector remains
an explicit hook for a later fleet-protocol revision.

Tested `systemd --user` templates for the loopback observer, campaign worker,
and remote laptop runner, plus a fixed-path renderer and WSL2 setup
instructions, live under
[`deploy/local/systemd`](../deploy/local/systemd/README.md). The units use
`Type=simple`, owner-only environment files, `UMask=0077`, bounded stop time,
and basic service hardening. Observer and campaign services use
`Restart=on-failure`; the remote runner uses `Restart=on-abnormal` so permanent
identity or configuration exits remain stopped. The worker deliberately remains alive after a queue reaches
`completed` so a verified adaptive enqueue can reopen it; an operator stop or
SIGTERM exits cleanly.

These files are implemented in the repository but are not activated on the
operator's laptop from this cloud workspace. Laptop activation requires
rendering the real local paths, enabling WSL systemd and user lingering, and
starting the units. A Windows startup task is still required to start a stopped
WSL distribution after host boot. No WSL user service can keep Windows alive
through sleep, reboot, or `wsl --shutdown`. The public Pages cockpit remains
static, and the remote conversation bridge does not acquire campaign execution
authority.

## Learning boundary

Campaign execution events and evidence remain inside the selected case. A
correction, retry, workaround, missing capability, misleading KPI, or recovery
creates a private case learning through the existing learning workflow. A
challenge-specific trick or target fact stays private and specific. Only a
reproduced, sanitized change at the right reusable abstraction may proceed
through the existing reviewed promotion path. The controller never promotes a
job result directly into global guidance and never uses learning to broaden the
grant, scope, or execution authority.
