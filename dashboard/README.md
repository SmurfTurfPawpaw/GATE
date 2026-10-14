# GATE observer dashboard

The observer is a dependency-free, read-only browser view of GATE's local event, supervised-execution, offline-analysis, learning, engagement, project, upstream, and token metadata. It reads the current `buildStatus` snapshot; it does not connect to a Codex app-server feed. Token availability depends on records that GATE can read from its private runtime state, and unknown measurements remain `null`.

Run it with:

```bash
npm run dashboard
```

The server binds to `127.0.0.1:4173` by default. It rejects non-loopback bind addresses, foreign `Host` authorities, non-local `Origin` values, explicit cross-site browser requests, and methods other than `GET` and `HEAD`.

## Static routes

The server uses this exact allowlist:

| Route | File | MIME type |
|---|---|---|
| `GET /` | `dashboard/index.html` | `text/html; charset=utf-8` |
| `GET /dashboard` | `dashboard/index.html` | `text/html; charset=utf-8` |
| `GET /dashboard/` | `dashboard/index.html` | `text/html; charset=utf-8` |
| `GET /dashboard/app.js` | `dashboard/app.js` | `text/javascript; charset=utf-8` |
| `GET /dashboard/favicon.svg` | `dashboard/favicon.svg` | `image/svg+xml` |
| `GET /dashboard/model.js` | `dashboard/model.js` | `text/javascript; charset=utf-8` |
| `GET /dashboard/styles.css` | `dashboard/styles.css` | `text/css; charset=utf-8` |

All static and JSON responses use `Cache-Control: no-store`, a self-only content security policy, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and `Cross-Origin-Resource-Policy: same-origin`. There is no CORS opt-in.

## JSON API

Every endpoint returns a server-side allowlisted `gate.observer/v1` projection. These responses are reduced views, rather than canonical event, learning, engagement, or usage records. `dashboard/model.js` applies a second allowlist before any value reaches the DOM.

### `GET /api/status`

The status response contains:

- `apiVersion`, fixed to `gate.observer/v1`, and snapshot generation time `at`;
- aggregate `state` and `counts` for queued, running, waiting, blocked, failed, succeeded, unknown, agent, and task records;
- `agents` and `tasks` derived from the latest valid GATE events, with process-scoped member, run, and task pseudonyms plus public component label, stage, status, effect class, and timestamps;
- `usage`, containing availability, source, nullable token counts, process-scoped session pseudonyms, and nullable context and bounded-loop budget measurements;
- `budget`, the configured bounded-loop limit and its source; v0.1 does not measure budget consumption;
- `telemetry`, containing source freshness and last-activity time;
- `execution`, with supervisor configuration, lane availability, mode, canonical lifecycle counts, enforced, best-effort, and unavailable capabilities, plus at most 30 recent runs containing only process-scoped pseudonyms and lifecycle metadata;
- `offlineAnalysis`, with offline-lane configuration and availability, canonical lifecycle counts, reviewed capability labels, at most 25 recent process-scoped run pseudonyms with status and isolation state, and bounded aggregate retention and control-health measurements;
- `engagements`, with process-scoped pseudonyms plus status, review state, validity time, token cap, one-shot-manifest requirement, global supervisor-lane state, explicit manifest-required eligibility, and local-unverified attestation status;
- `projects`, with process-scoped pseudonyms, registry status, provider and environment metadata, configuration flags, global supervisor-lane state, and explicit not-evaluated execution eligibility;
- `upstreams`, with `id`, pinned `version` or `commit`, `installed`, `integrityState`, and `ready`. Integrity state is `verified`, `receipt-only`, `commit-only`, `invalid`, `not-installed`, or `unknown`. `ready` can be true only with `verified` integrity and producer readiness. The built-in observer deliberately skips expensive content reconstruction, so receipt-only or commit-only entries may be installed but remain not ready. Run the full `gate upstream list` check before resolving an installed binary.

Example reduced status fields:

```json
{
  "apiVersion": "gate.observer/v1",
  "at": "2026-10-13T12:00:00.000Z",
  "state": "running",
  "counts": {
    "queued": 0,
    "running": 1,
    "waiting": 0,
    "blocked": 0,
    "failed": 0,
    "succeeded": 2,
    "unknown": 0,
    "agents": 1,
    "tasks": 1
  },
  "usage": {
    "availability": "exact",
    "source": "gate-token-log",
    "inputTokens": 14500,
    "cachedInputTokens": 9000,
    "outputTokens": 3920,
    "reasoningTokens": 2100,
    "totalTokens": 18420,
    "context": { "usedTokens": null, "windowTokens": null },
    "budget": { "usedTokens": null, "limitTokens": 500000 }
  },
  "execution": {
    "configured": true,
    "laneAvailable": true,
    "mode": "supervised-generic",
    "reason": null,
    "runningCount": 1,
    "counts": {
      "queued": 0,
      "running": 1,
      "stopping": 0,
      "succeeded": 2,
      "failed": 0,
      "cancelled": 0,
      "blocked": 0,
      "unknown": 0
    },
    "enforced": [
      "engagement-binding",
      "target-argument-binding",
      "declared-action-label-binding",
      "tool-allowlist",
      "exact-argv",
      "shell-disabled",
      "executable-descriptor-observed-sha256",
      "minimal-environment",
      "private-stdout-stderr",
      "one-shot-claim",
      "declared-bounds-within-receipt"
    ],
    "bestEffort": [
      "authorization-revocation-polling",
      "wall-duration",
      "process-group-termination"
    ],
    "unavailable": [
      "egress-target-restriction",
      "request-count-measurement",
      "request-rate-measurement",
      "tool-concurrency-measurement",
      "token-measurement",
      "daemon-escape-containment",
      "filesystem-isolation",
      "credential-broker",
      "tool-artifact-inventory",
      "known-good-executable-provenance",
      "argv-action-semantics-validation",
      "supervisor-crash-containment",
      "immutable-executable-snapshot"
    ],
    "recent": [
      {
        "runId": "run_fa2e7cb28411c327",
        "manifestId": "manifest_19e1d8aaf346cf69",
        "engagementId": "engagement_d4a90c2f72842d30",
        "status": "running",
        "createdAt": "2026-10-13T11:59:58.000Z",
        "startedAt": "2026-10-13T11:59:59.000Z",
        "finishedAt": null,
        "terminationReason": null,
        "exitCode": null,
        "signal": null
      }
    ]
  },
  "engagements": [
    {
      "id": "engagement_d4a90c2f72842d30",
      "status": "approved",
      "technicalReview": "passed",
      "operatorReceipt": "approved",
      "manifestRequired": true,
      "executionLaneAvailable": true,
      "executionMode": "supervised-generic",
      "executionEligibility": "manifest-required",
      "attestation": {
        "operatorProvenance": "local-unverified",
        "noMistakesReview": "local-unverified"
      },
      "validUntil": "2026-10-14T12:00:00.000Z",
      "maxTokens": 25000
    }
  ],
  "upstreams": [
    {
      "id": "skills-cli",
      "version": "1.7.2",
      "installed": true,
      "integrityState": "receipt-only",
      "ready": false,
      "commit": "13e4063a1cf913f5606d57d42ab83a86f5001e04"
    }
  ]
}
```

Token availability is `exact`, `estimated`, or `unavailable`. When availability is `unavailable`, token counts are `null` even if an input source supplied zero placeholders. Context use and bounded-loop budget use are unavailable in v0.1; a configured window or limit may still be shown. `telemetry.lastActivityAt` describes observed source activity, while `at` is only the time the snapshot was generated.

The Active execution panel separates configuration from supervisor-lane availability. An available lane means the local Linux supervisor prerequisites and the complete reviewed capability taxonomy are present. It does not authorize a project, engagement, target, action, tool, destination, or command. Every launch still requires a fresh, approved, digest-bound one-shot manifest for a host engagement whose receipt approves `gate-home`, because raw evidence always lands there. Running and stopping counts come from durable run records; they do not independently prove that a process is alive. Best-effort and unavailable controls remain visible beside enforced controls so the panel does not imply sandboxing, egress restriction, request metering, known-good executable provenance, immutable executable bytes, or containment after the supervisor itself crashes. `executable-descriptor-observed-sha256` means bytes were read through the opened descriptor; a same-UID writer can mutate a writable inode before or during exec, so this does not prove atomically frozen or launched bytes. A cancelled run with termination reason `process-group-remained` records that the leader exited while a same-session process-group descendant remained and the supervisor terminated and drained the group. If authenticated group identity is lost during teardown, status is `unknown` with termination reason `supervision-lost` rather than a termination claim.

The Offline analysis panel keeps zero-network artifact inspection visible without exposing artifact identities. It shows lifecycle totals and recent run pseudonyms with status and isolation state only. Retention health includes quotas and aggregate counts for missing, invalid, orphaned, purge-pending, and unknown records. Control health includes mutation availability, retention-lock and snapshot state, pending or invalid transactions, creation activity, invalid creation, claim, purge, and run records, and blocked manifests. An invalid or indeterminate lock, an indeterminate or mutation-active snapshot, or invalid global transaction or creation controls displays `Mutation blocked`; manifest-scoped invalid claim, purge, or run records display `Needs attention`. Missing or incomplete health telemetry stays `Unknown`. Artifact paths, hashes, manifest digests, evidence, output, confirmations, process identities, and control-record contents never cross the observer boundary.

### `GET /api/events`

```json
{
  "apiVersion": "gate.observer/v1",
  "at": "2026-10-13T12:00:00.000Z",
  "events": [
    {
      "id": "evt_20261013_abcdef12",
      "at": "2026-10-13T11:59:58.000Z",
      "runId": "run_fa2e7cb28411c327",
      "taskId": "task_19e1d8aaf346cf69",
      "component": "gate-observer",
      "agent": "member_7ac8c8807523d98f",
      "kind": "test.completed",
      "status": "succeeded",
      "effect": { "class": "local-read" },
      "action": {
        "category": "test",
        "toolName": "gate-observer",
        "durationMs": null,
        "exitCode": null
      }
    }
  ]
}
```

The event projection retains its event ID, time, process-scoped run/task/member pseudonyms, public component label, kind, status, effect class, and a small action summary. It removes canonical event `summary`, raw run/task/member identifiers, effect targets and authorization bindings, evidence references, usage references, and unknown fields. When status has no agent records, the browser can derive display cards from these reduced events.

### `GET /api/learnings`

```json
{
  "apiVersion": "gate.observer/v1",
  "at": "2026-10-13T12:00:00.000Z",
  "learnings": [
    {
      "id": "lrn_20261013_abcdef12",
      "at": "2026-10-13T11:55:00.000Z",
      "scope": "repository",
      "cause": "A cumulative counter appeared after reconnect.",
      "change": "Reconcile the counter baseline before recording a delta.",
      "status": "active",
      "sensitivity": "public",
      "supersedes": null,
      "evidenceCount": 1,
      "configurationCount": 1
    }
  ]
}
```

Learning `cause` and `change` are the only prose fields in the projection. Private records use fixed withheld text. The server and browser redact common URL, absolute-path, credential, and authorization forms; evidence values and configuration paths are represented only as counts.

## Failure and privacy behavior

The browser fetches the three API endpoints independently every two seconds. A valid empty `events` or `learnings` array clears that view. A failed or malformed endpoint preserves the last valid collection and marks the connection partial; it never replaces known history with an empty fallback from another endpoint. If the server cannot build a new snapshot, it serves the last snapshot with stale telemetry when one exists, or returns a generic `503` before the first valid snapshot.

The observer must never include prompt or response bodies, chat titles, task descriptions, tool arguments or results, commands, shell output, executable paths, process identities, absolute paths, target selectors, target URLs, packet data, evidence references or contents, manifest digests, credentials, or session JSONL records. Session, run, manifest, task, member, project, and engagement identifiers use a keyed HMAC with an ephemeral per-process key in HTTP projections. They cannot be matched with an offline dictionary of low-entropy names and intentionally change after an observer restart. Dynamic values are inserted with `textContent`; the dashboard has no third-party assets, analytics, outbound requests, or state-changing controls.

## Keyboard use

- `1` focuses agents and tasks.
- `2` focuses activity.
- `3` focuses Active execution.
- `4` focuses resource posture.
- `5` focuses learning.
- `6` focuses Offline analysis.
- `/` focuses the safe metadata filter.
- `R` refreshes all endpoints.
- `P` pauses or resumes polling.
- `?` opens the shortcut reference.

Run the focused dashboard and observer tests with:

```bash
node --test dashboard/app.test.js dashboard/model.test.js test/observer.test.mjs
```
