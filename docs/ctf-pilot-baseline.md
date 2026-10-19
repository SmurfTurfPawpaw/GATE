# CTF pilot baseline

The first CTF pilot measures three independent outcomes:

1. **Solving** uses `pass`, `provisional`, `fail`, `blocked`, or `unknown`. Its separate `now` field records the current operational step, while objective counts, bounded depth counts, and measured resource use explain the verdict.
2. **Learning** uses the same verdicts plus `not-applicable`. Its separate stages count observations, candidates, validations, applications, transfers to a distinct task, and regressions. A lesson counts as applied only after the workflow changed, and counts as transferred only after that change helps a distinct task.
3. **Cockpit** uses `pass`, `provisional`, `fail`, `blocked`, or `unknown`. Its separate `now` field records collection state, while signal coverage and missed or published update counts explain the verdict.

GATE does not combine these verdicts into one score. After the first flag, for example, Solving can be **PASS** while Learning remains **PROVISIONAL** until a validated adjustment transfers to another challenge. A strong cockpit cannot turn an unsolved challenge into a pass.

`unknown` means the case worker has a current axis record but cannot support a verdict. `unavailable` is transport or measurement state and carries a `null` verdict; it is never another verdict value. Learning uses `not-applicable` only when the run has no reusable adjustment to evaluate. A transferred count measures distinct applied lessons that later helped a distinct task, so it cannot exceed the applied count. It does not count every reuse event.

The case worker evaluates each verdict from private execution evidence. The public cockpit does not calculate, raise, or combine verdicts from the visible counters; those counters are a bounded explanation rather than the complete evidence record.

The verdicts also have mechanical ceilings. Solving can be `pass` only when the plan is complete, every measured objective is complete, no action remains, reproduction is confirmed or not applicable, and external acceptance is accepted or not applicable. Learning can be `pass` only when at least one audited transfer receipt exists; a run with no reusable adjustment uses `not-applicable`. Cockpit can be `pass` only when its feed is current, every signal is present, no update was missed, and no action remains.

## Private state

Each case may publish one owner-only state document at:

```text
GATE_HOME/cases/CASE_ID/state/ctf-pilot/state.json
```

The document must validate against `schemas/ctf-pilot-state.schema.json` and its `metadata.caseId` must match the case directory. `metadata.validUntil` is at most 180 seconds after `metadata.updatedAt`; reaching that deadline makes the scorecard unavailable. A campaign worker also binds the state to its private campaign and worker generation. A dead, released, mismatched, or unverifiable worker lease downgrades that state instead of leaving a stale success visible. GATE reads at most 64 KiB from a regular, owner-only file. A missing, expired, malformed, contradictory, relabelled, linked, oversized, or unavailable-worker document is unavailable.

The selected case worker can inspect the bounded state without exposing case identifiers:

```sh
gate --case CASE_ID ctf pilot status --json
```

To publish an update, the case worker writes a complete schema-valid document to a private `0600` regular file inside the selected case state directory, then runs:

```sh
gate --case CASE_ID ctf pilot update --file PRIVATE_FILE --json
```

The update command rejects symlinks, wrong owners or modes, cross-case metadata, stale or skipped revisions, equal or backwards timestamps, contradictory counters, and input larger than 64 KiB. One owner-only kernel lock covers read, compare, and atomic publication, so concurrent axis publishers cannot overwrite a newer update. It returns the same identifier-free status projection. The operator-facing workflow never asks the operator to author JSON; a case worker or reviewed local controller generates the private update file from execution events.

Learning transfers are separate owner-only receipts under the same case state directory. Each receipt binds the current learning digest, one applied change, validation evidence, and a distinct destination-task digest or pseudonym. GATE deduplicates both the destination task and applied learning before advancing the receipt-derived transferred count. The observer receives the count only; no digest, evidence reference, task identity, or path crosses the boundary.

Every measured value has its own availability marker. Producers write `null` with `unavailable`; they do not substitute zero. Zero is reserved for a measured zero.

## Cockpit boundary

The observer and remote bridge expose only allowlisted categorical verdicts, plan stages, actions, depth levels, counts, timestamps, and resource-use totals. They omit the challenge identity, target, flag, evidence references or digests, hypotheses, prompts, commands, cookies, and filesystem paths. An unknown field invalidates the pilot projection instead of being copied through.

The primary cockpit view shows:

- the independent Solving, Learning, and Cockpit verdicts;
- current plan step and action needed, kept separate from those verdicts;
- the fixed plan timeline, feed freshness, and latest bounded case-worker event category, state, and age;
- depth and efficiency measurements;
- learning stage and transfer counts plus cockpit signal state;
- integrity checks.

The operator conversation is a secondary channel for the dedicated cockpit runner. It is not a mirror of another Codex or cloud chat. Case worker state and case worker events are the source of pilot progress. A single available case is selected automatically. With multiple cases, the operator chooses an explicit opaque alias. The session-stored choice is bound to a random fleet selection epoch. A companion or runner restart, or any change to the private alias bindings, rotates that epoch and requires selection again, so a recycled alias cannot silently select a different case. The cockpit never falls back to the first case when multiple cases are present.

When no trustworthy fleet reaches the browser, the cockpit uses the neutral **Pilot feed unavailable** state and gives one recovery action:

```sh
npm run dashboard
```

This covers observer, runner, relay, preview, invalid-projection, and state-loss failures without guessing which component failed. The unavailable state never displays zero, idle, or successful progress. Local diagnostics can name a specific component only when they have direct evidence for it.
