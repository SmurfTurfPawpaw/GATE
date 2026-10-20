# Campaign acceptance and GATE improvement

Every real program campaign also exercises GATE itself. Target-specific Program
Profiles live in GATE's shared private profile registry. Campaign execution
observations and evidence stay inside the selected case, while only generalized
and independently validated workflow changes may enter the repository.

## Parallel campaign contract

Run each program through its own target-specific Program Profile in the shared
private registry and bind its exact digest into an immutable case. The profile
is not stored in that case. Its campaign execution observations, workflow
journal, token records, engagement, execution records, evidence, and private
learning must be case-bound. Keep `GATE_CASE` set in every campaign terminal or
prefix each case-owned command with `--case ID`; an unscoped campaign event or
learning write is an acceptance failure because the CLI still permits base-state
writes. Never use one campaign's profile or case-bound state as input to another
campaign. Shared tool runtimes and repository code may be reused only through
their existing reviewed contracts.

The observer may compare allowlisted lifecycle metadata, such as stage,
freshness, counts, categorical state, and resource availability. It must not
compare or merge targets, answers, commands, raw output, evidence, findings,
authorization material, or private learning prose.

## Acceptance matrix

Use at least two simultaneous campaigns to exercise these paths:

| Area | Evidence of success | Failure signal |
| --- | --- | --- |
| Profile intake | Each draft advances independently and reports truthful aggregate progress. | A draft is invisible, misattributed, or exposes a private answer. |
| Case isolation | Each intended campaign case is created explicitly from one ready profile and has a distinct state root and current binding. | A case is missing, unexpectedly duplicated, or shares state, activity, usage, or learning across a boundary. |
| Fleet clarity | Case rows show state, current work, freshness, attention, usage availability, and a case-backed learning count. Setup-only rows show learning as unavailable and show recommendation mode only when a reviewed producer supplies it. | An operator cannot identify what is active or needs attention, or a setup-only row implies case-backed data. |
| Recent activity | Selecting one campaign shows only its structured lifecycle feed and an honest progress state. | The UI invents a percentage, displays raw terminal data, or loses selection during refresh. |
| Runtime readiness | Required pinned tools report their observed local state and unresolved constraints. | Catalog presence is presented as installed, verified, or authorized. |
| Adaptive testing | Every meaningful attempt has a plan, result, review, and explicit next adaptation. | A retry repeats silently or a running plan changes after a learning update. |
| Resource accounting | Available token, request, time, evidence, and spend records retain their case attribution and availability labels. | Missing telemetry is rendered as zero or host usage is divided among cases. |
| Recovery | Stops, failures, stale bindings, incomplete scans, and unavailable controls remain visible. | A partial view is presented as complete or a failed operation disappears. |

## From campaign friction to a GATE change

1. Preserve the campaign event, attempt review, and evidence reference under
   that case's private state.
2. Record a private cause-and-change learning candidate when a correction,
   retry, workaround, missing capability, misleading display, or environment
   constraint changes reusable behavior.
3. Remove target, client, account, selector, evidence, path, and unpublished
   finding details before considering repository scope.
4. Reproduce the generalized problem with a fixture or a second applicable
   case. Similar metadata categories may be compared; private campaign content
   may not be copied between cases.
5. Implement the smallest reusable code, contract, test, or documentation
   change. A learning is incomplete until behavior changes.
6. Validate the change and pass the immutable No Mistakes handoff. Promote a
   sanitized learning only when its candidate digest and implementation Git
   head are bound to that review.
7. Apply the promoted lesson only to a later explicit plan. Never hot-reload a
   running assessment or use a learning to expand scope or authority.

The cockpit may show aggregate attempt, adaptation, candidate, and promotion
counts. It must not attribute shared learning prose to a campaign unless a
reviewed source provides that binding. Until GATE has a canonical structured
finding registry, the cockpit reports finding tracking as unavailable rather
than inferring findings from events or evidence.

## Completion

A campaign's security work can continue while a GATE improvement is being
reviewed, provided the campaign remains within its current immutable plan and
authority. A GATE acceptance item is complete only when the behavior is
observable, its isolation and privacy properties are tested, and the result is
landed at the exact reviewed Git head. Campaign completion and GATE acceptance
completion are separate states.
