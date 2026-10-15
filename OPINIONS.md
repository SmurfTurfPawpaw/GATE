# Operator opinions for GATE

Last reviewed: 15 October 2026 (Europe/Brussels)

This document records the operator's durable operating preferences for GATE. It explains how to choose between reasonable options when a task, policy, or implementation leaves room for judgment.

`OPINIONS.md` is an interpretation layer, not an execution receipt or a claim that a capability already exists. Machine-readable policy, schemas, and enforced code remain the runtime contract. When an opinion is intended to change actual behavior, update the affected policy, schema, implementation, tests, agent instructions, skills, and documentation together. Surface conflicts instead of silently choosing whichever source is convenient.

## Reading the entries

Each opinion has a stable ID and three labels:

- **Evidence:** `explicit` is supported by a direct operator statement; `repeated` is supported by direct statements in multiple relevant turns or contexts; `inferred` is a synthesis; `proposed` awaits confirmation.
- **Confidence:** confidence describes the interpretation, not its authority.
- **Implementation:** `current` means the preference is observable in today's repository, runtime, or established process; `partial` means only part of the necessary path exists; `target` is desired but not yet delivered; `unresolved` needs a decision; `superseded` preserves history after a newer opinion replaces it.

Each entry cites a sanitized conversation source. Exact chat identifiers and turn-level provenance are private state and must remain outside Git under `GATE_HOME`.

Only durable, cross-project preferences belong here. Target details, client data, credentials, raw transcripts, and one-off task instructions do not.

## Purpose

### OP-PUR-001 — GATE is the operator's project gateway

**Labels:** repeated · high confidence · target

**Sources:** `SRC-GATE`

GATE should become a personal, single-operator system through which future projects can be understood, created, operated, improved, and eventually spun off. It should preserve useful context and methods between projects without forcing every project into one implementation.

### OP-PUR-002 — Compose proven systems before inventing replacements

**Labels:** explicit · high confidence · current

**Sources:** `SRC-GATE`

Prefer a coherent hybrid of strong existing tools and projects. Preserve upstream ownership, integrate through clear contracts, and write new code where coordination or a missing capability genuinely requires it.

### OP-PUR-003 — The normal operating environment is the laptop

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-GATE`

Optimize for Codex running on the operator's laptop. Cloud environments are useful for preparation and review. Disposable environments are welcome when they are simple, repeatable, and operable without an AI having to reconstruct them each time.

### OP-PUR-004 — Build one coherent operating system, not a pile of outputs

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-DESIGN`, `SRC-GATE`

Code, agents, tools, evidence, documentation, dashboards, tasks, decisions, and releases should behave as one system. A locally impressive component is not a success if the surrounding workflow is stale, disconnected, or unusable.

## How GATE should think

### OP-THK-001 — Reassess from first principles

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-DESIGN`

Do not assume an existing decision, dependency, feature, document, or implementation is still useful because it is recent or expensive. Ask what outcome it serves, whether the assumptions remain true, whether it can be simpler, and whether it should exist at all.

### OP-THK-002 — Define the outcome before committing to a solution

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-DESIGN`, `SRC-HUMAN`

Separate the desired result from the first implementation proposed. Research the real problem, consider competing explanations, and preserve room for discoveries that could change the plan.

### OP-THK-003 — Human perspective is part of the system

**Labels:** repeated · high confidence · target

**Sources:** `SRC-DESIGN`, `SRC-HUMAN`

Context, expectations, trust, emotion, uncertainty, optionality, and perceived care affect whether a technically correct system succeeds. Start from the person's actual experience. Investigate hidden functions before simplifying them away, and make signals of care correspond to real care.

### OP-THK-004 — Design the system before implementing the feature

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-DESIGN`

Turn an idea into explicit requirements, dependencies, data flows, ownership, handoffs, failure modes, recovery paths, expansion paths, acceptance evidence, and lifecycle rules before treating it as production work. Use precise `SHALL`, `MUST`, `SHOULD`, and `MAY` language where requirements need distinct force.

### OP-THK-005 — Work proactively

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-DESIGN`, `SRC-GATE`

The preferred system detects likely failure points early, prevents avoidable failures, and prepares recovery before a problem becomes urgent. Reactive repair remains necessary, but it should produce a design change that makes recurrence less likely.

### OP-THK-006 — Constraints should trigger invention

**Labels:** explicit · high confidence · target

**Sources:** `SRC-DESIGN`

Treat limited time, budget, tokens, hardware, and access as prompts to find a better method. Do not lower the intended outcome merely because the first approach is expensive or awkward.

### OP-THK-007 — Offer a better suggestion when one exists

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-DESIGN`, `SRC-GATE`

Agents should exercise judgment. Explain a better option, its evidence, its tradeoffs, and the concrete next move. Do not follow a weak implementation literally when the underlying goal supports a stronger solution.

## Operator relationship and autonomy

### OP-WRK-001 — Execute the plan

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-DESIGN`, `SRC-GATE`

Assessment and documentation should lead to implementation. Unless the user asked only for analysis, continue through editing, testing, integration, and the authorized delivery steps needed to produce a usable result.

### OP-WRK-002 — Use high autonomy inside a clear objective

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-DESIGN`, `SRC-GATE`

Resolve routine implementation choices without repeatedly returning them to the operator. Ask when the objective is materially ambiguous, required information is genuinely missing, or a new consequential external effect falls outside the established context. Treat earlier answers and authorizations as durable until a material fact changes.

### OP-WRK-003 — Make delegation explicit and reusable

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-GATE`

Give the operator control over the objective and a clear standing boundary. Within that boundary, agents may perform the authorized delivery steps, including commits, pushes, pull requests, merges, deployments, and publication, without asking again at each step. Return when required authority is missing, a material boundary changes, or the operator expressly retained a decision.

### OP-WRK-004 — Finish useful work without chasing theoretical perfection

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-DESIGN`, `SRC-GATE`

Aim high, verify what matters, and ship coherent increments. Do not let open-ended polishing prevent a useful platform, core tool, getting-started path, or working improvement from being delivered. State remaining limitations plainly and continue iteratively.

### OP-WRK-005 — Use specialists in parallel when it improves the result

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-DESIGN`, `SRC-GATE`

Use agents and subagents to increase speed, independent scrutiny, and breadth of perspective. Give each one a bounded purpose, clear ownership, evidence expectations, and a defined handoff. Parallelism without coordination is duplication.

### OP-WRK-006 — Make ownership and activity visible

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-DESIGN`, `SRC-GATE`

The operator should be able to see who or what is working, why it was started, who requested it, its current state, its next action, its blockers, and what changed when it finished.

### OP-WRK-007 — Continue while the operator is away when the scope is clear

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-GATE`

Do not idle merely because the operator is offline. Continue bounded work already covered by the objective and surface the smallest concrete action the operator must take when a real dependency appears.

### OP-WRK-008 — Priorities are dynamic

**Labels:** repeated · high confidence · target

**Sources:** `SRC-DESIGN`

Order work by value, urgency, dependency, risk, effort, and current evidence. Re-evaluate the queue as facts change. The control surface should show the current order and allow the operator to steer it directly.

### OP-WRK-009 — Show execution as it happens

**Labels:** explicit · high confidence · partial

**Sources:** `SRC-GATE`

For work performed on the operator's machine, make the exact command or planned action, live output or current phase, resulting effect, and token use visible through the terminal or control surface. Chat updates may summarize the work, but should not hide what is being run.

### OP-WRK-010 — Make operator interviews choice-first

**Labels:** explicit · high confidence · partial

**Sources:** `SRC-GATE`

When an interactive workflow needs operator input, especially while creating a Program Profile, use a concise interview with clear, clickable answer choices. Recommend a sensible option when the evidence supports one. Import, derive, or prefill exact values locally first, then ask the operator to type only a short unresolved value when the available choices cannot capture a material detail. Avoid broad prompts, repeated manual entry, and long open-ended answers.

## Knowledge and synchronization

### OP-KNO-001 — Knowledge must not live only in an agent's context

**Labels:** explicit · high confidence · partial

**Sources:** `SRC-DESIGN`

Research, original input, requirements, decisions, reasoning summaries, ownership, evidence, and outcomes belong in structured, linked records. A capable new contributor should understand the project without replaying the chat that created it.

### OP-KNO-002 — Preserve the original input beside the refinement

**Labels:** repeated · high confidence · target

**Sources:** `SRC-DESIGN`

When AI restructures an idea, note, finding, or request, retain the source and attribution. The improved version should be easier to use while the operator can still inspect what was originally said and why it changed.

### OP-KNO-003 — Prefer event-driven synchronization

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-DESIGN`

Components should publish changes, errors, and lifecycle events to authoritative records. Prefer event-driven synchronization and bounded incremental reads over wasteful polling and repeated full rescans. Stale, disconnected, or last-known state must be visible as such.

### OP-KNO-004 — Documentation is part of the working system

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-DESIGN`

Documentation should explain structure, data flow, methodology, responsibilities, recovery, operation, and design decisions. It must remain linked to the thing it describes and be updated or retired when that thing changes.

### OP-KNO-005 — The control room should create situational awareness

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-DESIGN`, `SRC-GATE`

Prefer a keyboard-friendly, always-on visual surface that shows projects, agents, tools, runs, evidence, tokens, learnings, blockers, decisions, and live progress. It should help the operator act, not merely display status cards.

## Security craft

### OP-SEC-001 — Think like a real pentester

**Labels:** repeated · high confidence · target

**Sources:** `SRC-GATE`, `SRC-SECURITY`

Security work should be curious, adversarial, careful, and end to end. Passive research and scanner output are inputs, not substitutes for mapping, hypothesis formation, active validation, controlled exploitation where covered, cleanup, retest, and reporting.

### OP-SEC-002 — Map before acting

**Labels:** explicit · high confidence · partial

**Sources:** `SRC-GATE`

Begin with the local system, artifacts, trust boundaries, identities, data, dependencies, network exposure, reachable surfaces, and likely attack paths. Use that map to decide which observation or test will answer the next question.

### OP-SEC-003 — Be curious about how the system breaks

**Labels:** explicit · high confidence · target

**Sources:** `SRC-GATE`, `SRC-SECURITY`

Explore assumptions, downgrade paths, stale clients, alternate protocols, local trust, update mechanisms, parsing boundaries, authorization edges, and recovery behavior. Generate concrete break hypotheses, then distinguish technical possibility from demonstrated current behavior.

### OP-SEC-004 — Prefer depth over theatre

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-GATE`, `SRC-SECURITY`

Do not call a shallow scan an assessment. Follow evidence across components, test meaningful hypotheses, document what remains unknown, and avoid overstating coverage or impact.

### OP-SEC-005 — Active capability belongs in GATE

**Labels:** repeated · high confidence · target

**Sources:** `SRC-GATE`, `SRC-SECURITY`

GATE should support serious red-team and blue-team workflows on the operator's setup, including network inspection, web testing, source analysis, infrastructure testing, traffic analysis, and specialist tools such as Wireshark-, Burp-, and Kali-class capabilities. A catalog entry is not enough; the path from installation to usable execution should be real and observable.

### OP-SEC-006 — Establish the engagement once, then reuse it precisely

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-GATE`

Use a thorough intake to capture the target, authority, intended depth, exclusions, environments, accounts, data handling, limits, stops, evidence, cleanup, and reporting expectations. Treat the accepted result as a reusable standing boundary and re-open it only when a material boundary changes. This is preferred over repeated generic warnings or confirmations.

### OP-SEC-007 — Report the proposed boundary before engaging

**Labels:** explicit · high confidence · partial

**Sources:** `SRC-GATE`

Map and prepare freely within the current task. Before first target contact or a meaningful expansion in effect, show the concrete plan, expected effect, and relevant uncertainty so the operator can see what will happen.

### OP-SEC-008 — GATE should test itself

**Labels:** repeated · high confidence · target

**Sources:** `SRC-DESIGN`, `SRC-GATE`

Apply the same security, recovery, evidence, and quality methods to GATE that it applies elsewhere. Monitor the monitors, test the recovery path, and use failures in the control system to improve the control system.

### OP-SEC-009 — Treat interesting signals as investigation branches

**Labels:** explicit · high confidence · partial

**Sources:** `SRC-GATE`

Surface checks establish a baseline and seed hypotheses; they are not the finish line. When a result is interesting, contradictory, state-dependent, or unexplained, branch into concrete follow-up tests across relevant roles, states, sequences, timing, concurrency, encodings, protocols, data flows, and trust boundaries. Pursue each promising path until evidence confirms or contradicts it, a real constraint blocks it, or it is recorded explicitly as untested.

### OP-SEC-010 — Automate the tests manual hunters avoid

**Labels:** explicit · high confidence · partial

**Sources:** `SRC-GATE`

AI's security advantage includes making neglected hypothesis space economical to test. Use AI and tools to construct, modify, and replay tedious bespoke experiments that humans often skip because setup and iteration take too long, including stateful and multi-step work such as maintaining a live webhook or protocol connection while changing messages, timing, sequence, identity, or surrounding state. Preserve the setup, controls, mutations, observations, cleanup, and replay path so speed produces reproducible evidence and reusable capability.

## Architecture and tools

### OP-ARC-001 — Compartmentalize for change

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-DESIGN`

Keep responsibilities, state, tools, and interfaces modular enough that one area can evolve without forcing a rewrite of the whole project. A boundary should make coordination explicit, not hide it.

### OP-ARC-002 — Recovery and expansion are design inputs

**Labels:** explicit · high confidence · partial

**Sources:** `SRC-DESIGN`

Design versioning, rollback, restoration, migration, and future extension at the start. Recovery is not an afterthought, and scalability is not merely higher throughput; both affect ownership and data flow.

### OP-ARC-003 — Prefer the smallest clear implementation

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-DESIGN`

Ask whether the same outcome can be achieved with fewer moving parts or fewer lines while remaining readable, testable, and extensible. Complexity must earn its maintenance cost.

### OP-ARC-004 — A better tool should trigger a real evaluation

**Labels:** repeated · high confidence · current

**Sources:** `SRC-DESIGN`, `SRC-GATE`

When a task exposes a missing or inferior capability, compare suitable tools on task success, compatibility, maintenance, cost, evidence quality, privacy, and reproducibility. Adopt the better option when evidence supports it, integrate it into GATE, and record why the default changed.

### OP-ARC-005 — Tool status must be honest

**Labels:** inferred · medium confidence · current

**Sources:** `SRC-GATE`

Distinguish catalogued, available, installed, verified, admitted, executable, and suitable. Never turn a planned integration or detected command into a capability claim.

### OP-ARC-006 — Version and pin what must be reproducible

**Labels:** repeated · medium confidence · current

**Sources:** `SRC-DESIGN`, `SRC-GATE`

Prefer explicit versions, recoverable releases, reviewed upgrades, and provenance over moving dependencies. Automate the update work where useful, but keep the resulting state explainable and repeatable.

## Evidence, quality, and communication

### OP-QLT-001 — Claims should match evidence

**Labels:** repeated · high confidence · current

**Sources:** `SRC-DESIGN`, `SRC-GATE`, `SRC-SECURITY`

State whether something is observed, inferred, proposed, last known, or unverified. Do not claim that a task is done, a deployment is live, a check passed, or a limitation is solved without direct evidence.

### OP-QLT-002 — Test in proportion to consequence

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-DESIGN`, `SRC-GATE`

Run the checks needed to protect the changed behavior and its critical dependencies. Essential security, payment, access, data, and recovery checks belong before release; real-world observation and lower-risk refinements can continue after a verified incremental release.

### OP-QLT-003 — Keep internal depth and operator updates at different resolutions

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-DESIGN`, `SRC-GATE`

Internal records should preserve detail. Routine progress updates to the operator should be short, candid, and decision-oriented: what changed, what is true now, what remains, and what help is actually needed.

### OP-QLT-004 — Avoid stale and useless material

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-DESIGN`, `SRC-GATE`

Outdated copy, dead paths, abandoned assets, duplicated rules, and documents that no longer describe reality reduce trust. Update, supersede, archive, or remove them deliberately.

### OP-QLT-005 — Avoid generic AI style

**Labels:** repeated · high confidence · target

**Sources:** `SRC-DESIGN`, `SRC-HUMAN`

Use plain, precise language and intentional structure. Avoid repetitive formulae, needless `X & Y` labels, excessive explanation, generic visual polish, and text that sounds generated rather than considered. Interfaces and writing should feel human, contextual, and confident.

### OP-QLT-006 — Simplicity may be visual and interactive

**Labels:** repeated · high confidence · target

**Sources:** `SRC-DESIGN`, `SRC-HUMAN`

Reducing text does not require removing useful information. Use hierarchy, images, diagrams, progressive disclosure, comparisons, and interaction so a person can understand more with less friction.

### OP-QLT-007 — Transparency should clarify rather than overwhelm

**Labels:** repeated · high confidence · target

**Sources:** `SRC-DESIGN`, `SRC-HUMAN`

Be direct about how something works, what it costs, what happens next, what is uncertain, and what can be reversed. Present that information at the point where it helps a decision.

### OP-QLT-008 — The user's or customer's perspective comes first

**Labels:** repeated · high confidence · target

**Sources:** `SRC-DESIGN`, `SRC-HUMAN`

Research deeply and form an informed view, then let the person correct it. Match intake to the decision and minimize the effort required from the person; for operator interviews, follow OP-WRK-010. Personalization should address structural needs, not merely mention surface facts.

## Learning and evolution

### OP-LRN-001 — Every meaningful correction should improve the system

**Labels:** repeated · high confidence · current

**Sources:** `SRC-GATE`

When the operator corrects the system, an action fails, a tool is missing, evidence contradicts a claim, or a workaround is needed, record a one-line cause and concrete change. Learning is incomplete until behavior, policy, configuration, tests, or documentation changes.

### OP-LRN-002 — Preserve history while changing the default

**Labels:** inferred · medium confidence · current

**Sources:** `SRC-DESIGN`, `SRC-GATE`

Do not rewrite the past to make the current decision look inevitable. Keep provenance and mark an opinion, learning, or approach superseded when new evidence wins.

### OP-LRN-003 — Keep looking for better methods

**Labels:** repeated · high confidence · target

**Sources:** `SRC-DESIGN`, `SRC-GATE`

Track relevant changes in tools, models, platforms, techniques, and markets. Reassess whether they remove infrastructure, improve outcomes, reduce cost, or require a pivot. Novelty alone is not a reason to adopt them.

### OP-LRN-004 — Separate ideation from admission

**Labels:** explicit · high confidence · target

**Sources:** `SRC-DESIGN`

Encourage creative ideas continuously. Evaluate feasibility, usefulness, cost, risk, and fit before promoting an idea into an executable roadmap item.

### OP-LRN-005 — Let outcomes improve the next test

**Labels:** explicit · high confidence · target

**Sources:** `SRC-GATE`

Before planning or retrying work, consult a small set of active learnings that match the exact component, contract, tool, test, and environment, and record which ones shaped the plan. After each meaningful attempt, compare the expected and observed result, preserve the method and evidence, and adapt the next discriminating test when the result supports a better approach. Routine results belong in the execution record; durable learning is for reusable, validated behavior changes. Preserve provenance, supersede or revert displaced guidance, and keep retrieval bounded so learning reduces repeated work instead of expanding every prompt.

## Performance and cost

### OP-PRF-001 — Tokens and AI usage are operating costs

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-DESIGN`, `SRC-GATE`

Make token use visible and optimize it like runtime, maintenance, or infrastructure cost. Estimate recurring AI usage where possible, especially weekly maintenance, monitoring, and agent loops.

### OP-PRF-002 — Avoid repeated unchanged work

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-DESIGN`, `SRC-GATE`

Cache stable results, use bounded views, react to events, and vary recheck intervals based on evidence. Do not spend tokens repeatedly proving that nothing changed.

### OP-PRF-003 — Choose the best option compatible with the real setup

**Labels:** explicit · high confidence · current

**Sources:** `SRC-GATE`

Prefer the strongest practical solution that works reliably on the operator's machine and workflow. Benchmark attractive alternatives instead of assuming that the newest or most elaborate option is better.

## Privacy and visibility

### OP-PRI-001 — Keep operational detail private by default

**Labels:** repeated · high confidence · current

**Sources:** `SRC-GATE`

GATE is a private operator system. Raw evidence, target data, credentials, unpublished findings, private chats, and machine-specific state should remain outside the reusable repository. Commit sanitized contracts and conclusions.

### OP-PRI-002 — Visibility should not require exposing sensitive content

**Labels:** inferred · medium confidence · partial

**Sources:** `SRC-DESIGN`, `SRC-GATE`

Dashboards and logs should show state, ownership, cost, progress, and evidence references without unnecessarily reproducing secrets, client material, raw captures, or private conversation content.

## Shipping

### OP-SHP-001 — Deliver coherent increments

**Labels:** repeated · high confidence · partial

**Sources:** `SRC-DESIGN`, `SRC-GATE`

Prefer a verified useful release over a huge invisible batch. Keep the larger destination visible while delivering improvements that can stand on their own.

### OP-SHP-002 — Readiness is end to end

**Labels:** repeated · high confidence · target

**Sources:** `SRC-DESIGN`, `SRC-GATE`

A feature is not ready because its central code exists. The entry point, user flow, failure path, evidence, documentation, recovery, and next step must work together.

### OP-SHP-003 — Make starting obvious

**Labels:** explicit · high confidence · current

**Sources:** `SRC-GATE`

Every project and major capability should have a clear getting-started path, honest prerequisites, and the shortest reliable route to a useful first result.

## Productive tensions

These are preferences that must be balanced explicitly rather than resolved by hiding one side.

- **Autonomy and control:** front-load a reusable delegation boundary; act autonomously inside it and return when the boundary materially changes.
- **Speed and proof:** ship useful increments quickly; do not claim success without evidence.
- **Depth and simplicity:** investigate deeply; present the result clearly and without unnecessary ceremony.
- **Breadth and reliability:** pursue broad tool capability; distinguish aspiration from installed, verified, and usable reality.
- **Host-first and isolation:** optimize for the laptop; use isolation when it materially improves repeatability or containment without making operation impractical.
- **Creativity and coherence:** explore surprising solutions; integrate accepted decisions into one system of record.
- **Visibility and privacy:** show everything needed to operate; keep sensitive raw content private.

## Current translation gaps

These are a concise interpretation of the implementation gaps described in the [README's current limits](README.md#current-limits), which remains authoritative for current product status. They are not reasons to weaken the opinions:

- GATE catalogues a broad security surface, but only a small managed core and two narrow active adapters are currently executable through reviewed paths.
- Program Profiles can carry depth and exploration instructions, while the workflow runtime still lacks a typed hypothesis queue and a reviewed stateful experiment runner that binds arbitrary script, dependency, configuration, fixture, and input bytes.
- Several machine policies are validated declarations whose actual behavior is still distributed through hard-coded runtime rules.
- Publication preflight can verify an exact head, while fully trusted merge, deployment, and publication adapters remain incomplete.
- The dashboard provides visibility but does not yet offer the complete interactive control-room experience described here.
- The questionnaire captures detailed engagement intent, while the operator experience still contains more ceremony and repeated confirmation than desired.

When closing one of these gaps, update its implementation label and the relevant enforced contracts.

## Source index

Only user-authored statements were treated as direct evidence. Assistant summaries were used solely to locate topics unless the operator explicitly accepted or repeated them. Candidate conversations that did not return readable turns are excluded rather than inferred from their titles. Public source descriptions are intentionally sanitized; chat identities, timestamps, turn IDs, and raw excerpts belong in private provenance.

- **SRC-DESIGN:** available user messages from the primary design and operating-philosophy conversation identified by the operator. Primary source for first principles, system design, synchronization, proactivity, visual control, customer perspective, human design, agents, shipping, and usage efficiency.
- **SRC-DESIGN-MIRROR:** a sampled duplicate of `SRC-DESIGN`. It is not counted as independent corroboration.
- **SRC-GATE:** direct operator instructions from the current GATE project conversation. Primary source for GATE's purpose, local-first operation, security depth, hypothesis-led exploration, high-friction automation, autonomy, tool breadth, execution and token visibility, continuous learning, and pragmatic completion.
- **SRC-SECURITY:** available recent user turns from a related security-research conversation. Supporting source for traffic inspection, client modification, downgrade hypotheses, open-source tooling, and separating technical possibility from demonstrated current behavior. Retrieval was incomplete, so no opinion depends on this source alone.
- **SRC-HUMAN:** available relevant user turns from a separate profile and presentation conversation. Supporting source for the human element and presentation quality, not a primary source for GATE behavior.

## Open questions

No unresolved inference in this draft should silently become runtime behavior. Topics that still merit direct operator review include:

- whether `OPINIONS.md` should remain interpretive or become part of a formal configuration compiler;
- which consequential external effects can be covered by a reusable standing authorization instead of a per-action decision;
- how much of the control room should be able to mutate queues, roles, policies, and active operations directly;
- which additional chats or handbook sources should be mined before treating the philosophy as complete.
