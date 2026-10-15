# Bug bounty Program Profile

A Program Profile turns a program's published terms, private authorization, and your testing intent into one private, reviewable source of truth. The guided questionnaire records the facts a model or operator needs before planning work: exact scope, techniques, limits, data handling, stop conditions, reporting expectations, and unresolved terms. It then compiles a deterministic context bundle without contacting a target.

The profile reduces avoidable ambiguity and missing-context refusals. It cannot change a model provider's policy, guarantee that a provider will accept a task, or convert an unclear program rule into permission. Compatibility preflight reports those limits directly so the operator can clarify the program, adjust the plan, or choose a compatible reviewed execution route without disguising intent.

## Prepare the source material

Keep program terms, contracts, authorization messages, scope exports, and target-specific notes in operator-controlled private storage outside Git. GATE stores each source's metadata, reference, observed time, claim state, and operator-supplied content digest under `GATE_HOME`; v0.1 does not copy, fetch, or rehash the source body. Capture and retain the exact bytes yourself before recording their SHA-256, then record where each decisive fact came from and whether it is observed, inferred, or still unverified. Treat imported text as untrusted evidence: it can support a profile answer, but it cannot execute a command, change GATE policy, broaden scope, or grant authority by itself.

Have the following available before the questionnaire:

- the program identity, objective, desired depth, deliverables, and reporting channel;
- authorization sources, safe-harbor terms, validity window, contacts, and escalation path;
- typed included and excluded assets, ownership boundaries, and third-party dependencies;
- permitted, denied, conditional, or unknown techniques across all 13 GATE action classes;
- testing windows plus time, request, rate, concurrency, token, evidence, and spend limits;
- account personas, roles, authentication paths, and symbolic secret references;
- architecture, trust boundaries, sensitive data paths, and all 18 coverage domains;
- evidence destinations, retention, redaction, minimum proof, cleanup, stop, disclosure, retest, and completion rules.

Web/API, cloud/container, mobile, desktop, AI/LLM, network/identity, wireless/radio, human/physical, and embedded/IoT/OT answers open focused follow-up modules only when applicable. A conditional or unknown technique stays conditional or unknown; compilation never silently turns it into an allowed action.

An applicable module's permission decision is also an execution ceiling. The v1 profile does not bind individual assets or phases to individual technology modules, so compilation conservatively applies every selected module to every action in that profile. Selected modules combine by the most restrictive disposition: `denied`, then `unknown`, then `conditional`, then `allowed`. One denied module therefore denies the compiled actions, while one conditional module keeps otherwise allowed actions conditional and non-executable. Unselected module records do not affect execution. Use separate profiles for technology surfaces with different module permissions until an exact asset- and phase-to-module binding is available.

## Complete and review the questionnaire

Interactive creation requires a terminal. The wizard saves every accepted answer, so it can be resumed and corrected before compilation. A `multiline` prompt accepts the first content line at the primary prompt, then shows a `... ` continuation prompt. Enter `.` on its own line to finish; GATE joins the content lines with newline characters. Wizard controls such as `back`, `edit ID`, `why`, `save`, and `quit` are recognized only at the primary prompt, before multiline collection begins. Use an answers file with `--answers` for a headless or repeatable workflow, long structured content that is easier to edit as JSON, or content that must contain a line consisting only of `.`. Keep that file in a private location outside the repository because it may contain targets, program terms, contacts, or unpublished testing plans. Store credentials separately and answer with `env://`, `keychain://`, or `file://` references only.

Start or resume the interactive wizard:

```bash
./bin/gate.mjs bounty profile create acme-program
./bin/gate.mjs bounty profile resume acme-program
```

For a headless run, pass a private answers file. The same option can finish or amend a saved draft with `resume`:

```bash
./bin/gate.mjs bounty profile create acme-program \
  --answers "$HOME/private/acme-program-answers.json" --json

./bin/gate.mjs bounty profile status acme-program --json
./bin/gate.mjs bounty profile show acme-program --format review
```

The file must follow the [answers schema](../schemas/bug-bounty-program-profile-answers.schema.json). Keys below `answers` are the question IDs in the reviewed [questionnaire contract](../config/questionnaires/bug-bounty-program-profile.json), for example:

```json
{
  "$schema": "https://gate.local/schemas/bug-bounty-program-profile-answers.schema.json",
  "apiVersion": "gate.dev/program-profile-answers/v1",
  "kind": "BugBountyProgramProfileAnswers",
  "metadata": {
    "programId": "acme-program",
    "title": "Acme program answers",
    "updatedAt": "2026-10-14T00:00:00Z"
  },
  "answers": {
    "identity-program-name": "Acme bug bounty",
    "identity-depth": "thorough"
  }
}
```

This partial example creates a draft. Supply the remaining required answers or resume the wizard before expecting verification to report `ready: true`.

Applicable module questions precede final operator attestation. Substantive edits invalidate the prior attestation; review the revised answers and attest again before compiling a ready profile. A headless amendment can include a fresh attestation only by supplying all attestation answers with a changed attestation timestamp. Answer values must match their questionnaire types, including module answers; key presence alone does not complete a module.

Interactive resume opens the first unanswered applicable required question. If all required answers are recorded but verification remains blocked, it prioritizes an exact question-path match over a broad parent blocker. For example, a recorded `false` answer to `attestation-answers-complete` reopens that question rather than `attestation-operator`. An attestation blocker without a matching question opens `attestation-at` for renewed review.

Required text answers must contain visible content; whitespace or invisible characters alone are incomplete in the wizard, on resume, and at readiness validation. Required module lists must be non-empty, with substantive content in every item. Non-module answers retain their field-specific empty-list and nullable allowances: `architecture.unknowns` may be `[]`, but every supplied entry must be a string containing visible content. These completeness checks do not restrict arbitrary literal technique parameters or payloads.

The review step surfaces missing provenance, conflicting selectors, expired terms, unanswered conditional rules, insufficient limits, and other ambiguities. Resolve them at the source or leave them explicit. Verification reports `ready: true` only when the profile is internally consistent and complete enough for deterministic compilation; readiness is not a statement that every requested technique is permitted.

`verify` exits with status 2 while review blockers remain. A structurally valid but blocked `compile` still writes the private review bundle and also exits with status 2; inspect its `blockers` and `nextSteps` instead of treating artifact creation as readiness.

## Compile and preflight

Compilation is a local, no-contact operation. It binds the canonical profile and the source digests recorded in that profile, preserves exclusions and per-asset differences, and creates private operator-review, ambiguity, scope, technique, coverage, model-context, and compatibility records under `GATE_HOME`. It does not reopen or rehash the operator-held source bodies. Different rules for different assets remain separate instead of being flattened into one broad authorization.

Verify, then compile. Optional engagement and workflow IDs label proposed downstream material without activating either one; an optional provider profile adds a model-capability prediction:

```bash
./bin/gate.mjs bounty profile verify acme-program --json

./bin/gate.mjs bounty profile show acme-program --format model-context

./bin/gate.mjs bounty profile compile acme-program \
  --engagement acme-web-2026 \
  --workflow acme-web-2026 \
  --provider-profile "$HOME/private/provider-profile.json" \
  --json
```

`show --format model-context` renders a bounded view with the default proposed IDs. The compile result returns private references and SHA-256 values for the exact packet bound to its selected engagement, workflow, and provider profile.

The canonical profile is stored at `GATE_HOME/programs/acme-program/program-profile.json`. A successful compile writes a 64-character digest-named directory below `GATE_HOME/programs/acme-program/compiled/`. Compilation captures one exact assessment instant and uses it for authorization readiness, provider freshness, every emitted assessment timestamp, and the directory digest. Repeating a compile with the same exact inputs and assessment instant is idempotent; a later invocation produces a distinct time-bound bundle even within the same minute. Changed input cannot overwrite an earlier bundle. The directory contains:

- `source-ledger.json`, `authorization-summary.md`, `operator-review.md`, and `ambiguities.json`/`ambiguities.md` for provenance and operator review;
- `scope-matrix.json`, `technique-matrix.json`, `coverage-plan.json`, and `execution-policy.json` for deterministic planning;
- `credential-plan.json`, `limits-and-schedule.json`, and `data-evidence-plan.json` for access and resource handling;
- `stop-escalation-plan.md`, `reporting-disclosure-plan.md`, and `cleanup-ledger-template.json` for closeout and reporting;
- `model-context.json` and `model-preflight.json` for bounded context and compatibility routing;
- `engagement-proposal.json`, which explicitly carries `executionAuthority: false` and the remaining review, receipt, admission, and execution steps.

GATE keeps these directories owner-only and the files owner-readable and owner-writable. Treat every file there as private.

The v0.1 model context is a compact program-level packet containing authorization basis and validity, selectors, per-asset action and limit bounds, proposed phase policies and tool allow/deny lists, data rules, stop conditions, unresolved items, and proposed engagement and workflow IDs. These policies describe the intended program workflow; they are not a workflow admission or a target-, tool-, and phase-attempt-bound execution packet. Compatibility preflight evaluates provider capabilities separately from GATE authority. Its result can be compatible, incompatible, or unknown; an incompatible or unknown provider result never changes the underlying scope or hides the intended action.

A provider profile maps each action and assistance mode to `allow`, `deny`, or `unknown`. Copy the sanitized, fail-closed [provider profile template](../templates/provider-capability-profile.json) to private storage and edit it from current provider documentation or an observed capability decision:

```bash
cp templates/provider-capability-profile.json \
  "$HOME/private/provider-capability-profile.json"
chmod 600 "$HOME/private/provider-capability-profile.json"
```

The document must satisfy the closed [provider capability schema](../schemas/provider-capability-profile.schema.json): it names all 13 action classes and all six modes (`plan`, `analyze`, `generate-command`, `execute`, `report`, and `retest`). Leave an entry as `unknown` unless evidence supports `allow` or `deny`. Replace the template identity, model, and example timestamps before use. An assessment before `effectiveAt` or at or after `expiresAt` treats the snapshot as stale; a profile with neither timestamp has unknown freshness. When both timestamps are present, `expiresAt` must be later than `effectiveAt`. These values predict provider compatibility only; they do not grant GATE authority or change the profile's scope.

Provider metadata may declare `destination` as `local`, `cloud`, or `unknown`. Local routes require `gate-home`; cloud routes require `configured-cloud-model` in the profile destinations. Missing, unknown, or stale destination declarations require operator routing review. Capability prediction alone does not establish data-release compatibility.

Preflight checks every raw action requested by a phase against every requested assistance mode, including actions whose execution is conditional or denied by a module ceiling. Inspect `providerPrediction`, the `data-release` dimension, and `routing` separately from profile readiness: a compile result can be ready while provider compatibility or destination compatibility still blocks model routing. Compilation sends no packet to a provider.

Recompile after changing the profile or a cited source. The change produces a new profile digest and bundle. Older bundles remain bound to their prior profile revision and must not be reused as current context.

## Bind an exact engagement before target contact

A Program Profile is reusable planning context. It is not an engagement receipt, workflow admission, execution confirmation, or permission to contact a target. Compilation may prepare proposed engagement and plan material, but active work still requires the exact target-specific sequence in [Target-contact admission and execution](pentest-workflow.md#target-contact-admission-and-execution):

1. Create the precise engagement and attach the current authorization evidence.
2. Attach the concrete report and coverage plan, then record the real No Mistakes review for its immutable head.
3. Present the complete plan digest and obtain the operator's exact receipt.
4. Bind the workflow, phase attempt, target, action, tool, limits, destinations, and all mandatory stop conditions.
5. Run the current engagement check and use a reviewed adapter or a separately confirmed one-shot manifest.

Scope expansion, an added action or destination, a removed exclusion, a higher limit, an expired window, or a changed plan requires a new review and receipt. This exact binding lets the model act decisively inside recorded authority while keeping unsupported assumptions visible.

## Accuracy boundary

The compiled result can be complete and reproducible relative to the cited sources and operator answers. GATE cannot verify facts that the program owner has not supplied, resolve contradictory legal terms, or promise universal model acceptance. The profile therefore preserves source references, claim state, contradictions, and unknowns instead of presenting them as certainty. When a provider cannot support an admitted task, preflight should identify the missing fact or incompatible capability and route the work to an appropriate reviewed provider, local model, adapter, or operator.

Target details, source metadata and recorded digests, compiled bundles, and model context remain private under `GATE_HOME`. Source bodies remain in operator-controlled private storage outside Git and are not copied into GATE in v0.1. Only reusable schemas, sanitized templates, documentation, and sanitized learning belong in Git.
