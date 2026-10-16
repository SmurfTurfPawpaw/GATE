# Bug bounty Program Profile

A Program Profile turns a program's published terms, private authorization, and your testing intent into one private, reviewable source of truth. The guided questionnaire records the facts a model or operator needs before planning work: exact scope, techniques, limits, data handling, stop conditions, reporting expectations, and unresolved terms. It then compiles a deterministic context bundle without contacting a target.

The profile reduces avoidable ambiguity and missing-context refusals. It cannot change a model provider's policy, guarantee that a provider will accept a task, or convert an unclear program rule into permission. Compatibility preflight reports those limits directly so the operator can clarify the program, adjust the plan, or choose a compatible reviewed execution route without disguising intent.

## Prepare the source material

Keep program terms, contracts, authorization messages, scope exports, and target-specific notes in operator-controlled private storage outside Git. GATE stores each source's metadata, reference, observed time, claim state, and operator-supplied content digest under `GATE_HOME`; v0.1 does not copy, fetch, or rehash the source body. Capture and retain the exact bytes yourself before recording their SHA-256, then record where each decisive fact came from and whether it is observed, inferred, or still unverified. Treat imported text as untrusted evidence: it can support a profile answer, but it cannot execute a command, change GATE policy, broaden scope, or grant authority by itself.

Apply [the data policy](../policies/data-handling.json) before putting any source content into a model conversation. Public data is allowed, internal data requires the configured provider, sensitive data requires an explicit release, and secret data is denied. Client material, private case records, unpublished findings, and authentication artifacts are always sensitive. Passwords, API tokens, private keys, session cookies, and recovery codes are always secret. Accessibility on disk or under `GATE_HOME` is not release permission. GATE v0.1 does not generate a model-safe Program Profile projection. For a model-assisted interview, use only structural questionnaire metadata, current-conversation material permitted for the provider, and manually sanitized categorical outcomes from the operator or a reviewed local controller. Keep exact selectors, contacts, source records and bodies, digests, profile identity, private paths, and authentication material in local capture and review surfaces.

Have the following available before the questionnaire:

- the program identity, objective, desired depth, deliverables, success criteria, and reporting channel;
- authorization sources, safe-harbor terms, validity window, contacts, and escalation path;
- typed included and excluded assets, ownership boundaries, and third-party dependencies;
- permitted, denied, conditional, or unknown techniques across all 13 GATE action classes, including any stateful, multi-step, concurrent, timing-sensitive, callback, webhook, role or tenant matrix, or differential test that needs a specific rule;
- testing windows plus time, request, rate, concurrency, token, evidence, and spend limits;
- account personas, roles, authentication paths, and symbolic secret references;
- architecture, trust boundaries, sensitive data paths, and all 18 coverage domains;
- evidence destinations, retention, redaction, minimum proof, cleanup, stop, disclosure, retest, and completion rules.

Web/API, cloud/container, mobile, desktop, AI/LLM, network/identity, wireless/radio, human/physical, and embedded/IoT/OT answers open focused follow-up modules only when applicable. A conditional or unknown technique stays conditional or unknown; compilation never silently turns it into an allowed action.

An applicable module's permission decision is also an execution ceiling. The v1 profile does not bind individual assets or phases to individual technology modules, so compilation conservatively applies every selected module to every action in that profile. Selected modules combine by the most restrictive disposition: `denied`, then `unknown`, then `conditional`, then `allowed`. One denied module therefore denies the compiled actions, while one conditional module keeps otherwise allowed actions conditional and non-executable. Unselected module records do not affect execution. Use separate profiles for technology surfaces with different module permissions until an exact asset- and phase-to-module binding is available.

## Define depth as an evidence-led loop

Surface checks establish a map and generate leads. They do not, by themselves, complete an assessment. Record anomalous, differential, state-dependent, boundary-crossing, or internally inconsistent observations as candidate signals. Turn a promising signal into a testable hypothesis, choose a test that can distinguish the expected outcomes, preserve the result, and either open the next evidence-backed branch or record why the branch is blocked, not applicable, or untested.

AI is especially useful when the security question is straightforward but the experiment is tedious to orchestrate. Prefer a repeatable script, harness, or reviewed tool workflow for permitted tests that require an open callback or webhook connection, several dependent state transitions, precise timing or concurrency, many role or tenant combinations, or a large replay and mutation matrix. Automation removes setup and repetition cost; it does not lower the evidence standard or expand the recorded program boundary.

Use the existing profile fields together:

- `identity.depth` sets the expected effort. `targeted` goes deep on the narrow objective and records relevant deferred branches; `thorough` adds prioritized follow-up to the baseline map; `exhaustive` requires a disposition for relevant hypotheses and high-friction scenarios across applicable coverage.
- `identity.successCriteria` states what signal, hypothesis, workstream, and coverage dispositions are required before completion.
- `techniquePolicy.techniques` records exact rules for named high-friction techniques, while `executionPolicy.phases` binds permitted deeper work to assets, actions, tools, conditions, and tighter limits.
- architecture unknowns, trust boundaries, data flows, identities, and module answers provide the context used to generate hypotheses.

Compilation records these profile-specific values and a depth-aware exploration instruction in `model-context.json` for a future reviewed, sanitized routing path. That instruction tells a compatible routed model to use surface work as the baseline, follow promising evidence, prefer repeatable automation for high-friction tests, and keep untested branches visible. GATE v0.1 does not send this private packet to a model. The later workflow journal remains the record of hypotheses, evidence, phase dispositions, and actual execution.

## Complete and review the questionnaire

### Preferred: Codex-native choice interview

Install and invoke the reviewed [`gate-program-profile` skill](../skills/gate-program-profile/SKILL.md) when Codex is available. Give it only the current-conversation evidence and testing intent permitted for the configured provider, plus manually sanitized categorical outcomes from local review. It derives a source-backed draft and asks only the unresolved decisions through the platform's native choice controls. Questions arrive in batches of one to three with two or three mutually exclusive options; the best-supported recommendation appears first. Multi-select and structured fields are broken into smaller decisions or presented as a sanitized derived summary with focused exception choices. Native questions, options, and free-form replies are model input, so they use only approved categories and opaque slots.

Enter exact program or client names, target selectors, URLs, contacts, source references, private paths, authorization text, and authentication details through the local terminal wizard, a reviewed Lavish interface configured for local-only handling, or another reviewed private local interface. Do not return those literals to Codex through a tool result. Source-first inference remains intact: permitted current-conversation evidence and manually sanitized decision categories support the draft, while private literals fill opaque slots outside model context.

The operator does not need to compose JSON for the sanitized categorical interview. GATE v0.1 provides clickable choices, a local browser wizard for private structured fields, and a numbered terminal fallback. The skill translates accepted non-sensitive decisions into the structure of a private v2 `BugBountyProgramProfileAnswers` envelope, while the local path applies it through `bounty profile create|resume --answers`. The reviewed questionnaire v2 contract records this choice-first and recommendation preference in metadata version 5. Source-derived values remain labeled `observed`, `inferred`, or `unverified`, and unsupported choices remain unknown or explicit blockers rather than guesses.

The choice interface changes how ordinary answers are collected, not what they mean. The same questionnaire, answer schema, verification rules, private storage, operator-confirmed authorization answer, and final attestation requirements apply. A native model choice can continue to local review, request revision, or defer; it cannot serve as either confirmation. After the operator views the exact private review locally, the local controller captures the operator-confirmed authorization answer, operator identity, all attestation answers, and timestamp without returning them to model context. Substantive changes invalidate that attestation and require another exact local review. A choice selection is not an engagement approval or execution confirmation, and the skill makes no target contact.

### Browser wizard and terminal fallback

The normal private-data path is the loopback-only browser wizard:

```bash
unset GATE_CASE
./bin/gate.mjs bounty profile create acme-program --apply-recommended --json
./bin/gate.mjs bounty profile ui acme-program --open
```

The first command initializes a private draft and applies only eligible reviewed preferences; omit it when the profile already exists. The second starts one profile-bound local server, prints its private session URL, optionally opens the browser, and keeps the terminal attached until `Ctrl+C` or `SIGTERM`. It accepts only explicit `127.0.0.1` or `::1` bindings. It edits one local profile through typed controls, including per-asset action and limit overrides, phase limits, and technique parameters. Structured editors preserve unedited fields; advanced JSON remains a fallback. Enter each condition or secret reference on its own line; commas within an entry are preserved. The observer dashboard remains read-only. Interactive CLI creation remains available as a typed fallback. Enum and boolean prompts show numbered choices; multi-enum prompts accept comma-separated numbers or values. At a contact prompt, Enter or `1` hands the same saved profile to the guided loopback form at that contact question, `2` saves and stops, and `A` deliberately enters the advanced JSON path. `skip` moves to the next question without recording a guessed answer and preserves any existing answer. Unanswered required questions remain unresolved and are revisited on resume; optional questions remain unset and can be revisited with `edit QUESTION_ID`. A real supported recommendation remains available through `recommended` or `R`; the navigation recommendation to open the form never pretends to be an answer recommendation. The wizard saves every accepted answer, so it can be resumed and corrected before compilation. A `multiline` prompt accepts the first content line at the primary prompt, then shows a `... ` continuation prompt. Enter `.` on its own line to finish; GATE joins the content lines with newline characters. General wizard controls such as `back`, `edit ID`, `why`, `format`, `recommended`, `apply recommended`, `skip`, `save`, and `quit` are recognized only at the primary prompt, before multiline collection begins; `open ui` is available at contact prompts.

If an already-running terminal does not show the contact choices, enter `quit`, update GATE, and run `./bin/gate.mjs bounty profile resume acme-program` with the existing profile ID. Do not recreate the draft: accepted answers are already saved. At the contact question, Enter opens the guided form. If automatic browser launch is unavailable, open the printed private session URL locally.

### Reviewed recommendations

All 66 core questions and all 36 conditional-module questions declare one validated recommendation policy:

- `operator-preference` contains a reviewed, deterministic GATE preference that may be accepted with `recommended` or `R`;
- `evidence-proposal` needs a separate private proposal. Permission, scope, target-effect limits, coverage, phase policy, and module questions require an `observed` source-derived proposal with current cited sources. Other evidence questions may accept an observed or inferred local proposal;
- `manual-only` never has a recommendation. It applies to `authority-operator-confirmed` and the five final attestation questions.

Initial profile values and `format` examples are never recommendation inputs. An unverified proposal remains unresolved. A missing source, stale questionnaire digest, stale profile revision, stale profile digest, unsupported question, or manual-only proposal cannot be applied. The terminal and browser show the bounded `observed` or `inferred` evidence state before an evidence proposal can be accepted; they do not rely on its free-form summary to communicate confidence. Sensitive-question prompts report only that a private recommendation exists and may show that bounded evidence-state label; they do not print its value or free-form basis.

Apply every currently supported unanswered recommendation in one base-bound update:

```bash
./bin/gate.mjs bounty profile resume acme-program \
  --apply-recommended --json

./bin/gate.mjs bounty profile resume acme-program \
  --recommendations "$HOME/private/acme-program-recommendations.json" \
  --apply-recommended --json
```

To review proposals one at a time, omit `--apply-recommended` and use `recommended` at the selected terminal question, or open the private browser with the same bound envelope:

```bash
./bin/gate.mjs bounty profile resume acme-program \
  --recommendations "$HOME/private/acme-program-recommendations.json"

./bin/gate.mjs bounty profile ui acme-program --open \
  --recommendations "$HOME/private/acme-program-recommendations.json"
```

After any answer edit or accepted proposal changes the profile revision, reload or regenerate the proposal envelope against the new exact base before accepting another evidence proposal. The browser and terminal exclude stale evidence envelopes when applying independent reviewed policy preferences, so those preferences remain available without restarting the session or supplying a new proposal file.

Explicit answers always win. Bulk application recalculates conditional-module applicability as answers are selected, writes at most one new profile revision, and writes no revision when zero recommendations are eligible. Create with `--apply-recommended` validates the unbound proposal before publication and writes the initialized recommended draft in one profile transaction at revision 1. A substantive recommendation update uses the ordinary answer mutation path, so any prior attestation is invalidated. Recommendation selection does not confirm authorization, attest to the profile, create an engagement, or grant execution authority.

Private proposal files follow the [recommendation schema](../schemas/bug-bounty-program-profile-recommendations.schema.json). They bind the program ID, questionnaire ID/version/digest, and exact base profile revision/digest. Each proposal carries an exact value, `source-derived` or `local-derived` provenance, and a basis with a sanitized summary, claim state, and source references. Create-time proposal files use null base fields only for the same atomic create invocation; resume proposal files require the exact current base. Keep these files outside Git under owner-only permissions.

Enter the source ledger explicitly through the local form or an answer envelope before applying any source-required proposal. A proposal cannot establish the source record that it cites as its own authority; its cited source IDs must already exist in the current profile.

Use an answers file with `--answers` for a headless or repeatable workflow, or when structured content is easier to prepare outside the terminal wizard. An agent using the preferred skill may prepare the non-sensitive structure and categorical answers; a local control must merge exact private values without returning the filled file to model context. The operator should not have to author raw JSON during the normal flow. Keep the file in a private location outside the repository because it may contain targets, program terms, contacts, or unpublished testing plans. Store credentials separately and answer with `env://`, `keychain://`, or `file://` references only.

Start or resume the interactive wizard:

```bash
unset GATE_CASE
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

Run `show --format review` only in the operator's local terminal or local-only interface. It deliberately renders exact private profile details; do not run it through a model-visible tool, paste it into a model prompt, or ask an agent to ingest it. Return only an accept/revise choice or choice-safe categorical exceptions to the model-assisted interview.

The file must follow the [answers schema](../schemas/bug-bounty-program-profile-answers.schema.json). Keys below `answers` are the question IDs in the reviewed [questionnaire contract](../config/questionnaires/bug-bounty-program-profile.json), for example:

```json
{
  "$schema": "https://gate.local/schemas/bug-bounty-program-profile-answers.schema.json",
  "apiVersion": "gate.dev/program-profile-answers/v2",
  "kind": "BugBountyProgramProfileAnswers",
  "metadata": {
    "programId": "acme-program",
    "title": "Acme program answers",
    "updatedAt": "2026-10-14T00:00:00Z",
    "baseRevision": null,
    "baseProfileSha256": null
  },
  "answers": {
    "identity-program-name": "Acme bug bounty",
    "identity-depth": "thorough"
  }
}
```

This partial v2 example creates a draft, so both base fields are `null`. A resume envelope must instead carry the exact current base. After create or apply, the CLI result exposes top-level `revision` and `profileSha256`; `status --json` exposes `profile.revision` and top-level `profileSha256`. The local controller copies those current values into `baseRevision` and `baseProfileSha256` for the next headless batch without returning them to the model. Raw status also contains the profile ID, title, and blocker details. GATE v0.1 has no built-in model-safe Program Profile projector, so keep the command local and return only manually sanitized categorical outcomes when a model assists. GATE stores and rebinds its canonical v2 envelope after each apply; the programmatic resume result returns that binding in `answers`. GATE rejects stale, mismatched, and legacy v1 resume updates, so reload the current summary rather than reconstructing or guessing either base value. Supply the remaining required answers or resume the wizard before expecting verification to report `ready: true`.

The authorization confirmation question follows the source ledger, contacts, and every other authority-basis field. Public create and generic headless answer ingestion cannot establish or replay `authority-operator-confirmed: true`; complete that exact review in the local terminal or browser after import. Changing a cited source or any authorization review-basis field clears the prior confirmation and requires another local confirmation. Applicable module questions precede final operator attestation. Substantive edits invalidate the prior attestation; review the revised answers and attest again before compiling a ready profile. A headless amendment can include a fresh attestation only by supplying all attestation answers with a timestamp strictly later than both the current profile update and the prior attestation. Answer values must match their questionnaire types, including module answers; key presence alone does not complete a module.

Interactive resume opens the first unanswered applicable required question. An unconfirmed draft value does not count as an answer: enter it explicitly to confirm it. Progress counts only applicable questions. Quitting or finishing the questions returns a bounded saved-state summary and the next command; finishing alone does not establish readiness. If all required answers are recorded but verification remains blocked, it prioritizes an exact question-path match over a broad parent blocker. For example, a recorded `false` answer to `attestation-answers-complete` reopens that question rather than `attestation-operator`. An attestation blocker without a matching question opens `attestation-at` for renewed review.

Required text answers must contain visible content; whitespace or invisible characters alone are incomplete in the wizard, on resume, and at readiness validation. Required module lists must be non-empty, with substantive content in every item. Non-module answers retain their field-specific empty-list and nullable allowances: `architecture.unknowns` may be `[]`, but every supplied entry must be a string containing visible content. Literal technique parameters and payloads remain available within the same recursive safe-text and likely-secret scan applied to every profile key and value.

That scan rejects terminal controls and invisible direction-formatting characters, credential-bearing URLs, recognizable credential formats, and likely opaque secrets. Strings beneath sensitive field names, including nested credential and authentication fields, must be symbolic secret references. Keep actual credentials outside the profile even when documenting a payload. The compiled `literalSecretScan` reports `no-likely-secret-detected` using `gate-heuristic-v1`; it is a heuristic finding, not proof that arbitrary text contains no secret.

The review step surfaces missing provenance, conflicting selectors, expired terms, unanswered conditional rules, insufficient limits, and other ambiguities. Source observations, authorization verification, and attestation cannot be in the future. Authorization verification must not predate its cited sources; attestation must not predate authorization verification or any recorded source. Each architecture data flow must have a known classification, and the profile's release classification must cover its most sensitive flow. Resolve blockers at the source or leave them explicit. Verification reports `ready: true` only when the profile is internally consistent and complete enough for deterministic compilation; readiness is not a statement that every requested technique is permitted.

`verify` exits with status 2 while review blockers remain. A structurally valid but blocked `compile` still writes the private review bundle and also exits with status 2; inspect its `blockers` and `nextSteps` instead of treating artifact creation as readiness.

## Compile and preflight

Compilation is a local, no-contact operation. It binds the canonical profile and the source digests recorded in that profile, preserves exclusions and per-asset differences, and creates private operator-review, ambiguity, scope, technique, coverage, model-context, and compatibility records under `GATE_HOME`. It does not reopen or rehash the operator-held source bodies. Different rules for different assets remain separate instead of being flattened into one broad authorization.

Verify, then create or select an immutable case bound to that exact ready profile and compile inside it. Optional engagement and workflow IDs label proposed downstream material without activating either one. A provider profile is optional for creating the private review bundle, but a current, model-bound context-window declaration is required for the compile gate to pass:

```bash
unset GATE_CASE
./bin/gate.mjs bounty profile verify acme-program --json

./bin/gate.mjs bounty profile show acme-program --format model-context

./bin/gate.mjs case create acme-2026 \
  --program acme-program \
  --name "Acme 2026 program" --json

./bin/gate.mjs --case acme-2026 bounty profile compile acme-program \
  --engagement acme-web-2026 \
  --workflow acme-web-2026 \
  --provider-profile "$HOME/private/provider-profile.json" \
  --json
```

Program Profile creation, resume, status, show, and verification use the shared registry and reject `--case`, `GATE_CASE`, and `--unassigned`; run them with `GATE_CASE` unset. Compilation is case-owned and requires an explicit runtime selection. Use leading `--case ID` or `GATE_CASE` so the immutable case binds the profile being compiled. Leading `--unassigned` selects the writable base-state compatibility namespace, can create a new unscoped compilation, and opts out of case attribution and separation.

Run verification and compilation in the operator's local terminal. Raw verification output can include source references, asset IDs, and free-form ambiguity details. A model-assisted interview may receive only a manually sanitized categorical outcome, such as ready, blocked, or revise, plus choice-safe blocker categories.

`show --format model-context` renders a bounded local view with the default proposed IDs. The compile result returns private references and SHA-256 values for the exact packet bound to its selected engagement, workflow, and provider profile.

The canonical profile is stored at `GATE_HOME/programs/acme-program/program-profile.json`. A successful compile writes a 64-character digest-named directory below `GATE_HOME/programs/acme-program/compiled/`. Compilation captures one exact assessment instant and uses it for authorization readiness, provider freshness, every emitted assessment timestamp, and the directory digest. Repeating a compile with the same exact inputs and assessment instant is idempotent; a later invocation produces a distinct time-bound bundle even within the same minute. Changed input cannot overwrite an earlier bundle. The directory contains:

- `source-ledger.json`, `authorization-summary.md`, `operator-review.md`, and `ambiguities.json`/`ambiguities.md` for provenance and operator review;
- `scope-matrix.json`, `technique-matrix.json`, `coverage-plan.json`, and `execution-policy.json` for deterministic planning;
- `credential-plan.json`, `limits-and-schedule.json`, and `data-evidence-plan.json` for access and resource handling;
- `stop-escalation-plan.md`, `reporting-disclosure-plan.md`, and `cleanup-ledger-template.json` for closeout and reporting;
- compact `model-context.json` and readable `model-preflight.json` for bounded context and compatibility routing;
- `engagement-proposal.json`, which explicitly carries `executionAuthority: false` and the remaining review, receipt, admission, and execution steps.

GATE keeps these directories owner-only and the files owner-readable and owner-writable. Treat every file there as private.

The v3 model context is a compact program-level JSON packet bound to the `gate.dev/program-profile-compilation/v3` artifact contract. It contains authorization basis and validity, selectors, per-asset action and limit bounds, proposed phase policies and tool allow/deny lists, data rules, stop conditions, depth-aware exploration instructions, unresolved items, and proposed engagement and workflow IDs. `show --format model-context` remains a readable local rendering; the compiled machine artifact removes insignificant JSON whitespace, and its byte digest is the packet digest recorded by preflight. The packet is private `GATE_HOME` content and is not interview or prompt input. Keep it local. A future model sender must construct a separate sanitized request from explicitly approved fields and enforce the current provider, destination, classification, and release decision; v0.1 compilation does not send a packet. These policies describe the intended program workflow; they are not a workflow admission or a target-, tool-, and phase-attempt-bound execution packet. Compatibility preflight evaluates provider capabilities separately from GATE authority. Its result can be compatible, incompatible, or unknown; an incompatible or unknown provider result never changes the underlying scope or hides the intended action.

A provider profile maps each action and assistance mode to `allow`, `deny`, or `unknown`. Copy the sanitized, fail-closed [provider profile template](../templates/provider-capability-profile.json) to private storage and edit it from current provider documentation or an observed capability decision:

```bash
cp templates/provider-capability-profile.json \
  "$HOME/private/provider-capability-profile.json"
chmod 600 "$HOME/private/provider-capability-profile.json"
```

The document must satisfy the closed [provider capability schema](../schemas/provider-capability-profile.schema.json): v2 names all 13 action classes, all six modes (`plan`, `analyze`, `generate-command`, `execute`, `report`, and `retest`), and the optional context declaration. Legacy v1 profiles without `contextWindow` remain readable with unknown context accounting; adding that field requires v2. Leave an entry as `unknown` unless evidence supports `allow` or `deny`. Replace the template identity, then add the exact reviewed `model`, `effectiveAt`, and `expiresAt` before routing; known template sentinel values are rejected at compile time. Omitting either timestamp gives the snapshot unknown freshness. An assessment before `effectiveAt` or at or after `expiresAt` treats it as stale, and `expiresAt` must be later than `effectiveAt`. These values predict provider compatibility only; they do not grant GATE authority or change the profile's scope.

The template deliberately leaves `contextWindow` as `null`. That state prevents provider-model routing because GATE cannot infer a model's tokenizer or context window from its name. A current provider profile may instead bind a conservative request envelope:

```json
{
  "contextWindow": {
    "maxTokens": 128000,
    "reservedOutputTokens": 16000,
    "requestOverheadTokensUpperBound": 8000,
    "countingMethod": "utf8-bytes-upper-bound"
  }
}
```

`utf8-bytes-upper-bound` counts every byte of the exact compact `model-context.json` payload as at most one input token. Declare it only when current provider evidence supports that property. `requestOverheadTokensUpperBound` must conservatively cover all input outside that file, including system instructions, tool schemas, message framing, and provider-added text. Missing, stale, or unsupported accounting remains `unknown` and routes to the operator. GATE does not divide bytes by an assumed characters-per-token ratio.

The profile's `limits.maxTokens`, asset override, and phase override form a separate cumulative run-token budget. They do not describe the provider's per-request context window. Preflight reports both `provider-context-window` and `run-token-budget`: the former checks the complete proposed request against the provider ceiling, while the latter checks that even the initial bounded request can fit beneath the strictest cumulative run ceiling. A later execution runtime must still meter every turn against that cumulative budget.

Provider metadata may declare `destination` as `local`, `cloud`, or `unknown`. Local routes require `gate-home`; cloud routes require `configured-cloud-model` in the profile destinations. Missing, unknown, or stale destination declarations require operator routing review. Capability prediction alone does not establish data-release compatibility.

Preflight checks every raw action requested by a phase against every requested assistance mode, including actions whose execution is conditional or denied by a module ceiling. `profileReady` reports questionnaire and profile readiness. Compile `ready` and `gateDecision: pass` additionally require current bounded provider context accounting within both the provider window and the reviewed run budget; omission, stale bounds, or `contextWindow: null` leaves accounting unknown and exits with status 2 after creating the no-contact bundle. Inspect `providerPrediction`, `dataReleaseStatus`, both token dimensions, and `routing` separately. The compile summary exposes `dataReleaseStatus`, `routingStrategy`, `routingReason`, and `routeReady`; `routeReady: true` means only that this compiled provider-model route passed those no-contact checks. Compilation sends no packet to a provider.

When `--provider-profile` is supplied, `compile` also exits with status 2 if `routeReady` is false, even when compile `ready` is true. Inspect `routeBlockers` for destination or capability failures as well as profile and accounting blockers.

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
