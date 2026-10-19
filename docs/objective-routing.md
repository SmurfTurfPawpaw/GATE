# Objective routing

GATE routes a new objective before it opens a domain-specific intake. This keeps a bug bounty Program Profile focused on bug bounty terms while still giving software work, incident investigation, research, local artifacts, system operations, communications, and unfamiliar requests a common recommendation step.

The v0.2 core is deliberately small. A reviewed skill derives a categorical proposal from conversation material allowed by the data policy. A pure resolver binds that proposal to the exact route catalog and returns a deterministic, sanitized recommendation. It does not persist an objective, dispatch Firstmate, create a Program Profile or case, contact a target, send a message, operate a system, or grant execution authority.

## Route from dimensions, not keywords

The router does not scan raw prose for trigger words. The local agent or controller first classifies the objective on five independent dimensions:

- **domain:** software, security assessment, security incident, research, data analysis, system operations, communication, personal administration, other, mixed, or unknown;
- **deliverable:** change, answer, investigation report, decision, operation, monitor, communication, or unknown;
- **relationship:** operator-owned, authorized, public, third party, or unknown;
- **highest effect:** none, local read, local write, external read, external write, target contact, high impact, or unknown;
- **data class:** public, internal, sensitive, secret, or the routing-only `unknown` sentinel.

Bounded signals such as `repository`, `bounty-program`, `account`, `payment`, `order`, `artifact`, or `application` refine a route. They never contain a target, account, person, URL, path, or source body.

The model may infer the domain, deliverable, effect, data class, and signals. It labels those facts `inferred`. A non-unknown relationship must be directly operator-stated and `observed`; the resolver rejects model-inferred ownership or authorization. An unverified dimension is accepted only with its `unknown` value. An unknown or mixed domain routes to clarification; other unknown dimensions remain visible to the selected route. Signals and proposed answers cannot be unverified.

[`config/objective-routes.json`](../config/objective-routes.json) contains the reviewed routes. Each route names its current handler and one honest state:

- `ready`: the intake handler exists for this narrow purpose;
- `handoff-only`: the destination concept exists, but GATE has no reviewed dispatch bridge;
- `planning-only`: GATE can prepare the recommendation but has no persisted or executable domain workflow;
- `unavailable`: even the named handler cannot currently accept the handoff.

The unconditional general route ensures an unfamiliar objective still receives an evidence-led plan. A unique priority makes route selection independent of catalog order.

If the objective spans independently actionable outcomes, classify its domain as `mixed`. A higher-priority route detects a `mixed` or separately classified `security-incident` objective only when it also carries the bounty-program signal and a bounded incident signal. Common account, payment, order, identity, or device surfaces in an ordinary security assessment do not by themselves turn a bounty objective into an incident. Mixed and incident cases route to clarification and decomposition before either Program Profile or incident intake. The route returns two registered choice questions: which workstream should own the first result, and whether to split, choose one first, keep a combined planning-only view, or gather more evidence.

## Private categorical proposal

`ObjectiveRoutingProposal/v1` is a categorical, maximum-64-KiB envelope. It contains:

- a cryptographically random opaque objective handle, never a hex-encoded target or identifier;
- the exact route-catalog SHA-256 digest;
- the five dimensions and bounded signals;
- provenance, claim state, a registered categorical basis code, and opaque source references;
- explicit answers or answer recommendations for registered choice questions.

The proposal has no free-text field and no dedicated field for the raw objective. JSON Schema rejects extra fields, including a free-text basis summary. Producers must also generate objective handles and opaque source references randomly and must never encode the statement, target, account, contact, authorization text, source body, private path, URL, credential, command, or tool arguments into them. Keep the original statement in the current conversation only when its data classification permits that provider, or in a future private objective record under `GATE_HOME`. Secret values remain outside model input and belong in the existing secret-reference path.

The proposal is bound to `objectiveCanonicalSha256(catalog)`. A catalog change makes an older proposal stale. The resolver also returns a digest of the exact proposal and a digest of its recommendation. The recommendation never echoes the proposal's caller-controlled objective handle. It carries a full-length, domain-separated SHA-256 projection instead, while the proposal digest preserves deterministic internal binding. The proposal timestamp is normalized to fixed UTC millisecond form before output, so extra fractional digits cannot become an output channel.

Provenance has five values:

- `reviewed-policy` for a checked-in route or question default;
- `operator-stated` for a fact or selection the operator supplied directly;
- `source-derived` for a proposal tied to opaque local source references;
- `model-derived` for an AI inference, which can never be labeled observed;
- `local-derived` for a categorical result obtained by a local controller.

Every basis also names one code from the catalog's exact ordered vocabulary. The catalog binds each code to allowed provenance, so an `operator-explicit` basis cannot be relabeled model-derived and a `source-classification` requires source-derived provenance plus at least one opaque reference. Codes cover reviewed defaults, explicit selections, objective and source classification, local observation, insufficient evidence, mixed workstreams, requested outcomes, effect estimates, data classification, and signal classification. Arbitrary explanatory prose belongs outside the proposal and is omitted from the recommendation.

`reviewed-policy` provenance and the `reviewed-default` basis code are resolver-owned and cannot appear in a proposal. The resolver emits them only for the exact default choice on an `operator-preference` question in the checked-in catalog. This keeps a proposal from presenting an arbitrary fact or answer as reviewed policy.

The core validates the shape of opaque source references but has no source registry and cannot prove that a referenced source exists. A future persisted controller must resolve and bind those references before accepting a source-derived proposal.

## Choice-first decisions

Each registered question declares one policy class:

- `operator-preference` can show a reviewed default;
- `evidence-proposal` can show a source-, model-, or local-derived recommendation for acceptance;
- `manual-only` accepts only an explicit, observed, operator-stated choice.

Relationship, data access, project binding, artifact possession, system scope, and external-action intent are manual-only. The resolver rejects recommendations for them. A recommendation stays unresolved until the operator accepts it; it is never silently converted into an explicit answer.

When both the relationship dimension and `subject-relationship` answer are present, they must agree. An explicit answer can refine an `unknown` relationship dimension; it cannot contradict an already observed relationship.

Actions declare both the question they depend on and the exact choices that satisfy that dependency. An unresolved question leaves the action at `needs-input`. A resolved but disallowed choice blocks it with a categorical reason. For example, `report-only` does not unlock record preservation or timeline construction, unknown artifact possession does not unlock artifact inspection, unknown system scope does not unlock a system-state read, and `no-project-yet` does not unlock a project handoff.

The output carries every route question as structured choices. A native chat or local browser surface should present at most one to three unresolved questions at a time, put a supported recommendation first, and avoid a prose questionnaire.

## Recommendation output

`resolveObjectiveRecommendation(catalog, proposal)` returns `ObjectiveRecommendation/v1` with:

- the selected route, evidence state, handler, and handler readiness;
- a bounded evidence plan and category-only data requests;
- required capabilities and candidate tool IDs;
- bounded next actions with an effect, time cap, item cap, and unresolved requirements;
- explicit and recommended choice state;
- a sanitized provenance projection containing counts rather than source references or basis text;
- `executionAuthority: false`.

Candidate tools are labeled only `route-listed` with suitability `unknown`. Repository validation can compare the checked-in route catalog with an exact supplied security-tool ID set, but the recommendation is not bound to a runtime inventory. The objective router therefore does not call a tool catalogued, installed, verified, admitted, executable, or suitable. A domain handoff must use the existing tool runtime and workflow checks to establish those states.

An action is `ready-to-plan`, `needs-input`, or `blocked`. `ready-to-plan` means only that the next planning step is coherent. It does not mean ready to execute. An unresolved effect boundary or question yields `needs-input`; a disallowed accepted choice, an action above the proposed effect ceiling, or an unavailable handler yields `blocked`. Every reason remains visible in the result.

## Example: account and payment abuse

An objective about unexplained meal-delivery orders paid without the reported person's own funds is categorized as a security incident with account, payment, and order signals. It routes to `security-incident-investigation`, not to a bug bounty Program Profile.

The route first recommends a category-only evidence checklist. After the operator explicitly selects both a supported relationship and accessible-record basis, it can plan to preserve those records locally, correlate order, payment, account-change, session, device, notification, and destination timestamps, compare competing explanations, and identify the smallest missing observation. A `report-only` or third-party/unknown selection keeps record-dependent actions blocked. It asks whose records are involved, which records can be accessed, and whether the first result should explain the event, stop ongoing loss, or prepare a report.

The route is `planning-only` in v0.2. It does not infer access to another person's records, contact the delivery platform, test its application, or turn an allegation into target authority. If a separate authorized bug bounty objective emerges, that new objective can route into Program Profile intake.

## Current API and limits

The current programmatic entry points are exported from `src/lib/objective-router.mjs`:

- `objectiveCanonicalSha256(value)`;
- `objectiveRouteCatalogSemanticErrors(catalog, options)`;
- `objectiveRoutingProposalSemanticErrors(catalog, proposal, options)`;
- `resolveObjectiveRecommendation(catalog, proposal, options)`.

The resolver is deterministic: it reads no clock, network, private state, or environment-dependent tool status. The same catalog and proposal produce the same recommendation and digests.

The bounded local CLI entry point is:

```sh
gate objective recommend --proposal PRIVATE_FILE --json
```

It reads the exact checked-in route and security-tool catalogs, validates their schemas and semantic references, then resolves the proposal without creating `GATE_HOME` state. The proposal must be a stable, single-link regular file no larger than 64 KiB. The leaf path must not be a symbolic link. On POSIX the file must be owned by the current effective user with exact mode `0600`; the command reports a permissions error and does not change the mode. The command requires `--json` and writes only the sanitized `ObjectiveRecommendation` to stdout. It does not echo the private path, proposal body, caller-controlled objective handle, extra timestamp precision, structural details, raw objective, source references, or private values on proposal-validation failures.

This CLI is a read-only recommendation boundary. It does not persist the proposal or output, accept a raw natural-language objective, grant execution authority, dispatch the selected handler, or establish tool readiness.

Private objective persistence, a loopback browser form, source-reference resolution, bounded learning projection binding, cockpit projection, accepted-plan lifecycle, and reviewed dispatch bridges remain follow-up work. Until those exist, the skill uses the current conversation and the bounded local recommendation command, and reports every handoff state exactly as returned.
