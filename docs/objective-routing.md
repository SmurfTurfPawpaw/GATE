# Objective routing

GATE routes a new objective before it opens a domain-specific intake. This keeps a bug bounty Program Profile focused on bug bounty terms while still giving software work, incident investigation, research, local artifacts, system operations, communications, and unfamiliar requests a common recommendation step.

The v0.1 core is deliberately small. A reviewed skill derives a categorical proposal from conversation material allowed by the data policy. A pure resolver binds that proposal to the exact route catalog and returns a deterministic, sanitized recommendation. It does not persist an objective, dispatch Firstmate, create a Program Profile or case, contact a target, send a message, operate a system, or grant execution authority.

## Route from dimensions, not keywords

The router does not scan raw prose for trigger words. The local agent or controller first classifies the objective on five independent dimensions:

- **domain:** software, security assessment, security incident, research, data analysis, system operations, communication, personal administration, or other;
- **deliverable:** change, answer, investigation report, decision, operation, monitor, or communication;
- **relationship:** operator-owned, authorized, public, third party, or unknown;
- **highest effect:** none, local read, local write, external read, external write, target contact, high impact, or unknown;
- **data class:** the existing public, internal, sensitive, or secret vocabulary.

Bounded signals such as `repository`, `bounty-program`, `account`, `payment`, `order`, `artifact`, or `application` refine a route. They never contain a target, account, person, URL, path, or source body.

The model may infer the domain, deliverable, effect, data class, and signals. It labels those facts `inferred`. A non-unknown relationship must be directly operator-stated and `observed`; the resolver rejects model-inferred ownership or authorization. Unverified dimensions and signals cannot select a route.

[`config/objective-routes.json`](../config/objective-routes.json) contains the reviewed routes. Each route names its current handler and one honest state:

- `ready`: the intake handler exists for this narrow purpose;
- `handoff-only`: the destination concept exists, but GATE has no reviewed dispatch bridge;
- `planning-only`: GATE can prepare the recommendation but has no persisted or executable domain workflow;
- `unavailable`: even the named handler cannot currently accept the handoff.

The unconditional general route ensures an unfamiliar objective still receives an evidence-led plan. A unique priority makes route selection independent of catalog order.

## Private proposal

`ObjectiveRoutingProposal/v1` is a categorical, maximum-64-KiB envelope. It contains:

- a random opaque objective handle;
- the exact route-catalog SHA-256 digest;
- the five dimensions and bounded signals;
- provenance, claim state, a short sanitized basis, and opaque source references;
- explicit answers or answer recommendations for registered choice questions.

It has no field for the raw objective. JSON Schema rejects extra fields, so the statement, target, account, contact, authorization text, source body, private path, credential, command, and tool arguments cannot be added to this envelope. Keep the original statement in the current conversation only when its data classification permits that provider, or in a future private objective record under `GATE_HOME`. Secret values remain outside model input and belong in the existing secret-reference path.

The proposal is bound to `objectiveCanonicalSha256(catalog)`. A catalog change makes an older proposal stale. The resolver also returns a digest of the exact proposal and a digest of its recommendation.

Provenance has five values:

- `reviewed-policy` for a checked-in route or question default;
- `operator-stated` for a fact or selection the operator supplied directly;
- `source-derived` for a proposal tied to opaque local source references;
- `model-derived` for an AI inference, which can never be labeled observed;
- `local-derived` for a categorical result obtained by a local controller.

The core validates the shape of opaque source references but has no source registry and cannot prove that a referenced source exists. A future persisted controller must resolve and bind those references before accepting a source-derived proposal.

## Choice-first decisions

Each registered question declares one policy class:

- `operator-preference` can show a reviewed default;
- `evidence-proposal` can show a source-, model-, or local-derived recommendation for acceptance;
- `manual-only` accepts only an explicit, observed, operator-stated choice.

Relationship, data access, project binding, artifact possession, system scope, and external-action intent are manual-only. The resolver rejects recommendations for them. A recommendation stays unresolved until the operator accepts it; it is never silently converted into an explicit answer.

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

Candidate tools are labeled only `catalogued` with suitability `unknown`. The objective router does not claim that a candidate is installed, verified, admitted, or suitable. A domain handoff must use the existing tool runtime and workflow checks to establish those states.

An action is `ready-to-plan`, `needs-input`, or `blocked`. `ready-to-plan` means only that the next planning step is coherent. It does not mean ready to execute. An unresolved effect boundary, a missing required manual answer, an action above the proposed effect ceiling, or an unavailable handler remains visible in the result.

## Example: account and payment abuse

An objective about unexplained meal-delivery orders paid without the reported person's own funds is categorized as a security incident with account, payment, and order signals. It routes to `security-incident-investigation`, not to a bug bounty Program Profile.

The route first recommends a category-only evidence checklist. After the operator states which records are accessible, it can preserve those records locally, correlate order, payment, account-change, session, device, notification, and destination timestamps, compare competing explanations, and identify the smallest missing observation. It asks whose records are involved, which records can be accessed, and whether the first result should explain the event, stop ongoing loss, or prepare a report.

The route is `planning-only` in v0.1. It does not infer access to another person's records, contact the delivery platform, test its application, or turn an allegation into target authority. If a separate authorized bug bounty objective emerges, that new objective can route into Program Profile intake.

## Current API and limits

The current programmatic entry points are exported from `src/lib/objective-router.mjs`:

- `objectiveCanonicalSha256(value)`;
- `objectiveRouteCatalogSemanticErrors(catalog, options)`;
- `objectiveRoutingProposalSemanticErrors(catalog, proposal, options)`;
- `resolveObjectiveRecommendation(catalog, proposal, options)`.

The resolver is deterministic: it reads no clock, network, private state, or environment-dependent tool status. The same catalog and proposal produce the same recommendation and digests.

Private objective persistence, a loopback browser form, a CLI command, source-reference resolution, bounded learning projection binding, cockpit projection, accepted-plan lifecycle, and reviewed dispatch bridges remain follow-up work. Until those exist, the skill uses the current conversation and the pure router, and reports every handoff state exactly as returned.
