# Local cockpit companion

The local companion turns the static cockpit into a private operator surface on the same laptop. It serves the checked-in cockpit, injects an exact browser bridge, owns one dedicated Codex app-server thread, streams categorical activity and aggregate token events, and reads a separate bounded fleet and execution-mirror projection from GATE's loopback observer. It does not connect to the current Codex cloud chat or take over an arbitrary Codex Desktop thread.

## Start it

Prerequisites:

- Node.js 22.20 or newer;
- a working `codex` CLI login;
- GATE's read-only observer for live campaign numbers.

Use two terminals:

```sh
# terminal 1, in the GATE repository
# Set CODEX_HOME here when WSL must read Windows-hosted Codex sessions.
npm run dashboard

# terminal 2, in the same GATE repository
codex login status >/dev/null 2>&1 || codex login
npm run cockpit
```

The Codex working directory defaults to `GATE_REPO` when that environment variable is set. Otherwise the integrated GATE checkout is selected. Override it when needed:

```sh
npm run cockpit -- --cwd /path/to/GATE
```

The fleet source defaults to GATE's exact `http://127.0.0.1:4173/api/status` endpoint. Override only the explicit loopback port when needed:

```sh
npm run cockpit -- --gate-observer http://127.0.0.1:43173/api/status
```

The source option accepts only HTTP on `127.0.0.1` or `::1`, with the exact `/api/status` path and no credentials, query, fragment, redirect, or public host. The observer request has a 3.5-second deadline, a 2,000,000-byte response limit, and a two-second cache.

The command prints `GATE // Welcome, Giovanni.` and one private URL such as:

```text
http://127.0.0.1:43127/#session=…&csrf=…
```

Keep the terminal open. The session and CSRF capabilities exist only for that process and URL fragment. The default thread is ephemeral and dedicated to this companion. Use `--persistent` to let Codex persist a newly created thread, or `--thread-id ID` to resume a dedicated thread explicitly.

Resuming restores the bounded operator and final Codex messages returned by app-server, with notices when history is unavailable, unsafe, unsupported, or too large to display. The adapter retains at most 48 conversation entries including notices; the browser displays the latest 12. This is a recent conversation view, not a complete transcript.

The checked-in `cockpit/data/status.json` is a presentation preview. Static GitHub Pages and a normal preview server remain read-only because neither has the private bridge or capabilities. They display synthetic mirror entries and link to the authenticated live cockpit without calling it. Through the loopback companion, private conversation, native Codex questions, and the local GATE fleet work independently of that preview snapshot. Missing or invalid preview data does not clear an unsent local message. Public snapshots accept only preview mode; example decisions are disabled. Private choices use native Codex questions.

## What is working

The cockpit puts the selected CTF campaign scorecard first. It shows independent **Solving**, **Learning**, and **Cockpit** verdicts, the current plan step, action needed, latest bounded verified event, and feed freshness before the conversation channel. One available case is selected automatically. Multiple cases require an explicit opaque alias. A retained choice is bound to the current random fleet selection epoch and is cleared after a companion or runner restart or an alias-binding change, preventing an alias from silently pointing at a different case. The work-item Fleet and status cards follow the scorecard, and **Steer the dedicated runner** remains secondary.

On an authenticated cockpit, each Fleet card uses the bounded campaign context label as its heading and keeps the opaque alias visible underneath as `Campaign N · Profile setup` or `Campaign N · Case`. The compact view combines the reason for its current condition and one deterministic `Next:` action on one line. An accessible `Details` disclosure holds the richer status, attention, progress or work, and token context. Questionnaire cards show the number of remaining questions and the named next section. Operator-review cards may show a count of review issues; questionnaire verification findings are not presented as operational blockers. Case cards translate their observed state and attention into a concise reason and next action. A missing context label is shown as an untitled profile or case while preserving the alias. The selected pilot title and authenticated work-item selectors use the same label while retaining `Campaign N` as their stable value.

The four compact status cards are **Active work**, **Needs you**, **Blockers**, and **Tokens**. Active work counts nonterminal case and profile campaigns, so a running case remains visible even before it starts a workflow; the detail separately reports active workflow lanes, running executions, and analyses. Needs you combines native questions with fleet attention. Blockers combines cases whose observed state is `blocked` with issues that have reached operator review. Questionnaire verification findings stay in remaining-question progress and do not inflate this KPI. Each source keeps its own scan precision, and a partial total remains a lower bound. Missing measurements display `Unavailable`; they never become a dash, idle, or zero. Lower bounds use `+`.

The Tokens card prefers the case-bound fleet total and labels its exact, estimated, or partial provenance, with the dedicated-session total alongside when available. Without available fleet tokens it shows the exact dedicated-session total, or marks telemetry unavailable. Detailed input, cached-input, output, reasoning, and cost fields remain in the private API rather than separate visible counters. Host-wide usage stays separate from case attribution; case rows without canonical token data show `Awaiting attribution`. The public preview shows only an example token budget.

The selected case also has an **Operational mirror** grouped by recent supervised-execution attempt. The initial producer can show the operator-visible work order, deterministic secret-masked command, a bounded stdout/stderr tail, lifecycle state, timestamps and elapsed time, trustworthy progress when available, usage provenance, and result. Each entry is labelled `exact`, `redacted`, `summarized`, or `unavailable`; truncation is explicit. The local companion enables this local projection. See the complete [operational mirror contract](execution-mirror.md).

The companion currently provides:

- an exact `gate.local-cockpit-bridge/v1` browser adapter exposing `submitMessage` and `submitQuestion`;
- idempotent receipts that say only that the local companion accepted a request;
- Codex app-server initialization, dedicated thread start or resume, `turn/start`, and `turn/steer`;
- bounded native `item/tool/requestUserInput` choice capture and response in the adapter API;
- a capability-protected private-state API containing only user-visible operator and final Codex messages, dedicated-thread input/cached-input/output/reasoning/total counters, optional estimated cost, turn state, and bounded questions;
- an authenticated server-sent event stream containing only fixed activity categories, lifecycle state, optional completed/total counts, and aggregate token totals;
- an authenticated read-only `/api/fleet` endpoint containing only the exact `gate.local-fleet/v4` projection from GATE's observer. It adds bounded case/profile labels and the categorical next profile section while preserving opaque aliases and excluding targets, sources, answers, and raw blocker detail. Every projection carries a 15-second `validUntil`; the browser and remote coordinator remove it at expiry without clearing a still-current conversation;
- immediate browser snapshot refresh signals when an event arrives.

Private operator messages may include URLs and project context. They are limited to 1,000 characters and must not contain credentials or secrets. Native Codex questions are rendered as bounded one-to-three-choice controls, with the recommended option identified explicitly.

The fleet projection shows at most 32 current case rows and 32 current Program Profile rows under process-local `Campaign N` aliases. It carries scan completeness alongside every aggregate. Exact counts appear only when both source scans are complete and every visible case runtime is available; partial coverage uses lower bounds, and unavailable scans never relabel cached rows as current. Case workflow, supervised-run, and offline-analysis counts stay separate. Program Profile answered/total progress is determinate; case completion percentages are unavailable by contract. Per-case canonical token totals preserve exact versus estimated availability, while the fleet total becomes partial or unavailable when any visible total is missing. Host-wide observer input, cached input, output, and total counters are a separate projection and are never substituted for case-bound usage.

The generated protocol for Codex CLI 0.159.2 was used to bind `initialize`, `thread/start|resume`, `turn/start|steer`, `turn/started|completed`, `item/started|completed`, `thread/tokenUsage/updated`, and `item/tool/requestUserInput`. Regenerate it for review after a Codex CLI upgrade:

```sh
schema_dir="$(mktemp -d)"
codex app-server generate-json-schema --experimental --out "$schema_dir"
```

## Windows-hosted Codex telemetry from WSL

The observer reads `CODEX_HOME/sessions`. If those files live on Windows, either set a local symbolic path such as `CODEX_HOME=/mnt/c/Users/WINDOWS_USER/.codex` before `npm run dashboard`, or use the safe profile-detection snippet in [Laptop and cloud setup](setup.md#4-run-and-inspect). Do not commit the resolved username or path. This changes only the observer's Codex session source and does not change `GATE_HOME`.

## Visibility boundary

The browser may show the operator's own bounded message and Codex's final user-visible answer in its authenticated private state. The categorical activity stream never receives hidden reasoning, system or developer instructions, command lines, arguments, stdout or stderr, file paths, tool names, target selectors, evidence, credentials, internal thread IDs, raw errors, or request bodies. Apart from the bounded campaign context label, the fleet projection omits source IDs, exact targets, contacts, raw evidence, session records, and session paths. Its separate execution-mirror field is the narrow exception: it can include an opaque attempt label, an operator-visible work order, a deterministic secret-masked command, and up to four bounded lines selected from the final 4 KiB of each supervised run's stdout and stderr. Terminal controls are escaped; a still secret-shaped line is withheld as a whole. Private paths, target selectors, raw evidence, credentials, private IDs, hidden reasoning, and unbounded output remain excluded.

The bounded Fleet context label is private operator data because it can identify the program or objective. It is available only through the capability-protected companion or authenticated remote coordinator. The static public preview keeps synthetic opaque campaign aliases and never publishes a live context label.

Item types become fixed categories such as `tool`, `file-change`, `research`, or `agent`. Progress is determinate only when a producer supplies a real completed count and total. Dedicated-thread token state contains exact input, cached-input, output, reasoning-output, and total counters from Codex notifications. When `account/usage/read` returns a matching thread estimate, the browser receives only the estimated USD or credit micros and unit; account summaries, groups, model metadata, thread IDs, and raw responses remain private. Likely credentials are rejected from operator messages and withheld from mirrored Codex answers.

The server binds only to `127.0.0.1` or `::1`. It requires the exact loopback `Host`, rejects foreign origins and cross-site browser requests, requires a random session capability for every private API, and requires a separate CSRF capability plus exact origin for every write. The read-only observer source is fetched by the companion process and exposed only through the session-protected fleet endpoint. Fleet state is never added to a Codex prompt, message, thread state, or app-server request. Bodies, protocol lines, requests, retained events, messages, questions, and observer responses are bounded.

Do not place this listener behind a tunnel, port forward, public reverse proxy, or shared-host bind. The public GitHub Pages build remains a read-only preview and contains no companion endpoint or capability.

## Public snapshot integration

Public snapshots are static examples and cannot accept operator choices or claim live operational state. `npm run cockpit:build` recreates `cockpit/_site` from exactly `.nojekyll`, `index.html`, `robots.txt`, `assets/app.js`, `assets/favicon.svg`, `assets/model.js`, `assets/styles.css`, and `data/status.json`. It rejects linked or changing source files and excludes `companion/`, including the observer client and private endpoints.

Before copying or serving the checked-in snapshot, both the builder and the companion's file provider validate the bytes against the strict public contract in `cockpit/assets/model.js` (`parsePublicSnapshot`), rejecting unknown fields and snapshots larger than 65,536 bytes. They publish the exact bytes that passed validation. The builder also requires the snapshot's GATE version to match `package.json`; invalid data aborts the build, while the companion returns an unavailable response. Schema validation is not a substitute for reviewing sample values for sensitive content.

The Pages workflow deploys that allowlisted artifact at `https://smurfturfpawpaw.github.io/GATE/` after GitHub Pages is configured to use GitHub Actions. The page stays an explicit **PUBLIC PREVIEW · NO LIVE DATA**, accepts no observed snapshots, and links directly to the authoritative authenticated cockpit at `https://gate.giovannicallebaut.com/`. The two surfaces use the same checked-in interface but different data adapters and trust boundaries.

The visible Site and GATE badges identify the loaded static shell and repository package. The current fleet protocol does not carry the observer executable build or remote runner executable build, so these badges do not detect a live-process build mismatch. `/healthz` exposes the observer build locally for diagnostics, while runner attestation remains a separate deployment concern. Adding a cross-process build attestation would require a new signed, bounded runner/observer contract and is intentionally outside this cockpit KPI migration.

If a Codex turn fails while thread startup succeeds, refresh the Codex CLI login and restart the companion. The browser receives only a categorical failed event; authentication diagnostics remain in the launching terminal or Codex login flow.
