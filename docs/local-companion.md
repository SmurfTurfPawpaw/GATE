# Local cockpit companion

The local companion turns the static cockpit into a private operator surface on the same laptop. It serves the checked-in cockpit, injects an exact browser bridge, owns one dedicated Codex app-server thread, streams categorical activity and aggregate token events, and reads a separate bounded fleet projection from GATE's loopback observer. It does not connect to the current Codex cloud chat or take over an arbitrary Codex Desktop thread.

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

The checked-in `cockpit/data/status.json` is a presentation preview. Static GitHub Pages and a normal preview server remain read-only because neither has the private bridge or capabilities. Through the loopback companion, private conversation, native Codex questions, and the local GATE fleet work independently of that preview snapshot. Missing or invalid preview data does not clear an unsent local message. Public snapshots accept only preview mode; example decisions are disabled. Private choices use native Codex questions.

## What is working

The companion currently provides:

- an exact `gate.local-cockpit-bridge/v1` browser adapter exposing `submitMessage` and `submitQuestion`;
- idempotent receipts that say only that the local companion accepted a request;
- Codex app-server initialization, dedicated thread start or resume, `turn/start`, and `turn/steer`;
- bounded native `item/tool/requestUserInput` choice capture and response in the adapter API;
- a capability-protected private-state API containing only user-visible operator and final Codex messages, dedicated-thread input/cached-input/output/reasoning/total counters, optional estimated cost, turn state, and bounded questions;
- an authenticated server-sent event stream containing only fixed activity categories, lifecycle state, optional completed/total counts, and aggregate token totals;
- an authenticated read-only `/api/fleet` endpoint containing only the exact `gate.local-fleet/v1` projection from GATE's observer;
- immediate browser snapshot refresh signals when an event arrives.

Private operator messages may include URLs and project context. They are limited to 1,000 characters and must not contain credentials or secrets. Native Codex questions are rendered as bounded one-to-three-choice controls, with the recommended option identified explicitly.

The fleet projection shows at most 32 current case rows and 32 current Program Profile rows under process-local `Campaign N` aliases. It carries scan completeness alongside every aggregate. Exact counts appear only when both source scans are complete and every visible case runtime is available; partial coverage uses lower bounds, and unavailable scans never relabel cached rows as current. Case workflow, supervised-run, and offline-analysis counts stay separate. Program Profile answered/total progress is determinate; case completion percentages are unavailable by contract. Per-case canonical token totals preserve exact versus estimated availability, while the fleet total becomes partial or unavailable when any visible total is missing. Host-wide observer input, cached input, output, and total counters are a separate projection and are never substituted for case-bound usage. The cockpit renders missing case data as `Awaiting attribution`.

The generated protocol for Codex CLI 0.159.2 was used to bind `initialize`, `thread/start|resume`, `turn/start|steer`, `turn/started|completed`, `item/started|completed`, `thread/tokenUsage/updated`, and `item/tool/requestUserInput`. Regenerate it for review after a Codex CLI upgrade:

```sh
schema_dir="$(mktemp -d)"
codex app-server generate-json-schema --experimental --out "$schema_dir"
```

## Windows-hosted Codex telemetry from WSL

The observer reads `CODEX_HOME/sessions`. If those files live on Windows, either set a local symbolic path such as `CODEX_HOME=/mnt/c/Users/WINDOWS_USER/.codex` before `npm run dashboard`, or use the safe profile-detection snippet in [Laptop and cloud setup](setup.md#4-run-and-inspect). Do not commit the resolved username or path. This changes only the observer's Codex session source and does not change `GATE_HOME`.

## Visibility boundary

The browser may show the operator's own bounded message and Codex's final user-visible answer in its authenticated private state. It never receives hidden reasoning, system or developer instructions, command lines, arguments, stdout or stderr, file paths, tool names, target selectors, evidence, credentials, internal thread IDs, raw errors, or request bodies through the activity stream. The fleet projection also omits source IDs, case names, program names, targets, tools, prompts, evidence, contacts, raw events, session records, and session paths. It projects only token counters and categorical provenance from host usage.

Item types become fixed categories such as `tool`, `file-change`, `research`, or `agent`. Progress is determinate only when a producer supplies a real completed count and total. Dedicated-thread token state contains exact input, cached-input, output, reasoning-output, and total counters from Codex notifications. When `account/usage/read` returns a matching thread estimate, the browser receives only the estimated USD or credit micros and unit; account summaries, groups, model metadata, thread IDs, and raw responses remain private. Likely credentials are rejected from operator messages and withheld from mirrored Codex answers.

The server binds only to `127.0.0.1` or `::1`. It requires the exact loopback `Host`, rejects foreign origins and cross-site browser requests, requires a random session capability for every private API, and requires a separate CSRF capability plus exact origin for every write. The read-only observer source is fetched by the companion process and exposed only through the session-protected fleet endpoint. Fleet state is never added to a Codex prompt, message, thread state, or app-server request. Bodies, protocol lines, requests, retained events, messages, questions, and observer responses are bounded.

Do not place this listener behind a tunnel, port forward, public reverse proxy, or shared-host bind. The public GitHub Pages build remains a read-only preview and contains no companion endpoint or capability.

## Public snapshot integration

Public snapshots are static examples and cannot accept operator choices or claim live operational state. `npm run cockpit:build` recreates `cockpit/_site` from exactly `.nojekyll`, `index.html`, `robots.txt`, `assets/app.js`, `assets/favicon.svg`, `assets/model.js`, `assets/styles.css`, and `data/status.json`. It rejects linked or changing source files and excludes `companion/`, including the observer client and private endpoints.

Before copying or serving the checked-in snapshot, both the builder and the companion's file provider validate the bytes against the strict public contract in `cockpit/assets/model.js` (`parsePublicSnapshot`), rejecting unknown fields and snapshots larger than 65,536 bytes. They publish the exact bytes that passed validation. The builder also requires the snapshot's GATE version to match `package.json`; invalid data aborts the build, while the companion returns an unavailable response. Schema validation is not a substitute for reviewing sample values for sensitive content.

The Pages workflow deploys that allowlisted artifact at `https://smurfturfpawpaw.github.io/GATE/` after GitHub Pages is configured to use GitHub Actions. The page stays an explicit `PREVIEW · NOT LIVE` and does not accept observed snapshots. Serving it under a path such as `giovannicallebaut.com/bugbounty/` requires that site's host or proxy; a project Pages workflow cannot claim that path by itself.

If a Codex turn fails while thread startup succeeds, refresh the Codex CLI login and restart the companion. The browser receives only a categorical failed event; authentication diagnostics remain in the launching terminal or Codex login flow.
