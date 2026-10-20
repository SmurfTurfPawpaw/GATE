# Remote cockpit bridge

The remote cockpit bridge makes the progress-first cockpit reachable through an authenticated HTTPS origin while GATE and Codex continue to run on the operator's laptop. It is a separate deployment path from both the public GitHub Pages preview and the loopback-only local companion.

The repository contains the coordinator, browser adapter, durable protocol store, and outbound runner. That code does not make the published Pages site live by itself. A working deployment still needs an always-on coordinator host, a public HTTPS origin, an identity gateway, durable storage, an enrolled runner key, and a laptop runner with a working Codex login.

## What each surface is

| Surface | Where it runs | Interactive | Runtime connection |
| --- | --- | --- | --- |
| Public Pages preview | `https://smurfturfpawpaw.github.io/GATE/` | No | Checked-in synthetic data only |
| Local companion | Operator laptop, loopback only | Yes | One dedicated local Codex app-server thread |
| Remote cockpit | `https://gate.giovannicallebaut.com/` behind the authenticated HTTPS coordinator | Yes | One dedicated Codex app-server thread plus the runner's bounded current projections |

The remote runner does not attach to this Codex cloud conversation, an arbitrary Codex Desktop conversation, or a hidden existing thread. Starting it creates or resumes a separately configured dedicated app-server thread. The browser can send bounded messages and answer native choice questions in that thread. It receives the operator-visible conversation, categorical activity, bounded fleet state, token counters, and an optional operational-mirror projection that the runner is allowed to project.

GitHub Pages remains an explicit **PUBLIC PREVIEW · NO LIVE DATA** build. It publishes only the static allowlist documented in [Public snapshot integration](local-companion.md#public-snapshot-integration), shows synthetic mirror entries, and links to the authenticated personal-domain cockpit. The remote browser adapter and every coordinator or runner module stay out of that artifact.

## Architecture

```mermaid
flowchart LR
    B[Operator browser] -->|HTTPS + identity assertion| G[TLS and OIDC gateway]
    G -->|loopback HTTP; trusted assertion header| C[Case-bound coordinator]
    C --> D[(Durable SQLite store)]
    L[Laptop runner] -->|outbound HTTPS; signed requests| G
    L --> X[Dedicated Codex app-server thread]
    L --> O[Optional loopback observer]
```

The browser never receives a runner private key, provider token, OIDC client secret, Codex credential, or internal thread identifier. The coordinator never opens an inbound connection to the laptop. The laptop runner polls the coordinator over outbound HTTPS, leases one command, records it in an owner-only deduplication journal before dispatch, reports its lifecycle, and uploads bounded projections.

The first release binds one coordinator instance and one runner to one operator subject, one case ID, and one positive session revision. The reviewed systemd and Cloudflare bundles support exactly one case per VPS: every coordinator service would otherwise run as the same `gate-remote` UID and could cross another instance's file permissions. Run concurrent cases on separate VPSes with separate databases, runner keys, HTTPS hostnames, and service stacks. Each laptop runner also needs its own journal, dedicated Codex home, and working directory or checkout. A hostname boundary prevents the fixed secure session cookie from colliding between cases. The underlying store keys records by case, but the current server and runner configurations deliberately accept only one case binding per process.

Those boundaries separate protocol identity, durable state, retries, and model-thread context. They do not create filesystem, process, credential, kernel, or operating-system isolation. A separate working directory reduces accidental cross-case context, but another process under the same laptop account can still reach anything that account can reach, and the Codex sandbox is not a confidentiality boundary. Use a separate operating-system account or a separate VM for each case when cases must be confidential from one another.

## Browser and operator identity

Put the coordinator behind a TLS-terminating, identity-aware reverse proxy. The proxy must:

- authenticate the operator on browser routes and inject the configured assertion header only after that authentication;
- remove any assertion header supplied by a public client before applying the route-specific behavior below;
- preserve the exact public `Host` and report `X-Forwarded-Proto: https` on the loopback hop;
- expose one exact HTTPS origin with no path prefix;
- avoid caching cockpit, API, and event-stream responses;
- forward server-sent events without buffering.

Configure the gateway by exact route class. Do not apply one global interactive-OIDC rule to the whole hostname: the laptop runner has no browser login session and authenticates itself with its signed request.

| Path | Gateway authentication and header behavior | Exposure rule |
| --- | --- | --- |
| `/`, `/index.html`, `/assets/*`, `/remote/client.js`, `/data/status.json`, `/robots.txt`, `/.nojekyll`, `/api/cockpit/v1/*` | Require the operator's interactive OIDC session. Remove every client-supplied copy of the configured identity assertion header, then inject one current provider-signed JWT for the authenticated operator. | Browser only. Disable caching; disable buffering and extend streaming timeouts for `/api/cockpit/v1/events`. |
| `/api/runner/v1/*` | Do not require or redirect to interactive OIDC. Remove the identity assertion header and do not inject one. Preserve the request method, exact origin-form path, body bytes, and `X-GATE-Runner`, `X-GATE-Timestamp`, `X-GATE-Nonce`, `X-GATE-Body-SHA256`, and `X-GATE-Signature` headers; the coordinator verifies their Ed25519 signature. | Laptop runner only over HTTPS. Do not expose any unsigned bypass or service-token substitute. |
| `/healthz`, `/readyz` | No OIDC assertion is needed because the coordinator returns only bounded health state. | Keep on the host or a private platform-health network. Do not route these paths from the public hostname. |
| Every other path | None. | Deny at the gateway. |

For every proxied browser or runner request, preserve the exact public `Host`, set `X-Forwarded-Proto: https`, keep the path unchanged, and send it only to the configured loopback listener. A provider-specific gateway configuration is still required; the table above is the contract that configuration must implement.

Apply gateway rate and abuse controls separately to the browser and runner route classes before requests reach Node. Invalid or unsigned runner traffic must not consume the authenticated browser allowance or the allowance reserved for the enrolled runner. The coordinator also keeps independent windows for public/static requests, authenticated browser requests, and signature-verified runner requests, but those post-authentication windows do not replace edge controls against volumetric traffic or repeated signature-verification work.

The coordinator validates the assertion itself against an exact issuer, audience, immutable operator subject, the reviewed `RS256` or `ES256` algorithms, and a public HTTPS JWKS endpoint. It does not accept an arbitrary email or display name as the identity binding. Browser sessions use a random `__Host-gate-session` cookie with `Secure`, `HttpOnly`, `SameSite=Strict`, and `Path=/`. Every page bootstrap or refresh must present a fresh proxy-injected assertion and `Sec-Fetch-Site: same-origin` to the session endpoint; the cookie alone is insufficient. Writes also require the session's in-memory CSRF value, the exact `Origin`, and a same-origin fetch context.

Do not expose the coordinator directly on a public bind. Its Node server speaks HTTP and is intended to bind to loopback behind the gateway. Health endpoints reveal only service readiness and should be limited to the host or platform health checker.

## Runner identity and command delivery

Enroll one Ed25519 public key in the coordinator and keep its private key in an owner-only file on the laptop. Every runner request signs the protocol version, runner ID, HTTP method, exact path, timestamp, nonce, and SHA-256 of the body. The coordinator enforces the configured clock-skew window and one-time nonce use. TLS is still required; signatures authenticate the runner and bind the request but do not provide transport confidentiality.

Commands are durable and case-bound. Request IDs are idempotent within the exact operator subject, case ID, and session revision rather than the ephemeral browser-cookie session: after a refresh, retrying the same ID and payload returns the original receipt, while changing the payload is a conflict. The browser keeps a bounded tab-session retry index containing only that case and revision, request IDs, question tokens, and SHA-256 payload digests; operator messages and answer text are never written to browser storage. The refreshed session can therefore recover the original ID when the operator retries the same payload, while a different case or revision cannot reuse it. The refreshed session can also replay that scope's existing lifecycle events. The original browser-session ID remains recorded as command provenance, but it is neither the deduplication key nor an event-visibility boundary. Every refresh still verifies a fresh OIDC assertion, revokes the replaced page session, and issues a new CSRF proof. The browser receives a queued receipt rather than a claim that Codex completed the work. The runner reports `accepted`, `running`, and a terminal `completed` or `failed` command transition. Here, `completed` means the local `CodexCompanionAdapter` accepted the message, steer, or question response; it does not mean the Codex turn finished. Turn progress and the final visible reply arrive separately through state and activity projections. A `running` command whose lease is abandoned becomes `failed`; its delivery outcome is unknown and the coordinator never dispatches it again. Expiry, lease identity, payload digests, session revision, and the runner's owner-only journal prevent an old or replayed command from being silently dispatched as new work. Rotating the session revision invalidates stale browser and runner state.

Runner telemetry and conversation delivery have separate lifecycles. If the
dedicated Codex app-server is unavailable at startup or closes later, the
runner process keeps sending signed
heartbeats, explicit `codex.state=offline` state projections, and observer
fleet/campaign projections. It clears unanswerable pending questions and
withholds stale session-token totals. The cockpit labels this state `CONNECTED ·
FLEET · CODEX OFFLINE`, keeps current campaign and pilot KPIs visible, and
disables message and question submission. The runner does not call the lease
endpoint while conversation delivery is unavailable or quarantined.

An idle loss can reconnect automatically with bounded exponential backoff and
a bounded create/connect attempt, but only by resuming the exact already-used
thread from its owner-only record. The last readable adapter state must have
been `idle` with no pending question, the runner journal must contain no
unresolved accepted command, and the replacement must pass the complete remote
state projection contract before adoption. A newly created `provisional`
thread cannot be resumed automatically because it has not crossed the durable
first-turn boundary; the runner keeps telemetry live and leaves conversation
offline instead of starting a different thread. Startup failure has no trusted
connected-idle snapshot, so it also stays conversation-offline until the
operator restores or reconciles that exact adapter boundary.

Loss during delivery, a `working` or `waiting` turn, an uncertain terminal
transition, or an unresolved journal entry quarantines conversation dispatch.
That hold survives runner restart. A coordinator transition to `failed` after
lease abandonment still means delivery outcome unknown; it does not clear the
local hold. Reconcile the surviving journal and exact thread before following
the rotation procedure below. A command leased during the close race is not
accepted or delivered, and further leases remain suppressed through its
server lease deadline plus the protocol's maximum accepted clock-skew margin.

The runner has one conversation-only posture. It pins Codex app-server thread creation, resume, and every turn to approval policy `never` and sandbox mode `read-only`, verifies that app-server reports those effective settings, and disables network and environment access. It will not attach remote steering to a turn that was already active when the thread was resumed because that turn's original posture cannot be proven. Thread creation supplies empty dynamic-tool, selected-capability-root, and environment lists. The app-server process receives fixed flags that disable apps, plug-ins, hooks, browser and computer use, code mode, image generation, memories and history-notes tooling, both multi-agent implementations, tool suggestion, web search, orchestrator MCP, local shell and unified execution, filesystem and image inspection, skill search, worktrees, and workspace-dependency tools. It also replaces the legacy out-of-sandbox `notify` command with an empty list. Before any thread is created or resumed, the adapter reads the effective configuration for the selected checkout and fails closed unless every fixed disable is effective, legacy `notify` is empty, and the MCP server map is empty. The dedicated thread can exchange bounded messages and native choices; it cannot inspect or edit the checkout, run tests, or invoke a local tool.

The loopback local companion keeps its normal locally configured posture. The remote child receives only a small operating-system, path, locale, home, and Codex-home environment allowlist; ambient API keys, repository tokens, proxy credentials, runner configuration, and language-loader variables are omitted. It uses a required owner-only Codex home directly under that case's runner journal instead of inheriting the interactive Codex home. Authenticate that dedicated home explicitly; environment-only API keys are intentionally unavailable.

The fixed boundary keeps the dedicated child free of ambient credentials and does not pass `GATE_HOME`, private case state, or target execution adapters into Codex. Model requests and the signed coordinator polling connection still require their documented network paths. A same-user process that rewrites the dedicated Codex home, project configuration, or runner code while the runner is active remains inside the laptop trust boundary.

The remote bridge does not authorize or execute active target operations. A future active-operation lane needs a typed, case-bound controller outside Codex that consumes an authenticated, single-use operator capability for one exact admitted manifest digest through the existing engagement broker. Model-generated confirmation strings, raw command arguments, target values, private paths, and `GATE_HOME` must not cross the Codex tool boundary.

The runner needs:

- outbound HTTPS access to the exact coordinator origin;
- administrator-owned Node.js 22.20 or newer, exact administrator-owned Codex CLI/app-server `0.159.2`, and a working login in the case's dedicated remote Codex home;
- the GATE checkout and a dedicated Codex working directory or checkout for this case;
- one case ID, runner ID, and session revision matching the coordinator;
- an owner-only Ed25519 private-key file and owner-only journal directory;
- optional access to the loopback observer when fleet projection is wanted.

Keep the runner on the laptop that is meant to perform the work. The remote bridge does not move target tools, browser sessions, local evidence, or host capabilities into the coordinator.

## Data boundary

The coordinator persists only the remote protocol's bounded records:

- operator messages and choice answers accepted into the command queue;
- command digests, leases, lifecycle events, expiry, and idempotency identifiers;
- bounded operator-visible messages and final Codex replies;
- bounded native choice questions;
- categorical activity, bounded fleet state, aggregate token counters, and the optional bounded operational mirror;
- case, operator-subject, runner, browser-session, and session-revision bindings.

Resumed threads use the companion's [bounded conversation restoration](local-companion.md#start-it). The remote projection further bounds each message to 1,000 Unicode characters, 2,000 UTF-8 bytes, and 24 lines, adding an explicit truncation notice. It also marks omitted earlier entries. Questions whose headers, text, or options exceed the remote display contract are withheld as a whole, preserving answer identity; the conversation directs the operator to answer locally. When Codex is waiting without a displayable question, the cockpit shows `Open laptop`.

Automatic categorical activity and ordinary fleet/state fields do not carry hidden reasoning, system or developer instructions, command lines, arguments, stdout or stderr, file paths, raw evidence, dedicated target fields, credentials, internal Codex thread IDs, or arbitrary observer responses. The operational mirror is a separate, explicit exception. When `GATE_REMOTE_EXECUTION_MIRROR=1`, the runner can upload an operator-visible work order, deterministic secret-masked command, and up to four bounded lines selected from the final 4 KiB of each supervised run's stdout and stderr, plus structured state, timing, progress, usage, and result fields. Terminal controls are escaped, fidelity and truncation are labelled, and a line that still resembles a credential is withheld as a whole. Private paths, target selectors, raw evidence, credentials, private IDs, hidden reasoning, and unbounded logs remain excluded.

With `GATE_REMOTE_EXECUTION_MIRROR=1`, the runner polls and projects active supervised-run state and the bounded output tail at approximately one-second cadence. This is a near-real-time sequence of bounded snapshots, not byte or PTY streaming. Ordered entries are retained history; the active state and tail change during execution. Transport and browser latency still apply. The cockpit uses `Live` only for a concurrently active run whose runner and projection are connected, current, and authenticated; retained, delayed, stale, disconnected, and unavailable views remain labelled as such.

Remote fleet limits can prune mirror history or leave a campaign's mirror unavailable; see the [operational mirror contract](execution-mirror.md#what-the-mirror-means) for selection and truncation behavior.

Operator messages, final visible replies, rendered native questions, and enabled mirror lines can contain URLs, project context, target names, or a described command, and the coordinator stores their bounded text. Pattern filtering rejects common credential assignments, authorization headers, private-key markers, credential-bearing URLs, and several standalone token families from remote messages, answers, questions, mirrored conversation text, and mirror entries. It is not an exhaustive secret or target-data scanner. Treat the coordinator database as sensitive operator data, keep its service-writable state directory on encrypted persistent storage with owner-only access, and apply a deliberate backup and retention policy. Keep the separate production configuration and runner public key root-owned and read-only to the service. Do not send credentials, raw evidence, or unnecessary exact target details through the remote conversation or mirror.

Raw captures, reports, complete tool output, client material, exact target state, and other private operational evidence remain under `GATE_HOME` on the laptop. The remote projection does not replace the repository's data policy, case binding, engagement receipts, or execution adapters, and a browser message or displayed mirror entry does not itself grant active-operation authority. The [operational mirror contract](execution-mirror.md) defines producer coverage and display bounds.

## Deployment prerequisites

Prepare these before calling the bridge live:

1. One always-on Linux VPS per case, with Node.js 22.20 or newer and persistent local storage. The runtime must include `node:sqlite`.
2. A dedicated DNS name and valid TLS certificate for that case. Every concurrent case needs another VPS and hostname.
3. An identity-aware reverse proxy and an OIDC provider that can supply an `RS256`- or `ES256`-signed assertion with a stable subject. Record the exact issuer, audience, subject, JWKS URL, and private assertion-header name.
4. A root-owned, `gate-remote`-group-readable coordinator configuration and runner public-key enrollment, mode `0640` or `0440`, under `/etc/gate-remote/CASE`, plus a separate service-owned SQLite state directory under `/var/lib/gate-remote/CASE`. Do not put private keys or OIDC client secrets in Git or an image.
5. An Ed25519 runner keypair generated on the laptop. Transfer only the public key to the coordinator and keep the private key owner-only.
6. A laptop runner with a dedicated owner-only Codex home directly under its owner-only journal, Codex authenticated in that home, the exact public HTTPS coordinator origin, and matching case/session bindings.
7. Host monitoring for `/healthz` and `/readyz`, durable-volume backup, disk exhaustion, certificate expiry, runner heartbeat loss, and service restart.

Use separate operating-system identities or machines for the coordinator and its reverse proxy when practical. The proxy is trusted to authenticate the browser and protect the assertion header. The coordinator host is trusted with queued operator text, final visible replies, and bounded operational projections. The laptop remains trusted with Codex credentials, GATE private state, tools, and evidence.

## Configuration and entrypoints

The coordinator accepts one absolute JSON configuration through `--config` or `GATE_REMOTE_CONFIG`. Production uses `/etc/gate-remote/CASE/server.json` and `/etc/gate-remote/CASE/runner-public.pem` as protected `root:gate-remote` files with mode `0640` or `0440`; the service can read but cannot change them. An administrator-owned configuration anchors the public key's trust class, so startup rejects a key owned by the service identity even when that key is owner-only. Only `/var/lib/gate-remote/CASE` is service-writable, and it contains only `bridge.sqlite` plus transient SQLite WAL/SHM files. The configuration contains the exact public origin, loopback host and port, operator/case/session binding, absolute SQLite `databasePath`, OIDC verifier settings, assertion-header name, and `runner.publicKeyPath`. Administrator ownership is enforced as this production trust boundary only on POSIX; the reviewed deployment is the Linux VPS path.

After the identity application exists and its exact origin, issuer, audience, JWKS URL, and stable verified operator subject are known, `./bin/gate.mjs remote init` records this split through `--coordinator-config-root` and `--coordinator-state-root`. Both roots must be absolute, normalized, non-root paths and cannot overlap. The generated case bundle remains owner-only under local `GATE_HOME`; transfer only its coordinator config and runner public key, then install them with the production ownership above. Start the deployed coordinator with:

```bash
npm run cockpit:remote:server -- --config /etc/gate-remote/CASE/server.json
```

The laptop runner accepts the coordinator origin, case/session/runner binding, private-key path, journal directory, dedicated Codex home, and thread-record path as flags or `GATE_REMOTE_*` environment variables. The Codex home must be an existing owner-only directory directly under the journal. The runner posture is fixed in code to conversation-only with a read-only sandbox and disabled local tools. `GATE_REPO` selects the dedicated thread's working directory for configuration lookup, but the remote thread has no local filesystem or execution tools. That directory must exist and its resolved path must not traverse symbolic links. `remote init` and `remote doctor` reject overlap in either direction with `GATE_HOME`; runner startup independently rejects overlap with the journal, dedicated Codex home, private-key directory, or thread-record path. Keep the working directory outside private state rather than using a parent directory that contains it. `GATE_OBSERVER_URL` selects the exact loopback fleet endpoint. `GATE_REMOTE_EXECUTION_MIRROR=1` explicitly enables the secret-masked, bounded execution projection; its default is disabled. Give each concurrent case its own `GATE_REPO` directory or checkout even when the source revision is the same. Create and authenticate the dedicated home, then start the runner after loading the owner-only configuration:

```bash
runner_state="${GATE_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/gate}/remote/example-case/runner"
remote_codex_home="$runner_state/codex-home"
test -d "$runner_state" && test -d "$remote_codex_home"
export PATH=/opt/codex-0.159.2/bin:/opt/nodejs/node-v24.19.0-linux-x64/bin:/usr/bin:/bin
remote_codex=/opt/codex-0.159.2/bin/codex
test "$("$remote_codex" --version)" = "codex-cli 0.159.2"
CODEX_HOME="$remote_codex_home" "$remote_codex" login
CODEX_HOME="$remote_codex_home" "$remote_codex" login status

generated_runner_environment="$runner_state/runner.env"
test -f "$generated_runner_environment"
set -a
. "$generated_runner_environment"
set +a
# Optional: set this to 1 in the owner-only runner.env before startup.
# export GATE_REMOTE_EXECUTION_MIRROR=1
npm run cockpit:remote:runner
```

Install that exact release with the pinned artifact integrity and protected Node path in [Install the protected remote Codex release](setup.md#install-the-protected-remote-codex-release) before running these commands. The runner drops writable or unprotected `PATH` entries and selects Codex only from the remaining protected directories. The selected executable's resolved real path and every ancestor directory must be administrator-owned and non-writable by the operator. A user-owned installation cannot supply that executable; startup fails if no protected Codex executable is available. The dedicated `CODEX_HOME` remains owner-only and writable because it stores this thread's login and state; it is separate from the protected executable prefix. Load the case-bound `runner/runner.env` generated by `remote init`; the public template is only a variable-shape reference and must not replace it.

The runner can remain foreground-attended with the command above, or run under
the reviewed `gate-remote-runner@.service` user unit described in
[persistent local services](../deploy/local/systemd/README.md). The unit loads
an owner-only copy of the generated case-bound environment and calls this same
runner entrypoint. It restarts abnormal process termination but leaves a clean
exit or permanent identity, signature, session-revision, boundary, or
configuration rejection stopped for review. The runner itself retries
transient coordinator failures with bounded exponential backoff and jitter,
including HTTP 429 and 5xx responses. Never run a foreground process and a
service against the same journal.

The service removes the open-terminal dependency inside a running Linux or
WSL2 instance. It cannot keep Windows awake, resume through laptop sleep, or
start a stopped WSL distribution. Enable systemd and user lingering in WSL2;
use a deliberate Windows Task Scheduler entry if that distribution must start
after Windows boot. Until the laptop, WSL distribution, network, and runner are
back, the coordinator can remain reachable but the runner and its projections
become stale or unavailable. The journal and boundary-bound thread record are
designed to resume the existing runner state after a restart. Check the cockpit
for an ambiguous or failed command before retrying it.

The exact non-secret shapes, key-generation steps, and optional hardened systemd coordinator unit are under [`deploy/remote`](../deploy/remote/README.md). A provider-specific Cloudflare Tunnel and Access bundle for a Linux VPS is under [`deploy/remote/cloudflare-vps`](../deploy/remote/cloudflare-vps/README.md). They are templates rather than a deployment: every example identity, host, path, and case must be replaced, provider credentials stay outside Git, and the readiness checks still have to pass on the actual host. Both reviewed bundles support exactly one case on a VPS; use another VPS for every concurrent case.

## Readiness check

A deployment is ready only when all of these are observed:

- the external browser reaches the exact HTTPS origin through the identity gateway;
- the authenticated browser can load `/data/status.json` without a redirect or gateway denial;
- the browser receives a secure session only for the configured immutable subject;
- `/readyz` reports ready from the platform health path;
- a request receives a durable `queued` receipt, its dispatch lifecycle reaches a terminal state, and the separate state/activity stream later shows the expected Codex turn result;
- the enrolled runner is visible as current, not stale or offline;
- when the operational mirror is enabled, a supervised local fixture appears under the selected attempt with fidelity labels, bounded output, and no secret or private-path disclosure;
- stopping only the dedicated Codex app-server leaves observer fleet telemetry current, shows Codex offline, and prevents command leasing until a reviewed idle replacement resumes;
- state expires when runner updates stop instead of remaining falsely live;
- restarting the coordinator preserves queued state and restarting the runner preserves its deduplication journal;
- the runner rejects an ambient Codex home and stops before thread creation when effective MCP or external-tool configuration is present;
- sustained unsigned runner requests are limited at the gateway without spending the coordinator budgets for the authenticated browser or enrolled runner;
- the public Pages artifact still contains only the static allowlist, says `PUBLIC PREVIEW · NO LIVE DATA`, and shows only synthetic mirror entries.

Until those checks pass on an actual host, describe the remote cockpit as deployable code rather than a live bridge. Neither this repository nor ChatGPT Sites supplies the always-on coordinator, DNS, TLS, identity gateway, persistent volume, or laptop runner automatically.

## Recovery and rotation

Stop the runner before changing its case, key, session revision, dedicated Codex home, pinned app-server version, or remote boundary revision. Preserve its journal until every accepted command is terminal or deliberately retired. The runner holds an instance lock in its journal directory; after an unclean exit, verify that no runner process still owns the directory before removing only the proven-stale lock. The v3 thread record is written as `creating` immediately before thread creation, `provisional` after a valid start response, and `used` immediately before the first turn request. Only `used` resumes. An intentional clean stop removes a never-used provisional record after app-server closes; a `creating` or `provisional` record found at startup remains ambiguous and must stop. A failed `used` resume also stops rather than creating a replacement. Preserve and reconcile ambiguous or pre-v3 records, configure a new unused thread-record filename directly under the journal only after that decision, and let the runner create a fresh boundary-bound thread. Rotate a compromised runner key by removing the old public key from the coordinator, enrolling a new key, incrementing the session revision, and starting a fresh owner-only journal binding. Revoke browser sessions by restarting coordinator session state and require the identity gateway to issue a new assertion.

If coordinator state is lost, do not infer that a command failed or can safely be replayed. Compare the surviving runner journal and Codex thread state, record the ambiguity, increment the session revision, and issue a new request only after deciding whether repeating the action is safe. A stale projection, missing runner, signature error, storage error, or session mismatch must remain visible as unavailable or failed rather than being converted to success.
