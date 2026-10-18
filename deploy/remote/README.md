# Remote cockpit deployment scaffold

This directory is a provider-neutral starting point for one remote cockpit case. It contains no credentials, private keys, provider tokens, resolvable hosts, or deploy action. Copy the examples into private owner-only paths and replace every example value before starting a service.

The scaffold deliberately contains no container image. The coordinator needs an identity-aware HTTPS gateway that removes client-supplied assertion headers, and that boundary depends on the selected host and identity provider. A generic public container or static-site deployment would omit that control. The optional systemd unit keeps the Node coordinator on loopback and leaves TLS/OIDC termination to a separately reviewed gateway on the same host.

Read [Remote cockpit bridge](../../docs/remote-cockpit.md) before using these files.

## Files

- `server-config.example.json` matches the coordinator CLI's exact configuration shape. Every hostname, identity, case, and path is non-working example data.
- `runner.env.example` lists the exact laptop runner variables without values that could authenticate a deployment.
- `gate-remote@.service.example` is an optional hardened systemd coordinator template. It assumes a protected checkout at one reviewed immutable GATE commit under `/opt/gate`, the exact protected Linux x64 Node.js 24.19.0 installation used by this repository's setup guide, and a dedicated `gate-remote` service user. Replace that exact executable path for another supported architecture or reviewed Node release. Do not point the unit at a moving branch or user-writable runtime.

## Prepare one coordinator instance

The coordinator host needs the reviewed Node runtime and GATE source before an instance can start. Follow the administrator-owned Node 24 installation and integrity checks in [Laptop and cloud setup](../../docs/setup.md#1-prepare-wsl2-on-windows)—that official binary block is also usable on Linux x64 and ARM64 coordinator hosts—or use an equivalently protected distribution package that satisfies Node.js 22.20 or newer and provides `node:sqlite`. Do not use a service-user-owned runtime or a user-writable Node manager.

Create the non-login service identity once. These commands assume a Linux host with `useradd`; use the distribution-equivalent system-account command when it differs:

```bash
(
  set -e
  getent group gate-remote >/dev/null 2>&1 || \
    sudo groupadd --system gate-remote
  getent passwd gate-remote >/dev/null 2>&1 || \
    sudo useradd --system --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin --gid gate-remote gate-remote
)
```

Install one already reviewed, full 40-character commit into `/opt/gate` as root-owned, read-only source. The staging checkout must already contain that exact commit and a clean tree; fetching and review happen before this installation step. For a first install where `/opt/gate` does not yet exist:

```bash
(
  set -euo pipefail
  reviewed_checkout=/absolute/path/to/reviewed/GATE
  reviewed_commit=0123456789abcdef0123456789abcdef01234567

  test "$(git -C "$reviewed_checkout" rev-parse --verify HEAD)" = "$reviewed_commit"
  test -z "$(git -C "$reviewed_checkout" status --porcelain --untracked-files=all)"
  test ! -e /opt/gate
  sudo install -d -o root -g root -m 0755 /opt/gate
  git -C "$reviewed_checkout" archive "$reviewed_commit" | \
    sudo tar -x --no-same-owner --no-same-permissions -C /opt/gate
  sudo chown -R root:root /opt/gate
  sudo chmod -R u=rwX,go=rX /opt/gate
  printf '%s\n' "$reviewed_commit" | \
    sudo tee /opt/gate.REVIEWED_COMMIT >/dev/null
  sudo chown root:root /opt/gate.REVIEWED_COMMIT
  sudo chmod 0444 /opt/gate.REVIEWED_COMMIT
)
```

Replace the example commit with the exact reviewed head. For an update, build a fresh root-owned release directory and review the unit's new absolute path; do not overlay a moving branch onto the running tree. Verify the paths assumed by the example unit before continuing:

```bash
sudo -u gate-remote test -r /opt/gate/cockpit/remote/server-cli.mjs
test "$(sudo -u gate-remote /opt/nodejs/node-v24.19.0-linux-x64/bin/node --version)" = "v24.19.0"
sudo -u gate-remote /opt/nodejs/node-v24.19.0-linux-x64/bin/node \
  --input-type=module -e 'import "node:sqlite";'
sudo -u gate-remote test ! -w /opt/gate/cockpit/remote/server-cli.mjs
```

The checked-in unit uses the exact Linux x64 Node 24.19.0 path shown above. Change `ExecStart` to the reviewed administrator-owned executable for another supported architecture or Node release, then repeat the checks with that exact path.

Choose a filesystem-safe instance name such as the opaque case ID. As root on the coordinator host:

```bash
install -d -o gate-remote -g gate-remote -m 0700 \
  /var/lib/gate-remote/example-case
install -o gate-remote -g gate-remote -m 0600 \
  /opt/gate/deploy/remote/server-config.example.json \
  /var/lib/gate-remote/example-case/server.json
install -o gate-remote -g gate-remote -m 0600 \
  /secure/transfer/example-case-runner-public.pem \
  /var/lib/gate-remote/example-case/runner-public.pem
```

Edit the private copy of `server.json`. Keep `host` on explicit loopback, assign an unused nonzero port, set the exact external HTTPS origin, and replace every OIDC, operator, case, runner, and absolute-path value. `oidc.operatorSubject` must exactly equal `operatorId`. The identity gateway must inject the configured lowercase `identityAssertionHeader` after authentication and strip the same header from every public request.

Run the CLI directly for the first smoke test:

```bash
sudo -u gate-remote -- /opt/nodejs/node-v24.19.0-linux-x64/bin/node \
  /opt/gate/cockpit/remote/server-cli.mjs \
  --config /var/lib/gate-remote/example-case/server.json
```

For systemd, review the example, install it as `/etc/systemd/system/gate-remote@.service`, then enable only the configured instance:

```bash
sudo install -o root -g root -m 0644 \
  /opt/gate/deploy/remote/gate-remote@.service.example \
  /etc/systemd/system/gate-remote@.service
sudo systemd-analyze verify /etc/systemd/system/gate-remote@.service
systemctl daemon-reload
systemctl enable --now gate-remote@example-case.service
systemctl status gate-remote@example-case.service
```

The unit is not an identity gateway. Do not publish the loopback port directly. Configure the selected gateway separately, keep the assertion-header trust boundary on the coordinator host, and limit `/healthz` and `/readyz` to the platform health path.

The gateway must implement the exact route split in [Browser and operator identity](../../docs/remote-cockpit.md#browser-and-operator-identity). Browser assets, `/data/status.json`, and cockpit API routes require interactive OIDC and a freshly injected verified assertion. `/api/runner/v1/*` must reach the same HTTPS origin without an interactive-login redirect, with the identity assertion stripped and the five `X-GATE-*` signature headers and body preserved. Apply independent edge rate and abuse controls to browser and runner route classes so unsigned runner traffic cannot starve the authenticated browser or enrolled runner; the coordinator's separate post-authentication budgets do not replace those controls. Health endpoints stay host- or private-monitor-only, and every unlisted path is denied. The scaffold intentionally does not supply the provider-specific DNS, certificate, OIDC client, or gateway configuration.

## Prepare the laptop runner

Generate the Ed25519 key on the laptop and copy only the public key to the coordinator:

```bash
runner_state="$HOME/.local/share/gate/remote/example-case"
install -d -m 0700 "$runner_state"
umask 077
openssl genpkey -algorithm ED25519 \
  -out "$runner_state/runner-private.pem"
openssl pkey -in "$runner_state/runner-private.pem" -pubout \
  -out "$runner_state/runner-public.pem"
chmod 0600 "$runner_state/runner-private.pem" "$runner_state/runner-public.pem"

# Keep the remote thread's login and state separate from the interactive Codex home.
remote_codex_home="$runner_state/codex-home"
install -d -m 0700 "$remote_codex_home"
# If Codex is npm-managed on this laptop, install the reviewed runner version exactly.
npm install --global --prefix "$HOME/.local" @openai/codex@0.159.2
export PATH="$HOME/.local/bin:/usr/local/bin:$PATH"
test "$(codex --version)" = "codex-cli 0.159.2"
CODEX_HOME="$remote_codex_home" codex login
CODEX_HOME="$remote_codex_home" codex login status
```

Transfer `runner-public.pem` through the operator's reviewed private channel. Do not copy the private key to the coordinator. Copy `runner.env.example` to an owner-only local file, replace every value, then load it in the terminal that will keep the runner open:

```bash
install -m 0600 deploy/remote/runner.env.example \
  "$runner_state/runner.env"
# Edit the owner-only copy, then:
set -a
. "$runner_state/runner.env"
set +a
npm run cockpit:remote:runner
```

Run that command from the reviewed GATE checkout that contains `package.json`. The runner is an operator-attended foreground process in this release. A closed terminal, logout or WSL shutdown, laptop sleep or reboot, or lost network stops live steering; the coordinator remains reachable but must show the runner and its projections as stale or unavailable. When the laptop returns, reload the same environment and start the runner again. Its owner-only journal and thread record preserve the case binding, but an ambiguous or failed command must be reconciled before manual retry.

No laptop service definition is supplied. Do not use an unconditional shell or service restart loop: permanent authentication, signature, session-revision, Codex-boundary, and configuration failures deliberately stop the runner. Any future supervised wrapper must distinguish permanent from transient exits, keep all state owner-only, send a clean termination signal, and enforce one process per journal.

The thread record must be a direct child of the journal directory. The v3 lifecycle performs the version, home, and effective-configuration preflight before writing any record. Immediately before `thread/start` it writes `creating`; after a valid start response it writes `provisional`; immediately before the first `turn/start` request it durably writes `used`. Only `used` records are resumed. An intentional clean stop closes app-server and removes a never-used `provisional` record, so the next start creates a fresh thread. A `creating` or `provisional` record found at startup, or any failed resume of a `used` record, is ambiguous and stops without creating another thread. Reconcile it explicitly; do not delete it merely to make the runner start.

`GATE_REMOTE_CODEX_HOME` is required, must name that owner-only directory directly under the journal directory, and must not point at the operator's normal interactive Codex home. Remote protocol and feature controls are pinned to Codex CLI/app-server `0.159.2`; both the explicit `codex --version` preflight above and the runner's initialized app-server version check must pass. The runner pins the dedicated home instead of inheriting ambient `CODEX_HOME`, `HOME`, or XDG locations, removes ambient API keys, repository tokens, proxy credentials, runner settings, and language-loader variables, and requires its stored login. Before creating or resuming a thread, it asks app-server for the effective configuration at the selected checkout and stops if any MCP server is configured, the legacy out-of-sandbox `notify` command is not empty, or its fixed app, plug-in, hook, browser/computer-use, web-search, code-mode, memory/history-notes, or orchestrator-MCP disables are not effective. Thread creation also supplies empty dynamic-tool, capability-root, and environment lists; every turn keeps environment access empty. The local cockpit companion retains its ordinary local configuration.

Thread records created before `gate.remote-runner-thread/v3`, including v2 records, are rejected. They either do not prove that hidden dynamic-tool and capability-root state was empty or mark a thread resumable before its first turn made the app-server thread durable. Stop the old runner, preserve its record for reconciliation, select a new unused `GATE_REMOTE_THREAD_ID_FILE` directly under the same journal, and let the updated runner create a fresh boundary-bound thread. A v3 record is bound to the exact dedicated Codex home, app-server version, remote boundary revision, and posture; changing one requires the same fresh-thread procedure.

The CLI also creates `<journal-dir>/.remote-runner.lock` so two runners cannot own one journal and thread. A clean `SIGINT` or `SIGTERM` removes it. After an unclean exit, first verify that no runner process still owns that state directory, then remove only the proven-stale lock and record the recovery. Never remove it merely to make a second runner start.

## Verification before exposure

Keep the external DNS name private or access-restricted until the checks in [Readiness check](../../docs/remote-cockpit.md#readiness-check) pass. In addition, verify that:

- direct connections to the coordinator port are reachable only from the host;
- sending the assertion header from an unauthenticated public client does not reach the coordinator as trusted input;
- an unauthenticated browser request cannot reach any browser or cockpit API route, while a signed runner request reaches `/api/runner/v1/*` without an interactive-login redirect;
- the authenticated browser can fetch `/data/status.json`, and repeated unsigned runner requests are edge-limited without spending the authenticated browser or enrolled-runner budgets;
- the public hostname does not route `/healthz`, `/readyz`, or an unlisted path;
- the gateway preserves all five runner signature headers, exact request path, and body bytes, and strips the identity assertion from runner requests;
- the external response sets the `__Host-gate-session` cookie only over HTTPS;
- a coordinator restart preserves SQLite state and invalidates its in-memory browser sessions;
- a runner restart resumes its thread record and replay journal;
- the public Pages artifact still excludes `cockpit/remote/`.

Use a separate instance directory, database, runner key, session revision, gateway hostname, runner state directory, dedicated Codex home, thread record, and `GATE_REPO` working directory or checkout for each concurrent case. These are protocol, state, and context boundaries. They are not filesystem, credential, process, kernel, or operating-system isolation, and a separate checkout under the same account is still readable by that account. Use a separate operating-system account or VM for each case when one case must be confidential from another.
