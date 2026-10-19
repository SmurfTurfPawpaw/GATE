# Remote cockpit deployment scaffold

This directory is a provider-neutral starting point for one remote cockpit case. It contains no credentials, private keys, provider tokens, or resolvable hosts. Copy the examples into private owner-only paths and replace every example value before starting a service. The manual immutable installer deploys only an exact reviewed coordinator release that an administrator has authorized on the prepared host; it does not provision or host the service.

The scaffold deliberately contains no container image. The coordinator needs an identity-aware HTTPS gateway that removes client-supplied assertion headers, and that boundary depends on the selected host and identity provider. A generic public container or static-site deployment would omit that control. The optional systemd unit keeps the Node coordinator on loopback and leaves TLS/OIDC termination to a separately reviewed gateway on the same host.

> **One case per VPS.** The reviewed systemd and Cloudflare deployment bundles support exactly one remote cockpit case on a VPS. Every coordinator instance would otherwise run as the same `gate-remote` UID, which can cross case-directory permissions and read or change another instance's state. Run every concurrent case on a separate VPS with its own hostname; allocating another port or instance directory on the same VPS is not an isolation boundary.

Read [Remote cockpit bridge](../../docs/remote-cockpit.md) before using these files.

## Files

- `server-config.example.json` matches the coordinator CLI's exact configuration shape. Every hostname, identity, case, and path is non-working example data.
- `runner.env.example` documents the generated laptop runner variable shape and `/runner` layout without values that could authenticate a deployment. It is a reference template; do not copy it over the case-bound `runner/runner.env` created by `remote init`.
- `gate-remote@.service.example` is an optional hardened systemd coordinator template. It resolves one root-owned immutable release through `/opt/gate-remote/INSTANCE/current`, uses the exact protected Linux x64 Node.js 24.19.0 installation from the setup guide, and runs as the dedicated `gate-remote` service user. Replace that exact executable path for another supported architecture or reviewed Node release. Do not point the unit at a moving branch or user-writable runtime.
- `deploy-config.example` is the non-secret shape of the root-owned authorization record for one deployment. It binds the exact reviewed commit, archive SHA-256, installer SHA-256, and readiness port.
- `gate-remote-deployer.sudoers.example` is an optional narrow host template with `env_reset`, `NOSETENV`, a fixed protected path, and an exact administrator-supplied helper digest. `scripts/gate-remote-install-release` is the fixed root-owned release installer; do not install the sudoers template until its digest placeholder is replaced and `visudo` accepts the private copy.
- [`cloudflare-vps/`](cloudflare-vps/README.md) is a provider-specific, non-deployed bundle for a Linux VPS using a named Cloudflare Tunnel, Cloudflare Access, and a loopback-only Nginx route gateway. It preserves the browser/runner route split instead of putting interactive Access in front of the signed laptop runner.

## Prepare the private case bundle with GATE

The setup helper replaces the manual key and environment-file steps for one case. It refuses a `GATE_HOME` that overlaps the repository, creates every directory as `0700` and every file as `0600` on POSIX, generates an Ed25519 key with Node's cryptographic API, and never prints private-key or environment-file contents. It also refuses to replace an existing case.

Run it from the reviewed checkout only after the identity gateway exists and you have its exact HTTPS origin, issuer, audience, JWKS URL, and the intended operator's stable verified subject. Choose `--repo` using the [working-directory boundary](../../docs/remote-cockpit.md#configuration-and-entrypoints) for this case's remote Codex thread. The two coordinator roots describe the eventual VPS layout; both must be absolute, normalized, non-root paths, and they cannot overlap each other. Use a different working directory or checkout for every concurrent laptop runner, and use a separate VPS for every concurrently deployed coordinator.

```bash
./bin/gate.mjs remote init example-case \
  --origin https://gate-case.example.test \
  --issuer https://identity.example.test \
  --audience gate-case.example.test \
  --subject operator-subject-001 \
  --jwks-url https://identity.example.test/.well-known/jwks.json \
  --repo /absolute/path/to/example-case-work \
  --coordinator-config-root /etc/gate-remote/example-case \
  --coordinator-state-root /var/lib/gate-remote/example-case

./bin/gate.mjs remote doctor example-case
```

The generated bundle lives under `$GATE_HOME/remote/example-case`, outside Git:

- `runner/runner-private.pem` stays on the laptop;
- `runner/runner.env` contains the exact case-bound runner settings and stays on the laptop;
- `runner/codex-home/` is the dedicated login home for this remote thread;
- `runner/runner-public.pem` is a local copy used for comparison;
- `coordinator/server.json` is the deployable private coordinator configuration: its runner public-key path uses the exact `--coordinator-config-root`, while its database path uses the exact `--coordinator-state-root`;
- `coordinator/runner-public.pem` is the only key material to transfer and is the deployable enrollment copy of the public key.

The helper prepares files; it does not deploy them. The complete local bundle stays owner-only under `GATE_HOME`, with `0700` directories and `0600` files enforced on POSIX. On the coordinator host, install only `coordinator/server.json` and `coordinator/runner-public.pem` under the exact `--coordinator-config-root` as protected `root:gate-remote` files with mode `0640` or `0440`; the service can read but cannot change them. Create the exact `--coordinator-state-root` as a service-writable `gate-remote` directory; only `bridge.sqlite` and its transient SQLite WAL/SHM files belong there. The generated configuration already names those two roots, so its paths do not need a post-transfer rewrite. If either destination changes, initialize a new case bundle with the correct roots instead of making an untracked edit. Never transfer `runner/runner-private.pem`, `runner/runner.env`, the dedicated Codex home, runner journal, or thread record. The administrator-owned static-file posture is a POSIX ownership control; the reviewed production path is the Linux VPS deployment shown here.

`./bin/gate.mjs remote doctor` is read-only. It checks file types and owner-only modes without repairing them, validates the coordinator and runner bindings, cryptographically compares both public-key copies with the private key, checks Node.js and `node:sqlite`, requires exact Codex CLI `0.159.2`, and checks login status using only the dedicated Codex home and a narrow environment. Probe output is discarded. An exit status of zero means the local bundle is prepared; it deliberately reports the identity gateway and live round trip as `unverified` until those checks run on the deployed host.

Authenticate the generated dedicated home before expecting the doctor to pass:

```bash
runner_state="${GATE_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/gate}/remote/example-case/runner"
remote_node=/opt/nodejs/node-v24.19.0-linux-x64/bin
export PATH="/opt/codex-0.159.2/bin:$remote_node:/usr/bin:/bin"
CODEX_HOME="$runner_state/codex-home" /opt/codex-0.159.2/bin/codex login
CODEX_HOME="$runner_state/codex-home" /opt/codex-0.159.2/bin/codex login status
./bin/gate.mjs remote doctor example-case
```

## Prepare one coordinator instance

The coordinator host needs Linux with `/bin/bash`, systemd and procfs, GNU coreutils (including the reviewed `dd` flags used for bounded no-follow archive copying), an `awk` implementation, `curl`, GNU findutils, `flock` from util-linux, `gzip`, GNU tar, the reviewed Node runtime, and GATE source before an instance can start. On Ubuntu 24.04, install the non-base command dependencies with `sudo apt install --yes ca-certificates curl findutils gawk gzip tar util-linux`; use the distribution-equivalent protected packages elsewhere. Follow the administrator-owned Node 24 installation and integrity checks in [Laptop and cloud setup](../../docs/setup.md#1-prepare-wsl2-on-windows)—that official binary block is also usable on Linux x64 and ARM64 coordinator hosts—or use an equivalently protected distribution package that satisfies Node.js 22.20 or newer and provides `node:sqlite`. Do not use a service-user-owned runtime or a user-writable Node manager.

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

Install one already reviewed, full 40-character commit into a case-specific, root-owned, read-only release directory. The staging checkout must already contain that exact commit and a clean tree; fetching, testing, and No Mistakes review happen before this installation step. The administrator must verify that the review attestation names the same exact head before writing the authorization record. A changed head needs a new review and a new record.

A clean host uses two installer phases. `--stage-only` first verifies the authorization, bounded archive, and members and creates the immutable release without reading or changing `current` and without calling systemd. Install the protected configuration, writable state directory, and unit from that explicit staged release, then reload systemd. Only then run the same installer command without `--stage-only`; that activation changes `current` atomically, restarts the prepared unit, verifies readiness, and restores the prior release link if readiness fails. The transaction covers the immutable release link and service restart. Configuration, units, runtimes, gateway files, and other host dependencies are separate administrator-managed state.

First install the reviewed helper at its fixed protected path and create its protected configuration directories:

```bash
(
  set -euo pipefail
  reviewed_checkout=/absolute/path/to/reviewed/GATE
  installer_source="$reviewed_checkout/deploy/remote/scripts/gate-remote-install-release"
  test -f "$installer_source"
  sudo test -d /usr/local
  sudo test ! -L /usr/local
  sudo install -d -o root -g root -m 0755 /usr/local/sbin
  sudo /bin/bash --noprofile --norc -c '
    set -euo pipefail
    for directory in /usr/local /usr/local/sbin; do
      test -d "$directory" && test ! -L "$directory"
      identity=$(stat -c "%u:%a" -- "$directory")
      uid=${identity%%:*}
      mode=${identity#*:}
      test "$uid" = 0
      test $((8#$mode & 8#022)) = 0
    done
  '
  sudo install -d -o root -g root -m 0755 /etc/gate-remote /etc/gate-remote/deployments
  sudo install -o root -g root -m 0755 "$installer_source" \
    /usr/local/sbin/gate-remote-install-release
)
```

Next produce a deterministic archive from the clean reviewed head, calculate the two exact digests, have the administrator install a root-owned authorization record, and stage the release. `deploy-config.example` shows the required four fields. Its values must be literal lowercase digests and the full commit, with no shell expansion or extra fields:

```bash
(
  set -euo pipefail
  reviewed_checkout=/absolute/path/to/reviewed/GATE
  reviewed_commit=0123456789abcdef0123456789abcdef01234567
  deployment=example-case
  archive=/absolute/protected/staging/gate-$reviewed_commit.tar.gz
  authorization=$(mktemp)
  trap 'rm -f "$authorization"' EXIT

  test "$(git -C "$reviewed_checkout" rev-parse --verify HEAD)" = "$reviewed_commit"
  test -z "$(git -C "$reviewed_checkout" status --porcelain --untracked-files=all)"
  git -C "$reviewed_checkout" archive --format=tar "$reviewed_commit" | \
    gzip --no-name --best > "$archive"
  archive_sha256=$(sha256sum "$archive" | awk '{print $1}')
  installer_sha256=$(sha256sum \
    "$reviewed_checkout/deploy/remote/scripts/gate-remote-install-release" | awk '{print $1}')

  cat > "$authorization" <<EOF
HEALTH_PORT=43180
AUTHORIZED_COMMIT=$reviewed_commit
AUTHORIZED_ARCHIVE_SHA256=$archive_sha256
AUTHORIZED_INSTALLER_SHA256=$installer_sha256
EOF
  sudo install -o root -g root -m 0600 "$authorization" \
    "/etc/gate-remote/deployments/$deployment.conf"

  sudo /usr/local/sbin/gate-remote-install-release \
    --deployment "$deployment" \
    --archive "$archive" \
    --archive-sha256 "$archive_sha256" \
    --commit "$reviewed_commit" \
    --installer-sha256 "$installer_sha256" \
    --stage-only

  staged_release="/opt/gate-remote/$deployment/releases/$reviewed_commit"
  sudo -u gate-remote test -r "$staged_release/cockpit/remote/server-cli.mjs"
  sudo -u gate-remote test ! -w "$staged_release/cockpit/remote/server-cli.mjs"
)
```

At this point there is deliberately no `current` link and no service start on a clean host. Never authorize a moving branch, accept hashes supplied by an unreviewed build, or overlay a running release. For every later update, repeat exact-head review, replace the authorization record with the newly reviewed identities, and stage before inspecting any changed unit or configuration dependency. The helper sanitizes its environment before argument parsing, clears `TAR_OPTIONS` and other tool-control variables, disables curl configuration files, and checks the protected helper path. The sudo boundary must still strip caller environment before Bash starts and bind the exact helper bytes.

To grant the optional `gate-deployer` identity only this installer command, replace the sudoers digest token with the exact installed helper SHA-256, validate the resulting private file, and then install it. A new helper requires administrator review and a new sudoers digest before it can run:

```bash
(
  set -euo pipefail
  reviewed_checkout=/absolute/path/to/reviewed/GATE
  installer_sha256=$(sha256sum /usr/local/sbin/gate-remote-install-release | awk '{print $1}')
  sudoers_private=$(mktemp)
  trap 'rm -f "$sudoers_private"' EXIT
  sed "s/REPLACE_WITH_64_CHARACTER_LOWERCASE_INSTALLER_SHA256/$installer_sha256/" \
    "$reviewed_checkout/deploy/remote/gate-remote-deployer.sudoers.example" > "$sudoers_private"
  test -z "$(grep 'REPLACE_' "$sudoers_private" || true)"
  sudo visudo -cf "$sudoers_private"
  sudo install -o root -g root -m 0440 "$sudoers_private" \
    /etc/sudoers.d/gate-remote-deployer
)
```

Choose a filesystem-safe instance name such as the opaque case ID. After staging, prepare the protected configuration trust anchor separately from writable SQLite state. Transfer only the generated coordinator files through the administrator's private channel. As root on the coordinator host:

```bash
sudo install -d -o root -g gate-remote -m 0750 \
  /etc/gate-remote/example-case
sudo install -o root -g gate-remote -m 0640 \
  /secure/transfer/example-case-server.json \
  /etc/gate-remote/example-case/server.json
sudo install -o root -g gate-remote -m 0640 \
  /secure/transfer/example-case-runner-public.pem \
  /etc/gate-remote/example-case/runner-public.pem
sudo install -d -o gate-remote -g gate-remote -m 0700 \
  /var/lib/gate-remote/example-case
```

Review the generated `server.json` before installing it. Keep `host` on explicit loopback, use the bundle's one reviewed nonzero port, set the exact external HTTPS origin, and verify every OIDC, operator, case, runner, and absolute-path value. Its `runner.publicKeyPath` must stay under `/etc/gate-remote/example-case`, and its `databasePath` must stay under `/var/lib/gate-remote/example-case`; the two roots must remain absolute, normalized, non-root, and non-overlapping. `oidc.operatorSubject` must exactly equal `operatorId`. The identity gateway must inject the configured lowercase `identityAssertionHeader` after authentication and strip the same header from every public request.

Install the coordinator unit from the explicit staged release, not from `current` or an unrelated checkout. Reload systemd but do not start or enable the service yet:

```bash
reviewed_commit=0123456789abcdef0123456789abcdef01234567
staged_release="/opt/gate-remote/example-case/releases/$reviewed_commit"
sudo install -o root -g root -m 0644 \
  "$staged_release/deploy/remote/gate-remote@.service.example" \
  /etc/systemd/system/gate-remote@.service
sudo systemctl daemon-reload
```

The checked-in unit uses the exact Linux x64 Node 24.19.0 path. Change `ExecStart` to the exact reviewed administrator-owned executable for another supported architecture or Node release before `daemon-reload`. Verify the runtime and staged entrypoint as the service account:

```bash
test "$(sudo -u gate-remote /opt/nodejs/node-v24.19.0-linux-x64/bin/node --version)" = "v24.19.0"
sudo -u gate-remote /opt/nodejs/node-v24.19.0-linux-x64/bin/node \
  --input-type=module -e 'import "node:sqlite";'
sudo -u gate-remote test -r \
  /opt/gate-remote/example-case/releases/0123456789abcdef0123456789abcdef01234567/cockpit/remote/server-cli.mjs
```

Activate only after all prerequisites above exist. Use the same archive, commit, and hashes authorized during staging, omitting only `--stage-only`. The installer changes `current`, restarts the unit, and requires process-bound loopback readiness before it succeeds. Enable reboot persistence only after that successful activation:

```bash
reviewed_commit=0123456789abcdef0123456789abcdef01234567
archive="/absolute/protected/staging/gate-$reviewed_commit.tar.gz"
archive_sha256=$(sha256sum "$archive" | awk '{print $1}')
installer_sha256=$(sha256sum /usr/local/sbin/gate-remote-install-release | awk '{print $1}')

sudo /usr/local/sbin/gate-remote-install-release \
  --deployment example-case \
  --archive "$archive" \
  --archive-sha256 "$archive_sha256" \
  --commit "$reviewed_commit" \
  --installer-sha256 "$installer_sha256"
sudo systemctl enable gate-remote@example-case.service
sudo systemd-analyze verify /etc/systemd/system/gate-remote@.service
sudo systemctl is-active --quiet gate-remote@example-case.service
sudo systemctl status gate-remote@example-case.service
```

On a later code-only release, the stage phase leaves the running `current` link untouched. Keep the existing unit, coordinator configuration, runner key, protected runtime, health port, and gateway files byte-for-byte unchanged; disable public ingress during the activation; then run the activating invocation. A failed readiness check, `SIGHUP`, `SIGINT`, or `SIGTERM` restores the previous release link and restarts that release under the unchanged dependencies. Do not use `systemctl enable --now` as the first activation because it bypasses the installer's link and readiness transaction.

Changed host dependencies are outside that transaction. Before an update that changes any unit, configuration, public key, runtime, readiness port, Nginx file, or tunnel file, keep the public connector stopped, make a root-only byte-exact backup of every changed file, record its SHA-256 and mode/owner, and confirm the new dependency set works with both the previous and candidate release. If it is not backward-compatible, use a planned maintenance window. On failure, keep ingress stopped, restore every dependency from the protected backup, run `systemctl daemon-reload` when a unit changed, restore or reactivate the previously authorized release, and repeat local process-bound readiness before exposing the connector. The installer does not restore those external files.

`SIGKILL`, kernel failure, and power loss cannot run the rollback trap. After any such interruption, treat `current` and the service as unverified: keep ingress disabled, stop the coordinator, inspect the root-owned `current` target and the previous target recorded before the update, restore external dependency backups if any changed, reactivate the previously authorized release when the candidate has no recorded successful readiness result, and complete the local readiness checks before restarting ingress. The installer deliberately leaves immutable staged releases available for this reconciliation.

The unit is not an identity gateway. Do not publish the loopback port directly. Configure the selected gateway separately, keep the assertion-header trust boundary on the coordinator host, and limit `/healthz` and `/readyz` to the platform health path.

The gateway must implement the exact route split in [Browser and operator identity](../../docs/remote-cockpit.md#browser-and-operator-identity). Browser assets, `/data/status.json`, and cockpit API routes require interactive OIDC and a freshly injected verified assertion. `/api/runner/v1/*` must reach the same HTTPS origin without an interactive-login redirect, with the identity assertion stripped and the five `X-GATE-*` signature headers and body preserved. Apply independent edge rate and abuse controls to browser and runner route classes so unsigned runner traffic cannot starve the authenticated browser or enrolled runner; the coordinator's separate post-authentication budgets do not replace those controls. Health endpoints stay host- or private-monitor-only, and every unlisted path is denied. The scaffold intentionally does not supply the provider-specific DNS, certificate, OIDC client, or gateway configuration.

## Prepare the laptop runner

`./bin/gate.mjs remote init` already generated the Ed25519 keypair, exact runner environment, and dedicated Codex home under the private case bundle. Keep the private key on the laptop and copy only the public enrollment key to the coordinator. Install the pinned administrator-owned Codex release by following [Install the protected remote Codex release](../../docs/setup.md#install-the-protected-remote-codex-release), then authenticate the generated home:

```bash
runner_state="${GATE_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/gate}/remote/example-case/runner"
remote_codex_home="$runner_state/codex-home"
export PATH=/opt/codex-0.159.2/bin:/opt/nodejs/node-v24.19.0-linux-x64/bin:/usr/bin:/bin
remote_codex=/opt/codex-0.159.2/bin/codex
test -d "$remote_codex_home"
test "$("$remote_codex" --version)" = "codex-cli 0.159.2"
CODEX_HOME="$remote_codex_home" "$remote_codex" login
CODEX_HOME="$remote_codex_home" "$remote_codex" login status
```

Transfer `runner-public.pem` through the operator's reviewed private channel. Do not copy the private key to the coordinator. `remote init` already wrote the case-bound owner-only `runner/runner.env`; load that generated file unchanged for a foreground run. `runner.env.example` is only a public shape and layout reference and must not overwrite the generated configuration:

```bash
generated_runner_environment="$runner_state/runner.env"
test -f "$generated_runner_environment"
test "$(stat -c '%a' "$generated_runner_environment")" = 600
set -a
. "$generated_runner_environment"
set +a
npm run cockpit:remote:runner
```

Run that command from the reviewed GATE checkout that contains `package.json`. The remote thread is conversation-only and uses a read-only sandbox with every local filesystem, shell, image, skill, worktree, workspace-dependency, and unified-execution tool disabled. It cannot inspect or edit the checkout, run tests, or contact a target. Active target execution requires the separate typed, case-bound campaign controller and its own exact authority. For foreground-process lifetime, persistent user-service setup, automatic transient retries, and restart handling, follow [Configuration and entrypoints](../../docs/remote-cockpit.md#configuration-and-entrypoints). Reconcile an ambiguous or failed command before manual retry.

The Codex executable is a separate trust boundary from the writable dedicated `CODEX_HOME`. See [Configuration and entrypoints](../../docs/remote-cockpit.md#configuration-and-entrypoints) for protected executable selection and `PATH` filtering.

A tested `gate-remote-runner@.service` user unit and fixed-path renderer are supplied under [persistent local services](../local/systemd/README.md). It loads an owner-only copy of the generated environment and uses `Restart=on-abnormal`: permanent authentication, signature, session-revision, Codex-boundary, and configuration failures deliberately remain stopped. The runner handles transient coordinator failures internally. The unit sends a clean termination signal and must never share one journal with another service or foreground runner.

The thread record must be a direct child of the journal directory. The v3 lifecycle performs the version, home, and effective-configuration preflight before writing any record. Immediately before `thread/start` it writes `creating`; after a valid start response it writes `provisional`; immediately before the first `turn/start` request it durably writes `used`. Only `used` records are resumed. An intentional clean stop closes app-server and removes a never-used `provisional` record, so the next start creates a fresh thread. A `creating` or `provisional` record found at startup, or any failed resume of a `used` record, is ambiguous and stops without creating another thread. Reconcile it explicitly; do not delete it merely to make the runner start.

`GATE_REMOTE_CODEX_HOME` is required, must name that owner-only directory directly under the journal directory, and must not point at the operator's normal interactive Codex home. Remote protocol and feature controls are pinned to Codex CLI/app-server `0.159.2`; both the explicit `codex --version` preflight above and the runner's initialized app-server version check must pass. The runner pins the dedicated home instead of inheriting ambient `CODEX_HOME`, `HOME`, or XDG locations, removes ambient API keys, repository tokens, proxy credentials, runner settings, and language-loader variables, and requires its stored login. Before creating or resuming a thread, it asks app-server for the effective configuration at the selected checkout and stops if any MCP server is configured, the legacy out-of-sandbox `notify` command is not empty, or its fixed app, plug-in, hook, browser/computer-use, web-search, code-mode, memory/history-notes, orchestrator-MCP, local filesystem, shell, image, skill, worktree, workspace-dependency, or unified-execution disables are not effective. Thread creation also supplies empty dynamic-tool, capability-root, and environment lists; every turn keeps environment access empty. The local cockpit companion retains its ordinary local configuration.

Thread records created before `gate.remote-runner-thread/v3`, including v2 records, are rejected. They either do not prove that hidden dynamic-tool and capability-root state was empty or mark a thread resumable before its first turn made the app-server thread durable. Stop the old runner, preserve its record for reconciliation, select a new unused `GATE_REMOTE_THREAD_ID_FILE` directly under the same journal, and let the updated runner create a fresh boundary-bound thread. A v3 record is bound to the exact dedicated Codex home, app-server version, remote boundary revision, and read-only posture; changing one requires the same fresh-thread procedure.

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

The reviewed host bundle is ready for exactly one case. A second case must use another VPS and hostname because both systemd instances would otherwise share the `gate-remote` UID and could cross the configuration and SQLite boundaries. Each laptop runner also needs its own runner key, session revision, journal, dedicated Codex home, thread record, and `GATE_REPO` working directory or checkout. Those laptop paths separate protocol state and model context; another process under the same laptop account can still read that account's files, so use a separate operating-system account or VM when laptop-side confidentiality between cases is required.
