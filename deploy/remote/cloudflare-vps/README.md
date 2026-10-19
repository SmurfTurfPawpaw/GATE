# Cloudflare Tunnel and Access on a Linux VPS

This is a provider-specific deployment **template**, not evidence of a deployment. It runs the existing GATE coordinator on loopback, puts a loopback-only Nginx route gateway in front of it, and lets a named Cloudflare Tunnel connect outbound from the VPS. Cloudflare Access authenticates browser routes. The laptop runner reaches the same HTTPS hostname through a more-specific Access Bypass application and is authenticated by the coordinator's Ed25519 request signature.

Read the parent [deployment scaffold](../README.md) and [remote cockpit contract](../../../docs/remote-cockpit.md) first. Their protected configuration, owner-only state, laptop runner, recovery, and deployment limitations still apply.

> **This reviewed bundle supports exactly one case per VPS.** Every coordinator systemd instance would run as the same `gate-remote` UID, so separate directories and loopback ports on one VPS would not prevent cross-case access. A concurrent case needs a separate VPS, hostname, tunnel, gateway, and service stack.

## Files and trust boundaries

| File | Purpose |
| --- | --- |
| `access-route-contract.example.json` | Reviewable Cloudflare Access and origin-route contract. It is not an API import. |
| `server-config.cloudflare.example.json` | Coordinator configuration shape populated with Cloudflare Access issuer, audience, subject, and JWKS placeholders. |
| `cloudflared-config.yml.example` | Named-tunnel ingress. Health paths terminate in cloudflared and all other traffic goes only to the loopback Nginx gateway. |
| `cloudflared@.service.example` | Hardened systemd template for one pinned, administrator-owned cloudflared binary and one case configuration. |
| `nginx-gate-remote.conf.example` | Loopback listener, exact public route allowlist, health denial, and default denial. |
| `nginx-browser-proxy.inc.example` | Browser assertion translation and client-header replacement. |
| `nginx-runner-proxy.inc.example` | Runner header stripping and preservation of the five signed headers and request bytes. |
| `readiness-check.sh` | Non-secret host/public smoke checks. It does not log in to Access or send a valid runner signature. |

Every token beginning with `REPLACE_` is deliberately non-secret placeholder text and must be replaced in the private installed copy. The account ID, tunnel UUID, hostname, Access application audience tag, team name, case ID, runner ID, and stable Access `sub` claim are identifiers rather than credentials, but keep the operator subject and private configuration out of public logs.

The following values are secrets and have no checked-in placeholder value: the named-tunnel credentials JSON, IdP or Access OAuth secrets, Access cookies, runner private key, and Codex login. Never place them in this directory, the coordinator config, command arguments, issues, or logs. Only the runner **public** key is copied to the coordinator.

## Exact request path

```text
browser -- HTTPS --> Cloudflare Access allow policy --+
                                                     +--> named Tunnel --> 127.0.0.1:43179 Nginx --> 127.0.0.1:43180 coordinator
laptop runner -- HTTPS --> Access path Bypass -------+
```

The VPS needs no public HTTP or HTTPS listener. Permit the administrator's management path, deny inbound TCP to ports `80`, `443`, `43179`, and `43180`, disable any default Nginx public site, and verify that Nginx and the coordinator listen only on `127.0.0.1`. Cloudflared makes outbound connections to Cloudflare.

Cloudflare Access must have these two self-hosted applications on the same hostname:

1. **Runner application:** `REPLACE_PUBLIC_HOSTNAME/api/runner/v1/*`, with a `Bypass` policy whose include rule is `Everyone`. It must be the more-specific path application. Do not attach an interactive login, service token, browser challenge, or Access JWT injection to this route. Cloudflare WAF or bot settings must not issue an interactive challenge on this path. Independent path-specific rate limits may reject abuse, but valid signed POST bodies and all five `X-GATE-*` signature headers must pass unchanged.
2. **Browser application:** `REPLACE_PUBLIC_HOSTNAME` with no path, with an `Allow` policy restricted to the one intended operator identity at the identity provider. Set the Access application session duration to **1 hour or less**; the example coordinator rejects JWTs whose `exp - iat` exceeds its `oidc.maxTokenLifetimeSeconds` value of `3600`. Do not use Cloudflare's longer default, `Bypass`, or `Everyone` here. Record this application's Access Audience (`AUD`) tag in the coordinator config.

Cloudflare chooses the more-specific application for the runner path. The root browser application covers all remaining paths at the edge; Nginx then allows only the reviewed browser paths and returns `404` for everything else. The tunnel config sends `/healthz` and `/readyz` to cloudflared's built-in `http_status:404` service before Nginx, so the public hostname never reaches the coordinator's health responses. An authenticated request may therefore see `404`; an unauthenticated request may first see the root Access login. Neither response exposes coordinator health. Host monitoring calls the coordinator directly on loopback.

The complete route and header expectations are in `access-route-contract.example.json`. In particular:

- browser paths require Access and arrive with Cloudflare's provider-signed `Cf-Access-Jwt-Assertion`;
- Nginx overwrites any public `X-GATE-OIDC-Assertion` with that Access assertion, then removes the Cloudflare header before proxying;
- runner paths clear both identity assertion headers and forward the exact method, origin-form path, body bytes, and the five runner signature headers;
- `/healthz` and `/readyz` are loopback-only; and
- unlisted paths are denied.

The coordinator independently verifies the Access JWT. For Cloudflare Access, `oidc.issuer` is `https://REPLACE_ACCESS_TEAM_NAME.cloudflareaccess.com`, `oidc.jwksUrl` is that issuer plus `/cdn-cgi/access/certs`, and `oidc.audience` is the browser application's Access AUD tag. `operatorId` and `oidc.operatorSubject` must both equal the immutable `sub` claim from a current, valid operator Access JWT. Do not substitute the email address, display name, account ID, application ID, or tunnel ID.

## 1. Create the named tunnel and hostname

From an administrator workstation that already has reviewed Cloudflare account authentication, create the named tunnel and its exact DNS route before configuring Access or running `remote init`:

```bash
cloudflared tunnel create REPLACE_TUNNEL_NAME
cloudflared tunnel route dns REPLACE_TUNNEL_UUID REPLACE_PUBLIC_HOSTNAME
```

These commands mutate the Cloudflare account and DNS; they are shown for the administrator and have not been run by this repository. Tunnel creation writes a credentials JSON file that authenticates only that connector. Keep it in an administrator-controlled private transfer location, record the returned tunnel UUID, and do not put the credential, account-wide `cert.pem`, or an API token in Git or command arguments. The tunnel can remain offline until Step 4.

## 2. Create Access and obtain the identity bindings

Create the two Access applications described above before running `remote init`. Configure the browser application with the intended identity provider and a session duration no longer than the coordinator's `oidc.maxTokenLifetimeSeconds` (`1h` for the example). Restrict its Allow policy to the exact operator identity. Create the more-specific runner Bypass application at the same time. The hostname may return a tunnel error until the connector is started, but Access identity setup must be complete first.

Obtain and privately record all five inputs from the live Access configuration rather than guessing them:

- exact origin: `https://REPLACE_PUBLIC_HOSTNAME`;
- issuer: `https://REPLACE_ACCESS_TEAM_NAME.cloudflareaccess.com`;
- audience: the root browser application's current Access `AUD` tag;
- JWKS URL: the issuer plus `/cdn-cgi/access/certs`; and
- operator subject: the exact immutable `sub` from a current browser-application Access JWT for the intended operator.

Validate that JWT against the recorded issuer, audience, JWKS, algorithm, and lifetime before trusting its `sub`. Keep the JWT, Access cookie, and decoded private identity response out of shell history, issues, and logs. Do not substitute an email address, display name, account ID, application ID, tunnel ID, or an unverified decoded claim. Changing the Access application can change its AUD; obtain and review the current value again before reinitializing a case.

Only after those values exist, run the repository-local CLI from the reviewed laptop checkout. Replace the example identity values with the private values just obtained:

```bash
./bin/gate.mjs remote init REPLACE_CASE_ID \
  --origin https://REPLACE_PUBLIC_HOSTNAME \
  --issuer https://REPLACE_ACCESS_TEAM_NAME.cloudflareaccess.com \
  --audience REPLACE_ACCESS_APPLICATION_AUD \
  --subject REPLACE_OPERATOR_ACCESS_SUB \
  --jwks-url https://REPLACE_ACCESS_TEAM_NAME.cloudflareaccess.com/cdn-cgi/access/certs \
  --repo /absolute/path/to/REPLACE_CASE_ID-work \
  --coordinator-config-root /etc/gate-remote/REPLACE_CASE_ID \
  --coordinator-state-root /var/lib/gate-remote/REPLACE_CASE_ID
```

Review the generated local `coordinator/server.json`: it must contain no `REPLACE_` token, must keep `host` at `127.0.0.1`, and must bind `runner.publicKeyPath` to the config root and `databasePath` to the state root. Both roots must be absolute, normalized, non-root, and non-overlapping. The example ports reserve `43180` for the coordinator, `43179` for Nginx, and `49312` for cloudflared metrics. Do not allocate another port set for a second case on this VPS.

## 3. Stage the release, then prepare protected state and activate

Follow the complete clean-host flow in the [parent scaffold](../README.md#prepare-one-coordinator-instance): install the protected Node runtime and service identity, authorize the exact reviewed archive, and call the installer with `--stage-only` before the coordinator config, state directory, or unit exists. Then install only the generated `coordinator/server.json` and `coordinator/runner-public.pem`, create the service-writable state directory, install the unit from the explicit immutable staged release path, and run `systemctl daemon-reload`. Finally invoke the same installer without `--stage-only` so it atomically activates `current`, restarts the prepared unit, and verifies process-bound readiness. Do not bootstrap with `systemctl enable --now` and do not copy the unit from `current` before that first activation.

Keep the persistent files outside the checkout and split the trust anchor from service-writable state:

```text
/etc/gate-remote/REPLACE_CASE_ID/
  server.json                 mode 0640 or 0440, root:gate-remote, service-not-writable
  runner-public.pem          mode 0640 or 0440, root:gate-remote, service-not-writable

/var/lib/gate-remote/REPLACE_CASE_ID/
  bridge.sqlite              created owner-only by the coordinator
  bridge.sqlite-wal          transient SQLite WAL when present
  bridge.sqlite-shm          transient SQLite shared memory when present
```

Install the reviewed generated config and public key under `/etc` as `root:gate-remote` files with mode `0640` or `0440`. The Linux/POSIX production service can read but cannot change them; administrator ownership is not asserted as a production boundary on non-POSIX hosts.

Back up the protected configuration and service state to an encrypted administrator-controlled destination, preserving their different ownership and modes. For state, use a SQLite-aware snapshot, or stop `gate-remote@REPLACE_CASE_ID.service`, copy the database plus any WAL/SHM files as one set, and start it again. Test restoration on a separate replacement VPS rather than beside the production case. A coordinator restart preserves durable queue state but intentionally invalidates in-memory browser sessions.

## 4. Install the named tunnel connector without exposing credentials

Install a reviewed, checksum-verified cloudflared release at the absolute root-owned path used by `cloudflared@.service`. Replace `REPLACE_CLOUDFLARED_VERSION` in the installed unit with that pinned version. Do not use a moving download, user-writable binary, Quick Tunnel, remotely managed token on the command line, or cloudflared auto-update.

Create a non-login identity for the connector before installing its private case directory:

```bash
(
  set -e
  getent group cloudflared >/dev/null 2>&1 || \
    sudo groupadd --system cloudflared
  getent passwd cloudflared >/dev/null 2>&1 || \
    sudo useradd --system --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin --gid cloudflared cloudflared
)
```

Transfer only the case tunnel credentials created in Step 1 through an administrator-controlled path and install them without printing them. Prepare a private copy of the staged `cloudflared-config.yml.example`, replace every `REPLACE_` token, and review it before installation. The VPS does not need the workstation's account-wide `cert.pem` or an API token. The following commands assume the placeholder-free copy is `/secure/transfer/REPLACE_CASE_ID/cloudflared-config.yml`:

```bash
staged_release=/opt/gate-remote/REPLACE_CASE_ID/releases/REPLACE_REVIEWED_COMMIT
staged_cloudflared_template="$staged_release/deploy/remote/cloudflare-vps/cloudflared-config.yml.example"
private_cloudflared_config=/secure/transfer/REPLACE_CASE_ID/cloudflared-config.yml
test -r "$staged_cloudflared_template"
test -f "$private_cloudflared_config"
if grep -q 'REPLACE_' "$private_cloudflared_config"; then
  echo "cloudflared private config still contains placeholders" >&2
  exit 1
fi
sudo install -d -o cloudflared -g cloudflared -m 0700 \
  /etc/cloudflared/REPLACE_CASE_ID
sudo install -o cloudflared -g cloudflared -m 0400 \
  /secure/transfer/REPLACE_TUNNEL_UUID.json \
  /etc/cloudflared/REPLACE_CASE_ID/tunnel-credentials.json
sudo install -o root -g root -m 0644 \
  "$private_cloudflared_config" \
  /etc/cloudflared/REPLACE_CASE_ID/config.yml
```

The tunnel credentials path stays under the case directory. Back up that credentials file through the same encrypted administrator-controlled secret backup path as the private coordinator configuration.

Do not copy the workstation's account certificate or API credential to the VPS.

## 5. Install the loopback Nginx gateway

Install a reviewed distribution Nginx package while the tunnel connector remains stopped and the host firewall denies public HTTP/HTTPS. On the Ubuntu 24.04 baseline:

```bash
sudo apt-get update
sudo apt-get install --yes nginx
sudo systemctl disable --now nginx.service
if sudo test -L /etc/nginx/sites-enabled/default; then
  sudo unlink /etc/nginx/sites-enabled/default
fi
```

Use the distribution-equivalent package and default-site removal elsewhere. Do not continue while `nginx -T` shows a listener on public `:80` or `:443`.

Prepare administrator-controlled private copies of the three staged Nginx examples, replace every `REPLACE_` token, and review the complete files. The following installation assumes those placeholder-free copies are under `/secure/transfer/REPLACE_CASE_ID/nginx`:

```bash
private_nginx=/secure/transfer/REPLACE_CASE_ID/nginx
test -f "$private_nginx/browser-proxy.inc"
test -f "$private_nginx/runner-proxy.inc"
test -f "$private_nginx/gate-remote.conf"
if grep -Rq 'REPLACE_' "$private_nginx"; then
  echo "Nginx private copies still contain placeholders" >&2
  exit 1
fi
sudo install -d -o root -g root -m 0755 \
  /etc/nginx/gate-remote/REPLACE_CASE_ID
sudo install -o root -g root -m 0644 \
  "$private_nginx/browser-proxy.inc" \
  /etc/nginx/gate-remote/REPLACE_CASE_ID/browser-proxy.inc
sudo install -o root -g root -m 0644 \
  "$private_nginx/runner-proxy.inc" \
  /etc/nginx/gate-remote/REPLACE_CASE_ID/runner-proxy.inc
sudo install -o root -g root -m 0644 \
  "$private_nginx/gate-remote.conf" \
  /etc/nginx/conf.d/gate-remote-REPLACE_CASE_ID.conf
```

Disable the distribution's default public listeners. The example deliberately listens only on `127.0.0.1:43179`. It sets the exact public Host and `X-Forwarded-Proto: https` for the coordinator; it never trusts values for those headers from the client. It disables proxy caching and buffering, extends the SSE read timeout, strips the identity header on runner traffic, and denies health and unknown paths.

The upstream address in both snippets must equal the coordinator's loopback host and port. The include paths in the site configuration must equal the private case directory. Run `sudo nginx -t` before the first start and inspect the complete expanded configuration with `sudo nginx -T`; the latter contains no credentials but may contain private identifiers, so keep its output local. Leave Nginx stopped until the required edge controls in Step 6 are active.

## 6. Apply the edge controls before starting the connector

Reconfirm that the two Access applications still have the exact policies created in Step 2 and that the root application's current AUD still matches the protected coordinator config. Rotate `sessionRevision` and initialize a new reviewed binding whenever the application audience, case binding, or operator authority changes.

At the Cloudflare edge:

- disable caching for the hostname, including `/assets/*` and `/data/status.json`;
- disable response buffering or transformation that would break `text/event-stream` on `/api/cockpit/v1/events`;
- never cache, rewrite, decompress/recompress, redirect, or challenge `/api/runner/v1/*`;
- keep independent rate-limit rules for browser and runner route classes so one cannot consume the other's edge budget;
- do not log request bodies, cookies, Access assertions, or `X-GATE-Signature`; and
- do not create a Worker, Transform Rule, origin rule, or fallback origin that broadens the route table or rewrites signed runner requests.

Cloudflare Access is responsible for rejecting an unauthenticated browser and supplying a current provider-signed `Cf-Access-Jwt-Assertion`. The loopback Nginx gateway is responsible for converting only that header into the coordinator's private header. The coordinator remains responsible for JWT issuer, audience, subject, lifetime, and signature verification.

Keep `cloudflared@REPLACE_CASE_ID.service` disabled and stopped until every control above is active and independently reviewed. The runner application is an Access Bypass route, so starting the connector first would expose it before its cache, transformation, challenge, and rate-limit controls exist.

## 7. Install and start the edge services

The parent clean-host flow already installed and activated the coordinator unit from the explicit staged release. Prepare and review a private copy of the cloudflared unit from that same staged release, replace its pinned runtime path, and reject every remaining `REPLACE_` token. Confirm the coordinator remains active; do not start it outside the installer's activation transaction:

```bash
staged_release=/opt/gate-remote/REPLACE_CASE_ID/releases/REPLACE_REVIEWED_COMMIT
staged_cloudflared_unit="$staged_release/deploy/remote/cloudflare-vps/cloudflared@.service.example"
private_cloudflared_unit=/secure/transfer/REPLACE_CASE_ID/cloudflared@.service
test -r "$staged_cloudflared_unit"
test -f "$private_cloudflared_unit"
if grep -q 'REPLACE_' "$private_cloudflared_unit"; then
  echo "cloudflared private unit still contains placeholders" >&2
  exit 1
fi
sudo install -o root -g root -m 0644 \
  "$private_cloudflared_unit" \
  /etc/systemd/system/cloudflared@.service

sudo systemd-analyze verify \
  /etc/systemd/system/gate-remote@.service \
  /etc/systemd/system/cloudflared@.service
sudo nginx -t
sudo /opt/cloudflared/REPLACE_CLOUDFLARED_VERSION/cloudflared \
  --config /etc/cloudflared/REPLACE_CASE_ID/config.yml tunnel ingress validate
sudo /opt/cloudflared/REPLACE_CLOUDFLARED_VERSION/cloudflared \
  --config /etc/cloudflared/REPLACE_CASE_ID/config.yml \
  tunnel ingress rule https://REPLACE_PUBLIC_HOSTNAME/healthz
sudo /opt/cloudflared/REPLACE_CLOUDFLARED_VERSION/cloudflared \
  --config /etc/cloudflared/REPLACE_CASE_ID/config.yml \
  tunnel ingress rule https://REPLACE_PUBLIC_HOSTNAME/api/runner/v1/heartbeat
sudo systemctl daemon-reload
sudo systemctl is-active --quiet gate-remote@REPLACE_CASE_ID.service
sudo systemctl enable --now nginx.service
sudo systemctl is-active --quiet nginx.service
sudo ss -lntp
```

Before continuing, the ingress-rule output must select `http_status:404` for health and the loopback Nginx service for the runner. The socket listing must show Nginx only on `127.0.0.1:43179`, the coordinator only on `127.0.0.1:43180`, and no Nginx listener on public `:80` or `:443`. Start the outbound connector only after those checks and Step 6's edge controls pass:

```bash
sudo systemctl enable --now cloudflared@REPLACE_CASE_ID.service
sudo systemctl is-active --quiet cloudflared@REPLACE_CASE_ID.service
```

The cloudflared unit does not own the coordinator or Nginx lifecycle. A tunnel may temporarily return a gateway error while either local service is down. Monitor all three separately. Journal output must not include credentials, assertions, cookies, request bodies, operator messages, or runner signatures.

## 8. Readiness and rollback

Validate local configuration before relying on the hostname for operator use:

```bash
sudo /opt/cloudflared/REPLACE_CLOUDFLARED_VERSION/cloudflared \
  --config /etc/cloudflared/REPLACE_CASE_ID/config.yml tunnel ingress validate
sudo /opt/cloudflared/REPLACE_CLOUDFLARED_VERSION/cloudflared \
  --config /etc/cloudflared/REPLACE_CASE_ID/config.yml \
  tunnel ingress rule https://REPLACE_PUBLIC_HOSTNAME/healthz
sudo /opt/cloudflared/REPLACE_CLOUDFLARED_VERSION/cloudflared \
  --config /etc/cloudflared/REPLACE_CASE_ID/config.yml \
  tunnel ingress rule https://REPLACE_PUBLIC_HOSTNAME/api/runner/v1/heartbeat
sudo nginx -t
sudo ss -lntp
```

The health rule must select `http_status:404`; the runner rule must select the loopback Nginx service. `ss` must show ports `43179`, `43180`, and the cloudflared metrics port on loopback only, with no unintended Nginx listener on public `:80` or `:443`.

Run the supplied non-secret smoke script on the VPS:

```bash
GATE_REMOTE_PUBLIC_ORIGIN=https://REPLACE_PUBLIC_HOSTNAME \
GATE_REMOTE_COORDINATOR_URL=http://127.0.0.1:43180 \
GATE_REMOTE_GATEWAY_URL=http://127.0.0.1:43179 \
GATE_REMOTE_CLOUDFLARED_METRICS_URL=http://127.0.0.1:49312 \
  /bin/bash /opt/gate-remote/REPLACE_CASE_ID/current/deploy/remote/cloudflare-vps/readiness-check.sh
```

The immutable installer deliberately normalizes staged regular files to read-only mode, so invoke this reviewed script through the protected absolute `/bin/bash` interpreter rather than relying on an executable bit in the release tree.

Then verify the stateful checks from the parent [verification list](../README.md#verification-before-exposure): authenticate in a fresh browser, fetch `/data/status.json`, establish the SSE stream, send one harmless message, start the enrolled laptop runner, observe a signed heartbeat and lifecycle, restart the coordinator, and confirm durable SQLite state survives while the browser session is invalidated. Send a fake public `X-GATE-OIDC-Assertion` without an Access session and confirm it cannot establish a cockpit session. Confirm a runner request is never redirected to Access and a browser request never reaches the origin without Access.

If any route, header, identity, listener, or persistence check fails, remove or disable the public DNS route, stop `cloudflared@REPLACE_CASE_ID.service`, and leave the loopback coordinator available for diagnosis. Do not weaken JWT checks, expose the coordinator port, switch the runner to a browser token, or route health publicly as a workaround.
