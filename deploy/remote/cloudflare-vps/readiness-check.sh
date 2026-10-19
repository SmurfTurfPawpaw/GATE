#!/usr/bin/env bash
set -euo pipefail

: "${GATE_REMOTE_PUBLIC_ORIGIN:?set the exact https:// hostname without a path}"
: "${GATE_REMOTE_COORDINATOR_URL:=http://127.0.0.1:43180}"
: "${GATE_REMOTE_GATEWAY_URL:=http://127.0.0.1:43179}"
: "${GATE_REMOTE_CLOUDFLARED_METRICS_URL:=http://127.0.0.1:49312}"

if [[ "$GATE_REMOTE_PUBLIC_ORIGIN" != https://* ]]; then
  printf '%s\n' 'GATE_REMOTE_PUBLIC_ORIGIN must be an HTTPS origin.' >&2
  exit 2
fi
public_host=${GATE_REMOTE_PUBLIC_ORIGIN#https://}
if [[ -z "$public_host" || "$public_host" == */* || "$public_host" == *\?* \
    || "$public_host" == *\#* || "$public_host" == *@* || "$public_host" =~ [[:space:]] ]]; then
  printf '%s\n' 'GATE_REMOTE_PUBLIC_ORIGIN must be an exact HTTPS origin without credentials, path, query, or fragment.' >&2
  exit 2
fi
curl_common=(--silent --show-error --connect-timeout 5 --max-time 15 --output /dev/null)

expect_status() {
  local expected=$1
  local url=$2
  shift 2
  local actual
  actual=$(curl "${curl_common[@]}" --write-out '%{http_code}' "$@" "$url")
  if [[ "$actual" != "$expected" ]]; then
    printf 'expected HTTP %s from %s, received %s\n' "$expected" "$url" "$actual" >&2
    return 1
  fi
  printf 'ok  HTTP %s  %s\n' "$actual" "$url"
}

# Direct host monitoring is the only place that should receive coordinator health.
expect_status 200 "$GATE_REMOTE_COORDINATOR_URL/healthz"
expect_status 200 "$GATE_REMOTE_COORDINATOR_URL/readyz"

# The loopback public-route gateway must keep health private even with the public Host.
expect_status 404 "$GATE_REMOTE_GATEWAY_URL/healthz" --header "Host: $public_host"
expect_status 404 "$GATE_REMOTE_GATEWAY_URL/readyz" --header "Host: $public_host"
expect_status 404 "$GATE_REMOTE_GATEWAY_URL/unlisted-readiness-canary" --header "Host: $public_host"

# Cloudflared's local metrics server exposes only connector readiness on loopback.
expect_status 200 "$GATE_REMOTE_CLOUDFLARED_METRICS_URL/ready"

# The public tunnel must not expose coordinator health. Access may return its login
# response before cloudflared's 404, so only those bounded denial/redirect results
# are accepted. A 5xx is a failed readiness check rather than evidence of privacy.
for health_path in healthz readyz; do
  status=$(curl "${curl_common[@]}" --write-out '%{http_code}' "$GATE_REMOTE_PUBLIC_ORIGIN/$health_path")
  case "$status" in
    302|303|307|401|403|404) printf 'ok  public /%s did not expose health (HTTP %s)\n' "$health_path" "$status" ;;
    *) printf 'public /%s returned unexpected HTTP %s\n' "$health_path" "$status" >&2; exit 1 ;;
  esac
done

# The more-specific Access application must not redirect the headless runner to
# interactive login. A structurally valid request with a deliberately invalid
# credential must reach the coordinator and receive its authentication rejection.
runner_headers=$(mktemp)
runner_body=$(mktemp)
trap 'rm -f "$runner_headers" "$runner_body"' EXIT
runner_timestamp="$(printf '%(%s)T' -1)000"
runner_status=$(curl "${curl_common[@]}" --dump-header "$runner_headers" --write-out '%{http_code}' \
  --output "$runner_body" --max-filesize 4096 \
  --request POST --header 'Content-Type: application/json' --data '{}' \
  --header 'X-GATE-Runner: readiness.invalid' \
  --header "X-GATE-Timestamp: $runner_timestamp" \
  --header 'X-GATE-Nonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
  --header 'X-GATE-Body-SHA256: 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a' \
  --header 'X-GATE-Signature: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
  "$GATE_REMOTE_PUBLIC_ORIGIN/api/runner/v1/lease")
if [[ "$runner_status" != "401" ]]; then
  printf 'invalid runner probe expected coordinator HTTP 401, received %s\n' "$runner_status" >&2
  exit 1
fi
if awk '{line=tolower($0); if (line ~ /^location:/) found=1} END{exit found ? 0 : 1}' "$runner_headers"; then
  printf '%s\n' 'runner probe unexpectedly received a redirect Location header' >&2
  exit 1
fi
if ! awk '{line=tolower($0); sub(/\r$/, "", line)}
  line == "content-type: application/json; charset=utf-8" {found=1}
  END{exit found ? 0 : 1}' "$runner_headers"; then
  printf '%s\n' 'runner probe did not receive the coordinator JSON content type' >&2
  exit 1
fi
expected_runner_body='{"ok":false,"error":{"code":"runner-auth-rejected","message":"The runner authentication request was rejected."}}'
if [[ "$(cat "$runner_body")" != "$expected_runner_body" ]]; then
  printf '%s\n' 'runner probe did not receive the exact coordinator authentication rejection' >&2
  exit 1
fi
printf '%s\n' 'ok  invalid runner probe reached coordinator authentication without an Access redirect'

printf '%s\n' 'Smoke checks passed. Complete the authenticated browser and signed-runner checks in README.md.'
