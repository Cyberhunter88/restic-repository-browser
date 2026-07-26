#!/bin/sh
set -eu

mkdir -p /data/security /data/cache /repositories
# Restic creates private cache directories (0700) owned by rrb. The
# capability-restricted root process cannot traverse them and does not need to:
# cache contents are already created and consumed by rrb.
chown rrb:rrb /data /data/cache
chown -R rrb:rrb /data/security
find /data -maxdepth 1 -type f -exec chown rrb:rrb {} +

gosu rrb python -m backend.app.bootstrap

set -- uvicorn backend.app.main:app \
  --host 0.0.0.0 \
  --port "${RRB_HTTP_PORT:-8080}" \
  --proxy-headers \
  --forwarded-allow-ips "${RRB_TRUSTED_PROXY_IPS:-127.0.0.1,::1}"

if [ "${RRB_TLS_MODE:-proxy}" = "files" ]; then
  test -r "${RRB_TLS_CERT_FILE:-}" || {
    echo "RRB_TLS_CERT_FILE fehlt oder ist nicht lesbar" >&2
    exit 1
  }
  test -r "${RRB_TLS_KEY_FILE:-}" || {
    echo "RRB_TLS_KEY_FILE fehlt oder ist nicht lesbar" >&2
    exit 1
  }
  set -- "$@" \
    --ssl-certfile "$RRB_TLS_CERT_FILE" \
    --ssl-keyfile "$RRB_TLS_KEY_FILE"
fi

exec gosu rrb "$@"
