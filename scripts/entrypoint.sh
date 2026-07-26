#!/bin/sh
set -eu

mkdir -p /data/security /data/cache /repositories
chown -R rrb:rrb /data

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

