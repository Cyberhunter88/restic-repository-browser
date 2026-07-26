#!/bin/sh
set -eu

test -n "${RRB_SFTP_PASSWORD_FILE:-}"
exec cat -- "$RRB_SFTP_PASSWORD_FILE"
