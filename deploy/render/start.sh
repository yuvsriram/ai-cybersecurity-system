#!/usr/bin/env bash

set -Eeuo pipefail


PORT="${PORT:-10000}"

export PORT


require_variable() {
    local name="$1"

    if [[ -z "${!name:-}" ]]; then
        echo "Required environment variable is missing: ${name}" >&2
        exit 1
    fi
}


require_variable "DATABASE_URL"
require_variable "DEMO_API_KEY"
require_variable "GROQ_API_KEY"


if [[ "${#DEMO_API_KEY}" -lt 32 ]]; then
    echo "DEMO_API_KEY must contain at least 32 characters" >&2
    exit 1
fi


#
# Neon commonly supplies a standard postgresql:// URL.
#
# The application intentionally uses psycopg 3, so normalize
# that URL into SQLAlchemy's explicit psycopg dialect.
#

case "${DATABASE_URL}" in
    postgresql://*)
        export DATABASE_URL="postgresql+psycopg://${DATABASE_URL#postgresql://}"
        ;;

    postgres://*)
        export DATABASE_URL="postgresql+psycopg://${DATABASE_URL#postgres://}"
        ;;
esac


#
# The browser never receives DEMO_API_KEY.
#
# Nginx injects the raw credential server-side. FastAPI stores
# and compares only its SHA-256 digest.
#

export CYBERSEC_API_KEYS_JSON="$(
    python - <<'PY'
import hashlib
import json
import os

raw_key = os.environ["DEMO_API_KEY"]

digest = hashlib.sha256(
    raw_key.encode("utf-8")
).hexdigest()

print(
    json.dumps(
        [
            {
                "name": "demo-viewer",
                "role": "viewer",
                "sha256": digest,
            }
        ],
        separators=(",", ":"),
    )
)
PY
)"


#
# Reuse the already-hardened frontend Nginx allowlist.
#
# Docker Compose:
#   listen 8080
#   proxy_pass http://api:8000
#
# Render single container:
#   listen $PORT
#   proxy_pass http://127.0.0.1:8000
#
# Restrict envsubst to our two variables so Nginx variables such
# as $remote_addr and $request_method remain untouched.
#

sed \
    -e 's/listen 8080;/listen ${PORT};/' \
    -e 's#proxy_pass http://api:8000;#proxy_pass http://127.0.0.1:8000;#g' \
    /app/nginx/default.conf.template \
    | envsubst '${PORT} ${DEMO_API_KEY}' \
    > /tmp/render-default.conf


nginx \
    -t \
    -c /etc/nginx/nginx.conf


echo "Applying database migrations..."

python -m alembic upgrade head


echo "Starting FastAPI..."

python -m uvicorn \
    cybersec.main:app \
    --host 127.0.0.1 \
    --port 8000 \
    --proxy-headers \
    --forwarded-allow-ips 127.0.0.1 \
    &

api_pid="$!"


echo "Starting Nginx on port ${PORT}..."

nginx \
    -c /etc/nginx/nginx.conf \
    -g 'daemon off;' \
    &

nginx_pid="$!"


shutdown() {
    trap - TERM INT

    kill -TERM \
        "${nginx_pid}" \
        "${api_pid}" \
        2>/dev/null \
        || true

    wait \
        "${nginx_pid}" \
        "${api_pid}" \
        2>/dev/null \
        || true
}


trap shutdown TERM INT


set +e

wait -n \
    "${api_pid}" \
    "${nginx_pid}"

status="$?"

set -e


shutdown

exit "${status}"