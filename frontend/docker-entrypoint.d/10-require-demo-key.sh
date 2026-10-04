


set -eu



if [ -z "${DEMO_API_KEY:-}" ]; then

    echo >&2 "DEMO_API_KEY must be configured"

    exit 1

fi



if [ "${#DEMO_API_KEY}" -lt 32 ]; then

    echo >&2 "DEMO_API_KEY must contain at least 32 characters"

    exit 1

fi