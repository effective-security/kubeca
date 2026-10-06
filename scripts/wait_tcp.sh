#!/bin/bash
# Wait until every host:port argument accepts TCP connections (60 s each).
set -euo pipefail
for hp in "$@"; do
    host=${hp%:*}; port=${hp##*:}
    for _ in $(seq 1 60); do
        if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
            exec 3>&- 3<&-
            echo "wait_tcp: $hp is up"
            continue 2
        fi
        sleep 1
    done
    echo "wait_tcp: $hp did not come up" >&2
    exit 1
done
