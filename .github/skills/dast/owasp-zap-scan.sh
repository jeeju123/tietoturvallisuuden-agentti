#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:?Usage: ./script.sh <target_url>}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR" && git rev-parse --show-toplevel)"
REPORTS_DIR="$REPO_ROOT/artefacts"

SCHEME=$(echo "$TARGET" | sed -E 's#^([a-zA-Z]+)://.*#\1#')
HOST=$(echo "$TARGET" | sed -E 's#^[a-zA-Z]+://([^/:]+).*#\1#')

if [[ "$SCHEME" != "http" && "$SCHEME" != "https" ]]; then
    echo "BLOCKED: invalid scheme in '$TARGET'" >&2
    exit 1
fi

# WHITELISTED HOSTS: MODIFY THIS LIST TO INCLUDE ALL HOSTS YOU WANT TO ALLOW SCANS FOR
# NOTE: POTENTIALLY DANGEROUS - DAST SCAN IS INTRUSIVE! Only include hosts you trust and have permission to scan
ALLOWED_HOSTS=("localhost" "127.0.0.1" "host.docker.internal")

is_allowed=false
for allowed in "${ALLOWED_HOSTS[@]}"; do
    if [[ "$HOST" == "$allowed" ]]; then
        is_allowed=true
        break
    fi
done

if [[ "$is_allowed" == false ]]; then
    echo "BLOCKED: '$HOST' is not an allowed scan target - allowed hosts are: ${ALLOWED_HOSTS[*]}" >&2
    exit 1
fi

if [[ ! -d "$REPORTS_DIR" ]]; then
    echo "ERROR: expected output folder '$REPORTS_DIR' does not exist" >&2
    exit 1
fi

echo "Scanning $TARGET (validated) ..."
echo "Report will be written to: $REPORTS_DIR/"

docker run --rm -t \
    -v "$REPORTS_DIR:/zap/wrk/:rw" \
    zaproxy/zap-stable zap-baseline.py \
    -t "$TARGET" \
    -J dast-results.json

echo "OWASP ZAP scan (baseline) complete. Reports found at: $REPORTS_DIR/"