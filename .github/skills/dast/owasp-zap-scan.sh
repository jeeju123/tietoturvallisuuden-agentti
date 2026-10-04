#!/usr/bin/env bash
set -euo pipefail

TARGET=""
KEEP_TEMP=false

for arg in "$@"; do
    if [[ "$arg" == "--keep-temp" ]]; then
        KEEP_TEMP=true
    elif [[ -z "$TARGET" && "$arg" != -* ]]; then
        TARGET="$arg"
    fi
done

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target_url> [--keep-temp]" >&2
    exit 1
fi

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

echo "Starting OWASP ZAP baseline scan against $TARGET (validated)..."
echo "ZAP is actively spidering and scanning endpoints in a Docker container."
echo "This process typically takes 1 to 3 minutes. Please wait for the scan to finish..."

RAW_REPORT="raw-dast-report.json"

# ZAP baseline scan returns exit code 0 (clean), 1 (warnings/alerts found), or 2 (failures).
# We catch the exit code with set +e so findings are not truncated and parsing always runs.
set +e
docker run --rm -t \
    -v "$REPORTS_DIR:/zap/wrk/:rw" \
    zaproxy/zap-stable zap-baseline.py \
    -t "$TARGET" \
    -J "$RAW_REPORT"
ZAP_EXIT_CODE=$?
set -e

if [[ $ZAP_EXIT_CODE -gt 2 ]]; then
    echo "ERROR: OWASP ZAP scan failed with runtime error (code $ZAP_EXIT_CODE)" >&2
    if [[ "$KEEP_TEMP" == false ]]; then
        rm -f "$REPORTS_DIR/$RAW_REPORT" "$REPORTS_DIR/zap.yaml" "$REPORTS_DIR/zap.out" "$REPORTS_DIR/zap.log"
    else
        echo "Audit trail preserved: intermediate files retained on error."
    fi
    exit $ZAP_EXIT_CODE
fi

if [[ $ZAP_EXIT_CODE -eq 1 || $ZAP_EXIT_CODE -eq 2 ]]; then
    echo "OWASP ZAP scan completed with security alerts (exit code $ZAP_EXIT_CODE)."
else
    echo "OWASP ZAP scan completed with 0 warnings."
fi

# Parse raw ZAP report into compact SSDLC dast-results.json to minimize token consumption
if command -v node >/dev/null 2>&1; then
    echo "Parsing raw ZAP output into compact SSDLC format ($REPORTS_DIR/dast-results.json)..."
    EXTRA_PARSE_ARGS=()
    if [[ "$KEEP_TEMP" == true ]]; then
        EXTRA_PARSE_ARGS+=("--keep-temp")
    fi
    node "$SCRIPT_DIR/parse-zap-results.js" -i "$REPORTS_DIR/$RAW_REPORT" -o "$REPORTS_DIR/dast-results.json" "${EXTRA_PARSE_ARGS[@]}"
    if [[ "$KEEP_TEMP" == false ]]; then
        rm -f "$REPORTS_DIR/$RAW_REPORT" "$REPORTS_DIR/zap.yaml" "$REPORTS_DIR/zap.out" "$REPORTS_DIR/zap.log"
        echo "Cleaned up intermediate files ($RAW_REPORT, zap.yaml)."
    else
        echo "Audit trail preserved: intermediate files kept ($RAW_REPORT, zap.yaml, zap.out, zap.log)."
    fi
else
    echo "WARNING: Node.js executable not found in PATH. Moving raw output to $REPORTS_DIR/dast-results.json"
    if [[ "$KEEP_TEMP" == true ]]; then
        cp "$REPORTS_DIR/$RAW_REPORT" "$REPORTS_DIR/dast-results.json"
        echo "Audit trail preserved: intermediate files kept ($RAW_REPORT, zap.yaml, zap.out, zap.log)."
    else
        mv "$REPORTS_DIR/$RAW_REPORT" "$REPORTS_DIR/dast-results.json"
        rm -f "$REPORTS_DIR/zap.yaml" "$REPORTS_DIR/zap.out" "$REPORTS_DIR/zap.log"
    fi
fi

echo "OWASP ZAP scan (baseline) complete. Results saved at: $REPORTS_DIR/dast-results.json"