#!/usr/bin/env bash
#
# verify-demo.sh - end-to-end verification of the portable Argus + Hermes demo.
#
# Checks, in order: Elasticsearch health, seeded indices have documents, the
# API serves valid case/behavior data, the frontend responds, a real analyst
# action write-read cycle, and both Hermes dry-run scenarios produce their
# expected decision. Ends with a single PASS/FAIL summary line and a matching
# exit code (0 = pass, 1 = fail), so this is safe to use in a script or CI
# step, not just read by a person.
#
# Depends only on curl, grep, docker compose, and python (python is needed
# anyway to run Hermes, so this adds nothing new). No jq, no Node - kept
# deliberately minimal so the check script itself isn't another thing that
# might not run on a stranger's machine.
#
# Usage: ./scripts/verify-demo.sh   (run from anywhere, paths are resolved
# relative to this script's location)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

ES_URL="http://localhost:9200"
API_URL="http://localhost:8000"
FRONTEND_URL="http://localhost:5173"

ES_USER="elastic"
ELASTIC_PASSWORD=""
if [ -f .env ]; then
    ES_USER="$(grep -E '^ES_USER=' .env | cut -d= -f2-)"
    ELASTIC_PASSWORD="$(grep -E '^ELASTIC_PASSWORD=' .env | cut -d= -f2-)"
fi
ES_USER="${ES_USER:-elastic}"

PASS_COUNT=0
FAIL_COUNT=0
FAILED_CHECKS=()

check() {
    local label="$1" ok="$2" detail="${3:-}"
    if [ "$ok" = "true" ]; then
        echo "[PASS] $label"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "[FAIL] $label${detail:+ -- $detail}"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_CHECKS+=("$label")
    fi
}

echo "== Verifying portable Argus + Hermes demo =="
echo

# ---------------------------------------------------------------------------
# 1. Elasticsearch is healthy
# ---------------------------------------------------------------------------
es_status="$(curl -s -u "${ES_USER}:${ELASTIC_PASSWORD}" "$ES_URL/_cat/health?h=status" 2>/dev/null | tr -d '[:space:]')"
if [ "$es_status" = "green" ] || [ "$es_status" = "yellow" ]; then
    check "Elasticsearch cluster healthy (status=$es_status)" true
else
    check "Elasticsearch cluster healthy" false "status='$es_status', is the stack up? (docker compose up -d)"
fi

# ---------------------------------------------------------------------------
# 2. Seeded indices exist and have documents
# ---------------------------------------------------------------------------
for index in argus-cases argus-behaviors argus-actions; do
    count="$(curl -s -u "${ES_USER}:${ELASTIC_PASSWORD}" "$ES_URL/_cat/count/$index?h=count" 2>/dev/null | tr -d '[:space:]')"
    if [[ "$count" =~ ^[0-9]+$ ]] && [ "$count" -gt 0 ]; then
        check "$index has documents (count=$count)" true
    else
        check "$index has documents" false "count='$count', try: docker compose run --rm seed"
    fi
done

# ---------------------------------------------------------------------------
# 3. API returns valid case and behavior data
# ---------------------------------------------------------------------------
cases_resp="$(curl -s "$API_URL/api/cases" 2>/dev/null)"
if echo "$cases_resp" | grep -q '"ok":true'; then
    check "GET /api/cases returns ok:true" true
    first_case_id="$(echo "$cases_resp" | grep -oE '"case_id":"[^"]*"' | head -1 | sed -E 's/"case_id":"([^"]*)"/\1/')"
else
    check "GET /api/cases returns ok:true" false "$(echo "$cases_resp" | head -c 200)"
    first_case_id=""
fi

if [ -n "$first_case_id" ]; then
    behaviors_resp="$(curl -s "$API_URL/api/cases/$first_case_id/behaviors" 2>/dev/null)"
    if echo "$behaviors_resp" | grep -q '"ok":true'; then
        first_behavior_id="$(echo "$behaviors_resp" | grep -oE '"behavior_id":"[^"]*"' | head -1 | sed -E 's/"behavior_id":"([^"]*)"/\1/')"
        # No standalone GET /api/behaviors list endpoint exists (only
        # /api/behaviors/{id} and /api/cases/{id}/behaviors) -- also check
        # the single-behavior endpoint to cover both real behavior routes.
        if [ -n "$first_behavior_id" ]; then
            behavior_resp="$(curl -s "$API_URL/api/behaviors/$first_behavior_id" 2>/dev/null)"
            if echo "$behavior_resp" | grep -q '"ok":true'; then
                check "GET /api/cases/{id}/behaviors and /api/behaviors/{id} return valid data" true
            else
                check "GET /api/behaviors/{id} returns ok:true" false "$(echo "$behavior_resp" | head -c 200)"
            fi
        else
            check "GET /api/cases/{id}/behaviors returned a behavior_id to check" false "no behaviors in first case"
        fi
    else
        check "GET /api/cases/{id}/behaviors returns ok:true" false "$(echo "$behaviors_resp" | head -c 200)"
    fi
else
    check "GET /api/cases/{id}/behaviors returns ok:true" false "no case_id available from /api/cases"
fi

# ---------------------------------------------------------------------------
# 4. Frontend responds at its root URL
# ---------------------------------------------------------------------------
frontend_status="$(curl -s -o /dev/null -w '%{http_code}' "$FRONTEND_URL/" 2>/dev/null)"
if [ "$frontend_status" = "200" ]; then
    check "Frontend responds at $FRONTEND_URL/ (HTTP $frontend_status)" true
else
    check "Frontend responds at $FRONTEND_URL/" false "HTTP $frontend_status"
fi

# ---------------------------------------------------------------------------
# 5. Analyst action write-read cycle
# ---------------------------------------------------------------------------
token="verify-demo-$(date +%s)"
write_resp="$(curl -s -X POST "$API_URL/api/actions" \
    -H "Content-Type: application/json" \
    -d "{\"action\":\"NOTE\",\"behavior_id\":\"VERIFY-DEMO\",\"case_id\":\"VERIFY-DEMO\",\"note\":\"$token\",\"actor\":\"verify-demo-script\"}" 2>/dev/null)"

if echo "$write_resp" | grep -q '"ok":true' && echo "$write_resp" | grep -q '"action_id"'; then
    action_id="$(echo "$write_resp" | grep -oE '"action_id":"[^"]*"' | sed -E 's/"action_id":"([^"]*)"/\1/')"
    # Elasticsearch is near-real-time, not immediately consistent -- a
    # document isn't guaranteed searchable until the next refresh cycle
    # (~1s by default). This was a real, reproducible flake found in
    # manual testing earlier in this remediation, not a hypothetical.
    sleep 2
    read_resp="$(curl -s "$API_URL/api/actions?limit=50" 2>/dev/null)"
    if echo "$read_resp" | grep -q "$token"; then
        check "Analyst action write-read cycle (action_id=$action_id, note found on read-back)" true
    else
        check "Analyst action write-read cycle" false "wrote action_id=$action_id but note '$token' not found in GET /api/actions"
    fi
else
    check "Analyst action write-read cycle" false "POST /api/actions did not return ok:true with an action_id: $(echo "$write_resp" | head -c 200)"
fi

# ---------------------------------------------------------------------------
# 6. Hermes dry-run scenarios
# ---------------------------------------------------------------------------
noise_out="$(python -m hermes.cli dry-run --scenario noise 2>&1)"
if echo "$noise_out" | grep -q '"decision": "NOISE"'; then
    check "Hermes NOISE scenario produces NOISE decision" true
else
    check "Hermes NOISE scenario produces NOISE decision" false "$(echo "$noise_out" | head -c 200)"
fi

signal_out="$(python -m hermes.cli dry-run --scenario signal 2>&1)"
if echo "$signal_out" | grep -q '"decision": "SIGNAL"'; then
    check "Hermes SIGNAL scenario produces SIGNAL decision" true
else
    check "Hermes SIGNAL scenario produces SIGNAL decision" false "$(echo "$signal_out" | head -c 200)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
total=$((PASS_COUNT + FAIL_COUNT))
if [ "$FAIL_COUNT" -eq 0 ]; then
    echo "RESULT: PASS ($PASS_COUNT/$total checks)"
    exit 0
else
    echo "RESULT: FAIL ($FAIL_COUNT/$total checks failed: ${FAILED_CHECKS[*]})"
    exit 1
fi
