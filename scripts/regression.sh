#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for this script"
  exit 1
fi

echo "[1/6] health"
curl -sS "${BASE_URL}/v1/health" | jq .

echo "[2/6] submit low-risk action (expect ALLOW_EXECUTED)"
LOW_PAYLOAD=$(cargo run --quiet --example make_payload -- low act-low-1 run-low)
LOW=$(curl -sS -X POST "${BASE_URL}/v1/actions/submit" \
  -H 'content-type: application/json' \
  -d "${LOW_PAYLOAD}")
echo "$LOW" | jq .
if [[ "$(echo "$LOW" | jq -r '.status')" != "ALLOW_EXECUTED" ]]; then
  echo "unexpected status in step 2"
  exit 1
fi

echo "[3/6] submit high-risk action (expect ESCALATE_PENDING)"
HIGH_PAYLOAD=$(cargo run --quiet --example make_payload -- high act-esc-1 run-esc)
ESC=$(curl -sS -X POST "${BASE_URL}/v1/actions/submit" \
  -H 'content-type: application/json' \
  -d "${HIGH_PAYLOAD}")
echo "$ESC" | jq .
if [[ "$(echo "$ESC" | jq -r '.status')" != "ESCALATE_PENDING" ]]; then
  echo "unexpected status in step 3"
  exit 1
fi
APPROVAL_ID=$(echo "$ESC" | jq -r '.decision.approval_id')

if [[ "$APPROVAL_ID" == "null" || -z "$APPROVAL_ID" ]]; then
  echo "approval_id missing"
  exit 1
fi

echo "[4/6] approve high-risk action (expect APPROVED_EXECUTED)"
APPROVED=$(curl -sS -X POST "${BASE_URL}/v1/actions/act-esc-1/approve" \
  -H 'content-type: application/json' \
  -d "{\"approval_id\":\"${APPROVAL_ID}\",\"approver\":\"ops-oncall\"}")
echo "$APPROVED" | jq .
if [[ "$(echo "$APPROVED" | jq -r '.status')" != "APPROVED_EXECUTED" ]]; then
  echo "unexpected status in step 4"
  exit 1
fi

echo "[5/6] set read-only and verify write denied"
curl -sS -X POST "${BASE_URL}/v1/governor/degrade" \
  -H 'content-type: application/json' \
  -d '{"mode":"READ_ONLY","actor":"governor"}' | jq .

RO=$(curl -sS -X POST "${BASE_URL}/v1/actions/submit" \
  -H 'content-type: application/json' \
  -d "$(cargo run --quiet --example make_payload -- read_only_write act-ro-1 run-ro)")
echo "$RO" | jq .
if [[ "$(echo "$RO" | jq -r '.decision.reason_code')" != "GOVERNOR_READ_ONLY" ]]; then
  echo "unexpected reason in step 5"
  exit 1
fi

echo "[6/6] audit lookup"
curl -sS "${BASE_URL}/v1/audit/act-low-1" | jq .
