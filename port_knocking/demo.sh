#!/usr/bin/env bash
set -euo pipefail

TARGET_IP=${1:-172.20.0.40}
SEQUENCE=${2:-"1234,5678,9012"}
PROTECTED_PORT=${3:-2222}

echo "[1/4] Attempt protected port BEFORE knocking (should fail)"
nc -z -v "$TARGET_IP" "$PROTECTED_PORT" || true

echo "[2/4] Send knock sequence"
python3 knock_client.py --target "$TARGET_IP" --sequence "$SEQUENCE" --check

echo "[3/4] Attempt protected port AFTER knocking (should succeed briefly)"
nc -z -v "$TARGET_IP" "$PROTECTED_PORT" || true

echo "[4/4] (Optional) Try SSH (user=knockuser pass=knockme)"
echo "ssh -p $PROTECTED_PORT knockuser@$TARGET_IP"
