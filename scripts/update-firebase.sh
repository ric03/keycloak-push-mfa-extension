#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/update-firebase.sh <pseudonymous-user-id> <new-firebase-id>

Environment overrides:
  REALM_BASE        Realm base URL (default: value stored during enrollment, fallback http://localhost:8080/realms/push-mfa)
  DEVICE_STATE_DIR  Directory storing device state from enroll.sh (default: scripts/device-state)
  TOKEN_TTL_SECONDS Lifetime (seconds) for the device-signed assertion (default: 60)
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" || $# -ne 2 ]]; then
  usage
  exit $([[ $# -eq 2 ]] && [[ ${1:-} != "-h" && ${1:-} != "--help" ]] && echo 1 || echo 0)
fi

PSEUDONYMOUS_ID=$1
NEW_FIREBASE_ID=$2

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEVICE_STATE_DIR=${DEVICE_STATE_DIR:-"$REPO_ROOT/scripts/device-state"}
STATE_FILE="$DEVICE_STATE_DIR/${PSEUDONYMOUS_ID}.json"

if [[ ! -f "$STATE_FILE" ]]; then
  echo "error: device state file not found: $STATE_FILE" >&2
  exit 1
fi

TOKEN_TTL_SECONDS=${TOKEN_TTL_SECONDS:-60}

b64urlencode() {
  python3 -c "import base64, sys; data = sys.stdin.buffer.read(); print(base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii'))"
}

STATE=$(cat "$STATE_FILE")
USER_ID=$(echo "$STATE" | jq -r '.userId')
DEVICE_ID=$(echo "$STATE" | jq -r '.deviceId')
PRIVATE_KEY_B64=$(echo "$STATE" | jq -r '.privateKey')
KEY_ID=$(echo "$STATE" | jq -r '.keyId // "push-device-client-key"')
REALM_BASE_DEFAULT=$(echo "$STATE" | jq -r '.realmBase // empty')
REALM_BASE=${REALM_BASE:-$REALM_BASE_DEFAULT}
REALM_BASE=${REALM_BASE:-http://localhost:8080/realms/push-mfa}

for value in "$USER_ID" "$DEVICE_ID" "$PRIVATE_KEY_B64"; do
  if [[ -z $value || $value == "null" ]]; then
    echo "error: device state missing required fields" >&2
    exit 1
  fi
done

KEY_FILE="$DEVICE_STATE_DIR/${PSEUDONYMOUS_ID}.key"
python3 - "$PRIVATE_KEY_B64" "$KEY_FILE" <<'PY'
import base64, sys
b64 = sys.argv[1]
path = sys.argv[2]
with open(path, 'wb') as fh:
    fh.write(base64.b64decode(b64))
PY

SIGNING_EXP=$(($(date +%s) + TOKEN_TTL_SECONDS))
ASSERTION_PAYLOAD=$(jq -n \
  --arg sub "$USER_ID" \
  --arg deviceId "$DEVICE_ID" \
  --arg exp "$SIGNING_EXP" \
  '{"sub": $sub, "deviceId": $deviceId, "exp": ($exp|tonumber)}')
ASSERTION_HEADER_B64=$(printf '{"alg":"RS256","kid":"%s","typ":"JWT"}' "$KEY_ID" | b64urlencode)
ASSERTION_PAYLOAD_B64=$(printf '%s' "$ASSERTION_PAYLOAD" | b64urlencode)
ASSERTION_SIGNATURE_B64=$(printf '%s' "$ASSERTION_HEADER_B64.$ASSERTION_PAYLOAD_B64" | openssl dgst -binary -sha256 -sign "$KEY_FILE" | b64urlencode)
DEVICE_ASSERTION="$ASSERTION_HEADER_B64.$ASSERTION_PAYLOAD_B64.$ASSERTION_SIGNATURE_B64"

UPDATE_URL="$REALM_BASE/push-mfa/device/firebase"
echo ">> Updating Firebase ID for $PSEUDONYMOUS_ID"
curl -s -X PUT \
  -H "Authorization: Bearer $DEVICE_ASSERTION" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg firebaseId "$NEW_FIREBASE_ID" '{"firebaseId": $firebaseId}')" \
  "$UPDATE_URL" | jq
