#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/rotate-device-key.sh <pseudonymous-user-id>

Environment overrides:
  REALM_BASE          Realm base URL (default: value stored during enrollment, fallback http://localhost:8080/realms/push-mfa)
  DEVICE_STATE_DIR    Directory storing device state from enroll.sh (default: scripts/device-state)
  TOKEN_TTL_SECONDS   Lifetime (seconds) for the device-signed assertion (default: 60)
  NEW_DEVICE_KEY_ID   Key ID to embed in the new JWK (default: generated UUID)
  NEW_DEVICE_KEY_BITS RSA key size for the new key (default: 2048)
  NEW_DEVICE_ALG      Algorithm string persisted with the credential (default: RS256)
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" || $# -ne 1 ]]; then
  usage
  exit $([[ $# -eq 1 ]] && [[ ${1:-} != "-h" && ${1:-} != "--help" ]] && echo 1 || echo 0)
fi

PSEUDONYMOUS_ID=$1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEVICE_STATE_DIR=${DEVICE_STATE_DIR:-"$REPO_ROOT/scripts/device-state"}
STATE_FILE="$DEVICE_STATE_DIR/${PSEUDONYMOUS_ID}.json"

if [[ ! -f "$STATE_FILE" ]]; then
  echo "error: device state file not found: $STATE_FILE" >&2
  exit 1
fi

TOKEN_TTL_SECONDS=${TOKEN_TTL_SECONDS:-60}
NEW_DEVICE_KEY_BITS=${NEW_DEVICE_KEY_BITS:-2048}
NEW_DEVICE_ALG=${NEW_DEVICE_ALG:-RS256}
NEW_DEVICE_KEY_ID=${NEW_DEVICE_KEY_ID:-$(python3 - <<'PY'
import uuid
print(f"device-key-{uuid.uuid4()}")
PY
)}

b64urlencode() {
  python3 -c "import base64, sys; data = sys.stdin.buffer.read(); print(base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii'))"
}

require_crypto() {
  python3 - <<'PY' >/dev/null 2>&1
import importlib.util
import sys
sys.exit(0 if importlib.util.find_spec("cryptography") else 1)
PY
}

if ! require_crypto; then
  echo "error: Python module 'cryptography' is required (install via 'python3 -m pip install --user cryptography')" >&2
  exit 1
fi

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

WORKDIR=$(mktemp -d)
cleanup() {
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

KEY_FILE="$DEVICE_STATE_DIR/${PSEUDONYMOUS_ID}.key"
python3 - "$PRIVATE_KEY_B64" "$KEY_FILE" <<'PY'
import base64, sys
b64 = sys.argv[1]
path = sys.argv[2]
with open(path, 'wb') as fh:
    fh.write(base64.b64decode(b64))
PY

NEW_PRIV_PATH="$WORKDIR/new-device.key"
NEW_PUB_PATH="$WORKDIR/new-device.pub"
echo ">> Generating new device key pair"
openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$NEW_DEVICE_KEY_BITS" -out "$NEW_PRIV_PATH" >/dev/null 2>&1
openssl rsa -pubout -in "$NEW_PRIV_PATH" -out "$NEW_PUB_PATH" >/dev/null 2>&1

NEW_JWK_PATH="$WORKDIR/new-device-jwk.json"
DEVICE_PUBLIC_KEY_PATH="$NEW_PUB_PATH" DEVICE_KEY_ID="$NEW_DEVICE_KEY_ID" python3 - <<'PY' > "$NEW_JWK_PATH"
import json, base64, os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

with open(os.environ['DEVICE_PUBLIC_KEY_PATH'], 'rb') as fh:
    key = serialization.load_pem_public_key(fh.read(), backend=default_backend())

numbers = key.public_numbers()

def b64(i: int) -> str:
    raw = i.to_bytes((i.bit_length() + 7) // 8, 'big')
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')

jwk = {
    "kty": "RSA",
    "n": b64(numbers.n),
    "e": b64(numbers.e),
    "alg": "RS256",
    "use": "sig",
    "kid": os.environ.get("DEVICE_KEY_ID", "push-device-client-key")
}

print(json.dumps(jwk))
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

ROTATE_URL="$REALM_BASE/push-mfa/device/rotate-key"
echo ">> Rotating device key for $PSEUDONYMOUS_ID"
RESPONSE=$(curl -s -X PUT \
  -H "Authorization: Bearer $DEVICE_ASSERTION" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --argjson jwk "$(cat "$NEW_JWK_PATH")" --arg algorithm "$NEW_DEVICE_ALG" '{publicKeyJwk: $jwk, algorithm: $algorithm}')" \
  "$ROTATE_URL")
echo "$RESPONSE" | jq

NEW_PRIVATE_B64=$(base64 < "$NEW_PRIV_PATH" | tr -d '\n')
NEW_PUBLIC_B64=$(base64 < "$NEW_PUB_PATH" | tr -d '\n')
UPDATED_STATE=$(jq \
  --arg privateKey "$NEW_PRIVATE_B64" \
  --arg publicKey "$NEW_PUBLIC_B64" \
  --arg keyId "$NEW_DEVICE_KEY_ID" \
  --argjson publicJwk "$(cat "$NEW_JWK_PATH")" \
  '.privateKey = $privateKey | .publicKey = $publicKey | .keyId = $keyId | .publicJwk = $publicJwk' \
  "$STATE_FILE")
printf '%s\n' "$UPDATED_STATE" > "$STATE_FILE"
echo ">> Updated device state in $STATE_FILE"
