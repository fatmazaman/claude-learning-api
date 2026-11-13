#!/usr/bin/env bash
# Auth0 end-to-end check: get a REAL client-credentials token from your tenant, start the
# real compiled server against it, and call /me with the token, then with tampered copies.
#
# Credentials come from an untracked file in the project root (see "Setup" in the steps).
# This script never prints the client secret or the token. Run it yourself from the project
# root (in Claude Code: type `! scripts/auth0-e2e.sh`), not through Claude.
set -euo pipefail
cd "$(dirname "$0")/.."

for tool in curl jq node npm; do
	command -v "$tool" >/dev/null || { echo "Missing required tool: $tool" >&2; exit 1; }
done

ENV_FILE=.env.auth0
[ -f "$ENV_FILE" ] || {
	echo "Missing $ENV_FILE. Create it in your own editor (not in chat); see the setup steps." >&2
	exit 1
}
set -a
# shellcheck disable=SC1090
. "./$ENV_FILE"
set +a
for name in AUTH0_DOMAIN AUTH0_AUDIENCE AUTH0_CLIENT_ID AUTH0_CLIENT_SECRET; do
	[ -n "${!name:-}" ] || { echo "$name is not set in $ENV_FILE" >&2; exit 1; }
done

# Accept the domain as pasted from the dashboard, with or without "https://" or a trailing slash.
AUTH0_DOMAIN=${AUTH0_DOMAIN#https://}
AUTH0_DOMAIN=${AUTH0_DOMAIN%/}

ISSUER="https://${AUTH0_DOMAIN}/" # Auth0's iss claim ends with a slash
PORT=${PORT:-3457}
BASE="http://127.0.0.1:${PORT}"
failed=0

echo "1. Requesting a client-credentials token from ${AUTH0_DOMAIN}"
# The secret goes to curl on stdin, so it never appears in a process list.
response=$(
	jq -n --arg id "$AUTH0_CLIENT_ID" --arg secret "$AUTH0_CLIENT_SECRET" --arg aud "$AUTH0_AUDIENCE" \
		'{client_id: $id, client_secret: $secret, audience: $aud, grant_type: "client_credentials"}' |
		curl -sS -X POST "https://${AUTH0_DOMAIN}/oauth/token" \
			-H 'content-type: application/json' --data @- -w '\n%{http_code}'
)
status=${response##*$'\n'}
body=${response%$'\n'*}
if [ "$status" != 200 ]; then
	echo "   token request failed: HTTP $status"
	printf '%s' "$body" | jq -r '[.error, .error_description] | map(select(. != null)) | .[]' 2>/dev/null || true
	exit 1
fi
TOKEN=$(printf '%s' "$body" | jq -r .access_token)
export TOKEN
# The server must not inherit the credentials.
unset AUTH0_CLIENT_SECRET AUTH0_CLIENT_ID response body

echo "2. Token received (not printed). Its decoded header and claims:"
node -e '
const [h, p] = process.env.TOKEN.split(".").slice(0, 2).map((s) => JSON.parse(Buffer.from(s, "base64url")));
console.log("   header:", JSON.stringify({ alg: h.alg, typ: h.typ, kid: h.kid }));
const { iss, aud, sub, scope, exp } = p;
console.log("   claims:", JSON.stringify({ iss, aud, sub, scope, expires: new Date(exp * 1000).toISOString() }));
'

# Same token with the payload changed to sub=admin (signature no longer matches).
TAMPERED_PAYLOAD=$(node -e '
const [h, p, s] = process.env.TOKEN.split(".");
const payload = JSON.parse(Buffer.from(p, "base64url"));
payload.sub = "admin";
console.log([h, Buffer.from(JSON.stringify(payload)).toString("base64url"), s].join("."));
')
# Same token with the last signature bytes flipped.
TAMPERED_SIGNATURE=$(node -e '
const [h, p, s] = process.env.TOKEN.split(".");
console.log([h, p, s.slice(0, -2) + (s.endsWith("AA") ? "BB" : "AA")].join("."));
')

echo "3. Building and starting the real server against ${ISSUER}"
npm run build --silent
LOG=$(mktemp)
NODE_ENV=production PORT="$PORT" OIDC_ISSUER="$ISSUER" OIDC_AUDIENCE="$AUTH0_AUDIENCE" \
	node dist/server.js >"$LOG" 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true; rm -f "$LOG"' EXIT

for _ in $(seq 1 40); do
	if curl -sf "$BASE/health" >/dev/null 2>&1; then break; fi
	if ! kill -0 "$SERVER_PID" 2>/dev/null; then
		echo "   server exited during startup:"
		sed 's/^/   | /' "$LOG"
		exit 1
	fi
	sleep 0.25
done
curl -sf "$BASE/health" >/dev/null || { echo "   server did not become healthy" >&2; exit 1; }
echo "   server is up (discovery against your tenant succeeded)"

bearer() { printf 'Authorization: Bearer %s\n' "$1"; }

check() { # label, expected status, [curl args...]
	local label=$1 expected=$2 out code text mark=PASS
	shift 2
	out=$(curl -sS -w '\n%{http_code}' "$@" "$BASE/me")
	code=${out##*$'\n'}
	text=${out%$'\n'*}
	[ "$code" = "$expected" ] || { mark=FAIL; failed=1; }
	printf '   %s  %-36s -> %s %s\n' "$mark" "$label" "$code" "$text"
}

echo "4. Calling GET /me"
check "no token" 401
check "real Auth0 token" 200 -H @<(bearer "$TOKEN")
check "same token, payload changed to admin" 401 -H @<(bearer "$TAMPERED_PAYLOAD")
check "same token, signature altered" 401 -H @<(bearer "$TAMPERED_SIGNATURE")

echo "5. Did the server log the token or its signature?"
if grep -qF -e "$TOKEN" -e "${TOKEN##*.}" "$LOG"; then
	echo "   FAIL  found in the server log"
	failed=1
else
	echo "   PASS  not in the server log"
fi

echo
if [ "$failed" = 0 ]; then echo "All checks passed."; else echo "Some checks FAILED."; fi
exit "$failed"
