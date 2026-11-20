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
# The MCP server needs OIDC_AUDIENCE to be the MCP URL, so turn it on only when yours is.
case "$AUTH0_AUDIENCE" in
*/mcp) MCP_ON=1 ;;
*) MCP_ON=0 ;;
esac
NODE_ENV=production PORT="$PORT" OIDC_ISSUER="$ISSUER" OIDC_AUDIENCE="$AUTH0_AUDIENCE" \
	MCP_ENABLED="$MCP_ON" node dist/server.js >"$LOG" 2>&1 &
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

echo "4b. Scopes: GET and POST /notes (expected status follows the scopes in YOUR token)"
TOKEN_SCOPE=$(node -e '
const p = JSON.parse(Buffer.from(process.env.TOKEN.split(".")[1], "base64url"));
console.log(Array.isArray(p.scope) ? p.scope.join(" ") : typeof p.scope === "string" ? p.scope : "");
')
echo "   scopes in this token: ${TOKEN_SCOPE:-(none)}"
has_scope() { case " $TOKEN_SCOPE " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }
expect_read=403
has_scope notes:read && expect_read=200
expect_write=403
has_scope notes:write && expect_write=201

check_route() { # method, path, label, expected status, [curl args...]
	local method=$1 path=$2 label=$3 expected=$4 out code text headers mark=PASS
	shift 4
	headers=$(mktemp)
	out=$(curl -sS -X "$method" -D "$headers" -w '\n%{http_code}' "$@" "$BASE$path")
	code=${out##*$'\n'}
	text=${out%$'\n'*}
	[ "$code" = "$expected" ] || { mark=FAIL; failed=1; }
	printf '   %s  %-36s -> %s %s\n' "$mark" "$label" "$code" "$text"
	if [ "$code" = 401 ] || [ "$code" = 403 ]; then
		grep -i '^www-authenticate:' "$headers" | tr -d '\r' | sed 's/^/          /' || true
	fi
	rm -f "$headers"
}

check_route GET /notes "GET /notes, no token" 401
check_route GET /notes "GET /notes (needs notes:read)" "$expect_read" -H @<(bearer "$TOKEN")
check_route POST /notes "POST /notes (needs notes:write)" "$expect_write" \
	-H @<(bearer "$TOKEN") -H 'content-type: application/json' --data '{"text":"auth0 e2e note"}'
if [ "$expect_read" = 403 ] || [ "$expect_write" = 403 ]; then
	echo "   (A 403 above is the lesson: a valid, verified token that lacks the scope is not allowed in.)"
fi
echo

echo "4c. MCP server at /mcp"
if [ "$MCP_ON" != 1 ]; then
	echo "   skipped: AUTH0_AUDIENCE is not an MCP URL (it must end in /mcp, e.g. http://localhost:3000/mcp)."
else
	# Discovery: does the published metadata point at YOUR tenant and name THIS resource?
	metadata=$(curl -sS "$BASE/.well-known/oauth-protected-resource/mcp")
	echo "   metadata: $(printf '%s' "$metadata" | jq -c .)"
	if [ "$(printf '%s' "$metadata" | jq -r '.authorization_servers[0]')" = "$ISSUER" ] &&
		[ "$(printf '%s' "$metadata" | jq -r '.resource')" = "$AUTH0_AUDIENCE" ]; then
		echo "   PASS  authorization_servers[0] is your issuer and resource is your audience"
	else
		echo "   FAIL  metadata does not name your issuer and audience"
		failed=1
	fi

	MCP_META='{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"auth0-e2e","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}'
	mcp_call() { # label, method, params JSON, expected status, [curl args...]
		local label=$1 method=$2 params=$3 expected=$4 name body out code text headers mark=PASS summary
		shift 4
		name=$(printf '%s' "$params" | jq -r '.name // empty')
		body=$(jq -nc --arg method "$method" --argjson params "$params" --argjson meta "$MCP_META" \
			'{jsonrpc: "2.0", id: 1, method: $method, params: ($params + {_meta: $meta})}')
		headers=$(mktemp)
		if [ -n "$name" ]; then
			out=$(curl -sS -X POST -D "$headers" -w '\n%{http_code}' \
				-H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
				-H 'mcp-protocol-version: 2026-07-28' -H "mcp-method: $method" -H "mcp-name: $name" \
				--data "$body" "$@" "$BASE/mcp")
		else
			out=$(curl -sS -X POST -D "$headers" -w '\n%{http_code}' \
				-H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
				-H 'mcp-protocol-version: 2026-07-28' -H "mcp-method: $method" \
				--data "$body" "$@" "$BASE/mcp")
		fi
		code=${out##*$'\n'}
		text=${out%$'\n'*}
		[ "$code" = "$expected" ] || { mark=FAIL; failed=1; }
		summary=$(printf '%s' "$text" | jq -r '
			if .result.tools then "tools: " + ([.result.tools[].name] | join(", "))
			elif .result.content then (if .result.isError then "TOOL ERROR " else "" end) + (.result.content[0].text | gsub("\\s+"; " ") | .[0:80])
			else (. | tostring | .[0:80]) end' 2>/dev/null || printf '%s' "$text" | cut -c1-80)
		printf '   %s  %-34s -> %s %s\n' "$mark" "$label" "$code" "$summary"
		if [ "$code" = 401 ] || [ "$code" = 403 ]; then
			grep -i '^www-authenticate:' "$headers" | tr -d '\r' | sed 's/^/          /' || true
		fi
		rm -f "$headers"
	}

	mcp_call "tools/list, no token" tools/list '{}' 401
	mcp_call "tools/list" tools/list '{}' 200 -H @<(bearer "$TOKEN")
	mcp_call "list_notes (needs notes:read)" tools/call '{"name":"list_notes","arguments":{}}' \
		"$([ "$expect_read" = 200 ] && echo 200 || echo 403)" -H @<(bearer "$TOKEN")
	mcp_call "add_note (needs notes:write)" tools/call '{"name":"add_note","arguments":{"text":"auth0 e2e mcp note"}}' \
		"$([ "$expect_write" = 201 ] && echo 200 || echo 403)" -H @<(bearer "$TOKEN")
	mcp_call "tools/list, payload-tampered token" tools/list '{}' 401 -H @<(bearer "$TAMPERED_PAYLOAD")
	if [ "$expect_read" = 403 ] || [ "$expect_write" = 403 ]; then
		echo "   (A 403 above is the step-up signal: the client would now ask the user for the missing scope.)"
	fi
fi
echo

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
