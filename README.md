# claude-learning-api

A minimal [Fastify](https://fastify.dev) 5 + TypeScript API with bearer-token auth, compiled to CommonJS.

## Getting started

```bash
npm install
npm run dev   # http://127.0.0.1:3000, restarts on change
```

Requires Node.js 22.12 or newer (the OIDC library, `jose`, is ESM-only and is loaded with `require`).

`npm run dev` sets `NODE_ENV=development` and `ALLOW_STUB_AUTH=1` so you can call protected routes locally (see [Authentication](#authentication)).

## Scripts

| Command                       | What it does                               |
| ----------------------------- | ------------------------------------------ |
| `npm run dev`                 | Run `src/server.ts` with `tsx watch`       |
| `npm run build`               | Compile `src/` to `dist/`                  |
| `npm start`                   | Run the compiled server (`dist/server.js`) |
| `npm test`                    | Jest via ts-jest                           |
| `npm test -- test/me.test.ts` | Run a single test file                     |
| `npm run lint`                | ESLint and `prettier --check`              |
| `npm run format`              | Fix formatting with Prettier               |

Run Jest through `npm test`, not bare `npx jest`: it needs `--experimental-vm-modules`, which the script sets.

## Endpoints

| Method | Path      | Auth                         | Response                                                                                           |
| ------ | --------- | ---------------------------- | -------------------------------------------------------------------------------------------------- |
| GET    | `/health` | none                         | `{ "status": "ok" }`                                                                               |
| GET    | `/me`     | Bearer                       | `{ "sub": "...", "email": "..." }` (only these two claims)                                         |
| GET    | `/notes`  | Bearer + scope `notes:read`  | The caller's own notes                                                                             |
| POST   | `/notes`  | Bearer + scope `notes:write` | Creates a note from `{ "text": "..." }` (1 to 500 characters), `201`; at most 100 per user (`409`) |

Notes are a demo resource: in memory, per user (keyed by the token's `sub`), gone on restart. A token without the needed scope gets `403`, not `200`; see [Authorization](#authorization-scopes).

With `MCP_ENABLED=1` the same notes are also served as an MCP server: `POST /mcp` (Bearer; see [MCP server](#mcp-server-oauth-protected)) and the public `GET /.well-known/oauth-protected-resource` and `GET /.well-known/oauth-protected-resource/mcp`.

Requests are rate limited to 100 per minute per client, **including requests that fail authentication** (a flood of bad tokens is limited too), and responses carry security headers from `@fastify/helmet`. Unexpected server errors return a generic `500`; the detail is logged, never sent to the client.

```bash
# a throwaway unsigned token, only accepted by the dev stub verifier
TOKEN="x.$(printf '{"sub":"user-1","email":"a@b.c"}' | base64 | tr '+/' '-_' | tr -d '=').y"
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:3000/me
```

## Configuration

| Variable              | Default     | Purpose                                                                                                |
| --------------------- | ----------- | ------------------------------------------------------------------------------------------------------ |
| `PORT`                | `3000`      | Port to listen on                                                                                      |
| `HOST`                | `127.0.0.1` | Interface to bind. Set `0.0.0.0` in container or deploy config                                         |
| `TRUST_PROXY`         | off         | Number of trusted reverse-proxy hops (e.g. `1` behind one load balancer). Invalid means off            |
| `OIDC_ISSUER`         | unset       | OIDC issuer URL, exactly as in the token's `iss` claim (Auth0: with a trailing slash)                  |
| `OIDC_AUDIENCE`       | unset       | Audience (`aud`) tokens must be issued for. Must be set together with `OIDC_ISSUER`                    |
| `MCP_ENABLED`         | unset       | `1` serves the MCP server at `/mcp`. Needs the OIDC verifier; `OIDC_AUDIENCE` must then be the MCP URL |
| `MCP_ALLOWED_ORIGINS` | unset       | Comma-separated hostnames allowed in the `Origin` header besides localhost (browser-based MCP clients) |
| `ALLOW_STUB_AUTH`     | unset       | `1` enables the insecure stub verifier. Only honored when `NODE_ENV` is `development` or `test`        |
| `NODE_ENV`            | unset       | See above                                                                                              |

## Authentication

`requireAuth(verifier)` in `src/auth.ts` is an `onRequest` hook that reads `Authorization: Bearer <token>`, passes the token to a `TokenVerifier`, and sets `request.user`. It replies `401` for a missing or invalid token, and a generic `503` if the verifier could not check the token at all (for example the provider's keys are unreachable). Every `401` carries a `WWW-Authenticate` header: `Bearer` when no token was sent, `Bearer error="invalid_token"` when one was sent and rejected.

**OIDC verifier.** Set `OIDC_ISSUER` and `OIDC_AUDIENCE` and the server verifies tokens with `src/verifiers/oidc.ts`, built on [`jose`](https://github.com/panva/jose):

- **Startup:** it fetches `<issuer>/.well-known/openid-configuration`, requires the document's `issuer` to equal `OIDC_ISSUER` exactly, and reads `jwks_uri`. If any of that fails, the server refuses to start. Setting only one of the two variables is also an error.
- **Per request:** it checks the signature (**RS256 only**, which rules out `alg: none` and HS256 key-confusion), `iss` (exact match), `aud`, `exp` (required) and `nbf`, allowing 30 seconds of clock skew. Any failure is a `401`. The token is never logged.
- **Key rotation:** the key set is cached for 10 minutes. A token with an unknown `kid` triggers a refetch, at most once every 30 seconds, so a just-rotated key may get `401`s for a short while.
- **Issuer format:** `OIDC_ISSUER` must equal the token's `iss` claim character for character. Auth0 issuers end in a slash (`https://TENANT.auth0.com/`).
- **Mapping:** only `sub`, `scope` (as a list), `exp` and the client id (`client_id` or `azp`) reach `request.user`, so `/me` returns just `sub`.
- **Not enforced:** the `typ` header (RFC 9068 `at+jwt`).

**Dev stub.** If neither OIDC variable is set, the server starts only with `ALLOW_STUB_AUTH=1` and `NODE_ENV` of `development` or `test`. `stubVerifier` decodes the JWT payload **without checking the signature**, so anyone can forge a token. Never use it outside local development.

The verifier tests are fully offline: they sign tokens with a key pair generated in the test, and a throwaway server on `127.0.0.1` stands in for the provider.

## Authorization (scopes)

Authentication says who the caller is; scopes say what they may do. `requireScope(...scopes)` in `src/scopes.ts` runs after `requireAuth` and answers `403`, not `200`, when the token lacks a needed scope:

```ts
instance.get('/notes', { onRequest: [requireAuth(verify), requireScope('notes:read')] }, handler);
```

- **401 vs 403:** `401` means "I don't know who you are" (missing or invalid token). `403` means "I know who you are, and you may not do this". A `403` carries `WWW-Authenticate: Bearer error="insufficient_scope", scope="notes:write"`, naming what is needed (RFC 6750).
- **Matching:** the token must hold **all** the listed scopes. Whole tokens match exactly and case-sensitively, so `notes:readonly` does not satisfy `notes:read`. No wildcards, no hierarchy. A malformed `scope` claim grants nothing.
- **Source:** the token's `scope` claim, as a space-delimited string or an array. Other providers' claims (Auth0 RBAC's `permissions` array, Okta's `scp`, Azure's `roles`) are not mapped.
- **Why `onRequest`:** Fastify validates the body _before_ `preHandler`. With auth there, a caller who is not allowed in would get a `400` describing the schema instead of a `401`/`403`. In `onRequest` the check runs before the body is even parsed. Tests cover both orderings.
- **Strict validation:** the app turns off Fastify's default type coercion and silent removal of extra properties, so `{"text": 5}` and `{"text": "ok", "extra": 1}` are a `400`, not quietly rewritten.
- **Misuse fails closed:** a route that uses `requireScope` without `requireAuth` before it answers a generic `500`, never a `200`.

## MCP server (OAuth-protected)

With `MCP_ENABLED=1` the app also serves the notes as an [MCP](https://modelcontextprotocol.io) server at `/mcp` (Streamable HTTP, spec revision 2026-07-28), built on the v2 TypeScript SDK (`@modelcontextprotocol/server`). It reuses the OIDC verifier and acts as an OAuth 2.0 **resource server**: it never issues tokens, it checks them.

| Tool         | Scope         | What it does                                 |
| ------------ | ------------- | -------------------------------------------- |
| `list_notes` | `notes:read`  | Lists the signed-in user's notes             |
| `add_note`   | `notes:write` | Adds a note `{ "text": "..." }` for the user |

Both tools are scoped to the token's `sub` and share one store with the REST `/notes` routes, so a note added over MCP shows up in `GET /notes` and the other way round.

**How a client gets in** (the OAuth steps are the client's job; the server publishes what it needs):

1. The client calls `/mcp` without a token and gets `401` with `WWW-Authenticate: Bearer resource_metadata="https://<host>/.well-known/oauth-protected-resource/mcp", scope="notes:read"`.
2. It fetches that [protected resource metadata](https://datatracker.ietf.org/doc/html/rfc9728): `resource` (this server), `authorization_servers` (your `OIDC_ISSUER`) and `scopes_supported`. The same document is also served at `/.well-known/oauth-protected-resource`.
3. It discovers Auth0, registers itself, and runs the authorization-code flow with PKCE, asking for `notes:read` first (least privilege) and sending `resource=<this server's URL>`.
4. It calls `/mcp` with the token. A write (`add_note`) with a read-only token gets **`403`** with `WWW-Authenticate: Bearer error="insufficient_scope", scope="notes:write", resource_metadata="…"`, which tells the client to step up and ask the user for write access.

**Configuration.** `MCP_ENABLED=1` needs the real OIDC verifier (the stub accepts forged tokens, so the server refuses to start with it). `OIDC_AUDIENCE` is the server's resource identifier and must be exactly the MCP URL: `https://<host>/mcp` in canonical form (`http://localhost:3000/mcp` is allowed for local testing), no query or fragment, path `/mcp`. Anything else refuses to start. `MCP_ALLOWED_ORIGINS` (hostnames, comma-separated) adds browser origins to the localhost ones.

**What the server enforces** (MCP authorization spec, resource-server side):

- **Audience-bound tokens:** only tokens issued for this server (`aud` equals the MCP URL) are accepted; anything else is `401`. The REST routes share that audience, so a token for one works on both.
- **No token passthrough:** the MCP code makes no outbound requests. Once the token is verified, the `Authorization` header is removed from the request before the SDK sees it (the SDK otherwise hands tools the original request, headers included), and the description of the caller carries a blank token, so no tool can read or forward it. Tests spy on `fetch` and `http` and check the hand-off.
- **No long-lived streams:** `subscriptions/listen` is rejected (nothing here ever changes), so an authenticated caller cannot hold connections open.
- **Header only:** the token is read from `Authorization: Bearer` on every request, never from the query string.
- **DNS rebinding protection:** a `Host` that is not allowed, or an `Origin` that is present but not allowed (including `null`), gets `403` before authentication. A missing `Origin` is fine (non-browser clients).
- **Stateless:** the 2026-07-28 transport has no sessions. `GET` and `DELETE` answer `405`, an `Mcp-Session-Id` from an older client is ignored, and 2025-era clients (an `initialize` handshake) are served statelessly from the same tools.
- **Rate limited:** like every route, including requests that fail authentication.

**What Auth0 must be configured for** (from [Auth0's MCP guide](https://auth0.com/ai/docs/mcp/get-started/authorization-for-your-mcp-server) and its client-registration pages):

1. **Settings, Advanced:** turn on **Resource Parameter Compatibility Profile** (MCP clients send the RFC 8707 `resource` parameter; Auth0 otherwise only reads `audience`) and **Include Issuer in Authorization Responses**.
2. **Client registration:** turn on **Dynamic Client Registration** (or the Client ID Metadata Documents setting if your tenant offers it) so MCP clients can register themselves. Auth0 warns that an open endpoint lets anyone create applications in your tenant.
3. **Domain-level connections:** promote the login connection(s) to domain level (`is_domain_connection: true`), because dynamically registered applications are third-party.
4. **The API:** its **Identifier** is the MCP URL (exactly `OIDC_AUDIENCE`), signing algorithm **RS256**, permissions `notes:read` and `notes:write`.
5. **Who gets which scope:** with RBAC on, put the permissions in roles and assign them to users, and set **Default Permissions for Third-Party Applications** on the API so dynamically registered clients can be granted them.
6. **Machine-to-machine apps** (such as the end-to-end script's): authorize them for this API and its scopes.

**Try it.** Locally, use `OIDC_AUDIENCE=http://localhost:3000/mcp`. Then connect a client, for example `npx @modelcontextprotocol/inspector`, or `claude mcp add --transport http notes http://localhost:3000/mcp`, and complete the browser login. A hosted client (claude.ai, ChatGPT) needs a public HTTPS URL, for example a tunnel, with the API identifier set to that URL.

**Not covered:** MCP resources and prompts, change subscriptions (`subscriptions/listen`), browser CORS for `/mcp` beyond the origin allowlist, and a shared event bus for multi-instance deployments.

## Verified with a real MCP client

The MCP server was tested end to end with [MCP Inspector](https://github.com/modelcontextprotocol/inspector) 2.13.0 against a real Auth0 tenant (2026-11-20), using `http://localhost:3000/mcp` as the resource. What happened, in order:

1. Connect: `POST /mcp` answered `401` with the `resource_metadata` and `scope="notes:read"` challenge.
2. The client read the protected resource metadata, found Auth0, registered itself (Dynamic Client Registration) and sent the user to Auth0 with PKCE and `resource=http://localhost:3000/mcp`, asking for `notes:read`.
3. After login and consent the server accepted the token. This Inspector version speaks protocol 2025-11-25, so its `initialize` handshake was served by the stateless fallback, then `tools/list` and `list_notes` worked.
4. `add_note` with the read-only token got `403 insufficient_scope` (`scope="notes:write"`). The Inspector showed an "Additional permissions required" step-up that re-authorized with the union of the old and new scopes. After approving it, `add_note` succeeded and `list_notes` showed the note.

**If it does not work, check these** (each one was hit during this test):

| What you see                                                                                                                   | Cause                                                                                                                                                 | Fix                                                                                                                                                              |
| ------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Inspector: "Incompatible auth server: does not support dynamic client registration"                                            | Dynamic Client Registration is off, so Auth0's discovery page (`https://<tenant>/.well-known/openid-configuration`) has no `registration_endpoint`    | Turn on Dynamic Client Registration in Auth0 (Settings, Advanced), then check that field appears                                                                 |
| The same error after you turned it on, and your server's log shows only `POST /mcp` with a `401` and no `GET /.well-known/...` | The Inspector saved the earlier failure on disk (`~/.mcp-inspector/storage/oauth.json`), so restarting it or using a private window does not clear it | Stop the Inspector, move `~/.mcp-inspector/storage` aside, start it again                                                                                        |
| Auth0: "Callback URL mismatch"                                                                                                 | The Inspector registers `http://localhost:6274/oauth/callback`, but the page is open on `127.0.0.1`                                                   | In the registered application's **URLs** tab, add `http://127.0.0.1:6274/oauth/callback` to Allowed Callback URLs and save                                       |
| Auth0: "Client … is not authorized to access resource server"                                                                  | Applications that register themselves are third-party and get no API access by default                                                                | On the API, authorize user access for `notes:read` and `notes:write` (Settings, Default Permissions for Third-Party Applications, or the Application Access tab) |
| `scripts/auth0-e2e.sh`: "Service not enabled within domain"                                                                    | No API has that identifier, and identifiers cannot be edited                                                                                          | Create an API whose Identifier is exactly `OIDC_AUDIENCE`, add the two permissions, and authorize your machine-to-machine app                                    |

Dynamic Client Registration is open to anyone while it is on (anyone can create applications in your tenant), so turn it off again after testing and delete the test applications it created.

## Verified against Auth0

`scripts/auth0-e2e.sh` checks the verifier against a real Auth0 tenant. It requests a client-credentials token, starts the compiled server against the tenant, and calls `/me` with the real token and with tampered copies. Put `AUTH0_DOMAIN`, `AUTH0_AUDIENCE`, `AUTH0_CLIENT_ID` and `AUTH0_CLIENT_SECRET` in an untracked `.env.auth0` file and run the script yourself. It never prints the secret or the token. Output from a passing run (tenant and client ID replaced with placeholders):

```
1. Requesting a client-credentials token from YOUR-TENANT.us.auth0.com
2. Token received (not printed). Its decoded header and claims:
   header: {"alg":"RS256","typ":"JWT","kid":"..."}
   claims: {"iss":"https://YOUR-TENANT.us.auth0.com/","aud":"https://api.claude-learning.example","sub":"CLIENT_ID@clients","expires":"..."}
3. Building and starting the real server against https://YOUR-TENANT.us.auth0.com/
   server is up (discovery against your tenant succeeded)
4. Calling GET /me
   PASS  no token                             -> 401 {"error":"Unauthorized"}
   PASS  real Auth0 token                     -> 200 {"sub":"CLIENT_ID@clients"}
   PASS  same token, payload changed to admin -> 401 {"error":"Unauthorized"}
   PASS  same token, signature altered        -> 401 {"error":"Unauthorized"}
5. Did the server log the token or its signature?
   PASS  not in the server log
```

Two things this run shows. Auth0's `iss` ends in a slash and matches `OIDC_ISSUER` exactly. Auth0 access tokens carry `typ: JWT` rather than `at+jwt`, which is why the `typ` header is not enforced. Machine-to-machine tokens have no `scope` claim until you grant the app permissions.

The script also checks scopes against the `/notes` routes, with the expected status following the scopes in the token. With the Auth0 app granted only `notes:read`, `GET /notes` is `200` and `POST /notes` is `403` with `WWW-Authenticate: Bearer error="insufficient_scope", scope="notes:write"`. After also granting `notes:write`, the same token flow gives `201` on `POST /notes`. The token and the user are identical in both runs; only the granted permission changes the result.

## Project layout

```
src/app.ts      buildApp(): builds the Fastify instance and routes, never listens
src/auth.ts     requireAuth, TokenVerifier, stubVerifier, verifierFromEnv
src/scopes.ts   parseScope, requireScope (403 insufficient_scope)
src/verifiers/  oidc.ts: the real OIDC token verifier (jose)
src/notes-store.ts  the in-memory notes behind both REST and MCP
src/routes/     notes.ts: the REST notes routes
src/mcp/        the MCP server: config, metadata, guard, tools, routes
src/config.ts   HOST and TRUST_PROXY parsing
src/server.ts   entry point: the only place that calls listen()
test/           Jest tests; routes are exercised with app.inject(), not a real port
.claude/        Claude Code project config: skills/, hooks/ and settings.json
```

Add new routes inside the plugin in `buildApp`: its first hook is the rate limiter, which must run before any route's own auth hooks.

## Security review

A project skill, `.claude/skills/fastify-security-review`, reviews changed code for missing auth, secrets in logs, missing input validation, missing 401/403 tests and relevant OWASP Top 10 issues. In Claude Code, run `/fastify-security-review`.

## Security review eval

To check that the review skill really catches problems, the [`test-review`](https://github.com/fatmazaman/claude-learning-api/tree/test-review) branch plants two security bugs on top of `main`: an unauthenticated route and a bearer token written to the logs. Tests, lint and the typecheck all stay green there, so only the review catches them.

Read the [write-up](https://github.com/fatmazaman/claude-learning-api/blob/test-review/docs/security-review-demo.md) for the bugs, the proof and the fixes. The branch is intentionally vulnerable (its commit is labeled "DO NOT MERGE") and must never be merged into `main`.

## Claude Code hooks

Project hooks in `.claude/settings.json` apply to anyone running Claude Code in this repo. Claude Code may ask you to approve them the first time.

- **Format on edit** (PostToolUse): after an Edit or Write to a `.ts` file, runs `prettier --write` on it. It never blocks an edit.
- **Block secrets** (PreToolUse, `.claude/hooks/block-secrets.sh`): stops Claude from reading or editing `.env` files (`.env.example` and `.env.sample` are allowed) or anything under `secrets/`. The script exits `0` to allow, or `2` to block and send its stderr to Claude as the reason. It fails closed: input it can't parse is blocked too.

A second layer sits beside the hook: `permissions.deny` rules in the same file make Claude Code itself refuse `Read` of `.env`, `.env.*` and `secrets/**`, and `Edit` (which also covers Write) of `.env` and `secrets/**`. The deny rules do not exempt `.env.example`, so Claude cannot read that file with the Read tool even though the hook allows it. Remove `Read(./.env.*)` from the deny list if you want that file readable.

The secrets hook is a guardrail for Claude's tool calls, not access control. Its Bash check is best effort: it tests each word of the command, so it misses indirection such as `cat $(echo .e)nv` and symlinks. It also blocks a Bash command that merely mentions `.env` in plain text, for example in a commit message, so put the message in a file and use `git commit -F`.

See `CLAUDE.md` for further development notes.
