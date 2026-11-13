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

| Method | Path      | Auth   | Response                                                   |
| ------ | --------- | ------ | ---------------------------------------------------------- |
| GET    | `/health` | none   | `{ "status": "ok" }`                                       |
| GET    | `/me`     | Bearer | `{ "sub": "...", "email": "..." }` (only these two claims) |

Requests are rate limited to 100 per minute per client, and responses carry security headers from `@fastify/helmet`.

```bash
# a throwaway unsigned token, only accepted by the dev stub verifier
TOKEN="x.$(printf '{"sub":"user-1","email":"a@b.c"}' | base64 | tr '+/' '-_' | tr -d '=').y"
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:3000/me
```

## Configuration

| Variable          | Default     | Purpose                                                                                         |
| ----------------- | ----------- | ----------------------------------------------------------------------------------------------- |
| `PORT`            | `3000`      | Port to listen on                                                                               |
| `HOST`            | `127.0.0.1` | Interface to bind. Set `0.0.0.0` in container or deploy config                                  |
| `TRUST_PROXY`     | off         | Number of trusted reverse-proxy hops (e.g. `1` behind one load balancer). Invalid means off     |
| `OIDC_ISSUER`     | unset       | OIDC issuer URL, exactly as in the token's `iss` claim (Auth0: with a trailing slash)           |
| `OIDC_AUDIENCE`   | unset       | Audience (`aud`) tokens must be issued for. Must be set together with `OIDC_ISSUER`             |
| `ALLOW_STUB_AUTH` | unset       | `1` enables the insecure stub verifier. Only honored when `NODE_ENV` is `development` or `test` |
| `NODE_ENV`        | unset       | See above                                                                                       |

## Authentication

`requireAuth(verifier)` in `src/auth.ts` is a `preHandler` that reads `Authorization: Bearer <token>`, passes the token to a `TokenVerifier`, and sets `request.user`. It replies `401` for a missing or invalid token, and a generic `503` if the verifier could not check the token at all (for example the provider's keys are unreachable).

**OIDC verifier.** Set `OIDC_ISSUER` and `OIDC_AUDIENCE` and the server verifies tokens with `src/verifiers/oidc.ts`, built on [`jose`](https://github.com/panva/jose):

- **Startup:** it fetches `<issuer>/.well-known/openid-configuration`, requires the document's `issuer` to equal `OIDC_ISSUER` exactly, and reads `jwks_uri`. If any of that fails, the server refuses to start. Setting only one of the two variables is also an error.
- **Per request:** it checks the signature (**RS256 only**, which rules out `alg: none` and HS256 key-confusion), `iss` (exact match), `aud`, `exp` (required) and `nbf`, allowing 30 seconds of clock skew. Any failure is a `401`. The token is never logged.
- **Key rotation:** the key set is cached for 10 minutes. A token with an unknown `kid` triggers a refetch, at most once every 30 seconds, so a just-rotated key may get `401`s for a short while.
- **Issuer format:** `OIDC_ISSUER` must equal the token's `iss` claim character for character. Auth0 issuers end in a slash (`https://TENANT.auth0.com/`).
- **Mapping:** only `sub` and `scope` (as a list) reach `request.user`, so `/me` returns just `sub`.
- **Not enforced:** the `typ` header (RFC 9068 `at+jwt`).

**Dev stub.** If neither OIDC variable is set, the server starts only with `ALLOW_STUB_AUTH=1` and `NODE_ENV` of `development` or `test`. `stubVerifier` decodes the JWT payload **without checking the signature**, so anyone can forge a token. Never use it outside local development.

The verifier tests are fully offline: they sign tokens with a key pair generated in the test, and a throwaway server on `127.0.0.1` stands in for the provider.

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

## Project layout

```
src/app.ts      buildApp(): builds the Fastify instance and routes, never listens
src/auth.ts     requireAuth, TokenVerifier, stubVerifier, verifierFromEnv
src/verifiers/  oidc.ts: the real OIDC token verifier (jose)
src/config.ts   HOST and TRUST_PROXY parsing
src/server.ts   entry point: the only place that calls listen()
test/           Jest tests; routes are exercised with app.inject(), not a real port
.claude/        Claude Code project config: skills/, hooks/ and settings.json
```

Add new routes inside the plugin in `buildApp`. Rate limiting only covers routes registered after it loads.

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
