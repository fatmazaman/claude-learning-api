# claude-learning-api

A minimal [Fastify](https://fastify.dev) 5 + TypeScript API with bearer-token auth, compiled to CommonJS.

## Getting started

```bash
npm install
npm run dev   # http://127.0.0.1:3000, restarts on change
```

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
| `ALLOW_STUB_AUTH` | unset       | `1` enables the insecure stub verifier. Only honored when `NODE_ENV` is `development` or `test` |
| `NODE_ENV`        | unset       | See above                                                                                       |

## Authentication

`requireAuth(verifier)` in `src/auth.ts` is a `preHandler` that reads `Authorization: Bearer <token>`, passes the token to a `TokenVerifier`, and sets `request.user`. It replies `401` for a missing or invalid token and a generic `503` if the verifier itself throws.

There is **no real verifier yet**. The only one is `stubVerifier`, which decodes the JWT payload **without checking the signature**, so anyone can forge a token. The server refuses to start unless the stub is explicitly allowed (see `ALLOW_STUB_AUTH` above), which means it will not start in production as is.

To add real OAuth/OIDC, write a `TokenVerifier` (for example with `jose` and the issuer's JWKS) that checks signature, `exp`, `iss` and `aud`, and return it from `verifierFromEnv()` in `src/auth.ts`. Routes and `requireAuth` should not need to change.

## Project layout

```
src/app.ts      buildApp(): builds the Fastify instance and routes, never listens
src/auth.ts     requireAuth, TokenVerifier, stubVerifier, verifierFromEnv
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

The secrets hook is a guardrail for Claude's tool calls, not access control. Its Bash check is best effort: it tests each word of the command, so it misses indirection such as `cat $(echo .e)nv` and symlinks. It also blocks a Bash command that merely mentions `.env` in plain text, for example in a commit message, so put the message in a file and use `git commit -F`.

See `CLAUDE.md` for further development notes.
