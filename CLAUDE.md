# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Minimal Fastify 5 + TypeScript API (compiled to CommonJS).

## Commands

- `npm run dev` — run `src/server.ts` with `tsx watch` (port from `PORT`, default 3000)
- `npm run build` — `tsc -p tsconfig.build.json` → `dist/` (src only); `npm start` runs it
- `npm test` — Jest via ts-jest
  - single file: `npm test -- test/me.test.ts`
  - single test by name: `npm test -- -t "rejects malformed"`
- `npm run lint` — ESLint (flat config) **and** `prettier --check`; `npm run format` fixes formatting

## Architecture

- `src/app.ts` exports `buildApp(opts)`, which builds the Fastify instance and registers routes without listening. `src/server.ts` is the only entry point that calls `listen`. Tests call `buildApp()` and exercise routes with `app.inject()`, never over a real port.
- Auth (`src/auth.ts`): `requireAuth(verifier)` is an `onRequest` hook that parses `Authorization: Bearer <token>`, calls a `TokenVerifier` (`token => Promise<AuthUser | null>`), sets `request.user` (typed via a `declare module 'fastify'` augmentation), or replies 401 with a `WWW-Authenticate` header. `buildApp({ verifyToken })` **requires** a verifier; there is no default.
- `src/server.ts` awaits `verifierFromEnv()` (async) before building the app. With `OIDC_ISSUER` and `OIDC_AUDIENCE` set it returns the real verifier from `src/verifiers/oidc.ts`; with exactly one set it throws; with neither it throws unless `ALLOW_STUB_AUTH=1` **and** `NODE_ENV` is `development` or `test` (both set by `npm run dev`). `stubVerifier` **decodes the JWT payload without verifying the signature** (requires a string `sub`) and also throws in production. Verifier changes belong in `src/verifiers/` and `verifierFromEnv`, not in routes or `requireAuth`.
- The OIDC verifier (`jose`): `buildOidcVerifier` is pure (takes a key resolver, so tests pass a local JWKS); `createOidcVerifier` does startup discovery and builds the cached remote JWKS. It pins `RS256`, matches `iss` exactly (trailing slash matters), checks `aud`, requires `exp`, allows 30 s skew, and returns `null` for bad tokens. It **rethrows** key-source failures (so `requireAuth` answers 503) and must never rethrow claim errors (they carry the payload) or log tokens. Tests are offline: sign with a generated key pair, a local `node:http` server stands in for the provider.
- `buildApp` registers `@fastify/helmet` and `@fastify/rate-limit` (100/min), then the routes inside a separate plugin. Keep new routes in that plugin: rate-limit only covers routes added after it loads. `server.ts` binds to `HOST` (default `127.0.0.1`; set `0.0.0.0` in deploy config) and reads `TRUST_PROXY` (hop count, default off) via `src/config.ts`; the rate-limit store is in-memory, so use a shared store if you run several instances. Logger config in `server.ts` redacts the `authorization` and `cookie` headers; a verifier that throws yields a generic 503.
- `/me` has a response schema that whitelists `sub` and `email`; add new exposed claims there.
- Authorization (`src/scopes.ts`): `requireScope(...scopes)` (needs ALL listed, exact case-sensitive whole-token match, 403 with `WWW-Authenticate: insufficient_scope`) goes **after** `requireAuth`, and both go in **`onRequest`**, not `preHandler`: Fastify validates the body before `preHandler`, so auth there would answer 400 to callers who are not allowed in. `parseScope` normalizes the `scope` claim and is shared by the OIDC verifier and the stub. `requireScope` without `requireAuth` fails closed with a generic 500. Demo routes live in `src/routes/notes.ts` (in-memory, per `sub`).
- `buildApp` runs Ajv strict (`coerceTypes: false`, `removeAdditional: false`): Fastify's defaults coerce `5` to `"5"` and silently drop extra properties, which hides bad input. A future route with numeric query or path params must either declare them as strings and parse them, or relax validation for that route.
- `buildApp` sets a global error handler: errors with a status below 500 (validation 400, 413, rate-limit 429) keep their message, anything else becomes a generic `500 {"error":"Internal Server Error"}` with the detail logged server-side. Fastify's default handler would send `err.message` to clients, so do not remove this before adding a database or other libraries that throw descriptive errors.

## Environment quirks

- **Jest needs `--experimental-vm-modules`** (already set in the `test` script via `NODE_OPTIONS`). Fastify's `inject()` pulls in `light-my-request` → `cookie@2`, which is ESM-only; without the flag Jest fails with a require-ESM / "unexpected token" error. Run Jest through `npm test`, not bare `npx jest`, or set the flag yourself. The `ExperimentalWarning` it prints is expected. `jose` 6 is also ESM-only and needs the same flag under Jest; compiled code loads it with `require`, which needs Node >= 22.12 (see `engines`).
- **The project lives in an iCloud-synced Desktop folder.** `node_modules` is a symlink to `node_modules.nosync/` so iCloud doesn't evict package files (evicted files show as `dataless` in `ls -lO` and cause "Invalid package config" / "Cannot find module" errors). Keep this layout when reinstalling; both paths are git-, ESLint- and Prettier-ignored.
- Formatting uses **tabs**, set explicitly by `useTabs` in `.prettierrc.json`. Keep that setting: the user's `~/.editorconfig` also uses tabs, and Prettier's `.editorconfig` lookup stops at the project root once `.git` exists, so dropping it makes Prettier default to spaces.
- Remaining `npm audit` findings are in Jest's dev-dependency tree; `npm audit --omit=dev` is clean.
