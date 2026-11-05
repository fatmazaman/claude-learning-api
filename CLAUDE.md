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
- Auth (`src/auth.ts`): `requireAuth(verifier)` is a `preHandler` that parses `Authorization: Bearer <token>`, calls a `TokenVerifier` (`token => Promise<AuthUser | null>`), sets `request.user` (typed via a `declare module 'fastify'` augmentation), or replies 401. `buildApp({ verifyToken })` **requires** a verifier; there is no default.
- `src/server.ts` gets its verifier from `verifierFromEnv()`, which throws unless `ALLOW_STUB_AUTH=1` (set by `npm run dev`) and refuses that opt-in when `NODE_ENV=production`. `stubVerifier` **decodes the JWT payload without verifying the signature** (requires a string `sub`) and also throws in production. Real OAuth/OIDC is meant to be added as a new `TokenVerifier` returned from `verifierFromEnv`, not by changing routes or `requireAuth`.
- `buildApp` registers `@fastify/helmet` and `@fastify/rate-limit` (100/min), then the routes inside a separate plugin. Keep new routes in that plugin: rate-limit only covers routes added after it loads. Logger config in `server.ts` redacts the `authorization` and `cookie` headers; a verifier that throws yields a generic 503.
- `/me` has a response schema that whitelists `sub` and `email`; add new exposed claims there.

## Environment quirks

- **Jest needs `--experimental-vm-modules`** (already set in the `test` script via `NODE_OPTIONS`). Fastify's `inject()` pulls in `light-my-request` → `cookie@2`, which is ESM-only; without the flag Jest fails with a require-ESM / "unexpected token" error. Run Jest through `npm test`, not bare `npx jest`, or set the flag yourself. The `ExperimentalWarning` it prints is expected.
- **The project lives in an iCloud-synced Desktop folder.** `node_modules` is a symlink to `node_modules.nosync/` so iCloud doesn't evict package files (evicted files show as `dataless` in `ls -lO` and cause "Invalid package config" / "Cannot find module" errors). Keep this layout when reinstalling; both paths are git-, ESLint- and Prettier-ignored.
- Formatting uses **tabs**, set explicitly by `useTabs` in `.prettierrc.json`. Keep that setting: the user's `~/.editorconfig` also uses tabs, and Prettier's `.editorconfig` lookup stops at the project root once `.git` exists, so dropping it makes Prettier default to spaces.
- Remaining `npm audit` findings are in Jest's dev-dependency tree; `npm audit --omit=dev` is clean.
