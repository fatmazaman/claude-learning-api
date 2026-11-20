---
name: fastify-security-review
description: Review changed code in this Fastify API for security issues. Checks for missing auth on routes, secrets or tokens in logs, missing input validation, missing 401/403 tests, and relevant OWASP Top 10 risks. Use when asked to security-review a diff, branch, or PR, or before merging route, auth, or logging changes.
---

# Security review (Fastify API)

Review only the **changed code**, not the whole repo. Report findings as High/Medium/Low, each with `file:line` and a suggested fix.

## 1. Find the changes

1. Run `git diff main...HEAD --stat`, then `git diff main...HEAD` for the full diff.
2. Also run `git diff` and `git diff --staged` to cover uncommitted work.
3. If the user names a PR, branch, or path, use that instead.
4. Read the full surrounding file for any changed route, plugin, or auth code. A diff alone can hide a missing `preHandler` or a validation schema defined elsewhere.

## 2. Checks

### Authentication and authorization

- Every new or changed route in `src/` must use `requireAuth(verifier)`, unless it is deliberately public (e.g. a health check). For a public route, say so explicitly in the report.
- **Hook stage:** `requireAuth` and `requireScope` must run in `onRequest` (or `preValidation`), not `preHandler`. Fastify validates the body before `preHandler`, so auth there answers 400 (and reveals the schema) to callers who are not allowed in, and parses their body first. Flag any route with a body schema whose auth is in `preHandler`.
- **Scopes:** a route that needs a permission must use `requireScope(...)` after `requireAuth`. Flag routes that authenticate but never check a scope when a resource is read or written. `requireScope` needs ALL listed scopes and matches whole tokens exactly; flag any new scope check that matches by substring, prefix or case-insensitively, or that treats a missing `scope` claim as allowed.
- Routes registered inside a plugin or encapsulated scope: confirm the auth hook actually applies there. Fastify hooks do not leak out of their encapsulation context.
- **Authorization (403)**: routes that take an id or resource must check that `request.user` owns or may access it (IDOR / broken access control). Authentication alone is not enough.
- `stubVerifier` decodes the JWT **without verifying the signature**. Flag any new code that uses it outside tests/dev, or that relaxes its `NODE_ENV=production` guard. Real auth belongs in a new `TokenVerifier` passed to `buildApp`, not in route or `requireAuth` changes.
- Flag trust in client-supplied identity (user id in body, query, or headers) instead of `request.user`.

### Secrets and tokens in logs

- Search changed code for `console.*`, `request.log.*`, `app.log.*`, and `logger` calls that include `authorization`, tokens, cookies, passwords, API keys, or whole `request.headers` / `request.body` objects.
- Check Fastify logger config: it should redact `req.headers.authorization` and `req.headers.cookie` (via `redact`).
- Error handlers must not return or log stack traces, token contents, or internal details to clients.
- Flag hard-coded secrets, keys, or credentials, and new `.env` values committed to git.

### Input validation

- Every route that reads `body`, `querystring`, `params`, or `headers` needs a JSON Schema (or type-provider schema) for that input. Flag routes that read `request.body` / `request.query` without one.
- Schemas should set `additionalProperties: false`, bounded `maxLength` / `minimum` / `maximum`, and `required` where appropriate.
- Check the Ajv options in `buildApp`. Fastify's defaults (`coerceTypes`, `removeAdditional`) turn `5` into `"5"` and silently delete extra properties, so `additionalProperties: false` strips instead of rejecting. This app sets both to `false`; flag any change that re-enables them, and any route with a per-route validator that does.
- Add a response schema where sensitive fields could leak, since it filters output.
- Flag manual parsing (`JSON.parse`, `Number(...)`, casts like `as Foo`) that substitutes for validation.

### Missing 401/403 tests

- For each new or changed protected route, check `test/` for tests using `app.inject()` that cover:
  - no `Authorization` header → 401
  - malformed header or invalid token → 401
  - valid token but not allowed (when authorization rules exist) → 403, including a token with no scope claim and one with only a near-miss scope
  - for routes with a body: an invalid body from a caller who is not allowed in → 401/403, not 400
  - validation failure → 400
- Report each missing case by route. Suggest the test name and a short `app.inject()` sketch.

### MCP server (when `src/mcp/` or the `/mcp` route changes)

The MCP server is an OAuth 2.0 resource server (MCP authorization spec). Check each of these against the code, and cite `file:line`:

- **Audience binding:** tokens must be accepted only if issued for this server (`aud` equals the MCP URL, `OIDC_AUDIENCE`). Flag any verifier change that loosens `aud`, `iss` or `exp`, and any path that accepts a token the verifier did not validate.
- **No token passthrough (spec MUST NOT):** search `src/mcp/` for `fetch`, `http.request`, `https.request`, `axios`, `got`, and for any use of `request.headers.authorization`. The `authInfo` handed to the SDK must keep `token: ''`, **and the `Authorization` header must be deleted from the request before the hand-off** (the SDK passes tools the original `Request`, so a blank `authInfo.token` alone does not stop a tool from reading the header). Also check `createMcpHandler` keeps `maxSubscriptions: 0` unless a tool really needs `subscriptions/listen` (otherwise any authenticated caller can hold long-lived streams open). Flag any tool or helper that makes an outbound call, or that can reach the caller's token.
- **Tool scoping:** every tool must declare a `scopeChallenge` (`requireScopes(...)`) matching what it reads or writes, and must read the caller from `authInfo.extra.sub`, never from arguments. Flag a tool without a scope check, a tool that takes a user id as input, or a shared (not per-`sub`) data path.
- **Challenges:** a 401 must carry `WWW-Authenticate: Bearer resource_metadata=…` (and `scope`, least privilege); an under-scoped tool call must be HTTP 403 `insufficient_scope` naming the needed scope. Flag a scope challenge that includes more than the operation needs.
- **Transport guards:** Host and Origin must be validated before authentication (DNS rebinding, spec MUST) and the response must not echo the offending value. `GET`/`DELETE` on `/mcp` must stay `405` (no sessions). A token in the query string must be ignored.
- **Metadata:** the protected resource metadata is public, so it must contain no secrets, and `resource` must equal the configured audience exactly.
- **Configuration:** `MCP_ENABLED` must refuse to start without the real OIDC verifier (never with the stub), and must reject an audience that is not the canonical `https` (or localhost `http`) URL with path `/mcp`.
- **Dependencies:** run `npm audit --omit=dev` and note new transitive packages (the SDK adapter pulls in `hono`).

### OWASP Top 10, as relevant to Fastify

- **A01 Broken access control**: missing auth/ownership checks, IDOR, overly permissive CORS (`origin: true` or `*` with credentials).
- **A02 Cryptographic failures**: weak or unsigned tokens, secrets in code, plaintext sensitive data, missing TLS assumptions.
- **A03 Injection**: string-built SQL/NoSQL/shell/template inputs, `eval`, `child_process` with user input, unsafe path joins (path traversal), unsanitized reflected HTML.
- **A04 Insecure design**: no rate limiting on login or other sensitive routes (`@fastify/rate-limit`), unbounded pagination or payload sizes. **Rate limiting must run before the route's auth hooks:** in its default mode the plugin appends its hook after them, so requests that fail auth are never counted. This app registers it with `global: false` and adds `instance.rateLimit()` as the plugin's first `onRequest` hook; flag any change that reverts that, and any route registered outside that plugin.
- **A05 Security misconfiguration**: missing `@fastify/helmet`, verbose errors, a body limit that is too large, `trustProxy` set wrongly, debug flags on.
- **A06 Vulnerable components**: new or upgraded dependencies. Run `npm audit --omit=dev` and flag production findings. (Known dev-only Jest findings are expected.)
- **A07 Authentication failures**: missing token expiry, `exp`/`aud`/`iss` unchecked, signature verification skipped.
- **A08 Integrity failures**: unsafe deserialization, unpinned or unverified dependencies or scripts.
- **A09 Logging and monitoring failures**: no logging of auth failures, or logging sensitive data (see above).
- **A10 SSRF**: server-side `fetch`/`http` calls using user-supplied URLs without an allowlist.

Only report an OWASP item if the diff actually touches it. Don't pad the report with unrelated categories.

## 3. Output format

Group findings by severity. Within each, order by impact.

```
## Security review: <branch or scope>

### High
- **<short title>** — `src/routes/foo.ts:42`
  Issue: <what is wrong and how it could be exploited>
  Fix: <specific change, with a code snippet if short>

### Medium
...

### Low
...

### Summary
<N findings: H high / M medium / L low. Verdict: safe to merge | merge after fixes | do not merge.>
```

Severity guide:

- **High**: exploitable now. Unauthenticated access to protected data or actions, auth bypass, secrets/tokens logged or committed, injection, IDOR.
- **Medium**: exploitable under some conditions, or a missing defense-in-depth control. Missing validation on non-critical input, missing rate limiting, missing 401/403 tests on protected routes, permissive CORS.
- **Low**: hardening and hygiene. Overly loose schemas, verbose errors, minor header or config gaps.

## Rules

- Cite a real `file:line` for every finding. If a finding is about something absent (e.g. a missing test), cite the route or file it should cover.
- Don't invent findings. If a category is clean, say "No issues found" for it.
- If you aren't sure whether something is exploitable, report it as Low and say what you couldn't verify.
- Review only. Do not edit code unless the user asks you to apply the fixes.
