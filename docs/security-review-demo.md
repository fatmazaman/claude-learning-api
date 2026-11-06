# Security review demo: planted bugs in a Fastify API

**Branch:** `test-review` of `claude-learning-api`. The bugs are in commit `ea09618` ("DO NOT MERGE"); this document is a later commit on the same branch.
**Tool:** project skill `fastify-security-review` (`.claude/skills/fastify-security-review/SKILL.md`), run against `main...test-review`

## The story in 30 seconds

I built a small Fastify 5 + TypeScript API and hardened it through repeated security reviews (fail-closed auth, rate limiting, log redaction, tests for the 401/503 paths). To check that my review skill actually works, I created a throwaway branch and planted two realistic bugs. Tests, lint and the typecheck all stayed green, so CI would not have caught either one. The review found both, plus a missing-tests gap, and I confirmed each by running it instead of trusting the report.

## The two planted bugs

### 1. Unauthenticated route that returns any user's data (High)

`src/app.ts:40`

```ts
instance.get('/users/:id', async (request) => {
	const { id } = request.params as { id: string };
	return { id, email: `${id}@example.com`, role: 'admin' };
});
```

- No `requireAuth` preHandler, so no authentication at all.
- No ownership or role check, so it is also broken access control (IDOR): one user could read another's record.
- `params as { id: string }` is a type cast, not validation.

**Proof:** `GET /users/42` with no token returned
`200 {"id":"42","email":"42@example.com","role":"admin"}`.

**Fix:** require auth, check ownership (403 otherwise), validate `:id` with a schema, and whitelist the response fields.

```ts
instance.get(
	'/users/:id',
	{
		preHandler: requireAuth(verifyToken),
		schema: {
			params: {
				type: 'object',
				required: ['id'],
				properties: { id: { type: 'string', pattern: '^[a-zA-Z0-9_-]{1,64}$' } },
				additionalProperties: false,
			},
			response: {
				200: { type: 'object', properties: { id: { type: 'string' }, email: { type: 'string' } } },
			},
		},
	},
	async (request, reply) => {
		if (request.params.id !== request.user!.sub)
			return reply.code(403).send({ error: 'Forbidden' });
		// …load the user…
	},
);
```

### 2. Bearer token written to the logs (High)

`src/auth.ts:57`

```ts
request.log.info({ authorization: request.headers.authorization }, 'auth attempt');
```

The logger's redact list (`['req.headers.authorization', 'req.headers.cookie']`) only matches that exact path, so a custom top-level `authorization` key is not redacted.

**Proof:** one request to `/me` produced this log line:
`{"level":30,…,"authorization":"Bearer x.eyJzdWIiOiJ1MSJ9.SECRETSIG","msg":"auth attempt"}`

**Impact:** anyone with log access (log aggregator, support staff, a leaked file) can replay live tokens.

**Fix:** delete the line. If an auth-attempt log is needed, log only non-sensitive facts, e.g. `{ hasBearer: Boolean(match) }`. Also widen the redact paths (`'*.authorization'`) as defense in depth.

## What the review reported

| Severity | Finding                                                | Location              |
| -------- | ------------------------------------------------------ | --------------------- |
| High     | Unauthenticated route / broken access control          | `src/app.ts:40`       |
| High     | Raw bearer token logged                                | `src/auth.ts:57`      |
| Medium   | No validation on `:id`, echoed into the response       | `src/app.ts:41-42`    |
| Medium   | No tests for the new route (401/403/400 cases missing) | `test/` (no `/users`) |
| Low      | Redact config too narrow                               | `src/server.ts:6`     |

Verdict: **do not merge**.

## Why it matters (talking points)

- **Green CI is not a security signal.** Tests, lint and `tsc` all passed on the branch. Both bugs are only visible to a reviewer who knows what to look for, such as routes without `preHandler` and log calls that touch headers.
- **Defaults fail closed.** The real project cannot start with the forgeable stub verifier unless `ALLOW_STUB_AUTH=1` and `NODE_ENV` is `development` or `test`. A planted bug is the opposite: it fails open.
- **Verify, don't assume.** I reproduced both bugs with a small script instead of trusting a static read. That same habit caught a real problem earlier in the project: rate limiting silently did not apply to routes registered before the plugin loaded, and a test exposed it.
- **A reusable checklist.** The skill encodes the checks (auth on every route, secrets in logs, input validation, 401/403 tests, relevant OWASP Top 10) so any teammate or AI agent applies them the same way.

## How to reproduce

```bash
git checkout test-review
git diff main...ea09618       # the 8-line diff that plants the bugs
# then run /fastify-security-review in Claude Code
git checkout main             # leave the branch in place; never merge it
```
