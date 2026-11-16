import type { FastifyReply, FastifyRequest } from 'fastify';
// Type-only import: it also brings in the `request.user` augmentation declared in ./auth.
import type { AuthUser } from './auth';

/** RFC 6749 section 3.3: a scope token is one or more of %x21 / %x23-5B / %x5D-7E. */
const SCOPE_TOKEN = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

/**
 * Normalizes a `scope` claim: a space-delimited string (OAuth 2.0) or an array of strings.
 * Anything else yields undefined, so a malformed claim grants nothing.
 */
export function parseScope(value: unknown): string[] | undefined {
	if (typeof value === 'string') return value.split(/\s+/).filter(Boolean);
	if (Array.isArray(value) && value.every((item) => typeof item === 'string')) return value;
	return undefined;
}

/** True when the user holds every scope in `required` (exact, case-sensitive match). */
export function hasScopes(user: Pick<AuthUser, 'scope'>, required: readonly string[]): boolean {
	const granted = new Set(user.scope ?? []);
	return required.every((scope) => granted.has(scope));
}

/**
 * Authorization hook: the authenticated user must hold ALL of `scopes`, otherwise 403.
 * Register it after requireAuth, in `onRequest`, so it runs before the body is parsed or
 * validated (a caller who is not allowed in must not get a 400 that describes the schema).
 *
 * Scopes match whole tokens exactly: `notes:readonly` does not satisfy `notes:read`, and
 * there are no wildcards. A 403 carries `WWW-Authenticate: Bearer error="insufficient_scope"`
 * (RFC 6750) naming the scopes needed.
 */
export function requireScope(...scopes: string[]) {
	if (scopes.length === 0) {
		throw new Error('requireScope needs at least one scope.');
	}
	for (const scope of scopes) {
		// The token grammar excludes space, quote and backslash, so a scope name can never
		// break out of the quoted header value below.
		if (!SCOPE_TOKEN.test(scope)) {
			throw new Error(`Invalid scope name: ${JSON.stringify(scope)}`);
		}
	}
	const challenge = `Bearer error="insufficient_scope", scope="${scopes.join(' ')}"`;

	return async (request: FastifyRequest, reply: FastifyReply) => {
		if (!request.user) {
			// Programming error: requireScope was used without requireAuth before it. Fail
			// closed with a generic 500, and keep the detail out of the response.
			request.log.error('requireScope ran without an authenticated user; add requireAuth first');
			return reply.code(500).send({ error: 'Internal Server Error' });
		}
		if (!hasScopes(request.user, scopes)) {
			return reply.code(403).header('WWW-Authenticate', challenge).send({ error: 'Forbidden' });
		}
	};
}
