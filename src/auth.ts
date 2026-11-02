import type { FastifyReply, FastifyRequest } from 'fastify';

export interface AuthUser {
	sub: string;
	[claim: string]: unknown;
}

/** Resolves a raw bearer token to a user, or null if the token is invalid. */
export type TokenVerifier = (token: string) => Promise<AuthUser | null>;

/**
 * STUB: decodes the JWT payload WITHOUT verifying the signature.
 * Replace with real OIDC verification (e.g. `jose` + the issuer's JWKS).
 */
export const stubVerifier: TokenVerifier = async (token) => {
	if (process.env.NODE_ENV === 'production') {
		throw new Error('stubVerifier must not be used in production');
	}
	const parts = token.split('.');
	if (parts.length !== 3) return null;
	try {
		const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
		return typeof payload?.sub === 'string' ? (payload as AuthUser) : null;
	} catch {
		return null;
	}
};

declare module 'fastify' {
	interface FastifyRequest {
		user?: AuthUser;
	}
}

export function requireAuth(verify: TokenVerifier) {
	return async (request: FastifyRequest, reply: FastifyReply) => {
		const match = /^Bearer (.+)$/.exec(request.headers.authorization ?? '');
		const user = match ? await verify(match[1]) : null;
		if (!user) {
			return reply.code(401).send({ error: 'Unauthorized' });
		}
		request.user = user;
	};
}
