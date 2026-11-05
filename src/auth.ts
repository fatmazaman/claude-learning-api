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

/**
 * Picks the token verifier for the running server. There is no default: the stub
 * (which accepts forged tokens) must be opted into with ALLOW_STUB_AUTH=1 and is
 * only allowed when NODE_ENV is development or test. Add a real verifier here once
 * one exists.
 */
export function verifierFromEnv(env: NodeJS.ProcessEnv = process.env): TokenVerifier {
	if (env.ALLOW_STUB_AUTH === '1') {
		if (env.NODE_ENV !== 'development' && env.NODE_ENV !== 'test') {
			throw new Error('ALLOW_STUB_AUTH=1 is only permitted when NODE_ENV is development or test');
		}
		return stubVerifier;
	}
	throw new Error(
		'No token verifier configured. Set ALLOW_STUB_AUTH=1 for local development, or wire up a real TokenVerifier.',
	);
}

declare module 'fastify' {
	interface FastifyRequest {
		user?: AuthUser;
	}
}

export function requireAuth(verify: TokenVerifier) {
	return async (request: FastifyRequest, reply: FastifyReply) => {
		const match = /^Bearer (.+)$/i.exec(request.headers.authorization ?? '');
		let user: AuthUser | null = null;
		if (match) {
			try {
				user = await verify(match[1]);
			} catch (err) {
				// Verifier failure (e.g. JWKS unreachable) is not the client's fault: log it
				// server-side and return a generic 503 without leaking the error message.
				request.log.error({ err }, 'token verification failed');
				return reply.code(503).send({ error: 'Service Unavailable' });
			}
		}
		if (!user) {
			return reply.code(401).send({ error: 'Unauthorized' });
		}
		request.user = user;
	};
}
