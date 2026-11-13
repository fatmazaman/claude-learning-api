import type { FastifyReply, FastifyRequest } from 'fastify';
import { createOidcVerifier, oidcConfigFromEnv } from './verifiers/oidc';

export interface AuthUser {
	sub: string;
	[claim: string]: unknown;
}

/** Resolves a raw bearer token to a user, or null if the token is invalid. */
export type TokenVerifier = (token: string) => Promise<AuthUser | null>;

/**
 * STUB: decodes the JWT payload WITHOUT verifying the signature. For development and
 * tests only; the real verifier is in ./verifiers/oidc.
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
 * Picks the token verifier for the running server. There is no default.
 * 1. OIDC_ISSUER and OIDC_AUDIENCE set: the real OIDC verifier (any NODE_ENV). It fetches
 *    the provider's discovery document, so this rejects when that fails.
 * 2. Exactly one of the two set: throws, since that is a misconfiguration.
 * 3. Neither set: the stub (which accepts forged tokens), only with ALLOW_STUB_AUTH=1 and
 *    NODE_ENV of development or test.
 * 4. Otherwise throws, so the server refuses to start.
 */
export async function verifierFromEnv(
	env: NodeJS.ProcessEnv = process.env,
): Promise<TokenVerifier> {
	const oidc = oidcConfigFromEnv(env);
	if (oidc) return createOidcVerifier(oidc);
	if (env.ALLOW_STUB_AUTH === '1') {
		if (env.NODE_ENV !== 'development' && env.NODE_ENV !== 'test') {
			throw new Error('ALLOW_STUB_AUTH=1 is only permitted when NODE_ENV is development or test');
		}
		return stubVerifier;
	}
	throw new Error(
		'No token verifier configured. Set OIDC_ISSUER and OIDC_AUDIENCE, or ALLOW_STUB_AUTH=1 (with NODE_ENV=development or test) for local development.',
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
