import Fastify, { type FastifyServerOptions } from 'fastify';
import { requireAuth, stubVerifier, type TokenVerifier } from './auth';

export interface AppOptions extends FastifyServerOptions {
	verifyToken?: TokenVerifier;
}

export function buildApp({ verifyToken = stubVerifier, ...opts }: AppOptions = {}) {
	const app = Fastify(opts);

	app.get('/health', async () => ({ status: 'ok' }));

	app.get('/me', { preHandler: requireAuth(verifyToken) }, async (request) => request.user);

	return app;
}
