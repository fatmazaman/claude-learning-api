import Fastify, { type FastifyServerOptions } from 'fastify';
import { requireAuth, type TokenVerifier } from './auth';

export interface AppOptions extends FastifyServerOptions {
	verifyToken: TokenVerifier;
}

export function buildApp({ verifyToken, ...opts }: AppOptions) {
	const app = Fastify(opts);

	app.get('/health', async () => ({ status: 'ok' }));

	// The response schema whitelists fields, so other token claims are never echoed back.
	app.get(
		'/me',
		{
			preHandler: requireAuth(verifyToken),
			schema: {
				response: {
					200: {
						type: 'object',
						required: ['sub'],
						properties: { sub: { type: 'string' }, email: { type: 'string' } },
					},
				},
			},
		},
		async (request) => request.user,
	);

	return app;
}
