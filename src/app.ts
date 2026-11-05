import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyServerOptions } from 'fastify';
import { requireAuth, type TokenVerifier } from './auth';

export interface AppOptions extends FastifyServerOptions {
	verifyToken: TokenVerifier;
}

export function buildApp({ verifyToken, ...opts }: AppOptions) {
	const app = Fastify(opts);

	app.register(helmet);
	app.register(rateLimit, { max: 100, timeWindow: '1 minute' });

	// Routes live in their own plugin, registered after rate-limit: that plugin only
	// wraps routes added once it has loaded, so inline routes would escape the limit.
	app.register(async (instance) => {
		instance.get('/health', async () => ({ status: 'ok' }));

		// The response schema whitelists fields, so other token claims are never echoed back.
		instance.get(
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
	});

	return app;
}
