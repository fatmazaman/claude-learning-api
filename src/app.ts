import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyError, type FastifyServerOptions } from 'fastify';
import { requireAuth, type TokenVerifier } from './auth';
import { registerNotes } from './routes/notes';

export interface AppOptions extends FastifyServerOptions {
	verifyToken: TokenVerifier;
}

export function buildApp({ verifyToken, ...opts }: AppOptions) {
	// Fastify's default Ajv coerces types ({"text": 5} becomes "5") and silently deletes extra
	// properties instead of rejecting them. Run strict: malformed input is a 400, not a guess.
	const app = Fastify({
		ajv: { customOptions: { coerceTypes: false, removeAdditional: false } },
		...opts,
	});

	// Fastify's default error handler sends `err.message` to the client, so an unexpected
	// error (a database or library failure) would leak its detail. Log it here, and answer
	// 5xx with a generic body. Client errors (validation 400, 413, rate-limit 429) keep theirs.
	app.setErrorHandler((err: FastifyError, request, reply) => {
		if ((err.statusCode ?? 500) >= 500) {
			request.log.error({ err }, 'unhandled error');
			return reply.code(500).send({ error: 'Internal Server Error' });
		}
		return reply.send(err);
	});

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
				// onRequest, not preHandler: validation runs before preHandler (see CLAUDE.md).
				onRequest: requireAuth(verifyToken),
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

		registerNotes(instance, verifyToken);
	});

	return app;
}
