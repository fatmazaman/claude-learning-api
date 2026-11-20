import { toNodeHandler } from '@modelcontextprotocol/node';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { requireAuth, type AuthUser, type TokenVerifier } from '../auth';
import type { NotesStore } from '../notes-store';
import { toAuthInfo } from './auth-info';
import { MCP_PATH, type McpConfig } from './config';
import { mcpGuard } from './guard';
import { buildMetadata, metadataPaths, metadataUrl } from './metadata';
import { createNotesMcpHandler } from './server';

function userOf(request: FastifyRequest): AuthUser {
	if (!request.user) throw new Error('MCP route ran without requireAuth');
	return request.user;
}

/**
 * The MCP server at `/mcp`, protected as an OAuth 2.0 resource server (MCP spec 2026-07-28):
 * - the protected resource metadata is public (so clients can discover the authorization server);
 * - `/mcp` checks Host and Origin, then the bearer token, whose audience the verifier has already
 *   bound to this server; a 401 names the metadata URL and the scope to request first;
 * - the SDK then serves the request statelessly, answering an under-scoped tool call with 403.
 * Registered inside the app's route plugin, so rate limiting applies.
 */
export function registerMcp(
	instance: FastifyInstance,
	deps: { verifyToken: TokenVerifier; config: McpConfig; store: NotesStore },
) {
	const { config } = deps;
	const resource = new URL(config.resource);
	const resourceMetadataUrl = metadataUrl(resource);
	const metadata = buildMetadata(config);

	for (const path of metadataPaths(resource)) {
		instance.get(path, async (_request, reply) =>
			reply
				.header('Cache-Control', 'public, max-age=3600')
				.header('Access-Control-Allow-Origin', '*') // public document; browser clients read it
				.send(metadata),
		);
	}

	const authenticate = requireAuth(deps.verifyToken, {
		challenge: { resourceMetadataUrl, scope: config.challengeScope },
	});
	const handler = createNotesMcpHandler(deps.store);
	const node = toNodeHandler(handler);
	instance.addHook('onClose', async () => {
		await handler.close();
	});

	instance.route({
		method: ['GET', 'POST', 'DELETE'],
		url: MCP_PATH,
		bodyLimit: 32 * 1024,
		onRequest: [mcpGuard(config), authenticate],
		handler: async (request, reply) => {
			// 2026-07-28 has a single POST endpoint: no GET stream, no sessions to DELETE.
			if (request.method !== 'POST') {
				return reply.code(405).header('Allow', 'POST').send({ error: 'Method Not Allowed' });
			}
			const authInfo = toAuthInfo(userOf(request), config, resourceMetadataUrl);
			// The SDK hands tools the original Request, headers included. The token has been
			// verified, so remove it before the hand-off: no tool can then read or forward it
			// (the spec forbids passing tokens on). authInfo carries a blank token as well.
			delete request.raw.headers.authorization;
			reply.hijack();
			await node(Object.assign(request.raw, { auth: authInfo }), reply.raw, request.body);
		},
	});
}
