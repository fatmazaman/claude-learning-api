import { validateHostHeader, validateOriginHeader } from '@modelcontextprotocol/server';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { McpConfig } from './config';

/**
 * DNS rebinding protection, which the Streamable HTTP spec requires: a `Host` that is not on
 * the allowlist, or an `Origin` that is present but not allowed, gets 403 before anything else
 * runs. A missing `Origin` passes (non-browser MCP clients do not send one). The response never
 * echoes the offending header value.
 */
export function mcpGuard(config: McpConfig) {
	const forbidden = (reply: FastifyReply, message: string) =>
		reply.code(403).send({ jsonrpc: '2.0', id: null, error: { code: -32000, message } });

	return async (request: FastifyRequest, reply: FastifyReply) => {
		if (!validateHostHeader(request.headers.host, config.allowedHosts).ok) {
			return forbidden(reply, 'Forbidden: the Host header is not allowed.');
		}
		if (!validateOriginHeader(request.headers.origin, config.allowedOrigins).ok) {
			return forbidden(reply, 'Forbidden: the Origin header is not allowed.');
		}
	};
}
