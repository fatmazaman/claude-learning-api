import type { AuthInfo } from '@modelcontextprotocol/server';
import type { AuthUser } from '../auth';
import type { McpConfig } from './config';

/**
 * Describes the already-verified caller to the MCP SDK. The token itself is deliberately
 * blank, and routes.ts removes the Authorization header from the request the SDK passes to
 * tools: together nothing downstream (a tool, a library) can read or forward the token, which
 * is how this server honours the spec's rule against passing tokens on. The caller's
 * identity travels in `extra.sub`, and tools scope everything to it.
 */
export function toAuthInfo(
	user: AuthUser,
	config: McpConfig,
	resourceMetadataUrl: string,
): AuthInfo {
	return {
		token: '',
		clientId: user.clientId ?? 'unknown',
		scopes: user.scope ?? [],
		...(user.exp !== undefined ? { expiresAt: user.exp } : {}),
		resource: new URL(config.resource),
		resourceMetadataUrl,
		extra: { sub: user.sub },
	};
}
