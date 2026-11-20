import { getOAuthProtectedResourceMetadataUrl } from '@modelcontextprotocol/server';
import type { McpConfig } from './config';

const WELL_KNOWN = '/.well-known/oauth-protected-resource';

/** RFC 9728 Protected Resource Metadata (the document clients use to find the authorization server). */
export interface ProtectedResourceMetadata {
	resource: string;
	authorization_servers: string[];
	scopes_supported: string[];
	bearer_methods_supported: string[];
}

export function buildMetadata(config: McpConfig): ProtectedResourceMetadata {
	return {
		resource: config.resource,
		authorization_servers: [config.issuer],
		scopes_supported: [...config.scopesSupported],
		bearer_methods_supported: ['header'],
	};
}

/**
 * Where the metadata is served: at the path of the MCP endpoint (RFC 9728 inserts the
 * well-known segment ahead of the resource's path) and at the root. The spec lets clients
 * probe either, so we answer both.
 */
export function metadataPaths(resource: URL): string[] {
	return resource.pathname === '/'
		? [WELL_KNOWN]
		: [`${WELL_KNOWN}${resource.pathname}`, WELL_KNOWN];
}

/** The URL advertised in `WWW-Authenticate` as `resource_metadata`. */
export function metadataUrl(resource: URL): string {
	return getOAuthProtectedResourceMetadataUrl(resource);
}
