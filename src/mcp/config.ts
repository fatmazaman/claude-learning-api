import { localhostAllowedHostnames, localhostAllowedOrigins } from '@modelcontextprotocol/server';
import type { OidcConfig } from '../verifiers/oidc';

export const MCP_PATH = '/mcp';
export const NOTES_READ = 'notes:read';
export const NOTES_WRITE = 'notes:write';

export interface McpConfig {
	/** The resource identifier: exactly OIDC_AUDIENCE, which is what clients send as `resource`. */
	resource: string;
	/** The authorization server (OIDC_ISSUER), advertised in the protected resource metadata. */
	issuer: string;
	/** Every scope the server understands, advertised as `scopes_supported`. */
	scopesSupported: string[];
	/** The scope a client is asked to request first (least privilege); writes step up later. */
	challengeScope: string;
	/** Hostnames accepted in the `Host` header (DNS rebinding protection). */
	allowedHosts: string[];
	/** Hostnames accepted in a present `Origin` header; a missing `Origin` always passes. */
	allowedOrigins: string[];
}

const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '[::1]'];
// A hostname, a bracketed IPv6 address, or `<scheme>://*` (e.g. moz-extension://*).
const ORIGIN_ENTRY = /^(?:[a-z][a-z0-9+.-]*:\/\/\*|[a-z0-9.-]+|\[[0-9a-f:]+\])$/i;

function parseResource(audience: string): URL {
	let url: URL;
	try {
		url = new URL(audience);
	} catch {
		throw new Error(
			'OIDC_AUDIENCE must be an absolute URL when MCP_ENABLED=1: it is the MCP server resource identifier.',
		);
	}
	const loopback = LOOPBACK_HOSTS.includes(url.hostname);
	if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
		throw new Error('OIDC_AUDIENCE must use https (http is accepted only for localhost).');
	}
	if (url.username || url.password) {
		throw new Error('OIDC_AUDIENCE must not contain credentials.');
	}
	if (/[?#]/.test(audience)) {
		throw new Error('OIDC_AUDIENCE must not contain a query or fragment.');
	}
	if (url.pathname !== MCP_PATH) {
		throw new Error(
			`OIDC_AUDIENCE must be the MCP endpoint URL, with the path ${MCP_PATH} (for example https://mcp.example.com/mcp).`,
		);
	}
	// The resource identifier must be byte-for-byte what clients send and what `aud` holds.
	if (url.href !== audience) {
		throw new Error(`OIDC_AUDIENCE must be in canonical form: ${url.href}`);
	}
	return url;
}

function parseOrigins(value: string | undefined): string[] {
	const entries = (value ?? '')
		.split(',')
		.map((entry) => entry.trim())
		.filter(Boolean);
	for (const entry of entries) {
		// The SDK deliberately ignores these two wildcards (they would allow every website), so
		// accepting them here would only make an operator think they had allowed everything.
		if (/^https?:\/\/\*$/i.test(entry)) {
			throw new Error(
				'MCP_ALLOWED_ORIGINS cannot use http://* or https://*: list website hostnames instead.',
			);
		}
		if (!ORIGIN_ENTRY.test(entry)) {
			throw new Error(
				`MCP_ALLOWED_ORIGINS entries must be hostnames (no scheme, port or path); got "${entry}".`,
			);
		}
	}
	return entries;
}

/**
 * Reads MCP_ENABLED (and MCP_ALLOWED_ORIGINS). The MCP server is opt-in because it is new
 * attack surface. Returns null when it is not enabled, and throws on anything unsafe, so the
 * server refuses to start instead of exposing a misconfigured endpoint.
 */
export function mcpConfigFromEnv(
	env: NodeJS.ProcessEnv,
	oidc: Pick<OidcConfig, 'issuer' | 'audience'> | null,
): McpConfig | null {
	const enabled = env.MCP_ENABLED;
	if (enabled === undefined || enabled === '' || enabled === '0') return null;
	if (enabled !== '1') {
		throw new Error('MCP_ENABLED must be 1 to enable the MCP server (or unset).');
	}
	if (!oidc) {
		throw new Error(
			'MCP_ENABLED=1 needs the OIDC verifier (OIDC_ISSUER and OIDC_AUDIENCE): the dev stub accepts forged tokens.',
		);
	}
	const resource = parseResource(oidc.audience);
	return {
		resource: oidc.audience,
		issuer: oidc.issuer,
		scopesSupported: [NOTES_READ, NOTES_WRITE],
		challengeScope: NOTES_READ,
		allowedHosts: [...new Set([resource.hostname, ...localhostAllowedHostnames()])],
		allowedOrigins: [
			...new Set([...localhostAllowedOrigins(), ...parseOrigins(env.MCP_ALLOWED_ORIGINS)]),
		],
	};
}
