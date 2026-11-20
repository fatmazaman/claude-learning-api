import { mcpConfigFromEnv } from '../src/mcp/config';
import { buildMetadata, metadataPaths, metadataUrl } from '../src/mcp/metadata';

const OIDC = { issuer: 'https://auth.example.com/', audience: 'https://mcp.example.com/mcp' };
const enabled = (env: NodeJS.ProcessEnv = {}, oidc: typeof OIDC | null = OIDC) =>
	mcpConfigFromEnv({ MCP_ENABLED: '1', ...env }, oidc);

describe('mcpConfigFromEnv', () => {
	it('is off unless MCP_ENABLED=1', () => {
		for (const MCP_ENABLED of [undefined, '', '0']) {
			expect(mcpConfigFromEnv({ MCP_ENABLED }, OIDC)).toBeNull();
		}
	});

	it('refuses an ambiguous MCP_ENABLED value', () => {
		for (const MCP_ENABLED of ['true', 'yes', '2', 'on']) {
			expect(() => mcpConfigFromEnv({ MCP_ENABLED }, OIDC)).toThrow(/must be 1/);
		}
	});

	it('refuses to run without the real OIDC verifier, because the dev stub accepts forged tokens', () => {
		expect(() => enabled({}, null)).toThrow(/needs the OIDC verifier/);
	});

	it('builds the config from the OIDC settings', () => {
		expect(enabled()).toEqual({
			resource: 'https://mcp.example.com/mcp',
			issuer: 'https://auth.example.com/',
			scopesSupported: ['notes:read', 'notes:write'],
			challengeScope: 'notes:read',
			allowedHosts: expect.arrayContaining(['mcp.example.com', 'localhost', '127.0.0.1']),
			allowedOrigins: expect.arrayContaining(['localhost', '127.0.0.1']),
		});
	});

	it('accepts http only for localhost, as the audience of a local test server', () => {
		for (const audience of ['http://localhost:3000/mcp', 'http://127.0.0.1:3000/mcp']) {
			expect(enabled({}, { ...OIDC, audience })?.resource).toBe(audience);
		}
		expect(() => enabled({}, { ...OIDC, audience: 'http://mcp.example.com/mcp' })).toThrow(/https/);
	});

	it.each([
		['not a URL', 'mcp.example.com', /absolute URL/],
		['credentials', 'https://user:pass@mcp.example.com/mcp', /credentials/],
		['a query', 'https://mcp.example.com/mcp?x=1', /query or fragment/],
		['a fragment', 'https://mcp.example.com/mcp#top', /query or fragment/],
		['a different path', 'https://mcp.example.com/api/mcp', /path \/mcp/],
		['no path', 'https://mcp.example.com', /path \/mcp/],
		['a trailing slash', 'https://mcp.example.com/mcp/', /path \/mcp/],
		['an uppercase host', 'https://MCP.example.com/mcp', /canonical/],
		['an explicit default port', 'https://mcp.example.com:443/mcp', /canonical/],
	])('refuses an audience with %s', (_label, audience, message) => {
		expect(() => enabled({}, { ...OIDC, audience })).toThrow(message);
	});

	it('refuses the http:// and https:// wildcards, which the SDK would silently ignore', () => {
		for (const wildcard of ['http://*', 'https://*', 'HTTPS://*']) {
			expect(() => enabled({ MCP_ALLOWED_ORIGINS: wildcard })).toThrow(/cannot use http:\/\/\*/);
		}
	});

	it('adds only well-formed origins from MCP_ALLOWED_ORIGINS', () => {
		const config = enabled({ MCP_ALLOWED_ORIGINS: 'app.example.com, moz-extension://*' });
		expect(config?.allowedOrigins).toEqual(
			expect.arrayContaining(['app.example.com', 'moz-extension://*']),
		);
		for (const bad of ['https://app.example.com', 'app.example.com:8080', 'app.example.com/x']) {
			expect(() => enabled({ MCP_ALLOWED_ORIGINS: bad })).toThrow(/MCP_ALLOWED_ORIGINS/);
		}
	});
});

describe('protected resource metadata helpers', () => {
	const config = enabled();
	const resource = new URL('https://mcp.example.com/mcp');

	it('advertises the path-based metadata URL (RFC 9728 inserts the well-known segment)', () => {
		expect(metadataUrl(resource)).toBe(
			'https://mcp.example.com/.well-known/oauth-protected-resource/mcp',
		);
	});

	it('serves the path form first and the root form second', () => {
		expect(metadataPaths(resource)).toEqual([
			'/.well-known/oauth-protected-resource/mcp',
			'/.well-known/oauth-protected-resource',
		]);
	});

	it('names the resource, the authorization server and the scopes', () => {
		expect(config && buildMetadata(config)).toEqual({
			resource: 'https://mcp.example.com/mcp',
			authorization_servers: ['https://auth.example.com/'],
			scopes_supported: ['notes:read', 'notes:write'],
			bearer_methods_supported: ['header'],
		});
	});
});
