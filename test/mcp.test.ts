import http from 'node:http';
import https from 'node:https';
import { buildApp } from '../src/app';
import type { AuthUser } from '../src/auth';
import { toAuthInfo } from '../src/mcp/auth-info';
import { mcpConfigFromEnv, type McpConfig } from '../src/mcp/config';
import { makeKey, signToken, verifierFor, type Key } from './helpers/oidc';

// Everything runs offline: tokens are signed with a key generated in the test, the verifier
// checks them against a local JWKS, and requests go through app.inject().

const RESOURCE = 'https://mcp.example.com/mcp';
const AUTH_SERVER = 'https://auth.example.com/';
const METADATA_URL = 'https://mcp.example.com/.well-known/oauth-protected-resource/mcp';

function configFor(env: NodeJS.ProcessEnv = {}): McpConfig {
	const config = mcpConfigFromEnv(
		{ MCP_ENABLED: '1', ...env },
		{ issuer: AUTH_SERVER, audience: RESOURCE },
	);
	if (!config) throw new Error('test setup: MCP should be enabled');
	return config;
}

const META = {
	'io.modelcontextprotocol/protocolVersion': '2026-07-28',
	'io.modelcontextprotocol/clientInfo': { name: 'test-client', version: '1.0.0' },
	'io.modelcontextprotocol/clientCapabilities': {},
};

/** A 2026-07-28 request: per-request metadata in the body, mirrored into headers. */
function modern(method: string, params: Record<string, unknown> = {}, id = 1) {
	return {
		headers: {
			'content-type': 'application/json',
			accept: 'application/json, text/event-stream',
			'mcp-protocol-version': '2026-07-28',
			'mcp-method': method,
			...(typeof params.name === 'string' ? { 'mcp-name': params.name } : {}),
		} as Record<string, string>,
		payload: { jsonrpc: '2.0', id, method, params: { ...params, _meta: META } },
	};
}

/** A 2025-era request (initialize handshake, no per-request metadata). */
function legacy(method: string, params: Record<string, unknown> = {}, id = 1) {
	return {
		headers: {
			'content-type': 'application/json',
			accept: 'application/json, text/event-stream',
			...(method === 'initialize' ? {} : { 'mcp-protocol-version': '2025-11-25' }),
		} as Record<string, string>,
		payload: { jsonrpc: '2.0', id, method, params },
	};
}

const callTool = (name: string, args: Record<string, unknown> = {}, id = 1) =>
	modern('tools/call', { name, arguments: args }, id);

/** The JSON-RPC message in a response, whether it came back as JSON or as an SSE event. */
function rpc(res: { body: string; headers: Record<string, unknown> }) {
	if (String(res.headers['content-type'] ?? '').startsWith('text/event-stream')) {
		const data = res.body
			.split('\n')
			.filter((line) => line.startsWith('data:'))
			.map((line) => line.slice(5).trim());
		return JSON.parse(data[data.length - 1]);
	}
	return JSON.parse(res.body);
}

const textOf = (message: { result: { content: { text: string }[] } }) =>
	message.result.content[0].text;

describe('MCP server', () => {
	let key: Key;
	let app: ReturnType<typeof buildApp>;

	beforeAll(async () => {
		key = await makeKey('key-1');
	});
	beforeEach(() => {
		app = buildApp({
			verifyToken: verifierFor([key], { issuer: AUTH_SERVER, audience: RESOURCE }),
			mcp: configFor(),
		});
	});
	afterEach(() => app.close());

	/** A signed token for this server. `scope` undefined leaves the claim out. */
	const token = (scope?: string, sub = 'alice', extra: Record<string, unknown> = {}) =>
		signToken(key, {
			issuer: AUTH_SERVER,
			audience: RESOURCE,
			sub,
			extra: { ...(scope !== undefined ? { scope } : {}), ...extra },
		});

	const post = (
		request: { headers: Record<string, string>; payload: unknown },
		bearer?: string,
		headers: Record<string, string> = {},
	) =>
		app.inject({
			method: 'POST',
			url: '/mcp',
			headers: {
				host: 'mcp.example.com',
				...(bearer ? { authorization: `Bearer ${bearer}` } : {}),
				...request.headers,
				...headers,
			},
			payload: request.payload as object,
		});

	describe('protected resource metadata (RFC 9728)', () => {
		it('is served at the path of the MCP endpoint and at the root, without authentication', async () => {
			for (const url of [
				'/.well-known/oauth-protected-resource/mcp',
				'/.well-known/oauth-protected-resource',
			]) {
				const res = await app.inject({ method: 'GET', url });
				expect(res.statusCode).toBe(200);
				expect(res.headers['content-type']).toMatch(/application\/json/);
				expect(res.json()).toEqual({
					resource: RESOURCE,
					authorization_servers: [AUTH_SERVER],
					scopes_supported: ['notes:read', 'notes:write'],
					bearer_methods_supported: ['header'],
				});
			}
		});

		it('is public metadata: cacheable, and readable from a browser', async () => {
			const res = await app.inject({
				method: 'GET',
				url: '/.well-known/oauth-protected-resource/mcp',
			});
			expect(res.headers['access-control-allow-origin']).toBe('*');
			expect(res.headers['cache-control']).toMatch(/public/);
		});
	});

	describe('authentication', () => {
		const challenge = `resource_metadata="${METADATA_URL}", scope="notes:read"`;

		it('401 names the metadata URL and the scope to request first when there is no token', async () => {
			const res = await post(modern('tools/list'));
			expect(res.statusCode).toBe(401);
			expect(res.headers['www-authenticate']).toBe(`Bearer ${challenge}`);
		});

		it('401 adds invalid_token when a token was sent and rejected', async () => {
			const res = await post(modern('tools/list'), 'not-a-jwt');
			expect(res.statusCode).toBe(401);
			expect(res.headers['www-authenticate']).toBe(`Bearer error="invalid_token", ${challenge}`);
		});

		it('rejects an expired token', async () => {
			const expired = await signToken(key, {
				issuer: AUTH_SERVER,
				audience: RESOURCE,
				exp: Math.floor(Date.now() / 1000) - 600,
			});
			expect((await post(modern('tools/list'), expired)).statusCode).toBe(401);
		});

		it('rejects a token issued for another audience (the token must be for THIS server)', async () => {
			const other = await signToken(key, {
				issuer: AUTH_SERVER,
				audience: 'https://other-api.example.com/mcp',
				extra: { scope: 'notes:read' },
			});
			const res = await post(modern('tools/list'), other);
			expect(res.statusCode).toBe(401);
		});

		it('rejects a token from another issuer', async () => {
			const foreign = await signToken(key, {
				issuer: 'https://evil.example.com/',
				audience: RESOURCE,
				extra: { scope: 'notes:read' },
			});
			expect((await post(modern('tools/list'), foreign)).statusCode).toBe(401);
		});

		it('ignores a token passed in the query string', async () => {
			const valid = await token('notes:read');
			const request = modern('tools/list');
			const res = await app.inject({
				method: 'POST',
				url: `/mcp?access_token=${valid}`,
				headers: { host: 'mcp.example.com', ...request.headers },
				payload: request.payload,
			});
			expect(res.statusCode).toBe(401);
		});

		it('checks the token before the method, so an unauthenticated GET is a 401', async () => {
			const res = await app.inject({
				method: 'GET',
				url: '/mcp',
				headers: { host: 'mcp.example.com' },
			});
			expect(res.statusCode).toBe(401);
		});
	});

	describe('protocol', () => {
		it('lists both tools for a 2026-07-28 client, even with no scopes (so it can step up)', async () => {
			for (const scope of ['notes:read', undefined]) {
				const res = await post(modern('tools/list'), await token(scope));
				expect(res.statusCode).toBe(200);
				const names = rpc(res).result.tools.map((tool: { name: string }) => tool.name);
				expect(names).toEqual(['list_notes', 'add_note']);
			}
		});

		it('serves a 2025-era client statelessly: initialize, then tools/list, no session', async () => {
			const bearer = await token('notes:read');
			const init = await post(
				legacy('initialize', {
					protocolVersion: '2025-11-25',
					capabilities: {},
					clientInfo: { name: 'old-client', version: '1.0.0' },
				}),
				bearer,
			);
			expect(init.statusCode).toBe(200);
			expect(init.headers['mcp-session-id']).toBeUndefined();

			const list = await post(legacy('tools/list', {}, 2), bearer);
			expect(list.statusCode).toBe(200);
			expect(rpc(list).result.tools).toHaveLength(2);
		});

		it('ignores a session id from an older client and never mints one', async () => {
			const res = await post(modern('tools/list'), await token('notes:read'), {
				'mcp-session-id': 'abc-123',
			});
			expect(res.statusCode).toBe(200);
			expect(res.headers['mcp-session-id']).toBeUndefined();
		});

		it('answers GET and DELETE with 405 (no standalone stream, no sessions)', async () => {
			const bearer = await token('notes:read');
			for (const method of ['GET', 'DELETE'] as const) {
				const res = await app.inject({
					method,
					url: '/mcp',
					headers: { host: 'mcp.example.com', authorization: `Bearer ${bearer}` },
				});
				expect(res.statusCode).toBe(405);
				expect(res.headers.allow).toBe('POST');
			}
		});
	});

	describe('tools and scopes', () => {
		it('list_notes works with notes:read', async () => {
			const res = await post(callTool('list_notes'), await token('notes:read'));
			expect(res.statusCode).toBe(200);
			expect(JSON.parse(textOf(rpc(res)))).toEqual([]);
		});

		it('list_notes without the scope is HTTP 403 insufficient_scope, not a tool result', async () => {
			for (const scope of [undefined, 'notes:write', 'notes:readonly', 'Notes:Read']) {
				const res = await post(callTool('list_notes'), await token(scope));
				expect(res.statusCode).toBe(403);
				const header = String(res.headers['www-authenticate']);
				expect(header).toContain('Bearer error="insufficient_scope"');
				expect(header).toContain('scope="notes:read"');
				expect(header).toContain(`resource_metadata="${METADATA_URL}"`);
			}
		});

		it('add_note with a read-only token is 403 naming notes:write, and nothing is stored', async () => {
			const res = await post(callTool('add_note', { text: 'sneaky' }), await token('notes:read'));
			expect(res.statusCode).toBe(403);
			expect(String(res.headers['www-authenticate'])).toContain('scope="notes:write"');

			const list = await post(callTool('list_notes'), await token('notes:read'));
			expect(JSON.parse(textOf(rpc(list)))).toEqual([]);
		});

		it('add_note works with notes:write, and the note then shows up for a reader', async () => {
			const added = await post(
				callTool('add_note', { text: 'buy milk' }),
				await token('notes:write'),
			);
			expect(added.statusCode).toBe(200);
			expect(JSON.parse(textOf(rpc(added)))).toMatchObject({ text: 'buy milk' });

			const list = await post(callTool('list_notes'), await token('notes:read'));
			expect(JSON.parse(textOf(rpc(list)))).toEqual([
				{ id: expect.any(String), text: 'buy milk', createdAt: expect.any(String) },
			]);
		});

		it('rejects add_note arguments that do not match the schema, storing nothing', async () => {
			const bearer = await token('notes:read notes:write');
			const bad: Record<string, unknown>[] = [
				{},
				{ text: '' },
				{ text: 'x'.repeat(501) },
				{ text: 5 },
				{ text: 'ok', extra: 1 },
			];
			for (const args of bad) {
				const res = await post(callTool('add_note', args), bearer);
				expect(res.statusCode).toBeLessThan(500);
				expect(rpc(res).result.isError).toBe(true); // a tool error the model can read and retry
			}
			const list = await post(callTool('list_notes'), bearer);
			expect(JSON.parse(textOf(rpc(list)))).toEqual([]);
		});
	});

	describe('every tool is scoped to the token subject', () => {
		it("one user's notes are invisible to another", async () => {
			await post(
				callTool('add_note', { text: "alice's secret" }),
				await token('notes:write', 'alice'),
			);
			const bob = await post(callTool('list_notes'), await token('notes:read', 'bob'));
			expect(bob.statusCode).toBe(200);
			expect(JSON.parse(textOf(rpc(bob)))).toEqual([]);
			expect(bob.body).not.toContain('secret');
		});

		it('shares one store with the REST API: a note added over MCP appears in GET /notes', async () => {
			await post(callTool('add_note', { text: 'via mcp' }), await token('notes:write', 'alice'));
			const rest = await app.inject({
				method: 'GET',
				url: '/notes',
				headers: { authorization: `Bearer ${await token('notes:read', 'alice')}` },
			});
			expect(rest.statusCode).toBe(200);
			expect(rest.json()).toEqual([expect.objectContaining({ text: 'via mcp' })]);
		});

		it('and the other way round: a note added over REST is listed by the MCP tool', async () => {
			await app.inject({
				method: 'POST',
				url: '/notes',
				headers: { authorization: `Bearer ${await token('notes:write', 'alice')}` },
				payload: { text: 'via rest' },
			});
			const res = await post(callTool('list_notes'), await token('notes:read', 'alice'));
			expect(JSON.parse(textOf(rpc(res)))).toEqual([expect.objectContaining({ text: 'via rest' })]);
		});

		it('fails closed when the verified user has no subject', async () => {
			const noSub = buildApp({
				verifyToken: async () => ({ sub: '', scope: ['notes:read'] }) as AuthUser,
				mcp: configFor(),
			});
			const res = await noSub.inject({
				method: 'POST',
				url: '/mcp',
				headers: {
					host: 'mcp.example.com',
					authorization: 'Bearer anything',
					...callTool('list_notes').headers,
				},
				payload: callTool('list_notes').payload,
			});
			const message = rpc(res);
			expect(message.result.isError).toBe(true);
			expect(textOf(message)).toBe('No authenticated user.'); // an error, never a notes list
			await noSub.close();
		});
	});

	describe('Host and Origin validation (DNS rebinding)', () => {
		it('rejects a Host that is not on the allowlist, before authentication', async () => {
			const res = await post(modern('tools/list'), undefined, { host: 'evil.example' });
			expect(res.statusCode).toBe(403);
			expect(res.body).not.toContain('evil.example');
		});

		it('rejects an Origin that is present but not allowed, including the opaque "null" origin', async () => {
			const bearer = await token('notes:read');
			for (const origin of ['https://evil.example', 'null']) {
				const res = await post(modern('tools/list'), bearer, { origin });
				expect(res.statusCode).toBe(403);
				expect(res.body).not.toContain('evil.example');
			}
		});

		it('allows a localhost Origin (e.g. the MCP Inspector) and a missing Origin', async () => {
			const bearer = await token('notes:read');
			expect(
				(await post(modern('tools/list'), bearer, { origin: 'http://localhost:6274' })).statusCode,
			).toBe(200);
			expect((await post(modern('tools/list'), bearer)).statusCode).toBe(200);
		});

		it('allows an origin added through MCP_ALLOWED_ORIGINS, and only that one', async () => {
			const custom = buildApp({
				verifyToken: verifierFor([key], { issuer: AUTH_SERVER, audience: RESOURCE }),
				mcp: configFor({ MCP_ALLOWED_ORIGINS: 'app.example.com' }),
			});
			const bearer = await token('notes:read');
			const call = (origin: string) =>
				custom.inject({
					method: 'POST',
					url: '/mcp',
					headers: {
						host: 'mcp.example.com',
						authorization: `Bearer ${bearer}`,
						origin,
						...modern('tools/list').headers,
					},
					payload: modern('tools/list').payload,
				});
			expect((await call('https://app.example.com')).statusCode).toBe(200);
			expect((await call('https://evil.example')).statusCode).toBe(403);
			await custom.close();
		});
	});

	describe('no token passthrough', () => {
		it('makes no outbound request while serving tool calls', async () => {
			const fetchSpy = jest.spyOn(globalThis, 'fetch');
			const httpSpy = jest.spyOn(http, 'request');
			const httpsSpy = jest.spyOn(https, 'request');
			const bearer = await token('notes:read notes:write');

			await post(callTool('add_note', { text: 'hello' }), bearer);
			await post(callTool('list_notes'), bearer);

			expect(fetchSpy).not.toHaveBeenCalled();
			expect(httpSpy).not.toHaveBeenCalled();
			expect(httpsSpy).not.toHaveBeenCalled();
			jest.restoreAllMocks();
		});

		it('hands the SDK a caller description with no token in it', () => {
			const user: AuthUser = {
				sub: 'alice',
				scope: ['notes:read'],
				exp: 1_900_000_000,
				clientId: 'c1',
			};
			const info = toAuthInfo(user, configFor(), METADATA_URL);
			expect(info.token).toBe('');
			expect(JSON.stringify(info)).not.toMatch(/Bearer|eyJ/);
			expect(info).toMatchObject({
				clientId: 'c1',
				scopes: ['notes:read'],
				expiresAt: 1_900_000_000,
				resourceMetadataUrl: METADATA_URL,
				extra: { sub: 'alice' },
			});
			expect(info.resource?.href).toBe(RESOURCE);
		});

		it('falls back to an unknown client and no expiry when the token has neither', () => {
			const info = toAuthInfo({ sub: 'alice' }, configFor(), METADATA_URL);
			expect(info.clientId).toBe('unknown');
			expect(info.scopes).toEqual([]);
			expect(info.expiresAt).toBeUndefined();
		});
	});

	describe('rate limiting', () => {
		it('applies to /mcp like every other route', async () => {
			let last = 0;
			for (let i = 0; i < 101; i += 1) {
				last = (await post(modern('tools/list'))).statusCode;
			}
			expect(last).toBe(429);
		});
	});
});
