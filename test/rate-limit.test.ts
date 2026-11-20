import { buildApp } from '../src/app';
import { stubVerifier } from '../src/auth';
import { mcpConfigFromEnv } from '../src/mcp/config';

// Failed authentication must count against the rate limit. @fastify/rate-limit in its default
// mode appends its hook AFTER a route's own auth hooks, so a request that fails auth (401) or
// lacks a scope (403) would never be counted and bad-token floods would be unlimited. These
// tests send 101 requests that are all rejected by auth and expect the 101st to be a 429.

const mcp = mcpConfigFromEnv(
	{ MCP_ENABLED: '1' },
	{ issuer: 'https://auth.example.com/', audience: 'https://mcp.example.com/mcp' },
);

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
const stubToken = (claims: object) => `${b64({ alg: 'none' })}.${b64(claims)}.sig`;

async function lastStatusAfter101(
	request: { method: 'GET' | 'POST'; url: string; headers?: Record<string, string> },
	options: { withMcp?: boolean } = {},
) {
	const app = buildApp({
		verifyToken: stubVerifier,
		...(options.withMcp && mcp ? { mcp } : {}),
	});
	const statuses: number[] = [];
	for (let i = 0; i < 101; i += 1) {
		const res = await app.inject({
			...request,
			headers: { host: 'mcp.example.com', ...request.headers },
			...(request.method === 'POST' ? { payload: { text: 'x' } } : {}),
		});
		statuses.push(res.statusCode);
	}
	await app.close();
	return statuses;
}

describe('rate limiting counts requests that fail authentication', () => {
	it('GET /me with no token', async () => {
		const statuses = await lastStatusAfter101({ method: 'GET', url: '/me' });
		expect(statuses[0]).toBe(401);
		expect(statuses[100]).toBe(429);
	});

	it('GET /me with a garbage token', async () => {
		const statuses = await lastStatusAfter101({
			method: 'GET',
			url: '/me',
			headers: { authorization: 'Bearer not-a-jwt' },
		});
		expect(statuses[0]).toBe(401);
		expect(statuses[100]).toBe(429);
	});

	it('GET /notes with a valid token that lacks the scope (403s are counted too)', async () => {
		const statuses = await lastStatusAfter101({
			method: 'GET',
			url: '/notes',
			headers: { authorization: `Bearer ${stubToken({ sub: 'alice' })}` },
		});
		expect(statuses[0]).toBe(403);
		expect(statuses[100]).toBe(429);
	});

	it('POST /notes with no token', async () => {
		const statuses = await lastStatusAfter101({ method: 'POST', url: '/notes' });
		expect(statuses[0]).toBe(401);
		expect(statuses[100]).toBe(429);
	});

	it('POST /mcp with no token', async () => {
		const statuses = await lastStatusAfter101({ method: 'POST', url: '/mcp' }, { withMcp: true });
		expect(statuses[0]).toBe(401);
		expect(statuses[100]).toBe(429);
	});

	it('still lets the first 100 requests through', async () => {
		const statuses = await lastStatusAfter101({ method: 'GET', url: '/me' });
		expect(statuses.slice(0, 100).every((status) => status === 401)).toBe(true);
	});
});
