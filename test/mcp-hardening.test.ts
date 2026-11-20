import { buildApp } from '../src/app';
import { mcpConfigFromEnv } from '../src/mcp/config';
import { makeKey, signToken, verifierFor, type Key } from './helpers/oidc';

// Spy on the hand-off to the MCP SDK: toNodeHandler receives the Node request the SDK turns into
// the `Request` that tools can see. (jest.mock factories may only reference `mock*` variables.)
const mockSeenAuthorization: Array<string | undefined> = [];
jest.mock('@modelcontextprotocol/node', () => {
	const actual = jest.requireActual('@modelcontextprotocol/node');
	return {
		...actual,
		toNodeHandler: (handler: unknown) => {
			const node = actual.toNodeHandler(handler);
			return (req: { headers: { authorization?: string } }, res: unknown, body: unknown) => {
				mockSeenAuthorization.push(req.headers.authorization);
				return node(req, res, body);
			};
		},
	};
});

const RESOURCE = 'https://mcp.example.com/mcp';
const AUTH_SERVER = 'https://auth.example.com/';
const META = {
	'io.modelcontextprotocol/protocolVersion': '2026-07-28',
	'io.modelcontextprotocol/clientInfo': { name: 'test-client', version: '1.0.0' },
	'io.modelcontextprotocol/clientCapabilities': {},
};

describe('MCP hardening', () => {
	let key: Key;
	let app: ReturnType<typeof buildApp>;

	beforeAll(async () => {
		key = await makeKey('key-1');
	});
	beforeEach(() => {
		mockSeenAuthorization.length = 0;
		const config = mcpConfigFromEnv(
			{ MCP_ENABLED: '1' },
			{ issuer: AUTH_SERVER, audience: RESOURCE },
		);
		if (!config) throw new Error('test setup: MCP should be enabled');
		app = buildApp({
			verifyToken: verifierFor([key], { issuer: AUTH_SERVER, audience: RESOURCE }),
			mcp: config,
		});
	});
	afterEach(() => app.close());

	const bearer = () =>
		signToken(key, {
			issuer: AUTH_SERVER,
			audience: RESOURCE,
			extra: { scope: 'notes:read' },
		});

	const post = async (method: string, params: Record<string, unknown> = {}) =>
		app.inject({
			method: 'POST',
			url: '/mcp',
			headers: {
				host: 'mcp.example.com',
				authorization: `Bearer ${await bearer()}`,
				'content-type': 'application/json',
				accept: 'application/json, text/event-stream',
				'mcp-protocol-version': '2026-07-28',
				'mcp-method': method,
			},
			payload: { jsonrpc: '2.0', id: 1, method, params: { ...params, _meta: META } },
		});

	it('removes the Authorization header before the SDK sees the request, so no tool can read the token', async () => {
		const res = await post('tools/list');
		expect(res.statusCode).toBe(200); // the request is still served: auth travels as authInfo
		expect(mockSeenAuthorization).toEqual([undefined]);
	});

	it('rejects subscriptions/listen instead of holding a stream open for any authenticated caller', async () => {
		// If the stream stayed open, inject would never resolve and this test would time out.
		const res = await post('subscriptions/listen', { notifications: { toolsListChanged: true } });
		expect(res.headers['content-type']).toMatch(/application\/json/);
		expect(JSON.parse(res.body).error.message).toMatch(/Subscription limit reached/);
	}, 8000);
});
