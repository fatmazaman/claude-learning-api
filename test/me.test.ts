import { buildApp } from '../src/app';

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
const fakeJwt = (payload: object) => `${b64({ alg: 'none' })}.${b64(payload)}.sig`;

describe('GET /me', () => {
	const app = buildApp();
	afterAll(() => app.close());

	it('rejects requests without a token', async () => {
		const res = await app.inject({ method: 'GET', url: '/me' });
		expect(res.statusCode).toBe(401);
	});

	it('rejects malformed tokens', async () => {
		const res = await app.inject({
			method: 'GET',
			url: '/me',
			headers: { authorization: 'Bearer not-a-jwt' },
		});
		expect(res.statusCode).toBe(401);
	});

	it('returns the token claims for a valid token', async () => {
		const res = await app.inject({
			method: 'GET',
			url: '/me',
			headers: { authorization: `Bearer ${fakeJwt({ sub: 'user-1', email: 'a@b.c' })}` },
		});
		expect(res.statusCode).toBe(200);
		expect(res.json()).toEqual({ sub: 'user-1', email: 'a@b.c' });
	});

	it('uses an injected verifier', async () => {
		const custom = buildApp({ verifyToken: async () => null });
		const res = await custom.inject({
			method: 'GET',
			url: '/me',
			headers: { authorization: `Bearer ${fakeJwt({ sub: 'user-1' })}` },
		});
		expect(res.statusCode).toBe(401);
		await custom.close();
	});
});
