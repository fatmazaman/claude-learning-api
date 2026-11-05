import { buildApp } from '../src/app';
import { stubVerifier } from '../src/auth';

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
const fakeJwt = (payload: object) => `${b64({ alg: 'none' })}.${b64(payload)}.sig`;

describe('GET /me', () => {
	const app = buildApp({ verifyToken: stubVerifier });
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

	it('accepts the Bearer scheme case-insensitively', async () => {
		const res = await app.inject({
			method: 'GET',
			url: '/me',
			headers: { authorization: `bearer ${fakeJwt({ sub: 'user-1' })}` },
		});
		expect(res.statusCode).toBe(200);
	});

	it('rejects a non-Bearer scheme', async () => {
		const res = await app.inject({
			method: 'GET',
			url: '/me',
			headers: { authorization: `Basic ${fakeJwt({ sub: 'user-1' })}` },
		});
		expect(res.statusCode).toBe(401);
	});

	it('rejects a well-formed token without a string sub', async () => {
		for (const payload of [{ email: 'a@b.c' }, { sub: 42 }]) {
			const res = await app.inject({
				method: 'GET',
				url: '/me',
				headers: { authorization: `Bearer ${fakeJwt(payload)}` },
			});
			expect(res.statusCode).toBe(401);
		}
	});

	it('does not echo claims outside the response schema', async () => {
		const res = await app.inject({
			method: 'GET',
			url: '/me',
			headers: {
				authorization: `Bearer ${fakeJwt({ sub: 'u', email: 'a@b.c', groups: ['admin'] })}`,
			},
		});
		expect(res.statusCode).toBe(200);
		expect(res.json()).toEqual({ sub: 'u', email: 'a@b.c' });
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

	it('returns a generic 503 when the verifier throws', async () => {
		const throwing = buildApp({
			verifyToken: async () => {
				throw new Error('jwks unreachable');
			},
		});
		const res = await throwing.inject({
			method: 'GET',
			url: '/me',
			headers: { authorization: `Bearer ${fakeJwt({ sub: 'user-1' })}` },
		});
		expect(res.statusCode).toBe(503);
		expect(res.body).not.toContain('jwks');
		await throwing.close();
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
