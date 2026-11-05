import { buildApp } from '../src/app';
import { stubVerifier } from '../src/auth';

describe('GET /health', () => {
	it('returns ok', async () => {
		const app = buildApp({ verifyToken: stubVerifier });
		const res = await app.inject({ method: 'GET', url: '/health' });
		expect(res.statusCode).toBe(200);
		expect(res.json()).toEqual({ status: 'ok' });
		await app.close();
	});

	it('sets security headers', async () => {
		const app = buildApp({ verifyToken: stubVerifier });
		const res = await app.inject({ method: 'GET', url: '/health' });
		expect(res.headers['x-content-type-options']).toBe('nosniff');
		await app.close();
	});

	it('rate limits repeated requests', async () => {
		const app = buildApp({ verifyToken: stubVerifier });
		let last = 200;
		for (let i = 0; i < 101; i++) {
			last = (await app.inject({ method: 'GET', url: '/health' })).statusCode;
		}
		expect(last).toBe(429);
		await app.close();
	});
});
