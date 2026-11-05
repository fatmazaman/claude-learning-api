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
});
