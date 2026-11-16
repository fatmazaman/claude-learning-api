import { buildApp } from '../src/app';
import { stubVerifier } from '../src/auth';

describe('error handling', () => {
	function appWithRoutes(lines: string[] = []) {
		const app = buildApp({
			verifyToken: stubVerifier,
			logger: { level: 'trace', stream: { write: (line: string) => void lines.push(line) } },
		});
		app.get('/boom', async () => {
			throw new Error('internal detail: connection string is postgres://user:hunter2@db');
		});
		app.get('/teapot', async () => {
			throw Object.assign(new Error('short and stout'), { statusCode: 418 });
		});
		return app;
	}

	it('answers an unexpected error with a generic 500 and logs the detail server-side', async () => {
		const lines: string[] = [];
		const app = appWithRoutes(lines);
		const res = await app.inject({ method: 'GET', url: '/boom' });
		expect(res.statusCode).toBe(500);
		expect(res.json()).toEqual({ error: 'Internal Server Error' });
		expect(res.body).not.toMatch(/hunter2|postgres|internal detail/);
		expect(lines.some((line) => line.includes('hunter2'))).toBe(true); // kept for operators
		await app.close();
	});

	it('keeps the message of a client error (4xx)', async () => {
		const app = appWithRoutes();
		const res = await app.inject({ method: 'GET', url: '/teapot' });
		expect(res.statusCode).toBe(418);
		expect(res.json()).toMatchObject({ message: 'short and stout' });
		await app.close();
	});

	it('still reports validation errors as a 400 with their message', async () => {
		const app = appWithRoutes();
		const writer = `Bearer ${Buffer.from('{"alg":"none"}').toString('base64url')}.${Buffer.from(JSON.stringify({ sub: 'a', scope: 'notes:write' })).toString('base64url')}.sig`;
		const res = await app.inject({
			method: 'POST',
			url: '/notes',
			headers: { authorization: writer },
			payload: { text: 5 },
		});
		expect(res.statusCode).toBe(400);
		expect(res.json()).toMatchObject({ message: expect.stringContaining('body/text') });
		await app.close();
	});

	it('still rate limits with a 429', async () => {
		const app = appWithRoutes();
		let last = 0;
		for (let i = 0; i < 101; i += 1) {
			last = (await app.inject({ method: 'GET', url: '/health' })).statusCode;
		}
		expect(last).toBe(429);
		await app.close();
	});
});
