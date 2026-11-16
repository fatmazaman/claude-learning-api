import { buildApp } from '../src/app';
import { stubVerifier } from '../src/auth';

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
const fakeJwt = (payload: object) => `${b64({ alg: 'none' })}.${b64(payload)}.sig`;
const bearer = (claims: object) => ({ authorization: `Bearer ${fakeJwt(claims)}` });

const noScopes = bearer({ sub: 'alice' });
const reader = bearer({ sub: 'alice', scope: 'notes:read' });
const writer = bearer({ sub: 'alice', scope: 'notes:write' });
const readerWriter = bearer({ sub: 'alice', scope: 'notes:read notes:write' });

describe('GET /notes', () => {
	const app = buildApp({ verifyToken: stubVerifier });
	afterAll(() => app.close());
	const get = (headers: Record<string, string> = {}) =>
		app.inject({ method: 'GET', url: '/notes', headers });

	it('401 with a Bearer challenge when there is no token', async () => {
		const res = await get();
		expect(res.statusCode).toBe(401);
		expect(res.headers['www-authenticate']).toBe('Bearer');
	});

	it('401 with an invalid_token challenge when the token is rejected', async () => {
		const res = await get({ authorization: 'Bearer not-a-jwt' });
		expect(res.statusCode).toBe(401);
		expect(res.headers['www-authenticate']).toBe('Bearer error="invalid_token"');
	});

	it('403 for a valid token that holds no scopes, naming the scope it needs', async () => {
		const res = await get(noScopes);
		expect(res.statusCode).toBe(403);
		expect(res.json()).toEqual({ error: 'Forbidden' });
		expect(res.headers['www-authenticate']).toBe(
			'Bearer error="insufficient_scope", scope="notes:read"',
		);
	});

	it('403 for a valid token that only holds a different scope', async () => {
		expect((await get(writer)).statusCode).toBe(403);
	});

	it('200 with notes:read, whether scope is a string or an array', async () => {
		const res = await get(reader);
		expect(res.statusCode).toBe(200);
		expect(res.json()).toEqual([]);
		const asArray = await get(bearer({ sub: 'alice', scope: ['notes:read'] }));
		expect(asArray.statusCode).toBe(200);
	});

	it('HEAD /notes, which Fastify generates from the GET route, is protected the same way', async () => {
		const head = (headers: Record<string, string>) =>
			app.inject({ method: 'HEAD', url: '/notes', headers });
		expect((await head({})).statusCode).toBe(401);
		expect((await head(noScopes)).statusCode).toBe(403);
		expect((await head(writer)).statusCode).toBe(403);
		expect((await head(reader)).statusCode).toBe(200);
	});

	it('matches scopes exactly: near-misses are rejected', async () => {
		for (const scope of ['Notes:Read', 'notes:readonly', 'notes:read:all', 'notes', 'notes:']) {
			expect((await get(bearer({ sub: 'alice', scope }))).statusCode).toBe(403);
		}
	});

	it('a malformed scope claim grants nothing', async () => {
		for (const scope of [42, true, { a: 1 }, ['notes:read', 3]]) {
			expect((await get(bearer({ sub: 'alice', scope }))).statusCode).toBe(403);
		}
	});
});

describe('POST /notes', () => {
	const app = buildApp({ verifyToken: stubVerifier });
	afterAll(() => app.close());
	const post = (headers: Record<string, string>, payload?: unknown) =>
		app.inject({ method: 'POST', url: '/notes', headers, payload: payload as object });

	it('401 before validation: no token plus an invalid body is not a 400', async () => {
		const res = await post({}, { nope: true });
		expect(res.statusCode).toBe(401);
		expect(res.headers['www-authenticate']).toBe('Bearer');
	});

	it('401 before parsing: no token plus an unparseable body is not a 400', async () => {
		const res = await app.inject({
			method: 'POST',
			url: '/notes',
			headers: { 'content-type': 'application/json' },
			payload: '{',
		});
		expect(res.statusCode).toBe(401);
	});

	it('403 before validation: a token without notes:write plus an invalid body is not a 400', async () => {
		const res = await post(reader, { nope: true });
		expect(res.statusCode).toBe(403);
		expect(res.headers['www-authenticate']).toBe(
			'Bearer error="insufficient_scope", scope="notes:write"',
		);
	});

	it('403 for a token that has no scopes at all', async () => {
		expect((await post(noScopes, { text: 'hi' })).statusCode).toBe(403);
	});

	it('201 with notes:write, and the note then shows up for a reader', async () => {
		const created = await post(writer, { text: 'buy milk' });
		expect(created.statusCode).toBe(201);
		const note = created.json();
		expect(note).toEqual({
			id: expect.any(String),
			text: 'buy milk',
			createdAt: expect.any(String),
		});

		const list = await app.inject({ method: 'GET', url: '/notes', headers: reader });
		expect(list.statusCode).toBe(200);
		expect(list.json()).toEqual([note]);
	});

	it('400 for an invalid body once the caller is allowed in', async () => {
		const bad: unknown[] = [
			{},
			{ text: '' },
			{ text: 'x'.repeat(501) },
			{ text: 5 }, // no type coercion: a number is not turned into "5"
			{ text: ['a'] }, // nor an array into its first element
			{ text: null },
			{ text: 'ok', extra: 1 }, // extra properties are rejected, not silently dropped
		];
		for (const body of bad) {
			expect((await post(writer, body)).statusCode).toBe(400);
		}
	});

	it('413 for a body over the 4 KiB limit', async () => {
		const res = await post(writer, { text: 'x'.repeat(5000) });
		expect(res.statusCode).toBe(413);
	});
});

describe('notes per user', () => {
	it('keeps each user to their own notes', async () => {
		const app = buildApp({ verifyToken: stubVerifier });
		await app.inject({
			method: 'POST',
			url: '/notes',
			headers: readerWriter,
			payload: { text: "alice's note" },
		});
		const bob = bearer({ sub: 'bob', scope: 'notes:read' });
		const res = await app.inject({ method: 'GET', url: '/notes', headers: bob });
		expect(res.statusCode).toBe(200);
		expect(res.json()).toEqual([]);
		await app.close();
	});

	it('stops at 100 notes per user with a 409', async () => {
		const app = buildApp({ verifyToken: stubVerifier });
		const statuses: number[] = [];
		for (let i = 0; i < 101; i += 1) {
			// A distinct address per request keeps the rate limiter (100/min) out of the way.
			const res = await app.inject({
				method: 'POST',
				url: '/notes',
				headers: writer,
				payload: { text: `note ${i}` },
				remoteAddress: `10.0.0.${i + 1}`,
			});
			statuses.push(res.statusCode);
		}
		expect(statuses.slice(0, 100).every((s) => s === 201)).toBe(true);
		expect(statuses[100]).toBe(409);
		await app.close();
	});
});
