import Fastify from 'fastify';
import { hasScopes, parseScope, requireScope } from '../src/scopes';

describe('parseScope', () => {
	it('splits a space-delimited string', () => {
		expect(parseScope('notes:read notes:write')).toEqual(['notes:read', 'notes:write']);
	});

	it('ignores extra whitespace', () => {
		expect(parseScope('  notes:read \t notes:write\n')).toEqual(['notes:read', 'notes:write']);
		expect(parseScope('')).toEqual([]);
		expect(parseScope('   ')).toEqual([]);
	});

	it('accepts an array of strings', () => {
		expect(parseScope(['a', 'b'])).toEqual(['a', 'b']);
	});

	it('grants nothing for anything else', () => {
		for (const value of [undefined, null, 42, {}, ['a', 3], [null], true]) {
			expect(parseScope(value)).toBeUndefined();
		}
	});
});

describe('hasScopes', () => {
	it('requires every listed scope', () => {
		const user = { scope: ['a', 'b'] };
		expect(hasScopes(user, ['a'])).toBe(true);
		expect(hasScopes(user, ['a', 'b'])).toBe(true);
		expect(hasScopes(user, ['a', 'c'])).toBe(false);
	});

	it('matches whole tokens, exactly and case-sensitively', () => {
		expect(hasScopes({ scope: ['notes:readonly'] }, ['notes:read'])).toBe(false);
		expect(hasScopes({ scope: ['notes:read'] }, ['notes:read:all'])).toBe(false);
		expect(hasScopes({ scope: ['Notes:Read'] }, ['notes:read'])).toBe(false);
	});

	it('treats a missing scope list as no scopes', () => {
		expect(hasScopes({}, ['a'])).toBe(false);
		expect(hasScopes({}, [])).toBe(true);
	});
});

describe('requireScope', () => {
	it('refuses to be built without a scope', () => {
		expect(() => requireScope()).toThrow(/at least one scope/);
	});

	it('refuses scope names that are not valid scope tokens', () => {
		for (const bad of ['', 'two words', 'quo"te', 'back\\slash', 'new\nline', 'tab\t']) {
			expect(() => requireScope(bad)).toThrow(/Invalid scope name/);
		}
	});

	it('fails closed with a generic 500 when used without requireAuth', async () => {
		const app = Fastify();
		app.get('/oops', { onRequest: requireScope('notes:read') }, async () => ({ ok: true }));
		const res = await app.inject({ method: 'GET', url: '/oops' });
		expect(res.statusCode).toBe(500);
		expect(res.json()).toEqual({ error: 'Internal Server Error' });
		expect(res.body).not.toMatch(/requireAuth|requireScope|notes:read/);
		await app.close();
	});
});
