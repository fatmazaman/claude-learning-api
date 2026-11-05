import { stubVerifier, verifierFromEnv } from '../src/auth';

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
const fakeJwt = (payload: object) => `${b64({ alg: 'none' })}.${b64(payload)}.sig`;

describe('stubVerifier', () => {
	const original = process.env.NODE_ENV;
	afterEach(() => {
		process.env.NODE_ENV = original;
	});

	it('refuses to run when NODE_ENV=production', async () => {
		process.env.NODE_ENV = 'production';
		await expect(stubVerifier(fakeJwt({ sub: 'user-1' }))).rejects.toThrow(/production/);
	});

	it('decodes unsigned tokens outside production', async () => {
		process.env.NODE_ENV = 'test';
		await expect(stubVerifier(fakeJwt({ sub: 'user-1' }))).resolves.toEqual({ sub: 'user-1' });
	});
});

describe('verifierFromEnv', () => {
	it('throws when no verifier is configured', () => {
		expect(() => verifierFromEnv({})).toThrow(/No token verifier/);
		expect(() => verifierFromEnv({ NODE_ENV: 'staging' })).toThrow(/No token verifier/);
	});

	it('requires an explicit opt-in to use the stub', () => {
		expect(verifierFromEnv({ ALLOW_STUB_AUTH: '1', NODE_ENV: 'development' })).toBe(stubVerifier);
		expect(verifierFromEnv({ ALLOW_STUB_AUTH: '1', NODE_ENV: 'test' })).toBe(stubVerifier);
		expect(() => verifierFromEnv({ ALLOW_STUB_AUTH: 'true', NODE_ENV: 'development' })).toThrow();
	});

	it('refuses the stub opt-in outside development and test', () => {
		for (const NODE_ENV of ['production', 'staging', undefined]) {
			expect(() => verifierFromEnv({ ALLOW_STUB_AUTH: '1', NODE_ENV })).toThrow(/only permitted/);
		}
	});
});
