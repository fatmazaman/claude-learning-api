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
	// fetch refuses port 1 as a "bad port", so discovery fails fast, offline, without a connection.
	const unreachableIssuer = 'http://127.0.0.1:1';

	it('throws when no verifier is configured', async () => {
		await expect(verifierFromEnv({})).rejects.toThrow(/No token verifier/);
		await expect(verifierFromEnv({ NODE_ENV: 'staging' })).rejects.toThrow(/No token verifier/);
		await expect(verifierFromEnv({ NODE_ENV: 'production' })).rejects.toThrow(/No token verifier/);
	});

	it('requires an explicit opt-in to use the stub', async () => {
		await expect(verifierFromEnv({ ALLOW_STUB_AUTH: '1', NODE_ENV: 'development' })).resolves.toBe(
			stubVerifier,
		);
		await expect(verifierFromEnv({ ALLOW_STUB_AUTH: '1', NODE_ENV: 'test' })).resolves.toBe(
			stubVerifier,
		);
		await expect(
			verifierFromEnv({ ALLOW_STUB_AUTH: 'true', NODE_ENV: 'development' }),
		).rejects.toThrow();
	});

	it('refuses the stub opt-in outside development and test', async () => {
		for (const NODE_ENV of ['production', 'staging', undefined]) {
			await expect(verifierFromEnv({ ALLOW_STUB_AUTH: '1', NODE_ENV })).rejects.toThrow(
				/only permitted/,
			);
		}
	});

	it('refuses a half-configured OIDC setup in every environment', async () => {
		for (const NODE_ENV of ['production', 'development', 'test']) {
			await expect(
				verifierFromEnv({ NODE_ENV, OIDC_ISSUER: 'https://i.example/' }),
			).rejects.toThrow(/must both be set/);
			await expect(verifierFromEnv({ NODE_ENV, OIDC_AUDIENCE: 'api' })).rejects.toThrow(
				/must both be set/,
			);
		}
	});

	it('uses OIDC when both variables are set, and fails closed if discovery fails', async () => {
		await expect(
			verifierFromEnv({
				NODE_ENV: 'production',
				OIDC_ISSUER: unreachableIssuer,
				OIDC_AUDIENCE: 'api',
			}),
		).rejects.toThrow();
	});

	it('does not fall back to the stub when OIDC is configured', async () => {
		await expect(
			verifierFromEnv({
				NODE_ENV: 'development',
				ALLOW_STUB_AUTH: '1',
				OIDC_ISSUER: unreachableIssuer,
				OIDC_AUDIENCE: 'api',
			}),
		).rejects.toThrow();
	});
});
