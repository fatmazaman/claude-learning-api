import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
	SignJWT,
	createLocalJWKSet,
	exportJWK,
	exportSPKI,
	generateKeyPair,
	type JWK,
	type JWTPayload,
} from 'jose';
import { buildApp } from '../src/app';
import {
	buildOidcVerifier,
	createOidcVerifier,
	discoverJwksUri,
	oidcConfigFromEnv,
} from '../src/verifiers/oidc';

// Everything here runs offline: tokens are signed with a key pair generated in the test,
// and the "provider" is a throwaway HTTP server on 127.0.0.1.

const ISSUER = 'https://tenant.example.com/'; // trailing slash, like Auth0
const AUDIENCE = 'https://api.example.com';

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
const now = () => Math.floor(Date.now() / 1000);

async function makeKey(kid: string) {
	const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
	const jwk: JWK = { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };
	return { kid, publicKey, privateKey, jwk };
}
type Key = Awaited<ReturnType<typeof makeKey>>;

interface TokenOptions {
	kid?: string;
	issuer?: string;
	audience?: string;
	/** Absolute epoch seconds; null leaves the claim out. */
	exp?: number | null;
	nbf?: number;
	/** null leaves the claim out. */
	sub?: string | null;
	extra?: JWTPayload;
}

async function signToken(key: Key, options: TokenOptions = {}): Promise<string> {
	const jwt = new SignJWT({ ...options.extra })
		.setProtectedHeader({ alg: 'RS256', kid: options.kid ?? key.kid })
		.setIssuer(options.issuer ?? ISSUER)
		.setAudience(options.audience ?? AUDIENCE)
		.setIssuedAt(now());
	if (options.sub !== null) jwt.setSubject(options.sub ?? 'user-1');
	if (options.exp !== null) jwt.setExpirationTime(options.exp ?? now() + 300);
	if (options.nbf !== undefined) jwt.setNotBefore(options.nbf);
	return jwt.sign(key.privateKey);
}

function verifierFor(keys: Key[], overrides: { issuer?: string; audience?: string } = {}) {
	return buildOidcVerifier({
		issuer: overrides.issuer ?? ISSUER,
		audience: overrides.audience ?? AUDIENCE,
		getKey: createLocalJWKSet({ keys: keys.map((k) => k.jwk) }),
	});
}

describe('buildOidcVerifier', () => {
	let good: Key;
	let other: Key;
	beforeAll(async () => {
		good = await makeKey('key-1');
		other = await makeKey('key-2');
	});

	it('accepts a valid token and maps sub and scope', async () => {
		const token = await signToken(good, { extra: { scope: 'read:me write:me' } });
		await expect(verifierFor([good])(token)).resolves.toEqual({
			sub: 'user-1',
			scope: ['read:me', 'write:me'],
		});
	});

	it('accepts scope as an array and omits it when absent', async () => {
		const withArray = await signToken(good, { extra: { scope: ['a', 'b'] } });
		await expect(verifierFor([good])(withArray)).resolves.toEqual({
			sub: 'user-1',
			scope: ['a', 'b'],
		});
		const without = await signToken(good);
		await expect(verifierFor([good])(without)).resolves.toEqual({ sub: 'user-1' });
	});

	it('rejects an expired token but tolerates 30s of clock skew', async () => {
		const verify = verifierFor([good]);
		await expect(verify(await signToken(good, { exp: now() - 60 }))).resolves.toBeNull();
		await expect(verify(await signToken(good, { exp: now() - 10 }))).resolves.toMatchObject({
			sub: 'user-1',
		});
	});

	it('rejects a token that is not valid yet (nbf) beyond the skew tolerance', async () => {
		const verify = verifierFor([good]);
		await expect(verify(await signToken(good, { nbf: now() + 120 }))).resolves.toBeNull();
		await expect(verify(await signToken(good, { nbf: now() + 10 }))).resolves.toMatchObject({
			sub: 'user-1',
		});
	});

	it('rejects a wrong issuer', async () => {
		const token = await signToken(good, { issuer: 'https://evil.example.com/' });
		await expect(verifierFor([good])(token)).resolves.toBeNull();
	});

	it('matches the issuer exactly, trailing slash included', async () => {
		const withSlash = await signToken(good, { issuer: 'https://tenant.example.com/' });
		const withoutSlash = await signToken(good, { issuer: 'https://tenant.example.com' });
		const expectSlash = verifierFor([good], { issuer: 'https://tenant.example.com/' });
		const expectNoSlash = verifierFor([good], { issuer: 'https://tenant.example.com' });
		await expect(expectSlash(withSlash)).resolves.not.toBeNull();
		await expect(expectSlash(withoutSlash)).resolves.toBeNull();
		await expect(expectNoSlash(withoutSlash)).resolves.not.toBeNull();
		await expect(expectNoSlash(withSlash)).resolves.toBeNull();
	});

	it('rejects a token minted for another audience', async () => {
		const token = await signToken(good, { audience: 'https://other-api.example.com' });
		await expect(verifierFor([good])(token)).resolves.toBeNull();
	});

	it('rejects a bad signature (right kid, wrong private key)', async () => {
		const forged = await signToken(other, { kid: good.kid });
		await expect(verifierFor([good])(forged)).resolves.toBeNull();
	});

	it('rejects a valid token whose payload was tampered with', async () => {
		const [header, , signature] = (await signToken(good)).split('.');
		const swapped = `${header}.${b64({ iss: ISSUER, aud: AUDIENCE, sub: 'admin', exp: now() + 300 })}.${signature}`;
		await expect(verifierFor([good])(swapped)).resolves.toBeNull();
	});

	it('rejects an unknown kid', async () => {
		const token = await signToken(other); // kid "key-2" is not in the JWKS
		await expect(verifierFor([good])(token)).resolves.toBeNull();
	});

	it('rejects alg "none"', async () => {
		const unsigned = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ iss: ISSUER, aud: AUDIENCE, sub: 'admin', exp: now() + 300 })}.`;
		await expect(verifierFor([good])(unsigned)).resolves.toBeNull();
	});

	it('rejects an HS256 token signed with the public key as the secret (algorithm confusion)', async () => {
		const secret = new TextEncoder().encode(await exportSPKI(good.publicKey));
		const confused = await new SignJWT({})
			.setProtectedHeader({ alg: 'HS256', kid: good.kid })
			.setIssuer(ISSUER)
			.setAudience(AUDIENCE)
			.setSubject('admin')
			.setExpirationTime(now() + 300)
			.sign(secret);
		await expect(verifierFor([good])(confused)).resolves.toBeNull();
	});

	it('rejects a token with no expiry or no subject', async () => {
		const verify = verifierFor([good]);
		await expect(verify(await signToken(good, { exp: null }))).resolves.toBeNull();
		await expect(verify(await signToken(good, { sub: null }))).resolves.toBeNull();
		await expect(verify(await signToken(good, { sub: '' }))).resolves.toBeNull();
	});

	it('rejects a validly signed token that uses an algorithm outside the pinned list', async () => {
		// Same claims, a key the JWKS trusts, a correct signature, but PS256 instead of RS256.
		// Only the algorithm pin stands between this token and acceptance.
		const { publicKey, privateKey } = await generateKeyPair('PS256', { extractable: true });
		const ps256Jwk: JWK = {
			...(await exportJWK(publicKey)),
			kid: 'ps-key',
			alg: 'PS256',
			use: 'sig',
		};
		const token = await new SignJWT({})
			.setProtectedHeader({ alg: 'PS256', kid: 'ps-key' })
			.setIssuer(ISSUER)
			.setAudience(AUDIENCE)
			.setSubject('user-1')
			.setExpirationTime(now() + 300)
			.sign(privateKey);
		const verify = buildOidcVerifier({
			issuer: ISSUER,
			audience: AUDIENCE,
			getKey: createLocalJWKSet({ keys: [ps256Jwk] }),
		});
		await expect(verify(token)).resolves.toBeNull();
	});

	it('rejects malformed tokens', async () => {
		const verify = verifierFor([good]);
		for (const token of ['', 'abc', 'a.b', 'a.b.c', 'a.b.c.d.e']) {
			await expect(verify(token)).resolves.toBeNull();
		}
	});
});

describe('oidcConfigFromEnv', () => {
	it('returns null when neither variable is set (or both are empty)', () => {
		expect(oidcConfigFromEnv({})).toBeNull();
		expect(oidcConfigFromEnv({ OIDC_ISSUER: '', OIDC_AUDIENCE: '' })).toBeNull();
	});

	it('returns the config when both are set', () => {
		expect(oidcConfigFromEnv({ OIDC_ISSUER: ISSUER, OIDC_AUDIENCE: AUDIENCE })).toEqual({
			issuer: ISSUER,
			audience: AUDIENCE,
		});
	});

	it('throws when only one is set', () => {
		expect(() => oidcConfigFromEnv({ OIDC_ISSUER: ISSUER })).toThrow(/must both be set/);
		expect(() => oidcConfigFromEnv({ OIDC_AUDIENCE: AUDIENCE })).toThrow(/must both be set/);
	});
});

// ---- A throwaway provider on 127.0.0.1, for discovery, rotation and outage tests ----

interface ProviderState {
	/** Issuer the discovery document reports (defaults to the server origin). */
	issuer?: string;
	/** jwks_uri the discovery document reports; null leaves it out. */
	jwksUri?: string | null;
	jwks: { keys: JWK[] };
	discoveryStatus: number;
	jwksStatus: number;
	jwksHits: number;
}

async function startProvider(keys: JWK[]) {
	const state: ProviderState = {
		jwks: { keys },
		discoveryStatus: 200,
		jwksStatus: 200,
		jwksHits: 0,
	};
	const server: Server = createServer((req, res) => {
		const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
		res.setHeader('content-type', 'application/json');
		if (req.url === '/.well-known/openid-configuration') {
			res.statusCode = state.discoveryStatus;
			const doc: Record<string, unknown> = { issuer: state.issuer ?? origin };
			if (state.jwksUri !== null) doc.jwks_uri = state.jwksUri ?? `${origin}/jwks.json`;
			res.end(JSON.stringify(doc));
		} else if (req.url === '/jwks.json') {
			state.jwksHits += 1;
			res.statusCode = state.jwksStatus;
			res.end(JSON.stringify(state.jwks));
		} else {
			res.statusCode = 404;
			res.end('{}');
		}
	});
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
	const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
	return {
		origin,
		state,
		close: () =>
			new Promise<void>((resolve) => {
				server.close(() => resolve());
				server.closeAllConnections();
			}),
	};
}
type Provider = Awaited<ReturnType<typeof startProvider>>;

describe('discoverJwksUri', () => {
	let key: Key;
	let provider: Provider;
	beforeAll(async () => {
		key = await makeKey('key-1');
	});
	beforeEach(async () => {
		provider = await startProvider([key.jwk]);
	});
	afterEach(() => provider.close());

	it('returns the jwks_uri from the discovery document', async () => {
		await expect(discoverJwksUri(provider.origin)).resolves.toEqual(
			new URL(`${provider.origin}/jwks.json`),
		);
	});

	it('handles an issuer with a trailing slash', async () => {
		provider.state.issuer = `${provider.origin}/`;
		await expect(discoverJwksUri(`${provider.origin}/`)).resolves.toEqual(
			new URL(`${provider.origin}/jwks.json`),
		);
	});

	it('rejects when the provider reports a different issuer (e.g. a missing trailing slash)', async () => {
		provider.state.issuer = `${provider.origin}/`;
		await expect(discoverJwksUri(provider.origin)).rejects.toThrow(/issuer mismatch/);
	});

	it('rejects a discovery document with no jwks_uri', async () => {
		provider.state.jwksUri = null;
		await expect(discoverJwksUri(provider.origin)).rejects.toThrow(/no jwks_uri/);
	});

	it('rejects a non-https jwks_uri', async () => {
		provider.state.jwksUri = 'http://keys.evil.example/jwks.json';
		await expect(discoverJwksUri(provider.origin)).rejects.toThrow(/must use https/);
	});

	it('rejects a non-https issuer without making a request', async () => {
		const fetchSpy = jest.fn();
		await expect(discoverJwksUri('http://issuer.example.com', fetchSpy)).rejects.toThrow(
			/must use https/,
		);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it('explains why discovery failed when the provider is unreachable', async () => {
		// Grab a free port and close it again, so nothing is listening there. A bare
		// "fetch failed" would not tell an operator anything. (Port 1 would not do: fetch
		// refuses it as a "bad port" before connecting.)
		await provider.close();
		await expect(discoverJwksUri(provider.origin)).rejects.toThrow(
			new RegExp(
				`OIDC discovery request to ${provider.origin.replace(/[.]/g, '\\.')}/\\.well-known/openid-configuration failed: .*ECONNREFUSED`,
			),
		);
		provider = await startProvider([key.jwk]); // afterEach closes whatever is current
	});

	it('rejects when discovery returns an error status', async () => {
		provider.state.discoveryStatus = 404;
		await expect(discoverJwksUri(provider.origin)).rejects.toThrow(/returned 404/);
	});
});

describe('createOidcVerifier against a local provider', () => {
	let key1: Key;
	let key2: Key;
	let provider: Provider;
	beforeAll(async () => {
		key1 = await makeKey('key-1');
		key2 = await makeKey('key-2');
	});
	beforeEach(async () => {
		provider = await startProvider([key1.jwk]);
	});
	afterEach(() => provider.close());

	const tokenFor = (key: Key, options: TokenOptions = {}) =>
		signToken(key, { issuer: provider.origin, ...options });

	it('verifies a token signed by a key from the discovered JWKS', async () => {
		const verify = await createOidcVerifier({ issuer: provider.origin, audience: AUDIENCE });
		await expect(verify(await tokenFor(key1))).resolves.toEqual({ sub: 'user-1' });
	});

	it('refetches the JWKS when a new kid appears (key rotation)', async () => {
		const verify = await createOidcVerifier(
			{ issuer: provider.origin, audience: AUDIENCE },
			{ jwks: { cooldownDuration: 0 } },
		);
		await expect(verify(await tokenFor(key1))).resolves.not.toBeNull();

		provider.state.jwks = { keys: [key2.jwk] }; // the provider rotates its key
		await expect(verify(await tokenFor(key2))).resolves.not.toBeNull();
		await expect(verify(await tokenFor(key1))).resolves.toBeNull(); // old key is gone
	});

	it('caches the JWKS instead of fetching it on every request', async () => {
		const verify = await createOidcVerifier({ issuer: provider.origin, audience: AUDIENCE });
		for (let i = 0; i < 5; i += 1) {
			await expect(verify(await tokenFor(key1))).resolves.not.toBeNull();
		}
		expect(provider.state.jwksHits).toBe(1);
	});

	it('rate-limits refetches when tokens keep arriving with unknown kids', async () => {
		const verify = await createOidcVerifier({ issuer: provider.origin, audience: AUDIENCE });
		for (let i = 0; i < 5; i += 1) {
			await expect(verify(await tokenFor(key2))).resolves.toBeNull();
		}
		expect(provider.state.jwksHits).toBeLessThanOrEqual(2);
	});

	it('rethrows (so the route answers 503) when the key source is down, instead of returning null', async () => {
		const verify = await createOidcVerifier({ issuer: provider.origin, audience: AUDIENCE });
		provider.state.jwksStatus = 500;
		await expect(verify(await tokenFor(key1))).rejects.toThrow();
	});
});

describe('GET /me with the OIDC verifier', () => {
	let key: Key;
	beforeAll(async () => {
		key = await makeKey('key-1');
	});

	const meRequest = (app: ReturnType<typeof buildApp>, token: string) =>
		app.inject({ method: 'GET', url: '/me', headers: { authorization: `Bearer ${token}` } });

	it('accepts a real signed token and rejects the same token once modified', async () => {
		const app = buildApp({ verifyToken: verifierFor([key]) });
		const token = await signToken(key);
		const ok = await meRequest(app, token);
		expect(ok.statusCode).toBe(200);
		expect(ok.json()).toEqual({ sub: 'user-1' });

		const [header, , signature] = token.split('.');
		const tampered = `${header}.${b64({ iss: ISSUER, aud: AUDIENCE, sub: 'admin', exp: now() + 300 })}.${signature}`;
		expect((await meRequest(app, tampered)).statusCode).toBe(401);
		await app.close();
	});

	it('never writes a token to the logs or the response body', async () => {
		const lines: string[] = [];
		const app = buildApp({
			verifyToken: verifierFor([key]),
			logger: {
				level: 'trace',
				redact: ['req.headers.authorization', 'req.headers.cookie'],
				stream: { write: (line: string) => void lines.push(line) },
			},
		});
		const valid = await signToken(key);
		const [header, , signature] = valid.split('.');
		const tokens = [
			valid,
			await signToken(key, { exp: now() - 600 }),
			await signToken(key, { audience: 'https://other.example.com' }),
			`${header}.${b64({ sub: 'admin' })}.${signature}`,
		];
		for (const token of tokens) {
			const res = await meRequest(app, token);
			expect(res.body).not.toContain(token);
		}
		for (const token of tokens) {
			for (const line of lines) expect(line).not.toContain(token);
		}
		await app.close();
	});

	it('answers a generic 503 and does not log the token when the key source is down', async () => {
		const provider = await startProvider([key.jwk]);
		const lines: string[] = [];
		const verify = await createOidcVerifier({ issuer: provider.origin, audience: AUDIENCE });
		provider.state.jwksStatus = 500;
		const app = buildApp({
			verifyToken: verify,
			logger: { level: 'trace', stream: { write: (line: string) => void lines.push(line) } },
		});
		const token = await signToken(key, { issuer: provider.origin });
		const res = await meRequest(app, token);
		expect(res.statusCode).toBe(503);
		expect(res.json()).toEqual({ error: 'Service Unavailable' });
		for (const line of lines) expect(line).not.toContain(token);
		await app.close();
		await provider.close();
	});
});
