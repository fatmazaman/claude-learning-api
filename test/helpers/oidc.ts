import {
	SignJWT,
	createLocalJWKSet,
	exportJWK,
	generateKeyPair,
	type JWK,
	type JWTPayload,
} from 'jose';
import { buildOidcVerifier } from '../../src/verifiers/oidc';

// Offline helpers shared by the verifier and MCP tests: tokens are signed with a key pair
// generated in the test and checked against a local JWKS, so nothing touches the network.

export const ISSUER = 'https://tenant.example.com/'; // trailing slash, like Auth0
export const AUDIENCE = 'https://api.example.com';

export const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
export const now = () => Math.floor(Date.now() / 1000);

export async function makeKey(kid: string) {
	const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
	const jwk: JWK = { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };
	return { kid, publicKey, privateKey, jwk };
}
export type Key = Awaited<ReturnType<typeof makeKey>>;

export interface TokenOptions {
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

export async function signToken(key: Key, options: TokenOptions = {}): Promise<string> {
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

export function verifierFor(keys: Key[], overrides: { issuer?: string; audience?: string } = {}) {
	return buildOidcVerifier({
		issuer: overrides.issuer ?? ISSUER,
		audience: overrides.audience ?? AUDIENCE,
		getKey: createLocalJWKSet({ keys: keys.map((k) => k.jwk) }),
	});
}
