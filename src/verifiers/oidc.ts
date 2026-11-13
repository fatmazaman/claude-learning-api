import { createRemoteJWKSet, errors, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from 'jose';
import type { AuthUser, TokenVerifier } from '../auth';

export interface OidcConfig {
	/** Must equal the `iss` claim exactly, trailing slash included (Auth0 issuers end in "/"). */
	issuer: string;
	audience: string;
}

/** Only RS256 is accepted: this rules out `alg: none` and HS256 key-confusion attacks. */
const ALLOWED_ALGORITHMS = ['RS256'];
const CLOCK_TOLERANCE_SECONDS = 30;
const DISCOVERY_TIMEOUT_MS = 5_000;

/**
 * Reads OIDC_ISSUER and OIDC_AUDIENCE. Returns null when neither is set, and throws when
 * only one is, because a half-configured verifier is a mistake we should not paper over.
 */
export function oidcConfigFromEnv(env: NodeJS.ProcessEnv = process.env): OidcConfig | null {
	const issuer = env.OIDC_ISSUER || undefined;
	const audience = env.OIDC_AUDIENCE || undefined;
	if (!issuer && !audience) return null;
	if (!issuer || !audience) {
		throw new Error('OIDC_ISSUER and OIDC_AUDIENCE must both be set (only one was found).');
	}
	return { issuer, audience };
}

function isAllowedUrl(url: URL): boolean {
	if (url.protocol === 'https:') return true;
	// Plain http is only for local test providers.
	return url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
}

/**
 * Node's fetch reports every network failure as "fetch failed"; the useful detail
 * (ECONNREFUSED, ENOTFOUND, a timeout) is on `cause`. Duck-typed on purpose: errors from
 * Node's internals are not `instanceof` this realm's Error under Jest.
 */
function describeFailure(err: unknown): string {
	const messageOf = (value: unknown): string | undefined =>
		typeof value === 'object' &&
		value !== null &&
		'message' in value &&
		typeof value.message === 'string'
			? value.message
			: undefined;
	const cause = typeof err === 'object' && err !== null && 'cause' in err ? err.cause : undefined;
	return messageOf(cause) ?? messageOf(err) ?? String(err);
}

/**
 * Fetches `<issuer>/.well-known/openid-configuration` and returns its `jwks_uri`.
 * Throws on any problem, so the server refuses to start with a bad issuer.
 */
export async function discoverJwksUri(
	issuer: string,
	fetchImpl: typeof fetch = fetch,
): Promise<URL> {
	const issuerUrl = new URL(issuer);
	if (!isAllowedUrl(issuerUrl)) {
		throw new Error(`OIDC issuer must use https: ${issuer}`);
	}
	// Append (not replace), so issuers with a path work, with or without a trailing slash.
	const discoveryUrl = new URL(
		'.well-known/openid-configuration',
		issuer.endsWith('/') ? issuer : `${issuer}/`,
	);
	let res: Response;
	try {
		res = await fetchImpl(discoveryUrl, {
			headers: { accept: 'application/json' },
			redirect: 'error',
			signal: AbortSignal.timeout(DISCOVERY_TIMEOUT_MS),
		});
	} catch (err) {
		throw new Error(
			`OIDC discovery request to ${discoveryUrl.href} failed: ${describeFailure(err)}`,
			{ cause: err },
		);
	}
	if (!res.ok) {
		throw new Error(`OIDC discovery failed: ${discoveryUrl.href} returned ${res.status}`);
	}
	let doc: unknown;
	try {
		doc = await res.json();
	} catch (err) {
		throw new Error(
			`OIDC discovery response from ${discoveryUrl.href} is not valid JSON: ${describeFailure(err)}`,
			{ cause: err },
		);
	}
	if (typeof doc !== 'object' || doc === null) {
		throw new Error('OIDC discovery document is not a JSON object.');
	}
	const { issuer: reportedIssuer, jwks_uri: jwksUri } = doc as Record<string, unknown>;
	if (reportedIssuer !== issuer) {
		throw new Error(
			`OIDC discovery issuer mismatch: configured "${issuer}" but the provider reports "${String(reportedIssuer)}".`,
		);
	}
	if (typeof jwksUri !== 'string') {
		throw new Error('OIDC discovery document has no jwks_uri.');
	}
	const jwksUrl = new URL(jwksUri);
	if (!isAllowedUrl(jwksUrl)) {
		throw new Error(`OIDC jwks_uri must use https: ${jwksUri}`);
	}
	return jwksUrl;
}

/** Errors that mean "this token is not acceptable", as opposed to "we could not check it". */
function isTokenRejection(err: unknown): boolean {
	return (
		err instanceof errors.JWTExpired ||
		err instanceof errors.JWTClaimValidationFailed ||
		err instanceof errors.JWSSignatureVerificationFailed ||
		err instanceof errors.JOSEAlgNotAllowed ||
		err instanceof errors.JWKSNoMatchingKey ||
		err instanceof errors.JWKSMultipleMatchingKeys ||
		err instanceof errors.JWSInvalid ||
		err instanceof errors.JWTInvalid ||
		err instanceof errors.JOSENotSupported
	);
}

function parseScope(value: unknown): string[] | undefined {
	if (typeof value === 'string') return value.split(/\s+/).filter(Boolean);
	if (Array.isArray(value) && value.every((item) => typeof item === 'string')) return value;
	return undefined;
}

function toAuthUser(payload: JWTPayload): AuthUser | null {
	if (typeof payload.sub !== 'string' || payload.sub === '') return null;
	const user: AuthUser = { sub: payload.sub };
	const scope = parseScope(payload.scope);
	if (scope) user.scope = scope;
	return user;
}

/**
 * Builds a verifier from a key resolver. No network happens here, so tests can pass a
 * local JWKS. Bad tokens resolve to null (401). Failures to reach the key source are
 * rethrown so requireAuth answers 503 instead of blaming the caller. This function never
 * logs, and never rethrows claim errors (they carry the token payload).
 */
export function buildOidcVerifier({
	issuer,
	audience,
	getKey,
}: OidcConfig & { getKey: JWTVerifyGetKey }): TokenVerifier {
	return async (token) => {
		try {
			const { payload } = await jwtVerify(token, getKey, {
				issuer,
				audience,
				algorithms: ALLOWED_ALGORITHMS,
				clockTolerance: CLOCK_TOLERANCE_SECONDS,
				requiredClaims: ['exp'],
			});
			return toAuthUser(payload);
		} catch (err) {
			if (isTokenRejection(err)) return null;
			throw err;
		}
	};
}

export interface OidcDeps {
	fetch?: typeof fetch;
	jwks?: { cooldownDuration?: number; cacheMaxAge?: number; timeoutDuration?: number };
}

/**
 * Discovers the provider's jwks_uri once, then verifies tokens against its keys. jose caches
 * the key set and refetches when a token carries an unknown `kid` (key rotation), at most
 * once per cooldown, so the provider is not hit on every request.
 */
export async function createOidcVerifier(
	config: OidcConfig,
	deps: OidcDeps = {},
): Promise<TokenVerifier> {
	const jwksUri = await discoverJwksUri(config.issuer, deps.fetch);
	const getKey = createRemoteJWKSet(jwksUri, {
		cooldownDuration: 30_000,
		cacheMaxAge: 600_000,
		timeoutDuration: 5_000,
		...deps.jwks,
	});
	return buildOidcVerifier({ ...config, getKey });
}
