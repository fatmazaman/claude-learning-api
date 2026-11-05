/** Interface to bind. Defaults to loopback; set HOST=0.0.0.0 in container/deploy config. */
export function hostFromEnv(env: NodeJS.ProcessEnv = process.env): string {
	return env.HOST || '127.0.0.1';
}

/**
 * Number of trusted reverse-proxy hops (TRUST_PROXY=1 behind one load balancer).
 * Unset or invalid means false, so X-Forwarded-For is ignored and cannot be spoofed.
 */
export function trustProxyFromEnv(
	env: NodeJS.ProcessEnv = process.env,
): ((address: string, hop: number) => boolean) | false {
	const hops = Number(env.TRUST_PROXY);
	// Same semantics as a numeric trustProxy, which Fastify's types don't accept.
	return Number.isInteger(hops) && hops > 0 ? (_address, hop) => hop < hops : false;
}
