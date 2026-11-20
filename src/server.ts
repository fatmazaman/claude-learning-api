import { buildApp } from './app';
import { verifierFromEnv } from './auth';
import { hostFromEnv, trustProxyFromEnv } from './config';
import { mcpConfigFromEnv } from './mcp/config';
import { oidcConfigFromEnv } from './verifiers/oidc';

async function main() {
	// Check the MCP settings first (they are cheap and synchronous), then resolve the verifier:
	// with OIDC that fetches the provider's discovery document. Any failure here (bad issuer,
	// provider down, MCP enabled without a real verifier or with a bad audience) stops startup.
	const mcp = mcpConfigFromEnv(process.env, oidcConfigFromEnv(process.env));
	const verifyToken = await verifierFromEnv();
	const app = buildApp({
		logger: { redact: ['req.headers.authorization', 'req.headers.cookie'] },
		trustProxy: trustProxyFromEnv(),
		verifyToken,
		...(mcp ? { mcp } : {}),
	});
	const port = Number(process.env.PORT ?? 3000);

	try {
		await app.listen({ port, host: hostFromEnv() });
	} catch (err) {
		app.log.error(err);
		process.exit(1);
	}
}

main().catch((err) => {
	console.error(err instanceof Error ? err.message : err);
	process.exit(1);
});
