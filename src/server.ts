import { buildApp } from './app';
import { verifierFromEnv } from './auth';
import { hostFromEnv, trustProxyFromEnv } from './config';

async function main() {
	// Resolve the verifier first: with OIDC it fetches the provider's discovery document,
	// and any failure here (bad issuer, provider down, missing config) stops startup.
	const verifyToken = await verifierFromEnv();
	const app = buildApp({
		logger: { redact: ['req.headers.authorization', 'req.headers.cookie'] },
		trustProxy: trustProxyFromEnv(),
		verifyToken,
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
