import { buildApp } from './app';
import { verifierFromEnv } from './auth';
import { hostFromEnv, trustProxyFromEnv } from './config';

const app = buildApp({
	logger: { redact: ['req.headers.authorization', 'req.headers.cookie'] },
	trustProxy: trustProxyFromEnv(),
	verifyToken: verifierFromEnv(),
});
const port = Number(process.env.PORT ?? 3000);

app.listen({ port, host: hostFromEnv() }).catch((err) => {
	app.log.error(err);
	process.exit(1);
});
