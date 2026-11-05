import { buildApp } from './app';
import { verifierFromEnv } from './auth';

const app = buildApp({
	logger: { redact: ['req.headers.authorization', 'req.headers.cookie'] },
	verifyToken: verifierFromEnv(),
});
const port = Number(process.env.PORT ?? 3000);

app.listen({ port, host: '0.0.0.0' }).catch((err) => {
	app.log.error(err);
	process.exit(1);
});
