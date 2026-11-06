import Fastify from 'fastify';
import { hostFromEnv, trustProxyFromEnv } from '../src/config';

describe('hostFromEnv', () => {
	it('binds to loopback by default', () => {
		expect(hostFromEnv({})).toBe('127.0.0.1');
		expect(hostFromEnv({ HOST: '' })).toBe('127.0.0.1');
	});

	it('uses HOST when set', () => {
		expect(hostFromEnv({ HOST: '0.0.0.0' })).toBe('0.0.0.0');
	});
});

describe('trustProxyFromEnv', () => {
	it('does not trust proxies by default or for invalid values', () => {
		for (const TRUST_PROXY of [undefined, '', 'true', '0', '-1', '1.5', 'abc']) {
			expect(trustProxyFromEnv({ TRUST_PROXY })).toBe(false);
		}
	});

	it('returns the hop count when it is a positive integer', () => {
		const one = trustProxyFromEnv({ TRUST_PROXY: '1' });
		const two = trustProxyFromEnv({ TRUST_PROXY: '2' });
		if (!one || !two) throw new Error('expected trust functions');
		expect([one('10.0.0.1', 0), one('10.0.0.2', 1)]).toEqual([true, false]);
		expect([two('10.0.0.1', 0), two('10.0.0.2', 1), two('10.0.0.3', 2)]).toEqual([
			true,
			true,
			false,
		]);
	});
});

describe('trustProxyFromEnv with Fastify', () => {
	// The proxy at 10.0.0.1 appended the real client (203.0.113.9); the client itself
	// sent a spoofed 6.6.6.6 at the front of X-Forwarded-For.
	async function clientIp(TRUST_PROXY: string | undefined, forwardedFor: string) {
		const app = Fastify({ trustProxy: trustProxyFromEnv({ TRUST_PROXY }) });
		app.get('/ip', async (request) => request.ip);
		const res = await app.inject({
			method: 'GET',
			url: '/ip',
			remoteAddress: '10.0.0.1',
			headers: { 'x-forwarded-for': forwardedFor },
		});
		await app.close();
		return res.body;
	}

	it('ignores X-Forwarded-For when TRUST_PROXY is unset', async () => {
		expect(await clientIp(undefined, '6.6.6.6, 203.0.113.9')).toBe('10.0.0.1');
	});

	it('ignores a spoofed entry behind one trusted proxy', async () => {
		expect(await clientIp('1', '6.6.6.6, 203.0.113.9')).toBe('203.0.113.9');
	});

	it('walks two trusted proxies to the real client', async () => {
		expect(await clientIp('2', '203.0.113.9, 10.0.0.7')).toBe('203.0.113.9');
	});
});
