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
