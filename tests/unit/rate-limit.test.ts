import { describe, expect, test } from 'bun:test';
import { requestLimiter, requestSource } from '../../packages/signaling/rate-limit';

describe('bounded HTTP request budgets', () => {
    test('one abusive source cannot consume another source budget with rejected requests', () => {
        const allow = requestLimiter({ perSource: 2, global: 4 });
        expect(allow('a')).toBe(true); expect(allow('a')).toBe(true);
        for (let i = 0; i < 100; i++) expect(allow('a')).toBe(false);
        expect(allow('b')).toBe(true); expect(allow('b')).toBe(true);
        expect(allow('c')).toBe(false);
    });
    test('global budget limits many individually compliant sources', () => {
        const allow = requestLimiter({ perSource: 10, global: 2 });
        expect(allow('a')).toBe(true); expect(allow('b')).toBe(true); expect(allow('c')).toBe(false);
    });
    test('source state cannot grow beyond its cap and expires next window', () => {
        let now = 0;
        const allow = requestLimiter({ perSource: 2, global: 100, maxSources: 2, now: () => now });
        expect(allow('a')).toBe(true); expect(allow('b')).toBe(true);
        for (let i = 0; i < 100; i++) expect(allow(`new-${i}`)).toBe(false);
        expect(allow('a')).toBe(true);
        now = 999; expect(allow('c')).toBe(false);
        now = 1000; expect(allow('c')).toBe(true); expect(allow('a')).toBe(true);
    });
    test('rejects invalid limit configuration', () => {
        for (const value of [0, -1, NaN, Infinity, 1.5]) {
            expect(() => requestLimiter({ perSource: value })).toThrow();
            expect(() => requestLimiter({ global: value })).toThrow();
            expect(() => requestLimiter({ maxSources: value })).toThrow();
        }
    });
});

describe('reverse proxy source trust', () => {
    const headers = (address: string) => new Headers({ 'X-Real-IP': address });
    test('direct clients and disabled proxy trust cannot spoof identity', () => {
        expect(requestSource('198.51.100.2', headers('192.0.2.1'), true)).toBe('198.51.100.2');
        expect(requestSource('127.0.0.1', headers('192.0.2.1'))).toBe('127.0.0.1');
        expect(requestSource(undefined, headers('192.0.2.1'), true)).toBe('unknown');
    });
    test('explicit local proxy accepts a single valid address', () => {
        for (const loopback of ['127.0.0.1', '::1', '::ffff:127.0.0.1']) {
            expect(requestSource(loopback, headers('192.0.2.1'), true)).toBe('192.0.2.1');
            expect(requestSource(loopback, headers('2001:db8::1'), true)).toBe('2001:db8::1');
        }
    });
    test('lists, ports and invalid addresses cannot create attacker-defined buckets', () => {
        for (const invalid of ['192.0.2.1, 198.51.100.1', '192.0.2.1:80', '[2001:db8::1]:80', 'attacker', '']) {
            expect(requestSource('127.0.0.1', headers(invalid), true)).toBe('127.0.0.1');
        }
        expect(requestSource('127.0.0.1', new Headers({ 'X-Forwarded-For': '192.0.2.1' }), true)).toBe('127.0.0.1');
    });
});
