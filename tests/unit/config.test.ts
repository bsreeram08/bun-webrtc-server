import { describe, expect, test } from 'bun:test';
import { validateTurnUrl } from '../../packages/signaling/config';

describe('TURN endpoint configuration', () => {
    test('accepts hostname, IPv4 and bracketed IPv6 endpoints with valid transport and ports', () => {
        for (const value of [
            'turn:relay.example', 'turns:relay.example', 'turn:localhost:3478',
            'turn:relay.example.:3478?transport=udp', 'turn:relay.example:65535?transport=tcp',
            'turns:relay.example:5349?transport=tcp', 'turn:192.0.2.1:1',
            'turn:[2001:db8::1]:3478?transport=udp', 'turns:[::1]?transport=tcp',
        ]) expect(() => validateTurnUrl(value)).not.toThrow();
    });
    test('rejects impossible ports and unsupported secure UDP transport', () => {
        for (const value of [
            'turn:relay.example:0', 'turn:relay.example:65536', 'turn:relay.example:999999',
            'turn:relay.example:-1', 'turn:relay.example:1.5', 'turn:relay.example:',
            'turns:relay.example:5349?transport=udp', 'turn:relay.example:3478?transport=sctp',
        ]) expect(() => validateTurnUrl(value)).toThrow();
    });
    test('rejects credential, path, query and malformed host injection', () => {
        for (const value of [
            'https://relay.example:3478', 'turn://relay.example:3478', 'turn:user@relay.example:3478',
            'turn:relay.example:3478/path', 'turn:relay.example:3478#fragment',
            'turn:relay.example:3478?transport=udp&password=x', 'turn:relay.example:3478?transport=udp?transport=tcp',
            'turn:relay.example:3478\n', 'turn:relay example:3478', 'turn:relay%2eexample:3478',
            'turn:[no-ip]:3478', 'turn:2001:db8::1:3478', 'turn:999.0.0.1:3478',
            'turn:-relay.example:3478', 'turn:relay..example:3478', `turn:${'x'.repeat(64)}.example:3478`,
        ]) expect(() => validateTurnUrl(value)).toThrow();
    });
});
