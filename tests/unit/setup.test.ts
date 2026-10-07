import { expect, test } from 'bun:test';
import { mkdtemp, readFile, stat, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { configuration, setup } from '../../scripts/setup';

const args = ['calls.example.com', 'turn.example.com', '203.0.113.10', 'admin@example.com'];

test('configuration uses independent secrets and shares only the TURN secret with coturn', () => {
    const config = configuration(args);
    const env = Object.fromEntries(config.env.trim().split('\n').map(line => line.split('=')));
    expect(env.ADMIN_TOKEN).toMatch(/^[a-f0-9]{64}$/);
    expect(env.TURN_SECRET).toMatch(/^[a-f0-9]{64}$/);
    expect(env.ADMIN_TOKEN).not.toBe(env.TURN_SECRET);
    expect(config.turn).toContain(`static-auth-secret=${env.TURN_SECRET}\n`);
    expect(config.turn).not.toContain(env.ADMIN_TOKEN!);
    expect(config.turn).toContain('relay-ip=203.0.113.10\n');
    expect(config.turn).toContain('external-ip=203.0.113.10\n');
    const nat = configuration([...args, '10.0.0.2']);
    expect(nat.turn).toContain('relay-ip=10.0.0.2\n');
    expect(nat.turn).toContain('external-ip=203.0.113.10/10.0.0.2\n');
    expect(() => configuration([...args, 'invalid'])).toThrow();
    expect(() => configuration(['example.com\nno-auth', ...args.slice(1)])).toThrow();
});

test('setup refuses overwrites and protects secret permissions', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'webrtc-setup-'));
    try {
        await setup(args, directory);
        const initial = await readFile(join(directory, '.env'), 'utf8');
        expect((await stat(join(directory, '.env'))).mode & 0o777).toBe(0o600);
        expect((await stat(join(directory, 'turnserver.conf'))).mode & 0o777).toBe(0o600);
        await expect(setup(args, directory)).rejects.toThrow();
        expect(await readFile(join(directory, '.env'), 'utf8')).toBe(initial);
        await rm(join(directory, '.env'));
        await writeFile(join(directory, 'turnserver.conf'), 'preserve existing TURN configuration');
        await expect(setup(args, directory)).rejects.toThrow();
        expect(await readFile(join(directory, 'turnserver.conf'), 'utf8')).toBe('preserve existing TURN configuration');
        expect(await Bun.file(join(directory, '.env')).exists()).toBe(false);
    } finally { await rm(directory, { recursive: true, force: true }); }
});
