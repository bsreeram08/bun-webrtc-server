import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const source = readFileSync(new URL('../../packages/signaling/public/commands.js', import.meta.url), 'utf8');
function load() {
    const context: Record<string, any> = { Date, Event: class { constructor(public type: string) {} } };
    context.window = context;
    runInNewContext(source, context);
    return context.Commands;
}
/** A command context that records what commands asked for. */
function chat(where = 'account') {
    const calls: any[] = [];
    return {
        calls,
        context: {
            where, active: false,
            send: (message: any) => { calls.push(['send', message]); },
            press: (id: string) => { calls.push(['press', id]); },
            setTimer: (value: string) => { calls.push(['timer', value]); },
            setTheme: (name: string) => { calls.push(['theme', name]); return name === 'fsociety'; },
            notice: (text: string) => { calls.push(['notice', text]); },
            confirm: async () => true,
            clearChat: async () => { calls.push(['clear']); },
            remind: (at: number, text: string) => { calls.push(['remind', at, text]); },
            showHelp: () => { calls.push(['help']); },
            compose: (text: string) => { calls.push(['compose', text]); },
        },
    };
}

describe('slash command parsing', () => {
    test('parses names and quoted arguments; //text and plain text are not commands', () => {
        const Commands = load();
        expect(Commands.parse('/poll "Lunch?" "Pizza place" \'Sushi\' “Tacos”')).toEqual({ name: 'poll', args: ['Lunch?', 'Pizza place', 'Sushi', 'Tacos'], rest: '"Lunch?" "Pizza place" \'Sushi\' “Tacos”' });
        expect(Commands.parse('/ME waves hello')).toEqual({ name: 'me', args: ['waves', 'hello'], rest: 'waves hello' });
        expect(Commands.parse('//not a command')).toBeNull();
        expect(Commands.parse('hello /me')).toBeNull();
        expect(Commands.parse('/')).toEqual({ name: '', args: [], rest: '' });
    });
    test('reminder times: spans, clock times and tomorrow, within 30 days', () => {
        const Commands = load(), now = new Date(2026, 9, 6, 10, 0, 0);
        expect(Commands.parseWhen(['in', '10m', 'tea'], now)).toEqual({ at: now.getTime() + 600000, text: 'tea' });
        expect(Commands.parseWhen(['2h', 'call', 'mum'], now)).toEqual({ at: now.getTime() + 7200000, text: 'call mum' });
        expect(new Date(Commands.parseWhen(['tomorrow', '9am', 'standup'], now).at).getDate()).toBe(7);
        expect(new Date(Commands.parseWhen(['9:30', 'x'], now).at).getDate()).toBe(7); // Already past today.
        expect(new Date(Commands.parseWhen(['5pm', 'x'], now).at).getHours()).toBe(17);
        expect(Commands.parseWhen(['31d', 'too', 'far'], now)).toBeNull();
        expect(Commands.parseWhen(['soon', 'x'], now)).toBeNull();
        expect(Commands.parseWhen(['25:00', 'x'], now)).toBeNull();
    });
});

describe('slash command registry', () => {
    test('unknown and unavailable commands are refused, never sent', async () => {
        const Commands = load(), { calls, context } = chat('guest');
        expect((await Commands.run('/nope', context)).error).toContain('Unknown command /nope');
        expect((await Commands.run('/call', context)).error).toContain('not available');
        expect(calls).toEqual([]);
    });
    test('availability follows the conversation type', () => {
        const Commands = load(), names = (where: string) => Commands.list(chat(where).context).map((command: any) => command.name);
        expect(names('account')).toEqual(expect.arrayContaining(['call', 'video', 'reset', 'verify', 'poll', 'me', 'burn', 'emoji']));
        expect(names('guest')).not.toContain('call');
        expect(names('guest')).toContain('poll');
        expect(names('none')).toEqual(['help']);
        expect(Commands.suggestions('p', chat().context).map((command: any) => command.name)).toEqual(['poll']);
    });
    test('built-ins act only through the context', async () => {
        const Commands = load(), { calls, context } = chat();
        await Commands.run('/me waves', context);
        await Commands.run('/shrug fine', context);
        await Commands.run('/timer 24h', context);
        await Commands.run('/call', context);
        await Commands.run('/theme fsociety', context);
        await Commands.run('/clear', context);
        await Commands.run('/emoji party', context);
        expect(calls).toEqual(expect.arrayContaining([
            ['send', { text: 'waves', kind: 'action' }], ['send', { text: 'fine ¯\\_(ツ)_/¯' }], ['timer', '86400000'],
            ['press', 'conv-voice'], ['theme', 'fsociety'], ['clear'], ['compose', ':party'],
        ]));
        expect((await Commands.run('/me', context)).error).toBeTruthy();
        expect((await Commands.run('/timer forever', context)).error).toBeTruthy();
        expect((await Commands.run('/theme neon', context)).error).toContain('Unknown theme');
    });
    test('/poll builds a validated poll with a readable fallback', async () => {
        const Commands = load(), { calls, context } = chat();
        await Commands.run('/poll "Lunch?" "Pizza" "Sushi"', context);
        expect(calls[0]).toEqual(['send', { kind: 'poll', poll: { question: 'Lunch?', options: ['Pizza', 'Sushi'] }, text: '📊 Lunch?\n1. Pizza\n2. Sushi' }]);
        expect((await Commands.run('/poll "Only one" "A"', context)).error).toBeTruthy();
        expect((await Commands.run(`/poll Q ${Array.from({ length: 11 }, (_, index) => `o${index}`).join(' ')}`, context)).error).toContain('at most 10');
        expect((await Commands.run(`/poll Q a "${'x'.repeat(201)}"`, context)).error).toContain('200');
    });
    test('runtime registration: providers label their commands and cannot shadow others', async () => {
        const Commands = load(), { context } = chat();
        let ran = false;
        Commands.register({ name: 'deploy', description: 'Deploy', provider: 'bot:ci', run: () => { ran = true; } });
        expect(Commands.list(context).find((command: any) => command.name === 'deploy').provider).toBe('bot:ci');
        expect(() => Commands.register({ name: 'burn', provider: 'bot:evil', run: () => {} })).toThrow();
        expect(() => Commands.register({ name: 'Bad Name', run: () => {} })).toThrow();
        Commands.register({ name: 'deploy', description: 'Deploy v2', provider: 'bot:ci', run: () => { ran = true; } }); // Same provider may replace.
        await Commands.run('/deploy', context);
        expect(ran).toBe(true);
        Commands.unregister('deploy', 'bot:other');
        expect(Commands.suggestions('dep', context)).toHaveLength(1);
        Commands.unregister('deploy', 'bot:ci');
        expect(Commands.suggestions('dep', context)).toHaveLength(0);
    });
});
