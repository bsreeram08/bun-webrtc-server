import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const source = readFileSync(new URL('../../packages/signaling/public/emoji.js', import.meta.url), 'utf8');
const table = JSON.parse(readFileSync(new URL('../../packages/signaling/public/emoji-data.json', import.meta.url), 'utf8'));
async function load() {
    const context: Record<string, any> = { Intl, setTimeout: () => 0, fetch: async () => ({ ok: true, json: async () => table }) };
    context.window = context;
    runInNewContext(source, context);
    await context.Emoji.load();
    return context.Emoji;
}
const sha = 'a'.repeat(64);

describe('emoji shortcodes', () => {
    test('the vendored table is gemoji-sized and small', () => {
        expect(Object.keys(table).length).toBeGreaterThan(1800);
        expect(readFileSync(new URL('../../packages/signaling/public/emoji-data.json', import.meta.url)).byteLength).toBeLessThan(80 * 1024);
        expect(table.smile).toBe('😄');
        expect(table['+1']).toBe('👍');
    });
    test('standard shortcodes convert on send; custom and unknown ones stay as typed', async () => {
        const Emoji = await load();
        Emoji.setCustom([{ name: 'party_parrot', url: `/emoji/${sha}.gif`, animated: true }]);
        expect(Emoji.expand('hi :smile: and :+1: :party_parrot: :nope_nope: 10:30:')).toBe('hi 😄 and 👍 :party_parrot: :nope_nope: 10:30:');
    });
    test('custom pack entries must be same-origin /emoji/ images', async () => {
        const Emoji = await load();
        Emoji.setCustom([{ name: 'ok_one', url: `/emoji/${sha}.png` }, { name: 'evil', url: 'https://evil.example/x.png' }, { name: 'svg', url: `/emoji/${sha}.svg` }, { name: 'X', url: `/emoji/${sha}.png` }]);
        expect([...Emoji.custom.keys()]).toEqual(['ok_one']);
    });
    test('sizes: one custom emoji is a sticker, 1–3 emoji are big, anything with text is normal', async () => {
        const Emoji = await load();
        Emoji.setCustom([{ name: 'parrot', url: `/emoji/${sha}.gif`, animated: true }]);
        expect(Emoji.size(':parrot:')).toBe('sticker');
        expect(Emoji.size(' :parrot: ')).toBe('sticker');
        expect(Emoji.size('😄')).toBe('big');
        expect(Emoji.size('👍🏽🇮🇳 :parrot:')).toBe('big');
        expect(Emoji.size('😄😄😄😄')).toBe('');
        expect(Emoji.size('hi 😄')).toBe('');
        expect(Emoji.size(':unknown:')).toBe('');
        expect(Emoji.tokens('a :parrot: b')).toEqual([{ text: 'a ' }, { custom: 'parrot' }, { text: ' b' }]);
    });
    test('autocomplete offers custom emoji first, then standard names by prefix', async () => {
        const Emoji = await load();
        Emoji.setCustom([{ name: 'party_parrot', url: `/emoji/${sha}.gif` }]);
        const list = Emoji.suggestions('par');
        expect(list[0]).toEqual({ name: 'party_parrot', custom: true, url: `/emoji/${sha}.gif` });
        expect(list.some((entry: any) => entry.name === 'partying_face' && entry.emoji === '🥳')).toBe(true);
        expect(list.length).toBeLessThanOrEqual(8);
    });
});
