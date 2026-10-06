import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const source = readFileSync(new URL('../../packages/signaling/public/theme.js', import.meta.url), 'utf8');
/** Runs theme.js against a minimal DOM; returns its API and the CSS variables it set. */
function load(stored: Record<string, string> = {}) {
    const elements = new Map<string, any>(), vars = new Map<string, string>();
    const element = (id: string): any => {
        if (!elements.has(id)) elements.set(id, { id, dataset: {}, style: { setProperty() {} }, addEventListener() {}, closest: () => element(`${id}-parent`), querySelector: () => null, value: 'off', children: [] });
        return elements.get(id);
    };
    const context: any = {
        document: { getElementById: element, documentElement: { dataset: {}, style: { setProperty: (key: string, value: string) => vars.set(key, value) } }, querySelector: () => null, addEventListener() {} },
        localStorage: { getItem: (key: string) => stored[key] ?? null, setItem: (key: string, value: string) => { stored[key] = value; } },
        requestAnimationFrame: (callback: () => void) => callback(),
    };
    context.window = context;
    runInNewContext(source, context);
    return { Theme: context.Theme, vars, element, stored };
}

describe('themes', () => {
    test('every preset with any accent keeps bubble text and button text readable (WCAG AA)', () => {
        const { Theme } = load();
        for (const preset of Object.keys(Theme.PRESETS)) for (const accent of [null, '#ff8a3d', '#ffe600', '#2040ff', '#ffffff', '#000000', '#7f7f7f']) {
            const tokens = Theme.tokens(preset, accent);
            expect(Theme.contrast(tokens.mine, tokens['mine-text'])).toBeGreaterThanOrEqual(4.5);
            expect(Theme.contrast(tokens.theirs, tokens['theirs-text'])).toBeGreaterThanOrEqual(4.5);
            expect(Theme.contrast(tokens.accent, tokens['accent-ink'])).toBeGreaterThanOrEqual(4.5);
        }
    });
    test('stored preferences are sanitised: unknown presets, colours and wallpapers are ignored', () => {
        const { Theme, vars, element } = load({ 'theme-v1:guest': JSON.stringify({ app: { preset: 'nope', accent: 'red;}body{display:none', wallpaper: 'url(//evil)' }, chats: { 'x"y': { preset: 'light' } } }) });
        expect(vars.get('--bg')).toBe(Theme.PRESETS.midnight.bg);
        expect(vars.get('--accent')).toBe(Theme.PRESETS.midnight.accent);
        expect(element('app').dataset.wallpaper).toBe('none');
    });
    test('a chat override applies only to that conversation, per account', () => {
        const stored = { 'theme-v1:alice': JSON.stringify({ app: { preset: 'fsociety' }, chats: { 'pair:abc': { preset: 'light', wallpaper: 'grid' } } }) };
        const { Theme, vars, element } = load(stored);
        Theme.setAccount('alice');
        expect(vars.get('--bg')).toBe(Theme.PRESETS.fsociety.bg);
        Theme.use('pair:abc');
        expect(vars.get('--bg')).toBe(Theme.PRESETS.light.bg);
        expect(element('app').dataset.wallpaper).toBe('grid');
        Theme.use('pair:other');
        expect(vars.get('--bg')).toBe(Theme.PRESETS.fsociety.bg);
        expect(element('app').dataset.wallpaper).toBe('circuit');
        Theme.setAccount(null);
        expect(vars.get('--bg')).toBe(Theme.PRESETS.midnight.bg);
    });
});
