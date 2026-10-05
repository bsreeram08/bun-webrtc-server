import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const source = readFileSync(new URL('../../packages/signaling/public/sw.js', import.meta.url), 'utf8');
function pushWorker() {
    const handlers: Record<string, (event: any) => void> = {}, shown: [string, any][] = [], requests: { url: string; init: any }[] = [], messages: any[] = [], opened: string[] = [];
    let focused = 0, windows: any[] = [];
    runInNewContext(source, {
        URL, URLSearchParams, JSON,
        self: {
            location: { origin: 'https://calls.example' }, addEventListener: (name: string, handler: any) => { handlers[name] = handler; },
            registration: { showNotification: async (title: string, options: any) => { shown.push([title, options]); } },
            clients: { matchAll: async () => windows, openWindow: async (url: string) => { opened.push(url); } },
        },
        caches: { open: async () => ({}) }, fetch: async (url: string, init: any) => { requests.push({ url, init }); return new Response('{}'); },
    });
    const dispatch = async (name: string, event: any) => { let work: Promise<unknown> | undefined; handlers[name]!({ ...event, waitUntil(value: Promise<unknown>) { work = value; } }); await work; };
    return {
        shown, requests, messages, opened, get focused() { return focused; },
        withWindow() { windows = [{ url: 'https://calls.example/', postMessage: (value: any) => messages.push(value), focus: async () => { focused++; } }]; },
        push: (data: unknown) => dispatch('push', { data: { json: () => { if (data === 'bad') throw new Error('bad'); return data; } } }),
        click: (data: unknown, action = '') => dispatch('notificationclick', { action, notification: { data, close() {} } }),
    };
}

describe('push notifications in the service worker', () => {
    test('messages and calls show sender-only notifications; calls ring until answered', async () => {
        const sw = pushWorker();
        await sw.push({ type: 'message', from: 'alice', text: 'never shown' });
        await sw.push({ type: 'call', from: 'alice', kind: 'video', roomId: 'r'.repeat(43) });
        await sw.push({ type: 'missed', from: 'alice', kind: 'voice' });
        expect(sw.shown[0]![0]).toBe('New message from alice');
        expect(JSON.stringify(sw.shown[0])).not.toContain('never shown');
        expect(sw.shown[0]![1]).toMatchObject({ tag: 'message-alice', data: { open: 'alice' } });
        expect(sw.shown[1]![0]).toBe('Incoming video call from alice');
        expect(sw.shown[1]![1]).toMatchObject({ tag: 'call-alice', renotify: true, requireInteraction: true, data: { open: 'alice', call: 'video', roomId: 'r'.repeat(43) } });
        expect(sw.shown[1]![1].actions.map((action: any) => action.action)).toEqual(['open', 'decline']);
        expect(sw.shown[2]).toEqual(['Missed voice call from alice', expect.objectContaining({ tag: 'call-alice' })]);
    });
    test('malformed pushes still show a generic notification without echoing input', async () => {
        const sw = pushWorker();
        await sw.push('bad');
        await sw.push({ type: 'message', from: '<img src=x>' });
        expect(sw.shown.map(([title]) => title)).toEqual(['Private conversations', 'Private conversations']);
        expect(JSON.stringify(sw.shown)).not.toContain('<img');
    });
    test('tapping opens the conversation by username only and never answers; decline routes to the server', async () => {
        const sw = pushWorker();
        await sw.click({ open: 'alice' });
        await sw.click({ open: 'alice', call: 'video', roomId: 'r'.repeat(43) }, 'open');
        expect(sw.opened).toEqual(['/#open=alice', '/#open=alice&call=video']);
        await sw.click({ open: 'alice', call: 'voice', roomId: 'r'.repeat(43) }, 'decline');
        expect(sw.requests).toEqual([{ url: '/api/conversations/alice/decline', init: expect.objectContaining({ method: 'POST', body: JSON.stringify({ roomId: 'r'.repeat(43) }) }) }]);
        await sw.click({ open: '../rooms' });
        expect(sw.opened).toHaveLength(2);
        sw.withWindow();
        await sw.click({ open: 'bob', call: 'voice' }, 'open');
        expect(sw.messages).toEqual([{ type: 'open', user: 'bob', call: 'voice' }]);
        expect(sw.focused).toBe(1);
    });
});
