import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { createContext, runInContext } from 'node:vm';

const source = readFileSync(new URL('../../packages/signaling/public/app.js', import.meta.url), 'utf8');
const invitation = { roomId: 'r'.repeat(43), token: 't'.repeat(43) };
const flush = async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); };

/** A browser event harness: execute the shipped script; observe DOM, capture and network effects. */
function browser(options: { offlineDelete?: boolean } = {}) {
    let now = 100000, timerId = 0, mediaRequests = 0;
    const timers = new Map<number, { due: number; callback: () => void }>();
    const events = new Map<string, () => void>();
    const elements = new Map<string, any>();
    const requests: { url: string; init: RequestInit }[] = [];
    const sockets: Socket[] = [];
    const history: string[] = [];
    function element(id: string) {
        if (!elements.has(id)) elements.set(id, {
            disabled: false, checked: false, hidden: true, srcObject: null, textContent: '',
            attributes: new Map<string, string>(), listeners: new Map<string, (event: unknown) => unknown>(),
            addEventListener(type: string, callback: (event: unknown) => unknown) { this.listeners.set(type, callback); },
            setAttribute(key: string, value: string) { this.attributes.set(key, value); },
            getAttribute(key: string) { return this.attributes.get(key); },
            play: () => Promise.resolve(),
        });
        return elements.get(id);
    }
    class Socket {
        static CONNECTING = 0; static OPEN = 1; static CLOSING = 2; static CLOSED = 3;
        readyState = Socket.CONNECTING;
        onopen?: () => void;
        onclose?: (event: { code: number }) => void;
        onmessage?: (event: { data: string }) => void;
        sent: unknown[] = [];
        constructor(readonly url: string, readonly protocols: string[]) { sockets.push(this); }
        close() { this.readyState = Socket.CLOSED; this.onclose?.({ code: 1006 }); }
        open() { this.readyState = Socket.OPEN; this.onopen?.(); }
        send(value: string) { this.sent.push(JSON.parse(value)); }
        receive(value: unknown) { this.onmessage?.({ data: JSON.stringify(value) }); }
    }
    const tracks = ['audio', 'video'].map(kind => ({
        kind, enabled: true, readyState: 'live', stopCount: 0,
        stop() { this.readyState = 'ended'; this.stopCount++; },
    }));
    const stream = {
        getTracks: () => tracks,
        getVideoTracks: () => tracks.filter(track => track.kind === 'video'),
        getAudioTracks: () => tracks.filter(track => track.kind === 'audio'),
    };
    let resolveMedia!: (value: typeof stream) => void;
    const media = new Promise<typeof stream>(resolve => { resolveMedia = resolve; });
    class FakeDate extends Date { static now() { return now; } }
    const peer = class {
        addTrack() {} close() {}
    };
    const context = createContext({
        URLSearchParams, Date: FakeDate, Promise, WebSocket: Socket, RTCPeerConnection: peer,
        AbortSignal: { timeout: () => new AbortController().signal },
        location: { hash: `#${new URLSearchParams(invitation)}`, pathname: '/', protocol: 'http:', host: 'localhost:3000' },
        history: { replaceState(_state: unknown, _title: string, path: string) { history.push(path); } },
        document: { getElementById: element },
        window: { isSecureContext: true, RTCPeerConnection: peer, addEventListener(type: string, callback: () => void) { events.set(type, callback); } },
        navigator: { mediaDevices: { getUserMedia() { mediaRequests++; return media; } } },
        fetch: async (url: string, init: RequestInit) => {
            requests.push({ url, init });
            if (init.method === 'DELETE' && options.offlineDelete) throw new Error('Offline');
            return { ok: true, status: 200, json: async () => ({ iceServers: [], iceTransportPolicy: 'all' }) };
        },
        setTimeout(callback: () => void, delay = 0) { const id = ++timerId; timers.set(id, { due: now + delay, callback }); return id; },
        clearTimeout(id: number) { timers.delete(id); },
    });
    runInContext(source, context, { filename: 'packages/signaling/public/app.js' });
    async function nextTimer() {
        const first = [...timers].sort((a, b) => a[1].due - b[1].due)[0];
        if (!first) return false;
        now = first[1].due; timers.delete(first[0]); first[1].callback(); await flush(); return true;
    }
    return {
        element, sockets, tracks, requests, history, timers, get elapsed() { return now - 100000; }, get mediaRequests() { return mediaRequests; },
        join: () => element('join-form').listeners.get('submit')({ preventDefault() {} }) as Promise<void>,
        emit: (type: string) => events.get(type)?.(), acquire: () => resolveMedia(stream),
        hangup: () => element('hangup').onclick() as Promise<void>, nextTimer,
        uiText: () => [...elements.values()].map(value => value.textContent).join('\n'),
    };
}

describe('browser capture and reconnect lifecycle', () => {
    test('online during a pending media permission prompt does not open signaling prematurely', async () => {
        const page = browser(); const joining = page.join(); await flush();
        expect(page.mediaRequests).toBe(1);
        page.emit('online'); await flush();
        expect(page.sockets).toHaveLength(0);
        expect(page.timers.size).toBe(0);
        page.acquire(); await joining;
        expect(page.sockets).toHaveLength(1);
        page.sockets[0].open();
        page.sockets[0].receive({ type: 'welcome', polite: false });
        page.sockets[0].receive({ type: 'ready', sessionId: 's'.repeat(43) });
        await flush();
        expect(page.element('status').textContent).toContain('Connecting to the other participant');
        expect(page.tracks.every(track => track.readyState === 'live')).toBe(true);
        page.emit('pagehide');
    });

    for (const stop of ['hangup', 'pagehide'] as const) {
        test(`media acquired after ${stop} is stopped without opening a socket`, async () => {
            const page = browser(); const joining = page.join(); await flush();
            if (stop === 'hangup') await page.hangup(); else page.emit('pagehide');
            page.acquire(); await joining;
            expect(page.tracks.map(track => track.stopCount)).toEqual([1, 1]);
            expect(page.element('local').srcObject).toBeNull();
            expect(page.sockets).toHaveLength(0);
            page.emit('online'); await flush();
            expect(page.timers.size).toBe(0);
        });
    }

    test('stalled handshakes retry with bounded lifetime and finally stop capture', async () => {
        const page = browser(); page.acquire(); await page.join();
        expect(page.sockets).toHaveLength(1);
        expect(page.sockets[0].readyState).toBe(0);
        await page.nextTimer();
        expect(page.elapsed).toBe(10000);
        expect(page.sockets[0].readyState).toBe(3);
        expect(page.element('status').textContent).toContain('Reconnecting');
        // Each watchdog and retry must eventually terminate; no wall-clock sleeps.
        for (let steps = 0; steps < 40 && await page.nextTimer(); steps++) {}
        expect(page.sockets.length).toBeGreaterThan(1);
        expect(page.sockets.length).toBeLessThanOrEqual(10);
        expect(page.elapsed).toBeLessThanOrEqual(120000);
        expect(page.sockets.every(socket => socket.readyState === 3)).toBe(true);
        expect(page.timers.size).toBe(0);
        expect(page.tracks.map(track => track.stopCount)).toEqual([1, 1]);
        expect(page.element('local').srcObject).toBeNull();
        expect(page.element('status').textContent).toContain('Unable to reconnect');
        page.emit('online'); await flush();
        expect(page.timers.size).toBe(0);
    });

    test('an opened socket cancels its handshake deadline and duplicate online events do not open another', async () => {
        const page = browser(); page.acquire(); await page.join();
        page.sockets[0].open();
        page.emit('online'); page.emit('online'); await flush();
        expect(page.sockets).toHaveLength(1);
        expect(page.timers.size).toBe(0);
        expect(page.tracks.every(track => track.readyState === 'live')).toBe(true);
        page.emit('pagehide');
    });

    test('offline hangup stops capture immediately and never claims room revocation or exposes the token', async () => {
        const page = browser({ offlineDelete: true }); page.acquire(); await page.join();
        const ending = page.hangup();
        expect(page.tracks.every(track => track.readyState === 'ended')).toBe(true);
        await ending;
        expect(page.element('status').textContent).toContain('Could not end the room while offline');
        expect(page.history).toEqual(['/']);
        expect(page.uiText()).not.toContain(invitation.token);
        expect(page.uiText()).not.toContain(invitation.roomId);
        expect(page.requests.every(request => !request.url.includes(invitation.token))).toBe(true);
        expect(page.element('local').srcObject).toBeNull();
        expect(page.element('hangup').disabled).toBe(true);
        expect(page.timers.size).toBe(0);
    });
});
