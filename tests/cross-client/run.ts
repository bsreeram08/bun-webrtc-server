// Cross-client proof: the real web client (account.js + signal.js in Chromium) and the Flutter app's real
// crypto path (RustChatCrypto → crates/chatcore through flutter_rust_bridge, plus the app's Messenger, store,
// API client and events socket) talk through one local server.
//
//   bun tests/cross-client/run.ts
//
// Test-only bootstrap: both accounts and their sessions are created through the in-process server's
// `accounts.testing` helpers on a throwaway DATA_DIR (no passkeys needed); nothing here is reachable in
// production. Steps are synchronised with the Dart side through files in a temp dir.
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startSignaling } from '../../packages/signaling/server';

const root = join(dirname(fileURLToPath(import.meta.url)), '../..');
const appDir = join(root, 'apps/chat');
const sync = mkdtempSync(join(tmpdir(), 'cross-client-'));
const dataDir = join(sync, 'server');
const port = Number(process.env.TEST_PORT || 3191), origin = `http://localhost:${port}`;
let failed = false;
const step = (text: string) => console.log(`✓ ${text}`);

const build = spawnSync('cargo', ['build', '--quiet', '--manifest-path', join(appDir, 'rust/Cargo.toml')], { stdio: 'inherit' });
if (build.status !== 0) process.exit(1);
const dylib = join(appDir, 'rust/target/debug', process.platform === 'darwin' ? 'libchatcore_bridge.dylib' : 'libchatcore_bridge.so');

const app = startSignaling({ adminToken: 'x'.repeat(40), origin, hostname: '127.0.0.1', port, dataDir });
const testing = app.accounts!.testing;
const webUser = testing.createUser('webuser'), appUser = testing.createUser('appuser');
const cookie = testing.cookie(webUser.id), bearer = testing.bearer(appUser.id, 'ios');
const call = (path: string, init: RequestInit) => fetch(new URL(path, origin), init).then(async response => { if (!response.ok) throw new Error(`${path} → ${response.status} ${await response.text()}`); });
await call('/api/contacts', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: origin, Cookie: cookie }, body: JSON.stringify({ username: 'appuser' }) });
await call('/api/contacts/webuser/accept', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer}` }, body: '{}' });
step('two accounts (web and app) are mutual contacts');

const signal = (name: string, body = '') => writeFileSync(join(sync, `web-${name}`), body);
async function waitFor(name: string, timeout = 90000) {
    const file = join(sync, `app-${name}`), end = Date.now() + timeout;
    while (!existsSync(file)) { if (Date.now() > end || failed) throw new Error(`app never reached ${name}`); await Bun.sleep(100); }
    return readFileSync(file, 'utf8');
}

const dart = spawn('flutter', ['test', 'test/cross_client_test.dart', '--reporter', 'expanded'], {
    cwd: appDir, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, CROSS_BASE: origin, CROSS_TOKEN: bearer, CROSS_ME_ID: appUser.id, CROSS_ME_NAME: 'appuser', CROSS_PEER_ID: webUser.id, CROSS_PEER_NAME: 'webuser', CROSS_DIR: sync, CROSS_DYLIB: dylib },
});
let dartOutput = '';
dart.stdout.on('data', chunk => { dartOutput += chunk; });
dart.stderr.on('data', chunk => { dartOutput += chunk; });
const dartDone = new Promise<number>(resolve => dart.on('exit', code => { if (code) failed = true; resolve(code ?? 1); }));

const playwright = await import(process.env.PLAYWRIGHT_MODULE || 'playwright-core');
const browser = await playwright.chromium.launch();
const [name, value] = cookie.split('=');
async function webPage() {
    const context = await browser.newContext();
    await context.addCookies([{ name, value, url: origin }]);
    const page = await context.newPage();
    page.on('pageerror', (error: Error) => console.log(`  web pageerror: ${error.message}`));
    await page.goto(origin);
    await page.waitForSelector('#chats', { state: 'visible', timeout: 20000 });
    return { context, page };
}
const log = (page: any, text: string) => page.waitForFunction((t: string) => document.getElementById('chat-log').textContent.includes(t), text, { timeout: 45000 });

let code = 1;
try {
    await waitFor('ready');
    const { page } = await webPage();
    await page.click('#contact-list .contact.mutual .row-button');
    await page.fill('#chat-input', 'hello from web'); await page.click('#chat-send');
    signal('sent-1');
    await log(page, 'hello from app');
    await waitFor('sent-2');
    step('web → app and app → web messages decrypt (signal.js ↔ Rust core), with encrypted receipts');

    const appNumber = await waitFor('safety');
    await page.click('#conv-menu summary'); await page.click('#conv-safety');
    await page.waitForSelector('#safety', { state: 'visible' });
    const webNumber = (await page.textContent('#safety-number'))!.trim();
    await page.click('#safety-close');
    signal('safety-checked', webNumber === appNumber.trim() ? 'match' : 'mismatch');
    if (webNumber !== appNumber.trim()) throw new Error(`safety numbers differ: web ${webNumber} vs app ${appNumber}`);
    step(`safety numbers match on both clients (${webNumber.slice(0, 11)}…)`);

    await waitFor('reset-1');
    await log(page, 'Secure session reset by appuser'); await log(page, 'after app reset');
    step('a session reset started in the app is applied by the web client; messaging continues');

    await page.click('#conv-menu summary'); await page.click('#conv-rotate');
    await page.waitForSelector('#rotate-confirm', { state: 'visible' }); await page.click('#rotate-yes');
    await log(page, 'Secure session reset by you');
    await page.fill('#chat-input', 'after web reset'); await page.click('#chat-send');
    signal('reset-2');
    await waitFor('reset-2-ok');
    await log(page, 'reply on the new keys');
    step('a session reset started on the web is applied by the app (Rust core); messaging continues');

    // A second browser for the web account has no keys: it stays inactive and must not consume envelopes.
    const second = await webPage();
    await second.page.waitForFunction(() => !document.getElementById('device-banner').hidden, null, { timeout: 20000 });
    signal('second-device');
    await waitFor('sent-3');
    await log(page, 'for the active web device');
    const consumed = await second.page.evaluate(() => document.getElementById('chat-log')?.textContent?.includes('for the active web device') ?? false);
    if (consumed) throw new Error('the inactive device showed a message meant for the active one');
    await second.context.close();
    step('active-device rule: a second, inactive web browser leaves the app\'s message for the active one');

    await page.click('#conv-menu summary'); await page.click('#conv-burn');
    await page.waitForSelector('#burn-confirm', { state: 'visible' }); await page.click('#burn-confirm-yes');
    signal('burned');
    await waitFor('done');
    step('burn from the web deletes the conversation in the app');
    code = await dartDone;
    if (code !== 0) throw new Error('the app side failed');
    console.log('Cross-client check passed.');
} catch (error) {
    failed = true;
    console.log(`✗ ${(error as Error).message}`);
    dart.kill();
    await dartDone;
    console.log(dartOutput.split('\n').slice(-40).join('\n'));
    code = 1;
} finally {
    await browser.close();
    await app.stop();
    rmSync(sync, { recursive: true, force: true });
}
process.exit(code);
