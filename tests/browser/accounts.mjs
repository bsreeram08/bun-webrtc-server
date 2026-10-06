// End-to-end accounts check: passkey sign-up via invite, contacts, presence, Signal-protocol messages
// through the encrypted mailbox (online, offline, reordered, duplicated), safety numbers, key changes,
// burn, a video call accepted from the incoming sheet, sign-out and passkey sign-in.
// Uses Chromium's virtual authenticator.
// Starts its own signaling server on a throwaway DATA_DIR. Usage: node tests/browser/accounts.mjs
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';

const root = resolve(import.meta.dirname, '../..');
const playwright = await import(process.env.PLAYWRIGHT_MODULE || 'playwright-core');
const port = Number(process.env.TEST_PORT || 3127), origin = `http://localhost:${port}`;
const dataDir = process.env.DATA_DIR || mkdtempSync(join(tmpdir(), 'accounts-e2e-'));
const shots = process.env.SCREENSHOT_DIR;
const env = { ...process.env, PORT: String(port), ADMIN_TOKEN: randomBytes(32).toString('hex'), PUBLIC_ORIGIN: origin, DATA_DIR: dataDir };
const server = spawn('bun', ['--no-env-file', 'packages/signaling/server.ts'], { cwd: root, env, stdio: ['ignore', 'pipe', 'inherit'] });
process.on('exit', () => server.kill());
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => process.exit(1));
await new Promise((ok, fail) => { server.stdout.on('data', chunk => String(chunk).includes('listening') && ok()); server.on('exit', code => fail(new Error(`server exited ${code}`))); setTimeout(() => fail(new Error('server did not start')), 10000); });
const browser = await playwright.chromium.launch({ executablePath: process.env.BROWSER_EXECUTABLE, args: ['--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream'] });
const step = name => console.log(`✓ ${name}`);
const pages = [];
const diagnose = () => Promise.all(pages.map(page => page.evaluate(() => ({ auth: document.body.dataset.auth, screen: document.body.dataset.screen, state: document.body.dataset.state, status: document.getElementById('status').textContent, chat: document.getElementById('chat-status').textContent, verify: document.getElementById('verify-label').textContent, requests: Object.entries(performance.getEntriesByType('resource').reduce((all, entry) => { const key = new URL(entry.name).pathname.replace(/[A-Za-z0-9_-]{43}/, ':id'); all[key] = (all[key] || 0) + 1; return all; }, {})) })).catch(error => error.message)));
const shot = async (page, name) => { if (shots) await page.screenshot({ path: join(shots, `${name.startsWith('e2e-') ? '' : 'acct-'}${name}.png`) }); };
const logText = page => page.textContent('#chat-log');
const count = (text, needle) => text.split(needle).length - 1;
const serverBytes = () => Buffer.concat(readdirSync(dataDir).map(name => readFileSync(join(dataDir, name)))).toString('latin1');

async function person() {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
  await context.grantPermissions(['camera', 'microphone'], { origin });
  const page = await context.newPage(); pages.push(page);
  page.on('pageerror', error => { throw error; }); page.on('console', message => { if (message.text().includes('JOINDEBUG')) console.log(message.text()); });
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  return page;
}
const visible = (page, selector) => page.locator(selector).waitFor({ state: 'visible', timeout: 15000 });
const code = page => page.waitForFunction(() => /^\d{3} \d{3}$/.test(document.getElementById('verify-digits').textContent), null, { timeout: 30000 }).then(() => page.textContent('#verify-digits'));
async function register(page, invite, username) {
  await page.goto(`${origin}/#invite=${invite}`);
  await visible(page, '#welcome');
  if (await page.locator('#register-invite').inputValue() !== invite) throw new Error('Invite link did not prefill the code');
  await page.fill('#register-username', username);
  await page.click('#register-submit');
  await visible(page, '#chats');
  if ((await page.textContent('#me-name')) !== `@${username}`) throw new Error('Wrong signed-in user');
}

try {
  const bootstrap = spawnSync('bun', ['--no-env-file', 'scripts/create-invite.ts'], { cwd: root, env, encoding: 'utf8' });
  const firstInvite = /Invite code: (\S+)/.exec(bootstrap.stdout)?.[1];
  if (!firstInvite) throw new Error(`create-invite failed: ${bootstrap.stderr}`);
  const alice = await person(), bob = await person();
  await alice.goto(origin); await visible(alice, '#welcome'); await shot(alice, '1-welcome');
  await register(alice, firstInvite, 'alice'); step('alice registered with a passkey from the CLI invite');

  await alice.click('#account-menu summary'); await alice.click('#invite-create');
  await visible(alice, '#invite-result');
  const link = await alice.inputValue('#invite-link');
  await register(bob, new URL(link).hash.slice('#invite='.length), 'bob'); step('bob registered with an invite alice created in the app');

  await alice.fill('#contact-input', 'bob'); await alice.click('#contact-add');
  await bob.getByRole('button', { name: 'Accept' }).click({ timeout: 15000 });
  await alice.waitForFunction(() => document.querySelector('#contact-list .contact.mutual .avatar')?.dataset.online === 'true', null, { timeout: 15000 });
  step('contact request accepted; presence shows bob online');

  // Bob is online but has not opened the conversation: the message arrives at once, encrypted.
  await alice.click('#contact-list .contact.mutual .row-button');
  await visible(alice, '#conv-head');
  await alice.fill('#chat-input', 'hi bob, sealed end to end'); await alice.click('#chat-send');
  await alice.waitForFunction(() => document.querySelector('#chat-log li.outgoing')?.dataset.status === 'delivered', null, { timeout: 15000 });
  await bob.waitForFunction(() => document.querySelector('#contact-list .badge')?.textContent === '1', null, { timeout: 15000 });
  await shot(bob, 'e2e-1-list-unread');
  await bob.click('#contact-list .contact.mutual .row-button');
  await bob.waitForFunction(() => document.getElementById('chat-log').textContent.includes('sealed end to end'), null, { timeout: 15000 });
  await bob.fill('#chat-input', 'got it 👋'); await bob.click('#chat-send');
  await alice.waitForFunction(() => document.getElementById('chat-log').textContent.includes('got it'), null, { timeout: 15000 });
  await shot(alice, '3-conversation'); step('encrypted message delivered live with an unread badge, reply received, ✓✓ after the receipt');

  // Safety numbers: both devices compute the same 60 digits.
  const safety = async page => { await page.click('#conv-menu summary'); await page.click('#conv-safety'); await visible(page, '#safety'); return page.textContent('#safety-number'); };
  const [codeA, codeB] = [await safety(alice), await safety(bob)];
  if (!/^(\d{5} ){11}\d{5}$/.test(codeA) || codeA !== codeB) throw new Error(`Safety numbers differ: ${codeA} / ${codeB}`);
  await shot(alice, 'e2e-2-safety');
  await alice.click('#safety-verify'); await bob.click('#safety-close');
  step('safety numbers match on both devices; alice marked bob verified');

  // Offline delivery: bob signs out; the envelope waits on the server, which cannot read it.
  await bob.click('#conv-back'); await bob.click('#account-menu summary'); await bob.click('#signout'); await visible(bob, '#welcome');
  const marker = `offline-marker-${randomBytes(6).toString('hex')}`;
  await alice.fill('#chat-input', `while you were away ${marker}`); await alice.click('#chat-send');
  await alice.waitForFunction(() => [...document.querySelectorAll('#chat-log li.outgoing')].at(-1)?.dataset.status === 'sent', null, { timeout: 15000 });
  if (serverBytes().includes(marker)) throw new Error('Plaintext reached the server database');
  await bob.click('#signin'); await visible(bob, '#chats');
  await bob.click('#contact-list .contact.mutual .row-button');
  await bob.waitForFunction(m => document.getElementById('chat-log').textContent.includes(m), marker, { timeout: 15000 });
  await alice.waitForFunction(() => [...document.querySelectorAll('#chat-log li.outgoing')].at(-1)?.dataset.status === 'delivered', null, { timeout: 15000 });
  if (serverBytes().includes(marker)) throw new Error('Plaintext reached the server database');
  step('message sent while bob was signed out arrived decrypted after he signed in; the server database never held the text');

  // Reordered and duplicated envelopes: hold two posts, deliver them backwards and twice.
  await alice.evaluate(() => { const real = window.fetch; window.__held = []; window.__real = real; window.fetch = (url, init) => window.__hold && url === '/api/messages' ? (window.__held.push(init.body), Promise.resolve(new Response(JSON.stringify({ id: 'held', createdAt: Date.now() }), { status: 201, headers: { 'Content-Type': 'application/json' } }))) : real(url, init); window.__hold = true; });
  for (const text of ['order-one', 'order-two']) { await alice.fill('#chat-input', text); await alice.click('#chat-send'); }
  await alice.waitForFunction(() => window.__held.length === 2, null, { timeout: 10000 });
  await alice.evaluate(async () => { window.__hold = false; for (const body of [window.__held[1], window.__held[0], window.__held[0], window.__held[1]]) await window.__real('/api/messages', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body }); });
  await bob.waitForFunction(() => { const text = document.getElementById('chat-log').textContent; return text.includes('order-one') && text.includes('order-two'); }, null, { timeout: 15000 });
  await bob.waitForTimeout(500);
  const bobLog = await logText(bob);
  if (count(bobLog, 'order-one') !== 1 || count(bobLog, 'order-two') !== 1 || bobLog.indexOf('order-one') > bobLog.indexOf('order-two')) throw new Error(`Reordered/duplicated delivery broke the transcript: ${bobLog}`);
  if (/could not be decrypted/.test(await bob.textContent('#chats-status') + await bob.textContent('#chat-status'))) throw new Error('A duplicate was reported as undecryptable');
  await bob.fill('#chat-input', 'still in sync'); await bob.click('#chat-send');
  await alice.waitForFunction(() => document.getElementById('chat-log').textContent.includes('still in sync'), null, { timeout: 15000 });
  step('out-of-order and duplicated envelopes were shown once each, in order, and the ratchet kept working');

  // Key change: bob's device loses its keys (a reinstall). Alice verified him, so sending pauses.
  await bob.evaluate(async () => { const id = (await (await fetch('/api/me')).json()).user.id; await new Promise(done => { const request = indexedDB.deleteDatabase(`webrtc-bun-signal-v1-${id}`); request.onsuccess = request.onerror = request.onblocked = done; }); });
  await bob.reload(); await visible(bob, '#chats');
  // A device with new keys never takes over silently: it stays inactive until bob chooses it.
  await bob.waitForFunction(() => !document.getElementById('device-banner').hidden, null, { timeout: 15000 });
  await bob.click('#device-takeover');
  await bob.waitForFunction(() => document.getElementById('device-banner').hidden, null, { timeout: 15000 });
  step('a device with new keys stayed inactive until the user moved messaging to it');
  await alice.waitForFunction(() => !document.getElementById('key-banner').hidden, null, { timeout: 15000 });
  if (!(await alice.textContent('#key-banner-text')).includes('Sending is paused')) throw new Error('Verified contact was not blocked after a key change');
  await shot(alice, 'e2e-3-key-change');
  // Before alice accepts the new code, the new identity cannot burn her history.
  await bob.click('#contact-list .contact.mutual .row-button');
  await bob.click('#conv-menu summary'); await bob.click('#conv-burn'); await visible(bob, '#burn-confirm'); await bob.click('#burn-confirm-yes');
  await bob.waitForFunction(() => /Burned on this device/.test(document.getElementById('chat-status').textContent), null, { timeout: 15000 });
  await alice.waitForTimeout(2000);
  if (!(await logText(alice)).includes('sealed end to end')) throw new Error('An unaccepted identity burned the conversation');
  await bob.click('#conv-back');
  step('a burn from the unaccepted new identity was ignored');
  await alice.click('#key-banner-review'); await visible(alice, '#safety');
  if ((await alice.textContent('#safety-number')) === codeA) throw new Error('Safety number did not change');
  await alice.click('#safety-accept');
  await alice.fill('#chat-input', 'hello new device'); await alice.click('#chat-send');
  await bob.click('#contact-list .contact.mutual .row-button');
  await bob.waitForFunction(() => document.getElementById('chat-log').textContent.includes('hello new device'), null, { timeout: 15000 });
  step('a new identity raised the security-code banner, paused sending to the verified contact, and messaging resumed after review');

  // Burn through the mailbox: both copies go.
  await alice.click('#conv-menu summary'); await alice.click('#conv-burn'); await visible(alice, '#burn-confirm'); await alice.click('#burn-confirm-yes');
  await bob.waitForFunction(() => !document.getElementById('chat-log').textContent.includes('hello new device'), null, { timeout: 15000 });
  if ((await logText(alice)).includes('hello new device')) throw new Error('Burn left the local copy');
  step('burn deleted the conversation on both devices through an encrypted control message');

  await alice.click('#conv-back'); await visible(alice, '#chats');
  await alice.waitForFunction(() => document.querySelector('#contact-list .contact.mutual'), null, { timeout: 10000 });
  await shot(alice, '2-list');
  await bob.click('#conv-back');

  await alice.click('#contact-list .contact.mutual .row-button');
  await alice.click('#conv-video');
  await visible(bob, '#incoming'); await shot(bob, '4-incoming');
  await bob.click('#incoming-accept');
  const [callA, callB] = await Promise.all([code(alice), code(bob)]);
  if (callA !== callB) throw new Error('Call verification codes differ');
  await alice.waitForFunction(() => document.getElementById('app').dataset.state === 'call' && document.getElementById('status').textContent.includes('live'), null, { timeout: 30000 });
  await shot(alice, '5-call'); step(`video call accepted from the incoming sheet; matching code ${callA}`);
  await alice.click('#hangup');
  await bob.waitForFunction(() => document.getElementById('app').dataset.state !== 'call', null, { timeout: 15000 });
  step('hangup ended the call on both sides');

  await alice.click('#conv-back');
  await alice.click('#account-menu summary'); await alice.click('#signout');
  await visible(alice, '#welcome');
  if ((await alice.evaluate(() => fetch('/api/me').then(response => response.status))) !== 401) throw new Error('Session survived sign-out');
  await alice.click('#signin'); await visible(alice, '#chats');
  if ((await alice.textContent('#me-name')) !== '@alice') throw new Error('Passkey sign-in returned the wrong user');
  step('signed out, then back in with the passkey');
  console.log('Accounts end-to-end check passed.');
} catch (error) {
  console.error('Page state:', JSON.stringify(await diagnose(), null, 1));
  throw error;
} finally {
  await browser.close().catch(() => {});
  server.kill();
  if (!process.env.DATA_DIR) rmSync(dataDir, { recursive: true, force: true });
}
