// End-to-end accounts check: passkey sign-up via invite, contacts, presence, Signal-protocol messages
// through the encrypted mailbox (online, offline, reordered, duplicated), safety numbers, key changes,
// burn, slash commands (polls, /me, /timer, /verify, /reset), emoji shortcodes and custom emoji/stickers,
// a video call accepted from the incoming sheet, sign-out and passkey sign-in.
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
// CORE=wasm runs every step with the WebAssembly messaging core (core.js) instead of signal.js.
const wasm = process.env.CORE === 'wasm';
const keyDb = wasm ? 'webrtc-bun-core-v1-' : 'webrtc-bun-signal-v1-';
const pages = [];
const diagnose = () => Promise.all(pages.map(page => page.evaluate(() => ({ auth: document.body.dataset.auth, screen: document.body.dataset.screen, state: document.body.dataset.state, status: document.getElementById('status').textContent, chat: document.getElementById('chat-status').textContent, verify: document.getElementById('verify-label').textContent, requests: Object.entries(performance.getEntriesByType('resource').reduce((all, entry) => { const key = new URL(entry.name).pathname.replace(/[A-Za-z0-9_-]{43}/, ':id'); all[key] = (all[key] || 0) + 1; return all; }, {})) })).catch(error => error.message)));
const shot = async (page, name) => { if (shots) await page.screenshot({ path: join(shots, `${name.startsWith('e2e-') ? '' : 'acct-'}${name}.png`) }); };
const logText = page => page.textContent('#chat-log');
const count = (text, needle) => text.split(needle).length - 1;
const serverBytes = () => Buffer.concat(readdirSync(dataDir, { withFileTypes: true }).filter(entry => entry.isFile()).map(entry => readFileSync(join(dataDir, entry.name)))).toString('latin1');

async function person() {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
  await context.grantPermissions(['camera', 'microphone'], { origin });
  if (wasm) await context.addInitScript(() => localStorage.setItem('core-backend', 'wasm'));
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
  if (wasm) {
    // The keys must live in the WebAssembly core's sealed store, not signal.js's.
    const where = await alice.evaluate(async () => {
      const id = (await (await fetch('/api/me')).json()).user.id;
      const rows = name => new Promise(resolve => { const request = indexedDB.open(name); request.onsuccess = () => { const db = request.result; if (!db.objectStoreNames.contains('kv')) { db.close(); return resolve([]); } const all = db.transaction('kv').objectStore('kv').getAllKeys(); all.onsuccess = () => { db.close(); resolve(all.result); }; }; request.onerror = () => resolve([]); });
      return { core: await rows(`webrtc-bun-core-v1-${id}`), signal: await rows(`webrtc-bun-signal-v1-${id}`) };
    });
    if (!where.core.includes('identity') || where.signal.includes('identity')) throw new Error(`keys not in the WebAssembly core store: ${JSON.stringify(where)}`);
    step('keys are held by the WebAssembly core (sealed IndexedDB), not signal.js');
  }

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

  // ---------- Slash commands ----------
  const shotAs = async (page, name) => { if (shots) { await page.waitForTimeout(350); await page.screenshot({ path: join(shots, `${name}.png`) }); } };
  const command = async (page, text) => { await page.fill('#chat-input', text); await page.click('#chat-send'); };
  const popupNames = page => page.$$eval('#cmd-popup li .cmd-name', items => items.map(item => item.textContent));
  // Autocomplete: "/" lists commands, typing filters, arrows move, Tab completes.
  await alice.click('#chat-input'); await alice.keyboard.type('/');
  await alice.waitForFunction(() => !document.getElementById('cmd-popup').hidden, null, { timeout: 5000 });
  await alice.keyboard.type('po');
  if ((await popupNames(alice)).join() !== '/poll') throw new Error(`Autocomplete did not filter: ${await popupNames(alice)}`);
  if (await alice.getAttribute('#chat-input', 'aria-expanded') !== 'true' || !(await alice.getAttribute('#chat-input', 'aria-activedescendant'))) throw new Error('Autocomplete is not exposed to assistive technology');
  await shotAs(alice, 'cmd-1-autocomplete');
  await alice.keyboard.press('ArrowDown'); await alice.keyboard.press('Tab');
  if (await alice.inputValue('#chat-input') !== '/poll ') throw new Error('Tab did not complete the command');
  await alice.keyboard.type('"Lunch?" "Pizza" "Sushi"'); await alice.click('#chat-send');
  await alice.waitForFunction(() => document.getElementById('chat-input').value === '', null, { timeout: 5000 }).catch(() => { throw new Error('A successful command was left in the composer'); });
  await bob.waitForFunction(() => document.querySelector('#chat-log li.kind-poll .poll-question')?.textContent === 'Lunch?', null, { timeout: 15000 });
  await bob.click('#chat-log li.kind-poll .poll-option[data-option="1"]');
  await alice.waitForFunction(() => document.querySelector('#chat-log li.kind-poll .poll-option[data-option="1"] .poll-count')?.textContent === '1', null, { timeout: 15000 });
  await alice.click('#chat-log li.kind-poll .poll-option[data-option="0"]');
  await bob.waitForFunction(() => document.querySelector('#chat-log li.kind-poll .poll-option[data-option="0"] .poll-count')?.textContent === '1', null, { timeout: 15000 });
  // Bob changes his mind: Sushi → Pizza, and alice's tally follows.
  await bob.click('#chat-log li.kind-poll .poll-option[data-option="0"]');
  await alice.waitForFunction(() => document.querySelector('#chat-log li.kind-poll .poll-option[data-option="0"] .poll-count')?.textContent === '✓ 2' && document.querySelector('#chat-log li.kind-poll .poll-option[data-option="1"] .poll-count')?.textContent === '0', null, { timeout: 15000 });
  await bob.waitForFunction(() => document.querySelector('#chat-log li.kind-poll .poll-option[data-option="0"] .poll-count')?.textContent === '✓ 2', null, { timeout: 15000 });
  await shotAs(bob, 'cmd-2-poll');
  step('/poll from autocomplete (arrows + Tab); both voted, a changed vote, live tallies on both sides');

  await command(alice, '/me waves from the command line');
  await bob.waitForFunction(() => [...document.querySelectorAll('#chat-log li.kind-action .message-text')].some(item => item.textContent === 'alice waves from the command line'), null, { timeout: 15000 });
  await command(alice, '/shrug fine');
  await bob.waitForFunction(() => document.getElementById('chat-log').textContent.includes('fine ¯\\_(ツ)_/¯'), null, { timeout: 15000 });
  await shotAs(bob, 'cmd-3-me');
  step('/me renders an action line and /shrug appends ¯\\_(ツ)_/¯ on the other device');

  await command(alice, '/timer 1h');
  if (await alice.inputValue('#disappear') !== '3600000') throw new Error('/timer did not set the disappearing timer');
  await command(alice, '/timer off');
  if (await alice.inputValue('#disappear') !== 'off') throw new Error('/timer off did not clear the timer');
  await command(alice, '/verify'); await visible(alice, '#safety');
  if ((await alice.textContent('#safety-number')) !== codeA) throw new Error('/verify did not show the security code');
  await alice.click('#safety-close');
  await command(alice, '/reset'); await visible(alice, '#rotate-confirm'); await alice.click('#rotate-yes');
  await bob.waitForFunction(() => document.getElementById('chat-log').textContent.includes('Secure session reset by alice'), null, { timeout: 15000 });
  step('/timer sets and clears the timer, /verify opens the security code, /reset resets the secure session');

  const before = await logText(bob);
  await command(alice, '/nope do not send');
  if (!(await alice.textContent('#chat-status')).includes('Unknown command /nope')) throw new Error('Unknown command gave no hint');
  if (await alice.inputValue('#chat-input') !== '/nope do not send') throw new Error('An unknown command should stay in the composer to fix');
  await command(alice, '//literal slash');
  await bob.waitForFunction(() => document.getElementById('chat-log').textContent.includes('/literal slash'), null, { timeout: 15000 });
  if ((await logText(bob)).includes('nope do not send') || before.includes('/literal')) throw new Error('An unknown command reached the other device');
  await alice.fill('#chat-input', '/help'); await alice.click('#chat-send');
  await alice.waitForFunction(() => document.querySelectorAll('#cmd-popup li').length >= 10, null, { timeout: 5000 });
  if (!(await popupNames(alice)).includes('/emoji')) throw new Error('/help does not list /emoji');
  await shotAs(alice, 'cmd-4-help');
  await alice.keyboard.press('Escape');
  if (!(await alice.locator('#cmd-popup').isHidden())) throw new Error('Escape did not close the command list');
  step('unknown commands are never sent, //text sends a literal slash, /help lists every command');

  // ---------- Emoji ----------
  await alice.click('#chat-input'); await alice.fill('#chat-input', ''); await alice.keyboard.type('party time :partyi');
  await alice.waitForFunction(() => document.getElementById('cmd-popup').dataset.mode === 'emoji' && !document.getElementById('cmd-popup').hidden, null, { timeout: 5000 });
  await shotAs(alice, 'emoji-1-autocomplete');
  await alice.keyboard.press('Tab');
  if (!(await alice.inputValue('#chat-input')).includes('🥳')) throw new Error(`Emoji autocomplete did not insert: ${await alice.inputValue('#chat-input')}`);
  await alice.keyboard.type('and :smile: done'); await alice.click('#chat-send');
  await bob.waitForFunction(() => document.getElementById('chat-log').textContent.includes('party time 🥳 and 😄 done'), null, { timeout: 15000 });
  await command(alice, ':thumbsup:');
  await bob.waitForFunction(() => [...document.querySelectorAll('#chat-log li')].some(item => item.dataset.emoji === 'big' && item.textContent.includes('👍')), null, { timeout: 15000 });
  step('":partyi" autocompletes to 🥳, ":smile:" converts on send, and an emoji-only message renders big');

  // A custom emoji added in Settings: bob gets ":name:" end to end and renders it from the pack.
  await alice.click('#conv-back'); await alice.click('#account-menu summary'); await alice.click('#account-settings');
  await alice.fill('#emoji-name', 'test_parrot');
  const gif = Buffer.from('R0lGODlhEAAQAPAAAP8AAP///yH5BAAAAAAALAAAAAAQABAAAAIOhI+py+0Po5y02ouzPgUAOw==', 'base64');
  await alice.setInputFiles('#emoji-file', { name: 'parrot.gif', mimeType: 'image/gif', buffer: gif });
  await alice.click('#emoji-add');
  await alice.waitForFunction(() => document.getElementById('emoji-status').textContent.startsWith('Added :test_parrot:'), null, { timeout: 15000 });
  await alice.waitForFunction(() => document.querySelector('#emoji-list img.custom-emoji'), null, { timeout: 15000 });
  await alice.locator('.emoji-settings').scrollIntoViewIfNeeded(); await shotAs(alice, 'emoji-3-settings');
  await alice.evaluate(() => { document.getElementById('settings').open = false; });
  await alice.click('#contact-list .contact.mutual .row-button'); await visible(alice, '#conv-head');
  await alice.click('#chat-input'); await alice.keyboard.type('look :test_p');
  await alice.waitForFunction(() => document.querySelector('#cmd-popup:not([hidden]) li img.custom-emoji'), null, { timeout: 5000 });
  await alice.keyboard.press('Tab'); await alice.keyboard.type('nice'); await alice.click('#chat-send');
  await bob.waitForFunction(() => [...document.querySelectorAll('#chat-log li img.custom-emoji')].some(img => img.alt === ':test_parrot:' && img.complete && img.naturalWidth > 0), null, { timeout: 20000 });
  await command(alice, ':test_parrot:');
  await bob.waitForFunction(() => [...document.querySelectorAll('#chat-log li')].some(item => item.dataset.emoji === 'sticker'), null, { timeout: 15000 });
  const stickerSize = await bob.$$eval('#chat-log li[data-emoji="sticker"] img.custom-emoji', images => images.at(-1).getBoundingClientRect().width);
  if (stickerSize < 100) throw new Error(`Sticker rendered small: ${stickerSize}px`);
  await shotAs(bob, 'emoji-2-sticker');
  step('a custom emoji uploaded in Settings autocompletes with its thumbnail, reaches bob as :name: and renders inline and as a large sticker');

  // Manual key rotation from inside the chat: a fresh handshake, same security code, messages keep flowing.
  const rotShot = async (page, name) => { if (shots) { await page.waitForTimeout(400); await page.screenshot({ path: join(shots, `rot-${name}.png`) }); } };
  await alice.click('#conv-menu summary'); await rotShot(alice, '1-menu');
  await alice.click('#conv-rotate'); await visible(alice, '#rotate-confirm'); await rotShot(alice, '2-confirm');
  await alice.click('#rotate-yes');
  await alice.waitForFunction(() => document.getElementById('chat-log').textContent.includes('Secure session reset by you'), null, { timeout: 15000 });
  await bob.waitForFunction(() => document.getElementById('chat-log').textContent.includes('Secure session reset by alice'), null, { timeout: 15000 });
  await alice.fill('#chat-input', 'after the reset'); await alice.click('#chat-send');
  await bob.waitForFunction(() => document.getElementById('chat-log').textContent.includes('after the reset'), null, { timeout: 15000 });
  await bob.fill('#chat-input', 'new keys work'); await bob.click('#chat-send');
  await alice.waitForFunction(() => document.getElementById('chat-log').textContent.includes('new keys work'), null, { timeout: 15000 });
  await rotShot(alice, '3-system-line'); await rotShot(bob, '3-system-line-peer');
  const sameCode = await safety(alice); await alice.click('#safety-close');
  if (sameCode !== codeA) throw new Error('A session reset changed the security code');
  step('manual reset: new session keys, both sides show the reset line, messages flow both ways, security code unchanged');

  // Schedules: alice picks daily, bob weekly; the shorter (daily) applies on both sides.
  await alice.click('#conv-back'); await alice.click('#account-menu summary'); await alice.click('#account-settings');
  await alice.selectOption('#rotation-every', '86400000');
  await alice.locator('#rotation-every').scrollIntoViewIfNeeded(); await rotShot(alice, '4-settings');
  await bob.evaluate(() => { const select = document.getElementById('rotation-every'); select.value = '604800000'; select.dispatchEvent(new Event('change')); });
  await alice.evaluate(() => { document.getElementById('settings').open = false; });
  await alice.click('#contact-list .contact.mutual .row-button'); await visible(alice, '#conv-head');
  const rotationText = async page => { await page.click('#conv-menu summary'); await page.click('#conv-safety'); await visible(page, '#safety'); const text = await page.textContent('#safety-rotation'); await page.click('#safety-close'); return text; };
  await alice.waitForFunction(() => true);
  let [ruleA, ruleB] = ['', ''];
  for (let tries = 0; tries < 30 && !(ruleA.includes('every day (your setting)') && ruleB.includes('every day (their setting)')); tries++) {
    await alice.waitForTimeout(300); [ruleA, ruleB] = [await rotationText(alice), await rotationText(bob)];
  }
  if (!ruleA.includes('every day (your setting)') || !ruleB.includes('every day (their setting)')) throw new Error(`Rotation policy not shared: ${ruleA} / ${ruleB}`);
  await alice.click('#conv-menu summary'); await alice.click('#conv-safety'); await visible(alice, '#safety'); await rotShot(alice, '5-safety-policy'); await alice.click('#safety-close');
  step('alice daily, bob weekly: both chats show the shorter interval, one day');

  // A session older than the interval rotates before the next message goes out.
  if (wasm) await alice.evaluate(() => { const real = Date.now; window.__realNow = real; Date.now = () => real() + 2 * 86400000; });
  else await alice.evaluate(async () => {
    const me = (await (await fetch('/api/me')).json()).user.id, peer = (await (await fetch('/api/contacts')).json()).contacts.find(contact => contact.username === 'bob').id;
    const db = await new Promise((ok, fail) => { const request = indexedDB.open(`webrtc-bun-signal-v1-${me}`, 1); request.onsuccess = () => ok(request.result); request.onerror = fail; });
    const run = (mode, work) => new Promise((ok, fail) => { const tx = db.transaction('kv', mode), request = work(tx.objectStore('kv')); tx.oncomplete = () => ok(request.result); tx.onerror = fail; });
    const record = await run('readonly', store => store.get(`sessions:${peer}`));
    record.list[record.active].startedAt = Date.now() - 2 * 86400000;
    await run('readwrite', store => store.put(record, `sessions:${peer}`));
    db.close();
  });
  await alice.fill('#chat-input', 'sent after a scheduled rotation'); await alice.click('#chat-send');
  await alice.waitForFunction(() => document.getElementById('chat-log').textContent.includes('Keys rotated on schedule (every day)'), null, { timeout: 15000 });
  await bob.waitForFunction(() => { const text = document.getElementById('chat-log').textContent; return text.includes('Keys rotated on schedule by alice') && text.includes('sent after a scheduled rotation'); }, null, { timeout: 15000 });
  if (wasm) await alice.evaluate(() => { Date.now = window.__realNow; });
  step('a session older than the shared interval rotated automatically before the next message');

  // Key change: bob's device loses its keys (a reinstall). Alice verified him, so sending pauses.
  await bob.evaluate(async keyDb => { const id = (await (await fetch('/api/me')).json()).user.id; await new Promise(done => { const request = indexedDB.deleteDatabase(`${keyDb}${id}`); request.onsuccess = request.onerror = request.onblocked = done; }); }, keyDb);
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
  await bob.evaluate(() => { const select = document.getElementById('rotation-every'); select.value = '0'; select.dispatchEvent(new Event('change')); });
  await bob.click('#conv-menu summary'); await bob.click('#conv-rotate'); await visible(bob, '#rotate-confirm'); await bob.click('#rotate-yes');
  await bob.click('#conv-menu summary'); await bob.click('#conv-burn'); await visible(bob, '#burn-confirm'); await bob.click('#burn-confirm-yes');
  await bob.waitForFunction(() => /Burned on this device/.test(document.getElementById('chat-status').textContent), null, { timeout: 15000 });
  await alice.waitForTimeout(2000);
  if (!(await logText(alice)).includes('sealed end to end')) throw new Error('An unaccepted identity burned the conversation');
  if ((await logText(alice)).includes('Secure session reset by bob')) throw new Error('An unaccepted identity reset the session');
  if (!(await rotationText(alice)).includes('every day (your setting)')) throw new Error('An unaccepted identity changed the rotation policy');
  await bob.click('#conv-back');
  step('a burn, a session reset and a policy change from the unaccepted new identity were all ignored');
  await alice.click('#key-banner-review'); await visible(alice, '#safety');
  if ((await alice.textContent('#safety-number')) === codeA) throw new Error('Safety number did not change');
  await alice.click('#safety-accept');
  await alice.fill('#chat-input', 'hello new device'); await alice.click('#chat-send');
  await bob.click('#contact-list .contact.mutual .row-button');
  await bob.waitForFunction(() => document.getElementById('chat-log').textContent.includes('hello new device'), null, { timeout: 15000 });
  step('a new identity raised the security-code banner, paused sending to the verified contact, and messaging resumed after review');

  // Alice generates new identity keys on purpose: bob sees her security code change and reviews it.
  const aliceCodeBefore = await safety(bob); await bob.click('#safety-close');
  await alice.click('#conv-back'); await alice.click('#account-menu summary'); await alice.click('#account-settings');
  await alice.click('#identity-reset'); await visible(alice, '#identity-confirm'); await rotShot(alice, '6-identity-confirm');
  await alice.click('#identity-yes');
  await alice.waitForFunction(() => /New identity keys are in use/.test(document.getElementById('security-status').textContent), null, { timeout: 15000 });
  await bob.waitForFunction(() => !document.getElementById('key-banner').hidden, null, { timeout: 15000 });
  await bob.click('#key-banner-review'); await visible(bob, '#safety');
  if ((await bob.textContent('#safety-number')) === aliceCodeBefore) throw new Error('Identity regeneration did not change the security code');
  await bob.click('#safety-accept');
  await alice.evaluate(() => { document.getElementById('settings').open = false; });
  await alice.click('#contact-list .contact.mutual .row-button'); await visible(alice, '#conv-head');
  // Alice's pin for bob is unchanged; her new identity starts a fresh session with him.
  await alice.fill('#chat-input', 'from my new keys'); await alice.click('#chat-send');
  await bob.waitForFunction(() => document.getElementById('chat-log').textContent.includes('from my new keys'), null, { timeout: 15000 });
  step('own identity regeneration: bob saw alice\'s security code change, accepted it, and messages flow');

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
