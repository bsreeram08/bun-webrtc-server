// End-to-end accounts check: passkey sign-up via invite, contacts, presence, chat, a video call
// accepted from the incoming sheet, sign-out and passkey sign-in. Uses Chromium's virtual authenticator.
// Starts its own signaling server on a throwaway DATA_DIR. Usage: node tests/browser/accounts.mjs
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
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
const shot = async (page, name) => { if (shots) await page.screenshot({ path: join(shots, `acct-${name}.png`) }); };

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

  await alice.click('#contact-list .contact.mutual .row-button');
  await visible(alice, '#conv-head');
  const chatCode = await code(alice);
  await alice.fill('#chat-input', 'hi bob, this went device to device'); await alice.click('#chat-send');
  await alice.waitForFunction(() => document.querySelector('#chat-log li.outgoing')?.dataset.status === 'delivered', null, { timeout: 15000 });
  await bob.click('#contact-list .contact.mutual .row-button');
  await bob.waitForFunction(() => document.getElementById('chat-log').textContent.includes('hi bob'), null, { timeout: 15000 });
  if (await code(bob) !== chatCode) throw new Error('Chat verification codes differ');
  await bob.fill('#chat-input', 'got it 👋'); await bob.click('#chat-send');
  await alice.waitForFunction(() => document.getElementById('chat-log').textContent.includes('got it'), null, { timeout: 15000 });
  await shot(alice, '3-conversation'); step(`chat delivered both ways; matching code ${chatCode}`);

  await alice.click('#conv-back'); await visible(alice, '#chats');
  await alice.waitForFunction(() => document.querySelector('#contact-list .contact-text small')?.textContent.includes('got it'), null, { timeout: 10000 });
  await shot(alice, '2-list'); step('chat list shows the last message preview');

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
