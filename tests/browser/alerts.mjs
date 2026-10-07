// Ringtone and notification UI check: incoming and outgoing rings start and stop with the call,
// and the notification banner and settings render. Push delivery itself needs a real push service
// and is covered by unit tests. Usage: node tests/browser/alerts.mjs (SCREENSHOT_DIR optional)
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';

const root = resolve(import.meta.dirname, '../..');
const playwright = await import(process.env.PLAYWRIGHT_MODULE || 'playwright-core');
const port = Number(process.env.TEST_PORT || 3128), origin = `http://localhost:${port}`;
const shots = process.env.SCREENSHOT_DIR;
const env = { ...process.env, PORT: String(port), ADMIN_TOKEN: randomBytes(32).toString('hex'), PUBLIC_ORIGIN: origin, DATA_DIR: mkdtempSync(join(tmpdir(), 'alerts-e2e-')) };
const server = spawn('bun', ['--no-env-file', 'packages/signaling/server.ts'], { cwd: root, env, stdio: ['ignore', 'pipe', 'inherit'] });
process.on('exit', () => server.kill());
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => process.exit(1));
await new Promise((ok, fail) => { server.stdout.on('data', chunk => String(chunk).includes('listening') && ok()); server.on('exit', code => fail(new Error(`server exited ${code}`))); setTimeout(() => fail(new Error('server did not start')), 10000); });
const browser = await playwright.chromium.launch({ executablePath: process.env.BROWSER_EXECUTABLE, args: ['--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream', '--autoplay-policy=no-user-gesture-required'] });
const step = name => console.log(`✓ ${name}`);
const shot = async (page, name) => { if (shots) await page.screenshot({ path: join(shots, `push-${name}.png`) }); };
const visible = (page, selector) => page.locator(selector).waitFor({ state: 'visible', timeout: 15000 });
const ring = page => page.evaluate(() => window.Ring.state);
const until = (page, predicate, arg) => page.waitForFunction(predicate, arg, { timeout: 15000 });

async function person() {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
  await context.grantPermissions(['camera', 'microphone'], { origin });
  // Headless Chromium reports notifications as denied; present the first-run 'default' state, and
  // count camera/microphone requests so the test can prove nothing captures media before Accept.
  await context.addInitScript(() => {
    Object.defineProperty(Notification, 'permission', { get: () => 'default' });
    const original = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
    window.mediaRequests = 0; window.mediaConstraints = [];
    navigator.mediaDevices.getUserMedia = constraints => { window.mediaRequests++; window.mediaConstraints.push(constraints); return original(constraints); };
  });
  const page = await context.newPage();
  page.on('pageerror', error => { throw error; });
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  return page;
}
async function register(page, username) {
  const invite = /Invite code: (\S+)/.exec(spawnSync('bun', ['--no-env-file', 'scripts/create-invite.ts'], { cwd: root, env, encoding: 'utf8' }).stdout)?.[1];
  await page.goto(`${origin}/#invite=${invite}`);
  await visible(page, '#welcome');
  await page.fill('#register-username', username);
  await page.click('#register-submit');
  await visible(page, '#chats');
}

try {
  const alice = await person(), bob = await person();
  await register(alice, 'alice'); await register(bob, 'bob');
  await alice.fill('#contact-input', 'bob'); await alice.click('#contact-add');
  await bob.getByRole('button', { name: 'Accept' }).click({ timeout: 15000 });
  await until(alice, () => document.querySelector('#contact-list .contact.mutual .avatar')?.dataset.online === 'true');
  await visible(alice, '#notify-banner'); await shot(alice, '1-banner');
  step('notification banner offered after sign-in, without prompting');

  await alice.click('#account-menu summary'); await alice.click('#account-settings');
  await visible(alice, '#notify-toggle'); await shot(alice, '2-settings');
  await alice.click('#settings-close');
  step('settings show notification and silent toggles');

  await alice.click('#contact-list .contact.mutual .row-button');
  await visible(alice, '#conv-head');
  await alice.click('#conv-voice');
  await visible(bob, '#incoming');
  await until(bob, () => window.Ring.state.mode === 'incoming' && window.Ring.state.audio === 'running');
  await until(alice, () => window.Ring.state.mode === 'outgoing');
  await shot(bob, '3-incoming');
  step(`incoming ringtone playing (${JSON.stringify(await ring(bob))}); caller hears ringback`);

  await bob.click('#incoming-decline');
  await until(bob, () => window.Ring.state.mode === null);
  await until(alice, () => window.Ring.state.mode === null);
  step('decline stops both the ringtone and the ringback');

  await alice.click('#conv-voice');
  await visible(bob, '#incoming');
  await until(bob, () => window.Ring.state.mode === 'incoming');
  await bob.click('#incoming-accept');
  await until(alice, () => window.Ring.state.mode === null && document.getElementById('status').textContent.includes('live'));
  if ((await ring(bob)).mode !== null) throw new Error('Callee still ringing after accept');
  step('accepting stops ringing on both sides');
  await alice.click('#hangup');

  // A crafted link and a notification 'open' intent may only select the conversation: the call still rings.
  await until(alice, () => document.getElementById('app').dataset.state !== 'call');
  await bob.goto(`${origin}/#open=alice&call=video&answer=1`);
  await visible(bob, '#conv-head');
  await bob.evaluate(() => window.Alerts.onOpen({ user: 'alice', call: 'video', answer: true }));
  const before = await bob.evaluate(() => window.mediaRequests);
  await alice.click('#conv-video');
  await visible(bob, '#incoming');
  await bob.waitForTimeout(3000);
  if (await bob.evaluate(() => window.mediaRequests) !== before) throw new Error('Media was captured before Accept');
  if (!await bob.isVisible('#incoming')) throw new Error('Incoming sheet disappeared without a tap');
  await bob.click('#incoming-accept');
  await until(bob, start => window.mediaRequests === start + 1, before);
  step('notification/link open intent never answers: sheet keeps ringing and media starts only on Accept');
  await alice.click('#hangup');
  await until(bob, () => document.getElementById('app').dataset.state !== 'call');

  // A video call can be answered with the microphone only, and the camera added later.
  await alice.click('#conv-video');
  await visible(bob, '#incoming');
  if (!await bob.isVisible('#incoming-accept-audio')) throw new Error('No audio-only option on a video call');
  await bob.waitForTimeout(400); await shot(bob, '4-incoming-video');
  const asked = await bob.evaluate(() => window.mediaConstraints.length);
  await bob.click('#incoming-accept-audio');
  await until(alice, () => document.getElementById('status').textContent.includes('live')).catch(async error => {
    for (const page of [alice, bob]) console.error(await page.evaluate(() => ({ status: document.getElementById('status').textContent, ...document.getElementById('app').dataset })));
    throw error;
  });
  const answered = await bob.evaluate(index => window.mediaConstraints[index], asked);
  if (answered?.video !== false || answered?.audio !== true) throw new Error(`Audio-only accept asked for ${JSON.stringify(answered)}`);
  await until(bob, () => document.getElementById('app').dataset.local === 'off' && document.getElementById('app').dataset.remote === 'on');
  await until(alice, () => document.getElementById('app').dataset.remote === 'off' && document.getElementById('app').dataset.local === 'on');
  await until(alice, () => document.getElementById('remote').srcObject?.getAudioTracks().some(track => track.readyState === 'live' && !track.muted));
  await alice.waitForTimeout(600); await shot(alice, '5-audio-only-caller'); await shot(bob, '6-audio-only-callee');
  step('video call accepted audio only: no camera captured, caller sees an avatar, audio flows');
  await bob.click('#camera');
  await until(bob, () => document.getElementById('app').dataset.local === 'on');
  await until(alice, () => document.getElementById('app').dataset.remote === 'on');
  if ((await bob.evaluate(() => window.mediaConstraints.at(-1)))?.video !== true) throw new Error('Camera button did not capture video');
  step('turning the camera on later adds video for the caller');
  await alice.click('#hangup');
  await until(bob, () => document.getElementById('app').dataset.state !== 'call');

  await bob.click('#account-menu summary').catch(() => {});
  await bob.evaluate(() => { document.getElementById('account-menu').open = false; });
  await bob.evaluate(() => { window.Ring.silent = true; });
  await alice.click('#conv-voice');
  await visible(bob, '#incoming');
  if ((await ring(bob)).mode !== null) throw new Error('Silent mode still rang');
  step('silent mode shows the call without ringing');
  console.log('Alerts check passed.');
} catch (error) {
  console.error(error); process.exitCode = 1;
} finally {
  await browser.close(); server.kill();
}
