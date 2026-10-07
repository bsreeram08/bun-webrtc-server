// Safari (WebKit) regression: encryption keys must survive a reload, private keys must never be stored as plain
// bytes, and a message encrypted before a reload must decrypt after it. WebKit once stored X25519 CryptoKeys in
// IndexedDB as empty objects, so every load silently minted new identities. Runs the shipped signal.js in both
// engines against a local server (no accounts needed).
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
const playwright = await import(process.env.PLAYWRIGHT_MODULE || 'playwright-core');
const port = Number(process.env.TEST_PORT || 3172), origin = `http://localhost:${port}`;
const server = spawn('bun', ['--no-env-file', 'packages/signaling/server.ts'], { env: { ...process.env, PORT: String(port), ADMIN_TOKEN: randomBytes(32).toString('hex'), PUBLIC_ORIGIN: origin, ACCOUNTS: 'off' }, stdio: 'ignore' });
process.on('exit', () => server.kill());
for (let tries = 0; tries < 50; tries++) { try { if ((await fetch(`${origin}/health`)).ok) break; } catch {} await new Promise(resolve => setTimeout(resolve, 100)); }
for (const name of ['webkit', 'chromium']) {
  const browser = await playwright[name].launch(); const page = await (await browser.newContext()).newPage();
  await page.goto(origin);
  const first = await page.evaluate(async () => { const id = await window.Signal.box(window.Signal.indexedDbBackend('k')).identity(); return { dh: id.pub.dh, plain: 'priv' in id.dh, wrapped: ArrayBuffer.isView(id.dh.wrapped) }; });
  if (first.plain || !first.wrapped) throw new Error(`${name}: private key stored unwrapped`);
  await page.reload();
  const env = await page.evaluate(async () => {
    const A = window.Signal.box(window.Signal.indexedDbBackend('a')), B = window.Signal.box(window.Signal.indexedDbBackend('b'));
    const keys = await B.prekeys(), bundle = { identity: keys.identity, signedPreKey: keys.signedPreKey, oneTimePreKey: (await B.oneTimePreKeys(1))[0] };
    return { again: (await window.Signal.box(window.Signal.indexedDbBackend('k')).identity()).pub.dh, envelope: await A.encryptTo('b', { hi: 1 }, async () => bundle) };
  });
  if (env.again !== first.dh) throw new Error(`${name}: identity changed across a reload`);
  await page.reload();
  const got = await page.evaluate(async envelope => { let message; await window.Signal.box(window.Signal.indexedDbBackend('b')).decryptFrom('a', envelope, async value => { message = value; }); return message; }, env.envelope);
  if (got?.hi !== 1) throw new Error(`${name}: message encrypted before a reload did not decrypt after it`);
  console.log(`✓ ${name}: keys wrapped, stable across reloads, decrypt after reload`);
  await browser.close();
}
console.log('Key storage check passed.');
process.exit(0);
