// The WebAssembly messaging core in real browsers (WebKit and Chromium), through core.js and core-worker.js:
// keys stable across reloads, nothing unsealed in IndexedDB, a message encrypted before a reload decrypts
// after it, and with two tabs of one account only one runs the core while both can use it.
// Runs against a local server (no accounts needed). Usage: node tests/browser/webkit-wasm.mjs
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
const playwright = await import(process.env.PLAYWRIGHT_MODULE || 'playwright-core');
const port = Number(process.env.TEST_PORT || 3173), origin = `http://localhost:${port}`;
const server = spawn('bun', ['--no-env-file', 'packages/signaling/server.ts'], { env: { ...process.env, PORT: String(port), ADMIN_TOKEN: randomBytes(32).toString('hex'), PUBLIC_ORIGIN: origin, ACCOUNTS: 'off' }, stdio: 'ignore' });
process.on('exit', () => server.kill());
for (let tries = 0; tries < 50; tries++) { try { if ((await fetch(`${origin}/health`)).ok) break; } catch {} await new Promise(resolve => setTimeout(resolve, 100)); }
const step = text => console.log(`✓ ${text}`);

// In the page: a box per account id (alice/bob are two accounts in one browser profile).
const boxCall = (page, user, fn, arg) => page.evaluate(async ([user, source, arg]) => {
  const box = window.Core.box(user);
  return (0, eval)(`(${source})`)(box, arg);
}, [user, fn.toString(), arg]);

for (const name of ['webkit', 'chromium']) {
  const browser = await playwright[name].launch();
  const context = await browser.newContext();
  const page = await context.newPage();
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  await page.goto(origin);
  await page.waitForFunction(() => window.Core?.supported());

  const first = await boxCall(page, 'alice', async box => (await box.identity()).pub);
  await page.reload();
  const again = await boxCall(page, 'alice', async box => (await box.identity()).pub);
  if (first.dh !== again.dh || first.sign !== again.sign) throw new Error(`${name}: identity changed across a reload`);

  // Every stored value must be sealed bytes: nothing JSON-like, and the public key text appears nowhere.
  const raw = await page.evaluate(async () => {
    const db = await new Promise((resolve, reject) => { const request = indexedDB.open('webrtc-bun-core-v1-alice'); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
    const values = await new Promise(resolve => { const request = db.transaction('kv').objectStore('kv').getAll(); request.onsuccess = () => resolve(request.result); });
    return values.map(value => ({ keys: Object.keys(value).sort().join(','), iv: ArrayBuffer.isView(value.iv), ct: ArrayBuffer.isView(value.ct), text: new TextDecoder('latin1').decode(value.ct) }));
  });
  if (!raw.length || raw.some(row => row.keys !== 'ct,iv' || !row.iv || !row.ct || row.text.includes(first.dh) || row.text.includes('"dh"'))) throw new Error(`${name}: an IndexedDB value is not sealed`);
  step(`${name}: identity stable across reload; ${raw.length} rows, all sealed`);

  // Alice encrypts to bob's bundle, the page reloads, bob decrypts: prekeys and sessions really persisted.
  const envelope = await page.evaluate(async () => {
    const bob = window.Core.box('bob'), alice = window.Core.box('alice');
    const keys = await bob.prekeys(), bundle = { identity: keys.identity, signedPreKey: keys.signedPreKey, oneTimePreKey: (await bob.oneTimePreKeys(1))[0] };
    return alice.encryptTo('bob', { hi: 1 }, async () => bundle);
  });
  await page.reload();
  const got = await page.evaluate(async envelope => { let value; await window.Core.box('bob').decryptFrom('alice', envelope, async message => { value = message; }); return value; }, envelope);
  if (got?.hi !== 1) throw new Error(`${name}: a message encrypted before a reload did not decrypt after it`);
  const reply = await page.evaluate(async () => window.Core.box('bob').encryptTo('alice', { hi: 2 }, async () => { throw new Error('no bundle needed'); }));
  const back = await page.evaluate(async envelope => { let value; await window.Core.box('alice').decryptFrom('bob', envelope, async message => { value = message; }); return value; }, reply);
  if (back?.hi !== 2) throw new Error(`${name}: the reply did not decrypt`);
  step(`${name}: encrypt → reload → decrypt, and the reply, through the WebAssembly core`);

  // Two tabs, one account: exactly one leader runs the core; the follower's calls go through it.
  const second = await context.newPage();
  await second.goto(origin); await second.waitForFunction(() => window.Core?.supported());
  await boxCall(second, 'alice', async box => box.identity());
  const leaders = await Promise.all([page, second].map(tab => tab.evaluate(() => window.Core.box('alice').isLeader())));
  if (leaders.filter(Boolean).length !== 1) throw new Error(`${name}: expected exactly one leader, got ${leaders}`);
  const fromFollower = await boxCall(leaders[0] ? second : page, 'alice', async box => (await box.identity()).pub);
  if (fromFollower.dh !== first.dh) throw new Error(`${name}: the follower tab saw a different identity`);
  // The leader tab closes: the follower takes the lock, starts the core from disk, and keeps working.
  const [leaderTab, followerTab] = leaders[0] ? [page, second] : [second, page];
  await leaderTab.close();
  await followerTab.waitForFunction(() => window.Core.box('alice').isLeader(), null, { timeout: 10000 });
  const afterHandover = await boxCall(followerTab, 'alice', async box => (await box.identity()).pub);
  if (afterHandover.dh !== first.dh) throw new Error(`${name}: identity changed after the leader handover`);
  step(`${name}: two tabs — one writer, the follower works through it and takes over when the leader closes`);

  // Never two cores for one account: a tab running one core hears another tab start the other, and yields.
  const signalTab = await context.newPage();
  await signalTab.goto(origin); await signalTab.waitForFunction(() => window.Core?.supported());
  await signalTab.evaluate(() => { window.__yielded = null; window.Core.guard('carol', 'signal', next => { window.__yielded = next; }); });
  await followerTab.evaluate(() => window.Core.guard('carol', 'wasm', () => {}));
  await signalTab.waitForFunction(() => window.__yielded === 'wasm', null, { timeout: 5000 });
  step(`${name}: a tab on one core yields when another tab of the account starts the other core`);

  if (errors.length) throw new Error(`${name}: page errors: ${errors.join('; ')}`);
  await browser.close();
}
console.log('WebAssembly core check passed.');
process.exit(0);
