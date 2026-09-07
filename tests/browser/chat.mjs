// Browser acceptance through public UI. Use a disposable local test server.
import assert from 'node:assert/strict';
import { randomUUID, createHash, X509Certificate } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import https from 'node:https';

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright-core');
const origin = process.env.TEST_ORIGIN || 'http://localhost:3000';
assert(process.env.ADMIN_TOKEN, 'ADMIN_TOKEN is required');
const insecure = process.env.TEST_INSECURE_TLS === 'true';
assert(!insecure || ['localhost', '127.0.0.1', '[::1]'].includes(new URL(origin).hostname), 'Certificate bypass is restricted to a local test origin');
const directory = await mkdtemp(join(tmpdir(), 'webrtc-chat-browser-'));
const backupPath = join(directory, 'encrypted-chat-backup.json');
const contexts = [];
const traffic = [];
const errors = [];
const marker = `private-chat-${randomUUID()}`;
const reply = `reply-${randomUUID()}`;
const ephemeral = `disappearing-${randomUUID()}`;
const pressure = `backpressure-${randomUUID()}`;
const hostile = `<img src=x onerror="window.chatXssExecuted=true">${randomUUID()}`;
const password = `backup-test-${randomUUID()}`;
let browser, room, certificateSPKI;

async function api(path, method, bearer) {
  const url = new URL(path, origin);
  if (!insecure || url.protocol !== 'https:') {
    const response = await fetch(url, { method, headers: { Authorization: `Bearer ${bearer}` }, redirect: 'error', signal: AbortSignal.timeout(10000) });
    return { status: response.status, body: await response.text() };
  }
  // Scope the development certificate exception to this one request, never process-wide.
  return new Promise((resolve, reject) => {
    const request = https.request(url, { method, rejectUnauthorized: false, headers: { Authorization: `Bearer ${bearer}` } }, response => {
      if (!certificateSPKI) {
        try {
          const certificate = new X509Certificate(response.socket.getPeerCertificate().raw);
          certificateSPKI = createHash('sha256').update(certificate.publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
        } catch (error) { response.resume(); reject(error); return; }
      }
      let body = ''; response.setEncoding('utf8'); response.on('data', chunk => { body += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, body }));
    });
    request.setTimeout(10000, () => request.destroy(new Error('Test API request timed out')));
    request.on('error', reject); request.end();
  });
}

async function pageForDevice(time = Date.now()) {
  const context = await browser.newContext({ acceptDownloads: true, ignoreHTTPSErrors: insecure });
  contexts.push(context);
  // Chromium denies permissions outside this explicit empty grant list.
  await context.grantPermissions([], { origin });
  const page = await context.newPage();
  await page.clock.install({ time });
  page.on('pageerror', error => errors.push(error.message));
  page.on('dialog', dialog => dialog.accept());
  page.on('request', request => traffic.push(request.url(), request.postData() || ''));
  page.on('websocket', socket => {
    socket.on('framesent', frame => traffic.push(String(frame.payload)));
    socket.on('framereceived', frame => traffic.push(String(frame.payload)));
  });
  await page.addInitScript(() => {
    window.chatTestMediaRequests = 0;
    const getUserMedia = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
    navigator.mediaDevices.getUserMedia = (...args) => { window.chatTestMediaRequests++; return getUserMedia(...args); };
    window.chatTestPeers = [];
    window.chatTestChannels = [];
    const Native = window.RTCPeerConnection;
    window.RTCPeerConnection = class extends Native {
      constructor(...args) {
        super(...args); window.chatTestPeers.push(this);
        this.addEventListener('datachannel', event => window.chatTestChannels.push(event.channel));
      }
      createDataChannel(...args) { const channel = super.createDataChannel(...args); window.chatTestChannels.push(channel); return channel; }
    };
  });
  return page;
}

async function history(page) { return page.evaluate(() => window.ChatStore.list()); }
async function waitStored(page, text, present = true) {
  await page.waitForFunction(() => Boolean(window.ChatStore));
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    const records = await history(page);
    if (records.some(message => message.text === text) === present) return;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.equal((await history(page)).some(message => message.text === text), present, 'Expected message persistence state was not reached');
}
async function openBackup(page) {
  const section = page.locator('details.backup-section');
  if (!await section.evaluate(element => element.open)) await section.locator('summary').click();
}
async function waitServiceWorker(page) {
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    const active = await page.evaluate(async () => (await navigator.serviceWorker.getRegistration())?.active?.state === 'activated');
    if (active) return;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.fail('Service worker did not activate; inspect registration errors, including local certificate handling');
}
async function chooseConversation(page) {
  await page.locator(`#history-select option[value="${room.roomId}"]`).waitFor({ state: 'attached' });
  await page.locator('#history-select').selectOption(room.roomId);
}
async function waitVisible(page, text) {
  await page.locator('#chat-log .message-text').filter({ hasText: text }).waitFor();
  assert((await page.locator('#chat-log .message-text').allTextContents()).includes(text), 'Message text must render exactly');
}
async function send(from, to, text) {
  await from.locator('#chat-input').fill(text);
  await from.locator('#chat-send').click();
  await waitVisible(to, text);
  await from.waitForFunction(text => [...document.querySelectorAll('#chat-log li')].some(row => row.dataset.status === 'delivered' && row.querySelector('.message-text')?.textContent === text), text);
}

try {
  const created = await api('/rooms', 'POST', process.env.ADMIN_TOKEN);
  assert.equal(created.status, 201, 'Create disposable chat room');
  room = JSON.parse(created.body);
  // Service-worker script fetches do not inherit Playwright's context TLS bypass.
  // Accept only this disposable localhost fixture's public-key fingerprint.
  browser = await chromium.launch({ headless: true, executablePath: process.env.BROWSER_EXECUTABLE || undefined,
    args: insecure && certificateSPKI ? [`--ignore-certificate-errors-spki-list=${certificateSPKI}`] : [],
  });
  const peers = await Promise.all([pageForDevice(), pageForDevice()]);
  for (let i = 0; i < peers.length; i++) {
    await peers[i].goto(`${origin}/#${new URLSearchParams({ roomId: room.roomId, token: room.participants[i].token })}`);
    await peers[i].locator('#chat-only').check();
    await peers[i].locator('#join').click();
    if (i === 0) {
      await peers[0].locator('#chat-input').fill(marker);
      await peers[0].locator('#chat-send').click();
      await waitStored(peers[0], marker);
      assert.equal((await history(peers[0])).find(message => message.text === marker).status, 'queued', 'Message waits on the sender device while the friend is offline');
    }
  }
  await Promise.all(peers.map(page => page.waitForFunction(() => window.chatTestChannels.some(channel => channel.readyState === 'open'), null, { timeout: 45000 })));
  for (const page of peers) {
    assert.equal(await page.evaluate(() => window.chatTestMediaRequests), 0, 'Chat-only must not call getUserMedia');
    assert.equal(await page.evaluate(() => document.getElementById('local').srcObject), null);
    assert.equal(await page.evaluate(() => window.chatTestChannels.filter(channel => channel.readyState === 'open').every(channel => channel.ordered && channel.maxRetransmits === null && channel.maxPacketLifeTime === null)), true, 'Chat must use reliable ordered delivery');
  }
  const routes = await Promise.all(peers.map(page => page.evaluate(async () => {
    const stats = await window.chatTestPeers.at(-1).getStats();
    const transport = [...stats.values()].find(stat => stat.type === 'transport' && stat.selectedCandidatePairId);
    const pair = stats.get(transport?.selectedCandidatePairId);
    return { local: stats.get(pair?.localCandidateId)?.candidateType, remote: stats.get(pair?.remoteCandidateId)?.candidateType };
  })));
  if (process.env.EXPECT_RELAY === 'true') for (const route of routes) assert.equal(route.local, 'relay');
  await waitVisible(peers[1], marker);
  await peers[0].waitForFunction(text => [...document.querySelectorAll('#chat-log li')].some(row => row.dataset.status === 'delivered' && row.querySelector('.message-text')?.textContent === text), marker);
  await send(peers[1], peers[0], reply);
  await peers[1].evaluate(() => Object.defineProperty(window.chatTestChannels.find(channel => channel.readyState === 'open'), 'bufferedAmount', { configurable: true, get: () => 70000 }));
  await peers[0].locator('#chat-input').fill(pressure);
  await peers[0].locator('#chat-send').click();
  await waitStored(peers[1], pressure);
  assert.equal(await peers[1].evaluate(() => window.chatTestChannels.some(channel => channel.readyState === 'open')), true, 'ACK backpressure must not close the data channel');
  assert.notEqual((await history(peers[0])).find(message => message.text === pressure).status, 'delivered');
  await peers[1].evaluate(() => {
    const channel = window.chatTestChannels.find(channel => channel.readyState === 'open');
    delete channel.bufferedAmount; channel.dispatchEvent(new Event('bufferedamountlow'));
  });
  await peers[0].waitForFunction(text => [...document.querySelectorAll('#chat-log li')].some(row => row.dataset.status === 'delivered' && row.querySelector('.message-text')?.textContent === text), pressure);
  await send(peers[0], peers[1], hostile);
  assert.equal(await peers[1].locator('#chat-log img, #chat-log script').count(), 0, 'Peer HTML must stay inert text');
  assert.equal(await peers[1].evaluate(() => window.chatXssExecuted === true), false);
  await peers[0].locator('#disappear').selectOption('3600000');
  await send(peers[0], peers[1], ephemeral);
  await peers[0].locator('#disappear').selectOption('off');
  const beforeBackup = await history(peers[0]);
  const expiringRecord = beforeBackup.find(message => message.text === ephemeral);
  assert.equal(expiringRecord.expiresAt - expiringRecord.createdAt, 3600000, 'Expiry uses original creation time');
  await openBackup(peers[0]);
  await peers[0].locator('#backup-password').fill(password);
  const downloadEvent = peers[0].waitForEvent('download');
  await peers[0].locator('#backup-export').click();
  await (await downloadEvent).saveAs(backupPath);
  const encrypted = await readFile(backupPath, 'utf8');
  for (const secret of [marker, reply, ephemeral, password, room.roomId, ...room.participants.map(participant => participant.token)]) {
    assert(!encrypted.includes(secret), 'Export must not contain plaintext history, password or invitation credentials');
  }

  await waitServiceWorker(peers[0]);
  await peers[0].reload();
  await chooseConversation(peers[0]);
  await waitVisible(peers[0], marker);
  await waitVisible(peers[0], reply);
  assert.equal(await peers[0].evaluate(() => window.chatTestMediaRequests), 0, 'Opening local history must not request media');
  await peers[0].waitForFunction(() => navigator.serviceWorker?.controller, null, { timeout: 20000 });
  await peers[0].context().setOffline(true);
  try {
    await peers[0].reload();
    await chooseConversation(peers[0]);
    await waitVisible(peers[0], marker);
    assert.equal(await peers[0].evaluate(() => navigator.onLine), false, 'History reload must really run offline');
    assert.equal(await peers[0].evaluate(() => window.chatTestMediaRequests), 0);
  } finally { await peers[0].context().setOffline(false); }

  const restored = await pageForDevice();
  await restored.goto(origin);
  await openBackup(restored);
  await restored.locator('#backup-file').setInputFiles(backupPath);
  await restored.locator('#backup-password').fill('definitely-wrong-password');
  await restored.locator('#backup-import').click();
  await restored.locator('#backup-status').filter({ hasText: /incorrect|wrong|decrypt|invalid|failed/i }).waitFor();
  assert.equal((await history(restored)).length, 0, 'Wrong password must not partially import history');
  await restored.locator('#backup-password').fill(password);
  await restored.locator('#backup-import').click();
  await waitStored(restored, marker);
  await chooseConversation(restored);
  await waitVisible(restored, marker);
  await waitVisible(restored, ephemeral);
  assert.equal((await history(restored)).find(message => message.text === ephemeral).expiresAt, expiringRecord.expiresAt, 'Restoring cannot extend expiry');

  const afterExpiry = expiringRecord.expiresAt + 2000;
  await peers[0].clock.setSystemTime(new Date(afterExpiry));
  await peers[0].clock.runFor(5100);
  await waitStored(peers[0], ephemeral, false);
  assert(!(await peers[0].locator('#chat-log .message-text').allTextContents()).includes(ephemeral), 'Expired message disappears from visible transcript');
  await peers[0].reload();
  await waitStored(peers[0], ephemeral, false);
  await waitStored(peers[0], marker);
  const expiredRestore = await pageForDevice(afterExpiry);
  await expiredRestore.goto(origin);
  await openBackup(expiredRestore);
  await expiredRestore.locator('#backup-file').setInputFiles(backupPath);
  await expiredRestore.locator('#backup-password').fill(password);
  await expiredRestore.locator('#backup-import').click();
  await waitStored(expiredRestore, marker);
  assert(!(await history(expiredRestore)).some(message => message.text === ephemeral), 'Old backup cannot resurrect an expired message');

  for (const text of [marker, reply, ephemeral, hostile, pressure]) assert(traffic.every(frame => !frame.includes(text)), 'Chat plaintext must not traverse HTTP or signaling WebSocket traffic');
  assert.deepEqual(errors, [], 'No uncaught browser exceptions');
  console.log(JSON.stringify({ chatOnlyDeniedMedia: true, deviceOnlyQueue: true, ackBackpressureRecovery: true, reliableOrdered: true, bidirectionalAcknowledged: true, hostileTextInert: true, noChatInSignalingOrHttp: true, deviceHistoryReload: true, offlineShellAndHistory: true, encryptedBackup: true, wrongPasswordRejected: true, restoredOnFreshDevice: true, expiryPurged: true, backupCannotResurrectExpired: true, routes }));
} catch (error) {
  let detail = String(error?.stack || error);
  for (const sensitive of [process.env.ADMIN_TOKEN, password, marker, reply, ephemeral, hostile, pressure, ...(room?.participants.map(participant => participant.token) || [])]) {
    if (sensitive) detail = detail.replaceAll(sensitive, '[redacted]');
  }
  console.error(detail);
  process.exitCode = 1;
} finally {
  if (room) await api(`/rooms/${room.roomId}`, 'DELETE', room.participants[0].token).catch(() => {});
  await Promise.all(contexts.map(context => context.close().catch(() => {})));
  await browser?.close();
  await rm(directory, { recursive: true, force: true });
}
