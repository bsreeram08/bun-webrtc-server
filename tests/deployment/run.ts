import { randomBytes } from 'node:crypto';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const root = resolve(import.meta.dir, '../..');
const id = `webrtc-stack-${randomBytes(5).toString('hex')}`;
const directory = await mkdtemp(join(tmpdir(), `${id}-`));
const images = ['coturn/coturn:4.17.2-r0', 'caddy:2.11.4-alpine', 'moby/buildkit:buildx-stable-1'];
const ownImages: string[] = [];
const containers: string[] = [];
const token = randomBytes(32).toString('hex');
const secret = randomBytes(32).toString('hex');
let builderCreated = false;
console.log(`Isolated deployment verification: ${id}`);
async function command(args: string[], allowedFailure = false) {
  const child = Bun.spawn(args, { cwd: root, stdout: 'pipe', stderr: 'pipe' });
  const [out, err, code] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
  if (code && !allowedFailure) throw new Error(`${args[0]} ${args[1]} failed (${code}): ${err.replaceAll(token, '[redacted]').replaceAll(secret, '[redacted]')}`);
  return { out, code };
}
async function docker(args: string[], allowedFailure = false) { return command(['docker', ...args], allowedFailure); }
async function removeContainer(name: string) {
  await docker(['rm', '-f', '-v', name], true);
  if (!(await docker(['container', 'inspect', name], true)).code) throw new Error(`Could not remove test container ${name}`);
  const index = containers.indexOf(name); if (index >= 0) containers.splice(index, 1);
}
try {
  await docker(['info', '--format', '{{.ServerVersion}}']);
  for (const image of images) {
    if ((await docker(['image', 'inspect', image], true)).code) ownImages.push(image);
  }
  await docker(['buildx', 'create', '--name', id, '--driver', 'docker-container']);
  builderCreated = true;
  ownImages.push(`${id}:test`);
  console.log('Building isolated verification image…');
  await docker(['buildx', 'build', '--builder', id, '--load', '-t', `${id}:test`, '.']);
  for (const file of ['app.js', 'chat-store.js', 'sw.js', 'index.html', 'style.css', 'install.js', 'manifest.webmanifest', 'icon-192.png', 'icon-512.png']) {
    const imageHash = (await docker(['run', '--rm', '--entrypoint', 'sha256sum', `${id}:test`, `/app/packages/signaling/public/${file}`])).out.split(/\s/)[0];
    const sourceHash = new Bun.CryptoHasher('sha256').update(await Bun.file(join(root, `packages/signaling/public/${file}`)).arrayBuffer()).digest('hex');
    if (sourceHash !== imageHash) throw new Error('Client changed during image build; rerun verification');
    console.log(`Verified ${file} SHA256 ${sourceHash}`);
  }
  for (const image of images.slice(0, 2)) await docker(['pull', image]);
  const turn = `${id}-turn`; containers.push(turn);
  await docker(['run', '-d', '--name', turn, '-p', '127.0.0.1:33479:33479/udp', '-p', '127.0.0.1:33479:33479/tcp', '-p', '127.0.0.1:49400-49439:49400-49439/udp', '-e', `TEST_TURN_SECRET=${secret}`,
    '--entrypoint', 'sh', images[0]!, '-c', 'exec turnserver --listening-port=33479 --listening-ip=0.0.0.0 --relay-ip="$(hostname -i)" --external-ip=127.0.0.1 --min-port=49400 --max-port=49439 --realm=localhost --use-auth-secret --static-auth-secret="$TEST_TURN_SECRET" --allow-loopback-peers --no-cli --no-tls --no-dtls --no-tcp-relay --log-file=stdout']);
  await writeFile(join(directory, 'Caddyfile'), '{\n admin off\n auto_https disable_redirects\n}\nhttps://localhost:9443 {\n tls internal\n reverse_proxy 127.0.0.1:3000 {\n header_up X-Real-IP {remote_host}\n }\n}\n');
  for (const transport of ['udp', 'tcp']) {
    const app = `${id}-${transport}-app`, proxy = `${id}-${transport}-proxy`;
    containers.push(app);
    await docker(['run', '-d', '--name', app, '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '-p', '127.0.0.1:9443:9443',
      '-e', 'HOST=127.0.0.1', '-e', 'PORT=3000', '-e', 'TRUST_PROXY=true', '-e', 'PUBLIC_ORIGIN=https://localhost:9443', '-e', `ADMIN_TOKEN=${token}`,
      '-e', `TURN_SECRET=${secret}`, '-e', `TURN_URLS=turn:127.0.0.1:33479?transport=${transport}`, '-e', 'RELAY_ONLY=true', `${id}:test`]);
    containers.push(proxy);
    await docker(['run', '-d', '--name', proxy, '--network', `container:${app}`, '--tmpfs', '/data', '--tmpfs', '/config',
      '-v', `${join(directory, 'Caddyfile')}:/etc/caddy/Caddyfile:ro`, images[1]!]);
    let healthy = false;
    for (let attempt = 0; attempt < 40; attempt++) {
      // Local test certificate validation bypass; no global TLS setting is changed.
      try { healthy = (await fetch('https://localhost:9443/health', { tls: { rejectUnauthorized: false } })).ok; } catch {}
      if (healthy) break;
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    if (!healthy) throw new Error('Caddy HTTPS health did not become ready');
    console.log(`Verifying HTTPS/WSS and TURN ${transport.toUpperCase()} media…`);
    const child = Bun.spawn(['node', 'tests/deployment/browser.mjs'], { cwd: root, env: {
      ...process.env, ADMIN_TOKEN: token, TEST_ORIGIN: 'https://localhost:9443', TURN_TRANSPORT: transport,
    }, stdout: 'inherit', stderr: 'inherit' });
    if (await child.exited) throw new Error(`Browser ${transport} verification failed`);
    const chat = Bun.spawn(['node', 'tests/browser/chat.mjs'], { cwd: root, env: {
      ...process.env, ADMIN_TOKEN: token, TEST_ORIGIN: 'https://localhost:9443', TEST_INSECURE_TLS: 'true', EXPECT_RELAY: 'true',
    }, stdout: 'inherit', stderr: 'inherit' });
    if (await chat.exited) throw new Error(`Device chat ${transport} verification failed`);
    await removeContainer(proxy);
    await removeContainer(app);
  }
} finally {
  const expectedContainers = [...containers];
  for (const name of [...containers].reverse()) { try { await removeContainer(name); } catch {} }
  if (builderCreated) await docker(['buildx', 'rm', id], true);
  for (const image of ownImages.reverse()) await docker(['image', 'rm', image], true);
  await rm(directory, { recursive: true, force: true });
  for (const name of expectedContainers) if (!(await docker(['container', 'inspect', name], true)).code) throw new Error(`Cleanup incomplete: ${name}`);
  for (const image of ownImages) if (!(await docker(['image', 'inspect', image], true)).code) throw new Error(`Cleanup incomplete: ${image}`);
  if (builderCreated && !(await docker(['buildx', 'inspect', id], true)).code) throw new Error(`Cleanup incomplete: builder ${id}`);
  console.log('Cleaned isolated stack containers, images, builder cache, and temporary files.');
}
