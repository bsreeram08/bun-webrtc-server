// Regenerates packages/signaling/public/emoji-data.json (shortcode → emoji) from the pinned gemoji package.
// The output is vendored with gemoji's MIT license (emoji-data.LICENSE) so the app needs no runtime dependency.
//   npm pack gemoji@8.1.0 && tar xzf gemoji-8.1.0.tgz
//   bun --no-env-file scripts/build-emoji-data.ts ./package/index.js
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const source = process.argv[2];
if (!source) throw new Error('Usage: bun scripts/build-emoji-data.ts <path to gemoji@8.1.0 index.js>');
const { gemoji } = await import(pathToFileURL(resolve(source)).href) as { gemoji: { emoji: string; names: string[] }[] };
const table: Record<string, string> = {};
for (const entry of gemoji) for (const name of entry.names) if (/^[a-z0-9_+-]{1,40}$/.test(name) && !(name in table)) table[name] = entry.emoji;
const out = resolve(import.meta.dir, '../packages/signaling/public/emoji-data.json');
writeFileSync(out, JSON.stringify(table));
console.log(`Wrote ${Object.keys(table).length} shortcodes to ${out}`);
