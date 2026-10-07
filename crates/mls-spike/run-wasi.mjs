// Runs the benchmark compiled to wasm32-wasip1 inside node's V8 (same engine as Chrome).
// cargo build --release --bin bench --target wasm32-wasip1 && node --no-warnings run-wasi.mjs 10 100 1000 2500
import { readFile } from 'node:fs/promises';
import { WASI } from 'node:wasi';

const wasi = new WASI({ version: 'preview1', args: ['bench', ...process.argv.slice(2)], env: {} });
const module = await WebAssembly.compile(await readFile(new URL('./target/wasm32-wasip1/release/bench.wasm', import.meta.url)));
const instance = await WebAssembly.instantiate(module, wasi.getImportObject());
wasi.start(instance);
