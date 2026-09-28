// Runs web/test/crypto.html in a headless browser and exits non-zero on failure.
//
//   node web/test/run.mjs [firefox|chromium]
//
// No dependencies (see browser.mjs). The page loads from file://, exactly as a
// person opening it would.
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { launch, sleep } from './browser.mjs';

const TIMEOUT_MS = 300_000; // Argon2id at 64 MiB runs several times.
const browser = process.argv[2] ?? 'firefox';
if (browser !== 'firefox' && browser !== 'chromium') {
  console.error('usage: node web/test/run.mjs [firefox|chromium]');
  process.exit(2);
}
const page = pathToFileURL(join(dirname(fileURLToPath(import.meta.url)), 'crypto.html')).href;

const READ = `(() => {
  const s = document.getElementById('summary');
  return s && JSON.stringify({
    status: s.dataset.status,
    summary: s.textContent,
    results: Array.from(document.querySelectorAll('#results li'), (li) => [li.className, li.textContent]),
  });
})()`;

let b;
try {
  b = await launch(browser);
  await b.navigate(page);
  const deadline = Date.now() + TIMEOUT_MS;
  let state;
  for (;;) {
    const raw = await b.evaluate(READ);
    state = raw && JSON.parse(raw);
    if (state && state.status !== 'running') break;
    if (Date.now() > deadline) throw new Error('timed out waiting for the tests to finish');
    await sleep(500);
  }
  for (const [cls, text] of state.results) console.log(`${cls === 'pass' ? 'PASS' : 'FAIL'}  ${text}`);
  console.log(`\n${browser}: ${state.summary}`);
  b.close();
  process.exit(state.status === 'pass' ? 0 : 1);
} catch (err) {
  console.error(`${browser}: ${err.message}`);
  b?.close();
  process.exit(2);
}
