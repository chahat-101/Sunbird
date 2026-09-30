// End-to-end tests: build the server, run it on an empty data directory, and
// drive the real page in a headless browser. Covers upload, open, download,
// and what a hostile server can do by editing blobs on disk.
//
//   node web/test/e2e.mjs [firefox|chromium] [--phone]
//
// --phone runs everything at 390×844. Written for the old Go server and kept
// as the conformance test; only the build line changed.
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, sleep } from './browser.mjs';

const args = process.argv.slice(2);
const browser = args.find((arg) => !arg.startsWith('--')) ?? 'firefox';
const phone = args.includes('--phone');
const PHONE = [390, 844];
const root =join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const work = mkdtempSync(join(tmpdir(), 'sunbird-e2e-'));
const dataDir = join(work, 'data');

const NEWER_VERSION = 'This link was created by a newer version of Sunbird. Update your client.';
const NO_FILE = 'There is no file at this link: it expired, was deleted, or the link is wrong.';
const WEEK = 604800;
const nowSeconds = () => Math.floor(Date.now() / 1000);
// The upload query for limits read out of a blob's header, as a client must send them.
const limitsOf = (blob) => `expires_at=${blob.readBigUInt64BE(18)}&max_downloads=${blob.readUInt32BE(26)}`;
const KAT_FRAGMENT = 'AAECAwQFBgcICQoLDA0ODw';
// crypto.html's KAT.pwKey: Argon2id of "é sunbird" over salt 10..1f, from an independent implementation.
const KAT_PW_KEY = 'c5149c70ce74d0f923b88f8e36ece0c580fe7a12b3575728dbf804174fddcc4a';
// Tokens as `sunbird mint-token` makes them; only their hashes go in the config.
const TOKEN = randomBytes(16).toString('base64url');
const SMALL_TOKEN = randomBytes(16).toString('base64url'); // a member with a 2000-byte quota
const BAD_TOKEN = 'The server did not accept this upload token. Check it, or ask the admin whether it is still valid.';

// ---- helpers --------------------------------------------------------------

function pattern(n, seed) {
  const u = new Uint8Array(n);
  for (let i = 0; i < n; i++) u[i] = (i * 31 + seed) % 251;
  return u;
}
const sha256 = (u8) => createHash('sha256').update(u8).digest('hex');
const blobPath = (id) => join(dataDir, 'blobs', Buffer.from(id, 'base64url').toString('hex'));
const idOf = (link) => new URL(link).pathname.slice(3);

function eq(actual, expected, what) {
  if (actual !== expected) throw new Error(`${what}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}
function ok(condition, what) {
  if (!condition) throw new Error(what);
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

// Added to the page after each load: captures would-be saves and upload URLs,
// and can skew the clock.
function pageLib() {
  const pattern = (n, seed) => {
    const u = new Uint8Array(n);
    if (n > 16e6) return u;
    for (let i = 0; i < n; i++) u[i] = (i * 31 + seed) % 251;
    return u;
  };
  const hex = async (u8) => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', u8)),
    (x) => x.toString(16).padStart(2, '0')).join('');
  const saved = [];
  const createObjectURL = URL.createObjectURL.bind(URL);
  URL.createObjectURL = (blob) => { saved.push({ blob }); return createObjectURL(blob); };
  HTMLAnchorElement.prototype.click = function () {
    if (saved.length) saved[saved.length - 1].download = this.download;
  };
  const uploadUrls = [];
  const redirects = new Map();
  const realFetch = window.fetch.bind(window);
  window.fetch = (url, options) => {
    if (String(url).includes('/api/upload')) uploadUrls.push(String(url));
    return realFetch(redirects.get(String(url)) ?? url, options);
  };
  // The page uploads with XMLHttpRequest, for its progress events.
  const realOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    if (String(url).includes('/api/upload')) uploadUrls.push(String(url));
    return realOpen.call(this, method, url, ...rest);
  };
  const realNow = Date.now;
  window.T = {
    pattern,
    uploads: () => uploadUrls.length,
    uploadUrls: () => uploadUrls,
    skew: (seconds) => { Date.now = () => realNow() + seconds * 1000; },
    redirect: (from, to) => { redirects.set(from, to); },
    setFile(name, type, size, seed) {
      const dt = new DataTransfer();
      dt.items.add(new File([pattern(size, seed)], name, { type }));
      document.getElementById('file').files = dt.files;
      return document.getElementById('file').files[0].name;
    },
    saved: () => Promise.all(saved.map(async (s) => ({
      download: s.download, type: s.blob.type, size: s.blob.size,
      sha256: await hex(new Uint8Array(await s.blob.arrayBuffer())),
    }))),
  };
  return true;
}

// Added before the page's own scripts: counts Argon2id calls and main-thread
// stalls, and records every request and status change.
function probe() {
  const seen = { argon2id: 0, requests: [], stretches: [] };
  window.__probe = seen;
  const path = (url) => new URL(String(url), location.href).pathname;
  const realFetch = window.fetch.bind(window);
  window.fetch = (url, options) => {
    seen.requests.push(`${(options && options.method) || 'GET'} ${path(url)}`);
    return realFetch(url, options);
  };
  const realOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    seen.requests.push(`${method} ${path(url)}`);
    return realOpen.call(this, method, url, ...rest);
  };

  // Each record holds the value before a change.
  const log = [];
  const phases = new MutationObserver((records) => { for (const r of records) log.push([r.target.id, r.oldValue]); });
  phases.observe(document, { subtree: true, attributes: true, attributeFilter: ['data-phase'], attributeOldValue: true });
  seen.phasesOf = (id) => {
    for (const r of phases.takeRecords()) log.push([r.target.id, r.oldValue]);
    const values = [...log.filter(([of]) => of === id).map(([, v]) => v).slice(1), document.getElementById(id).dataset.phase];
    return values.filter((v, i) => v !== values[i - 1]);
  };

  // A browser restoring form state on reload: the box is ticked before the page's script runs.
  if (location.search === '?restored-ticked') {
    new MutationObserver((_, observer) => {
      const box = document.getElementById('protect');
      if (box) { box.checked = true; observer.disconnect(); }
    }).observe(document, { childList: true, subtree: true });
  }

  // A 10 ms timer runs during each Argon2id call; if the main thread did the
  // work, it would miss every tick.
  document.addEventListener('DOMContentLoaded', () => {
    const real = window.hashwasm && window.hashwasm.argon2id;
    if (typeof real !== 'function') return;
    window.hashwasm.argon2id = (...args) => {
      seen.argon2id++;
      const started = performance.now();
      let last = started;
      let longest = 0;
      const timer = setInterval(() => {
        const now = performance.now();
        longest = Math.max(longest, now - last);
        last = now;
      }, 10);
      const settle = () => {
        clearInterval(timer);
        const end = performance.now();
        seen.stretches.push({ ms: Math.round(end - started), longestPause: Math.round(Math.max(longest, end - last)) });
      };
      const result = real(...args);
      result.then(settle, settle);
      return result;
    };
  });
}

let b;

async function go(url) {
  await b.navigate(url);
  await b.evaluate(`(${pageLib})()`);
}

// Runs fn in the page with JSON arguments; returns its JSON result.
async function inPage(fn, ...args) {
  const raw = await b.evaluate(`(async () => JSON.stringify(await (${fn})(...${JSON.stringify(args)})))()`);
  return raw === undefined ? undefined : JSON.parse(raw);
}

const readStatus = (id) => inPage((id) => {
  const el = document.getElementById(id);
  return { state: el.dataset.state ?? '', text: el.textContent };
}, id);

async function waitState(id, states, timeout = 60_000) {
  const deadline = Date.now() + timeout;
  for (;;) {
    const s = await readStatus(id);
    if (states.includes(s.state)) return s;
    if (Date.now() > deadline) throw new Error(`#${id} never reached ${states.join('/')}: last ${JSON.stringify(s)}`);
    await sleep(50);
  }
}

// `expiry` and `downloads` are form values; `skew` shifts the page's clock.
async function uploadViaForm({ name, type, size, seed, passphrase, expiry, downloads, skew, token = TOKEN, origin = base }) {
  await go(`${origin}/`);
  const kept = await inPage((name, type, size, seed, passphrase, expiry, downloads, skew, token) => {
    document.getElementById('upload-token').value = token;
    const kept = T.setFile(name, type, size, seed);
    if (passphrase !== null) {
      const protect = document.getElementById('protect');
      protect.checked = true;
      protect.dispatchEvent(new Event('change'));
      document.getElementById('passphrase').value = passphrase;
    }
    if (expiry !== null) document.getElementById('expiry').value = expiry;
    if (downloads !== null) document.getElementById('downloads').value = downloads;
    if (skew !== null) T.skew(skew);
    document.getElementById('upload-button').click();
    return kept;
  }, name, type, size, seed, passphrase ?? null, expiry ?? null, downloads ?? null, skew ?? null, token);
  const status = await waitState('upload-status', ['done', 'error']);
  const result = await inPage(() => ({
    link: document.getElementById('link').value,
    token: document.getElementById('owner-token').textContent,
    shown: !document.getElementById('result').hidden,
    text: document.getElementById('result').textContent,
    uploadUrls: T.uploadUrls(),
  }));
  return { status, kept, ...result };
}

// Uploads hand-built bytes, bypassing the form. `build` is inlined because
// the CSP forbids eval.
async function uploadRaw(build) {
  await go(`${base}/`);
  return b.evaluate(`(async () => {
    const { blob, fragment } = await (${build})();
    const limits = 'expires_at=' + (Math.floor(Date.now() / 1000) + 3600) + '&max_downloads=0';
    const { id } = await (await fetch('/api/upload?' + limits, {
      method: 'POST', body: blob, headers: { Authorization: 'Bearer ' + ${JSON.stringify(TOKEN)} },
    })).json();
    return location.origin + '/d/' + id + (fragment ? '#' + fragment : '');
  })()`);
}

const details = () => inPage(() => ({
  name: document.getElementById('file-name').textContent,
  nameChildren: document.getElementById('file-name').children.length,
  size: document.getElementById('file-size').textContent,
  limit: document.getElementById('file-limit').textContent,
  warningHidden: document.getElementById('expired-warning').hidden,
  warning: document.getElementById('expired-warning').textContent,
  unlockHidden: document.getElementById('unlock').hidden,
  pwned: window.__pwned === 1,
}));

async function clickDownload() {
  await inPage(() => { document.getElementById('download-button').click(); });
  return waitState('download-status', ['done', 'error']);
}

// ---- tests ----------------------------------------------------------------

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

test('server: serves the client with its CSP at / and /d/<id>, and nothing else from web/', async () => {
  // The page is embedded: the server runs in a directory with no web/ beside it.
  ok(!existsSync(join(work, 'web')), 'the server\'s working directory has a web/');
  for (const path of ['/', '/d/AAAAAAAAAAAAAAAA']) {
    const r = await fetch(base + path);
    eq(r.status, 200, `${path} status`);
    ok(r.headers.get('content-type').startsWith('text/html'), `${path} content type`);
    ok(r.headers.get('content-security-policy').includes("script-src 'self' 'wasm-unsafe-eval'"), `${path} CSP`);
  }
  for (const path of ['/app.css', '/src/app.js', '/src/crypto.js', '/src/argon2.js', '/src/argon2-worker.js', '/vendor/hash-wasm/argon2.umd.min.js']) {
    const r = await fetch(base + path);
    eq(r.status, 200, `${path} status`);
    // A Worker takes its policy from its own response, not from the page.
    ok(r.headers.get('content-security-policy') === (await fetch(`${base}/`)).headers.get('content-security-policy'), `${path} CSP`);
  }
  for (const path of ['/test/crypto.html', '/test/e2e.mjs', '/web.go', '/src/', '/vendor/hash-wasm/']) {
    eq((await fetch(base + path)).status, 404, `${path} status`);
  }
});

test('form: defaults are 24 hours and 1 download; at most 7 days; no "0 downloads" option', async () => {
  await go(`${base}/`);
  const form = await inPage(() => ({
    expiry: document.getElementById('expiry').value,
    expiries: Array.from(document.getElementById('expiry').options, (o) => Number(o.value)),
    downloads: document.getElementById('downloads').value,
    limits: Array.from(document.getElementById('downloads').options, (o) => [o.value, o.textContent]),
    passphraseDisabled: document.getElementById('passphrase').disabled,
  }));
  eq(form.expiry, '86400', 'default expiry');
  ok(Math.max(...form.expiries) <= 604800, `an expiry over 7 days is offered: ${form.expiries}`);
  eq(form.downloads, '1', 'default download limit');
  for (const [value, text] of form.limits) {
    ok(!/^\s*0\b/.test(text), `an option reads as zero downloads: ${text}`);
    if (value === '0') ok(/No download limit/.test(text), `value 0 is not labelled as no limit: ${text}`);
  }
  ok(form.passphraseDisabled, 'passphrase field enabled without the box ticked');
});

test('restricted: upload through the form; open the link; wrong then right passphrase; bytes match', async () => {
  const size = 2 * 65519 + 123;
  const passphrase = 'correct horse ≠ battery';
  const up = await uploadViaForm({
    name: '<img src=x onerror="window.__pwned=1">नम/..\\evil.html', type: 'text/html', size, seed: 7, passphrase,
  });
  eq(up.status.state, 'done', `upload: ${up.status.text}`);
  ok(up.shown, 'result not shown');
  ok(new RegExp(`^${base}/d/[A-Za-z0-9_-]{16}#[A-Za-z0-9_-]{22}$`).test(up.link), `link ${up.link}`);
  ok(/^[A-Za-z0-9_-]{43}$/.test(up.token), `owner token ${up.token}`);
  ok(/never reaches\s+the server/.test(up.text), 'no note that the fragment never reaches the server');
  ok(/shown once/.test(up.text) && /cannot be recovered/.test(up.text), 'no warning that the token is shown once');

  // What went to the server: flag set, expiry now + 24 h, limit 1 — and no plaintext name.
  const stored = readFileSync(blobPath(idOf(up.link)));
  eq(stored[1], 1, 'stored flags');
  const expires = Number(stored.readBigUInt64BE(18));
  ok(Math.abs(expires - (Math.floor(Date.now() / 1000) + 86400)) < 300, `stored expires_at ${expires}`);
  eq(stored.readUInt32BE(26), 1, 'stored max_downloads');
  ok(!stored.includes(Buffer.from('evil')), 'the filename is readable in the stored blob');
  eq(up.uploadUrls.length, 1, 'uploads');
  eq(new URL(up.uploadUrls[0], base).search, `?${limitsOf(stored)}`, 'limits sent beside the blob vs sealed in its header');

  await go(up.link);
  await waitState('download-status', ['waiting']);
  await inPage(() => {
    document.getElementById('unlock-passphrase').value = 'wrong';
    document.getElementById('unlock').requestSubmit();
  });
  eq((await waitState('download-status', ['error'])).text, 'Wrong passphrase, or the link is damaged.', 'wrong passphrase message');
  await inPage((p) => {
    document.getElementById('unlock-passphrase').value = p;
    document.getElementById('unlock').requestSubmit();
  }, passphrase);
  await waitState('download-status', ['ready']);

  const d = await details();
  eq(d.name, up.kept, 'name shown');
  eq(d.nameChildren, 0, 'name rendered as elements');
  ok(!d.pwned, 'the filename ran as markup');
  ok(d.warningHidden, 'expiry warning shown for a live link');
  eq(d.limit, '1 download', 'limit shown');
  ok(d.unlockHidden, 'passphrase form still shown');

  const done = await clickDownload();
  eq(done.state, 'done', `download: ${done.text}`);
  const saved = await inPage(() => T.saved());
  eq(saved.length, 1, 'files saved');
  eq(saved[0].sha256, sha256(pattern(size, 7)), 'saved bytes');
  eq(saved[0].type, 'application/octet-stream', 'saved Blob type (never the metadata type)');
  ok(!/[/\\]/.test(saved[0].download), `download name keeps a path separator: ${saved[0].download}`);
  eq(saved[0].download, up.kept.replace(/[/\\]/g, ''), 'download name');
});

test('public: a 0-byte file opens with no passphrase prompt', async () => {
  const up = await uploadViaForm({ name: 'empty.txt', type: 'text/plain', size: 0, seed: 0 });
  eq(up.status.state, 'done', `upload: ${up.status.text}`);
  eq(readFileSync(blobPath(idOf(up.link)))[1], 0, 'stored flags');
  await go(up.link);
  await waitState('download-status', ['ready']);
  ok((await details()).unlockHidden, 'a passphrase was asked for');
  eq((await clickDownload()).state, 'done', 'download');
  const saved = await inPage(() => T.saved());
  eq(saved[0].size, 0, 'saved size');
});

const shownIds = (...ids) => inPage((ids) => ids.filter((id) => !document.getElementById(id).hidden), ids);
const probed = () => inPage(() => ({ argon2id: __probe.argon2id, requests: __probe.requests }));

const readMode = () => inPage(() => ({
  checked: document.getElementById('protect').checked,
  shown: ['mode-public', 'mode-restricted'].filter((id) => !document.getElementById(id).hidden),
  publicText: document.getElementById('mode-public').textContent.replace(/\s+/g, ' '),
  passphraseDisabled: document.getElementById('passphrase').disabled,
  button: document.getElementById('upload-button').textContent.replace(/\s+/g, ' '),
}));

test('mode at upload: says a public link opens for anyone holding it, on the button too; the box switches it; unticked disables the passphrase', async () => {
  await go(`${base}/`);
  const toggle = () => inPage(() => { document.getElementById('protect').click(); });
  const start = await readMode();
  eq(JSON.stringify(start.shown), '["mode-public"]', 'unticked: explanation shown');
  ok(/anyone who has the link can open this file/.test(start.publicText), `public explanation: ${start.publicText}`);
  ok(/no passphrase or other second factor/.test(start.publicText), `public explanation: ${start.publicText}`);
  ok(start.passphraseDisabled, 'unticked: passphrase field enabled');
  ok(/public link/.test(start.button) && !/passphrase/.test(start.button), `unticked: button reads ${start.button}`);
  await toggle();
  const ticked = await readMode();
  eq(JSON.stringify(ticked.shown), '["mode-restricted"]', 'ticked: explanation shown');
  ok(!ticked.passphraseDisabled, 'ticked: passphrase field disabled');
  ok(/passphrase-protected/.test(ticked.button) && !/public/.test(ticked.button), `ticked: button reads ${ticked.button}`);
  await toggle();
  const unticked = await readMode();
  eq(JSON.stringify(unticked.shown), '["mode-public"]', 'unticked again: explanation shown');
  ok(unticked.passphraseDisabled, 'unticked again: passphrase field enabled');
  ok(/public link/.test(unticked.button), `unticked again: button reads ${unticked.button}`);
});

test('mode at load: a box the browser restored ticked is followed before any change event — field, explanation, button', async () => {
  // A query, not a fragment: from `/`, a new fragment would not reload the page.
  await go(`${base}/?restored-ticked`);
  const restored = await readMode();
  ok(restored.checked, 'the probe did not tick the box before the page ran');
  ok(!restored.passphraseDisabled, 'passphrase field disabled with the box ticked');
  eq(JSON.stringify(restored.shown), '["mode-restricted"]', 'explanation shown');
  ok(/passphrase-protected/.test(restored.button), `button reads ${restored.button}`);
});

// Upload through the form, open the link, download; what the page said and did.
async function modeRoundTrip(passphrase) {
  const size = 70000;
  const seed = passphrase ? 12 : 13;
  const up = await uploadViaForm({ name: 'mode.bin', type: '', size, seed, passphrase });
  eq(up.status.state, 'done', `upload: ${up.status.text}`);
  const id = idOf(up.link);
  const flags = readFileSync(blobPath(id))[1];
  const sent = await probed();
  const link = await shownIds('link-public', 'link-restricted');

  await go(up.link);
  const first = await waitState('download-status', ['waiting', 'ready', 'error']);
  const beforePrompt = await shownIds('download-public', 'download-restricted', 'unlock');
  if (passphrase) {
    await inPage((p) => {
      document.getElementById('unlock-passphrase').value = p;
      document.getElementById('unlock').requestSubmit();
    }, passphrase);
    await waitState('download-status', ['ready']);
  }
  eq((await clickDownload()).state, 'done', 'download');
  eq((await inPage(() => T.saved()))[0].sha256, sha256(pattern(size, seed)), 'saved bytes');
  const opened = await probed();
  return {
    flags, link, first, beforePrompt,
    upload: { argon2id: sent.argon2id, requests: sent.requests },
    download: { argon2id: opened.argon2id, requests: opened.requests.map((r) => r.replace(id, '<id>')) },
  };
}

test('one path (D4): same requests in both modes; Argon2id only with a passphrase; the mode is said before any prompt', async () => {
  const pub = await modeRoundTrip(undefined);
  const res = await modeRoundTrip('a passphrase');
  eq(pub.flags, 0, 'public: stored flags');
  eq(res.flags, 1, 'restricted: stored flags');

  // Asserted on the call, never on elapsed time. The restricted counts show the probe works.
  eq(pub.upload.argon2id, 0, 'public upload: Argon2id calls');
  eq(pub.download.argon2id, 0, 'public download: Argon2id calls');
  eq(res.upload.argon2id, 1, 'restricted upload: Argon2id calls');
  eq(res.download.argon2id, 1, 'restricted download: Argon2id calls');

  eq(JSON.stringify(pub.upload.requests), '["POST /api/upload"]', 'public upload: requests');
  eq(JSON.stringify(pub.download.requests), '["GET /api/meta/<id>","GET /api/download/<id>"]', 'public download: requests');
  eq(JSON.stringify(res.upload.requests), JSON.stringify(pub.upload.requests), 'upload requests, restricted vs public');
  eq(JSON.stringify(res.download.requests), JSON.stringify(pub.download.requests), 'download requests, restricted vs public');

  eq(JSON.stringify(pub.link), '["link-public"]', 'public: link explanation shown');
  eq(JSON.stringify(res.link), '["link-restricted"]', 'restricted: link explanation shown');
  eq(pub.first.state, 'ready', 'public: first settled state (never waiting)');
  ok(!/passphrase/i.test(pub.first.text), `public status mentions a passphrase: ${pub.first.text}`);
  eq(JSON.stringify(pub.beforePrompt), '["download-public"]', 'public: shown on opening');
  eq(res.first.state, 'waiting', 'restricted: first settled state');
  eq(JSON.stringify(res.beforePrompt), '["download-restricted","unlock"]', 'restricted: shown while the prompt waits');
});

// crypto.html covers this attack in crypto.js; this runs it through the page.
test('server clears flags bit 0 on a restricted file: nothing is asked, the file does not open, nothing saved', async () => {
  const up = await uploadViaForm({ name: 'r.txt', type: 'text/plain', size: 2000, seed: 14, passphrase: 'secret' });
  eq(up.status.state, 'done', `upload: ${up.status.text}`);
  const path = blobPath(idOf(up.link));
  const blob = readFileSync(path);
  eq(blob[1], 1, 'stored flags');
  blob[1] = 0;
  writeFileSync(path, blob);

  await go(up.link);
  const status = await waitState('download-status', ['waiting', 'ready', 'error']);
  eq(status.state, 'error', 'state');
  eq(status.text, 'This link does not open the file: the link is damaged or incomplete.', 'message');
  eq((await probed()).argon2id, 0, 'Argon2id calls');
  eq(JSON.stringify(await shownIds('unlock', 'details')), '[]', 'a prompt or file details shown');
  eq((await inPage(() => T.saved())).length, 0, 'files saved');
});

async function publicReady(size, seed) {
  const up = await uploadViaForm({ name: 'f.bin', type: '', size, seed });
  eq(up.status.state, 'done', `upload: ${up.status.text}`);
  await go(up.link);
  await waitState('download-status', ['ready']);
  const id = idOf(up.link);
  return { id, path: blobPath(id), link: up.link };
}

// The server only sends as many bytes as its row says, so the grown blob is
// uploaded as a second file and the download is redirected to it.
test('slot grown between preview and download: records start after the downloaded slot', async () => {
  const size = 70000;
  const { id, path } = await publicReady(size, 3);
  const blob = readFileSync(path);
  eq(blob[558], 1, 'entry count before');
  const grown = Buffer.concat([blob.subarray(0, 558), Buffer.from([2]), blob.subarray(559, 622),
    Buffer.from([0x7f, 0x00, 0x05, 1, 2, 3, 4, 5]), blob.subarray(622)]);
  const { id: grownId } = await (await fetch(`${base}/api/upload?${limitsOf(grown)}`, {
    method: 'POST', body: grown, headers: { Authorization: `Bearer ${TOKEN}` },
  })).json();
  await inPage((from, to) => T.redirect(from, to), `/api/download/${id}`, `/api/download/${grownId}`);
  const done = await clickDownload();
  eq(done.state, 'done', `download: ${done.text}`);
  eq((await inPage(() => T.saved()))[0].sha256, sha256(pattern(size, 3)), 'saved bytes');
});

test('header_core changed between preview and download: rejected, nothing saved', async () => {
  const { path } = await publicReady(5000, 4);
  const blob = readFileSync(path);
  blob[29] ^= 0x01; // max_downloads
  writeFileSync(path, blob);
  const done = await clickDownload();
  eq(done.state, 'error', 'download state');
  ok(/does not match its preview/.test(done.text), `message: ${done.text}`);
  eq((await inPage(() => T.saved())).length, 0, 'files saved');
});

test('a flipped byte in the last record: rejected as corrupted, nothing saved', async () => {
  const { path } = await publicReady(100000, 5);
  const blob = readFileSync(path);
  blob[blob.length - 5] ^= 0x01;
  writeFileSync(path, blob);
  const done = await clickDownload();
  eq(done.state, 'error', 'download state');
  ok(/^The file is corrupted or was altered, so nothing was saved\./.test(done.text), `message: ${done.text}`);
  eq((await inPage(() => T.saved())).length, 0, 'files saved');
});

// The server refuses expired files, so the §8 warning needs a skewed clock:
// the recipient's clock is two hours fast.
test('past expires_at by the recipient\'s clock (§8): warns prominently and still downloads', async () => {
  const up = await uploadViaForm({ name: 'late.txt', type: 'text/plain', size: 1000, seed: 9, passphrase: 'p', expiry: '3600', downloads: '0' });
  eq(up.status.state, 'done', `upload: ${up.status.text}`);
  await go(up.link);
  await waitState('download-status', ['waiting']);
  await inPage(() => {
    T.skew(2 * 3600);
    document.getElementById('unlock-passphrase').value = 'p';
    document.getElementById('unlock').requestSubmit();
  });
  await waitState('download-status', ['ready']);
  const d = await details();
  ok(!d.warningHidden, 'no expiry warning');
  ok(/^The sender set this link to expire on .+\. The server provided it anyway\.$/.test(d.warning), `warning: ${d.warning}`);
  eq(d.limit, 'none (expires by time only)', 'limit shown');
  eq((await clickDownload()).state, 'done', 'download');
  eq((await inPage(() => T.saved()))[0].sha256, sha256(pattern(1000, 9)), 'saved bytes');
});

test('expiry vs the sender\'s clock: 7 days is sealed a few minutes short; fast and slow clocks', async () => {
  const before = nowSeconds();
  const up = await uploadViaForm({ name: 'week.txt', type: 'text/plain', size: 10, seed: 1, expiry: String(WEEK) });
  eq(up.status.state, 'done', `7 days: ${up.status.text}`);
  const stored = readFileSync(blobPath(idOf(up.link)));
  const expires = Number(stored.readBigUInt64BE(18));
  ok(expires < before + WEEK && expires > before + WEEK - 600, `7 days sealed as ${expires - before} s from now`);
  eq(new URL(up.uploadUrls[0], base).search, `?${limitsOf(stored)}`, 'limits sent vs sealed');

  const fast = await uploadViaForm({ name: 'week.txt', type: 'text/plain', size: 10, seed: 1, expiry: String(WEEK), skew: 240 });
  eq(fast.status.state, 'done', `7 days, clock 240 s fast: ${fast.status.text}`);

  const tooFast = await uploadViaForm({ name: 'week.txt', type: 'text/plain', size: 10, seed: 1, expiry: String(WEEK), skew: 400 });
  eq(tooFast.status.state, 'error', '7 days, clock 400 s fast: state');
  eq(tooFast.status.text, 'The server refused this upload: expires_at is more than 7 days after the server\'s clock. Your device\'s clock may be wrong.',
    '7 days, clock 400 s fast: message');
  ok(!tooFast.shown, 'a link was shown for a refused upload');

  const slow = await uploadViaForm({ name: 'hour.txt', type: 'text/plain', size: 10, seed: 1, expiry: '3600', skew: -7200 });
  eq(slow.status.state, 'error', '1 hour, clock 2 h slow: state');
  eq(slow.status.text, 'The server refused this upload: expires_at is not after the server\'s clock. Your device\'s clock may be wrong.',
    '1 hour, clock 2 h slow: message');
});

test('a 1-download link: deleted after the download; the next visit finds no file', async () => {
  const { id, link } = await publicReady(3000, 6);
  eq((await clickDownload()).state, 'done', 'download');
  for (const deadline = Date.now() + 5000; existsSync(blobPath(id)); await sleep(50)) {
    ok(Date.now() < deadline, 'blob still on disk after its only download');
  }
  // The page is still at `link`; navigating to the same URL would not reload it.
  await go(`${base}/`);
  await go(link);
  eq((await waitState('download-status', ['error'])).text, NO_FILE, 'second visit');
});

test('unknown version: the §9 message, verbatim; only unknown slot entries: the §5 message', async () => {
  const v2 = await uploadRaw(async () => {
    const bytes = new Uint8Array(700);
    bytes[0] = 0x02;
    return { blob: new Blob([bytes]) };
  });
  await go(`${v2}#${KAT_FRAGMENT}`);
  eq((await waitState('download-status', ['error'])).text, NEWER_VERSION, 'version 0x02');

  const unknown = await uploadRaw(async () => {
    const bytes = new Uint8Array(558 + 1 + 3 + 17);
    bytes[0] = 0x01;
    bytes[558] = 1; bytes[559] = 0x7f;
    return { blob: new Blob([bytes]) };
  });
  await go(`${unknown}#${KAT_FRAGMENT}`);
  eq((await waitState('download-status', ['error'])).text, 'This link needs a newer version of Sunbird.', 'unknown entry type');
});

test('upload refusals: too large, empty passphrase — decided before any work; nothing uploaded', async () => {
  await go(`${base}/`);
  const tooLarge = await inPage(() => {
    T.setFile('big.bin', '', 104857601, 0);
    document.getElementById('upload-button').click();
    const el = document.getElementById('upload-status'); // read synchronously: no await has run
    return { state: el.dataset.state, text: el.textContent, uploads: T.uploads() };
  });
  eq(tooLarge.state, 'error', 'too large: state');
  eq(tooLarge.text, 'This file is larger than 100 MiB, the most Sunbird can send.', 'too large: message');
  eq(tooLarge.uploads, 0, 'too large: uploads');

  const empty = await inPage(() => {
    T.setFile('a.txt', 'text/plain', 10, 0);
    const protect = document.getElementById('protect');
    protect.checked = true;
    protect.dispatchEvent(new Event('change'));
    document.getElementById('upload-button').click();
    const el = document.getElementById('upload-status');
    return { state: el.dataset.state, text: el.textContent, uploads: T.uploads() };
  });
  eq(empty.state, 'error', 'empty passphrase: state');
  ok(/Enter a passphrase/.test(empty.text), `empty passphrase: ${empty.text}`);
  eq(empty.uploads, 0, 'empty passphrase: uploads');
});

test('upload refusal: a name too long says so; nothing uploaded', async () => {
  const up = await uploadViaForm({ name: `${'क'.repeat(200)}.txt`, type: 'text/plain', size: 10, seed: 0 });
  eq(up.status.state, 'error', 'state');
  ok(/name is too long/.test(up.status.text), `message: ${up.status.text}`);
  eq(await inPage(() => T.uploads()), 0, 'uploads');
  ok(!up.shown, 'a link was shown');
});

test('upload token: the page says the server is shared and the token identifies the uploader; none and wrong refused', async () => {
  await go(`${base}/`);
  const note = await inPage(() => document.getElementById('token-note').textContent.replace(/\s+/g, ' '));
  ok(/shared server/.test(note), `no shared-server note: ${note}`);
  ok(/identifies you to the server's admin/.test(note), `no note that the token identifies the uploader: ${note}`);

  const none = await uploadViaForm({ name: 'a.txt', type: 'text/plain', size: 10, seed: 0, token: '' });
  eq(none.status.state, 'error', 'no token: state');
  ok(/^Enter your upload token\./.test(none.status.text), `no token: ${none.status.text}`);
  eq(none.uploadUrls.length, 0, 'no token: uploads');

  const wrong = await uploadViaForm({ name: 'a.txt', type: 'text/plain', size: 10, seed: 0, token: 'not-a-member-token' });
  eq(wrong.status.state, 'error', 'wrong token: state');
  eq(wrong.status.text, BAD_TOKEN, 'wrong token: message');
  ok(!wrong.shown, 'a link was shown for a refused upload');

  const direct = await fetch(`${base}/api/upload?expires_at=${nowSeconds() + 3600}&max_downloads=0`, { method: 'POST', body: 'x' });
  eq(direct.status, 401, 'upload with no Authorization header');
});

test('upload token: remembered in the browser only when asked, and only once accepted', async () => {
  await go(`${base}/`);
  const stored = () => inPage(() => localStorage.getItem('sunbird.uploadToken'));
  await inPage(() => { document.getElementById('remember-token').checked = true; });
  const up = await uploadViaForm({ name: 'a.txt', type: 'text/plain', size: 10, seed: 0 });
  // uploadViaForm navigated afresh, so the box was unticked for that upload.
  eq(up.status.state, 'done', `upload: ${up.status.text}`);
  eq(await stored(), null, 'remembered without the box ticked');

  await inPage((token) => {
    document.getElementById('upload-token').value = 'not-a-member-token';
    document.getElementById('remember-token').checked = true;
    T.setFile('a.txt', 'text/plain', 10, 0);
    document.getElementById('upload-button').click();
  }, TOKEN);
  await waitState('upload-status', ['done', 'error']);
  eq(await stored(), null, 'a refused token was remembered');

  await inPage((token) => {
    document.getElementById('upload-token').value = ` ${token}\n`;
    document.getElementById('upload-button').click();
  }, TOKEN);
  eq((await waitState('upload-status', ['done', 'error'])).state, 'done', 'upload with the box ticked');
  eq(await stored(), TOKEN, 'remembered token');
  await go(`${base}/`);
  eq(await inPage(() => [document.getElementById('upload-token').value, document.getElementById('remember-token').checked]).then(JSON.stringify),
    JSON.stringify([TOKEN, true]), 'field after reload');
  await inPage(() => {
    const box = document.getElementById('remember-token');
    box.checked = false;
    box.dispatchEvent(new Event('change'));
  });
  eq(await stored(), null, 'unticking did not forget the token');
});

test('quota: a refused upload shows which limit, and stores nothing', async () => {
  const up = await uploadViaForm({ name: 'big.bin', type: '', size: 5000, seed: 2, token: SMALL_TOKEN });
  eq(up.status.state, 'error', 'state');
  eq(up.status.text, 'Over your upload quota. This upload is larger than your limit of 2000 bytes stored at once.', 'message');
  ok(!up.shown, 'a link was shown for a refused upload');
});

test('bad links: no such file; damaged fragment', async () => {
  await go(`${base}/d/AAAAAAAAAAAAAAAA#${KAT_FRAGMENT}`);
  eq((await waitState('download-status', ['error'])).text, NO_FILE, 'unknown id');
  await go(`${base}/d/BBBBBBBBBBBBBBBB#${KAT_FRAGMENT.slice(0, 21)}`);
  ok(/^This link is damaged or incomplete\./.test((await readStatus('download-status')).text), 'short fragment');
});

// ---- the UI step: workers, progress, drops, copying, errors, phones --------

test('passphrase worker: the page runs Argon2id off its main thread, gives the known answer, and keeps running meanwhile', async () => {
  await go(`${base}/`);
  const page = await inPage(async () => {
    const password = new TextEncoder().encode('é sunbird');
    const salt = Uint8Array.from({ length: 16 }, (_, i) => 0x10 + i);
    const key = await hashwasm.argon2id({
      password, salt, iterations: 3, memorySize: 65536, parallelism: 1, hashLength: 32, outputType: 'binary',
    });
    return {
      key: Array.from(key, (x) => x.toString(16).padStart(2, '0')).join(''),
      scripts: Array.from(document.scripts, (s) => new URL(s.src).pathname),
      libraryApi: typeof hashwasm.createArgon2id,
      stretch: __probe.stretches[0],
    };
  });
  eq(page.key, KAT_PW_KEY, 'Argon2id through the page');
  eq(JSON.stringify(page.scripts), '["/src/argon2.js","/src/crypto.js","/src/app.js"]', 'scripts in the page (hash-wasm must not be one)');
  eq(page.libraryApi, 'undefined', 'hash-wasm\'s own API in the page');
  // A ratio, not a time: a main thread doing the work misses every tick for the whole call.
  ok(page.stretch.longestPause < page.stretch.ms / 2,
    `the main thread stalled ${page.stretch.longestPause} ms during a ${page.stretch.ms} ms Argon2id`);
});

const phasesOf = (id) => inPage((id) => __probe.phasesOf(id), id);
const stepsOf = (id) => inPage((id) => Array.from(document.querySelectorAll(`#${id} li:not([hidden])`), (li) => {
  const bar = li.querySelector('progress');
  return `${li.dataset.step} ${li.dataset.state}${bar.value === bar.max ? ' full' : ''}`;
}), id);

test('progress: every wait is its own named step with its own bar — passphrase, encrypting, uploading; downloading, decrypting', async () => {
  for (const passphrase of [undefined, 'progress']) {
    const kind = passphrase ? 'restricted' : 'public';
    const size = 3 * 65519 + 10;
    const up = await uploadViaForm({ name: 'progress.bin', type: '', size, seed: 20, passphrase });
    eq(up.status.state, 'done', `${kind} upload: ${up.status.text}`);
    eq((await phasesOf('upload-status')).join(' '), `read ${passphrase ? 'stretch ' : ''}encrypt upload done`, `${kind} upload: phases`);
    eq((await stepsOf('upload-steps')).join(', '), `${passphrase ? 'stretch done full, ' : ''}encrypt done full, upload done full`, `${kind} upload: steps`);
    if (passphrase) {
      const why = await inPage(() => document.querySelector('#upload-steps li[data-step="stretch"] .step-why').textContent);
      ok(/Argon2id/.test(why) && /guess/.test(why) && /1–3 seconds/.test(why), `the passphrase step does not say what it does and why: ${why}`);
      const [stretch] = await probed().then(() => inPage(() => __probe.stretches));
      ok(stretch.longestPause < stretch.ms / 2, `upload: main thread stalled ${stretch.longestPause} of ${stretch.ms} ms`);
    }

    await go(up.link);
    await waitState('download-status', ['waiting', 'ready']);
    if (passphrase) {
      await inPage((p) => {
        document.getElementById('unlock-passphrase').value = p;
        document.getElementById('unlock').requestSubmit();
      }, passphrase);
      await waitState('download-status', ['ready']);
    }
    eq((await clickDownload()).state, 'done', `${kind} download`);
    eq((await phasesOf('download-status')).join(' '),
      passphrase ? 'meta waiting stretch ready download decrypt done' : 'meta open ready download decrypt done', `${kind} download: phases`);
    eq((await stepsOf('download-steps')).join(', '),
      `${passphrase ? 'stretch done full, ' : ''}download done full, decrypt done full`, `${kind} download: steps`);
    eq((await inPage(() => T.saved()))[0].sha256, sha256(pattern(size, 20)), `${kind}: saved bytes`);
  }
});

test('passphrase: a live length count, and no rule about what a passphrase must contain', async () => {
  await go(`${base}/`);
  const r = await inPage(() => {
    document.getElementById('protect').click();
    const field = document.getElementById('passphrase');
    const type = (value) => {
      field.value = value;
      field.dispatchEvent(new Event('input'));
      return document.getElementById('passphrase-length').textContent;
    };
    return {
      hint: document.getElementById('passphrase-hint').textContent.replace(/\s+/g, ' '),
      decomposed: type('é sunbird'),
      words: type('correct horse battery staple'),
      one: type('x'),
    };
  });
  eq(r.decomposed, '9 characters', 'e + combining accent counts as the one letter it is (NFC, as §4.1)');
  eq(r.words, '28 characters', 'four words');
  eq(r.one, '1 character', 'one character');
  ok(/Length is what makes a passphrase hard to guess/.test(r.hint), `hint: ${r.hint}`);
  const up = await uploadViaForm({ name: 'x.txt', type: 'text/plain', size: 10, seed: 0, passphrase: 'x' });
  eq(up.status.state, 'done', `a one-character passphrase was refused: ${up.status.text}`);
});

test('drop: a file dropped anywhere on the upload page is chosen, as text, never opened; two are refused; the download page ignores drops', async () => {
  await go(`${base}/`);
  const size = 5000;
  const r = await inPage((size) => {
    const drag = (type, target, files) => {
      const dataTransfer = new DataTransfer();
      for (const f of files) dataTransfer.items.add(f);
      const event = new DragEvent(type, { dataTransfer, bubbles: true, cancelable: true });
      target.dispatchEvent(event);
      return event.defaultPrevented;
    };
    const file = new File([T.pattern(size, 21)], '<img src=x onerror="window.__pwned=1">dropped.txt', { type: 'text/html' });
    const heading = document.querySelector('h1');
    const one = {
      over: drag('dragover', heading, [file]),
      dropped: drag('drop', heading, [file]),
      input: document.getElementById('file').files[0]?.name,
      shown: document.getElementById('chosen-name').textContent,
      children: document.getElementById('chosen-name').children.length,
    };
    const status = document.getElementById('upload-status');
    drag('drop', document.getElementById('drop-zone'), [new File(['a'], 'a.txt'), new File(['b'], 'b.txt')]);
    const two = { state: status.dataset.state, text: status.textContent, input: document.getElementById('file').files[0]?.name };
    return { one, two, file: file.name, pwned: window.__pwned === 1 };
  }, size);
  ok(r.one.over && r.one.dropped, 'a drop outside the zone was not caught: the browser would open the file in the tab');
  eq(r.one.input, r.file, 'dropped file chosen');
  eq(r.one.shown, r.file, 'dropped name shown');
  eq(r.one.children, 0, 'dropped name rendered as elements');
  ok(!r.pwned, 'the dropped name ran as markup');
  eq(r.two.state, 'error', 'two files: state');
  ok(/one file at a time/.test(r.two.text), `two files: ${r.two.text}`);
  eq(r.two.input, r.file, 'two files replaced the chosen one');

  await inPage((token) => {
    document.getElementById('upload-token').value = token;
    document.getElementById('upload-button').click();
  }, TOKEN);
  eq((await waitState('upload-status', ['done', 'error'])).state, 'done', 'upload of the dropped file');
  await go(await inPage(() => document.getElementById('link').value));
  await waitState('download-status', ['ready']);
  const ignored = await inPage(async () => {
    const dataTransfer = new DataTransfer();
    dataTransfer.items.add(new File(['<b>x</b>'], 'x.html', { type: 'text/html' }));
    const event = new DragEvent('drop', { dataTransfer, bubbles: true, cancelable: true });
    document.body.dispatchEvent(event);
    return { prevented: event.defaultPrevented, state: document.getElementById('download-status').dataset.state, saved: (await T.saved()).length };
  });
  ok(ignored.prevented, 'download page: a drop was not caught');
  eq(`${ignored.state} ${ignored.saved}`, 'ready 0', 'download page: state and files saved after a drop');
  eq((await clickDownload()).state, 'done', 'download of the dropped file');
  eq((await inPage(() => T.saved()))[0].sha256, sha256(pattern(size, 21)), 'saved bytes');
});

test('copy: the link and the owner token copy exactly; with the clipboard refused, the text is selected and the page says so', async () => {
  const up = await uploadViaForm({ name: 'c.txt', type: 'text/plain', size: 10, seed: 0 });
  eq(up.status.state, 'done', `upload: ${up.status.text}`);
  const r = await inPage(async () => {
    const copied = [];
    let allowed = true;
    Object.defineProperty(Navigator.prototype, 'clipboard', {
      configurable: true,
      get: () => ({
        writeText: (text) => (allowed ? (copied.push(text), Promise.resolve()) : Promise.reject(new DOMException('refused', 'NotAllowedError'))),
      }),
    });
    const click = async (id) => {
      document.getElementById(id).click();
      await new Promise((resolve) => setTimeout(resolve, 50));
    };
    await click('copy-link');
    await click('copy-token');
    const granted = { copied: [...copied], link: document.getElementById('copy-link-status').textContent, token: document.getElementById('copy-token-status').textContent };
    allowed = false;
    await click('copy-link');
    const input = document.getElementById('link');
    const link = { text: document.getElementById('copy-link-status').textContent, selected: input.value.slice(input.selectionStart, input.selectionEnd) };
    await click('copy-token');
    const token = { text: document.getElementById('copy-token-status').textContent, selected: window.getSelection().toString() };
    return { granted, link, token };
  });
  eq(JSON.stringify(r.granted.copied), JSON.stringify([up.link, up.token]), 'copied text');
  eq(`${r.granted.link} ${r.granted.token}`, 'Copied. Copied.', 'copied: what the page said');
  eq(r.link.selected, up.link, 'refused: link selected');
  ok(/Could not copy automatically/.test(r.link.text), `refused link: ${r.link.text}`);
  eq(r.token.selected, up.token, 'refused: token selected');
  ok(/Could not copy automatically/.test(r.token.text), `refused token: ${r.token.text}`);
});

test('gone while the page was open: says what the verified limits let it say, instead of the server\'s one answer', async () => {
  const one = await publicReady(3000, 22);
  const elsewhere = await fetch(`${base}/api/download/${one.id}`);
  eq(elsewhere.status, 200, 'someone else downloads it');
  await elsewhere.arrayBuffer();
  for (const deadline = Date.now() + 5000; existsSync(one.path); await sleep(50)) {
    ok(Date.now() < deadline, 'blob still on disk after its only download');
  }
  let done = await clickDownload();
  eq(done.state, 'error', 'used up: state');
  eq(done.text, 'The server no longer has this file. Its limit of 1 download may have been used up since this page opened, or it was deleted.', 'used up: message');

  const ownerDelete = async (up) => {
    const r = await fetch(`${base}/api/${idOf(up.link)}`, { method: 'DELETE', headers: { Authorization: `Bearer ${up.token}` } });
    eq(r.status, 204, 'owner delete');
  };
  const unlimited = await uploadViaForm({ name: 'u.txt', type: 'text/plain', size: 100, seed: 23, downloads: '0' });
  await go(unlimited.link);
  await waitState('download-status', ['ready']);
  await ownerDelete(unlimited);
  done = await clickDownload();
  eq(done.text, 'The server no longer has this file. It has no download limit and had not expired by this device\'s clock, so it was most likely deleted since this page opened.', 'deleted: message');

  const late = await uploadViaForm({ name: 'l.txt', type: 'text/plain', size: 100, seed: 24, expiry: '3600', downloads: '5' });
  await go(late.link);
  await waitState('download-status', ['ready']);
  await ownerDelete(late);
  await inPage(() => T.skew(7200));
  done = await clickDownload();
  ok(/^The server no longer has this file\. By this device's clock it expired on .+\.$/.test(done.text), `expired: ${done.text}`);
});

test('rate limited: too many uploads, and a link opened too often, each say so and when to try again', async () => {
  const limited = await startServer('limited', {
    upload_rate: { requests: 1, seconds: 3600 },
    read_rate: { requests: 2, seconds: 3600 },
    members: [member('e2e', TOKEN)],
  });
  const first = await uploadViaForm({ name: 'r.txt', type: 'text/plain', size: 10, seed: 0, origin: limited });
  eq(first.status.state, 'done', `first upload: ${first.status.text}`);
  const second = await uploadViaForm({ name: 'r.txt', type: 'text/plain', size: 10, seed: 0, origin: limited });
  eq(second.status.state, 'error', 'second upload: state');
  ok(/^You have uploaded too many times in a short time, so the server is refusing your uploads for now\. Try again in (59|60) minutes\.$/.test(second.status.text),
    `second upload: ${second.status.text}`);
  ok(!second.shown, 'a link was shown for a refused upload');

  for (let i = 1; i <= 3; i++) {
    await go(`${limited}/`);
    await go(first.link);
    const opened = await waitState('download-status', ['ready', 'error']);
    if (i < 3) {
      eq(opened.state, 'ready', `opening ${i}: ${opened.text}`);
    } else {
      // The read limiter refills in steps, so its wait is not the whole window.
      ok(/^This network has made too many requests to the server in a short time, so it is refusing them for now\. Try again in \d+ minutes\.$/.test(opened.text),
        `opening 3: ${opened.text}`);
    }
  }
});

test('disk: an upload refused at the server\'s free-space floor says the server is out of space; no link, nothing stored', async () => {
  const full = await startServer('full', {
    upload_rate: { requests: 100, seconds: 60 },
    read_rate: { requests: 100, seconds: 60 },
    min_free_bytes: 2 ** 60, // more than any disk has: every upload is below the floor
    members: [member('e2e', TOKEN)],
  });
  const up = await uploadViaForm({ name: 'full.txt', type: 'text/plain', size: 1000, seed: 3, origin: full });
  eq(up.status.state, 'error', `state: ${up.status.text}`);
  eq(up.status.text, 'The server is running out of disk space, so it is not accepting uploads right now. Nothing was stored. Tell the server\'s admin.', 'message');
  ok(!up.shown, 'a link was shown for a refused upload');
  eq(readdirSync(join(work, 'full', 'blobs')).length + readdirSync(join(work, 'full', 'tmp')).length, 0, 'files left in blobs/ and tmp/');
});

test('phone (390×844): nothing scrolls sideways and every control is a 44 px target, from choosing a file to saving it', async () => {
  await b.viewport(...PHONE);
  try {
    const layout = (where) => inPage((where) => {
      const width = document.documentElement.clientWidth;
      const problems = [];
      if (window.innerWidth !== 390) problems.push(`${where}: the window is ${window.innerWidth} px wide`);
      if (document.documentElement.scrollWidth > width) {
        problems.push(`${where}: the page is ${document.documentElement.scrollWidth} px wide in ${width}`);
      }
      for (const el of document.querySelectorAll('button, input, select, #file-name, #chosen-name, #owner-token, #expired-warning')) {
        // A checkbox and the hidden file input are tapped through their labels.
        const target = el.type === 'checkbox' || el.type === 'file' ? el.closest('label') : el;
        const r = target.getBoundingClientRect();
        if (r.width === 0 && r.height === 0) continue; // not displayed
        if (r.right > width + 0.5) problems.push(`${where}: #${el.id} runs to ${Math.round(r.right)} px`);
        if (el.matches('button, input, select') && r.height < 44) problems.push(`${where}: #${el.id || target.id} is ${Math.round(r.height)} px tall`);
      }
      // A `display` rule would override `hidden` and show things that should be
      // hidden.
      for (const el of document.querySelectorAll('[hidden]')) {
        if (el.getClientRects().length > 0) problems.push(`${where}: hidden ${el.id ? `#${el.id}` : el.dataset.step || el.tagName} is displayed`);
      }
      return problems;
    }, where);
    const problems = [];
    await go(`${base}/`);
    problems.push(...await layout('empty form'));
    await inPage((name) => {
      T.setFile(name, 'text/plain', 150000, 25);
      document.getElementById('file').dispatchEvent(new Event('change'));
      document.getElementById('protect').click();
      document.getElementById('passphrase').value = 'phone passphrase';
    }, `${'a'.repeat(200)}.txt`);
    problems.push(...await layout('a long name chosen, passphrase ticked'));
    await inPage((token) => {
      document.getElementById('upload-token').value = token;
      document.getElementById('upload-button').click();
    }, TOKEN);
    eq((await waitState('upload-status', ['done', 'error'])).state, 'done', 'upload');
    problems.push(...await layout('uploaded: steps, link, owner token'));
    const link = await inPage(() => document.getElementById('link').value);
    const [sealing] = await inPage(() => __probe.stretches);

    await go(link);
    await waitState('download-status', ['waiting']);
    problems.push(...await layout('passphrase prompt'));
    await inPage(() => {
      T.skew(2 * 86400);
      document.getElementById('unlock-passphrase').value = 'phone passphrase';
      document.getElementById('unlock').requestSubmit();
    });
    await waitState('download-status', ['ready']);
    problems.push(...await layout('details: a long name and the expiry warning'));
    const [opening] = await inPage(() => __probe.stretches);
    eq((await clickDownload()).state, 'done', 'download');
    problems.push(...await layout('downloaded'));
    eq(problems.join('\n      '), '', 'layout problems');
    console.log(`      Argon2id in a 390×844 window, this machine's CPU: ${sealing.ms} ms sealing, ${opening.ms} ms opening; ` +
      `longest main-thread stall ${Math.max(sealing.longestPause, opening.longestPause)} ms`);
  } finally {
    await b.viewport(...(phone ? PHONE : [null]));
  }
});

// ---- runner ---------------------------------------------------------------

execFileSync('sh', ['-c', 'cargo build --quiet && cp target/debug/sunbird "$0"', join(work, 'sunbird')], { cwd: root, stdio: 'inherit' });
const tokenHash = (token) => createHash('sha256').update(token).digest('hex');
const lots = 2 ** 40;
function member(name, token, limits = {}) {
  return {
    id: randomBytes(16).toString('base64url'), name, token_sha256: tokenHash(token),
    max_active_bytes: lots, max_active_files: lots, max_bytes_per_week: lots, ...limits,
  };
}

// Starts a server over work/<dir> with `config`; resolves to its origin once it answers.
const servers = [];
async function startServer(dir, config) {
  const port = await freePort();
  const configPath = join(work, `${dir}.json`);
  writeFileSync(configPath, JSON.stringify({ trusted_proxies: [], admins: [], min_free_bytes: 1, ...config }));
  // Run from work/, where nothing but the binary, configs and data are.
  servers.push(spawn(join(work, 'sunbird'), ['-addr', `127.0.0.1:${port}`, '-data', join(work, dir), '-config', configPath],
    { stdio: 'ignore', cwd: work }));
  const origin = `http://127.0.0.1:${port}`;
  for (let deadline = Date.now() + 15_000; ; await sleep(100)) {
    try { if ((await fetch(`${origin}/`)).ok) return origin; } catch (_) { /* not up yet */ }
    if (Date.now() > deadline) throw new Error(`server ${dir} did not start`);
  }
}

let base;
let failed = 0;
try {
  base = await startServer('data', {
    upload_rate: { requests: 10000, seconds: 60 },
    read_rate: { requests: 100000, seconds: 60 },
    members: [member('e2e', TOKEN), member('small', SMALL_TOKEN, { max_active_bytes: 2000, max_active_files: 10 })],
  });
  b = await launch(browser);
  if (phone) await b.viewport(...PHONE);
  await b.preload(String(probe));
  for (const { name, fn } of tests) {
    const start = Date.now();
    try {
      await fn();
      console.log(`PASS  ${name}  (${Date.now() - start} ms)`);
    } catch (err) {
      failed++;
      console.log(`FAIL  ${name}\n      ${err.message}`);
    }
  }
  const where = `${browser}${phone ? ' (390×844)' : ''}`;
  console.log(`\n${where}: ${failed ? `${failed} of ${tests.length} tests failed` : `All ${tests.length} tests passed`}`);
} catch (err) {
  console.error(`${browser}: ${err.message}`);
  failed = -1;
} finally {
  b?.close();
  for (const server of servers) server.kill();
  rmSync(work, { recursive: true, force: true });
}
process.exit(failed === 0 ? 0 : failed < 0 ? 2 : 1);
