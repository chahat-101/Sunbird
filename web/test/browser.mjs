// Drives headless Firefox (WebDriver BiDi) or Chromium (DevTools protocol)
// with nothing but Node 22's built-in WebSocket. Shared by run.mjs and e2e.mjs.
// The browser binary is found by findBrowser, below.
import { spawn } from 'node:child_process';
import { accessSync, constants, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const PATH_NAMES = {
  firefox: ['firefox'],
  chromium: ['chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable', 'chrome'],
};

// Inside a Playwright browser directory (chromium_headless_shell-<rev> or
// chromium-<rev>), where each platform's build keeps its binary.
const PLAYWRIGHT_BINARIES = [
  'chrome-headless-shell-linux64/chrome-headless-shell',
  'chrome-headless-shell-mac-arm64/chrome-headless-shell',
  'chrome-headless-shell-mac-x64/chrome-headless-shell',
  'chrome-headless-shell-win64/chrome-headless-shell.exe',
  'chrome-linux64/chrome',
  'chrome-linux/chrome',
  'chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
  'chrome-mac/Chromium.app/Contents/MacOS/Chromium',
  'chrome-win64/chrome.exe',
  'chrome-win/chrome.exe',
];

function executable(path) {
  try {
    accessSync(path, constants.X_OK);
    return true;
  } catch (_) {
    return false;
  }
}

// The binary for `browser`, in this order, first found wins:
//   1. $BROWSER, if set (and then nothing else is tried);
//   2. PATH: firefox; or chromium, chromium-browser, google-chrome,
//      google-chrome-stable, chrome;
//   3. Chromium only, Playwright's caches: $PLAYWRIGHT_BROWSERS_PATH,
//      ~/.cache/ms-playwright, ~/Library/Caches/ms-playwright,
//      %LOCALAPPDATA%\ms-playwright. The headless shell first, then full
//      Chromium, newest revision first. (Playwright's Firefox is patched and
//      does not speak WebDriver BiDi the way this driver needs.)
// Throws, naming every place it looked, when nothing is found.
export function findBrowser(browser) {
  if (process.env.BROWSER) {
    if (executable(process.env.BROWSER)) return process.env.BROWSER;
    throw new Error(`$BROWSER is set to ${process.env.BROWSER}, which is not an executable file`);
  }
  const looked = [];
  const dirs = (process.env.PATH ?? '').split(delimiter).filter(Boolean);
  for (const name of PATH_NAMES[browser]) {
    for (const dir of dirs) {
      const candidate = join(dir, process.platform === 'win32' ? `${name}.exe` : name);
      if (executable(candidate)) return candidate;
    }
    looked.push(`${name} on PATH`);
  }
  if (browser === 'chromium') {
    const caches = [
      process.env.PLAYWRIGHT_BROWSERS_PATH,
      join(homedir(), '.cache', 'ms-playwright'),
      join(homedir(), 'Library', 'Caches', 'ms-playwright'),
      process.env.LOCALAPPDATA && join(process.env.LOCALAPPDATA, 'ms-playwright'),
    ].filter(Boolean);
    for (const cache of caches) {
      let entries = [];
      try { entries = readdirSync(cache); } catch (_) { /* no such cache */ }
      const revision = (name) => Number(name.slice(name.lastIndexOf('-') + 1));
      const found = entries
        .filter((name) => /^(chromium_headless_shell|chromium)-\d+$/.test(name))
        .sort((a, b) => (a.startsWith('chromium_headless_shell') === b.startsWith('chromium_headless_shell')
          ? revision(b) - revision(a)
          : a.startsWith('chromium_headless_shell') ? -1 : 1));
      for (const dir of found) {
        for (const binary of PLAYWRIGHT_BINARIES) {
          if (executable(join(cache, dir, binary))) return join(cache, dir, binary);
        }
      }
      looked.push(`Playwright's Chromium under ${cache}`);
    }
  }
  const install = browser === 'chromium'
    ? ' Install one (for example `npx playwright install chromium-headless-shell`), or set $BROWSER to its path.'
    : ' Install Firefox, or set $BROWSER to its path.';
  throw new Error(`no ${browser} found. Looked for: ${looked.join('; ')}.${install}`);
}

// Returns { navigate(url), evaluate(expression), preload(functionSource),
// viewport(width, height), close() }. evaluate awaits a promise result and
// returns it by value. preload runs the function in every page loaded
// afterwards, before the page's scripts. viewport sets a phone-sized window
// (device pixel ratio 3; in Chromium also mobile layout and touch), and
// viewport(null) restores the default.
export async function launch(browser) {
  if (browser !== 'firefox' && browser !== 'chromium') throw new Error(`unknown browser ${browser}`);
  const binary = findBrowser(browser);
  const profile = mkdtempSync(join(tmpdir(), 'sunbird-test-'));
  const args = browser === 'firefox'
    ? ['--headless', '--profile', profile, '--remote-debugging-port', '0', 'about:blank']
    : ['--headless', `--user-data-dir=${profile}`, '--remote-debugging-port=0', 'about:blank'];
  const child = spawn(binary, args, { stdio: ['ignore', 'ignore', 'pipe'] });
  const close = () => {
    child.kill();
    try { rmSync(profile, { recursive: true, force: true }); } catch (_) { /* best effort */ }
  };
  try {
    const send = await connect(await endpoint(child, browser));
    const page = browser === 'firefox' ? await firefoxPage(send) : await chromiumPage(send);
    return { ...page, close };
  } catch (err) {
    close();
    throw err;
  }
}

// Both browsers print their WebSocket endpoint on stderr once listening.
function endpoint(child, browser) {
  return new Promise((resolve, reject) => {
    let seen = '';
    child.on('error', reject);
    child.on('exit', (code) => reject(new Error(`browser exited (${code}) before listening:\n${seen}`)));
    child.stderr.on('data', (chunk) => {
      seen += chunk;
      const m = seen.match(/(?:WebDriver BiDi listening on|DevTools listening on) (ws:\/\/\S+)/);
      if (m) resolve(browser === 'firefox' ? `${m[1]}/session` : m[1]);
    });
  });
}

function connect(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    const pending = new Map();
    let nextId = 1;
    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      const p = pending.get(msg.id);
      if (!p) return;
      pending.delete(msg.id);
      if (msg.error) p.reject(new Error(`${msg.error.message ?? msg.error}: ${msg.message ?? ''}`));
      else p.resolve(msg.result);
    };
    ws.onerror = () => reject(new Error(`cannot connect to ${url}`));
    ws.onopen = () => resolve((method, params = {}, sessionId) => new Promise((res, rej) => {
      const id = nextId++;
      pending.set(id, { resolve: res, reject: rej });
      ws.send(JSON.stringify({ id, method, params, ...(sessionId && { sessionId }) }));
    }));
  });
}

async function firefoxPage(send) {
  await send('session.new', { capabilities: {} });
  const { contexts } = await send('browsingContext.getTree', {});
  const context = contexts[0].context;
  return {
    navigate: (url) => send('browsingContext.navigate', { context, url, wait: 'complete' }),
    preload: (fn) => send('script.addPreloadScript', { functionDeclaration: fn }),
    viewport: (width, height) => send('browsingContext.setViewport', width
      ? { context, viewport: { width, height }, devicePixelRatio: 3 }
      : { context, viewport: null, devicePixelRatio: null }),
    evaluate: async (expression) => {
      const r = await send('script.evaluate', { expression, target: { context }, awaitPromise: true });
      if (r.type === 'exception') throw new Error(r.exceptionDetails.text);
      return r.result.value;
    },
  };
}

async function chromiumPage(send) {
  const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
  // Without it, scripts added by preload are accepted and never run.
  await send('Page.enable', {}, sessionId);
  const evaluate = async (expression) => {
    const r = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, sessionId);
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
    return r.result.value;
  };
  return {
    evaluate,
    preload: (fn) => send('Page.addScriptToEvaluateOnNewDocument', { source: `(${fn})();` }, sessionId),
    viewport: async (width, height) => {
      if (!width) {
        await send('Emulation.clearDeviceMetricsOverride', {}, sessionId);
        await send('Emulation.setTouchEmulationEnabled', { enabled: false }, sessionId);
        return;
      }
      await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 3, mobile: true }, sessionId);
      await send('Emulation.setTouchEmulationEnabled', { enabled: true, maxTouchPoints: 5 }, sessionId);
    },
    // Page.navigate returns when the navigation commits; wait for the load.
    navigate: async (url) => {
      await send('Page.navigate', { url }, sessionId);
      const deadline = Date.now() + 30_000;
      for (;;) {
        try {
          if (await evaluate(`document.readyState === 'complete' && location.href === ${JSON.stringify(url)}`)) return;
        } catch (_) { /* context replaced mid-navigation */ }
        if (Date.now() > deadline) throw new Error(`timed out loading ${url}`);
        await sleep(50);
      }
    },
  };
}
