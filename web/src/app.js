// Sunbird client — the page for protocol.md §10. `/` uploads a file and
// shows a link; `/d/<id>#<fragment>` opens one and downloads the file. All
// cryptography and every header offset are in crypto.js, and Argon2id runs in
// a Worker (argon2.js). This file moves bytes and sets text.
//
// Rules a change to this page keeps:
// - Decrypted metadata is hostile input. It is only ever set with textContent;
//   `type` is never read; the file is never previewed, only saved, as
//   application/octet-stream, with path separators stripped from its name.
// - A file dropped anywhere on the page is caught, never opened by the browser.
// - Which kind of link a file gets is said before anything commits to it: by
//   the box, on the button that uploads, beside the link, and on opening,
//   before any prompt.
// - Each wait is its own named step with its own bar; a refusal says what
//   actually went wrong.
(function () {
  'use strict';
  const C = SunbirdCrypto;

  const MAX_PLAINTEXT = 104857600; // §6.4: the cap is on plaintext, not max_blob
  // D9 policy, not format: expiry defaults to 24 hours, at most 7 days; the
  // download limit defaults to 1. 0 is "no limit" and is labelled so.
  const MAX_LIFETIME = 7 * 24 * 3600;
  // The server refuses an expires_at more than 7 days after its own clock. The
  // 7-day choice asks for 300 s less, so a device clock a few minutes fast (a
  // laptop just woken, before NTP) is not refused. A courtesy, not a limit:
  // the server's bound is exact whatever the client does (§10).
  const CLOCK_MARGIN = 300;
  const DOWNLOAD_LIMITS = new Set([0, 1, 5, 10]);
  const ID_PATTERN = /^[A-Za-z0-9_-]{16}$/;
  const TOKEN_KEY = 'sunbird.uploadToken';

  // Expired, used up, deleted and never existed are one answer from the server.
  const NO_FILE = 'There is no file at this link: it expired, was deleted, or the link is wrong.';
  const BAD_TOKEN = 'The server did not accept this upload token. Check it, or ask the admin whether it is still valid.';
  const TOO_LARGE = 'This file is larger than 100 MiB, the most Sunbird can send.';
  // The server's words for a blob over max_blob; any other 413 is a member's quota.
  const SERVER_TOO_LARGE = 'upload is larger than the server accepts';

  const $ = (id) => document.getElementById(id);

  function coded(code, message) {
    const err = new Error(message);
    err.code = code;
    return err;
  }

  // `state` is busy, waiting, ready, done or error. `phase` names the wait
  // (read, stretch, encrypt, upload, meta, open, download, decrypt), and is
  // the state itself when there is no wait.
  function setStatus(el, state, text, phase) {
    el.dataset.state = state;
    el.dataset.phase = phase || state;
    el.textContent = text;
  }

  function formatBytes(n) {
    if (n < 1024) return `${n} byte${n === 1 ? '' : 's'}`;
    if (n < 1048576) return `${(n / 1024).toFixed(1)} KiB`;
    return `${(n / 1048576).toFixed(1)} MiB`;
  }

  function formatWait(seconds) {
    if (seconds < 90) return `${seconds} second${seconds === 1 ? '' : 's'}`;
    const minutes = Math.ceil(seconds / 60);
    return minutes < 90 ? `${minutes} minutes` : `${Math.ceil(minutes / 60)} hours`;
  }

  const percent = (done, total) => `${Math.floor((100 * done) / total)}%`;

  // What actually went wrong, in words a person can act on.
  function explain(err, restricted) {
    switch (err && err.code) {
      case 'wrong-passphrase':
        return restricted
          ? 'Wrong passphrase, or the link is damaged.'
          : 'This link does not open the file: the link is damaged or incomplete.';
      case 'empty-passphrase':
        return 'Enter a passphrase.';
      case 'too-large':
        return TOO_LARGE;
      case 'malformed':
      case 'corrupt':
      case 'truncated':
      case 'too-many-records':
      case 'size-mismatch':
        return `The file is corrupted or was altered, so nothing was saved. ${err.message}.`;
      // Written for people where they are raised.
      case 'needs-newer-version': // §5
      case 'unknown-version':     // §9, verbatim
      case 'name-too-long':
      case 'passphrase-worker':
      case 'link':
      case 'read':
      case 'network':
      case 'gone':
      case 'not-authorised':
      case 'quota':
      case 'rate-limited':
      case 'refused':
      case 'server':
        return err.message;
      default:
        return `Something failed that this page does not recognise: ${err && err.message}`;
    }
  }

  // A refusal from the server, as the error to show. `during` is 'upload' or
  // 'download': the rate limits and the 413 mean different things for each.
  function refusal(status, reason, retryAfter, during) {
    const said = typeof reason === 'string' ? reason.trim() : '';
    const sentence = /[.!?]$/.test(said) ? said : `${said}.`;
    switch (status) {
      case 401:
        return coded('not-authorised', BAD_TOKEN);
      case 404:
        return coded('gone', NO_FILE);
      case 413:
        // The server's quota messages name the limit and when it frees (step 07).
        return said === SERVER_TOO_LARGE || !said || during !== 'upload'
          ? coded('too-large', TOO_LARGE)
          : coded('quota', `Over your upload quota. ${sentence}`);
      case 429: {
        const seconds = /^[0-9]+$/.test(retryAfter || '') ? Number(retryAfter) : 0;
        const when = seconds > 0 ? `Try again in ${formatWait(seconds)}.` : sentence;
        return coded('rate-limited', during === 'upload'
          ? `You have uploaded too many times in a short time, so the server is refusing your uploads for now. ${when}`
          : `This network has made too many requests to the server in a short time, so it is refusing them for now. ${when}`);
      }
      case 507:
        // The disk is at its free-space floor: nothing the member changes helps.
        return coded('server', 'The server is running out of disk space, so it is not accepting uploads right now. Nothing was stored. Tell the server\'s admin.');
      case 400:
        if (during === 'upload' && said) return coded('refused', `The server refused this upload: ${sentence}`);
        // fall through
      default:
        return coded('server', `The server could not do this: it answered ${status}${said ? ` (${said.replace(/[.!?]$/, '')})` : ''}. Try again later.`);
    }
  }

  // A list of named waits. Each bar measures only its own wait; a wait with
  // nothing to measure animates, and counts the seconds so far.
  function steps(list) {
    const items = new Map(Array.from(list.querySelectorAll('li[data-step]'), (li) => [li.dataset.step, li]));
    let ticker = null;
    const stop = () => {
      clearInterval(ticker);
      ticker = null;
    };
    const set = (name, state, detail) => {
      const li = items.get(name);
      li.dataset.state = state;
      li.querySelector('.step-detail').textContent = detail;
      return li.querySelector('progress');
    };
    return {
      show(names) {
        stop();
        list.hidden = false;
        for (const [name, li] of items) {
          li.hidden = !names.includes(name);
          const bar = set(name, 'pending', '');
          bar.max = 1;
          bar.value = 0;
        }
      },
      wait(name, detail) {
        stop();
        const bar = set(name, 'active', '');
        bar.removeAttribute('value');
        const started = performance.now();
        const tick = () => {
          const seconds = Math.floor((performance.now() - started) / 1000);
          items.get(name).querySelector('.step-detail').textContent = `${detail}${seconds} s so far.`;
        };
        tick();
        ticker = setInterval(tick, 250);
      },
      measure(name, done, total, detail) {
        const bar = set(name, 'active', detail);
        if (total > 0) {
          bar.max = total;
          bar.value = Math.min(done, total);
        } else {
          bar.removeAttribute('value');
        }
      },
      done(name, detail) {
        stop();
        const bar = set(name, 'done', detail);
        bar.max = 1;
        bar.value = 1;
      },
      fail() {
        stop();
        for (const [name, li] of items) {
          if (li.dataset.state !== 'active') continue;
          const bar = set(name, 'error', 'Stopped.');
          bar.max = 1;
          bar.value = 0;
        }
      },
    };
  }

  // A file dropped where no page handles it is opened by the browser, in this
  // tab: shown, and the page left. So every drop anywhere is caught. On the
  // upload page it chooses the file; elsewhere it does nothing.
  function catchDrops(onFiles) {
    const zone = $('drop-zone');
    window.addEventListener('dragover', (event) => {
      event.preventDefault();
      if (event.dataTransfer) event.dataTransfer.dropEffect = onFiles ? 'copy' : 'none';
      if (onFiles) zone.dataset.dragging = '';
    });
    window.addEventListener('dragleave', (event) => {
      if (onFiles && !event.relatedTarget) delete zone.dataset.dragging;
    });
    window.addEventListener('drop', (event) => {
      event.preventDefault();
      if (!onFiles) return;
      delete zone.dataset.dragging;
      onFiles(event.dataTransfer && event.dataTransfer.files);
    });
  }

  // Clipboard access can be missing or refused (an http:// page, a browser
  // setting). Then the text is selected for the device's own copy command.
  async function copy(source, note) {
    const text = source instanceof HTMLInputElement ? source.value : source.textContent;
    try {
      await navigator.clipboard.writeText(text);
      setStatus(note, 'done', 'Copied.');
    } catch (_) {
      if (source instanceof HTMLInputElement) source.select();
      else window.getSelection().selectAllChildren(source);
      setStatus(note, 'error', 'Could not copy automatically. It is selected: copy it with your device’s copy command.');
    }
  }

  // ---- upload ---------------------------------------------------------------

  const STRETCH_DETAIL = 'This page is still working: ';
  let uploading = false;

  // Remembering the token is a convenience. Storage can be missing or throw
  // (private windows, blocked site data); then the field simply starts empty.
  function rememberedToken() {
    try { return localStorage.getItem(TOKEN_KEY) || ''; } catch (_) { return ''; }
  }
  function rememberToken(token) {
    try {
      if (token) localStorage.setItem(TOKEN_KEY, token);
      else localStorage.removeItem(TOKEN_KEY);
    } catch (_) { /* not remembered */ }
  }

  function showChosen() {
    const file = $('file').files[0];
    $('drop-zone').dataset.chosen = file ? 'yes' : 'no';
    $('drop-empty').hidden = Boolean(file);
    $('drop-chosen').hidden = !file;
    if (!file) return;
    $('chosen-name').textContent = file.name;
    $('chosen-size').textContent = formatBytes(file.size);
    const status = $('upload-status');
    if (file.size > MAX_PLAINTEXT) setStatus(status, 'error', TOO_LARGE);
    else if (status.dataset.state === 'error') setStatus(status, '', '');
  }

  function chooseDropped(files) {
    if (uploading || !files || files.length === 0) return;
    if (files.length > 1) {
      setStatus($('upload-status'), 'error', 'Drop one file at a time: Sunbird sends a single file. To send several, zip them into one first.');
      return;
    }
    $('file').files = files;
    showChosen();
  }

  function showUpload() {
    $('upload').hidden = false;
    const remembered = rememberedToken();
    if (remembered) {
      $('upload-token').value = remembered;
      $('remember-token').checked = true;
    }
    $('remember-token').addEventListener('change', () => {
      if (!$('remember-token').checked) rememberToken('');
    });

    const protect = $('protect');
    const passphrase = $('passphrase');
    // A length, and no rule about what the passphrase must contain.
    const count = () => {
      const n = Array.from(passphrase.value.normalize('NFC')).length;
      $('passphrase-length').textContent = `${n} character${n === 1 ? '' : 's'}`;
    };
    // The field, the explanation of the mode and the button's words follow
    // the box, including the state a browser may restore it to on reload.
    const follow = () => {
      passphrase.disabled = !protect.checked;
      if (!protect.checked) passphrase.value = '';
      $('mode-public').hidden = protect.checked;
      $('mode-restricted').hidden = !protect.checked;
      $('upload-mode').textContent = protect.checked ? 'passphrase-protected' : 'public link';
      count();
    };
    protect.addEventListener('change', follow);
    passphrase.addEventListener('input', count);
    follow();

    $('file').addEventListener('change', showChosen);
    showChosen();
    catchDrops(chooseDropped);
    $('upload-button').addEventListener('click', upload);
    $('copy-link').addEventListener('click', () => copy($('link'), $('copy-link-status')));
    $('copy-token').addEventListener('click', () => copy($('owner-token'), $('copy-token-status')));
  }

  // XMLHttpRequest, not fetch: only it reports upload progress in every browser.
  function post(url, body, token, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', url);
      try {
        xhr.setRequestHeader('Authorization', `Bearer ${token}`);
      } catch (_) {
        reject(coded('not-authorised', BAD_TOKEN)); // characters no token has
        return;
      }
      xhr.upload.addEventListener('progress', (event) => onProgress(event.loaded, body.size));
      xhr.upload.addEventListener('load', () => onProgress(body.size, body.size));
      xhr.addEventListener('load', () => resolve({
        status: xhr.status,
        text: xhr.responseText,
        retryAfter: xhr.getResponseHeader('Retry-After'),
      }));
      xhr.addEventListener('error', () => reject(coded('network',
        'Could not reach the server, or the connection dropped during the upload. Nothing was stored: try again.')));
      xhr.send(body);
    });
  }

  async function upload() {
    if (uploading) return;
    const status = $('upload-status');
    const button = $('upload-button');
    $('result').hidden = true;

    // Every refusal that needs no work comes before any, synchronously.
    const file = $('file').files[0];
    if (!file) return setStatus(status, 'error', 'Choose a file first.');
    if (file.size > MAX_PLAINTEXT) return setStatus(status, 'error', TOO_LARGE);
    const restricted = $('protect').checked;
    const passphrase = restricted ? $('passphrase').value : undefined;
    if (restricted && passphrase === '') {
      return setStatus(status, 'error', 'Enter a passphrase, or untick “Require a passphrase”.');
    }
    const lifetime = Number($('expiry').value);
    const maxDownloads = Number($('downloads').value);
    if (!Number.isInteger(lifetime) || lifetime <= 0 || lifetime > MAX_LIFETIME || !DOWNLOAD_LIMITS.has(maxDownloads)) {
      return setStatus(status, 'error', 'Choose an expiry of at most 7 days and a download limit from the list.');
    }
    // Machine-made, so surrounding whitespace is a paste artefact, not part of it.
    const token = $('upload-token').value.trim();
    if (token === '') return setStatus(status, 'error', 'Enter your upload token. The server\'s admin gives one to each member.');

    // Computed once: the same two values are sealed into the header and sent
    // beside the blob (§10). A mismatch would be a bug here, not a negotiation.
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = Math.min(now + lifetime, now + MAX_LIFETIME - CLOCK_MARGIN);

    uploading = true;
    button.disabled = true;
    const flow = steps($('upload-steps'));
    flow.show(restricted ? ['stretch', 'encrypt', 'upload'] : ['encrypt', 'upload']);
    try {
      setStatus(status, 'busy', 'Reading the file…', 'read');
      let plaintext;
      try {
        plaintext = new Uint8Array(await file.arrayBuffer());
      } catch (err) {
        throw coded('read', `Could not read this file from your device (${err.message}). If it is a folder, choose a file inside it.`);
      }

      let encrypting = false;
      const { fragment, blob } = await C.encryptFile(plaintext, {
        name: file.name,
        type: file.type || 'application/octet-stream',
        passphrase,
        expiresAt,
        maxDownloads,
        onProgress({ stage, done, total }) {
          if (stage === 'passphrase') {
            setStatus(status, 'busy', 'Stretching the passphrase…', 'stretch');
            flow.wait('stretch', STRETCH_DETAIL);
            return;
          }
          if (!encrypting) {
            encrypting = true;
            if (restricted) flow.done('stretch', 'Done.');
            setStatus(status, 'busy', 'Encrypting on this device…', 'encrypt');
          }
          flow.measure('encrypt', done, total, `${percent(done, total)} of ${formatBytes(plaintext.length)}`);
        },
      });
      flow.done('encrypt', `${formatBytes(plaintext.length)} encrypted.`);

      setStatus(status, 'busy', 'Uploading…', 'upload');
      let sent = false;
      const answer = await post(`/api/upload?expires_at=${expiresAt}&max_downloads=${maxDownloads}`, blob, token, (loaded, total) => {
        if (loaded < total) {
          flow.measure('upload', loaded, total, `${formatBytes(loaded)} of ${formatBytes(total)} sent`);
        } else if (!sent) {
          sent = true;
          flow.measure('upload', total, total, '');
          flow.wait('upload', `All ${formatBytes(total)} sent; the server is storing it. `);
        }
      });
      let reply = null;
      try { reply = JSON.parse(answer.text); } catch (_) { /* not JSON */ }
      if (answer.status < 200 || answer.status > 299) {
        throw refusal(answer.status, reply && reply.error, answer.retryAfter, 'upload');
      }
      const id = reply && reply.id;
      const ownerToken = reply && reply.ownerToken;
      if (typeof id !== 'string' || !ID_PATTERN.test(id) || typeof ownerToken !== 'string') {
        throw coded('server', 'The server gave a malformed answer to the upload, so there is no link. Try again.');
      }
      flow.done('upload', `${formatBytes(blob.size)} stored.`);

      // Only a token the server accepted is remembered.
      if ($('remember-token').checked) rememberToken(token);
      $('link').value = `${location.origin}/d/${id}#${fragment}`;
      // For a public file the fragment is the whole secret; the page says so.
      $('link-public').hidden = restricted;
      $('link-restricted').hidden = !restricted;
      $('owner-token').textContent = ownerToken;
      setStatus($('copy-link-status'), '', '');
      setStatus($('copy-token-status'), '', '');
      $('result').hidden = false;
      setStatus(status, 'done', 'Uploaded.');
      $('result').scrollIntoView({ block: 'start' });
    } catch (err) {
      flow.fail();
      setStatus(status, 'error', explain(err, restricted));
    } finally {
      uploading = false;
      button.disabled = false;
    }
  }

  // ---- download -------------------------------------------------------------

  function formatTime(seconds) {
    // Date covers ±8.64e12 seconds; anything later is shown as the raw number.
    return seconds <= 8640000000000n
      ? new Date(Number(seconds) * 1000).toLocaleString()
      : `${seconds} seconds after 1970`;
  }

  // GET, as bytes. `onProgress(received, declared)` drives a bar, nothing
  // else: `declared` is the server's Content-Length, or 0. The size a file is
  // checked against comes from inside it (§6.5), never from here.
  async function fetchBytes(url, onProgress) {
    let response;
    try {
      response = await fetch(url);
    } catch (err) {
      throw coded('network', `Could not reach the server (${err.message}).`);
    }
    if (!response.ok) {
      let reason = '';
      try { reason = (await response.json()).error; } catch (_) { /* no JSON body */ }
      throw refusal(response.status, reason, response.headers.get('Retry-After'), 'download');
    }
    try {
      if (!onProgress || !response.body) return new Uint8Array(await response.arrayBuffer());
      const declared = Number(response.headers.get('Content-Length'));
      const total = Number.isSafeInteger(declared) && declared > 0 ? declared : 0;
      const reader = response.body.getReader();
      const chunks = [];
      let received = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        received += value.length;
        onProgress(received, total);
      }
      const bytes = new Uint8Array(received);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.length;
      }
      return bytes;
    } catch (err) {
      // The server hands back an unfinished download's claim (step 06).
      throw coded('network', `The download was interrupted (${err.message}). It did not use up the link: try again.`);
    }
  }

  // `name` is hostile. Path separators are stripped so it cannot name a
  // directory, and the Blob's type is fixed: `type` never decides anything.
  function save(plaintext, name) {
    const safe = name.replace(/[/\\]/g, '');
    const url = URL.createObjectURL(new Blob([plaintext], { type: 'application/octet-stream' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = /[^.\s]/.test(safe) ? safe : 'download';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  }

  async function showDownload(id) {
    $('download').hidden = false;
    catchDrops(null);
    const status = $('download-status');
    const flow = steps($('download-steps'));

    // §10 steps 1–2.
    let secret;
    let preview;
    try {
      if (!ID_PATTERN.test(id)) throw coded('link', 'This link is damaged: the file ID is malformed.');
      try {
        secret = C.decodeFragment(location.hash.slice(1));
      } catch (err) {
        throw coded('link', `This link is damaged or incomplete. ${err.message}.`);
      }
      setStatus(status, 'busy', 'Fetching the file details…', 'meta');
      preview = C.parseHeader(await fetchBytes(`/api/meta/${id}`));
    } catch (err) {
      return setStatus(status, 'error', explain(err, false));
    }
    const restricted = (preview.flags & C.FLAG_PASSPHRASE) !== 0;
    // Which kind of link this is, before any prompt or work. The flag is what
    // the server sent until the details open (§7); a server that flips it gets
    // a file that does not open.
    $('download-public').hidden = restricted;
    $('download-restricted').hidden = !restricted;

    // After the details opened, the page knows the verified limits, so a file
    // gone since can be explained better than the server's one answer.
    function gone() {
      if (BigInt(Math.floor(Date.now() / 1000)) >= preview.expiresAt) {
        return `The server no longer has this file. By this device's clock it expired on ${formatTime(preview.expiresAt)}.`;
      }
      if (preview.maxDownloads > 0) {
        const limit = `${preview.maxDownloads} download${preview.maxDownloads === 1 ? '' : 's'}`;
        return `The server no longer has this file. Its limit of ${limit} may have been used up since this page opened, or it was deleted.`;
      }
      return 'The server no longer has this file. It has no download limit and had not expired by this device\'s clock, so it was most likely deleted since this page opened.';
    }

    // §10 steps 3–5.
    async function open(passphrase) {
      try {
        if (restricted) {
          flow.show(['stretch']);
          setStatus(status, 'busy', 'Checking the passphrase…', 'stretch');
          flow.wait('stretch', STRETCH_DETAIL);
        } else {
          setStatus(status, 'busy', 'Opening…', 'open');
        }
        const fileKey = await C.unlockFile(preview, secret, passphrase);
        // Opening the metadata verifies flags, expires_at and max_downloads (§7).
        const metadata = await C.decryptMetadata(fileKey, preview.headerCore);
        if (restricted) flow.done('stretch', 'Passphrase accepted.');
        showDetails(metadata);
        $('download-button').addEventListener('click', () => download(fileKey));
        setStatus(status, 'ready', 'Ready to download.');
        return true;
      } catch (err) {
        flow.fail();
        setStatus(status, 'error', explain(err, restricted));
        return false;
      }
    }

    function showDetails(metadata) {
      $('file-name').textContent = metadata.name;
      $('file-size').textContent = metadata.size < 1024
        ? formatBytes(metadata.size)
        : `${formatBytes(metadata.size)} (${metadata.size.toLocaleString()} bytes)`;
      const expiry = formatTime(preview.expiresAt);
      $('file-expiry').textContent = expiry;
      $('file-limit').textContent = preview.maxDownloads === 0
        ? 'none (expires by time only)'
        : `${preview.maxDownloads} download${preview.maxDownloads === 1 ? '' : 's'}`;
      // §8: the one server misbehaviour a client can see. Decrypt anyway; never
      // silently. The server refuses expired files itself, so this is reached
      // only through a skewed clock here or a server that ignores expiry.
      if (BigInt(Math.floor(Date.now() / 1000)) > preview.expiresAt) {
        $('expired-warning').textContent =
          `The sender set this link to expire on ${expiry}. The server provided it anyway.`;
        $('expired-warning').hidden = false;
      }
      $('details').hidden = false;
    }

    // §10 step 6.
    let downloading = false;
    async function download(fileKey) {
      if (downloading) return;
      downloading = true;
      const button = $('download-button');
      button.disabled = true;
      flow.show(restricted ? ['stretch', 'download', 'decrypt'] : ['download', 'decrypt']);
      if (restricted) flow.done('stretch', 'Passphrase accepted.');
      try {
        setStatus(status, 'busy', 'Downloading the encrypted file…', 'download');
        let blob;
        try {
          blob = await fetchBytes(`/api/download/${id}`, (received, total) => flow.measure('download', received, total,
            total ? `${formatBytes(received)} of ${formatBytes(total)}` : formatBytes(received)));
        } catch (err) {
          throw err.code === 'gone' ? coded('gone', gone()) : err;
        }
        flow.done('download', `${formatBytes(blob.length)} downloaded.`);

        setStatus(status, 'busy', 'Decrypting and checking every piece…', 'decrypt');
        flow.measure('decrypt', 0, 1, '0%');
        // Throws unless the header matches the preview, every record
        // authenticates, the final record is there and the size matches.
        // Nothing reaches the user before that.
        const { metadata, plaintext } = await C.decryptFile(fileKey, preview, blob,
          ({ done, total }) => flow.measure('decrypt', done, total, percent(done, total)));
        flow.done('decrypt', 'Every piece checked.');
        save(plaintext, metadata.name);
        setStatus(status, 'done', preview.maxDownloads === 1
          ? 'Downloaded. That was this link’s only download, so the server deletes the file now.'
          : 'Downloaded.');
      } catch (err) {
        flow.fail();
        setStatus(status, 'error', explain(err, restricted));
      } finally {
        downloading = false;
        button.disabled = false;
      }
    }

    if (!restricted) return open(undefined);
    $('unlock').hidden = false;
    setStatus(status, 'waiting', 'This file needs a passphrase.');
    $('unlock').addEventListener('submit', async (event) => {
      event.preventDefault();
      const passphrase = $('unlock-passphrase').value;
      if (passphrase === '') return setStatus(status, 'error', 'Enter the passphrase.');
      $('unlock-button').disabled = true;
      if (await open(passphrase)) $('unlock').hidden = true;
      $('unlock-button').disabled = false;
    });
  }

  const match = location.pathname.match(/^\/d\/([^/]*)$/);
  if (match) showDownload(match[1]);
  else showUpload();
})();
