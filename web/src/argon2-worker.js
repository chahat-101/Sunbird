// Runs hash-wasm's argon2id off the page's main thread. At 64 MiB it holds a
// thread for seconds; on the main thread that freezes the tab, and on a phone
// a frozen tab reads as a crash.
//
// It runs exactly what it is sent. Every parameter comes from crypto.js
// (ARGON2ID, protocol.md §4.1); nothing here chooses one. One Worker per
// call, ended by argon2.js once it answers, so the 64 MiB goes with it.
'use strict';
importScripts('/vendor/hash-wasm/argon2.umd.min.js');

self.onmessage = async (event) => {
  try {
    const hash = await self.hashwasm.argon2id({ ...event.data, outputType: 'binary' });
    self.postMessage({ hash }, [hash.buffer]);
  } catch (err) {
    self.postMessage({ error: String((err && err.message) || err) });
  }
};
