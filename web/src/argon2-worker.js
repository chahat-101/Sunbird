// Runs argon2id off the main thread; at 64 MiB it takes seconds, and a frozen
// tab looks like a crash on a phone. It uses exactly the parameters it's sent
// (from crypto.js), and each call gets a fresh Worker so the memory is freed.
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
