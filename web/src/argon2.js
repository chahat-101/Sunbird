// A drop-in `hashwasm.argon2id` that runs in a Worker (argon2-worker.js), so
// the tab doesn't freeze. crypto.js calls it just like hash-wasm, so the
// parameters stay in crypto.js.
(function (global) {
  'use strict';

  const WORKER = '/src/argon2-worker.js';

  // A person reads this message (app.js shows it as is).
  function failed(why) {
    const err = new Error(`This browser could not stretch the passphrase (${why}), so nothing was done with the file.`);
    err.code = 'passphrase-worker';
    return err;
  }

  function argon2id(options) {
    return new Promise((resolve, reject) => {
      if (options.outputType !== 'binary') {
        reject(new Error('only binary output is supported'));
        return;
      }
      let worker;
      try {
        worker = new Worker(WORKER);
      } catch (err) {
        reject(failed(`the worker did not start: ${err.message}`));
        return;
      }
      const end = (settle, value) => {
        worker.terminate(); // frees its 64 MiB at once
        settle(value);
      };
      worker.onmessage = (event) => {
        if (event.data.hash instanceof Uint8Array) end(resolve, event.data.hash);
        else end(reject, failed(`Argon2id failed: ${event.data.error}`));
      };
      // A script that fails to load, or is refused, arrives here.
      worker.onerror = (event) => {
        event.preventDefault();
        end(reject, failed(event.message || 'the worker did not load'));
      };
      const { password, salt, iterations, memorySize, parallelism, hashLength } = options;
      worker.postMessage({ password, salt, iterations, memorySize, parallelism, hashLength });
    });
  }

  // Not frozen: the tests wrap argon2id to count calls, as they wrap hash-wasm's.
  global.hashwasm = { argon2id };
})(globalThis);
