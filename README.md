# Sunbird

End-to-end encrypted file sharing for a small group. The browser does all the
cryptography; the server stores blobs it cannot read. The server hashes tokens
with SHA-256 and compares them in constant time. That is all the cryptography
it does, and it never looks inside a blob.

- `protocol.md` is the wire format. It is frozen: changing it breaks every
  link already shared.
- `DECISIONS.md` records what was chosen and why, so that a later change is a
  deliberate reversal rather than drift.
- `web/` is the browser client, built into the binary.
- `src/` is the server: `http.rs` (routes and handlers), `app.rs` (the data
  directory and the values requests carry), `db.rs` (schema and migrations).
  `src/migrations/` is frozen once shipped, like the protocol.

## Status

Built in four sessions. The first, this one, covers storage, the database,
upload, download and delete, plus schema versioning. It is **not deployable**:

- uploads are not authenticated;
- expiry and download limits are validated and stored, but not enforced;
- there are no quotas, rate limits, counters or disk floor.

Those come in sessions 02 (expiry), 03 (auth, quotas, limits) and 04
(counters, deploy).

## Running

    cargo build --release
    target/release/sunbird -addr 127.0.0.1:8080 -data data

    cargo test                           # the Rust tests
    node web/test/run.mjs firefox        # crypto.html, client only
    node web/test/e2e.mjs chromium --phone

The browser tests need Node 22 and Firefox or Chromium, found as described in
`web/test/browser.mjs`. e2e.mjs also needs `cargo` on PATH.
