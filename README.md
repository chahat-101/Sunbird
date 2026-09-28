# Sunbird

End-to-end encrypted file sharing for a small group. The browser does all the
cryptography; the server stores blobs it cannot read. The server hashes tokens
with SHA-256 and compares them in constant time. That is all the cryptography
it does, and it never looks inside a blob.

Licensed under the AGPL-3.0 (`LICENSE`): a hosted fork must publish the JavaScript it ships, the only lever against D1's excluded case, an operator serving modified JavaScript.

- `protocol.md` is the wire format. It is frozen: changing it breaks every
  link already shared.
- `DECISIONS.md` records what was chosen and why, so that a later change is a
  deliberate reversal rather than drift.
- `web/` is the browser client, built into the binary.
- `src/` is the server: `http.rs` (routes and handlers), `app.rs` (the data
  directory and the values requests carry), `db.rs` (schema and migrations),
  `config.rs` (members, admins, quotas), `limit.rs` (rate limits and the
  client address). `src/migrations/` is frozen once shipped, like the
  protocol.

## Status

Built in four sessions: 01 storage, the database, upload, download and
delete; 02 expiry; 03 authentication, quotas and rate limits. Uploads need a
member's token; downloads stay open. Session 04 (counters, the free-space
floor, deployment) is still to come; until then, keep the members' quotas,
summed, under the free space on the disk.

## Running

    cargo build --release
    target/release/sunbird mint-id       # one per person, once
    target/release/sunbird mint-token    # the token for them, the hash for the config
    target/release/sunbird -addr 127.0.0.1:8080 -data data -config sunbird.json

The config lists members (id, name, token hash, quotas), admins, trusted
proxies and the two rate limits. Every limit is required: the server has no
defaults. `sunbird.example.json` shows the shape; its numbers are an
illustration, not advice. An admin deletes any file with
`DELETE /api/admin/<id>` and `Authorization: Bearer <admin token>`; the
deletion is logged with the admin, the file and the uploader.

    cargo test                           # the Rust tests
    node web/test/run.mjs firefox        # crypto.html, client only
    node web/test/e2e.mjs chromium --phone

The browser tests need Node 22 and Firefox or Chromium, found as described in
`web/test/browser.mjs`. e2e.mjs also needs `cargo` on PATH.
