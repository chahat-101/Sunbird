# Sunbird — decisions

> The study these decisions cite by section (`§3.4`, `§Q5`, `§R3`, prior-art
> rows and file:line references) lives outside this repository.

Decided against `analysis/00-synthesis.md`. Each entry says what was chosen and
why, so a later change is a deliberate reversal rather than drift.

---

## D1. Threat model

**Defending against:** someone with root on the server who is not an intended
recipient. Concretely, a future administrator who inherits the box, or anyone
who takes a disk image or database dump.

**Not defending against:** an operator who serves modified frontend JavaScript.
Web-delivered crypto cannot survive that, and no project in the study solves it
(§3.4). State this in the README and in the talk.

**The honest claim:** *"Whoever runs this server cannot read your files. They
could, in principle, ship you modified JavaScript that leaks your key — a
native client would be needed to close that."*

Also not in scope: a recipient who already downloaded, and traffic analysis
(size and timing leak in every design, §Q5).

---

## D2. Restricted access (R1) — passphrase mixed into the content key

**Chosen:** PrivateBin's model. `content_key = KDF(fragment_secret, passphrase)`.
Both inputs are required to decrypt. Nothing passphrase-derived is ever sent to
the server.

**Rejected:** Send's model, where the password gates a server-side fetch and the
derived auth key is stored verbatim. Against D1 it is worth nothing — a
database dump lets the attacker sign the nonce and fetch ciphertext with no
password at all (send-tarnover, `server/routes/password.js:11`,
`server/middleware/auth.js:20-22`).

**Rejected for v1:** per-person X25519 wrapping. Needs accounts, a key
directory, and key-loss recovery. Nobody in the study solves the directory
honestly — ente's is the unverified server
(`server/pkg/controller/user/user.go:220-230`).

**Why this is strong against D1 specifically:** a root admin holds blobs and
database rows but not the fragment and not the passphrase. They cannot decrypt,
and cannot even begin an offline grind: a passphrase guess run through Argon2id
must still be combined with the 128-bit fragment they do not have before there
is anything to test it against. The offline-attack row in §R3 describes an
attacker holding *link plus blob* — not the adversary in D1.

**Amended in step 00:** the KDF salt is a random per-file value stored in the
blob header, not the fragment. The fragment is mixed in afterwards as HKDF
input keying material. Same security property against D1, without binding the
key to a server-controlled string — Send salts with the full share URL, which
is why a share opened through a different hostname derives a different key.
See `protocol.md`.

**KDF:** Argon2id, not PBKDF2. Someone who does obtain a link plus the blob can
grind offline, and Argon2id is what makes a human passphrase survivable there.

**Accepted limits:** not per-recipient. Anyone given the passphrase has access.
Revoking for one revokes for all.

**Workflow:** link and passphrase travel by different channels. Link in the
group chat; passphrase said aloud at the end of a session, or sent one to one.

---

## D3. Format — leave room for v2

Reserve a key-wrapping header slot from day one, even though v1 writes exactly
one entry (the passphrase-derived key). Wrapping can emulate derivation but not
the reverse (§Q2), so this is the difference between v2 being additive and v2
being a breaking change.

---

## D4. Public mode (R4) — same path, no second factor

One code path, one storage mode. Everything is encrypted; public means the
fragment alone decrypts, with no passphrase.

"Public but encrypted with a fragment" is R1-failing restricted mode under
another name (§R4) — here that is deliberate, and it avoids the middleware
drift that cost ente a rate limit on one of two paths.

Costs accepted: no CDN, no `sendfile`, no server-side preview, no moderation.

---

## D5. File size and streaming

**Ceiling:** 100 MB, enforced server-side.

**Download:** assemble to a Blob. No Service Worker. It exists to avoid holding
gigabytes in memory; at 100 MB it buys nothing.

**Format:** chunked AEAD anyway — 64 KiB records, authenticated end-of-stream.
Not for memory, but because the wire format cannot change later without
breaking every existing link. Whole-file GCM is what capped PrivateBin at
5-6 MB (`readAsDataURL`) and epherra at ~15 MB (base64-in-JSON).

**If the ceiling ever rises:** the format already supports streaming; add the
Service Worker then.

---

## D6. Expiry (R5)

**Both limits, first one wins.**

- **Count:** atomic claim before serving, refund on failed transfer
  (send-tarnover, `server/routes/download.js:11-19`). Count *completed*
  downloads. Suppress preview bots via `Vary: Accept` (PrivateBin).
- **Time:** lazy check on read, plus a sweeper on a timer. Not
  purge-on-upload — a quiet instance keeps blobs forever (PrivateBin).
- **Deletion:** verify it. Check the blob is gone after unlinking and log
  failures loudly. Send's filesystem backend never deletes time-expired blobs
  in either fork, behind a dead config flag (`server/config.js:115-119`) — the
  single most repeated failure in the study (§3.1). Scope: "verified" means
  confirmed gone from the filesystem — not overwritten; snapshots and backups
  are out of scope.
- **Tamper-evidence, narrowly:** bind the limits into AEAD additional data
  (PrivateBin). This proves the limits *the uploader set*; it does not prove
  the server honoured them. A client can check expiry against its own clock,
  but cannot know how many downloads already happened. The claim is only:
  *a server cannot silently alter the limits an uploader chose.* It can still
  serve past them. (Amended in step 00.)

---

## D7. Metadata

Filename, MIME type, and size go in a separate encrypted object under its own
subkey. A real random IV — Send uses an all-zero IV here
(`app/keychain.js:127`).

**Size still leaks** to the server and cannot not: quotas need it (§Q5).

**Render decrypted metadata as hostile input.** Six of PrivateBin's twelve
advisories come from displaying a decrypted filename or MIME type (§3.9).

---

## D8. Client

Web only for v1. Not because it is better — it makes R2 a policy rather than a
property (§5.2) — but because most people will not adopt a CLI, and adoption
is the point.

A Go CLI is on the roadmap as the honest mitigation for D1's excluded case. The
server is already Go, and ffsend shows constant-memory streaming is
straightforward outside a browser.

**Amended when the server was rewritten in Rust (session 01) — a deliberate
reversal of the aside, not the decision.** A native client is still the honest mitigation for D1's excluded
case, and the web client is still v1. But "the server is already Go" no longer
holds: the server is now Rust. That strengthens the argument rather than
weakening it. ffsend, prior-art row 07, is a Rust CLI, and it is the evidence
that constant-memory streaming is straightforward outside a browser. A Rust CLI
could also share format code with the server: the few rules the server has
(`max_blob`, the ID and upload-parameter spellings), and any §-level constants
kept beside them. The roadmap item is now a native CLI, most likely in Rust.
The paragraph above keeps the original wording, as the record of what was
decided then.

---

## D9. Operations

- **Bytes through the app.** One VPS, no object storage. Pins R6 to session
  affinity; R6 is explicitly later.
- **Upload is authenticated.** Known members only, from an explicit member
  list, with per-user quotas and rate limits. Firefox Send shipped anonymous and unquota'd and died of it.
- **Store `uploader_id`.** Cannot see the file; can revoke and can answer a
  takedown.
- **Trust the proxy correctly.** Do not read `X-Forwarded-For[0]` blindly
  (epherra, PrivateBin both get this wrong). Walk it over configured trusted
  proxies; throttle IPv6 by /64 (Nextcloud `Request.php:541-580`).
- **Defaults:** 24 hour expiry, 7 day maximum, download limit 1.

**Amended in R5: a deliberate reversal of part of the second bullet.** Tokens
used to be admin-minted only. An operator may now also let people register
themselves by signing in with Google. Uploads are still authenticated, with
quotas and rate limits, and still recorded under a member id.

*Why.* Adding every person by hand does not scale with adoption (D8). Google
sign-in proves "a person with a Google account" with no mail server, passwords
or account database of our own.

*The rule.* Signing in gets you a token; it is not a way to upload. Uploads
still need `Authorization: Bearer <token>` and nothing else, so there is one
upload path (D4). `App::member(token)` returns the same `Member` whether the
token came from the config or from a sign-in, and a test fails if the upload
handler ever mentions sign-in. Admin-minted tokens work unchanged.

*What we keep.* One table, `google_members`: a SHA-256 of Google's `sub`, the
member id, the hash of the current token, and a `banned` flag. No email, name,
picture or Google token. Signing in again mints a new token for the same member
id, so quota and files carry over, and it doubles as token recovery.

*No sessions.* No cookie, no session table. The redirect carries a random
`state` and `nonce`, held in memory for 10 minutes and spent on first use. The
ID token is checked server-side: RS256 only, signature against Google's cached
keys, then `iss`, `aud`, `exp`, `iat` and `nonce`.

*Bounds.* A Google account is free, so this proves little about who someone is.
`max_members` caps how many people exist, self-service members get lower default
quotas, and an admin can ban a member. A ban keeps the `sub` hash and holds its
place under the cap. Sign-in requests share the per-address `read_rate`.

*Accepted.* Google learns the person used this instance. With no cookie the flow
is not tied to a browser, so someone can be handed another person's callback;
that gives the other person nothing.

*Dependencies.* BUILD.md allowed no crypto crate beyond `sha2` and `subtle`.
Checking Google's RSA signatures and reaching Google over TLS needs `ring`,
`rustls`, `tokio-rustls` and `webpki-roots`. The server still never touches
file contents or file keys.

---

## D10. Sharing graph

Not applicable to v1 — no accounts means no graph. Becomes a real question only
if per-recipient wrapping arrives (§Q4).

---

## Deliberately deferred

- Per-recipient keys and accounts (D2, D3)
- Native CLI (D8)
- Distributed operation, R6 (D9)
- Key loss and multi-device recovery — no prior art found in the study (§5.4)
- Files above 100 MB (D5)

## Claims not to make

From §3.11, the projects that overstate. Do not join them.

- Not "zero-knowledge" — the server ships the JavaScript (D1).
- Not "files are deleted" unless deletion is verified (D6).
- Not "protocol unchanged" across any KDF or format change. Version the format.
- Not "anonymous" or "no third party" for Google sign-in: Google learns the
  person used this instance. Admin-minted tokens involve no third party.
