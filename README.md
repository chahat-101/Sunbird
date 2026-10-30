# Sunbird

Sunbird is a small file-sharing server you host yourself. You pick a file, your
browser encrypts it, and you get a link to send to whoever needs it.

The key lives in the part of the link after `#`. Browsers don't send that part
to the server, so all the server ever holds is scrambled bytes. Files go away
on their own: after 24 hours by default (7 days at most), or once they've been
downloaded as many times as you allowed.

Only members with an upload token can upload; anyone with the link can
download. For a second lock, add a passphrase and send it some other way. If
you'd rather no link carried a key at all, ask for the file with a request link
(see below).

## The page

It's one page, built into the server, with no framework and no build step. It
follows your device's light or dark setting until you pick one.

The upload button says what you're about to make, for example "Encrypt and
upload (public link)". Each wait is a named step with its own progress, and the
slow one, stretching a passphrase, says why it's slow. Colour never means
anything on its own: amber (a public link, or a file served past its expiry),
green and red always come with their own icon or words.

The recipient sees what kind of link it is, the file's details and a Download
button. The page never opens or previews the file, and shows file names as
plain text, never as HTML.

## Request links

To have someone send you a file, open `/r` and make a request link. Your
browser makes a key pair and keeps the private half. The link holds only the
public half, so it is safe to post anywhere. You also get a fingerprint, 12
characters in three groups.

The sender opens the link, checks with you that the fingerprint on their
screen matches yours, and uploads. They get back a plain `/d/<id>` link with
nothing after it, and send it to you. Open it in the same browser and the file
decrypts.

Their limits:

- A request works only in the browser that made it. Opened anywhere else, the
  link says so, and no download is used up.
- In a private window the key is lost when the window closes, and so is
  anything sent to the request.
- The key stays on your device until a file sent to it has been opened, or for
  7 days. Until then, anyone who can use that browser profile can use it.
- The sender must be signed in: they need an upload token like anyone else.
- One request takes one file. At most 20 requests can wait in one browser.
- The fingerprint check is what catches a link someone changed on its way to
  the sender. If the sender skips it, nothing else does.
- The browser needs X25519 in WebCrypto. One without it says so.

## Running it

    cargo build --release
    target/release/sunbird mint-id       # an id for each member or admin
    target/release/sunbird mint-token    # their token, and its hash for the config
    target/release/sunbird -addr 127.0.0.1:8080 -data data -config sunbird.json

Start your config from `deploy/sunbird.example.json`. Every limit in it is
required. The binary carries its own web page, so it doesn't need a `web/`
folder next to it.

To run the tests:

    cargo test
    node web/test/e2e.mjs firefox        # or chromium; add --phone

## Upload tokens

Every upload sends `Authorization: Bearer <token>`, wherever the token came
from. An admin can make one with `sunbird mint-token`, with no third party
involved. If the operator allows it, you can also get one by signing in with
Google, which tells Google you used this instance. Sunbird keeps a one-way hash
of an opaque Google identifier and nothing else, not your email. Signing in
again gives you a new token for the same member: your quota and files carry
over and the old token stops working, which is also how you recover a lost
one. Since a Google account is easy to make, the operator limits sign-ups with
`max_members`, lower quotas and bans.

## What it doesn't protect against

It isn't zero-knowledge. The server can't read your files, but it does serve
the JavaScript that encrypts them, so a dishonest operator could change that
code to leak your key. Only a native client would close that gap.

The server still sees each file's size, and when it's uploaded and downloaded.
With Google sign-in on, Google knows you used this instance. And anyone with
the link (plus the passphrase, if there is one) can open the file. A file sent
to a request link is the exception: it opens only with the request's key, in
the browser that made the request.

Deletion is checked, not forensic. Sunbird unlinks the blob, then checks the
path to confirm it's gone. If it's still there, the row stays marked, the
failure is logged loudly, and every sweep retries. It doesn't overwrite blocks,
which isn't reliably possible from userspace on an SSD, and it doesn't reach
filesystem snapshots or backups. That matters less than it sounds, because the
server never holds a key: a blob that survives a failed delete is ciphertext
the operator can't read. Verified deletion is a second layer, for when a link
leaks from somewhere else.

## Licence

AGPL-3.0, except for the photograph of two sunbirds in `web/assets/`. It isn't
the project's work, the AGPL doesn't cover it, and its source and licence
aren't recorded yet.

## More

`deploy/README.md` is for running it for real. `DECISIONS.md` says what was
chosen and why. `protocol.md` is the file format, which is versioned; this is
version 1.
