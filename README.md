# Sunbird

A small file-sharing server for a group that knows each other, such as a
club. You pick a file, Sunbird encrypts it in your browser, and you get a
link to send to whoever needs it.

The key to the file lives in the part of the link after `#`. Browsers never
send that part to the server, so the server only ever holds scrambled bytes.
Files disappear on their own: after 24 hours by default (7 days at most), or
once they have been downloaded as many times as you allowed.

Only members with an upload token can upload. Anyone with the link can
download. If you want an extra lock, add a passphrase, and send it by a
different route from the link.

## What it looks like

One page, built into the server, with no framework and no build step. It
follows your device's light or dark setting.

The upload page asks four things, in order: the file, your upload token,
who can open it, and how long it lasts. The button then says exactly what
you are about to make, such as "Encrypt and upload (public link)". While it
works, every wait is a named step with its own progress, and the slow one
says why it is slow on purpose.

Colour only ever means something:

- **orange** is the name and the one button to press;
- **green** is progress and success;
- **amber** warns that a link is public;
- **red** is for errors, and for a file served after its expiry date.

The recipient's page stays short and quiet: what kind of link it is, the
file's details, and a Download button. It never opens or previews the file.
File names are shown as plain text, never as HTML.

## Running it

    cargo build --release
    target/release/sunbird mint-id       # an id for each member or admin
    target/release/sunbird mint-token    # their token, and its hash for the config
    target/release/sunbird -addr 127.0.0.1:8080 -data data -config sunbird.json

Start your config from `deploy/sunbird.example.json`. Every limit in it is
required. The binary carries its own web page, so it needs no `web/` folder.

To run the tests:

    cargo test
    node web/test/e2e.mjs firefox        # or chromium; add --phone

## What it does not protect against

- **It is not zero-knowledge.** The server cannot read your files, but it
  serves the JavaScript that encrypts them, so a dishonest operator could
  change that code. Only a native client would close that gap.
- The server still sees each file's size, and when it is uploaded and
  downloaded.
- Anyone with the link (and the passphrase, if there is one) can open the
  file.
- "Deleted" means removed from disk and checked gone, not securely erased.

## Licence

AGPL-3.0. The one exception is the photograph of two sunbirds in
`web/assets/`. It is not the project's work, it is not covered by the AGPL,
and its source and licence are not recorded yet.

## More

- `deploy/README.md`: running it for real (TLS, members, limits, backups).
- `DECISIONS.md`: what was chosen, and why.
- `protocol.md`: the file format, version 1.
