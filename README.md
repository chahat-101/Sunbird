# Sunbird

End-to-end encrypted file sharing for a small group, such as a club. Upload a
file, get a link, send it. The file is encrypted in your browser before it
leaves your device, and the key is in the part of the link after `#`, which
browsers never send to the server. The file is deleted when its time runs out
(24 hours by default, 7 days at most) or its downloads are used up. Only
members with an upload token can upload; anyone with the link can download.

Licensed under the AGPL-3.0. The exception is the photograph of two
sunbirds in `web/assets/` (`sunbird.jpg` and `sunbird.webp`, both cropped
from it), which is not the project's work and is not covered by the AGPL.
Its source and licence are not recorded yet.

## The interface

One page, built into the server binary, with no framework and no build step.

**Theme.** Ink on warm paper: an off-white page (`#f6f5f1`, near-black in
dark mode, which follows the device automatically), near-black text, and
the system font on a deliberate scale: small capitals for labels, larger
type for what they label. The name is set in an old-style serif from the
system (Iowan, Palatino, or a clone of it). Colour is kept for meaning, so
it stands out:

- **orange**, the photo's flowers, is the name and the one action to take:
  upload, open, download;
- **green** is success and progress: the bars, the finished steps,
  "Uploaded.", "Downloaded.";
- **amber**, with a globe, marks a *public link*, which opens for anyone who
  has it;
- **red** is only for errors, and for the one warning a recipient must not
  miss: a file served after its expiry date.

A *passphrase-protected* link is marked by its lock and its words, in ink.

**Layout.** The upload page opens with the name and tagline on the left
and the photograph beside them. Below, divided by space and hairline rules
rather than boxes, are the decisions, numbered in the order you make them:
01 *File* and 02 *Upload token* (what is sent, and by whom), then 03 *Who
can open it* and 04 *Limits* (who can open it, and for how long), then one
button, whose label says what you are about to make: "Encrypt and upload
(public link)". On a wide screen the two pairs sit side by side; below
60rem it is one column in the same order. The waits (stretching
the passphrase, encrypting, uploading; downloading, decrypting) are a
timeline: each step a marker that fills as it finishes, and only the step
under way shows its bar and why it takes as long as it does. The recipient's
page is the same style: which kind of link it is, the file's details, then a
Download button.

**Design choices.**

- **Say what is happening.** Every wait is a named step with its own
  progress. The slow step says why it is slow on purpose.
- **Say it before, not after.** The page explains a public link before the
  upload, not in the result. The owner token is shown once, in a heavy
  box saying so.
- **Built for phones.** Every control is at least 44 px tall, inputs use
  16 px text so phones do not zoom, and nothing scrolls sideways at 390 px.
- **Accessible.** A visible focus ring, status messages announced to screen
  readers, and no animation when the device asks for reduced motion.
- **Safe to display.** Decrypted file names are shown as plain text, never
  HTML. The page loads only its own scripts, styles and one photo.

The recipient's page has no photo and no display type (the name is at a
reading size), and does not fetch the image.

The files are `web/index.html`, `web/app.css`, `web/src/app.js` and
`web/assets/`.

## Running

    cargo build --release
    target/release/sunbird mint-id       # an id for each member or admin
    target/release/sunbird mint-token    # their token, and its hash for the config
    target/release/sunbird -addr 127.0.0.1:8080 -data data -config sunbird.json

Start the config from `deploy/sunbird.example.json`. Every limit in it is
required. The binary needs no `web/` directory beside it.

    cargo test
    node web/test/e2e.mjs firefox        # or chromium; add --phone

## Limitations

- **Not zero-knowledge.** The server cannot read your files, but it serves the
  JavaScript that does the encryption, so a dishonest operator could change
  it. A native client would be needed to close that.
- The server sees each file's size and when it is uploaded and downloaded.
- Anyone with the link (and passphrase, if set) can open the file.
- "Deleted" means removed from disk and checked gone, not securely erased.

## More

- `deploy/README.md`: running it for real, with counters, TLS, limits,
  members, backups and upgrades.
- `DECISIONS.md`: what was chosen and why.
- `protocol.md`: the file format, version 1.
