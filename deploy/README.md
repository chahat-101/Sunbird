# Running Sunbird for real

Operator notes: what the server counts, how to deploy it behind Caddy and
systemd, how to pick the limits, members, backups and upgrades. The files
this refers to (`Caddyfile`, `sunbird.service`, `sunbird.example.json`) are
beside it. Paths below are from the repository root.

## Counters

The server counts, in totals only: never which file, never which member.

    curl -H "Authorization: Bearer <admin token>" https://files.example.org/admin/stats

returns them as JSON (401 without an admin token). The same line is logged
every hour and at shutdown, as `counters: {...}`. They are kept in memory,
saved to the database every minute and at shutdown, and carried on after a
restart. A crash, or a SIGKILL, loses at most the last minute of them.

| counter | counts |
|---|---|
| `uploads`, `bytes_uploaded` | files stored, and their blob bytes |
| `downloads` | downloads the server completed (below) |
| `failed_downloads` | downloads started and not completed; each was refunded |
| `failed_uploads` | uploads by a member, within their limits, that stored nothing: the client went away, the server failed, or shutdown cut them off. Refusals (401, 413, 429, 507) are not failures |
| `expired_swept` | files the sweeper deleted after their expiry time |
| `deletion_failures` | failed deletion attempts, one per attempt: a stuck file adds one a minute until it goes. Should stay 0 |
| `rate_limited_uploads`, `rate_limited_reads` | 429s from each limiter |
| `uploads_refused_low_disk` | 507s at the disk floor |
| `counting_since` | Unix time the totals start from |

**What "completed" means.** A download counts as completed when the server
has handed the last bytes of the blob to its HTTP layer for the connection.
To a client that has stopped reading, that layer may still be holding up to
about 400 KiB of it unsent. Behind a reverse proxy, "sent" means the proxy
has the bytes, not the recipient. A
proxy buffers a small file whole, so a recipient who drops off partway may
still have used up the file's one download. `failed_downloads` undercounts
for the same reason: a transfer that dies after the proxy has the bytes is
not a failure the server can see. The count is of transfers the server
completed, not of files people received. When someone reports "the link says
it was used but I never got the file", check this first.

## Deployment

`deploy/` holds one layout: Caddy on the same machine terminating TLS, the
server on 127.0.0.1:8080 under systemd.

1. Build with `cargo build --release` and copy `target/release/sunbird` to
   `/usr/local/bin/`.
2. `useradd --system --no-create-home --shell /usr/sbin/nologin sunbird`.
3. Write `/etc/sunbird/sunbird.json` from `deploy/sunbird.example.json`,
   owned by root, group `sunbird`, mode 0640. It holds only hashes, but it is
   the list of who may upload.
4. Install `deploy/sunbird.service` in `/etc/systemd/system/`, then
   `systemctl enable --now sunbird`. The data directory is
   `/var/lib/sunbird`, mode 0700.
5. Put your host name in `deploy/Caddyfile` and install it as Caddy's config.

### TLS is not optional

The fragment of a link, the key, never reaches the server. But the
JavaScript the server sends is what reads the fragment and does the
decryption. Over plain HTTP anyone on the path, the café Wi-Fi or the
campus network, can replace that JavaScript with one that sends the key
somewhere else. That is D1's excluded case, an operator serving modified
JavaScript, handed to anyone who can get between the browser and the
server. Serve it over HTTPS only. The Caddyfile redirects plain HTTP and sets
HSTS, so a browser that has visited once will not accept plain HTTP from
the host again.

### Picking the numbers

Quotas bound each member, not the disk. The worst case is every member full
at once:

    members × max_active_bytes + min_free_bytes  ≤  free space on the disk

**This must hold.** If it does not, uploads are refused with 507 at the floor
once the disk fills, and every member gets that refusal, not just the ones
who filled it. Without a floor the disk would run out mid-write, and uploads
would fail at 90%.

- `max_active_bytes`: at least the largest file a member should be able to
  send (the ceiling is about 100 MB), times how many they may have live at
  once. Divide the disk by the number of members first, then pick.
- `max_active_files`: how many live links one person needs. Tens, not
  thousands.
- `max_bytes_per_week`: bounds churn. Deleting a file does not give any of
  it back, so upload-delete-repeat cannot get around it. A small multiple of
  `max_active_bytes`.
- `min_free_bytes`: room for everything else that writes to this disk (the
  database and its WAL, the journal, the OS), plus 1 MiB for every upload that
  might be in progress at once. The floor is checked before an upload's body
  against its declared length, and again at least every MiB while it streams,
  so parallel uploads can each write up to 1 MiB past the last check. A few
  GB, or 5% of the disk, whichever is larger.
- `upload_rate`, per member: uploads need a member's token, so the quotas
  already do the real limiting. This is a brake on a script, or on a leaked
  token. A few dozen an hour.
- `read_rate`, per client address (an IPv6 /64 counts as one address),
  covers previews and downloads. Opening a
  link costs two requests: the preview, and the download if the recipient
  goes on.

Every campus, school or office behind one NAT address is a single client to
the download limit: a lecture hall opening one link at once is one address
making hundreds of requests. Downloads are unauthenticated, since the link
is all a recipient has, so there is nothing else to key the limit on, and no
cleverer limiter fixes it. Size `read_rate` for the largest room that will
open one link together: at least twice its headcount in `requests`, over a
few minutes in `seconds`. The limit refills evenly across its window, so
`{"requests": 600, "seconds": 300}` allows a burst of 600, then two a
second. Then watch `rate_limited_reads`, `failed_downloads` and
`failed_uploads` in `/admin/stats`. A rising 429 count after a class is a
limit set too low for that room.

### Members

Config changes take effect on a restart (`systemctl restart sunbird`, which
is a graceful shutdown and a start).

- **To add a member**, run `sunbird mint-id` and `sunbird mint-token`. Add an
  entry with that id, a name, the token hash and the three quotas, restart,
  and give them the token. Check that the disk sum above still holds.
- **To remove a member**, delete their entry and restart. Their token stops
  working at once. **Their files are not deleted.** They stay recorded under
  the member's id, and are served until they expire (at most 7 days after
  upload) or are used up. To take them down sooner, an admin deletes each
  with `DELETE /api/admin/<id>`. There is no endpoint that lists a member's
  files, by design, so the ids come from the database:
  `SELECT id FROM blobs WHERE uploader_id = '<member id>'`.
- **A lost or leaked token** is a new `mint-token` for the same entry: the id,
  and so the files and quota, stay theirs.

### Backups

Think before backing up. A blob is useless without its link, and the links
exist only in whoever's chat window they were pasted into; the server never
had them. So a backup can never help anyone open a file whose link is gone.
It can only bring back state:

- **The database alone, restored** after files have expired: its rows point at
  blobs that were deleted since. Rows with time left come back, and 404 on
  download, having no blob. Worse, the server deletes at startup every blob
  with no row, which is every file uploaded since the backup. The counters and
  the upload ledger go back to the backup's values too.
- **The database and blobs together, restored:** files come back that were
  used up, deleted by their owner, or taken down by an admin. **Every takedown
  since the backup must be done again**, from the admin log lines
  (`ADMIN DELETE`).

For most groups the right backup is the config file only.

### Upgrades

The database schema is changed only by migrations (`src/migrations/`, and
`MIGRATIONS` in `src/db.rs`). From the first real deployment, every shipped
migration is frozen: a change is a new migration appended to the list, never
an edit to an old one, not even its whitespace. A database that ran the old
text keeps its result forever, with nothing to tell it apart. A binary that
meets a database newer than itself refuses to start and changes nothing.
