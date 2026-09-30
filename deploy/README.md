# Running Sunbird for real

Notes for whoever looks after the server. The files mentioned here sit next
to this one; paths are from the repository root.

## Setting it up

Caddy handles HTTPS; Sunbird runs behind it on 127.0.0.1:8080 under systemd.

1. `cargo build --release`, then copy `target/release/sunbird` to `/usr/local/bin/`.
2. `useradd --system --no-create-home --shell /usr/sbin/nologin sunbird`
3. Write `/etc/sunbird/sunbird.json` from `deploy/sunbird.example.json`
   (owner root, group `sunbird`, mode 0640).
4. Install `deploy/sunbird.service` in `/etc/systemd/system/` and run
   `systemctl enable --now sunbird`. Data lives in `/var/lib/sunbird`.
5. Put your host name in `deploy/Caddyfile` and install it.

**Always use HTTPS.** The server never sees a file's key, but it does send
the JavaScript that reads it. Over plain HTTP, anyone on the network could
swap that code for one that leaks the key.

## Choosing the limits

Make sure the disk can hold everyone's quota at once:

    members × max_active_bytes + min_free_bytes  ≤  free disk space

If not, a full disk refuses uploads (507) for everyone.

- `max_active_bytes`: largest file (up to ~100 MB) × how many live at once.
- `max_active_files`: tens, not thousands.
- `max_bytes_per_week`: a small multiple of `max_active_bytes`. Deleting
  doesn't refund it.
- `min_free_bytes`: a few GB or 5% of the disk, whichever is larger.
- `upload_rate`: a brake on scripts or leaked tokens. A few dozen an hour.
- `read_rate`: per address. A school or office behind one NAT counts as one
  address, so allow at least twice the biggest room's headcount over a few
  minutes, e.g. `{"requests": 600, "seconds": 300}`.

## People

Config changes need `systemctl restart sunbird`.

- **Add:** run `sunbird mint-id` and `sunbird mint-token`, add the entry,
  restart, hand over the token.
- **Remove:** delete the entry and restart. **Their files stay up** until
  they expire (at most 7 days). To remove them sooner, find the ids with
  `SELECT id FROM blobs WHERE uploader_id = '<member id>'` and delete each
  with `DELETE /api/admin/<id>`.
- **Lost or leaked token:** mint a new one for the same entry.

## Counters

    curl -H "Authorization: Bearer <admin token>" https://files.example.org/admin/stats

Totals only, never per file or person, also logged hourly.

| counter | what it counts |
|---|---|
| `uploads`, `bytes_uploaded` | files stored, and their size |
| `downloads` | downloads the server finished sending |
| `failed_downloads` | downloads that didn't finish; each was refunded |
| `failed_uploads` | uploads within limits that stored nothing. Refusals don't count |
| `expired_swept` | files deleted because their time ran out |
| `deletion_failures` | failed deletion attempts. Should stay 0 |
| `rate_limited_uploads`, `rate_limited_reads` | 429s from each limit. Rising reads mean `read_rate` is too low |
| `uploads_refused_low_disk` | 507s at the disk floor |
| `counting_since` | when the totals started (Unix time) |

A download counts once the proxy has the bytes, not the person. If someone
says "the link was used but I never got the file", that's usually why.

## Backups

The server never has the links, so a backup can't rescue a lost one. Restoring
the database alone deletes every file uploaded since the backup. Restoring
files too brings back ones that were taken down, so every takedown since
must be redone. For most groups, back up the config file only.

## Upgrades

Never edit a migration that has shipped (`src/migrations/`); add a new one.
A binary that meets a newer database refuses to start and changes nothing.
