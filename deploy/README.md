# Running Sunbird for real

For whoever looks after the server. Paths are from the repository root.

## Setting it up

Caddy handles HTTPS, and Sunbird runs behind it on 127.0.0.1:8080 under systemd.

1. `cargo build --release`, then copy `target/release/sunbird` to `/usr/local/bin/`.
2. `useradd --system --no-create-home --shell /usr/sbin/nologin sunbird`
3. Write `/etc/sunbird/sunbird.json` from `deploy/sunbird.example.json`
   (owner root, group `sunbird`, mode 0640).
4. Install `deploy/sunbird.service` in `/etc/systemd/system/` and run
   `systemctl enable --now sunbird`. Data lives in `/var/lib/sunbird`.
5. Put your host name in `deploy/Caddyfile` and install it.

Always use HTTPS. The server never sees a file's key, but it sends the
JavaScript that reads it, and over plain HTTP anyone on the network could swap
in a version that leaks it.

## Choosing the limits

The disk has to hold everyone's quota at once:

    members × max_active_bytes + max_members × (google_signin max_active_bytes)
      + min_free_bytes  ≤  free disk

If it can't, a full disk refuses uploads (507) for everyone.

- `max_active_bytes`: largest file (up to ~100 MB) × how many live at once.
- `max_active_files`: tens, not thousands.
- `max_bytes_per_week`: a small multiple of `max_active_bytes`. Deleting a file
  doesn't refund it.
- `min_free_bytes`: a few GB or 5% of the disk, whichever is larger.
- `upload_rate`: a brake on scripts or leaked tokens. A few dozen an hour.
- `read_rate`: per address. Everyone behind one shared or institutional network
  address (NAT) counts as one, so allow at least twice the headcount of the
  largest group likely to open links together over a few minutes, e.g.
  `{"requests": 600, "seconds": 300}`.

## People

Any config change needs `systemctl restart sunbird`.

To add someone, run `sunbird mint-id` and `sunbird mint-token`, add the entry,
restart, and hand over the token. Removing someone is deleting their entry, but
their files stay up until they expire (at most 7 days). To remove those sooner,
find them with `SELECT id FROM blobs WHERE uploader_id = '<member id>'` and
delete each with `DELETE /api/admin/<id>`. For a lost or leaked token, mint a
new one for the same entry; Google members just sign in again.

## Sign-in with Google (optional)

Leave `google_signin` out of the config and nobody can sign in. To turn it on:

1. In your Google Cloud project, make an OAuth client of type "Web application"
   with `https://<your host>/auth/google/callback` as a redirect URI.
2. Add `google_signin` to the config: `client_id`, `client_secret`,
   `redirect_uri` (as registered), `max_members`, and the three quotas these
   members get. All of them are required.
3. Keep the client secret in the config file only (mode 0640). `.gitignore`
   covers `/sunbird.json` and `deploy/*.json`, but check before you commit.
4. Restart. The server needs to reach Google over HTTPS.

Each person who signs in gets a row in `google_members`: a hash of their Google
`sub`, their member id, the hash of their token and a `banned` flag, and nothing
else. `max_members` counts everyone who ever signed up, banned or not. Anyone
with a Google account can join, so give these members lower quotas than your
own. Sign-in requests count against `read_rate`.

To ban someone:

    curl -X POST -H "Authorization: Bearer <admin token>" https://files.example.org/api/admin/ban/<member id>

Their token stops working and they can't sign in again, but their files stay
until they expire; delete them as above. Member ids show in the log at sign-up
and in `blobs.uploader_id`. To lift a ban:

    sqlite3 /var/lib/sunbird/sunbird.db "UPDATE google_members SET banned = 0 WHERE member_id = '<id>'"

Turning sign-in off stops all their tokens working; turning it on restores them.

## Counters

    curl -H "Authorization: Bearer <admin token>" https://files.example.org/admin/stats

Totals only, never per file or person, and also logged hourly.

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

A download counts once the proxy has the bytes, not once the person does. If
someone says the link was used but they never got the file, that's usually why.

## Backups

The server never has the links, so a backup can't rescue a lost one. Restoring
the database alone deletes every file uploaded since the backup, and restoring
the files too brings back ones that were taken down, so every takedown since
must be redone. For most instances, back up only the config file. Google members
live in the database; if you lose it, they sign in again as new members.

## Upgrades

Never edit a migration that has shipped (`src/migrations/`); add a new one. A
binary that meets a newer database refuses to start and changes nothing. This
version adds `google_members` (schema 6), so older binaries won't open it.
