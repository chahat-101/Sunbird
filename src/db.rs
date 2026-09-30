//! The database: schema, migrations, and the statements the endpoints need.

use std::path::Path;
use std::time::Duration;

use rusqlite::{
    Connection, OptionalExtension, Transaction, TransactionBehavior, named_params, params,
};

use crate::app::{FileId, Limits, OwnerTokenHash};
use crate::config::{Member, MemberId, WEEK};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

enum Migration {
    Sql(&'static str),
    /// A migration that has to look at stored data. Runs in its transaction.
    Fill(fn(&Transaction) -> Result<(), Error>),
}

/// The schema, as migrations. MIGRATIONS[i] takes user_version i to i+1, each in
/// its own transaction.
///
/// FROZEN ONCE SHIPPED, like protocol.md. Append new migrations; never edit an
/// old one, not even whitespace. SQLite stores the CREATE text, and a database
/// that ran the old text keeps it forever.
///
/// There is no 4.sql on purpose: migration 4 only fills data, so it's Rust
/// (`member_ids`, below).
const MIGRATIONS: [Migration; 5] = [
    // 1: the blobs table (steps 03 to 05 of the original server).
    Migration::Sql(include_str!("migrations/1.sql")),
    // 2: expiry (step 06). Guesses D9's defaults for older rows.
    Migration::Sql(include_str!("migrations/2.sql")),
    // 3: uploader_id and the uploads ledger (step 07).
    Migration::Sql(include_str!("migrations/3.sql")),
    // 4: member names become member ids (step 08). A fill, not SQL.
    Migration::Fill(member_ids),
    // 5: counters (step 10).
    Migration::Sql(include_str!("migrations/5.sql")),
];

/// What "this file exists" means, for every endpoint. Deleted, expired or used
/// up (in-flight downloads included) files get the same 404 as unknown IDs.
/// max_downloads 0 means no limit. Binds :now.
const SERVABLE: &str =
    "deleting = 0 AND expires_at > :now AND (max_downloads = 0 OR downloads < max_downloads)";

pub struct Db(Connection);

impl Db {
    /// Opens the database in WAL mode and migrates it. Refuses, untouched, a
    /// database newer than this binary.
    pub fn open(path: &Path) -> Result<Db, Error> {
        let conn = Connection::open(path)?;
        let mode: String =
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))?;
        if mode != "wal" {
            return Err(format!("{}: journal_mode is {mode}, not wal", path.display()).into());
        }
        conn.busy_timeout(Duration::from_secs(5))?;
        let mut db = Db(conn);
        db.migrate()?;
        Ok(db)
    }

    /// Runs `f` in an IMMEDIATE transaction, which takes the write lock up front.
    /// A deferred one that reads then writes can fail with SQLITE_BUSY in WAL mode,
    /// which once let 2 of 16 parallel uploads past a quota with room for one.
    pub fn write<T>(
        &mut self,
        f: impl FnOnce(&Transaction) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let tx = self
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let value = f(&tx)?;
        tx.commit()?;
        Ok(value)
    }

    /// Runs each pending migration with its version bump in one transaction, so a
    /// crash never leaves a half-migrated version.
    fn migrate(&mut self) -> Result<(), Error> {
        let version: i64 = self
            .0
            .pragma_query_value(None, "user_version", |r| r.get(0))?;
        let mut version = usize::try_from(version)
            .map_err(|_| format!("the database has schema version {version}"))?;
        if version == 0 {
            version = self.unversioned()?;
        }
        if version > MIGRATIONS.len() {
            return Err(format!(
                "the database has schema version {version}, newer than this binary understands ({}); \
                 run the newer server that wrote it",
                MIGRATIONS.len()
            )
            .into());
        }
        for (i, migration) in MIGRATIONS.iter().enumerate().skip(version) {
            self.write(|tx| {
                match migration {
                    Migration::Sql(sql) => tx.execute_batch(sql)?,
                    Migration::Fill(fill) => fill(tx)?,
                }
                tx.pragma_update(None, "user_version", i as i64 + 1)?;
                Ok(())
            })
            .map_err(|e| format!("migrating the database to schema version {}: {e}", i + 1))?;
        }
        Ok(())
    }

    /// Works out the schema of a database with user_version 0 from its columns
    /// (early versions never set it). An empty file has no blobs table.
    fn unversioned(&self) -> Result<usize, Error> {
        let columns: Vec<String> = self
            .0
            .prepare("SELECT name FROM pragma_table_info('blobs')")?
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        let has = |name: &str| columns.iter().any(|c| c == name);
        if columns.is_empty() {
            Ok(0)
        } else if has("deleting") {
            Ok(2) // step 06
        } else if has("created_at") && !has("expires_at") {
            Ok(1) // steps 03 to 05
        } else {
            Err("the database has an unversioned schema this binary does not recognise".into())
        }
    }

    /// Stores a file's row and ledger entry if the uploader's quota allows.
    /// Ok(Err) is a refusal with a message; nothing was written.
    ///
    /// This is the deciding quota check. The earlier two hold no lock, so parallel
    /// uploads all pass them; this one reads and writes in one IMMEDIATE
    /// transaction, so they queue here.
    pub fn insert(
        &mut self,
        id: &FileId,
        owner: &OwnerTokenHash,
        size: u64,
        now: i64,
        limits: Limits,
        uploader: &Member,
    ) -> Result<Result<(), String>, Error> {
        self.write(|tx| {
            if let Err(refusal) = uploader.quota.admit(&usage(tx, &uploader.id, now)?, size, now) {
                return Ok(Err(refusal));
            }
            tx.execute(
                "INSERT INTO blobs (id, owner_token_hash, size, created_at, expires_at, max_downloads, uploader_id)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![id.to_string(), &owner.as_bytes()[..], size as i64, now, limits.expires_at, limits.max_downloads, uploader.id.as_str()],
            )?;
            tx.execute(
                "INSERT INTO uploads (uploader_id, size, created_at) VALUES (?, ?, ?)",
                params![uploader.id.as_str(), size as i64, now],
            )?;
            Ok(Ok(()))
        })
    }

    /// What a member has stored, and has uploaded in the last 7 days.
    pub fn usage(&self, member: &MemberId, now: i64) -> rusqlite::Result<Usage> {
        usage(&self.0, member, now)
    }

    /// The size of a servable file.
    pub fn size(&self, id: &FileId, now: i64) -> rusqlite::Result<Option<u64>> {
        self.0
            .query_row(
                &format!("SELECT size FROM blobs WHERE id = :id AND {SERVABLE}"),
                named_params! { ":id": id.to_string(), ":now": now },
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map(|size| size.map(|s| s as u64))
    }

    /// Claims one download and returns the size, or None if not servable. Check
    /// and claim are one statement, so two racers can't both take the last
    /// download. `end_download` refunds the claim if the transfer fails.
    pub fn claim(&mut self, id: &FileId, now: i64) -> Result<Option<u64>, Error> {
        self.write(|tx| {
            let size = tx
                .query_row(
                    &format!(
                        "UPDATE blobs SET downloads = downloads + 1, in_flight = in_flight + 1
                         WHERE id = :id AND {SERVABLE} RETURNING size"
                    ),
                    named_params! { ":id": id.to_string(), ":now": now },
                    |r| r.get::<_, i64>(0),
                )
                .optional()?;
            Ok(size.map(|s| s as u64))
        })
    }

    /// Ends a claimed download: kept if `completed`, refunded if not. Returns true
    /// if the file is now used up with nothing in flight (and marks it for
    /// purging). Never marks while another transfer might still be refunded.
    pub fn end_download(&mut self, id: &FileId, completed: bool) -> Result<bool, Error> {
        self.write(|tx| {
            tx.execute(
                "UPDATE blobs SET in_flight = in_flight - 1, downloads = downloads - ?2
                 WHERE id = ?1 AND in_flight > 0",
                params![id.to_string(), i64::from(!completed)],
            )?;
            Ok(tx.execute(
                "UPDATE blobs SET deleting = 1
                 WHERE id = ? AND deleting = 0 AND in_flight = 0
                   AND max_downloads > 0 AND downloads >= max_downloads",
                [id.to_string()],
            )? == 1)
        })
    }

    /// The sweeper's first step: mark every expired or used-up file. Returns how
    /// many.
    pub fn mark_spent(&self, now: i64) -> rusqlite::Result<usize> {
        self.0.execute(
            "UPDATE blobs SET deleting = 1
             WHERE deleting = 0 AND (expires_at <= ?
               OR (max_downloads > 0 AND downloads >= max_downloads AND in_flight = 0))",
            [now],
        )
    }

    /// Every file marked for deletion, including earlier failed attempts, each
    /// with whether it has expired at `now`.
    pub fn marked(&self, now: i64) -> Result<Vec<(FileId, bool)>, Error> {
        let rows: Vec<(String, bool)> = self
            .0
            .prepare("SELECT id, expires_at <= ? FROM blobs WHERE deleting = 1")?
            .query_map([now], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        rows.into_iter()
            .map(|(id, expired)| {
                FileId::parse(&id)
                    .map(|id| (id, expired))
                    .ok_or_else(|| format!("stored id {id:?} is malformed").into())
            })
            .collect()
    }

    /// Deletes ledger entries older than the 7-day window. Returns how many.
    pub fn prune_ledger(&self, now: i64) -> rusqlite::Result<usize> {
        self.0
            .execute("DELETE FROM uploads WHERE created_at <= ?", [now - WEEK])
    }

    /// Every row of the counters table, as (name, value).
    pub fn counters(&self) -> rusqlite::Result<Vec<(String, i64)>> {
        self.0
            .prepare("SELECT name, value FROM counters")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect()
    }

    /// Writes `rows` into the counters table, whole values, in one transaction.
    pub fn save_counters(&mut self, rows: &[(&str, i64)]) -> Result<(), Error> {
        self.write(|tx| {
            let mut stmt = tx.prepare(
                "INSERT INTO counters (name, value) VALUES (?, ?)
                 ON CONFLICT (name) DO UPDATE SET value = excluded.value",
            )?;
            for (name, value) in rows {
                stmt.execute(params![name, value])?;
            }
            Ok(())
        })
    }

    /// At startup, refunds every claim left in flight by a stopped process.
    /// Returns how many files had one.
    pub fn refund_in_flight(&self) -> rusqlite::Result<usize> {
        self.0.execute(
            "UPDATE blobs SET downloads = downloads - in_flight, in_flight = 0 WHERE in_flight > 0",
            [],
        )
    }

    /// The owner token hash of a servable file.
    pub fn owner(&self, id: &FileId, now: i64) -> Result<Option<OwnerTokenHash>, Error> {
        let stored: Option<Vec<u8>> = self
            .0
            .query_row(
                &format!("SELECT owner_token_hash FROM blobs WHERE id = :id AND {SERVABLE}"),
                named_params! { ":id": id.to_string(), ":now": now },
                |r| r.get(0),
            )
            .optional()?;
        stored
            .map(|b| {
                OwnerTokenHash::from_stored(&b).ok_or_else(|| {
                    format!("file {id}: stored owner token hash is {} bytes", b.len()).into()
                })
            })
            .transpose()
    }

    /// Marks a file never to be served again. False if it wasn't servable (for
    /// example, a concurrent delete got there first).
    pub fn mark_deleting(&self, id: &FileId) -> rusqlite::Result<bool> {
        Ok(self.0.execute(
            "UPDATE blobs SET deleting = 1 WHERE id = ? AND deleting = 0",
            [id.to_string()],
        )? == 1)
    }

    /// Removes the row of a file already marked, once its blob is gone.
    pub fn remove(&self, id: &FileId) -> rusqlite::Result<()> {
        self.0
            .execute(
                "DELETE FROM blobs WHERE id = ? AND deleting = 1",
                [id.to_string()],
            )
            .map(drop)
    }

    /// Whether any row has this `id`, and who uploaded it (None for files from
    /// before uploads needed a token).
    pub fn uploader(&self, id: &FileId) -> rusqlite::Result<Option<Option<String>>> {
        self.0
            .query_row(
                "SELECT uploader_id FROM blobs WHERE id = ?",
                [id.to_string()],
                |r| r.get(0),
            )
            .optional()
    }

    /// Whether any row, in any state, refers to `id`.
    pub fn has_row(&self, id: &FileId) -> rusqlite::Result<bool> {
        self.0.query_row(
            "SELECT EXISTS (SELECT 1 FROM blobs WHERE id = ?)",
            [id.to_string()],
            |r| r.get(0),
        )
    }

    #[cfg(test)]
    pub fn conn(&self) -> &Connection {
        &self.0
    }
}

/// A member's usage, as the quota counts it. Blob sizes, as stored.
pub struct Usage {
    /// (size, expires_at) of a member's live files, soonest first. A used-up file
    /// with a download in flight still counts, since it may be refunded.
    pub files: Vec<(u64, i64)>,
    /// (size, created_at) of each upload in the last 7 days, from the ledger.
    /// Deleting a file doesn't touch it.
    pub week: Vec<(u64, i64)>,
}

fn usage(conn: &Connection, member: &MemberId, now: i64) -> rusqlite::Result<Usage> {
    let pairs = |sql: &str, since: i64| -> rusqlite::Result<Vec<(u64, i64)>> {
        conn.prepare(sql)?
            .query_map(
                named_params! { ":member": member.as_str(), ":since": since },
                |r| Ok((r.get::<_, i64>(0)? as u64, r.get(1)?)),
            )?
            .collect()
    };
    Ok(Usage {
        files: pairs(
            "SELECT size, expires_at FROM blobs
             WHERE uploader_id = :member AND deleting = 0 AND expires_at > :since
             ORDER BY expires_at",
            now,
        )?,
        week: pairs(
            "SELECT size, created_at FROM uploads
             WHERE uploader_id = :member AND created_at > :since
             ORDER BY created_at",
            now - WEEK,
        )?,
    })
}

/// Migration 4: turn stored member names into member ids. It runs with no
/// member list, so a database holding any names is refused untouched.
fn member_ids(tx: &Transaction) -> Result<(), Error> {
    let names: Vec<String> = tx
        .prepare("SELECT uploader_id FROM blobs WHERE uploader_id IS NOT NULL UNION SELECT uploader_id FROM uploads")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    if names.is_empty() {
        return Ok(());
    }
    Err(format!(
        "files are recorded under member names that no member in the config has: {}. \
         This upgrade turns each stored name into the id of the config member with that name, \
         and this version reads no members, so it cannot; upgrading it needs a version with authentication",
        names.join(", ")
    )
    .into())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;

    use hyper::StatusCode;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::app::{App, FileId, Limits};
    use crate::http::tests::*;

    /// A data directory as an earlier step of the original server left it.
    fn old_data_dir(stmts: &[&str], blobs: &[(&str, &[u8])]) -> TempDir {
        let dir = TempDir::new();
        fs::create_dir_all(dir.0.join("blobs")).unwrap();
        let db = rusqlite::Connection::open(dir.0.join("sunbird.db")).unwrap();
        for stmt in stmts {
            db.execute_batch(stmt).unwrap();
        }
        for (id, blob) in blobs {
            fs::write(
                dir.0.join("blobs").join(FileId::parse(id).unwrap().hex()),
                blob,
            )
            .unwrap();
        }
        dir
    }

    const STEP05_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS blobs (
    	id               TEXT PRIMARY KEY,
    	owner_token_hash BLOB NOT NULL,    -- SHA-256 of the owner token, never the token
    	size             INTEGER NOT NULL,
    	created_at       INTEGER NOT NULL  -- Unix seconds
    ) STRICT;";

    const STEP06_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS blobs (
    	id               TEXT PRIMARY KEY,
    	owner_token_hash BLOB NOT NULL,    -- SHA-256 of the owner token, never the token
    	size             INTEGER NOT NULL,
    	created_at       INTEGER NOT NULL, -- Unix seconds
    	expires_at       INTEGER NOT NULL, -- Unix seconds; expired once the clock reaches it
    	max_downloads    INTEGER NOT NULL, -- 0 means no download limit, not zero downloads
    	downloads        INTEGER NOT NULL DEFAULT 0, -- claims not refunded, in flight included
    	in_flight        INTEGER NOT NULL DEFAULT 0, -- claims whose transfer has not ended
    	deleting         INTEGER NOT NULL DEFAULT 0  -- 1: never served again; blob, then row, go
    ) STRICT;
    CREATE INDEX IF NOT EXISTS blobs_expires_at ON blobs (expires_at);";

    /// Step 07's schema, version 3: the first three migrations.
    fn step07(stmts: &[&str]) -> TempDir {
        let mut all = vec![
            include_str!("migrations/1.sql"),
            include_str!("migrations/2.sql"),
            include_str!("migrations/3.sql"),
        ];
        all.push("PRAGMA user_version = 3");
        all.extend(stmts);
        old_data_dir(&all, &[])
    }

    /// A step 05 file's limits are sealed where the server can't read them, so
    /// guess cautiously: 24 hours and one download.
    #[tokio::test]
    async fn migrate_step05_database() {
        let now = now();
        let owner_token = "step-05-owner-token";
        let owner_hex: String = Sha256::digest(owner_token)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let (recent, second) = (FileId::random().to_string(), FileId::random().to_string());
        let blob = random_blob(1000);
        let insert = |id: &str, at: i64| {
            format!(
                "INSERT INTO blobs (id, owner_token_hash, size, created_at) VALUES ('{id}', x'{owner_hex}', 1000, {at})"
            )
        };
        let created = [(recent.clone(), now - 3600), (second.clone(), now - 60)];
        let (a, b) = (insert(&recent, now - 3600), insert(&second, now - 60));
        let dir = old_data_dir(
            &[STEP05_SCHEMA, &a, &b],
            &[(&recent, &blob), (&second, &blob)],
        );

        let s = Server {
            app: Arc::new(open(&dir.0).expect("a step 05 data directory did not open")),
            dir,
        };
        assert_eq!(user_version(s.app.db().conn()), 5);
        for (id, at) in &created {
            let row: (i64, i64, i64, i64, Option<String>) = s
                .app
                .db()
                .conn()
                .query_row("SELECT expires_at, max_downloads, downloads, deleting, uploader_id FROM blobs WHERE id = ?", [id], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })
                .unwrap();
            assert_eq!(
                row,
                (at + 86400, 1, 0, 0, None),
                "migrated row; want created_at + 24 hours, 1, 0, 0, NULL"
            );
        }
        let r = get(&s, &format!("/api/download/{recent}")).await;
        assert!(
            r.status == StatusCode::OK && r.body == blob,
            "download of a migrated file: {}",
            r.status
        );
        wait_until("the used-up file is deleted", || {
            counts(&s, &recent).is_none()
        })
        .await;
        assert_eq!(
            get(&s, &format!("/api/download/{recent}")).await.status,
            StatusCode::NOT_FOUND,
            "second download of a migrated file"
        );
        let r = send(
            &s,
            "DELETE",
            &format!("/api/{second}"),
            Source::bytes(b""),
            owner_token,
        )
        .await;
        assert_eq!(
            r.status,
            StatusCode::NO_CONTENT,
            "owner delete of a migrated file"
        );

        // Opening again migrates nothing and loses nothing.
        let Server { app, dir } = s;
        drop(app);
        let app = open(&dir.0).unwrap();
        let db = app.db();
        let rows: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM blobs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            (user_version(db.conn()), rows),
            (5, 0),
            "second open: version, rows"
        );
    }

    /// A step 06 database also says user_version 0; its columns place it.
    #[tokio::test]
    async fn migrate_step06_database() {
        let now = now();
        let id = FileId::random().to_string();
        let blob = random_blob(500);
        let row = format!(
            "INSERT INTO blobs (id, owner_token_hash, size, created_at, expires_at, max_downloads, downloads)
             VALUES ('{id}', x'00', 500, {}, {}, 5, 2)",
            now - 60,
            now + 3600
        );
        let dir = old_data_dir(&[STEP06_SCHEMA, &row], &[(&id, &blob)]);
        let s = Server {
            app: Arc::new(open(&dir.0).expect("a step 06 data directory did not open")),
            dir,
        };
        assert_eq!(user_version(s.app.db().conn()), 5);
        let kept: (i64, i64, i64) = s
            .app
            .db()
            .conn()
            .query_row(
                "SELECT expires_at, max_downloads, downloads FROM blobs WHERE id = ?",
                [&id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(kept, (now + 3600, 5, 2), "step 06 row changed");
        let r = get(&s, &format!("/api/download/{id}")).await;
        assert!(
            r.status == StatusCode::OK && r.body == blob,
            "download of a step 06 file: {}",
            r.status
        );
    }

    /// Step 07 stored member names, and with no members known, the upgrade stops
    /// and leaves the database untouched.
    #[test]
    fn migrate_step07_names_refused() {
        let now = now();
        let id = FileId::random().to_string();
        let file = format!(
            "INSERT INTO blobs (id, owner_token_hash, size, created_at, expires_at, max_downloads, uploader_id)
             VALUES ('{id}', x'00', 1, {now}, {}, 0, 'carol')",
            now + 3600
        );
        let ledger = format!(
            "INSERT INTO uploads (uploader_id, size, created_at) VALUES ('alice', 1, {now})"
        );
        let dir = step07(&[&file, &ledger]);
        let err = open(&dir.0)
            .err()
            .expect("a database holding member names opened")
            .to_string();
        assert!(
            err.contains("carol") && err.contains("alice"),
            "error {err:?} does not name both"
        );

        let db = rusqlite::Connection::open(dir.0.join("sunbird.db")).unwrap();
        let carol: String = db
            .query_row("SELECT uploader_id FROM blobs WHERE id = ?", [&id], |r| {
                r.get(0)
            })
            .unwrap();
        let alice: String = db
            .query_row("SELECT uploader_id FROM uploads", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            (user_version(&db), carol.as_str(), alice.as_str()),
            (3, "carol", "alice"),
            "the refused database was changed"
        );
    }

    /// With no names stored, only anonymous files, step 07's database upgrades.
    #[test]
    fn migrate_step07_without_names() {
        let now = now();
        let id = FileId::random().to_string();
        let file = format!(
            "INSERT INTO blobs (id, owner_token_hash, size, created_at, expires_at, max_downloads, uploader_id)
             VALUES ('{id}', x'00', 1, {now}, {}, 0, NULL)",
            now + 3600
        );
        let dir = step07(&[&file]);
        let app = open(&dir.0).expect("a step 07 database with no member names did not open");
        assert_eq!(user_version(app.db().conn()), 5);
    }

    #[tokio::test]
    async fn newer_database_refused() {
        let s = server();
        let u = upload(&s, &random_blob(100)).await;
        s.app
            .db()
            .conn()
            .execute_batch("PRAGMA user_version = 6")
            .unwrap();
        let Server { app, dir } = s;
        drop(app);

        let err = open(&dir.0)
            .err()
            .expect("a database from a newer binary opened")
            .to_string();
        assert!(
            err.contains("newer than this binary understands"),
            "error {err:?}"
        );
        let db = rusqlite::Connection::open(dir.0.join("sunbird.db")).unwrap();
        let n: i64 = db
            .query_row("SELECT COUNT(*) FROM blobs WHERE id = ?", [&u.id], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(
            (n, user_version(&db)),
            (1, 6),
            "the refused database was changed"
        );
    }

    /// IMMEDIATE transactions make read-then-write racers queue instead of fail:
    /// 16 connections each insert only if the table is empty, and exactly one row
    /// lands with no errors.
    #[test]
    fn write_transactions_queue() {
        let dir = TempDir::new();
        let path = dir.0.join("sunbird.db");
        drop(Db::open(&path).unwrap());
        let barrier = Arc::new(std::sync::Barrier::new(16));
        let racers: Vec<_> = (0..16)
            .map(|_| {
                let (path, barrier) = (path.clone(), barrier.clone());
                std::thread::spawn(move || {
                    let mut db = Db::open(&path).unwrap();
                    barrier.wait();
                    db.write(|tx| {
                        let n: i64 =
                            tx.query_row("SELECT COUNT(*) FROM counters", [], |r| r.get(0))?;
                        std::thread::sleep(std::time::Duration::from_millis(20));
                        if n == 0 {
                            tx.execute(
                                "INSERT INTO counters (name, value) VALUES ('race', 1)",
                                [],
                            )?;
                        }
                        Ok(())
                    })
                    .map_err(|e| e.to_string())
                })
            })
            .collect();
        let results: Vec<_> = racers.into_iter().map(|r| r.join().unwrap()).collect();
        let failed: Vec<_> = results.iter().filter_map(|r| r.as_ref().err()).collect();
        assert!(
            failed.is_empty(),
            "{} of 16 racers failed: {:?}",
            failed.len(),
            failed.first()
        );
        let rows: i64 = Db::open(&path)
            .unwrap()
            .conn()
            .query_row("SELECT COUNT(*) FROM counters", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 1);
    }

    /// Sixteen connections race for a one-download file, round after round:
    /// exactly one wins and none fails. Separate connections, so the mutex can't
    /// hide a broken check-then-claim.
    #[test]
    fn claim_race_across_connections() {
        const ROUNDS: usize = 200;
        const RACERS: usize = 16;
        let dir = TempDir::new();
        let path = dir.0.join("sunbird.db");
        let now = now();
        let mut db = Db::open(&path).unwrap();
        let ids: Arc<Vec<FileId>> = Arc::new((0..ROUNDS).map(|_| FileId::random()).collect());
        let limits = Limits {
            expires_at: now + 3600,
            max_downloads: 1,
        };
        let uploader = &test_config().members[0];
        for id in ids.iter() {
            db.insert(
                id,
                &crate::app::OwnerToken::random().hash(),
                1,
                now,
                limits,
                uploader,
            )
            .unwrap()
            .unwrap();
        }
        let barrier = Arc::new(std::sync::Barrier::new(RACERS));
        let racers: Vec<_> = (0..RACERS)
            .map(|_| {
                let (path, barrier, ids) = (path.clone(), barrier.clone(), ids.clone());
                std::thread::spawn(move || {
                    let mut db = Db::open(&path).unwrap();
                    // SQLite's busy handler backs off to 100 ms; retrying every 50 µs keeps
                    // this to seconds.
                    db.conn()
                        .busy_handler(Some(|tries| {
                            std::thread::sleep(std::time::Duration::from_micros(50));
                            tries < 1_000_000
                        }))
                        .unwrap();
                    ids.iter()
                        .map(|id| {
                            barrier.wait();
                            db.claim(id, now).map_err(|e| e.to_string())
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let results: Vec<_> = racers.into_iter().map(|r| r.join().unwrap()).collect();
        for round in 0..ROUNDS {
            let claims: Vec<_> = results.iter().map(|r| &r[round]).collect();
            let failed: Vec<_> = claims.iter().filter_map(|c| c.as_ref().err()).collect();
            assert!(failed.is_empty(), "round {round}: {:?}", failed[0]);
            let won = claims.iter().filter(|c| matches!(c, Ok(Some(_)))).count();
            assert_eq!(won, 1, "round {round}: claims won of a 1-download file");
        }
        let (downloads, in_flight): (i64, i64) = db
            .conn()
            .query_row(
                "SELECT SUM(downloads), SUM(in_flight) FROM blobs",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((downloads, in_flight), (ROUNDS as i64, ROUNDS as i64));
    }

    /// Sixteen connections race to store a file where the quota has room for
    /// one: exactly one lands each round.
    #[test]
    fn quota_race_across_connections() {
        const ROUNDS: usize = 50;
        const RACERS: usize = 16;
        let dir = TempDir::new();
        let path = dir.0.join("sunbird.db");
        drop(Db::open(&path).unwrap());
        let now = now();
        let limits = Limits {
            expires_at: now + 3600,
            max_downloads: 0,
        };
        let members: Arc<Vec<_>> = Arc::new(
            (0..ROUNDS)
                .map(|_| {
                    let id = crate::config::MemberId::mint().to_string();
                    config(vec![member(&id, "m", &id, [1000, LOTS, LOTS])], |_| {})
                        .members
                        .remove(0)
                })
                .collect(),
        );
        let barrier = Arc::new(std::sync::Barrier::new(RACERS));
        let racers: Vec<_> = (0..RACERS)
            .map(|_| {
                let (path, barrier, members) = (path.clone(), barrier.clone(), members.clone());
                std::thread::spawn(move || {
                    let mut db = Db::open(&path).unwrap();
                    db.conn()
                        .busy_handler(Some(|tries| {
                            std::thread::sleep(std::time::Duration::from_micros(50));
                            tries < 1_000_000
                        }))
                        .unwrap();
                    let owner = crate::app::OwnerToken::random().hash();
                    members
                        .iter()
                        .map(|m| {
                            barrier.wait();
                            db.insert(&FileId::random(), &owner, 600, now, limits, m)
                                .map(|stored| stored.is_ok())
                                .map_err(|e| e.to_string())
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let results: Vec<_> = racers.into_iter().map(|r| r.join().unwrap()).collect();
        for round in 0..ROUNDS {
            let tries: Vec<_> = results.iter().map(|r| &r[round]).collect();
            let failed: Vec<_> = tries.iter().filter_map(|t| t.as_ref().err()).collect();
            assert!(
                failed.is_empty(),
                "round {round}: {} failed: {}",
                failed.len(),
                failed[0]
            );
            let landed = tries.iter().filter(|t| matches!(t, Ok(true))).count();
            assert_eq!(landed, 1, "round {round}: files stored with room for one");
        }
    }

    /// tests/fixtures/r2 comes from the R2 server, before uploads needed a
    /// token. It's already schema 5, so opening it migrates nothing. Its files
    /// have no uploader: served as before, deletable by owner token or admin, and
    /// counted against nobody.
    #[tokio::test]
    async fn r2_directory_opens_under_auth() {
        capture_logs();
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read("tests/fixtures/r2.json").unwrap()).unwrap();
        let made_at = manifest["made_at"].as_i64().unwrap();
        let file = |label: &str| {
            manifest["files"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["label"] == label)
                .unwrap()
                .clone()
        };
        let dir = TempDir::new();
        copy_dir(Path::new("tests/fixtures/r2"), &dir.0);
        let before = rusqlite::Connection::open(dir.0.join("sunbird.db")).unwrap();
        let (schema_before, version_before) = (schema(&before), user_version(&before));
        let dump = |db: &rusqlite::Connection| -> Vec<String> {
            db.prepare("SELECT * FROM blobs ORDER BY id")
                .unwrap()
                .query_map([], |r| {
                    Ok((0..r.as_ref().column_count())
                        .map(|i| format!("{:?}", r.get::<_, rusqlite::types::Value>(i).unwrap()))
                        .collect::<Vec<_>>()
                        .join(" "))
                })
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        let rows_before = dump(&before);
        drop(before);
        assert_eq!(version_before, 5);
        assert!(
            !rows_before.is_empty() && rows_before.iter().all(|r| r.ends_with("Null")),
            "{rows_before:?}"
        );

        let tiny = config(
            vec![member(MEMBER_ID, "m", MEMBER_TOKEN, [100, 1, 100])],
            |_| {},
        );
        let mut app = App::open(&dir.0, tiny).expect("the R2 directory did not open");
        app.now = || 1_790_624_430; // the manifest's made_at
        assert_eq!(
            (app.now)(),
            made_at,
            "the clock is not the manifest's made_at"
        );
        let s = Server {
            app: Arc::new(app),
            dir,
        };
        {
            let db = s.app.db();
            assert_eq!(user_version(db.conn()), 5);
            assert!(
                schema(db.conn()) == schema_before,
                "opening changed the schema"
            );
            assert!(dump(db.conn()) == rows_before, "opening changed a row");
        }
        for f in manifest["files"].as_array().unwrap() {
            let r = get(&s, &format!("/api/meta/{}", f["id"].as_str().unwrap())).await;
            let want = match f["state"].as_str().unwrap() {
                "gone" => StatusCode::NOT_FOUND,
                _ => StatusCode::OK,
            };
            assert_eq!(r.status, want, "{}", f["label"]);
        }

        // A member whose whole quota is 100 bytes and one file still has it all.
        let r = send(
            &s,
            "POST",
            &format!("/api/upload?expires_at={}&max_downloads=0", made_at + 3600),
            Source::bytes(&random_blob(100)),
            MEMBER_TOKEN,
        )
        .await;
        assert_eq!(
            r.status,
            StatusCode::CREATED,
            "{}",
            String::from_utf8_lossy(&r.body)
        );

        let two = file("two-downloads");
        let r = send(
            &s,
            "DELETE",
            &format!("/api/{}", two["id"].as_str().unwrap()),
            Source::bytes(b""),
            two["ownerToken"].as_str().unwrap(),
        )
        .await;
        assert_eq!(
            r.status,
            StatusCode::NO_CONTENT,
            "owner delete with an R2 owner token"
        );

        let present = file("present");
        let id = present["id"].as_str().unwrap();
        let r = get(&s, &format!("/api/download/{id}")).await;
        let digest: String = Sha256::digest(&r.body)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            digest,
            present["sha256"].as_str().unwrap(),
            "downloaded bytes"
        );
        let r = send(
            &s,
            "DELETE",
            &format!("/api/admin/{id}"),
            Source::bytes(b""),
            ADMIN_TOKEN,
        )
        .await;
        assert_eq!(r.status, StatusCode::NO_CONTENT);
        let said = logged(id);
        assert!(
            said.len() == 1
                && said[0].1.contains(ADMIN_ID)
                && said[0].1.contains(
                    "uploaded by nobody: it was uploaded before uploads were authenticated"
                ),
            "{said:?}"
        );
    }

    /// The schema-v5 fixture recorded uploaders by member id. With that id in the
    /// config, the files and ledger belong to that member.
    #[tokio::test]
    async fn schema_v5_uploader_is_a_member_id() {
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read("tests/fixtures/schema-v5.json").unwrap()).unwrap();
        let uploader = manifest["uploader_id"].as_str().unwrap();
        let path = format!(
            "/api/upload?expires_at={}&max_downloads=0",
            1_790_584_249 + 3600
        );
        for (quota, want) in [
            (
                [LOTS, 4, LOTS],
                "You have 4 files stored, and your limit is 4 at once.",
            ),
            (
                [LOTS, LOTS, 80_200],
                "You have uploaded 80200 of your 80200 bytes allowed per 7 days.",
            ),
            (
                [80_100, LOTS, LOTS],
                "Your files take 79100 of your 80100 bytes stored at once.",
            ),
        ] {
            let dir = TempDir::new();
            copy_dir(Path::new("tests/fixtures/schema-v5"), &dir.0);
            let c = config(vec![member(uploader, "m", MEMBER_TOKEN, quota)], |_| {});
            let mut app = App::open(&dir.0, c).unwrap();
            app.now = || 1_790_584_249;
            let s = Server {
                app: Arc::new(app),
                dir,
            };
            let r = send(
                &s,
                "POST",
                &path,
                Source::bytes(&random_blob(1001)),
                MEMBER_TOKEN,
            )
            .await;
            assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE, "{want}");
            let error = r.json()["error"].as_str().unwrap().to_owned();
            assert!(error.starts_with(want), "{error}");
        }
    }

    fn copy_dir(from: &Path, to: &Path) {
        fs::create_dir_all(to).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                copy_dir(&entry.path(), &to.join(entry.file_name()));
            } else {
                fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
            }
        }
    }

    fn schema(db: &rusqlite::Connection) -> Vec<(String, String, Option<String>)> {
        db.prepare("SELECT type, name, sql FROM sqlite_master ORDER BY name")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    /// tests/fixtures/schema-v5 is real data from before the rewrite (manifest
    /// beside it). Its files expire on 2026-10-05, so the clock is pinned.
    ///
    /// Opening it must change nothing: every row, ledger entry and counter stays,
    /// every file is served byte for byte. And running the migrations on an empty
    /// database must produce exactly its schema, so no shipped migration was edited.
    #[tokio::test]
    async fn schema_v5_directory_survives_open() {
        let fixture = Path::new("tests/fixtures/schema-v5");
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read("tests/fixtures/schema-v5.json").unwrap()).unwrap();
        let dir = TempDir::new();
        copy_dir(fixture, &dir.0);
        let before = rusqlite::Connection::open(dir.0.join("sunbird.db")).unwrap();
        let (schema_before, version_before) = (schema(&before), user_version(&before));
        let table = |db: &rusqlite::Connection, sql: &str| -> Vec<Vec<String>> {
            let mut stmt = db.prepare(sql).unwrap();
            let columns = stmt.column_count();
            stmt.query_map([], |r| {
                (0..columns)
                    .map(|i| {
                        r.get::<_, rusqlite::types::Value>(i)
                            .map(|v| format!("{v:?}"))
                    })
                    .collect()
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
        };
        let other_tables = |db: &rusqlite::Connection| {
            (
                table(db, "SELECT * FROM uploads ORDER BY rowid"),
                table(db, "SELECT * FROM counters ORDER BY name"),
            )
        };
        let (blobs_before, others_before) = (
            table(&before, "SELECT * FROM blobs ORDER BY id"),
            other_tables(&before),
        );
        drop(before);

        let mut app = open(&dir.0).expect("the schema v5 directory did not open");
        app.now = || 1_790_584_249; // the manifest's made_at
        let s = Server {
            app: Arc::new(app),
            dir,
        };
        {
            let db = s.app.db();
            assert_eq!(
                (user_version(db.conn()), version_before),
                (5, 5),
                "user_version"
            );
            assert!(
                schema(db.conn()) == schema_before,
                "opening changed the schema"
            );
            assert!(
                table(db.conn(), "SELECT * FROM blobs ORDER BY id") == blobs_before,
                "opening changed a row"
            );
            assert!(
                other_tables(db.conn()) == others_before,
                "opening changed the ledger or the counters"
            );
        }
        // Its counters are this version's counters, by name, and count on.
        let v = s.app.counters.json();
        assert_eq!(
            (
                v["uploads"].as_u64(),
                v["bytes_uploaded"].as_u64(),
                v["downloads"].as_u64(),
                v["counting_since"].as_i64()
            ),
            (Some(6), Some(80_200), Some(2), Some(1_790_584_249)),
            "counters read from the fixture: {v}"
        );
        let fresh = TempDir::new();
        assert!(
            schema(open(&fresh.0).unwrap().db().conn()) == schema_before,
            "the migrations no longer produce schema v5"
        );

        let files = manifest["files"].as_array().unwrap();
        for f in files {
            let (label, id) = (f["label"].as_str().unwrap(), f["id"].as_str().unwrap());
            let download = get(&s, &format!("/api/download/{id}")).await;
            let meta = get(&s, &format!("/api/meta/{id}")).await;
            if f["state"] == "gone" {
                assert_eq!(
                    (download.status, meta.status),
                    (StatusCode::NOT_FOUND, StatusCode::NOT_FOUND),
                    "{label}"
                );
                continue;
            }
            assert_eq!(download.status, StatusCode::OK, "{label}");
            let digest: String = Sha256::digest(&download.body)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(
                digest,
                f["sha256"].as_str().unwrap(),
                "{label}: downloaded bytes"
            );
            assert!(
                meta.body == download.body[..download.body.len().min(8192)],
                "{label}: preview"
            );
        }
        let present = files.iter().find(|f| f["label"] == "records").unwrap();
        let path = format!("/api/{}", present["id"].as_str().unwrap());
        let r = send(
            &s,
            "DELETE",
            &path,
            Source::bytes(b""),
            present["ownerToken"].as_str().unwrap(),
        )
        .await;
        assert_eq!(
            r.status,
            StatusCode::NO_CONTENT,
            "delete with an owner token issued before the rewrite"
        );
        let u = upload(&s, &random_blob(10)).await;
        assert_eq!(
            get(&s, &format!("/api/download/{}", u.id)).await.status,
            StatusCode::OK,
            "upload into the existing directory"
        );
    }
}
