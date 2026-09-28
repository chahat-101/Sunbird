//! The database: the schema, its migrations, and the few statements the
//! endpoints need.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::app::{FileId, Limits, OwnerTokenHash};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

enum Migration {
    Sql(&'static str),
    /// A change that must look at what is stored. It runs in the migration's
    /// transaction.
    Fill(fn(&Transaction) -> Result<(), Error>),
}

/// The schema, as migrations. MIGRATIONS[i] takes a database from user_version
/// i to i+1, and they run in order, each in its own transaction.
///
/// FROZEN ONCE SHIPPED, the way protocol.md is. Append a new migration and never
/// edit an old one, not even to fix it, and not even its whitespace: SQLite keeps
/// the text of every CREATE in sqlite_master, and a database that ran the old
/// text keeps its result forever, with nothing to tell it apart from one that ran
/// the new.
///
/// There is no migrations/4.sql, and none is missing. Migration 4 is a data fill
/// with no schema change, so it is Rust (`member_ids`, below), not SQL. A
/// version 3 database goes through it to 5; `migrate_step07_without_names`
/// shows that.
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

/// The one definition of a file that exists, used by every endpoint. A file
/// that fails it gets the same 404 as an ID never issued. Expiry (session 02)
/// adds expired and used up.
const SERVABLE: &str = "deleting = 0";

pub struct Db(Connection);

impl Db {
    /// Opens the database at `path` in WAL mode and migrates it. A database
    /// newer than this binary is refused, untouched.
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

    /// Runs `f` in a transaction, which is the only way this type opens one.
    /// It is IMMEDIATE: it takes the write lock at BEGIN. A deferred
    /// transaction that reads and then writes must upgrade its lock, and in WAL
    /// mode an upgrade after another connection has committed fails at once with
    /// SQLITE_BUSY; busy_timeout does not help. In the original server's step 07
    /// that let 2 of 16 parallel uploads through when there was room for one.
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

    /// Brings the database up to MIGRATIONS.len(), one transaction per
    /// migration together with its version bump, so a crash leaves the database
    /// at a version it really is.
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

    /// Places a database whose user_version is 0. Steps 03 to 06 of the
    /// original server never set it, so their columns say which schema they have. A new, empty file
    /// has no blobs table.
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

    pub fn insert(
        &mut self,
        id: &FileId,
        owner: &OwnerTokenHash,
        size: u64,
        now: i64,
        limits: Limits,
    ) -> Result<(), Error> {
        self.write(|tx| {
            // uploader_id stays NULL: the record of a file uploaded before
            // uploads were authenticated. Authentication is session 03.
            tx.execute(
                "INSERT INTO blobs (id, owner_token_hash, size, created_at, expires_at, max_downloads)
                 VALUES (?, ?, ?, ?, ?, ?)",
                params![id.to_string(), &owner.as_bytes()[..], size as i64, now, limits.expires_at, limits.max_downloads],
            )?;
            Ok(())
        })
    }

    /// The size of a servable file.
    pub fn size(&self, id: &FileId) -> rusqlite::Result<Option<u64>> {
        self.0
            .query_row(
                &format!("SELECT size FROM blobs WHERE id = ? AND {SERVABLE}"),
                [id.to_string()],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map(|size| size.map(|s| s as u64))
    }

    /// The owner token hash of a servable file.
    pub fn owner(&self, id: &FileId) -> Result<Option<OwnerTokenHash>, Error> {
        let stored: Option<Vec<u8>> = self
            .0
            .query_row(
                &format!("SELECT owner_token_hash FROM blobs WHERE id = ? AND {SERVABLE}"),
                [id.to_string()],
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

    /// Marks a file never to be served again. False if it was not servable,
    /// for instance because a concurrent delete marked it first.
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

/// Migration 4: each member name stored as an uploader_id becomes the id of the
/// config member with that name. No members are read until session 03, so this
/// runs with an empty member list: a database with no stored names migrates,
/// and one with any is refused untouched, naming them — as it would be if the
/// config listed none of them. Session 03 supplies the members; no database this
/// version can migrate would come out differently then.
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
    use crate::app::{App, FileId};
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

    /// A step 05 file's limits are sealed where the server cannot read them, so
    /// the migration guesses, and the guess errs toward less access: D9's 24 hours
    /// and one download. (Serving the file once and then no more comes with expiry.)
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
            app: Arc::new(App::open(&dir.0).expect("a step 05 data directory did not open")),
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
        let app = App::open(&dir.0).unwrap();
        let db = app.db();
        let rows: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM blobs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            (user_version(db.conn()), rows),
            (5, 1),
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
            app: Arc::new(App::open(&dir.0).expect("a step 06 data directory did not open")),
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

    /// Step 07 recorded member names, and migration 4 maps each to the id of the
    /// config member with that name. No members are read until session 03, so every
    /// stored name is one no member has: the upgrade stops, database untouched.
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
        let err = App::open(&dir.0)
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
        let app = App::open(&dir.0).expect("a step 07 database with no member names did not open");
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

        let err = App::open(&dir.0)
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

    /// Db::write takes the write lock when the transaction begins, so racers that
    /// read and then write queue rather than fail. Sixteen connections each insert
    /// only if the table is empty: exactly one row, and no racer gets an error. A
    /// deferred transaction fails most of them with SQLITE_BUSY. So far the only
    /// read-then-write transaction is migration 4; the quota check will depend on this.
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

    /// tests/fixtures/schema-v5 is a data directory at schema version 5 that
    /// was produced before this rewrite, through a server's HTTP API: files
    /// uploaded, one downloaded, two gone (manifest beside it). It is live data
    /// in miniature, as a migration later will meet it.
    ///
    /// Version 5 is the current version, so opening it runs no migration. What
    /// this proves: opening a directory that already holds rows and blobs
    /// changes neither — every row, ledger entry and counter is as it was, every
    /// file is served byte for byte, and the gone ones stay gone; and the
    /// migrations, run on an empty database, still produce exactly this schema,
    /// text and all, so no shipped migration has been edited. That migrations
    /// apply in order to a directory with rows and blobs is the migrate_step*
    /// tests' job, from versions 0 to 3.
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

        let s = Server {
            app: Arc::new(App::open(&dir.0).expect("the schema v5 directory did not open")),
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
        let fresh = TempDir::new();
        assert!(
            schema(App::open(&fresh.0).unwrap().db().conn()) == schema_before,
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
