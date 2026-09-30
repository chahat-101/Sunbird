//! The data directory (sunbird.db, blobs/, tmp/) and the request values, each
//! checked once at the edge into a type that can't hold anything else.

use std::fs::{self, DirBuilder};
use std::io::ErrorKind;
use std::net::IpAddr;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::{Admin, Config, Member, MemberId};
use crate::counters::{Counter, Counters};
use crate::db::{Db, Error, Usage};
use crate::limit::Limiter;

/// max_blob (§6.4): 8,192 + 1601 × 65,536. The one format limit the server knows.
pub const MAX_BLOB: u64 = 104_931_328;
/// The preview from §3: the first min(8192, size) bytes, unparsed.
pub const PREVIEW_LEN: u64 = 8192;
/// The 7-day maximum. Anything later is refused, not clamped (§10).
const MAX_LIFETIME: u64 = 7 * 24 * 3600;

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0; N];
    getrandom::fill(&mut b).expect("the operating system's random source failed");
    b
}

/// A file ID (§2): 96 random bits as 16 base64url characters. One spelling
/// each, and never path syntax.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileId([u8; 12]);

impl FileId {
    pub fn random() -> Self {
        FileId(random())
    }

    /// Accepts exactly what `random` produces. 16 characters are exactly 96 bits,
    /// so there's no second spelling.
    pub fn parse(s: &str) -> Option<Self> {
        if s.len() != 16 {
            return None;
        }
        URL_SAFE_NO_PAD.decode(s).ok()?.try_into().ok().map(FileId)
    }

    /// The blob's file name: the ID in hex, so IDs that differ only in case can't
    /// collide on a case-insensitive filesystem.
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The inverse of `hex`, for a name found in blobs/. Lowercase only.
    pub fn from_hex(s: &str) -> Option<Self> {
        let digits = s.as_bytes();
        if digits.len() != 24
            || !digits
                .iter()
                .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
        {
            return None;
        }
        let mut b = [0; 12];
        for (i, pair) in digits.chunks(2).enumerate() {
            b[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
        }
        Some(FileId(b))
    }
}

impl std::fmt::Display for FileId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

/// The owner token, shown once at upload. The server keeps only its hash.
pub struct OwnerToken(String);

impl OwnerToken {
    pub fn random() -> Self {
        OwnerToken(URL_SAFE_NO_PAD.encode(random::<32>()))
    }

    pub fn hash(&self) -> OwnerTokenHash {
        OwnerTokenHash::of(&self.0)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// SHA-256 of an owner token. A fast hash is fine: the token is 256 random
/// bits, so there's nothing to guess.
#[derive(Clone, Copy)]
pub struct OwnerTokenHash([u8; 32]);

impl OwnerTokenHash {
    fn of(token: &str) -> Self {
        OwnerTokenHash(Sha256::digest(token.as_bytes()).into())
    }

    pub fn from_stored(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(OwnerTokenHash)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constant-time comparison, so nothing leaks about the stored hash.
    pub fn matches(&self, token: &str) -> bool {
        Self::of(token).0.ct_eq(&self.0).into()
    }
}

/// The limits sent beside the blob (§10). The server can't check them against
/// the sealed header, so out-of-range values are refused, never adjusted.
/// Whichever limit is reached first removes the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub expires_at: i64,
    pub max_downloads: i64,
}

impl Limits {
    pub fn parse(query: Option<&str>, now: i64) -> Result<Limits, &'static str> {
        let once = |key| {
            let mut values = query.unwrap_or("").split('&').filter_map(|pair| {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                (k == key).then_some(v)
            });
            values.next().filter(|_| values.next().is_none())
        };
        let expires_at = once("expires_at")
            .and_then(decimal::<u64>)
            .ok_or("expires_at must be given once, as Unix seconds in decimal")?;
        let max_downloads = once("max_downloads")
            .and_then(decimal::<u32>)
            .ok_or("max_downloads must be given once, as a decimal integer from 0 to 4294967295")?;
        // Refuse a file that would already be expired.
        let now = u64::try_from(now).expect("the clock is before 1970");
        if expires_at <= now {
            return Err(
                "expires_at is not after the server's clock. Your device's clock may be wrong.",
            );
        }
        if expires_at > now + MAX_LIFETIME {
            return Err(
                "expires_at is more than 7 days after the server's clock. Your device's clock may be wrong.",
            );
        }
        Ok(Limits {
            expires_at: expires_at as i64,
            max_downloads: max_downloads.into(),
        })
    }
}

/// Canonical decimal only (no sign, leading zeros or escapes), so each number
/// has one spelling.
fn decimal<T: std::str::FromStr>(s: &str) -> Option<T> {
    let canonical =
        !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    if canonical { s.parse().ok() } else { None }
}

// ---- the data directory -----------------------------------------------------

pub struct App {
    dir: PathBuf,
    db: Mutex<Db>,
    /// The clock limits are judged by, in Unix seconds. Tests replace it.
    pub now: fn() -> i64,
    pub config: Config,
    /// Uploads, per member id.
    pub upload_limit: Limiter<MemberId>,
    /// Previews and downloads, per client address (an IPv6 /64).
    pub read_limit: Limiter<IpAddr>,
    pub counters: Counters,
    /// Free bytes for a non-root process on `dir`'s filesystem. Tests replace it.
    pub free_space: fn(&Path) -> std::io::Result<u64>,
}

fn system_clock() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is before 1970")
        .as_secs() as i64
}

/// statvfs's f_bavail: excludes root's reserve, since we don't run as root.
fn statvfs_free(path: &Path) -> std::io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `path` is NUL-terminated and outlives the call; `st` is only read
    // after statvfs returns 0.
    let st = unsafe {
        if libc::statvfs(path.as_ptr(), st.as_mut_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        st.assume_init()
    };
    // Already u64 on 64-bit Linux; the conversions are for 32-bit targets.
    #[allow(clippy::useless_conversion)]
    Ok(u64::from(st.f_bavail).saturating_mul(u64::from(st.f_frsize)))
}

impl App {
    /// Creates the layout, opens and migrates the database, and cleans up after a
    /// previous process: partial uploads, claims in flight, blobs with no row.
    /// It doesn't sweep; tests set `now` first.
    pub fn open(dir: &Path, config: Config) -> Result<App, Error> {
        for sub in ["blobs", "tmp"] {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir.join(sub))?;
        }
        // Nothing refers to a file in tmp/ once its request is gone.
        for entry in fs::read_dir(dir.join("tmp"))? {
            fs::remove_file(entry?.path())?;
        }
        let db = Db::open(&dir.join("sunbird.db"))?;
        let refunded = db.refund_in_flight()?;
        if refunded > 0 {
            log::warn!(
                "refunded downloads left in flight by the previous process, on {refunded} files"
            );
        }
        // Loaded, not written, so just opening a directory changes nothing.
        let counters = Counters::load(&db.counters()?, system_clock());
        let app = App {
            dir: dir.to_owned(),
            db: Mutex::new(db),
            now: system_clock,
            upload_limit: Limiter::new(config.upload_rate),
            read_limit: Limiter::new(config.read_rate),
            counters,
            free_space: statvfs_free,
            config,
        };
        app.remove_orphans()?;
        Ok(app)
    }

    pub fn db(&self) -> MutexGuard<'_, Db> {
        // rusqlite rolls back on drop, so a panic leaves the connection usable.
        self.db.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn blob_path(&self, id: &FileId) -> PathBuf {
        self.dir.join("blobs").join(id.hex())
    }

    pub fn temp_path(&self) -> PathBuf {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).expect("the operating system's random source failed");
        self.dir
            .join("tmp")
            .join(format!("upload-{:016x}", u64::from_ne_bytes(b)))
    }

    /// What a member has stored, and has uploaded in the last 7 days.
    pub fn usage(&self, member: &MemberId) -> Result<Usage, Error> {
        Ok(self.db().usage(member, (self.now)())?)
    }

    /// Whether `more` bytes fit above min_free_bytes. Checked before the body and
    /// again while it streams.
    pub fn disk_has_room(&self, more: u64) -> std::io::Result<bool> {
        let free = (self.free_space)(&self.dir.join("tmp"))?;
        Ok(free >= self.config.min_free_bytes.saturating_add(more))
    }

    /// Writes the counters to the database.
    pub fn save_counters(&self) -> Result<(), Error> {
        self.db().save_counters(&self.counters.rows())
    }

    /// Gives a finished upload its ID if the quota allows (Ok(Err) is a refusal).
    /// A hard link never overwrites an existing blob. File before row: a crash
    /// leaves an orphan file, which the next `open` removes.
    pub fn commit(
        &self,
        tmp: &Path,
        owner: &OwnerTokenHash,
        size: u64,
        limits: Limits,
        uploader: &Member,
    ) -> Result<Result<FileId, String>, Error> {
        self.commit_as(
            std::iter::repeat_with(FileId::random).take(3),
            tmp,
            owner,
            size,
            limits,
            uploader,
        )
    }

    /// `commit`, trying each of `ids` in turn while the name is taken.
    pub fn commit_as(
        &self,
        ids: impl IntoIterator<Item = FileId>,
        tmp: &Path,
        owner: &OwnerTokenHash,
        size: u64,
        limits: Limits,
        uploader: &Member,
    ) -> Result<Result<FileId, String>, Error> {
        let mut taken = None;
        for id in ids {
            match fs::hard_link(tmp, self.blob_path(&id)) {
                Err(e) if e.kind() == ErrorKind::AlreadyExists => taken = Some(e),
                Err(e) => return Err(e.into()),
                Ok(()) => {
                    let inserted =
                        self.db()
                            .insert(&id, owner, size, (self.now)(), limits, uploader);
                    if !matches!(inserted, Ok(Ok(()))) {
                        let _ = fs::remove_file(self.blob_path(&id));
                    }
                    return inserted.map(|stored| stored.map(|()| id));
                }
            }
        }
        Err(taken.map_or_else(|| "no ID to try".into(), Into::into))
    }

    /// Deletes a marked file: blob, then row. It stopped being served when marked.
    ///
    /// The deletion is verified by checking the blob is really gone. If not, it's
    /// logged as an error and left marked for the next sweep.
    ///
    /// A download already streaming finishes: on POSIX the open file keeps its
    /// bytes until closed.
    pub fn purge(&self, id: &FileId) -> Result<(), Error> {
        let path = self.blob_path(id);
        let unlinked = fs::remove_file(&path);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(self.db().remove(id)?),
            Ok(_) => {
                let why = match unlinked {
                    Err(e) => e.to_string(),
                    Ok(()) => "the unlink reported success".into(),
                };
                self.counters.add(Counter::DeletionFailures, 1);
                log::error!(
                    "DELETION FAILED: file {id} is no longer served, but its blob is still on disk at {}: {why}",
                    path.display()
                );
                Err(format!("file {id}: blob still on disk").into())
            }
            Err(e) => {
                self.counters.add(Counter::DeletionFailures, 1);
                log::error!(
                    "DELETION FAILED: file {id} is no longer served, but whether its blob at {} is gone cannot be checked: {e}",
                    path.display()
                );
                Err(e.into())
            }
        }
    }

    /// An admin deletion (revocation or takedown). Works on any file with a row,
    /// even one expired but not yet swept. Verified like the sweeper's, and logged
    /// with the admin, the file and the uploader.
    pub fn admin_delete(&self, admin: &Admin, id: &FileId) -> Result<bool, Error> {
        // Bound first, as in `end_download`: `purge` locks the database again.
        let uploader = {
            let db = self.db();
            let Some(uploader) = db.uploader(id)? else {
                return Ok(false);
            };
            db.mark_deleting(id)?;
            uploader
        };
        let uploader = match uploader {
            None => "nobody: it was uploaded before uploads were authenticated".to_owned(),
            Some(uid) => match self.config.member_by_id(&uid) {
                Some(m) => format!("member {uid} ({})", m.name),
                None => format!("member {uid} (no longer in the config)"),
            },
        };
        let by = format!("admin {} ({})", admin.id, admin.name);
        match self.purge(id) {
            Ok(()) => {
                log::warn!("ADMIN DELETE: {by} deleted file {id}, uploaded by {uploader}");
                Ok(true)
            }
            Err(e) => {
                log::error!(
                    "ADMIN DELETE FAILED: {by} could not delete file {id}, uploaded by {uploader}: {e}"
                );
                Err(e)
            }
        }
    }

    /// Ends a claimed download and purges the file if that used it up.
    pub fn end_download(&self, id: &FileId, completed: bool) {
        self.counters.add(
            match completed {
                true => Counter::Downloads,
                false => Counter::FailedDownloads,
            },
            1,
        );
        // Bind first: a guard in the match would still hold the lock in `purge`.
        let ended = self.db().end_download(id, completed);
        match ended {
            Ok(true) => {
                let _ = self.purge(id); // logged; the sweeper retries
            }
            Ok(false) => {}
            // Leave the claim in flight; the next start refunds it.
            Err(e) => log::error!("file {id}: could not record the end of a download: {e}"),
        }
    }

    /// Deletes every file past its limits and retries earlier failures, marking
    /// first so they stop being served. Also prunes the ledger. Returns (deleted,
    /// failed).
    pub fn sweep(&self) -> Result<(usize, usize), Error> {
        let now = (self.now)();
        let marked = {
            let db = self.db();
            db.mark_spent(now)?;
            db.prune_ledger(now)?;
            db.marked(now)?
        };
        let mut failed = 0;
        for (id, expired) in &marked {
            match self.purge(id) {
                Ok(()) if *expired => self.counters.add(Counter::ExpiredSwept, 1),
                Ok(()) => {}
                Err(_) => failed += 1,
            }
        }
        Ok((marked.len() - failed, failed))
    }

    /// Deletes blobs with no row, left by a crash between link and insert. Runs
    /// before any upload can be mid-commit.
    fn remove_orphans(&self) -> Result<(), Error> {
        for entry in fs::read_dir(self.dir.join("blobs"))? {
            let entry = entry?;
            let id = entry.file_name().to_str().and_then(FileId::from_hex);
            if let Some(id) = id
                && self.db().has_row(&id)?
            {
                continue;
            }
            match fs::remove_file(entry.path()) {
                Ok(()) => log::info!("removed {}, a blob with no row", entry.path().display()),
                Err(e) => {
                    self.counters.add(Counter::DeletionFailures, 1);
                    log::error!(
                        "DELETION FAILED: {}, a blob with no row: {e}",
                        entry.path().display()
                    )
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI64, Ordering};

    use hyper::StatusCode;

    use super::*;
    use crate::http::tests::*;

    #[test]
    fn open_clears_partial_uploads() {
        let dir = TempDir::new();
        drop(open(&dir.0).unwrap());
        fs::write(dir.0.join("tmp/upload-123"), "partial").unwrap();
        drop(open(&dir.0).unwrap());
        assert_eq!(
            fs::read_dir(dir.0.join("tmp")).unwrap().count(),
            0,
            "a partial upload from a previous process survived open"
        );
    }

    /// One spelling per ID: base64url only, 16 characters, no padding.
    #[test]
    fn one_spelling_per_id() {
        assert!(
            FileId::parse("AAAAAAAAAAAAAAA-").is_some()
                && FileId::parse("AAAAAAAAAAAAAAA_").is_some()
        );
        for other in [
            "AAAAAAAAAAAAAAA+",
            "AAAAAAAAAAAAAAA/",
            "AAAAAAAAAAAAAAA=",
            "AAAAAAAAAAAAAAAAAAAAAA==",
            "AAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAA-A",
        ] {
            assert_eq!(FileId::parse(other), None, "{other}");
        }
    }

    /// IDs that differ only in case are separate files, even on a
    /// case-insensitive filesystem.
    #[test]
    fn blob_names_are_hex() {
        let a = FileId::parse("AAAAAAAAAAAAAAAA").unwrap();
        let b = FileId::parse("aaaaaaaaaaaaaaaa").unwrap();
        assert_eq!(a.hex(), "000000000000000000000000");
        assert!(a.hex().to_lowercase() != b.hex().to_lowercase());
        assert_eq!(FileId::from_hex(&b.hex()), Some(b));
    }

    /// A taken ID is never overwritten: the next one is tried, and with none left
    /// the upload fails cleanly.
    #[tokio::test]
    async fn id_collision_never_overwrites() {
        let s = server();
        let first = random_blob(1000);
        let taken = FileId::parse(&upload(&s, &first).await.id).unwrap();
        let tmp = s.app.temp_path();
        fs::write(&tmp, random_blob(500)).unwrap();
        let (owner, limits) = (
            OwnerToken::random().hash(),
            Limits {
                expires_at: now() + 60,
                max_downloads: 0,
            },
        );

        let uploader = &s.app.config.members[0];
        let three = std::iter::repeat_n(taken.clone(), 3);
        assert!(
            s.app
                .commit_as(three, &tmp, &owner, 500, limits, uploader)
                .is_err(),
            "a taken ID was accepted"
        );
        let fresh = FileId::random();
        let got = s
            .app
            .commit_as(
                [taken.clone(), fresh.clone()],
                &tmp,
                &owner,
                500,
                limits,
                uploader,
            )
            .unwrap()
            .unwrap();
        assert_eq!(got, fresh, "the next ID was not tried");
        assert!(
            fs::read(s.app.blob_path(&taken)).unwrap() == first,
            "the taken ID's blob was overwritten"
        );
        assert_eq!(rows(&s), 2);
    }

    /// Crash points recreated on disk, then a restart: an orphan blob, an
    /// unfinished claim, and a half-deleted file the first sweep finishes.
    #[tokio::test]
    async fn restart_after_crash() {
        let s = server();
        let marked = upload(&s, &random_blob(1000)).await;
        s.app
            .db()
            .conn()
            .execute("UPDATE blobs SET deleting = 1 WHERE id = ?", [&marked.id])
            .unwrap();
        let blob = random_blob(1000);
        let claimed = upload_with(
            &s,
            &format!("/api/upload?expires_at={}&max_downloads=1", now() + 3600),
            &blob,
        )
        .await;
        assert!(
            s.app
                .db()
                .claim(&FileId::parse(&claimed.id).unwrap(), now())
                .unwrap()
                .is_some(),
            "claim"
        );
        let orphan = s.dir.0.join("blobs").join(FileId::random().hex());
        fs::write(&orphan, random_blob(1000)).unwrap();
        let stray = s.dir.0.join("blobs").join("not-an-id");
        fs::write(&stray, "x").unwrap();

        let Server { app, dir } = s;
        drop(app);
        let s = Server {
            app: Arc::new(open(&dir.0).unwrap()),
            dir,
        };
        assert!(!orphan.exists(), "a blob with no row survived open");
        assert!(
            !stray.exists(),
            "a file in blobs/ that no ID names survived open"
        );
        for (method, prefix) in [
            ("GET", "/api/meta/"),
            ("GET", "/api/download/"),
            ("DELETE", "/api/"),
        ] {
            let r = send(
                &s,
                method,
                &format!("{prefix}{}", marked.id),
                Source::bytes(b""),
                &marked.owner_token,
            )
            .await;
            assert_eq!(
                r.status,
                StatusCode::NOT_FOUND,
                "{method} of a file marked for deletion"
            );
        }
        assert!(
            blob_exists(&s, &marked.id),
            "a marked file's blob has a row and must survive open"
        );
        assert_eq!(
            counts(&s, &claimed.id),
            Some((0, 0, 0)),
            "a claim left in flight, after open"
        );
        let r = get(&s, &format!("/api/download/{}", claimed.id)).await;
        assert!(
            r.status == StatusCode::OK && r.body == blob,
            "the refunded download: {}",
            r.status
        );

        assert_eq!(s.app.sweep().unwrap().1, 0, "sweep failures");
        assert!(
            !blob_exists(&s, &marked.id) && counts(&s, &marked.id).is_none(),
            "the sweep did not finish the marked file"
        );
    }

    const T0: i64 = 1_800_000_000;

    /// The sweeper deletes expired files (checked gone) and leaves the rest.
    #[tokio::test]
    async fn sweep_deletes_expired() {
        static CLOCK: AtomicI64 = AtomicI64::new(T0);
        let s = server_with(|app| app.now = || CLOCK.load(Ordering::Relaxed));
        let path = |expires_at: i64, max_downloads: u32| {
            format!("/api/upload?expires_at={expires_at}&max_downloads={max_downloads}")
        };
        let expiring = upload_with(&s, &path(T0 + 60, 0), &random_blob(1000)).await;
        let limited = upload_with(&s, &path(T0 + 7200, 3), &random_blob(1000)).await;
        let unlimited = upload_with(&s, &path(T0 + 7200, 0), &random_blob(1000)).await;

        CLOCK.store(T0 + 59, Ordering::Relaxed);
        assert_eq!(s.app.sweep().unwrap(), (0, 0), "a second before expires_at");
        CLOCK.store(T0 + 60, Ordering::Relaxed);
        assert_eq!(
            s.app.sweep().unwrap(),
            (1, 0),
            "at expires_at: deleted, failed"
        );
        assert!(
            fs::symlink_metadata(s.app.blob_path(&FileId::parse(&expiring.id).unwrap()))
                .is_err_and(|e| e.kind() == ErrorKind::NotFound),
            "the expired blob is still on disk"
        );
        assert_eq!(counts(&s, &expiring.id), None, "the expired row");
        for u in [&limited, &unlimited] {
            assert_eq!(
                get(&s, &format!("/api/meta/{}", u.id)).await.status,
                StatusCode::OK,
                "a live file after the sweep"
            );
        }
        assert_eq!((rows(&s), entries(&s, "blobs")), (2, 2));
    }

    /// Restores permissions after the test so the directory can be removed.
    struct Writable(std::path::PathBuf);

    impl Drop for Writable {
        fn drop(&mut self) {
            fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    /// A failed deletion is logged every time and the file stays unserved until
    /// one succeeds. Forced with a blobs directory that refuses the unlink.
    #[tokio::test]
    async fn failed_deletion_is_logged_and_retried() {
        static CLOCK: AtomicI64 = AtomicI64::new(T0);
        capture_logs();
        let s = server_with(|app| app.now = || CLOCK.load(Ordering::Relaxed));
        let u = upload_with(
            &s,
            &format!("/api/upload?expires_at={}&max_downloads=0", T0 + 60),
            &random_blob(1000),
        )
        .await;
        CLOCK.store(T0 + 60, Ordering::Relaxed);

        let blobs = s.dir.0.join("blobs");
        fs::set_permissions(&blobs, fs::Permissions::from_mode(0o500)).unwrap();
        let writable = Writable(blobs);
        for attempt in 1..=2 {
            assert_eq!(
                s.app.sweep().unwrap(),
                (0, 1),
                "attempt {attempt}: deleted, failed"
            );
            let failures: Vec<_> = logged(&u.id)
                .into_iter()
                .filter(|(level, message)| {
                    *level == log::Level::Error && message.starts_with("DELETION FAILED")
                })
                .collect();
            assert_eq!(
                failures.len(),
                attempt,
                "attempt {attempt}: logged failures"
            );
            assert_eq!(
                counts(&s, &u.id),
                Some((0, 0, 1)),
                "attempt {attempt}: the row, still marked"
            );
            assert!(blob_exists(&s, &u.id));
        }
        CLOCK.store(T0, Ordering::Relaxed);
        assert_eq!(
            get(&s, &format!("/api/meta/{}", u.id)).await.status,
            StatusCode::NOT_FOUND,
            "a marked file, served again once its clock says live"
        );

        drop(writable);
        assert_eq!(
            s.app.sweep().unwrap(),
            (1, 0),
            "once the unlink can succeed"
        );
        assert!(!blob_exists(&s, &u.id) && counts(&s, &u.id).is_none());
    }
}
