//! The data directory — sunbird.db, blobs/<hex id>, and tmp/ for uploads in
//! progress — and the values a request carries, each checked once, at the edge,
//! into a type that cannot hold anything else.

use std::fs::{self, DirBuilder};
use std::io::ErrorKind;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::db::{Db, Error};

/// max_blob from protocol.md §6.4: 8,192 + 1601 × 65,536. The only format
/// limit the server knows, and a plain byte count.
pub const MAX_BLOB: u64 = 104_931_328;
/// The preview from §3: the first min(8192, size) bytes, unparsed.
pub const PREVIEW_LEN: u64 = 8192;
/// D9's 7 day maximum. An expires_at further ahead than this is refused, never
/// clamped (§10).
const MAX_LIFETIME: u64 = 7 * 24 * 3600;

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0; N];
    getrandom::fill(&mut b).expect("the operating system's random source failed");
    b
}

/// A file's ID (§2): 96 random bits, 16 base64url characters. Every one has
/// exactly one spelling, and none contains path syntax.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileId([u8; 12]);

impl FileId {
    pub fn random() -> Self {
        FileId(random())
    }

    /// Accepts exactly what `random` produces: 16 characters of the base64url
    /// alphabet, no padding. 16 characters are 96 bits with none spare, so
    /// there is no second spelling to reject.
    pub fn parse(s: &str) -> Option<Self> {
        if s.len() != 16 {
            return None;
        }
        URL_SAFE_NO_PAD.decode(s).ok()?.try_into().ok().map(FileId)
    }

    /// The name of the blob on disk: the ID's bytes in hex. base64url is
    /// case-sensitive, and two IDs differing only in case must not be one file
    /// on a case-insensitive filesystem.
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

/// The owner token handed back once at upload: 256 random bits. The server
/// keeps only its hash, so there is no way to get one back from a `FileId`.
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

/// SHA-256 of an owner token's text: what the database holds instead of the
/// token. SHA-256 rather than a slow hash because the token is 256 random
/// bits; there is nothing to guess. The only comparison is `matches`.
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

    /// Whether `token` hashes to this, in constant time. Hashing first means
    /// the comparison could not leak the token's bytes anyway; comparing in
    /// constant time means it leaks nothing about the stored hash either.
    pub fn matches(&self, token: &str) -> bool {
        Self::of(token).0.ct_eq(&self.0).into()
    }
}

/// The limits an upload carries beside its blob (§10). They must be the values
/// the client sealed into the header; the server cannot check that, and cannot
/// read the header (§3). Out-of-range values are refused, not adjusted: the
/// header cannot be rewritten, and an adjusted row would promise something the
/// verified header does not.
///
/// Validated and stored now, so every row carries the limits its uploader
/// sealed. Enforcing them on read comes with expiry (session 02).
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
        // The file is expired once the clock reaches expires_at. Accepting one
        // already there would store a file that 404s.
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

/// Canonical decimal only: digits, no sign, no leading zero, no percent
/// escapes, so each number has one spelling. Out of range is refused.
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
}

fn system_clock() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is before 1970")
        .as_secs() as i64
}

impl App {
    /// Creates the layout if needed, opens and migrates the database, and
    /// clears what a previous process left behind: partial uploads in tmp/,
    /// and blobs with no row.
    pub fn open(dir: &Path) -> Result<App, Error> {
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
        let app = App {
            dir: dir.to_owned(),
            db: Mutex::new(db),
            now: system_clock,
        };
        app.remove_orphans()?;
        Ok(app)
    }

    pub fn db(&self) -> MutexGuard<'_, Db> {
        // A panic mid-statement leaves no transaction open: rusqlite rolls back
        // on drop. The connection is still good.
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

    /// Gives a completed upload its ID. The hard link fails if the name is
    /// taken, so an ID collision never overwrites a blob; a rename would.
    /// The file comes before the row: a crash in between leaves a file nothing
    /// refers to, which the next `open` removes, never a row with no file.
    pub fn commit(
        &self,
        tmp: &Path,
        owner: &OwnerTokenHash,
        size: u64,
        limits: Limits,
    ) -> Result<FileId, Error> {
        self.commit_as(
            std::iter::repeat_with(FileId::random).take(3),
            tmp,
            owner,
            size,
            limits,
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
    ) -> Result<FileId, Error> {
        let mut taken = None;
        for id in ids {
            match fs::hard_link(tmp, self.blob_path(&id)) {
                Err(e) if e.kind() == ErrorKind::AlreadyExists => taken = Some(e),
                Err(e) => return Err(e.into()),
                Ok(()) => {
                    if let Err(e) = self.db().insert(&id, owner, size, (self.now)(), limits) {
                        let _ = fs::remove_file(self.blob_path(&id));
                        return Err(e);
                    }
                    return Ok(id);
                }
            }
        }
        Err(taken.map_or_else(|| "no ID to try".into(), Into::into))
    }

    /// Deletes a file already marked deleting: the blob, then the row. The mark
    /// came first, so the file stopped being served before any bytes went. If
    /// the unlink fails the row stays marked, never served again.
    pub fn purge(&self, id: &FileId) -> Result<(), Error> {
        match fs::remove_file(self.blob_path(id)) {
            Err(e) if e.kind() != ErrorKind::NotFound => {
                log::error!(
                    "DELETION FAILED: file {id} is no longer served, but its blob is still on disk: {e}"
                );
                Err(e.into())
            }
            _ => Ok(self.db().remove(id)?),
        }
    }

    /// Deletes blobs with no row: an upload linked its file and the process
    /// stopped before the insert. Nothing could ever serve such a file. Runs
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
                Err(e) => log::error!(
                    "DELETION FAILED: {}, a blob with no row: {e}",
                    entry.path().display()
                ),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;

    use hyper::StatusCode;

    use super::*;
    use crate::http::tests::*;

    #[test]
    fn open_clears_partial_uploads() {
        let dir = TempDir::new();
        drop(App::open(&dir.0).unwrap());
        fs::write(dir.0.join("tmp/upload-123"), "partial").unwrap();
        drop(App::open(&dir.0).unwrap());
        assert_eq!(
            fs::read_dir(dir.0.join("tmp")).unwrap().count(),
            0,
            "a partial upload from a previous process survived open"
        );
    }

    /// Each ID has one spelling: base64url only, 16 characters, no padding.
    /// Decoding the standard alphabet too would give one blob two names.
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

    /// A file is named by its ID in hex, so two IDs that differ only in case are
    /// two files on a case-insensitive filesystem too.
    #[test]
    fn blob_names_are_hex() {
        let a = FileId::parse("AAAAAAAAAAAAAAAA").unwrap();
        let b = FileId::parse("aaaaaaaaaaaaaaaa").unwrap();
        assert_eq!(a.hex(), "000000000000000000000000");
        assert!(a.hex().to_lowercase() != b.hex().to_lowercase());
        assert_eq!(FileId::from_hex(&b.hex()), Some(b));
    }

    /// An ID that is already taken is never overwritten: the link fails, and the
    /// next ID is tried. With none left, the upload fails and nothing changes.
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

        let three = std::iter::repeat_n(taken.clone(), 3);
        assert!(
            s.app.commit_as(three, &tmp, &owner, 500, limits).is_err(),
            "a taken ID was accepted"
        );
        let fresh = FileId::random();
        let got = s
            .app
            .commit_as([taken.clone(), fresh.clone()], &tmp, &owner, 500, limits)
            .unwrap();
        assert_eq!(got, fresh, "the next ID was not tried");
        assert!(
            fs::read(s.app.blob_path(&taken)).unwrap() == first,
            "the taken ID's blob was overwritten"
        );
        assert_eq!(rows(&s), 2);
    }

    /// The crash points there are so far, reconstructed on disk, then a restart: a blob
    /// linked but never given a row, and a row marked deleting whose blob was not
    /// yet unlinked. (Refunds and the sweep that finishes a marked file come with expiry.)
    #[tokio::test]
    async fn restart_after_crash() {
        let s = server();
        let marked = upload(&s, &random_blob(1000)).await;
        s.app
            .db()
            .conn()
            .execute("UPDATE blobs SET deleting = 1 WHERE id = ?", [&marked.id])
            .unwrap();
        let orphan = s.dir.0.join("blobs").join(FileId::random().hex());
        fs::write(&orphan, random_blob(1000)).unwrap();
        let stray = s.dir.0.join("blobs").join("not-an-id");
        fs::write(&stray, "x").unwrap();

        let Server { app, dir } = s;
        drop(app);
        let s = Server {
            app: Arc::new(App::open(&dir.0).unwrap()),
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
    }
}
