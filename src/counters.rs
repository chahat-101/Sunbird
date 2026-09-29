//! The numbers the server keeps about itself: totals only, never which file or
//! which member. In memory, and saved to the `counters` table on a timer and
//! at shutdown, so a restart does not lose them. A crash loses what changed
//! since the last save.

use std::sync::atomic::{AtomicU64, Ordering};

/// Each counter, as its row in the `counters` table names it. The names are
/// the ones schema version 5 already stored (tests/fixtures/schema-v5), so a
/// database written before this rewrite carries on counting.
#[derive(Clone, Copy, Debug)]
pub enum Counter {
    /// Files stored.
    Uploads,
    /// Blob bytes of the files stored.
    BytesUploaded,
    /// Downloads whose last byte the server handed to the connection. Not
    /// files anyone received: see the README.
    Downloads,
    /// Downloads claimed and then not completed, so refunded.
    FailedDownloads,
    /// Uploads by a member, within their limits, that stored nothing: the
    /// client went away, the server failed (a full disk included), or
    /// shutdown cut them off.
    FailedUploads,
    /// Files the sweeper deleted after their expiry time.
    ExpiredSwept,
    /// Deletions that failed, one per attempt: a stuck file adds one every
    /// sweep until it goes.
    DeletionFailures,
    /// Uploads refused with 429 by the per-member limit.
    RateLimitedUploads,
    /// Previews and downloads refused with 429 by the per-address limit.
    RateLimitedReads,
    /// Uploads refused with 507 at the free-space floor, before or during the
    /// body.
    UploadsRefusedLowDisk,
}

const ALL: [Counter; 10] = [
    Counter::Uploads,
    Counter::BytesUploaded,
    Counter::Downloads,
    Counter::FailedDownloads,
    Counter::FailedUploads,
    Counter::ExpiredSwept,
    Counter::DeletionFailures,
    Counter::RateLimitedUploads,
    Counter::RateLimitedReads,
    Counter::UploadsRefusedLowDisk,
];

impl Counter {
    pub fn name(self) -> &'static str {
        match self {
            Counter::Uploads => "uploads",
            Counter::BytesUploaded => "bytes_uploaded",
            Counter::Downloads => "downloads",
            Counter::FailedDownloads => "failed_downloads",
            Counter::FailedUploads => "failed_uploads",
            Counter::ExpiredSwept => "expired_swept",
            Counter::DeletionFailures => "deletion_failures",
            Counter::RateLimitedUploads => "rate_limited_uploads",
            Counter::RateLimitedReads => "rate_limited_reads",
            Counter::UploadsRefusedLowDisk => "uploads_refused_low_disk",
        }
    }
}

/// The row holding when counting began, in Unix seconds.
pub const COUNTING_SINCE: &str = "counting_since";

pub struct Counters {
    values: [AtomicU64; ALL.len()],
    /// When the first of these was counted: the start of the totals.
    pub counting_since: i64,
}

impl Counters {
    /// The totals in `stored` (name, value) rows, carried on. With no
    /// counting_since row, counting begins at `now`. Rows this version does
    /// not know are left alone.
    pub fn load(stored: &[(String, i64)], now: i64) -> Counters {
        let get = |name: &str| {
            stored
                .iter()
                .find(|(n, _)| n == name)
                .map(|&(_, value)| value)
        };
        Counters {
            values: ALL.map(|c| AtomicU64::new(get(c.name()).unwrap_or(0).max(0) as u64)),
            counting_since: get(COUNTING_SINCE).unwrap_or(now),
        }
    }

    pub fn add(&self, counter: Counter, n: u64) {
        self.values[counter as usize].fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self, counter: Counter) -> u64 {
        self.values[counter as usize].load(Ordering::Relaxed)
    }

    /// Every counter, then counting_since, as rows to save. Each value is read
    /// once; saving writes them whole, not as increments, so a save that runs
    /// twice counts nothing twice.
    pub fn rows(&self) -> Vec<(&'static str, i64)> {
        ALL.iter()
            .map(|&c| (c.name(), self.get(c) as i64))
            .chain([(COUNTING_SINCE, self.counting_since)])
            .collect()
    }

    /// The totals as JSON, for /admin/stats and the log line.
    pub fn json(&self) -> serde_json::Value {
        let mut o = serde_json::Map::new();
        for (name, value) in self.rows() {
            o.insert(name.into(), value.into());
        }
        serde_json::Value::Object(o)
    }
}
