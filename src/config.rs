//! The config file: who may upload, how much each member may store, the rate
//! limits, and which proxies to believe. Every limit is required. The binary
//! carries no numbers of its own: a limit left out is an error, never a
//! default.

use std::net::IpAddr;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use subtle::{ConditionallySelectable, ConstantTimeEq};

use crate::db::{Error, Usage};

/// A person's id: 128 random bits as 22 base64url characters, minted once by
/// `sunbird mint-id`. Rows store it, never the display name, so a rename keeps
/// a member's files and quota, and a new member given a departed member's name
/// starts with nothing of theirs. Reissuing a token does not change it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MemberId(String);

impl MemberId {
    pub fn mint() -> Self {
        MemberId(URL_SAFE_NO_PAD.encode(random16()))
    }

    /// Accepts exactly what `mint` produces: one spelling per id.
    pub fn parse(s: &str) -> Option<Self> {
        let bytes = URL_SAFE_NO_PAD.decode(s).ok()?;
        (bytes.len() == 16 && URL_SAFE_NO_PAD.encode(&bytes) == s).then(|| MemberId(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MemberId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn random16() -> [u8; 16] {
    let mut b = [0; 16];
    getrandom::fill(&mut b).expect("the operating system's random source failed");
    b
}

/// A new upload or admin token, for `sunbird mint-token`: 128 bits from the
/// OS, base64url. The server never makes one; it only ever sees the hash.
pub fn mint_token() -> String {
    URL_SAFE_NO_PAD.encode(random16())
}

pub fn token_sha256(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// What one member may have. Blob bytes on disk, as the server stores them:
/// it keeps no format knowledge, so noise costs exactly what a real file does.
#[derive(Clone, Debug)]
pub struct Quota {
    /// Bytes of live files at once: freed when a file expires or is deleted.
    pub max_active_bytes: u64,
    /// Live files at once.
    pub max_active_files: u64,
    /// Bytes uploaded in any 7 days, counted from the upload ledger, which
    /// deleting a file never touches. Otherwise upload, delete, repeat would
    /// defeat it.
    pub max_bytes_per_week: u64,
}

pub const WEEK: i64 = 7 * 24 * 3600;

#[derive(Clone, Debug)]
pub struct Member {
    pub id: MemberId,
    pub name: String,
    token_sha256: [u8; 32],
    pub quota: Quota,
}

#[derive(Clone, Debug)]
pub struct Admin {
    pub id: MemberId,
    pub name: String,
    token_sha256: [u8; 32],
}

/// At most `requests` in any `seconds`, refilled evenly across them.
#[derive(Clone, Copy, Debug)]
pub struct Rate {
    pub requests: u32,
    pub seconds: u32,
}

pub struct Config {
    pub members: Vec<Member>,
    pub admins: Vec<Admin>,
    /// Proxies whose X-Forwarded-For entries are believed. Empty: the header
    /// is ignored, and the socket address is the client.
    pub trusted_proxies: Vec<IpAddr>,
    /// Per member id.
    pub upload_rate: Rate,
    /// Preview and download, per client address.
    pub read_rate: Rate,
    /// Free space on the data directory's filesystem below which uploads are
    /// refused. Quotas bound each member, not the disk: this bounds the disk.
    pub min_free_bytes: u64,
}

/// The entry in `entries` whose token hashes to `token`'s hash. Every entry is
/// compared, each in constant time, and the answer is selected without a
/// branch: how long this takes depends on how many entries there are, not on
/// which one matched or how much of a hash did.
fn find<'a, T>(entries: &'a [T], hash: impl Fn(&T) -> &[u8; 32], token: &str) -> Option<&'a T> {
    let presented = token_sha256(token);
    find_hash(entries, hash, &presented)
}

fn find_hash<'a, T>(
    entries: &'a [T],
    hash: impl Fn(&T) -> &[u8; 32],
    presented: &[u8; 32],
) -> Option<&'a T> {
    let mut found = u64::MAX;
    for (i, entry) in entries.iter().enumerate() {
        found.conditional_assign(&(i as u64), hash(entry).ct_eq(presented));
    }
    usize::try_from(found).ok().and_then(|i| entries.get(i))
}

impl Config {
    /// The member an upload token belongs to.
    pub fn member(&self, token: &str) -> Option<&Member> {
        find(&self.members, |m| &m.token_sha256, token)
    }

    /// The admin an admin token belongs to. Admin tokens are checked against
    /// the admins only: a member's token never deletes someone else's file.
    pub fn admin(&self, token: &str) -> Option<&Admin> {
        find(&self.admins, |a| &a.token_sha256, token)
    }

    /// The member with this id, for naming an uploader in a log.
    pub fn member_by_id(&self, id: &str) -> Option<&Member> {
        self.members.iter().find(|m| m.id.as_str() == id)
    }

    pub fn read(path: &Path) -> Result<Config, Error> {
        let text = std::fs::read(path).map_err(|e| format!("config {}: {e}", path.display()))?;
        Config::parse(&text).map_err(|e| format!("config {}: {e}", path.display()).into())
    }

    pub fn parse(json: &[u8]) -> Result<Config, String> {
        let value: Value = serde_json::from_slice(json).map_err(|e| e.to_string())?;
        let top = object(&value, "the config")?;
        known(
            top,
            "the config",
            &[
                "note",
                "members",
                "admins",
                "trusted_proxies",
                "upload_rate",
                "read_rate",
                "min_free_bytes",
            ],
        )?;
        if let Some(note) = top.get("note") {
            note.as_str().ok_or("note: a string, if given")?;
        }

        let mut members = Vec::new();
        for (i, v) in array(top, "members", "the config")?.iter().enumerate() {
            let what = format!("members[{i}]");
            let o = object(v, &what)?;
            known(
                o,
                &what,
                &[
                    "id",
                    "name",
                    "token_sha256",
                    "max_active_bytes",
                    "max_active_files",
                    "max_bytes_per_week",
                ],
            )?;
            members.push(Member {
                id: id(o, &what)?,
                name: name(o, &what)?,
                token_sha256: hash(o, &what)?,
                quota: Quota {
                    max_active_bytes: whole(o, "max_active_bytes", &what)?,
                    max_active_files: whole(o, "max_active_files", &what)?,
                    max_bytes_per_week: whole(o, "max_bytes_per_week", &what)?,
                },
            });
        }
        let mut admins = Vec::new();
        for (i, v) in array(top, "admins", "the config")?.iter().enumerate() {
            let what = format!("admins[{i}]");
            let o = object(v, &what)?;
            known(o, &what, &["id", "name", "token_sha256"])?;
            admins.push(Admin {
                id: id(o, &what)?,
                name: name(o, &what)?,
                token_sha256: hash(o, &what)?,
            });
        }
        let mut trusted_proxies = Vec::new();
        for (i, v) in array(top, "trusted_proxies", "the config")?
            .iter()
            .enumerate()
        {
            let address = v
                .as_str()
                .and_then(|s| s.parse::<IpAddr>().ok())
                .ok_or(format!("trusted_proxies[{i}]: an IP address, as a string"))?;
            trusted_proxies.push(address.to_canonical());
        }

        // One id is one person, so it appears once per list. A person who is
        // both a member and an admin keeps one id in both.
        for (list, ids) in [
            ("members", members.iter().map(|m| &m.id).collect::<Vec<_>>()),
            ("admins", admins.iter().map(|a| &a.id).collect()),
        ] {
            for (i, a) in ids.iter().enumerate() {
                if ids[..i].contains(a) {
                    return Err(format!("{list}: id {a} appears twice"));
                }
            }
        }
        // A token that opened two entries would make an upload or a deletion
        // belong to either.
        let hashes: Vec<_> = members
            .iter()
            .map(|m| (&m.token_sha256, &m.id))
            .chain(admins.iter().map(|a| (&a.token_sha256, &a.id)))
            .collect();
        for (i, (h, id)) in hashes.iter().enumerate() {
            if let Some((_, other)) = hashes[..i].iter().find(|(g, _)| g == h) {
                return Err(format!(
                    "{id} and {other} have the same token_sha256; each member and each admin needs a token of their own"
                ));
            }
        }

        Ok(Config {
            members,
            admins,
            trusted_proxies,
            upload_rate: rate(top, "upload_rate")?,
            read_rate: rate(top, "read_rate")?,
            min_free_bytes: whole(top, "min_free_bytes", "the config")?,
        })
    }
}

impl Quota {
    /// Whether one more upload of `size` bytes fits beside `usage`. Refused,
    /// the message names the limit hit and when waiting frees enough, for the
    /// member to read.
    pub fn admit(&self, usage: &Usage, size: u64, now: i64) -> Result<(), String> {
        let files = usage.files.len() as u64;
        if files >= self.max_active_files {
            // The (files - max + 1)th file to expire makes room for one more.
            let frees = usage
                .files
                .get((files - self.max_active_files) as usize)
                .map(|&(_, expires_at)| expires_at);
            return Err(format!(
                "You have {files} files stored, and your limit is {} at once.{}",
                self.max_active_files,
                frees_clause(
                    frees,
                    now,
                    "as your files expire, or sooner if you delete some"
                )
            ));
        }
        let active: u64 = usage.files.iter().map(|&(size, _)| size).sum();
        if active.saturating_add(size) > self.max_active_bytes {
            if size > self.max_active_bytes {
                return Err(format!(
                    "This upload is larger than your limit of {} bytes stored at once.",
                    self.max_active_bytes
                ));
            }
            let frees = frees_at(&usage.files, active + size - self.max_active_bytes, 0);
            return Err(format!(
                "Your files take {active} of your {} bytes stored at once.{}",
                self.max_active_bytes,
                frees_clause(
                    frees,
                    now,
                    "as your files expire, or sooner if you delete some"
                )
            ));
        }
        let week: u64 = usage.week.iter().map(|&(size, _)| size).sum();
        if week.saturating_add(size) > self.max_bytes_per_week {
            if size > self.max_bytes_per_week {
                return Err(format!(
                    "This upload is larger than your limit of {} bytes uploaded per 7 days.",
                    self.max_bytes_per_week
                ));
            }
            let frees = frees_at(&usage.week, week + size - self.max_bytes_per_week, WEEK);
            return Err(format!(
                "You have uploaded {week} of your {} bytes allowed per 7 days.{} Deleting files does not give any back.",
                self.max_bytes_per_week,
                frees_clause(frees, now, "as your earlier uploads pass 7 days old")
            ));
        }
        Ok(())
    }

    /// The most bytes one more upload could be beside `usage`.
    pub fn room(&self, usage: &Usage) -> u64 {
        let active: u64 = usage.files.iter().map(|&(size, _)| size).sum();
        let week: u64 = usage.week.iter().map(|&(size, _)| size).sum();
        self.max_active_bytes
            .saturating_sub(active)
            .min(self.max_bytes_per_week.saturating_sub(week))
    }
}

/// When enough of `entries`, (size, time) in the order they free, has freed
/// to cover `need` bytes: each frees at its time plus `after`.
fn frees_at(entries: &[(u64, i64)], need: u64, after: i64) -> Option<i64> {
    let mut freed = 0u64;
    for &(size, at) in entries {
        freed += size;
        if freed >= need {
            return Some(at + after);
        }
    }
    None
}

fn frees_clause(at: Option<i64>, now: i64, how: &str) -> String {
    match at {
        Some(at) => format!(" Enough frees in {} {how}.", wait(at - now)),
        None => " Waiting will not free enough; ask the server's admin.".into(),
    }
}

/// A wait in words, rounded up.
fn wait(seconds: i64) -> String {
    let seconds = seconds.max(1);
    let (n, unit) = if seconds < 90 {
        (seconds, "second")
    } else if seconds < 90 * 60 {
        ((seconds + 59) / 60, "minute")
    } else if seconds < 48 * 3600 {
        ((seconds + 3599) / 3600, "hour")
    } else {
        ((seconds + 86399) / 86400, "day")
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

// ---- parsing helpers ----------------------------------------------------------

fn object<'a>(v: &'a Value, what: &str) -> Result<&'a Map<String, Value>, String> {
    v.as_object().ok_or(format!("{what}: a JSON object"))
}

/// Refuses keys this version does not read: a misspelt limit must not pass
/// for an absent one.
fn known(o: &Map<String, Value>, what: &str, keys: &[&str]) -> Result<(), String> {
    match o.keys().find(|k| !keys.contains(&k.as_str())) {
        Some(k) => Err(format!("{what}: unknown key {k:?}")),
        None => Ok(()),
    }
}

fn array<'a>(o: &'a Map<String, Value>, key: &str, what: &str) -> Result<&'a Vec<Value>, String> {
    o.get(key)
        .ok_or(format!("{what}: {key} is required"))?
        .as_array()
        .ok_or(format!("{what}: {key} must be a list"))
}

fn whole(o: &Map<String, Value>, key: &str, what: &str) -> Result<u64, String> {
    o.get(key)
        .ok_or(format!("{what}: {key} is required; there is no default"))?
        .as_u64()
        .ok_or(format!("{what}: {key} must be a whole number"))
}

fn id(o: &Map<String, Value>, what: &str) -> Result<MemberId, String> {
    o.get("id")
        .ok_or(format!("{what}: id is required"))?
        .as_str()
        .and_then(MemberId::parse)
        .ok_or(format!(
            "{what}: id must be 22 base64url characters, as `sunbird mint-id` prints"
        ))
}

fn name(o: &Map<String, Value>, what: &str) -> Result<String, String> {
    o.get("name")
        .ok_or(format!("{what}: name is required"))?
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .map(str::to_owned)
        .ok_or(format!("{what}: name must be a non-empty string"))
}

fn hash(o: &Map<String, Value>, what: &str) -> Result<[u8; 32], String> {
    let bad = || {
        format!(
            "{what}: token_sha256 must be 64 hex digits, the hash `sunbird mint-token` prints; never the token itself"
        )
    };
    let s = o
        .get("token_sha256")
        .ok_or(format!("{what}: token_sha256 is required"))?
        .as_str()
        .ok_or_else(bad)?;
    if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(bad());
    }
    let mut out = [0; 32];
    for (i, pair) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| bad())?, 16)
            .map_err(|_| bad())?;
    }
    Ok(out)
}

fn rate(top: &Map<String, Value>, key: &str) -> Result<Rate, String> {
    let o = object(
        top.get(key)
            .ok_or(format!("{key} is required; there is no default"))?,
        key,
    )?;
    known(o, key, &["requests", "seconds"])?;
    let part = |k: &str| {
        let n = whole(o, k, key)?;
        u32::try_from(n)
            .ok()
            .filter(|&n| n > 0)
            .ok_or(format!("{key}: {k} must be from 1 to 4294967295"))
    };
    Ok(Rate {
        requests: part("requests")?,
        seconds: part("seconds")?,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const ID_A: &str = "AAAAAAAAAAAAAAAAAAAAAA";

    fn member_json(id: &str, token: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id, "name": "a", "token_sha256": hex(&token_sha256(token)),
            "max_active_bytes": 1, "max_active_files": 1, "max_bytes_per_week": 1,
        })
    }

    fn config_json(members: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({
            "members": members, "admins": [], "trusted_proxies": [],
            "upload_rate": { "requests": 1, "seconds": 1 },
            "read_rate": { "requests": 1, "seconds": 1 },
            "min_free_bytes": 1,
        })
    }

    fn parse(v: &serde_json::Value) -> Result<Config, String> {
        Config::parse(v.to_string().as_bytes())
    }

    /// The example in the repository parses: it cannot drift from the parser.
    #[test]
    fn example_config_parses() {
        let c = Config::read(Path::new("deploy/sunbird.example.json")).unwrap();
        assert!(!c.members.is_empty() && !c.admins.is_empty());
    }

    /// Every limit is required: leaving one out is an error naming it, never a
    /// default the binary picked.
    #[test]
    fn every_limit_is_required() {
        for key in ["max_active_bytes", "max_active_files", "max_bytes_per_week"] {
            let mut m = member_json(ID_A, "t");
            m.as_object_mut().unwrap().remove(key);
            let err = parse(&config_json(vec![m])).err().unwrap();
            assert!(err.contains(key) && err.contains("required"), "{err}");
        }
        for key in [
            "upload_rate",
            "read_rate",
            "min_free_bytes",
            "members",
            "admins",
            "trusted_proxies",
        ] {
            let mut c = config_json(vec![]);
            c.as_object_mut().unwrap().remove(key);
            let err = parse(&c).err().unwrap();
            assert!(err.contains(key), "{key}: {err}");
        }
        for (key, part) in [("upload_rate", "requests"), ("read_rate", "seconds")] {
            let mut c = config_json(vec![]);
            c[key].as_object_mut().unwrap().remove(part);
            let err = parse(&c).err().unwrap();
            assert!(err.contains(part) && err.contains("required"), "{err}");
            c[key][part] = 0.into();
            assert!(parse(&c).is_err(), "{key}.{part} of 0 accepted");
        }
    }

    #[test]
    fn config_refusals() {
        let token = mint_token();
        // The token itself where its hash belongs.
        let mut m = member_json(ID_A, "t");
        m["token_sha256"] = token.clone().into();
        let err = parse(&config_json(vec![m])).err().unwrap();
        assert!(err.contains("never the token itself"), "{err}");
        // A misspelt limit is not an absent one.
        let mut m = member_json(ID_A, "t");
        m["max_active_byte"] = 1.into();
        assert!(
            parse(&config_json(vec![m]))
                .err()
                .unwrap()
                .contains("unknown key")
        );
        // An id is minted, not made up.
        for bad in ["alice", "AAAAAAAAAAAAAAAAAAAAAB", "AAAAAAAAAAAAAAAAAAAAAAA"] {
            assert!(
                parse(&config_json(vec![member_json(bad, "t")])).is_err(),
                "id {bad}"
            );
        }
        // One id, one entry; one token, one person.
        let other = MemberId::mint().to_string();
        let err = parse(&config_json(vec![
            member_json(ID_A, "t"),
            member_json(ID_A, "u"),
        ]))
        .err()
        .unwrap();
        assert!(err.contains("appears twice"), "{err}");
        let err = parse(&config_json(vec![
            member_json(ID_A, "t"),
            member_json(&other, "t"),
        ]))
        .err()
        .unwrap();
        assert!(err.contains("same token_sha256"), "{err}");
        let mut c = config_json(vec![member_json(ID_A, "t")]);
        c["admins"] = serde_json::json!([{ "id": other, "name": "x", "token_sha256": hex(&token_sha256("t")) }]);
        assert!(
            parse(&c).err().unwrap().contains("same token_sha256"),
            "an admin token that is also a member's"
        );
    }

    #[test]
    fn minted_values() {
        let (a, b) = (mint_token(), mint_token());
        assert!(a != b);
        assert_eq!(URL_SAFE_NO_PAD.decode(&a).unwrap().len(), 16);
        let id = MemberId::mint();
        assert_eq!(MemberId::parse(id.as_str()), Some(id.clone()));
        assert!(id != MemberId::mint());
    }

    /// The comparison is the constant-time one, and it compares whole hashes:
    /// stored hashes that differ from the presented one only in their first
    /// byte, only in their last, or in one bit, match nothing; the exact one
    /// matches wherever it stands in the list. This checks the answers, not the
    /// timing. That comes from `subtle`, and from `find_hash` visiting every
    /// entry and selecting the answer without a branch.
    #[test]
    fn token_lookup_compares_whole_hashes() {
        let presented = token_sha256("the token");
        let near = |i: usize, bit: u8| {
            let mut h = presented;
            h[i] ^= bit;
            h
        };
        let misses = [
            near(0, 0xff),
            near(31, 0xff),
            near(16, 0x01),
            near(31, 0x80),
            [0; 32],
        ];
        assert!(find_hash(&misses, |h| h, &presented).is_none());
        for at in 0..=misses.len() {
            let mut list = misses.to_vec();
            list.insert(at, presented);
            let found = find_hash(&list, |h| h, &presented).map(|h| h as *const _);
            assert_eq!(found, Some(&list[at] as *const _), "exact hash at {at}");
        }
        assert!(find_hash::<[u8; 32]>(&[], |h| h, &presented).is_none());

        // Through the config: the hash itself, presented as a token, is not it.
        let token = mint_token();
        let c = parse(&config_json(vec![member_json(ID_A, &token)])).unwrap();
        assert!(c.member(&token).is_some());
        assert!(c.member(&hex(&token_sha256(&token))).is_none());
        assert!(c.member(&token[..21]).is_none());
        assert!(
            c.admin(&token).is_none(),
            "a member's token opened the admin list"
        );
    }

    #[test]
    fn waits_in_words() {
        for (s, w) in [
            (1, "1 second"),
            (60, "60 seconds"),
            (90, "2 minutes"),
            (3600, "60 minutes"),
            (5400, "2 hours"),
            (WEEK - 1, "7 days"),
        ] {
            assert_eq!(wait(s), w, "{s}");
        }
    }
}
