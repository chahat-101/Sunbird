//! Rate limits, and the client address the read limit is keyed by.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use hyper::header::HeaderValue;

use crate::config::Rate;

/// At most `requests` per `seconds` per key, refilled evenly (GCRA). Stores one
/// due time per key, and a refused request costs nothing.
pub struct Limiter<K> {
    /// One request's share of the window.
    every: Duration,
    /// How far ahead a key's due time may run: enough for a full burst.
    burst: Duration,
    due: Mutex<HashMap<K, Instant>>,
}

impl<K: Eq + Hash> Limiter<K> {
    pub fn new(rate: Rate) -> Self {
        let window = Duration::from_secs(rate.seconds.into());
        let every = window / rate.requests;
        Limiter {
            every,
            burst: window - every,
            due: Mutex::new(HashMap::new()),
        }
    }

    /// Ok, or the whole seconds until a request would be allowed.
    pub fn check(&self, key: K) -> Result<(), u64> {
        self.check_at(key, Instant::now())
    }

    pub fn check_at(&self, key: K, now: Instant) -> Result<(), u64> {
        let mut due = self.due.lock().unwrap_or_else(PoisonError::into_inner);
        let at = due.get(&key).copied().filter(|&t| t > now).unwrap_or(now);
        let ahead = at - now;
        if ahead > self.burst {
            let wait = ahead - self.burst;
            return Err(wait.as_secs() + u64::from(wait.subsec_nanos() > 0));
        }
        due.insert(key, at + self.every);
        Ok(())
    }

    /// Forgets keys that are back to a full allowance. The sweeper calls it.
    pub fn forget_idle(&self) {
        let now = Instant::now();
        self.due
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, &mut t| t > now);
    }
}

/// The real client address. With no trusted proxies, the socket address;
/// X-Forwarded-For is ignored, since anyone can write it. Otherwise, walk the
/// header right to left while each hop is a trusted proxy; the first untrusted
/// hop is the client. Anything further left may be forged.
///
/// An entry that isn't an address stops the walk there.
pub fn client<'a>(
    peer: IpAddr,
    forwarded: impl Iterator<Item = &'a HeaderValue>,
    trusted: &[IpAddr],
) -> IpAddr {
    let mut client = peer.to_canonical();
    if !trusted.contains(&client) {
        return client;
    }
    // Several header lines are one list, in order.
    let lines: Vec<&str> = forwarded.map(|v| v.to_str().unwrap_or("")).collect();
    for entry in lines.iter().rev().flat_map(|line| line.rsplit(',')) {
        if !trusted.contains(&client) {
            break;
        }
        match entry.trim().parse::<IpAddr>() {
            Ok(address) => client = address.to_canonical(),
            Err(_) => break,
        }
    }
    client
}

/// The rate-limit key. An IPv6 /64 is one customer, so one bucket. IPv4 written
/// as IPv6 (::ffff:a.b.c.d) counts as the IPv4 address.
pub fn bucket(address: IpAddr) -> IpAddr {
    match address.to_canonical() {
        IpAddr::V6(v6) => {
            let prefix = u128::from(v6) & !((1u128 << 64) - 1);
            IpAddr::V6(Ipv6Addr::from(prefix))
        }
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn xff(lines: &[&str]) -> Vec<HeaderValue> {
        lines
            .iter()
            .map(|l| HeaderValue::from_str(l).unwrap())
            .collect()
    }

    fn client_of(peer: &str, lines: &[&str], trusted: &[&str]) -> IpAddr {
        let trusted: Vec<IpAddr> = trusted.iter().map(|t| ip(t)).collect();
        client(ip(peer), xff(lines).iter(), &trusted)
    }

    /// With no trusted proxies the header is ignored entirely, whatever it says.
    #[test]
    fn no_trusted_proxies_ignores_the_header() {
        assert_eq!(
            client_of("203.0.113.9", &["1.2.3.4"], &[]),
            ip("203.0.113.9")
        );
        assert_eq!(
            client_of("127.0.0.1", &["1.2.3.4", "5.6.7.8"], &[]),
            ip("127.0.0.1")
        );
    }

    /// With one trusted proxy, the client is the entry just left of it; a direct
    /// request is its own address.
    #[test]
    fn one_trusted_proxy() {
        let proxy = ["10.0.0.1"];
        assert_eq!(
            client_of("10.0.0.1", &["198.51.100.7"], &proxy),
            ip("198.51.100.7")
        );
        // Not through the proxy: the header is the client's own invention.
        assert_eq!(
            client_of("198.51.100.7", &["1.2.3.4"], &proxy),
            ip("198.51.100.7")
        );
        // Through the proxy with no header: the proxy is all there is.
        assert_eq!(client_of("10.0.0.1", &[], &proxy), ip("10.0.0.1"));
    }

    /// A client's own X-Forwarded-For, however long, can't change the answer.
    #[test]
    fn forged_chains_cannot_move_the_client() {
        let proxy = ["10.0.0.1"];
        let real = ip("198.51.100.7");
        for forged in [
            "1.1.1.1",
            "1.1.1.1, 2.2.2.2, 3.3.3.3",
            "10.0.0.1",
            "1.1.1.1, 10.0.0.1",
            "not-an-address",
            "",
        ] {
            let line = format!("{forged}, 198.51.100.7");
            assert_eq!(client_of("10.0.0.1", &[&line], &proxy), real, "{line:?}");
            // The same, as two header lines.
            assert_eq!(
                client_of("10.0.0.1", &[forged, "198.51.100.7"], &proxy),
                real,
                "{forged:?} on its own line"
            );
        }
        // Two trusted proxies in a chain are both walked past.
        let chain = ["10.0.0.1", "10.0.0.2"];
        assert_eq!(
            client_of("10.0.0.2", &["6.6.6.6, 198.51.100.7, 10.0.0.1"], &chain),
            real
        );
        // Garbage from the trusted hop stops the walk at the proxy.
        assert_eq!(
            client_of("10.0.0.1", &["6.6.6.6, garbage"], &proxy),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn ipv6_throttled_by_64() {
        let a = bucket(ip("2001:db8:1:2:aaaa::1"));
        assert_eq!(
            a,
            bucket(ip("2001:db8:1:2:ffff:ffff:ffff:ffff")),
            "one /64, two buckets"
        );
        assert!(a != bucket(ip("2001:db8:1:3::1")), "two /64s, one bucket");
        // IPv4-mapped addresses are IPv4, one bucket each, not one for all of IPv4.
        assert_eq!(bucket(ip("::ffff:192.0.2.1")), ip("192.0.2.1"));
        assert!(bucket(ip("::ffff:192.0.2.1")) != bucket(ip("::ffff:192.0.2.2")));
        // And through a proxy, a mapped peer is still the proxy.
        assert_eq!(
            client_of("::ffff:10.0.0.1", &["2001:db8::5"], &["10.0.0.1"]),
            ip("2001:db8::5")
        );
    }

    #[test]
    fn limiter_bursts_then_refills_evenly() {
        let l = Limiter::new(Rate {
            requests: 3,
            seconds: 60,
        });
        let t0 = Instant::now();
        for i in 0..3 {
            assert_eq!(l.check_at("k", t0), Ok(()), "request {i} of the burst");
        }
        assert_eq!(l.check_at("k", t0), Err(20), "fourth at once");
        assert_eq!(l.check_at("other", t0), Ok(()), "another key");
        assert_eq!(l.check_at("k", t0 + Duration::from_millis(19_500)), Err(1));
        assert_eq!(
            l.check_at("k", t0 + Duration::from_secs(20)),
            Ok(()),
            "one share later"
        );
        assert_eq!(l.check_at("k", t0 + Duration::from_secs(20)), Err(20));
        // Refused requests used nothing: after a full window, a full burst.
        let t1 = t0 + Duration::from_secs(80);
        for i in 0..3 {
            assert_eq!(l.check_at("k", t1), Ok(()), "request {i} a window later");
        }
    }
}
