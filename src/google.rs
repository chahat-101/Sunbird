//! Google sign-in: a way to get a token, never a way to upload. No session, no
//! cookie; the only thing held between the redirect and the callback is a small
//! in-memory set of pending sign-ins.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::{Method, Request, Uri};
use hyper_util::rt::TokioIo;
use ring::signature::{self, RsaPublicKeyComponents};
use serde_json::Value;
use subtle::ConstantTimeEq;
use tokio::net::TcpStream;

use crate::config::GoogleSignin;

const ISSUERS: [&str; 2] = ["accounts.google.com", "https://accounts.google.com"];

/// Seconds a sign-in may take between the redirect and the callback.
const PENDING_TTL: i64 = 600;
/// Starting a sign-in needs no login, so the pending set is bounded.
const PENDING_MAX: usize = 1024;

/// The token is fresh from Google's token endpoint, so `iat` should be recent.
const MAX_TOKEN_AGE: i64 = 600;
const CLOCK_SKEW: i64 = 60;

/// Key set lifetime, and the least time between refetches for an unknown `kid`
/// (so a forged one cannot make us hammer Google).
const JWKS_MAX_AGE: i64 = 3600;
const JWKS_MIN_REFETCH: i64 = 60;

const MAX_ANSWER: usize = 1 << 20;
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_TOKEN_LEN: usize = 8192;

/// Tests point these at a local stand-in.
pub struct Endpoints {
    pub auth: String,
    pub token: String,
    pub jwks: String,
}

impl Endpoints {
    pub fn google() -> Endpoints {
        Endpoints {
            auth: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            token: "https://oauth2.googleapis.com/token".into(),
            jwks: "https://www.googleapis.com/oauth2/v3/certs".into(),
        }
    }
}

pub struct Signin {
    pub endpoints: Endpoints,
    pending: Mutex<HashMap<String, (String, i64)>>,
    keys: Mutex<Cached>,
}

#[derive(Default)]
struct Cached {
    keys: Arc<Vec<Jwk>>,
    fetched: Option<i64>,
}

impl Signin {
    pub fn new() -> Signin {
        Signin {
            endpoints: Endpoints::google(),
            pending: Mutex::default(),
            keys: Mutex::default(),
        }
    }

    /// A new `(state, nonce)`, or None if too many are waiting.
    pub fn begin(&self, now: i64) -> Option<(String, String)> {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        if pending.len() >= PENDING_MAX {
            pending.retain(|_, (_, expires)| *expires > now);
        }
        if pending.len() >= PENDING_MAX {
            return None;
        }
        let (state, nonce) = (random_text(), random_text());
        pending.insert(state.clone(), (nonce.clone(), now + PENDING_TTL));
        Some((state, nonce))
    }

    /// Spends a pending sign-in. None if unknown, used already, or expired.
    pub fn take(&self, state: &str, now: i64) -> Option<String> {
        let (nonce, expires) = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(state)?;
        (expires > now).then_some(nonce)
    }

    pub fn redirect_url(&self, google: &GoogleSignin, state: &str, nonce: &str) -> String {
        format!(
            "{}?{}",
            self.endpoints.auth,
            form(&[
                ("client_id", &google.client_id),
                ("redirect_uri", &google.redirect_uri),
                ("response_type", "code"),
                ("scope", "openid"),
                ("state", state),
                ("nonce", nonce),
            ])
        )
    }

    /// Exchanges the code, verifies the ID token, returns its `sub`.
    pub async fn subject(
        &self,
        google: &GoogleSignin,
        code: &str,
        nonce: &str,
        now: i64,
    ) -> Result<String, SigninError> {
        let answer = fetch(
            &self.endpoints.token,
            Some(form(&[
                ("code", code),
                ("client_id", &google.client_id),
                ("client_secret", &google.client_secret),
                ("redirect_uri", &google.redirect_uri),
                ("grant_type", "authorization_code"),
            ])),
        )
        .await
        .map_err(SigninError::Unreachable)?;
        let token = serde_json::from_slice::<Value>(&answer)
            .ok()
            .and_then(|v| v.get("id_token")?.as_str().map(str::to_owned))
            .ok_or_else(|| SigninError::Unreachable("no id_token in the answer".into()))?;

        let mut refetched = false;
        if self.keys_age(now).is_none_or(|age| age >= JWKS_MAX_AGE) {
            self.refresh_keys(now).await?;
            refetched = true;
        }
        let mut result = verify_id_token(&token, &self.keys(), &google.client_id, nonce, now);
        if matches!(result, Err(VerifyError::UnknownKey))
            && !refetched
            && self.keys_age(now).is_none_or(|age| age >= JWKS_MIN_REFETCH)
        {
            self.refresh_keys(now).await?;
            result = verify_id_token(&token, &self.keys(), &google.client_id, nonce, now);
        }
        result.map_err(SigninError::Rejected)
    }

    fn keys(&self) -> Arc<Vec<Jwk>> {
        self.keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys
            .clone()
    }

    fn keys_age(&self, now: i64) -> Option<i64> {
        let fetched = self
            .keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .fetched?;
        Some(now - fetched)
    }

    async fn refresh_keys(&self, now: i64) -> Result<(), SigninError> {
        let answer = fetch(&self.endpoints.jwks, None)
            .await
            .map_err(SigninError::Unreachable)?;
        let keys = parse_jwks(&answer).map_err(SigninError::Unreachable)?;
        *self.keys.lock().unwrap_or_else(PoisonError::into_inner) = Cached {
            keys: Arc::new(keys),
            fetched: Some(now),
        };
        Ok(())
    }
}

#[derive(Debug)]
pub enum SigninError {
    Unreachable(String),
    Rejected(VerifyError),
}

fn random_text() -> String {
    let mut b = [0; 16];
    getrandom::fill(&mut b).expect("the operating system's random source failed");
    URL_SAFE_NO_PAD.encode(b)
}

#[derive(Debug, Clone)]
pub struct Jwk {
    kid: String,
    n: Vec<u8>,
    e: Vec<u8>,
}

pub fn parse_jwks(json: &[u8]) -> Result<Vec<Jwk>, String> {
    let value: Value = serde_json::from_slice(json).map_err(|e| format!("key set: {e}"))?;
    let keys = value
        .get("keys")
        .and_then(Value::as_array)
        .ok_or("key set: no keys list")?;
    let part = |k: &Value, name: &str| {
        URL_SAFE_NO_PAD
            .decode(k.get(name)?.as_str()?)
            .ok()
            .filter(|b| !b.is_empty())
    };
    let keys: Vec<Jwk> = keys
        .iter()
        .filter(|k| k.get("kty").and_then(Value::as_str) == Some("RSA"))
        .filter(|k| k.get("alg").is_none_or(|a| a == "RS256"))
        .filter_map(|k| {
            Some(Jwk {
                kid: k.get("kid")?.as_str()?.to_owned(),
                n: part(k, "n")?,
                e: part(k, "e")?,
            })
        })
        .collect();
    if keys.is_empty() {
        return Err("key set: no usable RSA key".into());
    }
    Ok(keys)
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    Malformed,
    Algorithm,
    UnknownKey,
    Signature,
    Issuer,
    Audience,
    Expired,
    IssuedAt,
    Nonce,
    Subject,
}

/// Returns the token's `sub`. No claim is read until the signature holds.
pub fn verify_id_token(
    token: &str,
    keys: &[Jwk],
    client_id: &str,
    nonce: &str,
    now: i64,
) -> Result<String, VerifyError> {
    use VerifyError::*;
    if token.len() > MAX_TOKEN_LEN {
        return Err(Malformed);
    }
    let mut parts = token.split('.');
    let (Some(header), Some(claims), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Malformed);
    };
    let json = |part: &str| -> Result<Value, VerifyError> {
        let bytes = URL_SAFE_NO_PAD.decode(part).map_err(|_| Malformed)?;
        serde_json::from_slice(&bytes).map_err(|_| Malformed)
    };
    let header = json(header)?;
    if header.get("alg").and_then(Value::as_str) != Some("RS256") {
        return Err(Algorithm);
    }
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or(UnknownKey)?;
    let key = keys.iter().find(|k| k.kid == kid).ok_or(UnknownKey)?;
    let sig = URL_SAFE_NO_PAD.decode(sig).map_err(|_| Malformed)?;
    let signed = &token[..header_and_claims_len(token)];
    RsaPublicKeyComponents {
        n: &key.n,
        e: &key.e,
    }
    .verify(
        &signature::RSA_PKCS1_2048_8192_SHA256,
        signed.as_bytes(),
        &sig,
    )
    .map_err(|_| Signature)?;

    let claims = json(claims)?;
    let text = |name: &str| claims.get(name).and_then(Value::as_str);
    let number = |name: &str| claims.get(name).and_then(Value::as_i64);
    if !text("iss").is_some_and(|iss| ISSUERS.contains(&iss)) {
        return Err(Issuer);
    }
    if text("aud") != Some(client_id) {
        return Err(Audience);
    }
    if !number("exp").is_some_and(|exp| exp > now) {
        return Err(Expired);
    }
    if !number("iat").is_some_and(|iat| iat <= now + CLOCK_SKEW && now - iat <= MAX_TOKEN_AGE) {
        return Err(IssuedAt);
    }
    let presented = text("nonce").ok_or(Nonce)?;
    if !bool::from(presented.as_bytes().ct_eq(nonce.as_bytes())) {
        return Err(Nonce);
    }
    match text("sub") {
        Some(sub) if !sub.is_empty() && sub.len() <= 255 => Ok(sub.to_owned()),
        _ => Err(Subject),
    }
}

fn header_and_claims_len(token: &str) -> usize {
    token.rfind('.').expect("three parts were checked")
}

/// POST a form if `body` is given, else GET. Success only on a 2xx.
async fn fetch(url: &str, body: Option<String>) -> Result<Vec<u8>, String> {
    tokio::time::timeout(EXCHANGE_TIMEOUT, exchange(url, body))
        .await
        .map_err(|_| format!("{url}: no answer within {} s", EXCHANGE_TIMEOUT.as_secs()))?
}

async fn exchange(url: &str, body: Option<String>) -> Result<Vec<u8>, String> {
    let uri: Uri = url.parse().map_err(|e| format!("{url}: {e}"))?;
    let tls = match uri.scheme_str() {
        Some("https") => true,
        // Tests only.
        Some("http") => false,
        _ => return Err(format!("{url}: not an http or https URL")),
    };
    let host = uri.host().ok_or(format!("{url}: no host"))?;
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let tcp = TcpStream::connect((host, port))
        .await
        .map_err(|e| format!("{url}: {e}"))?;

    let request = Request::builder()
        .method(if body.is_some() {
            Method::POST
        } else {
            Method::GET
        })
        .uri(uri.path_and_query().map_or("/", |p| p.as_str()))
        .header("host", uri.authority().map_or(host, |a| a.as_str()))
        .header("connection", "close")
        .header("accept", "application/json");
    let request = match body {
        Some(body) => request
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Full::new(Bytes::from(body))),
        None => request.body(Full::new(Bytes::new())),
    }
    .map_err(|e| e.to_string())?;

    if tls {
        let name = rustls::pki_types::ServerName::try_from(host.to_owned())
            .map_err(|e| format!("{url}: {e}"))?;
        let stream = tokio_rustls::TlsConnector::from(tls_config())
            .connect(name, tcp)
            .await
            .map_err(|e| format!("{url}: {e}"))?;
        send(url, TokioIo::new(stream), request).await
    } else {
        send(url, TokioIo::new(tcp), request).await
    }
}

async fn send<T>(url: &str, io: T, request: Request<Full<Bytes>>) -> Result<Vec<u8>, String>
where
    T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    tokio::spawn(connection);
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    let status = response.status();
    let body = Limited::new(response.into_body(), MAX_ANSWER)
        .collect()
        .await
        .map_err(|e| format!("{url}: {e}"))?
        .to_bytes();
    if !status.is_success() {
        return Err(format!(
            "{url}: {status}: {}",
            String::from_utf8_lossy(&body)
        ));
    }
    Ok(body.to_vec())
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            Arc::new(
                rustls::ClientConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .expect("rustls's default protocol versions")
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        })
        .clone()
}

fn form(pairs: &[(&str, &str)]) -> String {
    let encode = |text: &str, out: &mut String| {
        for b in text.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    out.push(b as char)
                }
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
    };
    let mut out = String::new();
    for (i, (key, value)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        encode(key, &mut out);
        out.push('=');
        encode(value, &mut out);
    }
    out
}

/// A query value, percent-decoded. None if absent, repeated or not UTF-8.
pub fn query_value(query: Option<&str>, key: &str) -> Option<String> {
    let mut found = query.unwrap_or("").split('&').filter_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (k == key).then_some(v)
    });
    let value = found.next().filter(|_| found.next().is_none())?;
    let mut bytes = Vec::with_capacity(value.len());
    let mut raw = value.bytes();
    while let Some(b) = raw.next() {
        match b {
            b'%' => {
                let hi = raw.next()?;
                let lo = raw.next()?;
                let hex = [hi, lo];
                bytes.push(u8::from_str_radix(std::str::from_utf8(&hex).ok()?, 16).ok()?);
            }
            b'+' => bytes.push(b' '),
            _ => bytes.push(b),
        }
    }
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    //! ID token checks one by one, then the whole flow against a local fake Google.

    use std::sync::atomic::{AtomicI64, Ordering};

    use http_body_util::BodyExt;
    use hyper::body::Incoming;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Response, StatusCode};
    use ring::rand::SystemRandom;
    use ring::signature::RsaKeyPair;
    use sha2::{Digest, Sha256};
    use tokio::net::TcpListener;

    use super::*;
    use crate::http::tests::send;
    use crate::http::tests::*;

    const CLIENT: &str = "test-client.apps.googleusercontent.com";
    const SECRET: &str = "test-client-secret-value";
    const SUB: &str = "110169484474386276334";
    const EMAIL: &str = "someone@example.org";

    fn key(b64: &str) -> RsaKeyPair {
        let der = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .unwrap();
        RsaKeyPair::from_der(&der).unwrap()
    }

    fn key_a() -> RsaKeyPair {
        key(include_str!("../tests/fixtures/google-test-key-a.b64"))
    }

    fn key_b() -> RsaKeyPair {
        key(include_str!("../tests/fixtures/google-test-key-b.b64"))
    }

    fn jwk(kid: &str, pair: &RsaKeyPair) -> Value {
        let public: RsaPublicKeyComponents<Vec<u8>> = pair.public().into();
        serde_json::json!({
            "kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig",
            "n": URL_SAFE_NO_PAD.encode(&public.n),
            "e": URL_SAFE_NO_PAD.encode(&public.e),
        })
    }

    fn jwks(keys: &[(&str, &RsaKeyPair)]) -> String {
        let keys: Vec<Value> = keys.iter().map(|(kid, pair)| jwk(kid, pair)).collect();
        serde_json::json!({ "keys": keys }).to_string()
    }

    fn b64(v: &Value) -> String {
        URL_SAFE_NO_PAD.encode(v.to_string())
    }

    fn sign_with(pair: &RsaKeyPair, header: Value, claims: &Value) -> String {
        let signed = format!("{}.{}", b64(&header), b64(claims));
        let mut sig = vec![0; pair.public().modulus_len()];
        pair.sign(
            &signature::RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            signed.as_bytes(),
            &mut sig,
        )
        .unwrap();
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(sig))
    }

    fn sign(pair: &RsaKeyPair, claims: &Value) -> String {
        sign_with(
            pair,
            serde_json::json!({ "alg": "RS256", "kid": "k1", "typ": "JWT" }),
            claims,
        )
    }

    fn good_claims(nonce: &str, now: i64) -> Value {
        serde_json::json!({
            "iss": "https://accounts.google.com", "aud": CLIENT, "sub": SUB,
            "email": EMAIL, "email_verified": true, "name": "Some One",
            "picture": "https://example.org/p.png",
            "iat": now, "exp": now + 3600, "nonce": nonce,
        })
    }

    const NOW: i64 = 1_800_000_000;
    const NONCE: &str = "the-nonce-we-issued";

    fn verify_edited(edit: impl FnOnce(&mut Value)) -> Result<String, VerifyError> {
        let mut claims = good_claims(NONCE, NOW);
        edit(&mut claims);
        let keys = parse_jwks(jwks(&[("k1", &key_a())]).as_bytes()).unwrap();
        verify_id_token(&sign(&key_a(), &claims), &keys, CLIENT, NONCE, NOW)
    }

    #[test]
    fn a_good_token_verifies_and_yields_only_the_sub() {
        assert_eq!(verify_edited(|_| {}), Ok(SUB.to_owned()));
        // Google uses both spellings of its issuer.
        for iss in ["accounts.google.com", "https://accounts.google.com"] {
            assert_eq!(
                verify_edited(|c| c["iss"] = iss.into()),
                Ok(SUB.to_owned()),
                "{iss}"
            );
        }
    }

    #[test]
    fn rejects_a_wrong_signature() {
        // Signed by key B, but k1 is key A: the signature does not verify.
        let keys = parse_jwks(jwks(&[("k1", &key_a())]).as_bytes()).unwrap();
        let token = sign(&key_b(), &good_claims(NONCE, NOW));
        assert_eq!(
            verify_id_token(&token, &keys, CLIENT, NONCE, NOW),
            Err(VerifyError::Signature)
        );
    }

    #[test]
    fn rejects_claims_changed_after_signing() {
        let keys = parse_jwks(jwks(&[("k1", &key_a())]).as_bytes()).unwrap();
        let token = sign(&key_a(), &good_claims(NONCE, NOW));
        let mut parts: Vec<&str> = token.split('.').collect();
        let other = b64(&good_claims(NONCE, NOW)
            .as_object()
            .map(|o| {
                let mut o = o.clone();
                o.insert("sub".into(), "someone-else".into());
                Value::Object(o)
            })
            .unwrap());
        parts[1] = &other;
        assert_eq!(
            verify_id_token(&parts.join("."), &keys, CLIENT, NONCE, NOW),
            Err(VerifyError::Signature)
        );
    }

    #[test]
    fn rejects_a_wrong_audience() {
        assert_eq!(
            verify_edited(|c| c["aud"] = "another-app".into()),
            Err(VerifyError::Audience)
        );
        // An array is not accepted, even one that contains ours.
        assert_eq!(
            verify_edited(|c| c["aud"] = serde_json::json!([CLIENT, "another-app"])),
            Err(VerifyError::Audience)
        );
        assert_eq!(
            verify_edited(|c| {
                c.as_object_mut().unwrap().remove("aud");
            }),
            Err(VerifyError::Audience)
        );
    }

    #[test]
    fn rejects_an_expired_token() {
        assert_eq!(
            verify_edited(|c| c["exp"] = (NOW - 1).into()),
            Err(VerifyError::Expired)
        );
        assert_eq!(
            verify_edited(|c| c["exp"] = NOW.into()),
            Err(VerifyError::Expired),
            "exp == now"
        );
        assert_eq!(
            verify_edited(|c| {
                c.as_object_mut().unwrap().remove("exp");
            }),
            Err(VerifyError::Expired)
        );
        assert!(verify_edited(|c| c["exp"] = (NOW + 1).into()).is_ok());
    }

    #[test]
    fn rejects_a_wrong_issuer() {
        for iss in [
            "https://evil.example",
            "accounts.google.com.evil.example",
            "http://accounts.google.com",
            "",
        ] {
            assert_eq!(
                verify_edited(|c| c["iss"] = iss.into()),
                Err(VerifyError::Issuer),
                "{iss:?}"
            );
        }
        assert_eq!(
            verify_edited(|c| {
                c.as_object_mut().unwrap().remove("iss");
            }),
            Err(VerifyError::Issuer)
        );
    }

    #[test]
    fn rejects_a_wrong_nonce() {
        assert_eq!(
            verify_edited(|c| c["nonce"] = "another-nonce".into()),
            Err(VerifyError::Nonce)
        );
        assert_eq!(
            verify_edited(|c| c["nonce"] = "".into()),
            Err(VerifyError::Nonce)
        );
        assert_eq!(
            verify_edited(|c| {
                c.as_object_mut().unwrap().remove("nonce");
            }),
            Err(VerifyError::Nonce)
        );
    }

    #[test]
    fn rejects_an_implausible_issue_time() {
        assert_eq!(
            verify_edited(|c| c["iat"] = (NOW - MAX_TOKEN_AGE - 1).into()),
            Err(VerifyError::IssuedAt)
        );
        assert_eq!(
            verify_edited(|c| c["iat"] = (NOW + CLOCK_SKEW + 1).into()),
            Err(VerifyError::IssuedAt)
        );
        assert!(verify_edited(|c| c["iat"] = (NOW - MAX_TOKEN_AGE).into()).is_ok());
        assert!(verify_edited(|c| c["iat"] = (NOW + CLOCK_SKEW).into()).is_ok());
        assert_eq!(
            verify_edited(|c| {
                c.as_object_mut().unwrap().remove("iat");
            }),
            Err(VerifyError::IssuedAt)
        );
    }

    #[test]
    fn rejects_a_missing_or_absurd_sub() {
        assert_eq!(
            verify_edited(|c| {
                c.as_object_mut().unwrap().remove("sub");
            }),
            Err(VerifyError::Subject)
        );
        assert_eq!(
            verify_edited(|c| c["sub"] = "".into()),
            Err(VerifyError::Subject)
        );
        assert_eq!(
            verify_edited(|c| c["sub"] = 12345.into()),
            Err(VerifyError::Subject)
        );
        assert_eq!(
            verify_edited(|c| c["sub"] = "9".repeat(256).into()),
            Err(VerifyError::Subject)
        );
    }

    #[test]
    fn rejects_other_algorithms_unknown_keys_and_junk() {
        let keys = parse_jwks(jwks(&[("k1", &key_a())]).as_bytes()).unwrap();
        let claims = good_claims(NONCE, NOW);
        let verify = |token: &str| verify_id_token(token, &keys, CLIENT, NONCE, NOW);
        for alg in ["none", "HS256", "RS512", "rs256", ""] {
            let token = sign_with(
                &key_a(),
                serde_json::json!({ "alg": alg, "kid": "k1" }),
                &claims,
            );
            assert_eq!(verify(&token), Err(VerifyError::Algorithm), "alg {alg:?}");
        }
        // `alg: none` as attackers send it: no signature at all.
        let unsigned = format!(
            "{}.{}.",
            b64(&serde_json::json!({ "alg": "none" })),
            b64(&claims)
        );
        assert_eq!(verify(&unsigned), Err(VerifyError::Algorithm));
        let token = sign_with(
            &key_a(),
            serde_json::json!({ "alg": "RS256", "kid": "k9" }),
            &claims,
        );
        assert_eq!(verify(&token), Err(VerifyError::UnknownKey));
        let token = sign_with(&key_a(), serde_json::json!({ "alg": "RS256" }), &claims);
        assert_eq!(verify(&token), Err(VerifyError::UnknownKey), "no kid");
        for junk in [
            "",
            "a.b",
            "a.b.c.d",
            "a.b.c",
            "....",
            &"x".repeat(MAX_TOKEN_LEN + 1),
        ] {
            assert!(verify(junk).is_err(), "{junk:?}");
        }
    }

    #[test]
    fn key_set_parsing_keeps_only_usable_rsa_keys() {
        let good = jwk("k1", &key_a());
        let other =
            serde_json::json!({ "kid": "ec", "kty": "EC", "crv": "P-256", "x": "AA", "y": "AA" });
        let wrong_alg = {
            let mut k = jwk("k2", &key_b());
            k["alg"] = "RS512".into();
            k
        };
        let keys = parse_jwks(
            serde_json::json!({ "keys": [good, other, wrong_alg] })
                .to_string()
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            keys.iter().map(|k| k.kid.as_str()).collect::<Vec<_>>(),
            ["k1"]
        );
        for bad in ["", "{}", r#"{"keys": []}"#, r#"{"keys": [{"kid": "x"}]}"#] {
            assert!(parse_jwks(bad.as_bytes()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn pending_sign_ins_are_spent_once_expire_and_are_bounded() {
        let s = Signin::new();
        let (state, nonce) = s.begin(NOW).unwrap();
        assert_ne!(state, nonce);
        assert_eq!(s.take(&state, NOW + 1).as_deref(), Some(nonce.as_str()));
        assert_eq!(
            s.take(&state, NOW + 1),
            None,
            "a second use of the same state"
        );
        assert_eq!(s.take("never-issued", NOW), None);
        let (state, _) = s.begin(NOW).unwrap();
        assert_eq!(s.take(&state, NOW + PENDING_TTL), None, "expired");
        for _ in 0..PENDING_MAX {
            s.begin(NOW).unwrap();
        }
        assert!(s.begin(NOW).is_none(), "the set grew past its bound");
        assert!(
            s.begin(NOW + PENDING_TTL).is_some(),
            "expired ones make room"
        );
    }

    #[test]
    fn url_text() {
        assert_eq!(
            form(&[("a", "b c"), ("code", "4/0A+x=")]),
            "a=b%20c&code=4%2F0A%2Bx%3D"
        );
        assert_eq!(
            query_value(Some("code=4%2F0A%2Bx%3D&state=s"), "code").as_deref(),
            Some("4/0A+x=")
        );
        assert_eq!(query_value(Some("a=1&a=2"), "a"), None, "given twice");
        assert_eq!(query_value(Some("a=%ff"), "a"), None, "not UTF-8");
        assert_eq!(query_value(Some("a=%4"), "a"), None, "cut-off escape");
        assert_eq!(query_value(None, "a"), None);
    }

    struct FakeState {
        id_token: String,
        jwks: String,
        token_status: u16,
        token_posts: Vec<String>,
        jwks_gets: usize,
    }

    struct Fake {
        state: Arc<Mutex<FakeState>>,
        base: String,
    }

    impl Fake {
        fn endpoints(&self) -> Endpoints {
            Endpoints {
                auth: format!("{}/auth", self.base),
                token: format!("{}/token", self.base),
                jwks: format!("{}/certs", self.base),
            }
        }

        fn set(&self, f: impl FnOnce(&mut FakeState)) {
            f(&mut self.state.lock().unwrap());
        }

        fn posts(&self) -> Vec<String> {
            self.state.lock().unwrap().token_posts.clone()
        }

        fn jwks_gets(&self) -> usize {
            self.state.lock().unwrap().jwks_gets
        }
    }

    async fn fake_google() -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(FakeState {
            id_token: String::new(),
            jwks: jwks(&[("k1", &key_a())]),
            token_status: 200,
            token_posts: vec![],
            jwks_gets: 0,
        }));
        tokio::spawn({
            let state = state.clone();
            async move {
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let state = state.clone();
                    tokio::spawn(async move {
                        let service = service_fn(move |req: Request<Incoming>| {
                            let state = state.clone();
                            async move {
                                let path = req.uri().path().to_owned();
                                let body = req.into_body().collect().await.unwrap().to_bytes();
                                let mut st = state.lock().unwrap();
                                let (status, text) = match path.as_str() {
                                    "/token" => {
                                        st.token_posts.push(String::from_utf8_lossy(&body).into());
                                        let text = serde_json::json!({ "id_token": st.id_token, "access_token": "never-used" }).to_string();
                                        (st.token_status, text)
                                    }
                                    "/certs" => {
                                        st.jwks_gets += 1;
                                        (200, st.jwks.clone())
                                    }
                                    _ => (404, String::new()),
                                };
                                Ok::<_, std::convert::Infallible>(
                                    Response::builder()
                                        .status(status)
                                        .body(Full::new(Bytes::from(text)))
                                        .unwrap(),
                                )
                            }
                        });
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
            }
        });
        Fake { state, base }
    }

    const CALLBACK: &str = "https://files.example.org/auth/google/callback";

    fn signin_server(
        fake: &Fake,
        max_members: u64,
        files: u64,
        setup: impl FnOnce(&mut crate::app::App),
    ) -> Server {
        let endpoints = fake.endpoints();
        let config = config(
            vec![member(MEMBER_ID, "member", MEMBER_TOKEN, NO_LIMIT)],
            |c| {
                c["google_signin"] = serde_json::json!({
                    "client_id": CLIENT, "client_secret": SECRET, "redirect_uri": CALLBACK,
                    "max_members": max_members,
                    "max_active_bytes": 1 << 30, "max_active_files": files, "max_bytes_per_week": 1 << 30,
                });
            },
        );
        server_config(config, |app| {
            app.signin.endpoints = endpoints;
            setup(app);
        })
    }

    async fn start(s: &Server) -> (String, String) {
        let r = get(s, "/auth/google").await;
        assert_eq!(
            r.status,
            StatusCode::FOUND,
            "{}",
            String::from_utf8_lossy(&r.body)
        );
        let location = r.headers["location"].to_str().unwrap().to_owned();
        let query = location.split_once('?').unwrap().1.to_owned();
        let value = |k| query_value(Some(&query), k).unwrap();
        (value("state"), value("nonce"))
    }

    async fn callback(s: &Server, state: &str) -> Reply {
        get(
            s,
            &format!("/auth/google/callback?code=c0de%2F1&state={state}"),
        )
        .await
    }

    fn token_of(r: &Reply) -> String {
        let page = String::from_utf8_lossy(&r.body);
        assert_eq!(r.status, StatusCode::OK, "{page}");
        let after = page
            .split(r#"<code id="owner-token">"#)
            .nth(1)
            .expect("no token on the page");
        after.split('<').next().unwrap().to_owned()
    }

    async fn sign_in_as(
        s: &Server,
        fake: &Fake,
        sub: &str,
        edit: impl FnOnce(&mut Value),
    ) -> Reply {
        let (state, nonce) = start(s).await;
        let mut claims = good_claims(&nonce, now());
        claims["sub"] = sub.into();
        edit(&mut claims);
        let token = sign(&key_a(), &claims);
        fake.set(|f| f.id_token = token);
        callback(s, &state).await
    }

    async fn upload_as(s: &Server, token: &str, size: usize) -> Reply {
        send(
            s,
            "POST",
            &live_path(),
            Source::bytes(&random_blob(size)),
            token,
        )
        .await
    }

    fn member_rows(s: &Server) -> Vec<(Vec<u8>, String, Vec<u8>, i64)> {
        s.app
            .db()
            .conn()
            .prepare("SELECT sub_sha256, member_id, token_sha256, banned FROM google_members ORDER BY rowid")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn sha(text: &str) -> Vec<u8> {
        Sha256::digest(text.as_bytes()).to_vec()
    }

    #[tokio::test]
    async fn the_redirect_carries_state_and_nonce_and_no_cookie_is_set() {
        let fake = fake_google().await;
        let s = signin_server(&fake, 10, 5, |_| {});
        let r = get(&s, "/auth/google").await;
        assert_eq!(r.status, StatusCode::FOUND);
        let location = r.headers["location"].to_str().unwrap();
        let (base, query) = location.split_once('?').unwrap();
        assert_eq!(base, format!("{}/auth", fake.base));
        let value = |k| query_value(Some(query), k).unwrap();
        assert_eq!(value("client_id"), CLIENT);
        assert_eq!(value("redirect_uri"), CALLBACK);
        assert_eq!(value("response_type"), "code");
        assert_eq!(value("scope"), "openid");
        assert!(value("state").len() >= 22 && value("nonce").len() >= 22);
        assert!(
            !location.contains(SECRET),
            "the client secret went to the browser"
        );
        assert!(r.headers.get("set-cookie").is_none());

        let (state, _) = start(&s).await;
        let done = callback(&s, &state).await;
        assert!(
            done.headers.get("set-cookie").is_none(),
            "sign-in sets no cookie"
        );
    }

    #[tokio::test]
    async fn a_new_member_signs_in_and_uploads_under_the_self_service_quota() {
        let fake = fake_google().await;
        let s = signin_server(&fake, 10, 2, |_| {});
        let r = sign_in_as(&s, &fake, SUB, |_| {}).await;
        let token = token_of(&r);
        assert_eq!(r.headers["content-type"], "text/html; charset=utf-8");
        assert_eq!(r.headers["cache-control"], "no-store");
        assert!(!String::from_utf8_lossy(&r.body).contains(SECRET));

        // The token is a bearer token like any other.
        for _ in 0..2 {
            assert_eq!(upload_as(&s, &token, 100).await.status, StatusCode::CREATED);
        }
        let third = upload_as(&s, &token, 100).await;
        assert_eq!(third.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(
            third.json()["error"]
                .as_str()
                .unwrap()
                .contains("your limit is 2 at once")
        );
        // The config's member has her own, larger quota, on the same server.
        for _ in 0..3 {
            assert_eq!(
                upload_as(&s, MEMBER_TOKEN, 100).await.status,
                StatusCode::CREATED
            );
        }

        // The uploads are recorded under the member id the table holds.
        let rows = member_rows(&s);
        assert_eq!(rows.len(), 1);
        let uploaders: Vec<String> = s
            .app
            .db()
            .conn()
            .prepare("SELECT DISTINCT uploader_id FROM blobs ORDER BY 1")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(uploaders.contains(&rows[0].1) && uploaders.contains(&MEMBER_ID.to_owned()));

        // What went to Google's token endpoint: the code, intact, and the secret.
        let posts = fake.posts();
        assert_eq!(posts.len(), 1);
        for want in [
            "code=c0de%2F1",
            &format!("client_secret={SECRET}"),
            "grant_type=authorization_code",
            "redirect_uri=https%3A%2F%2Ffiles.example.org%2Fauth%2Fgoogle%2Fcallback",
        ] {
            assert!(posts[0].contains(want), "{want} missing from {}", posts[0]);
        }
    }

    #[tokio::test]
    async fn only_a_hash_of_the_sub_is_kept() {
        let fake = fake_google().await;
        let s = signin_server(&fake, 10, 5, |_| {});
        let token = token_of(&sign_in_as(&s, &fake, SUB, |_| {}).await);

        let rows = member_rows(&s);
        assert_eq!(
            (rows[0].0.clone(), rows[0].2.clone(), rows[0].3),
            (sha(SUB), sha(&token), 0)
        );
        let columns: Vec<String> = s
            .app
            .db()
            .conn()
            .prepare("SELECT name FROM pragma_table_info('google_members') ORDER BY cid")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            columns,
            ["sub_sha256", "member_id", "token_sha256", "banned"]
        );

        // Nothing Google said, and not the token, is anywhere in the files on disk.
        s.app
            .db()
            .conn()
            .execute_batch("PRAGMA wal_checkpoint(FULL)")
            .unwrap();
        for file in ["sunbird.db", "sunbird.db-wal"] {
            let bytes = std::fs::read(s.dir.0.join(file)).unwrap_or_default();
            for secret in [
                SUB,
                EMAIL,
                "Some One",
                "example.org/p.png",
                &token,
                "never-used",
            ] {
                let found = bytes.windows(secret.len()).any(|w| w == secret.as_bytes());
                assert!(!found, "{secret:?} is in {file}");
            }
        }
    }

    #[tokio::test]
    async fn a_returning_sub_keeps_its_member_id_quota_and_files_and_gets_a_new_token() {
        let fake = fake_google().await;
        let s = signin_server(&fake, 10, 2, |_| {});
        let first = token_of(&sign_in_as(&s, &fake, SUB, |_| {}).await);
        assert_eq!(upload_as(&s, &first, 100).await.status, StatusCode::CREATED);
        let id = member_rows(&s)[0].1.clone();

        let again = sign_in_as(&s, &fake, SUB, |_| {}).await;
        assert!(String::from_utf8_lossy(&again.body).contains("Welcome back"));
        let second = token_of(&again);
        assert_ne!(first, second);

        let rows = member_rows(&s);
        assert_eq!(rows.len(), 1, "a second member was made");
        assert_eq!(rows[0].1, id, "the member id changed");
        assert_eq!(rows[0].2, sha(&second));

        // The old token is dead; the new one works.
        let old = upload_as(&s, &first, 100).await;
        assert_eq!(old.status, StatusCode::UNAUTHORIZED);
        // The earlier file still counts: one more fits, two more do not.
        assert_eq!(
            upload_as(&s, &second, 100).await.status,
            StatusCode::CREATED
        );
        let over = upload_as(&s, &second, 100).await;
        assert_eq!(
            over.status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "the quota did not carry over"
        );
        let owned: i64 = s
            .app
            .db()
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM blobs WHERE uploader_id = ?",
                [&id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(owned, 2, "files are not under one member id");
    }

    #[tokio::test]
    async fn a_new_sub_past_max_members_is_refused_but_a_known_one_is_not() {
        let fake = fake_google().await;
        let s = signin_server(&fake, 2, 5, |_| {});
        token_of(&sign_in_as(&s, &fake, "sub-1", |_| {}).await);
        token_of(&sign_in_as(&s, &fake, "sub-2", |_| {}).await);

        let refused = sign_in_as(&s, &fake, "sub-3", |_| {}).await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN);
        let page = String::from_utf8_lossy(&refused.body);
        assert!(
            page.contains("reached the number of members it allows"),
            "{page}"
        );
        assert!(!page.contains("owner-token"), "a token was shown");
        assert_eq!(member_rows(&s).len(), 2);

        // Someone already a member can still come back, full or not.
        token_of(&sign_in_as(&s, &fake, "sub-1", |_| {}).await);
        assert_eq!(member_rows(&s).len(), 2);
    }

    #[tokio::test]
    async fn a_banned_sub_cannot_register_again_and_its_token_stops() {
        let fake = fake_google().await;
        let s = signin_server(&fake, 2, 5, |_| {});
        let token = token_of(&sign_in_as(&s, &fake, SUB, |_| {}).await);
        let id = member_rows(&s)[0].1.clone();
        assert_eq!(upload_as(&s, &token, 10).await.status, StatusCode::CREATED);

        // Only an admin may ban; a member's token, or none, does not.
        let ban = format!("/api/admin/ban/{id}");
        for who in ["", MEMBER_TOKEN, &token] {
            let r = send(&s, "POST", &ban, Source::bytes(b""), who).await;
            assert_eq!(r.status, StatusCode::UNAUTHORIZED, "token {who:?}");
        }
        let unknown = format!("/api/admin/ban/{}", crate::config::MemberId::mint());
        assert_eq!(
            send(&s, "POST", &unknown, Source::bytes(b""), ADMIN_TOKEN)
                .await
                .status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            send(
                &s,
                "POST",
                "/api/admin/ban/nope",
                Source::bytes(b""),
                ADMIN_TOKEN
            )
            .await
            .status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            upload_as(&s, &token, 10).await.status,
            StatusCode::CREATED,
            "refused bans changed something"
        );

        assert_eq!(
            send(&s, "POST", &ban, Source::bytes(b""), ADMIN_TOKEN)
                .await
                .status,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            upload_as(&s, &token, 10).await.status,
            StatusCode::UNAUTHORIZED,
            "a banned token uploaded"
        );

        let again = sign_in_as(&s, &fake, SUB, |_| {}).await;
        assert_eq!(again.status, StatusCode::FORBIDDEN);
        assert!(!String::from_utf8_lossy(&again.body).contains("owner-token"));
        let rows = member_rows(&s);
        assert_eq!(
            (rows.len(), rows[0].3, rows[0].2.clone()),
            (1, 1, sha(&token)),
            "the ban was undone or a token minted"
        );

        // The ban holds a place: banning must not make room for someone else.
        token_of(&sign_in_as(&s, &fake, "sub-2", |_| {}).await);
        assert_eq!(
            sign_in_as(&s, &fake, "sub-3", |_| {}).await.status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(member_rows(&s).len(), 2);
    }

    #[tokio::test]
    async fn a_replayed_state_is_refused_and_mints_nothing() {
        let fake = fake_google().await;
        let s = signin_server(&fake, 10, 5, |_| {});
        let (state, nonce) = start(&s).await;
        let token = sign(&key_a(), &good_claims(&nonce, now()));
        fake.set(|f| f.id_token = token);

        let first = callback(&s, &state).await;
        let issued = token_of(&first);
        let replay = callback(&s, &state).await;
        assert_eq!(replay.status, StatusCode::BAD_REQUEST);
        assert!(String::from_utf8_lossy(&replay.body).contains("expired or was already used"));
        assert_eq!(member_rows(&s).len(), 1);
        assert_eq!(
            member_rows(&s)[0].2,
            sha(&issued),
            "the replay replaced the token"
        );
        assert_eq!(fake.posts().len(), 1, "the replay reached Google");

        // A state we never issued gets no further than that.
        let r = callback(&s, "made-up").await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        assert_eq!(fake.posts().len(), 1);
        let r = get(&s, "/auth/google/callback?code=x").await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "no state at all");
        assert_eq!(fake.posts().len(), 1);
    }

    #[tokio::test]
    async fn a_failed_check_mints_no_token_and_registers_nobody() {
        let fake = fake_google().await;
        let s = signin_server(&fake, 10, 5, |_| {});
        let other_key = key_b();
        type Make<'a> = Box<dyn Fn(&str) -> String + 'a>;
        let cases: Vec<(&str, Make)> = vec![
            (
                "wrong signature",
                Box::new(|n| sign(&other_key, &good_claims(n, now()))),
            ),
            (
                "wrong audience",
                Box::new(|n| {
                    let mut c = good_claims(n, now());
                    c["aud"] = "other".into();
                    sign(&key_a(), &c)
                }),
            ),
            (
                "expired",
                Box::new(|n| {
                    let mut c = good_claims(n, now());
                    c["exp"] = (now() - 5).into();
                    sign(&key_a(), &c)
                }),
            ),
            (
                "wrong issuer",
                Box::new(|n| {
                    let mut c = good_claims(n, now());
                    c["iss"] = "https://evil.example".into();
                    sign(&key_a(), &c)
                }),
            ),
            (
                "another flow's nonce",
                Box::new(|_| sign(&key_a(), &good_claims("not-the-issued-one", now()))),
            ),
            (
                "stale iat",
                Box::new(|n| {
                    let mut c = good_claims(n, now());
                    c["iat"] = (now() - 7200).into();
                    sign(&key_a(), &c)
                }),
            ),
            (
                "not RS256",
                Box::new(|n| {
                    sign_with(
                        &key_a(),
                        serde_json::json!({ "alg": "none", "kid": "k1" }),
                        &good_claims(n, now()),
                    )
                }),
            ),
        ];
        for (what, make) in cases {
            let (state, nonce) = start(&s).await;
            let token = make(&nonce);
            fake.set(|f| f.id_token = token);
            let r = callback(&s, &state).await;
            assert_eq!(r.status, StatusCode::BAD_REQUEST, "{what}");
            assert!(
                !String::from_utf8_lossy(&r.body).contains("owner-token"),
                "{what}: a token was shown"
            );
            assert!(member_rows(&s).is_empty(), "{what}: someone was registered");
        }
    }

    #[tokio::test]
    async fn google_failing_or_the_person_cancelling_makes_no_token() {
        let fake = fake_google().await;
        let s = signin_server(&fake, 10, 5, |_| {});
        let (state, _) = start(&s).await;
        fake.set(|f| f.token_status = 500);
        let r = callback(&s, &state).await;
        assert_eq!(r.status, StatusCode::BAD_GATEWAY);
        assert!(
            !String::from_utf8_lossy(&r.body).contains("500"),
            "Google's error reached the person"
        );

        // Google sends `error=access_denied` and no code when the person says no.
        let (state, _) = start(&s).await;
        let r = get(
            &s,
            &format!("/auth/google/callback?error=access_denied&state={state}"),
        )
        .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        assert!(member_rows(&s).is_empty());
    }

    static CLOCK: AtomicI64 = AtomicI64::new(0);

    #[tokio::test]
    async fn the_key_set_is_cached_refreshed_on_age_and_on_an_unknown_key_but_not_hammered() {
        let fake = fake_google().await;
        CLOCK.store(now(), Ordering::SeqCst);
        let s = signin_server(&fake, 10, 5, |app| {
            app.now = || CLOCK.load(Ordering::SeqCst)
        });
        let sign_in = |sub: &'static str, pair: RsaKeyPair, kid: &'static str| {
            let (s, fake) = (&s, &fake);
            async move {
                let (state, nonce) = start(s).await;
                let mut claims = good_claims(&nonce, CLOCK.load(Ordering::SeqCst));
                claims["sub"] = sub.into();
                let token = sign_with(
                    &pair,
                    serde_json::json!({ "alg": "RS256", "kid": kid }),
                    &claims,
                );
                fake.set(|f| f.id_token = token);
                callback(s, &state).await
            }
        };

        assert_eq!(sign_in("a", key_a(), "k1").await.status, StatusCode::OK);
        assert_eq!(sign_in("b", key_a(), "k1").await.status, StatusCode::OK);
        assert_eq!(fake.jwks_gets(), 1, "fetched again though cached");

        // Google rotates. A token under the new key arrives at once: the cache is
        // seconds old, so the server does not fetch on a stranger's say-so.
        fake.set(|f| f.jwks = jwks(&[("k2", &key_b())]));
        assert_eq!(
            sign_in("c", key_b(), "k2").await.status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(fake.jwks_gets(), 1, "a forged kid made the server fetch");

        // A little later the same token is worth a refetch.
        CLOCK.fetch_add(JWKS_MIN_REFETCH, Ordering::SeqCst);
        assert_eq!(sign_in("c", key_b(), "k2").await.status, StatusCode::OK);
        assert_eq!(fake.jwks_gets(), 2);

        // And an old cache is replaced even for a key it knows.
        CLOCK.fetch_add(JWKS_MAX_AGE, Ordering::SeqCst);
        assert_eq!(sign_in("d", key_b(), "k2").await.status, StatusCode::OK);
        assert_eq!(fake.jwks_gets(), 3);
    }

    #[tokio::test]
    async fn an_admin_minted_token_uploads_exactly_as_before_through_the_one_path() {
        let fake = fake_google().await;
        let s = signin_server(&fake, 10, 5, |_| {});
        let google = token_of(&sign_in_as(&s, &fake, SUB, |_| {}).await);

        let theirs = upload_as(&s, MEMBER_TOKEN, 100).await;
        let ours = upload_as(&s, &google, 100).await;
        for r in [&theirs, &ours] {
            assert_eq!(r.status, StatusCode::CREATED);
            let mut keys: Vec<_> = r.json().as_object().unwrap().keys().cloned().collect();
            keys.sort();
            assert_eq!(
                keys,
                ["id", "ownerToken"],
                "the two answers differ in shape"
            );
        }
        // Without a token, or with junk, both fail the same way.
        for who in ["", "junk"] {
            let r = send(&s, "POST", &live_path(), Source::bytes(b"x"), who).await;
            assert_eq!(r.status, StatusCode::UNAUTHORIZED);
            assert_eq!(r.json()["error"], "a member's upload token is required");
        }

        // The upload code has no branch on how a token was made: it asks
        // `App::member` and uses what comes back. This reads the source, so a
        // later "if google" in either function fails here.
        let source = std::fs::read_to_string("src/http.rs").unwrap();
        let start = source.find("async fn upload<B>").unwrap();
        let end = source.find("/// Refuses with 507").unwrap();
        let handler = source[start..end].to_lowercase();
        for word in ["google", "signin", "self_service", "registration", "banned"] {
            assert!(
                !handler.contains(word),
                "the upload handler mentions {word}"
            );
        }
        // And the Authorization header is read in one place for the whole server.
        let server = &source[..source.find("#[cfg(test)]").unwrap()];
        assert_eq!(
            server.matches("header::AUTHORIZATION").count(),
            1,
            "a second reader of the Authorization header"
        );
    }

    #[tokio::test]
    async fn without_the_config_section_sign_in_is_off_and_stored_tokens_do_nothing() {
        let fake = fake_google().await;
        let on = signin_server(&fake, 10, 5, |_| {});
        let token = token_of(&sign_in_as(&on, &fake, SUB, |_| {}).await);
        // The same database, restarted without the google_signin section.
        let off = restart(on, test_config(), |_| {});
        for path in ["/auth/google", "/auth/google/callback?code=x&state=y"] {
            let r = get(&off, path).await;
            assert_eq!(r.status, StatusCode::NOT_FOUND, "{path}");
            assert!(String::from_utf8_lossy(&r.body).contains("not turned on"));
        }
        assert_eq!(
            upload_as(&off, &token, 10).await.status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            upload_as(&off, MEMBER_TOKEN, 10).await.status,
            StatusCode::CREATED
        );
    }

    #[tokio::test]
    async fn sign_in_requests_share_the_per_address_read_limit() {
        let fake = fake_google().await;
        let endpoints = fake.endpoints();
        let config = config(vec![], |c| {
            c["read_rate"] = serde_json::json!({ "requests": 3, "seconds": 3600 });
            c["google_signin"] = serde_json::json!({
                "client_id": CLIENT, "client_secret": SECRET, "redirect_uri": CALLBACK,
                "max_members": 10, "max_active_bytes": 1, "max_active_files": 1, "max_bytes_per_week": 1,
            });
        });
        let s = server_config(config, |app| app.signin.endpoints = endpoints);
        let mut statuses = vec![];
        for path in [
            "/auth/google",
            "/auth/google",
            "/auth/google/callback?state=x",
            "/auth/google",
        ] {
            statuses.push(get(&s, path).await.status);
        }
        assert_eq!(
            statuses,
            [
                StatusCode::FOUND,
                StatusCode::FOUND,
                StatusCode::BAD_REQUEST,
                StatusCode::TOO_MANY_REQUESTS
            ]
        );
        // Another address has its own allowance.
        let other = send_from(
            &s,
            "192.0.2.7",
            &[],
            "GET",
            "/auth/google",
            Source::bytes(b""),
            "",
        )
        .await;
        assert_eq!(other.status, StatusCode::FOUND);
    }

    #[tokio::test]
    async fn an_admin_delete_log_names_a_google_member_as_one() {
        capture_logs();
        let fake = fake_google().await;
        let s = signin_server(&fake, 10, 5, |_| {});
        let token = token_of(&sign_in_as(&s, &fake, SUB, |_| {}).await);
        let id = member_rows(&s)[0].1.clone();
        let up = upload_as(&s, &token, 10).await.json();
        let file = up["id"].as_str().unwrap();
        let r = send(
            &s,
            "DELETE",
            &format!("/api/admin/{file}"),
            Source::bytes(b""),
            ADMIN_TOKEN,
        )
        .await;
        assert_eq!(r.status, StatusCode::NO_CONTENT);
        let lines = logged(file);
        assert!(
            lines
                .iter()
                .any(|(_, l)| l.contains(&format!("member {id} (signed in with Google)"))),
            "{lines:?}"
        );
    }
}
