//! HMAC-SHA256 verification for Shopify webhooks and OAuth redirects.
//!
//! Shopify signs two things with the app client secret:
//!
//! - Webhooks: the raw body. The base64 digest travels in
//!   `X-Shopify-Hmac-Sha256`. See [`verify_webhook`].
//! - OAuth redirects: the decoded query pairs without `hmac`, sorted by
//!   key. The hex digest travels in the `hmac` parameter. See
//!   [`verify_query`].
//!
//! Both checks refuse the request when a value is missing or malformed, and
//! compare in constant time. A [`SecretSet`] holds the current secret and,
//! during rotation, the previous one.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

/// Header that carries the base64 webhook HMAC.
pub const HMAC_HEADER: &str = "x-shopify-hmac-sha256";

/// The app client secret, plus the previous one during rotation.
///
/// `Debug` redacts both values. App code cannot read them back:
///
/// ```compile_fail
/// let set = autumn_plugin_shopify::SecretSet::new("s", None).unwrap();
/// let _ = set.current();
/// ```
#[derive(Clone)]
pub struct SecretSet {
    current: String,
    previous: Option<String>,
}

impl std::fmt::Debug for SecretSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretSet")
            .field("current", &"<redacted>")
            .field("previous", &self.previous.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl SecretSet {
    /// Make a set from the current secret and an optional previous one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the current secret is blank.
    pub fn new(current: impl Into<String>, previous: Option<String>) -> Result<Self> {
        let current = current.into();
        if current.trim().is_empty() {
            return Err(Error::Config("the client secret is blank".to_owned()));
        }
        let previous = previous.filter(|secret| !secret.trim().is_empty());
        Ok(Self { current, previous })
    }

    /// The secrets to try, current first.
    fn iter(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.current.as_str()).chain(self.previous.as_deref())
    }

    /// The current secret. Never log it.
    #[must_use]
    pub(crate) fn current(&self) -> &str {
        &self.current
    }
}

/// Sign a webhook body: base64 HMAC-SHA256 with `secret`.
///
/// Use it in tests to make deliveries that the plugin accepts.
#[must_use]
pub fn sign_webhook(secret: &str, body: &[u8]) -> String {
    mac(secret, body).map_or_else(String::new, |mac| {
        BASE64.encode(mac.finalize().into_bytes())
    })
}

/// Verify a webhook HMAC header against the raw body.
///
/// # Errors
///
/// Returns [`Error::Signature`] when the header is missing, is not
/// base64, or matches no secret in `secrets`.
pub fn verify_webhook(secrets: &SecretSet, header: Option<&str>, body: &[u8]) -> Result<()> {
    let header = header.ok_or_else(|| Error::Signature(format!("missing {HMAC_HEADER} header")))?;
    let expected = BASE64
        .decode(header.trim())
        .map_err(|_| Error::Signature(format!("{HMAC_HEADER} is not base64")))?;
    verify_digest(secrets, body, &expected)
}

/// Sign OAuth query parameters: hex HMAC-SHA256 of the canonical message.
///
/// `params` are decoded `(key, value)` pairs. The message leaves out
/// `hmac`. Use it in tests to make callback URLs.
#[must_use]
pub fn sign_query(secret: &str, params: &[(String, String)]) -> String {
    mac(secret, query_message(params).as_bytes())
        .map_or_else(String::new, |mac| hex::encode(mac.finalize().into_bytes()))
}

/// Verify the `hmac` parameter of an OAuth redirect.
///
/// `params` are the decoded query pairs, `hmac` included.
///
/// # Errors
///
/// Returns [`Error::Signature`] when `hmac` is missing, is not hex, or
/// matches no secret in `secrets`.
pub fn verify_query(secrets: &SecretSet, params: &[(String, String)]) -> Result<()> {
    let hmac = params
        .iter()
        .find(|(key, _)| key == "hmac")
        .map(|(_, value)| value.as_str())
        .ok_or_else(|| Error::Signature("missing hmac parameter".to_owned()))?;
    let expected =
        hex::decode(hmac).map_err(|_| Error::Signature("hmac parameter is not hex".to_owned()))?;
    verify_digest(secrets, query_message(params).as_bytes(), &expected)
}

/// Build the message Shopify signs for a query.
///
/// Drop `hmac`, sort the decoded pairs by key (then value), and join
/// `key=value` with `&`. This is the rule on shopify.dev
/// ("Authorization code grant", 2026-10).
#[must_use]
pub fn query_message(params: &[(String, String)]) -> String {
    let mut pairs: Vec<&(String, String)> =
        params.iter().filter(|(key, _)| key != "hmac").collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// The HMAC-SHA256 of `message` under `secret`.
///
/// HMAC accepts a key of any length, so `None` does not occur. The callers
/// still fail closed on `None`.
fn mac(secret: &str, message: &[u8]) -> Option<HmacSha256> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(message);
    Some(mac)
}

/// Compare `expected` to the HMAC of `message` under each secret, in
/// constant time.
fn verify_digest(secrets: &SecretSet, message: &[u8], expected: &[u8]) -> Result<()> {
    let mut matched = false;
    for secret in secrets.iter() {
        // `verify_slice` compares in constant time. Try every secret, so
        // that the time does not show which secret matched.
        matched |= mac(secret, message).is_some_and(|mac| mac.verify_slice(expected).is_ok());
    }
    if matched {
        Ok(())
    } else {
        Err(Error::Signature("hmac does not match".to_owned()))
    }
}

#[cfg(test)]
mod tests;
