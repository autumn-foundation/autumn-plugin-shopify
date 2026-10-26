//! HMAC tests: fixed vectors, tampering, rotation, malformed input.

#![allow(clippy::expect_used)]

use super::*;
use crate::error::ErrorKind;
use proptest::prelude::*;

/// Python `hmac` reference: base64(HMAC-SHA256("hush", `{"id":1}`)).
const BODY: &[u8] = br#"{"id":1}"#;
const BODY_HMAC_HUSH: &str = "VnKUjZsLuN5iZWjn5EntcBVCF9kMN43LglzCE1/GSeY=";
const BODY_HMAC_OLD: &str = "qXaXF9OTa4KVT4q1mXmUiw6VbACWU+C0YHPPj4R7xN4=";

/// The OAuth example from Shopify's docs (secret `hush`).
const DOC_HMAC: &str = "700e2dadb827fcc8609e9d5ce208b2e9cdaab9df07390d2cbca10d7c328fc4bf";

fn secrets() -> SecretSet {
    SecretSet::new("hush", None).expect("secret set")
}

fn doc_params(hmac: &str) -> Vec<(String, String)> {
    vec![
        ("shop".into(), "some-shop.myshopify.com".into()),
        ("code".into(), "0907a61c0c8d55e99db179b68161bc00".into()),
        ("hmac".into(), hmac.into()),
        ("timestamp".into(), "1337178173".into()),
        ("state".into(), "0.6784241404160823".into()),
    ]
}

#[test]
fn sign_webhook_matches_reference_vector() {
    assert_eq!(sign_webhook("hush", BODY), BODY_HMAC_HUSH);
}

#[test]
fn verify_webhook_accepts_reference_vector() {
    verify_webhook(&secrets(), Some(BODY_HMAC_HUSH), BODY).expect("valid hmac");
}

#[test]
fn verify_webhook_trims_header_whitespace() {
    verify_webhook(&secrets(), Some(&format!(" {BODY_HMAC_HUSH} ")), BODY).expect("valid hmac");
}

#[test]
fn verify_webhook_rejects_tampered_body() {
    let err = verify_webhook(&secrets(), Some(BODY_HMAC_HUSH), br#"{"id": 1}"#)
        .expect_err("re-encoded body fails");
    assert_eq!(err.kind(), ErrorKind::Signature);
}

#[test]
fn verify_webhook_rejects_missing_header() {
    let err = verify_webhook(&secrets(), None, BODY).expect_err("missing header");
    assert_eq!(err.kind(), ErrorKind::Signature);
}

#[test]
fn verify_webhook_rejects_malformed_header() {
    for bad in ["", "not base64!!", "sha256=abc", &hex::encode([0u8; 32])] {
        let err = verify_webhook(&secrets(), Some(bad), BODY).expect_err(bad);
        assert_eq!(err.kind(), ErrorKind::Signature, "{bad:?}");
    }
}

#[test]
fn verify_webhook_rejects_wrong_secret() {
    let other = SecretSet::new("other", None).expect("secret set");
    verify_webhook(&other, Some(BODY_HMAC_HUSH), BODY).expect_err("wrong secret");
}

#[test]
fn verify_webhook_accepts_previous_secret_during_rotation() {
    let rotating = SecretSet::new("hush", Some("old-secret".into())).expect("secret set");
    verify_webhook(&rotating, Some(BODY_HMAC_OLD), BODY).expect("previous secret");
    verify_webhook(&rotating, Some(BODY_HMAC_HUSH), BODY).expect("current secret");
    verify_webhook(&secrets(), Some(BODY_HMAC_OLD), BODY).expect_err("no previous secret");
}

#[test]
fn secret_set_rejects_blank_secret_and_ignores_blank_previous() {
    SecretSet::new("  ", None).expect_err("blank secret");
    let set = SecretSet::new("hush", Some(" ".into())).expect("blank previous is dropped");
    assert!(set.previous.is_none());
    assert_eq!(set.current(), "hush");
}

#[test]
fn secret_set_debug_redacts() {
    let set = SecretSet::new("hush", Some("old-secret".into())).expect("secret set");
    let debug = format!("{set:?}");
    assert!(!debug.contains("hush"), "{debug}");
    assert!(!debug.contains("old-secret"), "{debug}");
}

#[test]
fn query_message_sorts_and_drops_hmac() {
    assert_eq!(
        query_message(&doc_params(DOC_HMAC)),
        "code=0907a61c0c8d55e99db179b68161bc00&shop=some-shop.myshopify.com&state=0.6784241404160823&timestamp=1337178173"
    );
}

#[test]
fn query_message_keeps_decoded_values_and_other_params() {
    let params = vec![
        ("host".to_owned(), "YWRtaW4=".to_owned()),
        ("signature".to_owned(), "kept".to_owned()),
        ("hmac".to_owned(), "dropped".to_owned()),
        ("a".to_owned(), "x y".to_owned()),
    ];
    assert_eq!(query_message(&params), "a=x y&host=YWRtaW4=&signature=kept");
}

#[test]
fn verify_query_accepts_shopify_doc_example() {
    verify_query(&secrets(), &doc_params(DOC_HMAC)).expect("doc example verifies");
    assert_eq!(sign_query("hush", &doc_params("ignored")), DOC_HMAC);
}

#[test]
fn verify_query_accepts_uppercase_hex() {
    verify_query(&secrets(), &doc_params(&DOC_HMAC.to_ascii_uppercase())).expect("uppercase hex");
}

#[test]
fn verify_query_rejects_tampered_params() {
    let mut params = doc_params(DOC_HMAC);
    params[0].1 = "evil-shop.myshopify.com".into();
    let err = verify_query(&secrets(), &params).expect_err("tampered shop");
    assert_eq!(err.kind(), ErrorKind::Signature);
}

#[test]
fn verify_query_rejects_missing_or_malformed_hmac() {
    let mut params = doc_params(DOC_HMAC);
    params.retain(|(k, _)| k != "hmac");
    verify_query(&secrets(), &params).expect_err("missing hmac");
    verify_query(&secrets(), &doc_params("zz")).expect_err("non-hex hmac");
}

proptest! {
    #[test]
    fn signed_webhooks_always_verify(secret in "[ -~]{1,40}", body in proptest::collection::vec(any::<u8>(), 0..512)) {
        prop_assume!(!secret.trim().is_empty());
        let set = SecretSet::new(secret.clone(), None).expect("secret set");
        let header = sign_webhook(&secret, &body);
        prop_assert!(verify_webhook(&set, Some(&header), &body).is_ok());
    }

    #[test]
    fn a_flipped_body_bit_never_verifies(body in proptest::collection::vec(any::<u8>(), 1..256), index in any::<usize>(), bit in 0u8..8) {
        let set = secrets();
        let header = sign_webhook("hush", &body);
        let mut tampered = body;
        let at = index % tampered.len();
        tampered[at] ^= 1 << bit;
        prop_assert!(verify_webhook(&set, Some(&header), &tampered).is_err());
    }

    #[test]
    fn signed_queries_always_verify(pairs in proptest::collection::vec(("[a-z_]{1,8}", "[ -~]{0,16}"), 0..6)) {
        let mut params: Vec<(String, String)> = pairs;
        params.retain(|(k, _)| k != "hmac");
        let hmac = sign_query("hush", &params);
        params.push(("hmac".into(), hmac));
        prop_assert!(verify_query(&secrets(), &params).is_ok());
    }
}
