//! Error mapping tests.

#![allow(clippy::expect_used)]

use super::*;

#[test]
fn every_kind_maps_to_the_documented_status() {
    let cases: Vec<(Error, u16)> = vec![
        (Error::Config("x".into()), 500),
        (Error::Signature("x".into()), 401),
        (Error::InvalidRequest("x".into()), 400),
        (Error::PayloadTooLarge { limit: 1 }, 413),
        (
            Error::ShopifyApi {
                status: 500,
                body: String::new(),
            },
            502,
        ),
        (Error::GraphQl(vec!["x".into()]), 502),
        (Error::Throttled { retries: 3 }, 503),
        (Error::UnexpectedResponse("x".into()), 502),
        (Error::InProgress("w".into()), 409),
        (Error::StateMismatch, 403),
        (
            Error::ScopeMismatch {
                missing: vec!["write_orders".into()],
            },
            403,
        ),
        (Error::NotInstalled("s".into()), 401),
        (Error::Reauthorize("s".into()), 401),
        (Error::OAuthDisabled, 404),
        (Error::Store("x".into()), 500),
        (Error::MissingRuntime, 503),
    ];
    for (err, status) in cases {
        assert_eq!(err.status().as_u16(), status, "{err}");
        assert_eq!(err.to_autumn_error().status().as_u16(), status, "{err}");
    }
}

#[test]
fn json_errors_are_bad_requests() {
    let err: Error = serde_json::from_str::<serde_json::Value>("nope")
        .map_err(Error::from)
        .expect_err("bad json");
    assert_eq!(err.kind(), ErrorKind::Json);
    assert_eq!(err.status().as_u16(), 400);
}

#[test]
fn messages_name_the_problem() {
    assert_eq!(
        Error::GraphQl(vec!["a".into(), "b".into()]).to_string(),
        "shopify graphql error: a; b"
    );
    assert_eq!(
        Error::ScopeMismatch {
            missing: vec!["read_a".into(), "write_b".into()]
        }
        .to_string(),
        "shopify scopes not granted: read_a,write_b"
    );
}
