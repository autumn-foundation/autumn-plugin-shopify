//! Admin client tests against a local stub. No network, no Shopify.

#![allow(clippy::expect_used, clippy::panic)]

use std::time::Duration;

use serde_json::json;

use super::*;
use crate::error::ErrorKind;
use crate::test_support::{Stub, StubResponse};

fn shop() -> ShopDomain {
    ShopDomain::parse("my-store.myshopify.com").expect("valid shop")
}

fn fast_retry(max_retries: u32) -> RetryPolicy {
    RetryPolicy {
        max_retries,
        max_wait: Duration::from_millis(5),
    }
}

fn client(stub: &Stub) -> ShopifyClient {
    ShopifyClient::new(shop(), ApiVersion::default(), "shpat_secret_token")
        .expect("client builds")
        .with_base_url(format!("{}/", stub.base_url))
        .with_retry(fast_retry(2))
}

fn throttled(requested: f64, available: f64, restore: f64) -> serde_json::Value {
    json!({
        "errors": [{"message": "Throttled", "extensions": {"code": "THROTTLED"}}],
        "extensions": {"cost": {
            "requestedQueryCost": requested,
            "actualQueryCost": null,
            "throttleStatus": {
                "maximumAvailable": 1000.0,
                "currentlyAvailable": available,
                "restoreRate": restore
            }
        }}
    })
}

#[test]
fn new_rejects_a_blank_token() {
    let err = ShopifyClient::new(shop(), ApiVersion::default(), " ").expect_err("blank token");
    assert_eq!(err.kind(), ErrorKind::Config);
}

#[test]
fn endpoint_defaults_to_the_shop_host() {
    let client = ShopifyClient::new(shop(), ApiVersion::default(), "t").expect("client builds");
    assert_eq!(
        client.endpoint(),
        "https://my-store.myshopify.com/admin/api/2026-10/graphql.json"
    );
    assert_eq!(client.shop().as_str(), "my-store.myshopify.com");
    assert_eq!(client.api_version().as_str(), "2026-10");
}

#[test]
fn debug_redacts_the_token() {
    let client = ShopifyClient::new(shop(), ApiVersion::default(), "shpat_secret_token")
        .expect("client builds");
    let debug = format!("{client:?}");
    assert!(!debug.contains("shpat_secret_token"), "{debug}");
}

#[tokio::test]
async fn graphql_posts_query_and_returns_data() {
    let stub = Stub::start(vec![StubResponse::json(
        200,
        &json!({"data": {"shop": {"name": "Test"}}}),
    )])
    .await;
    let data = client(&stub)
        .graphql("query { shop { name } }", json!({"a": 1}))
        .await
        .expect("query works");
    assert_eq!(data, json!({"shop": {"name": "Test"}}));

    let seen = stub.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].path, "/admin/api/2026-10/graphql.json");
    assert_eq!(
        seen[0].header(ACCESS_TOKEN_HEADER),
        Some("shpat_secret_token")
    );
    assert_eq!(
        seen[0].json(),
        json!({"query": "query { shop { name } }", "variables": {"a": 1}})
    );
}

#[tokio::test]
async fn graphql_errors_surface_their_messages() {
    let stub = Stub::start(vec![StubResponse::json(
        200,
        &json!({"errors": [{"message": "Field 'x' doesn't exist"}, {"message": "second"}]}),
    )])
    .await;
    let err = client(&stub)
        .graphql("query { x }", json!({}))
        .await
        .expect_err("graphql error");
    match err {
        Error::GraphQl(messages) => {
            assert_eq!(messages, vec!["Field 'x' doesn't exist", "second"]);
        }
        other => panic!("expected GraphQl, got {other:?}"),
    }
}

#[tokio::test]
async fn http_errors_keep_status_and_truncate_body() {
    let long = "x".repeat(2_000);
    let stub = Stub::start(vec![StubResponse::text(401, &long)]).await;
    let err = client(&stub)
        .graphql("query { shop { name } }", json!({}))
        .await
        .expect_err("401");
    match &err {
        Error::ShopifyApi { status, body } => {
            assert_eq!(*status, 401);
            assert_eq!(body.chars().count(), MAX_ERROR_BODY_CHARS);
        }
        other => panic!("expected ShopifyApi, got {other:?}"),
    }
    assert!(!err.to_string().contains("shpat_secret_token"));
    assert_eq!(stub.requests().len(), 1, "a 401 does not retry");
}

#[tokio::test]
async fn server_errors_do_not_retry() {
    let stub = Stub::start(vec![StubResponse::text(503, "down")]).await;
    let err = client(&stub)
        .graphql("mutation { x }", json!({}))
        .await
        .expect_err("503");
    assert_eq!(err.kind(), ErrorKind::ShopifyApi);
    assert_eq!(stub.requests().len(), 1);
}

#[tokio::test]
async fn throttled_graphql_retries_then_succeeds() {
    let stub = Stub::start(vec![
        StubResponse::json(200, &throttled(100.0, 10.0, 50.0)),
        StubResponse::json(200, &json!({"data": {"ok": true}})),
    ])
    .await;
    let data = client(&stub)
        .graphql("query { ok }", json!({}))
        .await
        .expect("retry works");
    assert_eq!(data, json!({"ok": true}));
    assert_eq!(stub.requests().len(), 2);
}

#[tokio::test]
async fn http_429_retries_then_succeeds() {
    let stub = Stub::start(vec![
        StubResponse::text(429, "slow down").header("retry-after", "0.001"),
        StubResponse::json(200, &json!({"data": {"ok": true}})),
    ])
    .await;
    client(&stub)
        .graphql("query { ok }", json!({}))
        .await
        .expect("retry works");
    assert_eq!(stub.requests().len(), 2);
}

#[tokio::test]
async fn throttle_retries_run_out() {
    let stub = Stub::start(vec![
        StubResponse::json(200, &throttled(100.0, 0.0, 50.0)),
        StubResponse::json(200, &throttled(100.0, 0.0, 50.0)),
        StubResponse::json(200, &throttled(100.0, 0.0, 50.0)),
    ])
    .await;
    let err = client(&stub)
        .graphql("query { ok }", json!({}))
        .await
        .expect_err("retries run out");
    match err {
        Error::Throttled { retries } => assert_eq!(retries, 2),
        other => panic!("expected Throttled, got {other:?}"),
    }
    assert_eq!(stub.requests().len(), 3);
}

#[tokio::test]
async fn zero_retries_fail_on_the_first_throttle() {
    let stub = Stub::start(vec![StubResponse::text(429, "slow down")]).await;
    let err = client(&stub)
        .with_retry(fast_retry(0))
        .graphql("query { ok }", json!({}))
        .await
        .expect_err("no retries");
    assert_eq!(err.kind(), ErrorKind::Throttled);
    assert_eq!(stub.requests().len(), 1);
}

#[tokio::test]
async fn query_deserializes_data() {
    #[derive(Debug, serde::Deserialize)]
    struct Data {
        count: u32,
    }
    let stub = Stub::start(vec![
        StubResponse::json(200, &json!({"data": {"count": 7}})),
        StubResponse::json(200, &json!({"data": {"count": "seven"}})),
    ])
    .await;
    let data: Data = client(&stub)
        .query("query { count }", json!({}))
        .await
        .expect("typed query");
    assert_eq!(data.count, 7);
    let err = client(&stub)
        .query::<Data>("query { count }", json!({}))
        .await
        .expect_err("wrong shape");
    assert_eq!(err.kind(), ErrorKind::ShopifyApi);
}

#[tokio::test]
async fn missing_data_is_an_error() {
    let stub = Stub::start(vec![StubResponse::json(200, &json!({}))]).await;
    let err = client(&stub)
        .graphql("query { x }", json!({}))
        .await
        .expect_err("no data");
    assert_eq!(err.kind(), ErrorKind::ShopifyApi);
}

#[tokio::test]
async fn non_json_success_is_an_error() {
    let stub = Stub::start(vec![StubResponse::text(200, "<html>")]).await;
    let err = client(&stub)
        .graphql("query { x }", json!({}))
        .await
        .expect_err("not json");
    assert_eq!(err.kind(), ErrorKind::ShopifyApi);
}

#[tokio::test]
async fn shop_info_reads_name_and_domain() {
    let stub = Stub::start(vec![StubResponse::json(
        200,
        &json!({"data": {"shop": {"name": "Test Store", "myshopifyDomain": "my-store.myshopify.com"}}}),
    )])
    .await;
    let info = client(&stub).shop_info().await.expect("shop info");
    assert_eq!(info.name, "Test Store");
    assert_eq!(info.myshopify_domain, "my-store.myshopify.com");
}

#[tokio::test]
async fn subscribe_webhook_sends_enum_topic_and_returns_id() {
    let stub = Stub::start(vec![StubResponse::json(
        200,
        &json!({"data": {"webhookSubscriptionCreate": {
            "webhookSubscription": {"id": "gid://shopify/WebhookSubscription/1"},
            "userErrors": []
        }}}),
    )])
    .await;
    let topic = Topic::parse("orders/create").expect("topic");
    let id = client(&stub)
        .subscribe_webhook(&topic, "https://app.example.com/shopify/webhooks")
        .await
        .expect("subscribed");
    assert_eq!(id, "gid://shopify/WebhookSubscription/1");
    let body = stub.requests()[0].json();
    assert_eq!(body["variables"]["topic"], "ORDERS_CREATE");
    assert_eq!(
        body["variables"]["webhookSubscription"]["uri"],
        "https://app.example.com/shopify/webhooks"
    );
    assert!(
        body["query"]
            .as_str()
            .expect("query")
            .contains("webhookSubscriptionCreate")
    );
}

#[tokio::test]
async fn subscribe_webhook_surfaces_user_errors() {
    let stub = Stub::start(vec![StubResponse::json(
        200,
        &json!({"data": {"webhookSubscriptionCreate": {
            "webhookSubscription": null,
            "userErrors": [{"field": ["uri"], "message": "Address is invalid"}]
        }}}),
    )])
    .await;
    let topic = Topic::parse("orders/create").expect("topic");
    let err = client(&stub)
        .subscribe_webhook(&topic, "nope")
        .await
        .expect_err("user error");
    match err {
        Error::GraphQl(messages) => assert_eq!(messages, vec!["Address is invalid"]),
        other => panic!("expected GraphQl, got {other:?}"),
    }
}

#[test]
fn throttle_wait_uses_cost_and_restore_rate() {
    assert_eq!(
        throttle_wait(&throttled(100.0, 50.0, 50.0)),
        Some(Duration::from_secs(1))
    );
    assert_eq!(
        throttle_wait(&throttled(300.0, 50.0, 100.0)),
        Some(Duration::from_millis(2_500))
    );
    // Enough capacity already: a short floor wait, not zero.
    assert_eq!(
        throttle_wait(&throttled(10.0, 50.0, 50.0)),
        Some(Duration::from_millis(100))
    );
}

#[test]
fn throttle_wait_defaults_to_one_second() {
    let bare = json!({"errors": [{"message": "Throttled", "extensions": {"code": "THROTTLED"}}]});
    assert_eq!(throttle_wait(&bare), Some(Duration::from_secs(1)));
    let zero_rate = throttled(100.0, 0.0, 0.0);
    assert_eq!(throttle_wait(&zero_rate), Some(Duration::from_secs(1)));
}

#[test]
fn throttle_wait_ignores_other_errors() {
    assert_eq!(throttle_wait(&json!({"data": {}})), None);
    assert_eq!(
        throttle_wait(&json!({"errors": [{"message": "bad", "extensions": {"code": "OTHER"}}]})),
        None
    );
}

#[test]
fn retry_after_reads_seconds() {
    let mut headers = reqwest::header::HeaderMap::new();
    assert_eq!(retry_after(&headers), Duration::from_secs(1));
    headers.insert("retry-after", "2.5".parse().expect("header"));
    assert_eq!(retry_after(&headers), Duration::from_millis(2_500));
    headers.insert("retry-after", "soon".parse().expect("header"));
    assert_eq!(retry_after(&headers), Duration::from_secs(1));
    headers.insert("retry-after", "-3".parse().expect("header"));
    assert_eq!(retry_after(&headers), Duration::from_secs(1));
}
