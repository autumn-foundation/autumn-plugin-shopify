//! Health indicator tests against a local stub.

#![allow(clippy::expect_used)]

use autumn_web::actuator::HealthStatus;
use serde_json::json;

use super::*;
use crate::test_support::{SHOP, Stub, StubResponse};
use crate::types::{ApiVersion, ShopDomain};

fn client(stub: &Stub) -> ShopifyClient {
    ShopifyClient::new(
        ShopDomain::parse(SHOP).expect("shop"),
        ApiVersion::default(),
        "shpat_health",
    )
    .expect("client")
    .with_base_url(stub.base_url.clone())
}

#[tokio::test]
async fn a_working_token_reports_up_with_the_shop_name() {
    let stub = Stub::start(vec![StubResponse::json(
        200,
        &json!({"data": {"shop": {"name": "Test Store", "myshopifyDomain": SHOP}}}),
    )])
    .await;
    let output = indicator(&client(&stub)).check().await;
    assert_eq!(output.status, HealthStatus::Up);
    assert_eq!(output.details.get("shop"), Some(&json!("Test Store")));
}

#[tokio::test]
async fn a_failing_token_reports_down_with_the_error() {
    let stub = Stub::start(vec![StubResponse::text(
        401,
        "Invalid API key or access token",
    )])
    .await;
    let output = ShopifyHealth::new(client(&stub)).check().await;
    assert_eq!(output.status, HealthStatus::Down);
    let error = output.details.get("error").expect("error detail");
    assert!(error.as_str().expect("string").contains("401"), "{error}");
    assert!(!error.to_string().contains("shpat_health"));
}
