//! Token store tests.

#![allow(clippy::expect_used)]

use super::*;

fn shop(name: &str) -> ShopDomain {
    ShopDomain::parse(&format!("{name}.myshopify.com")).expect("valid shop")
}

fn expiring(expires_at: i64, refresh_expires_at: i64) -> ShopToken {
    ShopToken {
        access_token: "shpat_a".into(),
        scope: "read_orders,write_products".into(),
        expires_at: Some(expires_at),
        refresh_token: Some("shprt_r".into()),
        refresh_token_expires_at: Some(refresh_expires_at),
    }
}

#[test]
fn non_expiring_tokens_never_need_refresh() {
    let token = ShopToken::non_expiring("shpat_a", "read_orders");
    assert!(!token.needs_refresh(i64::MAX - 100, 60));
    assert!(!token.can_refresh(0));
}

#[test]
fn needs_refresh_uses_the_margin() {
    let token = expiring(1_000, 10_000);
    assert!(!token.needs_refresh(939, 60));
    assert!(token.needs_refresh(940, 60));
    assert!(token.needs_refresh(2_000, 60));
}

#[test]
fn can_refresh_checks_refresh_expiry() {
    let token = expiring(1_000, 10_000);
    assert!(token.can_refresh(9_999));
    assert!(!token.can_refresh(10_000));
    let mut no_expiry = token.clone();
    no_expiry.refresh_token_expires_at = None;
    assert!(no_expiry.can_refresh(i64::MAX));
    let mut no_refresh = token;
    no_refresh.refresh_token = None;
    assert!(!no_refresh.can_refresh(0));
}

#[test]
fn scopes_split_on_commas() {
    let token = ShopToken::non_expiring("t", "read_orders, write_products,,");
    assert_eq!(token.scopes(), vec!["read_orders", "write_products"]);
}

#[test]
fn debug_redacts_tokens() {
    let debug = format!("{:?}", expiring(1, 2));
    assert!(!debug.contains("shpat_a"), "{debug}");
    assert!(!debug.contains("shprt_r"), "{debug}");
}

#[test]
fn tokens_round_trip_through_serde() {
    let token = expiring(1, 2);
    let json = serde_json::to_string(&token).expect("serializes");
    let back: ShopToken = serde_json::from_str(&json).expect("parses");
    assert_eq!(back, token);
}

#[tokio::test]
async fn in_memory_store_puts_gets_and_deletes() {
    let store = InMemoryTokenStore::new();
    let a = shop("a");
    let b = shop("b");
    assert!(store.is_empty());
    assert!(store.get(&a).await.expect("get").is_none());

    store
        .put(&a, ShopToken::non_expiring("one", "read_orders"))
        .await
        .expect("put");
    store
        .put(&a, ShopToken::non_expiring("two", "read_orders"))
        .await
        .expect("replace");
    store
        .put(&b, ShopToken::non_expiring("three", "read_orders"))
        .await
        .expect("put");
    assert_eq!(store.len(), 2);
    assert_eq!(
        store
            .get(&a)
            .await
            .expect("get")
            .expect("present")
            .access_token,
        "two"
    );

    store.delete(&a).await.expect("delete");
    store.delete(&a).await.expect("delete twice is fine");
    assert!(store.get(&a).await.expect("get").is_none());
    assert_eq!(store.len(), 1);
}
