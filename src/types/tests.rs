//! Domain type tests: shop domains, topics, API versions.

#![allow(clippy::expect_used)]

use super::*;
use proptest::prelude::*;

#[test]
fn shop_domain_accepts_and_lowercases() {
    let shop = ShopDomain::parse("My-Store.myshopify.com").expect("valid shop");
    assert_eq!(shop.as_str(), "my-store.myshopify.com");
    assert_eq!(shop.to_string(), "my-store.myshopify.com");
}

#[test]
fn shop_domain_does_not_trim() {
    ShopDomain::parse(" store1.myshopify.com").expect_err("leading space");
    ShopDomain::parse("store1.myshopify.com ").expect_err("trailing space");
}

#[test]
fn shop_domain_rejects_hostile_values() {
    for bad in [
        "",
        "myshopify.com",
        ".myshopify.com",
        "-store.myshopify.com",
        "store.myshopify.com.evil.com",
        "evil.com/store.myshopify.com",
        "https://store.myshopify.com",
        "store.myshopify.com/admin",
        "store.myshopify.com:443",
        "sto re.myshopify.com",
        "store_1.myshopify.com",
        "store.example.com",
        "store.myshopify.co",
        "store.myshopify.com.",
        "a.b.myshopify.com",
        "store@myshopify.com",
        "store.myshopify.com\n",
        "störe.myshopify.com",
    ] {
        let err = ShopDomain::parse(bad).expect_err(bad);
        assert_eq!(
            err.kind(),
            crate::error::ErrorKind::InvalidRequest,
            "{bad:?}"
        );
    }
}

#[test]
fn shop_domain_rejects_overlong_values() {
    let long = format!("{}.myshopify.com", "a".repeat(250));
    ShopDomain::parse(&long).expect_err("too long");
}

proptest! {
    #[test]
    fn shop_domain_accepts_every_valid_label(label in "[a-zA-Z0-9][a-zA-Z0-9-]{0,40}") {
        let input = format!("{label}.myshopify.com");
        let shop = ShopDomain::parse(&input).expect("valid label");
        prop_assert_eq!(shop.as_str(), input.to_ascii_lowercase());
    }

    #[test]
    fn shop_domain_never_accepts_a_suffix(label in "[a-z0-9]{1,10}", suffix in "[./:@?#][a-z0-9./]{0,10}") {
        let input = format!("{label}.myshopify.com{suffix}");
        prop_assert!(ShopDomain::parse(&input).is_err());
    }

    #[test]
    fn parsed_shop_is_always_lowercase_myshopify(input in ".{0,60}") {
        if let Ok(shop) = ShopDomain::parse(&input) {
            prop_assert!(shop.as_str().ends_with(".myshopify.com"));
            prop_assert_eq!(shop.as_str(), shop.as_str().to_ascii_lowercase());
        }
    }
}

#[test]
fn topic_parses_and_maps_to_graphql_enum() {
    let topic = Topic::parse("orders/create").expect("valid topic");
    assert_eq!(topic.as_str(), "orders/create");
    assert_eq!(topic.graphql_enum(), "ORDERS_CREATE");
    let topic = Topic::parse("customers/data_request").expect("valid topic");
    assert_eq!(topic.graphql_enum(), "CUSTOMERS_DATA_REQUEST");
    let topic = Topic::parse("app_subscriptions/approaching_capped_amount").expect("valid");
    assert_eq!(
        topic.graphql_enum(),
        "APP_SUBSCRIPTIONS_APPROACHING_CAPPED_AMOUNT"
    );
}

#[test]
fn topic_rejects_malformed_values() {
    for bad in [
        "",
        "orders",
        "/orders",
        "orders/",
        "orders//create",
        "Orders/Create",
        "orders/create ",
        "orders/cre-ate",
        "orders\\create",
    ] {
        Topic::parse(bad).expect_err(bad);
    }
}

#[test]
fn topic_flags_compliance_topics() {
    for topic in Topic::COMPLIANCE {
        assert!(Topic::parse(topic).expect("valid").is_compliance());
    }
    assert!(
        !Topic::parse("orders/create")
            .expect("valid")
            .is_compliance()
    );
    assert!(
        !Topic::parse(Topic::APP_UNINSTALLED)
            .expect("valid")
            .is_compliance()
    );
}

#[test]
fn api_version_accepts_quarterly_and_unstable() {
    for good in ["2026-10", "2025-01", "2026-04", "2026-07", "unstable"] {
        assert_eq!(ApiVersion::parse(good).expect(good).as_str(), good);
    }
    assert_eq!(ApiVersion::default().as_str(), DEFAULT_API_VERSION);
}

#[test]
fn api_version_rejects_malformed_values() {
    for bad in [
        "",
        "2026-02",
        "2026-1",
        "26-10",
        "2026_10",
        "latest",
        "2026-10-01",
    ] {
        let err = ApiVersion::parse(bad).expect_err(bad);
        assert_eq!(err.kind(), crate::error::ErrorKind::Config);
    }
}
