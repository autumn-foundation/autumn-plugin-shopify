//! Config tests. No process env changes: env lookups are closures.

#![allow(clippy::expect_used)]

use std::collections::HashMap;

use super::*;
use crate::error::ErrorKind;

fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    move |name| map.get(name).cloned()
}

const FULL: &str = r#"
[shopify]
api_key = "key123"
shop = "my-store.myshopify.com"
api_version = "2026-07"
app_url = "https://app.example.com/"
scopes = ["read_orders", "write_products"]
after_install_path = "/welcome"
max_throttle_retries = 5
"#;

#[test]
fn defaults_are_documented_values() {
    let config = ShopifyConfig::default();
    assert_eq!(config.api_version, "2026-10");
    assert_eq!(config.after_install_path, "/");
    assert_eq!(config.max_throttle_retries, 3);
    assert!(!config.oauth_enabled());
}

#[test]
fn toml_section_sets_every_field() {
    let config = ShopifyConfig::from_toml_str(FULL).expect("parses");
    assert_eq!(config.api_key.as_deref(), Some("key123"));
    assert_eq!(config.shop.as_deref(), Some("my-store.myshopify.com"));
    assert_eq!(config.api_version, "2026-07");
    assert_eq!(config.app_url.as_deref(), Some("https://app.example.com/"));
    assert_eq!(config.scopes, vec!["read_orders", "write_products"]);
    assert_eq!(config.after_install_path, "/welcome");
    assert_eq!(config.max_throttle_retries, 5);
    assert!(config.oauth_enabled());
}

#[test]
fn scopes_accept_a_comma_string() {
    let config = ShopifyConfig::from_toml_str("[shopify]\nscopes = \"read_a, write_b,,\"\n")
        .expect("parses");
    assert_eq!(config.scopes, vec!["read_a", "write_b"]);
}

#[test]
fn missing_section_gives_defaults() {
    let config = ShopifyConfig::from_toml_str("[other]\nx = 1\n").expect("parses");
    assert!(config.api_key.is_none());
    assert_eq!(config.api_version, "2026-10");
}

#[test]
fn secret_keys_in_the_file_fail_closed() {
    for key in [
        "api_secret",
        "client_secret",
        "access_token",
        "secret",
        "token",
    ] {
        let doc = format!("[shopify]\n{key} = \"leak\"\n");
        let err = ShopifyConfig::from_toml_str(&doc).expect_err(key);
        assert_eq!(err.kind(), ErrorKind::Config);
        assert!(!err.to_string().contains("leak"), "{err}");
    }
}

#[test]
fn unknown_keys_and_bad_toml_fail() {
    ShopifyConfig::from_toml_str("[shopify]\nshpo = \"typo\"\n").expect_err("unknown key");
    ShopifyConfig::from_toml_str("[shopify\n").expect_err("bad toml");
    ShopifyConfig::from_toml_str("shopify = 1\n").expect_err("not a table");
}

#[test]
fn env_overrides_file_and_carries_secrets() {
    let config = ShopifyConfig::from_sources(
        Some(FULL),
        env(&[
            ("SHOPIFY_API_KEY", "env-key"),
            ("SHOPIFY_SHOP", "other.myshopify.com"),
            ("SHOPIFY_API_VERSION", "2026-10"),
            ("SHOPIFY_APP_URL", "https://env.example.com"),
            ("SHOPIFY_SCOPES", "read_customers,write_orders"),
            ("SHOPIFY_API_SECRET", "s3cret"),
            ("SHOPIFY_API_SECRET_PREVIOUS", "old"),
            ("SHOPIFY_ACCESS_TOKEN", "shpat_123"),
        ]),
    )
    .expect("loads");
    assert_eq!(config.api_key.as_deref(), Some("env-key"));
    assert_eq!(config.shop.as_deref(), Some("other.myshopify.com"));
    assert_eq!(config.api_version, "2026-10");
    assert_eq!(config.app_url.as_deref(), Some("https://env.example.com"));
    assert_eq!(config.scopes, vec!["read_customers", "write_orders"]);
    assert_eq!(config.access_token(), Some("shpat_123"));
    assert_eq!(config.secrets().expect("secret").current(), "s3cret");
}

#[test]
fn blank_env_values_count_as_unset() {
    let config = ShopifyConfig::from_sources(
        Some(FULL),
        env(&[("SHOPIFY_API_KEY", "  "), ("SHOPIFY_ACCESS_TOKEN", "")]),
    )
    .expect("loads");
    assert_eq!(config.api_key.as_deref(), Some("key123"));
    assert!(config.access_token().is_none());
}

#[test]
fn no_file_still_reads_env() {
    let config =
        ShopifyConfig::from_sources(None, env(&[("SHOPIFY_API_SECRET", "s")])).expect("loads");
    assert!(config.secrets().is_ok());
}

#[test]
fn debug_redacts_secrets() {
    let config = ShopifyConfig::from_sources(
        None,
        env(&[
            ("SHOPIFY_API_SECRET", "s3cret-value"),
            ("SHOPIFY_API_SECRET_PREVIOUS", "old-value"),
            ("SHOPIFY_ACCESS_TOKEN", "shpat_value"),
        ]),
    )
    .expect("loads");
    let debug = format!("{config:?}");
    for secret in ["s3cret-value", "old-value", "shpat_value"] {
        assert!(!debug.contains(secret), "{debug}");
    }
    assert!(debug.contains("<redacted>"));
}

fn valid_oauth() -> ShopifyConfig {
    ShopifyConfig::from_sources(Some(FULL), env(&[("SHOPIFY_API_SECRET", "s")])).expect("loads")
}

#[test]
fn a_full_config_validates() {
    valid_oauth().validate().expect("valid");
}

#[test]
fn validate_needs_the_secret() {
    let config = ShopifyConfig::from_toml_str(FULL).expect("parses");
    let err = config.validate().expect_err("no secret");
    assert!(err.to_string().contains("SHOPIFY_API_SECRET"), "{err}");
    config.secrets().expect_err("no secret");
}

#[test]
fn validate_checks_shop_and_version() {
    let mut config = valid_oauth();
    config.shop = Some("evil.com".into());
    config.validate().expect_err("bad shop");
    config.shop_domain().expect_err("bad shop");

    let mut config = valid_oauth();
    config.api_version = "2026-02".into();
    config.validate().expect_err("bad version");
}

#[test]
fn validate_checks_oauth_fields() {
    let mut config = valid_oauth();
    config.api_key = None;
    config.validate().expect_err("oauth needs api_key");

    let mut config = valid_oauth();
    config.scopes.clear();
    config.validate().expect_err("oauth needs scopes");

    let mut config = valid_oauth();
    config.scopes = vec!["read orders".into()];
    config.validate().expect_err("bad scope");

    for url in [
        "http://app.example.com",
        "ftp://app.example.com",
        "not a url",
        "https://app.example.com/?x=1",
        "https://app.example.com/#frag",
    ] {
        let mut config = valid_oauth();
        config.app_url = Some(url.into());
        config.validate().expect_err(url);
    }

    for url in [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://a.example.com/base",
    ] {
        let mut config = valid_oauth();
        config.app_url = Some(url.into());
        config.validate().expect(url);
    }
}

#[test]
fn validate_blocks_open_redirects() {
    for path in [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "welcome",
        "",
    ] {
        let mut config = valid_oauth();
        config.after_install_path = path.into();
        config.validate().expect_err(path);
    }
}

#[test]
fn validate_bounds_retries() {
    let mut config = valid_oauth();
    config.max_throttle_retries = 11;
    config.validate().expect_err("too many retries");
    config.max_throttle_retries = 0;
    config.validate().expect("zero retries is allowed");
}

#[test]
fn webhooks_only_config_validates_without_oauth_fields() {
    let config =
        ShopifyConfig::from_sources(None, env(&[("SHOPIFY_API_SECRET", "s")])).expect("loads");
    config.validate().expect("webhooks-only is valid");
    assert!(config.redirect_uri().is_none());
}

#[test]
fn redirect_uri_joins_app_url_and_callback() {
    assert_eq!(
        valid_oauth().redirect_uri().as_deref(),
        Some("https://app.example.com/shopify/auth/callback")
    );
}

#[test]
fn shop_domain_is_parsed() {
    let shop = valid_oauth().shop_domain().expect("valid").expect("set");
    assert_eq!(shop.as_str(), "my-store.myshopify.com");
}

#[test]
fn env_sets_after_install_path_and_retries() {
    let config = ShopifyConfig::from_sources(
        Some(FULL),
        env(&[
            ("SHOPIFY_AFTER_INSTALL_PATH", "/app?tab=home"),
            ("SHOPIFY_MAX_THROTTLE_RETRIES", " 2 "),
        ]),
    )
    .expect("loads");
    assert_eq!(config.after_install_path, "/app?tab=home");
    assert_eq!(config.max_throttle_retries, 2);
    let err = ShopifyConfig::from_sources(None, env(&[("SHOPIFY_MAX_THROTTLE_RETRIES", "many")]))
        .expect_err("not a number");
    assert_eq!(err.kind(), ErrorKind::Config);
}

#[test]
fn after_install_path_allows_a_query_but_not_a_fragment() {
    let mut config = valid_oauth();
    config.after_install_path = "/app?tab=home".into();
    config.validate().expect("query is fine");
    config.after_install_path = "/app#top".into();
    config.validate().expect_err("fragment");
}
