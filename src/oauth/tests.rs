//! OAuth tests: install redirect, callback checks, token exchange.

#![allow(clippy::expect_used, clippy::panic)]

use serde_json::json;

use super::*;
use crate::error::ErrorKind;
use crate::plugin::ShopifyPlugin;
use crate::test_support::{NOW, OAUTH_TOML, SECRET, SHOP, Stub, StubResponse, app, config, state};
use crate::verify::sign_query;

fn oauth_state(admin_base: Option<&str>) -> AppState {
    let mut plugin = ShopifyPlugin::new();
    if let Some(base) = admin_base {
        plugin = plugin.admin_base_url(base);
    }
    state(Some(
        plugin
            .build_runtime(config(Some(OAUTH_TOML), &[]))
            .expect("runtime"),
    ))
}

fn location(response: &autumn_web::test::TestResponse) -> String {
    response
        .header("location")
        .expect("location header")
        .to_owned()
}

fn query_of(url: &str) -> Vec<(String, String)> {
    let query = url.split_once('?').map_or("", |(_, q)| q);
    url::form_urlencoded::parse(query.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn param<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn signed_callback(params: &[(&str, &str)], secret: &str) -> String {
    let mut pairs: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    let hmac = sign_query(secret, &pairs);
    pairs.push(("hmac".into(), hmac));
    let query: String = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    format!("/shopify/auth/callback?{query}")
}

fn callback_params<'a>(state_value: &'a str, shop: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("code", "auth-code-1"),
        ("host", "YWRtaW4uc2hvcGlmeS5jb20vc3RvcmUvbXktc3RvcmU="),
        ("shop", shop),
        ("state", state_value),
        ("timestamp", "1793000000"),
    ]
}

fn token_json() -> serde_json::Value {
    json!({
        "access_token": "shpat_new",
        "scope": "write_orders,write_products",
        "expires_in": 3600,
        "refresh_token": "shprt_new",
        "refresh_token_expires_in": 7_776_000
    })
}

// ── Install route ────────────────────────────────────────────────────

#[tokio::test]
async fn install_redirects_to_shopify_with_a_state_cookie() {
    let state = oauth_state(None);
    let response = app(&state)
        .get("/shopify/auth?shop=My-Store.myshopify.com")
        .send()
        .await;
    response.assert_status(302);
    let to = location(&response);
    assert!(
        to.starts_with("https://my-store.myshopify.com/admin/oauth/authorize?"),
        "{to}"
    );
    let pairs = query_of(&to);
    assert_eq!(param(&pairs, "client_id"), Some("client-id"));
    assert_eq!(param(&pairs, "scope"), Some("read_orders,write_products"));
    assert_eq!(
        param(&pairs, "redirect_uri"),
        Some("https://app.example.com/shopify/auth/callback")
    );
    let nonce = param(&pairs, "state").expect("state param");
    assert_eq!(nonce.len(), NONCE_BYTES * 2);
    assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));

    let cookie = response.header("set-cookie").expect("cookie");
    assert!(
        cookie.starts_with(&format!("{STATE_COOKIE}={nonce};")),
        "{cookie}"
    );
    for attribute in [
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        "Path=/shopify/auth",
        "Max-Age=600",
    ] {
        assert!(cookie.contains(attribute), "{cookie} lacks {attribute}");
    }
}

#[tokio::test]
async fn install_nonce_comes_from_the_app_entropy() {
    let first = app(&oauth_state(None))
        .get(&format!("/shopify/auth?shop={SHOP}"))
        .send()
        .await;
    let second = app(&oauth_state(None))
        .get(&format!("/shopify/auth?shop={SHOP}"))
        .send()
        .await;
    assert_eq!(
        param(&query_of(&location(&first)), "state"),
        param(&query_of(&location(&second)), "state"),
        "one seed gives one nonce"
    );
    let client = app(&oauth_state(None));
    let a = client
        .get(&format!("/shopify/auth?shop={SHOP}"))
        .send()
        .await;
    let b = client
        .get(&format!("/shopify/auth?shop={SHOP}"))
        .send()
        .await;
    assert_ne!(
        param(&query_of(&location(&a)), "state"),
        param(&query_of(&location(&b)), "state"),
        "each request draws a new nonce"
    );
}

#[tokio::test]
async fn install_rejects_bad_or_missing_shops() {
    let state = oauth_state(None);
    for path in [
        "/shopify/auth",
        "/shopify/auth?shop=",
        "/shopify/auth?shop=evil.com",
        "/shopify/auth?shop=my-store.myshopify.com.evil.com",
        "/shopify/auth?shop=a.myshopify.com&shop=b.myshopify.com",
    ] {
        app(&state).get(path).send().await.assert_status(400);
    }
}

#[tokio::test]
async fn oauth_routes_are_404_when_oauth_is_off() {
    let state = state(Some(
        ShopifyPlugin::new()
            .build_runtime(config(None, &[]))
            .expect("runtime"),
    ));
    app(&state)
        .get(&format!("/shopify/auth?shop={SHOP}"))
        .send()
        .await
        .assert_status(404);
    app(&state)
        .get(&signed_callback(&callback_params("n", SHOP), SECRET))
        .send()
        .await
        .assert_status(404);
}

#[tokio::test]
async fn oauth_routes_are_503_without_runtime() {
    let state = state(None);
    app(&state)
        .get(&format!("/shopify/auth?shop={SHOP}"))
        .send()
        .await
        .assert_status(503);
}

// ── Callback route ───────────────────────────────────────────────────

#[tokio::test]
async fn callback_exchanges_the_code_and_stores_the_token() {
    let stub = Stub::start(vec![StubResponse::json(200, &token_json())]).await;
    let state = oauth_state(Some(&stub.base_url));
    let response = app(&state)
        .get(&signed_callback(&callback_params("nonce-1", SHOP), SECRET))
        .header("cookie", &format!("other=1; {STATE_COOKIE}=nonce-1"))
        .send()
        .await;
    response.assert_status(302);
    assert_eq!(location(&response), "/welcome?shop=my-store.myshopify.com");
    let cookie = response.header("set-cookie").expect("clears cookie");
    assert!(cookie.starts_with(&format!("{STATE_COOKIE}=;")), "{cookie}");
    assert!(cookie.contains("Max-Age=0"), "{cookie}");

    let seen = stub.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].path, "/admin/oauth/access_token");
    assert_eq!(seen[0].header("accept"), Some("application/json"));
    let form = seen[0].form();
    assert_eq!(param(&form, "client_id"), Some("client-id"));
    assert_eq!(param(&form, "client_secret"), Some(SECRET));
    assert_eq!(param(&form, "code"), Some("auth-code-1"));
    assert_eq!(param(&form, "expiring"), Some("1"));

    let runtime = state.extension::<ShopifyRuntime>().expect("runtime");
    let shop = ShopDomain::parse(SHOP).expect("shop");
    let token = runtime
        .token_store()
        .get(&shop)
        .await
        .expect("get")
        .expect("stored");
    assert_eq!(token.access_token, "shpat_new");
    assert_eq!(token.expires_at, Some(NOW + 3600));
    assert_eq!(token.refresh_token.as_deref(), Some("shprt_new"));
    assert_eq!(token.refresh_token_expires_at, Some(NOW + 7_776_000));
}

#[tokio::test]
async fn callback_rejects_a_bad_hmac_with_401() {
    let stub = Stub::start(vec![]).await;
    let state = oauth_state(Some(&stub.base_url));
    app(&state)
        .get(&signed_callback(
            &callback_params("n", SHOP),
            "wrong-secret",
        ))
        .header("cookie", &format!("{STATE_COOKIE}=n"))
        .send()
        .await
        .assert_status(401);
    app(&state)
        .get(&format!(
            "/shopify/auth/callback?code=c&shop={SHOP}&state=n"
        ))
        .header("cookie", &format!("{STATE_COOKIE}=n"))
        .send()
        .await
        .assert_status(401);
    assert!(stub.requests().is_empty(), "no exchange after a bad hmac");
}

#[tokio::test]
async fn callback_rejects_a_state_mismatch_with_403() {
    let stub = Stub::start(vec![]).await;
    let state = oauth_state(Some(&stub.base_url));
    let url = signed_callback(&callback_params("nonce-1", SHOP), SECRET);
    app(&state)
        .get(&url)
        .header("cookie", &format!("{STATE_COOKIE}=other"))
        .send()
        .await
        .assert_status(403);
    app(&state).get(&url).send().await.assert_status(403);
    assert!(stub.requests().is_empty());
}

#[tokio::test]
async fn callback_rejects_a_bad_shop_with_400() {
    let stub = Stub::start(vec![]).await;
    let state = oauth_state(Some(&stub.base_url));
    app(&state)
        .get(&signed_callback(&callback_params("n", "evil.com"), SECRET))
        .header("cookie", &format!("{STATE_COOKIE}=n"))
        .send()
        .await
        .assert_status(400);
    assert!(stub.requests().is_empty());
}

#[tokio::test]
async fn callback_rejects_repeated_params_and_missing_code() {
    let stub = Stub::start(vec![]).await;
    let state = oauth_state(Some(&stub.base_url));
    let repeated = format!(
        "{}&shop=evil.myshopify.com",
        signed_callback(&callback_params("n", SHOP), SECRET)
    );
    app(&state)
        .get(&repeated)
        .header("cookie", &format!("{STATE_COOKIE}=n"))
        .send()
        .await
        .assert_status(400);
    let no_code = signed_callback(
        &[("shop", SHOP), ("state", "n"), ("timestamp", "1")],
        SECRET,
    );
    app(&state)
        .get(&no_code)
        .header("cookie", &format!("{STATE_COOKIE}=n"))
        .send()
        .await
        .assert_status(400);
    assert!(stub.requests().is_empty());
}

#[tokio::test]
async fn callback_rejects_missing_scopes_with_403() {
    let mut narrow = token_json();
    narrow["scope"] = json!("read_orders");
    let stub = Stub::start(vec![StubResponse::json(200, &narrow)]).await;
    let state = oauth_state(Some(&stub.base_url));
    let response = app(&state)
        .get(&signed_callback(&callback_params("n", SHOP), SECRET))
        .header("cookie", &format!("{STATE_COOKIE}=n"))
        .send()
        .await;
    response.assert_status(403);
    assert!(
        response.text().contains("write_products"),
        "{}",
        response.text()
    );
    let runtime = state.extension::<ShopifyRuntime>().expect("runtime");
    let shop = ShopDomain::parse(SHOP).expect("shop");
    assert!(
        runtime
            .token_store()
            .get(&shop)
            .await
            .expect("get")
            .is_none()
    );
}

#[tokio::test]
async fn callback_maps_exchange_failure_to_502_without_secrets() {
    let stub = Stub::start(vec![StubResponse::text(
        400,
        "{\"error\":\"invalid_request\"}",
    )])
    .await;
    let state = oauth_state(Some(&stub.base_url));
    let response = app(&state)
        .get(&signed_callback(&callback_params("n", SHOP), SECRET))
        .header("cookie", &format!("{STATE_COOKIE}=n"))
        .send()
        .await;
    response.assert_status(502);
    assert!(!response.text().contains(SECRET));
}

// ── Helpers ──────────────────────────────────────────────────────────

#[test]
fn missing_scopes_lets_write_cover_read() {
    let requested = vec![
        "read_orders".to_owned(),
        "write_products".to_owned(),
        "read_customers".to_owned(),
    ];
    assert!(
        missing_scopes(
            &requested,
            &["write_orders", "write_products", "read_customers"]
        )
        .is_empty()
    );
    assert_eq!(
        missing_scopes(&requested, &["read_products", "read_orders"]),
        vec!["write_products", "read_customers"]
    );
    assert!(missing_scopes(&[], &[]).is_empty());
}

#[test]
fn missing_scopes_does_not_let_read_cover_write() {
    assert_eq!(
        missing_scopes(&["write_orders".to_owned()], &["read_orders"]),
        vec!["write_orders"]
    );
}

#[test]
fn authorize_url_encodes_its_params() {
    let config = config(Some(OAUTH_TOML), &[]);
    let shop = ShopDomain::parse(SHOP).expect("shop");
    let url = authorize_url(&config, &shop, "abc").expect("url");
    assert_eq!(
        url,
        "https://my-store.myshopify.com/admin/oauth/authorize?client_id=client-id&scope=read_orders%2Cwrite_products&redirect_uri=https%3A%2F%2Fapp.example.com%2Fshopify%2Fauth%2Fcallback&state=abc"
    );
    let off = crate::test_support::config(None, &[]);
    assert_eq!(
        authorize_url(&off, &shop, "abc").expect_err("off").kind(),
        ErrorKind::OAuthDisabled
    );
}

#[test]
fn parse_query_decodes_and_rejects_repeats() {
    let pairs = parse_query(Some("a=1&b=x%20y&c=%26")).expect("parses");
    assert_eq!(
        pairs,
        vec![
            ("a".to_owned(), "1".to_owned()),
            ("b".to_owned(), "x y".to_owned()),
            ("c".to_owned(), "&".to_owned())
        ]
    );
    assert!(parse_query(None).expect("empty").is_empty());
    assert_eq!(
        parse_query(Some("a=1&a=2")).expect_err("repeat").kind(),
        ErrorKind::InvalidRequest
    );
}

#[test]
fn cookie_value_finds_the_named_cookie() {
    let mut headers = HeaderMap::new();
    headers.append(
        "cookie",
        "a=1; shopify_oauth_state=xyz".parse().expect("header"),
    );
    headers.append("cookie", "b=2".parse().expect("header"));
    assert_eq!(cookie_value(&headers, STATE_COOKIE), Some("xyz"));
    assert_eq!(cookie_value(&headers, "b"), Some("2"));
    assert_eq!(cookie_value(&headers, "shopify_oauth"), None);
    assert_eq!(cookie_value(&HeaderMap::new(), "a"), None);
}

#[test]
fn cookies_have_the_hardened_attributes() {
    assert_eq!(
        state_cookie("n1"),
        "shopify_oauth_state=n1; Path=/shopify/auth; Max-Age=600; HttpOnly; Secure; SameSite=Lax"
    );
    assert_eq!(
        clear_state_cookie(),
        "shopify_oauth_state=; Path=/shopify/auth; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
    );
}

#[test]
fn oauth_routes_are_declared() {
    let routes = oauth_routes();
    let paths: Vec<&str> = routes.iter().map(|r| r.path).collect();
    assert_eq!(paths, vec!["/auth", "/auth/callback"]);
}
