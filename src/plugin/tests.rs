//! Plugin and runtime tests: builder, contract, conformance, clients,
//! token refresh, startup warnings.

#![allow(clippy::expect_used, clippy::panic)]

use std::time::Duration;

use serde_json::json;

use super::*;
use crate::error::ErrorKind;
use crate::test_support::{NOW, OAUTH_TOML, SECRET, SHOP, Stub, StubResponse, config, state};
use crate::tokens::ShopToken;

fn shop() -> ShopDomain {
    ShopDomain::parse(SHOP).expect("shop")
}

fn other_shop() -> ShopDomain {
    ShopDomain::parse("other.myshopify.com").expect("shop")
}

fn expiring_token(expires_at: i64) -> ShopToken {
    ShopToken::non_expiring("shpat_old", "read_orders").with_refresh(
        expires_at,
        "shprt_old",
        Some(NOW + 86_400),
    )
}

fn refreshed_json() -> serde_json::Value {
    json!({
        "access_token": "shpat_fresh",
        "scope": "read_orders",
        "expires_in": 3600,
        "refresh_token": "shprt_fresh",
        "refresh_token_expires_in": 7_776_000
    })
}

fn oauth_runtime(stub: &Stub) -> ShopifyRuntime {
    ShopifyPlugin::new()
        .admin_base_url(stub.base_url.clone())
        .build_runtime(config(Some(OAUTH_TOML), &[]))
        .expect("runtime")
}

// ── Plugin surface ───────────────────────────────────────────────────

#[test]
fn plugin_name_is_stable() {
    assert_eq!(ShopifyPlugin::new().name(), "autumn-plugin-shopify");
}

#[test]
fn builder_collects_webhooks_and_stores() {
    let plugin = ShopifyPlugin::new()
        .webhook(
            "orders/create",
            |_ctx: crate::webhooks::WebhookContext| async { Ok(()) },
        )
        .token_store(Arc::new(InMemoryTokenStore::new()))
        .delivery_store(Arc::new(InMemoryDeliveryStore::default()))
        .admin_base_url("http://127.0.0.1:1")
        .configure(|c| c.max_throttle_retries = 1);
    assert_eq!(plugin.webhooks.len(), 1);
    assert!(plugin.token_store.is_some());
    assert!(plugin.delivery_store.is_some());
    assert!(format!("{plugin:?}").contains("orders/create"));
}

#[test]
fn contract_declares_supported_autumn_web_range() {
    let contract = ShopifyPlugin::new().contract().expect("contract");
    assert_eq!(contract.plugin, env!("CARGO_PKG_NAME"));
    assert_eq!(
        contract.plugin_version.as_deref(),
        Some(env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(contract.autumn_web.as_deref(), Some(SUPPORTED_AUTUMN_WEB));
}

#[test]
fn contract_is_compatible_with_linked_autumn_web() {
    use autumn_web::plugin_contract::{AUTUMN_WEB_VERSION, ContractVerdict, evaluate};
    let contract = ShopifyPlugin::new().contract().expect("contract");
    assert_eq!(
        evaluate(&contract, AUTUMN_WEB_VERSION),
        ContractVerdict::Compatible
    );
    for version in ["0.7.0", "0.9.0", "1.0.0"] {
        assert!(matches!(
            evaluate(&contract, version),
            ContractVerdict::Incompatible(_)
        ));
    }
}

#[test]
fn plugin_passes_the_conformance_harness() {
    use autumn_web::plugin_conformance::{ConformanceConfig, run_conformance};
    let plugin = ShopifyPlugin::new();
    let contract = plugin.contract().expect("contract");
    let app = autumn_web::app().plugin(plugin);
    assert!(app.has_plugin("autumn-plugin-shopify"));
    let routes = app.plugin_route_infos().expect("routes build");
    for (method, path) in [
        ("POST", "/shopify/webhooks"),
        ("GET", "/shopify/auth"),
        ("GET", "/shopify/auth/callback"),
    ] {
        assert!(
            routes.iter().any(|r| r.method == method && r.path == path),
            "{method} {path} is declared"
        );
    }
    let config = ConformanceConfig::new("autumn-plugin-shopify")
        .prefix("/shopify")
        .contract(contract);
    let report = run_conformance(&config, &routes);
    assert!(report.passed(), "{}", report.to_text_report());
}

// ── Startup ──────────────────────────────────────────────────────────

#[test]
fn start_installs_the_runtime_and_the_health_indicator() {
    let state = state(None);
    ShopifyPlugin::new()
        .start(
            &state,
            config(
                None,
                &[
                    ("SHOPIFY_SHOP", SHOP),
                    ("SHOPIFY_ACCESS_TOKEN", "shpat_fixed"),
                ],
            ),
        )
        .expect("starts");
    assert!(state.extension::<ShopifyRuntime>().is_some());
    assert!(
        state.health_indicator_registry().contains("shopify"),
        "health indicator is registered"
    );
}

#[test]
fn start_skips_health_without_single_store_mode() {
    let state = state(None);
    ShopifyPlugin::new()
        .start(&state, config(Some(OAUTH_TOML), &[]))
        .expect("starts");
    assert!(state.extension::<ShopifyRuntime>().is_some());
    assert!(!state.health_indicator_registry().contains("shopify"));
}

#[test]
fn start_fails_on_a_bad_config() {
    let state = state(None);
    let empty = ShopifyConfig::from_sources(None, |_| None).expect("loads");
    let err = ShopifyPlugin::new()
        .start(&state, empty)
        .expect_err("no secret");
    assert_eq!(err.kind(), ErrorKind::Config);
    assert!(state.extension::<ShopifyRuntime>().is_none());
}

// ── build_runtime ────────────────────────────────────────────────────

#[test]
fn build_runtime_needs_a_valid_config() {
    let empty = ShopifyConfig::from_sources(None, |_| None).expect("loads");
    let err = ShopifyPlugin::new()
        .build_runtime(empty)
        .expect_err("no secret");
    assert_eq!(err.kind(), ErrorKind::Config);
}

#[test]
fn build_runtime_rejects_bad_and_repeated_topics() {
    let ok = |_ctx: crate::webhooks::WebhookContext| async { Ok(()) };
    let err = ShopifyPlugin::new()
        .webhook("orders/create", ok)
        .webhook("orders/create", ok)
        .build_runtime(config(None, &[]))
        .expect_err("repeat");
    assert_eq!(err.kind(), ErrorKind::Config);
    let err = ShopifyPlugin::new()
        .webhook("not a topic", ok)
        .build_runtime(config(None, &[]))
        .expect_err("malformed");
    assert_eq!(err.kind(), ErrorKind::Config);
}

#[test]
fn configure_closures_win_over_env() {
    let runtime = ShopifyPlugin::new()
        .configure(|c| c.api_version = "2026-07".into())
        .configure(|c| c.max_throttle_retries = 7)
        .build_runtime(config(None, &[("SHOPIFY_API_VERSION", "2026-04")]))
        .expect("runtime");
    assert_eq!(runtime.config().api_version, "2026-07");
    assert_eq!(runtime.config().max_throttle_retries, 7);
}

#[test]
fn configure_cannot_make_a_config_invalid_unnoticed() {
    let err = ShopifyPlugin::new()
        .configure(|c| c.api_version = "bad".into())
        .build_runtime(config(None, &[]))
        .expect_err("validated after closures");
    assert_eq!(err.kind(), ErrorKind::Config);
}

#[test]
fn runtime_debug_hides_secrets() {
    let runtime = ShopifyPlugin::new()
        .build_runtime(config(
            None,
            &[
                ("SHOPIFY_SHOP", SHOP),
                ("SHOPIFY_ACCESS_TOKEN", "shpat_fixed"),
            ],
        ))
        .expect("runtime");
    let debug = format!("{runtime:?}");
    assert!(!debug.contains("shpat_fixed"), "{debug}");
    assert!(!debug.contains(SECRET), "{debug}");
    assert_eq!(runtime.secrets().current(), SECRET);
    assert!(runtime.registry().topics().is_empty());
    let claim = futures::executor::block_on(runtime.delivery_store().claim("x", 0));
    assert_eq!(claim.expect("claim"), crate::delivery::Claim::Fresh);
}

// ── Clients ──────────────────────────────────────────────────────────

#[tokio::test]
async fn single_store_client_uses_the_fixed_token() {
    let stub = Stub::start(vec![StubResponse::json(
        200,
        &json!({"data": {"ok": true}}),
    )])
    .await;
    let runtime = ShopifyPlugin::new()
        .admin_base_url(stub.base_url.clone())
        .build_runtime(config(
            None,
            &[
                ("SHOPIFY_SHOP", SHOP),
                ("SHOPIFY_ACCESS_TOKEN", "shpat_fixed"),
            ],
        ))
        .expect("runtime");
    runtime
        .client()
        .expect("client")
        .graphql("{ ok }", json!({}))
        .await
        .expect("call");
    let client = runtime.client_for(&shop(), NOW).await.expect("same shop");
    assert_eq!(client.shop(), &shop());
    assert_eq!(
        stub.requests()[0].header("x-shopify-access-token"),
        Some("shpat_fixed")
    );
}

#[tokio::test]
async fn client_needs_single_store_mode() {
    let runtime = ShopifyPlugin::new()
        .build_runtime(config(None, &[]))
        .expect("runtime");
    assert_eq!(
        runtime.client().expect_err("no shop").kind(),
        ErrorKind::Config
    );
    let runtime = ShopifyPlugin::new()
        .build_runtime(config(None, &[("SHOPIFY_SHOP", SHOP)]))
        .expect("runtime");
    assert_eq!(
        runtime.client().expect_err("no token").kind(),
        ErrorKind::Config
    );
}

#[tokio::test]
async fn client_for_an_unknown_shop_is_not_installed() {
    let stub = Stub::start(vec![]).await;
    let runtime = oauth_runtime(&stub);
    let err = runtime
        .client_for(&shop(), NOW)
        .await
        .expect_err("no token");
    assert_eq!(err.kind(), ErrorKind::NotInstalled);
}

#[tokio::test]
async fn client_for_a_fresh_token_makes_no_refresh() {
    let stub = Stub::start(vec![StubResponse::json(
        200,
        &json!({"data": {"ok": true}}),
    )])
    .await;
    let runtime = oauth_runtime(&stub);
    runtime
        .token_store()
        .put(&shop(), expiring_token(NOW + 3_600))
        .await
        .expect("put");
    let client = runtime.client_for(&shop(), NOW).await.expect("client");
    client.graphql("{ ok }", json!({})).await.expect("call");
    let seen = stub.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path, "/admin/api/2026-10/graphql.json");
    assert_eq!(seen[0].header("x-shopify-access-token"), Some("shpat_old"));
}

#[tokio::test]
async fn client_for_refreshes_a_token_near_expiry() {
    let stub = Stub::start(vec![StubResponse::json(200, &refreshed_json())]).await;
    let runtime = oauth_runtime(&stub);
    runtime
        .token_store()
        .put(&shop(), expiring_token(NOW + 30))
        .await
        .expect("put");
    runtime
        .client_for(&shop(), NOW)
        .await
        .expect("refreshed client");

    let seen = stub.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path, "/admin/oauth/access_token");
    let form = seen[0].form();
    let get = |k: &str| {
        form.iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(get("grant_type"), Some("refresh_token"));
    assert_eq!(get("refresh_token"), Some("shprt_old"));
    assert_eq!(get("client_id"), Some("client-id"));
    assert_eq!(get("client_secret"), Some(SECRET));

    let stored = runtime
        .token_store()
        .get(&shop())
        .await
        .expect("get")
        .expect("kept");
    assert_eq!(stored.access_token, "shpat_fresh");
    assert_eq!(stored.refresh_token.as_deref(), Some("shprt_fresh"));
    assert_eq!(stored.expires_at, Some(NOW + 3_600));
}

#[tokio::test]
async fn concurrent_callers_share_one_refresh() {
    let stub = Stub::start(vec![StubResponse::json(200, &refreshed_json())]).await;
    let runtime = Arc::new(oauth_runtime(&stub));
    runtime
        .token_store()
        .put(&shop(), expiring_token(NOW))
        .await
        .expect("put");
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let runtime = Arc::clone(&runtime);
            tokio::spawn(async move { runtime.client_for(&shop(), NOW).await })
        })
        .collect();
    for task in tasks {
        task.await
            .expect("joins")
            .expect("every caller gets a client");
    }
    assert_eq!(stub.requests().len(), 1, "one refresh for eight callers");
}

#[tokio::test]
async fn a_refused_refresh_deletes_the_token() {
    let stub = Stub::start(vec![StubResponse::json(
        401,
        &json!({"error": "invalid_request"}),
    )])
    .await;
    let runtime = oauth_runtime(&stub);
    runtime
        .token_store()
        .put(&shop(), expiring_token(NOW))
        .await
        .expect("put");
    let err = runtime.client_for(&shop(), NOW).await.expect_err("refused");
    assert_eq!(err.kind(), ErrorKind::Reauthorize);
    assert!(
        runtime
            .token_store()
            .get(&shop())
            .await
            .expect("get")
            .is_none()
    );
}

#[tokio::test]
async fn an_expired_refresh_token_needs_reinstall_without_a_call() {
    let stub = Stub::start(vec![]).await;
    let runtime = oauth_runtime(&stub);
    let mut token = expiring_token(NOW);
    token.refresh_token_expires_at = Some(NOW - 1);
    runtime
        .token_store()
        .put(&shop(), token)
        .await
        .expect("put");
    let err = runtime.client_for(&shop(), NOW).await.expect_err("expired");
    assert_eq!(err.kind(), ErrorKind::Reauthorize);
    assert!(stub.requests().is_empty());
    assert!(
        runtime
            .token_store()
            .get(&shop())
            .await
            .expect("get")
            .is_none()
    );
}

#[tokio::test]
async fn a_failed_refresh_keeps_the_token() {
    let stub = Stub::start(vec![StubResponse::text(503, "unavailable")]).await;
    let runtime = oauth_runtime(&stub);
    runtime
        .token_store()
        .put(&shop(), expiring_token(NOW))
        .await
        .expect("put");
    let err = runtime
        .client_for(&shop(), NOW)
        .await
        .expect_err("transient");
    assert_eq!(err.kind(), ErrorKind::ShopifyApi);
    assert!(
        runtime
            .token_store()
            .get(&shop())
            .await
            .expect("get")
            .is_some()
    );
}

#[tokio::test]
async fn refresh_needs_oauth_credentials() {
    let stub = Stub::start(vec![]).await;
    let runtime = ShopifyPlugin::new()
        .admin_base_url(stub.base_url.clone())
        .build_runtime(config(None, &[]))
        .expect("runtime");
    runtime
        .token_store()
        .put(&other_shop(), expiring_token(NOW))
        .await
        .expect("put");
    let err = runtime
        .client_for(&other_shop(), NOW)
        .await
        .expect_err("no api_key");
    assert_eq!(err.kind(), ErrorKind::Config);
}

#[tokio::test]
async fn the_retry_policy_follows_the_config() {
    let stub = Stub::start(vec![
        StubResponse::text(429, "slow").header("retry-after", "0.001"),
        StubResponse::text(429, "slow").header("retry-after", "0.001"),
    ])
    .await;
    let runtime = ShopifyPlugin::new()
        .admin_base_url(stub.base_url.clone())
        .configure(|c| c.max_throttle_retries = 1)
        .build_runtime(config(
            None,
            &[("SHOPIFY_SHOP", SHOP), ("SHOPIFY_ACCESS_TOKEN", "t")],
        ))
        .expect("runtime");
    let err = runtime
        .client()
        .expect("client")
        .graphql("{ ok }", json!({}))
        .await
        .expect_err("throttled");
    assert_eq!(err.kind(), ErrorKind::Throttled);
    assert_eq!(stub.requests().len(), 2);
}

// ── The Shopify handle ───────────────────────────────────────────────

#[tokio::test]
async fn shopify_handle_reads_the_runtime_and_clock() {
    let stub = Stub::start(vec![]).await;
    let state = state(Some(oauth_runtime(&stub)));
    let handle = Shopify::from_state(&state).expect("handle");
    handle
        .runtime()
        .token_store()
        .put(&shop(), expiring_token(NOW + 3_600))
        .await
        .expect("put");
    handle
        .client_for(&shop())
        .await
        .expect("fresh at the app clock");
    assert_eq!(
        handle.client().expect_err("no single store").kind(),
        ErrorKind::Config
    );
    assert!(format!("{handle:?}").contains("Shopify"));
}

#[test]
fn shopify_handle_needs_the_runtime() {
    let err = Shopify::from_state(&state(None)).expect_err("no runtime");
    assert_eq!(err.kind(), ErrorKind::MissingRuntime);
}

#[tokio::test]
async fn shopify_extractor_is_503_without_runtime() {
    use autumn_web::reexports::axum::extract::FromRequestParts as _;
    let (mut parts, ()) = autumn_web::reexports::http::Request::new(()).into_parts();
    let err = Shopify::from_request_parts(&mut parts, &state(None))
        .await
        .expect_err("no runtime");
    assert_eq!(err.status().as_u16(), 503);
}

// ── Startup warnings ─────────────────────────────────────────────────

#[test]
fn warnings_name_missing_compliance_handlers_when_oauth_is_on() {
    let ok = |_ctx: crate::webhooks::WebhookContext| async { Ok(()) };
    let runtime = ShopifyPlugin::new()
        .webhook("customers/redact", ok)
        .build_runtime(config(Some(OAUTH_TOML), &[]))
        .expect("runtime");
    let warnings = startup_warnings(&runtime, &autumn_web::config::AutumnConfig::default());
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("customers/data_request"))
    );
    assert!(warnings.iter().any(|w| w.contains("shop/redact")));

    let runtime = ShopifyPlugin::new()
        .build_runtime(config(None, &[]))
        .expect("runtime");
    assert!(startup_warnings(&runtime, &autumn_web::config::AutumnConfig::default()).is_empty());
}

#[test]
fn warnings_name_the_csrf_exemption() {
    let runtime = ShopifyPlugin::new()
        .build_runtime(config(None, &[]))
        .expect("runtime");
    let mut app_config = autumn_web::config::AutumnConfig::default();
    app_config.security.csrf.enabled = true;
    let warnings = startup_warnings(&runtime, &app_config);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("/shopify/webhooks"));

    app_config.security.csrf.exempt_paths = vec!["/shopify/".into()];
    assert!(startup_warnings(&runtime, &app_config).is_empty());
    app_config.security.csrf.exempt_paths = vec!["/shopify/webhooks".into()];
    assert!(startup_warnings(&runtime, &app_config).is_empty());
    app_config.security.csrf.exempt_paths = vec!["/shop".into()];
    assert_eq!(startup_warnings(&runtime, &app_config).len(), 1);
}

#[test]
fn the_refresh_margin_is_one_minute() {
    assert_eq!(REFRESH_MARGIN_SECS, 60);
    let _ = Duration::from_secs(1);
}

// ── Review round 1: refresh safety ───────────────────────────────────

#[tokio::test]
async fn a_refresh_400_keeps_the_token() {
    let stub = Stub::start(vec![StubResponse::json(
        400,
        &json!({"error": "invalid_request"}),
    )])
    .await;
    let runtime = oauth_runtime(&stub);
    runtime
        .token_store()
        .put(&shop(), expiring_token(NOW))
        .await
        .expect("put");
    let err = runtime.client_for(&shop(), NOW).await.expect_err("400");
    assert_eq!(err.kind(), ErrorKind::ShopifyApi);
    assert!(
        runtime
            .token_store()
            .get(&shop())
            .await
            .expect("get")
            .is_some()
    );
}

#[tokio::test]
async fn a_refresh_403_keeps_the_token() {
    // shopify.dev: bad client credentials get a 403, not a 401.
    let stub = Stub::start(vec![StubResponse::json(
        403,
        &json!({"error": "invalid_client"}),
    )])
    .await;
    let runtime = oauth_runtime(&stub);
    runtime
        .token_store()
        .put(&shop(), expiring_token(NOW))
        .await
        .expect("put");
    let err = runtime
        .client_for(&shop(), NOW)
        .await
        .expect_err("bad secret");
    assert_eq!(err.kind(), ErrorKind::ShopifyApi);
    assert!(
        runtime
            .token_store()
            .get(&shop())
            .await
            .expect("get")
            .is_some()
    );
}

#[tokio::test]
async fn a_failed_refresh_uses_the_old_token_while_it_is_valid_and_backs_off() {
    let stub = Stub::start(vec![StubResponse::text(503, "unavailable")]).await;
    let runtime = oauth_runtime(&stub);
    runtime
        .token_store()
        .put(&shop(), expiring_token(NOW + 30))
        .await
        .expect("put");
    let client = runtime
        .client_for(&shop(), NOW)
        .await
        .expect("old token still works");
    assert_eq!(client.shop(), &shop());
    // Inside the back-off window: no second refresh call.
    runtime
        .client_for(&shop(), NOW + 5)
        .await
        .expect("old token again");
    assert_eq!(stub.requests().len(), 1);
}

/// A store that hands out `first` once, then `later` on every read: as if
/// another replica stored a new pair during the refresh.
struct SwapStore {
    reads: std::sync::Mutex<u32>,
    first: ShopToken,
    later: std::sync::Mutex<Option<ShopToken>>,
}

impl TokenStore for SwapStore {
    fn get<'a>(
        &'a self,
        _shop: &'a ShopDomain,
    ) -> crate::tokens::StoreFuture<'a, Option<ShopToken>> {
        let reads = {
            let mut reads = self.reads.lock().expect("lock");
            *reads += 1;
            *reads
        };
        let token = if reads <= 2 {
            Some(self.first.clone())
        } else {
            self.later.lock().expect("lock").clone()
        };
        Box::pin(async move { Ok(token) })
    }

    fn put<'a>(
        &'a self,
        _shop: &'a ShopDomain,
        token: ShopToken,
    ) -> crate::tokens::StoreFuture<'a, ()> {
        *self.later.lock().expect("lock") = Some(token);
        Box::pin(async { Ok(()) })
    }

    fn delete<'a>(&'a self, _shop: &'a ShopDomain) -> crate::tokens::StoreFuture<'a, ()> {
        *self.later.lock().expect("lock") = None;
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test]
async fn a_refused_refresh_uses_and_keeps_a_pair_another_replica_stored() {
    let stub = Stub::start(vec![StubResponse::json(
        401,
        &json!({"error": "invalid_request"}),
    )])
    .await;
    let replica_pair = ShopToken::non_expiring("shpat_other_replica", "read_orders").with_refresh(
        NOW + 3_600,
        "shprt_other_replica",
        None,
    );
    let store = Arc::new(SwapStore {
        reads: std::sync::Mutex::new(0),
        first: expiring_token(NOW),
        later: std::sync::Mutex::new(Some(replica_pair.clone())),
    });
    let runtime = ShopifyPlugin::new()
        .admin_base_url(stub.base_url.clone())
        .token_store(store.clone())
        .build_runtime(config(Some(OAUTH_TOML), &[]))
        .expect("runtime");
    // The refused caller uses the fresh pair of the other replica.
    let client = runtime
        .client_for(&shop(), NOW)
        .await
        .expect("replica pair");
    assert_eq!(client.shop(), &shop());
    assert_eq!(
        store.later.lock().expect("lock").clone(),
        Some(replica_pair),
        "the newer pair survives"
    );
}

#[tokio::test]
async fn a_cancelled_caller_does_not_lose_the_rotated_pair() {
    let stub = Stub::start(vec![
        StubResponse::json(200, &refreshed_json()).delayed(Duration::from_millis(200)),
    ])
    .await;
    let runtime = oauth_runtime(&stub);
    runtime
        .token_store()
        .put(&shop(), expiring_token(NOW))
        .await
        .expect("put");
    let cancelled =
        tokio::time::timeout(Duration::from_millis(20), runtime.client_for(&shop(), NOW)).await;
    assert!(cancelled.is_err(), "the caller gave up");
    tokio::time::sleep(Duration::from_millis(600)).await;
    let stored = runtime
        .token_store()
        .get(&shop())
        .await
        .expect("get")
        .expect("kept");
    assert_eq!(
        stored.access_token, "shpat_fresh",
        "the refresh task finished"
    );
}

#[tokio::test]
async fn an_uninstall_during_a_refresh_wins() {
    let stub = Stub::start(vec![
        StubResponse::json(200, &refreshed_json()).delayed(Duration::from_millis(200)),
    ])
    .await;
    let runtime = Arc::new(oauth_runtime(&stub));
    runtime
        .token_store()
        .put(&shop(), expiring_token(NOW))
        .await
        .expect("put");
    let refresher = {
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move { runtime.client_for(&shop(), NOW).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    let deleted = runtime
        .keeper()
        .delete_for_event(&shop(), Some(NOW))
        .await
        .expect("delete");
    assert!(deleted);
    refresher
        .await
        .expect("joins")
        .expect("the refresh itself worked");
    assert!(
        runtime
            .token_store()
            .get(&shop())
            .await
            .expect("get")
            .is_none(),
        "the refresh does not bring the token back"
    );
}

#[tokio::test]
async fn a_late_uninstall_keeps_a_token_from_a_later_install() {
    let runtime = ShopifyPlugin::new()
        .build_runtime(config(Some(OAUTH_TOML), &[]))
        .expect("runtime");
    let token = ShopToken::non_expiring("shpat_new_install", "read_orders").with_installed_at(NOW);
    runtime
        .token_store()
        .put(&shop(), token)
        .await
        .expect("put");
    let deleted = runtime
        .keeper()
        .delete_for_event(&shop(), Some(NOW - 3_600))
        .await
        .expect("delete");
    assert!(!deleted);
    assert!(
        runtime
            .token_store()
            .get(&shop())
            .await
            .expect("get")
            .is_some()
    );
    assert!(
        runtime
            .keeper()
            .delete_for_event(&shop(), None)
            .await
            .expect("delete")
    );
}

// ── Review round 1: plugin surface ───────────────────────────────────

#[test]
fn every_plugin_route_is_classified_public() {
    use autumn_web::route_listing::RouteClassification;
    let (_, infos) = mount();
    assert_eq!(infos.len(), 3);
    for info in &infos {
        assert_eq!(
            info.classification,
            RouteClassification::Public,
            "{} {} must pass `autumn routes audit`",
            info.method,
            info.path
        );
        assert!(info.path.starts_with("/shopify/"), "{}", info.path);
    }
}

#[test]
fn admin_base_url_must_be_loopback() {
    for base in ["https://evil.example.com", "not a url", "ftp://127.0.0.1"] {
        let err = ShopifyPlugin::new()
            .admin_base_url(base)
            .build_runtime(config(None, &[]))
            .expect_err(base);
        assert_eq!(err.kind(), ErrorKind::Config);
    }
    for base in [
        "http://127.0.0.1:9",
        "http://localhost:3000",
        "https://[::1]:8443",
    ] {
        ShopifyPlugin::new()
            .admin_base_url(base)
            .build_runtime(config(None, &[]))
            .expect(base);
    }
}

#[test]
fn warnings_name_a_half_set_single_store_mode() {
    let runtime = ShopifyPlugin::new()
        .build_runtime(config(None, &[("SHOPIFY_SHOP", SHOP)]))
        .expect("runtime");
    let warnings = startup_warnings(&runtime, &autumn_web::config::AutumnConfig::default());
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("SHOPIFY_ACCESS_TOKEN"));
}

#[test]
fn install_url_points_at_the_install_route() {
    assert_eq!(
        Shopify::install_url(&shop()),
        "/shopify/auth?shop=my-store.myshopify.com"
    );
}

#[tokio::test]
async fn an_uninstall_keeps_the_per_shop_lock_entry() {
    let runtime = ShopifyPlugin::new()
        .build_runtime(config(Some(OAUTH_TOML), &[]))
        .expect("runtime");
    let before = runtime.keeper().lock_for(&shop()).expect("lock");
    runtime
        .keeper()
        .delete_for_event(&shop(), None)
        .await
        .expect("delete");
    let after = runtime.keeper().lock_for(&shop()).expect("lock");
    assert!(
        Arc::ptr_eq(&before, &after),
        "one shop keeps one lock, so an uninstall and an install never overlap"
    );
}

#[test]
fn install_context_new_fills_the_state_from_the_handle() {
    let state = state(Some(
        ShopifyPlugin::new()
            .build_runtime(config(Some(OAUTH_TOML), &[]))
            .expect("runtime"),
    ));
    let shopify = Shopify::from_state(&state).expect("handle");
    let ctx = InstallContext::new(shop(), "read_orders", shopify);
    assert_eq!(ctx.scope, "read_orders");
    assert!(format!("{ctx:?}").contains("my-store.myshopify.com"));
}

#[tokio::test]
async fn the_health_indicator_is_health_only_and_does_not_retry() {
    use autumn_web::actuator::{HealthStatus, IndicatorGroup};
    let stub = Stub::start(vec![
        StubResponse::text(429, "slow down").header("retry-after", "0.001"),
    ])
    .await;
    let state = state(None);
    ShopifyPlugin::new()
        .admin_base_url(stub.base_url.clone())
        .start(
            &state,
            config(
                None,
                &[
                    ("SHOPIFY_SHOP", SHOP),
                    ("SHOPIFY_ACCESS_TOKEN", "shpat_fixed"),
                ],
            ),
        )
        .expect("starts");
    let results = state.health_indicator_registry().run_all().await;
    let shopify = results
        .iter()
        .find(|result| result.name == "shopify")
        .expect("indicator registered");
    assert!(
        matches!(shopify.group, IndicatorGroup::HealthOnly),
        "not in /ready"
    );
    assert_eq!(shopify.output.status, HealthStatus::Down);
    assert_eq!(stub.requests().len(), 1, "a probe does not retry");
}
