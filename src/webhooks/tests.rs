//! Webhook route tests: HMAC, headers, duplicates, dispatch, cleanup.

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use autumn_web::AutumnError;

use super::*;
use crate::error::ErrorKind;
use crate::plugin::ShopifyPlugin;
use crate::test_support::{SECRET, SHOP, app, config, state};
use crate::tokens::ShopToken;
use crate::verify::sign_webhook;

const BODY: &str = r#"{"id":820982911946154508,"email":"jon@example.com"}"#;

type Seen = Arc<Mutex<Vec<WebhookContext>>>;

#[derive(Debug, serde::Deserialize)]
struct Wrong {
    #[allow(dead_code)]
    missing: String,
}

fn recorder(seen: &Seen) -> impl Fn(WebhookContext) -> WebhookFuture + Send + Sync + 'static {
    let seen = Arc::clone(seen);
    move |ctx| {
        let seen = Arc::clone(&seen);
        Box::pin(async move {
            seen.lock().expect("lock").push(ctx);
            Ok(())
        })
    }
}

fn plugin_with(seen: &Seen) -> ShopifyPlugin {
    ShopifyPlugin::new()
        .webhook("orders/create", recorder(seen))
        .webhook("app/uninstalled", recorder(seen))
        .webhook("shop/redact", recorder(seen))
}

fn setup(plugin: &ShopifyPlugin) -> AppState {
    state(Some(
        plugin.build_runtime(config(None, &[])).expect("runtime"),
    ))
}

struct Delivery<'a> {
    topic: &'a str,
    id: &'a str,
    body: Vec<u8>,
    hmac: Option<String>,
    shop: Option<&'a str>,
}

impl<'a> Delivery<'a> {
    fn new(topic: &'a str, id: &'a str) -> Self {
        Self {
            topic,
            id,
            body: BODY.as_bytes().to_vec(),
            hmac: Some(sign_webhook(SECRET, BODY.as_bytes())),
            shop: Some(SHOP),
        }
    }

    async fn send(self, state: &AppState) -> autumn_web::test::TestResponse {
        let client = app(state);
        let mut request = client.post("/shopify/webhooks");
        if !self.topic.is_empty() {
            request = request.header(TOPIC_HEADER, self.topic);
        }
        if !self.id.is_empty() {
            request = request.header(WEBHOOK_ID_HEADER, self.id);
        }
        if let Some(shop) = self.shop {
            request = request.header(SHOP_HEADER, shop);
        }
        if let Some(hmac) = &self.hmac {
            request = request.header(HMAC_HEADER, hmac);
        }
        request
            .header(EVENT_ID_HEADER, "evt-1")
            .header(API_VERSION_HEADER, "2026-10")
            .header(TRIGGERED_AT_HEADER, "2026-10-26T00:00:00Z")
            .header("content-type", "application/json")
            .body(self.body)
            .send()
            .await
    }
}

#[tokio::test]
async fn a_valid_delivery_runs_the_handler_with_full_context() {
    let seen = Seen::default();
    let state = setup(&plugin_with(&seen));
    Delivery::new("orders/create", "w-1")
        .send(&state)
        .await
        .assert_status(200);

    let ctx = {
        let seen = seen.lock().expect("lock");
        assert_eq!(seen.len(), 1);
        seen[0].clone()
    };
    assert_eq!(ctx.topic.as_str(), "orders/create");
    assert_eq!(ctx.shop.as_str(), SHOP);
    assert_eq!(ctx.webhook_id, "w-1");
    assert_eq!(ctx.event_id.as_deref(), Some("evt-1"));
    assert_eq!(ctx.api_version.as_deref(), Some("2026-10"));
    assert_eq!(ctx.triggered_at.as_deref(), Some("2026-10-26T00:00:00Z"));
    assert_eq!(ctx.body.as_ref(), BODY.as_bytes());
    let order: serde_json::Value = ctx.json().expect("json body");
    assert_eq!(order["email"], "jon@example.com");
    assert_eq!(
        ctx.json::<Wrong>().expect_err("wrong shape").kind(),
        ErrorKind::Json
    );
    assert!(!format!("{ctx:?}").contains("jon@example.com"));
}

#[tokio::test]
async fn hmac_failures_are_401_on_every_topic() {
    let seen = Seen::default();
    let state = setup(&plugin_with(&seen));
    for topic in [
        "orders/create",
        "customers/redact",
        "customers/data_request",
        "shop/redact",
    ] {
        let mut bad = Delivery::new(topic, "w-bad");
        bad.hmac = Some(sign_webhook("wrong-secret", BODY.as_bytes()));
        bad.send(&state).await.assert_status(401);

        let mut missing = Delivery::new(topic, "w-missing");
        missing.hmac = None;
        missing.send(&state).await.assert_status(401);

        let mut garbage = Delivery::new(topic, "w-garbage");
        garbage.hmac = Some("%%%".into());
        garbage.send(&state).await.assert_status(401);
    }
    assert!(seen.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn a_changed_body_is_401() {
    let seen = Seen::default();
    let state = setup(&plugin_with(&seen));
    let mut delivery = Delivery::new("orders/create", "w-1");
    delivery.body = BODY.replace("jon", "eve").into_bytes();
    delivery.send(&state).await.assert_status(401);
    assert!(seen.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn hmac_runs_before_header_checks() {
    let state = setup(&plugin_with(&Seen::default()));
    let mut delivery = Delivery::new("", "");
    delivery.hmac = None;
    delivery.send(&state).await.assert_status(401);
}

#[tokio::test]
async fn missing_or_bad_headers_are_400() {
    let seen = Seen::default();
    let state = setup(&plugin_with(&seen));
    Delivery::new("", "w-1")
        .send(&state)
        .await
        .assert_status(400);
    Delivery::new("orders/create", "")
        .send(&state)
        .await
        .assert_status(400);
    Delivery::new("Orders/Create", "w-1")
        .send(&state)
        .await
        .assert_status(400);
    let mut no_shop = Delivery::new("orders/create", "w-1");
    no_shop.shop = None;
    no_shop.send(&state).await.assert_status(400);
    let mut bad_shop = Delivery::new("orders/create", "w-1");
    bad_shop.shop = Some("evil.com");
    bad_shop.send(&state).await.assert_status(400);
    assert!(seen.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn an_oversized_body_is_413() {
    let state = setup(&plugin_with(&Seen::default()));
    let mut delivery = Delivery::new("orders/create", "w-1");
    delivery.body = vec![b' '; MAX_BODY_BYTES + 1];
    delivery.hmac = Some(sign_webhook(SECRET, &delivery.body));
    delivery.send(&state).await.assert_status(413);
}

#[tokio::test]
async fn a_duplicate_webhook_id_is_200_and_runs_nothing() {
    let seen = Seen::default();
    let state = setup(&plugin_with(&seen));
    Delivery::new("orders/create", "w-dup")
        .send(&state)
        .await
        .assert_status(200);
    Delivery::new("orders/create", "w-dup")
        .send(&state)
        .await
        .assert_status(200);
    assert_eq!(seen.lock().expect("lock").len(), 1);
}

#[tokio::test]
async fn a_failed_handler_is_500_and_its_retry_runs_again() {
    let calls = Arc::new(Mutex::new(0u32));
    let counter = Arc::clone(&calls);
    let plugin = ShopifyPlugin::new().webhook("orders/create", move |_ctx: WebhookContext| {
        let counter = Arc::clone(&counter);
        async move {
            let mut calls = counter.lock().expect("lock");
            *calls += 1;
            if *calls == 1 {
                Err(AutumnError::internal_server_error_msg("database down"))
            } else {
                Ok(())
            }
        }
    });
    let state = setup(&plugin);
    Delivery::new("orders/create", "w-retry")
        .send(&state)
        .await
        .assert_status(500);
    Delivery::new("orders/create", "w-retry")
        .send(&state)
        .await
        .assert_status(200);
    Delivery::new("orders/create", "w-retry")
        .send(&state)
        .await
        .assert_status(200);
    assert_eq!(*calls.lock().expect("lock"), 2);
}

#[tokio::test]
async fn an_unknown_topic_is_200_and_runs_nothing() {
    let seen = Seen::default();
    let state = setup(&plugin_with(&seen));
    Delivery::new("products/update", "w-1")
        .send(&state)
        .await
        .assert_status(200);
    assert!(seen.lock().expect("lock").is_empty());
}

async fn token_is_gone_before_handler(topic: &'static str) {
    let token_seen_by_handler = Arc::new(Mutex::new(Some(true)));
    let flag = Arc::clone(&token_seen_by_handler);
    let plugin = ShopifyPlugin::new().webhook(topic, move |ctx: WebhookContext| {
        let flag = Arc::clone(&flag);
        async move {
            let token = ctx
                .shopify
                .runtime()
                .token_store()
                .get(&ctx.shop)
                .await
                .map_err(|e| e.to_autumn_error())?;
            *flag.lock().expect("lock") = Some(token.is_some());
            Ok(())
        }
    });
    let state = setup(&plugin);
    let runtime = state.extension::<ShopifyRuntime>().expect("runtime");
    let shop = ShopDomain::parse(SHOP).expect("shop");
    runtime
        .token_store()
        .put(&shop, ShopToken::non_expiring("shpat_x", "read_orders"))
        .await
        .expect("put");

    Delivery::new(topic, "w-1")
        .send(&state)
        .await
        .assert_status(200);
    assert!(
        runtime
            .token_store()
            .get(&shop)
            .await
            .expect("get")
            .is_none()
    );
    assert_eq!(*token_seen_by_handler.lock().expect("lock"), Some(false));
}

#[tokio::test]
async fn app_uninstalled_deletes_the_token_first() {
    token_is_gone_before_handler("app/uninstalled").await;
}

#[tokio::test]
async fn shop_redact_deletes_the_token_first() {
    token_is_gone_before_handler("shop/redact").await;
}

#[tokio::test]
async fn uninstall_without_a_handler_still_deletes_the_token() {
    let state = setup(&ShopifyPlugin::new());
    let runtime = state.extension::<ShopifyRuntime>().expect("runtime");
    let shop = ShopDomain::parse(SHOP).expect("shop");
    runtime
        .token_store()
        .put(&shop, ShopToken::non_expiring("shpat_x", "read_orders"))
        .await
        .expect("put");
    Delivery::new("app/uninstalled", "w-1")
        .send(&state)
        .await
        .assert_status(200);
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
async fn the_previous_secret_verifies_during_rotation() {
    let seen = Seen::default();
    let runtime = plugin_with(&seen)
        .build_runtime(config(
            None,
            &[("SHOPIFY_API_SECRET_PREVIOUS", "old-secret")],
        ))
        .expect("runtime");
    let state = state(Some(runtime));
    let mut delivery = Delivery::new("orders/create", "w-1");
    delivery.hmac = Some(sign_webhook("old-secret", BODY.as_bytes()));
    delivery.send(&state).await.assert_status(200);
    assert_eq!(seen.lock().expect("lock").len(), 1);
}

#[tokio::test]
async fn no_runtime_is_503() {
    let state = state(None);
    Delivery::new("orders/create", "w-1")
        .send(&state)
        .await
        .assert_status(503);
}

#[tokio::test]
async fn process_reports_each_outcome() {
    let seen = Seen::default();
    let state = setup(&plugin_with(&seen));
    let runtime = state.extension::<ShopifyRuntime>().expect("runtime");
    let make = |topic: &str, id: &str| {
        let mut headers = HeaderMap::new();
        headers.insert(TOPIC_HEADER, topic.parse().expect("header"));
        headers.insert(WEBHOOK_ID_HEADER, id.parse().expect("header"));
        headers.insert(SHOP_HEADER, SHOP.parse().expect("header"));
        headers.insert(
            HMAC_HEADER,
            sign_webhook(SECRET, BODY.as_bytes())
                .parse()
                .expect("header"),
        );
        VerifiedWebhook::from_parts(Arc::clone(&runtime), &headers, Bytes::from(BODY))
            .expect("verified")
    };
    assert_eq!(
        process(&state, make("orders/create", "p-1"))
            .await
            .expect("ok"),
        WebhookOutcome::Handled
    );
    assert_eq!(
        process(&state, make("orders/create", "p-1"))
            .await
            .expect("ok"),
        WebhookOutcome::Duplicate
    );
    assert_eq!(
        process(&state, make("carts/update", "p-2"))
            .await
            .expect("ok"),
        WebhookOutcome::Unhandled
    );
    let webhook = make("orders/create", "p-3");
    assert_eq!(
        webhook.json::<serde_json::Value>().expect("json")["id"],
        820_982_911_946_154_508_u64
    );
    assert!(!format!("{webhook:?}").contains("jon@example.com"));
}

#[test]
fn registry_rejects_bad_and_repeated_topics() {
    let handler: WebhookHandler = Arc::new(|_| Box::pin(async { Ok(()) }));
    let mut registry = WebhookRegistry::new();
    registry
        .register("orders/create", Arc::clone(&handler))
        .expect("first");
    registry
        .register("app/uninstalled", Arc::clone(&handler))
        .expect("second");
    let err = registry
        .register("orders/create", Arc::clone(&handler))
        .expect_err("repeat");
    assert_eq!(err.kind(), ErrorKind::Config);
    let err = registry.register("Orders", handler).expect_err("malformed");
    assert_eq!(err.kind(), ErrorKind::Config);
    assert_eq!(registry.topics(), vec!["app/uninstalled", "orders/create"]);
    assert!(registry.contains("orders/create"));
    assert!(!registry.contains("orders/delete"));
    assert!(format!("{registry:?}").contains("orders/create"));
}

#[test]
fn webhook_route_is_declared() {
    let routes = webhook_routes();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].path, "/webhooks");
    assert_eq!(routes[0].method, "POST");
}

// ── Review round 1: claim safety ─────────────────────────────────────

#[tokio::test]
async fn a_panicking_handler_is_500_and_its_retry_runs_again() {
    let calls = Arc::new(Mutex::new(0u32));
    let counter = Arc::clone(&calls);
    let plugin = ShopifyPlugin::new().webhook("orders/create", move |_ctx: WebhookContext| {
        let counter = Arc::clone(&counter);
        async move {
            let first = {
                let mut calls = counter.lock().expect("lock");
                *calls += 1;
                *calls == 1
            };
            assert!(!first, "the first delivery panics");
            Ok(())
        }
    });
    let state = setup(&plugin);
    Delivery::new("orders/create", "w-panic")
        .send(&state)
        .await
        .assert_status(500);
    Delivery::new("orders/create", "w-panic")
        .send(&state)
        .await
        .assert_status(200);
    assert_eq!(*calls.lock().expect("lock"), 2);
}

#[tokio::test]
async fn a_dropped_request_still_settles_the_claim() {
    let calls = Arc::new(Mutex::new(0u32));
    let counter = Arc::clone(&calls);
    let plugin = ShopifyPlugin::new().webhook("orders/create", move |_ctx: WebhookContext| {
        let counter = Arc::clone(&counter);
        async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let mut calls = counter.lock().expect("lock");
            *calls += 1;
            if *calls == 1 {
                Err(AutumnError::internal_server_error_msg("slow and failed"))
            } else {
                Ok(())
            }
        }
    });
    let state = setup(&plugin);
    let dropped = tokio::time::timeout(
        std::time::Duration::from_millis(10),
        Delivery::new("orders/create", "w-drop").send(&state),
    )
    .await;
    assert!(dropped.is_err(), "the server gave up on the request");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    Delivery::new("orders/create", "w-drop")
        .send(&state)
        .await
        .assert_status(200);
    assert_eq!(
        *calls.lock().expect("lock"),
        2,
        "the retry ran the handler again"
    );
}

#[tokio::test]
async fn a_duplicate_while_the_first_still_runs_is_409() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let wait = Arc::clone(&gate);
    let plugin = ShopifyPlugin::new().webhook("orders/create", move |_ctx: WebhookContext| {
        let wait = Arc::clone(&wait);
        async move {
            wait.notified().await;
            Ok(())
        }
    });
    let state = setup(&plugin);
    let first = {
        let state = state.clone();
        tokio::spawn(async move { Delivery::new("orders/create", "w-slow").send(&state).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    Delivery::new("orders/create", "w-slow")
        .send(&state)
        .await
        .assert_status(409);
    gate.notify_one();
    first.await.expect("joins").assert_status(200);
    Delivery::new("orders/create", "w-slow")
        .send(&state)
        .await
        .assert_status(200);
}

// ── Review round 1: token cleanup safety ─────────────────────────────

async fn put_token(state: &AppState, token: ShopToken) -> Arc<ShopifyRuntime> {
    let runtime = state.extension::<ShopifyRuntime>().expect("runtime");
    let shop = ShopDomain::parse(SHOP).expect("shop");
    runtime.token_store().put(&shop, token).await.expect("put");
    runtime
}

#[tokio::test]
async fn an_uninstall_for_another_shop_in_the_body_is_400_and_deletes_nothing() {
    let state = setup(&ShopifyPlugin::new());
    let runtime = put_token(&state, ShopToken::non_expiring("shpat_x", "read_orders")).await;
    let body = br#"{"id":1,"myshopify_domain":"other.myshopify.com"}"#.to_vec();
    let mut delivery = Delivery::new("app/uninstalled", "w-forged");
    delivery.hmac = Some(sign_webhook(SECRET, &body));
    delivery.body = body;
    delivery.send(&state).await.assert_status(400);
    let shop = ShopDomain::parse(SHOP).expect("shop");
    assert!(
        runtime
            .token_store()
            .get(&shop)
            .await
            .expect("get")
            .is_some()
    );

    let body = format!(r#"{{"id":1,"myshopify_domain":"{SHOP}"}}"#).into_bytes();
    let mut delivery = Delivery::new("app/uninstalled", "w-real");
    delivery.hmac = Some(sign_webhook(SECRET, &body));
    delivery.body = body;
    delivery.send(&state).await.assert_status(200);
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
async fn a_shop_redact_for_another_shop_is_400() {
    let state = setup(&ShopifyPlugin::new());
    let body = br#"{"shop_id":1,"shop_domain":"other.myshopify.com"}"#.to_vec();
    let mut delivery = Delivery::new("shop/redact", "w-1");
    delivery.hmac = Some(sign_webhook(SECRET, &body));
    delivery.body = body;
    delivery.send(&state).await.assert_status(400);
}

#[tokio::test]
async fn a_late_uninstall_keeps_the_token_of_a_reinstall() {
    let state = setup(&ShopifyPlugin::new());
    // The token comes from an install after the event (the Delivery helper
    // sends X-Shopify-Triggered-At: 2026-10-26T00:00:00Z).
    let later = parse_time("2026-10-26T01:00:00Z").expect("time");
    let runtime = put_token(
        &state,
        ShopToken::non_expiring("shpat_new", "read_orders").with_installed_at(later),
    )
    .await;
    Delivery::new("app/uninstalled", "w-late")
        .send(&state)
        .await
        .assert_status(200);
    let shop = ShopDomain::parse(SHOP).expect("shop");
    assert!(
        runtime
            .token_store()
            .get(&shop)
            .await
            .expect("get")
            .is_some()
    );
}

/// A token store whose `delete` always fails.
struct BrokenStore;

impl crate::tokens::TokenStore for BrokenStore {
    fn get<'a>(
        &'a self,
        _shop: &'a ShopDomain,
    ) -> crate::tokens::StoreFuture<'a, Option<ShopToken>> {
        Box::pin(async { Ok(None) })
    }
    fn put<'a>(
        &'a self,
        _shop: &'a ShopDomain,
        _token: ShopToken,
    ) -> crate::tokens::StoreFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn delete<'a>(&'a self, _shop: &'a ShopDomain) -> crate::tokens::StoreFuture<'a, ()> {
        Box::pin(async { Err(Error::Store("disk full".into())) })
    }
}

#[tokio::test]
async fn a_store_failure_is_500_and_releases_the_claim() {
    let plugin = ShopifyPlugin::new().token_store(Arc::new(BrokenStore));
    let state = setup(&plugin);
    Delivery::new("app/uninstalled", "w-store")
        .send(&state)
        .await
        .assert_status(500);
    let runtime = state.extension::<ShopifyRuntime>().expect("runtime");
    let claim = runtime
        .delivery_store()
        .claim("w-store", 0)
        .await
        .expect("claim");
    assert_eq!(
        claim,
        crate::delivery::Claim::Fresh,
        "the claim was released"
    );
}

#[tokio::test]
async fn webhook_context_new_and_client_work_in_handler_tests() {
    let state = setup(&ShopifyPlugin::new());
    let shopify = crate::plugin::Shopify::from_state(&state).expect("handle");
    let ctx = WebhookContext::new(
        Topic::parse("orders/create").expect("topic"),
        ShopDomain::parse(SHOP).expect("shop"),
        "w-1",
        BODY,
        shopify,
    );
    assert!(ctx.event_id.is_none());
    assert_eq!(
        ctx.json::<serde_json::Value>().expect("json")["id"],
        820_982_911_946_154_508_u64
    );
    let err = ctx.client().await.expect_err("not installed");
    assert_eq!(err.kind(), ErrorKind::NotInstalled);
}

/// A custom route: the app mounts its own path with the extractor.
#[autumn_web::post("/hooks/shopify")]
async fn custom_route(
    autumn_web::State(state): autumn_web::State<AppState>,
    webhook: VerifiedWebhook,
) -> autumn_web::AutumnResult<String> {
    let outcome = process(&state, webhook).await?;
    Ok(format!("{outcome:?}"))
}

#[tokio::test]
async fn the_extractor_works_on_a_custom_route() {
    let seen = Seen::default();
    let state = setup(&plugin_with(&seen));
    let mut router = axum::Router::new();
    for route in autumn_web::routes![custom_route] {
        router = router.route(route.path, route.handler);
    }
    let client = autumn_web::test::TestApp::from_router(router.with_state(state.clone()), state);
    let send = |hmac: String| {
        client
            .post("/hooks/shopify")
            .header(TOPIC_HEADER, "orders/create")
            .header(WEBHOOK_ID_HEADER, "w-custom")
            .header(SHOP_HEADER, SHOP)
            .header(HMAC_HEADER, &hmac)
            .body(BODY.as_bytes().to_vec())
            .send()
    };
    send(sign_webhook("wrong", BODY.as_bytes()))
        .await
        .assert_status(401);
    let response = send(sign_webhook(SECRET, BODY.as_bytes())).await;
    response.assert_status(200);
    assert_eq!(response.text(), "Handled");
    assert_eq!(seen.lock().expect("lock").len(), 1);
}
