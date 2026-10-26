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
