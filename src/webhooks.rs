//! Signed webhooks, routed by topic.
//!
//! `POST /shopify/webhooks` receives every webhook Shopify sends. The
//! [`VerifiedWebhook`] extractor checks the HMAC on the raw body (401 on
//! failure, on every topic) and reads the `X-Shopify-*` headers. The route
//! then:
//!
//! 1. Claims the webhook id. A duplicate gets 200 and no handler runs.
//! 2. Deletes the shop token on `app/uninstalled` and `shop/redact`.
//! 3. Runs the handler for the topic. No handler: 200 and a warning.
//! 4. Answers 200 on success. On failure it releases the claim and answers
//!    500, so that Shopify retries.
//!
//! Shopify waits 5 seconds. Do slow work in a background job.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use autumn_web::reexports::axum::body::{Bytes, to_bytes};
use autumn_web::reexports::axum::extract::{FromRequest, Request};
use autumn_web::reexports::http::{HeaderMap, StatusCode};
use autumn_web::{AppState, AutumnError, AutumnResult, State, post, routes};
use serde::de::DeserializeOwned;

use crate::error::{Error, Result};
use crate::plugin::{Shopify, ShopifyRuntime};
use crate::types::{ShopDomain, Topic};
use crate::verify::{HMAC_HEADER, verify_webhook};

/// The largest webhook body the extractor reads: 5 MiB.
pub const MAX_BODY_BYTES: usize = 5 * 1024 * 1024;
/// Header with the webhook topic.
pub const TOPIC_HEADER: &str = "x-shopify-topic";
/// Header with the shop domain.
pub const SHOP_HEADER: &str = "x-shopify-shop-domain";
/// Header with the webhook id. Retries of one webhook share it.
pub const WEBHOOK_ID_HEADER: &str = "x-shopify-webhook-id";
/// Header with the event id. Deliveries from one merchant action share it.
pub const EVENT_ID_HEADER: &str = "x-shopify-event-id";
/// Header with the API version of the payload.
pub const API_VERSION_HEADER: &str = "x-shopify-api-version";
/// Header with the time Shopify triggered the webhook.
pub const TRIGGERED_AT_HEADER: &str = "x-shopify-triggered-at";

/// A webhook whose HMAC verified.
///
/// Use it on a custom route. HMAC failures give 401 before the handler
/// runs. `Debug` leaves out the body.
pub struct VerifiedWebhook {
    /// The topic, for example `orders/create`.
    pub topic: Topic,
    /// The shop that sent the webhook.
    pub shop: ShopDomain,
    /// The webhook id (`X-Shopify-Webhook-Id`).
    pub webhook_id: String,
    /// The event id (`X-Shopify-Event-Id`), if sent.
    pub event_id: Option<String>,
    /// The payload API version (`X-Shopify-Api-Version`), if sent.
    pub api_version: Option<String>,
    /// The trigger time (`X-Shopify-Triggered-At`), if sent.
    pub triggered_at: Option<String>,
    /// The raw, verified body.
    pub body: Bytes,
    /// The plugin runtime.
    pub runtime: Arc<ShopifyRuntime>,
}

impl std::fmt::Debug for VerifiedWebhook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedWebhook")
            .field("topic", &self.topic)
            .field("shop", &self.shop)
            .field("webhook_id", &self.webhook_id)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

impl VerifiedWebhook {
    /// Verify the HMAC and read the headers.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Signature`] when the HMAC fails, and
    /// [`Error::InvalidRequest`] when a required header is missing or bad.
    pub fn from_parts(
        runtime: Arc<ShopifyRuntime>,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<Self> {
        // The HMAC check runs first, on the raw bytes, before any header or
        // body parsing.
        verify_webhook(runtime.secrets(), header(headers, HMAC_HEADER), &body)?;
        let topic = Topic::parse(required(headers, TOPIC_HEADER)?)?;
        let shop = ShopDomain::parse(required(headers, SHOP_HEADER)?)?;
        let webhook_id = required(headers, WEBHOOK_ID_HEADER)?.to_owned();
        Ok(Self {
            topic,
            shop,
            webhook_id,
            event_id: header(headers, EVENT_ID_HEADER).map(ToOwned::to_owned),
            api_version: header(headers, API_VERSION_HEADER).map(ToOwned::to_owned),
            triggered_at: header(headers, TRIGGERED_AT_HEADER).map(ToOwned::to_owned),
            body,
            runtime,
        })
    }

    /// Parse the body as JSON.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Json`] when the body does not match `T`.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(Error::Json)
    }
}

impl FromRequest<AppState> for VerifiedWebhook {
    type Rejection = AutumnError;

    async fn from_request(
        req: Request,
        state: &AppState,
    ) -> std::result::Result<Self, Self::Rejection> {
        let runtime = state
            .extension::<ShopifyRuntime>()
            .ok_or_else(|| Error::MissingRuntime.to_autumn_error())?;
        let (parts, body) = req.into_parts();
        let body = to_bytes(body, MAX_BODY_BYTES).await.map_err(|_| {
            Error::PayloadTooLarge {
                limit: MAX_BODY_BYTES,
            }
            .to_autumn_error()
        })?;
        Self::from_parts(runtime, &parts.headers, body).map_err(|err| {
            tracing::warn!(error = %err, "shopify webhook rejected");
            err.to_autumn_error()
        })
    }
}

/// What a webhook handler receives.
#[derive(Clone)]
pub struct WebhookContext {
    /// The topic.
    pub topic: Topic,
    /// The shop that sent the webhook.
    pub shop: ShopDomain,
    /// The webhook id.
    pub webhook_id: String,
    /// The event id, if sent.
    pub event_id: Option<String>,
    /// The payload API version, if sent.
    pub api_version: Option<String>,
    /// The trigger time, if sent.
    pub triggered_at: Option<String>,
    /// The raw, verified body.
    pub body: Bytes,
    /// The app state: enqueue jobs, reach the database.
    pub state: AppState,
    /// The plugin handle: Admin API clients.
    pub shopify: Shopify,
}

impl std::fmt::Debug for WebhookContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookContext")
            .field("topic", &self.topic)
            .field("shop", &self.shop)
            .field("webhook_id", &self.webhook_id)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

impl WebhookContext {
    /// Parse the body as JSON.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Json`] when the body does not match `T`.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(Error::Json)
    }
}

/// The future a webhook handler returns.
pub type WebhookFuture = Pin<Box<dyn Future<Output = AutumnResult<()>> + Send + 'static>>;

/// A type-erased webhook handler.
pub type WebhookHandler = Arc<dyn Fn(WebhookContext) -> WebhookFuture + Send + Sync + 'static>;

/// Turns an async function into a [`WebhookHandler`].
pub trait IntoWebhookHandler {
    /// Erase the handler type.
    fn into_handler(self) -> WebhookHandler;
}

impl<F, Fut> IntoWebhookHandler for F
where
    F: Fn(WebhookContext) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = AutumnResult<()>> + Send + 'static,
{
    fn into_handler(self) -> WebhookHandler {
        Arc::new(move |ctx| Box::pin(self(ctx)))
    }
}

/// Webhook handlers by topic.
#[derive(Clone, Default)]
pub struct WebhookRegistry {
    handlers: HashMap<Topic, WebhookHandler>,
}

impl std::fmt::Debug for WebhookRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookRegistry")
            .field("topics", &self.topics())
            .finish()
    }
}

impl WebhookRegistry {
    /// Make an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `handler` for `topic`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the topic is malformed or already has
    /// a handler.
    pub fn register(&mut self, topic: &str, handler: WebhookHandler) -> Result<()> {
        let topic = Topic::parse(topic).map_err(|err| Error::Config(err.to_string()))?;
        if self.handlers.contains_key(&topic) {
            return Err(Error::Config(format!(
                "webhook topic {topic} has two handlers"
            )));
        }
        self.handlers.insert(topic, handler);
        Ok(())
    }

    /// The registered topics, sorted.
    #[must_use]
    pub fn topics(&self) -> Vec<&str> {
        let mut topics: Vec<&str> = self.handlers.keys().map(Topic::as_str).collect();
        topics.sort_unstable();
        topics
    }

    /// True when `topic` has a handler.
    #[must_use]
    pub fn contains(&self, topic: &str) -> bool {
        Topic::parse(topic).is_ok_and(|topic| self.handlers.contains_key(&topic))
    }

    /// The handler for `topic`.
    #[must_use]
    pub fn get(&self, topic: &Topic) -> Option<&WebhookHandler> {
        self.handlers.get(topic)
    }
}

/// What the webhook route did with one delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookOutcome {
    /// A handler ran and succeeded.
    Handled,
    /// The webhook id was seen before; nothing ran.
    Duplicate,
    /// No handler is registered for the topic.
    Unhandled,
}

/// Run one verified webhook: claim, token cleanup, dispatch.
///
/// The plugin route calls this. Call it from a custom route that uses
/// [`VerifiedWebhook`].
///
/// # Errors
///
/// Returns the handler error, or a store error. The claim is released
/// first, so that a Shopify retry runs again.
pub async fn process(state: &AppState, webhook: VerifiedWebhook) -> AutumnResult<WebhookOutcome> {
    let runtime = Arc::clone(&webhook.runtime);
    let deliveries = runtime.delivery_store();
    let now = state.clock().now().timestamp();
    let fresh = deliveries
        .claim(&webhook.webhook_id, now)
        .await
        .map_err(|err| err.to_autumn_error())?;
    if !fresh {
        tracing::info!(
            topic = %webhook.topic,
            shop = %webhook.shop,
            webhook_id = %webhook.webhook_id,
            "shopify webhook is a duplicate; skipped"
        );
        return Ok(WebhookOutcome::Duplicate);
    }
    let webhook_id = webhook.webhook_id.clone();
    let result = dispatch(state, webhook).await;
    if result.is_err() {
        // Release the claim, so that the Shopify retry runs again.
        if let Err(err) = deliveries.release(&webhook_id).await {
            tracing::error!(error = %err, webhook_id = %webhook_id, "shopify webhook claim release failed");
        }
    }
    result
}

/// Token cleanup, then the handler for the topic.
async fn dispatch(state: &AppState, webhook: VerifiedWebhook) -> AutumnResult<WebhookOutcome> {
    let runtime = Arc::clone(&webhook.runtime);
    let topic = webhook.topic.as_str();
    if topic == Topic::APP_UNINSTALLED || topic == Topic::SHOP_REDACT {
        runtime
            .token_store()
            .delete(&webhook.shop)
            .await
            .map_err(|err| err.to_autumn_error())?;
        tracing::info!(shop = %webhook.shop, topic, "shopify token deleted");
    }
    let Some(handler) = runtime.registry().get(&webhook.topic) else {
        tracing::warn!(
            topic = %webhook.topic,
            shop = %webhook.shop,
            "shopify webhook has no handler; answered 200"
        );
        return Ok(WebhookOutcome::Unhandled);
    };
    let ctx = WebhookContext {
        topic: webhook.topic,
        shop: webhook.shop,
        webhook_id: webhook.webhook_id,
        event_id: webhook.event_id,
        api_version: webhook.api_version,
        triggered_at: webhook.triggered_at,
        body: webhook.body,
        state: state.clone(),
        shopify: Shopify::from_runtime(Arc::clone(&runtime), state.clone()),
    };
    let topic = ctx.topic.clone();
    let shop = ctx.shop.clone();
    handler(ctx).await.map_err(|err| {
        tracing::warn!(topic = %topic, shop = %shop, error = %err, "shopify webhook handler failed");
        err
    })?;
    Ok(WebhookOutcome::Handled)
}

/// A header value as `&str`; `None` when missing, blank, or not ASCII.
fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)?
        .to_str()
        .ok()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// A required header.
fn required<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str> {
    header(headers, name).ok_or_else(|| Error::InvalidRequest(format!("missing {name} header")))
}

/// The plugin webhook route.
#[post("/webhooks")]
async fn webhooks_route(
    State(state): State<AppState>,
    webhook: VerifiedWebhook,
) -> AutumnResult<StatusCode> {
    process(&state, webhook).await?;
    Ok(StatusCode::OK)
}

/// The webhook route, for the plugin to mount under `/shopify`.
pub(crate) fn webhook_routes() -> Vec<autumn_web::Route> {
    routes![webhooks_route]
}

#[cfg(test)]
mod tests;
