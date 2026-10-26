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
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::Arc;

use autumn_web::reexports::axum::body::{Bytes, to_bytes};
use autumn_web::reexports::axum::extract::{FromRequest, Request};
use autumn_web::reexports::http::{HeaderMap, StatusCode};
use autumn_web::{AppState, AutumnError, AutumnResult, State, post, public, routes};
use futures::FutureExt as _;
use serde::de::DeserializeOwned;

use crate::delivery::Claim;
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
///
/// The HMAC covers the body only. The `X-Shopify-*` headers (topic, shop,
/// ids, times) are not signed. Read the shop from the body when a wrong
/// shop can do damage.
#[non_exhaustive]
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
        let body = to_bytes(body, MAX_BODY_BYTES).await.map_err(|err| {
            if is_length_limit(&err) {
                Error::PayloadTooLarge {
                    limit: MAX_BODY_BYTES,
                }
            } else {
                Error::InvalidRequest("the webhook body does not read".to_owned())
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
///
/// The HMAC covers `body` only. The header values (`topic`, `shop`, the
/// ids, `triggered_at`) are not signed.
#[derive(Clone)]
#[non_exhaustive]
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
    /// Make a context, for example to test a handler. The optional header
    /// values start as `None`.
    #[must_use]
    pub fn new(
        topic: Topic,
        shop: ShopDomain,
        webhook_id: impl Into<String>,
        body: impl Into<Bytes>,
        shopify: Shopify,
    ) -> Self {
        Self {
            topic,
            shop,
            webhook_id: webhook_id.into(),
            event_id: None,
            api_version: None,
            triggered_at: None,
            body: body.into(),
            state: shopify.state().clone(),
            shopify,
        }
    }

    /// The Admin API client for the shop that sent the webhook.
    ///
    /// # Errors
    ///
    /// See [`ShopifyRuntime::client_for`].
    pub async fn client(&self) -> Result<crate::client::ShopifyClient> {
        self.shopify.client_for(&self.shop).await
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
#[non_exhaustive]
pub enum WebhookOutcome {
    /// A handler ran and succeeded.
    Handled,
    /// The store already has this webhook id as done. No handler ran.
    Duplicate,
    /// The topic has no handler.
    Unhandled,
}

/// Run one verified webhook: claim, token cleanup, dispatch.
///
/// The plugin route calls this. Call it from a custom route that uses
/// [`VerifiedWebhook`].
///
/// The handler runs in its own task. A panic in the handler, or a request
/// that the server drops (timeout, closed connection), does not keep the
/// claim: the task releases it, so that the next Shopify retry runs the
/// handler again.
///
/// # Errors
///
/// Returns [`Error::InProgress`] (409) when another delivery of the same
/// webhook id still runs, the handler error, a panic as 500, or a store
/// error.
pub async fn process(state: &AppState, webhook: VerifiedWebhook) -> AutumnResult<WebhookOutcome> {
    let runtime = Arc::clone(&webhook.runtime);
    let now = state.clock().now().timestamp();
    let claim = runtime
        .delivery_store()
        .claim(&webhook.webhook_id, now)
        .await
        .map_err(|err| err.to_autumn_error())?;
    match claim {
        Claim::Fresh => {}
        Claim::Done => {
            tracing::info!(
                topic = %webhook.topic,
                shop = %webhook.shop,
                webhook_id = %webhook.webhook_id,
                "shopify webhook is a duplicate; skipped"
            );
            return Ok(WebhookOutcome::Duplicate);
        }
        _ => {
            return Err(Error::InProgress(webhook.webhook_id).to_autumn_error());
        }
    }
    let state = state.clone();
    let task = tokio::spawn(async move {
        let webhook_id = webhook.webhook_id.clone();
        let deliveries = Arc::clone(webhook.runtime.delivery_store());
        let outcome = AssertUnwindSafe(dispatch(&state, webhook))
            .catch_unwind()
            .await
            .unwrap_or_else(|_| {
                tracing::error!(webhook_id = %webhook_id, "shopify webhook handler panicked");
                Err(AutumnError::internal_server_error_msg(
                    "the shopify webhook handler panicked",
                ))
            });
        let settled = if outcome.is_ok() {
            deliveries.complete(&webhook_id).await
        } else {
            deliveries.release(&webhook_id).await
        };
        if let Err(err) = settled {
            tracing::error!(error = %err, webhook_id = %webhook_id, "shopify webhook claim update failed");
        }
        outcome
    });
    task.await.unwrap_or_else(|_| {
        Err(AutumnError::internal_server_error_msg(
            "the shopify webhook task stopped",
        ))
    })
}

/// Token cleanup, then the handler for the topic.
async fn dispatch(state: &AppState, webhook: VerifiedWebhook) -> AutumnResult<WebhookOutcome> {
    let runtime = Arc::clone(&webhook.runtime);
    let topic = webhook.topic.as_str();
    if topic == Topic::APP_UNINSTALLED || topic == Topic::SHOP_REDACT {
        check_body_shop(&webhook).map_err(|err| err.to_autumn_error())?;
        let event_at = webhook.triggered_at.as_deref().and_then(parse_time);
        let deleted = runtime
            .keeper()
            .delete_for_event(&webhook.shop, event_at)
            .await
            .map_err(|err| err.to_autumn_error())?;
        if deleted {
            tracing::info!(shop = %webhook.shop, topic, "shopify token deleted");
        } else {
            tracing::info!(shop = %webhook.shop, topic, "shopify token is from a later install; kept");
        }
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

/// For a token-deleting topic, check that the shop in the signed body is
/// the shop in the (unsigned) header.
///
/// `app/uninstalled` carries `myshopify_domain`; `shop/redact` carries
/// `shop_domain`. A body without the field passes.
fn check_body_shop(webhook: &VerifiedWebhook) -> Result<()> {
    let field = if webhook.topic.as_str() == Topic::SHOP_REDACT {
        "shop_domain"
    } else {
        "myshopify_domain"
    };
    let body: serde_json::Value = webhook.json()?;
    match body.get(field).and_then(serde_json::Value::as_str) {
        Some(domain) if !domain.eq_ignore_ascii_case(webhook.shop.as_str()) => Err(
            Error::InvalidRequest(format!("the body {field} does not match {SHOP_HEADER}")),
        ),
        _ => Ok(()),
    }
}

/// Parse an RFC 3339 time into Unix seconds.
fn parse_time(text: &str) -> Option<i64> {
    autumn_web::reexports::chrono::DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|time| time.timestamp())
}

/// True when `err` comes from the body length limit.
fn is_length_limit(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(err);
    while let Some(err) = current {
        if err.is::<http_body_util::LengthLimitError>() {
            return true;
        }
        current = err.source();
    }
    false
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
#[public]
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
