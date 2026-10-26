//! `autumn-plugin-shopify`: Shopify apps on Autumn.
//!
//! - Signed webhooks, routed by topic, with a duplicate guard.
//! - OAuth install with expiring offline tokens and refresh.
//! - An Admin GraphQL client that retries throttled calls.
//!
//! ```ignore
//! use autumn_plugin_shopify::{ShopifyPlugin, WebhookContext};
//! use autumn_web::prelude::*;
//!
//! async fn order_created(ctx: WebhookContext) -> AutumnResult<()> {
//!     let order: serde_json::Value = ctx.json().map_err(|e| e.to_autumn_error())?;
//!     tracing::info!(shop = %ctx.shop, id = %order["id"], "order created");
//!     Ok(())
//! }
//!
//! #[autumn_web::main]
//! async fn main() {
//!     autumn_web::app()
//!         .plugin(ShopifyPlugin::new().webhook("orders/create", order_created))
//!         .run()
//!         .await;
//! }
//! ```
//!
//! ## Modules
//!
//! | Module | Purpose |
//! |---|---|
//! | [`config`] | `[shopify]` config, `SHOPIFY_*` env, builder closures |
//! | [`types`] | [`ShopDomain`], [`Topic`], [`ApiVersion`] |
//! | [`verify`] | Webhook and OAuth HMAC checks |
//! | [`webhooks`] | The webhook route, extractor, and topic registry |
//! | [`delivery`] | Duplicate-delivery guard |
//! | [`oauth`] | Install and callback routes, token exchange, refresh |
//! | [`tokens`] | Token storage |
//! | [`client`] | Admin GraphQL client |
//! | [`health`] | Readiness check |
//! | [`plugin`] | [`ShopifyPlugin`], [`ShopifyRuntime`], [`Shopify`] |
//! | [`error`] | [`Error`], [`ErrorKind`], HTTP status mapping |

#![forbid(unsafe_code)]

pub mod client;
pub mod config;
pub mod delivery;
pub mod error;
pub mod health;
pub mod oauth;
pub mod plugin;
pub mod tokens;
pub mod types;
pub mod verify;
pub mod webhooks;

#[cfg(test)]
mod test_support;

pub use client::{RetryPolicy, ShopInfo, ShopifyClient};
pub use config::ShopifyConfig;
pub use delivery::{DeliveryStore, InMemoryDeliveryStore};
pub use error::{Error, ErrorKind, Result};
pub use health::ShopifyHealth;
pub use plugin::{Shopify, ShopifyPlugin, ShopifyRuntime};
pub use tokens::{InMemoryTokenStore, ShopToken, TokenStore};
pub use types::{ApiVersion, DEFAULT_API_VERSION, ShopDomain, Topic};
pub use verify::{SecretSet, sign_query, sign_webhook, verify_query, verify_webhook};
pub use webhooks::{VerifiedWebhook, WebhookContext, WebhookOutcome, WebhookRegistry};
