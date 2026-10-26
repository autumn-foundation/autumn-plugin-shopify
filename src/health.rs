//! Readiness check for single-store apps.
//!
//! [`ShopifyHealth`] implements Autumn's [`HealthIndicator`]. It calls
//! [`ShopifyClient::shop_info`] and reports `Up` with the shop name, or
//! `Down` with the error. The plugin registers it as `"shopify"` when
//! `shop` and `SHOPIFY_ACCESS_TOKEN` are set.

use std::collections::HashMap;
use std::sync::Arc;

use autumn_web::actuator::{HealthCheckOutput, HealthIndicator, HealthStatus};

use crate::client::ShopifyClient;

/// Health indicator for one shop and token.
#[derive(Debug, Clone)]
pub struct ShopifyHealth {
    client: ShopifyClient,
}

impl ShopifyHealth {
    /// Build the indicator around a client.
    #[must_use]
    pub const fn new(client: ShopifyClient) -> Self {
        Self { client }
    }
}

impl HealthIndicator for ShopifyHealth {
    fn check(&self) -> futures::future::BoxFuture<'_, HealthCheckOutput> {
        Box::pin(async move {
            let (status, key, value) = match self.client.shop_info().await {
                Ok(info) => (HealthStatus::Up, "shop", info.name),
                Err(err) => (HealthStatus::Down, "error", err.to_string()),
            };
            let mut details = HashMap::new();
            details.insert(key.to_owned(), serde_json::Value::String(value));
            HealthCheckOutput { status, details }
        })
    }
}

/// Build the shared indicator handle the plugin registers.
#[must_use]
pub fn indicator(client: &ShopifyClient) -> Arc<ShopifyHealth> {
    Arc::new(ShopifyHealth::new(client.clone()))
}

#[cfg(test)]
mod tests;
