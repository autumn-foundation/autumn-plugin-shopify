//! Access-token storage.
//!
//! [`TokenStore`] keeps one [`ShopToken`] per shop. The plugin writes it
//! after an OAuth install or a refresh, and deletes it on
//! `app/uninstalled` and `shop/redact`. [`InMemoryTokenStore`] is the
//! default. It does not survive a restart and does not share state across
//! replicas: production apps bring their own store.

use std::collections::HashMap;
use std::sync::Mutex;

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::types::ShopDomain;

/// A boxed store future.
pub type StoreFuture<'a, T> = BoxFuture<'a, Result<T>>;

/// An offline access token for one shop.
///
/// Times are Unix seconds. `Debug` redacts both tokens.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShopToken {
    /// The Admin API access token.
    pub access_token: String,
    /// The granted scopes, comma-separated.
    pub scope: String,
    /// When the access token expires. `None` means it does not expire.
    pub expires_at: Option<i64>,
    /// The refresh token, for expiring tokens.
    pub refresh_token: Option<String>,
    /// When the refresh token expires.
    pub refresh_token_expires_at: Option<i64>,
}

impl std::fmt::Debug for ShopToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShopToken")
            .field("access_token", &"<redacted>")
            .field("scope", &self.scope)
            .field("expires_at", &self.expires_at)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("refresh_token_expires_at", &self.refresh_token_expires_at)
            .finish()
    }
}

impl ShopToken {
    /// A token that does not expire.
    #[must_use]
    pub fn non_expiring(access_token: impl Into<String>, scope: impl Into<String>) -> Self {
        Self {
            access_token: access_token.into(),
            scope: scope.into(),
            expires_at: None,
            refresh_token: None,
            refresh_token_expires_at: None,
        }
    }

    /// True when the access token expires within `margin_secs` of `now`.
    #[must_use]
    pub fn needs_refresh(&self, now: i64, margin_secs: i64) -> bool {
        self.expires_at
            .is_some_and(|expires_at| now.saturating_add(margin_secs) >= expires_at)
    }

    /// True when a refresh token is present and not expired at `now`.
    #[must_use]
    pub fn can_refresh(&self, now: i64) -> bool {
        self.refresh_token.is_some()
            && self
                .refresh_token_expires_at
                .is_none_or(|expires_at| now < expires_at)
    }

    /// The granted scopes as a list.
    #[must_use]
    pub fn scopes(&self) -> Vec<&str> {
        self.scope
            .split(',')
            .map(str::trim)
            .filter(|scope| !scope.is_empty())
            .collect()
    }
}

/// Storage for shop tokens.
///
/// Implement it on a database or a secret store for production. Calls can
/// run at the same time from many requests.
pub trait TokenStore: Send + Sync + 'static {
    /// Read the token for `shop`.
    fn get<'a>(&'a self, shop: &'a ShopDomain) -> StoreFuture<'a, Option<ShopToken>>;
    /// Write (insert or replace) the token for `shop`.
    fn put<'a>(&'a self, shop: &'a ShopDomain, token: ShopToken) -> StoreFuture<'a, ()>;
    /// Delete the token for `shop`. Deleting a missing token is not an error.
    fn delete<'a>(&'a self, shop: &'a ShopDomain) -> StoreFuture<'a, ()>;
}

/// A process-local [`TokenStore`].
#[derive(Debug, Default)]
pub struct InMemoryTokenStore {
    tokens: Mutex<HashMap<ShopDomain, ShopToken>>,
}

impl InMemoryTokenStore {
    /// Make an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of stored tokens.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().map_or(0, |tokens| tokens.len())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<ShopDomain, ShopToken>>> {
        self.tokens
            .lock()
            .map_err(|_| Error::Store("token store lock is poisoned".to_owned()))
    }

    /// True when the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl TokenStore for InMemoryTokenStore {
    fn get<'a>(&'a self, shop: &'a ShopDomain) -> StoreFuture<'a, Option<ShopToken>> {
        let result = self.lock().map(|tokens| tokens.get(shop).cloned());
        Box::pin(async move { result })
    }

    fn put<'a>(&'a self, shop: &'a ShopDomain, token: ShopToken) -> StoreFuture<'a, ()> {
        let result = self.lock().map(|mut tokens| {
            tokens.insert(shop.clone(), token);
        });
        Box::pin(async move { result })
    }

    fn delete<'a>(&'a self, shop: &'a ShopDomain) -> StoreFuture<'a, ()> {
        let result = self.lock().map(|mut tokens| {
            tokens.remove(shop);
        });
        Box::pin(async move { result })
    }
}

#[cfg(test)]
mod tests;
