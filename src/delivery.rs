//! Duplicate-delivery guard for webhooks.
//!
//! Shopify can send one webhook more than once. Each delivery of one
//! webhook has the same `X-Shopify-Webhook-Id`. The webhook route claims
//! the id before it runs the handler, and releases the claim when the
//! handler fails, so that the Shopify retry runs again.
//!
//! [`InMemoryDeliveryStore`] keeps claims for a time window and drops the
//! oldest claim when it is full. It does not share state across replicas.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use crate::error::{Error, Result};
use crate::tokens::StoreFuture;

/// Default claim window: 24 hours. Shopify retries for 4 hours.
pub const DEFAULT_WINDOW_SECS: i64 = 24 * 60 * 60;
/// Default number of claims the in-memory store keeps.
pub const DEFAULT_CAPACITY: usize = 10_000;

/// Storage for webhook-id claims.
pub trait DeliveryStore: Send + Sync + 'static {
    /// Claim `webhook_id` at `now` (Unix seconds). Returns `true` for a new
    /// id and `false` for a duplicate inside the window.
    fn claim<'a>(&'a self, webhook_id: &'a str, now: i64) -> StoreFuture<'a, bool>;
    /// Release a claim, so that a retry of the same id runs again.
    fn release<'a>(&'a self, webhook_id: &'a str) -> StoreFuture<'a, ()>;
}

/// A process-local [`DeliveryStore`] with a time window and a size limit.
#[derive(Debug)]
pub struct InMemoryDeliveryStore {
    window_secs: i64,
    capacity: usize,
    inner: Mutex<Claims>,
}

#[derive(Debug, Default)]
struct Claims {
    by_id: HashMap<String, i64>,
    order: VecDeque<(String, i64)>,
}

impl Default for InMemoryDeliveryStore {
    fn default() -> Self {
        Self::new(DEFAULT_WINDOW_SECS, DEFAULT_CAPACITY)
    }
}

impl InMemoryDeliveryStore {
    /// Make a store with a window (seconds) and a capacity (claims).
    /// A capacity of zero is changed to one.
    #[must_use]
    pub fn new(window_secs: i64, capacity: usize) -> Self {
        Self {
            window_secs,
            capacity: capacity.max(1),
            inner: Mutex::new(Claims::default()),
        }
    }

    /// The number of live claims.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().map_or(0, |claims| claims.by_id.len())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Claims>> {
        self.inner
            .lock()
            .map_err(|_| Error::Store("delivery store lock is poisoned".to_owned()))
    }

    /// True when there are no claims.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl DeliveryStore for InMemoryDeliveryStore {
    fn claim<'a>(&'a self, webhook_id: &'a str, now: i64) -> StoreFuture<'a, bool> {
        let result = self.lock().map(|mut claims| {
            claims.prune(now.saturating_sub(self.window_secs));
            if claims.by_id.contains_key(webhook_id) {
                return false;
            }
            while claims.by_id.len() >= self.capacity {
                if !claims.pop_oldest() {
                    break;
                }
            }
            claims.by_id.insert(webhook_id.to_owned(), now);
            claims.order.push_back((webhook_id.to_owned(), now));
            claims.compact(self.capacity);
            true
        });
        Box::pin(async move { result })
    }

    fn release<'a>(&'a self, webhook_id: &'a str) -> StoreFuture<'a, ()> {
        let result = self.lock().map(|mut claims| {
            // The `order` entry stays; `pop_oldest` skips stale entries.
            claims.by_id.remove(webhook_id);
        });
        Box::pin(async move { result })
    }
}

impl Claims {
    /// Drop claims made before `cutoff`.
    fn prune(&mut self, cutoff: i64) {
        while self.order.front().is_some_and(|(_, at)| *at <= cutoff) {
            self.pop_oldest();
        }
    }

    /// Drop stale entries when they outnumber the live claims, so that
    /// released ids do not grow `order` without a bound.
    fn compact(&mut self, capacity: usize) {
        if self.order.len() > capacity.saturating_mul(2) {
            let by_id = &self.by_id;
            self.order.retain(|(id, at)| by_id.get(id) == Some(at));
        }
    }

    /// Drop the oldest entry. Returns `false` when there is none.
    ///
    /// An entry is stale when its id was released or claimed again later;
    /// a stale entry does not remove the live claim.
    fn pop_oldest(&mut self) -> bool {
        let Some((id, at)) = self.order.pop_front() else {
            return false;
        };
        if self.by_id.get(&id) == Some(&at) {
            self.by_id.remove(&id);
        }
        true
    }
}

#[cfg(test)]
mod tests;
