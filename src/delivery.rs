//! Duplicate-delivery guard for webhooks.
//!
//! Shopify can send one webhook more than once. Each delivery of one
//! webhook has the same `X-Shopify-Webhook-Id`. The webhook route claims
//! the id before it runs the handler:
//!
//! | Claim result | Route answer |
//! |---|---|
//! | [`Claim::Fresh`] | The handler runs. |
//! | [`Claim::InFlight`] | 409. Another delivery of this id still runs. Shopify retries later. |
//! | [`Claim::Done`] | 200. A handler already succeeded. |
//!
//! After success the route calls [`DeliveryStore::complete`]. After a
//! failure, a panic, or a cancelled request it calls
//! [`DeliveryStore::release`], so that the next Shopify retry runs again.
//!
//! [`InMemoryDeliveryStore`] keeps claims for a time window and drops the
//! oldest claim when it is full. An in-flight claim expires after a lease.
//! The store does not share state across replicas.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use crate::error::{Error, Result};
use crate::tokens::StoreFuture;

/// Default claim window: 24 hours. Shopify retries for 4 hours.
pub const DEFAULT_WINDOW_SECS: i64 = 24 * 60 * 60;
/// Default number of claims the in-memory store keeps.
pub const DEFAULT_CAPACITY: usize = 10_000;
/// Default lease of an in-flight claim: 5 minutes. After the lease, a new
/// delivery of the same id can claim it again (for example after a crash).
pub const DEFAULT_LEASE_SECS: i64 = 5 * 60;

/// The result of a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Claim {
    /// The id is new. The caller must run the handler, then call
    /// `complete` or `release`.
    Fresh,
    /// Another delivery of this id still runs.
    InFlight,
    /// A handler already succeeded for this id.
    Done,
}

/// Storage for webhook-id claims.
pub trait DeliveryStore: Send + Sync + 'static {
    /// Claim `webhook_id` at `now` (Unix seconds).
    fn claim<'a>(&'a self, webhook_id: &'a str, now: i64) -> StoreFuture<'a, Claim>;
    /// Mark a claim as done after the handler succeeds.
    fn complete<'a>(&'a self, webhook_id: &'a str) -> StoreFuture<'a, ()>;
    /// Release a claim, so that a retry of the same id runs again.
    fn release<'a>(&'a self, webhook_id: &'a str) -> StoreFuture<'a, ()>;
}

/// A process-local [`DeliveryStore`] with a time window, a lease, and a
/// size limit.
#[derive(Debug)]
pub struct InMemoryDeliveryStore {
    window_secs: i64,
    lease_secs: i64,
    capacity: usize,
    inner: Mutex<Claims>,
}

#[derive(Debug, Default)]
struct Claims {
    by_id: HashMap<String, Entry>,
    order: VecDeque<(String, i64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    at: i64,
    done: bool,
}

impl Default for InMemoryDeliveryStore {
    fn default() -> Self {
        Self::new(DEFAULT_WINDOW_SECS, DEFAULT_CAPACITY)
    }
}

impl InMemoryDeliveryStore {
    /// Make a store with a window (seconds) and a capacity (claims). The
    /// store changes a capacity of zero to one.
    #[must_use]
    pub fn new(window_secs: i64, capacity: usize) -> Self {
        Self {
            window_secs,
            lease_secs: DEFAULT_LEASE_SECS,
            capacity: capacity.max(1),
            inner: Mutex::new(Claims::default()),
        }
    }

    /// Set the lease of an in-flight claim, in seconds.
    #[must_use]
    pub const fn with_lease(mut self, lease_secs: i64) -> Self {
        self.lease_secs = lease_secs;
        self
    }

    /// The number of live claims.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Store`] when the lock is poisoned.
    pub fn len(&self) -> Result<usize> {
        self.lock().map(|claims| claims.by_id.len())
    }

    /// True when there are no claims.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Store`] when the lock is poisoned.
    pub fn is_empty(&self) -> Result<bool> {
        self.len().map(|len| len == 0)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Claims>> {
        self.inner
            .lock()
            .map_err(|_| Error::Store("delivery store lock is poisoned".to_owned()))
    }

    #[allow(
        clippy::significant_drop_tightening,
        reason = "one lock covers the check and the insert"
    )]
    fn claim_now(&self, webhook_id: &str, now: i64) -> Result<Claim> {
        let mut claims = self.lock()?;
        claims.prune(now.saturating_sub(self.window_secs));
        if let Some(entry) = claims.by_id.get(webhook_id).copied() {
            if entry.done {
                return Ok(Claim::Done);
            }
            if now.saturating_sub(entry.at) < self.lease_secs {
                return Ok(Claim::InFlight);
            }
            // The lease ran out: the first delivery crashed or hangs.
        }
        while claims.by_id.len() >= self.capacity && !claims.by_id.contains_key(webhook_id) {
            if !claims.pop_oldest() {
                break;
            }
        }
        claims.by_id.insert(
            webhook_id.to_owned(),
            Entry {
                at: now,
                done: false,
            },
        );
        claims.order.push_back((webhook_id.to_owned(), now));
        claims.compact(self.capacity);
        Ok(Claim::Fresh)
    }
}

impl DeliveryStore for InMemoryDeliveryStore {
    fn claim<'a>(&'a self, webhook_id: &'a str, now: i64) -> StoreFuture<'a, Claim> {
        let result = self.claim_now(webhook_id, now);
        Box::pin(async move { result })
    }

    fn complete<'a>(&'a self, webhook_id: &'a str) -> StoreFuture<'a, ()> {
        let result = self.lock().map(|mut claims| {
            if let Some(entry) = claims.by_id.get_mut(webhook_id) {
                entry.done = true;
            }
        });
        Box::pin(async move { result })
    }

    fn release<'a>(&'a self, webhook_id: &'a str) -> StoreFuture<'a, ()> {
        let result = self.lock().map(|mut claims| {
            // The `order` entry stays. `pop_oldest` skips stale entries.
            claims.by_id.remove(webhook_id);
        });
        Box::pin(async move { result })
    }
}

impl Claims {
    /// Drop claims made at or before `cutoff`.
    fn prune(&mut self, cutoff: i64) {
        while self.order.front().is_some_and(|(_, at)| *at <= cutoff) {
            self.pop_oldest();
        }
    }

    /// Drop stale entries when they outnumber the live claims, so that
    /// released ids do not grow `order` without a limit.
    fn compact(&mut self, capacity: usize) {
        if self.order.len() > capacity.saturating_mul(2) {
            let by_id = &self.by_id;
            self.order
                .retain(|(id, at)| by_id.get(id).is_some_and(|entry| entry.at == *at));
        }
    }

    /// Drop the oldest entry. Returns `false` when there is none.
    ///
    /// An entry is stale when its id was released or claimed again later.
    /// A stale entry does not remove the live claim.
    fn pop_oldest(&mut self) -> bool {
        let Some((id, at)) = self.order.pop_front() else {
            return false;
        };
        if self.by_id.get(&id).is_some_and(|entry| entry.at == at) {
            self.by_id.remove(&id);
        }
        true
    }
}

#[cfg(test)]
mod tests;
