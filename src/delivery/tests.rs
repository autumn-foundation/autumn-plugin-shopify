//! Duplicate guard tests.

#![allow(clippy::expect_used)]

use super::*;
use proptest::prelude::*;

#[tokio::test]
async fn a_new_id_is_fresh_and_a_running_one_is_in_flight() {
    let store = InMemoryDeliveryStore::default();
    assert_eq!(store.claim("w1", 100).await.expect("claim"), Claim::Fresh);
    assert_eq!(
        store.claim("w1", 101).await.expect("claim"),
        Claim::InFlight
    );
    assert_eq!(store.claim("w2", 101).await.expect("claim"), Claim::Fresh);
    assert_eq!(store.len().expect("len"), 2);
}

#[tokio::test]
async fn a_completed_id_is_done() {
    let store = InMemoryDeliveryStore::default();
    store.claim("w1", 100).await.expect("claim");
    store.complete("w1", 100).await.expect("complete");
    store
        .complete("missing", 100)
        .await
        .expect("complete of a missing id is fine");
    assert_eq!(store.claim("w1", 101).await.expect("claim"), Claim::Done);
}

#[tokio::test]
async fn release_lets_a_retry_claim_again() {
    let store = InMemoryDeliveryStore::default();
    assert_eq!(store.claim("w1", 100).await.expect("claim"), Claim::Fresh);
    store.release("w1", 100).await.expect("release");
    store
        .release("w1", 100)
        .await
        .expect("release twice is fine");
    assert_eq!(store.claim("w1", 200).await.expect("claim"), Claim::Fresh);
}

#[tokio::test]
async fn an_expired_lease_lets_a_retry_claim_again() {
    let store = InMemoryDeliveryStore::default().with_lease(60);
    assert_eq!(store.claim("w1", 1_000).await.expect("claim"), Claim::Fresh);
    assert_eq!(
        store.claim("w1", 1_059).await.expect("claim"),
        Claim::InFlight
    );
    assert_eq!(store.claim("w1", 1_060).await.expect("claim"), Claim::Fresh);
    assert_eq!(store.len().expect("len"), 1);
}

#[tokio::test]
async fn a_stale_owner_cannot_change_a_newer_claim() {
    let store = InMemoryDeliveryStore::default().with_lease(60);
    // Owner A claims at 0 and hangs. Owner B claims after the lease.
    assert_eq!(store.claim("w1", 0).await.expect("claim"), Claim::Fresh);
    assert_eq!(store.claim("w1", 61).await.expect("claim"), Claim::Fresh);
    // A fails late: its release must not free the claim of B.
    store.release("w1", 0).await.expect("release");
    assert_eq!(store.claim("w1", 62).await.expect("claim"), Claim::InFlight);
    // A succeeds late: its complete must not mark the claim of B as done.
    store.complete("w1", 0).await.expect("complete");
    assert_eq!(store.claim("w1", 63).await.expect("claim"), Claim::InFlight);
    // B settles its own claim.
    store.complete("w1", 61).await.expect("complete");
    assert_eq!(store.claim("w1", 64).await.expect("claim"), Claim::Done);
}

#[tokio::test]
async fn claims_expire_after_the_window() {
    let store = InMemoryDeliveryStore::new(60, 100);
    store.claim("w1", 1_000).await.expect("claim");
    store.complete("w1", 1_000).await.expect("complete");
    assert_eq!(store.claim("w1", 1_059).await.expect("claim"), Claim::Done);
    assert_eq!(store.claim("w1", 1_060).await.expect("claim"), Claim::Fresh);
}

#[tokio::test]
async fn expired_claims_are_pruned() {
    let store = InMemoryDeliveryStore::new(60, 100);
    store.claim("old", 0).await.expect("claim");
    store.claim("new", 100).await.expect("claim");
    assert_eq!(store.len().expect("len"), 1);
    assert!(!store.is_empty().expect("is_empty"));
}

#[tokio::test]
async fn capacity_drops_the_oldest_claim() {
    let store = InMemoryDeliveryStore::new(1_000, 2);
    store.claim("a", 1).await.expect("claim");
    store.claim("b", 2).await.expect("claim");
    store.claim("c", 3).await.expect("claim");
    assert_eq!(store.len().expect("len"), 2);
    assert_eq!(store.claim("a", 4).await.expect("claim"), Claim::Fresh);
    assert_eq!(store.claim("c", 4).await.expect("claim"), Claim::InFlight);
}

#[tokio::test]
async fn zero_capacity_is_one() {
    let store = InMemoryDeliveryStore::new(1_000, 0);
    assert_eq!(store.claim("a", 1).await.expect("claim"), Claim::Fresh);
    assert_eq!(store.claim("a", 1).await.expect("claim"), Claim::InFlight);
}

#[tokio::test]
async fn released_ids_do_not_grow_the_queue_without_limit() {
    let store = InMemoryDeliveryStore::new(1_000_000, 4);
    for now in 0..1_000 {
        store.claim("retry", now).await.expect("claim");
        store.release("retry", now).await.expect("release");
    }
    let queue = store.inner.lock().expect("lock").order.len();
    assert!(queue <= 8, "queue has {queue} entries");
}

proptest! {
    #[test]
    fn len_never_exceeds_capacity(ids in proptest::collection::vec("[a-d]{1,2}", 0..60), capacity in 1usize..8) {
        let runtime = tokio::runtime::Builder::new_current_thread().build().expect("runtime");
        let store = InMemoryDeliveryStore::new(1_000_000, capacity);
        runtime.block_on(async {
            for (now, id) in ids.iter().enumerate() {
                let now = i64::try_from(now).expect("small");
                let _ = store.claim(id, now).await;
                match now % 3 {
                    0 => { let _ = store.release(id, now).await; }
                    1 => { let _ = store.complete(id, now).await; }
                    _ => {}
                }
            }
        });
        prop_assert!(store.len().expect("len") <= capacity);
    }

    #[test]
    fn a_live_claim_always_blocks_its_duplicate(id in "[a-z0-9]{1,12}", now in 0i64..1_000_000, done in any::<bool>()) {
        let runtime = tokio::runtime::Builder::new_current_thread().build().expect("runtime");
        let store = InMemoryDeliveryStore::default();
        let (first, second) = runtime.block_on(async {
            let first = store.claim(&id, now).await;
            if done {
                store.complete(&id, now).await.expect("complete");
            }
            (first, store.claim(&id, now + 1).await)
        });
        prop_assert_eq!(first.expect("claim"), Claim::Fresh);
        prop_assert_eq!(second.expect("claim"), if done { Claim::Done } else { Claim::InFlight });
    }
}
