//! Duplicate guard tests.

#![allow(clippy::expect_used)]

use super::*;
use proptest::prelude::*;

#[tokio::test]
async fn first_claim_wins_and_duplicates_lose() {
    let store = InMemoryDeliveryStore::default();
    assert!(store.claim("w1", 100).await.expect("claim"));
    assert!(!store.claim("w1", 101).await.expect("claim"));
    assert!(store.claim("w2", 101).await.expect("claim"));
    assert_eq!(store.len(), 2);
}

#[tokio::test]
async fn release_lets_a_retry_claim_again() {
    let store = InMemoryDeliveryStore::default();
    assert!(store.claim("w1", 100).await.expect("claim"));
    store.release("w1").await.expect("release");
    store.release("w1").await.expect("release twice is fine");
    assert!(store.claim("w1", 200).await.expect("claim after release"));
}

#[tokio::test]
async fn claims_expire_after_the_window() {
    let store = InMemoryDeliveryStore::new(60, 100);
    assert!(store.claim("w1", 1_000).await.expect("claim"));
    assert!(!store.claim("w1", 1_059).await.expect("inside window"));
    assert!(store.claim("w1", 1_060).await.expect("after window"));
}

#[tokio::test]
async fn expired_claims_are_pruned() {
    let store = InMemoryDeliveryStore::new(60, 100);
    store.claim("old", 0).await.expect("claim");
    store.claim("new", 100).await.expect("claim");
    assert_eq!(store.len(), 1);
}

#[tokio::test]
async fn capacity_drops_the_oldest_claim() {
    let store = InMemoryDeliveryStore::new(1_000, 2);
    store.claim("a", 1).await.expect("claim");
    store.claim("b", 2).await.expect("claim");
    store.claim("c", 3).await.expect("claim");
    assert_eq!(store.len(), 2);
    assert!(store.claim("a", 4).await.expect("a was dropped"));
    assert!(!store.claim("c", 4).await.expect("c is kept"));
}

#[tokio::test]
async fn zero_capacity_is_one() {
    let store = InMemoryDeliveryStore::new(1_000, 0);
    assert!(store.claim("a", 1).await.expect("claim"));
    assert!(!store.claim("a", 1).await.expect("duplicate"));
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
                if now % 3 == 0 {
                    let _ = store.release(id).await;
                }
            }
        });
        prop_assert!(store.len() <= capacity);
    }

    #[test]
    fn a_live_claim_always_blocks_its_duplicate(id in "[a-z0-9]{1,12}", now in 0i64..1_000_000) {
        let runtime = tokio::runtime::Builder::new_current_thread().build().expect("runtime");
        let store = InMemoryDeliveryStore::default();
        let (first, second) = runtime.block_on(async {
            (store.claim(&id, now).await, store.claim(&id, now + 1).await)
        });
        prop_assert!(first.expect("claim"));
        prop_assert!(!second.expect("claim"));
    }
}

#[tokio::test]
async fn released_ids_do_not_grow_the_queue_without_bound() {
    let store = InMemoryDeliveryStore::new(1_000_000, 4);
    for now in 0..1_000 {
        store.claim("retry", now).await.expect("claim");
        store.release("retry").await.expect("release");
    }
    let queue = store.inner.lock().expect("lock").order.len();
    assert!(queue <= 8, "queue has {queue} entries");
}
