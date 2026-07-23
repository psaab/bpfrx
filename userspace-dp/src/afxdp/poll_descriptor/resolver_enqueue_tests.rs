use super::*;

#[cfg(test)]
mod try_enqueue_resolver_tests {
    use super::*;
    use crate::afxdp::neighbor_resolver::{NeighborResolver, ResolveItem, ResolverCounters};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use std::sync::mpsc;

    fn make_resolver() -> (NeighborResolver, mpsc::Receiver<ResolveItem>) {
        let (tx, rx) = mpsc::sync_channel::<ResolveItem>(8);
        let resolver = NeighborResolver::new(
            tx,
            Arc::new(ResolverCounters::default()),
            Arc::new(AtomicU64::new(0)),
            Arc::new(crate::afxdp::neighbor_latency::NeighborLatencyHist::default()),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        );
        (resolver, rx)
    }

    #[test]
    fn try_enqueue_resolver_throttles_within_window_and_bounds_map() {
        let (resolver, rx) = make_resolver();
        let mut throttle: FastMap<(i32, IpAddr), u64> = FastMap::default();
        let mut names: FastMap<i32, String> = FastMap::default();
        names.insert(12, "ge-0-0-2.80".to_string());
        let key = (12, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)));

        // First call enqueues and records the throttle entry.
        assert!(try_enqueue_resolver(
            &resolver,
            &mut throttle,
            &names,
            key,
            1_000
        ));
        assert_eq!(rx.try_recv().expect("first enqueue").ifindex, 12);
        assert!(throttle.contains_key(&key));

        // Second call within RESOLVER_ENQUEUE_THROTTLE_NS is throttled: no
        // enqueue (storm bound — at most one per key per window).
        assert!(!try_enqueue_resolver(
            &resolver,
            &mut throttle,
            &names,
            key,
            1_000 + RESOLVER_ENQUEUE_THROTTLE_NS - 1
        ));
        assert!(rx.try_recv().is_err(), "throttled call must not enqueue");

        // After the window elapses, it enqueues again.
        assert!(try_enqueue_resolver(
            &resolver,
            &mut throttle,
            &names,
            key,
            1_000 + RESOLVER_ENQUEUE_THROTTLE_NS
        ));
        assert_eq!(rx.try_recv().expect("post-window enqueue").ifindex, 12);
    }

    #[test]
    fn try_enqueue_resolver_skips_when_iface_has_no_name() {
        let (resolver, rx) = make_resolver();
        let mut throttle: FastMap<(i32, IpAddr), u64> = FastMap::default();
        let names: FastMap<i32, String> = FastMap::default(); // empty
        let key = (362, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)));
        // No name for the ifindex ⇒ no enqueue, no throttle entry.
        assert!(!try_enqueue_resolver(
            &resolver,
            &mut throttle,
            &names,
            key,
            1_000
        ));
        assert!(rx.try_recv().is_err());
        assert!(throttle.is_empty());
    }
}
