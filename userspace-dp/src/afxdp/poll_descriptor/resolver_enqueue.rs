// #6386 leaf extraction: the #1769/#1912 per-key rate-limited neighbor
// resolver enqueue helper, lifted verbatim out of poll_descriptor/mod.rs.
// The moved bare fn becomes pub(super) and keeps its existing #[inline]
// (cold-path only; attr-verbatim, no other non-motion change). Body
// byte-identical to its prior location.

use super::*;

/// #1769/#1912: per-key rate-limited enqueue of the shared neighbor
/// resolver. Both the neg-cache fast-fail branch and the #1912 tunnel
/// outer-hop branch use the identical throttle-check / `ifindex_to_name`
/// clone / `enqueue` / cap-clear / `insert` sequence keyed by
/// `(ifindex, next_hop)` — factored here so the throttle window, the cap
/// constant, and the clear-vs-evict policy live in ONE place (Copilot
/// #1912 r1 Medium). Returns true iff it actually enqueued (i.e. was not
/// throttled and the iface had a name). Cold-path only.
#[inline]
pub(super) fn try_enqueue_resolver(
    resolver: &NeighborResolver,
    throttle: &mut FastMap<(i32, IpAddr), u64>,
    ifindex_to_name: &FastMap<i32, String>,
    key: (i32, IpAddr),
    now_ns: u64,
) -> bool {
    // Cheap (i32, IpAddr) map check runs before any clone.
    let throttled = matches!(
        throttle.get(&key),
        Some(&t) if now_ns.saturating_sub(t) < RESOLVER_ENQUEUE_THROTTLE_NS
    );
    if throttled {
        return false;
    }
    let Some(name) = ifindex_to_name.get(&key.0) else {
        return false;
    };
    resolver.enqueue(key.0, key.1, name.clone());
    // Bound the throttle map like the negative cache: a /24 scan touches
    // <=254 keys, so clear wholesale past the cap (best-effort — losing
    // throttle for a few keys only risks one extra clone).
    if throttle.len() >= MAX_NEG_NEIGH_CACHE && !throttle.contains_key(&key) {
        throttle.clear();
    }
    throttle.insert(key, now_ns);
    true
}

#[cfg(test)]
#[path = "resolver_enqueue_tests.rs"]
mod tests;
