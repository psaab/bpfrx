// Tests for prefix_set.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep prefix_set.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "prefix_set_tests.rs"]` from prefix_set.rs.

use super::*;
use ipnet::{Ipv4Net, Ipv6Net};

/// Tiny deterministic LCG for seeded test inputs. We don't pull
/// in `rand` as a dev-dependency just for this.
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next_u32(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 32) as u32
    }
    fn next_u128(&mut self) -> u128 {
        let hi = self.next_u32() as u128;
        let mid = self.next_u32() as u128;
        let lo_a = self.next_u32() as u128;
        let lo_b = self.next_u32() as u128;
        (hi << 96) | (mid << 64) | (lo_a << 32) | lo_b
    }
}

fn p4(s: &str) -> PrefixV4 {
    PrefixV4::from_net(s.parse::<Ipv4Net>().expect("parse v4"))
}

fn p6(s: &str) -> PrefixV6 {
    PrefixV6::from_net(s.parse::<Ipv6Net>().expect("parse v6"))
}

#[test]
fn empty_input_yields_match_any() {
    let set = PrefixSetV4::from_prefixes(Vec::new());
    assert!(matches!(set, PrefixSetV4::MatchAny));
    assert!(set.contains("1.2.3.4".parse().expect("ip")));
    assert_eq!(set.prefix_count(), 0);
}

#[test]
fn match_any_set_matches_arbitrary_ips() {
    // 0.0.0.0/0 is funneled to MatchAny by the constructor.
    let set = PrefixSetV4::from_prefixes(vec![p4("0.0.0.0/0")]);
    assert!(matches!(set, PrefixSetV4::MatchAny));
    assert!(set.contains("172.16.80.5".parse().expect("ip")));
    assert!(set.contains("0.0.0.0".parse().expect("ip")));
}

#[test]
fn linear_set_matches_covered_ip() {
    let set = PrefixSetV4::from_prefixes(vec![
        p4("10.0.0.0/8"),
        p4("192.168.1.0/24"),
        p4("172.16.0.0/12"),
    ]);
    assert!(matches!(set, PrefixSetV4::Linear(_)));
    assert!(set.contains("10.0.61.102".parse().expect("ip")));
    assert!(set.contains("192.168.1.42".parse().expect("ip")));
    assert!(set.contains("172.16.80.5".parse().expect("ip")));
    assert!(!set.contains("8.8.8.8".parse().expect("ip")));
    assert!(!set.contains("192.168.2.1".parse().expect("ip")));
}

#[test]
fn linear_variant_chosen_when_count_eq_threshold() {
    let prefixes: Vec<PrefixV4> = (0..16).map(|i| p4(&format!("10.{i}.0.0/16"))).collect();
    let set = PrefixSetV4::from_prefixes(prefixes);
    assert!(matches!(set, PrefixSetV4::Linear(_)));
    assert_eq!(set.prefix_count(), 16);
}

#[test]
fn trie_variant_chosen_when_count_gt_threshold() {
    let prefixes: Vec<PrefixV4> = (0..17).map(|i| p4(&format!("10.{i}.0.0/16"))).collect();
    let set = PrefixSetV4::from_prefixes(prefixes);
    assert!(matches!(set, PrefixSetV4::Trie(_)));
    assert_eq!(set.prefix_count(), 17);
}

#[test]
fn trie_lookup_matches_linear_lookup_random_v4() {
    let mut rng = Lcg::new(0xCAFE_BABE_DEAD_BEEF);
    // Build 256 prefixes with random length 8..=32 — wider than
    // /32 only would hit the worst-case node count; we use a
    // mix to exercise both shared-prefix and unique-prefix paths.
    let mut prefixes: Vec<PrefixV4> = Vec::with_capacity(256);
    for _ in 0..256 {
        let len = 8 + (rng.next_u32() % 25) as u8; // 8..=32
        let addr = rng.next_u32();
        let net = Ipv4Net::new(Ipv4Addr::from(addr), len).expect("net");
        prefixes.push(PrefixV4::from_net(net));
    }
    // Force a Linear set by truncating to 16 vs a Trie set with
    // the full 256.
    let linear = PrefixSetV4::from_prefixes(prefixes.iter().take(16).copied().collect());
    let trie = PrefixSetV4::from_prefixes(prefixes.clone());
    assert!(matches!(linear, PrefixSetV4::Linear(_)));
    assert!(matches!(trie, PrefixSetV4::Trie(_)));
    // Boolean equivalence: against a fresh linear scan on the
    // same input, the trie must produce the same answer for
    // every probe IP.
    let reference: Vec<PrefixV4> = prefixes.clone();
    for _ in 0..4096 {
        let ip = Ipv4Addr::from(rng.next_u32());
        let want = reference.iter().any(|p| p.contains(ip));
        let got = trie.contains(ip);
        assert_eq!(want, got, "trie disagreed with linear at ip {}", ip);
    }
}

#[test]
fn trie_lookup_matches_linear_lookup_random_v6() {
    let mut rng = Lcg::new(0xFACE_FEED_C0DE_BEEF);
    let mut prefixes: Vec<PrefixV6> = Vec::with_capacity(256);
    for _ in 0..256 {
        let len = 32 + (rng.next_u32() % 97) as u8; // 32..=128
        let addr = rng.next_u128();
        let net = Ipv6Net::new(Ipv6Addr::from(addr), len).expect("net");
        prefixes.push(PrefixV6::from_net(net));
    }
    let trie = PrefixSetV6::from_prefixes(prefixes.clone());
    assert!(matches!(trie, PrefixSetV6::Trie(_)));
    let reference: Vec<PrefixV6> = prefixes;
    for _ in 0..4096 {
        let ip = Ipv6Addr::from(rng.next_u128());
        let want = reference.iter().any(|p| p.contains(ip));
        let got = trie.contains(ip);
        assert_eq!(want, got, "trie v6 disagreed with linear at ip {}", ip);
    }
}

#[test]
fn trie_short_circuits_on_covering_ancestor() {
    // /16 + /24 nested: the /16 is a strict superset of /24.
    // Any IP within the /16 should match because of the /16
    // covers flag at depth 16, regardless of /24 membership.
    let prefixes: Vec<PrefixV4> = (0..17)
        .map(|i| p4(&format!("10.{i}.0.0/24")))
        .chain(std::iter::once(p4("10.0.0.0/16")))
        .collect();
    let set = PrefixSetV4::from_prefixes(prefixes);
    assert!(matches!(set, PrefixSetV4::Trie(_)));
    // 10.0.99.42: second octet 0 → in 10.0.0.0/16 (depth-16
    // covers short-circuits before we ever check the /24 layer
    // for 10.0.99/24, which wasn't inserted).
    assert!(set.contains("10.0.99.42".parse().expect("ip")));
    // 10.1.0.42: in 10.1.0.0/24 (depth-24 covers). NOT in
    // 10.0.0.0/16 because second octet is 1 not 0.
    assert!(set.contains("10.1.0.42".parse().expect("ip")));
    // 10.1.5.10: NOT in 10.1.0.0/24 (third octet 5 not 0) and
    // NOT in 10.0.0.0/16 (second octet 1 not 0).
    assert!(!set.contains("10.1.5.10".parse().expect("ip")));
    // 10.20.0.5: outside every inserted /24 (only 10.0..10.16
    // were inserted) and outside 10.0.0.0/16.
    assert!(!set.contains("10.20.0.5".parse().expect("ip")));
}

#[test]
fn trie_handles_zero_prefix_via_match_any_shortcut() {
    // /0 must be filtered to MatchAny by the constructor —
    // even when mixed with other prefixes.
    let prefixes = vec![p4("10.0.0.0/24"), p4("0.0.0.0/0"), p4("192.168.1.0/24")];
    let set = PrefixSetV4::from_prefixes(prefixes);
    assert!(matches!(set, PrefixSetV4::MatchAny));
    assert!(set.contains("8.8.8.8".parse().expect("ip")));
}

#[test]
fn trie_handles_full_host_prefix() {
    // A single /32 — only the exact host matches.
    let prefixes: Vec<PrefixV4> = (0..17).map(|i| p4(&format!("10.0.0.{i}/32"))).collect();
    let set = PrefixSetV4::from_prefixes(prefixes);
    assert!(matches!(set, PrefixSetV4::Trie(_)));
    assert!(set.contains("10.0.0.5".parse().expect("ip")));
    assert!(!set.contains("10.0.0.20".parse().expect("ip")));
    assert!(!set.contains("10.0.0.100".parse().expect("ip")));
}

#[test]
fn duplicate_prefixes_dont_corrupt_the_set() {
    // Insert the same /24 three times. prefix_count should be
    // 1 (de-duplication via covers-already-set check), and the
    // lookup must still return true for IPs in that /24.
    let prefixes: Vec<PrefixV4> = (0..17)
        .map(|i| p4(&format!("5.5.{i}.0/24")))
        .chain(std::iter::repeat_with(|| p4("10.0.0.0/24")).take(3))
        .collect();
    let set = PrefixSetV4::from_prefixes(prefixes);
    match &set {
        PrefixSetV4::Trie(t) => {
            // 17 unique /24s + 1 deduped (10.0.0.0/24) = 18 unique.
            assert_eq!(t.size, 18, "trie size should dedupe");
        }
        _ => panic!("expected trie variant"),
    }
    assert!(set.contains("10.0.0.42".parse().expect("ip")));
    assert!(set.contains("5.5.16.1".parse().expect("ip")));
}

#[test]
fn unsorted_input_works() {
    // Bit-walk insertion order shouldn't affect the result.
    let prefixes: Vec<PrefixV4> = vec![
        p4("192.168.1.0/24"),
        p4("10.0.0.0/8"),
        p4("172.16.0.0/12"),
        p4("8.8.8.8/32"),
        p4("203.0.113.0/24"),
    ];
    // Build twice with different orders; both must agree.
    let a = PrefixSetV4::from_prefixes(prefixes.clone());
    let mut shuffled = prefixes;
    shuffled.reverse();
    let b = PrefixSetV4::from_prefixes(shuffled);
    for ip_str in [
        "10.0.0.1",
        "192.168.1.42",
        "172.16.80.5",
        "8.8.8.8",
        "203.0.113.99",
        "8.8.4.4", // not in any prefix
        "1.1.1.1", // not in any prefix
    ] {
        let ip: Ipv4Addr = ip_str.parse().expect("ip");
        assert_eq!(a.contains(ip), b.contains(ip), "disagree at {}", ip);
    }
}
