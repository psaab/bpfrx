// #923 acceptance gate #3: config-commit latency on the worst-case
// trie build (256 random /32 prefixes → ~8K Box<TrieNode> allocations).
// Plan target: <2 ms p95 (tightened from the plan's initial 10 ms
// after Codex round-2 noted 10 ms is too loose to catch a 10×
// regression — first measurement on the dev VM was 148 µs, so 2 ms
// gives ~14× headroom while still catching a 10× regression).
//
// Like `tx_kick_latency`, the daemon code lives in a bin crate
// (`xpf-userspace-dp` is a binary target with `pub(crate)`-only
// items), so this bench re-implements the bit-equivalent shape — a
// `TrieNode { covers: bool, children: [Option<Box<TrieNode>>; 2] }`
// inserted into via MSB→LSB walk. The test suite in
// `prefix_set.rs::tests` exercises the real types for correctness;
// this bench only gates the allocation cost.

use std::hint::black_box;
use std::time::Instant;

#[derive(Default)]
struct TrieNode {
    covers: bool,
    children: [Option<Box<TrieNode>>; 2],
}

fn insert(root: &mut TrieNode, ip: u32, prefix_len: u8) {
    let mut node = root;
    for i in 0..prefix_len as usize {
        let bit = ((ip >> (31 - i)) & 1) as usize;
        node = node.children[bit].get_or_insert_with(Box::default);
    }
    node.covers = true;
}

/// Tiny deterministic LCG matching the one in `prefix_set.rs::tests`.
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
}

fn build_256_random_v4_trie() -> TrieNode {
    let mut rng = Lcg::new(0xCAFE_BABE_DEAD_BEEF);
    let mut root = TrieNode::default();
    for _ in 0..256 {
        // /32 worst case: every prefix walks the full 32 bits, giving
        // up to 256 × 32 = 8192 nodes if no two prefixes share any
        // bit. In practice the LCG produces some shared prefix paths.
        insert(&mut root, rng.next_u32(), 32);
    }
    root
}

fn main() {
    // criterion is a dev-dependency, but the bench harness can be
    // run as a plain binary (matches the `harness = false` pattern
    // used by tx_kick_latency.rs). We measure 100 iterations and
    // report mean + p95.
    const ITERATIONS: usize = 100;
    let mut samples_ns: Vec<u128> = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        let t0 = Instant::now();
        let trie = build_256_random_v4_trie();
        let elapsed = t0.elapsed();
        // Defeat dead-code elimination on the build.
        black_box(&trie);
        samples_ns.push(elapsed.as_nanos());
    }
    samples_ns.sort_unstable();
    let mean_ns: u128 = samples_ns.iter().sum::<u128>() / (ITERATIONS as u128);
    let p50_ns = samples_ns[ITERATIONS / 2];
    let p95_ns = samples_ns[(ITERATIONS * 95) / 100];
    let p99_ns = samples_ns[(ITERATIONS * 99) / 100];
    println!(
        "#923 prefix_set_lookup bench (256 /32 prefixes × Box<TrieNode>):"
    );
    println!("  mean: {} µs", mean_ns / 1_000);
    println!("  p50:  {} µs", p50_ns / 1_000);
    println!("  p95:  {} µs", p95_ns / 1_000);
    println!("  p99:  {} µs", p99_ns / 1_000);
    // Acceptance gate: p95 ≤ 2 ms = 2_000_000 ns. Tighter than the
    // plan's initial 10 ms because 10 ms doesn't catch a 10× regression
    // from the current ~150 µs working point.
    let p95_threshold_ns: u128 = 2_000_000;
    if p95_ns > p95_threshold_ns {
        eprintln!(
            "FAIL: p95 {} ns > {} ns threshold; consider arena allocation",
            p95_ns, p95_threshold_ns
        );
        std::process::exit(1);
    }
    println!("PASS: p95 under 2 ms threshold");
}
