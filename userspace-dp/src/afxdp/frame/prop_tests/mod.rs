//! #1824 — in-tree proptest harness for the frame layer.
//!
//! Surfaces (plan: docs/research/1824-fuzz-harness/plan.md §5.3):
//!   - `inspect.rs`  — S1: parse no-panic (P-I1), bounds (P-I2), offset
//!     consistency (P-I3), valid-packet round-trip (P-I4), meta
//!     independence (P-I5).
//!   - `rewrite.rs`  — S2: NAT round-trip identity (P-N1) with the
//!     P-N2 validity oracle, descriptor-vs-generic differential
//!     (P-N3), decline/divergence pins as deterministic examples
//!     (P-N3b — including the #1838/#1839/#1840 defect pins), payload
//!     immutability (P-N4).
//!   - `segment.rs`  — S4: TSO splitter no-panic (P-T1), reassembly
//!     identity (P-T2), per-segment wellformedness (P-T3), NAT
//!     composition (P-T4).
//!   - `strategies.rs` — shared generators (garbage frames, arbitrary
//!     metadata, valid packet builders, structured IPv6 ext-header
//!     chains, NAT decisions).
//!   - `oracle.rs` — test-local full-recompute checksum validity
//!     oracle + masked byte-equality helper. Deliberately NOT
//!     `verify_built_frame_checksums` (v4-TCP-only, frame/mod.rs:1129
//!     early-returns `(true, true)` for everything else).
//!
//! Determinism contract (plan §5.4): passing runs use a fresh random
//! seed each run — continuous exploration is the point. What is
//! deterministic: (a) the committed `proptest-regressions/**` corpus,
//! replayed FIRST on every run (the actual regression-pinning
//! mechanism — never hand-edit or delete those files), and (b) the
//! explicit case counts below.
//!
//! Soak knob: `PROPTEST_CASES=100000 cargo test --release prop_` for
//! operator-driven deep runs; never wired into any gate.
//!
//! Known production divergences excluded from the property domains and
//! pinned by deterministic examples instead (tests must land green; we
//! don't commit xfail):
//!   - #1838 (D3): generic v6 NAT path assumes L4 at fixed offset 40 —
//!     NAT-applying generators emit IPv6 WITHOUT extension headers.
//!   - #1839 (D1): v6 0x0000→0xFFFF L4-checksum canonicalization scope
//!     mismatch (descriptor: all protocols; generic: UDP/ICMPv6 only)
//!     — byte comparisons exclude L4 checksum bytes; validity oracle
//!     accepts both one's-complement zero encodings.
//!   - #1840 (D2): family-ungated UDP zero-checksum skip on port
//!     rewrite — valid-packet generators never emit v6 UDP checksum 0.

use super::*;
use proptest::prelude::*;

mod inspect;
mod oracle;
mod rewrite;
mod segment;
mod strategies;

/// Explicit per-property config (plan §5.4): fixed case counts, fresh
/// run seed, bounded shrink effort. `PROPTEST_CASES` (read by proptest
/// itself before our overrides? it is not — we set cases explicitly,
/// so the env soak knob goes through `with_cases_env`).
fn cfg(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases: cases_env_override(cases),
        max_shrink_iters: 4096,
        ..ProptestConfig::default()
    }
}

/// Honor `PROPTEST_CASES` as a soak override even though every
/// property sets an explicit count (an explicit `cases` field would
/// otherwise shadow the env var).
fn cases_env_override(default_cases: u32) -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(default_cases)
}
