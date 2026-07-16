# Triage result — ps-review-028.md

**Review:** Cohort 5 — NAT / NAT64 / NPTv6 (re-audit)
**Base:** `b1bd96fb6` (fresh) · **Triaged vs:** origin/master `198d5a593`
**Outcome:** 0 GENUINE residuals · 3 not-material · 11 negatives verified · 0 confabulated · 0 dup

## Dispositions (review self-classified all Low/Info; "0 new fail-opens")
- **L-01** SNAT `try_next_port` synthetic (protocol==0) port untracked — **NOT-MATERIAL**. `nat/source.rs:1057/1081/1138`, `allocator.rs:295` present, but protocol==0 is the "L4 tuple unknown" sentinel used only by address-only `match_source_nat` probes (never a real packet); the port can never be written to a frame (rewriters gate every L4 write on `has_l4_ports`). Self-refuted + documented (`source.rs:1030-1050`).
- **I-01** NAT64 `pool_index` AtomicUsize dead in production — **NOT-MATERIAL (dead-code)**. `nat64.rs:171` read only in `#[cfg(test)] allocate_v4_source` (:518). Documented test-only. 8 bytes/prefix, zero impact. → noted on #4421 cleanup tracker.
- **I-02** `source_nat_runtime_compatible` dead function — **NOT-MATERIAL (dead-code)**. `nat/source.rs:650` `#[allow(dead_code)]`, 0 call sites (superseded by `allocator_key` reload path). → noted on #4421.
- **N-01..N-11** NEGATIVE — verified-clean fail-closed paths.

## Dedup: none of the 3 overlap the open #4518/#4519/#4520 (ps-021 NAT findings); prior NAT fixes (#4511/#4506/#4399/#4438/#4388/#4519-merged) all confirmed present. All cited symbols exist in bpfrx (no avacado confabulation).

*Clean re-audit — no new issue warranted; the 2 dead-code items are cosmetic housekeeping (tracked on #4421).*
