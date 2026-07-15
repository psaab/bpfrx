# Triage result — ps-review-029.md

**Review:** Cohort 6 — Session / conntrack (source repo /home/ps/git/avacado-xpf, but NOT confabulated — avacado+bpfrx in sync for this tree at this base)
**Base:** `b1bd96fb6` · **Triaged vs:** origin/master `198d5a593`
**Outcome:** 1 GENUINE residual (LOW) · 2 dup · 2 already-fixed · 7 negatives · 2 not-distinct · 0 confabulated

## Dispositions
- **M-02 → #4539** GENUINE (LOW hardening): should_cache_local_delivery_session_on_miss (forwarding/mod.rs:1741-1789) caches pure PSH/null/URG first packets via 2 narrow decline-gates instead of a positive has_syn predicate. Policy-skip NOT exploitable (poll_descriptor:899 re-runs junos-host teardown per hit). Fix: cache iff has_syn.
- **C-01/S-001** cross-zone hijack via bare 5-tuple SessionKey — DUP (review's own "confirmation not re-report"; ≈ the open #2387 VRF-session-key needs-decision).
- **C-02/S-002** bare ACK → ESTABLISHED 300s — DUP + documented-intentional mid-stream pickup (#3152 comment at install.rs:152-158).
- **C-03 (P6)** RST/FIN creates session — ALREADY-FIXED (#4400/#4453/#4487; all 3 arms gate is_closing && !has_syn).
- **C-04 (P7)** fabric NAT skip — ALREADY-FIXED (#4414/#4439; TCP|ICMP|ICMPv6 allowlist).
- **M-01** PSH+ACK first-packet → ESTABLISHED — DUP/NOT-MATERIAL (same is_initial_syn root as S-002; material PSH+ACK-with-data is the documented mid-stream pickup).
- **L-01** established-bool tri-state — NOT-MATERIAL (design/observability suggestion).
- **N-01..N-07** NEGATIVE (per-worker limit #2186/#1855, spoofed SYN-ACK F16, cross-worker race, NAT 1:N, sticky flags, bare-SYN→OPENING, flow-cache TCP state — all verified fail-closed).

## Confabulation check: PASSED — every cited symbol/file/line exists in bpfrx + matches (unlike the ps-021 avacado sibling). This session tree is in sync between the forks at this base.
