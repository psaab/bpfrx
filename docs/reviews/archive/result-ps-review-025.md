# Triage result — ps-review-025.md

**Review:** Cohort 1 — Policy verdict engine (`userspace-dp/src/policy.rs` + `pkg/policymatch`)
**Base:** `b1bd96fb6` (fresh, ~current) · **Triaged vs:** origin/master `a16ee5d08`
**Outcome:** 0 GENUINE residuals · 1 deliberate · 1 dup(#4146) · negatives verified · already-fixed(prior ps-019 5×HIGH) · 0 confabulated

## Dispositions
- **L-01** `PolicyState::default()` empty `default_counter.rule_id` — **DELIBERATE/NOT-MATERIAL**. Documented safe-guard (`policy.rs:2355-2357`): the empty-rule_id `Default` placeholder is not produced on any production path; production `parse_policy_state_with_counters` stamps `"default-policy"` via `rule_hit_counter` (`policy.rs:2628`). Dup of ps-018 H-01. No live path binds an empty-id counter.
- **L-02** XDP-shim `is_local_destination` shunts DNAT-external/local IPs to kernel, bypassing the userspace junos-host deny gate — **DUP of open #4146** (cited shim symbols exist `userspace-xdp/src/lib.rs:1363`; #4146's commit-warn partly landed). XDP-shim-layer gap BEFORE userspace-dp — out of the policy.rs cohort scope; the userspace gate is correct where consulted.
- **I-01/I-02/I-03 + N-01..N-17** — NEGATIVE (verified correct on master): MaxRulesPerPolicy overflow fail-closed, parse_port_spec("0")→reject (`policy.rs:4185/4191`), to-zone-any lifeline conservative-by-design, unzoned guard `from_id!=0 && to_id!=0` (#3110), address-excluded both-family-empty fail-closed, default→Deny+unknown→snapshot-reject, ICMP type/code validation, parse_protocol esp/ah/sctp/vrrp/igmp/pim/egp arms.
- **Prior ps-019 F-C1-02..F-C1-11 (5 HIGH)** — ALREADY-FIXED, all re-confirmed present on master (no regression between base and current).

## Confabulation check: NONE — every cited symbol located in bpfrx (this cohort clean of the ps-021 cross-fork contamination).

*The policy verdict engine is fully hardened. This re-confirms the prior ps-019 (Cohort-1) 0-residual result on a fresh base. No new issue filed.*
