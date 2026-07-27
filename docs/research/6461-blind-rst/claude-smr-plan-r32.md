# Claude SMR hostile plan-review — round 32 (v9.9.16 @ da60ac471)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.16 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.16-as-committed** — two self-found inventory/test gaps of exactly the
class Codex hunted in r30-M5 and r31-Q4. The design mechanisms themselves
survive my re-trace; the doc's SSOT inventories do not yet reflect them.

## Finding 1 (MEDIUM — §5.8 wire-schema inventory misses the lease inputs)

v9.9.16 added `(persistent_nat, persistent_nat_permit)` to the INSTALL tail
in the §5.2 B2 paragraph, but the §5.8 normative wire schema still says the
INSTALL/Open delta carries only `{(origin_process_nonce,
flow_incarnation_id, stable_rule_id_hash, admission_config_version)}`, and
the Go sidecar store inventory + atomic-snapshot tuple do not list the lease
inputs either. An implementer reading only §5.8 (the normative SSOT) builds
a tail without the lease inputs and re-opens the r31-B1 epoch-skew trace.
The lease inputs must be added to: (a) the §5.8 INSTALL tail inventory; (b)
the Go sidecar per-entry store (they are needed for resend/bulk
reconstruction — a resend must re-emit the SAME stamped inputs, not
re-derive them from the sender's current config, or the epoch-skew trace
returns through the resend path); (c) the atomic-snapshot tuple. Also state
the stamp-site rule explicitly: the inputs are stamped INTO THE ENTRY at
admission by the helper (same provenance as `stable_rule_id_hash` /
`admission_config_version`), and every wire emission (initial, resend, bulk)
carries the ENTRY's stamps — never a queue-time view.

## Finding 2 (MEDIUM — §9 test plan has no coverage of the r31/v9.9.16 mechanisms)

The §9 test inventory covers the escrow/conditional-delete fences but has no
cases for: (a) the epoch-skew lease import (C1 target-host-port → C2
any-remote-host; g2 INSTALLs processed while C1 is applied; assert F1/F2
co-hold P via the wire-carried inputs and no mid-flow port swap at
takeover); (b) the kind dispatch (persistent address-only flow preserving
source port 80 imports on the standby with NO port-bit reservation; public
address unchanged at failover); (c) the symmetric dual-record (release
through A during the migration window releases B's record; B never issues a
held tuple and never leaks a freed one); (d) the legacy tail-less import
stays non-persistent (rolling-upgrade parity with master); (e) the
cutover-fence path enumeration (a deterministic-PAT allocation attempted
during the migration window dual-applies or transient-fails). Add them.

## Finding 3 (nit — dual-apply lock order)

"Dual-applies to A and B under one lock" should name the order: the
migration wrapper locks A's `shared.live` then B's in a FIXED A→B order (A
and B are distinct `PortAllocator` objects); a single coordinator-driven
migration at a time makes this deadlock-free structurally, but say it.

## Verified-sound this round (my own re-trace)

- r31-B1 fold: wire-carried inputs close the epoch-skew trace for the
  initial-INSTALL path; legacy tail-less import = exactly master's
  `persistent_key: None` behavior (source.rs reserve path records
  `persistent_key: None` today) — parity confirmed, no new gap.
- r31-B2 fold: the ownership-path enumeration matches the source
  (allocate_translation, deterministic PAT source.rs:1431, deterministic
  NAT64 :995, address-only :1523, persistent address-only :1497,
  reserve_flow/reserve_address_only*, release paths).
- r31-H3 fold: kind dispatch is coherent; `reserve_address_only_persistent`
  (allocator.rs:1924) confirms the lease shape; pinning the wire address on
  create is a well-defined variant.
- r31-H4/L5 folds: stragglers removed; full-document grep clean except the
  §5.8 inventory gap (Finding 1).

## Verdict

**PLAN NO for v9.9.16** — fold Findings 1-3 as v9.9.17 (text/inventory/test
additions, no design change). Part A remains converged and untouched.
