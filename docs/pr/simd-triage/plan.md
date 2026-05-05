---
status: DRAFT v1 — pending adversarial plan review (4 SIMD-refactor proposals)
issues: #966 (SIMD policy classification), #967 (PSHUFB header rewrite), #968 (AES-NI/SHA-Ext crypto), #969 (AVX2 gather FIB)
phase: Triage all four; identify which (if any) survive adversarial review
---

## 1. Why one triage doc for four issues

#966/#967/#968/#969 are four issues filed with the same template
("Refactor: <Pattern>" / "The 'Amateur' Architecture" / "The Fix:
SIMD intrinsic"). They were grouped as "Tier D" SIMD refactor
proposals in the prior open-issues triage and flagged for
adversarial review. This single doc analyzes each against the
actual codebase so reviewers can verdict each in one pass.

Per the project's `feedback_difficult_path_pragmatism.md` memory:
"for 'Refactor: <Pattern>' issues proposing large rearchitectures,
stop and report rather than ship a wrong-target PR; #961/#946/#963/
#1144 all hit this." The pattern: speculative architectural
critique without measurement, proposing a refactor target that
doesn't match the actual hot path.

This plan EXPECTS most or all four to PLAN-KILL on cost-benefit
+ architecture-mismatch grounds. The job of the reviewer is to
either confirm or refute that with concrete code references.

## 2. Fresh perf measurement (current master, P=12 -R sustained)

From the #761 measurement on master HEAD `b029e91c`:

| % CPU | Symbol | Source |
|---:|---|---|
| 13.43 | `__memmove_evex_unaligned_erms` | libc — cross-worker FRAME-BODY memmove (#776) |
| 9.45 | `poll_binding_process_descriptor` | xpf-userspace-dp RX hot path (#777) |
| 5.94 | bpf_prog (XDP) | XDP redirect program |
| 4.50 | `worker_loop` | xpf-userspace-dp |
| 4.20 | `enqueue_pending_forwards` | xpf-userspace-dp TX dispatch (#779) |
| 1.52 | `htab_map_hash` | kernel — BPF hash map probe |
| 0.95 | `mlx5e_xsk_skb_from_cqe_linear` | mlx5_core — SKB fallback (#778) |

Note: **`__memmove_evex_unaligned_erms` IS already AVX-512 SIMD**
(EVEX = AVX-512 encoding). The 13.43 % cost is libc's hardware-
accelerated memmove on large frame bodies — not a scalar-byte
issue.

## 3. Per-issue codebase reality + verdict question

### #966 — SIMD policy classification (Bit-Vector / Tuple Space Search)

**Issue's premise**: "Your policy engine evaluates 5-tuples
against a list of rules ... doing this one packet at a time is
a waste of silicon ... evaluate one packet against 10000 rules
linearly."

**Codebase reality** (`bpf/headers/xpf_maps.h:146-187`):
- `zone_pair_policies` HASH map: key `(from_zone, to_zone)` →
  `policy_set_id`. **One hash probe per packet**, not 10K rule
  walks.
- `policy_rules` ARRAY map indexed by
  `policy_set_id * MAX_RULES_PER_POLICY + index`. The number of
  rules walked is bounded by `MAX_RULES_PER_POLICY` (current
  default ~32-64), not 10K.
- The walk is per-rule O(1) field comparisons against the BPF
  pkt_meta. SIMD over 5 tuple fields would replace ~5-10 ALU
  ops per rule with 1 vector op — saving fewer cycles than the
  hash probe itself.

**Codebase mismatch**: the issue assumes scalar 10K-rule walk;
reality is hash-keyed bounded array. Bit-vector / TSS
algorithms are designed for unbounded-rule-set hardware
firewalls (rte_acl handles 100K-rule ACLs). xpf's typical
config has dozens of policies, not thousands.

**Reviewer question**: is there ANY xpf workload where the
per-packet cost of 5-tuple comparison against the bounded
policy_rules array is a measurable bottleneck? The fresh perf
data shows zero contribution from policy lookup symbols.

### #967 — SIMD PSHUFB header rewrite

**Issue's premise**: "In `rewrite_forwarded_frame_in_place` you
are copying MAC addresses using `[u8; 6]` assignments, shifting
VLAN tags with `copy_within()` or memmove, and manually
rewriting TTL fields. Scalar memory copies generate a large
stream of micro-ops."

**Codebase reality**
(`userspace-dp/src/afxdp/frame/mod.rs:545,661,845`):
- `rewrite_forwarded_frame_in_place` does use `copy_within()`
  for the VLAN-add case (the ~14-byte→18-byte shift).
- BUT `__memmove_evex_unaligned_erms` (13.43 % CPU, the dominant
  symbol) is the cross-worker FRAME-BODY memmove for the
  `build_forwarded_frame_into_from_frame` path — copying 1.5KB
  packet bodies between worker UMEMs. That's not header rewrite.
- The header-only rewrite-in-place is invoked when no
  cross-worker copy is needed, and its cost doesn't appear in
  the perf top symbols (it's below the 0.95 % SKB-fallback
  noise floor).

**Codebase mismatch**: the issue targets the wrong cost. The
13.43 % memmove ALREADY uses AVX-512 (EVEX = AVX-512). Replacing
it with `_mm256_shuffle_epi8` would be a downgrade to AVX2.
PSHUFB on 32-byte headers would help only on the
header-rewrite-in-place path which is sub-1 %.

**Reviewer question**: would PSHUFB on the rewrite-in-place
path produce any measurable smoke-matrix delta? The relevant
benchmark is the cross-worker memcpy (#776), not the
header-rewrite hot path that #967 targets.

### #968 — AES-NI / SHA-Ext for SYN cookies + flow hashing

**Issue's premise**: "When generating SYN Cookies or hashing
flow 5-tuples for RSS / ECMP, your code likely relies on
standard Rust hashing (like SipHash or FxHash) executed in
software ... 14.8M cookies/sec will melt CPU."

**Codebase reality** (`bpf/xdp/xdp_screen.c:117,138,264,282`):
- SYN cookie generation uses kernel kfuncs:
  `bpf_tcp_raw_gen_syncookie_ipv4` /
  `bpf_tcp_raw_gen_syncookie_ipv6`. These are kernel-side and
  the kernel already uses hardware crypto where available.
- xpf userspace does NOT generate its own SYN cookies; the
  per-packet path delegates to the kernel.
- Flow hashing is done by the NIC for RSS (mlx5 RX hash). xpf
  doesn't compute its own RSS hash on the per-packet path.

**Codebase mismatch**: the issue assumes xpf is doing software
crypto for SYN cookies in userspace. It isn't — kernel kfunc.
The 14.8M cookies/sec scenario isn't in xpf's userspace path
at all.

**Reviewer question**: is there ANY actual software crypto
hot path in the xpf userspace dataplane today, on the per-
packet level? If yes, name it. If no, this issue is targeting
a non-existent code path.

### #969 — AVX2 gather for FIB / DIR-24-8 trie

**Issue's premise**: "When a new session is evaluated, your
code performs a Longest Prefix Match (LPM) lookup in the FIB
... walking the routing trie 64 separate times sequentially."

**Codebase reality**
(`bpf/headers/xpf_helpers.h:2419` and adjacent):
- xpf's FIB lookup uses the kernel kfunc `bpf_fib_lookup`. The
  kernel's FIB trie is highly optimized with kernel-internal
  caches. xpf does NOT walk a userspace LPM trie.
- For sessions, FIB is consulted at session-create time only.
  The hot path is session-table HASH lookup, not LPM.
- AVX2 gather instructions (`_mm256_i32gather_epi32`) on Intel
  CPUs were de-optimized following Spectre/Meltdown mitigations
  — gather has been measured slower than scalar loads on
  Skylake-X / Ice Lake / Sapphire Rapids in many real
  workloads. This is a known trap in production code.

**Codebase mismatch**: the issue assumes xpf does its own LPM.
It doesn't — kernel kfunc handles it. Even if a userspace LPM
were added, AVX2 gather is the wrong tool for it on Intel CPUs.

**Reviewer question**: where in xpf userspace would this
DIR-24-8 trie + AVX2 gather actually be wired? If it would
replace `bpf_fib_lookup`, that's a major architectural
change (userspace replacing a kernel facility); name the
target callsite. If it would supplement it, name the workload
where session-create-time FIB lookup is a measurable
bottleneck.

## 4. Risk assessment (whole batch)

| Class | Verdict | Notes |
|---|---|---|
| Operator value | **LOW** | Each issue targets a code path that the fresh perf data shows is NOT the bottleneck. The dominant 13.43 % cost is cross-worker memcpy (#776), 9.45 % is RX poll (#777). SIMD on policy/header/crypto/FIB doesn't address either. |
| Architectural mismatch (#961 / #946-Phase-2 dead-end) | **HIGH** | All four follow the "Refactor: <Pattern>" template. The premises don't match the codebase. Same shape as prior PLAN-KILLs. |
| Implementation risk | **HIGH** | Each proposal would require multi-week implementation. SIMD intrinsics are CPU-specific (Intel-only AVX2/AVX-512), need fallback paths, complicate verifier acceptance for BPF programs. |
| Hot-path budget | **NEUTRAL** | The hot-path budget at 22.9 Gbps is ~1 µs/packet. SIMD wins ~10 ns per call site. To move smoke matrix gates by 1 %, need to win ~10 ns × 0.01 / per-packet-headroom — i.e., the SIMD callsite has to be ~10 % of CPU. None of the proposals' targets are. |

## 5. Test plan if any survives

For any issue that survives adversarial review:
- Stage 0: targeted measurement showing the proposed callsite
  is at least **2 % CPU** in the fresh perf data, AFTER counting
  any new dispatch/setup cost the SIMD path would introduce.
- Stage 1: prototype with feature-flag fallback to scalar.
- Stage 2: A/B perf measurement showing ≥ 1 % CPU reduction on
  the smoke matrix.
- Stage 3: full implementation + verifier acceptance + smoke.

Without Stage 0 measurement showing a real ≥ 2 % bottleneck on
the proposed callsite, none of these should proceed.

## 6. Out of scope

- Generic "make the dataplane faster" investigation — already
  tracked as #774 (DP ceiling 18 vs 25+ Gbps), #775 (campaign),
  #776 (12 % memcpy), #777 (RX poll), #779 (TX dispatch), #781
  (structural pipeline stall, biggest single win). Those are
  the actual bottlenecks; SIMD on policy/header/crypto/FIB are
  not on that list.

## 7. Recommended verdict shape

For each of #966, #967, #968, #969 individually, the reviewer
returns one of:

- **PLAN-READY**: codebase mismatch claims above are wrong,
  there's a real callsite, perf measurement supports the SIMD
  win. (Unlikely.)
- **PLAN-NEEDS-MAJOR**: the issue identifies a real concern but
  the proposed approach is wrong; rewrite needed. (Possible
  for some.)
- **PLAN-KILL**: codebase mismatch confirmed; close the issue
  with the kill rationale + a pointer to the actual bottleneck
  issues (#776/#777/#781). (Most likely outcome for all four.)

## 8. Open questions for adversarial review

(Per-issue questions are in §3 above. Two cross-cutting
questions for the batch:)

1. **Is the project's "Refactor: <Pattern>" pattern producing
   any actual signal?** This is the 5th-6th batch of these
   issues that look like they were generated from a generic
   "audit the architecture" template without reading the
   codebase. If reviewers think the pattern is producing
   negative signal, that's worth flagging back to whoever is
   generating these.

2. **For any issue that survives, is the implementation cost
   worth it given xpf's actual scale targets?** xpf's gate is
   22+ Gbps on a 6-worker cluster. The proposed SIMD wins are
   relevant at 100+ Gbps with O(1000) interfaces / O(10K)
   policies — orders of magnitude beyond xpf's design point.
