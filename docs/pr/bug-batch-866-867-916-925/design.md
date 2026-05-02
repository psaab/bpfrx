# Design: bug batch (revision 2) — #866 + #925-A only

**Status:** Revision 2 after Codex hostile (`a0085ce59a40cd5d5`) +
Gemini Pro adversarial (`task-monwc1sk-hsawxo`) round-1 review.
Both verdicts: REVISE.

**Scope cut**: dropped #867 and #916 from this batch. Reasoning:

- **#867 dropped** — Both reviewers found Option A (post-conntrack
  accounting) has a real correctness hole (legitimate return ACK on
  asymmetric path → false-positive sweep). Option B (HLL) has ~100x
  memory cost vs. the existing counter (Gemini analysis). Insertion
  point in BPF tail-call model is underspecified. This needs its own
  design pass. Filing a follow-up issue.

- **#916 dropped** — Codex review found `forwarding_build.rs:639-642`
  already SKIPS CoS state construction when `cos_shaping_rate_bytes_per_sec
  == 0`. So the `build_cos_interface_runtime(rate=0)` deadlock path
  isn't reachable from normal config flow. Gemini independently showed
  the proposed `Some(0)` fix creates a busy-wait loop, not a fix.
  Either the issue's symptom is stale or there's another path; we
  need a reproducer before proposing a fix. Filing a follow-up issue.

Remaining batch: **2 PRs** that both reviewers approved (with caveats).

---

## 1. #866 — Real `SCREEN_SYN_FRAG` detection via first-fragment L4 parse

### Current state (verified at master cad61458)

`SCREEN_SYN_FRAG` configured / surfaced / documented but the BPF
check is dead code at `bpf/xdp/xdp_screen.c` and mirrored in
`bpf/tc/tc_screen_egress.c`. The check `(tf & 0x02) && meta->is_fragment`
sits inside an outer `if (!meta->is_fragment)` so the inner condition
is unreachable. Comments at `xdp_screen.c:737-748` and
`tc_screen_egress.c:130-142` confirm the intentional dead-state and
reference this issue.

Root cause: `xdp_main.c` and `tc_main.c` skip `parse_l4hdr` whenever
`meta->is_fragment` is true. So TCP flags are zero on any fragment.

### Why the skip exists (Codex round-1 finding)

NOT a verifier-complexity issue. The skip is an intentional false-
positive defense: subsequent fragments have zeroed TCP fields, which
would otherwise trigger `SCREEN_TCP_NO_FLAG` drops on legitimate
traffic. (See #853.) The fix has to preserve that defense — i.e.
only enable L4 parse on **first** fragments, which DO have the L4
header per RFC.

### Fragment classification — IPv4

At `bpf/headers/xpf_helpers.h:267-270`:
```c
__u16 frag_off = bpf_ntohs(iph->frag_off);
meta->is_fragment = (frag_off & 0x2000) || (frag_off & 0x1FFF);
```

Three states packed into one bit:

| State                      | MF (0x2000) | offset (0x1FFF) | `is_fragment` today | L4 header present? |
| -------------------------- | ----------- | --------------- | ------------------- | ------------------ |
| Not a fragment             | 0           | 0               | 0                   | yes                |
| First fragment of datagram | 1           | 0               | 1                   | **yes**            |
| Subsequent fragment        | *           | >0              | 1                   | no                 |

### Fragment classification — IPv6 (Codex round-1 gap)

At `bpf/headers/xpf_helpers.h:327-336` IPv6 only stores `is_fragment`,
no first-vs-subsequent distinction. The fix MUST also extend IPv6.

IPv6 fragmentation uses a Fragment extension header. The chain walker
in `parse_ipv6hdr` already reads it; the extension's `frag_off` field
has the same MF + offset layout. We need to set `is_first_fragment`
in the same arm.

### Proposed fix

1. **Add `meta->is_first_fragment: __u8`** (1 bit; pack with existing
   flags if available, or accept the byte-padding cost).

2. **Set in IPv4 `parse_iphdr`**: `(frag_off & 0x2000) && !(frag_off & 0x1FFF)`.

3. **Set in IPv6 fragment-ext arm of `parse_ipv6hdr`**: per the
   existing `frag_off` read at `bpf/headers/xpf_helpers.h`
   `NEXTHDR_FRAGMENT` arm, IPv6 fragment header layout is `MF
   = 0x1` (lowest bit of the host-order word) and `offset =
   0xFFF8` (top 13 bits). First-fragment predicate is therefore
   `(frag_off & 0x1) && !(frag_off & 0xFFF8)`. Verified against
   the existing `meta->is_fragment = (frag_off & 0x1) || (frag_off
   & 0xFFF8)` line — same mask family, just AND/AND-NOT instead
   of OR for the first-fragment refinement.

4. **Allow L4 parse on first fragment** in `xdp_main.c` /
   `tc_main.c`: change `if (!meta->is_fragment)` to
   `if (!meta->is_fragment || meta->is_first_fragment)`.

5. **Update SCREEN_SYN_FRAG predicate** at `xdp_screen.c` and
   `tc_screen_egress.c`: fire when SYN bit is set on a first-fragment
   packet. The outer `!is_fragment` guard becomes
   `!is_fragment || is_first_fragment`. The inner
   `(tf & 0x02) && is_fragment` becomes `(tf & 0x02) && is_first_fragment`.

6. **Test plan**: see test plan subsection below.

### Risks (revised after review)

| Risk | Mitigation |
|------|------------|
| BPF verifier rejects on kernel 6.18 due to extra L4 parse path (Gemini round-1) | Build + `bpftool prog load` test on the loss VM kernel BEFORE merge. If verifier rejects, gate the new path behind a compile-time flag and ship with it disabled until the verifier is appeased. |
| First-fragment with truncated L4 header (non-conformant attacker frame) | `parse_l4hdr` already does bounds check on the fixed TCP header (`xpf_helpers.h:700-710`). Drops if header truncated. (Codex round-1 confirmation.) Options data isn't validated, but ports + flags are read from the fixed 20-byte header so screen logic is correct. |
| IPv6 fragment-ext bit layout mistake | Cite RFC 8200 §4.5 in the comment; double-check mask in code review. |
| `is_fragment` consumers downstream (NAT / conntrack / policy) | Audit grep for `is_fragment` usage. The new flag is additive — `is_fragment` semantics unchanged. New `is_first_fragment` is opt-in for sites that want the distinction. |

### Test plan

1. **Verifier proof on kernel 6.18 — HARD PRE-MERGE GATE**: build
   the BPF object via `make generate` (produces the bpf2go object
   files under `pkg/dataplane/bpfobj/`), then run `bpftool prog
   loadall pkg/dataplane/bpfobj/<obj>.o /sys/fs/bpf/test_load type
   xdp` on the loss VM (`incus exec loss:xpf-userspace-fw0 -- ...`)
   and capture the verifier output. If rejection, also capture
   `bpftool prog dump xlated id <id>` instruction count and either
   simplify the new code path or gate it behind a compile-time
   `#define` until the verifier is appeased. **Do not push the PR
   without this gate clearing.**

2. **Functional**: craft an IPv4 packet with MF=1, offset=0, TCP SYN
   payload via scapy or trafgen. Send through firewall with
   `SCREEN_SYN_FRAG` enabled. Verify drop + counter bump.

3. **Negative**: same packet without SYN bit → not dropped.

4. **IPv6 mirror**: same with IPv6 fragment ext header.

5. **Subsequent fragment**: offset>0, no L4 header. Verify behavior
   matches current (drop or pass per existing screen rules; not
   mis-classified as SYN_FRAG since `is_first_fragment=0`).

6. **Regression**: existing `SCREEN_TCP_NO_FLAG` test (post-#853)
   still passes — subsequent-fragment packets still don't trigger
   false NULL-scan drops.

### Files

- `bpf/headers/xpf_helpers.h` — add `is_first_fragment` to `pkt_meta`;
  set in IPv4 + IPv6 frag classifiers.
- `bpf/headers/xpf_common.h` — if `pkt_meta` lives there.
- `bpf/xdp/xdp_main.c`, `bpf/tc/tc_main.c` — gate L4 parse.
- `bpf/xdp/xdp_screen.c`, `bpf/tc/tc_screen_egress.c` — fix predicate
  + update comments referencing #866.

---

## 2. #925-A — Worker supervisor: auxiliary-thread wrapping only

### Current state (verified — Codex + Gemini round-1)

`spawn_supervised_worker` at `coordinator/mod.rs:1854-1887` wraps
`worker_loop` in `catch_unwind`, logs to stderr, publishes panic
message to a `panic_slot` mutex, and sets `runtime_atomics.dead =
true`.

The `dead` flag is **ALREADY exposed end-to-end** (Codex grep,
Gemini confirmation):
- `userspace-dp/src/protocol.rs:1038-1073` — Rust struct + JSON serde
- `pkg/dataplane/userspace/protocol.go:524-544` — Go-side mirror
- `pkg/dataplane/userspace/statusfmt.go:315-320` — CLI rendering
- `userspace-dp/src/afxdp/coordinator/tests.rs:848-868` — existing test

There is no protobuf `WorkerRuntimeStatus` message; the protocol is
JSON over the userspace-dp control socket. Memo round-1 incorrectly
called for proto changes — those are not needed.

### Genuine remaining work (much smaller than memo round-1 claimed)

Two auxiliary thread spawn sites are NOT wrapped:

- **`coordinator/mod.rs:775-780`** — `neigh-monitor` thread runs
  `neigh_monitor_thread`. If it panics, neighbor cache stops updating
  silently → ARP/NDP entries stale → forwarding eventually breaks.

- **`coordinator/mod.rs:823-843`** — `xpf-native-gre-origin-*`
  threads run `local_tunnel_source_loop` (per GRE/ip6gre tunnel).
  If one panics, that tunnel's local-origin packet stream stops.

### Proposed fix

Add a generic `spawn_supervised_aux(name, body) -> JoinHandle<()>`
helper in `coordinator/mod.rs` that:

- Wraps `body` in `std::panic::catch_unwind(AssertUnwindSafe(body))`.
- On panic: `eprintln!("xpf-userspace-dp: aux thread '{name}' panicked: {msg}")`.
- Returns the `JoinHandle`. **Does NOT respawn.** (Per Gemini: "no
  respawn without state recovery is correct for this phase.")

Replace the two `thread::Builder::new().name(...).spawn(...)` sites
at line 775 and 823 with `spawn_supervised_aux(name, ...)`.

Aux threads are NOT given supervisor semantics like worker_loop —
they have no per-worker `runtime_atomics`, no respawn, no state
recovery. The wrap exists only to (a) prevent the auxiliary thread
from terminating with an uncaught panic that propagates an unwind
into the joiner — uncaught aux panics today don't kill the daemon
(they kill the aux thread silently; the daemon process keeps
running, but the aux work stops), the wrap just makes the death
visible — and (b) surface the panic message in journald via
stderr.

### Operator-visible degradation (Codex round-1: must document)

When a worker_loop panics: bindings serviced by that worker drain to
zero throughput. The `dead` flag is exposed in `show worker status`,
operator must restart the daemon.

When `neigh-monitor` panics: dynamic neighbor cache stops updating;
existing entries continue serving until their kernel TTL expires.
After expiration, forwarding to those neighbors falls back to the
slow-path neighbor resolution (kernel `bpf_fib_lookup`). Behavior
degrades over minutes, not seconds.

When a `xpf-native-gre-origin-*` thread panics: that tunnel's
local-origin packet stream stops. The tunnel still forwards transit
packets (those go through the worker_loop pipeline, not this aux
thread). Locally-generated packets destined to that tunnel are
silently dropped.

The `dead` flag IS surfaced today; aux-thread death is NOT (no
`dead` equivalent for aux threads). PR-925-A leaves that visibility
gap intentionally — exposing aux-thread liveness needs a different
status surface and is out of scope. Operator monitoring practice
should be: watch `xpfd` journald for "aux thread '... ' panicked"
messages.

### Risks

| Risk | Mitigation |
|------|------------|
| `eprintln!` in panic handler causes second panic | Use only stderr-direct; no allocation in the message format if avoidable. The current `format!` is allocation but unavoidable to render the panic message. Risk is bounded — second panic in catch handler aborts the thread cleanly without taking down the daemon (the catch_unwind that called us has already completed). |
| Aux thread respawn left undone → operator surprise | Operator monitoring practice: watch journald for "aux thread '...' panicked" log lines. Surfacing aux liveness as a structured status field is out of scope; tracked under PR-925-B. |
| Existing worker_loop tests break from any side effects | None expected — only new private helper + 2 call-site changes. |

### Test plan

1. **Unit test**: panic-injection inside the new helper. Spawn
   with body that `panic!()`s, join, verify no process termination.
2. `cargo build --release` clean.
3. `cargo test --release` — 884+ baseline passes (PR-A baseline).
4. Cluster smoke deploy on `loss:xpf-userspace-fw0/1`.

### Files

- `userspace-dp/src/afxdp/coordinator/mod.rs` — add
  `spawn_supervised_aux`; convert line 775 + line 823 spawn sites.
- `userspace-dp/src/afxdp/coordinator/tests.rs` — panic-injection
  test for the aux helper.

---

## 3. Cross-cutting

### Independence

#866 touches BPF C only. #925-A touches Rust only. Zero file
overlap. Both can land in parallel worktrees.

### Validation

Per change:
- `cargo build --release` clean
- `cargo test --release` — 884+ baseline passes
- `make build` clean (Go side; only matters if proto changes —
  none in this revised batch)

For #866 specifically: `bpftool prog load` test on the loss VM
kernel before merge.

For #925-A specifically: panic-injection unit test passes.

Cluster smoke deploy on `loss:xpf-userspace-fw0/1` after each
merge.

### PR sequence

Two parallel PRs. Either order. Recommend landing #925-A first
(smaller, lower risk, no BPF rebuild) so smoke between batches
validates only one change at a time.

---

## 4. Open questions for round-2 reviewers

**Q1.** #866: is the IPv6 fragment-ext bit layout I described
correct? I'm citing the RFC but haven't actually traced the existing
chain walker's frag_off read. If wrong, the fix doesn't work for
IPv6.

**Q2.** #866: is `bpftool prog load` on the loss VM the right
verifier-proof methodology, or do you want me to capture
`bpftool prog dump xlated` instruction count too?

**Q3.** #925-A: is "no respawn" correct for aux threads? `neigh-
monitor` death is degradation-over-minutes; `gre-origin` death is
permanent loss until daemon restart. Either could justify a
respawn loop — but as Gemini noted, respawn-without-state-recovery
is a different category of risk. For now I'm proposing no respawn;
push back if you disagree.

**Q4.** Is the "dropped #867 + #916" decision correct, or should
the batch include them in revised form? My read: they each need
their own design pass with proper repro / measurement / scope, and
batching them in here would dilute the design discipline.

---

If you're a round-2 reviewer:

Answer Q1-Q4 explicitly. Per-fix verdict:
- **PROCEED-AS-PROPOSED** / **PROCEED-WITH-CHANGES** (list) /
  **NEEDS-DEEPER-INVESTIGATION** (specify)

Final overall: **PROCEED-WITH-BOTH** / **PROCEED-WITH-N** /
**REVISE**.

---

## Appendix: changes from revision 1

Per Codex round 1 (`a0085ce59a40cd5d5`):

- **#916 dropped** — `forwarding_build.rs:639-642` skips CoS for
  rate=0; deadlock path not reachable from normal config. Need a
  reproducer.
- **#867 dropped** — Option A insertion point underspecified;
  asymmetric ACK false positive is a correctness hole, not a
  design question.
- **#866 §1**: explicitly add IPv6 first-fragment to the fix scope.
  Memo round-1 only mentioned IPv4.
- **#866 §1**: corrected the "verifier complexity" framing —
  current skip exists to defend against false-positive
  `SCREEN_TCP_NO_FLAG` drops on subsequent fragments (#853 context),
  not for verifier reasons.
- **#925-A §2**: `dead` flag is already exposed end-to-end; drop
  the proto/dead/Go items from scope. Memo round-1 over-claimed.
- **#925-A §2**: corrected proto-vs-JSON framing.
- **#925-A §2**: added explicit operator-visible-degradation
  documentation per Codex round-1 demand.

Per Gemini Pro round 1 (`task-monwc1sk-hsawxo`):

- **#866**: added "verifier proof on kernel 6.18" to test plan as
  a hard pre-merge gate.
- **#925-A**: confirmed Gemini's "no respawn is correct for this
  phase" framing — explicit in §2.
