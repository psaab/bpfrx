# Claude SMR — hostile plan review r1 — #2354 QinQ transit

Reviewing `docs/research/2354-qinq/plan.md` @ commit `903f2d2bb` against
`origin/master` `b3b8b6029`. Hostile posture: I tried to break the design, not
confirm it.

## Confirmed-accurate claims (walked the source)

- Shim single-tag parse → XDP_PASS of double-tagged frames: `parse_l2` at
  `userspace-xdp/src/lib.rs:1153` is an `if` (1161), not a `while`; dispatch `_`
  arm at `lib.rs:410` → `pass_non_ip_l2_direct()`. **Verified.**
- `UserspaceDpMeta` `sizeof==96` (`lib.rs:153`), spare `reserved:u16`@42,
  `reserved2:u32`@92, `meta_flags:u8`@39 (written 0 at `lib.rs:690`).
  **Verified** — the prior plan's "@41" for meta_flags was wrong; this plan
  corrected it to @39. Good.
- `Unit.InnerVlanID` parsed at `compiler_interfaces.go:303`, read ONLY in
  `parser_services_test.go` — **zero production consumers, verified.**
- `cos/ecn.rs:56 ethernet_l3` explicitly rejects QinQ (`None`). **Verified.**
- Egress TPID is config-derived, never ingress-preserved: forwarding sets
  `tx_vlan_id` (a bare VID) at `forwarding/mod.rs` (e.g. :882, :1932) and the
  serializer builds `TxVlanTag::from(vid)` → always `TPID_8021Q` (`headers.rs:130`).
  `TPID_8021AD` (`headers.rs:56`) is **never** used on the default egress path.
  **Verified — the plan's §4.6 correction of the prior plan is right.**

The confirmed-gap section (§4) is accurate. No fabricated file:line.

## Finding 1 (MAJOR — phasing introduces a policy-bypass window) — must fix

PR-A as written creates the **networkd stacked netdev pair** (`Kind=vlan` outer
802.1ad → inner C-VLAN) while the shim **still XDP_PASSes** double-tagged frames
(PR-B is what changes delivery). Combined with `enableForwarding`
(`pkg/daemon/daemon_run.go:1812-1820`, which sets `net.ipv4.ip_forward=1` and
`net.ipv6.conf.all.forwarding=1`), this is a NEW unfiltered forwarding path:

- **Today** a double-tagged frame XDP_PASSes to the kernel, the kernel has **no**
  matching stacked VLAN device, so it is dropped — no transit, no bypass.
- **After PR-A alone** the kernel now has a stacked S/C netdev to receive that
  XDP_PASSed frame, `ip_forward=1` is on, and FRR/kernel routing can forward the
  inner IP flow **without any AF_XDP firewall policy, NAT, or session state.**

So PR-A is not just "models QinQ, helper still single-tags safely" — it can
**silently enable a firewall-bypassing kernel slow path for QinQ traffic.** That
is a security regression, and it contradicts the plan's own §7 invariant 1
("single-tag bit-identity … zero regression") because double-tag behavior
changes from drop to unfiltered-forward.

**Required revision:** move the networkd stacked-netdev generation to **PR-B**
(land it together with XSK delivery), OR have PR-A create the netdev in a
non-forwarding posture (`ActivationPolicy=always-down` until the fast path owns
delivery). Once PR-B delivers double-tagged frames to the XSK (XDP_REDIRECT), the
kernel netdev only ever sees host-originated traffic — the bypass closes. This
also makes PR-A genuinely additive-safe (snapshot field + additive TX wire only;
no observable forwarding change). The single-tag case is unaffected because the
shim already delivers single-tag frames to the XSK, so the single-tag kernel
netdev never sees transit traffic today.

## Finding 2 (MINOR — inner-tag TPID narrowing) — fix in PR-B spec

PR-B's description hardcodes "inner 0x8100 → second VlanHdr". Real deployments
exist where the inner C-tag uses 0x88a8, or both tags use 0x8100
("802.1Q-in-802.1Q"), or both use 0x88a8. The first-tag check at `lib.rs:1161`
already accepts **either** `ETH_P_8021Q || ETH_P_8021AD`; the second-tag check
should mirror it (accept inner ∈ {0x8100, 0x88a8}) rather than hardcode 0x8100,
or document explicitly that only 0x88a8-S / 0x8100-C stacks are supported and the
others fall through to today's XDP_PASS. Pick one and pin it; silently parsing
only 0x8100-inner is an undocumented narrowing.

## Finding 3 (MINOR — strict-superset edge) — add a test, not a redesign

The `(ifindex, outer, inner)` `inner=0`=wildcard superset (fork b) is sound, but
there is one edge to pin with a test: a port that has BOTH a QinQ unit `(S=100,
C=200)` and a plain single-tag unit `VLAN=100`. A single-tagged VID-100 frame
must match `(ifindex,100,0)` (the single-tag unit), and a double-tagged
`(100,200)` must match the QinQ unit — distinct rows, no collision. Verify the
lookup never matches a `(outer, inner!=0)` row for a single-tagged frame (where
`STACKED_VLAN_PRESENT` is clear). This is a test obligation, not a flaw; add it
to PR-B's RED-on-revert set.

## Things I tried to break and could not

- **`sizeof==96` preservation:** repurposing `reserved:u16`@42 in place keeps the
  size assert valid; the verifier-insn-minimization rationale is sound — this is
  the right conservative call for the #1864 gate.
- **HA session-sync portability:** additive `TXInnerVLANID` on the `protocol.go`
  actions serializes identically; no node-local state. OK.
- **Architectural placement:** landing in `interfaces.go`/`protocol.go` (live
  JSON snapshot), not retired-eBPF `compiler_iface.go`, is correct per
  `reference_dataplane_compiler_is_retired_ebpf`.

## Disposition

The design is fundamentally sound and the gap is accurately confirmed, but
Finding 1 is a real correctness/security defect in the phasing that must be
fixed before this is PLAN-READY. After the networkd-phasing fix + the two MINOR
pins, the design converges.

This is a **low-demand additive FEATURE** with zero recorded operator demand and
an explicit author warning against speculative building, gated behind the
highest-risk #1864 verifier event. The honest terminal disposition is
**PLAN-DEFER** (`plan-deferred-research`): converge the design, fix Finding 1,
then STOP behind a manual `/engineer 2354` approval gate until concrete
stacked-VLAN demand exists. PLAN-KILL is also defensible.

**Verdict r1: PLAN-NEEDS-MINOR** (Finding 1 reclassified MINOR-phasing because it
is a reorder, not a redesign; Findings 2-3 are pins). Fix the three and the
disposition is **PLAN-DEFER**.
