# #2354 — QinQ / stacked-VLAN (802.1ad S-tag + C-tag) transit

## 1. Status

`v2 — CONVERGED, all three reviewers PLAN-DEFER`. Codex
(`task-mr0z5z4h-xlhx7i`), AGY (`adversarial-review-mr0z4yi0-l3rsnp`), and Claude
SMR (`claude-smr-plan-r1.md`) all returned **PLAN-DEFER** on v1. v2 folds every
round-1 tightening (see §12 review log) so a future `/engineer 2354` starts from
an accurate, hazard-pinned plan.

Research-only. No production code is touched. **Convergent disposition:
PLAN-DEFER (`plan-deferred-research`)** — the design below is converged and the
hazards are pinned, but this is a low-demand additive feature the issue author
explicitly warns must NOT be built speculatively, so it sits behind a manual
`/engineer 2354` approval gate awaiting concrete operator demand for stacked-VLAN
transit. PLAN-KILL is also defensible (no recorded demand).

Verified against `origin/master` @ `b3b8b6029` (`Merge pull request #3602`).
All file:line references below were re-confirmed on this SHA (the prior
campaign-8 plan was written against `0160fbfb9`; line numbers shifted, the
structure did not).

## 2. Issue framing

xpf parses QinQ config (`flexible-vlan-tagging`, `encapsulation
flexible-ethernet-services`, `inner-vlan-id`) into typed config but does **not
transit double-tagged frames**. A frame with an outer S-tag (802.1ad, TPID
0x88a8) and inner C-tag (802.1Q, TPID 0x8100) is silently handed to the kernel
slow path; it never reaches the AF_XDP userspace dataplane, so there is no
stateful policy, NAT, CoS, or fast-path forwarding on the inner flow.

The ask: real S-tag+C-tag transit end-to-end with stateful policy on the inner
flow, plus flexible push/pop/swap and a four-shape parse test matrix
(untagged / single / double / malformed).

## 3. Honest scope/value framing

This is a genuinely multi-layer feature, not a one-PR fix. The value is
**provider-edge / enterprise S-tag+C-tag trunking** — stacking many customer
C-VLANs under one provider S-tag, each a distinct logical interface / zone /
policy. That is a real Junos capability, but it is **niche**: there is no
current operator demand recorded on this issue, and the loss userspace cluster
(the smoke venue) has no QinQ topology. The win is *new capability*, not a
correctness fix — nothing is wrong today (double-tagged frames are safely
XDP_PASSed; single-tag transit is correct).

**If reviewers conclude the feature demand is too low to justify burning the
#1864 verifier-gate event and the four-PR churn now, PLAN-DEFER (or PLAN-KILL)
is an acceptable and expected verdict.** This plan converges the *design* so
that if/when demand materializes, `/engineer 2354` can start PR-A immediately
with the three architectural forks already decided.

## 4. What's already shipped / partially batched (the confirmed gap)

Every claim re-verified on `b3b8b6029`:

### 4.1 Config — parsed, ZERO production consumers (dead leaf)
- `Unit.InnerVlanID int` — `pkg/config/types_interfaces.go:48`.
- Parsed at `pkg/config/compiler_interfaces.go:299-303` (`unit.InnerVlanID = n`).
- Schema leaf — `pkg/config/schema_interfaces.go:92` (`inner-vlan-id`).
- `Interface.FlexibleVlanTagging bool` — `types_interfaces.go:19`, set at
  `compiler_interfaces.go:73-75`; schema `schema_interfaces.go:49`.
- `Interface.Encapsulation string` — `types_interfaces.go:20`; schema
  `schema_interfaces.go:50` (`encapsulation`, 1 arg).
- **`.InnerVlanID` is read ONLY in `pkg/config/parser_services_test.go`**
  (lines 675, 716, 726) — confirmed dormant: `grep -rn '\.InnerVlanID'
  --include='*.go'` returns the parse-site write + three test reads, nothing
  else. `FlexibleVlanTagging` / `Encapsulation` likewise have no dataplane
  consumer.

### 4.2 networkd — no stacked-VLAN device generation
- `pkg/networkd/networkd.go` writes `.netdev` files **only** for bond/LAG and
  bridge devices (`networkd.go:140,148,201-207`; `IsBond` / `IsBridge` gates).
- VLAN subinterfaces are single-tag `.network` only. There is no `Kind=vlan`
  nested S-tag/C-tag stack, no per-netdev `Protocol=802.1ad`.

### 4.3 Shim — single-tag parse → double-tagged frames XDP_PASS
- `userspace-xdp/src/lib.rs:1153 parse_l2()` strips exactly **one** tag: the
  VLAN branch is an `if` (line 1161), not a `while`. After it consumes one
  802.1Q/802.1ad tag, `eth_proto` becomes the *inner* TPID (0x8100 for a
  C-tag).
- Dispatch at `lib.rs:407-410`: `match eth_proto { ETH_P_IP => ..., ETH_P_IPV6
  => ..., _ => return Ok(pass_non_ip_l2_direct()) }`. A double-tagged frame's
  residual `eth_proto = 0x8100` hits the `_` arm → `pass_non_ip_l2_direct()`
  (`lib.rs:1011`) = **XDP_PASS to the kernel; never reaches the XSK.** Confirmed
  transit behavior.

### 4.4 Meta wire — version 4, spare bytes available
- `UserspaceDpMeta` — `lib.rs:122`, `sizeof == 96` (`const _: [(); 96]` assert
  at `lib.rs:153`), `USERSPACE_META_VERSION = 4` (`lib.rs:14`).
- **Spare capacity (verified offsets):** `meta_flags: u8` @ **39** (currently
  written 0, `lib.rs:690`), `reserved: u16` @ **42**, `reserved2: u32` @ **92**.
  `sizeof` stays 96 if these are repurposed in place. (The prior plan said
  `meta_flags` @ 41 — the true offset is 39; `reserved` @ 42 and `reserved2`
  @ 92 are correct.)
- Go mirror: `pkg/dataplane/userspace/maps_sync.go:41 userspaceMetadataVersion =
  4` (referenced at :153, :282, :355).

### 4.5 Five RX L2 parsers + canaries — all single-tag
- `userspace-dp/src/afxdp/frame/inspect.rs:26 frame_l3_offset` — single tag →
  `Some(18)`, else 14.
- `userspace-dp/src/afxdp/cos/ecn.rs:56 ethernet_l3` — **explicitly rejects
  QinQ**: nested VLAN inner ethertype → `None` ("QinQ or unknown inner — refuse
  to guess").
- `userspace-dp/src/afxdp/parser.rs:68 parse_eth_offsets` — single tag.
- `userspace-dp/src/nat64.rs:1997 frame_l3_offset` — single tag.
- `userspace-dp/src/afxdp/icmp.rs:287` + `icmp_ptb.rs:525 ingress_reply_l2` —
  single tag, returns `TxVlanTag`.
- Lockstep canaries: `afxdp/parser_tests.rs:344
  l2_offset_canary_all_parsers_agree` + `nat64_tests.rs:1199
  nat64_l2_offset_canary` (the #2150 agreement guard).

### 4.6 TX serializer — emits exactly one tag
- `userspace-dp/src/afxdp/frame/headers.rs:74 TxVlanTag{tpid,tci,present}`;
  `write_eth_header_tagged` (`headers.rs:162`) writes at most one tag at bytes
  [12:16]; `header_len()` is 14 or 18.
- **Egress TPID is config-derived, NOT ingress-preserved:** the forwarding path
  builds the egress tag via `TxVlanTag::from(vid)` (`headers.rs:127`), which
  *always* sets `tpid = TPID_8021Q` (0x8100). The S-tag TPID 0x88a8 must
  therefore come from the **egress unit's configured `encapsulation` /
  `Protocol`**, not from a preserved-from-ingress meta flag. This corrects a
  premise in the prior plan (which implied ingress preserves the outer TPID).

### 4.7 Live zone/VLAN binding is the JSON snapshot (not retired-eBPF)
- Single-tag units flow through
  `pkg/dataplane/userspace/interfaces.go` — VLAN child rows are built around
  line 275 (`VLANID: unit.VlanID`) with `Zone: zoneByInterface[unitName]`
  (line 267); `zoneByInterface` built at :168. `InterfaceSnapshot` struct at
  `protocol.go:236`, `VLANID` field at `:254`. TX-side VLAN wire fields
  `TXVLANID uint16` at `protocol.go:2614` (forwarding action) + `:2687`
  (session-sync action). **QinQ control-plane work lands here, NOT in the
  retired-eBPF `compiler_iface.go` / `SetZone` / `IfaceZoneKey`** (per
  `reference_dataplane_compiler_is_retired_ebpf`).

**Net:** the config grammar accepts QinQ stanzas and stores them; nothing
downstream consumes them; the shim hands double-tagged frames to the kernel. The
feature is parse-only dead config plus a hard XDP_PASS — exactly as the issue
states.

### 4a. Finding 1 (all three reviewers, r1) — the kernel slow-path policy-bypass window

The single most important phasing constraint, found independently by Codex
(check 5), AGY (open-question 1), and Claude SMR (Finding 1):

`enableForwarding` (`pkg/daemon/daemon_run.go:1812-1820`) sets
`net.ipv4.ip_forward=1` and `net.ipv6.conf.all.forwarding=1`. **Today** a
double-tagged frame XDP_PASSes to the kernel, the kernel has **no** matching
stacked VLAN device, so it is dropped — no transit, no bypass. **If a stacked
S/C netdev is created (fork c) BEFORE the AF_XDP fast path delivers double-tagged
frames to the XSK (PR-B),** the kernel now has a device to receive the XDP_PASSed
frame and `ip_forward=1` can forward the inner IP flow **with no AF_XDP firewall
policy, NAT, or session state.** That is a *new* firewall-bypassing forwarding
path introduced purely by ordering — the device-creation step must come no
earlier than XSK delivery. **Consequence: stacked-device creation lands in PR-B,
and PR-A is snapshot-field + additive-TX-wire ONLY (no device, no observable
forwarding change).** Once PR-B delivers to the XSK (XDP_REDIRECT), the kernel
netdev only ever sees host-originated traffic — the bypass closes, exactly as it
already is for single-tag VLAN devices (the shim delivers single-tag frames to
the XSK, so their kernel netdev never sees transit traffic).

## 5. Concrete design — the three forks DECIDED

### Fork (a) — wire: META_VERSION bump + inner-tag layout — DECIDED
**Bump `USERSPACE_META_VERSION` 4→5** (and Go `userspaceMetadataVersion` 4→5).
A bump is mandatory regardless of byte layout: the shim's *semantics* change (it
now delivers double-tagged frames and writes a second tag), and the version
field is the compat gate — an old helper MUST reject a v5 frame, not misread it
(`lib.rs:399` already gates on `ctrl.metadata_version != USERSPACE_META_VERSION`).

**Layout: reuse spare bytes, keep `sizeof == 96`.**
- Repurpose `reserved: u16` @ 42 → `ingress_inner_tci: u16` — the full inner
  C-tag TCI (PCP|DEI|VID). One field captures everything TX needs to re-emit or
  classify the inner tag; cleaner than the prior plan's split-VID-plus-stolen-
  PCP-byte, and leaves `reserved2` fully free for the next feature.
- Add two `meta_flags` bits (off 39): `STACKED_VLAN_PRESENT` (frame had two
  tags) and `OUTER_IS_8021AD` (outer TPID was 0x88a8 — needed for the
  *swap/preserve* rewrite mode where the egress S-tag TPID mirrors ingress; the
  *config-driven* transit mode derives it from the egress unit instead).
- `ingress_vlan_id` (@16) keeps the **outer (S) tag** VID for single-tag
  back-compat; `ingress_pcp` keeps the outer PCP.
- Result: `sizeof` unchanged → the `[(); 96]` size assert is untouched; add new
  offset asserts for `ingress_inner_tci`. Minimal verifier processed-insn delta
  and a bit-reproducible regen. Rationale: the #1864 verifier gate (1M-insn cap
  incident) is the single riskiest part of the feature — staying byte-for-byte
  close to today's struct is the conservative choice.

### Fork (b) — classification key — DECIDED (precedence pinned per r1)
**`(ifindex, outer, inner)`**, with `inner == 0` meaning "single-tag / outer-only
row". Junos models QinQ as a per-`(S-VLAN, C-VLAN)` logical interface; the
canonical SP use stacks many C-VLANs under one S-tag, each a distinct unit /
zone / policy. **Outer-only would collapse all C-VLANs under one S-tag into one
zone → wrong stateful + policy semantics.**

**Live key today is `FastMap<(i32, u16), i32>`** at
`userspace-dp/src/afxdp/types/forwarding.rs:102` — built `(bind_ifindex,
vlan_id)` at `forwarding_build/interfaces.rs:216-225`, probed `(ingress_ifindex,
ingress_vlan_id)` at `forwarding/mod.rs:583-591`. The Go snapshot carries only
`VLANID` (`protocol.go:254`); Rust only `vlan_id` (`protocol/snapshot.rs:39-62`).

**Lookup precedence MUST be pinned (Codex + AGY r1 — security-boundary fix):**
the lookup is NOT a plain wildcard. It is gated on the frame's tag count via
`STACKED_VLAN_PRESENT`:
- A **double-tagged** frame (`STACKED_VLAN_PRESENT` set) probes the EXACT
  `(ifindex, outer, inner)` row FIRST; it must NOT silently fall back to a
  single-tag `(ifindex, outer, 0)` row (that would leak a C-VLAN's traffic into
  the parent S-VLAN's zone). If no exact `(outer,inner)` row exists → miss
  (drop/no-zone), not parent-zone leak.
- A **single-tagged** frame (`STACKED_VLAN_PRESENT` clear) probes only the
  `(ifindex, outer, 0)` row — it must NEVER match a `(outer, inner!=0)` QinQ row.
- This makes `inner=0` a *tag-count-scoped* row, not a true wildcard. Existing
  single-tag rows stay bit-identical (they ARE `(ifindex, outer, 0)` with the
  single-tag frame gate). The key widens `(i32, u16)` → `(i32, u16, u16)` with
  the single-tag path always supplying `inner=0` and the lookup refusing
  cross-tag-count matches.

### Fork (c) — config / zone-binding + device creation — DECIDED (netlink, per r1)
**Config:** activate the already-parsed `Unit.InnerVlanID` — emit it
*additively* into `InterfaceSnapshot` (new `InnerVLANID int json:"inner_vlan_id,
omitempty"`), populated at `interfaces.go` next to the existing `VLANID:
unit.VlanID`. Bind the `(outer,inner)` logical interface to its zone via the
**existing** `zoneByInterface[unitName]` map — the unit name already encodes the
unit (e.g. `ge-0-0-2.100`). No new zone-binding mechanism. Do **not** route
through retired-eBPF `SetZone`/`IfaceZoneKey`.

**Device creation — NETLINK, not networkd (corrected from v1 per Codex/AGY r1).**
Single-tag VLAN sub-interface *devices* are created today via **netlink**, not
networkd: `ensureVLANSubInterface()` at
`pkg/dataplane/compiler_iface.go:103-131` does `netlink.LinkAdd(&netlink.Vlan{…
VlanId: vlanID})` (called from `compileZones` at `:352`; the live apply flow
still runs `compileZones` for device discovery/creation per the comment at
`pkg/daemon/daemon_apply.go:564`). That builder **does not set `VlanProtocol`**,
so it always creates an 802.1Q device. networkd writes `.netdev` files ONLY for
bond/bridge (`networkd.go:140-148`); it does NOT create VLAN devices. **The QinQ
stacked device must therefore extend the EXISTING netlink mechanism** — set
`VlanProtocol = unix.ETH_P_8021AD` on the S-tag `netlink.Vlan` and stack a C-tag
child `netlink.Vlan` (parent = S-device, default 802.1Q) — NOT introduce a
parallel networkd `.netdev` path. Two competing device-creation mechanisms would
race (AGY r1 open-question 3). Gate the stacked-device creation behind
`InnerVlanID != 0`.

**CRITICAL phasing constraint (all three reviewers r1):** the stacked device must
NOT be created until the AF_XDP fast path owns double-tagged delivery — see
Finding 1 in §4a below. The device-creation work lands in **PR-B**, not PR-A.

### 5.4 The resequenced 4-PR plan (each PR independently valuable; ONE verifier gate)

The prior campaign-8 critique stands and is adopted: a "PR-A = wire + extend all
5 parsers + canaries, no behavior change" foundation is **dead code AND a
premature gate burn** — it spends a META bump and a `make generate` /
verifier-gate event on a non-feature (inner fields written, nothing forwards).
Resequence so the META bump and XSK delivery land together, the Go control-plane
contract lands first (additive, no `make generate`), and TX stays in the helper
binary (no `make generate`).

**PR-A — control-plane contract (Go only; additive; NO meta bump; NO make generate; NO device creation)**
- Add `InnerVLANID` to `InterfaceSnapshot` (`protocol.go` ~:254); populate from
  `unit.InnerVlanID` in `interfaces.go` beside the existing `VLANID`.
- Zone binding for the `(outer,inner)` unit via existing
  `zoneByInterface[unitName]`.
- Add additive `TXInnerVLANID uint16` to the forwarding + session-sync actions
  (`protocol.go:2614` / `:2687`) — wire only; helper ignores until PR-C.
- **NO stacked-device creation here (Finding 1, §4a).** The netlink stacked
  device moves to PR-B so it never precedes XSK delivery.
- *Tests:* Go unit — snapshot carries `InnerVLANID`; `(S,C)` unit binds its zone;
  `userspaceMetadataVersion` stays 4; assert NO stacked device is created yet.
- *Independently valuable:* control plane models QinQ in the snapshot; helper
  still single-tags; double-tagged frames still XDP_PASS-and-drop (no stacked
  device exists to receive them) — zero regression, no bypass window.

**PR-B — shim two-tag RX + META bump + netlink stacked device (the ONLY make-generate / verifier-gate PR)**
- `userspace-xdp/src/lib.rs`: `parse_l2` unwinds a 2nd tag using **constant
  packet offsets** (Codex r1): outer ∈ {0x8100,0x88a8}; accept inner ∈
  {0x8100,0x88a8} (mirror the first-tag check — do NOT hardcode 0x8100, SMR r1
  Finding 2, or document the narrowing) → second `VlanHdr`; `l3_offset = 22`;
  fail-closed `read_bytes(...)?` on truncation. Dispatch DELIVERS double-tagged
  IP frames to the XSK (no longer XDP_PASS); fill `ingress_inner_tci` (@42) +
  `STACKED_VLAN_PRESENT`/`OUTER_IS_8021AD` meta_flags. **Single-tag frames MUST
  keep writing `reserved=0` and `STACKED_VLAN_PRESENT` clear** (lib.rs:690-700).
  Bump `USERSPACE_META_VERSION` 4→5.
- Go mirror: `userspaceMetadataVersion` 4→5 + struct mirror + size/offset asserts.
- Helper RX parsers unwind two tags: `frame/inspect.rs frame_l3_offset`,
  `cos/ecn.rs ethernet_l3`, `parser.rs parse_eth_offsets`, `nat64.rs
  frame_l3_offset`, `icmp.rs`+`icmp_ptb.rs ingress_reply_l2`; extend BOTH
  l2-offset canaries (`parser_tests.rs:344`, `nat64_tests.rs:1199`) with the
  double-tag shape (l3 = 22).
- Widen the forwarding key `FastMap<(i32,u16),i32>` → `(i32,u16,u16)`
  (`types/forwarding.rs:102`, builder `forwarding_build/interfaces.rs:216`,
  lookup `forwarding/mod.rs:583`); build `(ifindex,outer,inner)` rows from PR-A
  fields; pin the **tag-count-scoped lookup precedence** (fork b): exact
  `(outer,inner)` for stacked frames, `(outer,0)` for single-tag, NO
  cross-tag-count fallback (the security-boundary fix).
- **netlink stacked device** (fork c): extend `ensureVLANSubInterface`
  (`compiler_iface.go:103`) to create the S-tag device with
  `VlanProtocol=ETH_P_8021AD` + stack the C-tag child, gated on `InnerVlanID !=
  0`. Lands HERE (not PR-A) so it never precedes XSK delivery (§4a).
- **`make generate` + `cmd/shimverify` verifier gate MUST pass**; commit the
  regenerated `pkg/dataplane/userspace_xdp_bpfel.o`; require a clean
  `git diff --exit-code` on a pinned re-run (bit-reproducible, #1864); cluster
  smoke before merge.
- *Tests:* shim parity — a double-tagged frame reaches the XSK and classifies to
  the `(S,C)` unit/zone; the precedence test — a single-tag frame on a port that
  has a QinQ unit does NOT leak into the QinQ zone, and a double-tag frame does
  NOT fall back to the parent single-tag zone. *Independently valuable:* RX +
  local-deliver to a QinQ unit works (transit completes in PR-C).

**PR-C — TX two-tag serialize + transit (userspace-dp only; NO make generate)**
- `frame/headers.rs`: extend the TX path to a two-tag stack (`TxVlanStack{outer:
  TxVlanTag, inner: TxVlanTag}` or an `Option<TxVlanTag>` inner on the existing
  writer); `write_eth_header_*_tagged` emits S then C. **Do NOT route the S-tag
  through `TxVlanTag::from(vid)`** — it forces `TPID_8021Q` and would silently
  rewrite the S-tag to 0x8100 (Codex r1 check 4 + §4.6). The S-tag TPID
  (`TPID_8021AD`) comes from the egress unit's configured encapsulation; C-tag
  TPID 0x8100. Fix all `header_len`/eth_len sites (18→22 when stacked).
- **Extend the in-place L2 rewrite** (AGY r1 finding 4): `RewriteEthParams` /
  `InPlaceL2Rewrite` / `rewrite_prepare_eth_from_parts` (`frame/mod.rs:372,397`)
  assume a max 18-byte L2 header; a 22-byte double-tag frame would shift the
  payload upstream and corrupt the IP header. Extend the rewrite to a 22-byte
  target and verify UMEM headroom (256-byte headroom is ample; the
  `in_place_vlan_push_no_headroom_packets` memmove path, `umem/mod.rs`, must
  handle the larger shift).
- Transit preserving/rewriting both tags; thread the stack through forwarding,
  NAT, CoS/ECN (`ecn.rs ethernet_l3` flips QinQ-reject→accept — a deliberate
  behavior change; today's callers `maybe_mark_ecn_ce` `ecn.rs:179-189` map
  `None=>false`, so the flip only ADDS ECN marking to previously-skipped QinQ
  frames — pin it with a test), MSS-clamp, ICMP-reply (extend `ingress_reply_l2`
  to two tags), GRE, NAT64.
- Consume `TXInnerVLANID` (from PR-A) in the forwarding action.
- *Tests:* Rust unit — two-tag byte layout (S then C at [12:20]); the in-place
  rewrite on a 22-byte header does NOT corrupt the IP header; ecn marks a QinQ
  frame; iperf3 transit through a QinQ unit on the loss cluster (both dirs,
  v4+v6, sustained). Completes transit.

**PR-D — push/pop/swap + acceptance + docs**
- S-tag push/pop + C-tag swap (flexible-vlan-tagging rewrite ops), if in scope.
- Four-shape matrix (untagged / single / double / double+rewrite) end-to-end
  with a stateful policy on the **inner** flow.
- Docs: flip the QinQ tracker entry in `docs/feature-gaps.md:681` Partial→Done;
  operator doc; update `pkg/dataplane/README.md` + config-schema docs.

**make-generate gate summary:** only PR-B regenerates the shim `.o`; PR-A/C/D do
not touch `userspace-xdp/` → no regen. PR-B follows #1864 discipline (toolchain
pin, verify-then-install, bit-reproducible, cluster smoke).

## 6. Public API preservation

- `InterfaceSnapshot`, forwarding/session-sync action structs: **additive only**
  (`InnerVLANID`, `TXInnerVLANID` with `omitempty`). Existing single-tag JSON is
  bit-identical (new fields omit when 0). An old helper reading a new snapshot
  ignores unknown fields; a new helper reading an old snapshot sees `inner=0`
  (single-tag path).
- `parse_l2` signature unchanged for callers (still returns the existing tuple;
  inner fields are written into meta, not returned to the dispatch tuple — or,
  if the tuple grows, all four call sites at `lib.rs:403,985` updated together).
- `TxVlanTag` retained for single-tag callers; the two-tag path is additive
  (`emits()`/`header_len()` semantics preserved for `inner = NONE`).
- `USERSPACE_META_VERSION` bump is the intended compat break (old helper rejects
  v5) — that is the contract, not a regression.

## 7. Hidden invariants the change must preserve

1. **Single-tag bit-identity.** `inner = 0` / `STACKED_VLAN_PRESENT` clear must
   produce byte-identical meta, classification, and TX framing to today. The
   `(ifindex, outer, 0)` row must equal today's `(ifindex, vlan)` row.
1a. **Tag-count-scoped lookup (Finding, fork b).** The classifier MUST NOT do a
   plain `inner=0` wildcard fallback: a double-tagged frame matches ONLY an exact
   `(outer,inner)` row, a single-tagged frame matches ONLY an `(outer,0)` row.
   Cross-tag-count fallback would leak a C-VLAN's traffic into the parent
   S-VLAN's zone (a security-boundary violation). Pin with the precedence test.
1b. **No early kernel-bypass window (Finding 1, §4a).** The networkd/netlink
   stacked device MUST NOT be created before the AF_XDP fast path delivers
   double-tagged frames to the XSK (`ip_forward=1` would otherwise forward the
   inner flow unfiltered). Device creation lands no earlier than PR-B.
2. **Five-parser lockstep (#2150).** All five RX L2 parsers MUST agree on the
   double-tag offset (l3 = 22); both canaries extended or the agreement guard
   is meaningless. cos/ecn's *deliberate* QinQ rejection (§4.5) flips to
   acceptance — that is a behavior change PR-C must test, not an accident.
2a. **TX in-place rewrite length (AGY r1).** The in-place L2 rewrite
   (`RewriteEthParams`/`InPlaceL2Rewrite`, `frame/mod.rs`) must be extended from
   a max 18-byte to a 22-byte L2 header; a 22-byte frame under the 18-byte
   assumption shifts the payload and corrupts the IP header.
3. **Fail-closed on truncation.** A frame claiming two tags but too short MUST
   `read_bytes(...)?` → `None` → drop/degraded, never a wild pointer or
   XDP_PASS that re-enters the kernel with a half-parsed frame.
4. **Verifier gate (#1864).** PR-B must keep insn count under the 1M cap, pass
   `cmd/shimverify`, and produce a bit-reproducible `.o`. Reusing spare bytes
   (no struct growth) is chosen specifically to minimize the insn delta.
5. **Stack-limit / var_off in the shim** (CLAUDE.md BPF rules). The second tag
   read uses a constant offset from the validated `l3_offset` (now 18→22), not a
   wide var_off pointer; narrow as needed.
6. **Egress TPID source.** S-tag TPID is config-derived (egress unit), per
   §4.6 — do not assume ingress-preserved. Swap/preserve mode (`OUTER_IS_8021AD`)
   is the only path that mirrors ingress.
7. **HA session-sync portability.** The `(outer,inner)` key and `TXInnerVLANID`
   must serialize identically across nodes; session-sync wire is the additive
   `protocol.go:2687` action — no node-local pointers.
8. **No new control-socket high-frequency traffic** (CLAUDE.md) — this is a
   snapshot/forwarding change, not a poll change.

## 8. Risk assessment (4-class)

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | **MED-HIGH** | Five-parser + dispatch + TX touch the hot L2 path used by 100% of frames. Two security-relevant behavior changes: the tag-count-scoped lookup (no zone leak, inv 1a) and the kernel-bypass-window ordering (inv 1b, Finding 1). Mitigated by `inner=0` bit-identity + extended canaries + the precedence test + fail-on-revert single-tag tests. cos/ecn QinQ-reject→accept is an intentional flip needing its own test. |
| Lifetime / borrow / verifier | **HIGH** | The shim `.o` regen (PR-B) is the gated, irreversible-per-merge risk: #1864 1M-insn cap, bit-reproducible `.o`, constant-offset (not var_off) 2nd-tag read. The META bump + delivery is isolated to ONE PR; the layout reuses spare bytes (no struct growth) to minimize the insn delta. Codex r1: verifier safety is unprovable until `cmd/shimverify` runs — this is the residual unknown. |
| Performance regression | **LOW-MED** | One extra 4-byte bounds-checked read + branch per double-tagged frame; single-tag frames take an early-out (inner ethertype not a TPID) → near-zero delta. Confirm with a single-tag iperf3 A/B on the loss cluster (no throughput regression). |
| Architectural mismatch | **LOW** | Classification/zone binding lands in the live JSON-snapshot path (`interfaces.go`/`protocol.go` + helper `types/forwarding.rs`), the canonical post-#1476 model. Device creation reuses the EXISTING netlink VLAN mechanism (`ensureVLANSubInterface`, the device-creation — not eBPF-enforcement — part of `compiler_iface.go`), extended with `VlanProtocol=802.1ad` + stacking, rather than a parallel networkd path. The `(ifindex,outer,inner)` key matches Junos's per-`(S,C)` logical-interface model. No DPDK/eBPF dead-end. |

**Explicit:** this is a FEATURE, not a bug. **PLAN-DEFER is the expected
honest outcome** given (1) zero recorded operator demand, (2) a four-PR build
that burns the highest-risk #1864 verifier gate, (3) the issue author's explicit
"do NOT do speculatively". **PLAN-KILL is also defensible** if reviewers judge
stacked-VLAN transit out of xpf's product scope. The design is converged either
way so a future `/engineer 2354` does not re-litigate the forks.

## 9. Test plan (RED-on-revert)

- **PR-A (Go):** `go test ./pkg/dataplane/userspace/ ./pkg/config/`
  — snapshot carries `InnerVLANID`; `(S,C)` unit binds its zone; assert
  `userspaceMetadataVersion == 4` (RED if bumped prematurely); assert NO stacked
  device is created in PR-A (RED if device creation leaks back into PR-A —
  Finding 1 ordering guard).
- **PR-B (shim + canaries):** extend `parser_tests.rs:344
  l2_offset_canary_all_parsers_agree` + `nat64_tests.rs:1199
  nat64_l2_offset_canary` with a double-tagged shape — RED-on-revert if any of
  the five parsers is not advanced to l3=22. A truncated-double-tag frame →
  fail-closed (asserts drop/degraded, not XDP_PASS). `make generate` + `cmd/
  shimverify` MUST pass; `git diff --exit-code` clean on pinned re-run (#1864).
  Shim parity test: a constructed double-tagged frame reaches the XSK and
  classifies to the `(S,C)` zone (RED if dispatch still `_`-arms to XDP_PASS).
- **PR-C (TX + transit):** Rust unit — two-tag byte layout at [12:20] (S then C),
  18→22 eth_len; cos/ecn now marks ECN on a QinQ frame (RED if it still returns
  `None`). **iperf3 through a QinQ unit on the loss cluster**, both directions,
  v4+v6, sustained ≥15s, with `show security flow statistics` rx/tx advancing
  (per `feedback_verify_forwarding_with_sustained_iperf`) — and a single-tag A/B
  to prove no throughput regression.
- **PR-D (acceptance):** four-shape matrix (untagged / single / double /
  double+rewrite) end-to-end with a stateful policy matching on the **inner**
  flow; push/pop/swap unit + integration tests; `make test` (30 Go packages) +
  full `cargo test` (900+ tests) + 5/5 named-test flake check green.
- **Whole feature:** any HA-touching change (session-sync `TXInnerVLANID`) must
  pass `make test-failover` before that PR merges (CLAUDE.md).

## 10. Out of scope (explicitly)

- **Triple+ VLAN stacks** (3+ tags) — 802.1ad is two tags; deeper stacks are
  not a Junos QinQ model and are out of scope.
- **Per-flow S-tag *translation* tables** beyond simple push/pop/swap (PR-D
  covers basic rewrite; programmable S↔C mapping is a separate feature).
- **Kernel-slow-path QinQ** beyond the netlink stacked device (the device exists
  for host consistency; the fast path is AF_XDP strip/re-add). Note the device
  is created no earlier than PR-B (Finding 1) to avoid an unfiltered kernel
  forwarding window.
- **PR-D push/pop/swap may itself be deferred** to a PR-D-follow-up if PR-A→C
  (transit only) is judged sufficient for the first demand.

## 11. Open questions (r1 resolved many; these remain for the eventual /engineer)

**RESOLVED by r1 review** (folded into the plan, see §12):
- Classification precedence — RESOLVED: tag-count-scoped, no `inner=0` wildcard
  fallback (inv 1a, fork b).
- PR-A dead-code / bypass — RESOLVED: device creation moves to PR-B; PR-A is
  snapshot+wire only (§4a, Finding 1).
- Device mechanism — RESOLVED: netlink (`ensureVLANSubInterface` +
  `VlanProtocol=802.1ad`), not networkd (fork c). The networkd-stacking question
  is moot.
- Egress S-tag TPID — RESOLVED-confirmed: config-derived; PR-C must not use
  `TxVlanTag::from` for the S-tag (§4.6).
- TX in-place rewrite 18→22 — RESOLVED: extend `InPlaceL2Rewrite` (inv 2a).

**STILL OPEN for the /engineer phase (none block the DEFER disposition):**
1. **Demand / scope.** Is stacked-VLAN transit in xpf's product scope at all? No
   operator demand is recorded — this is why the disposition is PLAN-DEFER, not
   PLAN-READY. If product judges it out of scope, escalate to PLAN-KILL.
2. **Verifier gate (Codex r1 residual).** Will the second-tag read + branch + two
   meta writes stay under the #1864 1M-insn cap and reproduce bit-identically?
   **Unprovable until `cmd/shimverify` actually runs in PR-B** — the single
   largest implementation risk.
3. **Inner-tag TPID set.** Accept inner ∈ {0x8100, 0x88a8} (robust) or restrict
   to 0x8100-C and document the narrowing? (SMR r1 Finding 2.)
4. **Junos S-tag TPID semantics.** For the *transit* case, does Junos preserve
   the ingress S-tag TPID end-to-end, or always emit the egress unit's configured
   TPID? Affects whether `OUTER_IS_8021AD` drives every egress or only swap mode.
5. **Inner DEI / PCP.** The full inner TCI is preserved in `ingress_inner_tci`;
   confirm no consumer needs the inner DEI broken out separately.

## 12. Review log

**Round 1 (plan v1 `903f2d2bb`)** — Codex `task-mr0z5z4h-xlhx7i`, AGY
`adversarial-review-mr0z4yi0-l3rsnp`, Claude SMR `claude-smr-plan-r1.md`. **All
three returned PLAN-DEFER.** Findings folded into v2:
- **Finding 1 (all 3): kernel slow-path policy-bypass window.** Creating the
  stacked device (fork c) before PR-B's XSK delivery, with `ip_forward=1`
  (daemon_run.go:1817), would forward double-tagged frames unfiltered through the
  kernel. → device creation moved to PR-B; PR-A is snapshot+wire only (§4a, inv 1b).
- **Fork (b) precedence (Codex + AGY): zone-leak.** A plain `inner=0` wildcard
  lets a single-tag frame match a QinQ row (or a double-tag frame fall back to
  the parent zone). → tag-count-scoped lookup, no cross-count fallback (fork b,
  inv 1a). Live key is `FastMap<(i32,u16),i32>` `types/forwarding.rs:102`.
- **Fork (c) mechanism (AGY q3 + verified): netlink not networkd.** Single-tag
  VLAN devices are netlink-created (`ensureVLANSubInterface`,
  `compiler_iface.go:103`, no `VlanProtocol` → 802.1Q). → extend that mechanism
  with `VlanProtocol=802.1ad` + stacking, not a parallel networkd `.netdev` path.
- **S-tag egress TPID (Codex + SMR): `TxVlanTag::from` forces 0x8100.** → PR-C
  must build the S-tag with `TPID_8021AD` from egress-unit config, not
  `TxVlanTag::from` (§4.6, PR-C).
- **TX in-place rewrite (AGY): 18-byte max corrupts a 22-byte frame.** → extend
  `InPlaceL2Rewrite`/`rewrite_prepare_eth_from_parts` to 22 bytes + headroom
  check (inv 2a, PR-C).
- **Verifier offsets (Codex + SMR): use constant packet offsets, keep single-tag
  `reserved=0`.** → PR-B spec + inv 5.
- **Inner-tag TPID (SMR): accept inner ∈ {0x8100,0x88a8} or document.** → PR-B
  spec + open question 3.

Disposition unchanged across the round: **PLAN-DEFER**. The v2 revisions make the
deferred plan accurate and hazard-pinned; they do not change the recommendation
not to build now without demand.
