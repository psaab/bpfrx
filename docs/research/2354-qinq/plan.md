# #2354 — QinQ / stacked-VLAN (802.1ad S-tag + C-tag) transit

## 1. Status

`DRAFT v1 — pending adversarial plan review` (Codex + AGY + Claude SMR).

Research-only. No production code is touched. The convergent disposition is
expected to be **PLAN-DEFER (`plan-deferred-research`)**: the design below is
converged and ready to `/engineer`, but this is a low-demand additive feature
the issue author explicitly warns must NOT be built speculatively, so it sits
behind a manual `/engineer 2354` approval gate awaiting concrete operator demand
for stacked-VLAN transit.

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

### Fork (b) — classification key — DECIDED
**`(ifindex, outer, inner)`**, with `inner == 0` meaning "wildcard /
outer-only / single-tag" (a strict superset — existing single-tag rows stay
bit-identical). Junos models QinQ as a per-`(S-VLAN, C-VLAN)` logical
interface; the canonical SP use stacks many C-VLANs under one S-tag, each a
distinct unit / zone / policy. **Outer-only would collapse all C-VLANs under
one S-tag into one zone → wrong stateful + policy semantics.** The live snapshot
zone table is already keyed `(ifindex, vlan)`; QinQ extends it to `(ifindex,
outer, inner)` with `inner=0` preserving today's behavior bit-for-bit.

### Fork (c) — config / zone-binding + networkd — DECIDED
**Config:** activate the already-parsed `Unit.InnerVlanID` — emit it
*additively* into `InterfaceSnapshot` (new `InnerVLANID int json:"inner_vlan_id,
omitempty"`), populated at `interfaces.go` next to the existing `VLANID:
unit.VlanID`. Bind the `(outer,inner)` logical interface to its zone via the
**existing** `zoneByInterface[unitName]` map — the unit name already encodes the
unit (e.g. `ge-0-0-2.100`). No new zone-binding mechanism. Do **not** route
through retired-eBPF `SetZone`/`IfaceZoneKey`.

**networkd:** generate a stacked netdev pair **only when `InnerVlanID != 0`**:
outer S-VLAN netdev (`Kind=vlan`, `Id=S`, `Protocol=802.1ad`, parent=physical) →
inner C-VLAN netdev (`Kind=vlan`, `Id=C`, parent=S-netdev). systemd-networkd
supports vlan-on-vlan stacking + per-netdev `Protocol=`. The AF_XDP
strip/re-add fast path does **not** depend on these netdevs (they exist only for
kernel-slow-path / host consistency), so gate generation behind `InnerVlanID !=
0` — never speculative, no change to single-tag interfaces.

### 5.4 The resequenced 4-PR plan (each PR independently valuable; ONE verifier gate)

The prior campaign-8 critique stands and is adopted: a "PR-A = wire + extend all
5 parsers + canaries, no behavior change" foundation is **dead code AND a
premature gate burn** — it spends a META bump and a `make generate` /
verifier-gate event on a non-feature (inner fields written, nothing forwards).
Resequence so the META bump and XSK delivery land together, the Go control-plane
contract lands first (additive, no `make generate`), and TX stays in the helper
binary (no `make generate`).

**PR-A — control-plane contract (Go only; additive; NO meta bump; NO make generate)**
- Add `InnerVLANID` to `InterfaceSnapshot` (`protocol.go` ~:254); populate from
  `unit.InnerVlanID` in `interfaces.go` beside the existing `VLANID`.
- Zone binding for the `(outer,inner)` unit via existing
  `zoneByInterface[unitName]`.
- networkd stacked netdev pair, gated on `InnerVlanID != 0` (outer
  `Protocol=802.1ad` → inner C-VLAN).
- Add additive `TXInnerVLANID uint16` to the forwarding + session-sync actions
  (`protocol.go:2614` / `:2687`) — wire only; helper ignores until PR-C.
- *Tests:* Go unit — snapshot carries `InnerVLANID`; networkd writes the stacked
  pair; `(S,C)` unit binds its zone; `userspaceMetadataVersion` stays 4.
- *Independently valuable:* control plane fully models QinQ; helper still
  single-tags; double-tagged frames still safely XDP_PASS — zero regression.

**PR-B — shim two-tag RX + META bump (the ONLY make-generate / verifier-gate PR)**
- `userspace-xdp/src/lib.rs`: `parse_l2` unwinds a 2nd tag (outer ∈
  {0x8100,0x88a8}, inner 0x8100 → second `VlanHdr`; `l3_offset = 22`;
  fail-closed `read_bytes(...)?` on truncation); dispatch DELIVERS double-tagged
  IP frames to the XSK (no longer XDP_PASS); fill `ingress_inner_tci` +
  `STACKED_VLAN_PRESENT`/`OUTER_IS_8021AD`; bump `USERSPACE_META_VERSION` 4→5.
- Go mirror: `userspaceMetadataVersion` 4→5 + struct mirror + size/offset asserts.
- Helper RX parsers unwind two tags: `frame/inspect.rs frame_l3_offset`,
  `cos/ecn.rs ethernet_l3`, `parser.rs parse_eth_offsets`, `nat64.rs
  frame_l3_offset`, `icmp.rs`+`icmp_ptb.rs ingress_reply_l2`; extend BOTH
  l2-offset canaries (`parser_tests.rs:344`, `nat64_tests.rs:1199`) with the
  double-tag shape (l3 = 22).
- Helper builds the `(ifindex,outer,inner)` zone table from PR-A fields.
- **`make generate` + `cmd/shimverify` verifier gate MUST pass**; commit the
  regenerated `pkg/dataplane/userspace_xdp_bpfel.o`; require a clean
  `git diff --exit-code` on a pinned re-run (bit-reproducible, #1864); cluster
  smoke before merge.
- *Tests:* shim parity — a double-tagged frame reaches the XSK and classifies to
  the `(S,C)` unit/zone. *Independently valuable:* RX + local-deliver to a QinQ
  unit works (transit completes in PR-C).

**PR-C — TX two-tag serialize + transit (userspace-dp only; NO make generate)**
- `frame/headers.rs`: extend the TX path to a two-tag stack (`TxVlanStack{outer:
  TxVlanTag, inner: TxVlanTag}` or an `Option<TxVlanTag>` inner on the existing
  writer); `write_eth_header_*_tagged` emits S then C; fix all
  `header_len`/eth_len sites (18→22 when stacked). S-tag TPID from egress-unit
  config (per §4.6); C-tag TPID 0x8100.
- Transit preserving/rewriting both tags; thread the stack through forwarding,
  NAT, CoS/ECN (`ecn.rs` must now ACCEPT the QinQ shape it rejects today),
  MSS-clamp, ICMP-reply (extend `ingress_reply_l2` to two tags), GRE, NAT64.
- Consume `TXInnerVLANID` (from PR-A) in the forwarding action.
- *Tests:* Rust unit — two-tag byte layout; iperf3 transit through a QinQ unit on
  the loss cluster (both dirs, v4+v6). Completes transit.

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
2. **Five-parser lockstep (#2150).** All five RX L2 parsers MUST agree on the
   double-tag offset (l3 = 22); both canaries extended or the agreement guard
   is meaningless. cos/ecn's *deliberate* QinQ rejection (§4.5) flips to
   acceptance — that is a behavior change PR-C must test, not an accident.
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
| Behavioral regression | **MED** | Five-parser + dispatch + TX touch the hot L2 path used by 100% of frames. Mitigated by `inner=0` strict-superset bit-identity + extended canaries + fail-on-revert single-tag tests. cos/ecn QinQ-rejection→acceptance is an intentional flip needing its own test. |
| Lifetime / borrow / verifier | **HIGH** | The shim `.o` regen (PR-B) is the gated, irreversible-per-merge risk: #1864 1M-insn cap, bit-reproducible `.o`, var_off narrowing on the 2nd-tag read. This is why the META bump + delivery is isolated to ONE PR and the layout reuses spare bytes (no struct growth). |
| Performance regression | **LOW-MED** | One extra 4-byte bounds-checked read + branch per double-tagged frame; single-tag frames take an early-out (outer inner-ethertype not a TPID) → near-zero delta. Must be confirmed by a single-tag iperf3 A/B on the loss cluster (no throughput regression). |
| Architectural mismatch | **LOW** | The design lands in the live JSON-snapshot path (`interfaces.go`/`protocol.go`), the canonical post-#1476 forwarding model — NOT retired-eBPF `compiler_iface.go`. The `(ifindex,outer,inner)` key matches Junos's per-`(S,C)` logical-interface model. No DPDK/eBPF dead-end. |

**Explicit:** this is a FEATURE, not a bug. **PLAN-DEFER is the expected
honest outcome** given (1) zero recorded operator demand, (2) a four-PR build
that burns the highest-risk #1864 verifier gate, (3) the issue author's explicit
"do NOT do speculatively". **PLAN-KILL is also defensible** if reviewers judge
stacked-VLAN transit out of xpf's product scope. The design is converged either
way so a future `/engineer 2354` does not re-litigate the forks.

## 9. Test plan (RED-on-revert)

- **PR-A (Go):** `go test ./pkg/dataplane/userspace/ ./pkg/networkd/ ./pkg/config/`
  — snapshot carries `InnerVLANID`; networkd emits the stacked netdev pair ONLY
  when `InnerVlanID != 0` (RED if the gate is removed → speculative stacked
  device on single-tag ifaces); `(S,C)` unit binds its zone; assert
  `userspaceMetadataVersion == 4` (RED if bumped prematurely).
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
- **Kernel-slow-path QinQ** beyond the networkd stacked netdev pair (the netdevs
  exist for host consistency; the fast path is AF_XDP strip/re-add).
- **PR-D push/pop/swap may itself be deferred** to a PR-D-follow-up if PR-A→C
  (transit only) is judged sufficient for the first demand.

## 11. Open questions for adversarial review (each invitable to PLAN-DEFER/KILL)

1. **Demand / scope.** Is stacked-VLAN transit in xpf's product scope at all, or
   is this PLAN-KILL? No operator demand is recorded. Is converging the design
   now (vs deferring even the design) worth the reviewer cycles?
2. **Meta layout.** Is storing the full inner TCI in `reserved: u16` @ 42 (vs the
   prior split-VID-plus-stolen-PCP-byte) correct? Does any consumer need the
   inner DEI separately? Are two new `meta_flags` bits (STACKED_VLAN_PRESENT,
   OUTER_IS_8021AD) sufficient, or is an explicit outer-TPID byte needed?
3. **Egress TPID premise (§4.6).** Is "S-tag TPID is config-derived, not
   ingress-preserved" actually correct for the *transit* case, or does Junos
   QinQ transit preserve the ingress S-tag TPID end-to-end (forcing
   `OUTER_IS_8021AD` to drive every egress, not just swap mode)?
4. **Verifier gate.** Will adding a second-tag `read_bytes` + branch + two meta
   writes in `parse_l2`/`try_xdp_userspace` stay under the #1864 1M-insn cap and
   reproduce bit-identically? Is var_off on the 22-byte-offset read a hazard?
5. **Classification key.** Is `(ifindex, outer, inner)` with `inner=0`=wildcard a
   true strict superset, or does it perturb the existing `(ifindex, vlan)`
   single-tag rows (e.g. a single-tagged frame on a port that ALSO has QinQ
   units — does it match `(ifindex, outer, 0)` correctly and not a `(outer,
   inner)` row)?
6. **cos/ecn flip.** Flipping `ethernet_l3` from QinQ-reject (`None`) to
   QinQ-accept is a deliberate behavior change — does any current caller rely on
   the `None`-means-skip-ECN behavior for double-tagged frames in a way that
   acceptance would break?
7. **PR-A dead-code check.** Is PR-A (Go control-plane contract, helper still
   single-tags) genuinely *not* dead code — does anything observable change, or
   is it inert until PR-B? (It models config + writes networkd devices + emits
   additive JSON the helper safely ignores — argued non-dead, but challenge it.)
8. **networkd stacking.** Does systemd-networkd on the Ubuntu 26.04 base
   actually support `Kind=vlan` on a `Kind=vlan` parent with per-netdev
   `Protocol=802.1ad`, or is a different netdev kind (e.g. explicit
   `VLANProtocol=`) required?
