# Claude SMR hostile plan review — #1913 r1

Reviewer: Claude (domain SMR + CPU-arch/design + SW-design-patterns), HOSTILE pass.

## Independently re-verified claims (read source @ d535f1f3e)

1. **Allow-list divergence is real.** `tx/dispatch/slow_path.rs:90` filters
   `LocalDelivery | NoRoute | MissingNeighbor | NextTableUnsupported`; the
   `_from_frame` variant (slow_path.rs:129+) has NO such filter. CONFIRMED.

2. **PolicyDenied reaches :2814 with no early exit.** The arm at mod.rs:2799 is
   `ForwardingDisposition::PolicyDenied => telemetry.dbg.policy_deny += 1,` —
   a single statement, no `continue`/`return`. Falls through to
   `record_forwarding_disposition` (:2802) then the unconditional reinject
   (:2814). CONFIRMED.

3. **The reinject forwards a denied packet.** Walked
   `maybe_reinject_slow_path_from_frame`: `extract_l3_packet_with_nat`
   (depends on frame parseability + addr_family, NOT disposition) → succeeds;
   `tunnel_delivery` requires LocalDelivery → skipped for PolicyDenied; #1873
   gate requires `tunnel_endpoint_id != 0` → 0 for a normal denied transit
   flow → does NOT fire; `slow_path.enqueue(packet)` → kernel TUN → kernel
   FIB. CONFIRMED — this is a real zone-policy bypass.

4. **No use-after-recycle.** PolicyDenied/HAInactive keep `recycle_now = true`
   (default). The reinject extracts/copies the L3 bytes into an owned `Vec`
   BEFORE the `if recycle_now { scratch_recycle.push(desc.addr); }` epilogue
   at :2852. So the leak is a clean copy-out, not a buffer hazard. Severity is
   purely the policy bypass, not memory unsafety. CONFIRMED.

5. **Path B is correctly fatal.** `tx/dispatch/mod.rs:225` calls `_from_frame`
   with `request.decision` whose disposition is `FabricRedirect` (guarded by
   `if request.decision.resolution.disposition == FabricRedirect` at :223),
   and the sibling `else` at :238 uses the FILTERED wrapper. FabricRedirect is
   NOT in the allow-list, so the `_from_frame` choice is the deliberate
   bypass. Adding the filter inside `_from_frame` WOULD break this site.
   CONFIRMED — Path B rejection is sound.

6. **Path C is correctly fatal.** The wrapper `maybe_reinject_slow_path` takes
   `area: &MmapArea` + `desc: XdpDesc` and re-slices `area.slice(desc.addr,
   desc.len)`. The trailing site needs `packet_frame` (post-decap
   `owned_packet_frame`); using `desc` re-introduces the #1885 4-byte VLAN /
   un-decapped-outer bug documented at mod.rs:2163+. CONFIRMED.

## Hostile findings

### F1 (MINOR, plan-improving) — DiscardRoute is the clearest-cut leak; lead with it
The plan correctly flags DiscardRoute (§2.4) but buries it after PolicyDenied.
DiscardRoute has the LEAST ambiguous contract: a discard/reject route exists
SOLELY to drop, the wrapper allow-list explicitly excludes it, and there is no
"deny is logged" mitigation. The plan's severity framing should note
DiscardRoute is the cleanest proof the unfiltered reinject is a bug (no
plausible "intentional" reading). Not a blocker — Path A fixes all three
identically.

### F2 (MINOR) — §2.5 buffered-MissingNeighbor: the plan should be explicit that Path A does NOT touch it
The plan says "leave unchanged" but the recommended fix keeps MissingNeighbor
in the allow-list, so the duplicate-delivery the issue's Q3 flags is NOT fixed.
That is defensible (it is the documented #1901 recovery story), but the
converged plan + issue comment must say plainly: "Q3 is acknowledged and
DEFERRED; Path A does not change it." Otherwise a reader thinks #1913 closes
Q3. Recommend an explicit follow-up issue reference.

### F3 (NIT) — predicate location SSOT
Plan offers enum-method vs free-fn. Prefer the enum method
`ForwardingDisposition::is_slow_path_eligible` on `types/forwarding.rs`
alongside the existing `is_cacheable` — same pattern, discoverable, and the
doc comment lives with the enum that already documents each variant's intent
(:264-283). Free-fn in slow_path.rs is fine too; this is a nit.

### F4 (verify-at-/engineer) — telemetry double-count check
After the fix, suppressed frames are counted by `record_forwarding_disposition`
(:2802) which runs BEFORE the (now-gated) reinject. Confirm that with the
reinject suppressed there is no path that ALSO expected the reinject's
`record_slow_path_accept` to fire for these dispositions — there is not (the
`_ => {}` arm in `record_slow_path_accept` means PolicyDenied/HAInactive/
DiscardRoute never had a slow-path-specific counter anyway), so no counter goes
missing. Just pin this in a test.

## Verdict

**PLAN-READY-WITH-NITS.** The diagnosis is correct and independently
re-verified at every load-bearing step (policy bypass is real, not benign;
Path B and Path C rejections are both fatal-for-the-right-reason). Path A is
the right altitude: it aligns the trailing call with the contract the wrapper
has shipped since introduction, touches one call site + one pure refactor, and
preserves the one intentional unfiltered site. F1/F2 are wording/scope-clarity
improvements for the converged doc; F3 a nit; F4 a test pin. None block
PLAN-READY. Fold F1/F2 into r2 and I am at clean PLAN-READY.

(Per project discipline: a first-pass READY-WITH-NITS is a yellow flag. I
re-walked the §2.2 trace and the Path B/C rejections a second time specifically
to avoid a soft pass — they hold. The nits are genuinely non-structural.)
