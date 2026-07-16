# Triage result — codex-review-182 (Paladin Full-Tree Review, ~16k lines)

**Review base:** `cbba4c37a` · **Verified against origin/master:** `fc479ca65`.
**Method:** parent inline (FleetView roster walled — no delegated triage; the ps-044-style agent spawn returned "no space for new pane"). codex-182 is a coordinator-verified high-signal Codex full-tree review (2,752/2,752 files, 546/546 cross-layer rows) with a completed origin/master verification section. Per `feedback_review_triage_overfiles_cap_and_audit`, count is a signal to VERIFY a sample not rubber-stamp: parent spot-read **M17** (`daemon_apply.go:903-911` — ordinary apply failure falls through, commit reports success) and **M06** (`poll_descriptor/mod.rs:3906` — flowless `nat: NatDecision::default()`) directly on master; both CONFIRMED → trusted the coordinator-verified gate table for the rest, citing each finding's root + fix direction.

## Summary line
**43 MATERIAL roots FILED (#5673–#5715) / 17 exact closed-owner residuals REOPENED / 5 cohorts FILED (#5716–#5720) / DUP_OPEN + DUP_CLOSED already deduped by the review (incl. my #5658-5672).**

## FILED — 43 new MATERIAL roots

### 13 High
| ID | Issue | Root |
|---|---|---|
| M02 | #5673 | pre-policy RX source learning → spoofed neighbor-map growth + all-shard serialization (DoS) |
| M03 | #5674 | HA session imports bypass max_sessions + multiply per-worker queues |
| M09 | #5675 | multiple `interfaces` roots bypass first-root prepasses, replace range/filter state |
| M10 | #5676 | address vs address-set share untagged namespace → deny shadowing |
| M11 | #5677 | direct-host projection resolves application-set before same-named user app (≠#5629/#5671) |
| M12 | #5678 | qualified-next-hop preference dropped at AF_XDP snapshot → backup becomes ECMP |
| M17 | #5679 | ordinary full apply failure reports commit SUCCESS, preserves old policy (VERIFIED :903-911) |
| M18 | #5680 | route-only publication ACKs old-policy/new-route hybrid (#5642 residual) |
| M23 | #5681 | RG reconcile not joined before shutdown cleanup → late VIP/forwarding re-enable |
| M24 | #5682 | unreadable kernel-upgrade journal bypasses election hold (fail-open) |
| M28 | #5683 | PBR builds full 6-D product before the 1000-rule cap → pre-cap OOM |
| M33 | #5684 | custom config paths turn zeroize into parent-dir deletion |
| M40 | #5685 | release stamping embeds unvalidated apt URL into signed root shell |

### 30 Medium
M01 #5686 · M04 #5687 · M05 #5688 · M06 #5689 · M07 #5690 · M08 #5691 · M13 #5692 · M14 #5693 · M15 #5694 · M16 #5695 · M19 #5696 · M20 #5697 · M21 #5698 · M22 #5699 · M25 #5700 · M26 #5701 · M27 #5702 · M29 #5703 · M30 #5704 · M31 #5705 · M32 #5706 · M34 #5707 · M35 #5708 · M36 #5709 · M37 #5710 · M38 #5711 · M39 #5712 · M41 #5713 · M42 #5714 · M43 #5715

## REOPENED — 17 exact closed-owner residuals
(correct action for a regression on a specific closed bug — not a tracker comment; each reopened with the codex-182 residual)
- High: #5645 (composite/static-alias feed still publishes partial deny — residual after my #5665), #3718 (dup local addr inherits zoned allow), #103 (peer-dead election bypasses readiness), #72 (activation precedes fence), #2170 (stale delete defeats gen guard), #82 (sync listener before wiring), #4876 (staged-GC suppresses current-gen errors), #5043 (golden overwrite guard).
- Medium: #3366 (inline ICMP dup truncation), #3449 (DNAT range unbounded expand), #5628 (same-mode/packed-tail NAT terminal survives lowering — residual after my #5656), #5647 (local scoped clear widens global — residual), #3447 (rollback trailing tokens), #2448 (qualified next-hop bypasses validation), #2604 (MODP 17/18 invalid strongSwan tokens), #4905 (validation cleanup no per-run ownership).

**Parent-flag:** #5645, #5628, #5647 are residuals AFTER my own recent merges (#5665/#5656/#5652-class) — the fixes were incomplete; re-verify coverage before re-driving.

## COHORT — #5716 (C-RUST) · #5717 (C-CONFIG) · #5718 (C-HA) · #5719 (C-API) · #5720 (C-TOOLS)
22 post-gate low-materiality/defense-in-depth survivors bucketed per the review; no demonstrated live-enforcement bypass.

## DEDUP (review already excluded — not refiled)
Scheduler + DHCP-relay → #5669/#5670; tolerant app-set → #5671; NAT prefix → #5658/#5660; host-inbound zone-0 → #5659. Inline ICMP / DNAT expansion / raw NAT action cardinality routed to the #3366/#3449/#5628 reopens above. #5631 alias subtrace independently refuted + removed by the review.

---
*Marker: `/tmp/.researched-codex-review-182.md`. All spot-verification via `git show origin/master:<path>`. Triaged inline (parent) — roster walled. HA reopens (#103/#72/#2170/#82) + M23/M24 (#5681/#5682) need test-failover before any fix merges.*
