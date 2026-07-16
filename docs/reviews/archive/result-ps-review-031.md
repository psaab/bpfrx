# Triage result — ps-review-031.md

**Review:** Cohorts 9-11 — IPsec/IKE/WireGuard + Routing/FRR + HA/Cluster/VRRP
**Base:** `b1bd96fb6` · **Triaged vs:** origin/master `fb3b09a274`
**Cites real bpfrx code?** YES (one file misattribution — XFRMIfNameAndID/Secret are in xfrmi.go/secret.go not the review's types_ipsec.go — but the symbols are real). 0 confabulated.
**Outcome:** RE-VERIFICATION PASS — 0 NOVEL bugs. 8 genuine residuals (all previously-reported) · 2 not-material · 1 already-fixed · 0 confabulated

## GENUINE residuals — all tracked
- **F1 [HIGH] cross-zone session hijack** (bare 5-tuple SessionKey, no ingress-zone re-validation on a session-table HIT) — session/key.rs:10, session/lookup.rs:48-260. `lookup_with_origin` reads metadata.ingress_zone ONLY to resolve the *stored* zone's half-open override, never compares the *incoming* packet's ingress zone → the zone-aware flow-cache miss falls through to the zone-unaware session table. **DISPOSITION: already-tracked #2387** (OPEN, needs-decision). Confirmed still present.
- **F7 [MED→Low] WG rekey REJECT_AFTER_TIME** — engine.rs:729 peer_has_confirmed_session no age check → bounded ~0-1s rekey blackhole (GC ~1s tick self-heals). **FILED #4546.** (why Low: bounded + self-healing.)
- **F3 [MED→Low] IPsec dynamic-hostname DNS stall** — policy.go:717-792 synchronous 2s/gateway in ordered apply → N×2s commit stall. **FILED #4547.** (why Low: dynamic-hostname gateways only; commit latency not dataplane fault.)
- **F5 [MED→Low] VRRP masterAdverInterval no clamp** — instance.go:1505 adopts MaxAdvertInt*10ms floorless → flap. **FILED #4548.** (why Low: VRRPv3 unauthenticated, so an L2 attacker has a strictly stronger priority-255 hijack already — value is guarding a benign misconfig.)
- **F8/F9/F10/F11 [LOW batch] → #4549:** F8 VRRP raw-IPv6 no hop-limit (near-nil: ff02::12 unroutable off-link + fallback path rare); F9 HA heartbeat udp4-only (parity gap); F10 IPsec PSK not zeroized (Go strings can't reliably wipe + swanctl 0600 plaintext on disk anyway — defense-in-depth only); F11 election same-node-id split-brain (misconfig-only, invalid config).

## NOT-MATERIAL (disproving mechanism)
- **F2 [MED] WG AllowedIPs overlap silent drop** — DELIBERATE, standard WireGuard cryptokey routing: cross-peer overlap resolved by global-LPM most-specific-wins; the "peer-A 0/0 packet with src in peer-B's /24 → drop" IS WG's intended anti-source-spoof property (matches kernel WG / wireguard-go). The doc-test `duplicate_cross_peer_prefix_only_one_peer_wins` documents it as intentional. Not a bug.
- **F4 [MED] HA heartbeat HMAC verified after UnmarshalHeartbeat** — claim's harmful path is GATED. The election-driving `handlePeerHeartbeat(pkt)` runs only at the END, AFTER `heartbeatAuthDecision` accepts (heartbeat.go:740-753); replay admit is macOK-gated (`nonceFresh := macOK && r.authReplay.admit(...)`, short-circuit); UnmarshalHeartbeat has no side effect beyond an error counter; ClusterID/NodeID checks only `continue`-skip. The claim "cluster/node ID from unauthenticated data drives election before auth" is FALSE — election is gated. Only accept-before-full-auth is the deliberate dual-accept rolling-upgrade window (#4107). Reorder would be cosmetic.

## ALREADY-FIXED
- **F6 [MED] XFRM if_id collision no commit gate** — the review quoted a STALE xfrm.go comment + greps a wrong validator name. `validateSecureTunnelBindInterfaceAST` (compiler_ipsec_bindiface.go, #2933) is a commit-time AST pre-walk that HARD-REJECTS two bind-interface strings deriving the same if_id (explicitly the st0/st0.0 case), strict-on-commit/warn-on-load (#1960). #2929 routing guard is the runtime backstop. Not a residual.

*Re-verification of prior cohorts (ps-020 S-001, ps-021 crypto/HA) on a fresh base — surfaced no novel bugs. The genuine residuals now all have tracked dispositions (#2387/#4546/#4547/#4548/#4549). F2/F4 corrected from the review's MEDIUM to not-material with disproving traces; F6's stale-comment misdirection corrected to already-fixed #2933.*
