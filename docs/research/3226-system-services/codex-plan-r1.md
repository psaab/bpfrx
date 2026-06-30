# Codex — hostile plan review r1 — #3226

Agent: codex:codex-rescue (task adec24cdb50edffac). Verdict: **PLAN-DEFER-operator** ("No revision needed").

Verbatim result:

> PLAN-DEFER-operator
>
> **Task 1 — §3 current behavior: VERIFIED at all cited lines**
> - `host_inbound.rs:86-88`: `classify_system_service` maps `"all" | "any-service"` to `hi.all_services = true`. Off by 2 from `:88` but unambiguous.
> - `forwarding.rs:279-286` (plan says :284-286): `if self.all_services { return true; }` at 279. Off by 5, structurally correct.
> - `daemon_nft.go:486-493`: `hostInboundAllowsAll` true for `all`/`any-service`. Exact.
> - `daemon_nft.go:438-440`: bare `<fam> daddr <addrs> accept` + early return. Exact.
> - `daemon_nft.go:423-425`: `hostInboundEmitsDrop` false when allows-all. Exact.
> Net: packet-wide full-admit claim correct.
>
> **Task 2 — §4 lifeline safety (#3277): VERIFIED — plan's strongest claim, it holds**
> - `zones.go:73-83` derives Control/Fabric/Fabric1 from config; `:94-102` adds em0/fab* fallbacks; `:237-239`/`:295-297` lifeline ifaces contribute no addr/VIP → empty set.
> - `xpf-cluster-fw0.conf:17,19-20` control/fabric = fxp1/fab0/fab1; lines 100-101 all in control with `system-services all` → all lifeline-excluded → address-empty → scoping `all` has no effect.
> - HA bind path (`daemon_ha_sync.go:444-456`, `heartbeat_manager.go:30-51`, `sync_conn.go:529-569`/`:1034-1065`): no heartbeat/session-sync/config-sync path lands on a non-lifeline scoped address.
> - Minor: `xpf-cluster-fw1.conf:89-91` control zone uses `system-services ping`, not `all`. Not safety-breaking; plan's "both fixtures use all" slightly overstated.
>
> **Task 3 — #3199 (abe1030c0): VERIFIED.** Removed `protocols all` full-admit, kept `system-services all`/`any-service` broad deliberately. Posture framing accurate.
>
> **Task 4 — GRE nuance: VERIFIED, plan's handling CORRECT.** `host_inbound.rs:206-209` gre→47; `host_inbound_tokens.go:50-88` gre in SSOT; `daemon_nft.go:661-662` gre→l4proto 47. Union `all` still admits GRE; fixing the test expectation (not the code) is correct.
>
> **Task 5 — Verdict framing.** Documented POSTURE decision, not a bug. PLAN-DEFER-operator fits. Option B right recommended ship; Option A defensible fallback. No revision needed.
>
> **Task 6 — Gaps.** #3486 parity gap CONFIRMED (token-set parity only, not the `all` semantic expansion — behavioral round-trip test genuinely missing; plan flags it). #3225 family-awareness: no gap, already handled (Rust `forwarding.rs:232-264`/`:290-314`, Go `host_inbound_tokens.go:180-225`). HA risk correctly weighted post-#3277.
