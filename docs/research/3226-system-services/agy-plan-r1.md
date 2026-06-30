# AGY — hostile plan review r1 — #3226

Agent: agy:agy-rescue (task ab7bb9ec18cf6d31e). Verdict: **PLAN-DEFER-operator**.

Verbatim result:

> ### Verdict
> `PLAN-DEFER-operator`
>
> #### 1. Verification of Proven Behavior (§3)
> 100% accurate at master b3b8b6029. Rust: `host_inbound.rs:88` alias;
> `forwarding.rs:284-286` short-circuit. Go: `daemon_nft.go:486-493`
> `hostInboundAllowsAll`; `:438-441` bare accept no drop; `:423-425`
> `hostInboundEmitsDrop` false → no counter.
>
> #### 2. Lifeline Safety and Control-Plane Drops (§4)
> #3277 (`zones.go:73-103`) makes the split safe-by-construction. All canonical
> configs (`xpf-cluster-fw0.conf:100`, `ha-cluster.conf:142`,
> `ha-cluster-userspace.conf:151`, `ha-cluster-loss.conf:154`) put only control
> + fabric interfaces in the control zone; `hostInboundLifelineSet(cfg)` includes
> ControlInterface/FabricInterface/Fabric1Interface unioned with em0/fab*
> defaults; `BuildZoneHostInboundViews` (`zones.go:238`) skips lifelines →
> control zone contributes no addresses → `emitHostInboundZone` (`:430`) no-op on
> empty set. **No counterexample exists**: heartbeat/session-sync/config-sync/
> fabric ride strictly the control+fabric interfaces, which are excluded from the
> filter entirely.
>
> #### 3. Bug vs Posture
> Posture decision. The full-bypass alias was a deliberate documented #3199
> (abe1030c0) choice (control-zone interfaces were not yet safely excluded, so
> keeping it open was the safe default). Option B → silent upgrade behavior change
> for operators who used `system-services all` on data zones. PLAN-DEFER-operator
> is appropriate.
>
> #### 4. Gaps and Nuances
> Go↔Rust parity (#3486): addressed (`host_inbound_rust_parity_test.go:173` needs
> matching Go/Rust expansion for `all`). Family-awareness (#3225): addressed.
> GRE-as-system-service: correctly identified (`host_inbound.rs:208`,
> `host_inbound_tokens.go:87` → proto 47 still admitted by union-`all`; contradicts
> issue's test expectation). VRRP raw AF_PACKET bypass + IPsec global exemptions
> correctly noted as unaffected.
