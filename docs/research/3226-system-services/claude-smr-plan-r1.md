# Claude SMR — HOSTILE plan review r1 — #3226

Reviewing `docs/research/3226-system-services/plan.md` @ abb844918af6 against
origin/master b3b8b6029. Posture: adversarial, not synthesizer.

## Verified claims (independently re-checked source)

- **§3 current behavior is ACCURATE.** Confirmed `host_inbound.rs:88`
  (`"all" | "any-service" => hi.all_services = true`), `forwarding.rs:284-286`
  (`if self.all_services { return true; }`), `daemon_nft.go:486-493`
  (`hostInboundAllowsAll`), `:438-441` (bare `daddr accept`, `return`, no drop),
  `:423-425` (`hostInboundEmitsDrop` false → no counter). The packet-wide-admit
  characterization is correct.
- **§4 #3277 fix is REAL.** `zones.go:73-84` `hostInboundLifelineSet` config-
  derives the set from `cc.ControlInterface/FabricInterface/Fabric1Interface`;
  `xpf-cluster-fw0.conf:17` sets `control-interface fxp1`, so fxp1 IS now a
  lifeline. The prior research's hard blocker is genuinely resolved.
- **#3199 intent is correctly quoted.** abe1030c0's message keeps
  system-services all/any-service as a deliberate full-admit.

## HOSTILE findings (must be folded before convergence)

### H1 — Option B does NOT fully satisfy the issue's own example (honesty gap)
The issue's motivating test is "`system-services all` admits SSH/HTTPS/SNMP but
**denies OSPF/GRE/VRRP**." But §5 correctly establishes `gre` is a *named*
system-service (proto 47). So under Option B, `all` = union-of-named **still
admits GRE/47**. Option B therefore closes OSPF(89)/PIM(103)/raw+future
protos/unlisted TCP-UDP ports, but NOT GRE. The plan must state plainly, in §2,
that **Option B only partially addresses the issue's literal example** unless
gre is also reclassified (which §10 puts out of scope). This materially weakens
the "ship Option B" case and must not be buried in §5.

### H2 — the value is a no-op on every shipped config (strengthens PLAN-KILL)
§2 already says scoping `all` is a no-op on all canonical configs (control zone
is lifeline-only → empty address set). Combined with H1, the honest reading is:
Option B ships real churn (new `any_tcp`/`any_udp` fields, classifier rewrite,
nft mirror, an extended #3486 parity test, a mandatory `make test-failover`) for
a benefit that (a) materializes ONLY on a non-shipped data-zone-with-`all`
config and (b) doesn't even fully close the issue's example. The recommendation
should not *lean* Option B; it should present Option B and Option A as genuinely
co-equal and make explicit that the marginal value is the core reason this is
the maintainer's posture call. (The current §Recommendation "recommended default
if forced: Option B" over-weights B given H1+H2.)

### H3 — `any-service` split may be unjustified scope
The plan gives `any-service` its own entire-TCP/UDP-port-range semantics
(`any_tcp`/`any_udp`). Is there ANY evidence `any-service` is used in xpf, or
that distinguishing it from `all` has operational value? If not, the simpler and
lower-risk choice is to keep `any-service` aliased to whatever `all` becomes (or
keep BOTH as the documented full-admit and only split `all`). Splitting
`any-service` adds two struct fields + admits branches + an nft `meta l4proto {
tcp, udp }` rule for a token of unproven usage. Flag this as a sub-option:
"`any-service` stays a documented full-admit escape hatch" is cheaper and is
already named in §5 Option-A prose — make it a first-class sub-choice under
Option B too.

### H4 — parity-test claim is under-specified
§7.1/§9 say "extend `TestHostInboundRustClassifierMatchesGoSSOT` to cover the
`all` expansion." But that test (host_inbound_rust_parity_test.go) compares the
*token arm sets* (classify_system_service arms == KnownHostInboundSystemServices).
The `all` expansion is a DERIVED admit set, not a token arm — the existing test
would NOT catch a divergence in how Go vs Rust expand `all` into ports/protos.
The plan must specify a NEW assertion that compiles `system-services all` through
BOTH layers and compares the resulting admit sets (port/proto/icmp-type sets),
not just assert arm-token equality. Otherwise §7 invariant 1 (no split-brain) is
not actually guaranteed by the named test.

## Verdict

**PLAN-DEFER-operator** — I agree with the disposition: this is a posture
decision, not an engineer-fixable bug, and the #3277 prerequisite is genuinely
met so the engineering is ready. But the plan must fold H1 (Option B only
partially closes the issue), H2 (rebalance the recommendation to co-equal, not
B-leaning), H3 (any-service-stays-aliased as a first-class cheaper sub-option),
and H4 (concrete new parity assertion, not just "extend the existing arm test").
With those folded, PLAN-DEFER-operator is the correct terminal state — the
maintainer chooses Option A (PLAN-KILL + doc) vs Option B (split, test-failover
gated), and given H1+H2 the genuinely-neutral framing slightly favors A.
