# Claude SMR — hostile plan review r2 (#5275)

Reviewing `docs/research/5275-arm-failclosed/plan.md` @ r3 (post Codex
PLAN-NEEDS-MAJOR). I verified Codex's load-bearing findings firsthand before
accepting the rework, and re-probed the r3 design.

## Codex findings I verified firsthand (all held → accepted into r3)

- **C4** — `enableForwarding()` runs before the attach at both sites (bringup:211,
  naming:225); cluster ctor before dataplane (bringup:161). Reactive ⇒ withdraw,
  not "never published". ✓ → r3 §7.0 quarantine.
- **C3** — `applyErrSkipsPeerSync` (daemon_apply_commit.go:303) skips peer-sync
  only for required-protocol/ctx-cancel; every other error pushes config to the
  peer + clears sessions on the "armed" invariant (247/270). ✓ → r3 §5.A commit-wrapper.
- **C5** — new RGs init `StateSecondary/255` (group_state.go); #6358 demotes only
  primaries ⇒ high-priority secondary keeps advertising ordinary secondary. ✓ →
  r3 §5.B "all RGs".
- **C8** — RG0 transition auto-`ConfirmPendingOnDemotion()` on Secondary/SecondaryHold
  (daemon_ha.go:471) ⇒ reusing SecondaryHold would CONFIRM the failed commit. ✓ →
  r3 §5.B dedicated signal, not SecondaryHold.
- **C11** — DHCP relay is a per-packet forwarder started independent of arm
  (daemon_run.go:449), always-open standalone/RG0 gate, bypasses ip_forward. ✓ →
  r3 §6 + §7.2 FORWARD-drop barrier + relay master-gate.
- **C24** — partial attach pins A then fails B (loader.go:214-224); `d.dp=nil`
  without `Teardown()` (manager.go:478) leaks pins. ✓ → r3 §7.1 step 5.

Codex signal was ~6/6 real. PLAN-NEEDS-MAJOR was correct; r3 is a genuine rework.

## Re-probe of r3 (hostile)

### Resolved by r3
- Detection moved fully into the pipeline with a structured arm outcome (not a
  bool) + all first-arm paths + commit-wrapper handling. ✓
- Peer-yield via a dedicated advertised override covering all RGs + all writers,
  no SecondaryHold side-effect; B2 no-wire fallback documented. ✓
- FORWARD-drop barrier as the authoritative transit-deny (robust to relay /
  ip_forward bypass, no interface enumeration) + quarantine (install-before-
  enableForwarding, release-on-proof) closes the C4 pre-arm window. ✓
- Publisher set completed (relay, direct-VIP GARP/NA, cluster RA, DDNS, Kea) +
  epoch-at-sink closes the TOCTOU; façade over sinks addresses the circular-canary
  point. ✓
- Teardown: barrier-first invariant, real `Teardown()` before nil, consumer
  stop/join under `-race`, verified steps. ✓
- Tests bind real seams (heartbeat/election path, recorder for Teardown-before-nil,
  runnable attach-fail injection shipped WITH the fix). ✓

### Residual concerns (MINOR — do not block PLAN-READY; flag for `/engineer`)

- **N1 — nft FORWARD hook correctness.** The barrier assumes leaked transit
  traverses the kernel `FORWARD` chain. That is true precisely because the #5275
  failure = no XDP attached ⇒ packets fall to the kernel path. Confirm at
  implementation that the drop belongs on `FORWARD` (post-routing decision) and
  interacts correctly with any existing xpf nft tables / conntrack; a `raw`/`mangle`
  pre-routing drop may be needed to beat established-conntrack accept rules. Not a
  plan-level blocker; it is the first thing to validate in PR1.
- **N2 — quarterine release atomicity.** Releasing the barrier on arm-success must
  be the LAST arm step and must itself be verified; a crash between "armed" and
  "barrier removed" simply stays closed (safe). State this so the success path
  can't leave a half-open box. (r3 §7.0 implies it; make it explicit at impl.)
- **N3 — B1 wire bump vs B2.** B1 adds an HA protocol-version field; the project
  has a mixed-version HA path already. B1 is recommended but B2 (no wire, gate all
  writers + suppress RG0 auto-confirm) is a legitimate lighter path the user may
  prefer to avoid a protocol bump. The plan correctly leaves this as an
  `/engineer`-time decision with both fully specified — good, but the user should
  make the call explicitly.
- **N4 — sequencing.** §10's 3-PR split is sound (PR1 standalone fail-closed is
  independently correct and independently smoke-testable). Ensure partial PRs say
  "advances #5275", never a close-keyword (`feedback_never_close_keyword_even_negated`).

## Verdict

r3 correctly reframes the fix from a missing `if` to a fail-closed *posture* the
boot sequence never had, and addresses every firsthand-verified Codex finding plus
my r1 M1–M5. The residual concerns are implementation-validation items, not
architecture gaps. The design space is fully surfaced with recommended paths +
documented fallbacks (A1, B1/B2, C2+C1, quarantine/reactive), which is exactly the
`/research` deliverable.

VERDICT: PLAN-READY
