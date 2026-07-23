# Plan of action — #5275: fail closed on dataplane ARM/ATTACH failure at boot

- **Issue:** #5275 (HIGH; bug, dataplane, security, vsrx-parity)
- **Research branch:** `research/5275-arm-failclosed`
- **Base:** origin/master @ `6131eb4e6`
- **Revision:** r4 (re-architected after Codex r1+r2 PLAN-NEEDS-MAJOR — replaces
  the "gate every publisher" model with the #1960 "do not start the takeover
  machinery" model, which dissolves most of the round-1/2 findings by
  construction)
- **Prior art:** PR #6358 (draft) — MERGE-NEEDS-MAJOR. Superseded.
- **Status:** PLAN-READY candidate (research only — no production code;
  implementation via `/engineer 5275`).

---

## 1. Problem & scope

#1960/#1993 fail **closed only on a COMPILE failure**. A config that COMPILES but
whose dataplane fails to **arm** (attach the AF_XDP shim to the data interfaces)
degrades a cold-booted firewall to a policy-free Linux router (`ip_forward=1`, FRR
advertising, VRRP/VIP/cluster ownership, no XDP on the data interface). Scope: on
any **first-arm path** (boot arm, bootstrap-exit arm, config-less-HA first
commit), a successful compile + arm failure must fail closed like the #1960
compile-failure boot — management lifeline up, nothing else — and preserve #5679
day-2 semantics. Out of scope: the attach mechanism; the native→generic fallback
(iavf degraded mode is armed, not a failure).

---

## 2. Root-cause insight — why the fix is "don't start the machinery", not
## "gate every publisher"

The #6358 draft (and this plan's r1–r3) tried to gate each ownership publisher on
a `dataplaneArmFailed` flag. Codex's two hostile rounds showed that path is a
losing game: there are ~12 publishers across forwarding, FRR, RETH VRRP,
direct-VIP GARP/NA, cluster RA, standalone RA, proxy-ARP, DHCP relay, DDNS Surface
A **and** B, Kea; several read ownership from **different** raw accessors
(`GroupState()`, `LocalPriorities()`, per-service snapshots); an atomic predicate
cannot linearize a leaf network effect (TOCTOU); and a registry canary is circular.

**The decisive structural fact (firsthand, daemon_run.go):** every one of those
publishers — and every dataplane *consumer* (conntrack GC, session sync, event
stream, HA watchdogs) — is started in ONE goroutine section that runs **AFTER**
the boot phase `dataplane-setup` (the arm):

- `startClusterComms(ctx)` (heartbeat + sync + election) — daemon_run.go:384
- `runUserspaceEventStream` :356, DHCP relay + `SetMasterGate` :450-463,
  `proxyARPReassertLoop` :532, `runDDNSReconcileLoop` :545,
  `runSurfaceADDNSReconcileLoop`, `watchVRRPEvents` :565,
  `startReconcileRGStateLoop` :569, GC/session-sync (wired in `startClusterComms`).

This is exactly how #1960 fails closed: a compile failure resolves
`computeBootClass → bootClassBootstrap` (bootstrap.go:233), and bootstrap mode
**suppresses `enableForwarding`, the dataplane arm, the boot `applyConfig`, and
all takeover** (bringup:214 `if !NoDataplane && !inBootstrap`) — the node runs
gRPC/CLI/SSH as a management-lifeline box and starts NO ownership machinery. #5275
is the one fail-closed trigger that is only knowable AFTER a successful compile, so
it cannot use `computeBootClass`; but it can use the SAME posture: **on first-arm
failure, do not start the ownership/publisher/consumer machinery, and tear down
the little that ran before the arm.**

Consequences (each dissolves a round-1/2 finding by construction):

- **HA:** the failed node never starts `startClusterComms`, so it sends NO
  heartbeats and runs NO election → it is SILENT in the cluster → the healthy peer
  takes over ALL RGs via normal peer-timeout election. No arm-failed wire signal,
  no `StateSecondaryHold` reuse, no both-secondary, no dual-VIP, no handoff ACK
  barrier, no mixed-version protocol bump (dissolves Codex §2 entirely).
- **Publishers:** VRRP/FRR/RA/proxy-ARP/DDNS-A+B/cluster-RA/relay never start →
  no per-publisher gate, no epoch, no façade, no TOCTOU (dissolves Codex §3).
- **Dataplane lifetime:** GC/session-sync/event-stream/watchdog consumers never
  start → nothing captures `d.dp` → the "synchronized nil vs a goroutine holding
  an old pointer" race is not created (largely dissolves Codex §4's ref-guard
  concern for the first-arm case; real `Teardown()` of the partial attach still
  required).

The residual work is small and well-scoped (§4–§6).

---

## 3. STEP-0 evidence (firsthand @ 6131eb4e6)

- Real arm boundary = the first ApplyConfig attach, not `Start()`:
  `attachUserspaceShimXDP` (loader.go:204-247): native fail + generic success ⇒ no
  error (armed); **both fail ⇒ error@242**. Propagates `CompileUserspaceShim →
  userspace Compile (manager_compile.go:187) → ApplyConfig (manager.go:354) →
  daemon_apply.go:1073`, where it is mis-classified as a #5679 deferred error
  (only `IsRequiredProtocolGateError` aborts), so the tail publishes.
- `enableForwarding()` runs BEFORE the attach at both sites (bringup:214,
  naming:225); the cluster manager is constructed (bringup:161) but
  `startClusterComms` (heartbeat/election) runs later (daemon_run.go:384).
- Boot arm (`applyConfig`, bringup:490-522) discards its result; `applyConfig`
  (daemon_apply.go:49) is void.
- A terminal abort in `applyDataplaneAndHACore` short-circuits `applyConfigLocked`
  before the tail (daemon_apply.go:288) — verified. The outer commit wrapper
  (`daemon_apply_commit.go:303` `applyErrSkipsPeerSync`) still runs; a first-arm
  failure must be classed so it does NOT push config / clear sessions on the
  "armed" invariant (only relevant to bootstrap-exit/day-2 first-arm — see §6).
- Partial attach can pin interface A then fail on B (loader.go:214-224);
  `Teardown()`/`DetachXDP` exist (manager.go:478 / loader.go:639/1223) but
  `Teardown` currently only propagates the final `RemoveAll` error — needs error
  aggregation + readback + owner-retained-on-failure (Codex D18).
- Coverage semantics: an empty required set returns success (loader.go:211) — a
  historical `everArmed` boolean is the WRONG predicate; coverage is
  **per-candidate-generation** (Codex D3, verified). A hitless restart has a
  surviving-helper probe (boot_probe.go) that must be consulted so a survivor is
  not mis-classed as unarmed.

---

## 4. Detection — per-generation coverage (Finding 1; Codex D3/D4)

- `d.dp.ApplyConfig` returns a **structured arm outcome** on `ApplyResult` (or the
  `ErrShimAttachFailed` sentinel): the required data-interface surface for THIS
  candidate generation (resolved ifindexes + any unresolved logical identities),
  the attached set + mode (native/generic) per interface, and a kernel/helper
  readback. "Armed" = every required interface has a live XDP program (native or
  generic); a missing/unresolved required interface, an empty-but-expected set
  mismatch, or a readback failure ⇒ **unarmed** (fail closed). This is
  per-generation coverage, NOT a historical boolean, so an add-B-fails commit is a
  coverage gap on B (§6), not a vacuous "ever armed".
- **Where:** immediately after `d.dp.ApplyConfig` returns in
  `applyDataplaneAndHACore` (the arm sites' `applyConfig` is void). First-arm gate:
  the node has no prior proven coverage (fresh boot / bootstrap-exit /
  config-less-HA). On a hitless restart, the surviving-helper probe supplies prior
  coverage so a survivor is not torn down.
- **Transition ordering (D4):** `armPending → coverage verified → forwarding
  enabled/quarantine released (verified) → machinery started/armed`. Set the
  "armed OK" state only AFTER coverage AND the forwarding-open step are verified;
  a failure at any step stays closed. Symmetric: the machinery-start gate (§5) is
  the positive `armedOK`, so normal boot starts the machinery only on proof.

---

## 5. Fail-closed posture (Finding 4 + Codex C4/§1/§4) — the core

On a first-arm failure:

1. **Abort the boot `applyConfig` tail** (A1): return the arm failure as a terminal
   abort from `applyDataplaneAndHACore` so `applyConfigLocked` short-circuits
   before VRRP/FRR/RA/routing publish (verified daemon_apply.go:288). Set the
   sticky `d.dataplaneArmFailed` (never cleared at runtime; recovery = restart).
2. **Do NOT start the ownership/publisher/consumer machinery.** Gate the
   daemon_run.go after-`dataplane-setup` startup section on `armedOK`
   (== `!dataplaneArmFailed`): `startClusterComms` (→ silent node → peer owns all
   RGs), `watchVRRPEvents`, `proxyARPReassertLoop`, DDNS A+B loops,
   `startReconcileRGStateLoop`, the DHCP-relay master-gate/loop, GC/session-sync/
   event-stream consumers. gRPC/REST/CLI/SSH stay up (management lifeline). This
   is the #1960 posture applied post-arm.
3. **Tear down the little that ran before the arm:**
   - **Forwarding:** prefer the QUARANTINE (do not `enableForwarding` until
     `armedOK` — move the bringup:214 enable to after arm proof); on the reactive
     fallback, `disableForwarding` with readback (ip_forward=0 + IPv6). A kernel
     nftables `FORWARD`-hook **unconditional** drop of transit is optional
     defense-in-depth — note it is UNCONDITIONAL (management is INPUT, not FORWARD;
     an exemption would be a routed bypass — Codex D1) and does NOT cover the DHCP
     relay (a local-socket forwarder — Codex D2), which is already handled by not
     starting the relay (step 2).
   - **Dataplane:** call `d.dp.Teardown()` — hardened to aggregate close/unpin/
     detach/pin-removal errors + readback that every XDP link/pin is gone (cleans
     the partial attach, Codex D18); on failure RETAIN the backend (do not nil —
     nil-ing loses the only cleanup owner) and record teardown debt; only after a
     verified teardown set `d.dp=nil`. Because the consumers never started
     (step 2), there is no reader racing the nil for the first-arm case.

Result: `ip_forward=0` (or never enabled), no XDP attached, no FRR/RA/VRRP/VIP/
relay/DDNS, silent in cluster (peer owns all RGs), management reachable — a true
lifeline box, sticky until restart.

---

## 6. Scope boundaries + the day-2 residual (Codex D3/D9)

- **Boot arm / bootstrap-exit arm / config-less-HA first commit** — the core
  #5275 case — are all "no prior proven coverage" ⇒ §5 applies (don't start /
  tear down the machinery). For the bootstrap-exit + config-less-HA paths the arm
  runs from `runBootstrapExitStartup`, which also starts machinery — the same
  `armedOK` gate must guard those start sites, and the commit wrapper
  (`applyErrSkipsPeerSync`, daemon_apply_commit.go:303) must treat a first-arm
  failure as "not armed": do NOT clear sessions on the armed-invariant and do NOT
  push this node's state to the peer (the peer keeps its own working config; a
  silent node triggers normal peer takeover).
- **Day-2 binding-expansion partial attach (A armed, add B, B attach fails,
  Codex D3):** here the machinery is ALREADY running, so "don't start it" does not
  apply and tearing the whole node down would be a self-inflicted outage. This is
  a NARROWER hole (only the newly-added interface, only on an operator commit).
  Two options — **decide at `/engineer`:**
  - **(a) Fold a bounded fix (RECOMMENDED):** keep #5679 (old policy for the
    already-armed surface stays live; the commit fails) AND bring the
    newly-required-but-unattached interface administratively DOWN (and/or add it to
    the FORWARD-drop set) so it cannot forward unpoliced. Per-generation coverage
    (§4) already identifies exactly which interface is uncovered. Small, targeted.
  - **(b) File as a separate follow-up** ("binding-expansion partial-attach
    coverage gap") and keep #5275 to the first-arm/boot case. Advances-not-closes.
- **Config-sync/failover completeness (Codex D9):** only relevant if a
  bootstrap-exit/day-2 commit that ADDS an RG/VIP/service fails to arm. The safe
  default is to NOT half-publish: fail the commit closed and let the node stay
  lifeline/silent; the peer retains its last mutually-installed config. Replicating
  an un-arm-able config to the peer is explicitly avoided. Documented as the chosen
  outcome; folds into option (a)/(b) above.

---

## 7. What #6358 keeps vs drops

Keep the concepts: sticky `dataplaneArmFailed`, `disableForwarding` (transit
sysctls only), `clearFRRManagedSectionOnFailClosedBoot` sharing the #1993 probe.
Drop: the `Start()`-only boundary (use the ApplyConfig coverage, §4); the
`SetArmFailedHold`/`StateSecondaryHold` cluster mechanism (replaced by "silent
node → normal peer takeover", §2); the scattered per-publisher gates (replaced by
"don't start the machinery", §5). Keep #6358's `Start()`-failure wiring folded
into the same first-arm path (an independent shim-load failure is also a first-arm
failure).

---

## 8. Test plan (bind real seams — Codex C27/D19)

- **Detection:** `attachUserspaceShimXDP` both-fail ⇒ `ErrShimAttachFailed` +
  outcome shows the required ifindex uncovered; native-fail/generic-success ⇒
  covered (INV); empty-but-expected mismatch ⇒ uncovered; hitless-survivor probe ⇒
  covered (not torn down).
- **Machinery-not-started (the core):** with `dataplaneArmFailed` set at the arm,
  assert the after-`dataplane-setup` startup section starts NONE of
  startClusterComms / watchVRRPEvents / proxyARPReassertLoop / DDNS loops /
  reconcile loops / relay-master-gate / GC-session-sync-eventstream; and gRPC/CLI
  DO start. Fail-on-revert: drop the gate on any one start site ⇒ that goroutine
  starts ⇒ RED.
- **Boot abort:** first-arm both-fail ⇒ terminal abort, tail not run (no
  VRRP/FRR/RA published), `dataplaneArmFailed` set, `d.dp==nil` only AFTER a
  verified `Teardown()` (recorder), partial-attach link/pin detached (real pin
  cleanup, not a recorder-only check).
- **#5679 day-2 preserved:** an ever-armed node's day-2 attach failure keeps old
  policy live, machinery NOT torn down, `Teardown` NOT called — RED if the
  first-arm gate is bypassed. Add-B-fails (option a) ⇒ old policy for A live, B
  brought down, commit fails.
- **HA (two-node, real seams):** a node whose first arm fails is silent
  (no heartbeat) ⇒ the healthy peer becomes/stays primary for every RG and
  carries sustained iperf3 — via the real heartbeat-timeout election, not a direct
  `electRG` call. No both-secondary, no dual VIP.
- **Teardown hardening:** `Teardown()` aggregates close/unpin/detach errors +
  readback; on failure the backend is RETAINED (not nil) with recorded debt.
- **Parent-RED recipe:** every neutralization an ASSERTION failure, imports still
  used (`feedback_red_on_revert_must_be_assertion_not_build_break`).
  `GOCACHE=/dev/shm/gc-5275 GOTMPDIR=/dev/shm TMPDIR=/tmp go test ./pkg/daemon/...
  ./pkg/dataplane/... ./pkg/cluster/... 2>&1 | tail`.
- **Smoke (parent, loss cluster):** `make test-failover` (v4+v6, push+reverse) +
  a runnable both-attach-fail injection (build-tag/env seam forcing
  `link.AttachXDP` to fail both modes on the data VF, mirroring `failedNativeXDP`)
  — assert the injected node is lifeline (ip_forward=0, no XDP, no FRR/VRRP/VIP,
  silent), the peer carries sustained iperf3
  (`feedback_verify_forwarding_with_sustained_iperf`), SSH stays up. The seam
  lands WITH the fix, not as a follow-up.

---

## 9. Blast radius, sequencing, risks, docs

- **Files:** `pkg/dataplane` (structured arm outcome + `ErrShimAttachFailed` +
  hardened `Teardown`); `pkg/daemon` (pipeline detection + first-arm gate,
  `armedOK` gating of the after-`dataplane-setup` startup section + the
  bootstrap-exit start sites, quarantine of `enableForwarding`, commit-wrapper
  classing, option-(a) interface-down); optionally `daemon_nft.go` for the
  defense-in-depth FORWARD drop. Net: markedly smaller than r3 (no HA wire signal,
  no per-publisher façade/epoch, no effective-ownership view) — the reuse of the
  existing "started-after-arm" structure is the simplification.
- **Sequencing (safe on clusters):** because the fix is "don't start the
  machinery", PR1 (detection + first-arm gate + Teardown + quarantine) is
  independently correct AND cluster-safe (a silent node is handled by the peer's
  existing election); the day-2 option-(a) can be a small PR2. No feature-flag
  gating needed (Codex D20 dissolves — there is no half-published intermediate
  state). Partial PRs say "advances #5275".
- **Risks:** (1) day-2 regression tearing down a working dataplane — mitigated by
  the per-generation first-arm gate + RED test; (2) the `armedOK` gate wrongly
  suppressing machinery in a legitimate NoDataplane/retired build — the gate is
  `!dataplaneArmFailed` (false in NoDataplane; true only on an actual arm failure),
  with a negative-control test; (3) hitless-restart survivor mis-classed unarmed —
  the boot_probe consult + a test; (4) `Teardown` failure leaving a partial attach
  — owner-retained + debt + readback test.
- **Rollback:** Go control-plane only; `git revert` restores current behaviour.
- **Docs:** `pkg/daemon/README.md` (fail-closed posture: first-arm gate = don't
  start the machinery, mirrors #1960; per-generation coverage; teardown),
  `pkg/dataplane/README.md` (structured arm outcome + hardened Teardown), `_Log.md`.

---

## Appendix — key source coordinates (origin/master @ 6131eb4e6)

- Machinery start section (all AFTER boot phase `dataplane-setup` @ daemon_run.go:158):
  `runUserspaceEventStream`:356, `startClusterComms`:384, DHCP relay+`SetMasterGate`
  :450-463, `proxyARPReassertLoop`:532, `runDDNSReconcileLoop`:545,
  `runSurfaceADDNSReconcileLoop`, `watchVRRPEvents`:565, `startReconcileRGStateLoop`:569
- `pkg/daemon/bootstrap.go:220-274` `computeBootClass` (#1960 compile-fail →
  bootstrap); `:481-575` `clearFRRForFailClosedBoot` / `failClosedBootShouldClearFRR`
- `pkg/daemon/daemon_run_bringup.go:161` cluster ctor; `:214` enableForwarding
  before attach; `:490-522` boot arm (result discarded)
- `pkg/daemon/daemon_run_naming.go:225` enableForwarding; `:230` Start; `:240` NAT
  alarm monitor (bootstrap-exit arm)
- `pkg/daemon/daemon_apply.go:49` void `applyConfig`; `:288` terminal-abort
  short-circuit; `:1069-1094` ApplyConfig error classification (#5679)
- `pkg/daemon/daemon_apply_commit.go:247/270/303` peer-sync + session-clear +
  `applyErrSkipsPeerSync`
- `pkg/dataplane/loader.go:204-247` `attachUserspaceShimXDP` (both-fail@242,
  empty-set success@211, partial pin@214-224); `:639` `DetachXDP`; `:1223`
  `Teardown` (only final RemoveAll propagates); `userspace/manager.go:354`
  ApplyConfig→Compile, `:478` `Teardown`; `userspace/boot_probe.go` hitless probe
- HA (now only relevant to the "silent node → peer election" story):
  `pkg/cluster` heartbeat/election — a node that never starts `startClusterComms`
  sends no heartbeat, so the peer's normal masterDownTimer / peer-loss election
  (election.go) owns all RGs; no new HA mechanism required.
