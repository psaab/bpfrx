# Triage Result: ps-review-040-A6-b1

- **Subsystem:** Config Control-Plane (HA/VRRP, eventstream, serialization, compile/apply pipeline, integer truncation) — actually pkg/dataplane + pkg/dataplane/userspace.
- **Base == current master?** Yes. Triaged against origin/master @ `95b33d49634d56086269a62a92e213dae7926f88` (HEAD: #4685 ha-userspace-split).
- **Repo:** real bpfrx (`/home/ps/git/bpfrx`). All cited paths exist on origin/master — NOT the avacado-xpf fork.
- **Outcome counts:** 3 findings → 0 GENUINE-RESIDUAL, 2 NOT-MATERIAL, 1 DELIBERATE. Plus ~106 self-declared negative-result sweep entries (no claims to triage).

---

## Finding 1 — EventStream acceptLoop CPU-spin / goroutine leak on Close — NOT-MATERIAL

**Claim:** If `EventStream.Close()` closes the listener while the context passed to `Start(ctx)` remains uncancelled, `acceptLoop` spins at 10 Hz (`Accept()` on a closed listener returns immediately, `ctx.Err()==nil` fails to break, `time.Sleep(100ms)`, `continue`), leaking `acceptLoop`+`ackLoop`. Severity Medium.

**Symbol exists?** Yes. `pkg/dataplane/userspace/eventstream.go:271-285` acceptLoop matches the quoted code exactly on master. `Close()` at :162-176 closes the listener but does NOT cancel any context (EventStream holds no cancel func of its own).

**Disposition rationale (why NOT-MATERIAL):** The spin is unreachable on the real caller contract. The sole production owner is the userspace `Manager` (`pkg/dataplane/userspace/process.go`):
- Start path (:54-57): `esCtx, esCancel := context.WithCancel(context.Background()); es.Start(esCtx); m.eventStream = es; m.eventStreamCancel = esCancel`.
- Both teardown paths cancel the context **before** calling Close:
  - error path (:80-84): `m.eventStreamCancel()` then `m.eventStream.Close()`.
  - `stopLocked()` (:189-194): `m.eventStreamCancel()` (sets `m.eventStreamCancel=nil`) then `m.eventStream.Close()`.

Because `esCancel()` fires first, `ctx.Err()` is already non-nil by the time `Accept()` unblocks on the closed listener, so the guard at eventstream.go:278 (`if ctx.Err() != nil { return }`) returns immediately — no sleep, no next iteration, no leak. The finding's own trace step 5 ("ctx has not been cancelled") is the false premise: no production path closes the listener without first cancelling the context.

The only `Close()`-without-cancel callers are the tests (`eventstream_test.go:522,579 defer es.Close()`), which run under a test context and a process that exits — not a live daemon leak.

The suggested `errors.Is(err, net.ErrClosed)` guard is reasonable defensive hardening (belt-and-suspenders against a future caller that forgets to cancel), but on current master there is no reachable spin, so this is not a live defect. Weight-verify against the caller contract disproves the Medium severity.

**Lane:** go (defensive-only, no fix required).

---

## Finding 2 — uint16(counterID) truncation in SNATValue/SNATValueV6 — DELIBERATE

**Claim:** `pkg/dataplane/compiler_nat.go:247,266,608,636` truncate a 32-bit FNV-1a `counterID` to `uint16` when populating `SNATValue.CounterID` / `SNATValueV6.CounterID`. Severity Low. Confidence High.

**Symbol exists?** Yes. All four `CounterID: uint16(counterID)` sites present on master; `types.go:685,695` confirm both structs field `CounterID uint16`.

**Disposition rationale (why DELIBERATE, not a bug):** The finding self-refutes. Each of the four sites carries an explicit comment on master:
> `// Vestigial: the legacy BPF snat_value carries a u16 counter id, but the userspace runtime writes this struct through a no-op DataPlane and reads hits via the snapshot's u32 counter id instead (#2255).`

The legacy eBPF dataplane is retired (#1373/#1476); these `SNATValue`/`SNATValueV6` structs are written through a no-op `DataPlane` and never reach a live map. The authoritative counter id is the u32 in the JSON `ConfigSnapshot` (`types.go:201 CounterID uint32`), which is what userspace-dp actually consumes. The truncation therefore has zero runtime effect — no wrong output, no counter aliasing on the live path. The reviewer's own "refutation attempt" acknowledges this ("truncation is benign … reads the full 32-bit CounterID via the JSON ConfigSnapshot"). This is a documented, intentional vestige, not a residual to fix.

**Lane:** go (no action — deliberate/documented).

---

## Finding 3 — snapshotContentHash JSON-marshal GC/alloc overhead — NOT-MATERIAL

**Claim:** `pkg/dataplane/userspace/builder.go:160-179` `snapshotContentHash` does a shallow-copy + `json.Marshal(&tmp)` + `sha256.Sum256`. For large configs (feeds "up to 64 MiB") this allocates heavily and, running under the config-apply lock, slows HA re-convergence/failover. Severity Low. Confidence Medium.

**Symbol exists?** Yes. Function matches the quoted code on master.

**Disposition rationale (why NOT-MATERIAL):**
1. **Deliberate, documented tradeoff.** The code comment states the choice explicitly: "This is cheaper than a custom hasher and reuses the existing JSON tags." `tmp.Config = nil` already excludes the raw config AST (the largest non-forwarding blob), and neighbors are filtered to publishable-only (#1197). It is a considered design decision, not an oversight.
2. **No correctness impact.** Purely a performance opinion; there is no wrong output, no incorrect dedup decision. Whatever the cost, it is a one-shot marshal per config apply.
3. **The hash is strictly cheaper than the work it gates.** `snapshotContentHash` exists to *skip* redundant control-socket publishes. When the hash matches, the daemon avoids serializing and pushing the entire snapshot over the control socket (which itself marshals the same snapshot). So the marshal cost is bounded by, and often net-negative against, the publish it prevents.
4. **Path frequency.** This runs on the infrequent, lock-held control-plane config-apply path, not per-packet/per-session/per-poll-tick. The "64 MiB feed" figure is speculative (dynamic-feed address entries drive the size, and the existing publish already pays a comparable serialization cost regardless). Confidence is self-rated Medium.

A move to an incremental field hasher is a legitimate optimization idea but is optional tuning, not a residual defect. NOT-MATERIAL on correctness/severity grounds.

**Lane:** go (optional perf tuning).

---

## Module sweep (findings 1..106 "Negative Result")

Entries 1-106 are the reviewer's self-declared negative-result sweep of the batch file list. They assert no defect and require no triage. Spot-checks of the cited symbols (eventstream, compiler_nat, builder, types.go CounterID) all resolve on master; nothing in the negative list makes an actionable claim.

## Summary
No genuine residuals. Finding 1's Medium spin/leak is defused by the process.go cancel-before-close ordering (unreachable in production). Finding 2 is a self-documented benign vestige of the retired eBPF plane (#2255). Finding 3 is a deliberate performance tradeoff with a justifying comment, no correctness impact, on an infrequent lock-held path. Consistent with ps-038 expectation: this core dataplane/config scope is well-hardened and yields ~0 residuals.
