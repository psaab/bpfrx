# Claude SMR hostile review — #1917 plan v3, round 2

**Verdict: PLAN-READY.**

All three of my round-1 blocking corrections are resolved, all four of AGY's
round-1 blockers are folded in correctly, and I verified the one v3 edit most
likely to introduce a regression (the `active.json` manifest envelope) is
structurally safe.

## Round-1 blockers — resolved

1. **Phantom shim file → resolved.** §6.1 now states the shim is
   `//go:embed userspace_xdp_bpfel.o` (verified userspace_xdp_rust.go:11), collapses
   to a single `xpf` binary package, and explicitly ships no separate `.o`.
2. **Held-kernel contradiction → resolved.** §6.7 restates the premise honestly
   (userspace self-updates via apt; kernel does NOT free-update) and offers the
   verify-gated kernel channel; RISK #2 carries it.
3. **Manifest first-upgrade chicken-and-egg → resolved.** §8 enumerates the five
   no-manifest cases and states absence-of-manifest = schema-0, not corruption.

## AGY round-1 blockers — resolved

- **`dh_installsystemd` auto-restart → resolved** (§6.3a + RISK #9): `debian/rules`
  `--no-restart-on-upgrade --no-stop-on-upgrade`. This is the right fix and is the
  *load-bearing* one for "apt never cuts the dataplane."
- **Kernel verify needs a running kernel → resolved** (§6.7 + RISK #10): replaced
  the impossible "verify unbooted" with one-shot `grub-reboot` + boot-watchdog
  auto-fallback. Correct: the BPF verifier is kernel-space.
- **Non-atomic two-file manifest → resolved** (§8 + RISK #11): embed the manifest
  IN `active.json` (envelope) so the single `fsatomic.WriteFileDurable` rename
  stays the atomic unit.
- **Run staged orchestrator → resolved** (§6.3a + RISK #12): exec
  `/usr/local/lib/xpf/<N+1>/xpf-upgrade`, not the live symlink.

## Regression check on the highest-risk v3 edit (manifest envelope)

I verified the envelope cannot silently break other consumers: `active.json`,
`candidate.json`, and rollback slots are read ONLY through `db.readTree`
(db.go:111) — the single chokepoint reached by `ReadActive` (db.go:60) →
`store.go:128`. No other package unmarshals a `ConfigTree` from disk directly
(grep: only `db.go` does `json.Unmarshal(data, tree)`). HA config-sync uses
`Config.Format()` text, not the JSON file, so the envelope does not touch the wire
sync. The envelope therefore lands behind one reader/writer pair with a legacy
fallback — a contained, correct change. The implementer must still keep the
fallback (a bare `ConfigTree` with no envelope = schema-0) and update the
configstore tests (db_test.go round-trips), but that is engineering, not a plan
gap.

## Residual notes for `/engineer` (non-blocking)

- The boot-watchdog (RISK #10) needs a concrete health beacon + deadline; the plan
  names the mechanism, the implementer picks the beacon (e.g. a `verify-dataplane`
  PASS + an HTTP health 200 within N seconds, written to a marker the post-reboot
  oneshot promotes on).
- HA + kernel channel: do the one-shot kernel boot only on the drained/secondary
  node (the plan says so) — the implementer must sequence it inside the rolling
  drive so the cluster never has both nodes rebooting.
- `Conffiles`: the plan correctly keeps operator config out of the package; the
  implementer must ensure `/etc/xpf/.configdb`, `node-id`, `master.key` are not
  package paths and `postrm purge` leaves `/etc/xpf` alone (RISK #7).

This is a sound, honest, well-scoped plan. Recommend PLAN-READY pending the
round-2 Codex + AGY concurrence.
