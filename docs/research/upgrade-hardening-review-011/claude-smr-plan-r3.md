# Claude SMR plan review — round 3

**Plan:** `plan.md` @ `75a8b4435` (v2.2)
**Verdict: PLAN-READY**

v2.2 folds both r2 SMR points and every AGY-r2 nuance, all verified against the
code:

- **m1 (staged race):** §5 now states the truth — the preinst `LOCK_NB` gate
  only *narrows* the window (flock fd dies at preinst exit, not held across
  unpack), and `verify-dataplane` (cutover.go:151, runs against the copied
  binary before StopUnit) is the real torn-binary backstop, plus documented
  operator guidance. Outcome-safe.
- **m2 (C ↔ flip-failure):** §8 states C as an *unconditional pre-STOP
  invariant* with a required exhaustiveness test; §6's flip-failure rollback is
  now provably reachable only with a recovery path, and returns non-nil.
- **AGY-r2-1:** preinst idempotency hardened (always-repoint sbin; snapshot
  gated on `versions/current` absence; `rm -rf .partial`; oldver from
  `staged/xpfd version` with sanitized `$2` fallback, no fail on exec error).
- **AGY-r2-4:** lock re-entrancy (`Options.LockAlreadyHeld`) so the rolling
  path's inner `r.Run()` does not `EWOULDBLOCK`; `mkdir -p /run/xpf`.
- **AGY-r2-§5.3/§5.5:** postrm remove-on-purge; C2 dropped, C3 diagnostic-only.

The architecture (the `versions/`-is-maintainer-managed contract + A/B/C +
host-wide `/run` lock + verify-dataplane backstop) is internally consistent and
implementable. The four filed issues (#1964/#1965/#1966/#1967) are well-scoped;
two new must-fixes surfaced by review (flip-failure rollback, postrm) are folded
into #1967.

No remaining architectural objection. Remaining work is implementation-time and
explicitly enumerated in the plan (the C-pre-STOP exhaustiveness test and the
preinst crash-interleaving matrix). Recommend convergence to PLAN-READY pending
the final Codex/AGY confirmation on v2.2.

## Recommended implementation sequencing (for /engineer)

1. **#1965 lock first** (smallest, self-contained; unblocks safe concurrent
   testing of the others).
2. **#1964 seed/migration** (the spine; depends on the `versions/` contract).
3. **#1967 hardening** (flip-failure rollback + C1 validation + postrm + C3).
4. **#1966 doc** — ship-direct anytime.

Each is a separate PR; #1964 needs the baked-image + cluster-deb dogfood gates
(it changes every host's install path).
