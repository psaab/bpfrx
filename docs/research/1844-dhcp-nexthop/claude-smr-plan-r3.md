# Claude SMR plan-review — #1844 round 3

Reviewed v2.3 (`plan.md` @ 333e8ad6d + the Codex r3 §4.6 wording fold).
Scope: the two deltas since my r2 PLAN-READY — the pendingFIBBump
retry (Codex r2-1) and the eager DHCP-manager creation (AGY r2).

## Verdict: PLAN-READY (with one boot-failure semantics clause folded)

- **pendingFIBBump:** correct and minimal. The flag lives in the
  daemon actuator and is mutated only under `applySem`; the worked
  orderings (publish-ok/bump-fail/dup-skip ⇒ retry;
  publish-skip-with-confirmed-bump ⇒ silent) are both named tests.
  No interaction with the full-apply path: a full apply re-publishes
  and performs its own invalidation, and the flag only ever ADDS a
  bump (idempotent on the helper) — it can never suppress one.
- **Eager creation:** verified the precedent claim (`d.rpm` eager "so
  the pointer is stable", `daemon_run.go:236`) and that the resolver/
  CLI readers become race-free once `d.dhcp` is write-once-at-boot.
  ONE wrinkle the fold introduced (caught in this pass, resolution
  folded into §4.3): today's lazy path **retries** `dhcp.New` on
  every apply (`reconcileDHCPClients` re-enters when `d.dhcp == nil`);
  a naive eager-once port would permanently disable DHCP for the
  process if `netlink.NewHandle()` fails once at boot. Resolution: an
  eager `dhcp.New` failure at boot is a **fatal startup error** — the
  daemon cannot manage interfaces without netlink anyway, and
  fail-fast beats a silently DHCP-less firewall. This preserves the
  write-once invariant without a retry path.

No other findings. PLAN-READY.
