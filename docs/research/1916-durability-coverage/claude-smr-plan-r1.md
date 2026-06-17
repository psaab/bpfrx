# Claude SMR hostile plan review — #1916 r1

**Verdict: PLAN-NEEDS-REVISION** (not READY, not KILL).

The design is sound and the TLS fix is correct in shape. But the plan's
`os.WriteFile` inventory is **incomplete repo-wide**, which directly
breaks its own recommended Path A (writer-class repo-wide canary). Two
material revisions required before PLAN-READY; several open decisions are
fine to leave for /engineer.

---

## CRITICAL (must fix before PLAN-READY)

### C1 — Path A inventory is incomplete: 6 un-inventoried `os.WriteFile` sites will make the rewritten canary FAIL

The plan §2 inventories only `pkg/api` (1) and `pkg/daemon` (10 + the
procfs knobs). But a repo-wide scan (Path A, the plan's *recommended*
D1) flags EVERY direct `os.WriteFile` in `pkg/`. Grep of the base finds
direct `os.WriteFile` ALSO in:

- `pkg/dataplane/compiler.go:1484,1487,1493,1500` — RPS/RFS procfs/sysfs
  knobs (`rps_sock_flow_entries`, `rps_cpus`, `rps_flow_cnt`). All
  BestEffortKernelKnob.
- `pkg/dataplane/compiler_iface.go:139` — `accept_ra` procfs. Knob.
- `pkg/dataplane/userspace/process.go:160` — procfs/sysfs knob (verify
  enclosing func). Knob.
- `pkg/ra/sender.go:389,395` — `addr_gen_mode` / `accept_dad` procfs.
  Knob.

That is **7 additional knob writes across 3 packages** the plan never
mentions. Under Path A as written (Step 6: "walk all `pkg/**/*.go` …
flag every direct `os.WriteFile` EXCEPT functions named in
`allowedFunctions`"), the rewritten canary will FAIL on all 7 until they
are allowlisted. Step 5's allowlist seeding lists only the daemon knob
functions. **This is a self-inconsistency**: the plan's recommended path
cannot pass `make test` as specified.

**Fix**: §2 must add a complete repo-wide BestEffortKernelKnob inventory
(the 7 sites above + the daemon knobs + the existing
`restoreSlowPathRPFilter` which is in `pkg/networkd/networkd.go:221`, NOT
where Step 5 vaguely says "pkg/dhcp or wherever"). §5 Step 5 must seed
ALL of them. Without this, the plan is not implementable as-recommended.

This finding also *strengthens* the case for keying the allowlist by
`relpath::func` (multiple packages now contribute knob functions; bare
names risk collision, e.g. two packages with an `applyKernelTuning`-like
helper).

### C2 — Existing allowlist entry location is wrong in the plan

Step 5 says `restoreSlowPathRPFilter` is "in `pkg/dhcp` or wherever".
It is in `pkg/networkd/networkd.go:221`. A plan that mislocates the ONE
existing allowlisted function has not walked the canary's current
contract. Fix the reference; it matters because the `relpath::func`
migration (Step 6) must rewrite this exact entry's key.

---

## MEDIUM

### M1 — `pkg/dataplane`/`pkg/ra`/`pkg/dataplane/userspace` are currently OUTSIDE the canary; Path A pulls them in — confirm none hide a DURABLE writer

The plan assumes all newly-scanned sites are knobs. I verified the 7
above are procfs/sysfs (safe to allowlist). But the plan must *state*
this verification — a repo-wide scan is only safe if someone has
confirmed every newly-covered site is genuinely a knob and not a durable
writer that was silently escaping. This is the whole point of the issue
(false coverage confidence). The plan should add an explicit line:
"verified all newly-scanned non-daemon/api sites are procfs/sysfs knobs;
none are durable state." (They are — but the plan must own the claim.)

### M2 — `MkdirAllDurable` for `/etc/xpf/tls`: the cert dir is 0700 but the cert file is 0644 — confirm reader access

`os.MkdirAll("/etc/xpf/tls", 0700)` today. Cert is world-readable
(0644) but lives in a 0700 dir → only root can traverse. That is fine
for the daemon (runs as root) but the plan should note the perm is
preserved (0700 dir) so no access regression. Trivial, but the plan's
risk table mentions perms only for MkdirAllDurable, not the
dir-traversal interaction. Low-medium; just document.

### M3 — TLS test seam: `const`→`var` has a data-race smell if tests run in parallel

Step 7 proposes `const certPath`→`var` for injectability. If any other
`pkg/api` test mutates the package var concurrently (`t.Parallel()`),
that races. The plan's *preferred* alternative —
`generateSelfSignedCertAt(certPath, keyPath string)` with the entry
delegating — avoids the global entirely. **Recommend the plan commit to
the parameterized-function seam and drop the const→var option** to avoid
a reviewer round-trip at /engineer time.

---

## LOW / NITS

### L1 — TLS ordering claim is correct but should cite the failure mechanism precisely

The plan's "key-durable-first then cert-atomic eliminates the mismatched
state; key-only is rejected by `tls.LoadX509KeyPair`" is correct:
`LoadX509KeyPair` reads BOTH files and `ReadFile`s the cert first, so a
missing cert → error → regen. Good. But add the precise note: the
*current* code ALSO has a third bad state the plan should claim it fixes
— a cert write that succeeds + key write that fails (silent) leaves a
cert with NO key, and next boot `LoadX509KeyPair` fails → regen. With
the reorder (key first), the partial state is key-without-cert, same
clean-regen outcome. Net: every partial state self-heals. The plan
*implies* this; make it explicit so review can't claim a missed state.

### L2 — D4 (journal ReadAt) is genuinely orthogonal — consider splitting

It is a one-liner in `pkg/configstore/journal` (already a migrated
package, no canary impact). Including it is fine, but it dilutes the PR's
theme (daemon/api coverage). Mild preference to defer to a LOW follow-up,
but include-is-acceptable. Author's call.

### L3 — sshd drop-in D2 = DurableState is defensible but adds the only fsync on the SSH-apply path

Agree with the recommendation (security posture survives power loss). The
plan correctly notes fsync lands on operator-paced SSH-config apply only.
No objection — just flag that this is the single behavioral cost delta
(one fsync) and it is on a rare path. Fine.

---

## What's RIGHT (credit where due, to avoid over-flagging)

- TLS fix design (ordered individual-atomic, not a fake 2-phase commit) —
  correct and honestly scoped.
- Persistence-class assignments for the daemon/api files in §2 are
  correct per `docs/engineering-style.md` (authorized_keys/sudoers/
  hostname/timezone = DurableState; rsyslog/chrony/networkd drop-ins =
  AtomicGeneratedConfig).
- authorized_keys inode-replacement + keep-existing-chown reasoning is
  correct (root creates temp in user dir, rename, then `chown -R` fixes
  owner; sshd accepts root-or-user-owned 0600 keys).
- Waiving `make test-failover`: justified — none of the §6 files
  (config-apply + boot + TLS) feed cluster/VRRP/session-sync/failover.
  Confirmed by file list. **But** add a smoke that SSH still works after
  a key/sudoers config change (the plan already has this — good).
- DNS B-route preserving the EXDEV/EBUSY fallback as the sole allowlisted
  direct write is the cleanest handling.
- Correctly identifies the stale AGY-009 Part I.2 (rollback SyncDir
  already exists) and the LOW non-bug journal §3.

---

## Required for r2 → PLAN-READY

1. Fix C1: complete the repo-wide knob inventory (add dataplane/ra/
   userspace sites) and seed them all in the Step 5 allowlist.
2. Fix C2: correct `restoreSlowPathRPFilter` location
   (`pkg/networkd/networkd.go`).
3. Address M1: explicit "all newly-scanned non-daemon/api sites verified
   as procfs/sysfs knobs" line.
4. M3: commit to the parameterized-function TLS test seam.

M2/L1/L2/L3 are documentation polish — nice-to-have, not blocking.
