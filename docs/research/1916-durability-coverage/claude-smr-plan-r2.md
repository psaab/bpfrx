# Claude SMR hostile plan review — #1916 r2

**Verdict: PLAN-NEEDS-REVISION** (one MEDIUM self-correction; otherwise
PLAN-READY-quality).

r2 resolves all of my r1 findings (C1 inventory now exhaustive incl. the
dataplane/ra/userspace knobs; C2 location fixed; M1 verification line; M3
parameterized seam). The procfs-helper-extraction discipline (§2.D) is the
right answer to the false-negative hole. But re-attacking r2's OWN new
reasoning surfaces one factual error I introduced when settling D6.

---

## MEDIUM (must fix before PLAN-READY)

### M1 — D6's "loopback-only, drop the cert-pinning harm" premise is FALSE; cert should be DurableState

r2 §1 item 2 and §4 D6 settle the TLS cert as AtomicGeneratedConfig and
DROP the cert-pinning harm, on the stated premise:

> "the self-signed cert is generated for the HTTP REST API on
> 127.0.0.1:8080 (loopback). It is NOT distributed to remote clients that
> pin it; the only consumer is local."

**This is wrong.** Verified in `pkg/daemon/daemon_run.go:1093-1099`:

```go
httpsBindIP := "127.0.0.1"
if wm.HTTPSInterface != "" {
    httpsBindIP = resolveInterfaceAddr(wm.HTTPSInterface, "127.0.0.1")
    ...
}
apiCfg.TLS = true
apiCfg.HTTPSAddr = httpsBindIP + ":8443"
```

When `system services web-management https interface <if>` is configured,
the HTTPS API binds to a **non-loopback interface address** and is reached
by **remote** management clients. The HTTPS default is `:8443` (not the
`:8080` loopback HTTP port the D6 premise names). So:
- Remote clients DO connect to this cert.
- If the key fails to persist (or is lost on power cut while the cert is
  AtomicGeneratedConfig), the next boot regenerates a NEW self-signed
  cert → every remote management client sees a cert change (pin break /
  TOFU cache invalidation / browser warning). That is a real
  operator-visible regression, exactly the harm r2 deleted.

**This means Codex HIGH#2's contradiction is NOT actually resolved by
r2** — r2 resolved it in the wrong direction (dropped the harm) based on a
false loopback premise. The correct resolution is Codex's *other* branch:
**classify the cert as DurableState too** (so it survives power loss and
does not churn), keep the harm in §1, and keep the key DurableState. Cost:
one fsync on the rare cert-regen path (operator-paced) — acceptable per
the project rule.

**Fix for r2→r3**:
1. §1 item 2: restore the cert-stability harm (reachable via non-loopback
   `https interface`), correct the "loopback only / :8080" misstatement.
2. §4 D6: cert = **DurableState** (both cert and key DurableState).
3. §2.A: move the cert row from class B to class A
   (`fsatomic.WriteFileDurable` for both).
4. §5 Step 1 / D5 sequence: step 4 becomes
   `fsatomic.WriteFileDurable(certPath, certPEM, 0644)`.
5. §12 changelog: correct the D6 entry.

Note this STRENGTHENS D5: with both files DurableState, the
remove-stale-pair + ordered-durable-write sequence makes both halves
power-loss-durable, so the {key-only} crash window self-heals to a
matching pair on the next *successful* write rather than relying on regen.
The mismatch-elimination argument is unchanged and still correct.

---

## LOW / confirmations (not blocking)

### L1 — D5 stale-pair removal: confirm SyncDir ordering
r2 D5 step 2 = best-effort `os.Remove` of cert+key then one
`fsatomic.SyncDir`. Correct: SyncDir after the unlinks makes the {neither}
namespace state durable, so a crash after removal cannot resurrect the
stale pair. Good. (Minor: if `os.Remove` returns ENOENT that is fine —
best-effort; the plan says so.)

### L2 — WithOwner placement (D7-a) — confirm before durable sync
`WithOwner` must `fchown` the temp fd AFTER `chmodTemp` and BEFORE
`syncFile`/`closeTemp`/`renameFile`, mirroring the existing
`WithPreserveExisting` chown block (fsatomic.go:258-265). r2 §5 Step 0
says "after `chmodTemp` ... before the durable sync/close/rename" — correct
placement. Confirm the impl reuses the `chownTemp` seam (it does in the
preserve-existing path). No issue; just verify in code review.

### L3 — canary `relpath::method` keying for receivers
r2 §10 Q3 flags this correctly: `tuneInterfaceBuffers` (method on
`*CompileResult`) and `writeFile` (method on `realHostTunableFS`) key on
the bare method name today. `relpath::` disambiguates across packages, but
WITHIN `pkg/dataplane` two different types could share a method name. Low
risk here (no collision in the current inventory), but the plan's
fallback (`relpath::recv.method`) is the safe form. Author's call; bare
`relpath::method` is acceptable given verified no in-package collision.

### L4 — D8 failover: agreed, correctly un-waived.
RETH `.link` mechanism change is cluster-adjacent; `make test-failover` +
`make test-ha-crash` is the right gate. Mechanism-only change → expected
green. Good.

---

## What r2 got RIGHT (credit)

- Exhaustive §2 inventory incl. all 7 r1-missed knob sites; correct
  `restoreSlowPathRPFilter` location.
- §2.D procfs-helper extraction (the key insight: never allowlist a
  giant multi-purpose function) — this is the strongest part of r2 and
  directly closes Codex#4's false-negative hole.
- D7-a `WithOwner` — the only mechanism correct on both first-write and
  re-write; reuses the existing `chownTemp` seam.
- D5 remove-stale-pair-then-ordered-write — correctly eliminates the
  mismatched-pair crash state AGY#4/Codex#1 raised.
- D3 DNS exact error-routing + no `WithResolveSymlinks` + `errors.Is`
  confirmation.
- Parameterized `generateSelfSignedCertAt` test seam (no global race).

---

## Required for r3 → PLAN-READY

Only M1: classify the TLS **cert as DurableState** (not
AtomicGeneratedConfig), restore the cert-stability harm corrected to the
non-loopback `https interface` bind, and propagate through §1/§2/§4-D6/§5/
§12. Everything else is confirmation-only.
