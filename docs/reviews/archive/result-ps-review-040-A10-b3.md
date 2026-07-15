# Triage Result: ps-review-040-A10-b3

- **Subsystem**: Area A10 Batch 3 — `pkg/policymatch`, `pkg/scheduler`, `pkg/upgrade` (+ lock/manifest/stagedgen/runtime), `pkg/wgkey`, `scripts/{deploy,dist,image}`, `test/incus` python, `test/xsk-repro`, cold-path-flooder.
- **Base == master?** Yes — triaged against current origin/master.
- **Master SHA**: 95b33d49634d56086269a62a92e213dae7926f88
- **Repo provenance**: Review authored against the **gemini-xpf fork** (all `file://` paths are `/home/ps/git/gemini-xpf/...`). The cited packages/symbols are real xpf packages and exist on bpfrx master, so this is NOT confabulated — just a fork checkout of the same tree.
- **Outcome counts**: 1 concrete finding → 1 DUP+NOT-MATERIAL; the remainder of the document is a negative-findings / invariant-confirmation report (Section 2: "No new high- or medium-severity issues were found"). GENUINE residuals: 0.

## Nature of the report

This is a **defensive negative-findings sweep**. Sections 1.1–1.13 enumerate
invariants the reviewer checked and found sound (fail-closed policymatch, clock-drift
scheduler hold, flock'd atomic upgrade cutover, X25519 clamping, virtio-first deploy
ordering, TOCTOU-safe dist signing, etc.). None of these are findings — they are
"checked and OK" statements. Section 2 states plainly that no new HIGH/MEDIUM issues
exist in scope. Only one concrete item is called out, and the review itself pre-classifies
it as LOW and a duplicate.

## Per-finding disposition

### F1 — Manual `atoi` overflow hazard, `pkg/upgrade/cluster_cli.go:278` (LOW, self-declared DUP)

**Disposition: DUP + NOT-MATERIAL.**

- **Symbol exists**: Yes. `cluster_cli.go:278` is `func trailingInt(line string) (int, bool)`. The manual accumulate loop is at line 292 (`n = n*10 + int(r-'0')`), with two structurally identical copies at lines 466 and 499. No overflow/length guard on the digit run — the raw hazard the reviewer describes is factually present.
- **Why NOT-MATERIAL**: `trailingInt` is called only from `parseHAProtocolCompatible` (line 259/265), which parses the **local daemon's own rendered status/information topic** text for lines `ha protocol version:` / `peer ha protocol version:`. The value emitted there is a small internal constant (`CurrentHAProtocolVersion` / `LegacyHAProtocolVersion`, single/low-double digits) — not attacker-controlled external input. There is no reachable path feeding an arbitrarily long digit string.
  - Even in the hypothetical overflow case: Go `int` overflow **wraps deterministically**, there is no memory unsafety and no panic. The wrapped value is used *only* in the `local == peer` equality at line 273. Worst case is a wrong compat/incompat verdict — and the surrounding logic already **fails closed** (`if !haveLocal || !havePeer { return false }`; `PeerAlive` gates the happy path per the in-file comment at lines 249–251). So even a corrupted parse degrades to "not compatible," the safe direction.
- **Why DUP**: The review explicitly says this "is noted for duplication tracking" and is a "prior campaigns" finding, i.e. already-known / already-triaged, not novel to this batch.
- **Severity reconciliation**: Reviewer rated LOW. Agree it is at most LOW (I would call it INFO): trusted internal input, wrap-not-crash, fail-closed consumer. Not worth a fix beyond an optional cosmetic `strconv.Atoi` swap; no exploit or availability impact.

### Sections 1.1–1.13 — invariant confirmations (no findings)

All are "checked and sound" negative results. Spot-note: the claims align with the
heavily-hardened state of these packages this session (fail-closed policymatch,
scheduler clock-drift hold #3849/#3988, flock'd atomic upgrade cutover, wgkey X25519
clamping). Nothing here asserts a defect; nothing to triage.

## Conclusion

Consistent with the ps-039/040 expectation that these well-hardened scopes yield ~0
residuals. The single concrete item is a self-declared LOW duplicate on a trusted-input,
fail-closed, wrap-not-crash path — NOT-MATERIAL. No novel, reachable, un-fixed defect.
GENUINE residuals: 0.
