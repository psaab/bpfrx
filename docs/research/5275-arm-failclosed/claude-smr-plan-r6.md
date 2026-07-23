# Claude SMR — hostile plan review r6 (#5275)

Reviewing `plan.md` @ r7. Codex r5 confirmed 5/8 contracts closed and the
architecture VIABLE, and reduced to exactly 5 blocking design-composition items +
2 correctness holes + 2 wording cleanups. r7 folds all of them. Each verified
against the r5 finding and the source.

## Codex r5 blocking items → r7 folds (verified)

1. **Proof followed by proof-invalidating mutation** (§9 proved at step 4 then did
   networkd/VRF at step 5, which triggers RETH link-cycle/rebind AFTER the proof).
   r7 §5 splits a PRELIMINARY attachment proof (transaction decision) from ONE FINAL
   post-mutation proof (after networkd/RETH-rebind, daemon_apply_dataplane.go:219/386),
   and §9 step 5/6 reorders so addresses/FRR/services/release come only after the
   final proof. ✓
2. **RG0 read-only vs fix-forward contradiction** (store gate rejects user commit,
   store_lock.go). r7 §3 drops the blanket read-only and points to §8.5. ✓
3. **Publisher-generation TOCTOU** (candidate promoted+persisted before apply,
   daemon_apply_commit.go:225; DDNS/RA/VIP read ActiveConfig). r7 §8.5 adds DELAYED
   PROMOTION — promote only after the final arm proof; publishers read the last-armed
   applied generation, so an un-armed candidate is never published. Resolves #2 and
   #3 with one contract; `pkg/configstore` added to the blast radius. ✓
4. **Release/lifecycle ownership ambiguous.** r7 §5 makes `startTakeoverMachinery`
   the SOLE release owner with an ordered post-proof inventory, clearing
   `dataplaneUnproven` LAST (nothing follows the re-election it triggers). ✓
5. **Facade not sealed while pending.** r7 §7 makes the facade start SEALED (arming
   only via a private capability), open at the final release, revoke stickily. ✓

## Codex r5 correctness holes → r7 folds (verified)

- **Weight-zero gated on `effectiveHold`, not `dataplaneUnproven`** (else a dataplane
  proof un-yields while kernelTrial still holds → both-secondary). r7 §4 adds the
  effectiveHold gate. ✓
- **Failed withdrawal scrub safe branch** → r7 §3 escalates to a proved-down/
  service-fenced fallback before peer takeover. ✓

## Wording cleanups

- "peer owns every RG" → "every mutually-configured, eligible RG" (r7 §12 HA). ✓
- PR1 must not require the §9 (PR3) staged transaction — r7 §10 PR1 handles the boot
  single-generation arm and explicitly does not depend on §9. ✓

## Residual (MINOR — `/engineer` implementation audits, not design gaps)

- **N1 — delayed promotion is a real configstore reorder.** Promote-after-arm changes
  the commit pipeline (currently promote-then-apply). It is the correct contract but
  the single most invasive piece; PR1 must carry it or the TOCTOU stays. Flag as the
  highest-care implementation item.
- **N2 — facade capability plumbing.** The private arm-capability must reach exactly
  the arm transaction and nothing else; an audit of every `d.dp` capture + a
  per-consumer sealed/revoked test is the guard.
- **N3 — final-proof placement in the RETH path.** The final proof must sit after the
  LAST rebind even on the DeferWorkers path where the second reapply currently records
  debt; that reapply must return proof-or-failure (a real code change), not just be
  observed.

## Verdict

r7 resolves every Codex r5 blocking item and correctness hole with a named mechanism
and a source coordinate; the delayed-promotion contract elegantly collapses the
RG0-authority and publisher-TOCTOU findings into one. The architecture has been
viable since r5 (Codex's own words) and is now specified as a complete, composable
design contract with an honest, corrected phasing. The residuals are implementation
audits for `/engineer`. This is the `/research` deliverable: a plan a human can
approve for implementation with the real scope (a foundational fail-closed
architecture touching daemon boot, dataplane runtime, cluster HA, and configstore)
fully surfaced.

VERDICT: PLAN-READY
