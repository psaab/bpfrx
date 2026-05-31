# Claude-SMR plan-review r2 — #1703

Posture: HOSTILE confirm that r2 actually closes the r1 findings without
introducing a contradiction. Verdict: **PLAN-READY**.

## r1 findings disposition

- SMR r1 #1 (TAI64N monotonic+persisted+HA): folded into S2 acceptance
  criterion (§7) and §9. CLOSED.
- SMR r1 #2 (HA/RG session migration): added as S8 (§7). CLOSED.
- SMR r1 #3 (mac1 is keyed-BLAKE2s not HMAC): folded into S2 (§7). CLOSED.
- Codex r1 #1 (empty keepalive/key-confirm records rejected): demoted from
  already-works to gap C4; S5 + Test 2b; §2.3 caveat; §9 bypass-precision note.
  CLOSED — and the §9 note correctly requires keying the bypass off decrypted
  len==0, not off `inner_src_ip == None`, which would otherwise let a malformed
  non-empty inner skip the AllowedIPs gate (a security regression). Good catch
  to pre-empt.
- Codex r1 #2 (DSCP/ECN divergence hidden under already-works): demoted to C5;
  S7. CLOSED.
- Codex r1 #3 (S1/S2 gating deadlock): S1 now lands xfail against HEAD; S2
  acceptance = flip xfail→green; explicit ban on duplicate test-only framing.
  CLOSED.
- AGY r1 #1 (no userspace IP reassembly for fragmented outer UDP): added O1 +
  S3 DF/PMTUD/MSS + §9 as the top silent-failure risk. CLOSED.
- AGY r1 #2 (handshake heap-alloc must stay off poll worker): added O2 as an
  S2/S3 don't-regress criterion; the engine design already enforces this
  (handshakes are control-thread only), so it is a preserve-invariant gate, not
  new build-out. CLOSED.

## Hostile re-check of the r2 deltas

- No new contradiction introduced: S1-xfail / S2-flip-green is internally
  consistent with the §8 test plan (Test 1/2 now explicitly "lands as xfail").
- C4's scope is correctly bounded (len==0 only) so it cannot become an
  AllowedIPs bypass — I specifically tried to break this and the §9 note
  forecloses it.
- O1 is correctly framed as an operational LIMIT with a mitigation (MSS+DF),
  not a "build a reassembly engine" mandate — which would be wrong scope for a
  userspace dataplane.

Central verdict (NOT-YET-INTEROPERABLE, Path A, multi-PR S1→S8) unchanged and
still correct. PLAN-READY.
