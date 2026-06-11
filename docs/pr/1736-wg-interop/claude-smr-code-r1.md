# Claude SMR hostile code review — PR #1868, round 1

Verdict: NEEDS-CHANGES round 1 (concurrent with Codex/AGY; all findings
folded at 7a339321a) -> re-verify in round 2.

Independent checks beyond the other reviewers:

1. Transit-path composition (frame/wg.rs): with hydration-level
   canonicalize (Codex F1 fold), the AF_XDP transit egress now selects a
   v4 OUTER for a configured mapped literal — previously it would have
   built a v6 outer toward a mapped address. The fix improves the
   transit path, not just the control thread. Verified wg.rs outer
   selection consumes the same hydrated endpoint.
2. wg_send_to family matrix: v4 target/v6 socket -> mapped (the live
   bug); v4/v4 -> native (new test); v6 target/v6 socket -> untouched;
   v6 target/v4-fallback socket -> EAFNOSUPPORT recorded as exception —
   a learned v6 endpoint cannot occur on a v4 socket (it cannot receive
   v6), and a CONFIGURED v6 endpoint with a v4-only host is an S7
   (v6-outer) limitation, acceptable and documented.
3. dispatch_inbound replies use raw recv_from addr through wg_send_to:
   mapped-V6 and native-V6 pass through unmodified (correct on the v6
   socket); native-V4 on the fallback socket unmodified. No double
   mapping.
4. wg_identity_unchanged compares the HYDRATED Option<SocketAddr> on
   both sides of a reload — canonicalize is applied identically, so a
   mapped-literal config does not flap engine identity across commits.
5. Engine-identity freshness in the harness (fresh keys per configure)
   composes with the S2a identity-reuse contract: every configure is an
   identity change -> coordinator stop+join+respawn -> no dependence on
   the leaky removal path (#1866).
6. Hot path untouched: all Rust changes live in the control thread +
   hydration (one-time per reload); no allocations added; no AF_XDP
   worker code touched. The Go change is apply-time only.
7. Reviewed the live-evidence honesty: the PR's "Part of #1736" call and
   the taint mechanism (Codex F2 fold) match the
   review-scaffolding-against-consumer discipline — a recovered run can
   no longer read as clean merge evidence.

Residual (accepted, documented): P4b/P5/P6/P7 clean-run captures pending
a quiet cluster window; tracked in the PR body and the issue.
