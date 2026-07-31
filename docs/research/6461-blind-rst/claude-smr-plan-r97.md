# Claude SMR hostile plan-review — round 97 (v10.13.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — seventeenth
pass; I authored the v10.13.0 fold of Codex r96's 6B/1H/1M. Verdict:
**PLAN YES**.

## 1. Fold verification

**r96-1 (B — the cold master-split itself reuses released P1).**
Verified the load-bearing claim: `NatDecision::merge` prefers fields
already set (`nat/mod.rs:123-133` — "Merge two NAT decisions,
preferring fields already set in self"), the arm copies the retained
(P1-carrying) decision into `pending_decision` and merges the fresh
allocation into it (`poll_descriptor/mod.rs:4662`, `:4745-4758`), so
the seed/buffer carry P1 while the allocator owns P2, and the
install-refusal rollback mismatches (`:4890-4909`,
`allocator.rs:1398-1404`). Master's OWN cold path has the
released-tuple reuse — the v10.12.0 "correct because master" premise
was false. The fold asserts PARITY and documents the purge-aftermath
family (warm forward micro-window, cold merge-keeps-P1, rollback
mismatch leak, reinjection P1) in §7 as pre-existing #6599-machinery
defects. The plan neither worsens nor claims to fix them; the
close-aware gate keeps closes out of the machinery entirely.

**r96-2 (B — close→ACK not end-state-equivalent).** Verified: FIN/RST
is cache-ineligible (`flow_cache.rs:354-394`), so without a rule the
ACK purges and caches the sessionless retained descriptor
(`poll_descriptor/mod.rs:3900-3959`), consulted before session
resolution (`:298-327`) with no idle TTL. The fold adds the ONE
hardening delta: the purging dispatch suppresses the flow-cache
insert for the retained decision. This is not the v10.10.0 no-cache
divergence r94-3 killed — that rule forced packet-two installs; this
one forces nothing (the next packet clean-misses and installs fresh,
converging to master's close-first end-state), and it is strictly
safer than master's own ACK-first pin (documented as pre-existing).
The cold-seed timeout-class delta (non-closing ~300 s transient vs
master's closing 2 s/30 s) is documented as transient-placeholder-only.

**r96-3 (B — RG-activation crossover).** Verified: RG activation makes
the purge predicate false (`promote.rs:48-59`), so the next non-close
materializes/promotes the conflicted retained row, republishing and
emitting Open for the conflicted P1 without retrying the reservation
(`promote.rs:99-139`, `session/mod.rs:1480-1530`). Documented in §7
with the root-cause pointer (#6600's reservation-failure propagation;
#6522's holder fence).

**r96-4 (H — bound straggler + cache outlives delete).** The §7
paragraph is rewritten whole: exact bound (non-close purge or the
peer's synchronized delete; no deadline on the shared row; no removal
at local expiry) plus the cache caveat (the delete does not invalidate
the cache — `session_import.rs:243-320` vs `flow_cache.rs:767-780`).

**r96-5 (B — in-place adopt's authority/accounting hazards).** The
in-place adopt is retracted: overdue-K now REMOVES K locally
(local-only discipline: no NAT release, no BPF delete, no delta) and
installs nothing. Every hazard Codex named needed machinery to keep
alive an already-due entry (atomic reindex
`session/mod.rs:1627-1663`; counted-class transition
`install.rs:434-447`/`session/mod.rs:1782-1821`/`:901-941`;
origin-authority `entry.rs:242-269`/`shared_ops.rs:897-916`) — removal
needs none of it. The packet forwards with S2's decision; the next
packet re-materializes fresh. The non-overdue adopt keeps the full
remove+reinstall upsert (which rebuilds indexes and transitions the
counted class correctly — stated).

**r96-6 (B — mutually exclusive requirements).** Reconciled: §5.6
site-3 tail, §9's three bullets, the triplicated "(d) a genuine
top-level" splice, §9's reservation dangling clause, and §11's
3(a)/3(c) are all rewritten to the master-split + suppression +
scoped-accounting text. The arm-head outcome naming (r96-7) is
`ExistingResolved`/`PurgedRetained`/`SeedEligible` with
`SeedInstalled`/`SeedRefused` as results.

## 2. Full-document consistency re-read

After six surgical passes I re-read every mutated paragraph end-to-end
(the adopt paragraph, the site-3 supplement, §5.2 (iv), the §7
residual, the §9 tests, §11) — they are coherent and name the same
mechanisms; the version tags inside paragraphs form an accurate audit
trail (the arc's established style). The gate (§5.1–§5.4, §5.7) is
untouched for the twelfth consecutive round.

## 3. Bottom line

The plan's departure list on the purge path is now: the close-aware
purge gate (unconditional retention), the purge-dispatch cache-insert
suppression (justified hardening, strictly safer than master), and
documentation of every pre-existing corner (purge-aftermath reuse,
import-window race, RG-activation crossover, cache pin family). PLAN
YES for v10.13.0.
