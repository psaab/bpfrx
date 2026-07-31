# Claude SMR hostile plan-review — round 93 (v10.9.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — thirteenth
pass. This round's fold is different in kind: r92-1/r92-2 were
adjudicated DOCUMENT + RE-SCOPE rather than fold-into-design, so the
review must attack the adjudication itself, not just the text. Verdict:
**PLAN YES**.

## 1. The re-scope adjudication, attacked

**r92-1 (B — close-awareness is not an absorbing provenance fence).**
Codex's trace: spoofed non-close SYN on the non-owner → purge
(`promote.rs:167-207`, `shared_ops.rs:960`) → re-entered miss →
`ForwardFlow` install (`poll_descriptor/mod.rs:2449`) → Open
(`install.rs:234`, fresh generation `sync_conn_write.go:53`) → peer's
latest-generation-wins overwrite (`sync_conn_gen.go:435`,
`session_store.go:257`). Every code step verified at the branch base.
The adjudication question: is this the plan's bug to fix?

For the re-scope: (a) every step is unmodified master machinery — the
plan's v10.4.1 re-entry is defined as "exactly as if the resolve had
returned None" for non-close packets, and master's post-purge path
(purge → resolve → ForwardCandidate install → Open) is step-for-step
identical; the trace fires on master TODAY with zero plan code. (b)
The driving packet carries no closing flags — the issue's class is the
blind-close demote, and a demote gate is definitionally uninvolved.
(c) No sequence-validation mitigation can apply: a SYN is the sequence
bootstrap, so the spoofer trivially knows the state it seeded — the
gate's information-theoretic basis (the attacker must GUESS placement)
does not exist for a self-seeded flow. (d) The real mitigations are
anti-spoof/ingress filtering (network layer) and identity-carrying
sync deltas (Phase 2, §10.5) — both out of this plan's mechanics.
(e) The arc's own precedent: #6522 — a pre-existing bug one step
removed from the plan's machinery — was re-scoped to its own issue at
the terminal cut.

Against the re-scope, steelmanned: the plan touches this path (the
close-aware purge), and shipping a "the RWoLB close kill is dead"
claim while a same-effort SYN kills the same victim could read as
security theater. The honest answer: the plan does NOT claim the RWoLB
SYN path is safe — §7 now documents the exposure verbatim with its
trace, #6599 carries bug+security, and the plan's claim is scoped to
what it closes (blind-close demotion + its HA propagation), which it
does close. Shipping the gate leaves #6599 exactly as bad as it is on
master today — no worse, and the gate's own correctness does not
depend on #6599 (once #6599 is fixed, the attacker-crafted flow's
teardown kills only attacker-seeded state — the composition is stated
in §7). Blocking the blind-close fix on a pre-existing sync-identity
redesign would be the unfold pattern the terminal cut was carved to
stop. The adjudication stands.

**r92-2 (H — shared-backed does not prove P1 reserved).** Verified:
import publishes shared first (`session_import.rs:115`/`:215`), the
reservation lands in the worker upsert (`upsert_synced.rs:64`/`:80`),
workers poll with an empty queue (`loop_body/mod.rs:682`/`:887`), and
the steal-refusal is silent (`allocator.rs:1636`/`:1682`). The race is
packet-class-agnostic on master (any packet forwarded on a
shared-backed decision in the window); the buffered close inherits it
without widening. Documented + #6600.

## 2. The LOW folds, verified

- r92-3: the encoding is now specified against the real fields
  (`session/mod.rs:349` stores `last_seen_ns`/`expires_after_ns`;
  `expire.rs:50` saturating-sum wheel): store `last_seen_ns = now_ns`,
  `expires_after_ns = D.saturating_sub(now_ns)` — the wheel re-derives
  D exactly; §9 tests K-wins AND S2-wins. The rule/oracle conflict is
  gone.
- r92-4: §9(a) now scopes byte-identity to the purge-target state
  (shared entry, P1 reservation, aliases), notes a buffered close
  never reaches `account_packet`, and makes transmission conditional
  on the pending-neighbor rules (4096-next-hop cap `afxdp/mod.rs:418`,
  ~2 s stale-buffer drop `neighbor_dispatch.rs:187`) with
  delivery-parity framing. All four cites verified.

## 3. Consistency sweep

- §7 residuals, §10.6.2 entries, §9 tests, §11 question 6, and the
  header history all name #6599/#6600 with the same scoping rationale.
- No design rule changed this round: v10.9.0 is documentation +
  encoding specification + test-oracle narrowing. The gate and the
  Part-B rules are byte-stable from v10.8.0.

## 4. Bottom line

Codex's r92 BLOCKER is a real and severe pre-existing exposure — filed
as #6599 with bug+security and documented in the plan with its full
trace — but it is not this issue's class, not this plan's code, and
not closable by anything this plan could contain. PLAN YES for
v10.9.0. The convergence question for Codex r93 is precisely the
re-scope; if Codex accepts it (or fails to trace a close-class path
through it), the arc is done.
