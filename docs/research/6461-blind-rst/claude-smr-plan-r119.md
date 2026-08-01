# Claude SMR hostile plan-review — round 119 (v10.34.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — thirty-
ninth pass; I authored the v10.34.0 fold of Codex r118's 4B/3H/1M/1L.
Verdict: **PLAN YES** (fold verification + hostile sweep below).

## 1. Fold verification (Codex r118)

**r118-1/2/7/9 (the discriminator swap).** Verified the swap's premises
against the code, not the fold text: `session_id` is write-once
(`session/mod.rs:460-470` — "Write-once — never re-stamped"); the
promote/refresh bodies (`session/mod.rs:1344-1432`, `:1642-1720`)
contain NO `session_id` write (grep-verified); `upsert_synced`
(`install.rs:322-351`) adopts the wire id and documents "0 is never a
real id (the allocator starts its counter at 1), so the sentinel is
unambiguous"; `alloc_session_id` (`session/mod.rs:784-789`) starts at 1
and guards the wrap. The swap dissolves r118-2's replication objection
by construction: siblings regenerate `install_epoch` per upsert
(`upsert_synced.rs:64-79`) but ADOPT the wire id, so the id binding is
replication-invariant and the unimplementable "atomic epoch update"
clause is gone from the doc (verified absent).

**The lazy-bind kill + producer (c).** The v10.33.0
bind-on-first-reciprocity rule is gone (verified absent; the only
"lazy bind" mention is the absorbing rule's prohibition). Producer (c)
— bind at the reverse entry's own synced→local promote — I attacked
four ways: (i) promote-before-forward-promote: R binds to the
still-synced F's adopted wire id; F's later promote preserves the id
(write-once), so the binding survives; (ii) the UpsertRefused-overwrite
case (promotion replaces unrelated local K with synced S2): R1 bound to
K's id mismatches S2's distinct id → suppress (correct — R1's family is
gone), and S2's own synced reverse promotes and binds to S2 on its
first hit; (iii) RG-activation bulk refresh (`refresh_for_ha_transition`,
`session/mod.rs:1642-1665`) does NOT bypass the bind point — it
re-stamps without changing origin, so the first reverse hit post-
activation still fires `maybe_promote_synced_session`
(`session_glue/promote.rs:99-139`) and binds there; before that first
hit no hops exist for the entry; (iv) active/active: an imported R on
an already-active node promotes on its first local hit (same path) and
binds — the never-promoted case exists only on a standby, which runs
no hops. The #6311 adopted-vs-local id-collision residual is stated in
the doc with the correct bound (reciprocity still gates cross-family;
a colliding id requires same canonical key AND same NAT = packet-
indistinguishable same-family, benign samples).

**r118-3 (source/transition split).** The token now reads `source`
(sticky, set at the match) vs `transition` (the final OUT) — the
materialize→promote chain (`shared_ops.rs:614-635`,
`session_glue/mod.rs:1194-1254`) can no longer erase the ForwardWire
no-anchor-learn marker. Size unchanged (95 B of fields, 96 B padded;
`Option` niche-fills on the 4-variant `MatchSource`); §9 asserts both
`size_of::<MatchedToken>() == 96` and `size_of::<Option<MatchedToken>>
() == 96` exactly (r118-8).

**r118-4 (capacity corner).** The inheritance restores master's own
invariant: on master, companion propagation marks BOTH entries at close
time, so a non-closing R against a closing F exists ONLY in this
capacity corner; seeding the late synth from the family's sticky state
is master's half-close semantics (continued traffic refreshes the
closing entry on the 30 s window, `lookup.rs:151-156`), not a new
state. I attacked the wrong-inheritance direction: `closing` on F is
set only by an ACCEPTED (validated) close under the gate, so the
inheritance never arms from a refused mark. The accounting fold gives
exactly one `rev` charge on F on both install outcomes
(`account_packet`'s absent-reverse return traced,
`session/mod.rs:1177-1210`).

**r118-5 (cache mechanics).** My v10.33.1 "no interleaving mutation /
same warm line" claim was wrong on both axes (admission is the
`:427-497`/`:507-548` egress stage; master's `:295-317` probes mutate
in between; and the canonical vs query key distinction breaks the
same-key claim for reverse/translated hits). The v10.34.0 text corrects
both: the compare-then-mutate rides master's `:295-317` borrows (zero
added probes at commit; the reverse case has the canonical forward
entry in hand via the `reverse_session_key` derive,
`session/mod.rs:1177-1210`), and the early check is one added
canonical-key probe per session-backed hit, warm only for plain
forward hits. I re-verified the `:137-290` consumer region contains no
session-table call (grep: only comments mention them).

**r118-6 (conjunctions + scoping).** The §5.2 proof definition now
states the closing exact-proving segment is read-only §5.4 evidence
(rules 1/5 dominate); the site-2b Shared-refuse sentence and the §9
test are scoped to CLOSE VALIDATION with the non-closing
master-verbatim half asserted; the closing-SYN-ACK paragraph branches
on OPENING vs ESTABLISHED forward state.

**r118-8/9.** §9 layout gates now exact for the token pair with
worst-case totals at the entry bounds (7.0 MiB/worker at 56 B; +416
KiB/binding at 104 B). The zero-epoch LOW is moot under the id swap
(the id allocator's skip-zero is the guarantee, cited).

## 2. Hostile sweep of v10.34.0

- grep sweeps: no `fwd_companion_epoch`/`MatchProvenance`/`install_
  epoch`-as-token-field references survive; no lazy-bind/breadcrumb
  text; §5.6 is epoch-free; the §3.1 second-window row's claim (no
  plan-cited file moved in `fff7a4ab5..b4605ea9d`) verified by
  `git diff --name-only` (the window touches coordinator/forwarding/
  types/dhcprelay/config tooling only).
- The token's id discriminator IMPROVES the cache-check false-eviction
  posture (a pure ownership promote no longer evicts); a NAT/
  orientation-changing `update_session` still evicts on those fields.
- The §5.5 scoping (reciprocity for the close mark; id binding for
  anchor learning) is stated at both remaining "no generation token"
  sites (§5.5 text + the §9 reverse-hit bullet).

## 3. Bottom line

PLAN YES for v10.34.0 as the round-119 review basis. The gate
(§5.1–§5.4, §5.7) is untouched for the thirty-fourth consecutive round;
all v10.34.0 edits are binding-mechanics, token-shape, capacity-corner,
and accounting text.
