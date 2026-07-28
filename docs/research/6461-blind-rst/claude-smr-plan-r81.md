# Claude SMR hostile plan-review — round 81 (v9.9.54.35 @ 7123e853a)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.35 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.35-as-committed** — six precision pins (all nit-level; no
LOW or above). All seven r80 Codex folds are operative; the
lookup-generation capture, the active-copy selector, the counted
predecessor vector, the floor ACK digest, the shared preflight,
and the backfill verify against the code citations.

## Finding 1 (nit — the capture is one consistent read, or the entry's embedded generation detects the tear)

The B1 fold's lookup-generation capture needs its own consistency
rule: if the clone path (`shared_ops.rs:482`) is lock-free (atomic
loads), the entry load and the generation load can tear (entry
from G+1, generation read as G). State: the capture is either
under the same lock/RCU section as the clone, or the entry's OWN
embedded generation is compared against the captured drain
generation — a mismatch is a detected tear and the packet retries
(never proceeds on a mismatched pair).

## Finding 2 (nit — the checksum is the propagation-window guard, and the fallback is fail-closed-to-B)

The B2 fold's selector-then-copy two-load read has a cross-CPU
propagation window: a reader can see the selector's new value
(pointing at A) before A's data lands on its CPU. The checksum IS
the guard — a checksum computed over not-yet-visible data FAILS —
and the rule must be stated: on a selected-copy checksum failure
the reader falls back to the OTHER copy (old but complete), never
to a retry loop and never to the unchecked payload.

## Finding 3 (nit — the frame-size bound and the chunked-vector reassembly rule)

The B3 fold's counted predecessor vector needs its size discipline:
the NOTICE-plus-vector frame is bounded by the sync protocol's max
frame size; a merge whose vector approaches the bound is CHUNKED;
and a chunked vector is REASSEMBLED BEFORE application (the
replacement's atomicity lives at the logical-vector level — the
ACK covers the reassembled whole, never a fragment).

## Finding 4 (nit — the digest input is canonically sorted and domain-separated)

The H4 fold's `vector_digest` needs two one-liners: the digest's
input is the CANONICAL ascending-sorted `(rg_id, rg_incarnation,
contiguous_high_water)` vector (the merge is order-insensitive —
a differently-ordered same-set vector must digest identically);
and the digest's domain tag is distinct from the `scope_hash` tag
and the transcript's tags (no cross-construction collision is
possible by construction).

## Finding 5 (nit — ONE mint mechanism: the candidate-bound token, re-validated inside the promotion's lock domain)

The H6 fold offers an operative CHOICE again (token revalidation
OR hold-through). Pick one and kill the other: the candidate-bound
monotone token (binding the candidate's config generation AND
content hash), re-validated INSIDE the promotion's own lock
domain (the same lock the promotion takes — no gap between
revalidation and promotion); the hold-through alternative is
retracted (a lease held across a potentially-slow promotion can
itself expire mid-promotion — the token is the self-consistent
form).

## Finding 6 (nit — the backfill's first runtime adoption is free; only a later divergence pays the transaction)

The H7 fold's backfill needs its adoption rule for the peer's
existing runtime RG: the peer's runtime RG3 exists with NO
incarnation; the config arrives carrying I — the FIRST adoption
is a straight assignment (there is nothing to mismatch), and only
a LATER divergence (a second, different incarnation arriving for
the same runtime RG) pays the quiesced remove/re-add transaction.

## Bottom line

The v9.9.54.35 fold set closes the r80 set in the prescribed
direction; the transfer CAS, the selector, and the counted vector
are the first folds in their mechanisms that are total by
construction rather than by ordering. This is the second
consecutive all-nit SMR round. The remaining pins are the same
class as the last three rounds: state the invariant that makes
the fold auditable. Whether the reviewers read this as
convergence or as Zeno's plan-doc, every pin above is one
sentence and none opens a new mechanism.
