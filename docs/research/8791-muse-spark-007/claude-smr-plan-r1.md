# Claude SMR — hostile plan review r1

**Subject:** `docs/research/8791-muse-spark-007/plan.md` (DRAFT v1)
**Verdict:** **PLAN-KILL (as written)** — not because the plan is wrong, but
because the plan's own central finding makes the plan the wrong instrument.

---

## The objection that decides it: the plan delays a confirmed critical defect behind a triage process

The plan sequences finding 03 *first* — inside a triage framework that must first
converge through three reviewers. **I attacked finding 03 to try to break the
plan's one "verified" claim, and instead hardened it three ways.** It is not a
triage item.

**1. It is fatal, and `len=0` does not save it.** The obvious refutation — Go's
`make` with a huge *capacity* but zero *length* touches no pages, and Linux
overcommit will hand out the mapping — is wrong. Measured, on this host
(`overcommit_memory=0`, `MemTotal` 131 GB):

```
attempting make([]wire, 0, 4294967295) = 481036337040 bytes
fatal error: runtime: out of memory
runtime.sysMapOS(0x370643800000, 0x7000000000, ...)
```

`0x7000000000` = 481,036,337,152 bytes. The heuristic overcommit policy refuses a
448 GiB map outright.

**2. It is UNRECOVERABLE, which the source report understates.** My probe wrapped
the call in `defer func(){ recover() }()`. **The recover never fired** — a Go
runtime OOM is a `fatal error`, not a panic, and no recovery boundary anywhere in
the process can catch it. The report hedged: *"allocator rejection, makeslice
panic, runtime OOM, or extreme GC/memory pressure"* and separately noted "the
decoder runs in a goroutine without a recovery boundary." Both are too soft:
**adding a recovery boundary would not help.** This is unconditional process
death.

**3. It is reachable UNAUTHENTICATED.** `pkg/cluster/sync_conn_read.go`:

```go
if ac, ok := conn.(*authConn); ok && ac.readAuthed() {
    // ... read + verify HMAC trailer, drop connection on failure
}
s.handleMessage(conn, hdr.Type, payload)   // reached regardless
```

The verification is **conditional on the connection being a keyed `authConn`**.
On an unkeyed control link the frame reaches `handleMessage` unverified, and the
type-38 arm calls `decodePersistentNatLeasePayload(base)` on attacker bytes. The
`hdr.Length > 16*1024*1024` cap upstream is irrelevant: **the payload needs to be
four bytes.** The sequence gate (`admit(incarnation, seq)`) runs before the
decode and admits `(0,0)`.

**So: a 4-byte frame from any host reachable on an unkeyed HA control segment
kills xpfd unrecoverably, repeatably across reconnects, on both nodes.** The fix
is a two-line physical-count clamp on a cold path — the same clamp #7175 already
applied to the sibling DHCP decoder, which this function's own doc comment cites.

**A plan whose first act is to converge three reviewers before a two-line clamp
lands is the wrong shape.** Pull 03 out, fix it now under `/engineer`, and let the
plan govern the remaining 21.

## Second objection: the plan generalises from a biased sample

§2 justifies Gate B by citing four failures from *this team's own lanes today*.
That is the sample I have, and it is not the relevant population. Those four were
produced under campaign time pressure by agents optimising for throughput; the
external report has a stated independent-review gate, declined to pad to its
requested 100, and excluded 8 units for failing review. **Its base rate is
plausibly much better than my lanes', and I asserted otherwise without measuring
it.** Gate B may be right, but §2's argument for it is weak and should not be the
load-bearing justification.

Worse, it is self-serving in a specific way: I nearly declared this entire report
fabricated after reading a *filtered* rendering of it as if it were the file. My
instrument produced incoherence and I attributed it to the artifact. A plan
written immediately after that mistake, arguing that the external artifact needs
heavy verification, deserves suspicion about its motive.

## Third objection: one tracking issue actively hides a critical finding

§10 Q5 raises this and the plan then does it anyway. #8791 is titled *"Triage:
muse-spark-007 deep review — 22 verified Major findings"*. **Nothing in that title
or the board says "unauthenticated remote unrecoverable DoS on the HA control
plane."** The campaign goal of driving the board to zero is, exactly as Q5
suspects, corrupting the triage — and the plan names the hazard and then yields to
it. At minimum finding 03 needs its own issue with a title that says what it is.

## What survives

* **Gate A is sound and reproducible.** 22/22 at the report's base and 22/22 at
  current master, script committed. The freshness claim is real.
* **The "verified quote ≠ verified finding" distinction is correct**, even though
  §2's argument for its urgency is weak. It should stay, re-justified.
* **The HA shared-root-cause question (§10 Q6) is the highest-value open item.**
  01/02/11/16/17 all touch epoch/generation/snapshot handling; if they are one
  defect, four fix directions are wasted.
* **§6's "do not open 22 issues" and "do not batch fixes across areas"** are both
  right for the remaining 21.

## Required for PLAN-READY

1. **Remove finding 03 from the plan's scope.** File it as its own issue, titled
   as the unauthenticated remote DoS it is, and fix it under `/engineer` without
   waiting for this plan.
2. **Re-justify Gate B** on something other than four same-team failures — e.g.
   sample three findings at random, verify their mechanisms, and report the hit
   rate. That is a measurement rather than an analogy, and it directly answers
   §10 Q1 and Q2.
3. **State the reachability column per finding** (unauthenticated / authenticated
   peer / local operator / requires prior compromise). The plan asserts severity
   ordering without it, and 03 shows the column changes the answer.
