# Claude SMR hostile plan-review — round 73 (plan v74 @ `ffa0b2970`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r72 pass
returned PLAN-READY on v73 while Codex r72 found the no-op stubs, the
L/F overlap, the `xdpEntryProg` trio race, and the detach
misclassification — my r72 facade audit verified the constructor shape
but not the trio's field access. Recorded. This pass attacks the v74
fold; all line numbers re-verified against the worktree.

## A. Fold verification (r72 findings → v74)

### 1. Codex M1 (partition closure) — FOLDED

Direct-access + delegation rule present; the three stubs
(`StartFIBSync`/`NotifyLinkCycle`/`SyncFabricState`, maps_fabric.go:72-76
— verified no-op bodies) join category L; the oracle split is honest
(AST = totality, runtime tests = outcomes, access audit = correctness —
no machine-proved disjointness claimed). FOLDED.

### 2. Codex M2 (xdpEntryProg trio) — FOLDED, with nit m1

The race is real exactly as Codex described (verified :105-120 plain
access, :154 Start-window write, :481/:947 status reads). The v74 fold
(m.mu protection + the trio joins the overlap set) is the right
mechanism — but see m1: as WRITTEN it deadlocks and misses a writer.

### 3. Codex M3 (detaches to category G) — FOLDED

Verified `DetachXDP` (:639) and `DetachTC` (:1131) read only the
construction-created link maps and return nil when empty; neither
touches `m.maps`/`m.programs`. Category G with the neutral no-link nil
preserved. FOLDED.

### 4. Codex m1/m2/m3 (residual, oracle wording, error contract) — FOLDED

§10 gains the `VlanSubInterfaces` race (verified: status reads
`maps_sync.go:950`; the write at `loader.go:201` sits inside
`CompileUserspaceShim`, an apply-time writer — so residual-izing it
while folding the trio is PRINCIPLED: the trio has a Start-window
writer (`LoadUserspaceShim` :154), `VlanSubInterfaces` does not; the
principled line is the Start window, stated). The class-3 oracle wording
and the `ErrDataplaneNotArmed` declaration contract are present.
FOLDED.

## B. Fresh attacks on the v74 delta

**Attack 1 (SUCCEEDED as nit m1) — the trio fold deadlocks as written
and misses a writer.** (a) `UsingUserspaceXDPShimEntryProgram`
(`loader.go:118-120`) CALLS `m.XDPEntryProgram()`; v74 says "all three
accessors lock" — two nested `m.mu` acquisitions on a non-reentrant
`sync.Mutex` deadlock. The fold must specify the locked-helper shape:
`XDPEntryProgram` locks and delegates to an internal unlocked
`xdpEntryProgramLocked()`; `Using...` locks once and calls the internal.
(b) There is a FOURTH access the fold misses: `loader.go:632`
(`m.xdpEntryProg = name` inside `SwapToUserspaceXDPShimEntryProgram`,
:604) — a public class-1 method writing the field; it must join the
`m.mu` set (or the field's atomicity rule) too. One clause in the A3
trio bullet. MINOR.

**Attack 2 (FAILED) — another plain Manager field in a RACE window.**
Swept the struct (loader.go:30-60): `programs`/`maps` (A3's core),
`xdpLinks`/`tcLinks` (category G, named hazards), `xdpEntryProg` (the
trio), `loaded` (atomic), `lastCompile`/`lastApply` (applySem/m.mu-
serialized by their writers), `PersistentNAT` (own RWMutex),
`VlanSubInterfaces` (§10 residual), `xdpFlagClaims` (applySem-serialized
attach path). No unsynchronized Start-written field remains. FAILED.

**Attack 3 (FAILED) — the delegation rule is ambiguous for a
delegator that ALSO directly accesses.** `ApplyConfig` (apply.go:237)
delegates to `Compile` and reads `m.lastCompile` only after — the
direct read is of construction/applySem state, not Start-state. No
mixed-case method in the set reads Start-state directly while also
delegating in a way the rule leaves unordered. FAILED.

**Attack 4 (FAILED) — the class-2 all-22 overlap is impractical.** The
22 entries are enumerated in the audit; driving each under the barrier
is mechanical. FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (1)

**m1.** The trio synchronization needs the locked-helper shape
(`Using...` calls `XDPEntryProgram`, `loader.go:118-120` — nested
`m.mu` deadlocks) and must cover the fourth writer (`loader.go:632`
inside `SwapToUserspaceXDPShimEntryProgram`). One clause in the A3
trio bullet.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v74 keeps PR-1 self-contained.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the locked-helper shape +
the fourth writer). A v75 containing only this pin is PLAN-READY by
inspection from me.
