# #7494 — consuming the #6704 non-first-fragment sighting

**Status:** the IPv4 half is IMPLEMENTED; the IPv6 half is blocked on headroom.
Every shape below carries a measured figure or is explicitly marked unmeasured.

**§6 was rewritten after its original recommendation was measured WRONG.** It
recommended a guard at the branch point. That guard is structurally incapable
of fixing exposure #5, and a reader who followed it would have built the wrong
thing and measured it as a success.

**Base:** master `3e91d4ae0`. The shim is unchanged from `35399d2b3`, so every
number here is current for both.

## 0. The premise the issue was filed on has moved

The body's matrix was measured at `9e28d1c25`, **1836 commits** before this
plan. It recorded a 777,901-instruction baseline and 22.21% headroom.

| | body (`9e28d1c25`) | HEAD |
|---|---|---|
| processed insns | 777,901 | **801,448** |
| headroom vs the 1M cap | 22.21% | **19.86%** |
| **usable slack** (vs the 850,000 ceiling) | 72,099 | **48,552** |

The third row is the one that matters and the issue never had it. `shimverify`
exits **4** below the 15% floor and `build-userspace-xdp.sh` admits only exit 0
as a measured pass, so the install-blocking ceiling is **850,000**, not
1,000,000. Reading the headroom percentage against the cap overstates the
available room by 4.09x at HEAD. A shape that "fits under 1M" can still be
unshippable.

## 1. The instrument is bit-for-bit reproducible

Every delta below is attributable because the control was established first,
and independently three times: master built in two separate worktrees returned
**801,448** both times, and the object `make generate` emitted was byte-identical
to the tracked object built earlier by someone else
(`06bdcc84c4ac43afdaca07fb2957be79f69a8bf55db5fd9a506064f2457babf3`). Two
different source texts differing only in comments, identical counts, identical
bytes. **The noise floor is zero**, so a delta of a few thousand instructions is
signal rather than jitter.

All runs: real kernel verifier via `make generate` → `shimverify`, toolchain
`nightly-2026-05-23` / `bpf-linker 0.10.2`. No `XPF_SHIM_ALLOW_LOW_HEADROOM`
override was used anywhere; rc=6 would not be a measured pass.

## 2. Measured shapes

| # | shape | insns | verdict |
|---|---|---|---|
| C | **control** — unmodified master | 801,448 | PASS — 19.86%, 48,552 slack |
| A | carry the flag as a `ParsedPacket` field, **never read** | 1,000,001 | **REJECT** |
| B4 | **re-derive at the branch point, IPv4** — one masked load | **805,941** | **PASS — 19.41%, 44,059 slack** |
| B6 | …the same, plus IPv6 — re-run the ext-header walk | 1,000,001 | **REJECT** |

Shape A re-confirms the body's row 4 at HEAD with a control the original
measurement did not have. Three lines, nothing reads the field, and it costs
**≥198,552 instructions**.

**Shape B4 is the result: the IPv4 half is not blocked. It costs 4,493
instructions**, about 9% of the slack that exists.

## 3. The mechanism, which explains all four rows

Cost is not tracking work done. It tracks whether the fragment predicate
becomes correlated with state the verifier must carry across branches.

- the body's row 5 — fork the session block with an **empty** arm — 784,175,
  *identical to row 1*. A branch on the flag is free.
- the body's row 3 — mask two `u16`s — >1,000,000.
- shape A — one **unread** `bool` on the struct — >1,000,000. There was no work
  to pay for; widening the struct was sufficient.

Verifier diagnostics for shape A: `total_states 54787 peak_states 3684`. This
is state explosion, not a budget overrun.

The tree has paid for this lesson once already, at `lib.rs:560` (#1864):
`saturating_sub` lowering into a materialised-boolean re-branch **defeated state
pruning and took both cluster dataplanes down**.

**Consequence: "recover headroom elsewhere" does not address this issue.** A
linear saving cannot pay down a superlinear explosion. That option should be
closed on mechanism, not on arithmetic.

Shape B4 fits *because* re-derivation is a leaf computation that gates control
flow and nothing else. Carrying one bool costs >198,000; re-deriving the same
bit costs 4,493. Same information, three orders of magnitude apart.

## 4. Rejected shapes, with reasons

**R1 — have `parse_ipv6` return `None` for a non-first fragment.** No new field,
no correlation, so none of §3 applies. **It is a DROP:**

```rust
let Some(parsed) = parsed else {
    return drop_degraded_transit(ctrl, USERSPACE_FALLBACK_REASON_PARSE_FAIL);
};
```

This blackholes every legitimate fragment — IPv6 fragmentation, large DNS
responses, tunnelled traffic. It reads as the cheapest option on the board.
**It would also gate clean**, because no test in the tree asserts that a
fragment survives a path that has never produced one.

**R2 — hoisting the B4 guard into the existing condition.** Measured at 805,394
and **passes the verifier**:

```rust
if !native_gre && !ipv4_non_first_fragment(...) {   // WRONG
```

When `native_gre` is false and the packet *is* a fragment, the condition is
false and control enters the `else` — the **native-GRE inner classifier**. Every
non-native-GRE IPv4 fragment gets GRE-classified. Nesting the guard inside the
`!native_gre` arm costs 547 more instructions and is correct; that is the
difference between B4 (805,941) and this (805,394).

**Both versions pass the gate identically.** The verifier gate is a headroom
instrument, not a correctness one. On this issue it is doing so much work that
a PASS reads as validation, and R1 and R2 are both cases where it would not be.

