# Claude SMR r1 — #1752 plan v1 @ 75a21e4e5

**Verdict: PLAN-READY-WITH-MINORS.** This is a diagnosis-first research doc; the
findings are measured live (not asserted) and mostly honestly caveated. Two
real corrections below before it converges. Codex + AGY r1 pending.

## What holds up under hostile scrutiny

- **CoS attribution is methodologically sound on the CPU axis.** The ~19% is
  flat self-time summed from named `cos_*` symbols, and crucially crypto-DEK
  churn was present in *both* A/B arms — so the 16.0→23.4 delta is NOT
  confounded by crypto (it is a constant in both). The CoS symbols vanishing in
  the OFF profile is independent corroboration.
- **Crypto-DEK cost is measured; mechanism is correctly left as hypothesis.**
  The doc claims ~5.6% (measured, reproduced ×3 windows) but does NOT claim to
  know the caller — Path B step 1 is "trace the stack." That is the right
  epistemic posture; it does not overclaim.
- **Premise correction (6/6 = no headroom) is correct and important.** This
  reframes the user's question accurately.

## Correction 1 (MINOR) — lead with CPU%, caveat the 23.4 Gb/s

The CoS-OFF run hit 23.4 Gb/s **with 26,835 retransmits** vs ~1,469 in the CoS-ON
run. iperf3 sender Gb/s counts retransmitted bytes, so the *goodput* delta is
somewhat less than the headline 7.4 Gb/s — the unshaped arm was pushing into
loss. The firm number is the **~19% CPU self-time freed**; the Gb/s figure is
the (noisier) throughput consequence. §2/§3 should state the throughput delta as
"up to ~7.4 Gb/s gross, less in goodput" and anchor the claim on the CPU%.

## Correction 2 (MINOR) — make Path B non-invasive-first; move the strongSwan A/B off the HA node

§5 step 3 (stop strongSwan / flush xfrm on fw0) is invasive on an HA primary
with IPsec SA sync (Open Q4 flags this). Reorder so the **non-invasive perf
stack trace (step 1) is a hard gate**: only if it implicates strongSwan/xfrm do
we run the stop-A/B, and prefer the **standalone test VM** (or fw1 while fw0
holds RG-0) for the invasive arm, never the live primary. Drop the implication
that the stop-A/B is the default.

## On Path A (the kill-risk question, Open Q5)

#1207 and #1545 PLAN-KILLs were micro-opts (~1.5-3 KB code size, ~0.15% CPU) —
their cost/benefit died because the prize was tiny. A **19% / 7.4 Gb/s** prize
is a different order of magnitude; "CoS path was killed before" does NOT
transitively kill this. But the kills do warn that the path is hard. Correct
verdict: keep Path A alive as *its own future /research* (not prejudged dead),
but sequence Path B first because it is cheaper and de-noises the CoS numbers.
The doc already does this — do not let a reviewer over-rotate to Path D (pure
documentation) and discard a 7.4 Gb/s lever.

## Residual to watch

- `bpf_prog_*` (4.2-5.6% self) is *our* XDP program, lumped under "worker
  remainder" — it is arguably a 6th addressable cost center, partly under our
  control. Note it; don't let it hide inside the "inherent driver" bucket.
- The ~4.5% hashbrown session churn (Open Q6) is real and SW-addressable;
  worth keeping on the list even if lower priority than B.

Net: sound diagnosis, honest caveats, right recommended sequence. Fold the two
corrections and it is PLAN-READY.
