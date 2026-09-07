package userspace

import "sync/atomic"

// bindingWedgeGiveups counts the times bounded auto-rebind exhausted its
// attempt budget and STOPPED trying to recover a wedged XSK binding.
//
// #9043: this arm had no counter, and its own give-up message states why that
// matters more here than almost anywhere else:
//
//	"the affected queues will not forward and no readiness signal reports them"
//
// Per #8384 binding readiness cannot see a bound-but-dead queue, so once
// automatic recovery gives up there is NO other signal that anything is wrong.
// A single `slog.Error`, emitted exactly once per wedge by design, was the
// whole of it — and a log line that fires once is the hardest kind to alert on:
// it is gone from a ring buffer by the time anyone looks, and its absence is
// indistinguishable from a box that never wedged.
//
// The counter does not fix the blind spot; it makes the GIVE-UP state
// observable, which is the difference between an operator who can ask "is any
// queue in this state" and one who has to already suspect it.
//
// The blind spot itself — the box-wide `xskLivenessProven` masking split out of
// #9043 — was closed by #9331, which removed that flag from the wedge
// predicate. This counter is what keeps the newly-detected wedges observable
// once recovery exhausts its budget on them, and
// `TestTheGiveupCounterMovesForAPreviouslyMaskedWedge9331` binds the two
// together.
var bindingWedgeGiveups atomic.Uint64

// BindingWedgeGiveups reports the process-lifetime count of auto-rebind
// give-ups, for the Prometheus collector.
func BindingWedgeGiveups() uint64 { return bindingWedgeGiveups.Load() }

// noteBindingWedgeGiveup records one give-up. Called from the same branch as
// the give-up log so the two cannot drift: a counter incremented on a
// different condition than the message it accompanies is worse than no counter,
// because the number then describes something other than what the operator
// reads next to it.
func noteBindingWedgeGiveup() { bindingWedgeGiveups.Add(1) }
