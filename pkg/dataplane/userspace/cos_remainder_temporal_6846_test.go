package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6846: the two forms #4228 Gap 2 left inert are resolved in the Rust builder
// (forwarding_build::cos), which can only resolve what the Go side HANDS it.
//
// The Rust cells pin the resolver. They cannot see this: a correct resolver
// that is never given the values behaves exactly like a broken one — the queue
// gets default sizing and no explicit rate either way, which is precisely the
// pre-fix behaviour this change removes. Found by the mutation matrix, where
// zeroing each field at the snapshot boundary escaped GREEN against the whole
// Go suite.
func TestCoSSnapshotCarriesRemainderAndTemporal6846(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClassOfService = &config.ClassOfServiceConfig{
		ForwardingClasses: map[string]*config.CoSForwardingClass{
			"real": {Name: "real", Queue: 3},
		},
		Schedulers: map[string]*config.CoSScheduler{
			"s1": {
				Name:                  "s1",
				TransmitRateRemainder: true,
				BufferSizeTemporalUS:  50000,
			},
		},
		SchedulerMaps: map[string]*config.CoSSchedulerMap{
			"sm": {Name: "sm", Entries: map[string]*config.CoSSchedulerMapEntry{
				"real": {ForwardingClass: "real", Scheduler: "s1"},
			}},
		},
	}

	// Guard the fixture before asserting on the snapshot: if the compiled
	// scheduler ever stopped carrying these, every assertion below would pass
	// over zero values and prove nothing.
	src := cfg.ClassOfService.Schedulers["s1"]
	if !src.TransmitRateRemainder || src.BufferSizeTemporalUS != 50000 {
		t.Fatalf("fixture broken: the source scheduler must carry both forms "+
			"(remainder=%t temporal=%d)", src.TransmitRateRemainder, src.BufferSizeTemporalUS)
	}

	snap := buildClassOfServiceSnapshot(cfg)
	if snap == nil {
		t.Fatal("buildClassOfServiceSnapshot returned nil for a populated CoS config")
	}
	var got *CoSSchedulerSnapshot
	for i := range snap.Schedulers {
		if snap.Schedulers[i].Name == "s1" {
			got = &snap.Schedulers[i]
		}
	}
	if got == nil {
		t.Fatal("scheduler s1 is missing from the snapshot")
	}
	if !got.TransmitRateRemainder {
		t.Error("#6846: TransmitRateRemainder must reach the wire — without it the " +
			"Rust resolver never sees a remainder queue, and the queue falls back to " +
			"exactly the pre-fix no-explicit-rate behaviour")
	}
	if got.BufferSizeTemporalUS != 50000 {
		t.Errorf("#6846: BufferSizeTemporalUS must reach the wire verbatim, got %d — "+
			"without it the queue falls back to default sizing, which is the pre-fix "+
			"behaviour this change removes", got.BufferSizeTemporalUS)
	}
}
