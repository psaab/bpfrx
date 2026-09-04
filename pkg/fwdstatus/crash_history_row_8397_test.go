package fwdstatus

import (
	"strings"
	"testing"
	"time"
)

// #8397: the crash-episode row must render for a HEALTHY helper.
//
// This is the cell that matters, and it is aimed at a mistake that was made and
// caught during implementation rather than at a hypothetical one.
//
// The crash block returns early on `!LastExitWasCrash && !RestartPending`,
// which is correct for every CURRENT-episode row. A history row placed after
// that guard renders in every case EXCEPT the one it was written for: history
// exists precisely for the helper that crashed repeatedly and is running now,
// and at that moment `restartHelperAfterCrash` has already wiped the record, so
// both flags are false.
//
// That failure is invisible to review and to a naive test. A clean crash
// surface is exactly what a healthy helper is supposed to look like, so a cell
// that only exercises the crashed state passes against both placements.

func renderFor8397(fs ForwardingStatus) string {
	var b strings.Builder
	writeHelperCrash(&b, &fs)
	return b.String()
}

func TestCrashEpisodeRowRendersForAHealthyHelper8397(t *testing.T) {
	oldest := time.Date(2026, 9, 4, 9, 30, 0, 0, time.UTC)
	fs := ForwardingStatus{
		HelperCrashKnown: true,
		// The post-recovery state: the record has been wiped, so BOTH flags are
		// false. This is the case the row exists for.
		LastExitWasCrash:          false,
		RestartPending:            false,
		HelperCrashEpisodes:       4,
		HelperCrashEpisodesOldest: oldest,
	}
	out := renderFor8397(fs)
	if !strings.Contains(out, "Helper crash episodes") {
		t.Fatalf("a helper that recovered from 4 crashes must still report them.\n"+
			"This is #8397's whole point: the record is wiped on recovery, so a "+
			"recurring crasher presents a spotless surface.\ngot:\n%s", out)
	}
	if !strings.Contains(out, "4 recovered in this daemon") {
		t.Errorf("the count must be rendered; got:\n%s", out)
	}
	if !strings.Contains(out, oldest.Format(time.RFC3339)) {
		t.Errorf("the retention window must be rendered so the count has a "+
			"denominator in time; got:\n%s", out)
	}
}

func TestCrashEpisodeRowAlsoRendersDuringALiveCrash8397(t *testing.T) {
	// The other side: a row that only rendered when healthy would be just as
	// wrong. Both states must carry it.
	fs := ForwardingStatus{
		HelperCrashKnown:    true,
		LastExitWasCrash:    true,
		HelperCrashEpisodes: 2,
	}
	out := renderFor8397(fs)
	if !strings.Contains(out, "2 recovered in this daemon") {
		t.Errorf("the history row must render during a live crash too; got:\n%s", out)
	}
}

func TestNoCrashEpisodeRowWhenThereIsNoHistory8397(t *testing.T) {
	// CONTROL. Without this, a row rendered unconditionally would satisfy both
	// cells above while adding a permanent "0 recovered" line to every healthy
	// box — noise in the block this issue explicitly did not want to grow.
	fs := ForwardingStatus{HelperCrashKnown: true, LastExitWasCrash: true}
	if out := renderFor8397(fs); strings.Contains(out, "Helper crash episodes") {
		t.Errorf("a daemon with no recovered episode must not render the row; got:\n%s", out)
	}
}

func TestCrashRowsStaySilentWhenCrashStateIsUnknown8397(t *testing.T) {
	// The outer gate is unchanged: a dataplane that cannot report crash state
	// renders nothing, including no history row.
	fs := ForwardingStatus{HelperCrashKnown: false, HelperCrashEpisodes: 9}
	if out := renderFor8397(fs); out != "" {
		t.Errorf("unknown crash state must render nothing at all; got:\n%s", out)
	}
}
