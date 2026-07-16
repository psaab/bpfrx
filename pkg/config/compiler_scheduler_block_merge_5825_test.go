package config_test

// #5825: repeated hierarchical `schedulers scheduler <name> { ... }` blocks are
// distinct AST instances. compileSchedulers used to allocate a FRESH
// SchedulerConfig per instance and unconditionally `cfg.Schedulers[name] = sched`,
// so a later same-name block REPLACED the earlier — every day/window authored in
// the earlier block(s) vanished. Flat `set` composes into ONE path, so
// hierarchical and flat diverged. A policy time-gated by the scheduler then
// became active/inactive on the WRONG days with a clean commit (security).
//
// The fix REUSES the existing map entry so distinct weekday windows UNION across
// blocks (and across separate top-level `schedulers {}` roots), matching flat-set
// semantics. Daily/date scalars follow flat-set / Junos load-merge last-wins.
//
// FAIL-ON-REVERT: restoring the fresh-alloc + unconditional overwrite makes the
// second block replace the first — the merge test below sees ONLY the last
// block's day and goes RED.

import (
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func schedDays(sc *config.SchedulerConfig) []string {
	if sc == nil {
		return nil
	}
	days := make([]string, 0, len(sc.Days))
	for d := range sc.Days {
		days = append(days, d)
	}
	sort.Strings(days)
	return days
}

func getScheduler(t *testing.T, cfg *config.Config, name string) *config.SchedulerConfig {
	t.Helper()
	sc := cfg.Schedulers[name]
	if sc == nil {
		t.Fatalf("scheduler %q missing from compiled config", name)
	}
	return sc
}

// twoBlockSchedHier: block 1 defines the monday + tuesday windows, block 2 (SAME
// scheduler name) defines wednesday. Pre-fix, only wednesday survives.
const twoBlockSchedHier = `schedulers {
    scheduler S {
        monday {
            start-time 08:00:00;
            stop-time 12:00:00;
        }
        tuesday {
            start-time 09:00:00;
            stop-time 17:00:00;
        }
    }
    scheduler S {
        wednesday {
            start-time 10:00:00;
            stop-time 18:00:00;
        }
    }
}
`

// Acceptance: weekdays split across two hierarchical blocks all survive on ONE
// scheduler, with each day's window intact.
func TestSchedulerHierarchicalBlocksMergeDays_5825(t *testing.T) {
	cfg := compileHier(t, twoBlockSchedHier)
	sc := getScheduler(t, cfg, "S")

	if got := schedDays(sc); len(got) != 3 || got[0] != "monday" || got[1] != "tuesday" || got[2] != "wednesday" {
		t.Fatalf("day windows split across two blocks must MERGE onto one scheduler, got %v "+
			"(the earlier block's days were dropped by last-writer replacement) — #5825", got)
	}
	if w := sc.Days["monday"]; w == nil || w.StartTime != "08:00:00" || w.StopTime != "12:00:00" {
		t.Fatalf("block-1 monday window must survive, got %+v", sc.Days["monday"])
	}
	if w := sc.Days["tuesday"]; w == nil || w.StartTime != "09:00:00" || w.StopTime != "17:00:00" {
		t.Fatalf("block-1 tuesday window must survive, got %+v", sc.Days["tuesday"])
	}
	if w := sc.Days["wednesday"]; w == nil || w.StartTime != "10:00:00" || w.StopTime != "18:00:00" {
		t.Fatalf("block-2 wednesday window must survive, got %+v", sc.Days["wednesday"])
	}
}

// Acceptance: the two-block hierarchical form compiles to the SAME typed schedule
// as the equivalent flat `set` commands (which already compose under one path).
func TestSchedulerHierarchicalEqualsFlatSet_5825(t *testing.T) {
	hCfg := compileHier(t, twoBlockSchedHier)
	fCfg := compileFlat(t,
		"set schedulers scheduler S monday start-time 08:00:00",
		"set schedulers scheduler S monday stop-time 12:00:00",
		"set schedulers scheduler S tuesday start-time 09:00:00",
		"set schedulers scheduler S tuesday stop-time 17:00:00",
		"set schedulers scheduler S wednesday start-time 10:00:00",
		"set schedulers scheduler S wednesday stop-time 18:00:00",
	)
	h := getScheduler(t, hCfg, "S")
	f := getScheduler(t, fCfg, "S")

	hd, fd := schedDays(h), schedDays(f)
	if len(hd) != len(fd) {
		t.Fatalf("hierarchical vs flat day set diverged: %v vs %v", hd, fd)
	}
	for i := range hd {
		if hd[i] != fd[i] {
			t.Fatalf("hierarchical vs flat day set diverged: %v vs %v", hd, fd)
		}
		hw, fw := h.Days[hd[i]], f.Days[fd[i]]
		if hw.StartTime != fw.StartTime || hw.StopTime != fw.StopTime ||
			hw.AllDay != fw.AllDay || hw.Exclude != fw.Exclude {
			t.Fatalf("day %s window diverged hierarchical vs flat: %+v vs %+v", hd[i], hw, fw)
		}
	}
}

// Cross-root: two SEPARATE top-level `schedulers {}` roots (each a distinct
// compileSchedulers call) defining the same scheduler S must still merge — the
// reused persisted map entry composes across roots. (Acceptance: "repeated
// top-level roots".)
func TestSchedulerAcrossRootsMergeDays_5825(t *testing.T) {
	const src = `schedulers {
    scheduler S {
        monday {
            start-time 08:00:00;
            stop-time 12:00:00;
        }
    }
}
schedulers {
    scheduler S {
        wednesday {
            start-time 10:00:00;
            stop-time 18:00:00;
        }
    }
}
`
	cfg := compileHier(t, src)
	sc := getScheduler(t, cfg, "S")
	if got := schedDays(sc); len(got) != 2 || got[0] != "monday" || got[1] != "wednesday" {
		t.Fatalf("day windows across SEPARATE top-level schedulers roots must MERGE, got %v — #5825", got)
	}
	if sc.Days["monday"].StartTime != "08:00:00" || sc.Days["wednesday"].StartTime != "10:00:00" {
		t.Fatalf("cross-root windows lost their times: %+v", sc.Days)
	}
}

// A daily window plus a per-weekday override across two blocks both survive
// (daily scalar + weekday list compose onto the reused scheduler).
func TestSchedulerDailyPlusWeekdayMerge_5825(t *testing.T) {
	const src = `schedulers {
    scheduler S {
        daily {
            start-time 09:00:00;
            stop-time 17:00:00;
        }
    }
    scheduler S {
        saturday {
            all-day;
        }
    }
}
`
	cfg := compileHier(t, src)
	sc := getScheduler(t, cfg, "S")
	if !sc.Daily || sc.StartTime != "09:00:00" || sc.StopTime != "17:00:00" {
		t.Fatalf("block-1 daily window must survive the merge, got Daily=%v %s-%s",
			sc.Daily, sc.StartTime, sc.StopTime)
	}
	if w := sc.Days["saturday"]; w == nil || !w.AllDay {
		t.Fatalf("block-2 saturday all-day override must survive, got %+v", sc.Days["saturday"])
	}
}

// Acceptance: a single block is unchanged — one scheduler, its days intact.
func TestSchedulerSingleBlockUnchanged_5825(t *testing.T) {
	const src = `schedulers {
    scheduler Solo {
        monday {
            start-time 08:00:00;
            stop-time 12:00:00;
        }
    }
}
`
	cfg := compileHier(t, src)
	sc := getScheduler(t, cfg, "Solo")
	if got := schedDays(sc); len(got) != 1 || got[0] != "monday" {
		t.Fatalf("single-block scheduler days changed: %v", got)
	}
	if w := sc.Days["monday"]; w == nil || w.StartTime != "08:00:00" || w.StopTime != "12:00:00" {
		t.Fatalf("single-block monday window changed: %+v", sc.Days["monday"])
	}
}
