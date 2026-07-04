package config_test

// #3860: a scheduler that defines NO effective window (empty `scheduler x {}`
// or a bare `daily;` — no start/stop time, no all-day, no per-day arm, no
// start/stop calendar date) resolves to fail-closed INACTIVE at runtime after
// the #3849/#3858 flip away from the old always-on bug. That direction is
// safe, but an operator migrating a config that relied on the always-on bug
// loses enforcement silently, so ValidateConfig must emit a commit-time
// WARNING naming the scheduler. A scheduler carrying ANY window (daily/weekday
// time-of-day arm, all-day, or a start/stop date range) must NOT warn.
//
// RED-on-revert: dropping the warning loop in ValidateConfig makes the
// no-window cases below fire zero warnings and TestSchedulerNoWindowWarns goes
// RED (want-warning assertions fail).

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// schedulerNoWindowWarnings returns the subset of ValidateConfig warnings that
// concern a scheduler with no effective window.
func schedulerNoWindowWarnings(cfg *config.Config) []string {
	var got []string
	for _, w := range config.ValidateConfig(cfg) {
		if strings.HasPrefix(w, "scheduler ") && strings.Contains(w, "defines no time window") {
			got = append(got, w)
		}
	}
	return got
}

func TestSchedulerNoWindowWarns(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *config.Config
		wantWarn  bool
		wantNamed string // scheduler name expected in the warning text
	}{
		{
			name:      "empty scheduler body",
			cfg:       compileHier(t, "schedulers {\n    scheduler idle {\n    }\n}"),
			wantWarn:  true,
			wantNamed: "idle",
		},
		{
			name:      "bare daily flag, no window",
			cfg:       compileHier(t, "schedulers {\n    scheduler dailyflag {\n        daily;\n    }\n}"),
			wantWarn:  true,
			wantNamed: "dailyflag",
		},
		{
			name:      "empty scheduler via flat set",
			cfg:       compileFlat(t, "set schedulers scheduler flatidle"),
			wantWarn:  true,
			wantNamed: "flatidle",
		},
		{
			name: "daily time window does not warn",
			cfg: compileHier(t, "schedulers {\n    scheduler biz {\n        daily {\n"+
				"            start-time 09:00:00;\n            stop-time 17:00:00;\n        }\n    }\n}"),
			wantWarn: false,
		},
		{
			name:     "daily all-day does not warn",
			cfg:      compileHier(t, "schedulers {\n    scheduler always {\n        daily all-day;\n    }\n}"),
			wantWarn: false,
		},
		{
			name: "weekday arm does not warn",
			cfg: compileHier(t, "schedulers {\n    scheduler wd {\n        monday {\n"+
				"            start-time 08:00:00;\n            stop-time 12:00:00;\n        }\n    }\n}"),
			wantWarn: false,
		},
		{
			name: "date range only does not warn",
			cfg: compileHier(t, "schedulers {\n    scheduler dated {\n"+
				"        start-date 2026-03-01;\n        stop-date 2026-03-31;\n    }\n}"),
			wantWarn: false,
		},
		{
			name: "legacy start/stop-time does not warn",
			cfg: compileFlat(t,
				"set schedulers scheduler legacy start-time 09:00:00",
				"set schedulers scheduler legacy stop-time 17:00:00"),
			wantWarn: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := schedulerNoWindowWarnings(tc.cfg)
			if tc.wantWarn {
				if len(got) == 0 {
					t.Fatalf("expected a no-window warning, got none")
				}
				joined := strings.Join(got, "\n")
				if !strings.Contains(joined, "\""+tc.wantNamed+"\"") {
					t.Errorf("warning does not name scheduler %q: %q", tc.wantNamed, joined)
				}
				if !strings.Contains(joined, "INACTIVE") {
					t.Errorf("warning does not state INACTIVE behavior: %q", joined)
				}
			} else if len(got) != 0 {
				t.Errorf("unexpected no-window warning(s): %q", got)
			}
		})
	}
}
