package config_test

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6846 — the Go/Rust LEFTOVER AGREEMENT.
//
// `cosRemainderLeftoverIsPositive` (pkg/config) and `cos_remainder_rate_bytes`
// (userspace-dp/src/afxdp/forwarding_build/cos.rs) implement the same rule in
// two languages: subtract the resolved siblings from the interface shaping
// rate, count the remainder-marked queues, floor the split. Nothing shared
// computes it once — the Go side decides whether an operator is WARNED and the
// Rust side decides what the dataplane DOES — so the duplication is real and
// needs a guard.
//
// The guard asserts the AGREEMENT, not one side's literals: every row below is
// a Rust cell in `remainder_temporal_tests_6846` transcribed into Junos, and
// the expectation is derived from that cell's verdict. Advisory silent IFF the
// Rust resolver returns `Some`. If either side changes its arithmetic, the row
// whose two sides now disagree reds and names the Rust cell it mirrors.
//
// Not transcribable, and deliberately so: `a_scheduler_with_both_forms_is_not_a
// _remainder_queue` needs a scheduler carrying an absolute rate AND `remainder`,
// which the strict commit gate rejects. That shape is reachable only on the
// lenient load / peer-sync path, so it has no commit-time advisory to assert
// and is bound at the builder instead (build_cos_state_remainder_pre_pass_and_
// main_path_agree_on_the_divisor).
func TestRemainderAdvisoryTracksTheLeftover6846(t *testing.T) {
	remainderAdvisory := func(t *testing.T, lines ...string) string {
		t.Helper()
		for _, w := range config.ValidateConfig(mustCompileSet4228(t, lines...)) {
			if strings.Contains(w, "transmit-rate remainder is accepted but has no effect") {
				return w
			}
		}
		return ""
	}

	// A shaped interface bound to `sm`, shared by every row that needs a base.
	shaped := []string{
		"set class-of-service interfaces ge-0/0/0 scheduler-map sm",
		"set class-of-service interfaces ge-0/0/0 shaping-rate 100m",
	}
	with := func(lines ...string) []string {
		return append(append([]string{}, lines...), shaped...)
	}

	rows := []struct {
		name     string
		rustCell string
		lines    []string
		wantWarn bool
		// wantReason, when set, must appear in the advisory: the wording names
		// WHICH of the two reasons applies, and an operator's fix differs
		// between them. Asserting only "it warned" would let the two collapse.
		wantReason string
	}{
		{
			name:     "a percent sibling leaves a usable leftover",
			rustCell: "remainder_subtracts_resolved_percent_siblings",
			lines: with(
				"set class-of-service schedulers p transmit-rate percent 40",
				"set class-of-service schedulers r transmit-rate remainder",
				"set class-of-service scheduler-maps sm forwarding-class assured-forwarding scheduler p",
				"set class-of-service scheduler-maps sm forwarding-class best-effort scheduler r",
			),
			wantWarn: false,
		},
		{
			name:     "two remainder queues split what an absolute sibling left",
			rustCell: "cos_remainder_split_floors",
			lines: with(
				"set class-of-service schedulers a transmit-rate 1m",
				"set class-of-service schedulers r1 transmit-rate remainder",
				"set class-of-service schedulers r2 transmit-rate remainder",
				"set class-of-service scheduler-maps sm forwarding-class assured-forwarding scheduler a",
				"set class-of-service scheduler-maps sm forwarding-class best-effort scheduler r1",
				"set class-of-service scheduler-maps sm forwarding-class expedited-forwarding scheduler r2",
			),
			wantWarn: false,
		},
		{
			name:     "a remainder sibling claims nothing, so it cannot exhaust the rate",
			rustCell: "a_remainder_sibling_contributes_zero_to_the_claim",
			lines: with(
				"set class-of-service schedulers r1 transmit-rate remainder",
				"set class-of-service schedulers r2 transmit-rate remainder",
				"set class-of-service scheduler-maps sm forwarding-class best-effort scheduler r1",
				"set class-of-service scheduler-maps sm forwarding-class expedited-forwarding scheduler r2",
			),
			wantWarn: false,
		},
		{
			name:     "siblings claiming the WHOLE rate leave nothing to resolve",
			rustCell: "zero_leftover_must_not_resolve",
			lines: with(
				"set class-of-service schedulers p60 transmit-rate percent 60",
				"set class-of-service schedulers p40 transmit-rate percent 40",
				"set class-of-service schedulers r transmit-rate remainder",
				"set class-of-service scheduler-maps sm forwarding-class assured-forwarding scheduler p60",
				"set class-of-service scheduler-maps sm forwarding-class expedited-forwarding scheduler p40",
				"set class-of-service scheduler-maps sm forwarding-class best-effort scheduler r",
			),
			wantWarn:   true,
			wantReason: "leaving no usable leftover",
		},
		{
			name:     "over-subscribed siblings leave less than nothing",
			rustCell: "over_subscription_is_unresolvable",
			lines: with(
				"set class-of-service schedulers p90 transmit-rate percent 90",
				"set class-of-service schedulers q90 transmit-rate percent 90",
				"set class-of-service schedulers r transmit-rate remainder",
				"set class-of-service scheduler-maps sm forwarding-class assured-forwarding scheduler p90",
				"set class-of-service scheduler-maps sm forwarding-class expedited-forwarding scheduler q90",
				"set class-of-service scheduler-maps sm forwarding-class best-effort scheduler r",
			),
			wantWarn:   true,
			wantReason: "leaving no usable leftover",
		},
		{
			name:     "no shaping base at all",
			rustCell: "no_shaping_rate_is_unresolvable",
			lines: []string{
				"set class-of-service schedulers r transmit-rate remainder",
				"set class-of-service scheduler-maps sm forwarding-class best-effort scheduler r",
				"set class-of-service interfaces ge-0/0/0 scheduler-map sm",
			},
			wantWarn:   true,
			wantReason: "not bound via a scheduler-map to an interface with a root shaping-rate",
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got := remainderAdvisory(t, row.lines...)
			switch {
			case row.wantWarn && got == "":
				t.Fatalf("no remainder advisory, but %s says this leftover does not "+
					"resolve — the queue is inert at runtime and the operator is told "+
					"nothing", row.rustCell)
			case !row.wantWarn && got != "":
				t.Fatalf("remainder advisory fired for a shape %s resolves:\n  %s\n"+
					"an advisory that keeps firing for a configuration that now works "+
					"teaches the operator to ignore it", row.rustCell, got)
			}
			if row.wantReason != "" && !strings.Contains(got, row.wantReason) {
				t.Fatalf("advisory does not name the reason %q, so the operator cannot "+
					"tell which fix applies:\n  %s", row.wantReason, got)
			}
		})
	}
}

// The FLOOR is where the two implementations are most likely to drift: a
// leftover that is positive but smaller than the number of remainder queues
// divides to zero, and zero is the dataplane's "unshaped" sentinel rather than
// a rate.
//
// Split out of the table above because it needs a shaping rate and an absolute
// sibling chosen to leave exactly one byte/sec — a fixture the readable rows
// cannot carry. 100m is 12_500_000 B/s; an absolute sibling of 99_999_992 bps
// is 12_499_999 B/s, so two remainder queues split 1 byte and floor to nothing.
//
// A guard that used an evenly-divisible leftover here would pass whether the
// implementation floored, ceiled, or distributed the slack.
func TestRemainderLeftoverThatFloorsToZeroStillWarns6846(t *testing.T) {
	// PAIRED, because a lone "it warned" cell shows only correlation: an
	// implementation that answered "does not resolve" for every near-exact
	// subscription would satisfy it. The two rows differ by ONE byte/sec of
	// leftover — 1 floors to nothing, 2 floors to 1 — so only a real floor
	// separates them.
	for _, row := range []struct {
		absoluteBPS string
		leftover    string
		wantWarn    bool
	}{
		{absoluteBPS: "99999992", leftover: "1 B/s across 2 queues -> 0", wantWarn: true},
		{absoluteBPS: "99999984", leftover: "2 B/s across 2 queues -> 1", wantWarn: false},
	} {
		t.Run(row.leftover, func(t *testing.T) {
			warned := false
			for _, w := range config.ValidateConfig(mustCompileSet4228(t,
				"set class-of-service schedulers a transmit-rate "+row.absoluteBPS,
				"set class-of-service schedulers r1 transmit-rate remainder",
				"set class-of-service schedulers r2 transmit-rate remainder",
				"set class-of-service scheduler-maps sm forwarding-class assured-forwarding scheduler a",
				"set class-of-service scheduler-maps sm forwarding-class best-effort scheduler r1",
				"set class-of-service scheduler-maps sm forwarding-class expedited-forwarding scheduler r2",
				"set class-of-service interfaces ge-0/0/0 scheduler-map sm",
				"set class-of-service interfaces ge-0/0/0 shaping-rate 100m",
			)) {
				if strings.Contains(w, "transmit-rate remainder is accepted but has no effect") {
					warned = true
				}
			}
			switch {
			case row.wantWarn && !warned:
				t.Fatal("#6846: a 1 B/s leftover split across two remainder queues " +
					"floors to zero, the dataplane declines a zero share, and the " +
					"queues stay inert — so the advisory must fire. Answering " +
					"`resolves` here suppresses the warning on a config that does nothing")
			case !row.wantWarn && warned:
				t.Fatal("#6846: a 2 B/s leftover gives each remainder queue 1 B/s — " +
					"tiny, but resolved. Warning here would mean the predicate is " +
					"rejecting near-exact subscription generally rather than the floor, " +
					"and the row above would prove nothing")
			}
		})
	}
}
