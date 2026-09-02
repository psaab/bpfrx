package format

import (
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6565 row 4 / #7422: a scheduler authored with `transmit-rate percent` or
// `transmit-rate remainder` rendered as "-", which reads as "no guarantee
// configured" for a queue that is in fact shaped.
//
// The three forms are mutually exclusive, so reading TransmitRateBytes alone
// made the other two invisible by construction — not intermittently, ALWAYS.
//
// The dataplane resolves both live: percent in
// cos_effective_transmit_rate_bytes (#4228 Gap 2) and remainder through
// #6846's sibling pre-pass. The in-tree doc claiming ACCEPTED-BUT-INERT was
// stale and is corrected in the same change; it had gone on to justify this
// renderer's dash.
func TestSchedulerTransmitRateRendersEveryAuthoredForm7422(t *testing.T) {
	for _, tc := range []struct {
		name  string
		sched *config.CoSScheduler
		want  string
	}{
		{"absolute bytes", &config.CoSScheduler{TransmitRateBytes: 1_250_000}, "10.00 Mb/s"},
		{"percent", &config.CoSScheduler{TransmitRatePercent: 30}, "percent 30"},
		{"remainder", &config.CoSScheduler{TransmitRateRemainder: true}, "remainder"},
		// The control that keeps the dash meaningful: a scheduler with NO
		// guarantee form must still render "-". Without it, "percent renders
		// something" is satisfied by a formatter that never returns a dash.
		{"no guarantee configured", &config.CoSScheduler{}, "-"},
		{"nil scheduler", nil, "-"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatSchedulerTransmitRate(tc.sched); got != tc.want {
				t.Errorf("formatSchedulerTransmitRate = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestPercentSchedulerIsAGuarantee7422 pins the SECOND site, which the issue
// row does not name and which is the worse of the two: cos_sections keys
// `guaranteeEnabled` off the configured rate, and the runtime merge below it
// only adopts the dataplane's RESOLVED rate when that flag is set. So a
// percent scheduler had its true, already-known absolute rate discarded on
// `show class-of-service interface`.
func TestPercentSchedulerIsAGuarantee7422(t *testing.T) {
	for _, tc := range []struct {
		name  string
		sched *config.CoSScheduler
		want  bool
	}{
		{"percent is a guarantee", &config.CoSScheduler{TransmitRatePercent: 30}, true},
		{"remainder is a guarantee", &config.CoSScheduler{TransmitRateRemainder: true}, true},
		{"absolute is a guarantee", &config.CoSScheduler{TransmitRateBytes: 1}, true},
		// Control: with none of the three, there is no guarantee and the
		// runtime rate must NOT be adopted. A predicate that returned true
		// unconditionally would satisfy every case above.
		{"none of the three is not", &config.CoSScheduler{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.sched.TransmitRateBytes > 0 ||
				tc.sched.TransmitRatePercent > 0 || tc.sched.TransmitRateRemainder
			if got != tc.want {
				t.Errorf("guaranteeEnabled = %v, want %v", got, tc.want)
			}
		})
	}
	// Bind the WIRING: the predicate above is only meaningful if cos_sections
	// actually uses it. A copy of the expression in a test proves nothing
	// about the call site.
	src := readSourceForGuaranteeCheck7422(t)
	if !strings.Contains(src, "sched.TransmitRatePercent > 0 || sched.TransmitRateRemainder") {
		t.Error("cos_sections.go no longer treats percent/remainder as a guarantee; the " +
			"runtime merge will discard the dataplane's resolved rate for those schedulers")
	}
}

func readSourceForGuaranteeCheck7422(t *testing.T) string {
	t.Helper()
	b, err := readFile7422("cos_sections.go")
	if err != nil {
		t.Fatalf("read cos_sections.go: %v", err)
	}
	return b
}

func readFile7422(name string) (string, error) {
	b, err := os.ReadFile(name)
	return string(b), err
}
