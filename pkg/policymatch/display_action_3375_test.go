package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestDisplayActionSSOT pins #3375: DisplayAction is the single operator-facing
// verdict renderer shared by the REST and gRPC match-policies surfaces, so the
// transports cannot diverge. It must never return a blank string — the bug
// #3375 fixed was the gRPC surface emitting an EMPTY action for the
// host-inbound and default-deny verdicts.
//
// RED-on-revert: if DisplayAction is removed and a surface goes back to a blank
// action for HostInboundUnmatched, the host-inbound assertion below fails (the
// rendered string is "", not HostInboundActionString).
func TestDisplayActionSSOT(t *testing.T) {
	tests := []struct {
		name string
		res  Result
		want string
	}{
		{
			name: "host-inbound unmatched",
			res:  Result{HostInboundUnmatched: true},
			want: HostInboundActionString,
		},
		{
			name: "default deny (no match)",
			res:  Result{DefaultUsed: true, Action: config.PolicyDeny},
			want: "deny (default)",
		},
		{
			name: "default permit (no match)",
			res:  Result{DefaultUsed: true, Action: config.PolicyPermit},
			want: "permit (default)",
		},
		{
			name: "concrete permit match",
			res:  Result{Matched: true, Action: config.PolicyPermit},
			want: "permit",
		},
		{
			name: "concrete deny match",
			res:  Result{Matched: true, Action: config.PolicyDeny},
			want: "deny",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.res.DisplayAction()
			if got != tt.want {
				t.Errorf("DisplayAction() = %q, want %q", got, tt.want)
			}
			if got == "" {
				t.Errorf("DisplayAction() returned a BLANK verdict (#3375 regression)")
			}
		})
	}
}
