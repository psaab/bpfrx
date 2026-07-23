package sysservices

import (
	"strings"
	"testing"
)

// TestListenersLines pins the shared `show system services` listener renderer
// (#6385): effective addresses render verbatim, an empty address renders
// "disabled", and the two rows come out in render order. Both the local CLI and
// remote gRPC renderers call Lines, so this is where the shared format contract
// lives.
func TestListenersLines(t *testing.T) {
	cases := []struct {
		name string
		in   Listeners
		want []string
	}{
		{
			name: "both bound",
			in:   Listeners{GRPC: "127.0.0.1:50051", HTTP: "127.0.0.1:8080"},
			want: []string{
				"  gRPC:           127.0.0.1:50051",
				"  HTTP REST:      127.0.0.1:8080",
			},
		},
		{
			name: "relocated grpc, http disabled",
			in:   Listeners{GRPC: "127.0.0.1:50055"},
			want: []string{
				"  gRPC:           127.0.0.1:50055",
				"  HTTP REST:      disabled",
			},
		},
		{
			name: "both disabled",
			in:   Listeners{},
			want: []string{
				"  gRPC:           disabled",
				"  HTTP REST:      disabled",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.Lines()
			if len(got) != len(tc.want) {
				t.Fatalf("Lines() len = %d, want %d:\n%s", len(got), len(tc.want), strings.Join(got, "\n"))
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("Lines()[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}
