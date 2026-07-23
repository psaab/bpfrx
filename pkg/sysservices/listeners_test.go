package sysservices

import (
	"strings"
	"testing"
)

// TestListenersLines pins the shared `show system services` listener renderer
// (#6385/#6401): a Listening address renders verbatim, a Failed listener renders
// "addr (bind failed)" (or bare "bind failed" when the address is unknown), a
// Disabled listener renders "disabled", and the two rows come out in render
// order. Both the local CLI and remote gRPC renderers call Lines, so this is
// where the shared format contract lives.
func TestListenersLines(t *testing.T) {
	cases := []struct {
		name string
		in   Listeners
		want []string
	}{
		{
			name: "both listening",
			in: Listeners{
				GRPC: Listener{Addr: "127.0.0.1:50051", State: StateListening},
				HTTP: Listener{Addr: "127.0.0.1:8080", State: StateListening},
			},
			want: []string{
				"  gRPC:           127.0.0.1:50051",
				"  HTTP REST:      127.0.0.1:8080",
			},
		},
		{
			name: "relocated grpc, http disabled",
			in: Listeners{
				GRPC: Listener{Addr: "127.0.0.1:50055", State: StateListening},
				HTTP: Listener{State: StateDisabled},
			},
			want: []string{
				"  gRPC:           127.0.0.1:50055",
				"  HTTP REST:      disabled",
			},
		},
		{
			name: "http bind failed with address",
			in: Listeners{
				GRPC: Listener{Addr: "127.0.0.1:50051", State: StateListening},
				HTTP: Listener{Addr: "192.0.2.1:8080", State: StateFailed},
			},
			want: []string{
				"  gRPC:           127.0.0.1:50051",
				"  HTTP REST:      192.0.2.1:8080 (bind failed)",
			},
		},
		{
			name: "grpc bind failed no address",
			in: Listeners{
				GRPC: Listener{State: StateFailed},
				HTTP: Listener{Addr: "127.0.0.1:8080", State: StateListening},
			},
			want: []string{
				"  gRPC:           bind failed",
				"  HTTP REST:      127.0.0.1:8080",
			},
		},
		{
			name: "zero value renders disabled",
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
