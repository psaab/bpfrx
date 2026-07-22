package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// TestParseQueueCommandRejectsOutOfRange6215 pins the #6215 bounds check on
// the queue id parsed by ParseQueueCommand. Before the fix the id was read
// with a raw strconv.Atoi and cast straight to uint32, so a negative ("-1")
// wrapped to 4294967295 and an oversized value truncated silently — either
// one steering a queue register/arm op to an out-of-range worker binding.
// A valid queue id lives in [0, dataplane.BindingQueuesPerIface); ids at or
// above the stride alias the adjacent ifindex's queue-0 slot (the same
// failure the #4894 maps_sync guard rejects).
//
// Fail-on-revert: restoring the raw `strconv.Atoi(args[1])` + `uint32(...)`
// path makes the negative and oversized cases parse without error, failing
// the wantErr assertions below.
func TestParseQueueCommandRejectsOutOfRange6215(t *testing.T) {
	tests := []struct {
		name    string
		queue   string
		wantErr bool
		wantID  uint32
	}{
		{name: "negative", queue: "-1", wantErr: true},
		{name: "oversized_uint32_overflow", queue: "5000000000", wantErr: true},
		{name: "at_stride", queue: "16", wantErr: true},
		{name: "above_stride", queue: "9999", wantErr: true},
		{name: "valid_zero", queue: "0", wantErr: false, wantID: 0},
		{name: "valid_mid", queue: "3", wantErr: false, wantID: 3},
		{name: "valid_max", queue: "15", wantErr: false, wantID: 15},
	}
	// Guard the boundary constant so a future stride bump keeps the test's
	// "at_stride"/"valid_max" cases meaningful.
	if dataplane.BindingQueuesPerIface != 16 {
		t.Fatalf("test assumes BindingQueuesPerIface==16, got %d", dataplane.BindingQueuesPerIface)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			queueID, registered, armed, err := ParseQueueCommand([]string{"queue", tt.queue, "arm"})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseQueueCommand(queue=%s) = (%d,%t,%t,nil), want error",
						tt.queue, queueID, registered, armed)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseQueueCommand(queue=%s) error = %v, want nil", tt.queue, err)
			}
			if queueID != tt.wantID {
				t.Fatalf("ParseQueueCommand(queue=%s) queueID = %d, want %d", tt.queue, queueID, tt.wantID)
			}
			if !registered || !armed {
				t.Fatalf("ParseQueueCommand(queue=%s) = (registered=%t,armed=%t), want (true,true)",
					tt.queue, registered, armed)
			}
		})
	}
}
