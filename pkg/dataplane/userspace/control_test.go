package userspace

import "testing"

func TestParseRegistrationOperation(t *testing.T) {
	tests := []struct {
		name       string
		op         string
		registered bool
		armed      bool
		wantErr    bool
	}{
		{name: "register", op: "register", registered: true, armed: false},
		{name: "unregister", op: "unregister", registered: false, armed: false},
		{name: "arm", op: "arm", registered: true, armed: true},
		{name: "disarm", op: "disarm", registered: true, armed: false},
		{name: "bad", op: "enable", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registered, armed, err := ParseRegistrationOperation(tt.op)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseRegistrationOperation(%q) = nil error, want error", tt.op)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRegistrationOperation(%q) error = %v", tt.op, err)
			}
			if registered != tt.registered || armed != tt.armed {
				t.Fatalf("ParseRegistrationOperation(%q) = (%t,%t), want (%t,%t)", tt.op, registered, armed, tt.registered, tt.armed)
			}
		})
	}
}

func TestParseForwardingCommand(t *testing.T) {
	armed, err := ParseForwardingCommand([]string{"forwarding", "arm"})
	if err != nil {
		t.Fatalf("ParseForwardingCommand arm error = %v", err)
	}
	if !armed {
		t.Fatal("ParseForwardingCommand arm = false, want true")
	}
	armed, err = ParseForwardingCommand([]string{"forwarding", "disarm"})
	if err != nil {
		t.Fatalf("ParseForwardingCommand disarm error = %v", err)
	}
	if armed {
		t.Fatal("ParseForwardingCommand disarm = true, want false")
	}
}

func TestParseQueueAndBindingCommands(t *testing.T) {
	queueID, registered, armed, err := ParseQueueCommand([]string{"queue", "3", "arm"})
	if err != nil {
		t.Fatalf("ParseQueueCommand error = %v", err)
	}
	if queueID != 3 || !registered || !armed {
		t.Fatalf("ParseQueueCommand = (%d,%t,%t), want (3,true,true)", queueID, registered, armed)
	}
	slot, registered, armed, err := ParseBindingCommand([]string{"binding", "slot", "7", "unregister"})
	if err != nil {
		t.Fatalf("ParseBindingCommand error = %v", err)
	}
	if slot != 7 || registered || armed {
		t.Fatalf("ParseBindingCommand = (%d,%t,%t), want (7,false,false)", slot, registered, armed)
	}
}
