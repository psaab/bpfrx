package config

import "testing"

// compileOneStream compiles a single `security log stream s` with the given
// host/port child nodes and returns the resulting stream (nil if dropped).
func compileOneStream(t *testing.T, portVal string) *SyslogStream {
	t.Helper()
	logNode := &Node{
		Keys: []string{"log"},
		Children: []*Node{
			{
				Keys: []string{"stream", "s"},
				Children: []*Node{
					{Keys: []string{"host", "192.0.2.1"}},
					{Keys: []string{"port", portVal}},
				},
			},
		},
	}
	sec := &SecurityConfig{}
	if err := compileLog(logNode, sec); err != nil {
		t.Fatalf("compileLog: %v", err)
	}
	return sec.Log.Streams["s"]
}

// TestSyslogStreamPortRejectsOutOfRange_5250 is the fail-on-revert guard for the
// syslog stream port range guard (#5250 A3-b2 F2). An out-of-range port (70000)
// must be ignored so the dial-able 514 default is retained. Removing the
// validSyslogPort guard stores 70000, which fails every syslog dial.
func TestSyslogStreamPortRejectsOutOfRange_5250(t *testing.T) {
	st := compileOneStream(t, "70000")
	if st == nil {
		t.Fatal("stream s dropped; expected a stream with the default port")
	}
	if st.Port != 514 {
		t.Fatalf("Port = %d, want 514 (an out-of-range port must be ignored)", st.Port)
	}
}

// TestSyslogStreamPortAcceptsInRange_5250 confirms an in-range port is honored.
func TestSyslogStreamPortAcceptsInRange_5250(t *testing.T) {
	st := compileOneStream(t, "9006")
	if st == nil {
		t.Fatal("stream s dropped; expected a stream")
	}
	if st.Port != 9006 {
		t.Fatalf("Port = %d, want 9006 (an in-range port must be stored)", st.Port)
	}
}
