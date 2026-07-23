package config

import "testing"

// compileOneStream compiles a single `security log stream s` with the given
// host/port child nodes and returns the resulting stream (nil if dropped). The
// port lives as a DIRECT `port` child of the stream — the flat/first guard site
// in compileLog (`case "port":` in the stream property loop).
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

// compileOneStreamNestedHostPort compiles a single `security log stream s` whose
// port lives in the NESTED `host { <ip>; port <p>; }` block — the SECOND guard
// site in compileLog (`case "port":` inside the `host` child loop). The stream
// has NO direct `port` child, so only the nested guard is exercised; this binds
// the nested site independently of the flat site above.
func compileOneStreamNestedHostPort(t *testing.T, portVal string) *SyslogStream {
	t.Helper()
	logNode := &Node{
		Keys: []string{"log"},
		Children: []*Node{
			{
				Keys: []string{"stream", "s"},
				Children: []*Node{
					{
						Keys: []string{"host"},
						Children: []*Node{
							{Keys: []string{"192.0.2.1"}},
							{Keys: []string{"port", portVal}},
						},
					},
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

// TestSyslogStreamNestedHostPortRejectsOutOfRange_5250 is the fail-on-revert
// guard for the SECOND port guard site — the nested `host { port <p>; }`
// spelling at compiler_security_log.go's host-child loop. compileLog reads the
// port in two AST locations; the flat-site test above leaves this one unbound.
// An out-of-range nested port (70000) must be ignored so the 514 default is
// retained. Removing ONLY the nested `&& validSyslogPort(n)` guard stores 70000,
// which fails every syslog dial while the flat-site test still passes.
func TestSyslogStreamNestedHostPortRejectsOutOfRange_5250(t *testing.T) {
	st := compileOneStreamNestedHostPort(t, "70000")
	if st == nil {
		t.Fatal("stream s dropped; expected a stream with the default port")
	}
	if st.Port != 514 {
		t.Fatalf("Port = %d, want 514 (an out-of-range nested host port must be ignored)", st.Port)
	}
}

// TestSyslogStreamNestedHostPortAcceptsInRange_5250 confirms an in-range nested
// host port is honored (the nested guard admits valid values, not just rejects).
func TestSyslogStreamNestedHostPortAcceptsInRange_5250(t *testing.T) {
	st := compileOneStreamNestedHostPort(t, "9006")
	if st == nil {
		t.Fatal("stream s dropped; expected a stream")
	}
	if st.Port != 9006 {
		t.Fatalf("Port = %d, want 9006 (an in-range nested host port must be stored)", st.Port)
	}
}
