package config

import (
	"reflect"
	"testing"
)

// #8939 at `security flow`: a packed run set only its FIRST flag.
//
//	set security flow allow-dns-reply allow-embedded-icmp force-ip-reassembly
//	  packed  dns=true icmp=FALSE reasm=FALSE
//	  split   dns=true icmp=true  reasm=true
//
// compileFlow asks node.FindChild(...) once per flag, and the packed spelling is
// ONE child node carrying all three on its Keys — so the first lookup matched
// and every other one missed.
//
// `force-ip-reassembly` is the one that matters most: without it fragments are
// not reassembled before inspection, which is a classic evasion path. The packed
// spelling silently removed a control the operator had enabled, on a clean
// commit.
func TestSecurityFlowPackedRunKeepsEveryFlag8939(t *testing.T) {
	build := func(t *testing.T, lines ...string) *Config {
		t.Helper()
		tr := &ConfigTree{}
		for _, l := range lines {
			p, err := ParseSetCommand(l)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", l, err)
			}
			if err := tr.SetPath(p); err != nil {
				t.Fatalf("SetPath: %v", err)
			}
		}
		c, err := CompileConfig(tr)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		return c
	}

	split := build(t,
		"set security flow allow-dns-reply",
		"set security flow allow-embedded-icmp",
		"set security flow force-ip-reassembly")
	// REFERENCE ARM: the split spelling must set all three, or the comparison
	// below is between two equally broken results.
	if f := split.Security.Flow; !f.AllowDNSReply || !f.AllowEmbeddedICMP || !f.ForceIPReassembly {
		t.Fatalf("the SPLIT control set dns=%v icmp=%v reasm=%v — the comparison would prove "+
			"nothing", f.AllowDNSReply, f.AllowEmbeddedICMP, f.ForceIPReassembly)
	}

	packed := build(t, "set security flow allow-dns-reply allow-embedded-icmp force-ip-reassembly")
	if !reflect.DeepEqual(packed, split) {
		pf, sf := packed.Security.Flow, split.Security.Flow
		t.Errorf("packed dns=%v icmp=%v reasm=%v, split dns=%v icmp=%v reasm=%v",
			pf.AllowDNSReply, pf.AllowEmbeddedICMP, pf.ForceIPReassembly,
			sf.AllowDNSReply, sf.AllowEmbeddedICMP, sf.ForceIPReassembly)
	}

	// NARROWNESS, and here it is a SECURITY property in its own right: a fix
	// that set every flag whenever `security flow` appeared would satisfy the
	// comparison above and silently enable controls — and behaviours — the
	// operator never asked for.
	only := build(t, "set security flow allow-dns-reply")
	if f := only.Security.Flow; !f.AllowDNSReply || f.AllowEmbeddedICMP || f.ForceIPReassembly {
		t.Errorf("`allow-dns-reply` alone gave dns=%v icmp=%v reasm=%v, want true/false/false",
			f.AllowDNSReply, f.AllowEmbeddedICMP, f.ForceIPReassembly)
	}

	// A flag that takes a VALUE must keep it — the expansion is arity-aware
	// (#9124), and cutting a value here would turn a timeout into a flag.
	valued := build(t, "set security flow allow-dns-reply", "set security flow tcp-session tcp-initial-timeout 30")
	if valued.Security.Flow.TCPSession == nil {
		t.Error("a valued flow option did not survive the expansion")
	}
}
