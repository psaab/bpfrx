package config

import "testing"

// #8640 (found while censusing #8612): a CROSS-LANGUAGE agreement that nothing
// currently binds.
//
// THE COUPLING. The Rust HA import path reads a zero translated port off the
// sync wire as "this session has no port translation"
// (`userspace-dp/src/server/helpers/session_sync.rs`):
//
//	let nat_src_port = if req.nat_src_port != 0 { Some(req.nat_src_port) } else { None };
//	let nat_dst_port = if req.nat_dst_port != 0 { Some(req.nat_dst_port) } else { None };
//
// That inference is only valid while 0 is not a value the allocator can hand
// out, and the ONLY thing making that true is the floor enforced here in Go:
// `parseSourcePoolPortRange` rejects any endpoint below 1, so a source pool can
// never allocate port 0.
//
// So a Rust behaviour depends on a Go validator, in another package, in another
// language, with nothing connecting them. This test is the connection.
//
// WHY IT MATTERS, and why the failure mode is the bad kind. #4088 (RFC 5508
// §3.1) already established that for ICMP an identifier of 0 is a legal on-wire
// value, and retired exactly this `!= 0` heuristic from the allocator because
// "keying the query gate on `src_port != 0` misclassified an id==0 query as
// flowless". The sync path still carries it. If this floor were ever widened to
// admit 0, an ICMP session whose translated identifier is 0 would sync with
// `nat_src_port = 0`, the standby would rebuild it as UNTRANSLATED, and
// `reverse_session_key` would fall back to the ORIGINAL identifier. The reply
// carrying translated id 0 would not match the standby's reverse companion.
//
// That breaks ON FAILOVER ONLY. It is invisible in every test, every commit and
// every steady-state run, and appears at the one moment the standby has to
// work.
//
// This is an AGREEMENT assertion, not a restatement of the floor: #5457 already
// pins that a zero port is rejected, for its own reasons (a bad range silently
// PAT-translating over the default). What #5457 does not say is that something
// in another language reads the same 0 as a sentinel. Widening the floor reds
// both — this one tells you what else you broke.

// syncWireNoTranslationPort is the value the HA sync wire uses to mean "no port
// translation". Named here so the assertion below is about the AGREEMENT
// between two quantities rather than about a bare literal.
const syncWireNoTranslationPort = 0

func TestTheSourcePoolPortFloorExcludesTheSyncWireSentinel8640(t *testing.T) {
	// The sentinel must not be allocatable. Driven through the production parse
	// rather than by reading a constant, so the thing asserted is what an
	// operator's config actually does.
	for _, spec := range []string{
		"set security nat source pool p1 port 0",
		"set security nat source pool p1 port range 0 to 5000",
		"set security nat source pool p1 port range low 0 high 5000",
	} {
		tree := &ConfigTree{}
		for _, line := range []string{
			"set security nat source pool p1 address 203.0.113.5/32",
			spec,
		} {
			toks, err := ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := tree.SetPath(toks); err != nil {
				t.Fatalf("SetPath(%q): %v", line, err)
			}
		}
		if _, err := CompileConfig(tree); err == nil {
			t.Fatalf("a source pool configured with port %d COMPILED: %q\n\n"+
				"That is the value the HA sync wire uses to mean \"no port "+
				"translation\" (session_sync.rs reads `nat_src_port != 0` as "+
				"Some/None). With %d allocatable, an ICMP session whose translated "+
				"identifier is %d syncs as UNTRANSLATED, the standby rebuilds its "+
				"reverse companion from the ORIGINAL identifier, and the reply does "+
				"not match — breaking ON FAILOVER ONLY, invisible until then.\n\n"+
				"If admitting %d is intended, the Rust import path must stop "+
				"inferring translation from the port value first (see #4088, which "+
				"retired the same heuristic from the allocator for ICMP).",
				syncWireNoTranslationPort, spec,
				syncWireNoTranslationPort, syncWireNoTranslationPort,
				syncWireNoTranslationPort)
		}
	}

	// POSITIVE CONTROL, and it is load-bearing rather than decorative. The
	// assertion above is satisfied by a floor of 1, of 1024, or by a parser that
	// rejects every port range whatsoever — and the last of those would be a
	// broken product passing a green test. Port 1 (the value immediately above
	// the sentinel) must be ACCEPTED, which pins the floor to exactly the
	// sentinel + 1 rather than merely "somewhere above it".
	tree := &ConfigTree{}
	for _, line := range []string{
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 port range 1 to 5000",
	} {
		toks, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(toks); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("port range 1 to 5000 was REJECTED: %v\n\n"+
			"The floor must be exactly one above the sync sentinel. A floor higher "+
			"than that would satisfy every rejection above while quietly forbidding "+
			"usable configurations, and a parser that rejected everything would "+
			"satisfy them too", err)
	}
	if p := cfg.Security.NAT.SourcePools["p1"]; p == nil || p.PortLow != 1 {
		t.Fatalf("PortLow = %v, want 1 — the floor is not where this agreement "+
			"assumes it is", p)
	}
}
