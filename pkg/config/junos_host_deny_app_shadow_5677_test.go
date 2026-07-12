package config

import "testing"

// TestJunosHostDirectProjectionAppShadowsSet is the #5677 fail-on-revert guard
// for the DIRECT host-bound (to-zone junos-host) projection's application
// resolver. A user `application <X>` that shadows a same-named application-set
// MUST project ITS OWN ports into the kernel DENY, not the set's member ports.
//
// The pre-#5677 bug: junosHostResolveApplications consulted the application-SET
// table (ResolveApplicationSet, which also sees the #4102 predefined bundles)
// BEFORE the user application, so a shadowed application was mis-resolved to the
// set and the kernel `xpf_hostinbound` DENY dropped the wrong ports.
//
// This case uses a user application named `junos-ms-rpc` — the predefined
// application-set bundle (junos-ms-rpc-tcp tcp/135 + junos-ms-rpc-udp udp/135,
// #4102). A user application shadowing a PREDEFINED set name is NOT an
// application/application-set collision (only user-authored AST stanzas are
// examined by the #3339 gate; the predefined table lives outside the AST), so
// the config commits clean and both resolvers see the name.
//
// With the app-first fix the deny projects exactly tcp/9999 (the user
// application). Reverting to set-first re-expands the bundle and the deny
// projects tcp/135 + udp/135 instead — the ports the operator's application
// never named — making this test RED.
func TestJunosHostDirectProjectionAppShadowsSet(t *testing.T) {
	cmds := append(append([]string{}, junosHostBaseZones...),
		// User application shadowing the predefined `junos-ms-rpc` app-set.
		"set applications application junos-ms-rpc protocol tcp",
		"set applications application junos-ms-rpc destination-port 9999",
		// Deny the shadowed application on the direct host-bound path.
		"set security policies from-zone untrust to-zone junos-host policy block-rpc match source-address bad-host",
		"set security policies from-zone untrust to-zone junos-host policy block-rpc match destination-address any",
		"set security policies from-zone untrust to-zone junos-host policy block-rpc match application junos-ms-rpc",
		"set security policies from-zone untrust to-zone junos-host policy block-rpc then deny",
	)
	cfg, err := CompileConfig(buildJunosHostWarnTree(t, cmds))
	if err != nil {
		// A user application shadowing a PREDEFINED set name must commit clean
		// (not a #3339 collision). If this fails the shadow scenario itself is
		// unconstructible and the resolver-ordering assertion below is moot.
		t.Fatalf("CompileConfig: user application shadowing predefined app-set should commit clean, got %v", err)
	}

	proj := BuildJunosHostDenyProjection(cfg)
	var prog *JunosHostDenyProgram
	for i := range proj.Programs {
		if proj.Programs[i].Zone == "untrust" {
			prog = &proj.Programs[i]
			break
		}
	}
	if prog == nil {
		t.Fatalf("no untrust program in projection: %+v", proj.Programs)
	}
	if !prog.Representable {
		t.Fatalf("untrust program must be representable (tcp/9999 deny), got %+v", *prog)
	}

	// Collect every projected L4 fragment across both families.
	var frags []JunosHostDenyL4
	for _, r := range prog.RulesV4 {
		frags = append(frags, r.L4...)
	}
	for _, r := range prog.RulesV6 {
		frags = append(frags, r.L4...)
	}
	if len(frags) != 1 {
		t.Fatalf("want exactly 1 L4 fragment (the user application tcp/9999); got %d: %+v\n"+
			"set-first resolution (the #5677 bug) expands the junos-ms-rpc bundle to tcp/135 + udp/135",
			len(frags), frags)
	}
	f := frags[0]
	if f.Proto != HostInboundProtoTCP {
		t.Fatalf("fragment proto = %d, want TCP (%d) — the user application is tcp-only; a UDP fragment means the app-set bundle was expanded (set-first)",
			f.Proto, HostInboundProtoTCP)
	}
	if len(f.Ports) != 1 || f.Ports[0] != (PortRange{Lo: 9999, Hi: 9999}) {
		t.Fatalf("fragment ports = %+v, want [{9999 9999}] (the user application) — port 135 means the predefined junos-ms-rpc bundle was resolved instead (the #5677 set-first bug)",
			f.Ports)
	}
}
