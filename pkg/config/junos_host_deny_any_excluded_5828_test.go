package config

import "testing"

// jh5828Projection compiles a flat-set config (ParseSetCommand + SetPath, never
// NewParser — the parser merges newline-separated set lines) and returns the
// single ingress-zone junos-host deny program. Every case authors an `untrust`
// zone with one non-lifeline netdev (ge-0/0/1.0) so the program is enforceable.
func jh5828Projection(t *testing.T, policyCmds ...string) JunosHostDenyProgram {
	t.Helper()
	base := []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.10/24",
		"set security zones security-zone untrust interfaces ge-0/0/1.0",
		"set security zones security-zone untrust host-inbound-traffic system-services ssh",
	}
	tree := &ConfigTree{}
	for _, cmd := range append(base, policyCmds...) {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	proj := BuildJunosHostDenyProjection(cfg)
	if len(proj.Programs) != 1 {
		t.Fatalf("want exactly 1 junos-host program, got %d: %+v", len(proj.Programs), proj.Programs)
	}
	return proj.Programs[0]
}

// isUnconditionalDrop reports whether a projected deny rule matches EVERY source
// on its ingress iifname — the exact shape junosHostSrcPredicate renders with an
// empty source predicate (`SrcAny`, or an excluded set with no family prefix).
// The #5828 bug turned an `any` + source-address-excluded term into one of these.
func isUnconditionalDrop(r JunosHostDenyRule) bool {
	return r.SrcAny || (r.SrcExcluded && len(r.Src) == 0)
}

// TestJunosHostAnyExcludedProjectsNoRule is the #5828 fail-on-revert guard.
//
// `match source-address any` + `match source-address-excluded` + `then deny`
// is, in Junos exclusion semantics, "every source EXCEPT every source" = the
// empty set: the term matches NOTHING and must project NO drop rule for either
// family. The pre-fix projection classified `any`'s empty concrete slice as
// `SrcAny` in the excluded arm and emitted an UNCONDITIONAL all-source DROP —
// an over-deny that can lock out all direct host-bound traffic on the ingress
// zone (an availability/security failure).
//
// RED on revert: restoring the `len(src)==0 => SrcAny` behavior in
// junosHostBuildRule makes both families emit an unconditional drop, so
// len(RulesV4)/len(RulesV6) become 1 and isUnconditionalDrop is true — every
// assertion below fails.
func TestJunosHostAnyExcludedProjectsNoRule(t *testing.T) {
	p := jh5828Projection(t,
		"set security policies from-zone untrust to-zone junos-host policy blk match source-address any",
		"set security policies from-zone untrust to-zone junos-host policy blk match source-address-excluded",
		"set security policies from-zone untrust to-zone junos-host policy blk match destination-address any",
		"set security policies from-zone untrust to-zone junos-host policy blk match application any",
		"set security policies from-zone untrust to-zone junos-host policy blk then deny",
	)
	// The program stays representable — the term is inert, not un-representable.
	if !p.Representable {
		t.Fatalf("program must stay representable (the term is inert, not un-representable): %+v", p)
	}
	if len(p.RulesV4) != 0 {
		t.Errorf("IPv4: any + source-address-excluded must emit NO deny rule, got %+v", p.RulesV4)
	}
	if len(p.RulesV6) != 0 {
		t.Errorf("IPv6: any + source-address-excluded must emit NO deny rule, got %+v", p.RulesV6)
	}
	// Belt and suspenders: assert no unconditional all-source drop slipped in
	// under any classification (the exact #5828 over-deny shape).
	for _, r := range append(append([]JunosHostDenyRule{}, p.RulesV4...), p.RulesV6...) {
		if isUnconditionalDrop(r) {
			t.Errorf("emitted an unconditional all-source drop for any+excluded (the #5828 over-deny): %+v", r)
		}
	}
}

// TestJunosHostAnyDenyStillDropsAll is the deny-all regression guard: a plain
// `source-address any` + `then deny` with NO exclusion is a legitimate
// drop-every-source deny and MUST still emit the unconditional drop for both
// families. Only the degenerate any+excluded case changed.
func TestJunosHostAnyDenyStillDropsAll(t *testing.T) {
	p := jh5828Projection(t,
		"set security policies from-zone untrust to-zone junos-host policy blk match source-address any",
		"set security policies from-zone untrust to-zone junos-host policy blk match destination-address any",
		"set security policies from-zone untrust to-zone junos-host policy blk match application any",
		"set security policies from-zone untrust to-zone junos-host policy blk then deny",
	)
	if len(p.RulesV4) != 1 || !p.RulesV4[0].SrcAny {
		t.Errorf("IPv4: `any` deny (no excluded) must emit one all-source drop (SrcAny), got %+v", p.RulesV4)
	}
	if len(p.RulesV6) != 1 || !p.RulesV6[0].SrcAny {
		t.Errorf("IPv6: `any` deny (no excluded) must emit one all-source drop (SrcAny), got %+v", p.RulesV6)
	}
}

// TestJunosHostConcreteExcludedUnchanged is the non-`any` exclusion regression
// guard: `source-address 10.0.0.0/8` + excluded + deny drops every source
// EXCEPT 10/8 on IPv4 (SrcExcluded, Src=[10.0.0.0/8]) and — because the excluded
// set has no IPv6 prefix — drops ALL IPv6 (the documented match-all-of-opposite-
// family semantic). The #5828 fix keys strictly on the `any` wildcard, so this
// genuinely-constrained exclusion is UNCHANGED.
func TestJunosHostConcreteExcludedUnchanged(t *testing.T) {
	p := jh5828Projection(t,
		"set security address-book global address bad-net 10.0.0.0/8",
		"set security policies from-zone untrust to-zone junos-host policy blk match source-address bad-net",
		"set security policies from-zone untrust to-zone junos-host policy blk match source-address-excluded",
		"set security policies from-zone untrust to-zone junos-host policy blk match destination-address any",
		"set security policies from-zone untrust to-zone junos-host policy blk match application any",
		"set security policies from-zone untrust to-zone junos-host policy blk then deny",
	)
	if len(p.RulesV4) != 1 {
		t.Fatalf("IPv4: want one except-10/8 drop, got %+v", p.RulesV4)
	}
	r4 := p.RulesV4[0]
	if !r4.SrcExcluded || len(r4.Src) != 1 || r4.Src[0] != "10.0.0.0/8" || r4.SrcAny {
		t.Errorf("IPv4 rule = %+v, want SrcExcluded with Src=[10.0.0.0/8] (drop all except 10/8)", r4)
	}
	// IPv6: no v6 prefix in the excluded set -> match ALL v6 (unchanged
	// match-all-of-opposite-family semantic).
	if len(p.RulesV6) != 1 || !p.RulesV6[0].SrcAny {
		t.Errorf("IPv6: excluded set with no v6 prefix must match ALL v6 (SrcAny), got %+v", p.RulesV6)
	}
}

// TestJunosHostConcreteDenyUnchanged guards a normal per-source deny (no
// exclusion): `source-address 10.0.0.5/32` + deny drops exactly that source on
// IPv4 and nothing on IPv6 (no v6 prefix, positive set -> match nothing).
func TestJunosHostConcreteDenyUnchanged(t *testing.T) {
	p := jh5828Projection(t,
		"set security address-book global address bad-host 10.0.0.5/32",
		"set security policies from-zone untrust to-zone junos-host policy blk match source-address bad-host",
		"set security policies from-zone untrust to-zone junos-host policy blk match destination-address any",
		"set security policies from-zone untrust to-zone junos-host policy blk match application any",
		"set security policies from-zone untrust to-zone junos-host policy blk then deny",
	)
	if len(p.RulesV4) != 1 || p.RulesV4[0].SrcAny || len(p.RulesV4[0].Src) != 1 || p.RulesV4[0].Src[0] != "10.0.0.5/32" {
		t.Errorf("IPv4: want a single-source drop for 10.0.0.5/32, got %+v", p.RulesV4)
	}
	if len(p.RulesV6) != 0 {
		t.Errorf("IPv6: a v4-only positive source must emit no v6 rule, got %+v", p.RulesV6)
	}
}
