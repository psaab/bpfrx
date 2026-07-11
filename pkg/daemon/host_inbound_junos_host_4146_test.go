package daemon

import (
	"net"
	"os/exec"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/psaab/xpf/pkg/policymatch"
)

// junosHostDenyTestConfig builds a config with an `untrust` ingress zone (netdev
// ge-0-0-1) that coarse-admits ssh, plus a static address book, so #4146
// `to-zone junos-host` DENY projection + kernel nft emission can be exercised
// end to end without a live dataplane. Callers append the policy set.
func junosHostDenyTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.2.10/24"}},
		}},
		// fxp0 is a lifeline — a junos-host deny must NEVER scope to it.
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.10/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"untrust": {
			Name:               "untrust",
			Interfaces:         []string{"ge-0/0/1.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
		"mgmt": {
			Name:               "mgmt",
			Interfaces:         []string{"fxp0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh", "ping"}},
		},
	}
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"bad-host":  {Name: "bad-host", Value: "10.0.0.5/32"},
			"good-host": {Name: "good-host", Value: "10.0.0.6/32"},
			"bad-net":   {Name: "bad-net", Value: "10.0.0.0/8"},
		},
	}
	return cfg
}

func zonePairDeny(from, name string, matches ...string) []*config.Policy {
	return []*config.Policy{denyPolicy(name, matches...)}
}

func denyPolicy(name string, matches ...string) *config.Policy {
	p := &config.Policy{Name: name, Action: config.PolicyDeny}
	applyMatches(&p.Match, matches...)
	return p
}

func permitPolicy(name string, matches ...string) *config.Policy {
	p := &config.Policy{Name: name, Action: config.PolicyPermit}
	applyMatches(&p.Match, matches...)
	return p
}

// applyMatches is a tiny DSL: "src:bad-host", "srcx:bad-net" (excluded),
// "app:junos-ssh", "app:any".
func applyMatches(m *config.PolicyMatch, matches ...string) {
	for _, spec := range matches {
		kind, val, _ := strings.Cut(spec, ":")
		switch kind {
		case "src":
			m.SourceAddresses = append(m.SourceAddresses, val)
		case "srcx":
			m.SourceAddresses = append(m.SourceAddresses, val)
			m.SourceAddressExcluded = true
		case "app":
			m.Applications = append(m.Applications, val)
		}
	}
}

func junosHostPayload(t *testing.T, cfg *config.Config) (string, []dpuserspace.JunosHostProgram) {
	t.Helper()
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	programs := dpuserspace.BuildJunosHostPrograms(cfg)
	return buildHostInboundFilterPayload(views, nil, nil, programs, nil), programs
}

// junosHostSection returns the payload lines from the junos-host DROP subchain
// window — everything between the reply-direction established accept and the
// ND accepts.
func junosHostSection(payload string) []string {
	lines := strings.Split(payload, "\n")
	var out []string
	in := false
	for _, l := range lines {
		if strings.Contains(l, "ct direction reply accept") {
			in = true
			continue
		}
		if in && strings.Contains(l, "icmpv6 type { 1, 2, 3, 4 }") {
			break
		}
		if in {
			out = append(out, l)
		}
	}
	return out
}

// TestJunosHostDenyRendersDropScopedByIifname is the core #4146 enforcement
// guard: a representable `to-zone junos-host` DENY renders an iifname-scoped
// silent DROP (no fine accept) in the kernel chain, placed in coarse-then-fine
// order, and NOT scoped by destination address.
func TestJunosHostDenyRendersDropScopedByIifname(t *testing.T) {
	cfg := junosHostDenyTestConfig()
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host",
			Policies: zonePairDeny("untrust", "block-bad", "src:bad-host", "app:any")},
	}
	payload, programs := junosHostPayload(t, cfg)

	if len(programs) != 1 {
		t.Fatalf("want 1 junos-host program, got %d: %+v", len(programs), programs)
	}
	p := programs[0]
	if p.Zone != "untrust" {
		t.Fatalf("program zone = %q, want untrust", p.Zone)
	}
	if got := strings.Join(p.IngressIfnames, ","); got != "ge-0-0-1" {
		t.Fatalf("IngressIfnames = %q, want ge-0-0-1 (lifeline fxp0 excluded, iifname not daddr)", got)
	}

	cn := xnft.HostInboundJunosHostDenyCounterName("untrust", "ip")
	wantDrop := `iifname "ge-0-0-1" ip saddr 10.0.0.5/32 counter name "` + cn + `" drop`
	if !strings.Contains(payload, wantDrop) {
		t.Fatalf("payload missing iifname-scoped junos-host drop %q:\n%s", wantDrop, payload)
	}
	// The counter must be DECLARED (unquoted) so nft never references an
	// undeclared object.
	if !strings.Contains(payload, "counter "+cn+" {") {
		t.Fatalf("payload missing junos-host counter declaration for %q:\n%s", cn, payload)
	}
	// A junos-host DROP must never be scoped by destination address (daddr
	// under-/over-denies across zones — plan §3.2).
	sec := junosHostSection(payload)
	for _, l := range sec {
		if strings.Contains(l, "daddr") {
			t.Errorf("junos-host section must not scope by daddr: %q", l)
		}
		// DROP-only: no fine accept in the junos-host section (except the reply
		// established already excluded and the exemption shields, which this test
		// has none of).
		if strings.Contains(l, "drop") && strings.Contains(l, "accept") {
			t.Errorf("junos-host drop line must not carry accept: %q", l)
		}
	}

	// Coarse-then-fine ordering: ESP/AH accept, then reply-established, then the
	// fine DROP, then the ND accepts, then the residual established accept and
	// the coarse per-zone ssh accept.
	assertOrder(t, payload,
		"meta l4proto { 50, 51 } accept",
		"ct state established,related ct direction reply accept",
		wantDrop,
		"icmpv6 type { 1, 2, 3, 4 }",
		"ct state established,related accept",
		"tcp dport 22 accept",
	)
}

// TestJunosHostDenySetSubtraction proves an earlier permit carves a later deny
// via `saddr !=` and NEVER emits a fine accept (the coarse gate stays the sole
// admit authority).
func TestJunosHostDenySetSubtraction(t *testing.T) {
	cfg := junosHostDenyTestConfig()
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host", Policies: []*config.Policy{
			permitPolicy("allow-good", "src:good-host", "app:any"),
			denyPolicy("block-net", "src:bad-net", "app:any"),
		}},
	}
	payload, programs := junosHostPayload(t, cfg)
	if len(programs) != 1 {
		t.Fatalf("want 1 program, got %d", len(programs))
	}
	cn := xnft.HostInboundJunosHostDenyCounterName("untrust", "ip")
	want := `iifname "ge-0-0-1" ip saddr 10.0.0.0/8 ip saddr != 10.0.0.6/32 counter name "` + cn + `" drop`
	if !strings.Contains(payload, want) {
		t.Fatalf("set-subtraction drop missing %q:\n%s", want, payload)
	}
	// No fine accept anywhere in the junos-host section (a permit only narrows a
	// later deny; it must not re-admit anything).
	for _, l := range junosHostSection(payload) {
		if strings.Contains(l, "accept") {
			t.Errorf("permit must not emit a fine accept in the junos-host section: %q", l)
		}
	}
}

// TestJunosHostDenyIKEExemption proves the fine-eligible-L4 domain: an
// `application any` deny in an ike-admitting zone emits the IKE 500/4500
// exemption shield ahead of the drop (so coarse-admitted IKE survives).
func TestJunosHostDenyIKEExemption(t *testing.T) {
	cfg := junosHostDenyTestConfig()
	cfg.Security.Zones["untrust"].HostInboundTraffic.SystemServices = []string{"ike"}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host",
			Policies: zonePairDeny("untrust", "block-bad", "src:bad-host", "app:any")},
	}
	payload, programs := junosHostPayload(t, cfg)
	if len(programs) != 1 || !programs[0].CoarseAdmitsIKE {
		t.Fatalf("expected 1 program with CoarseAdmitsIKE, got %+v", programs)
	}
	shield := `iifname "ge-0-0-1" udp dport { 500, 4500 } accept`
	cn := xnft.HostInboundJunosHostDenyCounterName("untrust", "ip")
	drop := `iifname "ge-0-0-1" ip saddr 10.0.0.5/32 counter name "` + cn + `" drop`
	assertOrder(t, payload, shield, drop)
}

// TestJunosHostDenyAppScopedToExemptTupleWarns: a deny explicitly scoped to an
// IKE application is un-representable (the IPsec path owns it) so it emits NO
// kernel rule.
func TestJunosHostDenyAppScopedToExemptTupleUnrepresentable(t *testing.T) {
	cfg := junosHostDenyTestConfig()
	cfg.Applications.Applications = map[string]*config.Application{
		"my-ike": {Name: "my-ike", Protocol: "udp", DestinationPort: "500"},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host",
			Policies: zonePairDeny("untrust", "block-ike", "src:bad-host", "app:my-ike")},
	}
	_, programs := junosHostPayload(t, cfg)
	if len(programs) != 0 {
		t.Fatalf("a deny scoped to an IKE tuple must be un-representable (no program), got %+v", programs)
	}
}

// TestJunosHostDenyNftParses feeds a representable junos-host DENY payload
// through `nft -c -f -` so the rendered iifname / saddr / counter lines are
// validated against the real nft parser (v1.1.6). nft absent => skip; a
// non-syntax (netlink/permission) error => pass.
func TestJunosHostDenyNftParses(t *testing.T) {
	nftPath := findNft()
	if nftPath == "" {
		t.Skip("nft not found")
	}
	cfg := junosHostDenyTestConfig()
	cfg.Security.Zones["untrust"].HostInboundTraffic.SystemServices = []string{"ike"}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host", Policies: []*config.Policy{
			permitPolicy("allow-good", "src:good-host", "app:any"),
			denyPolicy("block-net", "src:bad-net", "app:any"),
		}},
	}
	payload, _ := junosHostPayload(t, cfg)
	cmd := exec.Command(nftPath, "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(payload)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return
	}
	if strings.Contains(string(out), "syntax error") {
		t.Fatalf("nft -c rejected junos-host payload:\n%s\npayload:\n%s", out, payload)
	}
	t.Logf("nft -c parsed (non-syntax error expected without CAP_NET_ADMIN): %v\n%s", err, out)
}

// TestJunosHostNftMatchesRustOracle is the #4146 cross-language parity fixture:
// for the representable ordered DENY class, the kernel nft projection must DROP
// exactly the sources the authoritative Rust junos-host semantics
// (policymatch.Match, the oracle pinned to userspace-dp evaluate_junos_host_
// policy) evaluate to a DENY, and never a permitted-exception source.
func TestJunosHostNftMatchesRustOracle(t *testing.T) {
	cfg := junosHostDenyTestConfig()
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host", Policies: []*config.Policy{
			permitPolicy("allow-good", "src:good-host", "app:any"),
			denyPolicy("block-net", "src:bad-net", "app:any"),
		}},
	}
	programs := dpuserspace.BuildJunosHostPrograms(cfg)
	if len(programs) != 1 {
		t.Fatalf("want 1 program, got %d", len(programs))
	}

	cases := []struct {
		ip       string
		wantDrop bool // nft drop == Rust deny
	}{
		{"10.0.0.6", false},    // permitted exception (good-host) — carved out
		{"10.0.0.5", true},     // in bad-net, not the permitted host — denied
		{"10.1.2.3", true},     // in bad-net — denied
		{"192.168.1.1", false}, // outside bad-net — no host rule matches
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		// Rust oracle.
		res := policymatch.Match(cfg, policymatch.Query{
			FromZone: "untrust", ToZone: policymatch.JunosHostZone,
			SrcIP: ip, DstIP: net.ParseIP("10.0.2.10"),
			Protocol: "tcp", DstPort: 22,
		})
		oracleDeny := res.Matched && res.Action == config.PolicyDeny
		// nft projection verdict.
		nftDrop := junosHostProgramDrops(programs[0], ip)
		if oracleDeny != tc.wantDrop || nftDrop != tc.wantDrop {
			t.Errorf("src %s: nftDrop=%v oracleDeny=%v want=%v (res=%+v)",
				tc.ip, nftDrop, oracleDeny, tc.wantDrop, res)
		}
	}
}

// TestJunosHostExemptTupleParity documents the fine-eligible-L4 exemptions as
// parity cells the naive `policymatch.Match` oracle CANNOT express. For an
// IKE-admitting / ident-resetting zone, a `match source BAD application any then
// deny` STILL admits BAD's IKE (udp 500/4500) and STILL RSTs BAD's ident (tcp
// 113) — because the Rust IPsec-passthrough / ident-reset stages run BEFORE the
// fine junos-host policy (Stage 11 returns pre-fine; ident-reset is a coarse
// terminal). The pure-fine oracle returns DENY for those tuples (it models only
// the fine layer), so the kernel nft ADMIT/RST is FAITHFUL to the Rust runtime,
// NOT a divergence — the exemption shields the codegen emits ahead of the
// application-any drop encode exactly that pre-fine behaviour. Only the
// fine-eligible tuples (e.g. tcp/22) are actually dropped.
func TestJunosHostExemptTupleParity(t *testing.T) {
	mkPayload := func(svc string) (string, dpuserspace.JunosHostProgram) {
		cfg := junosHostDenyTestConfig()
		cfg.Security.Zones["untrust"].HostInboundTraffic.SystemServices = []string{svc}
		cfg.Security.Policies = []*config.ZonePairPolicies{
			{FromZone: "untrust", ToZone: "junos-host",
				Policies: zonePairDeny("untrust", "block-bad", "src:bad-host", "app:any")},
		}
		payload, programs := junosHostPayload(t, cfg)
		if len(programs) != 1 {
			t.Fatalf("want 1 program for svc %q, got %d", svc, len(programs))
		}
		return payload, programs[0]
	}
	cn := xnft.HostInboundJunosHostDenyCounterName("untrust", "ip")

	// oracle: the pure-fine junos-host semantics DENY BAD on every app (incl. the
	// exempt tuples) — but that is NOT what the runtime does for IKE/ident.
	oracleDenies := func(proto string, port int) bool {
		res := policymatch.Match(junosHostDenyTestConfig4146Oracle(), policymatch.Query{
			FromZone: "untrust", ToZone: policymatch.JunosHostZone,
			SrcIP: net.ParseIP("10.0.0.5"), DstIP: net.ParseIP("10.0.2.10"),
			Protocol: proto, DstPort: port,
		})
		return res.Matched && res.Action == config.PolicyDeny
	}

	t.Run("IKE 500/4500 admitted despite deny (Stage-11 pre-fine)", func(t *testing.T) {
		payload, p := mkPayload("ike")
		if !p.CoarseAdmitsIKE {
			t.Fatal("zone should coarse-admit ike")
		}
		// The IKE shield precedes the application-any drop, so BAD's 500/4500 is
		// admitted before the drop can silence it.
		assertOrder(t, payload,
			`iifname "ge-0-0-1" udp dport { 500, 4500 } accept`,
			`iifname "ge-0-0-1" ip saddr 10.0.0.5/32`,
		)
		// The naive fine oracle would DENY BAD's 500 — nft's admit is the faithful
		// runtime behaviour, not a bug.
		if !oracleDenies("udp", 500) {
			t.Fatal("sanity: the pure-fine oracle should DENY BAD's udp/500 (documents the intended nft divergence)")
		}
	})

	t.Run("ident 113 RST despite deny (coarse-terminal pre-fine)", func(t *testing.T) {
		payload, p := mkPayload("ident-reset")
		if !p.CoarseIdentResets {
			t.Fatal("zone should coarse-reset ident")
		}
		assertOrder(t, payload,
			`iifname "ge-0-0-1" tcp dport 113 reject with tcp reset`,
			`iifname "ge-0-0-1" ip saddr 10.0.0.5/32`,
		)
		if !oracleDenies("tcp", 113) {
			t.Fatal("sanity: the pure-fine oracle should DENY BAD's tcp/113 (documents the intended nft divergence)")
		}
	})

	t.Run("fine-eligible tcp/22 still dropped", func(t *testing.T) {
		payload, _ := mkPayload("ike")
		// The drop is application-any (no L4 match), so it catches BAD's tcp/22.
		if !strings.Contains(payload, `iifname "ge-0-0-1" ip saddr 10.0.0.5/32 counter name "`+cn+`" drop`) {
			t.Fatalf("fine-eligible traffic from BAD must still be dropped:\n%s", payload)
		}
	})
}

// junosHostDenyTestConfig4146Oracle rebuilds the deny config for the oracle
// query (the zone's coarse services do not affect the fine junos-host verdict).
func junosHostDenyTestConfig4146Oracle() *config.Config {
	cfg := junosHostDenyTestConfig()
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host",
			Policies: zonePairDeny("untrust", "block-bad", "src:bad-host", "app:any")},
	}
	return cfg
}

// junosHostProgramDrops simulates the nft verdict of a program's v4 DROP rules
// for a source IP: a rule drops when the source matches its positive/excluded
// set AND is not in any permit-subtraction set. Application-any only (the fixture
// uses app any), first-drop wins.
func junosHostProgramDrops(p dpuserspace.JunosHostProgram, ip net.IP) bool {
	for _, r := range p.RulesV4 {
		if r.SrcExcluded {
			if !ipInAny(ip, r.Src) && !ipInAny(ip, r.PermitSubtract) {
				return true
			}
			continue
		}
		if r.SrcAny {
			if !ipInAny(ip, r.PermitSubtract) {
				return true
			}
			continue
		}
		if ipInAny(ip, r.Src) && !ipInAny(ip, r.PermitSubtract) {
			return true
		}
	}
	return false
}

func ipInAny(ip net.IP, cidrs []string) bool {
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// assertOrder asserts the given substrings appear in the payload in the given
// relative order (each strictly after the previous).
func assertOrder(t *testing.T, payload string, subs ...string) {
	t.Helper()
	idx := 0
	for _, s := range subs {
		found := strings.Index(payload[idx:], s)
		if found < 0 {
			t.Fatalf("payload missing %q at/after offset %d (or out of order):\n%s", s, idx, payload)
		}
		idx += found + len(s)
	}
}
