package daemon

// daemon_nft_netlink_parity_test.go is the #6387 PR-2 T1 ruleset-parity CI — the
// SECURITY MERGE GATE. It proves the additive pkg/nftables netlink installer is
// bit-for-bit equivalent to the CURRENT exec-`nft` payload builders in
// daemon_nft.go (the ORACLE) for a construct-complete matrix (§9 / §12.1):
//
//   render the oracle `nft -f -` text, load it into a fresh netns, dump
//   `nft list table`; install the NETLINK ruleset into the same fresh netns,
//   dump again; normalize (strip handles, sort set elements — but NEVER reorder
//   rules within a chain) and DIFF. Any diff fails the build.
//
// Because a dropped/widened/weakened rule is a host-inbound fail-open on the
// PRIMARY host path, this gate MUST run (not silently SKIP) wherever `nft` + a
// private netns are available. It self-isolates by re-executing under
// `unshare -rn`, so the forked `nft` and the Go netlink install share ONE
// private network namespace and the host ruleset is never touched. When `nft`
// or `unshare` is absent it SKIPs with an explicit logged reason (memory rule:
// no silent caps) — the parent runs it where `nft` exists.
//
// The converter below (daemon dpuserspace views/programs/terms -> pkg/nftables
// spec) is the field-copy PR-3 will promote to production; here it is test-only.

import (
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"

	gnft "github.com/google/nftables"
	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

const t1InnerEnv = "XPF_T1_PARITY_INNER"

// TestNftNetlinkParity is the T1 gate. The OUTER invocation re-execs the test
// binary under `unshare -rn` (a private netns) so nft + netlink share one
// namespace; the INNER invocation runs the actual oracle-vs-netlink diffs.
func TestNftNetlinkParity(t *testing.T) {
	if os.Getenv(t1InnerEnv) == "1" {
		runNftNetlinkParityInner(t)
		return
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("T1 ruleset-parity gate SKIPPED: `nft` binary not found in PATH — " +
			"this gate MUST run where nft exists (the parent runs it); it proves the " +
			"netlink installer is bit-equivalent to the exec-nft oracle")
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("T1 ruleset-parity gate SKIPPED: `unshare` not found — cannot self-isolate a private netns")
	}
	// Re-exec ONLY this test inside a fresh netns so a forked `nft` shares it and
	// the host ruleset is never touched.
	args := []string{"-rn", os.Args[0], "-test.run", "^TestNftNetlinkParity$", "-test.v"}
	cmd := exec.Command(unshare, args...)
	cmd.Env = append(os.Environ(), t1InnerEnv+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("inner T1 output:\n%s", out)
	if err != nil {
		if strings.Contains(string(out), "Operation not permitted") || strings.Contains(string(out), "unshare:") {
			t.Skipf("T1 gate SKIPPED: cannot create private netns under unshare (%v) — run as root or with CAP_NET_ADMIN", err)
		}
		t.Fatalf("T1 ruleset-parity gate FAILED (netlink build diverged from the exec-nft oracle): %v", err)
	}
}

func runNftNetlinkParityInner(t *testing.T) {
	inst := xnft.NewNetlinkInstaller()
	views, unzonedV4, unzonedV6, programs, wg := parityHostInboundInputs()

	t.Run("host_inbound", func(t *testing.T) {
		oracle := buildHostInboundFilterPayload(views, unzonedV4, unzonedV6, programs, wg)
		spec := toNftHostInboundSpec(views, unzonedV4, unzonedV6, programs, wg)
		parityCheck(t, xnft.HostInboundTableName, oracle, func() error { return inst.InstallHostInbound(spec) })

		// The junos-host iifname SET (`iifname { ge-0-0-2, ge-0-0-2.50 }`) is an
		// anonymous string-keyed set; google/nftables v0.3.0 does not emit the
		// NFTA_SET_USERDATA that nft's `list` uses to render such elements, so nft
		// renders it `{ "", "" }` even though the stored 16-byte ifname keys are
		// byte-identical to nft's own (verified below). The interface names are
		// canonicalized out of the TEXT diff (normalizeNftDump), so this asserts the
		// actual iifname SCOPE (the fail-open surface) directly against the kernel.
		if err := inst.InstallHostInbound(spec); err != nil {
			t.Fatalf("host-inbound re-install for iifname check: %v", err)
		}
		assertNetlinkIifnameSet(t, xnft.HostInboundTableName, []string{"ge-0-0-2", "ge-0-0-2.50"})
		nftDeleteTableBestEffort(xnft.HostInboundTableName)
	})

	t.Run("cold_boot_fence", func(t *testing.T) {
		oracle := buildHostInboundFencePayload(views, unzonedV4, unzonedV6, wg)
		spec := xnft.FenceSpec{Views: toNftViews(views), UnzonedV4: unzonedV4, UnzonedV6: unzonedV6, WGListenPorts: wg}
		parityCheck(t, xnft.HostInboundTableName, oracle, func() error { return inst.InstallColdBootFence(spec) })
	})

	t.Run("gap_fence", func(t *testing.T) {
		uncoveredV4 := []string{"10.0.1.1", "10.0.9.1"}
		uncoveredV6 := []string{"2001:db8:1::1"}
		oracle := buildHostInboundGapFencePayload(uncoveredV4, uncoveredV6, wg)
		spec := xnft.GapFenceSpec{UncoveredV4: uncoveredV4, UncoveredV6: uncoveredV6, WGListenPorts: wg}
		parityCheck(t, xnft.HostInboundGapTableName, oracle, func() error { return inst.InstallGapFence(spec) })
	})

	t.Run("lo0_filter", func(t *testing.T) {
		cfg := parityLo0Config()
		oracle := buildLo0FilterPayload(cfg, "lo0f", "lo0f6")
		spec := toNftLo0Spec(cfg, "lo0f", "lo0f6")
		parityCheck(t, xnft.Lo0TableName, oracle, func() error { return inst.InstallLo0(spec) })
	})

	// Mutation-sensitivity against the REAL oracle: each fail-open class must make
	// the netlink dump DIVERGE from the oracle dump — proving the gate catches a
	// fail-open rather than passing vacuously (§12.1).
	oracle := buildHostInboundFilterPayload(views, unzonedV4, unzonedV6, programs, wg)
	mutations := []struct {
		name   string
		mutate func(s *xnft.HostInboundSpec)
	}{
		{"widened_daddr_/32_to_/24", func(s *xnft.HostInboundSpec) { s.Views[0].V4Addrs = []string{"10.0.1.0/24"} }},
		{"dropped_saddr_except_subtraction", func(s *xnft.HostInboundSpec) { s.Programs[0].RulesV4[0].PermitSubtract = nil }},
		{"weakened_verdict_zone_opened_all", func(s *xnft.HostInboundSpec) { s.Views[0].SystemServices = []string{"all"} }},
		{"dropped_unzoned_deny", func(s *xnft.HostInboundSpec) { s.UnzonedV4 = nil; s.UnzonedV6 = nil }},
	}
	for _, mc := range mutations {
		t.Run("mutation_"+mc.name+"_diverges", func(t *testing.T) {
			nftDeleteTableBestEffort(xnft.HostInboundTableName)
			nftLoad(t, oracle)
			dumpOracle := nftListNormalized(t, xnft.HostInboundTableName)
			nftDeleteTableBestEffort(xnft.HostInboundTableName)

			mutated := toNftHostInboundSpec(views, unzonedV4, unzonedV6, programs, wg)
			mc.mutate(&mutated)
			if err := inst.InstallHostInbound(mutated); err != nil {
				t.Fatalf("mutated install failed: %v", err)
			}
			dumpMut := nftListNormalized(t, xnft.HostInboundTableName)
			nftDeleteTableBestEffort(xnft.HostInboundTableName)
			if dumpOracle == dumpMut {
				t.Errorf("mutation %q NOT detected: netlink dump identical to the oracle — the parity gate is vacuous", mc.name)
			}
		})
	}
}

// --- parity mechanics -------------------------------------------------------

func parityCheck(t *testing.T, table, oracleText string, install func() error) {
	t.Helper()
	nftDeleteTableBestEffort(table)
	nftLoad(t, oracleText)
	dumpOracle := nftListNormalized(t, table)
	nftDeleteTableBestEffort(table)

	if err := install(); err != nil {
		t.Fatalf("netlink install failed: %v", err)
	}
	dumpNetlink := nftListNormalized(t, table)
	nftDeleteTableBestEffort(table)

	if dumpOracle != dumpNetlink {
		t.Errorf("RULESET PARITY DIFF for %s (netlink diverged from the exec-nft oracle):\n"+
			"--- oracle (nft -f -) ---\n%s\n--- netlink ---\n%s", table, dumpOracle, dumpNetlink)
	}
}

func nftLoad(t *testing.T, payload string) {
	t.Helper()
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(payload)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -f - failed: %v\npayload:\n%s\noutput: %s", err, payload, out)
	}
}

func nftListNormalized(t *testing.T, table string) string {
	t.Helper()
	out, err := exec.Command("nft", "list", "table", "inet", table).CombinedOutput()
	if err != nil {
		t.Fatalf("nft list table inet %s failed: %v\n%s", table, err, out)
	}
	return normalizeNftDump(string(out))
}

func nftDeleteTableBestEffort(table string) {
	_ = exec.Command("nft", "delete", "table", "inet", table).Run()
}

var handleRe = regexp.MustCompile(`\s*#\s*handle\s+\d+\s*$`)
var wsRe = regexp.MustCompile(`\s+`)
var braceSetRe = regexp.MustCompile(`\{[^{}]*,[^{}]*\}`)

// iifnameSetRe canonicalizes an `iifname { ... }` set away from the text diff
// (both sides): google/nftables v0.3.0 renders such anonymous string sets with
// empty element strings, so the text is unreliable. The actual iifname scope is
// asserted byte-for-byte via assertNetlinkIifnameSet instead.
var iifnameSetRe = regexp.MustCompile(`iifname \{[^{}]*\}`)

// normalizeNftDump canonicalizes an `nft list table` dump for comparison: it
// strips rule handles, collapses whitespace, and SORTS the elements inside each
// inline `{ a, b }` set (the kernel may reorder set elements) — but it NEVER
// reorders rules within a chain, so a precedence-reordering fail-open is still
// caught (§12.1).
func normalizeNftDump(s string) string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		ln = handleRe.ReplaceAllString(ln, "")
		ln = strings.TrimSpace(wsRe.ReplaceAllString(ln, " "))
		if ln == "" {
			continue
		}
		ln = iifnameSetRe.ReplaceAllString(ln, "iifname { IFSET }")
		ln = braceSetRe.ReplaceAllStringFunc(ln, sortBraceSet)
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

func sortBraceSet(set string) string {
	inner := strings.TrimSuffix(strings.TrimPrefix(set, "{"), "}")
	parts := strings.Split(inner, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	sort.Strings(parts)
	return "{ " + strings.Join(parts, ", ") + " }"
}

// assertNetlinkIifnameSet reads the netlink-installed table's anonymous
// ifname-typed sets and asserts the UNION of their decoded interface names
// equals want — a direct byte-level check of the junos-host iifname scope (the
// fail-open surface the cosmetic nft-list rendering gap would otherwise hide).
func assertNetlinkIifnameSet(t *testing.T, table string, want []string) {
	t.Helper()
	c, err := gnft.New()
	if err != nil {
		t.Fatalf("nftables conn: %v", err)
	}
	sets, err := c.GetSets(&gnft.Table{Family: gnft.TableFamilyINet, Name: table})
	if err != nil {
		t.Fatalf("GetSets(%s): %v", table, err)
	}
	got := map[string]bool{}
	for _, s := range sets {
		if s.KeyType.Name != "ifname" {
			continue
		}
		els, err := c.GetSetElements(s)
		if err != nil {
			t.Fatalf("GetSetElements: %v", err)
		}
		for _, e := range els {
			got[string(bytesTrimRightZero(e.Key))] = true
		}
	}
	wantSet := map[string]bool{}
	for _, w := range want {
		wantSet[w] = true
	}
	if len(got) != len(wantSet) {
		t.Errorf("iifname set membership: got %v, want %v", keysOf(got), want)
		return
	}
	for w := range wantSet {
		if !got[w] {
			t.Errorf("iifname set missing %q; got %v", w, keysOf(got))
		}
	}
}

func bytesTrimRightZero(b []byte) []byte {
	i := len(b)
	for i > 0 && b[i-1] == 0 {
		i--
	}
	return b[:i]
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- converters (daemon/dpuserspace -> pkg/nftables spec) -------------------

func toNftViews(views []dpuserspace.ZoneHostInboundView) []xnft.HostInboundZoneView {
	out := make([]xnft.HostInboundZoneView, 0, len(views))
	for _, v := range views {
		out = append(out, xnft.HostInboundZoneView{
			Zone:           v.Zone,
			SystemServices: v.SystemServices,
			Protocols:      v.Protocols,
			V4Addrs:        v.V4Addrs,
			V6Addrs:        v.V6Addrs,
		})
	}
	return out
}

func toNftHostInboundSpec(views []dpuserspace.ZoneHostInboundView, unzonedV4, unzonedV6 []string, programs []dpuserspace.JunosHostProgram, wg []uint16) xnft.HostInboundSpec {
	spec := xnft.HostInboundSpec{
		Views:         toNftViews(views),
		UnzonedV4:     unzonedV4,
		UnzonedV6:     unzonedV6,
		WGListenPorts: wg,
	}
	for _, p := range programs {
		spec.Programs = append(spec.Programs, toNftProgram(p))
	}
	return spec
}

func toNftProgram(p dpuserspace.JunosHostProgram) xnft.JunosHostProgram {
	return xnft.JunosHostProgram{
		Zone:                  p.Zone,
		IngressIfnames:        p.IngressIfnames,
		RulesV4:               toNftDenyRules(p.RulesV4),
		RulesV6:               toNftDenyRules(p.RulesV6),
		CoarseAdmitsIKE:       p.CoarseAdmitsIKE,
		CoarseIdentResets:     p.CoarseIdentResets,
		HasApplicationAnyDeny: p.HasApplicationAnyDeny,
		IKEExemptNetdevs:      p.IKEExemptNetdevs,
		IdentResetNetdevs:     p.IdentResetNetdevs,
	}
}

func toNftDenyRules(rules []config.JunosHostDenyRule) []xnft.JunosHostDenyRule {
	out := make([]xnft.JunosHostDenyRule, 0, len(rules))
	for _, r := range rules {
		nr := xnft.JunosHostDenyRule{
			Family:         r.Family,
			SrcAny:         r.SrcAny,
			SrcExcluded:    r.SrcExcluded,
			Src:            r.Src,
			PermitSubtract: r.PermitSubtract,
		}
		for _, l4 := range r.L4 {
			nr.L4 = append(nr.L4, xnft.JunosHostDenyL4{
				Proto:       l4.Proto,
				Ports:       toNftPortRanges(l4.Ports),
				SourcePorts: toNftPortRanges(l4.SourcePorts),
				ICMPType:    l4.ICMPType,
				ICMPCode:    l4.ICMPCode,
			})
		}
		out = append(out, nr)
	}
	return out
}

func toNftPortRanges(prs []config.PortRange) []xnft.PortRange {
	out := make([]xnft.PortRange, 0, len(prs))
	for _, pr := range prs {
		out = append(out, xnft.PortRange{Lo: pr.Lo, Hi: pr.Hi})
	}
	return out
}

func toNftLo0Spec(cfg *config.Config, filterV4, filterV6 string) xnft.Lo0FilterSpec {
	var spec xnft.Lo0FilterSpec
	pl := cfg.PolicyOptions.PrefixLists
	if filterV4 != "" {
		if f, ok := cfg.Firewall.FiltersInet[filterV4]; ok {
			for _, term := range f.Terms {
				spec.V4Terms = append(spec.V4Terms, toNftLo0Term(term, pl))
			}
		}
	}
	if filterV6 != "" {
		if f, ok := cfg.Firewall.FiltersInet6[filterV6]; ok {
			for _, term := range f.Terms {
				spec.V6Terms = append(spec.V6Terms, toNftLo0Term(term, pl))
			}
		}
	}
	return spec
}

func toNftLo0Term(term *config.FirewallFilterTerm, pl map[string]*config.PrefixList) xnft.Lo0FilterTerm {
	src, srcEx, srcC := dpuserspace.ResolveFilterPrefixListAddrs(
		term.SourceAddresses, term.SourcePrefixLists, pl, "", term.Name, "source", term.Action)
	dst, dstEx, dstC := dpuserspace.ResolveFilterPrefixListAddrs(
		term.DestAddresses, term.DestPrefixLists, pl, "", term.Name, "destination", term.Action)
	return xnft.Lo0FilterTerm{
		Name:              term.Name,
		SrcAddrs:          src,
		SrcExcept:         srcEx,
		SrcConstrained:    srcC,
		DstAddrs:          dst,
		DstExcept:         dstEx,
		DstConstrained:    dstC,
		Protocols:         term.Protocols,
		SourcePorts:       term.SourcePorts,
		DestinationPorts:  term.DestinationPorts,
		SourcePortsExcept: term.SourcePortsExcept,
		DestPortsExcept:   term.DestPortsExcept,
		DSCPs:             term.DSCPs,
		ICMPTypes:         term.ICMPTypes,
		ICMPCodes:         term.ICMPCodes,
		TCPFlags:          term.TCPFlags,
		IsFragment:        term.IsFragment,
		Log:               term.Log,
		Count:             term.Count,
		Action:            term.Action,
		NextTerm:          term.NextTerm,
		RoutingInstance:   term.RoutingInstance,
	}
}

// --- construct-complete parity inputs ---------------------------------------

func parityHostInboundInputs() (views []dpuserspace.ZoneHostInboundView, unzonedV4, unzonedV6 []string, programs []dpuserspace.JunosHostProgram, wg []uint16) {
	views = []dpuserspace.ZoneHostInboundView{
		{Zone: "trust", SystemServices: []string{"ssh", "https", "ping", "dns"}, V4Addrs: []string{"10.0.1.1", "10.0.1.2"}, V6Addrs: []string{"2001:db8:1::1"}},
		{Zone: "mgmt", SystemServices: []string{"all"}, V4Addrs: []string{"10.0.9.1"}},
		{Zone: "core", Protocols: []string{"all"}, V4Addrs: []string{"10.0.5.1"}, V6Addrs: []string{"2001:db8:5::1"}},
		{Zone: "edge", SystemServices: []string{"ident-reset", "ssh"}, V4Addrs: []string{"10.0.7.1"}},
		{Zone: "quarantine", V4Addrs: []string{"10.0.8.1"}, V6Addrs: []string{"2001:db8:8::1"}},
	}
	unzonedV4 = []string{"10.0.99.1"}
	unzonedV6 = []string{"2001:db8:99::1"}
	wg = []uint16{51820, 51821}
	programs = []dpuserspace.JunosHostProgram{
		{
			Zone:                  "untrust",
			IngressIfnames:        []string{"ge-0-0-2", "ge-0-0-2.50"},
			HasApplicationAnyDeny: true,
			CoarseAdmitsIKE:       true,
			CoarseIdentResets:     true,
			IKEExemptNetdevs:      []string{"ge-0-0-2"},
			IdentResetNetdevs:     []string{"ge-0-0-2"},
			RulesV4: []config.JunosHostDenyRule{
				{Family: "ip", Src: []string{"192.0.2.0/24", "198.51.100.7"}, PermitSubtract: []string{"192.0.2.10"}},
				{Family: "ip", SrcExcluded: true, Src: []string{"203.0.113.0/24"}, L4: []config.JunosHostDenyL4{{Proto: config.HostInboundProtoTCP, Ports: []config.PortRange{{Lo: 22, Hi: 22}}}}},
				{Family: "ip", SrcAny: true, L4: []config.JunosHostDenyL4{{Proto: config.HostInboundProtoICMP, ICMPType: ptrU8(8), ICMPCode: ptrU8(0)}}},
			},
			RulesV6: []config.JunosHostDenyRule{
				{Family: "ip6", Src: []string{"2001:db8:a::/48"}, L4: []config.JunosHostDenyL4{{Proto: 47}}},
			},
		},
	}
	return views, unzonedV4, unzonedV6, programs, wg
}

func parityLo0Config() *config.Config {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"lo0f": {Terms: []*config.FirewallFilterTerm{
			{Name: "ssh-in", SourceAddresses: []string{"10.0.0.0/8"}, DestAddresses: []string{"10.0.1.1"}, Protocols: []string{"tcp"}, DestinationPorts: []string{"22"}, Count: "ssh_hits", Action: "accept"},
			{Name: "range-drop", SourcePorts: []string{"1024", "2048"}, DestinationPorts: []string{"33434-33523"}, DSCPs: []string{"ef"}, Log: true, Action: "discard"},
			{Name: "reject-term", DestPortsExcept: []string{"80", "443"}, ICMPTypes: []int{3}, ICMPCodes: []int{4}, IsFragment: true, Action: "reject"},
			{Name: "syn-only", TCPFlags: []string{"syn", "&", "!ack"}, Action: "accept"},
			{Name: "count-only", Count: "audit"},
			{Name: "multi", DestAddresses: []string{"10.0.1.1", "10.0.1.2"}, Protocols: []string{"tcp", "udp"}, Action: "accept"},
		}},
	}
	cfg.Firewall.FiltersInet6 = map[string]*config.FirewallFilter{
		"lo0f6": {Terms: []*config.FirewallFilterTerm{
			{Name: "v6-dscp", DestAddresses: []string{"2001:db8::/32"}, DSCPs: []string{"cs1"}, Action: "accept"},
			{Name: "v6-frag", ICMPTypes: []int{1, 2}, IsFragment: true, Action: "discard"},
			{Name: "v6-except", SourceAddresses: []string{"2001:db8:bad::/48"}, DestPortsExcept: []string{"22"}, Action: "accept"},
		}},
	}
	return cfg
}

func ptrU8(v uint8) *uint8 { return &v }
