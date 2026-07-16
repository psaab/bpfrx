package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #5644 (M37): cold boot with BOTH nft tables absent must not publish host
// service / VIP / HA-ready over an UNENFORCED host input path. On COLD BOOT
// there is no prior host-inbound table to retain, so a failed install (the boot
// apply only logs+discards the error) would leave host-bound services reachable
// with no host-inbound default-deny (fail-open). The fix installs a fail-closed
// DENY-ALL fence when the real ruleset fails to load and no enforcement table
// exists yet, so enforcement is established (fail-closed) before any host
// service is exposed. These are the fail-on-revert proofs: neutralize the fence
// (drop the installHostInboundColdBootFence call, or its emitted drops) and the
// cold-boot assertions go RED.

// realHostInboundPayload reports whether an nft `-f -` payload is the REAL
// host-inbound ruleset (carries a per-service ACCEPT) rather than the fence
// (drops only). hostInboundTestConfig's wan zone permits ssh, so the real
// payload contains `tcp dport 22 accept`; the fence never accepts a service.
func realHostInboundPayload(payload string) bool {
	return strings.Contains(payload, "tcp dport 22 accept")
}

// TestColdBootHostInboundInstallFailureInstallsFence is the primary #5644
// fail-on-revert proof: at cold boot, when the real host-inbound `nft -f -`
// install fails and no enforcement table has ever loaded this boot, a fail-closed
// DENY-ALL fence MUST be installed so host-bound services stay fenced. It also
// asserts the commit still fails (the error is surfaced) so the retry/re-render
// path is driven. Reverting the fence makes the fence-installed assertion and the
// hostInboundEnforced assertion RED.
func TestColdBootHostInboundInstallFailureInstallsFence(t *testing.T) {
	cfg := hostInboundTestConfig()

	injected := errors.New("nft: rule load failed")
	var payloads []string
	var fencePayload string
	orig := nftApplyPayload
	nftApplyPayload = func(payload string) ([]byte, error) {
		payloads = append(payloads, payload)
		if realHostInboundPayload(payload) {
			// Real ruleset install fails (injected cold-boot install failure).
			return []byte("Error: could not process rule\n"), injected
		}
		// The fence payload loads.
		fencePayload = payload
		return nil, nil
	}
	defer func() { nftApplyPayload = orig }()

	d := &Daemon{}
	// Cold boot: no enforcement table has ever loaded.
	if d.hostInboundEnforced.Load() {
		t.Fatal("precondition: hostInboundEnforced must start false (cold boot)")
	}

	err := d.applyHostInboundFilter(cfg)

	// The commit must still fail closed (the real ruleset did not load).
	if err == nil {
		t.Fatal("cold-boot install failure must be surfaced as an error, got nil")
	}
	if !errors.Is(err, injected) {
		t.Errorf("returned error must wrap the nft failure, got %v", err)
	}

	// A fence must have been installed (the second nft call).
	if fencePayload == "" {
		t.Fatalf("cold-boot install failure must install a fail-closed fence; nft payloads seen:\n%v", payloads)
	}
	if len(payloads) != 2 {
		t.Errorf("expected exactly 2 nft applies (real + fence), got %d:\n%v", len(payloads), payloads)
	}

	// Enforcement is now established (via the fence) — a later day-2 failure is
	// retained by the atomic load and needs no fence.
	if !d.hostInboundEnforced.Load() {
		t.Error("hostInboundEnforced must be true after the fence installs (enforcement established)")
	}

	// The fence must be a real xpf_hostinbound table that DENIES host services to
	// the enforced zone's addresses (both families), NOT leave them open.
	fenceMust := []string{
		"table inet xpf_hostinbound",
		"type filter hook input priority 10; policy accept;",
		"ct state established,related accept",
		// deny-all to the wan v4 + v6 firewall-local addresses (host services fenced).
		"ip daddr 172.16.50.8 drop",
		"ip6 daddr 2001:db8:50::8 drop",
	}
	for _, want := range fenceMust {
		if !strings.Contains(fencePayload, want) {
			t.Errorf("fence payload missing %q\n---\n%s", want, fencePayload)
		}
	}

	// The fence must NOT accept any host service — that would re-open the exposure.
	for _, banned := range []string{"tcp dport 22 accept", "icmp type echo-request accept"} {
		if strings.Contains(fencePayload, banned) {
			t.Errorf("fence must not accept host service %q (fail-open):\n%s", banned, fencePayload)
		}
	}
}

// TestColdBootFenceIsLifelineSafe proves the cold-boot fence never denies a
// management / cluster-control lifeline address: fxp0 (mgmt) and em0 (control)
// are lifelines, so their addresses are excluded from the deny sets and must not
// appear in the fence. A fence that dropped a lifeline address could strand
// management or break HA. Reverting the lifeline exclusion (or fencing on
// lifeline addrs) makes this RED.
func TestColdBootFenceIsLifelineSafe(t *testing.T) {
	cfg := hostInboundTestConfig()
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	unzonedV4, unzonedV6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
	fence := buildHostInboundFencePayload(views, unzonedV4, unzonedV6, nil)

	// em0's cluster-control address must never be fenced (lifeline).
	if strings.Contains(fence, "10.99.0.1") {
		t.Errorf("fence must not deny the em0 cluster-control lifeline address:\n%s", fence)
	}
	// The enforced wan address must be fenced.
	if !strings.Contains(fence, "ip daddr 172.16.50.8 drop") {
		t.Errorf("fence must deny the enforced wan address:\n%s", fence)
	}
}

// TestColdBootFenceAdmitsMandatoryL3 proves the fence still admits return
// traffic and mandatory L3 control (established, raw ESP/AH, IPv6 ND, v4/v6
// PMTUD+error), so the deny-all fence does not black-hole core operation.
func TestColdBootFenceAdmitsMandatoryL3(t *testing.T) {
	cfg := hostInboundTestConfig()
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	unzonedV4, unzonedV6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
	fence := buildHostInboundFencePayload(views, unzonedV4, unzonedV6, nil)

	for _, want := range []string{
		"ct state established,related accept",
		"meta l4proto { 50, 51 } accept",
		"icmpv6 type { 133, 134, 135, 136, 137 } accept",
		"icmp type { destination-unreachable, time-exceeded, parameter-problem } accept",
	} {
		if !strings.Contains(fence, want) {
			t.Errorf("fence missing mandatory L3 admit %q\n---\n%s", want, fence)
		}
	}
}

// TestColdBootFenceAdmitsWireGuardPort proves the fence admits the configured
// WireGuard listen port so a responder-only tunnel is not black-holed while the
// fence is active (mirrors the real chain's WG admit).
func TestColdBootFenceAdmitsWireGuardPort(t *testing.T) {
	cfg := hostInboundTestConfig()
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	fence := buildHostInboundFencePayload(views, nil, nil, []uint16{51820})
	if !strings.Contains(fence, "udp dport 51820 accept") {
		t.Errorf("fence must admit the configured WG listen port:\n%s", fence)
	}
}

// TestDay2HostInboundInstallFailureNoFence proves the NORMAL (tables-present)
// path is unchanged: once a real host-inbound table has installed
// (hostInboundEnforced == true), a LATER failed install must NOT install a fence
// — the atomic `-f -` load already retains the prior table (fail-closed). Only
// the real payload is attempted; no fence is emitted. This is the no-regression
// guard: if the cold-boot fence were installed unconditionally it would clobber
// the retained day-2 table with a deny-all, so this goes RED.
func TestDay2HostInboundInstallFailureNoFence(t *testing.T) {
	cfg := hostInboundTestConfig()

	// First apply: real install succeeds → enforcement established.
	orig := nftApplyPayload
	nftApplyPayload = func(string) ([]byte, error) { return nil, nil }
	d := &Daemon{}
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("first (successful) apply: %v", err)
	}
	if !d.hostInboundEnforced.Load() {
		t.Fatal("hostInboundEnforced must be true after a successful real install")
	}

	// Second apply: real install fails. The prior table is retained by the atomic
	// load, so NO fence must be installed.
	injected := errors.New("nft: transient failure")
	var payloads []string
	nftApplyPayload = func(payload string) ([]byte, error) {
		payloads = append(payloads, payload)
		if realHostInboundPayload(payload) {
			return []byte("Error\n"), injected
		}
		t.Errorf("day-2 failure must NOT install a fence; got fence payload:\n%s", payload)
		return nil, nil
	}
	defer func() { nftApplyPayload = orig }()

	err := d.applyHostInboundFilter(cfg)
	if err == nil {
		t.Fatal("day-2 install failure must still be surfaced as an error")
	}
	if !errors.Is(err, injected) {
		t.Errorf("returned error must wrap the nft failure, got %v", err)
	}
	if len(payloads) != 1 {
		t.Errorf("day-2 failure must attempt only the real payload (no fence), got %d applies:\n%v", len(payloads), payloads)
	}
}

// TestColdBootFenceCatastrophicFailureSurfaced proves that when the real install
// AND the fence both fail (nft itself broken), both errors are surfaced so the
// commit fails closed and the operator sees the fail-open guard fire.
func TestColdBootFenceCatastrophicFailureSurfaced(t *testing.T) {
	cfg := hostInboundTestConfig()

	realErr := errors.New("nft: rule load failed")
	fenceErr := errors.New("nft: binary missing")
	orig := nftApplyPayload
	nftApplyPayload = func(payload string) ([]byte, error) {
		if realHostInboundPayload(payload) {
			return nil, realErr
		}
		return nil, fenceErr
	}
	defer func() { nftApplyPayload = orig }()

	d := &Daemon{}
	err := d.applyHostInboundFilter(cfg)
	if err == nil {
		t.Fatal("catastrophic cold-boot failure must be surfaced as an error")
	}
	if !errors.Is(err, realErr) || !errors.Is(err, fenceErr) {
		t.Errorf("error must join both the real and fence failures, got %v", err)
	}
	// The fence never loaded, so enforcement is NOT established.
	if d.hostInboundEnforced.Load() {
		t.Error("hostInboundEnforced must stay false when the fence also fails")
	}
}

// TestColdBootZeroDropFenceRetriesAfterAddressAppears5759 proves that a
// program-only fallback with no address-scoped DROP leaves the historical gate
// false, allowing a later failed real invocation to fence an address visible in
// that invocation's snapshot. The DHCP assertion proves classification only;
// this test invokes applyHostInboundFilter directly and does not cover the
// callback-to-applyTailReconciles path.
func TestColdBootZeroDropFenceRetriesAfterAddressAppears5759(t *testing.T) {
	unit := &config.InterfaceUnit{Number: 0, DHCP: true}
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"xpf5759wan": {
			Name:  "xpf5759wan",
			Units: map[int]*config.InterfaceUnit{0: unit},
		},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"untrust": {
			Name:               "untrust",
			Interfaces:         []string{"xpf5759wan.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
	}
	cfg.Security.AddressBook = &config.AddressBook{Addresses: map[string]*config.Address{
		"bad-host": {Name: "bad-host", Value: "10.0.0.5/32"},
	}}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "untrust",
		ToZone:   "junos-host",
		Policies: []*config.Policy{{
			Name:   "block-bad-host",
			Action: config.PolicyDeny,
			Match: config.PolicyMatch{
				SourceAddresses: []string{"bad-host"},
				Applications:    []string{"any"},
			},
		}},
	}}

	d := &Daemon{}
	d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true, "fab0": true, "em0": true})
	if !d.dhcpLeaseChangeRequiresRecompile(cfg) {
		t.Fatal("fixture must be classified for full recompile; this does not prove the apply reaches host authorization")
	}

	assertProjection := func(wantV bool) {
		t.Helper()
		programs := dpuserspace.BuildJunosHostPrograms(cfg)
		if len(programs) != 1 {
			t.Fatalf("P = %d programs, want exactly 1", len(programs))
		}
		views := dpuserspace.BuildZoneHostInboundViews(cfg)
		gotV := hostInboundHasEnforceableView(views)
		if gotV != wantV {
			t.Fatalf("V = %t, want %t; views=%+v", gotV, wantV, views)
		}
		unzonedV4, unzonedV6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
		if len(unzonedV4) != 0 || len(unzonedV6) != 0 {
			t.Fatalf("U4/U6 must both be false, got v4=%v v6=%v", unzonedV4, unzonedV6)
		}
		gotD := gotV || len(unzonedV4) > 0 || len(unzonedV6) > 0
		if gotD != wantV {
			t.Fatalf("D = %t, want %t solely from V", gotD, wantV)
		}
	}
	assertProjection(false)
	if d.hostInboundEnforced.Load() {
		t.Fatal("precondition: hostInboundEnforced must start false")
	}

	injected := errors.New("nft: issue 5759 real load failure")
	cn := xnft.HostInboundJunosHostDenyCounterName("untrust", "ip")
	wantIIFDrop := `iifname "xpf5759wan" ip saddr 10.0.0.5/32 counter name "` + cn + `" drop`
	wantAddressDrop := "ip daddr 198.51.100.57 drop"
	var payloads []string
	orig := nftApplyPayload
	nftApplyPayload = func(payload string) ([]byte, error) {
		index := len(payloads)
		payloads = append(payloads, payload)
		if !strings.Contains(payload, "table inet xpf_hostinbound") {
			t.Fatalf("payload %d is not an xpf_hostinbound table:\n%s", index, payload)
		}
		switch index {
		case 0:
			if !strings.Contains(payload, wantIIFDrop) {
				t.Fatalf("initial real payload missing %q:\n%s", wantIIFDrop, payload)
			}
			return []byte("injected real failure"), injected
		case 1:
			if strings.Contains(payload, "iifname") || strings.Contains(payload, " daddr ") {
				t.Fatalf("initial fallback must have no iifname or address-scoped DROP:\n%s", payload)
			}
			return nil, nil
		case 2:
			if !strings.Contains(payload, wantIIFDrop) || !strings.Contains(payload, "ip daddr 198.51.100.57") {
				t.Fatalf("addressed real payload missing iifname deny or appeared destination:\n%s", payload)
			}
			return []byte("injected real failure"), injected
		case 3:
			if strings.Contains(payload, "iifname") {
				t.Fatalf("addressed fallback must not contain iifname:\n%s", payload)
			}
			if strings.Count(payload, wantAddressDrop) != 1 || strings.Count(payload, " daddr ") != 1 {
				t.Fatalf("addressed fallback must contain exactly one %q and one daddr rule:\n%s", wantAddressDrop, payload)
			}
			if strings.Contains(payload, cn) || strings.Contains(payload, "tcp dport 22 accept") {
				t.Fatalf("addressed fallback must not contain a junos-host counter or service accept:\n%s", payload)
			}
			return nil, nil
		default:
			t.Fatalf("unexpected nft payload index %d:\n%s", index, payload)
			return nil, nil
		}
	}
	defer func() { nftApplyPayload = orig }()

	err := d.applyHostInboundFilter(cfg)
	if !errors.Is(err, injected) {
		t.Fatalf("initial apply error = %v, want wrapped sentinel", err)
	}
	if d.hostInboundEnforced.Load() {
		t.Fatal("zero-drop fallback must leave state false")
	}
	if len(payloads) != 2 {
		t.Fatalf("initial apply payload count = %d, want 2", len(payloads))
	}

	unit.Addresses = []string{"198.51.100.57/24"}
	assertProjection(true)
	err = d.applyHostInboundFilter(cfg)
	if !errors.Is(err, injected) {
		t.Fatalf("addressed apply error = %v, want wrapped sentinel", err)
	}
	if !d.hostInboundEnforced.Load() {
		t.Fatal("address-scoped fallback must publish state true")
	}
	if len(payloads) != 4 {
		t.Fatalf("total payload count = %d, want 4", len(payloads))
	}
}

// TestColdBootFenceUnzonedDropPublishesState5759 proves the independent U4 and
// U6 terms of D. Each row uses a fresh daemon and a successful one-family
// fallback transaction with nil views, so publication derives solely from the
// selected unzoned-address term.
func TestColdBootFenceUnzonedDropPublishesState5759(t *testing.T) {
	tests := []struct {
		name         string
		views        []dpuserspace.ZoneHostInboundView
		unzonedV4    []string
		unzonedV6    []string
		wantDrop     string
		oppositeRule string
	}{
		{
			name:         "ipv4",
			unzonedV4:    []string{"192.0.2.57"},
			wantDrop:     "ip daddr 192.0.2.57 drop",
			oppositeRule: "ip6 daddr",
		},
		{
			name:         "ipv6",
			unzonedV6:    []string{"2001:db8:5759::57"},
			wantDrop:     "ip6 daddr 2001:db8:5759::57 drop",
			oppositeRule: "ip daddr",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &Daemon{}
			v := hostInboundHasEnforceableView(tc.views)
			u4 := len(tc.unzonedV4) > 0
			u6 := len(tc.unzonedV6) > 0
			if v {
				t.Fatal("V must be false for nil views")
			}
			if tc.name == "ipv4" && (!u4 || u6) {
				t.Fatalf("ipv4 U terms = U4:%t U6:%t, want true/false", u4, u6)
			}
			if tc.name == "ipv6" && (u4 || !u6) {
				t.Fatalf("ipv6 U terms = U4:%t U6:%t, want false/true", u4, u6)
			}
			if dValue := v || u4 || u6; !dValue {
				t.Fatal("D must be true solely from the selected U term")
			}
			if d.hostInboundEnforced.Load() {
				t.Fatal("fresh daemon state must be false")
			}

			calls := 0
			orig := nftApplyPayload
			nftApplyPayload = func(payload string) ([]byte, error) {
				calls++
				if calls != 1 {
					t.Fatalf("fallback nft call count = %d, want exactly 1", calls)
				}
				if !strings.Contains(payload, "table inet xpf_hostinbound") {
					t.Fatalf("fallback payload missing xpf_hostinbound table:\n%s", payload)
				}
				if strings.Count(payload, tc.wantDrop) != 1 || strings.Count(payload, " daddr ") != 1 {
					t.Fatalf("fallback must contain exactly one %q and one daddr rule:\n%s", tc.wantDrop, payload)
				}
				if strings.Contains(payload, tc.oppositeRule) {
					t.Fatalf("fallback contains opposite-family daddr rule %q:\n%s", tc.oppositeRule, payload)
				}
				for _, banned := range []string{"iifname", "counter name", "tcp dport", "udp dport", "icmp type echo-request"} {
					if strings.Contains(payload, banned) {
						t.Fatalf("fallback must not contain %q:\n%s", banned, payload)
					}
				}
				return nil, nil
			}
			defer func() { nftApplyPayload = orig }()

			if err := d.installHostInboundColdBootFence(tc.views, tc.unzonedV4, tc.unzonedV6, nil,
				hostInboundDesiredDropAddrs(tc.views, tc.unzonedV4, tc.unzonedV6)); err != nil {
				t.Fatalf("installHostInboundColdBootFence: %v", err)
			}
			if calls != 1 {
				t.Fatalf("fallback nft call count = %d, want 1", calls)
			}
			if !d.hostInboundEnforced.Load() {
				t.Fatal("successful U-only fallback must publish true")
			}
		})
	}
}
