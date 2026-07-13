package daemon

import (
	"errors"
	"strings"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
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
