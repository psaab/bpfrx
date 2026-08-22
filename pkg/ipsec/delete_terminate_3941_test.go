package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3941: deleting an IPsec VPN and committing must actively TERMINATE the
// deleted connection's live IKE/child SAs, not just unload its config via
// `swanctl --load-all`. Config unload leaves the established SAs forwarding
// until rekey/lifetime expiry — a removed VPN (compromised peer,
// decommissioned site) that keeps carrying traffic is a security gap.
//
// These tests drive Manager.Apply against a recording swanctl exec seam and
// assert that a `swanctl --terminate --ike <conn>` is issued for a deleted
// connection that has a live SA, and only for that connection.

// swanctlRecorder is a swanctl exec double. It records every invocation and
// returns a programmable `--list-sas` body so a test can present live SAs.
type swanctlRecorder struct {
	calls   [][]string
	listSAs string // body returned for `swanctl --list-sas`
	listErr error  // error returned for `swanctl --list-sas` (nil = ok)
	// terminateErr programs a per-connection failure for
	// `swanctl --terminate --ike <name>`; a name absent from the map (the
	// zero value, nil map) terminates successfully. Used by the #6542
	// teardown-debt tests.
	terminateErr map[string]error
}

func (r *swanctlRecorder) run(args ...string) ([]byte, error) {
	r.calls = append(r.calls, args)
	if len(args) > 0 && args[0] == "--list-sas" {
		return []byte(r.listSAs), r.listErr
	}
	if len(args) == 3 && args[0] == "--terminate" && args[1] == "--ike" {
		if err := r.terminateErr[args[2]]; err != nil {
			return []byte("terminate failed"), err
		}
	}
	return nil, nil
}

// terminateCalls returns the connection names passed to
// `swanctl --terminate --ike <name>`.
func (r *swanctlRecorder) terminateCalls() []string {
	var names []string
	for _, c := range r.calls {
		if len(c) == 3 && c[0] == "--terminate" && c[1] == "--ike" {
			names = append(names, c[2])
		}
	}
	return names
}

func (r *swanctlRecorder) sawListSAs() bool {
	for _, c := range r.calls {
		if len(c) > 0 && c[0] == "--list-sas" {
			return true
		}
	}
	return false
}

// newRecordingManager builds a Manager writing to a temp swanctl dir and
// routing every swanctl shell-out through rec.
func newRecordingManager(t *testing.T, rec *swanctlRecorder) *Manager {
	t.Helper()
	m := NewWithConfigDir(t.TempDir())
	m.swanctl = rec.run
	return m
}

// vpnCfg builds an IPsecConfig whose VPNs each name a direct peer IP + PSK so
// renderConfig emits a real connection block.
func vpnCfg(names ...string) *config.IPsecConfig {
	vpns := make(map[string]*config.IPsecVPN, len(names))
	for i, n := range names {
		vpns[n] = &config.IPsecVPN{
			LocalAddr: "10.0.1.1",
			// distinct routable peer per VPN
			Gateway: "10.0.2." + string(rune('1'+i)),
			PSK:     config.Secret("secret-" + n),
		}
	}
	return &config.IPsecConfig{
		VPNs:      vpns,
		Proposals: map[string]*config.IPsecProposal{},
	}
}

// liveSA renders a minimal but parseable `swanctl --list-sas` body for a set
// of established connections.
func liveSA(conns ...string) string {
	var b strings.Builder
	for i, c := range conns {
		b.WriteString(c)
		b.WriteString(": #")
		b.WriteByte(byte('1' + i))
		b.WriteString(", ESTABLISHED, IKEv2, 8f7c1c8e3a2b1234_i* 4d3c2b1a09876543_r\n")
		b.WriteString("  local  '10.0.1.1' @ 10.0.1.1[500]\n")
		b.WriteString("  remote '10.0.2.1' @ 10.0.2.1[500]\n")
		b.WriteString("  " + c + ": #")
		b.WriteByte(byte('1' + i))
		b.WriteString(", reqid 1, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128\n")
		b.WriteString("    installed 42s ago, rekeying in 3358s, expires in 3918s\n")
	}
	return b.String()
}

// TestDeleteVPNTerminatesLiveSA is the RED-on-revert core: deleting a VPN
// that has an active SA issues `swanctl --terminate --ike <conn>` for the
// removed connection. Reverting the fix (drop the terminateRemovedConns call)
// makes terminateCalls empty → this fails.
func TestDeleteVPNTerminatesLiveSA(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)

	// Baseline: two VPNs up. No prior config → nothing removed.
	if err := m.Apply(vpnCfg("site-a", "site-b")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	if got := rec.terminateCalls(); len(got) != 0 {
		t.Fatalf("initial Apply must not terminate anything, got %v", got)
	}
	if rec.sawListSAs() {
		t.Fatalf("initial Apply must not query SAs (nothing removed)")
	}

	// Both connections have live SAs; operator deletes site-a.
	rec.listSAs = liveSA("site-a", "site-b")
	if err := m.Apply(vpnCfg("site-b")); err != nil {
		t.Fatalf("delete Apply: %v", err)
	}

	got := rec.terminateCalls()
	if len(got) != 1 || got[0] != "site-a" {
		t.Fatalf("expected exactly one terminate for the deleted conn "+
			"site-a, got %v", got)
	}
	// The surviving connection must NOT be terminated.
	for _, n := range got {
		if n == "site-b" {
			t.Fatalf("terminated the surviving connection site-b")
		}
	}
}

// TestDeleteLastVPNTerminatesLiveSA covers the Clear() path: deleting the
// only VPN drives Apply → clearConfig, which must still terminate the deleted
// connection's live SA.
func TestDeleteLastVPNTerminatesLiveSA(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)

	if err := m.Apply(vpnCfg("site-a")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}

	rec.listSAs = liveSA("site-a")
	if err := m.Apply(nil); err != nil { // remove every VPN
		t.Fatalf("clear Apply: %v", err)
	}

	got := rec.terminateCalls()
	if len(got) != 1 || got[0] != "site-a" {
		t.Fatalf("expected terminate for deleted conn site-a on clear, got %v", got)
	}
}

// TestDeleteVPNNoActiveSAIsNoOp: deleting a VPN that has no live SA issues no
// terminate — a clean no-op.
func TestDeleteVPNNoActiveSAIsNoOp(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)

	if err := m.Apply(vpnCfg("site-a", "site-b")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}

	// site-a is deleted but no SA is established (empty --list-sas body).
	rec.listSAs = ""
	if err := m.Apply(vpnCfg("site-b")); err != nil {
		t.Fatalf("delete Apply: %v", err)
	}

	if got := rec.terminateCalls(); len(got) != 0 {
		t.Fatalf("deleting a VPN with no active SA must not terminate, got %v", got)
	}
	// It is allowed (and expected) to have queried live SAs to make that
	// decision, but it must never have issued a --terminate.
}

// TestAddAndModifyVPNDoNotTerminate: adding a new VPN or modifying an
// existing one leaves every SA in place — no --terminate, and no --list-sas
// probe at all when nothing was removed.
func TestAddAndModifyVPNDoNotTerminate(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)

	if err := m.Apply(vpnCfg("site-a")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	rec.listSAs = liveSA("site-a")

	// Add site-b (site-a unchanged).
	if err := m.Apply(vpnCfg("site-a", "site-b")); err != nil {
		t.Fatalf("add Apply: %v", err)
	}
	if got := rec.terminateCalls(); len(got) != 0 {
		t.Fatalf("adding a VPN must not terminate, got %v", got)
	}
	if rec.sawListSAs() {
		t.Fatalf("adding a VPN must not query SAs (nothing removed)")
	}

	// Modify site-a's PSK; still no removal.
	mod := vpnCfg("site-a", "site-b")
	mod.VPNs["site-a"].PSK = config.Secret("rotated")
	if err := m.Apply(mod); err != nil {
		t.Fatalf("modify Apply: %v", err)
	}
	if got := rec.terminateCalls(); len(got) != 0 {
		t.Fatalf("modifying a VPN must not terminate, got %v", got)
	}
}

// TestDeleteVPNListSAsErrorFallsBackToUnconditionalTerminate: if the live-SA
// query fails, the deleted connection is still terminated (idempotently) so a
// straggler SA is not left forwarding.
func TestDeleteVPNListSAsErrorFallsBackToUnconditionalTerminate(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)

	if err := m.Apply(vpnCfg("site-a", "site-b")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}

	rec.listErr = errListFailed
	if err := m.Apply(vpnCfg("site-b")); err != nil {
		t.Fatalf("delete Apply: %v", err)
	}

	got := rec.terminateCalls()
	if len(got) != 1 || got[0] != "site-a" {
		t.Fatalf("expected fallback terminate for deleted conn site-a, got %v", got)
	}
}

type listFailedErr struct{}

func (listFailedErr) Error() string { return "list-sas failed" }

var errListFailed = listFailedErr{}
