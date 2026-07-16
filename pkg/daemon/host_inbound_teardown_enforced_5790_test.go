package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5790: a SUCCESSFUL no-enforcement teardown of the xpf_hostinbound table must
// clear hostInboundEnforced. Before the fix the flag stayed sticky-true after a
// teardown even though NO table remained, so a later enforceable generation whose
// FIRST real nft load failed took the day-2 RETENTION branch (which assumes a
// retained table still protects the addresses) and SKIPPED the cold-boot fence —
// leaving newly reachable firewall-local addresses UNPROTECTED (fail-open). The
// nft-apply/delete seams (nftApplyPayload / nftDeleteTable) are the package-level
// fakes the existing #5644 host-inbound tests use.

// TestHostInboundTeardownClearsEnforcedThenFailedReinstallFences_5790 is the
// primary fail-on-revert proof for the whole install -> teardown -> failed
// reinstall ordering: an enforceable config installs a real table (flag true), a
// non-enforceable config tears it down (flag must go FALSE), then an enforceable
// config whose real load FAILS must take the cold-boot fence path (fail-closed),
// NOT the day-2 retention branch (there is no retained table after the teardown).
// Reverting the teardown Store(false) makes the flag stay true: the teardown
// assertion goes RED, AND the failed reinstall skips the fence (fencePayload stays
// empty) — a second RED that pins the fail-open the issue describes.
func TestHostInboundTeardownClearsEnforcedThenFailedReinstallFences_5790(t *testing.T) {
	origApply := nftApplyPayload
	origDelete := nftDeleteTable
	defer func() { nftApplyPayload = origApply; nftDeleteTable = origDelete }()

	enforceable := hostInboundTestConfig()
	d := &Daemon{}

	// --- Step 1: enforceable config, real install succeeds -> flag TRUE. ---
	nftApplyPayload = func(string) ([]byte, error) { return nil, nil }
	if err := d.applyHostInboundFilter(enforceable); err != nil {
		t.Fatalf("step 1 (install) apply: %v", err)
	}
	if !d.hostInboundEnforced.Load() {
		t.Fatal("step 1: hostInboundEnforced must be true after a successful real install")
	}

	// --- Step 2: non-enforceable config -> table teardown succeeds -> flag FALSE. ---
	var deleteCalls int
	nftDeleteTable = func(family, name string) ([]byte, error) {
		deleteCalls++
		if family != "inet" || name != "xpf_hostinbound" {
			t.Fatalf("step 2: unexpected delete target %q %q", family, name)
		}
		return nil, nil // teardown succeeds
	}
	nftApplyPayload = func(payload string) ([]byte, error) {
		t.Fatalf("step 2: the no-enforcement teardown path must not apply an nft payload:\n%s", payload)
		return nil, nil
	}
	if err := d.applyHostInboundFilter(&config.Config{}); err != nil {
		t.Fatalf("step 2 (teardown) apply: %v", err)
	}
	if deleteCalls != 1 {
		t.Fatalf("step 2: expected exactly one nftDeleteTable call, got %d", deleteCalls)
	}
	if d.hostInboundEnforced.Load() {
		t.Fatal("step 2 (THE #5790 BUG): a successful teardown must CLEAR hostInboundEnforced; " +
			"it stayed sticky-true after the table was deleted")
	}

	// --- Step 3: enforceable again, real install FAILS -> cold-boot fence path. ---
	injected := errors.New("nft: reinstall real load failed")
	var payloads []string
	var fencePayload string
	nftApplyPayload = func(payload string) ([]byte, error) {
		payloads = append(payloads, payload)
		if realHostInboundPayload(payload) {
			return []byte("Error: could not process rule\n"), injected
		}
		fencePayload = payload // the fence loads
		return nil, nil
	}
	nftDeleteTable = func(string, string) ([]byte, error) {
		t.Fatal("step 3: an enforceable generation must not tear down the table")
		return nil, nil
	}

	err := d.applyHostInboundFilter(enforceable)
	if err == nil || !errors.Is(err, injected) {
		t.Fatalf("step 3: the failed reinstall must surface the nft error, got %v", err)
	}
	if fencePayload == "" {
		t.Fatalf("step 3 (THE #5790 FAIL-OPEN): after the teardown cleared the flag, a failed real "+
			"reinstall MUST take the cold-boot fence path; no fence was installed — the stale-true "+
			"flag took the day-2 retention branch over a table that no longer exists. payloads:\n%v", payloads)
	}
	if len(payloads) != 2 {
		t.Errorf("step 3: expected real + fence (2 nft applies), got %d:\n%v", len(payloads), payloads)
	}
	// The fence must DENY the enforced wan addresses (both families) — fail-closed.
	for _, want := range []string{
		"table inet xpf_hostinbound",
		"ip daddr 172.16.50.8 drop",
		"ip6 daddr 2001:db8:50::8 drop",
	} {
		if !strings.Contains(fencePayload, want) {
			t.Errorf("step 3 fence missing %q\n---\n%s", want, fencePayload)
		}
	}
	// The fence must NOT accept any host service (that would re-open the exposure).
	if strings.Contains(fencePayload, "tcp dport 22 accept") {
		t.Errorf("step 3 fence must not accept a host service (fail-open):\n%s", fencePayload)
	}
	// The fence established enforcement (address-scoped DROP) -> flag true again.
	if !d.hostInboundEnforced.Load() {
		t.Error("step 3: hostInboundEnforced must be true after the address-scoped fence installs")
	}
}

// TestHostInboundTeardownFailureKeepsEnforced_5790 pins the other half of the
// contract: a FAILED teardown must NOT clear hostInboundEnforced, because a table
// the delete could not remove may still be installed and protecting the
// addresses. Clearing it unconditionally would let a later failed install fence
// over (or fail-open relative to) a live table. Moving the Store(false) out of the
// success-only path makes this RED.
func TestHostInboundTeardownFailureKeepsEnforced_5790(t *testing.T) {
	origApply := nftApplyPayload
	origDelete := nftDeleteTable
	defer func() { nftApplyPayload = origApply; nftDeleteTable = origDelete }()

	// Establish enforcement (flag true).
	nftApplyPayload = func(string) ([]byte, error) { return nil, nil }
	d := &Daemon{}
	if err := d.applyHostInboundFilter(hostInboundTestConfig()); err != nil {
		t.Fatalf("setup install: %v", err)
	}
	if !d.hostInboundEnforced.Load() {
		t.Fatal("setup: hostInboundEnforced must be true after a successful real install")
	}

	// Non-enforceable config, but the teardown FAILS.
	injected := errors.New("nft: delete table failed")
	nftDeleteTable = func(string, string) ([]byte, error) {
		return []byte("Error: table busy\n"), injected
	}
	err := d.applyHostInboundFilter(&config.Config{})
	if err == nil || !errors.Is(err, injected) {
		t.Fatalf("teardown failure must be surfaced as an error, got %v", err)
	}
	if !d.hostInboundEnforced.Load() {
		t.Error("teardown FAILURE must NOT clear hostInboundEnforced — a table the delete could " +
			"not remove may still be installed")
	}
}
