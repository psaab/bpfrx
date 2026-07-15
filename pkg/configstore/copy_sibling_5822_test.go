package configstore

import (
	"slices"
	"testing"
)

// #5822 integration: the operational `copy` path (Store.Copy -> ConfigTree.CopyPath)
// must resolve a NON-FIRST same-keyword destination parent (`security-zone zZ`,
// the third of three siblings) and land the copied subtree under it — not fail
// because the pre-#5822 insertNode stopped at the first same-keyword sibling.
//
// FAIL-ON-REVERT: routed back through insertNode, Store.Copy returns a
// "destination parent path element ... not found" error (insertNode descends the
// first sibling zA and cannot find zZ), so the `Copy` call errors and this test
// goes RED.
func TestStoreCopy_ResolvesNonFirstSiblingZone_5822(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	// Three same-keyword `security-zone` siblings; the copy target zZ is LAST.
	for _, cmd := range []string{
		"security zones security-zone zA host-inbound-traffic system-services ssh",
		"security zones security-zone zB host-inbound-traffic system-services ping",
		"security zones security-zone zZ host-inbound-traffic system-services dns",
	} {
		if err := s.SetFromInput(cmd); err != nil {
			t.Fatalf("set %q: %v", cmd, err)
		}
	}

	// Copy zA's `system-services ssh` into zZ. The destination PARENT
	// (security-zone zZ host-inbound-traffic) passes through the NON-FIRST
	// same-keyword sibling zZ.
	if err := s.Copy(
		[]string{"security", "zones", "security-zone", "zA", "host-inbound-traffic", "system-services", "ssh"},
		[]string{"security", "zones", "security-zone", "zZ", "host-inbound-traffic", "system-services", "ssh"},
	); err != nil {
		t.Fatalf("Store.Copy into non-first sibling zone failed: %v (insertNode cannot resolve zZ — #5822)", err)
	}
	if !s.IsDirty() {
		t.Error("store should be dirty after copy")
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit after copy: %v", err)
	}

	cfg := s.ActiveConfig()
	if cfg == nil {
		t.Fatal("compiled config is nil after commit")
	}
	zZ := cfg.Security.Zones["zZ"]
	if zZ == nil || zZ.HostInboundTraffic == nil {
		t.Fatalf("zZ or its host-inbound-traffic missing after copy: %+v", cfg.Security.Zones["zZ"])
	}
	if !slices.Contains(zZ.HostInboundTraffic.SystemServices, "ssh") {
		t.Fatalf("copied `ssh` did not land under zZ; zZ host-inbound services = %v (copy resolved the wrong "+
			"same-keyword parent — #5822)", zZ.HostInboundTraffic.SystemServices)
	}
	// It must NOT have leaked into the OTHER siblings (the #5822 bug lands it
	// under the first sibling).
	if zB := cfg.Security.Zones["zB"]; zB != nil && zB.HostInboundTraffic != nil &&
		slices.Contains(zB.HostInboundTraffic.SystemServices, "ssh") {
		t.Fatalf("copied `ssh` leaked into wrong sibling zB: %v (#5822)", zB.HostInboundTraffic.SystemServices)
	}
}
