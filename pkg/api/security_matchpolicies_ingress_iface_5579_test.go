package api

import (
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// security_matchpolicies_ingress_iface_5579_test.go pins the #5579 REST
// ingress-interface selector: a mixed `trust` zone exposes ssh host-inbound on
// ge-0/0/0.0 only, with a sibling ge-0/0/1.0 that default-denies host SSH. Before
// #5579 the REST match-policies host-inbound classifier OR-ed every effective
// view in the zone and returned on the first admit, so it reported a zone-wide
// `token-admit`/ssh even for a packet entering ge-0/0/1.0 — a FALSE admission for
// the interface the runtime denies. The endpoint now (a) scopes to one
// interface's TRUE posture when ingress_interface is supplied, and (b) reports
// `ambiguous` for an unqualified query when the per-interface views disagree.

// mixedHostInboundAPIStore builds the mixed-zone config via set commands: two
// addressed units in zone `trust`, ge-0/0/0.0 with an ssh host-inbound override
// and ge-0/0/1.0 with none (default-deny). No `to-zone junos-host` policy, so a
// host-bound query resolves to the host-inbound classifier verdict.
func mixedHostInboundAPIStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet(`set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.10/24
set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.10/24
set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh
set security zones security-zone trust interfaces ge-0/0/1.0
set security policies default-policy deny-all`); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// TestMatchPoliciesRESTIngressInterfaceScopesHostInbound is the REST
// fail-on-revert for #5579.
//
// RED-on-revert: drop the ingress_interface plumbing (the IngressInterface field
// on the Query, or the ClassifyHostInboundForInterface scoping) and the
// ge-0/0/1.0 query folds back to the zone-wide first-admit — status becomes
// `token-admit`/ssh instead of `denied`, so the deny assertion fails. Drop the
// per-view ambiguity and the unqualified query reports `token-admit`/ssh instead
// of `ambiguous`.
func TestMatchPoliciesRESTIngressInterfaceScopesHostInbound(t *testing.T) {
	store := mixedHostInboundAPIStore(t)
	s := &Server{store: store}

	base := func() url.Values {
		return url.Values{
			"from_zone": {"trust"}, "to_zone": {"junos-host"},
			"protocol": {"tcp"}, "dst_port": {"22"},
		}
	}

	// ge-0/0/0.0 (ssh override) — admits.
	admit := base()
	admit.Set("ingress_interface", "ge-0/0/0.0")
	if r := matchHostInbound(t, s, admit); r.Data.HostInbound == nil || r.Data.HostInbound.Status != "token-admit" || r.Data.HostInbound.Token != "ssh" {
		t.Errorf("ingress ge-0/0/0.0 host_inbound = %+v, want token-admit/ssh", r.Data.HostInbound)
	}

	// ge-0/0/1.0 (no override) — the TRUE posture is DENY, not the zone-wide
	// first-admit ssh. This is the core #5579 fix.
	deny := base()
	deny.Set("ingress_interface", "ge-0/0/1.0")
	if r := matchHostInbound(t, s, deny); r.Data.HostInbound == nil || r.Data.HostInbound.Status != "denied" {
		t.Errorf("ingress ge-0/0/1.0 host_inbound = %+v, want denied (false-admission #5579)", r.Data.HostInbound)
	}

	// Unqualified (no ingress_interface) — the per-interface views disagree, so the
	// endpoint reports ambiguity instead of the zone-wide first-admit ssh.
	if r := matchHostInbound(t, s, base()); r.Data.HostInbound == nil || r.Data.HostInbound.Status != "ambiguous" {
		t.Errorf("unqualified host_inbound = %+v, want ambiguous", r.Data.HostInbound)
	}
}

// TestMatchPoliciesRESTIngressInterfaceRejectsBadRef pins the fail-closed
// validation: an unknown / zone-mismatched / lifeline ingress_interface is a 400,
// mirroring the src_ip / port / protocol validators, so the host-inbound
// classifier is never scoped to a bogus interface.
func TestMatchPoliciesRESTIngressInterfaceRejectsBadRef(t *testing.T) {
	store := mixedHostInboundAPIStore(t)
	s := &Server{store: store}

	cases := []struct{ name, iface string }{
		{"unknown", "ge-9/9/9.9"},
		{"empty-value-is-not-error", ""}, // absent selector must NOT 400
	}
	for _, c := range cases {
		q := url.Values{"from_zone": {"trust"}, "to_zone": {"junos-host"}, "protocol": {"tcp"}, "dst_port": {"22"}}
		if c.iface != "" {
			q.Set("ingress_interface", c.iface)
		}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/v1/security/match?"+q.Encode(), nil)
		s.matchPoliciesHandler(rr, req)
		switch c.name {
		case "unknown":
			if rr.Code != 400 {
				t.Errorf("%s: status = %d, want 400; body: %s", c.name, rr.Code, rr.Body.String())
			}
		default:
			if rr.Code != 200 {
				t.Errorf("%s: status = %d, want 200; body: %s", c.name, rr.Code, rr.Body.String())
			}
		}
	}
}
