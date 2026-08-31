// #7473: the STRUCTURED NAT surfaces must carry the builder's fail-closed
// verdict, not just the CLI text renderers.
//
// A text renderer can be repaired by appending a line. A JSON or protobuf
// object cannot — a consumer parsing `{"type":"pool","pool":"p1"}` has nowhere
// to read that the rule translates nothing, and `hit_packets: 0` reads as "no
// traffic matched" rather than "not armed". That is why these needed a WIRE
// field rather than the same fix the text half got.
//
// The cells drive the real RPCs against a committed config, so they bind the
// HANDLER's population of the field, not the predicate — the predicate already
// has its own tests in pkg/config, and a cell that called it directly would
// pass on a handler that never consulted it.
//
// EVERY CELL CARRIES AN ARMED CONTROL. A handler that consults the predicate
// and one that hardcodes `not_installed = true` produce identical output for a
// disarmed rule, so the disarmed leg alone cannot tell them apart.
package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// natStructuredServer applies `content` through the TOLERANT peer-sync path
// and returns a server over the result.
//
// It cannot use LoadSet+Commit. #5877's strict commit gate REJECTS a rule that
// references an empty pool, and #7640's rejects a destination rule with no
// action — so a disarmed rule can never reach an operator surface by way of a
// local commit. `SyncApply` is the path by which it actually does: the tolerant
// ingress used by HA peer-sync, boot and rollback, which downgrades those gates
// to warnings (`compileTreeLenient`).
//
// That is not a convenience. It is the reason the whole #6534 family exists —
// the objects these surfaces lie about are precisely the ones a tolerant load
// admits and a strict commit would have refused. A fixture built through
// Commit could not reproduce the state under test at all.
func natStructuredServer(t *testing.T, content string) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := store.SyncApply(content, nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	return &Server{store: store}
}

// A source pool with NO members is `empty_pool`: the builder installs no
// allocator, so every rule translating through it is not installed. The pool is
// declared with an address and then the address removed, because a pool with no
// address at all does not survive the parser.
// sourceCfg renders a one-rule source-NAT config. `addr` empty produces the
// EMPTY POOL the builder refuses; a non-empty one is the armed control.
func sourceCfg(addr string) string {
	pool := "pool p1 {\n"
	if addr != "" {
		pool += "address " + addr + ";\n"
	}
	pool += "port { range low 1024 high 2023; }\n}\n"
	return "security {\nnat {\nsource {\n" + pool +
		"rule-set rs {\nfrom zone trust;\nto zone untrust;\n" +
		"rule r1 {\nmatch { source-address 10.0.0.0/8; }\n" +
		"then { source-nat { pool p1; } }\n}\n}\n}\n}\n}\n"
}

// destCfg renders a one-rule destination-NAT config. `action` empty produces
// the ACTIONLESS rule the builder excludes.
// destCfgPoolNoAddress: the rule references a pool that EXISTS but carries no
// address, so DestinationNATRuleExcludedReason excludes it while the rule still
// has a pool name and therefore reaches every renderer.
func destCfgPoolNoAddress() string {
	return "security {\nnat {\ndestination {\npool dp1 { }\n" +
		"rule-set drs {\nfrom zone untrust;\n" +
		"rule dr1 {\nmatch { destination-address 203.0.113.10/32; }\n" +
		"then { destination-nat { pool dp1; } }\n}\n}\n}\n}\n}\n"
}

func destCfg(action bool) string {
	then := ""
	if action {
		then = "then { destination-nat { pool dp1; } }\n"
	}
	return "security {\nnat {\ndestination {\npool dp1 { address 10.0.0.5; }\n" +
		"rule-set drs {\nfrom zone untrust;\n" +
		"rule dr1 {\nmatch { destination-address 203.0.113.10/32; }\n" +
		then + "}\n}\n}\n}\n}\n"
}

func TestGetNATSourceCarriesTheNotInstalledVerdict7473(t *testing.T) {
	disarmed := natStructuredServer(t, sourceCfg(""))
	resp, err := disarmed.GetNATSource(context.Background(), &pb.GetNATSourceRequest{})
	if err != nil {
		t.Fatalf("GetNATSource(disarmed): %v", err)
	}
	if len(resp.GetRules()) != 1 {
		t.Fatalf("fixture: want 1 rule, got %d — the assertions below would be vacuous",
			len(resp.GetRules()))
	}
	r := resp.GetRules()[0]
	if !r.GetNotInstalled() {
		t.Errorf("GetNATSource returned a rule the builder REFUSED with " +
			"not_installed=false. A consumer sees type=pool and a pool name and " +
			"has nowhere to learn the rule translates nothing (#7473)")
	}
	if r.GetNotInstalledReason() == "" {
		t.Error("not_installed is set with no reason; the remedy differs by cause " +
			"(no members, malformed member, aggregate budget) and the operator is " +
			"left inferring it")
	}

	// Control: an armed rule must NOT be marked, or the handler is stamping the
	// field unconditionally and the leg above proves nothing.
	armed := natStructuredServer(t, sourceCfg("203.0.113.10/32"))
	aresp, err := armed.GetNATSource(context.Background(), &pb.GetNATSourceRequest{})
	if err != nil {
		t.Fatalf("GetNATSource(armed): %v", err)
	}
	if len(aresp.GetRules()) != 1 {
		t.Fatalf("armed fixture: want 1 rule, got %d", len(aresp.GetRules()))
	}
	if aresp.GetRules()[0].GetNotInstalled() {
		t.Errorf("GetNATSource marked an ARMED rule not_installed (reason=%q) — the "+
			"handler is not consulting the predicate", aresp.GetRules()[0].GetNotInstalledReason())
	}
}

func TestGetNATRuleStatsCarriesTheNotInstalledVerdict7473(t *testing.T) {
	disarmed := natStructuredServer(t, sourceCfg(""))
	resp, err := disarmed.GetNATRuleStats(context.Background(), &pb.GetNATRuleStatsRequest{})
	if err != nil {
		t.Fatalf("GetNATRuleStats(disarmed): %v", err)
	}
	if len(resp.GetRules()) != 1 {
		t.Fatalf("fixture: want 1 rule, got %d", len(resp.GetRules()))
	}
	if !resp.GetRules()[0].GetNotInstalled() {
		t.Errorf("GetNATRuleStats attaches hit counters to a rule the builder " +
			"REFUSED without marking it. This is the issue's archetype: the 0 " +
			"reads as \"no traffic matched\" rather than \"not armed\" (#7473)")
	}

	armed := natStructuredServer(t, sourceCfg("203.0.113.10/32"))
	aresp, err := armed.GetNATRuleStats(context.Background(), &pb.GetNATRuleStatsRequest{})
	if err != nil {
		t.Fatalf("GetNATRuleStats(armed): %v", err)
	}
	if len(aresp.GetRules()) != 1 || aresp.GetRules()[0].GetNotInstalled() {
		t.Errorf("GetNATRuleStats marked an ARMED rule not_installed; the disarmed " +
			"leg above proves nothing")
	}
}

// GetNATRuleStats has TWO append sites, and this cell exists because the
// mutation matrix proved the first one was not enough.
//
// It is the only getter listed under BOTH families in the #6534 census: one
// arm walks `NAT.Source` and takes the source predicate, the other walks
// `NAT.Destination` and takes the destination one. Deleting only the
// destination arm left the source cell above GREEN — the behavioural coverage
// was entirely on one arm, and a reader counting functions would have seen a
// tested getter.
//
// The census did red on that mutation, but a census is a static-analysis guard:
// per #8185 it cannot see a partly-annotated function, so an edit that kept
// reaching the predicate on one arm while breaking the other would leave it
// green with nothing else watching.
func TestGetNATRuleStatsDestinationArmCarriesTheVerdict7473(t *testing.T) {
	// The destination arm is gated on `req.NatType == "destination"`; the
	// default request reaches only the source arm, which is why the first
	// draft of this cell found zero rules.
	//
	// The rule must also CARRY a pool: an actionless rule is excluded by the
	// builder but the arm renders it with `action = "off"`, so the fixture uses
	// a pool that exists with no address — excluded by
	// DestinationNATRuleExcludedReason while still reaching this code.
	disarmed := natStructuredServer(t, destCfgPoolNoAddress())
	resp, err := disarmed.GetNATRuleStats(context.Background(),
		&pb.GetNATRuleStatsRequest{NatType: "destination"})
	if err != nil {
		t.Fatalf("GetNATRuleStats(disarmed dest): %v", err)
	}
	if len(resp.GetRules()) != 1 {
		t.Fatalf("fixture: want 1 destination rule, got %d — this cell is about the "+
			"DESTINATION arm and must actually reach it", len(resp.GetRules()))
	}
	if !resp.GetRules()[0].GetNotInstalled() {
		t.Errorf("GetNATRuleStats attaches hit counters to a DESTINATION rule the " +
			"builder EXCLUDES without marking it. Annotating only the source arm " +
			"satisfies a reader counting functions and leaves destination rules " +
			"lying (#7473)")
	}

	armed := natStructuredServer(t, destCfg(true))
	aresp, err := armed.GetNATRuleStats(context.Background(),
		&pb.GetNATRuleStatsRequest{NatType: "destination"})
	if err != nil {
		t.Fatalf("GetNATRuleStats(armed dest): %v", err)
	}
	if len(aresp.GetRules()) != 1 || aresp.GetRules()[0].GetNotInstalled() {
		t.Errorf("GetNATRuleStats marked an ARMED destination rule not_installed; " +
			"the disarmed leg above proves nothing")
	}
}

func TestGetNATPoolStatsCarriesTheNotInstalledVerdict7473(t *testing.T) {
	disarmed := natStructuredServer(t, sourceCfg(""))
	resp, err := disarmed.GetNATPoolStats(context.Background(), &pb.GetNATPoolStatsRequest{})
	if err != nil {
		t.Fatalf("GetNATPoolStats(disarmed): %v", err)
	}
	if len(resp.GetPools()) != 1 {
		t.Fatalf("fixture: want 1 pool, got %d", len(resp.GetPools()))
	}
	if !resp.GetPools()[0].GetNotInstalled() {
		t.Errorf("GetNATPoolStats returned a REFUSED pool with not_installed=false. " +
			"Its capacity is 0, but a 0 is ambiguous — no members, a malformed " +
			"member and the aggregate budget all produce it and have different " +
			"remedies, which is why the verdict is stated rather than inferred (#7473)")
	}

	armed := natStructuredServer(t, sourceCfg("203.0.113.10/32"))
	aresp, err := armed.GetNATPoolStats(context.Background(), &pb.GetNATPoolStatsRequest{})
	if err != nil {
		t.Fatalf("GetNATPoolStats(armed): %v", err)
	}
	if len(aresp.GetPools()) != 1 || aresp.GetPools()[0].GetNotInstalled() {
		t.Errorf("GetNATPoolStats marked an ARMED pool not_installed; the disarmed " +
			"leg above proves nothing")
	}
}

// The destination family closed completely with this change, so its cell is
// what keeps it closed.
func TestGetNATDestinationCarriesTheNotInstalledVerdict7473(t *testing.T) {
	// A destination rule whose pool carries no address is excluded by
	// DestinationNATRuleExcludedReason.
	disarmed := natStructuredServer(t, destCfg(false))
	resp, err := disarmed.GetNATDestination(context.Background(), &pb.GetNATDestinationRequest{})
	if err != nil {
		t.Fatalf("GetNATDestination(disarmed): %v", err)
	}
	if len(resp.GetRules()) != 1 {
		t.Fatalf("fixture: want 1 rule, got %d", len(resp.GetRules()))
	}
	if !resp.GetRules()[0].GetNotInstalled() {
		t.Errorf("GetNATDestination returned a rule the builder EXCLUDES with " +
			"not_installed=false (#7473)")
	}

	armed := natStructuredServer(t, destCfg(true))
	aresp, err := armed.GetNATDestination(context.Background(), &pb.GetNATDestinationRequest{})
	if err != nil {
		t.Fatalf("GetNATDestination(armed): %v", err)
	}
	if len(aresp.GetRules()) != 1 || aresp.GetRules()[0].GetNotInstalled() {
		t.Errorf("GetNATDestination marked an ARMED rule not_installed; the disarmed " +
			"leg above proves nothing")
	}
}
