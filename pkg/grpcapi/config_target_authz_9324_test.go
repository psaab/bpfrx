package grpcapi

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #9324, gRPC half. ConfigTarget's proto3 zero value is CANDIDATE and ShowConfig
// is priced PermView, so a read-only principal that OMITTED the target read
// another session's uncommitted configuration.
//
// WHY THE DEFAULT IS NOT CHANGED HERE, and it is not a preference. proto3 cannot
// distinguish an omitted enum from an explicit zero, so "unset means ACTIVE"
// would also rewrite an EXPLICIT CANDIDATE request into an ACTIVE one — and
// cmd/cli/show.go:420 sends exactly that for the config-mode view, so the change
// would break a real in-tree caller. Renumbering the enum to give it an
// UNSPECIFIED sentinel is a wire REDEFINITION, which this repo treats as the
// rolling-upgrade hazard it is. So this surface is fixed by PRICE: reading a
// candidate costs PermConfig, the permission that lets you be in configuration
// mode at all — which is also the Junos reading, where operational
// `show configuration` renders the committed config and a candidate is only
// visible from configure mode.
//
// The REST twin CAN distinguish absent from explicit (`?target` is a string), so
// it additionally defaults to ACTIVE. Both surfaces agree on the price.

func TestConfigTargetProto3ZeroIsStillCandidate9324(t *testing.T) {
	// The premise. If this ever becomes an UNSPECIFIED sentinel, the pricing
	// below is still correct but its rationale above needs rewriting — so pin
	// the premise rather than leave the comment to rot.
	var unset pb.ShowConfigRequest
	if unset.GetTarget() != pb.ConfigTarget_CANDIDATE {
		t.Fatalf("an omitted ConfigTarget resolves to %v, not CANDIDATE — #9324's rationale is stale",
			unset.GetTarget())
	}
}

func TestCandidateReadRequiresPermConfig9324(t *testing.T) {
	method := "/" + serviceName + "/ShowConfig"

	// Omitted target: proto3 gives CANDIDATE, so it is priced as one.
	got, ok := configTargetReadPermission(method, &pb.ShowConfigRequest{})
	if !ok || got != config.PermConfig {
		t.Fatalf("omitted target -> (%v, %v), want (PermConfig, true) — this is the exact request "+
			"a client that never heard of ConfigTarget sends", got, ok)
	}

	// Explicit CANDIDATE: same price.
	got, ok = configTargetReadPermission(method, &pb.ShowConfigRequest{Target: pb.ConfigTarget_CANDIDATE})
	if !ok || got != config.PermConfig {
		t.Fatalf("explicit CANDIDATE -> (%v, %v), want (PermConfig, true)", got, ok)
	}

	// ACTIVE: not a candidate read, so the route's own PermView still governs.
	// Without this control the gate could price EVERY ShowConfig at PermConfig
	// and still pass the assertions above, breaking read-only `show configuration`.
	if _, ok := configTargetReadPermission(method, &pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE}); ok {
		t.Error("an ACTIVE read was priced as a candidate read; read-only `show configuration` would break")
	}
}

// Only the RPCs that read a config target are priced. A blanket predicate would
// silently re-price the whole service.
func TestOnlyConfigTargetReadsArePriced9324(t *testing.T) {
	for _, m := range []string{
		"/" + serviceName + "/GetSessions",
		"/" + serviceName + "/Commit",
		"/" + serviceName + "/ShowText",
		"/some.other.Service/ShowConfig",
	} {
		if _, ok := configTargetReadPermission(m, &pb.ShowConfigRequest{}); ok {
			t.Errorf("%s was priced as a config-target read", m)
		}
	}
}

// A request of the wrong type on ShowConfig must fail CLOSED. It is unreachable
// through the generated server, but "unreachable" is the assumption that has
// been wrong before, and the safe arm costs nothing.
func TestUnreadableShowConfigRequestFailsClosed9324(t *testing.T) {
	got, ok := configTargetReadPermission("/"+serviceName+"/ShowConfig", struct{}{})
	if !ok || got != config.PermConfig {
		t.Fatalf("an unreadable ShowConfig request -> (%v, %v), want (PermConfig, true)", got, ok)
	}
}
