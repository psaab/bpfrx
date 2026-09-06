// #9065, the members whose shape the census gate cannot reach.
//
// The completeness gate next door covers the ORDERING half: a value slot
// declared beside keyword children, where a modifier could overwrite a
// selector. Three members of this issue are a different shape and would not
// appear in that census, so they get cells of their own — and the reason each
// is a separate shape is recorded, so a later reader does not assume the gate
// covers them.

package main

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// zoneNAT9065 answers GetZones and GetNATPoolStats and records GetSessions.
type zoneNAT9065 struct {
	pb.BpfrxServiceClient
	zones    []*pb.ZoneInfo
	pools    []*pb.NATPoolStats
	sessReqs []*pb.GetSessionsRequest
}

func (f *zoneNAT9065) GetZones(context.Context, *pb.GetZonesRequest, ...grpc.CallOption) (*pb.GetZonesResponse, error) {
	return &pb.GetZonesResponse{Zones: f.zones}, nil
}
func (f *zoneNAT9065) GetSessions(_ context.Context, in *pb.GetSessionsRequest, _ ...grpc.CallOption) (*pb.GetSessionsResponse, error) {
	f.sessReqs = append(f.sessReqs, in)
	return &pb.GetSessionsResponse{}, nil
}
func (f *zoneNAT9065) GetNATPoolStats(context.Context, *pb.GetNATPoolStatsRequest, ...grpc.CallOption) (*pb.GetNATPoolStatsResponse, error) {
	return &pb.GetNATPoolStatsResponse{Pools: f.pools}, nil
}

// SHAPE: a TYPE break, not an ordering one — `zone` has a value slot and NO
// keyword children, so it is absent from the gate's census by construction.
//
// `show security flow session zone trust` ran strconv.ParseUint on the value
// and answered `invalid zone "trust"`. It is the only member that failed LOUD.
// Three independent contrasts said it was wrong: the local console resolves the
// name (pkg/cli/session_filter.go), pkg/cmdtree offers zone NAMES as the
// completion set for this exact path, and the SAME binary's `clear security
// flow session zone` takes a string.
func TestFlowSessionZoneAcceptsAName9065(t *testing.T) {
	fake := &zoneNAT9065{zones: []*pb.ZoneInfo{
		{Name: "trust", Id: 7}, {Name: "untrust", Id: 9},
	}}
	c := &ctl{client: fake}
	if err := c.showFlowSession([]string{"zone", "trust"}); err != nil {
		t.Fatalf("`show security flow session zone trust` must be accepted; got %v", err)
	}
	if len(fake.sessReqs) != 1 {
		t.Fatalf("expected exactly one GetSessions; got %d", len(fake.sessReqs))
	}
	if got := fake.sessReqs[0].GetZone(); got != 7 {
		t.Fatalf("zone name must resolve to the id GetSessions filters on: got %d, want 7", got)
	}
}

// THE WILDCARD IS THE TRAP, and this is the cell that matters most. Zone 0 in
// GetSessionsRequest means EVERY zone, so a resolve that failed soft would
// silently WIDEN the inspected set — strictly worse than the loud error it
// replaces, and the exact class of defect being fixed. An unknown name must
// error and must issue NO request.
func TestFlowSessionUnknownZoneDoesNotWiden9065(t *testing.T) {
	fake := &zoneNAT9065{zones: []*pb.ZoneInfo{{Name: "trust", Id: 7}}}
	c := &ctl{client: fake}
	err := c.showFlowSession([]string{"zone", "nosuchzone"})
	if err == nil {
		t.Fatal("an unknown zone must be refused; falling back to zone 0 silently " +
			"matches EVERY zone")
	}
	if !strings.Contains(err.Error(), "nosuchzone") {
		t.Errorf("the error must name the zone the operator typed; got %v", err)
	}
	if len(fake.sessReqs) != 0 {
		t.Fatalf("no GetSessions may be issued for an unresolvable zone; got %d with "+
			"zone=%d", len(fake.sessReqs), fake.sessReqs[0].GetZone())
	}
}

// A zone whose runtime id is 0 (no apply result yet) is indistinguishable on
// the wire from the wildcard, so it is refused rather than sent. Without this
// the resolve would "succeed" into the widest possible filter.
func TestFlowSessionZoneWithNoRuntimeIDRefused9065(t *testing.T) {
	fake := &zoneNAT9065{zones: []*pb.ZoneInfo{{Name: "trust", Id: 0}}}
	c := &ctl{client: fake}
	if err := c.showFlowSession([]string{"zone", "trust"}); err == nil {
		t.Fatal("a zone with runtime id 0 must be refused: id 0 is the request's " +
			"WILDCARD and would silently match every zone")
	}
	if len(fake.sessReqs) != 0 {
		t.Fatalf("no request may be issued; got %d", len(fake.sessReqs))
	}
}

// CONTROL: the numeric form still works, so existing scripts do not break. A
// name takes precedence over an id, which is why this is checked separately
// from the name case rather than assumed.
func TestFlowSessionNumericZoneStillWorks9065(t *testing.T) {
	fake := &zoneNAT9065{zones: []*pb.ZoneInfo{{Name: "trust", Id: 7}}}
	c := &ctl{client: fake}
	if err := c.showFlowSession([]string{"zone", "9"}); err != nil {
		t.Fatalf("a numeric zone id must still be accepted; got %v", err)
	}
	if got := fake.sessReqs[0].GetZone(); got != 9 {
		t.Fatalf("numeric zone = %d, want 9", got)
	}
}

// SHAPE: a DISCARDED operand, not an overwritten one — `pool` has no value slot
// declared in the tree at all, so the census does not reach it either.
//
// `show security nat source pool <name>` read the name off args[2] and threw it
// away, showing every pool. Scoped client-side because the request carries no
// selector, so the daemon does identical work either way.
func TestNATPoolSelectorIsHonoured9065(t *testing.T) {
	fake := &zoneNAT9065{pools: []*pb.NATPoolStats{
		{Name: "pool-a", Address: "198.51.100.0/24"},
		{Name: "pool-b", Address: "203.0.113.0/24"},
	}}
	c := &ctl{client: fake}
	out := captureStdout(t, func() {
		if err := c.handleShowNAT([]string{"source", "pool", "pool-b"}); err != nil {
			t.Fatalf("show security nat source pool pool-b: %v", err)
		}
	})
	if !strings.Contains(out, "pool-b") {
		t.Fatalf("the selected pool must be rendered; got:\n%s", out)
	}
	if strings.Contains(out, "pool-a") {
		t.Fatalf("#9065: the pool name was discarded and every pool was rendered. "+
			"The operator asked about one pool and is shown all of them with nothing "+
			"saying the selector was dropped.\ngot:\n%s", out)
	}
	// CONTROL: the bare form still lists everything, so the fix narrowed the
	// selected case rather than narrowing the command.
	all := captureStdout(t, func() {
		if err := c.handleShowNAT([]string{"source", "pool"}); err != nil {
			t.Fatalf("show security nat source pool: %v", err)
		}
	})
	if !strings.Contains(all, "pool-a") || !strings.Contains(all, "pool-b") {
		t.Fatalf("CONTROL: the unselected form must still list every pool; got:\n%s", all)
	}
}

// An unmatched pool name must FAIL. Printing nothing is the same silence the
// dropped selector produced: "no such pool" and "this pool is idle" must not
// read identically.
func TestNATPoolUnknownNameFails9065(t *testing.T) {
	fake := &zoneNAT9065{pools: []*pb.NATPoolStats{{Name: "pool-a"}}}
	c := &ctl{client: fake}
	_ = captureStdout(t, func() {
		if err := c.handleShowNAT([]string{"source", "pool", "ghost"}); err == nil {
			t.Fatal("an unknown pool name must be refused, not answered with silence")
		}
	})
}

// pingRecorder9065 records whether a Ping was issued at all.
type pingRecorder9065 struct {
	pb.BpfrxServiceClient
	issued int
}

func (f *pingRecorder9065) Ping(context.Context, *pb.PingRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.PingResponse], error) {
	f.issued++
	return nil, context.Canceled
}

// SHAPE: a DISCARDED ERROR, not a dropped selector. handlePing parsed each
// option with `if v, err := ...; err == nil` and no else, so a malformed or
// missing value silently fell back to the default and the operator got a ping
// with different parameters than they typed. Same family — the command
// succeeds while answering a different question — but it is not a tree-declared
// value slot, so the census gate does not reach it.
func TestPingRejectsMalformedOptionValues9065(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"non-numeric count", []string{"192.0.2.1", "count", "abc"}, "count"},
		{"non-numeric size", []string{"192.0.2.1", "size", "big"}, "size"},
		{"missing count value", []string{"192.0.2.1", "count"}, "count"},
		{"missing source value", []string{"192.0.2.1", "source"}, "source"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &pingRecorder9065{}
			c := &ctl{client: fake}
			err := c.handlePing(tc.args)
			if err == nil {
				t.Fatalf("`ping %s` must be refused; silently defaulting sends a "+
					"DIFFERENT ping than the operator typed", strings.Join(tc.args, " "))
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the error must name the option at fault (%q); got %v", tc.want, err)
			}
			if fake.issued != 0 {
				t.Errorf("no Ping may be issued for a rejected option; got %d", fake.issued)
			}
		})
	}
}

// CONTROL: a well-formed option is still accepted and reaches the request, so
// the strictness narrowed the malformed case rather than the command.
func TestPingAcceptsWellFormedOptions9065(t *testing.T) {
	fake := &pingRecorder9065{}
	c := &ctl{client: fake}
	// The stream fake returns an error, so handlePing returns non-nil; what is
	// asserted is that parsing got far enough to ISSUE the RPC.
	_ = c.handlePing([]string{"192.0.2.1", "count", "3", "size", "64",
		"source", "10.0.0.1", "routing-instance", "vr1"})
	if fake.issued != 1 {
		t.Fatalf("a well-formed ping must reach the RPC; issued=%d", fake.issued)
	}
}
