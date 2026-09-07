package userspace

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Issue 8892: `routing_domain` was added to the config snapshot WITHOUT bumping
// ProtocolVersion, so a helper built before it advertised the same 8, passed
// the exact-equality gate, ignored the field, and resolved every interface to
// domain 0 -- the cross-tenant session aliasing #7160 exists to close.
//
// WHAT A LOCKSTEP CHECK WOULD NOT HAVE CAUGHT, and this is the whole design of
// the guard below. A cell asserting "the Go constant equals the Rust constant"
// is the obvious defence and it would have passed straight through this defect:
// BOTH sides stayed at 8 and therefore AGREED. The drift was not between the
// two constants -- it was between the snapshot's SHAPE and its version.
//
// The existing TestSnapshotProtocolVersionLockstepWithRust already pins the two
// constants to each other and is NOT duplicated here: it answers the other
// question (did someone bump one side alone), and it would have passed straight
// through this defect.
//
// So this pins the shape. Add, remove or retype a field on a snapshot struct
// and the digest moves; the cell then demands that ProtocolVersion moved too.
// It cannot tell a compatible addition from an incompatible one, and does not
// try: it forces a human decision at the one moment the decision is cheap,
// which is the moment the field is added.

// snapshotShapeStructs8892 are the structs whose wire shape the helper parses.
// Adding a new snapshot struct here is part of adding one to the protocol.
func snapshotShapeStructs8892() []any {
	return []any{
		ConfigSnapshot{}, InterfaceSnapshot{}, FlowSnapshot{},
		AddressBookSnapshot{}, SnapshotSummary{}, FabricSnapshot{},
	}
}

func shapeDigest8892(t *testing.T) (string, int) {
	t.Helper()
	var lines []string
	var walk func(rt reflect.Type, prefix string, depth int)
	walk = func(rt reflect.Type, prefix string, depth int) {
		if depth > 4 || rt == nil {
			return
		}
		for rt.Kind() == reflect.Ptr || rt.Kind() == reflect.Slice || rt.Kind() == reflect.Array {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			if f.PkgPath != "" {
				continue // unexported: not on the wire
			}
			tag := f.Tag.Get("json")
			lines = append(lines, fmt.Sprintf("%s%s %s %q", prefix, f.Name, f.Type.String(), tag))
			walk(f.Type, prefix+f.Name+".", depth+1)
		}
	}
	for _, s := range snapshotShapeStructs8892() {
		rt := reflect.TypeOf(s)
		walk(rt, rt.Name()+".", 0)
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:]), len(lines)
}

// snapshotShapeGolden8892 is the digest of the wire shape AT ProtocolVersion 10.
// If it moves, the shape changed: either bump ProtocolVersion and update this
// value in the same commit, or explain in the commit message why the change is
// invisible to a helper.
//
// v10 (issue 9054): `ConfigSnapshot.LearnedRouteImportCapped`. ProtocolVersion
// WAS bumped alongside it, deliberately, and the reason is the one this cell's
// header states: an old helper that ignores the field keeps black-holing every
// learned destination whenever the #8355 cap trips, and black-holing IS the
// defect the field was added to fix. That is the "is what it enforced before
// acceptable?" question answering no, so the exact-equality gate must REFUSE
// the pairing rather than let it degrade silently.
// v10 STANDS (issue 9125): `StaticRoute.HasPreference` was added to the typed
// config, which moved this digest because ConfigSnapshot embeds the whole
// Config. It is tagged `json:"-"`, so it is NOT serialized and no helper --
// old or new -- can observe it. This is the "explain why the change is
// invisible to a helper" arm the header offers, not a version bump: bumping for
// a field nothing transmits would spend the one signal that tells a helper the
// wire actually changed.
//
// The digest still moved because this walk records the json TAG, deliberately:
// adding `json:"-"` to an EXISTING wire field would be a silent removal, and
// the cell has to see that. So a tag change costs a golden update and a
// sentence, which is the intended price.
//
// v10 STANDS (issue 9246): `SecurityConfig.MalformedZonePairs` was added to the
// typed config, and ConfigSnapshot embeds the whole Config, so it moved this
// digest for the same reason HasPreference did. Same arm, same answer: it is
// tagged `json:"-"`, it is a COMPILE-TIME DIAGNOSTIC recording zone-pair
// statements whose shape shows a bracketed-list collapse, and it is nil in
// every valid config. Nothing transmits it, so no helper of any vintage can
// observe it, and bumping the protocol for it would spend the one signal that
// says the wire really changed.
//
// v10 STANDS (issue 9424): `InterfacesConfig.MalformedAddresses` was added to
// the typed config, and ConfigSnapshot embeds the whole Config, so it moved
// this digest for the same reason HasPreference and MalformedZonePairs did.
// Same arm, same answer: it is tagged `json:"-"`, it is a COMPILE-TIME
// DIAGNOSTIC recording a token inside a bracketed interface address list that
// is neither a valid address for its family nor an `address` sub-statement, and
// it is nil in every valid config. Nothing transmits it, so no helper of any
// vintage can observe it, and bumping the protocol for it would spend the one
// signal that says the wire really changed.
//
// Recorded here rather than only in a commit message because this is now the
// FOURTH field to reach this cell by embedding, and the fourth to need the same
// paragraph. The general rule the four share: a field added to ANY pkg/config
// struct lands on the helper wire via ConfigSnapshot, so it is answerable to
// this cell whether or not the author was thinking about the helper -- and the
// gate that catches it is `go test ./...`, not the packages the diff touched.
// #9424 is the case in point: its change is entirely inside pkg/config and
// pkg/configstore, and a scoped run over those two packages is green.
const (
	snapshotShapeGolden8892  = "f40353b3185bae9d6d5e95bdd017b8b647c515dc29af82441f838b231a5d143b"
	snapshotShapeVersion8892 = 10
)

func TestSnapshotShapeIsPinnedToProtocolVersion8892(t *testing.T) {
	got, fields := shapeDigest8892(t)
	// LIVENESS: a digest over an empty field set would be stable and would
	// assert nothing. RoutingDomain in particular must be in the walk, since it
	// is the field whose silent addition this cell exists to catch.
	if fields < 50 {
		t.Fatalf("shape walk collected only %d fields — it is not reaching the snapshot structs, "+
			"so the digest below is stable for the wrong reason", fields)
	}
	if !strings.Contains(strings.Join(func() []string {
		var out []string
		rt := reflect.TypeOf(InterfaceSnapshot{})
		for i := 0; i < rt.NumField(); i++ {
			out = append(out, rt.Field(i).Name)
		}
		return out
	}(), ","), "RoutingDomain") {
		t.Fatal("InterfaceSnapshot no longer carries RoutingDomain — this cell was written to " +
			"guard that field's wire contract and can no longer see it")
	}

	if ProtocolVersion != snapshotShapeVersion8892 {
		t.Fatalf("ProtocolVersion is %d but this cell's golden was recorded at %d. "+
			"Update snapshotShapeVersion8892 AND snapshotShapeGolden8892 together, "+
			"in the commit that changes the wire", ProtocolVersion, snapshotShapeVersion8892)
	}
	if got != snapshotShapeGolden8892 {
		t.Errorf("the config-snapshot WIRE SHAPE changed while ProtocolVersion stayed at %d.\n"+
			"  want digest %s\n  got  digest %s\n"+
			"A helper built before this change advertises the same version, passes the "+
			"exact-equality gate, and reads the rows differently. That is #8892: routing_domain "+
			"was added at v8 with no bump, so an old helper resolved every interface to domain 0 "+
			"and reverted #7160's cross-tenant isolation.\n"+
			"Bump ProtocolVersion (and CONFIG_SNAPSHOT_PROTOCOL_VERSION in "+
			"userspace-dp/src/protocol/control.rs) and update both constants here.",
			ProtocolVersion, snapshotShapeGolden8892, got)
	}
}
