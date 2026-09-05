package userspace

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// The #6691 round 9b MIXED-VERSION MATRIX for the v5 -> v6 snapshot protocol
// bump, measured rather than reasoned.
//
// #6722 bumped 4 -> 5 earlier the same day, and its first matrix measured ONE
// ifindex and generalised to the population; the counterexample was an ifindex
// master forwarded, the buggy head forwarded, and the MIXED pairing dropped —
// strictly worse than both endpoints. So this asks the question the same way it
// should have been asked there: on the REFERENCE CLUSTER SHAPES, not on the
// shape the change was designed around.
//
// That distinction is the whole point. The motivating shape (a route-based
// IPsec tunnel) is the LEAST likely to expose a compatibility defect, because
// it is the one the gate was built for. What matters is what a mixed pairing
// does to a cluster that has no secure tunnel at all — which is every reference
// cluster this project runs.
func TestMixedVersionMatrix_6691(t *testing.T) {
	// (1) THE REFERENCE CLUSTER SHAPE ARMS NOTHING. If the loss userspace
	// cluster carried a flagged row, the gate would be part of its mixed-version
	// story; it does not, so the gate is inert there and the ONLY mechanism in
	// play is the helper's version-equality check.
	t.Run("reference cluster carries no flagged row, so the gate is inert", func(t *testing.T) {
		raw, err := os.ReadFile("../../../docs/ha-cluster-userspace.conf")
		if err != nil {
			t.Skipf("reference cluster config unavailable: %v", err)
		}
		tree, perrs := config.NewParser(string(raw)).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse reference cluster config: %v", perrs)
		}
		cfg, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("compile reference cluster config: %v", err)
		}
		rows := buildInterfaceSnapshots(cfg)
		if len(rows) == 0 {
			t.Fatal("premise broken: the reference cluster compiled to ZERO interface " +
				"rows, so this asserts nothing about it")
		}
		var flagged []string
		for _, row := range rows {
			if row.SecureTunnel {
				flagged = append(flagged, row.Name)
			}
		}
		if len(flagged) != 0 {
			t.Fatalf("the reference cluster carries flagged rows %v — the v6 gate is "+
				"NOT inert there and the mixed-version story for the smoke cluster is "+
				"different from the one this matrix describes", flagged)
		}
		if snapshotRequiresRefusalProtocol(&ConfigSnapshot{Interfaces: rows}) {
			t.Fatal("snapshotRequiresRefusalProtocol disagrees with the row scan above")
		}
		t.Logf("reference cluster: %d interface rows, 0 flagged — gate inert, "+
			"version-equality check is the only mechanism", len(rows))
	})

	// (2) THE VERSION REFUSAL IS NOT A GATE SENTINEL. This is what decides which
	// of the two failure paths a mixed pairing takes, and the two differ in a way
	// that matters: a gate sentinel ABORTS the commit and DISARMS the helper
	// (fail-closed, deliberately); an ordinary error takes the #5679 deferred
	// path, which FAILS the commit while leaving the helper armed on its
	// previous-good snapshot. For a version mismatch the second is correct — the
	// helper never installed the new snapshot, so its previous-good enforcement
	// is intact and disarming it would take a working dataplane down for a
	// handshake disagreement.
	t.Run("helper version refusal takes the ordinary deferred path", func(t *testing.T) {
		// A LITERAL copy of the string the helper produces
		// (server/handlers/snapshot.rs), shaped the way process_control.go
		// returns an ok=false response. Nothing here opens a socket or decodes a
		// helper reply, so this measures the CLASSIFICATION of that text, not
		// that the text is what a helper emits — see
		// TestMixedVersionHelperRefusalFailsTheCommit_6691 (pkg/daemon), which
		// states the same limit.
		helperRefusal := fmt.Errorf("publish userspace snapshot: %w",
			errors.New("unsupported snapshot protocol version 7 (want 6)"))
		if IsRequiredProtocolGateError(helperRefusal) {
			t.Fatal("a version refusal is classified as a required-protocol-gate error, " +
				"so it would ABORT the commit and DISARM the helper. That is wrong for " +
				"this failure: the helper refused the snapshot, so it is still enforcing " +
				"its previous-good image, and disarming it converts a handshake " +
				"disagreement into a dataplane outage")
		}
		// Symmetric direction: an older control plane's v6 snapshot refused by
		// this v7 helper produces the mirror-image string, same classification.
		older := fmt.Errorf("publish userspace snapshot: %w",
			errors.New("unsupported snapshot protocol version 7 (want 8)"))
		if IsRequiredProtocolGateError(older) {
			t.Fatal("the reverse direction is classified as a gate error")
		}
	})

	// (3) THE GATE SENTINEL *IS* ONE — the contrast that makes (2) meaningful.
	// On a config that DOES carry a secure tunnel, a pre-v6 helper would ignore
	// the flag and plan a binding for the xfrmi, so the correct action is the
	// opposite: abort AND disarm, because that helper would MISENFORCE rather
	// than merely fail to parse.
	t.Run("secure-tunnel gate sentinel aborts and disarms", func(t *testing.T) {
		if !IsRequiredProtocolGateError(ErrSecureTunnelProtocolIncompatible) {
			t.Fatal("ErrSecureTunnelProtocolIncompatible is not in " +
				"requiredProtocolGateSentinels — the gate would not abort the commit")
		}
		if !IsRequiredProtocolGateError(fmt.Errorf("wrapped: %w",
			ErrSecureTunnelProtocolIncompatible)) {
			t.Fatal("the sentinel does not survive wrapping")
		}
	})

	// (4) THE TWO PLANES AGREE ON THE NUMBER. A bump that moved only one side
	// would make every pairing a mismatch — including matched deployments.
	t.Run("both planes agree on the version", func(t *testing.T) {
		if ProtocolVersion != secureTunnelSnapshotProtocolVersion {
			t.Fatalf("Go ProtocolVersion = %d, want %d", ProtocolVersion,
				secureTunnelSnapshotProtocolVersion)
		}
		raw, err := os.ReadFile("../../../userspace-dp/src/protocol/control.rs")
		if err != nil {
			t.Skipf("Rust protocol constant unavailable: %v", err)
		}
		want := fmt.Sprintf("pub(crate) const CONFIG_SNAPSHOT_PROTOCOL_VERSION: i32 = %d;",
			secureTunnelSnapshotProtocolVersion)
		if !strings.Contains(string(raw), want) {
			t.Fatalf("Rust CONFIG_SNAPSHOT_PROTOCOL_VERSION is not %d — the planes "+
				"disagree, so EVERY pairing is a mismatch, matched ones included. "+
				"Expected the line %q", secureTunnelSnapshotProtocolVersion, want)
		}
	})
}
