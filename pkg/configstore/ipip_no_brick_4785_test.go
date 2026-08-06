package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4785 fold r2 F1: the #1960 no-brick property, bound at BOTH ingresses.
//
// The tolerant-path test in pkg/config drives CompileConfigLenient directly.
// That binds the compiler's behaviour, not the property — #1960 no-brick is a
// property of Store.SyncApply / Store.Load, and nothing drove an IPIP config
// through either. Route either through the strict compile, or register the
// gate outside lenientCompileOpts(), and every compiler-level test stays green
// while an already-persisted config stops booting and HA config sync
// alarm-loops.
//
// #6861 F2c: the two ingresses are covered by two tests, because they are two
// separate call sites reaching compileTreeLenient. TestSyncApplyToleratesIpip_4785
// covers the HA peer-sync ingress; TestLoadToleratesIpip_4785 covers the
// disk-boot one. Until #6861 only SyncApply was exercised while the comment
// above claimed both — the Load path was correct in code but had no regression
// of its own, so a future change that made Store.Load compile strictly (the
// literal boot brick this file exists to prevent) would have shipped green.
//
// This is the same argument peer_effective_ipip_4785_test.go makes for the
// STRICT path ("pkg/config's own tests drive the validator directly, which
// leaves the call site unbound"), applied in the other direction. The strict
// half got a store-level wiring guard on that reasoning; the lenient half needs
// one too, and it is the higher-stakes half — a false REJECT here bricks a
// booting node, which is worse than the dead tunnel it complains about.
//
// EXACTLY ONE warning is asserted, not merely "at least one". The #4785 re-gate
// N1 fix exists because the tolerant path emitted the same ~500-character
// paragraph twice per dead endpoint (ValidateConfig registers the advisory, and
// the gate appended it again). That fix is pinned at the compiler; this pins it
// where the operator actually reads it.

// ipipSyncConfig is the hierarchical form of a dead IPIP tunnel — the shape a
// config committed by an older binary is persisted and peer-synced in. The mode
// is never written: an `ip-*` interface infers `mode ipip`.
const ipipSyncConfig = `interfaces {
    ip-0/0/0 {
        tunnel {
            source 10.0.0.1;
            destination 10.0.0.2;
        }
    }
}`

// ipipPeerSyncConfig is the cluster shape: a shared `${node}` tree whose IPIP
// endpoint resolves only under `groups node1`. This is the tree F1 is about —
// the origin commits it green and the peer ingests it — so the no-brick
// property has to hold for it on BOTH nodes' ingress, not just for a plain
// standalone stanza.
const ipipPeerSyncConfig = `groups {
    node0 {
        interfaces {
            ge-0/0/9 {
                unit 0 {
                    family inet {
                        address 10.7.7.1/24;
                    }
                }
            }
        }
    }
    node1 {
        interfaces {
            ip-0/0/0 {
                tunnel {
                    source 10.9.9.1;
                    destination 10.9.9.2;
                }
            }
        }
    }
}
apply-groups "${node}";`

// countIpip4785Warnings returns how many compiled warnings are the #4785 dead-
// endpoint advisory.
func countIpip4785Warnings(warnings []string) int {
	n := 0
	for _, w := range warnings {
		if strings.Contains(w, "#4785") && strings.Contains(w, "mode ipip") {
			n++
		}
	}
	return n
}

// TestSyncApplyToleratesIpip_4785 is the fail-on-revert guard for no-brick at
// the ingress.
//
// RED-on-revert, both shapes: route SyncApply through compileTreeStrict, or
// drop lenientIpipTunnelMode from lenientCompileOpts(), and this fails at
// "SyncApply REJECTED a config carrying a dead IPIP tunnel".
func TestSyncApplyToleratesIpip_4785(t *testing.T) {
	for _, tc := range []struct {
		name    string
		nodeID  int
		content string
	}{
		{
			// Standalone: the plain persisted stanza.
			name:    "standalone",
			nodeID:  -1,
			content: ipipSyncConfig,
		},
		{
			// Cluster, node0's ingress of the peer-only tree. node0's own
			// effective view has NO tunnel at all, so this also pins that the
			// gate does not fire on a view that does not carry the endpoint.
			name:    "cluster_node0_ingests_peer_only_tree",
			nodeID:  0,
			content: ipipPeerSyncConfig,
		},
		{
			// Cluster, node1's ingress of the same tree — the node whose
			// effective view DOES resolve the dead endpoint. This is the one
			// that would be bricked by a strict ingress, and the one the
			// origin's peer gate now rejects at commit time instead.
			name:    "cluster_node1_ingests_its_own_dead_endpoint",
			nodeID:  1,
			content: ipipPeerSyncConfig,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
			if tc.nodeID >= 0 {
				s.SetNodeID(tc.nodeID)
			}

			cfg, err := s.SyncApply(tc.content, nil)
			if err != nil {
				t.Fatalf("SyncApply REJECTED a config carrying a dead IPIP tunnel. The HA "+
					"config-sync ingress is TOLERANT by contract (#1960): a standby that "+
					"refuses the primary's config alarm-loops and diverges the cluster, and "+
					"the same path backs Store.Load, so a node whose already-committed "+
					"config carries this stanza would fail to boot. That is a worse failure "+
					"than the dead tunnel it complains about: %v", err)
			}
			if cfg == nil {
				t.Fatal("SyncApply returned a nil config on the tolerated path")
			}

			// The stanza must be TOLERATED, not dropped: a node that silently
			// lost it would diverge from its peer.
			wantEndpoint := tc.nodeID != 0
			ifc := cfg.Interfaces.Interfaces["ip-0/0/0"]
			if wantEndpoint {
				if ifc == nil || ifc.Tunnel == nil || ifc.Tunnel.Mode != "ipip" {
					t.Fatalf("the tolerant ingress must PRESERVE the tunnel config, got %+v", ifc)
				}
			} else if ifc != nil {
				t.Fatalf("node0's effective view resolves no ip-0/0/0 at all; the fixture "+
					"does not isolate the peer-only shape, got %+v", ifc)
			}

			got := countIpip4785Warnings(cfg.Warnings)
			want := 0
			if wantEndpoint {
				want = 1
			}
			if got != want {
				t.Errorf("#4785 warnings at the ingress = %d, want %d. Two is the #4785 "+
					"re-gate N1 double-registration (ValidateConfig registers the advisory "+
					"and the gate appended it again), which is what the operator actually "+
					"reads on `show system alarms`; zero on a view that carries the endpoint "+
					"is a silently tolerated dead tunnel — the pre-#4785 behaviour. "+
					"warnings: %v", got, want, cfg.Warnings)
			}
		})
	}
}

// TestLoadToleratesIpip_4785 is the DISK-BOOT half of the no-brick guard
// (#6861 F2c): a node whose already-committed config carries a dead IPIP tunnel
// must still boot.
//
// This is the failure the SyncApply test's own message invokes ("the same path
// backs Store.Load, so a node whose already-committed config carries this stanza
// would fail to boot") but never drove. It is the higher-stakes of the two: a
// rejected peer sync alarm-loops one standby, whereas a rejected Load leaves
// ActiveConfig() nil and pushes the daemon into the #1922 bootstrap/lifeline
// state — an operator-visible outage on a box that was working before the
// upgrade.
//
// The tree is written straight to active.json with the committed marker set
// (DB.WriteActiveMarker), NOT through SyncApply. That is deliberate on two
// counts. It models the real scenario — bytes an OLDER binary committed, before
// any gate existed — rather than a config this binary just accepted. And it
// keeps the persistence step off the lenient compile path, so a mutation that
// makes the tolerant compile strict lands on THIS test's own Load assertion
// instead of tripping a precondition borrowed from the SyncApply test; a RED
// that only ever fires in a shared setup step proves nothing about Load.
//
// RED-on-revert: route Store.Load through compileTreeStrict, or drop
// lenientIpipTunnelMode from lenientCompileOpts(), and this fails at
// "Store.Load REFUSED a persisted config".
func TestLoadToleratesIpip_4785(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	tree, errs := config.NewParser(ipipSyncConfig).Parse()
	if len(errs) > 0 {
		t.Fatalf("precondition: the fixture must parse: %v", errs[0])
	}
	if err := newTestStoreAt(t, path).db.WriteActiveMarker(tree, true); err != nil {
		t.Fatalf("precondition: persisting the stanza must succeed: %v", err)
	}

	booted := newTestStoreAt(t, path)
	if err := booted.Load(); err != nil {
		t.Fatalf("Store.Load REFUSED a persisted config carrying a dead IPIP tunnel. "+
			"A config an older binary committed must still BOOT (#1960): a compile "+
			"failure here leaves ActiveConfig() nil, which is exactly the signal that "+
			"forces the daemon into the bootstrap/lifeline state — the box loses its "+
			"config over a tunnel that was already inert: %v", err)
	}

	cfg := booted.ActiveConfig()
	if cfg == nil {
		t.Fatal("Store.Load returned no error but left ActiveConfig() nil; the daemon " +
			"reads that as an uncompiled config and refuses takeover, so a silent nil " +
			"is the same brick as an error")
	}
	// TOLERATED, not dropped: a node that silently lost the stanza would
	// diverge from its peer on the next config comparison.
	ifc := cfg.Interfaces.Interfaces["ip-0/0/0"]
	if ifc == nil || ifc.Tunnel == nil || ifc.Tunnel.Mode != "ipip" {
		t.Fatalf("the tolerant boot must PRESERVE the tunnel config, got %+v", ifc)
	}
	if got := countIpip4785Warnings(cfg.Warnings); got != 1 {
		t.Errorf("#4785 warnings after boot = %d, want 1. Zero is a silently tolerated "+
			"dead tunnel (the pre-#4785 behaviour); two is the re-gate N1 double "+
			"registration. warnings: %v", got, cfg.Warnings)
	}
}

// TestSyncApplyIpipDoesNotRelaxTheStrictCommit_4785 is the over-reach guard for
// the tolerance: accepting the config at the ingress must NOT make the next
// operator commit accept it. Tolerant ingest and a strict commit are the two
// halves of #1960, and a fix that satisfied the first by weakening the second
// would delete this PR's whole point.
//
// Stays GREEN under both reverts.
func TestSyncApplyIpipDoesNotRelaxTheStrictCommit_4785(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if _, err := s.SyncApply(ipipSyncConfig, nil); err != nil {
		t.Fatalf("precondition: the ingress must tolerate the stanza: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("CommitCheck ACCEPTED a dead IPIP tunnel after a tolerated ingest — the " +
			"strict commit gate must stay strict; tolerating it at ingress is a boot-safety " +
			"concession, not a relaxation of the gate (#4785 / #1960)")
	}
	if !strings.Contains(err.Error(), "mode ipip") {
		t.Errorf("CommitCheck must reject for the IPIP reason, not some unrelated one: %v", err)
	}
}

// ipipPeerRetiredPlusIpip is the #6861 F2 shape: node1's `${node}` group carries
// BOTH a retired `system dataplane-type` leaf AND a complete `ip-*` tunnel.
//
// Real peer ingestion strips the retired leaf (rewriteRetiredDataplaneType,
// SyncCaller) BEFORE compiling, so node1 boots and installs the tunnel. The
// peer-effective gate used to be handed the RAW tree, where the unconditional
// retirement validator fails the compile — and ValidatePeerEffectiveStrict
// treats a peer view that will not compile as out of scope and returns nil.
const ipipPeerRetiredPlusIpip = `groups {
    node0 {
        interfaces {
            ge-0/0/9 {
                unit 0 {
                    family inet {
                        address 10.7.7.1/24;
                    }
                }
            }
        }
    }
    node1 {
        system {
            dataplane-type dpdk;
        }
        interfaces {
            ip-0/0/0 {
                tunnel {
                    source 10.9.9.1;
                    destination 10.9.9.2;
                }
            }
        }
    }
}
apply-groups "${node}";`

// TestPeerGateSeesTheTreeThePeerCompiles_4785 is the fail-on-revert guard for
// #6861 F2: the peer-effective gate must evaluate the tree the standby will
// ACTUALLY compile, not the raw candidate.
//
// Without the rewrite the gate did not merely pass — it never RAN its IPIP
// subject at all, which is a different and worse failure than a subject that
// evaluated and was satisfied. The r2 work closed "the gate ran and passed";
// this closes "the gate never ran".
//
// The second half asserts the consequence rather than trusting the mechanism:
// node1's tolerant ingest really does install the endpoint, so a green commit on
// node0 really does strand a dead tunnel on the peer.
//
// RED-on-revert: pass the raw `tree` to ValidatePeerEffectiveStrict again and
// this fails at "node0 COMMITTED a config that gives node1 a dead IPIP tunnel".
func TestPeerGateSeesTheTreeThePeerCompiles_4785(t *testing.T) {
	// The consequence, established FIRST so the assertion below is anchored to
	// a demonstrated outcome rather than to the gate's own bookkeeping.
	peer := newTestStoreAt(t, filepath.Join(t.TempDir(), "peer"))
	peer.SetNodeID(1)
	peerCfg, err := peer.SyncApply(ipipPeerRetiredPlusIpip, nil)
	if err != nil {
		t.Fatalf("precondition: node1's tolerant ingest must ACCEPT this tree "+
			"(#1960 no-brick) — that is what makes the origin's gate the only place "+
			"it can be caught: %v", err)
	}
	ifc := peerCfg.Interfaces.Interfaces["ip-0/0/0"]
	if ifc == nil || ifc.Tunnel == nil || ifc.Tunnel.Mode != "ipip" {
		t.Fatalf("precondition: node1 must actually INSTALL the dead endpoint, else "+
			"there is nothing for the origin gate to prevent: %+v", ifc)
	}

	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	s.SetNodeID(0)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.LoadOverride(ipipPeerRetiredPlusIpip); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	_, err = s.CommitCheck()
	if err == nil {
		t.Fatal("node0 COMMITTED a config that gives node1 a dead IPIP tunnel. The " +
			"peer-effective gate was handed the RAW tree, whose node1 view fails the " +
			"unconditional retired-dataplane validator, so ValidatePeerEffectiveStrict " +
			"took its out-of-scope arm and returned success WITHOUT EVER RUNNING the " +
			"IPIP subject. Production strips that leaf before compiling, so the gate " +
			"must be given the rewritten tree (#6861 F2)")
	}
	if !strings.Contains(err.Error(), "mode ipip") {
		t.Errorf("the rejection must be the IPIP subject firing, not some unrelated "+
			"failure — a gate that rejects for the wrong reason is not the gate "+
			"running: %v", err)
	}
	if !strings.Contains(err.Error(), "peer node1") {
		t.Errorf("the rejection must name the PEER whose view carries the defect: %v", err)
	}
}

// TestPeerGateRewriteDoesNotMutateTheCandidate_4785 is the over-reach guard for
// the F2 fix: modelling the peer's ingest must not edit the tree being
// committed.
//
// rewriteRetiredDataplaneType mutates in place, so passing the candidate
// directly would silently strip the operator's own `dataplane-type` leaf out of
// the committed config — turning a gate into an undeclared config rewrite, and
// removing the leaf that must still SYNC so the standby's own tolerance handles
// it.
//
// Stays GREEN under the revert (the raw-tree version never rewrote anything).
func TestPeerGateRewriteDoesNotMutateTheCandidate_4785(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	s.SetNodeID(0)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.LoadOverride(ipipPeerRetiredPlusIpip); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := s.CommitCheck(); err == nil {
		t.Fatal("precondition: this tree must be rejected for the peer's IPIP endpoint")
	}
	shown := s.ShowCandidate()
	if !strings.Contains(shown, "dataplane-type dpdk") {
		t.Errorf("the peer-gate rewrite leaked into the CANDIDATE: the operator's "+
			"`dataplane-type dpdk` leaf is gone from the tree they are committing. "+
			"The rewrite models the standby's ingest and must run on a CLONE — the "+
			"leaf has to survive to sync so the standby's own tolerance handles it "+
			"(#6861 F2). candidate:\n%s", shown)
	}
}
