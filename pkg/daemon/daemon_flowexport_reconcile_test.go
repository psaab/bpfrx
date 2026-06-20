package daemon

import (
	"context"
	"path/filepath"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/vrrp"
)

// flowSamplingConfig returns a config that enables NetFlow v9 flow
// export to a single (loopback, unreachable-but-resolvable) collector.
// UDP connect does not require a live listener, so NewExporter succeeds
// with no external dependency.
func flowSamplingConfig(collector string, rate int) *config.Config {
	cfg := &config.Config{}
	cfg.ForwardingOptions.Sampling = &config.SamplingConfig{
		Instances: map[string]*config.SamplingInstance{
			"s": {
				Name:      "s",
				InputRate: rate,
				FamilyInet: &config.SamplingFamily{
					FlowServers: []*config.FlowServer{
						{Address: collector, Port: 2055},
					},
				},
			},
		},
	}
	return cfg
}

// ipfixSamplingConfig augments a v9 sampling config with a
// services flow-monitoring version-ipfix stanza so the IPFIX exporter
// also becomes configured.
func ipfixSamplingConfig(collector string, rate int) *config.Config {
	cfg := flowSamplingConfig(collector, rate)
	cfg.Services.FlowMonitoring = &config.FlowMonitoringConfig{
		VersionIPFIX: &config.NetFlowIPFIXConfig{
			Templates: map[string]*config.NetFlowIPFIXTemplate{
				"t": {Name: "t"},
			},
		},
	}
	return cfg
}

// newFlowTestDaemon builds a daemon with the minimum wiring
// reconcileFlowExporters needs: a non-nil EventReader and a daemon
// context.
func newFlowTestDaemon() *Daemon {
	d := &Daemon{
		daemonCtx:   context.Background(),
		eventReader: logging.NewEventReader(nil, nil),
	}
	return d
}

// TestReconcileFlowExporterAddAfterBoot is the headline #2075 fix:
// flow export NOT configured at boot but ADDED in a later commit must
// start the exporter (previously it never started).
func TestReconcileFlowExporterAddAfterBoot(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)

	// No sampling configured: reconcile is a no-op start.
	if d.reconcileFlowExporters(&config.Config{}) {
		t.Fatal("empty config should not start an exporter")
	}
	if b := d.flowBundle.Load(); b != nil && b.exp != nil {
		t.Fatal("no exporter should exist for empty config")
	}

	// Add sampling in a later commit.
	if !d.reconcileFlowExporters(flowSamplingConfig("127.0.0.1", 100)) {
		t.Fatal("adding flow export must start the exporter")
	}
	if b := d.flowBundle.Load(); b == nil || b.exp == nil {
		t.Fatal("exporter must be live after add-after-boot")
	}
	if d.flowExporter == nil {
		t.Fatal("d.flowExporter must be set after add-after-boot")
	}
}

// TestReconcileFlowExporterRemoveAfterBoot proves a commit that removes
// flow export stops the exporter (impossible before #2075).
func TestReconcileFlowExporterRemoveAfterBoot(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)

	if !d.reconcileFlowExporters(flowSamplingConfig("127.0.0.1", 100)) {
		t.Fatal("initial config must start exporter")
	}
	if b := d.flowBundle.Load(); b == nil || b.exp == nil {
		t.Fatal("exporter must be live")
	}

	// Remove sampling.
	if !d.reconcileFlowExporters(&config.Config{}) {
		t.Fatal("removing flow export must reconcile (stop exporter)")
	}
	if b := d.flowBundle.Load(); b == nil || b.exp != nil {
		t.Fatal("exporter must be stopped after removal")
	}
	if d.flowExporter != nil {
		t.Fatal("d.flowExporter must be nil after removal")
	}
}

// TestReconcileFlowExporterHashGate proves an unrelated / identical
// commit does NOT bounce a healthy exporter — the SAME exporter
// instance survives, preserving its template-refresh + 1-in-N counter
// state.
func TestReconcileFlowExporterHashGate(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)

	if !d.reconcileFlowExporters(flowSamplingConfig("127.0.0.1", 100)) {
		t.Fatal("initial config must start exporter")
	}
	first := d.flowBundle.Load().exp
	if first == nil {
		t.Fatal("exporter must be live")
	}

	// Identical config: gated (no restart).
	if d.reconcileFlowExporters(flowSamplingConfig("127.0.0.1", 100)) {
		t.Fatal("identical config must be hash-gated (no restart)")
	}
	if got := d.flowBundle.Load().exp; got != first {
		t.Fatal("hash-gated reconcile must keep the SAME exporter instance")
	}

	// A real change re-applies and swaps to a new instance.
	if !d.reconcileFlowExporters(flowSamplingConfig("127.0.0.2", 100)) {
		t.Fatal("changed collector must re-apply")
	}
	if got := d.flowBundle.Load().exp; got == first {
		t.Fatal("a real config change must swap to a new exporter instance")
	}
	// A sampling-rate change also re-applies.
	if !d.reconcileFlowExporters(flowSamplingConfig("127.0.0.2", 50)) {
		t.Fatal("changed sampling rate must re-apply")
	}
}

// TestReconcileFlowExporterNoCallbackLeak proves the indirection
// callback is registered exactly once across many reconciles — the
// append-only EventReader callback list never grows.
func TestReconcileFlowExporterNoCallbackLeak(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)

	for i := 0; i < 5; i++ {
		// Alternate collectors so each reconcile actually swaps.
		coll := "127.0.0.1"
		if i%2 == 1 {
			coll = "127.0.0.2"
		}
		d.reconcileFlowExporters(ipfixSamplingConfig(coll, 100))
	}
	// Exactly one v9 callback + one IPFIX callback.
	if n := d.eventReader.CallbackCount(); n != 2 {
		t.Fatalf("expected exactly 2 callbacks (v9 + ipfix), got %d — callback leak", n)
	}
}

// TestReconcileV9IPFIXIndependence proves the two families gate
// independently: adding IPFIX in a later commit must not bounce the
// running v9 exporter.
func TestReconcileV9IPFIXIndependence(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)

	// v9 only at first.
	if !d.reconcileFlowExporters(flowSamplingConfig("127.0.0.1", 100)) {
		t.Fatal("v9 config must start")
	}
	v9 := d.flowBundle.Load().exp
	if v9 == nil {
		t.Fatal("v9 exporter must be live")
	}
	if b := d.ipfixBundlePtr.Load(); b != nil && b.exp != nil {
		t.Fatal("IPFIX must not be configured yet")
	}

	// Add IPFIX in a later commit.
	if !d.reconcileFlowExporters(ipfixSamplingConfig("127.0.0.1", 100)) {
		t.Fatal("adding IPFIX must reconcile")
	}
	if b := d.ipfixBundlePtr.Load(); b == nil || b.exp == nil {
		t.Fatal("IPFIX exporter must be live after add")
	}
	// v9 untouched (same instance).
	if got := d.flowBundle.Load().exp; got != v9 {
		t.Fatal("adding IPFIX must NOT bounce the running v9 exporter")
	}
}

// flowSamplingConfigSrc returns a sampling config that pins a collector
// source-address. An unassignable source IP makes dialCollectors fail,
// exercising the NewExporter create-failure path.
func flowSamplingConfigSrc(collector, source string, rate int) *config.Config {
	cfg := flowSamplingConfig(collector, rate)
	cfg.ForwardingOptions.Sampling.Instances["s"].FamilyInet.SourceAddress = source
	return cfg
}

// TestReconcileFlowExporterRetriesAfterCreateFailure proves a transient
// NewExporter failure (here: an unassignable pinned source-address) does
// NOT hash-gate the exporter into a permanently-dead state — a later
// commit (even of a working config) retries and starts it.
func TestReconcileFlowExporterRetriesAfterCreateFailure(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)

	// 192.0.2.250 (TEST-NET-1) is not assigned to this host, so binding
	// it as a UDP source fails with "cannot assign requested address".
	if !d.reconcileFlowExporters(flowSamplingConfigSrc("127.0.0.1", "192.0.2.250", 100)) {
		t.Fatal("a create-failing reconcile should still report a change")
	}
	if b := d.flowBundle.Load(); b == nil || b.exp != nil {
		t.Fatal("no exporter should be live after a create failure")
	}
	if d.flowHashSet {
		t.Fatal("the hash must NOT be recorded on a create failure " +
			"(else an identical retry would be gated into a dead exporter)")
	}

	// A later commit with a working config must retry and start.
	if !d.reconcileFlowExporters(flowSamplingConfig("127.0.0.1", 100)) {
		t.Fatal("a working config after a create failure must start the exporter")
	}
	if b := d.flowBundle.Load(); b == nil || b.exp == nil {
		t.Fatal("exporter must recover on the next working commit")
	}
}

// TestApplyConfigLockedReconcilesFlowExporters is the NON-tautological
// apply-wiring guard: it drives the REAL applyConfigLocked body (not the
// applyBodyForTest seam) and asserts the flow exporter started. It FAILS
// if the reconcileFlowExporters call is removed from applyConfigLocked.
//
// Mutation check: delete the `d.reconcileFlowExporters(cfg)` line from
// applyConfigLocked and this test fails — d.flowExporter stays nil after
// committing a config that enables flow-monitoring sampling.
func TestApplyConfigLockedReconcilesFlowExporters(t *testing.T) {
	installFakeNetworkctl(t)
	d := &Daemon{
		applySem:    semaphore.NewWeighted(1),
		dp:          &runtimeOnlyApplyTestDP{},
		vrrpMgr:     vrrp.NewManager(),
		store:       newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		eventReader: logging.NewEventReader(nil, nil),
		daemonCtx:   context.Background(),
		opts:        Options{NoDataplane: true},
	}
	t.Cleanup(d.stopFlowExporter)

	if err := d.applyConfigLocked(flowSamplingConfig("127.0.0.1", 100)); err != nil {
		t.Fatalf("applyConfigLocked: %v", err)
	}

	if d.flowExporter == nil {
		t.Fatal("applyConfigLocked did not reconcile the flow exporter: " +
			"a committed forwarding-options sampling stanza left the NetFlow " +
			"exporter unstarted (missing reconcileFlowExporters wiring)")
	}
}
