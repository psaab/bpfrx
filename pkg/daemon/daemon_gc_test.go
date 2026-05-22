package daemon

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
)

func TestDaemonConntrackGCPreservesLegacyDomains(t *testing.T) {
	dp := &legacyRuntimeGCDomainTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			{
				SrcIP:    [4]byte{10, 0, 0, 1},
				DstIP:    [4]byte{10, 0, 0, 2},
				SrcPort:  10001,
				DstPort:  443,
				Protocol: 6,
			}: {
				State:       dataplane.SessStateEstablished,
				LastSeen:    1 << 60,
				Timeout:     3600,
				IngressZone: 7,
			},
		},
	}
	d := &Daemon{dp: dp}
	gc := d.newConntrackGC(time.Millisecond)
	gc.SetSessionLimitEnabled(true)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		gc.Run(ctx)
	}()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if dp.srcUpdates.Load() > 0 && dp.dstUpdates.Load() > 0 && dp.persistentCalls.Load() > 0 {
			cancel()
			<-done
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	t.Fatalf(
		"GC legacy domain calls: srcUpdates=%d dstUpdates=%d persistentCalls=%d, want all > 0",
		dp.srcUpdates.Load(),
		dp.dstUpdates.Load(),
		dp.persistentCalls.Load(),
	)
}

type legacyRuntimeGCDomainTestDP struct {
	dataplane.DataPlane

	v4              map[dataplane.SessionKey]dataplane.SessionValue
	srcUpdates      atomic.Int32
	dstUpdates      atomic.Int32
	persistentCalls atomic.Int32
}

func (d *legacyRuntimeGCDomainTestDP) Start(context.Context) error { return nil }
func (d *legacyRuntimeGCDomainTestDP) Close() error                { return nil }
func (d *legacyRuntimeGCDomainTestDP) Teardown() error             { return nil }

func (d *legacyRuntimeGCDomainTestDP) ApplyConfig(context.Context, *config.Config) (*dataplane.ApplyResult, error) {
	return &dataplane.ApplyResult{}, nil
}

func (d *legacyRuntimeGCDomainTestDP) LastApplyResult() *dataplane.ApplyResult {
	return &dataplane.ApplyResult{}
}

func (d *legacyRuntimeGCDomainTestDP) Link() dataplane.LinkController {
	return noopLinkController{}
}

func (d *legacyRuntimeGCDomainTestDP) HA() dataplane.HAController {
	return dataplane.NewDataPlaneHAController(nil)
}

func (d *legacyRuntimeGCDomainTestDP) Sessions() dataplane.SessionStore {
	return dataplane.NewDataPlaneSessionStore(d)
}

func (d *legacyRuntimeGCDomainTestDP) Telemetry() dataplane.Telemetry {
	return nil
}

func (d *legacyRuntimeGCDomainTestDP) SessionDeltas() dpruntime.SessionDeltaSource {
	return nil
}

func (d *legacyRuntimeGCDomainTestDP) UpdateSessionCountSrc(dataplane.SessionCountKey, uint32) error {
	d.srcUpdates.Add(1)
	return nil
}

func (d *legacyRuntimeGCDomainTestDP) UpdateSessionCountDst(dataplane.SessionCountKey, uint32) error {
	d.dstUpdates.Add(1)
	return nil
}

func (d *legacyRuntimeGCDomainTestDP) ClearSessionCounts() error {
	return nil
}

func (d *legacyRuntimeGCDomainTestDP) GetPersistentNAT() *dataplane.PersistentNATTable {
	d.persistentCalls.Add(1)
	return nil
}

func (d *legacyRuntimeGCDomainTestDP) BatchIterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for key, val := range d.v4 {
		if !fn(key, val) {
			break
		}
	}
	return nil
}

func (d *legacyRuntimeGCDomainTestDP) BatchIterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}
