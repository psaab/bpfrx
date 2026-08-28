package daemon

import (
	"context"
	"log/slog"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"sync"
)

// captureRecord is one slog record captured by capturingHandler.
type captureRecord struct {
	level slog.Level
	msg   string
	attrs map[string]string
}

// capturingHandler collects slog records for assertion.
//
// #7075: it is installed as the GLOBAL slog default, so anything still logging
// in this process writes through it — including goroutines the test did not
// start and does not join, such as a leaked configstore persistRetryLoop. The
// previous shape appended to a caller-owned `*[]captureRecord` with no
// synchronisation at all, so `go test -race ./pkg/daemon/` reported a DATA RACE
// between two Handle calls, and the test it failed was whichever one happened
// to be running — not the one that leaked the goroutine.
//
// The mutex lives INSIDE the handler and the records are read back through
// records(), so a caller cannot hold the slice directly and forget the lock.
// That is the difference between fixing this instance and making the shape
// unrepresentable: the previous API handed out the address of the slice, which
// is an invitation to read it unguarded, and every caller accepted.
type capturingHandler struct{ sink *captureSink }

// captureSink owns the records and the mutex that guards them.
type captureSink struct {
	mu   sync.Mutex
	recs []captureRecord
}

// newCaptureSink returns a sink ready to be installed in a capturingHandler.
func newCaptureSink() *captureSink { return &captureSink{} }

// records returns a COPY of what has been captured so far, under the lock.
//
// A copy rather than the slice itself: the handler keeps appending for as long
// as it is the slog default, so handing out the live slice would move the race
// from the append to the caller's range loop.
func (s *captureSink) records() []captureRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]captureRecord, len(s.recs))
	copy(out, s.recs)
	return out
}

func (h capturingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h capturingHandler) Handle(_ context.Context, r slog.Record) error {
	attrs := map[string]string{}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})
	h.sink.mu.Lock()
	h.sink.recs = append(h.sink.recs, captureRecord{level: r.Level, msg: r.Message, attrs: attrs})
	h.sink.mu.Unlock()
	return nil
}
func (h capturingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h capturingHandler) WithGroup(string) slog.Handler      { return h }

// addresslessDaemonCfg builds a config with one zone (wan) whose interface has
// no address (the #3698 fail-open window) and one zone (trust) with a static
// address (scoped). withWANAddr controls whether wan's interface has resolved an
// address yet, simulating a DHCP lease landing.
func addresslessDaemonCfg(withWANAddr bool) *config.Config {
	cfg := &config.Config{}
	wan := &config.InterfaceUnit{Number: 0}
	if withWANAddr {
		wan.Addresses = []string{"203.0.113.9/24"}
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-0": {Name: "ge-0-0-0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.1.10/24"}},
		}},
		"ge-0-0-1": {Name: "ge-0-0-1", Units: map[int]*config.InterfaceUnit{0: wan}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"ge-0-0-0.0"}},
		"wan":   {Name: "wan", Interfaces: []string{"ge-0-0-1.0"}},
	}
	return cfg
}

// TestLogHostInboundAddresslessTransitions is the #3698 fail-on-revert proof for
// the daemon-side observability: an addressless enforcing zone logs a WARN once
// on ENTRY (not every apply), and an INFO on RECOVERY when it gains an address.
func TestLogHostInboundAddresslessTransitions(t *testing.T) {
	sink := newCaptureSink()
	prev := slog.Default()
	slog.SetDefault(slog.New(capturingHandler{sink: sink}))
	defer slog.SetDefault(prev)

	d := &Daemon{}

	warnsFor := func(zone string) int {
		n := 0
		for _, r := range sink.records() {
			if r.level == slog.LevelWarn && r.attrs["zone"] == zone {
				n++
			}
		}
		return n
	}
	infosFor := func(zone string) int {
		n := 0
		for _, r := range sink.records() {
			if r.level == slog.LevelInfo && r.attrs["zone"] == zone {
				n++
			}
		}
		return n
	}

	// Apply 1: wan is addressless → exactly one WARN for wan, none for trust.
	d.logHostInboundAddresslessTransitions(addresslessDaemonCfg(false))
	if warnsFor("wan") != 1 {
		t.Fatalf("first apply: wan warns = %d, want 1", warnsFor("wan"))
	}
	if warnsFor("trust") != 0 {
		t.Errorf("scoped trust zone must not warn, got %d", warnsFor("trust"))
	}
	if d.hostInboundFailOpen.addresslessZones["wan"] != true {
		t.Errorf("state not tracked: hostInboundFailOpen.addresslessZones[wan] = %v", d.hostInboundFailOpen.addresslessZones["wan"])
	}

	// Apply 2: still addressless → NO new WARN (state-transition dedup).
	d.logHostInboundAddresslessTransitions(addresslessDaemonCfg(false))
	if warnsFor("wan") != 1 {
		t.Fatalf("second apply: wan warns = %d, want 1 (dedup — must not re-log a persisting window)", warnsFor("wan"))
	}

	// Apply 3: wan gains an address → one INFO recovery, no new WARN, state cleared.
	d.logHostInboundAddresslessTransitions(addresslessDaemonCfg(true))
	if infosFor("wan") != 1 {
		t.Errorf("recovery: wan infos = %d, want 1 (window closed)", infosFor("wan"))
	}
	if warnsFor("wan") != 1 {
		t.Errorf("recovery must not emit another warn, wan warns = %d", warnsFor("wan"))
	}
	if d.hostInboundFailOpen.addresslessZones["wan"] {
		t.Errorf("state not cleared after recovery: hostInboundFailOpen.addresslessZones[wan] still set")
	}
}
