// #5719: the kernel nft host-inbound read used to collapse THREE distinct kernel
// states into one indistinguishable answer — real policy loaded, the #5644 M37
// cold-boot fail-closed FENCE (table PRESENT and actively DROPping, but rendered
// with deliberately NO named counters), and table ABSENT. Only the last of those
// makes "0 host-inbound kernel denies" true, yet REST published an AUTHORITATIVE
// zero (host_inbound_kernel_denies_unavailable absent/false) for the fence too —
// i.e. it certified "no denies" during exactly the degraded window in which the
// appliance is dropping host-bound traffic. That contradicts the #3345 /
// #3681-H05 "counter unavailable != zero" contract the same handler already
// honours for a netlink read failure.
//
// The fix routes the counterless-table state onto the EXISTING Unavailable
// channel (no new REST field, no new Prometheus series — the applied-state latch
// and a dedicated enforcement-degraded discriminator are a separate work item).
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/dataplane"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// hostInboundFenceStateCases enumerates the four kernel states the REST and
// Prometheus surfaces must keep distinguishable. Shared by the two tests below
// so the two surfaces cannot drift apart on the same input.
var hostInboundFenceStateCases = []struct {
	name  string
	state xnft.HostInboundTableState
	rows  []xnft.HostInboundDenyCount
	// wantUnavailable is the REST marker; it is also "Prometheus bumps
	// xpf_counter_read_errors_total", the analogue channel.
	wantUnavailable bool
	wantAggregate   uint64
	wantRows        int
}{
	{
		// NEGATIVE CONTROL: no table, no enforcement, so zero denies is TRUE and
		// must stay authoritative. Unchanged from pre-#5719 behaviour.
		name:            "table absent stays an authoritative zero",
		state:           xnft.HostInboundTableAbsent,
		rows:            nil,
		wantUnavailable: false,
		wantAggregate:   0,
		wantRows:        0,
	},
	{
		// THE DEFECT: fence installed, dropping, uncounted. The zero must NOT be
		// presented as authoritative.
		name:            "counterless fence table is not authoritative",
		state:           xnft.HostInboundTableCounterless,
		rows:            nil,
		wantUnavailable: true,
		wantAggregate:   0,
		wantRows:        0,
	},
	{
		// THE ASSERTION THAT MATTERS: real counter objects exist and merely read
		// zero. If the fix had made every zero unavailable, this goes RED.
		name:  "real counters reading zero stay AUTHORITATIVE",
		state: xnft.HostInboundTableCounted,
		rows: []xnft.HostInboundDenyCount{
			{Zone: "wan", Family: "ip", Packets: 0, Bytes: 0},
			{Zone: "wan", Family: "ip6", Packets: 0, Bytes: 0},
		},
		wantUnavailable: false,
		wantAggregate:   0,
		wantRows:        2,
	},
	{
		name:  "real counters with traffic unchanged",
		state: xnft.HostInboundTableCounted,
		rows: []xnft.HostInboundDenyCount{
			{Zone: "wan", Family: "ip", Packets: 7, Bytes: 700},
			{Zone: "wan", Family: "ip6", Packets: 3, Bytes: 300},
		},
		wantUnavailable: false,
		wantAggregate:   10,
		wantRows:        2,
	},
}

// TestGlobalStatsCounterlessHostInboundTableNotAuthoritative pins the REST half.
//
// RED on revert: with the counterless case folded back into the else-branch
// (pre-#5719 `if err != nil { Unavailable } else { accumulate }`), the fence row
// asserts "HostInboundKernelDeniesUnavailable = false ... a counterless table is
// an ENFORCING one".
func TestGlobalStatsCounterlessHostInboundTableNotAuthoritative(t *testing.T) {
	for _, tt := range hostInboundFenceStateCases {
		t.Run(tt.name, func(t *testing.T) {
			orig := readHostInboundDenyCounters
			defer func() { readHostInboundDenyCounters = orig }()
			readHostInboundDenyCounters = func() ([]xnft.HostInboundDenyCount, xnft.HostInboundTableState, error) {
				return tt.rows, tt.state, nil
			}

			s := &Server{dp: &idxValueAPIDP{Manager: dataplane.New()}}
			rr := httptest.NewRecorder()
			s.globalStatsHandler(rr, httptest.NewRequest("GET", "/api/v1/statistics/global", nil))
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200. body=%s", rr.Code, rr.Body.String())
			}
			data := decodeGlobalStats(t, rr)

			if data.HostInboundKernelDeniesUnavailable != tt.wantUnavailable {
				t.Errorf("HostInboundKernelDeniesUnavailable = %v, want %v "+
					"(a counterless table is an ENFORCING one whose 0 cannot be "+
					"certified; an absent table and real zero-valued counters both can)",
					data.HostInboundKernelDeniesUnavailable, tt.wantUnavailable)
			}
			if data.HostInboundKernelDenies != tt.wantAggregate {
				t.Errorf("HostInboundKernelDenies = %d, want %d",
					data.HostInboundKernelDenies, tt.wantAggregate)
			}
			if len(data.HostInboundKernelDenyDetail) != tt.wantRows {
				t.Errorf("HostInboundKernelDenyDetail = %+v, want %d rows",
					data.HostInboundKernelDenyDetail, tt.wantRows)
			}
		})
	}
}

// TestHostInboundKernelDeniesCounterlessBumpsReadError pins the Prometheus half
// on the SAME state table, so the two surfaces cannot disagree about which zero
// is authoritative. The analogue of the REST Unavailable marker is the
// xpf_counter_read_errors_total bump (no series exists to omit in the counterless
// state — there are no counter objects to label), matching what the collector
// already does on a netlink read failure.
//
// RED on revert: without the counterless branch the fence row bumps nothing, so
// "want counterReadErrors bumped" fires. The zero-valued-counters row is the
// over-trigger guard: it must emit its two series and bump NOTHING.
func TestHostInboundKernelDeniesCounterlessBumpsReadError(t *testing.T) {
	for _, tt := range hostInboundFenceStateCases {
		t.Run(tt.name, func(t *testing.T) {
			orig := readHostInboundDenyCounters
			defer func() { readHostInboundDenyCounters = orig }()
			readHostInboundDenyCounters = func() ([]xnft.HostInboundDenyCount, xnft.HostInboundTableState, error) {
				return tt.rows, tt.state, nil
			}

			c := newCollector(&Server{})
			ch := make(chan prometheus.Metric, 8)
			c.collectHostInboundKernelDenies(ch)
			close(ch)

			series := 0
			for range ch {
				series++
			}
			if series != tt.wantRows {
				t.Errorf("emitted %d kernel-deny series, want %d", series, tt.wantRows)
			}
			bumped := c.counterReadErrors.Load() > 0
			if bumped != tt.wantUnavailable {
				t.Errorf("counterReadErrors bumped = %v, want %v (the Prometheus "+
					"analogue of the REST unavailable marker must agree with it)",
					bumped, tt.wantUnavailable)
			}
		})
	}
}
