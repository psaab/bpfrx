package userspace

import (
	"encoding/json"
	"net"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #7917: the reverse companion must not carry the FORWARD direction's ingress
// identity onto the helper wire.
//
// `mirrorSessionPairV4`/`V6` synthesize a reverse companion from the forward
// value. They cleared the cached FIB result but not the #4983 ingress identity,
// so the companion inherited where the FORWARD flow's first packet arrived —
// a prediction of where the reply will land, not an observation of where it did,
// and routing may be asymmetric.
//
// THIS TEST GOES THROUGH THE WIRE, NOT THE STRUCT, ON PURPOSE. The struct-level
// census lives in `pkg/dataplane`. What matters here is the request the helper
// actually receives, and the request does not carry `IngressIfindex` from
// `val.IngressIfindex` at all — since #7095 it is RESOLVED from
// `val.IngressIfaceFold` (`buildSessionSyncRequestV4` -> `resolveIngressFoldLocked`).
// A fix that zeroed only the two node-local fields and left the fold would pass
// a struct-level check and still stamp the forward binding on the companion the
// helper installs. Only reading the emitted request can tell those apart.
//
// The FORWARD assertion is the over-reach control. Clearing the ingress identity
// on both halves would satisfy "the companion carries none" while destroying the
// datum #4983 exists to provide; the forward request must still carry it.

// captureSessionSync stands up the helper session socket, runs `emit`, and
// returns the sync requests the manager transmitted, in order.
func captureSessionSync(t *testing.T, emit func(m *Manager)) []SessionSyncRequest {
	t.Helper()
	dir := t.TempDir()
	ln, err := net.Listen("unix", filepath.Join(dir, "userspace-dp-sessions.sock"))
	if err != nil {
		t.Fatalf("listen session socket: %v", err)
	}
	defer ln.Close()

	got := make(chan SessionSyncRequest, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				dec := json.NewDecoder(conn)
				enc := json.NewEncoder(conn)
				for {
					var req ControlRequest
					if err := dec.Decode(&req); err != nil {
						return
					}
					if req.SessionSync != nil {
						got <- *req.SessionSync
					}
					if err := enc.Encode(ControlResponse{OK: true}); err != nil {
						return
					}
				}
			}()
		}
	}()

	m := New()
	m.proc = &exec.Cmd{}
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	// #7095: make the fold RESOLVE, so a leaked fold is observable as a non-zero
	// wire ifindex. With no resolver every request would carry 0 and the
	// companion assertion would pass without the fix.
	m.SetIngressFoldResolver(func(fold uint32) (uint32, uint16, bool) {
		if fold == forwardTestFold {
			return forwardTestIfindex, forwardTestVLAN, true
		}
		return 0, 0, false
	})

	emit(m)

	var out []SessionSyncRequest
	deadline := time.After(5 * time.Second)
	for len(out) < 2 {
		select {
		case req := <-got:
			out = append(out, req)
		case <-deadline:
			t.Fatalf("only %d session sync requests arrived in 5s; the forward and "+
				"its reverse companion are both required or the comparison below is "+
				"about nothing", len(out))
		}
	}
	return out
}

const (
	forwardTestFold    uint32 = 0xC0FFEE01
	forwardTestIfindex uint32 = 4242
	forwardTestVLAN    uint16 = 80
)

func TestReverseCompanionCarriesNoIngressIdentityV4_7917(t *testing.T) {
	key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 61, 102}, DstIP: [4]byte{172, 16, 80, 200},
		SrcPort: 1111, DstPort: 2222, Protocol: 6,
	}
	val := dataplane.SessionValue{
		ReverseKey: dataplane.SessionKey{
			SrcIP: [4]byte{172, 16, 80, 200}, DstIP: [4]byte{10, 0, 61, 102},
			SrcPort: 2222, DstPort: 1111, Protocol: 6,
		},
		IngressIfindex:   77,
		IngressVlanID:    80,
		IngressIfaceFold: forwardTestFold,
	}
	reqs := captureSessionSync(t, func(m *Manager) { m.mirrorSessionPairV4(key, val) })

	// Identify the pair by SOURCE IP, not port: the builder converts ports
	// network->host (`networkUint16ToHost`), so comparing against the raw
	// literal silently mislabels which request is which — and an inverted label
	// turns this cell's two assertions into each other's opposite, which is a
	// green-for-the-wrong-reason away from a false pass.
	fwd, rev := reqs[0], reqs[1]
	if fwd.SrcIP != "10.0.61.102" {
		fwd, rev = rev, fwd
	}
	if fwd.SrcIP != "10.0.61.102" || rev.SrcIP != "172.16.80.200" {
		t.Fatalf("could not identify the forward/companion pair: src IPs %q and %q",
			reqs[0].SrcIP, reqs[1].SrcIP)
	}

	// Over-reach control: the forward half must KEEP its ingress identity.
	if fwd.IngressIfindex != int(forwardTestIfindex) {
		t.Errorf("the FORWARD request lost its ingress identity (ifindex %d, want %d). "+
			"Clearing it on both halves would satisfy the companion assertion below "+
			"while destroying the datum #4983 exists to provide (#7917)",
			fwd.IngressIfindex, forwardTestIfindex)
	}
	// The subject.
	if rev.IngressIfindex != 0 || rev.IngressVLANID != 0 {
		t.Errorf("the reverse companion carries ingress identity {ifindex %d, vlan %d}, "+
			"which is the FORWARD direction's binding. The reply's own ingress has not "+
			"been observed and routing may be asymmetric, so this names a device on a "+
			"prediction (#7917)", rev.IngressIfindex, rev.IngressVLANID)
	}
}

func TestReverseCompanionCarriesNoIngressIdentityV6_7917(t *testing.T) {
	var src, dst [16]byte
	copy(src[:], net.ParseIP("2001:db8:1::102").To16())
	copy(dst[:], net.ParseIP("2001:db8:2::200").To16())
	key := dataplane.SessionKeyV6{SrcIP: src, DstIP: dst, SrcPort: 1111, DstPort: 2222, Protocol: 6}
	val := dataplane.SessionValueV6{
		ReverseKey:       dataplane.SessionKeyV6{SrcIP: dst, DstIP: src, SrcPort: 2222, DstPort: 1111, Protocol: 6},
		IngressIfindex:   77,
		IngressVlanID:    80,
		IngressIfaceFold: forwardTestFold,
	}
	reqs := captureSessionSync(t, func(m *Manager) { m.mirrorSessionPairV6(key, val) })

	fwd, rev := reqs[0], reqs[1]
	if fwd.SrcIP != "2001:db8:1::102" {
		fwd, rev = rev, fwd
	}
	if fwd.SrcIP != "2001:db8:1::102" || rev.SrcIP != "2001:db8:2::200" {
		t.Fatalf("could not identify the v6 forward/companion pair: src IPs %q and %q",
			reqs[0].SrcIP, reqs[1].SrcIP)
	}
	if fwd.IngressIfindex != int(forwardTestIfindex) {
		t.Errorf("the v6 FORWARD request lost its ingress identity (ifindex %d, want %d) (#7917)",
			fwd.IngressIfindex, forwardTestIfindex)
	}
	if rev.IngressIfindex != 0 || rev.IngressVLANID != 0 {
		t.Errorf("the v6 reverse companion carries the FORWARD direction's ingress "+
			"identity {ifindex %d, vlan %d} (#7917)", rev.IngressIfindex, rev.IngressVLANID)
	}
}
