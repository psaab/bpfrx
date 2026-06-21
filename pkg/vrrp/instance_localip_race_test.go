package vrrp

import (
	"net"
	"sync"
	"testing"
)

// #2258: sendPacket()/sendPacketIPv6() perform a one-shot LAZY-RESOLVE WRITE of
// localIP/localIPv6 from the run-loop goroutine (when the address was
// unresolved at openSocket() time), while the receiver goroutines
// (receiver/receiverIPv6/parseAfPacketIPv4/parseAfPacketIPv6) READ those fields
// to filter self-sent adverts. With localIP/localIPv6 as plain net.IP the
// write/read was an unsynchronized data race; `go test -race` flags it. The fix
// makes both fields atomic.Pointer[net.IP] accessed only via
// getLocalIP/setLocalIP and getLocalIPv6/setLocalIPv6.
//
// These tests are the fail-on-revert gate: under -race they are CLEAN with the
// atomic fix and DETECT the race if either field is reverted to a plain net.IP
// touched directly by both the lazy-resolve write and the receiver reads. The
// race detector reports on the FIRST unsynchronized concurrent access, so a few
// thousand tightly-interleaved iterations suffice (and keep the test fast even
// under -race on a loaded machine).

// installNopLogger silences slog for the duration of a test so the rx-drop
// warnings emitted while localIP is transiently nil (the advert is not filtered
// and lands on a full rxCh) don't spam output. It reuses the counting logger
// from instance_rxdrop_race_test.go and discards the count.
func installNopLogger(t *testing.T) func() {
	t.Helper()
	_, restore := installCountingLogger(t)
	return restore
}

// TestLocalIPLazyResolveConcurrentWithReceiver drives the lazy-resolve WRITE
// path (mirroring sendPacket's setLocalIP from the run-loop goroutine) and the
// receiver READ path (the real parseAfPacketIPv4, which reads getLocalIP)
// concurrently. The writer alternates the field between nil and the resolved
// address so the resolve transition keeps happening (the production lazy-resolve
// fires once); the reader observes it via the self-sent filter. Under -race this
// FAILS if localIP is reverted to a plain net.IP, and is CLEAN with the
// atomic.Pointer fix.
func TestLocalIPLazyResolveConcurrentWithReceiver(t *testing.T) {
	defer installNopLogger(t)()

	vi := newInstance(Instance{
		Interface: "ge-0-0-2",
		GroupID:   7,
		Priority:  100,
	}, &net.Interface{Name: "ge-0-0-2", Index: 1}, make(chan VRRPEvent, 256), nil)

	resolved := net.IPv4(10, 0, 0, 1).To4()

	// A self-sent IPv4 advert: source == the address the lazy-resolve will
	// install, so the reader exercises the getLocalIP()/srcIP.Equal() filter
	// branch — exactly the field read that races the run-loop write.
	frame := buildEthFrame(t, 0, net.IPv4(10, 0, 0, 1), net.IPv4(224, 0, 0, 18), &VRRPPacket{
		VRID:         7,
		Priority:     100,
		MaxAdvertInt: 100,
		IPAddresses:  []net.IP{net.IPv4(10, 0, 0, 100)},
	})

	const iters = 4000
	var wg sync.WaitGroup
	wg.Add(2)

	// Writer: the lazy-resolve WRITE the run-loop goroutine does in
	// sendPacket() — flipping nil/resolved keeps the resolve branch live.
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			if i%2 == 0 {
				vi.setLocalIP(nil)
			} else {
				vi.setLocalIP(resolved)
			}
		}
	}()

	// Reader: the real receiver-goroutine read path. parseAfPacketIPv4 reads
	// getLocalIP() to filter self-sent adverts.
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			vi.parseAfPacketIPv4(frame, len(frame), 14)
		}
	}()

	wg.Wait()

	// Resolve semantics preserved: once set, the address is readable.
	vi.setLocalIP(resolved)
	if got := vi.getLocalIP(); !got.Equal(resolved) {
		t.Fatalf("getLocalIP() = %v, want %v", got, resolved)
	}
}

// TestLocalIPv6LazyResolveConcurrentWithReceiver is the IPv6 sibling: it drives
// the sendPacketIPv6 lazy-resolve WRITE (setLocalIPv6 from the run-loop
// goroutine) concurrently with the real parseAfPacketIPv6 READ path
// (getLocalIPv6). Under -race this FAILS if localIPv6 is reverted to a plain
// net.IP, and is CLEAN with the atomic.Pointer fix.
func TestLocalIPv6LazyResolveConcurrentWithReceiver(t *testing.T) {
	defer installNopLogger(t)()

	vi := newInstance(Instance{
		Interface:        "ge-0-0-2",
		GroupID:          7,
		Priority:         100,
		VirtualAddresses: []string{"2001:db8::1/64"},
	}, &net.Interface{Name: "ge-0-0-2", Index: 1}, make(chan VRRPEvent, 256), nil)

	resolved := net.ParseIP("fe80::1")

	// Self-sent IPv6 advert sourced from the address the lazy-resolve installs.
	frame := buildEthIPv6Frame(t, 0, net.ParseIP("fe80::1"), net.ParseIP("ff02::12"), &VRRPPacket{
		VRID:         7,
		Priority:     100,
		MaxAdvertInt: 100,
		IPAddresses:  []net.IP{net.ParseIP("2001:db8::1")},
	})

	const iters = 4000
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			if i%2 == 0 {
				vi.setLocalIPv6(nil)
			} else {
				vi.setLocalIPv6(resolved)
			}
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			vi.parseAfPacketIPv6(frame, len(frame), 14)
		}
	}()

	wg.Wait()

	vi.setLocalIPv6(resolved)
	if got := vi.getLocalIPv6(); !got.Equal(resolved) {
		t.Fatalf("getLocalIPv6() = %v, want %v", got, resolved)
	}
}
