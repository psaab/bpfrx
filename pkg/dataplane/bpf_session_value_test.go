package dataplane

import (
	"testing"
	"unsafe"
)

// Sizes of the on-map C `struct session_value` / `struct session_value_v6`
// conntrack ABI (bpf/headers/xpf_conntrack.h), mirrored by the Rust helper's
// BpfSessionValueV4 / BpfSessionValueV6 and asserted on the Rust side at
// userspace-dp/src/afxdp/bpf_map_tests.rs (size_of == 128 / 176). These are
// the authoritative on-map value sizes — the Go map registration MUST match
// them, not sizeOf[SessionValue] (which is 8 bytes larger due to the sync-only
// Generation field, #2360).
const (
	conntrackValueSizeV4 = 128
	conntrackValueSizeV6 = 176
)

// TestBPFSessionValueMatchesConntrackABI pins the dedicated on-map ABI types to
// the C/Rust conntrack struct sizes. Fails if a field drifts so the Go layout
// no longer mirrors the kernel struct.
func TestBPFSessionValueMatchesConntrackABI(t *testing.T) {
	if got := unsafe.Sizeof(bpfSessionValue{}); got != conntrackValueSizeV4 {
		t.Fatalf("sizeof(bpfSessionValue) = %d, want %d (C struct session_value / Rust BpfSessionValueV4)",
			got, conntrackValueSizeV4)
	}
	if got := unsafe.Sizeof(bpfSessionValueV6{}); got != conntrackValueSizeV6 {
		t.Fatalf("sizeof(bpfSessionValueV6) = %d, want %d (C struct session_value_v6 / Rust BpfSessionValueV6)",
			got, conntrackValueSizeV6)
	}
	// The exported SSOT constants (used by production registration AND test
	// fixtures) must equal the literal C/Rust contract.
	if ConntrackSessionValueSize != conntrackValueSizeV4 {
		t.Fatalf("ConntrackSessionValueSize = %d, want %d", ConntrackSessionValueSize, conntrackValueSizeV4)
	}
	if ConntrackSessionValueSizeV6 != conntrackValueSizeV6 {
		t.Fatalf("ConntrackSessionValueSizeV6 = %d, want %d", ConntrackSessionValueSizeV6, conntrackValueSizeV6)
	}
}

// TestSessionValueCarriesSyncOnlyGeneration confirms SessionValue is exactly 8
// bytes (one uint64 Generation) larger than the on-map ABI type, and that the
// extra bytes are the trailing Generation field — the #2170 sync-only guard
// that must NOT be registered into the BPF map (#2360).
func TestSessionValueCarriesSyncOnlyGeneration(t *testing.T) {
	// The sync-only fields (#2170 Generation, #3301 PolicyCounterIdx) sit
	// strictly past the on-map conntrack ABI layout (bpfSessionValue). The
	// hard invariant guarding #2360 is that bpfSessionValue equals the on-map
	// ABI size — it must NOT pick up the sync-only fields — and that those
	// fields begin immediately past it. (The exact byte delta now includes
	// Generation(u64)+PolicyCounterIdx(u32)+alignment padding, so we assert
	// the field offsets, not a fixed delta.)
	if got := unsafe.Sizeof(bpfSessionValue{}); uintptr(conntrackValueSizeV4) != got {
		t.Fatalf("bpfSessionValue size = %d, want %d (on-map conntrack ABI)", got, conntrackValueSizeV4)
	}
	if got := unsafe.Sizeof(bpfSessionValueV6{}); uintptr(conntrackValueSizeV6) != got {
		t.Fatalf("bpfSessionValueV6 size = %d, want %d (on-map conntrack ABI)", got, conntrackValueSizeV6)
	}
	if unsafe.Sizeof(SessionValue{}) <= unsafe.Sizeof(bpfSessionValue{}) {
		t.Fatal("SessionValue must be larger than bpfSessionValue (carries sync-only fields)")
	}
	if unsafe.Sizeof(SessionValueV6{}) <= unsafe.Sizeof(bpfSessionValueV6{}) {
		t.Fatal("SessionValueV6 must be larger than bpfSessionValueV6 (carries sync-only fields)")
	}
	// Generation must be the first field past the on-map layout.
	if off := unsafe.Offsetof(SessionValue{}.Generation); off != conntrackValueSizeV4 {
		t.Fatalf("SessionValue.Generation offset = %d, want %d (must sit immediately past the on-map layout)",
			off, conntrackValueSizeV4)
	}
	if off := unsafe.Offsetof(SessionValueV6{}.Generation); off != conntrackValueSizeV6 {
		t.Fatalf("SessionValueV6.Generation offset = %d, want %d (must sit immediately past the on-map layout)",
			off, conntrackValueSizeV6)
	}
	// #3301: PolicyCounterIdx follows Generation (also sync-only, never on the
	// BPF map).
	if off := unsafe.Offsetof(SessionValue{}.PolicyCounterIdx); off != conntrackValueSizeV4+unsafe.Sizeof(uint64(0)) {
		t.Fatalf("SessionValue.PolicyCounterIdx offset = %d, want %d (immediately past Generation)",
			off, conntrackValueSizeV4+unsafe.Sizeof(uint64(0)))
	}
	if off := unsafe.Offsetof(SessionValueV6{}.PolicyCounterIdx); off != conntrackValueSizeV6+unsafe.Sizeof(uint64(0)) {
		t.Fatalf("SessionValueV6.PolicyCounterIdx offset = %d, want %d (immediately past Generation)",
			off, conntrackValueSizeV6+unsafe.Sizeof(uint64(0)))
	}
}

// TestSessionMapRegisteredAtConntrackABISize is the regression guard for
// #2360: the `sessions` / `sessions_v6` BPF maps MUST be registered with the
// on-map conntrack ABI value_size (128 / 176), NOT sizeOf[SessionValue] /
// sizeOf[SessionValueV6] (136 / 184). Registering at the larger SessionValue
// size makes the kernel value_size exceed the Rust helper's 128/176-byte lookup
// buffer, causing an 8-byte out-of-bounds copy. This test fails if anyone
// reverts the registration to sizeOf[SessionValue].
func TestSessionMapRegisteredAtConntrackABISize(t *testing.T) {
	specs := userspaceShimSharedMapSpecs()
	valueSize := make(map[string]uint32, len(specs))
	for _, spec := range specs {
		valueSize[spec.Name] = spec.ValueSize
	}

	if got := valueSize["sessions"]; got != conntrackValueSizeV4 {
		t.Fatalf("sessions map value_size = %d, want %d (C/Rust conntrack ABI); "+
			"must NOT be sizeOf[SessionValue]=%d which inflates the map by the sync-only Generation (#2360)",
			got, conntrackValueSizeV4, unsafe.Sizeof(SessionValue{}))
	}
	if got := valueSize["sessions_v6"]; got != conntrackValueSizeV6 {
		t.Fatalf("sessions_v6 map value_size = %d, want %d (C/Rust conntrack ABI); "+
			"must NOT be sizeOf[SessionValueV6]=%d which inflates the map by the sync-only Generation (#2360)",
			got, conntrackValueSizeV6, unsafe.Sizeof(SessionValueV6{}))
	}

	// And the registration must equal the dedicated ABI type's size — the
	// single source of the on-map layout.
	if got, want := valueSize["sessions"], uint32(unsafe.Sizeof(bpfSessionValue{})); got != want {
		t.Fatalf("sessions map value_size = %d, want sizeOf[bpfSessionValue]=%d", got, want)
	}
	if got, want := valueSize["sessions_v6"], uint32(unsafe.Sizeof(bpfSessionValueV6{})); got != want {
		t.Fatalf("sessions_v6 map value_size = %d, want sizeOf[bpfSessionValueV6]=%d", got, want)
	}
}

// TestSessionValueBPFRoundTripDropsGeneration verifies the conversion contract:
// every field except the sync-only Generation survives a SessionValue -> on-map
// -> SessionValue round trip, and Generation is dropped (the BPF map never
// stores it). The authoritative Generation lives in the Go session table / on
// the cluster sync wire, so dropping it at the map boundary is correct.
func TestSessionValueBPFRoundTripDropsGeneration(t *testing.T) {
	orig := SessionValue{
		State:       3,
		Flags:       SessFlagSNAT,
		TCPState:    4,
		IsReverse:   0,
		AppTimeout:  120,
		SessionID:   0xdeadbeefcafef00d,
		Created:     111,
		LastSeen:    222,
		Timeout:     300,
		PolicyID:    7,
		IngressZone: 1,
		EgressZone:  2,
		NATSrcIP:    0x0a000001,
		NATDstIP:    0x0a000002,
		NATSrcPort:  1234,
		NATDstPort:  5678,
		FwdPackets:  10,
		FwdBytes:    1000,
		RevPackets:  20,
		RevBytes:    2000,
		ReverseKey:  SessionKey{SrcPort: 5678, DstPort: 1234, Protocol: 6},
		ALGType:     1,
		LogFlags:    2,
		AppID:       42,
		FibIfindex:  9,
		FibVlanID:   50,
		FibDmac:     [6]byte{1, 2, 3, 4, 5, 6},
		FibSmac:     [6]byte{6, 5, 4, 3, 2, 1},
		FibGen:           99,
		Generation:       0x1122334455667788, // sync-only — must NOT survive to the map
		PolicyCounterIdx: 7,                  // #3301 sync-only — must NOT survive to the map
	}

	got := orig.toBPF().sessionValue()

	want := orig
	want.Generation = 0       // dropped at the map boundary
	want.PolicyCounterIdx = 0 // #3301 sync-only — dropped at the map boundary
	if got != want {
		t.Fatalf("v4 round trip mismatch:\n got=%+v\nwant=%+v", got, want)
	}

	origV6 := SessionValueV6{
		State:       3,
		Flags:       SessFlagDNAT,
		TCPState:    4,
		IsReverse:   1,
		AppTimeout:  60,
		SessionID:   0x0102030405060708,
		Created:     1,
		LastSeen:    2,
		Timeout:     30,
		PolicyID:    8,
		IngressZone: 2,
		EgressZone:  1,
		NATSrcIP:    [16]byte{0xfe, 0x80, 15: 1},
		NATDstIP:    [16]byte{0x20, 0x01, 15: 2},
		NATSrcPort:  4321,
		NATDstPort:  8765,
		FwdPackets:  5,
		FwdBytes:    500,
		RevPackets:  6,
		RevBytes:    600,
		ReverseKey:  SessionKeyV6{SrcPort: 8765, DstPort: 4321, Protocol: 17},
		ALGType:     2,
		LogFlags:    3,
		AppID:       43,
		FibIfindex:  10,
		FibVlanID:   80,
		FibDmac:     [6]byte{9, 8, 7, 6, 5, 4},
		FibSmac:     [6]byte{4, 5, 6, 7, 8, 9},
		FibGen:           77,
		Generation:       0x8877665544332211,
		PolicyCounterIdx: 11, // #3301 sync-only — must NOT survive to the map
	}

	gotV6 := origV6.toBPF().sessionValue()
	wantV6 := origV6
	wantV6.Generation = 0
	wantV6.PolicyCounterIdx = 0
	if gotV6 != wantV6 {
		t.Fatalf("v6 round trip mismatch:\n got=%+v\nwant=%+v", gotV6, wantV6)
	}
}
