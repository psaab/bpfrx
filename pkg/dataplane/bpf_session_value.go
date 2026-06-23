package dataplane

// On-map conntrack ABI types (#2360).
//
// The shared kernel-visible `sessions` / `sessions_v6` BPF HASH maps store the
// C `struct session_value` / `struct session_value_v6` layout (bpf/headers/
// xpf_conntrack.h), which the Rust helper mirrors as BpfSessionValueV4 (128
// bytes) / BpfSessionValueV6 (176 bytes) — test-asserted at
// userspace-dp/src/afxdp/bpf_map_tests.rs.
//
// SessionValue / SessionValueV6 (types.go) carry one EXTRA trailing field,
// `Generation uint64` — the #2170 HA deferred-delete install-generation guard.
// That field is userspace-sync-only metadata: it lives in the Go session table
// and travels on the cluster session-sync wire (pkg/cluster/sync_protocol.go,
// its own length-gated byte codec), and is deliberately NOT part of the BPF C
// conntrack struct. So SessionValue is 8 bytes larger than the on-map layout
// (136 vs 128 v4; 184 vs 176 v6).
//
// Registering the map at sizeof(SessionValue) (the previous behaviour) made the
// kernel value_size 8 bytes larger than every reader/writer's struct. A
// bpf_map_lookup_elem from the Rust side into its 128/176-byte buffer then has
// the kernel copy value_size (136/184) bytes into the smaller buffer — an
// 8-byte stack out-of-bounds write (latent because the trailing bytes are
// usually zero). See issue #2360.
//
// bpfSessionValue / bpfSessionValueV6 are the dedicated on-map ABI types:
// identical to SessionValue / SessionValueV6 minus the sync-only Generation.
// They are the size used for map registration AND for every map I/O (Update /
// Lookup / Iterate / Batch), so cilium/ebpf marshals exactly the C layout. The
// Go-facing accessors convert at the boundary; Generation never touches the
// BPF map (it is sourced from the Go session table / sync path).

// bpfSessionValue mirrors C `struct session_value` exactly (128 bytes). It is
// SessionValue without the sync-only Generation field. Keep field-for-field in
// sync with both SessionValue (types.go) and the C struct (xpf_conntrack.h);
// the parity test in maps_session_test.go fails if the size drifts from 128.
type bpfSessionValue struct {
	State      uint8
	Flags      uint8
	TCPState   uint8
	IsReverse  uint8
	AppTimeout uint32

	SessionID uint64

	Created  uint64
	LastSeen uint64
	Timeout  uint32
	PolicyID uint32

	IngressZone uint16
	EgressZone  uint16

	NATSrcIP   uint32
	NATDstIP   uint32
	NATSrcPort uint16
	NATDstPort uint16

	FwdPackets uint64
	FwdBytes   uint64
	RevPackets uint64
	RevBytes   uint64

	ReverseKey SessionKey

	ALGType  uint8
	LogFlags uint8
	AppID    uint16

	FibIfindex uint32
	FibVlanID  uint16
	FibDmac    [6]byte
	FibSmac    [6]byte
	FibGen     uint16
}

// bpfSessionValueV6 mirrors C `struct session_value_v6` exactly (176 bytes). It
// is SessionValueV6 without the sync-only Generation field.
type bpfSessionValueV6 struct {
	State      uint8
	Flags      uint8
	TCPState   uint8
	IsReverse  uint8
	AppTimeout uint32

	SessionID uint64

	Created  uint64
	LastSeen uint64
	Timeout  uint32
	PolicyID uint32

	IngressZone uint16
	EgressZone  uint16

	NATSrcIP   [16]byte
	NATDstIP   [16]byte
	NATSrcPort uint16
	NATDstPort uint16

	FwdPackets uint64
	FwdBytes   uint64
	RevPackets uint64
	RevBytes   uint64

	ReverseKey SessionKeyV6

	ALGType  uint8
	LogFlags uint8
	AppID    uint16

	FibIfindex uint32
	FibVlanID  uint16
	FibDmac    [6]byte
	FibSmac    [6]byte
	FibGen     uint16
}

// toBPF projects a SessionValue onto the on-map ABI layout, dropping the
// sync-only Generation. Used before any write to the BPF sessions map.
func (v SessionValue) toBPF() bpfSessionValue {
	return bpfSessionValue{
		State:       v.State,
		Flags:       v.Flags,
		TCPState:    v.TCPState,
		IsReverse:   v.IsReverse,
		AppTimeout:  v.AppTimeout,
		SessionID:   v.SessionID,
		Created:     v.Created,
		LastSeen:    v.LastSeen,
		Timeout:     v.Timeout,
		PolicyID:    v.PolicyID,
		IngressZone: v.IngressZone,
		EgressZone:  v.EgressZone,
		NATSrcIP:    v.NATSrcIP,
		NATDstIP:    v.NATDstIP,
		NATSrcPort:  v.NATSrcPort,
		NATDstPort:  v.NATDstPort,
		FwdPackets:  v.FwdPackets,
		FwdBytes:    v.FwdBytes,
		RevPackets:  v.RevPackets,
		RevBytes:    v.RevBytes,
		ReverseKey:  v.ReverseKey,
		ALGType:     v.ALGType,
		LogFlags:    v.LogFlags,
		AppID:       v.AppID,
		FibIfindex:  v.FibIfindex,
		FibVlanID:   v.FibVlanID,
		FibDmac:     v.FibDmac,
		FibSmac:     v.FibSmac,
		FibGen:      v.FibGen,
	}
}

// sessionValue lifts an on-map entry back to SessionValue. Generation is left
// zero — the BPF map never stores it; the authoritative Generation lives in the
// Go session table / cluster sync path.
func (v bpfSessionValue) sessionValue() SessionValue {
	return SessionValue{
		State:       v.State,
		Flags:       v.Flags,
		TCPState:    v.TCPState,
		IsReverse:   v.IsReverse,
		AppTimeout:  v.AppTimeout,
		SessionID:   v.SessionID,
		Created:     v.Created,
		LastSeen:    v.LastSeen,
		Timeout:     v.Timeout,
		PolicyID:    v.PolicyID,
		IngressZone: v.IngressZone,
		EgressZone:  v.EgressZone,
		NATSrcIP:    v.NATSrcIP,
		NATDstIP:    v.NATDstIP,
		NATSrcPort:  v.NATSrcPort,
		NATDstPort:  v.NATDstPort,
		FwdPackets:  v.FwdPackets,
		FwdBytes:    v.FwdBytes,
		RevPackets:  v.RevPackets,
		RevBytes:    v.RevBytes,
		ReverseKey:  v.ReverseKey,
		ALGType:     v.ALGType,
		LogFlags:    v.LogFlags,
		AppID:       v.AppID,
		FibIfindex:  v.FibIfindex,
		FibVlanID:   v.FibVlanID,
		FibDmac:     v.FibDmac,
		FibSmac:     v.FibSmac,
		FibGen:      v.FibGen,
	}
}

// toBPF projects a SessionValueV6 onto the on-map ABI layout, dropping the
// sync-only Generation.
func (v SessionValueV6) toBPF() bpfSessionValueV6 {
	return bpfSessionValueV6{
		State:       v.State,
		Flags:       v.Flags,
		TCPState:    v.TCPState,
		IsReverse:   v.IsReverse,
		AppTimeout:  v.AppTimeout,
		SessionID:   v.SessionID,
		Created:     v.Created,
		LastSeen:    v.LastSeen,
		Timeout:     v.Timeout,
		PolicyID:    v.PolicyID,
		IngressZone: v.IngressZone,
		EgressZone:  v.EgressZone,
		NATSrcIP:    v.NATSrcIP,
		NATDstIP:    v.NATDstIP,
		NATSrcPort:  v.NATSrcPort,
		NATDstPort:  v.NATDstPort,
		FwdPackets:  v.FwdPackets,
		FwdBytes:    v.FwdBytes,
		RevPackets:  v.RevPackets,
		RevBytes:    v.RevBytes,
		ReverseKey:  v.ReverseKey,
		ALGType:     v.ALGType,
		LogFlags:    v.LogFlags,
		AppID:       v.AppID,
		FibIfindex:  v.FibIfindex,
		FibVlanID:   v.FibVlanID,
		FibDmac:     v.FibDmac,
		FibSmac:     v.FibSmac,
		FibGen:      v.FibGen,
	}
}

// sessionValue lifts an on-map v6 entry back to SessionValueV6. Generation is
// left zero (not stored in the BPF map).
func (v bpfSessionValueV6) sessionValue() SessionValueV6 {
	return SessionValueV6{
		State:       v.State,
		Flags:       v.Flags,
		TCPState:    v.TCPState,
		IsReverse:   v.IsReverse,
		AppTimeout:  v.AppTimeout,
		SessionID:   v.SessionID,
		Created:     v.Created,
		LastSeen:    v.LastSeen,
		Timeout:     v.Timeout,
		PolicyID:    v.PolicyID,
		IngressZone: v.IngressZone,
		EgressZone:  v.EgressZone,
		NATSrcIP:    v.NATSrcIP,
		NATDstIP:    v.NATDstIP,
		NATSrcPort:  v.NATSrcPort,
		NATDstPort:  v.NATDstPort,
		FwdPackets:  v.FwdPackets,
		FwdBytes:    v.FwdBytes,
		RevPackets:  v.RevPackets,
		RevBytes:    v.RevBytes,
		ReverseKey:  v.ReverseKey,
		ALGType:     v.ALGType,
		LogFlags:    v.LogFlags,
		AppID:       v.AppID,
		FibIfindex:  v.FibIfindex,
		FibVlanID:   v.FibVlanID,
		FibDmac:     v.FibDmac,
		FibSmac:     v.FibSmac,
		FibGen:      v.FibGen,
	}
}
