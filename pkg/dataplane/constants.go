package dataplane

// Constants in this file are Go-visible mirrors of BPF-side limits.
// THEY MUST STAY IN SYNC WITH:
//
//   - MAX_INTERFACES in bpf/headers/xpf_common.h
//   - BINDING_QUEUES_PER_IFACE in userspace-xdp/src/lib.rs
//     (which derives BINDING_ARRAY_MAX_ENTRIES = MAX_INTERFACES *
//      BINDING_QUEUES_PER_IFACE via env!("MAX_INTERFACES"))
//
// Drift between these and the BPF objects is the exact recurrence #814
// was filed for (fab0 at ifindex 2561 overflowing tx_ports sized at 2048
// and USERSPACE_BINDINGS sized at 1024*16=16384). The load-time
// MaxEntries assertion in loader_ebpf.go catches drift by comparing the
// embedded bpf2go / userspace_xdp_bpfel.o maps' max_entries against
// these Go constants before ebpf.NewCollectionWithOptions runs.
const (
	// MaxInterfaces mirrors MAX_INTERFACES in bpf/headers/xpf_common.h.
	// This is the dense max_entries of the tx_ports DEVMAP and the
	// userspace-side ingress-iface HashMap. Raising it requires bumping
	// both the C constant and the Rust env!() wiring's input.
	MaxInterfaces uint32 = 65536

	// BindingQueuesPerIface mirrors BINDING_QUEUES_PER_IFACE in
	// userspace-xdp/src/lib.rs. Used as the stride in the flat
	// index formula `idx = ifindex * BindingQueuesPerIface + queue`.
	BindingQueuesPerIface uint32 = 16

	// BindingArrayMaxEntries mirrors BINDING_ARRAY_MAX_ENTRIES in
	// userspace-xdp/src/lib.rs. This is the max_entries of the aya
	// Array<UserspaceBindingValue> named "userspace_bindings".
	BindingArrayMaxEntries uint32 = MaxInterfaces * BindingQueuesPerIface
)
