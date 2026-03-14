package dataplane

import (
	"bytes"
	_ "embed"
	"fmt"

	"github.com/cilium/ebpf"
)

//go:embed userspace_xdp_bpfel.o
var userspaceXDPBytes []byte

func loadRustUserspaceXDP() (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(userspaceXDPBytes))
	if err != nil {
		return nil, fmt.Errorf("load Rust userspace XDP spec: %w", err)
	}
	return spec, nil
}
