package userspace

import (
	"fmt"
	"strconv"
	"strings"
	"syscall"
)

const InjectPacketUsage = "request chassis cluster data-plane userspace inject-packet slot <N> <valid|fib-mismatch|metadata-parse-error> [destination-ip <ip>]"

func ParseInjectPacketCommand(args []string) (slot uint32, mode string, extra map[string]string, err error) {
	if len(args) < 4 || args[0] != "inject-packet" || args[1] != "slot" {
		return 0, "", nil, fmt.Errorf("usage: %s", InjectPacketUsage)
	}
	slotNum, err := strconv.Atoi(args[2])
	if err != nil {
		return 0, "", nil, fmt.Errorf("invalid slot: %s", args[2])
	}
	slot = uint32(slotNum)
	mode = args[3]
	extra = make(map[string]string)
	for i := 4; i < len(args); i += 2 {
		if i+1 >= len(args) {
			return 0, "", nil, fmt.Errorf("missing value for %s", args[i])
		}
		key := strings.ToLower(args[i])
		extra[key] = args[i+1]
	}
	return slot, mode, extra, nil
}

func BuildInjectPacketRequest(slot uint32, mode string, extra map[string]string, status ProcessStatus) (InjectPacketRequest, error) {
	req := InjectPacketRequest{
		Slot:             slot,
		PacketLength:     128,
		AddrFamily:       uint8(syscall.AF_INET),
		Protocol:         6,
		ConfigGeneration: status.LastSnapshotGeneration,
		FIBGeneration:    status.LastFIBGeneration,
		MetadataValid:    true,
		DestinationIP:    extra["destination-ip"],
	}
	switch mode {
	case "valid":
	case "fib-mismatch":
		req.FIBGeneration++
	case "metadata-parse-error":
		req.MetadataValid = false
		req.PacketLength = 96
		req.AddrFamily = 0
		req.Protocol = 0
		req.ConfigGeneration = 0
		req.FIBGeneration = 0
	default:
		return InjectPacketRequest{}, fmt.Errorf("unknown inject mode %q", mode)
	}
	return req, nil
}
