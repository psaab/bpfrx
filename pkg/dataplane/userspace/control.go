package userspace

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/dataplane"
)

const (
	ForwardingUsage = "request chassis cluster data-plane userspace forwarding <arm|disarm>"
	QueueUsage      = "request chassis cluster data-plane userspace queue <N> <register|unregister|arm|disarm>"
	BindingUsage    = "request chassis cluster data-plane userspace binding slot <N> <register|unregister|arm|disarm>"
)

// parseBindingSlot parses a CLI/gRPC binding-slot argument and rejects
// negatives and values >= dataplane.BindingArrayMaxEntries. A valid slot
// lives in [0, BindingArrayMaxEntries), the max_entries of the
// "userspace_bindings" array (MaxInterfaces * BindingQueuesPerIface).
// Without the bounds check a "-1" slot passes strconv.Atoi and wraps to
// 4294967295 on the uint32 cast (#5449), which selects an out-of-bounds
// binding-array slot (and, on the inject path, is later truncated by
// uint16(req.Slot) into a wrong source port). The bound is compared in
// int space so a value larger than uint32 max cannot alias a valid slot
// via truncation.
func parseBindingSlot(arg string) (uint32, error) {
	n, err := strconv.Atoi(arg)
	if err != nil {
		return 0, fmt.Errorf("invalid slot: %s", arg)
	}
	if n < 0 || n >= int(dataplane.BindingArrayMaxEntries) {
		return 0, fmt.Errorf("slot %d out of range [0, %d)", n, dataplane.BindingArrayMaxEntries)
	}
	return uint32(n), nil
}

func ParseForwardingCommand(args []string) (bool, error) {
	if len(args) != 2 || args[0] != "forwarding" {
		return false, fmt.Errorf("usage: %s", ForwardingUsage)
	}
	switch strings.ToLower(args[1]) {
	case "arm":
		return true, nil
	case "disarm":
		return false, nil
	default:
		return false, fmt.Errorf("usage: %s", ForwardingUsage)
	}
}

func ParseQueueCommand(args []string) (queueID uint32, registered, armed bool, err error) {
	if len(args) != 3 || args[0] != "queue" {
		return 0, false, false, fmt.Errorf("usage: %s", QueueUsage)
	}
	queueNum, err := strconv.Atoi(args[1])
	if err != nil {
		return 0, false, false, fmt.Errorf("invalid queue: %s", args[1])
	}
	registered, armed, err = ParseRegistrationOperation(args[2])
	if err != nil {
		return 0, false, false, fmt.Errorf("usage: %s", QueueUsage)
	}
	return uint32(queueNum), registered, armed, nil
}

func ParseBindingCommand(args []string) (slot uint32, registered, armed bool, err error) {
	if len(args) != 4 || args[0] != "binding" || args[1] != "slot" {
		return 0, false, false, fmt.Errorf("usage: %s", BindingUsage)
	}
	slot, err = parseBindingSlot(args[2])
	if err != nil {
		return 0, false, false, err
	}
	registered, armed, err = ParseRegistrationOperation(args[3])
	if err != nil {
		return 0, false, false, fmt.Errorf("usage: %s", BindingUsage)
	}
	return slot, registered, armed, nil
}

func ParseRegistrationOperation(op string) (registered, armed bool, err error) {
	switch strings.ToLower(op) {
	case "register":
		return true, false, nil
	case "unregister":
		return false, false, nil
	case "arm":
		return true, true, nil
	case "disarm":
		return true, false, nil
	default:
		return false, false, fmt.Errorf("unknown operation %q", op)
	}
}
