package userspace

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	ForwardingUsage = "request chassis cluster data-plane userspace forwarding <arm|disarm>"
	QueueUsage      = "request chassis cluster data-plane userspace queue <N> <register|unregister|arm|disarm>"
	BindingUsage    = "request chassis cluster data-plane userspace binding slot <N> <register|unregister|arm|disarm>"
)

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
	slotNum, err := strconv.Atoi(args[2])
	if err != nil {
		return 0, false, false, fmt.Errorf("invalid slot: %s", args[2])
	}
	registered, armed, err = ParseRegistrationOperation(args[3])
	if err != nil {
		return 0, false, false, fmt.Errorf("usage: %s", BindingUsage)
	}
	return uint32(slotNum), registered, armed, nil
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
