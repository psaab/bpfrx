package config

import (
	"strconv"
	"strings"
)

// XFRMIfNameAndID resolves a secure-tunnel bind-interface to the Linux xfrmi
// device name and a stable XFRM if_id.
func XFRMIfNameAndID(bindIface string) (string, uint32) {
	if bindIface == "" {
		return "", 0
	}

	parts := strings.SplitN(bindIface, ".", 2)
	devName := parts[0]
	if len(devName) < 3 || devName[:2] != "st" {
		return "", 0
	}

	stIndex, err := strconv.Atoi(devName[2:])
	if err != nil || stIndex < 0 || stIndex >= 0x10000 {
		return "", 0
	}

	unit := 0
	if len(parts) == 2 {
		unit, err = strconv.Atoi(parts[1])
		if err != nil || unit < 0 || unit >= 0xffff {
			return "", 0
		}
	}

	ifID := uint32(stIndex)<<16 | uint32(unit+1)
	if ifID == 0 {
		return "", 0
	}

	return LinuxIfName(bindIface), ifID
}
