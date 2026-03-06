package dataplane

import (
	"fmt"
	"strings"
)

func allCPUMask(numCPU int) string {
	if numCPU <= 0 {
		return "0"
	}
	words := make([]uint32, (numCPU+31)/32)
	for cpu := 0; cpu < numCPU; cpu++ {
		words[cpu/32] |= 1 << uint(cpu%32)
	}
	return formatCPUMask(words)
}

func singleCPUMask(cpu int) string {
	if cpu < 0 {
		return "0"
	}
	words := make([]uint32, cpu/32+1)
	words[cpu/32] = 1 << uint(cpu%32)
	return formatCPUMask(words)
}

func formatCPUMask(words []uint32) string {
	hi := len(words) - 1
	for hi > 0 && words[hi] == 0 {
		hi--
	}
	if hi < 0 || words[hi] == 0 {
		return "0"
	}

	var b strings.Builder
	for i := hi; i >= 0; i-- {
		if i == hi {
			fmt.Fprintf(&b, "%x", words[i])
			continue
		}
		fmt.Fprintf(&b, ",%08x", words[i])
	}
	return b.String()
}
