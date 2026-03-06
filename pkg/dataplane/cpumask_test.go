package dataplane

import "testing"

func TestAllCPUMask(t *testing.T) {
	tests := []struct {
		numCPU int
		want   string
	}{
		{0, "0"},
		{1, "1"},
		{4, "f"},
		{32, "ffffffff"},
		{33, "1,ffffffff"},
		{40, "ff,ffffffff"},
		{64, "ffffffff,ffffffff"},
		{65, "1,ffffffff,ffffffff"},
	}

	for _, tt := range tests {
		if got := allCPUMask(tt.numCPU); got != tt.want {
			t.Fatalf("allCPUMask(%d) = %q, want %q",
				tt.numCPU, got, tt.want)
		}
	}
}

func TestSingleCPUMask(t *testing.T) {
	tests := []struct {
		cpu  int
		want string
	}{
		{-1, "0"},
		{0, "1"},
		{1, "2"},
		{31, "80000000"},
		{32, "1,00000000"},
		{33, "2,00000000"},
		{63, "80000000,00000000"},
		{64, "1,00000000,00000000"},
	}

	for _, tt := range tests {
		if got := singleCPUMask(tt.cpu); got != tt.want {
			t.Fatalf("singleCPUMask(%d) = %q, want %q",
				tt.cpu, got, tt.want)
		}
	}
}
