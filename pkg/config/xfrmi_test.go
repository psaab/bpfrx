package config

import "testing"

func TestXFRMIfNameAndID(t *testing.T) {
	tests := []struct {
		input    string
		wantName string
		wantID   uint32
	}{
		{"st0.0", "st0.0", 1},
		{"st0.1", "st0.1", 2},
		{"st1.0", "st1.0", 65537},
		{"st5.99", "st5.99", 327780},
		{"st0", "st0", 1},
		{"", "", 0},
		{"eth0", "", 0},
		{"st", "", 0},
		{"st65536.0", "", 0},
		{"st0.bad", "", 0},
	}

	for _, tt := range tests {
		gotName, gotID := XFRMIfNameAndID(tt.input)
		if gotName != tt.wantName || gotID != tt.wantID {
			t.Errorf("XFRMIfNameAndID(%q) = (%q, %d), want (%q, %d)",
				tt.input, gotName, gotID, tt.wantName, tt.wantID)
		}
	}
}
