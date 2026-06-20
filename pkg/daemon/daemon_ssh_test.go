package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestBuildSSHDConfigKeyExchange verifies the H5 (#2008) ssh key-exchange
// leaf renders to an sshd KexAlgorithms line, that multiple methods are
// comma-joined, and that key-exchange renders independently of root-login.
func TestBuildSSHDConfigKeyExchange(t *testing.T) {
	tests := []struct {
		name string
		ssh  *config.SSHServiceConfig
		want []string // substrings that must be present
		not  []string // substrings that must be absent
		// empty=true means buildSSHDConfig must return ""
		empty bool
	}{
		{
			name:  "nil",
			ssh:   nil,
			empty: true,
		},
		{
			name:  "no-settings",
			ssh:   &config.SSHServiceConfig{},
			empty: true,
		},
		{
			name: "key-exchange-only",
			ssh:  &config.SSHServiceConfig{KeyExchange: []string{"ecdh-sha2-nistp256"}},
			want: []string{"KexAlgorithms ecdh-sha2-nistp256"},
			not:  []string{"PermitRootLogin"},
		},
		{
			name: "multiple-key-exchange-comma-joined",
			ssh: &config.SSHServiceConfig{KeyExchange: []string{
				"ecdh-sha2-nistp256", "curve25519-sha256",
			}},
			want: []string{"KexAlgorithms ecdh-sha2-nistp256,curve25519-sha256"},
		},
		{
			name: "root-login-and-key-exchange",
			ssh: &config.SSHServiceConfig{
				RootLogin:   "deny",
				KeyExchange: []string{"curve25519-sha256"},
			},
			want: []string{"PermitRootLogin no", "KexAlgorithms curve25519-sha256"},
		},
		{
			name: "root-login-only",
			ssh:  &config.SSHServiceConfig{RootLogin: "allow"},
			want: []string{"PermitRootLogin yes"},
			not:  []string{"KexAlgorithms"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildSSHDConfig(tt.ssh)
			if tt.empty {
				if got != "" {
					t.Fatalf("buildSSHDConfig = %q, want empty", got)
				}
				return
			}
			if got == "" {
				t.Fatalf("buildSSHDConfig = empty, want content")
			}
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("output missing %q\ngot:\n%s", w, got)
				}
			}
			for _, n := range tt.not {
				if strings.Contains(got, n) {
					t.Errorf("output unexpectedly contains %q\ngot:\n%s", n, got)
				}
			}
		})
	}
}
