package config

import (
	"strings"
	"testing"
)

// TestValidateCryptHash covers the crypt(3)-hash recognizer shared by
// root-authentication and per-user authentication (#1944 §5.5). The
// central guarantee is that plaintext is ABSOLUTELY rejected (legacy DES
// is intentionally not accepted) while deliberate lock sentinels pass.
func TestValidateCryptHash(t *testing.T) {
	accept := []string{
		"$6$salt$hash",
		"$6$saltsalt$abc123def456",
		"$6$rounds=656000$salt$hash", // sha512crypt rounds param ('=' case)
		"$5$rounds=5000$salt$hash",
		"$y$j9T$saltsalt$hashhash",   // yescrypt (Debian 13 default)
		"$2b$10$abcdefghijklmnopqrst", // bcrypt
		"$2a$10$abcdefghijklmnopqrst",
		"$2y$10$abcdefghijklmnopqrst",
		"$1$salt$hash",         // md5crypt
		"$7$salt$hash",         // scrypt
		"$gy$j9T$salt$hash",    // gost-yescrypt
		"!$6$salt$hash",        // locked-but-restorable
		"!!$6$salt$hash",       // locked-but-restorable (double bang)
		"*",                    // bare lock sentinel
		"!",                    // bare lock sentinel
		"!!",                   // bare lock sentinel
	}
	for _, in := range accept {
		if err := ValidateCryptHash(in, nil); err != nil {
			t.Errorf("ValidateCryptHash(%q) = %v, want accept", in, err)
		}
	}

	reject := []string{
		"plaintext",      // the real footgun
		"password12345",  // 13 alnum — the DES-drop case (r3 Major-2)
		"",               // empty
		"$99$bogus$x",    // unknown id
		"$6$",            // no salt body / no checksum
		"$6$salt$",       // empty checksum (r3 Major-3)
		"$6$$hash",       // empty salt
		"$6$salt:hash",   // colon would corrupt chpasswd stdin
		"$6$salt$ab cd",  // space
		"$6$salt$ab\tcd", // tab control char
		"$6salt$hash",    // missing $ after id
	}
	for _, in := range reject {
		if err := ValidateCryptHash(in, nil); err == nil {
			t.Errorf("ValidateCryptHash(%q) = nil, want reject", in)
		}
	}
}

// TestParseLoginUserEncryptedPasswordHierarchical exercises the
// hierarchical AST shape (#1944 §7.1).
func TestParseLoginUserEncryptedPasswordHierarchical(t *testing.T) {
	input := `system {
    login {
        user op {
            class operator;
            authentication {
                encrypted-password "$6$salt$hash";
                ssh-ed25519 "ssh-ed25519 AAAA op@host";
            }
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	if cfg.System.Login == nil || len(cfg.System.Login.Users) != 1 {
		t.Fatalf("expected 1 user, got %+v", cfg.System.Login)
	}
	u := cfg.System.Login.Users[0]
	if u.EncryptedPassword != "$6$salt$hash" {
		t.Errorf("EncryptedPassword = %q, want %q", u.EncryptedPassword, "$6$salt$hash")
	}
	if len(u.SSHKeys) != 1 || u.SSHKeys[0] != "ssh-ed25519 AAAA op@host" {
		t.Errorf("SSHKeys = %v", u.SSHKeys)
	}
}

// TestParseLoginUserEncryptedPasswordFlatSet exercises the flat-set AST
// shape and asserts it compiles to the same struct as the hierarchical
// shape (Codex M-3, dual-AST pin). Uses ParseSetCommand + SetPath, never
// NewParser, per the project's set-syntax testing rule.
func TestParseLoginUserEncryptedPasswordFlatSet(t *testing.T) {
	cmds := []string{
		"set system login user op class operator",
		`set system login user op authentication encrypted-password "$6$salt$hash"`,
		`set system login user op authentication ssh-ed25519 "ssh-ed25519 AAAA op@host"`,
	}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.System.Login == nil || len(cfg.System.Login.Users) != 1 {
		t.Fatalf("expected 1 user, got %+v", cfg.System.Login)
	}
	u := cfg.System.Login.Users[0]
	if u.Name != "op" || u.Class != "operator" {
		t.Errorf("user = %q/%q", u.Name, u.Class)
	}
	if u.EncryptedPassword != "$6$salt$hash" {
		t.Errorf("flat-set EncryptedPassword = %q, want %q", u.EncryptedPassword, "$6$salt$hash")
	}
	if len(u.SSHKeys) != 1 || u.SSHKeys[0] != "ssh-ed25519 AAAA op@host" {
		t.Errorf("SSHKeys = %v", u.SSHKeys)
	}
}

// TestLoginUserEncryptedPasswordSchemaGate proves the typed-leaf gate
// hard-rejects a plaintext per-user encrypted-password at commit-check and
// accepts a valid hash (#1944 §5.6 / §7.4), including the root-auth E1
// parity (lock sentinel "*" accepted for root).
func TestLoginUserEncryptedPasswordSchemaGate(t *testing.T) {
	mustTree := func(t *testing.T, cmds ...string) *ConfigTree {
		t.Helper()
		tree := &ConfigTree{}
		for _, cmd := range cmds {
			path, err := ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}
		return tree
	}

	// Plaintext per-user → reject.
	bad := mustTree(t, `set system login user op authentication encrypted-password "letmein"`)
	if err := SchemaValidate(bad, nil); err == nil {
		t.Error("SchemaValidate accepted plaintext per-user encrypted-password, want reject")
	} else if !strings.Contains(err.Error(), "plaintext") {
		t.Errorf("expected plaintext rejection, got %v", err)
	}

	// Valid hash per-user → accept.
	good := mustTree(t, `set system login user op authentication encrypted-password "$6$salt$hash"`)
	if err := SchemaValidate(good, nil); err != nil {
		t.Errorf("SchemaValidate rejected a valid per-user hash: %v", err)
	}

	// Root-auth plaintext (E1 shared validator) → reject.
	rootBad := mustTree(t, `set system root-authentication encrypted-password "letmein"`)
	if err := SchemaValidate(rootBad, nil); err == nil {
		t.Error("SchemaValidate accepted plaintext root encrypted-password, want reject")
	}

	// Root-auth lock sentinel "*" → accept (the only way to lock root).
	rootLock := mustTree(t, `set system root-authentication encrypted-password "*"`)
	if err := SchemaValidate(rootLock, nil); err != nil {
		t.Errorf("SchemaValidate rejected root lock sentinel: %v", err)
	}
}

// TestLoginUserNoAuthMethodWarning covers the §5.8 commit warning for a
// user with no usable authentication method (no keys, no usable password).
func TestLoginUserNoAuthMethodWarning(t *testing.T) {
	cases := []struct {
		name      string
		user      *LoginUser
		wantWarn  bool
	}{
		{"no auth at all", &LoginUser{Name: "op"}, true},
		{"lock sentinel only", &LoginUser{Name: "op", EncryptedPassword: "!"}, true},
		{"double-bang sentinel only", &LoginUser{Name: "op", EncryptedPassword: "!!"}, true},
		{"star sentinel only", &LoginUser{Name: "op", EncryptedPassword: "*"}, true},
		// locked-but-restorable hash: cannot password-login until
		// unlocked, so it is NOT a usable auth method (Codex r1 Low).
		{"locked-restorable hash no ssh", &LoginUser{Name: "op", EncryptedPassword: "!$6$salt$hash"}, true},
		{"double-bang restorable hash no ssh", &LoginUser{Name: "op", EncryptedPassword: "!!$6$salt$hash"}, true},
		// locked-restorable hash + ssh key: ssh path is usable, no warning.
		{"locked-restorable hash with ssh", &LoginUser{Name: "op", EncryptedPassword: "!$6$salt$hash", SSHKeys: []string{"ssh-ed25519 AAAA"}}, false},
		{"usable password", &LoginUser{Name: "op", EncryptedPassword: "$6$salt$hash"}, false},
		{"ssh key only", &LoginUser{Name: "op", SSHKeys: []string{"ssh-ed25519 AAAA"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.System.Login = &LoginConfig{Users: []*LoginUser{tc.user}}
			warns := ValidateConfig(cfg)
			found := false
			for _, w := range warns {
				if strings.Contains(w, "no usable authentication method") {
					found = true
				}
			}
			if found != tc.wantWarn {
				t.Errorf("warning present = %v, want %v (warns: %v)", found, tc.wantWarn, warns)
			}
		})
	}
}
