package authz

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// authz_5561_test.go pins the authorization decision itself, independent of any
// transport. pkg/api covers the REST wiring; this covers what the shared layer
// decides, which is the part #5278 will reuse verbatim for gRPC.

func testConfig() *config.Config {
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{
		Users: []*config.LoginUser{
			{Name: "opsuser", Class: "read-only"},
			{Name: "adminuser", Class: "super-user"},
			{Name: "noclass"},
			{Name: "customuser", Class: "netops"},
			{Name: "ghostclass", Class: "does-not-exist"},
		},
		Classes: []*config.LoginClass{
			{Name: "netops", MappedPermissions: []config.LoginClassPermission{
				config.PermView, config.PermClear,
			}},
		},
	}
	return cfg
}

// TestAuthorizeDecisionMatrix_5561 walks the policy: superusers pass, a class
// is evaluated against the required permission, and everything the model does
// not describe is denied.
func TestAuthorizeDecisionMatrix_5561(t *testing.T) {
	cfg := testConfig()
	for _, tc := range []struct {
		name     string
		p        Principal
		required config.LoginClassPermission
		wantErr  string // "" = authorized; otherwise a substring of the denial
	}{
		{
			name:     "root is authorized for the destructive tier",
			p:        Principal{Source: SourcePeerUID, UID: 0, Username: "root", Superuser: true},
			required: config.PermMaint,
		},
		{
			name:     "api-auth credential is authorized for the destructive tier",
			p:        CredentialPrincipal("webadmin"),
			required: config.PermMaint,
		},
		{
			name:     "no identity is denied even for the view tier",
			p:        Unauthenticated("connection carries no local peer identity"),
			required: config.PermView,
			wantErr:  "could not establish who is calling",
		},
		{
			name:     "read-only holds view",
			p:        Principal{Source: SourcePeerUID, UID: 4242, Username: "opsuser", Class: "read-only"},
			required: config.PermView,
		},
		{
			name:     "read-only does not hold configure",
			p:        Principal{Source: SourcePeerUID, UID: 4242, Username: "opsuser", Class: "read-only"},
			required: config.PermConfig,
			wantErr:  "lacks the configure permission",
		},
		{
			name:     "operator does not hold maintenance",
			p:        Principal{Source: SourcePeerUID, UID: 4245, Username: "op", Class: "operator"},
			required: config.PermMaint,
			wantErr:  "lacks the maintenance permission",
		},
		{
			name:     "operator holds clear",
			p:        Principal{Source: SourcePeerUID, UID: 4245, Username: "op", Class: "operator"},
			required: config.PermClear,
		},
		{
			name:     "super-user class holds configure",
			p:        Principal{Source: SourcePeerUID, UID: 4243, Username: "adminuser", Class: "super-user"},
			required: config.PermConfig,
		},
		{
			name:     "a custom class is evaluated from its mapped permissions",
			p:        Principal{Source: SourcePeerUID, UID: 4246, Username: "customuser", Class: "netops"},
			required: config.PermClear,
		},
		{
			name:     "a custom class is denied a permission it was not mapped",
			p:        Principal{Source: SourcePeerUID, UID: 4246, Username: "customuser", Class: "netops"},
			required: config.PermConfig,
			wantErr:  "lacks the configure permission",
		},
		{
			name:     "an unknown class is denied rather than treated as empty",
			p:        Principal{Source: SourcePeerUID, UID: 4247, Username: "ghostclass", Class: "does-not-exist"},
			required: config.PermView,
			wantErr:  "unknown login class",
		},
		{
			name:     "a peer with no class is denied",
			p:        Principal{Source: SourcePeerUID, UID: 4244, Username: "stranger"},
			required: config.PermView,
			wantErr:  "not a configured `system login user`",
		},
		{
			name:     "the unauthorized class holds nothing",
			p:        Principal{Source: SourcePeerUID, UID: 4248, Username: "u", Class: "unauthorized"},
			required: config.PermView,
			wantErr:  "lacks the view permission",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Authorize(cfg, tc.p, tc.required)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Authorize denied an authorized principal: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Authorize ADMITTED %s for %s — expected a denial containing %q",
					tc.p, PermissionName(tc.required), tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("denial %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestAuthorizeDeniesWithoutActiveConfig_5561 covers early boot: before a config
// is active, only root (which does not consult the config) is authorized. A nil
// config must not read as "no restrictions".
func TestAuthorizeDeniesWithoutActiveConfig_5561(t *testing.T) {
	root := Principal{Source: SourcePeerUID, UID: 0, Username: "root", Superuser: true}
	if err := Authorize(nil, root, config.PermConfig); err != nil {
		t.Fatalf("root denied with no active config: %v", err)
	}
	user := Principal{Source: SourcePeerUID, UID: 4242, Username: "opsuser"}
	if err := Authorize(nil, user, config.PermView); err == nil {
		t.Fatal("a non-root caller was authorized against a nil active config — " +
			"an unconfigured box would be wide open on the REST mutation surface")
	}
}

// TestPrincipalForUIDResolution_5561 covers the UID -> account -> class chain,
// including every step that must produce an UNRESOLVED principal rather than a
// default one.
func TestPrincipalForUIDResolution_5561(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte(
		"root:x:0:0:root:/root:/bin/bash\n"+
			"opsuser:x:4242:4242::/home/opsuser:/bin/bash\n"+
			"noclass:x:4249:4249::/home/noclass:/bin/bash\n"+
			"stranger:x:4244:4244::/home/stranger:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer SetPasswdPathForTest(passwd)()
	cfg := testConfig()

	t.Run("root short-circuits without touching passwd or config", func(t *testing.T) {
		p := PrincipalForUID(nil, 0)
		if !p.Superuser || !p.Resolved() {
			t.Fatalf("uid 0 produced %+v, want a resolved superuser", p)
		}
	})

	t.Run("a configured login user resolves to its class", func(t *testing.T) {
		p := PrincipalForUID(cfg, 4242)
		if p.Username != "opsuser" || p.Class != "read-only" || !p.Resolved() {
			t.Fatalf("uid 4242 produced %+v, want opsuser/read-only", p)
		}
		if p.Superuser {
			t.Fatal("a read-only login user was marked superuser")
		}
	})

	t.Run("an account absent from the login model is unresolved", func(t *testing.T) {
		p := PrincipalForUID(cfg, 4244)
		if p.Resolved() {
			t.Fatalf("uid 4244 (a real account, not a login user) resolved to %+v", p)
		}
		if !strings.Contains(p.Detail, "stranger") {
			t.Errorf("detail does not name the account: %q", p.Detail)
		}
	})

	t.Run("a login user with no class is unresolved", func(t *testing.T) {
		p := PrincipalForUID(cfg, 4249)
		if p.Resolved() {
			t.Fatalf("uid 4249 (`system login user noclass` with no class) resolved to %+v", p)
		}
		if !strings.Contains(p.Detail, "no class") {
			t.Errorf("detail does not explain the missing class: %q", p.Detail)
		}
	})

	t.Run("a uid with no passwd entry is unresolved", func(t *testing.T) {
		p := PrincipalForUID(cfg, 65533)
		if p.Resolved() {
			t.Fatalf("uid 65533 resolved to %+v despite having no account", p)
		}
		if !strings.Contains(p.Detail, "/etc/passwd") {
			t.Errorf("detail does not explain the missing account: %q", p.Detail)
		}
	})
}

// TestUsernameForUIDParsesPasswd_5561 covers the account-database reader,
// including the duplicate-UID rule and the unreadable-database denial.
func TestUsernameForUIDParsesPasswd_5561(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte(
		"# a comment\n"+
			"\n"+
			"root:x:0:0:root:/root:/bin/bash\n"+
			"first:x:5000:5000::/home/first:/bin/bash\n"+
			"second:x:5000:5000::/home/second:/bin/bash\n"+
			"truncated:x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetPasswdPathForTest(passwd)

	if name, ok := UsernameForUID(0); !ok || name != "root" {
		t.Errorf("uid 0 = (%q, %v), want (root, true)", name, ok)
	}
	if name, ok := UsernameForUID(5000); !ok || name != "first" {
		t.Errorf("duplicate uid 5000 = (%q, %v), want the FIRST entry (first, true)", name, ok)
	}
	if _, ok := UsernameForUID(9999); ok {
		t.Error("an absent uid resolved to a name")
	}
	restore()

	defer SetPasswdPathForTest(filepath.Join(dir, "absent"))()
	if _, ok := UsernameForUID(0); ok {
		t.Error("an unreadable account database still produced an identity — " +
			"the resolver must fail closed")
	}
}

// TestResolveClassPermissionsIsSharedWithTheCLI_5561 pins the factoring: the
// built-in table and the custom-class fallback both resolve here, so pkg/cli
// and this package cannot answer differently for the same class.
func TestResolveClassPermissionsIsSharedWithTheCLI_5561(t *testing.T) {
	cfg := testConfig()
	for class, want := range map[string]bool{
		"super-user": true, "operator": true, "read-only": true,
		"config-viewer": true, "unauthorized": true, "netops": true,
		"nonexistent": false,
	} {
		if _, ok := config.ResolveClassPermissions(cfg, class); ok != want {
			t.Errorf("ResolveClassPermissions(%q) known=%v, want %v", class, ok, want)
		}
	}
	if config.ClassHasPermission(cfg, "read-only", config.PermConfig) {
		t.Error("read-only reported as holding configure")
	}
	if !config.ClassHasPermission(cfg, "super-user", config.PermMaint) {
		t.Error("super-user (PermAll) reported as NOT holding maintenance")
	}
	if _, ok := config.LoginUserClass(cfg, "adminuser"); !ok {
		t.Error("LoginUserClass did not find a configured user")
	}
	if _, ok := config.LoginUserClass(nil, "adminuser"); ok {
		t.Error("LoginUserClass found a user in a nil config")
	}
}
