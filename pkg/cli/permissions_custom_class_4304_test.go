package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestCustomLoginClassRuntimeRBAC is the runtime half of #4304 S-2: a user
// assigned to a custom `system login class <name>` must be enforced against
// the class's mapped permissions resolved from the active config — NOT locked
// out as an "unknown login class". Reverting resolveClassPerms back to a bare
// config.LoginClassPermissions lookup makes every subtest go RED (a custom
// class is unknown -> all commands denied).
func TestCustomLoginClassRuntimeRBAC(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(): %v", err)
	}
	sets := []string{
		// noc-admin: permissions all -> super-user (everything).
		"set system login class noc-admin permissions all",
		// viewer-plus: view + clear only.
		"set system login class viewer-plus permissions [ view clear ]",
		"set system login user alice class noc-admin",
		"set system login user bob class viewer-plus",
	}
	if _, err := store.LoadSet(strings.Join(sets, "\n")); err != nil {
		t.Fatalf("LoadSet(): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(): %v", err)
	}

	cases := []struct {
		class string
		parts []string
		allow bool
	}{
		{"noc-admin", []string{"configure"}, true},           // all -> super-user
		{"noc-admin", []string{"clear", "security"}, true},   //
		{"viewer-plus", []string{"show", "version"}, true},   // view granted
		{"viewer-plus", []string{"clear", "security"}, true}, // clear granted
		{"viewer-plus", []string{"configure"}, false},        // no config perm
		{"viewer-plus", []string{"request", "system", "reboot"}, false},
	}
	for _, tc := range cases {
		c := &CLI{store: store, userClass: tc.class}
		err := c.checkPermission(tc.parts)
		cmd := strings.Join(tc.parts, " ")
		if tc.allow && err != nil {
			t.Errorf("%q for class %q denied: %v (want allowed)", cmd, tc.class, err)
		}
		if !tc.allow && err == nil {
			t.Errorf("%q for class %q ALLOWED (want denied)", cmd, tc.class)
		}
	}

	// showConfigRedacted: the all-permissions custom class carries PermAll, so
	// it reads cleartext like super-user; the view-only custom class must be
	// redacted.
	if (&CLI{store: store, userClass: "noc-admin"}).showConfigRedacted() {
		t.Errorf("noc-admin (permissions all) should NOT redact (has PermAll)")
	}
	if !(&CLI{store: store, userClass: "viewer-plus"}).showConfigRedacted() {
		t.Errorf("viewer-plus (view/clear only) SHOULD redact secrets")
	}
}
