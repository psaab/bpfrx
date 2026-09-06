package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/authz"
)

// #9154: THE REST SURFACE PERFORMED CONFIG MUTATIONS WITH NO `*-configuration`
// REGEX CHECK. `pkg/api/authz.go` and `pkg/api/config.go` had zero matches for
// `Regex`, so a class restricted from configuring a subtree was restricted only
// at the console.
//
// Reachability is not theoretical: for a LOCAL caller the login model is the
// only authority, so a user in a PermConfig class who is regex-restricted on
// the CLI and on gRPC could `curl -X POST /api/v1/config/set` unrestricted.

const uid9154 = 4247

const passwd9154 = `root:x:0:0:root:/root:/bin/bash
cfguser:x:4247:4247::/home/cfguser:/bin/bash
`

// The class holds `configure`, so the COARSE permission bits admit it — the
// regex is the only thing standing between this caller and the mutation. That
// is what makes the test measure the regex rather than the permission tier.
const config9154 = `
system {
    host-name authz-9154;
    login {
        class limited {
            permissions [ configure view ];
            deny-configuration "system root-authentication";
        }
        user cfguser {
            class limited;
        }
    }
}
`

func usePasswd9154(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(passwd9154), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(path))
}

// enter9154 opens a REST config session and returns its id. A config mutation
// is addressed by the X-Config-Session header, so without this the control
// below fails on a 400 before the regex is ever consulted — which is exactly
// what it caught the first time this test was written.
func enter9154(t *testing.T, base string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/api/v1/config/enter", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("config/enter: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("config/enter returned %d: %s", resp.StatusCode, b)
	}
	var out struct {
		Data struct {
			SessionID string `json:"session_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &out); err != nil || out.Data.SessionID == "" {
		t.Fatalf("config/enter gave no session id: %s", b)
	}
	return out.Data.SessionID
}

func post9154(t *testing.T, base, path, input, session string) (int, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"input": input})
	req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if session != "" {
		req.Header.Set("X-Config-Session", session)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestConfigurationDenyIsEnforcedOverREST9154(t *testing.T) {
	usePasswd9154(t)
	store := authzStore(t, config9154)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(uid9154),
	})

	sess := enter9154(t, base)

	// POSITIVE CONTROL FIRST. An unrelated mutation must SUCCEED, or a 403
	// below could be the coarse permission tier refusing everything and the
	// regex would be untested.
	if code, body := post9154(t, base, "/api/v1/config/set", "system host-name fw9154", sess); code != http.StatusOK {
		t.Fatalf("control failed: an unrelated `set` returned %d, want 200 — this caller is "+
			"supposed to be able to configure: %s", code, body)
	}

	t.Run("set matching deny-configuration is refused", func(t *testing.T) {
		code, body := post9154(t, base, "/api/v1/config/set",
			"system root-authentication plain-text-password hunter2", sess)
		if code != http.StatusForbidden {
			t.Errorf("POST /api/v1/config/set returned %d, want 403 — a caller regex-restricted "+
				"on the CLI mutated the denied subtree over REST (#9154): %s", code, body)
		}
		// The path carries the operator's secret; the denial must not echo it.
		if bytes.Contains([]byte(body), []byte("hunter2")) {
			t.Errorf("the denial leaked the secret from the config path: %s", body)
		}
	})

	t.Run("delete matching deny-configuration is refused", func(t *testing.T) {
		code, body := post9154(t, base, "/api/v1/config/delete", "system root-authentication", sess)
		if code != http.StatusForbidden {
			t.Errorf("POST /api/v1/config/delete returned %d, want 403: %s", code, body)
		}
	})

	t.Run("an unrelated delete still works", func(t *testing.T) {
		// The narrowness control, in the other direction: over-denying here
		// would lock the operator out of the configuration they DO hold.
		if code, body := post9154(t, base, "/api/v1/config/delete", "system host-name", sess); code != http.StatusOK {
			t.Errorf("an unrelated `delete` returned %d, want 200: %s", code, body)
		}
	})
}
