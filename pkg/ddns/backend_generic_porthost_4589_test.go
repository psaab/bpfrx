package ddns

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4589 A10-b2 F-01: validateGenericURLTemplate only rejected an EMPTY
// authority, so `http://:8080/upd` — a non-empty authority (":8080") with an
// EMPTY host — slipped through, and Go's dialer treats an empty-host URL as
// localhost. Require a non-empty host after dropping the :port (and
// unwrapping a bracketed IPv6 literal). Residual of the #2841
// empty-authority-only check.
//
// RED-on-revert: without the ddnsTemplateHost gate the port-only cases
// return nil (accepted).
func TestGenericURLTemplatePortOnlyHostRejected(t *testing.T) {
	reject := []string{
		"http://:8080/upd?ip=%i",         // port only, no host
		"https://:443/upd",               // port only, https
		"https://user:%p@:8080/upd?h=%h", // userinfo stripped -> port only
	}
	for _, tmpl := range reject {
		if err := validateGenericURLTemplate(tmpl); err == nil {
			t.Errorf("validateGenericURLTemplate(%q) = nil, want error (empty host)", tmpl)
		}
		if _, err := newGenericBackend(&config.DDNSProvider{
			Name: "g", Backend: "generic", URLTemplate: tmpl,
		}, nil); err == nil {
			t.Errorf("newGenericBackend(%q) = nil error, want rejection", tmpl)
		}
	}

	accept := []string{
		"http://[2001:db8::1]:8080/upd?ip=%i", // bracketed IPv6 literal + port
		"http://[2001:db8::1]/upd",            // bracketed IPv6 literal, no port
		"https://host:8443/upd?ip=%i",         // real host + port
	}
	for _, tmpl := range accept {
		if err := validateGenericURLTemplate(tmpl); err != nil {
			t.Errorf("validateGenericURLTemplate(%q) = %v, want nil", tmpl, err)
		}
	}
}
