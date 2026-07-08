package configstore

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4578 drift guard: the commit-time gate config.ValidateMasterPasswordPRF
// mirrors the NAME set that prfHash (the SSOT for the name->hash.Hash mapping)
// accepts. If a selector is added to prfHash but not to
// config.MasterPasswordPRFNames, that selector would be rejected at commit yet
// work at runtime; if removed from prfHash but left in the list, a commit would
// accept a selector the encrypt path then fails on. This test fails on either
// drift by asserting every advertised name is honoured by prfHash.
func TestPRFHashAcceptsAdvertisedNames(t *testing.T) {
	for _, name := range config.MasterPasswordPRFNames {
		if _, err := prfHash(name); err != nil {
			t.Errorf("prfHash(%q) = %v, want nil — config.MasterPasswordPRFNames advertises "+
				"a selector prfHash does not accept (the commit gate and the encrypt path drifted)", name, err)
		}
	}
	// A selector the gate rejects must also fail prfHash (no silent runtime
	// path around the gate).
	if _, err := prfHash("hmac-sha256"); err == nil {
		t.Error("prfHash accepted \"hmac-sha256\" but config.ValidateMasterPasswordPRF rejects it — drift")
	}
}
