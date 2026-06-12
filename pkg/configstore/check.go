package configstore

import (
	"fmt"

	"github.com/psaab/xpf/pkg/config"
)

// CheckText runs the REAL strict commit-check pipeline against a config
// text without touching any store, DB, or daemon state: parse (the same
// strict parse LoadOverride uses), then compileTreeStrict — the exact
// gate sequence every operator commit goes through (typed-leaf
// SchemaValidate on the apply-groups-expanded view per #1319, then
// strict compile, including the retired-dataplane rejects).
//
// nodeID selects cluster ${node} expansion (0/1); pass -1 for
// standalone, which keeps the historical "${node} → node0" validation
// fallback from schemaValidateExpandedTreeForNode.
//
// This is the validation gate behind `xpfd check-config` (#1879): the
// first-boot config-drive loader validates an untrusted day-0 config
// with it BEFORE installing the file, so an invalid config never
// reaches the daemon's bootstrap-from-file path. It is deliberately a
// thin composition of the same functions Store.Commit uses — do not
// fork the gate logic here.
func CheckText(content string, nodeID int) (*config.Config, error) {
	tree, errs := config.NewParser(content).Parse()
	if len(errs) > 0 {
		return nil, fmt.Errorf("parse error: %v", errs[0])
	}
	compiled, err := compileTreeStrict(tree, nodeID)
	if err != nil {
		return nil, fmt.Errorf("commit check failed: %w", err)
	}
	return compiled, nil
}
