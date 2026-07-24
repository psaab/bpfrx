package config

import "fmt"

// runUniformGatesScreen runs the screen sub-run of the P6b uniform
// fail-open gate phase. It is a verbatim contiguous slice of the
// original runUniformGates god-function (#6423 decomposition): the
// gate order here and the segment-call order in runUniformGates together
// reproduce the exact flat gate sequence, so the first-failing-gate-wins
// strict ordering (invariant #6) and the tolerant warning-accumulation
// order (invariant #7) are preserved. See runUniformGates.
func runUniformGatesScreen(tree *ConfigTree, cfg *Config, opts compileOpts) error {
	// #3066 zone screen-profile reference fail-open gate. Strict on commit /
	// commit-check (hard-reject a zone whose `screen <name>` references a
	// screen-ids-option profile the config never defines — at runtime the
	// dataplane fails OPEN for a missing profile, silently skipping every
	// screen check for that zone); lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config still boots — #1960 no-brick).
	// Unlike the policy gates the runtime is NOT independently safe on the
	// lenient path, so the strict commit gate is the real fix.
	if err := validateScreenProfileReferencesStrict(cfg); err != nil {
		if opts.lenientScreenProfileRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("zone screen profile reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3317 screen numeric-value gate. Strict on commit / commit-check
	// (hard-reject a screen threshold / count leaf whose explicitly-provided
	// value is not a positive integer). Before this gate compileScreen swallowed
	// the strconv.Atoi error and silently fell back to a Junos default or to
	// zero/disabled — a typo'd threshold disabled or weakened the protection
	// (fail-open). Lenient on load / peer-sync (warn so an already-persisted or
	// peer-synced config still boots — #1960 no-brick; compileScreen applies the
	// default for the bad value independently on that path). Runs on the
	// fully-compiled *Config so the typed profile list (with BadNumeric
	// populated by compileScreen) is available.
	if err := validateScreenNumericStrict(cfg); err != nil {
		if opts.lenientScreenNumeric {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("screen numeric value (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3318 unknown-screen-leaf gate. Strict on commit / commit-check
	// (hard-reject a screen leaf the dataplane does NOT support). The screen
	// schema subtrees are open and compileScreen had no default case, so a
	// misspelled or unsupported leaf committed cleanly and was silently dropped
	// — the operator believed a protection was enabled when it was absent.
	// Lenient on load / peer-sync (warn so an already-persisted or peer-synced
	// config still boots — #1960 no-brick; the dataplane never represented the
	// leaf, so the profile runs without it independently). Runs on the
	// fully-compiled *Config so the typed profile list (with UnknownLeaves
	// populated by compileScreen) is available.
	if err := validateScreenUnknownStrict(cfg); err != nil {
		if opts.lenientScreenUnknown {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("screen unknown leaf (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	return nil
}
