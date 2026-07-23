package nftables

// netlink_capability.go implements the #6387 §12.5 FUNCTIONAL nf_tables
// capability probe. It reports whether the kernel `nf_tables` subsystem is
// usable via netlink, returning a DISTINCT signal (ErrNFTablesUnavailable) when
// the subsystem is absent so PR-3 can raise the Config-Sync monitor-failure with
// an explicit reason ("nf_tables unavailable") instead of a generic apply error.
//
// It is a FUNCTIONAL probe (NOT a /proc/modules check): nf_tables may be built
// into the kernel rather than a loadable module, and the first netlink request
// permits normal kernel autoload of a modular subsystem. The probe never
// installs or mutates anything, and it NEVER downgrades the H7 fail-closed
// contract — the real install still runs and propagates its own error; the probe
// only classifies WHY a failure occurred.

import (
	"errors"
	"fmt"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)

// ErrNFTablesUnavailable is returned by ProbeNFTablesAvailable when the kernel
// nf_tables subsystem is not usable (module absent and not autoloadable). It is
// the distinct signal PR-3 maps to the CF monitor-failure reason.
var ErrNFTablesUnavailable = errors.New("nf_tables subsystem unavailable")

// ProbeNFTablesAvailable functionally probes the kernel nf_tables subsystem. It
// opens a netlink connection and issues a benign table LIST — which triggers
// kernel autoload of a modular nf_tables — returning:
//
//   - nil                       : subsystem usable.
//   - ErrNFTablesUnavailable    : subsystem absent (EOPNOTSUPP / EAFNOSUPPORT /
//     EPROTONOSUPPORT), wrapped with the underlying errno for logging.
//   - other error               : a transient / permission netlink failure that
//     is NOT a definitive "subsystem absent" verdict (the caller should not
//     latch the CF reason on it).
func ProbeNFTablesAvailable() error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables conn: %w", err)
	}
	if _, err := c.ListTablesOfFamily(nftables.TableFamilyINet); err != nil {
		// ENOENT simply means "no tables yet" on a healthy subsystem.
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		if isSubsystemUnavailable(err) {
			return fmt.Errorf("%w: %v", ErrNFTablesUnavailable, err)
		}
		return fmt.Errorf("nftables capability probe: %w", err)
	}
	return nil
}

// IsNFTablesUnavailable reports whether err is (or wraps) the distinct
// subsystem-absent signal, so callers can branch the CF monitor-failure reason.
func IsNFTablesUnavailable(err error) bool {
	return errors.Is(err, ErrNFTablesUnavailable)
}

// isSubsystemUnavailable classifies an errno as "nf_tables subsystem absent".
// On Linux EOPNOTSUPP == ENOTSUP; a missing address family surfaces as
// EAFNOSUPPORT / EPROTONOSUPPORT.
func isSubsystemUnavailable(err error) bool {
	return errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EAFNOSUPPORT) ||
		errors.Is(err, unix.EPROTONOSUPPORT)
}
