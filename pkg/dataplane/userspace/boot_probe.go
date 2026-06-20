package userspace

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// DefaultControlSocketPath returns the control-socket path the userspace
// helper listens on, resolved exactly the way the runtime Manager resolves it
// (deriveUserspaceConfig): the operator-configured
// `system services userspace-dataplane control-socket` when set, else the
// default under os.TempDir(). cfg may be nil (e.g. a compile-failed boot has no
// active config), in which case the default path is returned — which matches
// what a surviving helper from a default-config deployment is listening on.
func DefaultControlSocketPath(cfg *config.Config) string {
	return deriveUserspaceConfig(cfg).ControlSocket
}

// ProbeForwardingArmed performs a lightweight, one-shot status query against a
// PRE-EXISTING userspace helper on its control socket, WITHOUT standing up a
// Manager or starting a helper. It is used early in boot (#1993) to decide
// whether a previous daemon's dataplane is genuinely still forwarding.
//
// It returns true only when the helper is reachable AND reports both
// Enabled && ForwardingArmed — the authoritative "forwarding is live" signal
// (ProcessStatus.Enabled / ForwardingArmed, the same pair manager.go and
// process.go gate forwarding on). Every failure mode — socket missing,
// connect-refused, timeout, malformed/!ok response, Enabled=false, or
// ForwardingArmed=false — returns false. The boolean is the decision; the
// error is informational only (connect/decode failures are returned with
// armed=false so the caller can log the cause but must still treat the helper
// as NOT armed).
//
// This deliberately does NOT distinguish "no helper" from "helper present but
// unarmed": both mean no live forwarding, and the #1993 caller fails toward
// clearing FRR in either case.
func ProbeForwardingArmed(controlSocket string, timeout time.Duration) (bool, error) {
	if controlSocket == "" {
		return false, errors.New("userspace dataplane control socket not configured")
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	conn, err := net.DialTimeout("unix", controlSocket, timeout)
	if err != nil {
		// No surviving helper (ENOENT / ECONNREFUSED) or it is not accepting:
		// not armed.
		return false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := json.NewEncoder(conn).Encode(&ControlRequest{Type: "status"}); err != nil {
		return false, err
	}
	var resp ControlResponse
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return false, err
	}
	if !resp.OK || resp.Status == nil {
		return false, nil
	}
	return resp.Status.Enabled && resp.Status.ForwardingArmed, nil
}
