package config

import (
	"fmt"
	"strconv"
	"strings"
)

// validateLoginClassRef accepts a `system login user <n> class <c>` value that
// is EITHER a system-defined built-in class (super-user/operator/read-only/
// config-viewer/unauthorized, from LoginClassPermissions) OR a custom `system
// login class <c>` defined in the same candidate tree (#4304 S-2). It replaces
// the fixed enum so a valid vSRX RBAC config that defines its own class is no
// longer hard-rejected at commit, while an undefined class still fails closed.
func validateLoginClassRef(raw string, refs *schemaRefs) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("missing value (expected a login class name)")
	}
	if _, ok := LoginClassPermissions[raw]; ok {
		return nil
	}
	if refs != nil {
		if _, ok := refs.loginClasses[raw]; ok {
			return nil
		}
	}
	return fmt.Errorf("login class %q is not defined; use a system-defined class (one of: %s) or add `set system login class %s permissions <...>` in the same commit",
		raw, strings.Join(ValidLoginClasses(), ", "), raw)
}

// cryptModularIDs is the set of crypt(3) modular-hash identifiers xpf
// accepts in an encrypted-password value. It is a permissive superset of
// what Debian 13 glibc / libxcrypt actually verify against — the OS, not
// this validator, is the final authority at PAM time, so we err toward
// "clearly a hash" rather than a brittle per-id structural parse. yescrypt
// ($y$) is the Debian 13 default; $6$ (sha512crypt) is universal; $2a$/
// $2b$/$2y$ (bcrypt), $5$ (sha256crypt), $1$ (md5crypt), $7$ (scrypt) and
// $gy$ (gost-yescrypt) are present via libxcrypt. #1944 §5.5.
var cryptModularIDs = map[string]bool{
	"1": true, "2a": true, "2b": true, "2y": true,
	"5": true, "6": true, "7": true, "y": true, "gy": true,
}

// cryptFieldRune reports whether r is allowed inside a crypt(3) salt or
// checksum field. The crypt-base64 alphabet is [./0-9A-Za-z]; modular
// param fields (e.g. yescrypt $y$j9T$... or sha512crypt
// $6$rounds=656000$...) additionally use '=' to introduce a parameter
// value. We allow '=' here and reject ':' implicitly (not in the set) so
// a value can never corrupt the `user:hash` chpasswd stdin line.
func cryptFieldRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	case r == '.' || r == '/' || r == '=':
		return true
	}
	return false
}

// ValidateCryptHash accepts a crypt(3) modular password hash or an
// explicit lock sentinel, and HARD-REJECTS plaintext. It is shared by
// `system root-authentication encrypted-password` and `system login user
// <name> authentication encrypted-password` (#1944, E1).
//
// Accepted:
//   - A modular crypt hash: an optional leading "!" or "!!" (the
//     locked-but-restorable form), then $<id>$<salt>$<checksum> where
//     <id> ∈ cryptModularIDs, <salt> is non-empty (and may itself carry
//     $-separated params such as rounds=N), and the FINAL $-field (the
//     checksum) is non-empty. A trailing empty checksum ($6$salt$) is
//     rejected — it writes a malformed shadow field PAM refuses.
//   - A bare lock sentinel: "*", "!", or "!!". This is the intentional
//     Unix way to lock an account and the only way to lock root via
//     config (root is excluded from the per-user D2 auto-lock). Accepting
//     a deliberate sentinel is NOT the plaintext footgun.
//
// Rejected: plaintext (no leading $-id, not a sentinel — the real
// footgun), the empty string, an unknown $<id>$, an empty salt or empty
// checksum, and any value carrying ':' (would corrupt chpasswd stdin) or
// a control character. Legacy 13-char DES is deliberately NOT accepted so
// that "reject plaintext" is an absolute guarantee (a 13-char alnum
// password would otherwise pass).
func ValidateCryptHash(raw string, _ *Config) error {
	if raw == "" {
		return fmt.Errorf("missing value (expected a crypt(3) hash, e.g. from `openssl passwd -6`)")
	}
	// Bare lock sentinels — deliberate, accepted as-is.
	if raw == "*" || raw == "!" || raw == "!!" {
		return nil
	}
	// Modular crypt hash, with an optional locked-but-restorable prefix.
	body := raw
	if strings.HasPrefix(body, "!!") {
		body = body[2:]
	} else if strings.HasPrefix(body, "!") {
		body = body[1:]
	}
	if !strings.HasPrefix(body, "$") {
		return fmt.Errorf("not an encrypted password hash (got %q) — plaintext is not "+
			"allowed; generate a hash with `openssl passwd -6` or `mkpasswd -m sha512crypt`", raw)
	}
	// Split into $-separated fields: leading "$" yields an empty first
	// element, so fields[0]=="" , fields[1]=<id>, fields[2..]=salt/params,
	// fields[last]=checksum. Require at least id + salt + checksum.
	fields := strings.Split(body, "$")
	// fields[0] is the empty string before the first '$'.
	if len(fields) < 4 {
		return fmt.Errorf("malformed crypt hash %q — expected $<id>$<salt>$<checksum>", raw)
	}
	id := fields[1]
	if !cryptModularIDs[id] {
		return fmt.Errorf("unknown crypt hash id %q in %q — expected one of "+
			"1, 2a, 2b, 2y, 5, 6, 7, y, gy", id, raw)
	}
	salt := fields[2]
	checksum := fields[len(fields)-1]
	if salt == "" {
		return fmt.Errorf("empty salt in crypt hash %q", raw)
	}
	if checksum == "" {
		return fmt.Errorf("empty checksum in crypt hash %q — a trailing $ "+
			"with no checksum writes a malformed shadow field", raw)
	}
	// Every salt/param/checksum field must be NON-EMPTY and use only the
	// crypt alphabet (which excludes ':' and whitespace), so the value can
	// never corrupt the chpasswd `user:hash` stdin line or smuggle a
	// separator. An empty intermediate field (e.g. "$6$salt$$hash", a
	// doubled '$') is not a valid modular crypt hash — it would pass an
	// alphabet-only check (no chars to reject) but fail at PAM, locking the
	// operator out. Reject it at commit (Copilot #1944 review).
	for _, f := range fields[2:] {
		if f == "" {
			return fmt.Errorf("empty field in crypt hash %q — a doubled "+
				"'$' (e.g. $6$salt$$hash) is malformed", raw)
		}
		for _, r := range f {
			if !cryptFieldRune(r) {
				return fmt.Errorf("invalid character %q in crypt hash %q", r, raw)
			}
		}
	}
	return nil
}

// MaxRingEntries is the inclusive upper bound for the AF_XDP `ring-entries`
// per-queue knob (#2524). The Rust helper preallocates UMEM frames directly
// from this value: per bind.rs binding_frame_count_for_driver, a virtio_net
// binding reserves ~3×ring_entries frames at UMEM_FRAME_SIZE=4096, i.e.
// ~96 MB per binding at ring_entries=8192 (×queues ×interfaces). With no
// ceiling a fat-fingered or malicious value drove an enormous preallocation
// and OOM'd at bring-up instead of failing as a clean commit/startup error.
// 16384 is double the documented 8192 example (~192 MB/binding worst case)
// and is the largest value we consider sane on a router; it must agree with
// the Rust backstop (afxdp/coordinator/reconcile/bringup.rs clamps to the
// same ceiling). The value must additionally be a power of two — the helper
// rounds ring sizes up to a power of two (xsk_ffi.rs next_power_of_two), so
// requiring it at commit keeps the configured number honest about the size
// actually allocated.
const MaxRingEntries = int64(16384)

// ValidateRingEntries accepts a bare integer in [1, MaxRingEntries] that is
// also a power of two. It is the typed-leaf gate for `system dataplane
// ring-entries` (#2524). Before #2524 the leaf used ValidateIntegerMin(1):
// any large value committed and was passed to the dataplane, where it sized
// per-binding UMEM preallocations and could OOM at bring-up. The power-of-two
// requirement matches the helper's own rounding so the operator-visible
// number equals the allocated ring depth.
func ValidateRingEntries(raw string, _ *Config) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("missing value (expected integer)")
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return fmt.Errorf("not an integer: %q", raw)
	}
	if v < 1 || v > MaxRingEntries {
		return fmt.Errorf("ring-entries out of range [1..%d] (got %d)", MaxRingEntries, v)
	}
	if v&(v-1) != 0 {
		return fmt.Errorf("ring-entries must be a power of two in [1..%d] (got %d)", MaxRingEntries, v)
	}
	return nil
}
