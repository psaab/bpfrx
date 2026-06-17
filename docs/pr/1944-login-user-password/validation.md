# #1944 validation — system login user encrypted-password

## Unit (default `go test ./...` gate)

- `go build ./...` clean; full `go test ./...` green.
- New tests stable over `-count=5`.
- `go vet ./pkg/config ./pkg/daemon` clean (the two daemon_flow.go
  copylock warnings are pre-existing and unrelated to this change —
  present on the merge base).
- Key unit coverage:
  - `TestValidateCryptHash` — accept (modular crypt incl. `rounds=`,
    yescrypt, bcrypt, `!`/`!!` prefix, bare sentinels) / reject
    (plaintext, 13-char DES-shape, empty, unknown id, empty salt, empty
    checksum, colon, control char).
  - `TestLoginUserEncryptedPasswordSchemaGate` — the REAL `SchemaValidate`
    commit-check gate rejects plaintext per-user AND root, accepts a valid
    hash and the root lock sentinel `*`. This is the live commit-check
    rejection proof (c).
  - Hierarchical + flat-set compile parity.
  - `TestPasswordAction` — full fail-open/fail-closed table.
  - `TestProvenanceMarkerUIDKeyed` — no-marker, match, UID-mismatch
    cleanup, rejoin, corrupt-marker cleanup.
  - `currentShadowHash` / `lookupUID` parse against sample files.

## Functional (live, real /etc/shadow + chpasswd)

Build-tagged harness `pkg/daemon/login_password_functional_test.go`
(`-tags functional1944`), cross-compiled on the host and run as root in a
throwaway privileged Debian 13 container (`t1944-shadow`). It drives the
ACTUAL production paths: `reconcileUserPassword` → `passwordAction` +
`currentShadowHash` + `chpasswd -e`, plus the UID-keyed marker.

```
=== RUN   TestFunctional1944
INFO user encrypted-password applied user=op1944
  (a) PASS: shadow field for op1944 equals the configured hash
  (a) PASS: op1944 authenticates with the cleartext password
  (d) PASS: unchanged re-commit is a noop (no chpasswd churn)
INFO user password locked (no encrypted-password in config) user=op1944
  (b) PASS: directive removal locked op1944 (shadow="!"), hash not orphaned
  (b) PASS: locked account rejects the old password
--- PASS: TestFunctional1944 (3.33s)
PASS
```

- (a) set → hash IS in `/etc/shadow` field 2 → `op1944` authenticates
  with the cleartext password `test123` (via `setpriv`-dropped `su`,
  a real PAM auth; the same harness confirms a wrong password is rejected
  with `su: Authentication failure`).
- (b) remove the directive → commit → account LOCKED: shadow field is the
  `!` lock sentinel, NOT the orphaned hash → old password rejected.
- (c) plaintext / 13-char-DES / empty-checksum rejected at the real
  `SchemaValidate` commit gate (unit, above).
- (d) idempotent re-commit → `pwNoop`, no `chpasswd` churn.

To reproduce:

```
go test -tags functional1944 -c -o /tmp/daemon_func.test ./pkg/daemon/
# push into a privileged container with chpasswd/useradd, then as root:
/tmp/daemon_func.test -test.run TestFunctional1944 -test.v
```
