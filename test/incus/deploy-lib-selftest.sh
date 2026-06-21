#!/usr/bin/env bash
# Self-test for test/incus/deploy-lib.sh (#2162/#2176). Runs WITHOUT incus or a
# live VM by mocking `incus exec` / `incus file push` against a local fake-VM
# rootfs ($FAKE_VM), so the reconciliation + sha-verify logic is exercised
# end-to-end. No cluster, no lock, no network.
#
# Usage: ./test/incus/deploy-lib-selftest.sh   (rc 0 = all pass)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Minimal info/warn/die the lib depends on. die exits non-zero (the whole point
# of the HARD-fail behavior), so tests that EXPECT a die run the call in a
# subshell and assert on the exit code.
info() { echo "  info: $*"; }
warn() { echo "  warn: $*" >&2; }
die()  { echo "  die: $*" >&2; exit 1; }

# shellcheck source=deploy-lib.sh
source "${SCRIPT_DIR}/deploy-lib.sh"

PASS=0
FAIL=0
ok()   { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad()  { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

# ── Fake VM + incus mock ──────────────────────────────────────────────
# FAKE_VM is a directory that stands in for the VM rootfs. The mock maps
# absolute remote paths under it. A small state file controls dynamic answers
# (MainPID, ExecStart path) the filesystem alone cannot express.
FAKE_VM=""
FAKE_MAINPID="0"
FAKE_EXECSTART="/usr/local/sbin/xpfd"

setup_fake_vm() {
	FAKE_VM=$(mktemp -d)
	FAKE_MAINPID="0"
	FAKE_EXECSTART="/usr/local/sbin/xpfd"
	mkdir -p "$FAKE_VM/usr/local/sbin" "$FAKE_VM/etc/systemd/system"
}

teardown_fake_vm() {
	[[ -n "$FAKE_VM" && -d "$FAKE_VM" ]] && rm -rf "$FAKE_VM"
	FAKE_VM=""
}

# incus mock: supports `incus exec <inst> -- <cmd...>` and
# `incus file push <local> <inst>/<path> [--mode m]`. <inst> is ignored
# (single fake VM). All paths resolve under $FAKE_VM.
incus() {
	local verb="$1"; shift
	case "$verb" in
	exec)
		shift          # instance name
		[[ "$1" == "--" ]] && shift
		_fake_exec "$@"
		;;
	file)
		local sub="$1"; shift
		case "$sub" in
		push)
			local src="$1" dst="$2"
			# dst is "<inst>/usr/local/sbin/xpfd" — strip the inst prefix.
			local rel="${dst#*/}"          # drop up to first slash => path after inst
			local target="$FAKE_VM/$rel"
			mkdir -p "$(dirname "$target")"
			# Mirror `incus file push` over a dangling symlink: it fails.
			if [[ -L "$target" && ! -e "$target" ]]; then
				echo "Error: push through dangling symlink $target" >&2
				return 1
			fi
			cp -f "$src" "$target"
			;;
		*) echo "unsupported incus file $sub" >&2; return 2 ;;
		esac
		;;
	*) echo "unsupported incus verb $verb" >&2; return 2 ;;
	esac
}

# _fake_exec runs a remote command against the fake VM. It special-cases the
# few commands the lib issues; bash -c bodies are rewritten to operate under
# $FAKE_VM, and systemctl/sha256sum/test/rm/readlink are intercepted.
_fake_exec() {
	# Reconstruct argv. The lib calls:
	#   test -f <path>
	#   rm -f <path>
	#   bash -c '<script>'
	#   systemctl daemon-reload
	#   systemctl show -p ExecStart --value xpfd  (via bash -c "... sed ...")
	#   sha256sum <path>
	case "$1" in
	test)
		shift
		# test -f <path>  /  used by deploy_reconcile_stale_pin
		if [[ "$1" == "-f" ]]; then
			[[ -f "$FAKE_VM/${2#/}" ]]
			return $?
		fi
		return 2
		;;
	rm)
		shift
		[[ "$1" == "-f" ]] && shift
		rm -f "$FAKE_VM/${1#/}"
		return 0
		;;
	systemctl)
		shift
		case "$1" in
		daemon-reload) return 0 ;;
		show)
			# systemctl show -p ExecStart --value xpfd  => emit a
			# "{ path=... ; ... }" line; -p MainPID --value => the pid.
			if [[ "$*" == *ExecStart* ]]; then
				echo "{ path=$FAKE_EXECSTART ; argv[]=$FAKE_EXECSTART ; ... }"
			elif [[ "$*" == *MainPID* ]]; then
				echo "$FAKE_MAINPID"
			fi
			return 0
			;;
		esac
		return 0
		;;
	sha256sum)
		shift
		sha256sum "$FAKE_VM/${1#/}" 2>/dev/null | awk -v p="$1" '{print $1"  "p}'
		return ${PIPESTATUS[0]}
		;;
	bash)
		# bash -c '<script>' — run the script with a tiny shim layer that
		# redirects absolute paths into $FAKE_VM and emulates systemctl/sha256sum
		# for the running-verify body.
		shift
		[[ "$1" == "-c" ]] && shift
		local body="$1"
		_fake_remote_bash "$body"
		return $?
		;;
	esac
	return 0
}

# _fake_remote_bash interprets the specific bash -c bodies the lib sends.
_fake_remote_bash() {
	local body="$1"
	# deploy_verify_running_xpfd: effective ExecStart query (systemctl show
	# ExecStart | sed path=). Emit the modeled ExecStart through the same sed
	# the lib applies, so the extraction path is exercised end-to-end.
	if [[ "$body" == *"systemctl show -p ExecStart"* ]]; then
		echo "{ path=$FAKE_EXECSTART ; argv[]=$FAKE_EXECSTART ; ... }" \
			| sed -n 's/.*path=\([^ ;]*\).*/\1/p' | head -n1
		return 0
	fi
	# deploy_reconcile_stale_pin: rmdir-empty-dir guard
	if [[ "$body" == *"xpfd.service.d"* && "$body" == *rmdir* ]]; then
		local d="$FAKE_VM/etc/systemd/system/xpfd.service.d"
		[ -d "$d" ] && [ -z "$(ls -A "$d" 2>/dev/null)" ] && rmdir "$d"
		return 0
	fi
	# deploy_reconcile_stale_pin: other-ExecStart-override scan
	if [[ "$body" == *"grep -lE"* && "$body" == *ExecStart* ]]; then
		local d="$FAKE_VM/etc/systemd/system/xpfd.service.d"
		[ -d "$d" ] || return 0
		grep -lE "^[[:space:]]*ExecStart[[:space:]]*=" "$d"/*.conf 2>/dev/null || true
		return 0
	fi
	# deploy_reconcile_dangling_sbin: [ -L p ] && [ ! -e p ]
	if [[ "$body" == *"-L"* && "$body" == *"-e"* ]]; then
		# Extract the quoted path: ...'<path>'...
		local p
		p=$(sed -E "s/.*-L '([^']+)'.*/\1/" <<<"$body")
		local fp="$FAKE_VM/${p#/}"
		[ -L "$fp" ] && [ ! -e "$fp" ]
		return $?
	fi
	# deploy_verify_running_xpfd: MainPID + sha256sum /proc/PID/exe
	if [[ "$body" == *MainPID* && "$body" == *"/proc/"* ]]; then
		[[ "$FAKE_MAINPID" != "0" ]] || return 1
		# The "running exe" is the file the fake pid points at: we model it as
		# whatever currently lives at /usr/local/sbin/xpfd in the fake VM.
		sha256sum "$FAKE_VM/usr/local/sbin/xpfd" 2>/dev/null || return 1
		return 0
	fi
	return 0
}

# ── Fixtures ──────────────────────────────────────────────────────────
make_local_bin() { printf '%s' "$2" > "$1"; }   # path, content

# ── Tests ─────────────────────────────────────────────────────────────

test_verify_pushed_sha_match() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "BINARY-A"
	cp "$lb" "$FAKE_VM/usr/local/sbin/xpfd"
	if ( deploy_verify_pushed_sha vm "$lb" /usr/local/sbin/xpfd xpfd ) >/dev/null 2>&1; then
		ok "verify_pushed_sha: matching sha passes"
	else
		bad "verify_pushed_sha: matching sha should pass"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_verify_pushed_sha_mismatch_hardfails() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "BINARY-NEW"
	make_local_bin "$FAKE_VM/usr/local/sbin/xpfd" "BINARY-OLD"
	if ( deploy_verify_pushed_sha vm "$lb" /usr/local/sbin/xpfd xpfd ) >/dev/null 2>&1; then
		bad "verify_pushed_sha: mismatch MUST hard-fail (stale binary)"
	else
		ok "verify_pushed_sha: mismatch hard-fails (rc!=0)"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_verify_pushed_sha_absent_hardfails() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "BINARY-A"
	# no file on VM
	if ( deploy_verify_pushed_sha vm "$lb" /usr/local/sbin/xpfd xpfd ) >/dev/null 2>&1; then
		bad "verify_pushed_sha: absent binary MUST hard-fail"
	else
		ok "verify_pushed_sha: absent binary hard-fails (empty readback)"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_reconcile_stale_pin_removes_managed() {
	setup_fake_vm
	mkdir -p "$FAKE_VM/etc/systemd/system/xpfd.service.d"
	printf '[Service]\nExecStart=\nExecStart=/usr/local/share/xpf/versions/v1/xpfd\n' \
		> "$FAKE_VM$DEPLOY_VERSION_DROPIN"
	if ( deploy_reconcile_stale_pin vm ) >/dev/null 2>&1; then :; else
		bad "reconcile_stale_pin: should succeed removing the managed pin"; teardown_fake_vm; return
	fi
	if [[ -f "$FAKE_VM$DEPLOY_VERSION_DROPIN" ]]; then
		bad "reconcile_stale_pin: managed pin still present after reconcile"
	elif [[ -d "$FAKE_VM/etc/systemd/system/xpfd.service.d" ]]; then
		bad "reconcile_stale_pin: empty drop-in dir not removed"
	else
		ok "reconcile_stale_pin: managed pin + empty dir removed"
	fi
	teardown_fake_vm
}

test_reconcile_stale_pin_no_pin_noop() {
	setup_fake_vm
	if ( deploy_reconcile_stale_pin vm ) >/dev/null 2>&1; then
		ok "reconcile_stale_pin: clean VM is a no-op (passes)"
	else
		bad "reconcile_stale_pin: clean VM should pass"
	fi
	teardown_fake_vm
}

test_reconcile_stale_pin_foreign_override_hardfails() {
	setup_fake_vm
	mkdir -p "$FAKE_VM/etc/systemd/system/xpfd.service.d"
	# A NON-managed ExecStart override (operator-authored) must HARD FAIL.
	printf '[Service]\nExecStart=\nExecStart=/opt/custom/xpfd\n' \
		> "$FAKE_VM/etc/systemd/system/xpfd.service.d/50-operator.conf"
	if ( deploy_reconcile_stale_pin vm ) >/dev/null 2>&1; then
		bad "reconcile_stale_pin: foreign ExecStart override MUST hard-fail"
	else
		ok "reconcile_stale_pin: foreign ExecStart override hard-fails"
	fi
	teardown_fake_vm
}

test_reconcile_dangling_sbin_removes() {
	setup_fake_vm
	# Dangling symlink into a removed versions dir.
	ln -s /usr/local/share/xpf/versions/current/xpfd "$FAKE_VM/usr/local/sbin/xpfd"
	if ( deploy_reconcile_dangling_sbin vm ) >/dev/null 2>&1; then :; else
		bad "reconcile_dangling_sbin: should succeed"; teardown_fake_vm; return
	fi
	if [[ -L "$FAKE_VM/usr/local/sbin/xpfd" ]]; then
		bad "reconcile_dangling_sbin: dangling symlink not removed"
	else
		ok "reconcile_dangling_sbin: dangling symlink removed (push can land a file)"
	fi
	# A subsequent push must now succeed (mock fails on dangling symlink).
	local lb; lb=$(mktemp); make_local_bin "$lb" "FRESH"
	if incus file push "$lb" "vm/usr/local/sbin/xpfd" --mode 0755 2>/dev/null; then
		ok "reconcile_dangling_sbin: push lands a regular file afterward"
	else
		bad "reconcile_dangling_sbin: push still fails after reconcile"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_reconcile_dangling_sbin_keeps_valid() {
	setup_fake_vm
	# A VALID symlink (target exists) is NOT removed.
	make_local_bin "$FAKE_VM/usr/local/sbin/.xpfd-real" "REAL"
	ln -s .xpfd-real "$FAKE_VM/usr/local/sbin/xpfd"
	( deploy_reconcile_dangling_sbin vm ) >/dev/null 2>&1
	if [[ -L "$FAKE_VM/usr/local/sbin/xpfd" ]]; then
		ok "reconcile_dangling_sbin: valid symlink preserved"
	else
		bad "reconcile_dangling_sbin: wrongly removed a VALID symlink"
	fi
	teardown_fake_vm
}

test_verify_running_match() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "RUNNING-OK"
	cp "$lb" "$FAKE_VM/usr/local/sbin/xpfd"
	FAKE_MAINPID="4242"
	FAKE_EXECSTART="/usr/local/sbin/xpfd"
	if ( deploy_verify_running_xpfd vm "$lb" ) >/dev/null 2>&1; then
		ok "verify_running: running sha == pushed + base ExecStart passes"
	else
		bad "verify_running: matching run should pass"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_verify_running_stale_pin_hardfails() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "RUNNING-OK"
	cp "$lb" "$FAKE_VM/usr/local/sbin/xpfd"
	FAKE_MAINPID="4242"
	# ExecStart points at a versioned path => a pin survived => MUST hard-fail.
	FAKE_EXECSTART="/usr/local/share/xpf/versions/v1/xpfd"
	if ( deploy_verify_running_xpfd vm "$lb" ) >/dev/null 2>&1; then
		bad "verify_running: surviving version pin MUST hard-fail"
	else
		ok "verify_running: surviving version pin hard-fails (ExecStart != base)"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_verify_running_stale_binary_hardfails() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "NEW-BUILD"
	# VM is running the OLD binary (different content) at the base path.
	make_local_bin "$FAKE_VM/usr/local/sbin/xpfd" "OLD-BUILD"
	FAKE_MAINPID="4242"
	FAKE_EXECSTART="/usr/local/sbin/xpfd"
	if ( deploy_verify_running_xpfd vm "$lb" ) >/dev/null 2>&1; then
		bad "verify_running: stale running binary MUST hard-fail"
	else
		ok "verify_running: stale running binary hard-fails (run sha != pushed)"
	fi
	rm -f "$lb"; teardown_fake_vm
}

# ── Run ───────────────────────────────────────────────────────────────
test_verify_pushed_sha_match
test_verify_pushed_sha_mismatch_hardfails
test_verify_pushed_sha_absent_hardfails
test_reconcile_stale_pin_removes_managed
test_reconcile_stale_pin_no_pin_noop
test_reconcile_stale_pin_foreign_override_hardfails
test_reconcile_dangling_sbin_removes
test_reconcile_dangling_sbin_keeps_valid
test_verify_running_match
test_verify_running_stale_pin_hardfails
test_verify_running_stale_binary_hardfails

echo "----------------------------------------"
echo "deploy-lib selftest: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
