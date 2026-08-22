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
# #6493: verdict the fake `xpfd verify-dataplane` probe returns, and an ordered
# log of every incus call the lib made. The log is what lets a test assert what
# did NOT happen (no stop, no push to /usr/local/sbin) on the REJECT path — the
# ordering invariant the pre-flight exists to hold.
FAKE_VERIFY_RC=0
# A FILE, not an array: every call under test runs in a subshell (die() exits,
# so the rc has to be caught), and an array mutated in a subshell is discarded
# on return. A file survives, so "what did NOT happen" is still assertable
# after the abort.
FAKE_CALL_LOG=""

setup_fake_vm() {
	FAKE_VM=$(mktemp -d)
	FAKE_MAINPID="0"
	FAKE_EXECSTART="/usr/local/sbin/xpfd"
	FAKE_VERIFY_RC=0
	FAKE_CALL_LOG=$(mktemp)
	mkdir -p "$FAKE_VM/usr/local/sbin" "$FAKE_VM/etc/systemd/system"
}

# fake_calls_contain <extended-regex> — did any recorded incus call match?
fake_calls_contain() {
	[[ -n "$FAKE_CALL_LOG" ]] && grep -qE "$1" "$FAKE_CALL_LOG" 2>/dev/null
}

teardown_fake_vm() {
	[[ -n "$FAKE_VM" && -d "$FAKE_VM" ]] && rm -rf "$FAKE_VM"
	FAKE_VM=""
	[[ -n "$FAKE_CALL_LOG" ]] && rm -f "$FAKE_CALL_LOG"
	FAKE_CALL_LOG=""
}

# incus mock: supports `incus exec <inst> -- <cmd...>` and
# `incus file push <local> <inst>/<path> [--mode m]`. <inst> is ignored
# (single fake VM). All paths resolve under $FAKE_VM.
incus() {
	# Record BEFORE dispatch so a call that dies/returns non-zero is still in
	# the log (the REJECT path's assertions read it).
	[[ -n "$FAKE_CALL_LOG" ]] && printf '%s\n' "$*" >> "$FAKE_CALL_LOG"
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
	# #6493 pre-flight probe: the body execs `<staged> verify-dataplane`.
	# Answer with the configured verdict. Checked FIRST so the generic
	# fall-through `return 0` at the bottom can never launder a REJECT into a
	# pass (a mock that silently returns 0 for an unrecognized body inverts the
	# result of every REJECT test in this file).
	if [[ "$body" == *"verify-dataplane"* ]]; then
		return "$FAKE_VERIFY_RC"
	fi
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

# ── #1864 verify-dataplane pre-flight (#6493) ────────────────────────
# The gate the standalone deploy was missing. Three properties:
#   1. a REJECT hard-fails (rc != 0) AND touches nothing on the box — no
#      systemctl stop, no push into /usr/local/sbin. That is the whole point:
#      the old daemon keeps forwarding while the operator rebuilds.
#   2. a PASS returns 0 so the deploy proceeds.
#   3. the staged /tmp/xpfd.preflight is removed on BOTH paths.
# RED on revert: drop the die() and (1) flips; drop the cleanup call from
# either path and (3) flips; hoist the call below the stop in setup.sh and the
# ORDERING test below flips.

test_preflight_pass_proceeds() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "GOOD-SHIM"
	FAKE_VERIFY_RC=0
	if ( deploy_verify_dataplane_preflight vm "$lb" ) >/dev/null 2>&1; then
		ok "preflight: verifier PASS lets the deploy proceed (rc 0)"
	else
		bad "preflight: verifier PASS must not abort the deploy"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_preflight_reject_hardfails() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "BAD-SHIM"
	FAKE_VERIFY_RC=1
	if ( deploy_verify_dataplane_preflight vm "$lb" ) >/dev/null 2>&1; then
		bad "preflight: verifier REJECT MUST hard-fail (this is the #1864 mode)"
	else
		ok "preflight: verifier REJECT hard-fails (rc!=0, deploy aborts)"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_preflight_reject_touches_nothing() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "BAD-SHIM"
	# The VM is running the OLD binary; a REJECT must leave it exactly there.
	make_local_bin "$FAKE_VM/usr/local/sbin/xpfd" "OLD-RUNNING"
	FAKE_VERIFY_RC=1
	# Subshell for the rc (die() exits); the call log is a file so it survives.
	local rc=0
	( deploy_verify_dataplane_preflight vm "$lb" ) >/dev/null 2>&1 || rc=$?
	if [[ $rc -eq 0 ]]; then
		bad "preflight: REJECT must not return 0"
		rm -f "$lb"; teardown_fake_vm; return
	fi
	if fake_calls_contain "systemctl stop"; then
		bad "preflight: REJECT stopped the daemon — the box was taken down to learn the binary is bad"
	elif fake_calls_contain "vm/usr/local/sbin/xpfd"; then
		bad "preflight: REJECT pushed into /usr/local/sbin — the bad binary replaced the good one"
	elif [[ "$(cat "$FAKE_VM/usr/local/sbin/xpfd")" != "OLD-RUNNING" ]]; then
		bad "preflight: REJECT overwrote the running binary"
	else
		ok "preflight: REJECT leaves the old daemon untouched (no stop, no sbin push)"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_preflight_cleans_up_on_pass() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "GOOD-SHIM"
	FAKE_VERIFY_RC=0
	( deploy_verify_dataplane_preflight vm "$lb" ) >/dev/null 2>&1
	if [[ -e "$FAKE_VM/tmp/xpfd.preflight" ]]; then
		bad "preflight: staged candidate left behind after PASS"
	else
		ok "preflight: staged /tmp/xpfd.preflight removed after PASS"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_preflight_cleans_up_on_reject() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "BAD-SHIM"
	FAKE_VERIFY_RC=1
	( deploy_verify_dataplane_preflight vm "$lb" ) >/dev/null 2>&1
	if [[ -e "$FAKE_VM/tmp/xpfd.preflight" ]]; then
		bad "preflight: staged candidate left behind after REJECT (poisons the next probe's diagnosis)"
	else
		ok "preflight: staged /tmp/xpfd.preflight removed after REJECT"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_preflight_missing_local_binary_hardfails() {
	setup_fake_vm
	FAKE_VERIFY_RC=0
	# No local build at all: must fail loudly rather than push nothing and
	# "pass" a probe of a binary that does not exist.
	if ( deploy_verify_dataplane_preflight vm /nonexistent/xpfd ) >/dev/null 2>&1; then
		bad "preflight: absent local xpfd MUST hard-fail"
	else
		ok "preflight: absent local xpfd hard-fails before any remote work"
	fi
	teardown_fake_vm
}

# ── ORDERING: the call site position, not the function ───────────────
# The function can be perfect and the gate still useless if a caller runs it
# after `systemctl stop xpfd`. These read the real deploy scripts and assert the
# pre-flight call precedes every destructive step in the same function. Purely
# textual (no incus), and RED the moment either call is hoisted or removed.
# _first_line_matching <file> <grep-ere> -> line number of the first matching
# NON-COMMENT line, or empty.
#
# The comment filter is load-bearing, not tidiness: the pre-flight call sites
# are documented with prose that NAMES the destructive steps ("...runs before
# `systemctl stop xpfd`..."), so an unanchored sweep matches the explanation of
# the invariant instead of the code that breaks it — and reports the gate as
# mis-ordered while it is in fact correct. Caught by this very test on its
# first run.
_first_line_matching() {
	grep -nE "$2" "$1" 2>/dev/null \
		| awk -F: '{ line = $0; sub(/^[0-9]+:/, "", line); if (line !~ /^[[:space:]]*#/) { print $1; exit } }'
}

test_preflight_precedes_destructive_steps_standalone() {
	local f="${SCRIPT_DIR}/setup.sh"
	local pre stop push
	pre=$(_first_line_matching "$f" '^[[:space:]]*deploy_verify_dataplane_preflight ')
	stop=$(_first_line_matching "$f" 'systemctl stop xpfd')
	push=$(_first_line_matching "$f" 'incus file push .*/usr/local/sbin/xpfd')
	if [[ -z "$pre" ]]; then
		bad "ordering(setup.sh): no deploy_verify_dataplane_preflight call — the standalone deploy has NO verifier gate (#6493)"
	elif [[ -z "$stop" || -z "$push" ]]; then
		bad "ordering(setup.sh): could not locate the stop/push anchors — test is stale, fix the pattern"
	elif (( pre < stop && pre < push )); then
		ok "ordering(setup.sh): pre-flight at :$pre precedes stop(:$stop) and sbin push(:$push)"
	else
		bad "ordering(setup.sh): pre-flight at :$pre runs AFTER stop(:$stop)/push(:$push) — the box is already down when the gate fires"
	fi
}

test_preflight_precedes_destructive_steps_cluster() {
	local f="${SCRIPT_DIR}/cluster-setup.sh"
	local pre stop push
	pre=$(_first_line_matching "$f" '^[[:space:]]*deploy_verify_dataplane_preflight ')
	stop=$(_first_line_matching "$f" 'systemctl stop bpfrxd')
	push=$(_first_line_matching "$f" 'incus file push .*/usr/local/sbin/xpfd')
	if [[ -z "$pre" ]]; then
		bad "ordering(cluster-setup.sh): no deploy_verify_dataplane_preflight call — the #1869 gate was lost"
	elif [[ -z "$stop" || -z "$push" ]]; then
		bad "ordering(cluster-setup.sh): could not locate the stop/push anchors — test is stale, fix the pattern"
	elif (( pre < stop && pre < push )); then
		ok "ordering(cluster-setup.sh): pre-flight at :$pre precedes migration stop(:$stop) and sbin push(:$push)"
	else
		bad "ordering(cluster-setup.sh): pre-flight at :$pre runs AFTER stop(:$stop)/push(:$push)"
	fi
}

# ── Rolling-deploy node ordering (#4009) ─────────────────────────────
# Captured `cli -c "show chassis cluster status"` samples (FormatStatus,
# pkg/cluster/status.go). deploy_rolling_secondary_node must echo the RG0
# SECONDARY node index (upgrade it FIRST). RED-on-revert: the retired
# inline `grep "secondary:node0"` never matched these space-separated,
# lowercase rows, so a node0-secondary cluster wrongly resolved to
# node1-first — restarting the PRIMARY first → a spurious mid-deploy failover.

STATUS_NODE0_PRIMARY="Monitor Failure codes:
    CS  Cold Sync monitoring        FL  Fabric Connection monitoring

Cluster ID: 1
Node name: node0

Node    Priority  Status         Preempt  Manual   Monitor-failures

Redundancy group: 0 , Failover count: 0
node0   200       primary        no       no       None
  Takeover ready: yes
  Transfer ready: yes
node1   100       secondary      no       no       None
"

STATUS_NODE0_SECONDARY="Redundancy group: 0 , Failover count: 1
node0   100       secondary      no       no       None
node1   200       primary        no       no       None
"

# Active-active: node0 is SECONDARY for RG0 but PRIMARY for RG1. The decision
# must be scoped to RG0 (the mastership that steers the WAN path) → node0 first.
STATUS_MULTI_RG_NODE0_SEC_RG0="Redundancy group: 0 , Failover count: 1
node0   200       secondary      no       no       None
node1   100       primary        no       no       None

Redundancy group: 1 , Failover count: 2
node0   200       primary        no       no       None
node1   100       secondary      no       no       None
"

STATUS_SECONDARY_HOLD="Redundancy group: 0 , Failover count: 0
node0   100       secondary-hold no       no       None
node1   200       primary        no       no       None
"

STATUS_PEER_DOWN="Redundancy group: 0 , Failover count: 0
node0   200       primary        no       no       None
"

test_rolling_secondary_node0_primary() {
	local got; got=$(printf '%s' "$STATUS_NODE0_PRIMARY" | deploy_rolling_secondary_node)
	if [[ "$got" == 1 ]]; then
		ok "rolling: node0 primary -> upgrade node1 (secondary) first"
	else
		bad "rolling: node0 primary -> expected 1, got '$got'"
	fi
}

test_rolling_secondary_node0_secondary() {
	local got; got=$(printf '%s' "$STATUS_NODE0_SECONDARY" | deploy_rolling_secondary_node)
	if [[ "$got" == 0 ]]; then
		ok "rolling: node0 secondary -> upgrade node0 first (no spurious failover)"
	else
		bad "rolling: node0 secondary -> expected 0, got '$got' (retired secondary:node0 grep gives 1 -> restarts PRIMARY first)"
	fi
}

test_rolling_secondary_multi_rg_scoped_to_rg0() {
	local got; got=$(printf '%s' "$STATUS_MULTI_RG_NODE0_SEC_RG0" | deploy_rolling_secondary_node)
	if [[ "$got" == 0 ]]; then
		ok "rolling: multi-RG decision scoped to RG0 (node0 secondary in RG0)"
	else
		bad "rolling: multi-RG -> expected 0 (RG0), got '$got'"
	fi
}

test_rolling_secondary_hold_counts_as_secondary() {
	local got; got=$(printf '%s' "$STATUS_SECONDARY_HOLD" | deploy_rolling_secondary_node)
	if [[ "$got" == 0 ]]; then
		ok "rolling: node0 secondary-hold -> upgrade node0 first"
	else
		bad "rolling: secondary-hold -> expected 0, got '$got'"
	fi
}

test_rolling_secondary_peer_down_defaults() {
	local got; got=$(printf '%s' "$STATUS_PEER_DOWN" | deploy_rolling_secondary_node)
	if [[ "$got" == 1 ]]; then
		ok "rolling: node0 primary (peer down) -> default node1 first"
	else
		bad "rolling: peer-down -> expected 1, got '$got'"
	fi
}

test_rolling_secondary_empty_defaults() {
	local got; got=$(printf '' | deploy_rolling_secondary_node)
	if [[ "$got" == 1 ]]; then
		ok "rolling: empty/unparseable status -> default node1 first"
	else
		bad "rolling: empty -> expected 1, got '$got'"
	fi
}

test_rolling_rg_ids() {
	local got; got=$(printf '%s' "$STATUS_MULTI_RG_NODE0_SEC_RG0" | deploy_rolling_rg_ids | tr '\n' ' ')
	if [[ "$got" == "0 1 " ]]; then
		ok "rolling: rg-id extraction lists '0 1' for the post-deploy reassert"
	else
		bad "rolling: rg-ids -> expected '0 1 ', got '$got'"
	fi
}

# ── Run ───────────────────────────────────────────────────────────────
test_rolling_secondary_node0_primary
test_rolling_secondary_node0_secondary
test_rolling_secondary_multi_rg_scoped_to_rg0
test_rolling_secondary_hold_counts_as_secondary
test_rolling_secondary_peer_down_defaults
test_rolling_secondary_empty_defaults
test_rolling_rg_ids
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
test_preflight_pass_proceeds
test_preflight_reject_hardfails
test_preflight_reject_touches_nothing
test_preflight_cleans_up_on_pass
test_preflight_cleans_up_on_reject
test_preflight_missing_local_binary_hardfails
test_preflight_precedes_destructive_steps_standalone
test_preflight_precedes_destructive_steps_cluster

echo "----------------------------------------"
echo "deploy-lib selftest: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
