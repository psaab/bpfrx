#!/usr/bin/env bash
# Shared raw-deploy reconciliation + verification helpers for the xpf test
# Incus deploy paths (setup.sh and cluster-setup.sh).
#
# Both scripts push xpfd/cli/xpf-userspace-dp to a VM with `incus file push`
# and then (re)start the systemd unit. Two classes of stale-state on the
# target VM silently defeat that swap and make a deploy report success while
# the node keeps running OLD code — the #1 false-result hazard:
#
#   #2176 (a): a leftover #1917 in-place-upgrade drop-in
#     /etc/systemd/system/xpfd.service.d/10-xpf-version.conf pins ExecStart to
#     a CONCRETE versioned binary (versions/<ver>/xpfd). A raw `incus file push`
#     replaces /usr/local/sbin/xpfd, but systemd still launches the pinned
#     versioned path, so the freshly-pushed binary never runs.
#
#   #2176 (b): after that drop-in's versions/ dir is removed,
#     /usr/local/sbin/{xpfd,cli,xpf-userspace-dp} are left as DANGLING symlinks
#     into versions/current/<bin>. `incus file push` onto a dangling symlink
#     fails (no target to write through), breaking the deploy.
#
# These helpers run BEFORE the binary push to reconcile both, and AFTER the
# restart to ASSERT the running binary sha == the pushed sha (#2176 (c)) and
# that the effective ExecStart is the base-unit path (no surviving pin).
#
# #2162: deploy_verify_pushed_sha generalizes the helper-only sha readback
# (#1962/#1980) so xpfd and cli get the same HARD post-push verification.
#
# All functions take a FULLY-RESOLVED instance name (e.g. "loss:xpf-userspace-fw0"
# or "xpf-fw") because the two callers compute that differently (cluster-setup.sh
# r() remote prefix vs setup.sh INSTANCE_NAME). They depend on info()/warn()/die()
# being defined by the sourcing script (both define them identically).

# deploy_managed_bins is the set of binaries the deploy paths push into
# /usr/local/sbin and that the #1917 upgrade machinery links/pins. Keep in
# sync with pkg/upgrade manifest.Names() (xpfd, cli, xpf-userspace-dp).
deploy_managed_bins=(xpfd cli xpf-userspace-dp)

# The #1917 in-place-upgrade ExecStart pin drop-in (pkg/upgrade/flip.go
# unitDropinName). Removing it reverts the unit to the package/base-unit
# ExecStart=/usr/local/sbin/xpfd.
DEPLOY_VERSION_DROPIN="/etc/systemd/system/xpfd.service.d/10-xpf-version.conf"

# deploy_reconcile_stale_pin <rinst>
#
# Detect a stale xpfd ExecStart override drop-in on the target and remove it,
# reverting to the base-unit ExecStart=/usr/local/sbin/xpfd, then daemon-reload
# so the change is in effect before the unit is (re)started. Without this a raw
# deploy pushes a new /usr/local/sbin/xpfd that systemd never launches (#2176a).
#
# Only the xpf-managed pin file (10-xpf-version.conf) is removed automatically;
# any OTHER, operator-authored ExecStart override under xpfd.service.d is a HARD
# FAILURE (we will not silently delete a drop-in we did not write).
deploy_reconcile_stale_pin() {
	local rinst="$1"

	# Is the managed #1917 pin present?
	if incus exec "$rinst" -- test -f "$DEPLOY_VERSION_DROPIN" 2>/dev/null; then
		warn "Removing stale #1917 ExecStart pin ($DEPLOY_VERSION_DROPIN) on $rinst — it would pin systemd to an OLD versioned xpfd and silently defeat this deploy (#2176)."
		incus exec "$rinst" -- rm -f "$DEPLOY_VERSION_DROPIN" 2>/dev/null \
			|| die "failed to remove stale ExecStart pin $DEPLOY_VERSION_DROPIN on $rinst"
		# Drop an empty xpfd.service.d if nothing else remains, so the unit
		# is purely the base file again.
		incus exec "$rinst" -- bash -c 'd=/etc/systemd/system/xpfd.service.d; [ -d "$d" ] && [ -z "$(ls -A "$d" 2>/dev/null)" ] && rmdir "$d"; true' 2>/dev/null || true
		incus exec "$rinst" -- systemctl daemon-reload 2>/dev/null || true
	fi

	# Refuse to proceed if SOME OTHER ExecStart override survives in the
	# drop-in dir — a raw deploy must never leave an unknown pin in force.
	local other
	other=$(incus exec "$rinst" -- bash -c '
		d=/etc/systemd/system/xpfd.service.d
		[ -d "$d" ] || exit 0
		grep -lE "^[[:space:]]*ExecStart[[:space:]]*=" "$d"/*.conf 2>/dev/null || true
	' 2>/dev/null || true)
	if [[ -n "$other" ]]; then
		die "unexpected ExecStart override(s) under xpfd.service.d on $rinst — a raw deploy will not run the pushed binary while these pin a different path. Remove them or fix the drop-in, then re-deploy:
$other"
	fi
}

# deploy_reconcile_dangling_sbin <rinst>
#
# Detect dangling /usr/local/sbin/{xpfd,cli,xpf-userspace-dp} symlinks (left
# pointing into a removed versions/current/ after a #1917 dogfood was torn
# down) and remove them, so the subsequent `incus file push` lands a fresh
# REGULAR file instead of failing to write through a broken symlink (#2176b).
deploy_reconcile_dangling_sbin() {
	local rinst="$1"
	local b
	for b in "${deploy_managed_bins[@]}"; do
		local p="/usr/local/sbin/$b"
		# -L: is a symlink; -e: resolves to an existing target. A symlink
		# that is NOT -e is dangling.
		if incus exec "$rinst" -- bash -c "[ -L '$p' ] && [ ! -e '$p' ]" 2>/dev/null; then
			warn "Replacing dangling symlink $p on $rinst (points into a removed versions/ dir) with the freshly-pushed binary (#2176)."
			incus exec "$rinst" -- rm -f "$p" 2>/dev/null \
				|| die "failed to remove dangling symlink $p on $rinst"
		fi
	done
}

# deploy_verify_pushed_sha <rinst> <local_path> <remote_path> <label>
#
# Assert the on-VM sha256 of a just-pushed binary matches the local build.
# An `incus file push` can silently no-op and the local build can be stale;
# either leaves the VM running an old/absent binary. HARD FAIL on mismatch or
# empty readback (#2162 generalizes the #1962/#1980 helper-only check).
deploy_verify_pushed_sha() {
	local rinst="$1" local_path="$2" remote_path="$3" label="$4"
	local local_sum vm_sum
	local_sum=$(sha256sum "$local_path" | awk '{print $1}')
	# Readback may fail (binary absent) — || true so the explicit empty-check
	# below produces the clear diagnostic instead of set -e aborting here.
	vm_sum=$(incus exec "$rinst" -- sha256sum "$remote_path" 2>/dev/null | awk '{print $1}' || true)
	if [[ -z "$vm_sum" ]]; then
		die "$label not present on $rinst after push (sha256 readback empty: $remote_path)"
	fi
	if [[ "$local_sum" != "$vm_sum" ]]; then
		die "$label sha256 mismatch after push to $rinst (local=$local_sum vm=$vm_sum) — push silently no-op'd or the build is stale"
	fi
	info "Verified $label sha256 on $rinst ($local_sum)."
}

# deploy_verify_running_xpfd <rinst> <local_xpfd_path>
#
# After (re)start, assert the LIVE xpfd process is the binary we just pushed
# (running-exe sha == local build) AND that the effective systemd ExecStart is
# the base-unit /usr/local/sbin/xpfd path — i.e. no version pin survived. This
# is the backstop that turns a silent stale-binary deploy into a HARD failure
# (#2176c). The whole point: a deploy MUST rc!=0 if the running binary != the
# pushed binary.
deploy_verify_running_xpfd() {
	local rinst="$1" local_xpfd="$2"
	local local_sum want_exec="/usr/local/sbin/xpfd"
	local_sum=$(sha256sum "$local_xpfd" | awk '{print $1}')

	# Effective ExecStart must resolve to the base-unit path. `systemctl show`
	# emits ExecStart={ path=/usr/local/sbin/xpfd ; ... }; extract the path=.
	local exec_path
	exec_path=$(incus exec "$rinst" -- bash -c "systemctl show -p ExecStart --value xpfd 2>/dev/null | sed -n 's/.*path=\([^ ;]*\).*/\1/p' | head -n1" 2>/dev/null || true)
	if [[ -z "$exec_path" ]]; then
		die "could not read effective xpfd ExecStart on $rinst — cannot confirm the deploy is in effect"
	fi
	if [[ "$exec_path" != "$want_exec" ]]; then
		die "xpfd ExecStart on $rinst is '$exec_path', not the base-unit '$want_exec' — a version pin survived this deploy (#2176); systemd is launching a different binary than was pushed"
	fi

	# Running-process exe sha must equal the local build. Wait briefly for the
	# unit to come up (enable --now / restart returns before the main PID is
	# necessarily settled).
	local tries=0 run_raw="" run_sum=""
	while [[ $tries -lt 15 ]]; do
		# The remote emits the raw `sha256sum /proc/PID/exe` line; the first
		# field is split off locally to avoid nested single-quote awk fragility.
		# sha256sum on /proc/PID/exe reads the LIVE process image even if the
		# on-disk file was replaced after exec ("(deleted)").
		run_raw=$(incus exec "$rinst" -- bash -c '
			p=$(systemctl show -p MainPID --value xpfd 2>/dev/null)
			[ -n "$p" ] && [ "$p" != "0" ] || exit 1
			sha256sum "/proc/$p/exe" 2>/dev/null || exit 1
		' 2>/dev/null || true)
		run_sum=${run_raw%% *}
		[[ -n "$run_sum" ]] && break
		tries=$((tries + 1))
		sleep 1
	done
	if [[ -z "$run_sum" ]]; then
		die "xpfd is not running on $rinst after deploy (no live MainPID) — cannot verify the running binary"
	fi
	if [[ "$run_sum" != "$local_sum" ]]; then
		die "running xpfd on $rinst (sha256=$run_sum) does not match the pushed build (sha256=$local_sum) — the deploy did NOT take effect (#2176); the node is running STALE code"
	fi
	info "Verified running xpfd on $rinst matches the pushed build ($local_sum, ExecStart=$exec_path)."
}
