package upgrade

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unsafe"

	"github.com/psaab/xpf/pkg/fsatomic"
	"golang.org/x/sys/unix"
)

var (
	// An efibootmgr entry line is "BootXXXX*<sp>LABEL<TAB>loader-path"
	// (active entries have the '*', inactive do not). The LABEL is the field
	// between the id and the TAB that introduces the device/loader path —
	// capture ONLY the label, not the trailing tab+path (a `(.+)` greedy
	// capture would fold the whole path into the key — caught live, #1930).
	// Some entries have no loader path (no tab) — `[^\t]+` then tolerates EOL.
	bootEntryRE          = regexp.MustCompile(`^Boot([0-9A-F]{4})\*?\s+([^\t]+?)(?:\t.*)?$`)
	bootCurrentRE        = regexp.MustCompile(`^BootCurrent:\s*([0-9A-F]{4})`)
	slotSelectorKernelRE = regexp.MustCompile(`xpf_slot_kernel="vmlinuz-([^"]+)"`)
)

// realKernelSystem is the production KernelSystem backed by UEFI, apt, GRUB,
// systemd, and the Linux watchdog device.
type realKernelSystem struct {
	// ProbeFunc is wired by the caller when a richer forward-health probe is
	// available (e.g. xpfd with its dataplane manager). When nil, ForwardBeacon
	// does a real reachability ping through the dataplane to BeaconTarget.
	ProbeFunc func(deadline time.Time) (bool, error)
	// BeaconTarget is the ForwardBeacon ping target; empty -> the IPv4 default
	// gateway. Set via XPF_KERNEL_BEACON_TARGET for a topology-specific peer.
	BeaconTarget string
}

var _ KernelSystem = (*realKernelSystem)(nil)

// NewKernelSystem returns the production KernelSystem implementation. The
// forward-beacon target may be pinned via XPF_KERNEL_BEACON_TARGET (else the
// IPv4 default gateway is used).
func NewKernelSystem() *realKernelSystem {
	return &realKernelSystem{BeaconTarget: os.Getenv("XPF_KERNEL_BEACON_TARGET")}
}

func (s *realKernelSystem) IsUEFI() bool {
	st, err := os.Stat("/sys/firmware/efi/efivars")
	return err == nil && st.IsDir()
}

func (s *realKernelSystem) EfibootmgrOK() bool {
	return runCmd("efibootmgr") == nil
}

func (s *realKernelSystem) BootEntries() (map[string]string, error) {
	out, err := captureCmd("efibootmgr")
	if err != nil {
		return nil, err
	}
	entries := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		m := bootEntryRE.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}
		entries[strings.TrimSpace(m[2])] = m[1]
	}
	return entries, nil
}

func (s *realKernelSystem) BootOrder() ([]string, error) {
	out, err := captureCmd("efibootmgr")
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(line, "BootOrder:")
		if !ok {
			continue
		}
		var order []string
		for _, part := range strings.Split(rest, ",") {
			id := strings.TrimSpace(part)
			if id != "" {
				order = append(order, id)
			}
		}
		return order, nil
	}
	return nil, fmt.Errorf("BootOrder not found in efibootmgr output")
}

func (s *realKernelSystem) GrubSubmenuDisabled() (bool, error) {
	hasDisable := false
	for _, path := range grubDefaultFiles() {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return false, fmt.Errorf("read %s: %w", path, err)
		}
		if strings.Contains(string(data), "GRUB_DISABLE_SUBMENU=y") {
			hasDisable = true
			break
		}
	}

	st, err := os.Stat("/etc/grub.d/09_xpf")
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("stat /etc/grub.d/09_xpf: %w", err)
	}
	return hasDisable && st.Mode()&0111 != 0, nil
}

func (s *realKernelSystem) WatchdogStatus() (bool, bool) {
	_, wdErr := os.Stat("/dev/watchdog")
	_, persistentErr := os.Stat("/etc/xpf/kernel-channel/watchdog-persistent")
	return wdErr == nil, persistentErr == nil
}

func (s *realKernelSystem) FreeBytes(path string) (uint64, error) {
	var st unix.Statfs_t
	// Stat the nearest existing ancestor so a not-yet-created versions dir
	// still yields the backing filesystem's free space.
	p := path
	for {
		if _, err := os.Stat(p); err == nil {
			break
		}
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		p = parent
	}
	if err := unix.Statfs(p, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", p, err)
	}
	return st.Bavail * uint64(st.Bsize), nil
}

func (s *realKernelSystem) RunningKernel() (string, error) {
	out, err := captureCmd("uname", "-r")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// KernelHeld reports whether EVERY currently-installed linux-* package is held
// (r1 Codex High: a "any linux- is held" check false-passes a PARTIAL rehold).
func (s *realKernelSystem) KernelHeld() (bool, error) {
	out, err := captureCmd("apt-mark", "showhold")
	if err != nil {
		return false, err
	}
	held := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if p := strings.TrimSpace(line); p != "" {
			held[p] = true
		}
	}
	installed := currentLinuxPackages()
	if len(installed) == 0 {
		// No linux-* installed at all — treat as "not held" so the caller
		// surfaces the anomaly rather than silently passing.
		return false, nil
	}
	for _, p := range installed {
		if !held[p] {
			return false, nil
		}
	}
	return true, nil
}

func (s *realKernelSystem) InstallCandidateKernel(version string) (string, error) {
	unholdLinuxPackages()
	reheld := false
	defer func() {
		// On ANY early return (install/initramfs/grub failure) the deferred
		// rehold restores the safety floor. A best-effort rehold here is
		// acceptable ONLY because the caller's KernelHeld() pre-arm re-assert
		// (kernel_run.go) verifies the FULL set is held and aborts the arm
		// otherwise (r1 Codex High); we log a failure so it is not silent.
		if !reheld {
			if err := holdLinuxPackages(); err != nil {
				fmt.Fprintf(os.Stderr, "kernel-upgrade: WARNING deferred rehold after failed install: %v\n", err)
			}
		}
	}()

	pkgs := []string{"linux-image-" + version, "linux-modules-" + version}
	// linux-modules-extra carries the mlx5/i40e (and other) NIC drivers the
	// appliance bake explicitly requires (bake.py asserts it). Omitting it
	// would boot a candidate that cannot drive the dataplane NICs — a failure
	// the virtio OVMF test would NOT surface (r1 Codex High). Include it when
	// available so the candidate has the same driver set as the running kernel.
	extraPkg := "linux-modules-extra-" + version
	if aptPackageAvailable(extraPkg) {
		pkgs = append(pkgs, extraPkg)
	}
	headersPkg := "linux-headers-" + version
	if aptPackageAvailable(headersPkg) {
		pkgs = append(pkgs, headersPkg)
	}
	installArgs := append([]string{"install", "-y"}, pkgs...)
	if err := aptGet(installArgs...); err != nil {
		return "", err
	}
	if err := runCmd("update-initramfs", "-u", "-k", version); err != nil {
		return "", err
	}
	if err := runCmd("update-grub"); err != nil {
		return "", err
	}

	// Rehold is load-bearing (the candidate must not be apt-movable after this
	// window) — a failure here is FATAL to the install (r1 Codex High).
	if err := holdLinuxPackages(); err != nil {
		return "", fmt.Errorf("rehold linux-* after candidate install: %w", err)
	}
	reheld = true

	// The candidate's uname -r is the requested version when the standard
	// "<version>" naming holds; prefer the actual /lib/modules dir if present.
	if _, err := os.Stat(filepath.Join("/lib/modules", version)); err == nil {
		return version, nil
	}
	return version, nil
}

func (s *realKernelSystem) DefaultBootEntry() (string, error) {
	order, err := s.BootOrder()
	if err != nil {
		return "", err
	}
	if len(order) == 0 {
		return "", fmt.Errorf("BootOrder is empty")
	}
	return order[0], nil
}

func (s *realKernelSystem) WriteSlotSelector(slot, unameR string) error {
	dir := filepath.Join("/boot/efi/EFI", slot)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create slot selector dir %s: %w", dir, err)
	}
	content := fmt.Sprintf("set xpf_slot_kernel=\"vmlinuz-%s\"\nset xpf_slot_initrd=\"initrd.img-%s\"\n", unameR, unameR)
	if err := fsatomic.WriteFileDurable(filepath.Join(dir, "xpf.selector"), []byte(content), 0644); err != nil {
		return fmt.Errorf("write slot selector: %w", err)
	}
	return nil
}

func (s *realKernelSystem) ReadSlotSelector(slot string) (string, error) {
	path := filepath.Join("/boot/efi/EFI", slot, "xpf.selector")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read slot selector %s: %w", path, err)
	}
	m := slotSelectorKernelRE.FindSubmatch(data)
	if len(m) != 2 {
		return "", nil
	}
	return string(m[1]), nil
}

func (s *realKernelSystem) SetBootNext(bootID string) error {
	return runCmd("efibootmgr", "--bootnext", bootID)
}

// watchdogTimeoutSecs is the timeout armed before the candidate reboot. It must
// exceed the WORST-CASE time from this arm to the candidate boot petting/
// disarming the watchdog — which on physical servers includes a full UEFI POST
// + memory training (minutes), so a 60s default would reset the box mid-POST
// (r1 AGY). Default 600s; overridable via XPF_KERNEL_WATCHDOG_TIMEOUT_SECS.
func watchdogTimeoutSecs() int32 {
	if v := os.Getenv("XPF_KERNEL_WATCHDOG_TIMEOUT_SECS"); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return int32(n)
		}
	}
	return 600
}

// ArmWatchdog sets a generous timeout and pets once. NOTE: the watchdog is
// best-effort (Path Option D2): the firmware-cleared BootNext is what actually
// closes the boot-LOOP; the watchdog only converts an early-boot HANG into the
// reset that triggers that fallback. It is armed only right before the reboot.
func (s *realKernelSystem) ArmWatchdog() error {
	if _, err := os.Stat("/dev/watchdog"); err != nil {
		return fmt.Errorf("/dev/watchdog unavailable: %w", err)
	}
	fd, err := unix.Open("/dev/watchdog", unix.O_WRONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open /dev/watchdog: %w", err)
	}
	defer unix.Close(fd)

	timeout := watchdogTimeoutSecs()
	// WDIOC_SETTIMEOUT failure (driver doesn't support it) is non-fatal — fall
	// through to a keepalive write to at least pet whatever default timeout the
	// driver has; the keepalive is the minimal arm signal.
	_, _, _ = unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.WDIOC_SETTIMEOUT), uintptr(unsafe.Pointer(&timeout)))
	return writeWatchdogKeepalive(fd)
}

func (s *realKernelSystem) Reboot() error {
	return exec.Command("systemctl", "reboot").Run()
}

// promotionMarkerPath records the last promoted kernel uname -r (survives the
// journal clear) for the external HA orchestrator's post-reboot version-check.
const promotionMarkerPath = "/var/lib/xpf/kernel-promoted"

func (s *realKernelSystem) WritePromotionMarker(unameR string) error {
	if err := fsatomic.MkdirAllDurable(filepath.Dir(promotionMarkerPath), 0755); err != nil {
		return fmt.Errorf("create promotion marker dir: %w", err)
	}
	return fsatomic.WriteFileDurable(promotionMarkerPath, []byte(unameR+"\n"), 0644)
}

func (s *realKernelSystem) ReadPromotionMarker() (string, error) {
	data, err := os.ReadFile(promotionMarkerPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read promotion marker: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

func (s *realKernelSystem) ClearPromotionMarker() error {
	if err := os.Remove(promotionMarkerPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear promotion marker: %w", err)
	}
	return nil
}

func (s *realKernelSystem) ClearRollLease() error {
	if err := os.Remove(DefaultKernelRollLeasePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear kernel-roll lease: %w", err)
	}
	return nil
}

func (s *realKernelSystem) BootCurrent() (string, error) {
	out, err := captureCmd("efibootmgr")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		m := bootCurrentRE.FindStringSubmatch(line)
		if len(m) == 2 {
			return m[1], nil
		}
	}
	return "", fmt.Errorf("BootCurrent not found in efibootmgr output")
}

func (s *realKernelSystem) VerifyDataplane() (bool, error) {
	cmd := exec.Command("xpfd", "verify-dataplane")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	if ee, ok := err.(*exec.ExitError); ok {
		// exit 3 = REJECT (verifier rejected the shim). main.go contract.
		if ee.ExitCode() == 3 {
			return false, nil
		}
	}
	return false, fmt.Errorf("verify-dataplane exec failed: %w (output: %s)", err, strings.TrimSpace(out.String()))
}

// ForwardBeacon proves the candidate kernel can actually FORWARD, not merely
// that a unit is active (r2 Codex Critical: `systemctl is-active` is not a
// forwarding proof).
//
// BeaconTarget guidance (r1 AGY): for a meaningful proof the operator SHOULD set
// XPF_KERNEL_BEACON_TARGET to a DATAPLANE-side target (e.g. the HA peer link or
// a known host reachable only through a dataplane interface). The default
// IPv4-gateway fallback is a WEAK best-effort: on a box whose default route is
// the out-of-band management interface it can false-PASS (ping succeeds over
// mgmt while the dataplane is broken), and on a transit/BGP router with no
// static default route it returns "" and fail-SAFE-reverts. Neither is a silent
// brick — a false-pass still required verify-dataplane (the #1864 kernel
// verifier, Gate 3) to PASS first, and the fail-safe revert is recoverable —
// but the strong gate is an operator-set dataplane BeaconTarget. A wired
// ProbeFunc (the richest probe, when the caller has the dataplane manager) takes
// precedence; otherwise this does a REAL reachability probe through the
// dataplane: the dataplane daemon (xpfd OR xpfd-userspace-dp) must be active AND
// a ping to BeaconTarget (default: the IPv4
// default gateway) must succeed within the
// deadline. A candidate kernel whose shim verified (Gate 3) but cannot forward
// fails the ping -> revert. The gateway is the most universally-available
// off-box target that exercises the forwarding path; an operator can override
// BeaconTarget for a topology-specific peer-link target.
func (s *realKernelSystem) ForwardBeacon(deadline time.Duration) (bool, error) {
	if s.ProbeFunc != nil {
		return s.ProbeFunc(time.Now().Add(deadline))
	}
	// the dataplane daemon (xpfd OR xpfd-userspace-dp) must be up at all — a
	// down daemon cannot
	// forward regardless of ping.
	if runCmd("systemctl", "is-active", "xpfd") != nil &&
		runCmd("systemctl", "is-active", "xpfd-userspace-dp") != nil {
		return false, nil
	}
	target := s.BeaconTarget
	if target == "" {
		target = defaultGateway()
	}
	if target == "" {
		// No reachable target to probe. Be HONEST: we cannot prove forwarding,
		// so do NOT promote on a "pass" we can't substantiate — return false so
		// the caller reverts (a conservative, fail-safe default; the operator
		// can set BeaconTarget to enable promotion on a box with no gateway).
		return false, fmt.Errorf("no forward-beacon target (no default gateway; set BeaconTarget)")
	}
	secs := int(deadline.Seconds())
	if secs < 1 {
		secs = 1
	}
	// ping -c <n> -w <deadline>: a single reply within the window proves the
	// dataplane forwarded a packet off-box on the candidate kernel.
	if err := runCmd("ping", "-c", "3", "-w", fmt.Sprintf("%d", secs), target); err != nil {
		return false, nil
	}
	return true, nil
}

// defaultGateway returns the IPv4 default-route next hop, or "" if none.
func defaultGateway() string {
	out, err := captureCmd("ip", "-4", "route", "show", "default")
	if err != nil {
		return ""
	}
	// "default via 10.0.0.1 dev eth0 ..."
	fields := strings.Fields(out)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "via" {
			return fields[i+1]
		}
	}
	return ""
}

func (s *realKernelSystem) SetBootOrderFront(bootID string) error {
	order, err := s.BootOrder()
	if err != nil {
		return err
	}
	if len(order) > 0 && order[0] == bootID {
		return nil
	}
	next := []string{bootID}
	for _, id := range order {
		if id != bootID {
			next = append(next, id)
		}
	}
	return runCmd("efibootmgr", "--bootorder", strings.Join(next, ","))
}

func (s *realKernelSystem) DisarmWatchdog() error {
	if _, err := os.Stat("/dev/watchdog"); err != nil {
		return nil
	}
	fd, err := unix.Open("/dev/watchdog", unix.O_WRONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil
	}
	_, _ = unix.Write(fd, []byte{'V'})
	_ = unix.Close(fd)
	return nil
}

func (s *realKernelSystem) PruneInactiveSlot(slot, knownGoodUnameR, candidateVersion string) error {
	if err := s.WriteSlotSelector(slot, knownGoodUnameR); err != nil {
		return err
	}
	// The candidate kernel packages are HELD (InstallCandidateKernel re-holds
	// the full set), so `apt-get purge` must be allowed to change held packages
	// or it leaves the candidate installed-in-dpkg while we delete its files
	// (r2 Codex High). Include linux-modules-extra (the install adds it). All
	// best-effort: a prune failure must not block the revert (the firmware
	// fallback is the safety), but we no longer purge a held pkg without the
	// override and we cover the same package set the install added.
	candPkgs := []string{
		"linux-image-" + candidateVersion,
		"linux-modules-" + candidateVersion,
		"linux-modules-extra-" + candidateVersion,
		"linux-headers-" + candidateVersion,
	}
	// Only purge packages that are actually installed (avoid apt errors on a
	// never-installed optional pkg like headers/modules-extra).
	var installed []string
	for _, p := range candPkgs {
		if isPkgInstalled(p) {
			installed = append(installed, p)
		}
	}
	if len(installed) > 0 {
		args := append([]string{"purge", "-y", "--allow-change-held-packages"}, installed...)
		if err := aptGet(args...); err != nil {
			fmt.Fprintf(os.Stderr, "kernel-upgrade: WARNING purge un-promoted candidate %s: %v\n", candidateVersion, err)
		}
	}
	_ = os.RemoveAll(filepath.Join("/lib/modules", candidateVersion))
	if matches, err := filepath.Glob(filepath.Join("/boot", "*-"+candidateVersion)); err == nil {
		for _, match := range matches {
			_ = os.RemoveAll(match)
		}
	}
	return nil
}

// isPkgInstalled reports whether a dpkg package is in the "installed" state.
func isPkgInstalled(pkg string) bool {
	out, err := captureCmd("dpkg-query", "-W", "-f=${Status}", pkg)
	if err != nil {
		return false
	}
	return strings.Contains(out, "install ok installed")
}

func (s *realKernelSystem) Now() time.Time {
	return time.Now()
}

func grubDefaultFiles() []string {
	files := []string{"/etc/default/grub"}
	matches, err := filepath.Glob("/etc/default/grub.d/*.cfg")
	if err == nil {
		files = append(files, matches...)
	}
	return files
}

func captureCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	// Force the C locale so the parsed output (efibootmgr "BootCurrent:" /
	// "BootOrder:", uname, ip route, dpkg-query) is never localized/translated,
	// which would break the regex/field parses and trigger spurious reverts
	// (r1 AGY: locale-robust parsing). LC_ALL=C wins over LANG/LC_*.
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w (output: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

func aptGet(args ...string) error {
	cmd := exec.Command("apt-get", args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("apt-get %s: %w (output: %s)", strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return nil
}

func aptPackageAvailable(pkg string) bool {
	if out, err := captureCmd("apt-cache", "show", pkg); err == nil && strings.TrimSpace(out) != "" {
		return true
	}
	if out, err := captureCmd("dpkg-query", "-W", "-f=${binary:Package}\n", pkg); err == nil && strings.TrimSpace(out) != "" {
		return true
	}
	return false
}

func unholdLinuxPackages() {
	linuxPackages := currentLinuxPackages()
	if len(linuxPackages) == 0 {
		return
	}
	// Unhold failure is non-fatal: at worst the candidate install fails (apt
	// refuses to touch a held pkg), which is itself surfaced as an error.
	_ = runCmd("apt-mark", append([]string{"unhold"}, linuxPackages...)...)
}

func holdLinuxPackages() error {
	linuxPackages := currentLinuxPackages()
	if len(linuxPackages) == 0 {
		return fmt.Errorf("no linux-* packages found to hold")
	}
	return runCmd("apt-mark", append([]string{"hold"}, linuxPackages...)...)
}

// kernelPkgPrefixes are the ACTUAL kernel image/module/header package families
// the channel holds. `linux-*` is too broad (r1 Copilot): it would pin
// linux-base, linux-libc-dev, linux-firmware, linux-tools-*, etc. — unrelated
// packages whose long-term hold blocks security updates and diverges from the
// bake's intent (which holds only the kernel set). We hold exactly the kernel
// families + the metapackages that pull them.
var kernelPkgPrefixes = []string{
	"linux-image-", "linux-modules-", "linux-modules-extra-",
	"linux-headers-", "linux-generic", "linux-image-generic",
	"linux-headers-generic", "linux-image-virtual", "linux-virtual",
}

func isKernelPkg(pkg string) bool {
	for _, p := range kernelPkgPrefixes {
		if pkg == p || strings.HasPrefix(pkg, p) {
			return true
		}
	}
	return false
}

func currentLinuxPackages() []string {
	out, err := captureCmd("dpkg-query", "-W", "-f=${binary:Package}\n", "linux-*")
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var pkgs []string
	for _, line := range strings.Split(out, "\n") {
		pkg := strings.TrimSpace(line)
		// Only the kernel image/module/header families + metas — NOT the broad
		// linux-* set (excludes linux-base / linux-libc-dev / firmware / tools).
		if pkg == "" || !isKernelPkg(pkg) || seen[pkg] {
			continue
		}
		seen[pkg] = true
		pkgs = append(pkgs, pkg)
	}
	return pkgs
}

func writeWatchdogKeepalive(fd int) error {
	n, err := unix.Write(fd, []byte{'K'})
	if err != nil {
		return fmt.Errorf("write watchdog keepalive: %w", err)
	}
	if n != 1 {
		return fmt.Errorf("write watchdog keepalive: short write %d", n)
	}
	return nil
}
