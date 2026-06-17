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
	// ProbeFunc is wired by the caller when a real forward-health probe is
	// available. The default only checks whether the dataplane unit is active.
	ProbeFunc func(deadline time.Time) (bool, error)
}

var _ KernelSystem = (*realKernelSystem)(nil)

// NewKernelSystem returns the production KernelSystem implementation.
func NewKernelSystem() *realKernelSystem {
	return &realKernelSystem{}
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

// ArmWatchdog intentionally closes /dev/watchdog without the magic "V"
// disarm byte. The caller must keep petting the watchdog or the host reboots.
func (s *realKernelSystem) ArmWatchdog() error {
	if _, err := os.Stat("/dev/watchdog"); err != nil {
		return fmt.Errorf("/dev/watchdog unavailable: %w", err)
	}
	fd, err := unix.Open("/dev/watchdog", unix.O_WRONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open /dev/watchdog: %w", err)
	}
	defer unix.Close(fd)

	timeout := int32(60)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.WDIOC_SETTIMEOUT), uintptr(unsafe.Pointer(&timeout)))
	if errno != 0 {
		return writeWatchdogKeepalive(fd)
	}
	return writeWatchdogKeepalive(fd)
}

func (s *realKernelSystem) Reboot() error {
	return exec.Command("systemctl", "reboot").Run()
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

func (s *realKernelSystem) ForwardBeacon(deadline time.Duration) (bool, error) {
	if s.ProbeFunc != nil {
		return s.ProbeFunc(time.Now().Add(deadline))
	}
	// The real forward probe is wired by the caller. Without it, unit
	// activity is the best local proxy available to this package.
	if runCmd("systemctl", "is-active", "xpfd-userspace-dp") == nil {
		return true, nil
	}
	if runCmd("systemctl", "is-active", "xpfd") == nil {
		return true, nil
	}
	return false, nil
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
	_ = aptGet("purge", "-y",
		"linux-image-"+candidateVersion,
		"linux-modules-"+candidateVersion,
		"linux-headers-"+candidateVersion,
	)
	_ = os.RemoveAll(filepath.Join("/lib/modules", candidateVersion))
	if matches, err := filepath.Glob(filepath.Join("/boot", "*-"+candidateVersion)); err == nil {
		for _, match := range matches {
			_ = os.RemoveAll(match)
		}
	}
	return nil
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

func currentLinuxPackages() []string {
	out, err := captureCmd("dpkg-query", "-W", "-f=${binary:Package}\n", "linux-*")
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var pkgs []string
	for _, line := range strings.Split(out, "\n") {
		pkg := strings.TrimSpace(line)
		if pkg == "" || !strings.HasPrefix(pkg, "linux-") || seen[pkg] {
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
