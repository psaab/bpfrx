#!/usr/bin/env python3
"""xpf-deploy — set up xpf appliance VMs (incus or libvirt), all in Python.

Subcommands:
  deploy <appliance.yaml> [...]   launch from YAML definition(s); a cluster
                                  is two files. (Default if args are *.yaml.)
  launch --name … --nic …         imperative launch without a YAML file.
  inventory                       list host NICs, SR-IOV VFs, bridges → the
                                  values you drop into a definition.
  fetch --version V [--image-url] download a signed appliance image from
                                  XPF_IMAGE_BASE_URL, VERIFY the exact bytes
                                  against the signed manifest (#1924), then
                                  import it to a local incus alias. Verify
                                  happens here, not at deploy/launch.
  kernel-roll --node A --node B   LANE-1 HA kernel roll (#1930 INC-2): drive a
              --version V          verify-gated kernel bump across the HA pair
                                  ONE NODE AT A TIME (drain -> arm+reboot into
                                  the candidate -> poll until promoted -> rejoin,
                                  then the peer). Survives the per-node reboots;
                                  holds a leased lock; STOPS (leaving the peer
                                  primary) if a node reverts. The per-node
                                  arm/verify/promote is `xpfd upgrade kernel`.

Interface naming is POSITIONAL (matches pkg/daemon/linksetup.go assignName):

  standalone:      pos1 -> fxp0   pos2 -> ge-0/0/0   posN -> ge-0/0/(N-2)
  cluster node 0:  pos1 -> fxp0   pos2 -> em0        posN -> ge-0/0/(N-3)
  cluster node 1:  pos1 -> fxp0   pos2 -> em0        posN -> ge-7/0/(N-3)

A NIC's backing (virtio bridge / SR-IOV VF / PCI passthrough) is declared
explicitly per interface — `backing:` in YAML, or the `<backing>:<source>`
spec for --nic. The tool translates each to the right incus device / libvirt
virt-install argument. The day-0 config drive is built and check-config
validated in-process (no shell helpers).

Global options: --dry-run  --hypervisor incus|libvirt  --no-start  --image X

Examples:
  xpf-deploy.py deploy examples/deploy/standalone-sriov.yaml
  xpf-deploy.py deploy --hypervisor libvirt examples/deploy/standalone-passthrough.yaml
  xpf-deploy.py launch --name fw1 --config standalone.conf \\
      --nic bridge:br-mgmt --nic sriov:enp8s0 --nic pci:0000:09:00.0
  xpf-deploy.py inventory
"""

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

try:
    import yaml
except ImportError:
    yaml = None

VALID_BACKINGS = {"net", "bridge", "macvlan", "sriov", "physical", "pci"}
SYS_NET = "/sys/class/net"


def die(msg):
    sys.exit(f"ERROR: {msg}")


# ── naming contract ───────────────────────────────────────────────────
def expected_name(idx, mode, node_id):
    """vSRX name the guest assigns to the NIC at position idx (0-based);
    mirrors assignName() in pkg/daemon/linksetup.go."""
    if idx == 0:
        return "fxp0"
    if mode == "cluster":
        if idx == 1:
            return "em0"
        fpc = 7 if node_id == 1 else 0
        return f"ge-{fpc}/0/{idx - 2}"
    return f"ge-0/0/{idx - 1}"


def norm_role(role):
    r = role.strip()
    m = re.fullmatch(r"ge-(\d+)[-/]0[-/](\d+)", r)
    return f"ge-{m.group(1)}/0/{m.group(2)}" if m else r


# ── host introspection ────────────────────────────────────────────────
def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ""


def is_physical_nic(dev):
    if dev == "lo" or not os.path.isdir(os.path.join(SYS_NET, dev, "device")):
        return False
    return not re.match(r"(veth|tap|br-|virbr|docker|incusbr)", dev)


def driver_of(dev):
    link = os.path.join(SYS_NET, dev, "device", "driver")
    return os.path.basename(os.path.realpath(link)) if os.path.exists(link) else "?"


def pci_of(dev):
    link = os.path.join(SYS_NET, dev, "device")
    return os.path.basename(os.path.realpath(link)) if os.path.exists(link) else "?"


def native_xdp_hint(driver):
    if driver in ("mlx5_core", "i40e", "ice", "ixgbe", "bnxt_en", "nfp"):
        return "native"
    if driver in ("iavf", "ixgbevf", "virtio_net"):
        return "no (generic)"
    return "unknown"


def vf_parent(addr):
    """(PF_netdev, vf_index) for an SR-IOV VF PCI address, or None."""
    if not os.path.isdir(SYS_NET):
        return None
    for pf in os.listdir(SYS_NET):
        devdir = os.path.join(SYS_NET, pf, "device")
        if not os.path.isdir(devdir):
            continue
        for entry in os.listdir(devdir):
            if entry.startswith("virtfn") and \
               os.path.basename(os.path.realpath(os.path.join(devdir, entry))) == addr:
                return pf, entry[len("virtfn"):]
    return None


def cmd_inventory(_args):
    print(f"=== Physical NICs ===")
    print(f"{'NETDEV':<14} {'DRIVER':<10} {'PCI':<14} {'MAC':<18} {'LINK':<6} NATIVE-XDP")
    for dev in sorted(os.listdir(SYS_NET)):
        if not is_physical_nic(dev):
            continue
        drv = driver_of(dev)
        print(f"{dev:<14} {drv:<10} {pci_of(dev):<14} "
              f"{_read(os.path.join(SYS_NET, dev, 'address')):<18} "
              f"{_read(os.path.join(SYS_NET, dev, 'operstate')):<6} {native_xdp_hint(drv)}")
        devdir = os.path.join(SYS_NET, dev, "device")
        total = _read(os.path.join(devdir, "sriov_totalvfs"))
        if total and total != "0":
            num = _read(os.path.join(devdir, "sriov_numvfs")) or "0"
            print(f"    SR-IOV: {num}/{total} VFs. Create N:  "
                  f"echo N | sudo tee {devdir}/sriov_numvfs")
            for entry in sorted(os.listdir(devdir)):
                if entry.startswith("virtfn"):
                    vfpci = os.path.basename(os.path.realpath(os.path.join(devdir, entry)))
                    print(f"      vf{entry[len('virtfn'):]:<3} pci:{vfpci}   "
                          f"(sriov:{dev}  |  pci:{vfpci},mac=02:..)")
    print("\n=== Host bridges (bridge:<name>) ===")
    found = False
    for dev in sorted(os.listdir(SYS_NET)):
        if os.path.isdir(os.path.join(SYS_NET, dev, "bridge")):
            print(f"  bridge:{dev}")
            found = True
    if not found:
        print("  (none — create: sudo ip link add br-lan type bridge; ip link set br-lan up)")
    return 0


# ── appliance model ───────────────────────────────────────────────────
def validate_appliance(ap, where):
    if not ap.get("name"):
        die(f"{where}: name is required")
    if ap["mode"] not in ("standalone", "cluster"):
        die(f"{where}: mode must be standalone|cluster")
    if ap["mode"] == "cluster" and ap.get("node_id") not in (0, 1):
        die(f"{where}: cluster needs node_id 0|1")
    if not ap["interfaces"]:
        die(f"{where}: at least one interface (position 1 = fxp0)")
    for i, ic in enumerate(ap["interfaces"]):
        if ic.get("backing") not in VALID_BACKINGS:
            die(f"{where}: interface {i + 1} backing must be one of {sorted(VALID_BACKINGS)}")
        if not ic.get("source"):
            die(f"{where}: interface {i + 1} needs a source")
        want = expected_name(i, ap["mode"], ap.get("node_id"))
        if ic.get("role") and norm_role(ic["role"]) != want:
            die(f"{where}: interface {i + 1} declares role '{ic['role']}' but position {i + 1} "
                f"is '{want}' — reorder or fix; position is the contract.")
        ic["_name"] = want


def load_yaml_appliance(path):
    if yaml is None:
        die("PyYAML required for YAML deploy (apt install python3-yaml). "
            "Use the 'launch' subcommand for a no-YAML, no-dependency path.")
    with open(path) as f:
        doc = yaml.safe_load(f)
    if not isinstance(doc, dict):
        die(f"{path}: top level must be a mapping")
    a = doc.get("appliance") or {}
    ap = {
        "name": a.get("name"), "mode": a.get("mode", "standalone"),
        "node_id": a.get("node_id"), "image": a.get("image", "xpf-appliance"),
        "cpu": a.get("cpu", 4), "memory": a.get("memory", "4GiB"),
        "config": a.get("config"), "interfaces": doc.get("interfaces") or [],
        "pool": a.get("pool", "default"),
        "base_dir": os.path.dirname(os.path.abspath(path)),
    }
    validate_appliance(ap, path)
    return ap


# ── day-0 config drive (pure Python; xorriso/genisoimage for the ISO) ──
def find_xpfd():
    for c in (os.environ.get("XPFD"), os.path.join(os.getcwd(), "xpfd"),
              shutil.which("xpfd")):
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def build_config_drive(ap, runner):
    cfg = ap.get("config")
    if not cfg:
        return None
    cfg_path = cfg if os.path.isabs(cfg) else os.path.join(ap["base_dir"], cfg)
    iso = os.path.join(os.getcwd(), f"{ap['name']}-day0.iso")
    if runner.dry:
        print(f"==> (dry-run) would build day-0 drive {iso} from {cfg_path} "
              f"(label xpf-config, check-config validated)")
        return iso
    if not os.path.isfile(cfg_path):
        die(f"config not found: {cfg_path}")
    xpfd = find_xpfd()
    if xpfd:
        nodearg = ["-node-id", str(ap["node_id"])] if ap["mode"] == "cluster" else []
        r = subprocess.run([xpfd, "check-config"] + nodearg + [cfg_path],
                           capture_output=True, text=True)
        if r.returncode != 0:
            die(f"day-0 config REJECTED by check-config:\n{r.stdout}{r.stderr}")
        print(f"==> day-0 config validated ({os.path.basename(cfg_path)})")
    else:
        print("WARNING: no xpfd binary found — skipping build-host validation "
              "(the appliance still validates at first boot).")
    mkiso = next((t for t in ("xorriso", "genisoimage", "mkisofs") if shutil.which(t)), None)
    if not mkiso:
        die("need xorriso/genisoimage/mkisofs to build the config drive (apt install xorriso)")
    stage = tempfile.mkdtemp(prefix="xpf-day0-")
    try:
        shutil.copyfile(cfg_path, os.path.join(stage, "xpf.conf"))
        os.chmod(os.path.join(stage, "xpf.conf"), 0o644)
        if ap["mode"] == "cluster":
            with open(os.path.join(stage, "node-id"), "w") as f:
                f.write(f"{ap['node_id']}\n")
        if mkiso == "xorriso":
            argv = ["xorriso", "-as", "mkisofs", "-quiet", "-V", "xpf-config",
                    "-J", "-r", "-o", iso, stage]
        else:
            argv = [mkiso, "-quiet", "-V", "xpf-config", "-J", "-r", "-o", iso, stage]
        subprocess.run(argv, check=True, capture_output=True, text=True)
        print(f"==> built day-0 drive {iso} (label xpf-config)")
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return iso


# ── memory / pci helpers ──────────────────────────────────────────────
def memory_mb(val):
    m = re.fullmatch(r"(\d+)\s*([GMgm]i?[Bb]?)?", str(val).strip())
    if not m:
        die(f"unparseable memory '{val}'")
    return int(m.group(1)) * 1024 if (m.group(2) or "M").upper().startswith("G") else int(m.group(1))


def pci_parts(addr):
    m = re.fullmatch(r"([0-9a-fA-F]{4}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])", addr)
    if not m:
        die(f"pci address '{addr}' is not DDDD:BB:DD.F")
    return {"domain": "0x" + m.group(1), "bus": "0x" + m.group(2),
            "slot": "0x" + m.group(3), "function": "0x" + m.group(4)}


class Runner:
    def __init__(self, dry):
        self.dry = dry

    def run(self, argv):
        if self.dry:
            print(" ".join(shlex.quote(a) for a in argv))
            return ""
        return subprocess.run(argv, check=True, capture_output=True, text=True).stdout


# ── deploy backends ───────────────────────────────────────────────────
def print_map(ap):
    tag = ap["mode"] + (f" node {ap['node_id']}" if ap["mode"] == "cluster" else "")
    print(f"==> {ap['name']}: {tag}, {len(ap['interfaces'])} NICs")
    for i, ic in enumerate(ap["interfaces"]):
        print(f"      pos {i + 1}: {ic['_name']:<10} <- {ic['backing']}:{ic['source']}")


def deploy_incus(ap, runner, start):
    name = ap["name"]
    print_map(ap)
    iso = build_config_drive(ap, runner)
    # --no-profiles: the default profile usually carries an `eth0` NIC,
    # which would be an extra virtio device the guest names positionally
    # alongside the declared dev00.. — a phantom interface that pollutes
    # the NIC->name map. Suppress all profile devices and provide the root
    # disk explicitly from the storage pool (default "default", override
    # with `pool:` in YAML) so the device set is EXACTLY the declared NICs.
    pool = ap.get("pool", "default")
    # incus -d sets ONE key=value per flag (<device>,<key>=<value>), so the
    # root disk needs three -d flags, not one comma-joined value.
    runner.run(["incus", "init", ap["image"], name, "--vm", "--no-profiles",
                "-c", f"limits.cpu={ap['cpu']}", "-c", f"limits.memory={ap['memory']}",
                "-d", "root,type=disk", "-d", f"root,pool={pool}", "-d", "root,path=/"])
    pins = []
    for i, ic in enumerate(ap["interfaces"]):
        dev = f"dev{i:02d}"
        b, src, mac = ic["backing"], str(ic["source"]), ic.get("mac")
        if b == "net":
            args = ["nic", f"network={src}"]
        elif b == "bridge":
            args = ["nic", "nictype=bridged", f"parent={src}"]
        elif b == "macvlan":
            args = ["nic", "nictype=macvlan", f"parent={src}"]
        elif b == "sriov":
            args = ["nic", "nictype=sriov", f"parent={src}"]
        elif b == "physical":
            args = ["nic", "nictype=physical", f"parent={src}"]
        elif b == "pci":
            args = ["pci", f"address={src}"]
        if mac and b in ("net", "bridge", "macvlan", "sriov"):
            args.append(f"hwaddr={mac}")
        if mac and b == "pci":
            par = None if runner.dry else vf_parent(src)
            if par:
                pins.append(["sudo", "ip", "link", "set", "dev", par[0], "vf", par[1], "mac", mac])
            elif runner.dry:
                print(f"      (dry-run) would pin VF MAC for pci:{src}")
            else:
                die(f"pci:{src} with mac= is not an SR-IOV VF here (drop mac= for whole-PF)")
        runner.run(["incus", "config", "device", "add", name, dev] + args)
    if iso:
        runner.run(["incus", "config", "device", "add", name, "day0", "disk", f"source={iso}"])
    for pin in pins:
        runner.run(["sudo", "ip", "link", "set", "dev", pin[5], "up"])
        print(f"==> pinning VF MAC: {' '.join(pin)}")
        runner.run(pin)
    if start:
        runner.run(["incus", "start", name])
        print(f"\n{name} launched. Verify the NIC->name map:\n"
              f"  incus exec {name} -- cli -c \"show interfaces terse\"")
    else:
        print(f"{name} created (not started): incus start {name}")


def deploy_libvirt(ap, runner, start):
    name = ap["name"]
    print_map(ap)
    iso = build_config_drive(ap, runner)
    argv = ["virt-install", "--name", name, "--memory", str(memory_mb(ap["memory"])),
            "--vcpus", str(ap["cpu"]), "--import",
            "--disk", f"path=/var/lib/libvirt/images/{ap['image']}.qcow2",
            "--osinfo", "ubuntu26.04", "--noautoconsole"]
    if iso:
        argv += ["--disk", f"path={iso},device=cdrom"]
    notes = []
    for ic in ap["interfaces"]:
        b, src, mac = ic["backing"], str(ic["source"]), ic.get("mac")
        if b in ("net", "bridge"):
            net = f"{'network' if b == 'net' else 'bridge'}={src},model=virtio"
            argv += ["--network", net + (f",mac.address={mac}" if mac else "")]
        elif b == "macvlan":
            net = f"type=direct,source={src},source_mode=bridge,model=virtio"
            argv += ["--network", net + (f",mac.address={mac}" if mac else "")]
        elif b == "physical":
            argv += ["--hostdev", src]
        elif b == "pci":
            if mac:
                p = pci_parts(src)
                argv += ["--network",
                         "type=hostdev,source.address.type=pci,"
                         f"source.address.domain={p['domain']},source.address.bus={p['bus']},"
                         f"source.address.slot={p['slot']},source.address.function={p['function']},"
                         f"mac.address={mac}"]
            else:
                argv += ["--hostdev", src]
        elif b == "sriov":
            pool = f"{src}-vfpool"
            argv += ["--network", f"network={pool}" + (f",mac.address={mac}" if mac else "")]
            notes.append(f"sriov:{src} -> libvirt VF pool '{pool}'. Define once:\n"
                         f"      <network><name>{pool}</name>"
                         f"<forward mode='hostdev' managed='yes'><pf dev='{src}'/></forward></network>\n"
                         f"      virsh net-define <f> && virsh net-start {pool} && virsh net-autostart {pool}")
    print("# virt-install — NIC order = guest PCI-slot order = positional names.")
    for n in notes:
        print(f"# NOTE: {n}")
    runner.run(argv)
    if start:
        print(f"\n{name}: verify with `virsh console {name}` then "
              f"`cli -c \"show interfaces terse\"`.")


def deploy(ap, args):
    runner = Runner(args.dry_run)
    if args.image:
        ap["image"] = args.image
    (deploy_incus if args.hypervisor == "incus" else deploy_libvirt)(
        ap, runner, not args.no_start)


# ── subcommands ───────────────────────────────────────────────────────
def cmd_deploy(args):
    if not args.yamls:
        die("deploy needs at least one YAML file")
    for path in args.yamls:
        deploy(load_yaml_appliance(path), args)
    return 0


def cmd_launch(args):
    ifaces = []
    for spec in args.nic:
        kind, _, rest = spec.partition(":")
        if not rest:
            kind, rest = "net", spec
        src, _, tail = rest.partition(",")
        mac = None
        m = re.search(r"mac=([^,]+)", tail)
        if m:
            mac = m.group(1)
        ic = {"backing": kind, "source": src}
        if mac:
            ic["mac"] = mac
        ifaces.append(ic)
    ap = {"name": args.name, "mode": args.mode, "node_id": args.node_id,
          "image": args.image or "xpf-appliance", "cpu": args.cpu,
          "memory": args.mem, "config": args.config, "interfaces": ifaces,
          "base_dir": os.getcwd()}
    validate_appliance(ap, "launch")
    deploy(ap, args)
    return 0


def cmd_fetch(args):
    """Download an appliance image from XPF_IMAGE_BASE_URL, VERIFY the exact
    downloaded bytes against the signed per-version manifest (#1924 §5.2),
    then import it to a local incus alias. Verification happens HERE (at
    fetch/import), not at deploy/launch — the alias-launch path consumes a
    previously-verified alias. This is the only deploy-side place that
    touches raw image bytes, so it is where the signature is bound."""
    HERE_D = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, os.path.join(os.path.dirname(HERE_D), "dist"))
    import sign  # noqa: E402

    base = args.image_url or os.environ.get("XPF_IMAGE_BASE_URL")
    if not base:
        die("fetch needs --image-url or XPF_IMAGE_BASE_URL (the image host).")
    base = base.rstrip("/")
    ver = args.version
    out = os.path.abspath(args.out or os.getcwd())
    os.makedirs(out, exist_ok=True)

    # Best-effort monotonic anti-rollback watermark (#1924 §5.6 / NIT-3):
    # remember the highest version fetched per channel so a stale mirror
    # serving an OLDER (still-signed) version is detected. Stateless CLI, so
    # this is best-effort: a fresh workstation has no watermark and trusts the
    # artifact's own signature. Override the channel with --channel; bypass the
    # guard with --allow-rollback (e.g. a deliberate downgrade).
    state_home = os.environ.get("XDG_STATE_HOME") or os.path.expanduser(
        "~/.local/state")
    wm_path = os.path.join(state_home, "xpf", "image-watermark.json")

    def _ver_key(v):
        # Compare on the dotted-numeric RELEASE, then a pre-release rank so a
        # pre-release sorts BEFORE its base release (AGY: 1.2.3-rc1 < 1.2.3, so
        # upgrading rc -> final is NOT a rollback). git-describe tails like
        # "-N-gHASH-dirty" are post-release commits ahead of the tag → rank
        # them AFTER the base. Split on the FIRST '-': left = release, right =
        # suffix.
        s = str(v)
        rel, _, suffix = s.partition("-")
        rel_key = []
        for tok in rel.split("."):
            rel_key.append((0, int(tok)) if tok.isdigit() else (1, tok))
        if not suffix:
            pre_rank = (1,)           # base release: after any pre-release
        elif suffix[:1].isdigit():
            pre_rank = (2, suffix)    # git-describe "N-gHASH": post-release
        else:
            pre_rank = (0, suffix)    # rc/alpha/beta/...: before the base
        return (rel_key, pre_rank)

    def read_watermark():
        try:
            with open(wm_path) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    if not args.dry_run and not args.allow_rollback:
        wm = read_watermark()
        prev = wm.get(args.channel)
        if prev and _ver_key(ver) < _ver_key(prev):
            die(f"requested version {ver} is OLDER than the last fetched "
                f"{prev} on channel '{args.channel}' (possible stale mirror / "
                "rollback). Pass --allow-rollback for a deliberate downgrade.")

    names = {
        "qcow2": f"xpf-{ver}.qcow2",
        "metadata": f"xpf-{ver}.incus-metadata.tar.gz",
        "manifest": f"xpf-{ver}.SHA256SUMS",
        "sig": f"xpf-{ver}.SHA256SUMS.minisig",
    }

    def fetch_one(name):
        dst = os.path.join(out, name)
        url = f"{base}/{name}"
        if args.dry_run:
            print(f"  (dry-run) curl -fsSL {url} -> {dst}")
            return dst
        print(f"==> fetching {url}")
        r = subprocess.run(["curl", "-fsSL", "-o", dst + ".tmp", url])
        if r.returncode != 0:
            die(f"download failed: {url}")
        os.replace(dst + ".tmp", dst)
        return dst

    # Need at least the manifest + sig + the artifact(s) the operator wants.
    want = ["qcow2"] if args.qcow2_only else ["qcow2", "metadata"]
    fetch_one(names["manifest"])
    fetch_one(names["sig"])
    for w in want:
        fetch_one(names[w])

    if args.dry_run:
        print("  (dry-run) verify each fetched file against the signed manifest,"
              " then incus image import")
        return 0

    manifest = os.path.join(out, names["manifest"])
    sig = os.path.join(out, names["sig"])
    for w in want:
        path = os.path.join(out, names[w])
        try:
            sign.verify_image_artifact(path, manifest, sig)
            print(f"==> signature OK: {names[w]}")
        except sign.SignError as e:
            die(f"VERIFICATION FAILED for {names[w]}: {e}")

    # Advance the monotonic watermark only AFTER a successful verify (so a
    # failed/tampered fetch never moves it). Best-effort: a write failure is
    # non-fatal (the signature is the real gate).
    if not args.allow_rollback:
        try:
            wm = read_watermark()
            prev = wm.get(args.channel)
            if not prev or _ver_key(ver) >= _ver_key(prev):
                wm[args.channel] = ver
                os.makedirs(os.path.dirname(wm_path), exist_ok=True)
                tmpw = wm_path + ".tmp"
                with open(tmpw, "w") as f:
                    json.dump(wm, f, indent=2, sort_keys=True)
                os.replace(tmpw, wm_path)
        except OSError:
            pass  # best-effort; never block a verified fetch on watermark I/O

    if args.no_import or args.qcow2_only:
        print(f"==> verified into {out} (not imported — use the qcow2 with "
              "virt-install --import, or re-run without --qcow2-only/--no-import "
              "for an incus image import).")
        return 0

    alias = args.alias or "xpf-appliance"
    subprocess.run(["incus", "image", "delete", alias],
                   capture_output=True, text=True)
    print(f"==> importing verified image as incus alias '{alias}'")
    r = subprocess.run(["incus", "image", "import",
                        os.path.join(out, names["metadata"]),
                        os.path.join(out, names["qcow2"]), "--alias", alias])
    if r.returncode != 0:
        die("incus image import failed")
    print(f"==> done. Deploy with: xpf-deploy.py deploy <appliance.yaml> "
          f"(image: {alias})")
    return 0


# ── LANE-1 HA kernel-rolling orchestration (#1930 INC-2) ──────────────────
#
# Drive a verify-gated kernel bump across an HA pair ONE NODE AT A TIME so the
# cluster keeps forwarding. Per the converged plan (§3.1-HA): the per-node
# arm/verify/promote/revert is owned by the in-guest `xpfd upgrade kernel`
# (INC-1, merged); this EXTERNAL driver survives the per-node reboots (an
# in-process driver would die at the reboot it triggers) and owns the cross-node
# sequencing + the "never both down" gate.
#
# Sequence per node N (peer P stays primary throughout):
#   1. hold a LEASE naming N (TTL) on BOTH nodes — suppresses N's local
#      self-recovery (INC-2 Go side) so it won't fight the roll, and is the
#      cluster-wide lock (a crashed driver's lease expires, freeing future rolls).
#   2. drain N -> P (xpfd upgrade kernel relies on the node being secondary; we
#      demote via the cluster CLI) and confirm P holds the RGs.
#   3. `xpfd upgrade kernel arm <ver>` on N -> N installs+arms+reboots into the
#      candidate; the in-guest promotion oneshot verifies+promotes or reverts.
#   4. poll N until it is back AND `uname -r == <ver>` AND `xpfd upgrade kernel
#      status` reports `promoted=<ver>` (a REVERTED node boots the OLD kernel and
#      reports promoted!=<ver> -> we STOP and leave P primary, never touch P).
#   5. rejoin N (clear failover) + confirm sync re-established.
#   6. release N's lease, then repeat for P.
#
# If a true cross-node reboot-roll cannot be driven (e.g. --dry-run, or a node
# is unreachable), the driver aborts BEFORE draining the second node, so the
# cluster never ends up with both nodes down.

def _node_exec(runner, backend, node, argv, check=True):
    """Run argv inside `node` via the chosen backend (incus|ssh)."""
    if backend == "ssh":
        full = ["ssh", node, "--"] + argv
    else:
        full = ["incus", "exec", node, "--"] + argv
    if runner.dry:
        print("   " + " ".join(shlex.quote(a) for a in full))
        return ""
    r = subprocess.run(full, capture_output=True, text=True)
    if check and r.returncode != 0:
        die(f"{node}: command failed ({' '.join(argv)}): "
            f"{r.stdout.strip()} {r.stderr.strip()}")
    return r.stdout


def _acquire_lease(runner, backend, node, target_node_id, holder, ttl_secs):
    """ATOMICALLY acquire the lease on `node`, or die if another holder has an
    unexpired one. The whole read-expired-decide-write is run inside an
    OS-level flock on a dedicated lock file, so the expired-lease RECLAIM is
    serialized too — closing the r3-Codex TOCTOU where a stale-read `rm` could
    delete a racing driver's just-created live lease. (flock is util-linux,
    present on the Debian/Ubuntu appliance base.) expires_at is rendered in the
    NODE's clock (clock-skew safe)."""
    h = holder.replace('"', "")
    # Inner critical section (runs while holding the flock): reclaim ONLY an
    # expired lease, then create the new one. Because the whole section is
    # serialized by flock, no other driver can interleave between the reclaim
    # and the create.
    crit = (
        "f=/var/lib/xpf/kernel-roll.lease; "
        'if [ -f "$f" ]; then '
        'exp=$(sed -n \'s/.*"expires_at": *"\\([^"]*\\)".*/\\1/p\' "$f"); '
        'now=$(date -u +%%s); ee=$(date -u -d "$exp" +%%s 2>/dev/null || echo 0); '
        # live lease held by someone else -> do NOT touch it; fail to acquire.
        'if [ "$now" -lt "$ee" ]; then exit 1; fi; '
        'fi; '
        "exp=$(date -u -d \"+%d seconds\" +%%Y-%%m-%%dT%%H:%%M:%%SZ); "
        "umask 022; "
        # Write to a temp file then atomic-rename, so a reader (the self-recovery
        # loop, which does NOT take the flock) never observes a partial/truncated
        # lease (r2 AGY non-atomic-write). The flock still serializes writers.
        "printf '{\"node_id\": %d, \"holder\": \"%s\", \"expires_at\": \"%%s\"}' "
        "\"$exp\" > \"$f.tmp\" && mv -f \"$f.tmp\" \"$f\""
    ) % (ttl_secs, target_node_id, h)
    # flock -w 30 serializes the critical section across concurrent drivers on
    # this node; -E 9 distinguishes a lock-acquire timeout (exit 9) from the
    # critical section's own exit-1 (live lease held).
    script = (
        "mkdir -p /var/lib/xpf; "
        "flock -w 30 -E 9 /var/lib/xpf/kernel-roll.lock "
        "sh -c " + shlex.quote(crit) + " && echo ACQUIRED"
    )
    out = _node_exec(runner, backend, node, ["sh", "-c", script], check=False)
    # Return whether WE won the lease (the caller releases-what-it-got + aborts
    # on a partial acquisition, rather than die()ing here with a stranded lease).
    return runner.dry or "ACQUIRED" in out


def _clear_lease(runner, backend, node, holder):
    # Release ONLY if WE still hold the lease (holder matches), under the same
    # flock as acquire (r4 Codex: an unconditional rm could delete a SUCCESSOR's
    # live lease if ours had expired and someone else re-acquired). No unlocked
    # fallback — a failure to take the lock means we do NOT delete (safer to
    # leave a lease that will expire than to delete a live successor's).
    h = holder.replace('"', "")
    crit = (
        'f=/var/lib/xpf/kernel-roll.lease; [ -f "$f" ] || exit 0; '
        'cur=$(sed -n \'s/.*"holder": *"\\([^"]*\\)".*/\\1/p\' "$f"); '
        '[ "$cur" = "%s" ] && rm -f "$f"; exit 0'
    ) % h
    _node_exec(runner, backend, node, ["sh", "-c",
               "flock -w 30 /var/lib/xpf/kernel-roll.lock sh -c " + shlex.quote(crit)],
               check=False)


def _kernel_status(runner, backend, node):
    """Return dict parsed from `xpfd upgrade kernel status` (promoted=, armed=)."""
    out = _node_exec(runner, backend, node,
                     ["xpfd", "upgrade", "kernel", "status"], check=False)
    st = {}
    for line in out.splitlines():
        for tok in line.split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                st[k] = v
    return st


def _running_kernel(runner, backend, node):
    return _node_exec(runner, backend, node, ["uname", "-r"], check=False).strip()


def cmd_kernel_roll(args):
    import time as _time
    runner = Runner(args.dry_run)
    backend = args.backend
    nodes = args.nodes               # ordered [first-to-roll, second]
    node_ids = {nodes[0]: args.node0_id, nodes[1]: args.node1_id}
    version = args.version
    # Sanitize the holder to a safe token set (r2 AGY): the nodename is
    # interpolated into a shell printf AND a Python %-format, so strip anything
    # that isn't [A-Za-z0-9._-] (drops quotes, %, spaces, shell metachars).
    import re as _re
    _raw_holder = f"{os.uname().nodename}:pid{os.getpid()}"
    holder = _re.sub(r"[^A-Za-z0-9._:-]", "_", _raw_holder)
    lease_ttl = args.lease_ttl
    poll_deadline = args.boot_deadline

    if len(nodes) != 2:
        die("kernel-roll needs exactly two --node arguments (the HA pair)")

    print(f"==> LANE-1 HA kernel roll to {version}: {nodes[0]} then {nodes[1]} "
          f"(one node at a time; peer keeps forwarding)")

    def roll_one(node, peer):
        nid = node_ids[node]
        print(f"\n--- rolling {node} (node-id {nid}); {peer} stays primary ---")
        # 1. ATOMICALLY acquire the lease on BOTH nodes (cross-driver mutex,
        #    flock-serialized + holder-guarded). Acquire in a CANONICAL order
        #    (sorted node name), NOT the roll order, so two drivers rolling in
        #    OPPOSITE order can't each grab one node and deadlock (r5 Codex):
        #    both contend for the same node's lease first. If we get the first
        #    but not the second, RELEASE the first (no stranded lease until TTL)
        #    and abort. Acquiring on `node` also suppresses its self-recovery.
        ordered = sorted([node, peer])
        got = []
        for n in ordered:
            if _acquire_lease(runner, backend, n, nid, holder, lease_ttl):
                got.append(n)
            else:
                for g in got:
                    _clear_lease(runner, backend, g, holder)
                die(f"{n}: could not acquire kernel-roll lease (a live lease is "
                    f"held by another orchestrator, or the lock timed out) — "
                    f"released {got or 'nothing'} and aborting.")
        try:
            # 2. DRAIN node -> peer via the non-interactive in-guest verb, which
            #    CONFIRMS the strong drain predicate (peer holds RGs, sync clean)
            #    before returning — so we never arm an undrained primary (r1
            #    Codex Critical). It also pre-checks peer-takeover-ready + HA
            #    protocol compat and refuses otherwise.
            print(f"   draining {node} -> {peer} (confirmed)...")
            _node_exec(runner, backend, node,
                       ["xpfd", "upgrade", "kernel", "drain"])  # check=True: abort on fail
            # 3. clear any STALE promotion marker so a prior roll to the SAME
            #    version can't false-satisfy this roll's poll (r1 Codex High);
            #    `arm` clears it in-guest too, belt-and-braces here for clarity.
            # 4. arm+install+reboot into the candidate (in-guest verb). `arm`
            #    reboots on success and the exec transport drops — expected.
            print(f"   arming candidate {version} on {node} (will reboot)...")
            _node_exec(runner, backend, node,
                       ["xpfd", "upgrade", "kernel", "arm", version], check=False)
            if runner.dry:
                print(f"   (dry-run) would poll {node} for promoted={version}, "
                      f"then `xpfd upgrade kernel rejoin`")
                return True
            # 5. poll until back + promoted==version (or STOP on revert/timeout)
            deadline = _time.time() + poll_deadline
            promoted = False
            while _time.time() < deadline:
                _time.sleep(10)
                st = _kernel_status(runner, backend, node)
                running = _running_kernel(runner, backend, node)
                if not running:
                    continue  # node still rebooting / unreachable
                if st.get("promoted") == version and running == version:
                    promoted = True
                    break
                if running and running != version and st.get("armed") in (None, "none"):
                    # node booted a NON-candidate kernel and nothing is armed ->
                    # it REVERTED. STOP: leave peer primary, do NOT roll peer.
                    die(f"{node} REVERTED (running {running}, not {version}); "
                        f"stopping the roll — {peer} stays primary, {node} is on "
                        f"its known-good kernel. Investigate before retrying.")
            if not promoted:
                die(f"{node} did not promote {version} within {poll_deadline}s "
                    f"(running={running}); stopping — {peer} stays primary.")
            print(f"   {node} promoted {version}")
            # 6. REJOIN + CONFIRM sync re-established BEFORE we touch the peer
            #    (the "never both down" gate — r1 Codex Critical). `rejoin`
            #    clears manual failover on ALL RGs and confirms peer-alive +
            #    sync; a failure here STOPS the roll (the peer stays primary).
            print(f"   rejoining {node} (confirming sync)...")
            _node_exec(runner, backend, node,
                       ["xpfd", "upgrade", "kernel", "rejoin"])  # check=True: abort on fail
            return True
        finally:
            # 7. release this node's lease on both nodes (best-effort)
            _clear_lease(runner, backend, node, holder)
            _clear_lease(runner, backend, peer, holder)

    roll_one(nodes[0], nodes[1])
    print(f"\n==> {nodes[0]} done; rolling the second node")
    roll_one(nodes[1], nodes[0])
    print(f"\n==> LANE-1 HA kernel roll to {version} COMPLETE on both nodes")
    return 0


def main():
    argv = sys.argv[1:]
    if "-h" in argv or "--help" in argv or not argv:
        print(__doc__)
        return 0 if ("-h" in argv or "--help" in argv) else 2

    # Peel the global options from ANYWHERE on the command line with a
    # globals-only pre-parser. parse_known_args picks up --dry-run /
    # --hypervisor / --no-start / --image whether they appear before or
    # after the subcommand, and (critically) it CONSUMES their values, so
    # an option value can never be mistaken for the subcommand token.
    g = argparse.ArgumentParser(add_help=False)
    g.add_argument("--dry-run", action="store_true")
    g.add_argument("--hypervisor", default="incus", choices=["incus", "libvirt"])
    g.add_argument("--no-start", action="store_true")
    g.add_argument("--image")
    gargs, rest = g.parse_known_args(argv)

    # `rest` now holds only the subcommand + its own args. The first token
    # is the subcommand; if it isn't one, treat the whole of `rest` as
    # YAML files for `deploy` (the bare-`xpf-deploy.py foo.yaml` shorthand).
    if rest and rest[0] in ("deploy", "launch", "inventory", "fetch", "kernel-roll"):
        cmd, cmd_argv = rest[0], rest[1:]
    else:
        cmd, cmd_argv = "deploy", rest

    if cmd == "fetch":
        sub = argparse.ArgumentParser(prog="xpf-deploy.py fetch", add_help=False)
        sub.add_argument("--version", required=True)
        sub.add_argument("--image-url", dest="image_url")
        sub.add_argument("--out")
        sub.add_argument("--alias")
        sub.add_argument("--channel", default="stable",
                         help="watermark channel (anti-rollback bucket)")
        sub.add_argument("--allow-rollback", action="store_true",
                         help="permit fetching an older version than the "
                              "recorded watermark (deliberate downgrade)")
        sub.add_argument("--qcow2-only", action="store_true",
                         help="fetch+verify only the qcow2 (libvirt/KVM path)")
        sub.add_argument("--no-import", action="store_true",
                         help="verify only; do not incus image import")
        args = sub.parse_args(cmd_argv)
    elif cmd == "inventory":
        sub = argparse.ArgumentParser(prog="xpf-deploy.py inventory", add_help=False)
        args = sub.parse_args(cmd_argv)
    elif cmd == "launch":
        sub = argparse.ArgumentParser(prog="xpf-deploy.py launch", add_help=False)
        sub.add_argument("--name", required=True)
        sub.add_argument("--mode", default="standalone", choices=["standalone", "cluster"])
        sub.add_argument("--node-id", type=int, dest="node_id")
        sub.add_argument("--cpu", type=int, default=4)
        sub.add_argument("--mem", default="4GiB")
        sub.add_argument("--config")
        sub.add_argument("--nic", action="append", default=[])
        args = sub.parse_args(cmd_argv)
    elif cmd == "kernel-roll":
        sub = argparse.ArgumentParser(prog="xpf-deploy.py kernel-roll", add_help=False)
        sub.add_argument("--node", dest="nodes", action="append", default=[],
                         required=True,
                         help="HA node (incus name or ssh host); give it TWICE "
                              "in roll order (first-to-roll then second)")
        sub.add_argument("--version", required=True,
                         help="candidate kernel uname -r to roll to")
        sub.add_argument("--backend", default="incus", choices=["incus", "ssh"])
        sub.add_argument("--node0-id", type=int, default=0,
                         help="cluster node-id of the FIRST --node (default 0)")
        sub.add_argument("--node1-id", type=int, default=1,
                         help="cluster node-id of the SECOND --node (default 1)")
        sub.add_argument("--lease-ttl", type=int, default=1800,
                         help="kernel-roll lease TTL seconds (suppresses the "
                              "node's local self-recovery during the roll)")
        sub.add_argument("--boot-deadline", type=int, default=600,
                         help="seconds to wait for a node to boot + promote the "
                              "candidate before STOPPING the roll")
        args = sub.parse_args(cmd_argv)
    else:  # deploy
        sub = argparse.ArgumentParser(prog="xpf-deploy.py deploy", add_help=False)
        sub.add_argument("yamls", nargs="*")
        args = sub.parse_args(cmd_argv)

    # Fold the peeled globals into the namespace the command handlers read.
    args.cmd = cmd
    args.dry_run = gargs.dry_run
    args.hypervisor = gargs.hypervisor
    args.no_start = gargs.no_start
    args.image = gargs.image

    if cmd == "fetch":
        return cmd_fetch(args)
    if cmd == "inventory":
        return cmd_inventory(args)
    if cmd == "launch":
        return cmd_launch(args)
    if cmd == "kernel-roll":
        return cmd_kernel_roll(args)
    return cmd_deploy(args)


if __name__ == "__main__":
    sys.exit(main())
