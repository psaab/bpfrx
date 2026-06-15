#!/usr/bin/env python3
"""xpf-deploy — set up xpf appliance VMs (incus or libvirt), all in Python.

Subcommands:
  deploy <appliance.yaml> [...]   launch from YAML definition(s); a cluster
                                  is two files. (Default if args are *.yaml.)
  launch --name … --nic …         imperative launch without a YAML file.
  inventory                       list host NICs, SR-IOV VFs, bridges → the
                                  values you drop into a definition.

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
    if rest and rest[0] in ("deploy", "launch", "inventory"):
        cmd, cmd_argv = rest[0], rest[1:]
    else:
        cmd, cmd_argv = "deploy", rest

    if cmd == "inventory":
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

    if cmd == "inventory":
        return cmd_inventory(args)
    if cmd == "launch":
        return cmd_launch(args)
    return cmd_deploy(args)


if __name__ == "__main__":
    sys.exit(main())
