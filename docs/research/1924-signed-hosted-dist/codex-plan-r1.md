Reading additional input from stdin...
OpenAI Codex v0.139.0
--------
workdir: /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
model: gpt-5.5
provider: openai
approval: never
sandbox: read-only
reasoning effort: xhigh
reasoning summaries: none
session id: 019ed298-fe84-7083-933e-c1bf7354f458
--------
user
You are a HOSTILE plan reviewer for a research-only plan (NO code yet). This is
the xpf project (Junos-style firewall, AF_XDP dataplane). The plan is for GitHub
issue #1924: signed, hosted appliance distribution (image signing + signed apt
repo + Tailscale-style install.sh).

Read the plan at docs/research/1924-signed-hosted-dist/plan.md (in THIS cwd).
Also read for grounding: scripts/image/bake.py, scripts/deploy/xpf-deploy.py,
scripts/image/validate.py, debian/control, docs/install-images.md,
docs/in-place-upgrade.md.

Your job: ADVERSARIALLY review the PLAN (mechanism + tradeoffs), not code.
Be hostile: FAIL the plan if the architecture/trust model is wrong, if a path
option is mis-recommended, if there is a security hole in the install.sh trust
bootstrap, if the minisign-for-image + PGP-for-apt split is wrong, if the apt
repo tooling choice (reprepro vs aptly vs flat) is mis-justified, or if the
two OPEN QUESTIONS (hosting target OQ-1, signing identity OQ-2) are actually
hidden blockers rather than engineer-time inputs.

Requirements for any KILL or finding: quote the exact plan line and give a
concrete counter-example or correct alternative. Do NOT KILL without a verified
counter-example. Do NOT rubber-stamp.

Specific things to pressure-test:
1. Is signing ONLY SHA256SUMS (not the qcow2/metadata directly) actually
   sound? Does the transitive trust hold?
2. install.sh embedding the keyring inline vs fetch+pin — is the recommended
   choice the secure one? Is the "install.sh.minisig signed by the image key"
   loop-closure actually closing the loop, or circular?
3. apt deb822 Signed-By + reprepro Release signing — is the modern keyring
   path correct (not legacy apt-key)?
4. Two-key split (minisign image + PGP apt) vs single PGP identity — is the
   recommendation justified or needless complexity?
5. Does anything here REQUIRE OQ-1/OQ-2 values to converge, making them real
   blockers?

End with a verdict line EXACTLY one of:
PLAN-READY / PLAN-READY-WITH-NITS / PLAN-NEEDS-MAJOR / PLAN-KILL
Then a one-paragraph rationale.
codex
I’ll review this as a plan reviewer only: first I’m reading the research plan with line numbers, then the referenced build/deploy/validation docs and packaging files for grounding.
exec
/bin/bash -lc 'nl -ba scripts/deploy/xpf-deploy.py' in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
     1	#!/usr/bin/env python3
     2	"""xpf-deploy — set up xpf appliance VMs (incus or libvirt), all in Python.
     3	
     4	Subcommands:
     5	  deploy <appliance.yaml> [...]   launch from YAML definition(s); a cluster
     6	                                  is two files. (Default if args are *.yaml.)
     7	  launch --name … --nic …         imperative launch without a YAML file.
     8	  inventory                       list host NICs, SR-IOV VFs, bridges → the
     9	                                  values you drop into a definition.
    10	
    11	Interface naming is POSITIONAL (matches pkg/daemon/linksetup.go assignName):
    12	
    13	  standalone:      pos1 -> fxp0   pos2 -> ge-0/0/0   posN -> ge-0/0/(N-2)
    14	  cluster node 0:  pos1 -> fxp0   pos2 -> em0        posN -> ge-0/0/(N-3)
    15	  cluster node 1:  pos1 -> fxp0   pos2 -> em0        posN -> ge-7/0/(N-3)
    16	
    17	A NIC's backing (virtio bridge / SR-IOV VF / PCI passthrough) is declared
    18	explicitly per interface — `backing:` in YAML, or the `<backing>:<source>`
    19	spec for --nic. The tool translates each to the right incus device / libvirt
    20	virt-install argument. The day-0 config drive is built and check-config
    21	validated in-process (no shell helpers).
    22	
    23	Global options: --dry-run  --hypervisor incus|libvirt  --no-start  --image X
    24	
    25	Examples:
    26	  xpf-deploy.py deploy examples/deploy/standalone-sriov.yaml
    27	  xpf-deploy.py deploy --hypervisor libvirt examples/deploy/standalone-passthrough.yaml
    28	  xpf-deploy.py launch --name fw1 --config standalone.conf \\
    29	      --nic bridge:br-mgmt --nic sriov:enp8s0 --nic pci:0000:09:00.0
    30	  xpf-deploy.py inventory
    31	"""
    32	
    33	import argparse
    34	import os
    35	import re
    36	import shlex
    37	import shutil
    38	import subprocess
    39	import sys
    40	import tempfile
    41	
    42	try:
    43	    import yaml
    44	except ImportError:
    45	    yaml = None
    46	
    47	VALID_BACKINGS = {"net", "bridge", "macvlan", "sriov", "physical", "pci"}
    48	SYS_NET = "/sys/class/net"
    49	
    50	
    51	def die(msg):
    52	    sys.exit(f"ERROR: {msg}")
    53	
    54	
    55	# ── naming contract ───────────────────────────────────────────────────
    56	def expected_name(idx, mode, node_id):
    57	    """vSRX name the guest assigns to the NIC at position idx (0-based);
    58	    mirrors assignName() in pkg/daemon/linksetup.go."""
    59	    if idx == 0:
    60	        return "fxp0"
    61	    if mode == "cluster":
    62	        if idx == 1:
    63	            return "em0"
    64	        fpc = 7 if node_id == 1 else 0
    65	        return f"ge-{fpc}/0/{idx - 2}"
    66	    return f"ge-0/0/{idx - 1}"
    67	
    68	
    69	def norm_role(role):
    70	    r = role.strip()
    71	    m = re.fullmatch(r"ge-(\d+)[-/]0[-/](\d+)", r)
    72	    return f"ge-{m.group(1)}/0/{m.group(2)}" if m else r
    73	
    74	
    75	# ── host introspection ────────────────────────────────────────────────
    76	def _read(path):
    77	    try:
    78	        with open(path) as f:
    79	            return f.read().strip()
    80	    except OSError:
    81	        return ""
    82	
    83	
    84	def is_physical_nic(dev):
    85	    if dev == "lo" or not os.path.isdir(os.path.join(SYS_NET, dev, "device")):
    86	        return False
    87	    return not re.match(r"(veth|tap|br-|virbr|docker|incusbr)", dev)
    88	
    89	
    90	def driver_of(dev):
    91	    link = os.path.join(SYS_NET, dev, "device", "driver")
    92	    return os.path.basename(os.path.realpath(link)) if os.path.exists(link) else "?"
    93	
    94	
    95	def pci_of(dev):
    96	    link = os.path.join(SYS_NET, dev, "device")
    97	    return os.path.basename(os.path.realpath(link)) if os.path.exists(link) else "?"
    98	
    99	
   100	def native_xdp_hint(driver):
   101	    if driver in ("mlx5_core", "i40e", "ice", "ixgbe", "bnxt_en", "nfp"):
   102	        return "native"
   103	    if driver in ("iavf", "ixgbevf", "virtio_net"):
   104	        return "no (generic)"
   105	    return "unknown"
   106	
   107	
   108	def vf_parent(addr):
   109	    """(PF_netdev, vf_index) for an SR-IOV VF PCI address, or None."""
   110	    if not os.path.isdir(SYS_NET):
   111	        return None
   112	    for pf in os.listdir(SYS_NET):
   113	        devdir = os.path.join(SYS_NET, pf, "device")
   114	        if not os.path.isdir(devdir):
   115	            continue
   116	        for entry in os.listdir(devdir):
   117	            if entry.startswith("virtfn") and \
   118	               os.path.basename(os.path.realpath(os.path.join(devdir, entry))) == addr:
   119	                return pf, entry[len("virtfn"):]
   120	    return None
   121	
   122	
   123	def cmd_inventory(_args):
   124	    print(f"=== Physical NICs ===")
   125	    print(f"{'NETDEV':<14} {'DRIVER':<10} {'PCI':<14} {'MAC':<18} {'LINK':<6} NATIVE-XDP")
   126	    for dev in sorted(os.listdir(SYS_NET)):
   127	        if not is_physical_nic(dev):
   128	            continue
   129	        drv = driver_of(dev)
   130	        print(f"{dev:<14} {drv:<10} {pci_of(dev):<14} "
   131	              f"{_read(os.path.join(SYS_NET, dev, 'address')):<18} "
   132	              f"{_read(os.path.join(SYS_NET, dev, 'operstate')):<6} {native_xdp_hint(drv)}")
   133	        devdir = os.path.join(SYS_NET, dev, "device")
   134	        total = _read(os.path.join(devdir, "sriov_totalvfs"))
   135	        if total and total != "0":
   136	            num = _read(os.path.join(devdir, "sriov_numvfs")) or "0"
   137	            print(f"    SR-IOV: {num}/{total} VFs. Create N:  "
   138	                  f"echo N | sudo tee {devdir}/sriov_numvfs")
   139	            for entry in sorted(os.listdir(devdir)):
   140	                if entry.startswith("virtfn"):
   141	                    vfpci = os.path.basename(os.path.realpath(os.path.join(devdir, entry)))
   142	                    print(f"      vf{entry[len('virtfn'):]:<3} pci:{vfpci}   "
   143	                          f"(sriov:{dev}  |  pci:{vfpci},mac=02:..)")
   144	    print("\n=== Host bridges (bridge:<name>) ===")
   145	    found = False
   146	    for dev in sorted(os.listdir(SYS_NET)):
   147	        if os.path.isdir(os.path.join(SYS_NET, dev, "bridge")):
   148	            print(f"  bridge:{dev}")
   149	            found = True
   150	    if not found:
   151	        print("  (none — create: sudo ip link add br-lan type bridge; ip link set br-lan up)")
   152	    return 0
   153	
   154	
   155	# ── appliance model ───────────────────────────────────────────────────
   156	def validate_appliance(ap, where):
   157	    if not ap.get("name"):
   158	        die(f"{where}: name is required")
   159	    if ap["mode"] not in ("standalone", "cluster"):
   160	        die(f"{where}: mode must be standalone|cluster")
   161	    if ap["mode"] == "cluster" and ap.get("node_id") not in (0, 1):
   162	        die(f"{where}: cluster needs node_id 0|1")
   163	    if not ap["interfaces"]:
   164	        die(f"{where}: at least one interface (position 1 = fxp0)")
   165	    for i, ic in enumerate(ap["interfaces"]):
   166	        if ic.get("backing") not in VALID_BACKINGS:
   167	            die(f"{where}: interface {i + 1} backing must be one of {sorted(VALID_BACKINGS)}")
   168	        if not ic.get("source"):
   169	            die(f"{where}: interface {i + 1} needs a source")
   170	        want = expected_name(i, ap["mode"], ap.get("node_id"))
   171	        if ic.get("role") and norm_role(ic["role"]) != want:
   172	            die(f"{where}: interface {i + 1} declares role '{ic['role']}' but position {i + 1} "
   173	                f"is '{want}' — reorder or fix; position is the contract.")
   174	        ic["_name"] = want
   175	
   176	
   177	def load_yaml_appliance(path):
   178	    if yaml is None:
   179	        die("PyYAML required for YAML deploy (apt install python3-yaml). "
   180	            "Use the 'launch' subcommand for a no-YAML, no-dependency path.")
   181	    with open(path) as f:
   182	        doc = yaml.safe_load(f)
   183	    if not isinstance(doc, dict):
   184	        die(f"{path}: top level must be a mapping")
   185	    a = doc.get("appliance") or {}
   186	    ap = {
   187	        "name": a.get("name"), "mode": a.get("mode", "standalone"),
   188	        "node_id": a.get("node_id"), "image": a.get("image", "xpf-appliance"),
   189	        "cpu": a.get("cpu", 4), "memory": a.get("memory", "4GiB"),
   190	        "config": a.get("config"), "interfaces": doc.get("interfaces") or [],
   191	        "pool": a.get("pool", "default"),
   192	        "base_dir": os.path.dirname(os.path.abspath(path)),
   193	    }
   194	    validate_appliance(ap, path)
   195	    return ap
   196	
   197	
   198	# ── day-0 config drive (pure Python; xorriso/genisoimage for the ISO) ──
   199	def find_xpfd():
   200	    for c in (os.environ.get("XPFD"), os.path.join(os.getcwd(), "xpfd"),
   201	              shutil.which("xpfd")):
   202	        if c and os.path.isfile(c) and os.access(c, os.X_OK):
   203	            return c
   204	    return None
   205	
   206	
   207	def build_config_drive(ap, runner):
   208	    cfg = ap.get("config")
   209	    if not cfg:
   210	        return None
   211	    cfg_path = cfg if os.path.isabs(cfg) else os.path.join(ap["base_dir"], cfg)
   212	    iso = os.path.join(os.getcwd(), f"{ap['name']}-day0.iso")
   213	    if runner.dry:
   214	        print(f"==> (dry-run) would build day-0 drive {iso} from {cfg_path} "
   215	              f"(label xpf-config, check-config validated)")
   216	        return iso
   217	    if not os.path.isfile(cfg_path):
   218	        die(f"config not found: {cfg_path}")
   219	    xpfd = find_xpfd()
   220	    if xpfd:
   221	        nodearg = ["-node-id", str(ap["node_id"])] if ap["mode"] == "cluster" else []
   222	        r = subprocess.run([xpfd, "check-config"] + nodearg + [cfg_path],
   223	                           capture_output=True, text=True)
   224	        if r.returncode != 0:
   225	            die(f"day-0 config REJECTED by check-config:\n{r.stdout}{r.stderr}")
   226	        print(f"==> day-0 config validated ({os.path.basename(cfg_path)})")
   227	    else:
   228	        print("WARNING: no xpfd binary found — skipping build-host validation "
   229	              "(the appliance still validates at first boot).")
   230	    mkiso = next((t for t in ("xorriso", "genisoimage", "mkisofs") if shutil.which(t)), None)
   231	    if not mkiso:
   232	        die("need xorriso/genisoimage/mkisofs to build the config drive (apt install xorriso)")
   233	    stage = tempfile.mkdtemp(prefix="xpf-day0-")
   234	    try:
   235	        shutil.copyfile(cfg_path, os.path.join(stage, "xpf.conf"))
   236	        os.chmod(os.path.join(stage, "xpf.conf"), 0o644)
   237	        if ap["mode"] == "cluster":
   238	            with open(os.path.join(stage, "node-id"), "w") as f:
   239	                f.write(f"{ap['node_id']}\n")
   240	        if mkiso == "xorriso":
   241	            argv = ["xorriso", "-as", "mkisofs", "-quiet", "-V", "xpf-config",
   242	                    "-J", "-r", "-o", iso, stage]
   243	        else:
   244	            argv = [mkiso, "-quiet", "-V", "xpf-config", "-J", "-r", "-o", iso, stage]
   245	        subprocess.run(argv, check=True, capture_output=True, text=True)
   246	        print(f"==> built day-0 drive {iso} (label xpf-config)")
   247	    finally:
   248	        shutil.rmtree(stage, ignore_errors=True)
   249	    return iso
   250	
   251	
   252	# ── memory / pci helpers ──────────────────────────────────────────────
   253	def memory_mb(val):
   254	    m = re.fullmatch(r"(\d+)\s*([GMgm]i?[Bb]?)?", str(val).strip())
   255	    if not m:
   256	        die(f"unparseable memory '{val}'")
   257	    return int(m.group(1)) * 1024 if (m.group(2) or "M").upper().startswith("G") else int(m.group(1))
   258	
   259	
   260	def pci_parts(addr):
   261	    m = re.fullmatch(r"([0-9a-fA-F]{4}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])", addr)
   262	    if not m:
   263	        die(f"pci address '{addr}' is not DDDD:BB:DD.F")
   264	    return {"domain": "0x" + m.group(1), "bus": "0x" + m.group(2),
   265	            "slot": "0x" + m.group(3), "function": "0x" + m.group(4)}
   266	
   267	
   268	class Runner:
   269	    def __init__(self, dry):
   270	        self.dry = dry
   271	
   272	    def run(self, argv):
   273	        if self.dry:
   274	            print(" ".join(shlex.quote(a) for a in argv))
   275	            return ""
   276	        return subprocess.run(argv, check=True, capture_output=True, text=True).stdout
   277	
   278	
   279	# ── deploy backends ───────────────────────────────────────────────────
   280	def print_map(ap):
   281	    tag = ap["mode"] + (f" node {ap['node_id']}" if ap["mode"] == "cluster" else "")
   282	    print(f"==> {ap['name']}: {tag}, {len(ap['interfaces'])} NICs")
   283	    for i, ic in enumerate(ap["interfaces"]):
   284	        print(f"      pos {i + 1}: {ic['_name']:<10} <- {ic['backing']}:{ic['source']}")
   285	
   286	
   287	def deploy_incus(ap, runner, start):
   288	    name = ap["name"]
   289	    print_map(ap)
   290	    iso = build_config_drive(ap, runner)
   291	    # --no-profiles: the default profile usually carries an `eth0` NIC,
   292	    # which would be an extra virtio device the guest names positionally
   293	    # alongside the declared dev00.. — a phantom interface that pollutes
   294	    # the NIC->name map. Suppress all profile devices and provide the root
   295	    # disk explicitly from the storage pool (default "default", override
   296	    # with `pool:` in YAML) so the device set is EXACTLY the declared NICs.
   297	    pool = ap.get("pool", "default")
   298	    # incus -d sets ONE key=value per flag (<device>,<key>=<value>), so the
   299	    # root disk needs three -d flags, not one comma-joined value.
   300	    runner.run(["incus", "init", ap["image"], name, "--vm", "--no-profiles",
   301	                "-c", f"limits.cpu={ap['cpu']}", "-c", f"limits.memory={ap['memory']}",
   302	                "-d", "root,type=disk", "-d", f"root,pool={pool}", "-d", "root,path=/"])
   303	    pins = []
   304	    for i, ic in enumerate(ap["interfaces"]):
   305	        dev = f"dev{i:02d}"
   306	        b, src, mac = ic["backing"], str(ic["source"]), ic.get("mac")
   307	        if b == "net":
   308	            args = ["nic", f"network={src}"]
   309	        elif b == "bridge":
   310	            args = ["nic", "nictype=bridged", f"parent={src}"]
   311	        elif b == "macvlan":
   312	            args = ["nic", "nictype=macvlan", f"parent={src}"]
   313	        elif b == "sriov":
   314	            args = ["nic", "nictype=sriov", f"parent={src}"]
   315	        elif b == "physical":
   316	            args = ["nic", "nictype=physical", f"parent={src}"]
   317	        elif b == "pci":
   318	            args = ["pci", f"address={src}"]
   319	        if mac and b in ("net", "bridge", "macvlan", "sriov"):
   320	            args.append(f"hwaddr={mac}")
   321	        if mac and b == "pci":
   322	            par = None if runner.dry else vf_parent(src)
   323	            if par:
   324	                pins.append(["sudo", "ip", "link", "set", "dev", par[0], "vf", par[1], "mac", mac])
   325	            elif runner.dry:
   326	                print(f"      (dry-run) would pin VF MAC for pci:{src}")
   327	            else:
   328	                die(f"pci:{src} with mac= is not an SR-IOV VF here (drop mac= for whole-PF)")
   329	        runner.run(["incus", "config", "device", "add", name, dev] + args)
   330	    if iso:
   331	        runner.run(["incus", "config", "device", "add", name, "day0", "disk", f"source={iso}"])
   332	    for pin in pins:
   333	        runner.run(["sudo", "ip", "link", "set", "dev", pin[5], "up"])
   334	        print(f"==> pinning VF MAC: {' '.join(pin)}")
   335	        runner.run(pin)
   336	    if start:
   337	        runner.run(["incus", "start", name])
   338	        print(f"\n{name} launched. Verify the NIC->name map:\n"
   339	              f"  incus exec {name} -- cli -c \"show interfaces terse\"")
   340	    else:
   341	        print(f"{name} created (not started): incus start {name}")
   342	
   343	
   344	def deploy_libvirt(ap, runner, start):
   345	    name = ap["name"]
   346	    print_map(ap)
   347	    iso = build_config_drive(ap, runner)
   348	    argv = ["virt-install", "--name", name, "--memory", str(memory_mb(ap["memory"])),
   349	            "--vcpus", str(ap["cpu"]), "--import",
   350	            "--disk", f"path=/var/lib/libvirt/images/{ap['image']}.qcow2",
   351	            "--osinfo", "ubuntu26.04", "--noautoconsole"]
   352	    if iso:
   353	        argv += ["--disk", f"path={iso},device=cdrom"]
   354	    notes = []
   355	    for ic in ap["interfaces"]:
   356	        b, src, mac = ic["backing"], str(ic["source"]), ic.get("mac")
   357	        if b in ("net", "bridge"):
   358	            net = f"{'network' if b == 'net' else 'bridge'}={src},model=virtio"
   359	            argv += ["--network", net + (f",mac.address={mac}" if mac else "")]
   360	        elif b == "macvlan":
   361	            net = f"type=direct,source={src},source_mode=bridge,model=virtio"
   362	            argv += ["--network", net + (f",mac.address={mac}" if mac else "")]
   363	        elif b == "physical":
   364	            argv += ["--hostdev", src]
   365	        elif b == "pci":
   366	            if mac:
   367	                p = pci_parts(src)
   368	                argv += ["--network",
   369	                         "type=hostdev,source.address.type=pci,"
   370	                         f"source.address.domain={p['domain']},source.address.bus={p['bus']},"
   371	                         f"source.address.slot={p['slot']},source.address.function={p['function']},"
   372	                         f"mac.address={mac}"]
   373	            else:
   374	                argv += ["--hostdev", src]
   375	        elif b == "sriov":
   376	            pool = f"{src}-vfpool"
   377	            argv += ["--network", f"network={pool}" + (f",mac.address={mac}" if mac else "")]
   378	            notes.append(f"sriov:{src} -> libvirt VF pool '{pool}'. Define once:\n"
   379	                         f"      <network><name>{pool}</name>"
   380	                         f"<forward mode='hostdev' managed='yes'><pf dev='{src}'/></forward></network>\n"
   381	                         f"      virsh net-define <f> && virsh net-start {pool} && virsh net-autostart {pool}")
   382	    print("# virt-install — NIC order = guest PCI-slot order = positional names.")
   383	    for n in notes:
   384	        print(f"# NOTE: {n}")
   385	    runner.run(argv)
   386	    if start:
   387	        print(f"\n{name}: verify with `virsh console {name}` then "
   388	              f"`cli -c \"show interfaces terse\"`.")
   389	
   390	
   391	def deploy(ap, args):
   392	    runner = Runner(args.dry_run)
   393	    if args.image:
   394	        ap["image"] = args.image
   395	    (deploy_incus if args.hypervisor == "incus" else deploy_libvirt)(
   396	        ap, runner, not args.no_start)
   397	
   398	
   399	# ── subcommands ───────────────────────────────────────────────────────
   400	def cmd_deploy(args):
   401	    if not args.yamls:
   402	        die("deploy needs at least one YAML file")
   403	    for path in args.yamls:
   404	        deploy(load_yaml_appliance(path), args)
   405	    return 0
   406	
   407	
   408	def cmd_launch(args):
   409	    ifaces = []
   410	    for spec in args.nic:
   411	        kind, _, rest = spec.partition(":")
   412	        if not rest:
   413	            kind, rest = "net", spec
   414	        src, _, tail = rest.partition(",")
   415	        mac = None
   416	        m = re.search(r"mac=([^,]+)", tail)
   417	        if m:
   418	            mac = m.group(1)
   419	        ic = {"backing": kind, "source": src}
   420	        if mac:
   421	            ic["mac"] = mac
   422	        ifaces.append(ic)
   423	    ap = {"name": args.name, "mode": args.mode, "node_id": args.node_id,
   424	          "image": args.image or "xpf-appliance", "cpu": args.cpu,
   425	          "memory": args.mem, "config": args.config, "interfaces": ifaces,
   426	          "base_dir": os.getcwd()}
   427	    validate_appliance(ap, "launch")
   428	    deploy(ap, args)
   429	    return 0
   430	
   431	
   432	def main():
   433	    argv = sys.argv[1:]
   434	    if "-h" in argv or "--help" in argv or not argv:
   435	        print(__doc__)
   436	        return 0 if ("-h" in argv or "--help" in argv) else 2
   437	
   438	    # Peel the global options from ANYWHERE on the command line with a
   439	    # globals-only pre-parser. parse_known_args picks up --dry-run /
   440	    # --hypervisor / --no-start / --image whether they appear before or
   441	    # after the subcommand, and (critically) it CONSUMES their values, so
   442	    # an option value can never be mistaken for the subcommand token.
   443	    g = argparse.ArgumentParser(add_help=False)
   444	    g.add_argument("--dry-run", action="store_true")
   445	    g.add_argument("--hypervisor", default="incus", choices=["incus", "libvirt"])
   446	    g.add_argument("--no-start", action="store_true")
   447	    g.add_argument("--image")
   448	    gargs, rest = g.parse_known_args(argv)
   449	
   450	    # `rest` now holds only the subcommand + its own args. The first token
   451	    # is the subcommand; if it isn't one, treat the whole of `rest` as
   452	    # YAML files for `deploy` (the bare-`xpf-deploy.py foo.yaml` shorthand).
   453	    if rest and rest[0] in ("deploy", "launch", "inventory"):
   454	        cmd, cmd_argv = rest[0], rest[1:]
   455	    else:
   456	        cmd, cmd_argv = "deploy", rest
   457	
   458	    if cmd == "inventory":
   459	        sub = argparse.ArgumentParser(prog="xpf-deploy.py inventory", add_help=False)
   460	        args = sub.parse_args(cmd_argv)
   461	    elif cmd == "launch":
   462	        sub = argparse.ArgumentParser(prog="xpf-deploy.py launch", add_help=False)
   463	        sub.add_argument("--name", required=True)
   464	        sub.add_argument("--mode", default="standalone", choices=["standalone", "cluster"])
   465	        sub.add_argument("--node-id", type=int, dest="node_id")
   466	        sub.add_argument("--cpu", type=int, default=4)
   467	        sub.add_argument("--mem", default="4GiB")
   468	        sub.add_argument("--config")
   469	        sub.add_argument("--nic", action="append", default=[])
   470	        args = sub.parse_args(cmd_argv)
   471	    else:  # deploy
   472	        sub = argparse.ArgumentParser(prog="xpf-deploy.py deploy", add_help=False)
   473	        sub.add_argument("yamls", nargs="*")
   474	        args = sub.parse_args(cmd_argv)
   475	
   476	    # Fold the peeled globals into the namespace the command handlers read.
   477	    args.cmd = cmd
   478	    args.dry_run = gargs.dry_run
   479	    args.hypervisor = gargs.hypervisor
   480	    args.no_start = gargs.no_start
   481	    args.image = gargs.image
   482	
   483	    if cmd == "inventory":
   484	        return cmd_inventory(args)
   485	    if cmd == "launch":
   486	        return cmd_launch(args)
   487	    return cmd_deploy(args)
   488	
   489	
   490	if __name__ == "__main__":
   491	    sys.exit(main())

exec
/bin/bash -lc 'nl -ba docs/research/1924-signed-hosted-dist/plan.md' in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
     1	# Plan of action — #1924: signed, hosted appliance distribution
     2	
     3	> Revision: r1 (2026-06-16)
     4	> Status: DRAFTING — pre-review
     5	> Branch: research/1924-signed-hosted-dist
     6	> Mode: `/research` — STOPS at PLAN-READY. No implementation, no PR, no
     7	> production source touched until `/engineer 1924`.
     8	
     9	## 1. Problem statement
    10	
    11	Follow-up from #1879 / PR #1906 (appliance images, Path C) and #1917/#1923
    12	(the `xpf` / `xpf-appliance` `.deb` + `make deb` + bake-installs-the-deb).
    13	Today the distribution story stops at "build the artifacts locally":
    14	
    15	- **No signatures.** `scripts/image/bake.py` step 6 emits `dist/SHA256SUMS`
    16	  (plain sha256 of the qcow2 + incus metadata) and a `dist/xpf-<ver>.manifest`
    17	  (provenance text). Neither is signed. An operator who downloads the image
    18	  has no cryptographic proof of origin — `sha256sum -c` only proves the file
    19	  matches a checksum file that itself is unauthenticated. A MITM or a
    20	  compromised mirror can serve a tampered image plus a matching `SHA256SUMS`.
    21	- **No published distribution channel.** `make deb` writes to `dist/deb/`;
    22	  `make image` writes to `dist/`. There is no hosted location, no retention
    23	  policy, no stable/edge channel layout. The CLAUDE.md "Quick Start" and
    24	  `docs/install-images.md` assume the operator builds locally or copies
    25	  files by hand.
    26	- **No `apt` path.** The `xpf-appliance` metapackage (debian/control) is
    27	  explicitly designed as "the operator-facing entry point: `apt install
    28	  xpf-appliance` … e.g. from a hosted apt repo" — but no such repo exists.
    29	  There is no `install.sh`, no signed `Release`/`InRelease`, no archive key.
    30	- **No verification on the consumer side.** `scripts/deploy/xpf-deploy.py`
    31	  and `scripts/image/validate.py` consume `--qcow2 … --metadata …` paths
    32	  directly with no signature import or check; `build_config_drive` in
    33	  xpf-deploy.py validates the day-0 *config*, not the *image*.
    34	
    35	Goal (issue): an operator fetches + verifies the appliance image and the
    36	packages from a trusted, signed source instead of copying files by hand.
    37	
    38	### Two decisions are the USER's, not this plan's (OPEN QUESTIONS)
    39	
    40	This plan deliberately does NOT invent answers to two inputs that are
    41	operator/infra/security decisions. The mechanism is designed so both are
    42	**config inputs**, not hardcoded constants, so the plan converges PLAN-READY
    43	pending only these two engineer-time values:
    44	
    45	- **OQ-1 — Hosting target.** WHERE artifacts are published (URL / S3 bucket /
    46	  repo host), the retention policy, and the channel layout (stable / edge).
    47	- **OQ-2 — Signing identity.** WHICH signing key, and key management: who
    48	  holds the secret key, rotation cadence, and where the public key is pinned.
    49	
    50	These are surfaced as `XPF_DIST_BASE_URL` (or equivalent) and a checked-in
    51	public key file + `XPF_SIGN_SECKEY` (path, never the key itself). See §9.
    52	
    53	## 2. Blast radius / affected surface
    54	
    55	New work is almost entirely ADDITIVE — no production dataplane / control-plane
    56	source is touched. Surface:
    57	
    58	| Area | Change class | Files |
    59	|---|---|---|
    60	| Image bake signing | extend (additive output) | `scripts/image/bake.py` (emit a signature next to SHA256SUMS) |
    61	| Image verify (deploy/validate) | extend (optional gate) | `scripts/deploy/xpf-deploy.py`, `scripts/image/validate.py` |
    62	| `.deb` repo build tooling | NEW | `scripts/dist/` (repo builder + signer) |
    63	| `install.sh` | NEW | `scripts/dist/install.sh` (or `dist/install.sh` template) |
    64	| Public key (pinned) | NEW (placeholder until OQ-2) | `scripts/dist/xpf-archive-keyring.asc` / `xpf.pub` |
    65	| Makefile | extend | `dist-sign`, `dist-repo`, `dist-publish` targets |
    66	| Docs | extend / NEW | `docs/install-images.md`, NEW `docs/distribution.md` |
    67	| CI/release (optional) | NEW (deferrable) | `.github/workflows/release.yml` |
    68	
    69	Zero changes to: `pkg/**` (Go control plane), `userspace-dp/**` (Rust
    70	dataplane), `bpf/**`, the daemon, CLI, or the wire protocol. No smoke-test
    71	exposure on the loss cluster (no forwarding-path change). This is build/release
    72	plumbing.
    73	
    74	## 3. Design overview
    75	
    76	Three independent-but-coordinated mechanisms, each gated by a config input:
    77	
    78	1. **Sign the image artifacts** at bake time: sign the `SHA256SUMS` file (the
    79	   checksum manifest), so one signature transitively authenticates the qcow2 +
    80	   incus metadata. Verify on import in `validate.py` / `xpf-deploy.py`.
    81	2. **Build + sign an apt repo** for the `xpf` / `xpf-appliance` `.deb`s, so
    82	   `apt install xpf-appliance` works from a hosted, authenticated index.
    83	3. **`install.sh`** (Tailscale-style) that bootstraps trust (installs the
    84	   pinned archive keyring), adds the apt source, and runs `apt install
    85	   xpf-appliance` — one command on a fresh Debian/Ubuntu host.
    86	
    87	Publishing (where bytes land) is a thin `dist-publish` target parametrised by
    88	`XPF_DIST_BASE_URL` (OQ-1). The mechanism is host-agnostic: a static file
    89	server, an S3/GCS bucket fronted by HTTPS, or GitHub Releases all satisfy the
    90	contract "serve these files under a base URL over TLS".
    91	
    92	### Trust model (the spine of the design)
    93	
    94	There are TWO distinct trust roots, and the plan keeps them clean:
    95	
    96	- **Image trust** — the signature over `SHA256SUMS`. The operator obtains the
    97	  PUBLIC key out-of-band ONCE (checked into the repo + published at a
    98	  well-known URL) and pins it. Every image download is verified against it.
    99	- **Apt trust** — the apt archive signing key. `apt` itself enforces this via
   100	  signed `Release`/`InRelease` once the archive keyring is installed under
   101	  `/etc/apt/keyrings/` (modern deb822 / signed-by, NOT legacy `apt-key`).
   102	
   103	The `install.sh` bootstrap is the ONLY moment trust is established over the
   104	network, so it is the highest-risk step and gets the most scrutiny (§5, §8).
   105	We **pin the keyring fingerprint inside install.sh** (and verify the fetched
   106	keyring against it) so a compromised host serving a bad keyring is caught —
   107	install.sh's own integrity is the remaining root (mitigations in §8).
   108	
   109	## 4. Multiple Path Options
   110	
   111	### 4A. Signing tool (image SHA256SUMS + optionally the .deb repo Release)
   112	
   113	| Option | Pros | Cons |
   114	|---|---|---|
   115	| **minisign** (issue's lead) | tiny, single static binary, no keyring DB, Ed25519, trivially scriptable, easy to pin one pubkey; matches issue text | NOT what `apt` understands natively — apt needs OpenPGP for `Release`; so minisign covers IMAGE only, apt repo still needs a PGP path |
   116	| **signify** (OpenBSD) | same shape as minisign | less ubiquitous on Debian than minisign; same apt gap |
   117	| **GPG / OpenPGP** (`sequoia`/`gpg`) | apt-native (apt verifies `Release` with PGP); ONE tool covers both image AND repo | heavier, keyring management, larger trust surface; for the IMAGE it is overkill vs minisign |
   118	| **cosign / sigstore** | keyless OIDC option, transparency log | requires Fulcio/Rekor infra or a static key; new dep; apt still needs PGP; over-engineered for a single-publisher appliance |
   119	
   120	**Recommendation (mechanism, value deferred to OQ-2):**
   121	- **Image artifacts → minisign** over `SHA256SUMS`. Smallest trust surface,
   122	  exactly the issue's lead, one pinned Ed25519 pubkey. The image consumer
   123	  (validate.py / xpf-deploy.py / operator) is a script we control, so it can
   124	  call `minisign -V` directly — we are not constrained to apt's PGP.
   125	- **Apt repo → OpenPGP** (`gpg`/`sequoia`) over `Release`, because apt
   126	  mandates it. This is unavoidable: apt will not trust a minisign signature.
   127	
   128	This is a deliberate **two-key, two-tool** split: minisign for images, PGP for
   129	the apt archive. It is NOT redundancy — they authenticate different artifacts
   130	to different consumers (our scripts vs apt). Both public keys are checked into
   131	the repo and published. (An ALTERNATIVE single-tool variant — PGP for both,
   132	dropping minisign — is documented in §4A-alt below for the reviewers to weigh;
   133	the recommendation is the two-tool split because minisign's single-pubkey pin
   134	is dramatically simpler to verify in install.sh and in our Python consumers.)
   135	
   136	#### 4A-alt. Single-tool (PGP-only) variant
   137	Use one OpenPGP key for BOTH the image `SHA256SUMS.asc` and the apt `Release`.
   138	Pros: one key to manage (one OQ-2 answer), apt-native. Cons: image consumers
   139	(validate.py, install.sh trust-bootstrap) must shell out to `gpg --verify`
   140	with a keyring, which is heavier and more error-prone to pin than `minisign
   141	-V -p key.pub`; PGP's web-of-trust/expiry semantics add footguns for a
   142	single-publisher appliance. Kept as a fallback if the user prefers exactly one
   143	signing identity.
   144	
   145	### 4B. Apt repository tooling
   146	
   147	| Option | Pros | Cons |
   148	|---|---|---|
   149	| **reprepro** | mature, deb-native, simple `conf/distributions`, signs `Release` with gpg, deterministic pool layout, no DB server | single-version-per-arch by default (fine for an appliance; multi-version needs care) |
   150	| **aptly** | snapshots, multi-version, mirroring, publish to S3 natively, channels (stable/edge) map to "distributions" cleanly | larger, its own DB, more moving parts than we need for one package |
   151	| **flat signed repo** (hand-rolled `dpkg-scanpackages` + `apt-ftparchive` + `gpg` over a flat `Release`) | zero extra tooling beyond dpkg + gpg; trivially scriptable; matches the appliance's "small set of debs" reality | we own all the index correctness; flat repos are slightly less standard for deb822 `signed-by` (work fine though) |
   152	
   153	**Recommendation:** **reprepro** for the pool repo. It is the smallest mature
   154	tool that produces a correct signed `Release`/`InRelease` with channels via
   155	distinct distributions (`stable`, `edge`), and its `conf/distributions` is one
   156	readable file. `aptly` is the upgrade path IF OQ-1 picks S3 + we later need
   157	snapshots/mirroring. The flat-repo path is the zero-dependency fallback
   158	(documented) if reprepro is unwanted on the build host.
   159	
   160	Channel layout (deb822, the contract install.sh writes):
   161	```
   162	/etc/apt/sources.list.d/xpf.sources:
   163	  Types: deb
   164	  URIs: <XPF_DIST_BASE_URL>/apt        # OQ-1
   165	  Suites: stable                       # or edge
   166	  Components: main
   167	  Architectures: amd64
   168	  Signed-By: /etc/apt/keyrings/xpf-archive-keyring.asc
   169	```
   170	
   171	### 4C. install.sh trust-bootstrap (the security-critical step)
   172	
   173	| Option | Pros | Cons |
   174	|---|---|---|
   175	| **Embed the full keyring inline** (heredoc the ASCII-armored pubkey INTO install.sh) | no second network fetch; install.sh integrity == keyring integrity (one thing to trust) | install.sh is bigger; rotating the key means re-issuing install.sh |
   176	| **Fetch keyring + verify against a pinned fingerprint** in install.sh | install.sh stays small; key rotation = republish keyring | install.sh must still embed the fingerprint (a hash), which is the real pin; two fetches |
   177	| **TOFU (trust on first use)** — just `apt-key add` whatever is served | trivial | INSECURE — rejected; defeats the entire point of the issue |
   178	
   179	**Recommendation:** **embed the ASCII-armored archive pubkey inline** in
   180	install.sh (Tailscale does exactly this) AND verify the fetched `.deb`/repo
   181	through apt's own signed `Release`. The keyring-in-install.sh means there is
   182	exactly ONE artifact whose integrity matters at bootstrap (install.sh itself),
   183	and we publish install.sh over HTTPS at a stable URL + document a
   184	`curl … | sha256sum` / signature check for the paranoid (§8). Inline-embed is
   185	strictly simpler to reason about than fetch+pin-fingerprint (which still
   186	reduces to "trust the fingerprint hash in install.sh"). TOFU is rejected.
   187	
   188	### 4D. Hosting / publish (OQ-1 — value is the user's; mechanism here)
   189	
   190	| Option | Pros | Cons |
   191	|---|---|---|
   192	| **GitHub Releases** (per-tag assets) | free, TLS, no infra, matches `gh release`; the repo is already on GitHub | not an apt repo by itself (need GitHub Pages or a bucket for the apt pool); release assets are per-tag not channel-stable URLs |
   193	| **Static bucket (S3/GCS/R2) behind HTTPS** | stable channel URLs, cheap, aptly publishes to S3 natively, retention via lifecycle rules | the user must own/configure the bucket + CDN/TLS (OQ-1) |
   194	| **Self-hosted static file server** | full control | the user runs+secures it |
   195	
   196	**Mechanism (host-agnostic):** `make dist-publish` rsync/`aws s3 sync`/`gh
   197	release upload`s the `dist/` tree (images + sigs) and the reprepro `apt/` pool
   198	to `XPF_DIST_BASE_URL`. The plan provides a pluggable `XPF_PUBLISH_CMD` so the
   199	user wires their chosen backend without the mechanism caring. Retention +
   200	channel layout are documented defaults (keep last N images per channel) the
   201	user tunes. **No backend is hardcoded.**
   202	
   203	## 5. Detailed mechanism (recommended path)
   204	
   205	### 5.1 Image signing (bake.py, additive)
   206	After step 6 writes `dist/SHA256SUMS`, add step 6b:
   207	```
   208	minisign -S -s "$XPF_SIGN_SECKEY" -m dist/SHA256SUMS \
   209	         -t "xpf image $ver" -x dist/SHA256SUMS.minisig
   210	```
   211	- `XPF_SIGN_SECKEY` is a PATH to the secret key (OQ-2), never the key bytes.
   212	  If unset, bake prints a clear WARNING and skips signing (so a dev bake still
   213	  works), exactly like `--skip-validate` today warns "do not publish".
   214	- The pinned PUBLIC key ships in-repo as `scripts/dist/xpf-image.pub` and is
   215	  ALSO copied into `dist/` so the published tree is self-describing.
   216	- One signature over `SHA256SUMS` transitively covers both image artifacts
   217	  (the checksums inside are verified after the signature checks out).
   218	
   219	### 5.2 Image verify (validate.py + xpf-deploy.py, optional gate)
   220	Add a `verify_artifacts(qcow2, metadata, sigdir)` helper:
   221	1. `minisign -V -p <pinned pub> -m SHA256SUMS -x SHA256SUMS.minisig`
   222	2. then `sha256sum -c SHA256SUMS` for the two files.
   223	Wire it as:
   224	- `validate.py`: a new `--verify-sig` flag (default ON when a `.minisig` is
   225	  present next to the artifacts; a `--no-verify-sig` escape hatch for local
   226	  dev bakes that skipped signing).
   227	- `xpf-deploy.py`: verify the image at `import_image`-equivalent time before
   228	  `incus image import` / `virt-install --import`. If the operator points at a
   229	  hosted URL (future `--image-url`), fetch then verify then import.
   230	- The pinned pubkey path is a constant in the script (checked-in pub) with an
   231	  `XPF_IMAGE_PUBKEY` override for rotation/testing.
   232	
   233	### 5.3 Apt repo (NEW scripts/dist/build-apt-repo.sh + reprepro)
   234	- `conf/distributions` with `stable` and `edge` suites, `Components: main`,
   235	  `Architectures: amd64`, `SignWith: <KEYID>` (OQ-2 PGP key).
   236	- `make dist-repo` runs `make deb` then `reprepro -b <repo> includedeb
   237	  <suite> dist/deb/xpf_*.deb dist/deb/xpf-appliance_*.deb`.
   238	- Output is the standard pool/dists tree under `dist/apt/`, ready to publish.
   239	- Flat-repo fallback script documented for no-reprepro hosts.
   240	
   241	### 5.4 install.sh (NEW)
   242	Tailscale-shaped, POSIX sh, idempotent:
   243	1. Detect distro/arch; refuse non-amd64 / non-Debian-family with a clear msg.
   244	2. Install the pinned archive keyring to `/etc/apt/keyrings/
   245	   xpf-archive-keyring.asc` (embedded inline, `0644`).
   246	3. Write `/etc/apt/sources.list.d/xpf.sources` (deb822, `Signed-By`,
   247	   `XPF_DIST_BASE_URL` substituted; default channel `stable`,
   248	   `XPF_CHANNEL=edge` override).
   249	4. `apt-get update && apt-get install -y xpf-appliance`.
   250	5. Print next steps (day-0 config, `cli`, mgmt reachability caveat — the
   251	   interface-takeover warning from #1879 is RESTATED here because a bare-metal
   252	   `apt install` on a remote box can cut mgmt if fxp0 mapping is wrong).
   253	- `install.sh` is itself published at `XPF_DIST_BASE_URL/install.sh` and the
   254	  doc gives the `curl -fsSL … | sh` one-liner PLUS the paranoid
   255	  "download, read, verify, run" variant.
   256	
   257	### 5.5 Makefile + docs
   258	- `make dist-sign` (sign existing dist/ image artifacts), `make dist-repo`
   259	  (build signed apt repo), `make dist-publish` (push via `XPF_PUBLISH_CMD`).
   260	- NEW `docs/distribution.md`: the publisher runbook (key management pointers,
   261	  channel policy, retention, publish backends) + the operator runbook (the
   262	  install.sh one-liner, the manual apt steps, the image verify steps).
   263	- Extend `docs/install-images.md`: replace "copy files by hand" with "fetch +
   264	  verify from `XPF_DIST_BASE_URL`"; document `SHA256SUMS.minisig`.
   265	
   266	## 6. Test / validation strategy (research scope = how /engineer will prove it)
   267	
   268	No loss-cluster smoke (no forwarding change). Validation is local + CI-shaped:
   269	
   270	1. **Sign/verify round-trip (image):** bake (or a stub SHA256SUMS) → sign with
   271	   a throwaway minisign key → `verify_artifacts` PASSES; flip one byte of the
   272	   qcow2 → verify FAILS at `sha256sum -c`; flip the `.minisig` → verify FAILS
   273	   at `minisign -V`; wrong pubkey → FAILS. (Negative tests are mandatory — a
   274	   verify that can't fail is theater.)
   275	2. **Apt repo:** build the signed repo into a temp dir → spin a Debian
   276	   container (or the local incus image flow) → run install.sh pointed at a
   277	   `file://` or `http://localhost` serving of the temp repo → `apt install
   278	   xpf-appliance` succeeds → `apt-get update` against a TAMPERED `Release`
   279	   FAILS with apt's signature error (negative test).
   280	3. **install.sh:** shellcheck-clean; idempotent (run twice = no error); refuses
   281	   wrong arch; the keyring fingerprint embedded matches the published keyring.
   282	4. **bake.py unchanged paths:** the existing image-validation matrix
   283	   (`scripts/image/validate.py a|b|c`) still passes; signing is additive and
   284	   does not perturb the boot/day-0 contract.
   285	5. **Doc accuracy:** the `curl | sh` one-liner and the manual steps are
   286	   copy-pasteable against a local test publish.
   287	
   288	The signing key used in tests is a generated throwaway, NEVER OQ-2's real key.
   289	
   290	## 7. Rollout / sequencing
   291	
   292	`/engineer` should land this as small, independently-reviewable increments
   293	(each its own commit, true-merge per project policy):
   294	
   295	- **Inc 1 — image signing + verify** (bake.py emit `.minisig`; validate.py +
   296	  xpf-deploy.py verify; checked-in image pubkey placeholder; round-trip +
   297	  negative tests; docs). Shippable alone; gives signed images immediately.
   298	- **Inc 2 — apt repo build tooling** (`scripts/dist/build-apt-repo.sh`,
   299	  reprepro `conf/distributions`, `make dist-repo`, PGP archive pubkey
   300	  placeholder; container repo test). Shippable alone.
   301	- **Inc 3 — install.sh + publish + docs** (`install.sh`, `make dist-publish`
   302	  with `XPF_PUBLISH_CMD`, `docs/distribution.md`; install.sh container test).
   303	- **Inc 4 (optional, deferrable) — CI release workflow** (`.github/workflows/
   304	  release.yml` on tag: bake → sign → build repo → publish). GATED on OQ-1 +
   305	  OQ-2 being real, and on the user wanting CI to hold the secret key (a
   306	  security decision — may prefer manual signing on an air-gapped host).
   307	
   308	The two OPEN QUESTIONS are NOT blockers to Inc 1–3 landing as MECHANISM with
   309	placeholder keys + parametrised URLs; they ARE blockers to a real public
   310	release (Inc 4 / actual `dist-publish`). The plan converges with placeholders;
   311	the values are dropped in at engineer/release time.
   312	
   313	## 8. Risks & mitigations
   314	
   315	- **R1 — install.sh is the trust root over the network.** A compromised host
   316	  serving a bad install.sh defeats everything. Mitigation: publish install.sh
   317	  over HTTPS at a stable URL; embed the keyring inline (so the apt path is
   318	  self-authenticating once install.sh runs); document a verify-before-run
   319	  variant (publish `install.sh.minisig` too, signed by the image key, so the
   320	  paranoid operator verifies install.sh with the SAME pinned pubkey they used
   321	  for the image). This closes the loop: ONE pinned pubkey authenticates both
   322	  the image and install.sh.
   323	- **R2 — key compromise / rotation.** OQ-2 owns the policy, but the mechanism
   324	  must not hardcode a single key. Mitigation: pubkey paths are overridable
   325	  (`XPF_IMAGE_PUBKEY`, apt `Signed-By` is a file), and the plan documents a
   326	  rotation runbook (publish new pubkey, dual-sign during overlap, retire old).
   327	- **R3 — apt repo correctness (stale Packages index, missing arch).** Use
   328	  reprepro (it owns index generation) rather than hand-rolled scanning;
   329	  negative test (tampered Release must fail apt).
   330	- **R4 — signing-tool availability on build host.** `minisign` and `reprepro`
   331	  may not be installed. Mitigation: `require()`-style preflight in the new
   332	  scripts with an apt-install hint (matches bake.py's existing `require`
   333	  pattern); bake.py SKIPS signing with a loud warning if `minisign` or
   334	  `XPF_SIGN_SECKEY` is absent (dev ergonomics preserved; "do not publish"
   335	  warning, same posture as `--skip-validate`).
   336	- **R5 — mgmt cut-off on bare-metal apt install.** #1879's interface-takeover
   337	  hazard applies harder to `apt install xpf-appliance` on a remote box than to
   338	  a VM image. Mitigation: install.sh PRINTS the warning and does NOT auto-start
   339	  a config that takes over interfaces; the package's first-boot/day-0 contract
   340	  (already built in #1879/#1917) governs safe bootstrap. (This is a
   341	  documentation + sequencing mitigation; no new safe-bootstrap code is in
   342	  scope for #1924 — it was #1879's deliverable.)
   343	- **R6 — two keys confuse operators.** Mitigation: docs/distribution.md has a
   344	  single "Trust" section: pubkey A (image+install.sh, minisign), pubkey B (apt
   345	  archive, PGP), each with its fingerprint and pin location. The single-tool
   346	  §4A-alt remains the fallback if the user wants exactly one identity.
   347	
   348	## 9. Open questions (engineer-time inputs — NOT blockers to PLAN-READY)
   349	
   350	- **OQ-1 (hosting target):** the value of `XPF_DIST_BASE_URL`, the channel
   351	  layout (which suites exist), and the retention policy. Mechanism treats it as
   352	  a parameter; the user supplies the URL + picks GitHub Releases / bucket /
   353	  self-host at `/engineer`/release time.
   354	- **OQ-2 (signing identity):** the minisign keypair (image) and the OpenPGP
   355	  archive key (apt), who holds the secret keys, rotation cadence, and where the
   356	  public keys are pinned/published. Mechanism ships placeholder pubkeys + reads
   357	  the secret-key PATH from env; the user supplies real keys at release time.
   358	- **OQ-3 (one tool vs two):** §4A recommends minisign(image)+PGP(apt); §4A-alt
   359	  is the PGP-only single-identity fallback. The user MAY collapse to one PGP
   360	  identity if they prefer one key to manage — flag for the user, default is the
   361	  two-tool split.
   362	- **OQ-4 (CI signing):** does the secret key live in CI (automated release) or
   363	  on an air-gapped host (manual sign+publish)? Drives whether Inc 4 ships. A
   364	  security posture choice; default assumption is manual until the user opts in.
   365	
   366	## 10. Why not just keep SHA256SUMS?
   367	
   368	A plain checksum file proves integrity against accidental corruption, not
   369	authenticity against an adversary. The issue's explicit goal is "a TRUSTED,
   370	SIGNED source." Without a signature, any party who can serve the file can serve
   371	a matching `SHA256SUMS`. Signing is the minimum bar; an apt repo + install.sh
   372	is the usability bar (the issue's "rather than copying files by hand").
   373	
   374	## 11. Recommendation summary
   375	
   376	- Image: **minisign** over `SHA256SUMS` (one pinned Ed25519 pubkey), verified
   377	  in validate.py + xpf-deploy.py. Additive to bake.py.
   378	- Apt: **reprepro**-built signed repo (PGP `Release`), `stable`/`edge` suites,
   379	  deb822 `Signed-By`.
   380	- Bootstrap: **install.sh** with the archive keyring embedded inline +
   381	  optional `install.sh.minisig` for verify-before-run. TOFU rejected.
   382	- Hosting: host-agnostic `make dist-publish` via `XPF_PUBLISH_CMD` +
   383	  `XPF_DIST_BASE_URL`. No backend hardcoded.
   384	- Ship as Inc 1–3 (each independently reviewable); Inc 4 (CI release) is
   385	  optional + gated on OQ-1/OQ-2/OQ-4.
   386	- The two OPEN QUESTIONS (hosting target, signing identity) are engineer-time
   387	  inputs, not PLAN-READY blockers; the mechanism is complete pending only their
   388	  values.
   389	```

exec
/bin/bash -lc 'nl -ba scripts/image/bake.py' in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
     1	#!/usr/bin/env python3
     2	"""xpf appliance image bake (#1879 Path C — vSRX-style prebuilt image), in Python.
     3	
     4	Builds ONE bootable root-disk image OFFLINE (libguestfs — never boots the
     5	image to provision it) and exports it for both hypervisors:
     6	
     7	  dist/xpf-<ver>.qcow2                  - libvirt/KVM (virt-install)
     8	  dist/xpf-<ver>.incus-metadata.tar.gz  - incus VM image metadata
     9	  dist/SHA256SUMS
    10	
    11	Pipeline: build the xpf .deb (`make deb`; no `make generate` — embeds the
    12	#1864 tracked shim) -> discover + SHA256-verify the latest Ubuntu cloud
    13	image (XPF_BASE_RELEASE pins) -> virt-resize root into a work disk ->
    14	virt-customize (runtime packages, linux-generic >= 6.18 with the full
    15	driver set, purge cloud-init/snapd/stale kernels, networkd,
    16	init_on_alloc=0, `apt-get install ./xpf.deb` which stages the binaries +
    17	creates the /usr/local/sbin symlinks + enables the units via its postinst)
    18	-> virt-sysprep seal -> virt-sparsify+compress export -> checksums +
    19	manifest -> in-guest verify-dataplane validation gate (validate.py).
    20	
    21	Requirements: make/go/cargo, libguestfs-tools, qemu-utils, curl; incus for
    22	the validation gate. /dev/kvm makes libguestfs fast.
    23	
    24	Usage:
    25	  bake.py [--version V] [--out DIR] [--skip-build] [--skip-validate] [--keep-work]
    26	"""
    27	
    28	import argparse
    29	import os
    30	import resource
    31	import shutil
    32	import subprocess
    33	import sys
    34	import tempfile
    35	import time
    36	
    37	HERE = os.path.dirname(os.path.abspath(__file__))
    38	ROOT = os.path.dirname(os.path.dirname(HERE))
    39	
    40	# Runtime dependency set installed explicitly into the image. This is the
    41	# same set the xpf-appliance metapackage Depends on (debian/control). The
    42	# bake installs the runtime packages explicitly + the xpf BINARY package,
    43	# rather than the metapackage, so apt does not have to resolve the full
    44	# dependency closure against a single local .deb during the offline bake;
    45	# the xpf-appliance metapackage is the operator-facing `apt install`
    46	# entry point (e.g. from a future hosted repo, #1924). Keep this list and
    47	# the metapackage Depends in debian/control in sync.
    48	RUNTIME_PACKAGES = [
    49	    "frr", "strongswan", "strongswan-swanctl",
    50	    "kea-dhcp4-server", "kea-dhcp6-server", "chrony",
    51	    "iproute2", "nftables", "ethtool", "tcpdump", "pciutils",
    52	    "iputils-ping", "traceroute", "openssh-server", "openssh-client",
    53	    "systemd-resolved", "rsyslog", "curl", "ca-certificates",
    54	]
    55	
    56	SYSCTL_CONF = (
    57	    "net.core.bpf_jit_enable=1\n"
    58	    "net.ipv4.ip_forward=1\n"
    59	    "net.ipv6.conf.all.forwarding=1\n"
    60	    "net.ipv6.conf.all.accept_ra=0\n"
    61	    "net.ipv6.conf.default.accept_ra=0\n"
    62	)
    63	
    64	# apt-get update exits 0 even when an index fetch fails; --error-on=any
    65	# makes that fatal, one retry covers a transient blip.
    66	APT_UPDATE = ("apt-get update -qq -o Acquire::Retries=5 --error-on=any || "
    67	              "{ echo 'apt update failed; retrying in 10s' >&2; sleep 10; "
    68	              "apt-get update -qq -o Acquire::Retries=5 --error-on=any; }")
    69	
    70	GRUB_DROPIN = (
    71	    '# xpf (#1879): init_on_alloc=0 — CONFIG_INIT_ON_ALLOC_DEFAULT_ON zeroes\n'
    72	    '# every allocated page (~20% CPU in the virtio-net XDP path). A grub.d\n'
    73	    '# drop-in, NOT a sed on /etc/default/grub: Ubuntu cloud images override\n'
    74	    '# GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub.d/50-cloudimg-settings.cfg.\n'
    75	    'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT init_on_alloc=0"'
    76	)
    77	
    78	SSHD_DROPIN = (
    79	    '# xpf factory posture (#1879): root password is EMPTY (console-only\n'
    80	    '# login, vSRX parity). Pin the OpenSSH defaults explicitly.\n'
    81	    'PermitRootLogin prohibit-password\n'
    82	    'PermitEmptyPasswords no'
    83	)
    84	
    85	
    86	def info(m):
    87	    print(f"==> {m}")
    88	
    89	
    90	def die(m):
    91	    sys.exit(f"ERROR: {m}")
    92	
    93	
    94	def require(tool, hint):
    95	    if not shutil.which(tool):
    96	        die(f"{tool} not found — {hint}")
    97	
    98	
    99	def run(argv, **kw):
   100	    return subprocess.run(argv, check=True, **kw)
   101	
   102	
   103	def out_text(argv):
   104	    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout
   105	
   106	
   107	def git_version():
   108	    try:
   109	        return out_text(["git", "-C", ROOT, "describe", "--tags", "--always", "--dirty"]).strip()
   110	    except Exception:
   111	        return "dev"
   112	
   113	
   114	def ensure_memlock():
   115	    """qemu io_uring needs locked memory beyond the 8 MiB default."""
   116	    soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
   117	    if hard == resource.RLIM_INFINITY or hard >= 1048576 * 1024:
   118	        return
   119	    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
   120	        # The shell original died if this failed; preserve that — a silent
   121	        # drop just relocates the failure into libguestfs/qemu later.
   122	        if subprocess.run(["sudo", "-n", "prlimit", "--memlock=unlimited:unlimited",
   123	                           "--pid", str(os.getpid())]).returncode != 0:
   124	            die("could not raise RLIMIT_MEMLOCK (libguestfs/qemu io_uring needs it)")
   125	    else:
   126	        die("RLIMIT_MEMLOCK too low for libguestfs/qemu io_uring — raise it "
   127	            "(sudo prlimit --memlock=unlimited:unlimited --pid $$) and re-run")
   128	
   129	
   130	def discover_base_release():
   131	    if os.environ.get("XPF_BASE_RELEASE"):
   132	        return os.environ["XPF_BASE_RELEASE"]
   133	    url = os.environ.get("XPF_UBUNTU_RELEASES_URL",
   134	                         "https://cloud-images.ubuntu.com/releases")
   135	    import re
   136	    html = out_text(["curl", "-fsSL", url + "/"])
   137	    rels = sorted(set(re.findall(r'href="(\d{2}\.\d{2})/"', html)),
   138	                  key=lambda v: tuple(int(x) for x in v.split(".")))
   139	    if not rels:
   140	        die(f"could not discover the latest Ubuntu release from {url}/ "
   141	            "(set XPF_BASE_RELEASE to pin one)")
   142	    return rels[-1]
   143	
   144	
   145	def sha256(path):
   146	    import hashlib
   147	    h = hashlib.sha256()
   148	    with open(path, "rb") as f:
   149	        for chunk in iter(lambda: f.read(1 << 20), b""):
   150	            h.update(chunk)
   151	    return h.hexdigest()
   152	
   153	
   154	def fetch_base(cache_dir, work_dir):
   155	    releases_url = os.environ.get("XPF_UBUNTU_RELEASES_URL",
   156	                                  "https://cloud-images.ubuntu.com/releases")
   157	    rel = discover_base_release()
   158	    base_url = os.environ.get("XPF_BASE_URL", f"{releases_url}/{rel}/release")
   159	    img = f"ubuntu-{rel}-server-cloudimg-amd64.img"
   160	    info(f"fetching Ubuntu {rel} server cloud image base ({base_url})")
   161	    cached = os.path.join(cache_dir, img)
   162	    if not os.path.isfile(cached):
   163	        run(["curl", "-fsSL", "-o", cached + ".tmp", f"{base_url}/{img}"])
   164	        os.replace(cached + ".tmp", cached)
   165	    # Re-verify the cache against the upstream checksum (cache not trusted).
   166	    sums = os.path.join(work_dir, "SHA256SUMS.upstream")
   167	    run(["curl", "-fsSL", "-o", sums, f"{base_url}/SHA256SUMS"])
   168	    expected = None
   169	    with open(sums) as f:
   170	        for line in f:
   171	            parts = line.split()
   172	            if len(parts) == 2 and parts[1].lstrip("*") == img:
   173	                expected = parts[0]
   174	                break
   175	    if not expected:
   176	        die(f"no SHA256 for {img} in upstream SHA256SUMS")
   177	    actual = sha256(cached)
   178	    if expected != actual:
   179	        os.remove(cached)
   180	        die("base image SHA256 mismatch (cache removed — re-run)")
   181	    info("base image checksum verified.")
   182	    return rel, base_url, img, cached, actual
   183	
   184	
   185	def virt_customize(work_qcow, xpf_deb):
   186	    pkgs = " ".join(RUNTIME_PACKAGES)
   187	    deb_name = os.path.basename(xpf_deb)
   188	    argv = [
   189	        "virt-customize", "-a", work_qcow, "--smp", "4", "--memsize", "2048",
   190	        "--hostname", "xpf",
   191	        # #1917 increment A: install xpf via the .deb instead of copying raw
   192	        # binaries. The package stages the binary set under
   193	        # /usr/local/share/xpf/staged, creates the live /usr/local/sbin
   194	        # symlinks, and enables xpfd + xpf-day0-config in its postinst — so
   195	        # the bake no longer hand-copies binaries/units or runs `systemctl
   196	        # enable xpfd`. The git-tracked, kernel-verified shim travels
   197	        # embedded inside the staged xpfd binary (#1864 contract preserved).
   198	        "--copy-in", f"{xpf_deb}:/var/tmp",
   199	        "--copy-in", f"{HERE}/incus-agent.service:/usr/lib/systemd/system",
   200	        "--copy-in", f"{HERE}/incus-agent-setup:/usr/lib/systemd",
   201	        "--copy-in", f"{HERE}/99-incus-agent.rules:/usr/lib/udev/rules.d",
   202	        "--run-command", "chmod 0755 /usr/lib/systemd/incus-agent-setup",
   203	        "--write", f"/etc/sysctl.d/99-xpf.conf:{SYSCTL_CONF}",
   204	        "--run-command", "mkdir -p /etc/xpf && chmod 0750 /etc/xpf",
   205	        "--run-command", f"export DEBIAN_FRONTEND=noninteractive && {APT_UPDATE}",
   206	        "--run-command", f"export DEBIAN_FRONTEND=noninteractive && "
   207	                         f"apt-get install -y -qq -o Acquire::Retries=5 {pkgs}",
   208	        "--run-command", "export DEBIAN_FRONTEND=noninteractive && "
   209	                         "apt-get install -y -qq -o Acquire::Retries=5 linux-generic",
   210	        "--run-command",
   211	        'latest=$(ls /lib/modules | sort -V | tail -1) && case "$latest" in [0-9]*) ;; '
   212	        '*) echo "FATAL: non-kernel entry $latest in /lib/modules" >&2; exit 1 ;; esac && '
   213	        'dpkg --compare-versions "${latest%%-*}" ge 6.18 || '
   214	        '{ echo "FATAL: newest installed kernel $latest < 6.18 (verifier floor)" >&2; exit 1; }',
   215	        "--run-command",
   216	        'test -d "/lib/modules/$(ls /lib/modules | sort -V | tail -1)/kernel/drivers/net/ethernet/mellanox" || '
   217	        '{ echo "FATAL: linux-modules-extra missing (mlx5/i40e)" >&2; exit 1; }',
   218	        "--run-command", "export DEBIAN_FRONTEND=noninteractive && apt-get purge -y -qq "
   219	                         "linux-virtual linux-image-virtual linux-headers-virtual 2>/dev/null || true",
   220	        # Ship EXACTLY ONE kernel. Ubuntu 26.04's cloudimg already runs a
   221	        # -generic kernel, so `apt install linux-generic` pulls a NEWER
   222	        # point release (e.g. 7.0.0-22 over the stock 7.0.0-15) and leaves
   223	        # the original — across packages a narrow name regex misses
   224	        # (linux-main-modules-zfs-<ver>, linux-headers-<ver>, …) AND
   225	        # depmod-generated files dpkg doesn't own. So for every non-newest
   226	        # version: purge ALL its packages via an apt glob, then rm -rf the
   227	        # leftover module dir + its /boot files. update-grub (below)
   228	        # regenerates the menu. Then HARD-ASSERT one kernel remains — the
   229	        # bake must catch this itself, not only the boot validation
   230	        # (this assert caught a real 2-kernel image during #1879 live bake).
   231	        "--run-command",
   232	        'export DEBIAN_FRONTEND=noninteractive; newest=$(ls /lib/modules | sort -V | tail -1); '
   233	        'for v in $(ls /lib/modules | grep -vxF "$newest"); do '
   234	        'apt-get purge -y -qq "linux-*$v*" 2>/dev/null || true; '
   235	        'rm -rf "/lib/modules/$v" /boot/*"$v"*; done; '
   236	        'apt-get autoremove --purge -y -qq 2>/dev/null || true; true',
   237	        "--run-command",
   238	        'n=$(ls /lib/modules | wc -l); [ "$n" -eq 1 ] || '
   239	        '{ echo "FATAL: $n kernels in /lib/modules after purge ($(ls /lib/modules | tr "\\n" " "))" >&2; exit 1; }',
   240	        "--run-command", "export DEBIAN_FRONTEND=noninteractive && apt-get purge -y -qq snapd "
   241	                         "2>/dev/null || true; rm -rf /snap /var/snap /var/lib/snapd /var/cache/snapd",
   242	        "--run-command", 'export DEBIAN_FRONTEND=noninteractive && apt-get purge -y -qq "cloud-init*" '
   243	                         "2>/dev/null || true; rm -rf /etc/cloud /var/lib/cloud",
   244	        "--run-command", "rm -f /etc/network/interfaces.d/* /etc/netplan/*.yaml 2>/dev/null || true",
   245	        "--run-command", f"export DEBIAN_FRONTEND=noninteractive && apt-get autoremove -y -qq && "
   246	                         f"{{ {APT_UPDATE}; }}",
   247	        "--run-command", "systemctl enable systemd-networkd systemd-resolved",
   248	        "--run-command", "systemctl disable systemd-networkd-wait-online.service 2>/dev/null || true",
   249	        "--run-command", "ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf",
   250	        "--run-command", "systemctl enable frr chrony",
   251	        "--run-command", 'sed -i "s/^pool /#pool /; s/^server /#server /" /etc/chrony/chrony.conf '
   252	                         "&& mkdir -p /etc/chrony/sources.d",
   253	        # Install the xpf .deb. apt resolves the package's deps (adduser,
   254	        # present) from the local file. The postinst stages the binaries,
   255	        # creates the /usr/local/sbin symlinks, and enables xpfd +
   256	        # xpf-day0-config — so there is no separate `systemctl enable xpfd`
   257	        # here. systemd is not running under virt-customize, so the
   258	        # postinst's deb-systemd-invoke start is a harmless no-op (the units
   259	        # are enabled and start on the real first boot). The xpfd version
   260	        # check below confirms the symlink resolves the staged binary.
   261	        "--run-command", "export DEBIAN_FRONTEND=noninteractive && "
   262	                         f"apt-get install -y -qq -o Acquire::Retries=5 /var/tmp/{deb_name} && "
   263	                         f"rm -f /var/tmp/{deb_name}",
   264	        "--write", f"/etc/default/grub.d/99-xpf.cfg:{GRUB_DROPIN}",
   265	        "--run-command", "update-grub",
   266	        "--write", f"/etc/ssh/sshd_config.d/10-xpf-factory.conf:{SSHD_DROPIN}",
   267	        "--run-command", "passwd -d root",
   268	        "--run-command", "/usr/local/sbin/xpfd version",
   269	    ]
   270	    run(argv)
   271	
   272	
   273	def main():
   274	    p = argparse.ArgumentParser(description=__doc__,
   275	                                formatter_class=argparse.RawDescriptionHelpFormatter)
   276	    p.add_argument("--version", default=git_version())
   277	    p.add_argument("--out", default=os.path.join(ROOT, "dist"))
   278	    p.add_argument("--skip-build", action="store_true")
   279	    p.add_argument("--skip-validate", action="store_true")
   280	    p.add_argument("--keep-work", action="store_true")
   281	    a = p.parse_args()
   282	
   283	    for t, hint in [("qemu-img", "apt-get install qemu-utils"),
   284	                    ("virt-customize", "apt-get install libguestfs-tools"),
   285	                    ("virt-resize", "apt-get install libguestfs-tools"),
   286	                    ("virt-sysprep", "apt-get install libguestfs-tools"),
   287	                    ("virt-sparsify", "apt-get install libguestfs-tools"),
   288	                    ("virt-filesystems", "apt-get install libguestfs-tools"),
   289	                    ("curl", "apt-get install curl")]:
   290	        require(t, hint)
   291	    if not (os.access("/dev/kvm", os.R_OK) and os.access("/dev/kvm", os.W_OK)):
   292	        print("WARNING: no /dev/kvm access — libguestfs will use TCG (slow).", file=sys.stderr)
   293	    ensure_memlock()
   294	
   295	    cache_dir = os.path.join(os.environ.get("XDG_CACHE_HOME",
   296	                             os.path.expanduser("~/.cache")), "xpf-image-bake")
   297	    os.makedirs(a.out, exist_ok=True)
   298	    os.makedirs(cache_dir, exist_ok=True)
   299	    work = tempfile.mkdtemp(prefix="xpf-bake-", dir=os.environ.get("TMPDIR", "/tmp"))
   300	
   301	    import glob
   302	    try:
   303	        # 1. build the xpf .deb (#1917 increment A). `make deb` runs
   304	        #    `make build build-ctl build-userspace-dp` via debian/rules, so
   305	        #    it picks up the embedded #1864 shim and the pinned cargo helper,
   306	        #    then packages the freshly-built binaries. The image consumes the
   307	        #    .deb instead of raw --copy-in binaries.
   308	        deb_dir = os.path.join(ROOT, "dist", "deb")
   309	        if not a.skip_build:
   310	            info("building xpf .deb (xpfd, cli, xpf-userspace-dp -> staged)...")
   311	            run(["make", "-C", ROOT, "deb"])
   312	        # The git-derived version is computed by the Makefile; glob for the
   313	        # binary package (NOT the xpf-appliance metapackage) and pick the
   314	        # NEWEST by mtime so a stale deb from an earlier (e.g. dirty-tree)
   315	        # build in dist/deb/ is never selected over the one just built.
   316	        debs = sorted((g for g in glob.glob(os.path.join(deb_dir, "xpf_*.deb"))
   317	                       if "xpf-appliance" not in os.path.basename(g)),
   318	                      key=os.path.getmtime)
   319	        if not debs:
   320	            die(f"no xpf_*.deb in {deb_dir} (run without --skip-build, or run `make deb`)")
   321	        xpf_deb = debs[-1]
   322	        info(f"using package: {xpf_deb}")
   323	        # build-host pre-gate (best-effort): verify the embedded shim against
   324	        # the build-host kernel before baking it in (#1864). Verify the xpfd
   325	        # that is ACTUALLY IN THE SELECTED .deb (extracted from the staging
   326	        # path), not ROOT/xpfd — under --skip-build those can diverge (a
   327	        # stale loose ROOT/xpfd next to a newer packaged binary), and the
   328	        # one that ships is the packaged one.
   329	        staged_xpfd = os.path.join(work, "pregate", "usr", "local",
   330	                                   "share", "xpf", "staged", "xpfd")
   331	        run(["dpkg-deb", "-x", xpf_deb, os.path.join(work, "pregate")])
   332	        if not os.access(staged_xpfd, os.X_OK):
   333	            die(f"package {xpf_deb} does not contain an executable staged xpfd")
   334	        if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
   335	            info(f"build-host pre-gate: packaged xpfd verify-dataplane "
   336	                 f"(host kernel {os.uname().release})...")
   337	            if subprocess.run(["sudo", "-n", "nice", "-n", "19",
   338	                               staged_xpfd, "verify-dataplane"]).returncode != 0:
   339	                die("embedded shim REJECTED by the build-host kernel verifier (#1864)")
   340	        else:
   341	            print("NOTE: no passwordless sudo — skipping build-host verify pre-gate "
   342	                  "(in-guest gate still enforces).", file=sys.stderr)
   343	
   344	        # 2. base
   345	        rel, base_url, base_img, cached, base_sha = fetch_base(cache_dir, work)
   346	
   347	        # 3. resize
   348	        disk = os.environ.get("XPF_IMAGE_DISK_SIZE", "8G")
   349	        info(f"creating {disk} work disk + expanding root partition...")
   350	        fs = out_text(["virt-filesystems", "-a", cached, "--filesystems", "--long", "--no-title"])
   351	        root_part = next((ln.split()[0] for ln in fs.splitlines()
   352	                          if len(ln.split()) >= 3 and ln.split()[2] == "ext4"), None)
   353	        if not root_part:
   354	            die("could not locate the ext4 root partition in the base image")
   355	        work_qcow = os.path.join(work, "work.qcow2")
   356	        run(["qemu-img", "create", "-f", "qcow2", "-o", "preallocation=off", work_qcow, disk],
   357	            stdout=subprocess.DEVNULL)
   358	        run(["virt-resize", "--quiet", "--expand", root_part, cached, work_qcow])
   359	
   360	        # 4. customize
   361	        info("customizing image offline (packages, kernel >= 6.18, xpf install)...")
   362	        virt_customize(work_qcow, xpf_deb)
   363	
   364	        # 5. seal
   365	        info("sealing image (virt-sysprep)...")
   366	        run(["virt-sysprep", "-a", work_qcow, "--quiet", "--enable",
   367	             "machine-id,ssh-hostkeys,ssh-userdir,logfiles,tmp-files,bash-history,"
   368	             "package-manager-cache,backup-files,passwd-backups,utmp",
   369	             "--run-command", "rm -rf /etc/xpf/.configdb /etc/xpf/xpf.conf "
   370	             "/etc/xpf/.day0-config-applied /var/lib/systemd/random-seed "
   371	             "/var/lib/apt/lists/* 2>/dev/null || true"])
   372	
   373	        # 6. export
   374	        ver = a.version
   375	        qcow_out = os.path.join(a.out, f"xpf-{ver}.qcow2")
   376	        meta_out = os.path.join(a.out, f"xpf-{ver}.incus-metadata.tar.gz")
   377	        info(f"exporting {qcow_out} (sparsified + compressed qcow2)...")
   378	        run(["virt-sparsify", "--quiet", "--tmp", work, "--compress", work_qcow, qcow_out])
   379	
   380	        info(f"exporting {meta_out} (incus VM image metadata)...")
   381	        meta = os.path.join(work, "metadata.yaml")
   382	        with open(meta, "w") as f:
   383	            f.write("architecture: x86_64\n"
   384	                    f"creation_date: {int(time.time())}\n"
   385	                    "properties:\n"
   386	                    f"  description: xpf appliance {ver} (Ubuntu {rel}, kernel >= 6.18, "
   387	                    "AF_XDP userspace dataplane)\n"
   388	                    "  os: Ubuntu\n"
   389	                    f"  release: {rel}\n"
   390	                    "  variant: xpf-appliance\n")
   391	        run(["tar", "-C", work, "-czf", meta_out, "metadata.yaml"])
   392	
   393	        sums = os.path.join(a.out, "SHA256SUMS")
   394	        with open(sums, "w") as f:
   395	            for path in (qcow_out, meta_out):
   396	                f.write(f"{sha256(path)}  {os.path.basename(path)}\n")
   397	        info("checksums:")
   398	        print(open(sums).read(), end="")
   399	
   400	        try:
   401	            commit = out_text(["git", "-C", ROOT, "rev-parse", "HEAD"]).strip()
   402	        except Exception:
   403	            commit = "unknown"
   404	        manifest = os.path.join(a.out, f"xpf-{ver}.manifest")
   405	        with open(manifest, "w") as f:
   406	            f.write(f"version: {ver}\ngit_commit: {commit}\n"
   407	                    f"base_image: {base_url}/{base_img}\nbase_release: {rel}\n"
   408	                    f"base_image_sha256: {base_sha}\n"
   409	                    f"bake_date: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
   410	                    f"bake_host_kernel: {os.uname().release}\n")
   411	        info(f"manifest: {manifest}")
   412	
   413	        # 7. validation gate
   414	        if a.skip_validate:
   415	            print("WARNING: --skip-validate — artifacts have NOT passed the in-guest "
   416	                  "verify-dataplane gate; do not publish them.", file=sys.stderr)
   417	        else:
   418	            info("running validation gate (factory boot + in-guest verify-dataplane + "
   419	                 "valid/invalid day-0 drives)...")
   420	            if subprocess.run([sys.executable, os.path.join(HERE, "validate.py"),
   421	                               "--qcow2", qcow_out, "--metadata", meta_out, "all"]).returncode != 0:
   422	                die(f"validation gate FAILED — artifacts in {a.out} are NOT publishable")
   423	
   424	        info(f"bake complete: {qcow_out}")
   425	        info("deploy quickstarts: docs/install-images.md")
   426	        return 0
   427	    finally:
   428	        if a.keep_work:
   429	            print(f"keeping work dir: {work}")
   430	        else:
   431	            shutil.rmtree(work, ignore_errors=True)
   432	
   433	
   434	if __name__ == "__main__":
   435	    sys.exit(main())

codex
The plan is unusually explicit about trust roots, but I’m going to check whether the recommendation survives the actual artifact shapes and install paths in this repo, not just the prose. Next pass is packaging and docs.
exec
/bin/bash -lc 'nl -ba scripts/image/validate.py' in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
exec
/bin/bash -lc 'nl -ba docs/install-images.md' in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
     1	# xpf appliance images (#1879 Path C)
     2	
     3	vSRX-style prebuilt-image distribution: one bootable root disk, built
     4	offline, carrying everything xpf needs — the LATEST Ubuntu release
     5	(operator policy: always the newest — 26.04 today, discovered at bake
     6	time), a >= 6.18 kernel (the AF_XDP shim's verifier floor; 26.04 ships
     7	7.0), FRR, strongSwan, Kea, chrony, systemd-networkd, and the xpf
     8	binaries (`xpfd`, `cli`, `xpf-userspace-dp`) with their systemd units.
     9	There is no dependency matrix to install and no kernel hunt: the image
    10	IS the dependency closure.
    11	
    12	Two deliverables, same root disk:
    13	
    14	| Artifact | Consumer | Deploy command |
    15	|---|---|---|
    16	| `dist/xpf-<ver>.qcow2` | libvirt/KVM, plain QEMU | `virt-install --import --disk path=...` |
    17	| `dist/xpf-<ver>.incus-metadata.tar.gz` + the same qcow2 | incus (VM) | `incus image import <meta> <qcow2> --alias xpf-appliance` |
    18	| `dist/SHA256SUMS` | both | `sha256sum -c` |
    19	
    20	## Bake
    21	
    22	```bash
    23	make image            # = python3 scripts/image/bake.py
    24	```
    25	
    26	Build-host requirements: the normal xpf build toolchain (Go, cargo),
    27	`libguestfs-tools`, `qemu-utils`, `curl`, `xorriso` (for config
    28	drives), and incus for the validation gate. `/dev/kvm` access makes
    29	the bake fast; the script self-raises `RLIMIT_MEMLOCK` via sudo when
    30	needed (qemu's io_uring).
    31	
    32	Pipeline (offline — the image is never booted to provision it):
    33	
    34	1. `make deb` (#1917 increment A). This runs `make build build-ctl
    35	   build-userspace-dp` via `debian/rules`, so the #1864 pinned-toolchain
    36	   contract holds — `make build` embeds the git-tracked shim object and
    37	   the bake never runs `make generate` — then packages the freshly built
    38	   binaries into the `xpf` Debian package (binary set staged under
    39	   `/usr/local/share/xpf/staged`). The bake installs that `.deb` instead
    40	   of copying raw binaries.
    41	2. Discover the LATEST Ubuntu release from the upstream listing
    42	   (`XPF_BASE_RELEASE` pins one), then fetch + SHA256-verify the
    43	   official Ubuntu *server cloudimg*. Upstream owns partitioning and
    44	   the UEFI/BIOS bootloader.
    45	3. `virt-resize` the root partition into an 8 GiB work disk
    46	   (`XPF_IMAGE_DISK_SIZE` overrides).
    47	4. `virt-customize` offline: runtime package set (the #1879 plan §5
    48	   dependency matrix; no build toolchain), the cloudimg's reduced
    49	   `linux-virtual` kernel replaced by `linux-generic` (full driver set
    50	   — mlx5/i40e for passthrough NICs live in `linux-modules-extra`)
    51	   with in-bake asserts that the kernel meets the >= 6.18 verifier
    52	   floor and the extra-modules tree is present, purge of cloud-init
    53	   (a competing network manager), snapd, and the virtual-kernel
    54	   metapackages, systemd-networkd + resolved enabled, FRR + chrony
    55	   enabled (default NTP pools neutered; xpfd manages
    56	   `sources.d/xpf.sources`), sysctls, `init_on_alloc=0` (via an
    57	   `/etc/default/grub.d` drop-in — Ubuntu cloud images override
    58	   `GRUB_CMDLINE_LINUX_DEFAULT` there), and `apt-get install ./xpf.deb`.
    59	   The package's `postinst` stages the binary set, creates the live
    60	   `/usr/local/sbin/{xpfd,cli,xpf-userspace-dp,xpf-day0-config}` symlinks
    61	   into the staging path, and enables `xpfd` + `xpf-day0-config` (so the
    62	   bake no longer hand-copies binaries/units or runs `systemctl enable
    63	   xpfd`). The incus-agent loader is still copied in and enabled
    64	   directly. A plain `apt upgrade xpf` only refreshes the staging path
    65	   and never restarts xpfd (`dh_installsystemd --no-stop-on-upgrade` + a
    66	   `needrestart` blacklist); the verified in-place cut-over is a separate
    67	   increment.
    68	5. `virt-sysprep` seal: machine-id, ssh host keys, logs, tmp files,
    69	   bash history, package caches, random seed; `/etc/xpf` factory-empty.
    70	6. Export compressed qcow2 + incus metadata tarball + SHA256SUMS.
    71	7. **Validation gate** (default on): the image is imported into local
    72	   incus and the FULL first-boot matrix runs — factory boot (fxp0
    73	   DHCP, sshd posture via `sshd -T`, -generic kernel flavor + full
    74	   driver set check) with `xpfd verify-dataplane` IN-GUEST against
    75	   the image's own kernel, plus the valid- and invalid-day-0-drive
    76	   scenarios. A failure fails the bake — the image must never ship a
    77	   verifier-failing shim (#1864/#1869 discipline). Use
    78	   `--skip-validate` only for iteration; such artifacts are not
    79	   publishable.
    80	
    81	Each bake also writes `dist/xpf-<ver>.manifest` recording the exact
    82	inputs (base image URL + release + verified SHA256, git commit, bake
    83	date/host kernel). Bakes are not bit-reproducible (the base tracks
    84	the newest upstream release unless `XPF_BASE_RELEASE` pins one); the
    85	manifest is the traceability record.
    86	
    87	Full first-boot matrix (run after a bake, or standalone):
    88	
    89	```bash
    90	python3 scripts/image/validate.py --qcow2 dist/xpf-<ver>.qcow2 \
    91	    --metadata dist/xpf-<ver>.incus-metadata.tar.gz all
    92	```
    93	
    94	> **Deploying at scale?** `docs/deploy-quickstart.md` +
    95	> `examples/deploy/README.md` are the operator runbook: the positional
    96	> naming contract, the Python deployer (`scripts/deploy/xpf-deploy.py`
    97	> — YAML-driven, incus/libvirt, builds the day-0 drive in-process),
    98	> validated standalone/HA example definitions, SR-IOV/passthrough, and
    99	> the fleet pattern. The sections below are the raw mechanics it builds
   100	> on. (`scripts/image/make_config_drive.py` shown here is the image
   101	> bakery's config-drive tool; the Python deployer builds drives
   102	> in-process too.)
   103	
   104	## Deploy quickstart — incus
   105	
   106	```bash
   107	incus image import dist/xpf-<ver>.incus-metadata.tar.gz \
   108	    dist/xpf-<ver>.qcow2 --alias xpf-appliance
   109	
   110	# Optional day-0 config drive (see below):
   111	python3 scripts/image/make_config_drive.py -o day0.iso my-xpf.conf
   112	
   113	incus init xpf-appliance xpf1 --vm -c limits.cpu=4 -c limits.memory=4GiB
   114	incus config device add xpf1 day0 disk source=$PWD/day0.iso
   115	incus start xpf1
   116	```
   117	
   118	The image carries the incus-agent loader (inert outside incus), so
   119	`incus exec xpf1 -- cli` works immediately. Add revenue NICs as extra
   120	devices before start; vNIC order maps to vSRX names (below).
   121	
   122	## Deploy quickstart — libvirt/KVM
   123	
   124	```bash
   125	virt-install --name xpf1 --memory 4096 --vcpus 4 \
   126	    --import --disk path=xpf-<ver>.qcow2 \
   127	    --disk path=day0.iso,device=cdrom \
   128	    --network bridge=br-mgmt --network bridge=br-trust \
   129	    --osinfo ubuntu26.04 --noautoconsole
   130	```
   131	
   132	Plain QEMU works the same way (`-drive file=xpf-<ver>.qcow2`
   133	`-cdrom day0.iso`); the image boots UEFI or BIOS.
   134	
   135	## First-boot contract (vSRX parity)
   136	
   137	| vSRX | xpf image |
   138	|---|---|
   139	| First vNIC is fxp0 (OOB mgmt), rest map to ge-0/0/N in attach order | Identical: `enumerateAndRenameInterfaces()` assigns fxp0 / em0 (cluster) / ge-X-0-N by PCI bus order |
   140	| Factory default: fxp0 DHCP, root console login, no password | Identical: fxp0 DHCP bootstrap; root login on the hypervisor console with empty password; sshd refuses empty/root-password auth |
   141	| Day-0 config: ISO with `juniper.conf` at the root, attached as CD-ROM | ISO (or any volume labeled `xpf-config`) with `xpf.conf` at the root — `juniper.conf` accepted as an alias; optional `node-id` file (`0`/`1`) for cluster members |
   142	| Bad day-0 config: boots factory-default | Identical, but stricter: the config is validated with the REAL commit-check gate (`xpfd check-config`) BEFORE install; a REJECT logs loudly and the system stays factory-default |
   143	| Day-0 applied once | Applied at most once: stamped after success; never clobbers an existing config (`.configdb` or preseeded `xpf.conf`). A REJECTED medium does not stamp — fix the config and reboot to retry while the system is still factory-default |
   144	
   145	Day-0 loader specifics (`scripts/image/xpf-day0-config`, oneshot unit
   146	`Before=xpfd.service`):
   147	
   148	- Probes volumes labeled `xpf-config` (any filesystem) plus any ISO9660
   149	  medium. Mounted `ro,nosuid,nodev,noexec`; only the two fixed
   150	  filenames at the volume root are considered; 4 MiB size cap;
   151	  validation under timeout. Nothing on the medium is executed.
   152	- On PASS the config is installed as `/etc/xpf/xpf.conf` (mode 0600 —
   153	  it may carry credential material) and xpfd's normal
   154	  bootstrap-from-file import commits it at startup. No second config
   155	  ingestion mechanism exists.
   156	- Failures never block the boot: the unit is ordering-only (no
   157	  `Requires=`), the script always exits 0, and `TimeoutStartSec`
   158	  backstops a hung mount. Fallback is always the factory bootstrap.
   159	
   160	Build a config drive:
   161	
   162	```bash
   163	python3 scripts/image/make_config_drive.py [-n 0|1] [-o day0.iso] my-xpf.conf
   164	```
   165	
   166	When an `xpfd` binary is present, the builder runs the same
   167	commit-check and refuses to build an ISO the appliance would reject.
   168	
   169	## Credentials / security posture
   170	
   171	- No default password over the network, ever. The root password is
   172	  empty: login works on the hypervisor console only. The image pins
   173	  this explicitly — `/etc/ssh/sshd_config.d/10-xpf-factory.conf` sets
   174	  `PermitRootLogin prohibit-password` + `PermitEmptyPasswords no`
   175	  (not relying on distro defaults), and the validation harness
   176	  asserts the effective `sshd -T` output.
   177	- Headless/SSH access comes from the day-0 config (`system
   178	  root-authentication`, `system login user ...`) — set credentials
   179	  there, or use the console once and `commit` a config.
   180	- The image ships no ssh host keys, no machine-id, no logs; both are
   181	  regenerated per-instance at first boot.
   182	- Verify artifacts with `sha256sum -c dist/SHA256SUMS`. (Detached
   183	  signing — minisign — is a follow-up; see the #1879 deferred list.)
   184	
   185	## Upgrades
   186	
   187	The vSRX "replace-image" model: deploy a new VM from the new image,
   188	copy `/etc/xpf/xpf.conf` (+ `/etc/xpf/node-id` on cluster members),
   189	swap traffic. The text config is the portable artifact — not
   190	`.configdb`. For HA pairs this is `deploy_rolling()` at VM granularity:
   191	replace the secondary, wait for session sync, fail over, replace the
   192	primary. Kernel + userspace move as one tested unit.
   193	
   194	In-place binary upgrades inside a running appliance follow the #1869
   195	ordering invariant: push the new `xpfd` to a temp path, run
   196	`xpfd verify-dataplane` there FIRST, and only on PASS stop/replace
   197	(see `test/incus/cluster-setup.sh deploy_vm()` for the reference
   198	implementation). A native .deb + `xpf-upgrade` wrapper is the M1a
   199	follow-up, not part of this deliverable.
   200	
   201	## Recovery
   202	
   203	- Lost mgmt connectivity after a bad commit: use the hypervisor
   204	  console (`incus console xpf1` / `virsh console xpf1`), log in as
   205	  root, run `cli`, `configure`, `rollback 1`, `commit`.
   206	- Unbootable/maimed instance: this is cattle — redeploy from the image
   207	  and re-apply your config (day-0 drive or copy `xpf.conf` in).
   208	- Day-0 config rejected at first boot: `journalctl -u xpf-day0-config`
   209	  shows the commit-check error verbatim. Fix the config, rebuild the
   210	  ISO, reboot — the system is still factory-default, so the loader
   211	  retries.
   212	- Pre-flight any config on the build host:
   213	  `xpfd check-config [-node-id 0|1] my-xpf.conf` (exit 0 PASS / 2
   214	  reject).
   215	
   216	## Validation
   217	
   218	`docs/image-validation.md` is the full validation runbook: Tier 1
   219	(automated first-boot gate via `scripts/image/validate.py` — boot,
   220	single ≥6.18 kernel, in-guest `verify-dataplane`, day-0 valid/invalid),
   221	Tier 2 (standalone forwarding + SNAT, manual), and Tier 3 (HA pair
   222	forwarding + failover, manual). Tier 1 gates the bake; Tiers 2–3 push
   223	real traffic and prove the image actually routes.
   224	
   225	## What the image does NOT solve
   226	
   227	AF_XDP line-rate behavior remains coupled to the NIC driver exposed to
   228	the VM (mlx5/i40e native XDP vs virtio vs iavf-generic) — see
   229	`CLAUDE.md` "XDP on SR-IOV Interfaces". The image guarantees the
   230	kernel side (>= 6.18, verifier-passing shim, `init_on_alloc=0`);
   231	passthrough/VF topology is the operator's hypervisor decision.

 succeeded in 0ms:
     1	#!/usr/bin/env python3
     2	"""xpf appliance image validation (#1879 Path C), in Python.
     3	
     4	Boots the baked artifacts under LOCAL incus (instances xpf-image-* —
     5	never the shared loss cluster) and proves the first-boot contract:
     6	
     7	  a  no config drive  -> factory bootstrap: boots, xpfd active, fxp0 DHCP,
     8	     sshd listening, AND in-guest `xpfd verify-dataplane` PASSES against
     9	     the image's own kernel (the bake gate).
    10	  b  valid day-0 drive -> config validated + installed + committed at first
    11	     boot (hostname applied); a reboot does NOT re-apply (stamp).
    12	  c  invalid day-0 drive -> commit-check REJECT logged, nothing installed,
    13	     boot survives, factory bootstrap still reachable.
    14	
    15	Usage:
    16	  validate.py --qcow2 <img> --metadata <tar.gz> [a|b|c|all]
    17	"""
    18	
    19	import argparse
    20	import os
    21	import shlex
    22	import subprocess
    23	import sys
    24	import tempfile
    25	import time
    26	
    27	HERE = os.path.dirname(os.path.abspath(__file__))
    28	sys.path.insert(0, HERE)
    29	import make_config_drive  # noqa: E402
    30	
    31	ALIAS = "xpf-image-validate"
    32	
    33	
    34	def info(m):
    35	    print(f"==> {m}")
    36	
    37	
    38	def fail(m):
    39	    print(f"FAIL: {m}", file=sys.stderr)
    40	    sys.exit(1)
    41	
    42	
    43	def incus(*args, check=True, capture=False):
    44	    return subprocess.run(["incus", *args], check=check,
    45	                          capture_output=capture, text=True)
    46	
    47	
    48	def guest(inst, *cmd, check=True, capture=False):
    49	    return subprocess.run(["incus", "exec", inst, "--", *cmd],
    50	                          check=check, capture_output=capture, text=True)
    51	
    52	
    53	def guest_sh(inst, script):
    54	    """Run a shell snippet in the guest; return True on exit 0."""
    55	    return subprocess.run(["incus", "exec", inst, "--", "sh", "-c", script],
    56	                          capture_output=True, text=True).returncode == 0
    57	
    58	
    59	class Harness:
    60	    def __init__(self, qcow2, metadata, net, keep):
    61	        self.qcow2, self.metadata, self.net, self.keep = qcow2, metadata, net, keep
    62	        self.created_net = False
    63	        self.instances = []
    64	        self.work = tempfile.mkdtemp(prefix="xpf-validate-")
    65	
    66	    # ── lifecycle ──
    67	    def ensure_network(self):
    68	        if incus("network", "show", self.net, check=False, capture=True).returncode != 0:
    69	            info(f"creating validation network {self.net} (NAT + DHCP)")
    70	            incus("network", "create", self.net, "ipv4.address=10.199.99.1/24",
    71	                  "ipv4.nat=true", "ipv6.address=none")
    72	            self.created_net = True
    73	
    74	    def import_image(self):
    75	        incus("image", "delete", ALIAS, check=False, capture=True)
    76	        info(f"importing image into local incus as {ALIAS}")
    77	        incus("image", "import", self.metadata, self.qcow2, "--alias", ALIAS)
    78	
    79	    def launch(self, name, iso=None):
    80	        incus("delete", "-f", name, check=False, capture=True)
    81	        incus("init", ALIAS, name, "--vm", "--network", self.net,
    82	              "-c", "limits.cpu=2", "-c", "limits.memory=2GiB", capture=True)
    83	        if iso:
    84	            incus("config", "device", "add", name, "day0", "disk",
    85	                  f"source={os.path.realpath(iso)}", capture=True)
    86	        self.instances.append(name)
    87	        incus("start", name)
    88	        self.wait_agent(name)
    89	
    90	    def drop(self, name):
    91	        if not self.keep:
    92	            incus("delete", "-f", name, check=False, capture=True)
    93	            if name in self.instances:
    94	                self.instances.remove(name)
    95	
    96	    def cleanup(self):
    97	        if self.keep:
    98	            print(f"keeping instances {self.instances}, alias {ALIAS}, network {self.net}")
    99	        else:
   100	            for i in self.instances:
   101	                incus("delete", "-f", i, check=False, capture=True)
   102	            incus("image", "delete", ALIAS, check=False, capture=True)
   103	            if self.created_net:
   104	                incus("network", "delete", self.net, check=False, capture=True)
   105	        subprocess.run(["rm", "-rf", self.work], check=False)
   106	
   107	    # ── waiters ──
   108	    def _wait(self, name, pred, tries, secs, what):
   109	        for _ in range(tries):
   110	            if pred():
   111	                return
   112	            time.sleep(secs)
   113	        fail(f"{name}: {what}")
   114	
   115	    def wait_agent(self, name):
   116	        self._wait(name, lambda: guest(name, "true", check=False, capture=True).returncode == 0,
   117	                   80, 3, "incus agent not ready after 240s")
   118	
   119	    def wait_xpfd(self, name):
   120	        self._wait(name, lambda: guest(name, "systemctl", "is-active", "--quiet", "xpfd",
   121	                                       check=False, capture=True).returncode == 0,
   122	                   40, 3, "xpfd not active after 120s")
   123	
   124	    def wait_fxp0_dhcp(self, name):
   125	        self._wait(name, lambda: guest_sh(name, 'ip -4 addr show fxp0 2>/dev/null | grep -q "inet "'),
   126	                   30, 3, "fxp0 has no IPv4 DHCP address after 90s")
   127	
   128	    # ── scenarios ──
   129	    def scenario_a(self):
   130	        info("── Scenario A: first boot, NO config drive ──")
   131	        self.launch("xpf-image-a")
   132	        self.wait_xpfd("xpf-image-a")
   133	        kver = guest("xpf-image-a", "uname", "-r", capture=True).stdout.strip()
   134	        info(f"guest kernel: {kver}")
   135	        rel = kver.split("-")[0]
   136	        if not _kver_ge(rel, (6, 18)):
   137	            fail(f"guest kernel {kver} < 6.18")
   138	        if not guest_sh("xpf-image-a", 'uname -r | grep -q -- -generic'):
   139	            fail("running kernel is not the -generic flavor")
   140	        if not guest_sh("xpf-image-a", 'test -d "/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/mellanox"'):
   141	            fail("linux-modules-extra (mlx5/i40e driver set) missing")
   142	        if not guest_sh("xpf-image-a", '[ "$(ls /lib/modules | wc -l)" -eq 1 ]'):
   143	            fail("more than one kernel in /lib/modules — stale cloudimg kernel not purged")
   144	        if not guest_sh("xpf-image-a", 'grep -qw init_on_alloc=0 /proc/cmdline'):
   145	            fail("init_on_alloc=0 missing from the booted kernel cmdline")
   146	        info("in-guest verify-dataplane (the bake gate, image kernel)...")
   147	        if guest("xpf-image-a", "nice", "-n", "19", "/usr/local/sbin/xpfd", "verify-dataplane",
   148	                 check=False).returncode != 0:
   149	            fail("in-guest verify-dataplane REJECTED — image must not ship")
   150	        self.wait_fxp0_dhcp("xpf-image-a")
   151	        if not guest_sh("xpf-image-a", 'ss -tln | grep -q ":22 "'):
   152	            fail("sshd not listening")
   153	        if not guest_sh("xpf-image-a",
   154	                        '/usr/sbin/sshd -T | grep -qxE "permitrootlogin (prohibit-password|without-password|no)"'):
   155	            fail("sshd effective config does not refuse root password auth")
   156	        if not guest_sh("xpf-image-a", '/usr/sbin/sshd -T | grep -qx "permitemptypasswords no"'):
   157	            fail("sshd effective config does not pin PermitEmptyPasswords no")
   158	        if guest("xpf-image-a", "test", "-e", "/etc/xpf/xpf.conf", check=False).returncode == 0:
   159	            fail("unexpected /etc/xpf/xpf.conf")
   160	        if guest("xpf-image-a", "test", "-e", "/etc/xpf/.day0-config-applied", check=False).returncode == 0:
   161	            fail("unexpected day-0 stamp")
   162	        if not guest_sh("xpf-image-a",
   163	                        'journalctl -u xpf-day0-config -b --no-pager | grep -q "no config medium found"'):
   164	            fail("day-0 loader did not log the no-medium fallback")
   165	        info("Scenario A PASS")
   166	        self.drop("xpf-image-a")
   167	
   168	    def scenario_b(self):
   169	        info("── Scenario B: first boot WITH valid day-0 config drive ──")
   170	        conf = os.path.join(self.work, "day0-valid.conf")
   171	        with open(conf, "w") as f:
   172	            f.write("system {\n    host-name xpf-day0-b;\n}\n"
   173	                    "interfaces {\n    fxp0 {\n        unit 0 {\n"
   174	                    "            family inet {\n                dhcp;\n"
   175	                    "            }\n        }\n    }\n}\n")
   176	        iso = make_config_drive.build_config_drive(conf, os.path.join(self.work, "day0-valid.iso"),
   177	                                                   validate=False)
   178	        self.launch("xpf-image-b", iso)
   179	        self.wait_xpfd("xpf-image-b")
   180	        if guest("xpf-image-b", "test", "-e", "/etc/xpf/.day0-config-applied", check=False).returncode != 0:
   181	            fail("day-0 stamp missing")
   182	        if guest("xpf-image-b", "test", "-s", "/etc/xpf/xpf.conf", check=False).returncode != 0:
   183	            fail("/etc/xpf/xpf.conf missing")
   184	        if not guest_sh("xpf-image-b",
   185	                        'journalctl -u xpf-day0-config -b --no-pager | grep -q "day-0 config installed"'):
   186	            fail("day-0 loader did not log the install")
   187	        self._wait("xpf-image-b",
   188	                   lambda: guest_sh("xpf-image-b",
   189	                                    'echo "show configuration" | /usr/local/sbin/cli 2>/dev/null '
   190	                                    '| grep -q "host-name xpf-day0-b"'),
   191	                   20, 3, "committed config does not show host-name xpf-day0-b")
   192	        if not guest_sh("xpf-image-b", '[ "$(hostname)" = xpf-day0-b ]'):
   193	            fail("hostname not applied")
   194	        info("rebooting xpf-image-b — second boot must NOT re-apply...")
   195	        incus("restart", "xpf-image-b")
   196	        self.wait_agent("xpf-image-b")
   197	        self.wait_xpfd("xpf-image-b")
   198	        if not guest_sh("xpf-image-b",
   199	                        '! journalctl -u xpf-day0-config -b --no-pager | grep -q "day-0 config installed"'):
   200	            fail("second boot re-applied the day-0 config")
   201	        if not guest_sh("xpf-image-b",
   202	                        'systemctl show -p ConditionResult xpf-day0-config | grep -q "ConditionResult=no" '
   203	                        '|| journalctl -u xpf-day0-config -b --no-pager | grep -q "already applied"'):
   204	            fail("second boot: day-0 loader neither condition-skipped nor stamp-skipped")
   205	        info("Scenario B PASS")
   206	        self.drop("xpf-image-b")
   207	
   208	    def scenario_c(self):
   209	        info("── Scenario C: first boot WITH INVALID day-0 config drive ──")
   210	        conf = os.path.join(self.work, "day0-invalid.conf")
   211	        with open(conf, "w") as f:
   212	            f.write("system {\n    host-name xpf-day0-c;\n    dataplane-type ebpf;\n}\n")
   213	        iso = make_config_drive.build_config_drive(conf, os.path.join(self.work, "day0-invalid.iso"),
   214	                                                   validate=False)
   215	        self.launch("xpf-image-c", iso)
   216	        self.wait_xpfd("xpf-image-c")
   217	        if not guest_sh("xpf-image-c",
   218	                        'journalctl -u xpf-day0-config -b --no-pager | grep -q "REJECTED by commit-check"'):
   219	            fail("day-0 loader did not log the commit-check REJECT")
   220	        if guest("xpf-image-c", "test", "-e", "/etc/xpf/xpf.conf", check=False).returncode == 0:
   221	            fail("invalid config was installed")
   222	        if guest("xpf-image-c", "test", "-e", "/etc/xpf/.day0-config-applied", check=False).returncode == 0:
   223	            fail("stamp written on REJECT")
   224	        self.wait_fxp0_dhcp("xpf-image-c")
   225	        if not guest_sh("xpf-image-c", '[ "$(hostname)" != xpf-day0-c ]'):
   226	            fail("invalid config changed the hostname")
   227	        info("Scenario C PASS (fallback reachable, boot survived)")
   228	        self.drop("xpf-image-c")
   229	
   230	
   231	def _kver_ge(ver, floor):
   232	    try:
   233	        parts = tuple(int(x) for x in ver.split(".")[:2])
   234	    except ValueError:
   235	        return False
   236	    return parts >= floor
   237	
   238	
   239	def maybe_reexec_incus_admin():
   240	    if subprocess.run(["incus", "list"], capture_output=True).returncode == 0:
   241	        return
   242	    import grp
   243	    try:
   244	        in_grp = "incus-admin" in [g.gr_name for g in grp.getgrall()
   245	                                   if os.getlogin() in g.gr_mem]
   246	    except Exception:
   247	        in_grp = False
   248	    if in_grp:
   249	        # Quote every token — a qcow2/metadata path with spaces or shell
   250	        # metacharacters must not break (or inject into) the `sg -c` shell.
   251	        cmd = " ".join(shlex.quote(a) for a in [sys.executable] + sys.argv)
   252	        os.execvp("sg", ["sg", "incus-admin", "-c", cmd])
   253	
   254	
   255	def main():
   256	    maybe_reexec_incus_admin()
   257	    p = argparse.ArgumentParser(description=__doc__,
   258	                                formatter_class=argparse.RawDescriptionHelpFormatter)
   259	    p.add_argument("--qcow2", required=True)
   260	    p.add_argument("--metadata", required=True)
   261	    p.add_argument("--keep", action="store_true")
   262	    p.add_argument("scenario", nargs="?", default="all", choices=["a", "b", "c", "all"])
   263	    a = p.parse_args()
   264	    if not os.path.isfile(a.qcow2):
   265	        fail(f"--qcow2 not found: {a.qcow2}")
   266	    if not os.path.isfile(a.metadata):
   267	        fail(f"--metadata not found: {a.metadata}")
   268	    net = os.environ.get("XPF_VALIDATE_NETWORK", "xpf-image-net")
   269	    h = Harness(a.qcow2, a.metadata, net, a.keep)
   270	    try:
   271	        h.ensure_network()
   272	        h.import_image()
   273	        scenarios = {"a": [h.scenario_a], "b": [h.scenario_b], "c": [h.scenario_c],
   274	                     "all": [h.scenario_a, h.scenario_b, h.scenario_c]}[a.scenario]
   275	        for s in scenarios:
   276	            s()
   277	        info("Validation complete.")
   278	        return 0
   279	    finally:
   280	        h.cleanup()
   281	
   282	
   283	if __name__ == "__main__":
   284	    sys.exit(main())

exec
/bin/bash -lc 'nl -ba docs/in-place-upgrade.md' in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
     1	# In-place upgrade mechanism (#1917)
     2	
     3	The `pkg/upgrade` package implements the verified, atomic,
     4	rollback-capable in-place upgrade cut-over for xpfd + the AF_XDP
     5	dataplane helper. It is invoked as `xpfd upgrade [--rolling]` and from
     6	the `.deb` postinst.
     7	
     8	This doc is the module contract for `pkg/upgrade`, the `xpfd upgrade`
     9	subcommand, the postinst HA-mode contract, and the dogfood deploy.
    10	
    11	## Layout
    12	
    13	```
    14	/usr/local/share/xpf/staged/          dpkg-static staging (increment A) — apt's write target
    15	/var/lib/xpf/versions/<ver>/          non-dpkg runtime version dirs (retain N=3)
    16	/var/lib/xpf/versions/current -> <ver># bookkeeping pointer (the verified-live version)
    17	/usr/local/sbin/{xpfd,cli,...} -> versions/current/<bin>   operator-tool links
    18	/var/lib/xpf/upgrade.state            crash-safe state-machine journal
    19	/etc/systemd/system/xpfd.service.d/10-xpf-version.conf     ExecStart pinned to the CONCRETE version
    20	```
    21	
    22	## State machine (`pkg/upgrade`)
    23	
    24	```
    25	STAGED -> PREFLIGHT -> COPIED -> VERIFIED -> STOPPED -> FLIPPED -> STARTED -> COMMITTED
    26	```
    27	
    28	Each transition is journaled (temp+fsync+rename) so a crash is
    29	recoverable and idempotent — re-running `xpfd upgrade` resumes from the
    30	journal. The ONLY live-state mutations are STOP and FLIP-then-START;
    31	PREFLIGHT / COPY / VERIFY are pure and abortable (a failure there leaves
    32	the running daemon and config untouched).
    33	
    34	- **PREFLIGHT** — check `/var` free ≥ staged size + config-DB snapshot
    35	  size + margin; GC eligible versions if short; take the pre-upgrade
    36	  config-DB snapshot (`.partial`+rename, never torn) for rollback.
    37	- **COPY** — `staged/` → `.<ver>.partial/` + checksum + atomic rename to
    38	  `versions/<ver>/`. A crash never leaves a half-populated version dir;
    39	  stray `.partial` dirs are swept on re-run.
    40	- **VERIFY** — `versions/<ver>/xpfd verify-dataplane` against the running
    41	  kernel with throwaway socket/state/pin env paths. A REJECT aborts with
    42	  the live dataplane untouched.
    43	- **STOP → FLIP → START** — stop the old daemon (closes the
    44	  respawn-mismatch race: no live process can re-resolve the flipped
    45	  helper), flip `current` + the `/usr/local/sbin` links + the unit
    46	  ExecStart drop-in, then start the new daemon.
    47	
    48	### Respawn-mismatch closure (two structural guards)
    49	
    50	1. **STOP-before-FLIP** — no live old xpfd exists to respawn a helper
    51	   after the unit is stopped.
    52	2. **Concrete-version ExecStart** — the FLIP templates the unit
    53	   `ExecStart`/`ExecStartPre` to the literal `/var/lib/xpf/versions/<ver>/xpfd`
    54	   path (NOT the `current` symlink — systemd does NOT symlink-resolve
    55	   `argv[0]`). So `dir(os.Args[0])` is the matching-version dir and even
    56	   a transient respawn resolves the matching-version `xpf-userspace-dp`,
    57	   never the shared `/usr/local/sbin` link.
    58	
    59	### Rollback (binary + DB atomic)
    60	
    61	Standalone auto-rollback (on an unhealthy post-start helper) and operator
    62	rollback both restore the config DB BEFORE re-flipping the binary:
    63	
    64	```
    65	stop -> restore config-DB snapshot (PREFLIGHT) -> re-flip current/sbin/unit to previous -> start
    66	```
    67	
    68	This is mandatory because the N+1 daemon writes `active.json` in the
    69	config compatibility envelope (see below); a bare binary re-flip to N
    70	would boot an N daemon that fatal-rejects the N+1 envelope DB (a brick).
    71	The HA path disables auto-rollback — HA rollback is operator-driven (an
    72	auto re-flip mid-rolling un-coordinates the cluster).
    73	
    74	## HA rolling upgrade (`xpfd upgrade --rolling`)
    75	
    76	Cuts the LOCAL clustered node with a controlled drain so the cluster
    77	keeps forwarding. Run on each node in turn (the deploy driver sequences
    78	both); exactly one node is primary throughout.
    79	
    80	1. assert peer alive + session sync established + HA protocol compatible
    81	   (`CurrentHAProtocolVersion`) — else ABORT to image-replace (Path C),
    82	   never drop connections.
    83	2. **peer-takeover-ready precheck BEFORE demoting** — demoting a node
    84	   whose peer cannot take over strands VIPs.
    85	3. `ForceSecondary()` to start the drain.
    86	4. **strong drain predicate** — peer owns the RGs, local VRRP BACKUP with
    87	   no VIPs, `rg_active` false, sync clean (NOT merely "weight 0 set" — an
    88	   RG keeps forwarding while VRRP is still MASTER). On timeout: fail back
    89	   and ABORT WITHOUT cutting (node still forwarding — no harm).
    90	5. single-node cut (auto-rollback disabled).
    91	6. wait for session sync to re-establish, bounded by `RejoinDeadline`
    92	   (60s default). The cut just restarted xpfd, so the local gRPC socket
    93	   refuses connections for the first few seconds — that `connection
    94	   refused` is the EXPECTED transient, treated as "not ready yet" and
    95	   re-polled until the deadline (NOT a hard abort on the first dial
    96	   error). Only the deadline aborts, surfacing the last observed error;
    97	   the node is then left secondary for the operator to inspect.
    98	7. `ResetFailover()` to rejoin election; forward-verify is the natural
    99	   post-promotion check (`make test-failover`) — a passive node
   100	   structurally cannot forward, so it is never "verified while passive".
   101	
   102	## Config compatibility envelope (D1, `pkg/configstore`)
   103	
   104	`active.json` carries a magic header LINE
   105	(`#xpf-config-envelope v=1 writer=.. ast=.. min-reader=.. rollback-fmt=..`)
   106	prepended to the (possibly-encrypted) JSON body. The leading `#` makes a
   107	pre-floor reader's `json.Unmarshal` ERROR (fail closed) instead of
   108	empty-loading a wrapping object and silently wiping config. A too-new
   109	`min-reader` is rejected. A present-but-unreadable DB is tagged
   110	`ErrConfigDBUnreadable` and made FATAL at startup (daemon_run.go) — never
   111	silently overwritten by a blind bootstrap. A pre-floor (no-envelope) DB
   112	still reads, so upgrading TO the floor is non-destructive.
   113	
   114	`mgmt-never-stranded`: on the appliance the day-0 + protected-set lifeline
   115	covers a fail-closed boot; #1922 hardens the foreign/non-appliance host
   116	case (NOT implemented here — see #1922).
   117	
   118	## postinst HA-mode contract
   119	
   120	- STANDALONE node (no `/etc/xpf/node-id`): the postinst invokes
   121	  `xpfd upgrade` (verified single-node cut). `XPF_NO_POSTINST_CUT=1`
   122	  suppresses it.
   123	- CLUSTERED node (node-id present): STAGE-ONLY. Cut ONLY via
   124	  `xpfd upgrade --rolling`. Keyed on node-id ALONE so a degraded-HA node
   125	  never falls through to an uncoordinated standalone cut.
   126	
   127	## Dogfood deploy
   128	
   129	`XPF_DEPLOY_DEB=1 make cluster-deploy` builds the `.deb` (outside the
   130	#1875 cluster lock), `apt install`s it (stage-only on the clustered
   131	nodes), and drives `xpfd upgrade --rolling` secondary-first. The default
   132	raw push+restart path (and `XPF_DEPLOY_FAST`) is unchanged for the dev
   133	inner loop. The deb path is opt-in until validated live; it then becomes
   134	the CI/smoke default.
   135	
   136	## Peer-takeover-readiness is best-effort; DrainComplete is authoritative
   137	
   138	The local control socket renders the LOCAL node's view, so the
   139	pre-demotion `PeerTakeoverReady` check cannot directly read the PEER's
   140	takeover-readiness — it requires the peer alive and no LOCAL takeover
   141	blocker. The AUTHORITATIVE guard is `DrainComplete`, which AFTER demotion
   142	confirms the peer ACTUALLY holds primary for EVERY RG; if it does not
   143	within the deadline, the rolling driver fails back and ABORTS WITHOUT
   144	cutting. A peer that cannot take over therefore never leads to a cut — at
   145	worst the drain times out and the local node is restored to forwarding.
   146	
   147	## Rolling protocol-bump limitation
   148	
   149	`HAProtocolCompatible` compares the RUNNING local daemon's HA protocol
   150	version against the peer's. It cannot see the STAGED version's protocol
   151	before the cut. So if a release BUMPS `CurrentHAProtocolVersion`, the
   152	first node's precheck passes (running N vs peer N), it cuts to N+1, and
   153	then the SECOND node's precheck fails (running N vs peer N+1) and aborts —
   154	leaving a mixed-version cluster. This is the "not rolling-upgradable"
   155	outcome the plan flags (Path C image-replace), but it is detected on the
   156	second node, not pre-emptively. Operators MUST treat a protocol bump as a
   157	non-rolling release (image-replace both nodes). A pre-emptive guard would
   158	require the staged binary to report its protocol version to the driver
   159	before the first cut (future work).
   160	
   161	## Honest limits
   162	
   163	- **No true zero-gap standalone restart.** The helper is an `exec.Command`
   164	  child held in xpfd memory; a fresh xpfd spawns a NEW helper and clears
   165	  the XSKMAP. Standalone cut-over is a bounded, MEASURED multi-second gap
   166	  (the ~3s NAPI bootstrap window is the floor). True zero-gap
   167	  (decoupled-helper re-attach) is future M-mech-2. The HA path masks the
   168	  gap with a single ~60ms VRRP failover per node.
   169	- Kernel/OS upgrades are #1930; a signed/hosted apt repo is #1924.

exec
/bin/bash -lc 'nl -ba debian/control' in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
     1	Source: xpf
     2	Section: net
     3	Priority: optional
     4	Maintainer: xpf maintainers <noreply@anthropic.com>
     5	Build-Depends: debhelper-compat (= 13)
     6	Standards-Version: 4.6.2
     7	Homepage: https://github.com/psaab/xpf
     8	Rules-Requires-Root: no
     9	
    10	Package: xpf
    11	Architecture: amd64
    12	Depends: ${shlibs:Depends}, ${misc:Depends}
    13	Description: Junos-style firewall with AF_XDP userspace dataplane
    14	 xpf is a Junos-style stateful firewall that clones Juniper vSRX
    15	 capabilities using native Junos configuration syntax. The runtime
    16	 forwarding path is a Rust AF_XDP userspace dataplane driven by the
    17	 Go control plane (xpfd).
    18	 .
    19	 This package ships the binary set (xpfd, xpf-userspace-dp, cli),
    20	 the day-0 config-drive loader, and the systemd units. Binaries are
    21	 installed to a dpkg-static staging path; the live /usr/local/sbin
    22	 symlinks are created on first install (the in-place upgrade cut-over
    23	 mechanism that flips them after a verify gate is a separate increment
    24	 and is intentionally not part of this package's postinst).
    25	 .
    26	 The AF_XDP shim is embedded into the xpfd binary (go:embed), so no
    27	 separate shim object is shipped.
    28	
    29	Package: xpf-appliance
    30	Architecture: amd64
    31	Depends: ${misc:Depends},
    32	 xpf (= ${binary:Version}),
    33	 frr,
    34	 strongswan,
    35	 strongswan-swanctl,
    36	 kea-dhcp4-server,
    37	 kea-dhcp6-server,
    38	 chrony,
    39	 iproute2,
    40	 nftables,
    41	 ethtool,
    42	 tcpdump,
    43	 pciutils,
    44	 iputils-ping,
    45	 traceroute,
    46	 openssh-server,
    47	 openssh-client,
    48	 systemd-resolved,
    49	 rsyslog,
    50	 curl,
    51	 ca-certificates
    52	Description: xpf firewall appliance metapackage
    53	 Pulls in the xpf firewall binary package plus the full runtime
    54	 dependency set (routing, IPsec, DHCP server, time sync, networking
    55	 tooling). This is the operator-facing entry point: `apt install
    56	 xpf-appliance` provisions a complete firewall in one step (e.g. from a
    57	 hosted apt repo).
    58	 .
    59	 NOTE: the appliance image bake (scripts/image/bake.py) installs the
    60	 runtime dependency set explicitly plus the xpf binary package, rather
    61	 than this metapackage, so apt does not have to resolve the full
    62	 dependency closure against a single local .deb during the offline bake.
    63	 The dependency set here MUST stay in sync with bake.py's
    64	 RUNTIME_PACKAGES.
    65	 .
    66	 The held/pinned kernel channel and the in-place kernel-upgrade
    67	 mechanism are out of scope for this package and tracked separately.

codex
I’ve got enough to form findings. The main pressure points are not “minisign over SHA256SUMS is inherently unsound” or “deb822 Signed-By is legacy”; the weaker parts are the exact verification contract, publish fail-closed behavior, and freshness/layout semantics.
exec
/bin/bash -lc 'rg -n "SHA256SUMS|manifest|xpf-.*qcow2|incus-metadata" scripts/image/bake.py docs/install-images.md' in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
docs/install-images.md:16:| `dist/xpf-<ver>.qcow2` | libvirt/KVM, plain QEMU | `virt-install --import --disk path=...` |
docs/install-images.md:17:| `dist/xpf-<ver>.incus-metadata.tar.gz` + the same qcow2 | incus (VM) | `incus image import <meta> <qcow2> --alias xpf-appliance` |
docs/install-images.md:18:| `dist/SHA256SUMS` | both | `sha256sum -c` |
docs/install-images.md:70:6. Export compressed qcow2 + incus metadata tarball + SHA256SUMS.
docs/install-images.md:81:Each bake also writes `dist/xpf-<ver>.manifest` recording the exact
docs/install-images.md:85:manifest is the traceability record.
docs/install-images.md:90:python3 scripts/image/validate.py --qcow2 dist/xpf-<ver>.qcow2 \
docs/install-images.md:91:    --metadata dist/xpf-<ver>.incus-metadata.tar.gz all
docs/install-images.md:107:incus image import dist/xpf-<ver>.incus-metadata.tar.gz \
docs/install-images.md:108:    dist/xpf-<ver>.qcow2 --alias xpf-appliance
docs/install-images.md:126:    --import --disk path=xpf-<ver>.qcow2 \
docs/install-images.md:132:Plain QEMU works the same way (`-drive file=xpf-<ver>.qcow2`
docs/install-images.md:182:- Verify artifacts with `sha256sum -c dist/SHA256SUMS`. (Detached
scripts/image/bake.py:7:  dist/xpf-<ver>.qcow2                  - libvirt/KVM (virt-install)
scripts/image/bake.py:8:  dist/xpf-<ver>.incus-metadata.tar.gz  - incus VM image metadata
scripts/image/bake.py:9:  dist/SHA256SUMS
scripts/image/bake.py:19:manifest -> in-guest verify-dataplane validation gate (validate.py).
scripts/image/bake.py:166:    sums = os.path.join(work_dir, "SHA256SUMS.upstream")
scripts/image/bake.py:167:    run(["curl", "-fsSL", "-o", sums, f"{base_url}/SHA256SUMS"])
scripts/image/bake.py:176:        die(f"no SHA256 for {img} in upstream SHA256SUMS")
scripts/image/bake.py:375:        qcow_out = os.path.join(a.out, f"xpf-{ver}.qcow2")
scripts/image/bake.py:376:        meta_out = os.path.join(a.out, f"xpf-{ver}.incus-metadata.tar.gz")
scripts/image/bake.py:393:        sums = os.path.join(a.out, "SHA256SUMS")
scripts/image/bake.py:404:        manifest = os.path.join(a.out, f"xpf-{ver}.manifest")
scripts/image/bake.py:405:        with open(manifest, "w") as f:
scripts/image/bake.py:411:        info(f"manifest: {manifest}")

exec
/bin/bash -lc "rg -n \"SHA256SUMS|install\\.sh|minisign|Signed-By|reprepro|Valid-Until|dist-publish|XPF_SIGN_SECKEY|XPF_DIST_BASE_URL|OPEN QUESTIONS|OQ-\" docs/research/1924-signed-hosted-dist/plan.md" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
15:- **No signatures.** `scripts/image/bake.py` step 6 emits `dist/SHA256SUMS`
20:  compromised mirror can serve a tampered image plus a matching `SHA256SUMS`.
29:  There is no `install.sh`, no signed `Release`/`InRelease`, no archive key.
38:### Two decisions are the USER's, not this plan's (OPEN QUESTIONS)
45:- **OQ-1 — Hosting target.** WHERE artifacts are published (URL / S3 bucket /
47:- **OQ-2 — Signing identity.** WHICH signing key, and key management: who
50:These are surfaced as `XPF_DIST_BASE_URL` (or equivalent) and a checked-in
51:public key file + `XPF_SIGN_SECKEY` (path, never the key itself). See §9.
60:| Image bake signing | extend (additive output) | `scripts/image/bake.py` (emit a signature next to SHA256SUMS) |
63:| `install.sh` | NEW | `scripts/dist/install.sh` (or `dist/install.sh` template) |
64:| Public key (pinned) | NEW (placeholder until OQ-2) | `scripts/dist/xpf-archive-keyring.asc` / `xpf.pub` |
65:| Makefile | extend | `dist-sign`, `dist-repo`, `dist-publish` targets |
78:1. **Sign the image artifacts** at bake time: sign the `SHA256SUMS` file (the
83:3. **`install.sh`** (Tailscale-style) that bootstraps trust (installs the
87:Publishing (where bytes land) is a thin `dist-publish` target parametrised by
88:`XPF_DIST_BASE_URL` (OQ-1). The mechanism is host-agnostic: a static file
96:- **Image trust** — the signature over `SHA256SUMS`. The operator obtains the
103:The `install.sh` bootstrap is the ONLY moment trust is established over the
105:We **pin the keyring fingerprint inside install.sh** (and verify the fetched
107:install.sh's own integrity is the remaining root (mitigations in §8).
111:### 4A. Signing tool (image SHA256SUMS + optionally the .deb repo Release)
115:| **minisign** (issue's lead) | tiny, single static binary, no keyring DB, Ed25519, trivially scriptable, easy to pin one pubkey; matches issue text | NOT what `apt` understands natively — apt needs OpenPGP for `Release`; so minisign covers IMAGE only, apt repo still needs a PGP path |
116:| **signify** (OpenBSD) | same shape as minisign | less ubiquitous on Debian than minisign; same apt gap |
117:| **GPG / OpenPGP** (`sequoia`/`gpg`) | apt-native (apt verifies `Release` with PGP); ONE tool covers both image AND repo | heavier, keyring management, larger trust surface; for the IMAGE it is overkill vs minisign |
120:**Recommendation (mechanism, value deferred to OQ-2):**
121:- **Image artifacts → minisign** over `SHA256SUMS`. Smallest trust surface,
124:  call `minisign -V` directly — we are not constrained to apt's PGP.
126:  mandates it. This is unavoidable: apt will not trust a minisign signature.
128:This is a deliberate **two-key, two-tool** split: minisign for images, PGP for
132:dropping minisign — is documented in §4A-alt below for the reviewers to weigh;
133:the recommendation is the two-tool split because minisign's single-pubkey pin
134:is dramatically simpler to verify in install.sh and in our Python consumers.)
137:Use one OpenPGP key for BOTH the image `SHA256SUMS.asc` and the apt `Release`.
138:Pros: one key to manage (one OQ-2 answer), apt-native. Cons: image consumers
139:(validate.py, install.sh trust-bootstrap) must shell out to `gpg --verify`
140:with a keyring, which is heavier and more error-prone to pin than `minisign
149:| **reprepro** | mature, deb-native, simple `conf/distributions`, signs `Release` with gpg, deterministic pool layout, no DB server | single-version-per-arch by default (fine for an appliance; multi-version needs care) |
153:**Recommendation:** **reprepro** for the pool repo. It is the smallest mature
156:readable file. `aptly` is the upgrade path IF OQ-1 picks S3 + we later need
158:(documented) if reprepro is unwanted on the build host.
160:Channel layout (deb822, the contract install.sh writes):
164:  URIs: <XPF_DIST_BASE_URL>/apt        # OQ-1
168:  Signed-By: /etc/apt/keyrings/xpf-archive-keyring.asc
171:### 4C. install.sh trust-bootstrap (the security-critical step)
175:| **Embed the full keyring inline** (heredoc the ASCII-armored pubkey INTO install.sh) | no second network fetch; install.sh integrity == keyring integrity (one thing to trust) | install.sh is bigger; rotating the key means re-issuing install.sh |
176:| **Fetch keyring + verify against a pinned fingerprint** in install.sh | install.sh stays small; key rotation = republish keyring | install.sh must still embed the fingerprint (a hash), which is the real pin; two fetches |
180:install.sh (Tailscale does exactly this) AND verify the fetched `.deb`/repo
181:through apt's own signed `Release`. The keyring-in-install.sh means there is
182:exactly ONE artifact whose integrity matters at bootstrap (install.sh itself),
183:and we publish install.sh over HTTPS at a stable URL + document a
186:reduces to "trust the fingerprint hash in install.sh"). TOFU is rejected.
188:### 4D. Hosting / publish (OQ-1 — value is the user's; mechanism here)
193:| **Static bucket (S3/GCS/R2) behind HTTPS** | stable channel URLs, cheap, aptly publishes to S3 natively, retention via lifecycle rules | the user must own/configure the bucket + CDN/TLS (OQ-1) |
196:**Mechanism (host-agnostic):** `make dist-publish` rsync/`aws s3 sync`/`gh
197:release upload`s the `dist/` tree (images + sigs) and the reprepro `apt/` pool
198:to `XPF_DIST_BASE_URL`. The plan provides a pluggable `XPF_PUBLISH_CMD` so the
206:After step 6 writes `dist/SHA256SUMS`, add step 6b:
208:minisign -S -s "$XPF_SIGN_SECKEY" -m dist/SHA256SUMS \
209:         -t "xpf image $ver" -x dist/SHA256SUMS.minisig
211:- `XPF_SIGN_SECKEY` is a PATH to the secret key (OQ-2), never the key bytes.
216:- One signature over `SHA256SUMS` transitively covers both image artifacts
221:1. `minisign -V -p <pinned pub> -m SHA256SUMS -x SHA256SUMS.minisig`
222:2. then `sha256sum -c SHA256SUMS` for the two files.
233:### 5.3 Apt repo (NEW scripts/dist/build-apt-repo.sh + reprepro)
235:  `Architectures: amd64`, `SignWith: <KEYID>` (OQ-2 PGP key).
236:- `make dist-repo` runs `make deb` then `reprepro -b <repo> includedeb
239:- Flat-repo fallback script documented for no-reprepro hosts.
241:### 5.4 install.sh (NEW)
246:3. Write `/etc/apt/sources.list.d/xpf.sources` (deb822, `Signed-By`,
247:   `XPF_DIST_BASE_URL` substituted; default channel `stable`,
253:- `install.sh` is itself published at `XPF_DIST_BASE_URL/install.sh` and the
259:  (build signed apt repo), `make dist-publish` (push via `XPF_PUBLISH_CMD`).
262:  install.sh one-liner, the manual apt steps, the image verify steps).
264:  verify from `XPF_DIST_BASE_URL`"; document `SHA256SUMS.minisig`.
270:1. **Sign/verify round-trip (image):** bake (or a stub SHA256SUMS) → sign with
271:   a throwaway minisign key → `verify_artifacts` PASSES; flip one byte of the
273:   at `minisign -V`; wrong pubkey → FAILS. (Negative tests are mandatory — a
276:   container (or the local incus image flow) → run install.sh pointed at a
280:3. **install.sh:** shellcheck-clean; idempotent (run twice = no error); refuses
288:The signing key used in tests is a generated throwaway, NEVER OQ-2's real key.
299:  reprepro `conf/distributions`, `make dist-repo`, PGP archive pubkey
301:- **Inc 3 — install.sh + publish + docs** (`install.sh`, `make dist-publish`
302:  with `XPF_PUBLISH_CMD`, `docs/distribution.md`; install.sh container test).
304:  release.yml` on tag: bake → sign → build repo → publish). GATED on OQ-1 +
305:  OQ-2 being real, and on the user wanting CI to hold the secret key (a
308:The two OPEN QUESTIONS are NOT blockers to Inc 1–3 landing as MECHANISM with
310:release (Inc 4 / actual `dist-publish`). The plan converges with placeholders;
315:- **R1 — install.sh is the trust root over the network.** A compromised host
316:  serving a bad install.sh defeats everything. Mitigation: publish install.sh
318:  self-authenticating once install.sh runs); document a verify-before-run
319:  variant (publish `install.sh.minisig` too, signed by the image key, so the
320:  paranoid operator verifies install.sh with the SAME pinned pubkey they used
322:  the image and install.sh.
323:- **R2 — key compromise / rotation.** OQ-2 owns the policy, but the mechanism
325:  (`XPF_IMAGE_PUBKEY`, apt `Signed-By` is a file), and the plan documents a
328:  reprepro (it owns index generation) rather than hand-rolled scanning;
330:- **R4 — signing-tool availability on build host.** `minisign` and `reprepro`
333:  pattern); bake.py SKIPS signing with a loud warning if `minisign` or
334:  `XPF_SIGN_SECKEY` is absent (dev ergonomics preserved; "do not publish"
338:  a VM image. Mitigation: install.sh PRINTS the warning and does NOT auto-start
344:  single "Trust" section: pubkey A (image+install.sh, minisign), pubkey B (apt
350:- **OQ-1 (hosting target):** the value of `XPF_DIST_BASE_URL`, the channel
354:- **OQ-2 (signing identity):** the minisign keypair (image) and the OpenPGP
358:- **OQ-3 (one tool vs two):** §4A recommends minisign(image)+PGP(apt); §4A-alt
362:- **OQ-4 (CI signing):** does the secret key live in CI (automated release) or
366:## 10. Why not just keep SHA256SUMS?
371:a matching `SHA256SUMS`. Signing is the minimum bar; an apt repo + install.sh
376:- Image: **minisign** over `SHA256SUMS` (one pinned Ed25519 pubkey), verified
378:- Apt: **reprepro**-built signed repo (PGP `Release`), `stable`/`edge` suites,
379:  deb822 `Signed-By`.
380:- Bootstrap: **install.sh** with the archive keyring embedded inline +
381:  optional `install.sh.minisig` for verify-before-run. TOFU rejected.
382:- Hosting: host-agnostic `make dist-publish` via `XPF_PUBLISH_CMD` +
383:  `XPF_DIST_BASE_URL`. No backend hardcoded.
385:  optional + gated on OQ-1/OQ-2/OQ-4.
386:- The two OPEN QUESTIONS (hosting target, signing identity) are engineer-time

exec
/bin/bash -lc 'rg -n "xpf-appliance|linux|kernel|apt install|hosted apt repo" debian/control docs/in-place-upgrade.md docs/install-images.md' in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
docs/install-images.md:6:time), a >= 6.18 kernel (the AF_XDP shim's verifier floor; 26.04 ships
docs/install-images.md:9:There is no dependency matrix to install and no kernel hunt: the image
docs/install-images.md:17:| `dist/xpf-<ver>.incus-metadata.tar.gz` + the same qcow2 | incus (VM) | `incus image import <meta> <qcow2> --alias xpf-appliance` |
docs/install-images.md:49:   `linux-virtual` kernel replaced by `linux-generic` (full driver set
docs/install-images.md:50:   — mlx5/i40e for passthrough NICs live in `linux-modules-extra`)
docs/install-images.md:51:   with in-bake asserts that the kernel meets the >= 6.18 verifier
docs/install-images.md:53:   (a competing network manager), snapd, and the virtual-kernel
docs/install-images.md:73:   DHCP, sshd posture via `sshd -T`, -generic kernel flavor + full
docs/install-images.md:75:   the image's own kernel, plus the valid- and invalid-day-0-drive
docs/install-images.md:83:date/host kernel). Bakes are not bit-reproducible (the base tracks
docs/install-images.md:108:    dist/xpf-<ver>.qcow2 --alias xpf-appliance
docs/install-images.md:113:incus init xpf-appliance xpf1 --vm -c limits.cpu=4 -c limits.memory=4GiB
docs/install-images.md:220:single ≥6.18 kernel, in-guest `verify-dataplane`, day-0 valid/invalid),
docs/install-images.md:230:kernel side (>= 6.18, verifier-passing shim, `init_on_alloc=0`);
docs/in-place-upgrade.md:41:  kernel with throwaway socket/state/pin env paths. A REJECT aborts with
docs/in-place-upgrade.md:130:#1875 cluster lock), `apt install`s it (stage-only on the clustered
docs/in-place-upgrade.md:169:- Kernel/OS upgrades are #1930; a signed/hosted apt repo is #1924.
debian/control:29:Package: xpf-appliance
debian/control:55: tooling). This is the operator-facing entry point: `apt install
debian/control:56: xpf-appliance` provisions a complete firewall in one step (e.g. from a
debian/control:57: hosted apt repo).
debian/control:66: The held/pinned kernel channel and the in-place kernel-upgrade

codex
**Findings**

1. **Artifact verification can authenticate the wrong bytes.** Plan line 222 says: “`then sha256sum -c SHA256SUMS` for the two files.” Counterexample: `SHA256SUMS` verifies `./xpf-1.qcow2`, but `xpf-deploy.py --qcow2 /tmp/evil/xpf-1.qcow2` imports a different path. The signature is valid, the checksum command passes, and the imported image is unauthenticated. Correct alternative: parse the signed `SHA256SUMS`, require exact expected basenames, reject duplicate/pathful entries, and hash the actual `qcow2` / `metadata` arguments.

2. **Publish is not fail-closed.** Plan lines 211-213 allow unsigned image output when `XPF_SIGN_SECKEY` is unset, and lines 196-198 say `dist-publish` uploads the `dist/` tree. Counterexample: CI misses `XPF_SIGN_SECKEY`; bake prints a warning; `make dist-publish XPF_PUBLISH_CMD='aws s3 sync dist s3://bucket'` publishes unsigned images. Correct alternative: local bake may skip signing, but `dist-publish` must hard-fail unless image signatures, apt Release signatures, and advertised `install.sh.minisig` verify locally.

3. **Retention/channel layout breaks signed-image verification.** Plan line 200 says “keep last N images per channel,” but bake currently emits one global `dist/SHA256SUMS` for the current qcow2 + metadata only. Counterexample: publish v1, then v2 while retaining v1; the channel `SHA256SUMS` now covers v2, so retained v1 has no matching signed checksum. Correct alternative: use per-version directories with their own `SHA256SUMS.minisig`, or sign a channel checksum/index containing all retained artifacts.

4. **Replay/freshness is missing.** Plan line 371 says signing is “the minimum bar,” but the plan does not distinguish authenticity from freshness. Counterexample: after a security fix in v2, a compromised mirror serves old signed v1 artifacts plus old signed `SHA256SUMS`; verification passes. Correct alternative: add signed channel metadata with latest version and expiry, and for apt configure Release freshness, e.g. `Valid-Until` / regular re-signing.

5. **install.sh trust bootstrap is internally inconsistent.** Plan lines 105-106 say the script pins a fingerprint and verifies a fetched keyring, but line 179 recommends embedding the archive pubkey inline. Pick one. Inline is fine, but then the trust model is “authentic install.sh contains the apt key,” not “fetched keyring is pinned.”

6. **The `install.sh.minisig` loop only closes with a real out-of-band image key.** Plan lines 319-322 claim the signed script “closes the loop.” Counterexample: operator fetches `install.sh`, `install.sh.minisig`, and `xpf-image.pub` from the same compromised distribution host; attacker swaps all three and verification succeeds. Correct alternative: docs must require the minisign public key/fingerprint from the source repo, release notes, or another out-of-band channel.

Not findings: signing `SHA256SUMS` instead of directly signing qcow2/metadata is sound if the verifier hashes the exact target files. deb822 `Signed-By: /etc/apt/keyrings/xpf-archive-keyring.asc` is the right modern apt path, not legacy `apt-key`. The minisign-image plus OpenPGP-apt split is defensible, though line 133 overclaims install.sh simplicity; the real justification is apt’s PGP requirement plus simpler Python image verification. OQ-1/OQ-2 are not hidden blockers to mechanism work, but they are blockers to any real public release.

PLAN-NEEDS-MAJOR

The architecture is salvageable, but the plan is not ready because the verification and publication contracts are too loose for a signed distribution. The trust-root choices are mostly acceptable; the dangerous gaps are path-binding during checksum verification, fail-open publishing, retention/index layout, and replay semantics. These are plan-level fixes, not implementation nits.
tokens used
58,639
**Findings**

1. **Artifact verification can authenticate the wrong bytes.** Plan line 222 says: “`then sha256sum -c SHA256SUMS` for the two files.” Counterexample: `SHA256SUMS` verifies `./xpf-1.qcow2`, but `xpf-deploy.py --qcow2 /tmp/evil/xpf-1.qcow2` imports a different path. The signature is valid, the checksum command passes, and the imported image is unauthenticated. Correct alternative: parse the signed `SHA256SUMS`, require exact expected basenames, reject duplicate/pathful entries, and hash the actual `qcow2` / `metadata` arguments.

2. **Publish is not fail-closed.** Plan lines 211-213 allow unsigned image output when `XPF_SIGN_SECKEY` is unset, and lines 196-198 say `dist-publish` uploads the `dist/` tree. Counterexample: CI misses `XPF_SIGN_SECKEY`; bake prints a warning; `make dist-publish XPF_PUBLISH_CMD='aws s3 sync dist s3://bucket'` publishes unsigned images. Correct alternative: local bake may skip signing, but `dist-publish` must hard-fail unless image signatures, apt Release signatures, and advertised `install.sh.minisig` verify locally.

3. **Retention/channel layout breaks signed-image verification.** Plan line 200 says “keep last N images per channel,” but bake currently emits one global `dist/SHA256SUMS` for the current qcow2 + metadata only. Counterexample: publish v1, then v2 while retaining v1; the channel `SHA256SUMS` now covers v2, so retained v1 has no matching signed checksum. Correct alternative: use per-version directories with their own `SHA256SUMS.minisig`, or sign a channel checksum/index containing all retained artifacts.

4. **Replay/freshness is missing.** Plan line 371 says signing is “the minimum bar,” but the plan does not distinguish authenticity from freshness. Counterexample: after a security fix in v2, a compromised mirror serves old signed v1 artifacts plus old signed `SHA256SUMS`; verification passes. Correct alternative: add signed channel metadata with latest version and expiry, and for apt configure Release freshness, e.g. `Valid-Until` / regular re-signing.

5. **install.sh trust bootstrap is internally inconsistent.** Plan lines 105-106 say the script pins a fingerprint and verifies a fetched keyring, but line 179 recommends embedding the archive pubkey inline. Pick one. Inline is fine, but then the trust model is “authentic install.sh contains the apt key,” not “fetched keyring is pinned.”

6. **The `install.sh.minisig` loop only closes with a real out-of-band image key.** Plan lines 319-322 claim the signed script “closes the loop.” Counterexample: operator fetches `install.sh`, `install.sh.minisig`, and `xpf-image.pub` from the same compromised distribution host; attacker swaps all three and verification succeeds. Correct alternative: docs must require the minisign public key/fingerprint from the source repo, release notes, or another out-of-band channel.

Not findings: signing `SHA256SUMS` instead of directly signing qcow2/metadata is sound if the verifier hashes the exact target files. deb822 `Signed-By: /etc/apt/keyrings/xpf-archive-keyring.asc` is the right modern apt path, not legacy `apt-key`. The minisign-image plus OpenPGP-apt split is defensible, though line 133 overclaims install.sh simplicity; the real justification is apt’s PGP requirement plus simpler Python image verification. OQ-1/OQ-2 are not hidden blockers to mechanism work, but they are blockers to any real public release.

PLAN-NEEDS-MAJOR

The architecture is salvageable, but the plan is not ready because the verification and publication contracts are too loose for a signed distribution. The trust-root choices are mostly acceptable; the dangerous gaps are path-binding during checksum verification, fail-open publishing, retention/index layout, and replay semantics. These are plan-level fixes, not implementation nits.
