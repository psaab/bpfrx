-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Format: 3.0 (quilt)
Source: xdp-tools
Binary: libxdp1, libxdp-dev, xdp-tools, xdp-tests
Architecture: linux-any
Version: 1.6.2-1
Maintainer: Luca Boccassi <bluca@debian.org>
Homepage: https://github.com/xdp-project/xdp-tools
Standards-Version: 4.7.3
Vcs-Browser: https://salsa.debian.org/debian/xdp-tools
Vcs-Git: https://salsa.debian.org/debian/xdp-tools.git
Testsuite: autopkgtest
Testsuite-Triggers: arping, ethtool, iproute2, iputils-ping, mount, ndisc6, netcat-openbsd, socat, tcpdump, tshark
Build-Depends: bpftool (>= 7.5.0~), clang, debhelper-compat (= 13), dh-package-notes, libbpf-dev, libelf-dev, libpcap-dev, llvm, pkgconf, zlib1g-dev
Package-List:
 libxdp-dev deb libdevel optional arch=linux-any
 libxdp1 deb libs optional arch=linux-any
 xdp-tests deb devel optional arch=linux-any
 xdp-tools deb devel optional arch=linux-any
Checksums-Sha1:
 9c8556bb07eb82adbc31e35d116ba625d03e22f8 389284 xdp-tools_1.6.2.orig.tar.gz
 6eea3a853575e29536aec98785c73cabeea1e9d8 7000 xdp-tools_1.6.2-1.debian.tar.xz
Checksums-Sha256:
 ccce43fff6bb6161e447588127524ddc5a9b6239ed3dc56ee8558b9a5f97d0a8 389284 xdp-tools_1.6.2.orig.tar.gz
 1088c0f312599ea0b4616096f53dc7b26481bec5469bd28eb87f997da589e89b 7000 xdp-tools_1.6.2-1.debian.tar.xz
Files:
 eb5e8252534d143cfe3b77e9d6bd205d 389284 xdp-tools_1.6.2.orig.tar.gz
 439b89d995dc7f39264e5679712ad4f0 7000 xdp-tools_1.6.2-1.debian.tar.xz

-----BEGIN PGP SIGNATURE-----

iQJFBAEBCgAvFiEErCSqx93EIPGOymuRKGv37813JB4FAmmc6bwRHGJsdWNhQGRl
Ymlhbi5vcmcACgkQKGv37813JB58gxAAmsZzhUzXI52zotQgttrTkaB4sCP5hVgX
xd3HkdTUvusO9wnB67Lp0B3uG0QFOqsq1D6dKTblqKdRO1pxqKtaiPUYmw2SKW3p
9WDmu6Oz+kaLaaTmlbDRfUOHLzQTkPv36Y48khXLfruC+oNFq2iFiJ4rzUqSVbrx
ATIGs+4VfCfYp8iK4/y5BJXGduCQs58cJm1ttFqjEoE7JI+zHRIGneWl155T20SQ
q759JtZwUS/IwIrEIhXGz6RgaNk5bZxcdFmxojyCzsGzQCAM2gHLbWF42ycW65zc
vH/FbfjXPW4G8bUZJRovGnZhL5YIi/nfY8fBcZKVOtE4ZTjM+ZWtJK2dbbCWCwrU
QVS+rSGAoXGZQeyRpnxaX5/NuMtNcA/ecc37XxIbQNl8As09Vy5DUNxOySQJQ37Z
V6+oQtArgnCx59e9SrRfX5rzpGExbgUTVaL+Wa/oeodEg0FV8gYyQydTeD6XEcLF
yQUwECaMuOh2cvR1f45YRWYPmSRaeU3bN/t+lpRh6Ve2yEjemgik9AxHJgXWA9Ry
XYn7pJZEW+VNfSrMfjTtRU6qmgufzT+tKW0GS40roxVClCoGUdz7NE0JYpT4H70l
4c+t4Z+BCCgaiivfafYfGPoAHe7Bbb+w0AI73wzzYTriflnxGEdamIi75xvzef/s
HFr8naAdn54=
=l6VM
-----END PGP SIGNATURE-----
