#!/bin/bash
# header-regen-in.sh - run inside an ubuntu container by header-regen.sh.
# Do not run it on a host: it installs packages and writes to /opt/mmt.
#
# Inputs: /w/sec.tar (git archive HEAD), /w/sec.commit, /w/debs/mmt-dpi_<v>.deb.
# Prints a transcript: each command as "$ cmd", then its output.
set -euo pipefail
trap 'chown -R "${OUT_UID:-0}:${OUT_GID:-0}" /w' EXIT

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends \
	gcc make libc6-dev libxml2-dev libpcap-dev libconfuse-dev binutils >/dev/null

run(){ printf '$ %s\n' "$*"; ( eval "$*" ) 2>&1 | sed 's/^/  /' || true; }
# (make -n output to a file: `make | grep -q` would SIGPIPE make under pipefail)
regen(){ make -n all >/tmp/n.log 2>&1 || true
	printf '  make -n all regenerates the header: %s\n' \
	"$(grep -q 'gen_dpi_header' /tmp/n.log && echo yes || echo no)"; }
# compile a rule that uses http.header (absent from mmt-dpi 1.10.x) to C only.
# compile_rule resolves the name first, then its data type:
#   "Data type for http.header has not implemented yet": the name resolved to an
#     id (the table compiled into compile_rule has http.header); its data type is
#     one mmt-security cannot encode, so the rule stops there;
#   "Attribute http.header has not implemented yet": the name did not resolve.
probe(){ ./compile_rule /tmp/probe.c /tmp/probe.xml -c >/tmp/probe.log 2>&1 || true
	echo "probe http.header: $(grep -m1 -o 'HALT_SEC: Error [0-9]*: .* yet' /tmp/probe.log || echo 'no error')"; }
baked(){ ./compile_rule rules/11.so rules/11.ip_size.xml >/dev/null 2>&1; \
	./rule_info rules/11.so | grep -o 'dpi version .*'; }
label(){ grep -a -o -E '1\.(7|10)\.[0-9]+ \([0-9a-f]{8}\)' src/lib/gen_code.o | sort -u | sed 's/^/gen_code.o holds: /'; }

echo "== mmt-security $(cat /w/sec.commit), $(. /etc/os-release; echo "$PRETTY_NAME") $(uname -m)"

echo
echo "== (a) first install after the checkout, then a downgrade and an upgrade"
mkdir -p /orig /b /a
tar -C /orig -xf /w/sec.tar src/dpi/mmt_dpi.h
# -m: files get the extraction time as mtime, as with a git clone
run "tar -C /b -xmf /w/sec.tar"
# the Makefile takes GIT_VERSION from git log; there is no .git here
sed -i "s/^GIT_VERSION := .*/GIT_VERSION := $(cut -c1-7 /w/sec.commit)/" /b/Makefile
run "dpkg -i /w/debs/mmt-dpi_1.10.3.deb >/dev/null; dpkg-query -W mmt-dpi"
run "stat -c '%y %n' /opt/mmt/dpi /b/src/dpi/mmt_dpi.h"
cd /b; regen
cd /
run "tar -C /a -xmf /w/sec.tar    # a checkout made while 1.10.3 is installed"
sed -i "s/^GIT_VERSION := .*/GIT_VERSION := $(cut -c1-7 /w/sec.commit)/" /a/Makefile
cd /a; regen; cd /
run "stat -c '%y %n' /opt/mmt/dpi /opt/mmt/dpi/lib"
run "dpkg -i /w/debs/mmt-dpi_1.10.2.deb >/dev/null; dpkg-query -W mmt-dpi    # downgrade"
run "stat -c '%y %n' /opt/mmt/dpi /opt/mmt/dpi/lib"
cd /a; regen; cd /
run "dpkg -i /w/debs/mmt-dpi_1.10.3.deb >/dev/null; dpkg-query -W mmt-dpi    # upgrade"
run "stat -c '%y %n' /opt/mmt/dpi /opt/mmt/dpi/lib"
cd /a; regen; cd /

echo
echo "== (b) the header is regenerated, the objects are not rebuilt"
cd /b
sed 's/http\.user_agent/http.header/g; s/property_id="15"/property_id="999"/' rules/15.nikto.xml > /tmp/probe.xml
run "make -j1 compile_rule rule_info >/dev/null 2>&1; head -c 110 src/dpi/mmt_dpi.h; echo"
run "probe; baked; label"
run "make -j1 all 2>&1 | grep -E 'Generate|COMPILE'    # nothing in src/lib is recompiled"
run "head -c 110 src/dpi/mmt_dpi.h; echo; cmp -s src/dpi/mmt_dpi.h /orig/src/dpi/mmt_dpi.h && echo 'same as committed' || echo 'differs from committed (git status: modified)'"
run "probe; baked; label    # still the committed table and label"
run "make clean >/dev/null; make -j1 all >/dev/null 2>&1; head -c 110 src/dpi/mmt_dpi.h; echo"
run "probe; baked; label    # after make clean"

echo
echo "== (c) which binaries link libmmt_core"
for f in compile_rule rule_info libmmt_security2.so mmt_sec_standalone; do
	printf '  %-22s NEEDED: %s\n' "$f" "$(readelf -d "$f" | sed -n 's/.*Shared library: \[\(.*\)\]/\1/p' | tr '\n' ' ')"
done
