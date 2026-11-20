#!/bin/bash
# in-container.sh - one mmt-dpi version, run inside an ubuntu container by run.sh.
#
# Part of tools/dpi-id-stability (issue #5, A0). Do not run it on a host: it
# installs packages and writes to /opt/mmt.
#
# Inputs (mounted by run.sh):
#   /in/mmt-dpi     a clone of https://github.com/Montimage/mmt-dpi (read-only)
#   /in/tool        this directory (read-only)
#   /in/mmt-sec     `git archive HEAD` of this repository (read-only)
#   /out            output directory for this version
#   DPI_REF         the mmt-dpi commit or tag to build
#   OUT_UID/OUT_GID owner to give /out at the end
#
# Outputs in /out:
#   dpi.txt                       DPI_REF, commit, mmt_version()
#   baked-regenerated.tsv         ids written into each rule's generated C by a
#                                 compile_rule whose src/dpi/mmt_dpi.h was
#                                 regenerated from this DPI (what `make` produces
#                                 when /opt/mmt/dpi is newer than the header, and
#                                 `make clean-all && make` in upstream CI)
#   baked-committed-header.tsv    the same with the committed src/dpi/mmt_dpi.h
#                                 (what `make compile_rule` produces, and `make`
#                                 when the header is newer than /opt/mmt/dpi)
#   core.tsv                      the same pairs resolved at run time by this
#                                 libmmt_core with all plugins loaded
#   compile-errors-*.txt          rules that compile_rule could not encode
#   mmt_dpi.h                     the regenerated header
#   committed-mmt_dpi.h           the committed header (from /in/mmt-sec)
set -euo pipefail

: "${DPI_REF:?}"
trap 'chown -R "${OUT_UID:-0}:${OUT_GID:-0}" /out' EXIT
JOBS=$(nproc)

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends \
	build-essential git ca-certificates libxml2-dev libpcap-dev >/dev/null

# ---- mmt-dpi ---------------------------------------------------------------
git config --global --add safe.directory '*'
git clone -q /in/mmt-dpi /build/dpi
git -C /build/dpi checkout -q "$DPI_REF"
DPI_COMMIT=$(git -C /build/dpi rev-parse HEAD)
echo ">>> building mmt-dpi $DPI_REF ($DPI_COMMIT)"
make -C /build/dpi/sdk -j"$JOBS" > /out/dpi-build.log 2>&1 \
	|| { tail -40 /out/dpi-build.log; exit 1; }
make -C /build/dpi/sdk install >> /out/dpi-build.log 2>&1 \
	|| { tail -40 /out/dpi-build.log; exit 1; }
export LD_LIBRARY_PATH=/opt/mmt/dpi/lib

# ---- run-time resolver -----------------------------------------------------
gcc -o /build/resolve_ids /in/tool/resolve_ids.c \
	-I/opt/mmt/dpi/include -L/opt/mmt/dpi/lib -l:libmmt_core.so -ldl

# ---- compile_rule, twice ---------------------------------------------------
# extract RULE_FILE SEC_DIR OUT_TSV ERR_FILE
# Run compile_rule -c on every rules/*.xml and print every (proto, att) entry of
# every generated proto_atts_<rule id> array.
extract(){
	local sec=$1 tsv=$2 err=$3 xml c
	: > "$tsv"; : > "$err"
	for xml in "$sec"/rules/*.xml; do
		c=/build/gen/$(basename "$xml" .xml).c
		if ! ( cd "$sec" && ./compile_rule "$c" "rules/$(basename "$xml")" -c ) >/build/gen/last.log 2>&1; then
			echo "$(basename "$xml"): $(grep -m1 -i 'error' /build/gen/last.log || tail -1 /build/gen/last.log)" >> "$err"
			continue
		fi
		awk -v f="$(basename "$xml")" '
			/static proto_attribute_t proto_atts_[0-9]+\[/ {
				match($0, /proto_atts_[0-9]+/); rid = substr($0, RSTART + 11, RLENGTH - 11)
			}
			/\.proto = "/ {
				line = $0
				sub(/^.*\.proto = /, ".proto = ", line)
				gsub(/[{};]/, "", line)
				n = split(line, kv, ",")
				p = ""; pid = ""; a = ""; aid = ""; dt = ""; t = ""
				for (i = 1; i <= n; i++) {
					s = kv[i]; gsub(/^[ \t]+|[ \t]+$/, "", s)
					split(s, x, " = "); gsub(/"/, "", x[2])
					if (x[1] == ".proto") p = x[2]
					else if (x[1] == ".proto_id") pid = x[2]
					else if (x[1] == ".att") a = x[2]
					else if (x[1] == ".att_id") aid = x[2]
					else if (x[1] == ".data_type") dt = x[2]
					else if (x[1] == ".dpi_type") t = x[2]
				}
				printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", f, rid, p, a, pid, aid, t
			}' "$c" >> "$tsv"
	done
}

build_sec(){ # build_sec DIR regenerate(0|1)
	cp -a /in/mmt-sec "$1"
	if [ "$2" = 1 ]; then
		rm -f "$1/src/dpi/mmt_dpi.h"
		make -C "$1" gen_dpi > /out/sec-build-regenerated.log 2>&1
	fi
	make -C "$1" -j1 compile_rule >> /out/sec-build-$3.log 2>&1 \
		|| { tail -40 /out/sec-build-$3.log; exit 1; }
}

mkdir -p /build/gen
build_sec /build/sec-committed 0 committed-header
extract /build/sec-committed /out/baked-committed-header.tsv /out/compile-errors-committed-header.txt
build_sec /build/sec-regen 1 regenerated
extract /build/sec-regen /out/baked-regenerated.tsv /out/compile-errors-regenerated.txt
cp /build/sec-regen/src/dpi/mmt_dpi.h /out/mmt_dpi.h
cp /in/mmt-sec/src/dpi/mmt_dpi.h /out/committed-mmt_dpi.h

cut -f3,4 /out/baked-committed-header.tsv /out/baked-regenerated.tsv | sort -u \
	| tr '\t' ' ' | /build/resolve_ids > /out/core.tsv

{
	echo "ref	$DPI_REF"
	echo "commit	$DPI_COMMIT"
	echo "commit_date	$(git -C /build/dpi log -1 --format=%cI)"
	echo "mmt_version	$(head -1 /out/core.tsv | cut -f2)"
	echo "header_line	$(head -1 /out/mmt_dpi.h)"
	echo "image	$(. /etc/os-release; echo "$PRETTY_NAME") $(uname -m)"
	echo "gcc	$(gcc -dumpfullversion)"
} > /out/dpi.txt
echo ">>> done $DPI_REF"
