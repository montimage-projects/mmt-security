#!/bin/bash
# run.sh - A0 (issue #5): are the protocol/attribute ids baked into compiled
# rules stable across mmt-dpi versions?
#
# For each mmt-dpi ref it builds mmt-dpi from source in a fresh ubuntu
# container, then encodes every rules/*.xml with compile_rule -c twice (with the
# committed src/dpi/mmt_dpi.h, and with a header regenerated from that DPI),
# and resolves the same (proto, att) pairs with that libmmt_core at run time.
# compare.py then prints the ids per version and every difference.
#
# Usage: tools/dpi-id-stability/run.sh [-w WORKDIR] [-i IMAGE] [-j PARALLEL] [REF...]
#   REF       mmt-dpi tags or commits (default: the A0 set below)
#   WORKDIR   scratch directory (default: tools/dpi-id-stability/.work, gitignored)
#   IMAGE     base image (default: ubuntu:24.04)
#   PARALLEL  containers at once (default: 3)
#
# Needs docker (user in the docker group) and git; no sudo. Containers run as
# root inside (to install mmt-dpi under /opt/mmt) and chown their output back
# to the caller. Nothing is written outside WORKDIR.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
WORK=$HERE/.work
IMAGE=ubuntu:24.04
PARALLEL=3
DPI_URL=https://github.com/Montimage/mmt-dpi.git

while getopts "w:i:j:h" o; do
	case $o in
	w) WORK=$OPTARG ;;
	i) IMAGE=$OPTARG ;;
	j) PARALLEL=$OPTARG ;;
	*) sed -n '2,20p' "$0"; exit 2 ;;
	esac
done
shift $((OPTIND - 1))

# fd93012d: the DPI the committed src/dpi/mmt_dpi.h was generated from
#           (its first line says "MMT-DPI v1.7.10 (fd93012d)")
# 6b1c9f53: the old upstream CI pin (.github/workflows/c-cpp.yml)
# v1.8.0:   the only 1.8.x tag
REFS=("$@")
[ ${#REFS[@]} -gt 0 ] || REFS=(fd93012d 6b1c9f53 v1.8.0 v1.10.2 v1.10.3)

mkdir -p "$WORK/out"
WORK=$(cd "$WORK" && pwd)

if [ -d "$WORK/mmt-dpi-src/.git" ]; then
	git -C "$WORK/mmt-dpi-src" fetch -q --tags origin
else
	git clone -q "$DPI_URL" "$WORK/mmt-dpi-src"
fi

# snapshot of this repository's tracked files (the working tree versions)
rm -rf "$WORK/mmt-sec"; mkdir -p "$WORK/mmt-sec"
git -C "$REPO" ls-files -z | (cd "$REPO" && tar --null -T - -cf -) | tar -C "$WORK/mmt-sec" -xf -
# the Makefile takes GIT_VERSION from git log; keep it meaningful without .git
sed -i "s/^GIT_VERSION := .*/GIT_VERSION := $(git -C "$REPO" log --format=%h -n1)/" "$WORK/mmt-sec/Makefile"

run_one(){
	local ref=$1 label=${1//\//_}
	local out="$WORK/out/$label"
	rm -rf "$out"; mkdir -p "$out"
	docker run --rm \
		-e DPI_REF="$ref" -e OUT_UID="$(id -u)" -e OUT_GID="$(id -g)" \
		-v "$WORK/mmt-dpi-src:/in/mmt-dpi:ro" \
		-v "$WORK/mmt-sec:/in/mmt-sec:ro" \
		-v "$HERE:/in/tool:ro" \
		-v "$out:/out" \
		"$IMAGE" bash /in/tool/in-container.sh \
		> "$out/container.log" 2>&1 \
		&& echo "ok   $ref" || { echo "FAIL $ref (see $out/container.log)"; tail -20 "$out/container.log"; return 1; }
}

pids=(); fail=0
for ref in "${REFS[@]}"; do
	while [ "$(jobs -rp | wc -l)" -ge "$PARALLEL" ]; do wait -n || fail=1; done
	run_one "$ref" &
done
while [ "$(jobs -rp | wc -l)" -gt 0 ]; do wait -n || fail=1; done

labels=()
for ref in "${REFS[@]}"; do labels+=("$WORK/out/${ref//\//_}"); done
python3 -I "$HERE/compare.py" "${labels[@]}" | tee "$WORK/out/report.txt"
exit $fail
